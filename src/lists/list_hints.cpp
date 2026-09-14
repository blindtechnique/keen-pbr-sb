#include "list_hints.hpp"

#include "../cache/cache_manager.hpp"
#include "../config/list_parser.hpp"
#include "list_source_decoder.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <map>
#include <set>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

using Clock = std::chrono::steady_clock;
using Conditions = std::tuple<std::string, std::optional<int64_t>, std::string,
                              std::string, std::string, std::string>;

Conditions conditions(const RouteRule& rule) {
    return {rule.proto.value_or(""), rule.dscp, rule.src_port.value_or(""),
            rule.dest_port.value_or(""), rule.src_addr.value_or(""),
            rule.dest_addr.value_or("")};
}

struct Owner {
    std::size_t rule;
    const std::string* list;
};

// Only representative examples are needed, not all pairs of duplicate lists.
// Retain the earliest owner and the earliest owner with a different outbound.
struct Owners {
    std::optional<Owner> first;
    std::optional<Owner> different;

    void add(Owner owner, const std::vector<RouteRule>& rules) {
        std::array<std::optional<Owner>, 3> candidates{first, different, owner};
        std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
            return a && (!b || a->rule < b->rule);
        });
        first = candidates.front();
        different.reset();
        for (const auto& candidate : candidates) {
            if (candidate && rules[candidate->rule].outbound != rules[first->rule].outbound) {
                different = candidate;
                break;
            }
        }
    }
};

struct FileDescriptor {
    int value;
    ~FileDescriptor() { if (value >= 0) ::close(value); }
};

class Analyzer {
public:
    Analyzer(const Config& config, const CacheManager* cache, ListHintsLimits limits)
        : config_(config), cache_(cache), limits_(limits), started_(Clock::now()),
          rules_(config.route && config.route->rules ? *config.route->rules : empty_rules_) {
        // The public response remains bounded even for custom diagnostic budgets.
        limits_.hints = std::min<std::size_t>(limits_.hints, 100);
    }

    api::ListHintsResponse run() {
        if (config_.lists) result_.total_lists = config_.lists->size();
        collect_usage();
        if (config_.lists) {
            for (const auto& [id, list] : *config_.lists) {
                if (expired()) break;
                if (!usage_incomplete_ && used_.count(id) == 0) {
                    api::ListHint hint{};
                    hint.code = "unused";
                    hint.list = id;
                    remember(0, std::move(hint));
                }
                scan_list(id, list);
                ++result_.scanned_lists;
                if (input_exhausted_) break;
            }
        }
        find_overlaps();
        // Round-robin prevents many unused lists from hiding overlap examples.
        for (std::size_t i = 0; i < limits_.hints; ++i) {
            for (std::size_t category : {2U, 1U, 0U}) {
                if (i >= hints_[category].size()) continue;
                if (result_.items.size() == limits_.hints) {
                    result_.hints_limited = true;
                } else {
                    result_.items.push_back(std::move(hints_[category][i]));
                }
            }
        }
        result_.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - started_).count();
        return std::move(result_);
    }

private:
    const Config& config_;
    const CacheManager* cache_;
    ListHintsLimits limits_;
    Clock::time_point started_;
    const std::vector<RouteRule> empty_rules_{};
    const std::vector<RouteRule>& rules_;
    api::ListHintsResponse result_{};
    bool input_exhausted_{false};
    bool usage_incomplete_{false};
    std::size_t input_bytes_{0};
    std::size_t index_owners_{0};
    std::set<std::string> used_;
    std::map<std::string, std::map<std::size_t, Owners>> users_;
    std::map<std::string, std::map<std::size_t, Owners>> domains_;
    std::array<std::vector<api::ListHint>, 3> hints_;
    std::set<std::pair<std::string, std::string>> wide_examples_;
    std::set<std::pair<std::size_t, std::size_t>> overlap_examples_;

    bool expired() {
        if (Clock::now() - started_ < limits_.elapsed) return false;
        result_.scan_limited = true;
        return true;
    }

    void remember(std::size_t category, api::ListHint hint) {
        if (hints_[category].size() < limits_.hints) {
            hints_[category].push_back(std::move(hint));
        } else {
            result_.hints_limited = true;
        }
    }

    void issue(const std::string& id, const std::string& reason) {
        for (const auto& item : result_.source_issues) {
            if (item.list == id && item.reason == reason) return;
        }
        if (result_.source_issues.size() == 100) {
            result_.source_issues_limited = true;
            return;
        }
        api::ListHintSourceIssue item{};
        item.list = id;
        item.reason = reason;
        result_.source_issues.push_back(std::move(item));
    }

    void collect_usage() {
        std::map<Conditions, std::size_t> groups;
        std::size_t references = 0;
        const auto use = [&](const std::string& id) {
            if (++references > limits_.index_owners || expired()) {
                usage_incomplete_ = result_.scan_limited = true;
                return false;
            }
            used_.insert(id);
            return true;
        };
        for (std::size_t i = 0; i < rules_.size(); ++i) {
            if (expired()) { usage_incomplete_ = true; return; }
            const auto& rule = rules_[i];
            const auto key = conditions(rule);
            if (route_rule_enabled(rule) && key != Conditions{}) ++result_.conditional_rules;
            auto group = groups.emplace(key, groups.size()).first->second;
            for (const auto& id : route_rule_lists(rule)) {
                if (!use(id)) return;
                if (!route_rule_enabled(rule)) continue;
                auto users = users_.try_emplace(id).first;
                users->second[group].add({i, &users->first}, rules_);
            }
        }
        if (config_.dns && config_.dns->rules) {
            for (const auto& rule : *config_.dns->rules) {
                for (const auto& id : rule.list) if (!use(id)) return;
            }
        }
        if (config_.daemon && config_.daemon->reconnect_owned_flows_on_routing_change_lists) {
            for (const auto& id : *config_.daemon->reconnect_owned_flows_on_routing_change_lists) {
                if (!use(id)) return;
            }
        }
        if (config_.tunnel_probe && config_.tunnel_probe->list) use(*config_.tunnel_probe->list);
    }

    bool entry_budget() {
        if (static_cast<std::size_t>(result_.scanned_entries) >= limits_.entries || expired()) {
            input_exhausted_ = result_.scan_limited = true;
            return false;
        }
        ++result_.scanned_entries;
        return true;
    }

    void entry(const std::string& id, EntryType type, std::string_view value) {
        if (type == EntryType::Cidr) {
            const auto slash = value.find('/');
            const auto prefix = std::stoi(std::string(value.substr(slash + 1)));
            if (prefix > (value.find(':') == std::string_view::npos ? 16 : 32)) return;
            const auto example = std::make_pair(id, std::string(value));
            if (wide_examples_.count(example) != 0) return;
            if (hints_[1].size() == limits_.hints) { result_.hints_limited = true; return; }
            wide_examples_.insert(example);
            api::ListHint hint{};
            hint.code = "wide_cidr";
            hint.list = id;
            hint.entry = example.second;
            remember(1, std::move(hint));
            return;
        }
        if (type != EntryType::Domain) return;
        const auto users = users_.find(id);
        if (users == users_.end()) return;
        std::string domain(value);
        std::transform(domain.begin(), domain.end(), domain.begin(), [](unsigned char ch) {
            return ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch;
        });
        for (const auto& [group, owners] : users->second) {
            if (expired()) return;
            // Bound work, not just allocation: many condition groups must not
            // turn a repeated domain list into a rules-times-entries scan.
            if (index_owners_ >= limits_.index_owners) {
                result_.scan_limited = true;
                return;
            }
            ++index_owners_;
            auto& target = domains_[domain][group];
            target.add(*owners.first, rules_);
            if (owners.different) target.add(*owners.different, rules_);
        }
    }

    void text_line(const std::string& id, std::string_view line, bool inline_entry = false) {
        if (!entry_budget()) return;
        FunctionalVisitor visitor([&](EntryType type, std::string_view value) {
            entry(id, type, value);
        });
        if (inline_entry) {
            if (!ListParser::classify_entry(line, visitor)) issue(id, "invalid_source");
        } else {
            const auto first = line.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos || line[first] == '#') return;
            line = line.substr(first, line.find_last_not_of(" \t\r\n") - first + 1);
            if (!ListParser::classify_entry(line, visitor)) issue(id, "invalid_source");
        }
    }

    // Read a stable regular file with a private descriptor. Never open FIFOs or
    // follow a final symlink, and never publish a partial structured source.
    void file(const std::string& id, const std::filesystem::path& path,
              const std::string& format) {
        if (input_exhausted_ || expired()) return;
        FileDescriptor fd{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)};
        struct stat before{};
        if (fd.value < 0 || ::fstat(fd.value, &before) != 0 || !S_ISREG(before.st_mode)) {
            issue(id, "unavailable");
            return;
        }
        const auto available = limits_.input_bytes - input_bytes_;
        if (before.st_size < 0 || static_cast<std::uintmax_t>(before.st_size) > limits_.file_bytes) {
            issue(id, "size_limit");
            return;
        }
        if (static_cast<std::uintmax_t>(before.st_size) > available) {
            input_exhausted_ = result_.scan_limited = true;
            issue(id, "size_limit");
            return;
        }
        std::string body;
        body.reserve(static_cast<std::size_t>(before.st_size));
        std::array<char, 16384> buffer{};
        while (!expired()) {
            const auto n = ::read(fd.value, buffer.data(), buffer.size());
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) { issue(id, "unavailable"); return; }
            if (n == 0) break;
            const auto size = static_cast<std::size_t>(n);
            if (size > available - body.size() || size > limits_.file_bytes - body.size()) {
                issue(id, "size_limit");
                return;
            }
            body.append(buffer.data(), size);
        }
        input_bytes_ += body.size();
        if (expired()) return;
        struct stat after{};
        if (::fstat(fd.value, &after) != 0 || before.st_size != after.st_size ||
            body.size() != static_cast<std::uintmax_t>(after.st_size) ||
            before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
            before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
            before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
            before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
            issue(id, "source_changed");
            return;
        }
        if (format != "text") {
            const auto decoded = decode_list_source(body, format);
            if (!decoded.complete) { issue(id, "invalid_source"); return; }
            for (const auto& item : decoded.entries) {
                text_line(id, item.value, true);
                if (input_exhausted_) break;
            }
        } else {
            std::size_t pos = 0;
            while (pos < body.size() && !input_exhausted_) {
                const auto end = body.find('\n', pos);
                const auto size = (end == std::string::npos ? body.size() : end) - pos;
                text_line(id, std::string_view(body).substr(pos, size));
                pos += size + 1;
            }
        }
    }

    void scan_list(const std::string& id, const ListConfig& list) {
        for (const auto* entries : {&list.domains, &list.ip_cidrs}) {
            if (!*entries) continue;
            for (const auto& value : **entries) {
                if (value.size() > limits_.input_bytes - input_bytes_) {
                    input_exhausted_ = result_.scan_limited = true;
                    return;
                }
                input_bytes_ += value.size();
                text_line(id, value, true);
                if (input_exhausted_) return;
            }
        }
        const auto format = list.source_format.value_or("text");
        if (list.file && !list.file->empty()) file(id, *list.file, format);
        if (input_exhausted_ || expired()) return;
        if (list.url && !list.url->empty()) {
            if (!cache_) { issue(id, "unavailable"); return; }
            try {
                const auto snapshot = cache_->capture_generation({id});
                const auto* handle = snapshot->find(id);
                if (!handle) issue(id, "unavailable");
                else if (!handle->matches_source(*list.url, format)) issue(id, "source_changed");
                else file(id, handle->path(), "text"); // Already decoded by cache publication.
            } catch (const std::exception&) {
                // No private URL/path/exception text escapes into the report.
                issue(id, "unavailable");
            }
        }
    }

    void overlap(Owner a, Owner b, const std::string& domain, const std::string& parent) {
        if (a.rule == b.rule || rules_[a.rule].outbound == rules_[b.rule].outbound) return;
        const bool swapped = a.rule > b.rule;
        if (swapped) std::swap(a, b);
        const auto pair = std::make_pair(a.rule, b.rule);
        if (overlap_examples_.count(pair) != 0) return;
        if (hints_[2].size() == limits_.hints) { result_.hints_limited = true; return; }
        overlap_examples_.insert(pair);
        api::ListHint hint{};
        hint.code = "domain_overlap";
        hint.list = *a.list;
        hint.other_list = *b.list;
        hint.rule_index = a.rule;
        hint.other_rule_index = b.rule;
        hint.outbound = rules_[a.rule].outbound;
        hint.other_outbound = rules_[b.rule].outbound;
        hint.entry = swapped ? parent : domain;
        hint.other_entry = swapped ? domain : parent;
        remember(2, std::move(hint));
    }

    void find_overlaps() {
        for (const auto& [domain, groups] : domains_) {
            if (expired()) return;
            for (const auto& [group, owners] : groups) {
                if (owners.different) overlap(*owners.first, *owners.different, domain, domain);
                auto dot = domain.find('.');
                while (dot != std::string::npos) {
                    if (expired()) return;
                    const auto parent = domain.substr(dot + 1);
                    const auto found = domains_.find(parent);
                    if (found != domains_.end()) {
                        const auto other = found->second.find(group);
                        if (other != found->second.end()) {
                            for (const auto& a : {owners.first, owners.different}) {
                                for (const auto& b : {other->second.first, other->second.different}) {
                                    if (a && b) overlap(*a, *b, domain, parent);
                                }
                            }
                        }
                    }
                    dot = domain.find('.', dot + 1);
                }
            }
        }
    }
};

} // namespace

api::ListHintsResponse build_list_hints(const Config& config, const CacheManager* cache,
                                      ListHintsLimits limits) {
    return Analyzer(config, cache, limits).run();
}

} // namespace keen_pbr3
