#ifdef WITH_API

#include "handler_test_routing.hpp"
#include "../cmd/test_routing.hpp"
#include "../nfqws/list_match.hpp"
#include "../util/nfqws_validator.hpp"
#include "generated/api_types.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

api::Evaluation to_api_evaluation(RoutingMatchEvaluation evaluation) {
    switch (evaluation) {
        case RoutingMatchEvaluation::Matched:
            return api::Evaluation::MATCHED;
        case RoutingMatchEvaluation::NotMatched:
            return api::Evaluation::NOT_MATCHED;
        case RoutingMatchEvaluation::InsufficientContext:
            return api::Evaluation::INSUFFICIENT_CONTEXT;
    }
    return api::Evaluation::INSUFFICIENT_CONTEXT;
}

std::vector<api::RoutingTestUnknownConditionElement>
to_api_unknown_conditions(const std::vector<std::string>& conditions) {
    std::vector<api::RoutingTestUnknownConditionElement> converted;
    converted.reserve(conditions.size());
    for (const auto& condition : conditions) {
        nlohmann::json value = condition;
        converted.push_back(
            value.get<api::RoutingTestUnknownConditionElement>());
    }
    return converted;
}

constexpr const char* kNfqwsConfigPath = "/opt/etc/nfqws2/nfqws2.conf";
constexpr const char* kNfqwsListsRoot = "/opt/etc/nfqws2/lists/";
constexpr std::size_t kMaxNfqwsConfigBytes = 256U * 1024U;
constexpr std::size_t kMaxNfqwsListBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaxCachedListBytes = 8U * 1024U * 1024U;
constexpr std::size_t kMaxCachedLists = 16U;
constexpr std::size_t kMaxActiveListReferences = 32U;
constexpr std::size_t kMaxCoverageMatches = 64U;

struct FileIdentity {
    std::uint64_t device{0};
    std::uint64_t inode{0};
    std::uint64_t size{0};
    std::int64_t mtime_seconds{0};
    std::int64_t mtime_nanoseconds{0};
    std::int64_t ctime_seconds{0};
    std::int64_t ctime_nanoseconds{0};

    bool operator==(const FileIdentity& other) const noexcept {
        return device == other.device && inode == other.inode &&
               size == other.size &&
               mtime_seconds == other.mtime_seconds &&
               mtime_nanoseconds == other.mtime_nanoseconds &&
               ctime_seconds == other.ctime_seconds &&
               ctime_nanoseconds == other.ctime_nanoseconds;
    }
};

FileIdentity identity_from_stat(const struct stat& metadata) {
    FileIdentity identity;
    identity.device = static_cast<std::uint64_t>(metadata.st_dev);
    identity.inode = static_cast<std::uint64_t>(metadata.st_ino);
    identity.size = static_cast<std::uint64_t>(metadata.st_size);
#if defined(__APPLE__)
    identity.mtime_seconds = metadata.st_mtimespec.tv_sec;
    identity.mtime_nanoseconds = metadata.st_mtimespec.tv_nsec;
    identity.ctime_seconds = metadata.st_ctimespec.tv_sec;
    identity.ctime_nanoseconds = metadata.st_ctimespec.tv_nsec;
#else
    identity.mtime_seconds = metadata.st_mtim.tv_sec;
    identity.mtime_nanoseconds = metadata.st_mtim.tv_nsec;
    identity.ctime_seconds = metadata.st_ctim.tv_sec;
    identity.ctime_nanoseconds = metadata.st_ctim.tv_nsec;
#endif
    return identity;
}

std::optional<FileIdentity> inspect_regular_file(const std::string& path,
                                                 std::size_t max_bytes) {
    struct stat metadata {};
    if (::lstat(path.c_str(), &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_size < 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > max_bytes) {
        return std::nullopt;
    }
    return identity_from_stat(metadata);
}

struct BoundedFile {
    FileIdentity identity;
    std::string contents;
};

std::optional<BoundedFile> read_bounded_regular_file(
    const std::string& path,
    std::size_t max_bytes) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return std::nullopt;

    const auto close_fd = [&]() { (void)::close(fd); };
    struct stat before {};
    if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_size < 0 ||
        static_cast<std::uint64_t>(before.st_size) > max_bytes) {
        close_fd();
        return std::nullopt;
    }

    std::string contents;
    contents.reserve(static_cast<std::size_t>(before.st_size));
    char buffer[8192];
    while (true) {
        const auto count = ::read(fd, buffer, sizeof(buffer));
        if (count < 0) {
            if (errno == EINTR) continue;
            close_fd();
            return std::nullopt;
        }
        if (count == 0) break;
        if (contents.size() + static_cast<std::size_t>(count) > max_bytes) {
            close_fd();
            return std::nullopt;
        }
        contents.append(buffer, static_cast<std::size_t>(count));
    }

    struct stat after {};
    if (::fstat(fd, &after) != 0) {
        close_fd();
        return std::nullopt;
    }
    close_fd();
    const auto before_identity = identity_from_stat(before);
    const auto after_identity = identity_from_stat(after);
    if (!(before_identity == after_identity) ||
        after_identity.size != contents.size()) {
        return std::nullopt;
    }
    return BoundedFile{after_identity, std::move(contents)};
}

bool is_confined_list_path(const std::string& path) {
    return path.rfind(kNfqwsListsRoot, 0) == 0 &&
           path.find("/../") == std::string::npos &&
           path.find("/./") == std::string::npos &&
           !(path.size() >= 3U &&
             path.compare(path.size() - 3U, 3U, "/..") == 0);
}

class NfqwsCoverageCache {
public:
    std::optional<std::vector<nfqws::ListReference>> active_references() {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto current =
            inspect_regular_file(kNfqwsConfigPath, kMaxNfqwsConfigBytes);
        if (!current.has_value()) return std::nullopt;
        if (config_identity_.has_value() &&
            *config_identity_ == *current) {
            return config_available_
                       ? std::optional<std::vector<nfqws::ListReference>>(
                             references_)
                       : std::nullopt;
        }

        const auto file = read_bounded_regular_file(
            kNfqwsConfigPath, kMaxNfqwsConfigBytes);
        if (!file.has_value() || file->contents.empty()) {
            return std::nullopt;
        }
        // Cache a stable invalid candidate too. Otherwise an accidentally
        // malformed config would force a complete parse on every API call.
        config_identity_ = file->identity;
        config_available_ = false;
        references_.clear();
        if (!validate_nfqws_candidate(file->contents).empty()) {
            return std::nullopt;
        }
        auto references = nfqws::parse_list_references(
            build_nfqws_dry_run_args(file->contents));
        references.erase(
            std::remove_if(
                references.begin(),
                references.end(),
                [](const nfqws::ListReference& reference) {
                    return !is_confined_list_path(reference.path);
                }),
            references.end());
        if (references.size() > kMaxActiveListReferences) {
            return std::nullopt;
        }
        references_ = std::move(references);
        config_available_ = true;
        return references_;
    }

    std::shared_ptr<const std::vector<std::string>> list_entries(
        const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_confined_list_path(path)) return {};
        const auto current = inspect_regular_file(path, kMaxNfqwsListBytes);
        if (!current.has_value()) return {};

        const auto cached = lists_.find(path);
        if (cached != lists_.end() && cached->second.identity == *current) {
            cached->second.last_used = ++clock_;
            return cached->second.entries;
        }

        const auto file = read_bounded_regular_file(path, kMaxNfqwsListBytes);
        if (!file.has_value()) return {};
        auto parsed = std::make_shared<const std::vector<std::string>>(
            nfqws::parse_hostlist(file->contents));

        if (cached != lists_.end()) {
            cached_bytes_ -= cached->second.source_bytes;
            lists_.erase(cached);
        }
        while (!lists_.empty() &&
               (lists_.size() >= kMaxCachedLists ||
                cached_bytes_ + file->contents.size() >
                    kMaxCachedListBytes)) {
            const auto oldest = std::min_element(
                lists_.begin(), lists_.end(), [](const auto& left,
                                                 const auto& right) {
                    return left.second.last_used < right.second.last_used;
                });
            cached_bytes_ -= oldest->second.source_bytes;
            lists_.erase(oldest);
        }
        if (file->contents.size() > kMaxCachedListBytes) return {};
        cached_bytes_ += file->contents.size();
        lists_.emplace(
            path,
            CachedList{
                file->identity,
                parsed,
                file->contents.size(),
                ++clock_,
            });
        return parsed;
    }

private:
    struct CachedList {
        FileIdentity identity;
        std::shared_ptr<const std::vector<std::string>> entries;
        std::size_t source_bytes{0};
        std::uint64_t last_used{0};
    };

    std::mutex mutex_;
    std::optional<FileIdentity> config_identity_;
    bool config_available_{false};
    std::vector<nfqws::ListReference> references_;
    std::map<std::string, CachedList> lists_;
    std::size_t cached_bytes_{0};
    std::uint64_t clock_{0};
};

NfqwsCoverageCache& nfqws_coverage_cache() {
    static NfqwsCoverageCache cache;
    return cache;
}

api::RoutingTestNfqwsMatchRole to_api_role(nfqws::ListRole role) {
    switch (role) {
        case nfqws::ListRole::hostlist:
            return api::RoutingTestNfqwsMatchRole::HOSTLIST;
        case nfqws::ListRole::hostlist_auto:
            return api::RoutingTestNfqwsMatchRole::HOSTLIST_AUTO;
        case nfqws::ListRole::hostlist_exclude:
            return api::RoutingTestNfqwsMatchRole::HOSTLIST_EXCLUDE;
        case nfqws::ListRole::ipset:
            return api::RoutingTestNfqwsMatchRole::IPSET;
        case nfqws::ListRole::ipset_exclude:
            return api::RoutingTestNfqwsMatchRole::IPSET_EXCLUDE;
    }
    return api::RoutingTestNfqwsMatchRole::HOSTLIST;
}

// Which nfqws lists cover this target, taken from the lists nfqws2.conf
// actually names rather than from a fixed pair of filenames: an operator may
// add lists of their own, and address lists are matched by prefix while
// hostlists are matched by domain.
//
// Exclude lists are reported too, and reported as themselves. They are not
// coverage - they are the reason coverage does not apply - and folding the two
// into one answer would invert the meaning for every domain on them.
api::RoutingTestNfqws nfqws_coverage(const TestRoutingResult& result) {
    api::RoutingTestNfqws coverage;
    const auto references = nfqws_coverage_cache().active_references();
    coverage.available = references.has_value();
    if (!references.has_value()) return coverage;

    // The target itself when it is an address, plus everything it resolved to:
    // a domain is handled by nfqws through its hostlists, but its addresses can
    // still sit in an ipset.
    std::vector<std::string> addresses;
    if (!result.is_domain) addresses.push_back(result.target);
    addresses.insert(addresses.end(),
                     result.resolved_ips.begin(),
                     result.resolved_ips.end());

    for (const auto& reference : *references) {
        const auto entries =
            nfqws_coverage_cache().list_entries(reference.path);
        if (!entries) continue;

        const auto append = [&](const nfqws::HostlistMatch& hit,
                                const std::string& matched) {
            api::RoutingTestNfqwsMatchElement element;
            element.list = reference.path;
            element.role = to_api_role(reference.role);
            element.includes = nfqws::role_includes(reference.role);
            element.entry = hit.entry;
            element.matched = matched;
            element.exact = hit.exact;
            coverage.matches.push_back(std::move(element));
        };

        if (nfqws::role_is_hostlist(reference.role)) {
            if (!result.is_domain) continue;
            if (const auto hit = nfqws::match_hostlist(*entries, result.target)) {
                append(*hit, result.target);
            }
        } else {
            for (const auto& address : addresses) {
                if (const auto hit = nfqws::match_ipset(*entries, address)) {
                    append(*hit, address);
                    break;
                }
            }
        }
        if (coverage.matches.size() >= kMaxCoverageMatches) break;
    }
    return coverage;
}

api::ListMatch to_api_list_match(const ListMatchInfo& match) {
    api::ListMatch converted;
    converted.list = match.list_name;
    converted.via = match.via;
    return converted;
}

} // namespace

void register_test_routing_handler(ApiServer& server, ApiContext& ctx) {
    server.post("/api/routing/test", [&ctx](const std::string& body) -> std::string {
        nlohmann::json j;
        try {
            j = nlohmann::json::parse(body);
        } catch (const nlohmann::json::exception&) {
            nlohmann::json payload = {{"error", "Invalid request body"}};
            throw ApiError("Invalid request body", 400, payload.dump());
        }

        api::RoutingTestRequest req;
        try {
            api::from_json(j, req);
        } catch (const std::exception&) {
            nlohmann::json payload = {{"error", "Invalid request body"}};
            throw ApiError("Invalid request body", 400, payload.dump());
        }

        if (req.target.empty()) {
            nlohmann::json payload = {{"error", "Field 'target' must not be empty"}};
            throw ApiError("Field 'target' must not be empty", 400, payload.dump());
        }

        auto result = ctx.compute_test_routing(req.target);

        api::RoutingTestResponse resp;
        resp.target       = result.target;
        resp.is_domain    = result.is_domain;
        resp.config_scope = api::ConfigScope::ACTIVE;
        resp.unapplied_draft = result.unapplied_draft;
        resp.dns_error    = result.dns_error;
        resp.no_matching_rule = result.no_matching_rule;
        resp.resolved_ips = result.resolved_ips;
        resp.warnings     = result.warnings;
        // A separate question with a separate answer: nfqws can be handling a
        // target the routing rules never touch, and the reverse.
        resp.nfqws        = nfqws_coverage(result);

        for (const auto& entry : result.entries) {
            api::RoutingTestEntry e;
            e.ip                = entry.ip;
            e.expected_outbound = entry.expected_outbound;
            e.actual_outbound   = entry.actual_outbound;
            e.ok                = entry.ok;
            e.evaluation = to_api_evaluation(entry.evaluation);
            e.unknown_conditions =
                to_api_unknown_conditions(entry.unknown_conditions);
            if (entry.list_match) {
                e.list_match = to_api_list_match(*entry.list_match);
            }
            resp.results.push_back(std::move(e));
        }

        for (const auto& rule_diag : result.rule_diagnostics) {
            api::RoutingTestRuleDiagnosticElement rd;
            rd.rule_index = rule_diag.rule_index;
            rd.rule = rule_diag.rule;
            rd.outbound = rule_diag.outbound;
            rd.interface_name = rule_diag.interface_name;
            rd.target_in_lists = rule_diag.target_in_lists;
            if (rule_diag.target_match) {
                api::ListMatch lm;
                lm.list = rule_diag.target_match->list_name;
                lm.via  = rule_diag.target_match->via;
                rd.target_match = std::move(lm);
            }
            for (const auto& ip_diag : rule_diag.ip_rows) {
                api::RoutingTestRuleIpDiagnosticElement ipd;
                ipd.ip = ip_diag.ip;
                ipd.in_ipset = ip_diag.in_ipset;
                ipd.in_lists = ip_diag.in_lists;
                ipd.evaluation =
                    to_api_evaluation(ip_diag.evaluation);
                ipd.unknown_conditions =
                    to_api_unknown_conditions(
                        ip_diag.unknown_conditions);
                if (ip_diag.list_match) {
                    ipd.list_match =
                        to_api_list_match(*ip_diag.list_match);
                }
                rd.ip_rows.push_back(std::move(ipd));
            }
            resp.rule_diagnostics.push_back(std::move(rd));
        }

        nlohmann::json out;
        api::to_json(out, resp);
        return out.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
