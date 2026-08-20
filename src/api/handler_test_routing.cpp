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
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

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
constexpr const char* kNfqwsListsRoot = "/opt/etc/nfqws2/lists";
constexpr const char* kNfqwsListsPrefix = "/opt/etc/nfqws2/lists/";
constexpr std::size_t kMaxNfqwsConfigBytes = 256U * 1024U;
constexpr std::size_t kMaxNfqwsListBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaxParsedListEntries = 32U * 1024U;
constexpr std::size_t kMaxParsedListCharacters = 2U * 1024U * 1024U;
constexpr std::size_t kMaxParsedListBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaxCachedParsedListBytes = 8U * 1024U * 1024U;
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

std::optional<std::string> confined_list_child(const std::string& path) {
    if (path.rfind(kNfqwsListsPrefix, 0) != 0) return std::nullopt;
    auto child = path.substr(std::char_traits<char>::length(kNfqwsListsPrefix));
    // Packaged and operator-managed nfqws lists are direct files in this
    // directory. Rejecting another slash removes every configurable parent
    // component, so an intermediate symlink cannot escape the fixed root.
    if (child.empty() || child == "." || child == ".." ||
        child.find('/') != std::string::npos) {
        return std::nullopt;
    }
    return child;
}

bool is_confined_list_path(const std::string& path) {
    return confined_list_child(path).has_value();
}

int open_lists_root() {
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int fd = ::open(kNfqwsListsRoot, flags);
    if (fd < 0) return -1;
    struct stat metadata {};
    if (::fstat(fd, &metadata) != 0 || !S_ISDIR(metadata.st_mode)) {
        (void)::close(fd);
        return -1;
    }
    return fd;
}

std::optional<FileIdentity> inspect_list_file(const std::string& path,
                                              std::size_t max_bytes) {
    const auto child = confined_list_child(path);
    if (!child.has_value()) return std::nullopt;
    const int root_fd = open_lists_root();
    if (root_fd < 0) return std::nullopt;

    struct stat metadata {};
    const int status = ::fstatat(
        root_fd,
        child->c_str(),
        &metadata,
#ifdef AT_SYMLINK_NOFOLLOW
        AT_SYMLINK_NOFOLLOW
#else
        0
#endif
    );
    (void)::close(root_fd);
    if (status != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size < 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > max_bytes) {
        return std::nullopt;
    }
    return identity_from_stat(metadata);
}

std::optional<BoundedFile> read_bounded_list_file(
    const std::string& path,
    std::size_t max_bytes) {
    const auto child = confined_list_child(path);
    if (!child.has_value()) return std::nullopt;
    const int root_fd = open_lists_root();
    if (root_fd < 0) return std::nullopt;
    const int fd = ::openat(
        root_fd, child->c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    (void)::close(root_fd);
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

std::optional<nfqws::BoundedHostlist> parse_list_for_cache(
    const std::string& contents) {
    return nfqws::parse_hostlist_bounded(
        contents,
        kMaxParsedListEntries,
        kMaxParsedListCharacters,
        kMaxParsedListBytes);
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

    std::optional<std::shared_ptr<const std::vector<std::string>>> list_entries(
        const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_confined_list_path(path)) return std::nullopt;
        const auto cached = lists_.find(path);
        const auto current = inspect_list_file(path, kMaxNfqwsListBytes);
        if (!current.has_value()) {
            if (cached != lists_.end()) {
                cached_bytes_ -= cached->second.parsed_bytes;
                lists_.erase(cached);
            }
            return std::nullopt;
        }

        if (cached != lists_.end() && cached->second.identity == *current) {
            cached->second.last_used = ++clock_;
            return cached->second.entries;
        }
        if (cached != lists_.end()) {
            cached_bytes_ -= cached->second.parsed_bytes;
            lists_.erase(cached);
        }

        const auto file = read_bounded_list_file(path, kMaxNfqwsListBytes);
        if (!file.has_value()) return std::nullopt;
        auto parsed = parse_list_for_cache(file->contents);
        if (!parsed.has_value()) return std::nullopt;
        const auto parsed_bytes = parsed->conservative_bytes;
        auto entries = std::make_shared<const std::vector<std::string>>(
            std::move(parsed->entries));

        while (!lists_.empty() &&
               (lists_.size() >= kMaxCachedLists ||
                parsed_bytes > kMaxCachedParsedListBytes - cached_bytes_)) {
            const auto oldest = std::min_element(
                lists_.begin(), lists_.end(), [](const auto& left,
                                                 const auto& right) {
                    return left.second.last_used < right.second.last_used;
                });
            cached_bytes_ -= oldest->second.parsed_bytes;
            lists_.erase(oldest);
        }
        if (parsed_bytes > kMaxCachedParsedListBytes) return std::nullopt;
        cached_bytes_ += parsed_bytes;
        lists_.emplace(
            path,
            CachedList{
                file->identity,
                entries,
                parsed_bytes,
                ++clock_,
            });
        return entries;
    }

private:
    struct CachedList {
        FileIdentity identity;
        std::shared_ptr<const std::vector<std::string>> entries;
        std::size_t parsed_bytes{0};
        std::uint64_t last_used{0};
    };

    std::mutex mutex_;
    std::optional<FileIdentity> config_identity_;
    bool config_available_{false};
    std::vector<nfqws::ListReference> references_;
    std::map<std::string, CachedList> lists_;
    // Source buffers are transient. This budget tracks the conservative heap
    // footprint that remains resident in the parsed-vector cache.
    std::size_t cached_bytes_{0};
    std::uint64_t clock_{0};
};

NfqwsCoverageCache& nfqws_coverage_cache() {
    static NfqwsCoverageCache cache;
    return cache;
}

std::mutex& nfqws_coverage_admission_mutex() {
    static std::mutex mutex;
    return mutex;
}

#ifdef KEEN_PBR3_TESTING
std::mutex& nfqws_coverage_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

NfqwsCoverageScanHook& nfqws_coverage_hook() {
    static NfqwsCoverageScanHook hook;
    return hook;
}

void invoke_nfqws_coverage_hook() {
    NfqwsCoverageScanHook hook;
    {
        std::lock_guard<std::mutex> lock(nfqws_coverage_hook_mutex());
        hook = nfqws_coverage_hook();
    }
    if (hook) hook();
}
#else
void invoke_nfqws_coverage_hook() {}
#endif

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
    std::unique_lock<std::mutex> admission(
        nfqws_coverage_admission_mutex(), std::try_to_lock);
    if (!admission.owns_lock()) {
        coverage.available = false;
        coverage.reason = "busy";
        return coverage;
    }
    invoke_nfqws_coverage_hook();

    const auto references = nfqws_coverage_cache().active_references();
    coverage.available = references.has_value();
    if (!references.has_value()) {
        coverage.reason = "unavailable";
        return coverage;
    }

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
        if (!entries.has_value()) {
            // Skipping an unreadable or over-budget active list would turn
            // "unknown" into a false "uncovered" verdict.
            coverage.available = false;
            coverage.reason = "unavailable";
            coverage.matches.clear();
            return coverage;
        }

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
            if (const auto hit =
                    nfqws::match_hostlist(**entries, result.target)) {
                append(*hit, result.target);
            }
        } else {
            for (const auto& address : addresses) {
                if (const auto hit =
                        nfqws::match_ipset(**entries, address)) {
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

#ifdef KEEN_PBR3_TESTING
void set_nfqws_coverage_scan_hook_for_testing(NfqwsCoverageScanHook hook) {
    std::lock_guard<std::mutex> lock(nfqws_coverage_hook_mutex());
    nfqws_coverage_hook() = std::move(hook);
}

void reset_nfqws_coverage_scan_hook_for_testing() {
    set_nfqws_coverage_scan_hook_for_testing({});
}

bool nfqws_list_path_confined_for_testing(const std::string& path) {
    return is_confined_list_path(path);
}

std::optional<std::size_t> nfqws_cached_list_footprint_for_testing(
    const std::string& contents) {
    const auto parsed = parse_list_for_cache(contents);
    if (!parsed.has_value()) return std::nullopt;
    return parsed->conservative_bytes;
}
#endif

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
