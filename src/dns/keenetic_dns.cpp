#include "keenetic_dns.hpp"

#include "dns_server.hpp"
#include "../http/http_client.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <chrono>
#include <functional>
#include <mutex>
#include <sstream>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr const char* kRciDnsProxyEndpoint = "http://127.0.0.1:79/rci/show/dns-proxy";
constexpr auto kKeeneticDnsCacheTtl = std::chrono::minutes(5);
constexpr auto kKeeneticDnsFailureRetry = std::chrono::seconds(5);

std::string fetch_keenetic_dns_via_rci() {
    HttpClient client;
    client.set_timeout(std::chrono::seconds(3));
    return client.download(kRciDnsProxyEndpoint);
}

#ifdef KEEN_PBR3_TESTING
std::mutex& keenetic_dns_test_hooks_mutex() {
    static std::mutex mutex;
    return mutex;
}

KeeneticDnsFetchFn& keenetic_dns_test_fetch_fn() {
    static KeeneticDnsFetchFn fetch_fn = fetch_keenetic_dns_via_rci;
    return fetch_fn;
}

KeeneticDnsNowFn& keenetic_dns_test_now_fn() {
    static KeeneticDnsNowFn now_fn = [] {
        return std::chrono::steady_clock::now();
    };
    return now_fn;
}

std::string fetch_keenetic_dns_for_shared_cache() {
    KeeneticDnsFetchFn fetch_fn;
    {
        std::lock_guard<std::mutex> lock(keenetic_dns_test_hooks_mutex());
        fetch_fn = keenetic_dns_test_fetch_fn();
    }
    return fetch_fn();
}

std::chrono::steady_clock::time_point now_for_shared_keenetic_dns_cache() {
    KeeneticDnsNowFn now_fn;
    {
        std::lock_guard<std::mutex> lock(keenetic_dns_test_hooks_mutex());
        now_fn = keenetic_dns_test_now_fn();
    }
    return now_fn();
}
#endif

std::string trim_copy(const std::string& s) {
    size_t begin = 0;
    while (begin < s.size() && std::isspace(static_cast<unsigned char>(s[begin]))) {
        ++begin;
    }
    size_t end = s.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(begin, end - begin);
}

struct ParsedDnsServerLine {
    std::string address;
    bool has_specific_domains{false};
    bool is_encrypted{false};
    std::string kind;
    std::string target;
};

struct ParsedStaticDnsLine {
    std::string domain;
    std::string address;
};

ParsedDnsServerLine parse_dns_server_line(const std::string& line) {
    constexpr const char* kPrefix = "dns_server = ";
    if (line.rfind(kPrefix, 0) != 0) {
        return {};
    }

    const std::string after_prefix =
        trim_copy(line.substr(std::char_traits<char>::length(kPrefix)));
    std::string rest = after_prefix;
    std::string comment;
    const auto comment_pos = rest.find('#');
    if (comment_pos != std::string::npos) {
        comment = trim_copy(rest.substr(comment_pos + 1));
        rest = trim_copy(rest.substr(0, comment_pos));
    }
    if (rest.empty()) {
        return {};
    }

    ParsedDnsServerLine parsed;
    const auto first_space = rest.find_first_of(" \t");
    if (first_space == std::string::npos) {
        parsed.address = trim_copy(rest);
    } else {
        parsed.address = trim_copy(rest.substr(0, first_space));
        const std::string suffix = trim_copy(rest.substr(first_space + 1));
        parsed.has_specific_domains = !suffix.empty() && suffix != ".";
    }
    if (parsed.address.empty()) {
        return {};
    }

    if (comment.rfind("https://", 0) == 0) {
        parsed.is_encrypted = true;
        parsed.kind = "DoH";
        const auto suffix_pos = comment.find('@');
        parsed.target = comment.substr(0, suffix_pos);
    } else if (comment.rfind("tls://", 0) == 0) {
        parsed.is_encrypted = true;
        parsed.kind = "DoT";
        const auto suffix_pos = comment.find('@');
        parsed.target = comment.substr(0, suffix_pos);
    } else if (comment.rfind("tls.", 0) == 0) {
        parsed.is_encrypted = true;
        parsed.kind = "DoT";
        parsed.target = comment;
    } else if (comment.find('@') != std::string::npos &&
               comment.find("://") == std::string::npos) {
        parsed.is_encrypted = true;
        parsed.kind = "DoT";
        const auto suffix_pos = comment.find('@');
        parsed.target = "tls://" + comment.substr(suffix_pos + 1);
    } else {
        parsed.kind = "Plain";
    }
    return parsed;
}

ParsedStaticDnsLine parse_static_dns_line(const std::string& line) {
    constexpr const char* kStaticAPrefix = "static_a = ";
    constexpr const char* kStaticAAAAPrefix = "static_aaaa = ";

    std::string rest;
    if (line.rfind(kStaticAPrefix, 0) == 0) {
        rest = trim_copy(line.substr(std::char_traits<char>::length(kStaticAPrefix)));
    } else if (line.rfind(kStaticAAAAPrefix, 0) == 0) {
        rest = trim_copy(line.substr(std::char_traits<char>::length(kStaticAAAAPrefix)));
    } else {
        return {};
    }

    if (rest.empty()) {
        return {};
    }

    std::istringstream parts(rest);
    ParsedStaticDnsLine parsed;
    if (!(parts >> parsed.domain >> parsed.address)) {
        return {};
    }
    return parsed;
}

bool is_supported_static_dns_domain(const std::string& domain) {
    if (domain.empty() || domain.size() > 255) {
        return false;
    }
    if (domain == "*") {
        return false;
    }
    if (domain.size() >= 2 && domain[0] == '*' && domain[1] == '.') {
        return domain.size() > 2;
    }
    return true;
}

bool looks_like_ipv6_dns_server_address(const std::string& address) {
    if (address.empty()) {
        return false;
    }
    if (address.front() == '[') {
        return true;
    }

    size_t colon_count = 0;
    for (char c : address) {
        if (c == ':') {
            ++colon_count;
            if (colon_count > 1) {
                return true;
            }
        }
    }
    return false;
}

bool keenetic_dns_snapshots_equal_impl(const KeeneticDnsSnapshot& lhs,
                                       const KeeneticDnsSnapshot& rhs) {
    if (lhs.addresses.size() != rhs.addresses.size() ||
        lhs.upstreams.size() != rhs.upstreams.size() ||
        lhs.static_entries.size() != rhs.static_entries.size()) {
        return false;
    }
    for (size_t i = 0; i < lhs.addresses.size(); ++i) {
        if (lhs.addresses[i] != rhs.addresses[i]) {
            return false;
        }
    }
    for (size_t i = 0; i < lhs.upstreams.size(); ++i) {
        if (lhs.upstreams[i].address != rhs.upstreams[i].address ||
            lhs.upstreams[i].kind != rhs.upstreams[i].kind ||
            lhs.upstreams[i].target != rhs.upstreams[i].target) {
            return false;
        }
    }
    for (size_t i = 0; i < lhs.static_entries.size(); ++i) {
        if (lhs.static_entries[i].domain != rhs.static_entries[i].domain ||
            lhs.static_entries[i].address != rhs.static_entries[i].address) {
            return false;
        }
    }
    return true;
}

KeeneticDnsSnapshot build_keenetic_dns_snapshot(std::vector<ParsedDnsServerLine> selected_servers,
                                                std::vector<KeeneticStaticDnsEntry> static_entries) {
    if (selected_servers.empty()) {
        throw KeeneticDnsError(
            "Built-in DNS proxy appears disabled or has no unscoped 'dns_server = ...' directives in System policy");
    }

    KeeneticDnsSnapshot snapshot;
    snapshot.addresses.reserve(selected_servers.size());
    snapshot.upstreams.reserve(selected_servers.size());
    for (const auto& server : selected_servers) {
        snapshot.addresses.push_back(server.address);
        snapshot.upstreams.push_back({server.address, server.kind, server.target});
    }
    snapshot.static_entries = std::move(static_entries);
    return snapshot;
}

std::vector<ParsedDnsServerLine> collect_selected_keenetic_dns_servers(
    const std::vector<ParsedDnsServerLine>& unscoped_plaintext_servers,
    const std::vector<ParsedDnsServerLine>& unscoped_encrypted_servers) {
    if (!unscoped_encrypted_servers.empty()) {
        return unscoped_encrypted_servers;
    }
    return unscoped_plaintext_servers;
}

} // namespace

bool keenetic_dns_snapshots_equal(const KeeneticDnsSnapshot& lhs,
                                  const KeeneticDnsSnapshot& rhs) {
    return keenetic_dns_snapshots_equal_impl(lhs, rhs);
}

bool dns_config_uses_keenetic_server(const DnsConfig& dns_config) {
    for (const auto& server : dns_config.servers.value_or(std::vector<DnsServer>{})) {
        if (server.type.value_or(api::DnsServerType::STATIC) ==
            api::DnsServerType::KEENETIC) {
            return true;
        }
    }
    return false;
}

KeeneticDnsSnapshot extract_keenetic_dns_snapshot_from_rci(const std::string& response_body) {
    using json = nlohmann::json;

    json doc;
    try {
        doc = json::parse(response_body);
    } catch (const std::exception& e) {
        throw KeeneticDnsError(std::string("Failed to parse RCI JSON response: ") + e.what());
    }

    const auto status_it = doc.find("proxy-status");
    if (status_it == doc.end() || !status_it->is_array()) {
        throw KeeneticDnsError(
            "RCI response missing 'proxy-status' array (endpoint: /rci/show/dns-proxy)");
    }

    for (const auto& entry : *status_it) {
        if (!entry.is_object()) {
            continue;
        }

        const auto name_it = entry.find("proxy-name");
        if (name_it == entry.end() || !name_it->is_string()) {
            continue;
        }
        if (name_it->get<std::string>() != "System") {
            continue;
        }

        const auto cfg_it = entry.find("proxy-config");
        if (cfg_it == entry.end() || !cfg_it->is_string()) {
            throw KeeneticDnsError(
                "RCI response has 'System' DNS proxy but missing string field 'proxy-config'");
        }
        std::vector<ParsedDnsServerLine> unscoped_plaintext_servers;
        std::vector<ParsedDnsServerLine> unscoped_encrypted_servers;
        std::vector<KeeneticStaticDnsEntry> static_entries;
        std::istringstream in(cfg_it->get<std::string>());
        std::string line;
        while (std::getline(in, line)) {
            const std::string trimmed = trim_copy(line);

            const ParsedStaticDnsLine static_parsed = parse_static_dns_line(trimmed);
            if (!static_parsed.domain.empty() || !static_parsed.address.empty()) {
                if (!is_supported_static_dns_domain(static_parsed.domain)) {
                    continue;
                }
                try {
                    (void)parse_dns_address_str(static_parsed.address);
                } catch (const DnsError& e) {
                    throw KeeneticDnsError(
                        "RCI returned invalid static dns address '" + static_parsed.address + "': " + e.what());
                }
                static_entries.push_back({static_parsed.domain, static_parsed.address});
                continue;
            }

            ParsedDnsServerLine parsed = parse_dns_server_line(trimmed);
            if (parsed.address.empty()) {
                continue;
            }
            if (looks_like_ipv6_dns_server_address(parsed.address)) {
                continue;
            }

            try {
                (void)parse_dns_address_str(parsed.address);
            } catch (const DnsError& e) {
                throw KeeneticDnsError(
                    "RCI returned invalid dns_server address '" + parsed.address + "': " + e.what());
            }

            if (parsed.has_specific_domains) {
                continue;
            }
            if (parsed.is_encrypted) {
                unscoped_encrypted_servers.push_back(parsed);
            } else {
                unscoped_plaintext_servers.push_back(parsed);
            }
        }

        if (!unscoped_plaintext_servers.empty() || !unscoped_encrypted_servers.empty()) {
            return build_keenetic_dns_snapshot(
                collect_selected_keenetic_dns_servers(
                    unscoped_plaintext_servers,
                    unscoped_encrypted_servers),
                std::move(static_entries));
        }
        throw KeeneticDnsError(
            "Built-in DNS proxy appears disabled or has no unscoped 'dns_server = ...' directives in System policy");
    }

    throw KeeneticDnsError(
        "RCI response does not contain DNS proxy policy 'System' (endpoint: /rci/show/dns-proxy)");
}

KeeneticDnsCache::KeeneticDnsCache(FetchFn fetch_fn,
                                   Clock::duration cache_ttl,
                                   Clock::duration failure_retry,
                                   NowFn now_fn)
    : fetch_fn_(std::move(fetch_fn)),
      now_fn_(std::move(now_fn)),
      cache_ttl_(cache_ttl),
      failure_retry_(failure_retry) {
    if (!fetch_fn_) {
        throw std::invalid_argument("Keenetic DNS fetch function is required");
    }
    if (!now_fn_) {
        now_fn_ = [] {
            return Clock::now();
        };
    }
}

KeeneticDnsCacheView KeeneticDnsCache::snapshot_locked(bool refreshed,
                                                       bool changed) const {
    auto effective_status = status_;
    if (snapshot_ &&
        effective_status == KeeneticDnsCacheStatus::fresh &&
        now_fn_() >= refresh_after_) {
        effective_status = KeeneticDnsCacheStatus::stale;
    }
    return {
        snapshot_,
        snapshot_ ? effective_status : KeeneticDnsCacheStatus::unavailable,
        refreshed,
        changed,
        refresh_generation_,
        last_error_,
    };
}

KeeneticDnsCacheView KeeneticDnsCache::peek() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_locked();
}

KeeneticDnsCacheView KeeneticDnsCache::get() {
    return get_impl(false);
}

KeeneticDnsCacheView KeeneticDnsCache::force_refresh() {
    return get_impl(true);
}

void KeeneticDnsCache::invalidate() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++invalidation_epoch_;
    status_ = snapshot_ ? KeeneticDnsCacheStatus::stale
                        : KeeneticDnsCacheStatus::unavailable;
    refresh_after_ = Clock::time_point{};
    forced_refresh_after_ = Clock::time_point{};
    last_error_.clear();
}

KeeneticDnsCacheView KeeneticDnsCache::get_impl(bool force_refresh) {
    std::unique_lock<std::mutex> lock(mutex_);
    for (;;) {
        const auto now = now_fn_();
        if (refresh_attempted_ &&
            ((!force_refresh && now < refresh_after_) ||
             (force_refresh && now < forced_refresh_after_))) {
            return snapshot_locked();
        }

        if (refresh_in_progress_) {
            const auto observed_generation = refresh_generation_;
            refresh_finished_.wait(
                lock,
                [this, observed_generation] {
                    return refresh_generation_ != observed_generation;
                });
            // An observer that arrived after invalidation must not accept
            // completion of a request from the previous topology epoch.
            if (last_completed_refresh_epoch_ != invalidation_epoch_) {
                continue;
            }
            return snapshot_locked(last_refresh_accepted_,
                                   last_refresh_changed_);
        }

        refresh_in_progress_ = true;
        const auto fetch_invalidation_epoch = invalidation_epoch_;
        lock.unlock();

        std::optional<KeeneticDnsSnapshot> fetched_snapshot;
        std::string fetch_error;
        try {
            // RCI I/O and JSON parsing deliberately happen without mutex_.
            fetched_snapshot =
                extract_keenetic_dns_snapshot_from_rci(fetch_fn_());
        } catch (const HttpError& e) {
            fetch_error =
                "Failed to query Keenetic RCI endpoint /rci/show/dns-proxy: " +
                std::string(e.what());
        } catch (const KeeneticDnsError& e) {
            fetch_error = e.what();
        } catch (const std::exception& e) {
            fetch_error =
                "Failed to refresh Keenetic DNS snapshot: " +
                std::string(e.what());
        } catch (...) {
            fetch_error = "Failed to refresh Keenetic DNS snapshot: unknown error";
        }
        lock.lock();
        const auto completed_at = now_fn_();
        refresh_attempted_ = true;
        const bool refresh_epoch_is_current =
            fetch_invalidation_epoch == invalidation_epoch_;
        const bool refresh_accepted =
            fetched_snapshot.has_value() && refresh_epoch_is_current;
        bool refresh_changed = false;
        if (refresh_accepted) {
            refresh_changed =
                !snapshot_ ||
                !keenetic_dns_snapshots_equal(*snapshot_, *fetched_snapshot);
            snapshot_ = std::move(*fetched_snapshot);
            status_ = KeeneticDnsCacheStatus::fresh;
            refresh_after_ = completed_at + cache_ttl_;
            last_error_.clear();
        } else {
            status_ = snapshot_ ? KeeneticDnsCacheStatus::stale
                                : KeeneticDnsCacheStatus::unavailable;
            refresh_after_ = refresh_epoch_is_current
                ? completed_at + failure_retry_
                : Clock::time_point{};
            if (refresh_epoch_is_current) {
                last_error_ = std::move(fetch_error);
            }
        }

        if (!refresh_epoch_is_current) {
            forced_refresh_after_ = Clock::time_point{};
        } else if (!fetched_snapshot) {
            forced_refresh_after_ = completed_at + failure_retry_;
        } else {
            // A successful explicit refresh must not suppress a subsequent
            // explicit observation. Only failures are retry-throttled.
            forced_refresh_after_ = Clock::time_point{};
        }

        refresh_in_progress_ = false;
        last_refresh_accepted_ = refresh_accepted;
        last_refresh_changed_ = refresh_changed;
        last_completed_refresh_epoch_ = fetch_invalidation_epoch;
        ++refresh_generation_;
        auto result = snapshot_locked(refresh_accepted, refresh_changed);
        lock.unlock();
        refresh_finished_.notify_all();
        return result;
    }
}

#ifdef KEEN_PBR3_TESTING
void KeeneticDnsCache::reset_for_tests() {
    std::unique_lock<std::mutex> lock(mutex_);
    refresh_finished_.wait(lock, [this] {
        return !refresh_in_progress_;
    });
    snapshot_.reset();
    status_ = KeeneticDnsCacheStatus::unavailable;
    refresh_after_ = Clock::time_point{};
    forced_refresh_after_ = Clock::time_point{};
    refresh_attempted_ = false;
    last_refresh_accepted_ = false;
    last_refresh_changed_ = false;
    refresh_generation_ = 0;
    invalidation_epoch_ = 0;
    last_completed_refresh_epoch_ = 0;
    last_error_.clear();
}
#endif

KeeneticDnsCache& shared_keenetic_dns_cache() {
#ifdef KEEN_PBR3_TESTING
    static KeeneticDnsCache cache(
        fetch_keenetic_dns_for_shared_cache,
        kKeeneticDnsCacheTtl,
        kKeeneticDnsFailureRetry,
        now_for_shared_keenetic_dns_cache);
#else
    static KeeneticDnsCache cache(
        fetch_keenetic_dns_via_rci,
        kKeeneticDnsCacheTtl,
        kKeeneticDnsFailureRetry);
#endif
    return cache;
}

KeeneticDnsRefreshResult refresh_keenetic_dns_address_cache(bool force_refresh) {
#ifdef USE_KEENETIC_API
    const auto view = force_refresh
        ? shared_keenetic_dns_cache().force_refresh()
        : shared_keenetic_dns_cache().get();
    if (!view.snapshot) {
        return {
            KeeneticDnsRefreshStatus::FETCH_FAILED_NO_CACHE,
            {},
            view.error,
            std::nullopt,
            view.generation,
        };
    }

    KeeneticDnsRefreshStatus status = KeeneticDnsRefreshStatus::UNCHANGED;
    if (view.refreshed && view.changed) {
        status = KeeneticDnsRefreshStatus::UPDATED;
    } else if (view.status == KeeneticDnsCacheStatus::stale) {
        status = KeeneticDnsRefreshStatus::FETCH_FAILED_USED_CACHE;
    }
    return {
        status,
        view.snapshot->addresses,
        view.error,
        view.snapshot,
        view.generation,
    };
#else
    (void)force_refresh;
    return {
        KeeneticDnsRefreshStatus::FETCH_FAILED_NO_CACHE,
        {},
        "DNS server type 'keenetic' requires build with USE_KEENETIC_API=ON",
        std::nullopt,
        0,
    };
#endif
}

std::vector<std::string> resolve_keenetic_dns_addresses(bool force_refresh) {
    const KeeneticDnsRefreshResult result = refresh_keenetic_dns_address_cache(force_refresh);
    if (!result.addresses.empty()) {
        return result.addresses;
    }
    throw KeeneticDnsError(result.error);
}

std::vector<KeeneticStaticDnsEntry> get_keenetic_static_dns_entries() {
    const auto view = shared_keenetic_dns_cache().peek();
    if (!view.snapshot) {
        return {};
    }
    return view.snapshot->static_entries;
}

std::vector<std::string> get_keenetic_dns_addresses() {
    const auto view = shared_keenetic_dns_cache().peek();
    if (!view.snapshot) {
        return {};
    }
    return view.snapshot->addresses;
}

std::vector<KeeneticDnsUpstreamEntry> get_keenetic_dns_upstreams() {
    const auto view = shared_keenetic_dns_cache().peek();
    if (!view.snapshot) {
        return {};
    }
    return view.snapshot->upstreams;
}

#ifdef KEEN_PBR3_TESTING
void set_keenetic_dns_fetcher_for_tests(KeeneticDnsFetchFn fetcher) {
    std::lock_guard<std::mutex> lock(keenetic_dns_test_hooks_mutex());
    keenetic_dns_test_fetch_fn() = std::move(fetcher);
}

void set_keenetic_dns_now_fn_for_tests(KeeneticDnsNowFn now_fn) {
    std::lock_guard<std::mutex> lock(keenetic_dns_test_hooks_mutex());
    keenetic_dns_test_now_fn() = std::move(now_fn);
}

void reset_keenetic_dns_test_state() {
    {
        std::lock_guard<std::mutex> lock(keenetic_dns_test_hooks_mutex());
        keenetic_dns_test_fetch_fn() = fetch_keenetic_dns_via_rci;
        keenetic_dns_test_now_fn() = [] {
            return std::chrono::steady_clock::now();
        };
    }
    shared_keenetic_dns_cache().reset_for_tests();
}
#endif

} // namespace keen_pbr3
