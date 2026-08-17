#pragma once

#include "../config/config.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

class KeeneticDnsError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct KeeneticStaticDnsEntry {
    std::string domain;
    std::string address;
};

struct KeeneticDnsUpstreamEntry {
    std::string address;
    std::string kind;
    std::string target;
};

struct KeeneticDnsSnapshot {
    std::vector<std::string> addresses;
    std::vector<KeeneticDnsUpstreamEntry> upstreams;
    std::vector<KeeneticStaticDnsEntry> static_entries;
};

inline void swap(KeeneticDnsSnapshot& lhs,
                 KeeneticDnsSnapshot& rhs) noexcept {
    using std::swap;
    swap(lhs.addresses, rhs.addresses);
    swap(lhs.upstreams, rhs.upstreams);
    swap(lhs.static_entries, rhs.static_entries);
}

// Compare the complete DNS proxy snapshots as one coherent unit.  Callers
// must not compare only addresses because static entries and upstream
// metadata belong to the same RCI generation.
bool keenetic_dns_snapshots_equal(const KeeneticDnsSnapshot& lhs,
                                  const KeeneticDnsSnapshot& rhs);

// Keep all runtime consumers on one predicate instead of independently
// scanning the generated DNS config model.
bool dns_config_uses_keenetic_server(const DnsConfig& dns_config);

enum class KeeneticDnsCacheStatus : uint8_t {
    fresh,
    stale,
    unavailable,
};

struct KeeneticDnsCacheView {
    std::optional<KeeneticDnsSnapshot> snapshot;
    KeeneticDnsCacheStatus status{KeeneticDnsCacheStatus::unavailable};
    // True only when this call observed a successfully accepted refresh.
    bool refreshed{false};
    // True only when the accepted refresh changed the cached snapshot.
    bool changed{false};
    std::uint64_t generation{0};
    std::string error;
};

// GCC 8's libstdc++ does not infer the noexcept guarantee through
// optional<KeeneticDnsSnapshot> consistently. Keep an explicit ADL swap so
// the DNS refresh transaction has the same non-throwing rollback contract on
// the Keenetic toolchain as it does on current host compilers.
inline void swap(KeeneticDnsCacheView& lhs,
                 KeeneticDnsCacheView& rhs) noexcept {
    using std::swap;
    swap(lhs.snapshot, rhs.snapshot);
    swap(lhs.status, rhs.status);
    swap(lhs.refreshed, rhs.refreshed);
    swap(lhs.changed, rhs.changed);
    swap(lhs.generation, rhs.generation);
    swap(lhs.error, rhs.error);
}

// Thread-safe single-flight cache for Keenetic's built-in DNS proxy snapshot.
// Fetching and parsing happen outside mutex_, so cache-only readers never wait
// for loopback RCI I/O. Failed refreshes preserve the last known-good snapshot.
class KeeneticDnsCache {
public:
    using Clock = std::chrono::steady_clock;
    using FetchFn = std::function<std::string()>;
    using NowFn = std::function<Clock::time_point()>;

    explicit KeeneticDnsCache(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::minutes(5),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {});

    KeeneticDnsCacheView get();
    KeeneticDnsCacheView force_refresh();
    KeeneticDnsCacheView peek() const;
    void invalidate();

#ifdef KEEN_PBR3_TESTING
    void reset_for_tests();
#endif

private:
    KeeneticDnsCacheView get_impl(bool force_refresh);
    KeeneticDnsCacheView snapshot_locked(bool refreshed = false,
                                         bool changed = false) const;

    FetchFn fetch_fn_;
    NowFn now_fn_;
    Clock::duration cache_ttl_;
    Clock::duration failure_retry_;

    mutable std::mutex mutex_;
    std::condition_variable refresh_finished_;
    std::optional<KeeneticDnsSnapshot> snapshot_;
    KeeneticDnsCacheStatus status_{KeeneticDnsCacheStatus::unavailable};
    Clock::time_point refresh_after_{};
    Clock::time_point forced_refresh_after_{};
    bool refresh_attempted_{false};
    bool refresh_in_progress_{false};
    bool last_refresh_accepted_{false};
    bool last_refresh_changed_{false};
    std::uint64_t refresh_generation_{0};
    std::uint64_t invalidation_epoch_{0};
    std::uint64_t last_completed_refresh_epoch_{0};
    std::string last_error_;
};

KeeneticDnsCache& shared_keenetic_dns_cache();

// RCI endpoint used as source of truth for the built-in DNS proxy:
// GET http://127.0.0.1:79/rci/show/dns-proxy
//
// We read proxy-status entry with proxy-name == "System" and only consider
// unscoped "dns_server = ..." directives. Domain-scoped entries are ignored.
// When the System policy has unscoped encrypted resolvers, we use all of them
// in order. Otherwise we fall back to all unscoped plaintext resolvers.
KeeneticDnsSnapshot extract_keenetic_dns_snapshot_from_rci(const std::string& response_body);

enum class KeeneticDnsRefreshStatus : uint8_t {
    UNCHANGED,
    UPDATED,
    FETCH_FAILED_USED_CACHE,
    FETCH_FAILED_NO_CACHE,
};

struct KeeneticDnsRefreshResult {
    KeeneticDnsRefreshStatus status{KeeneticDnsRefreshStatus::FETCH_FAILED_NO_CACHE};
    std::vector<std::string> addresses;
    std::string error;
    std::optional<KeeneticDnsSnapshot> snapshot;
    std::uint64_t generation{0};
};

// Refresh the coherent built-in DNS proxy snapshot via Keenetic RCI.
// When a previously cached value exists, fetch failures keep that exact
// snapshot intact.  The returned generation identifies the completed cache
// observation and lets consumers reject older prepared snapshots.
KeeneticDnsRefreshResult refresh_keenetic_dns_address_cache(bool force_refresh = false);

// Resolve built-in DNS server addresses via Keenetic RCI.
// Uses a 5-minute cache, attempts a refetch when the cache is stale or when
// force_refresh=true, and falls back to the previously cached value on fetch
// failures when possible.
// Throws KeeneticDnsError only when no usable cached value exists.
std::vector<std::string> resolve_keenetic_dns_addresses(bool force_refresh = false);

// Return the cached static_a/static_aaaa entries extracted from Keenetic RCI.
// Returns an empty vector when no Keenetic DNS snapshot has been cached yet.
std::vector<KeeneticStaticDnsEntry> get_keenetic_static_dns_entries();
std::vector<std::string> get_keenetic_dns_addresses();
std::vector<KeeneticDnsUpstreamEntry> get_keenetic_dns_upstreams();

#ifdef KEEN_PBR3_TESTING
using KeeneticDnsFetchFn = std::function<std::string()>;
using KeeneticDnsNowFn = std::function<std::chrono::steady_clock::time_point()>;

void set_keenetic_dns_fetcher_for_tests(KeeneticDnsFetchFn fetcher);
void set_keenetic_dns_now_fn_for_tests(KeeneticDnsNowFn now_fn);
void reset_keenetic_dns_test_state();
#endif

} // namespace keen_pbr3
