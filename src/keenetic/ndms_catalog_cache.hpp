#pragma once

#include "ndms_interface_inventory.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>

namespace keen_pbr3 {

enum class NdmsCatalogCacheStatus : std::uint8_t {
    fresh,
    stale,
    unavailable,
};

struct NdmsCatalogSnapshot {
    NdmsInterfaceCatalog catalog;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    // True only when this call observed a completed refresh generation
    // instead of receiving a TTL/throttle cache hit or peek. Authority is
    // represented by status=fresh: a recently verified cache hit remains
    // authoritative even though this particular call did not perform I/O.
    bool refreshed{false};
    // Steady instant this catalog was actually read from the firmware.
    //
    // Every live counter it carries is a "for the last N seconds" duration, so
    // it is only convertible into an instant together with this stamp - and a
    // snapshot served from cache can be a whole TTL older than the moment a
    // caller consumes it. Steady rather than wall on purpose: it is used to
    // derive durations, and this router has no battery-backed RTC, so the wall
    // clock steps once NTP catches up.
    std::optional<std::chrono::steady_clock::time_point> observed_at;

    // Monotonic process-local identity of the last catalog accepted from
    // firmware. It advances only when a parsed response belongs to the
    // current invalidation epoch. Cache hits, failed refreshes and rejected
    // pre-invalidation completions retain the previous value. Zero means no
    // catalog has ever been accepted by this cache instance.
    std::uint64_t observation_generation{0};

    // Topology epoch in which the retained catalog was accepted, and the
    // cache's current topology epoch respectively. After invalidate(), a
    // retained last-known-good catalog intentionally has
    // observation_epoch < invalidation_epoch until a replacement observation
    // is accepted. These are safe process-local counters, not firmware
    // revisions and not mutation authorization.
    std::uint64_t observation_epoch{0};
    std::uint64_t invalidation_epoch{0};
};

// Thread-safe, single-flight cache for the loopback NDMS request. Failed
// refreshes never replace the most recent catalog that parsed successfully.
// peek() is deliberately non-blocking with respect to network I/O so runtime
// reconciliation can use the last safe snapshot from the control loop.
class NdmsCatalogCache {
public:
    using Clock = std::chrono::steady_clock;
    using FetchFn = std::function<std::string()>;
    using NowFn = std::function<Clock::time_point()>;

    explicit NdmsCatalogCache(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {});

    NdmsCatalogSnapshot get();
    // Requests a fresh RCI observation even while the regular TTL is valid.
    // Repeated forced refreshes are still throttled by failure_retry_ and
    // concurrent callers share one in-flight request.
    NdmsCatalogSnapshot force_refresh();
    // Invalidates catalog authority without performing I/O. Interface events
    // call this before their cache-only reconciliation so a recently cached
    // kernel binding cannot be reused after an NDMS renumber/name-reuse event.
    // The next forced refresh is allowed immediately.
    void invalidate();
    NdmsCatalogSnapshot peek() const;

private:
    NdmsCatalogSnapshot get_impl(bool force_refresh);
    NdmsCatalogSnapshot snapshot_locked(bool refreshed = false) const;

    FetchFn fetch_fn_;
    NowFn now_fn_;
    Clock::duration cache_ttl_;
    Clock::duration failure_retry_;

    mutable std::mutex mutex_;
    std::condition_variable refresh_finished_;
    std::optional<NdmsInterfaceCatalog> catalog_;
    std::optional<Clock::time_point> catalog_observed_at_;
    NdmsCatalogCacheStatus status_{NdmsCatalogCacheStatus::unavailable};
    Clock::time_point refresh_after_{};
    Clock::time_point forced_refresh_after_{};
    bool refresh_attempted_{false};
    bool refresh_in_progress_{false};
    bool last_refresh_accepted_{false};
    std::uint64_t refresh_generation_{0};
    std::uint64_t invalidation_epoch_{0};
    std::uint64_t last_completed_refresh_epoch_{0};
    std::uint64_t accepted_observation_generation_{0};
    std::uint64_t accepted_observation_epoch_{0};
};

// Shared by the daemon runtime and the API inventory. This prevents duplicate
// RCI polling and gives control-loop code a cache-only peek path.
NdmsCatalogCache& shared_ndms_catalog_cache();

} // namespace keen_pbr3
