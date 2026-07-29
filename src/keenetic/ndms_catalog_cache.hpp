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
    NdmsCatalogCacheStatus status_{NdmsCatalogCacheStatus::unavailable};
    Clock::time_point refresh_after_{};
    Clock::time_point forced_refresh_after_{};
    bool refresh_attempted_{false};
    bool refresh_in_progress_{false};
    bool last_refresh_accepted_{false};
    std::uint64_t refresh_generation_{0};
    std::uint64_t invalidation_epoch_{0};
    std::uint64_t last_completed_refresh_epoch_{0};
};

// Shared by the daemon runtime and the API inventory. This prevents duplicate
// RCI polling and gives control-loop code a cache-only peek path.
NdmsCatalogCache& shared_ndms_catalog_cache();

} // namespace keen_pbr3
