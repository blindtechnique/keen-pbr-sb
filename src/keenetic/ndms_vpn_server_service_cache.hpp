#pragma once

#include "ndms_catalog_cache.hpp"
#include "ndms_vpn_server_service.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>

namespace keen_pbr3 {

struct NdmsVpnServerServiceSnapshot {
    NdmsVpnServerServiceCatalog catalog;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    bool refreshed{false};
};

// One shared, typed and single-flight observation of the VPN service sections
// in NDMS running-config. Both the daemon and Web API consume this cache, so
// opening Settings never starts a second polling loop.
class NdmsVpnServerServiceCache {
public:
    using Clock = std::chrono::steady_clock;
    using FetchFn = std::function<std::string()>;
    using NowFn = std::function<Clock::time_point()>;

    explicit NdmsVpnServerServiceCache(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {});

    NdmsVpnServerServiceSnapshot get();
    NdmsVpnServerServiceSnapshot force_refresh();
    void invalidate();
    NdmsVpnServerServiceSnapshot peek() const;

private:
    NdmsVpnServerServiceSnapshot get_impl(bool force_refresh);
    NdmsVpnServerServiceSnapshot snapshot_locked(
        bool refreshed = false) const;

    FetchFn fetch_fn_;
    NowFn now_fn_;
    Clock::duration cache_ttl_;
    Clock::duration failure_retry_;

    mutable std::mutex mutex_;
    std::condition_variable refresh_finished_;
    std::optional<NdmsVpnServerServiceCatalog> catalog_;
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

NdmsVpnServerServiceCache& shared_ndms_vpn_server_service_cache();

} // namespace keen_pbr3
