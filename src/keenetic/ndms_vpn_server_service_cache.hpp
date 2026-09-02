#pragma once

#include "ndms_catalog_cache.hpp"
#include "ndms_running_config_resource.hpp"
#include "ndms_vpn_server_service.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace keen_pbr3 {

struct NdmsVpnServerServiceSnapshot {
    NdmsVpnServerServiceCatalog catalog;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    bool refreshed{false};
    bool changed{false};
    // Exact raw running-config content generation from which catalog was
    // parsed. Zero means that no typed projection has been accepted.
    std::uint64_t source_content_generation{0};
    std::uint64_t source_observation_generation{0};
};

// Typed, non-secret projection of the sole running-config resource. Both the
// daemon and Web API consume this projection; it performs no independent RCI
// I/O and reparses only when the raw content generation changes.
class NdmsVpnServerServiceCache {
public:
    using Clock = NdmsRunningConfigResource::Clock;
    using FetchFn = NdmsRunningConfigResource::FetchFn;
    using NowFn = NdmsRunningConfigResource::NowFn;

    // Compatibility/test constructor. The created raw owner still follows the
    // same single-flight/LKG contract as the production shared resource.
    explicit NdmsVpnServerServiceCache(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {});

    explicit NdmsVpnServerServiceCache(
        NdmsRunningConfigResource& resource);

    NdmsVpnServerServiceSnapshot get();
    NdmsVpnServerServiceSnapshot force_refresh();
    void invalidate();
    NdmsVpnServerServiceSnapshot peek() const;

private:
    NdmsVpnServerServiceSnapshot project(
        const NdmsRunningConfigSnapshot& raw) const;
    NdmsVpnServerServiceSnapshot snapshot_locked(
        const NdmsRunningConfigSnapshot& raw,
        bool refreshed = false,
        bool changed = false) const;

    std::unique_ptr<NdmsRunningConfigResource> owned_resource_;
    NdmsRunningConfigResource* resource_{nullptr};

    mutable std::mutex mutex_;
    mutable std::optional<NdmsVpnServerServiceCatalog> catalog_;
    mutable std::uint64_t source_content_generation_{0};
    mutable std::uint64_t source_observation_generation_{0};
    mutable std::uint64_t attempted_content_generation_{0};
};

NdmsVpnServerServiceCache& shared_ndms_vpn_server_service_cache();

} // namespace keen_pbr3
