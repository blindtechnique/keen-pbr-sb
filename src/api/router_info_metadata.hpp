#pragma once

#include "router_info_cache.hpp"
#include "../routing/interface_monitor.hpp"

#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Router overview observations have independent failure domains. This is a
// projection of the existing caches, not a new cache/worker or mutation owner.
class RouterInfoMetadata {
public:
    using RciGetFn = std::function<std::optional<nlohmann::json>(const std::string&)>;
    using VersionGetFn = std::function<nlohmann::json()>;

    RouterInfoMetadata(RciGetFn rci_get, VersionGetFn version_get,
                       RouterInfoCache::NowFn now = {});
    nlohmann::json get();
    // Only marks the affected observations dirty. No RCI/network activity in
    // a netlink callback; the next ordinary API reader performs the refresh.
    bool invalidate(const InterfaceMonitor::Event& event);

private:
    RouterInfoCache::FetchResult fetch_wan();
    RouterInfoCache::FetchResult fetch_clients();

    RciGetFn rci_get_;
    VersionGetFn version_get_;
    RouterInfoCache wan_;
    RouterInfoCache clients_;
};

} // namespace keen_pbr3
