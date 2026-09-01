#pragma once

#include "internal_vpn_runtime_resolution.hpp"
#include "runtime_internal_vpn_lkg_store.hpp"
#include "../keenetic/ndms_catalog_cache.hpp"
#include "../keenetic/ndms_vpn_server_service_cache.hpp"
#include "../routing/netlink.hpp"

#include <algorithm>
#include <stdexcept>
#include <vector>

namespace keen_pbr3 {

inline bool config_has_stable_internal_vpn_server_policy(
    const Config& config) {
    const auto configured = config.route.has_value()
        ? config.route->internal_vpn_servers.value_or(
              std::vector<InternalVpnServer>{})
        : std::vector<InternalVpnServer>{};
    return std::any_of(
        configured.begin(), configured.end(), [](const auto& server) {
            return server.ndms_id.has_value();
        });
}

inline bool config_requires_internal_vpn_service_inventory(
    const Config& config) {
    if (!config.route.has_value()) return false;
    const auto services = config.route->internal_vpn_services.value_or(
        std::vector<InternalVpnService>{});
    if (!services.empty()) return true;
    // With an explicit ingress allowlist, unconfigured native service pools
    // inherit bypass. They must be observed to keep a shared Home/Bridge
    // ingress from accidentally opting those clients into keen-pbr.
    return config.route->inbound_interfaces.has_value() &&
           !config.route->inbound_interfaces->empty();
}

inline bool config_has_native_vpn_catalog_policy(const Config& config) {
    return config_has_stable_internal_vpn_server_policy(config) ||
           config_requires_internal_vpn_service_inventory(config);
}

inline bool internal_vpn_resolution_requires_catalog_refresh(
    const Config& config,
    InternalVpnRuntimeResolutionState state) {
    return config_has_stable_internal_vpn_server_policy(config) &&
           state != InternalVpnRuntimeResolutionState::verified;
}

class InternalVpnResolutionError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Sole owner of the committed native-VPN runtime view and its verified,
// include-only LKG. The active pair is control-loop-only and changes only via
// the existing firewall publication fence. The LKG remains independently
// synchronized because off-loop preparation may snapshot it.
//
// This owner performs only pure interpretation of snapshots supplied by the
// caller. NDMS I/O, invalidation, retries, scheduling and runtime admission
// deliberately remain outside this class.
class InternalVpnResolutionCache final {
public:
    InternalVpnResolutionCache() = default;
    InternalVpnResolutionCache(const InternalVpnResolutionCache&) = delete;
    InternalVpnResolutionCache& operator=(
        const InternalVpnResolutionCache&) = delete;

    const std::vector<InternalVpnServer>& active_servers() const noexcept {
        return active_servers_;
    }
    const std::vector<InternalVpnRuntimeTarget>&
    active_service_targets() const noexcept {
        return active_service_targets_;
    }

    bool active_matches(
        const std::vector<InternalVpnServer>& servers,
        const std::vector<InternalVpnRuntimeTarget>& service_targets) const
        noexcept;

    // Allocation-free exact exchange used for both publication and rollback.
    void exchange_active(
        std::vector<InternalVpnServer>& servers,
        std::vector<InternalVpnRuntimeTarget>& service_targets) noexcept {
        active_servers_.swap(servers);
        active_service_targets_.swap(service_targets);
    }

    InternalVpnRuntimeResolution resolve_servers(
        const Config& config,
        const NdmsCatalogSnapshot& snapshot,
        const std::vector<DumpedInterface>& live_interfaces) const;

    InternalVpnServiceRuntimeResolution resolve_services(
        const Config& config,
        const NdmsVpnServerServiceSnapshot& snapshot,
        const std::vector<DumpedInterface>& live_interfaces) const;

    std::vector<InternalVpnServer> snapshot_verified_servers() const {
        return verified_lkg_.snapshot_servers();
    }
    std::vector<InternalVpnRuntimeTarget>
    snapshot_verified_service_targets() const {
        return verified_lkg_.snapshot_service_targets();
    }

    void update_verified_servers(
        const InternalVpnRuntimeResolution& resolution) noexcept;
    void update_verified_service_targets(
        const InternalVpnServiceRuntimeResolution& resolution) noexcept;

    RuntimeInternalVpnLkgPublication prepare_verified_publication(
        const InternalVpnRuntimeResolution& server_resolution,
        const InternalVpnServiceRuntimeResolution& service_resolution) const {
        return verified_lkg_.prepare_publication(
            server_resolution, service_resolution);
    }
    void exchange_verified_publication(
        RuntimeInternalVpnLkgPublication& publication) {
        verified_lkg_.exchange(publication);
    }

private:
    std::vector<InternalVpnServer> active_servers_;
    std::vector<InternalVpnRuntimeTarget> active_service_targets_;
    RuntimeInternalVpnLkgStore verified_lkg_;
};

} // namespace keen_pbr3
