#pragma once

#include "../config/config.hpp"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

enum class InternalVpnRuntimeMatchKind : std::uint8_t {
    interface,
    source_pool,
};

struct InternalVpnVerifiedBridgeIngress {
    std::string interface;
    std::string bridge_port;

    bool operator==(
        const InternalVpnVerifiedBridgeIngress& other) const {
        return interface == other.interface &&
               bridge_port == other.bridge_port;
    }
};

// Runtime-only, verified ingress selector. Persisted configuration stores a
// stable NDMS identity; source pools are always re-derived from a fresh,
// bounded firmware observation.
struct InternalVpnRuntimeTarget {
    std::string stable_id;
    InternalVpnRuntimeMatchKind match_kind{
        InternalVpnRuntimeMatchKind::interface};
    bool process_clients{true};
    // Stable NDMS binding retained for diagnostics and reconciliation. It is
    // not trusted as a kernel interface until the current Netlink inventory
    // verifies an exact match in `interface`.
    std::optional<std::string> bound_interface_id;
    std::optional<std::string> interface;
    // Exact, live kernel interfaces verified as server-owned ingress for a
    // source-pool service. This runtime-only set is used by both firewall and
    // dnsmasq policy; a firmware LAN binding such as br0 is never copied here.
    std::vector<std::string> verified_ingress_interfaces;
    // Exact L3 bridge plus its verified server-owned physical bridge port.
    // This is required for a safe SSTP bypass on a bridge shared with LAN:
    // neither the bridge name nor the source pool alone proves ownership.
    std::vector<InternalVpnVerifiedBridgeIngress>
        verified_bridge_ingress_interfaces;
    // Exact verified ingress interfaces where NAT REDIRECT cannot safely
    // select a local resolver address for the corresponding family. IKE
    // xfrms devices are normally addressless. Such clients still participate
    // in keen-pbr routing, but their DNS packets must continue through the
    // native Keenetic resolver path instead of being redirected to an
    // unusable address.
    std::vector<std::string> dns_redirect_bypass_ingress_v4;
    std::vector<std::string> dns_redirect_bypass_ingress_v6;
    std::vector<std::string> source_cidrs_v4;
    std::vector<std::string> source_cidrs_v6;
};

inline InternalVpnRuntimeTarget internal_vpn_interface_runtime_target(
    const InternalVpnServer& server) {
    InternalVpnRuntimeTarget target;
    target.stable_id = server.ndms_id.has_value()
        ? "ndms-interface:" + *server.ndms_id
        : "kernel-interface:" + server.interface;
    target.match_kind = InternalVpnRuntimeMatchKind::interface;
    target.process_clients = server.process_clients;
    target.interface = server.interface;
    return target;
}

inline std::vector<InternalVpnRuntimeTarget>
internal_vpn_interface_runtime_targets(
    const std::vector<InternalVpnServer>& servers) {
    std::vector<InternalVpnRuntimeTarget> result;
    result.reserve(servers.size());
    for (const auto& server : servers) {
        result.push_back(internal_vpn_interface_runtime_target(server));
    }
    return result;
}

} // namespace keen_pbr3
