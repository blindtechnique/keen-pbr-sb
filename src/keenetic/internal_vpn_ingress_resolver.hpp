#pragma once

#include "internal_vpn_runtime_target.hpp"
#include "../routing/netlink.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

// Resolve only kernel interfaces that are owned by a native Keenetic VPN
// server. Firmware LAN bindings (for example Bridge0 -> br0) are not ingress
// ownership proof for pooled SSTP/L2TP/IKE clients and are intentionally
// ignored here.
std::vector<std::string> resolve_internal_vpn_service_ingress_interfaces(
    const InternalVpnRuntimeTarget& target,
    const std::vector<DumpedInterface>& live_interfaces);

// Refresh runtime-only interface ownership after every authoritative service
// resolution and after relevant Netlink changes. Persisted configuration
// remains stable and never stores these ephemeral kernel names.
void refresh_internal_vpn_service_ingress_interfaces(
    std::vector<InternalVpnRuntimeTarget>& targets,
    const std::vector<DumpedInterface>& live_interfaces);

// Used only to decide whether a Netlink event warrants reconciliation. The
// actual admission decision still requires the exact resolver above.
bool internal_vpn_service_interface_may_affect_ingress(
    std::string_view interface) noexcept;

} // namespace keen_pbr3
