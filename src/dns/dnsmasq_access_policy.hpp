#pragma once

#include "../config/config.hpp"
#include "../keenetic/internal_vpn_runtime_target.hpp"

#include <string>
#include <vector>

namespace keen_pbr3 {

bool is_safe_dnsmasq_interface_selector(
    const std::string& selector) noexcept;

// Build the dnsmasq interface allowlist needed for native Keenetic VPN
// servers. dnsmasq's local-service=net accepts only directly connected
// subnets, so it rejects pooled SSTP/IKE/L2TP/OpenConnect clients even when
// NDMS forwarding and SNAT are correct. An explicit interface allowlist makes
// dnsmasq use interface access control instead, while keeping WAN interfaces
// excluded.
//
// The inputs must be the already resolved runtime inventory. Persisted service
// IDs alone are intentionally insufficient: stale or unverified NDMS objects
// must never broaden DNS admission. Pooled services carry the same exact,
// live server-ingress ownership used by the firewall; no VPN wildcard is
// accepted here.
std::vector<std::string> build_dnsmasq_trusted_interfaces(
    const std::vector<InternalVpnServer>& interface_servers,
    const std::vector<InternalVpnRuntimeTarget>& service_targets);

} // namespace keen_pbr3
