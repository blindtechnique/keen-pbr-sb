#pragma once

#include "../config/config.hpp"
#include "../keenetic/internal_vpn_runtime_target.hpp"

#include <optional>
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

// A foreground lifecycle operation may prepare a native-VPN inventory before
// publishing it globally. Prefer its exact, already validated access policy so
// the resolver generation and its hash cannot be built from stale globals.
std::vector<std::string> select_dnsmasq_trusted_interfaces(
    std::optional<std::vector<std::string>> prepared_override,
    const std::vector<InternalVpnServer>& fallback_interface_servers,
    const std::vector<InternalVpnRuntimeTarget>& fallback_service_targets);

} // namespace keen_pbr3
