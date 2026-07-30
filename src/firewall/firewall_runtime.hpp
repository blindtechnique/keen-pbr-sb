#pragma once

#include "../cache/cache_manager.hpp"
#include "../config/config.hpp"
#include "../keenetic/internal_vpn_runtime_target.hpp"
#include "../routing/firewall_state.hpp"
#include "firewall.hpp"

#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Materialize the runtime firewall configuration using the real backend.
// Returns the realized rule-state snapshot that should be stored for later
// verification and status reporting.
std::vector<RuleState> apply_runtime_firewall(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::map<std::string, std::string>& urltest_selections,
    const CacheManager& cache_manager,
    Firewall& firewall,
    FirewallApplyMode mode,
    const std::vector<InternalVpnServer>*
        effective_internal_vpn_servers = nullptr,
    const std::vector<InternalVpnRuntimeTarget>*
        effective_internal_vpn_targets = nullptr);

// Build the source-scoped direct-egress SNAT contract for Keenetic's SSTP
// server. SSTP clients need this on the ordinary WAN path regardless of
// whether policy routing is enabled for them. Other native VPN services are
// deliberately excluded so their existing firmware/runtime paths remain
// unchanged.
std::vector<FirewallSourceEgressSnatSelector>
select_sstp_direct_egress_snat_selectors(
    const std::vector<InternalVpnRuntimeTarget>& internal_vpn_targets,
    const std::vector<std::string>& wan_interfaces);

// Runtime convenience overload. It uses the same current main-table default
// route inventory as the nfqws WAN configuration.
std::vector<FirewallSourceEgressSnatSelector>
select_sstp_direct_egress_snat_selectors(
    const std::vector<InternalVpnRuntimeTarget>& internal_vpn_targets);

} // namespace keen_pbr3
