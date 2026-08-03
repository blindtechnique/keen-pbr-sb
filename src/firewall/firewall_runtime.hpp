#pragma once

#include "../cache/cache_manager.hpp"
#include "../config/config.hpp"
#include "../dns/keenetic_dns.hpp"
#include "../keenetic/internal_vpn_runtime_target.hpp"
#include "../lists/list_set_usage.hpp"
#include "../routing/firewall_state.hpp"
#include "firewall.hpp"

#include <map>
#include <optional>
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
        effective_internal_vpn_targets = nullptr,
    const std::vector<FirewallSourceEgressSnatSelector>*
        native_vpn_direct_egress_snat_selectors = nullptr,
    AppliedListContentState* applied_list_content_state = nullptr,
    bool udp_call_affinity_ipset_available = true,
    const std::optional<KeeneticDnsSnapshot>& keenetic_dns_snapshot =
        std::nullopt);

// Build the source-scoped direct-egress SNAT contract for Keenetic's SSTP,
// L2TP and IKEv1 servers. Their clients need this on the ordinary WAN path
// regardless of whether policy routing is enabled for them. Other native VPN
// services are deliberately excluded so their established firmware/runtime
// paths remain unchanged.
std::vector<FirewallSourceEgressSnatSelector>
select_native_vpn_direct_egress_snat_selectors(
    const std::vector<InternalVpnRuntimeTarget>& internal_vpn_targets,
    const std::vector<std::string>& wan_interfaces);

// Runtime convenience overload. It uses the same current main-table default
// route inventory as the nfqws WAN configuration.
std::vector<FirewallSourceEgressSnatSelector>
select_native_vpn_direct_egress_snat_selectors(
    const std::vector<InternalVpnRuntimeTarget>& internal_vpn_targets);

// Return only source pools whose exact (egress, CIDR) contract changed.
// Reordering or adding another service must not retire unrelated live flows.
std::vector<std::string>
changed_native_vpn_direct_egress_source_cidrs(
    const std::vector<FirewallSourceEgressSnatSelector>& previous,
    const std::vector<FirewallSourceEgressSnatSelector>& current);

} // namespace keen_pbr3
