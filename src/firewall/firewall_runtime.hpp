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

// A firewall transaction that is fully described in memory but has not been
// handed to the kernel yet.
//
// The split exists because the commit step is the only part that spawns child
// processes - `ipset restore`, `iptables-restore`, `nft -f -` - each with a
// multi-second timeout and its own bounded retry. Staging primarily reads
// daemon state and fills backend buffers, although a legacy iptables prepare
// path may repair its ordinary mangle dispatcher. The strict Meta boundary is
// narrower: staging never publishes the Meta UDP/443 filter and never deletes
// conntrack tuples before the caller completes specialized preflight. Naming
// the boundary is what lets the commit later move off the control loop without
// the staging following it.
struct StagedRuntimeFirewall {
    // The realized rule-state snapshot to store for verification and status.
    std::vector<RuleState> rule_states;
    // Which list content this transaction was built from.
    AppliedListContentState list_content_state;
    // Carried through because the backend needs the same mode for both
    // `prepare_apply()` during staging and `apply()` at commit; splitting them
    // across two different modes would build one transaction and commit
    // another.
    FirewallApplyMode mode{FirewallApplyMode::Destructive};
};

// Build the complete backend transaction. It does not publish the Meta
// UDP/443 filter or delete conntrack tuples; see the staging note above.
StagedRuntimeFirewall stage_runtime_firewall(
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
    bool udp_call_affinity_ipset_available = true,
    const std::optional<KeeneticDnsSnapshot>& keenetic_dns_snapshot =
        std::nullopt,
    std::shared_ptr<const ListCacheGenerationSnapshot>
        list_cache_snapshot = nullptr);

// Hand the staged transaction to the kernel. This is the one blocking step:
// every child process of a firewall apply originates here.
void commit_runtime_firewall(Firewall& firewall,
                             const StagedRuntimeFirewall& staged);

// Materialize the runtime firewall configuration using the real backend.
// Returns the realized rule-state snapshot that should be stored for later
// verification and status reporting.
//
// Staging and commit back to back, which is what every current caller wants:
// they run inside a synchronous transaction whose rollback depends on the
// commit having already happened or not.
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
        std::nullopt,
    std::shared_ptr<const ListCacheGenerationSnapshot>
        list_cache_snapshot = nullptr);

// Build the source-scoped direct-egress SNAT contract for Keenetic's SSTP,
// OpenConnect, L2TP and IKEv1 servers. Their clients need this on the ordinary
// WAN path regardless of whether policy routing is enabled for them. Other
// native VPN services are deliberately excluded so their established
// firmware/runtime paths remain unchanged.
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
