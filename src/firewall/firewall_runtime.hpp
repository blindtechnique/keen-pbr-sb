#pragma once

#include "../cache/cache_manager.hpp"
#include "../config/config.hpp"
#include "../dns/keenetic_dns.hpp"
#include "../keenetic/internal_vpn_runtime_target.hpp"
#include "../lists/list_set_usage.hpp"
#include "../routing/firewall_state.hpp"
#include "../runtime/nfqws_runtime_contract.hpp"
#include "firewall.hpp"

#include <functional>
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
    // What each list's content implied for its kernel sets. Kept with the
    // content state so a later RulesOnly refresh can reuse it instead of
    // re-deriving it from a list it does not stream.
    std::map<std::string, ListSetUsage> list_usage;
    // Carried through because the backend needs the same mode for both
    // `prepare_apply()` during staging and `apply()` at commit; splitting them
    // across two different modes would build one transaction and commit
    // another.
    FirewallApplyMode mode{FirewallApplyMode::Destructive};
};

struct FirewallConfigApplyPolicy {
    FirewallApplyMode mode{FirewallApplyMode::PreserveSets};
    bool force_clear_dynamic_sets{false};
};

// What a RulesOnly stage reuses instead of streaming. All three come from the
// last committed transaction; a RulesOnly stage that cannot find what it needs
// in them throws FirewallRulesOnlyError rather than guessing.
struct PreviousRuntimeFirewall {
    const std::vector<RuleState>* rule_states{nullptr};
    const std::map<std::string, ListSetUsage>* list_usage{nullptr};
    const AppliedListContentState* list_content_state{nullptr};
};

// Capacity changes alter the schema of existing ipsets. Only iptables needs
// a destructive replacement; nftables ignores these optional hints.
FirewallConfigApplyPolicy firewall_config_apply_policy(
    FirewallBackend backend,
    const Config& current,
    const Config& candidate);

// Convert one stable active-runtime observation into the typed firewall
// desired state. The overload taking an observation is deterministic for
// tests; the production overload performs the bounded read-only observation.
PpeDeoffloadDesired ppe_deoffload_desired_from_observation(
    const Config& config,
    const NfqwsPpeRuntimeContractObservation& observation);
PpeDeoffloadDesired observe_ppe_deoffload_desired(const Config& config);
PpeDeoffloadDesired ppe_deoffload_desired_from_observation(
    PpeDeoffloadMode mode,
    bool quic_enabled,
    const NfqwsPpeRuntimeContractObservation& observation);
PpeDeoffloadDesired observe_ppe_deoffload_desired(
    PpeDeoffloadMode mode,
    bool quic_enabled);

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
        list_cache_snapshot = nullptr,
    bool force_clear_dynamic_sets = false,
    const PreviousRuntimeFirewall& previous = {});

// Hand the staged transaction to the kernel. This is the one blocking step:
// every child process of a firewall apply originates here.
void commit_runtime_firewall(Firewall& firewall,
                             const StagedRuntimeFirewall& staged);

// Own the one safe RulesOnly fallback boundary. A backend refusal is allowed
// to rebuild exactly one PreserveSets candidate, including any caller-owned
// preflight that must happen before COMMIT. The returned transaction is the
// one that actually reached the kernel. Any failure from the fallback stage
// or its commit propagates without attempting a second fallback.
using RuntimeFirewallFallbackStage = std::function<StagedRuntimeFirewall(
    const FirewallRulesOnlyError&)>;
StagedRuntimeFirewall commit_runtime_firewall_with_rules_only_fallback(
    Firewall& firewall,
    StagedRuntimeFirewall staged,
    RuntimeFirewallFallbackStage fallback_stage);

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
        list_cache_snapshot = nullptr,
    bool force_clear_dynamic_sets = false);

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
