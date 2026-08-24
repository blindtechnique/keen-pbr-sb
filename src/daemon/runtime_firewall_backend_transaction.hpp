#pragma once

#include "../firewall/firewall_runtime.hpp"
#include "../runtime/meta_udp_443_activation_contract.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// The blocking backend phase which failed. These values deliberately describe
// only stage/preflight/commit work; scheduling, coalescing and daemon-state
// publication remain control-loop responsibilities.
enum class RuntimeFirewallBackendTransactionPhase : std::uint8_t {
    initial_stage,
    initial_meta_preflight,
    initial_commit,
    fallback_stage,
    fallback_meta_preflight,
    fallback_commit,
};

enum class RuntimeFirewallBackendFailureKind : std::uint8_t {
    rules_only_refusal,
    transient_firewall,
    firewall,
    meta_preflight,
    unexpected_exception,
    unknown_exception,
};

struct RuntimeFirewallBackendFailure {
    RuntimeFirewallBackendTransactionPhase phase{
        RuntimeFirewallBackendTransactionPhase::initial_stage};
    RuntimeFirewallBackendFailureKind kind{
        RuntimeFirewallBackendFailureKind::unknown_exception};
    std::string message;
    bool external_repair{false};
};

// A RulesOnly refusal which was repaired by the one permitted PreserveSets
// fallback. It is retained on a successful result so the control loop can log
// the distinction between routine external repair and unexpected drift without
// parsing an exception string.
struct RuntimeFirewallRulesOnlyFallback {
    RuntimeFirewallBackendTransactionPhase refused_phase{
        RuntimeFirewallBackendTransactionPhase::initial_stage};
    std::string message;
    bool external_repair{false};
};

// Complete immutable input for one admitted delayed backend attempt. Every
// field is an owned value (or an immutable shared generation lease): a worker
// can retain this object without retaining Daemon, CacheManager, FirewallState,
// ListService, or any mutable control-loop field.
//
// The executor accepts this object by const reference. A scheduler normally
// moves one instance into its worker closure and never mutates it afterwards.
struct RuntimeFirewallBackendTransactionInput {
    std::uint64_t operation_serial{0};
    std::uint64_t runtime_generation{0};

    Config config;
    OutboundMarkMap outbound_marks;
    std::map<std::string, std::string> urltest_selections;
    std::vector<InternalVpnServer> effective_internal_vpn_servers;
    std::vector<InternalVpnRuntimeTarget> effective_internal_vpn_targets;
    std::vector<FirewallSourceEgressSnatSelector>
        candidate_native_vpn_direct_egress_snat_selectors;
    bool forwarded_scope_allows_unmarked_cleanup{false};
    std::optional<std::uint32_t> committed_meta_udp443_fwmark;
    std::uint32_t committed_meta_udp443_owned_mask{0U};

    std::size_t list_max_file_size_bytes{kDefaultMaxFileSizeBytes};
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot;
    std::map<std::string, std::string> requested_list_fingerprints;

    FirewallApplyMode requested_mode{FirewallApplyMode::PreserveSets};
    bool force_clear_dynamic_sets{false};
    bool udp_call_affinity_ipset_available{true};
    std::optional<KeeneticDnsSnapshot> keenetic_dns_snapshot;

    // RulesOnly consumes these through a short-lived pointer view constructed
    // inside the worker. The transaction itself never stores those pointers.
    std::vector<RuleState> previous_rules;
    std::map<std::string, ListSetUsage> previous_list_usage;
    AppliedListContentState previous_list_content_state;
    std::map<std::string, std::string> previous_list_fingerprints;
    std::vector<FirewallSourceEgressSnatSelector>
        previous_native_vpn_direct_egress_snat_selectors;
};

struct RuntimeFirewallBackendTransactionResult {
    std::uint64_t operation_serial{0};
    std::uint64_t runtime_generation{0};
    // A failed command can be ambiguous after entering the backend COMMIT
    // boundary. Keep that distinct from a staging failure so the control loop
    // never claims that the previous kernel generation is certainly intact.
    bool commit_entered{false};
    bool commit_returned{false};
    std::optional<StagedRuntimeFirewall> committed_firewall;
    // The candidate authority prepared immediately before the final COMMIT
    // attempt. It remains available after an ambiguous commit failure, but is
    // cleared when restaging begins and set again only after the fallback
    // candidate passes its own Meta preflight.
    std::optional<MetaUdp443ActivationPlan> meta_activation_plan;
    std::optional<RuntimeFirewallRulesOnlyFallback> rules_only_fallback;
    std::optional<RuntimeFirewallBackendFailure> failure;

    bool committed() const noexcept {
        return committed_firewall.has_value() && !failure.has_value();
    }
};

// Execute only the blocking stage+Meta-preflight+commit core on the
// already-admitted backend services. No daemon state is read or published
// here. A RulesOnly refusal may rebuild exactly once with PreserveSets,
// whether the refusal happened during initial staging or initial commit;
// every later refusal is terminal.
RuntimeFirewallBackendTransactionResult
execute_runtime_firewall_backend_transaction(
    const RuntimeFirewallBackendTransactionInput& input,
    Firewall& firewall,
    MetaUdp443ActivationBackendServices& meta_services);

// Production convenience overload. The explicit service references keep the
// worker boundary visible while constructing the narrow Meta adapter locally.
RuntimeFirewallBackendTransactionResult
execute_runtime_firewall_backend_transaction(
    const RuntimeFirewallBackendTransactionInput& input,
    Firewall& firewall,
    ConntrackManager& conntrack_manager,
    NetlinkManager& netlink);

} // namespace keen_pbr3
