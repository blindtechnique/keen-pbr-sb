#pragma once

#include <cstdint>

namespace keen_pbr3 {

// Already observed evidence for the START/cold-boot resolver boundary. The
// caller remains the owner of route/firewall state and maps its optionals to
// these value-only facts before entering this policy.
struct RuntimeFirewallStartResolverTailFacts final {
    bool cold_boot{false};
    bool worker_succeeded{false};
    bool worker_input_available{false};
    bool worker_result_available{false};
    bool route_preparation_required{false};
    bool worker_route_mutation_applied{false};
    std::uint64_t requested_route_epoch{0U};
    std::uint64_t current_route_epoch{0U};
    std::uint64_t operation_runtime_generation{0U};
    std::uint64_t current_runtime_generation{0U};
    bool route_checkpoint_published{false};
    bool route_checkpoint_mutation_applied{false};
    bool core_committed{false};
    bool commit_ambiguous{false};
};

struct RuntimeFirewallStartResolverTailPlan final {
    bool route_mutation_acknowledged{false};
    bool exact_route_checkpoint_verified{false};
    bool route_firewall_proven{false};
    bool begin_lifecycle_resolver{false};
    bool downgrade_nominal_worker_success{false};
};

RuntimeFirewallStartResolverTailPlan
plan_runtime_firewall_start_resolver_tail(
    const RuntimeFirewallStartResolverTailFacts& facts) noexcept;

enum class RuntimeFirewallResolverTailAction : std::uint8_t {
    no_stream,
    foreground_lifecycle_stream,
    background_existing_stream_retry,
    background_direct_stream,
    foreground_gated_failure,
};

// Facts used after a non-START core generation has been published. Foreground
// is explicit rather than inferred from a second lifecycle enum so this plan
// remains independent from the operation owner and cannot acquire authority.
struct RuntimeFirewallNonStartResolverTailFacts final {
    bool foreground_lifecycle{false};
    bool restart_lifecycle{false};
    bool resolver_refresh_required{false};
    bool resolver_waits_for_firewall{false};
    bool resolver_generation_published{false};
    bool resolver_stream_in_flight{false};
};

struct RuntimeFirewallNonStartResolverTailPlan final {
    // Preserves runtime_firewall_restart_resolver_initially_verified(): every
    // background pass is initially verified; a foreground restart is only
    // initially verified when neither refresh nor firewall gating is pending.
    bool initially_verified{false};
    bool publish_resolver_generation{false};
    bool cancel_existing_reload_retry{false};
    RuntimeFirewallResolverTailAction action{
        RuntimeFirewallResolverTailAction::no_stream};
};

RuntimeFirewallNonStartResolverTailPlan
plan_runtime_firewall_non_start_resolver_tail(
    const RuntimeFirewallNonStartResolverTailFacts& facts) noexcept;

} // namespace keen_pbr3
