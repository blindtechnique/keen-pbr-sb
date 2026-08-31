#include "runtime_firewall_resolver_tail_plan.hpp"

namespace keen_pbr3 {

RuntimeFirewallStartResolverTailPlan
plan_runtime_firewall_start_resolver_tail(
    const RuntimeFirewallStartResolverTailFacts& facts) noexcept {
    RuntimeFirewallStartResolverTailPlan plan;
    plan.route_mutation_acknowledged =
        facts.cold_boot &&
        facts.worker_input_available &&
        facts.worker_result_available &&
        facts.route_preparation_required &&
        facts.worker_route_mutation_applied;

    plan.exact_route_checkpoint_verified = !facts.cold_boot ||
        (plan.route_mutation_acknowledged &&
         facts.requested_route_epoch != 0U &&
         facts.requested_route_epoch == facts.current_route_epoch &&
         facts.operation_runtime_generation ==
             facts.current_runtime_generation &&
         facts.route_checkpoint_published &&
         facts.route_checkpoint_mutation_applied);

    plan.route_firewall_proven =
        plan.exact_route_checkpoint_verified &&
        facts.core_committed &&
        !facts.commit_ambiguous;
    plan.begin_lifecycle_resolver =
        facts.worker_succeeded && plan.route_firewall_proven;
    plan.downgrade_nominal_worker_success =
        facts.worker_succeeded && !plan.route_firewall_proven;
    return plan;
}

RuntimeFirewallNonStartResolverTailPlan
plan_runtime_firewall_non_start_resolver_tail(
    const RuntimeFirewallNonStartResolverTailFacts& facts) noexcept {
    RuntimeFirewallNonStartResolverTailPlan plan;
    plan.initially_verified = !facts.foreground_lifecycle ||
        (facts.restart_lifecycle &&
         !facts.resolver_refresh_required &&
         !facts.resolver_waits_for_firewall);
    plan.publish_resolver_generation =
        facts.resolver_refresh_required &&
        !facts.resolver_generation_published;

    if (facts.resolver_refresh_required &&
        !facts.resolver_waits_for_firewall) {
        plan.cancel_existing_reload_retry = true;
        if (facts.foreground_lifecycle) {
            plan.action = RuntimeFirewallResolverTailAction::
                foreground_lifecycle_stream;
        } else if (facts.resolver_stream_in_flight) {
            plan.action = RuntimeFirewallResolverTailAction::
                background_existing_stream_retry;
        } else {
            plan.action = RuntimeFirewallResolverTailAction::
                background_direct_stream;
        }
    } else if (facts.foreground_lifecycle &&
               facts.resolver_waits_for_firewall) {
        plan.action = RuntimeFirewallResolverTailAction::
            foreground_gated_failure;
    }
    return plan;
}

} // namespace keen_pbr3
