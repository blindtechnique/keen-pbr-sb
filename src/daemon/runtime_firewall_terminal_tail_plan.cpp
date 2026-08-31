#include "runtime_firewall_terminal_tail_plan.hpp"

namespace keen_pbr3 {
namespace {

constexpr std::string_view kStaleStartRouteObservationDetail{
    "runtime route observation changed before START publication"};

} // namespace

RuntimeFirewallTerminalTailPlan plan_runtime_firewall_terminal_tail(
    const RuntimeFirewallTerminalTailFacts& facts) noexcept {
    RuntimeFirewallTerminalTailPlan plan;
    plan.worker_succeeded_after_route_fence = facts.worker_succeeded;
    plan.successor_pending_after_route_fence = facts.successor_pending;

    if (!facts.lifecycle_start) {
        plan.dispatch = facts.worker_succeeded
            ? RuntimeFirewallTerminalTailDispatch::background_success
            : RuntimeFirewallTerminalTailDispatch::background_failure;
        return plan;
    }

    if (facts.worker_succeeded && !facts.route_epoch_current) {
        plan.downgrade_stale_start_success = true;
        plan.worker_succeeded_after_route_fence = false;
        plan.worker_failure_detail = kStaleStartRouteObservationDetail;

        const bool retry = !facts.lifecycle_cold_boot &&
            facts.ordinary_start_retry_available;
        plan.successor = retry
            ? RuntimeFirewallTerminalTailSuccessor::reschedule_retry
            : RuntimeFirewallTerminalTailSuccessor::clear;
        plan.force_successor = retry;
        plan.worker_failure_transient = retry;
        plan.successor_pending_after_route_fence = retry;
    }

    plan.verified_start =
        plan.worker_succeeded_after_route_fence &&
        facts.lifecycle_resolver_verified &&
        facts.start_candidate_published &&
        (facts.lifecycle_cold_boot || facts.core_published);
    if (plan.verified_start) {
        plan.dispatch =
            RuntimeFirewallTerminalTailDispatch::start_verified;
    } else if (plan.successor_pending_after_route_fence &&
               !facts.worker_commit_ambiguous) {
        plan.dispatch =
            RuntimeFirewallTerminalTailDispatch::start_pending;
    } else {
        plan.dispatch =
            RuntimeFirewallTerminalTailDispatch::start_failed;
    }
    return plan;
}

} // namespace keen_pbr3
