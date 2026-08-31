#include "runtime_firewall_conntrack_tail_plan.hpp"

#include <optional>

namespace keen_pbr3 {

RuntimeFirewallConntrackTailPlan plan_runtime_firewall_conntrack_tail(
    const RuntimeFirewallConntrackTailFacts& facts) noexcept {
    RuntimeFirewallConntrackTailPlan plan;

    if (facts.native_source_cleanup_failed) {
        plan.native_source_cleanup_failed = true;
        plan.native_source_cleanup_failure_detail =
            facts.native_source_cleanup_failure_detail;
    }

    const auto* recovery = facts.processed_snat_recovery;
    const bool repaired_snat_requires_cleanup = recovery != nullptr &&
        should_cleanup_conntrack_after_snat_repair(
            OwnedSnatRecovery{
                recovery->requested,
                recovery->missing_observed,
                std::nullopt},
            facts.inspected_snat_after);
    if (!facts.worker_succeeded || recovery == nullptr ||
        !repaired_snat_requires_cleanup ||
        !recovery->cleanup_snapshot.has_value() ||
        recovery->cleanup_snapshot->runtime_generation !=
            facts.current_runtime_generation) {
        return plan;
    }

    plan.cleanup_retry_snapshot = &*recovery->cleanup_snapshot;
    return plan;
}

RuntimeFirewallPostSuccessConntrackPlan
plan_runtime_firewall_post_success_conntrack(
    const RuntimeFirewallPostSuccessConntrackFacts& facts) noexcept {
    RuntimeFirewallPostSuccessConntrackPlan plan;
    if (!facts.attempted || facts.snapshot == nullptr) {
        return plan;
    }

    if (facts.command_unavailable) {
        plan.warn_command_unavailable = true;
        return plan;
    }

    if (facts.remaining_marks != nullptr &&
        !facts.remaining_marks->empty()) {
        plan.retry_snapshot = facts.snapshot;
        plan.reported_remaining_marks = facts.remaining_marks;
        plan.retry_marks =
            RuntimeFirewallPostSuccessConntrackMarks::reported_remaining;
    } else if (facts.cleanup_failed) {
        plan.retry_snapshot = facts.snapshot;
        plan.retry_marks =
            RuntimeFirewallPostSuccessConntrackMarks::ordered_snapshot;
    }
    return plan;
}

} // namespace keen_pbr3
