#include "runtime_firewall_meta_tail_plan.hpp"

namespace keen_pbr3 {
namespace {

constexpr std::string_view FASTNAT_DEGRADED_DETAIL =
    "FastNAT was re-enabled during delayed firewall publication";
constexpr std::string_view FORWARD_HOOK_DEGRADED_DETAIL =
    "the exact owned first FORWARD hook could not be reverified after "
    "delayed publication";
constexpr std::string_view BALANCED_FILTER_DEGRADED_DETAIL =
    "balanced mode could not verify absence of owned UDP/443 artifacts "
    "after delayed publication";
constexpr std::string_view AMBIGUOUS_COMMIT_DEGRADED_DETAIL =
    "delayed firewall COMMIT outcome is ambiguous; exact Meta cleanup "
    "authority was discarded";

constexpr std::string_view REPAIR_PUBLICATION_REFRESH_DETAIL =
    "could not repair delayed Meta UDP/443 publication";
constexpr std::string_view CLEAN_BALANCED_REFRESH_DETAIL =
    "could not clean stale balanced-mode Meta UDP/443 artifacts";
constexpr std::string_view RESNAPSHOT_AMBIGUOUS_REFRESH_DETAIL =
    "could not resnapshot Meta UDP/443 after an ambiguous delayed COMMIT";

} // namespace

RuntimeFirewallMetaTailPlan plan_runtime_firewall_meta_tail(
    const RuntimeFirewallMetaTailFacts& facts) noexcept {
    RuntimeFirewallMetaTailPlan plan;

    if (facts.core_published) {
        if (facts.candidate_plan != nullptr) {
            plan.cleanup_source =
                RuntimeFirewallMetaCleanupSource::candidate;
            plan.cleanup_plan = facts.candidate_plan;
            plan.cleanup_attempt =
                facts.fastnat_healthy && facts.filter_healthy ? 0U : 1U;

            if (facts.fastnat_healthy && facts.filter_healthy) {
                plan.incident_action =
                    RuntimeFirewallMetaIncidentAction::reset;
            } else {
                plan.incident_action =
                    RuntimeFirewallMetaIncidentAction::degraded;
                plan.incident_detail = facts.fastnat_healthy
                    ? FORWARD_HOOK_DEGRADED_DETAIL
                    : FASTNAT_DEGRADED_DETAIL;
                if (facts.fastnat_healthy) {
                    plan.full_refresh = true;
                    plan.refresh_detail =
                        REPAIR_PUBLICATION_REFRESH_DETAIL;
                }
            }
            return plan;
        }

        if (facts.filter_healthy) {
            plan.incident_action =
                RuntimeFirewallMetaIncidentAction::reset;
        } else {
            plan.incident_action =
                RuntimeFirewallMetaIncidentAction::degraded;
            plan.incident_detail = BALANCED_FILTER_DEGRADED_DETAIL;
            plan.full_refresh = true;
            plan.refresh_detail = CLEAN_BALANCED_REFRESH_DETAIL;
        }
        return plan;
    }

    const bool publication_may_have_changed =
        facts.worker_commit_ambiguous || facts.publication_epoch_changed;
    if (!publication_may_have_changed && facts.previous_plan != nullptr &&
        facts.previous_runtime_generation ==
            facts.current_runtime_generation) {
        plan.cleanup_source = RuntimeFirewallMetaCleanupSource::previous;
        plan.cleanup_plan = facts.previous_plan;
        plan.cleanup_attempt = facts.previous_attempt;
    } else if (publication_may_have_changed) {
        plan.incident_action =
            RuntimeFirewallMetaIncidentAction::degraded;
        plan.incident_detail = AMBIGUOUS_COMMIT_DEGRADED_DETAIL;
        plan.full_refresh = true;
        plan.refresh_detail = RESNAPSHOT_AMBIGUOUS_REFRESH_DETAIL;
    }

    return plan;
}

} // namespace keen_pbr3
