#include "ndms_native_import_recovery_plan.hpp"

namespace keen_pbr3 {

namespace {

using Step = NdmsNativeImportRecoveryStep;
using Phase = NdmsNativeImportWalPhase;
using Action = NdmsNativeImportRecoveryAction;

bool rollback_phase(const Phase phase) noexcept {
    return phase == Phase::rollback_requested ||
           phase == Phase::delete_may_be_inflight ||
           phase == Phase::absence_verified;
}

} // namespace

NdmsNativeImportRecoveryPlan plan_ndms_native_import_recovery(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryAction action) {
    NdmsNativeImportRecoveryPlan plan;
    switch (action) {
    case Action::retry_read_only_observation:
    case Action::block_unknown:
        // No dispatchable work. The lease admission already refuses these;
        // planning for them anyway would hand a dispatcher work the
        // classifier never authorized.
        return plan;

    case Action::abort_without_mutation:
        // Provably nothing was created: the record itself is the only thing
        // to clean up. Any phase the classifier reaches this verdict from is
        // eligible, because the verdict already encodes stable absence.
        plan.steps = {Step::remove_wal_record};
        return plan;

    case Action::resume_forward_reconcile:
        // Only a transaction that already published ownership may resume
        // forward: the classifier requires ownership_record_matches, and a
        // record in an earlier phase has no published claim to match.
        if (record.phase != Phase::ownership_published) return plan;
        plan.steps = {Step::remove_wal_record};
        return plan;

    case Action::rollback_delete_exact_owned:
        // A created target that must not survive. The rollback intent is
        // published before the delete may run, so a crash between the two
        // recovers as retry_exact_owned_delete instead of re-classifying a
        // half-rolled-back world from scratch.
        if (record.phase != Phase::import_may_be_inflight &&
            record.phase != Phase::response_recorded &&
            record.phase != Phase::target_verified) {
            return plan;
        }
        plan.steps = {Step::advance_wal_rollback_requested,
                      Step::advance_wal_delete_may_be_inflight,
                      Step::delete_exact_owned_target,
                      Step::advance_wal_absence_verified,
                      Step::remove_wal_record};
        return plan;

    case Action::retry_exact_owned_delete:
        // The rollback was already published; only the delete needs to run
        // again. Re-publishing rollback_requested here would move the WAL
        // backwards, and a WAL that moves backwards can replay a delete after
        // a later phase already proved absence.
        // Deliberately NOT from absence_verified: a target reappearing after
        // absence was proven stable is a world this plan has no authority
        // over, and re-entering the delete from there would ask the WAL to
        // move backwards. The empty plan sends it back to a human.
        if (record.phase != Phase::rollback_requested &&
            record.phase != Phase::delete_may_be_inflight) {
            return plan;
        }
        plan.steps = {Step::advance_wal_delete_may_be_inflight,
                      Step::delete_exact_owned_target,
                      Step::advance_wal_absence_verified,
                      Step::remove_wal_record};
        if (record.phase == Phase::delete_may_be_inflight) {
            // Already published; re-publishing the same phase would be a
            // self-transition the codec has no reason to allow.
            plan.steps.erase(plan.steps.begin());
        }
        return plan;

    case Action::complete_rollback:
        // Absence is already proven stable; what remains is bookkeeping.
        if (!rollback_phase(record.phase)) return plan;
        if (record.phase == Phase::absence_verified) {
            plan.steps = {Step::remove_wal_record};
        } else {
            plan.steps = {Step::advance_wal_absence_verified,
                          Step::remove_wal_record};
        }
        return plan;
    }
    return plan;
}

const char* ndms_native_import_recovery_step_name(
    const NdmsNativeImportRecoveryStep step) noexcept {
    switch (step) {
    case Step::advance_wal_target_verified:
        return "advance_wal_target_verified";
    case Step::publish_ownership:
        return "publish_ownership";
    case Step::advance_wal_ownership_published:
        return "advance_wal_ownership_published";
    case Step::advance_wal_rollback_requested:
        return "advance_wal_rollback_requested";
    case Step::advance_wal_delete_may_be_inflight:
        return "advance_wal_delete_may_be_inflight";
    case Step::delete_exact_owned_target:
        return "delete_exact_owned_target";
    case Step::advance_wal_absence_verified:
        return "advance_wal_absence_verified";
    case Step::remove_wal_record:
        return "remove_wal_record";
    }
    return "remove_wal_record";
}

} // namespace keen_pbr3
