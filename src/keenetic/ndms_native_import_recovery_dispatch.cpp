#include "ndms_native_import_recovery_dispatch.hpp"

#include "ndms_native_create_policy.hpp"

namespace keen_pbr3 {

namespace {

bool plan_deletes(const NdmsNativeImportRecoveryPlan& plan) {
    for (const auto step : plan.steps) {
        if (step ==
            NdmsNativeImportRecoveryStep::delete_exact_owned_target) {
            return true;
        }
    }
    return false;
}

std::optional<NdmsNativeImportWalPhase> phase_of(
    const NdmsNativeImportRecoveryStep step) {
    switch (step) {
    case NdmsNativeImportRecoveryStep::advance_wal_target_verified:
        return NdmsNativeImportWalPhase::target_verified;
    case NdmsNativeImportRecoveryStep::advance_wal_ownership_published:
        return NdmsNativeImportWalPhase::ownership_published;
    case NdmsNativeImportRecoveryStep::advance_wal_rollback_requested:
        return NdmsNativeImportWalPhase::rollback_requested;
    case NdmsNativeImportRecoveryStep::advance_wal_delete_may_be_inflight:
        return NdmsNativeImportWalPhase::delete_may_be_inflight;
    case NdmsNativeImportRecoveryStep::advance_wal_absence_verified:
        return NdmsNativeImportWalPhase::absence_verified;
    default:
        return std::nullopt;
    }
}

} // namespace

NdmsNativeImportRecoveryDispatchResult
dispatch_ndms_native_import_recovery(
    NdmsNativeImportWalStore& store,
    const NdmsNativeImportRecoveryLease& lease,
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryPlan& plan,
    const std::optional<std::string>& marker_target,
    const NdmsNativeImportRecoveryDeleteExecutor& delete_executor) {
    NdmsNativeImportRecoveryDispatchResult result;

    if (!lease.held()) {
        result.state =
            NdmsNativeImportRecoveryDispatchState::lease_not_held;
        return result;
    }
    if (!plan.actionable()) {
        result.state = NdmsNativeImportRecoveryDispatchState::plan_empty;
        return result;
    }
    if (plan_deletes(plan)) {
        if (!marker_target.has_value() || !delete_executor) {
            result.state =
                NdmsNativeImportRecoveryDispatchState::target_missing;
            return result;
        }
        // The last code before something deletes an interface re-checks the
        // name itself. The planner and the classifier both did; this is the
        // one place where being wrong is unrecoverable, so it checks again.
        if (!ndms_native_created_target_is_eligible(*marker_target) ||
            (record.created_interface.has_value() &&
             *record.created_interface != *marker_target)) {
            result.state =
                NdmsNativeImportRecoveryDispatchState::target_not_eligible;
            return result;
        }
    }

    auto current = record;
    for (const auto step : plan.steps) {
        bool step_ok = false;
        try {
            if (const auto phase = phase_of(step)) {
                auto next = current;
                next.phase = *phase;
                store.publish(next);
                current = next;
                step_ok = true;
            } else if (step == NdmsNativeImportRecoveryStep::
                                   delete_exact_owned_target) {
                step_ok =
                    delete_executor(*marker_target, current.marker) ==
                    NdmsNativeImportRecoveryDeleteOutcome::
                        deleted_confirmed;
            } else if (step ==
                       NdmsNativeImportRecoveryStep::remove_wal_record) {
                store.remove_exact(current);
                step_ok = true;
            } else {
                // publish_ownership belongs to the forward coordinator; a
                // recovery plan carrying it is a contradiction this
                // dispatcher refuses rather than half-implements.
                step_ok = false;
            }
        } catch (...) {
            step_ok = false;
        }
        if (!step_ok) {
            // Nothing is unwound. The WAL record left behind names the exact
            // phase reached - the one honest account the next recovery pass
            // will classify from.
            result.state =
                NdmsNativeImportRecoveryDispatchState::step_failed;
            result.failed_step = step;
            return result;
        }
        ++result.completed_steps;
    }

    result.state = NdmsNativeImportRecoveryDispatchState::completed;
    return result;
}

const char* ndms_native_import_recovery_dispatch_state_name(
    const NdmsNativeImportRecoveryDispatchState state) noexcept {
    switch (state) {
    case NdmsNativeImportRecoveryDispatchState::completed:
        return "completed";
    case NdmsNativeImportRecoveryDispatchState::lease_not_held:
        return "lease_not_held";
    case NdmsNativeImportRecoveryDispatchState::plan_empty:
        return "plan_empty";
    case NdmsNativeImportRecoveryDispatchState::target_missing:
        return "target_missing";
    case NdmsNativeImportRecoveryDispatchState::target_not_eligible:
        return "target_not_eligible";
    case NdmsNativeImportRecoveryDispatchState::step_failed:
        return "step_failed";
    }
    return "step_failed";
}

} // namespace keen_pbr3
