#include "ndms_native_import_recovery_dispatch.hpp"

#include "ndms_native_create_policy.hpp"
#include "ndms_native_ownership_store.hpp"

namespace keen_pbr3 {

namespace {

bool plan_contains(const NdmsNativeImportRecoveryPlan& plan,
                   const NdmsNativeImportRecoveryStep wanted) {
    for (const auto step : plan.steps) {
        if (step == wanted) return true;
    }
    return false;
}

bool plan_deletes(const NdmsNativeImportRecoveryPlan& plan) {
    return plan_contains(
        plan, NdmsNativeImportRecoveryStep::delete_exact_owned_target);
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
    const NdmsNativeImportRecoveryDeleteExecutor& delete_executor,
    NdmsNativeOwnershipStore* const ownership_store,
    const std::function<void(NdmsNativeImportRecoveryStep)>&
        step_observer,
    NdmsNativeImportSnapshotRetirer* const snapshot_retirer) {
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

    if (plan_contains(plan,
                      NdmsNativeImportRecoveryStep::publish_ownership) &&
        ownership_store == nullptr) {
        result.state = NdmsNativeImportRecoveryDispatchState::
            ownership_store_missing;
        return result;
    }
    // The retraction needs the store only when the record could actually have
    // published a claim: publish_ownership builds claims from exactly these
    // two fields, and the codec preserves them through every rollback phase.
    // A record without them cannot own a claim, and demanding a store then
    // would refuse rollbacks that have nothing to retract.
    if (plan_contains(
            plan, NdmsNativeImportRecoveryStep::remove_ownership_claim) &&
        record.created_interface.has_value() &&
        record.target_full_revision.has_value() &&
        ownership_store == nullptr) {
        result.state = NdmsNativeImportRecoveryDispatchState::
            ownership_store_missing;
        return result;
    }

    const bool snapshot_must_retire =
        plan_contains(
            plan, NdmsNativeImportRecoveryStep::remove_wal_record) &&
        !plan_contains(
            plan, NdmsNativeImportRecoveryStep::publish_ownership) &&
        record.phase != NdmsNativeImportWalPhase::ownership_published;
    if (snapshot_must_retire && snapshot_retirer == nullptr) {
        result.state = NdmsNativeImportRecoveryDispatchState::
            snapshot_retirer_missing;
        return result;
    }

    auto current = record;
    for (const auto step : plan.steps) {
        if (step_observer) step_observer(step);
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
                step_ok = !snapshot_must_retire ||
                    snapshot_retirer->remove_if_present_exact(
                        current.baseline.expected_created_interface,
                        current.transaction_id,
                        current.marker,
                        current.snapshot_revision);
                if (step_ok) store.remove_exact(current);
            } else if (step == NdmsNativeImportRecoveryStep::
                                   remove_ownership_claim) {
                if (!current.created_interface.has_value() ||
                    !current.target_full_revision.has_value()) {
                    // No claim can exist: publish_ownership builds one from
                    // exactly these fields, and this record never had them.
                    step_ok = true;
                } else {
                    // Reconstructed from the record, byte for byte the claim
                    // publish_ownership would have written for it. Only that
                    // claim is retracted; anything else on the slot is another
                    // transaction's assertion and stays.
                    NdmsNativeOwnershipRecord claim;
                    claim.interface_name = *current.created_interface;
                    claim.transaction_id = current.transaction_id;
                    claim.marker = current.marker;
                    claim.kind = current.kind;
                    claim.snapshot_revision =
                        current.snapshot_revision;
                    claim.target_full_revision =
                        *current.target_full_revision;
                    const auto existing = ownership_store->read(
                        *current.created_interface);
                    if (existing.state ==
                        NdmsNativeOwnershipReadState::absent) {
                        step_ok = true;
                    } else if (existing.state ==
                                   NdmsNativeOwnershipReadState::valid &&
                               !(*existing.record == claim)) {
                        step_ok = true;
                    } else if (existing.state ==
                               NdmsNativeOwnershipReadState::valid) {
                        step_ok = ownership_store->remove_exact(claim);
                    }
                    // Unreadable stays step_ok=false: a torn claim is evidence
                    // of an interrupted publish, and "nothing to retract" is
                    // exactly the reading that must not come from a torn one.
                }
            } else if (step ==
                       NdmsNativeImportRecoveryStep::publish_ownership) {
                // The claim is built from the record being dispatched, never
                // from caller-supplied fields: what ownership asserts is what
                // the WAL proved.
                if (current.created_interface.has_value() &&
                    current.target_full_revision.has_value()) {
                    NdmsNativeOwnershipRecord claim;
                    claim.interface_name = *current.created_interface;
                    claim.transaction_id = current.transaction_id;
                    claim.marker = current.marker;
                    claim.kind = current.kind;
                    claim.snapshot_revision =
                        current.snapshot_revision;
                    claim.target_full_revision =
                        *current.target_full_revision;
                    // Carried forward in memory so the very next WAL advance
                    // publishes the revision of the claim that actually
                    // exists on disk - one serialization, one digest.
                    current.ownership_revision =
                        ownership_store->publish(claim);
                    step_ok = true;
                }
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
    case NdmsNativeImportRecoveryDispatchState::ownership_store_missing:
        return "ownership_store_missing";
    case NdmsNativeImportRecoveryDispatchState::snapshot_retirer_missing:
        return "snapshot_retirer_missing";
    case NdmsNativeImportRecoveryDispatchState::step_failed:
        return "step_failed";
    }
    return "step_failed";
}

} // namespace keen_pbr3
