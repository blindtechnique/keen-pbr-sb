#pragma once

#include "ndms_native_import_wal.hpp"

#include <vector>

namespace keen_pbr3 {

// One typed step of an admitted recovery. The planner emits these; a future
// dispatcher executes them in order and stops at the first failure. No step
// carries free-form data: everything a step needs is already in the WAL
// record the lease admission validated.
enum class NdmsNativeImportRecoveryStep {
    // Forward completion of a verified import.
    advance_wal_target_verified,
    publish_ownership,
    advance_wal_ownership_published,
    // Rollback of an import that must not survive.
    advance_wal_rollback_requested,
    advance_wal_delete_may_be_inflight,
    delete_exact_owned_target,
    advance_wal_absence_verified,
    // Common terminal step: the transaction is finished and its record must
    // not block the next admission.
    remove_wal_record,
};

struct NdmsNativeImportRecoveryPlan {
    // Empty means "no plan": the action carries no dispatchable work, or the
    // record's phase contradicts the action. An empty plan is a refusal, and
    // the dispatcher must treat it exactly like a lease it never got.
    std::vector<NdmsNativeImportRecoveryStep> steps;

    bool actionable() const noexcept { return !steps.empty(); }
};

// Pure. Maps one admitted (record, action) pair to the exact ordered steps
// that finish it.
//
// The pairing matters as much as the action: resume_forward_reconcile from a
// phase that never recorded a response has nothing to resume, and a plan
// invented for it would forward-complete an import nobody verified. Every
// such contradiction yields the empty plan rather than a guess - the
// classifier and the lease admission were both fail-closed, and the planner
// does not become the first component in this chain to improvise.
NdmsNativeImportRecoveryPlan plan_ndms_native_import_recovery(
    const NdmsNativeImportWalRecord& record,
    NdmsNativeImportRecoveryAction action);

const char* ndms_native_import_recovery_step_name(
    NdmsNativeImportRecoveryStep step) noexcept;

} // namespace keen_pbr3
