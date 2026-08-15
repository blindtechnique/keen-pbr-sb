#pragma once

#include "ndms_native_import_recovery_lease.hpp"
#include "ndms_native_import_recovery_plan.hpp"

#include <cstddef>
#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

// What the injected delete executor reports. Only deleted_confirmed lets the
// plan continue: "probably gone" advances a WAL toward absence_verified on a
// guess, and the phase after this one asserts absence as proven.
enum class NdmsNativeImportRecoveryDeleteOutcome {
    deleted_confirmed,
    refused,
    failed,
};

// The one step that touches the router is injected, because this dispatcher
// is still dormant: no RCI transport exists in this slice, production wiring
// arrives only with the hardware-accepted executor. The callback receives the
// exact target and marker the WAL admitted, nothing else to aim at.
using NdmsNativeImportRecoveryDeleteExecutor =
    std::function<NdmsNativeImportRecoveryDeleteOutcome(
        const std::string& interface_name,
        const std::string& marker)>;

enum class NdmsNativeImportRecoveryDispatchState {
    completed,
    // Refusals before any step runs. A dispatcher that starts work it cannot
    // finish cleanly is worse than one that refuses loudly.
    lease_not_held,
    plan_empty,
    target_missing,
    target_not_eligible,
    ownership_store_missing,
    // A step ran and failed. Everything before it is durable, and the WAL
    // record that remains says exactly how far this got.
    step_failed,
};

struct NdmsNativeImportRecoveryDispatchResult {
    NdmsNativeImportRecoveryDispatchState state{
        NdmsNativeImportRecoveryDispatchState::step_failed};
    std::optional<NdmsNativeImportRecoveryStep> failed_step;
    std::size_t completed_steps{0};
};

// Executes an admitted plan in order and stops at the first failure.
//
// The caller brings the lease the admission handed out; the dispatcher only
// verifies it is held. It re-checks target eligibility on its own - defence
// in depth, not distrust of the planner: this is the last code before an
// injected executor deletes an interface, and the last code is the one that
// gets to be paranoid for free.
//
// A failed step is not rolled back. The WAL record left behind names the
// exact phase reached, which is precisely what the next recovery pass
// classifies from - unwinding it would erase the one honest account of how
// far this got.
class NdmsNativeOwnershipStore;

NdmsNativeImportRecoveryDispatchResult
dispatch_ndms_native_import_recovery(
    NdmsNativeImportWalStore& store,
    const NdmsNativeImportRecoveryLease& lease,
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryPlan& plan,
    const std::optional<std::string>& marker_target,
    const NdmsNativeImportRecoveryDeleteExecutor& delete_executor,
    // Required only by plans that publish ownership - the forward-completion
    // ones. A plan that needs it and does not get it is refused before the
    // first step, like every other missing dependency here.
    NdmsNativeOwnershipStore* ownership_store = nullptr,
    // Called immediately before each step executes. Exists for the
    // crash-at-each-phase acceptance, whose driver dies here on purpose: the
    // property under test is that a crash between any two steps leaves a WAL
    // the next recovery pass finishes from. Never called after a failure.
    const std::function<void(NdmsNativeImportRecoveryStep)>&
        step_observer = nullptr);

const char* ndms_native_import_recovery_dispatch_state_name(
    NdmsNativeImportRecoveryDispatchState state) noexcept;

} // namespace keen_pbr3
