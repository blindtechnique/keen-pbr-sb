#pragma once

#include "ndms_native_import_recovery_observation.hpp"
#include "ndms_native_import_recovery_plan.hpp"

namespace keen_pbr3 {

// Forward completion of an import whose response was recorded: verify the
// created target from measurements, publish the durable ownership claim, and
// finish the transaction. This is the half the executor deliberately stops
// short of - it ends at response_recorded - and the half the recovery
// classifier resumes only after ownership is already published. Between the
// two, until now, stood nothing.
struct NdmsNativeImportForwardCompletion {
    // The record to dispatch from: the caller's record enriched with the
    // measured created_interface and target_full_revision. Enriched here and
    // not in the dispatcher, because what gets adopted into the durable WAL
    // is a planning decision, not a dispatching one.
    NdmsNativeImportWalRecord enriched;
    NdmsNativeImportRecoveryPlan plan;

    bool actionable() const noexcept { return plan.actionable(); }
};

// Pure and fail-closed. The empty plan comes back unless every one of these
// holds: the record is at response_recorded or target_verified; the
// observation is authoritative with the world at rest (generation advanced,
// protected catalog unchanged); exactly one marker sighting exists, on the
// baseline's expected target, absent at baseline, still down - a target
// somebody already enabled is not ours to finish quietly; and any evidence
// the record already carries (created_interface, target_full_revision)
// matches the measurement exactly. A verified interface whose bytes moved
// since verification is re-verified, not trusted.
// `measured_target_revision` is the exact revision the probes measured for
// the sighted target, passed alongside the observation because the
// observation deliberately reduces it to a match/no-match bool - sufficient
// for recovery, which never adopts evidence, and insufficient here, where the
// measurement becomes the durable record.
NdmsNativeImportForwardCompletion
plan_ndms_native_import_forward_completion(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryObservation& observation,
    const std::string& measured_target_revision);

} // namespace keen_pbr3
