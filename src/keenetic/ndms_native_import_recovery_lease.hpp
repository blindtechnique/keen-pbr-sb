#pragma once

#include "ndms_native_import_recovery_observation.hpp"
#include "ndms_native_import_wal_store.hpp"

#include <optional>

namespace keen_pbr3 {

class NdmsNativeImportRecoveryLease;
struct NdmsNativeImportRecoveryAdmission;
NdmsNativeImportRecoveryAdmission admit_ndms_native_import_recovery(
    const NdmsNativeImportWalStore& store,
    const NdmsNativeImportWalRecord& classified_record,
    const NdmsNativeImportRecoveryObservation& observation);

// Cross-process exclusivity for one recovery decision and the action window
// that follows it.
//
// New imports are already excluded while a WAL record exists: admission
// requires an empty store. What nothing excluded until now is a second
// recoverer - the startup path and an API-triggered recovery, or two daemon
// instances, classifying the same record concurrently and both acting on it.
// Two exact-owned deletes of the same interface are not idempotent against a
// firmware allocator that may have reused the slot between them.
//
// The lease is a separate flock'd lock file BESIDE the store directory, never
// inside it: the inventory deliberately treats any unknown name in the store
// as an unsafe entry, and a lease that made every inventory unsafe would
// block the recovery it exists to serialize. It is held via the kernel for
// the lifetime of the object, so a crashed holder releases by dying.
class NdmsNativeImportRecoveryLease final {
public:
    NdmsNativeImportRecoveryLease(
        NdmsNativeImportRecoveryLease&& other) noexcept;
    NdmsNativeImportRecoveryLease& operator=(
        NdmsNativeImportRecoveryLease&& other) noexcept;
    NdmsNativeImportRecoveryLease(
        const NdmsNativeImportRecoveryLease&) = delete;
    NdmsNativeImportRecoveryLease& operator=(
        const NdmsNativeImportRecoveryLease&) = delete;
    ~NdmsNativeImportRecoveryLease();

    bool held() const noexcept;

private:
    friend struct NdmsNativeImportRecoveryAdmission;
    friend NdmsNativeImportRecoveryAdmission
    admit_ndms_native_import_recovery(
        const NdmsNativeImportWalStore&,
        const NdmsNativeImportWalRecord&,
        const NdmsNativeImportRecoveryObservation&);

    NdmsNativeImportRecoveryLease() = default;
    explicit NdmsNativeImportRecoveryLease(int descriptor) noexcept;

    int descriptor_{-1};
};

enum class NdmsNativeImportRecoveryAdmissionState {
    admitted,
    // Another recoverer holds the lease. Never waited for: recovery that
    // blocks on a peer is recovery that deadlocks on a stuck one.
    lease_busy,
    lease_io_error,
    // The bounded inventory is not a single safe record.
    inventory_not_ready,
    // The record the classification was made from is no longer loadable.
    record_missing,
    // The store holds a record for this transaction whose bytes differ from
    // the classified one. Somebody advanced it between classification and
    // admission; the classification describes a record that no longer exists.
    record_changed,
    // The classifier answered retry or block. Neither earns a lease: there is
    // no action to serialize, and handing out exclusivity for "wait" would
    // starve the recoverer that has something to do.
    action_not_actionable,
};

// The admission result. `action` is set only in the admitted state, and it is
// re-derived under the lease from the re-read record - never carried over
// from whatever the caller classified before admission.
struct NdmsNativeImportRecoveryAdmission final {
    NdmsNativeImportRecoveryAdmissionState state{
        NdmsNativeImportRecoveryAdmissionState::lease_io_error};
    std::optional<NdmsNativeImportRecoveryAction> action;
    NdmsNativeImportRecoveryLease lease;
};

// Admit exactly one recoverer for exactly the record it classified.
//
// Under the lease, in order: the bounded inventory must be safe and hold
// exactly one record; the record is re-read through the validating loader and
// compared byte-for-byte against `classified_record` - the compare-and-swap
// half of the contract, because a classification is a statement about one
// exact record, not about a transaction id; and the action is re-derived from
// the re-read record with the caller's observation. Any failure releases the
// lease before returning, so a refused caller leaves no lock behind.
NdmsNativeImportRecoveryAdmission admit_ndms_native_import_recovery(
    const NdmsNativeImportWalStore& store,
    const NdmsNativeImportWalRecord& classified_record,
    const NdmsNativeImportRecoveryObservation& observation);

const char* ndms_native_import_recovery_admission_state_name(
    NdmsNativeImportRecoveryAdmissionState state) noexcept;

} // namespace keen_pbr3
