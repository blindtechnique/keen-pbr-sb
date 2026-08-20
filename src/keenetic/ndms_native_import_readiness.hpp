#pragma once

#include "ndms_native_delete_wal_store.hpp"
#include "ndms_native_import_wal_store.hpp"

#include <cstdint>

namespace keen_pbr3 {

// Redacted, report-only summary of the durable native-import journal.  This
// state is never an allocator fence, recovery authorization or permission to
// expose Apply.  In particular, callers must keep the independent
// recovery_journal_not_integrated blocker until boot recovery is complete.
enum class NdmsNativeImportJournalReadinessState : std::uint8_t {
    // No state directory has ever been published. This can participate in a
    // fresh admission only while the caller holds the complete native writer;
    // the same value cached in an atomic remains report-only. It is never by
    // itself enough authority for ownership retirement.
    clean_never_activated,
    // A private, bounded and fully inspected journal exists and is empty.
    clean,
    // At least one structurally valid durable transaction still exists.
    recovery_required,
    // The bounded inventory or one of its entries is unsafe or incomplete.
    unsafe,
    // The journal could not be inspected due to an I/O or availability fault.
    unavailable,
};

// Redacted cross-WAL summary shared by bodyless preflight and the real
// sensitive route. It authorizes reading a request body only when computed
// from fresh bounded store reads under the complete ordered native writer.
// A cached copy is report-only. The server retains that writer through body
// handling, and the coordinator independently validates its exact journals
// and observation binding before dispatch.
enum class NdmsNativeMutationAdmissionState : std::uint8_t {
    admitted,
    blocked,
    unavailable,
};

// Collapses a bounded WAL inventory to a single non-identifying state.  No
// filename, transaction id, marker, revision, phase or record is retained.
NdmsNativeImportJournalReadinessState
summarize_ndms_native_import_readiness(
    const NdmsNativeImportWalInventory& inventory) noexcept;

// Ownership reconciliation removes durable claims.  It may run only when the
// same bounded snapshot proves that the WAL store exists, was inspected
// completely, and contains no transaction.  `absent` is intentionally not
// enough authority here: it is a report-only clean state while the writer is
// disabled, not proof that no other process owns an unpublished/recovery
// transition.
bool ndms_native_import_inventory_permits_ownership_reconciliation(
    const NdmsNativeImportWalInventory& inventory) noexcept;

NdmsNativeMutationAdmissionState summarize_ndms_native_mutation_admission(
    const NdmsNativeImportWalInventory& import_inventory,
    NdmsNativeDeleteWalReadiness delete_readiness) noexcept;

const char* ndms_native_import_journal_readiness_state_name(
    NdmsNativeImportJournalReadinessState state) noexcept;

const char* ndms_native_mutation_admission_state_name(
    NdmsNativeMutationAdmissionState state) noexcept;

} // namespace keen_pbr3
