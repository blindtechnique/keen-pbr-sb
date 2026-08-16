#pragma once

#include "ndms_native_import_wal_store.hpp"

#include <cstdint>

namespace keen_pbr3 {

// Redacted, report-only summary of the durable native-import journal.  This
// state is never an allocator fence, recovery authorization or permission to
// expose Apply.  In particular, callers must keep the independent
// recovery_journal_not_integrated blocker until boot recovery is complete.
enum class NdmsNativeImportJournalReadinessState : std::uint8_t {
    // No state directory has ever been published.  Treating this as clean is
    // valid only while every production writer/provider remains disabled.  A
    // future enabled writer must provision and verify the journal before this
    // state can participate in readiness decisions.
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

const char* ndms_native_import_journal_readiness_state_name(
    NdmsNativeImportJournalReadinessState state) noexcept;

} // namespace keen_pbr3
