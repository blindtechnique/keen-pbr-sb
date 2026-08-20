#include "ndms_native_import_readiness.hpp"

#include <algorithm>

namespace keen_pbr3 {
namespace {

bool complete_valid_inventory(
    const NdmsNativeImportWalInventory& inventory) noexcept {
    return std::all_of(
        inventory.items.begin(),
        inventory.items.end(),
        [](const NdmsNativeImportWalInventoryItem& item) {
            return item.state == NdmsNativeImportWalLoadState::valid &&
                   item.transaction_id.has_value() &&
                   item.record.has_value();
        });
}

} // namespace

NdmsNativeImportJournalReadinessState
summarize_ndms_native_import_readiness(
    const NdmsNativeImportWalInventory& inventory) noexcept {
    switch (inventory.state) {
    case NdmsNativeImportWalInventoryState::absent:
        return NdmsNativeImportJournalReadinessState::
            clean_never_activated;
    case NdmsNativeImportWalInventoryState::ready:
        if (inventory.items.empty()) {
            return NdmsNativeImportJournalReadinessState::clean;
        }
        return complete_valid_inventory(inventory)
                   ? NdmsNativeImportJournalReadinessState::
                         recovery_required
                   : NdmsNativeImportJournalReadinessState::unsafe;
    case NdmsNativeImportWalInventoryState::unsafe_store:
    case NdmsNativeImportWalInventoryState::directory_limit_exceeded:
    case NdmsNativeImportWalInventoryState::record_limit_exceeded:
        return NdmsNativeImportJournalReadinessState::unsafe;
    case NdmsNativeImportWalInventoryState::busy:
    case NdmsNativeImportWalInventoryState::io_error:
        return NdmsNativeImportJournalReadinessState::unavailable;
    }
    return NdmsNativeImportJournalReadinessState::unavailable;
}

bool ndms_native_import_inventory_permits_ownership_reconciliation(
    const NdmsNativeImportWalInventory& inventory) noexcept {
    return inventory.state == NdmsNativeImportWalInventoryState::ready &&
           inventory.items.empty();
}

NdmsNativeMutationAdmissionState summarize_ndms_native_mutation_admission(
    const NdmsNativeImportWalInventory& import_inventory,
    const NdmsNativeDeleteWalReadiness delete_readiness) noexcept {
    if (delete_readiness == NdmsNativeDeleteWalReadiness::unsafe) {
        return NdmsNativeMutationAdmissionState::unavailable;
    }
    if (delete_readiness != NdmsNativeDeleteWalReadiness::clean) {
        return NdmsNativeMutationAdmissionState::blocked;
    }

    const bool import_clean =
        (import_inventory.state ==
             NdmsNativeImportWalInventoryState::absent ||
         import_inventory.state ==
             NdmsNativeImportWalInventoryState::ready) &&
        import_inventory.items.empty();
    if (import_clean) {
        return NdmsNativeMutationAdmissionState::admitted;
    }
    // Only a complete inventory of valid durable records proves a known
    // unfinished transaction. Unsafe names/records, excessive inventories,
    // contention and I/O failure are unknown rather than "blocked".
    if (import_inventory.recovery_permitted() &&
        !import_inventory.items.empty()) {
        return NdmsNativeMutationAdmissionState::blocked;
    }
    return NdmsNativeMutationAdmissionState::unavailable;
}

const char* ndms_native_import_journal_readiness_state_name(
    const NdmsNativeImportJournalReadinessState state) noexcept {
    switch (state) {
    case NdmsNativeImportJournalReadinessState::clean_never_activated:
        return "clean_never_activated";
    case NdmsNativeImportJournalReadinessState::clean:
        return "clean";
    case NdmsNativeImportJournalReadinessState::recovery_required:
        return "recovery_required";
    case NdmsNativeImportJournalReadinessState::unsafe:
        return "unsafe";
    case NdmsNativeImportJournalReadinessState::unavailable:
        return "unavailable";
    }
    return "unavailable";
}

const char* ndms_native_mutation_admission_state_name(
    const NdmsNativeMutationAdmissionState state) noexcept {
    switch (state) {
    case NdmsNativeMutationAdmissionState::admitted:
        return "admitted";
    case NdmsNativeMutationAdmissionState::blocked:
        return "blocked";
    case NdmsNativeMutationAdmissionState::unavailable:
        return "unavailable";
    }
    return "unavailable";
}

} // namespace keen_pbr3
