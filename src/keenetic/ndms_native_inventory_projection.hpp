#pragma once

#include "ndms_interface_inventory.hpp"
#include "ndms_native_import_readiness.hpp"
#include "ndms_native_ownership_store.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// This is an advisory, read-only status projection.  Only the cooperative
// delete coordinator can authorize a mutation: it rereads the exact claim and
// verifies the encrypted snapshot, keen-pbr dependencies and direct NDMS
// state while holding the complete writer chain.
enum class NdmsNativeInventoryOwnershipState : std::uint8_t {
    not_applicable,
    foreign,
    panel_owned_active,
    panel_owned_tombstone,
    unavailable,
};

enum class NdmsNativeInventoryDeleteBlocker : std::uint8_t {
    unsupported_kind,
    invalid_or_protected_target,
    catalog_not_fresh,
    ownership_inventory_unavailable,
    ownership_absent,
    ownership_not_active,
    ownership_kind_mismatch,
    import_journal_not_authoritatively_clean,
    import_recovery_required,
    import_journal_unsafe,
    import_journal_unavailable,
    delete_recovery_required,
    delete_journal_unsafe,
};

enum class NdmsNativeInventoryDeferredDeleteCheck : std::uint8_t {
    encrypted_snapshot,
    keen_pbr_dependencies,
    direct_ndms_state,
};

// Page-level advisory state for a durable deleted tombstone. It is separate
// from firmware rows because a correctly deleted interface normally has no
// row left to carry an action.
enum class NdmsNativeRetainedDeletionBlocker : std::uint8_t {
    catalog_not_fresh,
    target_present,
    ownership_schema_not_forget_capable,
    import_journal_not_authoritatively_clean,
    import_recovery_required,
    import_journal_unsafe,
    import_journal_unavailable,
    delete_recovery_required,
    delete_journal_unsafe,
};

enum class NdmsNativeRetainedDeletionDeferredCheck : std::uint8_t {
    encrypted_snapshot_or_absence,
    keen_pbr_dependencies,
    retained_kernel_interface_absence,
    fresh_dual_scope_absence,
};

struct NdmsNativeRetainedDeletionProjection final {
    std::string interface_name;
    // Opaque exact tombstone CAS. No marker, transaction, snapshot revision,
    // historical kernel identity or target fingerprint crosses this boundary.
    std::string ownership_revision;
    bool forget_candidate{false};
    std::vector<NdmsNativeRetainedDeletionBlocker> forget_blockers;
    std::vector<NdmsNativeRetainedDeletionDeferredCheck>
        deferred_authoritative_checks;
};

struct NdmsNativeInterfaceInventoryProjection final {
    std::string interface_name;
    NdmsNativeInventoryOwnershipState ownership_state{
        NdmsNativeInventoryOwnershipState::unavailable};
    std::optional<NdmsNativeOwnershipLifecycle> ownership_lifecycle;
    std::optional<std::string> ownership_revision;

    // True means only that the current card has enough redacted evidence to
    // submit an exact expected-revision request.  It is never `can_delete` and
    // never predicts that the authoritative coordinator will accept it.
    bool delete_candidate{false};
    std::vector<NdmsNativeInventoryDeleteBlocker> delete_blockers;

    // These checks are intentionally deferred to POST.  Their presence makes
    // it explicit that the inventory did not decrypt a snapshot, scan config
    // dependencies or perform a live RCI observation.
    std::vector<NdmsNativeInventoryDeferredDeleteCheck>
        deferred_authoritative_checks;
};

struct NdmsNativeInventoryProjection final {
    bool ownership_inventory_available{false};
    // Echoes only the redacted readiness inputs used to derive the public
    // blockers.  They let the inventory explain a degraded candidate without
    // exposing a WAL filename, transaction id or record payload.
    NdmsNativeImportJournalReadinessState observed_import_journal_state{
        NdmsNativeImportJournalReadinessState::unavailable};
    NdmsNativeDeleteWalReadiness observed_delete_journal_state{
        NdmsNativeDeleteWalReadiness::unsafe};
    std::vector<NdmsNativeInterfaceInventoryProjection> interfaces;
    // Sorted, bounded by the same complete 128-entry ownership inspection.
    // Includes tombstones whose firmware row is absent.
    std::vector<NdmsNativeRetainedDeletionProjection>
        retained_deletions;
};

// Projects rows in the same order as the supplied catalogue.  Ownership
// inspection is already bounded to 128 directory entries; malformed or
// duplicate inspection input fails the whole ownership view closed.  Each
// blocker/check vector is drawn from a fixed enum set and contains no record
// identifiers, transaction ids, markers or snapshot revisions.
NdmsNativeInventoryProjection project_ndms_native_inventory(
    const std::vector<NdmsTunnelInterface>& interfaces,
    bool catalog_fresh,
    const NdmsNativeOwnershipInspection& ownership,
    NdmsNativeImportJournalReadinessState import_journal,
    NdmsNativeDeleteWalReadiness delete_journal) noexcept;

const char* ndms_native_inventory_ownership_state_name(
    NdmsNativeInventoryOwnershipState state) noexcept;
const char* ndms_native_inventory_delete_blocker_name(
    NdmsNativeInventoryDeleteBlocker blocker) noexcept;
const char* ndms_native_inventory_deferred_delete_check_name(
    NdmsNativeInventoryDeferredDeleteCheck check) noexcept;
const char* ndms_native_retained_deletion_blocker_name(
    NdmsNativeRetainedDeletionBlocker blocker) noexcept;
const char* ndms_native_retained_deletion_deferred_check_name(
    NdmsNativeRetainedDeletionDeferredCheck check) noexcept;

} // namespace keen_pbr3
