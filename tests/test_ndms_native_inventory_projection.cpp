#include <doctest/doctest.h>

#include "keenetic/ndms_native_inventory_projection.hpp"

#include <algorithm>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

NdmsTunnelInterface tunnel(
    std::string name,
    const NdmsTunnelKind kind = NdmsTunnelKind::wireguard) {
    NdmsTunnelInterface result;
    result.id = name;
    result.firmware_interface_name = std::move(name);
    result.kind = kind;
    return result;
}

NdmsNativeOwnershipInspection ownership(
    const NdmsNativeOwnershipLifecycle lifecycle =
        NdmsNativeOwnershipLifecycle::active_running_only,
    const NdmsNativeTunnelImportKind kind =
        NdmsNativeTunnelImportKind::wireguard,
    std::string name = "Wireguard5",
    const bool forget_capable = false) {
    NdmsNativeOwnershipInspection result;
    result.readable = true;
    result.claims.push_back(NdmsNativeOwnershipInspectionItem{
        std::move(name),
        kind,
        lifecycle,
        lifecycle == NdmsNativeOwnershipLifecycle::
                         deleted_save_acknowledged_unverified
            ? "ndms-native-owner-tombstone-v1-" + std::string(64U, 'b')
            : "ndms-native-owner-v3-" + std::string(64U, 'a'),
        forget_capable,
    });
    return result;
}

bool has_blocker(
    const NdmsNativeInterfaceInventoryProjection& projection,
    const NdmsNativeInventoryDeleteBlocker blocker) {
    return std::find(
               projection.delete_blockers.begin(),
               projection.delete_blockers.end(),
               blocker) != projection.delete_blockers.end();
}

bool has_forget_blocker(
    const NdmsNativeRetainedDeletionProjection& projection,
    const NdmsNativeRetainedDeletionBlocker blocker) {
    return std::find(
               projection.forget_blockers.begin(),
               projection.forget_blockers.end(),
               blocker) != projection.forget_blockers.end();
}

} // namespace

TEST_CASE("active panel ownership is only a delete request candidate") {
    const auto claims = ownership();
    const auto projected = project_ndms_native_inventory(
        {tunnel("Wireguard5")},
        true,
        claims,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);

    REQUIRE(projected.ownership_inventory_available);
    CHECK(projected.observed_import_journal_state ==
          NdmsNativeImportJournalReadinessState::clean);
    CHECK(projected.observed_delete_journal_state ==
          NdmsNativeDeleteWalReadiness::clean);
    REQUIRE(projected.interfaces.size() == 1U);
    const auto& item = projected.interfaces.front();
    CHECK(item.interface_name == "Wireguard5");
    CHECK(item.ownership_state ==
          NdmsNativeInventoryOwnershipState::panel_owned_active);
    CHECK(item.ownership_lifecycle ==
          std::optional<NdmsNativeOwnershipLifecycle>{
              NdmsNativeOwnershipLifecycle::active_running_only});
    CHECK(item.ownership_revision ==
          std::optional<std::string>{
              "ndms-native-owner-v3-" + std::string(64U, 'a')});
    CHECK(item.delete_candidate);
    CHECK(item.delete_blockers.empty());
    CHECK(item.deferred_authoritative_checks ==
          std::vector<NdmsNativeInventoryDeferredDeleteCheck>{
              NdmsNativeInventoryDeferredDeleteCheck::encrypted_snapshot,
              NdmsNativeInventoryDeferredDeleteCheck::keen_pbr_dependencies,
              NdmsNativeInventoryDeferredDeleteCheck::direct_ndms_state,
          });
}

TEST_CASE("a durable tombstone is panel-owned and never becomes foreign") {
    const auto claims = ownership(
        NdmsNativeOwnershipLifecycle::
            deleted_save_acknowledged_unverified);
    const auto projected = project_ndms_native_inventory(
        {tunnel("Wireguard5")},
        true,
        claims,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);

    REQUIRE(projected.interfaces.size() == 1U);
    const auto& item = projected.interfaces.front();
    CHECK(item.ownership_state ==
          NdmsNativeInventoryOwnershipState::panel_owned_tombstone);
    CHECK(item.ownership_revision.has_value());
    CHECK_FALSE(item.delete_candidate);
    CHECK(has_blocker(
        item, NdmsNativeInventoryDeleteBlocker::ownership_not_active));
    CHECK(item.deferred_authoritative_checks.empty());
    REQUIRE(projected.retained_deletions.size() == 1U);
    CHECK_FALSE(projected.retained_deletions.front().forget_candidate);
    CHECK(has_forget_blocker(
        projected.retained_deletions.front(),
        NdmsNativeRetainedDeletionBlocker::target_present));
    CHECK(has_forget_blocker(
        projected.retained_deletions.front(),
        NdmsNativeRetainedDeletionBlocker::
            ownership_schema_not_forget_capable));
}

TEST_CASE("a kernel-bound tombstone is visible without a firmware row") {
    const auto claims = ownership(
        NdmsNativeOwnershipLifecycle::
            deleted_save_acknowledged_unverified,
        NdmsNativeTunnelImportKind::wireguard,
        "Wireguard5",
        true);
    const auto projected = project_ndms_native_inventory(
        {},
        true,
        claims,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);

    REQUIRE(projected.ownership_inventory_available);
    CHECK(projected.interfaces.empty());
    REQUIRE(projected.retained_deletions.size() == 1U);
    const auto& retained = projected.retained_deletions.front();
    CHECK(retained.interface_name == "Wireguard5");
    CHECK(retained.ownership_revision ==
          "ndms-native-owner-tombstone-v1-" + std::string(64U, 'b'));
    CHECK(retained.forget_candidate);
    CHECK(retained.forget_blockers.empty());
    CHECK(retained.deferred_authoritative_checks ==
          std::vector<NdmsNativeRetainedDeletionDeferredCheck>{
              NdmsNativeRetainedDeletionDeferredCheck::
                  encrypted_snapshot_or_absence,
              NdmsNativeRetainedDeletionDeferredCheck::
                  keen_pbr_dependencies,
              NdmsNativeRetainedDeletionDeferredCheck::
                  fresh_dual_scope_absence,
          });
}

TEST_CASE("retained deletion journal blockers remain exact and advisory") {
    const auto claims = ownership(
        NdmsNativeOwnershipLifecycle::
            deleted_save_acknowledged_unverified,
        NdmsNativeTunnelImportKind::wireguard,
        "Wireguard5",
        true);
    const auto projected = project_ndms_native_inventory(
        {},
        false,
        claims,
        NdmsNativeImportJournalReadinessState::recovery_required,
        NdmsNativeDeleteWalReadiness::unfinished);

    REQUIRE(projected.retained_deletions.size() == 1U);
    const auto& retained = projected.retained_deletions.front();
    CHECK_FALSE(retained.forget_candidate);
    CHECK(has_forget_blocker(
        retained, NdmsNativeRetainedDeletionBlocker::catalog_not_fresh));
    CHECK(has_forget_blocker(
        retained,
        NdmsNativeRetainedDeletionBlocker::import_recovery_required));
    CHECK(has_forget_blocker(
        retained,
        NdmsNativeRetainedDeletionBlocker::delete_recovery_required));
}

TEST_CASE("an absent claim is foreign but an unreadable inventory is unknown") {
    NdmsNativeOwnershipInspection empty;
    empty.readable = true;
    const auto foreign = project_ndms_native_inventory(
        {tunnel("Wireguard5")},
        true,
        empty,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);
    REQUIRE(foreign.interfaces.size() == 1U);
    CHECK(foreign.interfaces.front().ownership_state ==
          NdmsNativeInventoryOwnershipState::foreign);
    CHECK_FALSE(foreign.interfaces.front().ownership_revision.has_value());
    CHECK(has_blocker(
        foreign.interfaces.front(),
        NdmsNativeInventoryDeleteBlocker::ownership_absent));

    NdmsNativeOwnershipInspection unreadable;
    const auto unknown = project_ndms_native_inventory(
        {tunnel("Wireguard5")},
        true,
        unreadable,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);
    REQUIRE(unknown.interfaces.size() == 1U);
    CHECK_FALSE(unknown.ownership_inventory_available);
    CHECK(unknown.retained_deletions.empty());
    CHECK(unknown.interfaces.front().ownership_state ==
          NdmsNativeInventoryOwnershipState::unavailable);
    CHECK_FALSE(unknown.interfaces.front().ownership_revision.has_value());
    CHECK(has_blocker(
        unknown.interfaces.front(),
        NdmsNativeInventoryDeleteBlocker::
            ownership_inventory_unavailable));
}

TEST_CASE("malformed or duplicate redacted claims fail the whole view closed") {
    auto duplicate = ownership();
    duplicate.claims.push_back(duplicate.claims.front());
    const auto duplicate_projection = project_ndms_native_inventory(
        {tunnel("Wireguard5")},
        true,
        duplicate,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);
    CHECK_FALSE(duplicate_projection.ownership_inventory_available);
    REQUIRE(duplicate_projection.interfaces.size() == 1U);
    CHECK(duplicate_projection.interfaces.front().ownership_state ==
          NdmsNativeInventoryOwnershipState::unavailable);

    auto malformed = ownership();
    malformed.claims.front().ownership_revision = "secret with spaces";
    const auto malformed_projection = project_ndms_native_inventory(
        {tunnel("Wireguard5")},
        true,
        malformed,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);
    CHECK_FALSE(malformed_projection.ownership_inventory_available);
    REQUIRE(malformed_projection.interfaces.size() == 1U);
    CHECK(malformed_projection.interfaces.front().ownership_state ==
          NdmsNativeInventoryOwnershipState::unavailable);

    auto forged_capability = ownership();
    forged_capability.claims.front().retained_deletion_forget_capable = true;
    const auto forged_projection = project_ndms_native_inventory(
        {tunnel("Wireguard5")},
        true,
        forged_capability,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);
    CHECK_FALSE(forged_projection.ownership_inventory_available);
    CHECK(forged_projection.retained_deletions.empty());
}

TEST_CASE("retained deletion projection stays bounded and sorted") {
    NdmsNativeOwnershipInspection claims;
    claims.readable = true;
    for (int slot = 98; slot >= 5; --slot) {
        claims.claims.push_back(NdmsNativeOwnershipInspectionItem{
            "Wireguard" + std::to_string(slot),
            NdmsNativeTunnelImportKind::wireguard,
            NdmsNativeOwnershipLifecycle::
                deleted_save_acknowledged_unverified,
            "ndms-native-owner-tombstone-v1-" + std::string(64U, 'b'),
            true,
        });
    }
    const auto projected = project_ndms_native_inventory(
        {},
        true,
        claims,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);

    REQUIRE(projected.ownership_inventory_available);
    REQUIRE(projected.retained_deletions.size() == 94U);
    CHECK(std::is_sorted(
        projected.retained_deletions.begin(),
        projected.retained_deletions.end(),
        [](const auto& left, const auto& right) {
            return left.interface_name < right.interface_name;
        }));
    CHECK(std::all_of(
        projected.retained_deletions.begin(),
        projected.retained_deletions.end(),
        [](const auto& retained) { return retained.forget_candidate; }));
}

TEST_CASE("known catalogue and journal blockers prevent candidacy precisely") {
    const auto claims = ownership(
        NdmsNativeOwnershipLifecycle::active_running_only,
        NdmsNativeTunnelImportKind::wireguard);
    const auto projected = project_ndms_native_inventory(
        {tunnel("Wireguard5", NdmsTunnelKind::amnezia_wireguard)},
        false,
        claims,
        NdmsNativeImportJournalReadinessState::recovery_required,
        NdmsNativeDeleteWalReadiness::unfinished);

    REQUIRE(projected.interfaces.size() == 1U);
    const auto& item = projected.interfaces.front();
    CHECK(item.ownership_state ==
          NdmsNativeInventoryOwnershipState::panel_owned_active);
    CHECK_FALSE(item.delete_candidate);
    CHECK(has_blocker(
        item, NdmsNativeInventoryDeleteBlocker::catalog_not_fresh));
    CHECK(has_blocker(
        item,
        NdmsNativeInventoryDeleteBlocker::ownership_kind_mismatch));
    CHECK(has_blocker(
        item,
        NdmsNativeInventoryDeleteBlocker::import_recovery_required));
    CHECK(has_blocker(
        item,
        NdmsNativeInventoryDeleteBlocker::delete_recovery_required));
    CHECK(item.deferred_authoritative_checks.size() == 3U);
}

TEST_CASE("never-activated import state is not authoritative for delete") {
    const auto projected = project_ndms_native_inventory(
        {tunnel("Wireguard5")},
        true,
        ownership(),
        NdmsNativeImportJournalReadinessState::clean_never_activated,
        NdmsNativeDeleteWalReadiness::clean);

    REQUIRE(projected.interfaces.size() == 1U);
    CHECK_FALSE(projected.interfaces.front().delete_candidate);
    CHECK(has_blocker(
        projected.interfaces.front(),
        NdmsNativeInventoryDeleteBlocker::
            import_journal_not_authoritatively_clean));
}

TEST_CASE("protected native slots and non-native interfaces stay inapplicable") {
    NdmsNativeOwnershipInspection empty;
    empty.readable = true;
    const auto projected = project_ndms_native_inventory(
        {tunnel("Wireguard4"),
         tunnel("OpenVpn0", NdmsTunnelKind::openvpn)},
        true,
        empty,
        NdmsNativeImportJournalReadinessState::clean,
        NdmsNativeDeleteWalReadiness::clean);

    REQUIRE(projected.interfaces.size() == 2U);
    CHECK(projected.interfaces[0].ownership_state ==
          NdmsNativeInventoryOwnershipState::foreign);
    CHECK(has_blocker(
        projected.interfaces[0],
        NdmsNativeInventoryDeleteBlocker::
            invalid_or_protected_target));
    CHECK(projected.interfaces[1].ownership_state ==
          NdmsNativeInventoryOwnershipState::not_applicable);
    CHECK(has_blocker(
        projected.interfaces[1],
        NdmsNativeInventoryDeleteBlocker::unsupported_kind));
}

TEST_CASE("projection enum names are stable and redacted") {
    CHECK(std::string{ndms_native_inventory_ownership_state_name(
              NdmsNativeInventoryOwnershipState::panel_owned_active)} ==
          "panel_owned_active");
    CHECK(std::string{ndms_native_inventory_delete_blocker_name(
              NdmsNativeInventoryDeleteBlocker::delete_journal_unsafe)} ==
          "delete_journal_unsafe");
    CHECK(std::string{ndms_native_inventory_deferred_delete_check_name(
              NdmsNativeInventoryDeferredDeleteCheck::
                  keen_pbr_dependencies)} ==
          "keen_pbr_dependencies");
    CHECK(std::string{ndms_native_retained_deletion_blocker_name(
              NdmsNativeRetainedDeletionBlocker::target_present)} ==
          "target_present");
    CHECK(std::string{
              ndms_native_retained_deletion_deferred_check_name(
                  NdmsNativeRetainedDeletionDeferredCheck::
                      fresh_dual_scope_absence)} ==
          "fresh_dual_scope_absence");
}
