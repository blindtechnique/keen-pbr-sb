#include "ndms_native_inventory_projection.hpp"

#include "ndms_wireguard_identity.hpp"

#include <algorithm>
#include <map>
#include <string_view>

namespace keen_pbr3 {
namespace {

constexpr std::size_t kMaximumOwnershipClaims = 128U;

bool native_wireguard_kind(const NdmsTunnelKind kind) noexcept {
    return kind == NdmsTunnelKind::wireguard ||
           kind == NdmsTunnelKind::amnezia_wireguard;
}

bool known_import_kind(const NdmsNativeTunnelImportKind kind) noexcept {
    return kind == NdmsNativeTunnelImportKind::wireguard ||
           kind == NdmsNativeTunnelImportKind::amnezia_wireguard;
}

bool matching_kind(const NdmsTunnelKind observed,
                   const NdmsNativeTunnelImportKind claimed) noexcept {
    return (observed == NdmsTunnelKind::wireguard &&
            claimed == NdmsNativeTunnelImportKind::wireguard) ||
           (observed == NdmsTunnelKind::amnezia_wireguard &&
            claimed ==
                NdmsNativeTunnelImportKind::amnezia_wireguard);
}

bool known_lifecycle(
    const NdmsNativeOwnershipLifecycle lifecycle) noexcept {
    return lifecycle ==
               NdmsNativeOwnershipLifecycle::active_running_only ||
           lifecycle == NdmsNativeOwnershipLifecycle::
               active_save_acknowledged_unverified ||
           lifecycle == NdmsNativeOwnershipLifecycle::
               deleted_save_acknowledged_unverified;
}

bool lower_hex_digest(const std::string_view value) noexcept {
    return value.size() == 64U &&
           std::all_of(value.begin(), value.end(), [](const char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

bool revision_with_prefix(const std::string_view value,
                          const std::string_view prefix) noexcept {
    return value.size() == prefix.size() + 64U &&
           value.substr(0U, prefix.size()) == prefix &&
           lower_hex_digest(value.substr(prefix.size()));
}

bool valid_opaque_revision(
    const NdmsNativeOwnershipInspectionItem& claim) noexcept {
    if (claim.lifecycle == NdmsNativeOwnershipLifecycle::
                               deleted_save_acknowledged_unverified) {
        return revision_with_prefix(
            claim.ownership_revision,
            "ndms-native-owner-tombstone-v1-");
    }
    return revision_with_prefix(
               claim.ownership_revision, "ndms-native-owner-v2-") ||
           revision_with_prefix(
               claim.ownership_revision, "ndms-native-owner-v3-");
}

using ClaimMap =
    std::map<std::string, const NdmsNativeOwnershipInspectionItem*>;

std::optional<ClaimMap> validated_claims(
    const NdmsNativeOwnershipInspection& ownership) {
    if (!ownership.readable ||
        ownership.claims.size() > kMaximumOwnershipClaims) {
        return std::nullopt;
    }
    ClaimMap claims;
    for (const auto& claim : ownership.claims) {
        const auto identity =
            parse_ndms_wireguard_identity(claim.interface_name);
        if (!identity || identity->canonical_name() != claim.interface_name ||
            !ndms_wireguard_identity_is_managed_candidate(*identity) ||
            !known_import_kind(claim.kind) ||
            !known_lifecycle(claim.lifecycle) ||
            !valid_opaque_revision(claim) ||
            !claims.emplace(claim.interface_name, &claim).second) {
            return std::nullopt;
        }
    }
    return claims;
}

void add_import_journal_blocker(
    NdmsNativeInterfaceInventoryProjection& projection,
    const NdmsNativeImportJournalReadinessState state) {
    switch (state) {
    case NdmsNativeImportJournalReadinessState::clean:
        return;
    case NdmsNativeImportJournalReadinessState::clean_never_activated:
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::
                import_journal_not_authoritatively_clean);
        return;
    case NdmsNativeImportJournalReadinessState::recovery_required:
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::import_recovery_required);
        return;
    case NdmsNativeImportJournalReadinessState::unsafe:
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::import_journal_unsafe);
        return;
    case NdmsNativeImportJournalReadinessState::unavailable:
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::
                import_journal_unavailable);
        return;
    }
    projection.delete_blockers.push_back(
        NdmsNativeInventoryDeleteBlocker::import_journal_unavailable);
}

void add_delete_journal_blocker(
    NdmsNativeInterfaceInventoryProjection& projection,
    const NdmsNativeDeleteWalReadiness state) {
    switch (state) {
    case NdmsNativeDeleteWalReadiness::clean:
        return;
    case NdmsNativeDeleteWalReadiness::unfinished:
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::delete_recovery_required);
        return;
    case NdmsNativeDeleteWalReadiness::unsafe:
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::delete_journal_unsafe);
        return;
    }
    projection.delete_blockers.push_back(
        NdmsNativeInventoryDeleteBlocker::delete_journal_unsafe);
}

NdmsNativeInterfaceInventoryProjection project_one(
    const NdmsTunnelInterface& interface,
    const bool catalog_fresh,
    const ClaimMap* claims,
    const NdmsNativeImportJournalReadinessState import_journal,
    const NdmsNativeDeleteWalReadiness delete_journal) {
    NdmsNativeInterfaceInventoryProjection projection;
    projection.interface_name = interface.firmware_interface_name;

    if (!native_wireguard_kind(interface.kind)) {
        projection.ownership_state =
            NdmsNativeInventoryOwnershipState::not_applicable;
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::unsupported_kind);
        return projection;
    }

    const auto identity = parse_ndms_wireguard_identity(
        interface.firmware_interface_name);
    if (!identity ||
        identity->canonical_name() != interface.firmware_interface_name ||
        !ndms_wireguard_identity_is_managed_candidate(*identity)) {
        projection.ownership_state =
            NdmsNativeInventoryOwnershipState::foreign;
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::
                invalid_or_protected_target);
        return projection;
    }

    if (claims == nullptr) {
        projection.ownership_state =
            NdmsNativeInventoryOwnershipState::unavailable;
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::
                ownership_inventory_unavailable);
        return projection;
    }

    const auto found = claims->find(interface.firmware_interface_name);
    if (found == claims->end()) {
        projection.ownership_state =
            NdmsNativeInventoryOwnershipState::foreign;
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::ownership_absent);
        return projection;
    }

    const auto& claim = *found->second;
    projection.ownership_lifecycle = claim.lifecycle;
    projection.ownership_revision = claim.ownership_revision;
    if (claim.lifecycle == NdmsNativeOwnershipLifecycle::
                               deleted_save_acknowledged_unverified) {
        // Do not call a tombstone foreign merely because the firmware row has
        // reappeared.  Its exact lifecycle remains durable panel ownership.
        projection.ownership_state =
            NdmsNativeInventoryOwnershipState::panel_owned_tombstone;
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::ownership_not_active);
        return projection;
    }

    projection.ownership_state =
        NdmsNativeInventoryOwnershipState::panel_owned_active;
    projection.deferred_authoritative_checks = {
        NdmsNativeInventoryDeferredDeleteCheck::encrypted_snapshot,
        NdmsNativeInventoryDeferredDeleteCheck::keen_pbr_dependencies,
        NdmsNativeInventoryDeferredDeleteCheck::direct_ndms_state,
    };
    if (!catalog_fresh) {
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::catalog_not_fresh);
    }
    if (!matching_kind(interface.kind, claim.kind)) {
        projection.delete_blockers.push_back(
            NdmsNativeInventoryDeleteBlocker::ownership_kind_mismatch);
    }
    add_import_journal_blocker(projection, import_journal);
    add_delete_journal_blocker(projection, delete_journal);
    projection.delete_candidate = projection.delete_blockers.empty();
    return projection;
}

} // namespace

NdmsNativeInventoryProjection project_ndms_native_inventory(
    const std::vector<NdmsTunnelInterface>& interfaces,
    const bool catalog_fresh,
    const NdmsNativeOwnershipInspection& ownership,
    const NdmsNativeImportJournalReadinessState import_journal,
    const NdmsNativeDeleteWalReadiness delete_journal) noexcept {
    NdmsNativeInventoryProjection result;
    result.observed_import_journal_state = import_journal;
    result.observed_delete_journal_state = delete_journal;
    try {
        const auto claims = validated_claims(ownership);
        result.ownership_inventory_available = claims.has_value();
        result.interfaces.reserve(interfaces.size());
        for (const auto& interface : interfaces) {
            result.interfaces.push_back(project_one(
                interface,
                catalog_fresh,
                claims ? &*claims : nullptr,
                import_journal,
                delete_journal));
        }
    } catch (...) {
        result.ownership_inventory_available = false;
        result.interfaces.clear();
        try {
            result.interfaces.reserve(interfaces.size());
            for (const auto& interface : interfaces) {
                NdmsNativeInterfaceInventoryProjection projection;
                projection.interface_name =
                    interface.firmware_interface_name;
                projection.ownership_state =
                    native_wireguard_kind(interface.kind)
                        ? NdmsNativeInventoryOwnershipState::unavailable
                        : NdmsNativeInventoryOwnershipState::not_applicable;
                projection.delete_blockers.push_back(
                    native_wireguard_kind(interface.kind)
                        ? NdmsNativeInventoryDeleteBlocker::
                              ownership_inventory_unavailable
                        : NdmsNativeInventoryDeleteBlocker::
                              unsupported_kind);
                result.interfaces.push_back(std::move(projection));
            }
        } catch (...) {
            result.interfaces.clear();
        }
    }
    return result;
}

const char* ndms_native_inventory_ownership_state_name(
    const NdmsNativeInventoryOwnershipState state) noexcept {
    switch (state) {
    case NdmsNativeInventoryOwnershipState::not_applicable:
        return "not_applicable";
    case NdmsNativeInventoryOwnershipState::foreign:
        return "foreign";
    case NdmsNativeInventoryOwnershipState::panel_owned_active:
        return "panel_owned_active";
    case NdmsNativeInventoryOwnershipState::panel_owned_tombstone:
        return "panel_owned_tombstone";
    case NdmsNativeInventoryOwnershipState::unavailable:
        return "unavailable";
    }
    return "unavailable";
}

const char* ndms_native_inventory_delete_blocker_name(
    const NdmsNativeInventoryDeleteBlocker blocker) noexcept {
    switch (blocker) {
    case NdmsNativeInventoryDeleteBlocker::unsupported_kind:
        return "unsupported_kind";
    case NdmsNativeInventoryDeleteBlocker::invalid_or_protected_target:
        return "invalid_or_protected_target";
    case NdmsNativeInventoryDeleteBlocker::catalog_not_fresh:
        return "catalog_not_fresh";
    case NdmsNativeInventoryDeleteBlocker::
        ownership_inventory_unavailable:
        return "ownership_inventory_unavailable";
    case NdmsNativeInventoryDeleteBlocker::ownership_absent:
        return "ownership_absent";
    case NdmsNativeInventoryDeleteBlocker::ownership_not_active:
        return "ownership_not_active";
    case NdmsNativeInventoryDeleteBlocker::ownership_kind_mismatch:
        return "ownership_kind_mismatch";
    case NdmsNativeInventoryDeleteBlocker::
        import_journal_not_authoritatively_clean:
        return "import_journal_not_authoritatively_clean";
    case NdmsNativeInventoryDeleteBlocker::import_recovery_required:
        return "import_recovery_required";
    case NdmsNativeInventoryDeleteBlocker::import_journal_unsafe:
        return "import_journal_unsafe";
    case NdmsNativeInventoryDeleteBlocker::import_journal_unavailable:
        return "import_journal_unavailable";
    case NdmsNativeInventoryDeleteBlocker::delete_recovery_required:
        return "delete_recovery_required";
    case NdmsNativeInventoryDeleteBlocker::delete_journal_unsafe:
        return "delete_journal_unsafe";
    }
    return "ownership_inventory_unavailable";
}

const char* ndms_native_inventory_deferred_delete_check_name(
    const NdmsNativeInventoryDeferredDeleteCheck check) noexcept {
    switch (check) {
    case NdmsNativeInventoryDeferredDeleteCheck::encrypted_snapshot:
        return "encrypted_snapshot";
    case NdmsNativeInventoryDeferredDeleteCheck::keen_pbr_dependencies:
        return "keen_pbr_dependencies";
    case NdmsNativeInventoryDeferredDeleteCheck::direct_ndms_state:
        return "direct_ndms_state";
    }
    return "direct_ndms_state";
}

} // namespace keen_pbr3
