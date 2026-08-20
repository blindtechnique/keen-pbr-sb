#ifdef WITH_API

#include "handler_ndms_names.hpp"

#include "../keenetic/ndms_catalog_cache.hpp"
#include "../keenetic/ndms_interface_inventory.hpp"
#include "../keenetic/ndms_interface_management.hpp"
#include "../keenetic/ndms_native_create_policy.hpp"
#include "../keenetic/ndms_native_import_readiness.hpp"
#include "../keenetic/ndms_vpn_server_service_cache.hpp"
#include "../keenetic/ndms_wireguard_identity.hpp"

#include <nlohmann/json.hpp>
#include <algorithm>
#include <optional>
#include <string_view>
#include <utility>

namespace keen_pbr3 {

namespace {

api::NdmsTunnelKindEnum api_tunnel_kind(NdmsTunnelKind kind) {
    switch (kind) {
    case NdmsTunnelKind::amnezia_wireguard:
        return api::NdmsTunnelKindEnum::AMNEZIA_WIREGUARD;
    case NdmsTunnelKind::wireguard:
        return api::NdmsTunnelKindEnum::WIREGUARD;
    case NdmsTunnelKind::openvpn:
        return api::NdmsTunnelKindEnum::OPENVPN;
    case NdmsTunnelKind::ike:
        return api::NdmsTunnelKindEnum::IKE;
    case NdmsTunnelKind::l2tp:
        return api::NdmsTunnelKindEnum::L2_TP;
    case NdmsTunnelKind::sstp:
        return api::NdmsTunnelKindEnum::SSTP;
    case NdmsTunnelKind::openconnect:
        return api::NdmsTunnelKindEnum::OPENCONNECT;
    case NdmsTunnelKind::http_proxy:
        return api::NdmsTunnelKindEnum::HTTP_PROXY;
    case NdmsTunnelKind::https_proxy:
        return api::NdmsTunnelKindEnum::HTTPS_PROXY;
    case NdmsTunnelKind::socks5_proxy:
        return api::NdmsTunnelKindEnum::SOCKS5_PROXY;
    }
    throw std::runtime_error("unsupported NDMS tunnel kind");
}

api::NdmsInterfaceRoleEnum api_interface_role(NdmsInterfaceRole role) {
    switch (role) {
    case NdmsInterfaceRole::client:
        return api::NdmsInterfaceRoleEnum::CLIENT;
    case NdmsInterfaceRole::server:
        return api::NdmsInterfaceRoleEnum::SERVER;
    case NdmsInterfaceRole::unknown:
        return api::NdmsInterfaceRoleEnum::UNKNOWN;
    }
    return api::NdmsInterfaceRoleEnum::UNKNOWN;
}

api::CatalogStatus api_catalog_status(
    NdmsCatalogCacheStatus status) {
    switch (status) {
    case NdmsCatalogCacheStatus::fresh:
        return api::CatalogStatus::FRESH;
    case NdmsCatalogCacheStatus::stale:
        return api::CatalogStatus::STALE;
    case NdmsCatalogCacheStatus::unavailable:
        return api::CatalogStatus::UNAVAILABLE;
    }
    return api::CatalogStatus::UNAVAILABLE;
}

api::NdmsVpnServerKind api_vpn_server_kind(
    NdmsVpnServerServiceKind kind) {
    switch (kind) {
    case NdmsVpnServerServiceKind::l2tp:
        return api::NdmsVpnServerKind::L2_TP;
    case NdmsVpnServerServiceKind::ikev1:
        return api::NdmsVpnServerKind::IKEV1;
    case NdmsVpnServerServiceKind::ikev2:
        return api::NdmsVpnServerKind::IKEV2;
    case NdmsVpnServerServiceKind::sstp:
        return api::NdmsVpnServerKind::SSTP;
    case NdmsVpnServerServiceKind::openconnect:
        return api::NdmsVpnServerKind::OPENCONNECT;
    }
    throw std::runtime_error("unsupported NDMS VPN server service kind");
}

const char* catalog_status_name(NdmsCatalogCacheStatus status) noexcept {
    switch (status) {
    case NdmsCatalogCacheStatus::fresh:
        return "fresh";
    case NdmsCatalogCacheStatus::stale:
        return "stale";
    case NdmsCatalogCacheStatus::unavailable:
        return "unavailable";
    }
    return "unavailable";
}

api::NdmsManagementBlockerElement api_management_blocker(
    NdmsInterfaceManagementBlocker blocker) {
    switch (blocker) {
    case NdmsInterfaceManagementBlocker::unsupported_kind:
        return api::NdmsManagementBlockerElement::UNSUPPORTED_KIND;
    case NdmsInterfaceManagementBlocker::unsupported_role:
        return api::NdmsManagementBlockerElement::UNSUPPORTED_ROLE;
    case NdmsInterfaceManagementBlocker::role_unknown:
        return api::NdmsManagementBlockerElement::ROLE_UNKNOWN;
    case NdmsInterfaceManagementBlocker::kernel_identity_unresolved:
        return api::NdmsManagementBlockerElement::
            KERNEL_IDENTITY_UNRESOLVED;
    case NdmsInterfaceManagementBlocker::typed_rci_unavailable:
        return api::NdmsManagementBlockerElement::TYPED_RCI_UNAVAILABLE;
    case NdmsInterfaceManagementBlocker::automatic_backup_unavailable:
        return api::NdmsManagementBlockerElement::
            AUTOMATIC_BACKUP_UNAVAILABLE;
    case NdmsInterfaceManagementBlocker::ownership_unknown:
        return api::NdmsManagementBlockerElement::OWNERSHIP_UNKNOWN;
    case NdmsInterfaceManagementBlocker::optimistic_revision_unavailable:
        return api::NdmsManagementBlockerElement::
            OPTIMISTIC_REVISION_UNAVAILABLE;
    }
    throw std::runtime_error("unsupported NDMS management blocker");
}

api::NdmsInterfaceManagementReadiness api_management_readiness(
    const NdmsTunnelInterface& tunnel) {
    const auto readiness = assess_ndms_interface_management(tunnel);
    api::NdmsInterfaceManagementReadiness result{};
    result.candidate = readiness.candidate;
    result.identity_stable = readiness.identity_stable;
    result.observed_revision = readiness.observed_revision;
    result.configuration_snapshot_available =
        readiness.configuration_snapshot_available;
    result.blockers.reserve(readiness.blockers.size());
    for (const auto blocker : readiness.blockers) {
        result.blockers.push_back(api_management_blocker(blocker));
    }
    return result;
}

api::NdmsNativeImportTargetRange native_import_target_range(
    const NdmsNativeWireguardTargetRange& source) {
    api::NdmsNativeImportTargetRange range{};
    range.prefix = api::NdmsNativeImportTargetPrefix::WIREGUARD;
    range.first_index = source.first_index;
    range.last_index = source.last_index;
    return range;
}

api::NdmsNativeImportJournalState api_native_import_journal_state(
    const NdmsNativeImportJournalReadinessState state) noexcept {
    switch (state) {
    case NdmsNativeImportJournalReadinessState::clean_never_activated:
        return api::NdmsNativeImportJournalState::CLEAN_NEVER_ACTIVATED;
    case NdmsNativeImportJournalReadinessState::clean:
        return api::NdmsNativeImportJournalState::CLEAN;
    case NdmsNativeImportJournalReadinessState::recovery_required:
        return api::NdmsNativeImportJournalState::RECOVERY_REQUIRED;
    case NdmsNativeImportJournalReadinessState::unsafe:
        return api::NdmsNativeImportJournalState::UNSAFE;
    case NdmsNativeImportJournalReadinessState::unavailable:
        return api::NdmsNativeImportJournalState::UNAVAILABLE;
    }
    return api::NdmsNativeImportJournalState::UNAVAILABLE;
}

api::NdmsNativeImportReadiness native_import_readiness(
    const NdmsNativeImportReadinessProvider& readiness_provider) {
    const auto policy = preview_ndms_native_create_policy();
    api::NdmsNativeImportReadiness readiness{};
    readiness.preview_only = policy.preview_only;
    readiness.apply_available = policy.apply_available;
    readiness.operation = policy.operation;
    readiness.request_name = policy.request_name;
    readiness.allocator_range =
        native_import_target_range(policy.allocator_range);
    readiness.eligible_returned_targets = native_import_target_range(
        policy.eligible_returned_targets);
    readiness.protected_targets.reserve(policy.protected_targets.size());
    for (const auto& range : policy.protected_targets) {
        readiness.protected_targets.push_back(
            native_import_target_range(range));
    }
    readiness.journal_state =
        api::NdmsNativeImportJournalState::DORMANT;
    if (readiness_provider) {
        try {
            readiness.journal_state = api_native_import_journal_state(
                readiness_provider());
        } catch (...) {
            // The endpoint stays available and fail-closed. A provider fault
            // can only degrade the redacted report; it cannot change any
            // mutation flag or remove an independent blocker.
            readiness.journal_state =
                api::NdmsNativeImportJournalState::UNAVAILABLE;
        }
    }
    readiness.reconcile_barrier_state =
        api::NdmsNativeImportReconcileBarrierState::DORMANT;
    readiness.blockers.reserve(policy.blockers.size());
    for (const auto blocker : policy.blockers) {
        switch (blocker) {
        case NdmsNativeCreatePolicyBlocker::writer_disabled:
            readiness.blockers.push_back(
                api::NdmsNativeImportBlocker::WRITER_DISABLED);
            break;
        case NdmsNativeCreatePolicyBlocker::allocator_range_unfenced:
            readiness.blockers.push_back(
                api::NdmsNativeImportBlocker::ALLOCATOR_RANGE_UNFENCED);
            break;
        case NdmsNativeCreatePolicyBlocker::
            recovery_journal_not_integrated:
            readiness.blockers.push_back(
                api::NdmsNativeImportBlocker::
                    RECOVERY_JOURNAL_NOT_INTEGRATED);
            break;
        case NdmsNativeCreatePolicyBlocker::
            reconcile_barrier_not_integrated:
            readiness.blockers.push_back(
                api::NdmsNativeImportBlocker::
                    RECONCILE_BARRIER_NOT_INTEGRATED);
            break;
        }
    }
    return readiness;
}

bool native_wireguard_kind(const NdmsTunnelKind kind) noexcept {
    return kind == NdmsTunnelKind::wireguard ||
           kind == NdmsTunnelKind::amnezia_wireguard;
}

bool managed_native_target(const NdmsTunnelInterface& tunnel) noexcept {
    const auto identity = parse_ndms_wireguard_identity(
        tunnel.firmware_interface_name);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity);
}

bool known_ownership_state(
    const NdmsNativeInventoryOwnershipState state) noexcept {
    switch (state) {
    case NdmsNativeInventoryOwnershipState::not_applicable:
    case NdmsNativeInventoryOwnershipState::foreign:
    case NdmsNativeInventoryOwnershipState::panel_owned_active:
    case NdmsNativeInventoryOwnershipState::panel_owned_tombstone:
    case NdmsNativeInventoryOwnershipState::unavailable:
        return true;
    }
    return false;
}

bool known_ownership_lifecycle(
    const NdmsNativeOwnershipLifecycle lifecycle) noexcept {
    switch (lifecycle) {
    case NdmsNativeOwnershipLifecycle::active_running_only:
    case NdmsNativeOwnershipLifecycle::
        active_save_acknowledged_unverified:
    case NdmsNativeOwnershipLifecycle::
        deleted_save_acknowledged_unverified:
        return true;
    }
    return false;
}

bool known_delete_blocker(
    const NdmsNativeInventoryDeleteBlocker blocker) noexcept {
    switch (blocker) {
    case NdmsNativeInventoryDeleteBlocker::unsupported_kind:
    case NdmsNativeInventoryDeleteBlocker::invalid_or_protected_target:
    case NdmsNativeInventoryDeleteBlocker::catalog_not_fresh:
    case NdmsNativeInventoryDeleteBlocker::
        ownership_inventory_unavailable:
    case NdmsNativeInventoryDeleteBlocker::ownership_absent:
    case NdmsNativeInventoryDeleteBlocker::ownership_not_active:
    case NdmsNativeInventoryDeleteBlocker::ownership_kind_mismatch:
    case NdmsNativeInventoryDeleteBlocker::
        import_journal_not_authoritatively_clean:
    case NdmsNativeInventoryDeleteBlocker::import_recovery_required:
    case NdmsNativeInventoryDeleteBlocker::import_journal_unsafe:
    case NdmsNativeInventoryDeleteBlocker::import_journal_unavailable:
    case NdmsNativeInventoryDeleteBlocker::delete_recovery_required:
    case NdmsNativeInventoryDeleteBlocker::delete_journal_unsafe:
        return true;
    }
    return false;
}

bool known_deferred_check(
    const NdmsNativeInventoryDeferredDeleteCheck check) noexcept {
    switch (check) {
    case NdmsNativeInventoryDeferredDeleteCheck::encrypted_snapshot:
    case NdmsNativeInventoryDeferredDeleteCheck::keen_pbr_dependencies:
    case NdmsNativeInventoryDeferredDeleteCheck::direct_ndms_state:
        return true;
    }
    return false;
}

bool known_import_journal_state(
    const NdmsNativeImportJournalReadinessState state) noexcept {
    switch (state) {
    case NdmsNativeImportJournalReadinessState::clean_never_activated:
    case NdmsNativeImportJournalReadinessState::clean:
    case NdmsNativeImportJournalReadinessState::recovery_required:
    case NdmsNativeImportJournalReadinessState::unsafe:
    case NdmsNativeImportJournalReadinessState::unavailable:
        return true;
    }
    return false;
}

bool known_delete_journal_state(
    const NdmsNativeDeleteWalReadiness state) noexcept {
    switch (state) {
    case NdmsNativeDeleteWalReadiness::clean:
    case NdmsNativeDeleteWalReadiness::unfinished:
    case NdmsNativeDeleteWalReadiness::unsafe:
        return true;
    }
    return false;
}

bool lower_hex_digest(const std::string_view value) noexcept {
    return value.size() == 64U &&
           std::all_of(
               value.begin(), value.end(), [](const char character) {
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

bool valid_ownership_revision(
    const std::string_view revision,
    const NdmsNativeOwnershipLifecycle lifecycle) noexcept {
    if (lifecycle == NdmsNativeOwnershipLifecycle::
                         deleted_save_acknowledged_unverified) {
        return revision_with_prefix(
            revision, "ndms-native-owner-tombstone-v1-");
    }
    return revision_with_prefix(revision, "ndms-native-owner-v2-") ||
           revision_with_prefix(revision, "ndms-native-owner-v3-");
}

std::optional<NdmsNativeInventoryDeleteBlocker>
import_journal_blocker(
    const NdmsNativeImportJournalReadinessState state) noexcept {
    switch (state) {
    case NdmsNativeImportJournalReadinessState::clean:
        return std::nullopt;
    case NdmsNativeImportJournalReadinessState::clean_never_activated:
        return NdmsNativeInventoryDeleteBlocker::
            import_journal_not_authoritatively_clean;
    case NdmsNativeImportJournalReadinessState::recovery_required:
        return NdmsNativeInventoryDeleteBlocker::
            import_recovery_required;
    case NdmsNativeImportJournalReadinessState::unsafe:
        return NdmsNativeInventoryDeleteBlocker::import_journal_unsafe;
    case NdmsNativeImportJournalReadinessState::unavailable:
        return NdmsNativeInventoryDeleteBlocker::
            import_journal_unavailable;
    }
    return std::nullopt;
}

std::optional<NdmsNativeInventoryDeleteBlocker>
delete_journal_blocker(const NdmsNativeDeleteWalReadiness state) noexcept {
    switch (state) {
    case NdmsNativeDeleteWalReadiness::clean:
        return std::nullopt;
    case NdmsNativeDeleteWalReadiness::unfinished:
        return NdmsNativeInventoryDeleteBlocker::
            delete_recovery_required;
    case NdmsNativeDeleteWalReadiness::unsafe:
        return NdmsNativeInventoryDeleteBlocker::delete_journal_unsafe;
    }
    return std::nullopt;
}

bool exact_simple_projection(
    const NdmsNativeInterfaceInventoryProjection& row,
    const NdmsNativeInventoryOwnershipState state,
    const NdmsNativeInventoryDeleteBlocker blocker) {
    return row.ownership_state == state &&
           !row.ownership_lifecycle.has_value() &&
           !row.ownership_revision.has_value() &&
           !row.delete_candidate &&
           row.delete_blockers ==
               std::vector<NdmsNativeInventoryDeleteBlocker>{blocker} &&
           row.deferred_authoritative_checks.empty();
}

bool valid_active_projection(
    const NdmsNativeInterfaceInventoryProjection& row,
    const bool catalog_fresh,
    const NdmsNativeImportJournalReadinessState import_journal,
    const NdmsNativeDeleteWalReadiness delete_journal) {
    if (!row.ownership_lifecycle.has_value() ||
        (*row.ownership_lifecycle !=
             NdmsNativeOwnershipLifecycle::active_running_only &&
         *row.ownership_lifecycle != NdmsNativeOwnershipLifecycle::
                                         active_save_acknowledged_unverified) ||
        !row.ownership_revision.has_value() ||
        !valid_ownership_revision(
            *row.ownership_revision, *row.ownership_lifecycle) ||
        row.deferred_authoritative_checks !=
            std::vector<NdmsNativeInventoryDeferredDeleteCheck>{
                NdmsNativeInventoryDeferredDeleteCheck::
                    encrypted_snapshot,
                NdmsNativeInventoryDeferredDeleteCheck::
                    keen_pbr_dependencies,
                NdmsNativeInventoryDeferredDeleteCheck::direct_ndms_state,
            }) {
        return false;
    }

    std::vector<NdmsNativeInventoryDeleteBlocker> expected;
    if (!catalog_fresh) {
        expected.push_back(
            NdmsNativeInventoryDeleteBlocker::catalog_not_fresh);
    }
    if (std::find(
            row.delete_blockers.begin(),
            row.delete_blockers.end(),
            NdmsNativeInventoryDeleteBlocker::ownership_kind_mismatch) !=
        row.delete_blockers.end()) {
        expected.push_back(
            NdmsNativeInventoryDeleteBlocker::ownership_kind_mismatch);
    }
    if (const auto blocker = import_journal_blocker(import_journal)) {
        expected.push_back(*blocker);
    }
    if (const auto blocker = delete_journal_blocker(delete_journal)) {
        expected.push_back(*blocker);
    }
    return row.delete_blockers == expected &&
           row.delete_candidate == expected.empty();
}

bool valid_native_projection_row(
    const NdmsTunnelInterface& tunnel,
    const NdmsNativeInterfaceInventoryProjection& row,
    const bool catalog_fresh,
    const bool ownership_inventory_available,
    const NdmsNativeImportJournalReadinessState import_journal,
    const NdmsNativeDeleteWalReadiness delete_journal) {
    if (row.interface_name != tunnel.firmware_interface_name ||
        !known_ownership_state(row.ownership_state) ||
        (row.ownership_lifecycle.has_value() &&
         !known_ownership_lifecycle(*row.ownership_lifecycle)) ||
        row.delete_blockers.size() > 13U ||
        !std::all_of(
            row.delete_blockers.begin(),
            row.delete_blockers.end(), known_delete_blocker) ||
        row.deferred_authoritative_checks.size() > 3U ||
        !std::all_of(
            row.deferred_authoritative_checks.begin(),
            row.deferred_authoritative_checks.end(),
            known_deferred_check)) {
        return false;
    }

    if (!native_wireguard_kind(tunnel.kind)) {
        return exact_simple_projection(
            row,
            NdmsNativeInventoryOwnershipState::not_applicable,
            NdmsNativeInventoryDeleteBlocker::unsupported_kind);
    }
    if (!managed_native_target(tunnel)) {
        return exact_simple_projection(
            row,
            NdmsNativeInventoryOwnershipState::foreign,
            NdmsNativeInventoryDeleteBlocker::
                invalid_or_protected_target);
    }
    if (!ownership_inventory_available) {
        return exact_simple_projection(
            row,
            NdmsNativeInventoryOwnershipState::unavailable,
            NdmsNativeInventoryDeleteBlocker::
                ownership_inventory_unavailable);
    }

    switch (row.ownership_state) {
    case NdmsNativeInventoryOwnershipState::foreign:
        return exact_simple_projection(
            row,
            NdmsNativeInventoryOwnershipState::foreign,
            NdmsNativeInventoryDeleteBlocker::ownership_absent);
    case NdmsNativeInventoryOwnershipState::panel_owned_active:
        return valid_active_projection(
            row, catalog_fresh, import_journal, delete_journal);
    case NdmsNativeInventoryOwnershipState::panel_owned_tombstone:
        return row.ownership_lifecycle ==
                   std::optional<NdmsNativeOwnershipLifecycle>{
                       NdmsNativeOwnershipLifecycle::
                           deleted_save_acknowledged_unverified} &&
               row.ownership_revision.has_value() &&
               valid_ownership_revision(
                   *row.ownership_revision, *row.ownership_lifecycle) &&
               !row.delete_candidate &&
               row.delete_blockers ==
                   std::vector<NdmsNativeInventoryDeleteBlocker>{
                       NdmsNativeInventoryDeleteBlocker::
                           ownership_not_active} &&
               row.deferred_authoritative_checks.empty();
    case NdmsNativeInventoryOwnershipState::not_applicable:
    case NdmsNativeInventoryOwnershipState::unavailable:
        return false;
    }
    return false;
}

bool valid_native_inventory_projection(
    const NdmsNativeInventoryProjection& projection,
    const std::vector<NdmsTunnelInterface>& tunnels,
    const bool catalog_fresh) {
    if (!known_import_journal_state(
            projection.observed_import_journal_state) ||
        !known_delete_journal_state(
            projection.observed_delete_journal_state) ||
        projection.interfaces.size() != tunnels.size()) {
        return false;
    }
    for (std::size_t index = 0U; index < tunnels.size(); ++index) {
        if (!valid_native_projection_row(
                tunnels[index],
                projection.interfaces[index],
                catalog_fresh,
                projection.ownership_inventory_available,
                projection.observed_import_journal_state,
                projection.observed_delete_journal_state)) {
            return false;
        }
    }
    return true;
}

std::optional<NdmsNativeInventoryProjection>
observe_native_inventory_projection(
    const NdmsNativeInventoryProjectionProvider& provider,
    const std::vector<NdmsTunnelInterface>& tunnels,
    const bool catalog_fresh) {
    if (!provider) return std::nullopt;
    try {
        auto projection = provider(tunnels, catalog_fresh);
        if (valid_native_inventory_projection(
                projection, tunnels, catalog_fresh)) {
            return projection;
        }
    } catch (...) {
        // A provider fault invalidates the entire native-mutation projection.
        // Never preserve apparently good rows from a malformed batch.
    }
    return std::nullopt;
}

api::OwnershipState api_ownership_state(
    const NdmsNativeInventoryOwnershipState state) {
    switch (state) {
    case NdmsNativeInventoryOwnershipState::not_applicable:
        return api::OwnershipState::NOT_APPLICABLE;
    case NdmsNativeInventoryOwnershipState::foreign:
        return api::OwnershipState::FOREIGN;
    case NdmsNativeInventoryOwnershipState::panel_owned_active:
        return api::OwnershipState::PANEL_OWNED_ACTIVE;
    case NdmsNativeInventoryOwnershipState::panel_owned_tombstone:
        return api::OwnershipState::PANEL_OWNED_TOMBSTONE;
    case NdmsNativeInventoryOwnershipState::unavailable:
        return api::OwnershipState::UNAVAILABLE;
    }
    throw std::runtime_error("invalid native ownership state");
}

api::OwnershipLifecycle api_ownership_lifecycle(
    const NdmsNativeOwnershipLifecycle lifecycle) {
    switch (lifecycle) {
    case NdmsNativeOwnershipLifecycle::active_running_only:
        return api::OwnershipLifecycle::ACTIVE_RUNNING_ONLY;
    case NdmsNativeOwnershipLifecycle::
        active_save_acknowledged_unverified:
        return api::OwnershipLifecycle::
            ACTIVE_SAVE_ACKNOWLEDGED_UNVERIFIED;
    case NdmsNativeOwnershipLifecycle::
        deleted_save_acknowledged_unverified:
        return api::OwnershipLifecycle::
            DELETED_SAVE_ACKNOWLEDGED_UNVERIFIED;
    }
    throw std::runtime_error("invalid native ownership lifecycle");
}

api::NdmsNativeInventoryDeleteBlockerElement api_delete_blocker(
    const NdmsNativeInventoryDeleteBlocker blocker) {
    using ApiBlocker = api::NdmsNativeInventoryDeleteBlockerElement;
    switch (blocker) {
    case NdmsNativeInventoryDeleteBlocker::unsupported_kind:
        return ApiBlocker::UNSUPPORTED_KIND;
    case NdmsNativeInventoryDeleteBlocker::invalid_or_protected_target:
        return ApiBlocker::INVALID_OR_PROTECTED_TARGET;
    case NdmsNativeInventoryDeleteBlocker::catalog_not_fresh:
        return ApiBlocker::CATALOG_NOT_FRESH;
    case NdmsNativeInventoryDeleteBlocker::
        ownership_inventory_unavailable:
        return ApiBlocker::OWNERSHIP_INVENTORY_UNAVAILABLE;
    case NdmsNativeInventoryDeleteBlocker::ownership_absent:
        return ApiBlocker::OWNERSHIP_ABSENT;
    case NdmsNativeInventoryDeleteBlocker::ownership_not_active:
        return ApiBlocker::OWNERSHIP_NOT_ACTIVE;
    case NdmsNativeInventoryDeleteBlocker::ownership_kind_mismatch:
        return ApiBlocker::OWNERSHIP_KIND_MISMATCH;
    case NdmsNativeInventoryDeleteBlocker::
        import_journal_not_authoritatively_clean:
        return ApiBlocker::IMPORT_JOURNAL_NOT_AUTHORITATIVELY_CLEAN;
    case NdmsNativeInventoryDeleteBlocker::import_recovery_required:
        return ApiBlocker::IMPORT_RECOVERY_REQUIRED;
    case NdmsNativeInventoryDeleteBlocker::import_journal_unsafe:
        return ApiBlocker::IMPORT_JOURNAL_UNSAFE;
    case NdmsNativeInventoryDeleteBlocker::import_journal_unavailable:
        return ApiBlocker::IMPORT_JOURNAL_UNAVAILABLE;
    case NdmsNativeInventoryDeleteBlocker::delete_recovery_required:
        return ApiBlocker::DELETE_RECOVERY_REQUIRED;
    case NdmsNativeInventoryDeleteBlocker::delete_journal_unsafe:
        return ApiBlocker::DELETE_JOURNAL_UNSAFE;
    }
    throw std::runtime_error("invalid native delete blocker");
}

api::NdmsNativeInventoryDeferredDeleteCheckElement api_deferred_check(
    const NdmsNativeInventoryDeferredDeleteCheck check) {
    using ApiCheck = api::NdmsNativeInventoryDeferredDeleteCheckElement;
    switch (check) {
    case NdmsNativeInventoryDeferredDeleteCheck::encrypted_snapshot:
        return ApiCheck::ENCRYPTED_SNAPSHOT;
    case NdmsNativeInventoryDeferredDeleteCheck::keen_pbr_dependencies:
        return ApiCheck::KEEN_PBR_DEPENDENCIES;
    case NdmsNativeInventoryDeferredDeleteCheck::direct_ndms_state:
        return ApiCheck::DIRECT_NDMS_STATE;
    }
    throw std::runtime_error("invalid native deferred delete check");
}

api::NativeMutation api_native_mutation(
    const NdmsNativeInterfaceInventoryProjection& source) {
    api::NativeMutation result{};
    result.ownership_state = api_ownership_state(source.ownership_state);
    if (source.ownership_lifecycle.has_value()) {
        result.ownership_lifecycle =
            api_ownership_lifecycle(*source.ownership_lifecycle);
    }
    result.ownership_revision = source.ownership_revision;
    result.delete_candidate = source.delete_candidate;
    result.delete_blockers.reserve(source.delete_blockers.size());
    for (const auto blocker : source.delete_blockers) {
        result.delete_blockers.push_back(api_delete_blocker(blocker));
    }
    result.deferred_authoritative_checks.reserve(
        source.deferred_authoritative_checks.size());
    for (const auto check : source.deferred_authoritative_checks) {
        result.deferred_authoritative_checks.push_back(
            api_deferred_check(check));
    }
    return result;
}

api::NativeMutation unavailable_native_mutation(
    const NdmsTunnelInterface& tunnel) {
    api::NativeMutation result{};
    result.delete_candidate = false;
    if (native_wireguard_kind(tunnel.kind)) {
        result.ownership_state = api::OwnershipState::UNAVAILABLE;
        result.delete_blockers = {
            api::NdmsNativeInventoryDeleteBlockerElement::
                OWNERSHIP_INVENTORY_UNAVAILABLE,
        };
    } else {
        result.ownership_state = api::OwnershipState::NOT_APPLICABLE;
        result.delete_blockers = {
            api::NdmsNativeInventoryDeleteBlockerElement::UNSUPPORTED_KIND,
        };
    }
    return result;
}

api::ObservedDeleteJournalState api_delete_journal_state(
    const NdmsNativeDeleteWalReadiness state) {
    switch (state) {
    case NdmsNativeDeleteWalReadiness::clean:
        return api::ObservedDeleteJournalState::CLEAN;
    case NdmsNativeDeleteWalReadiness::unfinished:
        return api::ObservedDeleteJournalState::RECOVERY_REQUIRED;
    case NdmsNativeDeleteWalReadiness::unsafe:
        return api::ObservedDeleteJournalState::UNSAFE;
    }
    throw std::runtime_error("invalid native delete journal state");
}

api::NativeMutationStatus native_mutation_status(
    const std::optional<NdmsNativeInventoryProjection>& projection) {
    api::NativeMutationStatus result{};
    result.advisory = true;
    if (!projection.has_value()) {
        result.ownership_inventory_available = false;
        result.observed_import_journal_state =
            api::NdmsNativeImportJournalState::UNAVAILABLE;
        result.observed_delete_journal_state =
            api::ObservedDeleteJournalState::UNAVAILABLE;
        return result;
    }
    result.ownership_inventory_available =
        projection->ownership_inventory_available;
    result.observed_import_journal_state =
        api_native_import_journal_state(
            projection->observed_import_journal_state);
    result.observed_delete_journal_state = api_delete_journal_state(
        projection->observed_delete_journal_state);
    return result;
}

api::NdmsInterfaceInventoryResponse typed_inventory(
    const NdmsInterfaceCatalog& catalog,
    NdmsCatalogCacheStatus catalog_status,
    const NdmsNativeImportReadinessProvider& readiness_provider,
    const NdmsNativeInventoryProjectionProvider& projection_provider) {
    api::NdmsInterfaceInventoryResponse response{};
    response.available =
        catalog.firmware_available &&
        catalog_status == NdmsCatalogCacheStatus::fresh;
    response.catalog_status = api_catalog_status(catalog_status);
    response.read_only = true;
    response.mutation_mode = api::MutationMode::DISABLED;
    response.required_guards = {
        api::RequiredGuard::TYPED_RCI,
        api::RequiredGuard::AUTOMATIC_BACKUP,
        api::RequiredGuard::OWNERSHIP_CHECK,
        api::RequiredGuard::OPTIMISTIC_REVISION,
    };
    response.native_import_readiness =
        native_import_readiness(readiness_provider);

    const bool catalog_is_fresh =
        catalog_status == NdmsCatalogCacheStatus::fresh;
    const auto native_projection = observe_native_inventory_projection(
        projection_provider, catalog.tunnels, catalog_is_fresh);
    response.native_mutation_status =
        native_mutation_status(native_projection);

    response.interfaces.reserve(catalog.tunnels.size());
    for (std::size_t index = 0U; index < catalog.tunnels.size(); ++index) {
        const auto& tunnel = catalog.tunnels[index];
        api::NdmsTunnelInterfaceElement item{};
        item.id = tunnel.id;
        item.firmware_interface_name = tunnel.firmware_interface_name;
        item.kernel_name = tunnel.kernel_name;
        item.label = tunnel.label;
        item.firmware_type = tunnel.firmware_type;
        item.kind = api_tunnel_kind(tunnel.kind);
        item.owner = api::Owner::KEENETIC;
        item.role = api_interface_role(tunnel.role);
        item.internal_vpn_server_candidate =
            catalog_is_fresh &&
            tunnel.internal_vpn_server_candidate;
        item.internal_vpn_server_role_confirmation_required =
            catalog_is_fresh &&
            tunnel.internal_vpn_server_role_confirmation_required;
        item.connected = tunnel.connected;
        item.link = tunnel.link;
        item.capabilities.can_edit = false;
        item.capabilities.can_delete = false;
        item.capabilities.can_hide = false;
        item.capabilities.backup_required = true;
        item.management_readiness = api_management_readiness(tunnel);
        item.native_mutation = native_projection.has_value()
            ? api_native_mutation(native_projection->interfaces[index])
            : unavailable_native_mutation(tunnel);
        response.interfaces.push_back(std::move(item));
    }
    return response;
}

api::NdmsVpnServerServiceInventoryResponse typed_vpn_service_inventory(
    const NdmsVpnServerServiceCatalog& catalog,
    NdmsCatalogCacheStatus catalog_status) {
    api::NdmsVpnServerServiceInventoryResponse response{};
    response.available =
        catalog.firmware_available &&
        catalog_status == NdmsCatalogCacheStatus::fresh;
    response.catalog_status = api_catalog_status(catalog_status);
    response.read_only = true;
    response.services.reserve(catalog.services.size());
    for (const auto& service : catalog.services) {
        api::NdmsVpnServerService item{};
        item.id = service.id;
        item.kind = api_vpn_server_kind(service.kind);
        item.label = service.label;
        item.enabled = service.enabled;
        item.bound_interface_id = service.bound_interface_id;
        item.inventory_revision = service.inventory_revision;
        item.source_cidrs.reserve(
            service.source_cidrs_v4.size() +
            service.source_cidrs_v6.size());
        item.source_cidrs.insert(
            item.source_cidrs.end(),
            service.source_cidrs_v4.begin(),
            service.source_cidrs_v4.end());
        item.source_cidrs.insert(
            item.source_cidrs.end(),
            service.source_cidrs_v6.begin(),
            service.source_cidrs_v6.end());
        response.services.push_back(std::move(item));
    }
    return response;
}

using RuntimeInterfaceNamesFn = std::function<std::vector<std::string>()>;
using TrafficInterfacesObserver =
    std::function<void(std::vector<std::string>)>;

struct CatalogResponse {
    NdmsInterfaceCatalog catalog;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
};

CatalogResponse catalog_for_response(
    NdmsCatalogCache& cache,
    const RuntimeInterfaceNamesFn& runtime_interface_names_fn) {
    auto snapshot = cache.get();
    std::vector<std::string> runtime_interface_names;
    try {
        runtime_interface_names = runtime_interface_names_fn();
    } catch (...) {
        // Runtime inventory is advisory for kernel-name resolution. The NDMS
        // metadata remains safe and useful when that live view is unavailable.
    }
    return {
        resolve_ndms_kernel_names(
            snapshot.catalog, runtime_interface_names),
        snapshot.status,
    };
}

void register_ndms_names_routes(
    ApiServer& server,
    NdmsCatalogCache& cache,
    RuntimeInterfaceNamesFn runtime_interface_names_fn,
    NdmsNativeImportReadinessProvider native_import_readiness_provider,
    NdmsNativeInventoryProjectionProvider native_inventory_projection_provider,
    TrafficInterfacesObserver traffic_interfaces_observer = {}) {
    server.get(
        "/api/system/interface-names",
        [&cache, runtime_interface_names_fn]() -> std::string {
            const auto response =
                catalog_for_response(cache, runtime_interface_names_fn);
            return nlohmann::json{
                {"names",
                 response.catalog.names.is_object()
                     ? response.catalog.names
                     : nlohmann::json::object()},
                {"available",
                 response.catalog.firmware_available &&
                     response.status == NdmsCatalogCacheStatus::fresh},
                {"catalog_status",
                 catalog_status_name(response.status)},
            }.dump();
        });

    server.get(
        "/api/system/ndms/interfaces",
        [&cache,
         runtime_interface_names_fn,
         native_import_readiness_provider,
         native_inventory_projection_provider,
         traffic_interfaces_observer]() -> std::string {
            const auto response =
                catalog_for_response(cache, runtime_interface_names_fn);
            if (traffic_interfaces_observer) {
                std::vector<std::string> interface_names;
                interface_names.reserve(response.catalog.tunnels.size());
                for (const auto& tunnel : response.catalog.tunnels) {
                    if (tunnel.kernel_name) {
                        interface_names.push_back(*tunnel.kernel_name);
                    }
                }
                traffic_interfaces_observer(std::move(interface_names));
            }
            return nlohmann::json(
                       typed_inventory(
                           response.catalog,
                           response.status,
                           native_import_readiness_provider,
                           native_inventory_projection_provider))
                .dump();
        });
}

void register_ndms_vpn_server_services_route(
    ApiServer& server,
    NdmsVpnServerServiceCache& cache) {
    server.get(
        "/api/system/ndms/vpn-server-services",
        [&cache]() -> std::string {
            const auto snapshot = cache.get();
            return nlohmann::json(
                       typed_vpn_service_inventory(
                           snapshot.catalog, snapshot.status))
                .dump();
        });
}

} // namespace

void register_ndms_names_handler(ApiServer& server, ApiContext& ctx) {
    register_ndms_names_routes(
        server,
        shared_ndms_catalog_cache(),
        [&ctx] {
            const auto inventory = ctx.get_runtime_interfaces();
            std::vector<std::string> names;
            names.reserve(inventory.interfaces.size());
            for (const auto& interface : inventory.interfaces) {
                names.push_back(interface.name);
            }
            return names;
        },
        ctx.get_ndms_native_import_readiness_fn,
        ctx.observe_ndms_native_inventory_projection_fn,
        [&ctx](std::vector<std::string> names) {
            ctx.replace_interface_traffic_targets(
                "native-tunnels", std::move(names));
        });
    register_ndms_vpn_server_services_route(
        server, shared_ndms_vpn_server_service_cache());
}

#ifdef KEEN_PBR3_TESTING
void register_ndms_names_handler_for_tests(ApiServer& server,
                                           NdmsCatalogCache& cache,
                                           std::vector<std::string>
                                               runtime_interface_names,
                                           NdmsNativeImportReadinessProvider
                                               native_import_readiness_provider,
                                           NdmsNativeInventoryProjectionProvider
                                               native_inventory_projection_provider) {
    register_ndms_names_routes(
        server,
        cache,
        [runtime_interface_names = std::move(runtime_interface_names)] {
            return runtime_interface_names;
        },
        std::move(native_import_readiness_provider),
        std::move(native_inventory_projection_provider));
}

void register_ndms_vpn_server_services_handler_for_tests(
    ApiServer& server,
    NdmsVpnServerServiceCache& cache) {
    register_ndms_vpn_server_services_route(server, cache);
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
