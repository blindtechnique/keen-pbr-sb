#include "ndms_native_tombstone_forget.hpp"

#include "ndms_native_import_readiness.hpp"
#include "ndms_native_import_recovery_probe.hpp"
#include "ndms_wireguard_identity.hpp"

#include <algorithm>
#include <string_view>
#include <utility>

#if defined(__linux__)
#include <net/if.h>
#endif

namespace keen_pbr3 {
namespace {

constexpr std::string_view kSlotRevisionPrefix{"ndms-wg-slot-v1-"};
constexpr std::size_t kMaximumLocalKernelInterfaces = 4096U;

bool lower_hex(const std::string_view value) noexcept {
    return std::all_of(
        value.begin(), value.end(), [](const unsigned char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f');
        });
}

bool prefixed_sha256(const std::string_view value,
                     const std::string_view prefix) noexcept {
    return value.size() == prefix.size() + 64U &&
           value.compare(0U, prefix.size(), prefix) == 0 &&
           lower_hex(value.substr(prefix.size()));
}

bool writer_still_held(NdmsNativeWriterLease& writer) noexcept {
    try {
        writer.verify_held();
        return true;
    } catch (...) {
        return false;
    }
}

class DirectObservationAdapter final
    : public NdmsNativeTombstoneForgetObservationGateway {
public:
    NdmsNativeDirectRecoveryObservation observe_recovery(
        const NdmsNativeDirectCatalogScope scope,
        const std::string& marker,
        const std::optional<std::string>& expected_target)
        noexcept override {
        return gateway_.observe_recovery(scope, marker, expected_target);
    }

private:
    NdmsNativeDirectObservationGateway gateway_;
};

bool safe_kernel_interface_name(const std::string_view value) noexcept {
    if (value.empty() || value.size() > 15U || value == "." ||
        value == "..") {
        return false;
    }
    return std::all_of(
        value.begin(), value.end(), [](const unsigned char character) {
            const bool ascii_alnum =
                (character >= 'a' && character <= 'z') ||
                (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9');
            return ascii_alnum || character == '_' ||
                   character == '-' || character == '.' ||
                   character == ':';
        });
}

class LocalKernelInventoryAdapter final
    : public NdmsNativeTombstoneForgetKernelInventoryGateway {
public:
    NdmsNativeTombstoneForgetKernelInventory observe() noexcept override {
        NdmsNativeTombstoneForgetKernelInventory result;
#if defined(__linux__)
        struct InterfaceNamesGuard final {
            struct if_nameindex* entries{nullptr};
            ~InterfaceNamesGuard() {
                if (entries != nullptr) ::if_freenameindex(entries);
            }
        } guard;
        try {
            guard.entries = ::if_nameindex();
            if (guard.entries == nullptr) return result;
            result.interface_names.reserve(32U);
            for (auto* entry = guard.entries;; ++entry) {
                if (entry->if_index == 0U && entry->if_name == nullptr) {
                    break;
                }
                if (entry->if_index == 0U || entry->if_name == nullptr ||
                    result.interface_names.size() >=
                        kMaximumLocalKernelInterfaces) {
                    result.interface_names.clear();
                    return result;
                }
                result.interface_names.emplace_back(entry->if_name);
            }
            std::sort(
                result.interface_names.begin(),
                result.interface_names.end());
            result.complete = true;
        } catch (...) {
            result.interface_names.clear();
        }
#endif
        return result;
    }
};

bool kernel_inventory_valid(
    const NdmsNativeTombstoneForgetKernelInventory& inventory) noexcept {
    return inventory.complete && !inventory.interface_names.empty() &&
           inventory.interface_names.size() <=
               kMaximumLocalKernelInterfaces &&
           std::all_of(
               inventory.interface_names.begin(),
               inventory.interface_names.end(),
               [](const std::string& name) {
                   return safe_kernel_interface_name(name);
               }) &&
           std::adjacent_find(
               inventory.interface_names.begin(),
               inventory.interface_names.end(),
               [](const std::string& left, const std::string& right) {
                   return left >= right;
               }) == inventory.interface_names.end();
}

NdmsNativeTombstoneForgetResult stopped(
    const NdmsNativeTombstoneForgetStop stop,
    const std::optional<std::string>& interface_name = std::nullopt) {
    NdmsNativeTombstoneForgetResult result;
    result.stop = stop;
    result.interface_name = interface_name;
    return result;
}

bool exact_v4_tombstone(
    const NdmsNativeOwnershipReadResult& claim,
    const std::string& interface_name,
    const std::string& expected_revision) noexcept {
    return claim.state == NdmsNativeOwnershipReadState::valid &&
           claim.record.has_value() && claim.revision.has_value() &&
           *claim.revision == expected_revision &&
           claim.record->interface_name == interface_name &&
           claim.record->schema_version ==
               kNdmsNativeOwnershipTombstoneSchemaVersion &&
           claim.record->lifecycle ==
               NdmsNativeOwnershipLifecycle::
                   deleted_save_acknowledged_unverified &&
           claim.record->lifecycle_evidence.has_value() &&
           claim.record->lifecycle_evidence->
               deleted_kernel_interface_name.has_value();
}

enum class SnapshotCheck : std::uint8_t {
    absent,
    exact,
    unreadable,
    mismatch,
};

SnapshotCheck inspect_snapshot(
    NdmsNativeSecretSnapshotStore& snapshots,
    const NdmsNativeOwnershipRecord& tombstone) {
    auto read = snapshots.read_panel_delete_snapshot(
        tombstone.interface_name,
        tombstone.transaction_id,
        tombstone.marker);
    if (read.state == NdmsNativeSecretReadState::absent) {
        return SnapshotCheck::absent;
    }
    if (read.state != NdmsNativeSecretReadState::valid ||
        !read.snapshot.has_value()) {
        return SnapshotCheck::unreadable;
    }
    const auto& snapshot = *read.snapshot;
    if (snapshot.marker() != tombstone.marker ||
        snapshot.kind() != tombstone.kind ||
        snapshot.canonical_revision() != tombstone.snapshot_revision ||
        (tombstone.kind ==
             NdmsNativeTunnelImportKind::amnezia_wireguard &&
         !snapshot.has_complete_awg_parameters())) {
        return SnapshotCheck::mismatch;
    }
    return SnapshotCheck::exact;
}

bool dependency_observation_valid(
    const NdmsNativeKeenPbrDependencyObservation& observation,
    const std::string& interface_name,
    const std::string& kernel_interface_name) noexcept {
    if (!observation.complete ||
        observation.scope != NdmsNativeKeenPbrDependencyScope::
            config_and_runtime_interface_references ||
        observation.firmware_interface_name != interface_name ||
        observation.kernel_interface_name !=
            std::optional<std::string>{kernel_interface_name}) {
        return false;
    }
    try {
        return observation.keen_pbr_dependency_revision ==
               ndms_native_keen_pbr_dependency_revision(observation);
    } catch (...) {
        return false;
    }
}

enum class AbsenceObservation : std::uint8_t {
    absent,
    failed,
    scope_mismatch,
    catalog_unsafe,
    target_present,
    marker_present,
};

bool catalog_slots_safe(
    const NdmsInterfaceCatalog& catalog,
    const NdmsNativeDirectCatalogScope scope) noexcept {
    if (!catalog.firmware_available ||
        !catalog.wireguard_slot_evidence_complete) {
        return false;
    }
    for (std::size_t slot = 0U;
         slot < catalog.wireguard_slots.size(); ++slot) {
        const auto& evidence = catalog.wireguard_slots[slot];
        switch (evidence.state) {
        case NdmsWireguardCatalogSlotState::absent:
            if (!evidence.structural_revision.empty()) return false;
            break;
        case NdmsWireguardCatalogSlotState::occupied: {
            if (!prefixed_sha256(
                    evidence.structural_revision,
                    kSlotRevisionPrefix)) {
                return false;
            }
            const auto expected =
                "Wireguard" + std::to_string(slot);
            const auto matches = scope ==
                    NdmsNativeDirectCatalogScope::runtime_state
                ? std::count_if(
                      catalog.tunnels.begin(), catalog.tunnels.end(),
                      [&expected](const NdmsTunnelInterface& tunnel) {
                          return tunnel.firmware_interface_name == expected &&
                                 (tunnel.kind == NdmsTunnelKind::wireguard ||
                                  tunnel.kind ==
                                      NdmsTunnelKind::amnezia_wireguard);
                      })
                : std::count_if(
                      catalog.interface_metadata.begin(),
                      catalog.interface_metadata.end(),
                      [&expected](const NdmsInterfaceMetadata& metadata) {
                          return metadata.firmware_interface_name == expected;
                      });
            if (matches != 1) return false;
            break;
        }
        case NdmsWireguardCatalogSlotState::unsafe:
            return false;
        }
    }
    return true;
}

AbsenceObservation inspect_absence_observation(
    const NdmsNativeDirectRecoveryObservation& observation,
    const NdmsNativeDirectCatalogScope expected_scope,
    const std::string& interface_name,
    const std::string& marker) noexcept {
    try {
        if (observation.catalog_scope != expected_scope ||
            observation.requested_catalog_scope != expected_scope) {
            return AbsenceObservation::scope_mismatch;
        }
        if (!observation.complete() || !observation.snapshot.has_value()) {
            return AbsenceObservation::failed;
        }
        const auto& snapshot = *observation.snapshot;
        if (snapshot.status != NdmsCatalogCacheStatus::fresh ||
            !snapshot.refreshed || !snapshot.observed_at.has_value() ||
            !catalog_slots_safe(snapshot.catalog, expected_scope) ||
            observation.catalog_revision !=
                ndms_native_import_recovery_catalog_revision(
                    snapshot.catalog, observation.target_evidence)) {
            return AbsenceObservation::catalog_unsafe;
        }
        const auto identity =
            parse_ndms_wireguard_identity(interface_name);
        if (!identity.has_value() ||
            identity->canonical_name() != interface_name ||
            !ndms_wireguard_identity_is_managed_candidate(*identity)) {
            return AbsenceObservation::catalog_unsafe;
        }
        if (snapshot.catalog.wireguard_slots[identity->slot].state !=
            NdmsWireguardCatalogSlotState::absent) {
            return AbsenceObservation::target_present;
        }
        if (std::any_of(
                snapshot.catalog.tunnels.begin(),
                snapshot.catalog.tunnels.end(),
                [&interface_name](const NdmsTunnelInterface& tunnel) {
                    return tunnel.firmware_interface_name == interface_name;
                }) ||
            std::any_of(
                snapshot.catalog.interface_metadata.begin(),
                snapshot.catalog.interface_metadata.end(),
                [&interface_name](const NdmsInterfaceMetadata& item) {
                    return item.firmware_interface_name == interface_name;
                })) {
            return AbsenceObservation::target_present;
        }
        const auto marker_visible =
            std::any_of(
                snapshot.catalog.tunnels.begin(),
                snapshot.catalog.tunnels.end(),
                [&marker](const NdmsTunnelInterface& tunnel) {
                    return tunnel.label.find(marker) != std::string::npos;
                }) ||
            std::any_of(
                snapshot.catalog.interface_metadata.begin(),
                snapshot.catalog.interface_metadata.end(),
                [&marker](const NdmsInterfaceMetadata& item) {
                    return item.label.find(marker) != std::string::npos;
                });
        if (marker_visible) return AbsenceObservation::marker_present;
        if (!observation.target_evidence.empty() ||
            !observation.target_protocols.empty()) {
            return AbsenceObservation::marker_present;
        }
        return AbsenceObservation::absent;
    } catch (...) {
        return AbsenceObservation::catalog_unsafe;
    }
}

NdmsNativeTombstoneForgetStop observation_stop(
    const AbsenceObservation observation,
    const bool runtime) noexcept {
    switch (observation) {
    case AbsenceObservation::absent:
        return NdmsNativeTombstoneForgetStop::none;
    case AbsenceObservation::failed:
        return runtime
            ? NdmsNativeTombstoneForgetStop::runtime_observation_failed
            : NdmsNativeTombstoneForgetStop::
                  running_config_observation_failed;
    case AbsenceObservation::scope_mismatch:
        return NdmsNativeTombstoneForgetStop::observation_scope_mismatch;
    case AbsenceObservation::catalog_unsafe:
        return NdmsNativeTombstoneForgetStop::observed_catalog_unsafe;
    case AbsenceObservation::target_present:
        return NdmsNativeTombstoneForgetStop::observed_target_present;
    case AbsenceObservation::marker_present:
        return NdmsNativeTombstoneForgetStop::observed_marker_present;
    }
    return NdmsNativeTombstoneForgetStop::observed_catalog_unsafe;
}

} // namespace

struct NdmsNativeTombstoneForgetCoordinator::Impl final {
    NdmsNativeImportWalStore& import_wal;
    NdmsNativeDeleteWalStore& delete_wal;
    NdmsNativeSecretSnapshotStore& snapshots;
    NdmsNativeOwnershipStore& ownership;
    NdmsNativeKeenPbrDependencyProvider& dependencies;
    NdmsNativeTombstoneForgetObservationGateway* gateway{nullptr};
    NdmsNativeTombstoneForgetKernelInventoryGateway* kernel_inventory{
        nullptr};
    std::unique_ptr<NdmsNativeTombstoneForgetObservationGateway>
        owned_gateway;
    std::unique_ptr<NdmsNativeTombstoneForgetKernelInventoryGateway>
        owned_kernel_inventory;

    Impl(NdmsNativeImportWalStore& import_wal_value,
         NdmsNativeDeleteWalStore& delete_wal_value,
         NdmsNativeSecretSnapshotStore& snapshots_value,
         NdmsNativeOwnershipStore& ownership_value,
         NdmsNativeKeenPbrDependencyProvider& dependencies_value)
        : import_wal(import_wal_value),
          delete_wal(delete_wal_value),
          snapshots(snapshots_value),
          ownership(ownership_value),
          dependencies(dependencies_value),
          owned_gateway(std::make_unique<DirectObservationAdapter>()),
          owned_kernel_inventory(
              std::make_unique<LocalKernelInventoryAdapter>()) {
        gateway = owned_gateway.get();
        kernel_inventory = owned_kernel_inventory.get();
    }

    Impl(NdmsNativeImportWalStore& import_wal_value,
         NdmsNativeDeleteWalStore& delete_wal_value,
         NdmsNativeSecretSnapshotStore& snapshots_value,
         NdmsNativeOwnershipStore& ownership_value,
         NdmsNativeKeenPbrDependencyProvider& dependencies_value,
         NdmsNativeTombstoneForgetObservationGateway& gateway_value,
         NdmsNativeTombstoneForgetKernelInventoryGateway&
             kernel_inventory_value)
        : import_wal(import_wal_value),
          delete_wal(delete_wal_value),
          snapshots(snapshots_value),
          ownership(ownership_value),
          dependencies(dependencies_value),
          gateway(&gateway_value),
          kernel_inventory(&kernel_inventory_value) {}
};

NdmsNativeTombstoneForgetCoordinator::
NdmsNativeTombstoneForgetCoordinator(
    NdmsNativeImportWalStore& import_wal,
    NdmsNativeDeleteWalStore& delete_wal,
    NdmsNativeSecretSnapshotStore& snapshots,
    NdmsNativeOwnershipStore& ownership,
    NdmsNativeKeenPbrDependencyProvider& dependencies)
    : impl_(std::make_unique<Impl>(
          import_wal, delete_wal, snapshots, ownership, dependencies)) {}

NdmsNativeTombstoneForgetCoordinator::
NdmsNativeTombstoneForgetCoordinator(
    std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

NdmsNativeTombstoneForgetCoordinator::
~NdmsNativeTombstoneForgetCoordinator() = default;
NdmsNativeTombstoneForgetCoordinator::
NdmsNativeTombstoneForgetCoordinator(
    NdmsNativeTombstoneForgetCoordinator&&) noexcept = default;
NdmsNativeTombstoneForgetCoordinator&
NdmsNativeTombstoneForgetCoordinator::operator=(
    NdmsNativeTombstoneForgetCoordinator&&) noexcept = default;

NdmsNativeTombstoneForgetResult
NdmsNativeTombstoneForgetCoordinator::forget_once(
    NdmsNativeWriterLease& writer,
    const NdmsNativeTombstoneForgetRequest& request) noexcept {
    const auto named = std::optional<std::string>{request.interface_name};
    if (request.exact_name_confirmation !=
            NdmsNativeTombstoneExactNameConfirmation::confirmed ||
        request.confirmed_interface_name != request.interface_name) {
        return stopped(
            NdmsNativeTombstoneForgetStop::exact_name_not_confirmed,
            named);
    }
    if (request.rollback_discard !=
        NdmsNativeTombstoneRollbackDiscardAcknowledgement::
            permanently_discard_rollback_data) {
        return stopped(
            NdmsNativeTombstoneForgetStop::
                rollback_discard_not_acknowledged,
            named);
    }
    if (request.foreign_reappearance !=
        NdmsNativeTombstoneForeignReappearanceAcknowledgement::
            accepted_reappearance_is_foreign) {
        return stopped(
            NdmsNativeTombstoneForgetStop::
                foreign_reappearance_not_acknowledged,
            named);
    }
    const auto identity =
        parse_ndms_wireguard_identity(request.interface_name);
    if (!identity.has_value() ||
        identity->canonical_name() != request.interface_name ||
        !ndms_wireguard_identity_is_managed_candidate(*identity)) {
        return stopped(
            NdmsNativeTombstoneForgetStop::
                invalid_or_protected_target,
            named);
    }
    if (!impl_) {
        return stopped(
            NdmsNativeTombstoneForgetStop::writer_missing, named);
    }
    if (!writer_still_held(writer)) {
        return stopped(
            NdmsNativeTombstoneForgetStop::writer_lost, named);
    }

    bool irreversible_local_retirement_started = false;
    try {
        switch (impl_->delete_wal.readiness()) {
        case NdmsNativeDeleteWalReadiness::clean:
            break;
        case NdmsNativeDeleteWalReadiness::unfinished:
            return stopped(
                NdmsNativeTombstoneForgetStop::delete_wal_unfinished,
                named);
        case NdmsNativeDeleteWalReadiness::unsafe:
            return stopped(
                NdmsNativeTombstoneForgetStop::delete_wal_unsafe,
                named);
        }
        const auto import_inventory = impl_->import_wal.inventory();
        if (!ndms_native_import_inventory_permits_ownership_reconciliation(
                import_inventory)) {
            return stopped(
                NdmsNativeTombstoneForgetStop::
                    import_wal_not_authoritatively_clean,
                named);
        }

        const auto claim = impl_->ownership.read(request.interface_name);
        if (claim.state == NdmsNativeOwnershipReadState::absent) {
            return stopped(
                NdmsNativeTombstoneForgetStop::ownership_absent, named);
        }
        if (claim.state != NdmsNativeOwnershipReadState::valid ||
            !claim.record.has_value() || !claim.revision.has_value()) {
            return stopped(
                NdmsNativeTombstoneForgetStop::ownership_unreadable,
                named);
        }
        if (claim.record->schema_version !=
                kNdmsNativeOwnershipTombstoneSchemaVersion ||
            claim.record->lifecycle !=
                NdmsNativeOwnershipLifecycle::
                    deleted_save_acknowledged_unverified ||
            !claim.record->lifecycle_evidence.has_value() ||
            !claim.record->lifecycle_evidence->
                 deleted_kernel_interface_name.has_value()) {
            return stopped(
                NdmsNativeTombstoneForgetStop::
                    ownership_not_forget_capable,
                named);
        }
        if (*claim.revision != request.expected_ownership_revision) {
            return stopped(
                NdmsNativeTombstoneForgetStop::ownership_changed,
                named);
        }
        const auto tombstone = *claim.record;
        const auto snapshot_check =
            inspect_snapshot(impl_->snapshots, tombstone);
        if (snapshot_check == SnapshotCheck::unreadable) {
            return stopped(
                NdmsNativeTombstoneForgetStop::snapshot_unreadable,
                named);
        }
        if (snapshot_check == SnapshotCheck::mismatch) {
            return stopped(
                NdmsNativeTombstoneForgetStop::snapshot_mismatch,
                named);
        }

        auto runtime = impl_->gateway->observe_recovery(
            NdmsNativeDirectCatalogScope::runtime_state,
            tombstone.marker,
            tombstone.interface_name);
        const auto runtime_absence = inspect_absence_observation(
            runtime,
            NdmsNativeDirectCatalogScope::runtime_state,
            tombstone.interface_name,
            tombstone.marker);
        const auto runtime_stop = observation_stop(runtime_absence, true);
        if (runtime_stop != NdmsNativeTombstoneForgetStop::none) {
            return stopped(runtime_stop, named);
        }
        auto running = impl_->gateway->observe_recovery(
            NdmsNativeDirectCatalogScope::running_config,
            tombstone.marker,
            tombstone.interface_name);
        const auto running_absence = inspect_absence_observation(
            running,
            NdmsNativeDirectCatalogScope::running_config,
            tombstone.interface_name,
            tombstone.marker);
        const auto running_stop = observation_stop(running_absence, false);
        if (running_stop != NdmsNativeTombstoneForgetStop::none) {
            return stopped(running_stop, named);
        }

        const auto& kernel_name = *tombstone.lifecycle_evidence->
                                       deleted_kernel_interface_name;
        const auto dependency = impl_->dependencies.observe_dependencies(
            tombstone.interface_name, kernel_name);
        if (!dependency_observation_valid(
                dependency, tombstone.interface_name, kernel_name)) {
            return stopped(
                NdmsNativeTombstoneForgetStop::
                    keen_pbr_dependency_scan_incomplete,
                named);
        }
        if (!dependency.references.empty()) {
            return stopped(
                NdmsNativeTombstoneForgetStop::
                    keen_pbr_dependencies_present,
                named);
        }
        const auto kernel_inventory = impl_->kernel_inventory->observe();
        if (!kernel_inventory_valid(kernel_inventory)) {
            return stopped(
                NdmsNativeTombstoneForgetStop::
                    kernel_inventory_unavailable,
                named);
        }
        if (std::binary_search(
                kernel_inventory.interface_names.begin(),
                kernel_inventory.interface_names.end(),
                kernel_name)) {
            return stopped(
                NdmsNativeTombstoneForgetStop::
                    retained_kernel_interface_present,
                named);
        }
        if (!writer_still_held(writer)) {
            return stopped(
                NdmsNativeTombstoneForgetStop::writer_lost, named);
        }
        const auto rebound = impl_->ownership.read(request.interface_name);
        if (!exact_v4_tombstone(
                rebound,
                request.interface_name,
                request.expected_ownership_revision) ||
            !(*rebound.record == tombstone)) {
            return stopped(
                NdmsNativeTombstoneForgetStop::ownership_changed,
                named);
        }

        NdmsNativeTombstoneForgetResult result;
        result.interface_name = request.interface_name;
        result.tombstone_state =
            NdmsNativeTombstoneForgetArtifactState::retained;
        result.snapshot_state = snapshot_check == SnapshotCheck::exact
            ? NdmsNativeTombstoneForgetArtifactState::retained
            : NdmsNativeTombstoneForgetArtifactState::unknown;

        irreversible_local_retirement_started = true;
        if (snapshot_check == SnapshotCheck::exact) {
            static_cast<void>(
                impl_->snapshots.remove_panel_delete_snapshot_exact(
                    tombstone.interface_name,
                    tombstone.transaction_id,
                    tombstone.marker,
                    tombstone.snapshot_revision));
        }
        if (!impl_->snapshots.ensure_absence_durable(
                tombstone.interface_name)) {
            const auto after =
                inspect_snapshot(impl_->snapshots, tombstone);
            if (after == SnapshotCheck::exact) {
                result.snapshot_state =
                    NdmsNativeTombstoneForgetArtifactState::retained;
                result.status =
                    NdmsNativeTombstoneForgetStatus::blocked;
            } else {
                result.snapshot_state =
                    NdmsNativeTombstoneForgetArtifactState::unknown;
                result.status = NdmsNativeTombstoneForgetStatus::
                    recovery_required;
            }
            result.stop = NdmsNativeTombstoneForgetStop::
                snapshot_retirement_failed;
            return result;
        }
        result.snapshot_state =
            NdmsNativeTombstoneForgetArtifactState::absent_durable;

        const auto partial_result =
            [&](const NdmsNativeTombstoneForgetStop stop) {
                result.status = NdmsNativeTombstoneForgetStatus::
                    recovery_required;
                result.stop = stop;
                const auto anchor =
                    impl_->ownership.read(tombstone.interface_name);
                result.tombstone_state =
                    exact_v4_tombstone(
                        anchor,
                        tombstone.interface_name,
                        request.expected_ownership_revision) &&
                        *anchor.record == tombstone
                    ? NdmsNativeTombstoneForgetArtifactState::retained
                    : NdmsNativeTombstoneForgetArtifactState::unknown;
                return result;
            };
        if (!writer_still_held(writer)) {
            return partial_result(
                NdmsNativeTombstoneForgetStop::writer_lost);
        }

        try {
            switch (impl_->delete_wal.readiness()) {
            case NdmsNativeDeleteWalReadiness::clean:
                break;
            case NdmsNativeDeleteWalReadiness::unfinished:
                return partial_result(
                    NdmsNativeTombstoneForgetStop::
                        delete_wal_unfinished);
            case NdmsNativeDeleteWalReadiness::unsafe:
                return partial_result(
                    NdmsNativeTombstoneForgetStop::delete_wal_unsafe);
            }
            const auto final_import_inventory =
                impl_->import_wal.inventory();
            if (!ndms_native_import_inventory_permits_ownership_reconciliation(
                    final_import_inventory)) {
                return partial_result(
                    NdmsNativeTombstoneForgetStop::
                        import_wal_not_authoritatively_clean);
            }
            const auto anchor =
                impl_->ownership.read(tombstone.interface_name);
            if (!exact_v4_tombstone(
                    anchor,
                    tombstone.interface_name,
                    request.expected_ownership_revision) ||
                !(*anchor.record == tombstone)) {
                return partial_result(
                    NdmsNativeTombstoneForgetStop::ownership_changed);
            }

            const auto final_dependency =
                impl_->dependencies.observe_dependencies(
                    tombstone.interface_name, kernel_name);
            if (!dependency_observation_valid(
                    final_dependency,
                    tombstone.interface_name,
                    kernel_name)) {
                return partial_result(
                    NdmsNativeTombstoneForgetStop::
                        keen_pbr_dependency_scan_incomplete);
            }
            if (!final_dependency.references.empty()) {
                return partial_result(
                    NdmsNativeTombstoneForgetStop::
                        keen_pbr_dependencies_present);
            }

            auto final_runtime = impl_->gateway->observe_recovery(
                NdmsNativeDirectCatalogScope::runtime_state,
                tombstone.marker,
                tombstone.interface_name);
            const auto final_runtime_stop = observation_stop(
                inspect_absence_observation(
                    final_runtime,
                    NdmsNativeDirectCatalogScope::runtime_state,
                    tombstone.interface_name,
                    tombstone.marker),
                true);
            if (final_runtime_stop !=
                NdmsNativeTombstoneForgetStop::none) {
                return partial_result(final_runtime_stop);
            }
            auto final_running = impl_->gateway->observe_recovery(
                NdmsNativeDirectCatalogScope::running_config,
                tombstone.marker,
                tombstone.interface_name);
            const auto final_running_stop = observation_stop(
                inspect_absence_observation(
                    final_running,
                    NdmsNativeDirectCatalogScope::running_config,
                    tombstone.interface_name,
                    tombstone.marker),
                false);
            if (final_running_stop !=
                NdmsNativeTombstoneForgetStop::none) {
                return partial_result(final_running_stop);
            }

            const auto final_kernel_inventory =
                impl_->kernel_inventory->observe();
            if (!kernel_inventory_valid(final_kernel_inventory)) {
                return partial_result(
                    NdmsNativeTombstoneForgetStop::
                        kernel_inventory_unavailable);
            }
            if (std::binary_search(
                    final_kernel_inventory.interface_names.begin(),
                    final_kernel_inventory.interface_names.end(),
                    kernel_name)) {
                return partial_result(
                    NdmsNativeTombstoneForgetStop::
                        retained_kernel_interface_present);
            }
            if (!impl_->snapshots.ensure_absence_durable(
                    tombstone.interface_name)) {
                const auto after =
                    inspect_snapshot(impl_->snapshots, tombstone);
                result.snapshot_state = after == SnapshotCheck::exact
                    ? NdmsNativeTombstoneForgetArtifactState::retained
                    : NdmsNativeTombstoneForgetArtifactState::unknown;
                return partial_result(
                    NdmsNativeTombstoneForgetStop::
                        snapshot_retirement_failed);
            }
            result.snapshot_state =
                NdmsNativeTombstoneForgetArtifactState::absent_durable;
            if (!writer_still_held(writer)) {
                return partial_result(
                    NdmsNativeTombstoneForgetStop::writer_lost);
            }
            const auto final_anchor =
                impl_->ownership.read(tombstone.interface_name);
            if (!exact_v4_tombstone(
                    final_anchor,
                    tombstone.interface_name,
                    request.expected_ownership_revision) ||
                !(*final_anchor.record == tombstone)) {
                return partial_result(
                    NdmsNativeTombstoneForgetStop::ownership_changed);
            }
        } catch (...) {
            return partial_result(
                NdmsNativeTombstoneForgetStop::unexpected_failure);
        }

        static_cast<void>(impl_->ownership.remove_v4_tombstone_exact(
            tombstone.interface_name,
            request.expected_ownership_revision));
        if (!impl_->ownership.ensure_absence_durable(
                tombstone.interface_name)) {
            const auto after =
                impl_->ownership.read(tombstone.interface_name);
            result.tombstone_state = exact_v4_tombstone(
                                         after,
                                         tombstone.interface_name,
                                         request.expected_ownership_revision)
                ? NdmsNativeTombstoneForgetArtifactState::retained
                : NdmsNativeTombstoneForgetArtifactState::unknown;
            result.status =
                NdmsNativeTombstoneForgetStatus::recovery_required;
            result.stop = NdmsNativeTombstoneForgetStop::
                tombstone_retirement_failed;
            return result;
        }
        result.tombstone_state =
            NdmsNativeTombstoneForgetArtifactState::absent_durable;
        result.status = NdmsNativeTombstoneForgetStatus::forgotten;
        result.stop = NdmsNativeTombstoneForgetStop::none;
        result.future_reappearance_is_foreign = true;
        return result;
    } catch (...) {
        auto result = stopped(
            NdmsNativeTombstoneForgetStop::unexpected_failure, named);
        if (irreversible_local_retirement_started) {
            result.status =
                NdmsNativeTombstoneForgetStatus::recovery_required;
            result.snapshot_state =
                NdmsNativeTombstoneForgetArtifactState::unknown;
            result.tombstone_state =
                NdmsNativeTombstoneForgetArtifactState::unknown;
        }
        return result;
    }
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeTombstoneForgetCoordinator
NdmsNativeTombstoneForgetCoordinatorTestIssuer::issue(
    NdmsNativeImportWalStore& import_wal,
    NdmsNativeDeleteWalStore& delete_wal,
    NdmsNativeSecretSnapshotStore& snapshots,
    NdmsNativeOwnershipStore& ownership,
    NdmsNativeKeenPbrDependencyProvider& dependencies,
    NdmsNativeTombstoneForgetObservationGateway& gateway,
    NdmsNativeTombstoneForgetKernelInventoryGateway& kernel_inventory) {
    return NdmsNativeTombstoneForgetCoordinator{
        std::make_unique<NdmsNativeTombstoneForgetCoordinator::Impl>(
            import_wal,
            delete_wal,
            snapshots,
            ownership,
            dependencies,
            gateway,
            kernel_inventory)};
}
#endif

const char* ndms_native_tombstone_forget_status_name(
    const NdmsNativeTombstoneForgetStatus status) noexcept {
    switch (status) {
    case NdmsNativeTombstoneForgetStatus::blocked: return "blocked";
    case NdmsNativeTombstoneForgetStatus::recovery_required:
        return "recovery_required";
    case NdmsNativeTombstoneForgetStatus::forgotten:
        return "forgotten";
    }
    return "blocked";
}

const char* ndms_native_tombstone_forget_stop_name(
    const NdmsNativeTombstoneForgetStop stop) noexcept {
    switch (stop) {
    case NdmsNativeTombstoneForgetStop::none: return "none";
    case NdmsNativeTombstoneForgetStop::exact_name_not_confirmed:
        return "exact_name_not_confirmed";
    case NdmsNativeTombstoneForgetStop::
        rollback_discard_not_acknowledged:
        return "rollback_discard_not_acknowledged";
    case NdmsNativeTombstoneForgetStop::
        foreign_reappearance_not_acknowledged:
        return "foreign_reappearance_not_acknowledged";
    case NdmsNativeTombstoneForgetStop::invalid_or_protected_target:
        return "invalid_or_protected_target";
    case NdmsNativeTombstoneForgetStop::writer_missing:
        return "writer_missing";
    case NdmsNativeTombstoneForgetStop::writer_lost:
        return "writer_lost";
    case NdmsNativeTombstoneForgetStop::
        import_wal_not_authoritatively_clean:
        return "import_wal_not_authoritatively_clean";
    case NdmsNativeTombstoneForgetStop::delete_wal_unfinished:
        return "delete_wal_unfinished";
    case NdmsNativeTombstoneForgetStop::delete_wal_unsafe:
        return "delete_wal_unsafe";
    case NdmsNativeTombstoneForgetStop::ownership_absent:
        return "ownership_absent";
    case NdmsNativeTombstoneForgetStop::ownership_unreadable:
        return "ownership_unreadable";
    case NdmsNativeTombstoneForgetStop::ownership_not_forget_capable:
        return "ownership_not_forget_capable";
    case NdmsNativeTombstoneForgetStop::ownership_changed:
        return "ownership_changed";
    case NdmsNativeTombstoneForgetStop::snapshot_unreadable:
        return "snapshot_unreadable";
    case NdmsNativeTombstoneForgetStop::snapshot_mismatch:
        return "snapshot_mismatch";
    case NdmsNativeTombstoneForgetStop::snapshot_retirement_failed:
        return "snapshot_retirement_failed";
    case NdmsNativeTombstoneForgetStop::
        keen_pbr_dependency_scan_incomplete:
        return "keen_pbr_dependency_scan_incomplete";
    case NdmsNativeTombstoneForgetStop::keen_pbr_dependencies_present:
        return "keen_pbr_dependencies_present";
    case NdmsNativeTombstoneForgetStop::kernel_inventory_unavailable:
        return "kernel_inventory_unavailable";
    case NdmsNativeTombstoneForgetStop::
        retained_kernel_interface_present:
        return "retained_kernel_interface_present";
    case NdmsNativeTombstoneForgetStop::runtime_observation_failed:
        return "runtime_observation_failed";
    case NdmsNativeTombstoneForgetStop::
        running_config_observation_failed:
        return "running_config_observation_failed";
    case NdmsNativeTombstoneForgetStop::observation_scope_mismatch:
        return "observation_scope_mismatch";
    case NdmsNativeTombstoneForgetStop::observed_target_present:
        return "observed_target_present";
    case NdmsNativeTombstoneForgetStop::observed_marker_present:
        return "observed_marker_present";
    case NdmsNativeTombstoneForgetStop::observed_catalog_unsafe:
        return "observed_catalog_unsafe";
    case NdmsNativeTombstoneForgetStop::tombstone_retirement_failed:
        return "tombstone_retirement_failed";
    case NdmsNativeTombstoneForgetStop::unexpected_failure:
        return "unexpected_failure";
    }
    return "unexpected_failure";
}

const char* ndms_native_tombstone_forget_artifact_state_name(
    const NdmsNativeTombstoneForgetArtifactState state) noexcept {
    switch (state) {
    case NdmsNativeTombstoneForgetArtifactState::unknown:
        return "unknown";
    case NdmsNativeTombstoneForgetArtifactState::retained:
        return "retained";
    case NdmsNativeTombstoneForgetArtifactState::absent_durable:
        return "absent_durable";
    }
    return "unknown";
}

} // namespace keen_pbr3
