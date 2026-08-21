#include "ndms_native_fresh_import_preflight.hpp"

#include "ndms_native_import_readiness.hpp"
#include "ndms_wireguard_identity.hpp"

#include <algorithm>
#include <array>
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
    : public NdmsNativeFreshImportPreflightObservationGateway {
public:
    NdmsNativeDirectCatalogObservation observe_catalog(
        const NdmsNativeDirectCatalogScope scope) noexcept override {
        return gateway_.observe_catalog(scope);
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
    : public NdmsNativeFreshImportKernelInventoryGateway {
public:
    NdmsNativeFreshImportKernelInventory observe() noexcept override {
        NdmsNativeFreshImportKernelInventory result;
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
    const NdmsNativeFreshImportKernelInventory& inventory) noexcept {
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

bool dependency_observation_valid(
    const NdmsNativeKeenPbrDependencyObservation& observation,
    const std::string& firmware_interface_name,
    const std::string& kernel_interface_name) noexcept {
    if (!observation.complete ||
        observation.scope != NdmsNativeKeenPbrDependencyScope::
            config_and_runtime_interface_references ||
        observation.firmware_interface_name != firmware_interface_name ||
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

NdmsNativeFreshImportPreflightResult result(
    const NdmsNativeFreshImportPreflightStatus status,
    const NdmsNativeFreshImportPreflightStop stop,
    std::optional<std::string> target = std::nullopt) {
    return {status, stop, std::move(target)};
}

bool catalog_slots_safe(
    const NdmsInterfaceCatalog& catalog,
    const bool require_typed_tunnel_views) noexcept {
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
            // show/rc/interface identifies WireGuard records by their
            // canonical WireguardN keys, but current Keenetic firmware does
            // not repeat the runtime `type` discriminator there.  The
            // runtime scope remains responsible for proving the typed tunnel
            // view; running-config proves the same slot occupancy through
            // its independently measured canonical keys.
            if (!require_typed_tunnel_views) break;
            const auto expected =
                "Wireguard" + std::to_string(slot);
            const auto matches = std::count_if(
                catalog.tunnels.begin(), catalog.tunnels.end(),
                [&expected](const NdmsTunnelInterface& tunnel) {
                    return tunnel.firmware_interface_name == expected &&
                           (tunnel.kind == NdmsTunnelKind::wireguard ||
                            tunnel.kind ==
                                NdmsTunnelKind::amnezia_wireguard);
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

struct CatalogMeasure final {
    NdmsNativeFreshImportPreflightStop stop{
        NdmsNativeFreshImportPreflightStop::observed_catalog_unsafe};
    std::optional<std::uint8_t> first_free_slot;
};

CatalogMeasure measure_catalog(
    const NdmsNativeDirectCatalogObservation& observation,
    const NdmsNativeDirectCatalogScope expected_scope,
    const bool runtime) noexcept {
    if (observation.scope != expected_scope) {
        return {
            NdmsNativeFreshImportPreflightStop::
                observation_scope_mismatch,
            std::nullopt};
    }
    if (observation.failure != NdmsNativeDirectObservationFailure::none ||
        !observation.snapshot.has_value()) {
        return {
            runtime
                ? NdmsNativeFreshImportPreflightStop::
                      runtime_observation_failed
                : NdmsNativeFreshImportPreflightStop::
                      running_config_observation_failed,
            std::nullopt};
    }
    const auto& snapshot = *observation.snapshot;
    if (snapshot.status != NdmsCatalogCacheStatus::fresh ||
        !snapshot.refreshed || !snapshot.observed_at.has_value() ||
        !catalog_slots_safe(snapshot.catalog, runtime)) {
        return {
            NdmsNativeFreshImportPreflightStop::observed_catalog_unsafe,
            std::nullopt};
    }
    for (std::size_t slot = 0U;
         slot < snapshot.catalog.wireguard_slots.size(); ++slot) {
        if (snapshot.catalog.wireguard_slots[slot].state ==
            NdmsWireguardCatalogSlotState::absent) {
            return {
                NdmsNativeFreshImportPreflightStop::none,
                static_cast<std::uint8_t>(slot)};
        }
    }
    return {
        NdmsNativeFreshImportPreflightStop::no_first_free_slot,
        std::nullopt};
}

bool target_has_claim(
    const NdmsNativeOwnershipInspection& inspection,
    const std::string& target) noexcept {
    return std::any_of(
        inspection.claims.begin(), inspection.claims.end(),
        [&target](const NdmsNativeOwnershipInspectionItem& item) {
            return item.interface_name == target;
        });
}

} // namespace

struct NdmsNativeFreshImportPreflight::Impl final {
    NdmsNativeImportWalStore& import_wal;
    NdmsNativeDeleteWalStore& delete_wal;
    NdmsNativeOwnershipStore& ownership;
    NdmsNativeSecretSnapshotStore& snapshots;
    NdmsNativeKeenPbrDependencyProvider& dependencies;
    NdmsNativeFreshImportPreflightObservationGateway* gateway{nullptr};
    NdmsNativeFreshImportKernelInventoryGateway* kernel_inventory{nullptr};
    std::unique_ptr<NdmsNativeFreshImportPreflightObservationGateway>
        owned_gateway;
    std::unique_ptr<NdmsNativeFreshImportKernelInventoryGateway>
        owned_kernel_inventory;

    Impl(NdmsNativeImportWalStore& import_wal_value,
         NdmsNativeDeleteWalStore& delete_wal_value,
         NdmsNativeOwnershipStore& ownership_value,
         NdmsNativeSecretSnapshotStore& snapshots_value,
         NdmsNativeKeenPbrDependencyProvider& dependencies_value)
        : import_wal(import_wal_value),
          delete_wal(delete_wal_value),
          ownership(ownership_value),
          snapshots(snapshots_value),
          dependencies(dependencies_value),
          owned_gateway(std::make_unique<DirectObservationAdapter>()),
          owned_kernel_inventory(
              std::make_unique<LocalKernelInventoryAdapter>()) {
        gateway = owned_gateway.get();
        kernel_inventory = owned_kernel_inventory.get();
    }

    Impl(NdmsNativeImportWalStore& import_wal_value,
         NdmsNativeDeleteWalStore& delete_wal_value,
         NdmsNativeOwnershipStore& ownership_value,
         NdmsNativeSecretSnapshotStore& snapshots_value,
         NdmsNativeKeenPbrDependencyProvider& dependencies_value,
         NdmsNativeFreshImportPreflightObservationGateway& gateway_value,
         NdmsNativeFreshImportKernelInventoryGateway&
             kernel_inventory_value)
        : import_wal(import_wal_value),
          delete_wal(delete_wal_value),
          ownership(ownership_value),
          snapshots(snapshots_value),
          dependencies(dependencies_value),
          gateway(&gateway_value),
          kernel_inventory(&kernel_inventory_value) {}
};

NdmsNativeFreshImportPreflight::NdmsNativeFreshImportPreflight(
    NdmsNativeImportWalStore& import_wal,
    NdmsNativeDeleteWalStore& delete_wal,
    NdmsNativeOwnershipStore& ownership,
    NdmsNativeSecretSnapshotStore& snapshots,
    NdmsNativeKeenPbrDependencyProvider& dependencies)
    : impl_(std::make_unique<Impl>(
          import_wal, delete_wal, ownership, snapshots, dependencies)) {}

NdmsNativeFreshImportPreflight::NdmsNativeFreshImportPreflight(
    std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

NdmsNativeFreshImportPreflight::~NdmsNativeFreshImportPreflight() = default;
NdmsNativeFreshImportPreflight::NdmsNativeFreshImportPreflight(
    NdmsNativeFreshImportPreflight&&) noexcept = default;
NdmsNativeFreshImportPreflight&
NdmsNativeFreshImportPreflight::operator=(
    NdmsNativeFreshImportPreflight&&) noexcept = default;

NdmsNativeFreshImportPreflightResult
NdmsNativeFreshImportPreflight::check_before_secret_take(
    NdmsNativeWriterLease& writer) noexcept {
    if (!impl_) {
        return result(
            NdmsNativeFreshImportPreflightStatus::unavailable,
            NdmsNativeFreshImportPreflightStop::writer_missing);
    }
    if (!writer_still_held(writer)) {
        return result(
            NdmsNativeFreshImportPreflightStatus::unavailable,
            NdmsNativeFreshImportPreflightStop::writer_lost);
    }
    try {
        const auto delete_readiness = impl_->delete_wal.readiness();
        if (delete_readiness == NdmsNativeDeleteWalReadiness::unfinished) {
            return result(
                NdmsNativeFreshImportPreflightStatus::blocked,
                NdmsNativeFreshImportPreflightStop::
                    delete_wal_unfinished);
        }
        if (delete_readiness == NdmsNativeDeleteWalReadiness::unsafe) {
            return result(
                NdmsNativeFreshImportPreflightStatus::unavailable,
                NdmsNativeFreshImportPreflightStop::delete_wal_unsafe);
        }
        const auto import_inventory = impl_->import_wal.inventory();
        const auto admission = summarize_ndms_native_mutation_admission(
            import_inventory, delete_readiness);
        if (admission != NdmsNativeMutationAdmissionState::admitted) {
            const bool known_recovery =
                admission == NdmsNativeMutationAdmissionState::blocked &&
                import_inventory.recovery_permitted() &&
                !import_inventory.items.empty();
            return result(
                known_recovery
                    ? NdmsNativeFreshImportPreflightStatus::blocked
                    : NdmsNativeFreshImportPreflightStatus::unavailable,
                known_recovery
                    ? NdmsNativeFreshImportPreflightStop::
                          import_recovery_required
                    : NdmsNativeFreshImportPreflightStop::
                          import_wal_unsafe);
        }

        auto runtime = impl_->gateway->observe_catalog(
            NdmsNativeDirectCatalogScope::runtime_state);
        const auto runtime_measure = measure_catalog(
            runtime,
            NdmsNativeDirectCatalogScope::runtime_state,
            true);
        if (runtime_measure.stop !=
            NdmsNativeFreshImportPreflightStop::none) {
            const auto unavailable =
                runtime_measure.stop !=
                NdmsNativeFreshImportPreflightStop::
                    no_first_free_slot;
            return result(
                unavailable
                    ? NdmsNativeFreshImportPreflightStatus::unavailable
                    : NdmsNativeFreshImportPreflightStatus::blocked,
                runtime_measure.stop);
        }
        auto running = impl_->gateway->observe_catalog(
            NdmsNativeDirectCatalogScope::running_config);
        const auto running_measure = measure_catalog(
            running,
            NdmsNativeDirectCatalogScope::running_config,
            false);
        if (running_measure.stop !=
            NdmsNativeFreshImportPreflightStop::none) {
            const auto unavailable =
                running_measure.stop !=
                NdmsNativeFreshImportPreflightStop::
                    no_first_free_slot;
            return result(
                unavailable
                    ? NdmsNativeFreshImportPreflightStatus::unavailable
                    : NdmsNativeFreshImportPreflightStatus::blocked,
                running_measure.stop);
        }
        if (runtime_measure.first_free_slot !=
            running_measure.first_free_slot) {
            return result(
                NdmsNativeFreshImportPreflightStatus::blocked,
                NdmsNativeFreshImportPreflightStop::
                    first_free_scope_mismatch);
        }
        if (!runtime_measure.first_free_slot.has_value()) {
            return result(
                NdmsNativeFreshImportPreflightStatus::blocked,
                NdmsNativeFreshImportPreflightStop::no_first_free_slot);
        }
        const auto target = "Wireguard" + std::to_string(
            *runtime_measure.first_free_slot);
        const auto identity = parse_ndms_wireguard_identity(target);
        if (!identity.has_value() ||
            identity->canonical_name() != target ||
            !ndms_wireguard_identity_is_managed_candidate(*identity)) {
            return result(
                NdmsNativeFreshImportPreflightStatus::blocked,
                NdmsNativeFreshImportPreflightStop::
                    first_free_target_not_managed,
                target);
        }

        const std::array<std::string, 2U> possible_kernel_names{
            target,
            "nwg" + std::to_string(identity->slot),
        };
        const auto live_and_dependencies_clear = [&]() {
            const auto inventory = impl_->kernel_inventory->observe();
            if (!kernel_inventory_valid(inventory)) {
                return NdmsNativeFreshImportPreflightStop::
                    kernel_inventory_unavailable;
            }
            for (const auto& kernel_name : possible_kernel_names) {
                if (std::binary_search(
                        inventory.interface_names.begin(),
                        inventory.interface_names.end(),
                        kernel_name)) {
                    return NdmsNativeFreshImportPreflightStop::
                        first_free_kernel_identity_present;
                }
                const auto dependency =
                    impl_->dependencies.observe_dependencies(
                        target, kernel_name);
                if (!dependency_observation_valid(
                        dependency, target, kernel_name)) {
                    return NdmsNativeFreshImportPreflightStop::
                        keen_pbr_dependency_scan_incomplete;
                }
                if (!dependency.references.empty()) {
                    return NdmsNativeFreshImportPreflightStop::
                        keen_pbr_dependencies_present;
                }
            }
            return NdmsNativeFreshImportPreflightStop::none;
        };
        const auto live_stop = live_and_dependencies_clear();
        if (live_stop != NdmsNativeFreshImportPreflightStop::none) {
            const bool unavailable = live_stop ==
                NdmsNativeFreshImportPreflightStop::
                    kernel_inventory_unavailable ||
                live_stop == NdmsNativeFreshImportPreflightStop::
                    keen_pbr_dependency_scan_incomplete;
            return result(
                unavailable
                    ? NdmsNativeFreshImportPreflightStatus::unavailable
                    : NdmsNativeFreshImportPreflightStatus::blocked,
                live_stop,
                target);
        }

        const auto inspection =
            impl_->ownership.inspect_bounded_read_only();
        if (!inspection.readable) {
            return result(
                NdmsNativeFreshImportPreflightStatus::unavailable,
                NdmsNativeFreshImportPreflightStop::
                    ownership_inventory_unreadable,
                target);
        }
        if (target_has_claim(inspection, target)) {
            return result(
                NdmsNativeFreshImportPreflightStatus::blocked,
                NdmsNativeFreshImportPreflightStop::
                    first_free_target_retains_ownership,
                target);
        }
        if (!writer_still_held(writer)) {
            return result(
                NdmsNativeFreshImportPreflightStatus::unavailable,
                NdmsNativeFreshImportPreflightStop::writer_lost,
                target);
        }
        if (!impl_->snapshots.ensure_absence_durable(target)) {
            return result(
                NdmsNativeFreshImportPreflightStatus::blocked,
                NdmsNativeFreshImportPreflightStop::
                    first_free_snapshot_absence_unproven,
                target);
        }
        if (!writer_still_held(writer)) {
            return result(
                NdmsNativeFreshImportPreflightStatus::unavailable,
                NdmsNativeFreshImportPreflightStop::writer_lost,
                target);
        }

        const auto final_delete_readiness =
            impl_->delete_wal.readiness();
        if (final_delete_readiness ==
            NdmsNativeDeleteWalReadiness::unfinished) {
            return result(
                NdmsNativeFreshImportPreflightStatus::blocked,
                NdmsNativeFreshImportPreflightStop::
                    delete_wal_unfinished,
                target);
        }
        if (final_delete_readiness ==
            NdmsNativeDeleteWalReadiness::unsafe) {
            return result(
                NdmsNativeFreshImportPreflightStatus::unavailable,
                NdmsNativeFreshImportPreflightStop::delete_wal_unsafe,
                target);
        }
        const auto final_import_inventory =
            impl_->import_wal.inventory();
        const auto final_admission =
            summarize_ndms_native_mutation_admission(
                final_import_inventory, final_delete_readiness);
        if (final_admission != NdmsNativeMutationAdmissionState::admitted) {
            const bool known_recovery =
                final_admission ==
                    NdmsNativeMutationAdmissionState::blocked &&
                final_import_inventory.recovery_permitted() &&
                !final_import_inventory.items.empty();
            return result(
                known_recovery
                    ? NdmsNativeFreshImportPreflightStatus::blocked
                    : NdmsNativeFreshImportPreflightStatus::unavailable,
                known_recovery
                    ? NdmsNativeFreshImportPreflightStop::
                          import_recovery_required
                    : NdmsNativeFreshImportPreflightStop::
                          import_wal_unsafe,
                target);
        }

        auto final_runtime = impl_->gateway->observe_catalog(
            NdmsNativeDirectCatalogScope::runtime_state);
        const auto final_runtime_measure = measure_catalog(
            final_runtime,
            NdmsNativeDirectCatalogScope::runtime_state,
            true);
        if (final_runtime_measure.stop !=
            NdmsNativeFreshImportPreflightStop::none) {
            const bool unavailable =
                final_runtime_measure.stop !=
                NdmsNativeFreshImportPreflightStop::
                    no_first_free_slot;
            return result(
                unavailable
                    ? NdmsNativeFreshImportPreflightStatus::unavailable
                    : NdmsNativeFreshImportPreflightStatus::blocked,
                final_runtime_measure.stop,
                target);
        }
        auto final_running = impl_->gateway->observe_catalog(
            NdmsNativeDirectCatalogScope::running_config);
        const auto final_running_measure = measure_catalog(
            final_running,
            NdmsNativeDirectCatalogScope::running_config,
            false);
        if (final_running_measure.stop !=
            NdmsNativeFreshImportPreflightStop::none) {
            const bool unavailable =
                final_running_measure.stop !=
                NdmsNativeFreshImportPreflightStop::
                    no_first_free_slot;
            return result(
                unavailable
                    ? NdmsNativeFreshImportPreflightStatus::unavailable
                    : NdmsNativeFreshImportPreflightStatus::blocked,
                final_running_measure.stop,
                target);
        }
        if (final_runtime_measure.first_free_slot !=
                final_running_measure.first_free_slot ||
            final_runtime_measure.first_free_slot !=
                runtime_measure.first_free_slot) {
            return result(
                NdmsNativeFreshImportPreflightStatus::blocked,
                NdmsNativeFreshImportPreflightStop::
                    first_free_scope_mismatch,
                target);
        }

        const auto final_inspection =
            impl_->ownership.inspect_bounded_read_only();
        if (!final_inspection.readable) {
            return result(
                NdmsNativeFreshImportPreflightStatus::unavailable,
                NdmsNativeFreshImportPreflightStop::
                    ownership_inventory_unreadable,
                target);
        }
        if (target_has_claim(final_inspection, target)) {
            return result(
                NdmsNativeFreshImportPreflightStatus::blocked,
                NdmsNativeFreshImportPreflightStop::
                    first_free_target_retains_ownership,
                target);
        }
        const auto final_live_stop = live_and_dependencies_clear();
        if (final_live_stop != NdmsNativeFreshImportPreflightStop::none) {
            const bool unavailable = final_live_stop ==
                NdmsNativeFreshImportPreflightStop::
                    kernel_inventory_unavailable ||
                final_live_stop == NdmsNativeFreshImportPreflightStop::
                    keen_pbr_dependency_scan_incomplete;
            return result(
                unavailable
                    ? NdmsNativeFreshImportPreflightStatus::unavailable
                    : NdmsNativeFreshImportPreflightStatus::blocked,
                final_live_stop,
                target);
        }
        if (!impl_->snapshots.ensure_absence_durable(target)) {
            return result(
                NdmsNativeFreshImportPreflightStatus::blocked,
                NdmsNativeFreshImportPreflightStop::
                    first_free_snapshot_absence_unproven,
                target);
        }
        if (!writer_still_held(writer)) {
            return result(
                NdmsNativeFreshImportPreflightStatus::unavailable,
                NdmsNativeFreshImportPreflightStop::writer_lost,
                target);
        }
        return result(
            NdmsNativeFreshImportPreflightStatus::admitted,
            NdmsNativeFreshImportPreflightStop::none,
            target);
    } catch (...) {
        return result(
            NdmsNativeFreshImportPreflightStatus::unavailable,
            NdmsNativeFreshImportPreflightStop::unexpected_failure);
    }
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeFreshImportPreflight
NdmsNativeFreshImportPreflightTestIssuer::issue(
    NdmsNativeImportWalStore& import_wal,
    NdmsNativeDeleteWalStore& delete_wal,
    NdmsNativeOwnershipStore& ownership,
    NdmsNativeSecretSnapshotStore& snapshots,
    NdmsNativeKeenPbrDependencyProvider& dependencies,
    NdmsNativeFreshImportPreflightObservationGateway& gateway,
    NdmsNativeFreshImportKernelInventoryGateway& kernel_inventory) {
    return NdmsNativeFreshImportPreflight{
        std::make_unique<NdmsNativeFreshImportPreflight::Impl>(
            import_wal,
            delete_wal,
            ownership,
            snapshots,
            dependencies,
            gateway,
            kernel_inventory)};
}
#endif

const char* ndms_native_fresh_import_preflight_status_name(
    const NdmsNativeFreshImportPreflightStatus status) noexcept {
    switch (status) {
    case NdmsNativeFreshImportPreflightStatus::blocked:
        return "blocked";
    case NdmsNativeFreshImportPreflightStatus::unavailable:
        return "unavailable";
    case NdmsNativeFreshImportPreflightStatus::admitted:
        return "admitted";
    }
    return "unavailable";
}

const char* ndms_native_fresh_import_preflight_stop_name(
    const NdmsNativeFreshImportPreflightStop stop) noexcept {
    switch (stop) {
    case NdmsNativeFreshImportPreflightStop::none: return "none";
    case NdmsNativeFreshImportPreflightStop::writer_missing:
        return "writer_missing";
    case NdmsNativeFreshImportPreflightStop::writer_lost:
        return "writer_lost";
    case NdmsNativeFreshImportPreflightStop::import_recovery_required:
        return "import_recovery_required";
    case NdmsNativeFreshImportPreflightStop::import_wal_unsafe:
        return "import_wal_unsafe";
    case NdmsNativeFreshImportPreflightStop::delete_wal_unfinished:
        return "delete_wal_unfinished";
    case NdmsNativeFreshImportPreflightStop::delete_wal_unsafe:
        return "delete_wal_unsafe";
    case NdmsNativeFreshImportPreflightStop::runtime_observation_failed:
        return "runtime_observation_failed";
    case NdmsNativeFreshImportPreflightStop::
        running_config_observation_failed:
        return "running_config_observation_failed";
    case NdmsNativeFreshImportPreflightStop::observation_scope_mismatch:
        return "observation_scope_mismatch";
    case NdmsNativeFreshImportPreflightStop::observed_catalog_unsafe:
        return "observed_catalog_unsafe";
    case NdmsNativeFreshImportPreflightStop::first_free_scope_mismatch:
        return "first_free_scope_mismatch";
    case NdmsNativeFreshImportPreflightStop::no_first_free_slot:
        return "no_first_free_slot";
    case NdmsNativeFreshImportPreflightStop::
        first_free_target_not_managed:
        return "first_free_target_not_managed";
    case NdmsNativeFreshImportPreflightStop::
        ownership_inventory_unreadable:
        return "ownership_inventory_unreadable";
    case NdmsNativeFreshImportPreflightStop::
        first_free_target_retains_ownership:
        return "first_free_target_retains_ownership";
    case NdmsNativeFreshImportPreflightStop::kernel_inventory_unavailable:
        return "kernel_inventory_unavailable";
    case NdmsNativeFreshImportPreflightStop::
        first_free_kernel_identity_present:
        return "first_free_kernel_identity_present";
    case NdmsNativeFreshImportPreflightStop::
        keen_pbr_dependency_scan_incomplete:
        return "keen_pbr_dependency_scan_incomplete";
    case NdmsNativeFreshImportPreflightStop::
        keen_pbr_dependencies_present:
        return "keen_pbr_dependencies_present";
    case NdmsNativeFreshImportPreflightStop::
        first_free_snapshot_absence_unproven:
        return "first_free_snapshot_absence_unproven";
    case NdmsNativeFreshImportPreflightStop::unexpected_failure:
        return "unexpected_failure";
    }
    return "unexpected_failure";
}

} // namespace keen_pbr3
