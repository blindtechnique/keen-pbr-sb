#pragma once

#include "ndms_native_cooperative_delete.hpp"
#include "ndms_native_delete_wal_store.hpp"
#include "ndms_native_direct_observation.hpp"
#include "ndms_native_import_wal_store.hpp"
#include "ndms_native_ownership_store.hpp"
#include "ndms_native_secret_snapshot.hpp"
#include "ndms_native_writer_lease.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class NdmsNativeTombstoneExactNameConfirmation : std::uint8_t {
    not_confirmed,
    confirmed,
};

enum class NdmsNativeTombstoneRollbackDiscardAcknowledgement
    : std::uint8_t {
    not_acknowledged,
    permanently_discard_rollback_data,
};

enum class NdmsNativeTombstoneForeignReappearanceAcknowledgement
    : std::uint8_t {
    not_acknowledged,
    accepted_reappearance_is_foreign,
};

struct NdmsNativeTombstoneForgetRequest final {
    std::string interface_name;
    std::string confirmed_interface_name;
    std::string expected_ownership_revision;
    NdmsNativeTombstoneExactNameConfirmation exact_name_confirmation{
        NdmsNativeTombstoneExactNameConfirmation::not_confirmed};
    NdmsNativeTombstoneRollbackDiscardAcknowledgement rollback_discard{
        NdmsNativeTombstoneRollbackDiscardAcknowledgement::
            not_acknowledged};
    NdmsNativeTombstoneForeignReappearanceAcknowledgement
        foreign_reappearance{
            NdmsNativeTombstoneForeignReappearanceAcknowledgement::
                not_acknowledged};
};

enum class NdmsNativeTombstoneForgetStatus : std::uint8_t {
    blocked,
    recovery_required,
    forgotten,
};

enum class NdmsNativeTombstoneForgetStop : std::uint8_t {
    none,
    exact_name_not_confirmed,
    rollback_discard_not_acknowledged,
    foreign_reappearance_not_acknowledged,
    invalid_or_protected_target,
    writer_missing,
    writer_lost,
    import_wal_not_authoritatively_clean,
    delete_wal_unfinished,
    delete_wal_unsafe,
    ownership_absent,
    ownership_unreadable,
    ownership_not_forget_capable,
    ownership_changed,
    snapshot_unreadable,
    snapshot_mismatch,
    snapshot_retirement_failed,
    keen_pbr_dependency_scan_incomplete,
    keen_pbr_dependencies_present,
    kernel_inventory_unavailable,
    retained_kernel_interface_present,
    runtime_observation_failed,
    running_config_observation_failed,
    observation_scope_mismatch,
    observed_target_present,
    observed_marker_present,
    observed_catalog_unsafe,
    tombstone_retirement_failed,
    unexpected_failure,
};

// Each artifact is reported independently because snapshot-first ordering can
// leave a safe resumable tombstone after the rollback snapshot is durably
// absent. `unknown` is never collapsed into absence.
enum class NdmsNativeTombstoneForgetArtifactState : std::uint8_t {
    unknown,
    retained,
    absent_durable,
};

struct NdmsNativeTombstoneForgetResult final {
    NdmsNativeTombstoneForgetStatus status{
        NdmsNativeTombstoneForgetStatus::blocked};
    NdmsNativeTombstoneForgetStop stop{
        NdmsNativeTombstoneForgetStop::none};
    std::optional<std::string> interface_name;
    NdmsNativeTombstoneForgetArtifactState snapshot_state{
        NdmsNativeTombstoneForgetArtifactState::unknown};
    NdmsNativeTombstoneForgetArtifactState tombstone_state{
        NdmsNativeTombstoneForgetArtifactState::unknown};
    // This core has no router mutation or save dependency. These facts remain
    // explicit so a future API cannot translate local metadata retirement
    // into a claim about firmware or startup-configuration durability.
    bool router_mutation_attempted{false};
    bool system_configuration_save_acknowledged{false};
    bool future_reappearance_is_foreign{false};
};

class NdmsNativeTombstoneForgetObservationGateway {
public:
    virtual ~NdmsNativeTombstoneForgetObservationGateway() = default;
    virtual NdmsNativeDirectRecoveryObservation observe_recovery(
        NdmsNativeDirectCatalogScope scope,
        const std::string& marker,
        const std::optional<std::string>& expected_target) noexcept = 0;
};

struct NdmsNativeTombstoneForgetKernelInventory final {
    bool complete{false};
    std::vector<std::string> interface_names;
};

class NdmsNativeTombstoneForgetKernelInventoryGateway {
public:
    virtual ~NdmsNativeTombstoneForgetKernelInventoryGateway() = default;
    virtual NdmsNativeTombstoneForgetKernelInventory observe() noexcept = 0;
};

// Metadata-only coordinator. The caller already owns and retains the complete
// Maintenance -> RuntimeMutation -> native-writer lease. No API route,
// automatic retry, router mutation backend or global-save capability exists
// in this type.
class NdmsNativeTombstoneForgetCoordinator final {
public:
    NdmsNativeTombstoneForgetCoordinator(
        NdmsNativeImportWalStore& import_wal,
        NdmsNativeDeleteWalStore& delete_wal,
        NdmsNativeSecretSnapshotStore& snapshots,
        NdmsNativeOwnershipStore& ownership,
        NdmsNativeKeenPbrDependencyProvider& dependencies);
    ~NdmsNativeTombstoneForgetCoordinator();

    NdmsNativeTombstoneForgetCoordinator(
        const NdmsNativeTombstoneForgetCoordinator&) = delete;
    NdmsNativeTombstoneForgetCoordinator& operator=(
        const NdmsNativeTombstoneForgetCoordinator&) = delete;
    NdmsNativeTombstoneForgetCoordinator(
        NdmsNativeTombstoneForgetCoordinator&&) noexcept;
    NdmsNativeTombstoneForgetCoordinator& operator=(
        NdmsNativeTombstoneForgetCoordinator&&) noexcept;

    NdmsNativeTombstoneForgetResult forget_once(
        NdmsNativeWriterLease& writer,
        const NdmsNativeTombstoneForgetRequest& request) noexcept;

private:
    struct Impl;
    explicit NdmsNativeTombstoneForgetCoordinator(
        std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;

#ifdef KEEN_PBR3_TESTING
    friend class NdmsNativeTombstoneForgetCoordinatorTestIssuer;
#endif
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeTombstoneForgetCoordinatorTestIssuer final {
public:
    static NdmsNativeTombstoneForgetCoordinator issue(
        NdmsNativeImportWalStore& import_wal,
        NdmsNativeDeleteWalStore& delete_wal,
        NdmsNativeSecretSnapshotStore& snapshots,
        NdmsNativeOwnershipStore& ownership,
        NdmsNativeKeenPbrDependencyProvider& dependencies,
        NdmsNativeTombstoneForgetObservationGateway& gateway,
        NdmsNativeTombstoneForgetKernelInventoryGateway& kernel_inventory);
};
#endif

const char* ndms_native_tombstone_forget_status_name(
    NdmsNativeTombstoneForgetStatus status) noexcept;
const char* ndms_native_tombstone_forget_stop_name(
    NdmsNativeTombstoneForgetStop stop) noexcept;
const char* ndms_native_tombstone_forget_artifact_state_name(
    NdmsNativeTombstoneForgetArtifactState state) noexcept;

} // namespace keen_pbr3
