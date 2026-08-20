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

enum class NdmsNativeFreshImportPreflightStatus : std::uint8_t {
    blocked,
    unavailable,
    admitted,
};

enum class NdmsNativeFreshImportPreflightStop : std::uint8_t {
    none,
    writer_missing,
    writer_lost,
    import_recovery_required,
    import_wal_unsafe,
    delete_wal_unfinished,
    delete_wal_unsafe,
    runtime_observation_failed,
    running_config_observation_failed,
    observation_scope_mismatch,
    observed_catalog_unsafe,
    first_free_scope_mismatch,
    no_first_free_slot,
    first_free_target_not_managed,
    ownership_inventory_unreadable,
    first_free_target_retains_ownership,
    kernel_inventory_unavailable,
    first_free_kernel_identity_present,
    keen_pbr_dependency_scan_incomplete,
    keen_pbr_dependencies_present,
    first_free_snapshot_absence_unproven,
    unexpected_failure,
};

// This is intentionally bodyless. A caller may take a secret request body
// only after `secret_body_may_be_taken()` returns true while retaining the
// same complete writer lease.
struct NdmsNativeFreshImportPreflightResult final {
    NdmsNativeFreshImportPreflightStatus status{
        NdmsNativeFreshImportPreflightStatus::unavailable};
    NdmsNativeFreshImportPreflightStop stop{
        NdmsNativeFreshImportPreflightStop::unexpected_failure};
    std::optional<std::string> expected_first_free_target;

    bool secret_body_may_be_taken() const noexcept {
        return status == NdmsNativeFreshImportPreflightStatus::admitted &&
               stop == NdmsNativeFreshImportPreflightStop::none &&
               expected_first_free_target.has_value();
    }
};

class NdmsNativeFreshImportPreflightObservationGateway {
public:
    virtual ~NdmsNativeFreshImportPreflightObservationGateway() = default;
    virtual NdmsNativeDirectCatalogObservation observe_catalog(
        NdmsNativeDirectCatalogScope scope) noexcept = 0;
};

struct NdmsNativeFreshImportKernelInventory final {
    bool complete{false};
    std::vector<std::string> interface_names;
};

class NdmsNativeFreshImportKernelInventoryGateway {
public:
    virtual ~NdmsNativeFreshImportKernelInventoryGateway() = default;
    virtual NdmsNativeFreshImportKernelInventory observe() noexcept = 0;
};

class NdmsNativeFreshImportPreflight final {
public:
    NdmsNativeFreshImportPreflight(
        NdmsNativeImportWalStore& import_wal,
        NdmsNativeDeleteWalStore& delete_wal,
        NdmsNativeOwnershipStore& ownership,
        NdmsNativeSecretSnapshotStore& snapshots,
        NdmsNativeKeenPbrDependencyProvider& dependencies);
    ~NdmsNativeFreshImportPreflight();

    NdmsNativeFreshImportPreflight(
        const NdmsNativeFreshImportPreflight&) = delete;
    NdmsNativeFreshImportPreflight& operator=(
        const NdmsNativeFreshImportPreflight&) = delete;
    NdmsNativeFreshImportPreflight(
        NdmsNativeFreshImportPreflight&&) noexcept;
    NdmsNativeFreshImportPreflight& operator=(
        NdmsNativeFreshImportPreflight&&) noexcept;

    NdmsNativeFreshImportPreflightResult check_before_secret_take(
        NdmsNativeWriterLease& writer) noexcept;

private:
    struct Impl;
    explicit NdmsNativeFreshImportPreflight(
        std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;

#ifdef KEEN_PBR3_TESTING
    friend class NdmsNativeFreshImportPreflightTestIssuer;
#endif
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeFreshImportPreflightTestIssuer final {
public:
    static NdmsNativeFreshImportPreflight issue(
        NdmsNativeImportWalStore& import_wal,
        NdmsNativeDeleteWalStore& delete_wal,
        NdmsNativeOwnershipStore& ownership,
        NdmsNativeSecretSnapshotStore& snapshots,
        NdmsNativeKeenPbrDependencyProvider& dependencies,
        NdmsNativeFreshImportPreflightObservationGateway& gateway,
        NdmsNativeFreshImportKernelInventoryGateway& kernel_inventory);
};
#endif

const char* ndms_native_fresh_import_preflight_status_name(
    NdmsNativeFreshImportPreflightStatus status) noexcept;
const char* ndms_native_fresh_import_preflight_stop_name(
    NdmsNativeFreshImportPreflightStop stop) noexcept;

} // namespace keen_pbr3
