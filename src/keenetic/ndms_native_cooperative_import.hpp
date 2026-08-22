#pragma once

#include "ndms_native_delete_wal_store.hpp"
#include "ndms_native_direct_observation.hpp"
#include "ndms_native_exact_mutation_transport.hpp"
#include "ndms_native_import_baseline.hpp"
#include "ndms_native_import_executor.hpp"
#include "ndms_native_import_recovery_dispatch.hpp"
#include "ndms_native_ownership_store.hpp"
#include "ndms_native_secret_snapshot.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace keen_pbr3 {

// The stock empty-name importer chooses the first free Wireguard slot, while
// Keenetic's UI, ndmc and third-party managers do not participate in the
// keen-pbr writer lease. Production therefore requires an explicit owner
// acknowledgement of that residual race. This is not an allocator fence.
enum class NdmsNativeExternalWriterRaceAcceptance : std::uint8_t {
    not_accepted,
    owner_accepted,
};

enum class NdmsNativeCooperativeImportStatus : std::uint8_t {
    blocked,
    recovery_required,
    completed,
};

enum class NdmsNativeCooperativeImportWalReadiness : std::uint8_t {
    clean,
    unfinished,
    unsafe,
};

enum class NdmsNativeCooperativeImportStop : std::uint8_t {
    none,
    external_writer_race_not_accepted,
    writer_missing,
    writer_lost,
    delete_wal_not_clean,
    import_wal_not_clean,
    request_invalid,
    runtime_catalog_failed,
    running_config_catalog_failed,
    prewrite_catalog_unsafe,
    prewrite_catalog_diverged,
    marker_collision,
    first_free_target_not_managed,
    ownership_target_not_available,
    snapshot_target_not_available,
    durable_observation_failed,
    cooperative_baseline_failed,
    cooperative_writer_admission_failed,
    executor_blocked,
    wal_record_unavailable,
    first_post_observation_failed,
    second_post_observation_failed,
    post_observation_kind_mismatch,
    post_observation_unstable,
    forward_completion_blocked,
    forward_admission_failed,
    target_verified_wal_publish_failed,
    ownership_publish_failed,
    ownership_wal_publish_failed,
    wal_cleanup_failed,
    unexpected_failure,
};

enum class NdmsNativeCooperativeImportResumeStatus : std::uint8_t {
    no_work,
    blocked,
    recovery_required,
    completed,
};

// `resume_once()` executes only classifier-authorized bounded work. It may
// finish forward bookkeeping, retire a stable-absence record without router
// mutation, or run one exact rollback delete after fresh invocation-scoped
// external-writer-risk acceptance. Unknown/divergent evidence stays blocked.
enum class NdmsNativeCooperativeImportResumeStop : std::uint8_t {
    none,
    writer_missing,
    writer_lost,
    delete_wal_not_clean,
    import_wal_not_single_safe,
    record_not_cooperative,
    phase_not_forward_only,
    external_writer_race_not_accepted,
    expected_target_not_managed,
    first_observation_failed,
    second_observation_failed,
    observation_kind_mismatch,
    durable_observation_failed,
    observation_unstable,
    ownership_not_exact,
    snapshot_not_exact,
    recovery_action_not_forward_only,
    recovery_action_not_actionable,
    forward_admission_failed,
    recovery_admission_failed,
    target_verified_wal_publish_failed,
    ownership_publish_failed,
    ownership_wal_publish_failed,
    rollback_wal_publish_failed,
    ownership_retract_failed,
    delete_wal_publish_failed,
    delete_guard_rejected,
    delete_transport_ambiguous,
    absence_wal_publish_failed,
    snapshot_retirement_failed,
    wal_cleanup_failed,
    unexpected_failure,
};

// Redacted operation result. A recovery-required result intentionally carries
// enough phase information for the caller to explain that automatic cleanup
// must run, but no request body, private key, endpoint or raw RCI response.
struct NdmsNativeCooperativeImportResult final {
    NdmsNativeCooperativeImportStatus status{
        NdmsNativeCooperativeImportStatus::blocked};
    NdmsNativeCooperativeImportStop stop{
        NdmsNativeCooperativeImportStop::none};
    bool external_ndms_writer_race_excluded{false};
    bool external_ndms_writer_race_accepted{false};
    bool system_configuration_save_performed{false};
    bool request_may_have_been_dispatched{false};
    bool wal_may_require_recovery{false};
    bool rollback_snapshot_may_be_retained{false};
    bool ownership_published{false};
    std::optional<std::string> transaction_id;
    std::optional<std::string> expected_interface;
    std::optional<std::string> created_interface;
    // Exact kernel identity resolved from the live local interface inventory;
    // never inferred from the firmware name alone.
    std::optional<std::string> created_kernel_interface;
    std::optional<NdmsNativeTunnelImportKind> kind;
    std::optional<NdmsNativeDeleteWalReadiness> delete_wal_readiness;
    std::optional<NdmsNativeCooperativeImportWalReadiness>
        import_wal_readiness;
    std::optional<NdmsNativeTunnelImportErrorCode> request_error;
    std::optional<NdmsNativeDirectObservationFailure>
        direct_observation_failure;
    std::optional<NdmsNativeImportBaselineBuildError> baseline_error;
    std::optional<NdmsNativeImportExecutionStop> executor_stop;
    std::optional<NdmsNativeImportRecoveryAdmissionState>
        forward_admission_state;
    std::optional<NdmsNativeImportRecoveryDispatchState>
        forward_dispatch_state;
    std::optional<NdmsNativeImportRecoveryStep> forward_failed_step;
};

// Redacted result for one bounded recovery pass.  The import POST and global
// save flags are permanently false.  A delete can run only for an exact
// rollback action after fresh invocation-scoped owner acceptance; that
// acceptance is never persisted as reusable authority.
// `created_interface` and `created_kernel_interface` are populated only after
// two fresh, stable, authoritative observations prove the exact marker,
// firmware target, same safe kernel identity, kind and full revision.
struct NdmsNativeCooperativeImportResumeResult final {
    NdmsNativeCooperativeImportResumeStatus status{
        NdmsNativeCooperativeImportResumeStatus::blocked};
    NdmsNativeCooperativeImportResumeStop stop{
        NdmsNativeCooperativeImportResumeStop::none};
    bool ndms_import_request_dispatched{false};
    bool ndms_delete_dispatched{false};
    bool system_configuration_save_performed{false};
    bool external_ndms_writer_race_excluded{false};
    bool external_ndms_writer_race_accepted{false};
    bool delete_perform_started{false};
    bool request_may_have_been_dispatched{false};
    bool wal_may_require_recovery{false};
    bool ownership_published{false};
    bool rollback_snapshot_retired{false};
    bool wal_removed{false};
    std::optional<std::string> transaction_id;
    std::optional<std::string> expected_interface;
    std::optional<std::string> created_interface;
    std::optional<std::string> created_kernel_interface;
    std::optional<NdmsNativeTunnelImportKind> kind;
    std::optional<NdmsNativeImportWalPhase> phase;
    std::optional<NdmsNativeDeleteWalReadiness> delete_wal_readiness;
    std::optional<NdmsNativeCooperativeImportWalReadiness>
        import_wal_readiness;
    std::optional<NdmsNativeDirectObservationFailure>
        direct_observation_failure;
    std::optional<NdmsNativeImportRecoveryAction> recovery_action;
    std::optional<NdmsNativeImportRecoveryAdmissionState>
        forward_admission_state;
    std::optional<NdmsNativeImportRecoveryDispatchState>
        forward_dispatch_state;
    std::optional<NdmsNativeImportRecoveryStep> forward_failed_step;
    std::optional<NdmsNativeImportRecoveryAdmissionState>
        recovery_admission_state;
    std::optional<NdmsNativeImportRecoveryDispatchState>
        recovery_dispatch_state;
    std::optional<NdmsNativeImportRecoveryStep> recovery_failed_step;
    std::optional<NdmsNativeExactMutationResponseOutcome>
        delete_transport_outcome;
};

// Narrow read-only seam. Production wraps the fixed-loopback direct gateway;
// offline tests inject typed observations and never contact a router.
class NdmsNativeCooperativeImportObservationGateway {
public:
    virtual ~NdmsNativeCooperativeImportObservationGateway() = default;

    virtual NdmsNativeDirectCatalogObservation observe_catalog(
        NdmsNativeDirectCatalogScope scope) noexcept = 0;
    virtual NdmsNativeDirectRecoveryObservation observe_recovery(
        NdmsNativeDirectCatalogScope scope,
        const std::string& marker,
        const std::optional<std::string>& expected_target) noexcept = 0;
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeCooperativeImportCoordinatorTestIssuer;
#endif

// First production-capable create-only coordinator for stock WG/AWG imports.
// It owns no outer lock: callers must already have acquired maintenance,
// runtime mutation admission and then NdmsNativeWriterLease in that order.
// A proved created interface is enabled and saved before ownership is
// finalized. Both writes are exact, fixed-loopback and idempotent; an
// interrupted pass leaves the existing import WAL for the same bodyless
// recovery path. The coordinator exposes no caller-selected RCI operation.
// Production wiring constructs and retains the hardened stores once, using
// the intended split layout (not per request): all owner-only mutable stores
// live below the root-owned /opt/etc/keen-pbr anchor. The snapshot key and
// encrypted snapshots use separate sibling directories under that anchor.
// This deliberately avoids assuming that Entware's /opt/var is root-owned.
// The mandatory delete-WAL
// dependency is read-only here and supplies symmetric cross-kind admission.
class NdmsNativeCooperativeImportCoordinator final {
public:
    NdmsNativeCooperativeImportCoordinator(
        NdmsNativeObservationStore& observations,
        NdmsNativeImportWalStore& wal,
        NdmsNativeDeleteWalStore& delete_wal,
        NdmsNativeSecretSnapshotStore& snapshots,
        NdmsNativeOwnershipStore& ownership);
    ~NdmsNativeCooperativeImportCoordinator();

    NdmsNativeCooperativeImportCoordinator(
        const NdmsNativeCooperativeImportCoordinator&) = delete;
    NdmsNativeCooperativeImportCoordinator& operator=(
        const NdmsNativeCooperativeImportCoordinator&) = delete;
    NdmsNativeCooperativeImportCoordinator(
        NdmsNativeCooperativeImportCoordinator&&) noexcept;
    NdmsNativeCooperativeImportCoordinator& operator=(
        NdmsNativeCooperativeImportCoordinator&&) noexcept;

    NdmsNativeCooperativeImportResult import_once(
        NdmsNativeWriterLease& writer,
        std::string&& raw_configuration,
        NdmsNativeExternalWriterRaceAcceptance race_acceptance,
        std::string_view display_name = {}) noexcept;

    // Completes at most one already-durable cooperative import. The default
    // bodyless/unconfirmed entrance can forward-complete or retire an exact
    // snapshot plus WAL after authoritative stable absence. It cannot delete.
    // An exact-present rollback additionally requires fresh owner acceptance
    // for this invocation; the WAL never stores it.
    NdmsNativeCooperativeImportResumeResult resume_once(
        NdmsNativeWriterLease& writer,
        NdmsNativeExternalWriterRaceAcceptance race_acceptance =
            NdmsNativeExternalWriterRaceAcceptance::not_accepted) noexcept;

private:
    struct Impl;
    explicit NdmsNativeCooperativeImportCoordinator(
        std::unique_ptr<Impl> impl) noexcept;

    NdmsNativeExactMutationTransportResult dispatch_delete_once(
        NdmsNativeExactMutationRequest request,
        NdmsNativeExactMutationPreDispatchGuard& guard);
    NdmsNativeExactMutationTransportResult dispatch_activation_once(
        NdmsNativeExactMutationRequest request,
        NdmsNativeExactMutationPreDispatchGuard& guard);
    bool normalize_completed_identity(
        NdmsNativeWriterLease& writer,
        const NdmsNativeOwnershipRecord& ownership,
        std::string_view display_name,
        std::string_view primary_peer_public_key) noexcept;

    std::unique_ptr<Impl> impl_;

#ifdef KEEN_PBR3_TESTING
    friend class NdmsNativeCooperativeImportCoordinatorTestIssuer;
#endif
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeCooperativeImportCoordinatorTestIssuer final {
public:
    static NdmsNativeCooperativeImportCoordinator issue(
        NdmsNativeObservationStore& observations,
        NdmsNativeImportWalStore& wal,
        NdmsNativeDeleteWalStore& delete_wal,
        NdmsNativeSecretSnapshotStore& snapshots,
        NdmsNativeOwnershipStore& ownership,
        NdmsNativeCooperativeImportObservationGateway& gateway,
        NdmsNativeLoopbackRciPostBackend& transport,
        NdmsNativeExactMutationBackend& delete_transport,
        NdmsNativeImportExecutorClock& clock,
        NdmsNativeExactMutationBackend* activation_transport = nullptr);
};
#endif

const char* ndms_native_cooperative_import_status_name(
    NdmsNativeCooperativeImportStatus status) noexcept;
const char* ndms_native_cooperative_import_stop_name(
    NdmsNativeCooperativeImportStop stop) noexcept;
const char* ndms_native_cooperative_import_resume_status_name(
    NdmsNativeCooperativeImportResumeStatus status) noexcept;
const char* ndms_native_cooperative_import_resume_stop_name(
    NdmsNativeCooperativeImportResumeStop stop) noexcept;

} // namespace keen_pbr3
