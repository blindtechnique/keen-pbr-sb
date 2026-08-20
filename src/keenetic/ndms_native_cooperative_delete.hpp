#pragma once

#include "ndms_native_delete_wal_store.hpp"
#include "ndms_native_direct_observation.hpp"
#include "ndms_native_exact_mutation_transport.hpp"
#include "ndms_native_import_wal_store.hpp"
#include "ndms_native_observation_store.hpp"
#include "ndms_native_ownership_store.hpp"
#include "ndms_native_secret_snapshot.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class NdmsNativeOwnerGlobalSaveConsent : std::uint8_t {
    not_acknowledged,
    // Keenetic's system save persists every pending device change. This is
    // owner consent to that scope, not whole-config CAS or saved-state proof.
    acknowledged_all_pending_keenetic_changes,
};

enum class NdmsNativeDeleteExternalWriterRaceAcceptance : std::uint8_t {
    not_accepted,
    // The cooperative lease orders keen-pbr writers only. Firmware UI, ndmc
    // and third-party managers can still race the final direct observation.
    owner_accepted,
};

// This gate covers only references owned by keen-pbr. It makes no claim about
// Keenetic Web UI, ndmc, AWG Manager or another third-party consumer.
enum class NdmsNativeKeenPbrDependencyScope : std::uint8_t {
    config_and_runtime_interface_references,
};

enum class NdmsNativeKeenPbrDependencyKind : std::uint8_t {
    interface_outbound,
    internal_vpn_policy,
    inbound_interface_policy,
    native_interface_preference,
};

struct NdmsNativeKeenPbrDependency final {
    NdmsNativeKeenPbrDependencyKind kind{
        NdmsNativeKeenPbrDependencyKind::interface_outbound};
    std::string dependent_id;

    bool operator==(
        const NdmsNativeKeenPbrDependency& other) const noexcept;
};

struct NdmsNativeKeenPbrDependencyObservation final {
    NdmsNativeKeenPbrDependencyScope scope{
        NdmsNativeKeenPbrDependencyScope::
            config_and_runtime_interface_references};
    bool complete{false};
    std::string firmware_interface_name;
    std::optional<std::string> kernel_interface_name;
    std::vector<NdmsNativeKeenPbrDependency> references;
    std::string keen_pbr_dependency_revision;
};

std::string ndms_native_keen_pbr_dependency_revision(
    const NdmsNativeKeenPbrDependencyObservation& observation);

class NdmsNativeKeenPbrDependencyProvider {
public:
    virtual ~NdmsNativeKeenPbrDependencyProvider() = default;
    virtual NdmsNativeKeenPbrDependencyObservation observe_dependencies(
        const std::string& firmware_interface_name,
        const std::optional<std::string>& kernel_interface_name) noexcept = 0;
};

class NdmsNativeCooperativeDeleteObservationGateway {
public:
    virtual ~NdmsNativeCooperativeDeleteObservationGateway() = default;
    virtual NdmsNativeDirectRecoveryObservation observe_recovery(
        NdmsNativeDirectCatalogScope scope,
        const std::string& marker,
        const std::optional<std::string>& expected_target) noexcept = 0;
};

struct NdmsNativeCooperativeDeleteRequest final {
    std::string interface_name;
    // Opaque revision rendered with the card. It prevents a stale card from
    // deleting a different panel-owned claim after the same slot is reused.
    std::string expected_ownership_revision;
    NdmsNativeOwnerGlobalSaveConsent global_save_consent{
        NdmsNativeOwnerGlobalSaveConsent::not_acknowledged};
    NdmsNativeDeleteExternalWriterRaceAcceptance external_writer_race{
        NdmsNativeDeleteExternalWriterRaceAcceptance::not_accepted};
};

// Fresh owner decisions for this single recovery invocation. They are never
// persisted as reusable authority: a later invocation must ask again before
// it can dispatch or re-dispatch Keenetic's global configuration save.
struct NdmsNativeCooperativeDeleteResumeAcknowledgement final {
    NdmsNativeOwnerGlobalSaveConsent global_save_consent{
        NdmsNativeOwnerGlobalSaveConsent::not_acknowledged};
    NdmsNativeDeleteExternalWriterRaceAcceptance external_writer_race{
        NdmsNativeDeleteExternalWriterRaceAcceptance::not_accepted};
};

enum class NdmsNativeCooperativeDeleteStatus : std::uint8_t {
    blocked,
    recovery_required,
    save_acknowledged_unverified,
};

enum class NdmsNativeCooperativeDeleteStop : std::uint8_t {
    none,
    owner_global_save_not_acknowledged,
    external_writer_race_not_accepted,
    save_reconfirmation_required,
    writer_missing,
    writer_lost,
    invalid_or_protected_target,
    import_wal_not_authoritatively_clean,
    delete_wal_unfinished,
    delete_wal_unsafe,
    no_delete_transaction,
    ownership_absent,
    ownership_unreadable,
    ownership_not_active,
    ownership_changed,
    snapshot_absent,
    snapshot_unreadable,
    snapshot_mismatch,
    keen_pbr_dependency_scan_incomplete,
    keen_pbr_dependencies_present,
    keen_pbr_dependency_changed,
    runtime_observation_failed,
    running_config_observation_failed,
    observation_scope_mismatch,
    observed_target_mismatch,
    observed_target_drifted,
    observed_target_reappeared_after_save,
    durable_observation_failed,
    delete_wal_publish_failed,
    delete_guard_rejected,
    delete_transport_ambiguous,
    save_guard_rejected,
    save_transport_ambiguous,
    tombstone_publish_failed,
    tombstone_mismatch,
    delete_wal_cleanup_failed,
    unexpected_failure,
};

struct NdmsNativeCooperativeDeleteResult final {
    NdmsNativeCooperativeDeleteStatus status{
        NdmsNativeCooperativeDeleteStatus::blocked};
    NdmsNativeCooperativeDeleteStop stop{
        NdmsNativeCooperativeDeleteStop::none};
    std::optional<NdmsNativeDeleteWalPhase> durable_phase;
    std::optional<std::string> transaction_id;
    std::optional<std::string> interface_name;
    std::optional<NdmsNativeTunnelImportKind> kind;
    bool external_writer_race_excluded{false};
    // These two fields are durable audit evidence from the original delete
    // admission. They are not authority to issue a save on a later recovery.
    bool external_writer_race_accepted{false};
    bool global_save_scope_acknowledged{false};
    // Transport facts below describe only this invocation. Durable phase and
    // the original audit evidence above describe earlier invocations.
    bool delete_perform_started{false};
    bool save_perform_started{false};
    bool request_may_have_been_dispatched{false};
    bool system_configuration_save_acknowledged{false};
    bool ownership_tombstone_durable{false};
    // True only after this invocation successfully reread the exact encrypted
    // full snapshot at the return boundary; false also represents unknown.
    bool rollback_snapshot_retained{false};
    std::optional<NdmsNativeExactMutationResponseOutcome>
        transport_outcome;
    std::optional<NdmsNativeDirectObservationFailure>
        observation_failure;
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeCooperativeDeleteCoordinatorTestIssuer;
#endif

// Production-capable core only. Callers already own the ordered cooperative
// writer lease and must retain it for the whole call. No API, daemon, router
// installation or automatic restore is wired here.
class NdmsNativeCooperativeDeleteCoordinator final {
public:
    NdmsNativeCooperativeDeleteCoordinator(
        NdmsNativeObservationStore& observations,
        NdmsNativeImportWalStore& import_wal,
        NdmsNativeDeleteWalStore& delete_wal,
        NdmsNativeSecretSnapshotStore& snapshots,
        NdmsNativeOwnershipStore& ownership,
        NdmsNativeKeenPbrDependencyProvider& dependencies);
    ~NdmsNativeCooperativeDeleteCoordinator();

    NdmsNativeCooperativeDeleteCoordinator(
        const NdmsNativeCooperativeDeleteCoordinator&) = delete;
    NdmsNativeCooperativeDeleteCoordinator& operator=(
        const NdmsNativeCooperativeDeleteCoordinator&) = delete;
    NdmsNativeCooperativeDeleteCoordinator(
        NdmsNativeCooperativeDeleteCoordinator&&) noexcept;
    NdmsNativeCooperativeDeleteCoordinator& operator=(
        NdmsNativeCooperativeDeleteCoordinator&&) noexcept;

    NdmsNativeCooperativeDeleteResult delete_once(
        NdmsNativeWriterLease& writer,
        const NdmsNativeCooperativeDeleteRequest& request) noexcept;

    // It never accepts a new target and cannot resume a corrupt/unsafe record.
    // A missing current acknowledgement can still advance idempotent delete
    // recovery, but it stops before any global-save dispatch. Post-save phases
    // need no new acknowledgement because they issue no further save.
    NdmsNativeCooperativeDeleteResult resume_once(
        NdmsNativeWriterLease& writer,
        const NdmsNativeCooperativeDeleteResumeAcknowledgement&
            current_acknowledgement = {}) noexcept;

private:
    struct Impl;
    explicit NdmsNativeCooperativeDeleteCoordinator(
        std::unique_ptr<Impl> impl) noexcept;

    NdmsNativeExactMutationTransportResult dispatch_once(
        NdmsNativeExactMutationRequest request,
        NdmsNativeExactMutationPreDispatchGuard& guard);

    NdmsNativeCooperativeDeleteResult run_record(
        NdmsNativeWriterLease& writer,
        NdmsNativeDeleteWalRecord record,
        bool current_save_reconfirmed);

    std::unique_ptr<Impl> impl_;

#ifdef KEEN_PBR3_TESTING
    friend class NdmsNativeCooperativeDeleteCoordinatorTestIssuer;
#endif
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeCooperativeDeleteCoordinatorTestIssuer final {
public:
    static NdmsNativeCooperativeDeleteCoordinator issue(
        NdmsNativeObservationStore& observations,
        NdmsNativeImportWalStore& import_wal,
        NdmsNativeDeleteWalStore& delete_wal,
        NdmsNativeSecretSnapshotStore& snapshots,
        NdmsNativeOwnershipStore& ownership,
        NdmsNativeKeenPbrDependencyProvider& dependencies,
        NdmsNativeCooperativeDeleteObservationGateway& gateway,
        NdmsNativeExactMutationBackend& backend,
        std::function<std::string()> transaction_id_factory = {});
};
#endif

const char* ndms_native_cooperative_delete_status_name(
    NdmsNativeCooperativeDeleteStatus status) noexcept;
const char* ndms_native_cooperative_delete_stop_name(
    NdmsNativeCooperativeDeleteStop stop) noexcept;

} // namespace keen_pbr3
