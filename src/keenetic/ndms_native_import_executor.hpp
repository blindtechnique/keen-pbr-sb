#pragma once

#include "ndms_native_allocator_fence.hpp"
#include "ndms_native_import_transport.hpp"
#include "ndms_native_import_wal_store.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Safe, non-secret material prepared by the future mutation planner. The
// coordinator deliberately accepts an already parsed, move-only request
// separately so this object can never become another credential lifetime.
struct NdmsNativeImportExecutionPlan final {
    std::string expected_created_interface;
    std::string generation_ticket;
    std::string firmware_identity;
    std::string allocator_implementation_digest;
    NdmsNativeObservationBinding observation_binding;
    NdmsNativeImportExecutionMode execution_mode{
        NdmsNativeImportExecutionMode::allocator_fenced};
    NdmsNativeAllocatorFenceMode fence_mode{
        NdmsNativeAllocatorFenceMode::bounded_atomic_import};
};

// The maintenance generation protects the transaction/reconcile sequence.
// The allocator generation is the authoritative generation bound into the
// opaque allocator receipt. Keeping them separate prevents a local
// maintenance reservation from being mistaken for an NDMS allocator fence.
struct NdmsNativeImportGenerationSnapshot final {
    std::uint32_t maintenance_generation{0U};
    std::uint64_t allocator_generation{0U};
};

class NdmsNativeImportGenerationCoordinator {
public:
    virtual ~NdmsNativeImportGenerationCoordinator() = default;

    virtual NdmsNativeImportGenerationSnapshot observe() = 0;

    // Reserves exactly base + 1 for this transaction. Implementations must
    // return nullopt on contention and must not silently skip generations.
    virtual std::optional<std::uint32_t> reserve_next(
        const std::string& transaction_id,
        const std::string& generation_ticket,
        std::uint32_t maintenance_base_generation) = 0;

    // Cooperative stock import has no allocator-fence receipt. Its exact-next
    // maintenance reservation is delegated to the already held composite
    // writer, whose MaintenanceLease performs the authoritative CAS.
    virtual std::optional<std::uint32_t> reserve_next_cooperative(
        const std::string& transaction_id,
        const std::string& generation_ticket,
        std::uint32_t maintenance_base_generation,
        NdmsNativeWriterLease& writer);
};

class NdmsNativeImportExecutorClock {
public:
    virtual ~NdmsNativeImportExecutorClock() = default;
    virtual NdmsNativeAllocatorMonotonicTime now() const noexcept = 0;
};

class NdmsNativeImportSteadyClock final
    : public NdmsNativeImportExecutorClock {
public:
    NdmsNativeAllocatorMonotonicTime now() const noexcept override;
};

// Narrow publisher boundary for deterministic ordering tests. The production
// adapter below delegates to the hardened NdmsNativeImportWalStore and does
// not expose load/removal: execution can append intent/evidence only.
class NdmsNativeImportWalPublisher {
public:
    virtual ~NdmsNativeImportWalPublisher() = default;

    // Atomically rejects a new transaction unless the complete durable store
    // is safe and empty, then publishes its prepared record.
    virtual NdmsNativeImportWalAdmissionState begin_prepared_exclusive(
        const NdmsNativeImportWalRecord& record) = 0;
    virtual void publish(const NdmsNativeImportWalRecord& record) = 0;
};

class NdmsNativeImportWalStorePublisher final
    : public NdmsNativeImportWalPublisher {
public:
    explicit NdmsNativeImportWalStorePublisher(
        NdmsNativeImportWalStore& store) noexcept;

    NdmsNativeImportWalAdmissionState begin_prepared_exclusive(
        const NdmsNativeImportWalRecord& record) override;
    void publish(const NdmsNativeImportWalRecord& record) override;

private:
    NdmsNativeImportWalStore& store_;
};

// Opaque durable boundary between the prepared WAL intent and any allocator
// generation reservation. A production adapter is deliberately not exposed
// by this slice: future wiring must prove where its key/store live. Returning
// normally means the exact move-only rollback snapshot is durable; throwing
// leaves the prepared WAL for recovery and transport must not be entered.
class NdmsNativeImportSnapshotPublisher {
public:
    virtual ~NdmsNativeImportSnapshotPublisher() = default;
    virtual void publish(
        const std::string& expected_interface,
        const std::string& transaction_id,
        const std::string& marker,
        NdmsNativePanelDeleteSnapshot snapshot) = 0;
};

struct NdmsNativeImportExecutionResult;
class NdmsNativeCooperativeImportWriter;
class NdmsNativeImportExecutorDependencies;
class NdmsNativeCooperativeImportCoordinator;
struct NdmsNativeCooperativeImportAdmission;
#ifdef KEEN_PBR3_TESTING
class NdmsNativeImportExecutorTestIssuer;
class NdmsNativeCooperativeImportWriterTestIssuer;
#endif

enum class NdmsNativeCooperativeImportAdmissionState : std::uint8_t {
    admitted,
    writer_missing,
    writer_lost,
    wrong_scope,
    observation_binding_invalid,
    observation_binding_not_durable,
};

// A narrow, non-owning admission for the measured stock empty-name import.
// It is explicitly cooperative: it excludes keen-pbr writers only and is
// never an NDMS-global allocator fence. The durable observation ledger is
// rechecked at admission and immediately before dispatch.
class NdmsNativeCooperativeImportWriter final {
public:
    NdmsNativeCooperativeImportWriter(
        NdmsNativeCooperativeImportWriter&& other) noexcept;
    NdmsNativeCooperativeImportWriter& operator=(
        NdmsNativeCooperativeImportWriter&& other) noexcept;
    NdmsNativeCooperativeImportWriter(
        const NdmsNativeCooperativeImportWriter&) = delete;
    NdmsNativeCooperativeImportWriter& operator=(
        const NdmsNativeCooperativeImportWriter&) = delete;

private:
    NdmsNativeCooperativeImportWriter(
        NdmsNativeWriterLease* writer,
        const NdmsNativeObservationStore* observations,
        NdmsNativeObservationBinding binding,
        NdmsNativeWriterLeaseScope scope) noexcept;

    void poison_after_move() noexcept;

    NdmsNativeWriterLease* writer_{nullptr};
    const NdmsNativeObservationStore* observations_{nullptr};
    NdmsNativeObservationBinding binding_;
    NdmsNativeWriterLeaseScope scope_{
        NdmsNativeWriterLeaseScope::keen_pbr_cooperative};

    friend struct NdmsNativeCooperativeImportAdmission;
    friend NdmsNativeCooperativeImportAdmission
    admit_ndms_native_cooperative_import_writer(
        NdmsNativeWriterLease&,
        const NdmsNativeObservationStore&,
        const NdmsNativeObservationBinding&) noexcept;
#ifdef KEEN_PBR3_TESTING
    friend class NdmsNativeCooperativeImportWriterTestIssuer;
#endif
    friend NdmsNativeImportExecutionResult
    execute_ndms_native_import_transaction(
        NdmsNativePreparedImport,
        const NdmsNativeImportExecutionPlan&,
        const NdmsNativeImportBaselineEvidence&,
        std::optional<NdmsNativeAllocatorFenceReceipt>,
        std::optional<NdmsNativeCooperativeImportWriter>,
        const NdmsNativeImportExecutorDependencies&);
};

struct NdmsNativeCooperativeImportAdmission final {
    NdmsNativeCooperativeImportAdmissionState state{
        NdmsNativeCooperativeImportAdmissionState::writer_missing};
    std::optional<NdmsNativeCooperativeImportWriter> writer;

    bool admitted() const noexcept {
        return state == NdmsNativeCooperativeImportAdmissionState::admitted &&
               writer.has_value();
    }
};

NdmsNativeCooperativeImportAdmission
admit_ndms_native_cooperative_import_writer(
    NdmsNativeWriterLease& writer,
    const NdmsNativeObservationStore& observations,
    const NdmsNativeObservationBinding& binding) noexcept;

#ifdef KEEN_PBR3_TESTING
class NdmsNativeCooperativeImportWriterTestIssuer final {
public:
    static NdmsNativeCooperativeImportWriter issue_unchecked(
        NdmsNativeWriterLease* writer,
        const NdmsNativeObservationStore* observations,
        NdmsNativeObservationBinding binding,
        NdmsNativeWriterLeaseScope scope) noexcept;
};
#endif

// Dependency injection is intentionally opaque in production. A caller
// cannot substitute a fake clock, WAL, generation source or transport after
// obtaining a real allocator receipt. There is no production construction
// authority; a future concrete wrapper must be added deliberately.
class NdmsNativeImportExecutorDependencies final {
public:
    NdmsNativeImportExecutorDependencies(
        const NdmsNativeImportExecutorDependencies&) = delete;
    NdmsNativeImportExecutorDependencies& operator=(
        const NdmsNativeImportExecutorDependencies&) = delete;
    NdmsNativeImportExecutorDependencies(
        NdmsNativeImportExecutorDependencies&&) noexcept = default;
    NdmsNativeImportExecutorDependencies& operator=(
        NdmsNativeImportExecutorDependencies&&) noexcept = default;

private:
    NdmsNativeImportExecutorDependencies(
        NdmsNativeImportWalPublisher* wal,
        NdmsNativeImportSnapshotPublisher* snapshots,
        NdmsNativeImportGenerationCoordinator* generations,
        NdmsNativeLoopbackRciPostBackend* transport,
        NdmsNativeImportExecutorClock* clock) noexcept;

    NdmsNativeImportWalPublisher* wal_{nullptr};
    NdmsNativeImportSnapshotPublisher* snapshots_{nullptr};
    NdmsNativeImportGenerationCoordinator* generations_{nullptr};
    NdmsNativeLoopbackRciPostBackend* transport_{nullptr};
    NdmsNativeImportExecutorClock* clock_{nullptr};

    // The production issuer remains one dormant, import-only coordinator;
    // there is no public dependency factory and no API/daemon wiring here.
    friend class NdmsNativeCooperativeImportCoordinator;
#ifdef KEEN_PBR3_TESTING
    friend class NdmsNativeImportExecutorTestIssuer;
#endif
    friend NdmsNativeImportExecutionResult
    execute_ndms_native_import_transaction(
        NdmsNativePreparedImport,
        const NdmsNativeImportExecutionPlan&,
        const NdmsNativeImportBaselineEvidence&,
        std::optional<NdmsNativeAllocatorFenceReceipt>,
        const NdmsNativeImportExecutorDependencies&);
    friend NdmsNativeImportExecutionResult
    execute_ndms_native_import_transaction(
        NdmsNativePreparedImport,
        const NdmsNativeImportExecutionPlan&,
        const NdmsNativeImportBaselineEvidence&,
        std::optional<NdmsNativeAllocatorFenceReceipt>,
        std::optional<NdmsNativeCooperativeImportWriter>,
        const NdmsNativeImportExecutorDependencies&);
};

#ifdef KEEN_PBR3_TESTING
class NdmsNativeImportExecutorTestIssuer final {
public:
    static NdmsNativeImportExecutorDependencies issue(
        NdmsNativeImportWalPublisher* wal,
        NdmsNativeImportSnapshotPublisher* snapshots,
        NdmsNativeImportGenerationCoordinator* generations,
        NdmsNativeLoopbackRciPostBackend* transport,
        NdmsNativeImportExecutorClock* clock) noexcept;
};
#endif

enum class NdmsNativeImportExecutionStatus : std::uint8_t {
    blocked,
    recovery_required,
    response_recorded_needs_verification,
};

enum class NdmsNativeImportExecutionStop : std::uint8_t {
    none,
    missing_dependency,
    request_identity_invalid,
    snapshot_identity_invalid,
    observation_binding_invalid,
    expected_target_ineligible,
    baseline_mismatch,
    incompatible_fence_mode,
    fence_required,
    authority_conflict,
    cooperative_writer_required,
    cooperative_writer_invalid,
    cooperative_writer_lost,
    cooperative_observation_changed,
    request_binding_failed,
    generation_observation_failed,
    fence_invalid,
    unfinished_transaction_present,
    prepared_wal_publish_failed,
    snapshot_publish_failed,
    generation_reservation_failed,
    generation_changed,
    inflight_wal_publish_failed,
    fence_lost_after_intent,
    transport_failed,
    response_wal_publish_failed,
    ambiguous_response,
};

struct NdmsNativeImportExecutionResult final {
    NdmsNativeImportExecutionStatus status{
        NdmsNativeImportExecutionStatus::blocked};
    NdmsNativeImportExecutionStop stop{
        NdmsNativeImportExecutionStop::none};
    NdmsNativeAllocatorFenceValidationError fence_error{
        NdmsNativeAllocatorFenceValidationError::none};
    bool prepared_wal_published{false};
    bool snapshot_published{false};
    bool inflight_wal_published{false};
    bool response_wal_published{false};
    // True only once the fixed backend boundary is known to have been
    // entered. This does not imply that curl_easy_perform() started.
    bool backend_call_confirmed{false};
    // True only at the final irreversible perform boundary.
    bool dispatch_perform_started{false};
    bool request_may_have_been_dispatched{false};
    std::optional<NdmsNativeImportResponseManifestV3> response_manifest;
    NdmsNativeImportRecoveryAction recovery_action{
        NdmsNativeImportRecoveryAction::block_unknown};
};

// Binds one non-secret request identity, its request-derived candidate
// revision and the exact pre-dispatch target into the allocator receipt.
// Binary field tags plus fixed-width lengths make the encoding unambiguous.
std::string ndms_native_import_request_binding_digest(
    const NdmsNativeWireguardImportRequest& request,
    const std::string& expected_created_interface);

// Executes the create-only stock import boundary. There is no delete,
// ownership publish, API registration, retry or recovery mutation here.
//
// WG and AWG share the measured stock empty-name import operation. Their kind
// remains bound through the request digest, WAL, response manifest and future
// ownership publication. A receipt is intentionally consumed through a
// move-only optional: production code cannot construct or replay one, and the
// measured KeeneticOS 5.1.1 provider always returns nullopt. Consequently this
// function cannot reach transport on that firmware.
NdmsNativeImportExecutionResult execute_ndms_native_import_transaction(
    NdmsNativePreparedImport prepared,
    const NdmsNativeImportExecutionPlan& plan,
    const NdmsNativeImportBaselineEvidence& baseline,
    std::optional<NdmsNativeAllocatorFenceReceipt> receipt,
    const NdmsNativeImportExecutorDependencies& dependencies);

NdmsNativeImportExecutionResult execute_ndms_native_import_transaction(
    NdmsNativePreparedImport prepared,
    const NdmsNativeImportExecutionPlan& plan,
    const NdmsNativeImportBaselineEvidence& baseline,
    std::optional<NdmsNativeAllocatorFenceReceipt> receipt,
    std::optional<NdmsNativeCooperativeImportWriter> cooperative_writer,
    const NdmsNativeImportExecutorDependencies& dependencies);

const char* ndms_native_import_execution_status_name(
    NdmsNativeImportExecutionStatus status) noexcept;
const char* ndms_native_cooperative_import_admission_state_name(
    NdmsNativeCooperativeImportAdmissionState state) noexcept;
const char* ndms_native_import_execution_stop_name(
    NdmsNativeImportExecutionStop stop) noexcept;

} // namespace keen_pbr3
