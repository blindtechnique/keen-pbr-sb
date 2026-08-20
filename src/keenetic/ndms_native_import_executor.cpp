#include "ndms_native_import_executor.hpp"

#include "ndms_native_create_policy.hpp"
#include "ndms_native_import_identity.hpp"

#include "../crypto/sha256.hpp"

#include <chrono>
#include <limits>
#include <string_view>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr const char* kResponseManifestDigestPrefix =
    "ndms-import-response-manifest-v3-";
bool compatible_empty_name_fence_mode(
    const NdmsNativeAllocatorFenceMode mode) noexcept {
    return mode == NdmsNativeAllocatorFenceMode::bounded_atomic_import ||
           mode == NdmsNativeAllocatorFenceMode::global_ndms_writer_lease;
}

NdmsNativeAllocatorFenceExpectation fence_expectation(
    const NdmsNativeImportExecutionPlan& plan,
    const std::string& request_binding_digest,
    const NdmsNativeImportGenerationSnapshot& generation,
    const NdmsNativeAllocatorMonotonicTime now) {
    NdmsNativeAllocatorFenceExpectation expectation;
    expectation.mode = plan.fence_mode;
    expectation.range = ndms_native_allocator_required_range();
    expectation.firmware_identity = plan.firmware_identity;
    expectation.implementation_digest =
        plan.allocator_implementation_digest;
    expectation.request_binding_digest = request_binding_digest;
    expectation.generation_ticket = plan.generation_ticket;
    expectation.exact_target = plan.expected_created_interface;
    expectation.current_generation = generation.allocator_generation;
    expectation.now = now;
    expectation.minimum_remaining =
        kNdmsNativeImportRequiredDispatchWindow;
    return expectation;
}

bool request_identity_is_valid(
    const NdmsNativeWireguardImportRequest& request) noexcept {
    return request.operation() == "interface.wireguard.import" &&
           request.has_pending_secret_body() &&
           valid_ndms_native_import_transaction_id(
               request.transaction_id()) &&
           valid_ndms_native_import_marker(
               request.marker(), request.transaction_id());
}

bool exactly_next_generation(
    const std::uint32_t base,
    const std::optional<std::uint32_t>& reserved) noexcept {
    return reserved.has_value() &&
           base != std::numeric_limits<std::uint32_t>::max() &&
           *reserved == base + 1U;
}

void validate_wal_record(const NdmsNativeImportWalRecord& record) {
    // The codec is the canonical schema validator. No serialized bytes are
    // retained or handed to transport; all fields are non-secret.
    static_cast<void>(serialize_ndms_native_import_wal(record));
}

std::string response_manifest_digest(
    const NdmsNativeImportResponseManifestV3& manifest) {
    return std::string{kResponseManifestDigestPrefix} +
           Sha256::hex(
               serialize_ndms_native_import_response_manifest_v3(
                   manifest));
}

NdmsNativeImportExecutionResult blocked(
    const NdmsNativeImportExecutionStop stop) noexcept {
    NdmsNativeImportExecutionResult result;
    result.stop = stop;
    return result;
}

NdmsNativeImportExecutionResult recovery_required(
    const NdmsNativeImportExecutionStop stop,
    const NdmsNativeImportWalRecord& record,
    NdmsNativeImportExecutionResult result = {}) noexcept {
    result.status = NdmsNativeImportExecutionStatus::recovery_required;
    result.stop = stop;
    result.recovery_action = classify_ndms_native_import_recovery(
        record, NdmsNativeImportRecoveryObservation{});
    return result;
}

bool publish_wal(
    NdmsNativeImportWalPublisher& publisher,
    const NdmsNativeImportWalRecord& record) {
    validate_wal_record(record);
    publisher.publish(record);
    return true;
}

class ExecutorPreDispatchGuard final
    : public NdmsNativeImportPreDispatchGuard {
public:
    ExecutorPreDispatchGuard(
        NdmsNativeAllocatorFenceExpectation& expectation,
        const NdmsNativeAllocatorFenceReceipt& receipt,
        NdmsNativeImportGenerationCoordinator& generations,
        NdmsNativeImportExecutorClock& clock,
        const std::uint32_t reserved_generation) noexcept
        : expectation_(expectation),
          receipt_(receipt),
          generations_(generations),
          clock_(clock),
          reserved_generation_(reserved_generation) {}

    bool authorize_dispatch() noexcept override {
        try {
            const auto generation = generations_.observe();
            if (generation.maintenance_generation !=
                reserved_generation_) {
                stop_ = NdmsNativeImportExecutionStop::generation_changed;
                return false;
            }
            expectation_.current_generation =
                generation.allocator_generation;
            expectation_.now = clock_.now();
            const auto validation =
                validate_ndms_native_allocator_fence(
                    receipt_, expectation_);
            fence_error_ = validation.error;
            if (!validation.authorizes()) {
                stop_ = NdmsNativeImportExecutionStop::
                    fence_lost_after_intent;
                return false;
            }
            return true;
        } catch (...) {
            stop_ = NdmsNativeImportExecutionStop::
                generation_observation_failed;
            return false;
        }
    }

    NdmsNativeImportExecutionStop stop() const noexcept {
        return stop_;
    }

    NdmsNativeAllocatorFenceValidationError fence_error() const noexcept {
        return fence_error_;
    }

private:
    NdmsNativeAllocatorFenceExpectation& expectation_;
    const NdmsNativeAllocatorFenceReceipt& receipt_;
    NdmsNativeImportGenerationCoordinator& generations_;
    NdmsNativeImportExecutorClock& clock_;
    std::uint32_t reserved_generation_{0U};
    NdmsNativeImportExecutionStop stop_{
        NdmsNativeImportExecutionStop::fence_lost_after_intent};
    NdmsNativeAllocatorFenceValidationError fence_error_{
        NdmsNativeAllocatorFenceValidationError::none};
};

} // namespace

NdmsNativeAllocatorMonotonicTime
NdmsNativeImportSteadyClock::now() const noexcept {
    return NdmsNativeAllocatorMonotonicClock::now();
}

NdmsNativeImportExecutorDependencies::
NdmsNativeImportExecutorDependencies(
    NdmsNativeImportWalPublisher* wal,
    NdmsNativeImportSnapshotPublisher* snapshots,
    NdmsNativeImportGenerationCoordinator* generations,
    NdmsNativeLoopbackRciPostBackend* transport,
    NdmsNativeImportExecutorClock* clock) noexcept
    : wal_(wal),
      snapshots_(snapshots),
      generations_(generations),
      transport_(transport),
      clock_(clock) {}

#ifdef KEEN_PBR3_TESTING
NdmsNativeImportExecutorDependencies
NdmsNativeImportExecutorTestIssuer::issue(
    NdmsNativeImportWalPublisher* wal,
    NdmsNativeImportSnapshotPublisher* snapshots,
    NdmsNativeImportGenerationCoordinator* generations,
    NdmsNativeLoopbackRciPostBackend* transport,
    NdmsNativeImportExecutorClock* clock) noexcept {
    return NdmsNativeImportExecutorDependencies{
        wal, snapshots, generations, transport, clock};
}
#endif

NdmsNativeImportWalStorePublisher::NdmsNativeImportWalStorePublisher(
    NdmsNativeImportWalStore& store) noexcept
    : store_(store) {}

void NdmsNativeImportWalStorePublisher::publish(
    const NdmsNativeImportWalRecord& record) {
    store_.publish(record);
}

NdmsNativeImportWalAdmissionState
NdmsNativeImportWalStorePublisher::begin_prepared_exclusive(
    const NdmsNativeImportWalRecord& record) {
    return store_.publish_prepared_exclusive(record);
}

std::string ndms_native_import_request_binding_digest(
    const NdmsNativeWireguardImportRequest& request,
    const std::string& expected_created_interface) {
    return ndms_native_import_request_binding_digest(
        request.transaction_id(),
        request.marker(),
        request.candidate_revision(),
        request.kind(),
        expected_created_interface);
}

NdmsNativeImportExecutionResult execute_ndms_native_import_transaction(
    NdmsNativePreparedImport prepared,
    const NdmsNativeImportExecutionPlan& plan,
    const NdmsNativeImportBaselineEvidence& baseline,
    std::optional<NdmsNativeAllocatorFenceReceipt> receipt,
    const NdmsNativeImportExecutorDependencies& dependencies) {
    if (dependencies.wal_ == nullptr ||
        dependencies.snapshots_ == nullptr ||
        dependencies.generations_ == nullptr ||
        dependencies.transport_ == nullptr ||
        dependencies.clock_ == nullptr) {
        return blocked(
            NdmsNativeImportExecutionStop::missing_dependency);
    }
    const auto& prepared_request = prepared.request_identity();
    const auto& prepared_snapshot = prepared.delete_snapshot_metadata();
    if (!request_identity_is_valid(prepared_request)) {
        return blocked(
            NdmsNativeImportExecutionStop::request_identity_invalid);
    }
    if (prepared_snapshot.sealed_payload_bytes() == 0U ||
        prepared_snapshot.kind() != prepared_request.kind() ||
        prepared_snapshot.marker() != prepared_request.marker() ||
        prepared_snapshot.canonical_revision() !=
            prepared_request.candidate_revision()) {
        return blocked(
            NdmsNativeImportExecutionStop::snapshot_identity_invalid);
    }
    auto request = prepared.take_request();
    auto snapshot = prepared.take_delete_snapshot();
    if (!valid_ndms_native_observation_binding(
            plan.observation_binding)) {
        return blocked(
            NdmsNativeImportExecutionStop::observation_binding_invalid);
    }
    if (!ndms_native_created_target_is_eligible(
            plan.expected_created_interface)) {
        return blocked(
            NdmsNativeImportExecutionStop::expected_target_ineligible);
    }
    NdmsNativeImportPersistedBaseline persisted_baseline;
    try {
        persisted_baseline =
            persist_ndms_native_import_baseline(baseline);
    } catch (...) {
        return blocked(
            NdmsNativeImportExecutionStop::baseline_mismatch);
    }
    if (!valid_ndms_native_import_persisted_baseline(
            persisted_baseline) ||
        persisted_baseline.expected_created_interface !=
            plan.expected_created_interface) {
        return blocked(
            NdmsNativeImportExecutionStop::baseline_mismatch);
    }
    if (!compatible_empty_name_fence_mode(plan.fence_mode)) {
        return blocked(
            NdmsNativeImportExecutionStop::incompatible_fence_mode);
    }
    if (!receipt.has_value()) {
        return blocked(NdmsNativeImportExecutionStop::fence_required);
    }

    std::string request_binding_digest;
    try {
        request_binding_digest =
            ndms_native_import_request_binding_digest(
                request, plan.expected_created_interface);
    } catch (...) {
        return blocked(
            NdmsNativeImportExecutionStop::request_binding_failed);
    }

    NdmsNativeImportGenerationSnapshot initial_generation;
    try {
        initial_generation = dependencies.generations_->observe();
    } catch (...) {
        return blocked(
            NdmsNativeImportExecutionStop::generation_observation_failed);
    }
    if (persisted_baseline.maintenance_base_generation !=
            initial_generation.maintenance_generation ||
        persisted_baseline.allocator_generation !=
            initial_generation.allocator_generation) {
        return blocked(
            NdmsNativeImportExecutionStop::baseline_mismatch);
    }

    NdmsNativeAllocatorFenceExpectation expectation;
    try {
        expectation = fence_expectation(
            plan,
            request_binding_digest,
            initial_generation,
            dependencies.clock_->now());
    } catch (...) {
        return blocked(
            NdmsNativeImportExecutionStop::request_binding_failed);
    }
    auto validation = validate_ndms_native_allocator_fence(
        *receipt, expectation);
    if (!validation.authorizes()) {
        auto result = blocked(
            NdmsNativeImportExecutionStop::fence_invalid);
        result.fence_error = validation.error;
        return result;
    }

    NdmsNativeImportWalRecord record;
    record.transaction_id = std::string(request.transaction_id());
    record.phase = NdmsNativeImportWalPhase::prepared;
    record.kind = request.kind();
    record.marker = std::string(request.marker());
    record.candidate_revision =
        std::string(request.candidate_revision());
    record.request_binding_sha256 = request_binding_digest;
    record.generation_ticket = plan.generation_ticket;
    record.maintenance_base_generation =
        initial_generation.maintenance_generation;
    record.observation_binding = plan.observation_binding;
    record.baseline = std::move(persisted_baseline);
    record.snapshot_revision =
        std::string(request.candidate_revision());

    NdmsNativeImportExecutionResult result;
    try {
        validate_wal_record(record);
        const auto admission =
            dependencies.wal_->begin_prepared_exclusive(record);
        if (admission == NdmsNativeImportWalAdmissionState::
                unfinished_transaction_present) {
            result.status =
                NdmsNativeImportExecutionStatus::recovery_required;
            result.stop = NdmsNativeImportExecutionStop::
                unfinished_transaction_present;
            result.recovery_action = NdmsNativeImportRecoveryAction::
                retry_read_only_observation;
            return result;
        }
        result.prepared_wal_published = true;
    } catch (...) {
        // A publisher may throw after rename but before directory fsync. The
        // request is not dispatched, yet recovery must inventory a record
        // that may already be visible before any later transaction proceeds.
        return recovery_required(
            NdmsNativeImportExecutionStop::prepared_wal_publish_failed,
            record,
            std::move(result));
    }

    try {
        dependencies.snapshots_->publish(
            plan.expected_created_interface,
            record.transaction_id,
            record.marker,
            std::move(snapshot));
        result.snapshot_published = true;
    } catch (...) {
        // prepared is already durable and transport has not been entered.
        // The publisher may have made the snapshot visible before throwing;
        // recovery therefore performs an exact idempotent retirement before
        // it may remove this WAL record.
        return recovery_required(
            NdmsNativeImportExecutionStop::snapshot_publish_failed,
            record,
            std::move(result));
    }

    std::optional<std::uint32_t> reserved;
    try {
        reserved = dependencies.generations_->reserve_next(
            record.transaction_id,
            record.generation_ticket,
            record.maintenance_base_generation);
    } catch (...) {
        return recovery_required(
            NdmsNativeImportExecutionStop::generation_reservation_failed,
            record,
            std::move(result));
    }
    if (!exactly_next_generation(
            record.maintenance_base_generation, reserved)) {
        return recovery_required(
            NdmsNativeImportExecutionStop::generation_reservation_failed,
            record,
            std::move(result));
    }

    NdmsNativeImportGenerationSnapshot reserved_generation;
    try {
        reserved_generation = dependencies.generations_->observe();
    } catch (...) {
        return recovery_required(
            NdmsNativeImportExecutionStop::generation_observation_failed,
            record,
            std::move(result));
    }
    if (reserved_generation.maintenance_generation != *reserved) {
        return recovery_required(
            NdmsNativeImportExecutionStop::generation_changed,
            record,
            std::move(result));
    }
    expectation.current_generation =
        reserved_generation.allocator_generation;
    expectation.now = dependencies.clock_->now();
    validation = validate_ndms_native_allocator_fence(
        *receipt, expectation);
    if (!validation.authorizes()) {
        result.fence_error = validation.error;
        return recovery_required(
            NdmsNativeImportExecutionStop::fence_invalid,
            record,
            std::move(result));
    }

    record.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    record.reserved_generation = reserved;
    try {
        publish_wal(*dependencies.wal_, record);
        result.inflight_wal_published = true;
    } catch (...) {
        return recovery_required(
            NdmsNativeImportExecutionStop::inflight_wal_publish_failed,
            record,
            std::move(result));
    }

    NdmsNativeImportGenerationSnapshot dispatch_generation;
    try {
        dispatch_generation = dependencies.generations_->observe();
    } catch (...) {
        return recovery_required(
            NdmsNativeImportExecutionStop::generation_observation_failed,
            record,
            std::move(result));
    }
    if (dispatch_generation.maintenance_generation != *reserved) {
        return recovery_required(
            NdmsNativeImportExecutionStop::generation_changed,
            record,
            std::move(result));
    }
    expectation.current_generation =
        dispatch_generation.allocator_generation;
    expectation.now = dependencies.clock_->now();
    validation = validate_ndms_native_allocator_fence(
        *receipt, expectation);
    if (!validation.authorizes()) {
        result.fence_error = validation.error;
        return recovery_required(
            NdmsNativeImportExecutionStop::fence_lost_after_intent,
            record,
            std::move(result));
    }

    NdmsNativeImportTransportResult transport_result;
    ExecutorPreDispatchGuard pre_dispatch_guard{
        expectation,
        *receipt,
        *dependencies.generations_,
        *dependencies.clock_,
        *reserved};
    try {
        auto capability = NdmsNativeImportDispatchCapability{
            NdmsNativeImportDispatchCapability::ConstructionKey{}};
        transport_result = post_ndms_native_import_once(
            std::move(capability),
            std::move(request),
            plan.expected_created_interface,
            pre_dispatch_guard,
            *dependencies.transport_);
    } catch (...) {
        // The helper collapses every exception from backend entry onward
        // into a transport result. Therefore an exception escaping it is
        // proven pre-backend: the durable inflight WAL still requires
        // recovery, but no network perform has started.
        result.backend_call_confirmed = false;
        result.dispatch_perform_started = false;
        result.request_may_have_been_dispatched = false;
        return recovery_required(
            NdmsNativeImportExecutionStop::transport_failed,
            record,
            std::move(result));
    }

    result.backend_call_confirmed =
        transport_result.backend_call_confirmed;
    result.dispatch_perform_started =
        transport_result.perform_started;

    if (!transport_result.pre_dispatch_guard_evaluated) {
        result.request_may_have_been_dispatched =
            transport_result.request_may_have_been_dispatched;
        try {
            result.response_manifest = transport_result.response_manifest;
        } catch (...) {
            return recovery_required(
                NdmsNativeImportExecutionStop::transport_failed,
                record,
                std::move(result));
        }
        return recovery_required(
            NdmsNativeImportExecutionStop::transport_failed,
            record,
            std::move(result));
    }

    if (!transport_result.pre_dispatch_guard_passed) {
        result.request_may_have_been_dispatched = false;
        result.fence_error = pre_dispatch_guard.fence_error();
        try {
            result.response_manifest = transport_result.response_manifest;
        } catch (...) {
            return recovery_required(
                pre_dispatch_guard.stop(),
                record,
                std::move(result));
        }
        return recovery_required(
            pre_dispatch_guard.stop(),
            record,
            std::move(result));
    }

    result.request_may_have_been_dispatched =
        transport_result.request_may_have_been_dispatched;
    try {
        result.response_manifest = transport_result.response_manifest;
        const auto manifest_digest =
            response_manifest_digest(transport_result.response_manifest);
        auto response_record = record;
        response_record.phase =
            NdmsNativeImportWalPhase::response_recorded;
        response_record.response_manifest_sha256 = manifest_digest;
        if (transport_result.response_manifest.success()) {
            response_record.created_interface =
                plan.expected_created_interface;
        }
        publish_wal(*dependencies.wal_, response_record);
        record = std::move(response_record);
        result.response_wal_published = true;
    } catch (...) {
        // From transport entry onward the request is irrevocably single-use.
        // The already durable inflight record is sufficient for read-only
        // recovery even when allocating or hashing redacted evidence fails.
        return recovery_required(
            NdmsNativeImportExecutionStop::response_wal_publish_failed,
            record,
            std::move(result));
    }

    result.recovery_action = classify_ndms_native_import_recovery(
        record, NdmsNativeImportRecoveryObservation{});
    if (!transport_result.request_may_have_been_dispatched ||
        !transport_result.response_manifest.success()) {
        result.status = NdmsNativeImportExecutionStatus::recovery_required;
        result.stop = NdmsNativeImportExecutionStop::ambiguous_response;
        return result;
    }

    result.status = NdmsNativeImportExecutionStatus::
        response_recorded_needs_verification;
    result.stop = NdmsNativeImportExecutionStop::none;
    return result;
}

const char* ndms_native_import_execution_status_name(
    const NdmsNativeImportExecutionStatus status) noexcept {
    switch (status) {
    case NdmsNativeImportExecutionStatus::blocked:
        return "blocked";
    case NdmsNativeImportExecutionStatus::recovery_required:
        return "recovery_required";
    case NdmsNativeImportExecutionStatus::
            response_recorded_needs_verification:
        return "response_recorded_needs_verification";
    }
    return "blocked";
}

const char* ndms_native_import_execution_stop_name(
    const NdmsNativeImportExecutionStop stop) noexcept {
    switch (stop) {
    case NdmsNativeImportExecutionStop::none:
        return "none";
    case NdmsNativeImportExecutionStop::missing_dependency:
        return "missing_dependency";
    case NdmsNativeImportExecutionStop::request_identity_invalid:
        return "request_identity_invalid";
    case NdmsNativeImportExecutionStop::snapshot_identity_invalid:
        return "snapshot_identity_invalid";
    case NdmsNativeImportExecutionStop::observation_binding_invalid:
        return "observation_binding_invalid";
    case NdmsNativeImportExecutionStop::expected_target_ineligible:
        return "expected_target_ineligible";
    case NdmsNativeImportExecutionStop::baseline_mismatch:
        return "baseline_mismatch";
    case NdmsNativeImportExecutionStop::incompatible_fence_mode:
        return "incompatible_fence_mode";
    case NdmsNativeImportExecutionStop::fence_required:
        return "fence_required";
    case NdmsNativeImportExecutionStop::request_binding_failed:
        return "request_binding_failed";
    case NdmsNativeImportExecutionStop::generation_observation_failed:
        return "generation_observation_failed";
    case NdmsNativeImportExecutionStop::fence_invalid:
        return "fence_invalid";
    case NdmsNativeImportExecutionStop::unfinished_transaction_present:
        return "unfinished_transaction_present";
    case NdmsNativeImportExecutionStop::prepared_wal_publish_failed:
        return "prepared_wal_publish_failed";
    case NdmsNativeImportExecutionStop::snapshot_publish_failed:
        return "snapshot_publish_failed";
    case NdmsNativeImportExecutionStop::generation_reservation_failed:
        return "generation_reservation_failed";
    case NdmsNativeImportExecutionStop::generation_changed:
        return "generation_changed";
    case NdmsNativeImportExecutionStop::inflight_wal_publish_failed:
        return "inflight_wal_publish_failed";
    case NdmsNativeImportExecutionStop::fence_lost_after_intent:
        return "fence_lost_after_intent";
    case NdmsNativeImportExecutionStop::transport_failed:
        return "transport_failed";
    case NdmsNativeImportExecutionStop::response_wal_publish_failed:
        return "response_wal_publish_failed";
    case NdmsNativeImportExecutionStop::ambiguous_response:
        return "ambiguous_response";
    }
    return "none";
}

} // namespace keen_pbr3
