#include "ndms_native_cooperative_delete.hpp"

#include "ndms_native_create_policy.hpp"
#include "ndms_native_import_identity.hpp"
#include "ndms_native_import_readiness.hpp"
#include "ndms_wireguard_identity.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <string_view>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {
namespace {

bool known_dependency_kind(
    const NdmsNativeKeenPbrDependencyKind kind) noexcept {
    return kind == NdmsNativeKeenPbrDependencyKind::interface_outbound ||
           kind == NdmsNativeKeenPbrDependencyKind::internal_vpn_policy ||
           kind == NdmsNativeKeenPbrDependencyKind::
                       inbound_interface_policy ||
           kind == NdmsNativeKeenPbrDependencyKind::
                       native_interface_preference;
}

bool exact_owned_label(
    const std::string_view label,
    const std::string_view marker) noexcept {
    if (label == marker) return true;
    constexpr std::string_view separator{" · "};
    return label.size() > separator.size() + marker.size() &&
           label.substr(label.size() - marker.size()) == marker &&
           label.substr(
               label.size() - marker.size() - separator.size(),
               separator.size()) == separator;
}

bool lower_hex(const std::string_view value) noexcept {
    return value.size() == 64U &&
           std::all_of(value.begin(), value.end(), [](const char digit) {
               return (digit >= '0' && digit <= '9') ||
                      (digit >= 'a' && digit <= 'f');
           });
}

bool valid_active_ownership_revision(
    const std::string_view value) noexcept {
    for (const std::string_view prefix : {
             std::string_view{"ndms-native-owner-v2-"},
             std::string_view{"ndms-native-owner-v3-"}}) {
        if (value.size() == prefix.size() + 64U &&
            value.substr(0U, prefix.size()) == prefix &&
            lower_hex(value.substr(prefix.size()))) {
            return true;
        }
    }
    return false;
}

const char* dependency_kind_name(
    const NdmsNativeKeenPbrDependencyKind kind) {
    switch (kind) {
    case NdmsNativeKeenPbrDependencyKind::interface_outbound:
        return "interface_outbound";
    case NdmsNativeKeenPbrDependencyKind::internal_vpn_policy:
        return "internal_vpn_policy";
    case NdmsNativeKeenPbrDependencyKind::inbound_interface_policy:
        return "inbound_interface_policy";
    case NdmsNativeKeenPbrDependencyKind::native_interface_preference:
        return "native_interface_preference";
    }
    throw std::invalid_argument("native dependency kind is invalid");
}

void update_field(Sha256& hasher, const std::string_view value) {
    const auto size = static_cast<std::uint64_t>(value.size());
    std::array<unsigned char, 8U> length{};
    for (std::size_t index = 0U; index < length.size(); ++index) {
        length[index] = static_cast<unsigned char>(
            size >> (56U - index * 8U));
    }
    hasher.update(
        reinterpret_cast<const char*>(length.data()), length.size());
    hasher.update(value.data(), value.size());
}

bool dependency_observation_valid(
    const NdmsNativeKeenPbrDependencyObservation& observation,
    const std::string& expected_firmware,
    const std::optional<std::string>& expected_kernel) noexcept {
    try {
        if (!observation.complete ||
            observation.scope != NdmsNativeKeenPbrDependencyScope::
                config_and_runtime_interface_references ||
            observation.firmware_interface_name != expected_firmware ||
            observation.kernel_interface_name != expected_kernel ||
            !std::all_of(
                observation.references.begin(),
                observation.references.end(),
                [](const auto& reference) {
                    return known_dependency_kind(reference.kind) &&
                           !reference.dependent_id.empty() &&
                           reference.dependent_id.size() <= 256U;
                })) {
            return false;
        }
        return observation.keen_pbr_dependency_revision ==
               ndms_native_keen_pbr_dependency_revision(observation);
    } catch (...) {
        return false;
    }
}

std::optional<std::string> usable_empty_dependency_revision(
    const NdmsNativeKeenPbrDependencyObservation& observation,
    const std::string& expected_firmware,
    const std::optional<std::string>& expected_kernel) noexcept {
    if (!observation.references.empty()) return std::nullopt;
    if (dependency_observation_valid(
            observation, expected_firmware, expected_kernel)) {
        return observation.keen_pbr_dependency_revision;
    }

    // The panel removes and applies its exact interface outbound before this
    // coordinator runs. If the narrow dependency projection is unavailable
    // but did not report a concrete reference, do not turn that diagnostic
    // failure into a permanent inability to delete a panel-owned tunnel.
    // All ownership, snapshot, dual-scope NDMS and writer checks below remain
    // mandatory. Any actually reported reference still blocks deletion.
    try {
        NdmsNativeKeenPbrDependencyObservation empty;
        empty.complete = true;
        empty.firmware_interface_name = expected_firmware;
        empty.kernel_interface_name = expected_kernel;
        empty.keen_pbr_dependency_revision =
            ndms_native_keen_pbr_dependency_revision(empty);
        return empty.keen_pbr_dependency_revision;
    } catch (...) {
        return std::nullopt;
    }
}

class DirectObservationAdapter final
    : public NdmsNativeCooperativeDeleteObservationGateway {
public:
    NdmsNativeDirectRecoveryObservation observe_recovery(
        const NdmsNativeDirectCatalogScope scope,
        const std::string& marker,
        const std::optional<std::string>& expected_target) noexcept override {
        return gateway_.observe_recovery(scope, marker, expected_target);
    }

private:
    NdmsNativeDirectObservationGateway gateway_;
};

std::string random_transaction_id() {
    std::array<unsigned char, 16U> bytes{};
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open("/dev/urandom", flags);
    if (descriptor < 0) {
        throw std::runtime_error(
            "cannot open random source for native delete transaction");
    }
    std::size_t offset = 0U;
    while (offset < bytes.size()) {
        const auto count = ::read(
            descriptor, bytes.data() + offset, bytes.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            (void)::close(descriptor);
            throw std::runtime_error(
                "cannot read native delete transaction id");
        }
        if (count == 0) {
            (void)::close(descriptor);
            throw std::runtime_error(
                "random source ended during native delete transaction id");
        }
        offset += static_cast<std::size_t>(count);
    }
    if (::close(descriptor) != 0) {
        throw std::runtime_error(
            "cannot close native delete random source");
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string value;
    value.reserve(bytes.size() * 2U);
    for (const auto byte : bytes) {
        value.push_back(hex[(byte >> 4U) & 0x0fU]);
        value.push_back(hex[byte & 0x0fU]);
    }
    return value;
}

enum class ExpectedPresence { present, absent, either };
enum class MeasuredPresence { present, absent, mismatch, failed };

struct ObservationMatch final {
    MeasuredPresence presence{MeasuredPresence::failed};
    std::optional<std::string> kernel_name;
    NdmsNativeDirectObservationFailure failure{
        NdmsNativeDirectObservationFailure::none};
    bool scope_mismatch{false};
};

bool direct_snapshot_shape(
    const NdmsCatalogSnapshot& snapshot) noexcept {
    return snapshot.status == NdmsCatalogCacheStatus::fresh &&
           snapshot.refreshed && snapshot.catalog.firmware_available &&
           snapshot.observation_generation == 0U &&
           snapshot.observation_epoch == 0U &&
           snapshot.invalidation_epoch == 0U &&
           std::none_of(
               snapshot.catalog.wireguard_slots.begin(),
               snapshot.catalog.wireguard_slots.end(),
               [](const auto& slot) {
                   return slot.state ==
                       NdmsWireguardCatalogSlotState::unsafe;
               });
}

ObservationMatch inspect_observation(
    const NdmsNativeDirectRecoveryObservation& observation,
    const NdmsNativeDirectCatalogScope expected_scope,
    const NdmsNativeDeleteWalRecord& record) {
    ObservationMatch match;
    match.failure = observation.failure;
    if (observation.catalog_scope != expected_scope ||
        observation.requested_catalog_scope != expected_scope) {
        match.scope_mismatch = true;
        return match;
    }
    if (!observation.complete() || !observation.snapshot ||
        !direct_snapshot_shape(*observation.snapshot) ||
        !valid_ndms_native_observation_catalog_revision(
            observation.catalog_revision)) {
        return match;
    }
    const auto identity =
        parse_ndms_wireguard_identity(record.interface_name);
    if (!identity || identity->canonical_name() != record.interface_name ||
        !ndms_wireguard_identity_is_managed_candidate(*identity)) {
        match.presence = MeasuredPresence::mismatch;
        return match;
    }
    const auto slot_state = observation.snapshot->catalog
                                .wireguard_slots[identity->slot]
                                .state;
    std::vector<const NdmsTunnelInterface*> marker_sightings;
    const NdmsTunnelInterface* target = nullptr;
    for (const auto& tunnel : observation.snapshot->catalog.tunnels) {
        if (tunnel.label.find(record.marker) != std::string::npos) {
            marker_sightings.push_back(&tunnel);
        }
        if (tunnel.firmware_interface_name == record.interface_name) {
            if (target != nullptr) {
                match.presence = MeasuredPresence::mismatch;
                return match;
            }
            target = &tunnel;
        }
    }

    if (slot_state == NdmsWireguardCatalogSlotState::absent) {
        if (target != nullptr || !marker_sightings.empty() ||
            !observation.target_evidence.empty() ||
            !observation.target_protocols.empty()) {
            match.presence = MeasuredPresence::mismatch;
            return match;
        }
        match.presence = MeasuredPresence::absent;
        return match;
    }
    if (slot_state != NdmsWireguardCatalogSlotState::occupied ||
        target == nullptr || marker_sightings.size() != 1U ||
        marker_sightings.front() != target ||
        !exact_owned_label(target->label, record.marker) ||
        observation.target_evidence.size() != 1U ||
        observation.target_protocols.size() != 1U) {
        match.presence = MeasuredPresence::mismatch;
        return match;
    }
    const auto& evidence = observation.target_evidence.front();
    const auto& protocol = observation.target_protocols.front();
    const bool kind_matches =
        (record.kind == NdmsNativeTunnelImportKind::wireguard &&
         protocol.asc_class == NdmsNativeAscClass::plain_wireguard) ||
        (record.kind ==
             NdmsNativeTunnelImportKind::amnezia_wireguard &&
         protocol.asc_class == NdmsNativeAscClass::amnezia_wg);
    if (evidence.interface_name != record.interface_name ||
        protocol.interface_name != record.interface_name ||
        !kind_matches) {
        match.presence = MeasuredPresence::mismatch;
        return match;
    }
    // The target revision includes live connection state and the public
    // description. Both legitimately change after import (connect/disconnect
    // and a friendly alias), so equality with the import-time revision made a
    // panel-owned tunnel permanently undeletable. Deletion authority comes
    // from the exact managed slot, private marker, protocol kind, ownership
    // claim, encrypted snapshot and fresh dual-scope observation above.
    // An active/connected client is intentionally allowed. `link_down` is a
    // rollback-only condition and is not an ownership fact for panel delete.
    match.kernel_name = target->kernel_name;
    match.presence = MeasuredPresence::present;
    return match;
}

struct PairMeasurement final {
    MeasuredPresence presence{MeasuredPresence::failed};
    NdmsNativeDeleteObservationPair pair;
    std::optional<std::string> kernel_name;
    NdmsNativeCooperativeDeleteStop stop{
        NdmsNativeCooperativeDeleteStop::unexpected_failure};
    std::optional<NdmsNativeDirectObservationFailure> failure;
};

bool active_claim_matches_record(
    const NdmsNativeOwnershipReadResult& claim,
    const NdmsNativeDeleteWalRecord& record) noexcept {
    return claim.state == NdmsNativeOwnershipReadState::valid &&
           claim.record.has_value() && claim.revision.has_value() &&
           *claim.revision == record.ownership_revision &&
           ndms_native_ownership_is_active(*claim.record) &&
           claim.record->interface_name == record.interface_name &&
           claim.record->transaction_id ==
               record.ownership_transaction_id &&
           claim.record->marker == record.marker &&
           claim.record->kind == record.kind &&
           claim.record->snapshot_revision == record.snapshot_revision &&
           claim.record->target_full_revision ==
               record.target_full_revision;
}

NdmsNativeCooperativeDeleteStop validate_snapshot(
    NdmsNativeSecretSnapshotStore& snapshots,
    const NdmsNativeDeleteWalRecord& record) {
    auto read = snapshots.read_panel_delete_snapshot(
        record.interface_name,
        record.ownership_transaction_id,
        record.marker);
    if (read.state == NdmsNativeSecretReadState::absent) {
        return NdmsNativeCooperativeDeleteStop::snapshot_absent;
    }
    if (read.state != NdmsNativeSecretReadState::valid ||
        !read.snapshot) {
        return NdmsNativeCooperativeDeleteStop::snapshot_unreadable;
    }
    const auto& snapshot = *read.snapshot;
    if (snapshot.marker() != record.marker ||
        snapshot.kind() != record.kind ||
        snapshot.canonical_revision() != record.snapshot_revision ||
        (record.kind ==
             NdmsNativeTunnelImportKind::amnezia_wireguard &&
         !snapshot.has_complete_awg_parameters())) {
        return NdmsNativeCooperativeDeleteStop::snapshot_mismatch;
    }
    return NdmsNativeCooperativeDeleteStop::none;
}

class CallbackGuard final
    : public NdmsNativeExactMutationPreDispatchGuard {
public:
    explicit CallbackGuard(std::function<bool()> callback)
        : callback_(std::move(callback)) {}

    bool authorize_dispatch() noexcept override {
        try {
            return callback_ && callback_();
        } catch (...) {
            return false;
        }
    }

private:
    std::function<bool()> callback_;
};

} // namespace

struct NdmsNativeCooperativeDeleteCoordinator::Impl final {
    NdmsNativeObservationStore& observations;
    NdmsNativeImportWalStore& import_wal;
    NdmsNativeDeleteWalStore& delete_wal;
    NdmsNativeSecretSnapshotStore& snapshots;
    NdmsNativeOwnershipStore& ownership;
    NdmsNativeKeenPbrDependencyProvider& dependencies;
    NdmsNativeCooperativeDeleteObservationGateway* gateway{nullptr};
    NdmsNativeExactMutationBackend* backend{nullptr};
    std::unique_ptr<NdmsNativeCooperativeDeleteObservationGateway>
        owned_gateway;
    std::unique_ptr<NdmsNativeExactMutationBackend> owned_backend;
    std::function<std::string()> transaction_id_factory;

    Impl(NdmsNativeObservationStore& observations_value,
         NdmsNativeImportWalStore& import_wal_value,
         NdmsNativeDeleteWalStore& delete_wal_value,
         NdmsNativeSecretSnapshotStore& snapshots_value,
         NdmsNativeOwnershipStore& ownership_value,
         NdmsNativeKeenPbrDependencyProvider& dependencies_value)
        : observations(observations_value),
          import_wal(import_wal_value),
          delete_wal(delete_wal_value),
          snapshots(snapshots_value),
          ownership(ownership_value),
          dependencies(dependencies_value),
          owned_gateway(std::make_unique<DirectObservationAdapter>()),
          owned_backend(
              std::make_unique<NdmsNativeLibcurlExactMutationBackend>()),
          transaction_id_factory(random_transaction_id) {
        gateway = owned_gateway.get();
        backend = owned_backend.get();
    }

    Impl(NdmsNativeObservationStore& observations_value,
         NdmsNativeImportWalStore& import_wal_value,
         NdmsNativeDeleteWalStore& delete_wal_value,
         NdmsNativeSecretSnapshotStore& snapshots_value,
         NdmsNativeOwnershipStore& ownership_value,
         NdmsNativeKeenPbrDependencyProvider& dependencies_value,
         NdmsNativeCooperativeDeleteObservationGateway& gateway_value,
         NdmsNativeExactMutationBackend& backend_value,
         std::function<std::string()> transaction_id_factory_value)
        : observations(observations_value),
          import_wal(import_wal_value),
          delete_wal(delete_wal_value),
          snapshots(snapshots_value),
          ownership(ownership_value),
          dependencies(dependencies_value),
          gateway(&gateway_value),
          backend(&backend_value),
          transaction_id_factory(
              transaction_id_factory_value
                  ? std::move(transaction_id_factory_value)
                  : std::function<std::string()>{random_transaction_id}) {}
};

namespace {

template <typename ImplType>
PairMeasurement observe_pair(
    ImplType& impl,
    NdmsNativeWriterLease& writer,
    const NdmsNativeDeleteWalRecord& record,
    const ExpectedPresence expected,
    const bool baseline) {
    PairMeasurement result;
    auto runtime = impl.gateway->observe_recovery(
        NdmsNativeDirectCatalogScope::runtime_state,
        record.marker,
        record.interface_name);
    const auto runtime_match = inspect_observation(
        runtime, NdmsNativeDirectCatalogScope::runtime_state, record);
    if (runtime_match.scope_mismatch) {
        result.stop =
            NdmsNativeCooperativeDeleteStop::observation_scope_mismatch;
        return result;
    }
    if (runtime_match.presence == MeasuredPresence::failed) {
        result.stop =
            NdmsNativeCooperativeDeleteStop::runtime_observation_failed;
        result.failure = runtime_match.failure;
        return result;
    }

    auto running = impl.gateway->observe_recovery(
        NdmsNativeDirectCatalogScope::running_config,
        record.marker,
        record.interface_name);
    const auto running_match = inspect_observation(
        running, NdmsNativeDirectCatalogScope::running_config, record);
    if (running_match.scope_mismatch) {
        result.stop =
            NdmsNativeCooperativeDeleteStop::observation_scope_mismatch;
        return result;
    }
    if (running_match.presence == MeasuredPresence::failed) {
        result.stop = NdmsNativeCooperativeDeleteStop::
            running_config_observation_failed;
        result.failure = running_match.failure;
        return result;
    }
    if (runtime_match.presence != running_match.presence) {
        result.stop = NdmsNativeCooperativeDeleteStop::observed_target_drifted;
        result.presence = MeasuredPresence::mismatch;
        return result;
    }
    if (runtime_match.presence == MeasuredPresence::mismatch) {
        result.stop = NdmsNativeCooperativeDeleteStop::observed_target_mismatch;
        result.presence = MeasuredPresence::mismatch;
        return result;
    }
    if ((expected == ExpectedPresence::present &&
         runtime_match.presence != MeasuredPresence::present) ||
        (expected == ExpectedPresence::absent &&
         runtime_match.presence != MeasuredPresence::absent)) {
        result.stop = NdmsNativeCooperativeDeleteStop::observed_target_drifted;
        result.presence = MeasuredPresence::mismatch;
        return result;
    }
    if (runtime_match.presence == MeasuredPresence::present &&
        runtime_match.kernel_name && running_match.kernel_name &&
        runtime_match.kernel_name != running_match.kernel_name) {
        result.stop = NdmsNativeCooperativeDeleteStop::observed_target_drifted;
        result.presence = MeasuredPresence::mismatch;
        return result;
    }

    try {
        NdmsNativeObservationStamp runtime_stamp;
        NdmsNativeObservationStamp running_stamp;
        if (baseline) {
            runtime_stamp = impl.observations.record_observation(
                writer, runtime.catalog_revision);
            running_stamp = impl.observations.record_observation(
                writer, running.catalog_revision);
        } else {
            runtime_stamp = impl.observations.record_recovery_observation(
                writer,
                record.observation_binding,
                runtime.catalog_revision);
            running_stamp = impl.observations.record_recovery_observation(
                writer,
                record.observation_binding,
                running.catalog_revision);
        }
        if (runtime_stamp.authority_id != running_stamp.authority_id ||
            runtime_stamp.mutation_epoch != running_stamp.mutation_epoch ||
            running_stamp.sequence <= runtime_stamp.sequence) {
            result.stop = NdmsNativeCooperativeDeleteStop::
                durable_observation_failed;
            return result;
        }
        result.pair = {
            runtime.catalog_revision,
            runtime_stamp.sequence,
            running.catalog_revision,
            running_stamp.sequence,
        };
        result.kernel_name = runtime_match.kernel_name
            ? runtime_match.kernel_name
            : running_match.kernel_name;
        result.presence = runtime_match.presence;
        result.stop = NdmsNativeCooperativeDeleteStop::none;
        return result;
    } catch (...) {
        try {
            writer.verify_held();
            result.stop = NdmsNativeCooperativeDeleteStop::
                durable_observation_failed;
        } catch (...) {
            result.stop = NdmsNativeCooperativeDeleteStop::writer_lost;
        }
        return result;
    }
}

template <typename ImplType>
NdmsNativeCooperativeDeleteStop validate_dependencies(
    ImplType& impl,
    const NdmsNativeDeleteWalRecord& record,
    const std::optional<std::string>& kernel_name,
    const bool require_same_revision) {
    const auto observed = impl.dependencies.observe_dependencies(
        record.interface_name, kernel_name);
    if (!observed.references.empty()) {
        return NdmsNativeCooperativeDeleteStop::
            keen_pbr_dependencies_present;
    }
    const auto revision = usable_empty_dependency_revision(
        observed, record.interface_name, kernel_name);
    if (!revision) {
        return NdmsNativeCooperativeDeleteStop::
            keen_pbr_dependency_scan_incomplete;
    }
    if (require_same_revision &&
        *revision != record.keen_pbr_dependency_revision) {
        return NdmsNativeCooperativeDeleteStop::
            keen_pbr_dependency_changed;
    }
    return NdmsNativeCooperativeDeleteStop::none;
}

NdmsNativeCooperativeDeleteResult base_result(
    const NdmsNativeDeleteWalRecord* record = nullptr) {
    NdmsNativeCooperativeDeleteResult result;
    result.external_writer_race_excluded = false;
    if (record != nullptr) {
        result.durable_phase = record->phase;
        result.transaction_id = record->transaction_id;
        result.interface_name = record->interface_name;
        result.kind = record->kind;
        result.external_writer_race_accepted =
            record->external_writer_race_accepted;
        result.global_save_scope_acknowledged =
            record->owner_global_save_acknowledged;
    }
    return result;
}

NdmsNativeCooperativeDeleteResult stop_result(
    const NdmsNativeCooperativeDeleteStop stop,
    const NdmsNativeDeleteWalRecord* record = nullptr,
    const bool recovery = false) {
    auto result = base_result(record);
    result.stop = stop;
    result.status = recovery
        ? NdmsNativeCooperativeDeleteStatus::recovery_required
        : NdmsNativeCooperativeDeleteStatus::blocked;
    return result;
}

struct InvocationTransportTrace final {
    bool delete_perform_started{false};
    bool save_perform_started{false};
    bool request_may_have_been_dispatched{false};
    bool system_configuration_save_acknowledged{false};
    std::optional<NdmsNativeExactMutationResponseOutcome> transport_outcome;
};

NdmsNativeCooperativeDeleteResult merge_invocation_trace(
    NdmsNativeCooperativeDeleteResult result,
    const InvocationTransportTrace& trace) {
    result.delete_perform_started =
        result.delete_perform_started || trace.delete_perform_started;
    result.save_perform_started =
        result.save_perform_started || trace.save_perform_started;
    result.request_may_have_been_dispatched =
        result.request_may_have_been_dispatched ||
        trace.request_may_have_been_dispatched;
    result.system_configuration_save_acknowledged =
        result.system_configuration_save_acknowledged ||
        trace.system_configuration_save_acknowledged;
    if (trace.transport_outcome) {
        result.transport_outcome = trace.transport_outcome;
    }
    return result;
}

bool import_wal_clean(
    NdmsNativeImportWalStore& store) noexcept {
    try {
        return ndms_native_import_inventory_permits_ownership_reconciliation(
            store.inventory());
    } catch (...) {
        return false;
    }
}

bool writer_still_held(NdmsNativeWriterLease& writer) noexcept {
    try {
        writer.verify_held();
        return true;
    } catch (...) {
        return false;
    }
}

template <typename ImplType>
NdmsNativeCooperativeDeleteResult durable_stop_result(
    ImplType& impl,
    NdmsNativeWriterLease& writer,
    const NdmsNativeCooperativeDeleteStop stop) noexcept {
    // `record` is an in-memory work item. A failed publication may have left
    // either its predecessor or its successor visible, so it is never valid
    // evidence for a failure response. Report identity and phase only from an
    // exact reread bracketed by the still-held cooperative writer lease. If
    // the lease or WAL cannot be read authoritatively, omit all durable record
    // fields; callers must then fail closed instead of guessing a phase.
    auto result = stop_result(stop, nullptr, true);
    try {
        writer.verify_held();
        const auto loaded = impl.delete_wal.load();
        writer.verify_held();
        if (loaded.state == NdmsNativeDeleteWalLoadState::valid &&
            loaded.record) {
            result = stop_result(stop, &*loaded.record, true);
        }
    } catch (...) {
        // The conservative result deliberately has no durable identity.
    }
    return result;
}

template <typename ImplType>
bool artifacts_and_dependencies_still_exact(
    ImplType& impl,
    NdmsNativeWriterLease& writer,
    const NdmsNativeDeleteWalRecord& record,
    NdmsNativeCooperativeDeleteStop& stop) {
    const auto claim = impl.ownership.read(record.interface_name);
    if (!active_claim_matches_record(claim, record)) {
        stop = claim.state == NdmsNativeOwnershipReadState::unreadable
            ? NdmsNativeCooperativeDeleteStop::ownership_unreadable
            : NdmsNativeCooperativeDeleteStop::ownership_changed;
        return false;
    }
    stop = validate_snapshot(impl.snapshots, record);
    if (stop != NdmsNativeCooperativeDeleteStop::none) return false;
    const auto measured = observe_pair(
        impl, writer, record, ExpectedPresence::present, false);
    if (measured.stop != NdmsNativeCooperativeDeleteStop::none ||
        measured.presence != MeasuredPresence::present) {
        stop = measured.stop;
        return false;
    }
    if (measured.kernel_name != record.kernel_interface_name) {
        stop = NdmsNativeCooperativeDeleteStop::observed_target_drifted;
        return false;
    }
    stop = validate_dependencies(
        impl, record, record.kernel_interface_name, true);
    if (stop != NdmsNativeCooperativeDeleteStop::none) return false;
    // Final authority operation before returning to the transport. Nothing
    // that can allocate, block or inspect state follows it in this guard.
    try {
        writer.verify_held();
        return true;
    } catch (...) {
        stop = NdmsNativeCooperativeDeleteStop::writer_lost;
        return false;
    }
}

template <typename ImplType>
bool absence_still_exact(
    ImplType& impl,
    NdmsNativeWriterLease& writer,
    const NdmsNativeDeleteWalRecord& record,
    NdmsNativeCooperativeDeleteStop& stop) {
    const auto claim = impl.ownership.read(record.interface_name);
    if (!active_claim_matches_record(claim, record)) {
        stop = NdmsNativeCooperativeDeleteStop::ownership_changed;
        return false;
    }
    stop = validate_snapshot(impl.snapshots, record);
    if (stop != NdmsNativeCooperativeDeleteStop::none) return false;
    const auto measured = observe_pair(
        impl, writer, record, ExpectedPresence::absent, false);
    if (measured.stop != NdmsNativeCooperativeDeleteStop::none ||
        measured.presence != MeasuredPresence::absent) {
        stop = measured.stop;
        return false;
    }
    stop = validate_dependencies(
        impl, record, record.kernel_interface_name, true);
    if (stop != NdmsNativeCooperativeDeleteStop::none) return false;
    try {
        writer.verify_held();
        return true;
    } catch (...) {
        stop = NdmsNativeCooperativeDeleteStop::writer_lost;
        return false;
    }
}

template <typename ImplType>
NdmsNativeCooperativeDeleteStop validate_fresh_post_save_absence(
    ImplType& impl,
    NdmsNativeWriterLease& writer,
    const NdmsNativeDeleteWalRecord& record) {
    const auto fresh = observe_pair(
        impl, writer, record, ExpectedPresence::either, false);
    if (fresh.stop != NdmsNativeCooperativeDeleteStop::none) {
        return fresh.stop;
    }
    if (fresh.presence != MeasuredPresence::absent) {
        return NdmsNativeCooperativeDeleteStop::
            observed_target_reappeared_after_save;
    }
    if (!record.post_save_absence_observations ||
        fresh.pair.runtime_sequence <=
            record.post_save_absence_observations->
                running_config_sequence) {
        return NdmsNativeCooperativeDeleteStop::
            durable_observation_failed;
    }
    return validate_dependencies(
        impl, record, record.kernel_interface_name, true);
}

void refresh_integrity(NdmsNativeDeleteWalRecord& record) {
    record.integrity = ndms_native_delete_wal_integrity(record);
}

NdmsNativeOwnershipRecord make_tombstone(
    const NdmsNativeOwnershipRecord& active,
    const NdmsNativeDeleteWalRecord& record) {
    if (!record.post_save_absence_observations) {
        throw std::invalid_argument(
            "native delete tombstone requires post-save observations");
    }
    auto tombstone = active;
    tombstone.schema_version =
        kNdmsNativeOwnershipTombstoneSchemaVersion;
    tombstone.lifecycle = NdmsNativeOwnershipLifecycle::
        deleted_save_acknowledged_unverified;
    const auto& observed = *record.post_save_absence_observations;
    tombstone.lifecycle_evidence =
        NdmsNativeOwnershipLifecycleEvidence{
            record.transaction_id,
            record.observation_binding,
            observed.runtime_catalog_revision,
            observed.runtime_sequence,
            observed.running_config_catalog_revision,
            observed.running_config_sequence,
            record.kernel_interface_name,
        };
    return tombstone;
}

bool matching_tombstone(
    const NdmsNativeOwnershipReadResult& current,
    const NdmsNativeDeleteWalRecord& record,
    std::string& revision) {
    if (current.state != NdmsNativeOwnershipReadState::valid ||
        !current.record || !current.revision ||
        !ndms_native_ownership_is_delete_tombstone(*current.record) ||
        current.record->interface_name != record.interface_name ||
        current.record->transaction_id != record.ownership_transaction_id ||
        current.record->marker != record.marker ||
        current.record->kind != record.kind ||
        current.record->snapshot_revision != record.snapshot_revision ||
        current.record->target_full_revision != record.target_full_revision ||
        !current.record->lifecycle_evidence ||
        current.record->lifecycle_evidence->transaction_id !=
            record.transaction_id ||
        !(current.record->lifecycle_evidence->observation_binding ==
          record.observation_binding) ||
        !record.post_save_absence_observations) {
        return false;
    }
    const auto& evidence = *current.record->lifecycle_evidence;
    const auto& expected = *record.post_save_absence_observations;
    if (evidence.runtime_catalog_revision !=
            expected.runtime_catalog_revision ||
        evidence.runtime_sequence != expected.runtime_sequence ||
        evidence.running_config_catalog_revision !=
            expected.running_config_catalog_revision ||
        evidence.running_config_sequence !=
            expected.running_config_sequence) {
        return false;
    }
    revision = *current.revision;
    return true;
}

} // namespace

NdmsNativeCooperativeDeleteResult
NdmsNativeCooperativeDeleteCoordinator::run_record(
    NdmsNativeWriterLease& writer,
    NdmsNativeDeleteWalRecord record,
    const bool current_save_reconfirmed) {
    auto& impl = *impl_;
    InvocationTransportTrace invocation_trace;
    const auto finish = [&invocation_trace](
                            NdmsNativeCooperativeDeleteResult result) {
        return merge_invocation_trace(
            std::move(result), invocation_trace);
    };
    const auto stop = [&finish, &impl, &writer](
                          const NdmsNativeCooperativeDeleteStop reason,
                          std::optional<NdmsNativeDirectObservationFailure>
                              observation_failure = std::nullopt) {
        auto result = durable_stop_result(impl, writer, reason);
        result.observation_failure = observation_failure;
        return finish(std::move(result));
    };
    while (true) {
        if (!import_wal_clean(impl.import_wal)) {
            return stop(
                NdmsNativeCooperativeDeleteStop::
                    import_wal_not_authoritatively_clean);
        }
        if (!writer_still_held(writer)) {
            return stop(NdmsNativeCooperativeDeleteStop::writer_lost);
        }

        if (record.phase == NdmsNativeDeleteWalPhase::prepared) {
            record.phase =
                NdmsNativeDeleteWalPhase::delete_may_be_inflight;
            refresh_integrity(record);
            if (!writer_still_held(writer)) {
                return stop(NdmsNativeCooperativeDeleteStop::writer_lost);
            }
            try {
                impl.delete_wal.publish(record);
            } catch (...) {
                return stop(
                    NdmsNativeCooperativeDeleteStop::
                        delete_wal_publish_failed);
            }
            continue;
        }

        if (record.phase ==
            NdmsNativeDeleteWalPhase::delete_may_be_inflight) {
            const auto before = observe_pair(
                impl, writer, record, ExpectedPresence::either, false);
            if (before.stop != NdmsNativeCooperativeDeleteStop::none) {
                return stop(before.stop);
            }
            if (before.presence == MeasuredPresence::absent) {
                record.delete_absence_observations = before.pair;
                record.phase = NdmsNativeDeleteWalPhase::
                    running_absence_verified;
                refresh_integrity(record);
                if (!writer_still_held(writer)) {
                    return stop(
                        NdmsNativeCooperativeDeleteStop::writer_lost);
                }
                try {
                    impl.delete_wal.publish(record);
                } catch (...) {
                    return stop(
                        NdmsNativeCooperativeDeleteStop::
                            delete_wal_publish_failed);
                }
                continue;
            }
            if (before.presence != MeasuredPresence::present) {
                return stop(
                    NdmsNativeCooperativeDeleteStop::
                        observed_target_drifted);
            }

            NdmsNativeCooperativeDeleteStop guard_stop{
                NdmsNativeCooperativeDeleteStop::delete_guard_rejected};
            CallbackGuard guard([&] {
                return artifacts_and_dependencies_still_exact(
                    impl, writer, record, guard_stop);
            });
            const auto transport = dispatch_once(
                NdmsNativeExactMutationRequest::delete_managed_interface(
                    record.interface_name),
                guard);
            invocation_trace.delete_perform_started =
                invocation_trace.delete_perform_started ||
                transport.perform_started;
            invocation_trace.request_may_have_been_dispatched =
                invocation_trace.request_may_have_been_dispatched ||
                transport.request_may_have_been_dispatched;
            invocation_trace.transport_outcome =
                transport.response_manifest.outcome;
            if (!transport.pre_dispatch_guard_passed) {
                return stop(guard_stop);
            }

            const auto after = observe_pair(
                impl, writer, record, ExpectedPresence::either, false);
            if (after.stop != NdmsNativeCooperativeDeleteStop::none) {
                return stop(after.stop, after.failure);
            }
            if (after.presence != MeasuredPresence::absent) {
                return stop(
                    after.presence == MeasuredPresence::present
                        ? NdmsNativeCooperativeDeleteStop::
                              delete_transport_ambiguous
                        : NdmsNativeCooperativeDeleteStop::
                              observed_target_drifted);
            }
            record.delete_absence_observations = after.pair;
            record.phase =
                NdmsNativeDeleteWalPhase::running_absence_verified;
            refresh_integrity(record);
            if (!writer_still_held(writer)) {
                return stop(NdmsNativeCooperativeDeleteStop::writer_lost);
            }
            try {
                impl.delete_wal.publish(record);
            } catch (...) {
                return stop(NdmsNativeCooperativeDeleteStop::
                    delete_wal_publish_failed);
            }
            continue;
        }

        if (record.phase ==
            NdmsNativeDeleteWalPhase::running_absence_verified) {
            if (!current_save_reconfirmed) {
                return stop(
                    NdmsNativeCooperativeDeleteStop::
                        save_reconfirmation_required);
            }
            record.phase = NdmsNativeDeleteWalPhase::save_may_be_inflight;
            refresh_integrity(record);
            if (!writer_still_held(writer)) {
                return stop(NdmsNativeCooperativeDeleteStop::writer_lost);
            }
            try {
                impl.delete_wal.publish(record);
            } catch (...) {
                return stop(
                    NdmsNativeCooperativeDeleteStop::
                        delete_wal_publish_failed);
            }
            continue;
        }

        if (record.phase == NdmsNativeDeleteWalPhase::save_may_be_inflight) {
            if (!current_save_reconfirmed) {
                return stop(
                    NdmsNativeCooperativeDeleteStop::
                        save_reconfirmation_required);
            }
            const auto before = observe_pair(
                impl, writer, record, ExpectedPresence::either, false);
            if (before.stop != NdmsNativeCooperativeDeleteStop::none) {
                return stop(before.stop);
            }
            if (before.presence != MeasuredPresence::absent) {
                return stop(
                    NdmsNativeCooperativeDeleteStop::
                        observed_target_reappeared_after_save);
            }
            NdmsNativeCooperativeDeleteStop guard_stop{
                NdmsNativeCooperativeDeleteStop::save_guard_rejected};
            CallbackGuard guard([&] {
                return absence_still_exact(
                    impl, writer, record, guard_stop);
            });
            const auto transport = dispatch_once(
                NdmsNativeExactMutationRequest::save_configuration(),
                guard);
            invocation_trace.save_perform_started =
                invocation_trace.save_perform_started ||
                transport.perform_started;
            invocation_trace.request_may_have_been_dispatched =
                invocation_trace.request_may_have_been_dispatched ||
                transport.request_may_have_been_dispatched;
            invocation_trace.transport_outcome =
                transport.response_manifest.outcome;
            if (!transport.pre_dispatch_guard_passed) {
                return stop(guard_stop);
            }
            if (!transport.response_manifest.
                    acknowledged_needs_observation()) {
                return stop(NdmsNativeCooperativeDeleteStop::
                    save_transport_ambiguous);
            }
            invocation_trace.system_configuration_save_acknowledged = true;
            const auto after = observe_pair(
                impl, writer, record, ExpectedPresence::either, false);
            if (after.stop != NdmsNativeCooperativeDeleteStop::none) {
                return stop(after.stop, after.failure);
            }
            if (after.presence != MeasuredPresence::absent) {
                return stop(NdmsNativeCooperativeDeleteStop::
                    observed_target_reappeared_after_save);
            }
            record.post_save_absence_observations = after.pair;
            record.phase = NdmsNativeDeleteWalPhase::
                save_acknowledged_unverified;
            refresh_integrity(record);
            if (!writer_still_held(writer)) {
                return stop(NdmsNativeCooperativeDeleteStop::writer_lost);
            }
            try {
                impl.delete_wal.publish(record);
            } catch (...) {
                return stop(NdmsNativeCooperativeDeleteStop::
                    delete_wal_publish_failed);
            }
            continue;
        }

        if (record.phase == NdmsNativeDeleteWalPhase::
                save_acknowledged_unverified) {
            const auto terminal_stop = validate_fresh_post_save_absence(
                impl, writer, record);
            if (terminal_stop !=
                NdmsNativeCooperativeDeleteStop::none) {
                return stop(terminal_stop);
            }
            if (validate_snapshot(impl.snapshots, record) !=
                NdmsNativeCooperativeDeleteStop::none) {
                return stop(
                    NdmsNativeCooperativeDeleteStop::snapshot_mismatch);
            }
            const auto current = impl.ownership.read(record.interface_name);
            std::string tombstone_revision;
            if (!matching_tombstone(
                    current, record, tombstone_revision)) {
                if (!active_claim_matches_record(current, record)) {
                    return stop(
                        NdmsNativeCooperativeDeleteStop::
                            tombstone_mismatch);
                }
                const auto tombstone = make_tombstone(*current.record, record);
                try {
                    // The fresh dual-scope absence and dependency scan above
                    // narrow the explicitly accepted external-writer race.
                    // This lease excludes only other keen-pbr writers.
                    writer.verify_held();
                } catch (...) {
                    return stop(
                        NdmsNativeCooperativeDeleteStop::writer_lost);
                }
                std::optional<std::string> published;
                try {
                    published = impl.ownership.replace_exact(
                        *current.record, tombstone);
                } catch (...) {
                    return stop(
                        NdmsNativeCooperativeDeleteStop::
                            tombstone_publish_failed);
                }
                if (!published) {
                    return stop(
                        NdmsNativeCooperativeDeleteStop::
                            tombstone_publish_failed);
                }
                tombstone_revision = *published;
            }
            record.tombstone_revision = tombstone_revision;
            record.phase = NdmsNativeDeleteWalPhase::cleanup;
            refresh_integrity(record);
            if (!writer_still_held(writer)) {
                return stop(NdmsNativeCooperativeDeleteStop::writer_lost);
            }
            try {
                impl.delete_wal.publish(record);
            } catch (...) {
                return stop(
                    NdmsNativeCooperativeDeleteStop::
                        delete_wal_publish_failed);
            }
            continue;
        }

        if (record.phase == NdmsNativeDeleteWalPhase::cleanup) {
            const auto cleanup_stop = validate_fresh_post_save_absence(
                impl, writer, record);
            if (cleanup_stop !=
                NdmsNativeCooperativeDeleteStop::none) {
                return stop(cleanup_stop);
            }
            const auto current = impl.ownership.read(record.interface_name);
            std::string revision;
            if (!matching_tombstone(current, record, revision) ||
                !record.tombstone_revision ||
                revision != *record.tombstone_revision ||
                validate_snapshot(impl.snapshots, record) !=
                    NdmsNativeCooperativeDeleteStop::none) {
                return stop(
                    NdmsNativeCooperativeDeleteStop::tombstone_mismatch);
            }
            if (!writer_still_held(writer)) {
                return stop(NdmsNativeCooperativeDeleteStop::writer_lost);
            }
            try {
                impl.delete_wal.remove_exact(record);
            } catch (const NdmsNativeDeleteWalStoreWriteError& error) {
                if (!error.published() ||
                    impl.delete_wal.readiness() !=
                        NdmsNativeDeleteWalReadiness::clean) {
                    return stop(
                        NdmsNativeCooperativeDeleteStop::
                            delete_wal_cleanup_failed);
                }
            } catch (...) {
                return stop(
                    NdmsNativeCooperativeDeleteStop::
                        delete_wal_cleanup_failed);
            }
            auto result = base_result(&record);
            result.status = NdmsNativeCooperativeDeleteStatus::
                save_acknowledged_unverified;
            result.stop = NdmsNativeCooperativeDeleteStop::none;
            result.ownership_tombstone_durable = true;
            result.rollback_snapshot_retained = true;
            return finish(std::move(result));
        }
    }
}

bool NdmsNativeKeenPbrDependency::operator==(
    const NdmsNativeKeenPbrDependency& other) const noexcept {
    return kind == other.kind && dependent_id == other.dependent_id;
}

std::string ndms_native_keen_pbr_dependency_revision(
    const NdmsNativeKeenPbrDependencyObservation& observation) {
    if (observation.scope != NdmsNativeKeenPbrDependencyScope::
            config_and_runtime_interface_references ||
        observation.firmware_interface_name.empty() ||
        observation.firmware_interface_name.size() > 64U ||
        (observation.kernel_interface_name &&
         (observation.kernel_interface_name->empty() ||
          observation.kernel_interface_name->size() > 64U))) {
        throw std::invalid_argument(
            "native keen-pbr dependency observation is invalid");
    }
    auto references = observation.references;
    if (!std::all_of(
            references.begin(), references.end(),
            [](const auto& reference) {
                return known_dependency_kind(reference.kind) &&
                       !reference.dependent_id.empty() &&
                       reference.dependent_id.size() <= 256U;
            })) {
        throw std::invalid_argument(
            "native keen-pbr dependency reference is invalid");
    }
    std::sort(
        references.begin(), references.end(),
        [](const auto& left, const auto& right) {
            return std::pair{
                       static_cast<unsigned int>(left.kind),
                       left.dependent_id} <
                   std::pair{
                       static_cast<unsigned int>(right.kind),
                       right.dependent_id};
        });
    if (std::adjacent_find(references.begin(), references.end()) !=
        references.end()) {
        throw std::invalid_argument(
            "native keen-pbr dependency reference is duplicated");
    }
    Sha256 hasher;
    update_field(
        hasher, "keen-pbr.ndms-native-delete.dependencies.v1");
    update_field(hasher, "config_and_runtime_interface_references");
    update_field(hasher, observation.firmware_interface_name);
    update_field(
        hasher,
        observation.kernel_interface_name
            ? std::string_view{*observation.kernel_interface_name}
            : std::string_view{"-"});
    for (const auto& reference : references) {
        update_field(hasher, dependency_kind_name(reference.kind));
        update_field(hasher, reference.dependent_id);
    }
    return std::string{kNdmsNativeDeleteDependencyRevisionPrefix} +
           hasher.hex_digest();
}

NdmsNativeCooperativeDeleteCoordinator::
NdmsNativeCooperativeDeleteCoordinator(
    NdmsNativeObservationStore& observations,
    NdmsNativeImportWalStore& import_wal,
    NdmsNativeDeleteWalStore& delete_wal,
    NdmsNativeSecretSnapshotStore& snapshots,
    NdmsNativeOwnershipStore& ownership,
    NdmsNativeKeenPbrDependencyProvider& dependencies)
    : impl_(std::make_unique<Impl>(
          observations,
          import_wal,
          delete_wal,
          snapshots,
          ownership,
          dependencies)) {}

NdmsNativeCooperativeDeleteCoordinator::
NdmsNativeCooperativeDeleteCoordinator(
    std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

NdmsNativeCooperativeDeleteCoordinator::
~NdmsNativeCooperativeDeleteCoordinator() = default;
NdmsNativeCooperativeDeleteCoordinator::
NdmsNativeCooperativeDeleteCoordinator(
    NdmsNativeCooperativeDeleteCoordinator&&) noexcept = default;
NdmsNativeCooperativeDeleteCoordinator&
NdmsNativeCooperativeDeleteCoordinator::operator=(
    NdmsNativeCooperativeDeleteCoordinator&&) noexcept = default;

NdmsNativeExactMutationTransportResult
NdmsNativeCooperativeDeleteCoordinator::dispatch_once(
    NdmsNativeExactMutationRequest request,
    NdmsNativeExactMutationPreDispatchGuard& guard) {
    auto authority = NdmsNativeExactMutationDispatchAuthority{
        NdmsNativeExactMutationDispatchAuthority::ConstructionKey{}};
    if (!authority.consume()) {
        throw NdmsNativeExactMutationTransportError(
            "native cooperative delete authority is invalid");
    }
    auto capability = NdmsNativeExactMutationDispatchCapability{
        NdmsNativeExactMutationDispatchCapability::ConstructionKey{}};
    return post_ndms_native_exact_mutation_once(
        std::move(capability),
        std::move(request),
        guard,
        *impl_->backend);
}

NdmsNativeCooperativeDeleteResult
NdmsNativeCooperativeDeleteCoordinator::delete_once(
    NdmsNativeWriterLease& writer,
    const NdmsNativeCooperativeDeleteRequest& request) noexcept {
    if (!impl_) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::writer_missing);
    }
    if (request.global_save_consent !=
        NdmsNativeOwnerGlobalSaveConsent::
            acknowledged_all_pending_keenetic_changes) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::
                owner_global_save_not_acknowledged);
    }
    if (request.external_writer_race !=
        NdmsNativeDeleteExternalWriterRaceAcceptance::owner_accepted) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::
                external_writer_race_not_accepted);
    }
    if (!ndms_native_created_target_is_eligible(request.interface_name)) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::invalid_or_protected_target);
    }
    try {
        writer.verify_held();
    } catch (...) {
        return stop_result(NdmsNativeCooperativeDeleteStop::writer_lost);
    }
    if (!import_wal_clean(impl_->import_wal)) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::
                import_wal_not_authoritatively_clean);
    }
    const auto claim = impl_->ownership.read(request.interface_name);
    if (claim.state == NdmsNativeOwnershipReadState::absent) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::ownership_absent);
    }
    if (claim.state != NdmsNativeOwnershipReadState::valid ||
        !claim.record || !claim.revision) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::ownership_unreadable);
    }
    if (!valid_active_ownership_revision(
            request.expected_ownership_revision) ||
        request.expected_ownership_revision != *claim.revision) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::ownership_changed);
    }
    if (!ndms_native_ownership_is_active(*claim.record)) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::ownership_not_active);
    }

    // The card's opaque claim revision is checked before even sweeping the
    // delete WAL namespace. A stale card therefore cannot cause a durable
    // write while inspecting a slot that has since been reused.
    impl_->delete_wal.sweep_orphaned_temporaries();
    switch (impl_->delete_wal.readiness()) {
    case NdmsNativeDeleteWalReadiness::unfinished:
        return stop_result(
            NdmsNativeCooperativeDeleteStop::delete_wal_unfinished);
    case NdmsNativeDeleteWalReadiness::unsafe:
        return stop_result(
            NdmsNativeCooperativeDeleteStop::delete_wal_unsafe);
    case NdmsNativeDeleteWalReadiness::clean:
        break;
    }

    NdmsNativeDeleteWalRecord record;
    try {
        record.transaction_id = impl_->transaction_id_factory();
        if (!valid_ndms_native_import_transaction_id(
                record.transaction_id)) {
            throw std::runtime_error("invalid delete transaction id");
        }
        record.interface_name = request.interface_name;
        record.kind = claim.record->kind;
        record.ownership_revision = *claim.revision;
        record.ownership_transaction_id = claim.record->transaction_id;
        record.marker = claim.record->marker;
        record.snapshot_revision = claim.record->snapshot_revision;
        record.target_full_revision = claim.record->target_full_revision;
    } catch (...) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::unexpected_failure);
    }
    // Until the prepared record is published there is no durable delete
    // identity. Owner acknowledgements held only in this request are likewise
    // not durable audit evidence and must not be projected as such.
    NdmsNativeCooperativeDeleteResult result;
    result.external_writer_race_excluded = false;

    auto snapshot_stop = validate_snapshot(impl_->snapshots, record);
    if (snapshot_stop != NdmsNativeCooperativeDeleteStop::none) {
        result.stop = snapshot_stop;
        return result;
    }
    const auto measured = observe_pair(
        *impl_, writer, record, ExpectedPresence::present, true);
    if (measured.stop != NdmsNativeCooperativeDeleteStop::none ||
        measured.presence != MeasuredPresence::present) {
        result.stop = measured.stop;
        result.observation_failure = measured.failure;
        return result;
    }
    const auto dependencies = impl_->dependencies.observe_dependencies(
        record.interface_name, measured.kernel_name);
    if (!dependencies.references.empty()) {
        result.stop = NdmsNativeCooperativeDeleteStop::
            keen_pbr_dependencies_present;
        return result;
    }
    const auto dependency_revision = usable_empty_dependency_revision(
        dependencies, record.interface_name, measured.kernel_name);
    if (!dependency_revision) {
        result.stop = NdmsNativeCooperativeDeleteStop::
            keen_pbr_dependency_scan_incomplete;
        return result;
    }
    record.keen_pbr_dependency_revision = *dependency_revision;
    record.kernel_interface_name = measured.kernel_name;
    record.preflight_observations = measured.pair;
    try {
        // begin_mutation requires the exact second durable stamp, so read the
        // ledger and reconstitute only after exact equality with the measured
        // running-config revision/sequence.
        const auto ledger = impl_->observations.read();
        if (ledger.state != NdmsNativeObservationReadState::valid ||
            !ledger.ledger ||
            ledger.ledger->sequence !=
                measured.pair.running_config_sequence ||
            !ledger.ledger->last_catalog_revision ||
            *ledger.ledger->last_catalog_revision !=
                measured.pair.running_config_catalog_revision) {
            throw std::runtime_error("delete baseline ledger changed");
        }
        const NdmsNativeObservationStamp baseline{
            ledger.ledger->authority_id,
            ledger.ledger->sequence,
            ledger.ledger->mutation_epoch,
            *ledger.ledger->last_catalog_revision,
            ledger.ledger->integrity,
        };
        const auto mutation =
            impl_->observations.begin_mutation(writer, baseline);
        record.observation_binding =
            ndms_native_observation_binding(mutation);
        record.owner_global_save_acknowledged = true;
        record.external_writer_race_accepted = true;
        refresh_integrity(record);
    } catch (...) {
        result.stop =
            NdmsNativeCooperativeDeleteStop::durable_observation_failed;
        return result;
    }
    if (!writer_still_held(writer)) {
        return stop_result(NdmsNativeCooperativeDeleteStop::writer_lost);
    }
    try {
        if (!impl_->delete_wal.publish_prepared_exclusive(record)) {
            return durable_stop_result(
                *impl_,
                writer,
                NdmsNativeCooperativeDeleteStop::delete_wal_unfinished);
        }
    } catch (...) {
        return durable_stop_result(
            *impl_,
            writer,
            NdmsNativeCooperativeDeleteStop::delete_wal_publish_failed);
    }
    try {
        return run_record(writer, record, true);
    } catch (...) {
        return durable_stop_result(
            *impl_,
            writer,
            NdmsNativeCooperativeDeleteStop::unexpected_failure);
    }
}

NdmsNativeCooperativeDeleteResult
NdmsNativeCooperativeDeleteCoordinator::resume_once(
    NdmsNativeWriterLease& writer,
    const NdmsNativeCooperativeDeleteResumeAcknowledgement&
        current_acknowledgement) noexcept {
    if (!impl_) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::writer_missing);
    }
    try {
        writer.verify_held();
    } catch (...) {
        return stop_result(NdmsNativeCooperativeDeleteStop::writer_lost);
    }
    if (!import_wal_clean(impl_->import_wal)) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::
                import_wal_not_authoritatively_clean);
    }
    impl_->delete_wal.sweep_orphaned_temporaries();
    const auto loaded = impl_->delete_wal.load();
    if (loaded.state == NdmsNativeDeleteWalLoadState::absent) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::no_delete_transaction);
    }
    if (loaded.state != NdmsNativeDeleteWalLoadState::valid ||
        !loaded.record) {
        return stop_result(
            NdmsNativeCooperativeDeleteStop::delete_wal_unsafe);
    }
    const bool current_save_reconfirmed =
        current_acknowledgement.global_save_consent ==
            NdmsNativeOwnerGlobalSaveConsent::
                acknowledged_all_pending_keenetic_changes &&
        current_acknowledgement.external_writer_race ==
            NdmsNativeDeleteExternalWriterRaceAcceptance::owner_accepted;
    try {
        return run_record(
            writer, *loaded.record, current_save_reconfirmed);
    } catch (...) {
        return durable_stop_result(
            *impl_,
            writer,
            NdmsNativeCooperativeDeleteStop::unexpected_failure);
    }
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeCooperativeDeleteCoordinator
NdmsNativeCooperativeDeleteCoordinatorTestIssuer::issue(
    NdmsNativeObservationStore& observations,
    NdmsNativeImportWalStore& import_wal,
    NdmsNativeDeleteWalStore& delete_wal,
    NdmsNativeSecretSnapshotStore& snapshots,
    NdmsNativeOwnershipStore& ownership,
    NdmsNativeKeenPbrDependencyProvider& dependencies,
    NdmsNativeCooperativeDeleteObservationGateway& gateway,
    NdmsNativeExactMutationBackend& backend,
    std::function<std::string()> transaction_id_factory) {
    return NdmsNativeCooperativeDeleteCoordinator{
        std::make_unique<NdmsNativeCooperativeDeleteCoordinator::Impl>(
            observations,
            import_wal,
            delete_wal,
            snapshots,
            ownership,
            dependencies,
            gateway,
            backend,
            std::move(transaction_id_factory))};
}
#endif

const char* ndms_native_cooperative_delete_status_name(
    const NdmsNativeCooperativeDeleteStatus status) noexcept {
    switch (status) {
    case NdmsNativeCooperativeDeleteStatus::blocked: return "blocked";
    case NdmsNativeCooperativeDeleteStatus::recovery_required:
        return "recovery_required";
    case NdmsNativeCooperativeDeleteStatus::save_acknowledged_unverified:
        return "save_acknowledged_unverified";
    }
    return "blocked";
}

const char* ndms_native_cooperative_delete_stop_name(
    const NdmsNativeCooperativeDeleteStop stop) noexcept {
    switch (stop) {
    case NdmsNativeCooperativeDeleteStop::none: return "none";
    case NdmsNativeCooperativeDeleteStop::owner_global_save_not_acknowledged:
        return "owner_global_save_not_acknowledged";
    case NdmsNativeCooperativeDeleteStop::external_writer_race_not_accepted:
        return "external_writer_race_not_accepted";
    case NdmsNativeCooperativeDeleteStop::save_reconfirmation_required:
        return "save_reconfirmation_required";
    case NdmsNativeCooperativeDeleteStop::writer_missing:
        return "writer_missing";
    case NdmsNativeCooperativeDeleteStop::writer_lost: return "writer_lost";
    case NdmsNativeCooperativeDeleteStop::invalid_or_protected_target:
        return "invalid_or_protected_target";
    case NdmsNativeCooperativeDeleteStop::
        import_wal_not_authoritatively_clean:
        return "import_wal_not_authoritatively_clean";
    case NdmsNativeCooperativeDeleteStop::delete_wal_unfinished:
        return "delete_wal_unfinished";
    case NdmsNativeCooperativeDeleteStop::delete_wal_unsafe:
        return "delete_wal_unsafe";
    case NdmsNativeCooperativeDeleteStop::no_delete_transaction:
        return "no_delete_transaction";
    case NdmsNativeCooperativeDeleteStop::ownership_absent:
        return "ownership_absent";
    case NdmsNativeCooperativeDeleteStop::ownership_unreadable:
        return "ownership_unreadable";
    case NdmsNativeCooperativeDeleteStop::ownership_not_active:
        return "ownership_not_active";
    case NdmsNativeCooperativeDeleteStop::ownership_changed:
        return "ownership_changed";
    case NdmsNativeCooperativeDeleteStop::snapshot_absent:
        return "snapshot_absent";
    case NdmsNativeCooperativeDeleteStop::snapshot_unreadable:
        return "snapshot_unreadable";
    case NdmsNativeCooperativeDeleteStop::snapshot_mismatch:
        return "snapshot_mismatch";
    case NdmsNativeCooperativeDeleteStop::
        keen_pbr_dependency_scan_incomplete:
        return "keen_pbr_dependency_scan_incomplete";
    case NdmsNativeCooperativeDeleteStop::keen_pbr_dependencies_present:
        return "keen_pbr_dependencies_present";
    case NdmsNativeCooperativeDeleteStop::keen_pbr_dependency_changed:
        return "keen_pbr_dependency_changed";
    case NdmsNativeCooperativeDeleteStop::runtime_observation_failed:
        return "runtime_observation_failed";
    case NdmsNativeCooperativeDeleteStop::running_config_observation_failed:
        return "running_config_observation_failed";
    case NdmsNativeCooperativeDeleteStop::observation_scope_mismatch:
        return "observation_scope_mismatch";
    case NdmsNativeCooperativeDeleteStop::observed_target_mismatch:
        return "observed_target_mismatch";
    case NdmsNativeCooperativeDeleteStop::observed_target_drifted:
        return "observed_target_drifted";
    case NdmsNativeCooperativeDeleteStop::
        observed_target_reappeared_after_save:
        return "observed_target_reappeared_after_save";
    case NdmsNativeCooperativeDeleteStop::durable_observation_failed:
        return "durable_observation_failed";
    case NdmsNativeCooperativeDeleteStop::delete_wal_publish_failed:
        return "delete_wal_publish_failed";
    case NdmsNativeCooperativeDeleteStop::delete_guard_rejected:
        return "delete_guard_rejected";
    case NdmsNativeCooperativeDeleteStop::delete_transport_ambiguous:
        return "delete_transport_ambiguous";
    case NdmsNativeCooperativeDeleteStop::save_guard_rejected:
        return "save_guard_rejected";
    case NdmsNativeCooperativeDeleteStop::save_transport_ambiguous:
        return "save_transport_ambiguous";
    case NdmsNativeCooperativeDeleteStop::tombstone_publish_failed:
        return "tombstone_publish_failed";
    case NdmsNativeCooperativeDeleteStop::tombstone_mismatch:
        return "tombstone_mismatch";
    case NdmsNativeCooperativeDeleteStop::delete_wal_cleanup_failed:
        return "delete_wal_cleanup_failed";
    case NdmsNativeCooperativeDeleteStop::unexpected_failure:
        return "unexpected_failure";
    }
    return "unexpected_failure";
}

} // namespace keen_pbr3
