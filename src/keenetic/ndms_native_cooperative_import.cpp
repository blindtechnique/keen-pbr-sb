#include "ndms_native_cooperative_import.hpp"

#include "ndms_native_import_forward_plan.hpp"
#include "ndms_native_import_recovery_dispatch.hpp"
#include "ndms_native_import_recovery_lease.hpp"
#include "ndms_native_import_recovery_probe.hpp"
#include "ndms_native_writer_lease.hpp"
#include "ndms_wireguard_identity.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <net/if.h>
#endif

namespace keen_pbr3 {

namespace {

void secure_wipe(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : value.data();
    for (std::size_t index = 0U;
         bytes != nullptr && index < value.size(); ++index) {
        bytes[index] = '\0';
    }
    value.clear();
}

class WipeStringGuard final {
public:
    explicit WipeStringGuard(std::string& value) noexcept
        : value_(value) {}
    ~WipeStringGuard() { secure_wipe(value_); }

    WipeStringGuard(const WipeStringGuard&) = delete;
    WipeStringGuard& operator=(const WipeStringGuard&) = delete;

private:
    std::string& value_;
};

constexpr std::size_t kMaximumLocalKernelInterfaces = 4096U;

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

std::optional<std::vector<std::string>> local_kernel_interfaces() noexcept {
#if defined(__linux__)
    struct InterfaceNamesGuard final {
        struct if_nameindex* entries{nullptr};
        ~InterfaceNamesGuard() {
            if (entries != nullptr) ::if_freenameindex(entries);
        }
    } guard;

    try {
        guard.entries = ::if_nameindex();
        if (guard.entries == nullptr) return std::nullopt;

        std::vector<std::string> names;
        names.reserve(32U);
        for (auto* entry = guard.entries;; ++entry) {
            if (entry->if_index == 0U && entry->if_name == nullptr) {
                break;
            }
            if (entry->if_index == 0U || entry->if_name == nullptr ||
                names.size() >= kMaximumLocalKernelInterfaces) {
                return std::nullopt;
            }
            names.emplace_back(entry->if_name);
        }
        if (names.empty()) return std::nullopt;
        std::sort(names.begin(), names.end());
        if (std::adjacent_find(names.begin(), names.end()) != names.end()) {
            return std::nullopt;
        }
        return names;
    } catch (...) {
        return std::nullopt;
    }
#else
    return std::nullopt;
#endif
}

bool attach_local_kernel_interfaces(
    NdmsNativeDirectRecoveryObservation& observation) noexcept {
    if (!observation.complete() || !observation.snapshot.has_value()) {
        return false;
    }
    const auto names = local_kernel_interfaces();
    if (!names.has_value()) return false;
    try {
        auto resolved = resolve_ndms_kernel_names(
            observation.snapshot->catalog, *names);
        auto revision = ndms_native_import_recovery_catalog_revision(
            resolved, observation.target_evidence);
        observation.snapshot->catalog = std::move(resolved);
        observation.catalog_revision = std::move(revision);
        return !observation.catalog_revision.empty();
    } catch (...) {
        return false;
    }
}

class DirectObservationGatewayAdapter final
    : public NdmsNativeCooperativeImportObservationGateway {
public:
    NdmsNativeDirectCatalogObservation observe_catalog(
        const NdmsNativeDirectCatalogScope scope) noexcept override {
        return gateway_.observe_catalog(scope);
    }

    NdmsNativeDirectRecoveryObservation observe_recovery(
        const NdmsNativeDirectCatalogScope scope,
        const std::string& marker,
        const std::optional<std::string>& expected_target) noexcept override {
        auto observed =
            gateway_.observe_recovery(scope, marker, expected_target);
        if (observed.complete() &&
            !attach_local_kernel_interfaces(observed)) {
            observed.catalog_revision.clear();
            observed.failure =
                NdmsNativeDirectObservationFailure::transport_failed;
        }
        return observed;
    }

private:
    NdmsNativeDirectObservationGateway gateway_;
};

class SecretSnapshotStorePublisher final
    : public NdmsNativeImportSnapshotPublisher {
public:
    explicit SecretSnapshotStorePublisher(
        NdmsNativeSecretSnapshotStore& store) noexcept
        : store_(store) {}

    void publish(
        const std::string& expected_interface,
        const std::string& transaction_id,
        const std::string& marker,
        NdmsNativePanelDeleteSnapshot snapshot) override {
        store_.publish_panel_delete_snapshot(
            expected_interface,
            transaction_id,
            marker,
            std::move(snapshot));
    }

private:
    NdmsNativeSecretSnapshotStore& store_;
};

// Production generation adapter for the already-held composite writer. The
// maintenance helper owns the durable exact-next CAS; this object merely
// remembers the value it just received so the executor can recheck it at each
// in-process boundary. It never fabricates an allocator generation.
class CooperativeGenerationCoordinator final
    : public NdmsNativeImportGenerationCoordinator {
public:
    explicit CooperativeGenerationCoordinator(
        NdmsNativeWriterLease& writer) noexcept
        : writer_(writer), current_(writer.maintenance_base_generation()) {}

    NdmsNativeImportGenerationSnapshot observe() override {
        writer_.verify_held();
        return {current_, 0U};
    }

    std::optional<std::uint32_t> reserve_next(
        const std::string&,
        const std::string&,
        const std::uint32_t) override {
        return std::nullopt;
    }

    std::optional<std::uint32_t> reserve_next_cooperative(
        const std::string& transaction_id,
        const std::string& generation_ticket,
        const std::uint32_t maintenance_base_generation,
        NdmsNativeWriterLease& writer) override {
        if (&writer != &writer_ ||
            maintenance_base_generation != current_) {
            return std::nullopt;
        }
        const auto reserved =
            NdmsNativeImportGenerationCoordinator::
                reserve_next_cooperative(
                    transaction_id,
                    generation_ticket,
                    maintenance_base_generation,
                    writer_);
        if (reserved.has_value()) current_ = *reserved;
        return reserved;
    }

private:
    NdmsNativeWriterLease& writer_;
    std::uint32_t current_{0U};
};

bool valid_slot_evidence(
    const NdmsWireguardCatalogSlotEvidence& slot) noexcept {
    switch (slot.state) {
    case NdmsWireguardCatalogSlotState::absent:
        return slot.structural_revision.empty();
    case NdmsWireguardCatalogSlotState::occupied:
        return ndms_native_import_prefixed_sha256(
            slot.structural_revision, "ndms-wg-slot-v1-");
    case NdmsWireguardCatalogSlotState::unsafe:
        return false;
    }
    return false;
}

bool safe_direct_catalog(
    const NdmsNativeDirectCatalogObservation& observation) noexcept {
    if (observation.failure !=
            NdmsNativeDirectObservationFailure::none ||
        !observation.snapshot.has_value()) {
        return false;
    }
    const auto& snapshot = *observation.snapshot;
    if (snapshot.status != NdmsCatalogCacheStatus::fresh ||
        !snapshot.refreshed || !snapshot.observed_at.has_value() ||
        !snapshot.catalog.firmware_available ||
        !snapshot.catalog.wireguard_slot_evidence_complete) {
        return false;
    }
    return std::all_of(
        snapshot.catalog.wireguard_slots.begin(),
        snapshot.catalog.wireguard_slots.end(),
        valid_slot_evidence);
}

using Occupancy = std::array<bool, kNdmsWireguardCatalogSlotCount>;

Occupancy occupancy_of(const NdmsInterfaceCatalog& catalog) noexcept {
    Occupancy occupancy{};
    for (std::size_t slot = 0U; slot < occupancy.size(); ++slot) {
        occupancy[slot] =
            catalog.wireguard_slots[slot].state ==
            NdmsWireguardCatalogSlotState::occupied;
    }
    return occupancy;
}

std::optional<std::uint8_t> first_free_slot(
    const Occupancy& occupancy) noexcept {
    for (std::size_t slot = 0U; slot < occupancy.size(); ++slot) {
        if (!occupancy[slot]) return static_cast<std::uint8_t>(slot);
    }
    return std::nullopt;
}

bool catalog_contains_marker(
    const NdmsInterfaceCatalog& catalog,
    const std::string_view marker) noexcept {
    return std::any_of(
        catalog.tunnels.begin(), catalog.tunnels.end(),
        [marker](const NdmsTunnelInterface& tunnel) {
            return tunnel.label.find(marker) != std::string::npos;
        });
}

std::string generation_ticket(
    const std::string_view transaction_id,
    const std::string_view marker,
    const std::string_view expected_interface,
    const NdmsNativeObservationBinding& binding) {
    Sha256 hasher;
    const std::string domain{
        "keen-pbr.ndms-native.cooperative-generation-ticket.v1"};
    hasher.update(domain);
    hasher.update(transaction_id.data(), transaction_id.size());
    hasher.update(marker.data(), marker.size());
    hasher.update(expected_interface.data(), expected_interface.size());
    hasher.update(binding.authority_id);
    hasher.update(&binding.mutation_epoch, sizeof(binding.mutation_epoch));
    hasher.update(
        &binding.baseline_sequence, sizeof(binding.baseline_sequence));
    return std::string{kNdmsNativeAllocatorGenerationTicketPrefix} +
           hasher.hex_digest();
}

bool kind_matches_protocol(
    const NdmsNativeDirectRecoveryObservation& measured,
    const std::string& expected_interface,
    const NdmsNativeTunnelImportKind kind) noexcept {
    std::size_t matches = 0U;
    bool kind_matches = false;
    for (const auto& protocol : measured.target_protocols) {
        if (protocol.interface_name != expected_interface) continue;
        ++matches;
        kind_matches =
            (kind == NdmsNativeTunnelImportKind::wireguard &&
             protocol.asc_class == NdmsNativeAscClass::plain_wireguard) ||
            (kind == NdmsNativeTunnelImportKind::amnezia_wireguard &&
             protocol.asc_class == NdmsNativeAscClass::amnezia_wg);
    }
    return matches == 1U && kind_matches;
}

std::optional<std::string> measured_target_revision(
    const NdmsNativeDirectRecoveryObservation& measured,
    const std::string& expected_interface) {
    std::optional<std::string> revision;
    for (const auto& evidence : measured.target_evidence) {
        if (evidence.interface_name != expected_interface) continue;
        if (revision.has_value()) return std::nullopt;
        revision = evidence.full_revision;
    }
    return revision;
}

NdmsNativeCooperativeImportResult blocked_result(
    const NdmsNativeCooperativeImportStop stop,
    const bool race_accepted) noexcept {
    NdmsNativeCooperativeImportResult result;
    result.stop = stop;
    result.external_ndms_writer_race_accepted = race_accepted;
    return result;
}

void mark_recovery_required(
    NdmsNativeCooperativeImportResult& result,
    const NdmsNativeCooperativeImportStop stop) noexcept {
    result.status = NdmsNativeCooperativeImportStatus::recovery_required;
    result.stop = stop;
    result.wal_may_require_recovery = true;
}

bool durable_forward_observation_is_current(
    const NdmsNativeObservationStore& observations,
    const NdmsNativeObservationBinding& binding,
    const NdmsNativeObservationStamp& latest) noexcept {
    const auto current = observations.read();
    return current.state == NdmsNativeObservationReadState::valid &&
           current.ledger.has_value() &&
           current.ledger->authority_id == binding.authority_id &&
           current.ledger->mutation_epoch == binding.mutation_epoch &&
           current.ledger->sequence == latest.sequence &&
           current.ledger->last_catalog_revision.has_value() &&
           *current.ledger->last_catalog_revision ==
               latest.catalog_revision &&
           current.ledger->integrity == latest.ledger_integrity;
}

NdmsNativeCooperativeImportStop dispatch_stop(
    const std::optional<NdmsNativeImportRecoveryStep>& step) noexcept {
    if (!step.has_value()) {
        return NdmsNativeCooperativeImportStop::
            forward_completion_blocked;
    }
    switch (*step) {
    case NdmsNativeImportRecoveryStep::advance_wal_target_verified:
        return NdmsNativeCooperativeImportStop::
            target_verified_wal_publish_failed;
    case NdmsNativeImportRecoveryStep::publish_ownership:
        return NdmsNativeCooperativeImportStop::
            ownership_publish_failed;
    case NdmsNativeImportRecoveryStep::
        advance_wal_ownership_published:
        return NdmsNativeCooperativeImportStop::
            ownership_wal_publish_failed;
    case NdmsNativeImportRecoveryStep::remove_wal_record:
        return NdmsNativeCooperativeImportStop::wal_cleanup_failed;
    default:
        return NdmsNativeCooperativeImportStop::
            forward_completion_blocked;
    }
}

NdmsNativeCooperativeImportResumeStop resume_dispatch_stop(
    const std::optional<NdmsNativeImportRecoveryStep>& step) noexcept {
    if (!step.has_value()) {
        return NdmsNativeCooperativeImportResumeStop::unexpected_failure;
    }
    switch (*step) {
    case NdmsNativeImportRecoveryStep::advance_wal_target_verified:
        return NdmsNativeCooperativeImportResumeStop::
            target_verified_wal_publish_failed;
    case NdmsNativeImportRecoveryStep::publish_ownership:
        return NdmsNativeCooperativeImportResumeStop::
            ownership_publish_failed;
    case NdmsNativeImportRecoveryStep::
        advance_wal_ownership_published:
        return NdmsNativeCooperativeImportResumeStop::
            ownership_wal_publish_failed;
    case NdmsNativeImportRecoveryStep::remove_wal_record:
        return NdmsNativeCooperativeImportResumeStop::wal_cleanup_failed;
    default:
        return NdmsNativeCooperativeImportResumeStop::
            recovery_action_not_forward_only;
    }
}

NdmsNativeCooperativeImportWalReadiness import_wal_readiness(
    const NdmsNativeImportWalInventory& inventory) noexcept {
    const bool clean =
        (inventory.state == NdmsNativeImportWalInventoryState::absent ||
         inventory.state == NdmsNativeImportWalInventoryState::ready) &&
        inventory.items.empty();
    if (clean) return NdmsNativeCooperativeImportWalReadiness::clean;
    if (inventory.recovery_permitted() && !inventory.items.empty()) {
        return NdmsNativeCooperativeImportWalReadiness::unfinished;
    }
    return NdmsNativeCooperativeImportWalReadiness::unsafe;
}

bool forward_only_phase(const NdmsNativeImportWalPhase phase) noexcept {
    return phase == NdmsNativeImportWalPhase::response_recorded ||
           phase == NdmsNativeImportWalPhase::target_verified ||
           phase == NdmsNativeImportWalPhase::ownership_published;
}

std::optional<NdmsNativeOwnershipRecord> ownership_claim_from(
    const NdmsNativeImportWalRecord& record) {
    if (!record.created_interface.has_value() ||
        !record.target_full_revision.has_value()) {
        return std::nullopt;
    }
    NdmsNativeOwnershipRecord claim;
    claim.interface_name = *record.created_interface;
    claim.transaction_id = record.transaction_id;
    claim.marker = record.marker;
    claim.kind = record.kind;
    claim.snapshot_revision = record.snapshot_revision;
    claim.target_full_revision = *record.target_full_revision;
    return claim;
}

bool exact_existing_claim_or_absent(
    const NdmsNativeOwnershipReadResult& existing,
    const NdmsNativeOwnershipRecord& expected) noexcept {
    return existing.state == NdmsNativeOwnershipReadState::absent ||
           (existing.state == NdmsNativeOwnershipReadState::valid &&
            existing.record.has_value() &&
            *existing.record == expected);
}

bool baseline_target_absent(
    const NdmsNativeImportPersistedBaseline& baseline) noexcept {
    if (baseline.occupancy_hex.size() !=
        kNdmsNativeImportOccupancyHexCharacters) {
        return false;
    }
    const auto slot = baseline.expected_target_slot;
    const auto character = baseline.occupancy_hex[
        static_cast<std::size_t>(slot / 8U) * 2U +
        ((slot % 8U) >= 4U ? 0U : 1U)];
    std::uint8_t nibble = 0U;
    if (character >= '0' && character <= '9') {
        nibble = static_cast<std::uint8_t>(character - '0');
    } else if (character >= 'a' && character <= 'f') {
        nibble = static_cast<std::uint8_t>(character - 'a' + 10);
    } else {
        return false;
    }
    const auto bit = static_cast<std::uint8_t>(1U << (slot % 4U));
    return (nibble & bit) == 0U;
}

bool stamp_matches_scoped_measurement(
    const NdmsNativeObservationBinding& binding,
    const NdmsNativeDirectRecoveryObservation& measured,
    const NdmsNativeObservationStamp& stamp) noexcept {
    return valid_ndms_native_observation_stamp(stamp) &&
           stamp.authority_id == binding.authority_id &&
           stamp.mutation_epoch == binding.mutation_epoch &&
           stamp.sequence > binding.baseline_sequence &&
           stamp.catalog_revision == measured.catalog_revision;
}

bool scoped_sightings_agree(
    const NdmsNativeImportRecoveryCatalogProbe& runtime,
    const NdmsNativeImportRecoveryCatalogProbe& running) noexcept {
    if (runtime.marker_sightings.size() !=
        running.marker_sightings.size()) {
        return false;
    }
    for (std::size_t index = 0U;
         index < runtime.marker_sightings.size(); ++index) {
        const auto& left = runtime.marker_sightings[index];
        const auto& right = running.marker_sightings[index];
        if (left.interface_name != right.interface_name ||
            left.link_down != right.link_down ||
            left.full_revision != right.full_revision) {
            return false;
        }
    }
    return true;
}

std::optional<std::string> measured_target_kernel_interface(
    const NdmsNativeDirectRecoveryObservation& measured,
    const std::string& expected_interface) noexcept {
    if (!measured.snapshot.has_value()) return std::nullopt;

    std::optional<std::string> kernel_interface;
    std::size_t matches = 0U;
    for (const auto& tunnel : measured.snapshot->catalog.tunnels) {
        if (tunnel.firmware_interface_name != expected_interface) continue;
        ++matches;
        if (matches != 1U || !tunnel.kernel_name.has_value() ||
            !safe_kernel_interface_name(*tunnel.kernel_name)) {
            return std::nullopt;
        }
        kernel_interface = *tunnel.kernel_name;
    }
    return matches == 1U ? kernel_interface : std::nullopt;
}

std::optional<std::string> scoped_target_kernel_interface(
    const NdmsNativeDirectRecoveryObservation& runtime_measured,
    const NdmsNativeDirectRecoveryObservation& running_measured,
    const std::string& expected_interface) noexcept {
    const auto runtime = measured_target_kernel_interface(
        runtime_measured, expected_interface);
    const auto running = measured_target_kernel_interface(
        running_measured, expected_interface);
    if (!runtime.has_value() || !running.has_value() ||
        *runtime != *running) {
        return std::nullopt;
    }
    return runtime;
}

struct ScopedForwardProof final {
    NdmsNativeImportRecoveryObservation observation;
    std::optional<std::string> created_kernel_interface;
};

// Runtime-state and running-config catalog documents are different RCI
// representations, so their structural catalog revisions are not expected
// to be byte-identical.  This coordinator binds each exact document to its
// own durable stamp, then compares only the facts that are meaningful across
// both scopes: complete slot occupancy, the exact marker sighting, link state
// and the direct config/runtime/ASC full revision.  Runtime structural
// evidence remains the one compared with the runtime baseline.
ScopedForwardProof build_scoped_forward_observation(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeDirectRecoveryObservation& runtime_measured,
    const NdmsNativeImportRecoveryCatalogProbe& runtime_probe,
    const NdmsNativeDirectRecoveryObservation& running_measured,
    const NdmsNativeImportRecoveryCatalogProbe& running_probe,
    const std::optional<std::string>& published_ownership_revision) {
    ScopedForwardProof proof;
    auto& observation = proof.observation;
    const auto& binding = record.observation_binding;
    const auto kernel_interface = scoped_target_kernel_interface(
        runtime_measured,
        running_measured,
        record.baseline.expected_created_interface);
    if (!valid_ndms_native_observation_binding(binding) ||
        !runtime_measured.complete() || !running_measured.complete() ||
        runtime_measured.requested_catalog_scope !=
            NdmsNativeDirectCatalogScope::runtime_state ||
        runtime_measured.catalog_scope !=
            NdmsNativeDirectCatalogScope::runtime_state ||
        running_measured.requested_catalog_scope !=
            NdmsNativeDirectCatalogScope::running_config ||
        running_measured.catalog_scope !=
            NdmsNativeDirectCatalogScope::running_config ||
        !runtime_probe.marker_scan_complete ||
        !running_probe.marker_scan_complete ||
        !stamp_matches_scoped_measurement(
            binding, runtime_measured,
            runtime_probe.durable_observation) ||
        !stamp_matches_scoped_measurement(
            binding, running_measured,
            running_probe.durable_observation) ||
        running_probe.durable_observation.sequence <=
            runtime_probe.durable_observation.sequence ||
        !runtime_measured.snapshot.has_value() ||
        !running_measured.snapshot.has_value() ||
        occupancy_of(runtime_measured.snapshot->catalog) !=
            occupancy_of(running_measured.snapshot->catalog) ||
        runtime_probe.protected_catalog_sha256 !=
            record.baseline.protected_catalog_sha256 ||
        !scoped_sightings_agree(runtime_probe, running_probe) ||
        runtime_probe.marker_sightings.size() > 1U ||
        !kernel_interface.has_value()) {
        return proof;
    }

    observation.authoritative = true;
    observation.generation_advanced = true;
    observation.protected_catalog_unchanged = true;
    observation.marker_match_count =
        runtime_probe.marker_sightings.size();
    observation.stable_absence =
        runtime_probe.marker_sightings.empty();
    if (!runtime_probe.marker_sightings.empty()) {
        const auto& sighting = runtime_probe.marker_sightings.front();
        observation.marker_target = sighting.interface_name;
        observation.target_absent_in_baseline =
            baseline_target_absent(record.baseline);
        observation.target_down = sighting.link_down;
        observation.target_fingerprint_matches =
            record.target_full_revision.has_value() &&
            *record.target_full_revision == sighting.full_revision;
    }
    observation.ownership_record_matches =
        record.ownership_revision.has_value() &&
        published_ownership_revision.has_value() &&
        *record.ownership_revision ==
            *published_ownership_revision;
    proof.created_kernel_interface = kernel_interface;
    return proof;
}

bool exact_created_observation(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryObservation& observation,
    const std::optional<std::string>& measured_revision) noexcept {
    return observation.authoritative &&
           observation.generation_advanced &&
           observation.protected_catalog_unchanged &&
           observation.marker_match_count == 1U &&
           observation.marker_target.has_value() &&
           *observation.marker_target ==
               record.baseline.expected_created_interface &&
           observation.target_absent_in_baseline &&
           observation.target_down &&
           observation.target_fingerprint_matches &&
           measured_revision.has_value() &&
           record.target_full_revision.has_value() &&
           *measured_revision == *record.target_full_revision;
}

bool expected_forward_steps(
    const NdmsNativeImportWalPhase phase,
    const std::vector<NdmsNativeImportRecoveryStep>& steps) {
    using Step = NdmsNativeImportRecoveryStep;
    if (phase == NdmsNativeImportWalPhase::response_recorded) {
        return steps == std::vector<Step>{
                            Step::advance_wal_target_verified,
                            Step::publish_ownership,
                            Step::advance_wal_ownership_published,
                            Step::remove_wal_record};
    }
    if (phase == NdmsNativeImportWalPhase::target_verified) {
        return steps == std::vector<Step>{
                            Step::publish_ownership,
                            Step::advance_wal_ownership_published,
                            Step::remove_wal_record};
    }
    if (phase == NdmsNativeImportWalPhase::ownership_published) {
        return steps == std::vector<Step>{Step::remove_wal_record};
    }
    return false;
}

} // namespace

struct NdmsNativeCooperativeImportCoordinator::Impl final {
    Impl(NdmsNativeObservationStore& observations_value,
         NdmsNativeImportWalStore& wal_value,
         NdmsNativeDeleteWalStore& delete_wal_value,
         NdmsNativeSecretSnapshotStore& snapshots_value,
         NdmsNativeOwnershipStore& ownership_value)
        : observations(&observations_value),
          wal(&wal_value),
          delete_wal(&delete_wal_value),
          snapshots(&snapshots_value),
          ownership(&ownership_value),
          owned_gateway(
              std::make_unique<DirectObservationGatewayAdapter>()),
          owned_transport(std::make_unique<
                          NdmsNativeLibcurlLoopbackRciPostBackend>()),
          owned_clock(
              std::make_unique<NdmsNativeImportSteadyClock>()),
          gateway(owned_gateway.get()),
          transport(owned_transport.get()),
          clock(owned_clock.get()) {}

    Impl(NdmsNativeObservationStore& observations_value,
         NdmsNativeImportWalStore& wal_value,
         NdmsNativeDeleteWalStore& delete_wal_value,
         NdmsNativeSecretSnapshotStore& snapshots_value,
         NdmsNativeOwnershipStore& ownership_value,
         NdmsNativeCooperativeImportObservationGateway& gateway_value,
         NdmsNativeLoopbackRciPostBackend& transport_value,
         NdmsNativeImportExecutorClock& clock_value)
        : observations(&observations_value),
          wal(&wal_value),
          delete_wal(&delete_wal_value),
          snapshots(&snapshots_value),
          ownership(&ownership_value),
          gateway(&gateway_value),
          transport(&transport_value),
          clock(&clock_value) {}

    NdmsNativeObservationStore* observations{nullptr};
    NdmsNativeImportWalStore* wal{nullptr};
    NdmsNativeDeleteWalStore* delete_wal{nullptr};
    NdmsNativeSecretSnapshotStore* snapshots{nullptr};
    NdmsNativeOwnershipStore* ownership{nullptr};
    std::unique_ptr<NdmsNativeCooperativeImportObservationGateway>
        owned_gateway;
    std::unique_ptr<NdmsNativeLoopbackRciPostBackend> owned_transport;
    std::unique_ptr<NdmsNativeImportExecutorClock> owned_clock;
    NdmsNativeCooperativeImportObservationGateway* gateway{nullptr};
    NdmsNativeLoopbackRciPostBackend* transport{nullptr};
    NdmsNativeImportExecutorClock* clock{nullptr};
};

NdmsNativeCooperativeImportCoordinator::
NdmsNativeCooperativeImportCoordinator(
    NdmsNativeObservationStore& observations,
    NdmsNativeImportWalStore& wal,
    NdmsNativeDeleteWalStore& delete_wal,
    NdmsNativeSecretSnapshotStore& snapshots,
    NdmsNativeOwnershipStore& ownership)
    : impl_(std::make_unique<Impl>(
          observations, wal, delete_wal, snapshots, ownership)) {}

NdmsNativeCooperativeImportCoordinator::
NdmsNativeCooperativeImportCoordinator(
    std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

NdmsNativeCooperativeImportCoordinator::
~NdmsNativeCooperativeImportCoordinator() = default;

NdmsNativeCooperativeImportCoordinator::
NdmsNativeCooperativeImportCoordinator(
    NdmsNativeCooperativeImportCoordinator&&) noexcept = default;

NdmsNativeCooperativeImportCoordinator&
NdmsNativeCooperativeImportCoordinator::operator=(
    NdmsNativeCooperativeImportCoordinator&&) noexcept = default;

NdmsNativeCooperativeImportResult
NdmsNativeCooperativeImportCoordinator::import_once(
    NdmsNativeWriterLease& writer,
    std::string&& raw_configuration,
    const NdmsNativeExternalWriterRaceAcceptance race_acceptance) noexcept {
    // The rvalue-only boundary adopts the secret even when admission stops
    // before parsing. Consent, cross-kind WAL and writer failures therefore
    // cannot return a caller buffer containing the private key.
    WipeStringGuard raw_guard(raw_configuration);
    const bool race_accepted =
        race_acceptance ==
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted;
    if (!race_accepted) {
        return blocked_result(
            NdmsNativeCooperativeImportStop::
                external_writer_race_not_accepted,
            false);
    }
    if (!impl_ || !impl_->observations || !impl_->wal ||
        !impl_->delete_wal ||
        !impl_->snapshots || !impl_->ownership || !impl_->gateway ||
        !impl_->transport || !impl_->clock) {
        return blocked_result(
            NdmsNativeCooperativeImportStop::unexpected_failure, true);
    }
    if (!writer.held()) {
        return blocked_result(
            NdmsNativeCooperativeImportStop::writer_missing, true);
    }
    try {
        writer.verify_held();
    } catch (...) {
        return blocked_result(
            NdmsNativeCooperativeImportStop::writer_lost, true);
    }

    NdmsNativeCooperativeImportResult result;
    result.external_ndms_writer_race_accepted = true;

    // The cooperative writer serializes every keen-pbr native mutation, so
    // this clean check cannot race another cooperating delete admission.
    // Any unfinished or unreadable delete WAL blocks before direct reads,
    // durable observation changes, import WAL publication or RCI dispatch.
    result.delete_wal_readiness = impl_->delete_wal->readiness();
    if (*result.delete_wal_readiness !=
        NdmsNativeDeleteWalReadiness::clean) {
        result.stop =
            NdmsNativeCooperativeImportStop::delete_wal_not_clean;
        return result;
    }

    // publish_prepared_exclusive() inside the executor is the final atomic
    // admission, but waiting until then would be too late: begin_mutation()
    // below advances the durable epoch. Advancing it while an older import
    // WAL still binds the previous epoch would strand that recovery. Under
    // the same cooperative writer, require a complete empty inventory first.
    NdmsNativeImportWalInventory import_inventory;
    try {
        import_inventory = impl_->wal->try_inventory();
    } catch (...) {
        result.import_wal_readiness =
            NdmsNativeCooperativeImportWalReadiness::unsafe;
        result.stop =
            NdmsNativeCooperativeImportStop::import_wal_not_clean;
        return result;
    }
    const bool import_wal_clean =
        (import_inventory.state ==
             NdmsNativeImportWalInventoryState::absent ||
         import_inventory.state ==
             NdmsNativeImportWalInventoryState::ready) &&
        import_inventory.items.empty();
    result.import_wal_readiness = import_wal_clean
        ? NdmsNativeCooperativeImportWalReadiness::clean
        : (import_inventory.recovery_permitted() &&
           !import_inventory.items.empty()
               ? NdmsNativeCooperativeImportWalReadiness::unfinished
               : NdmsNativeCooperativeImportWalReadiness::unsafe);
    if (!import_wal_clean) {
        result.stop =
            NdmsNativeCooperativeImportStop::import_wal_not_clean;
        return result;
    }

    try {
        auto prepared = prepare_ndms_native_import(
            std::move(raw_configuration));
        const auto& identity = prepared.request_identity();
        const auto transaction_id = std::string{identity.transaction_id()};
        const auto marker = std::string{identity.marker()};
        const auto kind = identity.kind();
        result.transaction_id = transaction_id;
        result.kind = kind;

        // Both direct scopes are read before the first durable intent. The
        // running-config endpoint describes current NDMS running config only;
        // it is deliberately not described as saved or persistent state.
        auto runtime_catalog = impl_->gateway->observe_catalog(
            NdmsNativeDirectCatalogScope::runtime_state);
        if (runtime_catalog.failure !=
                NdmsNativeDirectObservationFailure::none ||
            !runtime_catalog.snapshot.has_value()) {
            result.stop = NdmsNativeCooperativeImportStop::
                runtime_catalog_failed;
            result.direct_observation_failure = runtime_catalog.failure;
            return result;
        }
        auto running_catalog = impl_->gateway->observe_catalog(
            NdmsNativeDirectCatalogScope::running_config);
        if (running_catalog.failure !=
                NdmsNativeDirectObservationFailure::none ||
            !running_catalog.snapshot.has_value()) {
            result.stop = NdmsNativeCooperativeImportStop::
                running_config_catalog_failed;
            result.direct_observation_failure = running_catalog.failure;
            return result;
        }
        if (!safe_direct_catalog(runtime_catalog) ||
            !safe_direct_catalog(running_catalog)) {
            result.stop = NdmsNativeCooperativeImportStop::
                prewrite_catalog_unsafe;
            return result;
        }

        const auto runtime_occupancy = occupancy_of(
            runtime_catalog.snapshot->catalog);
        const auto running_occupancy = occupancy_of(
            running_catalog.snapshot->catalog);
        if (runtime_occupancy != running_occupancy ||
            first_free_slot(runtime_occupancy) !=
                first_free_slot(running_occupancy)) {
            result.stop = NdmsNativeCooperativeImportStop::
                prewrite_catalog_diverged;
            return result;
        }
        if (catalog_contains_marker(
                runtime_catalog.snapshot->catalog, marker) ||
            catalog_contains_marker(
                running_catalog.snapshot->catalog, marker)) {
            result.stop =
                NdmsNativeCooperativeImportStop::marker_collision;
            return result;
        }

        const auto first_free = first_free_slot(runtime_occupancy);
        if (!first_free.has_value() || *first_free < 5U ||
            *first_free > 98U) {
            result.stop = NdmsNativeCooperativeImportStop::
                first_free_target_not_managed;
            return result;
        }
        const auto expected_interface =
            NdmsWireguardIdentity{
                *first_free,
                NdmsWireguardSlotClass::managed_candidate}
                .canonical_name();
        result.expected_interface = expected_interface;

        NdmsNativeObservationStamp baseline_stamp;
        NdmsNativeMutationEpoch mutation;
        try {
            static_cast<void>(impl_->observations->provision(writer));
            baseline_stamp = impl_->observations->record_observation(
                writer,
                ndms_native_import_baseline_catalog_revision(
                    runtime_catalog.snapshot->catalog));
            mutation = impl_->observations->begin_mutation(
                writer, baseline_stamp);
        } catch (...) {
            result.stop = NdmsNativeCooperativeImportStop::
                durable_observation_failed;
            return result;
        }
        const auto binding = ndms_native_observation_binding(mutation);
        const auto baseline =
            build_ndms_native_cooperative_import_baseline(
                *runtime_catalog.snapshot,
                expected_interface,
                writer.maintenance_base_generation(),
                baseline_stamp,
                binding);
        if (!baseline.success() || !baseline.evidence.has_value()) {
            result.stop = NdmsNativeCooperativeImportStop::
                cooperative_baseline_failed;
            result.baseline_error = baseline.error;
            return result;
        }

        auto cooperative = admit_ndms_native_cooperative_import_writer(
            writer, *impl_->observations, binding);
        if (!cooperative.admitted()) {
            result.stop = NdmsNativeCooperativeImportStop::
                cooperative_writer_admission_failed;
            return result;
        }

        NdmsNativeImportExecutionPlan execution_plan;
        execution_plan.execution_mode =
            NdmsNativeImportExecutionMode::cooperative_stock_import;
        execution_plan.expected_created_interface = expected_interface;
        execution_plan.generation_ticket = generation_ticket(
            transaction_id, marker, expected_interface, binding);
        execution_plan.observation_binding = binding;

        NdmsNativeImportWalStorePublisher wal_publisher{*impl_->wal};
        SecretSnapshotStorePublisher snapshot_publisher{*impl_->snapshots};
        CooperativeGenerationCoordinator generations{writer};
        NdmsNativeImportExecutorDependencies dependencies{
            &wal_publisher,
            &snapshot_publisher,
            &generations,
            impl_->transport,
            impl_->clock};

        const auto executed = execute_ndms_native_import_transaction(
            std::move(prepared),
            execution_plan,
            *baseline.evidence,
            std::nullopt,
            std::move(cooperative.writer),
            dependencies);
        result.request_may_have_been_dispatched =
            executed.request_may_have_been_dispatched;
        result.rollback_snapshot_may_be_retained =
            executed.snapshot_published ||
            executed.prepared_wal_published;
        result.executor_stop = executed.stop;
        if (executed.status != NdmsNativeImportExecutionStatus::
                response_recorded_needs_verification) {
            if (executed.status ==
                NdmsNativeImportExecutionStatus::recovery_required) {
                mark_recovery_required(
                    result,
                    NdmsNativeCooperativeImportStop::executor_blocked);
            } else {
                result.stop = NdmsNativeCooperativeImportStop::
                    executor_blocked;
            }
            return result;
        }

        const auto loaded = impl_->wal->load(transaction_id);
        if (loaded.state != NdmsNativeImportWalLoadState::valid ||
            !loaded.record.has_value() ||
            loaded.record->phase !=
                NdmsNativeImportWalPhase::response_recorded ||
            loaded.record->transaction_id != transaction_id ||
            loaded.record->marker != marker ||
            loaded.record->kind != kind ||
            loaded.record->baseline.expected_created_interface !=
                expected_interface ||
            !(loaded.record->observation_binding == binding)) {
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::wal_record_unavailable);
            return result;
        }
        auto record = *loaded.record;

        writer.verify_held();
        auto earlier = impl_->gateway->observe_recovery(
            NdmsNativeDirectCatalogScope::runtime_state,
            marker, expected_interface);
        if (!earlier.complete()) {
            result.direct_observation_failure = earlier.failure;
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::
                    first_post_observation_failed);
            return result;
        }
        if (!kind_matches_protocol(earlier, expected_interface, kind)) {
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::
                    post_observation_kind_mismatch);
            return result;
        }
        NdmsNativeObservationStamp earlier_stamp;
        try {
            earlier_stamp =
                impl_->observations->record_mutation_observation(
                    writer, mutation, earlier.catalog_revision);
        } catch (...) {
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::
                    first_post_observation_failed);
            return result;
        }
        const auto earlier_probe =
            build_ndms_native_import_recovery_probe(
                *earlier.snapshot,
                earlier_stamp,
                *first_free,
                marker,
                earlier.target_evidence);

        writer.verify_held();
        auto later = impl_->gateway->observe_recovery(
            NdmsNativeDirectCatalogScope::running_config,
            marker, expected_interface);
        if (!later.complete()) {
            result.direct_observation_failure = later.failure;
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::
                    second_post_observation_failed);
            return result;
        }
        if (!kind_matches_protocol(later, expected_interface, kind)) {
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::
                    post_observation_kind_mismatch);
            return result;
        }
        NdmsNativeObservationStamp later_stamp;
        try {
            later_stamp =
                impl_->observations->record_mutation_observation(
                    writer, mutation, later.catalog_revision);
        } catch (...) {
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::
                    second_post_observation_failed);
            return result;
        }
        const auto later_probe =
            build_ndms_native_import_recovery_probe(
                *later.snapshot,
                later_stamp,
                *first_free,
                marker,
                later.target_evidence);

        const auto measured_revision = measured_target_revision(
            later, expected_interface);
        if (!measured_revision.has_value()) {
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::
                    post_observation_unstable);
            return result;
        }
        const auto scoped_proof =
            build_scoped_forward_observation(
                record,
                earlier,
                earlier_probe,
                later,
                later_probe,
                std::nullopt);
        const auto& observation = scoped_proof.observation;
        const auto completion =
            plan_ndms_native_import_forward_completion(
                record, observation, *measured_revision);
        const std::vector<NdmsNativeImportRecoveryStep> expected_steps{
            NdmsNativeImportRecoveryStep::
                advance_wal_target_verified,
            NdmsNativeImportRecoveryStep::publish_ownership,
            NdmsNativeImportRecoveryStep::
                advance_wal_ownership_published,
            NdmsNativeImportRecoveryStep::remove_wal_record,
        };
        if (!scoped_proof.created_kernel_interface.has_value() ||
            !completion.actionable() ||
            completion.plan.steps != expected_steps) {
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::
                    forward_completion_blocked);
            return result;
        }

        // Only now is "created" a measured fact rather than the stock
        // allocator target we predicted before dispatch.
        result.created_interface = expected_interface;
        result.created_kernel_interface =
            scoped_proof.created_kernel_interface;

        auto forward_admission = admit_ndms_native_import_forward(
            *impl_->wal, record, completion);
        result.forward_admission_state = forward_admission.state;
        if (forward_admission.state !=
                NdmsNativeImportRecoveryAdmissionState::admitted ||
            !forward_admission.lease.held()) {
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::
                    forward_admission_failed);
            return result;
        }

        const auto step_guard = [this, &writer, &binding, &later_stamp](
            const NdmsNativeImportRecoveryStep) {
            // The recovery/forward flock supplies same-WAL CAS. The composite
            // writer and exact latest durable observation are independently
            // revalidated immediately before every durable forward phase.
            writer.verify_held();
            if (!durable_forward_observation_is_current(
                    *impl_->observations, binding, later_stamp)) {
                throw std::runtime_error(
                    "native forward observation changed");
            }
        };

        NdmsNativeImportRecoveryDispatchResult dispatched;
        try {
            dispatched = dispatch_ndms_native_import_recovery(
                *impl_->wal,
                forward_admission.lease,
                completion.enriched,
                completion.plan,
                observation.marker_target,
                {},
                impl_->ownership,
                step_guard,
                nullptr);
        } catch (...) {
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::
                    forward_completion_blocked);
            return result;
        }
        result.forward_dispatch_state = dispatched.state;
        result.forward_failed_step = dispatched.failed_step;

        NdmsNativeOwnershipRecord expected_ownership;
        expected_ownership.interface_name = expected_interface;
        expected_ownership.transaction_id = transaction_id;
        expected_ownership.marker = marker;
        expected_ownership.kind = kind;
        expected_ownership.snapshot_revision =
            completion.enriched.snapshot_revision;
        expected_ownership.target_full_revision = *measured_revision;
        if (dispatched.state !=
            NdmsNativeImportRecoveryDispatchState::completed) {
            try {
                const auto published_ownership =
                    impl_->ownership->read(expected_interface);
                result.ownership_published =
                    published_ownership.state ==
                        NdmsNativeOwnershipReadState::valid &&
                    published_ownership.record.has_value() &&
                    *published_ownership.record == expected_ownership;
            } catch (...) {
                result.ownership_published = false;
            }
            mark_recovery_required(
                result, dispatch_stop(dispatched.failed_step));
            return result;
        }
        // A completed forward plan contains publish_ownership followed by an
        // ownership-revision WAL advance and exact WAL removal. The dispatcher
        // cannot report completed if any of those steps failed.
        result.ownership_published = true;

        result.status = NdmsNativeCooperativeImportStatus::completed;
        result.stop = NdmsNativeCooperativeImportStop::none;
        result.wal_may_require_recovery = false;
        result.rollback_snapshot_may_be_retained = true;
        return result;
    } catch (const NdmsNativeTunnelImportError& error) {
        result.stop = NdmsNativeCooperativeImportStop::request_invalid;
        result.request_error = error.code();
        return result;
    } catch (...) {
        if (result.request_may_have_been_dispatched ||
            result.rollback_snapshot_may_be_retained ||
            result.ownership_published) {
            mark_recovery_required(
                result,
                NdmsNativeCooperativeImportStop::unexpected_failure);
        } else {
            result.stop =
                NdmsNativeCooperativeImportStop::unexpected_failure;
        }
        return result;
    }
}

NdmsNativeCooperativeImportResumeResult
NdmsNativeCooperativeImportCoordinator::resume_once(
    NdmsNativeWriterLease& writer) noexcept {
    NdmsNativeCooperativeImportResumeResult result;
    if (!impl_ || !impl_->observations || !impl_->wal ||
        !impl_->delete_wal || !impl_->ownership || !impl_->gateway) {
        result.stop = NdmsNativeCooperativeImportResumeStop::
            unexpected_failure;
        return result;
    }
    if (!writer.held()) {
        result.stop =
            NdmsNativeCooperativeImportResumeStop::writer_missing;
        return result;
    }
    try {
        writer.verify_held();
    } catch (...) {
        result.stop = NdmsNativeCooperativeImportResumeStop::writer_lost;
        return result;
    }

    try {
        // Cross-kind order is identical to fresh import admission: the
        // already-held global writer, then delete WAL, then import WAL.  No
        // direct read or durable observation is allowed before both stores
        // have been bounded and the delete side is exactly clean.
        result.delete_wal_readiness = impl_->delete_wal->readiness();
        if (*result.delete_wal_readiness !=
            NdmsNativeDeleteWalReadiness::clean) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                delete_wal_not_clean;
            return result;
        }

        const auto inventory = impl_->wal->try_inventory();
        result.import_wal_readiness = import_wal_readiness(inventory);
        if (*result.import_wal_readiness ==
                NdmsNativeCooperativeImportWalReadiness::clean) {
            result.status =
                NdmsNativeCooperativeImportResumeStatus::no_work;
            result.stop = NdmsNativeCooperativeImportResumeStop::none;
            return result;
        }
        if (!inventory.recovery_permitted() ||
            inventory.items.size() != 1U ||
            !inventory.items.front().record.has_value() ||
            !inventory.items.front().transaction_id.has_value() ||
            inventory.items.front().record->transaction_id !=
                *inventory.items.front().transaction_id) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                import_wal_not_single_safe;
            return result;
        }

        const auto record = *inventory.items.front().record;
        result.transaction_id = record.transaction_id;
        result.expected_interface =
            record.baseline.expected_created_interface;
        result.kind = record.kind;
        result.phase = record.phase;
        result.wal_may_require_recovery = true;

        if (record.execution_mode !=
            NdmsNativeImportExecutionMode::cooperative_stock_import) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                record_not_cooperative;
            return result;
        }
        if (!forward_only_phase(record.phase)) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                phase_not_forward_only;
            return result;
        }

        const auto target_identity = parse_ndms_wireguard_identity(
            record.baseline.expected_created_interface);
        if (!target_identity.has_value() ||
            !ndms_wireguard_identity_is_managed_candidate(
                *target_identity) ||
            target_identity->slot !=
                record.baseline.expected_target_slot ||
            (record.created_interface.has_value() &&
             *record.created_interface !=
                 record.baseline.expected_created_interface)) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                expected_target_not_managed;
            return result;
        }

        writer.verify_held();
        auto runtime_measured = impl_->gateway->observe_recovery(
            NdmsNativeDirectCatalogScope::runtime_state,
            record.marker,
            record.baseline.expected_created_interface);
        if (!runtime_measured.complete()) {
            result.direct_observation_failure = runtime_measured.failure;
            result.stop = NdmsNativeCooperativeImportResumeStop::
                first_observation_failed;
            return result;
        }
        if (!kind_matches_protocol(
                runtime_measured,
                record.baseline.expected_created_interface,
                record.kind)) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                observation_kind_mismatch;
            return result;
        }
        NdmsNativeObservationStamp runtime_stamp;
        try {
            runtime_stamp = impl_->observations->
                record_recovery_observation(
                    writer,
                    record.observation_binding,
                    runtime_measured.catalog_revision);
        } catch (...) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                durable_observation_failed;
            return result;
        }
        const auto runtime_probe =
            build_ndms_native_import_recovery_probe(
                *runtime_measured.snapshot,
                runtime_stamp,
                target_identity->slot,
                record.marker,
                runtime_measured.target_evidence);

        writer.verify_held();
        auto running_measured = impl_->gateway->observe_recovery(
            NdmsNativeDirectCatalogScope::running_config,
            record.marker,
            record.baseline.expected_created_interface);
        if (!running_measured.complete()) {
            result.direct_observation_failure = running_measured.failure;
            result.stop = NdmsNativeCooperativeImportResumeStop::
                second_observation_failed;
            return result;
        }
        if (!kind_matches_protocol(
                running_measured,
                record.baseline.expected_created_interface,
                record.kind)) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                observation_kind_mismatch;
            return result;
        }
        NdmsNativeObservationStamp running_stamp;
        try {
            running_stamp = impl_->observations->
                record_recovery_observation(
                    writer,
                    record.observation_binding,
                    running_measured.catalog_revision);
        } catch (...) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                durable_observation_failed;
            return result;
        }
        const auto running_probe =
            build_ndms_native_import_recovery_probe(
                *running_measured.snapshot,
                running_stamp,
                target_identity->slot,
                record.marker,
                running_measured.target_evidence);

        const auto existing_ownership = impl_->ownership->read(
            record.baseline.expected_created_interface);
        const auto published_ownership_revision =
            existing_ownership.state ==
                    NdmsNativeOwnershipReadState::valid
                ? existing_ownership.revision
                : std::optional<std::string>{};
        const auto scoped_proof = build_scoped_forward_observation(
            record,
            runtime_measured,
            runtime_probe,
            running_measured,
            running_probe,
            published_ownership_revision);
        const auto& observation = scoped_proof.observation;
        const auto running_revision = measured_target_revision(
            running_measured,
            record.baseline.expected_created_interface);

        if (!scoped_proof.created_kernel_interface.has_value()) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                observation_unstable;
            return result;
        }

        NdmsNativeImportWalRecord dispatch_record = record;
        NdmsNativeImportRecoveryPlan forward_plan;
        std::optional<NdmsNativeImportRecoveryAdmission>
            forward_admission;
        std::optional<NdmsNativeOwnershipRecord> expected_ownership;

        if (record.phase ==
            NdmsNativeImportWalPhase::ownership_published) {
            result.recovery_action =
                classify_ndms_native_import_recovery(
                    record, observation);
            expected_ownership = ownership_claim_from(record);
            if (!expected_ownership.has_value() ||
                existing_ownership.state !=
                    NdmsNativeOwnershipReadState::valid ||
                !existing_ownership.record.has_value() ||
                !(*existing_ownership.record ==
                  *expected_ownership) ||
                !existing_ownership.revision.has_value() ||
                !record.ownership_revision.has_value() ||
                *existing_ownership.revision !=
                    *record.ownership_revision) {
                result.stop = NdmsNativeCooperativeImportResumeStop::
                    ownership_not_exact;
                return result;
            }
            if (!exact_created_observation(
                    record, observation, running_revision) ||
                *result.recovery_action !=
                    NdmsNativeImportRecoveryAction::
                        resume_forward_reconcile) {
                result.stop = NdmsNativeCooperativeImportResumeStop::
                    recovery_action_not_forward_only;
                return result;
            }
            forward_plan = plan_ndms_native_import_recovery(
                record, *result.recovery_action);
            if (!forward_plan.actionable() ||
                !expected_forward_steps(record.phase,
                                        forward_plan.steps)) {
                result.stop = NdmsNativeCooperativeImportResumeStop::
                    recovery_action_not_forward_only;
                return result;
            }
            result.created_interface =
                record.baseline.expected_created_interface;
            result.created_kernel_interface =
                scoped_proof.created_kernel_interface;
            result.ownership_published = true;
            forward_admission.emplace(
                admit_ndms_native_import_recovery(
                    *impl_->wal, record, observation));
        } else {
            const auto completion =
                plan_ndms_native_import_forward_completion(
                    record,
                    observation,
                    running_revision.value_or(std::string{}));
            if (!completion.actionable() ||
                !expected_forward_steps(
                    record.phase, completion.plan.steps)) {
                if (observation.authoritative) {
                    result.recovery_action =
                        classify_ndms_native_import_recovery(
                            record, observation);
                    result.stop = NdmsNativeCooperativeImportResumeStop::
                        recovery_action_not_forward_only;
                } else {
                    result.stop = NdmsNativeCooperativeImportResumeStop::
                        observation_unstable;
                }
                return result;
            }
            expected_ownership = ownership_claim_from(
                completion.enriched);
            if (!expected_ownership.has_value() ||
                !exact_existing_claim_or_absent(
                    existing_ownership, *expected_ownership)) {
                result.stop = NdmsNativeCooperativeImportResumeStop::
                    ownership_not_exact;
                return result;
            }
            result.created_interface =
                record.baseline.expected_created_interface;
            result.created_kernel_interface =
                scoped_proof.created_kernel_interface;
            result.ownership_published =
                existing_ownership.state ==
                NdmsNativeOwnershipReadState::valid;
            forward_admission.emplace(
                admit_ndms_native_import_forward(
                    *impl_->wal, record, completion));
            dispatch_record = completion.enriched;
            forward_plan = completion.plan;
        }

        result.forward_admission_state = forward_admission->state;
        if (forward_admission->state !=
                NdmsNativeImportRecoveryAdmissionState::admitted ||
            !forward_admission->lease.held()) {
            result.stop = NdmsNativeCooperativeImportResumeStop::
                forward_admission_failed;
            return result;
        }

        const auto step_guard = [this, &writer, &record, &running_stamp](
            const NdmsNativeImportRecoveryStep) {
            writer.verify_held();
            if (!durable_forward_observation_is_current(
                    *impl_->observations,
                    record.observation_binding,
                    running_stamp)) {
                throw std::runtime_error(
                    "native resume observation changed");
            }
        };
        const auto dispatched = dispatch_ndms_native_import_recovery(
            *impl_->wal,
            forward_admission->lease,
            dispatch_record,
            forward_plan,
            observation.marker_target,
            {},
            impl_->ownership,
            step_guard,
            nullptr);
        result.forward_dispatch_state = dispatched.state;
        result.forward_failed_step = dispatched.failed_step;
        if (dispatched.state !=
            NdmsNativeImportRecoveryDispatchState::completed) {
            if (expected_ownership.has_value()) {
                const auto current = impl_->ownership->read(
                    expected_ownership->interface_name);
                result.ownership_published =
                    current.state ==
                        NdmsNativeOwnershipReadState::valid &&
                    current.record.has_value() &&
                    *current.record == *expected_ownership;
            }
            result.stop = resume_dispatch_stop(
                dispatched.failed_step);
            return result;
        }

        result.status =
            NdmsNativeCooperativeImportResumeStatus::completed;
        result.stop = NdmsNativeCooperativeImportResumeStop::none;
        result.wal_may_require_recovery = false;
        result.ownership_published = true;
        result.wal_removed = true;
        return result;
    } catch (...) {
        result.stop =
            NdmsNativeCooperativeImportResumeStop::unexpected_failure;
        return result;
    }
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeCooperativeImportCoordinator
NdmsNativeCooperativeImportCoordinatorTestIssuer::issue(
    NdmsNativeObservationStore& observations,
    NdmsNativeImportWalStore& wal,
    NdmsNativeDeleteWalStore& delete_wal,
    NdmsNativeSecretSnapshotStore& snapshots,
    NdmsNativeOwnershipStore& ownership,
    NdmsNativeCooperativeImportObservationGateway& gateway,
    NdmsNativeLoopbackRciPostBackend& transport,
    NdmsNativeImportExecutorClock& clock) {
    return NdmsNativeCooperativeImportCoordinator{
        std::make_unique<NdmsNativeCooperativeImportCoordinator::Impl>(
            observations,
            wal,
            delete_wal,
            snapshots,
            ownership,
            gateway,
            transport,
            clock)};
}
#endif

const char* ndms_native_cooperative_import_status_name(
    const NdmsNativeCooperativeImportStatus status) noexcept {
    switch (status) {
    case NdmsNativeCooperativeImportStatus::blocked:
        return "blocked";
    case NdmsNativeCooperativeImportStatus::recovery_required:
        return "recovery_required";
    case NdmsNativeCooperativeImportStatus::completed:
        return "completed";
    }
    return "blocked";
}

const char* ndms_native_cooperative_import_stop_name(
    const NdmsNativeCooperativeImportStop stop) noexcept {
    switch (stop) {
    case NdmsNativeCooperativeImportStop::none:
        return "none";
    case NdmsNativeCooperativeImportStop::
        external_writer_race_not_accepted:
        return "external_writer_race_not_accepted";
    case NdmsNativeCooperativeImportStop::writer_missing:
        return "writer_missing";
    case NdmsNativeCooperativeImportStop::writer_lost:
        return "writer_lost";
    case NdmsNativeCooperativeImportStop::delete_wal_not_clean:
        return "delete_wal_not_clean";
    case NdmsNativeCooperativeImportStop::import_wal_not_clean:
        return "import_wal_not_clean";
    case NdmsNativeCooperativeImportStop::request_invalid:
        return "request_invalid";
    case NdmsNativeCooperativeImportStop::runtime_catalog_failed:
        return "runtime_catalog_failed";
    case NdmsNativeCooperativeImportStop::running_config_catalog_failed:
        return "running_config_catalog_failed";
    case NdmsNativeCooperativeImportStop::prewrite_catalog_unsafe:
        return "prewrite_catalog_unsafe";
    case NdmsNativeCooperativeImportStop::prewrite_catalog_diverged:
        return "prewrite_catalog_diverged";
    case NdmsNativeCooperativeImportStop::marker_collision:
        return "marker_collision";
    case NdmsNativeCooperativeImportStop::first_free_target_not_managed:
        return "first_free_target_not_managed";
    case NdmsNativeCooperativeImportStop::durable_observation_failed:
        return "durable_observation_failed";
    case NdmsNativeCooperativeImportStop::cooperative_baseline_failed:
        return "cooperative_baseline_failed";
    case NdmsNativeCooperativeImportStop::
        cooperative_writer_admission_failed:
        return "cooperative_writer_admission_failed";
    case NdmsNativeCooperativeImportStop::executor_blocked:
        return "executor_blocked";
    case NdmsNativeCooperativeImportStop::wal_record_unavailable:
        return "wal_record_unavailable";
    case NdmsNativeCooperativeImportStop::first_post_observation_failed:
        return "first_post_observation_failed";
    case NdmsNativeCooperativeImportStop::second_post_observation_failed:
        return "second_post_observation_failed";
    case NdmsNativeCooperativeImportStop::post_observation_kind_mismatch:
        return "post_observation_kind_mismatch";
    case NdmsNativeCooperativeImportStop::post_observation_unstable:
        return "post_observation_unstable";
    case NdmsNativeCooperativeImportStop::forward_completion_blocked:
        return "forward_completion_blocked";
    case NdmsNativeCooperativeImportStop::forward_admission_failed:
        return "forward_admission_failed";
    case NdmsNativeCooperativeImportStop::
        target_verified_wal_publish_failed:
        return "target_verified_wal_publish_failed";
    case NdmsNativeCooperativeImportStop::ownership_publish_failed:
        return "ownership_publish_failed";
    case NdmsNativeCooperativeImportStop::ownership_wal_publish_failed:
        return "ownership_wal_publish_failed";
    case NdmsNativeCooperativeImportStop::wal_cleanup_failed:
        return "wal_cleanup_failed";
    case NdmsNativeCooperativeImportStop::unexpected_failure:
        return "unexpected_failure";
    }
    return "unexpected_failure";
}

const char* ndms_native_cooperative_import_resume_status_name(
    const NdmsNativeCooperativeImportResumeStatus status) noexcept {
    switch (status) {
    case NdmsNativeCooperativeImportResumeStatus::no_work:
        return "no_work";
    case NdmsNativeCooperativeImportResumeStatus::blocked:
        return "blocked";
    case NdmsNativeCooperativeImportResumeStatus::completed:
        return "completed";
    }
    return "blocked";
}

const char* ndms_native_cooperative_import_resume_stop_name(
    const NdmsNativeCooperativeImportResumeStop stop) noexcept {
    switch (stop) {
    case NdmsNativeCooperativeImportResumeStop::none:
        return "none";
    case NdmsNativeCooperativeImportResumeStop::writer_missing:
        return "writer_missing";
    case NdmsNativeCooperativeImportResumeStop::writer_lost:
        return "writer_lost";
    case NdmsNativeCooperativeImportResumeStop::delete_wal_not_clean:
        return "delete_wal_not_clean";
    case NdmsNativeCooperativeImportResumeStop::
        import_wal_not_single_safe:
        return "import_wal_not_single_safe";
    case NdmsNativeCooperativeImportResumeStop::record_not_cooperative:
        return "record_not_cooperative";
    case NdmsNativeCooperativeImportResumeStop::phase_not_forward_only:
        return "phase_not_forward_only";
    case NdmsNativeCooperativeImportResumeStop::
        expected_target_not_managed:
        return "expected_target_not_managed";
    case NdmsNativeCooperativeImportResumeStop::
        first_observation_failed:
        return "first_observation_failed";
    case NdmsNativeCooperativeImportResumeStop::
        second_observation_failed:
        return "second_observation_failed";
    case NdmsNativeCooperativeImportResumeStop::
        observation_kind_mismatch:
        return "observation_kind_mismatch";
    case NdmsNativeCooperativeImportResumeStop::
        durable_observation_failed:
        return "durable_observation_failed";
    case NdmsNativeCooperativeImportResumeStop::observation_unstable:
        return "observation_unstable";
    case NdmsNativeCooperativeImportResumeStop::ownership_not_exact:
        return "ownership_not_exact";
    case NdmsNativeCooperativeImportResumeStop::
        recovery_action_not_forward_only:
        return "recovery_action_not_forward_only";
    case NdmsNativeCooperativeImportResumeStop::
        forward_admission_failed:
        return "forward_admission_failed";
    case NdmsNativeCooperativeImportResumeStop::
        target_verified_wal_publish_failed:
        return "target_verified_wal_publish_failed";
    case NdmsNativeCooperativeImportResumeStop::
        ownership_publish_failed:
        return "ownership_publish_failed";
    case NdmsNativeCooperativeImportResumeStop::
        ownership_wal_publish_failed:
        return "ownership_wal_publish_failed";
    case NdmsNativeCooperativeImportResumeStop::wal_cleanup_failed:
        return "wal_cleanup_failed";
    case NdmsNativeCooperativeImportResumeStop::unexpected_failure:
        return "unexpected_failure";
    }
    return "unexpected_failure";
}

} // namespace keen_pbr3
