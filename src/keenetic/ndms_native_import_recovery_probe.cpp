#include "ndms_native_import_recovery_probe.hpp"

#include "ndms_native_import_baseline.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <string_view>

namespace keen_pbr3 {

namespace {

void update_revision_field(Sha256& hasher, const std::string_view value) {
    const auto size = static_cast<std::uint64_t>(value.size());
    std::array<unsigned char, 8U> encoded_size{};
    for (std::size_t index = 0U; index < encoded_size.size(); ++index) {
        encoded_size[index] = static_cast<unsigned char>(
            size >> (56U - index * 8U));
    }
    hasher.update(encoded_size.data(), encoded_size.size());
    hasher.update(value.data(), value.size());
}

const char* slot_state_name(
    const NdmsWireguardCatalogSlotState state) noexcept {
    switch (state) {
    case NdmsWireguardCatalogSlotState::absent:
        return "absent";
    case NdmsWireguardCatalogSlotState::occupied:
        return "occupied";
    case NdmsWireguardCatalogSlotState::unsafe:
        return "unsafe";
    }
    return "unsafe";
}

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

bool valid_target_evidence_inventory(
    const std::vector<NdmsNativeImportRecoveryTargetEvidence>& evidence) {
    std::vector<std::string_view> names;
    names.reserve(evidence.size());
    for (const auto& item : evidence) {
        if (item.interface_name.empty() ||
            !ndms_native_import_prefixed_sha256(
                item.full_revision, "ndms-rci-full-v1-")) {
            return false;
        }
        names.emplace_back(item.interface_name);
    }
    std::sort(names.begin(), names.end());
    return std::adjacent_find(names.begin(), names.end()) == names.end();
}

} // namespace

std::string ndms_native_import_recovery_catalog_revision(
    const NdmsInterfaceCatalog& catalog,
    const std::vector<NdmsNativeImportRecoveryTargetEvidence>&
        target_evidence) {
    Sha256 hasher;
    update_revision_field(
        hasher, "keen-pbr.ndms-native-import.recovery-catalog.v1");
    update_revision_field(
        hasher, catalog.firmware_available ? "1" : "0");
    update_revision_field(
        hasher, catalog.wireguard_slot_evidence_complete ? "1" : "0");
    for (std::size_t index = 0U;
         index < catalog.wireguard_slots.size(); ++index) {
        const auto& slot = catalog.wireguard_slots[index];
        update_revision_field(hasher, std::to_string(index));
        update_revision_field(hasher, slot_state_name(slot.state));
        update_revision_field(hasher, slot.structural_revision);
    }

    std::vector<const NdmsNativeImportRecoveryTargetEvidence*> ordered;
    ordered.reserve(target_evidence.size());
    for (const auto& item : target_evidence) ordered.push_back(&item);
    std::sort(
        ordered.begin(), ordered.end(),
        [](const NdmsNativeImportRecoveryTargetEvidence* left,
           const NdmsNativeImportRecoveryTargetEvidence* right) {
            if (left->interface_name != right->interface_name) {
                return left->interface_name < right->interface_name;
            }
            if (left->link_down != right->link_down) {
                return left->link_down < right->link_down;
            }
            return left->full_revision < right->full_revision;
        });
    update_revision_field(hasher, std::to_string(ordered.size()));
    for (const auto* item : ordered) {
        update_revision_field(hasher, item->interface_name);
        update_revision_field(hasher, item->link_down ? "1" : "0");
        update_revision_field(hasher, item->full_revision);
    }
    return std::string{kNdmsNativeObservationCatalogRevisionPrefix} +
           hasher.hex_digest();
}

NdmsNativeImportRecoveryCatalogProbe
build_ndms_native_import_recovery_probe(
    const NdmsCatalogSnapshot& snapshot,
    const NdmsNativeObservationStamp& durable_observation,
    const std::uint8_t expected_target_slot,
    const std::string& marker,
    const std::vector<NdmsNativeImportRecoveryTargetEvidence>&
        target_evidence) {
    NdmsNativeImportRecoveryCatalogProbe probe;
    probe.durable_observation = durable_observation;
    probe.measured_catalog_revision =
        ndms_native_import_recovery_catalog_revision(
            snapshot.catalog, target_evidence);
    probe.protected_catalog_sha256 =
        ndms_native_import_protected_catalog_digest(
            snapshot.catalog, expected_target_slot);

    // A scan is complete only over a world that could actually be scanned:
    // an authoritative fresh snapshot, an available firmware, and not one
    // catalog slot the parser refused to trust. An unsafe slot is exactly
    // where a second marker could hide.
    bool complete =
        snapshot.status == NdmsCatalogCacheStatus::fresh &&
        snapshot.refreshed && snapshot.observed_at.has_value() &&
        snapshot.catalog.firmware_available &&
        snapshot.catalog.wireguard_slot_evidence_complete &&
        expected_target_slot < snapshot.catalog.wireguard_slots.size() &&
        !marker.empty() &&
        valid_target_evidence_inventory(target_evidence) &&
        valid_ndms_native_observation_stamp(durable_observation) &&
        durable_observation.catalog_revision ==
            probe.measured_catalog_revision;
    for (const auto& slot : snapshot.catalog.wireguard_slots) {
        if (!valid_slot_evidence(slot)) complete = false;
    }

    std::vector<std::string> sighted_interfaces;
    for (const auto& tunnel : snapshot.catalog.tunnels) {
        // Containment, not equality: the importer may compose the marker with
        // a label, and the direction that must not miss is detection. A false
        // sighting inflates the count and blocks; a missed one deletes the
        // wrong interface.
        if (tunnel.label.find(marker) == std::string::npos) continue;

        NdmsNativeImportRecoveryMarkerSighting sighting;
        sighting.interface_name = tunnel.firmware_interface_name;

        if (std::find(
                sighted_interfaces.begin(), sighted_interfaces.end(),
                sighting.interface_name) != sighted_interfaces.end()) {
            complete = false;
        }
        sighted_interfaces.push_back(sighting.interface_name);

        const NdmsNativeImportRecoveryTargetEvidence* evidence = nullptr;
        for (const auto& candidate : target_evidence) {
            if (candidate.interface_name ==
                tunnel.firmware_interface_name) {
                evidence = &candidate;
                break;
            }
        }
        if (evidence == nullptr ||
            !ndms_native_import_prefixed_sha256(
                evidence->full_revision, "ndms-rci-full-v1-")) {
            // A sighted marker nobody measured directly: the sighting is
            // still counted - the count is what stops a rollback aiming past
            // it - but the scan cannot claim completeness over evidence it
            // does not have.
            complete = false;
            probe.marker_sightings.push_back(std::move(sighting));
            continue;
        }
        sighting.link_down = evidence->link_down;
        sighting.full_revision = evidence->full_revision;
        probe.marker_sightings.push_back(std::move(sighting));
    }

    probe.marker_scan_complete = complete;
    return probe;
}

} // namespace keen_pbr3
