#include "ndms_native_import_recovery_probe.hpp"

#include "ndms_native_import_baseline.hpp"

namespace keen_pbr3 {

NdmsNativeImportRecoveryCatalogProbe
build_ndms_native_import_recovery_probe(
    const NdmsCatalogSnapshot& snapshot,
    const std::uint8_t expected_target_slot,
    const std::string& marker,
    const std::vector<NdmsNativeImportRecoveryTargetEvidence>&
        target_evidence) {
    NdmsNativeImportRecoveryCatalogProbe probe;
    probe.observation_generation = snapshot.observation_generation;
    probe.observation_epoch = snapshot.observation_epoch;
    probe.protected_catalog_sha256 =
        ndms_native_import_protected_catalog_digest(
            snapshot.catalog, expected_target_slot);

    // A scan is complete only over a world that could actually be scanned:
    // an authoritative fresh snapshot, an available firmware, and not one
    // catalog slot the parser refused to trust. An unsafe slot is exactly
    // where a second marker could hide.
    bool complete = snapshot.status == NdmsCatalogCacheStatus::fresh &&
                    snapshot.catalog.firmware_available &&
                    !marker.empty();
    for (const auto& slot : snapshot.catalog.wireguard_slots) {
        if (slot.state == NdmsWireguardCatalogSlotState::unsafe) {
            complete = false;
        }
    }

    for (const auto& tunnel : snapshot.catalog.tunnels) {
        // Containment, not equality: the importer may compose the marker with
        // a label, and the direction that must not miss is detection. A false
        // sighting inflates the count and blocks; a missed one deletes the
        // wrong interface.
        if (tunnel.label.find(marker) == std::string::npos) continue;

        NdmsNativeImportRecoveryMarkerSighting sighting;
        sighting.interface_name = tunnel.firmware_interface_name;

        const NdmsNativeImportRecoveryTargetEvidence* evidence = nullptr;
        for (const auto& candidate : target_evidence) {
            if (candidate.interface_name ==
                tunnel.firmware_interface_name) {
                evidence = &candidate;
                break;
            }
        }
        if (evidence == nullptr || evidence->full_revision.empty()) {
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
