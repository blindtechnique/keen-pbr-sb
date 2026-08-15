#include "ndms_native_import_recovery_observation.hpp"

#include "ndms_native_import_baseline.hpp"
#include "ndms_wireguard_identity.hpp"

#include <algorithm>

namespace keen_pbr3 {

namespace {

// Checked against the producer's own prefix constant, not against a shape
// guessed here. This used to demand a bare 64-hex digest while every producer
// - the probe builder and the persisted baseline alike - emits the prefixed
// form, so no real probe was ever internally valid and no observation could
// ever be authoritative. The hand-built fixtures were bare, so the tests
// agreed with the checker and never with production.
bool catalog_digest_well_formed(const std::string& value) {
    return ndms_native_import_prefixed_sha256(
        value, kNdmsNativeImportProtectedCatalogDigestPrefix);
}

bool probe_internally_valid(
    const NdmsNativeImportRecoveryCatalogProbe& probe) {
    if (probe.observation_generation == 0U ||
        !probe.marker_scan_complete ||
        !catalog_digest_well_formed(probe.protected_catalog_sha256)) {
        return false;
    }
    for (const auto& sighting : probe.marker_sightings) {
        if (sighting.interface_name.empty()) return false;
    }
    return true;
}

bool sightings_agree(
    const std::vector<NdmsNativeImportRecoveryMarkerSighting>& earlier,
    const std::vector<NdmsNativeImportRecoveryMarkerSighting>& later) {
    if (earlier.size() != later.size()) return false;
    // Order-insensitive: two scans of the same catalog may enumerate slots
    // differently without the world having moved.
    for (const auto& sighting : earlier) {
        const auto match = std::find_if(
            later.begin(), later.end(),
            [&sighting](
                const NdmsNativeImportRecoveryMarkerSighting& other) {
                return other.interface_name == sighting.interface_name &&
                       other.link_down == sighting.link_down &&
                       other.full_revision == sighting.full_revision;
            });
        if (match == later.end()) return false;
    }
    return true;
}

// The baseline recorded which slots were occupied before the import ran. A
// target absent there is one this transaction may have created; a target that
// was already occupied belongs to somebody else no matter what marker it
// carries now.
bool slot_absent_in_baseline(const std::string& occupancy_hex_value,
                             const std::string& interface_name,
                             bool& decodable) {
    decodable = false;
    if (occupancy_hex_value.size() !=
        kNdmsNativeImportOccupancyHexCharacters) {
        return false;
    }
    const auto identity = parse_ndms_wireguard_identity(interface_name);
    if (!identity) {
        // An unparseable name is decodable evidence, not a broken probe: the
        // marker sits on something outside the measured namespace, and the
        // classifier must see that as "not exact-owned", not as "try again".
        decodable = true;
        return false;
    }
    const auto slot = identity->slot;
    const auto character =
        occupancy_hex_value[static_cast<std::size_t>(slot / 8U) * 2U +
                            ((slot % 8U) >= 4U ? 0U : 1U)];
    std::uint8_t nibble = 0U;
    if (character >= '0' && character <= '9') {
        nibble = static_cast<std::uint8_t>(character - '0');
    } else if (character >= 'a' && character <= 'f') {
        nibble = static_cast<std::uint8_t>(character - 'a' + 10);
    } else {
        return false;
    }
    decodable = true;
    const auto bit = static_cast<std::uint8_t>(1U << (slot % 4U));
    return (nibble & bit) == 0U;
}

} // namespace

NdmsNativeImportRecoveryObservation
build_ndms_native_import_recovery_observation(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryCatalogProbe& earlier,
    const NdmsNativeImportRecoveryCatalogProbe& later,
    const std::optional<std::string>& published_ownership_revision) {
    NdmsNativeImportRecoveryObservation observation;

    // Every exit below this point that is not the final assembly returns the
    // default observation: authoritative=false, everything else at its safe
    // value. The classifier answers that with a read-only retry.
    if (!probe_internally_valid(earlier) || !probe_internally_valid(later)) {
        return observation;
    }
    // Same epoch as each other and as the baseline: a generation number from
    // another epoch is a number, not a successor.
    if (earlier.observation_epoch != later.observation_epoch ||
        earlier.observation_epoch != record.baseline.observation_epoch) {
        return observation;
    }
    // Strictly advancing: the same read handed in twice proves nothing about
    // stability, however far apart the calls were.
    if (later.observation_generation <= earlier.observation_generation) {
        return observation;
    }
    // The two reads must describe the same world. Disagreement - a marker
    // that appeared, a link that came up, a revision that moved - means the
    // world is still moving, and a moving world is observed again, not acted
    // on.
    if (earlier.protected_catalog_sha256 != later.protected_catalog_sha256 ||
        !sightings_agree(earlier.marker_sightings, later.marker_sightings)) {
        return observation;
    }

    observation.generation_advanced =
        earlier.observation_generation >
        record.baseline.observation_generation;
    observation.protected_catalog_unchanged =
        earlier.protected_catalog_sha256 ==
        record.baseline.protected_catalog_sha256;
    observation.marker_match_count = earlier.marker_sightings.size();

    if (observation.marker_match_count == 1U) {
        const auto& sighting = earlier.marker_sightings.front();
        observation.marker_target = sighting.interface_name;
        bool decodable = false;
        observation.target_absent_in_baseline = slot_absent_in_baseline(
            record.baseline.occupancy_hex, sighting.interface_name,
            decodable);
        if (!decodable) {
            // A baseline occupancy we cannot read is a probe we cannot trust
            // end to end; nothing built on it may claim authority.
            return NdmsNativeImportRecoveryObservation{};
        }
        observation.target_down = sighting.link_down;
        observation.target_fingerprint_matches =
            record.target_full_revision.has_value() &&
            !record.target_full_revision->empty() &&
            sighting.full_revision == *record.target_full_revision;
    }

    observation.ownership_record_matches =
        record.ownership_revision.has_value() &&
        !record.ownership_revision->empty() &&
        published_ownership_revision.has_value() &&
        *published_ownership_revision == *record.ownership_revision;

    observation.stable_absence = observation.marker_match_count == 0U;
    observation.authoritative = true;
    return observation;
}

} // namespace keen_pbr3
