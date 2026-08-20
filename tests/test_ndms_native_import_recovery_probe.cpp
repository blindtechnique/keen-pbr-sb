#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_import_recovery_probe.hpp"

#include "../src/keenetic/ndms_native_import_baseline.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

const std::string kMarker = "kpbr-ni-v1-" + std::string(32U, 'a');
const std::string kRevision = "ndms-rci-full-v1-" + std::string(64U, 'd');

NdmsCatalogSnapshot snapshot_with(
    const std::vector<std::pair<std::string, std::string>>& interfaces) {
    auto payload = nlohmann::json::object();
    for (const auto& [name, description] : interfaces) {
        payload[name] = {
            {"type", "Wireguard"},
            {"interface-name", name},
            {"description", description},
        };
    }
    NdmsCatalogSnapshot snapshot;
    snapshot.catalog = parse_ndms_interface_catalog(payload);
    snapshot.status = NdmsCatalogCacheStatus::fresh;
    snapshot.refreshed = true;
    snapshot.observed_at = std::chrono::steady_clock::now();
    // These process-local counters intentionally remain at zero. The probe's
    // only ordering identity is the durable observation stamp.
    return snapshot;
}

NdmsNativeImportRecoveryTargetEvidence evidence_for(
    const std::string& name) {
    NdmsNativeImportRecoveryTargetEvidence evidence;
    evidence.interface_name = name;
    evidence.link_down = true;
    evidence.full_revision = kRevision;
    return evidence;
}

NdmsNativeObservationStamp stamp_for(
    const NdmsCatalogSnapshot& snapshot,
    const std::vector<NdmsNativeImportRecoveryTargetEvidence>& evidence,
    const std::uint64_t sequence = 41U) {
    const auto revision = ndms_native_import_recovery_catalog_revision(
        snapshot.catalog, evidence);
    NdmsNativeObservationLedger ledger;
    ledger.authority_id = std::string(32U, '1');
    ledger.sequence = sequence;
    ledger.mutation_epoch = 17U;
    ledger.last_catalog_revision = revision;
    ledger.integrity = ndms_native_observation_integrity(ledger);
    return {
        ledger.authority_id,
        ledger.sequence,
        ledger.mutation_epoch,
        revision,
        ledger.integrity,
    };
}

NdmsNativeImportRecoveryCatalogProbe build_probe(
    const NdmsCatalogSnapshot& snapshot,
    const std::uint8_t expected_target_slot,
    const std::string& marker,
    const std::vector<NdmsNativeImportRecoveryTargetEvidence>& evidence) {
    return build_ndms_native_import_recovery_probe(
        snapshot, stamp_for(snapshot, evidence), expected_target_slot,
        marker, evidence);
}

} // namespace

TEST_CASE("a measured sighting produces a complete probe") {
    const auto snapshot = snapshot_with({{"Wireguard5", kMarker}});
    const auto probe = build_probe(
        snapshot, 5U, kMarker, {evidence_for("Wireguard5")});

    CHECK(probe.marker_scan_complete);
    CHECK(probe.durable_observation.sequence == 41U);
    CHECK(valid_ndms_native_observation_stamp(
        probe.durable_observation));
    CHECK(probe.measured_catalog_revision ==
          probe.durable_observation.catalog_revision);
    CHECK(probe.protected_catalog_sha256 ==
          ndms_native_import_protected_catalog_digest(
              snapshot.catalog, 5U));
    REQUIRE(probe.marker_sightings.size() == 1U);
    CHECK(probe.marker_sightings.front().interface_name == "Wireguard5");
    CHECK(probe.marker_sightings.front().link_down);
    CHECK(probe.marker_sightings.front().full_revision == kRevision);
}

TEST_CASE("a marker composed into a longer label is still a sighting") {
    // Detection is the direction that must not miss: a false sighting
    // inflates the count and blocks, a missed one lets a rollback aim past
    // an interface that carries the claim.
    const auto snapshot =
        snapshot_with({{"Wireguard6", "my tunnel " + kMarker + " (auto)"}});
    const auto probe = build_probe(
        snapshot, 5U, kMarker, {evidence_for("Wireguard6")});
    REQUIRE(probe.marker_sightings.size() == 1U);
    CHECK(probe.marker_sightings.front().interface_name == "Wireguard6");
}

TEST_CASE("a sighting without direct evidence is counted but never complete") {
    const auto snapshot = snapshot_with({{"Wireguard5", kMarker}});
    const auto probe = build_probe(
        snapshot, 5U, kMarker, {});
    // Counted - the count is what stops a rollback aiming past it - while
    // completeness is refused, so downstream authority is refused with it.
    CHECK(probe.marker_sightings.size() == 1U);
    CHECK_FALSE(probe.marker_scan_complete);
}

TEST_CASE("only a direct complete snapshot can claim completeness") {
    auto stale = snapshot_with({{"Wireguard5", kMarker}});
    stale.status = NdmsCatalogCacheStatus::stale;
    CHECK_FALSE(build_probe(
                    stale, 5U, kMarker, {evidence_for("Wireguard5")})
                    .marker_scan_complete);

    auto dark = snapshot_with({{"Wireguard5", kMarker}});
    dark.catalog.firmware_available = false;
    CHECK_FALSE(build_probe(
                    dark, 5U, kMarker, {evidence_for("Wireguard5")})
                    .marker_scan_complete);

    auto cached = snapshot_with({{"Wireguard5", kMarker}});
    cached.refreshed = false;
    CHECK_FALSE(build_probe(
                    cached, 5U, kMarker, {evidence_for("Wireguard5")})
                    .marker_scan_complete);

    auto unstamped_time = snapshot_with({{"Wireguard5", kMarker}});
    unstamped_time.observed_at.reset();
    CHECK_FALSE(build_probe(
                    unstamped_time, 5U, kMarker,
                    {evidence_for("Wireguard5")})
                    .marker_scan_complete);

    // An empty marker would match every label; refusing completeness keeps a
    // degenerate input from manufacturing a hundred sightings with authority.
    CHECK_FALSE(build_probe(
                    snapshot_with({{"Wireguard5", kMarker}}), 5U, "",
                    {evidence_for("Wireguard5")})
                    .marker_scan_complete);
}

TEST_CASE("an unsafe catalog slot poisons completeness, not the count") {
    auto snapshot = snapshot_with({{"Wireguard5", kMarker}});
    snapshot.catalog.wireguard_slots[9].state =
        NdmsWireguardCatalogSlotState::unsafe;
    const auto probe = build_probe(
        snapshot, 5U, kMarker, {evidence_for("Wireguard5")});
    // An unsafe slot is exactly where a second marker could hide.
    CHECK_FALSE(probe.marker_scan_complete);
    CHECK(probe.marker_sightings.size() == 1U);
}

TEST_CASE("two sightings survive into the count in any order") {
    const auto snapshot = snapshot_with(
        {{"Wireguard5", kMarker}, {"Wireguard7", kMarker}});
    const auto probe = build_probe(
        snapshot, 5U, kMarker,
        {evidence_for("Wireguard7"), evidence_for("Wireguard5")});
    CHECK(probe.marker_scan_complete);
    CHECK(probe.marker_sightings.size() == 2U);
}

TEST_CASE("a stamp from another scan cannot be attached to this payload") {
    const auto measured = snapshot_with({{"Wireguard5", kMarker}});
    const auto other = snapshot_with({{"Wireguard6", kMarker}});
    const auto evidence =
        std::vector<NdmsNativeImportRecoveryTargetEvidence>{
            evidence_for("Wireguard5")};
    const auto probe = build_ndms_native_import_recovery_probe(
        measured, stamp_for(other, {evidence_for("Wireguard6")}), 5U,
        kMarker, evidence);
    CHECK_FALSE(probe.marker_scan_complete);
    CHECK(probe.measured_catalog_revision !=
          probe.durable_observation.catalog_revision);
}

TEST_CASE("duplicate or malformed direct evidence fails closed") {
    const auto snapshot = snapshot_with({{"Wireguard5", kMarker}});
    const auto evidence = evidence_for("Wireguard5");
    CHECK_FALSE(build_probe(
                    snapshot, 5U, kMarker, {evidence, evidence})
                    .marker_scan_complete);

    auto malformed = evidence;
    malformed.full_revision = "not-a-full-revision";
    CHECK_FALSE(build_probe(snapshot, 5U, kMarker, {malformed})
                    .marker_scan_complete);
}

TEST_CASE("the digest tracks the catalog, so drift is visible downstream") {
    const auto before = snapshot_with({{"Wireguard0", "system"}});
    auto after = snapshot_with({{"Wireguard0", "renamed-system"}});
    CHECK(build_probe(before, 5U, kMarker, {})
              .protected_catalog_sha256 !=
          build_probe(after, 5U, kMarker, {})
              .protected_catalog_sha256);
    CHECK(ndms_native_import_recovery_catalog_revision(before.catalog, {}) !=
          ndms_native_import_recovery_catalog_revision(after.catalog, {}));

    const auto first = evidence_for("Wireguard5");
    const auto second = evidence_for("Wireguard7");
    CHECK(ndms_native_import_recovery_catalog_revision(
              before.catalog, {first, second}) ==
          ndms_native_import_recovery_catalog_revision(
              before.catalog, {second, first}));
}

} // namespace keen_pbr3
