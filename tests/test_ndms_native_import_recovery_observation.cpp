#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_import_recovery_observation.hpp"

#include "../src/keenetic/ndms_native_import_baseline.hpp"
#include "../src/keenetic/ndms_native_import_recovery_probe.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

// The prefixed shape the producers actually emit. Written as prefix + hex
// rather than as a bare digest: a bare fixture is what let the validator
// demand a shape no producer has ever emitted, with every test agreeing.
const std::string kBaselineCatalog =
    std::string(kNdmsNativeImportProtectedCatalogDigestPrefix) +
    std::string(64U, 'a');
const std::string kRevision =
    "ndms-rci-full-v1-" + std::string(64U, 'b');
const std::string kAuthority(32U, '1');
const std::string kMeasuredCatalog =
    std::string(kNdmsNativeObservationCatalogRevisionPrefix) +
    std::string(64U, '2');
constexpr std::uint64_t kMutationEpoch = 17U;
constexpr std::uint64_t kBaselineSequence = 40U;

NdmsNativeObservationStamp stamp_fixture(
    const std::uint64_t sequence,
    const std::string& catalog_revision = kMeasuredCatalog,
    const std::string& authority = kAuthority,
    const std::uint64_t mutation_epoch = kMutationEpoch) {
    NdmsNativeObservationLedger ledger;
    ledger.authority_id = authority;
    ledger.sequence = sequence;
    ledger.mutation_epoch = mutation_epoch;
    ledger.last_catalog_revision = catalog_revision;
    ledger.integrity = ndms_native_observation_integrity(ledger);
    return {
        authority,
        sequence,
        mutation_epoch,
        catalog_revision,
        ledger.integrity,
    };
}

// Wireguard5 occupied-free baseline: all slots free.
NdmsNativeImportWalRecord record_fixture() {
    NdmsNativeImportWalRecord record;
    record.observation_binding = {
        kAuthority,
        kMutationEpoch,
        kBaselineSequence,
    };
    // Deliberately unrelated process-local counters. Recovery ordering must
    // come only from the durable binding/stamps and survive their reset.
    record.baseline.observation_generation = 40U;
    record.baseline.observation_epoch = 7U;
    record.baseline.protected_catalog_sha256 = kBaselineCatalog;
    record.baseline.occupancy_hex = std::string(32U, '0');
    record.target_full_revision = kRevision;
    return record;
}

NdmsNativeImportRecoveryCatalogProbe probe_fixture(
    const std::uint64_t sequence) {
    NdmsNativeImportRecoveryCatalogProbe probe;
    probe.durable_observation = stamp_fixture(sequence);
    probe.measured_catalog_revision = kMeasuredCatalog;
    probe.protected_catalog_sha256 = kBaselineCatalog;
    probe.marker_scan_complete = true;
    return probe;
}

NdmsNativeImportRecoveryMarkerSighting sighting_fixture() {
    NdmsNativeImportRecoveryMarkerSighting sighting;
    sighting.interface_name = "Wireguard5";
    sighting.link_down = true;
    sighting.full_revision = kRevision;
    return sighting;
}

} // namespace

TEST_CASE("two agreeing advancing probes yield an authoritative observation") {
    auto earlier = probe_fixture(41U);
    auto later = probe_fixture(42U);
    earlier.marker_sightings.push_back(sighting_fixture());
    later.marker_sightings.push_back(sighting_fixture());

    const auto observation = build_ndms_native_import_recovery_observation(
        record_fixture(), earlier, later, std::nullopt);
    CHECK(observation.authoritative);
    CHECK(observation.generation_advanced);
    CHECK(observation.protected_catalog_unchanged);
    CHECK(observation.marker_match_count == 1U);
    REQUIRE(observation.marker_target.has_value());
    CHECK(*observation.marker_target == "Wireguard5");
    CHECK(observation.target_absent_in_baseline);
    CHECK(observation.target_down);
    CHECK(observation.target_fingerprint_matches);
    CHECK_FALSE(observation.stable_absence);
}

TEST_CASE("stable absence needs two empty scans across advancing generations") {
    const auto observation = build_ndms_native_import_recovery_observation(
        record_fixture(), probe_fixture(41U), probe_fixture(42U),
        std::nullopt);
    CHECK(observation.authoritative);
    CHECK(observation.stable_absence);
    CHECK(observation.marker_match_count == 0U);
    CHECK_FALSE(observation.marker_target.has_value());

    // The same generation handed in twice is one read, not two: absence
    // observed once is a moment, not a state.
    const auto same = build_ndms_native_import_recovery_observation(
        record_fixture(), probe_fixture(41U), probe_fixture(41U),
        std::nullopt);
    CHECK_FALSE(same.authoritative);
    CHECK_FALSE(same.stable_absence);
}

TEST_CASE("a moving world is observed again, not acted on") {
    // A marker that appeared between the reads.
    auto earlier = probe_fixture(41U);
    auto later = probe_fixture(42U);
    later.marker_sightings.push_back(sighting_fixture());
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), earlier, later, std::nullopt)
                    .authoritative);

    // A link that came up between the reads.
    earlier.marker_sightings.push_back(sighting_fixture());
    later.marker_sightings.front().link_down = false;
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), earlier, later, std::nullopt)
                    .authoritative);

    // A revision that moved between the reads: same interface, same link
    // state, different bytes. The production comment names this as one of the
    // three disagreements that must degrade the observation, but until this
    // case no test could fail if the full_revision comparison were deleted
    // from sightings_agree - the suite varied only set size and link_down.
    auto revised = probe_fixture(42U);
    revised.marker_sightings.push_back(sighting_fixture());
    revised.marker_sightings.front().full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'e');
    auto steady = probe_fixture(41U);
    steady.marker_sightings.push_back(sighting_fixture());
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), steady, revised, std::nullopt)
                    .authoritative);

    // A protected catalog that changed between the reads. Prefixed, so this
    // case fails on the drift it is named for; a bare digest would make the
    // probe internally invalid and the assertion would pass for the wrong
    // reason.
    auto drifting = probe_fixture(42U);
    drifting.protected_catalog_sha256 =
        std::string(kNdmsNativeImportProtectedCatalogDigestPrefix) +
        std::string(64U, 'c');
    REQUIRE(drifting.protected_catalog_sha256 != kBaselineCatalog);
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), probe_fixture(41U), drifting,
                    std::nullopt)
                    .authoritative);
}

TEST_CASE("an incomplete scan or foreign durable identity never gains authority") {
    auto incomplete = probe_fixture(41U);
    incomplete.marker_scan_complete = false;
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), incomplete, probe_fixture(42U),
                    std::nullopt)
                    .authoritative);

    // A sequence from another durable epoch is a number, not a successor.
    auto foreign_earlier = probe_fixture(41U);
    auto foreign_later = probe_fixture(42U);
    foreign_earlier.durable_observation = stamp_fixture(
        41U, kMeasuredCatalog, kAuthority, kMutationEpoch + 1U);
    foreign_later.durable_observation = stamp_fixture(
        42U, kMeasuredCatalog, kAuthority, kMutationEpoch + 1U);
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), foreign_earlier, foreign_later,
                    std::nullopt)
                    .authoritative);

    foreign_earlier.durable_observation = stamp_fixture(
        41U, kMeasuredCatalog, std::string(32U, '9'));
    foreign_later.durable_observation = stamp_fixture(
        42U, kMeasuredCatalog, std::string(32U, '9'));
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), foreign_earlier, foreign_later,
                    std::nullopt)
                    .authoritative);
}

TEST_CASE("catalog drift against the baseline is reported, not hidden") {
    // The probes agree with each other but not with the baseline: that is an
    // authoritative observation of drift, and hiding it behind a retry would
    // stall recovery on a world that is not going to change back.
    auto record = record_fixture();
    record.baseline.protected_catalog_sha256 =
        std::string(kNdmsNativeImportProtectedCatalogDigestPrefix) +
        std::string(64U, 'd');
    const auto observation = build_ndms_native_import_recovery_observation(
        record, probe_fixture(41U), probe_fixture(42U), std::nullopt);
    CHECK(observation.authoritative);
    CHECK_FALSE(observation.protected_catalog_unchanged);
}

TEST_CASE("both durable sequences must be newer than the WAL baseline") {
    auto record = record_fixture();
    record.observation_binding.baseline_sequence = 41U;
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record, probe_fixture(41U), probe_fixture(42U),
                    std::nullopt)
                    .authoritative);

    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), probe_fixture(43U),
                    probe_fixture(42U), std::nullopt)
                    .authoritative);

    auto invalid_binding = record_fixture();
    invalid_binding.observation_binding.baseline_sequence = 0U;
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    invalid_binding, probe_fixture(41U),
                    probe_fixture(42U), std::nullopt)
                    .authoritative);
}

TEST_CASE("restart ordering accepts high durable sequences and ignores cache reset") {
    auto record = record_fixture();
    record.observation_binding.baseline_sequence =
        (std::uint64_t{1} << 48U) + 7U;
    record.baseline.observation_generation = 1U;
    record.baseline.observation_epoch = 0U;
    const auto observation = build_ndms_native_import_recovery_observation(
        record,
        probe_fixture(record.observation_binding.baseline_sequence + 1U),
        probe_fixture(record.observation_binding.baseline_sequence + 9U),
        std::nullopt);
    CHECK(observation.authoritative);
    CHECK(observation.generation_advanced);
}

TEST_CASE("mixed or reused durable stamps fail closed") {
    auto mixed_payload = probe_fixture(41U);
    mixed_payload.durable_observation = stamp_fixture(
        41U,
        std::string(kNdmsNativeObservationCatalogRevisionPrefix) +
            std::string(64U, '8'));
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), mixed_payload, probe_fixture(42U),
                    std::nullopt)
                    .authoritative);

    auto mixed_integrity = probe_fixture(41U);
    ++mixed_integrity.durable_observation.sequence;
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), mixed_integrity, probe_fixture(43U),
                    std::nullopt)
                    .authoritative);

    auto other_world = probe_fixture(42U);
    other_world.measured_catalog_revision =
        std::string(kNdmsNativeObservationCatalogRevisionPrefix) +
        std::string(64U, '7');
    other_world.durable_observation = stamp_fixture(
        42U, other_world.measured_catalog_revision);
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), probe_fixture(41U), other_world,
                    std::nullopt)
                    .authoritative);

    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), probe_fixture(42U),
                    probe_fixture(42U), std::nullopt)
                    .authoritative);
}

TEST_CASE("a slot occupied at baseline is not this transaction's to own") {
    auto record = record_fixture();
    // Slot 5 lives in byte 0, bit 5 -> high nibble of the first byte, bit 1.
    record.baseline.occupancy_hex[0] = '2';
    auto earlier = probe_fixture(41U);
    auto later = probe_fixture(42U);
    earlier.marker_sightings.push_back(sighting_fixture());
    later.marker_sightings.push_back(sighting_fixture());
    const auto observation = build_ndms_native_import_recovery_observation(
        record, earlier, later, std::nullopt);
    CHECK(observation.authoritative);
    CHECK_FALSE(observation.target_absent_in_baseline);
}

TEST_CASE("a fingerprint is a match only against a recorded fingerprint") {
    auto record = record_fixture();
    record.target_full_revision.reset();
    auto earlier = probe_fixture(41U);
    auto later = probe_fixture(42U);
    earlier.marker_sightings.push_back(sighting_fixture());
    later.marker_sightings.push_back(sighting_fixture());
    const auto observation = build_ndms_native_import_recovery_observation(
        record, earlier, later, std::nullopt);
    CHECK(observation.authoritative);
    // No recorded revision means nothing to match, never a free pass.
    CHECK_FALSE(observation.target_fingerprint_matches);
}

TEST_CASE("ownership matches only a published record with the same revision") {
    auto record = record_fixture();
    record.ownership_revision = std::string(64U, 'e');
    auto earlier = probe_fixture(41U);
    auto later = probe_fixture(42U);
    earlier.marker_sightings.push_back(sighting_fixture());
    later.marker_sightings.push_back(sighting_fixture());

    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record, earlier, later, std::nullopt)
                    .ownership_record_matches);
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record, earlier, later, std::string(64U, 'f'))
                    .ownership_record_matches);
    CHECK(build_ndms_native_import_recovery_observation(
              record, earlier, later, std::string(64U, 'e'))
              .ownership_record_matches);
}

TEST_CASE("a marker outside the measured namespace is evidence, not a retry") {
    auto earlier = probe_fixture(41U);
    auto later = probe_fixture(42U);
    auto foreign = sighting_fixture();
    foreign.interface_name = "Wireguard127";
    earlier.marker_sightings.push_back(foreign);
    later.marker_sightings.push_back(foreign);
    const auto observation = build_ndms_native_import_recovery_observation(
        record_fixture(), earlier, later, std::nullopt);
    // Authoritative and not exact-owned: the classifier must block, because
    // retrying forever will not move a marker off an ineligible name.
    CHECK(observation.authoritative);
    CHECK_FALSE(observation.target_absent_in_baseline);
}

TEST_CASE("two markers are counted, and counted is all they need to be") {
    auto earlier = probe_fixture(41U);
    auto later = probe_fixture(42U);
    auto second = sighting_fixture();
    second.interface_name = "Wireguard6";
    earlier.marker_sightings = {sighting_fixture(), second};
    later.marker_sightings = {second, sighting_fixture()};
    const auto observation = build_ndms_native_import_recovery_observation(
        record_fixture(), earlier, later, std::nullopt);
    CHECK(observation.authoritative);
    CHECK(observation.marker_match_count == 2U);
    CHECK_FALSE(observation.marker_target.has_value());
}

TEST_CASE("duplicate sightings cannot masquerade as an agreeing multiset") {
    auto earlier = probe_fixture(41U);
    auto later = probe_fixture(42U);
    auto second = sighting_fixture();
    second.interface_name = "Wireguard6";
    earlier.marker_sightings = {sighting_fixture(), sighting_fixture()};
    later.marker_sightings = {sighting_fixture(), second};
    CHECK_FALSE(build_ndms_native_import_recovery_observation(
                    record_fixture(), earlier, later, std::nullopt)
                    .authoritative);
}

TEST_CASE("probes built by the real producer are accepted by this checker") {
    // The test that was missing, and whose absence let this module reject
    // every probe production could ever hand it. Nothing here is hand-built:
    // the probes come from build_ndms_native_import_recovery_probe and the
    // baseline digest from the same exported producer the probe uses, so a
    // checker that disagrees with either has nowhere to hide.
    auto payload = nlohmann::json::object();
    for (const auto* name :
         {"Wireguard0", "Wireguard1", "Wireguard2", "Wireguard3",
          "Wireguard4"}) {
        payload[name] = {{"type", "Wireguard"},
                         {"interface-name", name},
                         {"description", "occupied"}};
    }

    NdmsCatalogSnapshot snapshot;
    snapshot.catalog = parse_ndms_interface_catalog(payload);
    snapshot.status = NdmsCatalogCacheStatus::fresh;
    snapshot.refreshed = true;
    snapshot.observed_at = std::chrono::steady_clock::now();

    const std::string marker = "kpbr-ni-v1-" + std::string(32U, 'a');
    const auto measured_revision =
        ndms_native_import_recovery_catalog_revision(snapshot.catalog, {});
    const auto build_probe = [&](const std::uint64_t sequence) {
        return build_ndms_native_import_recovery_probe(
            snapshot, stamp_fixture(sequence, measured_revision), 5U,
            marker, {});
    };

    NdmsNativeImportWalRecord record;
    record.observation_binding = {
        kAuthority,
        kMutationEpoch,
        kBaselineSequence,
    };
    record.baseline.protected_catalog_sha256 =
        ndms_native_import_protected_catalog_digest(snapshot.catalog, 5U);
    record.baseline.occupancy_hex = std::string(32U, '0');

    const auto observation = build_ndms_native_import_recovery_observation(
        record, build_probe(41U), build_probe(42U), std::nullopt);
    CHECK(observation.authoritative);
    CHECK(observation.marker_match_count == 0U);
    // The producer emits the prefixed form; that is the shape, not an
    // accident of this fixture.
    CHECK(ndms_native_import_prefixed_sha256(
        record.baseline.protected_catalog_sha256,
        kNdmsNativeImportProtectedCatalogDigestPrefix));
}

} // namespace keen_pbr3
