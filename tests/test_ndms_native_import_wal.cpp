#include <doctest/doctest.h>

#include "crypto/sha256.hpp"
#include "keenetic/ndms_native_import_wal.hpp"
#include "keenetic/ndms_native_target_evidence.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

std::string digest(const std::string& prefix, const char value) {
    return prefix + std::string(64U, value);
}

NdmsNativeImportPersistedBaseline persisted_baseline(
    const std::uint32_t maintenance = 41U,
    const std::uint64_t allocator = 17U,
    const std::uint64_t observation = 7U) {
    auto payload = nlohmann::json::object();
    for (const std::uint8_t slot : {0U, 1U, 2U, 3U, 4U, 6U}) {
        const auto name = "Wireguard" + std::to_string(slot);
        payload[name] = {
            {"type", "Bridge"},
            {"interface-name", name},
            {"description", "occupied-slot"},
        };
    }
    NdmsCatalogSnapshot snapshot;
    snapshot.catalog = parse_ndms_interface_catalog(payload);
    snapshot.status = NdmsCatalogCacheStatus::fresh;
    snapshot.refreshed = true;
    snapshot.observed_at = std::chrono::steady_clock::time_point{
        std::chrono::seconds{123}};
    snapshot.observation_generation = observation;
    snapshot.observation_epoch = 3U;
    snapshot.invalidation_epoch = 3U;
    auto built = build_ndms_native_import_baseline(
        snapshot, "Wireguard5", maintenance, allocator);
    if (!built.success() || !built.evidence.has_value()) {
        throw std::runtime_error("cannot build WAL baseline fixture");
    }
    return persist_ndms_native_import_baseline(*built.evidence);
}

NdmsNativeImportWalRecord prepared_record() {
    NdmsNativeImportWalRecord record;
    record.transaction_id = std::string(32U, 'a');
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.candidate_revision =
        digest("ndms-native-import-v1-", 'b');
    record.baseline = persisted_baseline();
    record.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            record.transaction_id,
            record.marker,
            record.candidate_revision,
            record.baseline.expected_created_interface);
    record.generation_ticket =
        digest("ndms-create-ticket-v1-", 'c');
    record.maintenance_base_generation = 41U;
    return record;
}

void reserve(NdmsNativeImportWalRecord& record) {
    record.reserved_generation = 42U;
}

void record_response(NdmsNativeImportWalRecord& record) {
    record.response_manifest_sha256 =
        digest("ndms-import-response-manifest-v2-", 'f');
}

// The revision the production evidence builder actually emits, taken from it
// rather than spelled out here. Nine test files hardcode this prefix and none
// used to compare it against its producer - which is exactly the arrangement
// that let the observation builder demand a catalog-digest shape no producer
// has ever emitted, with every test agreeing and production always refusing.
// Deriving it means a divergence between the emitter and the WAL codec turns
// this suite red instead of passing on a shared guess.
std::string produced_target_revision() {
    const auto config = nlohmann::json::parse(R"({
      "description": "binding fixture",
      "ip": {"address": {"address": "10.0.0.1", "mask": "255.255.255.0"}},
      "up": true
    })");
    const auto status = nlohmann::json::parse(R"({
      "id": "Wireguard5", "interface-name": "Wireguard5",
      "type": "Wireguard", "description": "binding fixture",
      "link": "down", "state": "up"
    })");
    const auto result = build_ndms_native_target_evidence(
        "Wireguard5", config, status, nlohmann::json::object());
    REQUIRE(result.evidence.has_value());
    return result.evidence->full_revision;
}

void verify_target(NdmsNativeImportWalRecord& record) {
    record.created_interface = "Wireguard5";
    record.target_full_revision = produced_target_revision();
}

NdmsNativeImportRecoveryObservation stable_absence() {
    NdmsNativeImportRecoveryObservation observation;
    observation.authoritative = true;
    observation.generation_advanced = true;
    observation.protected_catalog_unchanged = true;
    observation.stable_absence = true;
    return observation;
}

NdmsNativeImportRecoveryObservation exact_owned_target() {
    auto observation = stable_absence();
    observation.stable_absence = false;
    observation.marker_match_count = 1U;
    observation.marker_target = "Wireguard5";
    observation.target_absent_in_baseline = true;
    observation.target_down = true;
    observation.target_fingerprint_matches = true;
    return observation;
}

bool parse_rejected(const std::string& value) {
    try {
        static_cast<void>(parse_ndms_native_import_wal(value));
        return false;
    } catch (const NdmsNativeImportWalError&) {
        return true;
    }
}

} // namespace

TEST_CASE("dormant native import WAL round-trips every valid phase") {
    std::vector<NdmsNativeImportWalRecord> records;

    auto prepared = prepared_record();
    records.push_back(prepared);

    auto inflight = prepared;
    inflight.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    reserve(inflight);
    records.push_back(inflight);

    auto response = inflight;
    response.phase = NdmsNativeImportWalPhase::response_recorded;
    record_response(response);
    response.created_interface = "Wireguard5";
    records.push_back(response);

    auto verified = response;
    verified.phase = NdmsNativeImportWalPhase::target_verified;
    verify_target(verified);
    records.push_back(verified);

    auto owned = verified;
    owned.phase = NdmsNativeImportWalPhase::ownership_published;
    owned.ownership_revision =
        digest("ndms-native-owner-v1-", 'e');
    records.push_back(owned);

    auto rollback = inflight;
    rollback.phase = NdmsNativeImportWalPhase::rollback_requested;
    records.push_back(rollback);

    auto deleting = rollback;
    deleting.phase = NdmsNativeImportWalPhase::delete_may_be_inflight;
    records.push_back(deleting);

    auto absent = deleting;
    absent.phase = NdmsNativeImportWalPhase::absence_verified;
    records.push_back(absent);

    for (const auto& record : records) {
        CAPTURE(ndms_native_import_wal_phase_name(record.phase));
        const auto serialized = serialize_ndms_native_import_wal(record);
        CHECK(serialized.size() <= kNdmsNativeImportWalMaximumBytes);
        CHECK(parse_ndms_native_import_wal(serialized) == record);
    }
}

TEST_CASE("native import WAL codec is exact integrity-bound and non-secret") {
    const auto record = prepared_record();
    const auto serialized = serialize_ndms_native_import_wal(record);
    CHECK(serialized.find("PrivateKey") == std::string::npos);
    CHECK(serialized.find("PresharedKey") == std::string::npos);
    CHECK(serialized.find("Endpoint") == std::string::npos);
    CHECK(serialized.find("AllowedIPs") == std::string::npos);
    CHECK(serialized.find("Address") == std::string::npos);
    CHECK(serialized.find("\"schema_version\": 2") !=
          std::string::npos);
    CHECK(serialized.find("\"baseline\"") != std::string::npos);
    CHECK(serialized.find("\"occupancy_hex\"") !=
          std::string::npos);
    CHECK(serialized.find("\"request_binding_sha256\"") !=
          std::string::npos);

    auto duplicate = serialized;
    duplicate.insert(
        duplicate.find('{') + 1U,
        "\n  \"phase\": \"prepared\",");
    CHECK(parse_rejected(duplicate));

    auto nested_duplicate = serialized;
    const auto baseline_object = nested_duplicate.find("\"baseline\": {");
    REQUIRE(baseline_object != std::string::npos);
    const auto baseline_open = nested_duplicate.find('{', baseline_object);
    REQUIRE(baseline_open != std::string::npos);
    nested_duplicate.insert(
        baseline_open + 1U,
        "\n    \"occupancy_hex\": "
        "\"5f000000000000000000000000000000\",");
    CHECK(parse_rejected(nested_duplicate));

    auto unknown = serialized;
    unknown.insert(
        unknown.find('{') + 1U,
        "\n  \"private_key\": \"must-not-enter-wal\",");
    CHECK(parse_rejected(unknown));

    auto tampered = serialized;
    const auto ticket = tampered.find(std::string(64U, 'c'));
    REQUIRE(ticket != std::string::npos);
    tampered[ticket] = 'd';
    CHECK(parse_rejected(tampered));

    CHECK(parse_rejected(std::string(
        kNdmsNativeImportWalMaximumBytes + 1U, 'x')));

    auto legacy = nlohmann::json::parse(serialized);
    legacy.erase("integrity_sha256");
    legacy["schema_version"] = 1;
    legacy["integrity_sha256"] = Sha256::hex(legacy.dump());
    CHECK(parse_rejected(legacy.dump()));
}

TEST_CASE("native import WAL rejects malformed or forged v2 baseline evidence") {
    auto forged_baseline = prepared_record();
    forged_baseline.baseline.baseline_sha256.back() =
        forged_baseline.baseline.baseline_sha256.back() == '0'
            ? '1'
            : '0';
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(forged_baseline),
        NdmsNativeImportWalError);

    auto malformed_occupancy = prepared_record();
    malformed_occupancy.baseline.occupancy_hex.pop_back();
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(malformed_occupancy),
        NdmsNativeImportWalError);

    auto forged_protected = prepared_record();
    forged_protected.baseline.protected_catalog_sha256.back() =
        forged_protected.baseline.protected_catalog_sha256.back() == '0'
            ? '1'
            : '0';
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(forged_protected),
        NdmsNativeImportWalError);

    auto forged_binding = prepared_record();
    forged_binding.request_binding_sha256.back() =
        forged_binding.request_binding_sha256.back() == '0' ? '1' : '0';
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(forged_binding),
        NdmsNativeImportWalError);

    auto mismatched_generation = prepared_record();
    mismatched_generation.baseline = persisted_baseline(40U);
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(mismatched_generation),
        NdmsNativeImportWalError);
}

TEST_CASE("native import WAL v2 rejects protected and non-first-free baselines") {
    auto protected_target = prepared_record();
    protected_target.baseline.expected_created_interface = "Wireguard4";
    protected_target.baseline.expected_target_slot = 4U;
    protected_target.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            protected_target.transaction_id,
            protected_target.marker,
            protected_target.candidate_revision,
            protected_target.baseline.expected_created_interface);
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(protected_target),
        NdmsNativeImportWalError);

    auto first_free_mismatch = prepared_record();
    first_free_mismatch.baseline.occupancy_hex[0] = '4';
    REQUIRE(first_free_mismatch.baseline.occupancy_hex !=
            prepared_record().baseline.occupancy_hex);
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(first_free_mismatch),
        NdmsNativeImportWalError);
}

TEST_CASE("native import WAL v2 is limited to measured plain WireGuard") {
    auto awg = prepared_record();
    awg.kind = NdmsNativeTunnelImportKind::amnezia_wireguard;
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(awg),
        NdmsNativeImportWalError);

    auto forged_document = nlohmann::json::parse(
        serialize_ndms_native_import_wal(prepared_record()));
    forged_document.erase("integrity_sha256");
    forged_document["kind"] = "amnezia_wireguard";
    forged_document["integrity_sha256"] =
        Sha256::hex(forged_document.dump());
    CHECK(parse_rejected(forged_document.dump()));
}

TEST_CASE("native import WAL rejects protected targets and phase evidence leaks") {
    auto protected_target = prepared_record();
    protected_target.phase =
        NdmsNativeImportWalPhase::response_recorded;
    reserve(protected_target);
    record_response(protected_target);
    protected_target.created_interface = "Wireguard99";
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(protected_target),
        NdmsNativeImportWalError);

    auto early_evidence = prepared_record();
    early_evidence.created_interface = "Wireguard5";
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(early_evidence),
        NdmsNativeImportWalError);

    auto mismatched_created_target = prepared_record();
    mismatched_created_target.phase =
        NdmsNativeImportWalPhase::response_recorded;
    reserve(mismatched_created_target);
    record_response(mismatched_created_target);
    mismatched_created_target.created_interface = "Wireguard6";
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(mismatched_created_target),
        NdmsNativeImportWalError);

    auto missing_manifest = prepared_record();
    missing_manifest.phase =
        NdmsNativeImportWalPhase::response_recorded;
    reserve(missing_manifest);
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(missing_manifest),
        NdmsNativeImportWalError);

    auto raw_manifest = prepared_record();
    raw_manifest.phase =
        NdmsNativeImportWalPhase::response_recorded;
    reserve(raw_manifest);
    raw_manifest.response_manifest_sha256 =
        "ndms-native-import-response-v2|message=secret-value";
    CHECK_THROWS_AS(
        serialize_ndms_native_import_wal(raw_manifest),
        NdmsNativeImportWalError);
}

TEST_CASE("native import WAL transitions are idempotent but never skip or rewind") {
    using Phase = NdmsNativeImportWalPhase;
    CHECK(valid_ndms_native_import_wal_transition(
        Phase::prepared, Phase::prepared));
    CHECK(valid_ndms_native_import_wal_transition(
        Phase::prepared, Phase::import_may_be_inflight));
    CHECK_FALSE(valid_ndms_native_import_wal_transition(
        Phase::prepared, Phase::response_recorded));
    CHECK(valid_ndms_native_import_wal_transition(
        Phase::import_may_be_inflight, Phase::response_recorded));
    CHECK(valid_ndms_native_import_wal_transition(
        Phase::import_may_be_inflight, Phase::rollback_requested));
    CHECK(valid_ndms_native_import_wal_transition(
        Phase::target_verified, Phase::ownership_published));
    CHECK(valid_ndms_native_import_wal_transition(
        Phase::ownership_published, Phase::rollback_requested));
    CHECK(valid_ndms_native_import_wal_transition(
        Phase::rollback_requested, Phase::delete_may_be_inflight));
    CHECK(valid_ndms_native_import_wal_transition(
        Phase::delete_may_be_inflight, Phase::absence_verified));
    CHECK_FALSE(valid_ndms_native_import_wal_transition(
        Phase::absence_verified, Phase::prepared));
}

TEST_CASE("native import recovery never retries an ambiguous import POST") {
    auto record = prepared_record();
    record.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    reserve(record);

    auto stale = stable_absence();
    stale.authoritative = false;
    CHECK(classify_ndms_native_import_recovery(record, stale) ==
          NdmsNativeImportRecoveryAction::retry_read_only_observation);

    CHECK(classify_ndms_native_import_recovery(
              record, stable_absence()) ==
          NdmsNativeImportRecoveryAction::abort_without_mutation);
    CHECK(classify_ndms_native_import_recovery(
              record, exact_owned_target()) ==
          NdmsNativeImportRecoveryAction::
              rollback_delete_exact_owned);

    // The observation the real builder would produce for THIS record. The
    // codec forbids target_full_revision at this phase, and the observation
    // sets target_fingerprint_matches only from a revision the record carries
    // - so a fingerprint here is not merely absent, it is impossible. The
    // assertion above passes on an observation that could never exist, which
    // is why demanding the fingerprint went unnoticed while it sent every
    // crashed import to block_unknown: an orphaned interface left on the
    // router and a WAL record blocking every future import.
    REQUIRE_FALSE(record.target_full_revision.has_value());
    auto unverifiable = exact_owned_target();
    unverifiable.target_fingerprint_matches = false;
    CHECK(classify_ndms_native_import_recovery(record, unverifiable) ==
          NdmsNativeImportRecoveryAction::
              rollback_delete_exact_owned);

    // ...and the marker triple is still doing the work: drop any leg of it and
    // the rollback is refused.
    for (const auto& weaken :
         {+[](NdmsNativeImportRecoveryObservation& o) {
              o.target_absent_in_baseline = false;
          },
          +[](NdmsNativeImportRecoveryObservation& o) {
              o.target_down = false;
          },
          +[](NdmsNativeImportRecoveryObservation& o) {
              o.marker_target = "Wireguard0";
          }}) {
        auto weakened = unverifiable;
        weaken(weakened);
        CHECK(classify_ndms_native_import_recovery(record, weakened) ==
              NdmsNativeImportRecoveryAction::block_unknown);
    }
}

TEST_CASE("the codec accepts the revision its producer actually emits") {
    // The binding the chain lacked. The evidence builder emits the target
    // revision; the WAL codec decides whether a record may carry it; and the
    // two agreed only by both being handed the same literal in tests. Round
    // -tripping a real one through serialize/parse is what proves they agree.
    auto record = prepared_record();
    record.phase = NdmsNativeImportWalPhase::target_verified;
    reserve(record);
    record_response(record);
    verify_target(record);
    const auto produced = *record.target_full_revision;
    CHECK(produced.rfind("ndms-rci-full-v1-", 0U) == 0U);

    const auto serialized = serialize_ndms_native_import_wal(record);
    const auto parsed = parse_ndms_native_import_wal(serialized);
    REQUIRE(parsed.target_full_revision.has_value());
    CHECK(*parsed.target_full_revision == produced);

    // And a revision of the wrong shape is still refused, so the acceptance
    // above is a decision rather than an absence of checking.
    auto wrong = record;
    wrong.target_full_revision = std::string(64U, 'd');
    CHECK_THROWS_AS(serialize_ndms_native_import_wal(wrong),
                    NdmsNativeImportWalError);
}

TEST_CASE("a recorded fingerprint that does not match still refuses") {
    // Where the codec DOES mandate a revision, a mismatch is a changed world
    // and must block - the relaxation above must not reach these phases.
    auto record = prepared_record();
    record.phase = NdmsNativeImportWalPhase::target_verified;
    reserve(record);
    record_response(record);
    verify_target(record);
    REQUIRE(record.target_full_revision.has_value());

    CHECK(classify_ndms_native_import_recovery(
              record, exact_owned_target()) ==
          NdmsNativeImportRecoveryAction::
              rollback_delete_exact_owned);

    auto moved = exact_owned_target();
    moved.target_fingerprint_matches = false;
    CHECK(classify_ndms_native_import_recovery(record, moved) ==
          NdmsNativeImportRecoveryAction::block_unknown);
}

TEST_CASE("prepared native import WAL can recover without generation advance") {
    const auto record = prepared_record();
    auto observation = stable_absence();
    observation.generation_advanced = false;

    CHECK(classify_ndms_native_import_recovery(record, observation) ==
          NdmsNativeImportRecoveryAction::abort_without_mutation);

    observation.authoritative = false;
    CHECK(classify_ndms_native_import_recovery(record, observation) ==
          NdmsNativeImportRecoveryAction::retry_read_only_observation);

    observation = exact_owned_target();
    observation.generation_advanced = false;
    CHECK(classify_ndms_native_import_recovery(record, observation) ==
          NdmsNativeImportRecoveryAction::block_unknown);
}

TEST_CASE("native import recovery blocks protected ambiguous and mismatched targets") {
    auto record = prepared_record();
    record.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    reserve(record);

    auto protected_target = exact_owned_target();
    protected_target.marker_target = "Wireguard4";
    CHECK(classify_ndms_native_import_recovery(
              record, protected_target) ==
          NdmsNativeImportRecoveryAction::block_unknown);

    auto unsupported_target = exact_owned_target();
    unsupported_target.marker_target = "Wireguard126";
    CHECK(classify_ndms_native_import_recovery(
              record, unsupported_target) ==
          NdmsNativeImportRecoveryAction::block_unknown);

    auto multiple = exact_owned_target();
    multiple.marker_match_count = 2U;
    CHECK(classify_ndms_native_import_recovery(record, multiple) ==
          NdmsNativeImportRecoveryAction::block_unknown);

    // A fingerprint mismatch used to be asserted here, and it pinned the
    // defect rather than a guarantee: this phase cannot carry a revision, so
    // target_fingerprint_matches is false in every observation the real
    // builder can produce, and the assertion quietly stated that a crashed
    // inflight import always blocks. The mismatch guarantee it was meant to
    // express is now pinned where a revision can actually exist, in "a
    // recorded fingerprint that does not match still refuses".
    auto missing_created = exact_owned_target();
    missing_created.target_fingerprint_matches = false;
    missing_created.target_absent_in_baseline = false;
    CHECK(classify_ndms_native_import_recovery(record, missing_created) ==
          NdmsNativeImportRecoveryAction::block_unknown);

    auto protected_changed = exact_owned_target();
    protected_changed.protected_catalog_unchanged = false;
    CHECK(classify_ndms_native_import_recovery(
              record, protected_changed) ==
          NdmsNativeImportRecoveryAction::block_unknown);
}

TEST_CASE("native import recovery separates forward ownership and exact rollback") {
    auto owned = prepared_record();
    owned.phase = NdmsNativeImportWalPhase::ownership_published;
    reserve(owned);
    record_response(owned);
    verify_target(owned);
    owned.ownership_revision =
        digest("ndms-native-owner-v1-", 'e');

    auto observation = exact_owned_target();
    observation.ownership_record_matches = true;
    CHECK(classify_ndms_native_import_recovery(owned, observation) ==
          NdmsNativeImportRecoveryAction::resume_forward_reconcile);
    observation.ownership_record_matches = false;
    CHECK(classify_ndms_native_import_recovery(owned, observation) ==
          NdmsNativeImportRecoveryAction::block_unknown);

    auto rollback = prepared_record();
    rollback.phase = NdmsNativeImportWalPhase::rollback_requested;
    reserve(rollback);
    CHECK(classify_ndms_native_import_recovery(
              rollback, exact_owned_target()) ==
          NdmsNativeImportRecoveryAction::retry_exact_owned_delete);

    rollback.created_interface = "Wireguard6";
    CHECK(classify_ndms_native_import_recovery(
              rollback, exact_owned_target()) ==
          NdmsNativeImportRecoveryAction::block_unknown);
    rollback.created_interface.reset();

    CHECK(classify_ndms_native_import_recovery(
              rollback, stable_absence()) ==
          NdmsNativeImportRecoveryAction::complete_rollback);
}

TEST_CASE("native import recovery rejects every structurally invalid public record") {
    auto owned = prepared_record();
    owned.phase = NdmsNativeImportWalPhase::ownership_published;
    reserve(owned);
    record_response(owned);
    verify_target(owned);
    owned.ownership_revision =
        digest("ndms-native-owner-v1-", 'e');
    auto observation = exact_owned_target();
    observation.ownership_record_matches = true;

    auto missing_ownership = owned;
    missing_ownership.ownership_revision.reset();
    CHECK(classify_ndms_native_import_recovery(
              missing_ownership, observation) ==
          NdmsNativeImportRecoveryAction::block_unknown);

    auto bad_marker = owned;
    bad_marker.marker = "kpbr-ni-v1-wrong-transaction";
    CHECK(classify_ndms_native_import_recovery(
              bad_marker, observation) ==
          NdmsNativeImportRecoveryAction::block_unknown);

    auto missing_manifest = owned;
    missing_manifest.response_manifest_sha256.reset();
    CHECK(classify_ndms_native_import_recovery(
              missing_manifest, observation) ==
          NdmsNativeImportRecoveryAction::block_unknown);

    auto rollback = prepared_record();
    rollback.phase = NdmsNativeImportWalPhase::rollback_requested;
    // An active rollback phase without its reserved generation is malformed.
    CHECK(classify_ndms_native_import_recovery(
              rollback, exact_owned_target()) ==
          NdmsNativeImportRecoveryAction::block_unknown);
}
