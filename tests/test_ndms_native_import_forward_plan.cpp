#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_import_forward_plan.hpp"

#include "../src/keenetic/ndms_catalog_cache.hpp"
#include "../src/keenetic/ndms_native_import_recovery_dispatch.hpp"
#include "../src/keenetic/ndms_native_ownership_store.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cerrno>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-nir-fwd-XXXXXX").string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        path = created;
    }

    ~TempDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
        fs::remove(fs::path(path.string() + ".recovery-lock"), error);
    }

    fs::path path;
};

const std::string kMeasuredRevision =
    "ndms-rci-full-v1-" + std::string(64U, 'd');

NdmsNativeImportPersistedBaseline forward_baseline() {
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
    snapshot.observation_generation = 7U;
    snapshot.observation_epoch = 3U;
    snapshot.invalidation_epoch = 3U;
    auto built = build_ndms_native_import_baseline(
        snapshot, "Wireguard5", 41U, 17U);
    REQUIRE(built.success());
    REQUIRE(built.evidence.has_value());
    return persist_ndms_native_import_baseline(*built.evidence);
}

NdmsNativeImportWalRecord response_recorded_record(
    const NdmsNativeTunnelImportKind kind =
        NdmsNativeTunnelImportKind::wireguard) {
    NdmsNativeImportWalRecord record;
    record.kind = kind;
    record.transaction_id = std::string(32U, 'a');
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.candidate_revision =
        "ndms-native-import-v1-" + std::string(64U, 'b');
    record.snapshot_revision = record.candidate_revision;
    record.observation_binding = {std::string(32U, 'd'), 9U, 7U};
    record.baseline = forward_baseline();
    record.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            record.transaction_id,
            record.marker,
            record.candidate_revision,
            record.kind,
            record.baseline.expected_created_interface);
    record.generation_ticket =
        "ndms-create-ticket-v1-" + std::string(64U, 'c');
    record.maintenance_base_generation = 41U;
    record.phase = NdmsNativeImportWalPhase::response_recorded;
    record.reserved_generation = 42U;
    record.response_manifest_sha256 =
        "ndms-import-response-manifest-v3-" + std::string(64U, 'e');
    return record;
}

NdmsNativeImportRecoveryObservation verified_observation() {
    NdmsNativeImportRecoveryObservation observation;
    observation.authoritative = true;
    observation.generation_advanced = true;
    observation.protected_catalog_unchanged = true;
    observation.marker_match_count = 1U;
    observation.marker_target = "Wireguard5";
    observation.target_absent_in_baseline = true;
    observation.target_down = true;
    observation.target_fingerprint_matches = false;
    return observation;
}

} // namespace

TEST_CASE("forward completion preserves WG and AWG kind into ownership") {
    for (const auto kind : std::array{
             NdmsNativeTunnelImportKind::wireguard,
             NdmsNativeTunnelImportKind::amnezia_wireguard}) {
        CAPTURE(ndms_native_tunnel_import_kind_name(kind));
        TempDirectory directory;
        NdmsNativeImportWalStoreTestHooks hooks;
        hooks.allow_current_process_owner = true;
        NdmsNativeImportWalStore store(directory.path / "wal", hooks);
        NdmsNativeOwnershipStore ownership(directory.path / "ownership");

        auto prepared = response_recorded_record(kind);
        prepared.phase = NdmsNativeImportWalPhase::prepared;
        prepared.reserved_generation.reset();
        prepared.response_manifest_sha256.reset();
        REQUIRE(store.publish_prepared_exclusive(prepared) ==
                NdmsNativeImportWalAdmissionState::admitted);
        auto inflight = response_recorded_record(kind);
        inflight.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
        inflight.response_manifest_sha256.reset();
        store.publish(inflight);
        const auto record = response_recorded_record(kind);
        store.publish(record);

        const auto completion = plan_ndms_native_import_forward_completion(
            record, verified_observation(), kMeasuredRevision);
        REQUIRE(completion.actionable());
        REQUIRE(completion.plan.steps.size() == 4U);
        CHECK(completion.enriched.created_interface == "Wireguard5");
        CHECK(completion.enriched.target_full_revision == kMeasuredRevision);

        auto admission = admit_ndms_native_import_forward(
            store, record, completion);
        REQUIRE(admission.state ==
                NdmsNativeImportRecoveryAdmissionState::admitted);

        const auto result = dispatch_ndms_native_import_recovery(
            store, admission.lease, completion.enriched, completion.plan,
            std::nullopt, nullptr, &ownership);
        CHECK(result.state ==
              NdmsNativeImportRecoveryDispatchState::completed);
        CHECK(result.completed_steps == 4U);

        CHECK(store.load(record.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        const auto claim = ownership.read("Wireguard5");
        REQUIRE(claim.state == NdmsNativeOwnershipReadState::valid);
        CHECK(claim.record->transaction_id == record.transaction_id);
        CHECK(claim.record->kind == kind);
        CHECK(claim.record->target_full_revision == kMeasuredRevision);
        CHECK(store.publish_prepared_exclusive(prepared) ==
              NdmsNativeImportWalAdmissionState::admitted);
    }
}

TEST_CASE("forward completion accepts exact owned up state but refuses drift") {
    const auto record = response_recorded_record();

    auto moved = verified_observation();
    moved.target_down = false;
    CHECK(plan_ndms_native_import_forward_completion(
              record, moved, kMeasuredRevision)
              .actionable());

    auto wrong_target = verified_observation();
    wrong_target.marker_target = "Wireguard6";
    CHECK_FALSE(plan_ndms_native_import_forward_completion(
                    record, wrong_target, kMeasuredRevision)
                    .actionable());

    auto drifted = verified_observation();
    drifted.protected_catalog_unchanged = false;
    CHECK_FALSE(plan_ndms_native_import_forward_completion(
                    record, drifted, kMeasuredRevision)
                    .actionable());

    CHECK_FALSE(plan_ndms_native_import_forward_completion(
                    record, verified_observation(), "bare-revision")
                    .actionable());

    auto rollback = record;
    rollback.phase = NdmsNativeImportWalPhase::rollback_requested;
    CHECK_FALSE(plan_ndms_native_import_forward_completion(
                    rollback, verified_observation(), kMeasuredRevision)
                    .actionable());
}

TEST_CASE("a verified interface whose bytes moved is re-verified, not trusted") {
    auto record = response_recorded_record();
    record.phase = NdmsNativeImportWalPhase::target_verified;
    record.created_interface = "Wireguard5";
    record.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'f');

    // The measurement disagrees with what verification recorded.
    auto observation = verified_observation();
    observation.target_fingerprint_matches = false;
    CHECK_FALSE(plan_ndms_native_import_forward_completion(
                    record, observation, kMeasuredRevision)
                    .actionable());

    // Agreeing measurement resumes with the shorter plan.
    observation.target_fingerprint_matches = true;
    const auto completion = plan_ndms_native_import_forward_completion(
        record, observation, *record.target_full_revision);
    REQUIRE(completion.actionable());
    CHECK(completion.plan.steps.size() == 3U);
    CHECK(completion.plan.steps.front() ==
          NdmsNativeImportRecoveryStep::publish_ownership);
}

TEST_CASE("a plan that publishes ownership demands the store for it") {
    TempDirectory directory;
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    NdmsNativeImportWalStore store(directory.path / "wal", hooks);

    auto prepared = response_recorded_record();
    prepared.phase = NdmsNativeImportWalPhase::prepared;
    prepared.reserved_generation.reset();
    prepared.response_manifest_sha256.reset();
    REQUIRE(store.publish_prepared_exclusive(prepared) ==
            NdmsNativeImportWalAdmissionState::admitted);
    auto inflight = response_recorded_record();
    inflight.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    inflight.response_manifest_sha256.reset();
    store.publish(inflight);
    const auto record = response_recorded_record();
    store.publish(record);

    const auto completion = plan_ndms_native_import_forward_completion(
        record, verified_observation(), kMeasuredRevision);
    REQUIRE(completion.actionable());
    auto admission = admit_ndms_native_import_forward(
        store, record, completion);
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);

    const auto refused = dispatch_ndms_native_import_recovery(
        store, admission.lease, completion.enriched, completion.plan,
        std::nullopt, nullptr, nullptr);
    CHECK(refused.state == NdmsNativeImportRecoveryDispatchState::
                               ownership_store_missing);
    // Refused before the first step: the record is untouched.
    const auto loaded = store.load(record.transaction_id);
    REQUIRE(loaded.recovery_permitted());
    CHECK(loaded.record->phase ==
          NdmsNativeImportWalPhase::response_recorded);
}

} // namespace keen_pbr3
