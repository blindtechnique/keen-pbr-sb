#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_import_recovery_dispatch.hpp"

#include "../src/keenetic/ndms_catalog_cache.hpp"
#include "../src/keenetic/ndms_interface_inventory.hpp"

#include <nlohmann/json.hpp>

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
            (fs::temp_directory_path() / "keen-pbr-nir-disp-XXXXXX")
                .string();
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

NdmsNativeImportPersistedBaseline dispatch_baseline() {
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

NdmsNativeImportWalRecord prepared_record() {
    NdmsNativeImportWalRecord record;
    record.transaction_id = std::string(32U, 'a');
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.candidate_revision =
        "ndms-native-import-v1-" + std::string(64U, 'b');
    record.baseline = dispatch_baseline();
    record.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            record.transaction_id,
            record.marker,
            record.candidate_revision,
            record.baseline.expected_created_interface);
    record.generation_ticket =
        "ndms-create-ticket-v1-" + std::string(64U, 'c');
    record.maintenance_base_generation = 41U;
    return record;
}

NdmsNativeImportWalRecord inflight_record() {
    auto record = prepared_record();
    record.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    record.reserved_generation = 42U;
    return record;
}

NdmsNativeImportWalStore store_for(const TempDirectory& directory) {
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return NdmsNativeImportWalStore(directory.path, hooks);
}

NdmsNativeImportRecoveryObservation absent_observation() {
    NdmsNativeImportRecoveryObservation observation;
    observation.authoritative = true;
    observation.generation_advanced = true;
    observation.protected_catalog_unchanged = true;
    observation.stable_absence = true;
    return observation;
}

NdmsNativeImportRecoveryObservation owned_target_observation() {
    NdmsNativeImportRecoveryObservation observation;
    observation.authoritative = true;
    observation.generation_advanced = true;
    observation.protected_catalog_unchanged = true;
    observation.marker_match_count = 1U;
    observation.marker_target = "Wireguard5";
    observation.target_absent_in_baseline = true;
    observation.target_down = true;
    observation.target_fingerprint_matches = true;
    return observation;
}

} // namespace

TEST_CASE("an aborted transaction dispatches to an empty, admissible store") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);

    auto admission = admit_ndms_native_import_recovery(
        store, record, absent_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);

    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, std::nullopt, nullptr);
    CHECK(result.state ==
          NdmsNativeImportRecoveryDispatchState::completed);
    CHECK(result.completed_steps == 1U);

    // The store is empty and admits the next transaction: the whole point of
    // finishing a recovery.
    CHECK(store.publish_prepared_exclusive(prepared_record()) ==
          NdmsNativeImportWalAdmissionState::admitted);
}

TEST_CASE("a rollback publishes intent, deletes under it, and finishes") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = inflight_record();
    REQUIRE(store.publish_prepared_exclusive(prepared_record()) ==
            NdmsNativeImportWalAdmissionState::admitted);
    store.publish(record);

    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_target_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    REQUIRE(*admission.action ==
            NdmsNativeImportRecoveryAction::rollback_delete_exact_owned);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);

    std::size_t deletes = 0U;
    NdmsNativeImportWalPhase phase_at_delete{};
    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5",
        [&](const std::string& target, const std::string& marker) {
            ++deletes;
            CHECK(target == "Wireguard5");
            CHECK(marker == record.marker);
            // The intent is durable before the delete runs: a crash right
            // here must recover as a retried delete, not as a deletion nobody
            // recorded the reason for.
            const auto loaded = store.load(record.transaction_id);
            REQUIRE(loaded.recovery_permitted());
            phase_at_delete = loaded.record->phase;
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        });
    CHECK(result.state ==
          NdmsNativeImportRecoveryDispatchState::completed);
    CHECK(result.completed_steps == 5U);
    CHECK(deletes == 1U);
    CHECK(phase_at_delete ==
          NdmsNativeImportWalPhase::delete_may_be_inflight);
    CHECK(store.load(record.transaction_id).state ==
          NdmsNativeImportWalLoadState::absent);
}

TEST_CASE("a failed delete leaves the durable account of how far this got") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = inflight_record();
    REQUIRE(store.publish_prepared_exclusive(prepared_record()) ==
            NdmsNativeImportWalAdmissionState::admitted);
    store.publish(record);

    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_target_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);

    const auto result = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::failed;
        });
    CHECK(result.state ==
          NdmsNativeImportRecoveryDispatchState::step_failed);
    REQUIRE(result.failed_step.has_value());
    CHECK(*result.failed_step ==
          NdmsNativeImportRecoveryStep::delete_exact_owned_target);
    CHECK(result.completed_steps == 2U);

    // Nothing unwound: the record still says delete_may_be_inflight, which is
    // exactly what the next recovery pass classifies from.
    const auto loaded = store.load(record.transaction_id);
    REQUIRE(loaded.recovery_permitted());
    CHECK(loaded.record->phase ==
          NdmsNativeImportWalPhase::delete_may_be_inflight);
}

TEST_CASE("the dispatcher refuses before the first step, loudly") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = inflight_record();
    REQUIRE(store.publish_prepared_exclusive(prepared_record()) ==
            NdmsNativeImportWalAdmissionState::admitted);
    store.publish(record);

    auto admission = admit_ndms_native_import_recovery(
        store, record, owned_target_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    const auto plan =
        plan_ndms_native_import_recovery(record, *admission.action);

    const auto no_executor = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard5", nullptr);
    CHECK(no_executor.state ==
          NdmsNativeImportRecoveryDispatchState::target_missing);

    const auto no_target = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, std::nullopt,
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        });
    CHECK(no_target.state ==
          NdmsNativeImportRecoveryDispatchState::target_missing);

    // A protected name reaching this far is refused by the last line of
    // defence, however it got past the earlier ones.
    const auto protected_slot = dispatch_ndms_native_import_recovery(
        store, admission.lease, record, plan, "Wireguard0",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        });
    CHECK(protected_slot.state ==
          NdmsNativeImportRecoveryDispatchState::target_not_eligible);

    NdmsNativeImportRecoveryLease released_lease =
        std::move(admission.lease);
    { const auto discard = std::move(released_lease); (void)discard; }
    const auto no_lease = dispatch_ndms_native_import_recovery(
        store, released_lease, record, plan, "Wireguard5",
        [](const std::string&, const std::string&) {
            return NdmsNativeImportRecoveryDeleteOutcome::
                deleted_confirmed;
        });
    CHECK(no_lease.state ==
          NdmsNativeImportRecoveryDispatchState::lease_not_held);

    // Every refusal above left the record untouched.
    const auto loaded = store.load(record.transaction_id);
    REQUIRE(loaded.recovery_permitted());
    CHECK(loaded.record->phase ==
          NdmsNativeImportWalPhase::import_may_be_inflight);
}

} // namespace keen_pbr3
