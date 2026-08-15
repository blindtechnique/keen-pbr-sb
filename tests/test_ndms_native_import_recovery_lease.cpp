#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_import_recovery_lease.hpp"

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
            (fs::temp_directory_path() / "keen-pbr-nir-lease-XXXXXX")
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

std::string digest_of(char value) { return std::string(64U, value); }

NdmsNativeImportPersistedBaseline lease_baseline() {
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
        "ndms-native-import-v1-" + digest_of('b');
    record.baseline = lease_baseline();
    record.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            record.transaction_id,
            record.marker,
            record.candidate_revision,
            record.baseline.expected_created_interface);
    record.generation_ticket = "ndms-create-ticket-v1-" + digest_of('c');
    record.maintenance_base_generation = 41U;
    return record;
}

NdmsNativeImportWalStore store_for(const TempDirectory& directory) {
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return NdmsNativeImportWalStore(directory.path, hooks);
}

// An observation whose classifier verdict for a prepared record is the
// actionable abort_without_mutation: authoritative stable absence.
NdmsNativeImportRecoveryObservation absent_observation() {
    NdmsNativeImportRecoveryObservation observation;
    observation.authoritative = true;
    observation.generation_advanced = true;
    observation.protected_catalog_unchanged = true;
    observation.stable_absence = true;
    return observation;
}

} // namespace

TEST_CASE("admission re-reads the record and hands out one actionable lease") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);

    auto admission = admit_ndms_native_import_recovery(
        store, record, absent_observation());
    REQUIRE(admission.state ==
            NdmsNativeImportRecoveryAdmissionState::admitted);
    REQUIRE(admission.action.has_value());
    CHECK(*admission.action ==
          NdmsNativeImportRecoveryAction::abort_without_mutation);
    CHECK(admission.lease.held());

    // A second recoverer while the first holds the lease is refused without
    // waiting, before it can even look at the store.
    const auto second = admit_ndms_native_import_recovery(
        store, record, absent_observation());
    CHECK(second.state ==
          NdmsNativeImportRecoveryAdmissionState::lease_busy);
    CHECK_FALSE(second.lease.held());
}

TEST_CASE("a released lease admits the next recoverer") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);

    {
        const auto admission = admit_ndms_native_import_recovery(
            store, record, absent_observation());
        REQUIRE(admission.state ==
                NdmsNativeImportRecoveryAdmissionState::admitted);
    }
    CHECK(admit_ndms_native_import_recovery(
              store, record, absent_observation())
              .state ==
          NdmsNativeImportRecoveryAdmissionState::admitted);
}

TEST_CASE("a record advanced since classification is refused, not acted on") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto classified = prepared_record();
    REQUIRE(store.publish_prepared_exclusive(classified) ==
            NdmsNativeImportWalAdmissionState::admitted);

    // Somebody advanced the transaction between classification and admission.
    auto advanced = classified;
    advanced.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    advanced.reserved_generation = 42U;
    store.publish(advanced);

    const auto admission = admit_ndms_native_import_recovery(
        store, classified, absent_observation());
    // The classification was a statement about a record that no longer
    // exists; acting on it would abort a transaction that already sent its
    // import.
    CHECK(admission.state ==
          NdmsNativeImportRecoveryAdmissionState::record_changed);
    CHECK_FALSE(admission.lease.held());
    CHECK_FALSE(admission.action.has_value());
}

TEST_CASE("an empty store is a missing record, and never a lease") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto admission = admit_ndms_native_import_recovery(
        store, prepared_record(), absent_observation());
    CHECK(admission.state ==
          NdmsNativeImportRecoveryAdmissionState::inventory_not_ready);
    CHECK_FALSE(admission.lease.held());
}

TEST_CASE("retry and block verdicts earn no lease") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto record = prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);

    // Non-authoritative observation -> classifier answers retry: nothing to
    // serialize, so exclusivity must not be consumed by a waiter.
    const auto refused = admit_ndms_native_import_recovery(
        store, record, NdmsNativeImportRecoveryObservation{});
    CHECK(refused.state ==
          NdmsNativeImportRecoveryAdmissionState::action_not_actionable);
    CHECK_FALSE(refused.lease.held());

    // ...and the refusal left no lock behind: an actionable observation is
    // admitted immediately afterwards.
    CHECK(admit_ndms_native_import_recovery(
              store, record, absent_observation())
              .state ==
          NdmsNativeImportRecoveryAdmissionState::admitted);
}

} // namespace keen_pbr3
