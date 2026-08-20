#include <doctest/doctest.h>

#include "keenetic/ndms_native_delete_wal_store.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace keen_pbr3;

namespace {

namespace fs = std::filesystem;

class DeleteWalTempDirectory final {
public:
    DeleteWalTempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-delete-wal-XXXXXX")
                .string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        path = created;
    }

    ~DeleteWalTempDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }

    fs::path path;
};

std::string revision(const std::string& prefix, const char digit) {
    return prefix + std::string(64U, digit);
}

NdmsNativeDeleteObservationPair observation_pair(
    const std::uint64_t first_sequence,
    const char first_revision,
    const char second_revision) {
    return {
        revision(kNdmsNativeObservationCatalogRevisionPrefix,
                 first_revision),
        first_sequence,
        revision(kNdmsNativeObservationCatalogRevisionPrefix,
                 second_revision),
        first_sequence + 1U,
    };
}

NdmsNativeDeleteWalRecord prepared_delete_record(
    const char transaction_digit = 'a') {
    NdmsNativeDeleteWalRecord record;
    record.transaction_id = std::string(32U, transaction_digit);
    record.interface_name = "Wireguard5";
    record.kind = NdmsNativeTunnelImportKind::wireguard;
    record.ownership_revision =
        revision("ndms-native-owner-v3-", 'b');
    record.ownership_transaction_id = std::string(32U, 'c');
    record.marker = "kpbr-ni-v1-" + record.ownership_transaction_id;
    record.snapshot_revision =
        revision("ndms-native-import-v1-", 'd');
    record.target_full_revision =
        revision("ndms-rci-full-v1-", 'e');
    record.keen_pbr_dependency_revision = revision(
        std::string{kNdmsNativeDeleteDependencyRevisionPrefix}, 'f');
    record.preflight_observations = observation_pair(1U, '1', '2');
    record.observation_binding = {std::string(32U, '3'), 1U, 2U};
    record.owner_global_save_acknowledged = true;
    record.external_writer_race_accepted = true;
    record.integrity = ndms_native_delete_wal_integrity(record);
    return record;
}

void refresh(NdmsNativeDeleteWalRecord& record) {
    record.integrity = ndms_native_delete_wal_integrity(record);
}

NdmsNativeDeleteWalRecord cleanup_record() {
    auto record = prepared_delete_record();
    record.phase = NdmsNativeDeleteWalPhase::cleanup;
    record.delete_absence_observations = observation_pair(3U, '4', '5');
    record.post_save_absence_observations =
        observation_pair(5U, '6', '7');
    record.tombstone_revision =
        revision("ndms-native-owner-tombstone-v1-", '8');
    refresh(record);
    return record;
}

std::size_t delete_temporary_count(const fs::path& directory) {
    if (!fs::exists(directory)) return 0U;
    std::size_t count = 0U;
    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.path().filename().string().rfind(
                ".native-panel-delete-wal.tmp.", 0U) == 0U) {
            ++count;
        }
    }
    return count;
}

void write_private(const fs::path& path, const std::string& body) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output.write(body.data(), static_cast<std::streamsize>(body.size()));
    output.close();
    REQUIRE(::chmod(path.c_str(), 0600) == 0);
}

int child_exit_status(const pid_t child) {
    int status = 0;
    pid_t waited = -1;
    do {
        waited = ::waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    REQUIRE(waited == child);
    REQUIRE(WIFEXITED(status));
    return WEXITSTATUS(status);
}

} // namespace

TEST_CASE("prepared native delete WAL round-trips with JSON null optionals") {
    const auto record = prepared_delete_record();
    REQUIRE(valid_ndms_native_delete_wal_record(record));
    const auto serialized = serialize_ndms_native_delete_wal(record);
    const auto document = nlohmann::json::parse(serialized);

    CHECK(document.at("delete_absence_observations").is_null());
    CHECK(document.at("post_save_absence_observations").is_null());
    CHECK(document.at("tombstone_revision").is_null());
    CHECK(document.at("kernel_interface_name").is_null());
    CHECK_FALSE(document.at("delete_absence_observations").is_array());
    CHECK(parse_ndms_native_delete_wal(serialized) == record);

    auto kernel_bound = record;
    kernel_bound.kernel_interface_name = "nwg5";
    refresh(kernel_bound);
    const auto kernel_serialized =
        serialize_ndms_native_delete_wal(kernel_bound);
    const auto kernel_document =
        nlohmann::json::parse(kernel_serialized);
    CHECK(kernel_document.at("kernel_interface_name") == "nwg5");
    CHECK(parse_ndms_native_delete_wal(kernel_serialized) ==
          kernel_bound);
}

TEST_CASE("native delete WAL admits only the exact forward phase chain") {
    std::vector<NdmsNativeDeleteWalRecord> records;
    records.push_back(prepared_delete_record());

    auto deleting = records.back();
    deleting.phase = NdmsNativeDeleteWalPhase::delete_may_be_inflight;
    refresh(deleting);
    records.push_back(deleting);

    auto absent = deleting;
    absent.phase = NdmsNativeDeleteWalPhase::running_absence_verified;
    absent.delete_absence_observations = observation_pair(3U, '4', '5');
    refresh(absent);
    records.push_back(absent);

    auto saving = absent;
    saving.phase = NdmsNativeDeleteWalPhase::save_may_be_inflight;
    refresh(saving);
    records.push_back(saving);

    auto acknowledged = saving;
    acknowledged.phase =
        NdmsNativeDeleteWalPhase::save_acknowledged_unverified;
    acknowledged.post_save_absence_observations =
        observation_pair(5U, '6', '7');
    refresh(acknowledged);
    records.push_back(acknowledged);

    auto cleanup = acknowledged;
    cleanup.phase = NdmsNativeDeleteWalPhase::cleanup;
    cleanup.tombstone_revision =
        revision("ndms-native-owner-tombstone-v1-", '8');
    refresh(cleanup);
    records.push_back(cleanup);

    for (std::size_t index = 0U; index < records.size(); ++index) {
        CAPTURE(ndms_native_delete_wal_phase_name(records[index].phase));
        CHECK(parse_ndms_native_delete_wal(
                  serialize_ndms_native_delete_wal(records[index])) ==
              records[index]);
        if (index + 1U < records.size()) {
            CHECK(valid_ndms_native_delete_wal_transition(
                records[index].phase, records[index + 1U].phase));
        }
    }
    CHECK_FALSE(valid_ndms_native_delete_wal_transition(
        NdmsNativeDeleteWalPhase::prepared,
        NdmsNativeDeleteWalPhase::save_may_be_inflight));
    CHECK_FALSE(valid_ndms_native_delete_wal_transition(
        NdmsNativeDeleteWalPhase::cleanup,
        NdmsNativeDeleteWalPhase::prepared));
}

TEST_CASE("native delete WAL corrupt legacy and rebound evidence fail closed") {
    const auto record = prepared_delete_record();
    const auto serialized = serialize_ndms_native_delete_wal(record);
    auto document = nlohmann::json::parse(serialized);

    document["schema_version"] = 0;
    CHECK_THROWS_AS(
        parse_ndms_native_delete_wal(document.dump()),
        NdmsNativeDeleteWalError);

    document = nlohmann::json::parse(serialized);
    document["schema_version"] = 1;
    CHECK_THROWS_AS(
        parse_ndms_native_delete_wal(document.dump()),
        NdmsNativeDeleteWalError);

    document = nlohmann::json::parse(serialized);
    document["unknown"] = true;
    CHECK_THROWS_AS(
        parse_ndms_native_delete_wal(document.dump()),
        NdmsNativeDeleteWalError);

    document = nlohmann::json::parse(serialized);
    document["owner_global_save_acknowledged"] = false;
    CHECK_THROWS_AS(
        parse_ndms_native_delete_wal(document.dump()),
        NdmsNativeDeleteWalError);

    document = nlohmann::json::parse(serialized);
    document["keen_pbr_dependency_revision"] =
        revision("ndms-native-delete-deps-v1-", '0');
    CHECK_THROWS_AS(
        parse_ndms_native_delete_wal(document.dump()),
        NdmsNativeDeleteWalError);

    document = nlohmann::json::parse(serialized);
    document["kernel_interface_name"] = "nwg5/../foreign";
    CHECK_THROWS_AS(
        parse_ndms_native_delete_wal(document.dump()),
        NdmsNativeDeleteWalError);

    CHECK_THROWS_AS(
        parse_ndms_native_delete_wal(
            R"({"schema_version":0,"phase":"prepared"})"),
        NdmsNativeDeleteWalError);
}

TEST_CASE("native delete WAL store is single-slot durable and repeatable") {
    DeleteWalTempDirectory temporary;
    const auto state = temporary.path / "delete";
    NdmsNativeDeleteWalStore store(state);
    const auto first = prepared_delete_record('a');
    const auto second = prepared_delete_record('9');

    CHECK(store.readiness() == NdmsNativeDeleteWalReadiness::clean);
    REQUIRE(store.publish_prepared_exclusive(first));
    CHECK_FALSE(store.publish_prepared_exclusive(second));
    REQUIRE(store.load().state == NdmsNativeDeleteWalLoadState::valid);
    CHECK(store.load().record == first);
    CHECK(store.readiness() == NdmsNativeDeleteWalReadiness::unfinished);
    CHECK(store.readiness() == NdmsNativeDeleteWalReadiness::unfinished);
    CHECK(delete_temporary_count(state) == 0U);

    struct stat directory_metadata {};
    struct stat record_metadata {};
    REQUIRE(::lstat(state.c_str(), &directory_metadata) == 0);
    REQUIRE(::lstat(
                (state / kNdmsNativeDeleteWalFilename).c_str(),
                &record_metadata) == 0);
    CHECK((directory_metadata.st_mode & 07777) == 0700);
    CHECK((record_metadata.st_mode & 07777) == 0600);
    CHECK(record_metadata.st_nlink == 1);

    auto deleting = first;
    deleting.phase = NdmsNativeDeleteWalPhase::delete_may_be_inflight;
    refresh(deleting);
    CHECK_NOTHROW(store.publish(deleting));
    CHECK(store.load().record == deleting);

    auto rebound_kernel = deleting;
    rebound_kernel.kernel_interface_name = "nwg5";
    refresh(rebound_kernel);
    CHECK_THROWS_AS(
        store.publish(rebound_kernel), NdmsNativeDeleteWalStoreError);
    CHECK(store.load().record == deleting);

    auto skipped = deleting;
    skipped.phase = NdmsNativeDeleteWalPhase::save_may_be_inflight;
    skipped.delete_absence_observations = observation_pair(3U, '4', '5');
    refresh(skipped);
    CHECK_THROWS_AS(store.publish(skipped), NdmsNativeDeleteWalStoreError);
    CHECK(store.load().record == deleting);
}

TEST_CASE("native delete WAL sweep sees every enumeration from its start") {
    DeleteWalTempDirectory temporary;
    const auto state = temporary.path / "delete";
    NdmsNativeDeleteWalStore store(state);
    const auto record = prepared_delete_record();
    REQUIRE(store.publish_prepared_exclusive(record));

    const auto orphan = state / ".native-panel-delete-wal.tmp.999999.1";
    write_private(orphan, serialize_ndms_native_delete_wal(record));
    REQUIRE(delete_temporary_count(state) == 1U);
    CHECK(store.load().state == NdmsNativeDeleteWalLoadState::unsafe_store);

    store.sweep_orphaned_temporaries();
    CHECK(delete_temporary_count(state) == 0U);
    for (unsigned int repeat = 0U; repeat < 2U; ++repeat) {
        const auto loaded = store.load();
        REQUIRE(loaded.state == NdmsNativeDeleteWalLoadState::valid);
        CHECK(loaded.record == record);
        CHECK(store.readiness() == NdmsNativeDeleteWalReadiness::unfinished);
    }
}

TEST_CASE("native delete WAL linked crash state is completed by sweep") {
    DeleteWalTempDirectory temporary;
    const auto state = temporary.path / "delete";
    const auto record = prepared_delete_record();
    const pid_t child = ::fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        NdmsNativeDeleteWalStoreTestHooks hooks;
        hooks.allow_current_process_owner = true;
        hooks.force_portable_linkat = true;
        hooks.fault_injector = [](const auto stage) {
            if (stage == NdmsNativeDeleteWalStoreFaultStage::
                             after_initial_link_before_temporary_unlink) {
                ::_exit(82);
            }
        };
        try {
            NdmsNativeDeleteWalStore interrupted(state, hooks);
            static_cast<void>(
                interrupted.publish_prepared_exclusive(record));
        } catch (...) {
            ::_exit(92);
        }
        ::_exit(93);
    }
    CHECK(child_exit_status(child) == 82);
    REQUIRE(fs::exists(state / kNdmsNativeDeleteWalFilename));
    REQUIRE(delete_temporary_count(state) == 1U);

    NdmsNativeDeleteWalStore recovered(state);
    recovered.sweep_orphaned_temporaries();
    CHECK(delete_temporary_count(state) == 0U);
    const auto loaded = recovered.load();
    REQUIRE(loaded.state == NdmsNativeDeleteWalLoadState::valid);
    CHECK(loaded.record == record);
    CHECK(recovered.readiness() ==
          NdmsNativeDeleteWalReadiness::unfinished);
}

TEST_CASE("native delete WAL cleanup is exact and legacy residue is unsafe") {
    DeleteWalTempDirectory temporary;
    const auto clean_state = temporary.path / "clean";
    NdmsNativeDeleteWalStore store(clean_state);
    auto record = prepared_delete_record();
    REQUIRE(store.publish_prepared_exclusive(record));

    auto deleting = record;
    deleting.phase = NdmsNativeDeleteWalPhase::delete_may_be_inflight;
    refresh(deleting);
    store.publish(deleting);
    auto absent = deleting;
    absent.phase = NdmsNativeDeleteWalPhase::running_absence_verified;
    absent.delete_absence_observations = observation_pair(3U, '4', '5');
    refresh(absent);
    store.publish(absent);
    auto saving = absent;
    saving.phase = NdmsNativeDeleteWalPhase::save_may_be_inflight;
    refresh(saving);
    store.publish(saving);
    auto acknowledged = saving;
    acknowledged.phase =
        NdmsNativeDeleteWalPhase::save_acknowledged_unverified;
    acknowledged.post_save_absence_observations =
        observation_pair(5U, '6', '7');
    refresh(acknowledged);
    store.publish(acknowledged);
    auto cleanup = cleanup_record();
    store.publish(cleanup);

    auto wrong = cleanup;
    wrong.tombstone_revision =
        revision("ndms-native-owner-tombstone-v1-", '9');
    refresh(wrong);
    CHECK_THROWS_AS(store.remove_exact(wrong),
                    NdmsNativeDeleteWalStoreError);
    CHECK(store.readiness() == NdmsNativeDeleteWalReadiness::unfinished);
    CHECK_NOTHROW(store.remove_exact(cleanup));
    CHECK(store.readiness() == NdmsNativeDeleteWalReadiness::clean);

    const auto legacy_state = temporary.path / "legacy";
    fs::create_directories(legacy_state);
    REQUIRE(::chmod(legacy_state.c_str(), 0700) == 0);
    write_private(
        legacy_state / kNdmsNativeDeleteWalFilename,
        R"({"schema_version":0,"phase":"prepared"})");
    NdmsNativeDeleteWalStore legacy(legacy_state);
    CHECK(legacy.load().state ==
          NdmsNativeDeleteWalLoadState::corrupt_record);
    CHECK(legacy.readiness() == NdmsNativeDeleteWalReadiness::unsafe);
}
