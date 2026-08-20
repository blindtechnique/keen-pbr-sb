#include <doctest/doctest.h>

#include "keenetic/ndms_native_import_wal_store.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <system_error>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace keen_pbr3;

namespace {

class WalStoreTempDirectory {
public:
    WalStoreTempDirectory() {
        char pattern[] = "/tmp/keen-pbr-native-wal-store-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~WalStoreTempDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

NdmsNativeImportWalStoreTestHooks unprivileged_test_hooks() {
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return hooks;
}

std::string store_digest(const std::string& prefix, char value) {
    return prefix + std::string(64U, value);
}

NdmsNativeImportPersistedBaseline store_baseline(
    const std::uint32_t maintenance = 41U,
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
        snapshot, "Wireguard5", maintenance, 17U);
    if (!built.success() || !built.evidence.has_value()) {
        throw std::runtime_error("cannot build WAL store baseline fixture");
    }
    return persist_ndms_native_import_baseline(*built.evidence);
}

NdmsNativeImportWalRecord store_prepared_record(char transaction_digit = 'a') {
    NdmsNativeImportWalRecord record;
    record.transaction_id = std::string(32U, transaction_digit);
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.candidate_revision =
        store_digest("ndms-native-import-v1-", 'b');
    record.snapshot_revision = record.candidate_revision;
    record.observation_binding = {std::string(32U, 'd'), 9U, 7U};
    record.baseline = store_baseline();
    record.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            record.transaction_id,
            record.marker,
            record.candidate_revision,
            record.kind,
            record.baseline.expected_created_interface);
    record.generation_ticket =
        store_digest("ndms-create-ticket-v1-", 'c');
    record.maintenance_base_generation = 41U;
    return record;
}

NdmsNativeImportWalRecord indexed_store_record(std::size_t index) {
    char transaction_id[33]{};
    const int count = std::snprintf(
        transaction_id,
        sizeof(transaction_id),
        "%032zx",
        index);
    REQUIRE(count == 32);
    auto record = store_prepared_record();
    record.transaction_id = transaction_id;
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            record.transaction_id,
            record.marker,
            record.candidate_revision,
            record.kind,
            record.baseline.expected_created_interface);
    return record;
}

NdmsNativeImportWalRecord store_inflight_record(char digit = 'a') {
    auto record = store_prepared_record(digit);
    record.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    record.reserved_generation = 42U;
    return record;
}

NdmsNativeImportWalRecord store_response_record(char digit = 'a') {
    auto record = store_inflight_record(digit);
    record.phase = NdmsNativeImportWalPhase::response_recorded;
    record.response_manifest_sha256 =
        store_digest("ndms-import-response-manifest-v3-", 'd');
    record.created_interface = "Wireguard5";
    return record;
}

NdmsNativeImportWalRecord store_record_for_phase(
    const NdmsNativeImportWalPhase phase,
    const char digit = 'e') {
    auto record = store_inflight_record(digit);
    record.phase = phase;
    if (phase == NdmsNativeImportWalPhase::response_recorded ||
        phase == NdmsNativeImportWalPhase::target_verified ||
        phase == NdmsNativeImportWalPhase::ownership_published) {
        record.response_manifest_sha256 =
            store_digest("ndms-import-response-manifest-v3-", 'd');
        record.created_interface = "Wireguard5";
    }
    if (phase == NdmsNativeImportWalPhase::target_verified ||
        phase == NdmsNativeImportWalPhase::ownership_published) {
        record.target_full_revision =
            store_digest("ndms-rci-full-v1-", 'e');
    }
    if (phase == NdmsNativeImportWalPhase::ownership_published) {
        record.ownership_revision =
            store_digest("ndms-native-owner-v2-", 'f');
    }
    return record;
}

std::filesystem::path record_path(
    const std::filesystem::path& state,
    const std::string& transaction_id) {
    return state / (transaction_id + ".wal");
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>(),
    };
}

void write_private_file(const std::filesystem::path& path,
                        const std::string& body) {
    std::ofstream output(
        path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output.write(body.data(), static_cast<std::streamsize>(body.size()));
    REQUIRE(output);
    output.close();
    REQUIRE(::chmod(path.c_str(), 0600) == 0);
}

mode_t permissions(const std::filesystem::path& path) {
    struct stat metadata {};
    REQUIRE(::lstat(path.c_str(), &metadata) == 0);
    return metadata.st_mode & 07777;
}

void admit_prepared(
    NdmsNativeImportWalStore& store,
    const NdmsNativeImportWalRecord& record) {
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);
}

} // namespace

TEST_CASE("native import WAL store publishes private non-secret records") {
    WalStoreTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
    const auto absent_inventory = store.inventory();
    CHECK(absent_inventory.state ==
          NdmsNativeImportWalInventoryState::absent);
    CHECK_FALSE(absent_inventory.recovery_permitted());

    const auto second = store_prepared_record('b');
    const auto first = store_prepared_record('a');
    admit_prepared(store, first);
    write_private_file(
        record_path(state, second.transaction_id),
        serialize_ndms_native_import_wal(second));

    CHECK(permissions(state) == 0700);
    CHECK(permissions(record_path(state, first.transaction_id)) == 0600);
    struct stat metadata {};
    REQUIRE(
        ::lstat(record_path(state, first.transaction_id).c_str(),
                &metadata) == 0);
    CHECK(S_ISREG(metadata.st_mode));
    CHECK(metadata.st_nlink == 1);
    CHECK(metadata.st_uid == ::geteuid());
    CHECK(metadata.st_gid == ::getegid());

    const auto loaded = store.load(first.transaction_id);
    REQUIRE(loaded.recovery_permitted());
    CHECK(loaded.record == first);

    const auto inventory = store.inventory();
    REQUIRE(inventory.state == NdmsNativeImportWalInventoryState::ready);
    REQUIRE(inventory.recovery_permitted());
    REQUIRE(inventory.items.size() == 2U);
    CHECK(inventory.items[0].filename == first.transaction_id + ".wal");
    CHECK(inventory.items[1].filename == second.transaction_id + ".wal");

    const auto disk = read_file(record_path(state, first.transaction_id));
    CHECK(disk == serialize_ndms_native_import_wal(first));
    CHECK(disk.find("PrivateKey") == std::string::npos);
    CHECK(disk.find("PresharedKey") == std::string::npos);
    CHECK(disk.find("private-key-material") == std::string::npos);
    CHECK(disk.size() <= kNdmsNativeImportWalMaximumBytes);
}

TEST_CASE("native import WAL store admits only one fresh transaction") {
    WalStoreTempDirectory temporary;
    NdmsNativeImportWalStore store(
        temporary.path / "state", unprivileged_test_hooks());
    const auto first = store_prepared_record('a');
    const auto second = store_prepared_record('b');

    CHECK_THROWS_AS(
        store.publish(first), NdmsNativeImportWalStoreError);
    CHECK(store.inventory().state ==
          NdmsNativeImportWalInventoryState::ready);
    CHECK(store.inventory().items.empty());
    CHECK(store.publish_prepared_exclusive(first) ==
          NdmsNativeImportWalAdmissionState::admitted);
    CHECK(store.publish_prepared_exclusive(first) ==
          NdmsNativeImportWalAdmissionState::
              unfinished_transaction_present);
    CHECK(store.publish_prepared_exclusive(second) ==
          NdmsNativeImportWalAdmissionState::
              unfinished_transaction_present);
    REQUIRE(store.inventory().items.size() == 1U);
    CHECK(store.load(first.transaction_id).record == first);

    store.remove_exact(first);
    CHECK(store.publish_prepared_exclusive(second) ==
          NdmsNativeImportWalAdmissionState::admitted);
    CHECK(store.load(second.transaction_id).record == second);
}

TEST_CASE("native import WAL try-inventory never waits for an exclusive writer") {
    WalStoreTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
    const auto record = store_prepared_record();
    admit_prepared(store, record);

    const int descriptor = ::open(
        state.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(descriptor >= 0);
    REQUIRE(::flock(descriptor, LOCK_EX) == 0);

    const auto started = std::chrono::steady_clock::now();
    const auto busy = store.try_inventory();
    const auto elapsed = std::chrono::steady_clock::now() - started;

    CHECK(::flock(descriptor, LOCK_UN) == 0);
    CHECK(::close(descriptor) == 0);
    CHECK(elapsed < std::chrono::milliseconds(500));
    CHECK(busy.state == NdmsNativeImportWalInventoryState::busy);
    CHECK(busy.items.empty());
    CHECK_FALSE(busy.recovery_permitted());
    CHECK(std::string(ndms_native_import_wal_inventory_state_name(
              busy.state)) == "busy");

    const auto after_unlock = store.try_inventory();
    REQUIRE(after_unlock.recovery_permitted());
    REQUIRE(after_unlock.items.size() == 1U);
    CHECK(after_unlock.items.front().record == record);
}

TEST_CASE("native import WAL try-inventory never waits for the process mutex") {
    WalStoreTempDirectory temporary;
    const auto state = temporary.path / "state";
    std::mutex hook_mutex;
    std::condition_variable hook_condition;
    std::atomic<bool> armed{false};
    bool writer_entered = false;
    bool release_writer = false;

    auto hooks = unprivileged_test_hooks();
    hooks.fault_injector =
        [&](const NdmsNativeImportWalStoreFaultStage stage) {
            if (stage != NdmsNativeImportWalStoreFaultStage::write ||
                !armed.exchange(false)) {
                return;
            }
            std::unique_lock<std::mutex> lock(hook_mutex);
            writer_entered = true;
            hook_condition.notify_all();
            hook_condition.wait(
                lock, [&release_writer] { return release_writer; });
        };
    NdmsNativeImportWalStore store(state, std::move(hooks));
    const auto prepared = store_prepared_record();
    const auto inflight = store_inflight_record();
    admit_prepared(store, prepared);

    std::exception_ptr writer_error;
    armed.store(true);
    std::thread writer([&] {
        try {
            store.publish(inflight);
        } catch (...) {
            writer_error = std::current_exception();
        }
    });

    bool observed_writer = false;
    {
        std::unique_lock<std::mutex> lock(hook_mutex);
        observed_writer = hook_condition.wait_for(
            lock,
            std::chrono::seconds(5),
            [&writer_entered] { return writer_entered; });
    }

    NdmsNativeImportWalInventory busy;
    std::chrono::steady_clock::duration elapsed{};
    if (observed_writer) {
        const auto started = std::chrono::steady_clock::now();
        busy = store.try_inventory();
        elapsed = std::chrono::steady_clock::now() - started;
    }

    {
        std::lock_guard<std::mutex> lock(hook_mutex);
        release_writer = true;
    }
    hook_condition.notify_all();
    writer.join();

    REQUIRE(observed_writer);
    REQUIRE(writer_error == nullptr);
    CHECK(elapsed < std::chrono::milliseconds(500));
    CHECK(busy.state == NdmsNativeImportWalInventoryState::busy);
    CHECK(busy.items.empty());
    CHECK_FALSE(busy.recovery_permitted());

    const auto after_writer = store.try_inventory();
    REQUIRE(after_writer.recovery_permitted());
    REQUIRE(after_writer.items.size() == 1U);
    CHECK(after_writer.items.front().record == inflight);
}

TEST_CASE("native import WAL admission is exclusive across processes") {
    WalStoreTempDirectory temporary;
    const auto state = temporary.path / "state";
    int start_pipe[2]{-1, -1};
    REQUIRE(::pipe(start_pipe) == 0);

    std::vector<pid_t> children;
    for (const char digit : {'a', 'b'}) {
        const pid_t child = ::fork();
        REQUIRE(child >= 0);
        if (child == 0) {
            (void)::close(start_pipe[1]);
            char token = 0;
            if (::read(start_pipe[0], &token, 1U) != 1) _exit(30);
            try {
                NdmsNativeImportWalStore child_store(
                    state, unprivileged_test_hooks());
                const auto admitted =
                    child_store.publish_prepared_exclusive(
                        store_prepared_record(digit));
                _exit(admitted ==
                              NdmsNativeImportWalAdmissionState::admitted
                          ? 0
                          : 10);
            } catch (...) {
                _exit(20);
            }
        }
        children.push_back(child);
    }

    REQUIRE(::close(start_pipe[0]) == 0);
    const char tokens[2]{'x', 'y'};
    REQUIRE(::write(start_pipe[1], tokens, sizeof(tokens)) ==
            static_cast<ssize_t>(sizeof(tokens)));
    REQUIRE(::close(start_pipe[1]) == 0);

    std::vector<int> exit_codes;
    for (const auto child : children) {
        int status = 0;
        REQUIRE(::waitpid(child, &status, 0) == child);
        REQUIRE(WIFEXITED(status));
        exit_codes.push_back(WEXITSTATUS(status));
    }
    std::sort(exit_codes.begin(), exit_codes.end());
    CHECK(exit_codes == std::vector<int>{0, 10});

    NdmsNativeImportWalStore inspect(state, unprivileged_test_hooks());
    const auto inventory = inspect.inventory();
    REQUIRE(inventory.recovery_permitted());
    CHECK(inventory.items.size() == 1U);
}

TEST_CASE("new native import WAL files must begin at prepared") {
    WalStoreTempDirectory temporary;
    NdmsNativeImportWalStore store(
        temporary.path / "state", unprivileged_test_hooks());

    const std::vector<NdmsNativeImportWalPhase> forbidden{
        NdmsNativeImportWalPhase::import_may_be_inflight,
        NdmsNativeImportWalPhase::response_recorded,
        NdmsNativeImportWalPhase::target_verified,
        NdmsNativeImportWalPhase::ownership_published,
        NdmsNativeImportWalPhase::rollback_requested,
        NdmsNativeImportWalPhase::delete_may_be_inflight,
        NdmsNativeImportWalPhase::absence_verified,
    };
    for (const auto phase : forbidden) {
        auto record = store_record_for_phase(phase);
        CAPTURE(ndms_native_import_wal_phase_name(phase));
        CHECK_NOTHROW(serialize_ndms_native_import_wal(record));
        CHECK_THROWS_AS(
            store.publish(record), NdmsNativeImportWalStoreError);
        CHECK(store.load(record.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
    }
}

TEST_CASE("native import WAL store advances only exact monotonic evidence") {
    WalStoreTempDirectory temporary;
    NdmsNativeImportWalStore store(
        temporary.path / "state", unprivileged_test_hooks());
    const auto prepared = store_prepared_record();
    admit_prepared(store, prepared);
    CHECK_NOTHROW(store.publish(prepared));

    auto same_phase_rewrite = prepared;
    same_phase_rewrite.candidate_revision =
        store_digest("ndms-native-import-v1-", 'e');
    same_phase_rewrite.snapshot_revision =
        same_phase_rewrite.candidate_revision;
    same_phase_rewrite.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            same_phase_rewrite.transaction_id,
            same_phase_rewrite.marker,
            same_phase_rewrite.candidate_revision,
            same_phase_rewrite.kind,
            same_phase_rewrite.baseline.expected_created_interface);
    CHECK_THROWS_AS(
        store.publish(same_phase_rewrite),
        NdmsNativeImportWalStoreError);

    const auto response = store_response_record();
    CHECK_THROWS_AS(
        store.publish(response),
        NdmsNativeImportWalStoreError);

    const auto inflight = store_inflight_record();
    auto changed_baseline = inflight;
    changed_baseline.baseline = store_baseline(41U, 8U);
    REQUIRE(changed_baseline.baseline.baseline_sha256 !=
            inflight.baseline.baseline_sha256);
    CHECK_THROWS_AS(
        store.publish(changed_baseline),
        NdmsNativeImportWalStoreError);
    auto changed_observation = inflight;
    ++changed_observation.observation_binding.mutation_epoch;
    CHECK_NOTHROW(serialize_ndms_native_import_wal(changed_observation));
    CHECK_THROWS_AS(
        store.publish(changed_observation),
        NdmsNativeImportWalStoreError);
    CHECK_NOTHROW(store.publish(inflight));
    CHECK_NOTHROW(store.publish(response));

    auto rewritten_response = response;
    rewritten_response.response_manifest_sha256 =
        store_digest("ndms-import-response-manifest-v3-", 'e');
    CHECK_THROWS_AS(
        store.publish(rewritten_response),
        NdmsNativeImportWalStoreError);
    CHECK(store.load(prepared.transaction_id).record == response);
}

TEST_CASE("prepared native import WAL v3 survives the published crash boundary") {
    WalStoreTempDirectory temporary;
    const auto state = temporary.path / "state";
    auto hooks = unprivileged_test_hooks();
    hooks.fault_injector = [](
                               const NdmsNativeImportWalStoreFaultStage stage) {
        if (stage ==
            NdmsNativeImportWalStoreFaultStage::directory_fsync) {
            throw std::runtime_error(
                "synthetic crash after prepared rename");
        }
    };
    const auto expected = store_prepared_record();
    NdmsNativeImportWalStore faulted(state, std::move(hooks));
    try {
        static_cast<void>(
            faulted.publish_prepared_exclusive(expected));
        FAIL("prepared publication should expose crash boundary");
    } catch (const NdmsNativeImportWalStoreWriteError& error) {
        CHECK(error.published());
    }

    NdmsNativeImportWalStore recovered(
        state, unprivileged_test_hooks());
    const auto loaded = recovered.load(expected.transaction_id);
    REQUIRE(loaded.recovery_permitted());
    REQUIRE(loaded.record.has_value());
    CHECK(*loaded.record == expected);
    CHECK(valid_ndms_native_import_persisted_baseline(
        loaded.record->baseline));
    CHECK(loaded.record->request_binding_sha256 ==
          expected.request_binding_sha256);
}

TEST_CASE("native import WAL load classifies corruption without records") {
    SUBCASE("legacy schema v1 is never authoritative") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
        const auto record = store_prepared_record();
        admit_prepared(store, record);
        auto body = read_file(record_path(state, record.transaction_id));
        const auto version = body.find("\"schema_version\": 3");
        REQUIRE(version != std::string::npos);
        body[version + std::string{"\"schema_version\": "}.size()] = '1';
        write_private_file(record_path(state, record.transaction_id), body);

        const auto loaded = store.load(record.transaction_id);
        CHECK(loaded.state ==
              NdmsNativeImportWalLoadState::corrupt_record);
        CHECK_FALSE(loaded.record.has_value());
        CHECK_FALSE(store.inventory().recovery_permitted());
    }

    SUBCASE("integrity or schema corruption") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
        const auto record = store_prepared_record();
        admit_prepared(store, record);
        auto body = read_file(record_path(state, record.transaction_id));
        const auto offset = body.find(std::string(64U, 'c'));
        REQUIRE(offset != std::string::npos);
        body[offset] = 'd';
        write_private_file(record_path(state, record.transaction_id), body);

        const auto loaded = store.load(record.transaction_id);
        CHECK(loaded.state ==
              NdmsNativeImportWalLoadState::corrupt_record);
        CHECK_FALSE(loaded.record.has_value());
        CHECK_FALSE(store.inventory().recovery_permitted());
    }

    SUBCASE("hard-linked record") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
        const auto record = store_prepared_record();
        admit_prepared(store, record);
        REQUIRE(::link(
                    record_path(state, record.transaction_id).c_str(),
                    (temporary.path / "second-link").c_str()) == 0);

        const auto loaded = store.load(record.transaction_id);
        CHECK(loaded.state == NdmsNativeImportWalLoadState::unsafe_entry);
        CHECK_FALSE(loaded.record.has_value());
    }

    SUBCASE("symbolic-link record") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
        const auto record = store_prepared_record();
        admit_prepared(store, record);
        REQUIRE(std::filesystem::remove(
            record_path(state, record.transaction_id)));
        REQUIRE(::symlink(
                    "/dev/null",
                    record_path(state, record.transaction_id).c_str()) == 0);

        CHECK(store.load(record.transaction_id).state ==
              NdmsNativeImportWalLoadState::unsafe_entry);
    }

    SUBCASE("oversized regular record") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
        const auto record = store_prepared_record();
        admit_prepared(store, record);
        const auto path = record_path(state, record.transaction_id);
        REQUIRE(::truncate(
                    path.c_str(),
                    static_cast<off_t>(
                        kNdmsNativeImportWalMaximumBytes + 1U)) == 0);

        const auto loaded = store.load(record.transaction_id);
        CHECK(loaded.state == NdmsNativeImportWalLoadState::too_large);
        CHECK_FALSE(loaded.record.has_value());
    }

    SUBCASE("record identity differs from filename") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
        const auto first = store_prepared_record('a');
        const auto second = store_prepared_record('b');
        admit_prepared(store, first);
        write_private_file(
            record_path(state, second.transaction_id),
            serialize_ndms_native_import_wal(first));

        const auto loaded = store.load(second.transaction_id);
        CHECK(loaded.state ==
              NdmsNativeImportWalLoadState::identity_mismatch);
        CHECK_FALSE(loaded.record.has_value());
    }
}

TEST_CASE("native import WAL store rejects unsafe state directories") {
    SUBCASE("state directory permissions are not owner-only") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        REQUIRE(std::filesystem::create_directory(state));
        REQUIRE(::chmod(state.c_str(), 0755) == 0);
        NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
        CHECK(store.inventory().state ==
              NdmsNativeImportWalInventoryState::unsafe_store);
        CHECK(store.load(std::string(32U, 'a')).state ==
              NdmsNativeImportWalLoadState::unsafe_store);
    }

    SUBCASE("state directory is a symbolic link") {
        WalStoreTempDirectory temporary;
        const auto real = temporary.path / "real";
        const auto link = temporary.path / "state";
        REQUIRE(std::filesystem::create_directory(real));
        REQUIRE(::chmod(real.c_str(), 0700) == 0);
        REQUIRE(::symlink(real.c_str(), link.c_str()) == 0);
        NdmsNativeImportWalStore store(link, unprivileged_test_hooks());
        CHECK(store.inventory().state ==
              NdmsNativeImportWalInventoryState::unsafe_store);
    }
}

TEST_CASE("native import WAL recovery inventory is sorted and fail closed") {
    WalStoreTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
    const auto first = store_prepared_record('a');
    const auto second = store_prepared_record('b');
    admit_prepared(store, first);
    write_private_file(
        record_path(state, second.transaction_id),
        serialize_ndms_native_import_wal(second));
    write_private_file(state / "FOREIGN", "not a WAL\n");

    const auto inventory = store.inventory();
    REQUIRE(inventory.state == NdmsNativeImportWalInventoryState::ready);
    CHECK_FALSE(inventory.recovery_permitted());
    REQUIRE(inventory.items.size() == 3U);
    std::vector<std::string> names;
    for (const auto& item : inventory.items) names.push_back(item.filename);
    auto sorted = names;
    std::sort(sorted.begin(), sorted.end());
    CHECK(names == sorted);
    CHECK(inventory.items.front().filename == "FOREIGN");
    CHECK(inventory.items.front().state ==
          NdmsNativeImportWalLoadState::unsafe_entry);
    CHECK_FALSE(inventory.items.front().record.has_value());
    CHECK_THROWS_AS(
        store.publish(store_prepared_record('c')),
        NdmsNativeImportWalStoreError);
}

TEST_CASE("a dead process's temporary cannot brick the store") {
    // The scenario: a process died between create_temporary and renameat - a
    // power cut during the fsync on the USB /opt is enough. Its temporary is a
    // real directory entry; the inventory reads any unrecognized name as an
    // unsafe entry; and before the sweep existed, recovery_permitted() was
    // false forever - recovery refused, publish refused, remove refused, with
    // a manual rm on the router as the only remedy.
    WalStoreTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
    admit_prepared(store, store_prepared_record('a'));

    // Written the way create_temporary writes it, owned by a pid that is not
    // alive. Init never dies, so no pid is reliably dead; instead use a value
    // above the default kernel pid ceiling, which kill(2) reports ESRCH for.
    const auto orphan =
        state / ".keen-pbr-native-import-wal.4194200.7";
    write_private_file(orphan, "torn half-written record");
    REQUIRE(std::filesystem::exists(orphan));

    auto poisoned = store.inventory();
    REQUIRE(poisoned.state == NdmsNativeImportWalInventoryState::ready);
    CHECK_FALSE(poisoned.recovery_permitted());

    // The read-only path: startup sweeps, then the same inventory call is
    // whole again - no write ever had to succeed to get here.
    store.sweep_orphaned_temporaries();
    CHECK_FALSE(std::filesystem::exists(orphan));
    auto swept = store.inventory();
    REQUIRE(swept.state == NdmsNativeImportWalInventoryState::ready);
    CHECK(swept.recovery_permitted());

    // The write path heals itself too: with a fresh orphan in place, publish
    // sweeps before judging the inventory instead of throwing on it.
    write_private_file(orphan, "torn again");
    auto record = store_prepared_record('a');
    record.phase = NdmsNativeImportWalPhase::import_may_be_inflight;
    record.reserved_generation = 42U;
    store.publish(record);
    CHECK_FALSE(std::filesystem::exists(orphan));
}

TEST_CASE("the sweep removes only dead-owner temporaries of the exact shape") {
    WalStoreTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
    admit_prepared(store, store_prepared_record('a'));

    // Our own live process: possibly mid-publish, never touched.
    const auto live = state / (".keen-pbr-native-import-wal." +
                               std::to_string(::getpid()) + ".3");
    // A foreign name: not ours to judge, stays for the operator.
    const auto foreign = state / "FOREIGN";
    // Our prefix but no parsable pid: unknown provenance, stays.
    const auto unparsable =
        state / ".keen-pbr-native-import-wal.notapid.1";
    // A dead owner but the wrong shape: 0644 is not what the writer creates.
    const auto wrong_shape =
        state / ".keen-pbr-native-import-wal.4194201.1";
    for (const auto& path : {live, foreign, unparsable, wrong_shape}) {
        write_private_file(path, "x");
    }
    REQUIRE(::chmod(wrong_shape.c_str(), 0644) == 0);

    store.sweep_orphaned_temporaries();

    CHECK(std::filesystem::exists(live));
    CHECK(std::filesystem::exists(foreign));
    CHECK(std::filesystem::exists(unparsable));
    CHECK(std::filesystem::exists(wrong_shape));

    // And the record the store actually owns is untouched throughout.
    CHECK(store.load(std::string(32U, 'a')).state ==
          NdmsNativeImportWalLoadState::valid);
}

TEST_CASE("native import WAL inventory stays bounded") {
    SUBCASE("directory entry limit returns no partial inventory") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        REQUIRE(std::filesystem::create_directory(state));
        REQUIRE(::chmod(state.c_str(), 0700) == 0);
        for (std::size_t index = 0U;
             index <= kNdmsNativeImportWalStoreMaximumDirectoryEntries;
             ++index) {
            char filename[32]{};
            const int count = std::snprintf(
                filename, sizeof(filename), "foreign-%03zu", index);
            REQUIRE(count > 0);
            write_private_file(state / filename, "x");
        }
        NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
        const auto inventory = store.inventory();
        CHECK(inventory.state ==
              NdmsNativeImportWalInventoryState::directory_limit_exceeded);
        CHECK(inventory.items.empty());
        CHECK_FALSE(inventory.recovery_permitted());
    }

    SUBCASE("record limit blocks inventory and new publication") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        REQUIRE(std::filesystem::create_directory(state));
        REQUIRE(::chmod(state.c_str(), 0700) == 0);
        for (std::size_t index = 0U;
             index <= kNdmsNativeImportWalStoreMaximumRecords;
             ++index) {
            const auto record = indexed_store_record(index);
            write_private_file(
                record_path(state, record.transaction_id),
                serialize_ndms_native_import_wal(record));
        }
        NdmsNativeImportWalStore store(state, unprivileged_test_hooks());
        auto inventory = store.inventory();
        CHECK(inventory.state ==
              NdmsNativeImportWalInventoryState::record_limit_exceeded);
        CHECK(inventory.items.empty());
        CHECK_FALSE(inventory.recovery_permitted());

        const auto excess = indexed_store_record(
            kNdmsNativeImportWalStoreMaximumRecords);
        REQUIRE(std::filesystem::remove(
            record_path(state, excess.transaction_id)));
        inventory = store.inventory();
        REQUIRE(inventory.state ==
                NdmsNativeImportWalInventoryState::ready);
        REQUIRE(inventory.items.size() ==
                kNdmsNativeImportWalStoreMaximumRecords);
        REQUIRE(inventory.recovery_permitted());
        CHECK_THROWS_AS(
            store.publish(excess),
            NdmsNativeImportWalStoreError);
    }
}

TEST_CASE("native import WAL publication faults report the rename boundary") {
    const std::vector<NdmsNativeImportWalStoreFaultStage> stages{
        NdmsNativeImportWalStoreFaultStage::write,
        NdmsNativeImportWalStoreFaultStage::file_fsync,
        NdmsNativeImportWalStoreFaultStage::rename,
        NdmsNativeImportWalStoreFaultStage::directory_fsync,
    };
    for (const auto stage : stages) {
        CAPTURE(static_cast<int>(stage));
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        auto hooks = unprivileged_test_hooks();
        hooks.fault_injector = [stage](
                                   NdmsNativeImportWalStoreFaultStage current) {
            if (current == stage) {
                throw std::runtime_error("injected WAL store fault");
            }
        };
        NdmsNativeImportWalStore faulted(state, hooks);
        const auto record = store_prepared_record();
        bool threw = false;
        bool published = false;
        try {
            static_cast<void>(
                faulted.publish_prepared_exclusive(record));
        } catch (const NdmsNativeImportWalStoreWriteError& error) {
            threw = true;
            published = error.published();
        }
        CHECK(threw);
        const bool after_rename =
            stage == NdmsNativeImportWalStoreFaultStage::directory_fsync;
        CHECK(published == after_rename);

        NdmsNativeImportWalStore inspect(
            state, unprivileged_test_hooks());
        const auto loaded = inspect.load(record.transaction_id);
        CHECK(loaded.recovery_permitted() == after_rename);
        const auto inventory = inspect.inventory();
        REQUIRE(inventory.state ==
                NdmsNativeImportWalInventoryState::ready);
        CHECK(inventory.recovery_permitted());
        CHECK(inventory.items.size() == (after_rename ? 1U : 0U));
    }
}

TEST_CASE("native import WAL exact removal is durable and fault classified") {
    SUBCASE("pre-unlink fault keeps the exact record") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        const auto record = store_prepared_record();
        NdmsNativeImportWalStore clean(state, unprivileged_test_hooks());
        admit_prepared(clean, record);

        auto hooks = unprivileged_test_hooks();
        hooks.fault_injector = [](
                                   NdmsNativeImportWalStoreFaultStage stage) {
            if (stage == NdmsNativeImportWalStoreFaultStage::remove) {
                throw std::runtime_error("injected pre-unlink fault");
            }
        };
        NdmsNativeImportWalStore faulted(state, hooks);
        try {
            faulted.remove_exact(record);
            FAIL("remove_exact should fail");
        } catch (const NdmsNativeImportWalStoreWriteError& error) {
            CHECK_FALSE(error.published());
        }
        CHECK(clean.load(record.transaction_id).record == record);
    }

    SUBCASE("post-unlink fsync fault exposes absence and retry repairs it") {
        WalStoreTempDirectory temporary;
        const auto state = temporary.path / "state";
        const auto record = store_prepared_record();
        NdmsNativeImportWalStore clean(state, unprivileged_test_hooks());
        admit_prepared(clean, record);

        auto hooks = unprivileged_test_hooks();
        hooks.fault_injector = [](
                                   NdmsNativeImportWalStoreFaultStage stage) {
            if (stage ==
                NdmsNativeImportWalStoreFaultStage::
                    remove_directory_fsync) {
                throw std::runtime_error("injected post-unlink fault");
            }
        };
        NdmsNativeImportWalStore faulted(state, hooks);
        try {
            faulted.remove_exact(record);
            FAIL("remove_exact should fail");
        } catch (const NdmsNativeImportWalStoreWriteError& error) {
            CHECK(error.published());
        }
        CHECK(clean.load(record.transaction_id).state ==
              NdmsNativeImportWalLoadState::absent);
        CHECK_NOTHROW(clean.remove_exact(record));
        CHECK(clean.inventory().recovery_permitted());
    }
}
