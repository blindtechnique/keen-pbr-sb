#include <doctest/doctest.h>

#include "keenetic/ndms_native_import_startup_recovery.hpp"

#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <type_traits>
#include <utility>
#include <vector>
#include <unistd.h>

using namespace keen_pbr3;

namespace {

static_assert(
    std::is_same<
        decltype(std::declval<
                     const NdmsNativeImportStartupRecoverySummary&>()
                     .items()),
        const std::vector<
            NdmsNativeImportStartupRecoveryItemSummary>&>::value,
    "startup recovery items must be exposed read-only");
static_assert(
    !std::is_copy_assignable<
        NdmsNativeImportStartupRecoverySummary>::value,
    "startup recovery summary must not be mutable by assignment");
static_assert(
    !std::is_copy_assignable<
        NdmsNativeImportStartupRecoveryItemSummary>::value,
    "startup recovery item summary must be immutable");

class StartupRecoveryTempDirectory {
public:
    StartupRecoveryTempDirectory() {
        char pattern[] =
            "/tmp/keen-pbr-native-startup-recovery-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~StartupRecoveryTempDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

NdmsNativeImportWalStoreTestHooks startup_test_hooks() {
    NdmsNativeImportWalStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return hooks;
}

std::string startup_digest(const std::string& prefix,
                           const char value) {
    return prefix + std::string(64U, value);
}

NdmsNativeImportPersistedBaseline startup_baseline() {
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
    if (!built.success() || !built.evidence.has_value()) {
        throw std::runtime_error(
            "cannot build startup WAL baseline fixture");
    }
    return persist_ndms_native_import_baseline(*built.evidence);
}

NdmsNativeImportWalRecord startup_prepared_record(
    const char transaction_digit = 'a') {
    NdmsNativeImportWalRecord record;
    record.transaction_id =
        std::string(32U, transaction_digit);
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.candidate_revision =
        startup_digest("ndms-native-import-v1-", 'b');
    record.baseline = startup_baseline();
    record.request_binding_sha256 =
        ndms_native_import_request_binding_digest(
            record.transaction_id,
            record.marker,
            record.candidate_revision,
            record.baseline.expected_created_interface);
    record.generation_ticket =
        startup_digest("ndms-create-ticket-v1-", 'c');
    record.maintenance_base_generation = 41U;
    return record;
}

NdmsNativeImportWalRecord startup_inflight_record(
    const char transaction_digit = 'a') {
    auto record = startup_prepared_record(transaction_digit);
    record.phase =
        NdmsNativeImportWalPhase::import_may_be_inflight;
    record.reserved_generation = 42U;
    return record;
}

NdmsNativeImportStartupRecoveryObservation
startup_absent_observation(const NdmsNativeImportWalRecord& record) {
    NdmsNativeImportStartupRecoveryObservation input;
    input.transaction_id = record.transaction_id;
    input.observation.authoritative = true;
    input.observation.protected_catalog_unchanged = true;
    input.observation.marker_match_count = 0U;
    return input;
}

NdmsNativeImportStartupRecoveryObservation
startup_exact_owned_observation(
    const NdmsNativeImportWalRecord& record) {
    NdmsNativeImportStartupRecoveryObservation input;
    input.transaction_id = record.transaction_id;
    input.observation.authoritative = true;
    input.observation.generation_advanced = true;
    input.observation.protected_catalog_unchanged = true;
    input.observation.marker_match_count = 1U;
    input.observation.marker_target = "Wireguard5";
    input.observation.target_absent_in_baseline = true;
    input.observation.target_down = true;
    input.observation.target_fingerprint_matches = true;
    return input;
}

void make_ready_empty_store_directory(
    const std::filesystem::path& state) {
    REQUIRE(std::filesystem::create_directory(state));
    REQUIRE(::chmod(state.c_str(), 0700) == 0);
}

void write_private_record(
    const std::filesystem::path& state,
    const NdmsNativeImportWalRecord& record) {
    const auto path = state / (record.transaction_id + ".wal");
    std::ofstream output(
        path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    const auto body = serialize_ndms_native_import_wal(record);
    output.write(body.data(), static_cast<std::streamsize>(body.size()));
    REQUIRE(output);
    output.close();
    REQUIRE(::chmod(path.c_str(), 0600) == 0);
}

bool startup_has_blocker(
    const NdmsNativeImportStartupRecoverySummary& summary,
    const NdmsNativeImportStartupRecoveryBlocker blocker) {
    for (const auto& item : summary.blockers()) {
        if (item.blocker() == blocker) return true;
    }
    return false;
}

void require_no_dispatch(
    const NdmsNativeImportStartupRecoverySummary& summary) {
    CHECK_FALSE(summary.side_effects_dispatched());
    CHECK_FALSE(summary.retry_dispatched());
    for (const auto& item : summary.items()) {
        CHECK_FALSE(item.action_dispatched());
    }
}

} // namespace

TEST_CASE("native import startup recovery blocks a non-ready inventory") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "absent";
    NdmsNativeImportWalStore store(state, startup_test_hooks());

    const auto summary =
        scan_ndms_native_import_startup_recovery(store, {});

    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::block_unknown);
    CHECK(summary.inventory_state() ==
          NdmsNativeImportWalInventoryState::absent);
    CHECK(summary.wal_record_count() == 0U);
    CHECK(startup_has_blocker(
        summary,
        NdmsNativeImportStartupRecoveryBlocker::inventory_absent));
    require_no_dispatch(summary);
}

TEST_CASE("native import startup recovery accepts only a ready empty store") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    make_ready_empty_store_directory(state);
    NdmsNativeImportWalStore store(state, startup_test_hooks());

    const auto summary =
        scan_ndms_native_import_startup_recovery(store, {});

    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::clean);
    CHECK(summary.inventory_state() ==
          NdmsNativeImportWalInventoryState::ready);
    CHECK(summary.wal_record_count() == 0U);
    CHECK(summary.supplied_observation_count() == 0U);
    CHECK(summary.items().empty());
    CHECK(summary.blockers().empty());
    require_no_dispatch(summary);
}

TEST_CASE("native import startup recovery reports an exclusive WAL lock immediately") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    make_ready_empty_store_directory(state);
    NdmsNativeImportWalStore store(state, startup_test_hooks());

    int ready_pipe[2]{};
    int release_pipe[2]{};
    REQUIRE(::pipe(ready_pipe) == 0);
    REQUIRE(::pipe(release_pipe) == 0);
    const pid_t child = ::fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        (void)::close(ready_pipe[0]);
        (void)::close(release_pipe[1]);
        const int descriptor = ::open(
            state.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (descriptor < 0 || ::flock(descriptor, LOCK_EX) != 0) {
            _exit(20);
        }
        const char ready = 'R';
        if (::write(ready_pipe[1], &ready, 1U) != 1) _exit(21);
        char release{};
        if (::read(release_pipe[0], &release, 1U) != 1) _exit(22);
        (void)::flock(descriptor, LOCK_UN);
        (void)::close(descriptor);
        _exit(0);
    }

    (void)::close(ready_pipe[1]);
    (void)::close(release_pipe[0]);
    char ready{};
    const ssize_t ready_count = ::read(ready_pipe[0], &ready, 1U);
    (void)::close(ready_pipe[0]);
    REQUIRE(ready_count == 1);
    REQUIRE(ready == 'R');

    const auto started = std::chrono::steady_clock::now();
    const auto summary =
        scan_ndms_native_import_startup_recovery(store, {});
    const auto elapsed = std::chrono::steady_clock::now() - started;

    const char release = 'X';
    CHECK(::write(release_pipe[1], &release, 1U) == 1);
    (void)::close(release_pipe[1]);
    int child_status = 0;
    REQUIRE(::waitpid(child, &child_status, 0) == child);
    REQUIRE(WIFEXITED(child_status));
    REQUIRE(WEXITSTATUS(child_status) == 0);

    CHECK(elapsed < std::chrono::milliseconds(500));
    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::block_unknown);
    CHECK(startup_has_blocker(
        summary,
        NdmsNativeImportStartupRecoveryBlocker::
            inventory_lock_busy));
    require_no_dispatch(summary);

    const auto after_unlock =
        scan_ndms_native_import_startup_recovery(store, {});
    CHECK(after_unlock.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::clean);
}

TEST_CASE("native import startup recovery reports prepared abort without removing WAL") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, startup_test_hooks());
    const auto record = startup_prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);

    const auto summary = scan_ndms_native_import_startup_recovery(
        store, {startup_absent_observation(record)});

    REQUIRE(summary.items().size() == 1U);
    const auto& item = summary.items().front();
    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::
              classified_report_only);
    CHECK(item.transaction_id() == record.transaction_id);
    CHECK(item.phase() == NdmsNativeImportWalPhase::prepared);
    CHECK(item.action() ==
          NdmsNativeImportRecoveryAction::abort_without_mutation);
    CHECK(item.observation_authoritative());
    CHECK(startup_has_blocker(
        summary,
        NdmsNativeImportStartupRecoveryBlocker::
            classified_action_not_dispatched));
    require_no_dispatch(summary);

    const auto unchanged = store.load(record.transaction_id);
    REQUIRE(unchanged.recovery_permitted());
    CHECK(unchanged.record == record);
}

TEST_CASE("native import startup recovery never dispatches exact-owned delete") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, startup_test_hooks());
    const auto prepared = startup_prepared_record();
    const auto record = startup_inflight_record();
    REQUIRE(store.publish_prepared_exclusive(prepared) ==
            NdmsNativeImportWalAdmissionState::admitted);
    store.publish(record);

    const auto summary = scan_ndms_native_import_startup_recovery(
        store, {startup_exact_owned_observation(record)});

    REQUIRE(summary.items().size() == 1U);
    CHECK(summary.items().front().action() ==
          NdmsNativeImportRecoveryAction::
              rollback_delete_exact_owned);
    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::
              classified_report_only);
    require_no_dispatch(summary);

    const auto unchanged = store.load(record.transaction_id);
    REQUIRE(unchanged.recovery_permitted());
    CHECK(unchanged.record == record);
}

TEST_CASE("native import startup recovery never retries read-only observation") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, startup_test_hooks());
    const auto prepared = startup_prepared_record();
    const auto record = startup_inflight_record();
    REQUIRE(store.publish_prepared_exclusive(prepared) ==
            NdmsNativeImportWalAdmissionState::admitted);
    store.publish(record);
    auto observation = startup_absent_observation(record);
    observation.observation.generation_advanced = false;

    const auto summary = scan_ndms_native_import_startup_recovery(
        store, {observation});

    REQUIRE(summary.items().size() == 1U);
    CHECK(summary.items().front().action() ==
          NdmsNativeImportRecoveryAction::
              retry_read_only_observation);
    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::
              classified_report_only);
    require_no_dispatch(summary);

    const auto unchanged = store.load(record.transaction_id);
    REQUIRE(unchanged.recovery_permitted());
    CHECK(unchanged.record == record);
}

TEST_CASE("native import startup recovery blocks non-authoritative evidence") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, startup_test_hooks());
    const auto record = startup_prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);
    auto observation = startup_absent_observation(record);
    observation.observation.authoritative = false;

    const auto summary = scan_ndms_native_import_startup_recovery(
        store, {observation});

    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::block_unknown);
    REQUIRE(summary.items().size() == 1U);
    CHECK(summary.items().front().action() ==
          NdmsNativeImportRecoveryAction::
              retry_read_only_observation);
    CHECK_FALSE(summary.items().front().observation_authoritative());
    CHECK(startup_has_blocker(
        summary,
        NdmsNativeImportStartupRecoveryBlocker::
            observation_not_authoritative));
    require_no_dispatch(summary);
}

TEST_CASE("native import startup recovery does not reconstruct missing evidence") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, startup_test_hooks());
    const auto record = startup_prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);
    auto observation = startup_absent_observation(record);
    observation.observation.protected_catalog_unchanged = false;

    const auto summary = scan_ndms_native_import_startup_recovery(
        store, {observation});

    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::block_unknown);
    REQUIRE(summary.items().size() == 1U);
    CHECK(summary.items().front().action() ==
          NdmsNativeImportRecoveryAction::block_unknown);
    CHECK(startup_has_blocker(
        summary,
        NdmsNativeImportStartupRecoveryBlocker::
            classifier_blocked_unknown));
    require_no_dispatch(summary);
}

TEST_CASE("native import startup recovery fails closed on observation set mismatch") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, startup_test_hooks());
    const auto record = startup_prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);
    const auto exact = startup_absent_observation(record);

    SUBCASE("missing") {
        const auto summary =
            scan_ndms_native_import_startup_recovery(store, {});
        CHECK(summary.disposition() ==
              NdmsNativeImportStartupRecoveryDisposition::block_unknown);
        CHECK(summary.items().empty());
        CHECK(startup_has_blocker(
            summary,
            NdmsNativeImportStartupRecoveryBlocker::
                observation_missing));
        require_no_dispatch(summary);
    }
    SUBCASE("duplicate") {
        const auto summary = scan_ndms_native_import_startup_recovery(
            store, {exact, exact});
        CHECK(summary.items().empty());
        CHECK(startup_has_blocker(
            summary,
            NdmsNativeImportStartupRecoveryBlocker::
                observation_duplicate));
        require_no_dispatch(summary);
    }
    SUBCASE("extra") {
        auto extra = exact;
        extra.transaction_id = std::string(32U, 'b');
        const auto summary = scan_ndms_native_import_startup_recovery(
            store, {exact, extra});
        CHECK(summary.items().empty());
        CHECK(startup_has_blocker(
            summary,
            NdmsNativeImportStartupRecoveryBlocker::
                observation_extra));
        require_no_dispatch(summary);
    }
    SUBCASE("wrong identity is both missing and extra") {
        auto other = exact;
        other.transaction_id = std::string(32U, 'b');
        const auto summary = scan_ndms_native_import_startup_recovery(
            store, {other});
        CHECK(summary.items().empty());
        CHECK(startup_has_blocker(
            summary,
            NdmsNativeImportStartupRecoveryBlocker::
                observation_missing));
        CHECK(startup_has_blocker(
            summary,
            NdmsNativeImportStartupRecoveryBlocker::
                observation_extra));
        require_no_dispatch(summary);
    }
    SUBCASE("malformed identity") {
        auto invalid = exact;
        invalid.transaction_id = "../../not-a-transaction";
        const auto summary = scan_ndms_native_import_startup_recovery(
            store, {invalid});
        CHECK(summary.items().empty());
        REQUIRE(summary.blockers().size() == 1U);
        CHECK(summary.blockers().front().blocker() ==
              NdmsNativeImportStartupRecoveryBlocker::
                  observation_identity_invalid);
        CHECK_FALSE(
            summary.blockers().front().transaction_id().has_value());
        require_no_dispatch(summary);
    }
}

TEST_CASE("native import startup recovery hard-blocks multiple valid records") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, startup_test_hooks());
    const auto first = startup_prepared_record('a');
    const auto second = startup_prepared_record('b');
    REQUIRE(store.publish_prepared_exclusive(first) ==
            NdmsNativeImportWalAdmissionState::admitted);
    write_private_record(state, second);
    REQUIRE(store.inventory().recovery_permitted());

    const auto summary = scan_ndms_native_import_startup_recovery(
        store,
        {startup_absent_observation(first),
         startup_absent_observation(second)});

    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::block_unknown);
    CHECK(summary.wal_record_count() == 2U);
    CHECK(summary.items().empty());
    CHECK(startup_has_blocker(
        summary,
        NdmsNativeImportStartupRecoveryBlocker::
            multiple_unfinished_transactions));
    require_no_dispatch(summary);
}

TEST_CASE("native import startup recovery blocks an unsafe inventory entry") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    make_ready_empty_store_directory(state);
    {
        std::ofstream foreign(state / "foreign.object");
        REQUIRE(foreign);
        foreign << "not a WAL";
    }
    REQUIRE(::chmod((state / "foreign.object").c_str(), 0600) == 0);
    NdmsNativeImportWalStore store(state, startup_test_hooks());

    const auto summary =
        scan_ndms_native_import_startup_recovery(store, {});

    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::block_unknown);
    CHECK(summary.items().empty());
    CHECK(startup_has_blocker(
        summary,
        NdmsNativeImportStartupRecoveryBlocker::
            inventory_entry_invalid));
    require_no_dispatch(summary);
}

TEST_CASE("native import startup recovery caps observation processing") {
    StartupRecoveryTempDirectory temporary;
    const auto state = temporary.path / "state";
    NdmsNativeImportWalStore store(state, startup_test_hooks());
    const auto record = startup_prepared_record();
    REQUIRE(store.publish_prepared_exclusive(record) ==
            NdmsNativeImportWalAdmissionState::admitted);

    std::vector<NdmsNativeImportStartupRecoveryObservation> observations;
    observations.reserve(
        kNdmsNativeImportStartupRecoveryMaximumObservations + 1U);
    for (std::size_t index = 0U;
         index <
             kNdmsNativeImportStartupRecoveryMaximumObservations + 1U;
         ++index) {
        char transaction_id[33]{};
        REQUIRE(std::snprintf(
                    transaction_id,
                    sizeof(transaction_id),
                    "%032zx",
                    index) == 32);
        auto observation = startup_absent_observation(record);
        observation.transaction_id = transaction_id;
        observations.push_back(std::move(observation));
    }

    const auto summary = scan_ndms_native_import_startup_recovery(
        store, observations);

    CHECK(summary.disposition() ==
          NdmsNativeImportStartupRecoveryDisposition::block_unknown);
    CHECK(summary.items().empty());
    CHECK(startup_has_blocker(
        summary,
        NdmsNativeImportStartupRecoveryBlocker::
            observation_limit_exceeded));
    require_no_dispatch(summary);
}

TEST_CASE("native import startup recovery names remain non-secret enums") {
    CHECK(std::string(
              ndms_native_import_startup_recovery_disposition_name(
                  NdmsNativeImportStartupRecoveryDisposition::
                      classified_report_only)) ==
          "classified_report_only");
    CHECK(std::string(
              ndms_native_import_startup_recovery_blocker_name(
                  NdmsNativeImportStartupRecoveryBlocker::
                      multiple_unfinished_transactions)) ==
          "multiple_unfinished_transactions");
}
