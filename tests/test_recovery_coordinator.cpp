#include <doctest/doctest.h>

#include "../src/backup/recovery_coordinator.hpp"
#include "../src/backup/restore_journal.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

constexpr const char* kConfigTransaction =
    "10000000000000000000000000000001";
constexpr const char* kBackupTransaction =
    "20000000000000000000000000000002";

class RecoveryTempDir {
public:
    RecoveryTempDir() {
        char pattern[] =
            "/tmp/keen-pbr-recovery-coordinator-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~RecoveryTempDir() {
        std::error_code error;
        fs::remove_all(path, error);
    }

    fs::path path;
};

std::string valid_config_json(
    const std::string& cache_suffix = "original") {
    nlohmann::json config{
        {"daemon",
         {
             {"cache_dir",
              "/tmp/keen-pbr-recovery-" + cache_suffix},
             {"firewall_backend", "auto"},
         }},
        {"api",
         {
             {"enabled", true},
             {"listen", "127.0.0.1:12121"},
         }},
        {"outbounds",
         nlohmann::json::array({
             {
                 {"type", "table"},
                 {"tag", "wan"},
                 {"table", 254},
             },
         })},
        {"dns",
         {
             {"system_resolver",
              {
                  {"address", "127.0.0.1"},
              }},
             {"servers",
              nlohmann::json::array({
                  {
                      {"tag", "default_dns"},
                      {"address", "127.0.0.1"},
                  },
              })},
             {"fallback",
              nlohmann::json::array({"default_dns"})},
         }},
        {"route", {{"rules", nlohmann::json::array()}}},
    };
    return config.dump(2) + "\n";
}

void write_binary(
    const fs::path& path,
    const std::string& content) {
    fs::create_directories(path.parent_path());
    std::ofstream output(
        path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output.write(
        content.data(),
        static_cast<std::streamsize>(content.size()));
    REQUIRE(output);
}

std::string read_binary(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>(),
    };
}

struct FileMetadata {
    mode_t mode;
    uid_t owner;
    gid_t group;
};

FileMetadata metadata_of(const fs::path& path) {
    struct stat metadata {};
    REQUIRE(::lstat(path.c_str(), &metadata) == 0);
    return {
        static_cast<mode_t>(metadata.st_mode & 0777),
        metadata.st_uid,
        metadata.st_gid,
    };
}

backup::RecoveryCoordinatorLayout test_layout(
    const fs::path& root) {
    backup::RecoveryCoordinatorLayout layout;
    layout.state_root = root / "recovery";
    layout.persistent.config =
        root / "etc" / "keen-pbr" / "config.json";
    layout.persistent.transports =
        root / "etc" / "keen-pbr" /
        "transports.json";
    layout.persistent.nfqws =
        root / "etc" / "nfqws2";
    layout.persistent.strategies =
        root / "etc" / "keen-pbr" /
        "nfqws-strategies";
    return layout;
}

fs::path operation_path(
    const backup::RecoveryCoordinatorLayout& layout,
    backup::RecoveryOperation operation) {
    return layout.state_root /
           backup::recovery_operation_name(operation);
}

std::string snapshot_payload(
    const nlohmann::json& snapshot) {
    return snapshot.dump(1, '\t') + "\n";
}

nlohmann::json exact_operation_snapshot(
    const backup::RecoveryCoordinatorLayout& layout,
    const std::vector<fs::path>& managed_paths = {}) {
    std::vector<
        std::pair<std::string, backup::FileSnapshot>>
        snapshots;
    snapshots.push_back({
        "config",
        backup::capture_file(
            layout.persistent.config,
            std::nullopt,
            backup::kMaxSnapshotBytes),
    });
    snapshots.push_back({
        "transports",
        backup::capture_file(
            layout.persistent.transports,
            std::nullopt,
            backup::kMaxSnapshotBytes),
    });
    for (const auto& path : managed_paths) {
        const auto under_nfqws =
            path.lexically_normal()
                .lexically_relative(
                    layout.persistent.nfqws
                        .lexically_normal());
        const bool is_nfqws =
            !under_nfqws.empty() &&
            !under_nfqws.is_absolute() &&
            *under_nfqws.begin() != "..";
        const auto root =
            is_nfqws
                ? layout.persistent.nfqws
                : layout.persistent.strategies;
        snapshots.push_back({
            backup::logical_target_for_path(
                layout.persistent, path),
            backup::capture_file(
                path,
                root,
                backup::kMaxManagedFileBytes),
        });
    }
    return backup::make_persistent_snapshot(
        std::move(snapshots));
}

RestoreJournalEntry begin_operation(
    const backup::RecoveryCoordinatorLayout& layout,
    backup::RecoveryOperation operation,
    const std::string& transaction,
    const std::string& payload) {
    RestoreJournal journal(
        operation_path(layout, operation));
    return journal.begin(
        transaction,
        payload,
        {RestoreJournalEffect::files});
}

backup::RecoveryCoordinatorError expect_recovery_error(
    backup::RecoveryCoordinator& coordinator) {
    try {
        (void)coordinator.recover();
        FAIL("recovery unexpectedly succeeded");
    } catch (const backup::RecoveryCoordinatorError& error) {
        return error;
    }
    throw std::runtime_error(
        "unreachable recovery error assertion");
}

} // namespace

TEST_CASE(
    "offline recovery ignores working config when no operation is active") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    write_binary(
        layout.persistent.config,
        "{ this is deliberately not working config JSON");

    backup::RecoveryCoordinator coordinator(layout);
    const auto result = coordinator.recover();

    CHECK(
        result.outcome ==
        backup::RecoveryOutcome::no_active_operation);
    CHECK_FALSE(result.operation.has_value());
    CHECK_FALSE(result.transaction_id.has_value());
    CHECK_FALSE(coordinator.global_unknown_present());
}

TEST_CASE(
    "offline recovery scans only the two fixed operation journals") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    write_binary(
        layout.persistent.config,
        valid_config_json());
    const auto payload = snapshot_payload(
        exact_operation_snapshot(layout));
    RestoreJournal unrelated(
        layout.state_root / "unrelated-operation");
    const auto unrelated_active = unrelated.begin(
        kConfigTransaction,
        payload,
        {RestoreJournalEffect::files});

    backup::RecoveryCoordinator coordinator(layout);
    const auto result = coordinator.recover();

    CHECK(
        result.outcome ==
        backup::RecoveryOutcome::no_active_operation);
    CHECK(unrelated.read_active() == unrelated_active);
    CHECK_FALSE(coordinator.global_unknown_present());
}

TEST_CASE(
    "offline recovery restores exact bytes tombstones and metadata") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    const auto list =
        layout.persistent.nfqws / "lists" / "user.list";
    const auto later =
        layout.persistent.nfqws / "lists" / "later.list";
    const auto config = valid_config_json();

    write_binary(layout.persistent.config, config);
    write_binary(
        layout.persistent.transports,
        "{\"version\":1}\n");
    write_binary(list, "example.org\n");
    REQUIRE(::chmod(layout.persistent.config.c_str(), 0640) == 0);
    REQUIRE(::chmod(list.c_str(), 0600) == 0);
    const auto config_metadata =
        metadata_of(layout.persistent.config);
    const auto list_metadata = metadata_of(list);

    const auto payload = snapshot_payload(
        exact_operation_snapshot(
            layout, {list, later}));
    begin_operation(
        layout,
        backup::RecoveryOperation::config_save,
        kConfigTransaction,
        payload);

    // Recovery must not attempt to parse this interrupted working file.
    write_binary(
        layout.persistent.config,
        "{ interrupted write");
    REQUIRE(::chmod(layout.persistent.config.c_str(), 0666) == 0);
    write_binary(
        layout.persistent.transports,
        "{\"version\":2}\n");
    write_binary(list, "changed.example\n");
    REQUIRE(::chmod(list.c_str(), 0644) == 0);
    write_binary(later, "must.be.removed\n");

    backup::RecoveryCoordinator coordinator(layout);
    const auto result = coordinator.recover();

    CHECK(
        result.outcome ==
        backup::RecoveryOutcome::rollback_completed);
    REQUIRE(result.operation.has_value());
    CHECK(
        *result.operation ==
        backup::RecoveryOperation::config_save);
    REQUIRE(result.transaction_id.has_value());
    CHECK(*result.transaction_id == kConfigTransaction);
    CHECK(read_binary(layout.persistent.config) == config);
    CHECK(
        read_binary(layout.persistent.transports) ==
        "{\"version\":1}\n");
    CHECK(read_binary(list) == "example.org\n");
    CHECK_FALSE(fs::exists(later));

    const auto restored_config =
        metadata_of(layout.persistent.config);
    CHECK(restored_config.mode == config_metadata.mode);
    CHECK(restored_config.owner == config_metadata.owner);
    CHECK(restored_config.group == config_metadata.group);
    const auto restored_list = metadata_of(list);
    CHECK(restored_list.mode == list_metadata.mode);
    CHECK(restored_list.owner == list_metadata.owner);
    CHECK(restored_list.group == list_metadata.group);

    RestoreJournal journal(operation_path(
        layout,
        backup::RecoveryOperation::config_save));
    CHECK_FALSE(journal.read_active().has_value());
    CHECK_FALSE(coordinator.global_unknown_present());
}

TEST_CASE(
    "offline recovery is idempotent after interruption before completion") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    write_binary(
        layout.persistent.config,
        valid_config_json());
    write_binary(
        layout.persistent.transports,
        "{\"state\":\"before\"}\n");
    const auto payload = snapshot_payload(
        exact_operation_snapshot(layout));
    const auto active = begin_operation(
        layout,
        backup::RecoveryOperation::backup_restore,
        kBackupTransaction,
        payload);
    write_binary(
        layout.persistent.transports,
        "{\"state\":\"after\"}\n");

    backup::RecoveryCoordinatorTestHooks hooks;
    hooks.after_files_verified =
        [](backup::RecoveryOperation) {
            throw std::runtime_error(
                "simulated power loss before journal completion");
        };
    backup::RecoveryCoordinator interrupted(
        layout, std::move(hooks));
    const auto error =
        expect_recovery_error(interrupted);
    CHECK(
        error.kind() ==
        backup::RecoveryErrorKind::retryable_io);
    CHECK(
        read_binary(layout.persistent.transports) ==
        "{\"state\":\"before\"}\n");
    CHECK_FALSE(interrupted.global_unknown_present());

    RestoreJournal journal(operation_path(
        layout,
        backup::RecoveryOperation::backup_restore));
    CHECK(journal.read_active() == active);

    backup::RecoveryCoordinator retry(layout);
    const auto result = retry.recover();
    CHECK(
        result.outcome ==
        backup::RecoveryOutcome::rollback_completed);
    CHECK_FALSE(journal.read_active().has_value());
    CHECK(
        read_binary(layout.persistent.transports) ==
        "{\"state\":\"before\"}\n");
}

TEST_CASE(
    "offline recovery retries a partially applied file transaction") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    write_binary(
        layout.persistent.config,
        valid_config_json());
    write_binary(
        layout.persistent.transports,
        "{\"state\":\"before\"}\n");
    const auto payload = snapshot_payload(
        exact_operation_snapshot(layout));
    begin_operation(
        layout,
        backup::RecoveryOperation::config_save,
        kConfigTransaction,
        payload);
    write_binary(
        layout.persistent.config,
        valid_config_json("interrupted"));
    write_binary(
        layout.persistent.transports,
        "{\"state\":\"after\"}\n");

    backup::RecoveryCoordinatorTestHooks hooks;
    hooks.file_apply.before_forward_write =
        [](std::size_t index, const fs::path&) {
            if (index == 1U) {
                throw std::runtime_error(
                    "simulated interruption");
            }
        };
    backup::RecoveryCoordinator interrupted(
        layout, std::move(hooks));
    const auto error =
        expect_recovery_error(interrupted);
    CHECK(
        error.kind() ==
        backup::RecoveryErrorKind::retryable_io);
    CHECK_FALSE(interrupted.global_unknown_present());

    backup::RecoveryCoordinator retry(layout);
    const auto result = retry.recover();
    CHECK(
        result.outcome ==
        backup::RecoveryOutcome::rollback_completed);
    CHECK(
        read_binary(layout.persistent.transports) ==
        "{\"state\":\"before\"}\n");
    CHECK(
        read_binary(layout.persistent.config) ==
        valid_config_json());
}

TEST_CASE(
    "two active operations create only global UNKNOWN") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    write_binary(
        layout.persistent.config,
        valid_config_json());
    const auto payload = snapshot_payload(
        exact_operation_snapshot(layout));
    const auto config_active = begin_operation(
        layout,
        backup::RecoveryOperation::config_save,
        kConfigTransaction,
        payload);
    const auto backup_active = begin_operation(
        layout,
        backup::RecoveryOperation::backup_restore,
        kBackupTransaction,
        payload);

    backup::RecoveryCoordinator coordinator(layout);
    const auto error =
        expect_recovery_error(coordinator);
    CHECK(
        error.kind() ==
        backup::RecoveryErrorKind::
            multiple_active_operations);
    CHECK(fs::exists(layout.state_root / "UNKNOWN"));

    RestoreJournal config_journal(operation_path(
        layout,
        backup::RecoveryOperation::config_save));
    RestoreJournal backup_journal(operation_path(
        layout,
        backup::RecoveryOperation::backup_restore));
    CHECK(config_journal.read_active() == config_active);
    CHECK(backup_journal.read_active() == backup_active);
    CHECK_FALSE(config_journal.unknown_present());
    CHECK_FALSE(backup_journal.unknown_present());
}

TEST_CASE(
    "corrupt operation payload blocks all automatic recovery") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    write_binary(
        layout.persistent.config,
        valid_config_json());
    const auto active = begin_operation(
        layout,
        backup::RecoveryOperation::backup_restore,
        kBackupTransaction,
        "not a persistent snapshot");

    backup::RecoveryCoordinator coordinator(layout);
    const auto error =
        expect_recovery_error(coordinator);
    CHECK(
        error.kind() ==
        backup::RecoveryErrorKind::corrupt_snapshot);
    CHECK(fs::exists(layout.state_root / "UNKNOWN"));

    RestoreJournal journal(operation_path(
        layout,
        backup::RecoveryOperation::backup_restore));
    CHECK(journal.read_active() == active);
    CHECK_FALSE(journal.unknown_present());
}

TEST_CASE(
    "scoped backup payload is rejected as a recovery operation") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    write_binary(
        layout.persistent.config,
        valid_config_json());
    const auto payload = snapshot_payload(
        backup::make_full_snapshot(layout.persistent));
    begin_operation(
        layout,
        backup::RecoveryOperation::backup_restore,
        kBackupTransaction,
        payload);

    backup::RecoveryCoordinator coordinator(layout);
    const auto error =
        expect_recovery_error(coordinator);
    CHECK(
        error.kind() ==
        backup::RecoveryErrorKind::corrupt_snapshot);
    CHECK(fs::exists(layout.state_root / "UNKNOWN"));

    RestoreJournal journal(operation_path(
        layout,
        backup::RecoveryOperation::backup_restore));
    CHECK(journal.read_active().has_value());
    CHECK_FALSE(journal.unknown_present());
}

TEST_CASE(
    "corrupt journal creates local and global UNKNOWN markers") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    write_binary(
        layout.persistent.config,
        valid_config_json());
    const auto payload = snapshot_payload(
        exact_operation_snapshot(layout));
    begin_operation(
        layout,
        backup::RecoveryOperation::config_save,
        kConfigTransaction,
        payload);
    write_binary(
        operation_path(
            layout,
            backup::RecoveryOperation::config_save) /
            (std::string(kConfigTransaction) + ".rollback"),
        "corrupt");

    backup::RecoveryCoordinator coordinator(layout);
    const auto error =
        expect_recovery_error(coordinator);
    CHECK(
        error.kind() ==
        backup::RecoveryErrorKind::corrupt_journal);
    CHECK(fs::exists(layout.state_root / "UNKNOWN"));
    CHECK(fs::exists(
        operation_path(
            layout,
            backup::RecoveryOperation::config_save) /
        "UNKNOWN"));
}

TEST_CASE(
    "global UNKNOWN blocks recovery without touching active payload") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    write_binary(
        layout.persistent.config,
        valid_config_json());
    const auto payload = snapshot_payload(
        exact_operation_snapshot(layout));
    const auto active = begin_operation(
        layout,
        backup::RecoveryOperation::config_save,
        kConfigTransaction,
        payload);
    RestoreJournal global(layout.state_root);
    global.mark_unknown();

    backup::RecoveryCoordinator coordinator(layout);
    const auto error =
        expect_recovery_error(coordinator);
    CHECK(
        error.kind() ==
        backup::RecoveryErrorKind::global_unknown);

    RestoreJournal journal(operation_path(
        layout,
        backup::RecoveryOperation::config_save));
    CHECK(journal.read_active() == active);
    CHECK(
        journal.read_rollback_payload(active) ==
        payload);
}

TEST_CASE(
    "a file appearing during recovery fails exact verification closed") {
    RecoveryTempDir temporary;
    const auto layout = test_layout(temporary.path);
    write_binary(
        layout.persistent.config,
        valid_config_json());
    const auto raced =
        layout.persistent.nfqws / "lists" / "raced.list";
    const auto payload = snapshot_payload(
        exact_operation_snapshot(layout, {raced}));
    begin_operation(
        layout,
        backup::RecoveryOperation::backup_restore,
        kBackupTransaction,
        payload);

    backup::RecoveryCoordinatorTestHooks hooks;
    hooks.after_files_applied =
        [&](backup::RecoveryOperation) {
            write_binary(raced, "appeared during recovery\n");
        };
    backup::RecoveryCoordinator coordinator(
        layout, std::move(hooks));
    const auto error =
        expect_recovery_error(coordinator);
    CHECK(
        error.kind() ==
        backup::RecoveryErrorKind::verification_failed);
    CHECK(fs::exists(layout.state_root / "UNKNOWN"));
    CHECK(fs::exists(raced));
}

} // namespace keen_pbr3
