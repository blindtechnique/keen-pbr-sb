#include <doctest/doctest.h>

#include "../src/backup/persistent_snapshot.hpp"
#include "../src/backup/restore_journal.hpp"
#include "../src/cmd/recover_persistent_state.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

class RecoveryCommandTempDir {
public:
    RecoveryCommandTempDir() {
        char pattern[] =
            "/tmp/keen-pbr-recovery-command-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~RecoveryCommandTempDir() {
        std::error_code error;
        fs::remove_all(path, error);
    }

    fs::path path;
};

void write_file(const fs::path& path,
                const std::string& body) {
    fs::create_directories(path.parent_path());
    std::ofstream output(
        path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output.write(
        body.data(),
        static_cast<std::streamsize>(body.size()));
    REQUIRE(output);
}

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>(),
    };
}

backup::RecoveryCoordinatorLayout command_layout(
    const fs::path& root) {
    backup::RecoveryCoordinatorLayout layout;
    layout.state_root = root / "state";
    layout.persistent.config =
        root / "etc" / "keen-pbr" / "config.json";
    layout.persistent.transports =
        root / "etc" / "keen-pbr" / "transports.json";
    layout.persistent.nfqws =
        root / "etc" / "nfqws2";
    layout.persistent.strategies =
        root / "etc" / "keen-pbr" / "nfqws-strategies";
    return layout;
}

std::string valid_command_config(
    const std::string& listen) {
    return nlohmann::json{
        {"api", {{"enabled", true}, {"listen", listen}}},
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
         }},
        {"route", {{"rules", nlohmann::json::array()}}},
    }.dump(2) + "\n";
}

struct LeaseCounters {
    int factories{0};
    int reserves{0};
    int verifies{0};
    std::uint32_t expected_generation{9};
};

class FakeRecoveryLease final : public MaintenanceLease {
public:
    explicit FakeRecoveryLease(LeaseCounters& counters)
        : counters_(counters) {}

    std::uint32_t base_generation() const noexcept override {
        return counters_.expected_generation;
    }

    std::uint32_t reserve(
        std::uint32_t expected_generation) override {
        CHECK(expected_generation ==
              counters_.expected_generation);
        ++counters_.reserves;
        return expected_generation + 1U;
    }

    void verify_held() override {
        ++counters_.verifies;
    }

private:
    LeaseCounters& counters_;
};

RecoverPersistentStateOptions command_options(
    backup::RecoveryCoordinatorLayout layout,
    LeaseCounters& counters) {
    RecoverPersistentStateOptions options;
    options.layout = std::move(layout);
    options.lease_factory =
        [&counters](const std::string& operation) {
            CHECK(operation == "persistent-recovery");
            ++counters.factories;
            return std::make_unique<FakeRecoveryLease>(
                counters);
        };
    options.runtime_active_probe =
        [](backup::RecoveryOperation) { return false; };
    return options;
}

nlohmann::json parse_result(
    const std::ostringstream& output) {
    return nlohmann::json::parse(output.str());
}

void create_private_directory(const fs::path& path) {
    fs::create_directories(path);
    REQUIRE(::chmod(path.c_str(), 0700) == 0);
}

TEST_CASE("persistent recovery clean preflight does not create state or reserve generation") {
    RecoveryCommandTempDir directory;
    const auto layout = command_layout(directory.path);
    LeaseCounters counters;
    auto options = command_options(layout, counters);
    std::ostringstream output;

    const int exit_code =
        run_recover_persistent_state(options, output);

    INFO(output.str());
    CHECK(exit_code ==
          static_cast<int>(
              RecoverPersistentStateExitCode::success));
    CHECK(counters.factories == 0);
    CHECK(counters.reserves == 0);
    CHECK(counters.verifies == 0);
    CHECK_FALSE(fs::exists(layout.state_root));
    const auto result = parse_result(output);
    CHECK(result.at("ok") == true);
    CHECK(result.at("outcome") ==
          "no_active_operation");
    CHECK(result.at("generation_reserved") == false);
}

TEST_CASE("persistent recovery clean no-op does not require runtime or lease callbacks") {
    RecoveryCommandTempDir directory;
    RecoverPersistentStateOptions options;
    options.layout = command_layout(directory.path);
    std::ostringstream output;

    CHECK(run_recover_persistent_state(options, output) ==
          static_cast<int>(
              RecoverPersistentStateExitCode::success));
    CHECK_FALSE(fs::exists(options.layout.state_root));
    CHECK(parse_result(output).at("outcome") ==
          "no_active_operation");
}

TEST_CASE("persistent recovery reserves one generation and restores active operation") {
    RecoveryCommandTempDir directory;
    const auto layout = command_layout(directory.path);
    const auto before =
        valid_command_config("127.0.0.1:12121");
    const auto after =
        valid_command_config("127.0.0.1:12122");
    write_file(
        layout.persistent.config, before);
    REQUIRE(::chmod(
                layout.persistent.config.c_str(),
                0600) == 0);

    auto snapshot = backup::make_persistent_snapshot({
        {
            "config",
            backup::capture_file(
                layout.persistent.config,
                std::nullopt,
                backup::kMaxSnapshotBytes),
        },
    });
    const std::string payload =
        snapshot.dump(1, '\t') + "\n";
    RestoreJournal journal(
        layout.state_root / "config-save");
    (void)journal.begin(
        "1234567890abcdef1234567890abcdef",
        payload,
        {RestoreJournalEffect::files});
    write_file(
        layout.persistent.config, after);

    LeaseCounters counters;
    auto options = command_options(layout, counters);
    std::ostringstream output;
    const int exit_code =
        run_recover_persistent_state(options, output);

    INFO(output.str());
    CHECK(exit_code ==
          static_cast<int>(
              RecoverPersistentStateExitCode::success));
    CHECK(counters.factories == 1);
    CHECK(counters.reserves == 1);
    CHECK(counters.verifies == 1);
    CHECK(read_file(layout.persistent.config) == before);
    CHECK_FALSE(journal.read_active().has_value());
    const auto result = parse_result(output);
    CHECK(result.at("outcome") ==
          "rollback_completed");
    CHECK(result.at("operation") == "config-save");
    CHECK(result.at("generation_reserved") == true);
    CHECK(result.at("transaction_id") ==
          "1234567890abcdef1234567890abcdef");
}

TEST_CASE("persistent recovery refuses to restore while affected runtime is active") {
    RecoveryCommandTempDir directory;
    const auto layout = command_layout(directory.path);
    write_file(layout.persistent.config, "before\n");
    const auto snapshot = backup::make_persistent_snapshot({
        {
            "config",
            backup::capture_file(
                layout.persistent.config,
                std::nullopt,
                backup::kMaxSnapshotBytes),
        },
    });
    RestoreJournal journal(layout.state_root / "config-save");
    (void)journal.begin(
        "abcdef1234567890abcdef1234567890",
        snapshot.dump(),
        {RestoreJournalEffect::files});
    write_file(layout.persistent.config, "after\n");

    LeaseCounters counters;
    auto options = command_options(layout, counters);
    options.runtime_active_probe =
        [](backup::RecoveryOperation operation) {
            CHECK(operation ==
                  backup::RecoveryOperation::config_save);
            return true;
        };
    std::ostringstream output;

    CHECK(run_recover_persistent_state(options, output) ==
          static_cast<int>(
              RecoverPersistentStateExitCode::blocked));
    CHECK(counters.factories == 0);
    CHECK(counters.reserves == 0);
    CHECK(read_file(layout.persistent.config) == "after\n");
    CHECK(journal.read_active().has_value());
    CHECK(parse_result(output).at("error").at("code") ==
          "runtime_still_active");
}

TEST_CASE("config-save recovery uses the full managed runtime boundary") {
    const std::vector<std::string> expected{
        "keen-pbr",
        "transport-manager",
        "nfqws2",
        "nfqws",
        "sing-box",
    };

    CHECK(
        recovery_managed_process_names_for_testing(
            backup::RecoveryOperation::config_save) ==
        expected);
    CHECK(
        recovery_managed_process_names_for_testing(
            backup::RecoveryOperation::backup_restore) ==
        expected);
}

TEST_CASE("persistent recovery rejects local UNKNOWN without acquiring maintenance") {
    RecoveryCommandTempDir directory;
    const auto layout = command_layout(directory.path);
    RestoreJournal journal(
        layout.state_root / "backup-restore");
    journal.mark_unknown();

    LeaseCounters counters;
    auto options = command_options(layout, counters);
    std::ostringstream output;
    const int exit_code =
        run_recover_persistent_state(options, output);

    CHECK(exit_code ==
          static_cast<int>(
              RecoverPersistentStateExitCode::blocked));
    CHECK(counters.factories == 0);
    CHECK(counters.reserves == 0);
    const auto result = parse_result(output);
    CHECK(result.at("error").at("class") ==
          "blocked");
    CHECK(result.at("error").at("code") ==
          "unknown_state");
}

TEST_CASE("persistent recovery rejects global UNKNOWN without acquiring maintenance") {
    RecoveryCommandTempDir directory;
    const auto layout = command_layout(directory.path);
    RestoreJournal global(layout.state_root);
    global.mark_unknown();

    LeaseCounters counters;
    auto options = command_options(layout, counters);
    std::ostringstream output;
    const int exit_code =
        run_recover_persistent_state(options, output);

    CHECK(exit_code ==
          static_cast<int>(
              RecoverPersistentStateExitCode::blocked));
    CHECK(counters.factories == 0);
    CHECK(counters.reserves == 0);
    const auto result = parse_result(output);
    CHECK(result.at("error").at("class") ==
          "blocked");
    CHECK(result.at("error").at("code") ==
          "unknown_state");
}

TEST_CASE("persistent recovery rejects two active journals before acquiring maintenance") {
    RecoveryCommandTempDir directory;
    const auto layout = command_layout(directory.path);
    create_private_directory(layout.state_root);
    for (const auto operation :
         {backup::RecoveryOperation::config_save,
          backup::RecoveryOperation::backup_restore}) {
        const auto operation_directory =
            layout.state_root /
            backup::recovery_operation_name(operation);
        create_private_directory(operation_directory);
        write_file(
            operation_directory / "active.json",
            "{}\n");
    }

    LeaseCounters counters;
    auto options = command_options(layout, counters);
    std::ostringstream output;
    const int exit_code =
        run_recover_persistent_state(options, output);

    CHECK(exit_code ==
          static_cast<int>(
              RecoverPersistentStateExitCode::blocked));
    CHECK(counters.factories == 0);
    CHECK(counters.reserves == 0);
    const auto result = parse_result(output);
    CHECK(result.at("error").at("code") ==
          "multiple_active_operations");
}

TEST_CASE("persistent recovery reports maintenance contention as retryable") {
    RecoveryCommandTempDir directory;
    const auto layout = command_layout(directory.path);
    create_private_directory(layout.state_root);
    const auto operation_directory =
        layout.state_root / "config-save";
    create_private_directory(operation_directory);
    write_file(
        operation_directory / "active.json", "{}\n");

    RecoverPersistentStateOptions options;
    options.layout = layout;
    options.runtime_active_probe =
        [](backup::RecoveryOperation) { return false; };
    options.lease_factory =
        [](const std::string&) ->
            std::unique_ptr<MaintenanceLease> {
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::busy,
                "maintenance is already active");
        };
    std::ostringstream output;
    const int exit_code =
        run_recover_persistent_state(options, output);

    CHECK(exit_code ==
          static_cast<int>(
              RecoverPersistentStateExitCode::retryable));
    const auto result = parse_result(output);
    CHECK(result.at("error").at("class") ==
          "retryable");
    CHECK(result.at("error").at("code") ==
          "maintenance_busy");
}

TEST_CASE("persistent recovery rejects unsafe marker types as corrupt") {
    RecoveryCommandTempDir directory;
    const auto layout = command_layout(directory.path);
    create_private_directory(layout.state_root);
    const auto operation_directory =
        layout.state_root / "config-save";
    create_private_directory(operation_directory);
    create_private_directory(
        operation_directory / "active.json");

    LeaseCounters counters;
    auto options = command_options(layout, counters);
    std::ostringstream output;
    const int exit_code =
        run_recover_persistent_state(options, output);

    CHECK(exit_code ==
          static_cast<int>(
              RecoverPersistentStateExitCode::blocked));
    CHECK(counters.factories == 0);
    CHECK(counters.reserves == 0);
    const auto result = parse_result(output);
    CHECK(result.at("error").at("code") ==
          "corrupt_journal");
}

} // namespace
} // namespace keen_pbr3
