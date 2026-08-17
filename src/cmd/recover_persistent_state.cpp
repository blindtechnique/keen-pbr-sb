#include "recover_persistent_state.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

#ifndef KEEN_PBR_DEFAULT_CONFIG_PATH
#define KEEN_PBR_DEFAULT_CONFIG_PATH "/etc/keen-pbr/config.json"
#endif

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

constexpr const char* kRecoveryOperation =
    "persistent-recovery";

struct ProbeResult {
    std::optional<backup::RecoveryOperation> operation;
};

class CommandFailure final : public std::runtime_error {
public:
    CommandFailure(RecoverPersistentStateExitCode exit_code,
                   std::string code,
                   std::string message)
        : std::runtime_error(std::move(message)),
          exit_code_(exit_code),
          code_(std::move(code)) {}

    RecoverPersistentStateExitCode exit_code() const noexcept {
        return exit_code_;
    }

    const std::string& code() const noexcept { return code_; }

private:
    RecoverPersistentStateExitCode exit_code_;
    std::string code_;
};

enum class EntryKind {
    missing,
    directory,
    regular_file,
    unsafe,
};

struct EntryInfo {
    EntryKind kind{EntryKind::missing};
    mode_t mode{0};
    uid_t owner{0};
};

[[noreturn]] void throw_probe_io(const fs::path& path,
                                 int error) {
    throw CommandFailure(
        RecoverPersistentStateExitCode::retryable,
        "journal_probe_io",
        "Cannot inspect persistent recovery state '" +
            path.string() + "': " + std::strerror(error));
}

EntryInfo inspect_entry(const fs::path& path) {
    struct stat metadata {};
    if (::lstat(path.c_str(), &metadata) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return {};
        }
        throw_probe_io(path, errno);
    }

    EntryKind kind = EntryKind::unsafe;
    if (S_ISDIR(metadata.st_mode)) {
        kind = EntryKind::directory;
    } else if (S_ISREG(metadata.st_mode)) {
        kind = EntryKind::regular_file;
    }
    return {
        kind,
        static_cast<mode_t>(metadata.st_mode & 07777),
        metadata.st_uid,
    };
}

void validate_private_directory(const fs::path& path,
                                const EntryInfo& entry) {
    if (entry.kind != EntryKind::directory ||
        entry.owner != ::geteuid() || entry.mode != 0700) {
        throw CommandFailure(
            RecoverPersistentStateExitCode::blocked,
            "unsafe_journal",
            "Persistent recovery journal is not a private owned directory: " +
                path.string());
    }
}

bool marker_present(const fs::path& path,
                    const std::string& marker_code) {
    const auto entry = inspect_entry(path);
    if (entry.kind == EntryKind::missing) return false;
    if (entry.kind != EntryKind::regular_file) {
        throw CommandFailure(
            RecoverPersistentStateExitCode::blocked,
            "corrupt_journal",
            "Persistent recovery marker is not a regular file: " +
                path.string());
    }
    if (marker_code == "unknown") {
        throw CommandFailure(
            RecoverPersistentStateExitCode::blocked,
            "unknown_state",
            "Persistent recovery is blocked by an UNKNOWN marker");
    }
    return true;
}

ProbeResult probe_recovery_state(
    const backup::RecoveryCoordinatorLayout& layout) {
    const auto root_entry = inspect_entry(layout.state_root);
    if (root_entry.kind == EntryKind::missing) {
        return {};
    }
    validate_private_directory(layout.state_root, root_entry);

    (void)marker_present(layout.state_root / "UNKNOWN", "unknown");

    unsigned int active_count = 0;
    std::optional<backup::RecoveryOperation> active_operation;
    for (const auto operation :
         {backup::RecoveryOperation::config_save,
          backup::RecoveryOperation::backup_restore}) {
        const auto operation_directory =
            layout.state_root /
            backup::recovery_operation_name(operation);
        const auto operation_entry =
            inspect_entry(operation_directory);
        if (operation_entry.kind == EntryKind::missing) continue;
        validate_private_directory(
            operation_directory, operation_entry);

        (void)marker_present(
            operation_directory / "UNKNOWN", "unknown");
        if (marker_present(
                operation_directory / "active.json", "active")) {
            ++active_count;
            active_operation = operation;
        }
    }

    if (active_count > 1U) {
        throw CommandFailure(
            RecoverPersistentStateExitCode::blocked,
            "multiple_active_operations",
            "Both config-save and backup-restore journals are active");
    }
    return {active_operation};
}

const std::vector<std::string>&
managed_process_names(
    backup::RecoveryOperation operation) {
    (void)operation;
    // A config-save transaction can own both config.json and
    // transports.json.  The preflight deliberately does not partially parse
    // active.json before the RecoveryCoordinator verifies the journal, so use
    // one conservative offline boundary for both operations.  This prevents a
    // live transport-manager from rewriting transports.json while recovery is
    // restoring the exact snapshot.
    static const std::vector<std::string> names{
        "keen-pbr",
        "transport-manager",
        "nfqws2",
        "nfqws",
        "sing-box",
    };
    return names;
}

bool production_runtime_active(
    backup::RecoveryOperation operation) {
    const auto& managed_names =
        managed_process_names(operation);
    const auto self = ::getpid();
    std::error_code error;
    fs::directory_iterator iterator(
        "/proc",
        fs::directory_options::skip_permission_denied,
        error);
    if (error) {
        throw CommandFailure(
            RecoverPersistentStateExitCode::retryable,
            "runtime_probe_io",
            "Cannot inspect /proc before persistent recovery: " +
                error.message());
    }

    for (const auto& entry : iterator) {
        const auto name = entry.path().filename().string();
        if (name.empty() ||
            name.find_first_not_of("0123456789") !=
                std::string::npos) {
            continue;
        }
        pid_t pid = 0;
        try {
            pid = static_cast<pid_t>(std::stol(name));
        } catch (...) {
            continue;
        }
        if (pid == self) continue;

        std::ifstream cmdline(
            entry.path() / "cmdline", std::ios::binary);
        std::string executable;
        if (cmdline) {
            std::getline(cmdline, executable, '\0');
        }
        if (executable.empty()) {
            std::ifstream comm(entry.path() / "comm");
            std::getline(comm, executable);
        }
        if (executable.empty()) continue;
        const auto executable_name =
            fs::path(executable).filename().string();
        if (std::find(
                managed_names.begin(),
                managed_names.end(),
                executable_name) != managed_names.end()) {
            return true;
        }
    }
    return false;
}

const char* recovery_error_code(
    backup::RecoveryErrorKind kind) noexcept {
    switch (kind) {
    case backup::RecoveryErrorKind::global_unknown:
        return "unknown_state";
    case backup::RecoveryErrorKind::multiple_active_operations:
        return "multiple_active_operations";
    case backup::RecoveryErrorKind::corrupt_journal:
        return "corrupt_journal";
    case backup::RecoveryErrorKind::corrupt_snapshot:
        return "corrupt_snapshot";
    case backup::RecoveryErrorKind::unsafe_state:
        return "unsafe_state";
    case backup::RecoveryErrorKind::retryable_io:
        return "recovery_io";
    case backup::RecoveryErrorKind::verification_failed:
        return "verification_failed";
    case backup::RecoveryErrorKind::completion_failed:
        return "completion_failed";
    case backup::RecoveryErrorKind::global_marker_failure:
        return "unknown_marker_failure";
    }
    return "recovery_failed";
}

RecoverPersistentStateExitCode recovery_exit_code(
    backup::RecoveryErrorKind kind) noexcept {
    switch (kind) {
    case backup::RecoveryErrorKind::retryable_io:
    case backup::RecoveryErrorKind::completion_failed:
        return RecoverPersistentStateExitCode::retryable;
    case backup::RecoveryErrorKind::global_unknown:
    case backup::RecoveryErrorKind::multiple_active_operations:
    case backup::RecoveryErrorKind::corrupt_journal:
    case backup::RecoveryErrorKind::corrupt_snapshot:
    case backup::RecoveryErrorKind::unsafe_state:
    case backup::RecoveryErrorKind::verification_failed:
    case backup::RecoveryErrorKind::global_marker_failure:
        return RecoverPersistentStateExitCode::blocked;
    }
    return RecoverPersistentStateExitCode::blocked;
}

const char* maintenance_error_code(
    MaintenanceLockErrorKind kind) noexcept {
    switch (kind) {
    case MaintenanceLockErrorKind::busy:
        return "maintenance_busy";
    case MaintenanceLockErrorKind::stale_generation:
        return "maintenance_generation_changed";
    case MaintenanceLockErrorKind::protocol_mismatch:
        return "maintenance_protocol_mismatch";
    case MaintenanceLockErrorKind::unsafe_state:
        return "unsafe_maintenance_state";
    case MaintenanceLockErrorKind::helper_execution:
        return "maintenance_helper_failed";
    case MaintenanceLockErrorKind::timeout:
        return "maintenance_timeout";
    case MaintenanceLockErrorKind::malformed_response:
        return "maintenance_response_invalid";
    case MaintenanceLockErrorKind::guardian_died:
        return "maintenance_guardian_died";
    case MaintenanceLockErrorKind::system_error:
        return "maintenance_system_error";
    }
    return "maintenance_failed";
}

RecoverPersistentStateExitCode maintenance_exit_code(
    MaintenanceLockErrorKind kind) noexcept {
    switch (kind) {
    case MaintenanceLockErrorKind::busy:
    case MaintenanceLockErrorKind::stale_generation:
    case MaintenanceLockErrorKind::helper_execution:
    case MaintenanceLockErrorKind::timeout:
    case MaintenanceLockErrorKind::guardian_died:
    case MaintenanceLockErrorKind::system_error:
        return RecoverPersistentStateExitCode::retryable;
    case MaintenanceLockErrorKind::protocol_mismatch:
    case MaintenanceLockErrorKind::unsafe_state:
    case MaintenanceLockErrorKind::malformed_response:
        return RecoverPersistentStateExitCode::blocked;
    }
    return RecoverPersistentStateExitCode::blocked;
}

void write_success(std::ostream& output,
                   const backup::RecoveryResult& result,
                   bool generation_reserved) {
    nlohmann::json document{
        {"ok", true},
        {"outcome",
         result.outcome ==
                 backup::RecoveryOutcome::rollback_completed
             ? "rollback_completed"
             : "no_active_operation"},
        {"generation_reserved", generation_reserved},
    };
    if (result.operation.has_value()) {
        document["operation"] =
            backup::recovery_operation_name(*result.operation);
    }
    if (result.transaction_id.has_value()) {
        document["transaction_id"] =
            *result.transaction_id;
    }
    output << document.dump() << '\n';
}

int write_failure(std::ostream& output,
                  RecoverPersistentStateExitCode exit_code,
                  const std::string& code,
                  const std::string& message) {
    const char* classification =
        exit_code == RecoverPersistentStateExitCode::retryable
            ? "retryable"
            : "blocked";
    output
        << nlohmann::json{
               {"ok", false},
               {"error",
                {
                    {"class", classification},
                    {"code", code},
                    {"message", message},
                }},
           }
               .dump()
        << '\n';
    return static_cast<int>(exit_code);
}

backup::RecoveryCoordinatorLayout production_layout() {
    backup::RecoveryCoordinatorLayout layout;
    layout.persistent.config =
        fs::path(KEEN_PBR_DEFAULT_CONFIG_PATH);
    layout.persistent.transports =
        layout.persistent.config.parent_path() /
        "transports.json";

    const auto etc_directory =
        layout.persistent.config.parent_path().parent_path();
    const auto prefix = etc_directory.parent_path();
    layout.state_root =
        prefix / "var" / "lib" / "keen-pbr" / "recovery";
    return layout;
}

} // namespace

#ifdef KEEN_PBR3_TESTING
std::vector<std::string>
recovery_managed_process_names_for_testing(
    backup::RecoveryOperation operation) {
    return managed_process_names(operation);
}
#endif

int run_recover_persistent_state(
    const RecoverPersistentStateOptions& options,
    std::ostream& output) {
    try {
        const auto probe =
            probe_recovery_state(options.layout);
        if (!probe.operation.has_value()) {
            write_success(
                output,
                {
                    backup::RecoveryOutcome::no_active_operation,
                    std::nullopt,
                    std::nullopt,
                },
                false);
            return static_cast<int>(
                RecoverPersistentStateExitCode::success);
        }

        if (!options.runtime_active_probe) {
            return write_failure(
                output,
                RecoverPersistentStateExitCode::blocked,
                "runtime_probe_missing",
                "Persistent recovery has no managed-runtime probe");
        }
        if (options.runtime_active_probe(*probe.operation)) {
            return write_failure(
                output,
                RecoverPersistentStateExitCode::blocked,
                "runtime_still_active",
                "Persistent recovery requires the affected services "
                "to be stopped");
        }
        if (!options.lease_factory) {
            return write_failure(
                output,
                RecoverPersistentStateExitCode::blocked,
                "maintenance_factory_missing",
                "Persistent recovery has no maintenance lease factory");
        }

        auto lease =
            options.lease_factory(kRecoveryOperation);
        if (!lease) {
            throw CommandFailure(
                RecoverPersistentStateExitCode::blocked,
                "maintenance_factory_failed",
                "Persistent recovery did not obtain a maintenance lease");
        }

        // Recovery owns one generation transition. reserve() also verifies
        // the guardian and durable lock record immediately before mutation.
        (void)lease->reserve(lease->base_generation());
        lease->verify_held();

        backup::RecoveryCoordinator coordinator(options.layout);
        const auto result = coordinator.recover();
        write_success(output, result, true);
        return static_cast<int>(
            RecoverPersistentStateExitCode::success);
    } catch (const CommandFailure& error) {
        return write_failure(
            output,
            error.exit_code(),
            error.code(),
            error.what());
    } catch (const backup::RecoveryCoordinatorError& error) {
        return write_failure(
            output,
            recovery_exit_code(error.kind()),
            recovery_error_code(error.kind()),
            error.what());
    } catch (const MaintenanceLockError& error) {
        return write_failure(
            output,
            maintenance_exit_code(error.kind()),
            maintenance_error_code(error.kind()),
            error.what());
    } catch (const std::exception& error) {
        return write_failure(
            output,
            RecoverPersistentStateExitCode::blocked,
            "unexpected_recovery_failure",
            error.what());
    }
}

int run_recover_persistent_state_command() {
    RecoverPersistentStateOptions options;
    options.layout = production_layout();
    options.lease_factory =
        [](const std::string& operation) {
            return std::make_unique<MaintenanceCoordinator>(
                operation);
        };
    options.runtime_active_probe =
        [](backup::RecoveryOperation operation) {
            return production_runtime_active(operation);
        };
    return run_recover_persistent_state(
        options, std::cout);
}

} // namespace keen_pbr3
