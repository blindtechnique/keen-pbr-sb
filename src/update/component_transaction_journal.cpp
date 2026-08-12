#include "component_transaction_journal.hpp"

#include "../config/config_writer.hpp"

#include <fstream>
#include <nlohmann/json.hpp>
#include <system_error>

#include <cerrno>
#include <csignal>
#include <sstream>

#include <fcntl.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

constexpr int kJournalVersion = 1;

std::optional<ComponentTransactionPhase> phase_from_name(
    const std::string& name) {
    if (name == "started") return ComponentTransactionPhase::started;
    if (name == "mutating") return ComponentTransactionPhase::mutating;
    if (name == "verifying") return ComponentTransactionPhase::verifying;
    return std::nullopt;
}

// A rename or unlink is only durable once the directory entry itself is on
// disk. Without this the record can reappear after a crash that followed a
// successful upgrade.
// Field 22 of /proc/<pid>/stat, past the comm field which may itself contain
// spaces and parentheses.
std::optional<std::string> process_start_time(std::int64_t pid) {
    std::ifstream input(std::filesystem::path("/proc") /
                        std::to_string(pid) / "stat");
    std::string stat;
    if (!std::getline(input, stat)) return std::nullopt;
    const auto comm_end = stat.rfind(") ");
    if (comm_end == std::string::npos) return std::nullopt;
    std::istringstream fields(stat.substr(comm_end + 2));
    std::string value;
    for (int field = 3; field <= 22; ++field) {
        if (!(fields >> value)) return std::nullopt;
    }
    return value;
}

bool owner_is_alive(std::int64_t pid, const std::string& expected_start) {
    if (pid <= 1 || expected_start.empty()) return false;
    if (::kill(static_cast<pid_t>(pid), 0) != 0 && errno != EPERM)
        return false;
    const auto actual = process_start_time(pid);
    return actual && *actual == expected_start;
}

void sync_directory(const std::filesystem::path& path) {
    const auto parent = path.parent_path();
    const int fd = ::open(parent.empty() ? "." : parent.c_str(),
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return;
    ::fsync(fd);
    ::close(fd);
}

} // namespace

void write_component_transaction(
    const std::filesystem::path& path,
    const ComponentTransactionRecord& record) {
    // Taken here rather than from the caller: the process that writes the
    // record is by definition the one performing the operation, and letting a
    // caller name someone else would let a record outlive its own truth.
    const auto owner_pid =
        record.owner_pid != 0 ? record.owner_pid
                              : static_cast<std::int64_t>(::getpid());
    const auto owner_start =
        !record.owner_start.empty()
            ? record.owner_start
            : process_start_time(owner_pid).value_or(std::string{});

    const nlohmann::json body = {
        {"version", kJournalVersion},
        {"component", record.component},
        {"operation", record.operation},
        {"phase", component_transaction_phase_name(record.phase)},
        {"started_at", record.started_at},
        {"binary_sha256", record.binary_sha256},
        {"config_sha256", record.config_sha256},
        {"runtime_was_running", record.runtime_was_running},
        {"owner_pid", owner_pid},
        {"owner_start", owner_start},
    };
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.default_file_mode = 0600;
    options.file_mode = static_cast<mode_t>(0600);
    write_file_atomically(path.string(), body.dump(), options);
}

ComponentTransactionStatus read_component_transaction(
    const std::filesystem::path& path) {
    ComponentTransactionStatus status;
    std::error_code error;
    if (!std::filesystem::exists(path, error)) {
        // An unreadable directory is not proof of absence. Say so rather than
        // report the state that lets the next upgrade proceed.
        if (error) status.state = ComponentTransactionState::unreadable;
        return status;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        status.state = ComponentTransactionState::unreadable;
        return status;
    }
    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(input);
    } catch (const nlohmann::json::exception&) {
        status.state = ComponentTransactionState::unreadable;
        return status;
    }
    if (!parsed.is_object() ||
        !parsed.contains("version") ||
        !parsed["version"].is_number_integer() ||
        parsed["version"].get<int>() != kJournalVersion) {
        status.state = ComponentTransactionState::unreadable;
        return status;
    }

    ComponentTransactionRecord record;
    try {
        record.component = parsed.at("component").get<std::string>();
        record.operation = parsed.at("operation").get<std::string>();
        const auto phase =
            phase_from_name(parsed.at("phase").get<std::string>());
        if (!phase || record.component.empty() || record.operation.empty()) {
            status.state = ComponentTransactionState::unreadable;
            return status;
        }
        record.phase = *phase;
        record.started_at = parsed.value("started_at", std::int64_t{0});
        record.binary_sha256 = parsed.value("binary_sha256", std::string{});
        record.config_sha256 = parsed.value("config_sha256", std::string{});
        record.runtime_was_running =
            parsed.value("runtime_was_running", false);
        record.owner_pid = parsed.value("owner_pid", std::int64_t{0});
        record.owner_start = parsed.value("owner_start", std::string{});
    } catch (const nlohmann::json::exception&) {
        status.state = ComponentTransactionState::unreadable;
        return status;
    }

    // A record without a live owner is one nobody is going to finish. Both
    // states block the next operation; only one of them is a problem to tell
    // the operator about.
    status.state = owner_is_alive(record.owner_pid, record.owner_start)
                       ? ComponentTransactionState::in_flight
                       : ComponentTransactionState::abandoned;
    status.record = std::move(record);
    return status;
}

bool clear_component_transaction(const std::filesystem::path& path) {
    std::error_code error;
    // A false return with no error means the record was already absent, which
    // is the end state this asks for. Only an error means it survived.
    std::filesystem::remove(path, error);
    sync_directory(path);
    return !error;
}

const char* component_transaction_phase_name(
    ComponentTransactionPhase phase) noexcept {
    switch (phase) {
        case ComponentTransactionPhase::started:
            return "started";
        case ComponentTransactionPhase::mutating:
            return "mutating";
        case ComponentTransactionPhase::verifying:
            return "verifying";
    }
    return "mutating";
}

const char* component_transaction_state_name(
    ComponentTransactionState state) noexcept {
    switch (state) {
        case ComponentTransactionState::none:
            return "none";
        case ComponentTransactionState::in_flight:
            return "in_flight";
        case ComponentTransactionState::abandoned:
            return "abandoned";
        case ComponentTransactionState::unreadable:
            return "unreadable";
    }
    return "unreadable";
}

} // namespace keen_pbr3
