#pragma once

#ifdef KEEN_PBR3_TESTING
#include <chrono>
#include <filesystem>
#include <optional>
#endif
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <sys/types.h>

namespace keen_pbr3 {

enum class MaintenanceLockErrorKind {
    busy,
    stale_generation,
    protocol_mismatch,
    unsafe_state,
    helper_execution,
    timeout,
    malformed_response,
    guardian_died,
    system_error,
};

class MaintenanceLockError final : public std::runtime_error {
public:
    MaintenanceLockError(MaintenanceLockErrorKind kind,
                         std::string message,
                         int helper_exit_code = -1);

    MaintenanceLockErrorKind kind() const noexcept;
    int helper_exit_code() const noexcept;

private:
    MaintenanceLockErrorKind kind_;
    int helper_exit_code_;
};

class MaintenanceLease {
public:
    virtual ~MaintenanceLease() = default;

    virtual std::uint32_t base_generation() const noexcept = 0;
    virtual std::uint32_t reserve(std::uint32_t expected_generation) = 0;
    virtual void verify_held() = 0;

    // Exact child-only capability for a trusted maintainer script that must
    // borrow this lease instead of contending with its parent. Test doubles
    // and leases without a shell borrower keep the default empty value.
    virtual pid_t borrow_owner_pid() const noexcept { return -1; }
    virtual std::string borrow_token() const { return {}; }
};

#ifdef KEEN_PBR3_TESTING
struct MaintenanceCoordinatorTestOptions {
    std::filesystem::path helper_path;
    std::optional<std::filesystem::path> rescue_root;
    std::chrono::milliseconds command_timeout{
        std::chrono::seconds{3}};
    std::chrono::milliseconds durability_timeout{
        std::chrono::seconds{3}};
    std::chrono::milliseconds ready_timeout{
        std::chrono::seconds{3}};
    std::chrono::milliseconds terminate_grace{
        std::chrono::milliseconds{250}};
};
#endif

// Owns a protocol-3 maintenance lease. The authoritative lock record belongs
// to this long-lived process; the guardian only observes the control pipe and
// performs the normal release on EOF. No shell command string is constructed:
// the trusted helper is always posix_spawn(3)'d directly.
class MaintenanceCoordinator final : public MaintenanceLease {
public:
    explicit MaintenanceCoordinator(std::string operation);
#ifdef KEEN_PBR3_TESTING
    MaintenanceCoordinator(
        std::string operation,
        MaintenanceCoordinatorTestOptions options);
#endif
    ~MaintenanceCoordinator() noexcept;

    MaintenanceCoordinator(const MaintenanceCoordinator&) = delete;
    MaintenanceCoordinator& operator=(const MaintenanceCoordinator&) =
        delete;
    MaintenanceCoordinator(MaintenanceCoordinator&&) = delete;
    MaintenanceCoordinator& operator=(MaintenanceCoordinator&&) = delete;

    const std::string& operation() const noexcept;
    std::uint32_t base_generation() const noexcept override;

    // Reserves exactly expected_generation + 1. Parent ownership and guardian
    // liveness are checked immediately before every compare-and-swap.
    std::uint32_t reserve(std::uint32_t expected_generation) override;

    // Checks both observer liveness and parent protocol ownership. Throws on
    // guardian death or on an unsafe/mismatched lock record.
    void verify_held() override;

    pid_t guardian_pid() const noexcept;
    pid_t borrow_owner_pid() const noexcept override;
    std::string borrow_token() const override;

private:
    struct RuntimeOptions;

    void start(std::string operation, RuntimeOptions options);
    void release_noexcept() noexcept;

    std::string operation_;
    std::string helper_path_;
    std::string token_;
    std::string rescue_root_;
    std::uint32_t base_generation_{0};
    pid_t owner_pid_{-1};
    pid_t guardian_pid_{-1};
    int control_fd_{-1};
    std::int64_t command_timeout_ms_{3000};
    std::int64_t durability_timeout_ms_{15000};
    std::int64_t ready_timeout_ms_{3000};
    std::int64_t terminate_grace_ms_{250};
    std::mutex reserve_mutex_;
};

} // namespace keen_pbr3
