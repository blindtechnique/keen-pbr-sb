#pragma once

#include "../log/logger.hpp"
#include "last_command_failure.hpp"

#include <algorithm>
#include <chrono>
#include <atomic>
#include <cstdint>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <optional>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {

struct ExecCaptureResult {
    std::string stdout_output;
    int exit_code{-1};
    bool truncated{false};
    bool timed_out{false};
    // A timeout is safe to recover from only after every process in the
    // command's process group is gone and the capture pipe reaches EOF. When
    // either cannot be established within the kill deadline, callers that
    // would mutate the same files must retain their journal and abstain.
    bool termination_uncertain{false};
};

inline void reset_child_signal_mask() {
    sigset_t empty_mask;
    sigemptyset(&empty_mask);
    sigprocmask(SIG_SETMASK, &empty_mask, nullptr);
}

inline bool redirect_child_stdin_to_devnull() {
    const int devnull = open("/dev/null", O_RDONLY);
    if (devnull < 0) {
        return false;
    }
    if (dup2(devnull, STDIN_FILENO) < 0) {
        close(devnull);
        return false;
    }
    if (devnull != STDIN_FILENO) {
        close(devnull);
    }
    return true;
}


struct SafeExecTimeouts {
    std::chrono::milliseconds timeout{std::chrono::seconds{30}};
    std::chrono::milliseconds kill_grace{std::chrono::seconds{2}};
};

enum class SafeExecFailureLog {
    Enabled,
    // Preserve the bounded last-command snapshot for support diagnostics
    // without promoting an error that a higher-level reconciler handles into
    // the user-facing log/notification stream.
    DiagnosticOnly,
    Suppressed,
};

struct SafeExecFailureDetail {
    std::string reason;
    std::string numeric_detail;
    int numeric_value{0};
};

inline void set_safe_exec_failure_detail(
    SafeExecFailureDetail* detail,
    std::string_view reason,
    std::string_view numeric_detail = {},
    int numeric_value = 0) {
    if (detail == nullptr) {
        return;
    }
    detail->reason.assign(reason.data(), reason.size());
    detail->numeric_detail.assign(
        numeric_detail.data(), numeric_detail.size());
    detail->numeric_value = numeric_value;
}

inline bool should_record_safe_exec_failure(SafeExecFailureLog mode) {
    return mode != SafeExecFailureLog::Suppressed;
}

inline bool should_log_safe_exec_failure(SafeExecFailureLog mode) {
    return mode == SafeExecFailureLog::Enabled;
}

inline std::atomic<std::int64_t>& safe_exec_timeout_ms_storage() {
    static std::atomic<std::int64_t> value{30000};
    return value;
}

inline std::atomic<std::int64_t>& safe_exec_kill_grace_ms_storage() {
    static std::atomic<std::int64_t> value{2000};
    return value;
}

inline void set_safe_exec_timeouts(std::chrono::milliseconds timeout,
                                   std::chrono::milliseconds kill_grace) {
    safe_exec_timeout_ms_storage().store(std::max<std::int64_t>(1, timeout.count()),
                                         std::memory_order_release);
    safe_exec_kill_grace_ms_storage().store(std::max<std::int64_t>(0, kill_grace.count()),
                                            std::memory_order_release);
}

inline SafeExecTimeouts safe_exec_timeouts() {
    return {
        std::chrono::milliseconds{safe_exec_timeout_ms_storage().load(std::memory_order_acquire)},
        std::chrono::milliseconds{safe_exec_kill_grace_ms_storage().load(std::memory_order_acquire)},
    };
}

struct ChildWaitResult {
    int status{0};
    bool reaped{false};
    bool timed_out{false};
    int wait_errno{0};
};

inline void prepare_child_process_group() {
    (void)setpgid(0, 0);
}

inline void prepare_parent_process_group(pid_t pid) {
    (void)setpgid(pid, pid);
}

inline void signal_child_process_group(pid_t pid, int signal_number) {
    if (kill(-pid, signal_number) != 0 && errno == ESRCH) {
        (void)kill(pid, signal_number);
    }
}

inline void signal_retained_process_group(pid_t group_id,
                                          int signal_number,
                                          bool direct_child_owned) noexcept {
    // The direct child may already have been reaped, so its pid can be reused.
    // Fall back to its positive pid only while it is still our unreaped child;
    // in that state pid reuse is impossible. This covers a failed setpgid()
    // without ever signalling an unrelated process after the leader is reaped.
    if (kill(-group_id, signal_number) != 0 && errno == ESRCH &&
        direct_child_owned) {
        (void)kill(group_id, signal_number);
    }
}

inline bool process_group_still_exists(pid_t group_id) noexcept {
    if (kill(-group_id, 0) == 0) return true;
    return errno != ESRCH;
}

struct ProcessGroupTerminationResult {
    bool group_gone{false};
    bool child_reaped{false};
    bool child_status_valid{false};
    int child_status{0};
    int wait_errno{0};
};

// Terminate and observe the whole execution group, including the case where
// its leader exited normally while a maintainer-script descendant retained the
// capture pipe. Both TERM and KILL phases are bounded. Returning group_gone=false
// is an explicit unsafe/unknown outcome; it is never permission to begin a
// rollback that could race the descendant.
inline ProcessGroupTerminationResult terminate_process_group_bounded(
    pid_t group_id,
    bool child_reaped,
    bool child_status_valid,
    int child_status,
    std::chrono::milliseconds kill_grace) noexcept {
    using clock = std::chrono::steady_clock;
    ProcessGroupTerminationResult result{
        false, child_reaped, child_status_valid, child_status, 0};

    auto observe_child = [&]() {
        if (result.child_reaped) return;
        while (true) {
            const pid_t waited =
                waitpid(group_id, &result.child_status, WNOHANG);
            if (waited == group_id) {
                result.child_reaped = true;
                result.child_status_valid = true;
                return;
            }
            if (waited == 0) return;
            if (waited < 0 && errno == EINTR) continue;
            if (waited < 0 && errno == ECHILD) {
                result.child_reaped = true;
                return;
            }
            if (waited < 0) {
                result.wait_errno = errno;
                return;
            }
        }
    };

    auto wait_until_gone = [&](clock::time_point deadline) {
        while (true) {
            observe_child();
            const bool group_exists =
                process_group_still_exists(group_id);
            bool direct_child_exists = false;
            if (!result.child_reaped) {
                direct_child_exists =
                    kill(group_id, 0) == 0 || errno == EPERM;
            }
            if (!group_exists && !direct_child_exists) return true;
            const auto now = clock::now();
            if (now >= deadline) return false;
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now);
            const int delay = static_cast<int>(std::max<std::int64_t>(
                1, std::min<std::int64_t>(20, remaining.count())));
            (void)poll(nullptr, 0, delay);
        }
    };

    signal_retained_process_group(
        group_id, SIGTERM, !result.child_reaped);
    if (!wait_until_gone(clock::now() + kill_grace)) {
        signal_retained_process_group(
            group_id, SIGKILL, !result.child_reaped);
        result.group_gone =
            wait_until_gone(clock::now() + kill_grace);
    } else {
        result.group_gone = true;
    }
    observe_child();
    return result;
}

inline ChildWaitResult wait_for_child_until(
    pid_t pid,
    std::chrono::steady_clock::time_point deadline,
    std::chrono::milliseconds kill_grace) {
    using clock = std::chrono::steady_clock;
    ChildWaitResult result;
    auto wait_until = [&](clock::time_point until) {
        while (true) {
            const pid_t waited = waitpid(pid, &result.status, WNOHANG);
            if (waited == pid) {
                result.reaped = true;
                return true;
            }
            if (waited < 0 && errno != EINTR) {
                result.wait_errno = errno;
                return true;
            }
            const auto now = clock::now();
            if (now >= until) {
                return false;
            }
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(until - now);
            const int delay = static_cast<int>(std::max<std::int64_t>(1,
                std::min<std::int64_t>(20, remaining.count())));
            (void)poll(nullptr, 0, delay);
        }
    };

    if (wait_until(deadline)) {
        return result;
    }
    result.timed_out = true;
    signal_child_process_group(pid, SIGTERM);
    if (wait_until(clock::now() + kill_grace)) {
        signal_child_process_group(pid, SIGKILL);
        return result;
    }
    signal_child_process_group(pid, SIGKILL);
    while (waitpid(pid, &result.status, 0) < 0) {
        if (errno != EINTR) {
            result.wait_errno = errno;
            return result;
        }
    }
    result.reaped = true;
    return result;
}

// Compatibility helper used by the existing test suite and small callers.
inline ChildWaitResult wait_for_child_with_timeout(pid_t pid,
                                                   std::chrono::seconds timeout) {
    return wait_for_child_until(pid,
                                std::chrono::steady_clock::now() + timeout,
                                std::chrono::seconds{2});
}

inline std::string safe_exec_command_string(const std::vector<std::string>& args) {
    std::ostringstream out;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i != 0) {
            out << ' ';
        }
        out << args[i];
    }
    return out.str();
}

inline void log_failed_pipe_input(const std::string& command,
                                  const std::string& input) {
    constexpr std::size_t max_preview_bytes = 4096;
    const bool truncated = input.size() > max_preview_bytes;
    const std::string preview =
        input.substr(0, std::min(input.size(), max_preview_bytes));
    Logger::instance().error(
        "safe_exec_pipe_input cmd={} input_bytes={} preview_bytes={} truncated={}:\n{}",
        command,
        input.size(),
        preview.size(),
        truncated ? "true" : "false",
        preview);
}

inline void record_safe_exec_pipe_failure(
    const std::vector<std::string>& args,
    int exit_code,
    const std::string& input,
    std::string_view response,
    std::string_view reason,
    std::string_view numeric_detail = {},
    int numeric_value = 0) noexcept {
    // Diagnostics are observational only. In particular, their filesystem
    // operations and allocations must not replace the command result or the
    // errno produced by pipe/fork/waitpid.
    const int saved_errno = errno;
    try {
        std::string rendered_reason(reason);
        if (!numeric_detail.empty()) {
            rendered_reason.push_back(' ');
            rendered_reason.append(
                numeric_detail.data(), numeric_detail.size());
            rendered_reason.push_back('=');
            rendered_reason += std::to_string(numeric_value);
        }
        (void)write_last_command_failure(LastCommandFailureView{
            args, exit_code, input, response, rendered_reason});
    } catch (...) {
        // Best-effort diagnostics are never part of command execution.
    }
    errno = saved_errno;
}

using ChildEnvironmentOverrides =
    std::vector<std::pair<std::string, std::string>>;

// A name must be a real name and a value must survive being copied into a
// NUL-terminated "NAME=VALUE" entry. Anything else would produce an entry the
// child cannot interpret, so it is rejected before fork() rather than after.
inline bool child_environment_overrides_are_valid(
    const ChildEnvironmentOverrides& child_environment) {
    for (const auto& [name, value] : child_environment) {
        if (name.empty() ||
            name.find('=') != std::string::npos ||
            name.find('\0') != std::string::npos ||
            value.find('\0') != std::string::npos) {
            return false;
        }
    }
    return true;
}

// execve() intentionally does not perform a PATH lookup. Requiring an absolute
// executable keeps the child branch async-signal-safe.
inline bool child_environment_needs_absolute_executable(
    const ChildEnvironmentOverrides& child_environment,
    const std::string& executable) {
    return !child_environment.empty() &&
           (executable.empty() || executable.front() != '/');
}

// Build the complete child environment before fork(). The child performs only
// descriptor operations and execve(); it never calls setenv(), which may
// allocate and deadlock after fork in this multithreaded daemon.
//
// `storage` owns the entries and must outlive `pointers`, which alias into it.
// `pointers` stays empty when there is nothing to override, which is the signal
// to keep using execvp() and the inherited environment.
inline void build_child_environment(
    const ChildEnvironmentOverrides& child_environment,
    std::vector<std::string>& storage,
    std::vector<char*>& pointers) {
    storage.clear();
    pointers.clear();
    if (child_environment.empty()) {
        return;
    }
    const auto is_overridden =
        [&child_environment](const std::string_view entry) {
            return std::any_of(
                child_environment.begin(),
                child_environment.end(),
                [entry](const auto& override_value) {
                    const auto& name = override_value.first;
                    return entry.size() > name.size() &&
                           entry.compare(0, name.size(), name) == 0 &&
                           entry[name.size()] == '=';
                });
        };
    for (char** entry = environ;
         entry != nullptr && *entry != nullptr;
         ++entry) {
        if (!is_overridden(*entry)) {
            storage.emplace_back(*entry);
        }
    }
    for (const auto& [name, value] : child_environment) {
        storage.push_back(name + "=" + value);
    }
    pointers.reserve(storage.size() + 1U);
    for (auto& entry : storage) {
        pointers.push_back(entry.data());
    }
    pointers.push_back(nullptr);
}

// Execute a command with arguments directly via fork()+execvp(), bypassing
// the shell entirely. This prevents shell injection attacks.
// Returns the process exit code (0-255), or -1 on fork/exec failure.
inline int safe_exec_with_timeouts(
    const std::vector<std::string>& args,
    bool suppress_output,
    const SafeExecTimeouts& timeouts,
    const ChildEnvironmentOverrides& child_environment = {},
    SafeExecFailureLog failure_log = SafeExecFailureLog::Enabled) {
    if (args.empty()) return -1;
    if (!child_environment_overrides_are_valid(child_environment)) {
        return -1;
    }
    if (child_environment_needs_absolute_executable(
            child_environment, args.front())) {
        return -1;
    }
    const std::string command = safe_exec_command_string(args);
    const auto started_at = std::chrono::steady_clock::now();
    Logger::instance().debug("safe_exec_start cmd={} suppress_output={}",
                             command,
                             suppress_output ? "true" : "false");

    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
        argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    std::vector<std::string> environment_storage;
    std::vector<char*> environment;
    build_child_environment(
        child_environment, environment_storage, environment);

    const pid_t pid = fork();
    if (pid == -1) {
        Logger::instance().verbose("safe_exec_error cmd={} duration_ms={} reason=fork_failed errno={}",
                                 command,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count(),
                                 errno);
        return -1;
    }

    if (pid == 0) {
        // Child process
        prepare_child_process_group();
        reset_child_signal_mask();
        if (!redirect_child_stdin_to_devnull()) {
            _exit(127);
        }
        if (suppress_output) {
            const int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        if (!environment.empty()) {
            ::execve(
                argv[0],
                const_cast<char* const*>(
                    argv.data()),
                environment.data());
        } else {
            ::execvp(
                argv[0],
                const_cast<char* const*>(
                    argv.data()));
        }
        _exit(127); // execvp failed
    }

    prepare_parent_process_group(pid);
    const ChildWaitResult wait_result = wait_for_child_until(
        pid, started_at + timeouts.timeout, timeouts.kill_grace);
    if (wait_result.timed_out) {
        if (should_record_safe_exec_failure(failure_log)) {
            try {
                const std::string reason =
                    "timeout timeout_ms=" +
                    std::to_string(timeouts.timeout.count());
                (void)write_last_command_failure(LastCommandFailureView{
                    args, -1, {}, {}, reason});
            } catch (...) {
                // Diagnostics never replace the bounded command result.
            }
        }
        if (should_log_safe_exec_failure(failure_log)) {
            Logger::instance().error(
                "Command '{}' exceeded {} ms and was killed. On Keenetic this usually "
                "means the firmware is holding the xtables lock; the operation will "
                "be retried.",
                command, timeouts.timeout.count());
        } else if (failure_log == SafeExecFailureLog::DiagnosticOnly) {
            Logger::instance().verbose(
                "safe_exec_timeout cmd={} timeout_ms={} notification=deferred",
                command,
                timeouts.timeout.count());
        }
        return -1;
    }
    int status = wait_result.status;
    if (!wait_result.reaped) {
        Logger::instance().verbose("safe_exec_error cmd={} duration_ms={} reason=waitpid_failed errno={}",
                                 command,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count(),
                                 errno);
        return -1;
    }
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at).count();
    if (WIFEXITED(status)) {
        const int exit_code = WEXITSTATUS(status);
        Logger::instance().trace("safe_exec_end",
                                 "cmd={} exit_code={} duration_ms={}",
                                 command,
                                 exit_code,
                                 duration_ms);
        return exit_code;
    }
    Logger::instance().verbose("safe_exec_error",
                                    "cmd={} duration_ms={} reason=abnormal_exit",
                                    command,
                                    duration_ms);
    return -1;
}

inline int safe_exec(const std::vector<std::string>& args,
                     bool suppress_output = false,
                     SafeExecFailureLog failure_log =
                         SafeExecFailureLog::Enabled) {
    return safe_exec_with_timeouts(
        args,
        suppress_output,
        safe_exec_timeouts(),
        {},
        failure_log);
}

// Apply fixed environment overrides in the forked child only. The executable
// must be absolute so the post-fork branch can call execve() directly without
// PATH lookup, allocation, or mutation of the daemon's environment.
inline int safe_exec_with_environment(
    const std::vector<std::string>& args,
    const ChildEnvironmentOverrides& child_environment,
    bool suppress_output = false) {
    return safe_exec_with_timeouts(
        args,
        suppress_output,
        safe_exec_timeouts(),
        child_environment);
}

// Execute a command with arguments, piping input data to its stdin.
// Returns the process exit code (0-255), or -1 on fork/exec/pipe failure.
//
// When stderr_out is given, the child's stderr is captured into it. Without
// this an "exited with status 1" from iptables-restore said nothing at all:
// the tool prints which line it choked on, and that message went to a stderr
// nobody was reading.
inline int safe_exec_pipe_stdin(const std::vector<std::string>& args,
                                const std::string& input,
                                std::string* stderr_out = nullptr,
                                SafeExecFailureLog failure_log =
                                    SafeExecFailureLog::Enabled,
                                SafeExecFailureDetail* failure_detail = nullptr,
                                std::optional<SafeExecTimeouts> timeout_override =
                                    std::nullopt) {
    if (failure_detail != nullptr) {
        *failure_detail = {};
    }
    if (args.empty()) {
        set_safe_exec_failure_detail(failure_detail, "empty_command");
        return -1;
    }
    const std::string command = safe_exec_command_string(args);
    const auto started_at = std::chrono::steady_clock::now();
    Logger::instance().trace("safe_exec_pipe_start",
                             "cmd={} input_bytes={}",
                             command,
                             input.size());

    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
        argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        const int pipe_errno = errno;
        set_safe_exec_failure_detail(
            failure_detail, "pipe_failed", "errno", pipe_errno);
        Logger::instance().trace("safe_exec_pipe_error",
                                 "cmd={} duration_ms={} reason=pipe_failed errno={}",
                                 command,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count(),
                                 pipe_errno);
        if (should_record_safe_exec_failure(failure_log)) {
            errno = pipe_errno;
            record_safe_exec_pipe_failure(
                args, -1, input, {}, "pipe_failed", "errno", pipe_errno);
        }
        errno = pipe_errno;
        return -1;
    }

    int errfd[2] = {-1, -1};
    if (stderr_out != nullptr && pipe2(errfd, O_CLOEXEC) == -1) {
        errfd[0] = errfd[1] = -1; // Capture is a nicety; carry on without it.
    }

    const pid_t pid = fork();
    if (pid == -1) {
        const int fork_errno = errno;
        set_safe_exec_failure_detail(
            failure_detail, "fork_failed", "errno", fork_errno);
        close(pipefd[0]);
        close(pipefd[1]);
        if (errfd[0] != -1) { close(errfd[0]); close(errfd[1]); }
        Logger::instance().trace("safe_exec_pipe_error",
                                 "cmd={} duration_ms={} reason=fork_failed errno={}",
                                 command,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count(),
                                 fork_errno);
        if (should_record_safe_exec_failure(failure_log)) {
            errno = fork_errno;
            record_safe_exec_pipe_failure(
                args, -1, input, {}, "fork_failed", "errno", fork_errno);
        }
        errno = fork_errno;
        return -1;
    }

    if (pid == 0) {
        // Child: read end becomes stdin
        prepare_child_process_group();
        reset_child_signal_mask();
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        if (errfd[1] != -1) {
            close(errfd[0]);
            dup2(errfd[1], STDERR_FILENO);
            close(errfd[1]);
        }
        execvp(argv[0], const_cast<char* const*>(argv.data()));
        _exit(127);
    }

    prepare_parent_process_group(pid);
    const SafeExecTimeouts timeouts =
        timeout_override.value_or(safe_exec_timeouts());
    const auto deadline = started_at + timeouts.timeout;

    // Write input and collect stderr concurrently. Both descriptors are
    // non-blocking so a helper that neither reads stdin nor closes stderr
    // cannot prevent the deadline from being enforced.
    close(pipefd[0]);
    if (errfd[1] != -1) {
        close(errfd[1]);
    }
    const int input_flags = fcntl(pipefd[1], F_GETFL, 0);
    if (input_flags >= 0) {
        (void)fcntl(pipefd[1], F_SETFL, input_flags | O_NONBLOCK);
    }
    if (errfd[0] != -1) {
        const int error_flags = fcntl(errfd[0], F_GETFL, 0);
        if (error_flags >= 0) {
            (void)fcntl(errfd[0], F_SETFL, error_flags | O_NONBLOCK);
        }
    }

    const char* data = input.data();
    size_t remaining = input.size();
    bool input_open = true;
    bool error_open = errfd[0] != -1;
    bool child_reaped = false;
    int waitpid_error = 0;
    int status = 0;
    bool deadline_exceeded = false;
    char buffer[512];

    const auto append_stderr =
        [stderr_out](const char* source, std::size_t count) {
            constexpr std::size_t kLimit = 8U * 1024U;
            if (stderr_out != nullptr) {
                const std::size_t available =
                    stderr_out->size() < kLimit
                        ? kLimit - stderr_out->size()
                        : 0;
                stderr_out->append(source, std::min(available, count));
            }
        };

    while ((!child_reaped || input_open || error_open) &&
           !deadline_exceeded &&
           waitpid_error == 0) {
        if (error_open) {
            while (true) {
                const ssize_t got = read(errfd[0], buffer, sizeof(buffer));
                if (got > 0) {
                    append_stderr(
                        buffer, static_cast<std::size_t>(got));
                    continue;
                }
                if (got == 0) {
                    close(errfd[0]);
                    error_open = false;
                }
                if (got < 0 && errno == EINTR) {
                    continue;
                }
                break;
            }
        }

        if (input_open && remaining > 0) {
            const ssize_t written = write(pipefd[1], data, remaining);
            if (written > 0) {
                data += written;
                remaining -= static_cast<size_t>(written);
            } else if (written < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                close(pipefd[1]);
                input_open = false;
            }
        }

        if (input_open && remaining == 0) {
            close(pipefd[1]);
            input_open = false;
        }

        if (!child_reaped) {
            const pid_t waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid) {
                child_reaped = true;
            } else if (waited < 0 && errno != EINTR) {
                waitpid_error = errno;
            }
        }
        if (child_reaped && !input_open && !error_open) {
            break;
        }
        deadline_exceeded = std::chrono::steady_clock::now() >= deadline;
        if (deadline_exceeded) {
            break;
        }

        pollfd descriptors[2]{};
        nfds_t count = 0;
        if (input_open) {
            descriptors[count++] = {pipefd[1], POLLOUT, 0};
        }
        if (error_open) {
            descriptors[count++] = {errfd[0], static_cast<short>(POLLIN | POLLHUP), 0};
        }
        (void)poll(descriptors, count, 20);
    }

    if (input_open) {
        close(pipefd[1]);
    }
    if (error_open) {
        close(errfd[0]);
    }
    if (stderr_out != nullptr) {
        while (!stderr_out->empty() &&
               (stderr_out->back() == '\n' || stderr_out->back() == '\r')) {
            stderr_out->pop_back();
        }
    }
    const std::string_view captured_stderr =
        stderr_out != nullptr ? std::string_view(*stderr_out)
                              : std::string_view{};

    if (waitpid_error != 0) {
        set_safe_exec_failure_detail(
            failure_detail, "waitpid_failed", "errno", waitpid_error);
        Logger::instance().trace(
            "safe_exec_pipe_error",
            "cmd={} duration_ms={} reason=waitpid_failed errno={}",
            command,
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started_at).count(),
            waitpid_error);
        if (should_record_safe_exec_failure(failure_log)) {
            errno = waitpid_error;
            record_safe_exec_pipe_failure(
                args,
                -1,
                input,
                captured_stderr,
                "waitpid_failed",
                "errno",
                waitpid_error);
        }
        errno = waitpid_error;
        return -1;
    }

    ChildWaitResult wait_result;
    if (child_reaped) {
        wait_result.status = status;
        wait_result.reaped = true;
        if (deadline_exceeded) {
            // The direct child is gone, but a descendant may still hold a
            // descriptor. Terminate the process group as well.
            signal_child_process_group(pid, SIGTERM);
            signal_child_process_group(pid, SIGKILL);
            wait_result.timed_out = true;
        }
    } else {
        wait_result = wait_for_child_until(pid, deadline, timeouts.kill_grace);
    }
    if (wait_result.timed_out) {
        set_safe_exec_failure_detail(failure_detail, "timeout");
        if (should_log_safe_exec_failure(failure_log)) {
            Logger::instance().error(
                "Command '{}' exceeded {} ms and was killed. On Keenetic this usually "
                "means the firmware is holding the xtables lock; the operation will "
                "be retried.",
                command, timeouts.timeout.count());
            log_failed_pipe_input(command, input);
        }
        if (should_record_safe_exec_failure(failure_log)) {
            record_safe_exec_pipe_failure(
                args, -1, input, captured_stderr, "timeout");
        }
        return -1;
    }
    status = wait_result.status;
    if (!wait_result.reaped) {
        const int wait_errno =
            wait_result.wait_errno != 0 ? wait_result.wait_errno : errno;
        set_safe_exec_failure_detail(
            failure_detail, "waitpid_failed", "errno", wait_errno);
        Logger::instance().trace("safe_exec_pipe_error",
                                 "cmd={} duration_ms={} reason=waitpid_failed errno={}",
                                 command,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count(),
                                 wait_errno);
        if (should_log_safe_exec_failure(failure_log)) {
            log_failed_pipe_input(command, input);
        }
        if (should_record_safe_exec_failure(failure_log)) {
            errno = wait_errno;
            record_safe_exec_pipe_failure(
                args,
                -1,
                input,
                captured_stderr,
                "waitpid_failed",
                "errno",
                wait_errno);
        }
        errno = wait_errno;
        return -1;
    }
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at).count();
    if (WIFEXITED(status)) {
        const int exit_code = WEXITSTATUS(status);
        if (exit_code == 0) {
            Logger::instance().trace("safe_exec_pipe_end",
                                     "cmd={} exit_code={} duration_ms={}",
                                     command,
                                     exit_code,
                                     duration_ms);
        } else if (should_log_safe_exec_failure(failure_log)) {
            Logger::instance().error(
                "safe_exec_pipe_failed cmd={} exit_code={} duration_ms={}",
                command,
                exit_code,
                duration_ms);
            log_failed_pipe_input(command, input);
        }
        if (exit_code != 0 &&
            should_record_safe_exec_failure(failure_log)) {
            record_safe_exec_pipe_failure(
                args,
                exit_code,
                input,
                captured_stderr,
                "nonzero_exit");
        }
        if (exit_code != 0) {
            set_safe_exec_failure_detail(
                failure_detail, "nonzero_exit");
        }
        return exit_code;
    }
    if (should_log_safe_exec_failure(failure_log)) {
        Logger::instance().error(
            "safe_exec_pipe_failed cmd={} duration_ms={} reason=abnormal_exit",
            command,
            duration_ms);
        log_failed_pipe_input(command, input);
    }
    if (should_record_safe_exec_failure(failure_log)) {
        if (WIFSIGNALED(status)) {
            record_safe_exec_pipe_failure(
                args,
                -1,
                input,
                captured_stderr,
                "abnormal_exit",
                "signal",
                WTERMSIG(status));
        } else {
            record_safe_exec_pipe_failure(
                args, -1, input, captured_stderr, "abnormal_exit");
        }
    }
    if (WIFSIGNALED(status)) {
        set_safe_exec_failure_detail(
            failure_detail,
            "abnormal_exit",
            "signal",
            WTERMSIG(status));
    } else {
        set_safe_exec_failure_detail(
            failure_detail, "abnormal_exit");
    }
    return -1;
}

// Execute a command with arguments and capture its output. Existing callers
// capture stdout only; security-sensitive callers may explicitly merge stderr
// into the bounded capture so a non-zero exit cannot lose its diagnostic.
//
// `child_environment` applies the same child-only override contract as
// safe_exec_with_timeouts(): the environment is built before fork(), the
// daemon's own environ is never mutated, and a non-empty override requires an
// absolute executable because execve() performs no PATH lookup.
inline ExecCaptureResult safe_exec_capture(const std::vector<std::string>& args,
                                           bool suppress_stderr = false,
                                           size_t max_bytes = 0,
                                           bool capture_stderr = false,
                                           bool drain_after_limit = false,
                                           SafeExecFailureLog failure_log =
                                               SafeExecFailureLog::Enabled,
                                           std::optional<SafeExecTimeouts>
                                               timeout_override =
                                                   std::nullopt,
                                           const ChildEnvironmentOverrides&
                                               child_environment = {}) {
    ExecCaptureResult result;
    if (args.empty()) return result;
    if (!child_environment_overrides_are_valid(child_environment)) {
        return result;
    }
    if (child_environment_needs_absolute_executable(
            child_environment, args.front())) {
        return result;
    }
    const std::string command = safe_exec_command_string(args);
    const auto started_at = std::chrono::steady_clock::now();
    Logger::instance().trace("safe_exec_capture_start",
                             "cmd={} suppress_stderr={} capture_stderr={} max_bytes={} drain_after_limit={}",
                             command,
                             suppress_stderr ? "true" : "false",
                             capture_stderr ? "true" : "false",
                             max_bytes,
                             drain_after_limit ? "true" : "false");

    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
        argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    std::vector<std::string> environment_storage;
    std::vector<char*> environment;
    build_child_environment(
        child_environment, environment_storage, environment);

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        Logger::instance().trace("safe_exec_capture_error",
                                 "cmd={} duration_ms={} reason=pipe_failed errno={}",
                                 command,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count(),
                                 errno);
        return result;
    }

    const pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        Logger::instance().trace("safe_exec_capture_error",
                                 "cmd={} duration_ms={} reason=fork_failed errno={}",
                                 command,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count(),
                                 errno);
        return result;
    }

    if (pid == 0) {
        // Child: write end becomes stdout
        prepare_child_process_group();
        reset_child_signal_mask();
        if (!redirect_child_stdin_to_devnull()) {
            _exit(127);
        }
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        if (capture_stderr) {
            dup2(pipefd[1], STDERR_FILENO);
        } else if (suppress_stderr) {
            const int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        close(pipefd[1]);
        if (!environment.empty()) {
            ::execve(argv[0],
                     const_cast<char* const*>(argv.data()),
                     environment.data());
        } else {
            ::execvp(argv[0], const_cast<char* const*>(argv.data()));
        }
        _exit(127);
    }

    prepare_parent_process_group(pid);
    const SafeExecTimeouts timeouts =
        timeout_override.value_or(safe_exec_timeouts());
    // Parent: read captured output without blocking forever. A service script,
    // nft or a descendant inheriting stdout can otherwise keep this pipe open
    // indefinitely and wedge the daemon request thread.
    close(pipefd[1]);
    const int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }
    char buf[4096];
    bool pipe_open = true;
    bool child_reaped = false;
    bool child_status_valid = false;
    bool timed_out = false;
    int status = 0;
    const auto deadline = started_at + timeouts.timeout;

    auto read_available_output = [&]() {
        if (!pipe_open) return;
        while (true) {
            const ssize_t n = read(pipefd[0], buf, sizeof(buf));
            if (n > 0) {
                const size_t received = static_cast<size_t>(n);
                const size_t remaining =
                    max_bytes == 0 ||
                            result.stdout_output.size() >= max_bytes
                        ? (max_bytes == 0 ? received : 0)
                        : max_bytes - result.stdout_output.size();
                result.stdout_output.append(
                    buf, std::min(received, remaining));
                if (max_bytes > 0 && received > remaining) {
                    result.truncated = true;
                }
                continue;
            }
            if (n == 0) {
                close(pipefd[0]);
                pipe_open = false;
            }
            if (n < 0 && errno == EINTR) continue;
            break;
        }
    };

    auto observe_child = [&]() {
        if (child_reaped) return;
        while (true) {
            const pid_t waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid) {
                child_status_valid = true;
                child_reaped = true;
                return;
            }
            if (waited == 0) return;
            if (waited < 0 && errno == EINTR) continue;
            if (waited < 0) {
                child_reaped = true;
                child_status_valid = false;
                return;
            }
        }
    };

    while (pipe_open || !child_reaped) {
        read_available_output();
        observe_child();
        const bool output_limit_reached =
            result.truncated && !drain_after_limit;
        if (output_limit_reached ||
            std::chrono::steady_clock::now() >= deadline) {
            timed_out = !output_limit_reached;

            // Always terminate the retained group. The leader can already be
            // reaped while an opkg maintainer-script descendant keeps stdout
            // open and continues mutating files. Returning before that group
            // is gone would let a rollback race the mutation we timed out.
            const auto terminated = terminate_process_group_bounded(
                pid,
                child_reaped,
                child_status_valid,
                status,
                timeouts.kill_grace);
            child_reaped = terminated.child_reaped;
            child_status_valid = terminated.child_status_valid;
            status = terminated.child_status;

            // A gone group must also yield EOF. If the descriptor remains
            // open, a process escaped the group (for example via setsid) and
            // recovery safety cannot be established. Drain only for the same
            // bounded grace; never turn cleanup into another indefinite wait.
            const auto drain_deadline =
                std::chrono::steady_clock::now() + timeouts.kill_grace;
            while (pipe_open &&
                   std::chrono::steady_clock::now() < drain_deadline) {
                read_available_output();
                if (!pipe_open) break;
                pollfd descriptor{
                    pipefd[0], static_cast<short>(POLLIN | POLLHUP), 0};
                (void)poll(&descriptor, 1, 20);
            }
            read_available_output();
            result.termination_uncertain =
                !terminated.group_gone || !child_reaped || pipe_open;
            if (pipe_open) close(pipefd[0]);
            pipe_open = false;
            break;
        }
        if (pipe_open || !child_reaped) {
            pollfd descriptor{pipe_open ? pipefd[0] : -1,
                              static_cast<short>(POLLIN | POLLHUP), 0};
            (void)poll(&descriptor, 1, 20);
        }
    }

    if (!timed_out && child_status_valid && WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    }
    if (timed_out) {
        if (should_log_safe_exec_failure(failure_log)) {
            Logger::instance().error(
                "Command '{}' exceeded {} ms and was killed; termination_uncertain={}",
                command,
                timeouts.timeout.count(),
                result.termination_uncertain ? "true" : "false");
        }
        result.timed_out = true;
    }
    Logger::instance().trace("safe_exec_capture_end",
                             "cmd={} exit_code={} duration_ms={} bytes={} truncated={} timed_out={} termination_uncertain={}",
                             command,
                             result.exit_code,
                             std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - started_at).count(),
                             result.stdout_output.size(),
                             result.truncated ? "true" : "false",
                             result.timed_out ? "true" : "false",
                             result.termination_uncertain ? "true" : "false");
    return result;
}

} // namespace keen_pbr3
