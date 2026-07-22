#pragma once

#include "../log/logger.hpp"

#include <algorithm>
#include <chrono>
#include <atomic>
#include <cstdint>
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {

struct ExecCaptureResult {
    std::string stdout_output;
    int exit_code{-1};
    bool truncated{false};
    bool timed_out{false};
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

// Execute a command with arguments directly via fork()+execvp(), bypassing
// the shell entirely. This prevents shell injection attacks.
// Returns the process exit code (0-255), or -1 on fork/exec failure.
inline int safe_exec(const std::vector<std::string>& args, bool suppress_output = false) {
    if (args.empty()) return -1;
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
        execvp(argv[0], const_cast<char* const*>(argv.data()));
        _exit(127); // execvp failed
    }

    prepare_parent_process_group(pid);
    const SafeExecTimeouts timeouts = safe_exec_timeouts();
    const ChildWaitResult wait_result = wait_for_child_until(
        pid, started_at + timeouts.timeout, timeouts.kill_grace);
    if (wait_result.timed_out) {
        Logger::instance().error(
            "Command '{}' exceeded {} ms and was killed. On Keenetic this usually "
            "means the firmware is holding the xtables lock; the operation will "
            "be retried.",
            command, timeouts.timeout.count());
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

// Execute a command with arguments, piping input data to its stdin.
// Returns the process exit code (0-255), or -1 on fork/exec/pipe failure.
//
// When stderr_out is given, the child's stderr is captured into it. Without
// this an "exited with status 1" from iptables-restore said nothing at all:
// the tool prints which line it choked on, and that message went to a stderr
// nobody was reading.
inline int safe_exec_pipe_stdin(const std::vector<std::string>& args,
                                const std::string& input,
                                std::string* stderr_out = nullptr) {
    if (args.empty()) return -1;
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
        Logger::instance().trace("safe_exec_pipe_error",
                                 "cmd={} duration_ms={} reason=pipe_failed errno={}",
                                 command,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count(),
                                 errno);
        return -1;
    }

    int errfd[2] = {-1, -1};
    if (stderr_out != nullptr && pipe2(errfd, O_CLOEXEC) == -1) {
        errfd[0] = errfd[1] = -1; // Capture is a nicety; carry on without it.
    }

    const pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        if (errfd[0] != -1) { close(errfd[0]); close(errfd[1]); }
        Logger::instance().trace("safe_exec_pipe_error",
                                 "cmd={} duration_ms={} reason=fork_failed errno={}",
                                 command,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count(),
                                 errno);
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
    const SafeExecTimeouts timeouts = safe_exec_timeouts();
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
    int status = 0;
    bool deadline_exceeded = false;
    constexpr size_t kMaxStderrBytes = 8 * 1024;
    char buffer[512];

    while ((!child_reaped || input_open || error_open) && !deadline_exceeded) {
        if (error_open) {
            while (true) {
                const ssize_t got = read(errfd[0], buffer, sizeof(buffer));
                if (got > 0) {
                    const size_t available = stderr_out->size() < kMaxStderrBytes
                        ? kMaxStderrBytes - stderr_out->size()
                        : 0;
                    stderr_out->append(buffer, std::min(available, static_cast<size_t>(got)));
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
            child_reaped = waited == pid || (waited < 0 && errno != EINTR);
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
        Logger::instance().error(
            "Command '{}' exceeded {} ms and was killed. On Keenetic this usually "
            "means the firmware is holding the xtables lock; the operation will "
            "be retried.",
            command, timeouts.timeout.count());
        return -1;
    }
    status = wait_result.status;
    if (!wait_result.reaped) {
        Logger::instance().trace("safe_exec_pipe_error",
                                 "cmd={} duration_ms={} reason=waitpid_failed errno={}",
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
        Logger::instance().trace("safe_exec_pipe_end",
                                 "cmd={} exit_code={} duration_ms={}",
                                 command,
                                 exit_code,
                                 duration_ms);
        return exit_code;
    }
    Logger::instance().trace("safe_exec_pipe_error",
                             "cmd={} duration_ms={} reason=abnormal_exit",
                             command,
                             duration_ms);
    return -1;
}

// Execute a command with arguments and capture its stdout output.
// Returns stdout, exit status and whether capture exceeded max_bytes.
inline ExecCaptureResult safe_exec_capture(const std::vector<std::string>& args,
                                           bool suppress_stderr = false,
                                           size_t max_bytes = 0) {
    ExecCaptureResult result;
    if (args.empty()) return result;
    const std::string command = safe_exec_command_string(args);
    const auto started_at = std::chrono::steady_clock::now();
    Logger::instance().trace("safe_exec_capture_start",
                             "cmd={} suppress_stderr={} max_bytes={}",
                             command,
                             suppress_stderr ? "true" : "false",
                             max_bytes);

    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
        argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

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
        if (suppress_stderr) {
            const int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        close(pipefd[1]);
        execvp(argv[0], const_cast<char* const*>(argv.data()));
        _exit(127);
    }

    prepare_parent_process_group(pid);
    const SafeExecTimeouts timeouts = safe_exec_timeouts();
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
    while (pipe_open || !child_reaped) {
        if (pipe_open) {
            while (true) {
                const ssize_t n = read(pipefd[0], buf, sizeof(buf));
                if (n > 0) {
                    const size_t received = static_cast<size_t>(n);
                    const size_t remaining = max_bytes == 0 || result.stdout_output.size() >= max_bytes
                        ? (max_bytes == 0 ? received : 0)
                        : max_bytes - result.stdout_output.size();
                    result.stdout_output.append(buf, std::min(received, remaining));
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
        }

        if (!child_reaped) {
            const pid_t waited = waitpid(pid, &status, WNOHANG);
            child_status_valid = waited == pid;
            child_reaped = child_status_valid || waited == -1;
        }
        if (result.truncated || std::chrono::steady_clock::now() >= deadline) {
            timed_out = !result.truncated;
            if (!child_reaped) {
                const auto wait_result = wait_for_child_until(
                    pid, std::chrono::steady_clock::now(), timeouts.kill_grace);
                status = wait_result.status;
                child_reaped = true;
                child_status_valid = status != -1;
            }
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
        Logger::instance().error("Command '{}' exceeded {} ms and was killed",
                                 command,
                                 timeouts.timeout.count());
        result.timed_out = true;
    }
    Logger::instance().trace("safe_exec_capture_end",
                             "cmd={} exit_code={} duration_ms={} bytes={} truncated={}",
                             command,
                             result.exit_code,
                             std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - started_at).count(),
                             result.stdout_output.size(),
                             result.truncated ? "true" : "false");
    return result;
}

} // namespace keen_pbr3
