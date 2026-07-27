#include "../src/util/safe_exec.hpp"
#include "../src/util/last_command_failure.hpp"
#include "../src/util/ipv6_support.hpp"
#include "../src/firewall/iptables.hpp"

#include <doctest/doctest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {

namespace {

struct SignalMaskGuard {
    sigset_t saved_mask{};
    bool valid{false};

    SignalMaskGuard() {
        valid = (sigprocmask(SIG_SETMASK, nullptr, &saved_mask) == 0);
    }

    ~SignalMaskGuard() {
        if (valid) {
            sigprocmask(SIG_SETMASK, &saved_mask, nullptr);
        }
    }
};

struct StdinGuard {
    int saved_stdin{dup(STDIN_FILENO)};

    ~StdinGuard() {
        if (saved_stdin >= 0) {
            dup2(saved_stdin, STDIN_FILENO);
            close(saved_stdin);
        }
    }
};

class EnvironmentGuard {
public:
    explicit EnvironmentGuard(std::string name)
        : name_(std::move(name)) {
        if (const char* value = std::getenv(name_.c_str())) {
            previous_value_ = value;
        }
    }

    ~EnvironmentGuard() {
        if (previous_value_) {
            setenv(name_.c_str(), previous_value_->c_str(), 1);
        } else {
            unsetenv(name_.c_str());
        }
    }

    void set(const std::string& value) {
        if (setenv(name_.c_str(), value.c_str(), 1) != 0) {
            throw std::runtime_error("setenv failed");
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_value_;
};

class TempDir {
public:
    TempDir() {
        char path_template[] = "/tmp/keen-pbr-safe-exec-XXXXXX";
        const char* created = mkdtemp(path_template);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = created;
    }

    ~TempDir() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

class SafeExecTimeoutGuard {
public:
    SafeExecTimeoutGuard() : previous_(safe_exec_timeouts()) {}

    ~SafeExecTimeoutGuard() {
        set_safe_exec_timeouts(previous_.timeout, previous_.kill_grace);
    }

private:
    SafeExecTimeouts previous_;
};

class LoggerSinkGuard {
public:
    ~LoggerSinkGuard() {
        Logger::instance().clear_sink();
    }
};

class LastCommandFailurePathGuard {
public:
    explicit LastCommandFailurePathGuard(
        const std::filesystem::path& path) {
        set_last_command_failure_path_for_testing(path.string());
    }

    ~LastCommandFailurePathGuard() {
        set_last_command_failure_post_commit_failure_for_testing(false);
        set_last_command_failure_path_for_testing(std::nullopt);
    }
};

void write_executable(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path);
    output << content;
    output.close();
    if (!output || chmod(path.c_str(), 0700) != 0) {
        throw std::runtime_error("failed to create executable");
    }
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

} // namespace

TEST_CASE("safe_exec_capture: child process does not inherit blocked signal mask") {
    SignalMaskGuard guard;
    REQUIRE(guard.valid);

    sigset_t blocked_mask;
    sigemptyset(&blocked_mask);
    sigaddset(&blocked_mask, SIGTERM);
    sigaddset(&blocked_mask, SIGINT);
    sigaddset(&blocked_mask, SIGHUP);
    REQUIRE(sigprocmask(SIG_BLOCK, &blocked_mask, nullptr) == 0);

    const auto result = safe_exec_capture(
        {"/bin/sh", "-c", "awk '/^SigBlk:/{print $2}' /proc/self/status"},
        true);

    CHECK(result.exit_code == 0);
    CHECK(result.stdout_output == "0000000000000000\n");
}

TEST_CASE("safe_exec_capture: output cap terminates a noisy child") {
    const auto started_at = std::chrono::steady_clock::now();
    const auto result = safe_exec_capture(
        {"/bin/sh", "-c", "while :; do printf 1234567890; done"},
        true,
        1024);

    CHECK(result.truncated);
    CHECK(result.stdout_output.size() == 1024);
    CHECK(std::chrono::steady_clock::now() - started_at < std::chrono::seconds(5));
}

TEST_CASE("safe_exec_capture: bounded diagnostics can drain a finite command") {
    const auto result = safe_exec_capture(
        {"/bin/sh", "-c", "head -c 4096 /dev/zero"},
        true,
        32,
        false,
        true);

    CHECK(result.exit_code == 0);
    CHECK(result.truncated);
    CHECK(result.stdout_output.size() == 32);
}

TEST_CASE("safe_exec_capture: stderr is merged only when explicitly requested") {
    const auto stdout_only = safe_exec_capture(
        {"/bin/sh", "-c", "printf out; printf err >&2"},
        /*suppress_stderr=*/true,
        1024);
    const auto combined = safe_exec_capture(
        {"/bin/sh", "-c", "printf out; printf err >&2"},
        /*suppress_stderr=*/false,
        1024,
        /*capture_stderr=*/true);

    CHECK(stdout_only.exit_code == 0);
    CHECK(stdout_only.stdout_output == "out");
    CHECK(combined.exit_code == 0);
    CHECK(combined.stdout_output.find("out") != std::string::npos);
    CHECK(combined.stdout_output.find("err") != std::string::npos);
}

TEST_CASE("safe_exec: child process receives devnull stdin") {
    StdinGuard stdin_guard;
    REQUIRE(stdin_guard.saved_stdin >= 0);

    int pipe_fds[2];
    REQUIRE(pipe(pipe_fds) == 0);
    REQUIRE(dup2(pipe_fds[0], STDIN_FILENO) >= 0);
    close(pipe_fds[0]);

    const int exit_code = safe_exec({
        "/bin/sh",
        "-c",
        "[ \"$(readlink /proc/self/fd/0)\" = /dev/null ]",
    });
    close(pipe_fds[1]);

    CHECK(exit_code == 0);
}

TEST_CASE(
    "safe_exec child environment override does not mutate daemon environment") {
    constexpr const char* variable =
        "KEEN_PBR_SAFE_EXEC_CHILD_ENV_TEST";
    const char* before = std::getenv(variable);
    const std::optional<std::string> original =
        before == nullptr
            ? std::nullopt
            : std::optional<std::string>(before);

    const int exit_code = safe_exec_with_environment(
        {
            "/bin/sh",
            "-c",
            "test \"$KEEN_PBR_SAFE_EXEC_CHILD_ENV_TEST\" "
            "= child-only",
        },
        {{variable, "child-only"}},
        true);

    CHECK(exit_code == 0);
    const char* after = std::getenv(variable);
    if (original.has_value()) {
        REQUIRE(after != nullptr);
        CHECK(std::string(after) == *original);
    } else {
        CHECK(after == nullptr);
    }
    CHECK(
        safe_exec_with_environment(
            {"sh", "-c", "exit 0"},
            {{variable, "must-not-run"}},
            true) == -1);
}

TEST_CASE("safe_exec: timeout escalates to SIGKILL") {
    SafeExecTimeoutGuard guard;
    set_safe_exec_timeouts(std::chrono::milliseconds{100},
                           std::chrono::milliseconds{50});

    const auto started = std::chrono::steady_clock::now();
    const int exit_code = safe_exec({
        "/bin/sh", "-c", "trap '' TERM; while :; do sleep 1; done",
    }, true);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    CHECK(exit_code == -1);
    CHECK(elapsed < std::chrono::seconds{2});
}

TEST_CASE("safe_exec_pipe_stdin: unread input is bounded by deadline") {
    SafeExecTimeoutGuard guard;
    LoggerSinkGuard logger_sink_guard;
    TempDir temp_dir;
    LastCommandFailurePathGuard failure_path(
        temp_dir.path() / "last-command-failure.log");
    std::string log;
    Logger::instance().set_sink([&log](const std::string& line) {
        log += line;
        log += '\n';
    });
    set_safe_exec_timeouts(std::chrono::milliseconds{100},
                           std::chrono::milliseconds{50});

    const std::string input(2U * 1024U * 1024U, 'x');
    const auto started = std::chrono::steady_clock::now();
    const int exit_code = safe_exec_pipe_stdin(
        {"/bin/sh", "-c", "trap '' TERM; sleep 10"}, input);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    CHECK(exit_code == -1);
    CHECK(elapsed < std::chrono::seconds{2});
    CHECK(log.size() < 16U * 1024U);
    CHECK(log.find("input_bytes=2097152") != std::string::npos);
    CHECK(log.find("truncated=true") != std::string::npos);
    const auto failure = read_last_command_failure();
    REQUIRE(failure.has_value());
    CHECK(failure->find("reason: timeout") != std::string::npos);
    CHECK(failure->find("stdin_bytes: 2097152") != std::string::npos);
}

TEST_CASE("safe_exec_pipe_stdin: failed command logs arguments and input") {
    LoggerSinkGuard logger_sink_guard;
    TempDir temp_dir;
    const auto failure_path =
        temp_dir.path() / "last-command-failure.log";
    LastCommandFailurePathGuard failure_path_guard(failure_path);
    std::string log;
    Logger::instance().set_sink([&log](const std::string& line) {
        log += line;
        log += '\n';
    });

    const std::string input = "*mangle\nCOMMIT\n";
    std::string stderr_output;
    const int exit_code = safe_exec_pipe_stdin(
        {"/bin/sh", "-c",
         "cat >/dev/null; printf 'line 7 failed\\n' >&2; exit 42"},
        input,
        &stderr_output);

    CHECK(exit_code == 42);
    CHECK(log.find("cmd=/bin/sh -c cat >/dev/null; printf 'line 7 failed") !=
          std::string::npos);
    CHECK(log.find(input) != std::string::npos);
    CHECK(log.find("truncated=false") != std::string::npos);
    const auto failure = read_last_command_failure();
    REQUIRE(failure.has_value());
    CHECK(failure->find("exit_code: 42") != std::string::npos);
    CHECK(failure->find(input) != std::string::npos);
    CHECK(failure->find("line 7 failed") != std::string::npos);
}

TEST_CASE("safe_exec_pipe_stdin: capability probes can suppress expected failures") {
    LoggerSinkGuard logger_sink_guard;
    TempDir temp_dir;
    const auto failure_path =
        temp_dir.path() / "last-command-failure.log";
    {
        std::ofstream sentinel(failure_path, std::ios::binary);
        sentinel << "unchanged";
    }
    LastCommandFailurePathGuard failure_path_guard(failure_path);
    std::string log;
    Logger::instance().set_sink([&log](const std::string& line) {
        log += line;
        log += '\n';
    });

    std::string stderr_output;
    const int exit_code = safe_exec_pipe_stdin(
        {"/bin/sh", "-c", "cat >/dev/null; printf 'unsupported\\n' >&2; exit 1"},
        "{}",
        &stderr_output,
        SafeExecFailureLog::Suppressed);

    CHECK(exit_code == 1);
    CHECK(stderr_output == "unsupported");
    CHECK(log.find("safe_exec_pipe_failed") == std::string::npos);
    CHECK(log.find("safe_exec_pipe_input") == std::string::npos);
    CHECK(read_file(failure_path) == "unchanged");
}

TEST_CASE("safe_exec_pipe_stdin: diagnostic-only failures do not notify") {
    LoggerSinkGuard logger_sink_guard;
    TempDir temp_dir;
    const auto failure_path =
        temp_dir.path() / "last-command-failure.log";
    LastCommandFailurePathGuard failure_path_guard(failure_path);
    std::string log;
    Logger::instance().set_sink([&log](const std::string& line) {
        log += line;
        log += '\n';
    });

    const std::string input = "*mangle\nCOMMIT\n";
    std::string stderr_output;
    const int exit_code = safe_exec_pipe_stdin(
        {"/bin/sh", "-c",
         "cat >/dev/null; printf 'line 2 failed\\n' >&2; exit 1"},
        input,
        &stderr_output,
        SafeExecFailureLog::DiagnosticOnly);

    CHECK(exit_code == 1);
    CHECK(stderr_output == "line 2 failed");
    CHECK(log.find("safe_exec_pipe_failed") == std::string::npos);
    CHECK(log.find("safe_exec_pipe_input") == std::string::npos);
    const auto failure = read_last_command_failure();
    REQUIRE(failure.has_value());
    CHECK(failure->find("exit_code: 1") != std::string::npos);
    CHECK(failure->find(input) != std::string::npos);
    CHECK(failure->find("line 2 failed") != std::string::npos);
}

TEST_CASE("safe_exec_pipe_stdin: records abnormal signal termination") {
    TempDir temp_dir;
    LastCommandFailurePathGuard failure_path(
        temp_dir.path() / "last-command-failure.log");

    const int exit_code = safe_exec_pipe_stdin(
        {"/bin/sh", "-c", "kill -TERM $$"}, {});

    CHECK(exit_code == -1);
    const auto failure = read_last_command_failure();
    REQUIRE(failure.has_value());
    CHECK(failure->find("reason: abnormal_exit signal=15") !=
          std::string::npos);
}

TEST_CASE("safe_exec_capture: ignored SIGTERM cannot hang capture") {
    SafeExecTimeoutGuard guard;
    set_safe_exec_timeouts(std::chrono::milliseconds{100},
                           std::chrono::milliseconds{50});

    const auto started = std::chrono::steady_clock::now();
    const auto result = safe_exec_capture(
        {"/bin/sh", "-c", "trap '' TERM; while :; do sleep 1; done"}, true);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    CHECK(result.exit_code == -1);
    CHECK(result.timed_out);
    CHECK(elapsed < std::chrono::seconds{2});
}

TEST_CASE("safe_exec_capture: suppressed timeout stays out of user log") {
    SafeExecTimeoutGuard timeout_guard;
    LoggerSinkGuard logger_sink_guard;
    set_safe_exec_timeouts(std::chrono::milliseconds{50},
                           std::chrono::milliseconds{25});
    std::string log;
    Logger::instance().set_sink([&log](const std::string& line) {
        log += line;
        log += '\n';
    });

    const auto result = safe_exec_capture(
        {"/bin/sh", "-c", "sleep 2"},
        /*suppress_stderr=*/true,
        /*max_bytes=*/1024,
        /*capture_stderr=*/false,
        /*drain_after_limit=*/false,
        SafeExecFailureLog::Suppressed);

    CHECK(result.exit_code == -1);
    CHECK(result.timed_out);
    CHECK(log.find("exceeded") == std::string::npos);
}

TEST_CASE("last command failure: writes one private atomic snapshot") {
    TempDir temp_dir;
    const auto path = temp_dir.path() / "last-command-failure.log";
    LastCommandFailurePathGuard failure_path_guard(path);
    const std::vector<std::string> first_command{
        "/usr/sbin/iptables-restore", "-w", "10"};
    const std::vector<std::string> second_command{
        "/usr/sbin/ip", "route", "replace", "default"};
    {
        std::ofstream output(path, std::ios::binary);
        output << "pre-existing diagnostic";
    }
    REQUIRE(::chmod(path.c_str(), 0644) == 0);

    REQUIRE(write_last_command_failure(
        {first_command, 1, "*mangle\nCOMMIT\n", "line 3 failed\n", {}}));
    struct stat first_metadata {};
    REQUIRE(::stat(path.c_str(), &first_metadata) == 0);
    CHECK((first_metadata.st_mode & 0777) == 0600);
    CHECK(first_metadata.st_uid == ::geteuid());
    CHECK(first_metadata.st_gid == ::getegid());

    std::ifstream old_snapshot(path, std::ios::binary);
    REQUIRE(old_snapshot);

    REQUIRE(write_last_command_failure(
        {second_command, 2, {}, "RTNETLINK answers: File exists\n", "retry"}));

    struct stat metadata {};
    REQUIRE(::stat(path.c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0600);
    CHECK(metadata.st_uid == ::geteuid());
    CHECK(metadata.st_gid == ::getegid());

    const std::string current = read_file(path);
    CHECK(current.find("command: /usr/sbin/ip route replace default") !=
          std::string::npos);
    CHECK(current.find("exit_code: 2") != std::string::npos);
    CHECK(current.find("reason: retry") != std::string::npos);
    CHECK(current.find("iptables-restore") == std::string::npos);

    const std::string previous{
        std::istreambuf_iterator<char>(old_snapshot),
        std::istreambuf_iterator<char>()};
    CHECK(previous.find("iptables-restore") != std::string::npos);
    CHECK(previous.find("RTNETLINK") == std::string::npos);

    for (const auto& entry :
         std::filesystem::directory_iterator(temp_dir.path())) {
        CHECK(entry.path().filename() == path.filename());
    }
}

TEST_CASE("last command failure: preserves errno and accepts visible commit") {
    TempDir temp_dir;
    const auto path = temp_dir.path() / "last-command-failure.log";
    LastCommandFailurePathGuard failure_path_guard(path);
    set_last_command_failure_post_commit_failure_for_testing(true);
    const std::vector<std::string> command{"/bin/false"};

    errno = EDOM;
    REQUIRE(write_last_command_failure(
        {command, 1, {}, "failed", "nonzero_exit"}));
    const int errno_after_write = errno;
    CHECK(errno_after_write == EDOM);

    errno = ERANGE;
    const auto record = read_last_command_failure();
    const int errno_after_read = errno;
    REQUIRE(record.has_value());
    CHECK(errno_after_read == ERANGE);
    CHECK(record->find("command: /bin/false") != std::string::npos);
}

TEST_CASE("last command failure: redacts obvious credentials") {
    TempDir temp_dir;
    const auto path = temp_dir.path() / "last-command-failure.log";
    LastCommandFailurePathGuard failure_path_guard(path);
    const std::vector<std::string> command{
        "/usr/bin/curl",
        "--token",
        "command-token-secret",
        "--password=command-password-secret",
        "-H",
        "Authorization: Bearer header-secret",
        "vless://share-uuid-secret@example.net:443",
    };
    const std::string input =
        R"({"password":"json-password-secret","client_secret":"json-client-secret","uuid":"json-uuid-secret"})";
    const std::string response =
        "Set-Cookie: session=response-cookie-secret\n"
        "proxy-authorization: Basic response-auth-secret\n";
    const std::string reason =
        "request https://reason-user:reason-password@example.net failed";

    REQUIRE(write_last_command_failure(
        {command, 22, input, response, reason}));
    const std::string record = read_file(path);

    CHECK(record.find("[REDACTED]") != std::string::npos);
    CHECK(record.find("example.net") != std::string::npos);
    CHECK(record.find("command-token-secret") == std::string::npos);
    CHECK(record.find("command-password-secret") == std::string::npos);
    CHECK(record.find("header-secret") == std::string::npos);
    CHECK(record.find("share-uuid-secret") == std::string::npos);
    CHECK(record.find("json-password-secret") == std::string::npos);
    CHECK(record.find("json-client-secret") == std::string::npos);
    CHECK(record.find("json-uuid-secret") == std::string::npos);
    CHECK(record.find("response-cookie-secret") == std::string::npos);
    CHECK(record.find("response-auth-secret") == std::string::npos);
    CHECK(record.find("reason-user") == std::string::npos);
    CHECK(record.find("reason-password") == std::string::npos);
}

TEST_CASE("last command failure: caps large records at 128 KiB") {
    TempDir temp_dir;
    const auto path = temp_dir.path() / "last-command-failure.log";
    LastCommandFailurePathGuard failure_path_guard(path);
    const std::vector<std::string> command{
        "/usr/sbin/iptables-restore"};
    const std::string input(512U * 1024U, 'i');
    const std::string response(512U * 1024U, 'r');

    REQUIRE(write_last_command_failure(
        {command, 1, input, response, "oversized"}));

    const auto size = std::filesystem::file_size(path);
    CHECK(size <= kLastCommandFailureMaxBytes);
    const std::string record = read_file(path);
    CHECK(record.find("stdin_bytes: 524288") != std::string::npos);
    CHECK(record.find("response_bytes: 524288") != std::string::npos);
    CHECK(record.find("[truncated; original_bytes=524288]") !=
          std::string::npos);
}

TEST_CASE("last command failure: refuses a symbolic-link destination") {
    TempDir temp_dir;
    const auto victim = temp_dir.path() / "victim";
    const auto destination = temp_dir.path() / "last-command-failure.log";
    {
        std::ofstream output(victim, std::ios::binary);
        output << "must-stay-unchanged";
    }
    std::filesystem::create_symlink(victim.filename(), destination);
    LastCommandFailurePathGuard failure_path_guard(destination);
    const std::vector<std::string> command{"/bin/false"};

    CHECK_FALSE(write_last_command_failure(
        {command, 1, {}, {}, "expected failure"}));
    CHECK(std::filesystem::is_symlink(destination));
    CHECK(read_file(victim) == "must-stay-unchanged");
    CHECK_FALSE(read_last_command_failure().has_value());
}

TEST_CASE("last command failure: secure reader rejects oversized files") {
    TempDir temp_dir;
    const auto path = temp_dir.path() / "last-command-failure.log";
    LastCommandFailurePathGuard failure_path_guard(path);
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output << std::string(kLastCommandFailureMaxBytes + 1U, 'x');
    }

    CHECK_FALSE(read_last_command_failure().has_value());
}

TEST_CASE("iptables_ipv6_supported: probes ip6tables-restore test script") {
    TempDir temp_dir;
    const auto restore_args_path = temp_dir.path() / "restore-args";
    const auto restore_stdin_path = temp_dir.path() / "restore-stdin";
    write_executable(
        temp_dir.path() / "ip6tables",
        "#!/bin/sh\n"
        "[ \"$#\" -eq 3 ] && [ \"$1\" = -t ] && [ \"$2\" = mangle ] && [ \"$3\" = -S ]\n");
    write_executable(
        temp_dir.path() / "ip6tables-restore",
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" > \"$KEEN_PBR_TEST_RESTORE_ARGS\"\n"
        "/bin/cat > \"$KEEN_PBR_TEST_RESTORE_STDIN\"\n"
        "[ \"$#\" -eq 1 ] && [ \"$1\" = --test ]\n");

    EnvironmentGuard path_guard("PATH");
    EnvironmentGuard restore_args_guard("KEEN_PBR_TEST_RESTORE_ARGS");
    EnvironmentGuard restore_stdin_guard("KEEN_PBR_TEST_RESTORE_STDIN");
    path_guard.set(temp_dir.path());
    restore_args_guard.set(restore_args_path);
    restore_stdin_guard.set(restore_stdin_path);

    CHECK(iptables_ipv6_supported());
    CHECK(read_file(restore_args_path) == "--test\n");
    CHECK(read_file(restore_stdin_path) == "*mangle\nCOMMIT\n");
}

TEST_CASE("iptables restore wait capability is probed without a rules transaction") {
    TempDir temp_dir;
    const auto probe_args_path = temp_dir.path() / "restore-probe-args";
    write_executable(
        temp_dir.path() / "iptables-restore",
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" > \"$KEEN_PBR_TEST_RESTORE_PROBE_ARGS\"\n"
        "printf 'iptables-restore: invalid option -- w\\n' >&2\n"
        "exit 1\n");

    EnvironmentGuard path_guard("PATH");
    EnvironmentGuard probe_args_guard("KEEN_PBR_TEST_RESTORE_PROBE_ARGS");
    LoggerSinkGuard logger_sink_guard;
    path_guard.set(temp_dir.path());
    probe_args_guard.set(probe_args_path);

    std::string log;
    const auto previous_level = Logger::instance().level();
    Logger::instance().set_level(LogLevel::debug);
    Logger::instance().set_sink([&log](const std::string& line) {
        log += line;
        log += '\n';
    });

    testing::reset_restore_wait_option_probe_for_test();
    CHECK_FALSE(testing::restore_wait_option_supported_for_test(
        "iptables-restore"));
    testing::reset_restore_wait_option_probe_for_test();
    Logger::instance().set_level(previous_level);

    CHECK(read_file(probe_args_path) == "-w 0 --test\n");
    CHECK(log.find("safe_exec_pipe_input") == std::string::npos);
    CHECK(log.find("safe_exec_pipe_failed") == std::string::npos);
    CHECK(log.find("invalid option") == std::string::npos);
}

TEST_CASE("wait_for_child_with_timeout: reaps a child that finishes in time") {
  const pid_t pid = fork();
  REQUIRE(pid >= 0);
  if (pid == 0) {
    _exit(7);
  }

  const auto result = wait_for_child_with_timeout(pid, std::chrono::seconds(5));
  CHECK_FALSE(result.timed_out);
  CHECK(WIFEXITED(result.status));
  CHECK(WEXITSTATUS(result.status) == 7);
}

TEST_CASE("wait_for_child_with_timeout: kills a child that overstays") {
  // This is the boot hang in miniature: iptables-restore blocked on the xtables
  // lock used to keep the daemon waiting forever.
  const pid_t pid = fork();
  REQUIRE(pid >= 0);
  if (pid == 0) {
    // Doctest installs a SIGTERM handler in the parent process. The child is
    // deliberately terminated by the function under test, so restore the
    // normal disposition to avoid reporting that expected termination as a
    // nested doctest crash.
    signal(SIGTERM, SIG_DFL);
    pause();
    _exit(0);
  }

  const auto started_at = std::chrono::steady_clock::now();
  const auto result = wait_for_child_with_timeout(pid, std::chrono::seconds(1));
  const auto elapsed = std::chrono::steady_clock::now() - started_at;

  CHECK(result.timed_out);
  // Killed rather than waited out: well under the child's own lifetime.
  CHECK(elapsed < std::chrono::seconds(5));
  CHECK(waitpid(pid, nullptr, WNOHANG) == -1);
}

} // namespace keen_pbr3
