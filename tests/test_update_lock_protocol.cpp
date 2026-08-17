#include <doctest/doctest.h>

#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH
#define KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH \
    "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/update-lock.sh"
#endif

#ifndef KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH
#define KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH \
    "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh"
#endif

namespace {

namespace fs = std::filesystem;

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() /
             "keen-pbr-update-lock-protocol-XXXXXX")
                .string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        if (created == nullptr) {
            throw std::system_error(
                errno, std::generic_category(), "mkdtemp");
        }
        path = created;
    }

    ~TempDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }

    TempDirectory(const TempDirectory&) = delete;
    TempDirectory& operator=(const TempDirectory&) = delete;

    fs::path path;
};

class PausedProcess {
public:
    PausedProcess() {
        pid_ = ::fork();
        if (pid_ < 0) {
            throw std::system_error(
                errno, std::generic_category(), "fork");
        }
        if (pid_ == 0) {
            ::signal(SIGTERM, SIG_DFL);
            for (;;) {
                ::pause();
            }
        }
    }

    ~PausedProcess() {
        if (pid_ <= 1) return;
        (void)::kill(pid_, SIGTERM);
        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
        }
    }

    PausedProcess(const PausedProcess&) = delete;
    PausedProcess& operator=(const PausedProcess&) = delete;

    pid_t pid() const noexcept {
        return pid_;
    }

private:
    pid_t pid_{-1};
};

struct CommandResult {
    int exit_code{-1};
    std::string output;
};

class RunningCommand {
public:
    RunningCommand(const fs::path& root,
                   const std::vector<std::string>& arguments,
                   const std::vector<std::pair<std::string, std::string>>&
                       environment = {}) {
        const auto metadata =
            root / "opt/var/lib/keen-pbr/rescue/portable-stat.sh";
        fs::create_directories(metadata.parent_path());
        if (::chmod(metadata.parent_path().c_str(), 0700) != 0) {
            throw std::system_error(
                errno, std::generic_category(), "chmod rescue directory");
        }
        fs::copy_file(
            KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH,
            metadata,
            fs::copy_options::overwrite_existing);
        if (::chmod(metadata.c_str(), 0700) != 0) {
            throw std::system_error(
                errno, std::generic_category(), "chmod");
        }
        int output_pipe[2] = {-1, -1};
        if (::pipe(output_pipe) != 0) {
            throw std::system_error(
                errno, std::generic_category(), "pipe");
        }
        pid_ = ::fork();
        if (pid_ < 0) {
            const int error = errno;
            ::close(output_pipe[0]);
            ::close(output_pipe[1]);
            throw std::system_error(
                error, std::generic_category(), "fork");
        }
        if (pid_ == 0) {
            ::close(output_pipe[0]);
            if (::dup2(output_pipe[1], STDOUT_FILENO) < 0) {
                _exit(126);
            }
            ::close(output_pipe[1]);
            const auto root_text = root.string();
            (void)::setenv(
                "KEEN_PBR_RESCUE_ROOT", root_text.c_str(), 1);
            (void)::setenv("PATH", "/usr/bin:/bin", 1);
            for (const auto& [name, value] : environment) {
                (void)::setenv(name.c_str(), value.c_str(), 1);
            }

            std::vector<std::string> storage;
            storage.reserve(arguments.size() + 2);
            storage.emplace_back("sh");
            storage.emplace_back(KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH);
            storage.insert(
                storage.end(), arguments.begin(), arguments.end());
            std::vector<char*> argv;
            argv.reserve(storage.size() + 1);
            for (auto& item : storage) argv.push_back(item.data());
            argv.push_back(nullptr);
            ::execv("/bin/sh", argv.data());
            _exit(127);
        }
        ::close(output_pipe[1]);
        output_ = output_pipe[0];
    }

    ~RunningCommand() {
        if (pid_ <= 1) return;
        (void)::kill(pid_, SIGKILL);
        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
        }
        ::close(output_);
    }

    RunningCommand(const RunningCommand&) = delete;
    RunningCommand& operator=(const RunningCommand&) = delete;

    CommandResult wait() {
        REQUIRE(pid_ > 1);
        std::string output;
        char buffer[256];
        for (;;) {
            const ssize_t count = ::read(output_, buffer, sizeof(buffer));
            if (count > 0) {
                output.append(buffer, static_cast<std::size_t>(count));
                continue;
            }
            if (count < 0 && errno == EINTR) continue;
            break;
        }
        ::close(output_);
        output_ = -1;

        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
        }
        pid_ = -1;
        CommandResult result;
        result.output = std::move(output);
        if (WIFEXITED(status)) {
            result.exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            result.exit_code = 128 + WTERMSIG(status);
        }
        return result;
    }

private:
    pid_t pid_{-1};
    int output_{-1};
};

CommandResult run_command(
    const fs::path& root,
    const std::vector<std::string>& arguments,
    const std::vector<std::pair<std::string, std::string>>&
        environment = {}) {
    RunningCommand command(root, arguments, environment);
    return command.wait();
}

void write_file(const fs::path& path,
                const std::string& contents,
                mode_t mode = 0600) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << contents;
    output.close();
    REQUIRE(output);
    REQUIRE(::chmod(path.c_str(), mode) == 0);
}

std::string process_start_time(pid_t pid) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/stat");
    REQUIRE(input);
    std::string line;
    std::getline(input, line);
    const auto close = line.rfind(") ");
    REQUIRE(close != std::string::npos);
    std::istringstream tail(line.substr(close + 2));
    std::string field;
    for (int index = 1; index <= 20; ++index) {
        const bool extracted =
            static_cast<bool>(tail >> field);
        REQUIRE(extracted);
    }
    return field;
}

bool wait_for_zombie(pid_t pid) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds{2};
    do {
        std::ifstream input(
            "/proc/" + std::to_string(pid) + "/stat");
        std::string line;
        if (input && std::getline(input, line)) {
            const auto close = line.rfind(") ");
            if (close != std::string::npos &&
                close + 2 < line.size() &&
                line[close + 2] == 'Z') {
                return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
}

bool wait_for_path(const fs::path& path) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds{3};
    do {
        if (fs::exists(path)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
}

std::string strip_newline(std::string value) {
    if (!value.empty() && value.back() == '\n') value.pop_back();
    return value;
}

} // namespace

TEST_CASE("provisional publication cannot be reaped while publisher is live") {
    TempDirectory temporary;
    PausedProcess owner;
    const auto lock =
        temporary.path / "opt/var/run/keen-pbr-update.lock";
    const auto marker =
        temporary.path /
        "opt/var/run/keen-pbr-update.lock.test-publish-paused";

    RunningCommand publisher(
        temporary.path,
        {"acquire",
         std::to_string(static_cast<long>(owner.pid())),
         "config-save"},
        {{"KEEN_PBR_UPDATE_LOCK_TEST_PAUSE_AFTER_PROVISIONAL", "1"}});
    REQUIRE(wait_for_path(marker));
    CHECK(fs::exists(lock / "provisional"));
    CHECK_FALSE(fs::exists(lock / "ready"));

    PausedProcess contender;
    const auto contention = run_command(
        temporary.path,
        {"acquire",
         std::to_string(static_cast<long>(contender.pid())),
         "backup-restore"});
    CHECK(contention.exit_code == 75);
    CHECK(fs::exists(lock / "provisional"));

    REQUIRE(fs::remove(marker));
    const auto published = publisher.wait();
    REQUIRE(published.exit_code == 0);
    const auto token = strip_newline(published.output);
    REQUIRE_FALSE(token.empty());
    CHECK_FALSE(fs::exists(lock / "provisional"));
    CHECK(run_command(
              temporary.path,
              {"release",
               std::to_string(static_cast<long>(owner.pid())),
               token})
              .exit_code == 0);
}

TEST_CASE("unsafe lock metadata is rejected without deleting the lock") {
    TempDirectory temporary;
    PausedProcess owner;
    const auto owner_text =
        std::to_string(static_cast<long>(owner.pid()));
    const auto acquired =
        run_command(temporary.path, {"acquire", owner_text, "config-save"});
    REQUIRE(acquired.exit_code == 0);
    const auto token = strip_newline(acquired.output);
    const auto lock =
        temporary.path / "opt/var/run/keen-pbr-update.lock";

    REQUIRE(::chmod((lock / "owner").c_str(), 0666) == 0);
    CHECK(run_command(
              temporary.path, {"held", owner_text, token})
              .exit_code == 1);
    PausedProcess contender;
    CHECK(run_command(
              temporary.path,
              {"acquire",
               std::to_string(static_cast<long>(contender.pid())),
               "backup-read"})
              .exit_code == 75);
    CHECK(fs::exists(lock));

    REQUIRE(::chmod((lock / "owner").c_str(), 0600) == 0);
    write_file(lock / "owner",
               owner_text + " " + process_start_time(owner.pid()) + " " +
                   token + "\ntrailing\n");
    CHECK(run_command(
              temporary.path, {"held", owner_text, token})
              .exit_code == 1);

    write_file(lock / "owner",
               owner_text + " " + process_start_time(owner.pid()) + " " +
                   token + "\n");
    REQUIRE(::chmod((lock / "ready").c_str(), 0644) == 0);
    CHECK(run_command(
              temporary.path, {"held", owner_text, token})
              .exit_code == 1);
    REQUIRE(::chmod((lock / "ready").c_str(), 0600) == 0);
    write_file(lock / "ready", "not-ready\n");
    CHECK(run_command(
              temporary.path, {"held", owner_text, token})
              .exit_code == 1);
    write_file(lock / "ready", "ready\n");
    REQUIRE(fs::remove(lock / "token"));
    const auto outside_token = temporary.path / "outside-token";
    write_file(outside_token, token + "\n");
    REQUIRE(::symlink(
                outside_token.c_str(), (lock / "token").c_str()) == 0);
    CHECK(run_command(
              temporary.path, {"held", owner_text, token})
              .exit_code == 1);
    REQUIRE(fs::remove(lock / "token"));
    write_file(lock / "token", token + "\n");

    REQUIRE(fs::remove(lock / "ready"));
    const auto outside = temporary.path / "outside-ready";
    write_file(outside, "ready\n");
    REQUIRE(::symlink(outside.c_str(), (lock / "ready").c_str()) == 0);
    CHECK(run_command(
              temporary.path, {"held", owner_text, token})
              .exit_code == 1);
    CHECK(fs::exists(lock));

    std::string oversized_token(193, 'a');
    CHECK(run_command(
              temporary.path,
              {"acquire", owner_text, "config-save", oversized_token})
              .exit_code == 2);
}

TEST_CASE("zombie lock owner is stale and can be recovered") {
    TempDirectory temporary;
    const pid_t zombie = ::fork();
    REQUIRE(zombie >= 0);
    if (zombie == 0) _exit(0);

    const auto zombie_start = process_start_time(zombie);
    REQUIRE(wait_for_zombie(zombie));
    const auto lock =
        temporary.path / "opt/var/run/keen-pbr-update.lock";
    fs::create_directories(lock);
    REQUIRE(::chmod(lock.c_str(), 0700) == 0);
    const std::string stale_token =
        "legacy-update." + std::to_string(static_cast<long>(zombie)) +
        ".stale";
    write_file(lock / "pid",
               std::to_string(static_cast<long>(zombie)) + "\n");
    write_file(lock / "start", zombie_start + "\n");
    write_file(lock / "token", stale_token + "\n");
    write_file(lock / "ready", "ready\n");

    PausedProcess contender;
    const auto contender_text =
        std::to_string(static_cast<long>(contender.pid()));
    const auto acquired = run_command(
        temporary.path, {"acquire", contender_text, "config-save"});
    REQUIRE(acquired.exit_code == 0);
    const auto token = strip_newline(acquired.output);
    CHECK(run_command(
              temporary.path, {"release", contender_text, token})
              .exit_code == 0);

    int status = 0;
    REQUIRE(::waitpid(zombie, &status, 0) == zombie);
    CHECK(WIFEXITED(status));
}

TEST_CASE("sync-generation is owner checked and reports canonical result") {
    TempDirectory temporary;
    PausedProcess owner;
    const auto owner_text =
        std::to_string(static_cast<long>(owner.pid()));
    const auto acquired =
        run_command(temporary.path, {"acquire", owner_text, "config-save"});
    REQUIRE(acquired.exit_code == 0);
    const auto token = strip_newline(acquired.output);

    const auto reserved = run_command(
        temporary.path, {"reserve", owner_text, token, "0"});
    REQUIRE(reserved.exit_code == 0);
    CHECK(reserved.output == "1\n");
    const auto synchronized = run_command(
        temporary.path,
        {"sync-generation", owner_text, token, "1"});
    CHECK(synchronized.exit_code == 0);
    CHECK(synchronized.output == "1\n");

    CHECK(run_command(
              temporary.path,
              {"sync-generation", owner_text, token, "0"})
              .exit_code == 73);
    CHECK(run_command(
              temporary.path,
              {"sync-generation", owner_text, token + "x", "1"})
              .exit_code == 1);
    CHECK(run_command(
              temporary.path,
              {"sync-generation", owner_text, token, "01"})
              .exit_code == 2);
    CHECK(run_command(
              temporary.path,
              {"sync-generation", owner_text, token, "1"},
              {{"KEEN_PBR_UPDATE_LOCK_TEST_FAIL_SYNC_GENERATION", "1"}})
              .exit_code == 74);

    CHECK(run_command(
              temporary.path, {"release", owner_text, token})
              .exit_code == 0);
}

TEST_CASE("only an uninstall owner can atomically release and remove rescue helpers") {
    TempDirectory temporary;
    PausedProcess owner;
    const auto owner_text =
        std::to_string(static_cast<long>(owner.pid()));
    const auto rescue =
        temporary.path / "opt/var/lib/keen-pbr/rescue";
    const auto guard =
        temporary.path / "opt/etc/init.d/S00keen-pbr-rescue";
    fs::create_directories(guard.parent_path());
    write_file(guard, "guard\n");
    write_file(rescue / "rescue-update.sh", "rescue\n");
    write_file(rescue / "update-lock.sh", "lock\n");

    const auto ordinary =
        run_command(temporary.path, {"acquire", owner_text, "config-save"});
    REQUIRE(ordinary.exit_code == 0);
    const auto ordinary_token = strip_newline(ordinary.output);
    CHECK(run_command(
              temporary.path,
              {"release-and-clean", owner_text, ordinary_token})
              .exit_code == 1);
    CHECK(fs::exists(guard));
    CHECK(fs::exists(rescue / "update-lock.sh"));
    REQUIRE(run_command(
                temporary.path,
                {"release", owner_text, ordinary_token})
                .exit_code == 0);

    const auto uninstall =
        run_command(temporary.path, {"acquire", owner_text, "uninstall"});
    REQUIRE(uninstall.exit_code == 0);
    const auto uninstall_token = strip_newline(uninstall.output);
    REQUIRE(run_command(
                temporary.path,
                {"release-and-clean", owner_text, uninstall_token})
                .exit_code == 0);
    CHECK_FALSE(fs::exists(
        temporary.path / "opt/var/run/keen-pbr-update.lock"));
    CHECK_FALSE(fs::exists(guard));
    CHECK_FALSE(fs::exists(rescue / "rescue-update.sh"));
    CHECK_FALSE(fs::exists(rescue / "update-lock.sh"));
    CHECK_FALSE(fs::exists(rescue / "portable-stat.sh"));
}
