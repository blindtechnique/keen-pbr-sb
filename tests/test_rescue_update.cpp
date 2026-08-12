#include <doctest/doctest.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef KEEN_PBR_RESCUE_SCRIPT_PATH
#define KEEN_PBR_RESCUE_SCRIPT_PATH \
    "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/rescue-update.sh"
#endif

#ifndef KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH
#define KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH \
    "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/update-lock.sh"
#endif

#ifndef KEEN_PBR_RESCUE_STARTUP_GUARD_PATH
#define KEEN_PBR_RESCUE_STARTUP_GUARD_PATH \
    "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/rescue-startup-guard.sh"
#endif

#ifndef KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH
#define KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH \
    "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh"
#endif

#ifndef KEEN_PBR_TRANSPORT_INIT_PATH
#define KEEN_PBR_TRANSPORT_INIT_PATH \
    "packages/keenetic/keen-pbr/files/opt/etc/init.d/S79transport-manager"
#endif

#ifndef KEEN_PBR_INSTALL_SCRIPT_PATH
#define KEEN_PBR_INSTALL_SCRIPT_PATH "install.sh"
#endif

#ifndef KEEN_PBR_POSTRM_SCRIPT_PATH
#define KEEN_PBR_POSTRM_SCRIPT_PATH \
    "packages/keenetic/keen-pbr/files/postrm"
#endif

#ifndef KEEN_PBR_POSTINST_SCRIPT_PATH
#define KEEN_PBR_POSTINST_SCRIPT_PATH \
    "packages/keenetic/keen-pbr/files/postinst"
#endif

namespace {

namespace fs = std::filesystem;

std::string read_file(const fs::path& path);
void install_portable_stat(const fs::path& root);

TEST_CASE(
    "transport init consumes persistent transaction bypass before daemon start") {
    const auto script =
        read_file(KEEN_PBR_TRANSPORT_INIT_PATH);
    const auto guard =
        script.find("run_recovery_guard start");
    const auto unset_flag =
        script.find(
            "unset KEEN_PBR_PERSISTENT_TRANSACTION",
            guard);
    const auto runtime =
        script.find(". /opt/etc/init.d/rc.func");

    REQUIRE(guard != std::string::npos);
    REQUIRE(unset_flag != std::string::npos);
    REQUIRE(runtime != std::string::npos);
    CHECK(guard < unset_flag);
    CHECK(unset_flag < runtime);
}

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-rescue-XXXXXX").string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        if (created == nullptr)
            throw std::system_error(errno, std::generic_category(), "mkdtemp");
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
        if (pid_ < 0)
            throw std::system_error(errno, std::generic_category(), "fork");
        if (pid_ == 0) {
            ::signal(SIGTERM, SIG_DFL);
            ::signal(SIGINT, SIG_DFL);
            for (;;) ::pause();
        }
    }

    ~PausedProcess() {
        if (pid_ <= 1) return;
        ::kill(pid_, SIGTERM);
        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
        }
    }

    PausedProcess(const PausedProcess&) = delete;
    PausedProcess& operator=(const PausedProcess&) = delete;

    pid_t pid() const {
        return pid_;
    }

private:
    pid_t pid_ = -1;
};

class LockGuardianProcess {
public:
    LockGuardianProcess(const fs::path& root,
                        const std::string& operation) {
        install_portable_stat(root);
        int control[2] = {-1, -1};
        int status[2] = {-1, -1};
        if (::pipe(control) != 0 || ::pipe(status) != 0) {
            if (control[0] >= 0) ::close(control[0]);
            if (control[1] >= 0) ::close(control[1]);
            if (status[0] >= 0) ::close(status[0]);
            if (status[1] >= 0) ::close(status[1]);
            throw std::system_error(
                errno, std::generic_category(), "pipe");
        }

        pid_ = ::fork();
        if (pid_ < 0) {
            const int error = errno;
            ::close(control[0]);
            ::close(control[1]);
            ::close(status[0]);
            ::close(status[1]);
            throw std::system_error(
                error, std::generic_category(), "fork");
        }
        if (pid_ == 0) {
            ::close(control[1]);
            ::close(status[0]);
            if (::dup2(control[0], STDIN_FILENO) < 0 ||
                ::dup2(status[1], STDOUT_FILENO) < 0) {
                _exit(126);
            }
            ::close(control[0]);
            ::close(status[1]);
            const auto root_string = root.string();
            ::setenv(
                "KEEN_PBR_RESCUE_ROOT", root_string.c_str(), 1);
            ::setenv("PATH", "/usr/bin:/bin", 1);
            std::string shell{"/bin/sh"};
            std::string script{
                KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH};
            std::string command{"guard"};
            std::string mutable_operation{operation};
            char* argv[] = {
                shell.data(),
                script.data(),
                command.data(),
                mutable_operation.data(),
                nullptr,
            };
            ::execv(argv[0], argv);
            _exit(127);
        }

        ::close(control[0]);
        ::close(status[1]);
        control_ = control[1];
        const int control_flags = ::fcntl(control_, F_GETFD);
        if (control_flags < 0 ||
            ::fcntl(
                control_,
                F_SETFD,
                control_flags | FD_CLOEXEC) < 0) {
            const int error = errno;
            ::close(status[0]);
            terminate_noexcept();
            throw std::system_error(
                error, std::generic_category(), "guardian control");
        }

        pollfd descriptor{
            status[0],
            static_cast<short>(POLLIN | POLLHUP),
            0,
        };
        const int ready = ::poll(&descriptor, 1, 3000);
        if (ready <= 0) {
            const int error = ready < 0 ? errno : ETIMEDOUT;
            ::close(status[0]);
            terminate_noexcept();
            throw std::system_error(
                error, std::generic_category(), "guardian ready");
        }

        std::string line;
        char byte = '\0';
        while (line.size() < 1024) {
            const auto received = ::read(status[0], &byte, 1);
            if (received == 1) {
                if (byte == '\n') break;
                line.push_back(byte);
                continue;
            }
            if (received < 0 && errno == EINTR) continue;
            break;
        }
        ::close(status[0]);

        std::istringstream fields(line);
        std::string extra;
        long owner = 0;
        if (!(fields >> owner >> token_ >> generation_) ||
            (fields >> extra) || owner <= 1 ||
            static_cast<pid_t>(owner) != pid_) {
            terminate_noexcept();
            throw std::runtime_error(
                "invalid guardian ready record: " + line);
        }
    }

    ~LockGuardianProcess() {
        release_noexcept();
    }

    LockGuardianProcess(const LockGuardianProcess&) = delete;
    LockGuardianProcess& operator=(const LockGuardianProcess&) =
        delete;

    pid_t pid() const {
        return pid_;
    }

    const std::string& token() const {
        return token_;
    }

    const std::string& generation() const {
        return generation_;
    }

    int release() {
        if (pid_ <= 1) return 0;
        if (control_ >= 0) {
            ::close(control_);
            control_ = -1;
        }
        const auto pid = pid_;
        pid_ = -1;
        return wait_for_child(pid);
    }

    int terminate() {
        if (pid_ <= 1) return 0;
        if (control_ >= 0) {
            ::close(control_);
            control_ = -1;
        }
        const auto pid = pid_;
        pid_ = -1;
        ::kill(pid, SIGKILL);
        return wait_for_child(pid);
    }

private:
    static int wait_for_child(pid_t pid) noexcept {
        int status = 0;
        while (::waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR) return 255;
        }
        if (WIFEXITED(status)) return WEXITSTATUS(status);
        if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        return 255;
    }

    void release_noexcept() noexcept {
        if (pid_ <= 1) return;
        if (control_ >= 0) {
            ::close(control_);
            control_ = -1;
        }
        const auto pid = pid_;
        pid_ = -1;
        (void)wait_for_child(pid);
    }

    void terminate_noexcept() noexcept {
        if (pid_ <= 1) return;
        if (control_ >= 0) {
            ::close(control_);
            control_ = -1;
        }
        const auto pid = pid_;
        pid_ = -1;
        ::kill(pid, SIGKILL);
        (void)wait_for_child(pid);
    }

    pid_t pid_ = -1;
    int control_ = -1;
    std::string token_;
    std::string generation_;
};

void write_file(const fs::path& path,
                const std::string& contents,
                mode_t mode = 0600) {
    fs::create_directories(path.parent_path());
    for (auto directory = path.parent_path();
         directory.filename() == "rescue" ||
         directory.filename() == "recovery" ||
         directory.filename() == "config-save" ||
         directory.filename() == "backup-restore";
         directory = directory.parent_path()) {
        REQUIRE(::chmod(directory.c_str(), 0700) == 0);
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE_MESSAGE(output, "cannot write " << path);
    output << contents;
    output.close();
    REQUIRE_MESSAGE(output, "cannot finish writing " << path);
    REQUIRE(::chmod(path.c_str(), mode) == 0);
}

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE_MESSAGE(input, "cannot read " << path);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

void install_portable_stat(const fs::path& root) {
    write_file(
        root / "opt/var/lib/keen-pbr/rescue/portable-stat.sh",
        read_file(KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH),
        0700);
}

std::size_t count_occurrences(const std::string& text,
                              const std::string& needle) {
    std::size_t count = 0;
    std::size_t offset = 0;
    while ((offset = text.find(needle, offset)) != std::string::npos) {
        ++count;
        offset += needle.size();
    }
    return count;
}

std::string process_start_time_for_test(pid_t pid) {
    std::ifstream input(fs::path("/proc") / std::to_string(pid) / "stat");
    std::string stat;
    REQUIRE(std::getline(input, stat));
    const auto comm_end = stat.rfind(") ");
    REQUIRE(comm_end != std::string::npos);
    std::istringstream fields(stat.substr(comm_end + 2));
    std::string value;
    for (int field = 3; field <= 22; ++field) {
        const bool parsed = static_cast<bool>(fields >> value);
        REQUIRE(parsed);
    }
    return value;
}

fs::path rescue_dir(const fs::path& root) {
    return root / "opt/var/lib/keen-pbr/rescue";
}

fs::path recovery_dir(const fs::path& root) {
    return root / "opt/var/lib/keen-pbr/recovery";
}

fs::path config_dir(const fs::path& root) {
    return root / "opt/etc/keen-pbr";
}

void install_runtime_mocks(const fs::path& root) {
    write_file(
        root / "opt/bin/stat",
        "#!/bin/sh\n"
        "if [ \"${1:-}\" != -t ]; then\n"
        "  printf '%s\\n' \"stat: invalid option -- '${1#-}'\" >&2\n"
        "  exit 1\n"
        "fi\n"
        "exec /usr/bin/stat -t \"$2\"\n",
        0700);
    write_file(
        root / "opt/bin/opkg",
        "#!/bin/sh\n"
        "count_file=\"$KEEN_PBR_RESCUE_ROOT/opkg-count\"\n"
        "count=0\n"
        "[ ! -f \"$count_file\" ] || IFS= read -r count < \"$count_file\"\n"
        "count=$((count + 1))\n"
        "printf '%s\\n' \"$count\" > \"$count_file\"\n"
        "printf '%s\\n' \"$*\" >> \"$KEEN_PBR_RESCUE_ROOT/opkg.log\"\n"
        "exit \"${KEEN_PBR_TEST_OPKG_EXIT:-0}\"\n",
        0700);
    write_file(
        root / "opt/bin/curl",
        "#!/bin/sh\n"
        "count_file=\"$KEEN_PBR_RESCUE_ROOT/curl-count\"\n"
        "count=0\n"
        "[ ! -f \"$count_file\" ] || IFS= read -r count < \"$count_file\"\n"
        "count=$((count + 1))\n"
        "printf '%s\\n' \"$count\" > \"$count_file\"\n"
        "output_file=\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    -o) output_file=${2:-}; shift 2 ;;\n"
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        "if [ \"$count\" -le \"${KEEN_PBR_TEST_CURL_FAIL_CALLS:-0}\" ]; then\n"
        "  [ -z \"$output_file\" ] || printf '%s\\n' "
        "'{\"error\":\"unavailable\"}' > \"$output_file\"\n"
        "  printf 500\n"
        "else\n"
        "  if [ \"${KEEN_PBR_TEST_AUTH_MISCONFIGURED:-0}\" = 1 ]; then\n"
        "    body='{\"authenticated\":false,\"enabled\":true,"
        "\"error\":\"auth_misconfigured\"}'\n"
        "  else\n"
        "    body='{\"authenticated\":false,\"enabled\":true}'\n"
        "  fi\n"
        "  [ -z \"$output_file\" ] || printf '%s\\n' \"$body\" > \"$output_file\"\n"
        "  printf 200\n"
        "fi\n",
        0700);
    const std::string init =
        "#!/bin/sh\n"
        "case \"${1:-}\" in check|restart|stop) exit 0 ;; *) exit 1 ;; esac\n";
    write_file(root / "opt/etc/init.d/S79transport-manager", init, 0700);
    write_file(root / "opt/etc/init.d/S80keen-pbr", init, 0700);
    write_file(
        root / "opt/usr/bin/keen-pbr",
        "#!/bin/sh\n"
        "[ \"${1:-}\" = recover-persistent-state ] || exit 2\n"
        "ROOT=${KEEN_PBR_RESCUE_ROOT:-}\n"
        "printf '%s\\n' recover-persistent-state >> \"$ROOT/recovery.log\"\n"
        "rm -f \"$ROOT/opt/var/lib/keen-pbr/recovery/config-save/active.json\" \\\n"
        "  \"$ROOT/opt/var/lib/keen-pbr/recovery/backup-restore/active.json\"\n",
        0700);
    write_file(root / "mock-bin/sleep", "#!/bin/sh\nexit 0\n", 0700);
    write_file(rescue_dir(root) / "portable-stat.sh",
               read_file(KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH),
               0700);
    write_file(rescue_dir(root) / "update-lock.sh",
               read_file(KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH),
               0700);
    write_file(rescue_dir(root) / "rescue-update.sh",
               read_file(KEEN_PBR_RESCUE_SCRIPT_PATH),
               0700);
    write_file(root / "opt/etc/init.d/S00keen-pbr-rescue",
               read_file(KEEN_PBR_RESCUE_STARTUP_GUARD_PATH),
               0700);
}

int wait_for_child(pid_t pid) {
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            throw std::system_error(errno, std::generic_category(), "waitpid");
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 255;
}

int run_script(const fs::path& root,
               const char* script,
               const std::vector<std::string>& arguments,
               int opkg_exit = 0,
               int curl_fail_calls = 0,
               const fs::path& stdout_path = {},
               bool mock_sleep = true,
               const std::string& inherited_pid = {},
               const std::string& inherited_token = {},
               const std::string& new_lock_helper = {},
               bool fail_lock_before_commit = false,
               const std::string& stop_after_rescue_phase = {},
               bool fail_rescue_cleanup = false,
               bool rescue_transaction = false,
               bool package_postinst = false,
               bool package_upgrade = false,
               bool fail_pending_after_commit = false,
               bool persistent_transaction = false,
               bool final_remove = false,
               bool auth_misconfigured = false) {
    const auto pid = ::fork();
    if (pid < 0)
        throw std::system_error(errno, std::generic_category(), "fork");
    if (pid == 0) {
        const auto root_string = root.string();
        const auto path = mock_sleep
                              ? (root / "mock-bin").string() +
                                    ":/usr/bin:/bin"
                              : std::string{"/usr/bin:/bin"};
        ::setenv("KEEN_PBR_RESCUE_ROOT", root_string.c_str(), 1);
        ::setenv("KEEN_PBR_TEST_OPKG_EXIT",
                 std::to_string(opkg_exit).c_str(),
                 1);
        ::setenv("KEEN_PBR_TEST_CURL_FAIL_CALLS",
                 std::to_string(curl_fail_calls).c_str(),
                 1);
        ::setenv("PATH", path.c_str(), 1);
        if (!inherited_pid.empty())
            ::setenv("KEEN_PBR_UPDATE_LOCK_PID", inherited_pid.c_str(), 1);
        if (!inherited_token.empty())
            ::setenv("KEEN_PBR_UPDATE_LOCK_TOKEN", inherited_token.c_str(), 1);
        if (!new_lock_helper.empty())
            ::setenv("KEEN_PBR_TEST_NEW_LOCK_HELPER",
                     new_lock_helper.c_str(),
                     1);
        if (fail_lock_before_commit)
            ::setenv("KEEN_PBR_UPDATE_LOCK_TEST_FAIL_BEFORE_COMMIT", "1", 1);
        if (!stop_after_rescue_phase.empty())
            ::setenv("KEEN_PBR_RESCUE_TEST_STOP_AFTER_PHASE",
                     stop_after_rescue_phase.c_str(),
                     1);
        if (fail_rescue_cleanup)
            ::setenv("KEEN_PBR_RESCUE_TEST_FAIL_CLEANUP", "1", 1);
        if (fail_pending_after_commit)
            ::setenv(
                "KEEN_PBR_RESCUE_TEST_FAIL_PENDING_AFTER_COMMIT",
                "1",
                1);
        if (rescue_transaction)
            ::setenv("KEEN_PBR_RESCUE_TRANSACTION", "1", 1);
        if (package_postinst)
            ::setenv("KEEN_PBR_PACKAGE_POSTINST", "1", 1);
        if (package_upgrade)
            ::setenv("PKG_UPGRADE", "1", 1);
        if (persistent_transaction)
            ::setenv("KEEN_PBR_PERSISTENT_TRANSACTION", "1", 1);
        if (final_remove)
            ::setenv("KEEN_PBR_FINAL_REMOVE", "1", 1);
        if (auth_misconfigured)
            ::setenv("KEEN_PBR_TEST_AUTH_MISCONFIGURED", "1", 1);
        if (!stdout_path.empty()) {
            const int descriptor =
                ::open(stdout_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (descriptor < 0) _exit(126);
            if (::dup2(descriptor, STDOUT_FILENO) < 0) _exit(126);
            ::close(descriptor);
        }

        std::vector<std::string> storage{"/bin/sh", script};
        storage.insert(storage.end(), arguments.begin(), arguments.end());
        std::vector<char*> argv;
        argv.reserve(storage.size() + 1);
        for (auto& value : storage) argv.push_back(value.data());
        argv.push_back(nullptr);
        ::execv(argv.front(), argv.data());
        _exit(127);
    }
    return wait_for_child(pid);
}

fs::path write_install_lock_harness(const fs::path& root) {
    install_portable_stat(root);
    const auto installer = read_file(KEEN_PBR_INSTALL_SCRIPT_PATH);
    const auto begin = installer.find("valid_lock_pid() {");
    const auto end = installer.find("\nsay() {", begin);
    REQUIRE(begin != std::string::npos);
    REQUIRE(end != std::string::npos);
    const auto functions = installer.substr(begin, end - begin);
    const auto harness = root / "install-lock-harness.sh";
    write_file(
        harness,
        "#!/bin/sh\n"
        "set -eu\n"
        "umask 077\n"
        "ROOT=$KEEN_PBR_RESCUE_ROOT\n"
        "LOCK_HELPER=\"$ROOT/opt/var/lib/keen-pbr/rescue/update-lock.sh\"\n"
        "METADATA_HELPER=\"$ROOT/opt/var/lib/keen-pbr/rescue/portable-stat.sh\"\n"
        "LOCK_DIR=\"$ROOT/opt/var/run/keen-pbr-update.lock\"\n"
        "LOCK_OWNER_PID=${KEEN_PBR_UPDATE_LOCK_PID:-}\n"
        "LOCK_TOKEN=${KEEN_PBR_UPDATE_LOCK_TOKEN:-}\n"
        "LOCK_OWNED=0\n"
        "LOCK_RETURN_PID=\n"
        "LOCK_HELPER_V2=0\n"
        "FALLBACK_CLEANUP_OWNED=0\n" +
            functions +
            "\nacquire_update_lock\n"
            "printf 'MODE=%s\\n' \"$(stat -c '%a' \"$LOCK_DIR\")\"\n"
            "printf 'READY='\n"
            "cat \"$LOCK_DIR/ready\"\n"
            "cp \"$KEEN_PBR_TEST_NEW_LOCK_HELPER\" \"$LOCK_HELPER\"\n"
            "chmod 0700 \"$LOCK_HELPER\"\n"
            "\"$LOCK_HELPER\" held \"$LOCK_OWNER_PID\" \"$LOCK_TOKEN\"\n"
            "\"$LOCK_HELPER\" release \"$LOCK_OWNER_PID\" \"$LOCK_TOKEN\"\n"
            "printf '%s\\n' LEGACY-UPGRADE-OK\n",
        0700);
    return harness;
}

int run_rescue(const fs::path& root,
               const std::vector<std::string>& arguments,
               int opkg_exit = 0,
               int curl_fail_calls = 0,
               const std::string& stop_after_phase = {},
               bool fail_cleanup = false,
               bool fail_pending_after_commit = false,
               bool auth_misconfigured = false) {
    return run_script(root,
                      KEEN_PBR_RESCUE_SCRIPT_PATH,
                      arguments,
                      opkg_exit,
                      curl_fail_calls,
                      {},
                      true,
                      {},
                      {},
                      {},
                      false,
                      stop_after_phase,
                      fail_cleanup,
                      false,
                      false,
                      false,
                      fail_pending_after_commit,
                      false,
                      false,
                      auth_misconfigured);
}

int run_lock(const fs::path& root,
             const std::vector<std::string>& arguments,
             const fs::path& stdout_path = {},
             bool fail_before_commit = false) {
    install_portable_stat(root);
    return run_script(root,
                      KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH,
                      arguments,
                      0,
                      0,
                      stdout_path,
                      false,
                      {},
                      {},
                      {},
                      fail_before_commit);
}

int run_startup_guard(const fs::path& root,
                      bool rescue_transaction = false,
                      bool package_postinst = false,
                      bool persistent_transaction = false) {
    const auto guard =
        root / "opt/etc/init.d/S00keen-pbr-rescue";
    return run_script(root,
                      guard.c_str(),
                      {"start"},
                      0,
                      0,
                      {},
                      true,
                      {},
                      {},
                      {},
                      false,
                      {},
                      false,
                      rescue_transaction,
                      package_postinst,
                      false,
                      false,
                      persistent_transaction);
}

int run_postrm(const fs::path& root,
               bool final_remove = false,
               bool package_upgrade = false) {
    return run_script(root,
                      KEEN_PBR_POSTRM_SCRIPT_PATH,
                      {},
                      0,
                      0,
                      {},
                      true,
                      {},
                      {},
                      {},
                      false,
                      {},
                      false,
                      false,
                      false,
                      package_upgrade,
                      false,
                      false,
                      final_remove);
}

void prepare_two_generations(const fs::path& root) {
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    write_file(config / "config.json", "config-a\n");
    write_file(config / "transports.json", "transport-a\n");
    write_file(config / "hook.sh", "#!/bin/sh\n# generation a\n", 0755);
    write_file(rescue / "current.ipk", "package-a\n");
    write_file(root / "candidate-source.ipk", "package-b\n", 0644);
    REQUIRE(run_rescue(root,
                       {"stage", (root / "candidate-source.ipk").string()}) ==
            0);
    write_file(config / "config.json", "config-b\n");
    write_file(config / "transports.json", "transport-b\n");
    write_file(config / "auth.json", "candidate-only\n");
    write_file(config / "hook.sh", "# generation b\n", 0640);
    REQUIRE(run_rescue(root, {"promote"}) == 0);
}

mode_t permissions(const fs::path& path) {
    struct stat status {};
    REQUIRE(::stat(path.c_str(), &status) == 0);
    return status.st_mode & 0777;
}

} // namespace

TEST_CASE("runtime verification accepts a healthy authentication status") {
    TempDirectory directory;
    const auto root = directory.path;
    install_runtime_mocks(root);
    write_file(config_dir(root) / "config.json",
               R"({"api":{"listen":"0.0.0.0:12121"}})");

    CHECK(run_rescue(root, {"verify"}) == 0);
}

TEST_CASE("runtime verification rejects a misconfigured authentication state") {
    TempDirectory directory;
    const auto root = directory.path;
    install_runtime_mocks(root);
    write_file(config_dir(root) / "config.json",
               R"({"api":{"listen":"0.0.0.0:12121"}})");

    CHECK(run_rescue(root,
                     {"verify"},
                     0,
                     0,
                     {},
                     false,
                     false,
                     true) == 1);
}

TEST_CASE("rescue stage publishes a complete private snapshot before pending state") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);

    write_file(config / "config.json", "config-a\n");
    write_file(config / "transports.json", "transport-a\n");
    write_file(rescue / "current.ipk", "package-a\n");
    write_file(root / "candidate-source.ipk", "package-b\n", 0644);

    REQUIRE(run_rescue(root,
                       {"stage", (root / "candidate-source.ipk").string()}) ==
            0);
    CHECK(read_file(rescue / "candidate.ipk") == "package-b\n");
    CHECK(read_file(rescue / "pre-update-config/config.json") == "config-a\n");
    CHECK_FALSE(read_file(rescue / "pre-update-config/.snapshot-manifest").empty());
    CHECK(read_file(rescue / "pre-update-config/.snapshot-ready").size() == 65);
    CHECK(read_file(rescue / "pending") == "candidate-staged\n");
    CHECK(permissions(rescue) == 0700);
    CHECK(permissions(rescue / "pre-update-config") == 0700);

    REQUIRE(run_rescue(root, {"promote"}) == 0);
    CHECK(read_file(rescue / "current.ipk") == "package-b\n");
    CHECK(read_file(rescue / "previous.ipk") == "package-a\n");
    CHECK(read_file(rescue / "previous-config/config.json") == "config-a\n");
    CHECK_FALSE(fs::exists(rescue / "pending"));
}

TEST_CASE(
    "post-commit pending failure preserves exact candidate recovery payload") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);

    write_file(config / "config.json", "config-a\n");
    write_file(config / "transports.json", "transport-a\n");
    write_file(rescue / "current.ipk", "package-a\n");
    write_file(root / "candidate-source.ipk", "package-b\n", 0644);

    CHECK(run_rescue(
              root,
              {"stage", (root / "candidate-source.ipk").string()},
              0,
              0,
              {},
              false,
              true) == 1);

    CHECK(read_file(rescue / "pending") == "candidate-staged\n");
    CHECK(read_file(rescue / "candidate.ipk") == "package-b\n");
    CHECK(fs::exists(rescue / "candidate.ipk.sha256"));
    CHECK(read_file(rescue / "pre-update-config/config.json") ==
          "config-a\n");
    CHECK(fs::exists(rescue / "pre-update-config/.snapshot-manifest"));
    CHECK(fs::exists(rescue / "UNKNOWN"));
}

TEST_CASE("successful package rollback swaps archives and exact configurations") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);
    prepare_two_generations(root);

    REQUIRE(run_rescue(root, {"rollback-previous"}) == 0);
    CHECK(read_file(rescue / "current.ipk") == "package-a\n");
    CHECK(read_file(rescue / "previous.ipk") == "package-b\n");
    CHECK(read_file(config / "config.json") == "config-a\n");
    CHECK(read_file(config / "transports.json") == "transport-a\n");
    CHECK_FALSE(fs::exists(config / "auth.json"));
    CHECK(read_file(config / "hook.sh") ==
          "#!/bin/sh\n# generation a\n");
    CHECK(permissions(config / "hook.sh") == 0755);
    CHECK(permissions(config / "config.json") == 0600);
    CHECK(read_file(rescue / "previous-config/config.json") == "config-b\n");
    CHECK(fs::exists(rescue / "previous-config/auth.json"));
    CHECK(permissions(rescue / "previous-config/hook.sh") == 0640);
    CHECK_FALSE(fs::exists(root / "opt/var/run/keen-pbr-self-update.pid"));
    CHECK(read_file(root / "opt/var/run/keen-pbr-self-update.json")
              .find("\"phase\":\"completed\"") != std::string::npos);
}

TEST_CASE(
    "post-commit rollback marker failure preserves both package generations") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    install_runtime_mocks(root);
    prepare_two_generations(root);

    CHECK(run_rescue(
              root,
              {"rollback-previous"},
              0,
              0,
              {},
              false,
              true) == 1);

    CHECK(read_file(rescue / "pending") == "rollback-previous\n");
    CHECK(fs::exists(rescue / "pending-baseline.ipk"));
    CHECK(fs::exists(rescue / "pending-baseline.ipk.sha256"));
    CHECK(fs::exists(rescue / "pending-target.ipk"));
    CHECK(fs::exists(rescue / "pending-target.ipk.sha256"));
    CHECK(fs::exists(rescue / "pending-baseline-config/.snapshot-manifest"));
    CHECK(fs::exists(rescue / "pending-target-config/.snapshot-manifest"));
    CHECK(fs::exists(rescue / "UNKNOWN"));
    CHECK_FALSE(fs::exists(root / "opkg.log"));
}

TEST_CASE("partial package snapshot fails closed before opkg") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    install_runtime_mocks(root);
    prepare_two_generations(root);

    REQUIRE(fs::remove(rescue / "previous-config/transports.json"));
    CHECK(run_rescue(root, {"can-rollback-previous"}) == 2);
    CHECK(run_rescue(root, {"rollback-previous"}) == 2);
    CHECK_FALSE(fs::exists(root / "opkg.log"));
    CHECK(read_file(rescue / "current.ipk") == "package-b\n");
    CHECK(read_file(rescue / "previous.ipk") == "package-a\n");
}

TEST_CASE("corrupt snapshot manifest hash fails closed before opkg") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    install_runtime_mocks(root);
    prepare_two_generations(root);

    {
        std::ofstream manifest(rescue / "previous-config/.snapshot-manifest",
                               std::ios::app);
        manifest << "absent config.json -\n";
    }
    CHECK(run_rescue(root, {"can-rollback-previous"}) == 2);
    CHECK(run_rescue(root, {"rollback-previous"}) == 2);
    CHECK_FALSE(fs::exists(root / "opkg.log"));
}

TEST_CASE("snapshot mode tampering fails closed before opkg") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    install_runtime_mocks(root);
    prepare_two_generations(root);

    REQUIRE(::chmod((rescue / "previous-config/hook.sh").c_str(), 0644) == 0);
    CHECK(run_rescue(root, {"can-rollback-previous"}) == 2);
    CHECK(run_rescue(root, {"rollback-previous"}) == 2);
    CHECK_FALSE(fs::exists(root / "opkg.log"));
}

TEST_CASE("corrupt previous IPK hash fails closed before services stop") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    install_runtime_mocks(root);
    prepare_two_generations(root);

    write_file(rescue / "previous.ipk", "tampered-package\n");
    CHECK(run_rescue(root, {"can-rollback-previous"}) == 2);
    CHECK(run_rescue(root, {"rollback-previous"}) == 2);
    CHECK_FALSE(fs::exists(root / "opkg.log"));
    const auto output = root / "status.json";
    REQUIRE(run_script(root,
                       KEEN_PBR_RESCUE_SCRIPT_PATH,
                       {"status"},
                       0,
                       0,
                       output) == 0);
    CHECK(read_file(output).find("\"rollback_available\":false") !=
          std::string::npos);
}

TEST_CASE("health failure after opkg success compensates package and live config") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);
    prepare_two_generations(root);

    CHECK(run_rescue(root, {"rollback-previous"}, 0, 15) == 1);
    CHECK(read_file(config / "config.json") == "config-b\n");
    CHECK(read_file(config / "transports.json") == "transport-b\n");
    CHECK(fs::exists(config / "auth.json"));
    CHECK(read_file(rescue / "current.ipk") == "package-b\n");
    CHECK(read_file(rescue / "previous.ipk") == "package-a\n");
    CHECK_FALSE(fs::exists(rescue / "pending"));
    CHECK_FALSE(fs::exists(rescue / "UNKNOWN"));
    CHECK(count_occurrences(read_file(root / "opkg.log"), "--force-reinstall") ==
          2);
    CHECK(read_file(root / "opt/var/run/keen-pbr-self-update.json")
              .find("\"phase\":\"failed\"") != std::string::npos);
}

TEST_CASE("uncompensated package-manager failure enters persistent UNKNOWN state") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);
    prepare_two_generations(root);

    CHECK(run_rescue(root, {"rollback-previous"}, 17) == 1);
    CHECK(read_file(config / "config.json") == "config-b\n");
    CHECK(read_file(rescue / "current.ipk") == "package-b\n");
    CHECK(read_file(rescue / "previous.ipk") == "package-a\n");
    CHECK(fs::exists(rescue / "pending"));
    CHECK(fs::exists(rescue / "UNKNOWN"));
    CHECK(run_rescue(root,
                     {"stage", (root / "candidate-source.ipk").string()}) ==
          3);
    CHECK(read_file(root / "opt/var/run/keen-pbr-self-update.json")
              .find("\"phase\":\"unknown\"") != std::string::npos);
}

TEST_CASE("interrupted staged candidate recovers the baseline package and config") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);

    write_file(config / "config.json", "config-a\n");
    write_file(rescue / "current.ipk", "package-a\n");
    write_file(root / "candidate-source.ipk", "package-b\n", 0644);
    REQUIRE(run_rescue(root,
                       {"stage", (root / "candidate-source.ipk").string()}) ==
            0);
    write_file(config / "config.json", "partially-installed-config-b\n");

    REQUIRE(run_rescue(root, {"recover-pending"}) == 0);
    CHECK(read_file(config / "config.json") == "config-a\n");
    CHECK(read_file(rescue / "current.ipk") == "package-a\n");
    CHECK_FALSE(fs::exists(rescue / "pending"));
    CHECK_FALSE(fs::exists(rescue / "candidate.ipk"));
}

TEST_CASE("early boot guard recovers pending state before legacy services start") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);

    // These mocks deliberately model a rolled-back package whose S79/S80
    // scripts predate the in-script rescue guards. S00 is the durable layer.
    CHECK(read_file(root / "opt/etc/init.d/S79transport-manager")
              .find("rescue-startup-guard") == std::string::npos);
    CHECK(read_file(root / "opt/etc/init.d/S80keen-pbr")
              .find("rescue-startup-guard") == std::string::npos);

    write_file(config / "config.json", "config-a\n");
    write_file(config / "transports.json", "transport-a\n");
    write_file(rescue / "current.ipk", "package-a\n");
    write_file(root / "candidate-source.ipk", "package-b\n", 0644);
    REQUIRE(run_rescue(root,
                       {"stage", (root / "candidate-source.ipk").string()}) ==
            0);
    write_file(config / "config.json", "mixed-config-b\n");
    write_file(config / "transports.json", "mixed-transport-b\n");

    REQUIRE(run_startup_guard(root) == 0);
    CHECK(read_file(config / "config.json") == "config-a\n");
    CHECK(read_file(config / "transports.json") == "transport-a\n");
    CHECK(read_file(rescue / "current.ipk") == "package-a\n");
    CHECK_FALSE(fs::exists(rescue / "pending"));
    CHECK_FALSE(fs::exists(rescue / "UNKNOWN"));
    CHECK(count_occurrences(read_file(root / "opkg.log"),
                            "--force-reinstall") == 1);
}

TEST_CASE("early boot guard blocks UNKNOWN and recursive postinst recovery") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);

    write_file(rescue / "UNKNOWN", "manual recovery required\n");
    CHECK(run_startup_guard(root) == 1);
    CHECK_FALSE(fs::exists(root / "opkg.log"));

    REQUIRE(fs::remove(rescue / "UNKNOWN"));
    write_file(config / "config.json", "config-a\n");
    write_file(rescue / "current.ipk", "package-a\n");
    write_file(root / "candidate-source.ipk", "package-b\n", 0644);
    REQUIRE(run_rescue(root,
                       {"stage", (root / "candidate-source.ipk").string()}) ==
            0);
    CHECK(run_startup_guard(root, false, true) == 1);
    CHECK(fs::exists(rescue / "pending"));
    CHECK_FALSE(fs::exists(root / "opkg.log"));

    // Descendants of the locked rescue transaction may start services while
    // PENDING is deliberate; the early guard must not recurse into opkg.
    CHECK(run_startup_guard(root, true, true) == 0);
    CHECK(fs::exists(rescue / "pending"));
    CHECK_FALSE(fs::exists(root / "opkg.log"));
}

TEST_CASE("persistent recovery startup guard is idempotent without active WAL") {
    TempDirectory directory;
    const auto root = directory.path;
    install_runtime_mocks(root);

    REQUIRE(run_startup_guard(root) == 0);
    REQUIRE(run_startup_guard(root) == 0);
    CHECK_FALSE(fs::exists(root / "recovery.log"));
}

TEST_CASE("persistent recovery runs once before startup and requires clean state") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto recovery = recovery_dir(root);
    install_runtime_mocks(root);
    write_file(recovery / "config-save/active.json", "{}\n");

    REQUIRE(run_startup_guard(root) == 0);
    CHECK_FALSE(fs::exists(recovery / "config-save/active.json"));
    CHECK(read_file(root / "recovery.log") ==
          "recover-persistent-state\n");

    REQUIRE(run_startup_guard(root) == 0);
    CHECK(read_file(root / "recovery.log") ==
          "recover-persistent-state\n");
}

TEST_CASE("config-save recovery refuses a live transport manager") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto active =
        recovery_dir(root) / "config-save/active.json";
    install_runtime_mocks(root);
    write_file(active, "{}\n");
    write_file(
        root / "mock-bin/pidof",
        "#!/bin/sh\n"
        "[ \"${1:-}\" = transport-manager ] || exit 1\n"
        "printf '%s\\n' 4242\n",
        0700);

    CHECK(run_startup_guard(root) == 1);
    CHECK(fs::exists(active));
    CHECK_FALSE(fs::exists(root / "recovery.log"));
}

TEST_CASE("persistent transaction bypass may restart the transport manager") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto active =
        recovery_dir(root) / "config-save/active.json";
    install_runtime_mocks(root);
    write_file(active, "{}\n");
    write_file(
        root / "mock-bin/pidof",
        "#!/bin/sh\n"
        "[ \"${1:-}\" = transport-manager ] || exit 1\n"
        "printf '%s\\n' 4242\n",
        0700);

    CHECK(run_startup_guard(root, false, false, true) == 0);
    CHECK(fs::exists(active));
    CHECK_FALSE(fs::exists(root / "recovery.log"));
}

TEST_CASE("persistent recovery rejects two active journals before invoking CLI") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto recovery = recovery_dir(root);
    install_runtime_mocks(root);
    write_file(recovery / "config-save/active.json", "{}\n");
    write_file(recovery / "backup-restore/active.json", "{}\n");

    CHECK(run_startup_guard(root) == 1);
    CHECK(fs::exists(recovery / "config-save/active.json"));
    CHECK(fs::exists(recovery / "backup-restore/active.json"));
    CHECK_FALSE(fs::exists(root / "recovery.log"));
}

TEST_CASE("persistent recovery failure keeps WAL and blocks startup") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto active = recovery_dir(root) / "config-save/active.json";
    install_runtime_mocks(root);
    write_file(active, "{}\n");
    write_file(root / "opt/usr/bin/keen-pbr",
               "#!/bin/sh\n"
               "exit 9\n",
               0700);

    CHECK(run_startup_guard(root) == 1);
    CHECK(fs::exists(active));
}

TEST_CASE("persistent recovery refuses a false-success result with active WAL") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto active = recovery_dir(root) / "config-save/active.json";
    install_runtime_mocks(root);
    write_file(active, "{}\n");
    write_file(root / "opt/usr/bin/keen-pbr",
               "#!/bin/sh\n"
               "exit 0\n",
               0700);

    CHECK(run_startup_guard(root) == 1);
    CHECK(fs::exists(active));
}

TEST_CASE("persistent UNKNOWN states block startup without invoking recovery") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto recovery = recovery_dir(root);
    install_runtime_mocks(root);

    for (const auto& unknown :
         {recovery / "UNKNOWN",
          recovery / "config-save/UNKNOWN",
          recovery / "backup-restore/UNKNOWN"}) {
        write_file(unknown, "manual recovery required\n");
        CHECK(run_startup_guard(root) == 1);
        CHECK_FALSE(fs::exists(root / "recovery.log"));
        REQUIRE(fs::remove(unknown));
    }

    const auto outside = root / "outside-unknown";
    write_file(outside, "manual recovery required\n");
    REQUIRE(::symlink(outside.c_str(),
                      (recovery / "config-save/UNKNOWN").c_str()) == 0);
    CHECK(run_startup_guard(root) == 1);
    CHECK_FALSE(fs::exists(root / "recovery.log"));
}

TEST_CASE("persistent recovery rejects unsafe markers and recovery binary") {
    SUBCASE("symbolic-link active marker") {
        TempDirectory directory;
        const auto root = directory.path;
        const auto recovery = recovery_dir(root);
        install_runtime_mocks(root);
        const auto outside = root / "outside-active";
        write_file(outside, "{}\n");
        fs::create_directories(recovery / "config-save");
        REQUIRE(::symlink(
                    outside.c_str(),
                    (recovery / "config-save/active.json").c_str()) == 0);
        CHECK(run_startup_guard(root) == 1);
        CHECK_FALSE(fs::exists(root / "recovery.log"));
    }

    SUBCASE("missing binary") {
        TempDirectory directory;
        const auto root = directory.path;
        install_runtime_mocks(root);
        write_file(recovery_dir(root) / "config-save/active.json", "{}\n");
        REQUIRE(fs::remove(root / "opt/usr/bin/keen-pbr"));
        CHECK(run_startup_guard(root) == 1);
    }

    SUBCASE("nonregular binary") {
        TempDirectory directory;
        const auto root = directory.path;
        install_runtime_mocks(root);
        write_file(recovery_dir(root) / "config-save/active.json", "{}\n");
        REQUIRE(fs::remove(root / "opt/usr/bin/keen-pbr"));
        REQUIRE(fs::create_directory(root / "opt/usr/bin/keen-pbr"));
        CHECK(run_startup_guard(root) == 1);
    }

    SUBCASE("symbolic-link binary") {
        TempDirectory directory;
        const auto root = directory.path;
        install_runtime_mocks(root);
        write_file(recovery_dir(root) / "config-save/active.json", "{}\n");
        const auto outside = root / "outside-keen-pbr";
        write_file(outside, "#!/bin/sh\nexit 0\n", 0700);
        REQUIRE(fs::remove(root / "opt/usr/bin/keen-pbr"));
        REQUIRE(::symlink(
                    outside.c_str(),
                    (root / "opt/usr/bin/keen-pbr").c_str()) == 0);
        CHECK(run_startup_guard(root) == 1);
    }
}

TEST_CASE("persistent transaction bypass is independent from package rescue") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto active = recovery_dir(root) / "config-save/active.json";
    install_runtime_mocks(root);
    write_file(active, "{}\n");

    REQUIRE(run_startup_guard(root, false, false, true) == 0);
    CHECK(fs::exists(active));
    CHECK_FALSE(fs::exists(root / "recovery.log"));
    CHECK(run_startup_guard(root, false, true, true) == 1);
    CHECK(fs::exists(active));

    write_file(rescue / "UNKNOWN", "manual recovery required\n");
    CHECK(run_startup_guard(root, false, false, true) == 1);
    REQUIRE(fs::remove(rescue / "UNKNOWN"));

    // A package-rescue transaction does not hide an unrelated persistent WAL.
    REQUIRE(run_startup_guard(root, true) == 0);
    CHECK_FALSE(fs::exists(active));
    CHECK(read_file(root / "recovery.log") ==
          "recover-persistent-state\n");
}

TEST_CASE("package postinst refuses persistent recovery before mutations") {
    TempDirectory directory;
    const auto root = directory.path;
    install_runtime_mocks(root);
    write_file(recovery_dir(root) / "backup-restore/active.json", "{}\n");

    CHECK(run_startup_guard(root, false, true) == 1);
    CHECK_FALSE(fs::exists(root / "recovery.log"));

    const auto postinst = read_file(KEEN_PBR_POSTINST_SCRIPT_PATH);
    const auto guard = postinst.find(
        "KEEN_PBR_PACKAGE_POSTINST=1");
    const auto first_mutation = postinst.find("answer=\"\"");
    REQUIRE(guard != std::string::npos);
    REQUIRE(first_mutation != std::string::npos);
    CHECK(guard < first_mutation);
}

TEST_CASE("package postinst restores early guard before metadata validation") {
    const auto postinst = read_file(KEEN_PBR_POSTINST_SCRIPT_PATH);
    const auto guard_install = postinst.find(
        "/opt/usr/lib/keen-pbr/rescue-startup-guard.sh");
    const auto metadata_load = postinst.find(". \"$METADATA_HELPER\"");
    REQUIRE(guard_install != std::string::npos);
    REQUIRE(metadata_load != std::string::npos);
    CHECK(guard_install < metadata_load);
}

TEST_CASE("target package scripts use the portable metadata boundary") {
    for (const auto* script :
         {KEEN_PBR_POSTINST_SCRIPT_PATH,
          KEEN_PBR_RESCUE_SCRIPT_PATH,
          KEEN_PBR_RESCUE_STARTUP_GUARD_PATH,
          KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH}) {
        CHECK(read_file(script).find("stat -c") == std::string::npos);
    }
}

TEST_CASE("package replacement protects the legacy postrm transition") {
    CHECK(
        read_file(KEEN_PBR_INSTALL_SCRIPT_PATH).find("PKG_UPGRADE=1") !=
        std::string::npos);
    CHECK(
        read_file(KEEN_PBR_RESCUE_SCRIPT_PATH).find("PKG_UPGRADE=1") !=
        std::string::npos);
}

TEST_CASE("unsafe rescue directory cannot inject metadata helper code") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto marker = root / "metadata-helper-executed";
    write_file(
        root / "opt/bin/stat",
        "#!/bin/sh\n"
        "[ \"${1:-}\" = -t ] || exit 1\n"
        "exec /usr/bin/stat -t \"$2\"\n",
        0700);
    write_file(
        rescue / "portable-stat.sh",
        "touch \"$KEEN_PBR_RESCUE_ROOT/metadata-helper-executed\"\n",
        0700);
    REQUIRE(::chmod(rescue.c_str(), 0777) == 0);

    CHECK(
        run_script(
            root,
            KEEN_PBR_RESCUE_SCRIPT_PATH,
            {"status"},
            0,
            0,
            {},
            false) == 2);
    CHECK_FALSE(fs::exists(marker));

    CHECK(
        run_script(
            root,
            KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH,
            {"protocol"},
            0,
            0,
            {},
            false) == 2);
    CHECK_FALSE(fs::exists(marker));
}

TEST_CASE(
    "only an explicit final uninstall removes the clean recovery guard") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto guard = root / "opt/etc/init.d/S00keen-pbr-rescue";
    write_file(guard, "#!/bin/sh\nexit 0\n", 0700);

    REQUIRE(run_postrm(root, false, true) == 0);
    CHECK(fs::exists(guard));

    // Same-version opkg --force-reinstall does not reliably set PKG_UPGRADE.
    REQUIRE(run_postrm(root) == 0);
    CHECK(fs::exists(guard));

    REQUIRE(run_postrm(root, true) == 0);
    CHECK_FALSE(fs::exists(guard));
}

TEST_CASE("final uninstall preserves early guard for forensic recovery state") {
    for (const auto& relative :
         {fs::path{"rescue/pending"},
          fs::path{"rescue/UNKNOWN"},
          fs::path{"recovery/UNKNOWN"},
          fs::path{"recovery/config-save/UNKNOWN"},
          fs::path{"recovery/backup-restore/UNKNOWN"},
          fs::path{"recovery/config-save/active.json"},
          fs::path{"recovery/backup-restore/active.json"}}) {
        TempDirectory directory;
        const auto root = directory.path;
        const auto guard = root / "opt/etc/init.d/S00keen-pbr-rescue";
        write_file(guard, "#!/bin/sh\nexit 0\n", 0700);
        write_file(root / "opt/var/lib/keen-pbr" / relative, "{}\n");

        REQUIRE(run_postrm(root, true) == 0);
        CHECK(fs::exists(guard));
    }
}

TEST_CASE("durable candidate-promoting phase recovers after a crash") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);
    write_file(config / "config.json", "config-a\n");
    write_file(rescue / "current.ipk", "package-a\n");
    write_file(root / "candidate-source.ipk", "package-b\n", 0644);
    REQUIRE(run_rescue(root,
                       {"stage", (root / "candidate-source.ipk").string()}) ==
            0);

    CHECK(run_rescue(root,
                     {"promote"},
                     0,
                     0,
                     "candidate-promoting") == 128 + SIGKILL);
    CHECK(read_file(rescue / "pending") == "candidate-promoting\n");
    CHECK(read_file(rescue / "current.ipk") == "package-a\n");
    REQUIRE(run_rescue(root, {"recover-pending"}) == 0);
    CHECK(read_file(rescue / "current.ipk") == "package-a\n");
    CHECK(read_file(config / "config.json") == "config-a\n");
    CHECK_FALSE(fs::exists(rescue / "pending"));
}

TEST_CASE("durable rollback-swapping phase restores baseline after a crash") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);
    prepare_two_generations(root);

    CHECK(run_rescue(root,
                     {"rollback-previous"},
                     0,
                     0,
                     "rollback-swapping") == 128 + SIGKILL);
    CHECK(read_file(rescue / "pending") == "rollback-swapping\n");
    CHECK(read_file(config / "config.json") == "config-a\n");
    REQUIRE(run_rescue(root, {"recover-pending"}) == 0);
    CHECK(read_file(rescue / "current.ipk") == "package-b\n");
    CHECK(read_file(rescue / "previous.ipk") == "package-a\n");
    CHECK(read_file(config / "config.json") == "config-b\n");
    CHECK_FALSE(fs::exists(rescue / "pending"));
}

TEST_CASE("post-commit cleanup failure never recreates pending state") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);
    write_file(config / "config.json", "config-a\n");
    write_file(rescue / "current.ipk", "package-a\n");
    write_file(root / "candidate-source.ipk", "package-b\n", 0644);
    REQUIRE(run_rescue(root,
                       {"stage", (root / "candidate-source.ipk").string()}) ==
            0);

    CHECK(run_rescue(root, {"promote"}, 0, 0, {}, true) == 0);
    CHECK_FALSE(fs::exists(rescue / "pending"));
    CHECK(read_file(rescue / "current.ipk") == "package-b\n");
    CHECK(fs::exists(rescue / "candidate.ipk"));

    // The next transaction performs the same idempotent garbage collection
    // before publishing a new PENDING marker.
    write_file(root / "candidate-source-2.ipk", "package-c\n", 0644);
    REQUIRE(run_rescue(
                root,
                {"stage", (root / "candidate-source-2.ipk").string()}) == 0);
    CHECK(read_file(rescue / "pending") == "candidate-staged\n");
    CHECK(read_file(rescue / "candidate.ipk") == "package-c\n");
}

TEST_CASE("common atomic lock rejects a concurrent rescue mutation") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto config = config_dir(root);
    install_runtime_mocks(root);
    write_file(config / "config.json", "config-a\n");
    write_file(rescue / "current.ipk", "package-a\n");
    write_file(root / "candidate-source.ipk", "package-b\n", 0644);

    PausedProcess owner;
    const auto token_file = root / "lock-token";
    REQUIRE(run_lock(root,
                     {"acquire",
                      std::to_string(static_cast<long>(owner.pid()))},
                     token_file) == 0);
    const auto token = read_file(token_file);
    REQUIRE_FALSE(token.empty());
    CHECK(run_rescue(root,
                     {"stage", (root / "candidate-source.ipk").string()}) ==
          75);
    CHECK_FALSE(fs::exists(rescue / "pending"));
    CHECK(run_lock(root,
                   {"release",
                    std::to_string(static_cast<long>(owner.pid())),
                    token.substr(0, token.find('\n'))}) == 0);
}

TEST_CASE("maintenance lock protocol extends v2 without changing its wire format") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto version_file = root / "version";
    const auto protocol_file = root / "protocol";
    REQUIRE(run_lock(root, {"version"}, version_file) == 0);
    REQUIRE(run_lock(root, {"protocol"}, protocol_file) == 0);
    CHECK(read_file(version_file) == "2\n");
    CHECK(read_file(protocol_file) == "3\n");

    PausedProcess owner;
    const auto owner_text =
        std::to_string(static_cast<long>(owner.pid()));
    const auto token_file = root / "operation-token";
    REQUIRE(run_lock(
                root,
                {"acquire", owner_text, "config-save"},
                token_file) == 0);
    auto token = read_file(token_file);
    token.resize(token.find('\n'));
    CHECK(token.rfind("config-save.", 0) == 0);

    const auto operation_file = root / "operation";
    CHECK(run_lock(
              root,
              {"operation", owner_text, token},
              operation_file) == 0);
    CHECK(read_file(operation_file) == "config-save\n");

    const auto lock =
        root / "opt/var/run/keen-pbr-update.lock";
    std::set<std::string> entries;
    for (const auto& entry : fs::directory_iterator(lock)) {
        entries.insert(entry.path().filename().string());
    }
    CHECK(entries ==
          std::set<std::string>{
              "owner", "pid", "ready", "start", "token"});
    CHECK(run_lock(root, {"held", owner_text, token}) == 0);
    REQUIRE(run_lock(root, {"release", owner_text, token}) == 0);

    // The original two-argument acquire command remains valid. Its operation
    // is explicitly classified as legacy package maintenance.
    REQUIRE(run_lock(root, {"acquire", owner_text}, token_file) == 0);
    token = read_file(token_file);
    token.resize(token.find('\n'));
    CHECK(token.rfind("legacy-update.", 0) == 0);
    CHECK(run_lock(
              root,
              {"operation", owner_text, token},
              operation_file) == 0);
    CHECK(read_file(operation_file) == "legacy-update\n");
    CHECK(run_lock(root, {"release", owner_text, token}) == 0);
}

TEST_CASE("maintenance generation reservation is durable and compare-and-swap") {
    TempDirectory directory;
    const auto root = directory.path;
    PausedProcess owner;
    const auto owner_text =
        std::to_string(static_cast<long>(owner.pid()));
    const auto token_file = root / "generation-token";
    REQUIRE(run_lock(
                root,
                {"acquire", owner_text, "backup-restore"},
                token_file) == 0);
    auto token = read_file(token_file);
    token.resize(token.find('\n'));

    const auto generation_output = root / "generation-output";
    REQUIRE(run_lock(root, {"generation"}, generation_output) == 0);
    CHECK(read_file(generation_output) == "0\n");

    const auto reserve_output = root / "reserve-output";
    REQUIRE(run_lock(
                root,
                {"reserve", owner_text, token, "0"},
                reserve_output) == 0);
    CHECK(read_file(reserve_output) == "1\n");
    const auto generation_file =
        root / "opt/var/lib/keen-pbr/maintenance-generation";
    CHECK(read_file(generation_file) == "1\n");
    CHECK(permissions(generation_file) == 0600);

    CHECK(run_lock(
              root,
              {"reserve", owner_text, token, "0"},
              reserve_output) == 73);
    CHECK(read_file(generation_file) == "1\n");
    REQUIRE(run_lock(
                root,
                {"reserve", owner_text, token, "1"},
                reserve_output) == 0);
    CHECK(read_file(reserve_output) == "2\n");
    CHECK(read_file(generation_file) == "2\n");
    CHECK(run_lock(root, {"release", owner_text, token}) == 0);
}

TEST_CASE("maintenance generation rejects malformed and symbolic-link state") {
    TempDirectory directory;
    const auto root = directory.path;
    PausedProcess owner;
    const auto owner_text =
        std::to_string(static_cast<long>(owner.pid()));
    const auto token_file = root / "unsafe-generation-token";
    REQUIRE(run_lock(
                root,
                {"acquire", owner_text, "config-save"},
                token_file) == 0);
    auto token = read_file(token_file);
    token.resize(token.find('\n'));

    const auto generation_file =
        root / "opt/var/lib/keen-pbr/maintenance-generation";
    write_file(generation_file, "not-a-generation\n");
    CHECK(run_lock(root, {"generation"}) == 1);
    CHECK(run_lock(
              root,
              {"reserve", owner_text, token, "-"}) == 1);
    CHECK(read_file(generation_file) == "not-a-generation\n");

    REQUIRE(fs::remove(generation_file));
    write_file(generation_file, "7\n", 0660);
    CHECK(run_lock(root, {"generation"}) == 1);
    CHECK(run_lock(
              root,
              {"reserve", owner_text, token, "-"}) == 1);
    REQUIRE(fs::remove(generation_file));

    const auto generation_directory = generation_file.parent_path();
    REQUIRE(::chmod(generation_directory.c_str(), 0770) == 0);
    CHECK(run_lock(root, {"generation"}) == 1);
    CHECK(run_lock(
              root,
              {"reserve", owner_text, token, "-"}) == 1);
    REQUIRE(::chmod(generation_directory.c_str(), 0700) == 0);

    const auto outside = root / "outside-generation";
    write_file(outside, "7\n");
    REQUIRE(::symlink(
                outside.c_str(), generation_file.c_str()) == 0);
    CHECK(run_lock(root, {"generation"}) == 1);
    CHECK(run_lock(
              root,
              {"reserve", owner_text, token, "-"}) == 1);
    CHECK(read_file(outside) == "7\n");
    CHECK(run_lock(root, {"release", owner_text, token}) == 0);
}

TEST_CASE("maintenance guardian holds the lock until its pipe closes") {
    TempDirectory directory;
    const auto root = directory.path;
    // Create the non-execing contender first so it cannot inherit the
    // guardian's write end and accidentally keep the EOF lease alive.
    PausedProcess contender;
    const auto contender_text =
        std::to_string(static_cast<long>(contender.pid()));
    LockGuardianProcess guardian(root, "backup-read");
    CHECK(guardian.token().rfind("backup-read.", 0) == 0);
    CHECK(guardian.generation() == "0");

    const auto operation_file = root / "guardian-operation";
    CHECK(run_lock(
              root,
              {"operation",
               std::to_string(static_cast<long>(guardian.pid())),
               guardian.token()},
              operation_file) == 0);
    CHECK(read_file(operation_file) == "backup-read\n");

    const auto contender_token = root / "guardian-contender";
    CHECK(run_lock(
              root,
              {"acquire", contender_text, "config-save"},
              contender_token) == 75);
    CHECK(guardian.release() == 0);

    REQUIRE(run_lock(
                root,
                {"acquire", contender_text, "config-save"},
                contender_token) == 0);
    auto token = read_file(contender_token);
    token.resize(token.find('\n'));
    CHECK(run_lock(
              root, {"release", contender_text, token}) == 0);
}

TEST_CASE("killed maintenance guardian leaves a safely recoverable stale lock") {
    TempDirectory directory;
    const auto root = directory.path;
    LockGuardianProcess guardian(root, "transport-save");
    CHECK(guardian.terminate() == 128 + SIGKILL);

    PausedProcess contender;
    const auto contender_text =
        std::to_string(static_cast<long>(contender.pid()));
    const auto token_file = root / "post-guardian-token";
    REQUIRE(run_lock(
                root,
                {"acquire", contender_text, "config-save"},
                token_file) == 0);
    auto token = read_file(token_file);
    token.resize(token.find('\n'));
    CHECK(run_lock(
              root, {"release", contender_text, token}) == 0);
}

TEST_CASE("lock transfer keeps an atomic authoritative owner record") {
    TempDirectory directory;
    const auto root = directory.path;
    install_runtime_mocks(root);
    PausedProcess initial_owner;
    PausedProcess replacement_owner;
    const auto parent = initial_owner.pid();
    const auto child = replacement_owner.pid();
    const auto token_file = root / "lock-token";
    REQUIRE(run_lock(root,
                     {"acquire", std::to_string(static_cast<long>(parent))},
                     token_file) == 0);
    auto token = read_file(token_file);
    token.resize(token.find('\n'));

    CHECK(run_lock(root,
                   {"transfer",
                    std::to_string(static_cast<long>(parent)),
                    token,
                    std::to_string(static_cast<long>(child))},
                   {},
                   true) == 1);
    CHECK(run_lock(root,
                   {"held",
                    std::to_string(static_cast<long>(parent)),
                    token}) == 0);

    const auto transfer_to_child =
        run_lock(root,
                 {"transfer",
                  std::to_string(static_cast<long>(parent)),
                  token,
                  std::to_string(static_cast<long>(child))});
    REQUIRE(transfer_to_child == 0);

    // Sidecars remain for compatibility with older readers. The atomic owner
    // record must remain authoritative if those copies are only half-written.
    write_file(root / "opt/var/run/keen-pbr-update.lock/pid", "1\n");
    write_file(root / "opt/var/run/keen-pbr-update.lock/start", "1\n");
    write_file(root / "opt/var/run/keen-pbr-update.lock/token", "stale\n");
    CHECK(run_lock(root,
                   {"held",
                    std::to_string(static_cast<long>(child)),
                    token}) == 0);

    const auto transfer_to_parent =
        run_lock(root,
                 {"transfer",
                  std::to_string(static_cast<long>(child)),
                  token,
                  std::to_string(static_cast<long>(parent))});
    REQUIRE(transfer_to_parent == 0);
    CHECK(run_lock(root,
                   {"release",
                    std::to_string(static_cast<long>(parent)),
                    token}) == 0);
}

TEST_CASE("incomplete common lock gets a publication grace period") {
    TempDirectory directory;
    const auto root = directory.path;
    install_runtime_mocks(root);
    const auto lock = root / "opt/var/run/keen-pbr-update.lock";
    fs::create_directories(lock);
    REQUIRE(::chmod(lock.c_str(), 0700) == 0);
    PausedProcess lock_owner;
    const auto owner = lock_owner.pid();
    const auto owner_start = process_start_time_for_test(owner);
    const auto publisher = ::fork();
    REQUIRE(publisher >= 0);
    if (publisher == 0) {
        ::usleep(100 * 1000);
        std::ofstream(lock / "pid") << owner << '\n';
        std::ofstream(lock / "start") << owner_start << '\n';
        std::ofstream(lock / "token") << "partial-publication-token\n";
        std::ofstream(lock / "ready") << "ready\n";
        _exit(0);
    }

    const auto contender_token = root / "contender-token";
    CHECK(run_lock(root,
                   {"acquire", std::to_string(static_cast<long>(owner))},
                   contender_token) == 75);
    CHECK(wait_for_child(publisher) == 0);
    CHECK(fs::exists(lock / "ready"));
    CHECK(read_file(lock / "token") == "partial-publication-token\n");
    CHECK(run_lock(root,
                   {"release",
                    std::to_string(static_cast<long>(owner)),
                    "partial-publication-token"}) == 0);
}

TEST_CASE("PID reuse fingerprint makes a stale live-PID lock recoverable") {
    TempDirectory directory;
    const auto root = directory.path;
    install_runtime_mocks(root);
    PausedProcess lock_owner;
    const auto owner = lock_owner.pid();
    const auto first_token_file = root / "first-token";
    REQUIRE(run_lock(root,
                     {"acquire", std::to_string(static_cast<long>(owner))},
                     first_token_file) == 0);
    const auto original_token = read_file(first_token_file);
    write_file(root / "opt/var/run/keen-pbr-update.lock/owner",
               std::to_string(static_cast<long>(owner)) + " 1 " +
                   original_token.substr(0, original_token.find('\n')) + "\n");

    const auto replacement_token_file = root / "replacement-token";
    REQUIRE(run_lock(root,
                     {"acquire", std::to_string(static_cast<long>(owner))},
                     replacement_token_file) == 0);
    const auto replacement_token = read_file(replacement_token_file);
    REQUIRE_FALSE(replacement_token.empty());
    CHECK(run_lock(root,
                   {"release",
                    std::to_string(static_cast<long>(owner)),
                    replacement_token.substr(0,
                                             replacement_token.find('\n'))}) ==
          0);
}

TEST_CASE("installer adopts an inherited legacy lock before installing v2 helper") {
    TempDirectory directory;
    const auto root = directory.path;
    const auto rescue = rescue_dir(root);
    const auto lock = root / "opt/var/run/keen-pbr-update.lock";
    fs::create_directories(rescue);
    fs::create_directories(lock);
    const auto legacy_helper = rescue / "update-lock.sh";
    write_file(
        legacy_helper,
        "#!/bin/sh\n"
        "case \"${1:-}\" in\n"
        "  held)\n"
        "    [ \"$(cat \"$KEEN_PBR_RESCUE_ROOT/opt/var/run/keen-pbr-update.lock/pid\")\" = \"$2\" ] &&\n"
        "      [ \"$(cat \"$KEEN_PBR_RESCUE_ROOT/opt/var/run/keen-pbr-update.lock/token\")\" = \"$3\" ] &&\n"
        "      kill -0 \"$2\" 2>/dev/null\n"
        "    ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
        0700);
    PausedProcess legacy_owner;
    const auto owner =
        std::to_string(static_cast<long>(legacy_owner.pid()));
    constexpr auto token = "legacy-inherited-token";
    write_file(lock / "pid", owner + "\n");
    write_file(lock / "token", std::string{token} + "\n");
    write_file(lock / "ready", "");
    const auto harness = write_install_lock_harness(root);
    const auto output = root / "legacy-upgrade-output";

    REQUIRE(run_script(root,
                       harness.c_str(),
                       {},
                       0,
                       0,
                       output,
                       false,
                       owner,
                       token,
                       KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH) == 0);
    CHECK(read_file(output) ==
          "MODE=700\n"
          "READY=ready\n"
          "LEGACY-UPGRADE-OK\n");
    CHECK_FALSE(fs::exists(lock));
}

TEST_CASE("installer rejects symbolic links in inherited legacy lock") {
    TempDirectory directory;
    PausedProcess legacy_owner;
    const auto owner =
        std::to_string(static_cast<long>(legacy_owner.pid()));
    constexpr auto token = "legacy-inherited-token";

    for (const auto& unsafe_name :
         {std::string{"pid"}, std::string{"token"}, std::string{"ready"}}) {
        const auto root = directory.path / unsafe_name;
        const auto rescue = rescue_dir(root);
        const auto lock = root / "opt/var/run/keen-pbr-update.lock";
        fs::create_directories(rescue);
        fs::create_directories(lock);
        write_file(
            rescue / "update-lock.sh",
            "#!/bin/sh\n"
            "case \"${1:-}\" in\n"
            "  held)\n"
            "    [ \"$(cat \"$KEEN_PBR_RESCUE_ROOT/opt/var/run/keen-pbr-update.lock/pid\")\" = \"$2\" ] &&\n"
            "      [ \"$(cat \"$KEEN_PBR_RESCUE_ROOT/opt/var/run/keen-pbr-update.lock/token\")\" = \"$3\" ] &&\n"
            "      kill -0 \"$2\" 2>/dev/null\n"
            "    ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
            0700);
        write_file(lock / "pid", owner + "\n");
        write_file(lock / "token", std::string{token} + "\n");
        write_file(lock / "ready", "");

        const auto unsafe = lock / unsafe_name;
        REQUIRE(fs::remove(unsafe));
        const auto outside = root / ("outside-" + unsafe_name);
        if (unsafe_name == "pid")
            write_file(outside, owner + "\n");
        else if (unsafe_name == "token")
            write_file(outside, std::string{token} + "\n");
        else
            write_file(outside, "");
        REQUIRE(::symlink(outside.c_str(), unsafe.c_str()) == 0);

        const auto harness = write_install_lock_harness(root);
        CHECK(run_script(root,
                         harness.c_str(),
                         {},
                         0,
                         0,
                         {},
                         false,
                         owner,
                         token,
                         KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH) != 0);
        CHECK(fs::is_symlink(unsafe));
    }
}
