#include <doctest/doctest.h>

#include "../src/update/maintenance_lock.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <signal.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#ifndef KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH
#define KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH \
    "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/update-lock.sh"
#endif

#ifndef KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH
#define KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH \
    "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh"
#endif

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

class MaintenanceTempDir {
public:
    MaintenanceTempDir() {
        char pattern[] = "/tmp/keen-pbr-maintenance-client-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }
    ~MaintenanceTempDir() {
        std::error_code error;
        fs::remove_all(path, error);
    }

    fs::path path;
};

class ScopedEnvironmentVariable {
public:
    ScopedEnvironmentVariable(const char* name, const char* value)
        : name_(name) {
        if (const char* previous = ::getenv(name)) {
            previous_ = previous;
        }
        REQUIRE(::setenv(name, value, 1) == 0);
    }

    ~ScopedEnvironmentVariable() {
        if (previous_.has_value()) {
            (void)::setenv(name_.c_str(), previous_->c_str(), 1);
        } else {
            (void)::unsetenv(name_.c_str());
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_;
};

void write_executable(const fs::path& path,
                      const std::string& body) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << body;
    output.close();
    REQUIRE(output);
    REQUIRE(::chmod(path.c_str(), 0700) == 0);
}

fs::path copy_real_helper(const fs::path& directory) {
    std::ifstream input(
        KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH, std::ios::binary);
    REQUIRE(input);
    const std::string body{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>(),
    };
    const auto helper = directory / "update-lock.sh";
    write_executable(helper, body);
    std::ifstream metadata_input(
        KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH, std::ios::binary);
    REQUIRE(metadata_input);
    const std::string metadata_body{
        std::istreambuf_iterator<char>(metadata_input),
        std::istreambuf_iterator<char>(),
    };
    write_executable(
        directory / "root" /
            "opt/var/lib/keen-pbr/rescue/portable-stat.sh",
        metadata_body);
    REQUIRE(
        ::chmod(
            (directory / "root" / "opt/var/lib/keen-pbr/rescue").c_str(),
            0700) == 0);
    return helper;
}

MaintenanceCoordinatorTestOptions real_options(
    const fs::path& helper,
    const fs::path& root) {
    MaintenanceCoordinatorTestOptions options;
    options.helper_path = helper;
    options.rescue_root = root;
    options.command_timeout = std::chrono::seconds{3};
    options.ready_timeout = std::chrono::seconds{3};
    options.terminate_grace = std::chrono::milliseconds{200};
    return options;
}

MaintenanceCoordinatorTestOptions fake_options(
    const fs::path& helper) {
    MaintenanceCoordinatorTestOptions options;
    options.helper_path = helper;
    options.command_timeout = std::chrono::milliseconds{300};
    options.ready_timeout = std::chrono::milliseconds{150};
    options.terminate_grace = std::chrono::milliseconds{50};
    return options;
}

MaintenanceLockErrorKind capture_kind(
    const std::function<void()>& operation,
    int* exit_code = nullptr) {
    try {
        operation();
    } catch (const MaintenanceLockError& error) {
        if (exit_code != nullptr) {
            *exit_code = error.helper_exit_code();
        }
        return error.kind();
    }
    FAIL("maintenance operation was expected to fail");
    return MaintenanceLockErrorKind::system_error;
}

pid_t read_pid(const fs::path& path) {
    std::ifstream input(path);
    long value = -1;
    input >> value;
    REQUIRE(input);
    REQUIRE(value > 1);
    return static_cast<pid_t>(value);
}

bool wait_until_process_is_gone(
    pid_t pid,
    std::chrono::milliseconds timeout =
        std::chrono::milliseconds{500}) {
    const auto process_is_live = [pid]() {
        errno = 0;
        if (::kill(pid, 0) != 0) return errno != ESRCH;

        // A killed helper descendant can briefly remain as a zombie until
        // the container/host subreaper collects it. kill(pid, 0) still
        // succeeds for Z, but it cannot execute or retain the lifecycle lock.
        // Use the same liveness contract as the shipped update-lock helper.
        std::ifstream stat(fs::path("/proc") /
                           std::to_string(pid) / "stat");
        std::string line;
        if (!std::getline(stat, line)) return true;
        const auto comm_end = line.rfind(") ");
        if (comm_end == std::string::npos || comm_end + 2 >= line.size())
            return true;
        const char state = line[comm_end + 2];
        return state != 'Z' && state != 'X' && state != 'x';
    };
    const auto deadline =
        std::chrono::steady_clock::now() + timeout;
    do {
        if (!process_is_live()) return true;
        std::this_thread::sleep_for(
            std::chrono::milliseconds{5});
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
}

std::string valid_fake_helper_body(
    const std::string& reserve_body =
        "next=$(($4 + 1)); printf '%s\\n' \"$next\"") {
    return
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  protocol) printf '3\\n' ;;\n"
        "  guard)\n"
        "    printf '%s %s 0\\n' \"$3\" \"$4\"\n"
        "    while IFS= read -r _; do :; done\n"
        "    ;;\n"
        "  held) exit 0 ;;\n"
        "  release) exit 0 ;;\n"
        "  generation) printf '0\\n' ;;\n"
        "  sync-generation) printf '%s\\n' \"$4\" ;;\n"
        "  reserve)\n" +
        reserve_body +
        "\n    ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n";
}

} // namespace

TEST_CASE("maintenance coordinator holds protocol-3 guardian") {
    MaintenanceTempDir temporary;
    const auto helper = copy_real_helper(temporary.path);
    const auto root = temporary.path / "root";

    MaintenanceCoordinator coordinator(
        "backup-restore", real_options(helper, root));

    CHECK(coordinator.operation() == "backup-restore");
    CHECK(coordinator.base_generation() == 0);
    CHECK(coordinator.guardian_pid() > 1);
    CHECK(coordinator.borrow_owner_pid() == ::getpid());
    CHECK_FALSE(coordinator.borrow_token().empty());
    std::ifstream owner_record(
        root / "opt/var/run/keen-pbr-update.lock/owner");
    long authoritative_owner = -1;
    owner_record >> authoritative_owner;
    REQUIRE(owner_record);
    CHECK(authoritative_owner == static_cast<long>(::getpid()));
    CHECK(
        authoritative_owner !=
        static_cast<long>(coordinator.guardian_pid()));
    CHECK_NOTHROW(coordinator.verify_held());
}

TEST_CASE("maintenance coordinator distinguishes contention") {
    MaintenanceTempDir temporary;
    const auto helper = copy_real_helper(temporary.path);
    const auto root = temporary.path / "root";
    const auto options = real_options(helper, root);
    MaintenanceCoordinator owner("backup-restore", options);

    int exit_code = -1;
    CHECK(
        capture_kind(
            [&] {
                MaintenanceCoordinator contender(
                    "config-save", options);
            },
            &exit_code) == MaintenanceLockErrorKind::busy);
    CHECK(exit_code == 75);
    CHECK_NOTHROW(owner.verify_held());
}

TEST_CASE("maintenance coordinator reserves generation with CAS") {
    MaintenanceTempDir temporary;
    const auto helper = copy_real_helper(temporary.path);
    const auto root = temporary.path / "root";
    MaintenanceCoordinator coordinator(
        "backup-restore", real_options(helper, root));

    int exit_code = -1;
    CHECK(
        capture_kind(
            [&] { (void)coordinator.reserve(1); },
            &exit_code) ==
        MaintenanceLockErrorKind::stale_generation);
    CHECK(exit_code == 73);
    CHECK(coordinator.reserve(0) == 1);
    CHECK(
        capture_kind(
            [&] { (void)coordinator.reserve(0); },
            &exit_code) ==
        MaintenanceLockErrorKind::stale_generation);
    CHECK(coordinator.reserve(1) == 2);
    CHECK(coordinator.base_generation() == 0);
}

TEST_CASE(
    "maintenance coordinator reconciles generation committed before helper failure") {
    MaintenanceTempDir temporary;
    const auto helper = copy_real_helper(temporary.path);
    const auto root = temporary.path / "root";
    MaintenanceCoordinator coordinator(
        "backup-restore", real_options(helper, root));

    ScopedEnvironmentVariable injected_failure(
        "KEEN_PBR_UPDATE_LOCK_TEST_FAIL_GENERATION_AFTER_COMMIT",
        "1");
    CHECK(coordinator.reserve(0) == 1);
    CHECK(coordinator.reserve(1) == 2);
}

TEST_CASE(
    "maintenance coordinator fails closed when visible generation is not durable") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "generation-not-durable.sh";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        " protocol) printf '3\\n' ;;\n"
        " guard)\n"
        "   printf '%s %s 0\\n' \"$3\" \"$4\"\n"
        "   while IFS= read -r _; do :; done\n"
        "   ;;\n"
        " held) exit 0 ;;\n"
        " release) exit 0 ;;\n"
        " generation) printf '1\\n' ;;\n"
        " reserve) exit 74 ;;\n"
        " sync-generation) exit 74 ;;\n"
        " *) exit 2 ;;\n"
        "esac\n");
    MaintenanceCoordinator coordinator(
        "backup-restore", fake_options(helper));

    CHECK(
        capture_kind([&] { (void)coordinator.reserve(0); }) ==
        MaintenanceLockErrorKind::unsafe_state);
}

TEST_CASE("maintenance coordinator destructor releases guardian lease") {
    MaintenanceTempDir temporary;
    const auto helper = copy_real_helper(temporary.path);
    const auto root = temporary.path / "root";
    const auto options = real_options(helper, root);
    const auto lock =
        root / "opt/var/run/keen-pbr-update.lock";
    {
        MaintenanceCoordinator coordinator("config-save", options);
        REQUIRE(fs::exists(lock / "ready"));
    }

    CHECK_FALSE(fs::exists(lock));
    CHECK_NOTHROW(
        MaintenanceCoordinator("transport-save", options));
}

TEST_CASE("maintenance coordinator detects guardian death") {
    MaintenanceTempDir temporary;
    const auto helper = copy_real_helper(temporary.path);
    const auto root = temporary.path / "root";
    MaintenanceCoordinator coordinator(
        "backup-restore", real_options(helper, root));
    const pid_t guardian = coordinator.guardian_pid();
    REQUIRE(guardian > 1);
    REQUIRE(::kill(guardian, SIGKILL) == 0);

    bool detected = false;
    MaintenanceLockErrorKind detected_kind =
        MaintenanceLockErrorKind::system_error;
    for (int attempt = 0; attempt < 40 && !detected; ++attempt) {
        try {
            coordinator.verify_held();
        } catch (const MaintenanceLockError& error) {
            detected = true;
            detected_kind = error.kind();
        }
        if (!detected) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds{5});
        }
    }
    CHECK(detected);
    CHECK(detected_kind == MaintenanceLockErrorKind::guardian_died);
}

TEST_CASE(
    "killed guardian cannot release a live parent-owned maintenance lock") {
    MaintenanceTempDir temporary;
    const auto helper = copy_real_helper(temporary.path);
    const auto root = temporary.path / "root";
    const auto options = real_options(helper, root);

    {
        MaintenanceCoordinator owner("backup-restore", options);
        CHECK(owner.reserve(0) == 1);
        const pid_t guardian = owner.guardian_pid();
        REQUIRE(guardian > 1);
        REQUIRE(::kill(guardian, SIGKILL) == 0);

        bool guardian_death_detected = false;
        for (int attempt = 0;
             attempt < 40 && !guardian_death_detected;
             ++attempt) {
            try {
                owner.verify_held();
            } catch (const MaintenanceLockError& error) {
                CHECK(
                    error.kind() ==
                    MaintenanceLockErrorKind::guardian_died);
                guardian_death_detected = true;
            }
            if (!guardian_death_detected) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds{5});
            }
        }
        REQUIRE(guardian_death_detected);

        int exit_code = -1;
        CHECK(
            capture_kind(
                [&] {
                    MaintenanceCoordinator contender(
                        "config-save", options);
                },
                &exit_code) == MaintenanceLockErrorKind::busy);
        CHECK(exit_code == 75);
    }

    CHECK_NOTHROW(
        MaintenanceCoordinator("transport-save", options));
}

TEST_CASE("maintenance coordinator verifies ownership before reserve") {
    MaintenanceTempDir temporary;
    const auto helper = copy_real_helper(temporary.path);
    const auto root = temporary.path / "root";
    MaintenanceCoordinator coordinator(
        "backup-restore", real_options(helper, root));
    const auto lock =
        root / "opt/var/run/keen-pbr-update.lock";
    REQUIRE(fs::remove(lock / "ready"));

    CHECK(
        capture_kind([&] { (void)coordinator.reserve(0); }) ==
        MaintenanceLockErrorKind::unsafe_state);
    CHECK_FALSE(fs::exists(
        root / "opt/var/lib/keen-pbr/maintenance-generation"));
}

TEST_CASE("maintenance coordinator rejects unsupported protocol") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "protocol-2.sh";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "[ \"$1\" = protocol ] && { printf '2\\n'; exit 0; }\n"
        "exit 2\n");

    CHECK(
        capture_kind([&] {
            MaintenanceCoordinator coordinator(
                "backup-restore", fake_options(helper));
        }) == MaintenanceLockErrorKind::protocol_mismatch);
}

TEST_CASE("maintenance coordinator reports direct exec failure") {
    MaintenanceTempDir temporary;
    const auto missing = temporary.path / "missing-helper";

    CHECK(
        capture_kind([&] {
            MaintenanceCoordinator coordinator(
                "backup-restore", fake_options(missing));
        }) == MaintenanceLockErrorKind::helper_execution);
}

TEST_CASE(
    "maintenance coordinator removes inherited rescue root when disabled") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "environment-unset.sh";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "[ \"${KEEN_PBR_RESCUE_ROOT+x}\" != x ] || exit 41\n" +
            valid_fake_helper_body());
    ScopedEnvironmentVariable inherited_root(
        "KEEN_PBR_RESCUE_ROOT", "/untrusted/inherited/root");

    MaintenanceCoordinator coordinator(
        "backup-restore", fake_options(helper));

    CHECK_NOTHROW(coordinator.verify_held());
    CHECK(coordinator.reserve(0) == 1);
}

TEST_CASE(
    "maintenance coordinator replaces inherited rescue root for every helper") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "environment-replaced.sh";
    const auto expected_root = temporary.path / "expected-root";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "[ \"$KEEN_PBR_RESCUE_ROOT\" = \"" +
            expected_root.string() +
            "\" ] || exit 41\n" +
            valid_fake_helper_body());
    ScopedEnvironmentVariable inherited_root(
        "KEEN_PBR_RESCUE_ROOT", "/untrusted/inherited/root");
    auto options = fake_options(helper);
    options.rescue_root = expected_root;

    MaintenanceCoordinator coordinator(
        "backup-restore", options);

    CHECK_NOTHROW(coordinator.verify_held());
    CHECK(coordinator.reserve(0) == 1);
}

TEST_CASE(
    "maintenance coordinator does not inherit arbitrary daemon environment") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "environment-minimal.sh";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "[ \"${KEEN_PBR_SHOULD_NOT_LEAK+x}\" != x ] || exit 41\n" +
            valid_fake_helper_body());
    ScopedEnvironmentVariable untrusted(
        "KEEN_PBR_SHOULD_NOT_LEAK", "request-controlled");

    MaintenanceCoordinator coordinator(
        "backup-restore", fake_options(helper));
    CHECK_NOTHROW(coordinator.verify_held());
}

TEST_CASE(
    "maintenance coordinator rejects writable or symbolic-link helper") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "unsafe-helper.sh";
    write_executable(helper, valid_fake_helper_body());

    REQUIRE(::chmod(helper.c_str(), 0722) == 0);
    CHECK(
        capture_kind([&] {
            MaintenanceCoordinator coordinator(
                "backup-restore", fake_options(helper));
        }) == MaintenanceLockErrorKind::unsafe_state);

    REQUIRE(::chmod(helper.c_str(), 0700) == 0);
    const auto link = temporary.path / "helper-link.sh";
    REQUIRE(::symlink(helper.c_str(), link.c_str()) == 0);
    CHECK(
        capture_kind([&] {
            MaintenanceCoordinator coordinator(
                "backup-restore", fake_options(link));
        }) == MaintenanceLockErrorKind::unsafe_state);
}

TEST_CASE("maintenance coordinator rejects malformed ready record") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "malformed-ready.sh";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        " protocol) printf '3\\n' ;;\n"
        " guard) printf 'not-a-ready-record\\n'; sleep 10 ;;\n"
        " release) exit 0 ;;\n"
        " held) exit 1 ;;\n"
        " *) exit 2 ;;\n"
        "esac\n");

    CHECK(
        capture_kind([&] {
            MaintenanceCoordinator coordinator(
                "backup-restore", fake_options(helper));
        }) == MaintenanceLockErrorKind::malformed_response);
}

TEST_CASE("maintenance coordinator bounds guardian ready timeout") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "ready-timeout.sh";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        " protocol) printf '3\\n' ;;\n"
        " guard) sleep 10 ;;\n"
        " release) exit 0 ;;\n"
        " held) exit 1 ;;\n"
        " *) exit 2 ;;\n"
        "esac\n");

    CHECK(
        capture_kind([&] {
            MaintenanceCoordinator coordinator(
                "backup-restore", fake_options(helper));
        }) == MaintenanceLockErrorKind::timeout);
}

TEST_CASE("maintenance coordinator reaps timed out one-shot helper") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "command-timeout.sh";
    const auto pid_file = temporary.path / "command.pid";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "if [ \"$1\" = protocol ]; then\n"
        "  printf '%s\\n' \"$$\" > \"" +
            pid_file.string() +
            "\"\n"
            "  sleep 10\n"
            "fi\n"
            "exit 2\n");

    CHECK(
        capture_kind([&] {
            MaintenanceCoordinator coordinator(
                "backup-restore", fake_options(helper));
        }) == MaintenanceLockErrorKind::timeout);
    REQUIRE(fs::exists(pid_file));
    CHECK(wait_until_process_is_gone(read_pid(pid_file)));
}

TEST_CASE(
    "maintenance coordinator kills TERM-ignoring helper descendants") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "descendant-timeout.sh";
    const auto child_pid_file = temporary.path / "child.pid";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "if [ \"$1\" = protocol ]; then\n"
        "  sh -c 'trap \"\" TERM; sleep 10' &\n"
        "  child=$!\n"
        "  printf '%s\\n' \"$child\" > \"" +
            child_pid_file.string() +
            "\"\n"
            "  wait \"$child\"\n"
            "fi\n"
            "exit 2\n");

    CHECK(
        capture_kind([&] {
            MaintenanceCoordinator coordinator(
                "backup-restore", fake_options(helper));
        }) == MaintenanceLockErrorKind::timeout);
    REQUIRE(fs::exists(child_pid_file));
    CHECK(wait_until_process_is_gone(
        read_pid(child_pid_file), std::chrono::seconds{2}));
}

TEST_CASE("maintenance coordinator reaps timed out guardian") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "guardian-timeout.sh";
    const auto pid_file = temporary.path / "guardian.pid";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        " protocol) printf '3\\n' ;;\n"
        " guard)\n"
        "   printf '%s\\n' \"$$\" > \"" +
            pid_file.string() +
            "\"\n"
            "   sleep 10\n"
            "   ;;\n"
            " release) exit 0 ;;\n"
            " held) exit 1 ;;\n"
            " *) exit 2 ;;\n"
            "esac\n");

    CHECK(
        capture_kind([&] {
            MaintenanceCoordinator coordinator(
                "backup-restore", fake_options(helper));
        }) == MaintenanceLockErrorKind::timeout);
    REQUIRE(fs::exists(pid_file));
    CHECK(wait_until_process_is_gone(read_pid(pid_file)));
}

TEST_CASE("maintenance coordinator rejects malformed reserve response") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "bad-reserve.sh";
    write_executable(
        helper,
        valid_fake_helper_body("printf 'unexpected\\n'"));
    MaintenanceCoordinator coordinator(
        "backup-restore", fake_options(helper));

    CHECK(
        capture_kind([&] { (void)coordinator.reserve(0); }) ==
        MaintenanceLockErrorKind::malformed_response);
}

TEST_CASE("maintenance coordinator validates operation before exec") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "unused.sh";
    write_executable(helper, "#!/bin/sh\nexit 0\n");

    CHECK(
        capture_kind([&] {
            MaintenanceCoordinator coordinator(
                "../unsafe", fake_options(helper));
        }) == MaintenanceLockErrorKind::unsafe_state);
}

TEST_CASE(
    "maintenance coordinator serializes concurrent generation reservations") {
    MaintenanceTempDir temporary;
    const auto helper = copy_real_helper(temporary.path);
    const auto root = temporary.path / "root";
    MaintenanceCoordinator coordinator(
        "config-save", real_options(helper, root));

    std::atomic<int> successes{0};
    std::atomic<int> stale{0};
    auto reserve = [&] {
        try {
            if (coordinator.reserve(0) == 1) {
                ++successes;
            }
        } catch (const MaintenanceLockError& error) {
            if (error.kind() ==
                MaintenanceLockErrorKind::stale_generation) {
                ++stale;
            }
        }
    };
    std::thread first(reserve);
    std::thread second(reserve);
    first.join();
    second.join();

    CHECK(successes.load() == 1);
    CHECK(stale.load() == 1);
}

TEST_CASE(
    "maintenance coordinator retains credentials after failed release") {
    MaintenanceTempDir temporary;
    const auto helper = temporary.path / "release-retry.sh";
    const auto held_file = temporary.path / "held";
    const auto fail_file = temporary.path / "fail-release";
    write_executable(
        helper,
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        " protocol) printf '3\\n' ;;\n"
        " guard)\n"
        "   : > \"" +
            held_file.string() +
            "\"\n"
            "   printf '%s %s 0\\n' \"$3\" \"$4\"\n"
            "   while IFS= read -r _; do :; done\n"
            "   rm -f \"" +
            held_file.string() +
            "\"\n"
            "   ;;\n"
            " held) [ -f \"" +
            held_file.string() +
            "\" ] ;;\n"
            " release)\n"
            "   if [ -f \"" +
            fail_file.string() +
            "\" ]; then sleep 10; fi\n"
            "   rm -f \"" +
            held_file.string() +
            "\"\n"
            "   ;;\n"
            " generation) printf '0\\n' ;;\n"
            " sync-generation) printf '%s\\n' \"$4\" ;;\n"
            " reserve) printf '%s\\n' \"$(($4 + 1))\" ;;\n"
            " *) exit 2 ;;\n"
            "esac\n");
    {
        std::ofstream fail(fail_file);
        REQUIRE(fail);
    }
    {
        MaintenanceCoordinator coordinator(
            "config-save", fake_options(helper));
        const pid_t guardian = coordinator.guardian_pid();
        REQUIRE(guardian > 1);
        REQUIRE(::kill(guardian, SIGKILL) == 0);
        bool detected = false;
        for (int attempt = 0; attempt < 40 && !detected; ++attempt) {
            try {
                coordinator.verify_held();
            } catch (const MaintenanceLockError& error) {
                detected =
                    error.kind() ==
                    MaintenanceLockErrorKind::guardian_died;
            }
            if (!detected) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds{5});
            }
        }
        REQUIRE(detected);
    }
    REQUIRE(fs::exists(held_file));
    REQUIRE(fs::remove(fail_file));

    // Construction drains the retained PID/token pair before acquiring a new
    // lease, so the live daemon cannot remain permanently self-deadlocked.
    CHECK_NOTHROW(
        MaintenanceCoordinator("config-save", fake_options(helper)));
}

} // namespace keen_pbr3
