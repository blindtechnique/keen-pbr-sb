#include <doctest/doctest.h>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef KEEN_PBR_SSH_BOOT_GUARD_PATH
#define KEEN_PBR_SSH_BOOT_GUARD_PATH \
    "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/ssh-boot-guard.sh"
#endif

namespace {

namespace fs = std::filesystem;

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

void write_file(const fs::path& path, const std::string& body,
                bool executable = false) {
    fs::create_directories(path.parent_path());
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output << body;
    }
    if (executable) ::chmod(path.c_str(), 0755);
}

// A fake router: Entware's dropbear layout, a /proc with hand-written
// cmdlines, and a netstat whose LISTEN table is a file the test (and the
// fake S51dropbear) writes.
class FakeRouter {
public:
    FakeRouter() {
        std::string pattern =
            (fs::temp_directory_path() / "ssh-guard-XXXXXX").string();
        REQUIRE(::mkdtemp(&pattern[0]) != nullptr);
        root = pattern;
        fs::create_directories(root / "mock-bin");
        fs::create_directories(root / "proc");
        fs::create_directories(root / "opt/var/run");
        // netstat prints whatever the listeners file holds.
        write_file(root / "mock-bin/netstat",
                   "#!/bin/sh\ncat \"$KEEN_PBR_TEST_LISTENERS\" 2>/dev/null\n",
                   true);
        // logger is silent; the guard's stdout is what the test reads.
        write_file(root / "mock-bin/logger", "#!/bin/sh\nexit 0\n", true);
    }
    ~FakeRouter() {
        std::error_code error;
        fs::remove_all(root, error);
    }

    void install_entware_dropbear(const std::string& port = "222") {
        write_file(root / "opt/sbin/dropbear", "#!/bin/sh\nexit 0\n", true);
        write_file(root / "opt/etc/config/dropbear.conf",
                   "# Entware dropbear\nPORT=" + port + "\n");
        // The init script records each start and, when told to, makes the
        // listener appear by installing the prepared netstat table.
        write_file(root / "opt/etc/init.d/S51dropbear",
                   "#!/bin/sh\n"
                   "echo \"$1\" >> \"$KEEN_PBR_TEST_INIT_LOG\"\n"
                   "if [ \"$1\" = start ] && [ -f \"$KEEN_PBR_TEST_AFTER_START\" ]; then\n"
                   "  cp \"$KEEN_PBR_TEST_AFTER_START\" \"$KEEN_PBR_TEST_LISTENERS\"\n"
                   "fi\n"
                   "exit 0\n",
                   true);
    }

    void process(const std::string& pid, const std::string& cmdline_spaced) {
        std::string cmdline = cmdline_spaced;
        for (auto& c : cmdline) {
            if (c == ' ') c = '\0';
        }
        cmdline.push_back('\0');
        write_file(root / "proc" / pid / "cmdline", cmdline);
    }

    static std::string listen_row(const std::string& local,
                                  const std::string& pid,
                                  const std::string& program) {
        return "tcp        0      0 " + local +
               "            0.0.0.0:*               LISTEN      " + pid +
               "/" + program + "\n";
    }

    void listeners(const std::string& table) {
        write_file(root / "listeners", table);
    }
    void listeners_after_start(const std::string& table) {
        write_file(root / "after-start", table);
    }
    void pidfile(const std::string& body) {
        write_file(root / "opt/var/run/dropbear.pid", body);
    }
    bool pidfile_exists() const {
        return fs::exists(root / "opt/var/run/dropbear.pid");
    }
    std::string init_log() const { return read_file(root / "init.log"); }
    std::string output() const { return read_file(root / "stdout"); }

    int run(const std::string& attempts = "2") {
        const auto pid = ::fork();
        REQUIRE(pid >= 0);
        if (pid == 0) {
            const auto path =
                (root / "mock-bin").string() + ":/usr/bin:/bin";
            ::setenv("KEEN_PBR_SSH_GUARD_ROOT", root.c_str(), 1);
            ::setenv("KEEN_PBR_SSH_GUARD_PROC", (root / "proc").c_str(), 1);
            ::setenv("KEEN_PBR_SSH_GUARD_PATH", path.c_str(), 1);
            ::setenv("KEEN_PBR_SSH_GUARD_ATTEMPTS", attempts.c_str(), 1);
            ::setenv("KEEN_PBR_SSH_GUARD_BACKOFF", "0", 1);
            ::setenv("KEEN_PBR_SSH_GUARD_BIND_WAIT", "0", 1);
            ::setenv("KEEN_PBR_TEST_LISTENERS", (root / "listeners").c_str(),
                     1);
            ::setenv("KEEN_PBR_TEST_AFTER_START",
                     (root / "after-start").c_str(), 1);
            ::setenv("KEEN_PBR_TEST_INIT_LOG", (root / "init.log").c_str(),
                     1);
            const int out = ::open((root / "stdout").c_str(),
                                   O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (out < 0 || ::dup2(out, STDOUT_FILENO) < 0) _exit(126);
            ::close(out);
            const char* argv[] = {"/bin/sh", KEEN_PBR_SSH_BOOT_GUARD_PATH,
                                  nullptr};
            ::execv(argv[0], const_cast<char**>(argv));
            _exit(127);
        }
        int status = 0;
        while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    fs::path root;
};

} // namespace

TEST_CASE("without Entware dropbear there is nothing to guard") {
    FakeRouter router;
    CHECK(router.run() == 0);
    CHECK(router.output().find("nothing to guard") != std::string::npos);
    CHECK(router.init_log().empty());
}

TEST_CASE("an Entware dropbear that owns the port is left exactly as it is") {
    FakeRouter router;
    router.install_entware_dropbear();
    const auto entware = (router.root / "opt/sbin/dropbear").string();
    router.process("988", entware + " -p 222 -P /opt/var/run/dropbear.pid");
    router.listeners(FakeRouter::listen_row("0.0.0.0:222", "988", "dropbear"));
    router.pidfile("988\n");
    CHECK(router.run() == 0);
    CHECK(router.output().find("pid 988) is listening on :222") !=
          std::string::npos);
    CHECK(router.init_log().empty());
    CHECK(router.pidfile_exists());
}

TEST_CASE("the stock daemon on the Entware port is reported, never fought") {
    FakeRouter router;
    router.install_entware_dropbear();
    // Stock dropbear on the Entware port, and on its own as well: the guard
    // must not be fooled by the program name matching.
    router.process("880", "/usr/sbin/dropbear");
    router.listeners(FakeRouter::listen_row("0.0.0.0:4122", "880", "dropbear") +
                     FakeRouter::listen_row(":::222", "880", "dropbear"));
    router.pidfile("880\n");
    CHECK(router.run() == 3);
    CHECK(router.output().find("not by Entware dropbear") != std::string::npos);
    CHECK(router.init_log().empty());
    CHECK(router.pidfile_exists());
}

TEST_CASE("a stale pidfile pointing at a reused pid is cleared and dropbear started") {
    FakeRouter router;
    router.install_entware_dropbear();
    const auto entware = (router.root / "opt/sbin/dropbear").string();
    // After the reboot pid 700 is somebody else entirely; the USB-backed
    // pidfile still names it. The stock daemon listens only on its port.
    router.process("700", "/usr/sbin/ndm");
    router.process("880", "/usr/sbin/dropbear");
    router.listeners(FakeRouter::listen_row("0.0.0.0:4122", "880", "dropbear"));
    router.pidfile("700\n");
    // Once S51dropbear start runs, the Entware daemon binds.
    router.process("1200", entware + " -p 222 -P /opt/var/run/dropbear.pid");
    router.listeners_after_start(
        FakeRouter::listen_row("0.0.0.0:4122", "880", "dropbear") +
        FakeRouter::listen_row("0.0.0.0:222", "1200", "dropbear"));

    CHECK(router.run() == 0);
    const auto output = router.output();
    CHECK(output.find("removing stale pidfile") != std::string::npos);
    CHECK(output.find("pid 700 is not Entware dropbear") != std::string::npos);
    CHECK(output.find("pid 1200) now listens on :222") != std::string::npos);
    CHECK(router.init_log() == "start\n");
}

TEST_CASE("a start that never produces a listener is bounded and reported") {
    FakeRouter router;
    router.install_entware_dropbear();
    router.listeners("");
    CHECK(router.run("2") == 1);
    CHECK(router.output().find("did not come up on :222 after 2 attempts") !=
          std::string::npos);
    CHECK(router.init_log() == "start\nstart\n");
}

TEST_CASE("the port is read from the conf, and an unreadable port refuses to guess") {
    FakeRouter router;
    router.install_entware_dropbear("2222");
    const auto entware = (router.root / "opt/sbin/dropbear").string();
    router.process("50", entware + " -p 2222");
    router.listeners(FakeRouter::listen_row("0.0.0.0:2222", "50", "dropbear") +
                     FakeRouter::listen_row("0.0.0.0:222", "880", "dropbear"));
    CHECK(router.run() == 0);
    CHECK(router.output().find("listening on :2222") != std::string::npos);

    write_file(router.root / "opt/etc/config/dropbear.conf", "PORT=$(id)\n");
    CHECK(router.run() == 2);
    CHECK(router.init_log().empty());
}

TEST_CASE("an Entware dropbear that is still binding is given its window") {
    FakeRouter router;
    router.install_entware_dropbear();
    const auto entware = (router.root / "opt/sbin/dropbear").string();
    router.process("988", entware + " -p 222 -P /opt/var/run/dropbear.pid");
    router.pidfile("988\n");
    // Not listening yet and the bind window is zero in tests, so the pidfile
    // is judged stale and a start is issued - after which the listener
    // belongs to the very same pid.
    router.listeners("");
    router.listeners_after_start(
        FakeRouter::listen_row("0.0.0.0:222", "988", "dropbear"));
    CHECK(router.run() == 0);
    CHECK(router.output().find("treating the pidfile as stale") !=
          std::string::npos);
    CHECK(router.init_log() == "start\n");
}
