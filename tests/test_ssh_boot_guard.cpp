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

// BusyBox netstat -tlnp as the router prints it: a header, then rows whose
// last column is "pid/program" or "-" when the socket cannot be attributed.
const char* kNetstatHeader =
    "Active Internet connections (only servers)\n"
    "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n";

// A fake router: Entware's dropbear layout, a /proc with hand-written
// cmdlines and exe links, and a netstat whose table is a file the test (and
// the fake S51dropbear) writes. The fake netstat counts its invocations so a
// test can make the listener appear only after the guard has waited.
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
        write_file(root / "mock-bin/netstat",
                   "#!/bin/sh\n"
                   "n=$(cat \"$KEEN_PBR_TEST_NETSTAT_CALLS\" 2>/dev/null || echo 0)\n"
                   "n=$((n + 1)); echo $n > \"$KEEN_PBR_TEST_NETSTAT_CALLS\"\n"
                   "if [ -n \"${KEEN_PBR_TEST_LISTENERS_FROM_CALL:-}\" ] &&\n"
                   "   [ $n -ge \"$KEEN_PBR_TEST_LISTENERS_FROM_CALL\" ] &&\n"
                   "   [ -f \"$KEEN_PBR_TEST_LISTENERS_LATER\" ]; then\n"
                   "  cat \"$KEEN_PBR_TEST_LISTENERS_LATER\"; exit 0\n"
                   "fi\n"
                   "cat \"$KEEN_PBR_TEST_LISTENERS\" 2>/dev/null\n",
                   true);
        write_file(root / "mock-bin/logger", "#!/bin/sh\nexit 0\n", true);
    }
    ~FakeRouter() {
        std::error_code error;
        fs::remove_all(root, error);
    }

    void install_entware_dropbear(const std::string& conf = "PORT=222\n") {
        write_file(root / "opt/sbin/dropbear", "#!/bin/sh\nexit 0\n", true);
        write_file(root / "opt/etc/config/dropbear.conf",
                   "# Entware dropbear\n" + conf);
        write_file(root / "opt/etc/init.d/S51dropbear",
                   "#!/bin/sh\n"
                   "echo \"$1\" >> \"$KEEN_PBR_TEST_INIT_LOG\"\n"
                   "if [ \"$1\" = start ] && [ -f \"$KEEN_PBR_TEST_AFTER_START\" ]; then\n"
                   "  cp \"$KEEN_PBR_TEST_AFTER_START\" \"$KEEN_PBR_TEST_LISTENERS\"\n"
                   "fi\n"
                   "exit 0\n",
                   true);
    }

    std::string entware_binary() const {
        return (root / "opt/sbin/dropbear").string();
    }

    // A process as /proc shows it: cmdline (space-separated here) and the
    // exe link. `exe` empty means the link is unreadable.
    void process(const std::string& pid, const std::string& cmdline_spaced,
                 const std::string& exe) {
        std::string cmdline = cmdline_spaced;
        for (auto& c : cmdline) {
            if (c == ' ') c = '\0';
        }
        cmdline.push_back('\0');
        write_file(root / "proc" / pid / "cmdline", cmdline);
        if (!exe.empty()) {
            fs::create_symlink(exe, root / "proc" / pid / "exe");
        }
    }
    void entware_process(const std::string& pid,
                         const std::string& arguments = "-p 222 -P /opt/var/run/dropbear.pid") {
        process(pid, entware_binary() + " " + arguments, entware_binary());
    }
    void stock_process(const std::string& pid) {
        process(pid, "/usr/sbin/dropbear", "/usr/sbin/dropbear");
    }

    static std::string listen_row(const std::string& local,
                                  const std::string& owner) {
        return "tcp        0      0 " + local +
               "            0.0.0.0:*               LISTEN      " + owner +
               "\n";
    }

    void listeners(const std::string& rows) {
        write_file(root / "listeners", kNetstatHeader + rows);
    }
    void listeners_after_start(const std::string& rows) {
        write_file(root / "after-start", kNetstatHeader + rows);
    }
    // From the N-th netstat call on, this table is printed instead.
    void listeners_from_call(int call, const std::string& rows) {
        write_file(root / "later", kNetstatHeader + rows);
        listeners_from = std::to_string(call);
    }
    void no_netstat() {
        // Keep the shim first on PATH. Removing it would let a host-provided
        // netstat satisfy the lookup, so the test would no longer model a
        // missing command on developer machines or GitHub runners that ship
        // net-tools.
        write_file(root / "mock-bin/netstat", "#!/bin/sh\nexit 127\n", true);
    }
    void pidfile(const std::string& body) {
        write_file(root / "opt/var/run/dropbear.pid", body);
    }
    bool pidfile_exists() const {
        return fs::exists(root / "opt/var/run/dropbear.pid");
    }
    std::string init_log() const { return read_file(root / "init.log"); }
    std::string output() const { return read_file(root / "stdout"); }
    int netstat_calls() const {
        const auto body = read_file(root / "netstat-calls");
        return body.empty() ? 0 : std::stoi(body);
    }

    int run(const std::string& attempts = "2",
            const std::string& bind_wait = "0") {
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
            ::setenv("KEEN_PBR_SSH_GUARD_BIND_WAIT", bind_wait.c_str(), 1);
            ::setenv("KEEN_PBR_TEST_LISTENERS", (root / "listeners").c_str(),
                     1);
            ::setenv("KEEN_PBR_TEST_LISTENERS_LATER", (root / "later").c_str(),
                     1);
            ::setenv("KEEN_PBR_TEST_LISTENERS_FROM_CALL",
                     listeners_from.c_str(), 1);
            ::setenv("KEEN_PBR_TEST_NETSTAT_CALLS",
                     (root / "netstat-calls").c_str(), 1);
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
    std::string listeners_from;
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
    router.entware_process("988");
    router.listeners(FakeRouter::listen_row("0.0.0.0:222", "988/dropbear"));
    router.pidfile("988\n");
    CHECK(router.run() == 0);
    CHECK(router.output().find("pid 988) is listening on :222") !=
          std::string::npos);
    CHECK(router.init_log().empty());
    CHECK(router.pidfile_exists());
}

TEST_CASE("identity is the executable, so a PATH-started dropbear still counts") {
    // rc.func vintage: `dropbear -p 222` found on PATH; cmdline has no
    // path, the exe link has. A daemon whose binary was replaced by an
    // upgrade shows "(deleted)" and is still the Entware one.
    FakeRouter router;
    router.install_entware_dropbear();
    router.process("988", "dropbear -p 222", router.entware_binary());
    router.listeners(FakeRouter::listen_row("0.0.0.0:222", "988/dropbear"));
    CHECK(router.run() == 0);

    FakeRouter upgraded;
    upgraded.install_entware_dropbear();
    upgraded.process("989", "dropbear -p 222",
                     upgraded.entware_binary() + " (deleted)");
    upgraded.listeners(FakeRouter::listen_row(":::222", "989/dropbear"));
    CHECK(upgraded.run() == 0);
    CHECK(upgraded.output().find("pid 989) is listening") != std::string::npos);
}

TEST_CASE("the stock daemon on the Entware port is reported, never fought") {
    FakeRouter router;
    router.install_entware_dropbear();
    // The stock daemon's program name is also "dropbear": the name proves
    // nothing, the executable does.
    router.stock_process("880");
    router.listeners(FakeRouter::listen_row("0.0.0.0:4122", "880/dropbear") +
                     FakeRouter::listen_row(":::222", "880/dropbear"));
    router.pidfile("880\n");
    CHECK(router.run() == 3);
    CHECK(router.output().find("not by Entware dropbear") != std::string::npos);
    CHECK(router.init_log().empty());
    CHECK(router.pidfile_exists());
}

TEST_CASE("a socket netstat cannot attribute is an unknown owner, not nobody") {
    FakeRouter router;
    router.install_entware_dropbear();
    router.entware_process("988");
    router.pidfile("988\n");
    router.listeners(FakeRouter::listen_row("127.0.0.1:7001", "-") +
                     FakeRouter::listen_row("0.0.0.0:222", "-"));
    CHECK(router.run() == 3);
    CHECK(router.output().find("an unattributed process") != std::string::npos);
    CHECK(router.init_log().empty());
    CHECK(router.pidfile_exists());
}

TEST_CASE("an unreadable socket table touches nothing") {
    FakeRouter router;
    router.install_entware_dropbear();
    router.entware_process("988");
    router.pidfile("988\n");

    SUBCASE("netstat is missing") {
        router.no_netstat();
    }
    SUBCASE("netstat prints nothing") {
        write_file(router.root / "listeners", "");
    }
    CHECK(router.run() == 2);
    CHECK(router.output().find("socket table could not be read") !=
          std::string::npos);
    CHECK(router.init_log().empty());
    CHECK(router.pidfile_exists());
}

TEST_CASE("a stale pidfile pointing at a reused pid is cleared and dropbear started") {
    FakeRouter router;
    router.install_entware_dropbear();
    // After the reboot pid 700 is somebody else entirely; the USB-backed
    // pidfile still names it. The stock daemon listens only on its port.
    router.process("700", "/usr/sbin/ndm", "/usr/sbin/ndm");
    router.stock_process("880");
    router.listeners(FakeRouter::listen_row("0.0.0.0:4122", "880/dropbear"));
    router.pidfile("700\n");
    router.entware_process("1200");
    router.listeners_after_start(
        FakeRouter::listen_row("0.0.0.0:4122", "880/dropbear") +
        FakeRouter::listen_row("0.0.0.0:222", "1200/dropbear"));

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

TEST_CASE("the port and pidfile come from the conf as Entware writes them") {
    FakeRouter router;
    router.install_entware_dropbear(
        "PORT=2222\nPIDFILE=\"/opt/var/run/db.pid\"\n");
    router.entware_process("50", "-p 2222 -P /opt/var/run/db.pid");
    router.listeners(FakeRouter::listen_row("0.0.0.0:2222", "50/dropbear") +
                     FakeRouter::listen_row("0.0.0.0:222", "880/dropbear"));
    CHECK(router.run() == 0);
    CHECK(router.output().find("listening on :2222") != std::string::npos);

    // The configured pidfile is the one judged: it names a reused pid, so
    // it is removed; the default path is not consulted.
    router.listeners("");
    write_file(router.root / "opt/var/run/db.pid", "700\n");
    router.process("700", "/usr/sbin/ndm", "/usr/sbin/ndm");
    router.pidfile("keep\n");
    router.entware_process("51", "-p 2222 -P /opt/var/run/db.pid");
    router.listeners_after_start(
        FakeRouter::listen_row("0.0.0.0:2222", "51/dropbear"));
    CHECK(router.run() == 0);
    CHECK_FALSE(fs::exists(router.root / "opt/var/run/db.pid"));
    CHECK(router.pidfile_exists());

    // An unreadable port refuses to guess.
    write_file(router.root / "opt/etc/config/dropbear.conf", "PORT=$(id)\n");
    CHECK(router.run() == 2);
}

TEST_CASE("an Entware dropbear that is still binding is given its window") {
    FakeRouter router;
    router.install_entware_dropbear();
    router.entware_process("988");
    router.pidfile("988\n");
    // Not listening on the first two looks, listening from the third:
    // the guard waits instead of declaring the pidfile stale, and issues
    // no start.
    router.listeners("");
    router.listeners_from_call(
        3, FakeRouter::listen_row("0.0.0.0:222", "988/dropbear"));
    CHECK(router.run("2", "3") == 0);
    CHECK(router.output().find("pid 988) came up on :222") !=
          std::string::npos);
    CHECK(router.init_log().empty());
    CHECK(router.pidfile_exists());
    CHECK(router.netstat_calls() >= 3);
}

TEST_CASE("an Entware dropbear listening on another port is not this guard's to replace") {
    FakeRouter router;
    router.install_entware_dropbear();
    // PORT was edited to 222 without a restart; the daemon the pidfile
    // names still serves 2222. Starting a second one would leave the first
    // unmanageable through S51dropbear's pidfile.
    router.entware_process("988", "-p 2222");
    router.pidfile("988\n");
    router.listeners(FakeRouter::listen_row("0.0.0.0:2222", "988/dropbear"));
    CHECK(router.run() == 3);
    CHECK(router.output().find("listening on another port") !=
          std::string::npos);
    CHECK(router.init_log().empty());
    CHECK(router.pidfile_exists());

    // Whereas one that listens nowhere - a leftover session child after
    // the listener died - is stale, and the start goes ahead.
    router.listeners("");
    router.entware_process("1300");
    router.listeners_after_start(
        FakeRouter::listen_row("0.0.0.0:222", "1300/dropbear"));
    CHECK(router.run() == 0);
    CHECK(router.output().find("listens nowhere; treating the pidfile as stale") !=
          std::string::npos);
    CHECK(router.init_log() == "start\n");
}
