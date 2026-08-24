#include <doctest/doctest.h>

#include "../src/update/component_package_transaction.hpp"
#include "../src/crypto/sha256.hpp"

#include <zlib.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

struct TempRoot {
    fs::path path;
    TempRoot() {
        std::string pattern =
            (fs::temp_directory_path() / "pkg-txn-XXXXXX").string();
        REQUIRE(::mkdtemp(&pattern[0]) != nullptr);
        path = pattern;
    }
    ~TempRoot() {
        std::error_code error;
        fs::remove_all(path, error);
    }
};

std::string digest_of(const std::string& bytes) {
    Sha256 hasher;
    hasher.update(bytes);
    return hasher.hex_digest();
}

std::string gzip(const std::string& plain) {
    z_stream stream{};
    REQUIRE(deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, 16 + MAX_WBITS,
                         8, Z_DEFAULT_STRATEGY) == Z_OK);
    std::string out(deflateBound(&stream, plain.size()) + 64, '\0');
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(plain.data()));
    stream.avail_in = static_cast<uInt>(plain.size());
    stream.next_out = reinterpret_cast<Bytef*>(&out[0]);
    stream.avail_out = static_cast<uInt>(out.size());
    REQUIRE(deflate(&stream, Z_FINISH) == Z_STREAM_END);
    out.resize(stream.total_out);
    deflateEnd(&stream);
    return out;
}

void write_file(const fs::path& path, const std::string& body) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << body;
}

std::string feed_stanza(const std::string& version, const std::string& bytes) {
    return "Package: nfqws2-keenetic\nVersion: " + version +
           "\nArchitecture: all\nFilename: nfqws2-keenetic_" + version +
           "_all_entware.ipk\nSize: " + std::to_string(bytes.size()) +
           "\nSHA256sum: " + digest_of(bytes) + "\nDescription: test\n\n";
}

// A runner that behaves like opkg for the commands the transaction issues.
struct FakeOpkg {
    std::vector<std::vector<std::string>> commands;
    // What `opkg download` writes, and under which name.
    std::string served_bytes;
    std::string served_filename;
    int update_exit{0};
    int download_exit{0};
    int install_exit{0};
    bool install_uncertain{false};

    // Every working directory the runner was handed, one per command, so a
    // test can show the download - and only the download - ran inside the
    // store's staging directory.
    std::vector<fs::path> working_directories;

    ComponentCommandRunner runner() {
        return [this](const std::vector<std::string>& argv,
                      SafeExecTimeouts, const fs::path& cwd) {
            commands.push_back(argv);
            working_directories.push_back(cwd);
            ExecCaptureResult result;
            REQUIRE_FALSE(argv.empty());
            CHECK(argv[0] == "/opt/bin/opkg");
            if (argv.size() == 2 && argv[1] == "update") {
                CHECK(cwd.empty());
                result.exit_code = update_exit;
                result.stdout_output = "Updated list of available packages\n";
                return result;
            }
            if (argv.size() == 3 && argv[1] == "download") {
                // opkg writes into its working directory; the transaction
                // must have pointed it at the staging directory, never at
                // the daemon's own cwd.
                CHECK(argv[2] == "nfqws2-keenetic");
                REQUIRE_FALSE(cwd.empty());
                REQUIRE(fs::is_directory(cwd));
                if (download_exit == 0) {
                    write_file(cwd / served_filename, served_bytes);
                }
                result.exit_code = download_exit;
                return result;
            }
            if (argv.size() >= 3 && argv[1] == "install") {
                CHECK(cwd.empty());
                result.exit_code = install_exit;
                result.termination_uncertain = install_uncertain;
                result.stdout_output = "Installing\n";
                return result;
            }
            FAIL("unexpected command " << argv[0] << " " << argv[1]);
            return result;
        };
    }
};

ComponentPackageOptions options_for(const TempRoot& root) {
    ComponentPackageOptions options;
    options.package = "nfqws2-keenetic";
    options.feed_list = root.path / "feed-list";
    return options;
}

} // namespace

TEST_CASE("an up-to-date install retains its exact ipk while the feed serves it") {
    TempRoot root;
    const std::string bytes = "ipk 1.2.4";
    write_file(root.path / "feed-list", gzip(feed_stanza("1.2.4", bytes)));
    FakeOpkg opkg;
    opkg.served_bytes = bytes;
    opkg.served_filename = "nfqws2-keenetic_1.2.4_all_entware.ipk";
    ComponentIpkStore store(root.path / "components", "nfqws2-keenetic");
    ComponentPackageTransaction txn(options_for(root), store, opkg.runner());

    const auto prep = txn.prepare("1.2.4");
    CHECK(prep.error.empty());
    CHECK(prep.feed_updated);
    CHECK(prep.feed_read);
    CHECK(prep.up_to_date);
    CHECK_FALSE(prep.target.has_value());
    CHECK(prep.retention == IpkRetentionAction::retain_now);
    CHECK(prep.previous_exact);
    CHECK_FALSE(prep.candidate_verified);
    REQUIRE(opkg.commands.size() == 2U);
    CHECK(opkg.commands[0] ==
          std::vector<std::string>{"/opt/bin/opkg", "update"});
    CHECK(opkg.commands[1] == std::vector<std::string>{
                                  "/opt/bin/opkg", "download",
                                  "nfqws2-keenetic"});
    REQUIRE(opkg.working_directories.size() == 2U);
    CHECK(opkg.working_directories[0].empty());
    CHECK(opkg.working_directories[1] == store.directory() / "staging");
    CHECK(store.inspect(IpkSlot::current).retained->version == "1.2.4");
    CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
    // The staged download was consumed, not left around.
    CHECK_FALSE(fs::exists(store.directory() / "staging" /
                           "nfqws2-keenetic_1.2.4_all_entware.ipk"));
    CHECK(prep.output.find("retained") != std::string::npos);

    // Second run: nothing to fetch.
    const auto again = txn.prepare("1.2.4");
    CHECK(again.retention == IpkRetentionAction::already_retained);
    CHECK(again.previous_exact);
    CHECK(opkg.commands.size() == 3U);
}

TEST_CASE("a newer feed version is verified into candidate and installed from the file") {
    TempRoot root;
    const std::string old_bytes = "ipk 1.2.4";
    const std::string new_bytes = "ipk 1.2.5 with more";
    ComponentIpkStore store(root.path / "components", "nfqws2-keenetic");
    {
        FeedPackageEntry old_entry;
        old_entry.package = "nfqws2-keenetic";
        old_entry.version = "1.2.4";
        old_entry.filename = "nfqws2-keenetic_1.2.4_all_entware.ipk";
        old_entry.size = old_bytes.size();
        old_entry.sha256 = digest_of(old_bytes);
        store.adopt(IpkSlot::current, old_bytes, old_entry);
    }
    write_file(root.path / "feed-list", feed_stanza("1.2.5", new_bytes));
    FakeOpkg opkg;
    opkg.served_bytes = new_bytes;
    opkg.served_filename = "nfqws2-keenetic_1.2.5_all_entware.ipk";
    ComponentPackageTransaction txn(options_for(root), store, opkg.runner());

    const auto prep = txn.prepare("1.2.4");
    CHECK(prep.error.empty());
    REQUIRE(prep.target.has_value());
    CHECK(prep.target->version == "1.2.5");
    CHECK_FALSE(prep.up_to_date);
    CHECK(prep.candidate_verified);
    CHECK(prep.previous_exact);
    CHECK(prep.retention == IpkRetentionAction::already_retained);
    CHECK(store.inspect(IpkSlot::candidate).retained->version == "1.2.5");

    const auto install = txn.install_candidate();
    CHECK(install.exit_code == 0);
    REQUIRE(opkg.commands.size() == 3U);
    CHECK(opkg.commands[2] == std::vector<std::string>{
                                  "/opt/bin/opkg", "install",
                                  (store.directory() / "candidate.ipk").string()});

    SUBCASE("proven installed: candidate becomes current") {
        txn.promote_installed_candidate();
        CHECK(store.inspect(IpkSlot::current).retained->version == "1.2.5");
        CHECK(store.inspect(IpkSlot::previous).retained->version == "1.2.4");
        CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
    }
    SUBCASE("failed: the exact previous ipk is reinstalled") {
        const auto rollback = txn.reinstall_current("1.2.4");
        CHECK(rollback.exit_code == 0);
        REQUIRE(opkg.commands.size() == 4U);
        CHECK(opkg.commands[3] == std::vector<std::string>{
                                      "/opt/bin/opkg", "install",
                                      "--force-downgrade", "--force-reinstall",
                                      (store.directory() / "current.ipk").string()});
        // The wrong expectation is refused without running anything, and
        // the refusal is an exception, not an exit code: a refusal must
        // never read as a package manager that ran and failed.
        CHECK_THROWS_AS(txn.reinstall_current("1.2.3"),
                        ComponentPackageRefused);
        CHECK(opkg.commands.size() == 4U);
    }
}

TEST_CASE("without a retained copy the upgrade still stages but says rollback is inexact") {
    TempRoot root;
    const std::string new_bytes = "ipk 1.2.5";
    write_file(root.path / "feed-list", feed_stanza("1.2.5", new_bytes));
    FakeOpkg opkg;
    opkg.served_bytes = new_bytes;
    opkg.served_filename = "nfqws2-keenetic_1.2.5_all_entware.ipk";
    ComponentIpkStore store(root.path / "components", "nfqws2-keenetic");
    ComponentPackageTransaction txn(options_for(root), store, opkg.runner());

    const auto prep = txn.prepare("1.2.4");
    CHECK(prep.error.empty());
    CHECK(prep.candidate_verified);
    CHECK_FALSE(prep.previous_exact);
    CHECK(prep.retention == IpkRetentionAction::unavailable);
    CHECK(prep.output.find("No exact copy of the installed version 1.2.4") !=
          std::string::npos);
    CHECK_THROWS_WITH_AS(txn.reinstall_current("1.2.4"),
                         doctest::Contains("no exact copy"),
                         ComponentPackageRefused);
    CHECK(opkg.commands.size() == 2U);
}

TEST_CASE("bytes that differ from the feed index never become a candidate") {
    TempRoot root;
    const std::string new_bytes = "ipk 1.2.5";
    write_file(root.path / "feed-list", feed_stanza("1.2.5", new_bytes));
    FakeOpkg opkg;
    // Same length as the feed's bytes, different content: this is the
    // SHA-256 path, which only a same-size tampering reaches.
    opkg.served_bytes = "ipk 1.2.X";
    REQUIRE(opkg.served_bytes.size() == new_bytes.size());
    opkg.served_filename = "nfqws2-keenetic_1.2.5_all_entware.ipk";
    ComponentIpkStore store(root.path / "components", "nfqws2-keenetic");
    ComponentPackageTransaction txn(options_for(root), store, opkg.runner());

    const auto prep = txn.prepare("1.2.4");
    CHECK(prep.error.find("refused") != std::string::npos);
    CHECK(prep.error.find("digest") != std::string::npos);
    CHECK_FALSE(prep.candidate_verified);
    CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
    // And install refuses rather than running opkg against nothing.
    CHECK_THROWS_AS(txn.install_candidate(), ComponentPackageRefused);
    CHECK(opkg.commands.size() == 2U);

    // Wrong size is caught before the digest is even computed: the file is
    // read with the feed's Size as the ceiling.
    opkg.served_bytes = new_bytes + "x";
    const auto larger = txn.prepare("1.2.4");
    CHECK(larger.error.find("not the size the feed promised") !=
          std::string::npos);
    CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
    opkg.served_bytes = new_bytes.substr(0, new_bytes.size() - 1);
    const auto smaller = txn.prepare("1.2.4");
    CHECK(smaller.error.find("refused") != std::string::npos);
    CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
}

TEST_CASE("preparation stops at the first failed step and touches nothing") {
    TempRoot root;
    const std::string bytes = "ipk 1.2.5";
    ComponentIpkStore store(root.path / "components", "nfqws2-keenetic");

    SUBCASE("opkg update fails") {
        write_file(root.path / "feed-list", feed_stanza("1.2.5", bytes));
        FakeOpkg opkg;
        opkg.update_exit = 1;
        ComponentPackageTransaction txn(options_for(root), store,
                                        opkg.runner());
        const auto prep = txn.prepare("1.2.4");
        CHECK_FALSE(prep.error.empty());
        CHECK_FALSE(prep.feed_updated);
        CHECK(opkg.commands.size() == 1U);
    }
    SUBCASE("feed index missing") {
        FakeOpkg opkg;
        ComponentPackageTransaction txn(options_for(root), store,
                                        opkg.runner());
        const auto prep = txn.prepare("1.2.4");
        CHECK(prep.feed_updated);
        CHECK_FALSE(prep.feed_read);
        CHECK(prep.error.find("feed index") != std::string::npos);
        CHECK(opkg.commands.size() == 1U);
    }
    SUBCASE("feed index names another package only") {
        write_file(root.path / "feed-list",
                   "Package: other\nVersion: 1\nFilename: o.ipk\nSize: 3\n"
                   "SHA256sum: " + std::string(64, 'a') + "\n\n");
        FakeOpkg opkg;
        ComponentPackageTransaction txn(options_for(root), store,
                                        opkg.runner());
        const auto prep = txn.prepare("1.2.4");
        CHECK(prep.feed_read);
        CHECK_FALSE(prep.listed.has_value());
        CHECK_FALSE(prep.error.empty());
    }
    SUBCASE("download fails") {
        write_file(root.path / "feed-list", feed_stanza("1.2.5", bytes));
        FakeOpkg opkg;
        opkg.download_exit = 4;
        ComponentPackageTransaction txn(options_for(root), store,
                                        opkg.runner());
        const auto prep = txn.prepare("1.2.4");
        CHECK(prep.error.find("opkg download") != std::string::npos);
        CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
    }
    SUBCASE("feed no longer serves the installed version and nothing is newer") {
        // Feed went backwards (or the operator installed ahead of it).
        write_file(root.path / "feed-list", feed_stanza("1.2.3", bytes));
        FakeOpkg opkg;
        ComponentPackageTransaction txn(options_for(root), store,
                                        opkg.runner());
        const auto prep = txn.prepare("1.2.4");
        CHECK(prep.error.empty());
        CHECK(prep.up_to_date);
        CHECK(prep.retention == IpkRetentionAction::unavailable);
        CHECK_FALSE(prep.previous_exact);
        CHECK(opkg.commands.size() == 1U);
    }
}

TEST_CASE("retain_installed keeps the installed ipk and never fetches a target") {
    TempRoot root;
    ComponentIpkStore store(root.path / "components", "nfqws2-keenetic");

    SUBCASE("the feed still serves the installed version") {
        const std::string bytes = "ipk 1.2.4";
        write_file(root.path / "feed-list", feed_stanza("1.2.4", bytes));
        FakeOpkg opkg;
        opkg.served_bytes = bytes;
        opkg.served_filename = "nfqws2-keenetic_1.2.4_all_entware.ipk";
        ComponentPackageTransaction txn(options_for(root), store,
                                        opkg.runner());
        const auto result = txn.retain_installed("1.2.4");
        CHECK(result.error.empty());
        CHECK(result.previous_exact);
        CHECK(result.retention == IpkRetentionAction::retain_now);
        CHECK(store.inspect(IpkSlot::current).retained->version == "1.2.4");
        CHECK(opkg.commands.size() == 2U);
    }
    SUBCASE("the feed has moved on: reported, not fetched") {
        const std::string bytes = "ipk 1.2.5";
        write_file(root.path / "feed-list", feed_stanza("1.2.5", bytes));
        FakeOpkg opkg;
        opkg.served_bytes = bytes;
        opkg.served_filename = "nfqws2-keenetic_1.2.5_all_entware.ipk";
        ComponentPackageTransaction txn(options_for(root), store,
                                        opkg.runner());
        const auto result = txn.retain_installed("1.2.4");
        CHECK(result.error.empty());
        CHECK_FALSE(result.previous_exact);
        CHECK(result.retention == IpkRetentionAction::unavailable);
        REQUIRE(result.target.has_value());
        CHECK(result.target->version == "1.2.5");
        CHECK_FALSE(result.candidate_verified);
        CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
        // Only opkg update ran; the newer version was not downloaded.
        CHECK(opkg.commands.size() == 1U);
        CHECK(result.output.find("not fetched here") != std::string::npos);
    }
}

TEST_CASE("an interrupted promotion is finished before anything else is decided") {
    // The install of 1.2.5 was verified, then the process died before the
    // candidate became current: 1.2.5 runs, its exact bytes sit in
    // candidate, current still says 1.2.4, and the feed now serves 1.2.6.
    TempRoot root;
    ComponentIpkStore store(root.path / "components", "nfqws2-keenetic");
    const std::string old_bytes = "ipk 1.2.4";
    const std::string run_bytes = "ipk 1.2.5";
    const std::string new_bytes = "ipk 1.2.6";
    const auto entry = [&](const std::string& version, const std::string& b) {
        FeedPackageEntry e;
        e.package = "nfqws2-keenetic";
        e.version = version;
        e.filename = "nfqws2-keenetic_" + version + "_all_entware.ipk";
        e.size = b.size();
        e.sha256 = digest_of(b);
        return e;
    };
    store.adopt(IpkSlot::current, old_bytes, entry("1.2.4", old_bytes));
    store.adopt(IpkSlot::candidate, run_bytes, entry("1.2.5", run_bytes));
    write_file(root.path / "feed-list", feed_stanza("1.2.6", new_bytes));
    FakeOpkg opkg;
    ComponentPackageTransaction txn(options_for(root), store, opkg.runner());

    const auto result = txn.retain_installed("1.2.5");
    CHECK(result.output.find("Finished an interrupted promotion") !=
          std::string::npos);
    CHECK(result.previous_exact);
    CHECK(result.retention == IpkRetentionAction::already_retained);
    CHECK(store.inspect(IpkSlot::current).retained->version == "1.2.5");
    CHECK(store.inspect(IpkSlot::previous).retained->version == "1.2.4");
    CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
    // Nothing was downloaded: the exact copy was already on disk.
    CHECK(opkg.commands.size() == 1U);
}

TEST_CASE("a feed listing several versions is read as its newest") {
    TempRoot root;
    const std::string older = "ipk 1.2.4";
    const std::string newer = "ipk 1.2.5";
    // Installed version listed first and a newer one after it.
    write_file(root.path / "feed-list",
               feed_stanza("1.2.4", older) + feed_stanza("1.2.5", newer));
    FakeOpkg opkg;
    opkg.served_bytes = newer;
    opkg.served_filename = "nfqws2-keenetic_1.2.5_all_entware.ipk";
    ComponentIpkStore store(root.path / "components", "nfqws2-keenetic");
    ComponentPackageTransaction txn(options_for(root), store, opkg.runner());

    const auto prep = txn.prepare("1.2.4");
    REQUIRE(prep.listed.has_value());
    CHECK(prep.listed->version == "1.2.5");
    REQUIRE(prep.target.has_value());
    CHECK(prep.target->version == "1.2.5");
    CHECK(prep.candidate_verified);
    // opkg download fetches only the newest, so the installed version -
    // although listed - cannot be retained through it, and the message
    // says exactly that rather than "no longer serves".
    CHECK(prep.retention == IpkRetentionAction::unavailable);
    const auto retain = txn.retain_installed("1.2.4");
    CHECK(retain.output.find("behind a newer one") != std::string::npos);
}

TEST_CASE("feed versions compare numerically") {
    CHECK(feed_version_newer("1.2.5", "1.2.4"));
    CHECK(feed_version_newer("1.10.0", "1.9.9"));
    CHECK(feed_version_newer("v2.0", "1.99.99"));
    CHECK_FALSE(feed_version_newer("1.2.4", "1.2.4"));
    CHECK_FALSE(feed_version_newer("1.2.3", "1.2.4"));
    CHECK_FALSE(feed_version_newer("garbage", "1.2.4"));
    CHECK_FALSE(feed_version_newer("", "1.2.4"));
}

namespace {

// The world a scripted install runs in: an adopted store slot, an init.d
// directory the test owns, and a runner that plays tar, the shell and opkg.
// The runner snapshots the init-script state at the moment postinst runs,
// because the whole point of the hold is what postinst sees, not what is
// true before or after.
struct ScriptedWorld {
    TempRoot root;
    ComponentIpkStore store{root.path / "components", "nfqws2-keenetic"};
    ComponentPackageOptions options;

    std::vector<std::vector<std::string>> commands;
    std::vector<fs::path> working_directories;
    int outer_tar_exit{0};
    int control_tar_exit{0};
    bool lay_control_archive{true};
    bool with_preinst{true};
    bool with_postinst{true};
    int preinst_exit{0};
    int unpack_exit{0};
    int postinst_exit{0};
    // Set while the fake postinst runs.
    bool init_present_during_postinst{true};
    bool held_present_during_postinst{false};
    // Lay a directory at the init-script path while postinst runs, so the
    // restoring rename has somewhere real to fail.
    bool occupy_init_path_during_postinst{false};

    ScriptedWorld() {
        options = options_for(root);
        options.scripted.init_script = root.path / "init.d" / "S51nfqws2";
        options.scripted.held_init_script =
            root.path / "init.d" / ".S51nfqws2.kpbr-held";
        fs::create_directories(root.path / "init.d");
    }

    void lay_init_script() {
        write_file(options.scripted.init_script, "#!/bin/sh\nexit 0\n");
    }

    void adopt_candidate(const std::string& version,
                         const std::string& bytes) {
        store.adopt(IpkSlot::candidate, bytes, entry(version, bytes));
    }
    void adopt_current(const std::string& version, const std::string& bytes) {
        store.adopt(IpkSlot::current, bytes, entry(version, bytes));
    }

    static FeedPackageEntry entry(const std::string& version,
                                  const std::string& bytes) {
        FeedPackageEntry e;
        e.package = "nfqws2-keenetic";
        e.version = version;
        e.filename = "nfqws2-keenetic_" + version + "_all_entware.ipk";
        e.size = bytes.size();
        e.sha256 = digest_of(bytes);
        return e;
    }

    // The commands the shell was asked to run, as "<script-name> <arg>".
    std::vector<std::string> script_runs;

    ComponentCommandRunner runner() {
        return [this](const std::vector<std::string>& argv,
                      SafeExecTimeouts, const fs::path& cwd) {
            commands.push_back(argv);
            working_directories.push_back(cwd);
            ExecCaptureResult result;
            REQUIRE_FALSE(argv.empty());
            if (argv[0] == "/opt/bin/tar") {
                REQUIRE(argv.size() == 5U);
                CHECK(argv[1] == "-xzf");
                CHECK(argv[3] == "-C");
                const fs::path source = argv[2];
                const fs::path target = argv[4];
                if (source.extension() == ".ipk") {
                    if (outer_tar_exit == 0 && lay_control_archive) {
                        write_file(target / "control.tar.gz", "control");
                    }
                    result.exit_code = outer_tar_exit;
                    return result;
                }
                CHECK(source.filename() == "control.tar.gz");
                if (control_tar_exit == 0) {
                    if (with_preinst) {
                        write_file(target / "preinst", "#!/bin/sh\n");
                    }
                    if (with_postinst) {
                        write_file(target / "postinst", "#!/bin/sh\n");
                    }
                }
                result.exit_code = control_tar_exit;
                return result;
            }
            if (argv[0] == "/opt/bin/sh") {
                REQUIRE(argv.size() == 3U);
                const fs::path script = argv[1];
                script_runs.push_back(script.filename().string() + " " +
                                      argv[2]);
                if (script.filename() == "preinst") {
                    result.exit_code = preinst_exit;
                    return result;
                }
                CHECK(script.filename() == "postinst");
                std::error_code error;
                init_present_during_postinst = fs::exists(
                    fs::symlink_status(options.scripted.init_script, error));
                held_present_during_postinst = fs::exists(fs::symlink_status(
                    options.scripted.held_init_script, error));
                if (occupy_init_path_during_postinst) {
                    fs::create_directories(options.scripted.init_script /
                                           "occupied");
                }
                result.exit_code = postinst_exit;
                return result;
            }
            REQUIRE(argv[0] == "/opt/bin/opkg");
            REQUIRE(argv.size() >= 6U);
            CHECK(argv[1] == "-o");
            CHECK(argv[2] == "/");
            CHECK(argv[3] == "-f");
            CHECK(argv[4] == "/opt/etc/opkg.conf");
            CHECK(argv[5] == "install");
            result.exit_code = unpack_exit;
            result.stdout_output = "Installing to root...\n";
            return result;
        };
    }

    ComponentPackageTransaction transaction() {
        return ComponentPackageTransaction(options, store, runner());
    }
};

} // namespace

TEST_CASE("a scripted install runs the package's scripts around a script-free unpack") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.lay_init_script();
    auto txn = world.transaction();

    ScriptedInstallReport report;
    txn.scripted_install_candidate(/*upgrade=*/true, report);

    CHECK(report.scripts_extracted);
    CHECK(report.preinst_ran);
    CHECK(report.preinst_ok);
    CHECK(report.mutation_started);
    CHECK(report.unpack_ok);
    CHECK(report.init_held);
    CHECK(report.postinst_ran);
    CHECK(report.postinst_ok);
    CHECK(report.init_restored);
    CHECK(scripted_install_succeeded(report));

    // The exact order: extract, extract, preinst, unpack, postinst.
    REQUIRE(world.commands.size() == 5U);
    CHECK(world.commands[0][0] == "/opt/bin/tar");
    CHECK(world.commands[1][0] == "/opt/bin/tar");
    CHECK(world.commands[2][0] == "/opt/bin/sh");
    CHECK(world.commands[3][0] == "/opt/bin/opkg");
    CHECK(world.commands[4][0] == "/opt/bin/sh");
    // The unpack installs the candidate's exact file with no extra flags.
    CHECK(world.commands[3] == std::vector<std::string>{
                                   "/opt/bin/opkg", "-o", "/", "-f",
                                   "/opt/etc/opkg.conf", "install",
                                   world.store.ipk_path(IpkSlot::candidate)
                                       .string()});
    CHECK(world.script_runs == std::vector<std::string>{
                                   "preinst upgrade", "postinst configure"});
    // While postinst ran, the init script was held aside; afterwards it is
    // back and the held name is gone.
    CHECK_FALSE(world.init_present_during_postinst);
    CHECK(world.held_present_during_postinst);
    std::error_code error;
    CHECK(fs::exists(world.options.scripted.init_script, error));
    CHECK_FALSE(fs::exists(world.options.scripted.held_init_script, error));
    // The extraction scratch is cleaned up: data.tar.gz is too large to
    // leave lying around.
    CHECK_FALSE(fs::exists(world.store.directory() / "staging", error));
}

TEST_CASE("a scripted fresh install tells preinst it is an install") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    auto txn = world.transaction();

    ScriptedInstallReport report;
    txn.scripted_install_candidate(/*upgrade=*/false, report);

    CHECK(scripted_install_succeeded(report));
    REQUIRE_FALSE(world.script_runs.empty());
    CHECK(world.script_runs.front() == "preinst install");
    // No init script existed (nothing is installed), so nothing was held
    // and there was nothing to restore.
    CHECK_FALSE(report.init_held);
    CHECK(report.init_restored);
}

TEST_CASE("a scripted reinstall keeps the exact-rollback opkg flags") {
    ScriptedWorld world;
    world.adopt_current("1.2.4", "ipk 1.2.4");
    world.lay_init_script();
    auto txn = world.transaction();

    ScriptedInstallReport report;
    txn.scripted_reinstall_current("1.2.4", report);

    CHECK(scripted_install_succeeded(report));
    REQUIRE(world.commands.size() == 5U);
    CHECK(world.commands[3] == std::vector<std::string>{
                                   "/opt/bin/opkg", "-o", "/", "-f",
                                   "/opt/etc/opkg.conf", "install",
                                   "--force-downgrade", "--force-reinstall",
                                   world.store.ipk_path(IpkSlot::current)
                                       .string()});
    // The reinstall is an upgrade to the maintainer scripts: the package is
    // installed and its files are being replaced.
    CHECK(world.script_runs.front() == "preinst upgrade");
}

TEST_CASE("scripted install refusals name the slot and issue no command") {
    ScriptedWorld world;
    auto txn = world.transaction();
    ScriptedInstallReport report;
    CHECK_THROWS_AS(txn.scripted_install_candidate(true, report),
                    ComponentPackageRefused);
    CHECK_THROWS_AS(txn.scripted_reinstall_current("1.2.4", report),
                    ComponentPackageRefused);
    world.adopt_current("1.2.4", "ipk 1.2.4");
    CHECK_THROWS_AS(txn.scripted_reinstall_current("1.2.3", report),
                    ComponentPackageRefused);
    CHECK(world.commands.empty());
}

TEST_CASE("a package whose archive cannot be opened mutates nothing") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    auto txn = world.transaction();
    ScriptedInstallReport report;

    SUBCASE("the outer extraction fails") { world.outer_tar_exit = 1; }
    SUBCASE("the archive has no control.tar.gz") {
        world.lay_control_archive = false;
    }
    SUBCASE("the control archive fails to extract") {
        world.control_tar_exit = 1;
    }

    txn.scripted_install_candidate(true, report);
    CHECK_FALSE(report.scripts_extracted);
    CHECK_FALSE(report.mutation_started);
    CHECK_FALSE(report.preinst_ran);
    CHECK_FALSE(scripted_install_succeeded(report));
    // No opkg command, no shell command: nothing was mutated.
    for (const auto& argv : world.commands) {
        CHECK(argv[0] == "/opt/bin/tar");
    }
}

TEST_CASE("a failed preinst stops the flow before the package manager") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.preinst_exit = 1;
    auto txn = world.transaction();
    ScriptedInstallReport report;
    txn.scripted_install_candidate(true, report);

    CHECK(report.scripts_extracted);
    CHECK(report.preinst_ran);
    CHECK_FALSE(report.preinst_ok);
    CHECK_FALSE(report.mutation_started);
    CHECK_FALSE(report.postinst_ran);
    CHECK_FALSE(scripted_install_succeeded(report));
    for (const auto& argv : world.commands) {
        CHECK(argv[0] != "/opt/bin/opkg");
    }
}

TEST_CASE("a failed unpack skips postinst and never touches the init script") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.lay_init_script();
    world.unpack_exit = 1;
    auto txn = world.transaction();
    ScriptedInstallReport report;
    txn.scripted_install_candidate(true, report);

    CHECK(report.mutation_started);
    CHECK_FALSE(report.unpack_ok);
    CHECK_FALSE(report.postinst_ran);
    CHECK_FALSE(report.init_held);
    CHECK_FALSE(scripted_install_succeeded(report));
    std::error_code error;
    CHECK(fs::exists(world.options.scripted.init_script, error));
    CHECK_FALSE(fs::exists(world.options.scripted.held_init_script, error));
}

TEST_CASE("a failed postinst still puts the init script back") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.lay_init_script();
    world.postinst_exit = 1;
    auto txn = world.transaction();
    ScriptedInstallReport report;
    txn.scripted_install_candidate(true, report);

    CHECK(report.unpack_ok);
    CHECK(report.postinst_ran);
    CHECK_FALSE(report.postinst_ok);
    CHECK(report.init_held);
    CHECK(report.init_restored);
    CHECK_FALSE(scripted_install_succeeded(report));
    std::error_code error;
    CHECK(fs::exists(world.options.scripted.init_script, error));
    CHECK_FALSE(fs::exists(world.options.scripted.held_init_script, error));
}

TEST_CASE("a package without a postinst needs no hold at all") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.lay_init_script();
    world.with_postinst = false;
    auto txn = world.transaction();
    ScriptedInstallReport report;
    txn.scripted_install_candidate(true, report);

    CHECK(report.unpack_ok);
    CHECK_FALSE(report.postinst_ran);
    CHECK(report.postinst_ok);
    CHECK_FALSE(report.init_held);
    CHECK(scripted_install_succeeded(report));
    CHECK(report.notes.find("no postinst") != std::string::npos);
}

TEST_CASE("an unholdable init script keeps postinst from running") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.lay_init_script();
    // A non-empty directory at the held name: the hold rename has nowhere
    // to go.
    fs::create_directories(world.options.scripted.held_init_script /
                           "occupied");
    auto txn = world.transaction();
    ScriptedInstallReport report;
    txn.scripted_install_candidate(true, report);

    CHECK(report.unpack_ok);
    CHECK_FALSE(report.init_held);
    CHECK_FALSE(report.postinst_ran);
    CHECK_FALSE(report.postinst_ok);
    CHECK_FALSE(scripted_install_succeeded(report));
    CHECK(report.notes.find("could not be held aside") != std::string::npos);
    // The init script itself was never moved.
    std::error_code error;
    CHECK(fs::exists(world.options.scripted.init_script, error));
}

TEST_CASE("a stale held copy from an interrupted run is replaced by the hold") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.lay_init_script();
    write_file(world.options.scripted.held_init_script, "stale old copy");
    auto txn = world.transaction();
    ScriptedInstallReport report;
    txn.scripted_install_candidate(true, report);

    CHECK(scripted_install_succeeded(report));
    // The restore consumed the held name; what is at the init path is the
    // file the unpack laid, not the stale copy.
    std::error_code error;
    CHECK(fs::exists(world.options.scripted.init_script, error));
    CHECK_FALSE(fs::exists(world.options.scripted.held_init_script, error));
}

TEST_CASE("the caller's service stop runs between preinst and the unpack") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.lay_init_script();
    auto txn = world.transaction();

    ScriptedInstallReport report;
    std::size_t commands_at_stop = 0;
    std::size_t scripts_at_stop = 0;
    int stop_calls = 0;
    txn.scripted_install_candidate(
        /*upgrade=*/true, report, [&](const ScriptedNoteSink& note) {
            ++stop_calls;
            commands_at_stop = world.commands.size();
            scripts_at_stop = world.script_runs.size();
            note("service stopped");
            return true;
        });

    CHECK(scripted_install_succeeded(report));
    CHECK(report.service_stop_ran);
    CHECK(report.service_stop_ok);
    CHECK(stop_calls == 1);
    // After the two extractions and preinst, before opkg: exactly the old
    // prerm's slot.
    CHECK(commands_at_stop == 3U);
    CHECK(scripts_at_stop == 1U);
    CHECK(report.notes.find("service stopped") != std::string::npos);
}

TEST_CASE("a service that cannot be stopped keeps its files") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.lay_init_script();
    auto txn = world.transaction();

    ScriptedInstallReport report;
    txn.scripted_install_candidate(
        /*upgrade=*/true, report,
        [&](const ScriptedNoteSink&) { return false; });

    CHECK(report.service_stop_ran);
    CHECK_FALSE(report.service_stop_ok);
    CHECK_FALSE(report.mutation_started);
    CHECK_FALSE(report.postinst_ran);
    CHECK_FALSE(scripted_install_succeeded(report));
    CHECK(report.notes.find("could not be proven stopped") !=
          std::string::npos);
    // preinst ran; the package manager did not.
    for (const auto& argv : world.commands) {
        CHECK(argv[0] != "/opt/bin/opkg");
    }
}

TEST_CASE("the extraction scratch is removed on early exits too") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.lay_init_script();
    auto txn = world.transaction();
    ScriptedInstallReport report;

    SUBCASE("failed preinst") { world.preinst_exit = 1; }
    SUBCASE("failed unpack") { world.unpack_exit = 1; }
    SUBCASE("failed postinst") { world.postinst_exit = 1; }
    SUBCASE("package without postinst") { world.with_postinst = false; }

    txn.scripted_install_candidate(true, report);
    std::error_code error;
    CHECK_FALSE(fs::exists(world.store.directory() / "staging", error));
}

TEST_CASE("a restore that fails leaves the held name for boot recovery") {
    ScriptedWorld world;
    world.adopt_candidate("1.2.5", "ipk 1.2.5");
    world.lay_init_script();
    world.occupy_init_path_during_postinst = true;
    auto txn = world.transaction();
    ScriptedInstallReport report;
    txn.scripted_install_candidate(true, report);

    CHECK(report.postinst_ok);
    CHECK(report.init_held);
    CHECK_FALSE(report.init_restored);
    CHECK_FALSE(scripted_install_succeeded(report));
    CHECK(report.notes.find("boot recovery restores it") !=
          std::string::npos);
    std::error_code error;
    CHECK(fs::exists(world.options.scripted.held_init_script, error));
}

} // namespace keen_pbr3
