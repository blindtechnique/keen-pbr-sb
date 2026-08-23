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

    ComponentCommandRunner runner() {
        return [this](const std::vector<std::string>& argv,
                      SafeExecTimeouts) {
            commands.push_back(argv);
            ExecCaptureResult result;
            REQUIRE_FALSE(argv.empty());
            if (argv.size() == 2 && argv[1] == "update") {
                result.exit_code = update_exit;
                result.stdout_output = "Updated list of available packages\n";
                return result;
            }
            if (argv.size() == 7 && argv[1] == "-c") {
                // The shell wrapper: cd "$1" && exec "$2" download "$3".
                CHECK(argv[0] == "/bin/sh");
                CHECK(argv[2] == "cd \"$1\" && exec \"$2\" download \"$3\"");
                CHECK(argv[5] == "/opt/bin/opkg");
                CHECK(argv[6] == "nfqws2-keenetic");
                if (download_exit == 0) {
                    write_file(fs::path(argv[4]) / served_filename,
                               served_bytes);
                }
                result.exit_code = download_exit;
                return result;
            }
            if (argv.size() >= 3 && argv[1] == "install") {
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
        // The wrong expectation is refused without running anything.
        const auto refused = txn.reinstall_current("1.2.3");
        CHECK(refused.exit_code != 0);
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
    const auto refused = txn.reinstall_current("1.2.4");
    CHECK(refused.exit_code != 0);
    CHECK(refused.stdout_output.find("no exact copy") != std::string::npos);
}

TEST_CASE("bytes that differ from the feed index never become a candidate") {
    TempRoot root;
    const std::string new_bytes = "ipk 1.2.5";
    write_file(root.path / "feed-list", feed_stanza("1.2.5", new_bytes));
    FakeOpkg opkg;
    opkg.served_bytes = "ipk 1.2.5 but tampered";
    opkg.served_filename = "nfqws2-keenetic_1.2.5_all_entware.ipk";
    ComponentIpkStore store(root.path / "components", "nfqws2-keenetic");
    ComponentPackageTransaction txn(options_for(root), store, opkg.runner());

    const auto prep = txn.prepare("1.2.4");
    CHECK_FALSE(prep.error.empty());
    CHECK_FALSE(prep.candidate_verified);
    CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
    // And install refuses rather than running opkg against nothing.
    const auto install = txn.install_candidate();
    CHECK(install.exit_code != 0);
    CHECK(opkg.commands.size() == 2U);

    // Same digest, wrong size - the feed's Size is checked too.
    opkg.served_bytes = new_bytes + "x";
    const auto prep2 = txn.prepare("1.2.4");
    CHECK_FALSE(prep2.error.empty());
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

TEST_CASE("feed versions compare numerically") {
    CHECK(feed_version_newer("1.2.5", "1.2.4"));
    CHECK(feed_version_newer("1.10.0", "1.9.9"));
    CHECK(feed_version_newer("v2.0", "1.99.99"));
    CHECK_FALSE(feed_version_newer("1.2.4", "1.2.4"));
    CHECK_FALSE(feed_version_newer("1.2.3", "1.2.4"));
    CHECK_FALSE(feed_version_newer("garbage", "1.2.4"));
    CHECK_FALSE(feed_version_newer("", "1.2.4"));
}

} // namespace keen_pbr3
