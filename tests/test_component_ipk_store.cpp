#include <doctest/doctest.h>

#include "../src/update/component_ipk_store.hpp"
#include "../src/crypto/sha256.hpp"

#include <filesystem>
#include <fstream>
#include <string>

#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

struct TempRoot {
    fs::path path;
    TempRoot() {
        std::string pattern =
            (fs::temp_directory_path() / "ipk-store-XXXXXX").string();
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

FeedPackageEntry entry_for(const std::string& version,
                           const std::string& bytes) {
    FeedPackageEntry entry;
    entry.package = "nfqws2-keenetic";
    entry.version = version;
    entry.filename = "nfqws2-keenetic_" + version + "_all_entware.ipk";
    entry.size = bytes.size();
    entry.sha256 = digest_of(bytes);
    return entry;
}

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

void write_file(const fs::path& path, const std::string& body) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << body;
}

} // namespace

TEST_CASE("an adopted ipk is usable and its files match the feed entry") {
    TempRoot root;
    ComponentIpkStore store(root.path, "nfqws2-keenetic");
    CHECK(store.inspect(IpkSlot::current).state == IpkSlotState::absent);

    const std::string bytes = "ipk bytes for 1.2.4";
    const auto retained =
        store.adopt(IpkSlot::current, bytes, entry_for("1.2.4", bytes));
    CHECK(retained.version == "1.2.4");
    CHECK(retained.sha256 == digest_of(bytes));

    const auto current = store.inspect(IpkSlot::current);
    REQUIRE(current.state == IpkSlotState::usable);
    REQUIRE(current.retained.has_value());
    CHECK(current.retained->version == "1.2.4");
    CHECK(current.retained->size == bytes.size());
    CHECK(current.retained->filename ==
          "nfqws2-keenetic_1.2.4_all_entware.ipk");
    CHECK(read_file(store.ipk_path(IpkSlot::current)) == bytes);
    // The sidecar is the same single-line shape the shell rescue store
    // verifies, so an operator can check it with sha256sum.
    CHECK(read_file(root.path / "nfqws2-keenetic" / "current.ipk.sha256") ==
          digest_of(bytes) + "\n");

    // The store is private.
    const auto mode = fs::status(store.directory()).permissions();
    CHECK((mode & fs::perms::group_all) == fs::perms::none);
    CHECK((mode & fs::perms::others_all) == fs::perms::none);
}

TEST_CASE("bytes that are not what the feed promised are refused untouched") {
    TempRoot root;
    ComponentIpkStore store(root.path, "nfqws2-keenetic");
    const std::string bytes = "genuine";

    auto wrong_size = entry_for("1.2.4", bytes);
    wrong_size.size = bytes.size() + 1;
    CHECK_THROWS(store.adopt(IpkSlot::candidate, bytes, wrong_size));

    auto wrong_digest = entry_for("1.2.4", bytes);
    wrong_digest.sha256 = std::string(64, '0');
    CHECK_THROWS(store.adopt(IpkSlot::candidate, bytes, wrong_digest));

    auto other_package = entry_for("1.2.4", bytes);
    other_package.package = "tpws-keenetic";
    CHECK_THROWS(store.adopt(IpkSlot::candidate, bytes, other_package));

    auto shell_version = entry_for("1.2.4", bytes);
    shell_version.version = "1.2.4;rm -rf /";
    CHECK_THROWS(store.adopt(IpkSlot::candidate, bytes, shell_version));

    CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
    CHECK_FALSE(fs::exists(store.ipk_path(IpkSlot::candidate)));
}

TEST_CASE("a slot whose bytes disagree with its manifest is corrupt, not usable") {
    TempRoot root;
    ComponentIpkStore store(root.path, "nfqws2-keenetic");
    const std::string bytes = "ipk bytes";
    store.adopt(IpkSlot::current, bytes, entry_for("1.2.4", bytes));

    SUBCASE("bytes replaced under the manifest") {
        write_file(store.ipk_path(IpkSlot::current), "tampered!");
        const auto current = store.inspect(IpkSlot::current);
        CHECK(current.state == IpkSlotState::corrupt);
        CHECK_FALSE(current.retained.has_value());
        CHECK_FALSE(current.detail.empty());
    }
    SUBCASE("ipk removed") {
        fs::remove(store.ipk_path(IpkSlot::current));
        CHECK(store.inspect(IpkSlot::current).state == IpkSlotState::corrupt);
    }
    SUBCASE("sidecar rewritten") {
        write_file(store.directory() / "current.ipk.sha256",
                   std::string(64, 'f') + "\n");
        CHECK(store.inspect(IpkSlot::current).state == IpkSlotState::corrupt);
    }
    SUBCASE("manifest removed: leftover bytes make no claim") {
        fs::remove(store.directory() / "current.json");
        CHECK(store.inspect(IpkSlot::current).state == IpkSlotState::absent);
    }
    SUBCASE("manifest for another package") {
        write_file(store.directory() / "current.json",
                   "{\"package\":\"other\",\"version\":\"1.2.4\","
                   "\"filename\":\"x.ipk\",\"size\":9,\"sha256\":\"" +
                       digest_of(bytes) + "\"}");
        CHECK(store.inspect(IpkSlot::current).state == IpkSlotState::corrupt);
    }
}

TEST_CASE("promotion keeps current as previous and installs the candidate") {
    TempRoot root;
    ComponentIpkStore store(root.path, "nfqws2-keenetic");
    const std::string old_bytes = "bytes 1.2.4";
    const std::string new_bytes = "bytes 1.2.5";
    store.adopt(IpkSlot::current, old_bytes, entry_for("1.2.4", old_bytes));
    store.adopt(IpkSlot::candidate, new_bytes, entry_for("1.2.5", new_bytes));

    store.promote_candidate();

    const auto current = store.inspect(IpkSlot::current);
    const auto previous = store.inspect(IpkSlot::previous);
    REQUIRE(current.state == IpkSlotState::usable);
    REQUIRE(previous.state == IpkSlotState::usable);
    CHECK(current.retained->version == "1.2.5");
    CHECK(previous.retained->version == "1.2.4");
    CHECK(read_file(store.ipk_path(IpkSlot::previous)) == old_bytes);
    CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);

    // Without a candidate there is nothing to promote, and nothing moves.
    CHECK_THROWS(store.promote_candidate());
    CHECK(store.inspect(IpkSlot::current).retained->version == "1.2.5");
}

TEST_CASE("promotion without a usable current does not invent a previous") {
    TempRoot root;
    ComponentIpkStore store(root.path, "nfqws2-keenetic");
    const std::string stale = "stale";
    const std::string new_bytes = "bytes 1.2.5";
    // A stale previous from long ago and a corrupt current.
    store.adopt(IpkSlot::previous, stale, entry_for("1.0.0", stale));
    store.adopt(IpkSlot::current, stale, entry_for("1.2.4", stale));
    write_file(store.ipk_path(IpkSlot::current), "damaged");
    store.adopt(IpkSlot::candidate, new_bytes, entry_for("1.2.5", new_bytes));

    store.promote_candidate();

    CHECK(store.inspect(IpkSlot::current).retained->version == "1.2.5");
    // The corrupt current was dropped, not demoted; the old previous stays
    // as it was because it is still an honest exact copy of 1.0.0.
    CHECK(store.inspect(IpkSlot::previous).retained->version == "1.0.0");
}

TEST_CASE("an interrupted promotion is finished on the next run") {
    TempRoot root;
    ComponentIpkStore store(root.path, "nfqws2-keenetic");
    const std::string old_bytes = "bytes 1.2.4";
    const std::string new_bytes = "bytes 1.2.5";
    store.adopt(IpkSlot::current, old_bytes, entry_for("1.2.4", old_bytes));
    store.adopt(IpkSlot::candidate, new_bytes, entry_for("1.2.5", new_bytes));

    // Simulate a crash after current moved to previous but before the
    // candidate moved: exactly what the rename order leaves behind.
    for (const char* name : {"ipk", "ipk.sha256", "json"}) {
        fs::rename(store.directory() / (std::string("current.") + name),
                   store.directory() / (std::string("previous.") + name));
    }
    CHECK(store.inspect(IpkSlot::current).state == IpkSlotState::absent);
    CHECK(store.inspect(IpkSlot::previous).retained->version == "1.2.4");
    CHECK(store.inspect(IpkSlot::candidate).retained->version == "1.2.5");

    store.promote_candidate();
    CHECK(store.inspect(IpkSlot::current).retained->version == "1.2.5");
    CHECK(store.inspect(IpkSlot::previous).retained->version == "1.2.4");
}

TEST_CASE("a move interrupted inside itself leaves exactly one usable slot") {
    // move_slot links the bytes under the destination names, renames the
    // manifest (the commit), then unlinks the source bytes. Each window is
    // reconstructed by hand and the store is asked what it sees and whether
    // a re-run converges.
    TempRoot root;
    ComponentIpkStore store(root.path / "components", "nfqws2-keenetic");
    const std::string old_bytes = "bytes 1.2.4";
    const std::string new_bytes = "bytes 1.2.5";
    const auto dir = store.directory();
    const auto link = [&](const char* from, const char* to) {
        fs::create_hard_link(dir / from, dir / to);
    };

    SUBCASE("after the first link: candidate still usable, current absent") {
        store.adopt(IpkSlot::candidate, new_bytes, entry_for("1.2.5", new_bytes));
        link("candidate.ipk", "current.ipk");
        CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::usable);
        CHECK(store.inspect(IpkSlot::current).state == IpkSlotState::absent);
        store.promote_candidate();
        CHECK(store.inspect(IpkSlot::current).retained->version == "1.2.5");
        CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
    }
    SUBCASE("after both links: same, and the re-run replaces the leftovers") {
        store.adopt(IpkSlot::candidate, new_bytes, entry_for("1.2.5", new_bytes));
        link("candidate.ipk", "current.ipk");
        link("candidate.ipk.sha256", "current.ipk.sha256");
        CHECK(store.inspect(IpkSlot::current).state == IpkSlotState::absent);
        store.promote_candidate();
        CHECK(store.inspect(IpkSlot::current).retained->version == "1.2.5");
        CHECK_FALSE(fs::exists(dir / "candidate.ipk"));
    }
    SUBCASE("after the manifest rename: committed, source bytes are leftovers") {
        store.adopt(IpkSlot::current, old_bytes, entry_for("1.2.4", old_bytes));
        store.adopt(IpkSlot::candidate, new_bytes, entry_for("1.2.5", new_bytes));
        // current -> previous fully done; candidate -> current stopped right
        // after its manifest moved.
        link("current.ipk", "previous.ipk");
        link("current.ipk.sha256", "previous.ipk.sha256");
        fs::rename(dir / "current.json", dir / "previous.json");
        fs::remove(dir / "current.ipk");
        fs::remove(dir / "current.ipk.sha256");
        link("candidate.ipk", "current.ipk");
        link("candidate.ipk.sha256", "current.ipk.sha256");
        fs::rename(dir / "candidate.json", dir / "current.json");
        CHECK(store.inspect(IpkSlot::current).retained->version == "1.2.5");
        CHECK(store.inspect(IpkSlot::previous).retained->version == "1.2.4");
        CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
        // Leftover candidate bytes carry no claim and a later adopt replaces
        // them rather than tripping over them.
        CHECK(fs::exists(dir / "candidate.ipk"));
        store.adopt(IpkSlot::candidate, "bytes 1.2.6", entry_for("1.2.6", "bytes 1.2.6"));
        CHECK(store.inspect(IpkSlot::candidate).retained->version == "1.2.6");
        // And the hard link did not let that adopt change current's bytes.
        CHECK(store.inspect(IpkSlot::current).state == IpkSlotState::usable);
    }
}

TEST_CASE("discard and staging leave no claims behind") {
    TempRoot root;
    ComponentIpkStore store(root.path, "nfqws2-keenetic");
    const std::string bytes = "bytes";
    store.adopt(IpkSlot::candidate, bytes, entry_for("1.2.5", bytes));
    store.discard(IpkSlot::candidate);
    CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
    CHECK_FALSE(fs::exists(store.ipk_path(IpkSlot::candidate)));
    // Discarding an absent slot is fine.
    store.discard(IpkSlot::previous);

    const auto staging = store.staging_directory();
    write_file(staging / "leftover.ipk", "partial");
    CHECK(fs::exists(staging / "leftover.ipk"));
    // Handing it out again empties it: a download in flight never meets an
    // older one.
    CHECK(store.staging_directory() == staging);
    CHECK_FALSE(fs::exists(staging / "leftover.ipk"));
}

} // namespace keen_pbr3
