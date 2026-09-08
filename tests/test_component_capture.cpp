#include <doctest/doctest.h>

#include "../src/update/component_capture.hpp"
#include "../src/crypto/sha256.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-capture-XXXXXX").string();
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

    fs::path path;
};

void write_file(const fs::path& path,
                const std::string& content,
                mode_t mode = 0644) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << content;
    output.close();
    REQUIRE(output);
    REQUIRE(::chmod(path.c_str(), mode) == 0);
}

fs::path active_capture(const fs::path& store) {
    std::ifstream input(store / "current");
    std::string generation;
    REQUIRE(std::getline(input, generation));
    REQUIRE_FALSE(generation.empty());
    return store / "generations" / generation;
}

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void replace_ready_manifest(const fs::path& generation,
                            const std::string& manifest) {
    write_file(generation / "manifest", manifest);
    Sha256 digest;
    digest.update(manifest.data(), manifest.size());
    write_file(generation / ".ready", digest.hex_digest() + "\n");
}

std::string package_paragraph(const std::string& package,
                               const std::string& version) {
    return "Package: " + package + "\nVersion: " + version +
           "\nStatus: install user installed\n";
}

struct CaptureMetadataFixture {
    TempDirectory directory;
    fs::path live = directory.path / "live" / "binary";
    fs::path added = directory.path / "live" / "target-only";
    fs::path store = directory.path / "store";
    ComponentOpkgMetadataPaths metadata{
        "nfqws2-keenetic", directory.path / "opkg" / "status",
        directory.path / "opkg" / "info", directory.path / "opkg.lock"};

    fs::path info(const std::string& suffix) const {
        return metadata.info_directory / (metadata.package + '.' + suffix);
    }
    std::string target(const std::string& version) const {
        return package_paragraph(metadata.package, version);
    }
    CaptureMetadataFixture() {
        write_file(live, "old-payload\n", 0755);
        write_file(info("control"), "Package: nfqws2-keenetic\nVersion: 1\n");
        write_file(info("list"), live.string() + "\n");
        write_file(metadata.status_file,
                   target("1") + "\n" + package_paragraph("unrelated", "old") + "\n");
    }
    ComponentCaptureResult capture() const {
        return capture_component_upgrade_files(
            observe_package_footprint({live.string()}), {live.string(), added.string()},
            store, metadata);
    }
    std::string upgrade() const {
        write_file(live, "new-failed-payload\n", 0644);
        write_file(added, "new-target-file\n");
        write_file(info("control"), "new-control\n");
        write_file(info("list"), "new-list\n");
        write_file(info("postinst"), "new-script\n", 0755);
        const auto unrelated = package_paragraph("unrelated", "newer") +
                               "X-New: preserve exactly\n\n" +
                               package_paragraph("new-package", "7") + "\n";
        write_file(metadata.status_file, target("2") + "\n" + unrelated, 0600);
        return unrelated;
    }
};

fs::path stored_kind(const fs::path& generation, char wanted) {
    std::istringstream input(read_file(generation / "manifest"));
    std::string line;
    while (std::getline(input, line)) {
        if (line.size() < 2U || line[0] != wanted || line[1] != ' ') continue;
        std::istringstream fields(line);
        char kind = '\0';
        std::size_t index = 0;
        REQUIRE(static_cast<bool>(fields >> kind >> index));
        auto name = std::to_string(index);
        name.insert(0, 6U - name.size(), '0');
        return generation / "files" / name;
    }
    FAIL("manifest entry kind missing");
    return {};
}

void check_reinstall_preparation_left_files_untouched(
    const CaptureMetadataFixture& fixture) {
    CHECK(read_file(fixture.live) == "new-failed-payload\n");
    CHECK(read_file(fixture.added) == "new-target-file\n");
    CHECK(read_file(fixture.info("control")) == "new-control\n");
    CHECK(read_file(fixture.info("list")) == "new-list\n");
    CHECK(read_file(fixture.info("postinst")) == "new-script\n");
}

} // namespace

TEST_CASE("a capture stores every present file and verifies from the copy") {
    TempDirectory directory;
    const auto binary = directory.path / "src" / "nfqws2";
    const auto blob = directory.path / "src" / "quic initial.bin";
    const auto gone = directory.path / "src" / "other-arch";
    write_file(binary, "binary-bytes\n", 0755);
    // A space in the path: the manifest puts the path last for exactly this.
    write_file(blob, "blob-bytes\n", 0644);

    const auto footprint = observe_package_footprint(
        {binary.string(), blob.string(), gone.string()});
    const auto store = directory.path / "store";
    const auto result = capture_component_files(footprint, store);

    CHECK(result.complete);
    CHECK(result.captured == 2U);
    CHECK(result.skipped_absent == 1U);
    CHECK(result.failed.empty());
    CHECK(verify_component_capture(store) == ComponentCaptureState::usable);
}

TEST_CASE("the store is private no matter how open the originals were") {
    // Measured on the live router: every one of nfqws2's six conffiles is in
    // opkg's file list, so the capture holds the operator's nfqws2.conf and
    // all five domain and address lists. A world-readable copy of those beside
    // a 0644 original is a copy that leaks what the original merely exposed.
    TempDirectory directory;
    const auto open_file = directory.path / "src" / "user.list";
    write_file(open_file, "example.test\n", 0666);

    const auto store = directory.path / "store";
    REQUIRE(capture_component_files(
                observe_package_footprint({open_file.string()}), store)
                .complete);

    struct stat info {};
    const auto generation = active_capture(store);
    for (const auto& path : {store,
                             store / "generations",
                             generation,
                             generation / "files",
                             generation / "files" / "000001",
                             generation / "manifest",
                             generation / ".ready",
                             store / "current"}) {
        REQUIRE(::lstat(path.c_str(), &info) == 0);
        const bool directory_entry = S_ISDIR(info.st_mode);
        CHECK((info.st_mode & 07777) ==
              (directory_entry ? 0700U : 0600U));
    }

    // The original's mode still travels in the manifest, so a restore puts it
    // back as it was rather than as the store kept it.
    write_file(open_file, "changed\n", 0600);
    REQUIRE(restore_component_files(store).complete);
    REQUIRE(::lstat(open_file.c_str(), &info) == 0);
    CHECK((info.st_mode & 07777) == 0666U);
}

TEST_CASE("an absent capture is absent, not damaged") {
    TempDirectory directory;
    CHECK(verify_component_capture(directory.path / "never") ==
          ComponentCaptureState::absent);
}

TEST_CASE("a capture without its readiness marker is incomplete") {
    TempDirectory directory;
    const auto source = directory.path / "file";
    write_file(source, "bytes\n");
    const auto store = directory.path / "store";
    REQUIRE(capture_component_files(
                observe_package_footprint({source.string()}), store)
                .complete);

    std::error_code error;
    fs::remove(active_capture(store) / ".ready", error);
    REQUIRE_FALSE(error);
    // The marker is written last, so its absence is how an interrupted
    // capture is told apart from a finished one.
    CHECK(verify_component_capture(store) ==
          ComponentCaptureState::incomplete);
}

TEST_CASE("a manifest edited after the fact does not pass as ready") {
    TempDirectory directory;
    const auto source = directory.path / "file";
    write_file(source, "bytes\n");
    const auto store = directory.path / "store";
    REQUIRE(capture_component_files(
                observe_package_footprint({source.string()}), store)
                .complete);

    std::ofstream manifest(active_capture(store) / "manifest", std::ios::app);
    manifest << "2 644 " << std::string(64, 'f') << " /invented\n";
    manifest.close();
    CHECK(verify_component_capture(store) ==
          ComponentCaptureState::incomplete);
}

TEST_CASE("stored bytes that drifted are corruption, not incompleteness") {
    TempDirectory directory;
    const auto source = directory.path / "file";
    write_file(source, "bytes\n");
    const auto store = directory.path / "store";
    REQUIRE(capture_component_files(
                observe_package_footprint({source.string()}), store)
                .complete);

    const auto generation = active_capture(store);
    write_file(generation / "files" / "000001", "tampered\n");
    // Distinct from `incomplete` on purpose: one says the capture never
    // finished, the other says it finished and something is damaging it.
    CHECK(verify_component_capture(store) ==
          ComponentCaptureState::corrupted);

    std::error_code error;
    fs::remove(generation / "files" / "000001", error);
    REQUIRE_FALSE(error);
    CHECK(verify_component_capture(store) ==
          ComponentCaptureState::corrupted);
}

TEST_CASE("a new capture leaves nothing of the previous one behind") {
    TempDirectory directory;
    const auto first = directory.path / "first";
    const auto second = directory.path / "second";
    write_file(first, "one\n");
    write_file(second, "two\n");
    const auto store = directory.path / "store";

    REQUIRE(capture_component_files(
                observe_package_footprint({first.string(), second.string()}),
                store)
                .complete);
    REQUIRE(fs::exists(active_capture(store) / "files" / "000002"));

    // A stale file left from a previous, larger capture could answer a
    // manifest entry from this run and make a short capture verify.
    REQUIRE(capture_component_files(
                observe_package_footprint({first.string()}), store)
                .complete);
    CHECK_FALSE(
        fs::exists(active_capture(store) / "files" / "000002"));
    CHECK(verify_component_capture(store) == ComponentCaptureState::usable);
}

TEST_CASE("a file that cannot be described is not captured as if it could") {
    TempDirectory directory;
    const auto opaque = directory.path / "src" / "directory-here";
    fs::create_directories(opaque);
    const auto good = directory.path / "src" / "file";
    write_file(good, "bytes\n");

    const auto store = directory.path / "store";
    const auto result = capture_component_files(
        observe_package_footprint({opaque.string(), good.string()}), store);

    // Present but unhashable: copying bytes we cannot describe would produce a
    // capture that verifies against nothing.
    CHECK_FALSE(result.complete);
    CHECK(result.captured == 0U);
    CHECK(result.failed.size() == 1U);
    CHECK(result.failed.front() == opaque.string());
    // A partial generation is never published as a restore point.
    CHECK(verify_component_capture(store) != ComponentCaptureState::usable);
}

TEST_CASE("a symlink is not captured as though it were its target") {
    // lstat says a symlink is not a regular file, so the footprint has no
    // digest for it, but an ifstream follows it and copies the target's bytes
    // quite happily. Unguarded, the store would hold the target's contents
    // under the symlink's path with an empty digest - a restore point that
    // restores something the package never installed there.
    //
    // Two checks in capture_component_files stop that, and this case pins the
    // pair rather than either one. Removing both lets the symlink into the
    // store and fails this; removing either alone does not, because the other
    // catches it. Said plainly here because the first version of this comment
    // credited one check with work the two do together, and a mutation of that
    // single check passed the suite.
    //
    // The earlier directory case pins nothing about those checks at all: a
    // directory fails to copy regardless.
    TempDirectory directory;
    const auto target = directory.path / "real-binary";
    write_file(target, "target-bytes\n", 0755);
    const auto link = directory.path / "link-to-binary";
    std::error_code error;
    fs::create_symlink(target, link, error);
    REQUIRE_FALSE(error);

    const auto store = directory.path / "store";
    const auto result = capture_component_files(
        observe_package_footprint({link.string(), target.string()}), store);

    CHECK_FALSE(result.complete);
    CHECK(result.captured == 0U);
    REQUIRE(result.failed.size() == 1U);
    CHECK(result.failed.front() == link.string());
    CHECK(verify_component_capture(store) != ComponentCaptureState::usable);
}

TEST_CASE("a failed capture preserves the previous usable generation") {
    TempDirectory directory;
    const auto live = directory.path / "live" / "nfqws2";
    write_file(live, "known-good\n", 0755);
    const auto store = directory.path / "store";
    REQUIRE(capture_component_files(
                observe_package_footprint({live.string()}), store)
                .complete);
    const auto selected_before = active_capture(store);

    write_file(live, "uncertain-new\n", 0755);
    const auto opaque = directory.path / "live" / "not-a-file";
    fs::create_directories(opaque);
    const auto failed = capture_component_files(
        observe_package_footprint({live.string(), opaque.string()}), store);

    CHECK_FALSE(failed.complete);
    CHECK(active_capture(store) == selected_before);
    CHECK(verify_component_capture(store) == ComponentCaptureState::usable);
    REQUIRE(restore_component_files(store).complete);
    std::ifstream restored(live);
    std::string body((std::istreambuf_iterator<char>(restored)),
                     std::istreambuf_iterator<char>());
    CHECK(body == "known-good\n");
}

TEST_CASE("a footprint with nothing present captures nothing and says so") {
    TempDirectory directory;
    const auto store = directory.path / "store";
    const auto result = capture_component_files(
        observe_package_footprint({(directory.path / "absent").string()}),
        store);
    CHECK_FALSE(result.complete);
    CHECK(result.captured == 0U);
    CHECK(verify_component_capture(store) !=
          ComponentCaptureState::usable);
}

TEST_CASE("a restore puts the captured bytes and modes back") {
    TempDirectory directory;
    const auto binary = directory.path / "live" / "nfqws2";
    const auto blob = directory.path / "live" / "quic initial.bin";
    write_file(binary, "old-binary\n", 0755);
    write_file(blob, "old-blob\n", 0644);

    const auto store = directory.path / "store";
    REQUIRE(capture_component_files(
                observe_package_footprint({binary.string(), blob.string()}),
                store)
                .complete);

    write_file(binary, "new-binary-that-fails\n", 0644);
    std::error_code error;
    fs::remove(blob, error);
    REQUIRE_FALSE(error);

    const auto restored = restore_component_files(store);
    CHECK(restored.complete);
    CHECK(restored.restored == 2U);
    CHECK(restored.refused.empty());

    std::ifstream check(binary);
    std::string body((std::istreambuf_iterator<char>(check)),
                     std::istreambuf_iterator<char>());
    CHECK(body == "old-binary\n");
    struct stat info {};
    REQUIRE(::lstat(binary.c_str(), &info) == 0);
    // A binary restored without its execute bit runs no better than one that
    // was never restored.
    CHECK((info.st_mode & 07777) == 0755U);
    CHECK(fs::exists(blob, error));
}

TEST_CASE("a restore refuses a capture it cannot trust, before touching anything") {
    TempDirectory directory;
    const auto live = directory.path / "live" / "nfqws2";
    write_file(live, "current\n", 0755);
    const auto store = directory.path / "store";
    REQUIRE(capture_component_files(
                observe_package_footprint({live.string()}), store)
                .complete);

    write_file(live, "newer\n", 0755);
    write_file(active_capture(store) / "files" / "000001", "rotted\n");

    // Discovering damage halfway through leaves the component neither the old
    // one nor the new one, which is worse than both.
    const auto refused = restore_component_files(store);
    CHECK_FALSE(refused.complete);
    CHECK(refused.restored == 0U);
    CHECK(refused.refused == "corrupted");

    std::ifstream check(live);
    std::string body((std::istreambuf_iterator<char>(check)),
                     std::istreambuf_iterator<char>());
    CHECK(body == "newer\n");
}

TEST_CASE("restoring from nothing is a refusal, not a silent success") {
    TempDirectory directory;
    const auto result = restore_component_files(directory.path / "never");
    CHECK_FALSE(result.complete);
    CHECK(result.refused == "absent");
}

TEST_CASE("every capture state has a distinct stable name") {
    std::set<std::string> names;
    for (const auto state : {ComponentCaptureState::usable,
                             ComponentCaptureState::absent,
                             ComponentCaptureState::incomplete,
                             ComponentCaptureState::corrupted}) {
        const std::string name = component_capture_state_name(state);
        CHECK_FALSE(name.empty());
        CHECK(names.insert(name).second);
    }
}

TEST_CASE("v2 capture stays readable and manual restore preserves new files") {
    TempDirectory directory;
    const auto live = directory.path / "live" / "binary";
    const auto added = directory.path / "live" / "new-file";
    const auto store = directory.path / "store";
    write_file(live, "old\n", 0755);
    REQUIRE(capture_component_files(
                observe_package_footprint({live.string(), added.string()}), store)
                .complete);
    CHECK(read_file(active_capture(store) / "manifest").find(
              "keen-pbr-component-capture-v2\n") == 0U);
    write_file(live, "new\n");
    write_file(added, "keep\n");
    const auto restored = restore_component_files(store, true);
    CHECK(restored.complete);
    CHECK(restored.removed == 0U);
    CHECK(read_file(live) == "old\n");
    CHECK(read_file(added) == "keep\n");
}

TEST_CASE("v3 upgrade union survives lost lists and preserves colliding user bytes") {
    TempDirectory directory;
    const auto live = directory.path / "live" / "binary";
    const auto user = directory.path / "live" / "existing-user-file";
    const auto added = directory.path / "live" / "target-only";
    const auto sibling = directory.path / "live" / "unlisted-sibling";
    const auto list = directory.path / "opkg.list";
    const auto store = directory.path / "store";
    write_file(live, "old-binary\n", 0755);
    write_file(user, "operator-owned\n", 0600);
    write_file(sibling, "unrelated\n");
    write_file(list, live.string() + "\n");
    {
        const auto previous = observe_package_footprint({live.string()});
        const auto capture = capture_component_upgrade_files(
            previous, {live.string(), user.string(), added.string()}, store);
        REQUIRE(capture.complete);
        CHECK(capture.captured == 2U);
        CHECK(capture.skipped_absent == 1U);
    } // No old footprint or target vector survives into recovery.
    const auto generation = active_capture(store);
    CHECK(read_file(generation / "manifest").find(
              "keen-pbr-component-capture-v3\n") == 0U);
    CHECK(verify_component_capture(store) == ComponentCaptureState::usable);
    write_file(live, "failed-upgrade\n");
    write_file(user, "package-overwrite\n");
    write_file(added, "new-package-file\n");
    REQUIRE(fs::remove(list));

    const auto manual = restore_component_files(store);
    CHECK(manual.complete);
    CHECK(manual.removed == 0U);
    CHECK(read_file(added) == "new-package-file\n");
    CHECK(read_file(user) == "operator-owned\n");

    const auto recovered = restore_component_files(fs::path(store.string()), true);
    CHECK(recovered.complete);
    CHECK_FALSE(recovered.exact_package_state);
    CHECK(recovered.restored == 2U);
    CHECK(recovered.removed == 1U);
    CHECK_FALSE(fs::exists(added));
    CHECK(read_file(live) == "old-binary\n");
    CHECK(read_file(user) == "operator-owned\n");
    CHECK(read_file(sibling) == "unrelated\n");
    const auto repeated = restore_component_files(store, true);
    CHECK(repeated.complete);
    CHECK(repeated.removed == 0U);
}

TEST_CASE("v3 recorded absence unlinks symlink leaf without touching its target") {
    TempDirectory directory;
    const auto live = directory.path / "live" / "binary";
    const auto added = directory.path / "live" / "added-link";
    const auto outside = directory.path / "unrelated";
    const auto store = directory.path / "store";
    write_file(live, "old\n");
    write_file(outside, "untouched\n");
    REQUIRE(capture_component_upgrade_files(observe_package_footprint({live.string()}),
                {added.string()}, store).complete);
    fs::create_symlink(outside, added);
    const auto restored = restore_component_files(store, true);
    CHECK(restored.complete);
    CHECK(restored.removed == 1U);
    CHECK_FALSE(fs::is_symlink(fs::symlink_status(added)));
    CHECK(read_file(outside) == "untouched\n");
}

TEST_CASE("v3 absence recovery refuses directories and parent symlinks") {
    TempDirectory directory;
    const auto live = directory.path / "live" / "binary";
    const auto added = directory.path / "new-directory" / "added";
    const auto store = directory.path / "store";
    write_file(live, "old\n");
    REQUIRE(capture_component_upgrade_files(observe_package_footprint({live.string()}),
                {added.string()}, store).complete);

    SUBCASE("directory leaf is not a file and is never recursively removed") {
        write_file(added / "child", "keep\n");
        const auto restored = restore_component_files(store, true);
        CHECK_FALSE(restored.complete);
        CHECK(restored.removed == 0U);
        REQUIRE(restored.failed.size() == 1U);
        CHECK(restored.failed.front() == added.string());
        CHECK(read_file(added / "child") == "keep\n");
    }
    SUBCASE("parent symlink cannot redirect an exact leaf removal") {
        const auto outside = directory.path / "outside";
        write_file(outside / "added", "keep\n");
        fs::create_directory_symlink(outside, added.parent_path());
        const auto restored = restore_component_files(store, true);
        CHECK_FALSE(restored.complete);
        CHECK(restored.removed == 0U);
        CHECK(read_file(outside / "added") == "keep\n");
    }
    SUBCASE("already missing parent succeeds without creating directories") {
        const auto restored = restore_component_files(store, true);
        CHECK(restored.complete);
        CHECK(restored.removed == 0U);
        CHECK_FALSE(fs::exists(added.parent_path()));
    }
    SUBCASE("nonregular leaf is blocked rather than unlinked") {
        fs::create_directories(added.parent_path());
        REQUIRE(::mkfifo(added.c_str(), 0600) == 0);
        const auto restored = restore_component_files(store, true);
        CHECK_FALSE(restored.complete);
        CHECK(restored.removed == 0U);
        struct stat state {};
        REQUIRE(::lstat(added.c_str(), &state) == 0);
        CHECK(S_ISFIFO(state.st_mode));
    }
}

TEST_CASE("failed present restoration prevents all absence removals") {
    TempDirectory directory;
    const auto live = directory.path / "live" / "binary";
    const auto added = directory.path / "added";
    const auto store = directory.path / "store";
    write_file(live, "old\n");
    REQUIRE(capture_component_upgrade_files(observe_package_footprint({live.string()}),
                {added.string()}, store).complete);
    const auto moved = directory.path / "moved";
    fs::rename(live.parent_path(), moved);
    fs::create_directory_symlink(moved, live.parent_path());
    write_file(added, "keep until old bytes can be restored\n");
    const auto restored = restore_component_files(store, true);
    CHECK_FALSE(restored.complete);
    CHECK(restored.restored == 0U);
    CHECK(restored.removed == 0U);
    CHECK(fs::exists(added));
}

TEST_CASE("v3 capture refuses unknown absence and preserves previous generation") {
    TempDirectory directory;
    const auto live = directory.path / "live";
    const auto added = directory.path / "added";
    const auto store = directory.path / "store";
    write_file(live, "old\n");
    REQUIRE(capture_component_files(observe_package_footprint({live.string()}),
                store).complete);
    const auto selected = active_capture(store);
    auto observation = observe_package_footprint({live.string(), added.string()});
    SUBCASE("unreadable flag is not absence even on a caller-built footprint") {
        for (auto& file : observation.files)
            if (file.path == added.string()) file.unreadable = true;
    }
    SUBCASE("absence changed since observation must be captured anew") {
        write_file(added, "new user data\n");
    }
    SUBCASE("duplicate manifest destinations are refused") {
        observation.files.push_back(observation.files.front());
    }
    SUBCASE("ancestor and descendant destinations conflict") {
        PackageFileState nested;
        nested.path = (added / "nested").string();
        observation.files.push_back(nested);
    }
    const auto captured = capture_component_files(observation, store, true);
    CHECK_FALSE(captured.complete);
    CHECK(active_capture(store) == selected);
    CHECK(verify_component_capture(store) == ComponentCaptureState::usable);
}

TEST_CASE("v3 capture refuses ENOTDIR or symlink parents rather than recording absence") {
    TempDirectory directory;
    const auto live = directory.path / "live";
    const auto parent = directory.path / "parent";
    const auto added = parent / "absent";
    const auto store = directory.path / "store";
    write_file(live, "old\n");
    SUBCASE("non-directory parent") { write_file(parent, "not a directory\n"); }
    SUBCASE("symlink parent") {
        const auto outside = directory.path / "outside";
        fs::create_directory(outside);
        fs::create_directory_symlink(outside, parent);
    }
    const auto captured = capture_component_upgrade_files(
        observe_package_footprint({live.string()}), {added.string()}, store);
    CHECK_FALSE(captured.complete);
    CHECK(verify_component_capture(store) != ComponentCaptureState::usable);
}

TEST_CASE("v3 parser rejects truncated and conflicting ready manifests") {
    TempDirectory directory;
    const auto live = directory.path / "live";
    const auto added = directory.path / "added";
    const auto store = directory.path / "store";
    write_file(live, "old\n");
    REQUIRE(capture_component_upgrade_files(observe_package_footprint({live.string()}),
                {added.string()}, store).complete);
    const auto generation = active_capture(store);
    auto manifest = read_file(generation / "manifest");
    SUBCASE("truncated final line even with matching ready hash") {
        manifest.pop_back();
    }
    SUBCASE("duplicate absent path") {
        manifest += "A 3 " + added.string() + "\n";
    }
    SUBCASE("absent path conflicts with present path") {
        manifest += "A 3 " + live.string() + "\n";
    }
    SUBCASE("absent path is missing") { manifest += "A 3\n"; }
    replace_ready_manifest(generation, manifest);
    CHECK(verify_component_capture(store) == ComponentCaptureState::incomplete);
    CHECK_FALSE(restore_component_files(store, true).complete);
    CHECK(read_file(live) == "old\n");
}

TEST_CASE("upgrade union bounds failures do not replace a usable v2 capture") {
    TempDirectory directory;
    const auto live = directory.path / "live";
    const auto store = directory.path / "store";
    write_file(live, "old\n");
    const auto previous = observe_package_footprint({live.string()});
    REQUIRE(capture_component_files(previous, store).complete);
    const auto selected = active_capture(store);
    CHECK_FALSE(capture_component_upgrade_files(previous, {}, store).complete);
    CHECK_FALSE(capture_component_upgrade_files(previous,
                    std::vector<std::string>(kComponentMaxPathCount + 1U,
                                             live.string()), store).complete);
    CHECK_FALSE(capture_component_files(observe_package_footprint(
                    {(directory.path / "only-absent").string()}), store, true)
                    .complete);
    CHECK(active_capture(store) == selected);
    CHECK(verify_component_capture(store) == ComponentCaptureState::usable);
}

TEST_CASE("v4 manual restore skips all metadata and recorded absences") {
    CaptureMetadataFixture fixture;
    const auto capture = fixture.capture();
    REQUIRE(capture.complete);
    CHECK(capture.metadata_recorded);
    CHECK(read_file(active_capture(fixture.store) / "manifest").find(
              "keen-pbr-component-capture-v4\n") == 0U);
    fixture.upgrade();
    REQUIRE(fs::remove(fixture.info("list")));
    const auto current_status = read_file(fixture.metadata.status_file);
    const auto restored = restore_component_files(fixture.store);
    CHECK(restored.complete);
    CHECK(restored.payload_restored);
    CHECK(restored.metadata_recorded);
    CHECK_FALSE(restored.metadata_restored);
    CHECK(restored.metadata_failed.empty());
    CHECK(read_file(fixture.live) == "old-payload\n");
    CHECK(fs::exists(fixture.added));
    CHECK_FALSE(fs::exists(fixture.info("list")));
    CHECK(read_file(fixture.info("control")) == "new-control\n");
    CHECK(fs::exists(fixture.info("postinst")));
    CHECK(read_file(fixture.metadata.status_file) == current_status);
}

TEST_CASE("v4 reload restores exact package info and only the target status paragraph") {
    CaptureMetadataFixture fixture;
    REQUIRE(fixture.capture().complete);
    const auto unrelated = fixture.upgrade();
    REQUIRE(fs::remove(fixture.info("list"))); // opkg's current record was lost.
    const auto foreign_info = fixture.metadata.info_directory / "new-package.postinst";
    write_file(foreign_info, "unrelated-new-script\n");
    const auto status_old = fixture.metadata.status_file.parent_path() / "status-old";
    write_file(status_old, "global-backup-not-ours\n");

    const auto restored = restore_component_files(fs::path(fixture.store.string()), true, "1");
    REQUIRE(restored.complete);
    CHECK(restored.payload_restored);
    CHECK(restored.metadata_recorded);
    CHECK(restored.metadata_restored);
    CHECK_FALSE(restored.exact_package_state);
    CHECK(restored.metadata_failed.empty());
    CHECK(read_file(fixture.live) == "old-payload\n");
    CHECK_FALSE(fs::exists(fixture.added));
    CHECK(read_file(fixture.info("list")) == fixture.live.string() + "\n");
    CHECK(read_file(fixture.info("control")) == "Package: nfqws2-keenetic\nVersion: 1\n");
    CHECK_FALSE(fs::exists(fixture.info("postinst")));
    CHECK(read_file(foreign_info) == "unrelated-new-script\n");
    CHECK(read_file(status_old) == "global-backup-not-ours\n");
    CHECK(read_file(fixture.metadata.status_file) == fixture.target("1") + "\n" + unrelated);
    struct stat current_status {};
    REQUIRE(::lstat(fixture.metadata.status_file.c_str(), &current_status) == 0);
    CHECK((current_status.st_mode & 07777) == 0600U); // Preserve CURRENT database mode.
    CHECK(restore_component_files(fixture.store, true, "1").metadata_restored);
}

TEST_CASE("v4 missing target status paragraph is rebuilt without replacing unrelated database") {
    CaptureMetadataFixture fixture;
    REQUIRE(fixture.capture().complete);
    const auto unrelated = fixture.upgrade();
    write_file(fixture.metadata.status_file, unrelated);
    const auto restored = restore_component_files(fixture.store, true, "1");
    REQUIRE(restored.complete);
    CHECK(restored.metadata_restored);
    CHECK(read_file(fixture.metadata.status_file) == unrelated + fixture.target("1"));
}

TEST_CASE("v4 bad current metadata preserves database while still restoring payload") {
    CaptureMetadataFixture fixture;
    REQUIRE(fixture.capture().complete);
    fixture.upgrade();
    std::string expected_version = "1";
    SUBCASE("malformed current database") {
        write_file(fixture.metadata.status_file, "not an opkg database\n");
    }
    SUBCASE("empty current database") { write_file(fixture.metadata.status_file, ""); }
    SUBCASE("journal version differs from saved target") { expected_version = "different"; }
    SUBCASE("native lock unavailable") {
        REQUIRE(fs::remove(fixture.metadata.lock_file));
        fs::create_directory(fixture.metadata.lock_file);
    }
    const auto status = read_file(fixture.metadata.status_file);
    const auto restored = restore_component_files(fixture.store, true, expected_version);
    CHECK_FALSE(restored.complete);
    CHECK(restored.payload_restored);
    CHECK(restored.metadata_recorded);
    CHECK_FALSE(restored.metadata_restored);
    CHECK_FALSE(restored.metadata_failed.empty());
    CHECK(restored.failed.empty());
    CHECK(read_file(fixture.live) == "old-payload\n");
    CHECK_FALSE(fs::exists(fixture.added));
    CHECK(read_file(fixture.metadata.status_file) == status);
    CHECK(read_file(fixture.info("list")) == "new-list\n");
    CHECK(read_file(fixture.info("postinst")) == "new-script\n");
    CHECK(verify_component_capture(fixture.store) == ComponentCaptureState::usable);
}

TEST_CASE("v4 damaged optional metadata cannot invalidate verified payload recovery") {
    CaptureMetadataFixture fixture;
    REQUIRE(fixture.capture().complete);
    const auto generation = active_capture(fixture.store);
    SUBCASE("saved shared status blob missing") { REQUIRE(fs::remove(stored_kind(generation, 'S'))); }
    SUBCASE("saved info blob corrupted") { write_file(stored_kind(generation, 'M'), "rot\n"); }
    fixture.upgrade();
    const auto status = read_file(fixture.metadata.status_file);
    CHECK(verify_component_capture(fixture.store) == ComponentCaptureState::usable);
    const auto restored = restore_component_files(fixture.store, true, "1");
    CHECK_FALSE(restored.complete);
    CHECK(restored.payload_restored);
    CHECK_FALSE(restored.metadata_restored);
    CHECK_FALSE(restored.metadata_failed.empty());
    CHECK(read_file(fixture.live) == "old-payload\n");
    CHECK_FALSE(fs::exists(fixture.added));
    CHECK(read_file(fixture.info("list")) == "new-list\n");
    CHECK(read_file(fixture.metadata.status_file) == status);
    CHECK(restore_component_files(fixture.store).complete);
}

TEST_CASE("v4 capture failure preserves the previous usable payload generation") {
    CaptureMetadataFixture fixture;
    REQUIRE(capture_component_upgrade_files(observe_package_footprint({fixture.live.string()}),
                {fixture.added.string()}, fixture.store).complete);
    const auto selected = active_capture(fixture.store);
    SUBCASE("malformed saved database") { write_file(fixture.metadata.status_file, "broken\n"); }
    SUBCASE("saved target is not installed") {
        write_file(fixture.metadata.status_file,
            "Package: nfqws2-keenetic\nVersion: 1\nStatus: install user unpacked\n");
    }
    SUBCASE("missing shared status is never recorded absent") {
        REQUIRE(fs::remove(fixture.metadata.status_file));
    }
    SUBCASE("unreadable info type") {
        REQUIRE(fs::remove(fixture.info("list")));
        fs::create_directory(fixture.info("list"));
    }
    const auto capture = fixture.capture();
    CHECK_FALSE(capture.complete);
    CHECK_FALSE(capture.metadata_recorded);
    CHECK(active_capture(fixture.store) == selected);
    CHECK(verify_component_capture(fixture.store) == ComponentCaptureState::usable);
}

TEST_CASE("v4 info restore refuses a directory without committing target status") {
    CaptureMetadataFixture fixture;
    REQUIRE(fixture.capture().complete);
    fixture.upgrade();
    const auto status = read_file(fixture.metadata.status_file);
    REQUIRE(fs::remove(fixture.info("list")));
    write_file(fixture.info("list") / "user-child", "keep\n");
    const auto restored = restore_component_files(fixture.store, true, "1");
    CHECK_FALSE(restored.complete);
    CHECK(restored.payload_restored);
    CHECK_FALSE(restored.metadata_restored);
    CHECK(read_file(fixture.info("list") / "user-child") == "keep\n");
    CHECK(read_file(fixture.metadata.status_file) == status);
    CHECK(fs::exists(fixture.info("postinst")));
}

TEST_CASE("reinstall preparation leaves legacy v2 and v3 captures as metadata-free no-ops") {
    CaptureMetadataFixture fixture;
    const auto footprint = observe_package_footprint({fixture.live.string()});
    SUBCASE("v2 captured payload only") {
        REQUIRE(capture_component_files(footprint, fixture.store).complete);
    }
    SUBCASE("v3 captured payload and target absences") {
        REQUIRE(capture_component_upgrade_files(footprint,
                    {fixture.added.string()}, fixture.store).complete);
    }
    fixture.upgrade();
    const std::string broken = "foreign status data cannot be reconstructed\n";
    write_file(fixture.metadata.status_file, broken);
    const auto selected = active_capture(fixture.store);
    const auto prepared = prepare_component_capture_reinstall(fixture.store, "1");
    CHECK(prepared.complete);
    CHECK_FALSE(prepared.metadata_recorded);
    CHECK_FALSE(prepared.status_repaired);
    CHECK(prepared.error.empty());
    CHECK(read_file(fixture.metadata.status_file) == broken);
    CHECK(active_capture(fixture.store) == selected);
    check_reinstall_preparation_left_files_untouched(fixture);
}

TEST_CASE("reinstall preparation does not rewrite healthy v4 status or require saved metadata") {
    CaptureMetadataFixture fixture;
    REQUIRE(fixture.capture().complete);
    fixture.upgrade();
    const auto generation = active_capture(fixture.store);
    SUBCASE("saved status intact") {}
    SUBCASE("saved optional status missing") {
        REQUIRE(fs::remove(stored_kind(generation, 'S')));
    }
    SUBCASE("saved optional status corrupted") {
        write_file(stored_kind(generation, 'S'), "damaged optional metadata\n");
    }
    const auto status = read_file(fixture.metadata.status_file);
    struct stat before {}, after {};
    REQUIRE(::lstat(fixture.metadata.status_file.c_str(), &before) == 0);
    // A healthy live database needs no snapshot restoration, including when
    // the recorded version is different from the interrupted transaction.
    const auto prepared = prepare_component_capture_reinstall(
        fs::path(fixture.store.string()), "different-saved-version");
    CHECK(prepared.complete);
    CHECK(prepared.metadata_recorded);
    CHECK_FALSE(prepared.status_repaired);
    CHECK(prepared.error.empty());
    CHECK(read_file(fixture.metadata.status_file) == status);
    REQUIRE(::lstat(fixture.metadata.status_file.c_str(), &after) == 0);
    CHECK(after.st_ino == before.st_ino);
    CHECK(after.st_dev == before.st_dev);
    CHECK((after.st_mode & 07777) == (before.st_mode & 07777));
    check_reinstall_preparation_left_files_untouched(fixture);
}

TEST_CASE("reinstall preparation repairs only a uniquely identified torn target before opkg") {
    CaptureMetadataFixture fixture;
    REQUIRE(fixture.capture().complete);
    fixture.upgrade();
    const std::string foreign_before =
        "Package: unrelated\r\nVersion: newer\r\nStatus: install user installed\r\n"
        "X-Unknown: preserve trailing spaces  \r\n\r\n";
    const auto foreign_after = package_paragraph("new-package", "7") + "\n";
    const std::string broken_target =
        "Package: nfqws2-keenetic\nVersion: 2\nStatus: install user installed\n"
        "Torn field without colon\n";
    write_file(fixture.metadata.status_file,
               foreign_before + broken_target + "\n" + foreign_after, 0600);
    const auto foreign_info = fixture.metadata.info_directory / "new-package.list";
    const auto status_old = fixture.metadata.status_file.parent_path() / "status-old";
    write_file(foreign_info, "unrelated new-package file list\n");
    write_file(status_old, "shared backup remains unchanged\n");
    const auto prepared_status = foreign_before + fixture.target("1") + "\n" + foreign_after;
    const auto prepared = prepare_component_capture_reinstall(
        fs::path(fixture.store.string()), "1");
    REQUIRE(prepared.complete);
    CHECK(prepared.metadata_recorded);
    CHECK(prepared.status_repaired);
    CHECK(prepared.error.empty());
    CHECK(read_file(fixture.metadata.status_file) == prepared_status);
    check_reinstall_preparation_left_files_untouched(fixture);
    CHECK(read_file(foreign_info) == "unrelated new-package file list\n");
    CHECK(read_file(status_old) == "shared backup remains unchanged\n");
    struct stat repaired_status {};
    REQUIRE(::lstat(fixture.metadata.status_file.c_str(), &repaired_status) == 0);
    CHECK((repaired_status.st_mode & 07777) == 0600U);

    const auto repeated = prepare_component_capture_reinstall(fixture.store, "1");
    CHECK(repeated.complete);
    CHECK_FALSE(repeated.status_repaired);
    CHECK(read_file(fixture.metadata.status_file) == prepared_status);

    // Simulate the existing reinstall callback only after preparation has
    // made the target paragraph readable to opkg. No real package command runs.
    bool opkg_called = false;
    const auto installed_during_recovery = package_paragraph("during-recovery", "3") + "\n";
    const auto reinstall = [&]() {
        REQUIRE(prepared.complete);
        CHECK(read_file(fixture.metadata.status_file) == prepared_status);
        opkg_called = true;
        write_file(fixture.live, "reinstalled-old-ipk-payload\n", 0755);
        write_file(fixture.info("list"), "reinstalled package list\n");
        write_file(fixture.metadata.status_file,
            foreign_before + fixture.target("1") + "Installed-Time: current\n\n" +
            foreign_after + installed_during_recovery, 0600);
    };
    CHECK_FALSE(opkg_called);
    reinstall();
    REQUIRE(opkg_called);
    const auto restored = restore_component_files(fixture.store, true, "1");
    REQUIRE(restored.complete);
    CHECK(restored.payload_restored);
    CHECK(restored.metadata_restored);
    CHECK(read_file(fixture.live) == "old-payload\n");
    CHECK_FALSE(fs::exists(fixture.added));
    CHECK(read_file(fixture.info("list")) == fixture.live.string() + "\n");
    CHECK_FALSE(fs::exists(fixture.info("postinst")));
    CHECK(read_file(fixture.metadata.status_file) ==
          prepared_status + installed_during_recovery);
    CHECK(read_file(foreign_info) == "unrelated new-package file list\n");
    CHECK(read_file(status_old) == "shared backup remains unchanged\n");
}

TEST_CASE("reinstall preparation refuses unrepairable live databases without losing payload recovery") {
    CaptureMetadataFixture fixture;
    REQUIRE(fixture.capture().complete);
    fixture.upgrade();
    bool missing = false;
    SUBCASE("missing shared database") {
        REQUIRE(fs::remove(fixture.metadata.status_file));
        missing = true;
    }
    SUBCASE("empty shared database") { write_file(fixture.metadata.status_file, ""); }
    SUBCASE("malformed foreign package paragraph") {
        write_file(fixture.metadata.status_file, fixture.target("2") + "\n" +
            "Package: unrelated\nVersion: newer\nTorn foreign field\n");
    }
    SUBCASE("ambiguous duplicate target paragraphs") {
        write_file(fixture.metadata.status_file,
                   fixture.target("2") + "\n" + fixture.target("3") + "\n");
    }
    SUBCASE("unidentifiable torn paragraph") {
        write_file(fixture.metadata.status_file, fixture.target("2") +
                   "\nVersion: unknown-owner\nTorn field\n");
    }
    const auto status = missing ? std::string{} : read_file(fixture.metadata.status_file);
    const auto prepared = prepare_component_capture_reinstall(fixture.store, "1");
    CHECK_FALSE(prepared.complete);
    CHECK(prepared.metadata_recorded);
    CHECK_FALSE(prepared.status_repaired);
    CHECK_FALSE(prepared.error.empty());
    check_reinstall_preparation_left_files_untouched(fixture);
    if (missing) CHECK_FALSE(fs::exists(fixture.metadata.status_file));
    else CHECK(read_file(fixture.metadata.status_file) == status);
    CHECK(verify_component_capture(fixture.store) == ComponentCaptureState::usable);
    const auto restored = restore_component_files(fixture.store, false);
    REQUIRE(restored.complete);
    CHECK(restored.payload_restored);
    CHECK_FALSE(restored.metadata_restored);
    CHECK(read_file(fixture.live) == "old-payload\n");
    CHECK(read_file(fixture.info("list")) == "new-list\n");
    CHECK(fs::exists(fixture.added));
    if (missing) CHECK_FALSE(fs::exists(fixture.metadata.status_file));
    else CHECK(read_file(fixture.metadata.status_file) == status);
}

TEST_CASE("v4 reconstructs a lost shared status from confirmed foreign metadata before reinstall") {
    CaptureMetadataFixture fixture;
    const auto foreign_alpha = package_paragraph("foreign-alpha", "4") + "\n";
    const auto foreign_beta = package_paragraph("foreign-beta", "7") + "\n";
    write_file(fixture.metadata.status_file,
               fixture.target("1") + "\n" + foreign_alpha + foreign_beta, 0640);
    for (const auto& package : {std::string("foreign-alpha"), std::string("foreign-beta")}) {
        const auto version = package == "foreign-alpha" ? "4" : "7";
        const auto payload = fixture.directory.path / "live" / package;
        write_file(payload, package + "-payload\n");
        write_file(fixture.metadata.info_directory / (package + ".control"),
                   "Package: " + package + "\nVersion: " + version + "\n");
        write_file(fixture.metadata.info_directory / (package + ".list"),
                   payload.string() + "\n");
    }
    REQUIRE(fixture.capture().complete);
    fixture.upgrade();
    mode_t expected_mode = 0600;
    SUBCASE("whole status file lost uses same-generation saved attributes") {
        REQUIRE(fs::remove(fixture.metadata.status_file));
        expected_mode = 0640;
    }
    SUBCASE("whole status file empty preserves current attributes") {
        write_file(fixture.metadata.status_file, "", 0600);
    }
    const auto selected = active_capture(fixture.store);
    const auto prepared = prepare_component_capture_reinstall(fixture.store, "1");
    REQUIRE(prepared.complete);
    CHECK(prepared.metadata_recorded);
    CHECK(prepared.status_repaired);
    CHECK(prepared.shared_database_reconstructed);
    CHECK(prepared.error.empty());
    check_reinstall_preparation_left_files_untouched(fixture);
    CHECK(active_capture(fixture.store) == selected);
    struct stat status {};
    REQUIRE(::lstat(fixture.metadata.status_file.c_str(), &status) == 0);
    CHECK((status.st_mode & 07777) == expected_mode);
    const auto reconstructed = read_file(fixture.metadata.status_file);
    CHECK(reconstructed.find(foreign_alpha) != std::string::npos);
    CHECK(reconstructed.find(foreign_beta) != std::string::npos);
    CHECK(reconstructed.find("Package: unrelated\n") == std::string::npos);
    // These are structurally recovered records, not proof that foreign
    // status-only flags still match their state immediately before power loss.
    const auto target = reconstructed.find(fixture.target("1"));
    REQUIRE(target != std::string::npos);
    auto after_reinstall = reconstructed;
    after_reinstall.insert(target + fixture.target("1").size(), "Installed-Time: current\n");
    write_file(fixture.live, "reinstalled-old-ipk-payload\n", 0755);
    write_file(fixture.info("list"), "reinstalled package list\n");
    write_file(fixture.metadata.status_file, after_reinstall);

    const auto restored = restore_component_files(fixture.store, true, "1");
    REQUIRE(restored.complete);
    CHECK(restored.payload_restored);
    CHECK(restored.metadata_restored);
    CHECK_FALSE(restored.exact_package_state);
    CHECK(read_file(fixture.live) == "old-payload\n");
    CHECK_FALSE(fs::exists(fixture.added));
    CHECK(read_file(fixture.info("control")) == "Package: nfqws2-keenetic\nVersion: 1\n");
    CHECK(read_file(fixture.info("list")) == fixture.live.string() + "\n");
    CHECK_FALSE(fs::exists(fixture.info("postinst")));
    CHECK(read_file(fixture.metadata.status_file) == reconstructed);
    for (const auto& package : {std::string("foreign-alpha"), std::string("foreign-beta")}) {
        const auto version = package == "foreign-alpha" ? "4" : "7";
        const auto payload = fixture.directory.path / "live" / package;
        CHECK(read_file(payload) == package + "-payload\n");
        CHECK(read_file(fixture.metadata.info_directory / (package + ".control")) ==
              "Package: " + package + "\nVersion: " + version + "\n");
        CHECK(read_file(fixture.metadata.info_directory / (package + ".list")) ==
              payload.string() + "\n");
    }
}

TEST_CASE("v4 does not publish a shared status when a foreign version changed after capture") {
    CaptureMetadataFixture fixture;
    write_file(fixture.metadata.status_file, fixture.target("1") + "\n" +
               package_paragraph("foreign-alpha", "4") + "\n" +
               package_paragraph("foreign-beta", "7") + "\n");
    for (const auto& package : {std::string("foreign-alpha"), std::string("foreign-beta")}) {
        const auto version = package == "foreign-alpha" ? "4" : "7";
        const auto payload = fixture.directory.path / "live" / package;
        write_file(payload, package + "-payload\n");
        write_file(fixture.metadata.info_directory / (package + ".control"),
                   "Package: " + package + "\nVersion: " + version + "\n");
        write_file(fixture.metadata.info_directory / (package + ".list"),
                   payload.string() + "\n");
    }
    REQUIRE(fixture.capture().complete);
    fixture.upgrade();
    const auto changed_control = fixture.metadata.info_directory / "foreign-alpha.control";
    const std::string changed = "Package: foreign-alpha\nVersion: 5\n";
    write_file(changed_control, changed);
    bool missing = false;
    SUBCASE("lost status stays absent") {
        REQUIRE(fs::remove(fixture.metadata.status_file));
        missing = true;
    }
    SUBCASE("empty status stays empty") { write_file(fixture.metadata.status_file, ""); }
    const auto selected = active_capture(fixture.store);
    const auto prepared = prepare_component_capture_reinstall(fixture.store, "1");
    CHECK_FALSE(prepared.complete);
    CHECK(prepared.metadata_recorded);
    CHECK_FALSE(prepared.status_repaired);
    CHECK_FALSE(prepared.shared_database_reconstructed);
    CHECK_FALSE(prepared.error.empty());
    check_reinstall_preparation_left_files_untouched(fixture);
    CHECK(active_capture(fixture.store) == selected);
    CHECK(read_file(changed_control) == changed);
    if (missing) CHECK_FALSE(fs::exists(fixture.metadata.status_file));
    else CHECK(read_file(fixture.metadata.status_file).empty());
    CHECK(verify_component_capture(fixture.store) == ComponentCaptureState::usable);

    const auto restored = restore_component_files(fixture.store, false);
    REQUIRE(restored.complete);
    CHECK(restored.payload_restored);
    CHECK_FALSE(restored.metadata_restored);
    CHECK(read_file(fixture.live) == "old-payload\n");
    CHECK(fs::exists(fixture.added));
    CHECK(read_file(fixture.info("list")) == "new-list\n");
    CHECK(read_file(changed_control) == changed);
    if (missing) CHECK_FALSE(fs::exists(fixture.metadata.status_file));
    else CHECK(read_file(fixture.metadata.status_file).empty());
}

TEST_CASE("v4 missing shared status requires verified same-generation status bytes and attributes") {
    CaptureMetadataFixture fixture;
    write_file(fixture.metadata.status_file, fixture.target("1") + "\n", 0640);
    REQUIRE(fixture.capture().complete);
    fixture.upgrade();
    REQUIRE(fs::remove(fixture.metadata.status_file));
    const auto saved_status = stored_kind(active_capture(fixture.store), 'S');
    bool intact = true;
    SUBCASE("intact saved status is a positive control") {}
    SUBCASE("missing saved blob must not supply attributes alone") {
        REQUIRE(fs::remove(saved_status));
        intact = false;
    }
    SUBCASE("changed saved blob must not supply attributes alone") {
        write_file(saved_status, fixture.target("2") + "\n");
        intact = false;
    }
    CHECK(verify_component_capture(fixture.store) == ComponentCaptureState::usable);
    const auto prepared = prepare_component_capture_reinstall(fixture.store, "1");
    CHECK(prepared.complete == intact);
    CHECK(prepared.shared_database_reconstructed == intact);
    CHECK(prepared.status_repaired == intact);
    if (intact) {
        CHECK(read_file(fixture.metadata.status_file) == fixture.target("1") + "\n");
        struct stat status {};
        REQUIRE(::lstat(fixture.metadata.status_file.c_str(), &status) == 0);
        CHECK((status.st_mode & 07777) == 0640);
    } else {
        CHECK_FALSE(prepared.error.empty());
        CHECK_FALSE(fs::exists(fixture.metadata.status_file));
    }
    check_reinstall_preparation_left_files_untouched(fixture);
}

TEST_CASE("reinstall preparation requires verified matching saved status only when repair is needed") {
    CaptureMetadataFixture fixture;
    REQUIRE(fixture.capture().complete);
    fixture.upgrade();
    const auto generation = active_capture(fixture.store);
    const auto saved_status = stored_kind(generation, 'S');
    std::string expected_version = "1";
    SUBCASE("required saved status missing") { REQUIRE(fs::remove(saved_status)); }
    SUBCASE("required saved status digest mismatch") { write_file(saved_status, "corrupt\n"); }
    SUBCASE("required saved status has no target even with a valid stored digest") {
        const auto original = read_file(saved_status);
        auto invalid = original;
        const auto marker = invalid.find("Package: nfqws2-keenetic");
        REQUIRE(marker != std::string::npos);
        invalid.replace(marker, 7U, "Unknown");
        REQUIRE(invalid.size() == original.size());
        Sha256 before, after;
        before.update(original.data(), original.size());
        after.update(invalid.data(), invalid.size());
        auto manifest = read_file(generation / "manifest");
        const auto digest = manifest.find(before.hex_digest());
        REQUIRE(digest != std::string::npos);
        manifest.replace(digest, 64U, after.hex_digest());
        write_file(saved_status, invalid);
        replace_ready_manifest(generation, manifest);
    }
    SUBCASE("saved version does not match the interrupted transaction") { expected_version = "other"; }
    const auto broken_status =
        "Package: nfqws2-keenetic\nVersion: 2\nTorn target field\n\n" +
        package_paragraph("unrelated", "newer") + "\n";
    write_file(fixture.metadata.status_file, broken_status);
    const auto prepared = prepare_component_capture_reinstall(fixture.store, expected_version);
    CHECK_FALSE(prepared.complete);
    CHECK(prepared.metadata_recorded);
    CHECK_FALSE(prepared.status_repaired);
    CHECK_FALSE(prepared.error.empty());
    CHECK(read_file(fixture.metadata.status_file) == broken_status);
    check_reinstall_preparation_left_files_untouched(fixture);
    CHECK(verify_component_capture(fixture.store) == ComponentCaptureState::usable);
    REQUIRE(restore_component_files(fixture.store, false).complete);
    CHECK(read_file(fixture.live) == "old-payload\n");
    CHECK(read_file(fixture.metadata.status_file) == broken_status);
    CHECK(read_file(fixture.info("list")) == "new-list\n");
}

} // namespace keen_pbr3
