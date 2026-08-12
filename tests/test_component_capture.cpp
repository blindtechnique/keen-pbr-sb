#include <doctest/doctest.h>

#include "../src/update/component_capture.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <set>
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

} // namespace keen_pbr3
