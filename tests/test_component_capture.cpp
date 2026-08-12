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
    fs::remove(store / ".ready", error);
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

    std::ofstream manifest(store / "manifest", std::ios::app);
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

    write_file(store / "files" / "000001", "tampered\n");
    // Distinct from `incomplete` on purpose: one says the capture never
    // finished, the other says it finished and something is damaging it.
    CHECK(verify_component_capture(store) ==
          ComponentCaptureState::corrupted);

    std::error_code error;
    fs::remove(store / "files" / "000001", error);
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
    REQUIRE(fs::exists(store / "files" / "000002"));

    // A stale file left from a previous, larger capture could answer a
    // manifest entry from this run and make a short capture verify.
    REQUIRE(capture_component_files(
                observe_package_footprint({first.string()}), store)
                .complete);
    CHECK_FALSE(fs::exists(store / "files" / "000002"));
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
    CHECK(result.captured == 1U);
    CHECK(result.failed.size() == 1U);
    CHECK(result.failed.front() == opaque.string());
    // What did get captured is still internally consistent - the caller is
    // told the restore point is incomplete, not handed a broken one.
    CHECK(verify_component_capture(store) == ComponentCaptureState::usable);
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
    CHECK(result.captured == 1U);
    REQUIRE(result.failed.size() == 1U);
    CHECK(result.failed.front() == link.string());
    CHECK(verify_component_capture(store) == ComponentCaptureState::usable);
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
