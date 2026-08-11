#include <doctest/doctest.h>

#include "../src/update/package_footprint.hpp"

#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <fstream>
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
            (fs::temp_directory_path() / "keen-pbr-footprint-XXXXXX").string();
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

bool contains(const std::vector<std::string>& values,
              const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

} // namespace

TEST_CASE("the opkg file list is read as paths, not trusted as truth") {
    TempDirectory directory;
    const auto list = directory.path / "pkg.list";
    write_file(list,
               "/opt/etc/init.d/S51nfqws2\n"
               "/opt/etc/nfqws2/blobs/quic_initial.bin\n"
               "\n"
               "relative/path/ignored\n"
               "/opt/tmp/nfqws2_binary/nfqws2-x86\r\n");

    const auto paths = read_opkg_file_list(list);
    REQUIRE(paths.size() == 3U);
    CHECK(paths[0] == "/opt/etc/init.d/S51nfqws2");
    CHECK(paths[1] == "/opt/etc/nfqws2/blobs/quic_initial.bin");
    // Trailing CR survives a file written on the wrong platform; a path with
    // an invisible character at the end would never match anything on disk.
    CHECK(paths[2] == "/opt/tmp/nfqws2_binary/nfqws2-x86");
}

TEST_CASE("a missing opkg record is empty, and says nothing about the package") {
    TempDirectory directory;
    CHECK(read_opkg_file_list(directory.path / "absent.list").empty());
}

TEST_CASE("listed but absent files are recorded, not treated as damage") {
    // This is the measured shape of a healthy nfqws2 install: opkg lists a
    // binary per architecture and the postinst deletes the staging directory
    // once it has picked one. Eight of twenty-four listed files were absent on
    // the live router, and the install was in perfect health.
    TempDirectory directory;
    const auto present = directory.path / "present.bin";
    write_file(present, "payload\n");
    const auto absent = directory.path / "staged" / "other-arch";

    const auto footprint = observe_package_footprint(
        {present.string(), absent.string()});
    REQUIRE(footprint.files.size() == 2U);
    CHECK(footprint.present_count == 1U);
    CHECK(footprint.absent_count == 1U);
    CHECK(footprint.unreadable_count == 0U);

    for (const auto& state : footprint.files) {
        if (state.path == present.string()) {
            CHECK(state.present);
            CHECK_FALSE(state.sha256.empty());
            CHECK(state.mode == 0644U);
        } else {
            CHECK_FALSE(state.present);
            CHECK(state.sha256.empty());
        }
    }
}

TEST_CASE("duplicate paths collapse and the observation stays sorted") {
    TempDirectory directory;
    const auto b = directory.path / "b";
    const auto a = directory.path / "a";
    write_file(a, "a\n");
    write_file(b, "b\n");

    const auto footprint = observe_package_footprint(
        {b.string(), a.string(), b.string()});
    REQUIRE(footprint.files.size() == 2U);
    CHECK(footprint.files[0].path < footprint.files[1].path);
}

TEST_CASE("a directory where a file is expected cannot be hashed") {
    TempDirectory directory;
    const auto entry = directory.path / "not-a-file";
    fs::create_directories(entry);

    const auto footprint = observe_package_footprint({entry.string()});
    REQUIRE(footprint.files.size() == 1U);
    // Present and unreadable, not absent: an empty digest that compared equal
    // to another empty digest would make two different directories look like
    // an unchanged file.
    CHECK(footprint.files[0].present);
    CHECK(footprint.files[0].unreadable);
    CHECK(footprint.files[0].sha256.empty());
    CHECK(footprint.unreadable_count == 1U);
}

TEST_CASE("the diff separates change from appearance, loss and ignorance") {
    TempDirectory directory;
    const auto stable = directory.path / "stable";
    const auto edited = directory.path / "edited";
    const auto removed = directory.path / "removed";
    const auto added = directory.path / "added";
    const auto opaque = directory.path / "opaque";
    write_file(stable, "same\n");
    write_file(edited, "before\n");
    write_file(removed, "doomed\n");
    write_file(opaque, "readable\n");

    const std::vector<std::string> paths = {
        stable.string(), edited.string(), removed.string(),
        added.string(), opaque.string()};
    const auto before = observe_package_footprint(paths);

    write_file(edited, "after\n");
    std::error_code error;
    fs::remove(removed, error);
    REQUIRE_FALSE(error);
    write_file(added, "new\n");
    fs::remove(opaque, error);
    REQUIRE_FALSE(error);
    fs::create_directories(opaque);
    const auto after = observe_package_footprint(paths);

    const auto diff = diff_package_footprint(before, after);
    CHECK(contains(diff.changed, edited.string()));
    CHECK(contains(diff.removed, removed.string()));
    CHECK(contains(diff.added, added.string()));
    CHECK(contains(diff.indeterminate, opaque.string()));
    CHECK_FALSE(contains(diff.changed, stable.string()));
    // An unreadable file must never be counted as a change: otherwise every
    // permission error reads as the upgrade having done work.
    CHECK_FALSE(contains(diff.changed, opaque.string()));
}

TEST_CASE("a mode change is a change even when the bytes are identical") {
    TempDirectory directory;
    const auto binary = directory.path / "nfqws2";
    write_file(binary, "same-bytes\n", 0755);
    const auto before = observe_package_footprint({binary.string()});
    REQUIRE(::chmod(binary.c_str(), 0644) == 0);
    const auto after = observe_package_footprint({binary.string()});

    // An executable that lost its execute bit runs no better than one that was
    // deleted, and the bytes alone cannot see it.
    CHECK(contains(diff_package_footprint(before, after).changed,
                   binary.string()));
}

TEST_CASE("the binary verdict distinguishes every outcome that matters") {
    TempDirectory directory;
    const auto binary = directory.path / "nfqws2";
    const auto path = binary.string();

    const auto empty = observe_package_footprint({path});
    CHECK(judge_package_binary(empty, empty, path) ==
          PackageBinaryOutcome::absent_throughout);

    write_file(binary, "v1\n", 0755);
    const auto v1 = observe_package_footprint({path});
    CHECK(judge_package_binary(empty, v1, path) ==
          PackageBinaryOutcome::replaced);
    CHECK(judge_package_binary(v1, v1, path) ==
          PackageBinaryOutcome::unchanged);

    write_file(binary, "v2\n", 0755);
    const auto v2 = observe_package_footprint({path});
    CHECK(judge_package_binary(v1, v2, path) ==
          PackageBinaryOutcome::replaced);

    std::error_code error;
    fs::remove(binary, error);
    REQUIRE_FALSE(error);
    const auto gone = observe_package_footprint({path});
    // The one outcome that must never be reported as a successful upgrade.
    CHECK(judge_package_binary(v2, gone, path) ==
          PackageBinaryOutcome::missing_after);

    fs::create_directories(binary);
    const auto opaque = observe_package_footprint({path});
    CHECK(judge_package_binary(v2, opaque, path) ==
          PackageBinaryOutcome::indeterminate);
    // Loss is decided before readability: a binary that is gone is gone, and
    // that conclusion never needs the old side to have been hashable.
    CHECK(judge_package_binary(opaque, gone, path) ==
          PackageBinaryOutcome::missing_after);
}

TEST_CASE("a path never observed at all is not mistaken for a lost binary") {
    TempDirectory directory;
    const auto binary = directory.path / "nfqws2";
    write_file(binary, "v1\n", 0755);
    const auto observed = observe_package_footprint({binary.string()});
    const PackageFootprint unobserved;

    // Nothing was seen on either side of an absent observation, so the honest
    // answer is "not there", not "it disappeared".
    CHECK(judge_package_binary(unobserved, unobserved, binary.string()) ==
          PackageBinaryOutcome::absent_throughout);
    CHECK(judge_package_binary(unobserved, observed, binary.string()) ==
          PackageBinaryOutcome::replaced);
}

TEST_CASE("every binary outcome has a distinct stable name") {
    const std::vector<PackageBinaryOutcome> outcomes = {
        PackageBinaryOutcome::replaced,
        PackageBinaryOutcome::unchanged,
        PackageBinaryOutcome::missing_after,
        PackageBinaryOutcome::absent_throughout,
        PackageBinaryOutcome::indeterminate,
    };
    std::vector<std::string> names;
    for (const auto outcome : outcomes) {
        std::string name = package_binary_outcome_name(outcome);
        CHECK_FALSE(name.empty());
        CHECK_FALSE(contains(names, name));
        names.push_back(std::move(name));
    }
}

} // namespace keen_pbr3
