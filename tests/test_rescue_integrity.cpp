#include <doctest/doctest.h>

#include "../src/update/rescue_integrity.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;
using keen_pbr3::rescue_integrity::kManagedFiles;
using keen_pbr3::rescue_integrity::sha256_file;
using keen_pbr3::rescue_integrity::verified_ipk_file;
using keen_pbr3::rescue_integrity::verified_snapshot;

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() /
             "keen-pbr-rescue-integrity-XXXXXX")
                .string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        if (created == nullptr)
            throw std::system_error(errno,
                                    std::generic_category(),
                                    "mkdtemp");
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
                mode_t mode = 0600) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << content;
    output.close();
    REQUIRE(output);
    REQUIRE(::chmod(path.c_str(), mode) == 0);
}

void build_snapshot(const fs::path& path) {
    std::error_code error;
    fs::remove_all(path, error);
    REQUIRE_FALSE(error);
    fs::create_directories(path);
    write_file(path / "config.json", "{}\n", 0600);
    const auto config_hash = sha256_file(path / "config.json");
    REQUIRE(config_hash.has_value());

    std::string manifest = "keen-pbr-snapshot-v2\n";
    for (const auto name : kManagedFiles) {
        if (name == "config.json") {
            manifest += "present config.json 600 " + *config_hash + "\n";
        } else {
            manifest += "absent " + std::string(name) + " - -\n";
        }
    }
    write_file(path / ".snapshot-manifest", manifest);
    const auto manifest_hash = sha256_file(path / ".snapshot-manifest");
    REQUIRE(manifest_hash.has_value());
    write_file(path / ".snapshot-ready", *manifest_hash + "\n");
}

} // namespace

TEST_CASE("rescue IPK sidecar detects at-rest corruption") {
    TempDirectory directory;
    const auto archive = directory.path / "current.ipk";
    write_file(archive, "package-a\n");
    const auto digest = sha256_file(archive);
    REQUIRE(digest.has_value());
    write_file(fs::path(archive.string() + ".sha256"), *digest + "\n");
    CHECK(verified_ipk_file(archive));

    write_file(archive, "tampered\n");
    CHECK_FALSE(verified_ipk_file(archive));
}

TEST_CASE("rescue snapshot validator rejects content mode and manifest corruption") {
    TempDirectory directory;
    const auto snapshot = directory.path / "snapshot";
    build_snapshot(snapshot);
    CHECK(verified_snapshot(snapshot));

    write_file(snapshot / "config.json", "{\"changed\":true}\n", 0600);
    CHECK_FALSE(verified_snapshot(snapshot));

    build_snapshot(snapshot);
    REQUIRE(::chmod((snapshot / "config.json").c_str(), 0644) == 0);
    CHECK_FALSE(verified_snapshot(snapshot));

    build_snapshot(snapshot);
    {
        std::ofstream manifest(snapshot / ".snapshot-manifest",
                               std::ios::app);
        manifest << "absent config.json - -\n";
    }
    CHECK_FALSE(verified_snapshot(snapshot));
}

TEST_CASE("rescue snapshot validator rejects unmanifested entries") {
    TempDirectory directory;
    const auto snapshot = directory.path / "snapshot";
    build_snapshot(snapshot);
    write_file(snapshot / "unexpected", "not managed\n");
    CHECK_FALSE(verified_snapshot(snapshot));
}
