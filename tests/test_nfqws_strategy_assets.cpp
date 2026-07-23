#include "../src/util/nfqws_strategy_assets.hpp"

#include <doctest/doctest.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

struct TemporaryDirectory {
    fs::path path;

    TemporaryDirectory() {
        char pattern[] = "/tmp/keen-pbr-nfqws-assets-XXXXXX";
        const auto created = ::mkdtemp(pattern);
        if (!created) throw std::runtime_error("mkdtemp failed");
        path = created;
    }

    ~TemporaryDirectory() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

void write_file(const fs::path& path, const std::string& content) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << content;
}

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

} // namespace

TEST_CASE("nfqws strategy assets install missing files and preserve existing files") {
    TemporaryDirectory temporary;
    const auto manifest = temporary.path / "required-blobs.txt";
    const auto source = temporary.path / "source";
    const auto destination = temporary.path / "destination";
    write_file(manifest, "# strategy dependencies\nnew.bin\nexisting.bin\n");
    write_file(source / "new.bin", "new-data");
    write_file(source / "existing.bin", "package-data");
    write_file(destination / "existing.bin", "user-data");

    const auto first = keen_pbr3::sync_nfqws_strategy_assets(
        manifest, source, destination);
    CHECK(first.installed == std::vector<std::string>{"new.bin"});
    CHECK(first.preserved == std::vector<std::string>{"existing.bin"});
    CHECK(read_file(destination / "new.bin") == "new-data");
    CHECK(read_file(destination / "existing.bin") == "user-data");

    const auto second = keen_pbr3::sync_nfqws_strategy_assets(
        manifest, source, destination);
    CHECK(second.installed.empty());
    CHECK(second.preserved ==
          std::vector<std::string>{"new.bin", "existing.bin"});
}

TEST_CASE("nfqws strategy asset manifests reject traversal") {
    TemporaryDirectory temporary;
    const auto manifest = temporary.path / "required-blobs.txt";
    write_file(manifest, "../escape.bin\n");

    CHECK_THROWS(keen_pbr3::sync_nfqws_strategy_assets(
        manifest, temporary.path / "source", temporary.path / "destination"));
}
