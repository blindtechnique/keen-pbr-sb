#include "../src/util/nfqws_file_writer.hpp"

#include <doctest/doctest.h>
#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

namespace {

namespace fs = std::filesystem;

struct TemporaryDirectory {
    fs::path path;

    TemporaryDirectory() {
        char pattern[] = "/tmp/keen-pbr-nfqws-writer-XXXXXX";
        const auto created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path = created;
    }

    ~TemporaryDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }
};

std::string read_plain(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};
}

std::string read_gzip(const fs::path& path) {
    gzFile input = ::gzopen(path.c_str(), "rb");
    if (input == nullptr) throw std::runtime_error("gzopen failed");
    std::array<char, 4096> buffer{};
    std::string content;
    int count = 0;
    while ((count = ::gzread(
                input,
                buffer.data(),
                static_cast<unsigned int>(buffer.size()))) > 0) {
        content.append(buffer.data(), static_cast<std::size_t>(count));
    }
    const int close_status = ::gzclose(input);
    if (count < 0 || close_status != Z_OK) {
        throw std::runtime_error("gzip read failed");
    }
    return content;
}

mode_t file_mode(const fs::path& path) {
    struct stat metadata {};
    if (::stat(path.c_str(), &metadata) != 0) {
        throw std::runtime_error("stat failed");
    }
    return metadata.st_mode & 0777;
}

struct stat file_metadata(const fs::path& path) {
    struct stat metadata {};
    if (::stat(path.c_str(), &metadata) != 0) {
        throw std::runtime_error("stat failed");
    }
    return metadata;
}

void write_plain(const fs::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << content;
}

} // namespace

TEST_CASE("nfqws writer creates readable plain files and private parents") {
    TemporaryDirectory temporary;
    const auto destination = temporary.path / "lists" / "user.list";

    keen_pbr3::write_nfqws_file_atomically(destination, "example.com\n");

    CHECK(read_plain(destination) == "example.com\n");
    CHECK(file_mode(destination) == 0644);
    CHECK(file_mode(destination.parent_path()) == 0755);
}

TEST_CASE("nfqws writer compresses gzip files through the atomic descriptor") {
    TemporaryDirectory temporary;
    const auto destination = temporary.path / "lua" / "helper.lua.gz";
    const std::string content = "return { enabled = true }\n";

    keen_pbr3::write_nfqws_file_atomically(destination, content);

    CHECK(read_gzip(destination) == content);
    CHECK(file_mode(destination) == 0644);
}

TEST_CASE("nfqws writer preserves ownership and adds service read bits") {
    TemporaryDirectory temporary;
    const auto destination = temporary.path / "existing.list";
    write_plain(destination, "old\n");
    REQUIRE(::chmod(destination.c_str(), 0600) == 0);
    const auto before = file_metadata(destination);

    keen_pbr3::write_nfqws_file_atomically(destination, "new\n");

    const auto after = file_metadata(destination);
    CHECK(read_plain(destination) == "new\n");
    CHECK(after.st_uid == before.st_uid);
    CHECK(after.st_gid == before.st_gid);
    CHECK((after.st_mode & 0777) == 0644);
}

TEST_CASE("nfqws writer refuses a symbolic-link destination") {
    TemporaryDirectory temporary;
    const auto sentinel = temporary.path / "sentinel";
    const auto destination = temporary.path / "user.list";
    write_plain(sentinel, "unchanged\n");
    REQUIRE(::symlink(sentinel.c_str(), destination.c_str()) == 0);

    CHECK_THROWS_AS(
        keen_pbr3::write_nfqws_file_atomically(destination, "clobbered\n"),
        keen_pbr3::AtomicFileWriteError);
    CHECK(read_plain(sentinel) == "unchanged\n");
    CHECK(fs::is_symlink(destination));
}

TEST_CASE("nfqws writer create-only mode preserves an existing file") {
    TemporaryDirectory temporary;
    const auto destination = temporary.path / "user.list";
    write_plain(destination, "original.example\n");

    keen_pbr3::AtomicFileWriteOptions options;
    options.replace_existing = false;
    CHECK_THROWS_AS(
        keen_pbr3::write_nfqws_file_atomically(
            destination, "replacement.example\n", options),
        keen_pbr3::AtomicFileWriteError);
    CHECK(read_plain(destination) == "original.example\n");
}

TEST_CASE("nfqws writer create-only mode publishes a new file") {
    TemporaryDirectory temporary;
    const auto destination = temporary.path / "new.list";

    keen_pbr3::AtomicFileWriteOptions options;
    options.replace_existing = false;
    const auto result = keen_pbr3::write_nfqws_file_atomically(
        destination, "created.example\n", options);

    CHECK(result.durable);
    CHECK(read_plain(destination) == "created.example\n");
}

TEST_CASE("nfqws writer keeps the old file on a pre-commit failure") {
    TemporaryDirectory temporary;
    const auto destination = temporary.path / "user.list";
    write_plain(destination, "old\n");

    keen_pbr3::AtomicFileWriteOptions options;
    options.fault_injector = [](keen_pbr3::AtomicFileWriteStage stage) {
        if (stage == keen_pbr3::AtomicFileWriteStage::rename) {
            throw std::runtime_error("injected pre-commit failure");
        }
    };

    bool committed = true;
    options.committed_result = &committed;
    try {
        keen_pbr3::write_nfqws_file_atomically(
            destination, "new\n", options);
        FAIL("expected atomic write failure");
    } catch (const keen_pbr3::AtomicFileWriteError& error) {
        CHECK_FALSE(error.committed());
    }
    CHECK_FALSE(committed);
    CHECK(read_plain(destination) == "old\n");

    for (const auto& entry : fs::directory_iterator(temporary.path)) {
        CHECK(entry.path().filename().string().rfind(
                  ".keen-pbr-atomic.", 0) != 0);
    }
}

TEST_CASE("nfqws writer reports uncertain durability after visible commit") {
    TemporaryDirectory temporary;
    const auto destination = temporary.path / "nfqws2.conf";
    write_plain(destination, "old\n");

    keen_pbr3::AtomicFileWriteOptions options;
    options.fault_injector = [](keen_pbr3::AtomicFileWriteStage stage) {
        if (stage == keen_pbr3::AtomicFileWriteStage::directory_fsync) {
            throw std::runtime_error("injected post-commit failure");
        }
    };

    bool committed = false;
    options.committed_result = &committed;
    const auto result = keen_pbr3::write_nfqws_file_atomically(
        destination, "new\n", options);

    CHECK(committed);
    CHECK_FALSE(result.durable);
    CHECK(read_plain(destination) == "new\n");
    for (const auto& entry : fs::directory_iterator(temporary.path)) {
        CHECK(entry.path().filename().string().rfind(
                  ".keen-pbr-atomic.", 0) != 0);
    }
}

TEST_CASE("nfqws writer enforces the uncompressed file-size limit") {
    TemporaryDirectory temporary;
    const auto destination = temporary.path / "oversized.list";
    const std::string content(
        keen_pbr3::kMaxNfqwsFileSize + 1U, 'x');

    CHECK_THROWS_AS(
        keen_pbr3::write_nfqws_file_atomically(destination, content),
        std::length_error);
    CHECK_FALSE(fs::exists(destination));
}
