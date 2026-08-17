#include <doctest/doctest.h>

#include "../src/config/config_writer.hpp"

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {
namespace {

class TempDir {
public:
    TempDir() {
        char pattern[] = "/tmp/keen-pbr-config-writer-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }
    ~TempDir() { std::filesystem::remove_all(path); }
    std::filesystem::path path;
};

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

mode_t file_mode(const std::filesystem::path& path) {
    struct stat st {};
    REQUIRE(::stat(path.c_str(), &st) == 0);
    return st.st_mode & 07777;
}

} // namespace

TEST_CASE("atomic config writer preserves existing mode") {
    TempDir dir;
    const auto config = dir.path / "config.json";
    { std::ofstream output(config); output << "old"; }
    REQUIRE(::chmod(config.c_str(), 0640) == 0);

    write_config_atomically(config.string(), "new");

    CHECK(read_file(config) == "new");
    CHECK(file_mode(config) == 0640);
}

TEST_CASE("atomic config writer creates private files") {
    TempDir dir;
    const auto config = dir.path / "config.json";
    write_config_atomically(config.string(), "new");
    CHECK(file_mode(config) == 0600);
}

TEST_CASE("atomic config writer refuses a symlink and leaves its target untouched") {
    TempDir dir;
    const auto sentinel = dir.path / "sentinel";
    const auto config = dir.path / "config.json";
    { std::ofstream output(sentinel); output << "unchanged"; }
    REQUIRE(::symlink(sentinel.c_str(), config.c_str()) == 0);

    CHECK_THROWS(write_config_atomically(config.string(), "clobbered"));
    CHECK(read_file(sentinel) == "unchanged");
}

TEST_CASE("generic atomic writer creates private directories and files") {
    TempDir dir;
    const auto backup_directory = dir.path / "private" / "rollback";
    const auto backup = backup_directory / "backup.json";
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.created_directory_mode = 0700;
    options.default_file_mode = 0600;

    write_file_atomically(backup.string(), "private", options);

    CHECK(read_file(backup) == "private");
    CHECK(file_mode(dir.path / "private") == 0700);
    CHECK(file_mode(backup_directory) == 0700);
    CHECK(file_mode(backup) == 0600);
}

TEST_CASE("generic atomic writer preserves an existing directory mode") {
    TempDir dir;
    const auto existing_directory = dir.path / "shared";
    REQUIRE(std::filesystem::create_directory(existing_directory));
    REQUIRE(::chmod(existing_directory.c_str(), 0750) == 0);

    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.created_directory_mode = 0700;
    options.default_file_mode = 0600;
    write_file_atomically(
        (existing_directory / "backup.json").string(), "private", options);

    CHECK(file_mode(existing_directory) == 0750);
}

#ifdef KEEN_PBR3_TESTING
TEST_CASE(
    "parent directory durability failures are repaired on the next write") {
    const std::vector<AtomicParentDirectoryStage> stages{
        AtomicParentDirectoryStage::mode,
        AtomicParentDirectoryStage::directory_fsync,
        AtomicParentDirectoryStage::parent_fsync,
    };
    for (std::size_t index = 0; index < stages.size(); ++index) {
        CAPTURE(index);
        TempDir dir;
        const auto target =
            dir.path / "new-parent" / "nested" / "config.json";
        bool injected = false;
        AtomicFileWriteOptions options;
        options.create_parent_directories = true;
        options.created_directory_mode = 0700;
        options.parent_directory_fault_injector =
            [stage_to_fail = stages[index], &injected](
                AtomicParentDirectoryStage stage) {
                if (!injected && stage == stage_to_fail) {
                    injected = true;
                    throw std::system_error(
                        EIO,
                        std::generic_category(),
                        "injected parent directory durability failure");
                }
            };

        CHECK_THROWS_AS(
            write_file_atomically(target.string(), "first", options),
            std::system_error);
        CHECK(injected);
        CHECK_FALSE(std::filesystem::exists(target));

        // mkdir already made at least one component visible. The retry must
        // repair its mode and parent-entry durability before publishing the
        // file instead of treating the existing path as proven durable.
        write_file_atomically(target.string(), "second", options);
        CHECK(read_file(target) == "second");
        CHECK(file_mode(dir.path / "new-parent") == 0700);
        CHECK(file_mode(dir.path / "new-parent" / "nested") == 0700);
    }
}

TEST_CASE(
    "existing parent directories do not trigger durability fsync stages") {
    TempDir dir;
    const auto existing = dir.path / "existing" / "nested";
    REQUIRE(std::filesystem::create_directories(existing));
    std::size_t parent_stage_calls = 0;
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.parent_directory_fault_injector =
        [&parent_stage_calls](AtomicParentDirectoryStage) {
            ++parent_stage_calls;
        };

    write_file_atomically(
        (existing / "config.json").string(), "content", options);

    CHECK(parent_stage_calls == 0U);
}
#endif

TEST_CASE("generic atomic writer preserves metadata and adds requested mode bits") {
    TempDir dir;
    const auto target = dir.path / "nfqws.conf";
    { std::ofstream output(target); output << "old"; }
    REQUIRE(::chmod(target.c_str(), 0600) == 0);
    struct stat before {};
    REQUIRE(::stat(target.c_str(), &before) == 0);

    AtomicFileWriteOptions options;
    options.default_file_mode = 0644;
    options.preserved_file_mode_mask = 0777;
    options.additional_file_mode_bits = 0444;
    write_file_atomically(target.string(), "new", options);

    struct stat after {};
    REQUIRE(::stat(target.c_str(), &after) == 0);
    CHECK(read_file(target) == "new");
    CHECK((after.st_mode & 0777) == 0644);
    CHECK(after.st_uid == before.st_uid);
    CHECK(after.st_gid == before.st_gid);
}

TEST_CASE("streaming atomic writer discards a partial ENOSPC write") {
    TempDir dir;
    const auto target = dir.path / "config.json";
    { std::ofstream output(target); output << "last-known-good"; }

    try {
        write_file_atomically_with(
            target.string(),
            [](int descriptor) {
                const char partial[] = "partial";
                REQUIRE(::write(descriptor, partial, sizeof(partial) - 1) ==
                        static_cast<ssize_t>(sizeof(partial) - 1));
                throw std::system_error(
                    ENOSPC,
                    std::generic_category(),
                    "injected out-of-space failure");
            });
        FAIL("out-of-space fault must abort the atomic replacement");
    } catch (const AtomicFileWriteError& error) {
        CHECK_FALSE(error.committed());
        CHECK(std::string(error.what()).find("out-of-space") !=
              std::string::npos);
    }

    CHECK(read_file(target) == "last-known-good");
    std::size_t entries = 0;
    for (const auto& ignored : std::filesystem::directory_iterator(dir.path)) {
        (void)ignored;
        ++entries;
    }
    CHECK(entries == 1U);
}

TEST_CASE("generic atomic writer refuses a symlink parent") {
    TempDir dir;
    const auto real_directory = dir.path / "real";
    const auto linked_directory = dir.path / "linked";
    REQUIRE(std::filesystem::create_directory(real_directory));
    REQUIRE(::symlink(real_directory.c_str(), linked_directory.c_str()) == 0);

    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    CHECK_THROWS(write_file_atomically(
        (linked_directory / "backup.json").string(), "blocked", options));
    CHECK_FALSE(std::filesystem::exists(real_directory / "backup.json"));
}

TEST_CASE("generic atomic writer rejects raw parent traversal") {
    TempDir dir;
    const auto target =
        dir.path / "allowed" / ".." / "escaped.json";
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;

    CHECK_THROWS(write_file_atomically(target.string(), "blocked", options));
    CHECK_FALSE(std::filesystem::exists(dir.path / "escaped.json"));
    CHECK_FALSE(std::filesystem::exists(dir.path / "allowed"));
}

TEST_CASE("generic atomic writer create-only mode never replaces a file") {
    TempDir dir;
    const auto target = dir.path / "existing.json";
    { std::ofstream output(target); output << "original"; }

    AtomicFileWriteOptions options;
    options.replace_existing = false;
    CHECK_THROWS_AS(
        write_file_atomically(target.string(), "replacement", options),
        AtomicFileWriteError);
    CHECK(read_file(target) == "original");
}

#ifdef KEEN_PBR3_TESTING
TEST_CASE("generic atomic writer create-only commit closes the stat race") {
    TempDir dir;
    const auto target = dir.path / "raced.json";

    AtomicFileWriteOptions options;
    options.replace_existing = false;
    options.fault_injector = [&target](AtomicFileWriteStage stage) {
        if (stage != AtomicFileWriteStage::rename) return;
        std::ofstream competing(target);
        competing << "competing";
    };

    CHECK_THROWS_AS(
        write_file_atomically(target.string(), "ours", options),
        AtomicFileWriteError);
    CHECK(read_file(target) == "competing");
}
#endif

TEST_CASE("generic atomic writer ignores the legacy predictable temp path") {
    TempDir dir;
    const auto target = dir.path / "backup.json";
    const auto sentinel = dir.path / "sentinel";
    const auto legacy_temporary =
        std::filesystem::path(target.string() + ".keen-pbr-sb.tmp");
    { std::ofstream output(sentinel); output << "unchanged"; }
    REQUIRE(::symlink(sentinel.c_str(), legacy_temporary.c_str()) == 0);

    write_file_atomically(target.string(), "new");

    CHECK(read_file(target) == "new");
    CHECK(read_file(sentinel) == "unchanged");
    CHECK(std::filesystem::is_symlink(legacy_temporary));
}

#ifdef KEEN_PBR3_TESTING
TEST_CASE("atomic writer fault stages report whether rename committed") {
    const std::vector<AtomicFileWriteStage> stages{
        AtomicFileWriteStage::write,
        AtomicFileWriteStage::file_fsync,
        AtomicFileWriteStage::rename,
        AtomicFileWriteStage::directory_fsync,
    };
    for (std::size_t index = 0; index < stages.size(); ++index) {
        CAPTURE(index);
        TempDir dir;
        const auto target = dir.path / "config.json";
        { std::ofstream output(target); output << "old"; }
        bool committed = true;
        AtomicFileWriteOptions options;
        options.committed_result = &committed;
        options.fault_injector =
            [fault_stage = stages[index]](
                AtomicFileWriteStage stage) {
                if (stage == fault_stage) {
                    throw std::system_error(
                        EIO,
                        std::generic_category(),
                        "injected atomic write fault");
                }
            };

        const bool post_rename =
            stages[index] == AtomicFileWriteStage::directory_fsync;
        try {
            write_file_atomically(target.string(), "new", options);
            FAIL("fault injection must make the atomic write fail");
        } catch (const AtomicFileWriteError& error) {
            CHECK(error.committed() == post_rename);
            CHECK(
                std::string(error.what()).find(
                    "injected atomic write fault") !=
                std::string::npos);
        }
        CHECK(committed == post_rename);
        CHECK(read_file(target) == (post_rename ? "new" : "old"));
        std::size_t entries = 0;
        for (const auto& ignored :
             std::filesystem::directory_iterator(dir.path)) {
            (void)ignored;
            ++entries;
        }
        CHECK(entries == 1U);
    }
}
#endif

} // namespace keen_pbr3
