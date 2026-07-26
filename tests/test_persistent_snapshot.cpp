#include <doctest/doctest.h>

#include "../src/backup/persistent_snapshot.hpp"
#include "../src/config/config_writer.hpp"
#include "../src/crypto/sha256.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

class PersistentSnapshotTempDir {
public:
    PersistentSnapshotTempDir() {
        char pattern[] =
            "/tmp/keen-pbr-persistent-snapshot-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~PersistentSnapshotTempDir() {
        std::error_code error;
        fs::remove_all(path, error);
    }

    fs::path path;
};

std::string valid_config_json() {
    return R"({
        "daemon": {
            "cache_dir": "/tmp/keen-pbr-persistent-cache",
            "firewall_backend": "auto"
        },
        "api": {
            "enabled": true,
            "listen": "127.0.0.1:12121"
        },
        "outbounds": [
            {
                "type": "table",
                "tag": "wan",
                "table": 254
            }
        ],
        "dns": {
            "system_resolver": {
                "address": "127.0.0.1"
            },
            "servers": [
                {
                    "tag": "default_dns",
                    "address": "127.0.0.1"
                }
            ],
            "fallback": ["default_dns"]
        },
        "route": {
            "rules": []
        }
    })";
}

void write_binary(const fs::path& path,
                  const std::string& content) {
    fs::create_directories(path.parent_path());
    std::ofstream output(
        path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output.write(
        content.data(),
        static_cast<std::streamsize>(content.size()));
    REQUIRE(output);
}

std::string read_binary(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>(),
    };
}

mode_t mode_of(const fs::path& path) {
    struct stat metadata {};
    REQUIRE(::lstat(path.c_str(), &metadata) == 0);
    return metadata.st_mode & 0777;
}

backup::PersistentLayout temporary_layout(
    const fs::path& root) {
    backup::PersistentLayout layout;
    layout.config = root / "keen-pbr" / "config.json";
    layout.transports =
        root / "keen-pbr" / "transports.json";
    layout.nfqws = root / "nfqws2";
    layout.strategies =
        root / "keen-pbr" / "nfqws-strategies";
    return layout;
}

} // namespace

TEST_CASE(
    "persistent snapshot defaults and codec preserve the wire contract") {
    PersistentSnapshotTempDir temporary;
    const backup::PersistentLayout defaults;
    CHECK(defaults.nfqws == fs::path("/opt/etc/nfqws2"));
    CHECK(
        defaults.strategies ==
        fs::path("/opt/etc/keen-pbr/nfqws-strategies"));

    backup::FileSnapshot config;
    config.path = "/opt/etc/keen-pbr/config.json";
    config.existed = true;
    config.content = valid_config_json();
    config.mode = 0640;
    config.owner = 1000;
    config.group = 1001;

    auto document = backup::make_persistent_snapshot(
        {{"config", config}}, {"config"});
    CHECK(
        document.at("format") ==
        backup::kPersistentSnapshotFormat);
    CHECK(
        document.at("schema") ==
        backup::kPersistentSnapshotSchema);
    auto canonical = document;
    canonical.erase("integrity");
    CHECK(
        document.at("integrity").at("algorithm") ==
        "sha256");
    CHECK(
        document.at("integrity").at("digest") ==
        Sha256::hex(canonical.dump()));

    const auto parsed =
        backup::parse_persistent_snapshot(document);
    REQUIRE(parsed.entries.size() == 1U);
    CHECK(parsed.scopes.size() == 1U);
    CHECK(parsed.scopes.count("config") == 1U);
    CHECK(parsed.entries.front().target == "config");
    CHECK(parsed.entries.front().content == config.content);
    CHECK(parsed.entries.front().mode == 0640);
    CHECK(parsed.entries.front().owner == 1000);
    CHECK(parsed.entries.front().group == 1001);

    const auto path = temporary.path / "rollback.json";
    const auto payload =
        backup::save_snapshot(document, path);
    CHECK(payload == document.dump(1, '\t') + "\n");
    CHECK(mode_of(path) == 0600);
    CHECK(backup::load_snapshot(path) == document);
}

TEST_CASE(
    "persistent snapshot full scope removes later managed files") {
    PersistentSnapshotTempDir temporary;
    const auto layout = temporary_layout(temporary.path);
    write_binary(layout.config, valid_config_json());
    write_binary(layout.transports, "{}\n");
    const auto original =
        layout.nfqws / "lists" / "original.list";
    const auto later =
        layout.nfqws / "lists" / "later.list";
    write_binary(original, "example.org\n");
    REQUIRE(::chmod(original.c_str(), 0600) == 0);

    const auto full = backup::make_full_snapshot(layout);
    write_binary(later, "later.example\n");
    const auto mutations =
        backup::prepare_persistent_restore(layout, full);

    const auto tombstone = std::find_if(
        mutations.begin(),
        mutations.end(),
        [](const backup::FileMutation& mutation) {
            return mutation.target ==
                   "nfqws2/lists/later.list";
        });
    REQUIRE(tombstone != mutations.end());
    CHECK(tombstone->replacement.remove);
    CHECK(tombstone->before.existed);
    const auto original_restore = std::find_if(
        mutations.begin(),
        mutations.end(),
        [](const backup::FileMutation& mutation) {
            return mutation.target ==
                   "nfqws2/lists/original.list";
        });
    REQUIRE(original_restore != mutations.end());
    CHECK_FALSE(
        original_restore->replacement.ensure_world_readable);
    REQUIRE(
        original_restore->replacement.mode_override.has_value());
    CHECK(
        *original_restore->replacement.mode_override == 0600);

    backup::FileReplacement replacement;
    replacement.path = layout.transports;
    replacement.content = "{\"changed\":true}\n";
    replacement.max_content_bytes =
        backup::kMaxSnapshotBytes;
    const auto operation_mutations =
        backup::snapshot_replacements(
            layout, {std::move(replacement)});
    const auto operation =
        backup::make_operation_snapshot(
            operation_mutations);
    CHECK(operation.at("scopes").empty());
    REQUIRE(operation.at("entries").size() == 1U);
    CHECK(
        operation.at("entries").front().at("target") ==
        "transports");
}

TEST_CASE(
    "persistent snapshot never follows source symlinks") {
    PersistentSnapshotTempDir temporary;
    const auto layout = temporary_layout(temporary.path);
    const auto outside =
        temporary.path / "outside.json";
    write_binary(outside, valid_config_json());
    fs::create_directories(
        layout.config.parent_path());
    REQUIRE(
        ::symlink(
            outside.c_str(),
            layout.config.c_str()) == 0);

    try {
        (void)backup::capture_file(
            layout.config,
            std::nullopt,
            backup::kMaxSnapshotBytes);
        FAIL("symbolic link was accepted as a snapshot source");
    } catch (const backup::PersistentSnapshotError& error) {
        CHECK(
            error.kind() ==
            backup::PersistentSnapshotErrorKind::
                unsafe_local_state);
    }

    const auto real_parent =
        temporary.path / "real-parent";
    const auto linked_parent =
        temporary.path / "linked-parent";
    write_binary(
        real_parent / "config.json",
        valid_config_json());
    REQUIRE(
        ::symlink(
            real_parent.c_str(),
            linked_parent.c_str()) == 0);
    try {
        (void)backup::capture_file(
            linked_parent / "config.json",
            std::nullopt,
            backup::kMaxSnapshotBytes);
        FAIL("symbolic-link parent was accepted");
    } catch (const backup::PersistentSnapshotError& error) {
        CHECK(
            error.kind() ==
            backup::PersistentSnapshotErrorKind::
                unsafe_local_state);
    }
}

TEST_CASE(
    "persistent snapshot rejects a pathname swap after open") {
    PersistentSnapshotTempDir temporary;
    const auto layout = temporary_layout(temporary.path);
    write_binary(layout.config, "original\n");
    REQUIRE(::chmod(layout.config.c_str(), 0600) == 0);
    const auto displaced =
        layout.config.parent_path() / "displaced.json";

    backup::FileCaptureHooks hooks;
    hooks.after_open = [&](const fs::path& path) {
        REQUIRE(path == layout.config);
        REQUIRE(
            ::rename(
                path.c_str(),
                displaced.c_str()) == 0);
        write_binary(path, "replacement\n");
        REQUIRE(::chmod(path.c_str(), 0644) == 0);
    };

    try {
        (void)backup::capture_file(
            layout.config,
            std::nullopt,
            backup::kMaxSnapshotBytes,
            nullptr,
            &hooks);
        FAIL("pathname swap was not detected");
    } catch (const backup::PersistentSnapshotError& error) {
        CHECK(
            error.kind() ==
            backup::PersistentSnapshotErrorKind::
                unsafe_local_state);
    }
    CHECK(read_binary(displaced) == "original\n");
    CHECK(read_binary(layout.config) == "replacement\n");
}

TEST_CASE(
    "persistent snapshot rejects mutation of the opened inode") {
    PersistentSnapshotTempDir temporary;
    const auto layout = temporary_layout(temporary.path);
    write_binary(layout.config, "old\n");

    backup::FileCaptureHooks hooks;
    hooks.after_open = [&](const fs::path& path) {
        std::ofstream output(
            path, std::ios::binary | std::ios::app);
        REQUIRE(output);
        output << "changed\n";
        REQUIRE(output);
    };

    try {
        (void)backup::capture_file(
            layout.config,
            std::nullopt,
            backup::kMaxSnapshotBytes,
            nullptr,
            &hooks);
        FAIL("in-place source mutation was not detected");
    } catch (const backup::PersistentSnapshotError& error) {
        CHECK(
            error.kind() ==
            backup::PersistentSnapshotErrorKind::
                unsafe_local_state);
    }
}

TEST_CASE(
    "persistent snapshot transaction rolls back a committed rename") {
    PersistentSnapshotTempDir temporary;
    const auto layout = temporary_layout(temporary.path);
    write_binary(layout.config, "old\n");
    REQUIRE(::chmod(layout.config.c_str(), 0600) == 0);

    backup::FileReplacement replacement;
    replacement.path = layout.config;
    replacement.content = "new\n";
    replacement.mode_override = 0644;
    replacement.max_content_bytes =
        backup::kMaxSnapshotBytes;
    const auto mutations =
        backup::snapshot_replacements(
            layout, {std::move(replacement)});

    bool injected = false;
    backup::FileApplyHooks hooks;
    hooks.atomic_write_fault =
        [&](const fs::path& path,
            AtomicFileWriteStage stage) {
            if (!injected && path == layout.config &&
                stage ==
                    AtomicFileWriteStage::directory_fsync) {
                injected = true;
                throw std::runtime_error(
                    "injected directory fsync failure");
            }
        };
    backup::FileMutationTransaction transaction(
        mutations, std::move(hooks));

    CHECK_THROWS(transaction.apply());
    CHECK(transaction.has_committed_changes());
    CHECK(read_binary(layout.config) == "new\n");
    CHECK(transaction.rollback().empty());
    CHECK_FALSE(transaction.has_committed_changes());
    CHECK(read_binary(layout.config) == "old\n");
    CHECK(mode_of(layout.config) == 0600);
}

TEST_CASE(
    "persistent snapshot requires explicit file size policy") {
    PersistentSnapshotTempDir temporary;
    const auto layout = temporary_layout(temporary.path);
    write_binary(layout.config, valid_config_json());

    backup::FileReplacement replacement;
    replacement.path = layout.config;
    replacement.content = valid_config_json();
    CHECK_THROWS_WITH_AS(
        backup::snapshot_replacements(
            layout, {std::move(replacement)}),
        "file replacement size policy is missing",
        backup::PersistentSnapshotError);
}

} // namespace keen_pbr3
