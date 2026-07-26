#include <doctest/doctest.h>

#include "../src/backup/restore_journal.hpp"
#include "../src/crypto/sha256.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <nlohmann/json.hpp>
#include <signal.h>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr const char* kTransaction = "00112233445566778899aabbccddeeff";

class JournalTempDir {
public:
    JournalTempDir() {
        char pattern[] = "/tmp/keen-pbr-restore-journal-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }
    ~JournalTempDir() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

std::string read_binary(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>(),
    };
}

void write_binary(const std::filesystem::path& path,
                  const std::string& body) {
    std::ofstream output(
        path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output.write(body.data(), static_cast<std::streamsize>(body.size()));
    REQUIRE(output);
}

mode_t mode_of(const std::filesystem::path& path) {
    struct stat metadata {};
    REQUIRE(::lstat(path.c_str(), &metadata) == 0);
    return metadata.st_mode & 07777;
}

void reseal(nlohmann::json& marker) {
    marker.erase("integrity_sha256");
    marker["integrity_sha256"] = Sha256::hex(marker.dump());
}

std::vector<RestoreJournalEffect> all_effects() {
    return {
        RestoreJournalEffect::files,
        RestoreJournalEffect::transport_manager,
        RestoreJournalEffect::core,
        RestoreJournalEffect::nfqws,
    };
}

void advance_to_final(RestoreJournal& journal) {
    CHECK(
        journal
            .advance_phase(
                kTransaction,
                RestoreJournalPhase::files_committed)
            .phase == RestoreJournalPhase::files_committed);
    CHECK(
        journal
            .advance_phase(
                kTransaction,
                RestoreJournalPhase::transports_ready)
            .phase == RestoreJournalPhase::transports_ready);
    CHECK(
        journal
            .advance_phase(
                kTransaction,
                RestoreJournalPhase::core_applied)
            .phase == RestoreJournalPhase::core_applied);
    CHECK(
        journal
            .advance_phase(
                kTransaction,
                RestoreJournalPhase::nfqws_ready)
            .phase == RestoreJournalPhase::nfqws_ready);
}

void commit_files_only(RestoreJournal& journal,
                       const std::string& transaction_id,
                       const std::string& payload = "rollback") {
    journal.begin(
        transaction_id,
        payload,
        {RestoreJournalEffect::files});
    journal.advance_phase(
        transaction_id, RestoreJournalPhase::files_committed);
    journal.commit(transaction_id);
}

void create_sparse_private_file(const std::filesystem::path& path,
                                std::uint64_t size) {
    const int fd =
        ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    REQUIRE(fd >= 0);
    REQUIRE(::fchmod(fd, 0600) == 0);
    REQUIRE(
        ::ftruncate(fd, static_cast<off_t>(size)) == 0);
    REQUIRE(::close(fd) == 0);
}

} // namespace

TEST_CASE("restore journal persists exact private rollback state") {
    JournalTempDir temporary;
    const auto state = temporary.path / "private" / "restore";
    RestoreJournal journal(state);
    const std::string payload{"backup\0bytes\n", 13};

    const auto started =
        journal.begin(kTransaction, payload, all_effects());

    CHECK(started.transaction_id == kTransaction);
    CHECK(started.phase == RestoreJournalPhase::prepared);
    CHECK(started.effects == all_effects());
    CHECK(started.snapshot_size == payload.size());
    CHECK(started.snapshot_sha256 == Sha256::hex(payload));
    CHECK(journal.read_active() == started);
    CHECK(journal.read_rollback_payload(started) == payload);
    CHECK(
        read_binary(state / (std::string(kTransaction) + ".rollback")) ==
        payload);
    CHECK(mode_of(state) == 0700);
    CHECK(mode_of(state / "active.json") == 0600);
    CHECK(
        mode_of(state / (std::string(kTransaction) + ".rollback")) ==
        0600);

    const auto marker =
        nlohmann::json::parse(read_binary(state / "active.json"));
    CHECK(marker.at("schema_version") == 1);
    CHECK(marker.at("transaction_id") == kTransaction);
    CHECK(marker.at("phase") == "prepared");
    CHECK(marker.at("snapshot").at("size") == payload.size());
    CHECK(
        marker.at("snapshot").at("sha256") == Sha256::hex(payload));
    auto without_integrity = marker;
    without_integrity.erase("integrity_sha256");
    CHECK(
        marker.at("integrity_sha256") ==
        Sha256::hex(without_integrity.dump()));
}

TEST_CASE("restore journal begin is idempotent only for exact data") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    const auto first =
        journal.begin(kTransaction, "exact", all_effects());

    CHECK(journal.begin(kTransaction, "exact", all_effects()) == first);
    CHECK_THROWS_WITH_AS(
        journal.begin(
            "ffeeddccbbaa99887766554433221100",
            "other",
            all_effects()),
        "Another restore transaction is already active",
        std::runtime_error);
    CHECK_FALSE(journal.unknown_present());

    advance_to_final(journal);
    journal.commit(kTransaction);
    CHECK_FALSE(journal.read_active().has_value());
    CHECK(std::filesystem::exists(
        state / (std::string(kTransaction) + ".rollback")));

    CHECK_THROWS(journal.begin(kTransaction, "different", all_effects()));
    CHECK(journal.unknown_present());
}

TEST_CASE("restore journal phases are ordered and idempotent") {
    JournalTempDir temporary;
    RestoreJournal journal(temporary.path / "restore");
    journal.begin(kTransaction, "rollback", all_effects());

    CHECK(
        journal
            .advance_phase(kTransaction, RestoreJournalPhase::prepared)
            .phase == RestoreJournalPhase::prepared);
    CHECK_THROWS(journal.advance_phase(
        kTransaction, RestoreJournalPhase::transports_ready));
    CHECK_THROWS(journal.advance_phase(
        "ffeeddccbbaa99887766554433221100",
        RestoreJournalPhase::files_committed));
    CHECK_THROWS(journal.commit(kTransaction));
    CHECK_FALSE(journal.unknown_present());

    advance_to_final(journal);
    CHECK(
        journal
            .advance_phase(kTransaction, RestoreJournalPhase::nfqws_ready)
            .phase == RestoreJournalPhase::nfqws_ready);
    CHECK_THROWS(journal.advance_phase(
        kTransaction, RestoreJournalPhase::transports_ready));

    journal.commit(kTransaction);
    journal.commit(kTransaction);
    CHECK_FALSE(journal.read_active().has_value());
}

TEST_CASE(
    "restore journal commit retry accepts only the committed transaction") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    {
        RestoreJournal journal(state);
        journal.begin(
            kTransaction, "rollback", {RestoreJournalEffect::files});
        journal.advance_phase(
            kTransaction, RestoreJournalPhase::files_committed);
        journal.commit(kTransaction);
        CHECK(mode_of(
                  state /
                  (std::string(kTransaction) + ".committed")) ==
              0600);
    }

    RestoreJournal reopened(state);
    CHECK_NOTHROW(reopened.commit(kTransaction));
    CHECK_THROWS_WITH_AS(
        reopened.commit("ffeeddccbbaa99887766554433221100"),
        "No matching committed restore transaction exists",
        std::runtime_error);
    CHECK_THROWS_WITH_AS(
        reopened.begin(
            kTransaction,
            "rollback",
            {RestoreJournalEffect::files}),
        "Restore transaction is already committed",
        std::runtime_error);
    CHECK_FALSE(reopened.unknown_present());

    REQUIRE(std::filesystem::remove(
        state / (std::string(kTransaction) + ".rollback")));
    RestoreJournal after_retention(state);
    CHECK_NOTHROW(after_retention.commit(kTransaction));
    CHECK_THROWS_WITH_AS(
        after_retention.begin(
            kTransaction,
            "rollback",
            {RestoreJournalEffect::files}),
        "Restore transaction is already committed",
        std::runtime_error);
    CHECK_FALSE(after_retention.unknown_present());
}

TEST_CASE("restore journal does not mistake an orphan payload for a commit") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    const auto orphan =
        state / (std::string(kTransaction) + ".rollback");
    write_binary(orphan, "rollback");
    REQUIRE(::chmod(orphan.c_str(), 0600) == 0);
    REQUIRE(std::filesystem::exists(
        state / (std::string(kTransaction) + ".rollback")));
    REQUIRE_FALSE(std::filesystem::exists(state / "active.json"));

    RestoreJournal reopened(state);
    CHECK_THROWS_WITH_AS(
        reopened.commit(kTransaction),
        "No matching committed restore transaction exists",
        std::runtime_error);
    CHECK_FALSE(reopened.unknown_present());
}

TEST_CASE("restore journal rejects a corrupt committed receipt fail closed") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    commit_files_only(journal, kTransaction);
    write_binary(
        state / (std::string(kTransaction) + ".committed"),
        "{}\n");

    CHECK_THROWS(journal.commit(kTransaction));
    CHECK(journal.unknown_present());
}

TEST_CASE("restore journal core phase is terminal without nfqws") {
    JournalTempDir temporary;
    RestoreJournal journal(temporary.path / "restore");
    journal.begin(
        kTransaction,
        "rollback",
        {
            RestoreJournalEffect::files,
            RestoreJournalEffect::transport_manager,
            RestoreJournalEffect::core,
        });
    journal.advance_phase(
        kTransaction, RestoreJournalPhase::files_committed);
    journal.advance_phase(
        kTransaction, RestoreJournalPhase::transports_ready);
    journal.advance_phase(
        kTransaction, RestoreJournalPhase::core_applied);

    CHECK_THROWS(journal.advance_phase(
        kTransaction, RestoreJournalPhase::nfqws_ready));
    journal.commit(kTransaction);
    CHECK_FALSE(journal.read_active().has_value());
}

TEST_CASE("restore journal phase matrix follows declared effects") {
    SUBCASE("files only") {
        JournalTempDir temporary;
        RestoreJournal journal(temporary.path / "restore");
        journal.begin(
            kTransaction,
            "rollback",
            {RestoreJournalEffect::files});

        CHECK_THROWS(journal.advance_phase(
            kTransaction, RestoreJournalPhase::transports_ready));
        CHECK_THROWS(journal.advance_phase(
            kTransaction, RestoreJournalPhase::core_applied));
        CHECK(
            journal
                .advance_phase(
                    kTransaction,
                    RestoreJournalPhase::files_committed)
                .phase == RestoreJournalPhase::files_committed);
        CHECK_THROWS(journal.advance_phase(
            kTransaction, RestoreJournalPhase::core_applied));
        CHECK_NOTHROW(journal.commit(kTransaction));
    }

    SUBCASE("transport after files") {
        JournalTempDir temporary;
        RestoreJournal journal(temporary.path / "restore");
        journal.begin(
            kTransaction,
            "rollback",
            {
                RestoreJournalEffect::files,
                RestoreJournalEffect::transport_manager,
            });

        journal.advance_phase(
            kTransaction, RestoreJournalPhase::files_committed);
        CHECK_THROWS(journal.advance_phase(
            kTransaction, RestoreJournalPhase::core_applied));
        CHECK(
            journal
                .advance_phase(
                    kTransaction,
                    RestoreJournalPhase::transports_ready)
                .phase == RestoreJournalPhase::transports_ready);
        CHECK_NOTHROW(journal.commit(kTransaction));
    }

    SUBCASE("core does not require a fake transport milestone") {
        JournalTempDir temporary;
        RestoreJournal journal(temporary.path / "restore");
        journal.begin(
            kTransaction,
            "rollback",
            {
                RestoreJournalEffect::files,
                RestoreJournalEffect::core,
            });

        journal.advance_phase(
            kTransaction, RestoreJournalPhase::files_committed);
        CHECK_THROWS(journal.advance_phase(
            kTransaction, RestoreJournalPhase::transports_ready));
        CHECK(
            journal
                .advance_phase(
                    kTransaction,
                    RestoreJournalPhase::core_applied)
                .phase == RestoreJournalPhase::core_applied);
        CHECK_NOTHROW(journal.commit(kTransaction));
    }

    SUBCASE("nfqws follows files when it is the only later effect") {
        JournalTempDir temporary;
        RestoreJournal journal(temporary.path / "restore");
        journal.begin(
            kTransaction,
            "rollback",
            {
                RestoreJournalEffect::files,
                RestoreJournalEffect::nfqws,
            });

        journal.advance_phase(
            kTransaction, RestoreJournalPhase::files_committed);
        CHECK_THROWS(journal.advance_phase(
            kTransaction, RestoreJournalPhase::core_applied));
        CHECK(
            journal
                .advance_phase(
                    kTransaction,
                    RestoreJournalPhase::nfqws_ready)
                .phase == RestoreJournalPhase::nfqws_ready);
        CHECK_NOTHROW(journal.commit(kTransaction));
    }

    SUBCASE("nfqws follows the last declared transport effect") {
        JournalTempDir temporary;
        RestoreJournal journal(temporary.path / "restore");
        journal.begin(
            kTransaction,
            "rollback",
            {
                RestoreJournalEffect::files,
                RestoreJournalEffect::transport_manager,
                RestoreJournalEffect::nfqws,
            });

        journal.advance_phase(
            kTransaction, RestoreJournalPhase::files_committed);
        journal.advance_phase(
            kTransaction, RestoreJournalPhase::transports_ready);
        CHECK_THROWS(journal.advance_phase(
            kTransaction, RestoreJournalPhase::core_applied));
        CHECK(
            journal
                .advance_phase(
                    kTransaction,
                    RestoreJournalPhase::nfqws_ready)
                .phase == RestoreJournalPhase::nfqws_ready);
        CHECK_NOTHROW(journal.commit(kTransaction));
    }

    SUBCASE("nfqws follows core without transport") {
        JournalTempDir temporary;
        RestoreJournal journal(temporary.path / "restore");
        journal.begin(
            kTransaction,
            "rollback",
            {
                RestoreJournalEffect::files,
                RestoreJournalEffect::core,
                RestoreJournalEffect::nfqws,
            });

        journal.advance_phase(
            kTransaction, RestoreJournalPhase::files_committed);
        journal.advance_phase(
            kTransaction, RestoreJournalPhase::core_applied);
        CHECK(
            journal
                .advance_phase(
                    kTransaction,
                    RestoreJournalPhase::nfqws_ready)
                .phase == RestoreJournalPhase::nfqws_ready);
        CHECK_NOTHROW(journal.commit(kTransaction));
    }
}

TEST_CASE("restore journal completes verified rollback without forward phases") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    const std::string payload{"exact rollback\0payload", 22};
    const auto started =
        journal.begin(kTransaction, payload, all_effects());

    REQUIRE(started.phase == RestoreJournalPhase::prepared);
    CHECK(journal.read_rollback_payload(started) == payload);
    CHECK_THROWS(journal.commit(kTransaction));

    journal.complete_rollback(kTransaction);
    CHECK_FALSE(journal.read_active().has_value());
    CHECK(
        read_binary(
            state / (std::string(kTransaction) + ".rollback")) ==
        payload);

    // Repeating completion after the durable marker removal is idempotent.
    CHECK_NOTHROW(journal.complete_rollback(kTransaction));
    CHECK_FALSE(journal.unknown_present());
}

TEST_CASE("restore journal rollback completion requires active transaction") {
    JournalTempDir temporary;
    RestoreJournal journal(temporary.path / "restore");
    const auto started =
        journal.begin(kTransaction, "rollback", all_effects());

    CHECK_THROWS_WITH_AS(
        journal.complete_rollback(
            "ffeeddccbbaa99887766554433221100"),
        "Restore transaction id does not match active journal",
        std::runtime_error);
    CHECK(journal.read_active() == started);
    CHECK_FALSE(journal.unknown_present());
}

TEST_CASE("restore journal rollback completion verifies payload integrity") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    journal.begin(kTransaction, "rollback", all_effects());
    write_binary(
        state / (std::string(kTransaction) + ".rollback"),
        "tampered");

    CHECK_THROWS(journal.complete_rollback(kTransaction));
    CHECK(std::filesystem::exists(state / "active.json"));
    CHECK(journal.unknown_present());
}

TEST_CASE("restore journal rejects invalid ids and effect sets") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);

    CHECK_THROWS(journal.begin("../escape", "rollback", all_effects()));
    CHECK_THROWS(journal.begin(
        "00112233445566778899AABBCCDDEEFF",
        "rollback",
        all_effects()));
    CHECK_THROWS(
        journal.begin(kTransaction, "rollback", {}));
    CHECK_THROWS(
        journal.begin(kTransaction, "", all_effects()));
    CHECK_THROWS(journal.begin(
        kTransaction,
        "rollback",
        {
            RestoreJournalEffect::files,
            RestoreJournalEffect::files,
        }));
    CHECK_THROWS(journal.begin(
        kTransaction,
        "rollback",
        {RestoreJournalEffect::core}));
    CHECK_FALSE(std::filesystem::exists(
        temporary.path / "escape.rollback"));
}

TEST_CASE("restore journal strictly rejects unknown marker fields") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    journal.begin(kTransaction, "rollback", all_effects());

    auto marker =
        nlohmann::json::parse(read_binary(state / "active.json"));
    marker["unexpected"] = true;
    reseal(marker);
    write_binary(state / "active.json", marker.dump());

    CHECK_THROWS(journal.read_active());
    CHECK(journal.unknown_present());
}

TEST_CASE("restore journal strictly rejects unknown snapshot fields") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    journal.begin(kTransaction, "rollback", all_effects());

    auto marker =
        nlohmann::json::parse(read_binary(state / "active.json"));
    marker["snapshot"]["path"] = "../../unsafe";
    reseal(marker);
    write_binary(state / "active.json", marker.dump());

    CHECK_THROWS(journal.read_active());
    CHECK(journal.unknown_present());
}

TEST_CASE("restore journal detects active marker integrity corruption") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    journal.begin(kTransaction, "rollback", all_effects());

    auto marker =
        nlohmann::json::parse(read_binary(state / "active.json"));
    marker["phase"] = "files_committed";
    write_binary(state / "active.json", marker.dump());

    CHECK_THROWS(journal.read_active());
    CHECK(journal.unknown_present());
}

TEST_CASE("restore journal detects rollback size and hash corruption") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    journal.begin(kTransaction, "rollback", all_effects());

    write_binary(
        state / (std::string(kTransaction) + ".rollback"),
        "tampered");

    CHECK_THROWS(journal.read_active());
    CHECK(journal.unknown_present());
}

TEST_CASE("restore journal rejects unsafe private state permissions") {
    SUBCASE("state directory mode") {
        JournalTempDir temporary;
        const auto state = temporary.path / "restore";
        REQUIRE(std::filesystem::create_directory(state));
        REQUIRE(::chmod(state.c_str(), 0755) == 0);
        CHECK_THROWS(RestoreJournal(state));
    }

    SUBCASE("active marker mode") {
        JournalTempDir temporary;
        const auto state = temporary.path / "restore";
        RestoreJournal journal(state);
        journal.begin(kTransaction, "rollback", all_effects());
        REQUIRE(::chmod((state / "active.json").c_str(), 0660) == 0);

        CHECK_THROWS(journal.read_active());
        CHECK(journal.unknown_present());
    }

    SUBCASE("rollback payload mode") {
        JournalTempDir temporary;
        const auto state = temporary.path / "restore";
        RestoreJournal journal(state);
        journal.begin(kTransaction, "rollback", all_effects());
        REQUIRE(::chmod(
                    (state /
                     (std::string(kTransaction) + ".rollback"))
                        .c_str(),
                    0660) == 0);

        CHECK_THROWS(journal.read_active());
        CHECK(journal.unknown_present());
    }
}

TEST_CASE("restore journal rejects unexpected ownership when test can change it") {
    if (::geteuid() != 0) {
        MESSAGE("ownership mutation test requires root");
        return;
    }

    SUBCASE("state directory owner") {
        JournalTempDir temporary;
        const auto state = temporary.path / "restore";
        REQUIRE(std::filesystem::create_directory(state));
        REQUIRE(::chmod(state.c_str(), 0700) == 0);
        if (::chown(state.c_str(), 65534, 65534) != 0) {
            MESSAGE("filesystem does not permit ownership mutation");
            return;
        }
        CHECK_THROWS(RestoreJournal(state));
    }

    SUBCASE("active marker owner") {
        JournalTempDir temporary;
        const auto state = temporary.path / "restore";
        RestoreJournal journal(state);
        journal.begin(kTransaction, "rollback", all_effects());
        if (::chown(
                (state / "active.json").c_str(), 65534, 65534) != 0) {
            MESSAGE("filesystem does not permit ownership mutation");
            return;
        }

        CHECK_THROWS(journal.read_active());
        CHECK(journal.unknown_present());
    }
}

TEST_CASE("restore journal never follows state or file symlinks") {
    SUBCASE("state directory") {
        JournalTempDir temporary;
        const auto real = temporary.path / "real";
        const auto linked = temporary.path / "linked";
        REQUIRE(std::filesystem::create_directory(real));
        REQUIRE(::symlink(real.c_str(), linked.c_str()) == 0);
        CHECK_THROWS(RestoreJournal(linked));
    }

    SUBCASE("active marker") {
        JournalTempDir temporary;
        const auto state = temporary.path / "restore";
        RestoreJournal journal(state);
        const auto sentinel = temporary.path / "sentinel";
        write_binary(sentinel, "unchanged");
        REQUIRE(
            ::symlink(sentinel.c_str(), (state / "active.json").c_str()) ==
            0);

        CHECK_THROWS(journal.read_active());
        CHECK(read_binary(sentinel) == "unchanged");
        CHECK(journal.unknown_present());
    }

    SUBCASE("rollback payload") {
        JournalTempDir temporary;
        const auto state = temporary.path / "restore";
        RestoreJournal journal(state);
        const auto sentinel = temporary.path / "sentinel";
        write_binary(sentinel, "unchanged");
        REQUIRE(::symlink(
                    sentinel.c_str(),
                    (state /
                     (std::string(kTransaction) + ".rollback"))
                        .c_str()) == 0);

        CHECK_THROWS(
            journal.begin(kTransaction, "rollback", all_effects()));
        CHECK(read_binary(sentinel) == "unchanged");
        CHECK(journal.unknown_present());
    }
}

#ifdef KEEN_PBR3_TESTING
TEST_CASE(
    "restore journal construction removes only dead-owner temporaries") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal initial(state);

    constexpr pid_t dead_pid =
        static_cast<pid_t>(std::numeric_limits<pid_t>::max());
    errno = 0;
    if (::kill(dead_pid, 0) == 0 || errno != ESRCH) {
        MESSAGE("could not reserve a provably dead pid for cleanup test");
        return;
    }

    const auto orphan =
        state /
        (".keen-pbr-restore-journal." +
         std::to_string(dead_pid) + ".1");
    const auto live =
        state /
        (".keen-pbr-restore-journal." +
         std::to_string(::getpid()) + ".2");
    const auto sentinel = temporary.path / "sentinel";
    const auto unsafe =
        state /
        (".keen-pbr-restore-journal." +
         std::to_string(dead_pid) + ".3");
    const auto malformed =
        state / ".keen-pbr-restore-journal.not-a-pid.4";

    create_sparse_private_file(orphan, 1);
    create_sparse_private_file(live, 1);
    write_binary(sentinel, "unchanged");
    REQUIRE(::symlink(sentinel.c_str(), unsafe.c_str()) == 0);
    create_sparse_private_file(malformed, 1);

    RestoreJournal cleanup(state);

    CHECK_FALSE(std::filesystem::exists(orphan));
    CHECK(std::filesystem::exists(live));
    CHECK(std::filesystem::is_symlink(unsafe));
    CHECK(read_binary(sentinel) == "unchanged");
    CHECK(std::filesystem::exists(malformed));
}

TEST_CASE(
    "restore journal writes stay anchored to the verified directory fd") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    const auto moved = temporary.path / "verified-restore";
    bool swapped = false;
    RestoreJournalTestHooks hooks;
    hooks.fault_injector =
        [&](RestoreJournalFaultStage stage) {
            if (stage != RestoreJournalFaultStage::active_write ||
                swapped) {
                return;
            }
            swapped = true;
            std::error_code error;
            std::filesystem::rename(state, moved, error);
            if (error) throw std::system_error(error);
            if (!std::filesystem::create_directory(state, error) ||
                error) {
                throw std::system_error(
                    error ? error
                          : std::make_error_code(
                                std::errc::file_exists));
            }
            if (::chmod(state.c_str(), 0700) != 0) {
                throw std::system_error(
                    errno, std::generic_category(), "chmod fault");
            }
        };
    RestoreJournal journal(state, std::move(hooks));

    CHECK_THROWS(journal.begin(kTransaction, "rollback", all_effects()));
    REQUIRE(swapped);
    CHECK(std::filesystem::exists(moved / "active.json"));
    CHECK(std::filesystem::exists(
        moved / (std::string(kTransaction) + ".rollback")));
    CHECK_FALSE(std::filesystem::exists(state / "active.json"));
    CHECK_FALSE(std::filesystem::exists(
        state / (std::string(kTransaction) + ".rollback")));
    CHECK(std::filesystem::exists(state / "UNKNOWN"));
}

TEST_CASE("restore journal retains only the three newest rollback payloads") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    const std::array<std::string, 5> transactions{
        "00000000000000000000000000000001",
        "00000000000000000000000000000002",
        "00000000000000000000000000000003",
        "00000000000000000000000000000004",
        "00000000000000000000000000000005",
    };

    for (const auto& transaction : transactions) {
        commit_files_only(journal, transaction, transaction);
    }

    CHECK_FALSE(std::filesystem::exists(
        state / (transactions[0] + ".rollback")));
    CHECK_FALSE(std::filesystem::exists(
        state / (transactions[1] + ".rollback")));
    for (std::size_t index = 2; index < transactions.size(); ++index) {
        CHECK(std::filesystem::exists(
            state / (transactions[index] + ".rollback")));
    }
    CHECK_FALSE(journal.read_active().has_value());
    CHECK_FALSE(journal.unknown_present());
}

TEST_CASE(
    "restore journal retention orders same-second payloads by nanoseconds") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    const std::string oldest =
        "ffffffffffffffffffffffffffffffff";
    const std::string middle =
        "88888888888888888888888888888888";
    const std::string newest =
        "00000000000000000000000000000000";

    const auto create_at = [&](const std::string& transaction,
                               long nanoseconds) {
        const auto path = state / (transaction + ".rollback");
        create_sparse_private_file(path, 1);
        const struct timespec timestamps[2]{
            {1000000000, nanoseconds},
            {1000000000, nanoseconds},
        };
        REQUIRE(
            ::utimensat(AT_FDCWD, path.c_str(), timestamps, 0) == 0);
    };
    create_at(oldest, 100);
    create_at(middle, 200);
    create_at(newest, 300);

    const std::string completing =
        "11111111111111111111111111111111";
    commit_files_only(journal, completing, "current");

    CHECK_FALSE(std::filesystem::exists(
        state / (oldest + ".rollback")));
    CHECK(std::filesystem::exists(
        state / (middle + ".rollback")));
    CHECK(std::filesystem::exists(
        state / (newest + ".rollback")));
    CHECK(std::filesystem::exists(
        state / (completing + ".rollback")));
}

TEST_CASE("restore journal retention enforces the aggregate byte budget") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    const std::string oldest =
        "00000000000000000000000000000001";
    const std::string newer =
        "00000000000000000000000000000002";
    const std::string newest =
        "00000000000000000000000000000003";
    create_sparse_private_file(
        state / (oldest + ".rollback"),
        64ULL * 1024ULL * 1024ULL);
    create_sparse_private_file(
        state / (newer + ".rollback"),
        64ULL * 1024ULL * 1024ULL);
    create_sparse_private_file(
        state / (newest + ".rollback"),
        64ULL * 1024ULL * 1024ULL);

    const std::string committed =
        "ffffffffffffffffffffffffffffffff";
    commit_files_only(journal, committed, "new");

    CHECK(std::filesystem::exists(
        state / (committed + ".rollback")));
    CHECK(std::filesystem::exists(
        state / (newest + ".rollback")));
    CHECK_FALSE(std::filesystem::exists(
        state / (newer + ".rollback")));
    CHECK_FALSE(std::filesystem::exists(
        state / (oldest + ".rollback")));
}

TEST_CASE(
    "restore journal never removes a rollback payload that became active") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    commit_files_only(
        journal, "10000000000000000000000000000001");
    commit_files_only(
        journal, "10000000000000000000000000000002");
    commit_files_only(
        journal, "10000000000000000000000000000003");

    const std::string completing =
        "20000000000000000000000000000000";
    journal.begin(
        completing, "completing", {RestoreJournalEffect::files});
    journal.advance_phase(
        completing, RestoreJournalPhase::files_committed);

    const std::string next_active =
        "00000000000000000000000000000000";
    bool activated = false;
    RestoreJournalTestHooks hooks;
    hooks.fault_injector =
        [&](RestoreJournalFaultStage stage) {
            if (stage != RestoreJournalFaultStage::rollback_gc_scan ||
                activated) {
                return;
            }
            activated = true;
            RestoreJournal next(state);
            next.begin(
                next_active,
                "active rollback",
                {RestoreJournalEffect::files});
        };
    RestoreJournal committing(state, std::move(hooks));
    CHECK_NOTHROW(committing.commit(completing));

    REQUIRE(activated);
    RestoreJournal verification(state);
    const auto active = verification.read_active();
    REQUIRE(active.has_value());
    CHECK(active->transaction_id == next_active);
    CHECK(std::filesystem::exists(
        state / (next_active + ".rollback")));
}

TEST_CASE(
    "restore journal retention revalidates payload identity before unlink") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal setup(state);
    const std::string oldest =
        "10000000000000000000000000000001";
    commit_files_only(setup, oldest, "rollback");
    commit_files_only(
        setup, "10000000000000000000000000000002", "rollback");
    commit_files_only(
        setup, "10000000000000000000000000000003", "rollback");

    const auto replacement = temporary.path / "replacement";
    write_binary(replacement, "replaced");
    REQUIRE(::chmod(replacement.c_str(), 0600) == 0);

    bool replaced = false;
    RestoreJournalTestHooks hooks;
    hooks.fault_injector =
        [&](RestoreJournalFaultStage stage) {
            if (stage != RestoreJournalFaultStage::rollback_gc_unlink ||
                replaced) {
                return;
            }
            replaced = true;
            if (::rename(
                    replacement.c_str(),
                    (state / (oldest + ".rollback")).c_str()) != 0) {
                throw std::system_error(
                    errno,
                    std::generic_category(),
                    "replace retention candidate");
            }
        };
    RestoreJournal journal(state, std::move(hooks));
    CHECK_NOTHROW(commit_files_only(
        journal,
        "20000000000000000000000000000000",
        "current"));

    REQUIRE(replaced);
    CHECK(
        read_binary(state / (oldest + ".rollback")) == "replaced");
    CHECK_FALSE(std::filesystem::exists(state / "active.json"));
    CHECK_FALSE(journal.unknown_present());
}

TEST_CASE(
    "restore journal ignores retention failure after durable commit") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournalTestHooks hooks;
    hooks.fault_injector =
        [](RestoreJournalFaultStage stage) {
            if (stage == RestoreJournalFaultStage::rollback_gc_scan) {
                throw std::system_error(
                    EIO,
                    std::generic_category(),
                    "retention scan fault");
            }
        };
    RestoreJournal journal(state, std::move(hooks));
    journal.begin(
        kTransaction, "rollback", {RestoreJournalEffect::files});
    journal.advance_phase(
        kTransaction, RestoreJournalPhase::files_committed);

    CHECK_NOTHROW(journal.commit(kTransaction));
    CHECK_FALSE(std::filesystem::exists(state / "active.json"));
    CHECK_FALSE(journal.unknown_present());
    CHECK(std::filesystem::exists(
        state / (std::string(kTransaction) + ".rollback")));
}

TEST_CASE(
    "restore journal retention refuses unsafe rollback symlinks") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournal journal(state);
    commit_files_only(
        journal, "10000000000000000000000000000001");
    commit_files_only(
        journal, "10000000000000000000000000000002");
    commit_files_only(
        journal, "10000000000000000000000000000003");

    const auto sentinel = temporary.path / "sentinel";
    write_binary(sentinel, "unchanged");
    const auto unsafe =
        state / "00000000000000000000000000000000.rollback";
    REQUIRE(::symlink(sentinel.c_str(), unsafe.c_str()) == 0);

    const std::string completing =
        "ffffffffffffffffffffffffffffffff";
    CHECK_NOTHROW(
        commit_files_only(journal, completing, "new rollback"));
    CHECK(read_binary(sentinel) == "unchanged");
    CHECK(std::filesystem::is_symlink(unsafe));
    CHECK_FALSE(std::filesystem::exists(state / "active.json"));
    CHECK_FALSE(journal.unknown_present());
    CHECK(std::filesystem::exists(
        state / (completing + ".rollback")));
}

TEST_CASE("restore journal pre-rename active failure is retryable") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournalTestHooks hooks;
    hooks.fault_injector = [](RestoreJournalFaultStage stage) {
        if (stage == RestoreJournalFaultStage::active_rename) {
            throw std::system_error(
                EIO, std::generic_category(), "active rename fault");
        }
    };
    RestoreJournal failing(state, std::move(hooks));

    CHECK_THROWS(failing.begin(kTransaction, "rollback", all_effects()));
    CHECK_FALSE(std::filesystem::exists(state / "active.json"));
    CHECK_FALSE(failing.unknown_present());
    CHECK(std::filesystem::exists(
        state / (std::string(kTransaction) + ".rollback")));

    RestoreJournal retry(state);
    CHECK(
        retry.begin(kTransaction, "rollback", all_effects()).phase ==
        RestoreJournalPhase::prepared);
}

TEST_CASE("restore journal post-rename active failure becomes UNKNOWN") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournalTestHooks hooks;
    hooks.fault_injector = [](RestoreJournalFaultStage stage) {
        if (stage ==
            RestoreJournalFaultStage::active_directory_fsync) {
            throw std::system_error(
                EIO,
                std::generic_category(),
                "active directory fsync fault");
        }
    };
    RestoreJournal journal(state, std::move(hooks));

    CHECK_THROWS(journal.begin(kTransaction, "rollback", all_effects()));
    CHECK(std::filesystem::exists(state / "active.json"));
    CHECK(journal.unknown_present());
}

TEST_CASE("restore journal post-rename snapshot failure is safely retryable") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    RestoreJournalTestHooks hooks;
    hooks.fault_injector = [](RestoreJournalFaultStage stage) {
        if (stage ==
            RestoreJournalFaultStage::snapshot_directory_fsync) {
            throw std::system_error(
                EIO,
                std::generic_category(),
                "snapshot directory fsync fault");
        }
    };
    RestoreJournal failing(state, std::move(hooks));

    CHECK_THROWS(failing.begin(kTransaction, "rollback", all_effects()));
    CHECK_FALSE(std::filesystem::exists(state / "active.json"));
    CHECK_FALSE(failing.unknown_present());

    RestoreJournal retry(state);
    CHECK(
        retry.begin(kTransaction, "rollback", all_effects()).phase ==
        RestoreJournalPhase::prepared);
}

TEST_CASE("restore journal commit fsync failure restores active marker") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    bool fail_commit = false;
    RestoreJournalTestHooks hooks;
    hooks.fault_injector =
        [&fail_commit](RestoreJournalFaultStage stage) {
            if (fail_commit &&
                stage == RestoreJournalFaultStage::
                             active_remove_directory_fsync) {
                throw std::system_error(
                    EIO,
                    std::generic_category(),
                    "commit directory fsync fault");
            }
        };
    RestoreJournal journal(state, std::move(hooks));
    journal.begin(kTransaction, "rollback", all_effects());
    advance_to_final(journal);

    fail_commit = true;
    CHECK_THROWS(journal.commit(kTransaction));
    CHECK(std::filesystem::exists(state / "active.json"));
    CHECK_FALSE(journal.unknown_present());
    CHECK(
        journal.read_active()->phase ==
        RestoreJournalPhase::nfqws_ready);
}

TEST_CASE("restore journal marks UNKNOWN when commit compensation fails") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    bool fail_commit = false;
    bool fail_recreation = false;
    RestoreJournalTestHooks hooks;
    hooks.fault_injector =
        [&fail_commit,
         &fail_recreation](RestoreJournalFaultStage stage) {
            if (fail_commit &&
                stage == RestoreJournalFaultStage::
                             active_remove_directory_fsync) {
                throw std::system_error(
                    EIO,
                    std::generic_category(),
                    "commit directory fsync fault");
            }
            if (fail_recreation &&
                stage == RestoreJournalFaultStage::active_rename) {
                throw std::system_error(
                    EIO,
                    std::generic_category(),
                    "active recreation rename fault");
            }
        };
    RestoreJournal journal(state, std::move(hooks));
    journal.begin(kTransaction, "rollback", all_effects());
    advance_to_final(journal);

    fail_commit = true;
    fail_recreation = true;
    CHECK_THROWS(journal.commit(kTransaction));
    CHECK_FALSE(std::filesystem::exists(state / "active.json"));
    CHECK(journal.unknown_present());
}

TEST_CASE(
    "restore journal rollback completion fsync failure restores exact marker") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    bool fail_completion = false;
    RestoreJournalTestHooks hooks;
    hooks.fault_injector =
        [&fail_completion](RestoreJournalFaultStage stage) {
            if (fail_completion &&
                stage == RestoreJournalFaultStage::
                             active_remove_directory_fsync) {
                throw std::system_error(
                    EIO,
                    std::generic_category(),
                    "rollback completion directory fsync fault");
            }
        };
    RestoreJournal journal(state, std::move(hooks));
    const auto started =
        journal.begin(kTransaction, "rollback", all_effects());
    const auto exact_marker = read_binary(state / "active.json");

    fail_completion = true;
    CHECK_THROWS(journal.complete_rollback(kTransaction));
    CHECK(read_binary(state / "active.json") == exact_marker);
    CHECK(journal.read_active() == started);
    CHECK_FALSE(journal.unknown_present());

    fail_completion = false;
    CHECK_NOTHROW(journal.complete_rollback(kTransaction));
    CHECK_FALSE(journal.read_active().has_value());
}

TEST_CASE(
    "restore journal rollback completion marks UNKNOWN if compensation fails") {
    JournalTempDir temporary;
    const auto state = temporary.path / "restore";
    bool fail_completion = false;
    bool fail_recreation = false;
    RestoreJournalTestHooks hooks;
    hooks.fault_injector =
        [&fail_completion,
         &fail_recreation](RestoreJournalFaultStage stage) {
            if (fail_completion &&
                stage == RestoreJournalFaultStage::
                             active_remove_directory_fsync) {
                throw std::system_error(
                    EIO,
                    std::generic_category(),
                    "rollback completion directory fsync fault");
            }
            if (fail_recreation &&
                stage == RestoreJournalFaultStage::active_rename) {
                throw std::system_error(
                    EIO,
                    std::generic_category(),
                    "rollback marker recreation rename fault");
            }
        };
    RestoreJournal journal(state, std::move(hooks));
    journal.begin(kTransaction, "rollback", all_effects());

    fail_completion = true;
    fail_recreation = true;
    CHECK_THROWS(journal.complete_rollback(kTransaction));
    CHECK_FALSE(std::filesystem::exists(state / "active.json"));
    CHECK(journal.unknown_present());
}
#endif

} // namespace keen_pbr3
