#include <doctest/doctest.h>

#include "../src/backup/restore_transaction.hpp"

#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {
namespace {

constexpr const char* kConfigTransaction =
    "00112233445566778899aabbccddeeff";
constexpr const char* kRestoreTransaction =
    "ffeeddccbbaa99887766554433221100";

class RestoreTransactionTempDir {
public:
    RestoreTransactionTempDir() {
        char pattern[] = "/tmp/keen-pbr-restore-transaction-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~RestoreTransactionTempDir() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

std::vector<RestoreJournalEffect> all_transaction_effects() {
    return {
        RestoreJournalEffect::files,
        RestoreJournalEffect::transport_manager,
        RestoreJournalEffect::core,
        RestoreJournalEffect::nfqws,
    };
}

} // namespace

TEST_CASE("restore transaction operations have isolated deterministic WALs") {
    const std::filesystem::path root{"/private/keen-pbr/restore"};

    CHECK(
        restore_transaction_state_directory(
            root, RestoreTransactionOperation::config_save) ==
        root / "config-save");
    CHECK(
        restore_transaction_state_directory(
            root, RestoreTransactionOperation::backup_restore) ==
        root / "backup-restore");
    CHECK(
        std::string(to_string(
            RestoreTransactionOperation::config_save)) == "config-save");
    CHECK(
        std::string(to_string(
            RestoreTransactionOperation::backup_restore)) ==
        "backup-restore");
    CHECK_THROWS_AS(
        restore_transaction_state_directory(
            root, static_cast<RestoreTransactionOperation>(255)),
        const std::invalid_argument&);
}

TEST_CASE("restore transaction preserves exact rollback bytes and effects") {
    RestoreTransactionTempDir temporary;
    const std::string payload{"config\0rollback\n", 16};
    const auto effects = all_transaction_effects();

    RestoreTransaction transaction(
        temporary.path, RestoreTransactionOperation::config_save);
    const auto started =
        transaction.begin(kConfigTransaction, payload, effects);

    CHECK(
        transaction.operation() ==
        RestoreTransactionOperation::config_save);
    CHECK(
        transaction.state_directory() ==
        temporary.path / "config-save");
    CHECK(started.phase == RestoreJournalPhase::prepared);
    CHECK(started.effects == effects);

    RestoreJournal inspection(transaction.state_directory());
    const auto active = inspection.read_active();
    REQUIRE(active.has_value());
    CHECK(inspection.read_rollback_payload(*active) == payload);
}

TEST_CASE("restore transaction exposes explicit durable phase milestones") {
    RestoreTransactionTempDir temporary;
    RestoreTransaction transaction(
        temporary.path, RestoreTransactionOperation::backup_restore);
    transaction.begin(
        kRestoreTransaction,
        "exact rollback",
        all_transaction_effects());

    CHECK(
        transaction.files_committed().phase ==
        RestoreJournalPhase::files_committed);
    CHECK(
        transaction.transports_ready().phase ==
        RestoreJournalPhase::transports_ready);
    CHECK(
        transaction.core_applied().phase ==
        RestoreJournalPhase::core_applied);
    CHECK(
        transaction.nfqws_ready().phase ==
        RestoreJournalPhase::nfqws_ready);
    transaction.commit();

    RestoreJournal inspection(transaction.state_directory());
    CHECK_FALSE(inspection.read_active().has_value());
}

TEST_CASE("restore transaction leaves skipped phases fail-closed in WAL") {
    RestoreTransactionTempDir temporary;
    const auto state = temporary.path / "config-save";

    {
        RestoreTransaction transaction(
            temporary.path, RestoreTransactionOperation::config_save);
        transaction.begin(
            kConfigTransaction,
            "rollback",
            {
                RestoreJournalEffect::files,
                RestoreJournalEffect::core,
            });

        CHECK_THROWS(transaction.core_applied());
        CHECK_THROWS(transaction.commit());

        RestoreJournal inspection(state);
        const auto active = inspection.read_active();
        REQUIRE(active.has_value());
        CHECK(active->phase == RestoreJournalPhase::prepared);
    }

    // Destruction is not a rollback or a commit. Startup recovery still sees
    // the exact prepared transaction.
    RestoreJournal after_scope(state);
    const auto active = after_scope.read_active();
    REQUIRE(active.has_value());
    CHECK(active->transaction_id == kConfigTransaction);
    CHECK(
        after_scope.read_rollback_payload(*active) ==
        "rollback");
}

TEST_CASE("restore transaction rejects use before begin") {
    RestoreTransactionTempDir temporary;
    RestoreTransaction transaction(
        temporary.path, RestoreTransactionOperation::config_save);

    CHECK_THROWS_AS(
        transaction.files_committed(), const std::logic_error&);
    CHECK_THROWS_AS(transaction.commit(), const std::logic_error&);
    CHECK_THROWS_AS(
        transaction.complete_rollback(), const std::logic_error&);
}

TEST_CASE("restore transaction begin remains exact and single identity") {
    RestoreTransactionTempDir temporary;
    RestoreTransaction transaction(
        temporary.path, RestoreTransactionOperation::config_save);
    const std::vector<RestoreJournalEffect> effects{
        RestoreJournalEffect::files,
    };

    transaction.begin(kConfigTransaction, "rollback", effects);
    CHECK_NOTHROW(
        transaction.begin(kConfigTransaction, "rollback", effects));
    CHECK_THROWS(
        transaction.begin(kConfigTransaction, "changed", effects));
    CHECK_THROWS_AS(
        transaction.begin(kRestoreTransaction, "rollback", effects),
        const std::logic_error&);
}

TEST_CASE("restore transaction completes an explicit verified rollback") {
    RestoreTransactionTempDir temporary;
    RestoreTransaction transaction(
        temporary.path, RestoreTransactionOperation::backup_restore);
    transaction.begin(
        kRestoreTransaction,
        "rollback",
        {RestoreJournalEffect::files});

    transaction.complete_rollback();

    RestoreJournal inspection(transaction.state_directory());
    CHECK_FALSE(inspection.read_active().has_value());
}

} // namespace keen_pbr3
