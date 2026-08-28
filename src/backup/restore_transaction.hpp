#pragma once

#include "restore_journal.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class RestoreTransactionOperation {
    config_save,
    backup_restore,
};

const char* to_string(RestoreTransactionOperation operation) noexcept;

// Each operation owns an independent WAL namespace below the supplied state
// root. Keeping this mapping in one place prevents config-save and
// backup-restore recovery from observing or completing each other's journal.
std::filesystem::path restore_transaction_state_directory(
    const std::filesystem::path& state_root,
    RestoreTransactionOperation operation);

// A typed, single-operation facade over RestoreJournal.
//
// RestoreJournal remains the only state machine and durable source of truth.
// This facade deliberately performs no automatic cleanup: if the process
// leaves scope before commit() or complete_rollback(), the active marker must
// remain available to startup recovery.
class RestoreTransaction {
public:
    RestoreTransaction(std::filesystem::path state_root,
                       RestoreTransactionOperation operation);
#ifdef KEEN_PBR3_TESTING
    RestoreTransaction(
        std::filesystem::path state_root,
        RestoreTransactionOperation operation,
        RestoreJournalTestHooks hooks);
#endif
    ~RestoreTransaction() = default;

    RestoreTransaction(const RestoreTransaction&) = delete;
    RestoreTransaction& operator=(const RestoreTransaction&) = delete;
    RestoreTransaction(RestoreTransaction&&) = delete;
    RestoreTransaction& operator=(RestoreTransaction&&) = delete;

    RestoreJournalEntry begin(
        const std::string& transaction_id,
        const std::string& exact_rollback_payload,
        std::vector<RestoreJournalEffect> effects);

    RestoreJournalEntry files_committed();
    RestoreJournalEntry transports_ready();
    RestoreJournalEntry core_applied();
    RestoreJournalEntry nfqws_ready();

    void commit();
    void complete_rollback();

    RestoreTransactionOperation operation() const noexcept;
    const std::filesystem::path& state_directory() const noexcept;

private:
    const std::string& require_transaction_id() const;
    RestoreJournalEntry advance(RestoreJournalPhase phase);

    RestoreTransactionOperation operation_;
    RestoreJournal journal_;
    std::optional<std::string> transaction_id_;
};

} // namespace keen_pbr3
