#include "restore_transaction.hpp"

#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

const char* to_string(RestoreTransactionOperation operation) noexcept {
    switch (operation) {
        case RestoreTransactionOperation::config_save:
            return "config-save";
        case RestoreTransactionOperation::backup_restore:
            return "backup-restore";
    }
    return "unknown";
}

std::filesystem::path restore_transaction_state_directory(
    const std::filesystem::path& state_root,
    RestoreTransactionOperation operation) {
    switch (operation) {
        case RestoreTransactionOperation::config_save:
            return state_root / "config-save";
        case RestoreTransactionOperation::backup_restore:
            return state_root / "backup-restore";
    }
    throw std::invalid_argument("Unknown restore transaction operation");
}

RestoreTransaction::RestoreTransaction(
    std::filesystem::path state_root,
    RestoreTransactionOperation operation)
    : operation_(operation),
      journal_(restore_transaction_state_directory(state_root, operation)) {}

#ifdef KEEN_PBR3_TESTING
RestoreTransaction::RestoreTransaction(
    std::filesystem::path state_root,
    RestoreTransactionOperation operation,
    RestoreJournalTestHooks hooks)
    : operation_(operation),
      journal_(
          restore_transaction_state_directory(state_root, operation),
          std::move(hooks)) {}
#endif

RestoreJournalEntry RestoreTransaction::begin(
    const std::string& transaction_id,
    const std::string& exact_rollback_payload,
    std::vector<RestoreJournalEffect> effects) {
    if (transaction_id_.has_value() &&
        *transaction_id_ != transaction_id) {
        throw std::logic_error(
            "RestoreTransaction cannot be reused for another transaction");
    }

    auto entry = journal_.begin(
        transaction_id,
        exact_rollback_payload,
        std::move(effects));
    transaction_id_ = entry.transaction_id;
    return entry;
}

RestoreJournalEntry RestoreTransaction::files_committed() {
    return advance(RestoreJournalPhase::files_committed);
}

RestoreJournalEntry RestoreTransaction::transports_ready() {
    return advance(RestoreJournalPhase::transports_ready);
}

RestoreJournalEntry RestoreTransaction::core_applied() {
    return advance(RestoreJournalPhase::core_applied);
}

RestoreJournalEntry RestoreTransaction::nfqws_ready() {
    return advance(RestoreJournalPhase::nfqws_ready);
}

void RestoreTransaction::commit() {
    journal_.commit(require_transaction_id());
}

void RestoreTransaction::complete_rollback() {
    journal_.complete_rollback(require_transaction_id());
}

RestoreTransactionOperation RestoreTransaction::operation() const noexcept {
    return operation_;
}

const std::filesystem::path& RestoreTransaction::state_directory()
    const noexcept {
    return journal_.state_directory();
}

const std::string& RestoreTransaction::require_transaction_id() const {
    if (!transaction_id_.has_value()) {
        throw std::logic_error(
            "Restore transaction has not been started");
    }
    return *transaction_id_;
}

RestoreJournalEntry RestoreTransaction::advance(
    RestoreJournalPhase phase) {
    return journal_.advance_phase(require_transaction_id(), phase);
}

} // namespace keen_pbr3
