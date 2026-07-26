#pragma once

#include "persistent_snapshot.hpp"
#include "restore_transaction.hpp"

#include <filesystem>
#ifdef KEEN_PBR3_TESTING
#include <functional>
#endif
#include <optional>
#include <stdexcept>
#include <string>

namespace keen_pbr3::backup {

// Share the operation identity with the forward WAL facade.  The coordinator
// deliberately scans only these two operations; a third directory appearing
// below state_root is never treated as an operation source.
using RecoveryOperation = RestoreTransactionOperation;

const char* recovery_operation_name(
    RecoveryOperation operation) noexcept;

enum class RecoveryOutcome {
    no_active_operation,
    rollback_completed,
};

struct RecoveryResult {
    RecoveryOutcome outcome{
        RecoveryOutcome::no_active_operation};
    std::optional<RecoveryOperation> operation;
    std::optional<std::string> transaction_id;
};

enum class RecoveryErrorKind {
    global_unknown,
    multiple_active_operations,
    corrupt_journal,
    corrupt_snapshot,
    unsafe_state,
    retryable_io,
    verification_failed,
    completion_failed,
    global_marker_failure,
};

class RecoveryCoordinatorError final : public std::runtime_error {
public:
    RecoveryCoordinatorError(
        RecoveryErrorKind kind,
        std::string message,
        std::optional<RecoveryOperation> operation =
            std::nullopt);

    RecoveryErrorKind kind() const noexcept;
    const std::optional<RecoveryOperation>& operation()
        const noexcept;

private:
    RecoveryErrorKind kind_;
    std::optional<RecoveryOperation> operation_;
};

struct RecoveryCoordinatorLayout {
    // Contains UNKNOWN and the fixed config-save/ and backup-restore/
    // journals.  The directory is private and owned by the effective user.
    std::filesystem::path state_root{
        "/opt/var/lib/keen-pbr/recovery"};
    PersistentLayout persistent;
};

#ifdef KEEN_PBR3_TESTING
struct RecoveryCoordinatorTestHooks {
    FileApplyHooks file_apply;
    // The active journal is intentionally still present at both hook points.
    // They model power loss after exact file restoration.
    std::function<void(RecoveryOperation)> after_files_applied;
    std::function<void(RecoveryOperation)> after_files_verified;
};
#endif

// Performs offline, file-only crash recovery.
//
// No live Config object, service, API context, or lifecycle state is consulted.
// The immutable journal payload is parsed as a persistent operation snapshot,
// applied with FileMutationTransaction, verified byte-for-byte (including
// tombstones and metadata), and only then completed in the journal.
class RecoveryCoordinator {
public:
    explicit RecoveryCoordinator(
        RecoveryCoordinatorLayout layout);
#ifdef KEEN_PBR3_TESTING
    RecoveryCoordinator(
        RecoveryCoordinatorLayout layout,
        RecoveryCoordinatorTestHooks hooks);
#endif

    RecoveryResult recover();
    bool global_unknown_present();

    const RecoveryCoordinatorLayout& layout() const noexcept;

private:
    RecoveryCoordinatorLayout layout_;
#ifdef KEEN_PBR3_TESTING
    RecoveryCoordinatorTestHooks test_hooks_;
#endif
};

} // namespace keen_pbr3::backup
