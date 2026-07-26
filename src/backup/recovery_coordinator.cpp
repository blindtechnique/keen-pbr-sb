#include "recovery_coordinator.hpp"

#include "restore_journal.hpp"

#include <algorithm>
#include <memory>
#include <nlohmann/json.hpp>
#include <utility>
#include <vector>

namespace keen_pbr3::backup {
namespace {

namespace fs = std::filesystem;

struct OperationState {
    RecoveryOperation operation;
    fs::path journal_path;
    std::unique_ptr<RestoreJournal> journal;
    std::optional<RestoreJournalEntry> active;
};

fs::path journal_path(
    const RecoveryCoordinatorLayout& layout,
    RecoveryOperation operation) {
    return layout.state_root /
           recovery_operation_name(operation);
}

std::vector<OperationState> operation_states(
    const RecoveryCoordinatorLayout& layout) {
    std::vector<OperationState> states;
    states.reserve(2);
    for (const auto operation :
         {RecoveryOperation::config_save,
          RecoveryOperation::backup_restore}) {
        states.push_back({
            operation,
            journal_path(layout, operation),
            nullptr,
            std::nullopt,
        });
    }
    return states;
}

[[noreturn]] void throw_fail_closed(
    RestoreJournal& global,
    RecoveryErrorKind kind,
    const std::string& message,
    std::optional<RecoveryOperation> operation =
        std::nullopt) {
    try {
        global.mark_unknown();
    } catch (const std::exception& marker_error) {
        throw RecoveryCoordinatorError(
            RecoveryErrorKind::global_marker_failure,
            message +
                "; additionally, the global UNKNOWN marker could not be "
                "made durable: " +
                marker_error.what(),
            operation);
    } catch (...) {
        throw RecoveryCoordinatorError(
            RecoveryErrorKind::global_marker_failure,
            message +
                "; additionally, the global UNKNOWN marker could not be "
                "made durable",
            operation);
    }
    throw RecoveryCoordinatorError(
        kind, message, operation);
}

bool exact_state_matches(
    const FileMutation& mutation) {
    const auto& actual = mutation.before;
    const auto& expected = mutation.replacement;
    if (expected.remove) {
        return !actual.existed;
    }
    if (!actual.existed ||
        actual.content != expected.content) {
        return false;
    }
    if (!expected.mode_override.has_value() ||
        !expected.owner_override.has_value() ||
        !expected.group_override.has_value()) {
        return false;
    }
    return actual.mode ==
               (*expected.mode_override & 0777) &&
           actual.owner == *expected.owner_override &&
           actual.group == *expected.group_override;
}

bool verify_exact_post_state(
    const PersistentLayout& layout,
    const nlohmann::json& snapshot) {
    // Rebuilding the restore plan is also the exact-scope check: any managed
    // file that appeared after the first plan becomes a tombstone here.
    const auto verification =
        prepare_persistent_restore(layout, snapshot);
    return std::all_of(
        verification.begin(),
        verification.end(),
        exact_state_matches);
}

RecoveryErrorKind classify_snapshot_error(
    PersistentSnapshotErrorKind kind,
    bool verification) {
    switch (kind) {
    case PersistentSnapshotErrorKind::invalid_document:
        return RecoveryErrorKind::corrupt_snapshot;
    case PersistentSnapshotErrorKind::limit_exceeded:
    case PersistentSnapshotErrorKind::internal:
        return verification
                   ? RecoveryErrorKind::verification_failed
                   : RecoveryErrorKind::corrupt_snapshot;
    case PersistentSnapshotErrorKind::unsafe_local_state:
        return RecoveryErrorKind::unsafe_state;
    case PersistentSnapshotErrorKind::io_failure:
        return RecoveryErrorKind::retryable_io;
    }
    return RecoveryErrorKind::unsafe_state;
}

bool must_mark_unknown(RecoveryErrorKind kind) {
    switch (kind) {
    case RecoveryErrorKind::corrupt_snapshot:
    case RecoveryErrorKind::unsafe_state:
    case RecoveryErrorKind::verification_failed:
        return true;
    case RecoveryErrorKind::global_unknown:
    case RecoveryErrorKind::multiple_active_operations:
    case RecoveryErrorKind::corrupt_journal:
    case RecoveryErrorKind::retryable_io:
    case RecoveryErrorKind::completion_failed:
    case RecoveryErrorKind::global_marker_failure:
        return false;
    }
    return true;
}

[[noreturn]] void rethrow_snapshot_failure(
    RestoreJournal& global,
    const PersistentSnapshotError& error,
    RecoveryOperation operation,
    bool verification) {
    const auto kind =
        classify_snapshot_error(error.kind(), verification);
    const std::string message =
        std::string(
            verification
                ? "Persistent rollback verification failed: "
                : "Persistent rollback failed: ") +
        error.what();
    if (must_mark_unknown(kind)) {
        throw_fail_closed(
            global, kind, message, operation);
    }
    throw RecoveryCoordinatorError(
        kind, message, operation);
}

[[noreturn]] void handle_completion_failure(
    RestoreJournal& global,
    OperationState& state,
    const RestoreJournalEntry& expected,
    const std::string& message) {
    try {
        if (!state.journal->unknown_present()) {
            const auto active =
                state.journal->read_active();
            if (active.has_value() &&
                *active == expected) {
                throw RecoveryCoordinatorError(
                    RecoveryErrorKind::completion_failed,
                    message,
                    state.operation);
            }
        }
    } catch (const RecoveryCoordinatorError&) {
        throw;
    } catch (...) {
        // The journal can no longer prove that the exact active marker was
        // restored after the failed commit point.
    }
    throw_fail_closed(
        global,
        RecoveryErrorKind::completion_failed,
        message,
        state.operation);
}

} // namespace

const char* recovery_operation_name(
    RecoveryOperation operation) noexcept {
    switch (operation) {
    case RecoveryOperation::config_save:
        return "config-save";
    case RecoveryOperation::backup_restore:
        return "backup-restore";
    }
    return "unknown";
}

RecoveryCoordinatorError::RecoveryCoordinatorError(
    RecoveryErrorKind kind,
    std::string message,
    std::optional<RecoveryOperation> operation)
    : std::runtime_error(std::move(message)),
      kind_(kind),
      operation_(operation) {}

RecoveryErrorKind
RecoveryCoordinatorError::kind() const noexcept {
    return kind_;
}

const std::optional<RecoveryOperation>&
RecoveryCoordinatorError::operation() const noexcept {
    return operation_;
}

RecoveryCoordinator::RecoveryCoordinator(
    RecoveryCoordinatorLayout layout)
    : layout_(std::move(layout)) {}

#ifdef KEEN_PBR3_TESTING
RecoveryCoordinator::RecoveryCoordinator(
    RecoveryCoordinatorLayout layout,
    RecoveryCoordinatorTestHooks hooks)
    : layout_(std::move(layout)),
      test_hooks_(std::move(hooks)) {}
#endif

RecoveryResult RecoveryCoordinator::recover() {
    std::unique_ptr<RestoreJournal> global;
    try {
        global =
            std::make_unique<RestoreJournal>(
                layout_.state_root);
        if (global->unknown_present()) {
            throw RecoveryCoordinatorError(
                RecoveryErrorKind::global_unknown,
                "Persistent recovery is blocked by global UNKNOWN");
        }
    } catch (const RecoveryCoordinatorError&) {
        throw;
    } catch (const std::exception& error) {
        throw RecoveryCoordinatorError(
            RecoveryErrorKind::global_marker_failure,
            std::string(
                "Cannot inspect global recovery state: ") +
                error.what());
    }

    auto states = operation_states(layout_);
    for (auto& state : states) {
        try {
            state.journal =
                std::make_unique<RestoreJournal>(
                    state.journal_path);
            state.active =
                state.journal->read_active();
        } catch (const std::exception& error) {
            throw_fail_closed(
                *global,
                RecoveryErrorKind::corrupt_journal,
                std::string("Cannot verify ") +
                    recovery_operation_name(
                        state.operation) +
                    " recovery journal: " +
                    error.what(),
                state.operation);
        }
    }

    const auto active_count =
        static_cast<std::size_t>(std::count_if(
            states.begin(),
            states.end(),
            [](const OperationState& state) {
                return state.active.has_value();
            }));
    if (active_count > 1U) {
        // Do not mutate either local journal.  Both immutable payloads remain
        // available for explicit operator recovery.
        throw_fail_closed(
            *global,
            RecoveryErrorKind::multiple_active_operations,
            "Both config-save and backup-restore journals are active");
    }
    if (active_count == 0U) {
        return {
            RecoveryOutcome::no_active_operation,
            std::nullopt,
            std::nullopt,
        };
    }

    auto& state = *std::find_if(
        states.begin(),
        states.end(),
        [](const OperationState& candidate) {
            return candidate.active.has_value();
        });
    const auto active = *state.active;

    std::string payload;
    try {
        payload =
            state.journal->read_rollback_payload(
                active);
    } catch (const std::exception& error) {
        throw_fail_closed(
            *global,
            RecoveryErrorKind::corrupt_journal,
            std::string("Cannot verify ") +
                recovery_operation_name(
                    state.operation) +
                " rollback payload: " +
                error.what(),
            state.operation);
    }

    nlohmann::json snapshot;
    try {
        snapshot = nlohmann::json::parse(payload);
        // Parse once before inspecting any target path.  This verifies the
        // snapshot envelope, per-entry hashes, limits, and target grammar.
        const auto parsed =
            parse_persistent_snapshot(snapshot);
        if (!parsed.scopes.empty()) {
            throw PersistentSnapshotError(
                PersistentSnapshotErrorKind::invalid_document,
                "recovery journal payload is not an operation snapshot");
        }
    } catch (const PersistentSnapshotError& error) {
        rethrow_snapshot_failure(
            *global, error, state.operation, false);
    } catch (const nlohmann::json::exception& error) {
        throw_fail_closed(
            *global,
            RecoveryErrorKind::corrupt_snapshot,
            std::string(
                "Rollback payload is not valid JSON: ") +
                error.what(),
            state.operation);
    } catch (const std::exception& error) {
        throw_fail_closed(
            *global,
            RecoveryErrorKind::corrupt_snapshot,
            std::string(
                "Rollback payload cannot be decoded: ") +
                error.what(),
            state.operation);
    }

    try {
        const auto mutations =
            prepare_persistent_restore(
                layout_.persistent, snapshot);
#ifdef KEEN_PBR3_TESTING
        FileMutationTransaction transaction(
            mutations, test_hooks_.file_apply);
#else
        FileMutationTransaction transaction(mutations);
#endif
        // Deliberately do not compensate back to the interrupted forward
        // state on failure.  The durable snapshot remains authoritative and
        // a later offline retry converges to it.
        transaction.apply();
#ifdef KEEN_PBR3_TESTING
        if (test_hooks_.after_files_applied) {
            test_hooks_.after_files_applied(
                state.operation);
        }
#endif
    } catch (const PersistentSnapshotError& error) {
        rethrow_snapshot_failure(
            *global, error, state.operation, false);
    } catch (const RecoveryCoordinatorError&) {
        throw;
    } catch (const std::exception& error) {
        throw RecoveryCoordinatorError(
            RecoveryErrorKind::retryable_io,
            std::string(
                "Persistent rollback apply was interrupted: ") +
                error.what(),
            state.operation);
    }

    try {
        if (!verify_exact_post_state(
                layout_.persistent, snapshot)) {
            throw_fail_closed(
                *global,
                RecoveryErrorKind::verification_failed,
                "Persistent rollback post-state is not exact",
                state.operation);
        }
#ifdef KEEN_PBR3_TESTING
        if (test_hooks_.after_files_verified) {
            test_hooks_.after_files_verified(
                state.operation);
        }
#endif
    } catch (const PersistentSnapshotError& error) {
        rethrow_snapshot_failure(
            *global, error, state.operation, true);
    } catch (const RecoveryCoordinatorError&) {
        throw;
    } catch (const std::exception& error) {
        throw RecoveryCoordinatorError(
            RecoveryErrorKind::retryable_io,
            std::string(
                "Persistent rollback verification was interrupted: ") +
                error.what(),
            state.operation);
    }

    try {
        state.journal->complete_rollback(
            active.transaction_id);
    } catch (const std::exception& error) {
        handle_completion_failure(
            *global,
            state,
            active,
            std::string(
                "Cannot complete persistent rollback journal: ") +
                error.what());
    }

    return {
        RecoveryOutcome::rollback_completed,
        state.operation,
        active.transaction_id,
    };
}

bool RecoveryCoordinator::global_unknown_present() {
    try {
        RestoreJournal global(layout_.state_root);
        return global.unknown_present();
    } catch (const std::exception& error) {
        throw RecoveryCoordinatorError(
            RecoveryErrorKind::global_marker_failure,
            std::string(
                "Cannot inspect global recovery state: ") +
                error.what());
    }
}

const RecoveryCoordinatorLayout&
RecoveryCoordinator::layout() const noexcept {
    return layout_;
}

} // namespace keen_pbr3::backup
