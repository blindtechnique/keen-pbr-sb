#pragma once

#ifdef KEEN_PBR3_TESTING
#include <functional>
#endif
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class RestoreJournalPhase {
    prepared,
    files_committed,
    transports_ready,
    core_applied,
    nfqws_ready,
};

enum class RestoreJournalEffect {
    files,
    transport_manager,
    core,
    nfqws,
};

struct RestoreJournalEntry {
    std::string transaction_id;
    RestoreJournalPhase phase{RestoreJournalPhase::prepared};
    std::vector<RestoreJournalEffect> effects;
    std::uint64_t snapshot_size{0};
    std::string snapshot_sha256;

    bool operator==(const RestoreJournalEntry& other) const noexcept;
};

#ifdef KEEN_PBR3_TESTING
enum class RestoreJournalFaultStage {
    snapshot_write,
    snapshot_file_fsync,
    snapshot_rename,
    snapshot_directory_fsync,
    active_write,
    active_file_fsync,
    active_rename,
    active_directory_fsync,
    unknown_write,
    unknown_file_fsync,
    unknown_rename,
    unknown_directory_fsync,
    active_remove,
    active_remove_directory_fsync,
    rollback_gc_scan,
    rollback_gc_unlink,
    rollback_gc_directory_fsync,
};

struct RestoreJournalTestHooks {
    std::function<void(RestoreJournalFaultStage)> fault_injector;
};
#endif

// Crash journal for a restore operation.
//
// The rollback payload is opaque and immutable. Its filename is derived only
// from a validated transaction id, while active.json is the single durable
// commit marker. Removing active.json and fsyncing the private state directory
// is the restore transaction's commit point.
class RestoreJournal {
public:
    static constexpr std::uint64_t kMaxRollbackPayloadBytes =
        64ULL * 1024ULL * 1024ULL;

    explicit RestoreJournal(std::filesystem::path state_directory);
#ifdef KEEN_PBR3_TESTING
    RestoreJournal(std::filesystem::path state_directory,
                   RestoreJournalTestHooks hooks);
#endif

    // Starts a journal or returns the identical already-started transaction.
    // A transaction id is exactly 32 lowercase hexadecimal characters.
    RestoreJournalEntry begin(
        const std::string& transaction_id,
        const std::string& exact_rollback_payload,
        std::vector<RestoreJournalEffect> effects);

    // Returns and fully verifies the active marker and its exact rollback
    // payload. Corrupt or unsafe state is marked UNKNOWN and rejected.
    std::optional<RestoreJournalEntry> read_active();

    // Reads the exact rollback bytes after checking size and SHA-256.
    std::string read_rollback_payload(const RestoreJournalEntry& entry);

    // Advances by one phase. Repeating the current phase is idempotent;
    // skipping or moving backwards is rejected.
    RestoreJournalEntry advance_phase(const std::string& transaction_id,
                                      RestoreJournalPhase phase);

    // Durably removes active.json. Repeating commit after it succeeded is
    // idempotent. A restore touching nfqws must first reach nfqws_ready;
    // otherwise core_applied is terminal. After the durable commit point,
    // immutable rollback payloads are retained newest-first (at most three
    // files and 128 MiB total); retention failure never changes commit state.
    void commit(const std::string& transaction_id);

    // Completes a rollback after the caller has restored and verified the
    // exact rollback payload. Unlike commit(), this is valid from any phase
    // and does not pretend that forward-restore effects completed. The active
    // transaction and immutable rollback payload are verified before the
    // durable marker removal.
    void complete_rollback(const std::string& transaction_id);

    // UNKNOWN is a durable fail-closed marker. It must be cleared only by a
    // future explicit recovery flow after an operator has resolved the state.
    bool unknown_present();
    void mark_unknown();

    const std::filesystem::path& state_directory() const noexcept;

private:
    void remove_active_marker(const RestoreJournalEntry& active,
                              bool preserve_commit_receipt);

    std::filesystem::path state_directory_;
#ifdef KEEN_PBR3_TESTING
    RestoreJournalTestHooks test_hooks_;
#endif
};

const char* to_string(RestoreJournalPhase phase) noexcept;
const char* to_string(RestoreJournalEffect effect) noexcept;

} // namespace keen_pbr3
