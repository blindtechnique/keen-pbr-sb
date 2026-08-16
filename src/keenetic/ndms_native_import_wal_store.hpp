#pragma once

#include "ndms_native_import_wal.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef KEEN_PBR3_TESTING
#include <functional>
#endif

namespace keen_pbr3 {

// A directory is deliberately small enough that recovery can inventory it
// without attacker-controlled, unbounded allocation. One record is at most
// kNdmsNativeImportWalMaximumBytes; only the strict WAL codec can create one.
constexpr std::size_t kNdmsNativeImportWalStoreMaximumRecords = 64U;
constexpr std::size_t kNdmsNativeImportWalStoreMaximumDirectoryEntries =
    128U;

enum class NdmsNativeImportWalLoadState {
    absent,
    valid,
    unsafe_store,
    unsafe_entry,
    too_large,
    corrupt_record,
    identity_mismatch,
    io_error,
};

struct NdmsNativeImportWalLoadResult {
    NdmsNativeImportWalLoadState state{
        NdmsNativeImportWalLoadState::io_error};
    std::optional<NdmsNativeImportWalRecord> record;

    bool recovery_permitted() const noexcept {
        return state == NdmsNativeImportWalLoadState::valid &&
               record.has_value();
    }
};

enum class NdmsNativeImportWalInventoryState {
    ready,
    absent,
    unsafe_store,
    io_error,
    busy,
    directory_limit_exceeded,
    record_limit_exceeded,
};

struct NdmsNativeImportWalInventoryItem {
    // Exact basename, never file contents. Unknown names are retained in the
    // sorted inventory so recovery cannot silently ignore foreign state.
    std::string filename;
    std::optional<std::string> transaction_id;
    NdmsNativeImportWalLoadState state{
        NdmsNativeImportWalLoadState::unsafe_entry};
    std::optional<NdmsNativeImportWalRecord> record;
};

struct NdmsNativeImportWalInventory {
    NdmsNativeImportWalInventoryState state{
        NdmsNativeImportWalInventoryState::io_error};
    std::vector<NdmsNativeImportWalInventoryItem> items;

    // Recovery is authorized only for a complete, bounded inventory whose
    // every entry passed metadata, identity, schema and integrity checks.
    bool recovery_permitted() const noexcept;
};

enum class NdmsNativeImportWalAdmissionState {
    admitted,
    unfinished_transaction_present,
};

class NdmsNativeImportWalStoreError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class NdmsNativeImportWalStoreWriteError final
    : public NdmsNativeImportWalStoreError {
public:
    NdmsNativeImportWalStoreWriteError(std::string message,
                                       bool published);

    // True once rename(2) made a new record visible, or unlinkat(2) removed
    // one. A later directory-fsync failure is never reported as "not done".
    bool published() const noexcept;

private:
    bool published_{false};
};

#ifdef KEEN_PBR3_TESTING
enum class NdmsNativeImportWalStoreFaultStage {
    write,
    file_fsync,
    rename,
    directory_fsync,
    remove,
    remove_directory_fsync,
};

struct NdmsNativeImportWalStoreTestHooks {
    std::function<void(NdmsNativeImportWalStoreFaultStage)> fault_injector;

    // Production always requires euid=uid=gid=0, directory 0700 and files
    // 0600. Unit tests may exercise the same owner-only contract as their
    // unprivileged runner without weakening the production constructor.
    bool allow_current_process_owner{false};
};
#endif

// Durable, non-secret storage only. This class deliberately performs no NDMS
// calls, no import replay, no API registration and no startup recovery. A
// future executor must consume only recovery_permitted() records and then use
// classify_ndms_native_import_recovery() for mutation admission.
class NdmsNativeImportWalStore {
public:
    explicit NdmsNativeImportWalStore(
        std::filesystem::path state_directory);
#ifdef KEEN_PBR3_TESTING
    NdmsNativeImportWalStore(
        std::filesystem::path state_directory,
        NdmsNativeImportWalStoreTestHooks hooks);
#endif

    // Advances an existing validated record with temp-write, file fsync,
    // rename and directory fsync. It never creates a transaction; creation is
    // available only through publish_prepared_exclusive().
    void publish(const NdmsNativeImportWalRecord& record);

    // Starts a new transaction only when the complete bounded store inventory
    // is safe and empty. The emptiness check and prepared-record publication
    // run under the same process mutex and directory flock, so overlapping
    // daemon instances cannot dispatch a second import while any earlier
    // transaction still needs recovery.
    NdmsNativeImportWalAdmissionState publish_prepared_exclusive(
        const NdmsNativeImportWalRecord& record);

    // No corruption is collapsed into "absent". The result carries a record
    // only after exact metadata, bounded read, schema and identity validation.
    NdmsNativeImportWalLoadResult load(
        const std::string& transaction_id) const;

    // Names and results are lexicographically sorted. Unknown objects are
    // explicit unsafe entries; excessive directories return a bounded top-
    // level state with no partial inventory.
    NdmsNativeImportWalInventory inventory() const;

    // Startup-safe form with the same metadata and content validation. Lock
    // order remains store mutex -> exact opened directory -> flock, but the
    // shared flock is non-blocking and reports busy instead of waiting for an
    // overlapping writer. No partial inventory is returned on contention.
    NdmsNativeImportWalInventory try_inventory() const;

    // Removes only the byte-for-byte logical record the caller already
    // verified. This is a storage primitive, not permission to finish a
    // transaction; the future executor owns that policy decision.
    void remove_exact(const NdmsNativeImportWalRecord& expected);

    // Removes this store's own temporaries left behind by a process that died
    // between creating one and renaming it into place. Publishing already does
    // this, but a read cannot: an orphan makes every inventory unsafe, so
    // recovery refuses with inventory_not_ready and no write is ever attempted
    // that could clean up. Call it once at startup, before the first recovery
    // scan, or a crash inside publish leaves the feature permanently refusing
    // with only a manual rm on the router as the remedy.
    //
    // Best effort and never throws. Only our own prefix, only a dead owner,
    // only the exact shape the writer creates; anything else is left alone.
    void sweep_orphaned_temporaries() noexcept;

    const std::filesystem::path& state_directory() const noexcept;

private:
    NdmsNativeImportWalAdmissionState publish_impl(
        const NdmsNativeImportWalRecord& record,
        bool require_empty_store,
        bool allow_new_record);

    std::filesystem::path state_directory_;
#ifdef KEEN_PBR3_TESTING
    NdmsNativeImportWalStoreTestHooks test_hooks_;
#endif
};

const char* ndms_native_import_wal_load_state_name(
    NdmsNativeImportWalLoadState state) noexcept;

const char* ndms_native_import_wal_inventory_state_name(
    NdmsNativeImportWalInventoryState state) noexcept;

} // namespace keen_pbr3
