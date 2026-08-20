#pragma once

#include "ndms_native_delete_wal.hpp"

#include <filesystem>
#include <optional>
#include <stdexcept>

#ifdef KEEN_PBR3_TESTING
#include <functional>
#endif

namespace keen_pbr3 {

inline constexpr char kNdmsNativeDeleteWalFilename[] =
    "native-panel-delete.wal";

enum class NdmsNativeDeleteWalLoadState : std::uint8_t {
    absent,
    valid,
    unsafe_store,
    unsafe_entry,
    too_large,
    corrupt_record,
    io_error,
};

struct NdmsNativeDeleteWalLoadResult final {
    NdmsNativeDeleteWalLoadState state{
        NdmsNativeDeleteWalLoadState::io_error};
    std::optional<NdmsNativeDeleteWalRecord> record;
};

// This three-way result is intentionally reusable by import admission and by
// startup ownership reconciliation. Only clean means that another native
// mutation may begin or an absent ownership claim may be retired.
enum class NdmsNativeDeleteWalReadiness : std::uint8_t {
    clean,
    unfinished,
    unsafe,
};

class NdmsNativeDeleteWalStoreError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class NdmsNativeDeleteWalStoreWriteError final
    : public NdmsNativeDeleteWalStoreError {
public:
    NdmsNativeDeleteWalStoreWriteError(
        std::string message,
        bool published);
    bool published() const noexcept;

private:
    bool published_{false};
};

#ifdef KEEN_PBR3_TESTING
enum class NdmsNativeDeleteWalStoreFaultStage : std::uint8_t {
    after_temporary_file_fsync,
    after_initial_link_before_temporary_unlink,
    after_replace_rename_before_directory_fsync,
    before_remove_inode_recheck,
    after_unlink_before_directory_fsync,
};

struct NdmsNativeDeleteWalStoreTestHooks final {
    bool allow_current_process_owner{false};
    bool force_portable_linkat{false};
    std::function<void(NdmsNativeDeleteWalStoreFaultStage)>
        fault_injector;
};
#endif

// Root-only, no-follow, fixed-name WAL. Initial publication uses portable
// linkat no-replace; updates rename only after an exact logical+inode recheck.
// A visible effect followed by a directory-fsync failure is reported through
// WriteError::published() and remains recoverable by exact reread.
class NdmsNativeDeleteWalStore final {
public:
    explicit NdmsNativeDeleteWalStore(
        std::filesystem::path state_directory);
#ifdef KEEN_PBR3_TESTING
    NdmsNativeDeleteWalStore(
        std::filesystem::path state_directory,
        NdmsNativeDeleteWalStoreTestHooks hooks);
#endif

    NdmsNativeDeleteWalLoadResult load() const noexcept;
    NdmsNativeDeleteWalReadiness readiness() const noexcept;

    // Returns false without changing the existing record when any unfinished
    // or unsafe delete state already occupies the single global slot.
    bool publish_prepared_exclusive(
        const NdmsNativeDeleteWalRecord& record);
    void publish(const NdmsNativeDeleteWalRecord& record);
    void remove_exact(const NdmsNativeDeleteWalRecord& expected);

    // Repairs only this store's own interrupted linkat/temporary residue.
    // Unknown names, metadata, links or live-owner temporaries remain unsafe.
    void sweep_orphaned_temporaries() noexcept;

    const std::filesystem::path& state_directory() const noexcept;

private:
    bool publish_impl(
        const NdmsNativeDeleteWalRecord& record,
        bool initial);

    std::filesystem::path state_directory_;
#ifdef KEEN_PBR3_TESTING
    NdmsNativeDeleteWalStoreTestHooks test_hooks_;
#endif
};

const char* ndms_native_delete_wal_load_state_name(
    NdmsNativeDeleteWalLoadState state) noexcept;
const char* ndms_native_delete_wal_readiness_name(
    NdmsNativeDeleteWalReadiness readiness) noexcept;

} // namespace keen_pbr3
