#pragma once

#include "ndms_native_import_wal.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#ifdef KEEN_PBR3_TESTING
#include <functional>
#endif

namespace keen_pbr3 {

inline constexpr std::uint32_t kNdmsNativeOwnershipSchemaVersion = 3U;
// Only a deleted tombstone uses v4. Fresh/active claims remain byte-compatible
// v3 records; the delete transition upgrades atomically once the exact live
// kernel identity is known. Legacy v3 tombstones remain readable but are not
// eligible for metadata retirement because their kernel dependency binding
// cannot be reconstructed safely after the firmware row disappears.
inline constexpr std::uint32_t
    kNdmsNativeOwnershipTombstoneSchemaVersion = 4U;

enum class NdmsNativeOwnershipLifecycle : std::uint8_t {
    // The interface is known to exist in running configuration. No claim is
    // made that `system configuration save` persisted it to startup state.
    active_running_only,
    // A save was acknowledged, but Keenetic exposes no exact saved-state/CAS
    // proof. The interface remains active and panel-owned.
    active_save_acknowledged_unverified,
    // Exact delete and running absence were observed, then save was
    // acknowledged without saved-state proof. Identity and encrypted rollback
    // snapshot remain durable so a reboot resurrection is never foreign.
    deleted_save_acknowledged_unverified,
};

struct NdmsNativeOwnershipLifecycleEvidence final {
    std::string transaction_id;
    NdmsNativeObservationBinding observation_binding;
    std::string runtime_catalog_revision;
    std::uint64_t runtime_sequence{0U};
    std::string running_config_catalog_revision;
    std::uint64_t running_config_sequence{0U};
    // Present only on a v4 deleted tombstone. This is the exact kernel
    // identity observed and dependency-checked by the delete WAL before the
    // firmware row disappeared. It never crosses the bounded inspection
    // boundary; that boundary exposes only a derived capability bit.
    std::optional<std::string> deleted_kernel_interface_name;

    bool operator==(
        const NdmsNativeOwnershipLifecycleEvidence& other) const noexcept;
};

// The durable claim that keen-pbr created a native interface.
//
// The WAL record dies with its transaction; ownership must not. After the
// transaction completes and its record is removed, this claim is the only
// thing that separates an interface keen-pbr may later delete or reconcile
// from one the operator created by hand - and deleting an operator's
// interface on a guess is the one mistake this whole pipeline exists to make
// impossible.
struct NdmsNativeOwnershipRecord {
    std::uint32_t schema_version{kNdmsNativeOwnershipSchemaVersion};
    std::string interface_name;
    std::string transaction_id;
    std::string marker;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    std::string snapshot_revision;
    std::string target_full_revision;
    NdmsNativeOwnershipLifecycle lifecycle{
        NdmsNativeOwnershipLifecycle::active_running_only};
    std::optional<NdmsNativeOwnershipLifecycleEvidence>
        lifecycle_evidence;

    bool operator==(const NdmsNativeOwnershipRecord& other) const noexcept;
};

// Domain-separated digest over every field. This is the value the WAL record
// carries as ownership_revision and the observation builder compares against:
// the claim and its digest come from one serialization, so they cannot drift
// apart.
std::string ndms_native_ownership_revision(
    const NdmsNativeOwnershipRecord& record);

enum class NdmsNativeOwnershipReadState {
    absent,
    valid,
    // Present and not parseable, or failing any field check. Never collapsed
    // into absent: a torn claim is evidence that a publish was interrupted,
    // and "no claim" is exactly the reading that must not come from a torn
    // one.
    unreadable,
};

struct NdmsNativeOwnershipReadResult {
    NdmsNativeOwnershipReadState state{
        NdmsNativeOwnershipReadState::unreadable};
    std::optional<NdmsNativeOwnershipRecord> record;
    std::optional<std::string> revision;
};

// Redacted claim metadata for status surfaces.  The full ownership record
// also binds the import marker, encrypted-snapshot revision and exact target
// revision; none of those values are needed by an inventory card and they
// deliberately do not cross this boundary.
struct NdmsNativeOwnershipInspectionItem final {
    std::string interface_name;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    NdmsNativeOwnershipLifecycle lifecycle{
        NdmsNativeOwnershipLifecycle::active_running_only};
    std::string ownership_revision;
    // True only for a validated v4 deleted tombstone carrying a safe retained
    // kernel identity. The identity itself is deliberately not exposed.
    bool retained_deletion_forget_capable{false};

    bool operator==(
        const NdmsNativeOwnershipInspectionItem& other) const noexcept;
};

struct NdmsNativeOwnershipInspection final {
    // False means the complete bounded directory could not be attributed.
    // Callers must not treat an empty `claims` vector as absence in that
    // state.
    bool readable{false};
    std::vector<NdmsNativeOwnershipInspectionItem> claims;
};

#ifdef KEEN_PBR3_TESTING
enum class NdmsNativeOwnershipStoreFaultStage {
    pre_publish_after_file_fsync,
    post_rename_directory_fsync,
    post_link_before_unlink,
    before_remove_inode_recheck,
    post_unlink_directory_fsync,
    absence_directory_fsync,
};

struct NdmsNativeOwnershipStoreTestHooks {
    std::function<void(NdmsNativeOwnershipStoreFaultStage)> fault_injector;
    bool allow_current_process_owner{false};
    bool force_portable_linkat{false};
};
#endif

// One file per interface under a root-only directory, written atomically and
// durably. Only managed-candidate identities are accepted anywhere: a claim
// over Wireguard0-4 or 99-126 is refused at publish, at read and at remove,
// so a corrupted store cannot even assert ownership of a protected slot.
class NdmsNativeOwnershipStore {
public:
    explicit NdmsNativeOwnershipStore(
        std::filesystem::path state_directory);
#ifdef KEEN_PBR3_TESTING
    NdmsNativeOwnershipStore(
        std::filesystem::path state_directory,
        NdmsNativeOwnershipStoreTestHooks hooks);
#endif

    // Durable publish-or-throw; returns the revision of what is now on disk.
    std::string publish(const NdmsNativeOwnershipRecord& record);

    // Atomically replaces one byte-exact claim with its validated successor.
    // There is no unlink window: a fsynced temporary is renamed over the
    // expected inode and then the directory is fsynced. Identity, kind and
    // snapshot binding and target evidence are immutable. The lifecycle may
    // only advance running -> save-ack or active -> deleted tombstone and can
    // never move backwards; within one lifecycle only byte-identical retry is
    // accepted.
    // A retry after a post-rename durability fault is idempotent. Nullopt
    // means the exact predecessor was not current or the transition failed.
    std::optional<std::string> replace_exact(
        const NdmsNativeOwnershipRecord& expected,
        const NdmsNativeOwnershipRecord& replacement);

    NdmsNativeOwnershipReadResult read(
        const std::string& interface_name) const;

    // Strictly read-only, bounded inventory for status projection.  Unlike
    // read() and list_claimed_interfaces(), this method never sweeps orphaned
    // temporaries or fsyncs anything.  Any temporary, unexpected name,
    // unsafe metadata, invalid record or directory larger than 128 entries
    // makes the whole result unreadable; no partial claim set is returned.
    NdmsNativeOwnershipInspection inspect_bounded_read_only() const;

    // Removes only a claim whose current bytes parse to exactly `expected`.
    // False means the claim survived - because it differs, or because the
    // remove failed - and the caller must treat it as still standing.
    bool remove_exact(const NdmsNativeOwnershipRecord& expected);

    // Dedicated metadata-retirement CAS. It accepts only the exact opaque
    // revision of a validated v4 deleted tombstone carrying its retained
    // kernel identity. Active claims and legacy v3 tombstones are never
    // removable through this path. False is deliberately ambiguous: callers
    // must reread and establish durable absence before reporting success.
    bool remove_v4_tombstone_exact(
        const std::string& interface_name,
        const std::string& expected_ownership_revision);

    // Establishes and rechecks the parent-directory durability boundary for
    // exact absence after a visible unlink whose fsync may have failed.
    bool ensure_absence_durable(const std::string& interface_name);

    // Every interface name this store currently holds a file for, sorted.
    // Any unexpected name (including a protected slot) makes the whole
    // inventory unreadable: reconciliation must not proceed from a directory
    // it cannot attribute completely to this store.
    //
    // Reading a claim can still fail per name - this only says which names
    // exist. An unreadable directory yields nothing, which callers must not
    // read as "no claims": use the returned flag.
    struct Listing {
        bool readable{false};
        std::vector<std::string> interface_names;
    };
    Listing list_claimed_interfaces() const;

    const std::filesystem::path& state_directory() const noexcept;

private:
    std::filesystem::path state_directory_;
#ifdef KEEN_PBR3_TESTING
    NdmsNativeOwnershipStoreTestHooks test_hooks_;
#endif
};

const char* ndms_native_ownership_read_state_name(
    NdmsNativeOwnershipReadState state) noexcept;
const char* ndms_native_ownership_lifecycle_name(
    NdmsNativeOwnershipLifecycle lifecycle) noexcept;
bool ndms_native_ownership_is_active(
    const NdmsNativeOwnershipRecord& record) noexcept;
bool ndms_native_ownership_is_delete_tombstone(
    const NdmsNativeOwnershipRecord& record) noexcept;

} // namespace keen_pbr3
