#pragma once

#include "ndms_native_panel_delete_snapshot.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#ifdef KEEN_PBR3_TESTING
#include <functional>
#endif

namespace keen_pbr3 {

// Encrypted-at-rest storage for secret rollback material the firmware cannot
// give back. The legacy raw API can retain a private key, but that is never
// enough to authorize panel deletion. The typed panel-delete API below seals
// a complete canonical WG/AWG configuration, including every PSK and every
// present optional ASC field, and validates/decrypts it again before mutation
// admission.
//
// What the encryption is for, stated honestly: /opt is a removable USB drive
// that gets pulled, imaged and backed up, and the master key necessarily
// lives on the same device, because this router has no hardware keystore.
// This protects keys from leaking through copies, exports and casual reads;
// it does not protect against an attacker who already has root and both
// files. That boundary is the owner's accepted trade-off, not an oversight.
enum class NdmsNativeSecretReadState {
    absent,
    valid,
    // Present and not decryptable: torn, tampered, rebound to another
    // identity, or sealed under a key that no longer exists. Never collapsed
    // into absent - "no snapshot" is the reading that authorizes a mutation
    // to proceed without one, and it must not come from damage.
    unreadable,
};

struct NdmsNativeSecretReadResult {
    NdmsNativeSecretReadResult() = default;
    ~NdmsNativeSecretReadResult() noexcept;
    NdmsNativeSecretReadResult(
        const NdmsNativeSecretReadResult&) = delete;
    NdmsNativeSecretReadResult& operator=(
        const NdmsNativeSecretReadResult&) = delete;
    NdmsNativeSecretReadResult(
        NdmsNativeSecretReadResult&& other) noexcept;
    NdmsNativeSecretReadResult& operator=(
        NdmsNativeSecretReadResult&& other) noexcept;

    NdmsNativeSecretReadState state{
        NdmsNativeSecretReadState::unreadable};
    std::optional<std::string> secret;
};

#ifdef KEEN_PBR3_TESTING
void reset_ndms_native_secret_result_wipe_count_for_testing() noexcept;
std::size_t ndms_native_secret_result_wipe_count_for_testing() noexcept;
#endif

struct NdmsNativePanelDeleteSnapshotReadResult {
    NdmsNativeSecretReadState state{
        NdmsNativeSecretReadState::unreadable};
    std::optional<NdmsNativePanelDeleteSnapshot> snapshot;
};

#ifdef KEEN_PBR3_TESTING
enum class NdmsNativeSecretSnapshotStoreFaultStage {
    pre_publish_after_file_fsync,
    post_rename_directory_fsync,
    post_link_before_unlink,
    before_remove_content_recheck,
    post_unlink_directory_fsync,
    absence_directory_fsync,
};

struct NdmsNativeSecretSnapshotStoreTestHooks {
    std::function<void(NdmsNativeSecretSnapshotStoreFaultStage)>
        fault_injector;
    bool allow_current_process_owner{false};
    bool force_portable_linkat{false};
};
#endif

class NdmsNativeSecretSnapshotStore {
public:
    // The master key file and the snapshot directory are separate paths on
    // purpose, so backup tooling can be taught to exclude the key without
    // excluding the snapshots (or the reverse). The key is created on first
    // publish from the kernel CSPRNG; an existing key that fails validation
    // is NEVER silently regenerated, because a regenerated key orphans every
    // snapshot sealed under the old one - that failure must reach a human.
    NdmsNativeSecretSnapshotStore(std::filesystem::path key_path,
                                  std::filesystem::path state_directory);
#ifdef KEEN_PBR3_TESTING
    NdmsNativeSecretSnapshotStore(
        std::filesystem::path key_path,
        std::filesystem::path state_directory,
        NdmsNativeSecretSnapshotStoreTestHooks hooks);
#endif

    // Durable seal-or-throw. The identity triple is authenticated data: a
    // snapshot copied onto another interface's name, or replayed for another
    // transaction, does not decrypt.
    void publish(const std::string& interface_name,
                 const std::string& transaction_id,
                 const std::string& marker,
                 const std::string& secret);

    // The only snapshot form sufficient for panel delete admission. The
    // move-only payload is encrypted without first copying its plaintext into
    // a generic std::string at this boundary.
    void publish_panel_delete_snapshot(
        const std::string& interface_name,
        const std::string& transaction_id,
        const std::string& marker,
        NdmsNativePanelDeleteSnapshot snapshot);

    NdmsNativeSecretReadResult read(const std::string& interface_name,
                                    const std::string& transaction_id,
                                    const std::string& marker) const;

    NdmsNativePanelDeleteSnapshotReadResult
    read_panel_delete_snapshot(
        const std::string& interface_name,
        const std::string& transaction_id,
        const std::string& marker) const;

    // Removes the snapshot only when it currently decrypts under exactly this
    // identity. False means it survived, and the caller must treat the secret
    // as still on disk.
    bool remove_panel_delete_snapshot_exact(
        const std::string& interface_name,
        const std::string& transaction_id,
        const std::string& marker,
        const std::string& expected_canonical_revision);

    // Re-fsyncs the exact state directory and rechecks that no snapshot for
    // this managed target exists. Used after an earlier unlink became visible
    // but did not cross the directory durability boundary.
    bool ensure_absence_durable(const std::string& interface_name);

private:
    void publish_payload(const std::string& interface_name,
                         const std::string& transaction_id,
                         const std::string& marker,
                         std::string_view payload);

    std::filesystem::path key_path_;
    std::filesystem::path state_directory_;
#ifdef KEEN_PBR3_TESTING
    NdmsNativeSecretSnapshotStoreTestHooks test_hooks_;
#endif
};

const char* ndms_native_secret_read_state_name(
    NdmsNativeSecretReadState state) noexcept;

} // namespace keen_pbr3
