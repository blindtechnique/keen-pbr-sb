#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Encrypted-at-rest storage for the one thing the firmware cannot give back:
// a native interface's private key. Measured on NC-1812 - no read endpoint
// returns it - so edit and delete stay blocked until a failed mutation can be
// rolled back from a snapshot taken while the key was still in hand.
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
    NdmsNativeSecretReadState state{
        NdmsNativeSecretReadState::unreadable};
    std::optional<std::string> secret;
};

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

    // Durable seal-or-throw. The identity triple is authenticated data: a
    // snapshot copied onto another interface's name, or replayed for another
    // transaction, does not decrypt.
    void publish(const std::string& interface_name,
                 const std::string& transaction_id,
                 const std::string& marker,
                 const std::string& secret);

    NdmsNativeSecretReadResult read(const std::string& interface_name,
                                    const std::string& transaction_id,
                                    const std::string& marker) const;

    // Removes the snapshot only when it currently decrypts under exactly this
    // identity. False means it survived, and the caller must treat the secret
    // as still on disk.
    bool remove_exact(const std::string& interface_name,
                      const std::string& transaction_id,
                      const std::string& marker);

private:
    std::filesystem::path key_path_;
    std::filesystem::path state_directory_;
};

const char* ndms_native_secret_read_state_name(
    NdmsNativeSecretReadState state) noexcept;

} // namespace keen_pbr3
