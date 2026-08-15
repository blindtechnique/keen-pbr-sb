#pragma once

#include "ndms_native_import_wal.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace keen_pbr3 {

// The durable claim that keen-pbr created a native interface.
//
// The WAL record dies with its transaction; ownership must not. After the
// transaction completes and its record is removed, this claim is the only
// thing that separates an interface keen-pbr may later delete or reconcile
// from one the operator created by hand - and deleting an operator's
// interface on a guess is the one mistake this whole pipeline exists to make
// impossible.
struct NdmsNativeOwnershipRecord {
    std::string interface_name;
    std::string transaction_id;
    std::string marker;
    NdmsNativeTunnelImportKind kind{
        NdmsNativeTunnelImportKind::wireguard};
    std::string target_full_revision;

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

// One file per interface under a root-only directory, written atomically and
// durably. Only managed-candidate identities are accepted anywhere: a claim
// over Wireguard0-4 or 99-126 is refused at publish, at read and at remove,
// so a corrupted store cannot even assert ownership of a protected slot.
class NdmsNativeOwnershipStore {
public:
    explicit NdmsNativeOwnershipStore(
        std::filesystem::path state_directory);

    // Durable publish-or-throw; returns the revision of what is now on disk.
    std::string publish(const NdmsNativeOwnershipRecord& record);

    NdmsNativeOwnershipReadResult read(
        const std::string& interface_name) const;

    // Removes only a claim whose current bytes parse to exactly `expected`.
    // False means the claim survived - because it differs, or because the
    // remove failed - and the caller must treat it as still standing.
    bool remove_exact(const NdmsNativeOwnershipRecord& expected);

    const std::filesystem::path& state_directory() const noexcept;

private:
    std::filesystem::path state_directory_;
};

const char* ndms_native_ownership_read_state_name(
    NdmsNativeOwnershipReadState state) noexcept;

} // namespace keen_pbr3
