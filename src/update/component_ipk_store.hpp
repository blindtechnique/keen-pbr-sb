#pragma once

#include "component_feed_index.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Three slots hold exact IPKs for one external component:
//
//   current   - the installed version, byte-for-byte as the feed served it.
//               This is what an exact rollback reinstalls.
//   previous  - the version before the last promoted transaction.
//   candidate - a verified target that has not been installed yet.
//
// Each slot is three files: <slot>.ipk, <slot>.ipk.sha256 (one line, the
// same sidecar shape keen-pbr's own rescue store uses, so shell tooling can
// verify it) and <slot>.json, the manifest. The manifest is the commit
// point: a slot without one is absent no matter what else lies there, and a
// slot whose manifest disagrees with its bytes is corrupt, never usable.
enum class IpkSlot { current, previous, candidate };

const char* ipk_slot_name(IpkSlot slot) noexcept;

enum class IpkSlotState { absent, usable, corrupt };

const char* ipk_slot_state_name(IpkSlotState state) noexcept;

struct IpkSlotInspection {
    IpkSlotState state{IpkSlotState::absent};
    // Filled only when usable.
    std::optional<RetainedIpk> retained;
    // Why a slot is corrupt, for the operator; empty otherwise.
    std::string detail;
};

class ComponentIpkStore {
public:
    // `root` is the components directory; the store lives in <root>/<package>.
    // Nothing is touched until a mutating call needs the directory.
    ComponentIpkStore(std::filesystem::path root, std::string package);

    const std::filesystem::path& directory() const noexcept;
    const std::string& package() const noexcept;
    std::filesystem::path ipk_path(IpkSlot slot) const;

    // Read-only. Hashes the blob, so it costs one pass over the file.
    IpkSlotInspection inspect(IpkSlot slot) const;

    // Verifies `bytes` against `entry` (size and SHA-256) and publishes them
    // as the slot, replacing whatever it held. The manifest is written last,
    // so an interruption leaves the slot absent rather than half-claimed.
    // Throws std::runtime_error when the bytes are not what the feed named;
    // nothing is written in that case.
    RetainedIpk adopt(IpkSlot slot,
                      const std::string& bytes,
                      const FeedPackageEntry& entry);

    // candidate -> current, and current -> previous when current is usable.
    // Run after the candidate has been proven installed. Re-runnable: an
    // interrupted promotion is finished, not repeated, because each move is
    // guarded by what the slots currently hold.
    // Throws std::runtime_error when there is no usable candidate.
    void promote_candidate();

    // Removes the slot's files; absent is fine.
    void discard(IpkSlot slot);

    // A private scratch directory inside the store for downloads in flight.
    // Created on demand and emptied every time it is handed out.
    std::filesystem::path staging_directory();

private:
    std::filesystem::path manifest_path(IpkSlot slot) const;
    std::filesystem::path sidecar_path(IpkSlot slot) const;
    void ensure_private_directory();
    void move_slot(IpkSlot from, IpkSlot to);

    std::filesystem::path directory_;
    std::string package_;
};

} // namespace keen_pbr3
