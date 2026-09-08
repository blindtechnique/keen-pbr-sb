#pragma once

#include <filesystem>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct ComponentOpkgMetadataPaths {
    std::string package;
    std::filesystem::path status_file;
    std::filesystem::path info_directory;
    std::filesystem::path lock_file;
};

bool valid_component_opkg_metadata_paths(const ComponentOpkgMetadataPaths& paths);

// The shared status database is first; all other entries are finite, exact
// component-owned info names. Neither status-old nor any global temporary
// database belongs to this recovery operation.
std::vector<std::string> component_opkg_metadata_files(
    const ComponentOpkgMetadataPaths& paths);

struct ComponentOpkgStatusMergeResult {
    bool complete{false};
    std::string body;
    std::string error;
};

// Saved may be a full captured database, but only its exact installed package
// paragraph is restored. Every unrelated current byte is preserved. An absent
// current package paragraph may be appended to an otherwise valid database.
ComponentOpkgStatusMergeResult merge_component_opkg_status(
    const std::string& saved, const std::string& current,
    const std::string& package, const std::string& expected_version = {});

// Entware opkg uses a POSIX lockf/F_TLOCK lock, not flock. Hold this only for
// direct metadata reads/writes, never while spawning opkg. Its own native lock
// filename is shared: closing releases our lock; we must never unlink it.
class ComponentOpkgMetadataLock {
public:
    explicit ComponentOpkgMetadataLock(const std::filesystem::path& lock_file);
    ~ComponentOpkgMetadataLock();
    ComponentOpkgMetadataLock(const ComponentOpkgMetadataLock&) = delete;
    ComponentOpkgMetadataLock& operator=(const ComponentOpkgMetadataLock&) = delete;
    bool locked() const noexcept;
    const std::string& error() const noexcept { return error_; }

private:
    int descriptor_{-1};
    std::filesystem::path path_;
    std::string error_;
};

// Caller holds ComponentOpkgMetadataLock through this whole operation. Reads
// the current database late, merges only the saved component paragraph, and
// atomically publishes with CURRENT database ownership and permissions.
// Missing/unreadable current database is incomplete, not a license to copy
// the entire saved database over unrelated package state.
ComponentOpkgStatusMergeResult restore_component_opkg_status(
    const ComponentOpkgMetadataPaths& paths, const std::string& saved_status,
    const std::string& expected_version = {});

struct ComponentOpkgStatusPreparationResult {
    bool complete{false};
    bool changed{false};
    std::string error;
    // Lost foreign status-only flags cannot be verified by control/list evidence.
    bool shared_database_reconstructed{false};
};

struct ComponentOpkgStatusFileAttributes {
    std::uint32_t mode{0};
    std::uint32_t owner{0};
    std::uint32_t group{0};
};

// Caller holds ComponentOpkgMetadataLock and releases it before running opkg.
// A structurally healthy current database is left unchanged, even if optional
// saved metadata is unavailable. A damaged component paragraph is repaired
// only when its exact identity is intact and all unrelated paragraphs parse.
// Shared loss/damage may be reconstructed from a verified full capture: current
// healthy foreign records win, and missing records need matching live info.
// Unknown/newer foreign state is incomplete, never invented or silently omitted.
// A missing status file additionally requires verified saved mode/ownership.
ComponentOpkgStatusPreparationResult prepare_component_opkg_status_for_reinstall(
    const ComponentOpkgMetadataPaths& paths, const std::string& saved_status,
    const std::string& expected_version = {},
    std::optional<ComponentOpkgStatusFileAttributes> saved_attributes = std::nullopt);

} // namespace keen_pbr3
