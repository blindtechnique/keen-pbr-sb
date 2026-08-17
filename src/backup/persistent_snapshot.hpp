#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <vector>

namespace keen_pbr3 {

enum class AtomicFileWriteStage;

namespace backup {

inline constexpr std::size_t kMaxSnapshotBytes =
    16U * 1024U * 1024U;
inline constexpr std::size_t kMaxManagedFileBytes =
    2U * 1024U * 1024U;
inline constexpr std::size_t kMaxManagedFiles = 512U;
inline constexpr std::size_t kMaxSnapshotEntries =
    kMaxManagedFiles + 2U;
inline constexpr const char* kPersistentSnapshotFormat =
    "keen-pbr-sb-rollback";
inline constexpr int kPersistentSnapshotSchema = 1;

enum class PersistentSnapshotErrorKind {
    invalid_document,
    limit_exceeded,
    unsafe_local_state,
    io_failure,
    internal,
};

class PersistentSnapshotError final : public std::runtime_error {
public:
    PersistentSnapshotError(
        PersistentSnapshotErrorKind kind,
        std::string message);

    PersistentSnapshotErrorKind kind() const noexcept;

private:
    PersistentSnapshotErrorKind kind_;
};

enum class NfqwsFileGroup {
    config,
    lists,
};

struct NfqwsSelection {
    bool config{false};
    bool lists{false};

    bool includes(NfqwsFileGroup group) const noexcept;
    bool any() const noexcept;
};

std::optional<NfqwsFileGroup> classify_nfqws_path(
    const std::filesystem::path& relative);

enum class PersistentTargetKind {
    config,
    transports,
    nfqws_config,
    nfqws_lists,
};

const char* persistent_scope_for_kind(
    PersistentTargetKind kind);

struct PersistentLayout {
    std::filesystem::path config;
    std::filesystem::path transports;
    std::filesystem::path nfqws{"/opt/etc/nfqws2"};
    std::filesystem::path strategies{
        "/opt/etc/keen-pbr/nfqws-strategies"};
};

struct ResolvedPersistentTarget {
    std::filesystem::path path;
    std::optional<std::filesystem::path> confinement_root;
    PersistentTargetKind kind;
};

PersistentTargetKind classify_persistent_target(
    const std::string& target);
ResolvedPersistentTarget resolve_persistent_target(
    const PersistentLayout& layout,
    const std::string& target);
std::string logical_target_for_path(
    const PersistentLayout& layout,
    const std::filesystem::path& path);

void validate_confined_target(
    const std::filesystem::path& root,
    const std::filesystem::path& target);

struct SnapshotBudget {
    std::size_t entries{0};
    std::size_t content_bytes{0};

    void reserve_entry();
    void ensure_content_fits(
        std::size_t bytes,
        std::size_t per_file_limit) const;
    void add_content(
        std::size_t bytes,
        std::size_t per_file_limit);
};

struct FileReplacement {
    std::filesystem::path path;
    std::string content;
    bool ensure_world_readable{false};
    std::optional<std::filesystem::path> confinement_root;
    std::optional<mode_t> mode_override;
    mode_t created_directory_mode{0755};
    bool remove{false};
    std::optional<uid_t> owner_override;
    std::optional<gid_t> group_override;
    // Callers must choose the policy explicitly: core snapshot files and
    // managed nfqws files intentionally have different limits.
    std::size_t max_content_bytes{0};
};

struct FileSnapshot {
    std::filesystem::path path;
    std::optional<std::filesystem::path> confinement_root;
    bool existed{false};
    std::string content;
    mode_t mode{0600};
    uid_t owner{0};
    gid_t group{0};
};

struct FileCaptureHooks {
    std::function<void(
        const std::filesystem::path&)> after_open;
};

FileSnapshot capture_file(
    const std::filesystem::path& path,
    const std::optional<std::filesystem::path>& confinement_root,
    std::size_t max_content_bytes,
    SnapshotBudget* budget = nullptr,
    const FileCaptureHooks* hooks = nullptr);

struct PersistentRollbackEntry {
    std::string target;
    bool existed{false};
    std::string content;
    mode_t mode{0600};
    uid_t owner{0};
    gid_t group{0};
};

struct PersistentRollbackSnapshot {
    std::vector<PersistentRollbackEntry> entries;
    std::set<std::string> scopes;
};

struct FileMutation {
    std::string target;
    PersistentTargetKind kind;
    FileReplacement replacement;
    FileSnapshot before;
};

using FileMutationPlan = std::vector<FileMutation>;

FileMutationPlan snapshot_replacements(
    const PersistentLayout& layout,
    std::vector<FileReplacement> replacements);

nlohmann::json make_persistent_snapshot(
    std::vector<std::pair<std::string, FileSnapshot>> snapshots,
    std::set<std::string> scopes = {});
PersistentRollbackSnapshot parse_persistent_snapshot(
    const nlohmann::json& document);
nlohmann::json make_operation_snapshot(
    const FileMutationPlan& mutations);
nlohmann::json make_full_snapshot(
    const PersistentLayout& layout);
FileMutationPlan prepare_persistent_restore(
    const PersistentLayout& layout,
    const nlohmann::json& document);

std::vector<std::string> current_nfqws_targets(
    const PersistentLayout& layout,
    const NfqwsSelection& selection);

struct FileApplyHooks {
    std::function<void(
        const std::filesystem::path&,
        AtomicFileWriteStage)> atomic_write_fault;
    std::function<void(
        std::size_t,
        const std::filesystem::path&)> before_forward_write;
    std::function<void(
        std::size_t,
        const std::filesystem::path&)> before_rollback_write;
};

class FileMutationTransaction {
public:
    FileMutationTransaction(
        const FileMutationPlan& mutations,
        FileApplyHooks hooks = {});

    void apply();
    std::vector<std::string> rollback();
    bool has_committed_changes() const noexcept;

private:
    const FileMutationPlan& mutations_;
    FileApplyHooks hooks_;
    std::vector<std::size_t> committed_indices_;
};

std::string save_snapshot(
    const nlohmann::json& snapshot,
    const std::filesystem::path& path,
    const FileApplyHooks& hooks = {});
nlohmann::json load_snapshot(
    const std::filesystem::path& path);

} // namespace backup
} // namespace keen_pbr3
