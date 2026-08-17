#include "persistent_snapshot.hpp"

#include "../config/config.hpp"
#include "../config/config_writer.hpp"
#include "../crypto/sha256.hpp"
#include "../util/base64.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <iterator>
#include <limits>
#include <nlohmann/json.hpp>
#include <system_error>
#include <utility>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3::backup {
namespace {

namespace fs = std::filesystem;

constexpr const char* kBase64Encoding = "base64";

[[noreturn]] void fail(
    PersistentSnapshotErrorKind kind,
    std::string message) {
    throw PersistentSnapshotError(kind, std::move(message));
}

void reject_nul_path(
    const std::string& value,
    const char* error_message) {
    if (value.find('\0') != std::string::npos) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            error_message);
    }
}

bool unsafe_relative_path(const fs::path& path) {
    return path.empty() || path.is_absolute() ||
           std::any_of(
               path.begin(),
               path.end(),
               [](const fs::path& component) {
                   return component == ".." || component == ".";
               });
}

bool has_unsafe_path_component(const fs::path& path) {
    return std::any_of(
        path.begin(),
        path.end(),
        [](const fs::path& component) {
            return component == ".." || component == ".";
        });
}

class UniqueFd {
public:
    explicit UniqueFd(int descriptor = -1) noexcept
        : descriptor_(descriptor) {}

    ~UniqueFd() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept
        : descriptor_(std::exchange(other.descriptor_, -1)) {}

    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this == &other) {
            return *this;
        }
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
        descriptor_ = std::exchange(other.descriptor_, -1);
        return *this;
    }

    int get() const noexcept {
        return descriptor_;
    }

private:
    int descriptor_;
};

struct CapturedRegularFile {
    bool existed{false};
    std::string content;
    struct stat metadata {};
};

bool unsafe_open_errno(int error) noexcept {
    return error == ELOOP || error == ENOTDIR;
}

[[noreturn]] void fail_open_path(
    const fs::path& path,
    int error,
    const char* operation) {
    if (unsafe_open_errno(error)) {
        fail(
            PersistentSnapshotErrorKind::unsafe_local_state,
            std::string(operation) +
                " contains a symbolic link or non-directory: " +
                path.string());
    }
    fail(
        PersistentSnapshotErrorKind::io_failure,
        std::string("cannot ") + operation + " " +
            path.string() + ": " +
            std::generic_category().message(error));
}

UniqueFd open_directory_no_follow(
    const fs::path& path,
    bool* missing) {
    if (missing != nullptr) {
        *missing = false;
    }
    const auto normalized = path.lexically_normal();
    const auto serialized = normalized.string();
    if (normalized.empty() ||
        serialized.find('\0') != std::string::npos ||
        (normalized != "." &&
         has_unsafe_path_component(normalized))) {
        fail(
            PersistentSnapshotErrorKind::unsafe_local_state,
            "snapshot source parent path is unsafe: " +
                path.string());
    }

    UniqueFd current(::open(
        normalized.is_absolute() ? "/" : ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (current.get() < 0) {
        fail_open_path(path, errno, "open snapshot source parent");
    }

    const auto components = normalized.is_absolute()
                                ? normalized.relative_path()
                                : normalized;
    for (const auto& component : components) {
        if (component.empty() || component == ".") {
            continue;
        }
        const int next = ::openat(
            current.get(),
            component.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0) {
            const int saved_errno = errno;
            if (saved_errno == ENOENT && missing != nullptr) {
                *missing = true;
                return UniqueFd();
            }
            fail_open_path(
                path, saved_errno,
                "open snapshot source parent");
        }
        current = UniqueFd(next);
    }
    return current;
}

bool same_timestamp(
    const struct timespec& left,
    const struct timespec& right) noexcept {
    return left.tv_sec == right.tv_sec &&
           left.tv_nsec == right.tv_nsec;
}

bool stable_snapshot_metadata(
    const struct stat& before,
    const struct stat& after) noexcept {
    return before.st_dev == after.st_dev &&
           before.st_ino == after.st_ino &&
           before.st_size == after.st_size &&
           before.st_mode == after.st_mode &&
           before.st_uid == after.st_uid &&
           before.st_gid == after.st_gid &&
           same_timestamp(before.st_mtim, after.st_mtim) &&
           same_timestamp(before.st_ctim, after.st_ctim);
}

CapturedRegularFile capture_regular_file(
    const fs::path& path,
    const std::optional<fs::path>& confinement_root,
    std::size_t max_content_bytes,
    PersistentSnapshotErrorKind missing_kind,
    const char* missing_message,
    const FileCaptureHooks* hooks = nullptr) {
    const auto normalized = path.lexically_normal();
    const auto filename = normalized.filename();
    if (normalized.empty() || filename.empty() ||
        filename == "." || filename == ".." ||
        normalized.string().find('\0') !=
            std::string::npos) {
        fail(
            PersistentSnapshotErrorKind::unsafe_local_state,
            "snapshot source path is unsafe: " +
                path.string());
    }

    fs::path parent;
    if (confinement_root.has_value()) {
        const auto normalized_root =
            confinement_root->lexically_normal();
        const auto relative =
            normalized.lexically_relative(normalized_root);
        if (unsafe_relative_path(relative)) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                "snapshot source escapes its confinement root");
        }
        parent = normalized_root / relative.parent_path();
    } else {
        parent = normalized.parent_path();
        if (parent.empty()) {
            parent = ".";
        }
    }

    bool parent_missing = false;
    auto directory =
        open_directory_no_follow(parent, &parent_missing);
    if (parent_missing) {
        return {};
    }

    const int descriptor = ::openat(
        directory.get(),
        filename.c_str(),
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        const int saved_errno = errno;
        if (saved_errno == ENOENT) {
            return {};
        }
        if (unsafe_open_errno(saved_errno)) {
            fail(
                PersistentSnapshotErrorKind::unsafe_local_state,
                "snapshot source is not a regular file: " +
                    path.string());
        }
        fail(
            missing_kind,
            std::string(missing_message) + ": " +
                std::generic_category().message(saved_errno));
    }
    UniqueFd source(descriptor);

    CapturedRegularFile result;
    if (::fstat(source.get(), &result.metadata) != 0) {
        fail(
            PersistentSnapshotErrorKind::io_failure,
            "cannot inspect opened snapshot source: " +
                path.string());
    }
    if (!S_ISREG(result.metadata.st_mode)) {
        fail(
            PersistentSnapshotErrorKind::unsafe_local_state,
            "snapshot source is not a regular file: " +
                path.string());
    }
    if (result.metadata.st_size < 0 ||
        static_cast<std::uintmax_t>(
            result.metadata.st_size) >
            static_cast<std::uintmax_t>(
                max_content_bytes)) {
        fail(
            PersistentSnapshotErrorKind::limit_exceeded,
            "snapshot source file is too large");
    }

    if (hooks != nullptr && hooks->after_open) {
        hooks->after_open(path);
    }

    result.content.reserve(
        static_cast<std::size_t>(result.metadata.st_size));
    char buffer[8192];
    for (;;) {
        const auto bytes_read =
            ::read(source.get(), buffer, sizeof(buffer));
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            fail(
                PersistentSnapshotErrorKind::io_failure,
                "cannot read snapshot source: " +
                    path.string());
        }
        if (bytes_read == 0) {
            break;
        }
        const auto chunk =
            static_cast<std::size_t>(bytes_read);
        if (chunk > max_content_bytes -
                        result.content.size()) {
            fail(
                PersistentSnapshotErrorKind::limit_exceeded,
                "snapshot source file is too large");
        }
        result.content.append(buffer, chunk);
    }

    struct stat after {};
    if (::fstat(source.get(), &after) != 0) {
        fail(
            PersistentSnapshotErrorKind::io_failure,
            "cannot re-inspect opened snapshot source: " +
                path.string());
    }
    struct stat path_after {};
    if (::fstatat(
            directory.get(),
            filename.c_str(),
            &path_after,
            AT_SYMLINK_NOFOLLOW) != 0) {
        fail(
            errno == ENOENT
                ? PersistentSnapshotErrorKind::unsafe_local_state
                : PersistentSnapshotErrorKind::io_failure,
            "snapshot source path changed while being read: " +
                path.string());
    }
    if (!S_ISREG(after.st_mode) ||
        !S_ISREG(path_after.st_mode) ||
        !stable_snapshot_metadata(after, path_after) ||
        !stable_snapshot_metadata(
            result.metadata, after) ||
        result.content.size() !=
            static_cast<std::size_t>(after.st_size)) {
        fail(
            PersistentSnapshotErrorKind::unsafe_local_state,
            "snapshot source changed while being read: " +
                path.string());
    }
    result.existed = true;
    return result;
}

std::string read_file(
    const fs::path& path,
    std::size_t max_content_bytes,
    PersistentSnapshotErrorKind missing_kind,
    const char* missing_message) {
    auto captured = capture_regular_file(
        path,
        std::nullopt,
        max_content_bytes,
        missing_kind,
        missing_message);
    if (!captured.existed) {
        fail(
            missing_kind, missing_message);
    }
    return std::move(captured.content);
}

void write_replacement(
    const FileReplacement& replacement,
    bool* committed_result,
    const FileApplyHooks& hooks) {
    if (committed_result != nullptr) {
        *committed_result = false;
    }
    if (replacement.confinement_root.has_value()) {
        validate_confined_target(
            *replacement.confinement_root,
            replacement.path);
    }
    if (replacement.max_content_bytes == 0U) {
        fail(
            PersistentSnapshotErrorKind::internal,
            "file replacement size policy is missing");
    }
    if (replacement.content.size() >
        replacement.max_content_bytes) {
        fail(
            PersistentSnapshotErrorKind::limit_exceeded,
            "backup file is too large");
    }

    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.created_directory_mode =
        replacement.created_directory_mode;
    options.default_file_mode = 0644;
    options.preserved_file_mode_mask = 0777;
    options.additional_file_mode_bits =
        replacement.ensure_world_readable
            ? static_cast<mode_t>(0444)
            : 0;
    options.file_mode = replacement.mode_override;
    options.owner = replacement.owner_override;
    options.group = replacement.group_override;
    options.committed_result = committed_result;
#ifdef KEEN_PBR3_TESTING
    if (hooks.atomic_write_fault) {
        options.fault_injector =
            [&replacement, &hooks](
                AtomicFileWriteStage stage) {
                hooks.atomic_write_fault(
                    replacement.path, stage);
            };
    }
#else
    (void)hooks;
#endif
    try {
        write_file_atomically(
            replacement.path.string(),
            replacement.content,
            options);
    } catch (const PersistentSnapshotError&) {
        throw;
    } catch (const std::exception& error) {
        fail(
            PersistentSnapshotErrorKind::io_failure,
            std::string("cannot write backup file: ") +
                error.what());
    }
}

bool remove_replacement(
    const FileReplacement& replacement,
    bool* committed_result,
    const FileApplyHooks& hooks) {
    if (committed_result != nullptr) {
        *committed_result = false;
    }
    if (replacement.confinement_root.has_value()) {
        validate_confined_target(
            *replacement.confinement_root,
            replacement.path);
    }
    if (replacement.max_content_bytes == 0U) {
        fail(
            PersistentSnapshotErrorKind::internal,
            "file replacement size policy is missing");
    }

    struct stat metadata {};
    if (::lstat(replacement.path.c_str(), &metadata) != 0) {
        if (errno == ENOENT) {
            return false;
        }
        fail(
            PersistentSnapshotErrorKind::io_failure,
            "cannot inspect restore target " +
                replacement.path.string());
    }
    if (S_ISLNK(metadata.st_mode) ||
        !S_ISREG(metadata.st_mode)) {
        fail(
            PersistentSnapshotErrorKind::unsafe_local_state,
            "restore target is not a regular file: " +
                replacement.path.string());
    }

    const auto parent = replacement.path.parent_path();
    const auto filename =
        replacement.path.filename().string();
    int directory_fd = -1;
    if (replacement.confinement_root.has_value()) {
        const auto normalized_root =
            replacement.confinement_root->lexically_normal();
        const auto relative_parent =
            parent.lexically_normal().lexically_relative(
                normalized_root);
        if (relative_parent.is_absolute() ||
            (relative_parent != "." &&
             unsafe_relative_path(relative_parent))) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                "restore parent escapes its confinement root");
        }
        directory_fd = ::open(
            normalized_root.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (directory_fd >= 0 && relative_parent != ".") {
            for (const auto& component : relative_parent) {
                const int next_fd = ::openat(
                    directory_fd,
                    component.c_str(),
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                        O_NOFOLLOW);
                const int saved_errno = errno;
                (void)::close(directory_fd);
                directory_fd = next_fd;
                if (directory_fd < 0) {
                    errno = saved_errno;
                    break;
                }
            }
        }
    } else {
        directory_fd = ::open(
            parent.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    }
    if (directory_fd < 0) {
        fail(
            PersistentSnapshotErrorKind::io_failure,
            "cannot open restore parent directory " +
                parent.string());
    }
    if (::unlinkat(
            directory_fd, filename.c_str(), 0) != 0) {
        const int saved_errno = errno;
        (void)::close(directory_fd);
        fail(
            PersistentSnapshotErrorKind::io_failure,
            "cannot remove restored file " +
                replacement.path.string() + ": " +
                std::generic_category().message(saved_errno));
    }
    if (committed_result != nullptr) {
        *committed_result = true;
    }

    try {
        if (hooks.atomic_write_fault) {
            hooks.atomic_write_fault(
                replacement.path,
                AtomicFileWriteStage::directory_fsync);
        }
        if (::fsync(directory_fd) != 0) {
            fail(
                PersistentSnapshotErrorKind::io_failure,
                "cannot synchronize restore parent directory " +
                    parent.string() + ": " +
                    std::generic_category().message(errno));
        }
    } catch (...) {
        (void)::close(directory_fd);
        throw;
    }
    if (::close(directory_fd) != 0) {
        fail(
            PersistentSnapshotErrorKind::io_failure,
            "cannot close restore parent directory after "
            "synchronization: " +
                parent.string());
    }
    return true;
}

void restore_file_snapshot(
    const FileSnapshot& snapshot,
    const FileApplyHooks& hooks) {
    FileReplacement replacement;
    replacement.path = snapshot.path;
    replacement.confinement_root =
        snapshot.confinement_root;
    replacement.max_content_bytes =
        snapshot.confinement_root.has_value()
            ? kMaxManagedFileBytes
            : kMaxSnapshotBytes;
    if (snapshot.existed) {
        replacement.content = snapshot.content;
        replacement.mode_override = snapshot.mode;
        replacement.owner_override = snapshot.owner;
        replacement.group_override = snapshot.group;
        write_replacement(replacement, nullptr, hooks);
        return;
    }
    replacement.remove = true;
    (void)remove_replacement(
        replacement, nullptr, hooks);
}

bool valid_sha256_hex(const std::string& value) {
    return value.size() == 64U &&
           std::all_of(
               value.begin(),
               value.end(),
               [](unsigned char character) {
                   return
                       (character >= '0' && character <= '9') ||
                       (character >= 'a' && character <= 'f');
               });
}

void require_exact_keys(
    const nlohmann::json& object,
    const std::set<std::string>& allowed,
    const std::set<std::string>& required,
    const char* error_message) {
    if (!object.is_object()) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            error_message);
    }
    for (const auto& item : object.items()) {
        if (allowed.find(item.key()) == allowed.end()) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                error_message);
        }
    }
    for (const auto& key : required) {
        if (!object.contains(key)) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                error_message);
        }
    }
}

template <typename Value>
Value checked_unsigned_json(
    const nlohmann::json& value,
    const char* error_message) {
    std::uint64_t decoded = 0;
    if (value.is_number_unsigned()) {
        decoded = value.get<std::uint64_t>();
    } else if (value.is_number_integer()) {
        const auto signed_value =
            value.get<std::int64_t>();
        if (signed_value < 0) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                error_message);
        }
        decoded = static_cast<std::uint64_t>(signed_value);
    } else {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            error_message);
    }
    if (decoded >
        static_cast<std::uint64_t>(
            std::numeric_limits<Value>::max())) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            error_message);
    }
    return static_cast<Value>(decoded);
}

void collect_nfqws_target_names(
    std::vector<std::string>& targets,
    const fs::path& root,
    const std::string& prefix,
    const NfqwsSelection& selection) {
    struct stat root_metadata {};
    if (::lstat(root.c_str(), &root_metadata) != 0) {
        if (errno == ENOENT) {
            return;
        }
        fail(
            PersistentSnapshotErrorKind::io_failure,
            "cannot inspect nfqws restore root " +
                root.string());
    }
    if (S_ISLNK(root_metadata.st_mode) ||
        !S_ISDIR(root_metadata.st_mode)) {
        fail(
            PersistentSnapshotErrorKind::unsafe_local_state,
            "nfqws restore root is not a directory: " +
                root.string());
    }

    std::error_code error;
    for (fs::recursive_directory_iterator iterator(root, error),
         end;
         iterator != end;
         iterator.increment(error)) {
        if (error) {
            fail(
                PersistentSnapshotErrorKind::io_failure,
                "cannot enumerate nfqws restore root " +
                    root.string());
        }
        const auto& entry = *iterator;
        const auto status =
            entry.symlink_status(error);
        if (error) {
            fail(
                PersistentSnapshotErrorKind::io_failure,
                "cannot inspect nfqws restore entry");
        }
        if (fs::is_symlink(status)) {
            iterator.disable_recursion_pending();
            fail(
                PersistentSnapshotErrorKind::unsafe_local_state,
                "nfqws restore does not support symbolic links: " +
                    entry.path().string());
        }
        if (fs::is_directory(status)) {
            continue;
        }
        if (!fs::is_regular_file(status)) {
            iterator.disable_recursion_pending();
            fail(
                PersistentSnapshotErrorKind::unsafe_local_state,
                "nfqws restore does not support non-regular entries: " +
                    entry.path().string());
        }

        const auto relative =
            fs::relative(entry.path(), root, error);
        if (error || unsafe_relative_path(relative)) {
            fail(
                PersistentSnapshotErrorKind::io_failure,
                "cannot resolve nfqws restore entry");
        }
        const auto target =
            (fs::path(prefix) / relative).generic_string();
        const auto group =
            classify_nfqws_path(fs::path(target));
        if (!group.has_value() ||
            !selection.includes(*group)) {
            continue;
        }
        if (targets.size() >= kMaxManagedFiles) {
            fail(
                PersistentSnapshotErrorKind::limit_exceeded,
                "nfqws restore contains too many files");
        }
        targets.push_back(target);
    }
    if (error) {
        fail(
            PersistentSnapshotErrorKind::io_failure,
            "cannot enumerate nfqws restore root " +
                root.string());
    }
}

void collect_full_tree(
    std::vector<std::pair<std::string, FileSnapshot>>& snapshots,
    const fs::path& root,
    const std::string& prefix,
    SnapshotBudget& budget) {
    struct stat root_metadata {};
    if (::lstat(root.c_str(), &root_metadata) != 0) {
        if (errno == ENOENT) {
            return;
        }
        fail(
            PersistentSnapshotErrorKind::io_failure,
            "cannot inspect rollback snapshot root " +
                root.string());
    }
    if (S_ISLNK(root_metadata.st_mode) ||
        !S_ISDIR(root_metadata.st_mode)) {
        fail(
            PersistentSnapshotErrorKind::unsafe_local_state,
            "rollback snapshot root is not a directory: " +
                root.string());
    }

    std::error_code error;
    for (fs::recursive_directory_iterator iterator(root, error),
         end;
         iterator != end;
         iterator.increment(error)) {
        if (error) {
            fail(
                PersistentSnapshotErrorKind::io_failure,
                "cannot enumerate rollback snapshot root " +
                    root.string());
        }
        const auto& entry = *iterator;
        const auto status =
            entry.symlink_status(error);
        if (error) {
            fail(
                PersistentSnapshotErrorKind::io_failure,
                "cannot inspect rollback snapshot entry");
        }
        if (fs::is_symlink(status)) {
            iterator.disable_recursion_pending();
            fail(
                PersistentSnapshotErrorKind::unsafe_local_state,
                "rollback snapshot does not support symbolic links: " +
                    entry.path().string());
        }
        if (fs::is_directory(status)) {
            continue;
        }
        if (!fs::is_regular_file(status)) {
            iterator.disable_recursion_pending();
            fail(
                PersistentSnapshotErrorKind::unsafe_local_state,
                "rollback snapshot does not support non-regular entries: " +
                    entry.path().string());
        }

        const auto relative =
            fs::relative(entry.path(), root, error);
        if (error || unsafe_relative_path(relative)) {
            fail(
                PersistentSnapshotErrorKind::io_failure,
                "cannot resolve rollback snapshot entry");
        }
        const auto target =
            (fs::path(prefix) / relative).generic_string();
        if (!classify_nfqws_path(
                 fs::path(target))
                 .has_value()) {
            continue;
        }
        snapshots.push_back({
            target,
            capture_file(
                entry.path(),
                root,
                kMaxManagedFileBytes,
                &budget),
        });
    }
    if (error) {
        fail(
            PersistentSnapshotErrorKind::io_failure,
            "cannot enumerate rollback snapshot root " +
                root.string());
    }
}

void add_scope_tombstones(
    const PersistentLayout& layout,
    PersistentRollbackSnapshot& snapshot) {
    std::set<std::string> declared;
    for (const auto& entry : snapshot.entries) {
        declared.insert(entry.target);
    }
    const NfqwsSelection selection{
        snapshot.scopes.count("nfqws_config") != 0U,
        snapshot.scopes.count("nfqws_lists") != 0U,
    };
    if (selection.any()) {
        for (const auto& target :
             current_nfqws_targets(layout, selection)) {
            if (!declared.insert(target).second) {
                continue;
            }
            if (snapshot.entries.size() >=
                kMaxSnapshotEntries) {
                fail(
                    PersistentSnapshotErrorKind::limit_exceeded,
                    "rollback snapshot contains too many files");
            }
            snapshot.entries.push_back(
                {target, false, {}, 0600, 0, 0});
        }
    }
    if (snapshot.scopes.count("config") != 0U &&
        declared.count("config") == 0U) {
        snapshot.entries.push_back(
            {"config", false, {}, 0600, 0, 0});
    }
    if (snapshot.scopes.count("transports") != 0U &&
        declared.count("transports") == 0U) {
        snapshot.entries.push_back(
            {"transports", false, {}, 0600, 0, 0});
    }
    std::sort(
        snapshot.entries.begin(),
        snapshot.entries.end(),
        [](const auto& left, const auto& right) {
            return left.target < right.target;
        });
}

} // namespace

PersistentSnapshotError::PersistentSnapshotError(
    PersistentSnapshotErrorKind kind,
    std::string message)
    : std::runtime_error(std::move(message)),
      kind_(kind) {}

PersistentSnapshotErrorKind
PersistentSnapshotError::kind() const noexcept {
    return kind_;
}

bool NfqwsSelection::includes(
    NfqwsFileGroup group) const noexcept {
    return group == NfqwsFileGroup::config
               ? config
               : lists;
}

bool NfqwsSelection::any() const noexcept {
    return config || lists;
}

std::optional<NfqwsFileGroup> classify_nfqws_path(
    const fs::path& relative) {
    if (relative.is_absolute() || relative.empty() ||
        has_unsafe_path_component(relative)) {
        return std::nullopt;
    }
    const auto first = *relative.begin();
    const auto extension = relative.extension().string();
    const auto filename = relative.filename().string();
    const bool compressed_lua =
        filename.size() >= 7 &&
        filename.substr(filename.size() - 7) == ".lua.gz";

    if (first == "strategies") {
        return extension == ".conf"
                   ? std::optional{NfqwsFileGroup::config}
                   : std::nullopt;
    }
    if (first != "nfqws2") {
        return std::nullopt;
    }
    if (extension == ".list") {
        return NfqwsFileGroup::lists;
    }
    if (extension == ".conf" || extension == ".lua" ||
        compressed_lua) {
        return NfqwsFileGroup::config;
    }
    return std::nullopt;
}

const char* persistent_scope_for_kind(
    PersistentTargetKind kind) {
    switch (kind) {
    case PersistentTargetKind::config:
        return "config";
    case PersistentTargetKind::transports:
        return "transports";
    case PersistentTargetKind::nfqws_config:
        return "nfqws_config";
    case PersistentTargetKind::nfqws_lists:
        return "nfqws_lists";
    }
    fail(
        PersistentSnapshotErrorKind::internal,
        "invalid rollback target kind");
}

PersistentTargetKind classify_persistent_target(
    const std::string& target) {
    reject_nul_path(target, "invalid rollback target");
    if (target == "config") {
        return PersistentTargetKind::config;
    }
    if (target == "transports") {
        return PersistentTargetKind::transports;
    }

    const fs::path relative(target);
    if (relative.generic_string() != target ||
        relative.lexically_normal().generic_string() !=
            target) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "invalid non-canonical rollback target");
    }
    const auto group = classify_nfqws_path(relative);
    if (!group.has_value()) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "invalid rollback target");
    }
    return *group == NfqwsFileGroup::config
               ? PersistentTargetKind::nfqws_config
               : PersistentTargetKind::nfqws_lists;
}

ResolvedPersistentTarget resolve_persistent_target(
    const PersistentLayout& layout,
    const std::string& target) {
    const auto kind = classify_persistent_target(target);
    if (kind == PersistentTargetKind::config) {
        return {
            layout.config, std::nullopt, kind,
        };
    }
    if (kind == PersistentTargetKind::transports) {
        return {
            layout.transports, std::nullopt, kind,
        };
    }

    const fs::path relative(target);
    const auto first = *relative.begin();
    const fs::path root =
        first == "nfqws2"
            ? layout.nfqws
            : layout.strategies;
    const auto tail =
        relative.lexically_relative(first);
    if (unsafe_relative_path(tail)) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "invalid rollback target");
    }
    const auto path = root / tail;
    validate_confined_target(root, path);
    return {path, root, kind};
}

std::string logical_target_for_path(
    const PersistentLayout& layout,
    const fs::path& path) {
    const auto normalized = path.lexically_normal();
    if (normalized == layout.config.lexically_normal()) {
        return "config";
    }
    if (normalized == layout.transports.lexically_normal()) {
        return "transports";
    }
    for (const auto& [root, prefix] :
         std::vector<std::pair<fs::path, std::string>>{
             {layout.nfqws, "nfqws2"},
             {layout.strategies, "strategies"},
         }) {
        const auto relative =
            normalized.lexically_relative(root.lexically_normal());
        if (unsafe_relative_path(relative)) {
            continue;
        }
        const auto target =
            (fs::path(prefix) / relative).generic_string();
        (void)classify_persistent_target(target);
        return target;
    }
    fail(
        PersistentSnapshotErrorKind::internal,
        "restore target cannot be represented in rollback snapshot");
}

void validate_confined_target(
    const fs::path& root,
    const fs::path& target) {
    const auto normalized_root = root.lexically_normal();
    const auto normalized_target = target.lexically_normal();
    if (!normalized_root.is_absolute() ||
        !normalized_target.is_absolute()) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "nfqws restore path must be absolute");
    }
    const auto relative =
        normalized_target.lexically_relative(normalized_root);
    if (unsafe_relative_path(relative)) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "nfqws restore path escapes its root");
    }

    auto inspect = [](
                       const fs::path& path,
                       bool require_directory,
                       bool allow_missing) {
        struct stat metadata {};
        if (::lstat(path.c_str(), &metadata) != 0) {
            if (errno == ENOENT && allow_missing) {
                return false;
            }
            fail(
                PersistentSnapshotErrorKind::io_failure,
                "cannot inspect nfqws restore path " +
                    path.string());
        }
        if (S_ISLNK(metadata.st_mode)) {
            fail(
                PersistentSnapshotErrorKind::unsafe_local_state,
                "nfqws restore path contains a symbolic link");
        }
        if (require_directory &&
            !S_ISDIR(metadata.st_mode)) {
            fail(
                PersistentSnapshotErrorKind::unsafe_local_state,
                "nfqws restore parent is not a directory");
        }
        if (!require_directory &&
            !S_ISREG(metadata.st_mode)) {
            fail(
                PersistentSnapshotErrorKind::unsafe_local_state,
                "nfqws restore target is not a regular file");
        }
        return true;
    };

    bool parent_missing =
        !inspect(normalized_root, true, true);
    fs::path current = normalized_root;
    for (auto component = relative.begin();
         component != relative.end();
         ++component) {
        current /= *component;
        const bool is_target =
            std::next(component) == relative.end();
        if (parent_missing) {
            continue;
        }
        const bool exists =
            inspect(current, !is_target, true);
        if (!exists) {
            parent_missing = true;
        }
    }
}

void SnapshotBudget::reserve_entry() {
    if (entries >= kMaxSnapshotEntries) {
        fail(
            PersistentSnapshotErrorKind::limit_exceeded,
            "rollback snapshot contains too many files");
    }
    ++entries;
}

void SnapshotBudget::ensure_content_fits(
    std::size_t bytes,
    std::size_t per_file_limit) const {
    if (bytes > per_file_limit ||
        bytes > kMaxSnapshotBytes - content_bytes) {
        fail(
            PersistentSnapshotErrorKind::limit_exceeded,
            "rollback snapshot exceeds the aggregate limit");
    }
}

void SnapshotBudget::add_content(
    std::size_t bytes,
    std::size_t per_file_limit) {
    ensure_content_fits(bytes, per_file_limit);
    content_bytes += bytes;
}

FileSnapshot capture_file(
    const fs::path& path,
    const std::optional<fs::path>& confinement_root,
    std::size_t max_content_bytes,
    SnapshotBudget* budget,
    const FileCaptureHooks* hooks) {
    if (confinement_root.has_value()) {
        validate_confined_target(*confinement_root, path);
    }
    if (budget != nullptr) {
        budget->reserve_entry();
    }

    FileSnapshot snapshot;
    snapshot.path = path;
    snapshot.confinement_root = confinement_root;
    auto captured = capture_regular_file(
        path,
        confinement_root,
        max_content_bytes,
        PersistentSnapshotErrorKind::io_failure,
        "cannot read restore target",
        hooks);
    if (!captured.existed) {
        return snapshot;
    }
    const auto declared_size =
        static_cast<std::uintmax_t>(
            captured.metadata.st_size);
    if (declared_size >
        static_cast<std::uintmax_t>(max_content_bytes)) {
        fail(
            PersistentSnapshotErrorKind::limit_exceeded,
            "rollback source file is too large");
    }
    if (budget != nullptr) {
        budget->ensure_content_fits(
            static_cast<std::size_t>(declared_size),
            max_content_bytes);
    }

    snapshot.existed = true;
    snapshot.content = std::move(captured.content);
    if (budget != nullptr) {
        budget->add_content(
            snapshot.content.size(),
            max_content_bytes);
    }
    snapshot.mode = captured.metadata.st_mode & 0777;
    snapshot.owner = captured.metadata.st_uid;
    snapshot.group = captured.metadata.st_gid;
    return snapshot;
}

FileMutationPlan snapshot_replacements(
    const PersistentLayout& layout,
    std::vector<FileReplacement> replacements) {
    FileMutationPlan mutations;
    mutations.reserve(replacements.size());
    SnapshotBudget budget;
    for (auto& replacement : replacements) {
        if (replacement.max_content_bytes == 0U) {
            fail(
                PersistentSnapshotErrorKind::internal,
                "file replacement size policy is missing");
        }
        const auto target =
            logical_target_for_path(layout, replacement.path);
        const auto kind =
            classify_persistent_target(target);
        auto before = capture_file(
            replacement.path,
            replacement.confinement_root,
            replacement.max_content_bytes,
            &budget);
        mutations.push_back({
            target,
            kind,
            std::move(replacement),
            std::move(before),
        });
    }
    return mutations;
}

nlohmann::json make_persistent_snapshot(
    std::vector<std::pair<std::string, FileSnapshot>> snapshots,
    std::set<std::string> scopes) {
    if (snapshots.size() > kMaxSnapshotEntries) {
        fail(
            PersistentSnapshotErrorKind::limit_exceeded,
            "rollback snapshot contains too many files");
    }
    std::sort(
        snapshots.begin(),
        snapshots.end(),
        [](const auto& left, const auto& right) {
            return left.first < right.first;
        });

    nlohmann::json entries = nlohmann::json::array();
    std::string previous_target;
    std::size_t total_bytes = 0;
    for (const auto& [target, snapshot] : snapshots) {
        const auto kind =
            classify_persistent_target(target);
        if (!scopes.empty() &&
            scopes.count(
                persistent_scope_for_kind(kind)) == 0U) {
            fail(
                PersistentSnapshotErrorKind::internal,
                "rollback target is outside declared scopes");
        }
        if (!previous_target.empty() &&
            target == previous_target) {
            fail(
                PersistentSnapshotErrorKind::internal,
                "duplicate rollback target");
        }
        previous_target = target;
        nlohmann::json entry{
            {"target", target},
            {"state", snapshot.existed ? "present" : "absent"},
        };
        if (snapshot.existed) {
            total_bytes += snapshot.content.size();
            const auto target_limit =
                kind == PersistentTargetKind::config ||
                        kind ==
                            PersistentTargetKind::transports
                    ? kMaxSnapshotBytes
                    : kMaxManagedFileBytes;
            if (snapshot.content.size() > target_limit ||
                total_bytes > kMaxSnapshotBytes) {
                fail(
                    PersistentSnapshotErrorKind::limit_exceeded,
                    "rollback snapshot exceeds the aggregate limit");
            }
            entry["mode"] = static_cast<std::uint64_t>(
                snapshot.mode & 0777);
            entry["uid"] =
                static_cast<std::uint64_t>(snapshot.owner);
            entry["gid"] =
                static_cast<std::uint64_t>(snapshot.group);
            entry["size"] = static_cast<std::uint64_t>(
                snapshot.content.size());
            entry["encoding"] = kBase64Encoding;
            entry["sha256"] =
                Sha256::hex(snapshot.content);
            entry["data"] =
                base64_encode(snapshot.content);
        }
        entries.push_back(std::move(entry));
    }

    nlohmann::json scope_array = nlohmann::json::array();
    for (const auto& scope : scopes) {
        scope_array.push_back(scope);
    }
    nlohmann::json snapshot{
        {"format", kPersistentSnapshotFormat},
        {"schema", kPersistentSnapshotSchema},
        {"created_at",
         std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now()
                 .time_since_epoch())
             .count()},
        {"scopes", std::move(scope_array)},
        {"entries", std::move(entries)},
    };
    snapshot["integrity"] = {
        {"algorithm", "sha256"},
        {"digest", Sha256::hex(snapshot.dump())},
    };
    if (snapshot.dump().size() > kMaxSnapshotBytes) {
        fail(
            PersistentSnapshotErrorKind::limit_exceeded,
            "rollback snapshot exceeds the aggregate limit");
    }
    return snapshot;
}

PersistentRollbackSnapshot parse_persistent_snapshot(
    const nlohmann::json& document) {
    require_exact_keys(
        document,
        {"format", "schema", "created_at", "scopes",
         "entries", "integrity"},
        {"format", "schema", "scopes", "entries",
         "integrity"},
        "invalid rollback snapshot");
    if (!document.at("format").is_string() ||
        document.at("format").get_ref<const std::string&>() !=
            kPersistentSnapshotFormat ||
        !document.at("schema").is_number_integer() ||
        document.at("schema").get<int>() !=
            kPersistentSnapshotSchema ||
        !document.at("scopes").is_array() ||
        !document.at("entries").is_array() ||
        document.at("entries").size() >
            kMaxSnapshotEntries) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "invalid rollback snapshot");
    }
    if (document.contains("created_at")) {
        (void)checked_unsigned_json<std::uint64_t>(
            document.at("created_at"),
            "invalid rollback snapshot creation time");
    }
    if (document.dump().size() > kMaxSnapshotBytes) {
        fail(
            PersistentSnapshotErrorKind::limit_exceeded,
            "rollback snapshot exceeds the aggregate limit");
    }
    require_exact_keys(
        document.at("integrity"),
        {"algorithm", "digest"},
        {"algorithm", "digest"},
        "invalid rollback snapshot integrity");
    if (!document.at("integrity")
             .at("algorithm")
             .is_string() ||
        document.at("integrity")
                .at("algorithm")
                .get_ref<const std::string&>() != "sha256" ||
        !document.at("integrity").at("digest").is_string()) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "invalid rollback snapshot integrity");
    }
    const auto& declared_digest =
        document.at("integrity")
            .at("digest")
            .get_ref<const std::string&>();
    if (!valid_sha256_hex(declared_digest)) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "invalid rollback snapshot integrity");
    }
    auto canonical = document;
    canonical.erase("integrity");
    if (Sha256::hex(canonical.dump()) != declared_digest) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "rollback snapshot integrity check failed");
    }

    PersistentRollbackSnapshot parsed;
    std::string previous_scope;
    static const std::set<std::string> kAllowedScopes{
        "config",
        "transports",
        "nfqws_config",
        "nfqws_lists",
    };
    for (const auto& scope_json :
         document.at("scopes")) {
        if (!scope_json.is_string()) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                "invalid rollback snapshot scope");
        }
        const auto& scope =
            scope_json.get_ref<const std::string&>();
        if (kAllowedScopes.find(scope) ==
                kAllowedScopes.end() ||
            (!previous_scope.empty() &&
             scope <= previous_scope)) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                "invalid rollback snapshot scope");
        }
        previous_scope = scope;
        parsed.scopes.insert(scope);
    }

    std::string previous_target;
    std::size_t total_bytes = 0;
    for (const auto& entry_json :
         document.at("entries")) {
        if (!entry_json.is_object() ||
            !entry_json.contains("target") ||
            !entry_json.at("target").is_string() ||
            !entry_json.contains("state") ||
            !entry_json.at("state").is_string()) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                "invalid rollback snapshot entry");
        }
        const auto& state =
            entry_json.at("state")
                .get_ref<const std::string&>();
        if (state != "present" && state != "absent") {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                "invalid rollback snapshot entry");
        }
        const bool existed = state == "present";
        const std::set<std::string> allowed =
            existed
                ? std::set<std::string>{
                      "target", "state", "mode", "uid",
                      "gid", "size", "encoding", "sha256",
                      "data"}
                : std::set<std::string>{"target", "state"};
        require_exact_keys(
            entry_json,
            allowed,
            allowed,
            "invalid rollback snapshot entry");

        PersistentRollbackEntry entry;
        entry.target =
            entry_json.at("target")
                .get_ref<const std::string&>();
        const auto kind =
            classify_persistent_target(entry.target);
        if (!parsed.scopes.empty() &&
            parsed.scopes.count(
                persistent_scope_for_kind(kind)) == 0U) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                "rollback target is outside declared scopes");
        }
        if (!previous_target.empty() &&
            entry.target <= previous_target) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                "duplicate or unsorted rollback target");
        }
        previous_target = entry.target;
        entry.existed = existed;
        if (existed) {
            entry.mode = checked_unsigned_json<mode_t>(
                entry_json.at("mode"),
                "invalid rollback file mode");
            if ((entry.mode & ~static_cast<mode_t>(0777)) != 0) {
                fail(
                    PersistentSnapshotErrorKind::invalid_document,
                    "invalid rollback file mode");
            }
            entry.owner = checked_unsigned_json<uid_t>(
                entry_json.at("uid"),
                "invalid rollback file owner");
            entry.group = checked_unsigned_json<gid_t>(
                entry_json.at("gid"),
                "invalid rollback file group");
            const auto declared_size =
                checked_unsigned_json<std::size_t>(
                    entry_json.at("size"),
                    "invalid rollback file size");
            if (!entry_json.at("encoding").is_string() ||
                entry_json.at("encoding")
                        .get_ref<const std::string&>() !=
                    kBase64Encoding ||
                !entry_json.at("sha256").is_string() ||
                !entry_json.at("data").is_string()) {
                fail(
                    PersistentSnapshotErrorKind::invalid_document,
                    "invalid rollback snapshot entry");
            }
            const auto& declared_file_digest =
                entry_json.at("sha256")
                    .get_ref<const std::string&>();
            if (!valid_sha256_hex(declared_file_digest)) {
                fail(
                    PersistentSnapshotErrorKind::invalid_document,
                    "invalid rollback file integrity");
            }
            try {
                entry.content = base64_decode(
                    entry_json.at("data")
                        .get_ref<const std::string&>());
            } catch (const std::invalid_argument&) {
                fail(
                    PersistentSnapshotErrorKind::invalid_document,
                    "invalid rollback file encoding");
            }
            const auto target_limit =
                kind == PersistentTargetKind::config ||
                        kind ==
                            PersistentTargetKind::transports
                    ? kMaxSnapshotBytes
                    : kMaxManagedFileBytes;
            if (entry.content.size() != declared_size ||
                entry.content.size() > target_limit ||
                Sha256::hex(entry.content) !=
                    declared_file_digest) {
                fail(
                    PersistentSnapshotErrorKind::invalid_document,
                    "rollback file integrity check failed");
            }
            if (entry.content.size() >
                kMaxSnapshotBytes - total_bytes) {
                fail(
                    PersistentSnapshotErrorKind::limit_exceeded,
                    "rollback snapshot exceeds the aggregate limit");
            }
            total_bytes += entry.content.size();
        }
        parsed.entries.push_back(std::move(entry));
    }

    if (parsed.scopes.count("config") != 0U &&
        std::none_of(
            parsed.entries.begin(),
            parsed.entries.end(),
            [](const PersistentRollbackEntry& entry) {
                return entry.target == "config";
            })) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "rollback configuration snapshot is missing");
    }
    const auto config_entry = std::find_if(
        parsed.entries.begin(),
        parsed.entries.end(),
        [](const PersistentRollbackEntry& entry) {
            return entry.target == "config" &&
                   entry.existed;
        });
    if (config_entry != parsed.entries.end()) {
        try {
            auto config =
                parse_config(config_entry->content);
            validate_config(config);
        } catch (const std::exception& error) {
            fail(
                PersistentSnapshotErrorKind::invalid_document,
                std::string(
                    "rollback configuration is invalid: ") +
                    error.what());
        }
    }
    if (parsed.scopes.count("transports") != 0U &&
        std::none_of(
            parsed.entries.begin(),
            parsed.entries.end(),
            [](const PersistentRollbackEntry& entry) {
                return entry.target == "transports";
            })) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "rollback transports snapshot is missing");
    }
    return parsed;
}

nlohmann::json make_operation_snapshot(
    const FileMutationPlan& mutations) {
    std::vector<std::pair<std::string, FileSnapshot>>
        snapshots;
    snapshots.reserve(mutations.size());
    for (const auto& mutation : mutations) {
        snapshots.push_back({
            mutation.target,
            mutation.before,
        });
    }
    return make_persistent_snapshot(
        std::move(snapshots));
}

nlohmann::json make_full_snapshot(
    const PersistentLayout& layout) {
    std::vector<std::pair<std::string, FileSnapshot>>
        snapshots;
    SnapshotBudget budget;
    auto config = capture_file(
        layout.config,
        std::nullopt,
        kMaxSnapshotBytes,
        &budget);
    if (!config.existed) {
        fail(
            PersistentSnapshotErrorKind::unsafe_local_state,
            "current configuration is unavailable for rollback");
    }
    snapshots.push_back({"config", std::move(config)});
    snapshots.push_back({
        "transports",
        capture_file(
            layout.transports,
            std::nullopt,
            kMaxSnapshotBytes,
            &budget),
    });
    collect_full_tree(
        snapshots,
        layout.nfqws,
        "nfqws2",
        budget);
    collect_full_tree(
        snapshots,
        layout.strategies,
        "strategies",
        budget);
    return make_persistent_snapshot(
        std::move(snapshots),
        {
            "config",
            "transports",
            "nfqws_config",
            "nfqws_lists",
        });
}

FileMutationPlan prepare_persistent_restore(
    const PersistentLayout& layout,
    const nlohmann::json& document) {
    auto snapshot = parse_persistent_snapshot(document);
    add_scope_tombstones(layout, snapshot);

    std::vector<FileReplacement> replacements;
    replacements.reserve(snapshot.entries.size());
    for (const auto& entry : snapshot.entries) {
        const auto resolved =
            resolve_persistent_target(
                layout, entry.target);
        FileReplacement replacement;
        replacement.path = resolved.path;
        replacement.content = entry.content;
        replacement.confinement_root =
            resolved.confinement_root;
        replacement.created_directory_mode =
            resolved.confinement_root.has_value()
                ? static_cast<mode_t>(0700)
                : static_cast<mode_t>(0755);
        replacement.remove = !entry.existed;
        replacement.max_content_bytes =
            resolved.confinement_root.has_value()
                ? kMaxManagedFileBytes
                : kMaxSnapshotBytes;
        if (entry.existed) {
            replacement.mode_override = entry.mode;
            replacement.owner_override = entry.owner;
            replacement.group_override = entry.group;
        }
        replacements.push_back(std::move(replacement));
    }
    return snapshot_replacements(
        layout, std::move(replacements));
}

std::vector<std::string> current_nfqws_targets(
    const PersistentLayout& layout,
    const NfqwsSelection& selection) {
    std::vector<std::string> targets;
    collect_nfqws_target_names(
        targets,
        layout.nfqws,
        "nfqws2",
        selection);
    collect_nfqws_target_names(
        targets,
        layout.strategies,
        "strategies",
        selection);
    std::sort(targets.begin(), targets.end());
    return targets;
}

FileMutationTransaction::FileMutationTransaction(
    const FileMutationPlan& mutations,
    FileApplyHooks hooks)
    : mutations_(mutations),
      hooks_(std::move(hooks)) {}

void FileMutationTransaction::apply() {
    if (!committed_indices_.empty()) {
        fail(
            PersistentSnapshotErrorKind::internal,
            "file mutation transaction was already applied");
    }
    for (std::size_t index = 0;
         index < mutations_.size();
         ++index) {
        const auto& replacement =
            mutations_[index].replacement;
        if (hooks_.before_forward_write) {
            hooks_.before_forward_write(
                index, replacement.path);
        }
        bool committed = false;
        try {
            if (replacement.remove) {
                (void)remove_replacement(
                    replacement,
                    &committed,
                    hooks_);
            } else {
                write_replacement(
                    replacement,
                    &committed,
                    hooks_);
            }
        } catch (...) {
            if (committed) {
                committed_indices_.push_back(index);
            }
            throw;
        }
        if (committed) {
            committed_indices_.push_back(index);
        }
    }
}

std::vector<std::string>
FileMutationTransaction::rollback() {
    std::vector<std::string> errors;
    for (auto committed = committed_indices_.rbegin();
         committed != committed_indices_.rend();
         ++committed) {
        const auto index = *committed;
        const auto& before =
            mutations_[index].before;
        try {
            if (hooks_.before_rollback_write) {
                hooks_.before_rollback_write(
                    index, before.path);
            }
            restore_file_snapshot(before, hooks_);
        } catch (const std::exception& error) {
            errors.push_back(error.what());
        }
    }
    committed_indices_.clear();
    return errors;
}

bool FileMutationTransaction::has_committed_changes()
    const noexcept {
    return !committed_indices_.empty();
}

std::string save_snapshot(
    const nlohmann::json& snapshot,
    const fs::path& path,
    const FileApplyHooks& hooks) {
    const auto payload = snapshot.dump(1, '\t') + "\n";
    FileReplacement replacement;
    replacement.path = path;
    replacement.content = payload;
    replacement.mode_override =
        static_cast<mode_t>(0600);
    replacement.created_directory_mode =
        static_cast<mode_t>(0700);
    replacement.max_content_bytes = kMaxSnapshotBytes;
    write_replacement(replacement, nullptr, hooks);
    return payload;
}

nlohmann::json load_snapshot(const fs::path& path) {
    struct stat metadata {};
    if (::lstat(path.c_str(), &metadata) != 0) {
        if (errno != ENOENT) {
            fail(
                PersistentSnapshotErrorKind::io_failure,
                "rollback snapshot is not readable");
        }
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "rollback snapshot is not readable");
    }
    if (S_ISLNK(metadata.st_mode) ||
        !S_ISREG(metadata.st_mode)) {
        fail(
            PersistentSnapshotErrorKind::unsafe_local_state,
            "rollback snapshot is not a regular file");
    }
    try {
        return nlohmann::json::parse(
            read_file(
                path,
                kMaxSnapshotBytes,
                PersistentSnapshotErrorKind::invalid_document,
                "rollback snapshot is not readable"));
    } catch (const PersistentSnapshotError&) {
        throw;
    } catch (const std::exception&) {
        fail(
            PersistentSnapshotErrorKind::invalid_document,
            "rollback snapshot is not readable");
    }
}

} // namespace keen_pbr3::backup
