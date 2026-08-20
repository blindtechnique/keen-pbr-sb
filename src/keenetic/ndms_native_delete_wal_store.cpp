#include "ndms_native_delete_wal_store.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <mutex>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

constexpr mode_t kDirectoryMode = 0700;
constexpr mode_t kFileMode = 0600;
constexpr std::size_t kMaximumDirectoryEntries = 66U;
constexpr std::string_view kTemporaryPrefix{
    ".native-panel-delete-wal.tmp."};

std::atomic<std::uint64_t> temporary_sequence{0U};
std::mutex delete_wal_store_mutex;

class FileDescriptor final {
public:
    explicit FileDescriptor(const int value = -1) noexcept : value_(value) {}
    ~FileDescriptor() {
        if (value_ >= 0) (void)::close(value_);
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept
        : value_(std::exchange(other.value_, -1)) {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            if (value_ >= 0) (void)::close(value_);
            value_ = std::exchange(other.value_, -1);
        }
        return *this;
    }
    int get() const noexcept { return value_; }
    int release() noexcept { return std::exchange(value_, -1); }

private:
    int value_{-1};
};

class DirectoryLock final {
public:
    DirectoryLock(const int descriptor, const int operation)
        : descriptor_(descriptor) {
        while (::flock(descriptor_, operation) != 0) {
            if (errno == EINTR) continue;
            throw NdmsNativeDeleteWalStoreError(
                "cannot lock native delete WAL directory: " +
                std::string{std::strerror(errno)});
        }
    }
    ~DirectoryLock() {
        if (descriptor_ >= 0) (void)::flock(descriptor_, LOCK_UN);
    }
    DirectoryLock(const DirectoryLock&) = delete;
    DirectoryLock& operator=(const DirectoryLock&) = delete;

private:
    int descriptor_{-1};
};

class DirectoryAbsent final : public std::exception {};

struct StorePolicy final {
    uid_t owner{0};
    gid_t group{0};
    bool require_root_process{true};
    bool force_portable_linkat{false};
#ifdef KEEN_PBR3_TESTING
    std::function<void(NdmsNativeDeleteWalStoreFaultStage)> fault_injector;
#endif
};

StorePolicy store_policy(
#ifdef KEEN_PBR3_TESTING
    const NdmsNativeDeleteWalStoreTestHooks& hooks
#endif
) {
    StorePolicy policy;
#ifdef KEEN_PBR3_TESTING
    policy.force_portable_linkat = hooks.force_portable_linkat;
    policy.fault_injector = hooks.fault_injector;
    if (hooks.allow_current_process_owner) {
        policy.owner = ::geteuid();
        policy.group = ::getegid();
        policy.require_root_process = false;
    }
#endif
    return policy;
}

#ifdef KEEN_PBR3_TESTING
void inject(const StorePolicy& policy,
            const NdmsNativeDeleteWalStoreFaultStage stage) {
    if (policy.fault_injector) policy.fault_injector(stage);
}
#endif

std::string errno_message(const std::string& prefix) {
    return prefix + ": " + std::strerror(errno);
}

void fsync_exact(const int descriptor, const char* what) {
    while (::fsync(descriptor) != 0) {
        if (errno == EINTR) continue;
        throw NdmsNativeDeleteWalStoreError(
            errno_message(std::string{"cannot fsync "} + what));
    }
}

void set_cloexec(const int descriptor) {
#ifndef O_CLOEXEC
    if (::fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
        throw NdmsNativeDeleteWalStoreError(
            errno_message("cannot protect native delete WAL descriptor"));
    }
#else
    (void)descriptor;
#endif
}

int directory_flags() noexcept {
    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    return flags;
}

std::vector<std::string> path_components(
    const std::filesystem::path& path) {
    if (!path.is_absolute() || path.empty() || path == path.root_path() ||
        path.lexically_normal() != path) {
        throw NdmsNativeDeleteWalStoreError(
            "native delete WAL requires a normalized absolute directory");
    }
    std::vector<std::string> result;
    for (const auto& raw : path.relative_path()) {
        const auto component = raw.string();
        if (component.empty() || component == "." || component == "..") {
            throw NdmsNativeDeleteWalStoreError(
                "native delete WAL path contains an unsafe component");
        }
        result.push_back(component);
    }
    if (result.empty()) {
        throw NdmsNativeDeleteWalStoreError(
            "native delete WAL requires a dedicated directory");
    }
    return result;
}

bool exact_directory(const struct stat& metadata,
                     const StorePolicy& policy) noexcept {
    return S_ISDIR(metadata.st_mode) && !S_ISLNK(metadata.st_mode) &&
           metadata.st_uid == policy.owner &&
           metadata.st_gid == policy.group &&
           (metadata.st_mode & 07777) == kDirectoryMode;
}

bool exact_file_links(const struct stat& metadata,
                      const StorePolicy& policy,
                      const nlink_t links) noexcept {
    return S_ISREG(metadata.st_mode) && !S_ISLNK(metadata.st_mode) &&
           metadata.st_uid == policy.owner &&
           metadata.st_gid == policy.group &&
           (metadata.st_mode & 07777) == kFileMode &&
           metadata.st_nlink == links;
}

bool exact_file(const struct stat& metadata,
                const StorePolicy& policy) noexcept {
    return exact_file_links(metadata, policy, 1);
}

FileDescriptor open_directory(const std::filesystem::path& path,
                              const bool create,
                              const StorePolicy& policy) {
    if (policy.require_root_process &&
        (::geteuid() != 0 || ::getegid() != 0)) {
        throw NdmsNativeDeleteWalStoreError(
            "native delete WAL storage requires a root process");
    }
    FileDescriptor current(::open("/", directory_flags()));
    if (current.get() < 0) {
        throw NdmsNativeDeleteWalStoreError(
            errno_message("cannot open native delete WAL path root"));
    }
    set_cloexec(current.get());
    const auto components = path_components(path);
    for (std::size_t index = 0U; index < components.size(); ++index) {
        const bool final = index + 1U == components.size();
        const auto& component = components[index];
        struct stat before {};
        bool created = false;
        if (::fstatat(current.get(), component.c_str(), &before,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT && !create && final) {
                throw DirectoryAbsent{};
            }
            if (errno != ENOENT || !create || !final) {
                throw NdmsNativeDeleteWalStoreError(
                    errno_message(
                        "cannot inspect native delete WAL directory"));
            }
            if (::mkdirat(current.get(), component.c_str(),
                          kDirectoryMode) != 0) {
                if (errno != EEXIST) {
                    throw NdmsNativeDeleteWalStoreError(
                        errno_message(
                            "cannot create native delete WAL directory"));
                }
            } else {
                created = true;
            }
            if (::fstatat(current.get(), component.c_str(), &before,
                          AT_SYMLINK_NOFOLLOW) != 0) {
                throw NdmsNativeDeleteWalStoreError(
                    errno_message(
                        "cannot inspect created delete WAL directory"));
            }
        }
        if (!S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode)) {
            throw NdmsNativeDeleteWalStoreError(
                "native delete WAL path contains a symlink or non-directory");
        }
        FileDescriptor child(
            ::openat(current.get(), component.c_str(), directory_flags()));
        if (child.get() < 0) {
            throw NdmsNativeDeleteWalStoreError(
                errno_message("cannot open native delete WAL directory"));
        }
        set_cloexec(child.get());
        struct stat opened {};
        if (::fstat(child.get(), &opened) != 0 ||
            opened.st_dev != before.st_dev ||
            opened.st_ino != before.st_ino || !S_ISDIR(opened.st_mode)) {
            throw NdmsNativeDeleteWalStoreError(
                "native delete WAL directory changed while opening");
        }
        if (final) {
            if (created) {
                if (::fchown(child.get(), policy.owner, policy.group) != 0 ||
                    ::fchmod(child.get(), kDirectoryMode) != 0) {
                    throw NdmsNativeDeleteWalStoreError(
                        errno_message(
                            "cannot protect native delete WAL directory"));
                }
                fsync_exact(child.get(), "native delete WAL directory");
                fsync_exact(current.get(),
                            "native delete WAL parent directory");
                if (::fstat(child.get(), &opened) != 0) {
                    throw NdmsNativeDeleteWalStoreError(
                        errno_message(
                            "cannot reinspect native delete WAL directory"));
                }
            }
            if (!exact_directory(opened, policy)) {
                throw NdmsNativeDeleteWalStoreError(
                    "native delete WAL directory is not exact owner-only 0700");
            }
        } else if (policy.require_root_process &&
                   (opened.st_uid != 0 || (opened.st_mode & 0022) != 0)) {
            throw NdmsNativeDeleteWalStoreError(
                "native delete WAL parent is not root protected");
        }
        current = std::move(child);
    }
    return current;
}

enum class LockedReadState { absent, valid, unsafe, too_large, corrupt };

struct LockedRead final {
    LockedReadState state{LockedReadState::unsafe};
    std::optional<NdmsNativeDeleteWalRecord> record;
    dev_t device{};
    ino_t inode{};
};

LockedRead read_locked(const int directory,
                       const StorePolicy& policy) {
    LockedRead result;
    struct stat before {};
    if (::fstatat(directory, kNdmsNativeDeleteWalFilename, &before,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) result.state = LockedReadState::absent;
        return result;
    }
    if (!exact_file(before, policy) || before.st_size <= 0) return result;
    if (static_cast<std::uint64_t>(before.st_size) >
        kNdmsNativeDeleteWalMaximumBytes) {
        result.state = LockedReadState::too_large;
        return result;
    }
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
    flags |= O_NONBLOCK;
#endif
    FileDescriptor input(::openat(
        directory, kNdmsNativeDeleteWalFilename, flags));
    if (input.get() < 0) return result;
    try {
        set_cloexec(input.get());
    } catch (...) {
        return result;
    }
    struct stat opened {};
    if (::fstat(input.get(), &opened) != 0 ||
        !exact_file(opened, policy) || opened.st_dev != before.st_dev ||
        opened.st_ino != before.st_ino || opened.st_size != before.st_size) {
        return result;
    }
    std::string body;
    try {
        body.reserve(static_cast<std::size_t>(opened.st_size));
        std::array<char, 4096U> buffer{};
        while (true) {
            const auto count =
                ::read(input.get(), buffer.data(), buffer.size());
            if (count < 0) {
                if (errno == EINTR) continue;
                return result;
            }
            if (count == 0) break;
            if (body.size() + static_cast<std::size_t>(count) >
                kNdmsNativeDeleteWalMaximumBytes) {
                result.state = LockedReadState::too_large;
                return result;
            }
            body.append(buffer.data(), static_cast<std::size_t>(count));
        }
    } catch (...) {
        return result;
    }
    struct stat after {};
    if (::fstat(input.get(), &after) != 0 ||
        !exact_file(after, policy) || after.st_dev != opened.st_dev ||
        after.st_ino != opened.st_ino || after.st_size != opened.st_size ||
        after.st_mtime != opened.st_mtime ||
        after.st_ctime != opened.st_ctime ||
        body.size() != static_cast<std::size_t>(opened.st_size)) {
        return result;
    }
    try {
        result.record = parse_ndms_native_delete_wal(body);
    } catch (const NdmsNativeDeleteWalError&) {
        result.state = LockedReadState::corrupt;
        return result;
    } catch (...) {
        return result;
    }
    result.state = LockedReadState::valid;
    result.device = opened.st_dev;
    result.inode = opened.st_ino;
    return result;
}

bool decimal(const std::string_view value) noexcept {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(), [](const char value) {
               return value >= '0' && value <= '9';
           });
}

bool temporary_name(const std::string_view name) noexcept {
    if (name.substr(0U, kTemporaryPrefix.size()) != kTemporaryPrefix) {
        return false;
    }
    const auto suffix = name.substr(kTemporaryPrefix.size());
    const auto separator = suffix.find('.');
    return separator != std::string_view::npos && separator != 0U &&
           separator + 1U < suffix.size() &&
           decimal(suffix.substr(0U, separator)) &&
           decimal(suffix.substr(separator + 1U));
}

bool inventory_safe(const int directory,
                    const StorePolicy& policy,
                    const bool allow_temporaries) {
    const int duplicate = ::dup(directory);
    if (duplicate < 0) return false;
    DIR* stream = ::fdopendir(duplicate);
    if (stream == nullptr) {
        (void)::close(duplicate);
        return false;
    }
    bool safe = true;
    std::size_t count = 0U;
    ::rewinddir(stream);
    errno = 0;
    while (const auto* item = ::readdir(stream)) {
        const std::string name(item->d_name);
        if (name == "." || name == "..") {
            errno = 0;
            continue;
        }
        if (++count > kMaximumDirectoryEntries) {
            safe = false;
            break;
        }
        struct stat metadata {};
        if (::fstatat(directory, name.c_str(), &metadata,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            safe = false;
            break;
        }
        if (name == kNdmsNativeDeleteWalFilename) {
            if (!exact_file(metadata, policy) &&
                !(allow_temporaries &&
                  exact_file_links(metadata, policy, 2))) {
                safe = false;
                break;
            }
        } else if (!allow_temporaries || !temporary_name(name) ||
                   (!exact_file_links(metadata, policy, 1) &&
                    !exact_file_links(metadata, policy, 2))) {
            safe = false;
            break;
        }
        errno = 0;
    }
    const int read_error = errno;
    if (::closedir(stream) != 0 || read_error != 0) safe = false;
    return safe;
}

bool cleanup_temporaries(const int directory,
                         const StorePolicy& policy) {
    if (!inventory_safe(directory, policy, true)) return false;
    const int duplicate = ::dup(directory);
    if (duplicate < 0) return false;
    DIR* stream = ::fdopendir(duplicate);
    if (stream == nullptr) {
        (void)::close(duplicate);
        return false;
    }
    std::vector<std::string> names;
    bool safe = true;
    ::rewinddir(stream);
    errno = 0;
    while (const auto* item = ::readdir(stream)) {
        const std::string name(item->d_name);
        if (temporary_name(name)) names.push_back(name);
        errno = 0;
    }
    const int read_error = errno;
    if (::closedir(stream) != 0 || read_error != 0) safe = false;
    if (!safe) return false;
    std::sort(names.begin(), names.end());
    bool changed = false;
    for (const auto& name : names) {
        struct stat temporary {};
        if (::fstatat(directory, name.c_str(), &temporary,
                      AT_SYMLINK_NOFOLLOW) != 0 ||
            (!exact_file_links(temporary, policy, 1) &&
             !exact_file_links(temporary, policy, 2))) {
            return false;
        }
        if (temporary.st_nlink == 2) {
            struct stat published {};
            if (::fstatat(directory, kNdmsNativeDeleteWalFilename,
                          &published, AT_SYMLINK_NOFOLLOW) != 0 ||
                !exact_file_links(published, policy, 2) ||
                published.st_dev != temporary.st_dev ||
                published.st_ino != temporary.st_ino) {
                return false;
            }
        }
        if (::unlinkat(directory, name.c_str(), 0) != 0) return false;
        changed = true;
    }
    if (changed) {
        try {
            fsync_exact(directory, "native delete WAL directory");
        } catch (...) {
            return false;
        }
    }
    return inventory_safe(directory, policy, false);
}

void write_all(const int descriptor, const std::string_view body) {
    std::size_t offset = 0U;
    while (offset < body.size()) {
        const auto count =
            ::write(descriptor, body.data() + offset, body.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            throw NdmsNativeDeleteWalStoreError(
                errno_message("cannot write native delete WAL"));
        }
        if (count == 0) {
            throw NdmsNativeDeleteWalStoreError(
                "cannot write native delete WAL: short write");
        }
        offset += static_cast<std::size_t>(count);
    }
}

std::string create_temporary(const int directory,
                             FileDescriptor& output,
                             const StorePolicy& policy) {
    for (unsigned int attempt = 0U; attempt < 128U; ++attempt) {
        const auto sequence = temporary_sequence.fetch_add(
            1U, std::memory_order_relaxed);
        const auto name = std::string{kTemporaryPrefix} +
                          std::to_string(::getpid()) + "." +
                          std::to_string(sequence);
        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        output = FileDescriptor(
            ::openat(directory, name.c_str(), flags, kFileMode));
        if (output.get() < 0) {
            if (errno == EEXIST) continue;
            throw NdmsNativeDeleteWalStoreError(
                errno_message("cannot create temporary native delete WAL"));
        }
        set_cloexec(output.get());
        if (::fchown(output.get(), policy.owner, policy.group) != 0 ||
            ::fchmod(output.get(), kFileMode) != 0) {
            throw NdmsNativeDeleteWalStoreError(
                errno_message("cannot protect temporary native delete WAL"));
        }
        struct stat metadata {};
        if (::fstat(output.get(), &metadata) != 0 ||
            !exact_file(metadata, policy)) {
            throw NdmsNativeDeleteWalStoreError(
                "temporary native delete WAL metadata is unsafe");
        }
        return name;
    }
    throw NdmsNativeDeleteWalStoreError(
        "native delete WAL temporary namespace is exhausted");
}

bool optional_pair_preserved(
    const std::optional<NdmsNativeDeleteObservationPair>& before,
    const std::optional<NdmsNativeDeleteObservationPair>& after) noexcept {
    return !before.has_value() || before == after;
}

bool optional_string_preserved(
    const std::optional<std::string>& before,
    const std::optional<std::string>& after) noexcept {
    return !before.has_value() || before == after;
}

void validate_update(const NdmsNativeDeleteWalRecord& before,
                     const NdmsNativeDeleteWalRecord& after) {
    if (before == after) return;
    if (!valid_ndms_native_delete_wal_transition(
            before.phase, after.phase) ||
        before.schema_version != after.schema_version ||
        before.transaction_id != after.transaction_id ||
        before.interface_name != after.interface_name ||
        before.kind != after.kind ||
        before.ownership_revision != after.ownership_revision ||
        before.ownership_transaction_id !=
            after.ownership_transaction_id ||
        before.marker != after.marker ||
        before.snapshot_revision != after.snapshot_revision ||
        before.target_full_revision != after.target_full_revision ||
        before.keen_pbr_dependency_revision !=
            after.keen_pbr_dependency_revision ||
        before.kernel_interface_name != after.kernel_interface_name ||
        !(before.preflight_observations ==
          after.preflight_observations) ||
        !(before.observation_binding == after.observation_binding) ||
        before.owner_global_save_acknowledged !=
            after.owner_global_save_acknowledged ||
        before.external_writer_race_accepted !=
            after.external_writer_race_accepted ||
        !optional_pair_preserved(
            before.delete_absence_observations,
            after.delete_absence_observations) ||
        !optional_pair_preserved(
            before.post_save_absence_observations,
            after.post_save_absence_observations) ||
        !optional_string_preserved(
            before.tombstone_revision, after.tombstone_revision)) {
        throw NdmsNativeDeleteWalStoreError(
            "native delete WAL update changes immutable evidence");
    }
}

NdmsNativeDeleteWalLoadResult load_result(const LockedRead& read) {
    switch (read.state) {
    case LockedReadState::absent:
        return {NdmsNativeDeleteWalLoadState::absent, std::nullopt};
    case LockedReadState::valid:
        return {NdmsNativeDeleteWalLoadState::valid, read.record};
    case LockedReadState::unsafe:
        return {NdmsNativeDeleteWalLoadState::unsafe_entry, std::nullopt};
    case LockedReadState::too_large:
        return {NdmsNativeDeleteWalLoadState::too_large, std::nullopt};
    case LockedReadState::corrupt:
        return {NdmsNativeDeleteWalLoadState::corrupt_record,
                std::nullopt};
    }
    return {NdmsNativeDeleteWalLoadState::io_error, std::nullopt};
}

} // namespace

NdmsNativeDeleteWalStoreWriteError::NdmsNativeDeleteWalStoreWriteError(
    std::string message,
    const bool published)
    : NdmsNativeDeleteWalStoreError(std::move(message)),
      published_(published) {}

bool NdmsNativeDeleteWalStoreWriteError::published() const noexcept {
    return published_;
}

NdmsNativeDeleteWalStore::NdmsNativeDeleteWalStore(
    std::filesystem::path state_directory)
    : state_directory_(std::move(state_directory)) {
#ifdef KEEN_PBR3_TESTING
    test_hooks_.allow_current_process_owner = true;
#endif
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeDeleteWalStore::NdmsNativeDeleteWalStore(
    std::filesystem::path state_directory,
    NdmsNativeDeleteWalStoreTestHooks hooks)
    : state_directory_(std::move(state_directory)),
      test_hooks_(std::move(hooks)) {}
#endif

NdmsNativeDeleteWalLoadResult
NdmsNativeDeleteWalStore::load() const noexcept {
    const auto policy = store_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(delete_wal_store_mutex);
    try {
        auto directory = open_directory(state_directory_, false, policy);
        DirectoryLock lock(directory.get(), LOCK_SH);
        if (!inventory_safe(directory.get(), policy, false)) {
            return {NdmsNativeDeleteWalLoadState::unsafe_store,
                    std::nullopt};
        }
        return load_result(read_locked(directory.get(), policy));
    } catch (const DirectoryAbsent&) {
        return {NdmsNativeDeleteWalLoadState::absent, std::nullopt};
    } catch (...) {
        return {NdmsNativeDeleteWalLoadState::io_error, std::nullopt};
    }
}

NdmsNativeDeleteWalReadiness
NdmsNativeDeleteWalStore::readiness() const noexcept {
    const auto loaded = load();
    switch (loaded.state) {
    case NdmsNativeDeleteWalLoadState::absent:
        return NdmsNativeDeleteWalReadiness::clean;
    case NdmsNativeDeleteWalLoadState::valid:
        return loaded.record
            ? NdmsNativeDeleteWalReadiness::unfinished
            : NdmsNativeDeleteWalReadiness::unsafe;
    case NdmsNativeDeleteWalLoadState::unsafe_store:
    case NdmsNativeDeleteWalLoadState::unsafe_entry:
    case NdmsNativeDeleteWalLoadState::too_large:
    case NdmsNativeDeleteWalLoadState::corrupt_record:
    case NdmsNativeDeleteWalLoadState::io_error:
        return NdmsNativeDeleteWalReadiness::unsafe;
    }
    return NdmsNativeDeleteWalReadiness::unsafe;
}

bool NdmsNativeDeleteWalStore::publish_prepared_exclusive(
    const NdmsNativeDeleteWalRecord& record) {
    if (record.phase != NdmsNativeDeleteWalPhase::prepared) {
        throw NdmsNativeDeleteWalStoreError(
            "new native delete WAL must start prepared");
    }
    return publish_impl(record, true);
}

void NdmsNativeDeleteWalStore::publish(
    const NdmsNativeDeleteWalRecord& record) {
    static_cast<void>(publish_impl(record, false));
}

bool NdmsNativeDeleteWalStore::publish_impl(
    const NdmsNativeDeleteWalRecord& record,
    const bool initial) {
    const auto body = serialize_ndms_native_delete_wal(record);
    if (!(parse_ndms_native_delete_wal(body) == record)) {
        throw NdmsNativeDeleteWalStoreError(
            "native delete WAL codec round-trip failed");
    }
    const auto policy = store_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(delete_wal_store_mutex);
    auto directory = open_directory(state_directory_, true, policy);
    DirectoryLock lock(directory.get(), LOCK_EX);
    if (!cleanup_temporaries(directory.get(), policy)) {
        throw NdmsNativeDeleteWalStoreError(
            "native delete WAL inventory is unsafe");
    }
    const auto existing = read_locked(directory.get(), policy);
    if (initial) {
        if (existing.state == LockedReadState::valid) return false;
        if (existing.state != LockedReadState::absent) {
            throw NdmsNativeDeleteWalStoreError(
                "native delete WAL admission is unsafe");
        }
    } else {
        if (existing.state != LockedReadState::valid || !existing.record) {
            throw NdmsNativeDeleteWalStoreError(
                "native delete WAL update has no exact predecessor");
        }
        validate_update(*existing.record, record);
    }

    FileDescriptor temporary;
    const auto temporary_name =
        create_temporary(directory.get(), temporary, policy);
    bool temporary_exists = true;
    bool published = false;
    try {
        write_all(temporary.get(), body);
        fsync_exact(temporary.get(), "temporary native delete WAL");
#ifdef KEEN_PBR3_TESTING
        inject(policy,
               NdmsNativeDeleteWalStoreFaultStage::
                   after_temporary_file_fsync);
#endif
        if (::close(temporary.release()) != 0) {
            throw NdmsNativeDeleteWalStoreError(
                errno_message("cannot close temporary native delete WAL"));
        }

        const auto revalidated = read_locked(directory.get(), policy);
        if (revalidated.state != existing.state ||
            revalidated.record.has_value() != existing.record.has_value() ||
            (existing.record &&
             !(*existing.record == *revalidated.record)) ||
            (existing.state == LockedReadState::valid &&
             (existing.device != revalidated.device ||
              existing.inode != revalidated.inode))) {
            throw NdmsNativeDeleteWalStoreError(
                "native delete WAL changed before publication");
        }

        if (initial) {
            // linkat is the portable no-replace primitive. It also leaves a
            // recognizable two-link crash state that sweep can finish.
            if (::linkat(directory.get(), temporary_name.c_str(),
                         directory.get(), kNdmsNativeDeleteWalFilename,
                         0) != 0) {
                if (errno == EEXIST) {
                    if (::unlinkat(
                            directory.get(), temporary_name.c_str(), 0) !=
                        0) {
                        throw NdmsNativeDeleteWalStoreError(
                            errno_message(
                                "cannot clean rejected native delete WAL "
                                "temporary"));
                    }
                    temporary_exists = false;
                    fsync_exact(
                        directory.get(),
                        "rejected native delete WAL temporary cleanup");
                    return false;
                }
                throw NdmsNativeDeleteWalStoreError(
                    errno_message("cannot link initial native delete WAL"));
            }
            published = true;
#ifdef KEEN_PBR3_TESTING
            inject(policy,
                   NdmsNativeDeleteWalStoreFaultStage::
                       after_initial_link_before_temporary_unlink);
#endif
            if (::unlinkat(directory.get(), temporary_name.c_str(), 0) !=
                0) {
                throw NdmsNativeDeleteWalStoreError(
                    errno_message(
                        "cannot unlink linked native delete WAL temporary"));
            }
            temporary_exists = false;
        } else {
            if (::renameat(directory.get(), temporary_name.c_str(),
                           directory.get(),
                           kNdmsNativeDeleteWalFilename) != 0) {
                throw NdmsNativeDeleteWalStoreError(
                    errno_message("cannot replace native delete WAL"));
            }
            temporary_exists = false;
            published = true;
#ifdef KEEN_PBR3_TESTING
            inject(policy,
                   NdmsNativeDeleteWalStoreFaultStage::
                       after_replace_rename_before_directory_fsync);
#endif
        }

        const auto verified = read_locked(directory.get(), policy);
        if (verified.state != LockedReadState::valid || !verified.record ||
            !(*verified.record == record)) {
            throw NdmsNativeDeleteWalStoreError(
                "published native delete WAL failed exact verification");
        }
        fsync_exact(directory.get(), "native delete WAL directory");
    } catch (const std::exception& error) {
        if (temporary_exists) {
            if (::unlinkat(directory.get(), temporary_name.c_str(), 0) ==
                0) {
                try {
                    fsync_exact(directory.get(),
                                "native delete WAL temporary cleanup");
                } catch (...) {
                }
            }
        }
        throw NdmsNativeDeleteWalStoreWriteError(
            error.what(), published);
    } catch (...) {
        if (temporary_exists) {
            (void)::unlinkat(directory.get(), temporary_name.c_str(), 0);
        }
        throw NdmsNativeDeleteWalStoreWriteError(
            "unknown native delete WAL publication failure", published);
    }
    return true;
}

void NdmsNativeDeleteWalStore::remove_exact(
    const NdmsNativeDeleteWalRecord& expected) {
    if (expected.phase != NdmsNativeDeleteWalPhase::cleanup) {
        throw NdmsNativeDeleteWalStoreError(
            "native delete WAL removal requires cleanup phase");
    }
    static_cast<void>(serialize_ndms_native_delete_wal(expected));
    const auto policy = store_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(delete_wal_store_mutex);
    auto directory = open_directory(state_directory_, false, policy);
    DirectoryLock lock(directory.get(), LOCK_EX);
    if (!cleanup_temporaries(directory.get(), policy)) {
        throw NdmsNativeDeleteWalStoreError(
            "native delete WAL inventory is unsafe");
    }
    const auto existing = read_locked(directory.get(), policy);
    if (existing.state == LockedReadState::absent) {
        fsync_exact(directory.get(), "native delete WAL directory");
        return;
    }
    if (existing.state != LockedReadState::valid || !existing.record ||
        !(*existing.record == expected)) {
        throw NdmsNativeDeleteWalStoreError(
            "native delete WAL exact removal precondition failed");
    }
#ifdef KEEN_PBR3_TESTING
    inject(policy,
           NdmsNativeDeleteWalStoreFaultStage::
               before_remove_inode_recheck);
#endif
    struct stat current {};
    if (::fstatat(directory.get(), kNdmsNativeDeleteWalFilename, &current,
                  AT_SYMLINK_NOFOLLOW) != 0 ||
        !exact_file(current, policy) ||
        current.st_dev != existing.device ||
        current.st_ino != existing.inode) {
        throw NdmsNativeDeleteWalStoreError(
            "native delete WAL changed before exact removal");
    }
    bool published = false;
    try {
        if (::unlinkat(directory.get(), kNdmsNativeDeleteWalFilename, 0) !=
            0) {
            throw NdmsNativeDeleteWalStoreError(
                errno_message("cannot remove native delete WAL"));
        }
        published = true;
#ifdef KEEN_PBR3_TESTING
        inject(policy,
               NdmsNativeDeleteWalStoreFaultStage::
                   after_unlink_before_directory_fsync);
#endif
        if (read_locked(directory.get(), policy).state !=
            LockedReadState::absent) {
            throw NdmsNativeDeleteWalStoreError(
                "removed native delete WAL remains visible");
        }
        fsync_exact(directory.get(), "native delete WAL directory");
    } catch (const std::exception& error) {
        throw NdmsNativeDeleteWalStoreWriteError(
            error.what(), published);
    } catch (...) {
        throw NdmsNativeDeleteWalStoreWriteError(
            "unknown native delete WAL removal failure", published);
    }
}

void NdmsNativeDeleteWalStore::sweep_orphaned_temporaries() noexcept {
    const auto policy = store_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(delete_wal_store_mutex);
    try {
        auto directory = open_directory(state_directory_, false, policy);
        DirectoryLock lock(directory.get(), LOCK_EX);
        static_cast<void>(cleanup_temporaries(directory.get(), policy));
    } catch (...) {
    }
}

const std::filesystem::path&
NdmsNativeDeleteWalStore::state_directory() const noexcept {
    return state_directory_;
}

const char* ndms_native_delete_wal_load_state_name(
    const NdmsNativeDeleteWalLoadState state) noexcept {
    switch (state) {
    case NdmsNativeDeleteWalLoadState::absent: return "absent";
    case NdmsNativeDeleteWalLoadState::valid: return "valid";
    case NdmsNativeDeleteWalLoadState::unsafe_store: return "unsafe_store";
    case NdmsNativeDeleteWalLoadState::unsafe_entry: return "unsafe_entry";
    case NdmsNativeDeleteWalLoadState::too_large: return "too_large";
    case NdmsNativeDeleteWalLoadState::corrupt_record:
        return "corrupt_record";
    case NdmsNativeDeleteWalLoadState::io_error: return "io_error";
    }
    return "io_error";
}

const char* ndms_native_delete_wal_readiness_name(
    const NdmsNativeDeleteWalReadiness readiness) noexcept {
    switch (readiness) {
    case NdmsNativeDeleteWalReadiness::clean: return "clean";
    case NdmsNativeDeleteWalReadiness::unfinished: return "unfinished";
    case NdmsNativeDeleteWalReadiness::unsafe: return "unsafe";
    }
    return "unsafe";
}

} // namespace keen_pbr3
