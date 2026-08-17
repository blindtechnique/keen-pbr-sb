#include "ndms_native_import_wal_store.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <optional>
#include <signal.h>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr mode_t kDirectoryMode = 0700;
constexpr mode_t kFileMode = 0600;
constexpr std::string_view kRecordSuffix{".wal"};
constexpr std::string_view kTemporaryPrefix{
    ".keen-pbr-native-import-wal."};

std::string errno_message(const std::string& prefix);

class FileDescriptor {
public:
    explicit FileDescriptor(int value = -1) noexcept : value_(value) {}
    ~FileDescriptor() {
        if (value_ >= 0) (void)::close(value_);
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept
        : value_(std::exchange(other.value_, -1)) {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this == &other) return *this;
        if (value_ >= 0) (void)::close(value_);
        value_ = std::exchange(other.value_, -1);
        return *this;
    }

    int get() const noexcept { return value_; }
    int release() noexcept { return std::exchange(value_, -1); }

private:
    int value_;
};

class DirectoryLock final {
public:
    DirectoryLock(const int descriptor, const int operation)
        : descriptor_(descriptor) {
        if (::flock(descriptor_, operation) != 0) {
            throw NdmsNativeImportWalStoreError(
                errno_message("Cannot lock native import WAL directory"));
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

class AdoptedDirectoryLock final {
public:
    explicit AdoptedDirectoryLock(const int descriptor) noexcept
        : descriptor_(descriptor) {}

    ~AdoptedDirectoryLock() {
        if (descriptor_ >= 0) (void)::flock(descriptor_, LOCK_UN);
    }

    AdoptedDirectoryLock(const AdoptedDirectoryLock&) = delete;
    AdoptedDirectoryLock& operator=(const AdoptedDirectoryLock&) = delete;

private:
    int descriptor_{-1};
};

enum class DirectoryErrorKind {
    absent,
    unsafe,
    io,
};

class DirectoryError final : public std::runtime_error {
public:
    DirectoryError(DirectoryErrorKind kind, std::string message)
        : std::runtime_error(std::move(message)), kind_(kind) {}

    DirectoryErrorKind kind() const noexcept { return kind_; }

private:
    DirectoryErrorKind kind_;
};

struct StorePolicy {
    uid_t owner{0};
    gid_t group{0};
    bool require_root_process{true};
#ifdef KEEN_PBR3_TESTING
    std::function<void(NdmsNativeImportWalStoreFaultStage)> fault_injector;
#endif
};

std::mutex& store_mutex() {
    // The daemon is the only intended writer. A process-wide mutex also keeps
    // separate store objects from interleaving their inspect/rename sequence.
    static std::mutex mutex;
    return mutex;
}

std::atomic<unsigned int> temporary_sequence{0U};

std::string errno_message(const std::string& prefix) {
    const int error = errno;
    return prefix + ": " + std::strerror(error);
}

[[noreturn]] void throw_directory_errno(const std::string& message) {
    throw DirectoryError(DirectoryErrorKind::io, errno_message(message));
}

int directory_open_flags() {
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

void set_close_on_exec_if_needed(int fd, const std::string& what) {
#ifndef O_CLOEXEC
    if (::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        throw std::runtime_error(errno_message(
            "Cannot mark " + what + " close-on-exec"));
    }
#else
    (void)fd;
    (void)what;
#endif
}

void fsync_exact(int fd, const std::string& what) {
    while (::fsync(fd) != 0) {
        if (errno == EINTR) continue;
        throw std::runtime_error(errno_message("Cannot fsync " + what));
    }
}

bool is_lower_hex(std::string_view value, std::size_t size) noexcept {
    return value.size() == size &&
           std::all_of(
               value.begin(), value.end(), [](unsigned char character) {
                   return (character >= '0' && character <= '9') ||
                          (character >= 'a' && character <= 'f');
               });
}

bool valid_transaction_id(std::string_view value) noexcept {
    return is_lower_hex(value, 32U);
}

std::string record_filename(const std::string& transaction_id) {
    if (!valid_transaction_id(transaction_id)) {
        throw NdmsNativeImportWalStoreError(
            "Native import WAL transaction id is invalid");
    }
    return transaction_id + std::string{kRecordSuffix};
}

std::optional<std::string> transaction_from_filename(
    const std::string& filename) {
    if (filename.size() != 32U + kRecordSuffix.size() ||
        filename.compare(32U, kRecordSuffix.size(), kRecordSuffix) != 0) {
        return std::nullopt;
    }
    const std::string transaction_id = filename.substr(0U, 32U);
    if (!valid_transaction_id(transaction_id)) return std::nullopt;
    return transaction_id;
}

bool exact_directory_metadata(const struct stat& metadata,
                              const StorePolicy& policy) noexcept {
    return S_ISDIR(metadata.st_mode) && !S_ISLNK(metadata.st_mode) &&
           metadata.st_uid == policy.owner &&
           metadata.st_gid == policy.group &&
           (metadata.st_mode & 07777) == kDirectoryMode;
}

bool exact_file_metadata(const struct stat& metadata,
                         const StorePolicy& policy) noexcept {
    return S_ISREG(metadata.st_mode) && !S_ISLNK(metadata.st_mode) &&
           metadata.st_uid == policy.owner &&
           metadata.st_gid == policy.group &&
           (metadata.st_mode & 07777) == kFileMode &&
           metadata.st_nlink == 1;
}

std::vector<std::string> path_components(
    const std::filesystem::path& path) {
    if (!path.is_absolute() || path.empty() || path == path.root_path()) {
        throw DirectoryError(
            DirectoryErrorKind::unsafe,
            "Native import WAL needs an absolute dedicated state directory");
    }
    std::vector<std::string> components;
    for (const auto& raw : path.relative_path()) {
        const std::string component = raw.string();
        if (component.empty()) continue;
        if (component == "." || component == "..") {
            throw DirectoryError(
                DirectoryErrorKind::unsafe,
                "Native import WAL path contains an unsafe component");
        }
        components.push_back(component);
    }
    if (components.empty()) {
        throw DirectoryError(
            DirectoryErrorKind::unsafe,
            "Native import WAL needs a dedicated state directory");
    }
    return components;
}

void verify_opened_directory(int fd,
                             const struct stat& before,
                             const std::string& component) {
    struct stat after {};
    if (::fstat(fd, &after) != 0) {
        throw_directory_errno(
            "Cannot inspect opened native import WAL directory");
    }
    if (!S_ISDIR(after.st_mode) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino) {
        throw DirectoryError(
            DirectoryErrorKind::unsafe,
            "Native import WAL directory changed while opening '" +
                component + "'");
    }
}

FileDescriptor open_store_directory(
    const std::filesystem::path& path,
    bool create,
    const StorePolicy& policy) {
    if (policy.require_root_process &&
        (::geteuid() != 0 || ::getegid() != 0)) {
        throw DirectoryError(
            DirectoryErrorKind::unsafe,
            "Native import WAL storage requires a root process");
    }

    const auto components = path_components(path);
    FileDescriptor current(::open("/", directory_open_flags()));
    if (current.get() < 0) {
        throw_directory_errno("Cannot open native import WAL path root");
    }
    set_close_on_exec_if_needed(
        current.get(), "native import WAL path root");

    for (std::size_t index = 0U; index < components.size(); ++index) {
        const bool final = index + 1U == components.size();
        const std::string& component = components[index];
        struct stat before {};
        bool created = false;
        if (::fstatat(current.get(),
                      component.c_str(),
                      &before,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT || !create || !final) {
                if (errno == ENOENT && final) {
                    throw DirectoryError(
                        DirectoryErrorKind::absent,
                        "Native import WAL state directory is absent");
                }
                throw_directory_errno(
                    "Cannot inspect native import WAL directory component");
            }
            if (::mkdirat(
                    current.get(), component.c_str(), kDirectoryMode) != 0) {
                if (errno != EEXIST) {
                    throw_directory_errno(
                        "Cannot create native import WAL state directory");
                }
            } else {
                created = true;
            }
            if (::fstatat(current.get(),
                          component.c_str(),
                          &before,
                          AT_SYMLINK_NOFOLLOW) != 0) {
                throw_directory_errno(
                    "Cannot inspect created native import WAL directory");
            }
        }
        if (!S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode)) {
            throw DirectoryError(
                DirectoryErrorKind::unsafe,
                "Native import WAL path contains a non-directory or symlink");
        }

        FileDescriptor child(::openat(
            current.get(), component.c_str(), directory_open_flags()));
        if (child.get() < 0) {
            throw_directory_errno("Cannot open native import WAL directory");
        }
        set_close_on_exec_if_needed(
            child.get(), "native import WAL directory");
        verify_opened_directory(child.get(), before, component);

        if (final) {
            if (created) {
                if (::fchown(child.get(), policy.owner, policy.group) != 0 ||
                    ::fchmod(child.get(), kDirectoryMode) != 0) {
                    throw_directory_errno(
                        "Cannot make native import WAL directory root-only");
                }
                fsync_exact(child.get(), "native import WAL state directory");
                fsync_exact(current.get(),
                            "native import WAL state directory parent");
            }
            struct stat exact {};
            if (::fstat(child.get(), &exact) != 0) {
                throw_directory_errno(
                    "Cannot inspect native import WAL state directory");
            }
            if (!exact_directory_metadata(exact, policy)) {
                throw DirectoryError(
                    DirectoryErrorKind::unsafe,
                    "Native import WAL state directory is not exact root-only "
                    "0700 state");
            }
        } else if (policy.require_root_process &&
                   (before.st_uid != 0 ||
                    (before.st_mode & 0022) != 0)) {
            throw DirectoryError(
                DirectoryErrorKind::unsafe,
                "Native import WAL parent directory is not root-owned and "
                "protected from writes");
        }
        current = std::move(child);
    }
    return current;
}

NdmsNativeImportWalLoadResult directory_error_result(
    const DirectoryError& error) {
    switch (error.kind()) {
    case DirectoryErrorKind::absent:
        return {NdmsNativeImportWalLoadState::absent, std::nullopt};
    case DirectoryErrorKind::unsafe:
        return {NdmsNativeImportWalLoadState::unsafe_store, std::nullopt};
    case DirectoryErrorKind::io:
        return {NdmsNativeImportWalLoadState::io_error, std::nullopt};
    }
    return {NdmsNativeImportWalLoadState::io_error, std::nullopt};
}

NdmsNativeImportWalLoadResult read_record_from_directory(
    int directory_fd,
    const std::string& transaction_id,
    const StorePolicy& policy) {
    if (!valid_transaction_id(transaction_id)) {
        return {
            NdmsNativeImportWalLoadState::identity_mismatch,
            std::nullopt};
    }
    const std::string filename =
        transaction_id + std::string{kRecordSuffix};
    struct stat before {};
    if (::fstatat(directory_fd,
                  filename.c_str(),
                  &before,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        return {
            errno == ENOENT ? NdmsNativeImportWalLoadState::absent
                            : NdmsNativeImportWalLoadState::io_error,
            std::nullopt};
    }
    if (!exact_file_metadata(before, policy)) {
        return {
            NdmsNativeImportWalLoadState::unsafe_entry,
            std::nullopt};
    }
    if (before.st_size < 0 ||
        static_cast<std::uint64_t>(before.st_size) >
            kNdmsNativeImportWalMaximumBytes) {
        return {
            NdmsNativeImportWalLoadState::too_large,
            std::nullopt};
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
    FileDescriptor input(::openat(directory_fd, filename.c_str(), flags));
    if (input.get() < 0) {
        return {
            errno == ELOOP ? NdmsNativeImportWalLoadState::unsafe_entry
                           : NdmsNativeImportWalLoadState::io_error,
            std::nullopt};
    }
    try {
        set_close_on_exec_if_needed(input.get(), "native import WAL file");
    } catch (...) {
        return {NdmsNativeImportWalLoadState::io_error, std::nullopt};
    }

    struct stat opened {};
    if (::fstat(input.get(), &opened) != 0) {
        return {NdmsNativeImportWalLoadState::io_error, std::nullopt};
    }
    if (!exact_file_metadata(opened, policy) ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino ||
        opened.st_size != before.st_size) {
        return {
            NdmsNativeImportWalLoadState::unsafe_entry,
            std::nullopt};
    }

    std::string body;
    body.reserve(static_cast<std::size_t>(opened.st_size));
    std::array<char, 4096U> buffer{};
    while (true) {
        const ssize_t count =
            ::read(input.get(), buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            return {NdmsNativeImportWalLoadState::io_error, std::nullopt};
        }
        if (count == 0) break;
        if (body.size() + static_cast<std::size_t>(count) >
            kNdmsNativeImportWalMaximumBytes) {
            return {
                NdmsNativeImportWalLoadState::too_large,
                std::nullopt};
        }
        body.append(buffer.data(), static_cast<std::size_t>(count));
    }

    struct stat after {};
    if (::fstat(input.get(), &after) != 0) {
        return {NdmsNativeImportWalLoadState::io_error, std::nullopt};
    }
    if (!exact_file_metadata(after, policy) ||
        after.st_dev != opened.st_dev || after.st_ino != opened.st_ino ||
        after.st_size != opened.st_size ||
        body.size() != static_cast<std::size_t>(opened.st_size) ||
        after.st_mtime != opened.st_mtime ||
        after.st_ctime != opened.st_ctime) {
        return {
            NdmsNativeImportWalLoadState::unsafe_entry,
            std::nullopt};
    }

    try {
        auto record = parse_ndms_native_import_wal(body);
        if (record.transaction_id != transaction_id) {
            return {
                NdmsNativeImportWalLoadState::identity_mismatch,
                std::nullopt};
        }
        return {
            NdmsNativeImportWalLoadState::valid,
            std::move(record)};
    } catch (const NdmsNativeImportWalError&) {
        return {
            NdmsNativeImportWalLoadState::corrupt_record,
            std::nullopt};
    } catch (...) {
        return {NdmsNativeImportWalLoadState::io_error, std::nullopt};
    }
}

NdmsNativeImportWalInventory inventory_from_directory(
    int directory_fd,
    const StorePolicy& policy) {
    FileDescriptor duplicate(::dup(directory_fd));
    if (duplicate.get() < 0) {
        return {NdmsNativeImportWalInventoryState::io_error, {}};
    }
    DIR* stream = ::fdopendir(duplicate.release());
    if (stream == nullptr) {
        return {NdmsNativeImportWalInventoryState::io_error, {}};
    }

    std::vector<std::string> names;
    bool over_limit = false;
    errno = 0;
    while (const dirent* item = ::readdir(stream)) {
        const std::string name(item->d_name);
        if (name == "." || name == "..") {
            errno = 0;
            continue;
        }
        if (names.size() >=
            kNdmsNativeImportWalStoreMaximumDirectoryEntries) {
            over_limit = true;
            break;
        }
        names.push_back(name);
        errno = 0;
    }
    const int read_error = errno;
    const int close_result = ::closedir(stream);
    if (read_error != 0 || close_result != 0) {
        return {NdmsNativeImportWalInventoryState::io_error, {}};
    }
    if (over_limit) {
        return {
            NdmsNativeImportWalInventoryState::directory_limit_exceeded,
            {}};
    }

    std::sort(names.begin(), names.end());
    std::size_t record_count = 0U;
    for (const auto& name : names) {
        if (transaction_from_filename(name).has_value()) ++record_count;
    }
    if (record_count > kNdmsNativeImportWalStoreMaximumRecords) {
        return {
            NdmsNativeImportWalInventoryState::record_limit_exceeded,
            {}};
    }

    NdmsNativeImportWalInventory inventory;
    inventory.state = NdmsNativeImportWalInventoryState::ready;
    inventory.items.reserve(names.size());
    for (const auto& name : names) {
        NdmsNativeImportWalInventoryItem item;
        item.filename = name;
        item.transaction_id = transaction_from_filename(name);
        if (!item.transaction_id.has_value()) {
            item.state = NdmsNativeImportWalLoadState::unsafe_entry;
        } else {
            auto loaded = read_record_from_directory(
                directory_fd, *item.transaction_id, policy);
            item.state = loaded.state == NdmsNativeImportWalLoadState::absent
                             ? NdmsNativeImportWalLoadState::unsafe_entry
                             : loaded.state;
            item.record = std::move(loaded.record);
        }
        inventory.items.push_back(std::move(item));
    }
    return inventory;
}

void require_safe_inventory(
    const NdmsNativeImportWalInventory& inventory) {
    if (!inventory.recovery_permitted()) {
        throw NdmsNativeImportWalStoreError(
            "Native import WAL inventory is incomplete or unsafe");
    }
}

bool optional_string_preserved(
    const std::optional<std::string>& before,
    const std::optional<std::string>& after) noexcept {
    return !before.has_value() || before == after;
}

void validate_update(const NdmsNativeImportWalRecord& before,
                     const NdmsNativeImportWalRecord& after) {
    if (before == after) return;
    if (before.phase == after.phase ||
        !valid_ndms_native_import_wal_transition(
            before.phase, after.phase)) {
        throw NdmsNativeImportWalStoreError(
            "Native import WAL update skips, rewinds or rewrites a phase");
    }
    if (before.transaction_id != after.transaction_id ||
        before.kind != after.kind || before.marker != after.marker ||
        before.candidate_revision != after.candidate_revision ||
        before.request_binding_sha256 !=
            after.request_binding_sha256 ||
        before.generation_ticket != after.generation_ticket ||
        before.maintenance_base_generation !=
            after.maintenance_base_generation ||
        !(before.baseline == after.baseline) ||
        (before.reserved_generation.has_value() &&
         before.reserved_generation != after.reserved_generation) ||
        !optional_string_preserved(
            before.response_manifest_sha256,
            after.response_manifest_sha256) ||
        !optional_string_preserved(
            before.created_interface, after.created_interface) ||
        !optional_string_preserved(
            before.target_full_revision, after.target_full_revision) ||
        !optional_string_preserved(
            before.ownership_revision, after.ownership_revision)) {
        throw NdmsNativeImportWalStoreError(
            "Native import WAL update changes immutable evidence");
    }
}

void write_all(int fd, const std::string& body) {
    std::size_t offset = 0U;
    while (offset < body.size()) {
        const ssize_t written =
            ::write(fd, body.data() + offset, body.size() - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(
                errno_message("Cannot write native import WAL file"));
        }
        if (written == 0) {
            throw std::runtime_error(
                "Cannot write native import WAL file: short write");
        }
        offset += static_cast<std::size_t>(written);
    }
}

#ifdef KEEN_PBR3_TESTING
void inject(const StorePolicy& policy,
            NdmsNativeImportWalStoreFaultStage stage) {
    if (policy.fault_injector) policy.fault_injector(stage);
}
#endif

std::string create_temporary(int directory_fd,
                             FileDescriptor& descriptor,
                             const StorePolicy& policy) {
    for (unsigned int attempt = 0U; attempt < 128U; ++attempt) {
        const unsigned int sequence = temporary_sequence.fetch_add(
            1U, std::memory_order_relaxed);
        const std::string name = std::string{kTemporaryPrefix} +
                                 std::to_string(::getpid()) + "." +
                                 std::to_string(sequence);
        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        descriptor = FileDescriptor(
            ::openat(directory_fd, name.c_str(), flags, kFileMode));
        if (descriptor.get() < 0) {
            if (errno == EEXIST) continue;
            throw std::runtime_error(errno_message(
                "Cannot create temporary native import WAL file"));
        }
        set_close_on_exec_if_needed(
            descriptor.get(), "temporary native import WAL file");
        if (::fchown(descriptor.get(), policy.owner, policy.group) != 0 ||
            ::fchmod(descriptor.get(), kFileMode) != 0) {
            throw std::runtime_error(errno_message(
                "Cannot make temporary native import WAL file root-only"));
        }
        struct stat metadata {};
        if (::fstat(descriptor.get(), &metadata) != 0 ||
            !exact_file_metadata(metadata, policy)) {
            throw NdmsNativeImportWalStoreError(
                "Temporary native import WAL file metadata is unsafe");
        }
        return name;
    }
    throw NdmsNativeImportWalStoreError(
        "Temporary native import WAL name space is exhausted");
}

// The owning pid encoded by create_temporary, or nothing if the name is not
// one of ours. Parsed strictly: a name we cannot read as our own temporary is
// somebody else's, and this must never widen into a general directory cleaner.
std::optional<pid_t> temporary_owner_pid(const std::string& filename) {
    if (filename.size() <= kTemporaryPrefix.size() ||
        filename.compare(0U, kTemporaryPrefix.size(), kTemporaryPrefix) !=
            0) {
        return std::nullopt;
    }
    const std::size_t pid_begin = kTemporaryPrefix.size();
    const std::size_t separator = filename.find('.', pid_begin);
    if (separator == std::string::npos || separator == pid_begin ||
        separator + 1U == filename.size()) {
        return std::nullopt;
    }
    std::uint64_t parsed = 0U;
    for (std::size_t index = pid_begin; index < separator; ++index) {
        const auto character =
            static_cast<unsigned char>(filename[index]);
        if (character < '0' || character > '9') return std::nullopt;
        const unsigned int digit = character - '0';
        const auto limit = static_cast<std::uint64_t>(
            std::numeric_limits<pid_t>::max());
        if (parsed > (limit - digit) / 10U) return std::nullopt;
        parsed = parsed * 10U + digit;
    }
    if (parsed == 0U) return std::nullopt;
    return static_cast<pid_t>(parsed);
}

bool process_may_still_exist(const pid_t pid) noexcept {
    if (pid == ::getpid()) return true;
    if (::kill(pid, 0) == 0) return true;
    return errno != ESRCH;
}

// publish_impl creates its temporary as a real directory entry and only then
// writes, fsyncs and renames it. A process killed inside that window - a power
// cut on the USB /opt is enough - leaves the temporary behind, and nothing
// swept it. inventory_from_directory calls every unrecognized name an unsafe
// entry, so recovery_permitted() then stayed false forever: the surviving
// transaction could never be rolled back, completed or removed, and no new
// import could be admitted. The only remedy was an rm on the router.
//
// Modelled on cleanup_orphaned_temporaries in src/backup/restore_journal.cpp,
// which already does exactly this for the identical write pattern. Removal is
// deliberately narrow: only our own prefix, only a dead owner, only the exact
// shape create_temporary produces, and only if a second stat still describes
// the same inode. Anything else is left for an operator to look at.
//
// Failures are swallowed: a directory we could not tidy is the situation we
// were already in, and letting it throw would turn a best-effort sweep into a
// new way for publish to fail.
void cleanup_orphaned_temporaries(int directory_fd,
                                  const StorePolicy& policy) noexcept {
    const int duplicate = ::dup(directory_fd);
    if (duplicate < 0) return;
    DIR* stream = ::fdopendir(duplicate);
    if (stream == nullptr) {
        (void)::close(duplicate);
        return;
    }
    // The dup shares its offset with directory_fd. Without the rewinds this
    // sweep starts wherever the last consumer stopped, and - worse - leaves
    // the offset at end-of-directory, so the inventory read that follows on
    // the same fd sees an EMPTY store: publish would then admit a second
    // transaction beside the first, the exact double-admission the exclusive
    // path exists to prevent. Caught by the cross-process admission test the
    // moment this target was made buildable again.
    ::rewinddir(stream);
    while (const dirent* item = ::readdir(stream)) {
        const std::string filename(item->d_name);
        const auto owner = temporary_owner_pid(filename);
        if (!owner.has_value() || process_may_still_exist(*owner)) continue;

        struct stat scanned {};
        if (::fstatat(directory_fd, filename.c_str(), &scanned,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }
        // An early out, not the enforcement: the revalidation below re-tests
        // the same shape, and mutation shows only the pair is load-bearing.
        if (!exact_file_metadata(scanned, policy)) continue;

        struct stat revalidated {};
        if (::fstatat(directory_fd, filename.c_str(), &revalidated,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }
        // Same inode, still the same shape: nothing was swapped underneath
        // between the decision and the unlink.
        if (!exact_file_metadata(revalidated, policy) ||
            revalidated.st_dev != scanned.st_dev ||
            revalidated.st_ino != scanned.st_ino) {
            continue;
        }
        (void)::unlinkat(directory_fd, filename.c_str(), 0);
    }
    ::rewinddir(stream);
    (void)::closedir(stream);
}

StorePolicy make_policy(
#ifdef KEEN_PBR3_TESTING
    const NdmsNativeImportWalStoreTestHooks& hooks
#endif
) {
    StorePolicy policy;
#ifdef KEEN_PBR3_TESTING
    policy.fault_injector = hooks.fault_injector;
    if (hooks.allow_current_process_owner) {
        policy.owner = ::geteuid();
        policy.group = ::getegid();
        policy.require_root_process = false;
    }
#endif
    return policy;
}

} // namespace

bool NdmsNativeImportWalInventory::recovery_permitted() const noexcept {
    if (state != NdmsNativeImportWalInventoryState::ready) return false;
    return std::all_of(
        items.begin(), items.end(), [](const auto& item) {
            return item.state == NdmsNativeImportWalLoadState::valid &&
                   item.transaction_id.has_value() &&
                   item.record.has_value();
        });
}

NdmsNativeImportWalStoreWriteError::NdmsNativeImportWalStoreWriteError(
    std::string message,
    bool published)
    : NdmsNativeImportWalStoreError(std::move(message)),
      published_(published) {}

bool NdmsNativeImportWalStoreWriteError::published() const noexcept {
    return published_;
}

NdmsNativeImportWalStore::NdmsNativeImportWalStore(
    std::filesystem::path state_directory)
    : state_directory_(std::move(state_directory)) {}

#ifdef KEEN_PBR3_TESTING
NdmsNativeImportWalStore::NdmsNativeImportWalStore(
    std::filesystem::path state_directory,
    NdmsNativeImportWalStoreTestHooks hooks)
    : state_directory_(std::move(state_directory)),
      test_hooks_(std::move(hooks)) {}
#endif

void NdmsNativeImportWalStore::publish(
    const NdmsNativeImportWalRecord& record) {
    static_cast<void>(publish_impl(record, false, false));
}

NdmsNativeImportWalAdmissionState
NdmsNativeImportWalStore::publish_prepared_exclusive(
    const NdmsNativeImportWalRecord& record) {
    return publish_impl(record, true, true);
}

NdmsNativeImportWalAdmissionState
NdmsNativeImportWalStore::publish_impl(
    const NdmsNativeImportWalRecord& record,
    const bool require_empty_store,
    const bool allow_new_record) {
    // This is the only accepted payload path. Reparse before touching disk so
    // no future caller can bypass the codec's exact non-secret schema.
    const std::string body = serialize_ndms_native_import_wal(record);
    if (!(parse_ndms_native_import_wal(body) == record)) {
        throw NdmsNativeImportWalStoreError(
            "Native import WAL codec round-trip is inconsistent");
    }
    const std::string filename = record_filename(record.transaction_id);
    const StorePolicy policy = make_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );

    std::lock_guard<std::mutex> lock(store_mutex());
    FileDescriptor directory;
    try {
        directory = open_store_directory(
            state_directory_, true, policy);
    } catch (const DirectoryError& error) {
        throw NdmsNativeImportWalStoreError(error.what());
    }
    DirectoryLock directory_lock(directory.get(), LOCK_EX);

    // Before the inventory is judged, not after: our own crash residue would
    // otherwise be read as a foreign entry and refuse the very write that
    // would make progress.
    cleanup_orphaned_temporaries(directory.get(), policy);

    const auto before_inventory =
        inventory_from_directory(directory.get(), policy);
    require_safe_inventory(before_inventory);
    if (require_empty_store) {
        if (record.phase != NdmsNativeImportWalPhase::prepared) {
            throw NdmsNativeImportWalStoreError(
                "Exclusive native import WAL admission requires prepared phase");
        }
        if (!before_inventory.items.empty()) {
            return NdmsNativeImportWalAdmissionState::
                unfinished_transaction_present;
        }
    }
    const auto existing = read_record_from_directory(
        directory.get(), record.transaction_id, policy);
    if (existing.state == NdmsNativeImportWalLoadState::valid) {
        validate_update(*existing.record, record);
    } else if (existing.state == NdmsNativeImportWalLoadState::absent) {
        if (!allow_new_record) {
            throw NdmsNativeImportWalStoreError(
                "Native import WAL update cannot create a transaction");
        }
        if (record.phase != NdmsNativeImportWalPhase::prepared) {
            throw NdmsNativeImportWalStoreError(
                "New native import WAL transaction must start prepared");
        }
        if (before_inventory.items.size() >=
            kNdmsNativeImportWalStoreMaximumRecords) {
            throw NdmsNativeImportWalStoreError(
                "Native import WAL record limit is exhausted");
        }
    } else {
        throw NdmsNativeImportWalStoreError(
            "Native import WAL destination is unsafe or corrupt");
    }

    FileDescriptor temporary;
    std::string temporary_name;
    bool temporary_exists = false;
    bool published = false;
    try {
        temporary_name =
            create_temporary(directory.get(), temporary, policy);
        temporary_exists = true;
#ifdef KEEN_PBR3_TESTING
        inject(policy, NdmsNativeImportWalStoreFaultStage::write);
#endif
        write_all(temporary.get(), body);
#ifdef KEEN_PBR3_TESTING
        inject(policy, NdmsNativeImportWalStoreFaultStage::file_fsync);
#endif
        fsync_exact(temporary.get(), "temporary native import WAL file");
        if (::close(temporary.release()) != 0) {
            throw std::runtime_error(errno_message(
                "Cannot close temporary native import WAL file"));
        }

        // Revalidate the logical compare-and-swap immediately before rename.
        const auto revalidated = read_record_from_directory(
            directory.get(), record.transaction_id, policy);
        if (existing.state != revalidated.state ||
            (existing.record.has_value() != revalidated.record.has_value()) ||
            (existing.record.has_value() &&
             !(*existing.record == *revalidated.record))) {
            throw NdmsNativeImportWalStoreError(
                "Native import WAL destination changed before publication");
        }
#ifdef KEEN_PBR3_TESTING
        inject(policy, NdmsNativeImportWalStoreFaultStage::rename);
#endif
        if (::renameat(directory.get(),
                       temporary_name.c_str(),
                       directory.get(),
                       filename.c_str()) != 0) {
            throw std::runtime_error(
                errno_message("Cannot publish native import WAL file"));
        }
        temporary_exists = false;
        published = true;

        const auto verified = read_record_from_directory(
            directory.get(), record.transaction_id, policy);
        if (verified.state != NdmsNativeImportWalLoadState::valid ||
            !verified.record.has_value() ||
            !(*verified.record == record)) {
            throw NdmsNativeImportWalStoreError(
                "Published native import WAL failed exact verification");
        }
#ifdef KEEN_PBR3_TESTING
        inject(policy, NdmsNativeImportWalStoreFaultStage::directory_fsync);
#endif
        fsync_exact(directory.get(), "native import WAL directory");
    } catch (const std::exception& error) {
        if (temporary_exists) {
            if (::unlinkat(
                    directory.get(), temporary_name.c_str(), 0) == 0) {
                try {
                    fsync_exact(directory.get(),
                                "native import WAL temporary cleanup");
                } catch (...) {
                }
            }
        }
        throw NdmsNativeImportWalStoreWriteError(
            error.what(), published);
    } catch (...) {
        if (temporary_exists) {
            (void)::unlinkat(directory.get(), temporary_name.c_str(), 0);
        }
        throw NdmsNativeImportWalStoreWriteError(
            "Unknown native import WAL publication failure", published);
    }
    return NdmsNativeImportWalAdmissionState::admitted;
}

NdmsNativeImportWalLoadResult NdmsNativeImportWalStore::load(
    const std::string& transaction_id) const {
    if (!valid_transaction_id(transaction_id)) {
        return {
            NdmsNativeImportWalLoadState::identity_mismatch,
            std::nullopt};
    }
    const StorePolicy policy = make_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> lock(store_mutex());
    try {
        auto directory = open_store_directory(
            state_directory_, false, policy);
        DirectoryLock directory_lock(directory.get(), LOCK_SH);
        return read_record_from_directory(
            directory.get(), transaction_id, policy);
    } catch (const DirectoryError& error) {
        return directory_error_result(error);
    } catch (...) {
        return {NdmsNativeImportWalLoadState::io_error, std::nullopt};
    }
}

void NdmsNativeImportWalStore::sweep_orphaned_temporaries() noexcept {
    const StorePolicy policy = make_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    try {
        std::lock_guard<std::mutex> lock(store_mutex());
        auto directory = open_store_directory(
            state_directory_, false, policy);
        DirectoryLock directory_lock(directory.get(), LOCK_EX);
        cleanup_orphaned_temporaries(directory.get(), policy);
    } catch (...) {
        // An absent or unsafe store directory is not this function's problem
        // to report: every other entry point already classifies it.
    }
}

NdmsNativeImportWalInventory NdmsNativeImportWalStore::inventory() const {
    const StorePolicy policy = make_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> lock(store_mutex());
    try {
        auto directory = open_store_directory(
            state_directory_, false, policy);
        DirectoryLock directory_lock(directory.get(), LOCK_SH);
        return inventory_from_directory(directory.get(), policy);
    } catch (const DirectoryError& error) {
        switch (error.kind()) {
        case DirectoryErrorKind::absent:
            return {NdmsNativeImportWalInventoryState::absent, {}};
        case DirectoryErrorKind::unsafe:
            return {NdmsNativeImportWalInventoryState::unsafe_store, {}};
        case DirectoryErrorKind::io:
            return {NdmsNativeImportWalInventoryState::io_error, {}};
        }
    } catch (...) {
    }
    return {NdmsNativeImportWalInventoryState::io_error, {}};
}

NdmsNativeImportWalInventory
NdmsNativeImportWalStore::try_inventory() const {
    const StorePolicy policy = make_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    // Preserve the writer's canonical lock order. Unlike an external gate,
    // this cannot invert store_mutex()/flock or lock a path that was replaced
    // before the authoritative directory walk completed.
    std::unique_lock<std::mutex> lock(
        store_mutex(), std::try_to_lock);
    if (!lock.owns_lock()) {
        return {NdmsNativeImportWalInventoryState::busy, {}};
    }
    try {
        auto directory = open_store_directory(
            state_directory_, false, policy);
        if (::flock(directory.get(), LOCK_SH | LOCK_NB) != 0) {
            return {
                errno == EWOULDBLOCK || errno == EAGAIN
                    ? NdmsNativeImportWalInventoryState::busy
                    : NdmsNativeImportWalInventoryState::io_error,
                {}};
        }
        AdoptedDirectoryLock directory_lock(directory.get());
        return inventory_from_directory(directory.get(), policy);
    } catch (const DirectoryError& error) {
        switch (error.kind()) {
        case DirectoryErrorKind::absent:
            return {NdmsNativeImportWalInventoryState::absent, {}};
        case DirectoryErrorKind::unsafe:
            return {NdmsNativeImportWalInventoryState::unsafe_store, {}};
        case DirectoryErrorKind::io:
            return {NdmsNativeImportWalInventoryState::io_error, {}};
        }
    } catch (...) {
    }
    return {NdmsNativeImportWalInventoryState::io_error, {}};
}

void NdmsNativeImportWalStore::remove_exact(
    const NdmsNativeImportWalRecord& expected) {
    // Validate the expected value without ever accepting caller-provided raw
    // bytes. Its serialized form is intentionally not retained here.
    static_cast<void>(serialize_ndms_native_import_wal(expected));
    const std::string filename = record_filename(expected.transaction_id);
    const StorePolicy policy = make_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> lock(store_mutex());
    FileDescriptor directory;
    try {
        directory = open_store_directory(
            state_directory_, false, policy);
    } catch (const DirectoryError& error) {
        throw NdmsNativeImportWalStoreError(error.what());
    }
    DirectoryLock directory_lock(directory.get(), LOCK_EX);

    require_safe_inventory(
        inventory_from_directory(directory.get(), policy));
    const auto loaded = read_record_from_directory(
        directory.get(), expected.transaction_id, policy);
    if (loaded.state == NdmsNativeImportWalLoadState::absent) {
        // A retry after an uncertain directory fsync makes the visible absence
        // durable before treating exact removal as idempotent.
        fsync_exact(directory.get(), "native import WAL directory");
        return;
    }
    if (loaded.state != NdmsNativeImportWalLoadState::valid ||
        !loaded.record.has_value() ||
        !(*loaded.record == expected)) {
        throw NdmsNativeImportWalStoreError(
            "Native import WAL exact removal precondition failed");
    }

    bool published = false;
    try {
#ifdef KEEN_PBR3_TESTING
        inject(policy, NdmsNativeImportWalStoreFaultStage::remove);
#endif
        if (::unlinkat(directory.get(), filename.c_str(), 0) != 0) {
            throw std::runtime_error(
                errno_message("Cannot remove native import WAL file"));
        }
        published = true;
        const auto absent = read_record_from_directory(
            directory.get(), expected.transaction_id, policy);
        if (absent.state != NdmsNativeImportWalLoadState::absent) {
            throw NdmsNativeImportWalStoreError(
                "Removed native import WAL remains visible");
        }
#ifdef KEEN_PBR3_TESTING
        inject(
            policy,
            NdmsNativeImportWalStoreFaultStage::remove_directory_fsync);
#endif
        fsync_exact(directory.get(), "native import WAL directory");
    } catch (const std::exception& error) {
        throw NdmsNativeImportWalStoreWriteError(
            error.what(), published);
    } catch (...) {
        throw NdmsNativeImportWalStoreWriteError(
            "Unknown native import WAL removal failure", published);
    }
}

const std::filesystem::path&
NdmsNativeImportWalStore::state_directory() const noexcept {
    return state_directory_;
}

const char* ndms_native_import_wal_load_state_name(
    NdmsNativeImportWalLoadState state) noexcept {
    switch (state) {
    case NdmsNativeImportWalLoadState::absent:
        return "absent";
    case NdmsNativeImportWalLoadState::valid:
        return "valid";
    case NdmsNativeImportWalLoadState::unsafe_store:
        return "unsafe_store";
    case NdmsNativeImportWalLoadState::unsafe_entry:
        return "unsafe_entry";
    case NdmsNativeImportWalLoadState::too_large:
        return "too_large";
    case NdmsNativeImportWalLoadState::corrupt_record:
        return "corrupt_record";
    case NdmsNativeImportWalLoadState::identity_mismatch:
        return "identity_mismatch";
    case NdmsNativeImportWalLoadState::io_error:
        return "io_error";
    }
    return "io_error";
}

const char* ndms_native_import_wal_inventory_state_name(
    NdmsNativeImportWalInventoryState state) noexcept {
    switch (state) {
    case NdmsNativeImportWalInventoryState::ready:
        return "ready";
    case NdmsNativeImportWalInventoryState::absent:
        return "absent";
    case NdmsNativeImportWalInventoryState::unsafe_store:
        return "unsafe_store";
    case NdmsNativeImportWalInventoryState::io_error:
        return "io_error";
    case NdmsNativeImportWalInventoryState::busy:
        return "busy";
    case NdmsNativeImportWalInventoryState::directory_limit_exceeded:
        return "directory_limit_exceeded";
    case NdmsNativeImportWalInventoryState::record_limit_exceeded:
        return "record_limit_exceeded";
    }
    return "io_error";
}

} // namespace keen_pbr3
