#include "ndms_native_secret_snapshot.hpp"

#include "ndms_wireguard_identity.hpp"

#include "../crypto/chacha20poly1305.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <signal.h>
#include <stdexcept>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr char kMagic[] = "keen-pbr-secret-snapshot-v1\n";
constexpr std::size_t kMagicBytes = sizeof(kMagic) - 1U;
constexpr std::size_t kMaximumSnapshotPayloadBytes =
    kNdmsNativeTunnelImportMaximumBytes + 128U;
constexpr std::size_t kMaximumSnapshotBytes =
    kMagicBytes + kChaCha20Poly1305NonceBytes +
    kMaximumSnapshotPayloadBytes + kChaCha20Poly1305TagBytes;
constexpr mode_t kSecretDirectoryMode = 0700;
constexpr mode_t kSecretFileMode = 0600;
constexpr std::string_view kSecretTemporaryPrefix{
    ".keen-pbr-secret-snapshot."};

std::mutex secret_store_mutex;
std::atomic<unsigned int> secret_temporary_sequence{0U};
#ifdef KEEN_PBR3_TESTING
std::atomic<std::size_t> secret_result_wipe_count{0U};
#endif

void secure_wipe_bytes(void* pointer, const std::size_t size) noexcept {
    volatile unsigned char* bytes =
        static_cast<volatile unsigned char*>(pointer);
    for (std::size_t index = 0U; index < size; ++index) {
        bytes[index] = 0U;
    }
}

void secure_wipe_string(std::string& value) noexcept {
    if (!value.empty()) secure_wipe_bytes(value.data(), value.size());
    value.clear();
}

void wipe_secret_result(
    std::optional<std::string>& secret) noexcept {
    if (!secret.has_value()) return;
    secure_wipe_string(*secret);
    secret.reset();
#ifdef KEEN_PBR3_TESTING
    secret_result_wipe_count.fetch_add(1U, std::memory_order_relaxed);
#endif
}

bool constant_time_equal(const std::string_view left,
                         const std::string_view right) noexcept {
    const std::size_t maximum = std::max(left.size(), right.size());
    std::size_t difference = left.size() ^ right.size();
    for (std::size_t index = 0U; index < maximum; ++index) {
        const unsigned char left_byte = index < left.size()
            ? static_cast<unsigned char>(left[index]) : 0U;
        const unsigned char right_byte = index < right.size()
            ? static_cast<unsigned char>(right[index]) : 0U;
        difference |= static_cast<std::size_t>(left_byte ^ right_byte);
    }
    return difference == 0U;
}

class WipeString final {
public:
    explicit WipeString(std::string& value) noexcept : value_(value) {}
    ~WipeString() { secure_wipe_string(value_); }
    WipeString(const WipeString&) = delete;
    WipeString& operator=(const WipeString&) = delete;

private:
    std::string& value_;
};

template <std::size_t Size>
class WipeArray final {
public:
    WipeArray() = default;
    ~WipeArray() { secure_wipe_bytes(bytes, Size); }
    WipeArray(const WipeArray&) = delete;
    WipeArray& operator=(const WipeArray&) = delete;
    unsigned char* data() noexcept { return bytes; }
    const unsigned char* data() const noexcept { return bytes; }
    constexpr std::size_t size() const noexcept { return Size; }
    unsigned char bytes[Size]{};
};

class SecretFileDescriptor final {
public:
    explicit SecretFileDescriptor(const int value = -1) noexcept
        : value_(value) {}
    ~SecretFileDescriptor() {
        if (value_ >= 0) (void)::close(value_);
    }
    SecretFileDescriptor(const SecretFileDescriptor&) = delete;
    SecretFileDescriptor& operator=(const SecretFileDescriptor&) = delete;
    SecretFileDescriptor(SecretFileDescriptor&& other) noexcept
        : value_(std::exchange(other.value_, -1)) {}
    SecretFileDescriptor& operator=(SecretFileDescriptor&& other) noexcept {
        if (this == &other) return *this;
        if (value_ >= 0) (void)::close(value_);
        value_ = std::exchange(other.value_, -1);
        return *this;
    }
    int get() const noexcept { return value_; }
    int release() noexcept { return std::exchange(value_, -1); }

private:
    int value_{-1};
};

class SecretDirectoryLock final {
public:
    SecretDirectoryLock(const int descriptor, const int operation)
        : descriptor_(descriptor) {
        while (::flock(descriptor_, operation) != 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(
                "cannot lock native secret directory: " +
                std::string(std::strerror(errno)));
        }
    }
    ~SecretDirectoryLock() {
        if (descriptor_ >= 0) (void)::flock(descriptor_, LOCK_UN);
    }
    SecretDirectoryLock(const SecretDirectoryLock&) = delete;
    SecretDirectoryLock& operator=(const SecretDirectoryLock&) = delete;

private:
    int descriptor_{-1};
};

class SecretDirectoryAbsent final : public std::exception {};

struct SecretStorePolicy final {
    uid_t owner{0};
    gid_t group{0};
    bool require_root_process{true};
#ifdef KEEN_PBR3_TESTING
    std::function<void(NdmsNativeSecretSnapshotStoreFaultStage)>
        fault_injector;
    bool force_portable_linkat{false};
#endif
};

SecretStorePolicy secret_policy(
#ifdef KEEN_PBR3_TESTING
    const NdmsNativeSecretSnapshotStoreTestHooks& hooks
#endif
) {
    SecretStorePolicy policy;
#ifdef KEEN_PBR3_TESTING
    policy.fault_injector = hooks.fault_injector;
    policy.force_portable_linkat = hooks.force_portable_linkat;
    if (hooks.allow_current_process_owner) {
        policy.owner = ::geteuid();
        policy.group = ::getegid();
        policy.require_root_process = false;
    }
#endif
    return policy;
}

#ifdef KEEN_PBR3_TESTING
void inject_secret_fault(
    const SecretStorePolicy& policy,
    const NdmsNativeSecretSnapshotStoreFaultStage stage) {
    if (policy.fault_injector) policy.fault_injector(stage);
}
#endif

std::string error_text(const std::string& prefix) {
    return prefix + ": " + std::strerror(errno);
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

void set_cloexec(const int descriptor) {
#ifndef O_CLOEXEC
    if (::fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
        throw std::runtime_error(
            error_text("cannot protect native secret descriptor"));
    }
#else
    (void)descriptor;
#endif
}

void fsync_exact(const int descriptor, const char* what) {
    while (::fsync(descriptor) != 0) {
        if (errno == EINTR) continue;
        throw std::runtime_error(
            error_text(std::string("cannot fsync ") + what));
    }
}

bool exact_directory(const struct stat& metadata,
                     const SecretStorePolicy& policy) noexcept {
    return S_ISDIR(metadata.st_mode) &&
           metadata.st_uid == policy.owner &&
           metadata.st_gid == policy.group &&
           (metadata.st_mode & 07777) == kSecretDirectoryMode;
}

bool exact_file_links(const struct stat& metadata,
                      const SecretStorePolicy& policy,
                      const nlink_t links) noexcept {
    return S_ISREG(metadata.st_mode) &&
           metadata.st_uid == policy.owner &&
           metadata.st_gid == policy.group &&
           (metadata.st_mode & 07777) == kSecretFileMode &&
           metadata.st_nlink == links;
}

bool exact_file(const struct stat& metadata,
                const SecretStorePolicy& policy) noexcept {
    return exact_file_links(metadata, policy, 1);
}

std::vector<std::string> path_components(
    const std::filesystem::path& path) {
    if (!path.is_absolute() || path.empty() || path == path.root_path()) {
        throw std::runtime_error(
            "native secret store requires an absolute dedicated directory");
    }
    std::vector<std::string> result;
    for (const auto& raw : path.relative_path()) {
        const auto component = raw.string();
        if (component.empty()) continue;
        if (component == "." || component == "..") {
            throw std::runtime_error(
                "native secret path contains an unsafe component");
        }
        result.push_back(component);
    }
    if (result.empty()) {
        throw std::runtime_error(
            "native secret store requires a dedicated directory");
    }
    return result;
}

bool path_is_prefix(const std::filesystem::path& prefix,
                    const std::filesystem::path& value) {
    auto prefix_iterator = prefix.begin();
    auto value_iterator = value.begin();
    while (prefix_iterator != prefix.end() &&
           value_iterator != value.end()) {
        if (*prefix_iterator != *value_iterator) return false;
        ++prefix_iterator;
        ++value_iterator;
    }
    return prefix_iterator == prefix.end();
}

std::string key_filename(const std::filesystem::path& key_path);

void validate_store_paths(
    const std::filesystem::path& key_path,
    const std::filesystem::path& state_directory) {
    (void)key_filename(key_path);
    (void)path_components(key_path.parent_path());
    (void)path_components(state_directory);
    const auto key_directory = key_path.parent_path().lexically_normal();
    const auto snapshot_directory = state_directory.lexically_normal();
    if (key_directory == snapshot_directory ||
        path_is_prefix(key_directory, snapshot_directory) ||
        path_is_prefix(snapshot_directory, key_directory)) {
        throw std::invalid_argument(
            "native secret key and snapshot directories must be separate");
    }
}

SecretFileDescriptor open_directory(
    const std::filesystem::path& path,
    const bool create,
    const SecretStorePolicy& policy) {
    if (policy.require_root_process &&
        (::geteuid() != 0 || ::getegid() != 0)) {
        throw std::runtime_error(
            "native secret storage requires a root process");
    }
    SecretFileDescriptor current(::open("/", directory_flags()));
    if (current.get() < 0) {
        throw std::runtime_error(
            error_text("cannot open native secret path root"));
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
                throw SecretDirectoryAbsent{};
            }
            if (errno != ENOENT || !create || !final) {
                throw std::runtime_error(
                    error_text("cannot inspect native secret directory"));
            }
            if (::mkdirat(current.get(), component.c_str(),
                          kSecretDirectoryMode) != 0) {
                if (errno != EEXIST) {
                    throw std::runtime_error(
                        error_text("cannot create native secret directory"));
                }
            } else {
                created = true;
            }
            if (::fstatat(current.get(), component.c_str(), &before,
                          AT_SYMLINK_NOFOLLOW) != 0) {
                throw std::runtime_error(
                    error_text("cannot inspect created secret directory"));
            }
        }
        if (!S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode)) {
            throw std::runtime_error(
                "native secret path contains a symlink or non-directory");
        }
        SecretFileDescriptor child(
            ::openat(current.get(), component.c_str(), directory_flags()));
        if (child.get() < 0) {
            throw std::runtime_error(
                error_text("cannot open native secret directory"));
        }
        set_cloexec(child.get());
        struct stat opened {};
        if (::fstat(child.get(), &opened) != 0 ||
            opened.st_dev != before.st_dev ||
            opened.st_ino != before.st_ino ||
            !S_ISDIR(opened.st_mode)) {
            throw std::runtime_error(
                "native secret directory changed while opening");
        }
        if (final) {
            if (created) {
                if (::fchown(child.get(), policy.owner, policy.group) != 0 ||
                    ::fchmod(child.get(), kSecretDirectoryMode) != 0) {
                    throw std::runtime_error(
                        error_text("cannot protect native secret directory"));
                }
                fsync_exact(child.get(), "native secret directory");
                fsync_exact(current.get(),
                            "native secret parent directory");
                if (::fstat(child.get(), &opened) != 0) {
                    throw std::runtime_error(
                        error_text("cannot reinspect secret directory"));
                }
            }
            if (!exact_directory(opened, policy)) {
                throw std::runtime_error(
                    "native secret directory is not exact owner-only 0700");
            }
        } else if (policy.require_root_process &&
                   (opened.st_uid != 0 ||
                    (opened.st_mode & 0022) != 0)) {
            throw std::runtime_error(
                "native secret parent is not root protected");
        }
        current = std::move(child);
    }
    return current;
}

enum class SecureReadState { absent, valid, unsafe };

bool claimable_interface(const std::string& name);

enum class SnapshotInventoryState { empty, nonempty, unsafe };

SnapshotInventoryState inspect_snapshot_inventory(
    const int directory,
    const SecretStorePolicy& policy) {
    const int duplicate = ::dup(directory);
    if (duplicate < 0) return SnapshotInventoryState::unsafe;
    DIR* stream = ::fdopendir(duplicate);
    if (stream == nullptr) {
        (void)::close(duplicate);
        return SnapshotInventoryState::unsafe;
    }
    ::rewinddir(stream);
    std::size_t entries = 0U;
    bool any = false;
    bool safe = true;
    while (const auto* item = ::readdir(stream)) {
        const std::string name(item->d_name);
        if (name == "." || name == "..") continue;
        any = true;
        if (++entries > 128U || !claimable_interface(name)) {
            safe = false;
            break;
        }
        struct stat metadata {};
        if (::fstatat(directory, name.c_str(), &metadata,
                      AT_SYMLINK_NOFOLLOW) != 0 ||
            !exact_file(metadata, policy) || metadata.st_size <= 0 ||
            static_cast<std::uint64_t>(metadata.st_size) >
                kMaximumSnapshotBytes) {
            safe = false;
            break;
        }
    }
    ::rewinddir(stream);
    if (::closedir(stream) != 0) safe = false;
    if (!safe) return SnapshotInventoryState::unsafe;
    return any ? SnapshotInventoryState::nonempty
               : SnapshotInventoryState::empty;
}

SecureReadState read_secure_file(
    const int directory,
    const std::string& filename,
    const std::size_t maximum,
    const SecretStorePolicy& policy,
    std::string& output) noexcept {
    secure_wipe_string(output);
    struct stat before {};
    if (::fstatat(directory, filename.c_str(), &before,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT ? SecureReadState::absent
                               : SecureReadState::unsafe;
    }
    if (!exact_file(before, policy) || before.st_size < 0 ||
        static_cast<std::uint64_t>(before.st_size) > maximum) {
        return SecureReadState::unsafe;
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
    SecretFileDescriptor input(
        ::openat(directory, filename.c_str(), flags));
    if (input.get() < 0) return SecureReadState::unsafe;
    try {
        set_cloexec(input.get());
    } catch (...) {
        return SecureReadState::unsafe;
    }
    struct stat opened {};
    if (::fstat(input.get(), &opened) != 0 ||
        !exact_file(opened, policy) ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino ||
        opened.st_size != before.st_size) {
        return SecureReadState::unsafe;
    }
    try {
        output.reserve(static_cast<std::size_t>(opened.st_size));
        std::array<char, 4096U> buffer{};
        while (true) {
            const auto count = ::read(
                input.get(), buffer.data(), buffer.size());
            if (count < 0) {
                if (errno == EINTR) continue;
                secure_wipe_bytes(buffer.data(), buffer.size());
                return SecureReadState::unsafe;
            }
            if (count == 0) {
                secure_wipe_bytes(buffer.data(), buffer.size());
                break;
            }
            if (output.size() + static_cast<std::size_t>(count) > maximum) {
                secure_wipe_bytes(buffer.data(), buffer.size());
                return SecureReadState::unsafe;
            }
            output.append(buffer.data(), static_cast<std::size_t>(count));
            secure_wipe_bytes(buffer.data(), buffer.size());
        }
    } catch (...) {
        secure_wipe_string(output);
        return SecureReadState::unsafe;
    }
    struct stat after {};
    if (::fstat(input.get(), &after) != 0 ||
        !exact_file(after, policy) ||
        after.st_dev != opened.st_dev || after.st_ino != opened.st_ino ||
        after.st_size != opened.st_size ||
        after.st_mtime != opened.st_mtime ||
        after.st_ctime != opened.st_ctime ||
        output.size() != static_cast<std::size_t>(opened.st_size)) {
        secure_wipe_string(output);
        return SecureReadState::unsafe;
    }
    return SecureReadState::valid;
}

bool decimal_text(const std::string_view value) noexcept {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(), [](const char character) {
               return character >= '0' && character <= '9';
           });
}

struct SecretTemporaryIdentity final {
    std::string target;
};

std::optional<SecretTemporaryIdentity> secret_temporary_identity(
    const std::string_view name,
    const std::optional<std::string_view> key_filename) {
    if (name.substr(0U, kSecretTemporaryPrefix.size()) !=
        kSecretTemporaryPrefix) {
        return std::nullopt;
    }
    const auto remainder = name.substr(kSecretTemporaryPrefix.size());
    const auto first = remainder.find('.');
    const auto second = first == std::string_view::npos
        ? std::string_view::npos : remainder.find('.', first + 1U);
    if (first == std::string_view::npos ||
        second == std::string_view::npos || first == 0U ||
        second == first + 1U || second + 1U >= remainder.size() ||
        !decimal_text(remainder.substr(0U, first)) ||
        !decimal_text(remainder.substr(
            first + 1U, second - first - 1U))) {
        return std::nullopt;
    }
    std::string target(remainder.substr(second + 1U));
    const bool target_valid = key_filename
        ? target == *key_filename
        : claimable_interface(target);
    if (!target_valid) return std::nullopt;
    return SecretTemporaryIdentity{std::move(target)};
}

bool cleanup_secret_temporaries(
    const int directory,
    const SecretStorePolicy& policy,
    const std::optional<std::string_view> key_filename) {
    const int duplicate = ::dup(directory);
    if (duplicate < 0) return false;
    DIR* stream = ::fdopendir(duplicate);
    if (stream == nullptr) {
        (void)::close(duplicate);
        return false;
    }
    ::rewinddir(stream);
    bool safe = true;
    bool changed = false;
    std::size_t entries = 0U;
    while (const auto* item = ::readdir(stream)) {
        const std::string name(item->d_name);
        if (name == "." || name == "..") continue;
        if (++entries > 256U) {
            safe = false;
            break;
        }
        const bool starts_temporary =
            std::string_view(name).substr(
                0U, kSecretTemporaryPrefix.size()) ==
            kSecretTemporaryPrefix;
        const auto temporary = secret_temporary_identity(
            name, key_filename);
        if (!temporary) {
            const bool allowed_published = key_filename
                ? name == *key_filename
                : claimable_interface(name);
            if (starts_temporary || !allowed_published) {
                safe = false;
                break;
            }
            continue;
        }
        struct stat temporary_metadata {};
        if (::fstatat(directory, name.c_str(), &temporary_metadata,
                      AT_SYMLINK_NOFOLLOW) != 0 ||
            (!exact_file_links(temporary_metadata, policy, 1) &&
             !exact_file_links(temporary_metadata, policy, 2))) {
            safe = false;
            break;
        }
        if (temporary_metadata.st_nlink == 2) {
            struct stat target_metadata {};
            if (::fstatat(directory, temporary->target.c_str(),
                          &target_metadata, AT_SYMLINK_NOFOLLOW) != 0 ||
                !exact_file_links(target_metadata, policy, 2) ||
                target_metadata.st_dev != temporary_metadata.st_dev ||
                target_metadata.st_ino != temporary_metadata.st_ino) {
                safe = false;
                break;
            }
        }
        if (::unlinkat(directory, name.c_str(), 0) != 0) {
            safe = false;
            break;
        }
        changed = true;
        if (temporary_metadata.st_nlink == 2) {
            std::string verified;
            WipeString verified_guard(verified);
            const auto maximum = key_filename
                ? 4096U : kMaximumSnapshotBytes;
            if (read_secure_file(
                    directory, temporary->target, maximum,
                    policy, verified) != SecureReadState::valid ||
                (key_filename &&
                 verified.size() != kChaCha20Poly1305KeyBytes)) {
                safe = false;
                break;
            }
        }
    }
    if (::closedir(stream) != 0) safe = false;
    if (safe && changed) {
        try {
            fsync_exact(directory, "native secret directory");
        } catch (...) {
            safe = false;
        }
    }
    return safe;
}

void write_all(const int descriptor, const std::string_view body) {
    std::size_t offset = 0U;
    while (offset < body.size()) {
        const auto count = ::write(
            descriptor, body.data() + offset, body.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(
                error_text("cannot write native secret file"));
        }
        if (count == 0) {
            throw std::runtime_error(
                "cannot write native secret file: short write");
        }
        offset += static_cast<std::size_t>(count);
    }
}

std::string create_temporary(
    const int directory,
    SecretFileDescriptor& output,
    const std::string& target,
    const SecretStorePolicy& policy) {
    for (unsigned int attempt = 0U; attempt < 128U; ++attempt) {
        const auto sequence = secret_temporary_sequence.fetch_add(
            1U, std::memory_order_relaxed);
        const auto name = std::string{kSecretTemporaryPrefix} +
                          std::to_string(::getpid()) + "." +
                          std::to_string(sequence) + "." + target;
        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        output = SecretFileDescriptor(
            ::openat(directory, name.c_str(), flags, kSecretFileMode));
        if (output.get() < 0) {
            if (errno == EEXIST) continue;
            throw std::runtime_error(
                error_text("cannot create temporary native secret file"));
        }
        set_cloexec(output.get());
        if (::fchown(output.get(), policy.owner, policy.group) != 0 ||
            ::fchmod(output.get(), kSecretFileMode) != 0) {
            throw std::runtime_error(
                error_text("cannot protect temporary native secret file"));
        }
        struct stat metadata {};
        if (::fstat(output.get(), &metadata) != 0 ||
            !exact_file(metadata, policy)) {
            throw std::runtime_error(
                "temporary native secret file metadata is unsafe");
        }
        return name;
    }
    throw std::runtime_error(
        "temporary native secret namespace is exhausted");
}

int rename_noreplace(
    const int directory,
    const char* old_name,
    const char* new_name) noexcept {
#if defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0U)
#endif
    return static_cast<int>(::syscall(
        SYS_renameat2, directory, old_name,
        directory, new_name, RENAME_NOREPLACE));
#else
    (void)directory;
    (void)old_name;
    (void)new_name;
    errno = ENOTSUP;
    return -1;
#endif
}

void write_secure_file_locked(
    const int directory,
    const std::string& filename,
    const std::string_view body,
    const bool no_clobber,
    const SecretStorePolicy& policy) {
    SecretFileDescriptor temporary;
    const auto temporary_name = create_temporary(
        directory, temporary, filename, policy);
    bool temporary_exists = true;
    try {
        write_all(temporary.get(), body);
        fsync_exact(temporary.get(), "temporary native secret file");
        if (::close(temporary.release()) != 0) {
            throw std::runtime_error(
                error_text("cannot close temporary native secret file"));
        }
#ifdef KEEN_PBR3_TESTING
        inject_secret_fault(
            policy,
            NdmsNativeSecretSnapshotStoreFaultStage::
                pre_publish_after_file_fsync);
#endif
        int result = no_clobber
            ?
#ifdef KEEN_PBR3_TESTING
              (policy.force_portable_linkat
                   ? (errno = ENOTSUP, -1)
                   : rename_noreplace(directory, temporary_name.c_str(),
                                      filename.c_str()))
#else
              rename_noreplace(directory, temporary_name.c_str(),
                               filename.c_str())
#endif
            : ::renameat(directory, temporary_name.c_str(),
                         directory, filename.c_str());
        if (no_clobber && result != 0 &&
            (errno == ENOSYS || errno == EINVAL || errno == ENOTSUP ||
             errno == EOPNOTSUPP)) {
            result = ::linkat(
                directory, temporary_name.c_str(),
                directory, filename.c_str(), 0);
            if (result == 0) {
                // The target is committed but has two names until the
                // temporary link is retired. On any failure, leave the exact
                // pair for bounded EX-lock recovery instead of guessing.
                temporary_exists = false;
#ifdef KEEN_PBR3_TESTING
                inject_secret_fault(
                    policy,
                    NdmsNativeSecretSnapshotStoreFaultStage::
                        post_link_before_unlink);
#endif
                if (::unlinkat(
                        directory, temporary_name.c_str(), 0) != 0) {
                    throw std::runtime_error(
                        error_text(
                            "cannot retire linked native secret temporary"));
                }
            }
        }
        if (result != 0) {
            throw std::runtime_error(
                error_text("cannot publish native secret file"));
        }
        temporary_exists = false;
        std::string verified;
        WipeString verified_guard(verified);
        if (read_secure_file(directory, filename, body.size(), policy,
                             verified) != SecureReadState::valid ||
            verified != body) {
            throw std::runtime_error(
                "published native secret file failed exact verification");
        }
#ifdef KEEN_PBR3_TESTING
        inject_secret_fault(
            policy,
            NdmsNativeSecretSnapshotStoreFaultStage::
                post_rename_directory_fsync);
#endif
        fsync_exact(directory, "native secret directory");
    } catch (...) {
        if (temporary_exists) {
            (void)::unlinkat(directory, temporary_name.c_str(), 0);
        }
        throw;
    }
}

bool read_urandom(unsigned char* output, const std::size_t size) noexcept {
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    SecretFileDescriptor random(::open("/dev/urandom", flags));
    if (random.get() < 0) return false;
    try {
        set_cloexec(random.get());
    } catch (...) {
        return false;
    }
    std::size_t offset = 0U;
    while (offset < size) {
        const auto count = ::read(random.get(), output + offset,
                                  size - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (count == 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    return true;
}

bool claimable_interface(const std::string& name) {
    const auto identity = parse_ndms_wireguard_identity(name);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity) &&
           identity->canonical_name() == name;
}

bool lower_hex(const std::string_view value) noexcept {
    return std::all_of(value.begin(), value.end(), [](const char character) {
        return (character >= '0' && character <= '9') ||
               (character >= 'a' && character <= 'f');
    });
}

bool identity_valid(const std::string& interface_name,
                    const std::string& transaction_id,
                    const std::string& marker) {
    return claimable_interface(interface_name) &&
           transaction_id.size() == 32U && lower_hex(transaction_id) &&
           marker == "kpbr-ni-v1-" + transaction_id;
}

std::string bind_aad(const std::string& interface_name,
                     const std::string& transaction_id,
                     const std::string& marker) {
    std::string aad = "keen-pbr.ndms-native-secret.v1";
    for (const auto* part : {&interface_name, &transaction_id, &marker}) {
        aad.push_back('\0');
        aad += std::to_string(part->size());
        aad.push_back('\0');
        aad += *part;
    }
    return aad;
}

std::string key_filename(const std::filesystem::path& key_path) {
    const auto filename = key_path.filename().string();
    if (filename.empty() || filename == "." || filename == ".." ||
        filename.size() > 128U || key_path.parent_path().empty() ||
        filename.rfind(kSecretTemporaryPrefix, 0U) == 0U ||
        !std::all_of(
            filename.begin(), filename.end(), [](const char character) {
                return (character >= 'a' && character <= 'z') ||
                       (character >= 'A' && character <= 'Z') ||
                       (character >= '0' && character <= '9') ||
                       character == '.' || character == '_' ||
                       character == '-';
            })) {
        throw std::runtime_error("native secret master key path is invalid");
    }
    return filename;
}

bool load_or_create_key(
    const std::filesystem::path& path,
    WipeArray<kChaCha20Poly1305KeyBytes>& key,
    const bool allow_create,
    const SecretStorePolicy& policy) {
    SecretFileDescriptor directory;
    try {
        directory = open_directory(
            path.parent_path(), allow_create, policy);
    } catch (const SecretDirectoryAbsent&) {
        return false;
    }
    SecretDirectoryLock lock(directory.get(), LOCK_EX);
    const auto filename = key_filename(path);
    if (!cleanup_secret_temporaries(
            directory.get(), policy, filename)) {
        throw std::runtime_error(
            "native secret key directory inventory is unsafe");
    }
    std::string bytes;
    WipeString bytes_guard(bytes);
    auto state = read_secure_file(
        directory.get(), filename, 4096U, policy, bytes);
    if (state == SecureReadState::absent && allow_create) {
        WipeArray<kChaCha20Poly1305KeyBytes> candidate;
        if (!read_urandom(candidate.data(), candidate.size())) {
            return false;
        }
        std::string candidate_body(
            reinterpret_cast<const char*>(candidate.data()),
            candidate.size());
        WipeString candidate_guard(candidate_body);
        write_secure_file_locked(
            directory.get(), filename, candidate_body,
            /*no_clobber=*/true, policy);
        state = read_secure_file(
            directory.get(), filename, 4096U, policy, bytes);
    }
    if (state != SecureReadState::valid ||
        bytes.size() != key.size()) {
        return false;
    }
    // Establish durability for a key installed by an earlier process before
    // any new ciphertext is allowed to depend on it.
    fsync_exact(directory.get(), "native secret key directory");
    std::memcpy(key.data(), bytes.data(), key.size());
    return true;
}

NdmsNativeSecretReadResult read_snapshot_locked(
    const int state_directory,
    const std::filesystem::path& key_path,
    const std::string& interface_name,
    const std::string& transaction_id,
    const std::string& marker,
    const SecretStorePolicy& policy) {
    NdmsNativeSecretReadResult result;
    std::string body;
    WipeString body_guard(body);
    const auto state = read_secure_file(
        state_directory, interface_name, kMaximumSnapshotBytes,
        policy, body);
    if (state == SecureReadState::absent) {
        result.state = NdmsNativeSecretReadState::absent;
        return result;
    }
    if (state != SecureReadState::valid ||
        body.size() < kMagicBytes + kChaCha20Poly1305NonceBytes +
                          kChaCha20Poly1305TagBytes ||
        std::memcmp(body.data(), kMagic, kMagicBytes) != 0) {
        return result;
    }

    WipeArray<kChaCha20Poly1305KeyBytes> key;
    if (!load_or_create_key(
            key_path, key, /*allow_create=*/false, policy)) {
        return result;
    }
    WipeArray<kChaCha20Poly1305NonceBytes> nonce;
    std::memcpy(nonce.data(), body.data() + kMagicBytes,
                nonce.size());
    auto aad = bind_aad(interface_name, transaction_id, marker);
    WipeString aad_guard(aad);
    auto opened = chacha20poly1305_open(
        key.bytes, nonce.bytes, aad,
        std::string_view(body).substr(kMagicBytes + nonce.size()));
    if (!opened) return result;
    result.secret = std::move(*opened);
    result.state = NdmsNativeSecretReadState::valid;
    return result;
}

} // namespace

NdmsNativeSecretReadResult::~NdmsNativeSecretReadResult() noexcept {
    wipe_secret_result(secret);
}

NdmsNativeSecretReadResult::NdmsNativeSecretReadResult(
    NdmsNativeSecretReadResult&& other) noexcept
    : state(other.state), secret(std::move(other.secret)) {
    wipe_secret_result(other.secret);
    other.state = NdmsNativeSecretReadState::unreadable;
}

NdmsNativeSecretReadResult& NdmsNativeSecretReadResult::operator=(
    NdmsNativeSecretReadResult&& other) noexcept {
    if (this == &other) return *this;
    wipe_secret_result(secret);
    state = other.state;
    secret = std::move(other.secret);
    wipe_secret_result(other.secret);
    other.state = NdmsNativeSecretReadState::unreadable;
    return *this;
}

#ifdef KEEN_PBR3_TESTING
void reset_ndms_native_secret_result_wipe_count_for_testing() noexcept {
    secret_result_wipe_count.store(0U, std::memory_order_relaxed);
}

std::size_t ndms_native_secret_result_wipe_count_for_testing() noexcept {
    return secret_result_wipe_count.load(std::memory_order_relaxed);
}
#endif

NdmsNativeSecretSnapshotStore::NdmsNativeSecretSnapshotStore(
    std::filesystem::path key_path,
    std::filesystem::path state_directory)
    : key_path_(std::move(key_path)),
      state_directory_(std::move(state_directory)) {
    validate_store_paths(key_path_, state_directory_);
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeSecretSnapshotStore::NdmsNativeSecretSnapshotStore(
    std::filesystem::path key_path,
    std::filesystem::path state_directory,
    NdmsNativeSecretSnapshotStoreTestHooks hooks)
    : key_path_(std::move(key_path)),
      state_directory_(std::move(state_directory)),
      test_hooks_(std::move(hooks)) {
    validate_store_paths(key_path_, state_directory_);
}
#endif

void NdmsNativeSecretSnapshotStore::publish(
    const std::string& interface_name,
    const std::string& transaction_id,
    const std::string& marker,
    const std::string& secret) {
    publish_payload(interface_name, transaction_id, marker, secret);
}

void NdmsNativeSecretSnapshotStore::publish_panel_delete_snapshot(
    const std::string& interface_name,
    const std::string& transaction_id,
    const std::string& marker,
    NdmsNativePanelDeleteSnapshot snapshot) {
    if (snapshot.marker() != marker) {
        throw std::runtime_error(
            "panel delete snapshot marker does not match its identity");
    }
    publish_payload(interface_name, transaction_id, marker,
                    snapshot.sealed_payload_for_store());
}

void NdmsNativeSecretSnapshotStore::publish_payload(
    const std::string& interface_name,
    const std::string& transaction_id,
    const std::string& marker,
    const std::string_view secret) {
    if (!identity_valid(interface_name, transaction_id, marker) ||
        secret.empty() || secret.size() > kMaximumSnapshotPayloadBytes) {
        throw std::runtime_error(
            "native secret snapshot is not publishable");
    }
    const auto policy = secret_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(secret_store_mutex);
    auto directory = open_directory(state_directory_, true, policy);
    SecretDirectoryLock directory_lock(directory.get(), LOCK_EX);
    if (!cleanup_secret_temporaries(
            directory.get(), policy, std::nullopt)) {
        throw std::runtime_error(
            "native secret snapshot directory inventory is unsafe");
    }
    const auto inventory = inspect_snapshot_inventory(
        directory.get(), policy);
    if (inventory == SnapshotInventoryState::unsafe) {
        throw std::runtime_error(
            "native secret snapshot inventory is unsafe");
    }
    WipeArray<kChaCha20Poly1305KeyBytes> key;
    if (!load_or_create_key(
            key_path_, key, /*allow_create=*/false, policy)) {
        if (inventory != SnapshotInventoryState::empty ||
            !load_or_create_key(
                key_path_, key, /*allow_create=*/true, policy)) {
            throw std::runtime_error(
                "native secret master key is unavailable and must not be "
                "regenerated while snapshots exist");
        }
    }
    std::string existing_ciphertext;
    WipeString existing_ciphertext_guard(existing_ciphertext);
    const auto existing = read_secure_file(
        directory.get(), interface_name, kMaximumSnapshotBytes,
        policy, existing_ciphertext);
    if (existing == SecureReadState::unsafe) {
        throw std::runtime_error(
            "existing native secret snapshot is unsafe and immutable");
    }
    if (existing == SecureReadState::valid) {
        auto opened = read_snapshot_locked(
            directory.get(), key_path_, interface_name,
            transaction_id, marker, policy);
        if (opened.state != NdmsNativeSecretReadState::valid ||
            !opened.secret.has_value() ||
            !constant_time_equal(*opened.secret, secret)) {
            if (opened.secret) secure_wipe_string(*opened.secret);
            throw std::runtime_error(
                "existing native secret snapshot differs and is immutable");
        }
        secure_wipe_string(*opened.secret);
        // A prior publish may have installed this exact immutable file and
        // then failed while syncing the directory.  Exact idempotence is not
        // enough to establish durability; repair that boundary before
        // reporting success.
        fsync_exact(directory.get(), "native secret directory");
        return;
    }

    WipeArray<kChaCha20Poly1305NonceBytes> nonce;
    if (!read_urandom(nonce.data(), nonce.size())) {
        throw std::runtime_error(
            "kernel randomness is unavailable for the snapshot nonce");
    }
    auto aad = bind_aad(interface_name, transaction_id, marker);
    WipeString aad_guard(aad);
    auto ciphertext = chacha20poly1305_seal(
        key.bytes, nonce.bytes, aad, secret);
    WipeString ciphertext_guard(ciphertext);
    std::string body(kMagic, kMagicBytes);
    WipeString body_guard(body);
    body.append(reinterpret_cast<const char*>(nonce.data()),
                nonce.size());
    body.append(ciphertext);
    write_secure_file_locked(
        directory.get(), interface_name, body,
        /*no_clobber=*/true, policy);
}

NdmsNativeSecretReadResult NdmsNativeSecretSnapshotStore::read(
    const std::string& interface_name,
    const std::string& transaction_id,
    const std::string& marker) const {
    NdmsNativeSecretReadResult result;
    if (!identity_valid(interface_name, transaction_id, marker)) {
        return result;
    }
    const auto policy = secret_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(secret_store_mutex);
    try {
        auto directory = open_directory(
            state_directory_, false, policy);
        SecretDirectoryLock directory_lock(directory.get(), LOCK_SH);
        return read_snapshot_locked(
            directory.get(), key_path_, interface_name,
            transaction_id, marker, policy);
    } catch (const SecretDirectoryAbsent&) {
        result.state = NdmsNativeSecretReadState::absent;
    } catch (...) {
    }
    return result;
}

NdmsNativePanelDeleteSnapshotReadResult
NdmsNativeSecretSnapshotStore::read_panel_delete_snapshot(
    const std::string& interface_name,
    const std::string& transaction_id,
    const std::string& marker) const {
    NdmsNativePanelDeleteSnapshotReadResult result;
    auto raw = read(interface_name, transaction_id, marker);
    result.state = raw.state;
    if (raw.state != NdmsNativeSecretReadState::valid ||
        !raw.secret.has_value()) {
        return result;
    }
    try {
        result.snapshot.emplace(
            NdmsNativePanelDeleteSnapshot::from_sealed_payload(
                std::move(*raw.secret), marker));
        raw.secret.reset();
        result.state = NdmsNativeSecretReadState::valid;
    } catch (...) {
        if (raw.secret) secure_wipe_string(*raw.secret);
        raw.secret.reset();
        result.snapshot.reset();
        result.state = NdmsNativeSecretReadState::unreadable;
    }
    return result;
}

bool NdmsNativeSecretSnapshotStore::remove_panel_delete_snapshot_exact(
    const std::string& interface_name,
    const std::string& transaction_id,
    const std::string& marker,
    const std::string& expected_canonical_revision) {
    if (!identity_valid(interface_name, transaction_id, marker) ||
        expected_canonical_revision.size() !=
            std::string_view{"ndms-native-import-v1-"}.size() + 64U ||
        expected_canonical_revision.rfind(
            "ndms-native-import-v1-", 0U) != 0U ||
        !lower_hex(std::string_view(expected_canonical_revision).substr(
            std::string_view{"ndms-native-import-v1-"}.size()))) {
        return false;
    }
    const auto policy = secret_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(secret_store_mutex);
    try {
        auto directory = open_directory(
            state_directory_, false, policy);
        SecretDirectoryLock directory_lock(directory.get(), LOCK_EX);
        if (!cleanup_secret_temporaries(
                directory.get(), policy, std::nullopt)) {
            return false;
        }
        const auto matches_expected = [&]() {
            auto current = read_snapshot_locked(
                directory.get(), key_path_, interface_name,
                transaction_id, marker, policy);
            if (current.state != NdmsNativeSecretReadState::valid ||
                !current.secret.has_value()) {
                return false;
            }
            try {
                auto typed =
                    NdmsNativePanelDeleteSnapshot::from_sealed_payload(
                        std::move(*current.secret), marker);
                current.secret.reset();
                return typed.canonical_revision() ==
                       expected_canonical_revision;
            } catch (...) {
                if (current.secret) {
                    secure_wipe_string(*current.secret);
                }
                return false;
            }
        };
        if (!matches_expected()) return false;
#ifdef KEEN_PBR3_TESTING
        inject_secret_fault(
            policy,
            NdmsNativeSecretSnapshotStoreFaultStage::
                before_remove_content_recheck);
#endif
        if (!matches_expected()) return false;
        if (::unlinkat(directory.get(), interface_name.c_str(), 0) != 0) {
            return false;
        }
#ifdef KEEN_PBR3_TESTING
        inject_secret_fault(
            policy,
            NdmsNativeSecretSnapshotStoreFaultStage::
                post_unlink_directory_fsync);
#endif
        fsync_exact(directory.get(), "native secret directory");
        std::string ignored;
        WipeString ignored_guard(ignored);
        return read_secure_file(
                   directory.get(), interface_name,
                   kMaximumSnapshotBytes, policy, ignored) ==
               SecureReadState::absent;
    } catch (...) {
        return false;
    }
}

bool NdmsNativeSecretSnapshotStore::ensure_absence_durable(
    const std::string& interface_name) {
    if (!claimable_interface(interface_name)) return false;
    const auto policy = secret_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(secret_store_mutex);
    try {
        auto directory = open_directory(
            state_directory_, true, policy);
        SecretDirectoryLock directory_lock(directory.get(), LOCK_EX);
        if (!cleanup_secret_temporaries(
                directory.get(), policy, std::nullopt)) {
            return false;
        }
        std::string ignored;
        WipeString ignored_guard(ignored);
        if (read_secure_file(
                directory.get(), interface_name,
                kMaximumSnapshotBytes, policy, ignored) !=
            SecureReadState::absent) {
            return false;
        }
#ifdef KEEN_PBR3_TESTING
        inject_secret_fault(
            policy,
            NdmsNativeSecretSnapshotStoreFaultStage::
                absence_directory_fsync);
#endif
        fsync_exact(directory.get(), "native secret directory");
        return read_secure_file(
                   directory.get(), interface_name,
                   kMaximumSnapshotBytes, policy, ignored) ==
               SecureReadState::absent;
    } catch (...) {
        return false;
    }
}

const char* ndms_native_secret_read_state_name(
    const NdmsNativeSecretReadState state) noexcept {
    switch (state) {
    case NdmsNativeSecretReadState::absent:
        return "absent";
    case NdmsNativeSecretReadState::valid:
        return "valid";
    case NdmsNativeSecretReadState::unreadable:
        return "unreadable";
    }
    return "unreadable";
}

} // namespace keen_pbr3
