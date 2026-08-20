#include "ndms_native_ownership_store.hpp"

#include "ndms_wireguard_identity.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr const char* kHeader = "keen-pbr-native-ownership-v2";
constexpr std::size_t kMaximumRecordBytes = 4096U;
constexpr mode_t kOwnershipDirectoryMode = 0700;
constexpr mode_t kOwnershipFileMode = 0600;
constexpr std::string_view kOwnershipTemporaryPrefix{
    ".keen-pbr-ownership-tmp-"};

std::mutex ownership_store_mutex;
std::atomic<std::uint64_t> ownership_temporary_sequence{0U};

class OwnershipFileDescriptor final {
public:
    explicit OwnershipFileDescriptor(const int value = -1) noexcept
        : value_(value) {}
    ~OwnershipFileDescriptor() {
        if (value_ >= 0) (void)::close(value_);
    }
    OwnershipFileDescriptor(const OwnershipFileDescriptor&) = delete;
    OwnershipFileDescriptor& operator=(const OwnershipFileDescriptor&) =
        delete;
    OwnershipFileDescriptor(OwnershipFileDescriptor&& other) noexcept
        : value_(std::exchange(other.value_, -1)) {}
    OwnershipFileDescriptor& operator=(
        OwnershipFileDescriptor&& other) noexcept {
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

class OwnershipDirectoryLock final {
public:
    OwnershipDirectoryLock(const int descriptor, const int operation)
        : descriptor_(descriptor) {
        while (::flock(descriptor_, operation) != 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(
                std::string("cannot lock native ownership directory: ") +
                std::strerror(errno));
        }
    }
    ~OwnershipDirectoryLock() {
        if (descriptor_ >= 0) (void)::flock(descriptor_, LOCK_UN);
    }
    OwnershipDirectoryLock(const OwnershipDirectoryLock&) = delete;
    OwnershipDirectoryLock& operator=(const OwnershipDirectoryLock&) =
        delete;

private:
    int descriptor_{-1};
};

class OwnershipDirectoryAbsent final : public std::exception {};

struct OwnershipStorePolicy final {
    uid_t owner{0};
    gid_t group{0};
    bool require_root_process{true};
#ifdef KEEN_PBR3_TESTING
    std::function<void(NdmsNativeOwnershipStoreFaultStage)> fault_injector;
    bool force_portable_linkat{false};
#endif
};

OwnershipStorePolicy ownership_policy(
#ifdef KEEN_PBR3_TESTING
    const NdmsNativeOwnershipStoreTestHooks& hooks
#endif
) {
    OwnershipStorePolicy policy;
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
void inject_ownership_fault(
    const OwnershipStorePolicy& policy,
    const NdmsNativeOwnershipStoreFaultStage stage) {
    if (policy.fault_injector) policy.fault_injector(stage);
}
#endif

std::string ownership_error(const std::string& prefix) {
    return prefix + ": " + std::strerror(errno);
}

void set_cloexec(const int descriptor) {
#ifndef O_CLOEXEC
    if (::fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
        throw std::runtime_error(
            ownership_error("cannot protect native ownership descriptor"));
    }
#else
    (void)descriptor;
#endif
}

void fsync_exact(const int descriptor, const char* what) {
    while (::fsync(descriptor) != 0) {
        if (errno == EINTR) continue;
        throw std::runtime_error(
            ownership_error(std::string("cannot fsync ") + what));
    }
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

bool exact_directory(const struct stat& metadata,
                     const OwnershipStorePolicy& policy) noexcept {
    return S_ISDIR(metadata.st_mode) && metadata.st_uid == policy.owner &&
           metadata.st_gid == policy.group &&
           (metadata.st_mode & 07777) == kOwnershipDirectoryMode;
}

bool exact_file_links(const struct stat& metadata,
                      const OwnershipStorePolicy& policy,
                      const nlink_t links) noexcept {
    return S_ISREG(metadata.st_mode) && metadata.st_uid == policy.owner &&
           metadata.st_gid == policy.group &&
           (metadata.st_mode & 07777) == kOwnershipFileMode &&
           metadata.st_nlink == links;
}

bool exact_file(const struct stat& metadata,
                const OwnershipStorePolicy& policy) noexcept {
    return exact_file_links(metadata, policy, 1);
}

std::vector<std::string> path_components(
    const std::filesystem::path& path) {
    if (!path.is_absolute() || path.empty() || path == path.root_path()) {
        throw std::runtime_error(
            "native ownership store requires an absolute dedicated directory");
    }
    std::vector<std::string> result;
    for (const auto& raw : path.relative_path()) {
        const auto component = raw.string();
        if (component.empty()) continue;
        if (component == "." || component == "..") {
            throw std::runtime_error(
                "native ownership path contains an unsafe component");
        }
        result.push_back(component);
    }
    if (result.empty()) {
        throw std::runtime_error(
            "native ownership store requires a dedicated directory");
    }
    return result;
}

OwnershipFileDescriptor open_directory(
    const std::filesystem::path& path,
    const bool create,
    const OwnershipStorePolicy& policy) {
    if (policy.require_root_process &&
        (::geteuid() != 0 || ::getegid() != 0)) {
        throw std::runtime_error(
            "native ownership storage requires a root process");
    }
    OwnershipFileDescriptor current(::open("/", directory_flags()));
    if (current.get() < 0) {
        throw std::runtime_error(
            ownership_error("cannot open native ownership path root"));
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
                throw OwnershipDirectoryAbsent{};
            }
            if (errno != ENOENT || !create || !final) {
                throw std::runtime_error(
                    ownership_error(
                        "cannot inspect native ownership directory"));
            }
            if (::mkdirat(current.get(), component.c_str(),
                          kOwnershipDirectoryMode) != 0) {
                if (errno != EEXIST) {
                    throw std::runtime_error(
                        ownership_error(
                            "cannot create native ownership directory"));
                }
            } else {
                created = true;
            }
            if (::fstatat(current.get(), component.c_str(), &before,
                          AT_SYMLINK_NOFOLLOW) != 0) {
                throw std::runtime_error(
                    ownership_error(
                        "cannot inspect created ownership directory"));
            }
        }
        if (!S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode)) {
            throw std::runtime_error(
                "native ownership path contains a symlink or non-directory");
        }
        OwnershipFileDescriptor child(
            ::openat(current.get(), component.c_str(), directory_flags()));
        if (child.get() < 0) {
            throw std::runtime_error(
                ownership_error("cannot open native ownership directory"));
        }
        set_cloexec(child.get());
        struct stat opened {};
        if (::fstat(child.get(), &opened) != 0 ||
            opened.st_dev != before.st_dev ||
            opened.st_ino != before.st_ino || !S_ISDIR(opened.st_mode)) {
            throw std::runtime_error(
                "native ownership directory changed while opening");
        }
        if (final) {
            if (created) {
                if (::fchown(child.get(), policy.owner, policy.group) != 0 ||
                    ::fchmod(child.get(), kOwnershipDirectoryMode) != 0) {
                    throw std::runtime_error(
                        ownership_error(
                            "cannot protect native ownership directory"));
                }
                fsync_exact(child.get(), "native ownership directory");
                fsync_exact(current.get(),
                            "native ownership parent directory");
                if (::fstat(child.get(), &opened) != 0) {
                    throw std::runtime_error(
                        ownership_error(
                            "cannot reinspect ownership directory"));
                }
            }
            if (!exact_directory(opened, policy)) {
                throw std::runtime_error(
                    "native ownership directory is not exact owner-only 0700");
            }
        } else if (policy.require_root_process &&
                   (opened.st_uid != 0 || (opened.st_mode & 0022) != 0)) {
            throw std::runtime_error(
                "native ownership parent is not root protected");
        }
        current = std::move(child);
    }
    return current;
}

bool lower_hex(const std::string_view value,
               const std::size_t size) noexcept {
    return value.size() == size &&
           std::all_of(value.begin(), value.end(), [](const char ch) {
               return (ch >= '0' && ch <= '9') ||
                      (ch >= 'a' && ch <= 'f');
           });
}

bool rci_full_revision(const std::string_view value) noexcept {
    constexpr std::string_view prefix{"ndms-rci-full-v1-"};
    return value.size() == prefix.size() + 64U &&
           value.substr(0U, prefix.size()) == prefix &&
           lower_hex(value.substr(prefix.size()), 64U);
}

bool snapshot_revision(const std::string_view value) noexcept {
    constexpr std::string_view prefix{"ndms-native-import-v1-"};
    return value.size() == prefix.size() + 64U &&
           value.substr(0U, prefix.size()) == prefix &&
           lower_hex(value.substr(prefix.size()), 64U);
}

bool claimable_interface(const std::string& name) {
    const auto identity = parse_ndms_wireguard_identity(name);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity) &&
           identity->canonical_name() == name;
}

bool record_fields_valid(const NdmsNativeOwnershipRecord& record) {
    return (record.kind == NdmsNativeTunnelImportKind::wireguard ||
            record.kind ==
                NdmsNativeTunnelImportKind::amnezia_wireguard) &&
            claimable_interface(record.interface_name) &&
            lower_hex(record.transaction_id, 32U) &&
            record.marker == "kpbr-ni-v1-" + record.transaction_id &&
            snapshot_revision(record.snapshot_revision) &&
            rci_full_revision(record.target_full_revision);
}

void update_field(Sha256& hasher, const std::string_view value) {
    const auto size = static_cast<std::uint64_t>(value.size());
    unsigned char length[8];
    for (std::size_t index = 0U; index < 8U; ++index) {
        length[index] =
            static_cast<unsigned char>(size >> (56U - index * 8U));
    }
    hasher.update(reinterpret_cast<const char*>(length), sizeof(length));
    hasher.update(value.data(), value.size());
}

const char* kind_name(const NdmsNativeTunnelImportKind kind) {
    if (kind == NdmsNativeTunnelImportKind::wireguard) {
        return "wireguard";
    }
    if (kind == NdmsNativeTunnelImportKind::amnezia_wireguard) {
        return "amnezia_wireguard";
    }
    throw std::runtime_error("native ownership kind is invalid");
}

std::string serialize(const NdmsNativeOwnershipRecord& record) {
    std::ostringstream body;
    body << kHeader << '\n'
         << record.interface_name << '\n'
         << record.transaction_id << '\n'
         << record.marker << '\n'
         << kind_name(record.kind) << '\n'
         << record.snapshot_revision << '\n'
         << record.target_full_revision << '\n';
    return body.str();
}

std::optional<NdmsNativeOwnershipRecord> parse(const std::string& body) {
    std::istringstream input(body);
    std::string header;
    NdmsNativeOwnershipRecord record;
    std::string kind;
    std::string extra;
    if (!std::getline(input, header) || header != kHeader ||
        !std::getline(input, record.interface_name) ||
        !std::getline(input, record.transaction_id) ||
        !std::getline(input, record.marker) ||
        !std::getline(input, kind) ||
        !std::getline(input, record.snapshot_revision) ||
        !std::getline(input, record.target_full_revision) ||
        std::getline(input, extra)) {
        return std::nullopt;
    }
    if (kind == "wireguard") {
        record.kind = NdmsNativeTunnelImportKind::wireguard;
    } else if (kind == "amnezia_wireguard") {
        record.kind = NdmsNativeTunnelImportKind::amnezia_wireguard;
    } else {
        return std::nullopt;
    }
    if (!record_fields_valid(record)) return std::nullopt;
    return record;
}

enum class OwnershipReadState { absent, valid, unsafe };

struct OwnershipFileRead final {
    OwnershipReadState state{OwnershipReadState::unsafe};
    std::optional<NdmsNativeOwnershipRecord> record;
    std::optional<std::string> revision;
    dev_t device{};
    ino_t inode{};
};

OwnershipFileRead read_locked(
    const int directory,
    const std::string& interface_name,
    const OwnershipStorePolicy& policy) {
    OwnershipFileRead result;
    struct stat before {};
    if (::fstatat(directory, interface_name.c_str(), &before,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) result.state = OwnershipReadState::absent;
        return result;
    }
    if (!exact_file(before, policy) || before.st_size <= 0 ||
        static_cast<std::uint64_t>(before.st_size) > kMaximumRecordBytes) {
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
    OwnershipFileDescriptor input(
        ::openat(directory, interface_name.c_str(), flags));
    if (input.get() < 0) return result;
    try {
        set_cloexec(input.get());
    } catch (...) {
        return result;
    }
    struct stat opened {};
    if (::fstat(input.get(), &opened) != 0 || !exact_file(opened, policy) ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino ||
        opened.st_size != before.st_size) {
        return result;
    }
    std::string body;
    try {
        body.reserve(static_cast<std::size_t>(opened.st_size));
        std::array<char, 1024U> buffer{};
        while (true) {
            const auto count = ::read(
                input.get(), buffer.data(), buffer.size());
            if (count < 0) {
                if (errno == EINTR) continue;
                return result;
            }
            if (count == 0) break;
            if (body.size() + static_cast<std::size_t>(count) >
                kMaximumRecordBytes) {
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
    auto parsed = parse(body);
    if (!parsed || parsed->interface_name != interface_name) return result;
    result.revision = ndms_native_ownership_revision(*parsed);
    result.record = std::move(parsed);
    result.device = opened.st_dev;
    result.inode = opened.st_ino;
    result.state = OwnershipReadState::valid;
    return result;
}

bool decimal_text(const std::string_view value) noexcept {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(), [](const char character) {
               return character >= '0' && character <= '9';
           });
}

std::optional<std::string> ownership_temporary_target(
    const std::string_view name) {
    if (name.substr(0U, kOwnershipTemporaryPrefix.size()) !=
        kOwnershipTemporaryPrefix) {
        return std::nullopt;
    }
    const auto remainder = name.substr(kOwnershipTemporaryPrefix.size());
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
    return claimable_interface(target)
        ? std::optional<std::string>{std::move(target)}
        : std::nullopt;
}

bool cleanup_ownership_temporaries(
    const int directory,
    const OwnershipStorePolicy& policy) {
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
        if (++entries > 128U) {
            safe = false;
            break;
        }
        const bool starts_temporary =
            std::string_view(name).substr(
                0U, kOwnershipTemporaryPrefix.size()) ==
            kOwnershipTemporaryPrefix;
        const auto target = ownership_temporary_target(name);
        if (!target) {
            if (starts_temporary || !claimable_interface(name)) {
                safe = false;
                break;
            }
            continue;
        }
        struct stat temporary {};
        if (::fstatat(directory, name.c_str(), &temporary,
                      AT_SYMLINK_NOFOLLOW) != 0 ||
            (!exact_file_links(temporary, policy, 1) &&
             !exact_file_links(temporary, policy, 2))) {
            safe = false;
            break;
        }
        if (temporary.st_nlink == 2) {
            struct stat published {};
            if (::fstatat(directory, target->c_str(), &published,
                          AT_SYMLINK_NOFOLLOW) != 0 ||
                !exact_file_links(published, policy, 2) ||
                published.st_dev != temporary.st_dev ||
                published.st_ino != temporary.st_ino) {
                safe = false;
                break;
            }
        }
        if (::unlinkat(directory, name.c_str(), 0) != 0) {
            safe = false;
            break;
        }
        changed = true;
        if (temporary.st_nlink == 2) {
            const auto recovered = read_locked(
                directory, *target, policy);
            if (recovered.state != OwnershipReadState::valid ||
                !recovered.record) {
                safe = false;
                break;
            }
        }
    }
    if (::closedir(stream) != 0) safe = false;
    if (safe && changed) {
        try {
            fsync_exact(directory, "native ownership directory");
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
                ownership_error("cannot write native ownership file"));
        }
        if (count == 0) {
            throw std::runtime_error(
                "cannot write native ownership file: short write");
        }
        offset += static_cast<std::size_t>(count);
    }
}

std::string create_temporary(
    const int directory,
    OwnershipFileDescriptor& output,
    const std::string& target,
    const OwnershipStorePolicy& policy) {
    for (unsigned int attempt = 0U; attempt < 128U; ++attempt) {
        const auto sequence = ownership_temporary_sequence.fetch_add(
            1U, std::memory_order_relaxed);
        const auto name = std::string{kOwnershipTemporaryPrefix} +
                          std::to_string(::getpid()) + "." +
                          std::to_string(sequence) + "." + target;
        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        output = OwnershipFileDescriptor(
            ::openat(directory, name.c_str(), flags, kOwnershipFileMode));
        if (output.get() < 0) {
            if (errno == EEXIST) continue;
            throw std::runtime_error(
                ownership_error(
                    "cannot create temporary native ownership file"));
        }
        set_cloexec(output.get());
        if (::fchown(output.get(), policy.owner, policy.group) != 0 ||
            ::fchmod(output.get(), kOwnershipFileMode) != 0) {
            throw std::runtime_error(
                ownership_error(
                    "cannot protect temporary native ownership file"));
        }
        struct stat metadata {};
        if (::fstat(output.get(), &metadata) != 0 ||
            !exact_file(metadata, policy)) {
            throw std::runtime_error(
                "temporary native ownership file metadata is unsafe");
        }
        return name;
    }
    throw std::runtime_error(
        "temporary native ownership namespace is exhausted");
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

void publish_locked(
    const int directory,
    const std::string& filename,
    const std::string_view body,
    const OwnershipStorePolicy& policy) {
    OwnershipFileDescriptor temporary;
    const auto temporary_name = create_temporary(
        directory, temporary, filename, policy);
    bool temporary_exists = true;
    try {
        write_all(temporary.get(), body);
        fsync_exact(temporary.get(), "temporary native ownership file");
        if (::close(temporary.release()) != 0) {
            throw std::runtime_error(
                ownership_error(
                    "cannot close temporary native ownership file"));
        }
#ifdef KEEN_PBR3_TESTING
        inject_ownership_fault(
            policy,
            NdmsNativeOwnershipStoreFaultStage::
                pre_publish_after_file_fsync);
#endif
        int result =
#ifdef KEEN_PBR3_TESTING
            policy.force_portable_linkat
                ? (errno = ENOTSUP, -1)
                :
#endif
                  rename_noreplace(
                      directory, temporary_name.c_str(), filename.c_str());
        if (result != 0 &&
            (errno == ENOSYS || errno == EINVAL || errno == ENOTSUP ||
             errno == EOPNOTSUPP)) {
            result = ::linkat(
                directory, temporary_name.c_str(),
                directory, filename.c_str(), 0);
            if (result == 0) {
                temporary_exists = false;
#ifdef KEEN_PBR3_TESTING
                inject_ownership_fault(
                    policy,
                    NdmsNativeOwnershipStoreFaultStage::
                        post_link_before_unlink);
#endif
                if (::unlinkat(
                        directory, temporary_name.c_str(), 0) != 0) {
                    throw std::runtime_error(
                        ownership_error(
                            "cannot retire linked native ownership temporary"));
                }
            }
        }
        if (result != 0) {
            throw std::runtime_error(
                ownership_error("cannot publish native ownership file"));
        }
        temporary_exists = false;
#ifdef KEEN_PBR3_TESTING
        inject_ownership_fault(
            policy,
            NdmsNativeOwnershipStoreFaultStage::
                post_rename_directory_fsync);
#endif
        fsync_exact(directory, "native ownership directory");
    } catch (...) {
        if (temporary_exists) {
            (void)::unlinkat(directory, temporary_name.c_str(), 0);
        }
        throw;
    }
}

} // namespace

bool NdmsNativeOwnershipRecord::operator==(
    const NdmsNativeOwnershipRecord& other) const noexcept {
    return interface_name == other.interface_name &&
           transaction_id == other.transaction_id &&
           marker == other.marker && kind == other.kind &&
           snapshot_revision == other.snapshot_revision &&
           target_full_revision == other.target_full_revision;
}

std::string ndms_native_ownership_revision(
    const NdmsNativeOwnershipRecord& record) {
    if (!record_fields_valid(record)) {
        throw std::runtime_error(
            "native ownership record cannot be revisioned");
    }
    Sha256 hasher;
    update_field(hasher, "keen-pbr.ndms-native-ownership.revision.v2");
    update_field(hasher, record.interface_name);
    update_field(hasher, record.transaction_id);
    update_field(hasher, record.marker);
    update_field(hasher, kind_name(record.kind));
    update_field(hasher, record.snapshot_revision);
    update_field(hasher, record.target_full_revision);
    return std::string("ndms-native-owner-v2-") + hasher.hex_digest();
}

NdmsNativeOwnershipStore::NdmsNativeOwnershipStore(
    std::filesystem::path state_directory)
    : state_directory_(std::move(state_directory)) {
#ifdef KEEN_PBR3_TESTING
    // Existing unit/crash fixtures intentionally live below /tmp or a bind
    // mount. Production builds do not carry this member or this relaxation;
    // dedicated metadata-policy tests can still pass explicit strict hooks.
    test_hooks_.allow_current_process_owner = true;
#endif
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeOwnershipStore::NdmsNativeOwnershipStore(
    std::filesystem::path state_directory,
    NdmsNativeOwnershipStoreTestHooks hooks)
    : state_directory_(std::move(state_directory)),
      test_hooks_(std::move(hooks)) {}
#endif

std::string NdmsNativeOwnershipStore::publish(
    const NdmsNativeOwnershipRecord& record) {
    if (!record_fields_valid(record)) {
        throw std::runtime_error(
            "native ownership record is not publishable");
    }
    const auto policy = ownership_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(ownership_store_mutex);
    auto directory = open_directory(state_directory_, true, policy);
    OwnershipDirectoryLock directory_lock(directory.get(), LOCK_EX);
    if (!cleanup_ownership_temporaries(directory.get(), policy)) {
        throw std::runtime_error(
            "native ownership directory inventory is unsafe");
    }
    const auto existing = read_locked(
        directory.get(), record.interface_name, policy);
    if (existing.state == OwnershipReadState::valid) {
        if (!existing.record || !(*existing.record == record)) {
            throw std::runtime_error(
                "native ownership claim differs and is immutable");
        }
#ifdef KEEN_PBR3_TESTING
        inject_ownership_fault(
            policy,
            NdmsNativeOwnershipStoreFaultStage::
                post_rename_directory_fsync);
#endif
        fsync_exact(directory.get(), "native ownership directory");
        return ndms_native_ownership_revision(record);
    }
    if (existing.state != OwnershipReadState::absent) {
        throw std::runtime_error(
            "existing native ownership claim is unsafe and immutable");
    }
    const auto body = serialize(record);
    publish_locked(
        directory.get(), record.interface_name, body, policy);
    const auto verified = read_locked(
        directory.get(), record.interface_name, policy);
    if (verified.state != OwnershipReadState::valid || !verified.record ||
        !(*verified.record == record)) {
        throw std::runtime_error(
            "published native ownership claim failed exact verification");
    }
    return ndms_native_ownership_revision(record);
}

std::optional<std::string> NdmsNativeOwnershipStore::replace_exact(
    const NdmsNativeOwnershipRecord& expected,
    const NdmsNativeOwnershipRecord& replacement) {
    if (!record_fields_valid(expected) ||
        !record_fields_valid(replacement) ||
        expected.interface_name != replacement.interface_name ||
        expected.transaction_id != replacement.transaction_id ||
        expected.marker != replacement.marker ||
        expected.kind != replacement.kind ||
        expected.snapshot_revision != replacement.snapshot_revision) {
        return std::nullopt;
    }
    const auto policy = ownership_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(ownership_store_mutex);
    try {
        auto directory = open_directory(
            state_directory_, false, policy);
        OwnershipDirectoryLock directory_lock(directory.get(), LOCK_EX);
        if (!cleanup_ownership_temporaries(
                directory.get(), policy)) {
            return std::nullopt;
        }
        const auto current = read_locked(
            directory.get(), expected.interface_name, policy);
        if (current.state != OwnershipReadState::valid ||
            !current.record) {
            return std::nullopt;
        }
        if (*current.record == replacement) {
            fsync_exact(directory.get(), "native ownership directory");
            return ndms_native_ownership_revision(replacement);
        }
        if (!(*current.record == expected)) return std::nullopt;

        OwnershipFileDescriptor temporary;
        const auto temporary_name = create_temporary(
            directory.get(), temporary, expected.interface_name, policy);
        bool temporary_exists = true;
        try {
            const auto body = serialize(replacement);
            write_all(temporary.get(), body);
            fsync_exact(
                temporary.get(), "temporary native ownership file");
            if (::close(temporary.release()) != 0) {
                throw std::runtime_error(
                    ownership_error(
                        "cannot close temporary native ownership file"));
            }
#ifdef KEEN_PBR3_TESTING
            inject_ownership_fault(
                policy,
                NdmsNativeOwnershipStoreFaultStage::
                    pre_publish_after_file_fsync);
#endif
            const auto rebound = read_locked(
                directory.get(), expected.interface_name, policy);
            if (rebound.state != OwnershipReadState::valid ||
                !rebound.record || !(*rebound.record == expected) ||
                rebound.device != current.device ||
                rebound.inode != current.inode) {
                throw std::runtime_error(
                    "native ownership claim changed during exact replace");
            }
            if (::renameat(
                    directory.get(), temporary_name.c_str(),
                    directory.get(), expected.interface_name.c_str()) != 0) {
                throw std::runtime_error(
                    ownership_error(
                        "cannot replace native ownership file"));
            }
            temporary_exists = false;
#ifdef KEEN_PBR3_TESTING
            inject_ownership_fault(
                policy,
                NdmsNativeOwnershipStoreFaultStage::
                    post_rename_directory_fsync);
#endif
            fsync_exact(directory.get(), "native ownership directory");
        } catch (...) {
            if (temporary_exists) {
                (void)::unlinkat(
                    directory.get(), temporary_name.c_str(), 0);
            }
            throw;
        }
        const auto verified = read_locked(
            directory.get(), expected.interface_name, policy);
        if (verified.state != OwnershipReadState::valid ||
            !verified.record || !(*verified.record == replacement)) {
            return std::nullopt;
        }
        return ndms_native_ownership_revision(replacement);
    } catch (...) {
        return std::nullopt;
    }
}

NdmsNativeOwnershipReadResult NdmsNativeOwnershipStore::read(
    const std::string& interface_name) const {
    NdmsNativeOwnershipReadResult result;
    if (!claimable_interface(interface_name)) return result;
    const auto policy = ownership_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(ownership_store_mutex);
    try {
        auto directory = open_directory(
            state_directory_, false, policy);
        OwnershipDirectoryLock directory_lock(directory.get(), LOCK_EX);
        if (!cleanup_ownership_temporaries(
                directory.get(), policy)) {
            return result;
        }
        const auto current = read_locked(
            directory.get(), interface_name, policy);
        if (current.state == OwnershipReadState::absent) {
            result.state = NdmsNativeOwnershipReadState::absent;
        } else if (current.state == OwnershipReadState::valid) {
            result.record = current.record;
            result.revision = current.revision;
            result.state = NdmsNativeOwnershipReadState::valid;
        }
    } catch (const OwnershipDirectoryAbsent&) {
        result.state = NdmsNativeOwnershipReadState::absent;
    } catch (...) {
    }
    return result;
}

bool NdmsNativeOwnershipStore::remove_exact(
    const NdmsNativeOwnershipRecord& expected) {
    if (!record_fields_valid(expected)) return false;
    const auto policy = ownership_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(ownership_store_mutex);
    try {
        auto directory = open_directory(
            state_directory_, false, policy);
        OwnershipDirectoryLock directory_lock(directory.get(), LOCK_EX);
        if (!cleanup_ownership_temporaries(
                directory.get(), policy)) {
            return false;
        }
        const auto current = read_locked(
            directory.get(), expected.interface_name, policy);
        if (current.state != OwnershipReadState::valid ||
            !current.record || !(*current.record == expected)) {
            return false;
        }
#ifdef KEEN_PBR3_TESTING
        inject_ownership_fault(
            policy,
            NdmsNativeOwnershipStoreFaultStage::
                before_remove_inode_recheck);
#endif
        const auto rebound = read_locked(
            directory.get(), expected.interface_name, policy);
        if (rebound.state != OwnershipReadState::valid ||
            !rebound.record || !(*rebound.record == expected) ||
            rebound.device != current.device ||
            rebound.inode != current.inode) {
            return false;
        }
        if (::unlinkat(
                directory.get(), expected.interface_name.c_str(), 0) != 0) {
            return false;
        }
#ifdef KEEN_PBR3_TESTING
        inject_ownership_fault(
            policy,
            NdmsNativeOwnershipStoreFaultStage::
                post_unlink_directory_fsync);
#endif
        fsync_exact(directory.get(), "native ownership directory");
        return read_locked(
                   directory.get(), expected.interface_name, policy)
                   .state == OwnershipReadState::absent;
    } catch (...) {
        return false;
    }
}

bool NdmsNativeOwnershipStore::ensure_absence_durable(
    const std::string& interface_name) {
    if (!claimable_interface(interface_name)) return false;
    const auto policy = ownership_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(ownership_store_mutex);
    try {
        auto directory = open_directory(
            state_directory_, true, policy);
        OwnershipDirectoryLock directory_lock(directory.get(), LOCK_EX);
        if (!cleanup_ownership_temporaries(
                directory.get(), policy)) {
            return false;
        }
        if (read_locked(directory.get(), interface_name, policy).state !=
            OwnershipReadState::absent) {
            return false;
        }
#ifdef KEEN_PBR3_TESTING
        inject_ownership_fault(
            policy,
            NdmsNativeOwnershipStoreFaultStage::
                absence_directory_fsync);
#endif
        fsync_exact(directory.get(), "native ownership directory");
        return read_locked(directory.get(), interface_name, policy).state ==
               OwnershipReadState::absent;
    } catch (...) {
        return false;
    }
}

NdmsNativeOwnershipStore::Listing
NdmsNativeOwnershipStore::list_claimed_interfaces() const {
    Listing listing;
    const auto policy = ownership_policy(
#ifdef KEEN_PBR3_TESTING
        test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(ownership_store_mutex);
    try {
        auto directory = open_directory(
            state_directory_, false, policy);
        OwnershipDirectoryLock directory_lock(directory.get(), LOCK_EX);
        if (!cleanup_ownership_temporaries(
                directory.get(), policy)) {
            return listing;
        }
        const int duplicate = ::dup(directory.get());
        if (duplicate < 0) return listing;
        DIR* stream = ::fdopendir(duplicate);
        if (stream == nullptr) {
            (void)::close(duplicate);
            return listing;
        }
        ::rewinddir(stream);
        bool safe = true;
        std::size_t entries = 0U;
        try {
            while (const auto* item = ::readdir(stream)) {
                const std::string name(item->d_name);
                if (name == "." || name == "..") continue;
                if (++entries > 128U) {
                    safe = false;
                    break;
                }
                if (claimable_interface(name)) {
                    listing.interface_names.push_back(name);
                } else {
                    safe = false;
                    break;
                }
            }
        } catch (...) {
            safe = false;
        }
        if (::closedir(stream) != 0) safe = false;
        if (!safe) {
            listing.interface_names.clear();
            return listing;
        }
        std::sort(listing.interface_names.begin(),
                  listing.interface_names.end());
        listing.readable = true;
    } catch (const OwnershipDirectoryAbsent&) {
        listing.readable = true;
    } catch (...) {
    }
    return listing;
}

const std::filesystem::path&
NdmsNativeOwnershipStore::state_directory() const noexcept {
    return state_directory_;
}

const char* ndms_native_ownership_read_state_name(
    const NdmsNativeOwnershipReadState state) noexcept {
    switch (state) {
    case NdmsNativeOwnershipReadState::absent:
        return "absent";
    case NdmsNativeOwnershipReadState::valid:
        return "valid";
    case NdmsNativeOwnershipReadState::unreadable:
        return "unreadable";
    }
    return "unreadable";
}

} // namespace keen_pbr3
