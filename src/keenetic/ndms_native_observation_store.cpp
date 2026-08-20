#include "ndms_native_observation_store.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <dirent.h>
#include <exception>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

constexpr std::string_view kHeader{"keen-pbr-native-observation-v1"};
constexpr mode_t kDirectoryMode = 0700;
constexpr mode_t kFileMode = 0600;
constexpr std::size_t kMaximumLedgerBytes = 4096U;
constexpr std::size_t kMaximumTemporaryFiles = 64U;
constexpr std::string_view kTemporaryPrefix{".observation.tmp."};

std::atomic<std::uint64_t> temporary_sequence{0U};
std::mutex observation_store_mutex;

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

class DirectoryAbsent final : public std::exception {};

struct StorePolicy final {
    uid_t owner{0};
    gid_t group{0};
    bool require_root_process{true};
#ifdef KEEN_PBR3_TESTING
    std::function<std::string()> authority_id_factory;
    std::function<void(NdmsNativeObservationStoreFaultStage)> fault_injector;
#endif
};

std::string errno_message(const std::string& prefix) {
    const int error = errno;
    return prefix + ": " + std::strerror(error);
}

int directory_flags() {
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
        throw NdmsNativeObservationStoreError(errno_message(
            "cannot mark native observation descriptor close-on-exec"));
    }
#else
    (void)descriptor;
#endif
}

void fsync_exact(const int descriptor, const std::string& what) {
    while (::fsync(descriptor) != 0) {
        if (errno == EINTR) continue;
        throw NdmsNativeObservationStoreError(
            errno_message("cannot fsync " + what));
    }
}

std::vector<std::string> path_components(
    const std::filesystem::path& path) {
    if (!path.is_absolute() || path.empty() || path == path.root_path() ||
        path.lexically_normal() != path) {
        throw NdmsNativeObservationStoreError(
            "native observation store requires a normalized absolute directory");
    }
    std::vector<std::string> result;
    for (const auto& raw : path.relative_path()) {
        const auto component = raw.string();
        if (component.empty() || component == "." || component == "..") {
            throw NdmsNativeObservationStoreError(
                "native observation path contains an unsafe component");
        }
        result.push_back(component);
    }
    if (result.empty()) {
        throw NdmsNativeObservationStoreError(
            "native observation store requires a dedicated directory");
    }
    return result;
}

bool exact_directory(const struct stat& status,
                     const StorePolicy& policy) noexcept {
    return S_ISDIR(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_uid == policy.owner && status.st_gid == policy.group &&
           (status.st_mode & 07777) == kDirectoryMode;
}

bool exact_file_links(const struct stat& status,
                      const StorePolicy& policy,
                      const nlink_t links) noexcept {
    return S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_uid == policy.owner && status.st_gid == policy.group &&
           (status.st_mode & 07777) == kFileMode && status.st_nlink == links;
}

bool exact_file(const struct stat& status,
                const StorePolicy& policy) noexcept {
    return exact_file_links(status, policy, 1);
}

FileDescriptor open_directory(const std::filesystem::path& path,
                              const StorePolicy& policy) {
    if (policy.require_root_process &&
        (::geteuid() != 0 || ::getegid() != 0)) {
        throw NdmsNativeObservationStoreError(
            "native observation storage requires a root process");
    }
    FileDescriptor current(::open("/", directory_flags()));
    if (current.get() < 0) {
        throw NdmsNativeObservationStoreError(
            errno_message("cannot open native observation path root"));
    }
    set_cloexec(current.get());
    const auto components = path_components(path);
    for (std::size_t index = 0U; index < components.size(); ++index) {
        const bool final = index + 1U == components.size();
        const auto& component = components[index];
        struct stat before {};
        if (::fstatat(current.get(), component.c_str(), &before,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT && final) throw DirectoryAbsent{};
            throw NdmsNativeObservationStoreError(
                errno_message("cannot inspect native observation directory"));
        }
        if (!S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode)) {
            throw NdmsNativeObservationStoreError(
                "native observation path contains a symlink or non-directory");
        }
        FileDescriptor child(
            ::openat(current.get(), component.c_str(), directory_flags()));
        if (child.get() < 0) {
            throw NdmsNativeObservationStoreError(
                errno_message("cannot open native observation directory"));
        }
        set_cloexec(child.get());
        struct stat opened {};
        if (::fstat(child.get(), &opened) != 0 ||
            !S_ISDIR(opened.st_mode) || opened.st_dev != before.st_dev ||
            opened.st_ino != before.st_ino) {
            throw NdmsNativeObservationStoreError(
                "native observation directory changed while opening");
        }
        if (final) {
            if (!exact_directory(opened, policy)) {
                throw NdmsNativeObservationStoreError(
                    "native observation directory is not exact owner-only 0700");
            }
        } else if (policy.require_root_process &&
                   (opened.st_uid != 0 || (opened.st_mode & 0022) != 0)) {
            throw NdmsNativeObservationStoreError(
                "native observation parent directory is not root protected");
        }
        current = std::move(child);
    }
    return current;
}

bool lower_hex(const std::string_view value,
               const std::size_t size) noexcept {
    return value.size() == size &&
           std::all_of(value.begin(), value.end(), [](const char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

bool prefixed_digest(const std::string_view value,
                     const std::string_view prefix) noexcept {
    return value.size() == prefix.size() + 64U &&
           value.substr(0U, prefix.size()) == prefix &&
           lower_hex(value.substr(prefix.size()), 64U);
}

bool core_fields_valid(const NdmsNativeObservationLedger& ledger) noexcept {
    if (!lower_hex(ledger.authority_id, 32U)) return false;
    if (ledger.sequence == 0U) {
        return ledger.mutation_epoch == 0U &&
               !ledger.last_catalog_revision.has_value();
    }
    return ledger.last_catalog_revision.has_value() &&
           valid_ndms_native_observation_catalog_revision(
               *ledger.last_catalog_revision);
}

void update_field(Sha256& hasher, const std::string_view value) {
    const auto size = static_cast<std::uint64_t>(value.size());
    unsigned char length[8];
    for (std::size_t index = 0U; index < 8U; ++index) {
        length[index] =
            static_cast<unsigned char>(size >> (56U - index * 8U));
    }
    hasher.update(length, sizeof(length));
    hasher.update(value.data(), value.size());
}

std::string decimal(const std::uint64_t value) {
    return std::to_string(value);
}

bool parse_decimal(const std::string_view text,
                   std::uint64_t& output) noexcept {
    if (text.empty() || (text.size() > 1U && text.front() == '0')) return false;
    std::uint64_t parsed = 0U;
    const auto result = std::from_chars(
        text.data(), text.data() + text.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return false;
    }
    output = parsed;
    return true;
}

std::string serialize(const NdmsNativeObservationLedger& ledger) {
    if (!core_fields_valid(ledger) ||
        !prefixed_digest(
            ledger.integrity, kNdmsNativeObservationIntegrityPrefix) ||
        ledger.integrity != ndms_native_observation_integrity(ledger)) {
        throw NdmsNativeObservationStoreError(
            "native observation ledger is not serializable");
    }
    std::ostringstream output;
    output << kHeader << '\n'
           << ledger.authority_id << '\n'
           << ledger.sequence << '\n'
           << ledger.mutation_epoch << '\n'
           << (ledger.last_catalog_revision.has_value()
                   ? *ledger.last_catalog_revision
                   : std::string{"-"})
           << '\n'
           << ledger.integrity << '\n';
    return output.str();
}

std::optional<NdmsNativeObservationLedger> parse(
    const std::string& body) {
    std::istringstream input(body);
    std::string header;
    std::string sequence;
    std::string epoch;
    std::string catalog;
    std::string extra;
    NdmsNativeObservationLedger ledger;
    if (!std::getline(input, header) || header != kHeader ||
        !std::getline(input, ledger.authority_id) ||
        !std::getline(input, sequence) || !std::getline(input, epoch) ||
        !std::getline(input, catalog) ||
        !std::getline(input, ledger.integrity) || std::getline(input, extra) ||
        !parse_decimal(sequence, ledger.sequence) ||
        !parse_decimal(epoch, ledger.mutation_epoch)) {
        return std::nullopt;
    }
    if (catalog != "-") ledger.last_catalog_revision = std::move(catalog);
    if (!core_fields_valid(ledger) ||
        !prefixed_digest(
            ledger.integrity, kNdmsNativeObservationIntegrityPrefix) ||
        ledger.integrity != ndms_native_observation_integrity(ledger)) {
        return std::nullopt;
    }
    return ledger;
}

enum class LockedReadState { absent, valid, unsafe };

struct LockedRead final {
    LockedReadState state{LockedReadState::unsafe};
    std::optional<NdmsNativeObservationLedger> ledger;
    dev_t device{};
    ino_t inode{};
};

LockedRead read_locked(const int directory, const StorePolicy& policy) {
    LockedRead result;
    struct stat before {};
    if (::fstatat(directory, kNdmsNativeObservationStateFilename, &before,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) result.state = LockedReadState::absent;
        return result;
    }
    if (!exact_file(before, policy) || before.st_size <= 0 ||
        static_cast<std::uint64_t>(before.st_size) > kMaximumLedgerBytes) {
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
        directory, kNdmsNativeObservationStateFilename, flags));
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
                kMaximumLedgerBytes) {
                return result;
            }
            body.append(buffer.data(), static_cast<std::size_t>(count));
        }
    } catch (...) {
        return result;
    }
    struct stat after {};
    if (::fstat(input.get(), &after) != 0 || !exact_file(after, policy) ||
        after.st_dev != opened.st_dev || after.st_ino != opened.st_ino ||
        after.st_size != opened.st_size || after.st_mtime != opened.st_mtime ||
        after.st_ctime != opened.st_ctime ||
        body.size() != static_cast<std::size_t>(opened.st_size)) {
        return result;
    }
    auto parsed = parse(body);
    if (!parsed.has_value()) return result;
    result.ledger = std::move(parsed);
    result.device = opened.st_dev;
    result.inode = opened.st_ino;
    result.state = LockedReadState::valid;
    return result;
}

bool decimal_component(const std::string_view value) noexcept {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(), [](const char character) {
               return character >= '0' && character <= '9';
           });
}

bool valid_temporary_name(const std::string_view name) noexcept {
    if (name.substr(0U, kTemporaryPrefix.size()) != kTemporaryPrefix) {
        return false;
    }
    const auto suffix = name.substr(kTemporaryPrefix.size());
    const auto separator = suffix.find('.');
    return separator != std::string_view::npos && separator != 0U &&
           separator + 1U < suffix.size() &&
           decimal_component(suffix.substr(0U, separator)) &&
           decimal_component(suffix.substr(separator + 1U));
}

bool cleanup_temporaries(const int directory, const StorePolicy& policy) {
    const int duplicate = ::dup(directory);
    if (duplicate < 0) return false;
    DIR* stream = ::fdopendir(duplicate);
    if (stream == nullptr) {
        (void)::close(duplicate);
        return false;
    }
    bool safe = true;
    bool changed = false;
    std::size_t temporary_count = 0U;
    ::rewinddir(stream);
    while (const auto* item = ::readdir(stream)) {
        const std::string name(item->d_name);
        if (name == "." || name == "..") continue;
        if (std::string_view{name}.substr(0U, kTemporaryPrefix.size()) !=
            kTemporaryPrefix) {
            continue;
        }
        if (++temporary_count > kMaximumTemporaryFiles ||
            !valid_temporary_name(name)) {
            safe = false;
            break;
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
            if (::fstatat(
                    directory, kNdmsNativeObservationStateFilename,
                    &published, AT_SYMLINK_NOFOLLOW) != 0 ||
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
    }
    if (::closedir(stream) != 0) safe = false;
    if (safe && changed) {
        try {
            fsync_exact(directory, "native observation directory");
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
            throw NdmsNativeObservationStoreError(
                errno_message("cannot write native observation ledger"));
        }
        if (count == 0) {
            throw NdmsNativeObservationStoreError(
                "cannot write native observation ledger: short write");
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
            throw NdmsNativeObservationStoreError(errno_message(
                "cannot create temporary native observation ledger"));
        }
        set_cloexec(output.get());
        if (::fchown(output.get(), policy.owner, policy.group) != 0 ||
            ::fchmod(output.get(), kFileMode) != 0) {
            throw NdmsNativeObservationStoreError(errno_message(
                "cannot protect temporary native observation ledger"));
        }
        struct stat status {};
        if (::fstat(output.get(), &status) != 0 ||
            !exact_file(status, policy)) {
            throw NdmsNativeObservationStoreError(
                "temporary native observation ledger metadata is unsafe");
        }
        return name;
    }
    throw NdmsNativeObservationStoreError(
        "native observation temporary namespace is exhausted");
}

#ifdef KEEN_PBR3_TESTING
void inject_fault(const StorePolicy& policy,
                  const NdmsNativeObservationStoreFaultStage stage) {
    if (policy.fault_injector) policy.fault_injector(stage);
}
#endif

void publish_locked(const int directory,
                    const NdmsNativeObservationLedger& ledger,
                    const bool initial,
                    const StorePolicy& policy) {
    const auto body = serialize(ledger);
    FileDescriptor temporary;
    const auto temporary_name = create_temporary(
        directory, temporary, policy);
    bool temporary_exists = true;
    try {
        write_all(temporary.get(), body);
        fsync_exact(temporary.get(), "temporary native observation ledger");
        if (::close(temporary.release()) != 0) {
            throw NdmsNativeObservationStoreError(errno_message(
                "cannot close temporary native observation ledger"));
        }
#ifdef KEEN_PBR3_TESTING
        inject_fault(
            policy,
            NdmsNativeObservationStoreFaultStage::
                after_temporary_file_fsync);
#endif
        if (initial) {
            if (::linkat(directory, temporary_name.c_str(), directory,
                         kNdmsNativeObservationStateFilename, 0) != 0) {
                throw NdmsNativeObservationStoreError(errno_message(
                    "cannot publish initial native observation ledger"));
            }
#ifdef KEEN_PBR3_TESTING
            inject_fault(
                policy,
                NdmsNativeObservationStoreFaultStage::
                    after_initial_link_before_temporary_unlink);
#endif
            if (::unlinkat(directory, temporary_name.c_str(), 0) != 0) {
                throw NdmsNativeObservationStoreError(errno_message(
                    "cannot retire linked native observation temporary"));
            }
            temporary_exists = false;
        } else {
            if (::renameat(directory, temporary_name.c_str(), directory,
                           kNdmsNativeObservationStateFilename) != 0) {
                throw NdmsNativeObservationStoreError(errno_message(
                    "cannot replace native observation ledger"));
            }
            temporary_exists = false;
#ifdef KEEN_PBR3_TESTING
            inject_fault(
                policy,
                NdmsNativeObservationStoreFaultStage::
                    after_replace_rename_before_directory_fsync);
#endif
        }
        fsync_exact(directory, "native observation directory");
#ifdef KEEN_PBR3_TESTING
        inject_fault(
            policy,
            NdmsNativeObservationStoreFaultStage::after_directory_fsync);
#endif
    } catch (...) {
        if (temporary_exists) {
            (void)::unlinkat(directory, temporary_name.c_str(), 0);
            try {
                fsync_exact(directory, "native observation directory");
            } catch (...) {
            }
        }
        throw;
    }
}

std::string random_authority_id() {
    std::array<unsigned char, 16U> bytes{};
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    FileDescriptor random(::open("/dev/urandom", flags));
    if (random.get() < 0) {
        throw NdmsNativeObservationStoreError(
            errno_message("cannot open /dev/urandom for observation authority"));
    }
    set_cloexec(random.get());
    std::size_t offset = 0U;
    while (offset < bytes.size()) {
        const auto count = ::read(
            random.get(), bytes.data() + offset, bytes.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            throw NdmsNativeObservationStoreError(errno_message(
                "cannot read observation authority from /dev/urandom"));
        }
        if (count == 0) {
            throw NdmsNativeObservationStoreError(
                "unexpected end of /dev/urandom for observation authority");
        }
        offset += static_cast<std::size_t>(count);
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(bytes.size() * 2U);
    for (const auto byte : bytes) {
        output.push_back(hex[byte >> 4U]);
        output.push_back(hex[byte & 0x0fU]);
    }
    return output;
}

StorePolicy read_policy(
#ifdef KEEN_PBR3_TESTING
    const NdmsNativeObservationStoreTestHooks& hooks
#endif
) {
    StorePolicy policy;
#ifdef KEEN_PBR3_TESTING
    if (hooks.allow_current_process_owner) {
        policy.owner = ::geteuid();
        policy.group = ::getegid();
        policy.require_root_process = false;
    }
    policy.authority_id_factory = hooks.authority_id_factory;
    policy.fault_injector = hooks.fault_injector;
#endif
    return policy;
}

StorePolicy writer_policy(
    const uid_t owner,
    const gid_t group
#ifdef KEEN_PBR3_TESTING
    , const NdmsNativeObservationStoreTestHooks& hooks
#endif
) {
    StorePolicy policy;
    policy.owner = owner;
    policy.group = group;
    policy.require_root_process = false;
#ifdef KEEN_PBR3_TESTING
    policy.authority_id_factory = hooks.authority_id_factory;
    policy.fault_injector = hooks.fault_injector;
#endif
    return policy;
}

std::string make_authority_id(const StorePolicy& policy) {
#ifdef KEEN_PBR3_TESTING
    if (policy.authority_id_factory) {
        auto value = policy.authority_id_factory();
        if (!lower_hex(value, 32U)) {
            throw NdmsNativeObservationStoreError(
                "test observation authority id is invalid");
        }
        return value;
    }
#else
    (void)policy;
#endif
    return random_authority_id();
}

NdmsNativeObservationStamp stamp_from(
    const NdmsNativeObservationLedger& ledger) {
    if (!ledger.last_catalog_revision.has_value()) {
        throw NdmsNativeObservationStoreError(
            "native observation ledger has no catalog stamp");
    }
    return {
        ledger.authority_id,
        ledger.sequence,
        ledger.mutation_epoch,
        *ledger.last_catalog_revision,
        ledger.integrity,
    };
}

void require_valid_catalog_revision(const std::string& revision) {
    if (!valid_ndms_native_observation_catalog_revision(revision)) {
        throw NdmsNativeObservationStoreError(
            "native observation catalog revision is invalid");
    }
}

} // namespace

bool NdmsNativeObservationLedger::operator==(
    const NdmsNativeObservationLedger& other) const noexcept {
    return authority_id == other.authority_id && sequence == other.sequence &&
           mutation_epoch == other.mutation_epoch &&
           last_catalog_revision == other.last_catalog_revision &&
           integrity == other.integrity;
}

bool NdmsNativeObservationBinding::operator==(
    const NdmsNativeObservationBinding& other) const noexcept {
    return authority_id == other.authority_id &&
           mutation_epoch == other.mutation_epoch &&
           baseline_sequence == other.baseline_sequence;
}

bool valid_ndms_native_observation_catalog_revision(
    const std::string& revision) noexcept {
    return prefixed_digest(
        revision, kNdmsNativeObservationCatalogRevisionPrefix);
}

bool valid_ndms_native_observation_stamp(
    const NdmsNativeObservationStamp& stamp) noexcept {
    const NdmsNativeObservationBinding shape{
        stamp.authority_id,
        stamp.mutation_epoch,
        stamp.sequence,
    };
    if (!valid_ndms_native_observation_binding(shape) ||
        !valid_ndms_native_observation_catalog_revision(
            stamp.catalog_revision)) {
        return false;
    }
    try {
        NdmsNativeObservationLedger ledger;
        ledger.authority_id = stamp.authority_id;
        ledger.sequence = stamp.sequence;
        ledger.mutation_epoch = stamp.mutation_epoch;
        ledger.last_catalog_revision = stamp.catalog_revision;
        ledger.integrity = stamp.ledger_integrity;
        return prefixed_digest(
                   stamp.ledger_integrity,
                   kNdmsNativeObservationIntegrityPrefix) &&
               stamp.ledger_integrity ==
                   ndms_native_observation_integrity(ledger);
    } catch (...) {
        return false;
    }
}

bool valid_ndms_native_observation_binding(
    const NdmsNativeObservationBinding& binding) noexcept {
    return lower_hex(binding.authority_id, 32U) &&
           binding.mutation_epoch != 0U &&
           binding.baseline_sequence != 0U;
}

NdmsNativeObservationBinding ndms_native_observation_binding(
    const NdmsNativeMutationEpoch& mutation) {
    NdmsNativeObservationBinding binding{
        mutation.authority_id,
        mutation.mutation_epoch,
        mutation.baseline_sequence,
    };
    if (!valid_ndms_native_observation_binding(binding)) {
        throw NdmsNativeObservationStoreError(
            "native mutation epoch cannot bind a WAL record");
    }
    return binding;
}

std::string ndms_native_observation_integrity(
    const NdmsNativeObservationLedger& ledger) {
    if (!core_fields_valid(ledger)) {
        throw NdmsNativeObservationStoreError(
            "native observation ledger fields are invalid");
    }
    Sha256 hasher;
    update_field(hasher, "keen-pbr.ndms-native-observation.integrity.v1");
    update_field(hasher, ledger.authority_id);
    update_field(hasher, decimal(ledger.sequence));
    update_field(hasher, decimal(ledger.mutation_epoch));
    update_field(
        hasher,
        ledger.last_catalog_revision.has_value()
            ? std::string_view{*ledger.last_catalog_revision}
            : std::string_view{"-"});
    return std::string{kNdmsNativeObservationIntegrityPrefix} +
           hasher.hex_digest();
}

NdmsNativeObservationStore::NdmsNativeObservationStore(
    std::filesystem::path state_directory)
    : state_directory_(std::move(state_directory)) {
#ifdef KEEN_PBR3_TESTING
    test_hooks_.allow_current_process_owner = true;
#endif
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeObservationStore::NdmsNativeObservationStore(
    std::filesystem::path state_directory,
    NdmsNativeObservationStoreTestHooks hooks)
    : state_directory_(std::move(state_directory)),
      test_hooks_(std::move(hooks)) {}
#endif

const std::filesystem::path&
NdmsNativeObservationStore::state_directory() const noexcept {
    return state_directory_;
}

void NdmsNativeObservationStore::verify_writer(
    NdmsNativeWriterLease& writer) const {
    writer.verify_held();
    if (writer.state_directory_.lexically_normal() !=
        state_directory_.lexically_normal()) {
        throw NdmsNativeObservationStoreError(
            "native observation store and writer lease directories differ");
    }
}

NdmsNativeObservationReadResult
NdmsNativeObservationStore::read() const noexcept {
    NdmsNativeObservationReadResult result;
    try {
        const auto policy = read_policy(
#ifdef KEEN_PBR3_TESTING
            test_hooks_
#endif
        );
        std::lock_guard<std::mutex> process_lock(observation_store_mutex);
        auto directory = open_directory(state_directory_, policy);
        const auto current = read_locked(directory.get(), policy);
        if (current.state == LockedReadState::absent) {
            result.state = NdmsNativeObservationReadState::absent;
        } else if (current.state == LockedReadState::valid &&
                   current.ledger.has_value()) {
            result.ledger = current.ledger;
            result.state = NdmsNativeObservationReadState::valid;
        }
    } catch (const DirectoryAbsent&) {
        result.state = NdmsNativeObservationReadState::absent;
    } catch (...) {
    }
    return result;
}

NdmsNativeObservationLedger NdmsNativeObservationStore::provision(
    NdmsNativeWriterLease& writer) {
    verify_writer(writer);
    const auto policy = writer_policy(
        static_cast<uid_t>(writer.owner_),
        static_cast<gid_t>(writer.group_)
#ifdef KEEN_PBR3_TESTING
        , test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(observation_store_mutex);
    if (!cleanup_temporaries(writer.directory_descriptor_, policy)) {
        throw NdmsNativeObservationStoreError(
            "native observation temporary inventory is unsafe");
    }
    const auto current = read_locked(writer.directory_descriptor_, policy);
    if (current.state == LockedReadState::valid && current.ledger.has_value()) {
        return *current.ledger;
    }
    if (current.state != LockedReadState::absent) {
        throw NdmsNativeObservationStoreError(
            "existing native observation ledger is unreadable");
    }

    NdmsNativeObservationLedger ledger;
    ledger.authority_id = make_authority_id(policy);
    ledger.integrity = ndms_native_observation_integrity(ledger);
    publish_locked(writer.directory_descriptor_, ledger, true, policy);
    const auto verified = read_locked(writer.directory_descriptor_, policy);
    if (verified.state != LockedReadState::valid || !verified.ledger ||
        !(*verified.ledger == ledger)) {
        throw NdmsNativeObservationStoreError(
            "published native observation authority failed verification");
    }
    writer.verify_held();
    return ledger;
}

NdmsNativeObservationStamp
NdmsNativeObservationStore::record_observation(
    NdmsNativeWriterLease& writer,
    std::string catalog_revision) {
    require_valid_catalog_revision(catalog_revision);
    verify_writer(writer);
    const auto policy = writer_policy(
        static_cast<uid_t>(writer.owner_),
        static_cast<gid_t>(writer.group_)
#ifdef KEEN_PBR3_TESTING
        , test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(observation_store_mutex);
    if (!cleanup_temporaries(writer.directory_descriptor_, policy)) {
        throw NdmsNativeObservationStoreError(
            "native observation temporary inventory is unsafe");
    }
    const auto current = read_locked(writer.directory_descriptor_, policy);
    if (current.state != LockedReadState::valid || !current.ledger) {
        throw NdmsNativeObservationStoreError(
            "native observation authority is not provisioned and valid");
    }
    if (current.ledger->sequence ==
        std::numeric_limits<std::uint64_t>::max()) {
        throw NdmsNativeObservationStoreError(
            "native observation sequence is exhausted");
    }
    auto next = *current.ledger;
    ++next.sequence;
    next.last_catalog_revision = std::move(catalog_revision);
    next.integrity = ndms_native_observation_integrity(next);
    publish_locked(writer.directory_descriptor_, next, false, policy);
    const auto verified = read_locked(writer.directory_descriptor_, policy);
    if (verified.state != LockedReadState::valid || !verified.ledger ||
        !(*verified.ledger == next)) {
        throw NdmsNativeObservationStoreError(
            "sequenced native observation failed durable verification");
    }
    writer.verify_held();
    return stamp_from(next);
}

NdmsNativeMutationEpoch NdmsNativeObservationStore::begin_mutation(
    NdmsNativeWriterLease& writer,
    const NdmsNativeObservationStamp& baseline) {
    require_valid_catalog_revision(baseline.catalog_revision);
    verify_writer(writer);
    const auto policy = writer_policy(
        static_cast<uid_t>(writer.owner_),
        static_cast<gid_t>(writer.group_)
#ifdef KEEN_PBR3_TESTING
        , test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(observation_store_mutex);
    if (!cleanup_temporaries(writer.directory_descriptor_, policy)) {
        throw NdmsNativeObservationStoreError(
            "native observation temporary inventory is unsafe");
    }
    const auto current = read_locked(writer.directory_descriptor_, policy);
    if (current.state != LockedReadState::valid || !current.ledger ||
        current.ledger->sequence == 0U ||
        !current.ledger->last_catalog_revision.has_value() ||
        baseline.authority_id != current.ledger->authority_id ||
        baseline.sequence != current.ledger->sequence ||
        baseline.mutation_epoch != current.ledger->mutation_epoch ||
        baseline.catalog_revision !=
            *current.ledger->last_catalog_revision ||
        baseline.ledger_integrity != current.ledger->integrity) {
        throw NdmsNativeObservationStoreError(
            "native mutation baseline stamp failed exact CAS");
    }
    if (current.ledger->mutation_epoch ==
        std::numeric_limits<std::uint64_t>::max()) {
        throw NdmsNativeObservationStoreError(
            "native observation mutation epoch is exhausted");
    }
    auto next = *current.ledger;
    ++next.mutation_epoch;
    next.integrity = ndms_native_observation_integrity(next);
    publish_locked(writer.directory_descriptor_, next, false, policy);
    const auto verified = read_locked(writer.directory_descriptor_, policy);
    if (verified.state != LockedReadState::valid || !verified.ledger ||
        !(*verified.ledger == next)) {
        throw NdmsNativeObservationStoreError(
            "native mutation epoch failed durable verification");
    }
    writer.verify_held();
    return {
        next.authority_id,
        baseline.sequence,
        next.mutation_epoch,
        baseline.catalog_revision,
        next.integrity,
    };
}

NdmsNativeObservationStamp
NdmsNativeObservationStore::record_mutation_observation(
    NdmsNativeWriterLease& writer,
    const NdmsNativeMutationEpoch& mutation,
    std::string catalog_revision) {
    require_valid_catalog_revision(catalog_revision);
    require_valid_catalog_revision(mutation.baseline_catalog_revision);
    verify_writer(writer);
    const auto policy = writer_policy(
        static_cast<uid_t>(writer.owner_),
        static_cast<gid_t>(writer.group_)
#ifdef KEEN_PBR3_TESTING
        , test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(observation_store_mutex);
    if (!cleanup_temporaries(writer.directory_descriptor_, policy)) {
        throw NdmsNativeObservationStoreError(
            "native observation temporary inventory is unsafe");
    }
    const auto current = read_locked(writer.directory_descriptor_, policy);
    if (current.state != LockedReadState::valid || !current.ledger ||
        mutation.authority_id != current.ledger->authority_id ||
        mutation.baseline_sequence == 0U ||
        current.ledger->sequence < mutation.baseline_sequence ||
        mutation.mutation_epoch == 0U ||
        mutation.mutation_epoch != current.ledger->mutation_epoch ||
        (current.ledger->sequence == mutation.baseline_sequence &&
         mutation.ledger_integrity != current.ledger->integrity)) {
        throw NdmsNativeObservationStoreError(
            "native mutation observation token is stale or mismatched");
    }
    if (current.ledger->sequence ==
        std::numeric_limits<std::uint64_t>::max()) {
        throw NdmsNativeObservationStoreError(
            "native observation sequence is exhausted");
    }
    auto next = *current.ledger;
    ++next.sequence;
    next.last_catalog_revision = std::move(catalog_revision);
    next.integrity = ndms_native_observation_integrity(next);
    publish_locked(writer.directory_descriptor_, next, false, policy);
    const auto verified = read_locked(writer.directory_descriptor_, policy);
    if (verified.state != LockedReadState::valid || !verified.ledger ||
        !(*verified.ledger == next)) {
        throw NdmsNativeObservationStoreError(
            "native mutation observation failed durable verification");
    }
    writer.verify_held();
    return stamp_from(next);
}

NdmsNativeObservationStamp
NdmsNativeObservationStore::record_recovery_observation(
    NdmsNativeWriterLease& writer,
    const NdmsNativeObservationBinding& wal_binding,
    std::string catalog_revision) {
    require_valid_catalog_revision(catalog_revision);
    if (!valid_ndms_native_observation_binding(wal_binding)) {
        throw NdmsNativeObservationStoreError(
            "native recovery observation binding is invalid");
    }
    verify_writer(writer);
    const auto policy = writer_policy(
        static_cast<uid_t>(writer.owner_),
        static_cast<gid_t>(writer.group_)
#ifdef KEEN_PBR3_TESTING
        , test_hooks_
#endif
    );
    std::lock_guard<std::mutex> process_lock(observation_store_mutex);
    if (!cleanup_temporaries(writer.directory_descriptor_, policy)) {
        throw NdmsNativeObservationStoreError(
            "native observation temporary inventory is unsafe");
    }
    const auto current = read_locked(writer.directory_descriptor_, policy);
    if (current.state != LockedReadState::valid || !current.ledger ||
        wal_binding.authority_id != current.ledger->authority_id ||
        wal_binding.mutation_epoch != current.ledger->mutation_epoch ||
        current.ledger->sequence < wal_binding.baseline_sequence) {
        throw NdmsNativeObservationStoreError(
            "native recovery observation binding is stale or mismatched");
    }
    if (current.ledger->sequence ==
        std::numeric_limits<std::uint64_t>::max()) {
        throw NdmsNativeObservationStoreError(
            "native observation sequence is exhausted");
    }
    auto next = *current.ledger;
    ++next.sequence;
    next.last_catalog_revision = std::move(catalog_revision);
    next.integrity = ndms_native_observation_integrity(next);
    publish_locked(writer.directory_descriptor_, next, false, policy);
    const auto verified = read_locked(writer.directory_descriptor_, policy);
    if (verified.state != LockedReadState::valid || !verified.ledger ||
        !(*verified.ledger == next)) {
        throw NdmsNativeObservationStoreError(
            "native recovery observation failed durable verification");
    }
    writer.verify_held();
    return stamp_from(next);
}

const char* ndms_native_observation_read_state_name(
    const NdmsNativeObservationReadState state) noexcept {
    switch (state) {
    case NdmsNativeObservationReadState::absent:
        return "absent";
    case NdmsNativeObservationReadState::valid:
        return "valid";
    case NdmsNativeObservationReadState::unreadable:
        return "unreadable";
    }
    return "unreadable";
}

} // namespace keen_pbr3
