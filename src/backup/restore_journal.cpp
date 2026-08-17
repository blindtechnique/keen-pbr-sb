#include "restore_journal.hpp"

#include "../config/config_writer.hpp"
#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <ctime>
#include <cstring>
#include <dirent.h>
#include <exception>
#include <fcntl.h>
#include <limits>
#include <nlohmann/json.hpp>
#include <signal.h>
#include <set>
#include <stdexcept>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr int kSchemaVersion = 1;
constexpr std::uint64_t kMaxActiveBytes = 64ULL * 1024ULL;
constexpr std::string_view kActiveFilename = "active.json";
constexpr std::string_view kUnknownFilename = "UNKNOWN";
constexpr std::string_view kUnknownBody = "UNKNOWN\n";
constexpr std::string_view kTemporaryPrefix =
    ".keen-pbr-restore-journal.";
constexpr std::string_view kCommittedSuffix = ".committed";
constexpr std::size_t kRetainedRollbackPayloads = 3;
constexpr std::uint64_t kRetainedRollbackBytes =
    128ULL * 1024ULL * 1024ULL;

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

private:
    int value_;
};

std::runtime_error errno_error(const std::string& prefix) {
    const int error = errno;
    return std::runtime_error(prefix + ": " + std::strerror(error));
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
        throw errno_error("Cannot mark " + what + " close-on-exec");
    }
#else
    (void)fd;
    (void)what;
#endif
}

void verify_same_directory(int fd,
                           const struct stat& before,
                           const std::string& component) {
    struct stat after {};
    if (::fstat(fd, &after) != 0) {
        throw errno_error("Cannot inspect opened restore journal directory");
    }
    if (!S_ISDIR(after.st_mode) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino) {
        throw std::runtime_error(
            "Restore journal directory changed while opening '" + component +
            "'");
    }
}

FileDescriptor open_state_directory(const std::filesystem::path& path,
                                    bool create) {
    if (path.empty() || path == "." || path == path.root_path()) {
        throw std::runtime_error(
            "Restore journal needs a dedicated private state directory");
    }

    FileDescriptor current(
        ::open(path.is_absolute() ? "/" : ".", directory_open_flags()));
    if (current.get() < 0) {
        throw errno_error("Cannot open restore journal path root");
    }
    set_close_on_exec_if_needed(
        current.get(), "restore journal path root");

    std::size_t component_count = 0;
    bool final_component_created = false;
    for (const auto& path_component : path.relative_path()) {
        const std::string component = path_component.string();
        if (component.empty() || component == ".") continue;
        if (component == "..") {
            throw std::runtime_error(
                "Restore journal path must not contain '..'");
        }
        ++component_count;

        struct stat before {};
        bool component_created = false;
        if (::fstatat(current.get(),
                      component.c_str(),
                      &before,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT || !create) {
                throw errno_error(
                    "Cannot inspect restore journal directory component");
            }
            if (::mkdirat(current.get(), component.c_str(), 0700) != 0) {
                throw errno_error(
                    "Cannot create restore journal directory component");
            }
            component_created = true;
            if (::fsync(current.get()) != 0) {
                throw errno_error(
                    "Cannot fsync restore journal parent directory");
            }
            if (::fstatat(current.get(),
                          component.c_str(),
                          &before,
                          AT_SYMLINK_NOFOLLOW) != 0) {
                throw errno_error(
                    "Cannot inspect created restore journal directory");
            }
        }
        if (!S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode)) {
            throw std::runtime_error(
                "Refusing a non-directory or symbolic-link restore journal "
                "path component");
        }

        FileDescriptor child(::openat(
            current.get(), component.c_str(), directory_open_flags()));
        if (child.get() < 0) {
            throw errno_error("Cannot open restore journal directory");
        }
        set_close_on_exec_if_needed(
            child.get(), "restore journal directory");
        verify_same_directory(child.get(), before, component);
        current = std::move(child);
        final_component_created = component_created;
    }
    if (component_count == 0) {
        throw std::runtime_error(
            "Restore journal needs a dedicated private state directory");
    }

    struct stat state {};
    if (::fstat(current.get(), &state) != 0) {
        throw errno_error("Cannot inspect restore journal state directory");
    }
    if (state.st_uid != ::geteuid()) {
        throw std::runtime_error(
            "Restore journal state directory has an unexpected owner");
    }
    if ((state.st_mode & 07777) != 0700 && !final_component_created) {
        throw std::runtime_error(
            "Restore journal state directory must have mode 0700");
    }
    if ((state.st_mode & 07777) != 0700) {
        if (::fchmod(current.get(), 0700) != 0) {
            throw errno_error(
                "Cannot make restore journal state directory private");
        }
        if (::fsync(current.get()) != 0) {
            throw errno_error(
                "Cannot fsync private restore journal state directory");
        }
    }
    return current;
}

bool is_lower_hex(const std::string& text, std::size_t length) {
    if (text.size() != length) return false;
    return std::all_of(text.begin(), text.end(), [](unsigned char value) {
        return (value >= '0' && value <= '9') ||
               (value >= 'a' && value <= 'f');
    });
}

void validate_transaction_id(const std::string& transaction_id) {
    if (!is_lower_hex(transaction_id, 32)) {
        throw std::runtime_error(
            "Restore transaction id must be 32 lowercase hexadecimal "
            "characters");
    }
}

std::string snapshot_filename(const std::string& transaction_id) {
    validate_transaction_id(transaction_id);
    return transaction_id + ".rollback";
}

std::string committed_filename(const std::string& transaction_id) {
    validate_transaction_id(transaction_id);
    return transaction_id + std::string(kCommittedSuffix);
}

int phase_index(RestoreJournalPhase phase) {
    switch (phase) {
        case RestoreJournalPhase::prepared:
            return 0;
        case RestoreJournalPhase::files_committed:
            return 1;
        case RestoreJournalPhase::transports_ready:
            return 2;
        case RestoreJournalPhase::core_applied:
            return 3;
        case RestoreJournalPhase::nfqws_ready:
            return 4;
    }
    throw std::runtime_error("Unknown restore journal phase");
}

RestoreJournalPhase parse_phase(const std::string& value) {
    if (value == "prepared") return RestoreJournalPhase::prepared;
    if (value == "files_committed") {
        return RestoreJournalPhase::files_committed;
    }
    if (value == "transports_ready") {
        return RestoreJournalPhase::transports_ready;
    }
    if (value == "core_applied") return RestoreJournalPhase::core_applied;
    if (value == "nfqws_ready") return RestoreJournalPhase::nfqws_ready;
    throw std::runtime_error("Unknown restore journal phase '" + value + "'");
}

int effect_index(RestoreJournalEffect effect) {
    switch (effect) {
        case RestoreJournalEffect::files:
            return 0;
        case RestoreJournalEffect::transport_manager:
            return 1;
        case RestoreJournalEffect::core:
            return 2;
        case RestoreJournalEffect::nfqws:
            return 3;
    }
    throw std::runtime_error("Unknown restore journal effect");
}

RestoreJournalEffect parse_effect(const std::string& value) {
    if (value == "files") return RestoreJournalEffect::files;
    if (value == "transport_manager") {
        return RestoreJournalEffect::transport_manager;
    }
    if (value == "core") return RestoreJournalEffect::core;
    if (value == "nfqws") return RestoreJournalEffect::nfqws;
    throw std::runtime_error("Unknown restore journal effect '" + value + "'");
}

RestoreJournalPhase phase_for_effect(RestoreJournalEffect effect) {
    switch (effect) {
        case RestoreJournalEffect::files:
            return RestoreJournalPhase::files_committed;
        case RestoreJournalEffect::transport_manager:
            return RestoreJournalPhase::transports_ready;
        case RestoreJournalEffect::core:
            return RestoreJournalPhase::core_applied;
        case RestoreJournalEffect::nfqws:
            return RestoreJournalPhase::nfqws_ready;
    }
    throw std::runtime_error("Unknown restore journal effect");
}

std::optional<RestoreJournalEffect> effect_for_phase(
    RestoreJournalPhase phase) {
    switch (phase) {
        case RestoreJournalPhase::prepared:
            return std::nullopt;
        case RestoreJournalPhase::files_committed:
            return RestoreJournalEffect::files;
        case RestoreJournalPhase::transports_ready:
            return RestoreJournalEffect::transport_manager;
        case RestoreJournalPhase::core_applied:
            return RestoreJournalEffect::core;
        case RestoreJournalPhase::nfqws_ready:
            return RestoreJournalEffect::nfqws;
    }
    throw std::runtime_error("Unknown restore journal phase");
}

void canonicalize_effects(std::vector<RestoreJournalEffect>& effects) {
    if (effects.empty()) {
        throw std::runtime_error(
            "Restore journal effects must not be empty");
    }
    std::sort(effects.begin(), effects.end(), [](auto left, auto right) {
        return effect_index(left) < effect_index(right);
    });
    if (std::adjacent_find(effects.begin(), effects.end()) != effects.end()) {
        throw std::runtime_error(
            "Restore journal effects must not contain duplicates");
    }
    if (effects.front() != RestoreJournalEffect::files) {
        throw std::runtime_error(
            "Restore journal must include the files effect");
    }
}

void validate_entry(const RestoreJournalEntry& entry) {
    validate_transaction_id(entry.transaction_id);
    (void)phase_index(entry.phase);
    auto effects = entry.effects;
    canonicalize_effects(effects);
    if (effects != entry.effects) {
        throw std::runtime_error(
            "Restore journal effects are not in canonical order");
    }
    const auto completed_effect = effect_for_phase(entry.phase);
    if (completed_effect.has_value() &&
        std::find(entry.effects.begin(),
                  entry.effects.end(),
                  *completed_effect) == entry.effects.end()) {
        throw std::runtime_error(
            "Restore journal phase does not belong to a declared effect");
    }
    if (entry.snapshot_size == 0) {
        throw std::runtime_error(
            "Restore rollback payload must not be empty");
    }
    if (entry.snapshot_size > RestoreJournal::kMaxRollbackPayloadBytes) {
        throw std::runtime_error(
            "Restore rollback payload exceeds the journal size limit");
    }
    if (!is_lower_hex(entry.snapshot_sha256, 64)) {
        throw std::runtime_error(
            "Restore rollback payload SHA-256 is invalid");
    }
}

void require_exact_keys(const nlohmann::json& object,
                        std::initializer_list<const char*> keys,
                        const std::string& context) {
    if (!object.is_object()) {
        throw std::runtime_error(context + " must be a JSON object");
    }
    std::set<std::string> expected;
    for (const char* key : keys) expected.emplace(key);
    std::set<std::string> actual;
    for (auto it = object.begin(); it != object.end(); ++it) {
        actual.emplace(it.key());
    }
    if (actual != expected) {
        throw std::runtime_error(
            context + " has missing or unknown fields");
    }
}

nlohmann::json entry_without_integrity(const RestoreJournalEntry& entry) {
    validate_entry(entry);
    nlohmann::json effects = nlohmann::json::array();
    for (const auto effect : entry.effects) {
        effects.push_back(to_string(effect));
    }
    return {
        {"schema_version", kSchemaVersion},
        {"transaction_id", entry.transaction_id},
        {"phase", to_string(entry.phase)},
        {"effects", std::move(effects)},
        {"snapshot",
         {
             {"size", entry.snapshot_size},
             {"sha256", entry.snapshot_sha256},
         }},
    };
}

std::string serialize_entry(const RestoreJournalEntry& entry) {
    auto document = entry_without_integrity(entry);
    document["integrity_sha256"] = Sha256::hex(document.dump());
    return document.dump(2) + "\n";
}

RestoreJournalEntry parse_entry(const std::string& body) {
    const auto document = nlohmann::json::parse(body);
    require_exact_keys(
        document,
        {"schema_version",
         "transaction_id",
         "phase",
         "effects",
         "snapshot",
         "integrity_sha256"},
        "Restore journal marker");
    if (!document.at("schema_version").is_number_integer() ||
        document.at("schema_version").get<int>() != kSchemaVersion) {
        throw std::runtime_error(
            "Unsupported restore journal schema version");
    }
    if (!document.at("transaction_id").is_string() ||
        !document.at("phase").is_string() ||
        !document.at("effects").is_array() ||
        !document.at("integrity_sha256").is_string()) {
        throw std::runtime_error(
            "Restore journal marker has invalid field types");
    }

    const auto& snapshot = document.at("snapshot");
    require_exact_keys(
        snapshot, {"size", "sha256"}, "Restore journal snapshot");
    if (!snapshot.at("size").is_number_unsigned() ||
        !snapshot.at("sha256").is_string()) {
        throw std::runtime_error(
            "Restore journal snapshot has invalid field types");
    }

    RestoreJournalEntry entry;
    entry.transaction_id = document.at("transaction_id").get<std::string>();
    entry.phase = parse_phase(document.at("phase").get<std::string>());
    for (const auto& effect : document.at("effects")) {
        if (!effect.is_string()) {
            throw std::runtime_error(
                "Restore journal effect must be a string");
        }
        entry.effects.push_back(
            parse_effect(effect.get<std::string>()));
    }
    entry.snapshot_size = snapshot.at("size").get<std::uint64_t>();
    entry.snapshot_sha256 = snapshot.at("sha256").get<std::string>();
    validate_entry(entry);

    const std::string integrity =
        document.at("integrity_sha256").get<std::string>();
    if (!is_lower_hex(integrity, 64)) {
        throw std::runtime_error(
            "Restore journal integrity SHA-256 is invalid");
    }
    if (integrity != Sha256::hex(entry_without_integrity(entry).dump())) {
        throw std::runtime_error(
            "Restore journal integrity verification failed");
    }
    return entry;
}

std::optional<std::string> read_regular_file(
    int directory_fd,
    const std::string& filename,
    std::uint64_t maximum_size) {
    struct stat before {};
    if (::fstatat(directory_fd,
                  filename.c_str(),
                  &before,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return std::nullopt;
        throw errno_error("Cannot inspect restore journal file");
    }
    if (!S_ISREG(before.st_mode) || S_ISLNK(before.st_mode)) {
        throw std::runtime_error(
            "Refusing a non-regular or symbolic-link restore journal file");
    }
    if (before.st_uid != ::geteuid()) {
        throw std::runtime_error(
            "Restore journal file has an unexpected owner");
    }
    if ((before.st_mode & 07777) != 0600) {
        throw std::runtime_error(
            "Restore journal file must have mode 0600");
    }
    if (before.st_size < 0 ||
        static_cast<std::uint64_t>(before.st_size) > maximum_size) {
        throw std::runtime_error(
            "Restore journal file exceeds its size limit");
    }

    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    FileDescriptor input(::openat(directory_fd, filename.c_str(), flags));
    if (input.get() < 0) {
        throw errno_error("Cannot open restore journal file");
    }
    set_close_on_exec_if_needed(input.get(), "restore journal file");

    struct stat opened {};
    if (::fstat(input.get(), &opened) != 0) {
        throw errno_error("Cannot inspect opened restore journal file");
    }
    if (!S_ISREG(opened.st_mode) || opened.st_uid != ::geteuid() ||
        (opened.st_mode & 07777) != 0600 ||
        before.st_dev != opened.st_dev ||
        before.st_ino != opened.st_ino || before.st_size != opened.st_size) {
        throw std::runtime_error(
            "Restore journal file changed while opening");
    }

    std::string body;
    body.reserve(static_cast<std::size_t>(opened.st_size));
    std::array<char, 8192> buffer{};
    while (true) {
        const ssize_t count =
            ::read(input.get(), buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            throw errno_error("Cannot read restore journal file");
        }
        if (count == 0) break;
        if (body.size() + static_cast<std::size_t>(count) >
            maximum_size) {
            throw std::runtime_error(
                "Restore journal file grew beyond its size limit");
        }
        body.append(buffer.data(), static_cast<std::size_t>(count));
    }
    if (body.size() != static_cast<std::uint64_t>(opened.st_size)) {
        throw std::runtime_error(
            "Restore journal file changed while reading");
    }
    return body;
}

#ifdef KEEN_PBR3_TESTING
using FaultInjector =
    std::function<void(RestoreJournalFaultStage)>;

void inject(const FaultInjector& injector,
            RestoreJournalFaultStage stage) {
    if (injector) injector(stage);
}

RestoreJournalFaultStage map_atomic_stage(
    RestoreJournalFaultStage write,
    RestoreJournalFaultStage file_fsync,
    RestoreJournalFaultStage rename,
    RestoreJournalFaultStage directory_fsync,
    AtomicFileWriteStage stage) {
    switch (stage) {
        case AtomicFileWriteStage::write:
            return write;
        case AtomicFileWriteStage::file_fsync:
            return file_fsync;
        case AtomicFileWriteStage::rename:
            return rename;
        case AtomicFileWriteStage::directory_fsync:
            return directory_fsync;
    }
    throw std::runtime_error("Unknown atomic journal write stage");
}
#endif

enum class JournalFileKind {
    snapshot,
    active,
    unknown,
};

std::atomic<unsigned int> journal_temporary_sequence{0};

void write_all(int fd, const std::string& body) {
    std::size_t offset = 0;
    while (offset < body.size()) {
        const ssize_t written =
            ::write(fd, body.data() + offset, body.size() - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            throw errno_error("Cannot write restore journal file");
        }
        if (written == 0) {
            throw std::runtime_error(
                "Cannot write restore journal file: short write");
        }
        offset += static_cast<std::size_t>(written);
    }
}

bool inspect_journal_destination(int directory_fd,
                                 const std::string& filename,
                                 struct stat& metadata) {
    if (::fstatat(directory_fd,
                  filename.c_str(),
                  &metadata,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return false;
        throw errno_error("Cannot inspect restore journal destination");
    }
    if (!S_ISREG(metadata.st_mode) || S_ISLNK(metadata.st_mode)) {
        throw std::runtime_error(
            "Refusing a non-regular or symbolic-link restore journal "
            "destination");
    }
    if (metadata.st_uid != ::geteuid()) {
        throw std::runtime_error(
            "Restore journal destination has an unexpected owner");
    }
    if ((metadata.st_mode & 07777) != 0600) {
        throw std::runtime_error(
            "Restore journal destination must have mode 0600");
    }
    return true;
}

std::optional<pid_t> temporary_owner_pid(const std::string& filename) {
    if (filename.compare(0, kTemporaryPrefix.size(), kTemporaryPrefix) != 0) {
        return std::nullopt;
    }
    const std::size_t pid_begin = kTemporaryPrefix.size();
    const std::size_t separator = filename.find('.', pid_begin);
    if (separator == std::string::npos || separator == pid_begin ||
        separator + 1 == filename.size()) {
        return std::nullopt;
    }

    std::uint64_t pid_value = 0;
    for (std::size_t index = pid_begin; index < separator; ++index) {
        const unsigned char character =
            static_cast<unsigned char>(filename[index]);
        if (character < '0' || character > '9') return std::nullopt;
        const unsigned int digit = character - '0';
        if (pid_value >
            (static_cast<std::uint64_t>(
                 std::numeric_limits<pid_t>::max()) -
             digit) /
                10) {
            return std::nullopt;
        }
        pid_value = pid_value * 10 + digit;
    }
    for (std::size_t index = separator + 1; index < filename.size();
         ++index) {
        const unsigned char character =
            static_cast<unsigned char>(filename[index]);
        if (character < '0' || character > '9') return std::nullopt;
    }
    if (pid_value == 0) return std::nullopt;
    return static_cast<pid_t>(pid_value);
}

bool process_may_still_exist(pid_t pid) {
    if (pid == ::getpid()) return true;
    if (::kill(pid, 0) == 0) return true;
    return errno != ESRCH;
}

void cleanup_orphaned_temporaries(int directory_fd) {
    const int duplicate = ::dup(directory_fd);
    if (duplicate < 0) {
        throw errno_error(
            "Cannot duplicate restore journal directory for cleanup");
    }
    DIR* directory = ::fdopendir(duplicate);
    if (directory == nullptr) {
        const int error = errno;
        (void)::close(duplicate);
        errno = error;
        throw errno_error(
            "Cannot enumerate restore journal directory for cleanup");
    }

    bool removed = false;
    errno = 0;
    while (const dirent* item = ::readdir(directory)) {
        const std::string filename(item->d_name);
        const auto owner_pid = temporary_owner_pid(filename);
        if (!owner_pid.has_value() ||
            process_may_still_exist(*owner_pid)) {
            errno = 0;
            continue;
        }

        struct stat scanned {};
        if (::fstatat(directory_fd,
                      filename.c_str(),
                      &scanned,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) {
                errno = 0;
                continue;
            }
            const int error = errno;
            (void)::closedir(directory);
            errno = error;
            throw errno_error(
                "Cannot inspect orphaned restore journal temporary");
        }
        // The state directory is private, but still delete only the exact
        // regular-file shape created by write_journal_file(). Unsafe or
        // ambiguous entries are left untouched for operator inspection.
        if (!S_ISREG(scanned.st_mode) || S_ISLNK(scanned.st_mode) ||
            scanned.st_uid != ::geteuid() ||
            (scanned.st_mode & 07777) != 0600 || scanned.st_nlink != 1) {
            errno = 0;
            continue;
        }

        struct stat revalidated {};
        if (::fstatat(directory_fd,
                      filename.c_str(),
                      &revalidated,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) {
                errno = 0;
                continue;
            }
            const int error = errno;
            (void)::closedir(directory);
            errno = error;
            throw errno_error(
                "Cannot revalidate orphaned restore journal temporary");
        }
        if (!S_ISREG(revalidated.st_mode) ||
            revalidated.st_uid != ::geteuid() ||
            (revalidated.st_mode & 07777) != 0600 ||
            revalidated.st_nlink != 1 ||
            revalidated.st_dev != scanned.st_dev ||
            revalidated.st_ino != scanned.st_ino) {
            errno = 0;
            continue;
        }
        if (::unlinkat(directory_fd, filename.c_str(), 0) != 0) {
            if (errno == ENOENT) {
                errno = 0;
                continue;
            }
            const int error = errno;
            (void)::closedir(directory);
            errno = error;
            throw errno_error(
                "Cannot remove orphaned restore journal temporary");
        }
        removed = true;
        errno = 0;
    }
    const int read_error = errno;
    if (::closedir(directory) != 0 && read_error == 0) {
        throw errno_error(
            "Cannot close restore journal cleanup directory");
    }
    if (read_error != 0) {
        errno = read_error;
        throw errno_error(
            "Cannot enumerate restore journal directory for cleanup");
    }
    if (removed && ::fsync(directory_fd) != 0) {
        throw errno_error(
            "Cannot fsync restore journal temporary cleanup");
    }
}

int create_journal_temporary(int directory_fd, std::string& name) {
    for (unsigned int attempt = 0; attempt < 128; ++attempt) {
        const auto sequence = journal_temporary_sequence.fetch_add(
            1, std::memory_order_relaxed);
        name = std::string(kTemporaryPrefix) +
               std::to_string(::getpid()) + "." +
               std::to_string(sequence);

        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        const int fd =
            ::openat(directory_fd, name.c_str(), flags, 0600);
        if (fd >= 0) {
            try {
                set_close_on_exec_if_needed(
                    fd, "temporary restore journal file");
            } catch (...) {
                (void)::close(fd);
                (void)::unlinkat(directory_fd, name.c_str(), 0);
                throw;
            }
            return fd;
        }
        if (errno != EEXIST) {
            throw errno_error(
                "Cannot create temporary restore journal file");
        }
    }
    throw std::runtime_error(
        "Cannot create temporary restore journal file: name space "
        "exhausted");
}

void write_journal_file(
    int directory_fd,
    const std::string& filename,
    const std::string& body,
    JournalFileKind kind
#ifdef KEEN_PBR3_TESTING
    ,
    const FaultInjector& injector
#endif
) {
    if (filename.empty() || filename == "." || filename == ".." ||
        filename.find('/') != std::string::npos) {
        throw std::runtime_error(
            "Invalid restore journal destination filename");
    }

    int temporary_fd = -1;
    std::string temporary_name;
    bool temporary_exists = false;
    bool committed = false;
    try {
        struct stat existing {};
        const bool exists = inspect_journal_destination(
            directory_fd, filename, existing);
        temporary_fd =
            create_journal_temporary(directory_fd, temporary_name);
        temporary_exists = true;
        if (exists &&
            ::fchown(
                temporary_fd, existing.st_uid, existing.st_gid) != 0) {
            throw errno_error(
                "Cannot preserve restore journal file ownership");
        }
        if (::fchmod(temporary_fd, 0600) != 0) {
            throw errno_error(
                "Cannot set temporary restore journal file mode");
        }
#ifdef KEEN_PBR3_TESTING
        const auto inject_stage =
            [kind, &injector](AtomicFileWriteStage stage) {
            RestoreJournalFaultStage mapped{};
            switch (kind) {
                case JournalFileKind::snapshot:
                    mapped = map_atomic_stage(
                        RestoreJournalFaultStage::snapshot_write,
                        RestoreJournalFaultStage::snapshot_file_fsync,
                        RestoreJournalFaultStage::snapshot_rename,
                        RestoreJournalFaultStage::snapshot_directory_fsync,
                        stage);
                    break;
                case JournalFileKind::active:
                    mapped = map_atomic_stage(
                        RestoreJournalFaultStage::active_write,
                        RestoreJournalFaultStage::active_file_fsync,
                        RestoreJournalFaultStage::active_rename,
                        RestoreJournalFaultStage::active_directory_fsync,
                        stage);
                    break;
                case JournalFileKind::unknown:
                    mapped = map_atomic_stage(
                        RestoreJournalFaultStage::unknown_write,
                        RestoreJournalFaultStage::unknown_file_fsync,
                        RestoreJournalFaultStage::unknown_rename,
                        RestoreJournalFaultStage::unknown_directory_fsync,
                        stage);
                    break;
            }
            inject(injector, mapped);
        };
#endif

#ifdef KEEN_PBR3_TESTING
        inject_stage(AtomicFileWriteStage::write);
#else
        (void)kind;
#endif
        write_all(temporary_fd, body);
#ifdef KEEN_PBR3_TESTING
        inject_stage(AtomicFileWriteStage::file_fsync);
#endif
        if (::fsync(temporary_fd) != 0) {
            throw errno_error(
                "Cannot fsync temporary restore journal file");
        }
        if (::close(temporary_fd) != 0) {
            temporary_fd = -1;
            throw errno_error(
                "Cannot close temporary restore journal file");
        }
        temporary_fd = -1;

#ifdef KEEN_PBR3_TESTING
        inject_stage(AtomicFileWriteStage::rename);
#endif
        if (::renameat(directory_fd,
                       temporary_name.c_str(),
                       directory_fd,
                       filename.c_str()) != 0) {
            throw errno_error("Cannot replace restore journal file");
        }
        temporary_exists = false;
        committed = true;

#ifdef KEEN_PBR3_TESTING
        inject_stage(AtomicFileWriteStage::directory_fsync);
#endif
        if (::fsync(directory_fd) != 0) {
            throw errno_error("Cannot fsync restore journal directory");
        }
    } catch (const std::exception& error) {
        if (temporary_fd >= 0) (void)::close(temporary_fd);
        if (temporary_exists) {
            (void)::unlinkat(
                directory_fd, temporary_name.c_str(), 0);
        }
        throw AtomicFileWriteError(error.what(), committed);
    } catch (...) {
        if (temporary_fd >= 0) (void)::close(temporary_fd);
        if (temporary_exists) {
            (void)::unlinkat(
                directory_fd, temporary_name.c_str(), 0);
        }
        throw AtomicFileWriteError(
            "Unknown restore journal write failure", committed);
    }
}

void make_existing_payload_durable(
    const std::filesystem::path& directory,
    const std::string& filename
#ifdef KEEN_PBR3_TESTING
    ,
    const FaultInjector& injector
#endif
) {
    auto directory_fd = open_state_directory(directory, false);
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    FileDescriptor payload(
        ::openat(directory_fd.get(), filename.c_str(), flags));
    if (payload.get() < 0) {
        throw errno_error(
            "Cannot open existing restore rollback payload");
    }
    set_close_on_exec_if_needed(
        payload.get(), "restore rollback payload");
#ifdef KEEN_PBR3_TESTING
    inject(injector, RestoreJournalFaultStage::snapshot_file_fsync);
#endif
    if (::fsync(payload.get()) != 0) {
        throw errno_error(
            "Cannot fsync existing restore rollback payload");
    }
#ifdef KEEN_PBR3_TESTING
    inject(
        injector,
        RestoreJournalFaultStage::snapshot_directory_fsync);
#endif
    if (::fsync(directory_fd.get()) != 0) {
        throw errno_error(
            "Cannot fsync restore rollback payload directory");
    }
}

struct RollbackCandidate {
    std::string filename;
    std::string transaction_id;
    std::uint64_t size{0};
    dev_t device{0};
    ino_t inode{0};
    struct timespec modified_at {};
};

std::optional<std::string> active_transaction_for_gc(int directory_fd) {
    const auto marker = read_regular_file(
        directory_fd,
        std::string(kActiveFilename),
        kMaxActiveBytes);
    if (!marker.has_value()) return std::nullopt;
    return parse_entry(*marker).transaction_id;
}

std::optional<RestoreJournalEntry> read_committed_receipt(
    int directory_fd,
    const std::string& transaction_id) {
    const auto marker = read_regular_file(
        directory_fd,
        committed_filename(transaction_id),
        kMaxActiveBytes);
    if (!marker.has_value()) return std::nullopt;

    const auto receipt = parse_entry(*marker);
    if (receipt.transaction_id != transaction_id ||
        receipt.phase != phase_for_effect(receipt.effects.back())) {
        throw std::runtime_error(
            "Restore commit receipt does not describe the requested "
            "terminal transaction");
    }
    return receipt;
}

std::vector<RollbackCandidate> scan_rollback_candidates(
    int directory_fd) {
    const int duplicate = ::dup(directory_fd);
    if (duplicate < 0) {
        throw errno_error(
            "Cannot duplicate restore journal directory for retention");
    }
    DIR* directory = ::fdopendir(duplicate);
    if (directory == nullptr) {
        const int error = errno;
        (void)::close(duplicate);
        errno = error;
        throw errno_error(
            "Cannot enumerate restore journal directory");
    }

    std::vector<RollbackCandidate> candidates;
    errno = 0;
    while (const dirent* item = ::readdir(directory)) {
        const std::string filename(item->d_name);
        constexpr std::string_view suffix = ".rollback";
        if (filename.size() != 32 + suffix.size() ||
            filename.compare(32, suffix.size(), suffix) != 0) {
            continue;
        }
        const std::string transaction_id = filename.substr(0, 32);
        if (!is_lower_hex(transaction_id, 32)) continue;

        struct stat metadata {};
        if (::fstatat(directory_fd,
                      filename.c_str(),
                      &metadata,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            const int error = errno;
            (void)::closedir(directory);
            errno = error;
            throw errno_error(
                "Cannot inspect retained restore rollback payload");
        }
        if (!S_ISREG(metadata.st_mode) || S_ISLNK(metadata.st_mode) ||
             metadata.st_uid != ::geteuid() ||
             (metadata.st_mode & 07777) != 0600 ||
             metadata.st_nlink != 1 ||
             metadata.st_size < 0 ||
            static_cast<std::uint64_t>(metadata.st_size) >
                RestoreJournal::kMaxRollbackPayloadBytes) {
            (void)::closedir(directory);
            throw std::runtime_error(
                "Refusing unsafe restore rollback payload during "
                "retention");
        }
        candidates.push_back(
            {filename,
             transaction_id,
             static_cast<std::uint64_t>(metadata.st_size),
             metadata.st_dev,
             metadata.st_ino,
             metadata.st_mtim});
        errno = 0;
    }
    const int read_error = errno;
    if (::closedir(directory) != 0 && read_error == 0) {
        throw errno_error(
            "Cannot close restore journal retention directory");
    }
    if (read_error != 0) {
        errno = read_error;
        throw errno_error(
            "Cannot enumerate restore journal directory");
    }

    std::sort(
        candidates.begin(),
        candidates.end(),
        [](const RollbackCandidate& left,
           const RollbackCandidate& right) {
            if (left.modified_at.tv_sec != right.modified_at.tv_sec ||
                left.modified_at.tv_nsec != right.modified_at.tv_nsec) {
                if (left.modified_at.tv_sec != right.modified_at.tv_sec) {
                    return left.modified_at.tv_sec >
                           right.modified_at.tv_sec;
                }
                return left.modified_at.tv_nsec >
                       right.modified_at.tv_nsec;
            }
            return left.filename > right.filename;
        });
    return candidates;
}

void collect_old_rollback_payloads(
    int directory_fd
#ifdef KEEN_PBR3_TESTING
    ,
    const FaultInjector& injector
#endif
) {
#ifdef KEEN_PBR3_TESTING
    inject(injector, RestoreJournalFaultStage::rollback_gc_scan);
#endif
    // Never perform retention while any restore transaction is active. This
    // also makes a concurrent post-commit begin fail-safe: retention becomes
    // a no-op instead of trying to reason about its immutable payload.
    if (active_transaction_for_gc(directory_fd).has_value()) return;
    const auto candidates =
        scan_rollback_candidates(directory_fd);

    std::size_t retained = 0;
    std::uint64_t retained_bytes = 0;
    std::size_t first_expired = candidates.size();
    for (std::size_t index = 0; index < candidates.size(); ++index) {
        const auto& candidate = candidates[index];
        if (retained == kRetainedRollbackPayloads ||
            candidate.size > kRetainedRollbackBytes - retained_bytes) {
            first_expired = index;
            break;
        }
        ++retained;
        retained_bytes += candidate.size;
    }
    if (first_expired == candidates.size()) return;

    bool removed = false;
    for (std::size_t index = first_expired;
         index < candidates.size();
         ++index) {
        const auto& candidate = candidates[index];

        // A new restore may have been activated after the initial scan.
        // Re-read the marker before every unlink and always privilege
        // recovery correctness over retention bounds.
        if (active_transaction_for_gc(directory_fd).has_value()) return;

#ifdef KEEN_PBR3_TESTING
        // Fault injection happens before the last identity check so tests can
        // model a pathname replacement between the scan and unlink.
        inject(injector, RestoreJournalFaultStage::rollback_gc_unlink);
#endif
        struct stat metadata {};
        if (::fstatat(directory_fd,
                      candidate.filename.c_str(),
                      &metadata,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) continue;
            throw errno_error(
                "Cannot revalidate old restore rollback payload");
        }
        if (!S_ISREG(metadata.st_mode) || S_ISLNK(metadata.st_mode) ||
             metadata.st_uid != ::geteuid() ||
             (metadata.st_mode & 07777) != 0600 ||
             metadata.st_nlink != 1 ||
             metadata.st_size < 0 ||
             static_cast<std::uint64_t>(metadata.st_size) !=
                 candidate.size ||
             metadata.st_dev != candidate.device ||
             metadata.st_ino != candidate.inode) {
            throw std::runtime_error(
                "Refusing changed or unsafe restore rollback payload "
                "during retention");
        }
        if (::unlinkat(
                directory_fd, candidate.filename.c_str(), 0) != 0) {
            if (errno == ENOENT) continue;
            throw errno_error(
                "Cannot remove old restore rollback payload");
        }
        removed = true;
    }
    if (!removed) return;
#ifdef KEEN_PBR3_TESTING
    inject(
        injector,
        RestoreJournalFaultStage::rollback_gc_directory_fsync);
#endif
    if (::fsync(directory_fd) != 0) {
        throw errno_error(
            "Cannot fsync restore rollback retention changes");
    }
}

class UnsafeRestoreJournalError final : public std::runtime_error {
public:
    explicit UnsafeRestoreJournalError(const std::string& reason)
        : std::runtime_error(
              "Restore journal is unsafe: " + reason) {}
};

UnsafeRestoreJournalError journal_error(const std::string& reason) {
    return UnsafeRestoreJournalError(reason);
}

} // namespace

bool RestoreJournalEntry::operator==(
    const RestoreJournalEntry& other) const noexcept {
    return transaction_id == other.transaction_id &&
           phase == other.phase && effects == other.effects &&
           snapshot_size == other.snapshot_size &&
           snapshot_sha256 == other.snapshot_sha256;
}

const char* to_string(RestoreJournalPhase phase) noexcept {
    switch (phase) {
        case RestoreJournalPhase::prepared:
            return "prepared";
        case RestoreJournalPhase::files_committed:
            return "files_committed";
        case RestoreJournalPhase::transports_ready:
            return "transports_ready";
        case RestoreJournalPhase::core_applied:
            return "core_applied";
        case RestoreJournalPhase::nfqws_ready:
            return "nfqws_ready";
    }
    return "unknown";
}

const char* to_string(RestoreJournalEffect effect) noexcept {
    switch (effect) {
        case RestoreJournalEffect::files:
            return "files";
        case RestoreJournalEffect::transport_manager:
            return "transport_manager";
        case RestoreJournalEffect::core:
            return "core";
        case RestoreJournalEffect::nfqws:
            return "nfqws";
    }
    return "unknown";
}

RestoreJournal::RestoreJournal(
    std::filesystem::path state_directory)
    : state_directory_(std::move(state_directory)) {
    auto directory_fd = open_state_directory(state_directory_, true);
    cleanup_orphaned_temporaries(directory_fd.get());
}

#ifdef KEEN_PBR3_TESTING
RestoreJournal::RestoreJournal(
    std::filesystem::path state_directory,
    RestoreJournalTestHooks hooks)
    : state_directory_(std::move(state_directory)),
      test_hooks_(std::move(hooks)) {
    auto directory_fd = open_state_directory(state_directory_, true);
    cleanup_orphaned_temporaries(directory_fd.get());
}
#endif

RestoreJournalEntry RestoreJournal::begin(
    const std::string& transaction_id,
    const std::string& exact_rollback_payload,
    std::vector<RestoreJournalEffect> effects) {
    validate_transaction_id(transaction_id);
    canonicalize_effects(effects);
    if (exact_rollback_payload.empty()) {
        throw std::runtime_error(
            "Restore rollback payload must not be empty");
    }
    if (exact_rollback_payload.size() > kMaxRollbackPayloadBytes) {
        throw std::runtime_error(
            "Restore rollback payload exceeds the journal size limit");
    }
    if (unknown_present()) {
        throw journal_error("UNKNOWN marker is present");
    }

    RestoreJournalEntry expected{
        transaction_id,
        RestoreJournalPhase::prepared,
        std::move(effects),
        static_cast<std::uint64_t>(exact_rollback_payload.size()),
        Sha256::hex(exact_rollback_payload),
    };

    if (const auto active = read_active()) {
        if (active->transaction_id != expected.transaction_id) {
            throw std::runtime_error(
                "Another restore transaction is already active");
        }
        const auto existing_payload = read_rollback_payload(*active);
        if (active->effects != expected.effects ||
            active->snapshot_size != expected.snapshot_size ||
            active->snapshot_sha256 != expected.snapshot_sha256 ||
            existing_payload != exact_rollback_payload) {
            try {
                mark_unknown();
            } catch (...) {
            }
            throw journal_error(
                "transaction id was reused with different restore data");
        }
        return *active;
    }

    const std::string filename = snapshot_filename(transaction_id);
    auto directory_fd = open_state_directory(state_directory_, false);
    std::optional<std::string> existing;
    std::optional<RestoreJournalEntry> committed;
    try {
        existing = read_regular_file(
            directory_fd.get(), filename, kMaxRollbackPayloadBytes);
        committed = read_committed_receipt(
            directory_fd.get(), transaction_id);
    } catch (const std::exception& error) {
        try {
            mark_unknown();
        } catch (...) {
        }
        throw journal_error(error.what());
    }
    if (existing.has_value()) {
        if (*existing != exact_rollback_payload) {
            try {
                mark_unknown();
            } catch (...) {
            }
            throw journal_error(
                "immutable rollback payload already has different bytes");
        }
    }
    if (committed.has_value()) {
        if (committed->effects != expected.effects ||
            committed->snapshot_size != expected.snapshot_size ||
            committed->snapshot_sha256 != expected.snapshot_sha256) {
            try {
                mark_unknown();
            } catch (...) {
            }
            throw journal_error(
                "committed transaction id has different restore "
                "metadata");
        }
        throw std::runtime_error(
            "Restore transaction is already committed");
    }

    if (existing.has_value()) {
        make_existing_payload_durable(
            state_directory_,
            filename
#ifdef KEEN_PBR3_TESTING
            ,
            test_hooks_.fault_injector
#endif
        );
    } else {
        write_journal_file(
            directory_fd.get(),
            filename,
            exact_rollback_payload,
            JournalFileKind::snapshot
#ifdef KEEN_PBR3_TESTING
            ,
            test_hooks_.fault_injector
#endif
        );
    }

    // Verify exact bytes again before publishing the active marker.
    directory_fd = open_state_directory(state_directory_, false);
    const auto durable_payload = read_regular_file(
        directory_fd.get(), filename, kMaxRollbackPayloadBytes);
    if (!durable_payload.has_value() ||
        durable_payload->size() != expected.snapshot_size ||
        Sha256::hex(*durable_payload) != expected.snapshot_sha256 ||
        *durable_payload != exact_rollback_payload) {
        try {
            mark_unknown();
        } catch (...) {
        }
        throw journal_error(
            "rollback payload verification failed before activation");
    }

    try {
        write_journal_file(
            directory_fd.get(),
            std::string(kActiveFilename),
            serialize_entry(expected),
            JournalFileKind::active
#ifdef KEEN_PBR3_TESTING
            ,
            test_hooks_.fault_injector
#endif
        );
    } catch (const AtomicFileWriteError& error) {
        if (error.committed()) {
            try {
                mark_unknown();
            } catch (...) {
            }
        }
        throw;
    }

    const auto active = read_active();
    if (!active.has_value() || !(*active == expected)) {
        try {
            mark_unknown();
        } catch (...) {
        }
        throw journal_error(
            "active marker verification failed after activation");
    }
    return *active;
}

std::optional<RestoreJournalEntry> RestoreJournal::read_active() {
    if (unknown_present()) {
        throw journal_error("UNKNOWN marker is present");
    }
    try {
        auto directory_fd =
            open_state_directory(state_directory_, false);
        const auto body = read_regular_file(
            directory_fd.get(),
            std::string(kActiveFilename),
            kMaxActiveBytes);
        if (!body.has_value()) return std::nullopt;

        const auto entry = parse_entry(*body);
        (void)read_rollback_payload(entry);
        return entry;
    } catch (const UnsafeRestoreJournalError&) {
        throw;
    } catch (const std::exception& error) {
        try {
            mark_unknown();
        } catch (...) {
        }
        throw journal_error(error.what());
    }
}

std::string RestoreJournal::read_rollback_payload(
    const RestoreJournalEntry& entry) {
    if (unknown_present()) {
        throw journal_error("UNKNOWN marker is present");
    }
    try {
        validate_entry(entry);
        auto directory_fd =
            open_state_directory(state_directory_, false);
        const auto body = read_regular_file(
            directory_fd.get(),
            snapshot_filename(entry.transaction_id),
            kMaxRollbackPayloadBytes);
        if (!body.has_value()) {
            throw std::runtime_error(
                "Restore rollback payload is missing");
        }
        if (body->size() != entry.snapshot_size) {
            throw std::runtime_error(
                "Restore rollback payload size does not match active marker");
        }
        if (Sha256::hex(*body) != entry.snapshot_sha256) {
            throw std::runtime_error(
                "Restore rollback payload SHA-256 does not match active "
                "marker");
        }
        return *body;
    } catch (const UnsafeRestoreJournalError&) {
        throw;
    } catch (const std::exception& error) {
        try {
            mark_unknown();
        } catch (...) {
        }
        throw journal_error(error.what());
    }
}

RestoreJournalEntry RestoreJournal::advance_phase(
    const std::string& transaction_id,
    RestoreJournalPhase phase) {
    validate_transaction_id(transaction_id);
    const auto active = read_active();
    if (!active.has_value()) {
        throw std::runtime_error(
            "No restore transaction is active");
    }
    if (active->transaction_id != transaction_id) {
        throw std::runtime_error(
            "Restore transaction id does not match active journal");
    }

    if (phase == active->phase) return *active;

    std::size_t next_effect_index = 0;
    const auto completed_effect = effect_for_phase(active->phase);
    if (completed_effect.has_value()) {
        const auto current_effect =
            std::find(active->effects.begin(),
                      active->effects.end(),
                      *completed_effect);
        if (current_effect == active->effects.end()) {
            throw std::runtime_error(
                "Active restore phase is not a declared effect");
        }
        next_effect_index =
            static_cast<std::size_t>(
                std::distance(active->effects.begin(), current_effect)) +
            1;
    }
    if (next_effect_index >= active->effects.size()) {
        throw std::runtime_error(
            "Restore transaction has already reached its terminal phase");
    }
    const RestoreJournalPhase expected =
        phase_for_effect(active->effects[next_effect_index]);
    if (phase != expected) {
        throw std::runtime_error(
            "Restore journal must advance to the next declared-effect "
            "milestone");
    }

    RestoreJournalEntry updated = *active;
    updated.phase = phase;
    auto directory_fd =
        open_state_directory(state_directory_, false);
    try {
        write_journal_file(
            directory_fd.get(),
            std::string(kActiveFilename),
            serialize_entry(updated),
            JournalFileKind::active
#ifdef KEEN_PBR3_TESTING
            ,
            test_hooks_.fault_injector
#endif
        );
    } catch (const AtomicFileWriteError& error) {
        if (error.committed()) {
            try {
                mark_unknown();
            } catch (...) {
            }
        }
        throw;
    }

    const auto verified = read_active();
    if (!verified.has_value() || !(*verified == updated)) {
        try {
            mark_unknown();
        } catch (...) {
        }
        throw journal_error(
            "active marker verification failed after phase advance");
    }
    return *verified;
}

void RestoreJournal::commit(const std::string& transaction_id) {
    validate_transaction_id(transaction_id);
    if (unknown_present()) {
        throw journal_error("UNKNOWN marker is present");
    }
    const auto active = read_active();
    if (!active.has_value()) {
        try {
            auto directory_fd =
                open_state_directory(state_directory_, false);
            if (read_committed_receipt(
                    directory_fd.get(), transaction_id)
                    .has_value()) {
                return;
            }
        } catch (const std::exception& error) {
            try {
                mark_unknown();
            } catch (...) {
            }
            throw journal_error(error.what());
        }
        throw std::runtime_error(
            "No matching committed restore transaction exists");
    }
    if (active->transaction_id != transaction_id) {
        throw std::runtime_error(
            "Restore transaction id does not match active journal");
    }
    const RestoreJournalPhase terminal =
        phase_for_effect(active->effects.back());
    if (active->phase != terminal) {
        throw std::runtime_error(
            "Restore transaction has not reached its terminal phase");
    }

    remove_active_marker(*active, true);
}

void RestoreJournal::complete_rollback(
    const std::string& transaction_id) {
    validate_transaction_id(transaction_id);
    if (unknown_present()) {
        throw journal_error("UNKNOWN marker is present");
    }

    // read_active() verifies both the marker integrity and the exact immutable
    // rollback payload before the transaction can be completed.
    const auto active = read_active();
    if (!active.has_value()) return;
    if (active->transaction_id != transaction_id) {
        throw std::runtime_error(
            "Restore transaction id does not match active journal");
    }

    remove_active_marker(*active, false);
}

void RestoreJournal::remove_active_marker(
    const RestoreJournalEntry& active,
    bool preserve_commit_receipt) {
    bool active_disappeared = false;
    try {
        auto directory_fd =
            open_state_directory(state_directory_, false);
        const std::string receipt =
            committed_filename(active.transaction_id);
        const auto existing_receipt = read_committed_receipt(
            directory_fd.get(), active.transaction_id);
        if (existing_receipt.has_value() &&
            !(*existing_receipt == active)) {
            throw std::runtime_error(
                "Restore commit receipt does not match active journal");
        }

        if (!preserve_commit_receipt &&
            existing_receipt.has_value() &&
            ::unlinkat(directory_fd.get(), receipt.c_str(), 0) != 0 &&
            errno != ENOENT) {
            throw errno_error(
                "Cannot remove stale restore commit receipt");
        }
#ifdef KEEN_PBR3_TESTING
        inject(
            test_hooks_.fault_injector,
            RestoreJournalFaultStage::active_remove);
#endif
        if (preserve_commit_receipt) {
            // Renaming the exact terminal active marker preserves a durable
            // transaction-specific receipt while making active.json absent
            // at the same commit point. That lets a retry distinguish this
            // committed transaction from an unrelated id without widening
            // the public journal API.
            if (::renameat(directory_fd.get(),
                           kActiveFilename.data(),
                           directory_fd.get(),
                           receipt.c_str()) != 0) {
                throw errno_error(
                    "Cannot publish restore commit receipt");
            }
            active_disappeared = true;
        } else {
            if (::unlinkat(directory_fd.get(),
                           kActiveFilename.data(),
                           0) != 0) {
                throw errno_error(
                    "Cannot remove active restore journal marker");
            }
            active_disappeared = true;
        }
#ifdef KEEN_PBR3_TESTING
        inject(
            test_hooks_.fault_injector,
            RestoreJournalFaultStage::active_remove_directory_fsync);
#endif
        if (::fsync(directory_fd.get()) != 0) {
            throw errno_error(
                "Cannot fsync restore journal commit point");
        }
    } catch (...) {
        const auto original_failure = std::current_exception();
        if (active_disappeared) {
            try {
                // A marker removal/rename without a durable parent fsync is
                // not a reliable commit: publish the exact previous marker
                // again so startup can deterministically roll back. UNKNOWN
                // is reserved for the rarer case where even that
                // compensation cannot be made durable.
                auto directory_fd =
                    open_state_directory(state_directory_, false);
                write_journal_file(
                    directory_fd.get(),
                    std::string(kActiveFilename),
                    serialize_entry(active),
                    JournalFileKind::active
#ifdef KEEN_PBR3_TESTING
                    ,
                    test_hooks_.fault_injector
#endif
                );
            } catch (...) {
                try {
                    mark_unknown();
                } catch (...) {
                }
            }
        }
        std::rethrow_exception(original_failure);
    }

    // The active-marker removal and its parent fsync are the transaction
    // commit point. Retention is deliberately best-effort after that point:
    // its failure must never recreate active.json or manufacture UNKNOWN.
    try {
        auto directory_fd =
            open_state_directory(state_directory_, false);
        collect_old_rollback_payloads(
            directory_fd.get()
#ifdef KEEN_PBR3_TESTING
            ,
            test_hooks_.fault_injector
#endif
        );
    } catch (...) {
    }
}

bool RestoreJournal::unknown_present() {
    auto directory_fd =
        open_state_directory(state_directory_, false);
    return read_regular_file(
               directory_fd.get(),
               std::string(kUnknownFilename),
               64)
        .has_value();
}

void RestoreJournal::mark_unknown() {
    auto directory_fd =
        open_state_directory(state_directory_, false);
    write_journal_file(
        directory_fd.get(),
        std::string(kUnknownFilename),
        std::string(kUnknownBody),
        JournalFileKind::unknown
#ifdef KEEN_PBR3_TESTING
        ,
        test_hooks_.fault_injector
#endif
    );
}

const std::filesystem::path& RestoreJournal::state_directory() const noexcept {
    return state_directory_;
}

} // namespace keen_pbr3
