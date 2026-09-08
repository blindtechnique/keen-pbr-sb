#include "component_capture.hpp"

#include "rescue_integrity.hpp"

#include "../config/config_writer.hpp"
#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <optional>
#include <set>
#include <sstream>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

constexpr const char* kManifestHeader = "keen-pbr-component-capture-v2";
constexpr const char* kAbsentManifestHeader = "keen-pbr-component-capture-v3";
constexpr const char* kMetadataManifestHeader = "keen-pbr-component-capture-v4";
constexpr const char* kManifestName = "manifest";
constexpr const char* kReadyName = ".ready";
constexpr const char* kFilesDir = "files";
constexpr const char* kGenerationsDir = "generations";
constexpr const char* kCurrentName = "current";
constexpr mode_t kStoredFileMode = 0600;
constexpr mode_t kStoreDirectoryMode = 0700;
constexpr std::size_t kMaxStoredGenerations = 8;
constexpr std::uintmax_t kMaxManifestBytes =
    kComponentMaxPathCount * (kComponentMaxPathLength + 160U) +
    4U * kComponentMaxPathLength + 256U;

struct ManifestEntry {
    std::size_t index{0};
    std::uint32_t mode{0};
    std::uint32_t owner{0};
    std::uint32_t group{0};
    std::uintmax_t size{0};
    std::string sha256;
    std::string path;
    bool absent{false};
    bool metadata{false};
    bool status{false};
};

std::string stored_name(std::size_t index) {
    std::ostringstream name;
    name << std::setw(6) << std::setfill('0') << index;
    return name.str();
}

bool real_directory(const fs::path& path) {
    struct stat state {};
    return ::lstat(path.c_str(), &state) == 0 && S_ISDIR(state.st_mode);
}

bool valid_path(const std::string& value) {
    if (value.empty() || value.size() > kComponentMaxPathLength ||
        value.front() != '/' || value.find('\0') != std::string::npos) {
        return false;
    }
    if (std::any_of(value.begin(), value.end(), [](unsigned char ch) {
            return ch < 0x20U || ch == 0x7fU;
        })) {
        return false;
    }
    const fs::path path(value);
    return path.is_absolute() && path.lexically_normal() == path &&
           path.has_filename() && path != path.root_path();
}

bool insert_unique_path(std::set<std::string>& paths, const std::string& path) {
    if (paths.count(path) != 0U) return false;
    for (auto parent = fs::path(path).parent_path();
         parent != parent.root_path(); parent = parent.parent_path()) {
        if (paths.count(parent.string()) != 0U) return false;
    }
    const auto prefix = path + '/';
    const auto child = paths.lower_bound(prefix);
    if (child != paths.end() && child->compare(0, prefix.size(), prefix) == 0)
        return false;
    paths.insert(path);
    return true;
}

bool below(const fs::path& path, const fs::path& root) {
    const auto relative = path.lexically_relative(root);
    return !relative.empty() && relative != "." &&
           *relative.begin() != ".." && !relative.is_absolute();
}

std::optional<fs::path> source_anchor(const fs::path& path,
                                    const fs::path& store) {
    if (below(path, fs::path("/opt"))) return fs::path("/opt");
    // Fixtures have no global override: both store and source must belong to
    // the same private directory immediately below the system temporary root.
    std::error_code error;
    const auto temporary = fs::temp_directory_path(error);
    if (error || temporary == temporary.root_path() ||
        !below(path, temporary) || !below(store, temporary)) return std::nullopt;
    const auto relative = path.lexically_relative(temporary);
    const auto anchor = temporary / *relative.begin();
    if (!below(path, anchor) || !below(store, anchor) ||
        !real_directory(anchor)) return std::nullopt;
    return anchor;
}

enum class ParentState { blocked, missing, ready };

struct SourceParent {
    int fd{-1};
    ParentState state{ParentState::blocked};
    SourceParent() = default;
    SourceParent(const SourceParent&) = delete;
    SourceParent& operator=(const SourceParent&) = delete;
    ~SourceParent() { if (fd >= 0) ::close(fd); }
};

void open_source_parent(const fs::path& path, const fs::path& store,
                        SourceParent& result) {
    const auto anchor = source_anchor(path, store);
    if (!anchor) return;
    // /opt itself may be the platform's mount alias; only this trusted anchor
    // is followed. Each parent below it is inspected without following links.
    const int anchor_flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                             (*anchor == fs::path("/opt") ? 0 : O_NOFOLLOW);
    result.fd = ::open(anchor->c_str(), anchor_flags);
    if (result.fd < 0) return;
    const auto parents = path.parent_path().lexically_relative(*anchor);
    for (const auto& part : parents) {
        if (part == ".") continue;
        struct stat state {};
        if (::fstatat(result.fd, part.c_str(), &state, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT) return;
            result.state = ParentState::missing;
            return;
        }
        if (!S_ISDIR(state.st_mode)) return;
        const int next = ::openat(result.fd, part.c_str(),
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) return;
        struct stat opened {};
        if (::fstat(next, &opened) != 0 || !S_ISDIR(opened.st_mode) ||
            opened.st_dev != state.st_dev || opened.st_ino != state.st_ino) {
            ::close(next);
            return;
        }
        ::close(result.fd);
        result.fd = next;
    }
    result.state = ParentState::ready;
}

bool source_is_absent(const fs::path& path, const fs::path& store) {
    SourceParent parent;
    open_source_parent(path, store, parent);
    if (parent.state == ParentState::missing) return true;
    if (parent.state != ParentState::ready) return false;
    struct stat state {};
    return ::fstatat(parent.fd, path.filename().c_str(), &state,
                     AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}

bool restore_absent_leaf(const fs::path& path, const fs::path& store,
                         bool& removed) {
    SourceParent parent;
    open_source_parent(path, store, parent);
    if (parent.state == ParentState::missing) return true;
    if (parent.state != ParentState::ready) return false;
    struct stat state {};
    if (::fstatat(parent.fd, path.filename().c_str(), &state,
                  AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT && ::fsync(parent.fd) == 0;
    if (!S_ISREG(state.st_mode) && !S_ISLNK(state.st_mode)) return false;
    // unlinkat never follows the leaf, and a directory race cannot turn this
    // into tree removal because AT_REMOVEDIR is deliberately not supplied.
    if (::unlinkat(parent.fd, path.filename().c_str(), 0) != 0)
        return errno == ENOENT && ::fsync(parent.fd) == 0;
    removed = true;
    return ::fsync(parent.fd) == 0;
}

bool valid_generation_name(const std::string& value) {
    if (value.empty() || value.size() > 96U || value == "." || value == "..")
        return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '-' || ch == '_';
    });
}

bool write_all(int fd, const char* data, std::size_t size) {
    while (size != 0U) {
        const auto written = ::write(fd, data, size);
        if (written < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (written == 0) return false;
        data += written;
        size -= static_cast<std::size_t>(written);
    }
    return true;
}

bool sync_directory(const fs::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
}

bool write_private_file(const fs::path& path, const std::string& body) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL |
                                            O_NOFOLLOW | O_CLOEXEC,
                          kStoredFileMode);
    if (fd < 0) return false;
    const bool ok = write_all(fd, body.data(), body.size()) &&
                    ::fchmod(fd, kStoredFileMode) == 0 && ::fsync(fd) == 0;
    const bool closed = ::close(fd) == 0;
    return ok && closed;
}

std::optional<std::string> bounded_digest(const fs::path& path,
                                          std::uintmax_t maximum,
                                          std::optional<std::uintmax_t>
                                              expected_size = std::nullopt) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    struct stat state {};
    if (::fstat(fd, &state) != 0 || !S_ISREG(state.st_mode) ||
        state.st_size < 0 ||
        static_cast<std::uintmax_t>(state.st_size) > maximum ||
        (expected_size &&
         static_cast<std::uintmax_t>(state.st_size) != *expected_size)) {
        ::close(fd);
        return std::nullopt;
    }
    Sha256 hasher;
    std::array<char, 64U * 1024U> buffer{};
    std::uintmax_t total = 0;
    bool ok = true;
    while (ok) {
        const auto count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        if (count == 0) break;
        total += static_cast<std::uintmax_t>(count);
        if (total > maximum) {
            ok = false;
            break;
        }
        hasher.update(buffer.data(), static_cast<std::size_t>(count));
    }
    ok = ok && total == static_cast<std::uintmax_t>(state.st_size);
    const bool closed = ::close(fd) == 0;
    if (!ok || !closed) return std::nullopt;
    return hasher.hex_digest();
}

std::optional<std::string> read_bounded_single_line(const fs::path& path,
                                                    std::uintmax_t maximum) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    struct stat state {};
    if (::fstat(fd, &state) != 0 || !S_ISREG(state.st_mode) ||
        state.st_size <= 0 ||
        static_cast<std::uintmax_t>(state.st_size) > maximum) {
        ::close(fd);
        return std::nullopt;
    }
    std::string body(static_cast<std::size_t>(state.st_size), '\0');
    std::size_t offset = 0;
    bool ok = true;
    while (offset < body.size()) {
        const auto count =
            ::read(fd, body.data() + offset, body.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        if (count == 0) {
            ok = false;
            break;
        }
        offset += static_cast<std::size_t>(count);
    }
    char extra = '\0';
    const auto trailing = ok ? ::read(fd, &extra, 1U) : -1;
    const bool closed = ::close(fd) == 0;
    if (!ok || trailing != 0 || !closed) return std::nullopt;
    if (!body.empty() && body.back() == '\n') body.pop_back();
    if (!body.empty() && body.back() == '\r') body.pop_back();
    if (body.empty() || body.find_first_of("\r\n") != std::string::npos)
        return std::nullopt;
    return body;
}

std::optional<std::string> read_exact_file(const fs::path& path,
                                           std::uintmax_t expected) {
    if (expected > kComponentMaxFileBytes) return std::nullopt;
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    struct stat state {};
    if (::fstat(fd, &state) != 0 || !S_ISREG(state.st_mode) ||
        state.st_size < 0 ||
        static_cast<std::uintmax_t>(state.st_size) != expected) {
        ::close(fd);
        return std::nullopt;
    }
    std::string body(static_cast<std::size_t>(expected), '\0');
    std::size_t offset = 0;
    bool ok = true;
    while (offset < body.size()) {
        const auto count =
            ::read(fd, body.data() + offset, body.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        if (count == 0) {
            ok = false;
            break;
        }
        offset += static_cast<std::size_t>(count);
    }
    char extra = '\0';
    const auto trailing = ok ? ::read(fd, &extra, 1U) : -1;
    const bool closed = ::close(fd) == 0;
    if (!ok || trailing != 0 || !closed) return std::nullopt;
    return body;
}

struct CopyResult {
    bool complete{false};
    std::uint32_t mode{0};
    std::uint32_t owner{0};
    std::uint32_t group{0};
    std::uintmax_t size{0};
};

CopyResult copy_file(const PackageFileState& expected, const fs::path& to) {
    CopyResult result;
    const int input = ::open(expected.path.c_str(), O_RDONLY | O_NOFOLLOW |
                                                       O_CLOEXEC);
    if (input < 0) return result;
    struct stat state {};
    if (::fstat(input, &state) != 0 || !S_ISREG(state.st_mode) ||
        state.st_size < 0 ||
        static_cast<std::uintmax_t>(state.st_size) > kComponentMaxFileBytes) {
        ::close(input);
        return result;
    }
    result.mode = static_cast<std::uint32_t>(state.st_mode & 07777);
    result.owner = static_cast<std::uint32_t>(state.st_uid);
    result.group = static_cast<std::uint32_t>(state.st_gid);
    result.size = static_cast<std::uintmax_t>(state.st_size);
    if (result.mode != expected.mode || result.owner != expected.owner ||
        result.group != expected.group || result.size != expected.size) {
        ::close(input);
        return result;
    }

    const int output = ::open(to.c_str(), O_WRONLY | O_CREAT | O_EXCL |
                                            O_NOFOLLOW | O_CLOEXEC,
                              kStoredFileMode);
    if (output < 0) {
        ::close(input);
        return result;
    }
    bool ok = true;
    std::uintmax_t copied = 0;
    std::array<char, 64U * 1024U> buffer{};
    while (ok) {
        const auto count = ::read(input, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        if (count == 0) break;
        copied += static_cast<std::uintmax_t>(count);
        if (copied > kComponentMaxFileBytes ||
            !write_all(output, buffer.data(), static_cast<std::size_t>(count))) {
            ok = false;
        }
    }
    ok = ok && copied == result.size && ::fchmod(output, kStoredFileMode) == 0 &&
         ::fsync(output) == 0;
    const bool input_closed = ::close(input) == 0;
    const bool output_closed = ::close(output) == 0;
    if (!(ok && input_closed && output_closed)) return result;
    const auto digest =
        bounded_digest(to, kComponentMaxFileBytes, result.size);
    result.complete = digest && *digest == expected.sha256;
    return result;
}

bool parse_manifest(const fs::path& manifest,
                    std::vector<ManifestEntry>& entries,
                    std::optional<ComponentOpkgMetadataPaths>* metadata_out = nullptr) {
    struct stat state {};
    if (::lstat(manifest.c_str(), &state) != 0 || !S_ISREG(state.st_mode) ||
        state.st_size <= 0 ||
        static_cast<std::uintmax_t>(state.st_size) > kMaxManifestBytes) {
        return false;
    }
    std::ifstream input(manifest);
    if (!input) return false;
    std::string line;
    if (!std::getline(input, line) || input.eof() ||
        (line != kManifestHeader && line != kAbsentManifestHeader &&
         line != kMetadataManifestHeader)) return false;
    const bool records_metadata = line == kMetadataManifestHeader;
    const bool records_absent = line != kManifestHeader;
    std::optional<ComponentOpkgMetadataPaths> metadata;
    std::set<std::string> metadata_paths;
    if (records_metadata) {
        ComponentOpkgMetadataPaths paths;
        auto field = [&](const char* label, std::string& value) {
            const std::string prefix = std::string(label) + ' ';
            if (!std::getline(input, line) || input.eof() ||
                line.compare(0, prefix.size(), prefix) != 0) return false;
            value = line.substr(prefix.size());
            return !value.empty();
        };
        std::string status, info, lock;
        if (!field("package", paths.package) || !field("status", status) ||
            !field("info", info) || !field("lock", lock) ||
            !valid_path(status) || !valid_path(info) || !valid_path(lock)) return false;
        paths.status_file = status;
        paths.info_directory = info;
        paths.lock_file = lock;
        if (!valid_component_opkg_metadata_paths(paths)) return false;
        const auto files = component_opkg_metadata_files(paths);
        metadata_paths.insert(files.begin(), files.end());
        metadata = std::move(paths);
    }
    std::uintmax_t total = 0;
    std::size_t present = 0;
    std::set<std::string> paths;
    while (std::getline(input, line)) {
        if (input.eof()) return false; // A published line is never truncated.
        std::istringstream fields(line);
        ManifestEntry entry;
        if (records_absent) {
            std::string kind;
            if (!(fields >> kind) ||
                (kind != "P" && kind != "A" &&
                 !(records_metadata && (kind == "M" || kind == "N" || kind == "S"))))
                return false;
            entry.absent = kind == "A" || kind == "N";
            entry.metadata = kind == "M" || kind == "N" || kind == "S";
            entry.status = kind == "S";
        }
        if (!(fields >> entry.index) || entry.index != entries.size() + 1U ||
            entries.size() >= kComponentMaxPathCount) return false;
        if (entry.absent) {
            fields >> std::ws;
            std::getline(fields, entry.path);
            if (!valid_path(entry.path) ||
                !insert_unique_path(paths, entry.path)) return false;
            entries.push_back(std::move(entry));
            continue;
        }
        std::string mode;
        if (!(fields >> mode >> entry.owner >> entry.group >>
              entry.size >> entry.sha256)) {
            return false;
        }
        if (!rescue_integrity::valid_sha256_hex(entry.sha256) ||
            entry.index != entries.size() + 1U ||
            entries.size() >= kComponentMaxPathCount ||
            entry.size > kComponentMaxFileBytes ||
            total > kComponentMaxTotalBytes - entry.size) {
            return false;
        }
        char* end = nullptr;
        errno = 0;
        const auto parsed = std::strtoul(mode.c_str(), &end, 8);
        if (errno != 0 || end == nullptr || *end != '\0' || parsed > 07777U)
            return false;
        entry.mode = static_cast<std::uint32_t>(parsed);
        fields >> std::ws;
        std::getline(fields, entry.path);
        if (!valid_path(entry.path) ||
            !insert_unique_path(paths, entry.path)) return false;
        total += entry.size;
        if (!entry.metadata) ++present;
        entries.push_back(std::move(entry));
    }
    if (present == 0U || input.bad()) return false;
    if (metadata) {
        for (const auto& entry : entries) {
            const bool known = metadata_paths.count(entry.path) != 0U;
            if (entry.metadata != known) return false;
            if (!known) continue;
            const bool status = entry.path == metadata->status_file.string();
            if (entry.status != status || (status && entry.absent)) return false;
            metadata_paths.erase(entry.path);
        }
        if (!metadata_paths.empty()) return false;
    }
    if (metadata_out) *metadata_out = std::move(metadata);
    return true;
}

ComponentCaptureState verify_generation(const fs::path& generation,
                                         bool verify_metadata = false) {
    if (!real_directory(generation)) return ComponentCaptureState::incomplete;
    const auto manifest = generation / kManifestName;
    const auto expected =
        read_bounded_single_line(generation / kReadyName, 80U);
    const auto actual = bounded_digest(manifest, kMaxManifestBytes);
    if (!expected || !actual ||
        !rescue_integrity::valid_sha256_hex(*expected) || *expected != *actual)
        return ComponentCaptureState::incomplete;
    std::vector<ManifestEntry> entries;
    if (!parse_manifest(manifest, entries))
        return ComponentCaptureState::incomplete;
    for (const auto& entry : entries) {
        if (entry.absent || (entry.metadata && !verify_metadata)) continue;
        const auto stored = generation / kFilesDir / stored_name(entry.index);
        struct stat state {};
        if (::lstat(stored.c_str(), &state) != 0 ||
            !S_ISREG(state.st_mode) || state.st_size < 0 ||
            static_cast<std::uintmax_t>(state.st_size) != entry.size) {
            return ComponentCaptureState::corrupted;
        }
        const auto digest =
            bounded_digest(stored, kComponentMaxFileBytes, entry.size);
        if (!digest || *digest != entry.sha256)
            return ComponentCaptureState::corrupted;
    }
    return ComponentCaptureState::usable;
}

std::optional<fs::path> active_generation(const fs::path& store) {
    const auto selected =
        read_bounded_single_line(store / kCurrentName, 128U);
    if (selected) {
        if (!valid_generation_name(*selected)) return std::nullopt;
        return store / kGenerationsDir / *selected;
    }
    // Detect the first local layout so it reports `incomplete` rather than
    // `absent`. Its v1 manifest lacks uid/gid/size and is deliberately not
    // accepted as a v2 restore promise.
    std::error_code error;
    if (fs::exists(store / kManifestName, error) ||
        fs::exists(store / kReadyName, error)) {
        return store;
    }
    return std::nullopt;
}

std::string generation_name() {
    static std::atomic<unsigned long long> sequence{0};
    const auto stamp = static_cast<unsigned long long>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    return "gen-" + std::to_string(static_cast<long long>(::getpid())) + "-" +
           std::to_string(stamp) + "-" +
           std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
}

void remove_generation(const fs::path& generation) noexcept {
    std::error_code error;
    fs::remove_all(generation, error);
}

bool remove_stale_generations(const fs::path& store,
                              const std::string& selected) noexcept {
    std::error_code error;
    std::size_t inspected = 0;
    for (const auto& entry :
         fs::directory_iterator(store / kGenerationsDir, error)) {
        if (error || ++inspected > kComponentMaxPathCount) return false;
        const auto name = entry.path().filename().string();
        if (name == selected || !valid_generation_name(name)) continue;
        const auto status = entry.symlink_status(error);
        if (error) return false;
        if (fs::is_directory(status) && !fs::is_symlink(status))
            remove_generation(entry.path());
    }
    return !error;
}

bool generation_count_is_bounded(const fs::path& store) noexcept {
    std::error_code error;
    std::size_t count = 0;
    for (const auto& entry :
         fs::directory_iterator(store / kGenerationsDir, error)) {
        (void)entry;
        if (error || ++count > kMaxStoredGenerations) return false;
    }
    return !error;
}

std::optional<std::string> stored_entry_body(const fs::path& generation,
                                            const ManifestEntry& entry) {
    const auto body = read_exact_file(generation / kFilesDir /
                                      stored_name(entry.index), entry.size);
    if (!body) return std::nullopt;
    Sha256 digest;
    digest.update(body->data(), body->size());
    return digest.hex_digest() == entry.sha256 ? body : std::nullopt;
}

bool restore_present_entry(const fs::path& generation,
                            const ManifestEntry& entry) {
    const auto body = stored_entry_body(generation, entry);
    if (!body) return false;
    try {
        AtomicFileWriteOptions options;
        options.create_parent_directories = true;
        options.file_mode = static_cast<mode_t>(entry.mode);
        options.owner = static_cast<uid_t>(entry.owner);
        options.group = static_cast<gid_t>(entry.group);
        write_file_atomically(entry.path, *body, options);
    } catch (const std::exception&) {
        return false;
    }
    const auto written = bounded_digest(entry.path, kComponentMaxFileBytes,
                                         entry.size);
    struct stat destination {};
    return written && *written == entry.sha256 &&
           ::lstat(entry.path.c_str(), &destination) == 0 &&
           S_ISREG(destination.st_mode) &&
           static_cast<std::uint32_t>(destination.st_mode & 07777) == entry.mode &&
           static_cast<std::uint32_t>(destination.st_uid) == entry.owner &&
           static_cast<std::uint32_t>(destination.st_gid) == entry.group &&
           destination.st_size >= 0 &&
           static_cast<std::uintmax_t>(destination.st_size) == entry.size;
}

bool restore_metadata_entries(const fs::path& generation,
                               const fs::path& store,
                               const std::vector<ManifestEntry>& entries,
                               const ComponentOpkgMetadataPaths& metadata,
                               const std::string& expected_version,
                               std::vector<std::string>& failed) {
    if (!source_anchor(metadata.status_file, store) ||
        !source_anchor(metadata.info_directory, store) ||
        !source_anchor(metadata.lock_file, store)) {
        failed.emplace_back("metadata paths are outside the capture source boundary");
        return false;
    }
    std::optional<std::string> saved_status;
    for (const auto& entry : entries) {
        if (!entry.metadata || entry.absent) continue;
        const auto body = stored_entry_body(generation, entry);
        if (!body) failed.push_back(entry.path);
        else if (entry.status) saved_status = *body;
    }
    if (!failed.empty() || !saved_status) return false;

    ComponentOpkgMetadataLock lock(metadata.lock_file);
    if (!lock.locked()) {
        failed.push_back(lock.error());
        return false;
    }
    // Validate the live database before any info mutation. The saved database
    // is input to a package-paragraph merge, never an overwrite candidate.
    struct stat status {};
    if (::lstat(metadata.status_file.c_str(), &status) != 0 ||
        !S_ISREG(status.st_mode) || status.st_size < 0) {
        failed.push_back(metadata.status_file.string());
        return false;
    }
    const auto current = read_exact_file(metadata.status_file,
                         static_cast<std::uintmax_t>(status.st_size));
    if (!current || !merge_component_opkg_status(*saved_status, *current,
                                                 metadata.package, expected_version).complete) {
        failed.push_back(metadata.status_file.string());
        return false;
    }
    for (const auto& entry : entries) {
        if (!entry.metadata || entry.status || entry.absent) continue;
        if (!restore_present_entry(generation, entry)) failed.push_back(entry.path);
    }
    if (!failed.empty()) return false;
    for (const auto& entry : entries) {
        if (!entry.metadata || !entry.absent) continue;
        bool removed = false;
        if (!restore_absent_leaf(entry.path, store, removed)) failed.push_back(entry.path);
    }
    if (!failed.empty()) return false;
    const auto merged = restore_component_opkg_status(metadata, *saved_status,
                                                       expected_version);
    if (!merged.complete) {
        failed.push_back(metadata.status_file.string() + ": " + merged.error);
        return false;
    }
    return true;
}

} // namespace

ComponentCaptureResult capture_component_files(
    const PackageFootprint& requested, const fs::path& store,
    bool record_absent, std::optional<ComponentOpkgMetadataPaths> metadata) {
    ComponentCaptureResult result;
    if (!requested.complete || requested.files.size() > kComponentMaxPathCount ||
        requested.total_bytes > kComponentMaxTotalBytes) {
        result.failed = requested.errors;
        if (result.failed.empty())
            result.failed.emplace_back("component footprint exceeds capture limits");
        return result;
    }
    std::optional<ComponentOpkgMetadataLock> metadata_lock;
    std::set<std::string> metadata_paths;
    PackageFootprint expanded;
    if (metadata) {
        if (!valid_component_opkg_metadata_paths(*metadata) ||
            !source_anchor(metadata->status_file, store) ||
            !source_anchor(metadata->info_directory, store) ||
            !source_anchor(metadata->lock_file, store)) {
            result.failed.emplace_back("invalid component metadata paths");
            return result;
        }
        metadata_lock.emplace(metadata->lock_file);
        if (!metadata_lock->locked()) {
            result.failed.push_back(metadata_lock->error());
            return result;
        }
        const auto files = component_opkg_metadata_files(*metadata);
        metadata_paths.insert(files.begin(), files.end());
        std::set<std::string> union_paths = metadata_paths;
        for (const auto& file : requested.files) {
            if (metadata_paths.count(file.path) != 0U ||
                !insert_unique_path(union_paths, file.path)) {
                result.failed.push_back(file.path);
                return result;
            }
        }
        if (union_paths.size() > kComponentMaxPathCount) {
            result.failed.emplace_back("metadata capture union exceeds path limit");
            return result;
        }
        expanded = observe_package_footprint(
            std::vector<std::string>(union_paths.begin(), union_paths.end()));
        record_absent = true;
    }
    const auto& footprint = metadata ? expanded : requested;
    if (!footprint.complete || footprint.files.size() > kComponentMaxPathCount ||
        footprint.total_bytes > kComponentMaxTotalBytes) {
        result.failed = footprint.errors;
        if (result.failed.empty())
            result.failed.emplace_back("component footprint exceeds capture limits");
        return result;
    }

    std::set<std::string> paths;
    for (const auto& state : footprint.files) {
        if (!valid_path(state.path) || !insert_unique_path(paths, state.path) ||
            state.unreadable ||
            (record_absent && !source_anchor(state.path, store))) {
            result.failed.push_back(state.path);
        }
    }
    if (!result.failed.empty()) return result;

    std::error_code error;
    if (fs::exists(store, error) && !real_directory(store)) {
        result.failed.push_back(store.string());
        return result;
    }
    error.clear();
    fs::create_directories(store / kGenerationsDir, error);
    if (error || !real_directory(store) ||
        !real_directory(store / kGenerationsDir) ||
        ::chmod(store.c_str(), kStoreDirectoryMode) != 0 ||
        ::chmod((store / kGenerationsDir).c_str(), kStoreDirectoryMode) != 0 ||
        !sync_directory(store / kGenerationsDir) ||
        !sync_directory(store) ||
        !sync_directory(store.parent_path().empty() ? fs::path(".")
                                                    : store.parent_path())) {
        result.failed.push_back(store.string());
        return result;
    }
    const auto selected_before =
        read_bounded_single_line(store / kCurrentName, 128U);
    const bool selected_is_usable =
        verify_component_capture(store) == ComponentCaptureState::usable;
    if (selected_is_usable &&
        !remove_stale_generations(
            store, selected_before && valid_generation_name(*selected_before)
                       ? *selected_before
                       : std::string{})) {
        result.failed.push_back((store / kGenerationsDir).string());
        return result;
    }
    if (!selected_is_usable && !generation_count_is_bounded(store)) {
        result.failed.push_back((store / kGenerationsDir).string());
        return result;
    }

    const auto name = generation_name();
    const auto generation = store / kGenerationsDir / name;
    if (fs::exists(generation, error) || error) {
        result.failed.push_back(generation.string());
        return result;
    }
    error.clear();
    const bool generation_created =
        fs::create_directory(generation, error);
    if (error || !generation_created) {
        result.failed.push_back(generation.string());
        return result;
    }
    error.clear();
    const bool files_created =
        fs::create_directory(generation / kFilesDir, error);
    if (error || !files_created ||
        ::chmod(generation.c_str(), kStoreDirectoryMode) != 0 ||
        ::chmod((generation / kFilesDir).c_str(), kStoreDirectoryMode) != 0) {
        result.failed.push_back(generation.string());
        remove_generation(generation);
        return result;
    }

    std::ostringstream manifest;
    manifest << (metadata ? kMetadataManifestHeader :
                 record_absent ? kAbsentManifestHeader : kManifestHeader) << '\n';
    if (metadata) {
        manifest << "package " << metadata->package << '\n'
                 << "status " << metadata->status_file.string() << '\n'
                 << "info " << metadata->info_directory.string() << '\n'
                 << "lock " << metadata->lock_file.string() << '\n';
    }
    std::size_t index = 0;
    std::size_t payload_captured = 0;
    std::uintmax_t total = 0;
    for (const auto& state : footprint.files) {
        const bool metadata_entry = metadata_paths.count(state.path) != 0U;
        const bool status_entry = metadata && state.path == metadata->status_file.string();
        if (!state.present) {
            ++result.skipped_absent;
            if (record_absent) {
                if (status_entry || !state.sha256.empty() || state.mode != 0U ||
                    state.owner != 0U || state.group != 0U || state.size != 0U ||
                    !source_is_absent(state.path, store)) {
                    result.failed.push_back(state.path);
                    continue;
                }
                manifest << (metadata_entry ? "N " : "A ") << ++index
                         << ' ' << state.path << '\n';
            }
            continue;
        }
        if (record_absent) {
            SourceParent parent;
            open_source_parent(state.path, store, parent);
            if (parent.state != ParentState::ready) {
                result.failed.push_back(state.path);
                continue;
            }
        }
        if (state.unreadable || state.sha256.empty() ||
            !valid_path(state.path) || state.size > kComponentMaxFileBytes ||
            total > kComponentMaxTotalBytes - state.size) {
            result.failed.push_back(state.path);
            continue;
        }
        const auto copy = copy_file(state,
                                    generation / kFilesDir /
                                        stored_name(++index));
        if (!copy.complete) {
            result.failed.push_back(state.path);
            continue;
        }
        total += copy.size;
        if (status_entry) {
            const auto body = read_exact_file(
                generation / kFilesDir / stored_name(index), copy.size);
            if (!body || !merge_component_opkg_status(*body, *body, metadata->package).complete) {
                result.failed.push_back(state.path);
                continue;
            }
        }
        if (record_absent)
            manifest << (status_entry ? "S " : metadata_entry ? "M " : "P ");
        manifest << index << ' ' << std::oct << copy.mode << std::dec << ' '
                 << copy.owner << ' ' << copy.group << ' ' << copy.size << ' '
                 << state.sha256 << ' ' << state.path << '\n';
        ++result.captured;
        if (!metadata_entry) ++payload_captured;
    }

    if (payload_captured == 0 || !result.failed.empty()) {
        if (result.failed.empty()) result.failed.push_back(store.string());
        remove_generation(generation);
        return result;
    }
    if (!write_private_file(generation / kManifestName, manifest.str())) {
        result.failed.push_back((generation / kManifestName).string());
        remove_generation(generation);
        return result;
    }
    const auto manifest_digest =
        bounded_digest(generation / kManifestName, kMaxManifestBytes);
    if (!manifest_digest ||
        !write_private_file(generation / kReadyName,
                            *manifest_digest + "\n") ||
        !sync_directory(generation / kFilesDir) ||
        !sync_directory(generation) ||
        !sync_directory(store / kGenerationsDir) ||
        verify_generation(generation, true) != ComponentCaptureState::usable) {
        result.failed.push_back(generation.string());
        remove_generation(generation);
        return result;
    }

    bool pointer_committed = false;
    try {
        AtomicFileWriteOptions options;
        options.file_mode = static_cast<mode_t>(kStoredFileMode);
        options.committed_result = &pointer_committed;
        write_file_atomically((store / kCurrentName).string(), name + "\n",
                              options);
    } catch (const std::exception&) {
        result.failed.push_back((store / kCurrentName).string());
        // Once rename made the pointer visible, removing its target would turn
        // a durability warning into a definitely broken active point. The
        // previous generation is retained as well; after a reboot either
        // pointer outcome therefore still names usable bytes.
        if (!pointer_committed) remove_generation(generation);
        return result;
    }
    if (verify_component_capture(store) != ComponentCaptureState::usable) {
        result.failed.push_back(store.string());
        return result;
    }
    remove_stale_generations(store, name);
    result.complete = true;
    result.metadata_recorded = metadata.has_value();
    return result;
}

ComponentCaptureResult capture_component_upgrade_files(
    const PackageFootprint& previous,
    const std::vector<std::string>& target_paths, const fs::path& store,
    std::optional<ComponentOpkgMetadataPaths> metadata) {
    ComponentCaptureResult result;
    if (!previous.complete || previous.files.empty() || target_paths.empty() ||
        previous.files.size() > kComponentMaxPathCount ||
        target_paths.size() > kComponentMaxPathCount) {
        result.failed.emplace_back("upgrade capture requires bounded current and target paths");
        return result;
    }
    std::set<std::string> unique(target_paths.begin(), target_paths.end());
    for (const auto& state : previous.files) unique.insert(state.path);
    if (unique.size() > kComponentMaxPathCount) {
        result.failed.emplace_back("upgrade capture union exceeds path limit");
        return result;
    }
    const std::vector<std::string> paths(unique.begin(), unique.end());
    return capture_component_files(observe_package_footprint(paths), store, true,
                                    std::move(metadata));
}

ComponentCaptureState verify_component_capture(const fs::path& store) {
    std::error_code error;
    if (!fs::exists(store, error) && !error)
        return ComponentCaptureState::absent;
    if (error || !real_directory(store))
        return ComponentCaptureState::incomplete;
    const auto active = active_generation(store);
    return active ? verify_generation(*active)
                  : ComponentCaptureState::incomplete;
}

ComponentCaptureReinstallPreparation prepare_component_capture_reinstall(
    const fs::path& store, const std::string& expected_version) {
    ComponentCaptureReinstallPreparation result;
    try {
        const auto state = verify_component_capture(store);
        if (state != ComponentCaptureState::usable) {
            result.error = component_capture_state_name(state);
            return result;
        }
        const auto active = active_generation(store);
        std::vector<ManifestEntry> entries;
        std::optional<ComponentOpkgMetadataPaths> metadata;
        if (!active || !parse_manifest(*active / kManifestName, entries, &metadata)) {
            result.error = "incomplete component capture manifest";
            return result;
        }
        result.metadata_recorded = metadata.has_value();
        if (!metadata) {
            // v2/v3 never promised opkg metadata; preserve their old-IPK path.
            result.complete = true;
            return result;
        }
        if (!source_anchor(metadata->status_file, store) ||
            !source_anchor(metadata->info_directory, store) ||
            !source_anchor(metadata->lock_file, store)) {
            result.error = "metadata paths are outside the capture source boundary";
            return result;
        }
        std::string saved_status;
        std::optional<ComponentOpkgStatusFileAttributes> saved_attributes;
        for (const auto& entry : entries) {
            if (!entry.status) continue;
            const auto body = stored_entry_body(*active, entry);
            if (body) {
                saved_status = *body;
                saved_attributes = ComponentOpkgStatusFileAttributes{
                    entry.mode, entry.owner, entry.group};
            }
            break;
        }
        ComponentOpkgMetadataLock lock(metadata->lock_file);
        if (!lock.locked()) {
            result.error = lock.error();
            return result;
        }
        // A healthy current database needs no saved status. Optional metadata
        // damage must not prevent reinstalling a verified old IPK in that case.
        // A real repair, however, can only use the verified same-generation S
        // blob and the expected version from the interrupted transaction.
        const auto prepared = prepare_component_opkg_status_for_reinstall(
            *metadata, saved_status, expected_version, saved_attributes);
        result.complete = prepared.complete;
        result.status_repaired = prepared.changed;
        result.shared_database_reconstructed = prepared.shared_database_reconstructed;
        result.error = prepared.error;
    } catch (const std::exception& error) {
        result.error = error.what();
    } catch (...) {
        result.error = "component status preparation failed unexpectedly";
    }
    return result;
}

ComponentRestoreResult restore_component_files(const fs::path& store,
                                                bool restore_absent,
                                                const std::string& expected_version) {
    ComponentRestoreResult result;
    const auto state = verify_component_capture(store);
    if (state != ComponentCaptureState::usable) {
        result.refused = component_capture_state_name(state);
        return result;
    }
    const auto active = active_generation(store);
    if (!active) {
        result.refused = "incomplete";
        return result;
    }
    std::vector<ManifestEntry> entries;
    std::optional<ComponentOpkgMetadataPaths> metadata;
    if (!parse_manifest(*active / kManifestName, entries, &metadata)) {
        result.refused = "incomplete";
        return result;
    }
    result.metadata_recorded = metadata.has_value();

    std::size_t present = 0;
    for (const auto& entry : entries) {
        if (entry.absent || entry.metadata) continue;
        ++present;
        if (!restore_present_entry(*active, entry)) {
            result.failed.push_back(entry.path);
            continue;
        }
        ++result.restored;
    }
    std::size_t absence_count = 0;
    std::size_t absence_restored = 0;
    if (restore_absent) {
        for (const auto& entry : entries) {
            if (!entry.absent || entry.metadata) continue;
            ++absence_count;
            // Failed present restoration must not be compounded by removals.
            if (result.restored != present) continue;
            bool removed = false;
            const bool restored = restore_absent_leaf(entry.path, store, removed);
            if (removed) ++result.removed;
            if (restored) ++absence_restored;
            else result.failed.push_back(entry.path);
        }
    }
    result.payload_restored = result.failed.empty() && result.restored == present &&
                              absence_restored == absence_count;
    if (result.payload_restored && restore_absent && metadata) {
        try {
            result.metadata_restored = restore_metadata_entries(
                *active, store, entries, *metadata, expected_version,
                result.metadata_failed);
        } catch (const std::exception& error) {
            result.metadata_failed.push_back(std::string("metadata recovery failed: ") + error.what());
        } catch (...) {
            result.metadata_failed.emplace_back("metadata recovery failed unexpectedly");
        }
    }
    result.complete = result.payload_restored &&
                      (!restore_absent || !metadata || result.metadata_restored);
    return result;
}

const char* component_capture_state_name(ComponentCaptureState state) noexcept {
    switch (state) {
        case ComponentCaptureState::usable:
            return "usable";
        case ComponentCaptureState::absent:
            return "absent";
        case ComponentCaptureState::incomplete:
            return "incomplete";
        case ComponentCaptureState::corrupted:
            return "corrupted";
    }
    return "incomplete";
}

} // namespace keen_pbr3
