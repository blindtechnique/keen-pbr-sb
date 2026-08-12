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
#include <sstream>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

constexpr const char* kManifestHeader = "keen-pbr-component-capture-v2";
constexpr const char* kManifestName = "manifest";
constexpr const char* kReadyName = ".ready";
constexpr const char* kFilesDir = "files";
constexpr const char* kGenerationsDir = "generations";
constexpr const char* kCurrentName = "current";
constexpr mode_t kStoredFileMode = 0600;
constexpr mode_t kStoreDirectoryMode = 0700;
constexpr std::size_t kMaxStoredGenerations = 8;
constexpr std::uintmax_t kMaxManifestBytes =
    kComponentMaxPathCount * (kComponentMaxPathLength + 160U);

struct ManifestEntry {
    std::size_t index{0};
    std::uint32_t mode{0};
    std::uint32_t owner{0};
    std::uint32_t group{0};
    std::uintmax_t size{0};
    std::string sha256;
    std::string path;
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
    return path.is_absolute() && path.lexically_normal() == path;
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
                    std::vector<ManifestEntry>& entries) {
    struct stat state {};
    if (::lstat(manifest.c_str(), &state) != 0 || !S_ISREG(state.st_mode) ||
        state.st_size <= 0 ||
        static_cast<std::uintmax_t>(state.st_size) > kMaxManifestBytes) {
        return false;
    }
    std::ifstream input(manifest);
    if (!input) return false;
    std::string line;
    if (!std::getline(input, line) || line != kManifestHeader) return false;
    std::uintmax_t total = 0;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        ManifestEntry entry;
        std::string mode;
        if (!(fields >> entry.index >> mode >> entry.owner >> entry.group >>
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
        if (!valid_path(entry.path)) return false;
        total += entry.size;
        entries.push_back(std::move(entry));
    }
    return !entries.empty() && !input.bad();
}

ComponentCaptureState verify_generation(const fs::path& generation) {
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

} // namespace

ComponentCaptureResult capture_component_files(
    const PackageFootprint& footprint, const fs::path& store) {
    ComponentCaptureResult result;
    if (!footprint.complete || footprint.files.size() > kComponentMaxPathCount ||
        footprint.total_bytes > kComponentMaxTotalBytes) {
        result.failed = footprint.errors;
        if (result.failed.empty())
            result.failed.emplace_back("component footprint exceeds capture limits");
        return result;
    }

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
    manifest << kManifestHeader << '\n';
    std::size_t index = 0;
    std::uintmax_t total = 0;
    for (const auto& state : footprint.files) {
        if (!state.present) {
            ++result.skipped_absent;
            continue;
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
        manifest << index << ' ' << std::oct << copy.mode << std::dec << ' '
                 << copy.owner << ' ' << copy.group << ' ' << copy.size << ' '
                 << state.sha256 << ' ' << state.path << '\n';
        ++result.captured;
    }

    if (result.captured == 0 || !result.failed.empty()) {
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
        verify_generation(generation) != ComponentCaptureState::usable) {
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
    return result;
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

ComponentRestoreResult restore_component_files(const fs::path& store) {
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
    if (!parse_manifest(*active / kManifestName, entries)) {
        result.refused = "incomplete";
        return result;
    }

    for (const auto& entry : entries) {
        const auto stored = *active / kFilesDir / stored_name(entry.index);
        const auto body = read_exact_file(stored, entry.size);
        if (!body) {
            result.failed.push_back(entry.path);
            continue;
        }
        try {
            AtomicFileWriteOptions options;
            options.create_parent_directories = true;
            options.file_mode = static_cast<mode_t>(entry.mode);
            options.owner = static_cast<uid_t>(entry.owner);
            options.group = static_cast<gid_t>(entry.group);
            write_file_atomically(entry.path, *body, options);
        } catch (const std::exception&) {
            result.failed.push_back(entry.path);
            continue;
        }
        const auto written =
            bounded_digest(entry.path, kComponentMaxFileBytes, entry.size);
        struct stat destination {};
        if (!written || *written != entry.sha256 ||
            ::lstat(entry.path.c_str(), &destination) != 0 ||
            !S_ISREG(destination.st_mode) ||
            static_cast<std::uint32_t>(destination.st_mode & 07777) !=
                entry.mode ||
            static_cast<std::uint32_t>(destination.st_uid) != entry.owner ||
            static_cast<std::uint32_t>(destination.st_gid) != entry.group ||
            destination.st_size < 0 ||
            static_cast<std::uintmax_t>(destination.st_size) != entry.size) {
            result.failed.push_back(entry.path);
            continue;
        }
        ++result.restored;
    }
    result.complete = result.failed.empty() && result.restored == entries.size();
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
