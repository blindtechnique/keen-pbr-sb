#include "package_footprint.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fstream>
#include <optional>
#include <set>
#include <system_error>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

bool valid_observation_path(const std::string& value) {
    if (value.empty() || value.size() > kComponentMaxPathLength ||
        value.front() != '/' || value.find('\0') != std::string::npos) {
        return false;
    }
    if (std::any_of(value.begin(), value.end(), [](unsigned char ch) {
            return ch < 0x20U || ch == 0x7fU;
        })) {
        return false;
    }
    const std::filesystem::path path(value);
    return path.is_absolute() && path.lexically_normal() == path;
}

const PackageFileState* find_state(const PackageFootprint& footprint,
                                   const std::string& path) {
    const auto found = std::lower_bound(
        footprint.files.begin(), footprint.files.end(), path,
        [](const PackageFileState& state, const std::string& value) {
            return state.path < value;
        });
    if (found == footprint.files.end() || found->path != path) return nullptr;
    return &*found;
}

// Comparable only when both sides were actually read. Anything else is a
// question mark, not an answer.
bool both_readable(const PackageFileState& before,
                   const PackageFileState& after) {
    return before.present && after.present && !before.unreadable &&
           !after.unreadable;
}

} // namespace

std::vector<std::string> read_opkg_file_list(
    const std::filesystem::path& list_file) {
    std::vector<std::string> paths;
    std::ifstream input(list_file);
    if (!input) return paths;
    std::string line;
    while (std::getline(input, line)) {
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == ' ' ||
                line.back() == '\t')) {
            line.pop_back();
        }
        if (line.empty() || line.front() != '/') continue;
        paths.push_back(line);
    }
    return paths;
}

std::optional<std::string> hash_bounded_regular_file(
    const std::string& path, const struct stat& expected) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    struct stat opened {};
    if (::fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
        opened.st_dev != expected.st_dev || opened.st_ino != expected.st_ino ||
        opened.st_size < 0 ||
        static_cast<std::uintmax_t>(opened.st_size) >
            kComponentMaxFileBytes) {
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
        if (total > kComponentMaxFileBytes) {
            ok = false;
            break;
        }
        hasher.update(buffer.data(), static_cast<std::size_t>(count));
    }
    struct stat finished {};
    ok = ok && ::fstat(fd, &finished) == 0 &&
         finished.st_size == opened.st_size &&
         finished.st_mtime == opened.st_mtime &&
         total == static_cast<std::uintmax_t>(opened.st_size);
    const bool closed = ::close(fd) == 0;
    if (!ok || !closed) return std::nullopt;
    return hasher.hex_digest();
}

PackagePathList read_opkg_file_list_bounded(
    const std::filesystem::path& list_file) {
    PackagePathList result;
    std::vector<std::string> paths;
    std::error_code size_error;
    const auto list_size = std::filesystem::file_size(list_file, size_error);
    constexpr auto kMaximumListBytes =
        kComponentMaxPathCount * (kComponentMaxPathLength + 2U);
    if (!size_error && list_size > kMaximumListBytes) {
        result.error = "package file list exceeds the size limit";
        return result;
    }
    std::ifstream input(list_file);
    if (!input) {
        result.error = "package file list is missing or unreadable";
        return result;
    }
    std::string line;
    while (std::getline(input, line)) {
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == ' ' ||
                line.back() == '\t')) {
            line.pop_back();
        }
        // Only absolute paths. A relative entry cannot be resolved against any
        // directory we could justify choosing, and guessing one would make the
        // observation depend on the daemon's working directory.
        if (line.empty()) continue;
        if (!valid_observation_path(line)) {
            result.error = "package file list contains an unsafe path";
            return result;
        }
        if (paths.size() >= kComponentMaxPathCount) {
            result.error = "package file list exceeds the path-count limit";
            return result;
        }
        paths.push_back(line);
    }
    if (input.bad()) {
        result.error = "package file list could not be read completely";
        return result;
    }
    if (paths.empty()) {
        result.error = "package file list is empty";
        return result;
    }
    result.complete = true;
    result.paths = std::move(paths);
    return result;
}

PackageFootprint observe_package_footprint(
    const std::vector<std::string>& paths) {
    PackageFootprint footprint;
    if (paths.size() > kComponentMaxPathCount) {
        footprint.complete = false;
        footprint.errors.emplace_back("component path-count limit exceeded");
        return footprint;
    }
    const std::set<std::string> unique(paths.begin(), paths.end());
    footprint.files.reserve(unique.size());
    for (const auto& path : unique) {
        PackageFileState state;
        state.path = path;

        if (!valid_observation_path(path)) {
            state.unreadable = true;
            ++footprint.unreadable_count;
            footprint.complete = false;
            footprint.errors.push_back(path);
            footprint.files.push_back(std::move(state));
            continue;
        }

        struct stat status {};
        if (::lstat(path.c_str(), &status) != 0) {
            if (errno == ENOENT || errno == ENOTDIR) {
                ++footprint.absent_count;
            } else {
                state.unreadable = true;
                ++footprint.unreadable_count;
                footprint.complete = false;
                footprint.errors.push_back(path);
            }
            footprint.files.push_back(std::move(state));
            continue;
        }
        state.present = true;
        state.mode = static_cast<std::uint32_t>(status.st_mode & 07777);
        state.owner = static_cast<std::uint32_t>(status.st_uid);
        state.group = static_cast<std::uint32_t>(status.st_gid);
        state.size = status.st_size < 0
                         ? 0U
                         : static_cast<std::uintmax_t>(status.st_size);
        if (!S_ISREG(status.st_mode)) {
            // A directory or a symlink where a package file is expected is a
            // real state, but not one we can hash. Reporting it as readable
            // with an empty digest would make it compare equal to anything.
            state.unreadable = true;
            ++footprint.present_count;
            ++footprint.unreadable_count;
            footprint.complete = false;
            footprint.errors.push_back(path);
            footprint.files.push_back(std::move(state));
            continue;
        }
        if (state.size > kComponentMaxFileBytes ||
            footprint.total_bytes > kComponentMaxTotalBytes - state.size) {
            state.unreadable = true;
            ++footprint.present_count;
            ++footprint.unreadable_count;
            footprint.complete = false;
            footprint.errors.push_back(path);
            footprint.files.push_back(std::move(state));
            continue;
        }
        const auto digest = hash_bounded_regular_file(path, status);
        if (!digest) {
            state.unreadable = true;
            ++footprint.unreadable_count;
            footprint.complete = false;
            footprint.errors.push_back(path);
        } else {
            state.sha256 = *digest;
            footprint.total_bytes += state.size;
        }
        ++footprint.present_count;
        footprint.files.push_back(std::move(state));
    }
    return footprint;
}

PackageFootprintDiff diff_package_footprint(const PackageFootprint& before,
                                            const PackageFootprint& after) {
    PackageFootprintDiff diff;
    std::set<std::string> paths;
    for (const auto& state : before.files) paths.insert(state.path);
    for (const auto& state : after.files) paths.insert(state.path);

    for (const auto& path : paths) {
        const auto* was = find_state(before, path);
        const auto* now = find_state(after, path);
        const bool was_present = was != nullptr && was->present;
        const bool now_present = now != nullptr && now->present;

        if (!was_present && !now_present) continue;
        if (!was_present) {
            if (now->unreadable) {
                diff.indeterminate.push_back(path);
            } else {
                diff.added.push_back(path);
            }
            continue;
        }
        if (!now_present) {
            diff.removed.push_back(path);
            continue;
        }
        if (!both_readable(*was, *now)) {
            diff.indeterminate.push_back(path);
            continue;
        }
        if (was->sha256 != now->sha256 || was->mode != now->mode ||
            was->owner != now->owner || was->group != now->group ||
            was->size != now->size)
            diff.changed.push_back(path);
    }
    return diff;
}

PackageBinaryOutcome judge_package_binary(const PackageFootprint& before,
                                          const PackageFootprint& after,
                                          const std::string& binary_path) {
    const auto* was = find_state(before, binary_path);
    const auto* now = find_state(after, binary_path);
    const bool was_present = was != nullptr && was->present;
    const bool now_present = now != nullptr && now->present;

    if (!was_present && !now_present)
        return PackageBinaryOutcome::absent_throughout;
    // Checked before readability: a binary that is gone is gone, and that
    // conclusion does not need the old one to have been hashable.
    if (was_present && !now_present)
        return PackageBinaryOutcome::missing_after;
    if (!was_present)
        return now->unreadable ? PackageBinaryOutcome::indeterminate
                               : PackageBinaryOutcome::replaced;
    if (!both_readable(*was, *now))
        return PackageBinaryOutcome::indeterminate;
    return was->sha256 == now->sha256 ? PackageBinaryOutcome::unchanged
                                      : PackageBinaryOutcome::replaced;
}

const char* package_binary_outcome_name(
    PackageBinaryOutcome outcome) noexcept {
    switch (outcome) {
        case PackageBinaryOutcome::replaced:
            return "replaced";
        case PackageBinaryOutcome::unchanged:
            return "unchanged";
        case PackageBinaryOutcome::missing_after:
            return "missing_after";
        case PackageBinaryOutcome::absent_throughout:
            return "absent_throughout";
        case PackageBinaryOutcome::indeterminate:
            return "indeterminate";
    }
    return "indeterminate";
}

} // namespace keen_pbr3
