#include "package_footprint.hpp"

#include "rescue_integrity.hpp"

#include <algorithm>
#include <fstream>
#include <set>
#include <system_error>

#include <sys/stat.h>

namespace keen_pbr3 {

namespace {

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
        // Only absolute paths. A relative entry cannot be resolved against any
        // directory we could justify choosing, and guessing one would make the
        // observation depend on the daemon's working directory.
        if (line.empty() || line.front() != '/') continue;
        paths.push_back(line);
    }
    return paths;
}

PackageFootprint observe_package_footprint(
    const std::vector<std::string>& paths) {
    PackageFootprint footprint;
    const std::set<std::string> unique(paths.begin(), paths.end());
    footprint.files.reserve(unique.size());
    for (const auto& path : unique) {
        PackageFileState state;
        state.path = path;

        struct stat status {};
        if (::lstat(path.c_str(), &status) != 0) {
            ++footprint.absent_count;
            footprint.files.push_back(std::move(state));
            continue;
        }
        state.present = true;
        state.mode = static_cast<std::uint32_t>(status.st_mode & 07777);
        if (!S_ISREG(status.st_mode)) {
            // A directory or a symlink where a package file is expected is a
            // real state, but not one we can hash. Reporting it as readable
            // with an empty digest would make it compare equal to anything.
            state.unreadable = true;
            ++footprint.present_count;
            ++footprint.unreadable_count;
            footprint.files.push_back(std::move(state));
            continue;
        }
        const auto digest = rescue_integrity::sha256_file(path);
        if (!digest) {
            state.unreadable = true;
            ++footprint.unreadable_count;
        } else {
            state.sha256 = *digest;
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
        if (was->sha256 != now->sha256 || was->mode != now->mode)
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
