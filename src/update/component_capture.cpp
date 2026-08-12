#include "component_capture.hpp"

#include "rescue_integrity.hpp"

#include "../config/config_writer.hpp"

#include <cstdio>
#include <fstream>
#include <sys/stat.h>
#include <iomanip>
#include <sstream>
#include <system_error>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

constexpr const char* kManifestHeader = "keen-pbr-component-capture-v1";
constexpr const char* kManifestName = "manifest";
constexpr const char* kReadyName = ".ready";
constexpr const char* kFilesDir = "files";

std::string stored_name(std::size_t index) {
    std::ostringstream name;
    name << std::setw(6) << std::setfill('0') << index;
    return name.str();
}

// The store holds whatever the package owns, and for nfqws2 that was measured
// to include every conffile: the operator's nfqws2.conf and all five domain
// and address lists. So the copy is private regardless of how permissive the
// original was, and the original's mode is carried in the manifest and applied
// on restore rather than on the stored copy.
constexpr mode_t kStoredFileMode = 0600;
constexpr mode_t kStoreDirectoryMode = 0700;

bool copy_file_bytes(const fs::path& from, const fs::path& to) {
    std::ifstream input(from, std::ios::binary);
    if (!input) return false;
    std::ofstream output(to, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output << input.rdbuf();
    if (input.bad() || !output) return false;
    output.close();
    if (!output) return false;
    // Narrowed after creation rather than through the open, because the mode
    // an ofstream creates with is whatever the process umask allows.
    return ::chmod(to.c_str(), kStoredFileMode) == 0;
}

bool write_private_file(const fs::path& path, const std::string& body) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output << body;
    output.close();
    if (!output) return false;
    return ::chmod(path.c_str(), kStoredFileMode) == 0;
}

struct ManifestEntry {
    std::size_t index{0};
    std::uint32_t mode{0};
    std::string sha256;
    std::string path;
};

// Strict. A manifest line we cannot parse makes the whole capture unusable,
// because a partially understood record of what a rollback would restore is
// not something to restore from.
bool parse_manifest(const fs::path& manifest,
                    std::vector<ManifestEntry>& entries) {
    std::ifstream input(manifest);
    if (!input) return false;
    std::string line;
    if (!std::getline(input, line) || line != kManifestHeader) return false;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        ManifestEntry entry;
        std::string mode;
        if (!(fields >> entry.index >> mode >> entry.sha256)) return false;
        if (!rescue_integrity::valid_sha256_hex(entry.sha256)) return false;
        char* end = nullptr;
        errno = 0;
        const auto parsed = std::strtoul(mode.c_str(), &end, 8);
        if (errno != 0 || end == nullptr || *end != '\0') return false;
        entry.mode = static_cast<std::uint32_t>(parsed);
        // The path is the rest of the line, so it may contain spaces.
        if (!(fields >> std::ws)) return false;
        std::getline(fields, entry.path);
        if (entry.path.empty()) return false;
        entries.push_back(std::move(entry));
    }
    return !entries.empty();
}

} // namespace

ComponentCaptureResult capture_component_files(
    const PackageFootprint& footprint,
    const fs::path& store) {
    ComponentCaptureResult result;
    std::error_code error;
    // A previous capture describes a version that is about to stop being the
    // installed one. Leaving any of it behind would let a stale file answer a
    // manifest entry from this run.
    fs::remove_all(store, error);
    fs::create_directories(store / kFilesDir, error);
    if (error) {
        result.failed.push_back(store.string());
        return result;
    }
    if (::chmod(store.c_str(), kStoreDirectoryMode) != 0 ||
        ::chmod((store / kFilesDir).c_str(), kStoreDirectoryMode) != 0) {
        result.failed.push_back(store.string());
        return result;
    }

    std::ostringstream manifest;
    manifest << kManifestHeader << '\n';
    std::size_t index = 0;
    for (const auto& state : footprint.files) {
        if (!state.present) {
            ++result.skipped_absent;
            continue;
        }
        // Unreadable means we could not hash it, so there is nothing to
        // record about what would be stored.
        //
        // This and the digest check below are redundant on purpose, and
        // neither is individually load bearing: a symlink skipped here would
        // otherwise be copied and then rejected there, because the target's
        // digest cannot match an entry that has none. Removing both lets it
        // into the store; removing either one does not. The test says so.
        if (state.unreadable || state.sha256.empty()) {
            result.failed.push_back(state.path);
            continue;
        }
        const auto name = stored_name(++index);
        if (!copy_file_bytes(state.path, store / kFilesDir / name)) {
            result.failed.push_back(state.path);
            continue;
        }
        const auto stored_digest =
            rescue_integrity::sha256_file(store / kFilesDir / name);
        // Verified from the copy, not assumed from the source. A short write
        // that nothing checked is exactly the failure a rollback would meet at
        // the worst moment. See the note above on why this pairs with the
        // check there rather than standing alone.
        if (!stored_digest || *stored_digest != state.sha256) {
            result.failed.push_back(state.path);
            continue;
        }
        manifest << index << ' ' << std::oct << state.mode << std::dec << ' '
                 << state.sha256 << ' ' << state.path << '\n';
        ++result.captured;
    }

    if (result.captured == 0) {
        result.failed.push_back(store.string());
        return result;
    }

    // The manifest names every captured path, so it is no less private than
    // the files it describes.
    if (!write_private_file(store / kManifestName, manifest.str())) {
        result.failed.push_back((store / kManifestName).string());
        return result;
    }
    const auto manifest_digest =
        rescue_integrity::sha256_file(store / kManifestName);
    if (!manifest_digest) {
        result.failed.push_back((store / kManifestName).string());
        return result;
    }
    // Written last on purpose: until this exists the capture is not a capture,
    // so an interruption anywhere above is detectable rather than silently
    // short.
    if (!write_private_file(store / kReadyName, *manifest_digest + "\n")) {
        result.failed.push_back((store / kReadyName).string());
        return result;
    }

    result.complete = result.failed.empty();
    return result;
}

ComponentCaptureState verify_component_capture(const fs::path& store) {
    std::error_code error;
    if (!fs::is_directory(store, error) || error)
        return ComponentCaptureState::absent;

    const auto manifest = store / kManifestName;
    const auto declared =
        rescue_integrity::read_strict_single_line(store / kReadyName);
    const auto actual = rescue_integrity::sha256_file(manifest);
    if (!declared || !actual ||
        !rescue_integrity::valid_sha256_hex(*declared) ||
        *declared != *actual) {
        return ComponentCaptureState::incomplete;
    }

    std::vector<ManifestEntry> entries;
    if (!parse_manifest(manifest, entries))
        return ComponentCaptureState::incomplete;

    for (const auto& entry : entries) {
        const auto stored = store / kFilesDir / stored_name(entry.index);
        const auto digest = rescue_integrity::sha256_file(stored);
        if (!digest || *digest != entry.sha256)
            return ComponentCaptureState::corrupted;
    }
    return ComponentCaptureState::usable;
}

ComponentRestoreResult restore_component_files(const fs::path& store) {
    ComponentRestoreResult result;
    const auto state = verify_component_capture(store);
    if (state != ComponentCaptureState::usable) {
        result.refused = component_capture_state_name(state);
        return result;
    }

    std::vector<ManifestEntry> entries;
    if (!parse_manifest(store / kManifestName, entries)) {
        // verify_component_capture just parsed this successfully, so reaching
        // here means the store changed underneath us.
        result.refused = "incomplete";
        return result;
    }

    for (const auto& entry : entries) {
        const auto stored = store / kFilesDir / stored_name(entry.index);
        std::ifstream input(stored, std::ios::binary);
        if (!input) {
            result.failed.push_back(entry.path);
            continue;
        }
        std::string body((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
        if (input.bad()) {
            result.failed.push_back(entry.path);
            continue;
        }
        try {
            AtomicFileWriteOptions options;
            options.create_parent_directories = true;
            options.file_mode = static_cast<mode_t>(entry.mode);
            write_file_atomically(entry.path, body, options);
        } catch (const std::exception&) {
            result.failed.push_back(entry.path);
            continue;
        }
        // Confirmed from the destination. The point of this whole path is that
        // the bytes are what they are claimed to be, and the one place that
        // must not be taken on trust is the last one.
        const auto written = rescue_integrity::sha256_file(entry.path);
        if (!written || *written != entry.sha256) {
            result.failed.push_back(entry.path);
            continue;
        }
        ++result.restored;
    }

    result.complete = result.failed.empty() && result.restored == entries.size();
    return result;
}

const char* component_capture_state_name(
    ComponentCaptureState state) noexcept {
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
