#include "component_ipk_store.hpp"

#include "rescue_integrity.hpp"
#include "../config/config_writer.hpp"
#include "../crypto/sha256.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <ctime>
#include <fstream>
#include <stdexcept>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace fs = std::filesystem;

namespace {

constexpr std::size_t kMaxManifestBytes = 4U * 1024U;

void sync_directory(const fs::path& path) noexcept {
    const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return;
    (void)::fsync(fd);
    ::close(fd);
}

std::string sha256_of(const std::string& bytes) {
    Sha256 hasher;
    hasher.update(bytes.data(), bytes.size());
    return hasher.hex_digest();
}

bool valid_version(const std::string& value) {
    // Versions travel into file names and opkg arguments; keep them to the
    // characters opkg itself accepts in a version field.
    if (value.empty() || value.size() > 64) return false;
    for (const unsigned char c : value) {
        if (!(std::isalnum(c) || c == '.' || c == '-' || c == '+' ||
              c == '~' || c == ':' || c == '_')) {
            return false;
        }
    }
    return true;
}

std::optional<RetainedIpk> read_manifest(const fs::path& path,
                                         const std::string& package,
                                         std::string& detail) {
    if (!rescue_integrity::regular_nonempty_file(path)) {
        detail = "manifest is not a regular file";
        return std::nullopt;
    }
    std::error_code error;
    const auto size = fs::file_size(path, error);
    if (error || size > kMaxManifestBytes) {
        detail = "manifest is oversized";
        return std::nullopt;
    }
    std::ifstream input(path, std::ios::binary);
    std::string body((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
    nlohmann::json document;
    try {
        document = nlohmann::json::parse(body);
    } catch (const std::exception&) {
        detail = "manifest is not JSON";
        return std::nullopt;
    }
    if (!document.is_object()) {
        detail = "manifest is not an object";
        return std::nullopt;
    }
    const auto string_field = [&](const char* key) -> std::string {
        const auto it = document.find(key);
        if (it == document.end() || !it->is_string()) return {};
        return it->get<std::string>();
    };
    RetainedIpk retained;
    retained.version = string_field("version");
    retained.sha256 = string_field("sha256");
    retained.filename = string_field("filename");
    const auto size_it = document.find("size");
    if (size_it != document.end() && size_it->is_number_unsigned()) {
        retained.size = size_it->get<std::uint64_t>();
    }
    if (string_field("package") != package) {
        detail = "manifest names a different package";
        return std::nullopt;
    }
    if (!valid_version(retained.version) ||
        !rescue_integrity::valid_sha256_hex(retained.sha256) ||
        retained.filename.empty() || retained.size == 0) {
        detail = "manifest is incomplete";
        return std::nullopt;
    }
    return retained;
}

} // namespace

const char* ipk_slot_name(IpkSlot slot) noexcept {
    switch (slot) {
    case IpkSlot::current: return "current";
    case IpkSlot::previous: return "previous";
    case IpkSlot::candidate: return "candidate";
    }
    return "unknown";
}

const char* ipk_slot_state_name(IpkSlotState state) noexcept {
    switch (state) {
    case IpkSlotState::absent: return "absent";
    case IpkSlotState::usable: return "usable";
    case IpkSlotState::corrupt: return "corrupt";
    }
    return "unknown";
}

ComponentIpkStore::ComponentIpkStore(fs::path root, std::string package)
    : directory_(root / package), package_(std::move(package)) {}

const fs::path& ComponentIpkStore::directory() const noexcept {
    return directory_;
}

const std::string& ComponentIpkStore::package() const noexcept {
    return package_;
}

fs::path ComponentIpkStore::ipk_path(IpkSlot slot) const {
    return directory_ / (std::string(ipk_slot_name(slot)) + ".ipk");
}

fs::path ComponentIpkStore::sidecar_path(IpkSlot slot) const {
    return directory_ / (std::string(ipk_slot_name(slot)) + ".ipk.sha256");
}

fs::path ComponentIpkStore::manifest_path(IpkSlot slot) const {
    return directory_ / (std::string(ipk_slot_name(slot)) + ".json");
}

IpkSlotInspection ComponentIpkStore::inspect(IpkSlot slot) const {
    IpkSlotInspection inspection;
    const auto manifest = manifest_path(slot);
    std::error_code error;
    if (!fs::exists(fs::symlink_status(manifest, error)) || error) {
        // No manifest, no slot. Leftover bytes without one are an aborted
        // publish and carry no claim.
        return inspection;
    }
    std::string detail;
    auto retained = read_manifest(manifest, package_, detail);
    if (!retained) {
        inspection.state = IpkSlotState::corrupt;
        inspection.detail = detail;
        return inspection;
    }
    const auto ipk = ipk_path(slot);
    if (!rescue_integrity::regular_nonempty_file(ipk)) {
        inspection.state = IpkSlotState::corrupt;
        inspection.detail = "ipk is missing or not a regular file";
        return inspection;
    }
    const auto size = fs::file_size(ipk, error);
    if (error || size != retained->size) {
        inspection.state = IpkSlotState::corrupt;
        inspection.detail = "ipk size differs from the manifest";
        return inspection;
    }
    const auto digest = rescue_integrity::sha256_file(ipk);
    if (!digest || *digest != retained->sha256) {
        inspection.state = IpkSlotState::corrupt;
        inspection.detail = "ipk digest differs from the manifest";
        return inspection;
    }
    const auto sidecar =
        rescue_integrity::read_strict_single_line(sidecar_path(slot));
    if (!sidecar || *sidecar != retained->sha256) {
        inspection.state = IpkSlotState::corrupt;
        inspection.detail = "sha256 sidecar differs from the manifest";
        return inspection;
    }
    inspection.state = IpkSlotState::usable;
    inspection.retained = std::move(retained);
    return inspection;
}

void ComponentIpkStore::ensure_private_directory() {
    std::error_code error;
    const auto status = fs::symlink_status(directory_, error);
    if (!error && fs::exists(status)) {
        if (!fs::is_directory(status)) {
            throw std::runtime_error("component store path is not a directory");
        }
    } else {
        fs::create_directories(directory_);
    }
    if (::chmod(directory_.c_str(), 0700) != 0) {
        throw std::runtime_error("component store could not be made private");
    }
}

RetainedIpk ComponentIpkStore::adopt(IpkSlot slot,
                                     const std::string& bytes,
                                     const FeedPackageEntry& entry) {
    if (!entry.identifies_ipk() || entry.package != package_) {
        throw std::runtime_error("feed entry does not identify this package");
    }
    if (!valid_version(entry.version)) {
        throw std::runtime_error("feed entry version is not usable");
    }
    if (bytes.size() != entry.size) {
        throw std::runtime_error(
            "ipk size is " + std::to_string(bytes.size()) +
            ", the feed promised " + std::to_string(entry.size));
    }
    const auto digest = sha256_of(bytes);
    if (digest != entry.sha256) {
        throw std::runtime_error("ipk digest differs from what the feed promised");
    }

    ensure_private_directory();

    // Retract any claim first, so a crash between the writes below leaves
    // an absent slot, never the old manifest over new bytes.
    std::error_code error;
    fs::remove(manifest_path(slot), error);
    sync_directory(directory_);

    AtomicFileWriteOptions options;
    options.file_mode = 0600;
    write_file_atomically(ipk_path(slot).string(), bytes, options);
    write_file_atomically(sidecar_path(slot).string(), digest + "\n",
                          options);

    RetainedIpk retained;
    retained.version = entry.version;
    retained.sha256 = digest;
    retained.size = entry.size;
    retained.filename = entry.filename;
    const nlohmann::json manifest{
        {"package", package_},
        {"version", retained.version},
        {"filename", retained.filename},
        {"size", retained.size},
        {"sha256", retained.sha256},
        {"retained_at", static_cast<std::int64_t>(std::time(nullptr))},
    };
    write_file_atomically(manifest_path(slot).string(),
                          manifest.dump(2) + "\n", options);
    return retained;
}

void ComponentIpkStore::move_slot(IpkSlot from, IpkSlot to) {
    // Manifest of the destination goes first (destination becomes absent),
    // the source manifest moves last (source stays usable until the bytes
    // have arrived). Between them the destination is at worst corrupt, and
    // corrupt is never acted on.
    std::error_code error;
    fs::remove(manifest_path(to), error);
    sync_directory(directory_);
    fs::rename(ipk_path(from), ipk_path(to));
    fs::rename(sidecar_path(from), sidecar_path(to));
    fs::rename(manifest_path(from), manifest_path(to));
    sync_directory(directory_);
}

void ComponentIpkStore::promote_candidate() {
    const auto candidate = inspect(IpkSlot::candidate);
    if (candidate.state != IpkSlotState::usable) {
        throw std::runtime_error(
            std::string("candidate slot is ") +
            ipk_slot_state_name(candidate.state) +
            (candidate.detail.empty() ? "" : ": " + candidate.detail));
    }
    if (inspect(IpkSlot::current).state == IpkSlotState::usable) {
        move_slot(IpkSlot::current, IpkSlot::previous);
    } else {
        // Nothing exact to keep: do not let stale bytes pose as previous.
        discard(IpkSlot::current);
    }
    move_slot(IpkSlot::candidate, IpkSlot::current);
}

void ComponentIpkStore::discard(IpkSlot slot) {
    std::error_code error;
    fs::remove(manifest_path(slot), error);
    sync_directory(directory_);
    fs::remove(sidecar_path(slot), error);
    fs::remove(ipk_path(slot), error);
    sync_directory(directory_);
}

fs::path ComponentIpkStore::staging_directory() {
    ensure_private_directory();
    const auto staging = directory_ / "staging";
    std::error_code error;
    const auto status = fs::symlink_status(staging, error);
    if (!error && fs::exists(status)) {
        if (!fs::is_directory(status)) {
            throw std::runtime_error("staging path is not a directory");
        }
        for (const auto& entry : fs::directory_iterator(staging, error)) {
            fs::remove_all(entry.path(), error);
        }
    } else {
        fs::create_directory(staging);
    }
    if (::chmod(staging.c_str(), 0700) != 0) {
        throw std::runtime_error("staging directory could not be made private");
    }
    return staging;
}

} // namespace keen_pbr3
