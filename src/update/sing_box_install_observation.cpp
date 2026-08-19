#include "sing_box_install_observation.hpp"

#include "../util/safe_exec.hpp"

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fcntl.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {

namespace {

// `opkg print-architecture` prints one "arch <name> <priority>" line per
// supported architecture. install.sh picks the highest priority among the
// lines that are neither `all` nor a `_kn` firmware architecture; the same
// choice is made here, because picking a different line picks a different
// asset.
struct ArchitectureLine {
    std::string name;
    long long priority{0};
    bool valid{false};
};

ArchitectureLine parse_architecture_line(const std::string& line) {
    ArchitectureLine parsed;
    std::istringstream fields(line);
    std::string keyword;
    std::string name;
    std::string priority;
    if (!(fields >> keyword >> name >> priority)) return parsed;
    std::string extra;
    if (fields >> extra) return parsed;
    if (name.empty() || name == "all") return parsed;
    // Firmware architectures. They are not Entware targets and no sing-box
    // asset corresponds to them.
    if (name.size() >= 3U && name.compare(name.size() - 3U, 3U, "_kn") == 0) {
        return parsed;
    }
    try {
        std::size_t consumed = 0U;
        parsed.priority = std::stoll(priority, &consumed);
        if (consumed != priority.size()) return parsed;
    } catch (const std::exception&) {
        return parsed;
    }
    parsed.name = name;
    parsed.valid = true;
    return parsed;
}

} // namespace

std::string select_entware_architecture(const std::string& opkg_output) {
    std::string selected;
    long long best = 0;
    bool any = false;
    std::istringstream lines(opkg_output);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto parsed = parse_architecture_line(line);
        if (!parsed.valid) continue;
        // `>=` rather than `>`: install.sh's awk keeps the LAST line at the
        // winning priority, and a different tie-break would select a
        // different asset on a router that lists two at the same priority.
        if (!any || parsed.priority >= best) {
            best = parsed.priority;
            selected = parsed.name;
            any = true;
        }
    }
    return selected;
}

std::string parse_sing_box_version(const std::string& version_output) {
    std::istringstream lines(version_output);
    std::string first;
    if (!std::getline(lines, first)) return {};
    if (!first.empty() && first.back() == '\r') first.pop_back();

    std::istringstream fields(first);
    std::string program;
    std::string keyword;
    std::string version;
    if (!(fields >> program >> keyword >> version)) return {};
    if (program != "sing-box" || keyword != "version") return {};
    // Anything that is not a dotted release is not a version we can compare
    // against the pin, and reporting it as one would let "1.13.14-dirty" pass
    // for the pinned release.
    if (version.empty()) return {};
    bool digit_seen = false;
    for (const char ch : version) {
        if (ch >= '0' && ch <= '9') {
            digit_seen = true;
            continue;
        }
        if (ch != '.') return {};
    }
    return digit_seen ? version : std::string{};
}

bool sing_box_managed_marker_matches(
    const std::string& marker_contents,
    const std::string& binary_path) noexcept {
    if (binary_path.empty() || binary_path.front() != '/') return false;
    return marker_contents == binary_path + "\n";
}

bool sing_box_managed_marker_metadata_is_trusted(
    const std::uintmax_t owner_uid,
    const std::uintmax_t hard_link_count,
    const std::uint32_t mode) noexcept {
    return owner_uid == 0U && hard_link_count == 1U &&
           (mode & static_cast<std::uint32_t>(S_IWGRP | S_IWOTH)) == 0U;
}

SingBoxInstallObservation observe_sing_box_install(
    const SingBoxInstallProbes& probes,
    const std::string& binary_path,
    const std::string& managed_marker_path) {
    SingBoxInstallObservation observation;

    const std::string architectures =
        probes.read_opkg_architectures ? probes.read_opkg_architectures()
                                       : std::string{};
    // Entware is present when opkg answered at all. An empty answer is a
    // command that did not run, which the policy must not read as a router
    // whose architecture is merely exotic.
    observation.entware_present = !architectures.empty();
    observation.entware_architecture =
        select_entware_architecture(architectures);

    const auto binary_presence =
        probes.path_exists ? probes.path_exists(binary_path)
                           : std::optional<bool>{};
    const bool binary_presence_known = binary_presence.has_value();
    // An uninspectable target is occupied for replacement-authority purposes.
    // Treating an error as absence would let rename() replace an operator-owned
    // entry without the marker that is required for every known-present entry.
    observation.binary_present =
        !binary_presence_known || *binary_presence;
    if (binary_presence_known && probes.read_managed_marker) {
        const auto marker = probes.read_managed_marker(managed_marker_path);
        observation.managed_marker_matches_binary =
            marker.has_value() &&
            sing_box_managed_marker_matches(*marker, binary_path);
    }
    // The path where an earlier install tried to keep the replaced binary.
    // This is only a presence observation; policy separately decides whether
    // that is enough to promise a rollback capability.
    if (probes.path_exists) {
        const auto previous_presence =
            probes.path_exists(binary_path + ".previous");
        observation.previous_binary_present =
            previous_presence.has_value() && *previous_presence;
    }

    if (observation.binary_present && probes.read_binary_version) {
        observation.installed_version =
            parse_sing_box_version(probes.read_binary_version(binary_path));
    }

    const auto directory =
        std::filesystem::path(binary_path).parent_path().string();
    observation.target_directory_writable =
        probes.directory_writable && probes.directory_writable(directory);

    if (probes.count_running_transports) {
        observation.running_transports = probes.count_running_transports();
    }
    return observation;
}

SingBoxInstallProbes production_sing_box_install_probes() {
    SingBoxInstallProbes probes;
    probes.read_opkg_architectures = []() -> std::string {
        const auto result = safe_exec_capture(
            {"/opt/bin/opkg", "print-architecture"},
            /*suppress_stderr=*/true,
            /*max_bytes=*/64U * 1024U,
            /*capture_stderr=*/false);
        if (result.exit_code != 0 || result.truncated) return {};
        return result.stdout_output;
    };
    probes.read_binary_version =
        [](const std::string& binary) -> std::string {
        const auto result = safe_exec_capture({binary, "version"},
                                              /*suppress_stderr=*/true,
                                              /*max_bytes=*/8U * 1024U,
                                              /*capture_stderr=*/false);
        if (result.exit_code != 0 || result.truncated) return {};
        return result.stdout_output;
    };
    probes.read_managed_marker =
        [](const std::string& marker) -> std::optional<std::string> {
        const int descriptor =
            ::open(marker.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0) return std::nullopt;

        const auto close_descriptor = [&]() { (void)::close(descriptor); };
        struct stat status {};
        if (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
            !sing_box_managed_marker_metadata_is_trusted(
                static_cast<std::uintmax_t>(status.st_uid),
                static_cast<std::uintmax_t>(status.st_nlink),
                static_cast<std::uint32_t>(status.st_mode))) {
            close_descriptor();
            return std::nullopt;
        }
        constexpr std::uintmax_t kMaximumMarkerBytes = 4096U;
        if (status.st_size <= 0 ||
            static_cast<std::uintmax_t>(status.st_size) >
                kMaximumMarkerBytes) {
            close_descriptor();
            return std::nullopt;
        }

        std::string contents(static_cast<std::size_t>(status.st_size), '\0');
        std::size_t consumed = 0U;
        while (consumed < contents.size()) {
            const auto count = ::read(descriptor, contents.data() + consumed,
                                      contents.size() - consumed);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) {
                close_descriptor();
                return std::nullopt;
            }
            consumed += static_cast<std::size_t>(count);
        }
        char extra = '\0';
        const auto trailing = ::read(descriptor, &extra, 1U);
        close_descriptor();
        if (trailing != 0) return std::nullopt;
        return contents;
    };
    probes.path_exists = [](const std::string& path) -> std::optional<bool> {
        std::error_code error;
        const auto status = std::filesystem::symlink_status(path, error);
        if (error) {
            if (error == std::errc::no_such_file_or_directory ||
                error == std::errc::not_a_directory) {
                return false;
            }
            return std::nullopt;
        }
        return status.type() != std::filesystem::file_type::not_found;
    };
    probes.directory_writable = [](const std::string& directory) {
        if (directory.empty()) return false;
        return ::access(directory.c_str(), W_OK | X_OK) == 0;
    };
    // Deliberately unset: only the caller can ask the transport manager, and
    // leaving it null here rather than defaulting to zero keeps "nobody asked"
    // from looking like "nothing is running".
    return probes;
}

} // namespace keen_pbr3
