#include "sing_box_install_observation.hpp"

#include "../util/safe_exec.hpp"

#include <cstdio>
#include <filesystem>
#include <sstream>
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

    observation.binary_present =
        probes.path_exists && probes.path_exists(binary_path);
    observation.managed_marker_present =
        probes.path_exists && probes.path_exists(managed_marker_path);

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
    probes.path_exists = [](const std::string& path) {
        std::error_code error;
        return std::filesystem::exists(path, error) && !error;
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
