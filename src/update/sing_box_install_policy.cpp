#include "sing_box_install_policy.hpp"

#include <algorithm>

namespace keen_pbr3 {

namespace {

// The Entware architecture prefix, i.e. everything before the ABI suffix that
// `opkg print-architecture` appends ("aarch64-3.10" -> "aarch64").
std::string entware_family(const std::string& architecture) {
    const auto dash = architecture.find('-');
    if (dash == std::string::npos) return {};
    // A leading dash, or nothing after it, is not an architecture; an empty
    // family would otherwise fall through to the unmapped branch by accident
    // rather than by decision.
    if (dash == 0U || dash + 1U >= architecture.size()) return {};
    return architecture.substr(0U, dash);
}

} // namespace

const char* sing_box_install_blocker_name(
    const SingBoxInstallBlocker blocker) noexcept {
    switch (blocker) {
    case SingBoxInstallBlocker::architecture_unsupported:
        return "architecture_unsupported";
    case SingBoxInstallBlocker::entware_absent:
        return "entware_absent";
    case SingBoxInstallBlocker::target_not_writable:
        return "target_not_writable";
    case SingBoxInstallBlocker::foreign_binary_present:
        return "foreign_binary_present";
    case SingBoxInstallBlocker::transports_running:
        return "transports_running";
    case SingBoxInstallBlocker::transport_state_unknown:
        return "transport_state_unknown";
    }
    return "architecture_unsupported";
}

const char* sing_box_install_operation_name(
    const SingBoxInstallOperation operation) noexcept {
    switch (operation) {
    case SingBoxInstallOperation::install:
        return "install";
    case SingBoxInstallOperation::replace:
        return "replace";
    case SingBoxInstallOperation::reinstall_same_version:
        return "reinstall_same_version";
    }
    return "install";
}

std::string sing_box_asset_architecture(
    const std::string& entware_architecture) {
    // install.sh maps the Entware family to its own KEEN_ARCH, then KEEN_ARCH
    // to the official asset name. Both steps are reproduced here; a gate
    // compares this table against that file.
    const std::string family = entware_family(entware_architecture);
    if (family == "aarch64") return "arm64";
    if (family == "armv7") return "armv7";
    if (family == "mipsel") return "mipsle";
    if (family == "mips") return "mips";
    if (family == "x64") return "amd64";
    return {};
}

SingBoxInstallPolicy evaluate_sing_box_install(
    const SingBoxInstallObservation& observation,
    const std::string& pinned_version) {
    SingBoxInstallPolicy policy;
    policy.asset_architecture =
        sing_box_asset_architecture(observation.entware_architecture);

    // Entware first: without it there is no /opt to install into, and the
    // architecture question is not merely unanswered, it is unaskable.
    if (!observation.entware_present) {
        policy.blockers.push_back(SingBoxInstallBlocker::entware_absent);
    } else if (policy.asset_architecture.empty()) {
        // An unreadable architecture lands here too, and that is deliberate:
        // an architecture we could not read is not one we may guess.
        policy.blockers.push_back(
            SingBoxInstallBlocker::architecture_unsupported);
    }

    if (observation.entware_present &&
        !observation.target_directory_writable) {
        policy.blockers.push_back(
            SingBoxInstallBlocker::target_not_writable);
    }

    if (observation.binary_present &&
        !observation.managed_marker_matches_binary) {
        policy.blockers.push_back(
            SingBoxInstallBlocker::foreign_binary_present);
    }

    if (!observation.running_transports.has_value()) {
        // Nobody could take the count. Treating that as zero would let an
        // unreachable transport manager authorise the one operation the
        // manager exists to veto.
        policy.blockers.push_back(
            SingBoxInstallBlocker::transport_state_unknown);
    } else if (*observation.running_transports > 0U) {
        policy.blockers.push_back(
            SingBoxInstallBlocker::transports_running);
    }

    // What installing WOULD do, computed before and regardless of whether it
    // may. These are different questions, and collapsing them lost the answer
    // to the first: with a transport running, a router already on the pinned
    // version reported "blocked" and nothing else, so a client could not tell
    // "stop your tunnel and I will update you" from "stop your tunnel so I can
    // install the version you already have". Measured on NC-1812, which is
    // where it showed up as an Update button that had nothing to do.
    if (!observation.binary_present) {
        policy.operation = SingBoxInstallOperation::install;
    } else if (!observation.installed_version.empty() &&
               observation.installed_version == pinned_version) {
        policy.operation =
            SingBoxInstallOperation::reinstall_same_version;
    } else {
        // Includes the case where the binary is ours but would not report a
        // version: something is there, it is not demonstrably the pinned
        // release, and replacing it is the honest description.
        policy.operation = SingBoxInstallOperation::replace;
    }
    policy.available = policy.blockers.empty();
    return policy;
}

bool sing_box_install_awaits_transport_consent(
    const SingBoxInstallPolicy& policy) noexcept {
    if (policy.available) return false;
    if (policy.blockers.empty()) return false;
    // Nothing to gain. Asking somebody to drop their tunnels so the daemon can
    // reinstall the version already on the router is a question whose honest
    // answer is always no - a reinstall is still allowed, but not at that
    // price and not without being asked for by name.
    if (policy.operation ==
        SingBoxInstallOperation::reinstall_same_version) {
        return false;
    }
    for (const auto blocker : policy.blockers) {
        if (blocker != SingBoxInstallBlocker::transports_running) {
            return false;
        }
    }
    return true;
}

} // namespace keen_pbr3
