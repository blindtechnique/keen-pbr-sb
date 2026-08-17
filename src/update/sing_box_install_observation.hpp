#pragma once

#include "sing_box_install_policy.hpp"

#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Fills a SingBoxInstallObservation from the router.
//
// The policy that consumes it performs no I/O on purpose; this is the other
// half, and it is split the same way for the same reason. The primitives below
// are injected, so what a measurement DOES with a command's output is testable
// without a router, and the commands themselves stay in one obvious place.
//
// Every reader reports failure distinguishably from a negative answer. A
// command that did not run is not a router without Entware, and a version that
// could not be read is not a version that is wrong - the policy needs those
// apart to stay fail-closed, and a reader that flattens them would make the
// decision confident about something nobody measured.

struct SingBoxInstallProbes {
    // stdout of `opkg print-architecture`, empty when it could not run.
    std::function<std::string()> read_opkg_architectures;
    // stdout of `<binary> version`, empty when absent or it would not run.
    std::function<std::string(const std::string& binary)> read_binary_version;
    std::function<bool(const std::string& path)> path_exists;
    std::function<bool(const std::string& directory)> directory_writable;
    // Managed sing-box transports currently running, or nullopt when the
    // manager could not be asked.
    //
    // Optional rather than throwing, because "nobody could ask" is a state the
    // policy already knows how to describe (transport_state_unknown) and an
    // exception is not: an exception leaves the handler entirely, so the
    // capability read fails with no detail and the blocker it should have
    // produced can never occur. A probe that cannot report its own failure
    // makes the decision it feeds unreachable.
    std::function<std::optional<std::size_t>()> count_running_transports;
};

// The Entware architecture opkg would install for, chosen the way install.sh
// chooses it: the highest-priority line that is neither `all` nor a `_kn`
// firmware architecture. Empty when the output names none.
//
// Exposed because the selection rule is the interesting part - `opkg
// print-architecture` lists several and picking the wrong line picks the wrong
// asset - and because it is worth testing against real output without a
// router.
std::string select_entware_architecture(const std::string& opkg_output);

// The version an installed sing-box reports, from the first line of
// `sing-box version` ("sing-box version 1.13.14"). Empty when the output is
// not that shape, which includes a binary that did not run at all.
std::string parse_sing_box_version(const std::string& version_output);

SingBoxInstallObservation observe_sing_box_install(
    const SingBoxInstallProbes& probes,
    const std::string& binary_path,
    const std::string& managed_marker_path);

// The probes the daemon uses: safe_exec for the two commands, the filesystem
// for the two paths. `count_running_transports` is left unset and must be
// supplied by the caller, which is the only party that can ask the transport
// manager.
SingBoxInstallProbes production_sing_box_install_probes();

} // namespace keen_pbr3
