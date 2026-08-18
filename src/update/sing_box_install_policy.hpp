#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Whether the daemon may install the pinned sing-box release, and what it can
// honestly promise about the result.
//
// Roadmap item 7 asks for pinned+signed, staged validation and exact rescue
// recovery, and says an unknown backend capability stays fail-closed. This
// module is the fail-closed part: it decides from measurements only, and every
// promise it cannot keep is reported as a false flag rather than omitted.
//
// It performs no I/O. The observation below is filled by the caller from
// `opkg print-architecture`, the filesystem and the transport manager, so the
// decision is testable without a router and the measurement is testable
// without the decision.

enum class SingBoxInstallBlocker : std::uint8_t {
    // `opkg print-architecture` gave nothing, or nothing this build knows how
    // to turn into an official sing-box asset name. Guessing an asset name is
    // how you install an ARM binary on MIPS.
    architecture_unsupported,
    // No Entware, so no /opt/bin to install into and no opkg to have asked.
    entware_absent,
    // /opt/bin is not writable by this daemon.
    target_not_writable,
    // A sing-box exists that this daemon did not install. Replacing an
    // operator's own binary is a decision they have to make explicitly; the
    // marker file is what distinguishes ours from theirs.
    foreign_binary_present,
    // Managed transports are running on the binary about to be replaced.
    // Swapping it underneath them is what "the current runtime is not changed
    // until a confirmed operation" exists to prevent.
    transports_running,
    // Nobody could determine whether transports are running. Distinct from
    // `transports_running` because the operator fixes them differently: one
    // is "stop your tunnels", the other is "your transport manager is down".
    transport_state_unknown,
};

const char* sing_box_install_blocker_name(
    SingBoxInstallBlocker blocker) noexcept;

// What installing WOULD do. Deliberately independent of whether it may: a
// router already on the pinned version says so even while a running transport
// blocks the install, because "stop your tunnel and I will update you" and
// "stop your tunnel so I can reinstall what you have" are different requests.
enum class SingBoxInstallOperation : std::uint8_t {
    // Nothing is installed; a first install would be a pure addition.
    install,
    // Ours is installed at a different version.
    replace,
    // Ours is installed at exactly the pinned version. Reinstalling is still
    // allowed - a corrupt binary is a real reason - but it is not an upgrade
    // and must not be presented as one.
    reinstall_same_version,
};

const char* sing_box_install_operation_name(
    SingBoxInstallOperation operation) noexcept;

struct SingBoxInstallObservation {
    // Exactly what `opkg print-architecture` selected, e.g. "aarch64-3.10".
    // Empty means the read failed - which is unknown, not absent.
    std::string entware_architecture;
    bool entware_present{false};
    bool target_directory_writable{false};
    // A binary exists at the configured path.
    bool binary_present{false};
    // The marker this daemon writes when it installed that binary. Absent with
    // a present binary means the binary is the operator's.
    bool managed_marker_present{false};
    // A byte-exact copy of the binary an earlier install replaced, kept beside
    // the target. Its presence is what makes an undo possible, so the
    // capability reports the measurement rather than a promise.
    bool previous_binary_present{false};
    // `sing-box version` as reported by the installed binary, empty when it is
    // absent or would not run. An installed binary we cannot interrogate is
    // not the pinned one as far as this decision is concerned.
    std::string installed_version;
    // Managed sing-box transports currently running. Empty means nobody could
    // ask - the manager was unreachable, or the caller supplied no probe.
    // That is not zero: an install that swaps the binary under running
    // transports is exactly what a count nobody took would have permitted.
    std::optional<std::size_t> running_transports;
};

struct SingBoxInstallPolicy {
    bool available{false};
    SingBoxInstallOperation operation{SingBoxInstallOperation::install};
    std::vector<SingBoxInstallBlocker> blockers;
    // The official asset architecture this build would fetch, e.g. "arm64".
    // Empty when the architecture is unsupported.
    std::string asset_architecture;
    // Promises this implementation does NOT keep yet. They are fields rather
    // than prose so a client cannot render a capability it does not have, and
    // so that turning one true is a visible change.
    //
    // True since the installer refuses a release that publishes no checksums
    // file, rather than downgrading to an unverified install the way the shell
    // installer does. The archive is verified against the published digest
    // before anything is unpacked, and the unpacked binary must report the
    // pinned version before it replaces anything.
    bool verified_archive_checksum{true};
    // Nothing signs these archives. GitHub release assets carry no signature
    // this daemon can check, so "pinned+signed" is currently pinned-only.
    bool signed_release{false};
    // Whether a byte-exact copy of the replaced binary is on the router right
    // now. Measured, not declared: the first install has nothing to preserve,
    // and preserving it is best effort - a full filesystem is a reason to have
    // no rollback, not a reason to refuse an install the operator asked for.
    bool exact_rollback{false};
};

// The official sing-box asset architecture for an Entware architecture string,
// or empty when this build has no mapping for it.
//
// Mirrors the two `case` tables in install.sh. Neither side can read the
// other - the installer runs standalone on a router - so a gate compares them,
// the same way the pinned version is handled.
std::string sing_box_asset_architecture(
    const std::string& entware_architecture);

SingBoxInstallPolicy evaluate_sing_box_install(
    const SingBoxInstallObservation& observation,
    const std::string& pinned_version);

// Whether an operator's consent can unblock this install.
//
// Running transports are the only blocker consent can answer, and the reason
// is that they are the only one that is about the operator's choice rather
// than about the router. Somebody can agree to their tunnels stopping for a
// minute; nobody can agree Entware into existence, or agree a directory into
// being writable, or agree away a binary that belongs to them.
//
// Available already means nothing is blocking, so it is not a case for consent
// either - and answering true there would let a caller "consent" to stopping
// transports that are not running.
bool sing_box_install_awaits_transport_consent(
    const SingBoxInstallPolicy& policy) noexcept;

} // namespace keen_pbr3
