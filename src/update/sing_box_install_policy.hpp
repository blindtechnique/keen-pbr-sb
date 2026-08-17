#pragma once

#include <cstdint>
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
};

const char* sing_box_install_blocker_name(
    SingBoxInstallBlocker blocker) noexcept;

enum class SingBoxInstallOperation : std::uint8_t {
    // Nothing is installed; a first install would be a pure addition.
    install,
    // Ours is installed at a different version.
    replace,
    // Ours is installed at exactly the pinned version. Reinstalling is still
    // allowed - a corrupt binary is a real reason - but it is not an upgrade
    // and must not be presented as one.
    reinstall_same_version,
    // At least one blocker; no operation is offered.
    blocked,
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
    // `sing-box version` as reported by the installed binary, empty when it is
    // absent or would not run. An installed binary we cannot interrogate is
    // not the pinned one as far as this decision is concerned.
    std::string installed_version;
    // Managed sing-box transports currently running.
    std::size_t running_transports{0U};
};

struct SingBoxInstallPolicy {
    bool available{false};
    SingBoxInstallOperation operation{SingBoxInstallOperation::blocked};
    std::vector<SingBoxInstallBlocker> blockers;
    // The official asset architecture this build would fetch, e.g. "arm64".
    // Empty when the architecture is unsupported.
    std::string asset_architecture;
    // Promises this implementation does NOT keep yet. They are fields rather
    // than prose so a client cannot render a capability it does not have, and
    // so that turning one true is a visible change.
    //
    // The release archive is fetched over TLS from GitHub and its checksum is
    // published beside it - but a checksums file that is merely absent must
    // not silently downgrade to an unverified install, which is what the shell
    // installer does today. Until the fetch path here refuses that, this stays
    // false.
    bool verified_archive_checksum{false};
    // Nothing signs these archives. GitHub release assets carry no signature
    // this daemon can check, so "pinned+signed" is currently pinned-only.
    bool signed_release{false};
    // No captured previous binary to restore byte-exactly after a failure.
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

} // namespace keen_pbr3
