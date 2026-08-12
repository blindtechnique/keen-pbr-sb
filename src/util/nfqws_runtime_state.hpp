#pragma once

#include <string>

namespace keen_pbr3 {

// Whether nfqws2 is actually running the binary that was just installed.
//
// Measured on the live router, in the shipped maintainer scripts:
//
//   prerm    -> S51nfqws2 stop        (the service is taken down)
//   unpack   -> new files land
//   postinst -> start_func -> S51nfqws2 start
//
// So an upgrade always stops the component and brings it back up itself, with
// nothing in between checking that the new binary can run against the
// operator's configuration. The init script's own start() begins with
// `validate_config || return 1`, which means the most ordinary bad outcome is
// not a crash but a silence: the service simply does not come back.
//
// That is the failure this reports. It is the likely one right after a
// CONFIG_VERSION migration, because the configuration the new binary is asked
// to validate is no longer the one the operator tested.
enum class NfqwsRuntimeOutcome {
    // A live process whose image is the installed binary. What success means.
    running_current,
    // Live, but the image it is running is not the file on disk. The upgrade
    // replaced the binary without the process being restarted onto it.
    running_stale,
    // It was running before the upgrade and is not running now. Not a
    // degraded state - the component is simply gone, and reporting the
    // upgrade as successful would hide that.
    stopped_by_upgrade,
    // It was not running before either. The operator had it stopped; leaving
    // it stopped is correct, not a regression.
    idle,
    // The process or its image could not be inspected. Says nothing; must not
    // be read as either health or failure.
    unknown,
};

struct NfqwsRuntimeObservation {
    bool process_present{false};
    // Every live process agreed on one image. False when at least one could
    // not be read, or when they disagree - which is itself not health.
    bool image_consistent{false};
    std::string image_sha256;
};

// Pure. `installed_sha256` is the digest of the binary on disk after the
// upgrade; empty means it could not be read or is not there.
NfqwsRuntimeOutcome judge_nfqws_runtime(
    const NfqwsRuntimeObservation& before,
    const NfqwsRuntimeObservation& after,
    const std::string& installed_sha256);

// True for outcomes on which a transaction must not commit: either the
// component is broken or its running image could not be verified.
bool nfqws_runtime_is_failure(NfqwsRuntimeOutcome outcome) noexcept;

const char* nfqws_runtime_outcome_name(NfqwsRuntimeOutcome outcome) noexcept;

} // namespace keen_pbr3
