#pragma once

#include <filesystem>

namespace keen_pbr3 {

// Why a byte-exact package rollback is or is not possible right now.
//
// This exists because the answer was previously a bare boolean, and a bare
// boolean is unusable at the moment it matters. An operator told only "rollback
// unavailable" cannot tell an expected situation from a broken one, and a
// transaction that is about to replace a working binary cannot decide whether
// it is safe to start. The states below are separated exactly where the
// response differs.
//
// Measured on a live router before this was written: the rescue store is
// populated only by keen-pbr's own update path. A plain `opkg install` - which
// is how the package is installed by hand, and how it had been installed on
// that router all day - bypasses the store entirely, so `previous.ipk` was
// never written and no rollback existed. Nothing said so until a rollback was
// attempted. A previous package that was never captured cannot be manufactured
// afterwards; the only honest fix is to report the absence early.
enum class PackageRollbackState {
    // A verified previous package and its configuration snapshot are both
    // present. This says a rollback can start, not that it will succeed.
    available,
    // A previous update or rollback was interrupted and its recovery has not
    // finished. The store describes a transition, not a resting state, so its
    // contents must not be treated as a rollback target. Recovery first.
    recovery_pending,
    // The rescue helper marked the state UNKNOWN: it could not determine what
    // is installed. Distinct from every other value because it is the one that
    // says the store's own account of itself is not trustworthy.
    recovery_unknown,
    // The rescue helper is missing or not executable. Nothing here can be
    // driven, whatever the store contains.
    helper_missing,
    // No previous package was ever captured - the ordinary state after a fresh
    // install, or after any install that did not go through keen-pbr's own
    // update path. Not a fault: it is what a first installation looks like.
    //
    // Indistinguishable from a store somebody cleared, because a store that was
    // cleared leaves no record of having existed. Reported as absence rather
    // than as damage; claiming damage we cannot show would be a guess.
    never_captured,
    // A previous package is recorded but does not match its sha256 sidecar, or
    // only half the pair survived. Unlike `never_captured` this is a fault: the
    // store was written and is now wrong, and installing from it is exactly the
    // thing integrity verification exists to prevent.
    package_unverified,
    // The previous package verifies but its configuration snapshot does not.
    // Rolling back the binary alone would leave it running against
    // configuration it never shipped with, which is not the state being rolled
    // back to.
    snapshot_unverified,
};

// What was actually seen on disk. Separated from the judgement below because
// the defect this slice addresses was never in the judgement - it was in what
// the judgement was handed. Both halves get their own tests.
struct PackageRollbackObservations {
    bool recovery_pending{false};
    bool recovery_unknown{false};
    bool helper_usable{false};
    // Present as a regular non-empty file. Kept apart from `verified` so an
    // absent package and a corrupted one do not collapse into one report.
    bool previous_package_present{false};
    bool previous_package_verified{false};
    bool previous_config_present{false};
    bool previous_config_verified{false};
};

// Pure. The order is the point: a store that cannot describe itself is
// reported before anything is concluded from its contents.
PackageRollbackState classify_package_rollback(
    const PackageRollbackObservations& observations);

// True only for `available`. Written as its own function so no caller has to
// re-state which values are the safe ones.
bool package_rollback_is_available(PackageRollbackState state) noexcept;

// Stable wire name. Consumed by the UI, which owns the translated text.
const char* package_rollback_state_name(PackageRollbackState state) noexcept;

// English sentence for the refusal an operator gets if a rollback is started
// anyway. Shares a source with the reported state on purpose: a pre-flight
// report and a refusal that can disagree are worse than either alone.
const char* package_rollback_state_message(PackageRollbackState state) noexcept;

// Where the rescue store keeps the files this reads. Passed in rather than
// hardcoded so the observation half can be tested against a real store built
// in a temporary directory.
struct RescueStoreLayout {
    std::filesystem::path helper;
    std::filesystem::path previous_package;
    std::filesystem::path previous_config;
    std::filesystem::path pending_marker;
    std::filesystem::path unknown_marker;
};

// Reads the store. An unreadable rescue directory counts as a marker being
// present, never as its absence: the one reading that must not be produced by
// a filesystem error is "nothing to recover".
PackageRollbackObservations observe_package_rollback(
    const RescueStoreLayout& layout);

} // namespace keen_pbr3
