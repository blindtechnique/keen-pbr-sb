#include "nfqws_runtime_state.hpp"

namespace keen_pbr3 {

NfqwsRuntimeOutcome judge_nfqws_runtime(
    const NfqwsRuntimeObservation& before,
    const NfqwsRuntimeObservation& after,
    const std::string& installed_sha256) {
    if (!after.process_present) {
        // Only a loss is a failure. An operator who had the component stopped
        // gets it back stopped, and calling that a regression would train them
        // to ignore the warning.
        return before.process_present ? NfqwsRuntimeOutcome::stopped_by_upgrade
                                      : NfqwsRuntimeOutcome::idle;
    }
    if (!after.image_consistent || after.image_sha256.empty() ||
        installed_sha256.empty()) {
        // Something is running. Whether it is the right something could not be
        // established, and an unverifiable answer is its own answer.
        return NfqwsRuntimeOutcome::unknown;
    }
    return after.image_sha256 == installed_sha256
               ? NfqwsRuntimeOutcome::running_current
               : NfqwsRuntimeOutcome::running_stale;
}

bool nfqws_runtime_is_failure(NfqwsRuntimeOutcome outcome) noexcept {
    switch (outcome) {
        case NfqwsRuntimeOutcome::stopped_by_upgrade:
        case NfqwsRuntimeOutcome::running_stale:
            return true;
        case NfqwsRuntimeOutcome::running_current:
        case NfqwsRuntimeOutcome::idle:
        // Deliberately not a failure. `unknown` means the check could not be
        // made, and turning "I could not look" into a red result would make
        // every unreadable /proc entry fail an upgrade that worked.
        case NfqwsRuntimeOutcome::unknown:
            return false;
    }
    return false;
}

const char* nfqws_runtime_outcome_name(NfqwsRuntimeOutcome outcome) noexcept {
    switch (outcome) {
        case NfqwsRuntimeOutcome::running_current:
            return "running_current";
        case NfqwsRuntimeOutcome::running_stale:
            return "running_stale";
        case NfqwsRuntimeOutcome::stopped_by_upgrade:
            return "stopped_by_upgrade";
        case NfqwsRuntimeOutcome::idle:
            return "idle";
        case NfqwsRuntimeOutcome::unknown:
            return "unknown";
    }
    return "unknown";
}

} // namespace keen_pbr3
