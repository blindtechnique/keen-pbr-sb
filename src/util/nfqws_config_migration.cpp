#include "nfqws_config_migration.hpp"

namespace keen_pbr3 {

NfqwsConfigOutcome judge_nfqws_config(const NfqwsConfigObservation& before,
                                      const NfqwsConfigObservation& after) {
    if (!before.active_present && !after.active_present)
        return NfqwsConfigOutcome::absent_throughout;
    if (before.active_present && !after.active_present)
        return NfqwsConfigOutcome::lost;
    if (!before.active_present) {
        // Nothing was there to displace, so a .conf-old sitting next to a new
        // file is somebody else's leftover, not evidence about this upgrade.
        return NfqwsConfigOutcome::edited_in_place;
    }
    // An unreadable file on either side leaves both digests empty, and two
    // empty digests must not compare equal - that would report a configuration
    // we could not read as one we had proven unchanged.
    if (before.active_sha256.empty() || after.active_sha256.empty())
        return NfqwsConfigOutcome::edited_in_place;
    if (before.active_sha256 == after.active_sha256)
        return NfqwsConfigOutcome::preserved;
    if (after.displaced_present &&
        !after.displaced_sha256.empty() &&
        after.displaced_sha256 == before.active_sha256) {
        return NfqwsConfigOutcome::replaced_by_package;
    }
    return NfqwsConfigOutcome::edited_in_place;
}

const char* nfqws_config_outcome_name(NfqwsConfigOutcome outcome) noexcept {
    switch (outcome) {
        case NfqwsConfigOutcome::preserved:
            return "preserved";
        case NfqwsConfigOutcome::edited_in_place:
            return "edited_in_place";
        case NfqwsConfigOutcome::replaced_by_package:
            return "replaced_by_package";
        case NfqwsConfigOutcome::lost:
            return "lost";
        case NfqwsConfigOutcome::absent_throughout:
            return "absent_throughout";
    }
    return "edited_in_place";
}

} // namespace keen_pbr3
