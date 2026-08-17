#pragma once

#include <string>

namespace keen_pbr3 {

// What happened to the operator's active nfqws2 configuration across a package
// upgrade.
//
// Measured in the shipped preinst of nfqws2-keenetic:
//
//     INSTALLED_VERSION=$(grep -E '^CONFIG_VERSION=' "$CONFFILE" | ...)
//     if [ "$INSTALLED_VERSION" -lt "$CURRENT_VERSION" ]; then
//         mv "$CONFFILE" "$CONFFILE-old"
//         echo "install" > "/opt/tmp/nfqws2_install_type"
//     fi
//
// So whenever upstream bumps CONFIG_VERSION, the operator's own nfqws2.conf is
// moved aside and the package installs its defaults in its place. This happens
// before opkg's conffile machinery ever sees the file, which is why none of
// the `.conf-opkg*` names keen-pbr already watches for ever appear: from
// opkg's point of view there was no existing conffile to collide with.
//
// The upgrade then reports success, the operator's strategy is gone, and the
// file holding their settings sits at nfqws2.conf-old with nothing pointing at
// it. The roadmap's requirement is not that this must not happen - it is
// upstream's package and its migration - but that it must not happen silently.
enum class NfqwsConfigOutcome {
    // Byte-identical before and after. Nothing to say.
    preserved,
    // The active file changed and no displaced copy of the previous one
    // appeared. Ordinary conffile handling, or a change keen-pbr itself made.
    edited_in_place,
    // The active file changed AND a displaced copy holding exactly the
    // previous bytes appeared. This is the migration above, identified by
    // evidence rather than by guessing from the version number.
    replaced_by_package,
    // There was a configuration and now there is none.
    lost,
    absent_throughout,
};

struct NfqwsConfigObservation {
    bool active_present{false};
    std::string active_sha256;
    // nfqws2.conf-old. Persists forever once the first migration has run,
    // which is why its mere presence proves nothing and its contents must be
    // compared against the configuration that was actually displaced.
    bool displaced_present{false};
    std::string displaced_sha256;
};

// Pure.
//
// `replaced_by_package` requires the displaced copy to hold the bytes the
// active file had before this upgrade. Without that check a stale .conf-old
// left by an upgrade months ago would make every later upgrade report a
// replacement that did not happen - and a warning that cries wolf on every run
// is one an operator learns to skip past on the run that mattered.
NfqwsConfigOutcome judge_nfqws_config(const NfqwsConfigObservation& before,
                                      const NfqwsConfigObservation& after);

const char* nfqws_config_outcome_name(NfqwsConfigOutcome outcome) noexcept;

} // namespace keen_pbr3
