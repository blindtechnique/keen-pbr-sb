#include <doctest/doctest.h>

#include "../src/util/nfqws_config_migration.hpp"

#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

const std::string kOperatorConfig =
    "0000000000000000000000000000000000000000000000000000000000000001";
const std::string kPackageDefaults =
    "0000000000000000000000000000000000000000000000000000000000000002";
const std::string kAncientConfig =
    "0000000000000000000000000000000000000000000000000000000000000003";

NfqwsConfigObservation active(const std::string& digest) {
    NfqwsConfigObservation observation;
    observation.active_present = true;
    observation.active_sha256 = digest;
    return observation;
}

} // namespace

TEST_CASE("an untouched configuration is reported as untouched") {
    CHECK(judge_nfqws_config(active(kOperatorConfig),
                             active(kOperatorConfig)) ==
          NfqwsConfigOutcome::preserved);
}

TEST_CASE("the CONFIG_VERSION migration is identified by evidence") {
    // Exactly what the shipped preinst does: move the operator's file to
    // nfqws2.conf-old, then let the package install its defaults.
    auto after = active(kPackageDefaults);
    after.displaced_present = true;
    after.displaced_sha256 = kOperatorConfig;

    CHECK(judge_nfqws_config(active(kOperatorConfig), after) ==
          NfqwsConfigOutcome::replaced_by_package);
}

TEST_CASE("a stale displaced copy does not manufacture a replacement") {
    // .conf-old survives forever once the first migration has run. An upgrade
    // that only edits the config must not be reported as having taken the
    // operator's settings away, or the warning becomes noise on every run and
    // gets skipped past on the run that mattered.
    NfqwsConfigObservation before = active(kOperatorConfig);
    before.displaced_present = true;
    before.displaced_sha256 = kAncientConfig;

    auto after = active(kPackageDefaults);
    after.displaced_present = true;
    after.displaced_sha256 = kAncientConfig;

    CHECK(judge_nfqws_config(before, after) ==
          NfqwsConfigOutcome::edited_in_place);

    // ...and when the same upgrade does displace the current configuration,
    // the stale copy having been there first changes nothing.
    after.displaced_sha256 = kOperatorConfig;
    CHECK(judge_nfqws_config(before, after) ==
          NfqwsConfigOutcome::replaced_by_package);
}

TEST_CASE("an unchanged configuration is never called a replacement") {
    auto after = active(kOperatorConfig);
    after.displaced_present = true;
    after.displaced_sha256 = kOperatorConfig;
    // The displaced copy matches, but the active file never moved.
    CHECK(judge_nfqws_config(active(kOperatorConfig), after) ==
          NfqwsConfigOutcome::preserved);
}

TEST_CASE("a configuration we could not read is not a configuration we proved") {
    NfqwsConfigObservation unreadable;
    unreadable.active_present = true;

    // Two empty digests must not compare equal. Reporting `preserved` here
    // would claim a proof that was never obtained.
    CHECK(judge_nfqws_config(unreadable, unreadable) ==
          NfqwsConfigOutcome::edited_in_place);
    CHECK(judge_nfqws_config(active(kOperatorConfig), unreadable) ==
          NfqwsConfigOutcome::edited_in_place);
    CHECK(judge_nfqws_config(unreadable, active(kOperatorConfig)) ==
          NfqwsConfigOutcome::edited_in_place);
}

TEST_CASE("appearance and loss are their own answers") {
    const NfqwsConfigObservation nothing;
    CHECK(judge_nfqws_config(nothing, nothing) ==
          NfqwsConfigOutcome::absent_throughout);
    CHECK(judge_nfqws_config(active(kOperatorConfig), nothing) ==
          NfqwsConfigOutcome::lost);

    auto appeared = active(kPackageDefaults);
    appeared.displaced_present = true;
    appeared.displaced_sha256 = kAncientConfig;
    // Nothing was there to displace, so somebody else's leftover .conf-old
    // must not be read as evidence about this upgrade.
    CHECK(judge_nfqws_config(nothing, appeared) ==
          NfqwsConfigOutcome::edited_in_place);
}

TEST_CASE("every configuration outcome has a distinct stable name") {
    const std::vector<NfqwsConfigOutcome> outcomes = {
        NfqwsConfigOutcome::preserved,
        NfqwsConfigOutcome::edited_in_place,
        NfqwsConfigOutcome::replaced_by_package,
        NfqwsConfigOutcome::lost,
        NfqwsConfigOutcome::absent_throughout,
    };
    std::set<std::string> names;
    for (const auto outcome : outcomes) {
        const std::string name = nfqws_config_outcome_name(outcome);
        CHECK_FALSE(name.empty());
        CHECK(names.insert(name).second);
    }
}

} // namespace keen_pbr3
