#include <doctest/doctest.h>

#include "../src/util/nfqws_runtime_state.hpp"

#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

const std::string kOldImage =
    "1111111111111111111111111111111111111111111111111111111111111111";
const std::string kNewImage =
    "2222222222222222222222222222222222222222222222222222222222222222";

NfqwsRuntimeObservation running(const std::string& image) {
    NfqwsRuntimeObservation observation;
    observation.process_present = true;
    observation.image_consistent = true;
    observation.image_sha256 = image;
    return observation;
}

NfqwsRuntimeObservation stopped() { return {}; }

} // namespace

TEST_CASE("an upgrade that restarts onto the new binary is the success case") {
    CHECK(judge_nfqws_runtime(running(kOldImage), running(kNewImage),
                              kNewImage) ==
          NfqwsRuntimeOutcome::running_current);
    CHECK_FALSE(nfqws_runtime_is_failure(
        NfqwsRuntimeOutcome::running_current));
}

TEST_CASE("a service that did not come back is a failure, not a detail") {
    // The measured sequence is prerm -> stop, postinst -> start, and the init
    // script's start() begins with `validate_config || return 1`. So the
    // ordinary bad outcome is not a crash but a silence, and it is likeliest
    // right after a configuration migration.
    const auto outcome =
        judge_nfqws_runtime(running(kOldImage), stopped(), kNewImage);
    CHECK(outcome == NfqwsRuntimeOutcome::stopped_by_upgrade);
    CHECK(nfqws_runtime_is_failure(outcome));
}

TEST_CASE("a component the operator had stopped stays stopped without alarm") {
    const auto outcome = judge_nfqws_runtime(stopped(), stopped(), kNewImage);
    CHECK(outcome == NfqwsRuntimeOutcome::idle);
    // Calling this a regression would train the operator to ignore the one
    // warning that matters.
    CHECK_FALSE(nfqws_runtime_is_failure(outcome));
}

TEST_CASE("a live process on the previous image is not a working upgrade") {
    const auto outcome =
        judge_nfqws_runtime(running(kOldImage), running(kOldImage), kNewImage);
    CHECK(outcome == NfqwsRuntimeOutcome::running_stale);
    CHECK(nfqws_runtime_is_failure(outcome));
}

TEST_CASE("an unestablished image is reported as unestablished") {
    NfqwsRuntimeObservation inconsistent;
    inconsistent.process_present = true;
    inconsistent.image_consistent = false;
    CHECK(judge_nfqws_runtime(running(kOldImage), inconsistent, kNewImage) ==
          NfqwsRuntimeOutcome::unknown);

    NfqwsRuntimeObservation unhashable;
    unhashable.process_present = true;
    unhashable.image_consistent = true;
    CHECK(judge_nfqws_runtime(running(kOldImage), unhashable, kNewImage) ==
          NfqwsRuntimeOutcome::unknown);

    // An installed binary we could not hash leaves nothing to compare against,
    // and a comparison with an empty digest would call every process stale.
    CHECK(judge_nfqws_runtime(running(kOldImage), running(kNewImage), "") ==
          NfqwsRuntimeOutcome::unknown);

    // A transaction cannot be committed on an unverified process image. This
    // does not prove the service is broken, but it is a fail-closed operation
    // result and its journal must remain available for recovery.
    CHECK(nfqws_runtime_is_failure(NfqwsRuntimeOutcome::unknown));
}

TEST_CASE("loss outranks every question about the image") {
    NfqwsRuntimeObservation was_unreadable;
    was_unreadable.process_present = true;
    was_unreadable.image_consistent = false;
    // It was running, whatever it was running, and now it is not. That
    // conclusion never needed the old image to be identifiable.
    CHECK(judge_nfqws_runtime(was_unreadable, stopped(), kNewImage) ==
          NfqwsRuntimeOutcome::stopped_by_upgrade);
}

TEST_CASE("every runtime outcome has a distinct stable name") {
    const std::vector<NfqwsRuntimeOutcome> outcomes = {
        NfqwsRuntimeOutcome::running_current,
        NfqwsRuntimeOutcome::running_stale,
        NfqwsRuntimeOutcome::stopped_by_upgrade,
        NfqwsRuntimeOutcome::idle,
        NfqwsRuntimeOutcome::unknown,
    };
    std::set<std::string> names;
    for (const auto outcome : outcomes) {
        const std::string name = nfqws_runtime_outcome_name(outcome);
        CHECK_FALSE(name.empty());
        CHECK(names.insert(name).second);
    }
}

} // namespace keen_pbr3
