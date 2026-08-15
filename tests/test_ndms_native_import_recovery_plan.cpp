#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_import_recovery_plan.hpp"

#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

using Step = NdmsNativeImportRecoveryStep;
using Phase = NdmsNativeImportWalPhase;
using Action = NdmsNativeImportRecoveryAction;

NdmsNativeImportWalRecord record_at(const Phase phase) {
    NdmsNativeImportWalRecord record;
    record.phase = phase;
    return record;
}

std::vector<Step> steps_for(const Phase phase, const Action action) {
    return plan_ndms_native_import_recovery(record_at(phase), action).steps;
}

} // namespace

TEST_CASE("retry and block verdicts plan nothing") {
    for (const auto phase :
         {Phase::prepared, Phase::response_recorded,
          Phase::ownership_published, Phase::absence_verified}) {
        CHECK(steps_for(phase, Action::retry_read_only_observation).empty());
        CHECK(steps_for(phase, Action::block_unknown).empty());
    }
}

TEST_CASE("an abort cleans up only the record") {
    CHECK(steps_for(Phase::prepared, Action::abort_without_mutation) ==
          std::vector<Step>{Step::remove_wal_record});
}

TEST_CASE("a rollback publishes its intent before the delete may run") {
    const auto steps = steps_for(Phase::response_recorded,
                                 Action::rollback_delete_exact_owned);
    REQUIRE(steps.size() == 5U);
    CHECK(steps[0] == Step::advance_wal_rollback_requested);
    CHECK(steps[1] == Step::advance_wal_delete_may_be_inflight);
    CHECK(steps[2] == Step::delete_exact_owned_target);
    CHECK(steps[3] == Step::advance_wal_absence_verified);
    CHECK(steps[4] == Step::remove_wal_record);

    // The delete must never precede the published intent: a crash between
    // them would leave a deletion nobody recorded the reason for.
    for (std::size_t index = 0U; index < steps.size(); ++index) {
        if (steps[index] == Step::delete_exact_owned_target) {
            CHECK(index > 0U);
            CHECK(steps[index - 1U] ==
                  Step::advance_wal_delete_may_be_inflight);
        }
    }
}

TEST_CASE("a retried delete does not republish a phase it already holds") {
    const auto from_requested = steps_for(Phase::rollback_requested,
                                          Action::retry_exact_owned_delete);
    REQUIRE(from_requested.size() == 4U);
    CHECK(from_requested[0] == Step::advance_wal_delete_may_be_inflight);

    const auto from_inflight = steps_for(Phase::delete_may_be_inflight,
                                         Action::retry_exact_owned_delete);
    REQUIRE(from_inflight.size() == 3U);
    // Re-publishing delete_may_be_inflight from itself would be a
    // self-transition the codec has no reason to allow.
    CHECK(from_inflight[0] == Step::delete_exact_owned_target);
}

TEST_CASE("a target reappearing after proven absence is nobody's to delete") {
    CHECK(steps_for(Phase::absence_verified,
                    Action::retry_exact_owned_delete)
              .empty());
}

TEST_CASE("completing a rollback never moves the WAL backwards") {
    CHECK(steps_for(Phase::delete_may_be_inflight,
                    Action::complete_rollback) ==
          (std::vector<Step>{Step::advance_wal_absence_verified,
                             Step::remove_wal_record}));
    CHECK(steps_for(Phase::absence_verified, Action::complete_rollback) ==
          std::vector<Step>{Step::remove_wal_record});
    // ...and a forward phase has no rollback to complete.
    CHECK(steps_for(Phase::response_recorded,
                    Action::complete_rollback)
              .empty());
}

TEST_CASE("forward resume requires the published claim its verdict rests on") {
    CHECK(steps_for(Phase::ownership_published,
                    Action::resume_forward_reconcile) ==
          std::vector<Step>{Step::remove_wal_record});
    // The classifier only reaches this verdict from ownership_published; a
    // record in any earlier phase carrying it is a contradiction, and the
    // planner refuses rather than forward-completing an unverified import.
    CHECK(steps_for(Phase::response_recorded,
                    Action::resume_forward_reconcile)
              .empty());
    CHECK(steps_for(Phase::target_verified,
                    Action::resume_forward_reconcile)
              .empty());
}

TEST_CASE("a rollback plan exists only for phases that may hold a target") {
    CHECK(steps_for(Phase::prepared, Action::rollback_delete_exact_owned)
              .empty());
    CHECK(steps_for(Phase::absence_verified,
                    Action::rollback_delete_exact_owned)
              .empty());
}

TEST_CASE("every step has a distinct stable name") {
    std::set<std::string> names;
    for (const auto step :
         {Step::advance_wal_target_verified, Step::publish_ownership,
          Step::advance_wal_ownership_published,
          Step::advance_wal_rollback_requested,
          Step::advance_wal_delete_may_be_inflight,
          Step::delete_exact_owned_target,
          Step::advance_wal_absence_verified, Step::remove_wal_record}) {
        CHECK(names.insert(ndms_native_import_recovery_step_name(step))
                  .second);
    }
}

} // namespace keen_pbr3
