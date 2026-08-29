#include <doctest/doctest.h>

#include "daemon/runtime_cold_boot_terminal_policy.hpp"
#include "runtime/runtime_mutation_admission.hpp"

#include <cstdint>
#include <utility>

using namespace keen_pbr3;

namespace {

RuntimeColdBootCandidateEvidence base_evidence() {
    RuntimeColdBootCandidateEvidence evidence;
    evidence.exact_lease_owned = true;
    evidence.runtime_generation_current = true;
    evidence.exact_route_checkpoint_verified = true;
    return evidence;
}

RuntimeColdBootCandidateEvidence successful_evidence() {
    auto evidence = base_evidence();
    evidence.terminal.outcome =
        RuntimeFirewallLifecycleOutcome::verified_success;
    evidence.terminal.committed = true;
    evidence.terminal.commit_ambiguous = false;
    evidence.resolver_terminal_verified = true;
    evidence.running_publication_succeeded = true;
    return evidence;
}

} // namespace

TEST_CASE("cold boot publishes only after route firewall resolver and running proof") {
    auto evidence = successful_evidence();
    CHECK(plan_runtime_cold_boot_candidate_terminal(evidence) ==
          RuntimeColdBootCandidateAction::publish_running);

    evidence.exact_route_checkpoint_verified = false;
    CHECK(plan_runtime_cold_boot_candidate_terminal(evidence) ==
          RuntimeColdBootCandidateAction::start_full_rollback);
    evidence.exact_route_checkpoint_verified = true;
    evidence.resolver_terminal_verified = false;
    CHECK(plan_runtime_cold_boot_candidate_terminal(evidence) ==
          RuntimeColdBootCandidateAction::start_full_rollback);
}

TEST_CASE("cold boot clean precommit terminal retains crash surviving generation") {
    auto evidence = base_evidence();
    evidence.terminal.outcome =
        RuntimeFirewallLifecycleOutcome::not_verified;
    evidence.terminal.committed = false;
    evidence.terminal.commit_ambiguous = false;
    evidence.terminal.previous_generation_certainly_retained = true;
    evidence.exact_route_checkpoint_verified = false;
    CHECK(plan_runtime_cold_boot_candidate_terminal(evidence) ==
          RuntimeColdBootCandidateAction::
              retain_previous_and_finish_available);
}

TEST_CASE("cold boot route mutation receives exact preimage rollback") {
    auto evidence = base_evidence();
    evidence.terminal.outcome =
        RuntimeFirewallLifecycleOutcome::not_verified;
    evidence.terminal.committed = false;
    evidence.terminal.commit_ambiguous = false;
    // A retained old firewall generation does not make the candidate route
    // mutation safe to leave installed.
    evidence.terminal.previous_generation_certainly_retained = true;
    evidence.route_candidate_mutated = true;
    CHECK(plan_runtime_cold_boot_candidate_terminal(evidence) ==
          RuntimeColdBootCandidateAction::start_exact_route_rollback);

    CHECK(plan_runtime_cold_boot_rollback_terminal(
              RuntimeColdBootRollbackKind::route_preimage,
              /*exact_lease_owned=*/true,
              /*runtime_generation_current=*/true,
              /*rollback_verified=*/true) ==
          RuntimeColdBootRollbackAction::finish_available);
}

TEST_CASE("cold boot route revision without control checkpoint is not rollback authority") {
    auto evidence = base_evidence();
    evidence.exact_route_checkpoint_verified = false;
    evidence.route_candidate_mutated = true;
    evidence.terminal.outcome =
        RuntimeFirewallLifecycleOutcome::not_verified;
    evidence.terminal.committed = false;
    evidence.terminal.commit_ambiguous = false;
    evidence.terminal.previous_generation_certainly_retained = true;
    CHECK(plan_runtime_cold_boot_candidate_terminal(evidence) ==
          RuntimeColdBootCandidateAction::finish_available_degraded);

    evidence.terminal.commit_ambiguous = true;
    CHECK(plan_runtime_cold_boot_candidate_terminal(evidence) ==
          RuntimeColdBootCandidateAction::finish_available_degraded);
}

TEST_CASE("cold boot rollback rejection retains exact authority until verified or exhausted") {
    RuntimeMutationAdmission admission;
    auto lease = admission.try_acquire("cold-boot-rollback-authority");
    REQUIRE(lease.has_value());
    const auto token = lease->token();

    for (std::size_t failures = 0U;
         failures < kRuntimeFirewallStartRollbackHandoffRetryLimit;
         ++failures) {
        CHECK(plan_runtime_cold_boot_rollback_recovery(
                  /*exact_lease_owned=*/true,
                  /*runtime_generation_current=*/true,
                  /*rollback_verified=*/false,
                  failures,
                  kRuntimeFirewallStartRollbackHandoffRetryLimit) ==
              RuntimeColdBootRollbackRecoveryDispatch::
                  retry_same_authority);
        REQUIRE(admission.active().has_value());
        CHECK(admission.active()->token == token);
    }

    CHECK(plan_runtime_cold_boot_rollback_recovery(
              /*exact_lease_owned=*/true,
              /*runtime_generation_current=*/true,
              /*rollback_verified=*/false,
              kRuntimeFirewallStartRollbackHandoffRetryLimit,
              kRuntimeFirewallStartRollbackHandoffRetryLimit) ==
          RuntimeColdBootRollbackRecoveryDispatch::
              release_and_finish_degraded);
    CHECK(plan_runtime_cold_boot_rollback_recovery(
              /*exact_lease_owned=*/false,
              /*runtime_generation_current=*/true,
              /*rollback_verified=*/false,
              /*recorded_failures=*/0U,
              kRuntimeFirewallStartRollbackHandoffRetryLimit) ==
          RuntimeColdBootRollbackRecoveryDispatch::
              release_and_finish_degraded);
    CHECK(plan_runtime_cold_boot_rollback_recovery(
              /*exact_lease_owned=*/true,
              /*runtime_generation_current=*/false,
              /*rollback_verified=*/false,
              /*recorded_failures=*/0U,
              kRuntimeFirewallStartRollbackHandoffRetryLimit) ==
          RuntimeColdBootRollbackRecoveryDispatch::
              release_and_finish_degraded);
    lease.reset();
    CHECK_FALSE(admission.active().has_value());

    CHECK(plan_runtime_cold_boot_fresh_recovery_dispatch(
              /*recovery_required=*/false,
              /*exact_lease_still_owned=*/false,
              /*bounded_retry_available=*/true) ==
          RuntimeColdBootRecoveryDispatch::none);
}

TEST_CASE("verified cold boot rollback releases before bounded fresh observation") {
    RuntimeMutationAdmission admission;
    auto lease = admission.try_acquire("cold-boot-rollback-verified");
    REQUIRE(lease.has_value());
    CHECK(plan_runtime_cold_boot_rollback_recovery(
              /*exact_lease_owned=*/true,
              /*runtime_generation_current=*/true,
              /*rollback_verified=*/true,
              /*recorded_failures=*/2U,
              kRuntimeFirewallStartRollbackHandoffRetryLimit) ==
          RuntimeColdBootRollbackRecoveryDispatch::
              release_and_schedule_fresh);
    REQUIRE(admission.active().has_value());
    lease.reset();
    REQUIRE_FALSE(admission.active().has_value());
    CHECK(plan_runtime_cold_boot_fresh_recovery_dispatch(
              /*recovery_required=*/true,
              /*exact_lease_still_owned=*/false,
              /*bounded_retry_available=*/true) ==
          RuntimeColdBootRecoveryDispatch::schedule_with_backoff);
}

TEST_CASE("cold boot ambiguous commit never rolls back or replays") {
    auto evidence = base_evidence();
    evidence.terminal.outcome =
        RuntimeFirewallLifecycleOutcome::not_verified;
    evidence.terminal.committed = false;
    evidence.terminal.commit_ambiguous = true;
    evidence.route_candidate_mutated = true;
    CHECK(plan_runtime_cold_boot_candidate_terminal(evidence) ==
          RuntimeColdBootCandidateAction::request_fresh_recovery);
}

TEST_CASE("cold boot lost authority never baselines a mutated candidate") {
    auto route_mutated = base_evidence();
    route_mutated.exact_lease_owned = false;
    route_mutated.route_candidate_mutated = true;
    route_mutated.terminal.outcome =
        RuntimeFirewallLifecycleOutcome::not_verified;
    route_mutated.terminal.committed = false;
    route_mutated.terminal.commit_ambiguous = false;
    CHECK(plan_runtime_cold_boot_candidate_terminal(route_mutated) ==
          RuntimeColdBootCandidateAction::finish_available_degraded);

    auto post_commit = successful_evidence();
    post_commit.exact_lease_owned = false;
    CHECK(plan_runtime_cold_boot_candidate_terminal(post_commit) ==
          RuntimeColdBootCandidateAction::finish_available_degraded);

    auto stale_generation = route_mutated;
    stale_generation.exact_lease_owned = true;
    stale_generation.runtime_generation_current = false;
    CHECK(plan_runtime_cold_boot_candidate_terminal(stale_generation) ==
          RuntimeColdBootCandidateAction::finish_available_degraded);
}

TEST_CASE("cold boot shutdown is quiet and never opens degraded services") {
    auto evidence = base_evidence();
    evidence.terminal.outcome =
        RuntimeFirewallLifecycleOutcome::shutdown;
    evidence.terminal.committed = false;
    evidence.terminal.commit_ambiguous = true;
    evidence.route_candidate_mutated = true;
    CHECK(plan_runtime_cold_boot_candidate_terminal(evidence) ==
          RuntimeColdBootCandidateAction::finish_shutdown);
    CHECK(plan_runtime_cold_boot_fresh_recovery_dispatch(
              /*recovery_required=*/false,
              /*exact_lease_still_owned=*/false,
              /*bounded_retry_available=*/true) ==
          RuntimeColdBootRecoveryDispatch::none);
}

TEST_CASE("cold boot resolver and publication failures use stopped rollback") {
    auto resolver_failed = successful_evidence();
    resolver_failed.terminal.outcome =
        RuntimeFirewallLifecycleOutcome::not_verified;
    resolver_failed.resolver_terminal_verified = false;
    resolver_failed.running_publication_succeeded = false;
    CHECK(plan_runtime_cold_boot_candidate_terminal(resolver_failed) ==
          RuntimeColdBootCandidateAction::start_full_rollback);

    auto publication_mismatch = successful_evidence();
    publication_mismatch.running_publication_succeeded = false;
    CHECK(plan_runtime_cold_boot_candidate_terminal(publication_mismatch) ==
          RuntimeColdBootCandidateAction::start_full_rollback);
}

TEST_CASE("cold boot recovery starts only after exact mutation lease release") {
    RuntimeMutationAdmission admission;
    auto lease = admission.try_acquire("cold-boot-recovery-order");
    REQUIRE(lease.has_value());
    CHECK(plan_runtime_cold_boot_fresh_recovery_dispatch(
        /*recovery_required=*/true,
        admission.active().has_value(),
        /*bounded_retry_available=*/true) ==
          RuntimeColdBootRecoveryDispatch::wait_for_exact_lease_release);
    lease.reset();
    REQUIRE_FALSE(admission.active().has_value());
    CHECK(plan_runtime_cold_boot_fresh_recovery_dispatch(
        /*recovery_required=*/true,
        admission.active().has_value(),
        /*bounded_retry_available=*/true) ==
          RuntimeColdBootRecoveryDispatch::schedule_with_backoff);
}

TEST_CASE("cold boot recovery exhaustion stays available but never running") {
    CHECK(plan_runtime_cold_boot_fresh_recovery_dispatch(
              /*recovery_required=*/true,
              /*exact_lease_still_owned=*/false,
              /*bounded_retry_available=*/false) ==
          RuntimeColdBootRecoveryDispatch::finish_available_degraded);
    CHECK(plan_runtime_cold_boot_fresh_recovery_dispatch(
              /*recovery_required=*/false,
              /*exact_lease_still_owned=*/false,
              /*bounded_retry_available=*/true) ==
          RuntimeColdBootRecoveryDispatch::none);
}

TEST_CASE("cold boot shares one three-body budget across retained and fresh contexts") {
    constexpr auto maximum =
        kRuntimeFirewallStartBoundedRetryCount;
    static_assert(maximum == 3U);

    const auto initial =
        plan_runtime_cold_boot_candidate_budget(0U, maximum);
    CHECK(initial.dispatch ==
          RuntimeColdBootCandidateBudgetDispatch::dispatch_immediately);
    CHECK(initial.next_attempt == 0U);

    const auto retained_retry =
        plan_runtime_cold_boot_candidate_budget(1U, maximum);
    CHECK(retained_retry.dispatch ==
          RuntimeColdBootCandidateBudgetDispatch::schedule_with_backoff);
    CHECK(retained_retry.next_attempt == 1U);
    CHECK(retained_retry.backoff_index == 0U);
    CHECK(kRuntimeFirewallStartRetryDelays[
              retained_retry.backoff_index] ==
          std::chrono::milliseconds{100});

    // A rollback and fresh observation do not reset the global counter.
    const auto fresh_after_rollback =
        plan_runtime_cold_boot_candidate_budget(2U, maximum);
    CHECK(fresh_after_rollback.dispatch ==
          RuntimeColdBootCandidateBudgetDispatch::schedule_with_backoff);
    CHECK(fresh_after_rollback.next_attempt == 2U);
    CHECK(fresh_after_rollback.backoff_index == 1U);
    CHECK(kRuntimeFirewallStartRetryDelays[
              fresh_after_rollback.backoff_index] ==
          std::chrono::milliseconds{200});

    const auto exhausted =
        plan_runtime_cold_boot_candidate_budget(3U, maximum);
    CHECK(exhausted.dispatch ==
          RuntimeColdBootCandidateBudgetDispatch::exhausted);
    CHECK(exhausted.next_attempt == 0U);

    CHECK(plan_runtime_cold_boot_candidate_budget(0U, 0U).dispatch ==
          RuntimeColdBootCandidateBudgetDispatch::exhausted);
}

TEST_CASE("cold boot same context retry requires an untouched route preimage") {
    CHECK(runtime_cold_boot_same_context_retry_allowed(
        /*transient=*/true,
        /*committed=*/false,
        /*commit_ambiguous=*/false,
        /*route_preimage_certainly_retained=*/true,
        /*bounded_retry_available=*/true));
    CHECK_FALSE(runtime_cold_boot_same_context_retry_allowed(
        true, false, false, /*route_preimage_certainly_retained=*/false, true));
    CHECK_FALSE(runtime_cold_boot_same_context_retry_allowed(
        true, false, /*commit_ambiguous=*/true, true, true));
    CHECK_FALSE(runtime_cold_boot_same_context_retry_allowed(
        true, /*committed=*/true, false, true, true));
    CHECK_FALSE(runtime_cold_boot_same_context_retry_allowed(
        true, false, false, true, /*bounded_retry_available=*/false));
}

TEST_CASE("cold boot scheduler and service gates reject false handoffs") {
    CHECK(runtime_cold_boot_scheduler_task_accepted(0));
    CHECK_FALSE(runtime_cold_boot_scheduler_task_accepted(-1));
    CHECK(runtime_cold_boot_services_may_open(
        /*shutdown_requested=*/false, /*already_opened=*/false));
    CHECK_FALSE(runtime_cold_boot_services_may_open(
        /*shutdown_requested=*/true, /*already_opened=*/false));
    CHECK_FALSE(runtime_cold_boot_services_may_open(
        /*shutdown_requested=*/false, /*already_opened=*/true));
}

TEST_CASE("cold boot publication seam is atomic on generation mismatch") {
    struct Published {
        int firewall{1};
        int resolver{2};
        int lkg{3};
        int runtime{4};
    } published, candidate{11, 12, 13, 14};
    int calls = 0;

    CHECK_FALSE(publish_runtime_cold_boot_if_current(
        []() noexcept { return false; },
        [&]() noexcept {
            ++calls;
            using std::swap;
            swap(published.firewall, candidate.firewall);
            swap(published.resolver, candidate.resolver);
            swap(published.lkg, candidate.lkg);
            swap(published.runtime, candidate.runtime);
        }));
    CHECK(calls == 0);
    CHECK(published.firewall == 1);
    CHECK(published.resolver == 2);
    CHECK(published.lkg == 3);
    CHECK(published.runtime == 4);

    CHECK(publish_runtime_cold_boot_if_current(
        []() noexcept { return true; },
        [&]() noexcept {
            ++calls;
            using std::swap;
            swap(published.firewall, candidate.firewall);
            swap(published.resolver, candidate.resolver);
            swap(published.lkg, candidate.lkg);
            swap(published.runtime, candidate.runtime);
        }));
    CHECK(calls == 1);
    CHECK(published.firewall == 11);
    CHECK(published.resolver == 12);
    CHECK(published.lkg == 13);
    CHECK(published.runtime == 14);
}
