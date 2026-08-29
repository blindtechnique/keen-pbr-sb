#pragma once

#include "runtime_firewall_lifecycle_completion.hpp"
#include "runtime_firewall_start_retry_policy.hpp"

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {

enum class RuntimeColdBootCandidateAction : std::uint8_t {
    publish_running,
    retain_previous_and_finish_available,
    finish_available_degraded,
    finish_shutdown,
    start_exact_route_rollback,
    start_full_rollback,
    request_fresh_recovery,
};

struct RuntimeColdBootCandidateEvidence final {
    RuntimeFirewallLifecycleTerminal terminal;
    bool exact_lease_owned{false};
    bool runtime_generation_current{false};
    bool exact_route_checkpoint_verified{false};
    bool route_candidate_mutated{false};
    bool resolver_terminal_verified{false};
    bool running_publication_succeeded{false};
};

constexpr RuntimeColdBootCandidateAction
plan_runtime_cold_boot_candidate_terminal(
    const RuntimeColdBootCandidateEvidence& evidence) noexcept {
    // Losing the exact writer/generation is not proof that a route mutation
    // or firewall COMMIT is absent. Keep diagnostics available, but never
    // resnapshot that unknown kernel state as a fresh rollback baseline.
    if (evidence.terminal.outcome ==
        RuntimeFirewallLifecycleOutcome::shutdown) {
        return RuntimeColdBootCandidateAction::finish_shutdown;
    }
    if (!evidence.exact_lease_owned ||
        !evidence.runtime_generation_current) {
        return RuntimeColdBootCandidateAction::
            finish_available_degraded;
    }

    const bool verified_candidate =
        evidence.terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        evidence.terminal.committed &&
        !evidence.terminal.commit_ambiguous &&
        evidence.exact_route_checkpoint_verified &&
        evidence.resolver_terminal_verified;
    if (verified_candidate) {
        return evidence.running_publication_succeeded
            ? RuntimeColdBootCandidateAction::publish_running
            : RuntimeColdBootCandidateAction::start_full_rollback;
    }

    // A revision delta plus worker acknowledgement proves that a mutation
    // happened, but it is not exact rollback authority. Without the matching
    // control checkpoint/epoch, neither rollback nor a fresh baseline is
    // safe.
    if (evidence.route_candidate_mutated &&
        !evidence.exact_route_checkpoint_verified) {
        return RuntimeColdBootCandidateAction::
            finish_available_degraded;
    }

    // An unknown COMMIT boundary is never authority to replay the candidate
    // or to run a rollback body against an invented preimage.
    if (evidence.terminal.commit_ambiguous) {
        return RuntimeColdBootCandidateAction::request_fresh_recovery;
    }

    if (!evidence.terminal.committed &&
        evidence.route_candidate_mutated &&
        evidence.exact_route_checkpoint_verified) {
        return RuntimeColdBootCandidateAction::start_exact_route_rollback;
    }

    // Retaining the previous firewall generation says nothing about routes:
    // an acknowledged candidate route mutation still has to restore its exact
    // preimage before cold boot may finish available.
    if (!evidence.terminal.committed &&
        evidence.terminal.previous_generation_certainly_retained) {
        return RuntimeColdBootCandidateAction::
            retain_previous_and_finish_available;
    }

    // A resolver or running-publication failure happens after a proven
    // firewall COMMIT. The stopped-runtime cleanup is the only exact local
    // rollback; it is performed with the same physical mutation token.
    if (evidence.terminal.committed) {
        return RuntimeColdBootCandidateAction::start_full_rollback;
    }

    return RuntimeColdBootCandidateAction::request_fresh_recovery;
}

enum class RuntimeColdBootRollbackKind : std::uint8_t {
    route_preimage,
    stopped_runtime,
};

enum class RuntimeColdBootRollbackAction : std::uint8_t {
    finish_available,
    request_fresh_recovery,
};

constexpr RuntimeColdBootRollbackAction
plan_runtime_cold_boot_rollback_terminal(
    RuntimeColdBootRollbackKind kind,
    bool exact_lease_owned,
    bool runtime_generation_current,
    bool rollback_verified) noexcept {
    (void)kind;
    return exact_lease_owned && runtime_generation_current &&
            rollback_verified
        ? RuntimeColdBootRollbackAction::finish_available
        : RuntimeColdBootRollbackAction::request_fresh_recovery;
}

enum class RuntimeColdBootRollbackRecoveryDispatch : std::uint8_t {
    retry_same_authority,
    release_and_schedule_fresh,
    release_and_finish_degraded,
};

// A route-mutated candidate may not turn its current state into a new
// baseline merely because the rollback worker or its control completion was
// rejected. Retry keeps the exact lease and preimage. Only a verified
// rollback may release that authority and start a fresh candidate; exhaustion
// releases into diagnostics without resnapshotting the mutated route.
constexpr RuntimeColdBootRollbackRecoveryDispatch
plan_runtime_cold_boot_rollback_recovery(
    bool exact_lease_owned,
    bool runtime_generation_current,
    bool rollback_verified,
    std::size_t recorded_failures,
    std::size_t failure_limit) noexcept {
    if (exact_lease_owned && runtime_generation_current &&
        rollback_verified) {
        return RuntimeColdBootRollbackRecoveryDispatch::
            release_and_schedule_fresh;
    }
    if (exact_lease_owned && runtime_generation_current &&
        recorded_failures < failure_limit) {
        return RuntimeColdBootRollbackRecoveryDispatch::
            retry_same_authority;
    }
    return RuntimeColdBootRollbackRecoveryDispatch::
        release_and_finish_degraded;
}

enum class RuntimeColdBootRecoveryDispatch : std::uint8_t {
    none,
    wait_for_exact_lease_release,
    schedule_with_backoff,
    finish_available_degraded,
};

enum class RuntimeColdBootCandidateBudgetDispatch : std::uint8_t {
    dispatch_immediately,
    schedule_with_backoff,
    exhausted,
};

struct RuntimeColdBootCandidateBudgetPlan final {
    RuntimeColdBootCandidateBudgetDispatch dispatch{
        RuntimeColdBootCandidateBudgetDispatch::exhausted};
    std::size_t next_attempt{0U};
    std::size_t backoff_index{0U};
};

// completed_candidate_bodies is shared by retained-owner retries and fresh
// post-lease observations. It is deliberately a body count, not a per-owner
// retry counter: splitting recovery across new contexts must not multiply the
// START budget. Attempt zero is immediate; every later body consumes the
// delay following the previously completed global attempt.
constexpr RuntimeColdBootCandidateBudgetPlan
plan_runtime_cold_boot_candidate_budget(
    std::size_t completed_candidate_bodies,
    std::size_t maximum_candidate_bodies) noexcept {
    if (completed_candidate_bodies >= maximum_candidate_bodies) {
        return {};
    }
    if (completed_candidate_bodies == 0U) {
        return RuntimeColdBootCandidateBudgetPlan{
            RuntimeColdBootCandidateBudgetDispatch::dispatch_immediately,
            /*next_attempt=*/0U,
            /*backoff_index=*/0U};
    }
    return RuntimeColdBootCandidateBudgetPlan{
        RuntimeColdBootCandidateBudgetDispatch::schedule_with_backoff,
        /*next_attempt=*/completed_candidate_bodies,
        /*backoff_index=*/completed_candidate_bodies - 1U};
}

// A fresh observation is never a same-body replay. It starts only after the
// exact candidate/rollback lease has returned and only while the shared START
// retry budget still admits another delayed attempt. Exhaustion leaves the
// control plane available in a diagnostic (not running) state.
constexpr RuntimeColdBootRecoveryDispatch
plan_runtime_cold_boot_fresh_recovery_dispatch(
    bool recovery_required,
    bool exact_lease_still_owned,
    bool bounded_retry_available) noexcept {
    if (!recovery_required) {
        return RuntimeColdBootRecoveryDispatch::none;
    }
    if (exact_lease_still_owned) {
        return RuntimeColdBootRecoveryDispatch::
            wait_for_exact_lease_release;
    }
    return bounded_retry_available
        ? RuntimeColdBootRecoveryDispatch::schedule_with_backoff
        : RuntimeColdBootRecoveryDispatch::finish_available_degraded;
}

// A retained owner may retry the same body only before any route/firewall
// mutation. Once the route candidate is acknowledged, the exact preimage has
// to be restored and a later retry must start from a fresh observation.
constexpr bool runtime_cold_boot_same_context_retry_allowed(
    bool transient,
    bool committed,
    bool commit_ambiguous,
    bool route_preimage_certainly_retained,
    bool bounded_retry_available) noexcept {
    return transient && !committed && !commit_ambiguous &&
        route_preimage_certainly_retained && bounded_retry_available;
}

// Scheduler callbacks are authority transfers: a negative task id is a
// rejected handoff, not a successfully armed retry/watchdog.
constexpr bool runtime_cold_boot_scheduler_task_accepted(
    int task_id) noexcept {
    return task_id >= 0;
}

// Shutdown closes every producer before service publication. A callback
// armed earlier must recheck this gate before opening API/probes/schedulers.
constexpr bool runtime_cold_boot_services_may_open(
    bool shutdown_requested,
    bool already_opened) noexcept {
    return !shutdown_requested && !already_opened;
}

// One no-throw publication fence for the realized firewall/LKG/resolver and
// the externally visible running cursor. A stale generation never invokes
// the commit callback and therefore cannot expose a half-published boot.
template <typename CurrentFn, typename CommitFn>
bool publish_runtime_cold_boot_if_current(
    CurrentFn&& current,
    CommitFn&& commit) noexcept {
    static_assert(
        std::is_nothrow_invocable_r_v<bool, CurrentFn&>,
        "cold-boot publication predicate must be noexcept");
    static_assert(
        std::is_nothrow_invocable_r_v<void, CommitFn&>,
        "cold-boot publication callback must be noexcept");
    if (!current()) return false;
    commit();
    return true;
}

} // namespace keen_pbr3
