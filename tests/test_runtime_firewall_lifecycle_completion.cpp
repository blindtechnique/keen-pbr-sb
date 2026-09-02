#include <doctest/doctest.h>

#include "daemon/runtime_config_terminal_policy.hpp"
#include "daemon/runtime_firewall_lifecycle_completion.hpp"
#include "daemon/runtime_urltest_terminal_orchestrator.hpp"
#include "daemon/runtime_urltest_terminal_policy.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <optional>
#include <string>
#include <thread>
#include <utility>

using namespace keen_pbr3;

namespace {

using LifecycleCompletion = RuntimeFirewallLifecycleCompletion;
using LifecycleOutcome = RuntimeFirewallLifecycleOutcome;
using LifecycleTerminal = RuntimeFirewallLifecycleTerminal;
using SettleStatus = LifecycleCompletion::Source::SettleStatus;

LifecycleTerminal verified_terminal(std::string detail) {
    LifecycleTerminal terminal;
    terminal.outcome = LifecycleOutcome::verified_success;
    terminal.committed = true;
    terminal.commit_ambiguous = false;
    terminal.detail = std::move(detail);
    return terminal;
}

LifecycleTerminal unverified_terminal(std::string detail) {
    LifecycleTerminal terminal;
    terminal.transient = true;
    terminal.detail = std::move(detail);
    return terminal;
}

constexpr std::uint64_t published_generation() noexcept {
    return 41U;
}

constexpr ConfigTerminalOperationIdentity candidate_identity() noexcept {
    return {
        ConfigTerminalOperationKind::candidate,
        17U,
        published_generation(),
        published_generation() + 1U};
}

constexpr ConfigTerminalOperationIdentity rollback_identity() noexcept {
    constexpr std::uint64_t candidate_generation = 42U;
    return {
        ConfigTerminalOperationKind::rollback,
        18U,
        candidate_generation,
        candidate_generation + 1U};
}

} // namespace

TEST_CASE("runtime firewall lifecycle completion settles exactly once") {
    auto pair = LifecycleCompletion::create();
    auto competing_source = pair.source;
    std::atomic<unsigned int> settled{0U};

    std::thread first([source = pair.source, &settled]() mutable {
        if (source.settle(verified_terminal("verified winner")) ==
            SettleStatus::settled) {
            settled.fetch_add(1U, std::memory_order_relaxed);
        }
    });
    std::thread second(
        [source = std::move(competing_source), &settled]() mutable {
            if (source.settle(unverified_terminal("unverified winner")) ==
                SettleStatus::settled) {
                settled.fetch_add(1U, std::memory_order_relaxed);
            }
        });

    first.join();
    second.join();

    CHECK(settled.load(std::memory_order_relaxed) == 1U);
    const auto terminal = pair.wait.try_get();
    REQUIRE(terminal.has_value());
    if (terminal->detail == "verified winner") {
        CHECK(terminal->outcome == LifecycleOutcome::verified_success);
        CHECK(terminal->committed);
        CHECK_FALSE(terminal->commit_ambiguous);
        CHECK_FALSE(terminal->transient);
    } else {
        CHECK(terminal->detail == "unverified winner");
        CHECK(terminal->outcome == LifecycleOutcome::not_verified);
        CHECK_FALSE(terminal->committed);
        CHECK(terminal->commit_ambiguous);
        CHECK(terminal->transient);
    }

    CHECK(pair.source.settle(
              verified_terminal("late terminal")) ==
          SettleStatus::already_settled);
    LifecycleCompletion::Source empty_source;
    CHECK(empty_source.settle(
              unverified_terminal("no source")) ==
          SettleStatus::no_source);
}

TEST_CASE("runtime firewall lifecycle completion wakes every waiter") {
    using namespace std::chrono_literals;

    auto pair = LifecycleCompletion::create();
    auto first_wait = pair.wait;
    auto second_wait = pair.wait;
    std::optional<LifecycleTerminal> first_terminal;
    std::optional<LifecycleTerminal> second_terminal;

    std::thread first([&]() {
        first_terminal = first_wait.wait_for(2s);
    });
    std::thread second([&]() {
        second_terminal = second_wait.wait_for(2s);
    });

    CHECK(pair.source.settle(
              verified_terminal("both waiters")) ==
          SettleStatus::settled);
    first.join();
    second.join();

    REQUIRE(first_terminal.has_value());
    REQUIRE(second_terminal.has_value());
    CHECK(first_terminal->outcome ==
          LifecycleOutcome::verified_success);
    CHECK(second_terminal->outcome ==
          LifecycleOutcome::verified_success);
    CHECK(first_terminal->detail == "both waiters");
    CHECK(second_terminal->detail == "both waiters");
}

TEST_CASE(
    "last runtime firewall lifecycle source publishes conservative terminal") {
    using namespace std::chrono_literals;

    auto pair = LifecycleCompletion::create();
    auto last_source = pair.source;
    auto wait = pair.wait;

    pair.source = {};
    CHECK_FALSE(wait.ready());
    last_source = {};

    const auto terminal = wait.wait_for(2s);
    REQUIRE(terminal.has_value());
    CHECK(terminal->outcome == LifecycleOutcome::not_verified);
    CHECK_FALSE(terminal->committed);
    CHECK(terminal->commit_ambiguous);
    CHECK_FALSE(terminal->transient);
    CHECK(terminal->detail ==
          "runtime firewall lifecycle source abandoned");
    CHECK_FALSE(terminal->observed_config_identity.has_value());
    CHECK_FALSE(terminal->previous_generation_certainly_retained);
    CHECK_FALSE(terminal->candidate_noop_verified);
}

TEST_CASE("runtime firewall lifecycle completion preserves typed config proof") {
    auto pair = LifecycleCompletion::create();
    auto terminal = verified_terminal("typed candidate proof");
    terminal.observed_config_identity = candidate_identity();
    terminal.previous_generation_certainly_retained = true;
    terminal.candidate_noop_verified = true;

    CHECK(pair.source.settle(std::move(terminal)) ==
          SettleStatus::settled);
    const auto observed = pair.wait.wait();
    REQUIRE(observed.observed_config_identity.has_value());
    CHECK(*observed.observed_config_identity == candidate_identity());
    CHECK(observed.previous_generation_certainly_retained);
    CHECK(observed.candidate_noop_verified);
}

TEST_CASE("runtime firewall lifecycle completion preserves shutdown") {
    auto pair = LifecycleCompletion::create();
    LifecycleTerminal shutdown;
    shutdown.outcome = LifecycleOutcome::shutdown;
    shutdown.commit_ambiguous = false;
    shutdown.detail = "daemon shutdown";

    CHECK(pair.source.settle(std::move(shutdown)) ==
          SettleStatus::settled);
    const auto terminal = pair.wait.wait();
    CHECK(terminal.outcome == LifecycleOutcome::shutdown);
    CHECK_FALSE(terminal.committed);
    CHECK_FALSE(terminal.commit_ambiguous);
    CHECK_FALSE(terminal.transient);
    CHECK(terminal.detail == "daemon shutdown");
}

TEST_CASE("config operation identities use logical monotonic generations") {
    const auto candidate = candidate_identity();
    const auto rollback = rollback_identity();

    CHECK(candidate.base_runtime_generation == published_generation());
    CHECK(candidate.target_runtime_generation ==
          published_generation() + 1U);
    CHECK(rollback.base_runtime_generation ==
          candidate.target_runtime_generation);
    CHECK(rollback.target_runtime_generation ==
          candidate.target_runtime_generation + 1U);

    // The publication fence remains the still-published runtime G. It is an
    // independent caller proof, not the rollback identity's logical G+1 base.
    ConfigRollbackEvidence evidence;
    evidence.expected_identity = rollback;
    evidence.exact_lease_owned = true;
    evidence.published_generation_current = true;
    evidence.terminal = verified_terminal("verified rollback");
    evidence.terminal.observed_config_identity = rollback;
    CHECK(plan_config_rollback_terminal(evidence) ==
          ConfigRollbackAction::accept_verified_rollback);
}

TEST_CASE("config candidate terminal policy is evidence complete") {
    struct CandidateCase {
        const char* name;
        bool exact_lease_owned;
        bool published_generation_current;
        LifecycleOutcome outcome;
        bool committed;
        bool commit_ambiguous;
        bool candidate_noop_verified;
        bool previous_generation_certainly_retained;
        bool exact_rollback_available;
        ConfigCandidateAction expected;
    };

    const std::array<CandidateCase, 11> cases{{
        {"verified no-op publishes",
         true, true, LifecycleOutcome::verified_success,
         false, false, true, true, true,
         ConfigCandidateAction::publish_candidate},
        {"verified commit publishes",
         true, true, LifecycleOutcome::verified_success,
         true, false, false, false, true,
         ConfigCandidateAction::publish_candidate},
        {"generic uncommitted success starts rollback",
         true, true, LifecycleOutcome::verified_success,
         false, false, false, true, true,
         ConfigCandidateAction::begin_exact_rollback},
        {"clean pre-commit rejection preserves runtime",
         true, true, LifecycleOutcome::not_verified,
         false, false, false, true, true,
         ConfigCandidateAction::reject_runtime_unchanged},
        {"committed unverified candidate starts rollback",
         true, true, LifecycleOutcome::not_verified,
         true, false, false, false, true,
         ConfigCandidateAction::begin_exact_rollback},
        {"ambiguous candidate starts distinct rollback",
         true, true, LifecycleOutcome::not_verified,
         false, true, false, false, true,
         ConfigCandidateAction::begin_exact_rollback},
        {"ambiguous candidate without rollback requires recovery",
         true, true, LifecycleOutcome::not_verified,
         false, true, false, false, false,
         ConfigCandidateAction::recovery_required},
        {"lost exact lease dominates verified terminal",
         false, true, LifecycleOutcome::verified_success,
         true, false, false, false, true,
         ConfigCandidateAction::recovery_required},
        {"stale published runtime fence never publishes",
         true, false, LifecycleOutcome::verified_success,
         true, false, false, false, true,
         ConfigCandidateAction::recovery_required},
        {"shutdown never claims a clean rejection",
         true, true, LifecycleOutcome::shutdown,
         false, false, false, true, true,
         ConfigCandidateAction::recovery_required},
        {"inconsistent pre-commit evidence uses rollback",
         true, true, LifecycleOutcome::not_verified,
         false, false, false, false, true,
         ConfigCandidateAction::begin_exact_rollback},
    }};

    for (const auto& test : cases) {
        CAPTURE(test.name);
        ConfigCandidateEvidence evidence;
        evidence.expected_identity = candidate_identity();
        evidence.exact_lease_owned = test.exact_lease_owned;
        evidence.published_generation_current =
            test.published_generation_current;
        evidence.terminal.observed_config_identity = candidate_identity();
        evidence.terminal.outcome = test.outcome;
        evidence.terminal.committed = test.committed;
        evidence.terminal.commit_ambiguous = test.commit_ambiguous;
        evidence.terminal.candidate_noop_verified =
            test.candidate_noop_verified;
        evidence.terminal.previous_generation_certainly_retained =
            test.previous_generation_certainly_retained;
        evidence.exact_rollback_available =
            test.exact_rollback_available;
        CHECK(plan_config_candidate_terminal(evidence) == test.expected);
    }
}

TEST_CASE(
    "active runtime reload defers only a clean transient owner rejection") {
    LifecycleTerminal terminal;
    terminal.outcome = LifecycleOutcome::not_verified;
    terminal.committed = false;
    terminal.commit_ambiguous = false;
    terminal.transient = true;
    terminal.previous_generation_certainly_retained = true;
    terminal.detail =
        kConfigCandidateOwnerDidNotAcceptOperation;

    CHECK(should_defer_active_runtime_reload_owner_rejection(
        /*retry_available=*/true,
        /*exact_lease_owned=*/true,
        /*published_generation_current=*/true,
        /*shutdown_requested=*/false,
        terminal));
    CHECK_FALSE(should_defer_active_runtime_reload_owner_rejection(
        /*retry_available=*/false,
        /*exact_lease_owned=*/true,
        /*published_generation_current=*/true,
        /*shutdown_requested=*/false,
        terminal));
    CHECK_FALSE(should_defer_active_runtime_reload_owner_rejection(
        /*retry_available=*/true,
        /*exact_lease_owned=*/false,
        /*published_generation_current=*/true,
        /*shutdown_requested=*/false,
        terminal));
    CHECK_FALSE(should_defer_active_runtime_reload_owner_rejection(
        /*retry_available=*/true,
        /*exact_lease_owned=*/true,
        /*published_generation_current=*/false,
        /*shutdown_requested=*/false,
        terminal));
    CHECK_FALSE(should_defer_active_runtime_reload_owner_rejection(
        /*retry_available=*/true,
        /*exact_lease_owned=*/true,
        /*published_generation_current=*/true,
        /*shutdown_requested=*/true,
        terminal));

    terminal.transient = false;
    CHECK_FALSE(should_defer_active_runtime_reload_owner_rejection(
        true, true, true, false, terminal));
    terminal.transient = true;
    terminal.commit_ambiguous = true;
    CHECK_FALSE(should_defer_active_runtime_reload_owner_rejection(
        true, true, true, false, terminal));
    terminal.commit_ambiguous = false;
    terminal.previous_generation_certainly_retained = false;
    CHECK_FALSE(should_defer_active_runtime_reload_owner_rejection(
        true, true, true, false, terminal));
    terminal.previous_generation_certainly_retained = true;
    terminal.detail = "different clean rejection";
    CHECK_FALSE(should_defer_active_runtime_reload_owner_rejection(
        true, true, true, false, terminal));
}

TEST_CASE("config candidate terminal policy binds exact operation identity") {
    struct IdentityCase {
        const char* name;
        ConfigTerminalOperationIdentity expected;
        ConfigTerminalOperationIdentity observed;
    };

    auto wrong_kind = candidate_identity();
    wrong_kind.kind = ConfigTerminalOperationKind::rollback;
    auto preapply = candidate_identity();
    preapply.kind = ConfigTerminalOperationKind::config_preapply;
    auto wrong_serial = candidate_identity();
    ++wrong_serial.operation_serial;
    auto wrong_base = candidate_identity();
    ++wrong_base.base_runtime_generation;
    auto wrong_target = candidate_identity();
    ++wrong_target.target_runtime_generation;
    auto zero_target = candidate_identity();
    zero_target.target_runtime_generation = 0U;

    const std::array<IdentityCase, 7> cases{{
        {"wrong operation kind", candidate_identity(), wrong_kind},
        {"preapply terminal", candidate_identity(), preapply},
        {"wrong operation serial", candidate_identity(), wrong_serial},
        {"wrong base generation", candidate_identity(), wrong_base},
        {"wrong target generation", candidate_identity(), wrong_target},
        {"missing expected identity", {}, candidate_identity()},
        {"zero observed identity field", candidate_identity(), zero_target},
    }};

    for (const auto& test : cases) {
        CAPTURE(test.name);
        ConfigCandidateEvidence evidence;
        evidence.expected_identity = test.expected;
        evidence.exact_lease_owned = true;
        evidence.published_generation_current = true;
        evidence.terminal.observed_config_identity = test.observed;
        evidence.terminal.outcome = LifecycleOutcome::verified_success;
        evidence.terminal.committed = true;
        evidence.terminal.commit_ambiguous = false;
        evidence.exact_rollback_available = true;
        CHECK(plan_config_candidate_terminal(evidence) ==
              ConfigCandidateAction::recovery_required);
    }

    ConfigCandidateEvidence missing_observed;
    missing_observed.expected_identity = candidate_identity();
    missing_observed.exact_lease_owned = true;
    missing_observed.published_generation_current = true;
    missing_observed.terminal = verified_terminal("untyped terminal");
    missing_observed.exact_rollback_available = true;
    CHECK(plan_config_candidate_terminal(missing_observed) ==
          ConfigCandidateAction::recovery_required);
}

TEST_CASE("config rollback terminal policy accepts only exact verified proof") {
    struct RollbackCase {
        const char* name;
        ConfigTerminalOperationIdentity expected_identity;
        ConfigTerminalOperationIdentity observed_identity;
        bool exact_lease_owned;
        bool published_generation_current;
        LifecycleOutcome outcome;
        bool commit_ambiguous;
        ConfigRollbackAction expected;
        bool committed{true};
        bool candidate_noop_verified{false};
    };

    auto wrong_kind = rollback_identity();
    wrong_kind.kind = ConfigTerminalOperationKind::candidate;
    auto preapply = rollback_identity();
    preapply.kind = ConfigTerminalOperationKind::config_preapply;
    auto wrong_serial = rollback_identity();
    ++wrong_serial.operation_serial;
    auto wrong_base = rollback_identity();
    ++wrong_base.base_runtime_generation;
    auto wrong_target = rollback_identity();
    ++wrong_target.target_runtime_generation;
    auto zero_serial = rollback_identity();
    zero_serial.operation_serial = 0U;

    const std::array<RollbackCase, 15> cases{{
        {"verified rollback is accepted",
         rollback_identity(), rollback_identity(),
         true, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::accept_verified_rollback},
        {"verified rollback no-op is accepted",
         rollback_identity(), rollback_identity(),
         true, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::accept_verified_rollback,
         false, true},
        {"generic uncommitted rollback success requires recovery",
         rollback_identity(), rollback_identity(),
         true, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::recovery_required,
         false, false},
        {"lost exact lease requires recovery",
         rollback_identity(), rollback_identity(),
         false, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::recovery_required},
        {"stale published runtime fence requires recovery",
         rollback_identity(), rollback_identity(),
         true, false, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::recovery_required},
        {"unverified rollback requires recovery",
         rollback_identity(), rollback_identity(),
         true, true, LifecycleOutcome::not_verified, false,
         ConfigRollbackAction::recovery_required},
        {"ambiguous rollback requires recovery",
         rollback_identity(), rollback_identity(),
         true, true, LifecycleOutcome::verified_success, true,
         ConfigRollbackAction::recovery_required},
        {"shutdown rollback requires recovery",
         rollback_identity(), rollback_identity(),
         true, true, LifecycleOutcome::shutdown, false,
         ConfigRollbackAction::recovery_required},
        {"rollback rejects candidate terminal",
         rollback_identity(), wrong_kind,
         true, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::recovery_required},
        {"rollback rejects preapply terminal",
         rollback_identity(), preapply,
         true, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::recovery_required},
        {"rollback rejects wrong serial",
         rollback_identity(), wrong_serial,
         true, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::recovery_required},
        {"rollback rejects wrong base",
         rollback_identity(), wrong_base,
         true, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::recovery_required},
        {"rollback rejects wrong target",
         rollback_identity(), wrong_target,
         true, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::recovery_required},
        {"rollback rejects missing expected identity",
         {}, rollback_identity(),
         true, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::recovery_required},
        {"rollback rejects zero observed identity",
         rollback_identity(), zero_serial,
         true, true, LifecycleOutcome::verified_success, false,
         ConfigRollbackAction::recovery_required},
    }};

    for (const auto& test : cases) {
        CAPTURE(test.name);
        ConfigRollbackEvidence evidence;
        evidence.expected_identity = test.expected_identity;
        evidence.exact_lease_owned = test.exact_lease_owned;
        evidence.published_generation_current =
            test.published_generation_current;
        evidence.terminal.observed_config_identity =
            test.observed_identity;
        evidence.terminal.outcome = test.outcome;
        evidence.terminal.commit_ambiguous = test.commit_ambiguous;
        evidence.terminal.committed = test.committed;
        evidence.terminal.candidate_noop_verified =
            test.candidate_noop_verified;
        CHECK(plan_config_rollback_terminal(evidence) == test.expected);
    }
}

TEST_CASE("config runtime terminal policy fails closed on unknown state") {
    auto candidate = verified_terminal("candidate");
    candidate.observed_config_identity = candidate_identity();
    CHECK(plan_config_runtime_terminal(
              /*candidate_published=*/true, candidate) ==
          ConfigRuntimeTerminalAction::keep_active);
    CHECK(plan_config_runtime_terminal(
              /*candidate_published=*/false, candidate) ==
          ConfigRuntimeTerminalAction::fail_closed);

    auto candidate_noop = candidate;
    candidate_noop.committed = false;
    candidate_noop.candidate_noop_verified = true;
    CHECK(plan_config_runtime_terminal(
              /*candidate_published=*/true, candidate_noop) ==
          ConfigRuntimeTerminalAction::keep_active);

    auto rollback = verified_terminal("rollback");
    rollback.observed_config_identity = rollback_identity();
    CHECK(plan_config_runtime_terminal(false, rollback) ==
          ConfigRuntimeTerminalAction::keep_active);

    LifecycleTerminal unchanged;
    unchanged.outcome = LifecycleOutcome::not_verified;
    unchanged.committed = false;
    unchanged.commit_ambiguous = false;
    unchanged.previous_generation_certainly_retained = true;
    unchanged.observed_config_identity = candidate_identity();
    CHECK(plan_config_runtime_terminal(false, unchanged) ==
          ConfigRuntimeTerminalAction::keep_active);

    auto ambiguous = rollback;
    ambiguous.commit_ambiguous = true;
    CHECK(plan_config_runtime_terminal(false, ambiguous) ==
          ConfigRuntimeTerminalAction::fail_closed);

    auto unverified = rollback;
    unverified.outcome = LifecycleOutcome::not_verified;
    CHECK(plan_config_runtime_terminal(false, unverified) ==
          ConfigRuntimeTerminalAction::fail_closed);

    LifecycleTerminal shutdown;
    shutdown.outcome = LifecycleOutcome::shutdown;
    CHECK(plan_config_runtime_terminal(false, shutdown) ==
          ConfigRuntimeTerminalAction::shutdown);
}

TEST_CASE("stopped config bootstrap publishes running only from exact candidate proof") {
    auto candidate = verified_terminal("bootstrap candidate");
    candidate.observed_config_identity = candidate_identity();
    CHECK(plan_config_bootstrap_terminal(
              /*candidate_published=*/true, candidate) ==
          ConfigBootstrapTerminalAction::keep_running);

    auto candidate_noop = candidate;
    candidate_noop.committed = false;
    candidate_noop.candidate_noop_verified = true;
    CHECK(plan_config_bootstrap_terminal(true, candidate_noop) ==
          ConfigBootstrapTerminalAction::keep_running);

    // The router candidate may be exact while the staged ConfigStore CAS is
    // rejected. There is no active-runtime rollback generation for a stopped
    // bootstrap, so this is recovery-required rather than stopped.
    CHECK(plan_config_bootstrap_terminal(false, candidate) ==
          ConfigBootstrapTerminalAction::fail_closed);

    LifecycleTerminal unchanged;
    unchanged.outcome = LifecycleOutcome::not_verified;
    unchanged.committed = false;
    unchanged.commit_ambiguous = false;
    unchanged.previous_generation_certainly_retained = true;
    unchanged.observed_config_identity = candidate_identity();
    CHECK(plan_config_bootstrap_terminal(false, unchanged) ==
          ConfigBootstrapTerminalAction::restore_stopped);

    CHECK(plan_config_bootstrap_terminal(true, unchanged) ==
          ConfigBootstrapTerminalAction::fail_closed);

    auto ambiguous = candidate;
    ambiguous.commit_ambiguous = true;
    CHECK(plan_config_bootstrap_terminal(false, ambiguous) ==
          ConfigBootstrapTerminalAction::fail_closed);

    auto committed_unverified = candidate;
    committed_unverified.outcome = LifecycleOutcome::not_verified;
    CHECK(plan_config_bootstrap_terminal(
              false, committed_unverified) ==
          ConfigBootstrapTerminalAction::fail_closed);

    auto wrong_identity = candidate;
    wrong_identity.observed_config_identity = rollback_identity();
    CHECK(plan_config_bootstrap_terminal(true, wrong_identity) ==
          ConfigBootstrapTerminalAction::fail_closed);

    LifecycleTerminal shutdown;
    shutdown.outcome = LifecycleOutcome::shutdown;
    CHECK(plan_config_bootstrap_terminal(false, shutdown) ==
          ConfigBootstrapTerminalAction::shutdown);
}

TEST_CASE("urltest candidate publishes only from the exact verified terminal") {
    UrltestCandidateEvidence evidence;
    evidence.exact_lease_owned = true;
    evidence.runtime_generation_current = true;
    evidence.manager_generation_current = true;
    evidence.exact_rollback_available = true;
    evidence.terminal = verified_terminal("urltest candidate");

    CHECK(plan_urltest_candidate_terminal(evidence) ==
          UrltestCandidateAction::publish_candidate);

    // A newer probe may finish while the private worker is running. The
    // verified kernel candidate must then roll back instead of publishing a
    // stale manager cursor.
    evidence.manager_generation_current = false;
    CHECK(plan_urltest_candidate_terminal(evidence) ==
          UrltestCandidateAction::begin_exact_rollback);

    evidence.manager_generation_current = true;
    evidence.runtime_generation_current = false;
    CHECK(plan_urltest_candidate_terminal(evidence) ==
          UrltestCandidateAction::recovery_required);
}

TEST_CASE("urltest candidate distinguishes clean pre-COMMIT rejection from rollback") {
    UrltestCandidateEvidence evidence;
    evidence.exact_lease_owned = true;
    evidence.runtime_generation_current = true;
    evidence.manager_generation_current = true;
    evidence.exact_rollback_available = true;

    evidence.terminal = unverified_terminal("stage rejected");
    evidence.terminal.commit_ambiguous = false;
    evidence.terminal.previous_generation_certainly_retained = true;
    CHECK(plan_urltest_candidate_terminal(evidence) ==
          UrltestCandidateAction::reject_runtime_unchanged);

    // Route mutation may already have committed even when firewall COMMIT was
    // never entered. The combined generation is then not the old generation.
    evidence.terminal.previous_generation_certainly_retained = false;
    CHECK(plan_urltest_candidate_terminal(evidence) ==
          UrltestCandidateAction::begin_exact_rollback);

    evidence.terminal.commit_ambiguous = true;
    CHECK(plan_urltest_candidate_terminal(evidence) ==
          UrltestCandidateAction::begin_exact_rollback);

    evidence.exact_rollback_available = false;
    CHECK(plan_urltest_candidate_terminal(evidence) ==
          UrltestCandidateAction::recovery_required);
}

TEST_CASE("urltest rollback requires exact lease generation and COMMIT proof") {
    UrltestRollbackEvidence evidence;
    evidence.exact_lease_owned = true;
    evidence.runtime_generation_current = true;
    evidence.terminal = verified_terminal("urltest rollback");
    CHECK(plan_urltest_rollback_terminal(evidence) ==
          UrltestRollbackAction::accept_verified_rollback);

    evidence.terminal.commit_ambiguous = true;
    CHECK(plan_urltest_rollback_terminal(evidence) ==
          UrltestRollbackAction::recovery_required);
    evidence.terminal.commit_ambiguous = false;
    evidence.runtime_generation_current = false;
    CHECK(plan_urltest_rollback_terminal(evidence) ==
          UrltestRollbackAction::recovery_required);
    evidence.runtime_generation_current = true;
    evidence.exact_lease_owned = false;
    CHECK(plan_urltest_rollback_terminal(evidence) ==
          UrltestRollbackAction::recovery_required);
}

TEST_CASE("urltest typed terminal keeps both public cursors private until verified commit") {
    RuntimeUrltestTerminalOrchestrator orchestrator;
    const RuntimeUrltestMetaFence fence{
        73U,
        /*delayed_cleanup_invalidated=*/true,
        /*mutation_barrier_crossed=*/true};

    const auto started = orchestrator.begin_candidate(fence);
    CHECK(started.effect_count == 1U);
    CHECK(started.effects[0] ==
          RuntimeUrltestTerminalEffect::start_candidate);
    CHECK(orchestrator.phase() ==
          RuntimeUrltestTerminalPhase::candidate_in_flight);
    CHECK(orchestrator.manager_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
    CHECK(orchestrator.firewall_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
    CHECK(orchestrator.exact_lease_owned());
    CHECK(orchestrator.meta_fence().cleanup_epoch == 73U);

    UrltestCandidateEvidence evidence;
    evidence.exact_lease_owned = true;
    evidence.runtime_generation_current = true;
    evidence.manager_generation_current = true;
    evidence.exact_rollback_available = true;
    evidence.terminal = verified_terminal("route and firewall committed");
    CHECK(orchestrator.candidate_publication_admitted(
        evidence, /*exact_route_checkpoint_verified=*/true));
    CHECK_FALSE(orchestrator.candidate_publication_admitted(
        evidence, /*exact_route_checkpoint_verified=*/false));
    const auto completed = orchestrator.complete_candidate(
        evidence,
        /*exact_route_checkpoint_verified=*/true);

    REQUIRE(completed.effect_count == 3U);
    CHECK(completed.effects[0] ==
          RuntimeUrltestTerminalEffect::
              publish_manager_and_firewall_candidate);
    CHECK(completed.effects[1] ==
          RuntimeUrltestTerminalEffect::finish_candidate_meta_tail);
    CHECK(completed.effects[2] ==
          RuntimeUrltestTerminalEffect::release_exact_lease);
    CHECK(completed.meta_cleanup_epoch == 73U);
    CHECK(orchestrator.manager_cursor() ==
          RuntimeUrltestPublishedCursor::candidate);
    CHECK(orchestrator.firewall_cursor() ==
          RuntimeUrltestPublishedCursor::candidate);
    CHECK_FALSE(orchestrator.exact_lease_owned());
    CHECK_FALSE(orchestrator.recovery_requested());
}

TEST_CASE("urltest clean pre-COMMIT rejection leaves runtime old without rollback") {
    RuntimeUrltestTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin_candidate(
                RuntimeUrltestMetaFence{91U, true, true})
                .contains(RuntimeUrltestTerminalEffect::start_candidate));

    UrltestCandidateEvidence evidence;
    evidence.exact_lease_owned = true;
    evidence.runtime_generation_current = true;
    evidence.manager_generation_current = true;
    evidence.exact_rollback_available = true;
    evidence.terminal = unverified_terminal("rejected before COMMIT");
    evidence.terminal.commit_ambiguous = false;
    evidence.terminal.previous_generation_certainly_retained = true;
    const auto completed = orchestrator.complete_candidate(
        evidence,
        /*exact_route_checkpoint_verified=*/false);

    REQUIRE(completed.effect_count == 1U);
    CHECK(completed.effects[0] ==
          RuntimeUrltestTerminalEffect::release_exact_lease);
    CHECK_FALSE(completed.contains(
        RuntimeUrltestTerminalEffect::start_exact_rollback));
    CHECK_FALSE(orchestrator.recovery_requested());
    CHECK(orchestrator.manager_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
    CHECK(orchestrator.firewall_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
}

TEST_CASE("urltest COMMIT proof without exact route checkpoint cannot publish") {
    RuntimeUrltestTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin_candidate(
                RuntimeUrltestMetaFence{103U, true, true})
                .contains(RuntimeUrltestTerminalEffect::start_candidate));

    UrltestCandidateEvidence evidence;
    evidence.exact_lease_owned = true;
    evidence.runtime_generation_current = true;
    evidence.manager_generation_current = true;
    evidence.exact_rollback_available = true;
    evidence.terminal = verified_terminal("firewall committed only");
    const auto transition = orchestrator.complete_candidate(
        evidence,
        /*exact_route_checkpoint_verified=*/false);

    REQUIRE(transition.effect_count == 1U);
    CHECK(transition.effects[0] ==
          RuntimeUrltestTerminalEffect::start_exact_rollback);
    CHECK(orchestrator.manager_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
    CHECK(orchestrator.firewall_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
    CHECK(orchestrator.exact_lease_owned());
}

TEST_CASE("urltest mutated or ambiguous candidate retains lease for exact rollback") {
    const auto check_rollback = [](
        bool previous_generation_retained,
        bool commit_ambiguous) {
        RuntimeUrltestTerminalOrchestrator orchestrator;
        REQUIRE(orchestrator.begin_candidate(
                    RuntimeUrltestMetaFence{117U, true, true})
                    .contains(
                        RuntimeUrltestTerminalEffect::start_candidate));

        UrltestCandidateEvidence evidence;
        evidence.exact_lease_owned = true;
        evidence.runtime_generation_current = true;
        evidence.manager_generation_current = true;
        evidence.exact_rollback_available = true;
        evidence.terminal = unverified_terminal("candidate not verified");
        evidence.terminal.commit_ambiguous = commit_ambiguous;
        evidence.terminal.previous_generation_certainly_retained =
            previous_generation_retained;
        const auto transition =
            orchestrator.complete_candidate(
                evidence,
                /*exact_route_checkpoint_verified=*/false);

        REQUIRE(transition.effect_count == 1U);
        CHECK(transition.effects[0] ==
              RuntimeUrltestTerminalEffect::start_exact_rollback);
        CHECK(transition.meta_cleanup_epoch == 117U);
        CHECK(orchestrator.phase() ==
              RuntimeUrltestTerminalPhase::rollback_in_flight);
        CHECK(orchestrator.exact_lease_owned());
        CHECK(orchestrator.meta_fence().cleanup_epoch == 117U);
        CHECK(orchestrator.manager_cursor() ==
              RuntimeUrltestPublishedCursor::previous);
        CHECK(orchestrator.firewall_cursor() ==
              RuntimeUrltestPublishedCursor::previous);
    };

    SUBCASE("route mutated before firewall COMMIT") {
        check_rollback(
            /*previous_generation_retained=*/false,
            /*commit_ambiguous=*/false);
    }
    SUBCASE("firewall COMMIT outcome ambiguous") {
        check_rollback(
            /*previous_generation_retained=*/false,
            /*commit_ambiguous=*/true);
    }
}

TEST_CASE("urltest verified rollback publishes old cursors and fenced Meta tail") {
    RuntimeUrltestTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin_candidate(
                RuntimeUrltestMetaFence{181U, true, true})
                .contains(RuntimeUrltestTerminalEffect::start_candidate));

    UrltestCandidateEvidence candidate;
    candidate.exact_lease_owned = true;
    candidate.runtime_generation_current = true;
    candidate.manager_generation_current = true;
    candidate.exact_rollback_available = true;
    candidate.terminal = unverified_terminal("candidate mutated route");
    candidate.terminal.commit_ambiguous = false;
    candidate.terminal.previous_generation_certainly_retained = false;
    REQUIRE(orchestrator.complete_candidate(
                candidate,
                /*exact_route_checkpoint_verified=*/false)
                .contains(
                    RuntimeUrltestTerminalEffect::start_exact_rollback));

    UrltestRollbackEvidence rollback;
    rollback.exact_lease_owned = true;
    rollback.runtime_generation_current = true;
    rollback.terminal = verified_terminal("rollback committed");
    CHECK(orchestrator.rollback_publication_admitted(
        rollback, /*exact_route_checkpoint_verified=*/true));
    CHECK_FALSE(orchestrator.rollback_publication_admitted(
        rollback, /*exact_route_checkpoint_verified=*/false));
    const auto completed = orchestrator.complete_rollback(
        rollback,
        /*exact_route_checkpoint_verified=*/true);

    REQUIRE(completed.effect_count == 3U);
    CHECK(completed.effects[0] ==
          RuntimeUrltestTerminalEffect::
              publish_manager_and_firewall_rollback);
    CHECK(completed.effects[1] ==
          RuntimeUrltestTerminalEffect::finish_rollback_meta_tail);
    CHECK(completed.effects[2] ==
          RuntimeUrltestTerminalEffect::release_exact_lease);
    CHECK(completed.meta_cleanup_epoch == 181U);
    CHECK(orchestrator.manager_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
    CHECK(orchestrator.firewall_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
    CHECK_FALSE(orchestrator.exact_lease_owned());
    CHECK_FALSE(orchestrator.recovery_requested());
}

TEST_CASE("urltest rollback manager mismatch blocks core publication and recovers") {
    RuntimeUrltestTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin_candidate(
                RuntimeUrltestMetaFence{197U, true, true})
                .contains(RuntimeUrltestTerminalEffect::start_candidate));

    UrltestCandidateEvidence candidate;
    candidate.exact_lease_owned = true;
    candidate.runtime_generation_current = true;
    candidate.manager_generation_current = true;
    candidate.exact_rollback_available = true;
    candidate.terminal = unverified_terminal("candidate ambiguous");
    candidate.terminal.commit_ambiguous = true;
    REQUIRE(orchestrator.complete_candidate(
                candidate,
                /*exact_route_checkpoint_verified=*/false)
                .contains(
                    RuntimeUrltestTerminalEffect::start_exact_rollback));

    UrltestRollbackEvidence rollback;
    rollback.exact_lease_owned = true;
    rollback.runtime_generation_current = true;
    rollback.terminal = verified_terminal("rollback committed");
    REQUIRE(orchestrator.rollback_publication_admitted(
        rollback, /*exact_route_checkpoint_verified=*/true));

    std::size_t manager_sync_calls = 0U;
    std::size_t core_publication_calls = 0U;
    const bool combined_publication =
        publish_runtime_urltest_cursor_pair(
            [&manager_sync_calls]() {
                ++manager_sync_calls;
                return false;
            },
            [&core_publication_calls]() {
                ++core_publication_calls;
            });
    CHECK_FALSE(combined_publication);
    CHECK(manager_sync_calls == 1U);
    CHECK(core_publication_calls == 0U);

    const auto failed = orchestrator.complete_rollback(
        rollback,
        /*exact_route_checkpoint_verified=*/true,
        combined_publication);
    REQUIRE(failed.effect_count == 2U);
    CHECK(failed.effects[0] ==
          RuntimeUrltestTerminalEffect::release_exact_lease);
    CHECK(failed.effects[1] ==
          RuntimeUrltestTerminalEffect::request_recovery);
    CHECK(orchestrator.manager_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
    CHECK(orchestrator.firewall_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
    CHECK_FALSE(orchestrator.exact_lease_owned());
    CHECK(orchestrator.recovery_requested());
}

TEST_CASE("urltest rollback failure releases exact lease before recovery") {
    RuntimeUrltestTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin_candidate(
                RuntimeUrltestMetaFence{211U, true, true})
                .contains(RuntimeUrltestTerminalEffect::start_candidate));

    UrltestCandidateEvidence candidate;
    candidate.exact_lease_owned = true;
    candidate.runtime_generation_current = true;
    candidate.manager_generation_current = true;
    candidate.exact_rollback_available = true;
    candidate.terminal = unverified_terminal("candidate ambiguous");
    candidate.terminal.commit_ambiguous = true;
    REQUIRE(orchestrator.complete_candidate(
                candidate,
                /*exact_route_checkpoint_verified=*/false)
                .contains(
        RuntimeUrltestTerminalEffect::start_exact_rollback));

    UrltestRollbackEvidence rollback;
    rollback.exact_lease_owned = true;
    rollback.runtime_generation_current = true;
    rollback.terminal = unverified_terminal("rollback not verified");
    const auto failed = orchestrator.complete_rollback(
        rollback,
        /*exact_route_checkpoint_verified=*/false);

    REQUIRE(failed.effect_count == 2U);
    CHECK(failed.effects[0] ==
          RuntimeUrltestTerminalEffect::release_exact_lease);
    CHECK(failed.effects[1] ==
          RuntimeUrltestTerminalEffect::request_recovery);
    CHECK(failed.position(
              RuntimeUrltestTerminalEffect::release_exact_lease) <
          failed.position(
              RuntimeUrltestTerminalEffect::request_recovery));
    CHECK_FALSE(orchestrator.exact_lease_owned());
    CHECK(orchestrator.recovery_requested());
    CHECK(orchestrator.manager_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
    CHECK(orchestrator.firewall_cursor() ==
          RuntimeUrltestPublishedCursor::previous);
}

TEST_CASE("urltest Meta cleanup fence is required before candidate worker") {
    RuntimeUrltestTerminalOrchestrator orchestrator;
    const auto rejected = orchestrator.begin_candidate(
        RuntimeUrltestMetaFence{
            313U,
            /*delayed_cleanup_invalidated=*/true,
            /*mutation_barrier_crossed=*/false});

    REQUIRE(rejected.effect_count == 2U);
    CHECK_FALSE(rejected.contains(
        RuntimeUrltestTerminalEffect::start_candidate));
    CHECK(rejected.effects[0] ==
          RuntimeUrltestTerminalEffect::release_exact_lease);
    CHECK(rejected.effects[1] ==
          RuntimeUrltestTerminalEffect::request_recovery);
    CHECK(orchestrator.phase() ==
          RuntimeUrltestTerminalPhase::complete);
    CHECK_FALSE(orchestrator.exact_lease_owned());
    CHECK(orchestrator.recovery_requested());
}
