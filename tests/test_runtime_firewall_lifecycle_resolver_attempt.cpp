#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_lifecycle_resolver_attempt.hpp"
#include "../src/daemon/runtime_resolver_generation_snapshot.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {

static_assert(noexcept(
    std::declval<RuntimeFirewallLifecycleResolverAttempt&>().prearm(
        std::declval<std::string>(),
        std::uint64_t{},
        std::declval<
            RuntimeFirewallLifecycleResolverAttempt::GenerationPtr>())));
static_assert(noexcept(
    std::declval<RuntimeFirewallLifecycleResolverAttempt&>()
        .complete_without_stream()));
static_assert(noexcept(
    std::declval<RuntimeFirewallLifecycleResolverAttempt&>()
        .coordinator_started()));
static_assert(noexcept(
    std::declval<RuntimeFirewallLifecycleResolverAttempt&>().complete(
        std::declval<const
            RuntimeFirewallLifecycleResolverCompletionFacts&>())));

namespace {

using Action = RuntimeFirewallLifecycleResolverAttemptAction;
using Phase = RuntimeFirewallLifecycleResolverAttemptPhase;
using GenerationPtr =
    RuntimeFirewallLifecycleResolverAttempt::GenerationPtr;

GenerationPtr resolver_generation(
    std::uint64_t generation,
    std::uint64_t stream_epoch) {
    auto snapshot = std::make_shared<ResolverGenerationSnapshot>();
    snapshot->generation = generation;
    snapshot->stream_epoch = stream_epoch;
    snapshot->list_cache_snapshot =
        std::make_shared<ListCacheGenerationSnapshot>();
    return snapshot;
}

RuntimeFirewallLifecycleResolverAttempt armed_attempt(
    const std::string& attempt_id,
    std::uint64_t stream_epoch,
    const GenerationPtr& generation) {
    RuntimeFirewallLifecycleResolverAttempt attempt;
    const auto transition = attempt.prearm(
        attempt_id, stream_epoch, generation);
    CHECK(transition.state_changed);
    CHECK(transition.action == Action::none);
    CHECK(attempt.phase() == Phase::armed);
    return attempt;
}

RuntimeFirewallLifecycleResolverCompletionFacts exact_completion(
    const std::string& attempt_id,
    std::uint64_t stream_epoch,
    const GenerationPtr& generation) {
    RuntimeFirewallLifecycleResolverCompletionFacts facts;
    facts.completed_attempt_id = attempt_id;
    facts.completed_stream_epoch = stream_epoch;
    facts.completed_generation = generation;
    facts.active_attempt_id = attempt_id;
    facts.active_generation = generation;
    facts.lifecycle_generation_current = true;
    facts.operation_completed = true;
    facts.exit_code_zero = true;
    facts.default_failure_detail = "resolver reload failed";
    return facts;
}

} // namespace

TEST_CASE("lifecycle resolver attempt prearms one exact immutable identity") {
    const std::string attempt_id(32U, 'a');
    const auto generation = resolver_generation(7U, 11U);
    auto attempt = armed_attempt(attempt_id, 11U, generation);

    CHECK(attempt.attempt_id() == attempt_id);
    CHECK(attempt.stream_epoch() == 11U);
    CHECK(attempt.generation().get() == generation.get());
    CHECK_FALSE(attempt.verified());

    const auto duplicate = attempt.prearm(
        std::string(32U, 'b'),
        12U,
        resolver_generation(8U, 12U));
    CHECK_FALSE(duplicate.state_changed);
    CHECK(duplicate.action == Action::none);
    CHECK(attempt.attempt_id() == attempt_id);
}

TEST_CASE("invalid prearm identity fails synchronously without dispatch") {
    const auto valid_generation = resolver_generation(7U, 11U);

    RuntimeFirewallLifecycleResolverAttempt empty_id;
    auto transition = empty_id.prearm({}, 11U, valid_generation);
    CHECK(empty_id.phase() == Phase::completed);
    CHECK(transition.action == Action::continue_terminal);
    CHECK_FALSE(transition.request_terminal_drain);
    CHECK_FALSE(transition.verified);
    CHECK_FALSE(transition.failure_detail.empty());

    RuntimeFirewallLifecycleResolverAttempt zero_epoch;
    transition = zero_epoch.prearm(
        std::string(32U, 'a'), 0U, valid_generation);
    CHECK(zero_epoch.phase() == Phase::completed);
    CHECK_FALSE(transition.verified);

    RuntimeFirewallLifecycleResolverAttempt missing_generation;
    transition = missing_generation.prearm(
        std::string(32U, 'a'), 11U, nullptr);
    CHECK(missing_generation.phase() == Phase::completed);
    CHECK_FALSE(transition.verified);

    RuntimeFirewallLifecycleResolverAttempt mismatched_epoch;
    transition = mismatched_epoch.prearm(
        std::string(32U, 'a'),
        12U,
        valid_generation);
    CHECK(mismatched_epoch.phase() == Phase::completed);
    CHECK_FALSE(transition.verified);
}

TEST_CASE("empty hook arguments complete verified without a coordinator") {
    const std::string attempt_id(32U, 'c');
    const auto generation = resolver_generation(9U, 13U);
    auto attempt = armed_attempt(attempt_id, 13U, generation);

    const auto terminal = attempt.complete_without_stream();
    CHECK(terminal.action == Action::continue_terminal);
    CHECK(terminal.state_changed);
    CHECK_FALSE(terminal.request_terminal_drain);
    CHECK(terminal.verified);
    CHECK(terminal.failure_detail.empty());
    CHECK(attempt.phase() == Phase::completed);
    CHECK(attempt.verified());

    const auto duplicate = attempt.complete_without_stream();
    CHECK(duplicate.action == Action::none);
    CHECK_FALSE(duplicate.state_changed);
    CHECK_FALSE(duplicate.request_terminal_drain);
}

TEST_CASE("lifecycle with no resolver work completes without an identity") {
    RuntimeFirewallLifecycleResolverAttempt no_refresh;
    const auto verified = no_refresh.complete_not_required();
    CHECK(verified.action == Action::continue_terminal);
    CHECK(verified.state_changed);
    CHECK(verified.verified);
    CHECK_FALSE(verified.request_terminal_drain);
    CHECK(no_refresh.phase() == Phase::completed);

    RuntimeFirewallLifecycleResolverAttempt failed_start;
    const auto failed = failed_start.fail_before_start(
        "resolver generation is unavailable");
    CHECK(failed.action == Action::continue_terminal);
    CHECK(failed.state_changed);
    CHECK_FALSE(failed.verified);
    CHECK(failed.failure_detail ==
          "resolver generation is unavailable");
    CHECK_FALSE(failed.request_terminal_drain);
    CHECK(failed_start.phase() == Phase::completed);
}

TEST_CASE("coordinator admission waits while busy or rejection fail inline") {
    const std::string attempt_id(32U, 'd');
    const auto generation = resolver_generation(10U, 14U);
    auto accepted = armed_attempt(attempt_id, 14U, generation);

    const auto waiting = accepted.coordinator_started();
    CHECK(waiting.action == Action::wait_for_completion);
    CHECK(waiting.state_changed);
    CHECK_FALSE(waiting.request_terminal_drain);
    CHECK(accepted.phase() == Phase::in_flight);

    auto busy = armed_attempt(attempt_id, 14U, generation);
    const std::string detail = "resolver stream is busy";
    const auto failed = busy.coordinator_not_started(detail);
    CHECK(failed.action == Action::continue_terminal);
    CHECK(failed.state_changed);
    CHECK_FALSE(failed.request_terminal_drain);
    CHECK_FALSE(failed.verified);
    CHECK(failed.failure_detail == detail);
    CHECK(busy.phase() == Phase::completed);
}

TEST_CASE("poll waits only for the exact active identity") {
    const std::string attempt_id(32U, 'e');
    const auto generation = resolver_generation(11U, 15U);
    auto attempt = armed_attempt(attempt_id, 15U, generation);
    REQUIRE(
        attempt.coordinator_started().action ==
        Action::wait_for_completion);

    RuntimeFirewallLifecycleResolverActiveFacts active;
    active.coordinator_in_flight = true;
    active.active_attempt_id = attempt_id;
    active.active_generation = generation;
    const auto waiting = attempt.poll(active, "lost handoff");
    CHECK(waiting.action == Action::wait_for_completion);
    CHECK_FALSE(waiting.state_changed);
    CHECK(attempt.phase() == Phase::in_flight);

    // Equal scalar fields do not substitute for the exact immutable pointer.
    active.active_generation = resolver_generation(11U, 15U);
    const auto lost = attempt.poll(active, "lost handoff");
    CHECK(lost.action == Action::continue_terminal);
    CHECK(lost.state_changed);
    CHECK_FALSE(lost.request_terminal_drain);
    CHECK_FALSE(lost.verified);
    CHECK(lost.failure_detail == "lost handoff");
    CHECK(attempt.phase() == Phase::completed);

    const auto observed = attempt.poll(active, "different detail");
    CHECK(observed.action == Action::continue_terminal);
    CHECK_FALSE(observed.state_changed);
    CHECK_FALSE(observed.request_terminal_drain);
}

TEST_CASE("exact asynchronous completion verifies and requests one drain") {
    const std::string attempt_id(32U, 'f');
    const auto generation = resolver_generation(12U, 16U);
    auto attempt = armed_attempt(attempt_id, 16U, generation);
    REQUIRE(
        attempt.coordinator_started().action ==
        Action::wait_for_completion);

    const auto terminal = attempt.complete(
        exact_completion(attempt_id, 16U, generation));
    CHECK(terminal.action == Action::continue_terminal);
    CHECK(terminal.state_changed);
    CHECK(terminal.request_terminal_drain);
    CHECK(terminal.verified);
    CHECK(terminal.failure_detail.empty());
    CHECK(attempt.phase() == Phase::completed);
    CHECK(attempt.verified());

    const auto duplicate = attempt.complete(
        exact_completion(attempt_id, 16U, generation));
    CHECK(duplicate.action == Action::none);
    CHECK_FALSE(duplicate.state_changed);
    CHECK_FALSE(duplicate.request_terminal_drain);
}

TEST_CASE("inline exact completion is accepted from the prearmed phase") {
    const std::string attempt_id(32U, '1');
    const auto generation = resolver_generation(13U, 17U);
    auto attempt = armed_attempt(attempt_id, 17U, generation);

    const auto inline_terminal = attempt.complete(
        exact_completion(attempt_id, 17U, generation));
    REQUIRE(inline_terminal.request_terminal_drain);
    REQUIRE(inline_terminal.verified);

    const auto admitted = attempt.coordinator_started();
    CHECK(admitted.action == Action::continue_terminal);
    CHECK_FALSE(admitted.state_changed);
    CHECK_FALSE(admitted.request_terminal_drain);
    CHECK(admitted.verified);
    CHECK(attempt.phase() == Phase::completed);
}

TEST_CASE("completion requires every state active and result proof") {
    const std::string attempt_id(32U, '2');
    const std::string other_attempt_id(32U, '3');
    const auto generation = resolver_generation(14U, 18U);
    const auto other_pointer = resolver_generation(14U, 18U);

    auto run = [&](RuntimeFirewallLifecycleResolverCompletionFacts facts) {
        auto attempt = armed_attempt(attempt_id, 18U, generation);
        REQUIRE(
            attempt.coordinator_started().action ==
            Action::wait_for_completion);
        return attempt.complete(facts);
    };

    auto facts = exact_completion(attempt_id, 18U, generation);
    facts.completed_attempt_id = other_attempt_id;
    CHECK_FALSE(run(facts).verified);

    facts = exact_completion(attempt_id, 18U, generation);
    facts.completed_stream_epoch = 19U;
    CHECK_FALSE(run(facts).verified);

    facts = exact_completion(attempt_id, 18U, generation);
    facts.completed_generation = other_pointer;
    CHECK_FALSE(run(facts).verified);

    facts = exact_completion(attempt_id, 18U, generation);
    facts.active_attempt_id = other_attempt_id;
    CHECK_FALSE(run(facts).verified);

    facts = exact_completion(attempt_id, 18U, generation);
    facts.active_generation = other_pointer;
    CHECK_FALSE(run(facts).verified);

    facts = exact_completion(attempt_id, 18U, generation);
    facts.lifecycle_generation_current = false;
    CHECK_FALSE(run(facts).verified);

    facts = exact_completion(attempt_id, 18U, generation);
    facts.operation_completed = false;
    CHECK_FALSE(run(facts).verified);

    facts = exact_completion(attempt_id, 18U, generation);
    facts.exit_code_zero = false;
    facts.failure_detail = "hook returned exit status 1";
    const auto failed = run(facts);
    CHECK_FALSE(failed.verified);
    CHECK(failed.failure_detail == "hook returned exit status 1");
    CHECK(failed.request_terminal_drain);
}

} // namespace keen_pbr3
