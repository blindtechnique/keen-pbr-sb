#include "runtime_firewall_lifecycle_resolver_attempt.hpp"

#include "runtime_resolver_generation_snapshot.hpp"

#include <type_traits>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::string_view kInvalidAttemptDetail =
    "resolver lifecycle attempt identity is incomplete";
constexpr std::string_view kLostHandoffDetail =
    "resolver lifecycle completion was not published";
constexpr std::string_view kFailedCompletionDetail =
    "resolver lifecycle stream did not complete";

} // namespace

static_assert(std::is_nothrow_move_assignable_v<std::string>);
static_assert(std::is_nothrow_move_assignable_v<
              RuntimeFirewallLifecycleResolverAttempt::GenerationPtr>);

RuntimeFirewallLifecycleResolverAttemptTransition
RuntimeFirewallLifecycleResolverAttempt::prearm(
    std::string attempt_id,
    std::uint64_t stream_epoch,
    GenerationPtr generation) noexcept {
    if (phase_ !=
        RuntimeFirewallLifecycleResolverAttemptPhase::not_started) {
        return {};
    }

    if (attempt_id.empty() || stream_epoch == 0U || !generation ||
        generation->stream_epoch != stream_epoch) {
        return finish(
            false, kInvalidAttemptDetail,
            /*request_terminal_drain=*/false);
    }

    attempt_id_ = std::move(attempt_id);
    stream_epoch_ = stream_epoch;
    generation_ = std::move(generation);
    verified_ = false;
    phase_ = RuntimeFirewallLifecycleResolverAttemptPhase::armed;

    RuntimeFirewallLifecycleResolverAttemptTransition transition;
    transition.state_changed = true;
    return transition;
}

RuntimeFirewallLifecycleResolverAttemptTransition
RuntimeFirewallLifecycleResolverAttempt::complete_not_required() noexcept {
    if (phase_ != RuntimeFirewallLifecycleResolverAttemptPhase::not_started) {
        return {};
    }
    return finish(
        true, {}, /*request_terminal_drain=*/false);
}

RuntimeFirewallLifecycleResolverAttemptTransition
RuntimeFirewallLifecycleResolverAttempt::fail_before_start(
    std::string_view failure_detail) noexcept {
    if (phase_ != RuntimeFirewallLifecycleResolverAttemptPhase::not_started) {
        return {};
    }
    if (failure_detail.empty()) {
        failure_detail = kFailedCompletionDetail;
    }
    return finish(
        false, failure_detail, /*request_terminal_drain=*/false);
}

RuntimeFirewallLifecycleResolverAttemptTransition
RuntimeFirewallLifecycleResolverAttempt::complete_without_stream() noexcept {
    if (phase_ != RuntimeFirewallLifecycleResolverAttemptPhase::armed) {
        return {};
    }
    return finish(
        true, {}, /*request_terminal_drain=*/false);
}

RuntimeFirewallLifecycleResolverAttemptTransition
RuntimeFirewallLifecycleResolverAttempt::coordinator_started() noexcept {
    if (phase_ == RuntimeFirewallLifecycleResolverAttemptPhase::completed) {
        // An inline control executor may have completed the exact operation
        // before request() returned `started`. Observe the terminal without
        // issuing a second drain.
        return terminal_observation();
    }
    if (phase_ != RuntimeFirewallLifecycleResolverAttemptPhase::armed) {
        return {};
    }

    phase_ = RuntimeFirewallLifecycleResolverAttemptPhase::in_flight;
    RuntimeFirewallLifecycleResolverAttemptTransition transition;
    transition.action = RuntimeFirewallLifecycleResolverAttemptAction::
        wait_for_completion;
    transition.state_changed = true;
    return transition;
}

RuntimeFirewallLifecycleResolverAttemptTransition
RuntimeFirewallLifecycleResolverAttempt::coordinator_not_started(
    std::string_view failure_detail) noexcept {
    if (phase_ != RuntimeFirewallLifecycleResolverAttemptPhase::armed) {
        return {};
    }
    if (failure_detail.empty()) {
        failure_detail = kFailedCompletionDetail;
    }
    return finish(
        false, failure_detail, /*request_terminal_drain=*/false);
}

RuntimeFirewallLifecycleResolverAttemptTransition
RuntimeFirewallLifecycleResolverAttempt::poll(
    const RuntimeFirewallLifecycleResolverActiveFacts& facts,
    std::string_view lost_handoff_detail) noexcept {
    if (phase_ == RuntimeFirewallLifecycleResolverAttemptPhase::completed) {
        return terminal_observation();
    }
    if (phase_ != RuntimeFirewallLifecycleResolverAttemptPhase::in_flight) {
        return {};
    }

    const bool exact_active = facts.coordinator_in_flight &&
        runtime_resolver_stream_completion_is_exact(
            attempt_id_,
            stream_epoch_,
            generation_,
            facts.active_attempt_id,
            facts.active_generation);
    if (exact_active) {
        RuntimeFirewallLifecycleResolverAttemptTransition transition;
        transition.action = RuntimeFirewallLifecycleResolverAttemptAction::
            wait_for_completion;
        return transition;
    }

    if (lost_handoff_detail.empty()) {
        lost_handoff_detail = kLostHandoffDetail;
    }
    return finish(
        false, lost_handoff_detail,
        /*request_terminal_drain=*/false);
}

RuntimeFirewallLifecycleResolverAttemptTransition
RuntimeFirewallLifecycleResolverAttempt::complete(
    const RuntimeFirewallLifecycleResolverCompletionFacts& facts) noexcept {
    if (phase_ != RuntimeFirewallLifecycleResolverAttemptPhase::armed &&
        phase_ != RuntimeFirewallLifecycleResolverAttemptPhase::in_flight) {
        return {};
    }

    const bool exact_state_identity =
        facts.completed_attempt_id == attempt_id_ &&
        facts.completed_stream_epoch == stream_epoch_ &&
        facts.completed_generation.get() == generation_.get();
    const bool exact_active_identity =
        runtime_resolver_stream_completion_is_exact(
            facts.completed_attempt_id,
            facts.completed_stream_epoch,
            facts.completed_generation,
            facts.active_attempt_id,
            facts.active_generation);
    const bool verified = exact_state_identity && exact_active_identity &&
        facts.lifecycle_generation_current && facts.operation_completed &&
        facts.exit_code_zero;

    std::string_view failure_detail;
    if (!verified) {
        failure_detail = facts.failure_detail.empty()
            ? facts.default_failure_detail
            : facts.failure_detail;
        if (failure_detail.empty()) {
            failure_detail = kFailedCompletionDetail;
        }
    }

    return finish(
        verified, failure_detail,
        /*request_terminal_drain=*/true);
}

RuntimeFirewallLifecycleResolverAttemptTransition
RuntimeFirewallLifecycleResolverAttempt::finish(
    bool verified,
    std::string_view failure_detail,
    bool request_terminal_drain) noexcept {
    verified_ = verified;
    phase_ = RuntimeFirewallLifecycleResolverAttemptPhase::completed;

    RuntimeFirewallLifecycleResolverAttemptTransition transition;
    transition.action = RuntimeFirewallLifecycleResolverAttemptAction::
        continue_terminal;
    transition.request_terminal_drain = request_terminal_drain;
    transition.state_changed = true;
    transition.verified = verified;
    transition.failure_detail = verified
        ? std::string_view{}
        : failure_detail;
    return transition;
}

RuntimeFirewallLifecycleResolverAttemptTransition
RuntimeFirewallLifecycleResolverAttempt::terminal_observation()
    const noexcept {
    RuntimeFirewallLifecycleResolverAttemptTransition transition;
    transition.action = RuntimeFirewallLifecycleResolverAttemptAction::
        continue_terminal;
    transition.verified = verified_;
    return transition;
}

} // namespace keen_pbr3
