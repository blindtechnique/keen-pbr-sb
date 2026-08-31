#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace keen_pbr3 {

struct ResolverGenerationSnapshot;

enum class RuntimeFirewallLifecycleResolverAttemptPhase : std::uint8_t {
    not_started,
    armed,
    in_flight,
    completed,
};

enum class RuntimeFirewallLifecycleResolverAttemptAction : std::uint8_t {
    none,
    wait_for_completion,
    continue_terminal,
};

// Value-only result for the caller-owned effect adapter. A non-empty failure
// detail is borrowed from the method input or from static storage and must be
// copied by the caller before that input is destroyed.
struct RuntimeFirewallLifecycleResolverAttemptTransition final {
    RuntimeFirewallLifecycleResolverAttemptAction action{
        RuntimeFirewallLifecycleResolverAttemptAction::none};
    bool request_terminal_drain{false};
    bool state_changed{false};
    bool verified{false};
    std::string_view failure_detail;
};

struct RuntimeFirewallLifecycleResolverActiveFacts final {
    bool coordinator_in_flight{false};
    std::string_view active_attempt_id;
    std::shared_ptr<const ResolverGenerationSnapshot> active_generation;
};

struct RuntimeFirewallLifecycleResolverCompletionFacts final {
    std::string_view completed_attempt_id;
    std::uint64_t completed_stream_epoch{0U};
    std::shared_ptr<const ResolverGenerationSnapshot> completed_generation;
    std::string_view active_attempt_id;
    std::shared_ptr<const ResolverGenerationSnapshot> active_generation;
    bool lifecycle_generation_current{false};
    bool operation_completed{false};
    bool exit_code_zero{false};
    std::string_view failure_detail;
    std::string_view default_failure_detail;
};

// Per-firewall-operation resolver attempt state. This object owns no executor,
// gate, retry, incident or callback authority. The caller prepares every
// fallible value before prearm(), publishes the exact generation/active
// identity, dispatches the coordinator request and applies the returned value
// transition.
//
// `armed` deliberately precedes coordinator admission. An exact completion is
// accepted from both armed and in_flight so an inline control executor cannot
// complete before the caller records RequestResult::started.
class RuntimeFirewallLifecycleResolverAttempt final {
public:
    using GenerationPtr =
        std::shared_ptr<const ResolverGenerationSnapshot>;

    RuntimeFirewallLifecycleResolverAttemptTransition prearm(
        std::string attempt_id,
        std::uint64_t stream_epoch,
        GenerationPtr generation) noexcept;

    RuntimeFirewallLifecycleResolverAttemptTransition
    complete_not_required() noexcept;

    RuntimeFirewallLifecycleResolverAttemptTransition
    fail_before_start(std::string_view failure_detail) noexcept;

    RuntimeFirewallLifecycleResolverAttemptTransition
    complete_without_stream() noexcept;

    RuntimeFirewallLifecycleResolverAttemptTransition
    coordinator_started() noexcept;

    RuntimeFirewallLifecycleResolverAttemptTransition
    coordinator_not_started(std::string_view failure_detail) noexcept;

    RuntimeFirewallLifecycleResolverAttemptTransition poll(
        const RuntimeFirewallLifecycleResolverActiveFacts& facts,
        std::string_view lost_handoff_detail) noexcept;

    RuntimeFirewallLifecycleResolverAttemptTransition complete(
        const RuntimeFirewallLifecycleResolverCompletionFacts& facts)
        noexcept;

    RuntimeFirewallLifecycleResolverAttemptPhase phase() const noexcept {
        return phase_;
    }

    bool verified() const noexcept {
        return verified_;
    }

    std::string_view attempt_id() const noexcept {
        return attempt_id_;
    }

    std::uint64_t stream_epoch() const noexcept {
        return stream_epoch_;
    }

    const GenerationPtr& generation() const noexcept {
        return generation_;
    }

private:
    RuntimeFirewallLifecycleResolverAttemptTransition finish(
        bool verified,
        std::string_view failure_detail,
        bool request_terminal_drain) noexcept;

    RuntimeFirewallLifecycleResolverAttemptTransition terminal_observation()
        const noexcept;

    RuntimeFirewallLifecycleResolverAttemptPhase phase_{
        RuntimeFirewallLifecycleResolverAttemptPhase::not_started};
    std::string attempt_id_;
    std::uint64_t stream_epoch_{0U};
    GenerationPtr generation_;
    bool verified_{false};
};

} // namespace keen_pbr3
