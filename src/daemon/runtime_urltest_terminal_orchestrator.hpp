#pragma once

#include "runtime_urltest_terminal_policy.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace keen_pbr3 {

// Exact proof that delayed Meta UDP/443 cleanup from the published
// generation cannot race a private URLTEST candidate or its rollback. The
// epoch is retained through both phases and is also the fence for the
// terminal Meta tail.
struct RuntimeUrltestMetaFence final {
    std::uint64_t cleanup_epoch{0U};
    bool delayed_cleanup_invalidated{false};
    bool mutation_barrier_crossed{false};

    constexpr bool valid() const noexcept {
        return cleanup_epoch != 0U && delayed_cleanup_invalidated &&
               mutation_barrier_crossed;
    }
};

enum class RuntimeUrltestTerminalPhase : std::uint8_t {
    not_started,
    candidate_in_flight,
    rollback_in_flight,
    complete,
};

enum class RuntimeUrltestPublishedCursor : std::uint8_t {
    previous,
    candidate,
};

// Publication of the manager cursor and FirewallState is one effect. Splitting
// it into two effects would make a half-published selection representable.
enum class RuntimeUrltestTerminalEffect : std::uint8_t {
    start_candidate,
    publish_manager_and_firewall_candidate,
    start_exact_rollback,
    publish_manager_and_firewall_rollback,
    finish_candidate_meta_tail,
    finish_rollback_meta_tail,
    release_exact_lease,
    request_recovery,
};

struct RuntimeUrltestTerminalTransition final {
    std::array<RuntimeUrltestTerminalEffect, 4U> effects{};
    std::size_t effect_count{0U};
    std::uint64_t meta_cleanup_epoch{0U};

    constexpr bool contains(
        RuntimeUrltestTerminalEffect effect) const noexcept {
        for (std::size_t index = 0U; index < effect_count; ++index) {
            if (effects[index] == effect) return true;
        }
        return false;
    }

    constexpr std::size_t position(
        RuntimeUrltestTerminalEffect effect) const noexcept {
        for (std::size_t index = 0U; index < effect_count; ++index) {
            if (effects[index] == effect) return index;
        }
        return effect_count;
    }
};

// The manager generation fence is the sole fallible cursor publication step.
// CorePublication callbacks contain only no-throw swaps/scalar stores and may
// run only after that fence accepts the exact manager generation. Keeping this
// seam executable prevents rollback from reporting success with divergent
// manager and FirewallState cursors.
template <typename ManagerSync, typename CorePublication>
bool publish_runtime_urltest_cursor_pair(
    ManagerSync&& synchronize_manager,
    CorePublication&& publish_core) noexcept {
    try {
        if (!std::forward<ManagerSync>(synchronize_manager)()) {
            return false;
        }
        std::forward<CorePublication>(publish_core)();
        return true;
    } catch (...) {
        return false;
    }
}

// Small executable seam for the terminal ordering owned by Daemon. It keeps
// both public cursors on the previous child while a worker is in flight,
// retains the exact lease across candidate -> rollback, and makes recovery
// unrepresentable before that lease has been released.
class RuntimeUrltestTerminalOrchestrator final {
public:
    RuntimeUrltestTerminalTransition begin_candidate(
        RuntimeUrltestMetaFence meta_fence) noexcept {
        RuntimeUrltestTerminalTransition transition;
        transition.meta_cleanup_epoch = meta_fence.cleanup_epoch;
        if (phase_ != RuntimeUrltestTerminalPhase::not_started ||
            !exact_lease_owned_ || !meta_fence.valid()) {
            release_then_recover(transition);
            return transition;
        }

        meta_fence_ = meta_fence;
        phase_ = RuntimeUrltestTerminalPhase::candidate_in_flight;
        append(
            transition,
            RuntimeUrltestTerminalEffect::start_candidate);
        return transition;
    }

    RuntimeUrltestTerminalTransition complete_candidate(
        const UrltestCandidateEvidence& evidence,
        bool exact_route_checkpoint_verified,
        bool combined_publication_succeeded = true) noexcept {
        RuntimeUrltestTerminalTransition transition;
        transition.meta_cleanup_epoch = meta_fence_.cleanup_epoch;
        if (phase_ != RuntimeUrltestTerminalPhase::candidate_in_flight ||
            !meta_fence_.valid()) {
            release_then_recover(transition);
            return transition;
        }
        if (!evidence.exact_lease_owned || !exact_lease_owned_) {
            release_then_recover(transition);
            return transition;
        }

        auto action = plan_urltest_candidate_terminal(evidence);
        if (action == UrltestCandidateAction::publish_candidate &&
            exact_route_checkpoint_verified &&
            combined_publication_succeeded) {
            manager_cursor_ = RuntimeUrltestPublishedCursor::candidate;
            firewall_cursor_ = RuntimeUrltestPublishedCursor::candidate;
            append(
                transition,
                RuntimeUrltestTerminalEffect::
                    publish_manager_and_firewall_candidate);
            append(
                transition,
                RuntimeUrltestTerminalEffect::finish_candidate_meta_tail);
            release(transition);
            phase_ = RuntimeUrltestTerminalPhase::complete;
            return transition;
        }

        if (action == UrltestCandidateAction::publish_candidate) {
            action = evidence.exact_rollback_available
                ? UrltestCandidateAction::begin_exact_rollback
                : UrltestCandidateAction::recovery_required;
        }
        if (action == UrltestCandidateAction::reject_runtime_unchanged) {
            release(transition);
            phase_ = RuntimeUrltestTerminalPhase::complete;
            return transition;
        }
        if (action == UrltestCandidateAction::begin_exact_rollback &&
            exact_lease_owned_) {
            phase_ = RuntimeUrltestTerminalPhase::rollback_in_flight;
            append(
                transition,
                RuntimeUrltestTerminalEffect::start_exact_rollback);
            return transition;
        }

        release_then_recover(transition);
        return transition;
    }

    bool candidate_publication_admitted(
        const UrltestCandidateEvidence& evidence,
        bool exact_route_checkpoint_verified) const noexcept {
        return phase_ ==
                   RuntimeUrltestTerminalPhase::candidate_in_flight &&
               meta_fence_.valid() && exact_lease_owned_ &&
               evidence.exact_lease_owned &&
               exact_route_checkpoint_verified &&
               plan_urltest_candidate_terminal(evidence) ==
                   UrltestCandidateAction::publish_candidate;
    }

    RuntimeUrltestTerminalTransition complete_rollback(
        const UrltestRollbackEvidence& evidence,
        bool exact_route_checkpoint_verified,
        bool combined_publication_succeeded = true) noexcept {
        RuntimeUrltestTerminalTransition transition;
        transition.meta_cleanup_epoch = meta_fence_.cleanup_epoch;
        if (phase_ != RuntimeUrltestTerminalPhase::rollback_in_flight ||
            !meta_fence_.valid()) {
            release_then_recover(transition);
            return transition;
        }
        if (!evidence.exact_lease_owned || !exact_lease_owned_) {
            release_then_recover(transition);
            return transition;
        }

        const bool rollback_verified =
            plan_urltest_rollback_terminal(evidence) ==
                UrltestRollbackAction::accept_verified_rollback &&
            exact_route_checkpoint_verified &&
            combined_publication_succeeded;
        if (!rollback_verified) {
            release_then_recover(transition);
            return transition;
        }

        manager_cursor_ = RuntimeUrltestPublishedCursor::previous;
        firewall_cursor_ = RuntimeUrltestPublishedCursor::previous;
        append(
            transition,
            RuntimeUrltestTerminalEffect::
                publish_manager_and_firewall_rollback);
        append(
            transition,
            RuntimeUrltestTerminalEffect::finish_rollback_meta_tail);
        release(transition);
        phase_ = RuntimeUrltestTerminalPhase::complete;
        return transition;
    }

    bool rollback_publication_admitted(
        const UrltestRollbackEvidence& evidence,
        bool exact_route_checkpoint_verified) const noexcept {
        return phase_ ==
                   RuntimeUrltestTerminalPhase::rollback_in_flight &&
               meta_fence_.valid() && exact_lease_owned_ &&
               evidence.exact_lease_owned &&
               exact_route_checkpoint_verified &&
               plan_urltest_rollback_terminal(evidence) ==
                   UrltestRollbackAction::accept_verified_rollback;
    }

    constexpr RuntimeUrltestTerminalPhase phase() const noexcept {
        return phase_;
    }

    constexpr RuntimeUrltestPublishedCursor manager_cursor() const noexcept {
        return manager_cursor_;
    }

    constexpr RuntimeUrltestPublishedCursor firewall_cursor() const noexcept {
        return firewall_cursor_;
    }

    constexpr bool exact_lease_owned() const noexcept {
        return exact_lease_owned_;
    }

    constexpr bool recovery_requested() const noexcept {
        return recovery_requested_;
    }

    constexpr const RuntimeUrltestMetaFence& meta_fence() const noexcept {
        return meta_fence_;
    }

private:
    static constexpr void append(
        RuntimeUrltestTerminalTransition& transition,
        RuntimeUrltestTerminalEffect effect) noexcept {
        if (transition.effect_count < transition.effects.size()) {
            transition.effects[transition.effect_count++] = effect;
        }
    }

    void release(RuntimeUrltestTerminalTransition& transition) noexcept {
        if (!exact_lease_owned_) return;
        exact_lease_owned_ = false;
        append(
            transition,
            RuntimeUrltestTerminalEffect::release_exact_lease);
    }

    void release_then_recover(
        RuntimeUrltestTerminalTransition& transition) noexcept {
        release(transition);
        phase_ = RuntimeUrltestTerminalPhase::complete;
        recovery_requested_ = true;
        append(
            transition,
            RuntimeUrltestTerminalEffect::request_recovery);
    }

    RuntimeUrltestTerminalPhase phase_{
        RuntimeUrltestTerminalPhase::not_started};
    RuntimeUrltestPublishedCursor manager_cursor_{
        RuntimeUrltestPublishedCursor::previous};
    RuntimeUrltestPublishedCursor firewall_cursor_{
        RuntimeUrltestPublishedCursor::previous};
    RuntimeUrltestMetaFence meta_fence_;
    bool exact_lease_owned_{true};
    bool recovery_requested_{false};
};

} // namespace keen_pbr3
