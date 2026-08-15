#include "ndms_native_reconcile_barrier.hpp"

#include <limits>

namespace keen_pbr3 {

std::uint64_t next_ndms_native_reconcile_ticket_serial(
    const std::uint64_t current) noexcept {
    auto next = current + 1U;
    if (next == 0U) ++next;
    return next;
}

NdmsNativeReconcileBarrierSnapshot
NdmsNativeReconcileBarrier::snapshot() const {
    NdmsNativeReconcileBarrierSnapshot result;
    result.state = state_;
    result.apply_available = false;
    result.ticket = ticket_;
    result.accepted_observation_generation =
        accepted_observation_generation_;
    result.accepted_observation_epoch = accepted_observation_epoch_;
    result.blockers = {
        NdmsNativeReconcileBarrierBlocker::mutation_release_disabled,
        NdmsNativeReconcileBarrierBlocker::allocator_range_unfenced,
    };

    switch (state_) {
    case NdmsNativeReconcileBarrierState::dormant:
    case NdmsNativeReconcileBarrierState::converged:
        break;
    case NdmsNativeReconcileBarrierState::awaiting_catalog:
        if (catalog_not_fresh_observed_) {
            result.blockers.push_back(
                NdmsNativeReconcileBarrierBlocker::catalog_not_fresh);
        }
        result.blockers.push_back(
            NdmsNativeReconcileBarrierBlocker::
                post_invalidation_catalog_pending);
        if (target_post_state_unverified_) {
            result.blockers.push_back(
                NdmsNativeReconcileBarrierBlocker::
                    target_post_state_unverified);
        }
        break;
    case NdmsNativeReconcileBarrierState::awaiting_firewall:
        result.blockers.push_back(
            NdmsNativeReconcileBarrierBlocker::firewall_commit_pending);
        break;
    case NdmsNativeReconcileBarrierState::stale:
        result.blockers.push_back(
            stale_due_to_runtime_generation_
                ? NdmsNativeReconcileBarrierBlocker::
                      runtime_generation_changed
                : NdmsNativeReconcileBarrierBlocker::ticket_superseded);
        break;
    case NdmsNativeReconcileBarrierState::failed:
        result.blockers.push_back(
            NdmsNativeReconcileBarrierBlocker::reconcile_failed);
        break;
    }
    return result;
}

std::optional<NdmsNativeReconcileTicket>
NdmsNativeReconcileBarrier::arm(
    const std::uint64_t expected_runtime_generation,
    const NdmsCatalogSnapshot& baseline) {
    const bool authoritative_baseline =
        baseline.status == NdmsCatalogCacheStatus::fresh &&
        baseline.observation_generation != 0U &&
        baseline.observation_epoch == baseline.invalidation_epoch;
    if (expected_runtime_generation == 0U || !authoritative_baseline ||
        baseline.invalidation_epoch ==
            std::numeric_limits<std::uint64_t>::max()) {
        return std::nullopt;
    }

    next_ticket_serial_ =
        next_ndms_native_reconcile_ticket_serial(next_ticket_serial_);
    ticket_ = NdmsNativeReconcileTicket{
        next_ticket_serial_,
        expected_runtime_generation,
        baseline.observation_generation,
        baseline.invalidation_epoch + 1U,
    };
    state_ = NdmsNativeReconcileBarrierState::awaiting_catalog;
    accepted_observation_generation_ = 0U;
    accepted_observation_epoch_ = 0U;
    catalog_high_water_generation_ = 0U;
    catalog_high_water_epoch_ = 0U;
    catalog_invalidation_epoch_high_water_ =
        ticket_->required_invalidation_epoch;
    catalog_high_water_same_pair_recheck_allowed_ = false;
    catalog_high_water_pair_revoked_ = false;
    catalog_not_fresh_observed_ = false;
    target_post_state_unverified_ = false;
    stale_due_to_runtime_generation_ = false;
    return ticket_;
}

bool NdmsNativeReconcileBarrier::owns(
    const std::uint64_t ticket_serial) const noexcept {
    return ticket_.has_value() && ticket_serial != 0U &&
           ticket_->serial == ticket_serial;
}

NdmsNativeReconcileBarrierTransition
NdmsNativeReconcileBarrier::mark_stale(
    const bool runtime_generation_changed) noexcept {
    state_ = NdmsNativeReconcileBarrierState::stale;
    accepted_observation_generation_ = 0U;
    accepted_observation_epoch_ = 0U;
    stale_due_to_runtime_generation_ = runtime_generation_changed;
    return NdmsNativeReconcileBarrierTransition::stale;
}

NdmsNativeReconcileBarrierTransition
NdmsNativeReconcileBarrier::observe_catalog(
    const NdmsNativeReconcileCatalogEvidence& evidence) noexcept {
    if (!owns(evidence.ticket_serial) ||
        state_ == NdmsNativeReconcileBarrierState::dormant ||
        state_ == NdmsNativeReconcileBarrierState::converged ||
        state_ == NdmsNativeReconcileBarrierState::stale ||
        state_ == NdmsNativeReconcileBarrierState::failed) {
        return NdmsNativeReconcileBarrierTransition::no_change;
    }
    if (!evidence.runtime_active ||
        evidence.runtime_generation !=
            ticket_->expected_runtime_generation) {
        return mark_stale(/*runtime_generation_changed=*/true);
    }

    // Invalidation is independently monotonic. Seeing a later invalidation
    // revokes both the active pair and any same-pair target recheck, even when
    // the retained catalog generation/observation pair has not changed yet.
    if (evidence.invalidation_epoch != 0U) {
        if (evidence.invalidation_epoch <
            catalog_invalidation_epoch_high_water_) {
            return NdmsNativeReconcileBarrierTransition::no_change;
        }
        if (evidence.invalidation_epoch >
            catalog_invalidation_epoch_high_water_) {
            catalog_invalidation_epoch_high_water_ =
                evidence.invalidation_epoch;
            catalog_high_water_same_pair_recheck_allowed_ = false;
            catalog_high_water_pair_revoked_ = true;
            accepted_observation_generation_ = 0U;
            accepted_observation_epoch_ = 0U;
            state_ = NdmsNativeReconcileBarrierState::awaiting_catalog;
        }
    }

    // Learn a monotonic cache version even from a stale observation. A stale
    // snapshot cannot authorize progress, but it proves that an older catalog
    // must never be accepted again after the current pair is revoked.
    bool advanced_high_water = false;
    const bool structurally_versioned =
        evidence.observation_generation >
            ticket_->baseline_observation_generation &&
        evidence.observation_epoch != 0U &&
        evidence.invalidation_epoch != 0U;
    if (structurally_versioned) {
        if (catalog_high_water_generation_ != 0U &&
            (evidence.observation_generation <
                 catalog_high_water_generation_ ||
             (evidence.observation_generation ==
                  catalog_high_water_generation_ &&
              evidence.observation_epoch != catalog_high_water_epoch_))) {
            return NdmsNativeReconcileBarrierTransition::no_change;
        }
        if (evidence.observation_generation >
            catalog_high_water_generation_) {
            catalog_high_water_generation_ =
                evidence.observation_generation;
            catalog_high_water_epoch_ = evidence.observation_epoch;
            catalog_high_water_same_pair_recheck_allowed_ = false;
            catalog_high_water_pair_revoked_ = false;
            advanced_high_water = true;
        }
    }
    if (evidence.status != NdmsCatalogCacheStatus::fresh) {
        catalog_not_fresh_observed_ = true;
        catalog_high_water_same_pair_recheck_allowed_ = false;
        catalog_high_water_pair_revoked_ = true;
        state_ = NdmsNativeReconcileBarrierState::awaiting_catalog;
        accepted_observation_generation_ = 0U;
        accepted_observation_epoch_ = 0U;
        return NdmsNativeReconcileBarrierTransition::no_change;
    }

    const bool post_invalidation_observation =
        evidence.observation_generation >
            ticket_->baseline_observation_generation &&
        evidence.observation_epoch == evidence.invalidation_epoch &&
        evidence.invalidation_epoch >=
            ticket_->required_invalidation_epoch &&
        evidence.invalidation_epoch ==
            catalog_invalidation_epoch_high_water_;
    if (!post_invalidation_observation) {
        return NdmsNativeReconcileBarrierTransition::no_change;
    }
    if (!evidence.exact_target_verified) {
        target_post_state_unverified_ = true;
        catalog_high_water_same_pair_recheck_allowed_ =
            !catalog_high_water_pair_revoked_;
        state_ = NdmsNativeReconcileBarrierState::awaiting_catalog;
        accepted_observation_generation_ = 0U;
        accepted_observation_epoch_ = 0U;
        return NdmsNativeReconcileBarrierTransition::no_change;
    }

    const bool same_observation =
        state_ == NdmsNativeReconcileBarrierState::awaiting_firewall &&
        accepted_observation_generation_ ==
            evidence.observation_generation &&
        accepted_observation_epoch_ == evidence.observation_epoch;
    if (!same_observation && !advanced_high_water &&
        (!catalog_high_water_same_pair_recheck_allowed_ ||
         catalog_high_water_pair_revoked_)) {
        return NdmsNativeReconcileBarrierTransition::no_change;
    }
    accepted_observation_generation_ = evidence.observation_generation;
    accepted_observation_epoch_ = evidence.observation_epoch;
    catalog_high_water_same_pair_recheck_allowed_ = false;
    state_ = NdmsNativeReconcileBarrierState::awaiting_firewall;
    catalog_not_fresh_observed_ = false;
    target_post_state_unverified_ = false;
    return same_observation
        ? NdmsNativeReconcileBarrierTransition::no_change
        : NdmsNativeReconcileBarrierTransition::catalog_accepted;
}

NdmsNativeReconcileBarrierTransition
NdmsNativeReconcileBarrier::observe_firewall(
    const NdmsNativeReconcileFirewallEvidence& evidence) noexcept {
    if (!owns(evidence.ticket_serial) ||
        state_ == NdmsNativeReconcileBarrierState::dormant ||
        state_ == NdmsNativeReconcileBarrierState::converged ||
        state_ == NdmsNativeReconcileBarrierState::stale ||
        state_ == NdmsNativeReconcileBarrierState::failed) {
        return NdmsNativeReconcileBarrierTransition::no_change;
    }
    if (!evidence.runtime_active ||
        evidence.runtime_generation !=
            ticket_->expected_runtime_generation) {
        return mark_stale(/*runtime_generation_changed=*/true);
    }
    if (state_ != NdmsNativeReconcileBarrierState::awaiting_firewall ||
        !evidence.committed ||
        evidence.observation_generation !=
            accepted_observation_generation_ ||
        evidence.observation_epoch != accepted_observation_epoch_) {
        return NdmsNativeReconcileBarrierTransition::no_change;
    }

    state_ = NdmsNativeReconcileBarrierState::converged;
    return NdmsNativeReconcileBarrierTransition::converged;
}

NdmsNativeReconcileBarrierTransition
NdmsNativeReconcileBarrier::supersede(
    const std::uint64_t ticket_serial) noexcept {
    if (!owns(ticket_serial) ||
        state_ == NdmsNativeReconcileBarrierState::dormant ||
        state_ == NdmsNativeReconcileBarrierState::stale) {
        return NdmsNativeReconcileBarrierTransition::no_change;
    }
    return mark_stale(/*runtime_generation_changed=*/false);
}

NdmsNativeReconcileBarrierTransition
NdmsNativeReconcileBarrier::fail(
    const std::uint64_t ticket_serial) noexcept {
    if (!owns(ticket_serial) ||
        (state_ != NdmsNativeReconcileBarrierState::awaiting_catalog &&
         state_ != NdmsNativeReconcileBarrierState::awaiting_firewall)) {
        return NdmsNativeReconcileBarrierTransition::no_change;
    }
    state_ = NdmsNativeReconcileBarrierState::failed;
    accepted_observation_generation_ = 0U;
    accepted_observation_epoch_ = 0U;
    return NdmsNativeReconcileBarrierTransition::failed;
}

const char* ndms_native_reconcile_barrier_state_name(
    const NdmsNativeReconcileBarrierState state) noexcept {
    switch (state) {
    case NdmsNativeReconcileBarrierState::dormant: return "dormant";
    case NdmsNativeReconcileBarrierState::awaiting_catalog:
        return "awaiting_catalog";
    case NdmsNativeReconcileBarrierState::awaiting_firewall:
        return "awaiting_firewall";
    case NdmsNativeReconcileBarrierState::converged: return "converged";
    case NdmsNativeReconcileBarrierState::stale: return "stale";
    case NdmsNativeReconcileBarrierState::failed: return "failed";
    }
    return "unknown";
}

const char* ndms_native_reconcile_barrier_blocker_name(
    const NdmsNativeReconcileBarrierBlocker blocker) noexcept {
    switch (blocker) {
    case NdmsNativeReconcileBarrierBlocker::mutation_release_disabled:
        return "mutation_release_disabled";
    case NdmsNativeReconcileBarrierBlocker::allocator_range_unfenced:
        return "allocator_range_unfenced";
    case NdmsNativeReconcileBarrierBlocker::catalog_not_fresh:
        return "catalog_not_fresh";
    case NdmsNativeReconcileBarrierBlocker::
        post_invalidation_catalog_pending:
        return "post_invalidation_catalog_pending";
    case NdmsNativeReconcileBarrierBlocker::runtime_generation_changed:
        return "runtime_generation_changed";
    case NdmsNativeReconcileBarrierBlocker::firewall_commit_pending:
        return "firewall_commit_pending";
    case NdmsNativeReconcileBarrierBlocker::
        target_post_state_unverified:
        return "target_post_state_unverified";
    case NdmsNativeReconcileBarrierBlocker::ticket_superseded:
        return "ticket_superseded";
    case NdmsNativeReconcileBarrierBlocker::reconcile_failed:
        return "reconcile_failed";
    }
    return "unknown";
}

} // namespace keen_pbr3
