#pragma once

#include "ndms_catalog_cache.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace keen_pbr3 {

// Pure, dormant groundwork for a future post-import convergence barrier.
// This module performs no RCI I/O, schedules no work, sleeps nowhere and has
// no mutation/executor hook. In particular, reaching `converged` is evidence
// about two caller-supplied completion stages, not permission to mutate NDMS.
enum class NdmsNativeReconcileBarrierState : std::uint8_t {
    dormant,
    awaiting_catalog,
    awaiting_firewall,
    converged,
    stale,
    failed,
};

enum class NdmsNativeReconcileBarrierBlocker : std::uint8_t {
    mutation_release_disabled,
    allocator_range_unfenced,
    catalog_not_fresh,
    post_invalidation_catalog_pending,
    runtime_generation_changed,
    firewall_commit_pending,
    target_post_state_unverified,
    ticket_superseded,
    reconcile_failed,
};

enum class NdmsNativeReconcileBarrierTransition : std::uint8_t {
    no_change,
    catalog_accepted,
    converged,
    stale,
    failed,
};

// Process-local ticket. It is never a credential or an API authorization
// token. The future owner must keep it inside the daemon and combine it with
// the existing runtime mutation lease before any writer can be considered.
struct NdmsNativeReconcileTicket {
    std::uint64_t serial{0};
    std::uint64_t expected_runtime_generation{0};
    std::uint64_t baseline_observation_generation{0};
    std::uint64_t required_invalidation_epoch{0};

    bool valid() const noexcept {
        return serial != 0U && expected_runtime_generation != 0U &&
               baseline_observation_generation != 0U &&
               required_invalidation_epoch != 0U;
    }
};

// Redacted post-invalidation catalog evidence. `exact_target_verified` is a
// future verifier result; the barrier intentionally does not construct it.
struct NdmsNativeReconcileCatalogEvidence {
    std::uint64_t ticket_serial{0};
    std::uint64_t runtime_generation{0};
    bool runtime_active{false};
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
    std::uint64_t observation_generation{0};
    std::uint64_t observation_epoch{0};
    std::uint64_t invalidation_epoch{0};
    bool exact_target_verified{false};
};

// Evidence from the sole future route/firewall reconciliation owner. The
// exact catalog generation/epoch pair prevents an unrelated or pre-event
// firewall completion from satisfying the ticket.
struct NdmsNativeReconcileFirewallEvidence {
    std::uint64_t ticket_serial{0};
    std::uint64_t runtime_generation{0};
    bool runtime_active{false};
    std::uint64_t observation_generation{0};
    std::uint64_t observation_epoch{0};
    bool committed{false};
};

struct NdmsNativeReconcileBarrierSnapshot {
    NdmsNativeReconcileBarrierState state{
        NdmsNativeReconcileBarrierState::dormant};
    // Hard false in this preview-only slice, including after convergence.
    bool apply_available{false};
    std::optional<NdmsNativeReconcileTicket> ticket;
    std::uint64_t accepted_observation_generation{0};
    std::uint64_t accepted_observation_epoch{0};
    std::vector<NdmsNativeReconcileBarrierBlocker> blockers;
};

// Returns the next non-zero process-local serial. Exposed so the wrap
// invariant can be unit-tested without a test-only constructor.
std::uint64_t next_ndms_native_reconcile_ticket_serial(
    std::uint64_t current) noexcept;

class NdmsNativeReconcileBarrier {
public:
    NdmsNativeReconcileBarrierSnapshot snapshot() const;

    // Arms only from a currently authoritative baseline. The required epoch
    // is the first post-invalidation epoch; additional invalidations are
    // allowed, but only an observation accepted in the then-current epoch can
    // advance the ticket. A rejected arm leaves any existing ticket intact.
    std::optional<NdmsNativeReconcileTicket> arm(
        std::uint64_t expected_runtime_generation,
        const NdmsCatalogSnapshot& baseline);

    NdmsNativeReconcileBarrierTransition observe_catalog(
        const NdmsNativeReconcileCatalogEvidence& evidence) noexcept;

    NdmsNativeReconcileBarrierTransition observe_firewall(
        const NdmsNativeReconcileFirewallEvidence& evidence) noexcept;

    // Exact-ticket terminal transitions. Completions for a replaced ticket
    // are deliberately ignored and cannot disturb its successor.
    NdmsNativeReconcileBarrierTransition supersede(
        std::uint64_t ticket_serial) noexcept;
    NdmsNativeReconcileBarrierTransition fail(
        std::uint64_t ticket_serial) noexcept;

private:
    bool owns(std::uint64_t ticket_serial) const noexcept;
    NdmsNativeReconcileBarrierTransition mark_stale(
        bool runtime_generation_changed) noexcept;

    NdmsNativeReconcileBarrierState state_{
        NdmsNativeReconcileBarrierState::dormant};
    std::optional<NdmsNativeReconcileTicket> ticket_;
    std::uint64_t next_ticket_serial_{0};
    std::uint64_t accepted_observation_generation_{0};
    std::uint64_t accepted_observation_epoch_{0};
    // Monotonic within one ticket, even when the currently accepted pair is
    // invalidated while a newer catalog/target proof is pending. Without a
    // separate high-water mark, a late older catalog could be accepted after
    // accepted_observation_* is cleared and then satisfy firewall evidence.
    std::uint64_t catalog_high_water_generation_{0};
    std::uint64_t catalog_high_water_epoch_{0};
    std::uint64_t catalog_invalidation_epoch_high_water_{0};
    bool catalog_high_water_same_pair_recheck_allowed_{false};
    bool catalog_high_water_pair_revoked_{false};
    bool catalog_not_fresh_observed_{false};
    bool target_post_state_unverified_{false};
    bool stale_due_to_runtime_generation_{false};
};

const char* ndms_native_reconcile_barrier_state_name(
    NdmsNativeReconcileBarrierState state) noexcept;
const char* ndms_native_reconcile_barrier_blocker_name(
    NdmsNativeReconcileBarrierBlocker blocker) noexcept;

} // namespace keen_pbr3
