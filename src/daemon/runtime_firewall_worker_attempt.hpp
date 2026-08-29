#pragma once

#include "runtime_background_point_mutation.hpp"
#include "runtime_firewall_backend_transaction.hpp"
#include "runtime_route_health_plan.hpp"
#include "runtime_recovery_policy.hpp"
#include "runtime_stop_cleanup_transaction.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

namespace keen_pbr3 {

enum class RuntimeFirewallWorkerOperationKind : std::uint8_t {
    reconcile_generation,
    // Verify/repair only the currently published generation before a caller
    // is allowed to reuse its numerical marks for a prepared candidate.
    config_preapply,
    // Apply a prepared configuration generation while Daemon keeps every
    // user-visible/config-store cursor on the previous generation. Candidate
    // and rollback are deliberately distinct operation epochs: an ambiguous
    // candidate is never replayed as a rollback or vice versa.
    config_candidate,
    config_rollback,
    urltest_candidate,
    urltest_rollback,
    keenetic_dns_candidate,
    keenetic_dns_rollback,
    // One exact, non-coalescing point mutation. The immutable target is
    // re-observed and either completed or compensated under the same retained
    // runtime-mutation lease; it never enters the generation-apply pipeline.
    exact_tcp_reset_point_mutation,
    // One bounded tagged observer/maintenance mutation. Partial per-item
    // outcomes are authoritative and return through the typed control terminal.
    background_point_mutation,
    stop_cleanup,
};

enum class RuntimeExactTcpResetPointMutationKind : std::uint8_t {
    install_then_delete_exact_flow,
    remove_rule,
};

struct RuntimeExactTcpResetPointMutationTarget final {
    RuntimeExactTcpResetPointMutationKind kind{
        RuntimeExactTcpResetPointMutationKind::remove_rule};
    std::uint64_t runtime_generation{0U};
    std::uint64_t coverage_generation{0U};
    std::uint64_t target_serial{0U};
    FirewallExactTcpResetRule rule;
    std::optional<ConntrackExactForwardedFlow> exact_flow;
    std::uint32_t owned_mask{0U};

    bool valid() const noexcept {
        if (runtime_generation == 0U || target_serial == 0U ||
            rule.source.empty() || rule.destination.empty() ||
            rule.source_port == 0U || rule.destination_port == 0U ||
            rule.full_mark == 0U) {
            return false;
        }
        if (kind == RuntimeExactTcpResetPointMutationKind::remove_rule) {
            return !exact_flow.has_value();
        }
        if (!exact_flow.has_value() || coverage_generation == 0U ||
            owned_mask == 0U) {
            return false;
        }
        const auto& flow = *exact_flow;
        return flow.family == ConntrackFlowFamily::Ipv4 &&
               flow.protocol == ConntrackFlowProtocol::Tcp &&
               flow.tcp_state ==
                   std::optional<ConntrackTcpState>{
                       ConntrackTcpState::Established} &&
               flow.destination_port == 443U && flow.mark == rule.full_mark &&
               (flow.mark & owned_mask) != 0U &&
               (flow.mark & ~owned_mask) == 0U &&
               flow.source == rule.source &&
               flow.destination == rule.destination &&
               flow.source_port == rule.source_port &&
               flow.destination_port == rule.destination_port;
    }

    bool operator==(
        const RuntimeExactTcpResetPointMutationTarget& other) const {
        return kind == other.kind &&
               runtime_generation == other.runtime_generation &&
               coverage_generation == other.coverage_generation &&
               target_serial == other.target_serial && rule == other.rule &&
               exact_flow == other.exact_flow &&
               owned_mask == other.owned_mask;
    }

    bool operator!=(
        const RuntimeExactTcpResetPointMutationTarget& other) const {
        return !(*this == other);
    }
};

struct RuntimeExactTcpResetPointMutationResult final {
    RuntimeExactTcpResetPointMutationTarget target;
    bool mutation_boundary_entered{false};
    bool flow_revalidated{false};
    FirewallExactTcpResetResult install_result{
        FirewallExactTcpResetResult::failed};
    bool conntrack_delete_attempted{false};
    ConntrackCleanupResult conntrack_delete_result{
        ConntrackCleanupResult::Failed};
    bool removal_attempted{false};
    bool removal_verified{false};

    bool fully_verified() const noexcept {
        if (target.kind ==
            RuntimeExactTcpResetPointMutationKind::remove_rule) {
            return removal_attempted && removal_verified;
        }
        return flow_revalidated &&
               install_result == FirewallExactTcpResetResult::installed &&
               conntrack_delete_attempted &&
               conntrack_delete_result == ConntrackCleanupResult::Succeeded;
    }

    bool unsafe_publication_possible() const noexcept {
        return target.kind ==
                   RuntimeExactTcpResetPointMutationKind::
                       install_then_delete_exact_flow &&
               mutation_boundary_entered && !fully_verified() &&
               !removal_verified;
    }
};

constexpr bool runtime_firewall_worker_operation_is_config_generation(
    RuntimeFirewallWorkerOperationKind kind) noexcept {
    return kind == RuntimeFirewallWorkerOperationKind::config_candidate ||
           kind == RuntimeFirewallWorkerOperationKind::config_rollback;
}

constexpr bool runtime_firewall_worker_operation_is_urltest_generation(
    RuntimeFirewallWorkerOperationKind kind) noexcept {
    return kind == RuntimeFirewallWorkerOperationKind::urltest_candidate ||
           kind == RuntimeFirewallWorkerOperationKind::urltest_rollback;
}

constexpr bool runtime_firewall_worker_operation_is_keenetic_dns_generation(
    RuntimeFirewallWorkerOperationKind kind) noexcept {
    return kind ==
               RuntimeFirewallWorkerOperationKind::keenetic_dns_candidate ||
           kind ==
               RuntimeFirewallWorkerOperationKind::keenetic_dns_rollback;
}

enum class RuntimeFirewallOwnedConntrackCleanupMode : std::uint8_t {
    none,
    // START retires marks described by the firewall candidate which has just
    // reached a verified COMMIT.
    committed_candidate,
    // A pre-apply barrier consumes immutable current-generation authorities:
    // an already-mandatory remainder is always selected, while the complete
    // pre-mutation snapshot is selected only after observing missing SNAT.
    // It must never manufacture either authority from post-COMMIT state,
    // where the same numerical marks may already have a new owner.
    exact_pre_mutation_snapshot,
};

// One fully-owned worker input. The control loop decides whether owned-SNAT
// health is part of this attempt; the worker then keeps both inspections and
// the firewall transaction inside the same externally serialized backend
// boundary.
struct RuntimeFirewallWorkerAttemptInput {
    RuntimeFirewallWorkerOperationKind operation_kind{
        RuntimeFirewallWorkerOperationKind::reconcile_generation};
    RuntimeFirewallBackendTransactionInput transaction;
    // Optional central-runtime preflight. The worker takes one coherent live
    // route/interface observation, applies it through the combined routing
    // owner, releases that owner, then publishes the immutable result through
    // the control rendezvous. Firewall COMMIT waits for that publication.
    RuntimeRouteHealthRequest route_health_request;
    // Ordinary runtime repair keeps its established deferred semantics. A
    // restart operation may request strict route convergence through the same
    // immutable worker input without teaching the worker about its caller.
    RouteReconcileMode route_reconcile_mode{
        RouteReconcileMode::DeferredRepair};
    std::shared_ptr<RuntimeRouteMutationCheckpoint>
        route_mutation_checkpoint;
    // transaction.previous_native_vpn_direct_egress_snat_selectors and
    // transaction.candidate_native_vpn_direct_egress_snat_selectors are the
    // exact control-loop snapshots used for worker-side source-flow cleanup.
    // The worker never reads or mutates Daemon's published selector cursor.
    bool inspect_owned_snat{false};
    // Captured on the control loop before the worker can enter COMMIT. For a
    // config pre-apply operation this is the complete current-generation
    // authority which becomes destructive only when the worker itself
    // observes missing SNAT. A healthy observation must not clean this broad
    // snapshot merely because a later configuration may reuse its marks.
    std::optional<OwnedConntrackCleanupSnapshot>
        pre_mutation_owned_conntrack_cleanup_snapshot;
    // Exact current-generation remainder which was already pending before
    // config pre-apply admission (for example, a bounded cleanup retry). It
    // must converge even when SNAT is healthy, but it must never be widened to
    // the broad missing-SNAT snapshot above.
    std::optional<OwnedConntrackCleanupSnapshot>
        mandatory_owned_conntrack_cleanup_snapshot;
    // Selects the only snapshot authority which may be used after the worker's
    // verified observation/transaction boundary. The worker performs the
    // bounded cleanup attempt so the control loop never runs conntrack CLI.
    RuntimeFirewallOwnedConntrackCleanupMode owned_conntrack_cleanup_mode{
        RuntimeFirewallOwnedConntrackCleanupMode::none};
    std::optional<RuntimeExactTcpResetPointMutationTarget>
        exact_tcp_reset_point_target;
    std::optional<RuntimeBackgroundPointMutationTarget>
        background_point_mutation_target;
};

struct RuntimeFirewallWorkerRoutePreparation {
    bool required{false};
    bool observation_succeeded{false};
    std::optional<RuntimeRouteMutationAck> worker_mutation_ack;
    std::string worker_mutation_failure_detail;
    bool checkpoint_published{false};
    // Control-loop acknowledgement of the already-completed worker mutation.
    // The control side performs publication/fence checks only; it does not
    // write routes or policy rules.
    std::optional<RuntimeRouteMutationAck> mutation_ack;
    RuntimeRouteHealthFailure observation_failure;
};

enum class RuntimeFirewallWorkerInspectionFailureKind : std::uint8_t {
    none,
    standard_exception,
    unknown_exception,
};

struct RuntimeFirewallWorkerInspectionFailure {
    RuntimeFirewallWorkerInspectionFailureKind kind{
        RuntimeFirewallWorkerInspectionFailureKind::none};
    std::string message;

    bool failed() const noexcept {
        return kind != RuntimeFirewallWorkerInspectionFailureKind::none;
    }
};

struct RuntimeFirewallWorkerOwnedSnatObservation {
    bool attempted{false};
    std::optional<OwnedSnatState> state;
    RuntimeFirewallWorkerInspectionFailure failure;
};

struct RuntimeFirewallWorkerForwardUdpRejectObservation {
    bool attempted{false};
    std::optional<OwnedForwardUdpRejectState> state;
    RuntimeFirewallWorkerInspectionFailure failure;
};

struct RuntimeFirewallWorkerFastnatObservation {
    bool attempted{false};
    // Absent means the Meta policy did not request a FastNAT observation, or
    // that the exact observation threw. Never substitute a permissive value.
    std::optional<bool> disabled_or_unavailable;
    RuntimeFirewallWorkerInspectionFailure failure;
};

struct RuntimeFirewallWorkerSourceConntrackCleanup {
    bool attempted{false};
    // Exact symmetric difference of the previous and known-committed
    // source/interface selector sets. Retained even when the bounded backend
    // cleanup fails so control publication can report or retry precisely.
    std::vector<std::string> affected_source_cidrs;
    ConntrackSourceCleanupSummary summary;
    RuntimeFirewallWorkerInspectionFailure failure;
};

struct RuntimeFirewallWorkerOwnedConntrackCleanup {
    bool attempted{false};
    std::optional<OwnedConntrackCleanupSnapshot> snapshot;
    ConntrackCleanupSummary summary;
    RuntimeFirewallWorkerInspectionFailure failure;
};

// Durable terminal value for one admitted backend attempt. No field refers to
// Daemon or another control-loop object, so this value may remain in a worker
// mailbox until the control loop (or shutdown drain) consumes it.
struct RuntimeFirewallWorkerAttemptResult {
    RuntimeFirewallWorkerOperationKind operation_kind{
        RuntimeFirewallWorkerOperationKind::reconcile_generation};
    RuntimeFirewallOwnedConntrackCleanupMode owned_conntrack_cleanup_mode{
        RuntimeFirewallOwnedConntrackCleanupMode::none};
    // Both pre-apply authorities are validated independently against the
    // immutable transaction generation and fwmark mask. An absent mandatory
    // authority means there is no already-pending cleanup; an authoritative
    // empty mark set is likewise a successful no-op.
    bool missing_snat_cleanup_authority_valid{false};
    bool mandatory_cleanup_authority_valid{false};
    bool exact_cleanup_authority_valid{false};
    bool exact_cleanup_required{false};
    RuntimeFirewallWorkerRoutePreparation route_preparation;
    bool transaction_executed{false};
    RuntimeFirewallBackendTransactionResult transaction;

    bool owned_snat_inspection_required{false};
    RuntimeFirewallWorkerOwnedSnatObservation owned_snat_before;
    RuntimeFirewallWorkerOwnedSnatObservation owned_snat_after;
    // Immutable copy of the control-loop snapshot above. A finalizer must not
    // manufacture a replacement after COMMIT, where numerical marks may
    // already belong to a different runtime generation.
    std::optional<OwnedConntrackCleanupSnapshot>
        pre_mutation_owned_conntrack_cleanup_snapshot;
    std::optional<OwnedConntrackCleanupSnapshot>
        mandatory_owned_conntrack_cleanup_snapshot;
    // The only snapshot authorized for this attempt after the owned-SNAT
    // observation: mandatory-only while healthy, or the union with the broad
    // pre-mutation snapshot after a missing observation.
    std::optional<OwnedConntrackCleanupSnapshot>
        selected_owned_conntrack_cleanup_snapshot;

    std::uint64_t meta_publication_epoch_before{0U};
    std::uint64_t meta_publication_epoch_after{0U};
    RuntimeFirewallWorkerForwardUdpRejectObservation
        forward_udp_reject_after_commit;
    // The preflight value consumed while preparing the activation plan.
    RuntimeFirewallWorkerFastnatObservation fastnat;
    // A separate verification after COMMIT was entered. It is sampled only
    // for a transaction which retained a Meta activation plan and never
    // overwrites the preflight evidence above.
    RuntimeFirewallWorkerFastnatObservation fastnat_after_commit;
    // Populated only after transaction.committed() proves that the candidate
    // selector set returned from COMMIT is authoritative. Merely entering an
    // ambiguous COMMIT boundary never grants destructive cleanup authority.
    RuntimeFirewallWorkerSourceConntrackCleanup
        native_direct_egress_source_cleanup;
    RuntimeFirewallWorkerOwnedConntrackCleanup
        post_commit_owned_conntrack_cleanup;
    // STOP uses the same durable worker mailbox/lease as apply operations,
    // but its monotonic owned-state deletion has a distinct typed result.
    std::shared_ptr<const RuntimeStopCleanupResult> stop_cleanup;
    std::shared_ptr<const RuntimeExactTcpResetPointMutationResult>
        exact_tcp_reset_point_mutation;
    std::shared_ptr<const RuntimeBackgroundPointMutationResult>
        background_point_mutation;

    // This proof is intentionally based only on whether COMMIT was entered.
    // A changed publication epoch strengthens ambiguity, but an unchanged one
    // cannot make an entered backend command safe to replay.
    bool previous_generation_certainly_retained() const noexcept {
        return !transaction.commit_entered;
    }

    bool config_preapply_verified() const noexcept {
        if (operation_kind !=
                RuntimeFirewallWorkerOperationKind::config_preapply ||
             owned_conntrack_cleanup_mode !=
                 RuntimeFirewallOwnedConntrackCleanupMode::
                     exact_pre_mutation_snapshot ||
             !exact_cleanup_authority_valid ||
             !owned_snat_inspection_required ||
             !owned_snat_before.attempted ||
             (owned_snat_before.state !=
                  std::optional<OwnedSnatState>{OwnedSnatState::healthy} &&
              owned_snat_before.state !=
                  std::optional<OwnedSnatState>{OwnedSnatState::missing}) ||
             owned_snat_before.failure.failed() ||
             !owned_snat_after.attempted ||
             owned_snat_after.state !=
                 std::optional<OwnedSnatState>{OwnedSnatState::healthy} ||
            owned_snat_after.failure.failed() ||
            (transaction_executed && !transaction.committed())) {
            return false;
        }
        if (!exact_cleanup_required) {
            return true;
        }
        if (!selected_owned_conntrack_cleanup_snapshot.has_value() ||
            !selected_owned_conntrack_cleanup_snapshot->valid()) {
            return false;
        }
        return post_commit_owned_conntrack_cleanup.attempted &&
               post_commit_owned_conntrack_cleanup.snapshot.has_value() &&
               owned_conntrack_cleanup_snapshot_equal(
                   *post_commit_owned_conntrack_cleanup.snapshot,
                   *selected_owned_conntrack_cleanup_snapshot) &&
               !post_commit_owned_conntrack_cleanup.failure.failed() &&
               !post_commit_owned_conntrack_cleanup.summary
                    .command_unavailable &&
               post_commit_owned_conntrack_cleanup.summary.failed == 0U &&
               post_commit_owned_conntrack_cleanup.summary.skipped == 0U &&
               post_commit_owned_conntrack_cleanup.summary
                    .remaining_marks.empty();
    }
};

static_assert(
    std::is_nothrow_move_constructible_v<
        RuntimeFirewallWorkerAttemptResult>,
    "a normal worker result must enter its preallocated publication slot "
    "without opening a post-COMMIT exception gap");

using RuntimeFirewallWorkerAttemptResultPtr =
    std::shared_ptr<const RuntimeFirewallWorkerAttemptResult>;

// Injectable execution seam for the durable production adapter below. The
// callback is invoked only after one shared holder has allocated both its
// conservative commit-entered result and separate exact-result storage. Any
// exception which escapes the callback leaves the conservative result intact.
using RuntimeFirewallWorkerAttemptRunner =
    std::function<RuntimeFirewallWorkerAttemptResult()>;

struct RuntimeRouteWorkerMutationResult final {
    RuntimeRouteMutationAck ack{RuntimeRouteMutationAck::mutation_failed};
    std::string failure_detail;
};

using RuntimeRouteWorkerMutationRunner = std::function<
    RuntimeRouteWorkerMutationResult(
        const RuntimeRouteHealthPlan&, RouteReconcileMode)>;

// Execute route/link observation and the combined route/rule mutation in the
// worker before invoking the existing firewall runner. The mutation runner
// must release its routing-owner lease before returning: this function then
// waits for a control-only publication acknowledgement without any backend
// mutex held.
RuntimeFirewallWorkerAttemptResult
execute_runtime_firewall_worker_attempt_with_route_preparation(
    const RuntimeFirewallWorkerAttemptInput& input,
    RuntimeRouteHealthServices& route_health_services,
    RuntimeRouteWorkerMutationRunner run_route_mutation,
    RuntimeFirewallWorkerAttemptRunner run_firewall_attempt);

// Execute all blocking observations and the transaction once. The caller
// owns the global firewall/conntrack/netlink serialization barrier. Backend
// exceptions are converted to typed result fields; no observation is replayed
// inside this function.
RuntimeFirewallWorkerAttemptResult execute_runtime_firewall_worker_attempt(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    MetaUdp443ActivationBackendServices& meta_services);

RuntimeFirewallWorkerAttemptResult execute_runtime_firewall_worker_attempt(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    MetaUdp443ActivationBackendServices& meta_services,
    ConntrackManager& conntrack_manager);

// Production adapter. Both FastNAT observations use the same SystemMeta
// service instance; the post-COMMIT verification remains distinct from the
// value consumed by Meta preflight.
RuntimeFirewallWorkerAttemptResult execute_runtime_firewall_worker_attempt(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    ConntrackManager& conntrack_manager,
    NetlinkManager& netlink);

// Allocate and fully initialize the mailbox-owned holder before the backend
// callback may enter COMMIT. A normal typed result is move-constructed into
// separate inline storage; it never overwrites the conservative value. If an
// unexpected exception escapes after an unknown backend boundary, return the
// original commit-entered value instead of exposing an exception-only terminal
// which could permit replay of the same operation.
RuntimeFirewallWorkerAttemptResultPtr
execute_runtime_firewall_worker_attempt_durable(
    const RuntimeFirewallWorkerAttemptInput& input,
    RuntimeFirewallWorkerAttemptRunner run_attempt);

RuntimeFirewallWorkerAttemptResultPtr
execute_runtime_firewall_worker_attempt_durable_with_route_preparation(
    const RuntimeFirewallWorkerAttemptInput& input,
    RuntimeRouteHealthServices& route_health_services,
    RuntimeRouteWorkerMutationRunner run_route_mutation,
    RuntimeFirewallWorkerAttemptRunner run_firewall_attempt);

RuntimeFirewallWorkerAttemptResultPtr
execute_runtime_firewall_worker_attempt_durable(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    MetaUdp443ActivationBackendServices& meta_services);

RuntimeFirewallWorkerAttemptResultPtr
execute_runtime_firewall_worker_attempt_durable(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    MetaUdp443ActivationBackendServices& meta_services,
    ConntrackManager& conntrack_manager);

RuntimeFirewallWorkerAttemptResultPtr
execute_runtime_firewall_worker_attempt_durable(
    const RuntimeFirewallWorkerAttemptInput& input,
    Firewall& firewall,
    ConntrackManager& conntrack_manager,
    NetlinkManager& netlink);

} // namespace keen_pbr3
