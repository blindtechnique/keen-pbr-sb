#pragma once

#include "internal_vpn_runtime_resolution.hpp"
#include "runtime_firewall_terminal_owner.hpp"
#include "runtime_firewall_worker_attempt.hpp"
#include "runtime_firewall_lifecycle_completion.hpp"
#include "runtime_recovery_policy.hpp"

#include "../runtime/runtime_mutation_admission.hpp"
#include "../util/blocking_executor.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>

namespace keen_pbr3 {

// Domain preparation and publication remain control-loop responsibilities.
// The generic operation owner retains this opaque state only to give those
// continuations the same lifetime as the exact transport operation.
struct RuntimeFirewallOperationDomainState {
    virtual ~RuntimeFirewallOperationDomainState() = default;
};

using RuntimeFirewallDelayedWorker = RuntimeFirewallWorkerOperation<
    RuntimeFirewallWorkerAttemptInput,
    RuntimeFirewallWorkerAttemptResult>;
using RuntimeFirewallDelayedTerminalOwner = RuntimeFirewallTerminalOwner<
    RuntimeFirewallWorkerAttemptInput,
    RuntimeFirewallWorkerAttemptResult>;

// Foreground lifecycle operations keep stronger route/firewall/resolver
// semantics and retain their exact request admission through every successor.
// A typed kind avoids invalid combinations of independent start/restart flags.
enum class RuntimeFirewallLifecycleKind : std::uint8_t {
    background,
    start_from_stopped,
    restart_active,
};

constexpr bool runtime_firewall_lifecycle_is_foreground(
    RuntimeFirewallLifecycleKind kind) noexcept {
    return kind != RuntimeFirewallLifecycleKind::background;
}

constexpr bool runtime_firewall_lifecycle_is_start(
    RuntimeFirewallLifecycleKind kind) noexcept {
    return kind == RuntimeFirewallLifecycleKind::start_from_stopped;
}

constexpr bool runtime_firewall_lifecycle_is_restart(
    RuntimeFirewallLifecycleKind kind) noexcept {
    return kind == RuntimeFirewallLifecycleKind::restart_active;
}

constexpr std::size_t kRuntimeFirewallStartBoundedRetryCount = 3U;

constexpr bool runtime_firewall_start_retry_available(
    std::size_t completed_attempt) noexcept {
    return completed_attempt <
           kRuntimeFirewallStartBoundedRetryCount;
}

constexpr std::size_t
    kRuntimeFirewallStartRollbackHandoffRetryLimit = 4U;

constexpr bool runtime_firewall_start_rollback_handoff_retry_available(
    std::size_t recorded_rejections) noexcept {
    return recorded_rejections <
           kRuntimeFirewallStartRollbackHandoffRetryLimit;
}

constexpr bool runtime_firewall_restart_resolver_initially_verified(
    RuntimeFirewallLifecycleKind lifecycle_kind,
    bool resolver_refresh_required,
    bool resolver_waits_for_firewall) noexcept {
    return lifecycle_kind == RuntimeFirewallLifecycleKind::background ||
           (runtime_firewall_lifecycle_is_restart(lifecycle_kind) &&
            !resolver_refresh_required &&
            !resolver_waits_for_firewall);
}

// One exact runtime-firewall operation. Only transport/ownership state lives
// here; the Daemon-specific candidate and publication checkpoints live in the
// polymorphic domain_state retained above.
struct RuntimeFirewallOperationContext final {
    enum class SuccessorMode : std::uint8_t {
        none,
        reschedule_retry,
        defer_same_attempt,
    };

    std::shared_ptr<RuntimeFirewallOperationDomainState> domain_state;
    std::shared_ptr<RuntimeFirewallDelayedTerminalOwner> terminal_owner;
    std::shared_ptr<RuntimeFirewallDelayedWorker> worker_operation;
    std::shared_ptr<const RuntimeFirewallWorkerAttemptInput> worker_input;
    // Optional production admission already owned by the initiating caller.
    // It remains a single move-only authority until the worker mailbox or the
    // control-side terminal explicitly takes it.
    std::unique_ptr<RuntimeMutationAdmission::Lease>
        retained_mutation_lease;
    // Optional foreground waiter. It follows the same exact successor chain
    // as the pre-owned admission and is settled only by the final control-side
    // terminal (or conservatively by source abandonment).
    RuntimeFirewallLifecycleCompletion::Source lifecycle_completion;
    // Foreground lifecycle intent follows the same exact successor chain.
    RuntimeFirewallLifecycleKind lifecycle_kind{
        RuntimeFirewallLifecycleKind::background};

    RuntimeFirewallOperationClaim queued_claim;
    OwnedSnatRecovery submitted_snat_recovery;
    PreparedNativeVpnCatalogPtr prepared_native_vpn_catalog;
    OwnedSnatRecovery trailing_snat_recovery;
    PreparedNativeVpnCatalogPtr trailing_prepared_native_vpn_catalog;
    bool schedule_catalog_refresh{true};

    bool worker_succeeded{false};
    bool worker_commit_ambiguous{false};
    bool completion_captured{false};
    RuntimeFirewallOperationCompletion completion;

    SuccessorMode successor_mode{SuccessorMode::none};
    std::size_t successor_attempt{0U};
    std::uint64_t successor_runtime_generation{0U};
    bool successor_schedule_catalog_refresh{true};
    bool force_successor{false};
    // Consecutive failures before begin_worker(). Foreground lifecycle
    // operations bound this transport-only loop separately from ordinary
    // firewall retry attempts; a running worker resets the counter.
    std::size_t foreground_transport_rejections{0U};
    // The owner exhausted all bounded pre-worker transport attempts after a
    // foreground successor had already left its previous terminal context.
    // A synthetic owned terminal returns this lifecycle to Daemon so START
    // can run its normal rollback/broken finalizer instead of being settled
    // directly while runtime remains `starting`.
    bool foreground_transport_exhausted{false};
    // Preserve the exact pre-worker claim while its typed terminal is being
    // transferred. If another authoritative terminal already won the phase,
    // the watchdog drains that winner without creating a second owner.
    bool preworker_terminal_retry_pending{false};
    RuntimeFirewallOperationClaim preworker_terminal_claim;
    SuccessorMode preworker_terminal_successor_mode{SuccessorMode::none};
    bool preworker_terminal_force_rerun{false};

    std::atomic<bool> terminal_ready{false};
    std::atomic<bool> drain_post_inflight{false};
    // Optional one-shot rendezvous used by a worker which must publish an
    // immutable pre-COMMIT observation to control and wait for a typed ack.
    // These callbacks do not own coordinator authority: the exact running
    // claim and TerminalOwner lease remain the sole operation owner.
    std::function<void()> pump_worker_checkpoint;
    std::function<void()> cancel_worker_checkpoint;
    int watchdog_task_id{-1};
    std::uint64_t watchdog_serial{0U};
};

// Owns the complete asynchronous transport authority for delayed firewall
// work. It deliberately has no Daemon pointer: scheduling, control wakeups,
// domain preparation and publication enter through the narrow callbacks.
class RuntimeFirewallOperationOwner final
    : public std::enable_shared_from_this<
          RuntimeFirewallOperationOwner> {
public:
    using Context = RuntimeFirewallOperationContext;
    using ContextPtr = std::shared_ptr<Context>;
    using MutationLeasePtr =
        std::unique_ptr<RuntimeMutationAdmission::Lease>;
    using DomainStatePtr =
        std::shared_ptr<RuntimeFirewallOperationDomainState>;
    using WorkerRunner = std::function<RuntimeFirewallWorkerAttemptResultPtr(
        const RuntimeFirewallWorkerAttemptInput&,
        const RuntimeFirewallDelayedWorker::RunningClaim&)>;

    struct PendingSuccessor final {
        Context::SuccessorMode mode{Context::SuccessorMode::none};
        std::size_t attempt{0U};
        std::uint64_t runtime_generation{0U};
        OwnedSnatRecovery snat_recovery;
        PreparedNativeVpnCatalogPtr prepared_catalog;
        bool schedule_catalog_refresh{true};
        // A foreground lifecycle mutation retains its exact admission across
        // bounded retry/defer successors. Ordinary background successors keep
        // this empty and acquire admission only when their worker is ready.
        MutationLeasePtr retained_mutation_lease;
        RuntimeFirewallLifecycleCompletion::Source lifecycle_completion;
        RuntimeFirewallLifecycleKind lifecycle_kind{
            RuntimeFirewallLifecycleKind::background};
        std::size_t foreground_transport_rejections{0U};
    };

    struct PreownedImmediateStartResult final {
        RuntimeFirewallImmediateDisposition disposition{
            RuntimeFirewallImmediateDisposition::rejected};
        MutationLeasePtr unaccepted_lease;
    };

    static_assert(
        std::is_nothrow_move_constructible_v<
            PreownedImmediateStartResult>,
        "pre-owned admission must return to its caller without a throwing "
        "ownership gap");

    static_assert(
        std::is_nothrow_move_constructible_v<PendingSuccessor>,
        "an exact successor must enter durable owner storage before the old "
        "terminal is retired");
    static_assert(
        std::is_nothrow_move_assignable_v<PendingSuccessor>,
        "a fully prepared successor merge must commit without throwing");

    struct Callbacks final {
        std::function<DomainStatePtr()> create_domain_state;
        std::function<bool(std::function<void()>, std::string)> post_control;
        std::function<int(std::chrono::milliseconds,
                          std::function<void()>,
                          std::string)> schedule_oneshot;
        std::function<int(std::chrono::milliseconds,
                          std::function<void()>,
                          std::string)> schedule_repeating;
        std::function<void(int)> cancel_scheduled;
        std::function<bool(
            std::uint64_t,
            RuntimeFirewallLifecycleKind)> runtime_is_current;
        std::function<bool(std::uint64_t)> urltest_waiting;
        std::function<void(ContextPtr,
                           RuntimeFirewallOperationClaim,
                           OwnedSnatRecovery,
                           PreparedNativeVpnCatalogPtr,
                           bool)> dispatch_attempt;
        std::function<void(ContextPtr, bool)> drain_terminal;
        std::function<std::string()> active_mutation_label;
    };

    RuntimeFirewallOperationOwner(
        RuntimeFirewallRetryCoordinator& coordinator,
        Callbacks callbacks);
    ~RuntimeFirewallOperationOwner();

    RuntimeFirewallOperationOwner(
        const RuntimeFirewallOperationOwner&) = delete;
    RuntimeFirewallOperationOwner& operator=(
        const RuntimeFirewallOperationOwner&) = delete;

    ContextPtr active_context() const noexcept;
    bool is_active(const ContextPtr& context) const noexcept;
    void reset_if_active(const ContextPtr& context) noexcept;
    void reset_active() noexcept;

    bool shutdown_requested() const noexcept;
    void request_shutdown() noexcept;

    RuntimeFirewallImmediateDisposition start_immediate(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        OwnedSnatRecovery snat_recovery,
        PreparedNativeVpnCatalogPtr prepared_catalog,
        bool schedule_catalog_refresh,
        const DomainStatePtr& domain_state);

    // Starts an immediate operation with the caller's already-admitted
    // production mutation. Rejection returns the exact physical lease; an
    // accepted result leaves it in the operation context for the typed worker
    // hand-off. Pre-owned authority is never coalesced into another chain.
    PreownedImmediateStartResult start_immediate_preowned(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        OwnedSnatRecovery snat_recovery,
        PreparedNativeVpnCatalogPtr prepared_catalog,
        bool schedule_catalog_refresh,
        const DomainStatePtr& domain_state,
        const RuntimeMutationAdmission& admission,
        MutationLeasePtr mutation_lease,
        RuntimeFirewallLifecycleCompletion::Source lifecycle_completion = {},
        RuntimeFirewallLifecycleKind lifecycle_kind =
            RuntimeFirewallLifecycleKind::background);

    void schedule(std::size_t attempt,
                  std::uint64_t runtime_generation,
                  OwnedSnatRecovery snat_recovery,
                  PreparedNativeVpnCatalogPtr prepared_catalog = {});
    void defer(std::size_t attempt,
               std::uint64_t runtime_generation,
               PreparedNativeVpnCatalogPtr prepared_catalog,
               bool schedule_catalog_refresh,
               OwnedSnatRecovery snat_recovery);
    void cancel_retry() noexcept;
    bool foreground_lifecycle_pending() const noexcept;
    bool note_foreground_transport_rejection(
        const ContextPtr& context) noexcept;

    bool retain_pending_successor(
        const ContextPtr& completed_context,
        Context::SuccessorMode mode,
        std::size_t attempt,
        std::uint64_t runtime_generation,
        OwnedSnatRecovery snat_recovery,
        PreparedNativeVpnCatalogPtr prepared_catalog,
        bool schedule_catalog_refresh,
        bool detach_foreground = false) noexcept;
    bool launch_pending_successor();
    bool pending_successor() const noexcept;
    const PendingSuccessor* pending_successor_state() const noexcept;

    void terminate_before_worker(
        const ContextPtr& context,
        RuntimeFirewallOperationClaim claim,
        Context::SuccessorMode successor_mode,
        bool force_rerun) noexcept;
    bool enqueue_worker(
        const ContextPtr& context,
        RuntimeFirewallOperationClaim claim,
        std::shared_ptr<const RuntimeFirewallWorkerAttemptInput> input,
        std::unique_ptr<RuntimeMutationAdmission::Lease> mutation_lease,
        WorkerRunner runner);
    bool enqueue_worker_with_retained_lease(
        const ContextPtr& context,
        RuntimeFirewallOperationClaim claim,
        std::shared_ptr<const RuntimeFirewallWorkerAttemptInput> input,
        WorkerRunner runner);
    // Runs one lifecycle-specific blocking tail on the same dedicated owner
    // executor after the primary worker has published its terminal. The
    // retained context/lease remain control-side authority throughout.
    bool enqueue_auxiliary(
        const ContextPtr& context,
        std::string label,
        std::function<void()> task) noexcept;

    void request_terminal_drain(const ContextPtr& context) noexcept;
    bool arm_completion_watchdog(const ContextPtr& context) noexcept;
    void cancel_completion_watchdog() noexcept;
    void pump_terminal_for_shutdown() noexcept;

    void cancel_pending_work() noexcept;
    void shutdown_executor() noexcept;

private:
    ContextPtr ensure_context(DomainStatePtr domain_state = {});
    void dispatch_terminal_drain(const ContextPtr& context,
                                 bool shutdown) noexcept;
    void pump_preworker_terminal(const ContextPtr& context) noexcept;
    void pump_pending_successor(std::uint64_t watchdog_serial) noexcept;
    bool retain_pending_transport_retry_or_finish() noexcept;
    bool terminalize_pending_foreground_transport_exhaustion() noexcept;
    void cancel_pending_successor_watchdog() noexcept;
    void retain_trailing_intent(
        const ContextPtr& context,
        std::size_t attempt,
        std::uint64_t runtime_generation,
        OwnedSnatRecovery snat_recovery,
        PreparedNativeVpnCatalogPtr prepared_catalog,
        bool schedule_catalog_refresh);
    void merge_pending_intent(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        OwnedSnatRecovery snat_recovery,
        PreparedNativeVpnCatalogPtr prepared_catalog,
        bool schedule_catalog_refresh);
    bool schedule_fresh(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        OwnedSnatRecovery snat_recovery,
        PreparedNativeVpnCatalogPtr prepared_catalog,
        bool schedule_catalog_refresh,
        MutationLeasePtr* retained_mutation_lease,
        RuntimeFirewallLifecycleCompletion::Source* lifecycle_completion,
        RuntimeFirewallLifecycleKind lifecycle_kind);
    bool defer_fresh(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        PreparedNativeVpnCatalogPtr prepared_catalog,
        bool schedule_catalog_refresh,
        OwnedSnatRecovery snat_recovery,
        MutationLeasePtr* retained_mutation_lease,
        RuntimeFirewallLifecycleCompletion::Source* lifecycle_completion,
        RuntimeFirewallLifecycleKind lifecycle_kind);

    RuntimeFirewallRetryCoordinator& coordinator_;
    Callbacks callbacks_;
    std::atomic<bool> shutdown_requested_{false};
    ContextPtr active_context_;
    std::optional<PendingSuccessor> pending_successor_;
    bool launching_pending_successor_{false};
    // A successor inherits the already-armed terminal watchdog before its
    // completed context is retired. This gives the durable exact lease/source
    // an independent wake even when the retry timer registration just failed.
    int pending_successor_watchdog_task_id_{-1};
    std::uint64_t pending_successor_watchdog_serial_{0U};
    std::uint64_t watchdog_serial_counter_{0U};
    BlockingExecutor executor_{1, 1};
};

} // namespace keen_pbr3
