#include "runtime_firewall_operation_owner.hpp"

#include "../log/logger.hpp"

#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr std::array<std::chrono::seconds, 6> kRetryDelays{
    std::chrono::seconds{1},
    std::chrono::seconds{2},
    std::chrono::seconds{4},
    std::chrono::seconds{8},
    std::chrono::seconds{16},
    std::chrono::seconds{32},
};
constexpr std::array<std::chrono::milliseconds, 3> kStartRetryDelays{
    std::chrono::milliseconds{100},
    std::chrono::milliseconds{200},
    std::chrono::milliseconds{400},
};
static_assert(
    kStartRetryDelays.size() ==
        kRuntimeFirewallStartBoundedRetryCount,
    "START retry policy must match the lifecycle publication fence");
constexpr auto kAdmissionRetryDelay = std::chrono::seconds{1};
constexpr auto kMaintenanceRetryDelay = std::chrono::seconds{60};
constexpr auto kTerminalWatchdogDelay = std::chrono::milliseconds{200};
constexpr std::size_t kForegroundTransportRetryLimit = 4U;

std::size_t bounded_retry_count(
    RuntimeFirewallLifecycleKind lifecycle_kind) noexcept {
    return runtime_firewall_lifecycle_uses_hot_retry(lifecycle_kind)
        ? kStartRetryDelays.size()
        : kRetryDelays.size();
}

std::chrono::milliseconds bounded_retry_delay(
    RuntimeFirewallLifecycleKind lifecycle_kind,
    std::size_t attempt) noexcept {
    if (runtime_firewall_lifecycle_uses_hot_retry(lifecycle_kind)) {
        return kStartRetryDelays[attempt];
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        kRetryDelays[attempt]);
}

std::uint64_t next_nonzero_serial(std::uint64_t serial) noexcept {
    return serial == std::numeric_limits<std::uint64_t>::max()
        ? 1U
        : serial + 1U;
}

bool context_has_preowned_authority(
    const RuntimeFirewallOperationOwner::ContextPtr& context) noexcept {
    return context &&
           (context->retained_mutation_lease ||
            context->lifecycle_completion ||
            context->preowned_terminal_continuation);
}

void return_unaccepted_preowned_authority(
    const RuntimeFirewallOperationOwner::ContextPtr& context,
    RuntimeFirewallOperationOwner::MutationLeasePtr* mutation_lease,
    RuntimeFirewallLifecycleCompletion::Source* lifecycle_completion,
    RuntimeFirewallOperationOwner::PreownedTerminalContinuation*
        terminal_continuation)
    noexcept {
    if (!context) return;
    if (mutation_lease && context->retained_mutation_lease) {
        *mutation_lease =
            std::move(context->retained_mutation_lease);
    }
    if (lifecycle_completion && context->lifecycle_completion) {
        *lifecycle_completion =
            std::move(context->lifecycle_completion);
    }
    if (terminal_continuation &&
        context->preowned_terminal_continuation) {
        *terminal_continuation =
            std::move(context->preowned_terminal_continuation);
    }
}

void invoke_preowned_terminal_continuation(
    RuntimeFirewallOperationOwner::PreownedTerminalContinuation continuation,
    RuntimeFirewallOperationOwner::MutationLeasePtr mutation_lease,
    RuntimeFirewallLifecycleTerminal terminal) noexcept {
    if (!continuation) return;
    continuation.invoke(
        std::move(terminal), std::move(mutation_lease));
}

} // namespace

RuntimeFirewallOperationOwner::RuntimeFirewallOperationOwner(
    RuntimeFirewallRetryCoordinator& coordinator,
    Callbacks callbacks)
    : coordinator_(coordinator), callbacks_(std::move(callbacks)) {
    if (!callbacks_.create_domain_state || !callbacks_.post_control ||
        !callbacks_.schedule_oneshot || !callbacks_.schedule_repeating ||
        !callbacks_.cancel_scheduled ||
        !callbacks_.runtime_is_current || !callbacks_.urltest_waiting ||
        !callbacks_.dispatch_attempt || !callbacks_.drain_terminal) {
        throw std::invalid_argument(
            "runtime firewall owner requires complete callbacks");
    }
}

RuntimeFirewallOperationOwner::~RuntimeFirewallOperationOwner() {
    // The control owner may already be absent from callbacks which captured
    // it: shared_ptr::reset() clears the caller's slot before entering this
    // destructor. Normal Daemon shutdown drains terminals while the owner is
    // still alive. This fallback therefore must not re-enter
    // callbacks_.drain_terminal; it only makes any externally retained
    // ContextPtr inert after the executor join barrier.
    const auto retiring_context = active_context_;
    request_shutdown();
    cancel_completion_watchdog();
    // Retire a timer slot without publishing through the external control
    // callback.  The returned coordinator authority is intentionally
    // abandoned here; the inert-context cleanup below owns the conservative
    // lifecycle fallback.
    (void)coordinator_.cancel_timer_for_terminal(
        [this](int task_id) { callbacks_.cancel_scheduled(task_id); });
    if (retiring_context && retiring_context->cancel_worker_checkpoint) {
        try {
            retiring_context->cancel_worker_checkpoint();
        } catch (...) {
        }
    }
    // Destruction is a last-resort resource fallback and must never re-enter
    // an external continuation while the owner object is being torn down.
    // Normal Daemon shutdown calls cancel_pending_work() while the owner is
    // still alive and publishes the typed shutdown handoff there.
    cancel_pending_work_impl(/*publish_preowned_terminal=*/false);
    shutdown_executor();

    if (retiring_context) {
        // Release every possible holder of the exact mutation authority
        // before abandoning the lifecycle Source. Late timers may retain the
        // ContextPtr, but they must never extend either authority lifetime.
        retiring_context->retained_mutation_lease.reset();
        retiring_context->worker_operation.reset();
        retiring_context->terminal_owner.reset();
        retiring_context->worker_input.reset();
        retiring_context->pump_worker_checkpoint = {};
        retiring_context->cancel_worker_checkpoint = {};
        retiring_context->lifecycle_completion = {};
        retiring_context->preowned_terminal_continuation = {};
    }
    reset_active();
}

RuntimeFirewallOperationOwner::ContextPtr
RuntimeFirewallOperationOwner::active_context() const noexcept {
    return active_context_;
}

bool RuntimeFirewallOperationOwner::is_active(
    const ContextPtr& context) const noexcept {
    return context && active_context_.get() == context.get();
}

void RuntimeFirewallOperationOwner::reset_if_active(
    const ContextPtr& context) noexcept {
    if (is_active(context)) active_context_.reset();
}

void RuntimeFirewallOperationOwner::reset_active() noexcept {
    active_context_.reset();
}

bool RuntimeFirewallOperationOwner::shutdown_requested() const noexcept {
    return shutdown_requested_.load(std::memory_order_acquire);
}

void RuntimeFirewallOperationOwner::request_shutdown() noexcept {
    // This is the public cross-thread shutdown fence. active_context_ and its
    // callbacks are control-owned and deliberately not read here; the control
    // shutdown drain cancels any checkpoint before joining the executor.
    shutdown_requested_.store(true, std::memory_order_release);
}

RuntimeFirewallOperationOwner::ContextPtr
RuntimeFirewallOperationOwner::ensure_context(DomainStatePtr domain_state) {
    if (active_context_) return active_context_;

    auto context = std::make_shared<Context>();
    context->domain_state = domain_state
        ? std::move(domain_state)
        : callbacks_.create_domain_state();
    if (!context->domain_state) {
        throw std::runtime_error(
            "runtime firewall domain-state factory returned null");
    }
    std::weak_ptr<Context> weak_context{context};
    const auto weak_self = weak_from_this();
    context->terminal_owner = RuntimeFirewallDelayedTerminalOwner::create(
        [weak_self, weak_context]() noexcept {
            const auto self = weak_self.lock();
            if (!self) return;
            if (const auto retained = weak_context.lock()) {
                retained->terminal_ready.store(
                    true, std::memory_order_release);
                self->request_terminal_drain(retained);
            }
        });
    active_context_ = context;
    return context;
}

RuntimeFirewallImmediateDisposition
RuntimeFirewallOperationOwner::start_immediate(
    std::size_t attempt,
    std::uint64_t runtime_generation,
    OwnedSnatRecovery snat_recovery,
    PreparedNativeVpnCatalogPtr prepared_catalog,
    bool schedule_catalog_refresh,
    const DomainStatePtr& domain_state) {
    if (shutdown_requested() || !domain_state) {
        return RuntimeFirewallImmediateDisposition::rejected;
    }
    if (!launching_pending_successor_ && pending_successor_ &&
        !active_context_) {
        merge_pending_intent(
            attempt,
            runtime_generation,
            std::move(snat_recovery),
            std::move(prepared_catalog),
            schedule_catalog_refresh);
        try {
            (void)launch_pending_successor();
        } catch (...) {
            // The durable pending slot, not this invocation, still owns the
            // exact recovery/catalog intent.
        }
        return RuntimeFirewallImmediateDisposition::coalesced;
    }
    if (active_context_) {
        retain_trailing_intent(
            active_context_,
            attempt,
            runtime_generation,
            std::move(snat_recovery),
            std::move(prepared_catalog),
            schedule_catalog_refresh);
        return RuntimeFirewallImmediateDisposition::coalesced;
    }

    ContextPtr context;
    try {
        context = ensure_context(domain_state);
    } catch (...) {
        return RuntimeFirewallImmediateDisposition::rejected;
    }
    context->successor_mode = Context::SuccessorMode::defer_same_attempt;
    context->successor_attempt = attempt;
    context->successor_runtime_generation = runtime_generation;
    context->successor_schedule_catalog_refresh = schedule_catalog_refresh;
    context->prepared_native_vpn_catalog = prepared_catalog;
    context->queued_claim.runtime_generation = runtime_generation;
    context->queued_claim.attempt = attempt;

    // Arm the independent drain before the coordinator can publish an inline
    // stale/copy/queue terminal. A rejected control post must never strand an
    // accepted phase claim and its mutation lease.
    if (!arm_completion_watchdog(context)) {
        reset_if_active(context);
        return RuntimeFirewallImmediateDisposition::rejected;
    }

    const auto weak_self = weak_from_this();
    const auto disposition = coordinator_
        .start_immediate_operation_with_prepared_catalog_and_terminal(
            attempt,
            runtime_generation,
            std::move(snat_recovery),
            prepared_catalog,
            [weak_self, context](std::uint64_t generation) {
                const auto self = weak_self.lock();
                return self &&
                       self->callbacks_.runtime_is_current(
                           generation, context->lifecycle_kind);
            },
            [weak_self, context, schedule_catalog_refresh](
                RuntimeFirewallOperationClaim claim,
                OwnedSnatRecovery recovery,
                PreparedNativeVpnCatalogPtr catalog) {
                const auto self = weak_self.lock();
                if (!self) return;
                self->callbacks_.dispatch_attempt(
                    context,
                    claim,
                    std::move(recovery),
                    std::move(catalog),
                    schedule_catalog_refresh);
            },
            context->terminal_owner->coordinator_terminal_sink());
    if (disposition !=
        RuntimeFirewallImmediateDisposition::handed_off) {
        cancel_completion_watchdog();
        reset_if_active(context);
    }
    return disposition;
}

RuntimeFirewallOperationOwner::PreownedImmediateStartResult
RuntimeFirewallOperationOwner::start_immediate_preowned(
    std::size_t attempt,
    std::uint64_t runtime_generation,
    OwnedSnatRecovery snat_recovery,
    PreparedNativeVpnCatalogPtr prepared_catalog,
    bool schedule_catalog_refresh,
    const DomainStatePtr& domain_state,
    const RuntimeMutationAdmission& admission,
    MutationLeasePtr mutation_lease,
    RuntimeFirewallLifecycleCompletion::Source lifecycle_completion,
    RuntimeFirewallLifecycleKind lifecycle_kind,
    PreownedTerminalContinuation terminal_continuation) {
    PreownedImmediateStartResult result;
    result.unaccepted_lease = std::move(mutation_lease);
    result.unaccepted_continuation = std::move(terminal_continuation);
    const bool has_terminal_continuation =
        static_cast<bool>(result.unaccepted_continuation);
    const bool has_lifecycle_completion =
        static_cast<bool>(lifecycle_completion);
    const bool uses_lifecycle_completion =
        runtime_firewall_lifecycle_is_start(lifecycle_kind) ||
        runtime_firewall_lifecycle_is_restart(lifecycle_kind);
    if (!result.unaccepted_lease ||
        !static_cast<bool>(*result.unaccepted_lease) ||
        !admission.owns(*result.unaccepted_lease) ||
        (has_terminal_continuation && has_lifecycle_completion) ||
        (has_terminal_continuation !=
         runtime_firewall_lifecycle_uses_preowned_continuation(
             lifecycle_kind)) ||
        (has_lifecycle_completion != uses_lifecycle_completion) ||
        shutdown_requested() || !domain_state || active_context_ ||
        pending_successor_ || launching_pending_successor_) {
        return result;
    }

    std::shared_ptr<std::atomic<bool>> dispatch_entered;
    ContextPtr context;
    try {
        dispatch_entered =
            std::make_shared<std::atomic<bool>>(false);
        context = ensure_context(domain_state);
    } catch (...) {
        return result;
    }
    context->successor_mode =
        Context::SuccessorMode::defer_same_attempt;
    context->successor_attempt = attempt;
    context->successor_runtime_generation = runtime_generation;
    context->successor_schedule_catalog_refresh =
        schedule_catalog_refresh;
    context->prepared_native_vpn_catalog = prepared_catalog;
    context->queued_claim.runtime_generation = runtime_generation;
    context->queued_claim.attempt = attempt;

    if (!arm_completion_watchdog(context)) {
        reset_if_active(context);
        return result;
    }

    // The dispatch callback may run inline. Publish the exact lease into its
    // durable context before the coordinator can expose that callback.
    context->retained_mutation_lease =
        std::move(result.unaccepted_lease);
    context->lifecycle_completion = std::move(lifecycle_completion);
    context->preowned_terminal_continuation =
        std::move(result.unaccepted_continuation);
    context->lifecycle_kind = lifecycle_kind;

    const auto weak_self = weak_from_this();
    RuntimeFirewallImmediateDisposition disposition{
        RuntimeFirewallImmediateDisposition::rejected};
    try {
        disposition = coordinator_
            .start_immediate_operation_with_prepared_catalog_and_terminal(
                attempt,
                runtime_generation,
                std::move(snat_recovery),
                prepared_catalog,
                [weak_self, context](std::uint64_t generation) {
                    const auto self = weak_self.lock();
                    return self &&
                           self->callbacks_.runtime_is_current(
                               generation, context->lifecycle_kind);
                },
                [weak_self,
                 context,
                 schedule_catalog_refresh,
                 dispatch_entered](
                    RuntimeFirewallOperationClaim claim,
                    OwnedSnatRecovery recovery,
                    PreparedNativeVpnCatalogPtr catalog) {
                    const auto self = weak_self.lock();
                    if (!self) return;
                    dispatch_entered->store(
                        true, std::memory_order_release);
                    self->callbacks_.dispatch_attempt(
                        context,
                        claim,
                        std::move(recovery),
                        std::move(catalog),
                        schedule_catalog_refresh);
                },
                context->terminal_owner->coordinator_terminal_sink());
    } catch (...) {
        if (dispatch_entered->load(std::memory_order_acquire) ||
            coordinator_.retry_pending() ||
            !context->retained_mutation_lease) {
            // An inline callback is authoritative even if the coordinator
            // reports an exceptional compatibility result afterwards.
            result.disposition =
                RuntimeFirewallImmediateDisposition::handed_off;
            if (context->terminal_ready.load(
                    std::memory_order_acquire)) {
                arm_completion_watchdog(context);
            }
            return result;
        }

        cancel_completion_watchdog();
        result.unaccepted_lease =
            std::move(context->retained_mutation_lease);
        result.unaccepted_continuation =
            std::move(context->preowned_terminal_continuation);
        lifecycle_completion =
            std::move(context->lifecycle_completion);
        reset_if_active(context);
        return result;
    }
    result.disposition = disposition;
    if (disposition ==
        RuntimeFirewallImmediateDisposition::handed_off) {
        return result;
    }

    cancel_completion_watchdog();
    if (context->retained_mutation_lease) {
        result.unaccepted_lease =
            std::move(context->retained_mutation_lease);
        result.unaccepted_continuation =
            std::move(context->preowned_terminal_continuation);
        lifecycle_completion =
            std::move(context->lifecycle_completion);
        reset_if_active(context);
        return result;
    }

    // A callback which already moved the physical token is authoritative even
    // if a compatibility coordinator result says otherwise. Never report
    // caller ownership after the exact lease has crossed that boundary.
    result.disposition =
        RuntimeFirewallImmediateDisposition::handed_off;
    return result;
}

void RuntimeFirewallOperationOwner::retain_trailing_intent(
    const ContextPtr& context,
    std::size_t attempt,
    std::uint64_t runtime_generation,
    OwnedSnatRecovery snat_recovery,
    PreparedNativeVpnCatalogPtr prepared_catalog,
    bool schedule_catalog_refresh) {
    auto merged_recovery = merge_owned_snat_recovery(
        context->trailing_snat_recovery, snat_recovery);
    auto newest_catalog =
        context->trailing_prepared_native_vpn_catalog;
    if (prepared_catalog &&
        (!newest_catalog ||
         prepared_catalog->runtime_generation >=
             newest_catalog->runtime_generation)) {
        newest_catalog = std::move(prepared_catalog);
    }
    context->trailing_snat_recovery = std::move(merged_recovery);
    context->trailing_prepared_native_vpn_catalog =
        std::move(newest_catalog);
    context->force_successor = true;
    context->successor_mode = Context::SuccessorMode::defer_same_attempt;
    if (runtime_generation >= context->successor_runtime_generation) {
        context->successor_attempt = attempt;
        context->successor_runtime_generation = runtime_generation;
        context->successor_schedule_catalog_refresh =
            schedule_catalog_refresh;
    }
    if (context->terminal_ready.load(std::memory_order_acquire)) {
        request_terminal_drain(context);
        arm_completion_watchdog(context);
    }
}

void RuntimeFirewallOperationOwner::merge_pending_intent(
    std::size_t attempt,
    std::uint64_t runtime_generation,
    OwnedSnatRecovery snat_recovery,
    PreparedNativeVpnCatalogPtr prepared_catalog,
    bool schedule_catalog_refresh) {
    if (!pending_successor_) return;

    // Prepare every allocating copy/merge beside the durable slot. The final
    // move assignment is statically non-throwing, so a failure leaves the old
    // exact successor byte-for-byte intact and a successful merge retains the
    // new intent before any launch can fail.
    auto merged = PendingSuccessor{
        pending_successor_->mode,
        pending_successor_->attempt,
        pending_successor_->runtime_generation,
        pending_successor_->snat_recovery,
        pending_successor_->prepared_catalog,
        pending_successor_->schedule_catalog_refresh,
        pending_successor_->domain_state,
        {},
        pending_successor_->lifecycle_completion,
        {},
        pending_successor_->lifecycle_kind,
        pending_successor_->foreground_transport_rejections,
        pending_successor_->preapply_commit_observed};
    merged.snat_recovery = merge_owned_snat_recovery(
        std::move(merged.snat_recovery),
        std::move(snat_recovery));
    if (prepared_catalog &&
        (!merged.prepared_catalog ||
         prepared_catalog->runtime_generation >=
             merged.prepared_catalog->runtime_generation)) {
        merged.prepared_catalog = std::move(prepared_catalog);
    }
    if (runtime_generation >= merged.runtime_generation) {
        merged.mode = Context::SuccessorMode::defer_same_attempt;
        merged.attempt = attempt;
        merged.runtime_generation = runtime_generation;
        merged.schedule_catalog_refresh = schedule_catalog_refresh;
    }
    if (merged.prepared_catalog &&
        merged.prepared_catalog->runtime_generation <
            merged.runtime_generation) {
        // A newer catalog-less observation must build a fresh cache snapshot;
        // retaining the older exact catalog would make the coordinator reject
        // this otherwise-current generation forever.
        merged.prepared_catalog.reset();
    }
    if (merged.prepared_catalog &&
        merged.prepared_catalog->runtime_generation >=
            merged.runtime_generation) {
        if (merged.prepared_catalog->runtime_generation >
            merged.runtime_generation) {
            merged.mode = Context::SuccessorMode::defer_same_attempt;
            merged.attempt = 0U;
            merged.runtime_generation =
                merged.prepared_catalog->runtime_generation;
        }
        merged.schedule_catalog_refresh =
            merged.prepared_catalog->schedule_catalog_refresh;
    }
    // Only after every allocating copy/merge succeeded may the physical
    // admission token cross into the prepared replacement. The final move is
    // non-throwing, so the old slot or the new slot always owns it.
    merged.retained_mutation_lease =
        std::move(pending_successor_->retained_mutation_lease);
    merged.lifecycle_completion =
        std::move(pending_successor_->lifecycle_completion);
    merged.preowned_terminal_continuation =
        std::move(pending_successor_->preowned_terminal_continuation);
    *pending_successor_ = std::move(merged);
}

void RuntimeFirewallOperationOwner::schedule(
    std::size_t attempt,
    std::uint64_t runtime_generation,
    OwnedSnatRecovery snat_recovery,
    PreparedNativeVpnCatalogPtr prepared_catalog) {
    if (shutdown_requested()) return;
    if (!launching_pending_successor_ && pending_successor_ &&
        !active_context_) {
        merge_pending_intent(
            attempt,
            runtime_generation,
            std::move(snat_recovery),
            std::move(prepared_catalog),
            /*schedule_catalog_refresh=*/true);
        (void)launch_pending_successor();
        return;
    }
    if (active_context_) {
        retain_trailing_intent(
            active_context_,
            attempt,
            runtime_generation,
            std::move(snat_recovery),
            std::move(prepared_catalog),
            /*schedule_catalog_refresh=*/true);
        return;
    }

    (void)schedule_fresh(
        attempt,
        runtime_generation,
        std::move(snat_recovery),
        std::move(prepared_catalog),
        /*schedule_catalog_refresh=*/true,
        nullptr,
        nullptr,
        nullptr,
        RuntimeFirewallLifecycleKind::background,
        {});
}

bool RuntimeFirewallOperationOwner::schedule_fresh(
    std::size_t attempt,
    std::uint64_t runtime_generation,
    OwnedSnatRecovery snat_recovery,
    PreparedNativeVpnCatalogPtr prepared_catalog,
    bool schedule_catalog_refresh,
    MutationLeasePtr* retained_mutation_lease,
    RuntimeFirewallLifecycleCompletion::Source* lifecycle_completion,
    PreownedTerminalContinuation* terminal_continuation,
    RuntimeFirewallLifecycleKind lifecycle_kind,
    DomainStatePtr domain_state) {
    if (shutdown_requested()) return false;

    const auto dispatch_entered =
        std::make_shared<std::atomic<bool>>(false);
    const auto context = ensure_context(std::move(domain_state));
    context->successor_mode = Context::SuccessorMode::defer_same_attempt;
    context->successor_attempt = attempt;
    context->successor_runtime_generation = runtime_generation;
    context->successor_schedule_catalog_refresh =
        schedule_catalog_refresh;
    context->prepared_native_vpn_catalog = prepared_catalog;
    context->queued_claim.runtime_generation = runtime_generation;
    context->queued_claim.attempt = attempt;
    if (retained_mutation_lease && *retained_mutation_lease) {
        context->retained_mutation_lease =
            std::move(*retained_mutation_lease);
    }
    if (lifecycle_completion && *lifecycle_completion) {
        context->lifecycle_completion =
            std::move(*lifecycle_completion);
    }
    if (terminal_continuation && *terminal_continuation) {
        context->preowned_terminal_continuation =
            std::move(*terminal_continuation);
    }
    context->lifecycle_kind = lifecycle_kind;
    const bool carried_preowned_authority =
        context_has_preowned_authority(context);

    RuntimeFirewallRetryPlan retry_plan;
    const auto weak_self = weak_from_this();
    try {
        retry_plan = coordinator_
            .schedule_operation_with_prepared_catalog_and_terminal(
                attempt,
                runtime_generation,
                bounded_retry_count(lifecycle_kind),
                std::move(snat_recovery),
                prepared_catalog,
                [this, attempt, lifecycle_kind](
                    const RuntimeFirewallRetryPlan& plan,
                    auto callback) {
                    const auto delay = plan.maintenance
                        ? kMaintenanceRetryDelay
                        : bounded_retry_delay(
                              lifecycle_kind, attempt);
                    return callbacks_.schedule_oneshot(
                        std::chrono::duration_cast<
                            std::chrono::milliseconds>(delay),
                        std::move(callback),
                        "runtime-firewall-retry");
                },
                [weak_self, context](std::uint64_t generation) {
                    const auto self = weak_self.lock();
                    return self &&
                           self->callbacks_.runtime_is_current(
                               generation, context->lifecycle_kind);
                },
                [weak_self,
                 context,
                 schedule_catalog_refresh,
                 dispatch_entered](
                    RuntimeFirewallOperationClaim claim,
                    OwnedSnatRecovery recovery,
                    PreparedNativeVpnCatalogPtr catalog) {
                    const auto self = weak_self.lock();
                    if (!self) return;
                    dispatch_entered->store(
                        true, std::memory_order_release);
                    self->callbacks_.dispatch_attempt(
                        context,
                        claim,
                        std::move(recovery),
                        std::move(catalog),
                        schedule_catalog_refresh);
                },
                context->terminal_owner->coordinator_terminal_sink(),
                callbacks_.urltest_waiting(runtime_generation));
    } catch (...) {
        const bool dispatch_was_entered = dispatch_entered->load(
            std::memory_order_acquire);
        const bool coordinator_owns_operation =
            coordinator_.retry_pending();
        if (carried_preowned_authority && !dispatch_was_entered &&
            !coordinator_owns_operation) {
            return_unaccepted_preowned_authority(
                context,
                retained_mutation_lease,
                lifecycle_completion,
                terminal_continuation);
            reset_if_active(context);
            throw;
        }
        if (context->terminal_ready.load(std::memory_order_acquire)) {
            arm_completion_watchdog(context);
        }
        const bool accepted = dispatch_was_entered ||
            coordinator_owns_operation ||
            context->terminal_ready.load(std::memory_order_acquire);
        if (!accepted) {
            return_unaccepted_preowned_authority(
                context,
                retained_mutation_lease,
                lifecycle_completion,
                terminal_continuation);
            reset_if_active(context);
        }
        throw;
    }

    if (!retry_plan.schedule) {
        const bool dispatch_was_entered = dispatch_entered->load(
            std::memory_order_acquire);
        const bool coordinator_owns_operation =
            coordinator_.retry_pending();
        if (carried_preowned_authority && !dispatch_was_entered &&
            !coordinator_owns_operation) {
            return_unaccepted_preowned_authority(
                context,
                retained_mutation_lease,
                lifecycle_completion,
                terminal_continuation);
            reset_if_active(context);
            return false;
        }
        if (context->terminal_ready.load(std::memory_order_acquire)) {
            arm_completion_watchdog(context);
            return true;
        }
        if (coordinator_owns_operation) return true;
        return_unaccepted_preowned_authority(
            context,
            retained_mutation_lease,
            lifecycle_completion,
            terminal_continuation);
        if (!coordinator_owns_operation) {
            reset_if_active(context);
        }
        return false;
    }

    if (retry_plan.maintenance) {
        Logger::instance().verbose(
            "Persistent firewall maintenance recovery scheduled in {}s.",
            kMaintenanceRetryDelay.count());
    } else {
        Logger::instance().info(
            "Runtime firewall recovery retry {} scheduled in {}ms.",
            retry_plan.next_attempt,
            bounded_retry_delay(lifecycle_kind, attempt).count());
    }
    return true;
}

void RuntimeFirewallOperationOwner::defer(
    std::size_t attempt,
    std::uint64_t runtime_generation,
    PreparedNativeVpnCatalogPtr prepared_catalog,
    bool schedule_catalog_refresh,
    OwnedSnatRecovery snat_recovery) {
    if (shutdown_requested()) return;
    if (!launching_pending_successor_ && pending_successor_ &&
        !active_context_) {
        merge_pending_intent(
            attempt,
            runtime_generation,
            std::move(snat_recovery),
            std::move(prepared_catalog),
            schedule_catalog_refresh);
        (void)launch_pending_successor();
        return;
    }
    if (active_context_) {
        retain_trailing_intent(
            active_context_,
            attempt,
            runtime_generation,
            std::move(snat_recovery),
            std::move(prepared_catalog),
            schedule_catalog_refresh);
        return;
    }

    (void)defer_fresh(
        attempt,
        runtime_generation,
        std::move(prepared_catalog),
        schedule_catalog_refresh,
        std::move(snat_recovery),
        nullptr,
        nullptr,
        nullptr,
        RuntimeFirewallLifecycleKind::background,
        {});
}

bool RuntimeFirewallOperationOwner::defer_fresh(
    std::size_t attempt,
    std::uint64_t runtime_generation,
    PreparedNativeVpnCatalogPtr prepared_catalog,
    bool schedule_catalog_refresh,
    OwnedSnatRecovery snat_recovery,
    MutationLeasePtr* retained_mutation_lease,
    RuntimeFirewallLifecycleCompletion::Source* lifecycle_completion,
    PreownedTerminalContinuation* terminal_continuation,
    RuntimeFirewallLifecycleKind lifecycle_kind,
    DomainStatePtr domain_state) {
    if (shutdown_requested()) return false;

    const auto dispatch_entered =
        std::make_shared<std::atomic<bool>>(false);
    const auto context = ensure_context(std::move(domain_state));
    context->successor_mode = Context::SuccessorMode::defer_same_attempt;
    context->successor_attempt = attempt;
    context->successor_runtime_generation = runtime_generation;
    context->successor_schedule_catalog_refresh =
        schedule_catalog_refresh;
    context->prepared_native_vpn_catalog = prepared_catalog;
    context->queued_claim.runtime_generation = runtime_generation;
    context->queued_claim.attempt = attempt;
    if (retained_mutation_lease && *retained_mutation_lease) {
        context->retained_mutation_lease =
            std::move(*retained_mutation_lease);
    }
    if (lifecycle_completion && *lifecycle_completion) {
        context->lifecycle_completion =
            std::move(*lifecycle_completion);
    }
    if (terminal_continuation && *terminal_continuation) {
        context->preowned_terminal_continuation =
            std::move(*terminal_continuation);
    }
    context->lifecycle_kind = lifecycle_kind;
    const bool carried_preowned_authority =
        context_has_preowned_authority(context);

    const auto weak_self = weak_from_this();
    try {
        const bool scheduled = coordinator_
            .defer_same_attempt_operation_with_prepared_catalog_and_terminal(
                attempt,
                runtime_generation,
                std::move(snat_recovery),
                prepared_catalog,
                [this](auto callback) {
                    return callbacks_.schedule_oneshot(
                        std::chrono::duration_cast<
                            std::chrono::milliseconds>(
                                kAdmissionRetryDelay),
                        std::move(callback),
                        "runtime-firewall-admission-retry");
                },
                [weak_self, context](std::uint64_t generation) {
                    const auto self = weak_self.lock();
                    return self &&
                           self->callbacks_.runtime_is_current(
                               generation, context->lifecycle_kind);
                },
                [weak_self,
                 context,
                 schedule_catalog_refresh,
                 dispatch_entered](
                    RuntimeFirewallOperationClaim claim,
                    OwnedSnatRecovery recovery,
                    PreparedNativeVpnCatalogPtr catalog) {
                    const auto self = weak_self.lock();
                    if (!self) return;
                    dispatch_entered->store(
                        true, std::memory_order_release);
                    self->callbacks_.dispatch_attempt(
                        context,
                        claim,
                        std::move(recovery),
                        std::move(catalog),
                        schedule_catalog_refresh);
                },
                context->terminal_owner->coordinator_terminal_sink());
        if (scheduled) {
            const auto label = callbacks_.active_mutation_label
                ? callbacks_.active_mutation_label()
                : std::string{"unknown"};
            Logger::instance().verbose(
                "Runtime firewall reconciliation deferred behind runtime "
                "mutation '{}' without consuming retry budget.",
                label);
            return true;
        } else if (carried_preowned_authority &&
                   !dispatch_entered->load(std::memory_order_acquire) &&
                   !coordinator_.retry_pending()) {
            return_unaccepted_preowned_authority(
                context,
                retained_mutation_lease,
                lifecycle_completion,
                terminal_continuation);
            reset_if_active(context);
            return false;
        } else if (context->terminal_ready.load(
                       std::memory_order_acquire)) {
            arm_completion_watchdog(context);
            return true;
        } else if (coordinator_.retry_pending()) {
            return true;
        } else if (!coordinator_.retry_pending()) {
            return_unaccepted_preowned_authority(
                context,
                retained_mutation_lease,
                lifecycle_completion,
                terminal_continuation);
            reset_if_active(context);
            Logger::instance().error(
                "Runtime firewall admission retry was rejected; the periodic "
                "health owner retains the recovery intent.");
            return false;
        }
    } catch (const std::exception& error) {
        try {
            Logger::instance().error(
                "Could not defer runtime firewall reconciliation behind "
                "another writer: {}",
                error.what());
        } catch (...) {
        }
        if (carried_preowned_authority &&
            !dispatch_entered->load(std::memory_order_acquire) &&
            !coordinator_.retry_pending()) {
            return_unaccepted_preowned_authority(
                context,
                retained_mutation_lease,
                lifecycle_completion,
                terminal_continuation);
            reset_if_active(context);
            return false;
        }
        if (context->terminal_ready.load(std::memory_order_acquire)) {
            arm_completion_watchdog(context);
            return true;
        }
        if (coordinator_.retry_pending()) return true;
        return_unaccepted_preowned_authority(
            context,
            retained_mutation_lease,
            lifecycle_completion,
            terminal_continuation);
        if (!coordinator_.retry_pending()) {
            reset_if_active(context);
        }
        return false;
    } catch (...) {
        if (carried_preowned_authority &&
            !dispatch_entered->load(std::memory_order_acquire) &&
            !coordinator_.retry_pending()) {
            return_unaccepted_preowned_authority(
                context,
                retained_mutation_lease,
                lifecycle_completion,
                terminal_continuation);
            reset_if_active(context);
            return false;
        }
        if (context->terminal_ready.load(std::memory_order_acquire)) {
            arm_completion_watchdog(context);
            return true;
        }
        if (coordinator_.retry_pending()) return true;
        return_unaccepted_preowned_authority(
            context,
            retained_mutation_lease,
            lifecycle_completion,
            terminal_continuation);
        if (!coordinator_.retry_pending()) {
            reset_if_active(context);
        }
        return false;
    }
    return false;
}

void RuntimeFirewallOperationOwner::cancel_retry() noexcept {
    // A netfilter refresh may ask to replace an older background timer, but
    // it must never cancel the exact START/restart chain which owns the
    // caller's lifecycle Source and mutation lease. Shutdown is the only
    // caller allowed to tear that foreground timer down.
    if (!shutdown_requested() && foreground_lifecycle_pending()) {
        return;
    }
    const auto foreground_context = active_context_;
    if (shutdown_requested() && foreground_context &&
        runtime_firewall_lifecycle_is_foreground(
            foreground_context->lifecycle_kind)) {
        auto terminal = coordinator_.cancel_timer_for_terminal(
            [this](int task_id) {
                callbacks_.cancel_scheduled(task_id);
            });
        if (terminal.owned && foreground_context->terminal_owner) {
            foreground_context->terminal_owner
                ->coordinator_terminal_sink()(std::move(terminal));
            request_terminal_drain(foreground_context);
        }
        // A queued/running foreground operation is not timer-cancellable.
        // Its executor envelope remains the exact terminal owner and the
        // shutdown drain will collect it.
        return;
    }
    try {
        coordinator_.cancel(
            [this](int task_id) { callbacks_.cancel_scheduled(task_id); });
    } catch (const std::exception& error) {
        try {
            Logger::instance().verbose(
                "Runtime firewall timer cancellation reported: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
    }
    const auto context = active_context_;
    if (context && !coordinator_.retry_pending() &&
        !context->terminal_ready.load(std::memory_order_acquire)) {
        cancel_completion_watchdog();
        reset_if_active(context);
    }
}

bool RuntimeFirewallOperationOwner::foreground_lifecycle_pending()
    const noexcept {
    return (active_context_ &&
            runtime_firewall_lifecycle_is_foreground(
                active_context_->lifecycle_kind)) ||
           (pending_successor_ &&
            runtime_firewall_lifecycle_is_foreground(
                pending_successor_->lifecycle_kind));
}

bool RuntimeFirewallOperationOwner::note_foreground_transport_rejection(
    const ContextPtr& context) noexcept {
    if (!context ||
        !runtime_firewall_lifecycle_is_foreground(
            context->lifecycle_kind)) {
        return true;
    }
    if (context->foreground_transport_rejections <
        kForegroundTransportRetryLimit) {
        ++context->foreground_transport_rejections;
    }
    const bool retry = context->foreground_transport_rejections <
                       kForegroundTransportRetryLimit;
    context->foreground_transport_exhausted = !retry;
    return retry;
}

bool RuntimeFirewallOperationOwner::retain_pending_successor(
    const ContextPtr& completed_context,
    Context::SuccessorMode mode,
    std::size_t attempt,
    std::uint64_t runtime_generation,
    OwnedSnatRecovery snat_recovery,
    PreparedNativeVpnCatalogPtr prepared_catalog,
    bool schedule_catalog_refresh,
    bool detach_foreground) noexcept {
    const bool exact_foreground_authority =
        context_has_preowned_authority(completed_context);
    if (!is_active(completed_context) || pending_successor_ ||
        pending_successor_watchdog_task_id_ != -1 ||
        (exact_foreground_authority &&
         (completed_context->watchdog_task_id < 0 ||
          completed_context->watchdog_serial == 0U)) ||
        (detach_foreground &&
         runtime_firewall_lifecycle_uses_preowned_continuation(
             completed_context->lifecycle_kind)) ||
        mode == Context::SuccessorMode::none) {
        return false;
    }
    pending_successor_.emplace(PendingSuccessor{
        mode,
        attempt,
        runtime_generation,
        std::move(snat_recovery),
        std::move(prepared_catalog),
        schedule_catalog_refresh,
        completed_context->domain_state,
        detach_foreground
            ? MutationLeasePtr{}
            : std::move(completed_context->retained_mutation_lease),
        detach_foreground
            ? RuntimeFirewallLifecycleCompletion::Source{}
            : std::move(completed_context->lifecycle_completion),
        detach_foreground
            ? PreownedTerminalContinuation{}
            : std::move(
                  completed_context->preowned_terminal_continuation),
        detach_foreground
            ? RuntimeFirewallLifecycleKind::background
            : completed_context->lifecycle_kind,
        detach_foreground
            ? 0U
            : completed_context->foreground_transport_rejections,
        detach_foreground
            ? false
            : completed_context->preapply_commit_observed});
    // Promote the already-proven repeating wake before the old terminal is
    // retired. A failed successor oneshot registration therefore cannot leave
    // the exact lifecycle lease/source waiting for an unrelated future event.
    if (completed_context->watchdog_task_id >= 0) {
        pending_successor_watchdog_task_id_ =
            std::exchange(completed_context->watchdog_task_id, -1);
        pending_successor_watchdog_serial_ =
            completed_context->watchdog_serial;
    }
    return true;
}

bool RuntimeFirewallOperationOwner::launch_pending_successor() {
    if (!pending_successor_) {
        cancel_pending_successor_watchdog();
        return true;
    }
    if (shutdown_requested() || active_context_) return false;

    // Copying can allocate (the exact SNAT cleanup snapshot may own vectors),
    // so keep the durable slot untouched until the new coordinator/context
    // has accepted the successor.
    auto candidate = PendingSuccessor{
        pending_successor_->mode,
        pending_successor_->attempt,
        pending_successor_->runtime_generation,
        pending_successor_->snat_recovery,
        pending_successor_->prepared_catalog,
        pending_successor_->schedule_catalog_refresh,
        pending_successor_->domain_state,
        {},
        pending_successor_->lifecycle_completion,
        {},
        pending_successor_->lifecycle_kind,
        pending_successor_->foreground_transport_rejections,
        pending_successor_->preapply_commit_observed};
    if (candidate.mode == Context::SuccessorMode::none) {
        auto mutation_lease =
            std::move(pending_successor_->retained_mutation_lease);
        auto lifecycle_completion =
            std::move(pending_successor_->lifecycle_completion);
        auto terminal_continuation = std::move(
            pending_successor_->preowned_terminal_continuation);
        pending_successor_.reset();
        cancel_pending_successor_watchdog();
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = candidate.preapply_commit_observed;
        terminal.commit_ambiguous = false;
        if (terminal_continuation) {
            invoke_preowned_terminal_continuation(
                std::move(terminal_continuation),
                std::move(mutation_lease),
                std::move(terminal));
        } else {
            mutation_lease.reset();
            if (lifecycle_completion) {
                (void)lifecycle_completion.settle(std::move(terminal));
            }
        }
        return true;
    }

    bool retry_plan_required = false;
    if (candidate.mode ==
        Context::SuccessorMode::reschedule_retry) {
        try {
            retry_plan_required = plan_runtime_firewall_retry(
                candidate.attempt,
                bounded_retry_count(candidate.lifecycle_kind),
                candidate.snat_recovery.requested ||
                    coordinator_.owned_snat_recovery_pending(),
                callbacks_.urltest_waiting(
                    candidate.runtime_generation)).schedule;
        } catch (...) {
            // A failed prerequisite observation cannot prove that the
            // bounded retry policy was intentionally complete.
            retry_plan_required = true;
        }
    }

    launching_pending_successor_ = true;
    bool accepted = false;
    try {
        if (candidate.mode ==
            Context::SuccessorMode::defer_same_attempt) {
            accepted = defer_fresh(
                candidate.attempt,
                candidate.runtime_generation,
                std::move(candidate.prepared_catalog),
                candidate.schedule_catalog_refresh,
                std::move(candidate.snat_recovery),
                &pending_successor_->retained_mutation_lease,
                &pending_successor_->lifecycle_completion,
                &pending_successor_->preowned_terminal_continuation,
                candidate.lifecycle_kind,
                candidate.domain_state);
        } else {
            accepted = schedule_fresh(
                candidate.attempt,
                candidate.runtime_generation,
                std::move(candidate.snat_recovery),
                std::move(candidate.prepared_catalog),
                candidate.schedule_catalog_refresh,
                &pending_successor_->retained_mutation_lease,
                &pending_successor_->lifecycle_completion,
                &pending_successor_->preowned_terminal_continuation,
                candidate.lifecycle_kind,
                candidate.domain_state);
        }
    } catch (...) {
        launching_pending_successor_ = false;
        const auto terminal_context = active_context_;
        if (terminal_context) {
            terminal_context->preapply_commit_observed =
                candidate.preapply_commit_observed;
        }
        // schedule/defer may throw after an inline callback has already
        // transferred exact ownership. Clear the duplicate durable slot only
        // when another owner now demonstrably retains the operation.
        if (active_context_ || coordinator_.retry_pending()) {
            pending_successor_.reset();
            cancel_pending_successor_watchdog();
        }
        if (terminal_context && terminal_context->terminal_ready.load(
                                    std::memory_order_acquire)) {
            request_terminal_drain(terminal_context);
            arm_completion_watchdog(terminal_context);
        }
        if (!terminal_context && pending_successor_ &&
            !retain_pending_transport_retry_or_finish()) {
            return true;
        }
        throw;
    }
    launching_pending_successor_ = false;

    if (accepted) {
        const auto terminal_context = active_context_;
        if (terminal_context) {
            terminal_context->foreground_transport_rejections =
                candidate.foreground_transport_rejections;
            terminal_context->preapply_commit_observed =
                candidate.preapply_commit_observed;
        }
        pending_successor_.reset();
        cancel_pending_successor_watchdog();
        if (terminal_context && terminal_context->terminal_ready.load(
                                    std::memory_order_acquire)) {
            request_terminal_drain(terminal_context);
            arm_completion_watchdog(terminal_context);
        }
        return true;
    }
    if (candidate.mode == Context::SuccessorMode::reschedule_retry) {
        if (retry_plan_required) {
            // A timer-registration/collision failure is not a completed
            // bounded policy. The durable slot keeps its exact authority and
            // the promoted watchdog retries the same exact successor.
            return retain_pending_transport_retry_or_finish()
                ? false
                : true;
        }
        // A normal no-plan result means the bounded policy intentionally
        // completed. This differs from defer rejection, where periodic health
        // must get another chance to launch the exact retained intent.
        // START/RESTART release admission before waking their waiter. Config
        // pre-apply/candidate/rollback instead return the same physical token
        // to the durable caller continuation; no second acquisition is
        // permitted.
        auto mutation_lease =
            std::move(pending_successor_->retained_mutation_lease);
        auto lifecycle_completion =
            std::move(pending_successor_->lifecycle_completion);
        auto terminal_continuation = std::move(
            pending_successor_->preowned_terminal_continuation);
        pending_successor_.reset();
        cancel_pending_successor_watchdog();
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = candidate.preapply_commit_observed;
        terminal.commit_ambiguous = false;
        if (terminal_continuation) {
            invoke_preowned_terminal_continuation(
                std::move(terminal_continuation),
                std::move(mutation_lease),
                std::move(terminal));
        } else {
            mutation_lease.reset();
            if (lifecycle_completion) {
                (void)lifecycle_completion.settle(std::move(terminal));
            }
        }
        return true;
    }
    return retain_pending_transport_retry_or_finish()
        ? false
        : true;
}

bool RuntimeFirewallOperationOwner::pending_successor() const noexcept {
    return pending_successor_.has_value();
}

const RuntimeFirewallOperationOwner::PendingSuccessor*
RuntimeFirewallOperationOwner::pending_successor_state() const noexcept {
    return pending_successor_ ? &*pending_successor_ : nullptr;
}

std::optional<RuntimeFirewallOperationOwner::
    PreownedContinuationFinalizationPermit>
RuntimeFirewallOperationOwner::prepare_preowned_continuation_finalization(
    const ContextPtr& context) const noexcept {
    if (!is_active(context) || pending_successor_ ||
        launching_pending_successor_ ||
        !runtime_firewall_lifecycle_uses_preowned_continuation(
            context->lifecycle_kind) ||
        context->lifecycle_completion ||
        !context->preowned_terminal_continuation ||
        !context->retained_mutation_lease ||
        !context->terminal_owner) {
        return std::nullopt;
    }
    return PreownedContinuationFinalizationPermit{context};
}

bool RuntimeFirewallOperationOwner::complete_preowned_continuation(
    PreownedContinuationFinalizationPermit&& permit,
    TerminalFinalizationProof&& finalization_proof,
    RuntimeFirewallLifecycleTerminal terminal) noexcept {
    const auto context = permit.context_;
    if (!context || !context->terminal_owner) {
        return false;
    }

    // The owner serializes normal background intent into the active config
    // context. Defensively retire a timer installed directly on the shared
    // coordinator before returning the exact writer lease. A queued/running
    // foreign claim cannot be cancelled safely; in that impossible-through-
    // owner state, keep the continuation and lease instead of allowing a
    // background replay after authority has returned to the config writer.
    if (coordinator_.retry_pending()) {
        try {
            coordinator_.cancel([this](int task_id) {
                callbacks_.cancel_scheduled(task_id);
            });
        } catch (...) {
        }
        if (coordinator_.retry_pending()) {
            return false;
        }
    }
    if (!finalization_proof.consume_for(
            context->terminal_owner.get())) {
        return false;
    }
    permit.context_.reset();

    auto continuation =
        std::move(context->preowned_terminal_continuation);
    auto mutation_lease = std::move(context->retained_mutation_lease);
    cancel_completion_watchdog();
    reset_if_active(context);
    invoke_preowned_terminal_continuation(
        std::move(continuation),
        std::move(mutation_lease),
        std::move(terminal));
    return true;
}

bool RuntimeFirewallOperationOwner::
retain_pending_transport_retry_or_finish() noexcept {
    if (!pending_successor_ ||
        !runtime_firewall_lifecycle_is_foreground(
            pending_successor_->lifecycle_kind)) {
        return true;
    }
    if (pending_successor_->foreground_transport_rejections <
        kForegroundTransportRetryLimit) {
        ++pending_successor_->foreground_transport_rejections;
    }
    if (pending_successor_->foreground_transport_rejections <
        kForegroundTransportRetryLimit) {
        return true;
    }

    // START must not be settled directly from this transport-only owner: its
    // prior attempt may already have published resolver/firewall state and
    // only Daemon owns the rollback/broken-state policy. Convert the durable
    // pending slot back into one terminal context and let the normal terminal
    // drain finish it. Allocation failure leaves the slot and promoted
    // watchdog intact for another tick.
    return !terminalize_pending_foreground_transport_exhaustion();
}

bool RuntimeFirewallOperationOwner::
terminalize_pending_foreground_transport_exhaustion() noexcept {
    if (!pending_successor_ || active_context_ ||
        pending_successor_watchdog_task_id_ < 0 ||
        !runtime_firewall_lifecycle_is_foreground(
            pending_successor_->lifecycle_kind)) {
        return false;
    }

    ContextPtr context;
    try {
        context = ensure_context(pending_successor_->domain_state);
    } catch (...) {
        return false;
    }

    context->retained_mutation_lease =
        std::move(pending_successor_->retained_mutation_lease);
    context->lifecycle_completion =
        std::move(pending_successor_->lifecycle_completion);
    context->preowned_terminal_continuation =
        std::move(pending_successor_->preowned_terminal_continuation);
    context->lifecycle_kind = pending_successor_->lifecycle_kind;
    context->foreground_transport_rejections =
        pending_successor_->foreground_transport_rejections;
    context->preapply_commit_observed =
        pending_successor_->preapply_commit_observed;
    context->foreground_transport_exhausted = true;
    context->queued_claim.runtime_generation =
        pending_successor_->runtime_generation;
    context->queued_claim.attempt = pending_successor_->attempt;
    context->successor_runtime_generation =
        pending_successor_->runtime_generation;
    context->successor_attempt = pending_successor_->attempt;
    context->successor_mode = Context::SuccessorMode::none;
    context->force_successor = false;
    context->successor_schedule_catalog_refresh =
        pending_successor_->schedule_catalog_refresh;

    // Reattach the already-proven repeating wake before retiring the pending
    // slot. The synthetic completion below is allocation-free and the active
    // context now owns the only lease/source plus its independent drain wake.
    context->watchdog_task_id =
        std::exchange(pending_successor_watchdog_task_id_, -1);
    context->watchdog_serial = pending_successor_watchdog_serial_;
    pending_successor_watchdog_serial_ = 0U;
    RuntimeFirewallOperationCompletion terminal;
    terminal.owned = true;
    terminal.rerun_requested = true;
    terminal.snat_recovery =
        std::move(pending_successor_->snat_recovery);
    terminal.next_prepared_catalog =
        std::move(pending_successor_->prepared_catalog);
    pending_successor_.reset();
    context->terminal_owner->coordinator_terminal_sink()(
        std::move(terminal));
    request_terminal_drain(context);
    return true;
}

void RuntimeFirewallOperationOwner::terminate_before_worker(
    const ContextPtr& context,
    RuntimeFirewallOperationClaim claim,
    Context::SuccessorMode successor_mode,
    bool force_rerun) noexcept {
    if (!context || !context->terminal_owner) return;
    context->successor_mode = successor_mode;
    context->force_successor = force_rerun;
    context->preworker_terminal_claim = claim;
    context->preworker_terminal_successor_mode = successor_mode;
    context->preworker_terminal_force_rerun = force_rerun;
    context->preworker_terminal_retry_pending = true;
    pump_preworker_terminal(context);
    if (context->preworker_terminal_retry_pending) {
        (void)arm_completion_watchdog(context);
    }
}

bool RuntimeFirewallOperationOwner::enqueue_worker(
    const ContextPtr& context,
    RuntimeFirewallOperationClaim claim,
    std::shared_ptr<const RuntimeFirewallWorkerAttemptInput> input,
    std::unique_ptr<RuntimeMutationAdmission::Lease> mutation_lease,
    WorkerRunner runner) {
    if (!context || !context->terminal_owner || !input || !mutation_lease ||
        !runner) {
        return false;
    }
    context->worker_input = std::move(input);
    context->worker_operation = RuntimeFirewallDelayedWorker::create(
        coordinator_,
        claim,
        context->worker_input,
        std::move(mutation_lease),
        context->terminal_owner->worker_terminal_mailbox());
    std::function<void()> closure;
    try {
        closure = context->worker_operation->make_queued_closure(
            std::move(runner));
    } catch (...) {
        // No queue envelope exists. Destroying the operation publishes the
        // one exact pre-worker terminal instead of stranding its claim.
        context->worker_operation.reset();
        throw;
    }
    const bool queued = executor_.try_post(
        "runtime-firewall-attempt", std::move(closure));
    (void)queued;
    // On rejection the destroyed queue envelope is the sole exact terminal.
    return queued;
}

bool RuntimeFirewallOperationOwner::enqueue_worker_with_retained_lease(
    const ContextPtr& context,
    RuntimeFirewallOperationClaim claim,
    std::shared_ptr<const RuntimeFirewallWorkerAttemptInput> input,
    WorkerRunner runner) {
    if (!context || !context->terminal_owner || !input || !runner ||
        !context->retained_mutation_lease || context->worker_operation ||
        !claim ||
        claim.phase != RuntimeFirewallOperationPhase::worker_queued ||
        !coordinator_.operation_is_current(claim)) {
        return false;
    }

    context->worker_input = std::move(input);
    context->worker_operation = RuntimeFirewallDelayedWorker::create(
        coordinator_,
        claim,
        context->worker_input,
        RuntimeFirewallDelayedWorker::MutationLeaseBinding::retained_lease(
            std::move(context->retained_mutation_lease)),
        context->terminal_owner->worker_terminal_mailbox());
    std::function<void()> closure;
    try {
        closure = context->worker_operation->make_queued_closure(
            std::move(runner));
    } catch (...) {
        // The mailbox now owns the exact outer lease. Force its durable
        // pre-worker terminal before propagating the preparation failure.
        context->worker_operation.reset();
        throw;
    }
    const bool queued = executor_.try_post(
        "runtime-firewall-attempt", std::move(closure));
    (void)queued;
    return queued;
}

bool RuntimeFirewallOperationOwner::enqueue_auxiliary(
    const ContextPtr& context,
    std::string label,
    std::function<void()> task) noexcept {
    if (!task || !is_active(context) || shutdown_requested()) {
        return false;
    }
    try {
        return executor_.try_post(std::move(label), std::move(task));
    } catch (...) {
        return false;
    }
}

void RuntimeFirewallOperationOwner::request_terminal_drain(
    const ContextPtr& context) noexcept {
    // This entry point can run on the worker thread. Active-context ownership
    // remains control-loop-only, so defer that comparison to the posted
    // callback instead of racing the control loop's shared_ptr.
    if (!context) return;
    bool expected = false;
    if (!context->drain_post_inflight.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        return;
    }

    bool posted = false;
    try {
        std::weak_ptr<Context> weak_context{context};
        const auto weak_self = weak_from_this();
        posted = callbacks_.post_control(
            [weak_self, weak_context]() {
                const auto self = weak_self.lock();
                const auto retained = weak_context.lock();
                if (!self || !retained) return;
                self->dispatch_terminal_drain(
                    retained, self->shutdown_requested());
                retained->drain_post_inflight.store(
                    false, std::memory_order_release);
            },
            "runtime-firewall-terminal");
    } catch (...) {
        posted = false;
    }
    if (!posted) {
        context->drain_post_inflight.store(
            false, std::memory_order_release);
    }
}

void RuntimeFirewallOperationOwner::dispatch_terminal_drain(
    const ContextPtr& context,
    bool shutdown) noexcept {
    if (!is_active(context)) return;
    if (launching_pending_successor_) {
        // A scheduler may publish its rejection terminal synchronously while
        // the old PendingSuccessor slot is still the only rollback owner.
        // Classify acceptance first; launch_pending_successor() explicitly
        // re-arms a genuinely accepted inline terminal afterwards.
        return;
    }
    // A timer-registration failure can reach this path without a mailbox
    // terminal yet. Retry the exact scalar queued claim before asking the
    // daemon to drain; with the coordinator's non-throwing ownership lock an
    // empty result now means another authoritative terminal already won.
    pump_preworker_terminal(context);
    try {
        callbacks_.drain_terminal(context, shutdown);
    } catch (const std::exception& error) {
        try {
            Logger::instance().error(
                "Runtime firewall terminal drain failed: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().error(
                "Runtime firewall terminal drain failed: unknown error");
        } catch (...) {
        }
    }
}

void RuntimeFirewallOperationOwner::pump_preworker_terminal(
    const ContextPtr& context) noexcept {
    if (!context || !context->terminal_owner ||
        !context->preworker_terminal_retry_pending) {
        return;
    }

    auto completion = coordinator_.terminate_operation_for_resnapshot(
        context->preworker_terminal_claim,
        context->preworker_terminal_force_rerun);

    if (!completion.owned) {
        // The non-throwing coordinator lock makes empty an exact stale-claim
        // result. Keep the owner parked until the authoritative terminal that
        // won that phase reaches its mailbox/sink.
        return;
    }
    context->preworker_terminal_retry_pending = false;
    context->successor_mode =
        context->preworker_terminal_successor_mode;
    context->force_successor =
        context->preworker_terminal_force_rerun;
    context->terminal_owner->coordinator_terminal_sink()(
        std::move(completion));
}

void RuntimeFirewallOperationOwner::pump_pending_successor(
    std::uint64_t watchdog_serial) noexcept {
    if (watchdog_serial == 0U ||
        pending_successor_watchdog_task_id_ < 0 ||
        pending_successor_watchdog_serial_ != watchdog_serial ||
        !pending_successor_ || active_context_ ||
        launching_pending_successor_ || shutdown_requested()) {
        return;
    }
    try {
        (void)launch_pending_successor();
    } catch (const std::exception& error) {
        try {
            Logger::instance().error(
                "Runtime firewall pending successor wake failed: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().error(
                "Runtime firewall pending successor wake failed: unknown "
                "error");
        } catch (...) {
        }
    }
}

bool RuntimeFirewallOperationOwner::arm_completion_watchdog(
    const ContextPtr& context) noexcept {
    if (!is_active(context)) return true;
    if (context->watchdog_task_id != -1) return true;

    watchdog_serial_counter_ =
        next_nonzero_serial(watchdog_serial_counter_);
    context->watchdog_serial = watchdog_serial_counter_;
    const auto serial = context->watchdog_serial;
    context->watchdog_task_id = -2;
    std::weak_ptr<Context> weak_context{context};
    const auto weak_self = weak_from_this();
    int task_id = -1;
    try {
        task_id = callbacks_.schedule_repeating(
            kTerminalWatchdogDelay,
            [weak_self, weak_context, serial]() {
                const auto self = weak_self.lock();
                if (!self) return;
                const auto retained = weak_context.lock();
                if (retained &&
                    retained->watchdog_serial == serial &&
                    self->is_active(retained)) {
                    self->pump_preworker_terminal(retained);
                    if (!self->is_active(retained)) return;
                    if (retained->pump_worker_checkpoint) {
                        try {
                            retained->pump_worker_checkpoint();
                        } catch (...) {
                        }
                    }
                    if (!retained->drain_post_inflight.load(
                            std::memory_order_acquire)) {
                        self->dispatch_terminal_drain(
                            retained, self->shutdown_requested());
                    }
                    // The drain may promote this very timer and perform one
                    // eager successor launch. Do not immediately launch the
                    // same pending slot a second time in the same watchdog
                    // tick; the next 200-ms tick is its retry boundary.
                    return;
                }
                self->pump_pending_successor(serial);
            },
            "runtime-firewall-terminal-watchdog");
    } catch (const std::exception& error) {
        if (context->watchdog_serial == serial &&
            context->watchdog_task_id == -2) {
            context->watchdog_task_id = -1;
        }
        try {
            Logger::instance().error(
                "Runtime firewall terminal watchdog could not be armed: {}",
                error.what());
        } catch (...) {
        }
        dispatch_terminal_drain(context, shutdown_requested());
        return !is_active(context);
    } catch (...) {
        if (context->watchdog_serial == serial &&
            context->watchdog_task_id == -2) {
            context->watchdog_task_id = -1;
        }
        try {
            Logger::instance().error(
                "Runtime firewall terminal watchdog could not be armed: "
                "unknown error");
        } catch (...) {
        }
        dispatch_terminal_drain(context, shutdown_requested());
        return !is_active(context);
    }

    if (task_id < 0) {
        if (context->watchdog_serial == serial &&
            context->watchdog_task_id == -2) {
            context->watchdog_task_id = -1;
        }
        try {
            Logger::instance().error(
                "Runtime firewall terminal watchdog registration was "
                "rejected.");
        } catch (...) {
        }
        dispatch_terminal_drain(context, shutdown_requested());
        return !is_active(context);
    }
    if (is_active(context) && context->watchdog_serial == serial &&
        context->watchdog_task_id == -2) {
        context->watchdog_task_id = task_id;
        return true;
    }
    if (task_id >= 0) {
        try {
            callbacks_.cancel_scheduled(task_id);
        } catch (...) {
        }
    }
    return !is_active(context);
}

void RuntimeFirewallOperationOwner::cancel_completion_watchdog() noexcept {
    const auto context = active_context_;
    if (!context) return;
    const int task_id = std::exchange(context->watchdog_task_id, -1);
    context->watchdog_serial =
        next_nonzero_serial(context->watchdog_serial);
    if (task_id < 0) return;
    try {
        callbacks_.cancel_scheduled(task_id);
    } catch (...) {
    }
}

void RuntimeFirewallOperationOwner::cancel_pending_successor_watchdog()
    noexcept {
    const int task_id =
        std::exchange(pending_successor_watchdog_task_id_, -1);
    pending_successor_watchdog_serial_ = 0U;
    if (task_id < 0) return;
    try {
        callbacks_.cancel_scheduled(task_id);
    } catch (...) {
    }
}

void RuntimeFirewallOperationOwner::pump_terminal_for_shutdown() noexcept {
    const auto context = active_context_;
    if (!context) return;
    if (context->cancel_worker_checkpoint) {
        try {
            context->cancel_worker_checkpoint();
        } catch (...) {
        }
    }
    dispatch_terminal_drain(context, /*shutdown=*/true);
}

void RuntimeFirewallOperationOwner::cancel_pending_work() noexcept {
    cancel_pending_work_impl(/*publish_preowned_terminal=*/true);
}

void RuntimeFirewallOperationOwner::cancel_pending_work_impl(
    bool publish_preowned_terminal) noexcept {
    // Shutdown calls this before waiting for mutation admission to become
    // idle. First retire the durable slot and its watchdog; only then may a
    // normal shutdown continuation re-enter the caller with the exact token.
    MutationLeasePtr mutation_lease;
    RuntimeFirewallLifecycleCompletion::Source lifecycle_completion;
    PreownedTerminalContinuation terminal_continuation;
    bool preapply_commit_observed = false;
    if (pending_successor_) {
        mutation_lease =
            std::move(pending_successor_->retained_mutation_lease);
        lifecycle_completion =
            std::move(pending_successor_->lifecycle_completion);
        terminal_continuation = std::move(
            pending_successor_->preowned_terminal_continuation);
        preapply_commit_observed =
            pending_successor_->preapply_commit_observed;
    }
    pending_successor_.reset();
    cancel_pending_successor_watchdog();
    launching_pending_successor_ = false;

    RuntimeFirewallLifecycleTerminal terminal;
    terminal.outcome = RuntimeFirewallLifecycleOutcome::shutdown;
    terminal.committed = preapply_commit_observed;
    terminal.commit_ambiguous = false;
    if (publish_preowned_terminal && terminal_continuation) {
        invoke_preowned_terminal_continuation(
            std::move(terminal_continuation),
            std::move(mutation_lease),
            std::move(terminal));
    } else {
        // START/RESTART preserve their existing waiter contract. A destructor
        // fallback deliberately destroys a config-preapply callback without
        // invoking external code; its lease is then released here.
        terminal_continuation = {};
        mutation_lease.reset();
        if (lifecycle_completion) {
            (void)lifecycle_completion.settle(std::move(terminal));
        }
    }
    try {
        executor_.cancel_pending();
    } catch (...) {
    }
}

void RuntimeFirewallOperationOwner::shutdown_executor() noexcept {
    try {
        executor_.cancel_pending_and_shutdown();
    } catch (...) {
    }
}

} // namespace keen_pbr3
