#pragma once

#include "runtime_firewall_worker_operation.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {

namespace detail {

// The coordinator terminal sink is noexcept and runs only after the retry
// coordinator has transferred its exact catalogue/recovery authority.  A
// throwing platform mutex at that point would make it impossible to return
// ownership.  This tiny per-operation lock has a non-throwing acquisition
// path; owner critical sections are deliberately bounded and never wait for
// worker execution or invoke the control wake callback.
class RuntimeFirewallTerminalOwnerMutex final {
public:
    RuntimeFirewallTerminalOwnerMutex() noexcept = default;
    RuntimeFirewallTerminalOwnerMutex(
        const RuntimeFirewallTerminalOwnerMutex&) = delete;
    RuntimeFirewallTerminalOwnerMutex& operator=(
        const RuntimeFirewallTerminalOwnerMutex&) = delete;

    void lock() noexcept {
        while (locked_.test_and_set(std::memory_order_acquire)) {
        }
    }

    void unlock() noexcept {
        locked_.clear(std::memory_order_release);
    }

private:
    std::atomic_flag locked_ = ATOMIC_FLAG_INIT;
};

} // namespace detail

// Durable control-loop owner for one asynchronous runtime-firewall terminal.
//
// RuntimeFirewallWorkerOperation publishes into a one-shot mailbox. Taking an
// envelope directly from that mailbox is insufficient for production use: a
// throwing control continuation would destroy the local envelope, release its
// mutation lease and strand a still-current coordinator claim. This owner
// moves the envelope into stable storage before it grants drain ownership and
// retains it until the control path explicitly proves terminal completion.
//
// One owner belongs to one logical operation. create() wires the mailbox wake
// through a weak_ptr, so the mailbox retained by a queued worker cannot keep
// the control owner alive. The independent coordinator_terminal_sink() is the
// noexcept destination required by exact-catalogue schedule/defer rejection;
// it only retains the completion and requests a control drain.
template <typename Input, typename Result>
class RuntimeFirewallTerminalOwner final
    : public std::enable_shared_from_this<
          RuntimeFirewallTerminalOwner<Input, Result>> {
public:
    using Owner = RuntimeFirewallTerminalOwner<Input, Result>;
    using OwnerPtr = std::shared_ptr<Owner>;
    using WorkerOperation =
        RuntimeFirewallWorkerOperation<Input, Result>;
    using WorkerTerminal = typename WorkerOperation::TerminalEnvelope;
    using WorkerTerminalStatus = typename WorkerOperation::TerminalStatus;
    using WorkerTerminalMailboxPtr =
        typename WorkerOperation::TerminalMailboxPtr;
    using MutationLeasePtr =
        typename WorkerOperation::MutationLeasePtr;
    using MutationLeaseReturnPolicy =
        typename WorkerOperation::MutationLeaseReturnPolicy;
    using OnDrainReady = std::function<void()>;

    enum class DrainKind : std::uint8_t {
        worker,
        coordinator,
    };

    // A concrete noexcept callback rather than std::function: the typed retry
    // coordinator statically rejects a possibly-throwing terminal sink.
    class CoordinatorTerminalSink final {
    public:
        void operator()(
            RuntimeFirewallOperationCompletion completion) const noexcept {
            const auto owner = owner_.lock();
            if (!owner) return;
            owner->retain_coordinator_terminal(std::move(completion));
        }

    private:
        friend class RuntimeFirewallTerminalOwner<Input, Result>;

        explicit CoordinatorTerminalSink(
            std::weak_ptr<Owner> owner) noexcept
            : owner_(std::move(owner)) {}

        std::weak_ptr<Owner> owner_;
    };

    class DrainGuard;

    // Move-only evidence that this exact terminal owner accepted and closed
    // one authoritative DrainGuard terminal. It can be minted only by a
    // successful finish_worker_terminal()/finish_coordinator_terminal() and
    // consumed only once for the same owner instance. A bare coordinator
    // completion is deliberately insufficient evidence.
    class FinalizationProof final {
    public:
        FinalizationProof() noexcept = default;

        FinalizationProof(FinalizationProof&&) noexcept = default;
        FinalizationProof& operator=(FinalizationProof&&) noexcept = default;

        FinalizationProof(const FinalizationProof&) = delete;
        FinalizationProof& operator=(const FinalizationProof&) = delete;

        explicit operator bool() const noexcept {
            return !owner_.expired();
        }

        bool consume_for(const Owner* expected_owner) noexcept {
            const auto retained = owner_.lock();
            if (!expected_owner || retained.get() != expected_owner) {
                return false;
            }
            owner_.reset();
            return true;
        }

    private:
        friend class DrainGuard;

        explicit FinalizationProof(const OwnerPtr& owner) noexcept
            : owner_(owner) {}

        std::weak_ptr<Owner> owner_;
    };

    static_assert(
        std::is_nothrow_move_constructible_v<FinalizationProof>);
    static_assert(
        std::is_nothrow_move_assignable_v<FinalizationProof>);

    // Exclusive, move-only right to inspect and advance one retained terminal.
    // Unless finish_* succeeds, destruction re-arms the same stable terminal
    // for a later control pass. This is the exception boundary around daemon
    // publication: a continuation may throw without moving out or losing the
    // result, completion, exact catalogue, coordinator proof, or lease.
    class DrainGuard final {
    public:
        ~DrainGuard() noexcept { retry(); }

        DrainGuard(const DrainGuard&) = delete;
        DrainGuard& operator=(const DrainGuard&) = delete;

        DrainGuard(DrainGuard&& other) noexcept
            : owner_(std::move(other.owner_)),
              serial_(std::exchange(other.serial_, 0U)),
              kind_(other.kind_) {}

        DrainGuard& operator=(DrainGuard&& other) noexcept {
            if (this == &other) return *this;
            retry();
            owner_ = std::move(other.owner_);
            serial_ = std::exchange(other.serial_, 0U);
            kind_ = other.kind_;
            return *this;
        }

        explicit operator bool() const noexcept {
            return owner_ && serial_ != 0U;
        }

        DrainKind kind() const noexcept { return kind_; }

        // Stable views: neither terminal can be moved out. References remain
        // valid until this guard successfully finishes the corresponding
        // terminal. A retry guard sees the same retained object.
        const WorkerTerminal* worker_terminal() const noexcept {
            return owner_
                ? owner_->worker_terminal_for(serial_, kind_)
                : nullptr;
        }

        const RuntimeFirewallOperationCompletion*
        coordinator_terminal() const noexcept {
            return owner_
                ? owner_->coordinator_terminal_for(serial_, kind_)
                : nullptr;
        }

        const RuntimeFirewallOperationCompletion*
        worker_control_completion() const noexcept {
            return owner_
                ? owner_->worker_control_completion_for(serial_, kind_)
                : nullptr;
        }

        const RuntimeFirewallOperationClaim*
        worker_control_claim() const noexcept {
            return owner_
                ? owner_->worker_control_claim_for(serial_, kind_)
                : nullptr;
        }

        // The owner performs the one-way coordinator transition and retains
        // the resulting claim in the same critical section. There is no
        // caller-visible "begin, then remember" window which could strand a
        // control_pending claim after an exception or failed second lock.
        bool begin_worker_control(
            RuntimeFirewallRetryCoordinator& coordinator) noexcept {
            return owner_ && owner_->begin_worker_control(
                serial_, kind_, coordinator);
        }

        // Publication is executed by the owner as one non-throwing,
        // idempotent transaction and checkpointed before this call returns.
        // A callback returning false must either have made no change or be
        // safe to repeat. Once true is retained, retries never invoke it
        // again and proceed directly to coordinator completion.
        template <typename Publish>
        bool publish_worker_control(Publish&& publish) noexcept {
            static_assert(
                std::is_nothrow_invocable_r_v<
                    bool,
                    std::decay_t<Publish>&>,
                "control publication must be a noexcept bool transaction");
            return owner_ && owner_->publish_worker_control(
                serial_,
                kind_,
                std::forward<Publish>(publish));
        }

        // Likewise, coordinator completion and durable retention are one
        // owner operation. complete_operation_into() finishes every allocating
        // copy, stores the result directly in this owner's sentinel slot and
        // only then releases coordinator ownership. If preparation throws,
        // the retained control claim remains current and DrainGuard re-arms it.
        bool complete_worker_control(
            RuntimeFirewallRetryCoordinator& coordinator,
            bool succeeded,
            OwnedSnatRecovery processed_recovery) {
            return owner_ && owner_->complete_worker_control(
                serial_,
                kind_,
                coordinator,
                succeeded,
                std::move(processed_recovery));
        }

        // Admission must remain held through control publication and
        // coordinator completion. Therefore release is rejected until an
        // owned completion has been durably recorded. A retained pre-worker
        // lease uses take_retained_mutation_lease() instead.
        bool release_worker_lease() noexcept {
            return owner_ &&
                   owner_->release_worker_lease(serial_, kind_);
        }

        // A lease admitted by an outer operation owner is never released by
        // this attempt. Move that exact token back only after the terminal's
        // authoritative coordinator completion is durably retained.
        MutationLeasePtr take_retained_mutation_lease() noexcept {
            return owner_
                ? owner_->take_retained_mutation_lease(serial_, kind_)
                : MutationLeasePtr{};
        }

        std::optional<FinalizationProof>
        finish_worker_terminal() noexcept {
            const auto finalized_owner = owner_;
            if (!finalized_owner ||
                !finalized_owner->finish_worker_terminal(
                    serial_, kind_)) {
                return std::nullopt;
            }
            disarm();
            auto proof = FinalizationProof{finalized_owner};
            return std::optional<FinalizationProof>{std::move(proof)};
        }

        std::optional<FinalizationProof>
        finish_coordinator_terminal() noexcept {
            const auto finalized_owner = owner_;
            if (!finalized_owner ||
                !finalized_owner->finish_coordinator_terminal(
                    serial_, kind_)) {
                return std::nullopt;
            }
            disarm();
            auto proof = FinalizationProof{finalized_owner};
            return std::optional<FinalizationProof>{std::move(proof)};
        }

        void retry() noexcept {
            if (!owner_ || serial_ == 0U) return;
            auto owner = std::move(owner_);
            const auto serial = std::exchange(serial_, 0U);
            owner->release_drain_for_retry(serial);
        }

        // An external asynchronous tail (resolver activation or rollback)
        // keeps the retained terminal authoritative but deliberately does not
        // request another control pass until its exact completion callback.
        // This avoids the busy-loop produced by the ordinary retry guard.
        void park_until_wake() noexcept {
            if (!owner_ || serial_ == 0U) return;
            auto owner = std::move(owner_);
            const auto serial = std::exchange(serial_, 0U);
            owner->release_drain_for_park(serial);
        }

    private:
        friend class RuntimeFirewallTerminalOwner<Input, Result>;

        DrainGuard(OwnerPtr owner,
                   std::uint64_t serial,
                   DrainKind kind) noexcept
            : owner_(std::move(owner)), serial_(serial), kind_(kind) {}

        void disarm() noexcept {
            serial_ = 0U;
            owner_.reset();
        }

        OwnerPtr owner_;
        std::uint64_t serial_{0U};
        DrainKind kind_{DrainKind::worker};
    };

    static_assert(
        std::is_nothrow_move_constructible_v<WorkerTerminal>,
        "worker terminal retention must not fail after mailbox take");
    static_assert(
        std::is_nothrow_move_constructible_v<
            RuntimeFirewallOperationCompletion>,
        "coordinator terminal retention must be allocation-free");
    static_assert(
        std::is_nothrow_copy_constructible_v<
            RuntimeFirewallOperationClaim>,
        "control claim retention must not fail after begin_control");
    static_assert(
        std::is_nothrow_invocable_v<
            CoordinatorTerminalSink&,
            RuntimeFirewallOperationCompletion>,
        "coordinator terminal sink must remain noexcept");

    static OwnerPtr create(OnDrainReady on_drain_ready = {}) {
        auto owner = OwnerPtr(new Owner(std::move(on_drain_ready)));
        std::weak_ptr<Owner> weak_owner{owner};
        owner->self_weak_ = weak_owner;
        owner->worker_terminal_mailbox_ =
            WorkerOperation::create_terminal_mailbox(
                [weak_owner]() noexcept {
                    const auto retained = weak_owner.lock();
                    if (retained) retained->notify_drain_ready();
                });
        return owner;
    }

    RuntimeFirewallTerminalOwner(
        const RuntimeFirewallTerminalOwner&) = delete;
    RuntimeFirewallTerminalOwner& operator=(
        const RuntimeFirewallTerminalOwner&) = delete;

    WorkerTerminalMailboxPtr worker_terminal_mailbox() const noexcept {
        return worker_terminal_mailbox_;
    }

    CoordinatorTerminalSink coordinator_terminal_sink() const noexcept {
        return CoordinatorTerminalSink{self_weak_};
    }

    // Watchdogs and posted control continuations use the same entry point.
    // The mailbox is consumed into owner storage before a DrainGuard is
    // returned. At most one guard exists; another caller observes no work.
    std::optional<DrainGuard> try_begin_drain() {
        std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(mutex_);
        if (closed_ || drain_active_) return std::nullopt;

        // Always absorb an already-published mailbox terminal, even when the
        // coordinator terminal won the race. The coordinator completion has
        // drain priority; a pre-worker lost envelope is its subordinate
        // second source, after any retained lease is returned exactly once.
        if (!worker_terminal_.has_value()) {
            auto terminal = worker_terminal_mailbox_->take_terminal();
            if (terminal.has_value()) {
                worker_terminal_.emplace(std::move(*terminal));
            }
        }

        DrainKind kind{DrainKind::worker};
        if (coordinator_terminal_.has_value()) {
            // A pre-owned lease may still be inside the accepted queue
            // envelope. Closing the coordinator terminal now would make its
            // later lost_claim unobservable and destroy the caller's token.
            // The mailbox publishes another wake after moving the binding
            // into its terminal envelope.
            if (!worker_terminal_.has_value() &&
                worker_terminal_mailbox_
                    ->retained_mutation_lease_pending()) {
                return std::nullopt;
            }
            kind = DrainKind::coordinator;
        } else if (!worker_terminal_.has_value() ||
                   provisional_preworker_loser_locked()) {
            // A bare pre-worker lost_claim is not a terminal authority. The
            // coordinator may already have extracted the exact completion
            // and be about to enter its noexcept sink. Keep the owner and the
            // loser intact until that authoritative second source arrives.
            return std::nullopt;
        }

        drain_active_ = true;
        drain_serial_ = next_nonzero(drain_serial_);
        return std::optional<DrainGuard>{DrainGuard{
            this->shared_from_this(), drain_serial_, kind}};
    }

private:
    explicit RuntimeFirewallTerminalOwner(
        OnDrainReady on_drain_ready) noexcept
        : on_drain_ready_(std::move(on_drain_ready)) {}

    static std::uint64_t next_nonzero(std::uint64_t value) noexcept {
        ++value;
        if (value == 0U) ++value;
        return value;
    }

    bool guard_matches_locked(
        std::uint64_t serial,
        DrainKind kind) const noexcept {
        return !closed_ && drain_active_ && serial != 0U &&
               serial == drain_serial_ && active_kind_unsafe() == kind;
    }

    DrainKind active_kind_unsafe() const noexcept {
        return coordinator_terminal_.has_value()
            ? DrainKind::coordinator
            : DrainKind::worker;
    }

    bool provisional_preworker_loser_locked() const noexcept {
        return worker_terminal_.has_value() &&
               worker_terminal_->status ==
                   WorkerTerminalStatus::lost_claim &&
               !worker_terminal_->running_claim.has_value() &&
               !worker_terminal_->coordinator_completion.has_value();
    }

    const WorkerTerminal* worker_terminal_for(
        std::uint64_t serial,
        DrainKind kind) const noexcept {
        try {
            std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(mutex_);
            if (!guard_matches_locked(serial, kind) ||
                kind != DrainKind::worker) {
                return nullptr;
            }
            return worker_terminal_ ? &*worker_terminal_ : nullptr;
        } catch (...) {
            return nullptr;
        }
    }

    const RuntimeFirewallOperationCompletion* coordinator_terminal_for(
        std::uint64_t serial,
        DrainKind kind) const noexcept {
        try {
            std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(mutex_);
            if (!guard_matches_locked(serial, kind) ||
                kind != DrainKind::coordinator) {
                return nullptr;
            }
            return coordinator_terminal_
                ? &*coordinator_terminal_
                : nullptr;
        } catch (...) {
            return nullptr;
        }
    }

    const RuntimeFirewallOperationCompletion*
    worker_control_completion_for(
        std::uint64_t serial,
        DrainKind kind) const noexcept {
        try {
            std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(mutex_);
            if (!guard_matches_locked(serial, kind) ||
                kind != DrainKind::worker) {
                return nullptr;
            }
            return worker_control_completion_.owned
                ? &worker_control_completion_
                : nullptr;
        } catch (...) {
            return nullptr;
        }
    }

    const RuntimeFirewallOperationClaim* worker_control_claim_for(
        std::uint64_t serial,
        DrainKind kind) const noexcept {
        try {
            std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(mutex_);
            if (!guard_matches_locked(serial, kind) ||
                kind != DrainKind::worker) {
                return nullptr;
            }
            return worker_control_claim_
                ? &worker_control_claim_
                : nullptr;
        } catch (...) {
            return nullptr;
        }
    }

    static bool same_operation_identity(
        const RuntimeFirewallOperationClaim& left,
        const RuntimeFirewallOperationClaim& right) noexcept {
        return left.serial == right.serial &&
               left.runtime_generation == right.runtime_generation &&
               left.attempt == right.attempt &&
               left.recovery_revision == right.recovery_revision;
    }

    // Cross-object transition lock order is always owner -> coordinator.
    // Retry terminal callbacks acquire the owner only after coordinator
    // methods have returned and released operation_mutex_, so the reverse
    // order does not exist.

    bool begin_worker_control(
        std::uint64_t serial,
        DrainKind kind,
        RuntimeFirewallRetryCoordinator& coordinator) noexcept {
        std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(
            mutex_);
        if (!guard_matches_locked(serial, kind) ||
            kind != DrainKind::worker || !worker_terminal_ ||
            !worker_terminal_->running_claim.has_value()) {
            return false;
        }

        if (worker_control_claim_) return true;

        const auto& running_claim =
            worker_terminal_->running_claim->raw_claim();
        if (running_claim.phase !=
            RuntimeFirewallOperationPhase::worker_running) {
            return false;
        }
        return coordinator.begin_control_into(
                   running_claim, worker_control_claim_) &&
               worker_control_claim_.phase ==
                   RuntimeFirewallOperationPhase::control_pending &&
               same_operation_identity(
                   running_claim, worker_control_claim_);
    }

    bool complete_worker_control(
        std::uint64_t serial,
        DrainKind kind,
        RuntimeFirewallRetryCoordinator& coordinator,
        bool succeeded,
        OwnedSnatRecovery processed_recovery) {
        std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(
            mutex_);
        if (!guard_matches_locked(serial, kind) ||
            kind != DrainKind::worker || !worker_terminal_ ||
            !worker_terminal_->running_claim.has_value() ||
            !worker_control_claim_ ||
            !worker_publication_complete_) {
            return false;
        }
        if (worker_control_completion_.owned) return true;

        return coordinator.complete_operation_into(
            worker_control_claim_,
            succeeded,
            std::move(processed_recovery),
            worker_control_completion_);
    }

    template <typename Publish>
    bool publish_worker_control(
        std::uint64_t serial,
        DrainKind kind,
        Publish&& publish) noexcept {
        std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(
            mutex_);
        if (!guard_matches_locked(serial, kind) ||
            kind != DrainKind::worker || !worker_terminal_ ||
            !worker_terminal_->running_claim.has_value() ||
            !worker_control_claim_) {
            return false;
        }
        if (worker_publication_complete_) return true;
        if (!publish()) return false;
        worker_publication_complete_ = true;
        return true;
    }

    bool release_worker_lease(
        std::uint64_t serial,
        DrainKind kind) noexcept {
        std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(
            mutex_);
        if (!guard_matches_locked(serial, kind) ||
            kind != DrainKind::worker || !worker_terminal_ ||
            !worker_terminal_->running_claim.has_value() ||
            !worker_control_completion_.owned ||
            worker_terminal_->mutation_lease.return_policy !=
                MutationLeaseReturnPolicy::release_after_attempt) {
            return false;
        }
        worker_terminal_->mutation_lease.reset();
        return true;
    }

    MutationLeasePtr take_retained_mutation_lease(
        std::uint64_t serial,
        DrainKind kind) noexcept {
        std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(
            mutex_);
        if (!guard_matches_locked(serial, kind) || !worker_terminal_ ||
            worker_terminal_->mutation_lease.return_policy !=
                MutationLeaseReturnPolicy::return_to_operation_owner ||
            !worker_terminal_->mutation_lease.lease) {
            return {};
        }

        bool exact_completion_owned = false;
        if (kind == DrainKind::worker) {
            if (worker_terminal_->running_claim.has_value()) {
                exact_completion_owned =
                    worker_control_completion_.owned;
            } else if (
                worker_terminal_->status ==
                    WorkerTerminalStatus::queued_abandoned) {
                exact_completion_owned =
                    worker_terminal_->coordinator_completion.has_value() &&
                    worker_terminal_->coordinator_completion->owned;
            }
        } else if (kind == DrainKind::coordinator) {
            exact_completion_owned = coordinator_terminal_.has_value() &&
                                     coordinator_terminal_->owned &&
                                     provisional_preworker_loser_locked();
        }

        if (!exact_completion_owned) return {};
        return std::move(worker_terminal_->mutation_lease.lease);
    }

    bool finish_worker_terminal(
        std::uint64_t serial,
        DrainKind kind) noexcept {
        std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(
            mutex_);
        if (!guard_matches_locked(serial, kind) ||
            kind != DrainKind::worker || !worker_terminal_ ||
            worker_terminal_->mutation_lease) {
            return false;
        }

        if (worker_terminal_->running_claim.has_value()) {
            if (!worker_control_claim_ ||
                !worker_control_completion_.owned) {
                return false;
            }
        } else if (
            worker_terminal_->status ==
                WorkerTerminalStatus::queued_abandoned) {
            if (!worker_terminal_->coordinator_completion ||
                !worker_terminal_->coordinator_completion->owned) {
                return false;
            }
        } else {
            return false;
        }

        worker_control_completion_ = {};
        worker_control_claim_ = {};
        worker_publication_complete_ = false;
        worker_terminal_.reset();
        drain_active_ = false;
        closed_ = true;
        return true;
    }

    bool finish_coordinator_terminal(
        std::uint64_t serial,
        DrainKind kind) noexcept {
        bool notify_worker = false;
        {
            std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(
                mutex_);
            if (!guard_matches_locked(serial, kind) ||
                kind != DrainKind::coordinator ||
                !coordinator_terminal_ ||
                !coordinator_terminal_->owned ||
                (!worker_terminal_.has_value() &&
                 worker_terminal_mailbox_
                     ->retained_mutation_lease_pending())) {
                return false;
            }

            if (worker_terminal_.has_value()) {
                const bool subordinate_preworker_loss =
                    provisional_preworker_loser_locked();
                if (subordinate_preworker_loss) {
                    if (worker_terminal_->mutation_lease.lease) {
                        return false;
                    }
                    worker_terminal_.reset();
                } else {
                    // An unexpected independent worker terminal is never
                    // discarded. It gets its own subsequent drain.
                    notify_worker = true;
                }
            }

            coordinator_terminal_.reset();
            drain_active_ = false;
            if (!worker_terminal_.has_value()) {
                // Once the coordinator released this queued claim, any later
                // worker envelope can only fail begin_worker(), publish a
                // lost_claim, and is safe for the closed owner to ignore.
                // A retained binding is excluded by the pending-mailbox and
                // subordinate-terminal checks above.
                closed_ = true;
            }
        }
        if (notify_worker) notify_drain_ready();
        return true;
    }

    void release_drain_for_retry(std::uint64_t serial) noexcept {
        bool notify = false;
        {
            std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(
                mutex_);
            if (closed_ || !drain_active_ || serial == 0U ||
                serial != drain_serial_) {
                return;
            }
            drain_active_ = false;
            notify = coordinator_terminal_.has_value() ||
                     worker_terminal_.has_value();
        }
        if (notify) notify_drain_ready();
    }

    void release_drain_for_park(std::uint64_t serial) noexcept {
        std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(
            mutex_);
        if (closed_ || !drain_active_ || serial == 0U ||
            serial != drain_serial_) {
            return;
        }
        drain_active_ = false;
    }

    void retain_coordinator_terminal(
        RuntimeFirewallOperationCompletion completion) noexcept {
        if (!completion.owned) return;
        bool notify = false;
        {
            std::lock_guard<detail::RuntimeFirewallTerminalOwnerMutex> lock(
                mutex_);
            if (closed_ || coordinator_terminal_.has_value()) {
                return;
            }
            // Coordinator completion outranks any already-retained
            // pre-worker terminal. The non-throwing owner lock and completion
            // move make this sink lossless after coordinator slot transfer.
            coordinator_terminal_.emplace(std::move(completion));
            notify = true;
        }
        if (notify) notify_drain_ready();
    }

    void notify_drain_ready() noexcept {
        if (!on_drain_ready_) return;
        try {
            on_drain_ready_();
        } catch (...) {
            // Publication already happened. A rejected post is recovered by
            // the owner's watchdog/shutdown drain.
        }
    }

    const OnDrainReady on_drain_ready_;
    std::weak_ptr<Owner> self_weak_;
    WorkerTerminalMailboxPtr worker_terminal_mailbox_;

    mutable detail::RuntimeFirewallTerminalOwnerMutex mutex_;
    std::optional<WorkerTerminal> worker_terminal_;
    std::optional<RuntimeFirewallOperationCompletion>
        coordinator_terminal_;
    RuntimeFirewallOperationCompletion worker_control_completion_;
    RuntimeFirewallOperationClaim worker_control_claim_;
    bool worker_publication_complete_{false};
    bool drain_active_{false};
    bool closed_{false};
    std::uint64_t drain_serial_{0U};
};

} // namespace keen_pbr3
