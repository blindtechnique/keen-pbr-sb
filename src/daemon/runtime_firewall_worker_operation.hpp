#pragma once

#include "runtime_recovery_policy.hpp"
#include "../runtime/runtime_mutation_admission.hpp"

#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

// Shared cross-thread storage for one admitted runtime-firewall worker. The
// retry coordinator remains the sole operation phase state machine. This
// object retains only one immutable input and a caller-owned durable mailbox;
// that mailbox owns the single mutation lease and terminal outcome.
//
// RuntimeFirewallRetryCoordinator must outlive every operation and every
// queued std::function produced by it. BlockingExecutor::cancel_pending()
// destroys unclaimed callbacks outside its own lock, allowing the queue
// envelope to complete the coordinator hand-off safely during shutdown.
template <typename Input, typename Result>
class RuntimeFirewallWorkerOperation final
    : public std::enable_shared_from_this<
          RuntimeFirewallWorkerOperation<Input, Result>> {
public:
    using Operation = RuntimeFirewallWorkerOperation<Input, Result>;
    using OperationPtr = std::shared_ptr<Operation>;
    using InputPtr = std::shared_ptr<const Input>;
    using ResultPtr = std::shared_ptr<const Result>;
    using MutationLeasePtr =
        std::unique_ptr<RuntimeMutationAdmission::Lease>;

    // An unforgeable proof that this exact queue envelope successfully crossed
    // RuntimeFirewallRetryCoordinator::begin_worker(). Callers can copy the
    // capability after receiving it, but cannot construct one from a raw claim
    // or by replacing the phase on a queued claim.
    class RunningClaim final {
    public:
        RunningClaim(const RunningClaim&) noexcept = default;
        RunningClaim& operator=(const RunningClaim&) noexcept = default;
        RunningClaim(RunningClaim&&) noexcept = default;
        RunningClaim& operator=(RunningClaim&&) noexcept = default;

        const RuntimeFirewallOperationClaim& raw_claim() const noexcept {
            return claim_;
        }

    private:
        friend class RuntimeFirewallWorkerOperation<Input, Result>;

        explicit RunningClaim(
            RuntimeFirewallOperationClaim claim) noexcept
            : claim_(claim) {}

        RuntimeFirewallOperationClaim claim_;
    };

    enum class TerminalStatus : std::uint8_t {
        result,
        exception,
        missing_result,
        queued_abandoned,
        lost_claim,
    };

    // One move-only terminal outcome. Running outcomes carry the exact
    // capability and transfer the sole mutation lease to the control owner,
    // which must call begin_control(), publish daemon state, complete the
    // coordinator operation, and finally release the lease. Outcomes without
    // a running capability contain no lease: it was released before this
    // envelope became observable. A lost claim detected after begin_worker()
    // retains both capability and lease but deliberately drops stale result.
    struct TerminalEnvelope {
        TerminalStatus status{TerminalStatus::lost_claim};
        std::optional<RunningClaim> running_claim;
        ResultPtr result;
        std::exception_ptr exception;
        std::optional<RuntimeFirewallOperationCompletion>
            coordinator_completion;
        MutationLeasePtr mutation_lease;
    };

    using OnTerminalReady = std::function<void()>;

    // Durable one-shot terminal storage is deliberately separate from the
    // operation object. The control owner creates and retains this mailbox
    // before create(), so an allocation failure or destruction before the
    // queue envelope is armed cannot strand the coordinator claim or lose its
    // exact completion. Publication always precedes the best-effort wake.
    class TerminalMailbox final {
    public:
        TerminalMailbox(const TerminalMailbox&) = delete;
        TerminalMailbox& operator=(const TerminalMailbox&) = delete;

        std::optional<TerminalEnvelope> take_terminal() {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!terminal_.has_value() || terminal_taken_) {
                return std::nullopt;
            }
            terminal_taken_ = true;
            auto terminal = std::move(terminal_);
            terminal_.reset();
            return terminal;
        }

    private:
        friend class RuntimeFirewallWorkerOperation<Input, Result>;

        explicit TerminalMailbox(
            OnTerminalReady on_terminal_ready) noexcept
            : on_terminal_ready_(std::move(on_terminal_ready)) {}

        bool bind_mutation_lease(MutationLeasePtr mutation_lease) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (operation_bound_ || terminal_.has_value() ||
                terminal_taken_) {
                return false;
            }
            operation_bound_ = true;
            mutation_lease_ = std::move(mutation_lease);
            return true;
        }

        bool publish_running_terminal(
            TerminalStatus status,
            RunningClaim running_claim,
            ResultPtr result,
            std::exception_ptr exception) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!operation_bound_ || terminal_.has_value() ||
                    terminal_taken_ || !mutation_lease_) {
                    return false;
                }

                std::optional<RunningClaim> retained_claim;
                retained_claim.emplace(std::move(running_claim));
                terminal_.emplace(TerminalEnvelope{
                    status,
                    std::move(retained_claim),
                    std::move(result),
                    std::move(exception),
                    std::nullopt,
                    std::move(mutation_lease_)});
            }
            notify_terminal_ready();
            return true;
        }

        bool publish_preworker_terminal(
            TerminalStatus status,
            std::optional<RuntimeFirewallOperationCompletion> completion) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!operation_bound_ || terminal_.has_value() ||
                    terminal_taken_) {
                    return false;
                }

                // Releasing admission is part of publication. The mailbox
                // cannot become observable and no wake can run while the
                // pre-worker lease remains owned.
                mutation_lease_.reset();
                terminal_.emplace(TerminalEnvelope{
                    status,
                    std::nullopt,
                    {},
                    {},
                    std::move(completion),
                    {}});
            }
            notify_terminal_ready();
            return true;
        }

        void notify_terminal_ready() noexcept {
            if (!on_terminal_ready_) return;
            try {
                on_terminal_ready_();
            } catch (...) {
                // The mailbox already owns the complete terminal outcome. A
                // rejected control post is recoverable by its watchdog.
            }
        }

        std::mutex mutex_;
        OnTerminalReady on_terminal_ready_;
        bool operation_bound_{false};
        MutationLeasePtr mutation_lease_;
        std::optional<TerminalEnvelope> terminal_;
        bool terminal_taken_{false};
    };

    using TerminalMailboxPtr = std::shared_ptr<TerminalMailbox>;

    // The worker is deliberately pure with respect to Operation: it receives
    // immutable input and the opaque running capability, then returns one
    // immutable result. The queue envelope owns all terminal publication.
    using Worker = std::function<ResultPtr(
        const Input&, const RunningClaim&)>;

    static TerminalMailboxPtr create_terminal_mailbox(
        OnTerminalReady on_terminal_ready = {}) {
        return TerminalMailboxPtr(new TerminalMailbox(
            std::move(on_terminal_ready)));
    }

    static OperationPtr create(
        RuntimeFirewallRetryCoordinator& coordinator,
        RuntimeFirewallOperationClaim queued_claim,
        InputPtr input,
        MutationLeasePtr mutation_lease,
        const TerminalMailboxPtr& terminal_mailbox) {
        if (!queued_claim ||
            queued_claim.phase !=
                RuntimeFirewallOperationPhase::worker_queued ||
            !coordinator.operation_is_current(queued_claim)) {
            throw std::invalid_argument(
                "runtime firewall worker requires its current queued claim");
        }
        if (!input) {
            throw std::invalid_argument(
                "runtime firewall worker requires immutable input");
        }
        if (!mutation_lease || !*mutation_lease) {
            throw std::invalid_argument(
                "runtime firewall worker requires an exclusive mutation lease");
        }
        if (!terminal_mailbox) {
            throw std::invalid_argument(
                "runtime firewall worker requires a durable terminal mailbox");
        }
        if (!terminal_mailbox->bind_mutation_lease(
                std::move(mutation_lease))) {
            throw std::logic_error(
                "runtime firewall terminal mailbox is already bound");
        }

        try {
            return OperationPtr(new Operation(
                coordinator,
                queued_claim,
                std::move(input),
                terminal_mailbox));
        } catch (...) {
            terminate_queued_claim(
                coordinator, queued_claim, terminal_mailbox);
            throw;
        }
    }

    ~RuntimeFirewallWorkerOperation() noexcept {
        bool queue_was_never_armed = false;
        try {
            std::lock_guard<std::mutex> lock(envelope_mutex_);
            if (!queue_envelope_created_) {
                queue_envelope_created_ = true;
                queue_was_never_armed = true;
            }
        } catch (...) {
            // std::mutex failures are unrecoverable for the mailbox protocol,
            // but a destructor must not terminate daemon shutdown.
            return;
        }
        if (queue_was_never_armed) {
            terminate_queued_claim(
                coordinator_, queued_claim_, terminal_mailbox_);
        }
    }

    RuntimeFirewallWorkerOperation(
        const RuntimeFirewallWorkerOperation&) = delete;
    RuntimeFirewallWorkerOperation& operator=(
        const RuntimeFirewallWorkerOperation&) = delete;

    const Input& input() const noexcept { return *input_; }
    const InputPtr& input_ptr() const noexcept { return input_; }

    RuntimeFirewallOperationClaim queued_claim() const noexcept {
        return queued_claim_;
    }

    // Return the operation's only copy-safe executor envelope. Temporary
    // std::function copies share one QueueState, so moving/copying a task does
    // not abandon its claim. The reservation is made after QueueState exists
    // but before std::function's potentially throwing target allocation.
    std::function<void()> make_queued_closure(Worker worker) {
        if (!worker) {
            throw std::invalid_argument(
                "runtime firewall worker requires a callback");
        }

        std::shared_ptr<QueuedClosureState> state;
        {
            std::lock_guard<std::mutex> lock(envelope_mutex_);
            if (queue_envelope_created_) {
                throw std::logic_error(
                    "runtime firewall worker already has a queue envelope");
            }
            state = std::make_shared<QueuedClosureState>(
                this->shared_from_this(),
                std::move(worker));
            // make_shared failure leaves the flag false and can be retried.
            // Every later failure destroys state, publishes a terminal queue
            // outcome and must not permit a stale second envelope.
            queue_envelope_created_ = true;
        }

        std::function<void()> closure =
            [state = std::move(state)]() { state->invoke(); };
        return closure;
    }

    std::optional<TerminalEnvelope> take_terminal() {
        return terminal_mailbox_->take_terminal();
    }

private:
    enum class ClosureState : std::uint8_t {
        queued,
        invoking,
        running,
        terminalized,
    };

    class QueuedClosureState final {
    public:
        QueuedClosureState(
            OperationPtr operation,
            Worker worker)
            : operation_(std::move(operation)),
              worker_(std::move(worker)) {}

        ~QueuedClosureState() noexcept {
            auto expected = ClosureState::queued;
            if (!state_.compare_exchange_strong(
                    expected,
                    ClosureState::terminalized,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                return;
            }

            Operation::terminate_queued_claim(
                operation_->coordinator_,
                operation_->queued_claim_,
                operation_->terminal_mailbox_);
        }

        void invoke() {
            auto expected = ClosureState::queued;
            if (!state_.compare_exchange_strong(
                    expected,
                    ClosureState::invoking,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                return;
            }

            const auto running =
                operation_->coordinator_.begin_worker(
                    operation_->queued_claim_);
            if (!running.has_value()) {
                state_.store(
                    ClosureState::terminalized,
                    std::memory_order_release);
                operation_->publish_preworker_terminal(
                    TerminalStatus::lost_claim, std::nullopt);
                return;
            }

            RunningClaim running_claim =
                operation_->make_running_claim(*running);
            state_.store(
                ClosureState::running,
                std::memory_order_release);

            ResultPtr result;
            std::exception_ptr exception;
            TerminalStatus status{TerminalStatus::missing_result};
            try {
                result = worker_(operation_->input(), running_claim);
                status = result
                    ? TerminalStatus::result
                    : TerminalStatus::missing_result;
            } catch (...) {
                exception = std::current_exception();
                status = TerminalStatus::exception;
            }

            operation_->publish_running_terminal(
                status,
                running_claim,
                std::move(result),
                std::move(exception));
            state_.store(
                ClosureState::terminalized,
                std::memory_order_release);
        }

    private:
        OperationPtr operation_;
        Worker worker_;
        std::atomic<ClosureState> state_{ClosureState::queued};
    };

    RuntimeFirewallWorkerOperation(
        RuntimeFirewallRetryCoordinator& coordinator,
        RuntimeFirewallOperationClaim queued_claim,
        InputPtr input,
        TerminalMailboxPtr terminal_mailbox) noexcept
        : coordinator_(coordinator),
          queued_claim_(queued_claim),
          input_(std::move(input)),
          terminal_mailbox_(std::move(terminal_mailbox)) {}

    bool running_claim_matches_operation(
        const RunningClaim& running_claim) const noexcept {
        const auto& claim = running_claim.raw_claim();
        return claim.phase ==
                   RuntimeFirewallOperationPhase::worker_running &&
               claim.serial == queued_claim_.serial &&
               claim.runtime_generation ==
                   queued_claim_.runtime_generation &&
               claim.attempt == queued_claim_.attempt &&
               claim.recovery_revision ==
                   queued_claim_.recovery_revision;
    }

    RunningClaim make_running_claim(
        RuntimeFirewallOperationClaim claim) const noexcept {
        return RunningClaim{claim};
    }

    static void terminate_queued_claim(
        RuntimeFirewallRetryCoordinator& coordinator,
        RuntimeFirewallOperationClaim queued_claim,
        const TerminalMailboxPtr& terminal_mailbox) noexcept {
        if (!terminal_mailbox) return;

        std::optional<RuntimeFirewallOperationCompletion> completion;
        try {
            auto transferred =
                coordinator.terminate_operation_for_resnapshot(
                    queued_claim,
                    /*force_rerun=*/true);
            if (transferred.owned) {
                completion.emplace(std::move(transferred));
            }
        } catch (...) {
            // A lost-claim terminal is still published below. Queue teardown
            // and operation destruction must never terminate shutdown.
        }

        const auto status = completion.has_value()
            ? TerminalStatus::queued_abandoned
            : TerminalStatus::lost_claim;
        try {
            terminal_mailbox->publish_preworker_terminal(
                status, std::move(completion));
        } catch (...) {
            // Standard mailbox moves are allocation-free. Retain noexcept
            // destruction even if the platform mutex reports a fatal error.
        }
    }

    bool publish_running_terminal(
        TerminalStatus status,
        const RunningClaim& running_claim,
        ResultPtr result,
        std::exception_ptr exception) {
        if (!running_claim_matches_operation(running_claim) ||
            (status != TerminalStatus::result &&
             status != TerminalStatus::exception &&
             status != TerminalStatus::missing_result)) {
            return false;
        }

        // A caller must not advance the coordinator to control (or replace it
        // with a successor) before the worker terminal is retained. Discard a
        // result from that stale phase and publish only a typed lost-claim
        // outcome so the watchdog can release the transferred lease without
        // accepting stale backend data.
        if (!coordinator_.operation_is_current(
                running_claim.raw_claim())) {
            status = TerminalStatus::lost_claim;
            result.reset();
            exception = {};
        }

        return terminal_mailbox_->publish_running_terminal(
            status,
            running_claim,
            std::move(result),
            std::move(exception));
    }

    bool publish_preworker_terminal(
        TerminalStatus status,
        std::optional<RuntimeFirewallOperationCompletion> completion) {
        if (status != TerminalStatus::queued_abandoned &&
            status != TerminalStatus::lost_claim) {
            return false;
        }

        return terminal_mailbox_->publish_preworker_terminal(
            status, std::move(completion));
    }

    RuntimeFirewallRetryCoordinator& coordinator_;
    const RuntimeFirewallOperationClaim queued_claim_;
    const InputPtr input_;
    const TerminalMailboxPtr terminal_mailbox_;

    std::mutex envelope_mutex_;
    bool queue_envelope_created_{false};
};

} // namespace keen_pbr3
