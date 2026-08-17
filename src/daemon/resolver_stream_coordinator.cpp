#include "resolver_stream_coordinator.hpp"

#include "../util/blocking_executor.hpp"

#include <condition_variable>
#include <exception>
#include <mutex>
#include <utility>

namespace keen_pbr3 {

struct ResolverStreamCoordinator::State final
    : std::enable_shared_from_this<State> {
    enum class ClaimPhase : std::uint8_t {
        idle,
        worker,
        posting,
        queued,
        control_claimed,
    };

    struct ClaimContext {
        std::uint64_t claim_id{0};
        ResolverStreamOperation operation;
        bool stream_completed{false};
    };

    State(BlockingExecutor& executor_value,
          PostControlFn post_control_value,
          CommitFn commit_value)
        : executor(executor_value),
          post_control(std::move(post_control_value)),
          commit(std::move(commit_value)) {}

    RequestResult request(ResolverStreamOperation operation) noexcept {
        try {
            std::shared_ptr<ClaimContext> context;
            {
                std::lock_guard<std::mutex> lock(mutex);
                if (stopping) {
                    return RequestResult::rejected;
                }
                if (active) {
                    return RequestResult::busy;
                }
                if (!operation.invoke_hook || operation.stream_epoch == 0 ||
                    operation.attempt_id.empty() ||
                    operation.timeout <= std::chrono::milliseconds::zero()) {
                    return RequestResult::rejected;
                }

                context = std::make_shared<ClaimContext>();
                context->claim_id = next_claim_id_locked();
                context->operation = std::move(operation);
                active = context;
                phase = ClaimPhase::worker;
            }

            bool queued = false;
            try {
                const auto self = shared_from_this();
                queued = executor.try_post(
                    "resolver-stream-recovery",
                    [self, context]() { self->run_worker(context); });
            } catch (...) {
                queued = false;
            }
            if (!queued) {
                retire_claim(context);
                return RequestResult::rejected;
            }
            return RequestResult::started;
        } catch (...) {
            return RequestResult::rejected;
        }
    }

    void notify_stream_completed(std::string_view attempt_id,
                                 std::uint64_t stream_epoch) noexcept {
        bool matched = false;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (active &&
                active->operation.attempt_id == attempt_id &&
                active->operation.stream_epoch == stream_epoch) {
                active->stream_completed = true;
                matched = true;
            }
        }
        if (matched) {
            stream_cv.notify_all();
        }
    }

    void request_stop() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex);
            stopping = true;
        }
        stream_cv.notify_all();
        idle_cv.notify_all();
    }

    bool wait_for_idle_for(std::chrono::milliseconds timeout) const noexcept {
        std::unique_lock<std::mutex> lock(mutex);
        return idle_cv.wait_for(lock, timeout, [this]() {
            return !active;
        });
    }

    bool in_flight() const noexcept {
        std::lock_guard<std::mutex> lock(mutex);
        return static_cast<bool>(active);
    }

private:
    struct ClaimLease {
        State* owner{nullptr};
        std::shared_ptr<ClaimContext> context;

        ~ClaimLease() noexcept {
            if (owner) {
                owner->complete_claim(context);
            }
        }

        void transfer_to_control() noexcept {
            owner = nullptr;
            context.reset();
        }
    };

    bool claim_is_current_locked(
        const std::shared_ptr<ClaimContext>& context) const noexcept {
        return active && context &&
               active->claim_id == context->claim_id;
    }

    bool begin_worker(
        const std::shared_ptr<ClaimContext>& context) noexcept {
        std::lock_guard<std::mutex> lock(mutex);
        return !stopping && claim_is_current_locked(context) &&
               phase == ClaimPhase::worker;
    }

    bool wait_for_stream(
        const std::shared_ptr<ClaimContext>& context) noexcept {
        std::unique_lock<std::mutex> lock(mutex);
        const bool ready = stream_cv.wait_for(
            lock,
            context->operation.timeout,
            [this, context]() {
                return stopping || !claim_is_current_locked(context) ||
                       context->stream_completed;
            });
        return ready && !stopping && claim_is_current_locked(context) &&
               context->stream_completed;
    }

    bool begin_posting(
        const std::shared_ptr<ClaimContext>& context) noexcept {
        std::lock_guard<std::mutex> lock(mutex);
        if (stopping || !claim_is_current_locked(context) ||
            phase != ClaimPhase::worker) {
            return false;
        }
        phase = ClaimPhase::posting;
        return true;
    }

    bool finish_posting(const std::shared_ptr<ClaimContext>& context,
                        bool posted) noexcept {
        bool retire = false;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!claim_is_current_locked(context)) {
                return phase == ClaimPhase::idle;
            }
            if (phase == ClaimPhase::control_claimed) {
                return true;
            }
            if (phase != ClaimPhase::posting) {
                return false;
            }
            if (!posted || stopping) {
                retire = true;
            } else {
                phase = ClaimPhase::queued;
            }
        }
        if (retire) {
            // Preserve the same idle contract as every other terminal path:
            // release the external IPC/admission lifetime before advertising
            // that a replacement claim can start.
            retire_claim(context);
            return false;
        }
        return true;
    }

    bool begin_control(
        const std::shared_ptr<ClaimContext>& context) noexcept {
        std::lock_guard<std::mutex> lock(mutex);
        if (stopping || !claim_is_current_locked(context) ||
            (phase != ClaimPhase::posting && phase != ClaimPhase::queued)) {
            return false;
        }
        phase = ClaimPhase::control_claimed;
        return true;
    }

    void run_worker(const std::shared_ptr<ClaimContext>& context) {
        ClaimLease claim{this, context};
        if (!begin_worker(context)) {
            return;
        }

        ResolverStreamResult result;
        try {
            result.hook_exit_code = context->operation.invoke_hook();
            if (result.hook_exit_code != 0) {
                result.error = "system resolver hook failed";
            } else if (!wait_for_stream(context)) {
                std::lock_guard<std::mutex> lock(mutex);
                result.error = stopping
                    ? "resolver stream coordinator stopped"
                    : "resolver stream timed out";
            } else {
                result.completed = true;
            }
        } catch (const std::exception& error) {
            result.error = error.what();
        } catch (...) {
            result.error = "system resolver hook threw an unknown error";
        }

        if (!begin_posting(context)) {
            return;
        }

        bool posted = false;
        try {
            const auto self = shared_from_this();
            posted = post_control(
                [self, context, result = std::move(result)]() mutable {
                    self->commit_on_control(context, result);
                });
        } catch (...) {
            posted = false;
        }

        const bool control_owns_claim = finish_posting(context, posted);
        if (control_owns_claim) {
            claim.transfer_to_control();
        }
    }

    void commit_on_control(
        const std::shared_ptr<ClaimContext>& context,
        const ResolverStreamResult& result) noexcept {
        ClaimLease claim{this, context};
        if (!begin_control(context)) {
            return;
        }
        try {
            commit(context->operation, result);
        } catch (...) {
            // Completion ownership must always be released. The daemon commit
            // callback owns detailed logging because it has the operation's
            // generation and retry context.
        }
    }

    void retire_claim(
        const std::shared_ptr<ClaimContext>& context) noexcept {
        std::shared_ptr<void> lifetime;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!claim_is_current_locked(context)) {
                return;
            }
            // Idle means that the daemon-side IPC gate and mutation admission
            // have already been returned, not merely that no callback owns
            // the coordinator claim. Keep the claim visible while releasing
            // the external lifetime so a replacement request cannot overlap.
            lifetime = std::move(active->operation.lifetime);
        }
        lifetime.reset();

        std::shared_ptr<ClaimContext> retired;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!claim_is_current_locked(context)) {
                return;
            }
            retired = std::move(active);
            phase = ClaimPhase::idle;
        }
        idle_cv.notify_all();
        stream_cv.notify_all();
        retired.reset();
    }

    void complete_claim(
        const std::shared_ptr<ClaimContext>& context) noexcept {
        retire_claim(context);
    }

    std::uint64_t next_claim_id_locked() noexcept {
        ++last_claim_id;
        if (last_claim_id == 0) {
            ++last_claim_id;
        }
        return last_claim_id;
    }

    BlockingExecutor& executor;
    PostControlFn post_control;
    CommitFn commit;

    mutable std::mutex mutex;
    mutable std::condition_variable idle_cv;
    std::condition_variable stream_cv;
    std::shared_ptr<ClaimContext> active;
    std::uint64_t last_claim_id{0};
    ClaimPhase phase{ClaimPhase::idle};
    bool stopping{false};
};

ResolverStreamCoordinator::ResolverStreamCoordinator(
    BlockingExecutor& executor,
    PostControlFn post_control,
    CommitFn commit)
    : state_(std::make_shared<State>(executor,
                                     std::move(post_control),
                                     std::move(commit))) {}

ResolverStreamCoordinator::~ResolverStreamCoordinator() {
    request_stop();
}

ResolverStreamCoordinator::RequestResult
ResolverStreamCoordinator::request(
    ResolverStreamOperation operation) noexcept {
    if (!state_) {
        return RequestResult::rejected;
    }
    return state_->request(std::move(operation));
}

void ResolverStreamCoordinator::notify_stream_completed(
    std::string_view attempt_id,
    std::uint64_t stream_epoch) noexcept {
    if (state_) {
        state_->notify_stream_completed(attempt_id, stream_epoch);
    }
}

void ResolverStreamCoordinator::request_stop() noexcept {
    if (state_) {
        state_->request_stop();
    }
}

bool ResolverStreamCoordinator::wait_for_idle_for(
    std::chrono::milliseconds timeout) const noexcept {
    return !state_ || state_->wait_for_idle_for(timeout);
}

bool ResolverStreamCoordinator::in_flight() const noexcept {
    return state_ && state_->in_flight();
}

} // namespace keen_pbr3
