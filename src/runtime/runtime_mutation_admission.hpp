#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace keen_pbr3 {

// Serializes ownership of an external runtime mutation. A lease is an
// unforgeable, move-only claim: destroying or explicitly releasing it returns
// ownership only when its token is still current. Shutdown is terminal for
// new acquisitions, but an operation already admitted keeps ownership until
// its lease is released. This lets daemon shutdown quiesce accepted work
// instead of invalidating it halfway through a commit.
class RuntimeMutationAdmission {
private:
    struct State {
        mutable std::mutex mutex;
        std::uint64_t next_token{0};
        std::uint64_t active_token{0};
        std::string active_label;
        std::uint64_t handoff_count{0};
        bool accepting{true};
        std::condition_variable idle_cv;
    };

public:
    class Lease {
    public:
        Lease() noexcept = default;

        ~Lease() noexcept {
            release();
        }

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;

        Lease(Lease&& other) noexcept
            : state_(std::move(other.state_)),
              token_(std::exchange(other.token_, 0)) {}

        Lease& operator=(Lease&& other) noexcept {
            if (this == &other) {
                return *this;
            }
            release();
            state_ = std::move(other.state_);
            token_ = std::exchange(other.token_, 0);
            return *this;
        }

        explicit operator bool() const noexcept {
            return state_ && token_ != 0;
        }

        std::uint64_t token() const noexcept {
            return token_;
        }

        void release() noexcept {
            auto state = std::move(state_);
            const auto token = std::exchange(token_, 0);
            if (!state || token == 0) {
                return;
            }

            {
                std::lock_guard<std::mutex> lock(state->mutex);
                if (state->active_token != token) {
                    return;
                }
                state->active_token = 0;
                state->active_label.clear();
            }
            state->idle_cv.notify_all();
        }

    private:
        friend class RuntimeMutationAdmission;

        Lease(std::shared_ptr<State> state, std::uint64_t token) noexcept
            : state_(std::move(state)), token_(token) {}

        std::shared_ptr<State> state_;
        std::uint64_t token_{0};
    };

    class HandoffGate {
    public:
        HandoffGate() noexcept = default;

        ~HandoffGate() noexcept {
            release();
        }

        HandoffGate(const HandoffGate&) = delete;
        HandoffGate& operator=(const HandoffGate&) = delete;

        HandoffGate(HandoffGate&& other) noexcept
            : state_(std::move(other.state_)) {}

        HandoffGate& operator=(HandoffGate&& other) noexcept {
            if (this == &other) {
                return *this;
            }
            release();
            state_ = std::move(other.state_);
            return *this;
        }

        explicit operator bool() const noexcept {
            return static_cast<bool>(state_);
        }

        void release() noexcept {
            auto state = std::move(state_);
            if (!state) {
                return;
            }
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                if (state->handoff_count != 0) {
                    --state->handoff_count;
                }
            }
            state->idle_cv.notify_all();
        }

    private:
        friend class RuntimeMutationAdmission;

        explicit HandoffGate(std::shared_ptr<State> state) noexcept
            : state_(std::move(state)) {}

        std::shared_ptr<State> state_;
    };

    RuntimeMutationAdmission() : state_(std::make_shared<State>()) {}

    ~RuntimeMutationAdmission() noexcept {
        shutdown();
    }

    RuntimeMutationAdmission(const RuntimeMutationAdmission&) = delete;
    RuntimeMutationAdmission& operator=(const RuntimeMutationAdmission&) =
        delete;
    RuntimeMutationAdmission(RuntimeMutationAdmission&&) = delete;
    RuntimeMutationAdmission& operator=(RuntimeMutationAdmission&&) = delete;

    struct Active {
        std::uint64_t token{0};
        std::string label;
    };

    std::optional<Lease> try_acquire(std::string label) {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (!state_->accepting || state_->active_token != 0 ||
            state_->handoff_count != 0) {
            return std::nullopt;
        }

        ++state_->next_token;
        if (state_->next_token == 0) {
            ++state_->next_token;
        }
        state_->active_token = state_->next_token;
        state_->active_label = std::move(label);
        return Lease{state_, state_->active_token};
    }

    std::optional<HandoffGate> try_acquire_handoff_gate(
        const Lease& lease) noexcept {
        const auto state = state_;
        std::lock_guard<std::mutex> lock(state->mutex);
        if (!lease.state_ || lease.state_.get() != state.get() ||
            lease.token_ == 0 || state->active_token != lease.token_) {
            return std::nullopt;
        }
        ++state->handoff_count;
        return HandoffGate{state};
    }

    // Used by deferred external writers such as SIGHUP. Returns true once the
    // current owner is gone, or false when shutdown closes admission first.
    bool wait_until_idle() const noexcept {
        const auto state = state_;
        std::unique_lock<std::mutex> lock(state->mutex);
        state->idle_cv.wait(lock, [state] {
            return !state->accepting ||
                   (state->active_token == 0 &&
                    state->handoff_count == 0);
        });
        return state->accepting && state->active_token == 0 &&
               state->handoff_count == 0;
    }

    // Shutdown uses a bounded wait while pumping the control queue. Unlike
    // wait_until_idle(), closing admission does not make this predicate true:
    // an already admitted operation must release its exact token first.
    template<class Rep, class Period>
    bool wait_for_idle_for(
        const std::chrono::duration<Rep, Period>& timeout) const noexcept {
        const auto state = state_;
        std::unique_lock<std::mutex> lock(state->mutex);
        return state->idle_cv.wait_for(lock, timeout, [state] {
            return state->active_token == 0 &&
                   state->handoff_count == 0;
        });
    }

    bool owns(const Lease& lease) const noexcept {
        if (!lease.state_ || lease.state_.get() != state_.get() ||
            lease.token_ == 0) {
            return false;
        }

        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->active_token == lease.token_;
    }

    std::optional<Active> active() const {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->active_token == 0) {
            return std::nullopt;
        }
        return Active{state_->active_token, state_->active_label};
    }

    void shutdown() noexcept {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            state_->accepting = false;
        }
        state_->idle_cv.notify_all();
    }

private:
    std::shared_ptr<State> state_;
};

// A copyable handle around one exact move-only mutation lease. Copies share
// the handoff state, but only the first successful take() receives ownership
// of the Lease. This is intentionally not a shared_ptr<Lease>: after transfer
// there is one unambiguous owner which must carry the lease through commit and
// rollback.
enum class RuntimeMutationLeaseHandoffState : std::uint8_t {
    Empty,
    Ready,
    Taken,
    Invalid,
};

enum class RuntimeMutationLeaseTakeStatus : std::uint8_t {
    Acquired,
    Empty,
    AlreadyTaken,
    Invalid,
};

struct RuntimeMutationLeaseTakeResult {
    RuntimeMutationLeaseTakeStatus status{
        RuntimeMutationLeaseTakeStatus::Empty};
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease;

    explicit operator bool() const noexcept {
        return status == RuntimeMutationLeaseTakeStatus::Acquired && lease &&
               static_cast<bool>(*lease);
    }
};

class RuntimeMutationLeaseHandoff final {
public:
    using Lease = RuntimeMutationAdmission::Lease;
    using LeasePtr = std::unique_ptr<Lease>;

    RuntimeMutationLeaseHandoff() noexcept = default;

    // A null pointer or an already-empty Lease creates an explicit Invalid
    // handle. Callers can therefore reject a broken ownership handoff instead
    // of silently treating it as a read-only operation.
    explicit RuntimeMutationLeaseHandoff(LeasePtr lease)
        : state_(std::make_shared<SharedState>(std::move(lease))) {}

    RuntimeMutationLeaseHandoff(const RuntimeMutationLeaseHandoff&) noexcept =
        default;
    RuntimeMutationLeaseHandoff& operator=(
        const RuntimeMutationLeaseHandoff&) noexcept = default;
    RuntimeMutationLeaseHandoff(RuntimeMutationLeaseHandoff&&) noexcept =
        default;
    RuntimeMutationLeaseHandoff& operator=(
        RuntimeMutationLeaseHandoff&&) noexcept = default;

    RuntimeMutationLeaseHandoffState state() const {
        if (!state_) {
            return RuntimeMutationLeaseHandoffState::Empty;
        }
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->handoff_state;
    }

    RuntimeMutationLeaseTakeResult take() const {
        if (!state_) {
            return {RuntimeMutationLeaseTakeStatus::Empty, {}};
        }

        std::lock_guard<std::mutex> lock(state_->mutex);
        switch (state_->handoff_state) {
        case RuntimeMutationLeaseHandoffState::Empty:
            return {RuntimeMutationLeaseTakeStatus::Empty, {}};
        case RuntimeMutationLeaseHandoffState::Taken:
            return {RuntimeMutationLeaseTakeStatus::AlreadyTaken, {}};
        case RuntimeMutationLeaseHandoffState::Invalid:
            return {RuntimeMutationLeaseTakeStatus::Invalid, {}};
        case RuntimeMutationLeaseHandoffState::Ready:
            break;
        }

        if (!state_->lease || !static_cast<bool>(*state_->lease)) {
            state_->lease.reset();
            state_->handoff_state =
                RuntimeMutationLeaseHandoffState::Invalid;
            return {RuntimeMutationLeaseTakeStatus::Invalid, {}};
        }

        state_->handoff_state = RuntimeMutationLeaseHandoffState::Taken;
        return {RuntimeMutationLeaseTakeStatus::Acquired,
                std::move(state_->lease)};
    }

private:
    struct SharedState {
        explicit SharedState(LeasePtr exact_lease)
            : lease(std::move(exact_lease)),
              handoff_state(
                  lease && static_cast<bool>(*lease)
                      ? RuntimeMutationLeaseHandoffState::Ready
                      : RuntimeMutationLeaseHandoffState::Invalid) {}

        std::mutex mutex;
        LeasePtr lease;
        RuntimeMutationLeaseHandoffState handoff_state{
            RuntimeMutationLeaseHandoffState::Invalid};
    };

    std::shared_ptr<SharedState> state_;
};

} // namespace keen_pbr3
