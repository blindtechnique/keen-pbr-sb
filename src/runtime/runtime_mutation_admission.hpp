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
        if (!state_->accepting || state_->active_token != 0) {
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

    // Used by deferred external writers such as SIGHUP. Returns true once the
    // current owner is gone, or false when shutdown closes admission first.
    bool wait_until_idle() const noexcept {
        const auto state = state_;
        std::unique_lock<std::mutex> lock(state->mutex);
        state->idle_cv.wait(lock, [state] {
            return !state->accepting || state->active_token == 0;
        });
        return state->accepting && state->active_token == 0;
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
            return state->active_token == 0;
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

} // namespace keen_pbr3
