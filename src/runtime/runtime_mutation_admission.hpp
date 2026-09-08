#pragma once

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace keen_pbr3 {

// Serializes ownership of an external runtime mutation. A lease is an
// unforgeable, move-only claim: destroying or explicitly releasing it returns
// ownership only when its token is still current. Shutdown is terminal for
// new acquisitions, but an operation already admitted keeps ownership until
// its lease is released. This lets daemon shutdown quiesce accepted work
// instead of invalidating it halfway through a commit.
class RuntimeMutationAdmission {
public:
    enum class Kind : std::uint8_t {
        Foreground,
        Background,
    };

private:
    struct State {
        mutable std::mutex mutex;
        std::uint64_t next_token{0};
        std::uint64_t active_token{0};
        std::string active_label;
        Kind active_kind{Kind::Foreground};
        std::uint64_t handoff_count{0};
        std::uint64_t handoff_token{0};
        std::uint64_t foreground_waiters{0};
        bool accepting{true};
        // Process shutdown may need one final typed cleanup after ordinary
        // writers have quiesced. This latch prevents that private authority
        // from becoming a second post-shutdown admission channel.
        bool shutdown_cleanup_claimed{false};
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
                if (state->handoff_count == 0) {
                    state->active_label.clear();
                }
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
                if (state->handoff_count == 0) {
                    state->handoff_token = 0;
                    if (state->active_token == 0) {
                        state->active_label.clear();
                    }
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

    std::optional<Lease> try_acquire(
        std::string label, Kind kind = Kind::Foreground) {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (!state_->accepting || state_->active_token != 0 ||
            state_->handoff_count != 0 || state_->foreground_waiters != 0) {
            return std::nullopt;
        }

        return acquire_locked(state_, std::move(label), kind);
    }

    // Foreground API mutations normally fail immediately when another writer
    // owns the runtime. Explicitly classified background work is
    // different: it normally only needs to finish its current terminal.
    // Reserve priority over new background probes while that exact predecessor
    // and its handoff finish, then claim admission under the same mutex.
    // Another waiting foreground may win, but a background successor cannot
    // repeatedly take its place. Timeout and shutdown release only this wait.
    template<class Rep, class Period>
    std::optional<Lease> try_acquire_after_background_for(
        std::string label,
        const std::chrono::duration<Rep, Period>& timeout) {
        return try_acquire_after_matching_for(
            std::move(label), timeout, [](const State& active) {
                return active.active_kind == Kind::Background;
            });
    }

    // Compatibility for callers which intentionally wait for one named owner.
    // Production foreground admission uses the explicit background kind above.
    template<class Rep, class Period>
    std::optional<Lease> try_acquire_after_for(
        std::string label,
        const std::string& waitable_active_label,
        const std::chrono::duration<Rep, Period>& timeout) {
        return try_acquire_after_for(
            std::move(label), {std::string_view{waitable_active_label}}, timeout);
    }

    template<class Rep, class Period>
    std::optional<Lease> try_acquire_after_for(
        std::string label,
        std::initializer_list<std::string_view> waitable_active_labels,
        const std::chrono::duration<Rep, Period>& timeout) {
        return try_acquire_after_matching_for(
            std::move(label), timeout, [waitable_active_labels](const State& active) {
                return std::find(waitable_active_labels.begin(),
                                 waitable_active_labels.end(), active.active_label)
                    != waitable_active_labels.end();
            });
    }

private:
    template<class Rep, class Period, class Waitable>
    std::optional<Lease> try_acquire_after_matching_for(
        std::string label,
        const std::chrono::duration<Rep, Period>& timeout,
        Waitable waitable) {
        const auto state = state_;
        std::unique_lock<std::mutex> lock(state->mutex);
        if (!state->accepting) {
            return std::nullopt;
        }
        if (state->active_token == 0 && state->handoff_count == 0) {
            if (state->foreground_waiters != 0) return std::nullopt;
            return acquire_locked(state, std::move(label));
        }
        if (!waitable(*state)) {
            return std::nullopt;
        }

        const auto predecessor_token = state->active_token != 0
            ? state->active_token
            : state->handoff_token;
        // The scope is destroyed while lock still owns state->mutex, including
        // every timeout/exception path; no pending operation or body is stored.
        struct ForegroundWaitPriority {
            State& state;
            explicit ForegroundWaitPriority(State& value) noexcept
                : state(value) {
                ++state.foreground_waiters;
            }
            ~ForegroundWaitPriority() noexcept {
                --state.foreground_waiters;
                state.idle_cv.notify_all();
            }
        } priority{*state};
        if (!state->idle_cv.wait_for(lock, timeout, [&] {
                return !state->accepting ||
                       (state->active_token != 0 &&
                        state->active_token != predecessor_token) ||
                       (state->active_token == 0 &&
                        state->handoff_count == 0);
            })) {
            return std::nullopt;
        }
        if (!state->accepting || state->active_token != 0 ||
            state->handoff_count != 0) {
            return std::nullopt;
        }
        return acquire_locked(state, std::move(label));
    }

public:
    // Admit exactly one internal cleanup only after shutdown() has closed
    // ordinary writers and every previously accepted lease/handoff has
    // quiesced. The returned object is the same exact RAII Lease used by
    // normal runtime mutations; releasing it wakes wait_for_idle_for().
    // A failed probe does not consume the one-shot authority.
    std::optional<Lease> try_acquire_shutdown_cleanup(std::string label) {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->accepting || state_->active_token != 0 ||
            state_->handoff_count != 0 ||
            state_->shutdown_cleanup_claimed) {
            return std::nullopt;
        }

        auto next_token = state_->next_token + 1U;
        if (next_token == 0U) {
            next_token = 1U;
        }
        state_->active_label = std::move(label);
        state_->active_kind = Kind::Foreground;
        state_->next_token = next_token;
        state_->active_token = next_token;
        state_->shutdown_cleanup_claimed = true;
        return Lease{state_, next_token};
    }

    std::optional<HandoffGate> try_acquire_handoff_gate(
        const Lease& lease) noexcept {
        const auto state = state_;
        std::lock_guard<std::mutex> lock(state->mutex);
        if (!lease.state_ || lease.state_.get() != state.get() ||
            lease.token_ == 0 || state->active_token != lease.token_) {
            return std::nullopt;
        }
        state->handoff_token = lease.token_;
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
                    state->handoff_count == 0 &&
                    state->foreground_waiters == 0);
        });
        return state->accepting && state->active_token == 0 &&
               state->handoff_count == 0 && state->foreground_waiters == 0;
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
    static Lease acquire_locked(
        const std::shared_ptr<State>& state,
        std::string label,
        Kind kind = Kind::Foreground) {
        ++state->next_token;
        if (state->next_token == 0) {
            ++state->next_token;
        }
        state->active_token = state->next_token;
        state->active_label = std::move(label);
        state->active_kind = kind;
        return Lease{state, state->active_token};
    }

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
