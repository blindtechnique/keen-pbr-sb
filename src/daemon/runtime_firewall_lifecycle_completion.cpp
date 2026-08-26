#include "runtime_firewall_lifecycle_completion.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <new>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

namespace {

class LifecycleCompletionMutex final {
public:
    LifecycleCompletionMutex() noexcept = default;
    LifecycleCompletionMutex(const LifecycleCompletionMutex&) = delete;
    LifecycleCompletionMutex& operator=(
        const LifecycleCompletionMutex&) = delete;

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

RuntimeFirewallLifecycleTerminal abandoned_terminal() {
    return {
        RuntimeFirewallLifecycleOutcome::not_verified,
        false,
        true,
        false,
        "runtime firewall lifecycle source abandoned"};
}

void replace_terminal(
    RuntimeFirewallLifecycleTerminal& destination,
    RuntimeFirewallLifecycleTerminal&& source) noexcept {
    destination.~RuntimeFirewallLifecycleTerminal();
    ::new (static_cast<void*>(std::addressof(destination)))
        RuntimeFirewallLifecycleTerminal(std::move(source));
}

} // namespace

struct RuntimeFirewallLifecycleCompletion::SharedState final {
    SharedState()
        : terminal(abandoned_terminal()) {}

    void add_source() noexcept {
        std::lock_guard<LifecycleCompletionMutex> lock(mutex);
        ++source_count;
    }

    void release_source() noexcept {
        bool notify = false;
        {
            std::lock_guard<LifecycleCompletionMutex> lock(mutex);
            if (source_count == 0U) return;
            --source_count;
            if (source_count == 0U && !terminal_ready) {
                terminal_ready = true;
                notify = true;
            }
        }
        if (notify) terminal_ready_cv.notify_all();
    }

    bool settle(
        RuntimeFirewallLifecycleTerminal prepared_terminal) noexcept {
        {
            std::lock_guard<LifecycleCompletionMutex> lock(mutex);
            if (terminal_ready) return false;
            replace_terminal(terminal, std::move(prepared_terminal));
            terminal_ready = true;
        }
        terminal_ready_cv.notify_all();
        return true;
    }

    RuntimeFirewallLifecycleTerminal wait() {
        std::unique_lock<LifecycleCompletionMutex> lock(mutex);
        terminal_ready_cv.wait(lock, [this]() noexcept {
            return terminal_ready;
        });
        return terminal;
    }

    std::optional<RuntimeFirewallLifecycleTerminal> wait_for(
        std::chrono::milliseconds timeout) {
        std::unique_lock<LifecycleCompletionMutex> lock(mutex);
        if (!terminal_ready_cv.wait_for(
                lock,
                timeout,
                [this]() noexcept { return terminal_ready; })) {
            return std::nullopt;
        }
        return terminal;
    }

    std::optional<RuntimeFirewallLifecycleTerminal> try_get() {
        std::lock_guard<LifecycleCompletionMutex> lock(mutex);
        if (!terminal_ready) return std::nullopt;
        return terminal;
    }

    bool ready() noexcept {
        std::lock_guard<LifecycleCompletionMutex> lock(mutex);
        return terminal_ready;
    }

    LifecycleCompletionMutex mutex;
    std::condition_variable_any terminal_ready_cv;
    RuntimeFirewallLifecycleTerminal terminal;
    std::size_t source_count{1U};
    bool terminal_ready{false};
};

RuntimeFirewallLifecycleCompletion::Pair
RuntimeFirewallLifecycleCompletion::create() {
    auto state = std::make_shared<SharedState>();
    return {
        Source{state},
        WaitHandle{std::move(state)}};
}

RuntimeFirewallLifecycleCompletion::Source::Source(
    std::shared_ptr<SharedState> state) noexcept
    : state_(std::move(state)) {}

RuntimeFirewallLifecycleCompletion::Source::~Source() noexcept {
    release();
}

RuntimeFirewallLifecycleCompletion::Source::Source(
    const Source& other) noexcept
    : state_(other.state_) {
    if (state_) state_->add_source();
}

RuntimeFirewallLifecycleCompletion::Source&
RuntimeFirewallLifecycleCompletion::Source::operator=(
    const Source& other) noexcept {
    if (this == &other) return *this;

    auto next = other.state_;
    if (next) next->add_source();
    release();
    state_ = std::move(next);
    return *this;
}

RuntimeFirewallLifecycleCompletion::Source&
RuntimeFirewallLifecycleCompletion::Source::operator=(
    Source&& other) noexcept {
    if (this == &other) return *this;
    release();
    state_ = std::move(other.state_);
    return *this;
}

RuntimeFirewallLifecycleCompletion::Source::SettleStatus
RuntimeFirewallLifecycleCompletion::Source::settle(
    RuntimeFirewallLifecycleTerminal prepared_terminal) const noexcept {
    if (!state_) return SettleStatus::no_source;
    return state_->settle(std::move(prepared_terminal))
        ? SettleStatus::settled
        : SettleStatus::already_settled;
}

void RuntimeFirewallLifecycleCompletion::Source::release() noexcept {
    if (!state_) return;
    auto state = std::move(state_);
    state->release_source();
}

RuntimeFirewallLifecycleCompletion::WaitHandle::WaitHandle(
    std::shared_ptr<SharedState> state) noexcept
    : state_(std::move(state)) {}

RuntimeFirewallLifecycleTerminal
RuntimeFirewallLifecycleCompletion::WaitHandle::wait() const {
    if (!state_) {
        throw std::logic_error(
            "runtime firewall lifecycle wait requires a shared state");
    }
    return state_->wait();
}

std::optional<RuntimeFirewallLifecycleTerminal>
RuntimeFirewallLifecycleCompletion::WaitHandle::wait_for(
    std::chrono::milliseconds timeout) const {
    if (!state_) return std::nullopt;
    return state_->wait_for(timeout);
}

std::optional<RuntimeFirewallLifecycleTerminal>
RuntimeFirewallLifecycleCompletion::WaitHandle::try_get() const {
    if (!state_) return std::nullopt;
    return state_->try_get();
}

bool RuntimeFirewallLifecycleCompletion::WaitHandle::ready() const noexcept {
    return state_ && state_->ready();
}

} // namespace keen_pbr3
