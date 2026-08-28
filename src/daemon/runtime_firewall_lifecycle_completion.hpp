#pragma once

#include "runtime_config_operation_identity.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {

enum class RuntimeFirewallLifecycleOutcome : std::uint8_t {
    verified_success,
    not_verified,
    shutdown,
};

// Callers prepare the complete terminal before handing it to Source::settle().
// The shared state already owns a conservative fallback terminal, so terminal
// publication needs only non-allocating move reconstruction and a wake-up.
struct RuntimeFirewallLifecycleTerminal final {
    RuntimeFirewallLifecycleOutcome outcome{
        RuntimeFirewallLifecycleOutcome::not_verified};
    bool committed{false};
    bool commit_ambiguous{true};
    bool transient{false};
    std::string detail;
    std::optional<ConfigTerminalOperationIdentity> observed_config_identity;
    bool previous_generation_certainly_retained{false};
    bool candidate_noop_verified{false};
};

class RuntimeFirewallLifecycleCompletion final {
public:
    class Source;
    class WaitHandle;
    struct Pair;

    static Pair create();

private:
    struct SharedState;
};

// Copying Source creates another producer capability for the same lifecycle
// result. Exactly one producer can settle it. If every Source disappears
// first, the last destructor publishes the preallocated conservative result.
class RuntimeFirewallLifecycleCompletion::Source final {
public:
    enum class SettleStatus : std::uint8_t {
        settled,
        already_settled,
        no_source,
    };

    Source() noexcept = default;
    ~Source() noexcept;

    Source(const Source& other) noexcept;
    Source& operator=(const Source& other) noexcept;
    Source(Source&& other) noexcept = default;
    Source& operator=(Source&& other) noexcept;

    SettleStatus settle(
        RuntimeFirewallLifecycleTerminal prepared_terminal) const noexcept;

    explicit operator bool() const noexcept {
        return static_cast<bool>(state_);
    }

private:
    friend class RuntimeFirewallLifecycleCompletion;
    friend struct RuntimeFirewallLifecycleCompletion::Pair;

    explicit Source(std::shared_ptr<SharedState> state) noexcept;
    void release() noexcept;

    std::shared_ptr<SharedState> state_;
};

// WaitHandle is safe to copy and use from multiple non-control threads. The
// daemon control loop must publish continuations instead of blocking on it;
// this handle is for the lifecycle caller that is waiting while the control
// loop remains free to drain the asynchronous firewall operation.
class RuntimeFirewallLifecycleCompletion::WaitHandle final {
public:
    WaitHandle() noexcept = default;

    RuntimeFirewallLifecycleTerminal wait() const;
    std::optional<RuntimeFirewallLifecycleTerminal> wait_for(
        std::chrono::milliseconds timeout) const;
    std::optional<RuntimeFirewallLifecycleTerminal> try_get() const;
    bool ready() const noexcept;

    explicit operator bool() const noexcept {
        return static_cast<bool>(state_);
    }

private:
    friend class RuntimeFirewallLifecycleCompletion;
    friend struct RuntimeFirewallLifecycleCompletion::Pair;

    explicit WaitHandle(std::shared_ptr<SharedState> state) noexcept;

    std::shared_ptr<SharedState> state_;
};

struct RuntimeFirewallLifecycleCompletion::Pair final {
    Source source;
    WaitHandle wait;
};

static_assert(
    std::is_nothrow_move_constructible_v<
        RuntimeFirewallLifecycleTerminal>);
static_assert(
    std::is_nothrow_destructible_v<
        RuntimeFirewallLifecycleTerminal>);
static_assert(
    std::is_nothrow_copy_constructible_v<
        RuntimeFirewallLifecycleCompletion::Source>);
static_assert(
    std::is_nothrow_move_constructible_v<
        RuntimeFirewallLifecycleCompletion::Source>);

} // namespace keen_pbr3
