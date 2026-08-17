#pragma once

#include "../dns/keenetic_dns.hpp"

#include <cstdint>
#include <functional>
#include <memory>

namespace keen_pbr3 {

class BlockingExecutor;
class PeriodicTaskMetricsRegistry;

// Runs the potentially blocking Keenetic RCI DNS refresh outside the daemon's
// control loop. Requests are single-flight: while one refresh is in progress,
// any number of additional requests collapse into one rerun using the newest
// runtime generation.
class KeeneticDnsRefreshCoordinator {
public:
    using RefreshFn = std::function<KeeneticDnsRefreshResult()>;
    using ControlTask = std::function<void()>;
    // Must enqueue the task and return whether enqueueing succeeded; it must
    // not execute the callback inline.
    using PostControlFn = std::function<bool(ControlTask)>;

    // Return false when the result belongs to a stale/inactive runtime. The
    // coordinator then records an abandoned run instead of publishing side
    // effects for an obsolete generation.
    using CommitFn = std::function<bool(
        std::uint64_t runtime_generation,
        const KeeneticDnsRefreshResult& result)>;

    enum class RequestResult : std::uint8_t {
        started,
        coalesced,
        rejected,
    };

    KeeneticDnsRefreshCoordinator(
        BlockingExecutor& executor,
        PeriodicTaskMetricsRegistry& metrics,
        RefreshFn refresh,
        PostControlFn post_control,
        CommitFn commit);
    ~KeeneticDnsRefreshCoordinator();

    KeeneticDnsRefreshCoordinator(
        const KeeneticDnsRefreshCoordinator&) = delete;
    KeeneticDnsRefreshCoordinator& operator=(
        const KeeneticDnsRefreshCoordinator&) = delete;

    RequestResult request(std::uint64_t runtime_generation) noexcept;

    // Prevents new work, waits for callbacks already using the owner, and
    // suppresses queued worker/control callbacks that have not started yet.
    void stop() noexcept;

    static constexpr const char* metric_label() noexcept {
        return "keenetic-dns-refresh";
    }

private:
    struct State;
    std::shared_ptr<State> state_;
};

} // namespace keen_pbr3
