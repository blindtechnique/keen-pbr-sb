#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace keen_pbr3 {

class BlockingExecutor;
struct ResolverStreamResult;

struct ResolverStreamOperation {
    std::uint64_t runtime_generation{0};
    std::size_t retry_attempt{0};
    std::uint64_t stream_epoch{0};
    std::string attempt_id;
    std::chrono::milliseconds timeout{0};
    // Keeps the runtime-mutation admission, exact resolver generation and IPC
    // stream claim alive until either the worker or the control callback owns
    // the single terminal completion.
    std::shared_ptr<void> lifetime;
    std::function<int()> invoke_hook;
    // A lifecycle operation may own its completion instead of entering the
    // background reload policy callback. It still runs on the control loop
    // under the coordinator's exact claim.
    std::function<void(
        const ResolverStreamOperation&,
        const ResolverStreamResult&)> completion;
};

struct ResolverStreamResult {
    bool completed{false};
    int hook_exit_code{0};
    std::string error;
};

// A deliberately policy-free handoff for resolver stream I/O. The daemon's
// ResolverSyncStateMachine and evaluate_resolver_reload_retry() remain the
// only authorities for convergence and backoff; this class only moves the
// blocking hook/stream wait off the control loop and returns one fenced result.
class ResolverStreamCoordinator {
public:
    using ControlTask = std::function<void()>;
    using PostControlFn = std::function<bool(ControlTask)>;
    using CommitFn = std::function<void(
        const ResolverStreamOperation&, const ResolverStreamResult&)>;

    enum class RequestResult : std::uint8_t {
        started,
        busy,
        rejected,
    };

    ResolverStreamCoordinator(BlockingExecutor& executor,
                              PostControlFn post_control,
                              CommitFn commit);
    ~ResolverStreamCoordinator();

    ResolverStreamCoordinator(const ResolverStreamCoordinator&) = delete;
    ResolverStreamCoordinator& operator=(
        const ResolverStreamCoordinator&) = delete;

    RequestResult request(ResolverStreamOperation operation) noexcept;
    void notify_stream_completed(std::string_view attempt_id,
                                 std::uint64_t stream_epoch) noexcept;

    // Stops admission and wakes a worker waiting for dnsmasq. This method is
    // non-blocking so the daemon can keep pumping its IPC/control sockets while
    // the already accepted hook unwinds.
    void request_stop() noexcept;
    bool wait_for_idle_for(std::chrono::milliseconds timeout) const noexcept;
    bool in_flight() const noexcept;

private:
    struct State;
    std::shared_ptr<State> state_;
};

} // namespace keen_pbr3
