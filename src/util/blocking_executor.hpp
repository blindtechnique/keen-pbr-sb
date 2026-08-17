#pragma once

#include "../log/trace.hpp"

#include <condition_variable>
#include <cstddef>
#include <future>
#include <functional>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <queue>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace keen_pbr3 {

class BlockingExecutor {
public:
    BlockingExecutor(std::size_t worker_count, std::size_t max_queue_size);
    ~BlockingExecutor();

    BlockingExecutor(const BlockingExecutor&) = delete;
    BlockingExecutor& operator=(const BlockingExecutor&) = delete;

    void shutdown();
    // Drop work which no worker has claimed yet without stopping the pool.
    // Lifecycle code uses this before coordinator quiescence so a queued task
    // cannot retain an admission lease that the same thread is waiting for.
    void cancel_pending();
    // Service teardown must not turn already-obsolete background work into a
    // serial shutdown tail. Tasks which a worker has already claimed finish
    // normally; tasks still in the queue are destroyed outside the executor
    // lock, releasing captured leases and completing submit() futures with a
    // broken-promise error.
    void cancel_pending_and_shutdown();

    bool try_post(std::string label,
                  std::function<void()> task,
                  TraceId trace_id = current_trace_id());

    template<typename Fn>
    auto submit(std::string label,
                Fn&& fn,
                TraceId trace_id = current_trace_id())
        -> std::future<typename std::invoke_result_t<Fn>> {
        using Result = typename std::invoke_result_t<Fn>;

        auto promise = std::make_shared<std::promise<Result>>();
        auto future = promise->get_future();
        const bool enqueued = enqueue(
            std::move(label),
            [promise, fn = std::forward<Fn>(fn)]() mutable {
                try {
                    if constexpr (std::is_void_v<Result>) {
                        fn();
                        promise->set_value();
                    } else {
                        promise->set_value(fn());
                    }
                } catch (...) {
                    promise->set_exception(std::current_exception());
                }
            },
            trace_id,
            /*block_until_room=*/true);
        if (!enqueued) {
            promise->set_exception(
                std::make_exception_ptr(std::runtime_error("BlockingExecutor is shutting down")));
        }
        return future;
    }

private:
    struct Task {
        std::string label;
        std::function<void()> callback;
        TraceId trace_id{0};
    };

    struct WorkerStart {
        BlockingExecutor* executor;
        std::size_t index;
    };

    static void* worker_entry(void* arg) noexcept;
    void start_worker(std::size_t index);

    bool enqueue(std::string label,
                 std::function<void()> task,
                 TraceId trace_id,
                 bool block_until_room);
    void worker_loop(std::size_t worker_index);

    std::size_t max_queue_size_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::condition_variable space_cv_;
    bool stopping_{false};
    bool shutdown_complete_{false};
    std::queue<Task> queue_;
    std::vector<WorkerStart> worker_starts_;
    std::vector<pthread_t> workers_;
};

} // namespace keen_pbr3
