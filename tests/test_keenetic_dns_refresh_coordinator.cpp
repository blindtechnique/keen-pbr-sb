#include <doctest/doctest.h>

#include "daemon/keenetic_dns_refresh_coordinator.hpp"
#include "daemon/keenetic_dns_refresh_transaction.hpp"
#include "runtime/periodic_task_metrics.hpp"
#include "util/blocking_executor.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

using namespace std::chrono_literals;

class ManualControlQueue {
public:
    bool post(std::function<void()> task) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!accepting_) {
            return false;
        }
        tasks_.push(std::move(task));
        condition_.notify_all();
        return true;
    }

    void set_accepting(bool accepting) {
        std::lock_guard<std::mutex> lock(mutex_);
        accepting_ = accepting;
    }

    bool wait_for_size(std::size_t expected) {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, 2s, [this, expected]() {
            return tasks_.size() >= expected;
        });
    }

    void run_one() {
        std::function<void()> task;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            REQUIRE_FALSE(tasks_.empty());
            task = std::move(tasks_.front());
            tasks_.pop();
        }
        task();
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    std::queue<std::function<void()>> tasks_;
    bool accepting_{true};
};

// Deterministic barrier for the outcomes the coordinator records on the
// worker thread with no control-queue callback to observe (post rejected or
// post throwing). The tests run a single-worker BlockingExecutor and its queue
// is FIFO, so a task submitted after the refresh task can only start once
// `run_worker` has returned - after its metric write and after the claim and
// callback leases have been released. Waiting on that future is the
// coordinator's own completion signal.
//
// This replaces a poll loop on a fixed 2s wall-clock deadline, which was wrong
// three times over. It could expire under CPU contention before the metric
// converged. Every spin re-evaluated the predicate, so a predicate that
// asserted made the binary's total assertion count depend on how many times
// the loop happened to turn. And waiting on the metric alone was too weak an
// event: the token is finished before the claim lease is released, so a test
// that resumed on the metric could still find the single-flight gate closed
// and see its next `request()` coalesce instead of start.
void drain_refresh_worker(BlockingExecutor& executor) {
    executor.submit("test-drain-refresh-worker", []() {}).get();
}

PeriodicTaskMetricsSnapshot only_metrics(
    const PeriodicTaskMetricsRegistry& registry) {
    const auto snapshots = registry.snapshot();
    REQUIRE(snapshots.size() == 1);
    return snapshots.front();
}

KeeneticDnsRefreshResult updated_result() {
    KeeneticDnsRefreshResult result;
    result.status = KeeneticDnsRefreshStatus::UPDATED;
    result.addresses = {"192.0.2.53"};
    return result;
}

} // namespace

TEST_CASE("Keenetic DNS refresh runs off-thread and commits on control queue") {
    BlockingExecutor executor(1, 4);
    PeriodicTaskMetricsRegistry metrics(
        {KeeneticDnsRefreshCoordinator::metric_label()});
    ManualControlQueue control;
    const std::thread::id caller_thread = std::this_thread::get_id();
    std::thread::id refresh_thread;
    std::vector<std::uint64_t> committed_generations;

    KeeneticDnsRefreshCoordinator coordinator(
        executor,
        metrics,
        [&]() {
            refresh_thread = std::this_thread::get_id();
            return updated_result();
        },
        [&](std::function<void()> task) {
            return control.post(std::move(task));
        },
        [&](std::uint64_t generation,
            const KeeneticDnsRefreshResult&) {
            const bool committed_on_caller_thread =
                std::this_thread::get_id() == caller_thread;
            CHECK(committed_on_caller_thread);
            committed_generations.push_back(generation);
            return true;
        });

    CHECK(coordinator.request(17) ==
          KeeneticDnsRefreshCoordinator::RequestResult::started);
    REQUIRE(control.wait_for_size(1));
    const bool refreshed_off_caller_thread =
        refresh_thread != caller_thread;
    CHECK(refreshed_off_caller_thread);
    CHECK(committed_generations.empty());
    control.run_one();

    REQUIRE(committed_generations.size() == 1);
    CHECK(committed_generations.front() == 17);
    const auto snapshot = only_metrics(metrics);
    CHECK(snapshot.success == 1);
    CHECK(snapshot.in_flight == 0);
    executor.shutdown();
}

TEST_CASE("Keenetic DNS refresh retains mutation lifetime through control commit") {
    BlockingExecutor executor(1, 4);
    PeriodicTaskMetricsRegistry metrics(
        {KeeneticDnsRefreshCoordinator::metric_label()});
    ManualControlQueue control;
    auto exact_payload = std::make_shared<int>(53);
    std::weak_ptr<int> observed = exact_payload;
    bool commit_observed_lifetime = false;

    KeeneticDnsRefreshCoordinator coordinator(
        executor,
        metrics,
        []() { return updated_result(); },
        [&](std::function<void()> task) {
            return control.post(std::move(task));
        },
        [&](std::uint64_t generation,
            const KeeneticDnsRefreshResult&) {
            CHECK(generation == 23);
            const auto payload = observed.lock();
            REQUIRE(payload);
            CHECK(*payload == 53);
            commit_observed_lifetime = true;
            return true;
        });

    REQUIRE(coordinator.request(23, exact_payload) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    exact_payload.reset();
    REQUIRE(control.wait_for_size(1));
    CHECK_FALSE(observed.expired());
    control.run_one();

    CHECK(commit_observed_lifetime);
    CHECK(observed.expired());
    executor.shutdown();
}

TEST_CASE("Keenetic DNS refresh coalesces requests into one latest-generation rerun") {
    BlockingExecutor executor(1, 4);
    PeriodicTaskMetricsRegistry metrics(
        {KeeneticDnsRefreshCoordinator::metric_label()});
    ManualControlQueue control;
    std::mutex refresh_mutex;
    std::condition_variable refresh_condition;
    bool release_first{false};
    std::size_t refresh_calls{0};
    std::vector<std::uint64_t> committed_generations;

    KeeneticDnsRefreshCoordinator coordinator(
        executor,
        metrics,
        [&]() {
            std::unique_lock<std::mutex> lock(refresh_mutex);
            ++refresh_calls;
            refresh_condition.notify_all();
            if (refresh_calls == 1) {
                refresh_condition.wait(lock, [&]() {
                    return release_first;
                });
                return updated_result();
            }
            KeeneticDnsRefreshResult result;
            result.status = KeeneticDnsRefreshStatus::UNCHANGED;
            return result;
        },
        [&](std::function<void()> task) {
            return control.post(std::move(task));
        },
        [&](std::uint64_t generation,
            const KeeneticDnsRefreshResult&) {
            committed_generations.push_back(generation);
            return true;
        });

    REQUIRE(coordinator.request(1) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    {
        std::unique_lock<std::mutex> lock(refresh_mutex);
        REQUIRE(refresh_condition.wait_for(lock, 2s, [&]() {
            return refresh_calls == 1;
        }));
    }
    CHECK(coordinator.request(2) ==
          KeeneticDnsRefreshCoordinator::RequestResult::coalesced);
    CHECK(coordinator.request(3) ==
          KeeneticDnsRefreshCoordinator::RequestResult::coalesced);
    {
        std::lock_guard<std::mutex> lock(refresh_mutex);
        release_first = true;
    }
    refresh_condition.notify_all();

    REQUIRE(control.wait_for_size(1));
    control.run_one();
    REQUIRE(control.wait_for_size(1));
    control.run_one();

    REQUIRE(committed_generations.size() == 2);
    CHECK(committed_generations[0] == 1);
    CHECK(committed_generations[1] == 3);
    CHECK(refresh_calls == 2);
    const auto snapshot = only_metrics(metrics);
    CHECK(snapshot.runs == 2);
    CHECK(snapshot.success == 1);
    CHECK(snapshot.noop == 1);
    executor.shutdown();
}

TEST_CASE("Keenetic DNS refresh releases gate when control post is rejected") {
    BlockingExecutor executor(1, 4);
    PeriodicTaskMetricsRegistry metrics(
        {KeeneticDnsRefreshCoordinator::metric_label()});
    ManualControlQueue control;
    control.set_accepting(false);
    std::size_t refresh_calls{0};

    KeeneticDnsRefreshCoordinator coordinator(
        executor,
        metrics,
        [&]() {
            ++refresh_calls;
            return updated_result();
        },
        [&](std::function<void()> task) {
            return control.post(std::move(task));
        },
        [](std::uint64_t, const KeeneticDnsRefreshResult&) {
            return true;
        });

    REQUIRE(coordinator.request(1) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    drain_refresh_worker(executor);
    REQUIRE(only_metrics(metrics).abandoned == 1);

    control.set_accepting(true);
    const auto retry_request = coordinator.request(2);
    REQUIRE(retry_request !=
            KeeneticDnsRefreshCoordinator::RequestResult::rejected);
    REQUIRE(control.wait_for_size(1));
    control.run_one();
    CHECK(refresh_calls == 2);
    const auto snapshot = only_metrics(metrics);
    CHECK(snapshot.abandoned == 1);
    CHECK(snapshot.success == 1);
    CHECK(snapshot.in_flight == 0);
    executor.shutdown();
}

TEST_CASE("Keenetic DNS refresh ignores a callback queued before post throws") {
    BlockingExecutor executor(1, 4);
    PeriodicTaskMetricsRegistry metrics(
        {KeeneticDnsRefreshCoordinator::metric_label()});
    ManualControlQueue control;
    std::size_t post_calls{0};
    std::vector<std::uint64_t> committed_generations;

    KeeneticDnsRefreshCoordinator coordinator(
        executor,
        metrics,
        []() { return updated_result(); },
        [&](std::function<void()> task) {
            const bool posted = control.post(std::move(task));
            ++post_calls;
            if (post_calls == 1) {
                throw std::runtime_error("wake failed after queue ownership");
            }
            return posted;
        },
        [&](std::uint64_t generation,
            const KeeneticDnsRefreshResult&) {
            committed_generations.push_back(generation);
            return true;
        });

    REQUIRE(coordinator.request(1) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    REQUIRE(control.wait_for_size(1));
    drain_refresh_worker(executor);
    REQUIRE(only_metrics(metrics).failure == 1);

    REQUIRE(coordinator.request(2) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    REQUIRE(control.wait_for_size(2));

    // The first callback no longer owns the active claim and must not commit
    // or disturb the retry that was accepted after the enqueue exception.
    control.run_one();
    CHECK(committed_generations.empty());
    control.run_one();

    REQUIRE(committed_generations.size() == 1);
    CHECK(committed_generations.front() == 2);
    const auto snapshot = only_metrics(metrics);
    CHECK(snapshot.failure == 1);
    CHECK(snapshot.success == 1);
    CHECK(snapshot.in_flight == 0);
    executor.shutdown();
}

TEST_CASE("Keenetic DNS refresh fences a callback started before post throws") {
    BlockingExecutor executor(1, 4);
    PeriodicTaskMetricsRegistry metrics(
        {KeeneticDnsRefreshCoordinator::metric_label()});
    ManualControlQueue control;
    std::mutex callback_mutex;
    std::condition_variable callback_condition;
    bool callback_started{false};
    bool callback_returned{false};
    bool callback_started_in_time{false};
    bool callback_was_waiting{false};
    std::thread early_control_callback;
    std::size_t post_calls{0};
    std::vector<std::uint64_t> committed_generations;

    KeeneticDnsRefreshCoordinator coordinator(
        executor,
        metrics,
        []() { return updated_result(); },
        [&](std::function<void()> task) {
            ++post_calls;
            if (post_calls == 1) {
                early_control_callback = std::thread(
                    [task = std::move(task),
                     &callback_mutex,
                     &callback_condition,
                     &callback_started,
                     &callback_returned]() mutable {
                        {
                            std::lock_guard<std::mutex> lock(callback_mutex);
                            callback_started = true;
                        }
                        callback_condition.notify_all();
                        task();
                        {
                            std::lock_guard<std::mutex> lock(callback_mutex);
                            callback_returned = true;
                        }
                        callback_condition.notify_all();
                    });
                {
                    std::unique_lock<std::mutex> lock(callback_mutex);
                    callback_started_in_time =
                        callback_condition.wait_for(lock, 2s, [&]() {
                        return callback_started;
                    });
                    callback_was_waiting = !callback_returned;
                }
                throw std::runtime_error(
                    "wake failed while callback was already running");
            }
            return control.post(std::move(task));
        },
        [&](std::uint64_t generation,
            const KeeneticDnsRefreshResult&) {
            committed_generations.push_back(generation);
            return true;
        });

    REQUIRE(coordinator.request(1) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    drain_refresh_worker(executor);
    REQUIRE(only_metrics(metrics).failure == 1);
    REQUIRE(early_control_callback.joinable());
    early_control_callback.join();
    CHECK(callback_started_in_time);
    CHECK(callback_was_waiting);
    CHECK(callback_returned);
    CHECK(committed_generations.empty());

    REQUIRE(coordinator.request(2) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    REQUIRE(control.wait_for_size(1));
    control.run_one();

    REQUIRE(committed_generations.size() == 1);
    CHECK(committed_generations.front() == 2);
    const auto snapshot = only_metrics(metrics);
    CHECK(snapshot.failure == 1);
    CHECK(snapshot.success == 1);
    CHECK(snapshot.in_flight == 0);
    executor.shutdown();
}

TEST_CASE("Keenetic DNS refresh releases gate and token on executor rejection") {
    BlockingExecutor executor(0, 0);
    PeriodicTaskMetricsRegistry metrics(
        {KeeneticDnsRefreshCoordinator::metric_label()});
    KeeneticDnsRefreshCoordinator coordinator(
        executor,
        metrics,
        []() { return updated_result(); },
        [](std::function<void()>) { return true; },
        [](std::uint64_t, const KeeneticDnsRefreshResult&) {
            return true;
        });

    CHECK(coordinator.request(1) ==
          KeeneticDnsRefreshCoordinator::RequestResult::rejected);
    CHECK(coordinator.request(2) ==
          KeeneticDnsRefreshCoordinator::RequestResult::rejected);
    const auto snapshot = only_metrics(metrics);
    // Rejected work never ran; it is tracked only as a skipped attempt.
    CHECK(snapshot.runs == 0);
    CHECK(snapshot.skipped == 2);
    CHECK(snapshot.in_flight == 0);
    executor.shutdown();
}

TEST_CASE("Keenetic DNS refresh records stale commit and fetch failure outcomes") {
    BlockingExecutor executor(1, 4);
    PeriodicTaskMetricsRegistry metrics(
        {KeeneticDnsRefreshCoordinator::metric_label()});
    ManualControlQueue control;
    std::size_t refresh_calls{0};

    KeeneticDnsRefreshCoordinator coordinator(
        executor,
        metrics,
        [&]() {
            ++refresh_calls;
            if (refresh_calls == 1) {
                return updated_result();
            }
            KeeneticDnsRefreshResult result;
            result.status =
                KeeneticDnsRefreshStatus::FETCH_FAILED_USED_CACHE;
            result.error = "RCI unavailable";
            return result;
        },
        [&](std::function<void()> task) {
            return control.post(std::move(task));
        },
        [](std::uint64_t generation,
           const KeeneticDnsRefreshResult&) {
            return generation != 4;
        });

    REQUIRE(coordinator.request(4) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    REQUIRE(control.wait_for_size(1));
    control.run_one();
    REQUIRE(coordinator.request(5) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    REQUIRE(control.wait_for_size(1));
    control.run_one();

    const auto snapshot = only_metrics(metrics);
    CHECK(snapshot.abandoned == 1);
    CHECK(snapshot.failure == 1);
    CHECK(snapshot.last_error == "RCI unavailable");
    executor.shutdown();
}

TEST_CASE("Keenetic DNS refresh stop waits for callback and suppresses commit") {
    BlockingExecutor executor(1, 4);
    PeriodicTaskMetricsRegistry metrics(
        {KeeneticDnsRefreshCoordinator::metric_label()});
    ManualControlQueue control;
    std::mutex refresh_mutex;
    std::condition_variable refresh_condition;
    bool refresh_started{false};
    bool release_refresh{false};
    std::atomic<bool> stop_returned{false};
    std::size_t commit_calls{0};

    KeeneticDnsRefreshCoordinator coordinator(
        executor,
        metrics,
        [&]() {
            std::unique_lock<std::mutex> lock(refresh_mutex);
            refresh_started = true;
            refresh_condition.notify_all();
            refresh_condition.wait(lock, [&]() {
                return release_refresh;
            });
            return updated_result();
        },
        [&](std::function<void()> task) {
            return control.post(std::move(task));
        },
        [&](std::uint64_t, const KeeneticDnsRefreshResult&) {
            ++commit_calls;
            return true;
        });

    REQUIRE(coordinator.request(9) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    {
        std::unique_lock<std::mutex> lock(refresh_mutex);
        REQUIRE(refresh_condition.wait_for(lock, 2s, [&]() {
            return refresh_started;
        }));
    }

    std::thread stopper([&]() {
        coordinator.stop();
        stop_returned.store(true, std::memory_order_release);
    });

    // `stop()` publishes the stopping flag under the state mutex before it
    // blocks on the in-flight callback, and `request()` is rejected only once
    // that flag is set. A rejection is therefore proof that `stop()` has
    // reached its wait. The refresh callback is still parked inside
    // `refresh()` holding the callback lease, so the in-flight count cannot
    // have dropped to zero and `stop()` cannot have returned yet.
    //
    // The previous `sleep_for(5ms)` guessed at that instead. Under CPU
    // contention the stopper thread could go unscheduled for the whole 5ms,
    // the test would then release the refresh before `stop()` had set the
    // flag, and the run would complete normally through the control queue -
    // leaving the token unfinished and failing the abandoned/in_flight checks
    // below with no indication that a timing assumption, not the coordinator,
    // was at fault.
    while (coordinator.request(10) !=
           KeeneticDnsRefreshCoordinator::RequestResult::rejected) {
        std::this_thread::yield();
    }
    CHECK_FALSE(stop_returned.load(std::memory_order_acquire));

    {
        std::lock_guard<std::mutex> lock(refresh_mutex);
        release_refresh = true;
    }
    refresh_condition.notify_all();
    stopper.join();

    CHECK(stop_returned.load(std::memory_order_acquire));
    CHECK(commit_calls == 0);
    CHECK(coordinator.request(10) ==
          KeeneticDnsRefreshCoordinator::RequestResult::rejected);
    const auto snapshot = only_metrics(metrics);
    CHECK(snapshot.runs == 1);
    CHECK(snapshot.abandoned == 1);
    CHECK(snapshot.in_flight == 0);
    executor.shutdown();
}

TEST_CASE("Keenetic DNS refresh releases single-flight after transactional commit rollback") {
    BlockingExecutor executor(1, 4);
    PeriodicTaskMetricsRegistry metrics(
        {KeeneticDnsRefreshCoordinator::metric_label()});
    ManualControlQueue control;
    std::size_t commit_calls{0};
    int active_generation{1};

    KeeneticDnsRefreshCoordinator coordinator(
        executor,
        metrics,
        []() { return updated_result(); },
        [&](std::function<void()> task) {
            return control.post(std::move(task));
        },
        [&](std::uint64_t,
            const KeeneticDnsRefreshResult&) {
            ++commit_calls;
            const bool fail_this_commit = commit_calls == 1;
            const auto transaction =
                run_keenetic_dns_refresh_transaction(
                    /*firewall_needed=*/false,
                    [&]() noexcept { active_generation = 2; },
                    []() {},
                    [&](bool& resolver_stream_attempted) {
                        resolver_stream_attempted = true;
                        if (fail_this_commit) {
                            throw std::runtime_error(
                                "resolver stream failed");
                        }
                    },
                    [&]() noexcept { active_generation = 1; },
                    []() {},
                    []() {});
            if (transaction.primary_failure) {
                std::rethrow_exception(transaction.primary_failure);
            }
            return transaction.committed;
        });

    REQUIRE(coordinator.request(31) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    REQUIRE(control.wait_for_size(1));
    control.run_one();
    CHECK(active_generation == 1);

    REQUIRE(coordinator.request(32) ==
            KeeneticDnsRefreshCoordinator::RequestResult::started);
    REQUIRE(control.wait_for_size(1));
    control.run_one();
    CHECK(active_generation == 2);

    const auto snapshot = only_metrics(metrics);
    CHECK(snapshot.runs == 2);
    CHECK(snapshot.failure == 1);
    CHECK(snapshot.success == 1);
    CHECK(snapshot.in_flight == 0);
    executor.shutdown();
}
