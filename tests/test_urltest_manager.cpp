#include <doctest/doctest.h>

#include "../src/daemon/scheduler.hpp"
#include "../src/health/url_tester.hpp"
#include "../src/routing/urltest_manager.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

class FakeRepeatingScheduler final : public RepeatingTaskScheduler {
public:
    int schedule_repeating(std::chrono::milliseconds,
                           TaskCallback callback,
                           std::string label) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fail_next_schedule_) {
            fail_next_schedule_ = false;
            throw std::runtime_error(
                "scripted repeating-task admission failure");
        }
        const int task_id = next_task_id_++;
        tasks_.emplace(task_id,
                       Task{std::move(callback), std::move(label)});
        return task_id;
    }

    void cancel(int task_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        cancelled_ = tasks_.erase(task_id) > 0 || cancelled_;
    }

    bool cancelled() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cancelled_;
    }

    void fail_next_schedule() {
        std::lock_guard<std::mutex> lock(mutex_);
        fail_next_schedule_ = true;
    }

    bool fire_label(const std::string& label) {
        TaskCallback callback;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto task = std::find_if(
                tasks_.begin(),
                tasks_.end(),
                [&label](const auto& entry) {
                    return entry.second.label == label;
                });
            if (task == tasks_.end()) {
                return false;
            }
            callback = task->second.callback;
        }
        callback();
        return true;
    }

    std::size_t count_label(const std::string& label) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<std::size_t>(std::count_if(
            tasks_.begin(),
            tasks_.end(),
            [&label](const auto& entry) {
                return entry.second.label == label;
            }));
    }

private:
    struct Task {
        TaskCallback callback;
        std::string label;
    };

    mutable std::mutex mutex_;
    int next_task_id_{17};
    std::map<int, Task> tasks_;
    bool cancelled_{false};
    bool fail_next_schedule_{false};
};

class UrltestTransport final : public HttpTransport {
public:
    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        HttpTransportResponse response;
        if (request.fwmark == kPrimaryMark &&
            !primary_available_.load(std::memory_order_acquire)) {
            response.status_code = 503;
            response.elapsed = std::chrono::milliseconds(1);
            return response;
        }

        response.status_code = 204;
        const bool prefer_primary = prefer_primary_.load(std::memory_order_acquire);
        if (request.fwmark == kPrimaryMark) {
            response.elapsed = std::chrono::milliseconds(prefer_primary ? 8 : 80);
        } else {
            response.elapsed = std::chrono::milliseconds(prefer_primary ? 80 : 8);
        }
        return response;
    }

    void prefer_primary(bool value) {
        prefer_primary_.store(value, std::memory_order_release);
    }

    void set_primary_available(bool value) {
        primary_available_.store(value, std::memory_order_release);
    }

    static constexpr std::uint32_t kPrimaryMark = 0x10000;
    static constexpr std::uint32_t kBackupMark = 0x20000;

private:
    std::atomic<bool> prefer_primary_{true};
    std::atomic<bool> primary_available_{true};
};

class BindingCaptureUrltestTransport final : public HttpTransport {
public:
    HttpTransportResponse perform(
        const HttpTransportRequest& request) override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            bind_interfaces_[request.fwmark] = request.bind_interface;
        }
        return HttpTransportResponse{
            .status_code = 204,
            .elapsed = std::chrono::milliseconds(1),
        };
    }

    std::string bind_interface(std::uint32_t fwmark) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = bind_interfaces_.find(fwmark);
        return found != bind_interfaces_.end() ? found->second
                                               : std::string{};
    }

private:
    mutable std::mutex mutex_;
    std::map<std::uint32_t, std::string> bind_interfaces_;
};

class CoordinatedUrltestTransport final : public HttpTransport {
public:
    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        std::unique_lock<std::mutex> lock(mutex_);
        if (request.fwmark == UrltestTransport::kPrimaryMark) {
            primary_started_ = true;
            cv_.notify_all();
            cv_.wait(lock, [this]() {
                return release_primary_;
            });
        } else {
            backup_started_ = true;
            cv_.notify_all();
        }

        HttpTransportResponse response;
        response.status_code = 204;
        response.elapsed = std::chrono::milliseconds(1);
        return response;
    }

    bool wait_for_both_candidates() {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, std::chrono::seconds(1), [this]() {
            return primary_started_ && backup_started_;
        });
    }

    void release_primary() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            release_primary_ = true;
        }
        cv_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    bool primary_started_{false};
    bool backup_started_{false};
    bool release_primary_{false};
};

class RecoverableUrltestTransport final : public HttpTransport {
public:
    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        if (request.fwmark == UrltestTransport::kPrimaryMark) {
            if (throw_primary_.load(std::memory_order_acquire)) {
                throw std::runtime_error("scripted primary probe failure");
            }
            if (!primary_available_.load(std::memory_order_acquire)) {
                return HttpTransportResponse{
                    .status_code = 503,
                    .elapsed = std::chrono::milliseconds(1),
                };
            }
        }

        return HttpTransportResponse{
            .status_code = 204,
            .elapsed = std::chrono::milliseconds(1),
        };
    }

    void set_primary_available(bool value) {
        primary_available_.store(value, std::memory_order_release);
    }

    void set_throw_primary(bool value) {
        throw_primary_.store(value, std::memory_order_release);
    }

private:
    std::atomic<bool> primary_available_{true};
    std::atomic<bool> throw_primary_{false};
};

class BlockingOnceUrltestTransport final : public HttpTransport {
public:
    HttpTransportResponse perform(const HttpTransportRequest&) override {
        std::unique_lock<std::mutex> lock(mutex_);
        ++call_count_;
        if (call_count_ == 1) {
            first_started_ = true;
            cv_.notify_all();
            cv_.wait(lock, [this]() { return release_first_; });
        }
        return HttpTransportResponse{
            .status_code = 204,
            .elapsed = std::chrono::milliseconds(1),
        };
    }

    bool wait_for_first() {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, std::chrono::seconds(2), [this]() {
            return first_started_;
        });
    }

    void release_first() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            release_first_ = true;
        }
        cv_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    int call_count_{0};
    bool first_started_{false};
    bool release_first_{false};
};

class BlockingTaskGate {
public:
    void run() {
        std::unique_lock<std::mutex> lock(mutex_);
        started_ = true;
        cv_.notify_all();
        cv_.wait(lock, [this]() { return released_; });
    }

    bool wait_until_started() {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, std::chrono::seconds(2), [this]() {
            return started_;
        });
    }

    void release() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            released_ = true;
        }
        cv_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    bool started_{false};
    bool released_{false};
};

struct PendingCommit {
    std::string tag;
    std::uint64_t generation{0};
    std::map<std::string, URLTestResult> results;
};

class CommitQueue {
public:
    void push(std::string tag,
              std::uint64_t generation,
              std::map<std::string, URLTestResult> results) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            commits_.push_back(PendingCommit{
                .tag = std::move(tag),
                .generation = generation,
                .results = std::move(results),
            });
        }
        cv_.notify_one();
    }

    PendingCommit pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        const bool ready = cv_.wait_for(lock, std::chrono::seconds(2), [this]() {
            return !commits_.empty();
        });
        REQUIRE(ready);
        auto commit = std::move(commits_.front());
        commits_.erase(commits_.begin());
        return commit;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return commits_.size();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<PendingCommit> commits_;
};

Outbound make_urltest_outbound() {
    OutboundGroup group;
    group.outbounds = {"primary", "backup"};
    group.weight = 1;

    RetryConfig retry;
    retry.attempts = 1;
    retry.interval_ms = 0;

    Outbound outbound;
    outbound.tag = "automatic";
    outbound.type = OutboundType::URLTEST;
    outbound.url = "https://example.test/generate_204";
    outbound.interval_ms = 600000;
    outbound.probe_timeout_ms = 1000;
    outbound.retry = retry;
    outbound.tolerance_ms = 0;
    outbound.outbound_groups = std::vector<OutboundGroup>{group};
    return outbound;
}

Outbound make_priority_urltest_outbound() {
    auto outbound = make_urltest_outbound();
    outbound.selection_mode = UrltestSelectionMode::PRIORITY;

    CircuitBreakerConfig circuit_breaker;
    circuit_breaker.failure_threshold = 1;
    circuit_breaker.success_threshold = 2;
    circuit_breaker.half_open_max_requests = 1;
    circuit_breaker.timeout_ms = 0;
    outbound.circuit_breaker = circuit_breaker;

    return outbound;
}

Outbound make_single_candidate_urltest_outbound() {
    auto outbound = make_urltest_outbound();
    OutboundGroup group;
    group.outbounds = {"primary"};
    group.weight = 1;
    outbound.outbound_groups = std::vector<OutboundGroup>{group};
    return outbound;
}

OutboundMarkMap make_marks() {
    return {
        {"primary", UrltestTransport::kPrimaryMark},
        {"backup", UrltestTransport::kBackupMark},
    };
}

template <typename Predicate>
bool wait_until(Predicate&& predicate) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return predicate();
}

} // namespace

TEST_CASE("initial urltest probe commits through the controller callback") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(1, 8);
    CommitQueue commits;
    std::vector<UrltestSelectionChange> changes;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&changes](const UrltestSelectionChange& change) {
            changes.push_back(change);
            return true;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_urltest_outbound());
    auto initial = commits.pop();

    CHECK(initial.tag == "automatic");
    CHECK(manager.get_selected("automatic").empty());
    REQUIRE(manager.get_state("automatic").has_value());
    CHECK(manager.get_state("automatic")->probe_inflight);

    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));
    CHECK(manager.get_selected("automatic") == "primary");
    REQUIRE(changes.size() == 1);
    CHECK(changes.front().urltest_tag == "automatic");
    CHECK(changes.front().previous_child_tag.empty());
    CHECK(changes.front().new_child_tag == "primary");
    CHECK(changes.front().reason ==
          UrltestSelectionChangeReason::initial);

    transport->prefer_primary(false);
    manager.trigger_immediate_test("automatic");
    auto changed = commits.pop();

    // A newly measured selection is not visible until the controller commits
    // it; this is the boundary that prevents publishing stale routing state.
    CHECK(manager.get_selected("automatic") == "primary");
    CHECK(manager.commit_probe_results(changed.tag,
                                       changed.generation,
                                       std::move(changed.results)));
    CHECK(manager.get_selected("automatic") == "backup");
    REQUIRE(changes.size() == 2);
    CHECK(changes.back().previous_child_tag == "primary");
    CHECK(changes.back().new_child_tag == "backup");
    CHECK(changes.back().reason ==
          UrltestSelectionChangeReason::healthy_rebalance);
}

TEST_CASE("urltest binds direct interface children and keeps nested selectors mark-only") {
    constexpr std::uint32_t kDirectMark = 0x30000;
    constexpr std::uint32_t kNestedSelectorMark = 0x40000;
    auto transport = std::make_shared<BindingCaptureUrltestTransport>();
    URLTester tester(transport);
    const OutboundMarkMap marks = {
        {"direct", kDirectMark},
        {"nested", kNestedSelectorMark},
    };
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    auto outbound = make_priority_urltest_outbound();
    OutboundGroup group;
    group.outbounds = {"direct", "nested"};
    group.weight = 1;
    outbound.outbound_groups = std::vector<OutboundGroup>{group};

    // The daemon supplies only direct INTERFACE children. A nested URLTEST
    // selector intentionally has no device because its mark resolves to a
    // dynamic leaf.
    manager.register_urltest(
        outbound, {}, {{"direct", "nwg5"}});
    auto initial = commits.pop();
    REQUIRE(initial.results.count("direct") == 1);
    REQUIRE(initial.results.count("nested") == 1);
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));

    CHECK(transport->bind_interface(kDirectMark) == "nwg5");
    CHECK(transport->bind_interface(kNestedSelectorMark).empty());
    const auto state = manager.get_state("automatic");
    REQUIRE(state.has_value());
    CHECK(state->direct_child_interfaces.count("direct") == 1);
    CHECK(state->direct_child_interfaces.count("nested") == 0);
}

TEST_CASE("retained urltest selection is the cursor for the first probe") {
    auto transport = std::make_shared<UrltestTransport>();
    transport->set_primary_available(false);
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(1, 8);
    CommitQueue commits;
    std::vector<UrltestSelectionChange> changes;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&changes](const UrltestSelectionChange& change) {
            changes.push_back(change);
            return true;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_priority_urltest_outbound(), "primary");
    CHECK(manager.get_selected("automatic") == "primary");

    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));
    CHECK(manager.get_selected("automatic") == "backup");
    REQUIRE(changes.size() == 1);
    CHECK(changes.front().previous_child_tag == "primary");
    CHECK(changes.front().new_child_tag == "backup");
    CHECK(changes.front().reason ==
          UrltestSelectionChangeReason::previous_unhealthy);
}

TEST_CASE("urltest selection cursor can be restored after an apply failure") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(1, 8);
    CommitQueue commits;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_urltest_outbound(), "primary");
    REQUIRE(manager.get_state("automatic").has_value());
    const auto probe_generation =
        manager.get_state("automatic")->generation;
    CHECK(manager.synchronize_selected_if_generation(
        "automatic", probe_generation, "backup"));
    CHECK(manager.get_selected("automatic") == "backup");
    CHECK_FALSE(manager.synchronize_selected_if_generation(
        "automatic", probe_generation + 1, "primary"));
    CHECK(manager.get_selected("automatic") == "backup");
    CHECK(manager.synchronize_selected("automatic", "backup"));
    CHECK(manager.get_selected("automatic") == "backup");
    CHECK(manager.synchronize_selected("automatic", "primary"));
    CHECK(manager.get_selected("automatic") == "primary");

    CHECK_FALSE(manager.synchronize_selected("automatic", "missing"));
    CHECK(manager.get_selected("automatic") == "primary");
    CHECK_FALSE(manager.synchronize_selected("removed", "primary"));
}

TEST_CASE("urltest probes two candidates concurrently without changing priority order") {
    auto transport = std::make_shared<CoordinatedUrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_priority_urltest_outbound());

    // The primary probe is deliberately held open. The backup must still
    // start on the second bounded blocking worker instead of waiting for the
    // primary timeout/retry sequence.
    CHECK(transport->wait_for_both_candidates());
    transport->release_primary();

    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));
    // Parallel completion order must not affect declared-priority selection.
    CHECK(manager.get_selected("automatic") == "primary");
}

TEST_CASE("urltest ignores a probe result from a previous registration") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(1, 8);
    CommitQueue commits;
    int change_count = 0;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&change_count](const UrltestSelectionChange&) {
            ++change_count;
            return true;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_urltest_outbound());
    auto stale = commits.pop();
    manager.clear();
    CHECK(scheduler.cancelled());

    manager.register_urltest(make_urltest_outbound());
    auto current = commits.pop();
    REQUIRE(current.generation != stale.generation);

    CHECK_FALSE(manager.commit_probe_results(stale.tag,
                                             stale.generation,
                                             std::move(stale.results)));
    CHECK(manager.get_selected("automatic").empty());
    REQUIRE(manager.get_state("automatic").has_value());
    CHECK(manager.get_state("automatic")->probe_inflight);
    CHECK(change_count == 0);

    CHECK(manager.commit_probe_results(current.tag,
                                       current.generation,
                                       std::move(current.results)));
    CHECK(manager.get_selected("automatic") == "primary");
    CHECK(change_count == 1);
}

TEST_CASE("priority urltest returns to the first healthy declared outbound") {
    auto transport = std::make_shared<UrltestTransport>();
    // The preferred outbound is deliberately slower. Priority mode must use
    // declaration order, not latency, while both candidates are healthy.
    transport->prefer_primary(false);

    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(1, 8);
    CommitQueue commits;
    std::vector<UrltestSelectionChange> changes;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&changes](const UrltestSelectionChange& change) {
            changes.push_back(change);
            return true;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_priority_urltest_outbound());
    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));
    CHECK(manager.get_selected("automatic") == "primary");

    transport->set_primary_available(false);
    manager.trigger_immediate_test("automatic");
    auto failed_primary = commits.pop();
    CHECK(manager.commit_probe_results(failed_primary.tag,
                                       failed_primary.generation,
                                       std::move(failed_primary.results)));
    CHECK(manager.get_selected("automatic") == "backup");

    transport->set_primary_available(true);
    manager.trigger_immediate_test("automatic");
    auto first_recovery_probe = commits.pop();
    CHECK_FALSE(manager.commit_probe_results(first_recovery_probe.tag,
                                             first_recovery_probe.generation,
                                             std::move(first_recovery_probe.results)));
    CHECK(manager.get_selected("automatic") == "backup");

    manager.trigger_immediate_test("automatic");
    auto recovered_primary = commits.pop();
    CHECK(manager.commit_probe_results(recovered_primary.tag,
                                       recovered_primary.generation,
                                       std::move(recovered_primary.results)));
    CHECK(manager.get_selected("automatic") == "primary");

    REQUIRE(changes.size() == 3);
    CHECK(changes[0].reason ==
          UrltestSelectionChangeReason::initial);
    CHECK(changes[1].previous_child_tag == "primary");
    CHECK(changes[1].new_child_tag == "backup");
    CHECK(changes[1].reason ==
          UrltestSelectionChangeReason::previous_unhealthy);
    CHECK(changes[2].previous_child_tag == "backup");
    CHECK(changes[2].new_child_tag == "primary");
    CHECK(changes[2].reason ==
          UrltestSelectionChangeReason::healthy_rebalance);
}

TEST_CASE("priority urltest quarantines a failed preferred child until consecutive recovery successes") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    std::vector<UrltestSelectionChange> changes;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&changes](const UrltestSelectionChange& change) {
            changes.push_back(change);
            return true;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    auto outbound = make_priority_urltest_outbound();
    // Match the live configuration shape: one failed selected probe causes
    // fail-away while the generic circuit remains CLOSED below its threshold.
    outbound.circuit_breaker->failure_threshold = 5;
    outbound.circuit_breaker->success_threshold = 2;
    outbound.circuit_breaker->timeout_ms = 30000;

    manager.register_urltest(
        outbound,
        {},
        {{"primary", "nwg5"}, {"backup", "nwg6"}});
    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));
    CHECK(manager.get_selected("automatic") == "primary");

    transport->set_primary_available(false);
    manager.trigger_immediate_test("automatic");
    auto failed_primary = commits.pop();
    CHECK(manager.commit_probe_results(failed_primary.tag,
                                       failed_primary.generation,
                                       std::move(failed_primary.results)));
    CHECK(manager.get_selected("automatic") == "backup");
    auto state = manager.get_state("automatic");
    REQUIRE(state.has_value());
    CHECK(state->circuit_breakers.at("primary").state("primary") ==
          CircuitState::closed);
    CHECK(state->priority_recovery_successes.at("primary") == 0);

    transport->set_primary_available(true);
    manager.trigger_immediate_test("automatic");
    auto first_success = commits.pop();
    CHECK_FALSE(manager.commit_probe_results(first_success.tag,
                                             first_success.generation,
                                             std::move(first_success.results)));
    CHECK(manager.get_selected("automatic") == "backup");
    CHECK(manager.get_state("automatic")
              ->priority_recovery_successes.at("primary") == 1);

    // A failed recovery probe resets the consecutive-success streak even
    // though the generic breaker remains CLOSED.
    transport->set_primary_available(false);
    manager.trigger_immediate_test("automatic");
    auto interrupted_recovery = commits.pop();
    CHECK_FALSE(manager.commit_probe_results(
        interrupted_recovery.tag,
        interrupted_recovery.generation,
        std::move(interrupted_recovery.results)));
    CHECK(manager.get_selected("automatic") == "backup");
    CHECK(manager.get_state("automatic")
              ->priority_recovery_successes.at("primary") == 0);

    transport->set_primary_available(true);
    manager.trigger_immediate_test("automatic");
    auto restarted_recovery = commits.pop();
    CHECK_FALSE(manager.commit_probe_results(
        restarted_recovery.tag,
        restarted_recovery.generation,
        std::move(restarted_recovery.results)));
    CHECK(manager.get_selected("automatic") == "backup");

    manager.trigger_immediate_test("automatic");
    auto recovered_primary = commits.pop();
    CHECK(manager.commit_probe_results(recovered_primary.tag,
                                       recovered_primary.generation,
                                       std::move(recovered_primary.results)));
    CHECK(manager.get_selected("automatic") == "primary");
    state = manager.get_state("automatic");
    REQUIRE(state.has_value());
    CHECK(state->priority_recovery_successes.count("primary") == 0);

    REQUIRE(changes.size() == 3);
    CHECK(changes[1].previous_child_tag == "primary");
    CHECK(changes[1].new_child_tag == "backup");
    CHECK(changes[2].previous_child_tag == "backup");
    CHECK(changes[2].new_child_tag == "primary");
}

TEST_CASE("priority urltest honors group weight before declaration order") {
    auto transport = std::make_shared<UrltestTransport>();
    transport->prefer_primary(false);

    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(1, 8);
    CommitQueue commits;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    auto outbound = make_priority_urltest_outbound();
    OutboundGroup lower_priority;
    lower_priority.outbounds = {"backup"};
    lower_priority.weight = 20;
    OutboundGroup higher_priority;
    higher_priority.outbounds = {"primary"};
    higher_priority.weight = 5;
    outbound.outbound_groups =
        std::vector<OutboundGroup>{lower_priority, higher_priority};

    manager.register_urltest(outbound);
    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));
    CHECK(manager.get_selected("automatic") == "primary");
}

TEST_CASE("urltest worker exception abandons the batch and releases half-open requests") {
    auto transport = std::make_shared<RecoverableUrltestTransport>();
    transport->set_primary_available(false);
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    std::atomic<int> admitted_commits{0};

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits, &admitted_commits](
            const std::string& tag,
            std::uint64_t generation,
            std::map<std::string, URLTestResult> results,
            TraceId) {
            admitted_commits.fetch_add(1, std::memory_order_release);
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_priority_urltest_outbound());
    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));
    CHECK(manager.get_selected("automatic") == "backup");

    // timeout_ms=0 moves the failed primary into half-open on this round.
    // Its active-request lease must still be released when the transport
    // throws and aborts the complete two-worker batch.
    transport->set_primary_available(true);
    transport->set_throw_primary(true);
    manager.trigger_immediate_test("automatic");
    REQUIRE(wait_until([&manager]() {
        const auto state = manager.get_state("automatic");
        return state.has_value() && !state->probe_inflight;
    }));
    CHECK(admitted_commits.load(std::memory_order_acquire) == 1);

    transport->set_throw_primary(false);
    manager.trigger_immediate_test("automatic");
    auto recovered = commits.pop();
    // If the aborted half-open request leaked, primary would be rejected by
    // is_allowed() and this result would contain only backup.
    CHECK(recovered.results.count("primary") == 1);
    CHECK(recovered.results.count("backup") == 1);
    // The first half-open success releases the probe but does not yet satisfy
    // this test's success_threshold=2, so the selected backup is unchanged.
    CHECK_FALSE(manager.commit_probe_results(recovered.tag,
                                             recovered.generation,
                                             std::move(recovered.results)));
}

TEST_CASE("urltest commit mutation exception preserves state and releases ownership") {
    auto transport = std::make_shared<RecoverableUrltestTransport>();
    transport->set_primary_available(false);
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_priority_urltest_outbound());
    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));
    CHECK(manager.get_selected("automatic") == "backup");

    transport->set_primary_available(true);
    manager.trigger_immediate_test("automatic");
    auto failed_commit = commits.pop();
    CHECK(failed_commit.results.count("primary") == 1);
    manager.fail_next_commit_after_prepare_for_testing();
    CHECK_THROWS_AS(
        manager.commit_probe_results(failed_commit.tag,
                                     failed_commit.generation,
                                     std::move(failed_commit.results)),
        std::runtime_error);

    REQUIRE(manager.get_state("automatic").has_value());
    CHECK_FALSE(manager.get_state("automatic")->probe_inflight);
    CHECK(manager.get_selected("automatic") == "backup");

    // The failed candidate was never published, but its exact half-open lease
    // was released. The next round must include primary again and begin its
    // success threshold from the last committed state.
    manager.trigger_immediate_test("automatic");
    auto retry = commits.pop();
    CHECK(retry.results.count("primary") == 1);
    CHECK(retry.results.count("backup") == 1);
    CHECK_FALSE(manager.commit_probe_results(retry.tag,
                                             retry.generation,
                                             std::move(retry.results)));
    CHECK(manager.get_selected("automatic") == "backup");
}

TEST_CASE("urltest retries a selection transition rejected by the controller") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    std::atomic<int> transition_admissions{0};

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&transition_admissions](const UrltestSelectionChange&) {
            return transition_admissions.fetch_add(
                       1, std::memory_order_acq_rel) != 0;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_urltest_outbound());
    auto rejected = commits.pop();
    CHECK_FALSE(manager.commit_probe_results(rejected.tag,
                                             rejected.generation,
                                             std::move(rejected.results)));
    CHECK(manager.get_selected("automatic").empty());
    REQUIRE(manager.get_state("automatic").has_value());
    CHECK_FALSE(manager.get_state("automatic")->probe_inflight);

    manager.trigger_immediate_test("automatic");
    auto retry = commits.pop();
    CHECK(manager.commit_probe_results(retry.tag,
                                       retry.generation,
                                       std::move(retry.results)));
    CHECK(manager.get_selected("automatic") == "primary");
    CHECK(transition_admissions.load(std::memory_order_acquire) == 2);
}

TEST_CASE("urltest keeps the exact probe single-flight through selection resolution") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    UrltestManager* manager_ptr = nullptr;
    bool callback_observed_inflight = false;
    std::atomic<int> transition_count{0};

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&manager_ptr,
         &callback_observed_inflight,
         &transition_count](const UrltestSelectionChange& change) {
            REQUIRE(manager_ptr != nullptr);
            const auto state = manager_ptr->get_state(change.urltest_tag);
            REQUIRE(state.has_value());
            callback_observed_inflight = state->probe_inflight;
            transition_count.fetch_add(1, std::memory_order_release);

            // A synchronous controller may cause health/status callbacks to
            // request another probe. It must remain coalesced until this
            // exact transition has resolved.
            manager_ptr->trigger_immediate_test(change.urltest_tag);
            return true;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });
    manager_ptr = &manager;

    manager.register_urltest(make_urltest_outbound());
    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));
    CHECK(callback_observed_inflight);
    REQUIRE(manager.get_state("automatic").has_value());
    CHECK_FALSE(manager.get_state("automatic")->probe_inflight);
    CHECK(transition_count.load(std::memory_order_acquire) == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    CHECK(commits.size() == 0);
}

TEST_CASE("external health transition launches one trailing urltest after an inflight probe") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_priority_urltest_outbound());
    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));
    CHECK(manager.get_selected("automatic") == "primary");

    // Hold an already measured, stale-good generation at the controller
    // boundary. The interface transition happens after those measurements,
    // so this generation must not consume the external request.
    manager.trigger_immediate_test("automatic");
    auto stale_good = commits.pop();
    REQUIRE(manager.get_state("automatic")->probe_inflight);
    transport->set_primary_available(false);
    manager.trigger_external_health_test("automatic");
    manager.trigger_external_health_test("automatic");

    constexpr const char* retry_label =
        "urltest-external-health-retry:automatic";
    CHECK(scheduler.count_label(retry_label) == 1);
    CHECK_FALSE(manager.commit_probe_results(
        stale_good.tag,
        stale_good.generation,
        std::move(stale_good.results)));

    auto trailing = commits.pop();
    REQUIRE(trailing.results.count("primary") == 1);
    CHECK_FALSE(trailing.results.at("primary").success);
    CHECK(manager.commit_probe_results(trailing.tag,
                                       trailing.generation,
                                       std::move(trailing.results)));
    CHECK(manager.get_selected("automatic") == "backup");
    const auto final_state = manager.get_state("automatic");
    REQUIRE(final_state.has_value());
    CHECK(final_state->external_health_completed_serial ==
          final_state->external_health_request_serial);
    CHECK(scheduler.count_label(retry_label) == 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    CHECK(commits.size() == 0);
}

TEST_CASE("resolved cursor mismatch launches one durable convergence probe") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    UrltestManager* manager_ptr = nullptr;
    std::atomic<int> transition_count{0};

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&manager_ptr, &transition_count](
            const UrltestSelectionChange& change) {
            REQUIRE(manager_ptr != nullptr);
            const int transition = transition_count.fetch_add(
                1, std::memory_order_acq_rel);
            if (transition == 0) {
                // Simulate the daemon finding that the live firewall cursor
                // is empty rather than the retained backup cursor carried by
                // this event. The candidate was not applied, so the daemon
                // requests one trailing convergence round before admitting
                // the cursor resolution.
                REQUIRE(manager_ptr->synchronize_selected_if_generation(
                    change.urltest_tag,
                    change.probe_generation,
                    ""));
                manager_ptr->trigger_external_health_test(
                    change.urltest_tag);
            }
            return true;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });
    manager_ptr = &manager;

    manager.register_urltest(make_priority_urltest_outbound(), "backup");
    auto mismatched = commits.pop();
    CHECK(manager.commit_probe_results(mismatched.tag,
                                       mismatched.generation,
                                       std::move(mismatched.results)));

    auto convergence = commits.pop();
    CHECK(manager.commit_probe_results(convergence.tag,
                                       convergence.generation,
                                       std::move(convergence.results)));
    CHECK(manager.get_selected("automatic") == "primary");
    CHECK(transition_count.load(std::memory_order_acquire) == 2);

    constexpr const char* retry_label =
        "urltest-external-health-retry:automatic";
    const auto final_state = manager.get_state("automatic");
    REQUIRE(final_state.has_value());
    CHECK(final_state->external_health_completed_serial ==
          final_state->external_health_request_serial);
    CHECK(scheduler.count_label(retry_label) == 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    CHECK(commits.size() == 0);
}

TEST_CASE("selection admission busy queues one trailing probe without recursion") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    UrltestManager* manager_ptr = nullptr;
    int callback_depth = 0;
    int maximum_callback_depth = 0;
    int transition_count = 0;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&](const UrltestSelectionChange& change) {
            REQUIRE(manager_ptr != nullptr);
            ++callback_depth;
            maximum_callback_depth =
                std::max(maximum_callback_depth, callback_depth);
            ++transition_count;
            if (transition_count == 1) {
                // This is the daemon's admission-busy path. The request is
                // made from inside the selection callback while the exact
                // probe generation is still inflight.
                manager_ptr->trigger_external_health_test(
                    change.urltest_tag);
                --callback_depth;
                return false;
            }
            --callback_depth;
            return true;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });
    manager_ptr = &manager;

    manager.register_urltest(make_priority_urltest_outbound());
    auto initial = commits.pop();
    CHECK_FALSE(manager.commit_probe_results(
        initial.tag, initial.generation, std::move(initial.results)));
    CHECK(maximum_callback_depth == 1);
    CHECK(transition_count == 1);

    auto trailing = commits.pop();
    CHECK(manager.commit_probe_results(
        trailing.tag, trailing.generation, std::move(trailing.results)));
    CHECK(maximum_callback_depth == 1);
    CHECK(transition_count == 2);
    CHECK(manager.get_selected("automatic") == "primary");

    constexpr const char* retry_label =
        "urltest-external-health-retry:automatic";
    const auto state = manager.get_state("automatic");
    REQUIRE(state.has_value());
    CHECK(state->external_health_completed_serial ==
          state->external_health_request_serial);
    CHECK_FALSE(state->probe_inflight);
    CHECK(scheduler.count_label(retry_label) == 0);
    CHECK(commits.size() == 0);
}

TEST_CASE("external health retries a transient commit admission failure") {
    bool throw_on_first_failure = false;
    bool fail_first_retry_schedule = false;
    SUBCASE("false return") {
        throw_on_first_failure = false;
    }
    SUBCASE("exception") {
        throw_on_first_failure = true;
    }
    SUBCASE("retry timer admission exception") {
        fail_first_retry_schedule = true;
    }

    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    std::atomic<bool> reject_external{false};
    std::atomic<int> external_admissions{0};

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits,
         &reject_external,
         &external_admissions,
         throw_on_first_failure](
            const std::string& tag,
            std::uint64_t generation,
            std::map<std::string, URLTestResult> results,
            TraceId) {
            if (reject_external.load(std::memory_order_acquire)) {
                const int attempt = external_admissions.fetch_add(
                    1, std::memory_order_acq_rel);
                if (attempt == 0) {
                    if (throw_on_first_failure) {
                        throw std::runtime_error(
                            "scripted external commit admission failure");
                    }
                    return false;
                }
            }
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_urltest_outbound());
    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));

    reject_external.store(true, std::memory_order_release);
    if (fail_first_retry_schedule) {
        scheduler.fail_next_schedule();
    }
    manager.trigger_external_health_test("automatic");
    constexpr const char* retry_label =
        "urltest-external-health-retry:automatic";
    REQUIRE(wait_until([&manager,
                        &external_admissions,
                        &scheduler,
                        retry_label]() {
        const auto state = manager.get_state("automatic");
        return external_admissions.load(std::memory_order_acquire) == 1 &&
               state.has_value() && !state->probe_inflight &&
               scheduler.count_label(retry_label) == 1;
    }));

    REQUIRE(scheduler.count_label(retry_label) == 1);
    REQUIRE(scheduler.fire_label(retry_label));
    auto retry = commits.pop();
    CHECK_FALSE(manager.commit_probe_results(retry.tag,
                                             retry.generation,
                                             std::move(retry.results)));
    CHECK(external_admissions.load(std::memory_order_acquire) == 2);
    const auto final_state = manager.get_state("automatic");
    REQUIRE(final_state.has_value());
    CHECK(final_state->external_health_completed_serial ==
          final_state->external_health_request_serial);
    CHECK(final_state->external_health_failures == 0);
    CHECK(scheduler.count_label(retry_label) == 0);
}

TEST_CASE("external health retry budget is bounded under persistent rejection") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    std::atomic<bool> reject_external{false};
    std::atomic<int> external_admissions{0};

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits, &reject_external, &external_admissions](
            const std::string& tag,
            std::uint64_t generation,
            std::map<std::string, URLTestResult> results,
            TraceId) {
            if (reject_external.load(std::memory_order_acquire)) {
                external_admissions.fetch_add(
                    1, std::memory_order_acq_rel);
                return false;
            }
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_urltest_outbound());
    auto initial = commits.pop();
    CHECK(manager.commit_probe_results(initial.tag,
                                       initial.generation,
                                       std::move(initial.results)));

    reject_external.store(true, std::memory_order_release);
    manager.trigger_external_health_test("automatic");
    REQUIRE(wait_until([&manager, &external_admissions]() {
        const auto state = manager.get_state("automatic");
        return external_admissions.load(std::memory_order_acquire) == 1 &&
               state.has_value() && !state->probe_inflight;
    }));

    constexpr const char* retry_label =
        "urltest-external-health-retry:automatic";
    for (int expected_attempts = 2; expected_attempts <= 4;
         ++expected_attempts) {
        REQUIRE(scheduler.fire_label(retry_label));
        REQUIRE(wait_until([&manager,
                            &external_admissions,
                            expected_attempts]() {
            const auto state = manager.get_state("automatic");
            return external_admissions.load(std::memory_order_acquire) ==
                       expected_attempts &&
                   state.has_value() && !state->probe_inflight;
        }));
    }
    // The next timer edge retires the retry job without starting a fifth
    // probe. A later genuine health transition receives a new bounded budget.
    REQUIRE(scheduler.fire_label(retry_label));
    CHECK(scheduler.count_label(retry_label) == 0);
    CHECK(external_admissions.load(std::memory_order_acquire) == 4);
    CHECK_FALSE(scheduler.fire_label(retry_label));
}

TEST_CASE("urltest retries a selection transition when controller admission throws") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    std::atomic<int> transition_admissions{0};

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&transition_admissions](const UrltestSelectionChange&) {
            if (transition_admissions.fetch_add(
                    1, std::memory_order_acq_rel) == 0) {
                throw std::runtime_error(
                    "scripted selection transition admission failure");
            }
            return true;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_urltest_outbound());
    auto rejected = commits.pop();
    CHECK_FALSE(manager.commit_probe_results(rejected.tag,
                                             rejected.generation,
                                             std::move(rejected.results)));
    CHECK(manager.get_selected("automatic").empty());
    REQUIRE(manager.get_state("automatic").has_value());
    CHECK_FALSE(manager.get_state("automatic")->probe_inflight);

    manager.trigger_immediate_test("automatic");
    auto retry = commits.pop();
    CHECK(manager.commit_probe_results(retry.tag,
                                       retry.generation,
                                       std::move(retry.results)));
    CHECK(manager.get_selected("automatic") == "primary");
    CHECK(transition_admissions.load(std::memory_order_acquire) == 2);
}

TEST_CASE("urltest retries after commit admission returns false") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    std::atomic<int> admission_calls{0};

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits, &admission_calls](
            const std::string& tag,
            std::uint64_t generation,
            std::map<std::string, URLTestResult> results,
            TraceId) {
            const int call =
                admission_calls.fetch_add(1, std::memory_order_acq_rel);
            if (call == 0) {
                return false;
            }
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_urltest_outbound());
    REQUIRE(wait_until([&manager, &admission_calls]() {
        const auto state = manager.get_state("automatic");
        return admission_calls.load(std::memory_order_acquire) >= 1 &&
               state.has_value() && !state->probe_inflight;
    }));

    manager.trigger_immediate_test("automatic");
    auto retry = commits.pop();
    CHECK(manager.commit_probe_results(retry.tag,
                                       retry.generation,
                                       std::move(retry.results)));
}

TEST_CASE("urltest retries after commit admission throws") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(2, 8);
    CommitQueue commits;
    std::atomic<int> admission_calls{0};

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits, &admission_calls](
            const std::string& tag,
            std::uint64_t generation,
            std::map<std::string, URLTestResult> results,
            TraceId) {
            const int call =
                admission_calls.fetch_add(1, std::memory_order_acq_rel);
            if (call == 0) {
                throw std::runtime_error("scripted admission failure");
            }
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_urltest_outbound());
    REQUIRE(wait_until([&manager, &admission_calls]() {
        const auto state = manager.get_state("automatic");
        return admission_calls.load(std::memory_order_acquire) >= 1 &&
               state.has_value() && !state->probe_inflight;
    }));

    manager.trigger_immediate_test("automatic");
    auto retry = commits.pop();
    CHECK(manager.commit_probe_results(retry.tag,
                                       retry.generation,
                                       std::move(retry.results)));
}

TEST_CASE("partial urltest worker admission invalidates the exact generation") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(1, 1);
    BlockingTaskGate blocker;
    std::atomic<int> admitted_commits{0};

    REQUIRE(executor.try_post("block-urltest-worker", [&blocker]() {
        blocker.run();
    }));
    REQUIRE(blocker.wait_until_started());

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&admitted_commits](const std::string&,
                            std::uint64_t,
                            std::map<std::string, URLTestResult>,
                            TraceId) {
            admitted_commits.fetch_add(1, std::memory_order_release);
            return true;
        });

    // The first of two workers occupies the only queue slot; admission of the
    // second fails deterministically while the executor worker is blocked.
    manager.register_urltest(make_urltest_outbound());
    REQUIRE(manager.get_state("automatic").has_value());
    CHECK_FALSE(manager.get_state("automatic")->probe_inflight);

    blocker.release();
    executor.submit("drain-partial-urltest", []() {}).get();
    CHECK(admitted_commits.load(std::memory_order_acquire) == 0);
}

TEST_CASE("urltest executor shutdown releases probe admission") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(1, 8);
    executor.shutdown();

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [](const std::string&,
           std::uint64_t,
           std::map<std::string, URLTestResult>,
           TraceId) { return true; });

    manager.register_urltest(make_urltest_outbound());
    REQUIRE(manager.get_state("automatic").has_value());
    CHECK_FALSE(manager.get_state("automatic")->probe_inflight);
}

TEST_CASE("stale worker completion cannot abandon a newer urltest generation") {
    auto transport = std::make_shared<BlockingOnceUrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(1, 8);
    CommitQueue commits;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [](const UrltestSelectionChange&) { return true; },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
            return true;
        });

    manager.register_urltest(make_single_candidate_urltest_outbound());
    REQUIRE(transport->wait_for_first());
    const auto stale_generation =
        manager.get_state("automatic")->generation;

    manager.clear();
    manager.register_urltest(make_single_candidate_urltest_outbound());
    const auto current_generation =
        manager.get_state("automatic")->generation;
    REQUIRE(current_generation != stale_generation);

    transport->release_first();
    auto current = commits.pop();
    CHECK(current.generation == current_generation);
    REQUIRE(manager.get_state("automatic").has_value());
    CHECK(manager.get_state("automatic")->probe_inflight);
    CHECK(manager.commit_probe_results(current.tag,
                                       current.generation,
                                       std::move(current.results)));
}

TEST_CASE("retired-flow cleanup defaults to failure-only") {
    using Reason = UrltestSelectionChangeReason;
    const std::optional<ConntrackOnSwitch> unset;

    // The gap this default closes: a degraded-but-UP child keeps its CONNMARK
    // on established flows, and preserving them routes traffic into the dead
    // child's table until conntrack expiry.
    CHECK(should_cleanup_retired_urltest_flows(
        unset, Reason::previous_unhealthy, false));

    // A healthy rebalance retires a working child; its flows finish there.
    CHECK_FALSE(should_cleanup_retired_urltest_flows(
        unset, Reason::healthy_rebalance, false));
    // The initial selection retires nobody.
    CHECK_FALSE(should_cleanup_retired_urltest_flows(
        unset, Reason::initial, false));
    // A nested selector's group mark may be shared; the default must not do
    // what an explicit config is refused at validation.
    CHECK_FALSE(should_cleanup_retired_urltest_flows(
        unset, Reason::previous_unhealthy, true));
}

TEST_CASE("an explicit conntrack mode is taken at its word") {
    using Reason = UrltestSelectionChangeReason;

    // Explicit preserve is the operator's escape hatch: it holds even through
    // an unhealthy switch, where the unset default would clean.
    CHECK_FALSE(should_cleanup_retired_urltest_flows(
        ConntrackOnSwitch::PRESERVE, Reason::previous_unhealthy, false));

    CHECK(should_cleanup_retired_urltest_flows(
        ConntrackOnSwitch::DELETE, Reason::previous_unhealthy, false));
    CHECK(should_cleanup_retired_urltest_flows(
        ConntrackOnSwitch::DELETE, Reason::healthy_rebalance, false));
    CHECK_FALSE(should_cleanup_retired_urltest_flows(
        ConntrackOnSwitch::DELETE, Reason::initial, false));

    CHECK(should_cleanup_retired_urltest_flows(
        ConntrackOnSwitch::DELETE_ON_FAILURE,
        Reason::previous_unhealthy,
        false));
    CHECK_FALSE(should_cleanup_retired_urltest_flows(
        ConntrackOnSwitch::DELETE_ON_FAILURE,
        Reason::healthy_rebalance,
        false));
}

} // namespace keen_pbr3
