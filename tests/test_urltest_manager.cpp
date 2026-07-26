#include <doctest/doctest.h>

#include "../src/daemon/scheduler.hpp"
#include "../src/health/url_tester.hpp"
#include "../src/routing/urltest_manager.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

class FakeRepeatingScheduler final : public RepeatingTaskScheduler {
public:
    int schedule_repeating(std::chrono::milliseconds,
                           TaskCallback callback,
                           std::string) override {
        callback_ = std::move(callback);
        return task_id_;
    }

    void cancel(int task_id) override {
        if (task_id == task_id_) {
            cancelled_ = true;
        }
    }

    bool cancelled() const { return cancelled_; }

private:
    const int task_id_{17};
    TaskCallback callback_;
    bool cancelled_{false};
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

private:
    std::mutex mutex_;
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

OutboundMarkMap make_marks() {
    return {
        {"primary", UrltestTransport::kPrimaryMark},
        {"backup", UrltestTransport::kBackupMark},
    };
}

} // namespace

TEST_CASE("initial urltest probe commits through the controller callback") {
    auto transport = std::make_shared<UrltestTransport>();
    URLTester tester(transport);
    const auto marks = make_marks();
    FakeRepeatingScheduler scheduler;
    BlockingExecutor executor(1, 8);
    CommitQueue commits;
    std::vector<std::pair<std::string, std::string>> changes;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&changes](const std::string& tag, const std::string& selected) {
            changes.emplace_back(tag, selected);
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
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
    CHECK(changes.front() == std::make_pair(std::string("automatic"),
                                            std::string("primary")));

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
    CHECK(changes.back() == std::make_pair(std::string("automatic"),
                                           std::string("backup")));
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
        [](const std::string&, const std::string&) {},
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
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
        [&change_count](const std::string&, const std::string&) {
            ++change_count;
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
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
    std::vector<std::string> changes;

    UrltestManager manager(
        tester,
        marks,
        scheduler,
        executor,
        [&changes](const std::string&, const std::string& selected) {
            changes.push_back(selected);
        },
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
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

    CHECK(changes == std::vector<std::string>{"primary", "backup", "primary"});
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
        [](const std::string&, const std::string&) {},
        [&commits](const std::string& tag,
                   std::uint64_t generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId) {
            commits.push(tag, generation, std::move(results));
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

} // namespace keen_pbr3
