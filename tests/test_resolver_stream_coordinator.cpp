#include "../src/daemon/resolver_stream_coordinator.hpp"
#include "../src/util/blocking_executor.hpp"

#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

bool wait_until(const std::function<bool()>& predicate,
                std::chrono::milliseconds timeout = 1s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(2ms);
    }
    return predicate();
}

struct CoordinatorHarness {
    BlockingExecutor executor{1, 8};
    std::mutex mutex;
    std::vector<std::function<void()>> control_tasks;
    std::vector<ResolverStreamResult> results;
    ResolverStreamCoordinator coordinator{
        executor,
        [this](std::function<void()> task) {
            std::lock_guard<std::mutex> lock(mutex);
            control_tasks.push_back(std::move(task));
            return true;
        },
        [this](const ResolverStreamOperation&,
               const ResolverStreamResult& result) {
            std::lock_guard<std::mutex> lock(mutex);
            results.push_back(result);
        }};

    std::size_t queued() {
        std::lock_guard<std::mutex> lock(mutex);
        return control_tasks.size();
    }

    void run_one() {
        std::function<void()> task;
        {
            std::lock_guard<std::mutex> lock(mutex);
            REQUIRE_FALSE(control_tasks.empty());
            task = std::move(control_tasks.front());
            control_tasks.erase(control_tasks.begin());
        }
        task();
    }
};

ResolverStreamOperation operation(std::string attempt_id,
                                  std::uint64_t epoch,
                                  std::function<int()> hook = [] {
                                      return 0;
                                  }) {
    ResolverStreamOperation result;
    result.runtime_generation = 7;
    result.retry_attempt = 1;
    result.stream_epoch = epoch;
    result.attempt_id = std::move(attempt_id);
    result.timeout = 250ms;
    result.invoke_hook = std::move(hook);
    return result;
}

} // namespace

TEST_CASE("resolver stream coordinator accepts only the exact attempt and epoch") {
    CoordinatorHarness harness;
    const std::string token = "0123456789abcdef0123456789abcdef";

    CHECK(harness.coordinator.request(operation(token, 41)) ==
          ResolverStreamCoordinator::RequestResult::started);
    harness.coordinator.notify_stream_completed(token, 40);
    harness.coordinator.notify_stream_completed(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 41);
    std::this_thread::sleep_for(20ms);
    CHECK(harness.queued() == 0);

    harness.coordinator.notify_stream_completed(token, 41);
    REQUIRE(wait_until([&] { return harness.queued() == 1; }));
    harness.run_one();
    REQUIRE(harness.results.size() == 1);
    CHECK(harness.results.front().completed);
    CHECK(harness.coordinator.wait_for_idle_for(100ms));
}

TEST_CASE("late completion from an old token cannot satisfy a reused epoch") {
    CoordinatorHarness harness;
    const std::string first = "11111111111111111111111111111111";
    const std::string second = "22222222222222222222222222222222";

    REQUIRE(harness.coordinator.request(operation(first, 9)) ==
            ResolverStreamCoordinator::RequestResult::started);
    harness.coordinator.notify_stream_completed(first, 9);
    REQUIRE(wait_until([&] { return harness.queued() == 1; }));
    harness.run_one();
    REQUIRE(harness.coordinator.wait_for_idle_for(100ms));

    REQUIRE(harness.coordinator.request(operation(second, 9)) ==
            ResolverStreamCoordinator::RequestResult::started);
    harness.coordinator.notify_stream_completed(first, 9);
    std::this_thread::sleep_for(20ms);
    CHECK(harness.queued() == 0);
    harness.coordinator.notify_stream_completed(second, 9);
    REQUIRE(wait_until([&] { return harness.queued() == 1; }));
    harness.run_one();
    REQUIRE(harness.results.size() == 2);
    CHECK(harness.results.back().completed);
}

TEST_CASE("resolver stream coordinator supports a synchronous control handoff") {
    BlockingExecutor executor{1, 8};
    std::atomic<int> commits{0};
    ResolverStreamCoordinator* coordinator_ptr = nullptr;
    ResolverStreamCoordinator coordinator{
        executor,
        [](std::function<void()> task) {
            task();
            return true;
        },
        [&commits](const ResolverStreamOperation&,
                   const ResolverStreamResult& result) {
            CHECK(result.completed);
            ++commits;
        }};
    coordinator_ptr = &coordinator;

    const std::string token = "33333333333333333333333333333333";
    auto request = operation(token, 12, [coordinator_ptr, token] {
        coordinator_ptr->notify_stream_completed(token, 12);
        return 0;
    });
    CHECK(coordinator.request(std::move(request)) ==
          ResolverStreamCoordinator::RequestResult::started);
    REQUIRE(wait_until([&] { return commits.load() == 1; }));
    CHECK(coordinator.wait_for_idle_for(100ms));
}

TEST_CASE("resolver stream coordinator releases a rejected control handoff once") {
    BlockingExecutor executor{1, 8};
    std::atomic<int> releases{0};
    ResolverStreamCoordinator* coordinator_ptr = nullptr;
    ResolverStreamCoordinator coordinator{
        executor,
        [](std::function<void()>) { return false; },
        [](const ResolverStreamOperation&, const ResolverStreamResult&) {
            FAIL("a rejected control task must not commit");
        }};
    coordinator_ptr = &coordinator;

    const std::string token = "44444444444444444444444444444444";
    auto request = operation(token, 13, [coordinator_ptr, token] {
        coordinator_ptr->notify_stream_completed(token, 13);
        return 0;
    });
    request.lifetime = std::shared_ptr<void>(
        new int{1},
        [&releases](void* value) {
            delete static_cast<int*>(value);
            ++releases;
        });
    CHECK(coordinator.request(std::move(request)) ==
          ResolverStreamCoordinator::RequestResult::started);
    REQUIRE(coordinator.wait_for_idle_for(1s));
    CHECK(releases.load() == 1);
}

TEST_CASE("resolver stream coordinator stop wakes an exact stream wait") {
    CoordinatorHarness harness;
    const std::string token = "55555555555555555555555555555555";
    REQUIRE(harness.coordinator.request(operation(token, 14)) ==
            ResolverStreamCoordinator::RequestResult::started);
    REQUIRE(wait_until([&] { return harness.coordinator.in_flight(); }));

    harness.coordinator.request_stop();

    CHECK(harness.coordinator.wait_for_idle_for(1s));
    CHECK(harness.queued() == 0);
    CHECK(harness.results.empty());
    CHECK(harness.coordinator.request(operation(token, 15)) ==
          ResolverStreamCoordinator::RequestResult::rejected);
}

} // namespace keen_pbr3
