#include <doctest/doctest.h>

#include "runtime/periodic_task_metrics.hpp"

#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

struct FakeClocks {
    std::chrono::steady_clock::time_point steady{};
    std::int64_t wall_ms{0};

    PeriodicTaskMetricsClocks callbacks() {
        return {
            [this]() { return steady; },
            [this]() { return wall_ms; },
        };
    }

    void advance(std::chrono::milliseconds duration) {
        steady += duration;
        wall_ms += duration.count();
    }
};

const PeriodicTaskMetricsSnapshot& only_snapshot(
    const PeriodicTaskMetricsRegistry& registry,
    std::vector<PeriodicTaskMetricsSnapshot>& storage) {
    storage = registry.snapshot();
    REQUIRE(storage.size() == 1);
    return storage.front();
}

void check_run_invariant(const PeriodicTaskMetricsSnapshot& snapshot) {
    CHECK(snapshot.runs == snapshot.success + snapshot.noop +
                               snapshot.failure + snapshot.abandoned +
                               snapshot.in_flight);
}

} // namespace

TEST_CASE("periodic task metrics require bounded pre-registered stable labels") {
    CHECK_THROWS_AS(
        PeriodicTaskMetricsRegistry(
            {"one", "two"}, {}, PeriodicTaskMetricsOptions{1, 10}),
        std::length_error);
    CHECK_THROWS_AS(PeriodicTaskMetricsRegistry({"duplicate", "duplicate"}),
                    std::invalid_argument);
    CHECK_THROWS_AS(PeriodicTaskMetricsRegistry({"dynamic/value"}),
                    std::invalid_argument);

    PeriodicTaskMetricsRegistry registry({"z-task", "a-task"});
    CHECK(registry.size() == 2);
    CHECK(registry.capacity() == 32);
    const auto snapshot = registry.snapshot();
    REQUIRE(snapshot.size() == 2);
    CHECK(snapshot[0].label == "a-task");
    CHECK(snapshot[1].label == "z-task");
    CHECK_THROWS_AS(registry.begin("not-registered"), std::out_of_range);
}

TEST_CASE("periodic task metrics track outcomes clocks durations and invariant") {
    FakeClocks clocks;
    clocks.wall_ms = 1'700'000'000'000LL;
    PeriodicTaskMetricsRegistry registry({"resolver-refresh"},
                                         clocks.callbacks());

    auto success = registry.begin("resolver-refresh");
    std::vector<PeriodicTaskMetricsSnapshot> storage;
    auto snapshot = only_snapshot(registry, storage);
    CHECK(snapshot.runs == 1);
    CHECK(snapshot.in_flight == 1);
    CHECK(snapshot.last_started_at_unix_ms == clocks.wall_ms);
    check_run_invariant(snapshot);

    clocks.advance(std::chrono::milliseconds(17));
    CHECK(success.success());

    auto noop = registry.begin("resolver-refresh");
    clocks.advance(std::chrono::milliseconds(3));
    CHECK(noop.noop());

    auto failure = registry.begin("resolver-refresh");
    clocks.advance(std::chrono::milliseconds(29));
    CHECK(failure.failure("dnsmasq did not reload"));
    registry.record_skipped("resolver-refresh", "cooldown active");

    snapshot = only_snapshot(registry, storage);
    CHECK(snapshot.runs == 3);
    CHECK(snapshot.success == 1);
    CHECK(snapshot.noop == 1);
    CHECK(snapshot.failure == 1);
    CHECK(snapshot.skipped == 1);
    CHECK(snapshot.abandoned == 0);
    CHECK(snapshot.in_flight == 0);
    CHECK(snapshot.total_duration_ms == 49);
    CHECK(snapshot.max_duration_ms == 29);
    CHECK(snapshot.last_duration_ms == 29);
    CHECK(snapshot.last_finished_at_unix_ms == 1'700'000'000'049LL);
    CHECK(snapshot.last_event_at_unix_ms == 1'700'000'000'049LL);
    CHECK(snapshot.last_outcome == PeriodicTaskOutcome::Skipped);
    CHECK(snapshot.last_error == "cooldown active");
    check_run_invariant(snapshot);
}

TEST_CASE("periodic task token move and destruction finalize exactly once") {
    FakeClocks clocks;
    PeriodicTaskMetricsRegistry registry({"route-repair"}, clocks.callbacks());

    {
        auto original = registry.begin("route-repair");
        auto moved = std::move(original);
        CHECK_FALSE(original.active());
        CHECK(moved.active());
        clocks.advance(std::chrono::milliseconds(8));
    }

    auto completed = registry.begin("route-repair");
    clocks.advance(std::chrono::milliseconds(5));
    CHECK(completed.success());
    CHECK_FALSE(completed.success());

    std::vector<PeriodicTaskMetricsSnapshot> storage;
    const auto& snapshot = only_snapshot(registry, storage);
    CHECK(snapshot.runs == 2);
    CHECK(snapshot.abandoned == 1);
    CHECK(snapshot.success == 1);
    CHECK(snapshot.in_flight == 0);
    check_run_invariant(snapshot);
}

TEST_CASE("periodic task token move assignment abandons its previous run") {
    FakeClocks clocks;
    PeriodicTaskMetricsRegistry registry({"route-repair"}, clocks.callbacks());

    auto first = registry.begin("route-repair");
    auto second = registry.begin("route-repair");
    clocks.advance(std::chrono::milliseconds(4));
    second = std::move(first);
    CHECK(second.success());

    std::vector<PeriodicTaskMetricsSnapshot> storage;
    const auto& snapshot = only_snapshot(registry, storage);
    CHECK(snapshot.runs == 2);
    CHECK(snapshot.abandoned == 1);
    CHECK(snapshot.success == 1);
    CHECK(snapshot.in_flight == 0);
    check_run_invariant(snapshot);
}

TEST_CASE("periodic task skipped token is separate from runs") {
    FakeClocks clocks;
    PeriodicTaskMetricsRegistry registry({"resolver-refresh"},
                                         clocks.callbacks());
    auto token = registry.begin("resolver-refresh");
    clocks.advance(std::chrono::milliseconds(2));
    CHECK(token.skipped("stale generation"));

    std::vector<PeriodicTaskMetricsSnapshot> storage;
    const auto& snapshot = only_snapshot(registry, storage);
    CHECK(snapshot.runs == 0);
    CHECK(snapshot.skipped == 1);
    CHECK(snapshot.in_flight == 0);
    CHECK(snapshot.total_duration_ms == 0);
    CHECK(snapshot.max_duration_ms == 0);
    CHECK_FALSE(snapshot.last_duration_ms.has_value());
    check_run_invariant(snapshot);
}

TEST_CASE("periodic task success clears a previous transient error") {
    FakeClocks clocks;
    PeriodicTaskMetricsRegistry registry({"resolver-refresh"},
                                         clocks.callbacks());

    auto failed = registry.begin("resolver-refresh");
    clocks.advance(std::chrono::milliseconds(7));
    REQUIRE(failed.failure("temporary resolver failure"));

    auto recovered = registry.begin("resolver-refresh");
    clocks.advance(std::chrono::milliseconds(5));
    REQUIRE(recovered.success());

    std::vector<PeriodicTaskMetricsSnapshot> storage;
    const auto& snapshot = only_snapshot(registry, storage);
    CHECK(snapshot.last_outcome == PeriodicTaskOutcome::Success);
    CHECK(snapshot.last_error.empty());
    CHECK(snapshot.total_duration_ms == 12);
    CHECK(snapshot.last_duration_ms == 5);
    check_run_invariant(snapshot);
}

TEST_CASE("periodic task errors are single-line valid UTF-8 and bounded") {
    FakeClocks clocks;
    PeriodicTaskMetricsRegistry registry({"resolver-refresh"},
                                         clocks.callbacks());
    auto token = registry.begin("resolver-refresh");
    std::string error = "  first\n\tsecond\x01 ";
    error.push_back(static_cast<char>(0xff));
    error += " ";
    error += std::string(300, 'x');
    CHECK(token.failure(error));

    std::vector<PeriodicTaskMetricsSnapshot> storage;
    const auto& snapshot = only_snapshot(registry, storage);
    CHECK(snapshot.last_error.size() <= 256);
    CHECK(snapshot.last_error.find('\n') == std::string::npos);
    CHECK(snapshot.last_error.find('\t') == std::string::npos);
    CHECK(snapshot.last_error.find("first second ?") == 0);
}

TEST_CASE("periodic task counters saturate without breaking run invariant") {
    FakeClocks clocks;
    PeriodicTaskMetricsRegistry registry(
        {"route-repair"},
        clocks.callbacks(),
        PeriodicTaskMetricsOptions{/*capacity=*/1, /*counter_ceiling=*/2});

    for (int i = 0; i < 4; ++i) {
        auto token = registry.begin("route-repair");
        CHECK(token.success());
        registry.record_skipped("route-repair");
    }

    std::vector<PeriodicTaskMetricsSnapshot> storage;
    const auto& snapshot = only_snapshot(registry, storage);
    CHECK(snapshot.runs == 2);
    CHECK(snapshot.success == 2);
    CHECK(snapshot.skipped == 2);
    CHECK(snapshot.in_flight == 0);
    check_run_invariant(snapshot);
}

TEST_CASE("periodic task elapsed duration never underflows") {
    FakeClocks clocks;
    clocks.steady = std::chrono::steady_clock::time_point(
        std::chrono::milliseconds(100));
    PeriodicTaskMetricsRegistry registry({"clock-step"}, clocks.callbacks());
    auto token = registry.begin("clock-step");
    clocks.steady -= std::chrono::milliseconds(50);
    clocks.wall_ms -= 50;
    CHECK(token.success());

    std::vector<PeriodicTaskMetricsSnapshot> storage;
    const auto& snapshot = only_snapshot(registry, storage);
    CHECK(snapshot.last_duration_ms == 0);
    CHECK(snapshot.total_duration_ms == 0);
}
