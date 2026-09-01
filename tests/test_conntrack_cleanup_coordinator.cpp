#include <doctest/doctest.h>

#include "../src/daemon/conntrack_cleanup_coordinator.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

constexpr std::uint32_t kOwnedMask = 0x00FF0000U;
constexpr std::uint32_t kMarkOne = 0x00010000U;
constexpr std::uint32_t kMarkTwo = 0x00020000U;
constexpr std::uint32_t kMarkThree = 0x00030000U;
constexpr std::uint32_t kForeignMark = 0x00000042U;

OwnedConntrackCleanupSnapshot snapshot(
    std::uint64_t runtime_generation = 1U,
    std::uint32_t owned_mask = kOwnedMask,
    std::set<std::uint32_t> marks = {kMarkOne, kMarkTwo},
    std::set<std::uint32_t> priority_marks = {kMarkOne},
    bool ipv6_enabled = false) {
    OwnedConntrackCleanupSnapshot result;
    result.runtime_generation = runtime_generation;
    result.owned_mask = owned_mask;
    result.marks = std::move(marks);
    result.priority_marks = std::move(priority_marks);
    result.ipv6_enabled = ipv6_enabled;
    return result;
}

OwnedConntrackCleanupRetry retry(
    std::vector<std::uint32_t> ordered_marks,
    std::size_t no_progress_attempt = 0U,
    std::uint64_t runtime_generation = 1U) {
    auto retry_snapshot = snapshot(
        runtime_generation,
        kOwnedMask,
        std::set<std::uint32_t>{
            ordered_marks.begin(), ordered_marks.end()},
        {kMarkOne},
        false);
    return OwnedConntrackCleanupRetry{
        std::move(retry_snapshot),
        std::move(ordered_marks),
        no_progress_attempt};
}

struct CoordinatorHarness final {
    struct ScheduledTask final {
        std::chrono::milliseconds delay;
        std::string name;
        std::function<void()> callback;
    };

    int next_task_id{1};
    bool throw_on_schedule{false};
    bool return_negative_task_id{false};
    bool throw_on_cancel{false};
    std::vector<std::chrono::milliseconds> delays;
    std::vector<std::string> names;
    std::map<int, ScheduledTask> tasks;
    std::vector<int> cancelled_task_ids;
    std::vector<OwnedConntrackCleanupRetry> dispatched;
    std::size_t exhausted_count{0U};

    ConntrackCleanupCoordinatorCallbacks callbacks() {
        ConntrackCleanupCoordinatorCallbacks result;
        result.schedule_oneshot =
            [this](std::chrono::milliseconds delay,
                   std::function<void()> callback,
                   std::string name) {
                delays.push_back(delay);
                names.push_back(name);
                if (throw_on_schedule) {
                    throw std::runtime_error{"scheduler unavailable"};
                }
                if (return_negative_task_id) {
                    return -1;
                }
                const int task_id = next_task_id++;
                tasks.emplace(
                    task_id,
                    ScheduledTask{
                        delay, std::move(name), std::move(callback)});
                return task_id;
            };
        result.cancel_scheduled = [this](int task_id) {
            cancelled_task_ids.push_back(task_id);
            if (throw_on_cancel) {
                throw std::runtime_error{"cancel unavailable"};
            }
            tasks.erase(task_id);
        };
        result.dispatch_retry =
            [this](OwnedConntrackCleanupRetry pending_retry) {
                dispatched.push_back(std::move(pending_retry));
            };
        result.retry_budget_exhausted = [this]() { ++exhausted_count; };
        return result;
    }

    bool fire(int task_id) {
        const auto iterator = tasks.find(task_id);
        if (iterator == tasks.end()) {
            return false;
        }
        auto callback = std::move(iterator->second.callback);
        tasks.erase(iterator);
        callback();
        return true;
    }
};

} // namespace

TEST_CASE("ConntrackCleanupCoordinator ignores invalid or empty work") {
    CoordinatorHarness harness;
    ConntrackCleanupCoordinator coordinator{harness.callbacks()};

    coordinator.schedule(snapshot(0U), {kMarkOne});
    coordinator.schedule(snapshot(1U, 0U), {kMarkOne});
    coordinator.schedule(snapshot(1U, kOwnedMask, {}), {kMarkOne});
    coordinator.schedule(snapshot(), {});
    coordinator.schedule(snapshot(), {kForeignMark});

    CHECK_FALSE(coordinator.has_pending());
    CHECK_FALSE(coordinator.timer_pending());
    CHECK(harness.delays.empty());
    CHECK(harness.dispatched.empty());
}

TEST_CASE(
    "ConntrackCleanupCoordinator filters, deduplicates, and preserves mark order") {
    CoordinatorHarness harness;
    ConntrackCleanupCoordinator coordinator{harness.callbacks()};
    auto source = snapshot(
        11U,
        kOwnedMask,
        {kMarkOne, kMarkTwo},
        {kMarkTwo, kForeignMark},
        true);

    coordinator.schedule(
        source,
        {kMarkTwo, kMarkOne, kMarkTwo, kForeignMark});

    REQUIRE(harness.tasks.size() == 1U);
    const int task_id = harness.tasks.begin()->first;
    CHECK(harness.fire(task_id));
    REQUIRE(harness.dispatched.size() == 1U);
    const auto& dispatched = harness.dispatched.front();
    CHECK(dispatched.ordered_marks ==
          std::vector<std::uint32_t>{kMarkTwo, kMarkOne});
    CHECK(dispatched.snapshot.marks ==
          std::set<std::uint32_t>{kMarkOne, kMarkTwo});
    CHECK(dispatched.snapshot.priority_marks ==
          std::set<std::uint32_t>{kMarkTwo});
    CHECK(dispatched.snapshot.ipv6_enabled);
}

TEST_CASE(
    "ConntrackCleanupCoordinator coalesces one identity behind one timer") {
    CoordinatorHarness harness;
    ConntrackCleanupCoordinator coordinator{harness.callbacks()};

    coordinator.schedule(
        snapshot(7U, kOwnedMask, {kMarkOne}, {kMarkOne}, false),
        {kMarkOne},
        3U);
    REQUIRE(harness.tasks.size() == 1U);
    const int task_id = harness.tasks.begin()->first;

    coordinator.schedule(
        snapshot(
            7U,
            kOwnedMask,
            {kMarkOne, kMarkTwo},
            {kMarkTwo},
            true),
        {kMarkOne, kMarkTwo},
        1U);

    CHECK(harness.tasks.size() == 1U);
    CHECK(harness.delays ==
          std::vector<std::chrono::milliseconds>{std::chrono::seconds{16}});
    CHECK(harness.cancelled_task_ids.empty());
    const auto pending = coordinator.pending_remainder(7U);
    REQUIRE(pending.has_value());
    CHECK(pending->marks ==
          std::set<std::uint32_t>{kMarkOne, kMarkTwo});
    CHECK(pending->priority_marks ==
          std::set<std::uint32_t>{kMarkOne, kMarkTwo});
    CHECK(pending->ipv6_enabled);

    CHECK(harness.fire(task_id));
    REQUIRE(harness.dispatched.size() == 1U);
    CHECK(harness.dispatched.front().ordered_marks ==
          std::vector<std::uint32_t>{kMarkOne, kMarkTwo});
    CHECK(harness.dispatched.front().no_progress_attempt == 1U);
}

TEST_CASE(
    "ConntrackCleanupCoordinator replaces a different identity and cancels its timer") {
    CoordinatorHarness harness;
    ConntrackCleanupCoordinator coordinator{harness.callbacks()};

    coordinator.schedule(snapshot(3U), {kMarkOne});
    REQUIRE(harness.tasks.size() == 1U);
    const int old_task_id = harness.tasks.begin()->first;

    coordinator.schedule(snapshot(4U), {kMarkTwo});

    REQUIRE(harness.cancelled_task_ids.size() == 1U);
    CHECK(harness.cancelled_task_ids.front() == old_task_id);
    REQUIRE(harness.tasks.size() == 1U);
    const int replacement_task_id = harness.tasks.begin()->first;
    CHECK(replacement_task_id != old_task_id);
    CHECK_FALSE(harness.fire(old_task_id));
    CHECK(harness.fire(replacement_task_id));
    REQUIRE(harness.dispatched.size() == 1U);
    CHECK(harness.dispatched.front().snapshot.runtime_generation == 4U);
    CHECK(harness.dispatched.front().ordered_marks ==
          std::vector<std::uint32_t>{kMarkTwo});
}

TEST_CASE(
    "ConntrackCleanupCoordinator applies bounded retry delays and exhausts attempt five") {
    const std::vector<std::chrono::milliseconds> expected_delays{
        std::chrono::seconds{2},
        std::chrono::seconds{4},
        std::chrono::seconds{8},
        std::chrono::seconds{16},
        std::chrono::seconds{30},
    };

    for (std::size_t attempt = 0U; attempt < expected_delays.size();
         ++attempt) {
        CoordinatorHarness harness;
        ConntrackCleanupCoordinator coordinator{harness.callbacks()};
        coordinator.schedule(snapshot(), {kMarkOne}, attempt);
        CHECK(harness.delays ==
              std::vector<std::chrono::milliseconds>{
                  expected_delays[attempt]});
        CHECK(coordinator.has_pending());
        CHECK(coordinator.timer_pending());
        CHECK(harness.exhausted_count == 0U);
    }

    CoordinatorHarness exhausted_harness;
    ConntrackCleanupCoordinator exhausted{exhausted_harness.callbacks()};
    exhausted.schedule(snapshot(), {kMarkOne}, 5U);
    CHECK(exhausted_harness.delays.empty());
    CHECK(exhausted_harness.exhausted_count == 1U);
    CHECK_FALSE(exhausted.has_pending());
    CHECK_FALSE(exhausted.timer_pending());
}

TEST_CASE("ConntrackCleanupCoordinator dispatches a timer payload exactly once") {
    CoordinatorHarness harness;
    ConntrackCleanupCoordinator coordinator{harness.callbacks()};
    coordinator.schedule(snapshot(22U), {kMarkTwo}, 2U);
    REQUIRE(harness.tasks.size() == 1U);
    const int task_id = harness.tasks.begin()->first;

    CHECK(harness.fire(task_id));
    CHECK_FALSE(harness.fire(task_id));
    CHECK(harness.dispatched.size() == 1U);
    CHECK_FALSE(coordinator.has_pending());
    CHECK_FALSE(coordinator.timer_pending());
    CHECK(harness.dispatched.front().snapshot.runtime_generation == 22U);
    CHECK(harness.dispatched.front().ordered_marks ==
          std::vector<std::uint32_t>{kMarkTwo});
    CHECK(harness.dispatched.front().no_progress_attempt == 2U);
}

TEST_CASE(
    "ConntrackCleanupCoordinator resets attempts on progress and increments without it") {
    SUBCASE("progress resets the attempt") {
        CoordinatorHarness harness;
        ConntrackCleanupCoordinator coordinator{harness.callbacks()};
        const auto source_retry =
            retry({kMarkOne, kMarkTwo, kMarkThree}, 3U);

        coordinator.schedule_remaining(
            source_retry, {kMarkTwo, kMarkThree});

        CHECK(harness.delays ==
              std::vector<std::chrono::milliseconds>{
                  std::chrono::seconds{2}});
        REQUIRE(harness.tasks.size() == 1U);
        CHECK(harness.fire(harness.tasks.begin()->first));
        REQUIRE(harness.dispatched.size() == 1U);
        CHECK(harness.dispatched.front().no_progress_attempt == 0U);
        CHECK(harness.dispatched.front().ordered_marks ==
              std::vector<std::uint32_t>{kMarkTwo, kMarkThree});
    }

    SUBCASE("no progress increments the attempt") {
        CoordinatorHarness harness;
        ConntrackCleanupCoordinator coordinator{harness.callbacks()};
        const auto source_retry = retry({kMarkOne, kMarkTwo}, 2U);

        coordinator.schedule_remaining(
            source_retry, {kMarkTwo, kMarkOne});

        CHECK(harness.delays ==
              std::vector<std::chrono::milliseconds>{
                  std::chrono::seconds{16}});
        REQUIRE(harness.tasks.size() == 1U);
        CHECK(harness.fire(harness.tasks.begin()->first));
        REQUIRE(harness.dispatched.size() == 1U);
        CHECK(harness.dispatched.front().no_progress_attempt == 3U);
    }

    SUBCASE("an empty remainder schedules nothing") {
        CoordinatorHarness harness;
        ConntrackCleanupCoordinator coordinator{harness.callbacks()};
        coordinator.schedule_remaining(retry({kMarkOne}, 1U), {});
        CHECK_FALSE(coordinator.has_pending());
        CHECK(harness.delays.empty());
    }
}

TEST_CASE(
    "ConntrackCleanupCoordinator retains pending work when timer publication fails") {
    SUBCASE("a throwing scheduler can be armed later") {
        CoordinatorHarness harness;
        harness.throw_on_schedule = true;
        ConntrackCleanupCoordinator coordinator{harness.callbacks()};

        CHECK_THROWS_AS(
            coordinator.schedule(snapshot(), {kMarkOne}, 1U),
            std::runtime_error);
        CHECK(coordinator.has_pending());
        CHECK_FALSE(coordinator.timer_pending());

        harness.throw_on_schedule = false;
        coordinator.arm();
        CHECK(coordinator.has_pending());
        CHECK(coordinator.timer_pending());
        REQUIRE(harness.tasks.size() == 1U);
        CHECK(harness.fire(harness.tasks.begin()->first));
        CHECK(harness.dispatched.size() == 1U);
    }

    SUBCASE("a negative task id can be armed later") {
        CoordinatorHarness harness;
        harness.return_negative_task_id = true;
        ConntrackCleanupCoordinator coordinator{harness.callbacks()};

        coordinator.schedule(snapshot(), {kMarkOne}, 1U);
        CHECK(coordinator.has_pending());
        CHECK_FALSE(coordinator.timer_pending());

        harness.return_negative_task_id = false;
        coordinator.arm();
        CHECK(coordinator.has_pending());
        CHECK(coordinator.timer_pending());
        REQUIRE(harness.tasks.size() == 1U);
        CHECK(harness.fire(harness.tasks.begin()->first));
        CHECK(harness.dispatched.size() == 1U);
    }
}

TEST_CASE(
    "ConntrackCleanupCoordinator exposes only the exact generation remainder") {
    CoordinatorHarness harness;
    ConntrackCleanupCoordinator coordinator{harness.callbacks()};
    coordinator.schedule(
        snapshot(
            41U,
            kOwnedMask,
            {kMarkOne, kMarkTwo},
            {kMarkOne, kMarkTwo},
            true),
        {kMarkTwo});

    CHECK_FALSE(coordinator.pending_remainder(40U).has_value());
    const auto exact = coordinator.pending_remainder(41U);
    REQUIRE(exact.has_value());
    CHECK(exact->runtime_generation == 41U);
    CHECK(exact->marks == std::set<std::uint32_t>{kMarkTwo});
    CHECK(exact->priority_marks == std::set<std::uint32_t>{kMarkTwo});

    REQUIRE(harness.tasks.size() == 1U);
    const int task_id = harness.tasks.begin()->first;
    coordinator.cancel();
    CHECK(harness.cancelled_task_ids == std::vector<int>{task_id});
    CHECK_FALSE(coordinator.has_pending());
    CHECK_FALSE(coordinator.timer_pending());
    CHECK_FALSE(coordinator.pending_remainder(41U).has_value());
}

TEST_CASE(
    "ConntrackCleanupCoordinator clears accepted handoff despite cancellation failure") {
    CoordinatorHarness harness;
    ConntrackCleanupCoordinator coordinator{harness.callbacks()};
    coordinator.schedule(snapshot(), {kMarkOne});
    REQUIRE(harness.tasks.size() == 1U);
    const int task_id = harness.tasks.begin()->first;
    harness.throw_on_cancel = true;

    CHECK_NOTHROW(coordinator.clear_after_handoff());
    CHECK_FALSE(coordinator.has_pending());
    CHECK_FALSE(coordinator.timer_pending());
    CHECK(harness.cancelled_task_ids == std::vector<int>{task_id});
    CHECK(harness.fire(task_id));
    CHECK(harness.dispatched.empty());
}

TEST_CASE("ConntrackCleanupCoordinator reports command absence only once") {
    ConntrackCleanupCoordinator coordinator;
    CHECK(coordinator.note_command_unavailable());
    CHECK_FALSE(coordinator.note_command_unavailable());
    CHECK_FALSE(coordinator.note_command_unavailable());
}

TEST_CASE(
    "ConntrackCleanupCoordinator owns the committed native VPN SNAT cursor") {
    ConntrackCleanupCoordinator coordinator;
    std::vector<FirewallSourceEgressSnatSelector> first{
        {"nwg0", "10.0.0.0/24"},
        {"nwg1", "2001:db8::/64"},
    };
    const auto expected_first = first;

    coordinator.commit_native_vpn_direct_egress_snat_selectors(first);
    first.clear();
    CHECK(
        coordinator.committed_native_vpn_direct_egress_snat_selectors() ==
        expected_first);

    std::vector<FirewallSourceEgressSnatSelector> second{
        {"nwg2", "10.2.0.0/24"},
    };
    const auto expected_second = second;
    static_assert(noexcept(
        coordinator.exchange_native_vpn_direct_egress_snat_selectors(second)));
    coordinator.exchange_native_vpn_direct_egress_snat_selectors(second);

    CHECK(
        coordinator.committed_native_vpn_direct_egress_snat_selectors() ==
        expected_second);
    CHECK(second == expected_first);
}

} // namespace keen_pbr3
