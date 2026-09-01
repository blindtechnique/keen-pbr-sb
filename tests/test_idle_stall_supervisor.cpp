#include <doctest/doctest.h>

#include "daemon/idle_stall_supervisor.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

constexpr std::uint32_t kOwnedMask = 0x00FF0000U;
constexpr std::uint32_t kPreventiveMark = 0x00070000U;

struct SupervisorHarness final {
    struct ScheduledTask final {
        std::chrono::milliseconds delay;
        std::string name;
        std::function<void()> callback;
    };

    int next_task_id{1};
    bool throw_on_schedule{false};
    bool return_negative_task_id{false};
    bool run_schedule_inline{false};
    bool throw_on_cancel{false};
    bool retain_cancelled_task{false};
    std::map<int, ScheduledTask> tasks;
    std::vector<std::chrono::milliseconds> delays;
    std::vector<std::string> names;
    std::vector<int> cancelled_task_ids;
    std::vector<std::string> schedule_failures;
    std::size_t observer_runs{0U};

    IdleStallSupervisorCallbacks callbacks() {
        IdleStallSupervisorCallbacks result;
        result.schedule_oneshot =
            [this](std::chrono::milliseconds delay,
                   std::function<void()> callback,
                   std::string name) {
                delays.push_back(delay);
                names.push_back(name);
                if (throw_on_schedule) {
                    throw std::runtime_error{"scheduler unavailable"};
                }
                if (return_negative_task_id) return -1;
                const int task_id = next_task_id++;
                if (run_schedule_inline) {
                    callback();
                    return task_id;
                }
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
            if (!retain_cancelled_task) tasks.erase(task_id);
        };
        result.run_observer = [this]() { ++observer_runs; };
        result.schedule_failed = [this](std::string detail) {
            schedule_failures.push_back(std::move(detail));
        };
        return result;
    }

    bool fire(int task_id) {
        const auto iterator = tasks.find(task_id);
        if (iterator == tasks.end()) return false;
        auto callback = std::move(iterator->second.callback);
        tasks.erase(iterator);
        callback();
        return true;
    }
};

IdleStallFlowSample idle_sample() {
    return IdleStallFlowSample{
        IdleStallFlowKey{
            IdleStallAddressFamily::ipv4,
            IdleStallProtocol::tcp,
            "192.168.1.44",
            "31.13.66.10",
            41000U,
            443U,
            0U},
        IdleStallFlowCounters{10U, 1000U, 10U, 1000U},
        IdleStallFlowReadiness::tcp_established,
        false,
        IdleStallRecoveryPolicy::standard};
}

void seed_idle_detector(IdleStallSupervisor& supervisor) {
    IdleStallScan scan;
    scan.epoch = IdleStallEpoch{17U, supervisor.coverage_generation()};
    scan.owned_mark_mask = kOwnedMask;
    scan.flows = {idle_sample()};
    CHECK(supervisor.idle_detector().observe(
              scan, IdleStallDetector::TimePoint{})
              .empty());
    CHECK(supervisor.idle_detector().tracked_flow_count() == 1U);
}

ConntrackExactForwardedFlow affinity_flow(
    std::string destination,
    std::uint16_t destination_port,
    std::uint32_t mark,
    std::uint64_t packets,
    std::uint64_t reply_packets = 0U,
    bool assured = false,
    bool seen_reply = false) {
    ConntrackExactForwardedFlow flow;
    flow.family = ConntrackFlowFamily::Ipv4;
    flow.protocol = ConntrackFlowProtocol::Udp;
    flow.source = "192.168.1.44";
    flow.destination = std::move(destination);
    flow.source_port = static_cast<std::uint16_t>(
        30000U + destination_port % 20000U);
    flow.destination_port = destination_port;
    flow.mark = mark;
    flow.original = {packets, packets * 900U};
    flow.reply = {reply_packets, reply_packets * 700U};
    flow.assured = assured;
    flow.seen_reply = seen_reply;
    return flow;
}

void seed_affinity_detector(IdleStallSupervisor& supervisor) {
    const auto now = UdpCallAffinityDetector::TimePoint{};
    const std::vector<UdpCallAffinityTarget> targets{
        {"meta_whatsapp_ip", kPreventiveMark}};
    const auto seed = affinity_flow(
        "157.240.253.142",
        443U,
        kPreventiveMark,
        10U,
        12U,
        true,
        true);
    const std::vector<ConntrackExactForwardedFlow> candidates{
        affinity_flow("64.176.66.4", 443U, 0U, 3U),
        affinity_flow("13.38.106.1", 53U, 0U, 3U),
        affinity_flow("37.46.119.30", 22U, 0U, 3U),
        affinity_flow("130.195.209.69", 554U, 0U, 3U),
    };
    CHECK(supervisor.affinity_detector()
              .observe(
                  IdleStallEpoch{17U, supervisor.coverage_generation()},
                  IdleStallScanStatus{},
                  kOwnedMask,
                  targets,
                  {seed},
                  candidates,
                  now)
              .empty());
    CHECK(supervisor.affinity_detector().needs_fast_followup(now));
}

} // namespace

TEST_CASE("IdleStallSupervisor gates and consumes the initial timer") {
    SupervisorHarness harness;
    IdleStallSupervisor supervisor{harness.callbacks()};

    supervisor.reset(false, 5s);
    CHECK_FALSE(supervisor.enabled());
    CHECK_FALSE(supervisor.timer_pending());
    CHECK(harness.tasks.empty());

    supervisor.reset(true, 5s);
    CHECK(supervisor.enabled());
    CHECK(supervisor.timer_pending());
    REQUIRE(harness.tasks.size() == 1U);
    CHECK(harness.delays.back() == 5s);
    CHECK(harness.names.back() == "idle-stall-observer");
    const int task_id = harness.tasks.begin()->first;

    CHECK(harness.fire(task_id));
    CHECK_FALSE(harness.fire(task_id));
    CHECK_FALSE(supervisor.timer_pending());
    CHECK(harness.observer_runs == 1U);
}

TEST_CASE("IdleStallSupervisor replaces one exact timer") {
    SupervisorHarness harness;
    IdleStallSupervisor supervisor{harness.callbacks()};
    supervisor.reset(true, 5s);
    REQUIRE(harness.tasks.size() == 1U);
    const int first_task_id = harness.tasks.begin()->first;

    supervisor.schedule_after(30s, /*runtime_active=*/true);

    CHECK(harness.cancelled_task_ids == std::vector<int>{first_task_id});
    REQUIRE(harness.tasks.size() == 1U);
    const int second_task_id = harness.tasks.begin()->first;
    CHECK(second_task_id != first_task_id);
    CHECK(harness.tasks.begin()->second.delay == 30s);
    CHECK_FALSE(harness.fire(first_task_id));
    CHECK(harness.fire(second_task_id));
    CHECK(harness.observer_runs == 1U);
}

TEST_CASE("IdleStallSupervisor does not publish an inline-consumed timer") {
    SupervisorHarness harness;
    harness.run_schedule_inline = true;
    IdleStallSupervisor supervisor{harness.callbacks()};

    supervisor.reset(true, 5s);

    CHECK(supervisor.enabled());
    CHECK_FALSE(supervisor.timer_pending());
    CHECK(harness.tasks.empty());
    CHECK(harness.observer_runs == 1U);
}

TEST_CASE(
    "IdleStallSupervisor ignores a stale callback after timer replacement") {
    SupervisorHarness harness;
    harness.retain_cancelled_task = true;
    IdleStallSupervisor supervisor{harness.callbacks()};
    supervisor.reset(true, 5s);
    REQUIRE(harness.tasks.size() == 1U);
    const int stale_task_id = harness.tasks.begin()->first;

    supervisor.schedule_after(30s, /*runtime_active=*/true);
    REQUIRE(harness.tasks.size() == 2U);
    const int current_task_id = harness.tasks.rbegin()->first;
    REQUIRE(current_task_id != stale_task_id);

    CHECK(harness.fire(stale_task_id));
    CHECK(harness.observer_runs == 0U);
    CHECK(supervisor.timer_pending());
    CHECK(harness.fire(current_task_id));
    CHECK(harness.observer_runs == 1U);
    CHECK_FALSE(supervisor.timer_pending());
}

TEST_CASE("IdleStallSupervisor keeps one inflight observation across cancel") {
    SupervisorHarness harness;
    IdleStallSupervisor supervisor{harness.callbacks()};
    supervisor.reset(true, 5s);

    CHECK(supervisor.try_begin_inflight());
    CHECK_FALSE(supervisor.try_begin_inflight());
    CHECK(supervisor.inflight());

    const auto coverage_before_cancel = supervisor.coverage_generation();
    supervisor.cancel();
    CHECK_FALSE(supervisor.enabled());
    CHECK(supervisor.inflight());
    CHECK(supervisor.coverage_generation() == coverage_before_cancel + 1U);
    CHECK_FALSE(supervisor.current_coverage(coverage_before_cancel));

    supervisor.finish_inflight();
    CHECK_FALSE(supervisor.inflight());

    CHECK(supervisor.try_begin_inflight());
    {
        auto guard = supervisor.adopt_inflight();
        CHECK(supervisor.inflight());
    }
    CHECK_FALSE(supervisor.inflight());
}

TEST_CASE("IdleStallSupervisor scope identity resets both detectors once") {
    IdleStallSupervisor supervisor;
    const std::vector<std::string> destinations{
        "31.13.64.0/18", "157.240.0.0/16"};
    const std::vector<std::string> affinity{"157.240.0.0/16"};

    const auto initial_generation = supervisor.coverage_generation();
    CHECK(supervisor.update_observation_scope(
        destinations, affinity, kPreventiveMark, true));
    CHECK(supervisor.coverage_generation() == initial_generation + 1U);
    seed_idle_detector(supervisor);
    seed_affinity_detector(supervisor);

    const auto stable_generation = supervisor.coverage_generation();
    CHECK_FALSE(supervisor.update_observation_scope(
        destinations, affinity, kPreventiveMark, true));
    CHECK(supervisor.coverage_generation() == stable_generation);
    CHECK(supervisor.idle_detector().tracked_flow_count() == 1U);
    CHECK(supervisor.affinity_detector().needs_fast_followup(
        UdpCallAffinityDetector::TimePoint{}));

    CHECK(supervisor.update_observation_scope(
        {"31.13.64.0/18"}, affinity, kPreventiveMark, true));
    CHECK(supervisor.coverage_generation() == stable_generation + 1U);
    CHECK(supervisor.idle_detector().tracked_flow_count() == 0U);
    CHECK_FALSE(supervisor.affinity_detector().needs_fast_followup(
        UdpCallAffinityDetector::TimePoint{}));

    seed_idle_detector(supervisor);
    CHECK(supervisor.update_observation_scope(
        {"31.13.64.0/18"}, {}, kPreventiveMark, true));
    CHECK(supervisor.idle_detector().tracked_flow_count() == 0U);

    seed_idle_detector(supervisor);
    CHECK(supervisor.update_observation_scope(
        {"31.13.64.0/18"}, {}, std::nullopt, true));
    CHECK(supervisor.idle_detector().tracked_flow_count() == 0U);

    seed_idle_detector(supervisor);
    CHECK(supervisor.update_observation_scope(
        {"31.13.64.0/18"}, {}, std::nullopt, false));
    CHECK(supervisor.idle_detector().tracked_flow_count() == 0U);
}

TEST_CASE(
    "IdleStallSupervisor invalidates incomplete coverage without disabling") {
    SupervisorHarness harness;
    IdleStallSupervisor supervisor{harness.callbacks()};
    supervisor.reset(true, 5s);
    CHECK(supervisor.update_observation_scope(
        {"31.13.64.0/18"},
        {"157.240.0.0/16"},
        kPreventiveMark,
        true));
    seed_idle_detector(supervisor);
    seed_affinity_detector(supervisor);
    const auto previous_generation = supervisor.coverage_generation();

    supervisor.invalidate_incomplete_scope();

    CHECK(supervisor.enabled());
    CHECK(supervisor.coverage_generation() == previous_generation + 1U);
    CHECK(supervisor.destination_selectors().empty());
    CHECK(supervisor.affinity_destination_selectors().empty());
    // Preserve the previous characterization: incomplete coverage clears
    // selector continuity, while the next complete scope comparison retires
    // unchanged preventive authority and packaged-only provenance.
    CHECK(supervisor.preventive_owned_mark() == kPreventiveMark);
    CHECK(supervisor.packaged_whatsapp_only_observation());
    CHECK(supervisor.idle_detector().tracked_flow_count() == 0U);
    CHECK_FALSE(supervisor.affinity_detector().needs_fast_followup(
        UdpCallAffinityDetector::TimePoint{}));
}

TEST_CASE("IdleStallSupervisor schedules the consumed WhatsApp fast hint") {
    SupervisorHarness harness;
    IdleStallSupervisor supervisor{harness.callbacks()};
    supervisor.reset(true, 5s);

    auto flow = idle_sample();
    flow.recovery_policy =
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion;
    IdleStallScan scan;
    scan.epoch = IdleStallEpoch{17U, supervisor.coverage_generation()};
    scan.owned_mark_mask = kOwnedMask;
    scan.flows = {flow};
    CHECK(supervisor.idle_detector().observe(
              scan, IdleStallDetector::TimePoint{})
              .empty());

    flow.counters.original_packets += 4U;
    flow.counters.original_bytes += 600U;
    scan.flows = {flow};
    CHECK(supervisor.idle_detector().observe(
              scan,
              IdleStallDetector::TimePoint{} + 31s)
              .empty());
    const auto fast_followup =
        supervisor.idle_detector().take_whatsapp_fast_followup_delay();
    REQUIRE(fast_followup.has_value());

    supervisor.schedule_after(*fast_followup, true);

    CHECK(harness.delays.back() == 1s);
    CHECK_FALSE(supervisor.idle_detector()
                    .take_whatsapp_fast_followup_delay()
                    .has_value());
}

TEST_CASE("IdleStallSupervisor cancel is complete even when cancellation throws") {
    SupervisorHarness harness;
    IdleStallSupervisor supervisor{harness.callbacks()};
    supervisor.reset(true, 5s);
    CHECK(supervisor.update_observation_scope(
        {"31.13.64.0/18"},
        {"157.240.0.0/16"},
        kPreventiveMark,
        true));
    seed_idle_detector(supervisor);
    REQUIRE(harness.tasks.size() == 1U);
    const int stale_task_id = harness.tasks.begin()->first;
    const auto previous_generation = supervisor.coverage_generation();
    harness.throw_on_cancel = true;

    CHECK_NOTHROW(supervisor.cancel());

    CHECK_FALSE(supervisor.enabled());
    CHECK_FALSE(supervisor.timer_pending());
    CHECK(supervisor.coverage_generation() == previous_generation + 1U);
    CHECK(supervisor.destination_selectors().empty());
    CHECK(supervisor.affinity_destination_selectors().empty());
    CHECK_FALSE(supervisor.preventive_owned_mark().has_value());
    CHECK_FALSE(supervisor.packaged_whatsapp_only_observation());
    CHECK(supervisor.idle_detector().tracked_flow_count() == 0U);
    CHECK(harness.fire(stale_task_id));
    CHECK(harness.observer_runs == 0U);
}

TEST_CASE("IdleStallSupervisor fails closed when timer publication throws") {
    SupervisorHarness harness;
    IdleStallSupervisor supervisor{harness.callbacks()};
    supervisor.reset(true, 5s);
    CHECK(supervisor.update_observation_scope(
        {"31.13.64.0/18"},
        {"157.240.0.0/16"},
        kPreventiveMark,
        true));
    seed_idle_detector(supervisor);
    const auto previous_generation = supervisor.coverage_generation();
    harness.throw_on_schedule = true;

    CHECK_NOTHROW(supervisor.schedule_after(30s, true));

    CHECK_FALSE(supervisor.enabled());
    CHECK_FALSE(supervisor.timer_pending());
    CHECK(supervisor.coverage_generation() == previous_generation + 1U);
    CHECK(supervisor.destination_selectors().empty());
    CHECK(supervisor.affinity_destination_selectors().empty());
    CHECK_FALSE(supervisor.preventive_owned_mark().has_value());
    CHECK_FALSE(supervisor.packaged_whatsapp_only_observation());
    CHECK(supervisor.idle_detector().tracked_flow_count() == 0U);
    CHECK(harness.schedule_failures ==
          std::vector<std::string>{"scheduler unavailable"});
}

TEST_CASE("IdleStallSupervisor rejects a negative timer publication") {
    SupervisorHarness harness;
    harness.return_negative_task_id = true;
    IdleStallSupervisor supervisor{harness.callbacks()};
    const auto initial_generation = supervisor.coverage_generation();

    supervisor.reset(true, 5s);

    CHECK_FALSE(supervisor.enabled());
    CHECK_FALSE(supervisor.timer_pending());
    CHECK(supervisor.coverage_generation() == initial_generation + 2U);
    CHECK(harness.tasks.empty());
}

TEST_CASE("IdleStallSupervisor keeps the current timer while runtime is inactive") {
    SupervisorHarness harness;
    IdleStallSupervisor supervisor{harness.callbacks()};
    supervisor.reset(true, 5s);
    REQUIRE(harness.tasks.size() == 1U);
    const int task_id = harness.tasks.begin()->first;

    supervisor.schedule_after(30s, /*runtime_active=*/false);

    CHECK(supervisor.enabled());
    CHECK(supervisor.timer_pending());
    CHECK(harness.tasks.size() == 1U);
    CHECK(harness.tasks.begin()->first == task_id);
    CHECK(harness.cancelled_task_ids.empty());
}

} // namespace keen_pbr3
