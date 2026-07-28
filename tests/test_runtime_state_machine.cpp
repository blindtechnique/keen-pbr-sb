#include <doctest/doctest.h>

#include "daemon/runtime_recovery_policy.hpp"
#include "runtime/runtime_state_machine.hpp"

#include <chrono>
#include <vector>

using namespace keen_pbr3;

TEST_CASE("runtime state machine accepts recovery and rejects impossible transitions") {
    RuntimeStateMachine machine;
    std::string error;

    CHECK(machine.transition(RuntimeState::running, "startup complete", error));
    CHECK(machine.transition(RuntimeState::applying, "apply", error));
    CHECK(machine.transition(RuntimeState::broken, "apply failed", error));
    CHECK(machine.transition(RuntimeState::applying, "rollback", error));
    CHECK(machine.transition(RuntimeState::running, "rollback complete", error));
    CHECK(machine.transition(RuntimeState::stopped, "stopped", error));
    CHECK_FALSE(machine.transition(RuntimeState::running, "invalid shortcut", error));
    CHECK(error == "invalid runtime transition: stopped -> running");
}

TEST_CASE("broken runtime can be started explicitly") {
    RuntimeStateMachine machine(RuntimeState::broken);
    std::string error;
    CHECK(machine.transition(RuntimeState::starting, "retry requested", error));
    CHECK(machine.transition(RuntimeState::running, "retry complete", error));
}

TEST_CASE("runtime recovery runs only for the active configuration generation") {
    CHECK(runtime_recovery_is_current(true, 7, 7));
    CHECK_FALSE(runtime_recovery_is_current(false, 7, 7));
    CHECK_FALSE(runtime_recovery_is_current(true, 7, 8));
}

TEST_CASE("new runtime refresh coalesces with a pending recovery chain") {
    CHECK(runtime_recovery_request_should_coalesce(0, true));
    CHECK_FALSE(runtime_recovery_request_should_coalesce(0, false));
    CHECK_FALSE(runtime_recovery_request_should_coalesce(1, true));
}

TEST_CASE("runtime incident latch reports threshold once and resets") {
    RuntimeIncidentLatch incidents(3);

    CHECK_FALSE(incidents.record_failure("selector").notify);
    CHECK_FALSE(incidents.record_failure("selector").notify);
    const auto threshold = incidents.record_failure("selector");
    CHECK(threshold.notify);
    CHECK(threshold.consecutive_failures == 3);
    CHECK_FALSE(incidents.record_failure("selector").notify);

    incidents.reset("selector");
    CHECK_FALSE(incidents.record_failure("selector").notify);
}

TEST_CASE("runtime incident latch reports an immediate severe failure once") {
    RuntimeIncidentLatch incidents(3);

    const auto first =
        incidents.record_failure("selector", /*notify_immediately=*/true);
    CHECK(first.notify);
    CHECK(first.consecutive_failures == 1);
    CHECK_FALSE(
        incidents.record_failure(
            "selector", /*notify_immediately=*/true)
            .notify);

    incidents.clear();
    CHECK(
        incidents.record_failure(
            "selector", /*notify_immediately=*/true)
            .notify);
}

TEST_CASE("hot apply retries only transient firewall failures with backoff") {
    std::size_t apply_attempts = 0;
    std::vector<std::chrono::milliseconds> waits;
    std::vector<std::size_t> retries;

    retry_hot_apply_firewall(
        [&]() {
            ++apply_attempts;
            if (apply_attempts < 3) {
                throw TransientFirewallError("firmware changed the hook");
            }
        },
        [&](std::chrono::milliseconds delay) {
            waits.push_back(delay);
        },
        [&](std::size_t retry,
            std::chrono::milliseconds,
            const TransientFirewallError&) {
            retries.push_back(retry);
        });

    CHECK(apply_attempts == 3);
    const std::vector<std::chrono::milliseconds> expected_waits{
        std::chrono::milliseconds{100},
        std::chrono::milliseconds{200},
    };
    const std::vector<std::size_t> expected_retries{1, 2};
    CHECK(waits == expected_waits);
    CHECK(retries == expected_retries);
}

TEST_CASE("hot apply propagates a permanent firewall failure immediately") {
    std::size_t apply_attempts = 0;
    std::size_t waits = 0;

    CHECK_THROWS_AS(
        retry_hot_apply_firewall(
            [&]() {
                ++apply_attempts;
                throw FirewallError("invalid generated rule");
            },
            [&](std::chrono::milliseconds) {
                ++waits;
            },
            [](std::size_t,
               std::chrono::milliseconds,
               const TransientFirewallError&) {}),
        FirewallError);

    CHECK(apply_attempts == 1);
    CHECK(waits == 0);
}

TEST_CASE("hot apply bounds repeated transient firewall failures") {
    std::size_t apply_attempts = 0;
    std::vector<std::chrono::milliseconds> waits;

    CHECK_THROWS_AS(
        retry_hot_apply_firewall(
            [&]() {
                ++apply_attempts;
                throw TransientFirewallError("firmware is still changing");
            },
            [&](std::chrono::milliseconds delay) {
                waits.push_back(delay);
            },
            [](std::size_t,
               std::chrono::milliseconds,
               const TransientFirewallError&) {}),
        TransientFirewallError);

    CHECK(apply_attempts == 4);
    const std::vector<std::chrono::milliseconds> expected_waits{
        std::chrono::milliseconds{100},
        std::chrono::milliseconds{200},
        std::chrono::milliseconds{400},
    };
    CHECK(waits == expected_waits);
}
