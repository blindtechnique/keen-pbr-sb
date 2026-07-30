#include <doctest/doctest.h>

#include "daemon/runtime_recovery_policy.hpp"
#include "runtime/runtime_state_machine.hpp"

#include <chrono>
#include <stdexcept>
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

TEST_CASE("SNAT recovery evicts only flows affected by a confirmed repair") {
    OwnedSnatRecovery recovery{
        /*requested=*/true,
        /*missing_observed=*/false};
    recovery =
        observe_owned_snat_state(recovery, OwnedSnatState::missing);
    CHECK(should_cleanup_conntrack_after_snat_repair(
        recovery,
        OwnedSnatState::healthy));
    CHECK_FALSE(should_cleanup_conntrack_after_snat_repair(
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/false},
        OwnedSnatState::healthy));
    CHECK_FALSE(should_cleanup_conntrack_after_snat_repair(
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/false},
        OwnedSnatState::healthy));
    CHECK_FALSE(should_cleanup_conntrack_after_snat_repair(
        recovery,
        OwnedSnatState::unknown));
    CHECK_FALSE(should_cleanup_conntrack_after_snat_repair(
        recovery,
        OwnedSnatState::missing));
    CHECK_FALSE(should_cleanup_conntrack_after_snat_repair(
        OwnedSnatRecovery{
            /*requested=*/false,
            /*missing_observed=*/true},
        OwnedSnatState::healthy));
}

TEST_CASE("SNAT recovery keeps the missing observation across retries") {
    OwnedSnatRecovery recovery{
        /*requested=*/true,
        /*missing_observed=*/false};
    recovery =
        observe_owned_snat_state(recovery, OwnedSnatState::missing);
    recovery =
        observe_owned_snat_state(recovery, OwnedSnatState::unknown);
    recovery =
        observe_owned_snat_state(recovery, OwnedSnatState::healthy);

    CHECK(recovery.missing_observed);
    CHECK(should_cleanup_conntrack_after_snat_repair(
        recovery, OwnedSnatState::healthy));

    const auto merged = merge_owned_snat_recovery(
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/false},
        recovery);
    CHECK(merged.requested);
    CHECK(merged.missing_observed);
}

TEST_CASE("periodic SNAT repair runs only for confirmed drift") {
    CHECK(should_run_periodic_snat_repair(
        true, false, false, OwnedSnatState::missing));
    CHECK(should_run_periodic_snat_repair(
        true, false, false, OwnedSnatState::stale));

    CHECK_FALSE(should_run_periodic_snat_repair(
        true, false, false, OwnedSnatState::healthy));
    CHECK_FALSE(should_run_periodic_snat_repair(
        true, false, false, OwnedSnatState::unknown));
    CHECK_FALSE(should_run_periodic_snat_repair(
        false, false, false, OwnedSnatState::missing));
    CHECK_FALSE(should_run_periodic_snat_repair(
        true, true, false, OwnedSnatState::missing));
    CHECK_FALSE(should_run_periodic_snat_repair(
        true, false, true, OwnedSnatState::stale));
}

TEST_CASE("conntrack cleanup retry cannot cross a runtime generation") {
    OwnedConntrackCleanupRetry retry{
        OwnedConntrackCleanupSnapshot{
            /*runtime_generation=*/17,
            /*owned_mask=*/0x00ff0000U,
            /*marks=*/{0x00010000U, 0x00020000U},
            /*priority_marks=*/{0x00010000U},
            /*ipv6_enabled=*/true},
        /*ordered_marks=*/{0x00010000U, 0x00020000U},
        /*no_progress_attempt=*/1};

    CHECK(owned_conntrack_cleanup_retry_is_current(
        true, retry, /*current_generation=*/17));
    CHECK_FALSE(owned_conntrack_cleanup_retry_is_current(
        true, retry, /*current_generation=*/18));
    CHECK_FALSE(owned_conntrack_cleanup_retry_is_current(
        false, retry, /*current_generation=*/17));

    retry.ordered_marks.clear();
    CHECK_FALSE(owned_conntrack_cleanup_retry_is_current(
        true, retry, /*current_generation=*/17));
}

TEST_CASE("SNAT recovery retains the owned mark snapshot from confirmed loss") {
    OwnedSnatRecovery recovery{
        /*requested=*/true,
        /*missing_observed=*/false};
    recovery = observe_owned_snat_state(
        std::move(recovery),
        OwnedSnatState::missing,
        OwnedConntrackCleanupSnapshot{
            /*runtime_generation=*/11,
            /*owned_mask=*/0x00ff0000U,
            /*marks=*/{0x00010000U, 0x00020000U}});
    recovery = observe_owned_snat_state(
        std::move(recovery), OwnedSnatState::unknown);

    REQUIRE(recovery.cleanup_snapshot.has_value());
    CHECK(recovery.cleanup_snapshot->runtime_generation == 11U);
    CHECK(recovery.cleanup_snapshot->owned_mask == 0x00ff0000U);
    CHECK(recovery.cleanup_snapshot->marks ==
          std::set<std::uint32_t>{0x00010000U, 0x00020000U});
}

TEST_CASE("SNAT recovery merges priority marks within one runtime generation") {
    auto merged = merge_owned_conntrack_cleanup_snapshot(
        OwnedConntrackCleanupSnapshot{
            /*runtime_generation=*/11,
            /*owned_mask=*/0x00ff0000U,
            /*marks=*/{0x00010000U, 0x00020000U},
            /*priority_marks=*/{0x00010000U},
            /*ipv6_enabled=*/false},
        OwnedConntrackCleanupSnapshot{
            /*runtime_generation=*/11,
            /*owned_mask=*/0x00ff0000U,
            /*marks=*/{0x00020000U, 0x00030000U},
            /*priority_marks=*/{0x00030000U},
            /*ipv6_enabled=*/false});

    CHECK(merged.marks ==
          std::set<std::uint32_t>{
              0x00010000U, 0x00020000U, 0x00030000U});
    CHECK(merged.priority_marks ==
          std::set<std::uint32_t>{0x00010000U, 0x00030000U});
    CHECK_FALSE(merged.ipv6_enabled);
}

TEST_CASE("SNAT recovery never mixes cleanup marks from runtime generations") {
    const auto merged = merge_owned_snat_recovery(
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/true,
            OwnedConntrackCleanupSnapshot{
                /*runtime_generation=*/8,
                /*owned_mask=*/0x00ff0000U,
                /*marks=*/{0x00010000U}}},
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/true,
            OwnedConntrackCleanupSnapshot{
                /*runtime_generation=*/9,
                /*owned_mask=*/0x00ff0000U,
                /*marks=*/{0x00020000U}}});

    REQUIRE(merged.cleanup_snapshot.has_value());
    CHECK(merged.cleanup_snapshot->runtime_generation == 9U);
    CHECK(merged.cleanup_snapshot->marks ==
          std::set<std::uint32_t>{0x00020000U});
}

TEST_CASE("runtime firewall retry becomes quiet SNAT maintenance after exhaustion") {
    const auto bounded =
        plan_runtime_firewall_retry(2, 6, /*snat_recovery_requested=*/false);
    CHECK(bounded.schedule);
    CHECK_FALSE(bounded.maintenance);
    CHECK(bounded.next_attempt == 3U);

    const auto generic_exhausted =
        plan_runtime_firewall_retry(6, 6, /*snat_recovery_requested=*/false);
    CHECK_FALSE(generic_exhausted.schedule);

    const auto snat_maintenance =
        plan_runtime_firewall_retry(6, 6, /*snat_recovery_requested=*/true);
    CHECK(snat_maintenance.schedule);
    CHECK(snat_maintenance.maintenance);
    CHECK(snat_maintenance.next_attempt == 0U);
}

TEST_CASE("single-flight refresh hands one pending request to an immediate rerun") {
    CoalescedSingleFlightGate gate;
    std::size_t launched_workers = 0;
    const auto schedule = [&]() {
        if (gate.request()) {
            ++launched_workers;
        }
    };

    schedule();
    schedule();
    schedule();
    CHECK(launched_workers == 1);

    if (gate.complete()) {
        schedule();
    }
    CHECK(launched_workers == 2);
    CHECK_FALSE(gate.complete());
}

TEST_CASE("observation gap recovery invalidates, cancels, reconciles, then coalesces refresh") {
    CoalescedSingleFlightGate refresh_gate;
    std::vector<std::string> events;
    std::size_t launched_workers = 0;
    const auto schedule_refresh = [&]() {
        events.push_back("request-refresh");
        if (refresh_gate.request()) {
            ++launched_workers;
        }
    };

    // Model an authoritative NDMS read which was already in flight when either
    // ENOBUFS or a successful netlink reconnect reported an observation gap.
    REQUIRE(refresh_gate.request());
    ++launched_workers;

    recover_internal_vpn_after_observation_gap(
        [&]() { events.push_back("invalidate"); },
        [&]() { events.push_back("cancel-retry"); },
        [&]() { events.push_back("reconcile"); },
        schedule_refresh);

    const std::vector<std::string> expected{
        "invalidate",
        "cancel-retry",
        "reconcile",
        "request-refresh",
    };
    CHECK(events == expected);
    CHECK(launched_workers == 1);

    if (refresh_gate.complete()) {
        schedule_refresh();
    }
    CHECK(launched_workers == 2);
    CHECK_FALSE(refresh_gate.complete());
}

TEST_CASE("post-commit resolver retry is cancelled by a newer generation") {
    std::vector<std::string> events{"commit", "schedule:7"};
    bool reload_called = false;

    const auto outcome = evaluate_resolver_reload_retry(
        true,
        /*expected_generation=*/7,
        /*current_generation=*/8,
        /*attempt=*/0,
        /*max_attempts=*/5,
        [&]() {
            reload_called = true;
            events.push_back("reload");
            return true;
        });

    CHECK(outcome == ResolverReloadRetryOutcome::stale_generation);
    CHECK_FALSE(reload_called);
    const std::vector<std::string> expected{"commit", "schedule:7"};
    CHECK(events == expected);
}

TEST_CASE("current resolver recovery retries, recovers, and eventually exhausts") {
    CHECK(
        evaluate_resolver_reload_retry(
            true, 7, 7, 0, 5, []() { return false; }) ==
        ResolverReloadRetryOutcome::retry);
    CHECK(
        evaluate_resolver_reload_retry(
            true, 7, 7, 1, 5, []() { return true; }) ==
        ResolverReloadRetryOutcome::recovered);
    CHECK(
        evaluate_resolver_reload_retry(
            true, 7, 7, 4, 5, []() { return false; }) ==
        ResolverReloadRetryOutcome::exhausted);
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

TEST_CASE("native VPN inventory grace suppresses transient refresh failures") {
    RuntimeIncidentLatch incidents(5);

    for (std::size_t attempt = 1; attempt < 5; ++attempt) {
        const auto decision = incidents.record_failure("ndms-catalog");
        CHECK(decision.consecutive_failures == attempt);
        CHECK_FALSE(decision.notify);
    }
    const auto persistent = incidents.record_failure("ndms-catalog");
    CHECK(persistent.consecutive_failures == 5U);
    CHECK(persistent.notify);
    CHECK_FALSE(incidents.record_failure("ndms-catalog").notify);

    incidents.clear();
    CHECK_FALSE(incidents.record_failure("ndms-catalog").notify);
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

TEST_CASE("runtime replacement reconciles before firewall and resolver") {
    std::vector<std::string> events;

    apply_runtime_replacement(
        [&]() { events.push_back("routing"); },
        [&]() { events.push_back("firewall"); },
        [](std::chrono::milliseconds) {},
        [](std::size_t,
           std::chrono::milliseconds,
           const TransientFirewallError&) {},
        [&]() { events.push_back("resolver"); });

    const std::vector<std::string> expected{
        "routing",
        "firewall",
        "resolver",
    };
    CHECK(events == expected);
}

TEST_CASE("runtime replacement keeps later stages untouched after firewall failure") {
    bool previous_runtime_active = true;
    bool resolver_reloaded = false;
    std::size_t attempts = 0;

    CHECK_THROWS_AS(
        apply_runtime_replacement(
            []() {},
            [&]() {
                ++attempts;
                throw TransientFirewallError("firmware is still changing");
            },
            [](std::chrono::milliseconds) {},
            [](std::size_t,
               std::chrono::milliseconds,
               const TransientFirewallError&) {},
            [&]() { resolver_reloaded = true; }),
        TransientFirewallError);

    CHECK(attempts == 4);
    CHECK(previous_runtime_active);
    CHECK_FALSE(resolver_reloaded);
}

TEST_CASE("runtime replacement does not stop the previous runtime on resolver failure") {
    bool previous_runtime_active = true;

    CHECK_THROWS_AS(
        apply_runtime_replacement(
            []() {},
            []() {},
            [](std::chrono::milliseconds) {},
            [](std::size_t,
               std::chrono::milliseconds,
               const TransientFirewallError&) {},
            []() { throw std::runtime_error("resolver reload failed"); }),
        std::runtime_error);

    CHECK(previous_runtime_active);
}
