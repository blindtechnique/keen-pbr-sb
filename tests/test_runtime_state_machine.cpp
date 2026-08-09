#include <doctest/doctest.h>

#include "daemon/runtime_recovery_policy.hpp"
#include "runtime/runtime_state_machine.hpp"

#include <chrono>
#include <functional>
#include <stdexcept>
#include <vector>

using namespace keen_pbr3;

namespace {

struct FakeRuntimeFirewallRetryScheduler {
    template <typename Callback>
    int schedule(const RuntimeFirewallRetryPlan& plan, Callback&& callback) {
        plans.push_back(plan);
        callbacks.emplace_back(std::forward<Callback>(callback));
        return next_task_id++;
    }

    std::vector<RuntimeFirewallRetryPlan> plans;
    std::vector<std::function<void()>> callbacks;
    int next_task_id{1};
};

} // namespace

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

TEST_CASE(
    "routing change reconnect defaults on and respects explicit disable") {
    Config absent;
    CHECK(reconnect_unmarked_flows_on_routing_change_enabled(absent));

    Config null_value;
    null_value.daemon = DaemonConfig{};
    null_value.daemon->reconnect_unmarked_flows_on_routing_change =
        std::nullopt;
    CHECK(reconnect_unmarked_flows_on_routing_change_enabled(null_value));

    Config enabled = null_value;
    enabled.daemon->reconnect_unmarked_flows_on_routing_change = true;
    CHECK(reconnect_unmarked_flows_on_routing_change_enabled(enabled));

    Config disabled = null_value;
    disabled.daemon->reconnect_unmarked_flows_on_routing_change = false;
    CHECK_FALSE(reconnect_unmarked_flows_on_routing_change_enabled(disabled));
}

TEST_CASE(
    "continuous reconnect observes only active destination-only mark lists") {
    RuleState active_mark;
    active_mark.rule_index = 0U;
    active_mark.action_type = RuleActionType::Mark;
    active_mark.fwmark = 0x00010000U;
    active_mark.list_names = {"whatsapp", "shared"};
    active_mark.criteria.dst_set_name = "kpbr4_whatsapp";

    RuleState unused_mark = active_mark;
    unused_mark.rule_index = 1U;
    unused_mark.list_names = {"configured-but-not-selected"};

    const auto active = active_destination_only_reconnect_list_names(
        {"whatsapp", "selected-but-unused"},
        {active_mark, unused_mark});

    CHECK(active == std::set<std::string>{"whatsapp"});
}

TEST_CASE(
    "continuous reconnect excludes non-mark and scoped routing rules") {
    RuleState eligible;
    eligible.rule_index = 0U;
    eligible.action_type = RuleActionType::Mark;
    eligible.fwmark = 0x00010000U;
    eligible.list_names = {"eligible"};
    eligible.criteria.dst_set_name = "kpbr4_eligible";

    RuleState pass = eligible;
    pass.rule_index = 1U;
    pass.action_type = RuleActionType::Pass;
    pass.list_names = {"pass"};

    RuleState skip = eligible;
    skip.rule_index = 2U;
    skip.action_type = RuleActionType::Skip;
    skip.list_names = {"skip"};

    RuleState drop = eligible;
    drop.rule_index = 3U;
    drop.action_type = RuleActionType::Drop;
    drop.list_names = {"drop"};

    RuleState source_scoped = eligible;
    source_scoped.rule_index = 4U;
    source_scoped.list_names = {"source-scoped"};
    source_scoped.criteria.src_addr = {"192.168.1.44/32"};

    RuleState protocol_scoped = eligible;
    protocol_scoped.rule_index = 5U;
    protocol_scoped.list_names = {"protocol-scoped"};
    protocol_scoped.criteria.proto = L4Proto::Tcp;

    RuleState unrealized_mark = eligible;
    unrealized_mark.rule_index = 6U;
    unrealized_mark.list_names = {"zero-mark"};
    unrealized_mark.fwmark = 0U;

    const auto active = active_destination_only_reconnect_list_names(
        {"eligible",
         "pass",
         "skip",
         "drop",
         "source-scoped",
         "protocol-scoped",
         "zero-mark"},
        {eligible,
         pass,
         skip,
         drop,
         source_scoped,
         protocol_scoped,
         unrealized_mark});

    CHECK(active == std::set<std::string>{"eligible"});
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

TEST_CASE("runtime firewall retry merges owned recovery before coalescing") {
    RuntimeFirewallRetryCoordinator coordinator;
    FakeRuntimeFirewallRetryScheduler scheduler;
    const auto schedule = [&scheduler](
                              const RuntimeFirewallRetryPlan& plan,
                              auto callback) {
        return scheduler.schedule(plan, std::move(callback));
    };

    const auto initial = coordinator.begin_attempt(0, {});
    REQUIRE_FALSE(initial.coalesced);
    const auto retry = coordinator.schedule(
        0,
        /*runtime_generation=*/17,
        /*bounded_retry_count=*/6,
        initial.snat_recovery,
        schedule,
        [](std::uint64_t) { return true; },
        [](std::size_t, OwnedSnatRecovery) {});
    REQUIRE(retry.schedule);
    REQUIRE(coordinator.retry_pending());

    const auto coalesced = coordinator.begin_attempt(
        0,
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/true});
    CHECK(coalesced.coalesced);
    CHECK(coalesced.snat_recovery.requested);
    CHECK(coalesced.snat_recovery.missing_observed);
    CHECK(coordinator.owned_snat_recovery_pending());
}

TEST_CASE("stale runtime firewall retry releases its slot and skips the attempt") {
    RuntimeFirewallRetryCoordinator coordinator;
    FakeRuntimeFirewallRetryScheduler scheduler;
    std::size_t attempt_calls = 0;
    std::uint64_t checked_generation = 0;
    const auto admission = coordinator.begin_attempt(
        0,
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/false});
    const auto retry = coordinator.schedule(
        0,
        /*runtime_generation=*/17,
        /*bounded_retry_count=*/6,
        admission.snat_recovery,
        [&scheduler](const RuntimeFirewallRetryPlan& plan, auto callback) {
            return scheduler.schedule(plan, std::move(callback));
        },
        [&](std::uint64_t expected_generation) {
            checked_generation = expected_generation;
            return false;
        },
        [&](std::size_t, OwnedSnatRecovery) { ++attempt_calls; });
    REQUIRE(retry.schedule);
    REQUIRE(scheduler.callbacks.size() == 1U);

    auto callback = scheduler.callbacks.front();
    callback();

    CHECK(checked_generation == 17U);
    CHECK_FALSE(coordinator.retry_pending());
    CHECK(attempt_calls == 0U);
    CHECK(coordinator.owned_snat_recovery_pending());
}

TEST_CASE("runtime firewall retry releases its slot before a reentrant successor") {
    RuntimeFirewallRetryCoordinator coordinator;
    FakeRuntimeFirewallRetryScheduler scheduler;
    const auto schedule = [&scheduler](
                              const RuntimeFirewallRetryPlan& plan,
                              auto callback) {
        return scheduler.schedule(plan, std::move(callback));
    };
    RuntimeFirewallRetryPlan successor;
    const auto admission = coordinator.begin_attempt(0, {});
    const auto retry = coordinator.schedule(
        0,
        /*runtime_generation=*/17,
        /*bounded_retry_count=*/6,
        admission.snat_recovery,
        schedule,
        [](std::uint64_t) { return true; },
        [&](std::size_t retry_attempt, OwnedSnatRecovery snat_recovery) {
            CHECK(retry_attempt == 1U);
            CHECK_FALSE(coordinator.retry_pending());
            successor = coordinator.schedule(
                retry_attempt,
                /*runtime_generation=*/17,
                /*bounded_retry_count=*/6,
                std::move(snat_recovery),
                schedule,
                [](std::uint64_t) { return true; },
                [](std::size_t, OwnedSnatRecovery) {});
        });
    REQUIRE(retry.schedule);
    REQUIRE(scheduler.callbacks.size() == 1U);

    auto callback = scheduler.callbacks.front();
    callback();

    CHECK(successor.schedule);
    CHECK(successor.next_attempt == 2U);
    CHECK(coordinator.retry_pending());
    CHECK(scheduler.callbacks.size() == 2U);
}

TEST_CASE(
    "resolver recovery remains gated after the firewall retry slot is exhausted") {
    RuntimeFirewallRetryCoordinator firewall_retry;
    ResolverAfterFirewallRecoveryGate resolver_gate;

    resolver_gate.wait_for(/*runtime_generation=*/17);

    CHECK_FALSE(firewall_retry.retry_pending());
    CHECK(resolver_gate.waiting_for(17));
    CHECK_FALSE(resolver_gate.waiting_for(18));
    CHECK_FALSE(resolver_gate.release(18));
    CHECK(resolver_gate.waiting_for(17));
    CHECK(resolver_gate.release(17));
    CHECK_FALSE(resolver_gate.waiting_for(17));
}

TEST_CASE("runtime firewall retry exhausts generic work but keeps owned maintenance") {
    RuntimeFirewallRetryCoordinator coordinator;
    FakeRuntimeFirewallRetryScheduler scheduler;
    const auto schedule = [&scheduler](
                              const RuntimeFirewallRetryPlan& plan,
                              auto callback) {
        return scheduler.schedule(plan, std::move(callback));
    };

    const auto generic = coordinator.schedule(
        6,
        /*runtime_generation=*/17,
        /*bounded_retry_count=*/6,
        OwnedSnatRecovery{},
        schedule,
        [](std::uint64_t) { return true; },
        [](std::size_t, OwnedSnatRecovery) {});
    CHECK_FALSE(generic.schedule);
    CHECK(scheduler.callbacks.empty());

    const auto latched = coordinator.begin_attempt(
        0,
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/true});
    REQUIRE_FALSE(latched.coalesced);
    OwnedSnatRecovery callback_recovery;
    const auto owned = coordinator.schedule(
        6,
        /*runtime_generation=*/17,
        /*bounded_retry_count=*/6,
        /*snat_recovery=*/{},
        schedule,
        [](std::uint64_t) { return true; },
        [&](std::size_t, OwnedSnatRecovery recovery) {
            callback_recovery = std::move(recovery);
        });
    CHECK(owned.schedule);
    CHECK(owned.maintenance);
    CHECK(owned.next_attempt == 0U);
    CHECK(scheduler.callbacks.size() == 1U);

    auto callback = scheduler.callbacks.front();
    callback();
    CHECK(callback_recovery.requested);
    CHECK(callback_recovery.missing_observed);
}

TEST_CASE("route unavailability schedules runtime retry only for owned SNAT") {
    RuntimeFirewallRetryCoordinator coordinator;

    const auto generic = coordinator.begin_attempt(0, {});
    coordinator.complete_attempt(
        /*succeeded=*/false, generic.snat_recovery);
    CHECK_FALSE(coordinator.route_unavailable_retry_required());

    const auto owned = coordinator.begin_attempt(
        0,
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/false});
    coordinator.complete_attempt(
        /*succeeded=*/false, owned.snat_recovery);
    CHECK(coordinator.route_unavailable_retry_required());
}

TEST_CASE("runtime firewall success clears owned recovery while failure retains it") {
    RuntimeFirewallRetryCoordinator coordinator;
    const OwnedSnatRecovery recovery{
        /*requested=*/true,
        /*missing_observed=*/true,
        OwnedConntrackCleanupSnapshot{
            /*runtime_generation=*/17,
            /*owned_mask=*/0x00ff0000U,
            /*marks=*/{0x00010000U}}};
    const auto admission = coordinator.begin_attempt(0, recovery);

    coordinator.complete_attempt(
        /*succeeded=*/false, admission.snat_recovery);
    REQUIRE(coordinator.owned_snat_recovery_pending());
    CHECK(coordinator.pending_owned_snat_recovery().missing_observed);
    CHECK(coordinator.pending_owned_snat_recovery()
              .cleanup_snapshot.has_value());

    coordinator.complete_attempt(
        /*succeeded=*/true,
        coordinator.pending_owned_snat_recovery());
    CHECK_FALSE(coordinator.owned_snat_recovery_pending());
    CHECK_FALSE(coordinator.pending_owned_snat_recovery().missing_observed);
    CHECK_FALSE(coordinator.pending_owned_snat_recovery()
                    .cleanup_snapshot.has_value());
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

TEST_CASE("periodic Meta UDP 443 repair is drift and FastNAT aware") {
    using S = OwnedForwardUdpRejectState;
    CHECK(should_run_periodic_forward_udp_reject_repair(
        true, false, false, true, true, S::missing));
    CHECK(should_run_periodic_forward_udp_reject_repair(
        true, false, false, false, true, S::stale));
    CHECK(should_run_periodic_forward_udp_reject_repair(
        true, false, false, true, false, S::healthy));
    CHECK_FALSE(should_run_periodic_forward_udp_reject_repair(
        true, false, false, false, true, S::healthy));
    CHECK_FALSE(should_run_periodic_forward_udp_reject_repair(
        true, false, false, true, true, S::unknown));
    CHECK_FALSE(should_run_periodic_forward_udp_reject_repair(
        false, false, false, true, false, S::missing));
    CHECK_FALSE(should_run_periodic_forward_udp_reject_repair(
        true, true, false, true, false, S::missing));
    CHECK_FALSE(should_run_periodic_forward_udp_reject_repair(
        true, false, true, true, false, S::missing));
}

TEST_CASE("Meta UDP 443 deferred cleanup is nonzero and rollback fenced") {
    CHECK(meta_udp443_initial_cleanup_delay().count() > 0);
    CHECK(meta_udp443_cleanup_authority_matches(7U, 7U, 11U, 11U));
    CHECK_FALSE(meta_udp443_cleanup_authority_matches(7U, 8U, 11U, 11U));
    CHECK_FALSE(meta_udp443_cleanup_authority_matches(7U, 7U, 11U, 12U));
    CHECK(should_resume_pending_meta_udp443_cleanup(
        true,
        true,
        OwnedForwardUdpRejectState::healthy,
        -1,
        true));
    CHECK_FALSE(should_resume_pending_meta_udp443_cleanup(
        true,
        true,
        OwnedForwardUdpRejectState::healthy,
        42,
        true));
    CHECK_FALSE(should_resume_pending_meta_udp443_cleanup(
        true,
        false,
        OwnedForwardUdpRejectState::healthy,
        -1,
        true));
    CHECK_FALSE(should_resume_pending_meta_udp443_cleanup(
        true,
        true,
        OwnedForwardUdpRejectState::missing,
        -1,
        true));
    CHECK_FALSE(should_resume_pending_meta_udp443_cleanup(
        true,
        true,
        OwnedForwardUdpRejectState::healthy,
        -1,
        true,
        true));
    CHECK(should_restore_pending_meta_udp443_cleanup_after_apply_failure(
        true, 17U, 17U, false));
    CHECK_FALSE(
        should_restore_pending_meta_udp443_cleanup_after_apply_failure(
            true, 16U, 17U, false));
    CHECK_FALSE(
        should_restore_pending_meta_udp443_cleanup_after_apply_failure(
            false, 17U, 17U, false));
    CHECK_FALSE(
        should_restore_pending_meta_udp443_cleanup_after_apply_failure(
            true, 17U, 17U, true));
    CHECK(should_retain_candidate_meta_udp443_cleanup_after_apply_failure(
        true, true));
    CHECK_FALSE(
        should_retain_candidate_meta_udp443_cleanup_after_apply_failure(
            false, true));
    CHECK_FALSE(
        should_retain_candidate_meta_udp443_cleanup_after_apply_failure(
            true, false));

    CHECK(netfilter_refresh_callback_is_current(9U, 9U));
    CHECK_FALSE(netfilter_refresh_callback_is_current(8U, 9U));
    CHECK(meta_udp443_failed_completion_matches_pending(12U, 12U));
    CHECK_FALSE(meta_udp443_failed_completion_matches_pending(11U, 12U));
    CHECK_FALSE(meta_udp443_failed_completion_matches_pending(0U, 0U));
    CHECK(newest_meta_udp443_failed_completion_serial(11U, 12U) == 12U);
    CHECK(newest_meta_udp443_failed_completion_serial(13U, 12U) == 13U);
    std::atomic<std::uint64_t> failed_completion_serial{13U};
    publish_newest_meta_udp443_failed_completion_serial(
        failed_completion_serial, 12U);
    CHECK(failed_completion_serial.load() == 13U);
    publish_newest_meta_udp443_failed_completion_serial(
        failed_completion_serial, 14U);
    CHECK(failed_completion_serial.load() == 14U);
}

TEST_CASE("manual single-flight stays active through its coalesced trailing run") {
    CoalescedManualSingleFlightGate gate;

    const auto periodic = gate.request(/*manual=*/false);
    CHECK(periodic.launch);
    CHECK_FALSE(periodic.manual_accepted);

    const auto manual = gate.request(/*manual=*/true);
    CHECK_FALSE(manual.launch);
    CHECK(manual.manual_accepted);
    CHECK(gate.manual_inflight());

    // More timer ticks cannot build an unbounded queue, and another click is
    // rejected until the accepted manual observation actually completes.
    CHECK_FALSE(gate.request(/*manual=*/false).launch);
    const auto duplicate_manual = gate.request(/*manual=*/true);
    CHECK_FALSE(duplicate_manual.launch);
    CHECK_FALSE(duplicate_manual.manual_accepted);

    const auto first_completion = gate.complete();
    CHECK(first_completion.launch_trailing);
    CHECK_FALSE(first_completion.manual_completed);
    CHECK(gate.manual_inflight());

    const auto final_completion = gate.complete();
    CHECK_FALSE(final_completion.launch_trailing);
    CHECK(final_completion.manual_completed);
    CHECK_FALSE(gate.manual_inflight());
}

TEST_CASE("aborting a manual single-flight releases its admission") {
    CoalescedManualSingleFlightGate gate;
    const auto periodic = gate.request(/*manual=*/false);
    REQUIRE(periodic.launch);

    // This is the exception-sensitive handoff shape: the manual request has
    // been accepted as the one trailing round, but the active producer fails
    // before it can transfer ownership to its executor/control queue.
    const auto admission = gate.request(/*manual=*/true);
    REQUIRE_FALSE(admission.launch);
    REQUIRE(admission.manual_accepted);

    CHECK(gate.abort());
    CHECK_FALSE(gate.manual_inflight());

    const auto retry = gate.request(/*manual=*/true);
    CHECK(retry.launch);
    CHECK(retry.manual_accepted);
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

TEST_CASE("destination retirement plans only selectors newly governed by changed rules") {
    RuleState direct;
    direct.rule_index = 0U;
    direct.action_type = RuleActionType::Pass;
    direct.list_names = {"meta"};

    RuleState tunneled = direct;
    tunneled.action_type = RuleActionType::Mark;
    tunneled.outbound_tag = "awg";
    tunneled.fwmark = 0x00010000U;

    const auto changed = plan_conntrack_destination_retirement(
        {direct}, {tunneled});
    CHECK(changed.current_list_names == std::set<std::string>{"meta"});
    CHECK(changed.current_destination_selectors.empty());

    RuleState direct_address;
    direct_address.rule_index = 0U;
    direct_address.action_type = RuleActionType::Pass;
    direct_address.criteria.dst_addr = {"31.13.64.0/18"};
    RuleState tunneled_address = direct_address;
    tunneled_address.action_type = RuleActionType::Mark;
    tunneled_address.outbound_tag = "awg";
    tunneled_address.fwmark = 0x00010000U;
    const auto address_changed = plan_conntrack_destination_retirement(
        {direct_address}, {tunneled_address});
    CHECK(address_changed.current_destination_selectors ==
          std::vector<std::string>{"31.13.64.0/18"});

    const auto unchanged = plan_conntrack_destination_retirement(
        {tunneled}, {tunneled});
    CHECK(unchanged.current_list_names.empty());
    CHECK(unchanged.current_destination_selectors.empty());

    const auto content_changed = plan_conntrack_destination_retirement(
        {tunneled}, {tunneled}, {"meta"});
    CHECK(content_changed.current_list_names ==
          std::set<std::string>{"meta"});

    const auto removed = plan_conntrack_destination_retirement(
        {tunneled}, {});
    CHECK(removed.current_list_names.empty());
    CHECK(removed.current_destination_selectors.empty());
}

TEST_CASE("strong reconnect targets only selected list policy changes") {
    RuleState previous;
    previous.rule_index = 0U;
    previous.action_type = RuleActionType::Mark;
    previous.list_names = {"whatsapp_ip"};
    previous.outbound_tag = "awg";
    previous.fwmark = 0x00010000U;

    auto current = previous;
    current.outbound_tag = "vless";
    current.fwmark = 0x00020000U;

    CHECK(
        plan_conntrack_owned_destination_reconnect(
            {previous},
            {current},
            {"whatsapp_ip"}) ==
        std::set<std::string>{"whatsapp_ip"});
    CHECK(
        plan_conntrack_owned_destination_reconnect(
            {previous},
            {current},
            {"telegram_ip"})
            .empty());

    current.action_type = RuleActionType::Pass;
    current.fwmark = 0U;
    CHECK(
        plan_conntrack_owned_destination_reconnect(
            {previous},
            {current},
            {"whatsapp_ip"}) ==
        std::set<std::string>{"whatsapp_ip"});
}

TEST_CASE("strong reconnect reacts to content changes and first enablement") {
    RuleState current;
    current.rule_index = 0U;
    current.action_type = RuleActionType::Mark;
    current.list_names = {"whatsapp_ip"};
    current.outbound_tag = "awg";
    current.fwmark = 0x00010000U;

    CHECK(
        plan_conntrack_owned_destination_reconnect(
            {current},
            {current},
            {"whatsapp_ip"},
            {"whatsapp_ip"}) ==
        std::set<std::string>{"whatsapp_ip"});
    CHECK(
        plan_conntrack_owned_destination_reconnect(
            {current},
            {current},
            {"whatsapp_ip"},
            {},
            {"whatsapp_ip"}) ==
        std::set<std::string>{"whatsapp_ip"});
    CHECK(
        plan_conntrack_owned_destination_reconnect(
            {current},
            {current},
            {"whatsapp_ip"})
            .empty());
}

TEST_CASE("strong reconnect catalogue recommendation remains opt-out") {
    Config automatic;
    ListConfig whatsapp;
    whatsapp.catalog_identity =
        "0475c85d06ea258343fdda22ee85bfd0a3e1fb2fa88751ab39ee0ffb64efedbe";
    automatic.lists = std::map<std::string, ListConfig>{
        {"friendly_whatsapp_ips", whatsapp}};
    CHECK(
        reconnect_owned_flows_on_routing_change_list_names(automatic) ==
        std::set<std::string>{"friendly_whatsapp_ips"});

    automatic.daemon = DaemonConfig{};
    automatic.daemon
        ->reconnect_owned_flows_on_routing_change_lists =
        std::vector<std::string>{};
    CHECK(
        reconnect_owned_flows_on_routing_change_list_names(automatic)
            .empty());
}

TEST_CASE("strong reconnect coverage merges old and new list addresses") {
    AppliedListContentState previous;
    previous.static_destinations = {
        {"whatsapp_ip", {"31.13.64.0/18"}}};
    AppliedListContentState current;
    current.static_destinations = {
        {"whatsapp_ip", {"57.144.0.0/14"}}};
    const auto plan = destination_retirement_plan_for_lists(
        {"whatsapp_ip"});
    const auto merged = merge_conntrack_destination_retirement_coverage(
        collect_conntrack_destination_retirement_coverage(plan, current),
        collect_conntrack_destination_retirement_coverage(plan, previous));
    CHECK(
        merged.destination_selectors ==
        std::vector<std::string>{"57.144.0.0/14", "31.13.64.0/18"});
}

TEST_CASE("stale-flow reconnect runs only for the committed current runtime") {
    StaleFlowReconnectRequest request;
    request.expected_runtime_generation = 17U;
    request.exact_forwarded_scope = true;
    request.normal.destination_selectors = {"31.13.64.0/18"};
    request.aggressive.destination_selectors = {"157.240.0.0/16"};

    std::vector<std::string> events;
    const auto result = run_stale_flow_reconnect_if_committed(
        RuntimeReconnectCommitState::committed,
        request,
        [&]() {
            events.push_back("active");
            return true;
        },
        [&]() {
            events.push_back("generation");
            return std::uint64_t{17U};
        },
        [&]() {
            events.push_back("prepare");
            return std::vector<std::string>{"192.168.1.1"};
        },
        [&](const std::vector<std::string>& local_addresses,
            const StaleFlowReconnectRequest& observed) {
            events.push_back("cleanup");
            CHECK(local_addresses ==
                  std::vector<std::string>{"192.168.1.1"});
            CHECK(observed.normal.destination_selectors ==
                  std::vector<std::string>{"31.13.64.0/18"});
            CHECK(observed.aggressive.destination_selectors ==
                  std::vector<std::string>{"157.240.0.0/16"});
        });

    CHECK(result == StaleFlowReconnectExecution::completed);
    const std::vector<std::string> expected{
        "active",
        "generation",
        "prepare",
        "active",
        "generation",
        "cleanup",
    };
    CHECK(events == expected);
}

TEST_CASE("failed and rolled-back applies never reconnect stale flows") {
    StaleFlowReconnectRequest request;
    request.expected_runtime_generation = 17U;
    request.exact_forwarded_scope = true;
    request.normal.destination_selectors = {"31.13.64.0/18"};

    for (const auto state : {
             RuntimeReconnectCommitState::failed,
             RuntimeReconnectCommitState::rolled_back}) {
        std::size_t callback_calls = 0U;
        const auto result = run_stale_flow_reconnect_if_committed(
            state,
            request,
            [&]() {
                ++callback_calls;
                return true;
            },
            [&]() {
                ++callback_calls;
                return std::uint64_t{17U};
            },
            [&]() {
                ++callback_calls;
                return 1;
            },
            [&](int, const StaleFlowReconnectRequest&) {
                ++callback_calls;
            });

        CHECK(result ==
              StaleFlowReconnectExecution::skipped_not_committed);
        CHECK(callback_calls == 0U);
    }
}

TEST_CASE("stale-flow reconnect rejects inactive and stale runtimes") {
    StaleFlowReconnectRequest request;
    request.expected_runtime_generation = 17U;
    request.exact_forwarded_scope = true;
    request.normal.destination_selectors = {"31.13.64.0/18"};

    std::size_t prepare_calls = 0U;
    std::size_t cleanup_calls = 0U;
    const auto inactive = run_stale_flow_reconnect_if_committed(
        RuntimeReconnectCommitState::committed,
        request,
        []() { return false; },
        []() { return std::uint64_t{17U}; },
        [&]() {
            ++prepare_calls;
            return 1;
        },
        [&](int, const StaleFlowReconnectRequest&) {
            ++cleanup_calls;
        });
    CHECK(inactive ==
          StaleFlowReconnectExecution::skipped_inactive_runtime);

    const auto stale = run_stale_flow_reconnect_if_committed(
        RuntimeReconnectCommitState::committed,
        request,
        []() { return true; },
        []() { return std::uint64_t{18U}; },
        [&]() {
            ++prepare_calls;
            return 1;
        },
        [&](int, const StaleFlowReconnectRequest&) {
            ++cleanup_calls;
        });
    CHECK(stale == StaleFlowReconnectExecution::skipped_stale_generation);
    CHECK(prepare_calls == 0U);
    CHECK(cleanup_calls == 0U);
}

TEST_CASE("stale-flow reconnect rechecks generation after scope preparation") {
    StaleFlowReconnectRequest request;
    request.expected_runtime_generation = 17U;
    request.exact_forwarded_scope = true;
    request.normal.destination_selectors = {"31.13.64.0/18"};

    std::size_t generation_checks = 0U;
    std::size_t prepare_calls = 0U;
    std::size_t cleanup_calls = 0U;
    const auto result = run_stale_flow_reconnect_if_committed(
        RuntimeReconnectCommitState::committed,
        request,
        []() { return true; },
        [&]() {
            ++generation_checks;
            return generation_checks == 1U
                ? std::uint64_t{17U}
                : std::uint64_t{18U};
        },
        [&]() {
            ++prepare_calls;
            return 1;
        },
        [&](int, const StaleFlowReconnectRequest&) {
            ++cleanup_calls;
        });

    CHECK(result ==
          StaleFlowReconnectExecution::skipped_generation_changed);
    CHECK(generation_checks == 2U);
    CHECK(prepare_calls == 1U);
    CHECK(cleanup_calls == 0U);
}

TEST_CASE("stale-flow reconnect fails closed for unsafe plans") {
    const auto execute = [](const StaleFlowReconnectRequest& request) {
        std::size_t callback_calls = 0U;
        const auto result = run_stale_flow_reconnect_if_committed(
            RuntimeReconnectCommitState::committed,
            request,
            [&]() {
                ++callback_calls;
                return true;
            },
            [&]() {
                ++callback_calls;
                return request.expected_runtime_generation;
            },
            [&]() {
                ++callback_calls;
                return 1;
            },
            [&](int, const StaleFlowReconnectRequest&) {
                ++callback_calls;
            });
        return std::pair{result, callback_calls};
    };

    StaleFlowReconnectRequest empty;
    empty.expected_runtime_generation = 17U;
    empty.exact_forwarded_scope = true;
    const auto empty_result = execute(empty);
    CHECK(empty_result.first ==
          StaleFlowReconnectExecution::skipped_empty_plan);
    CHECK(empty_result.second == 0U);

    auto inexact = empty;
    inexact.exact_forwarded_scope = false;
    inexact.normal.destination_selectors = {"31.13.64.0/18"};
    const auto inexact_result = execute(inexact);
    CHECK(inexact_result.first ==
          StaleFlowReconnectExecution::skipped_inexact_forwarded_scope);
    CHECK(inexact_result.second == 0U);

    auto global = empty;
    global.normal.destination_selectors = {" 192.0.2.1 / 0 "};
    const auto global_result = execute(global);
    CHECK(global_result.first ==
          StaleFlowReconnectExecution::skipped_global_destination_scope);
    CHECK(global_result.second == 0U);

    auto invalid_generation = empty;
    invalid_generation.expected_runtime_generation = 0U;
    invalid_generation.normal.destination_selectors = {"31.13.64.0/18"};
    const auto invalid_generation_result = execute(invalid_generation);
    CHECK(invalid_generation_result.first ==
          StaleFlowReconnectExecution::skipped_invalid_generation);
    CHECK(invalid_generation_result.second == 0U);
}

TEST_CASE("stale-flow reconnect contains preparation and cleanup failures") {
    StaleFlowReconnectRequest request;
    request.expected_runtime_generation = 17U;
    request.exact_forwarded_scope = true;
    request.normal.destination_selectors = {"31.13.64.0/18"};

    std::size_t cleanup_calls = 0U;
    const auto prepare_failed = run_stale_flow_reconnect_if_committed(
        RuntimeReconnectCommitState::committed,
        request,
        []() { return true; },
        []() { return std::uint64_t{17U}; },
        []() -> int { throw std::runtime_error("scope unavailable"); },
        [&](int, const StaleFlowReconnectRequest&) {
            ++cleanup_calls;
        });
    CHECK(prepare_failed == StaleFlowReconnectExecution::failed);
    CHECK(cleanup_calls == 0U);

    const auto cleanup_failed = run_stale_flow_reconnect_if_committed(
        RuntimeReconnectCommitState::committed,
        request,
        []() { return true; },
        []() { return std::uint64_t{17U}; },
        []() { return 1; },
        [](int, const StaleFlowReconnectRequest&) {
            throw std::runtime_error("cleanup unavailable");
        });
    CHECK(cleanup_failed == StaleFlowReconnectExecution::failed);
}

TEST_CASE("destination retirement does not treat shifted unchanged rules as new") {
    RuleState existing;
    existing.rule_index = 0U;
    existing.action_type = RuleActionType::Mark;
    existing.outbound_tag = "awg";
    existing.fwmark = 0x00010000U;
    existing.list_names = {"existing"};

    RuleState inserted = existing;
    inserted.rule_index = 0U;
    inserted.list_names = {"meta"};

    RuleState shifted = existing;
    shifted.rule_index = 1U;

    const auto plan = plan_conntrack_destination_retirement(
        {existing},
        {inserted, shifted});

    CHECK(plan.current_list_names == std::set<std::string>{"meta"});
}

TEST_CASE("destination retirement ignores negated destinations") {
    RuleState current;
    current.rule_index = 0U;
    current.action_type = RuleActionType::Mark;
    current.fwmark = 0x00010000U;
    current.criteria.dst_addr = {"31.13.64.0/18"};
    current.criteria.negate_dst_addr = true;

    const auto plan = plan_conntrack_destination_retirement({}, {current});
    CHECK(plan.current_destination_selectors.empty());
}

TEST_CASE("destination retirement rejects list and address intersections") {
    RuleState current;
    current.rule_index = 0U;
    current.action_type = RuleActionType::Mark;
    current.fwmark = 0x00010000U;
    current.list_names = {"meta"};
    current.criteria.dst_addr = {"31.13.64.0/18"};

    const auto plan = plan_conntrack_destination_retirement(
        {}, {current});

    CHECK(plan.current_list_names.empty());
    CHECK(plan.current_destination_selectors.empty());
}

TEST_CASE("destination retirement fails closed behind an earlier pass rule") {
    RuleState bypass;
    bypass.rule_index = 0U;
    bypass.action_type = RuleActionType::Pass;
    bypass.criteria.dst_addr = {"203.0.113.7/32"};

    RuleState current;
    current.rule_index = 1U;
    current.action_type = RuleActionType::Mark;
    current.fwmark = 0x00010000U;
    current.list_names = {"meta"};

    const auto plan = plan_conntrack_destination_retirement(
        {bypass}, {bypass, current});

    CHECK(plan.current_list_names.empty());
    CHECK(plan.current_destination_selectors.empty());
}

TEST_CASE("destination retirement rejects selectors conntrack cannot scope") {
    RuleState broad;
    broad.rule_index = 0U;
    broad.action_type = RuleActionType::Mark;
    broad.fwmark = 0x00010000U;
    broad.list_names = {"meta"};
    broad.criteria.dst_set_name = "kpbr_meta_v4";

    const auto require_no_cleanup = [](const RuleState& scoped) {
        const auto plan = plan_conntrack_destination_retirement(
            {}, {scoped});
        CHECK(plan.current_list_names.empty());
        CHECK(plan.current_destination_selectors.empty());
    };

    auto source_address = broad;
    source_address.criteria.src_addr = {"192.168.1.44/32"};
    require_no_cleanup(source_address);

    auto source_address_negated = broad;
    source_address_negated.criteria.src_addr = {"192.168.1.44/32"};
    source_address_negated.criteria.negate_src_addr = true;
    require_no_cleanup(source_address_negated);

    auto protocol = broad;
    protocol.criteria.proto = L4Proto::Udp;
    require_no_cleanup(protocol);

    auto source_port = broad;
    source_port.criteria.src_port = "443";
    require_no_cleanup(source_port);

    auto destination_port = broad;
    destination_port.criteria.dst_port = "443";
    require_no_cleanup(destination_port);

    auto negated_port = broad;
    negated_port.criteria.dst_port = "443";
    negated_port.criteria.negate_dst_port = true;
    require_no_cleanup(negated_port);

    auto dscp = broad;
    dscp.criteria.dscp = 46U;
    require_no_cleanup(dscp);
}

TEST_CASE("destination retirement requires a positive destination selector") {
    RuleState source_only;
    source_only.rule_index = 0U;
    source_only.action_type = RuleActionType::Mark;
    source_only.fwmark = 0x00010000U;
    source_only.criteria.src_addr = {"192.168.1.44/32"};

    const auto plan = plan_conntrack_destination_retirement(
        {}, {source_only});

    CHECK(plan.current_list_names.empty());
    CHECK(plan.current_destination_selectors.empty());
}

TEST_CASE("destination retirement does not reconnect explicit direct rules") {
    RuleState direct;
    direct.rule_index = 0;
    direct.list_names = {"direct-list"};
    direct.action_type = RuleActionType::Pass;
    direct.criteria.dst_addr = {"203.0.113.9/32"};

    const auto plan = plan_conntrack_destination_retirement(
        {}, {direct});

    CHECK(plan.current_list_names.empty());
    CHECK(plan.current_destination_selectors.empty());
}

TEST_CASE("destination retirement coverage reports domain and static limits") {
    ConntrackDestinationRetirementPlan plan;
    plan.current_list_names = {
        "domain-only", "mixed", "static", "truncated"};
    plan.current_destination_selectors = {"203.0.113.7/32"};

    AppliedListContentState content;
    content.static_destinations = {
        {"domain-only", {}},
        {"mixed", {"31.13.64.0/18"}},
        {"static", {"157.240.0.0/16"}},
        {"truncated", {"169.44.0.0/16"}},
    };
    content.domain_entry_lists = {"domain-only", "mixed"};
    content.truncated_static_destination_lists = {"truncated"};

    const auto coverage =
        collect_conntrack_destination_retirement_coverage(plan, content);

    const std::vector<std::string> expected_selectors{
        "203.0.113.7/32",
        "31.13.64.0/18",
        "157.240.0.0/16",
        "169.44.0.0/16"};
    const std::set<std::string> expected_domain_lists{
        "domain-only", "mixed"};
    const std::set<std::string> expected_truncated_lists{"truncated"};
    CHECK(coverage.destination_selectors == expected_selectors);
    CHECK(coverage.domain_backed_list_names == expected_domain_lists);
    CHECK(coverage.truncated_static_list_names == expected_truncated_lists);
    CHECK(coverage.partial());
}

TEST_CASE("destination retirement coverage is complete for bounded static lists") {
    ConntrackDestinationRetirementPlan plan;
    plan.current_list_names = {"static"};

    AppliedListContentState content;
    content.static_destinations = {
        {"static", {"31.13.64.0/18"}},
    };

    const auto coverage =
        collect_conntrack_destination_retirement_coverage(plan, content);

    CHECK(coverage.destination_selectors ==
          std::vector<std::string>{"31.13.64.0/18"});
    CHECK_FALSE(coverage.partial());
}
