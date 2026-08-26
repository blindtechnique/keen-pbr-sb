#include <doctest/doctest.h>

#include "daemon/runtime_firewall_immediate_completion.hpp"

#include <chrono>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

const PeriodicTaskMetricsSnapshot& only_metric(
    const PeriodicTaskMetricsRegistry& registry,
    std::vector<PeriodicTaskMetricsSnapshot>& retained) {
    retained = registry.snapshot();
    REQUIRE(retained.size() == 1U);
    return retained.front();
}

} // namespace

TEST_CASE("runtime firewall immediate URLTEST completion policy is exact") {
    const RuntimeFirewallImmediateCompletionSpec spec{
        RuntimeFirewallImmediateIntentKind::periodic_urltest_recovery,
        false,
        false};
    const auto success = plan_runtime_firewall_immediate_completion(
        spec,
        RuntimeFirewallImmediateTerminalOutcome::verified_success);
    CHECK(success.metric == RuntimeFirewallImmediateMetricAction::success);
    CHECK(success.metric_detail.empty());
    CHECK_FALSE(success.claim_broad_urltest_probe);

    const auto failure = plan_runtime_firewall_immediate_completion(
        spec,
        RuntimeFirewallImmediateTerminalOutcome::not_verified);
    CHECK(failure.metric == RuntimeFirewallImmediateMetricAction::failure);
    CHECK(failure.metric_detail ==
          "URLTEST firewall recovery did not converge");
    CHECK_FALSE(failure.claim_broad_urltest_probe);
}

TEST_CASE("runtime firewall immediate owned completion policy is exact") {
    const RuntimeFirewallImmediateCompletionSpec spec{
        RuntimeFirewallImmediateIntentKind::
            periodic_owned_firewall_repair,
        false,
        false};
    const auto success = plan_runtime_firewall_immediate_completion(
        spec,
        RuntimeFirewallImmediateTerminalOutcome::verified_success);
    CHECK(success.metric == RuntimeFirewallImmediateMetricAction::success);

    const auto failure = plan_runtime_firewall_immediate_completion(
        spec,
        RuntimeFirewallImmediateTerminalOutcome::not_verified);
    CHECK(failure.metric == RuntimeFirewallImmediateMetricAction::failure);
    CHECK(failure.metric_detail == "owned SNAT repair did not converge");

    const auto shutdown = plan_runtime_firewall_immediate_completion(
        spec,
        RuntimeFirewallImmediateTerminalOutcome::shutdown);
    CHECK(shutdown.metric == RuntimeFirewallImmediateMetricAction::abandon);
    CHECK(shutdown.metric_detail == "runtime firewall shutdown");
}

TEST_CASE("runtime firewall immediate broad probe policy requires exact proof") {
    for (const auto outcome : {
             RuntimeFirewallImmediateTerminalOutcome::verified_success,
             RuntimeFirewallImmediateTerminalOutcome::not_verified,
             RuntimeFirewallImmediateTerminalOutcome::shutdown}) {
        for (const bool full : {false, true}) {
            for (const bool targeted : {false, true}) {
                const auto plan =
                    plan_runtime_firewall_immediate_completion(
                        RuntimeFirewallImmediateCompletionSpec{
                            RuntimeFirewallImmediateIntentKind::
                                netfilter_refresh,
                            full,
                            targeted},
                        outcome);
                CHECK(plan.claim_broad_urltest_probe ==
                      (outcome == RuntimeFirewallImmediateTerminalOutcome::
                                      verified_success &&
                       full && !targeted));
                CHECK(plan.metric ==
                      RuntimeFirewallImmediateMetricAction::none);
            }
        }
    }
}

TEST_CASE("runtime firewall immediate success metric settles exactly once") {
    PeriodicTaskMetricsRegistry registry{{"owned-snat-health"}};
    auto intent =
        RuntimeFirewallImmediateCompletionIntent::periodic_owned_firewall(
            registry.begin("owned-snat-health"));
    REQUIRE(intent.pending());

    const auto first = intent.settle(
        RuntimeFirewallImmediateTerminalOutcome::verified_success);
    CHECK(first.status ==
          RuntimeFirewallImmediateCompletionIntent::SettleStatus::consumed);
    CHECK_FALSE(first.broad_urltest_probe_claimed);
    CHECK_FALSE(intent.pending());
    const auto second = intent.settle(
        RuntimeFirewallImmediateTerminalOutcome::verified_success);
    CHECK(second.status ==
          RuntimeFirewallImmediateCompletionIntent::SettleStatus::
              already_consumed);

    std::vector<PeriodicTaskMetricsSnapshot> metrics;
    const auto& snapshot = only_metric(registry, metrics);
    CHECK(snapshot.runs == 1U);
    CHECK(snapshot.success == 1U);
    CHECK(snapshot.failure == 0U);
    CHECK(snapshot.in_flight == 0U);
}

TEST_CASE("runtime firewall immediate failure metric settles exactly once") {
    PeriodicTaskMetricsRegistry registry{{"owned-snat-health"}};
    auto intent =
        RuntimeFirewallImmediateCompletionIntent::periodic_urltest(
            registry.begin("owned-snat-health"));

    CHECK(intent.settle(
              RuntimeFirewallImmediateTerminalOutcome::not_verified)
              .status ==
          RuntimeFirewallImmediateCompletionIntent::SettleStatus::consumed);
    CHECK(intent.settle(
              RuntimeFirewallImmediateTerminalOutcome::not_verified)
              .status ==
          RuntimeFirewallImmediateCompletionIntent::SettleStatus::
              already_consumed);

    std::vector<PeriodicTaskMetricsSnapshot> metrics;
    const auto& snapshot = only_metric(registry, metrics);
    CHECK(snapshot.failure == 1U);
    CHECK(snapshot.success == 0U);
    CHECK(snapshot.last_error ==
          "URLTEST firewall recovery did not converge");
    CHECK(snapshot.in_flight == 0U);
}

TEST_CASE("runtime firewall immediate metric settlement retries clock fault") {
    bool throw_finish_clock_once = false;
    PeriodicTaskMetricsClocks clocks;
    clocks.steady_now = [&]() {
        if (std::exchange(throw_finish_clock_once, false)) {
            throw std::runtime_error("one-shot clock failure");
        }
        return std::chrono::steady_clock::time_point{};
    };
    clocks.wall_now_unix_ms = []() { return std::int64_t{17}; };
    PeriodicTaskMetricsRegistry registry{
        {"owned-snat-health"}, clocks};
    auto intent =
        RuntimeFirewallImmediateCompletionIntent::periodic_owned_firewall(
            registry.begin("owned-snat-health"));
    throw_finish_clock_once = true;

    const auto first = intent.settle(
        RuntimeFirewallImmediateTerminalOutcome::not_verified);
    CHECK(first.status ==
          RuntimeFirewallImmediateCompletionIntent::SettleStatus::retry);
    CHECK(intent.pending());
    const auto second = intent.settle(
        RuntimeFirewallImmediateTerminalOutcome::not_verified);
    CHECK(second.status ==
          RuntimeFirewallImmediateCompletionIntent::SettleStatus::consumed);
    CHECK_FALSE(intent.pending());

    std::vector<PeriodicTaskMetricsSnapshot> metrics;
    const auto& snapshot = only_metric(registry, metrics);
    CHECK(snapshot.failure == 1U);
    CHECK(snapshot.abandoned == 0U);
    CHECK(snapshot.in_flight == 0U);
}

TEST_CASE("runtime firewall immediate broad probe claim is exact once") {
    auto successful = RuntimeFirewallImmediateCompletionIntent::netfilter(
        /*full_refresh=*/true,
        /*targeted_recovery_pending_before_refresh=*/false);
    std::size_t probe_runs = 0U;
    const auto execute_claim = [&](const auto& settlement) noexcept {
        if (settlement.broad_urltest_probe_claimed) ++probe_runs;
    };
    execute_claim(successful.settle(
        RuntimeFirewallImmediateTerminalOutcome::verified_success));
    execute_claim(successful.settle(
        RuntimeFirewallImmediateTerminalOutcome::verified_success));
    CHECK(probe_runs == 1U);

    auto failed = RuntimeFirewallImmediateCompletionIntent::netfilter(
        true, false);
    execute_claim(failed.settle(
        RuntimeFirewallImmediateTerminalOutcome::not_verified));
    auto shutdown = RuntimeFirewallImmediateCompletionIntent::netfilter(
        true, false);
    execute_claim(shutdown.settle(
        RuntimeFirewallImmediateTerminalOutcome::shutdown));
    CHECK(probe_runs == 1U);
}

TEST_CASE("runtime firewall immediate intent is isolated from successor") {
    PeriodicTaskMetricsRegistry registry{{"owned-snat-health"}};
    auto original =
        RuntimeFirewallImmediateCompletionIntent::periodic_owned_firewall(
            registry.begin("owned-snat-health"));
    RuntimeFirewallImmediateCompletionIntent successor;
    CHECK_FALSE(successor.pending());

    CHECK(original.settle(
              RuntimeFirewallImmediateTerminalOutcome::not_verified)
              .status ==
          RuntimeFirewallImmediateCompletionIntent::SettleStatus::consumed);
    CHECK(successor.settle(
              RuntimeFirewallImmediateTerminalOutcome::verified_success)
              .status ==
          RuntimeFirewallImmediateCompletionIntent::SettleStatus::
              already_consumed);

    std::vector<PeriodicTaskMetricsSnapshot> metrics;
    const auto& snapshot = only_metric(registry, metrics);
    CHECK(snapshot.failure == 1U);
    CHECK(snapshot.success == 0U);
}
