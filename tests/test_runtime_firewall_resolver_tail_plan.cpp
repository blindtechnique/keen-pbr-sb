#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_resolver_tail_plan.hpp"

#include <array>
#include <cstdint>

namespace keen_pbr3 {
namespace {

RuntimeFirewallStartResolverTailFacts verified_start_facts(
    bool cold_boot) noexcept {
    RuntimeFirewallStartResolverTailFacts facts;
    facts.cold_boot = cold_boot;
    facts.worker_succeeded = true;
    facts.worker_input_available = true;
    facts.worker_result_available = true;
    facts.route_preparation_required = true;
    facts.worker_route_mutation_applied = true;
    facts.requested_route_epoch = 11U;
    facts.current_route_epoch = 11U;
    facts.operation_runtime_generation = 7U;
    facts.current_runtime_generation = 7U;
    facts.route_checkpoint_published = true;
    facts.route_checkpoint_mutation_applied = true;
    facts.core_committed = true;
    facts.commit_ambiguous = false;
    return facts;
}

} // namespace

TEST_CASE("ordinary START requires committed unambiguous firewall core") {
    auto facts = verified_start_facts(false);
    auto plan = plan_runtime_firewall_start_resolver_tail(facts);

    CHECK_FALSE(plan.route_mutation_acknowledged);
    CHECK(plan.exact_route_checkpoint_verified);
    CHECK(plan.route_firewall_proven);
    CHECK(plan.begin_lifecycle_resolver);
    CHECK_FALSE(plan.downgrade_nominal_worker_success);

    facts.core_committed = false;
    plan = plan_runtime_firewall_start_resolver_tail(facts);
    CHECK_FALSE(plan.route_firewall_proven);
    CHECK_FALSE(plan.begin_lifecycle_resolver);
    CHECK(plan.downgrade_nominal_worker_success);

    facts.core_committed = true;
    facts.commit_ambiguous = true;
    plan = plan_runtime_firewall_start_resolver_tail(facts);
    CHECK_FALSE(plan.route_firewall_proven);
    CHECK(plan.downgrade_nominal_worker_success);
}

TEST_CASE("cold boot requires the exact route and generation checkpoint") {
    const auto verified = verified_start_facts(true);
    const auto accepted =
        plan_runtime_firewall_start_resolver_tail(verified);
    CHECK(accepted.route_mutation_acknowledged);
    CHECK(accepted.exact_route_checkpoint_verified);
    CHECK(accepted.route_firewall_proven);
    CHECK(accepted.begin_lifecycle_resolver);

    using Flag = bool RuntimeFirewallStartResolverTailFacts::*;
    constexpr std::array<Flag, 6> required_flags{
        &RuntimeFirewallStartResolverTailFacts::worker_input_available,
        &RuntimeFirewallStartResolverTailFacts::worker_result_available,
        &RuntimeFirewallStartResolverTailFacts::route_preparation_required,
        &RuntimeFirewallStartResolverTailFacts::worker_route_mutation_applied,
        &RuntimeFirewallStartResolverTailFacts::route_checkpoint_published,
        &RuntimeFirewallStartResolverTailFacts::
            route_checkpoint_mutation_applied,
    };
    for (const auto flag : required_flags) {
        auto missing = verified;
        missing.*flag = false;
        const auto plan =
            plan_runtime_firewall_start_resolver_tail(missing);
        CHECK_FALSE(plan.exact_route_checkpoint_verified);
        CHECK_FALSE(plan.begin_lifecycle_resolver);
        CHECK(plan.downgrade_nominal_worker_success);
    }

    auto zero_epoch = verified;
    zero_epoch.requested_route_epoch = 0U;
    CHECK_FALSE(plan_runtime_firewall_start_resolver_tail(zero_epoch)
                    .exact_route_checkpoint_verified);

    auto stale_route = verified;
    stale_route.current_route_epoch = 12U;
    CHECK_FALSE(plan_runtime_firewall_start_resolver_tail(stale_route)
                    .exact_route_checkpoint_verified);

    auto stale_generation = verified;
    stale_generation.current_runtime_generation = 8U;
    CHECK_FALSE(plan_runtime_firewall_start_resolver_tail(stale_generation)
                    .exact_route_checkpoint_verified);
}

TEST_CASE("an existing worker failure is not classified as a new downgrade") {
    auto facts = verified_start_facts(true);
    facts.worker_succeeded = false;
    facts.core_committed = false;
    const auto plan = plan_runtime_firewall_start_resolver_tail(facts);

    CHECK_FALSE(plan.begin_lifecycle_resolver);
    CHECK_FALSE(plan.downgrade_nominal_worker_success);
}

TEST_CASE("non-START plan preserves the existing initial verification policy") {
    RuntimeFirewallNonStartResolverTailFacts background;
    auto plan = plan_runtime_firewall_non_start_resolver_tail(background);
    CHECK(plan.initially_verified);
    CHECK_FALSE(plan.publish_resolver_generation);
    CHECK(plan.action == RuntimeFirewallResolverTailAction::no_stream);

    RuntimeFirewallNonStartResolverTailFacts clean_restart;
    clean_restart.foreground_lifecycle = true;
    clean_restart.restart_lifecycle = true;
    plan = plan_runtime_firewall_non_start_resolver_tail(clean_restart);
    CHECK(plan.initially_verified);
    CHECK(plan.action == RuntimeFirewallResolverTailAction::no_stream);

    auto other_foreground = clean_restart;
    other_foreground.restart_lifecycle = false;
    plan = plan_runtime_firewall_non_start_resolver_tail(other_foreground);
    CHECK_FALSE(plan.initially_verified);
    CHECK(plan.action == RuntimeFirewallResolverTailAction::no_stream);
}

TEST_CASE("foreground refresh publishes generation then starts lifecycle stream") {
    RuntimeFirewallNonStartResolverTailFacts facts;
    facts.foreground_lifecycle = true;
    facts.restart_lifecycle = true;
    facts.resolver_refresh_required = true;
    const auto plan = plan_runtime_firewall_non_start_resolver_tail(facts);

    CHECK_FALSE(plan.initially_verified);
    CHECK(plan.publish_resolver_generation);
    CHECK(plan.cancel_existing_reload_retry);
    CHECK(
        plan.action == RuntimeFirewallResolverTailAction::
            foreground_lifecycle_stream);
}

TEST_CASE("background refresh chooses existing-stream retry or direct stream") {
    RuntimeFirewallNonStartResolverTailFacts facts;
    facts.resolver_refresh_required = true;
    facts.resolver_stream_in_flight = true;
    auto plan = plan_runtime_firewall_non_start_resolver_tail(facts);
    CHECK(plan.initially_verified);
    CHECK(plan.publish_resolver_generation);
    CHECK(plan.cancel_existing_reload_retry);
    CHECK(
        plan.action == RuntimeFirewallResolverTailAction::
            background_existing_stream_retry);

    facts.resolver_generation_published = true;
    facts.resolver_stream_in_flight = false;
    plan = plan_runtime_firewall_non_start_resolver_tail(facts);
    CHECK_FALSE(plan.publish_resolver_generation);
    CHECK(
        plan.action == RuntimeFirewallResolverTailAction::
            background_direct_stream);
}

TEST_CASE("firewall gating blocks only foreground lifecycle as a failure") {
    RuntimeFirewallNonStartResolverTailFacts facts;
    facts.foreground_lifecycle = true;
    facts.restart_lifecycle = true;
    facts.resolver_refresh_required = true;
    facts.resolver_waits_for_firewall = true;
    auto plan = plan_runtime_firewall_non_start_resolver_tail(facts);

    CHECK_FALSE(plan.initially_verified);
    CHECK(plan.publish_resolver_generation);
    CHECK_FALSE(plan.cancel_existing_reload_retry);
    CHECK(
        plan.action == RuntimeFirewallResolverTailAction::
            foreground_gated_failure);

    facts.foreground_lifecycle = false;
    facts.restart_lifecycle = false;
    plan = plan_runtime_firewall_non_start_resolver_tail(facts);
    CHECK(plan.initially_verified);
    CHECK(plan.publish_resolver_generation);
    CHECK_FALSE(plan.cancel_existing_reload_retry);
    CHECK(plan.action == RuntimeFirewallResolverTailAction::no_stream);
}

TEST_CASE("foreground firewall gate remains visible without a refresh flag") {
    RuntimeFirewallNonStartResolverTailFacts facts;
    facts.foreground_lifecycle = true;
    facts.restart_lifecycle = true;
    facts.resolver_waits_for_firewall = true;
    const auto plan = plan_runtime_firewall_non_start_resolver_tail(facts);

    CHECK_FALSE(plan.initially_verified);
    CHECK_FALSE(plan.publish_resolver_generation);
    CHECK_FALSE(plan.cancel_existing_reload_retry);
    CHECK(
        plan.action == RuntimeFirewallResolverTailAction::
            foreground_gated_failure);
}

} // namespace keen_pbr3
