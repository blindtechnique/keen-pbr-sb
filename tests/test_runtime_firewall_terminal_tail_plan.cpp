#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_terminal_tail_plan.hpp"

#include <type_traits>
#include <utility>

namespace keen_pbr3 {

static_assert(noexcept(plan_runtime_firewall_terminal_tail(
    std::declval<const RuntimeFirewallTerminalTailFacts&>())));
static_assert(std::is_nothrow_copy_constructible_v<
              RuntimeFirewallTerminalTailPlan>);

namespace {

RuntimeFirewallTerminalTailFacts verified_start_facts() {
    RuntimeFirewallTerminalTailFacts facts;
    facts.lifecycle_start = true;
    facts.worker_succeeded = true;
    facts.route_epoch_current = true;
    facts.lifecycle_resolver_verified = true;
    facts.start_candidate_published = true;
    facts.core_published = true;
    return facts;
}

} // namespace

TEST_CASE("terminal tail classifies background outcomes without START policy") {
    RuntimeFirewallTerminalTailFacts facts;

    auto plan = plan_runtime_firewall_terminal_tail(facts);
    CHECK(plan.dispatch ==
          RuntimeFirewallTerminalTailDispatch::background_failure);
    CHECK_FALSE(plan.downgrade_stale_start_success);
    CHECK(plan.successor ==
          RuntimeFirewallTerminalTailSuccessor::preserve);

    facts.worker_succeeded = true;
    plan = plan_runtime_firewall_terminal_tail(facts);
    CHECK(plan.dispatch ==
          RuntimeFirewallTerminalTailDispatch::background_success);
    CHECK(plan.worker_succeeded_after_route_fence);
}

TEST_CASE("verified START requires every ordinary publication proof") {
    auto facts = verified_start_facts();
    CHECK(plan_runtime_firewall_terminal_tail(facts).verified_start);

    facts.lifecycle_resolver_verified = false;
    CHECK_FALSE(plan_runtime_firewall_terminal_tail(facts).verified_start);
    facts.lifecycle_resolver_verified = true;

    facts.start_candidate_published = false;
    CHECK_FALSE(plan_runtime_firewall_terminal_tail(facts).verified_start);
    facts.start_candidate_published = true;

    facts.core_published = false;
    CHECK_FALSE(plan_runtime_firewall_terminal_tail(facts).verified_start);
    facts.core_published = true;

    facts.worker_succeeded = false;
    CHECK_FALSE(plan_runtime_firewall_terminal_tail(facts).verified_start);
}

TEST_CASE("cold boot START does not require a separately published core") {
    auto facts = verified_start_facts();
    facts.lifecycle_cold_boot = true;
    facts.core_published = false;

    const auto plan = plan_runtime_firewall_terminal_tail(facts);
    CHECK(plan.verified_start);
    CHECK(plan.dispatch ==
          RuntimeFirewallTerminalTailDispatch::start_verified);
}

TEST_CASE("stale ordinary START success consumes the existing retry policy") {
    auto facts = verified_start_facts();
    facts.route_epoch_current = false;
    facts.ordinary_start_retry_available = true;

    const auto plan = plan_runtime_firewall_terminal_tail(facts);
    CHECK(plan.downgrade_stale_start_success);
    CHECK_FALSE(plan.worker_succeeded_after_route_fence);
    CHECK(plan.successor ==
          RuntimeFirewallTerminalTailSuccessor::reschedule_retry);
    CHECK(plan.force_successor);
    CHECK(plan.worker_failure_transient);
    CHECK(plan.successor_pending_after_route_fence);
    CHECK(plan.dispatch ==
          RuntimeFirewallTerminalTailDispatch::start_pending);
    CHECK(plan.worker_failure_detail ==
          "runtime route observation changed before START publication");
}

TEST_CASE("stale START clears the successor after retry exhaustion") {
    auto facts = verified_start_facts();
    facts.route_epoch_current = false;
    facts.ordinary_start_retry_available = false;
    facts.successor_pending = true;

    const auto plan = plan_runtime_firewall_terminal_tail(facts);
    CHECK(plan.successor ==
          RuntimeFirewallTerminalTailSuccessor::clear);
    CHECK_FALSE(plan.force_successor);
    CHECK_FALSE(plan.worker_failure_transient);
    CHECK_FALSE(plan.successor_pending_after_route_fence);
    CHECK(plan.dispatch ==
          RuntimeFirewallTerminalTailDispatch::start_failed);
}

TEST_CASE("cold boot never mints an ordinary stale-route successor") {
    auto facts = verified_start_facts();
    facts.lifecycle_cold_boot = true;
    facts.route_epoch_current = false;
    facts.ordinary_start_retry_available = true;

    const auto plan = plan_runtime_firewall_terminal_tail(facts);
    CHECK(plan.downgrade_stale_start_success);
    CHECK(plan.successor ==
          RuntimeFirewallTerminalTailSuccessor::clear);
    CHECK_FALSE(plan.successor_pending_after_route_fence);
    CHECK(plan.dispatch ==
          RuntimeFirewallTerminalTailDispatch::start_failed);
}

TEST_CASE("an ambiguous START terminal cannot be reported as pending") {
    auto facts = verified_start_facts();
    facts.worker_succeeded = false;
    facts.successor_pending = true;
    facts.worker_commit_ambiguous = true;

    const auto plan = plan_runtime_firewall_terminal_tail(facts);
    CHECK_FALSE(plan.verified_start);
    CHECK(plan.successor_pending_after_route_fence);
    CHECK(plan.dispatch ==
          RuntimeFirewallTerminalTailDispatch::start_failed);
}

TEST_CASE("a non-ambiguous existing successor remains pending") {
    auto facts = verified_start_facts();
    facts.worker_succeeded = false;
    facts.successor_pending = true;

    const auto plan = plan_runtime_firewall_terminal_tail(facts);
    CHECK(plan.successor ==
          RuntimeFirewallTerminalTailSuccessor::preserve);
    CHECK(plan.successor_pending_after_route_fence);
    CHECK(plan.dispatch ==
          RuntimeFirewallTerminalTailDispatch::start_pending);
}

} // namespace keen_pbr3
