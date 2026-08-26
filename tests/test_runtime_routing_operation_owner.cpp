#include <doctest/doctest.h>

#include "../src/routing/runtime_routing_operation_owner.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <functional>
#include <future>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

class RecordingRuntimeRoutingNetlink final
    : public RouteNetlinkOperations,
      public RuleNetlinkOperations {
public:
    RouteAddResult add_route(const RouteSpec& spec) override {
        if (before_route_add) before_route_add();
        events.push_back("route:add:" + std::to_string(spec.table));
        if (std::any_of(
                live_routes.begin(),
                live_routes.end(),
                [&](const DumpedRoute& route) {
                    return route_table_detail::route_occupies_same_slot(
                        spec, route);
                })) {
            return RouteAddResult::AlreadyPresent;
        }
        live_routes.push_back(to_live(spec));
        return RouteAddResult::Created;
    }

    void replace_route(const RouteSpec& spec) override {
        events.push_back("route:replace:" + std::to_string(spec.table));
        ++route_replace_calls;
        if (failing_route_replace_from_call &&
            route_replace_calls >= *failing_route_replace_from_call) {
            throw std::runtime_error(
                "injected route replacement failure");
        }
        live_routes.erase(
            std::remove_if(
                live_routes.begin(),
                live_routes.end(),
                [&](const DumpedRoute& route) {
                    return route_table_detail::route_occupies_same_slot(
                        spec, route);
                }),
            live_routes.end());
        live_routes.push_back(to_live(spec));
    }

    void delete_route(const RouteSpec& spec) override {
        events.push_back("route:delete:" + std::to_string(spec.table));
        if (failing_route_delete_table &&
            *failing_route_delete_table == spec.table) {
            throw std::runtime_error("injected route delete failure");
        }
        live_routes.erase(
            std::remove_if(
                live_routes.begin(),
                live_routes.end(),
                [&](const DumpedRoute& route) {
                    return route_table_detail::route_matches_live(
                        spec, route);
                }),
            live_routes.end());
        if (failing_route_delete_after_effect_table &&
            *failing_route_delete_after_effect_table == spec.table) {
            throw std::runtime_error(
                "injected route delete failure after effect");
        }
    }

    std::vector<DumpedRoute> dump_routes(int family = 0) override {
        ++route_dump_calls;
        if (failing_route_dump ||
            (failing_route_dump_call &&
             route_dump_calls == *failing_route_dump_call)) {
            throw std::runtime_error("injected route dump failure");
        }
        if (family == 0) return live_routes;
        std::vector<DumpedRoute> result;
        std::copy_if(
            live_routes.begin(),
            live_routes.end(),
            std::back_inserter(result),
            [family](const DumpedRoute& route) {
                return route.family == family;
            });
        return result;
    }

    RuleAddResult add_rule_for_family(
        const RuleSpec& spec,
        int family) override {
        events.push_back("rule:add:" + std::to_string(spec.table));
        if (failing_rule_priority &&
            *failing_rule_priority == spec.priority) {
            throw std::runtime_error("injected rule failure");
        }
        if (failing_rule_add_family &&
            *failing_rule_add_family == family) {
            throw std::runtime_error("injected rule family add failure");
        }
        if (has_rule(spec, family)) {
            return RuleAddResult::AlreadyPresent;
        }
        live_rules.push_back(DumpedRule{
            spec.priority,
            spec.fwmark,
            spec.fwmask,
            spec.table,
            family});
        return RuleAddResult::Created;
    }

    void delete_rule_for_family(
        const RuleSpec& spec,
        int family) override {
        events.push_back("rule:delete:" + std::to_string(spec.table));
        if (failing_rule_delete_priority &&
            *failing_rule_delete_priority == spec.priority) {
            throw std::runtime_error("injected rule delete failure");
        }
        if (failing_rule_delete_family &&
            *failing_rule_delete_family == family) {
            throw std::runtime_error(
                "injected rule family delete failure");
        }
        live_rules.erase(
            std::remove_if(
                live_rules.begin(),
                live_rules.end(),
                [&](const DumpedRule& rule) {
                    return rule.priority == spec.priority &&
                           rule.fwmark == spec.fwmark &&
                           rule.fwmask == spec.fwmask &&
                           rule.table == spec.table &&
                           rule.family == family;
                }),
            live_rules.end());
        if (failing_rule_delete_after_effect_priority &&
            *failing_rule_delete_after_effect_priority == spec.priority) {
            throw std::runtime_error(
                "injected rule delete failure after effect");
        }
    }

    std::vector<DumpedRule> dump_policy_rules(int family = 0) override {
        ++rule_dump_calls;
        if (failing_rule_dump_call &&
            rule_dump_calls == *failing_rule_dump_call) {
            throw std::runtime_error("injected rule dump failure");
        }
        if (family == 0) return live_rules;
        std::vector<DumpedRule> result;
        std::copy_if(
            live_rules.begin(),
            live_rules.end(),
            std::back_inserter(result),
            [family](const DumpedRule& rule) {
                return rule.family == family;
            });
        return result;
    }

    void seed_foreign_route(const RouteSpec& spec) {
        auto route = to_live(spec);
        route.protocol = 4U;
        live_routes.push_back(std::move(route));
    }

    bool contains_route(const RouteSpec& spec) const {
        return std::any_of(
            live_routes.begin(),
            live_routes.end(),
            [&](const DumpedRoute& route) {
                return route_table_detail::route_matches_live(spec, route);
            });
    }

    std::optional<std::uint32_t> failing_rule_priority;
    std::optional<int> failing_rule_add_family;
    std::optional<int> failing_rule_delete_family;
    std::optional<std::uint32_t> failing_route_delete_table;
    std::optional<std::uint32_t>
        failing_route_delete_after_effect_table;
    std::optional<std::uint32_t> failing_rule_delete_priority;
    std::optional<std::uint32_t>
        failing_rule_delete_after_effect_priority;
    bool failing_route_dump{false};
    std::optional<std::size_t> failing_route_dump_call;
    std::size_t route_dump_calls{0U};
    std::optional<std::size_t> failing_route_replace_from_call;
    std::size_t route_replace_calls{0U};
    std::optional<std::size_t> failing_rule_dump_call;
    std::size_t rule_dump_calls{0U};
    std::function<void()> before_route_add;
    std::vector<std::string> events;
    std::vector<DumpedRoute> live_routes;
    std::vector<DumpedRule> live_rules;

private:
    static DumpedRoute to_live(const RouteSpec& spec) {
        return DumpedRoute{
            spec.destination,
            spec.table,
            spec.interface,
            spec.gateway,
            spec.blackhole,
            spec.unreachable,
            spec.family,
            spec.metric,
            spec.protocol};
    }

    bool has_rule(const RuleSpec& spec, int family) const {
        return std::any_of(
            live_rules.begin(),
            live_rules.end(),
            [&](const DumpedRule& rule) {
                return rule.priority == spec.priority &&
                       rule.fwmark == spec.fwmark &&
                       rule.fwmask == spec.fwmask &&
                       rule.table == spec.table &&
                       rule.family == family;
            });
    }
};

RouteSpec route_for(std::uint32_t table) {
    RouteSpec route;
    route.destination = "default";
    route.table = table;
    route.blackhole = true;
    route.family = AF_INET;
    return route;
}

RuleSpec rule_for(std::uint32_t table) {
    RuleSpec rule;
    rule.fwmark = table;
    rule.table = table;
    rule.priority = table;
    rule.family = AF_INET;
    return rule;
}

RuntimeRoutingOperationRequest request_for(
    std::uint64_t operation_serial,
    std::uint64_t base_revision,
    RouteSpec route,
    RuleSpec rule) {
    RuntimeRoutingOperationRequest request;
    request.identity.operation_serial = operation_serial;
    request.identity.runtime_generation = 7U;
    request.identity.intent_serial = operation_serial + 100U;
    request.identity.base_inventory_revision = base_revision;
    request.identity.route_epoch = 11U;
    request.desired_routes.push_back(std::move(route));
    request.desired_rules.push_back(std::move(rule));
    return request;
}

RuntimeRoutingOperationOwner make_owner(
    RecordingRuntimeRoutingNetlink& netlink) {
    return RuntimeRoutingOperationOwner{
        netlink,
        netlink,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        }};
}

} // namespace

TEST_CASE("runtime routing inventory authority has one fail-closed classifier") {
    RuntimeRoutingInventorySnapshotPtr missing;
    CHECK(classify_runtime_routing_inventory(missing) ==
          RuntimeRoutingInventoryAuthority::missing);

    auto mutable_inventory =
        std::make_shared<RuntimeRoutingInventorySnapshot>();
    RuntimeRoutingInventorySnapshotPtr inventory = mutable_inventory;
    CHECK(classify_runtime_routing_inventory(inventory) ==
          RuntimeRoutingInventoryAuthority::authoritative);

    mutable_inventory->inventory_complete = false;
    CHECK(classify_runtime_routing_inventory(inventory) ==
          RuntimeRoutingInventoryAuthority::inventory_incomplete);

    mutable_inventory->inventory_complete = true;
    mutable_inventory->kernel_state_known = false;
    CHECK(classify_runtime_routing_inventory(inventory) ==
          RuntimeRoutingInventoryAuthority::kernel_state_unknown);
}

TEST_CASE("runtime routing owner rejects invalid stale and replayed identity before netlink") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);

    auto invalid = request_for(0U, 1U, route_for(150), rule_for(150));
    CHECK(
        owner.reconcile(invalid).outcome ==
        RuntimeRoutingOperationOutcome::rejected_invalid_identity);
    CHECK(netlink.events.empty());

    auto stale = request_for(1U, 99U, route_for(150), rule_for(150));
    CHECK(
        owner.reconcile(stale).outcome ==
        RuntimeRoutingOperationOutcome::rejected_stale_inventory);
    CHECK(netlink.events.empty());
    CHECK(owner.snapshot()->revision == 1U);
    CHECK(owner.snapshot()->highest_consumed_operation_serial == 1U);

    stale.identity.base_inventory_revision = 1U;
    CHECK(
        owner.reconcile(stale).outcome ==
        RuntimeRoutingOperationOutcome::rejected_replay);
    CHECK(netlink.events.empty());

    auto old_intent = request_for(
        2U, 1U, route_for(150), rule_for(150));
    old_intent.identity.intent_serial = 100U;
    CHECK(
        owner.reconcile(old_intent).outcome ==
        RuntimeRoutingOperationOutcome::rejected_replay);
    CHECK(netlink.events.empty());
}

TEST_CASE("runtime routing owner preserves combined add before delete order") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);

    auto initial = request_for(1U, 1U, route_for(150), rule_for(150));
    REQUIRE(owner.reconcile(initial).compatibility_converged());
    CHECK(owner.snapshot()->revision == 2U);

    netlink.events.clear();
    auto replacement = request_for(2U, 2U, route_for(151), rule_for(151));
    const auto result = owner.reconcile(replacement);

    REQUIRE(result.compatibility_converged());
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151",
        "rule:add:151",
        "rule:delete:150",
        "route:delete:150"});
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(result.inventory->revision == 3U);
    REQUIRE(result.inventory->routes.size() == 1U);
    CHECK(result.inventory->routes.front().table == 151U);
    REQUIRE(result.inventory->rules.size() == 1U);
    CHECK(result.inventory->rules.front().table == 151U);
}

TEST_CASE("desired rule does not block route replacement in the same table") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    auto first_route = route_for(150U);
    first_route.blackhole = false;
    first_route.interface = "wg-old";
    REQUIRE(owner.reconcile(
        request_for(1U, 1U, first_route, rule_for(150U)))
                .compatibility_converged());

    auto replacement_route = route_for(150U);
    replacement_route.blackhole = false;
    replacement_route.interface = "wg-new";
    netlink.events.clear();
    const auto result = owner.reconcile(
        request_for(2U, 2U, replacement_route, rule_for(150U)));

    REQUIRE(result.compatibility_converged());
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(result.inventory->inventory_complete);
    CHECK(result.inventory->kernel_state_known);
    REQUIRE(result.inventory->routes.size() == 1U);
    REQUIRE(result.inventory->routes.front().interface);
    CHECK(*result.inventory->routes.front().interface == "wg-new");
    REQUIRE(result.inventory->rules.size() == 1U);
}

TEST_CASE("deferred missing desired route cannot authorize firewall generation") {
    RecordingRuntimeRoutingNetlink netlink;
    bool interface_ready = true;
    RuntimeRoutingOperationOwner owner{
        netlink,
        netlink,
        [&](const std::string&) {
            return interface_ready
                ? netlink_detail::InterfaceAdminState::Up
                : netlink_detail::InterfaceAdminState::Down;
        }};
    auto route = route_for(150U);
    route.blackhole = false;
    route.interface = "wg-missing";
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route}, {rule_for(150U)})));

    netlink.live_routes.clear();
    netlink.events.clear();
    interface_ready = false;
    const auto reconciled = owner.reconcile_compatibility_generation(
        {route},
        {rule_for(150U)},
        RouteReconcileMode::DeferredRepair);

    REQUIRE(static_cast<bool>(reconciled));
    CHECK(reconciled->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_cleanup_pending);
    CHECK(reconciled->inventory_complete);
    CHECK_FALSE(reconciled->kernel_state_known);
    CHECK(classify_runtime_routing_inventory(reconciled) ==
          RuntimeRoutingInventoryAuthority::kernel_state_unknown);
    CHECK(netlink.events.empty());
}

TEST_CASE("runtime routing owner publishes typed partial inventory and converges on a fresh revision") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    REQUIRE(owner.reconcile(
        request_for(1U, 1U, route_for(150), rule_for(150)))
                .compatibility_converged());

    netlink.events.clear();
    netlink.failing_rule_priority = 151U;
    const auto failed = owner.reconcile(
        request_for(2U, 2U, route_for(151), rule_for(151)));
    CHECK(
        failed.outcome ==
        RuntimeRoutingOperationOutcome::partial_failure);
    REQUIRE(static_cast<bool>(failed.journal));
    CHECK(failed.journal->mutation_boundary_entered);
    CHECK(
        failed.journal->phase == RuntimeRoutingMutationPhase::failed);
    REQUIRE(static_cast<bool>(failed.inventory));
    CHECK(failed.inventory->revision == 3U);
    CHECK(failed.inventory->inventory_complete);
    CHECK_FALSE(failed.inventory->kernel_state_known);
    CHECK(failed.inventory->routes.size() == 2U);
    CHECK(failed.inventory->rules.size() == 1U);
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151", "rule:add:151"});

    netlink.failing_rule_priority.reset();
    netlink.events.clear();
    const auto retried = owner.reconcile(
        request_for(3U, 3U, route_for(151), rule_for(151)));
    REQUIRE(retried.compatibility_converged());
    CHECK(retried.inventory->revision == 4U);
    CHECK(retried.inventory->inventory_complete);
    CHECK(retried.inventory->kernel_state_known);
    CHECK(netlink.events == std::vector<std::string>{
        "rule:add:151",
        "rule:delete:150",
        "route:delete:150"});
}

TEST_CASE("runtime routing owner never claims or clears a foreign route collision") {
    RecordingRuntimeRoutingNetlink netlink;
    const auto foreign = route_for(170);
    netlink.seed_foreign_route(foreign);
    auto owner = make_owner(netlink);

    const auto result = owner.reconcile(
        request_for(1U, 1U, foreign, rule_for(170)));
    CHECK(
        result.outcome ==
        RuntimeRoutingOperationOutcome::partial_failure);
    CHECK(netlink.events == std::vector<std::string>{"route:add:170"});
    CHECK(netlink.live_rules.empty());

    netlink.events.clear();
    const auto cleared = owner.clear();
    REQUIRE(static_cast<bool>(cleared));
    CHECK(cleared->outcome == RuntimeRoutingOperationOutcome::cleared);
    CHECK(netlink.events.empty());
    REQUIRE(netlink.live_routes.size() == 1U);
    CHECK(netlink.live_routes.front().protocol == 4U);
}

TEST_CASE("runtime routing snapshots remain immutable across later operations") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    REQUIRE(owner.reconcile(
        request_for(1U, 1U, route_for(150), rule_for(150)))
                .compatibility_converged());
    const auto retained = owner.snapshot();
    REQUIRE(static_cast<bool>(retained));
    CHECK(retained->revision == 2U);
    REQUIRE(retained->routes.size() == 1U);
    CHECK(retained->routes.front().table == 150U);

    REQUIRE(owner.reconcile(
        request_for(2U, 2U, route_for(151), rule_for(151)))
                .compatibility_converged());
    CHECK(owner.snapshot()->revision == 3U);
    CHECK(owner.snapshot()->routes.front().table == 151U);

    CHECK(retained->revision == 2U);
    REQUIRE(retained->routes.size() == 1U);
    CHECK(retained->routes.front().table == 150U);
}

TEST_CASE("runtime routing owner retains old journals and clears rules before routes") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);

    const auto first = owner.reconcile(
        request_for(1U, 1U, route_for(150), rule_for(150)));
    REQUIRE(first.compatibility_converged());
    REQUIRE(static_cast<bool>(first.journal));
    const auto retained_journal = first.journal;

    const auto second = owner.reconcile(
        request_for(2U, 2U, route_for(151), rule_for(151)));
    REQUIRE(second.compatibility_converged());
    REQUIRE(static_cast<bool>(second.journal));
    CHECK(second.journal.get() != retained_journal.get());
    CHECK(retained_journal->identity.operation_serial == 1U);
    CHECK(retained_journal->phase == RuntimeRoutingMutationPhase::complete);

    netlink.events.clear();
    const auto cleared = owner.clear();
    REQUIRE(static_cast<bool>(cleared));
    CHECK(netlink.events == std::vector<std::string>{
        "rule:delete:151", "route:delete:151"});
    CHECK(retained_journal->identity.operation_serial == 1U);
    CHECK(retained_journal->phase == RuntimeRoutingMutationPhase::complete);
    CHECK(second.journal->identity.operation_serial == 2U);
    CHECK(second.journal->phase == RuntimeRoutingMutationPhase::complete);
}

TEST_CASE("daemon compatibility routing paths stay behind one combined owner") {
    RecordingRuntimeRoutingNetlink netlink;
    {
        auto owner = make_owner(netlink);
        const auto populated = owner.populate_initial_generation(
            {route_for(150U)}, {rule_for(150U)});
        REQUIRE(static_cast<bool>(populated));
        CHECK(populated->revision == 2U);
        CHECK(populated->outcome ==
              RuntimeRoutingOperationOutcome::compatibility_converged);
        CHECK(netlink.events == std::vector<std::string>{
            "route:add:150", "rule:add:150"});

        netlink.events.clear();
        const auto reconciled =
            owner.reconcile_compatibility_generation(
                {route_for(151U)},
                {rule_for(151U)},
                RouteReconcileMode::Strict);
        REQUIRE(static_cast<bool>(reconciled));
        CHECK(reconciled->revision == 3U);
        CHECK(reconciled->routes.front().table == 151U);
        CHECK(reconciled->rules.front().table == 151U);
        CHECK(netlink.events == std::vector<std::string>{
            "route:add:151",
            "rule:add:151",
            "rule:delete:150",
            "route:delete:150"});

        netlink.events.clear();
    }

    // The owner performs its one ordered best-effort teardown while locked;
    // disarmed manager destructors cannot issue a second unlocked cleanup.
    CHECK(netlink.events == std::vector<std::string>{
        "rule:delete:151", "route:delete:151"});
}

TEST_CASE("failed initial generation is cleared and published by the combined owner") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    netlink.failing_rule_priority = 150U;

    CHECK_THROWS_AS(
        owner.populate_initial_generation(
            {route_for(150U)}, {rule_for(150U)}),
        std::runtime_error);
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:150",
        "rule:add:150",
        "route:delete:150"});
    const auto inventory = owner.snapshot();
    REQUIRE(static_cast<bool>(inventory));
    CHECK(inventory->revision == 2U);
    CHECK(inventory->outcome ==
          RuntimeRoutingOperationOutcome::partial_failure);
    CHECK(inventory->inventory_complete);
    CHECK_FALSE(inventory->kernel_state_known);
    CHECK(inventory->routes.empty());
    CHECK(inventory->rules.empty());
}

TEST_CASE("ambiguous family rollback retains its policy route anchor") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    auto dual_stack_rule = rule_for(150U);
    dual_stack_rule.family = 0;
    netlink.failing_rule_add_family = AF_INET6;
    netlink.failing_rule_delete_family = AF_INET;

    CHECK_THROWS_AS(
        owner.populate_initial_generation(
            {route_for(150U)}, {dual_stack_rule}),
        std::runtime_error);

    const auto inventory = owner.snapshot();
    REQUIRE(static_cast<bool>(inventory));
    CHECK(inventory->outcome ==
          RuntimeRoutingOperationOutcome::partial_failure);
    CHECK(inventory->inventory_complete);
    CHECK_FALSE(inventory->kernel_state_known);
    REQUIRE(inventory->routes.size() == 1U);
    REQUIRE(inventory->rules.size() == 1U);
    CHECK(netlink.contains_route(route_for(150U)));
    REQUIRE(netlink.live_rules.size() == 1U);
    CHECK(netlink.live_rules.front().family == AF_INET);
    CHECK(std::find(
              netlink.events.begin(),
              netlink.events.end(),
              "route:delete:150") == netlink.events.end());
}

TEST_CASE("ambiguous managed route restoration remains in the owner ledger") {
    RecordingRuntimeRoutingNetlink netlink;
    auto previous = route_for(150U);
    previous.blackhole = false;
    previous.interface = "wg-old";
    netlink.live_routes.push_back(DumpedRoute{
        previous.destination,
        previous.table,
        previous.interface,
        previous.gateway,
        previous.blackhole,
        previous.unreachable,
        previous.family,
        previous.metric,
        previous.protocol});
    auto desired = route_for(150U);
    desired.blackhole = false;
    desired.interface = "wg-new";
    netlink.failing_route_dump_call = 4U;
    netlink.failing_route_replace_from_call = 2U;
    auto owner = make_owner(netlink);

    CHECK_THROWS_AS(
        owner.populate_initial_generation(
            {desired}, {rule_for(150U)}),
        std::runtime_error);

    const auto inventory = owner.snapshot();
    REQUIRE(static_cast<bool>(inventory));
    CHECK(inventory->outcome ==
          RuntimeRoutingOperationOutcome::partial_failure);
    CHECK(inventory->inventory_complete);
    CHECK_FALSE(inventory->kernel_state_known);
    REQUIRE(inventory->routes.size() == 1U);
    CHECK(inventory->routes.front().interface == desired.interface);
    CHECK(inventory->rules.empty());
    CHECK(netlink.contains_route(desired));
}

TEST_CASE("failed stale rule delete retains its dependent route anchor") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route_for(150U)}, {rule_for(150U)})));

    netlink.events.clear();
    netlink.failing_rule_delete_priority = 150U;
    const auto reconciled = owner.reconcile_compatibility_generation(
        {route_for(151U)},
        {rule_for(151U)},
        RouteReconcileMode::Strict);

    REQUIRE(static_cast<bool>(reconciled));
    CHECK(reconciled->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_cleanup_pending);
    CHECK(reconciled->inventory_complete);
    CHECK_FALSE(reconciled->kernel_state_known);
    CHECK(reconciled->revision == 3U);
    REQUIRE(reconciled->routes.size() == 2U);
    CHECK(reconciled->routes[0].table == 150U);
    CHECK(reconciled->routes[1].table == 151U);
    REQUIRE(reconciled->rules.size() == 2U);
    CHECK(reconciled->rules[0].table == 150U);
    CHECK(reconciled->rules[1].table == 151U);
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151",
        "rule:add:151",
        "rule:delete:150"});
    CHECK(netlink.contains_route(route_for(150U)));
}

TEST_CASE("tracked unowned live rule retains its dependent route anchor") {
    RecordingRuntimeRoutingNetlink netlink;
    const auto old_rule = rule_for(150U);
    netlink.live_rules.push_back(DumpedRule{
        old_rule.priority,
        old_rule.fwmark,
        old_rule.fwmask,
        old_rule.table,
        old_rule.family});
    auto owner = make_owner(netlink);

    // Simulate an AlreadyPresent rule whose best-effort ownership adoption
    // could not obtain a live inventory. It is tracked, but not safe to
    // delete as an owned object.
    netlink.failing_rule_dump_call = 3U;
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route_for(150U)}, {old_rule})));
    netlink.failing_rule_dump_call.reset();

    netlink.events.clear();
    const auto reconciled = owner.reconcile_compatibility_generation(
        {route_for(151U)},
        {rule_for(151U)},
        RouteReconcileMode::Strict);

    REQUIRE(static_cast<bool>(reconciled));
    CHECK(reconciled->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_cleanup_pending);
    CHECK(reconciled->inventory_complete);
    CHECK_FALSE(reconciled->kernel_state_known);
    REQUIRE(reconciled->routes.size() == 2U);
    REQUIRE(reconciled->rules.size() == 2U);
    CHECK(netlink.contains_route(route_for(150U)));
    CHECK(std::find(
              netlink.events.begin(),
              netlink.events.end(),
              "rule:delete:150") == netlink.events.end());
    CHECK(std::find(
              netlink.events.begin(),
              netlink.events.end(),
              "route:delete:150") == netlink.events.end());
}

TEST_CASE("foreign live rule protects an obsolete generated route anchor") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route_for(150U)}, {rule_for(150U)})));
    netlink.live_rules.push_back(DumpedRule{
        950U,
        0x950U,
        0xFFFFFFFFU,
        150U,
        AF_INET,
        false});

    netlink.events.clear();
    const auto reconciled = owner.reconcile_compatibility_generation(
        {route_for(151U)},
        {rule_for(151U)},
        RouteReconcileMode::Strict);

    REQUIRE(static_cast<bool>(reconciled));
    CHECK(reconciled->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_cleanup_pending);
    CHECK(reconciled->inventory_complete);
    CHECK_FALSE(reconciled->kernel_state_known);
    REQUIRE(reconciled->routes.size() == 2U);
    REQUIRE(reconciled->rules.size() == 1U);
    CHECK(netlink.contains_route(route_for(150U)));
    CHECK(std::find(
              netlink.events.begin(),
              netlink.events.end(),
              "rule:delete:150") != netlink.events.end());
    CHECK(std::find(
              netlink.events.begin(),
              netlink.events.end(),
              "route:delete:150") == netlink.events.end());
}

TEST_CASE("foreign live rule protects a restart orphan route before adoption") {
    RecordingRuntimeRoutingNetlink netlink;
    const auto orphan_route = route_for(150U);
    netlink.live_routes.push_back(DumpedRoute{
        orphan_route.destination,
        orphan_route.table,
        orphan_route.interface,
        orphan_route.gateway,
        orphan_route.blackhole,
        orphan_route.unreachable,
        orphan_route.family,
        orphan_route.metric,
        orphan_route.protocol});
    netlink.live_rules.push_back(DumpedRule{
        950U,
        0x950U,
        0xFFFFFFFFU,
        150U,
        AF_INET});
    auto owner = make_owner(netlink);

    const auto reconciled = owner.reconcile_compatibility_generation(
        {route_for(151U)},
        {rule_for(151U)},
        RouteReconcileMode::Strict);

    REQUIRE(static_cast<bool>(reconciled));
    CHECK(reconciled->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_cleanup_pending);
    CHECK(reconciled->inventory_complete);
    CHECK_FALSE(reconciled->kernel_state_known);
    REQUIRE(reconciled->routes.size() == 2U);
    CHECK(netlink.contains_route(orphan_route));
    CHECK(std::find(
              netlink.events.begin(),
              netlink.events.end(),
              "route:delete:150") == netlink.events.end());
}

TEST_CASE("failed orphan route inventory cannot publish authoritative cleanup") {
    RecordingRuntimeRoutingNetlink netlink;
    const auto orphan_route = route_for(150U);
    netlink.live_routes.push_back(DumpedRoute{
        orphan_route.destination,
        orphan_route.table,
        orphan_route.interface,
        orphan_route.gateway,
        orphan_route.blackhole,
        orphan_route.unreachable,
        orphan_route.family,
        orphan_route.metric,
        orphan_route.protocol});
    netlink.failing_route_dump_call = 3U;
    auto owner = make_owner(netlink);

    CHECK_THROWS_AS(
        owner.reconcile_compatibility_generation(
            {route_for(151U)},
            {rule_for(151U)},
            RouteReconcileMode::Strict),
        std::runtime_error);

    const auto snapshot = owner.snapshot();
    REQUIRE(static_cast<bool>(snapshot));
    CHECK(snapshot->outcome ==
          RuntimeRoutingOperationOutcome::partial_failure);
    CHECK(snapshot->inventory_complete);
    CHECK_FALSE(snapshot->kernel_state_known);
    CHECK(netlink.contains_route(orphan_route));
    CHECK(std::find(
              netlink.events.begin(),
              netlink.events.end(),
              "route:delete:150") == netlink.events.end());
}

TEST_CASE("failed stale route delete remains visible as cleanup pending") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route_for(150U)}, {rule_for(150U)})));

    netlink.events.clear();
    netlink.failing_route_delete_table = 150U;
    const auto reconciled = owner.reconcile_compatibility_generation(
        {route_for(151U)},
        {rule_for(151U)},
        RouteReconcileMode::Strict);

    REQUIRE(static_cast<bool>(reconciled));
    CHECK(reconciled->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_cleanup_pending);
    CHECK(reconciled->inventory_complete);
    CHECK_FALSE(reconciled->kernel_state_known);
    REQUIRE(reconciled->routes.size() == 2U);
    REQUIRE(reconciled->rules.size() == 1U);
    CHECK(reconciled->rules.front().table == 151U);
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151",
        "rule:add:151",
        "rule:delete:150",
        "route:delete:150"});
}

TEST_CASE("unknown after-effect rule delete keeps its route anchor for recovery") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route_for(150U)}, {rule_for(150U)})));

    netlink.events.clear();
    netlink.failing_rule_delete_after_effect_priority = 150U;
    const auto reconciled = owner.reconcile_compatibility_generation(
        {route_for(151U)},
        {rule_for(151U)},
        RouteReconcileMode::Strict);

    REQUIRE(static_cast<bool>(reconciled));
    CHECK(reconciled->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_cleanup_pending);
    CHECK(reconciled->inventory_complete);
    CHECK_FALSE(reconciled->kernel_state_known);
    REQUIRE(reconciled->routes.size() == 2U);
    REQUIRE(reconciled->rules.size() == 2U);
    CHECK(netlink.contains_route(route_for(150U)));
    CHECK(std::none_of(
        netlink.live_rules.begin(),
        netlink.live_rules.end(),
        [](const DumpedRule& rule) { return rule.table == 150U; }));
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151",
        "rule:add:151",
        "rule:delete:150"});
}

TEST_CASE("unknown after-effect route delete retains a conservative ledger") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route_for(150U)}, {rule_for(150U)})));

    netlink.events.clear();
    netlink.failing_route_delete_after_effect_table = 150U;
    const auto reconciled = owner.reconcile_compatibility_generation(
        {route_for(151U)},
        {rule_for(151U)},
        RouteReconcileMode::Strict);

    REQUIRE(static_cast<bool>(reconciled));
    CHECK(reconciled->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_cleanup_pending);
    CHECK(reconciled->inventory_complete);
    CHECK_FALSE(reconciled->kernel_state_known);
    REQUIRE(reconciled->routes.size() == 2U);
    REQUIRE(reconciled->rules.size() == 1U);
    CHECK_FALSE(netlink.contains_route(route_for(150U)));
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151",
        "rule:add:151",
        "rule:delete:150",
        "route:delete:150"});
}

TEST_CASE("clear never removes a route anchor after rule deletion uncertainty") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route_for(150U)}, {rule_for(150U)})));

    netlink.events.clear();
    netlink.failing_rule_delete_priority = 150U;
    const auto cleared = owner.clear();

    REQUIRE(static_cast<bool>(cleared));
    CHECK(cleared->outcome ==
          RuntimeRoutingOperationOutcome::partial_failure);
    CHECK(cleared->inventory_complete);
    CHECK_FALSE(cleared->kernel_state_known);
    REQUIRE(cleared->routes.size() == 1U);
    REQUIRE(cleared->rules.size() == 1U);
    CHECK(netlink.events ==
          std::vector<std::string>{"rule:delete:150"});
    CHECK(netlink.contains_route(route_for(150U)));
}

TEST_CASE("repopulate preserves an anchor while prior rule cleanup is uncertain") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route_for(150U)}, {rule_for(150U)})));

    netlink.failing_rule_delete_priority = 150U;
    REQUIRE(static_cast<bool>(owner.clear()));
    netlink.events.clear();

    const auto populated = owner.populate_initial_generation(
        {route_for(151U)}, {rule_for(151U)});

    REQUIRE(static_cast<bool>(populated));
    CHECK(populated->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_cleanup_pending);
    CHECK(populated->inventory_complete);
    CHECK_FALSE(populated->kernel_state_known);
    REQUIRE(populated->routes.size() == 2U);
    REQUIRE(populated->rules.size() == 2U);
    CHECK(netlink.contains_route(route_for(150U)));
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151",
        "rule:add:151",
        "rule:delete:150"});
}

TEST_CASE("repopulate restores a tracked rule lost during uncertain clear") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route_for(150U)}, {rule_for(150U)})));

    netlink.failing_rule_delete_after_effect_priority = 150U;
    const auto cleared = owner.clear();
    REQUIRE(static_cast<bool>(cleared));
    CHECK_FALSE(cleared->kernel_state_known);
    CHECK(netlink.live_rules.empty());
    CHECK(netlink.contains_route(route_for(150U)));

    netlink.failing_rule_delete_after_effect_priority.reset();
    netlink.events.clear();
    const auto populated = owner.populate_initial_generation(
        {route_for(150U)}, {rule_for(150U)});

    REQUIRE(static_cast<bool>(populated));
    CHECK(populated->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_converged);
    CHECK(populated->inventory_complete);
    CHECK(populated->kernel_state_known);
    REQUIRE(populated->routes.size() == 1U);
    REQUIRE(populated->rules.size() == 1U);
    CHECK(netlink.events ==
          std::vector<std::string>{"rule:add:150"});
    REQUIRE(netlink.live_rules.size() == 1U);
}

TEST_CASE("clear retains a route anchor for a tracked unowned live rule") {
    RecordingRuntimeRoutingNetlink netlink;
    const auto rule = rule_for(150U);
    netlink.live_rules.push_back(DumpedRule{
        rule.priority,
        rule.fwmark,
        rule.fwmask,
        rule.table,
        rule.family});
    auto owner = make_owner(netlink);

    netlink.failing_rule_dump_call = 3U;
    REQUIRE(static_cast<bool>(owner.populate_initial_generation(
        {route_for(150U)}, {rule})));
    netlink.failing_rule_dump_call.reset();

    netlink.events.clear();
    const auto cleared = owner.clear();

    REQUIRE(static_cast<bool>(cleared));
    CHECK(cleared->outcome ==
          RuntimeRoutingOperationOutcome::partial_failure);
    CHECK(cleared->inventory_complete);
    CHECK_FALSE(cleared->kernel_state_known);
    REQUIRE(cleared->routes.size() == 1U);
    REQUIRE(cleared->rules.size() == 1U);
    CHECK(netlink.events.empty());
    CHECK(netlink.contains_route(route_for(150U)));
}

TEST_CASE("clear preserves an orphan route anchor with an untracked live rule") {
    RecordingRuntimeRoutingNetlink netlink;
    const auto orphan_route = route_for(150U);
    netlink.live_routes.push_back(DumpedRoute{
        orphan_route.destination,
        orphan_route.table,
        orphan_route.interface,
        orphan_route.gateway,
        orphan_route.blackhole,
        orphan_route.unreachable,
        orphan_route.family,
        orphan_route.metric,
        orphan_route.protocol});
    const auto desired_rule = rule_for(151U);
    netlink.live_rules.push_back(DumpedRule{
        150U,
        desired_rule.fwmark,
        desired_rule.fwmask,
        150U,
        AF_INET});
    netlink.failing_rule_delete_priority = 150U;
    auto owner = make_owner(netlink);

    const auto reconciled = owner.reconcile_compatibility_generation(
        {route_for(151U)},
        {desired_rule},
        RouteReconcileMode::Strict);
    REQUIRE(static_cast<bool>(reconciled));
    CHECK(reconciled->outcome ==
          RuntimeRoutingOperationOutcome::compatibility_cleanup_pending);
    CHECK(netlink.contains_route(orphan_route));

    netlink.events.clear();
    const auto cleared = owner.clear();

    REQUIRE(static_cast<bool>(cleared));
    CHECK(cleared->outcome ==
          RuntimeRoutingOperationOutcome::partial_failure);
    CHECK(cleared->inventory_complete);
    CHECK_FALSE(cleared->kernel_state_known);
    REQUIRE(cleared->routes.size() == 1U);
    CHECK(cleared->routes.front().table == 150U);
    CHECK(cleared->rules.empty());
    CHECK(netlink.contains_route(orphan_route));
    CHECK(std::find(
              netlink.events.begin(),
              netlink.events.end(),
              "route:delete:150") == netlink.events.end());
    CHECK(std::find(
              netlink.events.begin(),
              netlink.events.end(),
              "route:delete:151") != netlink.events.end());
}

TEST_CASE("post-mutation publication failure uses preallocated incomplete inventory") {
    RecordingRuntimeRoutingNetlink netlink;
    std::size_t allocations = 0U;
    RuntimeRoutingOperationOwner owner{
        netlink,
        netlink,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        },
        {},
        [&]() -> std::shared_ptr<RuntimeRoutingInventorySnapshot> {
            ++allocations;
            if (allocations == 3U) {
                throw std::bad_alloc();
            }
            return std::make_shared<RuntimeRoutingInventorySnapshot>();
        }};

    const auto published = owner.populate_initial_generation(
        {route_for(150U)}, {rule_for(150U)});
    REQUIRE(static_cast<bool>(published));
    CHECK(published->revision == 2U);
    CHECK_FALSE(published->inventory_complete);
    CHECK(published->kernel_state_known);
    CHECK(published->routes.empty());
    CHECK(published->rules.empty());
    CHECK(netlink.contains_route(route_for(150U)));
    REQUIRE(netlink.live_rules.size() == 1U);

    netlink.events.clear();
    const auto refreshed = owner.reconcile_compatibility_generation(
        {route_for(150U)},
        {rule_for(150U)},
        RouteReconcileMode::Strict);
    REQUIRE(static_cast<bool>(refreshed));
    CHECK(refreshed->revision == 3U);
    CHECK(refreshed->inventory_complete);
    CHECK(refreshed->kernel_state_known);
    REQUIRE(refreshed->routes.size() == 1U);
    REQUIRE(refreshed->rules.size() == 1U);
    CHECK(netlink.events.empty());
}

TEST_CASE("pre-mutation observation failures preserve the authoritative inventory") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    const auto before = owner.snapshot();
    REQUIRE(static_cast<bool>(before));
    REQUIRE(before->inventory_complete);
    REQUIRE(before->kernel_state_known);

    netlink.failing_route_dump = true;
    CHECK_THROWS_AS(
        owner.reconcile_compatibility_generation(
            {route_for(150U)},
            {rule_for(150U)},
            RouteReconcileMode::Strict),
        std::runtime_error);
    CHECK(owner.snapshot().get() == before.get());
    CHECK(owner.snapshot()->revision == 1U);
    CHECK(netlink.events.empty());

    netlink.failing_route_dump = false;
    CHECK_THROWS_AS(
        owner.reconcile_compatibility_generation(
            {route_for(150U)},
            {rule_for(150U)},
            RouteReconcileMode::Strict,
            []() -> bool {
                throw std::runtime_error("injected fence failure");
            }),
        std::runtime_error);
    CHECK(owner.snapshot().get() == before.get());
    CHECK(owner.snapshot()->revision == 1U);
    CHECK(netlink.events.empty());
}

TEST_CASE("exact observation failure publishes consumed identity without changing inventory") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    const auto before = owner.snapshot();
    REQUIRE(static_cast<bool>(before));
    REQUIRE(before->inventory_complete);
    REQUIRE(before->kernel_state_known);

    const auto request =
        request_for(1U, 1U, route_for(150U), rule_for(150U));
    netlink.failing_route_dump = true;
    const auto failed = owner.reconcile(request);

    CHECK(failed.outcome == RuntimeRoutingOperationOutcome::partial_failure);
    REQUIRE(static_cast<bool>(failed.journal));
    CHECK(failed.journal->phase == RuntimeRoutingMutationPhase::failed);
    CHECK_FALSE(failed.journal->mutation_boundary_entered);
    REQUIRE(static_cast<bool>(failed.inventory));
    CHECK(failed.inventory.get() != before.get());
    CHECK(failed.inventory->revision == before->revision);
    CHECK(failed.inventory->highest_consumed_operation_serial == 1U);
    CHECK(failed.inventory->highest_consumed_runtime_generation == 7U);
    CHECK(failed.inventory->highest_consumed_intent_serial == 101U);
    CHECK(failed.inventory->highest_consumed_route_epoch == 11U);
    CHECK_FALSE(failed.inventory->last_identity.has_value());
    CHECK_FALSE(before->last_identity.has_value());
    CHECK(failed.inventory->phase == before->phase);
    CHECK(failed.inventory->outcome == before->outcome);
    CHECK(failed.inventory->inventory_complete == before->inventory_complete);
    CHECK(failed.inventory->kernel_state_known == before->kernel_state_known);
    CHECK(failed.inventory->routes.empty());
    CHECK(failed.inventory->rules.empty());
    CHECK(before->routes.empty());
    CHECK(before->rules.empty());
    CHECK(netlink.events.empty());

    netlink.failing_route_dump = false;
    CHECK(owner.reconcile(request).outcome ==
          RuntimeRoutingOperationOutcome::rejected_replay);
    CHECK(netlink.events.empty());

    const auto recovered = owner.reconcile(
        request_for(2U, 1U, route_for(150U), rule_for(150U)));
    REQUIRE(recovered.compatibility_converged());
    REQUIRE(static_cast<bool>(recovered.inventory));
    CHECK(recovered.inventory->revision == 2U);
    CHECK(recovered.inventory->highest_consumed_operation_serial == 2U);
    CHECK(recovered.inventory->highest_consumed_runtime_generation == 7U);
    CHECK(recovered.inventory->highest_consumed_intent_serial == 102U);
    CHECK(recovered.inventory->highest_consumed_route_epoch == 11U);
}

TEST_CASE("pre-terminal allocation failure leaves exact identity retryable") {
    RecordingRuntimeRoutingNetlink netlink;
    std::size_t allocations = 0U;
    RuntimeRoutingOperationOwner owner{
        netlink,
        netlink,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        },
        {},
        [&]() -> std::shared_ptr<RuntimeRoutingInventorySnapshot> {
            ++allocations;
            if (allocations == 3U) {
                throw std::bad_alloc();
            }
            return std::make_shared<RuntimeRoutingInventorySnapshot>();
        }};
    const auto before = owner.snapshot();
    const auto request =
        request_for(1U, 1U, route_for(150U), rule_for(150U));

    CHECK_THROWS_AS(owner.reconcile(request), std::bad_alloc);
    CHECK(owner.snapshot().get() == before.get());
    CHECK(owner.snapshot()->highest_consumed_operation_serial == 0U);
    CHECK(owner.snapshot()->highest_consumed_intent_serial == 0U);
    CHECK(netlink.events.empty());

    const auto retried = owner.reconcile(request);
    REQUIRE(retried.compatibility_converged());
    REQUIRE(static_cast<bool>(retried.inventory));
    CHECK(retried.inventory->revision == 2U);
    CHECK(retried.inventory->highest_consumed_operation_serial == 1U);
}

TEST_CASE("combined owner rejects distinct route and rule backends") {
    RecordingRuntimeRoutingNetlink route_backend;
    RecordingRuntimeRoutingNetlink rule_backend;
    const auto construct = [&]() {
        RuntimeRoutingOperationOwner owner{
            static_cast<RouteNetlinkOperations&>(route_backend),
            static_cast<RuleNetlinkOperations&>(rule_backend)};
    };

    CHECK_THROWS_AS(construct(), std::invalid_argument);
    CHECK(route_backend.events.empty());
    CHECK(rule_backend.events.empty());
}

TEST_CASE("compatibility fence is evaluated inside the combined owner before netlink") {
    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    int fence_calls = 0;

    const auto rejected = owner.reconcile_compatibility_generation(
        {route_for(150U)},
        {rule_for(150U)},
        RouteReconcileMode::DeferredRepair,
        [&]() {
            ++fence_calls;
            return false;
        });

    CHECK_FALSE(static_cast<bool>(rejected));
    CHECK(fence_calls == 1);
    CHECK(netlink.events.empty());
    CHECK(netlink.live_routes.empty());
    CHECK(netlink.live_rules.empty());
    CHECK(owner.snapshot()->revision == 1U);
}

TEST_CASE("immutable routing snapshot never waits for an active worker mutation") {
    using namespace std::chrono_literals;

    RecordingRuntimeRoutingNetlink netlink;
    auto owner = make_owner(netlink);
    std::promise<void> route_add_entered;
    auto entered = route_add_entered.get_future();
    std::promise<void> release_route_add;
    const auto release = release_route_add.get_future().share();
    netlink.before_route_add = [&]() {
        route_add_entered.set_value();
        release.wait();
    };

    auto mutation = std::async(std::launch::async, [&]() {
        return owner.populate_initial_generation(
            {route_for(150U)}, {rule_for(150U)});
    });
    const auto entered_status = entered.wait_for(1s);
    if (entered_status != std::future_status::ready) {
        release_route_add.set_value();
        (void)mutation.wait_for(1s);
    }
    REQUIRE(entered_status == std::future_status::ready);

    auto read = std::async(std::launch::async, [&]() {
        return owner.snapshot();
    });
    const auto read_status = read.wait_for(1s);
    auto notify = std::async(std::launch::async, [&]() {
        owner.notify_interface_up("wg-new");
    });
    const auto notify_status = notify.wait_for(1s);
    release_route_add.set_value();
    REQUIRE(mutation.wait_for(1s) == std::future_status::ready);
    const auto committed = mutation.get();
    REQUIRE(static_cast<bool>(committed));
    CHECK(committed->revision == 2U);
    netlink.before_route_add = {};

    REQUIRE(read_status == std::future_status::ready);
    REQUIRE(notify_status == std::future_status::ready);
    notify.get();
    const auto retained = read.get();
    REQUIRE(static_cast<bool>(retained));
    CHECK(retained->revision == 1U);
    CHECK(retained->routes.empty());
    CHECK(retained->rules.empty());
}
