#include <doctest/doctest.h>

#include "../src/routing/runtime_routing_operation_owner.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

bool same_route_slot(const RouteSpec& expected, const DumpedRoute& actual) {
    return expected.destination == actual.destination &&
           expected.table == actual.table &&
           expected.family == actual.family &&
           expected.metric == actual.metric;
}

bool exact_route(const RouteSpec& expected, const DumpedRoute& actual) {
    return actual.exact_identity_representable &&
           same_route_slot(expected, actual) &&
           expected.interface == actual.interface &&
           expected.gateway == actual.gateway &&
           expected.blackhole == actual.blackhole &&
           expected.unreachable == actual.unreachable &&
           expected.protocol == actual.protocol;
}

bool exact_rule(
    const RuleSpec& expected,
    int family,
    const DumpedRule& actual) {
    return actual.exact_identity_representable &&
           expected.priority == actual.priority &&
           expected.fwmark == actual.fwmark &&
           expected.fwmask == actual.fwmask &&
           expected.table == actual.table && family == actual.family;
}

class ExactOwnerNetlink final
    : public RouteNetlinkOperations,
      public RuleNetlinkOperations {
public:
    class Lease final : public ExactRoutingTransactionLease {};

    bool supports_exact_route_transaction() const noexcept override {
        return true;
    }

    bool supports_exact_rule_transaction() const noexcept override {
        return true;
    }

    std::unique_ptr<ExactRoutingTransactionLease>
    acquire_exact_transaction_lease() override {
        return std::make_unique<Lease>();
    }

    RouteAddResult add_route(const RouteSpec& spec) override {
        observe_write();
        events.push_back("route:add:" + std::to_string(spec.table));
        const bool occupied = std::any_of(
            routes.begin(), routes.end(), [&](const DumpedRoute& route) {
                return same_route_slot(spec, route);
            });
        if (occupied) return RouteAddResult::AlreadyPresent;
        routes.push_back(to_live(spec));
        if (fail_route_add_after_effect) {
            throw std::runtime_error("route add failed after effect");
        }
        return RouteAddResult::Created;
    }

    void replace_route(const RouteSpec& spec) override {
        observe_write();
        events.push_back("route:replace:" + std::to_string(spec.table));
        erase_route_slot(spec);
        routes.push_back(to_live(spec));
    }

    void delete_route(const RouteSpec& spec) override {
        observe_write();
        ++broad_route_deletes;
        events.push_back("route:delete:" + std::to_string(spec.table));
        erase_route_slot(spec);
    }

    RouteExactDeleteResult delete_route_if_exact(
        const RouteSpec& spec) override {
        observe_write();
        ++exact_route_deletes;
        events.push_back("route:delete:" + std::to_string(spec.table));
        if (force_route_delete_precondition) {
            return RouteExactDeleteResult::PreconditionMismatch;
        }
        const auto it = std::find_if(
            routes.begin(), routes.end(), [&](const DumpedRoute& route) {
                return exact_route(spec, route);
            });
        if (it == routes.end()) {
            const bool occupied = std::any_of(
                routes.begin(), routes.end(), [&](const DumpedRoute& route) {
                    return same_route_slot(spec, route);
                });
            return occupied
                ? RouteExactDeleteResult::PreconditionMismatch
                : RouteExactDeleteResult::AlreadyAbsent;
        }
        routes.erase(it);
        return RouteExactDeleteResult::Deleted;
    }

    RouteExactReplaceResult replace_route_if_exact(
        const RouteSpec& expected,
        const RouteSpec& replacement) override {
        observe_write();
        events.push_back(
            "route:replace:" + std::to_string(replacement.table));
        const auto it = std::find_if(
            routes.begin(), routes.end(), [&](const DumpedRoute& route) {
                return exact_route(expected, route);
            });
        if (it == routes.end()) {
            return RouteExactReplaceResult::PreconditionMismatch;
        }
        *it = to_live(replacement);
        return RouteExactReplaceResult::Replaced;
    }

    std::vector<DumpedRoute> dump_routes(int family = 0) override {
        if (family == 0) return routes;
        std::vector<DumpedRoute> filtered;
        std::copy_if(
            routes.begin(),
            routes.end(),
            std::back_inserter(filtered),
            [family](const DumpedRoute& route) {
                return route.family == family;
            });
        return filtered;
    }

    RuleAddResult add_rule_for_family(
        const RuleSpec& spec,
        int family) override {
        observe_write();
        events.push_back("rule:add:" + std::to_string(spec.table));
        if (fail_rule_add_before_effect) {
            throw std::runtime_error("rule add failed before effect");
        }
        const bool present = std::any_of(
            rules.begin(), rules.end(), [&](const DumpedRule& rule) {
                return exact_rule(spec, family, rule);
            });
        if (present) return RuleAddResult::AlreadyPresent;
        rules.push_back(to_live(spec, family));
        if (fail_rule_add_after_effect) {
            throw std::runtime_error("rule add failed after effect");
        }
        return RuleAddResult::Created;
    }

    void delete_rule_for_family(
        const RuleSpec& spec,
        int family) override {
        observe_write();
        ++broad_rule_deletes;
        events.push_back("rule:delete:" + std::to_string(spec.table));
        erase_rule(spec, family);
    }

    RuleExactDeleteResult delete_rule_if_exact(
        const RuleSpec& spec,
        int family) override {
        observe_write();
        ++exact_rule_deletes;
        events.push_back("rule:delete:" + std::to_string(spec.table));
        if (force_rule_delete_precondition) {
            return RuleExactDeleteResult::PreconditionMismatch;
        }
        const auto it = std::find_if(
            rules.begin(), rules.end(), [&](const DumpedRule& rule) {
                return exact_rule(spec, family, rule);
            });
        if (it == rules.end()) {
            return RuleExactDeleteResult::AlreadyAbsent;
        }
        rules.erase(it);
        return RuleExactDeleteResult::Deleted;
    }

    std::vector<DumpedRule> dump_policy_rules(int family = 0) override {
        if (family == 0) return rules;
        std::vector<DumpedRule> filtered;
        std::copy_if(
            rules.begin(),
            rules.end(),
            std::back_inserter(filtered),
            [family](const DumpedRule& rule) {
                return rule.family == family;
            });
        return filtered;
    }

    std::function<void()> before_write;
    bool fail_route_add_after_effect{false};
    bool fail_rule_add_before_effect{false};
    bool fail_rule_add_after_effect{false};
    bool force_route_delete_precondition{false};
    bool force_rule_delete_precondition{false};
    std::size_t broad_route_deletes{0U};
    std::size_t exact_route_deletes{0U};
    std::size_t broad_rule_deletes{0U};
    std::size_t exact_rule_deletes{0U};
    std::vector<std::string> events;
    std::vector<DumpedRoute> routes;
    std::vector<DumpedRule> rules;

private:
    void observe_write() {
        if (before_write) before_write();
    }

    void erase_route_slot(const RouteSpec& spec) {
        routes.erase(
            std::remove_if(
                routes.begin(),
                routes.end(),
                [&](const DumpedRoute& route) {
                    return same_route_slot(spec, route);
                }),
            routes.end());
    }

    void erase_rule(const RuleSpec& spec, int family) {
        rules.erase(
            std::remove_if(
                rules.begin(),
                rules.end(),
                [&](const DumpedRule& rule) {
                    return exact_rule(spec, family, rule);
                }),
            rules.end());
    }

    static DumpedRoute to_live(const RouteSpec& spec) {
        DumpedRoute route;
        route.destination = spec.destination;
        route.table = spec.table;
        route.interface = spec.interface;
        route.gateway = spec.gateway;
        route.blackhole = spec.blackhole;
        route.unreachable = spec.unreachable;
        route.family = spec.family;
        route.metric = spec.metric;
        route.protocol = spec.protocol;
        route.exact_identity_representable = true;
        return route;
    }

    static DumpedRule to_live(const RuleSpec& spec, int family) {
        DumpedRule rule;
        rule.priority = spec.priority;
        rule.fwmark = spec.fwmark;
        rule.fwmask = spec.fwmask;
        rule.table = spec.table;
        rule.family = family;
        rule.exact_identity_representable = true;
        return rule;
    }
};

RouteSpec exact_owner_route(std::uint32_t table) {
    RouteSpec route;
    route.destination = "default";
    route.table = table;
    route.blackhole = true;
    route.family = AF_INET;
    return route;
}

RuleSpec exact_owner_rule(std::uint32_t table) {
    RuleSpec rule;
    rule.fwmark = 0x00070000U;
    rule.fwmask = 0x00FF0000U;
    rule.table = table;
    rule.priority = table;
    rule.family = AF_INET;
    return rule;
}

RuntimeRoutingOperationRequest exact_owner_request(
    std::uint64_t operation,
    std::uint64_t intent,
    std::uint64_t revision,
    std::uint64_t route_epoch,
    std::uint32_t table) {
    RuntimeRoutingOperationRequest request;
    request.identity.operation_serial = operation;
    request.identity.runtime_generation = 7U;
    request.identity.intent_serial = intent;
    request.identity.base_inventory_revision = revision;
    request.identity.route_epoch = route_epoch;
    request.desired_routes.push_back(exact_owner_route(table));
    request.desired_rules.push_back(exact_owner_rule(table));
    request.authorized_external_tables.push_back(
        RuntimeRoutingExternalTableAuthority{999U, AF_INET});
    return request;
}

RuntimeRoutingCurrentFence exact_owner_fence(
    const RuntimeRoutingOperationRequest& request,
    std::uint64_t last_operation) {
    RuntimeRoutingCurrentFence fence;
    fence.last_operation_serial = last_operation;
    fence.runtime_generation = request.identity.runtime_generation;
    fence.intent_serial = request.identity.intent_serial;
    fence.inventory_revision = request.identity.base_inventory_revision;
    fence.route_epoch = request.identity.route_epoch;
    return fence;
}

RuntimeRoutingOperationResult run_exact(
    RuntimeRoutingOperationOwner& owner,
    const RuntimeRoutingOperationRequest& request,
    std::uint64_t last_operation) {
    const auto fence = exact_owner_fence(request, last_operation);
    return owner.reconcile_exact(request, [fence]() { return fence; });
}

} // namespace

TEST_CASE("exact routing owner retains its journal before the first write") {
    ExactOwnerNetlink netlink;
    RuntimeRoutingOperationOwner owner(netlink, netlink);
    const auto request = exact_owner_request(1U, 101U, 1U, 11U, 151U);
    bool journal_was_visible_before_write = false;
    netlink.before_write = [&]() {
        const auto journal = owner.exact_journal();
        REQUIRE(static_cast<bool>(journal));
        CHECK(journal->identity.operation_serial == 1U);
        CHECK(journal->mutation_started.load(std::memory_order_relaxed));
        journal_was_visible_before_write = true;
    };

    const auto result = run_exact(owner, request, 0U);

    CHECK(journal_was_visible_before_write);
    CHECK(
        result.outcome ==
        RuntimeRoutingOperationOutcome::exact_candidate_committed);
    REQUIRE(static_cast<bool>(result.exact_journal));
    CHECK(result.exact_journal.get() == owner.exact_journal().get());
    CHECK(
        result.exact_journal->acquire_terminal() ==
        RuntimeRoutingTerminal::candidate_committed);
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(result.inventory->revision == 2U);
    CHECK(
        classify_runtime_routing_inventory(result.inventory) ==
        RuntimeRoutingInventoryAuthority::authoritative);
    REQUIRE(result.inventory->routes.size() == 1U);
    REQUIRE(result.inventory->rules.size() == 1U);
    CHECK(result.inventory->routes.front().table == 151U);
    CHECK(result.inventory->rules.front().table == 151U);
}

TEST_CASE("exact routing owner consumes stale identities only once") {
    ExactOwnerNetlink netlink;
    RuntimeRoutingOperationOwner owner(netlink, netlink);
    const auto first = exact_owner_request(1U, 101U, 1U, 11U, 151U);
    REQUIRE(
        run_exact(owner, first, 0U).outcome ==
        RuntimeRoutingOperationOutcome::exact_candidate_committed);
    netlink.events.clear();

    const auto replay = run_exact(owner, first, 0U);
    CHECK(
        replay.outcome ==
        RuntimeRoutingOperationOutcome::rejected_replay);
    CHECK(netlink.events.empty());

    const auto stale = exact_owner_request(2U, 102U, 1U, 12U, 152U);
    const auto stale_result = run_exact(owner, stale, 1U);
    CHECK(
        stale_result.outcome ==
        RuntimeRoutingOperationOutcome::rejected_stale_inventory);
    CHECK(netlink.events.empty());

    auto rewritten = stale;
    rewritten.identity.base_inventory_revision = 2U;
    const auto rewritten_result = run_exact(owner, rewritten, 1U);
    CHECK(
        rewritten_result.outcome ==
        RuntimeRoutingOperationOutcome::rejected_replay);
    CHECK(netlink.events.empty());
}

TEST_CASE("exact routing owner maps a transaction fence miss without writes") {
    ExactOwnerNetlink netlink;
    RuntimeRoutingOperationOwner owner(netlink, netlink);
    const auto request = exact_owner_request(1U, 101U, 1U, 11U, 151U);
    auto fence = exact_owner_fence(request, 0U);
    ++fence.route_epoch;

    const auto result = owner.reconcile_exact(
        request, [fence]() { return fence; });

    CHECK(
        result.outcome ==
        RuntimeRoutingOperationOutcome::exact_stale_before_mutation);
    CHECK_FALSE(static_cast<bool>(result.exact_journal));
    CHECK(netlink.events.empty());
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(result.inventory->revision == 1U);
    CHECK(result.inventory->highest_consumed_operation_serial == 1U);
}

TEST_CASE("exact routing owner republishes the prior inventory after rollback") {
    ExactOwnerNetlink netlink;
    netlink.fail_rule_add_before_effect = true;
    RuntimeRoutingOperationOwner owner(netlink, netlink);
    const auto request = exact_owner_request(1U, 101U, 1U, 11U, 151U);

    const auto result = run_exact(owner, request, 0U);

    CHECK(
        result.outcome ==
        RuntimeRoutingOperationOutcome::exact_candidate_rolled_back);
    REQUIRE(static_cast<bool>(result.exact_journal));
    CHECK(
        result.exact_journal->acquire_terminal() ==
        RuntimeRoutingTerminal::candidate_rolled_back);
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(result.inventory->revision == 2U);
    CHECK(result.inventory->routes.empty());
    CHECK(result.inventory->rules.empty());
    CHECK(
        classify_runtime_routing_inventory(result.inventory) ==
        RuntimeRoutingInventoryAuthority::authoritative);
    CHECK(netlink.routes.empty());
    CHECK(netlink.rules.empty());
}

TEST_CASE("exact routing owner makes a drifted rollback preimage non-authoritative") {
    ExactOwnerNetlink netlink;
    RuntimeRoutingOperationOwner owner(netlink, netlink);
    const auto first = exact_owner_request(1U, 101U, 1U, 11U, 151U);
    const auto committed = run_exact(owner, first, 0U);
    REQUIRE(
        committed.outcome ==
        RuntimeRoutingOperationOutcome::exact_candidate_committed);

    // Simulate firmware removing the previously published generation before
    // the next candidate. A successful undo of only the new candidate cannot
    // prove that this older preimage came back.
    netlink.routes.clear();
    netlink.rules.clear();
    netlink.events.clear();
    netlink.fail_rule_add_before_effect = true;
    const auto second = exact_owner_request(
        2U, 102U, committed.inventory->revision, 12U, 152U);

    const auto result = run_exact(owner, second, 1U);

    CHECK(
        result.outcome ==
        RuntimeRoutingOperationOutcome::exact_partial_unknown);
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(
        classify_runtime_routing_inventory(result.inventory) !=
        RuntimeRoutingInventoryAuthority::authoritative);
    REQUIRE(static_cast<bool>(result.exact_journal));
    CHECK(
        result.exact_journal->acquire_terminal() ==
        RuntimeRoutingTerminal::partial_unknown);
}

TEST_CASE("exact routing owner invalidates a drifted base at raw preflight") {
    ExactOwnerNetlink netlink;
    RuntimeRoutingOperationOwner owner(netlink, netlink);
    const auto first = exact_owner_request(1U, 101U, 1U, 11U, 151U);
    const auto committed = run_exact(owner, first, 0U);
    REQUIRE(
        committed.outcome ==
        RuntimeRoutingOperationOutcome::exact_candidate_committed);
    REQUIRE(netlink.routes.size() == 1U);

    netlink.routes.front().blackhole = false;
    netlink.routes.front().unreachable = true;
    netlink.routes.front().exact_identity_representable = false;
    netlink.events.clear();
    const auto second = exact_owner_request(
        2U, 102U, committed.inventory->revision, 12U, 151U);

    const auto result = run_exact(owner, second, 1U);

    CHECK(
        result.outcome ==
        RuntimeRoutingOperationOutcome::exact_precondition_failed);
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(
        classify_runtime_routing_inventory(result.inventory) !=
        RuntimeRoutingInventoryAuthority::authoritative);
    CHECK(netlink.events.empty());
}

TEST_CASE("exact routing owner rejects an extra generated route after rollback") {
    ExactOwnerNetlink netlink;
    RuntimeRoutingOperationOwner owner(netlink, netlink);
    const auto first = exact_owner_request(1U, 101U, 1U, 11U, 151U);
    const auto committed = run_exact(owner, first, 0U);
    REQUIRE(
        committed.outcome ==
        RuntimeRoutingOperationOutcome::exact_candidate_committed);

    const auto extra_spec = exact_owner_route(199U);
    DumpedRoute extra;
    extra.destination = extra_spec.destination;
    extra.table = extra_spec.table;
    extra.interface = extra_spec.interface;
    extra.gateway = extra_spec.gateway;
    extra.blackhole = extra_spec.blackhole;
    extra.unreachable = extra_spec.unreachable;
    extra.family = extra_spec.family;
    extra.metric = extra_spec.metric;
    extra.protocol = KEEN_PBR_GENERATED_ROUTE_PROTOCOL;
    extra.exact_identity_representable = true;
    netlink.routes.push_back(std::move(extra));
    netlink.events.clear();
    netlink.fail_rule_add_before_effect = true;
    const auto second = exact_owner_request(
        2U, 102U, committed.inventory->revision, 12U, 152U);

    const auto result = run_exact(owner, second, 1U);

    CHECK(
        result.outcome ==
        RuntimeRoutingOperationOutcome::exact_partial_unknown);
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(
        classify_runtime_routing_inventory(result.inventory) !=
        RuntimeRoutingInventoryAuthority::authoritative);
    CHECK(std::any_of(
        netlink.routes.begin(), netlink.routes.end(),
        [](const DumpedRoute& route) { return route.table == 199U; }));
}

TEST_CASE("exact routing owner makes an ambiguous effect non-authoritative") {
    ExactOwnerNetlink netlink;
    netlink.fail_route_add_after_effect = true;
    netlink.force_route_delete_precondition = true;
    RuntimeRoutingOperationOwner owner(netlink, netlink);
    const auto request = exact_owner_request(1U, 101U, 1U, 11U, 151U);

    const auto result = run_exact(owner, request, 0U);

    CHECK(
        result.outcome ==
        RuntimeRoutingOperationOutcome::exact_partial_unknown);
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(result.inventory->revision == 2U);
    CHECK_FALSE(result.inventory->inventory_complete);
    CHECK_FALSE(result.inventory->kernel_state_known);
    REQUIRE(static_cast<bool>(result.exact_journal));
    CHECK(
        result.exact_journal->acquire_terminal() ==
        RuntimeRoutingTerminal::partial_unknown);

    netlink.fail_route_add_after_effect = false;
    netlink.force_route_delete_precondition = false;
    const auto recovery = exact_owner_request(
        2U, 102U, result.inventory->revision, 12U, 151U);
    const auto recovered = run_exact(owner, recovery, 1U);

    CHECK(
        recovered.outcome ==
        RuntimeRoutingOperationOutcome::exact_candidate_committed);
    REQUIRE(static_cast<bool>(recovered.inventory));
    CHECK(
        classify_runtime_routing_inventory(recovered.inventory) ==
        RuntimeRoutingInventoryAuthority::authoritative);
    REQUIRE(netlink.routes.size() == 1U);
    REQUIRE(netlink.rules.size() == 1U);
    CHECK(netlink.routes.front().table == 151U);
    CHECK(netlink.rules.front().table == 151U);
}

TEST_CASE(
    "exact routing owner retains observed rule ownership until exact recovery") {
    ExactOwnerNetlink netlink;
    netlink.fail_rule_add_after_effect = true;
    netlink.force_rule_delete_precondition = true;
    RuntimeRoutingOperationOwner owner(netlink, netlink);
    const auto request = exact_owner_request(1U, 101U, 1U, 11U, 151U);

    const auto result = run_exact(owner, request, 0U);

    CHECK(
        result.outcome ==
        RuntimeRoutingOperationOutcome::exact_partial_unknown);
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(
        classify_runtime_routing_inventory(result.inventory) !=
        RuntimeRoutingInventoryAuthority::authoritative);
    REQUIRE(netlink.rules.size() == 1U);
    REQUIRE(netlink.routes.size() == 1U);
    CHECK(netlink.broad_rule_deletes == 0U);
    CHECK(netlink.broad_route_deletes == 0U);

    netlink.fail_rule_add_after_effect = false;
    netlink.force_rule_delete_precondition = false;
    netlink.events.clear();
    (void)owner.clear();

    CHECK(netlink.rules.empty());
    CHECK(netlink.routes.empty());
    CHECK(netlink.broad_rule_deletes == 0U);
    CHECK(netlink.broad_route_deletes == 0U);
    CHECK(std::any_of(
        netlink.events.begin(),
        netlink.events.end(),
        [](const std::string& event) {
            return event.find("rule:delete:") == 0U;
        }));
    CHECK(std::any_of(
        netlink.events.begin(),
        netlink.events.end(),
        [](const std::string& event) {
            return event.find("route:delete:") == 0U;
        }));
}

TEST_CASE("exact routing owner does not publish desired state while cleanup is pending") {
    ExactOwnerNetlink netlink;
    RuntimeRoutingOperationOwner owner(netlink, netlink);
    const auto first = exact_owner_request(1U, 101U, 1U, 11U, 150U);
    REQUIRE(
        run_exact(owner, first, 0U).outcome ==
        RuntimeRoutingOperationOutcome::exact_candidate_committed);

    netlink.force_rule_delete_precondition = true;
    const auto second = exact_owner_request(2U, 102U, 2U, 12U, 151U);
    const auto result = run_exact(owner, second, 1U);

    CHECK(
        result.outcome ==
        RuntimeRoutingOperationOutcome::exact_committed_cleanup_pending);
    REQUIRE(static_cast<bool>(result.exact_journal));
    CHECK(
        result.exact_journal->acquire_terminal() ==
        RuntimeRoutingTerminal::committed_cleanup_pending);
    REQUIRE(static_cast<bool>(result.inventory));
    CHECK(result.inventory->revision == 3U);
    CHECK_FALSE(result.inventory->inventory_complete);
    CHECK_FALSE(result.inventory->kernel_state_known);
    REQUIRE(result.inventory->routes.size() == 1U);
    CHECK(result.inventory->routes.front().table == 150U);

    netlink.force_rule_delete_precondition = false;
    const auto recovery = exact_owner_request(
        3U, 103U, result.inventory->revision, 13U, 151U);
    const auto recovered = run_exact(owner, recovery, 2U);

    CHECK(
        recovered.outcome ==
        RuntimeRoutingOperationOutcome::exact_candidate_committed);
    REQUIRE(static_cast<bool>(recovered.inventory));
    CHECK(
        classify_runtime_routing_inventory(recovered.inventory) ==
        RuntimeRoutingInventoryAuthority::authoritative);
    REQUIRE(netlink.routes.size() == 1U);
    REQUIRE(netlink.rules.size() == 1U);
    CHECK(netlink.routes.front().table == 151U);
    CHECK(netlink.rules.front().table == 151U);
}

TEST_CASE("exact routing owner adopts only policy rules with a Created receipt") {
    SUBCASE("an identical pre-existing rule remains foreign") {
        ExactOwnerNetlink netlink;
        const auto logical = exact_owner_rule(151U);
        DumpedRule foreign;
        foreign.priority = logical.priority;
        foreign.fwmark = logical.fwmark;
        foreign.fwmask = logical.fwmask;
        foreign.table = logical.table;
        foreign.family = logical.family;
        foreign.exact_identity_representable = true;
        netlink.rules.push_back(foreign);

        RuntimeRoutingOperationOwner owner(netlink, netlink);
        const auto request =
            exact_owner_request(1U, 101U, 1U, 11U, 151U);
        REQUIRE(
            run_exact(owner, request, 0U).outcome ==
            RuntimeRoutingOperationOutcome::exact_candidate_committed);

        netlink.events.clear();
        (void)owner.clear();
        CHECK(netlink.rules.size() == 1U);
        CHECK(std::none_of(
            netlink.events.begin(),
            netlink.events.end(),
            [](const std::string& event) {
                return event.find("rule:delete:") == 0U;
            }));
    }

    SUBCASE("a rule created by the exact transaction is removed by clear") {
        ExactOwnerNetlink netlink;
        RuntimeRoutingOperationOwner owner(netlink, netlink);
        const auto request =
            exact_owner_request(1U, 101U, 1U, 11U, 151U);
        REQUIRE(
            run_exact(owner, request, 0U).outcome ==
            RuntimeRoutingOperationOutcome::exact_candidate_committed);
        REQUIRE(netlink.rules.size() == 1U);

        netlink.events.clear();
        (void)owner.clear();
        CHECK(netlink.rules.empty());
        CHECK(netlink.routes.empty());
        CHECK(netlink.broad_rule_deletes == 0U);
        CHECK(netlink.broad_route_deletes == 0U);
        CHECK(netlink.exact_rule_deletes == 1U);
        CHECK(netlink.exact_route_deletes == 1U);
        CHECK(std::any_of(
            netlink.events.begin(),
            netlink.events.end(),
            [](const std::string& event) {
                return event.find("rule:delete:") == 0U;
            }));
    }
}
