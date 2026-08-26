#include <doctest/doctest.h>

#include "../src/routing/runtime_routing_transaction.hpp"
#include "../src/routing/policy_rule.hpp"
#include "../src/routing/route_table.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

enum class FaultTiming {
    none,
    before_effect,
    after_effect,
};

std::uint32_t fake_kernel_metric(std::uint32_t metric, int family) {
    return family == AF_INET6 && metric == 0U ? 1024U : metric;
}

bool fake_same_route_slot(
    const RouteSpec& expected,
    const DumpedRoute& actual) {
    return expected.destination == actual.destination &&
           expected.table == actual.table &&
           expected.family == actual.family &&
           fake_kernel_metric(expected.metric, expected.family) ==
               fake_kernel_metric(actual.metric, actual.family);
}

bool fake_exact_route_match(
    const RouteSpec& expected,
    const DumpedRoute& actual) {
    return actual.exact_identity_representable &&
           fake_same_route_slot(expected, actual) &&
           expected.interface == actual.interface &&
           expected.gateway == actual.gateway &&
           expected.blackhole == actual.blackhole &&
           expected.unreachable == actual.unreachable &&
           expected.protocol == actual.protocol;
}

class ScriptedRoutingNetlink final
    : public RouteNetlinkOperations,
      public RuleNetlinkOperations {
public:
    bool supports_exact_route_transaction() const noexcept override {
        return exact_route_capability;
    }

    bool supports_exact_rule_transaction() const noexcept override {
        return exact_rule_capability;
    }

    RouteAddResult add_route(const RouteSpec& spec) override {
        events.push_back("route:add:" + std::to_string(spec.table));
        if (route_add_fault_table == spec.table &&
            route_add_fault == FaultTiming::before_effect) {
            throw std::runtime_error("route add before effect");
        }
        const bool occupied = std::any_of(
            routes.begin(), routes.end(), [&](const DumpedRoute& route) {
                return fake_same_route_slot(spec, route);
            });
        if (occupied) return RouteAddResult::AlreadyPresent;
        routes.push_back(to_live(spec));
        if (route_add_fault_table == spec.table &&
            route_add_fault == FaultTiming::after_effect) {
            throw std::runtime_error("route add after effect");
        }
        return RouteAddResult::Created;
    }

    void replace_route(const RouteSpec& spec) override {
        events.push_back("route:replace:" + std::to_string(spec.table));
        if (route_replace_fault_table == spec.table &&
            route_replace_fault == FaultTiming::before_effect) {
            throw std::runtime_error("route replace before effect");
        }
        routes.erase(
            std::remove_if(
                routes.begin(), routes.end(), [&](const DumpedRoute& route) {
                    return fake_same_route_slot(spec, route);
                }),
            routes.end());
        routes.push_back(to_live(spec));
        if (route_replace_fault_table == spec.table &&
            route_replace_fault == FaultTiming::after_effect) {
            throw std::runtime_error("route replace after effect");
        }
    }

    void delete_route(const RouteSpec& spec) override {
        events.push_back("route:delete:" + std::to_string(spec.table));
        if (route_delete_fault_table == spec.table &&
            route_delete_fault == FaultTiming::before_effect) {
            throw std::runtime_error("route delete before effect");
        }
        // Model the kernel key conservatively: deleting an obsolete image can
        // remove a replacement in the same slot even when nexthop/type differ.
        routes.erase(
            std::remove_if(
                routes.begin(), routes.end(), [&](const DumpedRoute& route) {
                    return fake_same_route_slot(spec, route);
                }),
            routes.end());
        if (route_delete_fault_table == spec.table &&
            route_delete_fault == FaultTiming::after_effect) {
            throw std::runtime_error("route delete after effect");
        }
    }

    RouteExactDeleteResult delete_route_if_exact(
        const RouteSpec& spec) override {
        events.push_back("route:delete:" + std::to_string(spec.table));
        if (route_delete_fault_table == spec.table &&
            route_delete_fault == FaultTiming::before_effect) {
            throw std::runtime_error("route delete before effect");
        }
        if (before_exact_route_delete) before_exact_route_delete(spec);
        std::size_t slot_count = 0U;
        bool exact = false;
        for (const auto& route : routes) {
            if (!fake_same_route_slot(spec, route)) {
                continue;
            }
            ++slot_count;
            exact = exact || fake_exact_route_match(spec, route);
        }
        if (slot_count == 0U) {
            return RouteExactDeleteResult::AlreadyAbsent;
        }
        if (slot_count != 1U || !exact) {
            return RouteExactDeleteResult::PreconditionMismatch;
        }
        routes.erase(
            std::remove_if(
                routes.begin(), routes.end(), [&](const DumpedRoute& route) {
                    return fake_exact_route_match(spec, route);
                }),
            routes.end());
        if (route_delete_fault_table == spec.table &&
            route_delete_fault == FaultTiming::after_effect) {
            throw std::runtime_error("route delete after effect");
        }
        return RouteExactDeleteResult::Deleted;
    }

    RouteExactReplaceResult replace_route_if_exact(
        const RouteSpec& expected,
        const RouteSpec& replacement) override {
        events.push_back(
            "route:replace:" + std::to_string(replacement.table));
        if (route_replace_fault_table == replacement.table &&
            route_replace_fault == FaultTiming::before_effect) {
            throw std::runtime_error("route replace before effect");
        }
        if (before_exact_route_replace) {
            before_exact_route_replace(expected, replacement);
        }
        std::size_t slot_count = 0U;
        bool exact = false;
        for (const auto& route : routes) {
            if (!fake_same_route_slot(expected, route)) {
                continue;
            }
            ++slot_count;
            exact = exact || fake_exact_route_match(expected, route);
        }
        if (slot_count != 1U || !exact) {
            return RouteExactReplaceResult::PreconditionMismatch;
        }
        routes.erase(
            std::remove_if(
                routes.begin(), routes.end(), [&](const DumpedRoute& route) {
                    return fake_exact_route_match(expected, route);
                }),
            routes.end());
        routes.push_back(to_live(replacement));
        if (route_replace_fault_table == replacement.table &&
            route_replace_fault == FaultTiming::after_effect) {
            throw std::runtime_error("route replace after effect");
        }
        return RouteExactReplaceResult::Replaced;
    }

    std::vector<DumpedRoute> dump_routes(int family = 0) override {
        if (before_dump_routes) before_dump_routes(family);
        if (family == 0) return routes;
        std::vector<DumpedRoute> result;
        std::copy_if(
            routes.begin(), routes.end(), std::back_inserter(result),
            [family](const DumpedRoute& route) {
                return route.family == family;
            });
        return result;
    }

    RuleAddResult add_rule_for_family(
        const RuleSpec& spec,
        int family) override {
        events.push_back("rule:add:" + std::to_string(spec.table));
        if (rule_add_fault_priority == spec.priority &&
            rule_add_fault == FaultTiming::before_effect) {
            throw std::runtime_error("rule add before effect");
        }
        if (has_rule(spec, family)) return RuleAddResult::AlreadyPresent;
        rules.push_back(to_live(spec, family));
        if (rule_add_fault_priority == spec.priority &&
            rule_add_fault == FaultTiming::after_effect) {
            throw std::runtime_error("rule add after effect");
        }
        return RuleAddResult::Created;
    }

    void delete_rule_for_family(
        const RuleSpec& spec,
        int family) override {
        events.push_back("rule:delete:" + std::to_string(spec.table));
        if (rule_delete_fault_priority == spec.priority &&
            rule_delete_fault == FaultTiming::before_effect) {
            throw std::runtime_error("rule delete before effect");
        }
        rules.erase(
            std::remove_if(
                rules.begin(), rules.end(), [&](const DumpedRule& rule) {
                    return policy_rule_detail::rule_matches_live(spec, rule) &&
                           rule.family == family;
                }),
            rules.end());
        if (rule_delete_fault_priority == spec.priority &&
            rule_delete_fault == FaultTiming::after_effect) {
            throw std::runtime_error("rule delete after effect");
        }
    }

    RuleExactDeleteResult delete_rule_if_exact(
        const RuleSpec& spec,
        int family) override {
        events.push_back("rule:delete:" + std::to_string(spec.table));
        if (rule_delete_fault_priority == spec.priority &&
            rule_delete_fault == FaultTiming::before_effect) {
            throw std::runtime_error("rule delete before effect");
        }
        if (before_exact_rule_delete) {
            before_exact_rule_delete(spec, family);
        }
        RuleSpec concrete = spec;
        concrete.family = family;
        std::size_t identity_count = 0U;
        bool exact = false;
        for (const auto& rule : rules) {
            const bool same_identity =
                rule.priority == concrete.priority &&
                rule.fwmark == concrete.fwmark &&
                rule.fwmask == concrete.fwmask &&
                rule.table == concrete.table &&
                rule.family == concrete.family;
            if (!same_identity) continue;
            ++identity_count;
            exact = exact ||
                (rule.exact_identity_representable &&
                 policy_rule_detail::rule_matches_live(concrete, rule));
        }
        if (identity_count == 0U) {
            return RuleExactDeleteResult::AlreadyAbsent;
        }
        if (identity_count != 1U || !exact) {
            return RuleExactDeleteResult::PreconditionMismatch;
        }
        rules.erase(
            std::remove_if(
                rules.begin(), rules.end(), [&](const DumpedRule& rule) {
                    return rule.exact_identity_representable &&
                           policy_rule_detail::rule_matches_live(
                               concrete, rule);
                }),
            rules.end());
        if (rule_delete_fault_priority == spec.priority &&
            rule_delete_fault == FaultTiming::after_effect) {
            throw std::runtime_error("rule delete after effect");
        }
        return RuleExactDeleteResult::Deleted;
    }

    std::vector<DumpedRule> dump_policy_rules(int family = 0) override {
        if (family == 0) return rules;
        std::vector<DumpedRule> result;
        std::copy_if(
            rules.begin(), rules.end(), std::back_inserter(result),
            [family](const DumpedRule& rule) {
                return rule.family == family;
            });
        return result;
    }

    void seed_route(const RouteSpec& spec, std::uint8_t protocol =
                    KEEN_PBR_GENERATED_ROUTE_PROTOCOL) {
        auto route = to_live(spec);
        route.protocol = protocol;
        routes.push_back(std::move(route));
    }

    void seed_rule(const RuleSpec& spec, int family = AF_INET) {
        rules.push_back(to_live(spec, family));
    }

    bool has_route(const RouteSpec& spec) const {
        return std::any_of(
            routes.begin(), routes.end(), [&](const DumpedRoute& route) {
                return fake_exact_route_match(spec, route);
            });
    }

    bool has_exact_rule(const RuleSpec& spec) const {
        return std::any_of(
            rules.begin(), rules.end(), [&](const DumpedRule& rule) {
                return rule.exact_identity_representable &&
                       policy_rule_detail::rule_matches_live(spec, rule);
            });
    }

    std::optional<std::uint32_t> route_add_fault_table;
    bool exact_route_capability{true};
    bool exact_rule_capability{true};
    FaultTiming route_add_fault{FaultTiming::none};
    std::optional<std::uint32_t> route_replace_fault_table;
    FaultTiming route_replace_fault{FaultTiming::none};
    std::optional<std::uint32_t> route_delete_fault_table;
    FaultTiming route_delete_fault{FaultTiming::none};
    std::optional<std::uint32_t> rule_add_fault_priority;
    FaultTiming rule_add_fault{FaultTiming::none};
    std::optional<std::uint32_t> rule_delete_fault_priority;
    FaultTiming rule_delete_fault{FaultTiming::none};
    std::function<void(const RouteSpec&)> before_exact_route_delete;
    std::function<void(const RouteSpec&, const RouteSpec&)>
        before_exact_route_replace;
    std::function<void(const RuleSpec&, int)> before_exact_rule_delete;
    std::function<void(int)> before_dump_routes;
    std::vector<std::string> events;
    std::vector<DumpedRoute> routes;
    std::vector<DumpedRule> rules;

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

    static DumpedRule to_live(const RuleSpec& spec, int family) {
        return DumpedRule{
            spec.priority,
            spec.fwmark,
            spec.fwmask,
            spec.table,
            family};
    }

    bool has_rule(const RuleSpec& spec, int family) const {
        RuleSpec concrete = spec;
        concrete.family = family;
        return has_exact_rule(concrete);
    }
};

RouteSpec transaction_route(std::uint32_t table) {
    RouteSpec route;
    route.destination = "default";
    route.table = table;
    route.blackhole = true;
    route.family = AF_INET;
    return route;
}

RuleSpec transaction_rule(
    std::uint32_t table,
    std::uint32_t fwmark = 0x00070000U) {
    RuleSpec rule;
    rule.fwmark = fwmark;
    rule.fwmask = 0x00FF0000U;
    rule.table = table;
    rule.priority = table;
    rule.family = AF_INET;
    return rule;
}

RuntimeRoutingTransactionRequest transaction_request(
    std::vector<RouteSpec> routes,
    std::vector<RuleSpec> rules) {
    RuntimeRoutingTransactionRequest request;
    request.identity.operation_serial = 1U;
    request.identity.runtime_generation = 7U;
    request.identity.intent_serial = 101U;
    request.identity.base_inventory_revision = 4U;
    request.identity.route_epoch = 11U;
    request.desired_routes = std::move(routes);
    request.desired_rules = std::move(rules);
    return request;
}

RuntimeRoutingCurrentFence current_fence() {
    RuntimeRoutingCurrentFence fence;
    fence.last_operation_serial = 0U;
    fence.runtime_generation = 7U;
    fence.intent_serial = 101U;
    fence.inventory_revision = 4U;
    fence.route_epoch = 11U;
    return fence;
}

RuntimeRoutingTransactionResult run_transaction(
    const RuntimeRoutingTransactionRequest& request,
    ScriptedRoutingNetlink& netlink) {
    const auto fence = current_fence();
    RuntimeRoutingPublishedJournalPtr retained;
    return execute_runtime_routing_transaction(
        request,
        [fence]() { return fence; },
        netlink,
        netlink,
        [&](const RuntimeRoutingPublishedJournalPtr& journal) {
            retained = journal;
            return true;
        });
}

} // namespace

TEST_CASE("runtime routing transaction commits candidate before stale cleanup") {
    ScriptedRoutingNetlink netlink;
    const auto old_route = transaction_route(150U);
    const auto old_rule = transaction_rule(150U);
    const auto desired_route = transaction_route(151U);
    const auto desired_rule = transaction_rule(151U);
    netlink.seed_route(old_route);
    netlink.seed_rule(old_rule);

    auto request = transaction_request({desired_route}, {desired_rule});
    request.prior_owned_rules.push_back(old_rule);
    const auto result = run_transaction(request, netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::candidate_committed);
    CHECK(result.candidate_exact_verified);
    CHECK(result.stale_rule_absence_proven);
    CHECK(result.route_cleanup_attempted);
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151",
        "rule:add:151",
        "rule:delete:150",
        "route:delete:150"});
    CHECK(netlink.has_route(desired_route));
    CHECK(netlink.has_exact_rule(desired_rule));
    CHECK_FALSE(netlink.has_route(old_route));
    CHECK_FALSE(netlink.has_exact_rule(old_rule));
}

TEST_CASE("runtime routing transaction rechecks the fence before the first write") {
    ScriptedRoutingNetlink netlink;
    const auto request = transaction_request(
        {transaction_route(151U)}, {transaction_rule(151U)});
    auto fence = current_fence();
    int probes = 0;
    RuntimeRoutingPublishedJournalPtr retained;

    const auto result = execute_runtime_routing_transaction(
        request,
        [&]() {
            ++probes;
            auto observed = fence;
            if (probes >= 2) ++observed.route_epoch;
            return observed;
        },
        netlink,
        netlink,
        [&](const RuntimeRoutingPublishedJournalPtr& journal) {
            retained = journal;
            return true;
        });

    CHECK(result.terminal == RuntimeRoutingTerminal::stale_before_mutation);
    CHECK(
        result.stale_reason ==
        RuntimeRoutingStaleReason::route_epoch_changed);
    CHECK_FALSE(result.mutation_started);
    CHECK(netlink.events.empty());
}

TEST_CASE("runtime routing transaction refuses an incapable backend before mutation") {
    const auto request = transaction_request(
        {transaction_route(151U)}, {transaction_rule(151U)});

    for (const bool missing_route_capability : {true, false}) {
        ScriptedRoutingNetlink netlink;
        netlink.exact_route_capability = !missing_route_capability;
        netlink.exact_rule_capability = missing_route_capability;

        const auto result = run_transaction(request, netlink);

        CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
        CHECK_FALSE(result.mutation_started);
        CHECK_FALSE(result.candidate_exact_verified);
        CHECK(result.detail.find("capabilities") != std::string::npos);
        CHECK(netlink.events.empty());
        CHECK(netlink.routes.empty());
        CHECK(netlink.rules.empty());
        CHECK_FALSE(static_cast<bool>(result.published_journal));
        CHECK(result.journal.empty());
    }
}

TEST_CASE("runtime routing transaction requires one combined capable backend") {
    ScriptedRoutingNetlink route_backend;
    ScriptedRoutingNetlink rule_backend;
    const auto request = transaction_request(
        {transaction_route(151U)}, {transaction_rule(151U)});
    const auto fence = current_fence();
    bool published = false;

    const auto result = execute_runtime_routing_transaction(
        request,
        [fence]() { return fence; },
        route_backend,
        rule_backend,
        [&](const RuntimeRoutingPublishedJournalPtr&) {
            published = true;
            return true;
        });

    CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
    CHECK_FALSE(result.mutation_started);
    CHECK_FALSE(result.candidate_exact_verified);
    CHECK(result.detail.find("capabilities") != std::string::npos);
    CHECK(route_backend.events.empty());
    CHECK(rule_backend.events.empty());
    CHECK_FALSE(published);
    CHECK_FALSE(static_cast<bool>(result.published_journal));
    CHECK(result.journal.empty());
}

TEST_CASE("runtime routing transaction rejects a foreign route collision") {
    ScriptedRoutingNetlink netlink;
    const auto desired = transaction_route(151U);
    netlink.seed_route(desired, 4U);

    const auto result = run_transaction(
        transaction_request({desired}, {transaction_rule(151U)}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
    CHECK_FALSE(result.mutation_started);
    CHECK(netlink.events.empty());
    REQUIRE(netlink.routes.size() == 1U);
    CHECK(netlink.routes.front().protocol == 4U);
}

TEST_CASE("runtime routing transaction rejects an additional initial slot image") {
    ScriptedRoutingNetlink netlink;
    const auto desired = transaction_route(151U);
    auto additional = desired;
    additional.blackhole = false;
    additional.unreachable = true;
    netlink.seed_route(desired);
    netlink.seed_route(additional);

    const auto result = run_transaction(
        transaction_request({desired}, {transaction_rule(151U)}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
    CHECK_FALSE(result.mutation_started);
    CHECK(result.detail.find("only image") != std::string::npos);
    CHECK(netlink.events.empty());
    CHECK(netlink.routes.size() == 2U);
    CHECK_FALSE(static_cast<bool>(result.published_journal));
}

TEST_CASE("runtime routing transaction rejects IPv6 metric aliases in either desired order") {
    auto metric_zero = transaction_route(151U);
    metric_zero.family = AF_INET6;
    auto metric_default = metric_zero;
    metric_default.metric = 1024U;

    for (const auto reverse : {false, true}) {
        ScriptedRoutingNetlink netlink;
        const auto routes = reverse
            ? std::vector<RouteSpec>{metric_default, metric_zero}
            : std::vector<RouteSpec>{metric_zero, metric_default};
        const auto result = run_transaction(
            transaction_request(routes, {}), netlink);

        CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
        CHECK_FALSE(result.mutation_started);
        CHECK(result.detail.find("same kernel slot") != std::string::npos);
        CHECK(netlink.events.empty());
        CHECK(netlink.routes.empty());
        CHECK(netlink.rules.empty());
        CHECK_FALSE(static_cast<bool>(result.published_journal));
    }
}

TEST_CASE("runtime routing transaction rejects an unrepresentable managed-slot image") {
    ScriptedRoutingNetlink netlink;
    const auto desired = transaction_route(151U);
    netlink.seed_route(desired);
    REQUIRE(netlink.routes.size() == 1U);
    netlink.routes.front().exact_identity_representable = false;

    const auto result = run_transaction(
        transaction_request({desired}, {transaction_rule(151U)}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
    CHECK_FALSE(result.mutation_started);
    CHECK(netlink.events.empty());
    CHECK_FALSE(static_cast<bool>(result.published_journal));
}

TEST_CASE("runtime routing transaction rejects malformed terminal routes before mutation") {
    auto conflicting = transaction_route(151U);
    conflicting.unreachable = true;
    auto with_nexthop = transaction_route(152U);
    with_nexthop.gateway = "192.0.2.1";

    for (const auto& route : {conflicting, with_nexthop}) {
        ScriptedRoutingNetlink netlink;
        const auto result = run_transaction(
            transaction_request({route}, {}), netlink);

        CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
        CHECK_FALSE(result.mutation_started);
        CHECK_FALSE(result.candidate_exact_verified);
        CHECK(netlink.events.empty());
        CHECK(netlink.routes.empty());
        CHECK(netlink.rules.empty());
        CHECK_FALSE(static_cast<bool>(result.published_journal));
        CHECK(result.journal.empty());
    }
}

TEST_CASE("runtime routing transaction rejects noncanonical route text before mutation") {
    auto destination_alias = transaction_route(151U);
    destination_alias.destination = "0.0.0.0/0";
    auto gateway_alias = transaction_route(152U);
    gateway_alias.blackhole = false;
    gateway_alias.family = AF_INET6;
    gateway_alias.gateway = "2001:0db8::1";

    for (const auto& route : {destination_alias, gateway_alias}) {
        ScriptedRoutingNetlink netlink;
        const auto result = run_transaction(
            transaction_request({route}, {}), netlink);

        CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
        CHECK_FALSE(result.mutation_started);
        CHECK(result.detail.find("canonical") != std::string::npos);
        CHECK(netlink.events.empty());
        CHECK(netlink.routes.empty());
        CHECK(netlink.rules.empty());
        CHECK_FALSE(static_cast<bool>(result.published_journal));
        CHECK(result.journal.empty());
    }
}

TEST_CASE("runtime routing transaction rejects a zero-priority candidate rule") {
    ScriptedRoutingNetlink netlink;
    const auto route = transaction_route(151U);
    auto rule = transaction_rule(151U);
    rule.priority = 0U;

    const auto result = run_transaction(
        transaction_request({route}, {rule}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
    CHECK_FALSE(result.mutation_started);
    CHECK_FALSE(result.candidate_exact_verified);
    CHECK(result.detail.find("wildcard") != std::string::npos);
    CHECK(netlink.events.empty());
    CHECK(netlink.routes.empty());
    CHECK(netlink.rules.empty());
    CHECK_FALSE(static_cast<bool>(result.published_journal));
    CHECK(result.journal.empty());
}

TEST_CASE("runtime routing transaction rejects an unrepresentable same-base candidate rule") {
    ScriptedRoutingNetlink netlink;
    const auto route = transaction_route(151U);
    const auto rule = transaction_rule(151U);
    netlink.seed_route(route);
    netlink.seed_rule(rule);
    REQUIRE(netlink.rules.size() == 1U);
    netlink.rules.front().exact_identity_representable = false;

    const auto result = run_transaction(
        transaction_request({route}, {rule}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
    CHECK_FALSE(result.mutation_started);
    CHECK_FALSE(result.candidate_exact_verified);
    CHECK(result.detail.find("unrepresentable") != std::string::npos);
    CHECK(netlink.events.empty());
    CHECK(netlink.has_route(route));
    REQUIRE(netlink.rules.size() == 1U);
    CHECK_FALSE(netlink.rules.front().exact_identity_representable);
    CHECK(netlink.rules.front().table == rule.table);
    CHECK(netlink.rules.front().priority == rule.priority);
    CHECK_FALSE(static_cast<bool>(result.published_journal));
    CHECK(result.journal.empty());
}

TEST_CASE("runtime routing transaction rolls back created routes after a rule failure") {
    ScriptedRoutingNetlink netlink;
    const auto route = transaction_route(151U);
    const auto rule = transaction_rule(151U);
    netlink.rule_add_fault_priority = rule.priority;
    netlink.rule_add_fault = FaultTiming::before_effect;

    const auto result = run_transaction(
        transaction_request({route}, {rule}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::candidate_rolled_back);
    CHECK(result.mutation_started);
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151", "rule:add:151", "route:delete:151"});
    CHECK_FALSE(netlink.has_route(route));
    CHECK_FALSE(netlink.has_exact_rule(rule));
}

TEST_CASE("runtime routing transaction never rolls back a preexisting rule") {
    ScriptedRoutingNetlink netlink;
    const auto route = transaction_route(151U);
    const auto existing = transaction_rule(151U, 0x00070000U);
    auto failing = transaction_rule(151U, 0x00080000U);
    failing.priority = 152U;
    netlink.seed_rule(existing);
    netlink.rule_add_fault_priority = failing.priority;
    netlink.rule_add_fault = FaultTiming::before_effect;

    const auto result = run_transaction(
        transaction_request({route}, {existing, failing}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::candidate_rolled_back);
    CHECK(netlink.has_exact_rule(existing));
    CHECK(std::find(
        netlink.events.begin(), netlink.events.end(), "rule:delete:151") ==
        netlink.events.end());
    CHECK_FALSE(netlink.has_route(route));
}

TEST_CASE("runtime routing transaction blocks route cleanup while a stale rule remains") {
    ScriptedRoutingNetlink netlink;
    const auto old_route = transaction_route(150U);
    const auto old_rule = transaction_rule(150U);
    const auto desired_route = transaction_route(151U);
    const auto desired_rule = transaction_rule(151U);
    netlink.seed_route(old_route);
    netlink.seed_rule(old_rule);
    netlink.rule_delete_fault_priority = old_rule.priority;
    netlink.rule_delete_fault = FaultTiming::before_effect;

    auto request = transaction_request({desired_route}, {desired_rule});
    request.prior_owned_rules.push_back(old_rule);
    const auto result = run_transaction(request, netlink);

    CHECK(
        result.terminal ==
        RuntimeRoutingTerminal::committed_cleanup_pending);
    CHECK(result.candidate_exact_verified);
    CHECK_FALSE(result.stale_rule_absence_proven);
    CHECK_FALSE(result.route_cleanup_attempted);
    CHECK(netlink.has_route(old_route));
    CHECK(netlink.has_exact_rule(old_rule));
    CHECK(netlink.has_route(desired_route));
    CHECK(netlink.has_exact_rule(desired_rule));
    CHECK(std::find(
        netlink.events.begin(), netlink.events.end(), "route:delete:150") ==
        netlink.events.end());
}

TEST_CASE("runtime routing transaction restores a managed replacement after rule failure") {
    ScriptedRoutingNetlink netlink;
    const auto previous = transaction_route(160U);
    auto candidate = previous;
    candidate.blackhole = false;
    candidate.unreachable = true;
    const auto rule = transaction_rule(160U);
    netlink.seed_route(previous);
    netlink.rule_add_fault_priority = rule.priority;
    netlink.rule_add_fault = FaultTiming::before_effect;

    const auto result = run_transaction(
        transaction_request({candidate}, {rule}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::candidate_rolled_back);
    CHECK(netlink.events == std::vector<std::string>{
        "route:replace:160", "rule:add:160", "route:replace:160"});
    CHECK(netlink.has_route(previous));
    CHECK_FALSE(netlink.has_route(candidate));
}

TEST_CASE("runtime routing transaction retains an after-effect route as partial unknown") {
    ScriptedRoutingNetlink netlink;
    const auto route = transaction_route(151U);
    netlink.route_add_fault_table = route.table;
    netlink.route_add_fault = FaultTiming::after_effect;

    const auto result = run_transaction(
        transaction_request({route}, {transaction_rule(151U)}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::partial_unknown);
    CHECK(result.mutation_started);
    CHECK(netlink.has_route(route));
    CHECK(netlink.events == std::vector<std::string>{"route:add:151"});
    REQUIRE(static_cast<bool>(result.published_journal));
    CHECK(
        result.published_journal->terminal.load(std::memory_order_acquire) ==
        RuntimeRoutingTerminal::partial_unknown);
    const auto add_receipt = std::find_if(
        result.published_journal->entries.begin(),
        result.published_journal->entries.end(),
        [](const RuntimeRoutingJournalEntry& entry) {
            return entry.operation ==
                RuntimeRoutingJournalOperation::add_candidate_route;
        });
    REQUIRE(add_receipt != result.published_journal->entries.end());
    CHECK(
        add_receipt->receipt ==
        RuntimeRoutingJournalReceipt::effect_unknown);
}

TEST_CASE("runtime routing transaction never deletes an old same-slot replacement image") {
    ScriptedRoutingNetlink netlink;
    const auto previous = transaction_route(160U);
    auto candidate = previous;
    candidate.blackhole = false;
    candidate.unreachable = true;
    const auto rule = transaction_rule(160U);
    netlink.seed_route(previous);

    const auto result = run_transaction(
        transaction_request({candidate}, {rule}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::candidate_committed);
    CHECK(netlink.has_route(candidate));
    CHECK_FALSE(netlink.has_route(previous));
    CHECK(std::find(
        netlink.events.begin(), netlink.events.end(), "route:delete:160") ==
        netlink.events.end());
}

TEST_CASE("runtime routing transaction retains a different-mark route dependency") {
    ScriptedRoutingNetlink netlink;
    const auto old_route = transaction_route(150U);
    const auto old_rule = transaction_rule(150U, 0x00090000U);
    const auto desired_route = transaction_route(151U);
    const auto desired_rule = transaction_rule(151U, 0x00070000U);
    netlink.seed_route(old_route);
    netlink.seed_rule(old_rule);

    const auto result = run_transaction(
        transaction_request({desired_route}, {desired_rule}), netlink);

    CHECK(
        result.terminal ==
        RuntimeRoutingTerminal::committed_cleanup_pending);
    CHECK(result.candidate_exact_verified);
    CHECK_FALSE(result.stale_rule_absence_proven);
    CHECK_FALSE(result.route_cleanup_attempted);
    CHECK(netlink.has_route(old_route));
    CHECK(netlink.has_exact_rule(old_rule));
    CHECK(netlink.has_route(desired_route));
    CHECK(netlink.has_exact_rule(desired_rule));
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151", "rule:add:151"});
}

TEST_CASE("runtime routing transaction rejects a rule without explicit authority") {
    ScriptedRoutingNetlink netlink;
    const auto rule = transaction_rule(151U);

    const auto absent = run_transaction(
        transaction_request({}, {rule}), netlink);
    CHECK(absent.terminal == RuntimeRoutingTerminal::precondition_failed);
    CHECK_FALSE(absent.mutation_started);
    CHECK(netlink.events.empty());
    CHECK(absent.detail.find("route anchor") != std::string::npos);

    auto foreign = transaction_route(151U);
    foreign.protocol = 4U;
    netlink.seed_route(foreign, 4U);
    const auto foreign_without_grant = run_transaction(
        transaction_request({}, {rule}), netlink);
    CHECK(
        foreign_without_grant.terminal ==
        RuntimeRoutingTerminal::precondition_failed);
    CHECK(netlink.events.empty());

    auto wrong_family = transaction_route(151U);
    wrong_family.family = AF_INET6;
    const auto mismatched = run_transaction(
        transaction_request({wrong_family}, {rule}), netlink);
    CHECK(mismatched.terminal == RuntimeRoutingTerminal::precondition_failed);
    CHECK(netlink.events.empty());
}

TEST_CASE("runtime routing transaction accepts and observes an authorized external table") {
    ScriptedRoutingNetlink netlink;
    auto external = transaction_route(170U);
    external.protocol = 4U;
    netlink.seed_route(external, 4U);
    auto request = transaction_request({}, {transaction_rule(170U)});
    request.authorized_external_tables.push_back({170U, AF_INET});

    const auto result = run_transaction(request, netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::candidate_committed);
    CHECK(result.candidate_exact_verified);
    CHECK(netlink.has_exact_rule(transaction_rule(170U)));
    CHECK(netlink.events == std::vector<std::string>{"rule:add:170"});
}

TEST_CASE("runtime routing transaction retires an exact prior-owned external rule") {
    ScriptedRoutingNetlink netlink;
    auto external = transaction_route(170U);
    external.protocol = 4U;
    const auto prior = transaction_rule(170U, 0x00090000U);
    netlink.seed_route(external, 4U);
    netlink.seed_rule(prior);
    auto request = transaction_request({}, {});
    request.prior_owned_rules.push_back(prior);

    const auto result = run_transaction(request, netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::candidate_committed);
    CHECK_FALSE(netlink.has_exact_rule(prior));
    CHECK(netlink.events == std::vector<std::string>{"rule:delete:170"});
}

TEST_CASE("runtime routing exact-delete race retains a complex rule and its route anchor") {
    ScriptedRoutingNetlink netlink;
    const auto old_route = transaction_route(150U);
    const auto old_rule = transaction_rule(150U);
    const auto desired_route = transaction_route(151U);
    const auto desired_rule = transaction_rule(151U);
    netlink.seed_route(old_route);
    netlink.seed_rule(old_rule);
    netlink.before_exact_rule_delete = [&](const RuleSpec& spec, int family) {
        if (spec.table != old_rule.table || family != old_rule.family) return;
        for (auto& rule : netlink.rules) {
            if (rule.table == old_rule.table &&
                rule.priority == old_rule.priority &&
                rule.fwmark == old_rule.fwmark &&
                rule.fwmask == old_rule.fwmask &&
                rule.family == old_rule.family) {
                rule.exact_identity_representable = false;
            }
        }
    };

    auto request = transaction_request({desired_route}, {desired_rule});
    request.prior_owned_rules.push_back(old_rule);
    const auto result = run_transaction(request, netlink);

    CHECK(
        result.terminal ==
        RuntimeRoutingTerminal::committed_cleanup_pending);
    CHECK(result.candidate_exact_verified);
    CHECK_FALSE(result.stale_rule_absence_proven);
    CHECK_FALSE(result.route_cleanup_attempted);
    CHECK(netlink.has_route(old_route));
    CHECK(netlink.has_route(desired_route));
    CHECK(netlink.has_exact_rule(desired_rule));
    const auto complex = std::find_if(
        netlink.rules.begin(), netlink.rules.end(),
        [&](const DumpedRule& live) {
            return live.table == old_rule.table &&
                   live.priority == old_rule.priority &&
                   live.fwmark == old_rule.fwmark &&
                   live.fwmask == old_rule.fwmask &&
                   live.family == old_rule.family &&
                   !live.exact_identity_representable;
        });
    REQUIRE(complex != netlink.rules.end());
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151", "rule:add:151", "rule:delete:150"});

    const auto stale_delete = std::find_if(
        result.journal.begin(), result.journal.end(),
        [](const RuntimeRoutingJournalEntry& entry) {
            return entry.operation ==
                       RuntimeRoutingJournalOperation::delete_stale_rule &&
                   entry.rule.has_value() && entry.rule->table == 150U;
        });
    REQUIRE(stale_delete != result.journal.end());
    CHECK(stale_delete->state == RuntimeRoutingJournalState::failed);
    CHECK(
        stale_delete->receipt ==
        RuntimeRoutingJournalReceipt::precondition_mismatch);
    const auto stale_route = std::find_if(
        result.journal.begin(), result.journal.end(),
        [](const RuntimeRoutingJournalEntry& entry) {
            return entry.operation ==
                       RuntimeRoutingJournalOperation::delete_obsolete_route &&
                   entry.route.has_value() && entry.route->table == 150U;
        });
    REQUIRE(stale_route != result.journal.end());
    CHECK(stale_route->state == RuntimeRoutingJournalState::skipped);
    CHECK(stale_route->receipt == RuntimeRoutingJournalReceipt::none);
    REQUIRE(static_cast<bool>(result.published_journal));
    CHECK(
        result.published_journal->acquire_terminal() ==
        RuntimeRoutingTerminal::committed_cleanup_pending);
}

TEST_CASE("runtime routing transaction uses kernel rule heuristics only by explicit recovery opt-in") {
    ScriptedRoutingNetlink netlink;
    const auto old_route = transaction_route(150U);
    const auto old_rule = transaction_rule(150U);
    const auto desired_route = transaction_route(151U);
    const auto desired_rule = transaction_rule(151U);
    netlink.seed_route(old_route);
    netlink.seed_rule(old_rule);
    auto request = transaction_request({desired_route}, {desired_rule});
    request.allow_recovery_rule_heuristic = true;

    const auto result = run_transaction(request, netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::candidate_committed);
    CHECK_FALSE(netlink.has_exact_rule(old_rule));
    CHECK_FALSE(netlink.has_route(old_route));
    CHECK(netlink.has_route(desired_route));
    CHECK(netlink.has_exact_rule(desired_rule));
}

TEST_CASE("runtime routing transaction rolls back when the fence changes before a rule write") {
    ScriptedRoutingNetlink netlink;
    const auto route = transaction_route(151U);
    const auto rule = transaction_rule(151U);
    const auto request = transaction_request({route}, {rule});
    int probes = 0;
    RuntimeRoutingPublishedJournalPtr retained;

    const auto result = execute_runtime_routing_transaction(
        request,
        [&]() {
            auto fence = current_fence();
            if (++probes >= 4) ++fence.route_epoch;
            return fence;
        },
        netlink,
        netlink,
        [&](const RuntimeRoutingPublishedJournalPtr& journal) {
            retained = journal;
            return true;
        });

    CHECK(result.terminal == RuntimeRoutingTerminal::candidate_rolled_back);
    CHECK(
        result.stale_reason ==
        RuntimeRoutingStaleReason::route_epoch_changed);
    CHECK_FALSE(netlink.has_route(route));
    CHECK_FALSE(netlink.has_exact_rule(rule));
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151", "route:delete:151"});
}

TEST_CASE("runtime routing transaction stops cleanup after the committed fence changes") {
    ScriptedRoutingNetlink netlink;
    const auto old_route = transaction_route(150U);
    const auto old_rule = transaction_rule(150U);
    const auto desired_route = transaction_route(151U);
    const auto desired_rule = transaction_rule(151U);
    netlink.seed_route(old_route);
    netlink.seed_rule(old_rule);
    auto request = transaction_request(
        {desired_route}, {desired_rule});
    request.prior_owned_rules.push_back(old_rule);
    int probes = 0;
    RuntimeRoutingPublishedJournalPtr retained;

    const auto result = execute_runtime_routing_transaction(
        request,
        [&]() {
            auto fence = current_fence();
            if (++probes >= 6) ++fence.intent_serial;
            return fence;
        },
        netlink,
        netlink,
        [&](const RuntimeRoutingPublishedJournalPtr& journal) {
            retained = journal;
            return true;
        });

    CHECK(
        result.terminal ==
        RuntimeRoutingTerminal::committed_cleanup_pending);
    CHECK(result.candidate_exact_verified);
    CHECK(netlink.has_route(old_route));
    CHECK(netlink.has_exact_rule(old_rule));
    CHECK(netlink.has_route(desired_route));
    CHECK(netlink.has_exact_rule(desired_rule));
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151", "rule:add:151"});
}

TEST_CASE("runtime routing transaction keeps the stale route when the fence changes after rule cleanup") {
    ScriptedRoutingNetlink netlink;
    const auto old_route = transaction_route(150U);
    const auto old_rule = transaction_rule(150U);
    const auto desired_route = transaction_route(151U);
    const auto desired_rule = transaction_rule(151U);
    netlink.seed_route(old_route);
    netlink.seed_rule(old_rule);
    auto request = transaction_request(
        {desired_route}, {desired_rule});
    request.prior_owned_rules.push_back(old_rule);
    int probes = 0;
    RuntimeRoutingPublishedJournalPtr retained;

    const auto result = execute_runtime_routing_transaction(
        request,
        [&]() {
            auto fence = current_fence();
            if (++probes >= 7) ++fence.route_epoch;
            return fence;
        },
        netlink,
        netlink,
        [&](const RuntimeRoutingPublishedJournalPtr& journal) {
            retained = journal;
            return true;
        });

    CHECK(
        result.terminal ==
        RuntimeRoutingTerminal::committed_cleanup_pending);
    CHECK(result.candidate_exact_verified);
    CHECK_FALSE(netlink.has_exact_rule(old_rule));
    CHECK(netlink.has_route(old_route));
    CHECK(netlink.has_route(desired_route));
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151", "rule:add:151", "rule:delete:150"});
}

TEST_CASE("runtime routing transaction never deletes a same-slot rollback racer") {
    ScriptedRoutingNetlink netlink;
    const auto candidate = transaction_route(151U);
    const auto rule = transaction_rule(151U);
    auto foreign = candidate;
    foreign.blackhole = false;
    foreign.unreachable = true;
    foreign.protocol = 4U;
    netlink.rule_add_fault_priority = rule.priority;
    netlink.rule_add_fault = FaultTiming::before_effect;
    netlink.before_exact_route_delete = [&](const RouteSpec& spec) {
        if (spec.table != candidate.table) return;
        netlink.routes.clear();
        netlink.seed_route(foreign, 4U);
    };

    const auto result = run_transaction(
        transaction_request({candidate}, {rule}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::partial_unknown);
    CHECK(netlink.has_route(foreign));
    CHECK_FALSE(netlink.has_route(candidate));
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151", "rule:add:151", "route:delete:151"});
}

TEST_CASE("runtime routing transaction never deletes a same-slot cleanup racer") {
    ScriptedRoutingNetlink netlink;
    const auto old_route = transaction_route(150U);
    const auto old_rule = transaction_rule(150U);
    const auto desired_route = transaction_route(151U);
    const auto desired_rule = transaction_rule(151U);
    auto foreign = old_route;
    foreign.blackhole = false;
    foreign.unreachable = true;
    foreign.protocol = 4U;
    netlink.seed_route(old_route);
    netlink.seed_rule(old_rule);
    netlink.before_exact_route_delete = [&](const RouteSpec& spec) {
        if (spec.table != old_route.table) return;
        netlink.routes.erase(
            std::remove_if(
                netlink.routes.begin(), netlink.routes.end(),
                [&](const DumpedRoute& route) {
                    return route.table == old_route.table;
                }),
            netlink.routes.end());
        netlink.seed_route(foreign, 4U);
    };

    auto request = transaction_request({desired_route}, {desired_rule});
    request.prior_owned_rules.push_back(old_rule);
    const auto result = run_transaction(request, netlink);

    CHECK(
        result.terminal ==
        RuntimeRoutingTerminal::committed_cleanup_pending);
    CHECK(netlink.has_route(foreign));
    CHECK(netlink.has_route(desired_route));
    CHECK(netlink.has_exact_rule(desired_rule));
    CHECK(netlink.events == std::vector<std::string>{
        "route:add:151",
        "rule:add:151",
        "rule:delete:150",
        "route:delete:150"});
}

TEST_CASE("runtime routing transaction keeps cleanup pending for a post-delete slot racer") {
    ScriptedRoutingNetlink netlink;
    const auto old_route = transaction_route(150U);
    const auto old_rule = transaction_rule(150U);
    const auto desired_route = transaction_route(151U);
    const auto desired_rule = transaction_rule(151U);
    auto foreign = old_route;
    foreign.blackhole = false;
    foreign.unreachable = true;
    foreign.protocol = 4U;
    netlink.seed_route(old_route);
    netlink.seed_rule(old_rule);
    bool injected = false;
    netlink.before_dump_routes = [&](int) {
        if (injected || netlink.events.empty() ||
            netlink.events.back() != "route:delete:150") {
            return;
        }
        injected = true;
        netlink.seed_route(foreign, 4U);
    };

    auto request = transaction_request({desired_route}, {desired_rule});
    request.prior_owned_rules.push_back(old_rule);
    const auto result = run_transaction(request, netlink);

    CHECK(injected);
    CHECK(
        result.terminal ==
        RuntimeRoutingTerminal::committed_cleanup_pending);
    CHECK(result.route_cleanup_attempted);
    CHECK(netlink.has_route(foreign));
    CHECK(netlink.has_route(desired_route));
    CHECK(netlink.has_exact_rule(desired_rule));
    const auto stale_route = std::find_if(
        result.journal.begin(), result.journal.end(),
        [](const RuntimeRoutingJournalEntry& entry) {
            return entry.operation ==
                       RuntimeRoutingJournalOperation::delete_obsolete_route &&
                   entry.route.has_value() && entry.route->table == 150U;
        });
    REQUIRE(stale_route != result.journal.end());
    CHECK(stale_route->state == RuntimeRoutingJournalState::failed);
    CHECK(
        stale_route->receipt ==
        RuntimeRoutingJournalReceipt::deleted_or_absent);
}

TEST_CASE("runtime routing transaction never commits with an additional same-slot image") {
    ScriptedRoutingNetlink netlink;
    const auto candidate = transaction_route(151U);
    const auto rule = transaction_rule(151U);
    auto foreign = candidate;
    foreign.blackhole = false;
    foreign.unreachable = true;
    foreign.protocol = 4U;
    int route_dumps = 0;
    netlink.before_dump_routes = [&](int) {
        if (++route_dumps != 3) return;
        netlink.seed_route(foreign, 4U);
    };

    const auto result = run_transaction(
        transaction_request({candidate}, {rule}), netlink);

    CHECK(result.terminal == RuntimeRoutingTerminal::partial_unknown);
    CHECK_FALSE(result.candidate_exact_verified);
    CHECK(netlink.has_route(candidate));
    CHECK(netlink.has_route(foreign));
    CHECK_FALSE(netlink.has_exact_rule(rule));
    REQUIRE(static_cast<bool>(result.published_journal));
    CHECK(
        result.published_journal->acquire_terminal() ==
        RuntimeRoutingTerminal::partial_unknown);
}

TEST_CASE("runtime routing transaction publishes every replacement preimage") {
    ScriptedRoutingNetlink netlink;
    const auto previous = transaction_route(160U);
    auto candidate = previous;
    candidate.blackhole = false;
    candidate.unreachable = true;
    const auto rule = transaction_rule(160U);
    netlink.seed_route(previous);
    netlink.rule_add_fault_priority = rule.priority;
    netlink.rule_add_fault = FaultTiming::before_effect;

    const auto result = run_transaction(
        transaction_request({candidate}, {rule}), netlink);

    const auto journal = std::find_if(
        result.journal.begin(), result.journal.end(),
        [](const RuntimeRoutingJournalEntry& entry) {
            return entry.operation ==
                RuntimeRoutingJournalOperation::restore_replaced_route;
        });
    REQUIRE(journal != result.journal.end());
    REQUIRE(journal->route.has_value());
    CHECK(journal->route->destination == previous.destination);
    CHECK(journal->route->table == previous.table);
    CHECK(journal->route->family == previous.family);
    CHECK(journal->route->blackhole == previous.blackhole);
    CHECK(journal->route->unreachable == previous.unreachable);
    CHECK(journal->route->protocol == previous.protocol);
    CHECK(journal->state == RuntimeRoutingJournalState::rolled_back);
}

TEST_CASE("runtime routing transaction requires journal retention before the first write") {
    ScriptedRoutingNetlink netlink;
    const auto request = transaction_request(
        {transaction_route(151U)}, {transaction_rule(151U)});
    RuntimeRoutingPublishedJournalPtr observed;

    const auto result = execute_runtime_routing_transaction(
        request,
        []() { return current_fence(); },
        netlink,
        netlink,
        [&](const RuntimeRoutingPublishedJournalPtr& journal) {
            observed = journal;
            CHECK(netlink.events.empty());
            return false;
        });

    REQUIRE(static_cast<bool>(observed));
    CHECK(static_cast<bool>(result.published_journal == observed));
    CHECK(result.terminal == RuntimeRoutingTerminal::precondition_failed);
    CHECK(
        observed->terminal.load(std::memory_order_acquire) ==
        RuntimeRoutingTerminal::precondition_failed);
    CHECK(
        observed->failure_stage.load(std::memory_order_relaxed) ==
        RuntimeRoutingFailureStage::journal_publish);
    CHECK_FALSE(observed->mutation_started.load(std::memory_order_relaxed));
    CHECK(netlink.events.empty());
}

TEST_CASE("runtime routing transaction updates the retained journal through terminal publication") {
    ScriptedRoutingNetlink netlink;
    const auto request = transaction_request(
        {transaction_route(151U)}, {transaction_rule(151U)});
    RuntimeRoutingPublishedJournalPtr retained;
    bool published_before_write = false;

    const auto result = execute_runtime_routing_transaction(
        request,
        []() { return current_fence(); },
        netlink,
        netlink,
        [&](const RuntimeRoutingPublishedJournalPtr& journal) {
            published_before_write = netlink.events.empty();
            CHECK(
                journal->acquire_terminal() ==
                RuntimeRoutingTerminal::prepared);
            CHECK_FALSE(RuntimeRoutingPublishedJournal::entries_stable_after(
                journal->acquire_terminal()));
            retained = journal;
            return true;
        });

    REQUIRE(static_cast<bool>(retained));
    CHECK(published_before_write);
    CHECK(static_cast<bool>(result.published_journal == retained));
    const auto terminal = retained->acquire_terminal();
    CHECK(terminal == RuntimeRoutingTerminal::candidate_committed);
    CHECK(RuntimeRoutingPublishedJournal::entries_stable_after(terminal));
    CHECK(retained->mutation_started.load(std::memory_order_relaxed));
    CHECK(
        retained->candidate_exact_verified.load(
            std::memory_order_relaxed));
    CHECK(retained->entries.size() == result.journal.size());
    const auto created_receipts = std::count_if(
        retained->entries.begin(), retained->entries.end(),
        [](const RuntimeRoutingJournalEntry& entry) {
            return entry.receipt == RuntimeRoutingJournalReceipt::created;
        });
    CHECK(created_receipts == 2U);
}
