#include <doctest/doctest.h>

#include "../src/config/list_delete_planner.hpp"

#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {

Config planner_fixture() {
    Config config;
    config.lists = std::map<std::string, ListConfig>{
        {"meta", ListConfig{}},
        {"instagram", ListConfig{}},
        {"manual", ListConfig{}},
    };

    RouteRule list_only;
    list_only.list =
        std::vector<std::string>{"instagram"};
    list_only.outbound = "vpn";

    RouteRule protocol_only_after_delete;
    protocol_only_after_delete.list =
        std::vector<std::string>{"instagram"};
    protocol_only_after_delete.proto = "udp";
    protocol_only_after_delete.outbound = "vpn";

    RouteRule independently_matched;
    independently_matched.list =
        std::vector<std::string>{"instagram"};
    independently_matched.dest_port = "443";
    independently_matched.proto = "tcp";
    independently_matched.outbound = "vpn";

    RouteRule rebound;
    rebound.list =
        std::vector<std::string>{"instagram", "manual"};
    rebound.outbound = "vpn";

    RouteConfig route;
    route.rules = std::vector<RouteRule>{
        list_only,
        protocol_only_after_delete,
        independently_matched,
        rebound,
    };
    config.route = std::move(route);

    DnsRule removed_dns;
    removed_dns.list = {"instagram"};
    removed_dns.server = "vpn_dns";
    DnsRule rebound_dns;
    rebound_dns.list = {"instagram", "manual"};
    rebound_dns.server = "vpn_dns";
    DnsConfig dns;
    dns.rules =
        std::vector<DnsRule>{removed_dns, rebound_dns};
    config.dns = std::move(dns);
    return config;
}

} // namespace

TEST_CASE(
    "list delete planner removes orphan rules and keeps real conditions") {
    const auto plan = plan_list_delete(
        planner_fixture(),
        {{"instagram", std::nullopt}});

    REQUIRE(plan.config.route.has_value());
    REQUIRE(plan.config.route->rules.has_value());
    REQUIRE(plan.config.route->rules->size() == 2U);
    CHECK_FALSE(
        plan.config.route->rules->at(0).list.has_value());
    CHECK(
        plan.config.route->rules->at(0).dest_port ==
        std::optional<std::string>{"443"});
    CHECK(
        route_rule_lists(plan.config.route->rules->at(1)) ==
        std::vector<std::string>{"manual"});

    REQUIRE(plan.config.dns.has_value());
    REQUIRE(plan.config.dns->rules.has_value());
    REQUIRE(plan.config.dns->rules->size() == 1U);
    CHECK(
        plan.config.dns->rules->front().list ==
        std::vector<std::string>{"manual"});
    CHECK(plan.summary.removed_route_rules == 2U);
    CHECK(plan.summary.updated_route_rules == 2U);
    CHECK(plan.summary.removed_dns_rules == 1U);
    CHECK(plan.summary.updated_dns_rules == 1U);
}

TEST_CASE(
    "list delete planner rebinds route and DNS references without duplicates") {
    auto config = planner_fixture();
    config.route->rules->front().list =
        std::vector<std::string>{"instagram", "meta"};
    config.dns->rules->front().list =
        std::vector<std::string>{"instagram", "meta"};

    const auto plan = plan_list_delete(
        config,
        {{"instagram", std::string{"meta"}}});

    REQUIRE(plan.config.lists.has_value());
    CHECK(plan.config.lists->count("instagram") == 0U);
    CHECK(plan.config.lists->count("meta") == 1U);
    CHECK(
        route_rule_lists(plan.config.route->rules->front()) ==
        std::vector<std::string>{"meta"});
    CHECK(
        plan.config.dns->rules->front().list ==
        std::vector<std::string>{"meta"});
    CHECK(plan.summary.rebound_references == 6U);
    CHECK(plan.summary.removed_route_rules == 0U);
    CHECK(plan.summary.removed_dns_rules == 0U);
}

TEST_CASE("list delete planner validates the full replacement set") {
    const Config config = planner_fixture();

    CHECK_THROWS_WITH_AS(
        plan_list_delete(
            config,
            {{"instagram", std::string{"missing"}}}),
        "Replacement list does not exist: missing",
        std::invalid_argument);
    CHECK_THROWS_WITH_AS(
        plan_list_delete(
            config,
            {
                {"instagram", std::string{"meta"}},
                {"meta", std::nullopt},
            }),
        "Replacement list is also selected for deletion: meta",
        std::invalid_argument);
    CHECK_THROWS_WITH_AS(
        plan_list_delete(
            config,
            {
                {"instagram", std::nullopt},
                {"instagram", std::nullopt},
            }),
        "Duplicate list delete target: instagram",
        std::invalid_argument);
}

} // namespace keen_pbr3
