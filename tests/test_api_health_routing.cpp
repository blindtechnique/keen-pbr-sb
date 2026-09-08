#ifdef WITH_API

#include <doctest/doctest.h>
#include <nlohmann/json.hpp>

#include "api/handler_health_routing.hpp"

using namespace keen_pbr3;

TEST_CASE("routing health response retains observation failure as an ApiError 500") {
    RoutingHealthReport report;
    report.error = "runtime routing inventory is not authoritative; waiting for reconciliation";
    try {
        (void)make_routing_health_response(report);
        FAIL("An unavailable observation must not be returned as HTTP success");
    } catch (const ApiError& error) {
        CHECK(error.status() == 500);
        CHECK(std::string(error.what()) == "Routing health check failed");
        REQUIRE(error.body().has_value());
        const auto body = nlohmann::json::parse(*error.body());
        CHECK(body == nlohmann::json{{"overall", "error"}, {"error", report.error}});
        CHECK_FALSE(body.contains("firewall_rules"));
    }
}

TEST_CASE("routing health response retains valid empty arrays for either firewall backend") {
    for (const auto backend : {FirewallBackend::iptables, FirewallBackend::nftables}) {
        RoutingHealthReport report;
        report.firewall_backend = backend;
        report.overall_ok = true;
        report.firewall_chain.chain_present = true;
        report.firewall_chain.prerouting_hook_present = true;
        const auto body = nlohmann::json::parse(make_routing_health_response(report));
        CHECK(body.at("overall") == "ok");
        CHECK(body.at("firewall_rules").is_array());
        CHECK(body.at("firewall_rules").empty());
        CHECK(body.at("route_tables").is_array());
        CHECK(body.at("route_tables").empty());
        CHECK(body.at("policy_rules").is_array());
        CHECK(body.at("policy_rules").empty());
        CHECK(body.at("firewall_backend") ==
              (backend == FirewallBackend::iptables ? "iptables" : "nftables"));
        CHECK_FALSE(body.contains("error"));
    }
}

TEST_CASE("routing health response keeps a completed degraded check as a valid report") {
    RoutingHealthReport report;
    report.firewall_backend = FirewallBackend::iptables;
    FirewallRuleCheck rule;
    rule.set_name = "kpbr4s_example";
    rule.action = "mark";
    rule.expected_fwmark = 0x00010000;
    rule.status = CheckStatus::missing;
    rule.detail = "rule not found";
    report.firewall_rules.push_back(rule);
    report.route_tables.emplace_back();
    report.policy_rules.emplace_back();

    const auto body = nlohmann::json::parse(make_routing_health_response(report));
    CHECK(body.at("overall") == "degraded");
    CHECK(body.at("firewall_rules").size() == 1);
    CHECK(body.at("firewall_rules")[0].at("status") == "missing");
    CHECK(body.at("firewall_rules")[0].at("expected_fwmark") == "0x00010000");
    CHECK(body.at("firewall_rules")[0].at("detail") == "rule not found");
    CHECK(body.at("route_tables").size() == 1);
    CHECK(body.at("policy_rules").size() == 1);
    CHECK_FALSE(body.contains("error"));
}

TEST_CASE("routing health response does not disguise an invalid success snapshot") {
    // The HTTP handler's existing std::exception catch converts this to the
    // same 500 error DTO. No server, auth or kernel fixture is needed here.
    CHECK_THROWS_WITH_AS(make_routing_health_response(RoutingHealthReport{}),
                         "Routing health report missing firewall backend",
                         std::runtime_error);
}

#endif
