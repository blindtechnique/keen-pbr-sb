#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_test_routing.hpp"
#include "../src/api/server.hpp"
#include "../src/api/sse_broadcaster.hpp"

namespace keen_pbr3 {

namespace {

const std::string kApiConfigPath = "/tmp/keen-pbr-test-config.json";
constexpr const char* kApiListen = "127.0.0.1:18190";

ApiContext make_test_api_context(SseBroadcaster& broadcaster) {
    return ApiContext{
        kApiConfigPath,
        broadcaster,
        []() { return Config{}; },
        []() { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> { return std::nullopt; },
        []() {},
        [](const Config&) {},
        []() { return ServiceHealthState{}; },
        []() { return RoutingHealthReport{}; },
        []() { return api::RuntimeOutboundsResponse{}; },
        []() { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) { return std::map<std::string, api::ListRefreshStateValue>{}; },
        [](const std::string& target) {
            TestRoutingResult result;
            result.target = target;
            result.unapplied_draft = true;
            TestRoutingEntry entry;
            entry.ip = "203.0.113.7";
            entry.expected_outbound = "(unknown)";
            entry.actual_outbound = "(unknown)";
            entry.ok = false;
            entry.evaluation =
                RoutingMatchEvaluation::InsufficientContext;
            entry.unknown_conditions = {
                "source_address", "destination_port"};
            entry.list_match =
                ListMatchInfo{"work", "203.0.113.7"};
            result.entries.push_back(std::move(entry));

            RuleDiagnostic rule;
            rule.rule_index = 0;
            rule.rule.outbound = "vpn";
            rule.outbound = "vpn";
            rule.interface_name = "ppp0";
            RuleIpDiagnostic ip;
            ip.ip = "203.0.113.7";
            ip.in_lists = true;
            ip.list_match =
                ListMatchInfo{"work", "203.0.113.7"};
            ip.in_ipset = true;
            ip.evaluation =
                RoutingMatchEvaluation::InsufficientContext;
            ip.unknown_conditions = {"source_address"};
            rule.ip_rows.push_back(std::move(ip));
            result.rule_diagnostics.push_back(std::move(rule));
            return result;
        },
        []() {},
        []() {},
        [](Config, std::string) { return ConfigApplyResult{}; },
        []() {},
        []() {},
        []() {},
        [](std::optional<std::string>) { return ListRefreshOperationResult{}; },
    };
}

} // namespace

TEST_CASE("register_test_routing_handler: rejects empty target") {
    SseBroadcaster broadcaster;
    ApiConfig api_config;
    api_config.listen = std::string(kApiListen);

    ApiServer server(api_config);
    auto ctx = make_test_api_context(broadcaster);
    register_test_routing_handler(server, ctx);

    server.start();

    httplib::Client client("127.0.0.1", 18190);
    const auto response =
        client.Post("/api/routing/test", R"({"target":""})", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 400);

    const auto body = nlohmann::json::parse(response->body);
    CHECK(body["error"] == "Field 'target' must not be empty");
}

TEST_CASE("register_test_routing_handler: exposes active scope and honest per-IP detail") {
    SseBroadcaster broadcaster;
    ApiConfig api_config;
    api_config.listen = std::string(kApiListen);

    ApiServer server(api_config);
    auto ctx = make_test_api_context(broadcaster);
    register_test_routing_handler(server, ctx);
    server.start();

    httplib::Client client("127.0.0.1", 18190);
    const auto response = client.Post(
        "/api/routing/test",
        R"({"target":"example.com"})",
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("config_scope") == "active");
    CHECK(body.at("unapplied_draft") == true);
    REQUIRE(body.at("results").size() == 1);
    CHECK(body.at("results")[0].at("evaluation") ==
          "insufficient_context");
    CHECK(body.at("results")[0].at("unknown_conditions") ==
          nlohmann::json{"source_address", "destination_port"});
    REQUIRE(body.at("rule_diagnostics").size() == 1);
    const auto& row =
        body.at("rule_diagnostics")[0].at("ip_rows")[0];
    CHECK(row.at("in_lists") == true);
    CHECK(row.at("list_match").at("list") == "work");
    CHECK(row.at("evaluation") == "insufficient_context");
}

} // namespace keen_pbr3

#endif // WITH_API
