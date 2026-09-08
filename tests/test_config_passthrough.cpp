#include <doctest/doctest.h>

#include "../src/config/config.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>
#include <string>
#include <type_traits>
#include <utility>

using namespace keen_pbr3;

namespace {
using Json = nlohmann::json;

template <typename T>
void check_opaque_object(Json source = Json::object()) {
    source["extension_null"] = nullptr;
    source["extension_empty"] = Json::object();
    source["extension_array"] = Json::array();
    source["extension_nested"] = {
        {"null", nullptr}, {"empty", Json::object()},
        {"items", Json::array({nullptr, Json::object(), Json::array(), "kept"})}};
    const auto typed = source.get<T>();
    CHECK(typed._config_unknown_fields.size() == 4);
    auto output = Json(typed);
    (void)api::prune_config_json_for_persistence(output, typed);
    for (const auto& field : typed._config_unknown_fields.items()) {
        REQUIRE(output.contains(field.key()));
        CHECK(output.at(field.key()) == field.value());
    }
    CHECK(output.get<T>()._config_unknown_fields == typed._config_unknown_fields);
    CHECK_FALSE(output.contains("_config_unknown_fields"));
}

Json routing_document() {
    return Json::parse(R"({
        "schema_version":2,
        "outbounds":[
            {"tag":"one","type":"interface","interface":"wg0","extension":"vpn-one"},
            {"tag":"two","type":"interface","interface":"wg1","extension":"vpn-two"}],
        "lists":{"one":{"domains":["one.example"],"extension":"list-one"},
                 "two":{"domains":["two.example"],"extension":"list-two"}},
        "route":{"rules":[
            {"id":"rule_one","list":["one"],"outbound":"one","extension":"route-one"},
            {"id":"rule_two","list":["two"],"outbound":"two","extension":"route-two"}]},
        "dns":{"system_resolver":{"address":"127.0.0.1"},
               "servers":[{"tag":"dns","address":"9.9.9.9","extension":{"empty":{}}}],
               "fallback":["dns"],
               "rules":[{"list":["one"],"server":"dns","extension":"dns-one"},
                        {"list":["two"],"server":"dns","extension":"dns-two"}]},
        "extension":{"null":null,"empty":{},"array":[]}
    })");
}
}

TEST_CASE("config passthrough: every reachable config object retains opaque payloads") {
    check_opaque_object<Config>({{"schema_version", 2}});
    check_opaque_object<ApiConfig>();
    check_opaque_object<DaemonConfig>();
    check_opaque_object<DnsConfig>();
    check_opaque_object<api::ClientDnsEnforcement>();
    check_opaque_object<DnsTestServer>({{"listen", "127.0.0.1:12153"}});
    check_opaque_object<DnsRule>({{"list", {"example"}}, {"server", "dns"}});
    check_opaque_object<DnsServer>({{"tag", "dns"}});
    check_opaque_object<api::SystemResolver>({{"address", "127.0.0.1"}});
    check_opaque_object<FwmarkConfig>();
    check_opaque_object<IprouteConfig>();
    check_opaque_object<ListRefreshConfig>();
    check_opaque_object<ListConfig>();
    check_opaque_object<api::ShrinkPolicy>();
    check_opaque_object<ListsAutoupdateConfig>();
    check_opaque_object<Outbound>({{"tag", "vpn"}, {"type", "interface"}});
    check_opaque_object<OutboundGroup>({{"outbounds", {"vpn"}}});
    check_opaque_object<RetryConfig>();
    check_opaque_object<CircuitBreakerConfig>();
    check_opaque_object<RouteConfig>();
    check_opaque_object<InternalVpnServer>({{"interface", "oc0"}, {"process_clients", true}});
    check_opaque_object<InternalVpnService>({{"service_id", "openconnect"}, {"process_clients", true}});
    check_opaque_object<RouteRule>({{"outbound", "vpn"}});
    check_opaque_object<TunnelProbeConfig>();
    check_opaque_object<UiPreferencesConfig>();
    check_opaque_object<PlainDnsTemplate>({{"name", "DNS"}, {"primary_ipv4", "9.9.9.9"}});
}

TEST_CASE("config passthrough: ordinary edit save reload preserves nested extensions") {
    const auto source = routing_document();
    auto config = parse_and_validate_config(source.dump());
    config.outbounds->front().display_name = "Renamed VPN";
    config.route->rules->front().outbound = "two";
    config.dns->servers->front().address = "1.1.1.1";
    const auto encoded = serialize_config_document(config);
    CHECK(encoded.back() == '\n');
    const auto output = Json::parse(encoded);
    CHECK(output["extension"] == source["extension"]);
    CHECK(output["outbounds"][0]["extension"] == "vpn-one");
    CHECK(output["outbounds"][0]["display_name"] == "Renamed VPN");
    CHECK(output["route"]["rules"][0]["extension"] == "route-one");
    CHECK(output["route"]["rules"][0]["outbound"] == "two");
    CHECK(output["dns"]["servers"][0]["extension"] == source["dns"]["servers"][0]["extension"]);
    CHECK(output["dns"]["servers"][0]["address"] == "1.1.1.1");
    CHECK(serialize_config_document(parse_and_validate_config(encoded)) == encoded);
}

TEST_CASE("config passthrough: reorder and deletion never reattach stale objects by index") {
    auto config = parse_and_validate_config(routing_document().dump());
    std::reverse(config.outbounds->begin(), config.outbounds->end());
    std::reverse(config.route->rules->begin(), config.route->rules->end());
    std::reverse(config.dns->rules->begin(), config.dns->rules->end());
    auto output = Json::parse(serialize_config_document(config));
    CHECK(output["outbounds"][0]["tag"] == "two");
    CHECK(output["outbounds"][0]["extension"] == "vpn-two");
    CHECK(output["route"]["rules"][0]["id"] == "rule_two");
    CHECK(output["route"]["rules"][0]["extension"] == "route-two");
    CHECK(output["dns"]["rules"][0]["extension"] == "dns-two");
    config.outbounds->pop_back();
    config.route->rules->pop_back();
    config.dns->rules->pop_back();
    config.lists->erase("one");
    output = Json::parse(serialize_config_document(config));
    CHECK(output["outbounds"].size() == 1);
    CHECK(output["outbounds"][0]["extension"] == "vpn-two");
    CHECK(output["route"]["rules"].size() == 1);
    CHECK(output["route"]["rules"][0]["extension"] == "route-two");
    CHECK(output["dns"]["rules"].size() == 1);
    CHECK(output["dns"]["rules"][0]["extension"] == "dns-two");
    CHECK_FALSE(output["lists"].contains("one"));
    CHECK(output["lists"]["two"]["extension"] == "list-two");
    CHECK_NOTHROW(parse_and_validate_config(output.dump()));
}

TEST_CASE("config passthrough: nested group and map extras follow current members") {
    auto config = parse_config(R"({
        "outbounds":[{"tag":"group","type":"urltest",
          "retry":{"attempts":2,"extension":null},
          "outbound_groups":[{"outbounds":["one"],"extension":{"id":1}},
                             {"outbounds":["two"],"extension":{"id":2}}]}],
        "lists":{"source":{"domains":["example.org"],"shrink_policy":{"extension":{}}}}
    })");
    auto& outbound = config.outbounds->front();
    std::reverse(outbound.outbound_groups->begin(), outbound.outbound_groups->end());
    outbound.outbound_groups->pop_back();
    outbound.retry->attempts.reset();
    const auto output = Json::parse(serialize_config_document(config));
    CHECK(output["outbounds"][0]["outbound_groups"].size() == 1);
    CHECK(output["outbounds"][0]["outbound_groups"][0]["extension"]["id"] == 2);
    CHECK(output["outbounds"][0]["retry"] == Json({{"extension", nullptr}}));
    CHECK(output["lists"]["source"]["shrink_policy"] == Json({{"extension", Json::object()}}));
}

TEST_CASE("config passthrough: cleared known fields win and removed sections stay removed") {
    auto config = parse_config(R"({"outbounds":[{"tag":"vpn","type":"interface",
      "display_name":"old","gateway":"192.0.2.1","extension":null}],
      "list_refresh":{"detour":"vpn","extension":{}},"extension":[]})");
    auto& outbound = config.outbounds->front();
    outbound.display_name.reset();
    outbound.gateway.reset();
    // Even an accidental bag collision cannot override a current typed value.
    outbound._config_unknown_fields["display_name"] = "stale";
    outbound._config_unknown_fields["tag"] = "wrong";
    config.list_refresh.reset();
    const auto output = Json::parse(serialize_config_document(config));
    CHECK_FALSE(output["outbounds"][0].contains("display_name"));
    CHECK_FALSE(output["outbounds"][0].contains("gateway"));
    CHECK(output["outbounds"][0]["tag"] == "vpn");
    CHECK(output["outbounds"][0].contains("extension"));
    CHECK_FALSE(output.contains("list_refresh"));
    CHECK(output["extension"] == Json::array());
}

TEST_CASE("config passthrough: compact known defaults and empty arrays keep old format") {
    Config config;
    CHECK(Json::parse(serialize_config_document(config)) == Json({{"schema_version", 2}}));
    CHECK(config._config_unknown_fields.is_null());
    config.daemon = DaemonConfig{};
    config.lists = std::map<std::string, ListConfig>{{"empty", ListConfig{}}};
    config.outbounds = std::vector<Outbound>{};
    const auto output = Json::parse(serialize_config_document(config));
    CHECK_FALSE(output.contains("daemon"));
    CHECK_FALSE(output.contains("lists"));
    CHECK(output["outbounds"] == Json::array());
    CHECK(config.daemon->_config_unknown_fields.is_null());
}

TEST_CASE("config passthrough: reused parser and independent drafts retain exact ownership") {
    Config reused = parse_config(R"({"extension":"old"})");
    Json({{"schema_version", 2}}).get_to(reused);
    CHECK(reused._config_unknown_fields.is_null());
    auto active = parse_config(R"({"extension":{"value":"active"}})");
    auto draft = active;
    draft._config_unknown_fields["extension"]["value"] = "draft";
    CHECK(Json(active)["extension"]["value"] == "active");
    static_assert(std::is_nothrow_move_constructible_v<Config>);
    static_assert(noexcept(api::swap(active, draft)));
    api::swap(active, draft);
    CHECK(Json(active)["extension"]["value"] == "draft");
    CHECK(Json(draft)["extension"]["value"] == "active");
    api::swap(active, active);
    CHECK(Json(active)["extension"]["value"] == "draft");
}
