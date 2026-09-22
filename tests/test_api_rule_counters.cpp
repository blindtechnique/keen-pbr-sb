#ifdef WITH_API
#include <doctest/doctest.h>
#include <httplib.h>
#include "../src/api/handler_rule_counters.hpp"

#include <limits>
#include <stdexcept>

namespace keen_pbr3 {
namespace {
Config counter_config(std::size_t count = 3) {
    Config config;
    config.route.emplace();
    config.route->rules.emplace();
    for (std::size_t index = 0; index < count; ++index) {
        RouteRule rule;
        rule.outbound = "vpn";
        rule.display_name = "applied-" + std::to_string(index);
        config.route->rules->push_back(rule);
    }
    config.outbounds.emplace();
    Outbound out;
    out.tag = "vpn";
    out.display_name = "Applied VPN";
    out.type = OutboundType::INTERFACE;
    config.outbounds->push_back(out);
    return config;
}

FirewallClassifierEvidence counts(const FirewallClassifierQuery& query) {
    FirewallClassifierEvidence result;
    result.status = FirewallCounterStatus::Observed;
    result.snapshot_at = 100;
    result.total = 1;
    FirewallClassifierCounter row;
    row.family = query.family;
    row.table = "raw";
    row.chain = "KeenPbrRaw_B";
    row.position = 1;
    row.action = "mark";
    row.set_name = "kpbr4_test";
    row.packets = query.rule_index;
    row.bytes = std::numeric_limits<std::uint64_t>::max();
    result.rules.push_back(row);
    return result;
}
} // namespace

TEST_CASE("rule counters snapshot uses applied labels and one lookup for enabled rules") {
    auto config = counter_config();
    config.route->rules->at(1).enabled = false;
    config.route->rules->at(2).display_name.reset();
    config.route->rules->at(2).outbound = "missing";
    int calls = 0;
    const auto result = build_rule_counters_response(config, true, [&](const auto& queries) {
        ++calls;
        REQUIRE(queries.size() == 4);
        CHECK(queries[0].rule_index == 0);
        CHECK(queries[0].family == AF_INET);
        CHECK(queries[1].family == AF_INET6);
        CHECK(queries[2].rule_index == 2);
        CHECK(queries[3].rule_index == 2);
        std::vector<FirewallClassifierEvidence> observations;
        for (const auto& query : queries) observations.push_back(counts(query));
        return observations;
    });
    const nlohmann::json json = result;
    CHECK(calls == 1);
    CHECK(json["captured_at"].get<std::int64_t>() > 0);
    CHECK(json["unapplied_draft"] == true);
    CHECK(json["total"] == 3);
    CHECK(json["truncated"] == false);
    const auto& rows = json["rules"];
    REQUIRE(rows.size() == 3);
    CHECK(rows[0]["name"] == "applied-0");
    CHECK(rows[0]["outbound_name"] == "Applied VPN");
    CHECK(rows[0]["ipv4"]["rules"][0]["packets"] == "0");
    CHECK(rows[0]["ipv4"]["rules"][0]["bytes"] == "18446744073709551615");
    CHECK(rows[0]["ipv6"]["rules"][0]["family"] == "ipv6");
    CHECK(rows[1]["ipv4"]["status"] == "not_applicable");
    CHECK(rows[1]["ipv6"]["rules"].empty());
    CHECK(rows[2]["rule_index"] == 2);
    CHECK(rows[2]["name"] == "");
    CHECK(rows[2]["outbound_name"] == "missing");
    CHECK(rows[2]["ipv4"]["rules"][0]["packets"] == "2");
}

TEST_CASE("rule counters snapshot bounds logical rows before collection") {
    std::size_t calls = 0;
    const auto result = build_rule_counters_response(counter_config(140), false,
        [&](const auto& queries) {
            ++calls;
            CHECK(queries.size() == 256);
            CHECK(queries.back().rule_index == 127);
            return std::vector<FirewallClassifierEvidence>{};
        });
    CHECK(calls == 1);
    CHECK(result.rules.size() == 128);
    CHECK(result.total == 140);
    CHECK(result.truncated);
}

TEST_CASE("rule counters snapshot does not turn absent or failed observations into zero") {
    auto config = counter_config(1);
    RoutingFirewallEvidenceLookup lookup;
    SUBCASE("no reader") {}
    SUBCASE("exception") {
        lookup = [](const auto&) -> std::vector<FirewallClassifierEvidence> {
            throw std::runtime_error("unavailable");
        };
    }
    SUBCASE("incomplete response") {
        lookup = [](const auto&) { return std::vector<FirewallClassifierEvidence>(1); };
    }
    const nlohmann::json result = build_rule_counters_response(config, false, lookup);
    for (const auto* family : {"ipv4", "ipv6"}) {
        const auto& evidence = result["rules"][0][family];
        CHECK(evidence["status"] == "unavailable");
        CHECK(evidence["rules"].empty());
    }
    CHECK(result["rules"][0]["enabled"] == true);
}

TEST_CASE("rule counters snapshot retains family availability ambiguity and truncation separately") {
    const nlohmann::json result = build_rule_counters_response(counter_config(1), false,
        [](const auto& queries) {
            auto observed = counts(queries[0]);
            observed.total = 40;
            observed.truncated = true;
            FirewallClassifierEvidence ambiguous;
            ambiguous.status = FirewallCounterStatus::Ambiguous;
            return std::vector<FirewallClassifierEvidence>{observed, ambiguous};
        });
    CHECK(result["rules"][0]["ipv4"]["status"] == "observed");
    CHECK(result["rules"][0]["ipv4"]["truncated"] == true);
    CHECK(result["rules"][0]["ipv6"]["status"] == "ambiguous");
    CHECK(result["rules"][0]["ipv6"]["rules"].empty());
    CHECK(result["truncated"] == false);
}

TEST_CASE("rule counters snapshot empty and disabled configurations perform no read") {
    Config config;
    SUBCASE("no route") {}
    SUBCASE("empty route") { config.route.emplace(); }
    SUBCASE("empty rules") { config = counter_config(0); }
    SUBCASE("disabled rule") {
        config = counter_config(1);
        config.route->rules->at(0).enabled = false;
    }
    int calls = 0;
    const auto result = build_rule_counters_response(config, false, [&](const auto&) {
        ++calls;
        return std::vector<FirewallClassifierEvidence>{};
    });
    CHECK(calls == 0);
    CHECK_FALSE(result.truncated);
}

TEST_CASE("rule counters endpoint never invokes mutation health or target probes") {
    SseBroadcaster broadcaster;
    ApiContext ctx{"/tmp/unused-met-config", broadcaster};
    int reads = 0;
    bool unavailable = false;
    SUBCASE("one successful read") {}
    SUBCASE("missing callback") { unavailable = true; }
    if (!unavailable) {
        ctx.get_rule_counters_fn = [&]() {
            ++reads;
            return build_rule_counters_response(counter_config(0), false, {});
        };
    }
    // All writer, health, target/DNS/HTTP and draft callbacks stay unset.
    ApiConfig config;
    config.listen = "127.0.0.1:18192";
    ApiServer server(config);
    register_rule_counters_handler(server, ctx);
    server.start();
    httplib::Client client("127.0.0.1", 18192);
    const auto response = client.Get("/api/routing/counters");
    server.stop();
    REQUIRE(response);
    CHECK(response->status == (unavailable ? 503 : 200));
    CHECK(response->get_header_value("Cache-Control") == "no-store");
    CHECK(reads == (unavailable ? 0 : 1));
    if (!unavailable) {
        const auto json = nlohmann::json::parse(response->body);
        CHECK(json["total"] == 0);
        CHECK(json["rules"].empty());
    }
}
} // namespace keen_pbr3
#endif
