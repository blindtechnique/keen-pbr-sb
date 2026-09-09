#include <doctest/doctest.h>

#include "../src/config/outbound_delete.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>

namespace keen_pbr3 {
TEST_CASE("external native metadata cleanup retains every dependent outbound") {
    Config config;
    Outbound vpn;
    vpn.tag = "native";
    vpn.type = OutboundType::INTERFACE;
    vpn.interface = "nwg4";
    config.outbounds = std::vector<Outbound>{vpn};
    CHECK(interface_outbounds_are_unreferenced(config, "nwg4"));
    CHECK(interface_outbounds_are_unreferenced(config, "nwg9"));
    CHECK_FALSE(interface_outbounds_are_unreferenced(config, ""));

    RouteRule rule;
    rule.outbound = vpn.tag;
    rule.enabled = false;
    config.route = RouteConfig{};
    config.route->rules = std::vector<RouteRule>{rule};
    CHECK_FALSE(interface_outbounds_are_unreferenced(config, "nwg4"));
    config.route.reset();
    Outbound group;
    group.tag = "group";
    group.type = OutboundType::URLTEST;
    OutboundGroup members;
    members.outbounds = {vpn.tag};
    group.outbound_groups = std::vector<OutboundGroup>{members};
    config.outbounds->push_back(group);
    CHECK_FALSE(interface_outbounds_are_unreferenced(config, "nwg4"));
}

namespace {

Outbound interface_outbound(const std::string& tag) {
    Outbound result;
    result.tag = tag;
    result.type = OutboundType::INTERFACE;
    result.interface = "tun-" + tag;
    result.display_name = "Name " + tag;
    return result;
}

Outbound selector(const std::string& tag,
                  const std::vector<std::vector<std::string>>& members) {
    Outbound result;
    result.tag = tag;
    result.type = OutboundType::URLTEST;
    result.selection_mode = UrltestSelectionMode::PRIORITY;
    result.outbound_groups = std::vector<OutboundGroup>{};
    for (const auto& tags : members) {
        OutboundGroup group;
        group.outbounds = tags;
        group.weight = 5;
        result.outbound_groups->push_back(group);
    }
    return result;
}

Config fixture() {
    Config config;
    config.outbounds = std::vector<Outbound>{
        interface_outbound("vpn"), interface_outbound("backup"),
        selector("single", {{"vpn"}}),
        selector("nested", {{"single"}}),
        selector("survivor", {{"vpn"}, {"vpn", "backup"}})};
    RouteRule removed;
    removed.outbound = "nested";
    removed.list = std::vector<std::string>{"media"};
    RouteRule fallback;
    fallback.outbound = "backup";
    fallback.failure_policy = api::FailurePolicy::FALLBACK;
    fallback.fallback_outbound = "single";
    fallback.enabled = false;
    fallback.id = "keep-rule-id";
    fallback.display_name = "Keep rule name";
    RouteConfig route;
    route.rules = std::vector<RouteRule>{removed, fallback};
    route.inbound_interfaces = std::vector<std::string>{"br0"};
    config.route = route;
    DnsServer remote;
    remote.tag = "remote";
    remote.address = "1.1.1.1";
    remote.detour = "single";
    DnsConfig dns;
    dns.servers = std::vector<DnsServer>{remote};
    dns.fallback = std::vector<std::string>{"remote"};
    config.dns = dns;
    ListConfig list;
    list.url = "https://example.test/domains.txt";
    list.display_name = "Keep list name";
    list.ttl_ms = 120000;
    list.detour = "vpn";
    list.fallback_detours = std::vector<std::string>{"backup"};
    list.refresh_detour_mode = ListRefreshDetourMode::OVERRIDE;
    config.lists = std::map<std::string, ListConfig>{{"media", list}};
    ListRefreshConfig refresh;
    refresh.detour = "nested";
    refresh.fallback_detours = std::vector<std::string>{"backup"};
    config.list_refresh = refresh;
    DaemonConfig daemon;
    daemon.ipv6_enabled = true;
    config.daemon = daemon;
    return config;
}

} // namespace

TEST_CASE("outbound delete matches the confirmed cascade without unrelated edits") {
    const auto original = fixture();
    const auto original_json = nlohmann::json(original);
    auto expected = original;
    expected.outbounds = std::vector<Outbound>{
        interface_outbound("backup"), selector("survivor", {{"backup"}})};
    expected.route->rules->erase(expected.route->rules->begin());
    expected.route->rules->front().failure_policy = api::FailurePolicy::BLOCK;
    expected.route->rules->front().fallback_outbound.reset();
    expected.dns->servers->front().detour.reset();
    auto& list = expected.lists->at("media");
    list.detour.reset();
    list.fallback_detours.reset();
    list.refresh_detour_mode.reset();
    expected.list_refresh = ListRefreshConfig{};

    const auto result = remove_outbound_dependencies(original, {"vpn"});
    CHECK(nlohmann::json(result) == nlohmann::json(expected));
    CHECK(nlohmann::json(original) == original_json);
    CHECK(nlohmann::json(remove_outbound_dependencies(result, {"vpn"})) ==
          nlohmann::json(result));
}

TEST_CASE("outbound delete prunes list fallback chains without resetting primary") {
    auto config = fixture();
    auto& list = config.lists->at("media");
    list.detour = "backup";
    list.fallback_detours = std::vector<std::string>{"vpn", "backup", "single"};
    config.list_refresh->detour = "backup";
    config.list_refresh->fallback_detours = list.fallback_detours;

    auto result = remove_outbound_dependencies(config, {"vpn"});
    const auto& remaining_list = result.lists->at("media");
    CHECK(remaining_list.detour == "backup");
    CHECK(remaining_list.refresh_detour_mode == ListRefreshDetourMode::OVERRIDE);
    REQUIRE(remaining_list.fallback_detours.has_value());
    CHECK(*remaining_list.fallback_detours == std::vector<std::string>{"backup"});
    CHECK(result.list_refresh->detour == "backup");
    CHECK(result.list_refresh->fallback_detours == remaining_list.fallback_detours);

    list.fallback_detours = std::vector<std::string>{"vpn", "single"};
    config.list_refresh->fallback_detours = list.fallback_detours;
    result = remove_outbound_dependencies(config, {"vpn"});
    CHECK_FALSE(result.lists->at("media").fallback_detours.has_value());
    CHECK_FALSE(result.list_refresh->fallback_detours.has_value());
}

TEST_CASE("outbound delete retains unknown refresh settings when clearing its detour") {
    auto document = nlohmann::json(fixture());
    const auto future_policy = nlohmann::json::parse(
        R"({"empty":{},"unset":null,"phases":[null,{},[]]})");
    document["list_refresh"]["future_policy"] = future_policy;
    const auto original = document.get<Config>();

    const auto result = remove_outbound_dependencies(original, {"vpn"});
    REQUIRE(result.list_refresh.has_value());
    CHECK_FALSE(result.list_refresh->detour.has_value());
    CHECK_FALSE(result.list_refresh->fallback_detours.has_value());
    auto persisted = nlohmann::json(result);
    (void)api::prune_config_json_for_persistence(persisted, result);
    REQUIRE(persisted.contains("list_refresh"));
    REQUIRE(persisted["list_refresh"].contains("future_policy"));
    CHECK(persisted["list_refresh"]["future_policy"] == future_policy);
    CHECK_FALSE(persisted["list_refresh"].contains("detour"));
    CHECK_FALSE(persisted["list_refresh"].contains("fallback_detours"));
    CHECK(nlohmann::json(original) == document);
}

TEST_CASE("outbound delete preserves optional absence and explicit empty chains") {
    Config config;
    config.outbounds = std::vector<Outbound>{interface_outbound("vpn")};
    auto result = remove_outbound_dependencies(config, {"vpn"});
    REQUIRE(result.outbounds.has_value());
    CHECK(result.outbounds->empty());
    CHECK_FALSE(result.route.has_value());
    CHECK_FALSE(result.dns.has_value());
    CHECK_FALSE(result.lists.has_value());
    CHECK_FALSE(result.list_refresh.has_value());

    config.route = RouteConfig{};
    config.dns = DnsConfig{};
    ListConfig list;
    list.fallback_detours = std::vector<std::string>{};
    config.lists = std::map<std::string, ListConfig>{{"list", list}};
    ListRefreshConfig refresh;
    refresh.fallback_detours = std::vector<std::string>{};
    config.list_refresh = refresh;
    result = remove_outbound_dependencies(config, {"vpn"});
    CHECK_FALSE(result.route->rules.has_value());
    CHECK_FALSE(result.dns->servers.has_value());
    REQUIRE(result.lists->at("list").fallback_detours.has_value());
    CHECK(result.lists->at("list").fallback_detours->empty());
    REQUIRE(result.list_refresh->fallback_detours.has_value());
    CHECK(result.list_refresh->fallback_detours->empty());
}

TEST_CASE("outbound delete ignores absent targets and system outbounds") {
    auto config = fixture();
    for (const auto type : {OutboundType::TABLE, OutboundType::IGNORE,
                            OutboundType::BLACKHOLE}) {
        auto system = interface_outbound("system-" + std::to_string(static_cast<int>(type)));
        system.type = type;
        config.outbounds->push_back(system);
        CHECK(nlohmann::json(remove_outbound_dependencies(config, {system.tag})) ==
              nlohmann::json(config));
    }
    CHECK(nlohmann::json(remove_outbound_dependencies(config, {})) ==
          nlohmann::json(config));
    CHECK(nlohmann::json(remove_outbound_dependencies(config, {"missing"})) ==
          nlohmann::json(config));
    CHECK(nlohmann::json(remove_outbound_dependencies(Config{}, {"vpn"})) ==
          nlohmann::json(Config{}));
}

TEST_CASE("outbound delete preserves inactive fallback metadata") {
    for (const auto policy : {api::FailurePolicy::INHERIT, api::FailurePolicy::BLOCK}) {
        auto config = fixture();
        auto& rule = config.route->rules->back();
        rule.failure_policy = policy;
        const auto result = remove_outbound_dependencies(config, {"vpn"});
        CHECK(result.route->rules->back().failure_policy == policy);
        CHECK(result.route->rules->back().fallback_outbound == "single");
    }
}

TEST_CASE("outbound delete accepts several targets and direct group deletion") {
    auto config = fixture();
    auto result = remove_outbound_dependencies(config, {"vpn", "backup"});
    CHECK(result.outbounds->empty());
    CHECK(result.route->rules->empty());
    result = remove_outbound_dependencies(config, {"single"});
    REQUIRE(result.outbounds->size() == 3);
    CHECK(result.outbounds->at(0).tag == "vpn");
    CHECK(result.outbounds->at(1).tag == "backup");
    CHECK(result.outbounds->at(2).tag == "survivor");
    CHECK(result.outbounds->at(2).outbound_groups->size() == 2);
}

TEST_CASE("native outbound delete plans active and rebound draft tags independently") {
    Config active;
    auto first = interface_outbound("first");
    first.interface = "nwg5";
    auto second = interface_outbound("second");
    second.interface = "nwg8";
    active.outbounds = std::vector<Outbound>{first, second, selector("group", {{"second"}})};
    RouteRule first_rule;
    first_rule.outbound = "first";
    RouteRule second_rule;
    second_rule.outbound = "second";
    active.route = RouteConfig{};
    active.route->rules = std::vector<RouteRule>{first_rule, second_rule};
    Config draft = active;
    draft.outbounds->at(0).interface = "nwg8";
    draft.outbounds->at(1).interface = "nwg5";
    draft.outbounds->at(2) = selector("group", {{"first"}});
    draft.daemon = DaemonConfig{};
    draft.daemon->ipv6_enabled = true;

    const auto active_plan = plan_native_interface_outbound_delete(active, "nwg5");
    const auto draft_plan = plan_native_interface_outbound_delete(draft, "nwg5");
    CHECK(active_plan.tags == std::set<std::string>{"first"});
    CHECK(draft_plan.tags == std::set<std::string>{"second"});
    CHECK_FALSE(active_plan.used_by_group);
    CHECK_FALSE(draft_plan.used_by_group);
    auto expected_active = active;
    expected_active.outbounds->erase(expected_active.outbounds->begin());
    expected_active.route->rules->erase(expected_active.route->rules->begin());
    auto expected_draft = draft;
    expected_draft.outbounds->erase(expected_draft.outbounds->begin() + 1);
    expected_draft.route->rules->erase(expected_draft.route->rules->begin() + 1);
    CHECK(nlohmann::json(active_plan.config) == nlohmann::json(expected_active));
    CHECK(nlohmann::json(draft_plan.config) == nlohmann::json(expected_draft));
    CHECK(nlohmann::json(plan_native_interface_outbound_delete(active, "").config) ==
          nlohmann::json(active));
}

TEST_CASE("native outbound delete keeps group membership as an explicit user change") {
    const auto original = fixture();
    const auto plan = plan_native_interface_outbound_delete(original, "tun-vpn");
    CHECK(plan.tags == std::set<std::string>{"vpn"});
    CHECK(plan.used_by_group);
    CHECK(nlohmann::json(plan.config) == nlohmann::json(original));
    const auto missing = plan_native_interface_outbound_delete(original, "nwg99");
    CHECK(missing.tags.empty());
    CHECK_FALSE(missing.used_by_group);
    CHECK(nlohmann::json(missing.config) == nlohmann::json(original));
}

} // namespace keen_pbr3
