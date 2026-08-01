#include <doctest/doctest.h>

#include "../src/config/config.hpp"
#include "../src/config/routing_state.hpp"
#include "../src/util/system_info.hpp"

#include <nlohmann/json.hpp>
#include <string>

using namespace keen_pbr3;

namespace {

struct SystemInfoTestGuard {
    ~SystemInfoTestGuard() { reset_system_info_for_tests(); }
};

Config parse_test_config(const std::string& json_str) {
    Config cfg = parse_config(json_str);
    if (!cfg.dns.has_value()) {
        cfg.dns = DnsConfig{};
    }
    if (!cfg.dns->servers.has_value()) {
        DnsServer fallback_server;
        fallback_server.tag = "default_dns";
        fallback_server.address = "127.0.0.1";
        cfg.dns->servers = std::vector<DnsServer>{fallback_server};
    }
    if (!cfg.dns->fallback.has_value()) {
        cfg.dns->fallback = std::vector<std::string>{"default_dns"};
    }
    if (!cfg.dns->system_resolver.has_value()) {
        api::SystemResolver resolver;
        resolver.address = "127.0.0.1";
        cfg.dns->system_resolver = resolver;
    }
    validate_config(cfg);
    return cfg;
}

} // namespace

// Helper: build a minimal valid config JSON with a single list entry.
static std::string list_config_json(const std::string& list_name,
                                    const std::string& list_body = R"({"ip_cidrs":["10.0.0.1"]})") {
    nlohmann::json config;
    config["lists"] = nlohmann::json::object();
    config["lists"][list_name] = nlohmann::json::parse(list_body);
    return config.dump();
}

static std::vector<ConfigValidationIssue> parse_issues(const std::string& json) {
    try {
        (void)parse_config(json);
        return {};
    } catch (const ConfigValidationError& e) {
        return e.issues();
    }
}

static std::vector<ConfigValidationIssue> validate_issues(const std::string& json) {
    try {
        auto cfg = parse_config(json);
        if (!cfg.dns.has_value()) {
            cfg.dns = DnsConfig{};
        }
        if (!cfg.dns->servers.has_value()) {
            DnsServer fallback_server;
            fallback_server.tag = "default_dns";
            fallback_server.address = "127.0.0.1";
            cfg.dns->servers = std::vector<DnsServer>{fallback_server};
        }
        if (!cfg.dns->fallback.has_value()) {
            cfg.dns->fallback = std::vector<std::string>{"default_dns"};
        }
        if (!cfg.dns->system_resolver.has_value()) {
            api::SystemResolver resolver;
            resolver.address = "127.0.0.1";
            cfg.dns->system_resolver = resolver;
        }
        validate_config(cfg);
        return {};
    } catch (const ConfigValidationError& e) {
        return e.issues();
    }
}

static const ConfigValidationIssue* find_issue(
    const std::vector<ConfigValidationIssue>& issues,
    const std::string& path) {
    for (const auto& issue : issues) {
        if (issue.path == path) {
            return &issue;
        }
    }
    return nullptr;
}

// =============================================================================
// List name: length validation
// =============================================================================

TEST_CASE("list name: exactly 24 chars is valid") {
    const std::string name(24, 'a'); // "aaaaaaaaaaaaaaaaaaaaaaaa"
    CHECK_NOTHROW(parse_test_config(list_config_json(name)));
}

TEST_CASE("list name: 25 chars is rejected") {
    const std::string name(25, 'a');
    CHECK_THROWS_AS(parse_test_config(list_config_json(name)), ConfigError);
}

TEST_CASE("list name: 1 char is valid") {
    CHECK_NOTHROW(parse_test_config(list_config_json("a")));
}

TEST_CASE("list name: empty string is rejected") {
    // JSON object key "" is valid JSON but must be rejected by our validation.
    const std::string json = R"({"lists":{"":{"ip_cidrs":["10.0.0.1"]}}})";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

// =============================================================================
// List name: character set validation
// =============================================================================

TEST_CASE("list name: lowercase letters only is valid") {
    CHECK_NOTHROW(parse_test_config(list_config_json("mylist")));
}

TEST_CASE("list name: uppercase letters are rejected") {
    CHECK_THROWS_AS(parse_test_config(list_config_json("MyList")), ConfigError);
}

TEST_CASE("list name: uppercase first char is rejected") {
    CHECK_THROWS_AS(parse_test_config(list_config_json("Mylist")), ConfigError);
}

TEST_CASE("list name: mixed case + digits + underscore is rejected") {
    CHECK_THROWS_AS(parse_test_config(list_config_json("My_List01")), ConfigError);
}

TEST_CASE("list name: lowercase + digits + underscore is valid") {
    CHECK_NOTHROW(parse_test_config(list_config_json("my_list01")));
}

TEST_CASE("list name: first char digit is rejected") {
    CHECK_THROWS_AS(parse_test_config(list_config_json("1list")), ConfigError);
}

TEST_CASE("list name: first char underscore is rejected") {
    CHECK_THROWS_AS(parse_test_config(list_config_json("_list")), ConfigError);
}

TEST_CASE("list name: hyphen in name is rejected") {
    CHECK_THROWS_AS(parse_test_config(list_config_json("my-list")), ConfigError);
}

TEST_CASE("list name: space in name is rejected") {
    CHECK_THROWS_AS(parse_test_config(list_config_json("my list")), ConfigError);
}

TEST_CASE("list name: dot in name is rejected") {
    CHECK_THROWS_AS(parse_test_config(list_config_json("my.list")), ConfigError);
}

TEST_CASE("list display_name supports unicode and round-trips") {
    const auto parsed = parse_test_config(
        list_config_json(
            "ai_services",
            R"({"display_name":"Сервисы ИИ","domains":["example.com"]})"));
    REQUIRE(parsed.lists.has_value());
    REQUIRE(parsed.lists->at("ai_services").display_name.has_value());
    CHECK(*parsed.lists->at("ai_services").display_name == "Сервисы ИИ");

    const auto serialized = nlohmann::json(parsed);
    CHECK(serialized.at("lists")
              .at("ai_services")
              .at("display_name") == "Сервисы ИИ");
    const auto reparsed = parse_test_config(serialized.dump());
    REQUIRE(reparsed.lists->at("ai_services").display_name.has_value());
    CHECK(*reparsed.lists->at("ai_services").display_name == "Сервисы ИИ");
}

TEST_CASE("catalog list identity is a lowercase SHA-256 digest") {
    const std::string valid_identity(64U, 'a');
    const auto parsed = parse_test_config(
        list_config_json(
            "catalog_list",
            nlohmann::json{
                {"catalog_identity", valid_identity},
                {"domains", nlohmann::json::array({"example.com"})},
            }
                .dump()));
    REQUIRE(parsed.lists->at("catalog_list").catalog_identity.has_value());
    CHECK(
        *parsed.lists->at("catalog_list").catalog_identity ==
        valid_identity);

    const auto uppercase = validate_issues(
        list_config_json(
            "catalog_list",
            nlohmann::json{
                {"catalog_identity", std::string(64U, 'A')},
                {"domains", nlohmann::json::array({"example.com"})},
            }
                .dump()));
    REQUIRE(uppercase.size() == 1U);
    CHECK(uppercase.front().path == "lists.catalog_list.catalog_identity");

    const auto short_identity = validate_issues(
        list_config_json(
            "catalog_list",
            nlohmann::json{
                {"catalog_identity", std::string(63U, 'a')},
                {"domains", nlohmann::json::array({"example.com"})},
            }
                .dump()));
    REQUIRE(short_identity.size() == 1U);
    CHECK(
        short_identity.front().path ==
        "lists.catalog_list.catalog_identity");
}

TEST_CASE("catalog list identity is unique across configured lists") {
    const std::string identity(64U, 'c');
    nlohmann::json config;
    config["lists"] = {
        {"first",
         {{"catalog_identity", identity},
          {"domains", nlohmann::json::array({"first.example"})}}},
        {"second",
         {{"catalog_identity", identity},
          {"domains", nlohmann::json::array({"second.example"})}}},
    };

    const auto issues = validate_issues(config.dump());
    REQUIRE(issues.size() == 1U);
    CHECK(issues.front().path == "lists.second.catalog_identity");
    CHECK(
        issues.front().message ==
        "lists.second.catalog_identity duplicates catalogue provenance "
        "first declared at lists.first.catalog_identity");
}

TEST_CASE("list display_name rejects blank and ASCII control values") {
    const auto blank = validate_issues(
        list_config_json(
            "ads",
            R"({"display_name":" \t\r\n ","domains":["example.com"]})"));
    REQUIRE(blank.size() == 1);
    CHECK(blank[0].path == "lists.ads.display_name");

    const auto control = validate_issues(
        list_config_json(
            "ads",
            R"({"display_name":"Ads\u0007list","domains":["example.com"]})"));
    REQUIRE(control.size() == 1);
    CHECK(control[0].path == "lists.ads.display_name");

    const auto unicode_blank = validate_issues(
        list_config_json(
            "ads",
            R"({"display_name":"\u00a0\u3000","domains":["example.com"]})"));
    REQUIRE(unicode_blank.size() == 1);
    CHECK(unicode_blank[0].path == "lists.ads.display_name");
}

TEST_CASE("display_name rejects C1 and bidirectional controls") {
    const auto c1 = validate_issues(
        list_config_json(
            "ads",
            R"({"display_name":"Ads\u0080list","domains":["example.com"]})"));
    REQUIRE(c1.size() == 1);
    CHECK(c1[0].path == "lists.ads.display_name");

    const auto bidi = validate_issues(
        list_config_json(
            "ads",
            R"({"display_name":"Safe\u202Etxt.exe","domains":["example.com"]})"));
    REQUIRE(bidi.size() == 1);
    CHECK(bidi[0].path == "lists.ads.display_name");

    CHECK_NOTHROW(parse_test_config(list_config_json(
        "family",
        R"({"display_name":"Семья 👨‍👩‍👦","domains":["example.com"]})")));
}

TEST_CASE("list display_name limit counts Unicode code points") {
    std::string valid_alias;
    for (size_t index = 0; index < 80; ++index) valid_alias += "Я";
    const std::string too_long_alias = valid_alias + "Я";

    nlohmann::json valid_body{
        {"display_name", valid_alias},
        {"domains", nlohmann::json::array({"example.com"})},
    };
    CHECK_NOTHROW(parse_test_config(
        list_config_json("unicode", valid_body.dump())));

    nlohmann::json invalid_body{
        {"display_name", too_long_alias},
        {"domains", nlohmann::json::array({"example.com"})},
    };
    const auto issues = validate_issues(
        list_config_json("unicode", invalid_body.dump()));
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "lists.unicode.display_name");
}

TEST_CASE("legacy config without UI preferences remains valid") {
    const auto config = parse_test_config(
        R"({"lists":{"legacy":{"domains":["example.com"]}}})");
    CHECK_FALSE(config.ui_preferences.has_value());
}

TEST_CASE("remote list accepts at most three ordered routable fallbacks") {
    const auto config = parse_test_config(R"({
        "outbounds":[
            {"tag":"primary","type":"interface","interface":"eth0"},
            {"tag":"backup_a","type":"interface","interface":"eth1"},
            {"tag":"backup_b","type":"table","table":201},
            {"tag":"backup_c","type":"interface","interface":"eth2"}
        ],
        "lists":{"remote":{
            "url":"https://example.test/list.txt",
            "detour":"primary",
            "fallback_detours":["backup_a","backup_b","backup_c"]
        }}
    })");

    REQUIRE(config.lists.has_value());
    REQUIRE(config.lists->at("remote").fallback_detours.has_value());
    CHECK(*config.lists->at("remote").fallback_detours ==
          std::vector<std::string>{"backup_a", "backup_b", "backup_c"});
}

TEST_CASE("remote list fallback validation prevents implicit or invalid routes") {
    const auto no_primary = validate_issues(R"({
        "outbounds":[
            {"tag":"backup","type":"interface","interface":"eth1"}
        ],
        "lists":{"remote":{
            "url":"https://example.test/list.txt",
            "fallback_detours":["backup"]
        }}
    })");
    CHECK(find_issue(no_primary, "lists.remote.fallback_detours") != nullptr);

    const auto too_many = validate_issues(R"({
        "outbounds":[
            {"tag":"primary","type":"interface","interface":"eth0"},
            {"tag":"a","type":"interface","interface":"eth1"},
            {"tag":"b","type":"interface","interface":"eth2"},
            {"tag":"c","type":"interface","interface":"eth3"},
            {"tag":"d","type":"interface","interface":"eth4"}
        ],
        "lists":{"remote":{
            "url":"https://example.test/list.txt",
            "detour":"primary",
            "fallback_detours":["a","b","c","d"]
        }}
    })");
    CHECK(find_issue(too_many, "lists.remote.fallback_detours") != nullptr);

    const auto duplicate = validate_issues(R"({
        "outbounds":[
            {"tag":"primary","type":"interface","interface":"eth0"}
        ],
        "lists":{"remote":{
            "url":"https://example.test/list.txt",
            "detour":"primary",
            "fallback_detours":["primary"]
        }}
    })");
    CHECK(find_issue(
              duplicate, "lists.remote.fallback_detours[0]") != nullptr);
}

TEST_CASE("global list refresh chain accepts ordered routable fallbacks and round-trips") {
    const auto config = parse_test_config(R"({
        "outbounds":[
            {"tag":"primary","type":"interface","interface":"eth0"},
            {"tag":"backup_a","type":"interface","interface":"eth1"},
            {"tag":"backup_b","type":"table","table":201}
        ],
        "list_refresh":{
            "detour":"primary",
            "fallback_detours":["backup_a","backup_b"]
        },
        "lists":{
            "inherited":{"url":"https://example.test/inherited.txt"},
            "explicit_inherited":{
                "url":"https://example.test/explicit.txt",
                "refresh_detour_mode":"inherit"
            }
        }
    })");

    REQUIRE(config.list_refresh.has_value());
    REQUIRE(config.list_refresh->detour.has_value());
    CHECK(*config.list_refresh->detour == "primary");
    REQUIRE(config.list_refresh->fallback_detours.has_value());
    CHECK(*config.list_refresh->fallback_detours ==
          std::vector<std::string>{"backup_a", "backup_b"});

    REQUIRE(config.lists.has_value());
    CHECK(effective_list_refresh_detour_mode(
              config.lists->at("inherited")) ==
          ListRefreshDetourMode::INHERIT);
    CHECK(effective_list_refresh_detours(
              config, config.lists->at("inherited")) ==
          std::vector<std::string>{"primary", "backup_a", "backup_b"});
    CHECK(effective_list_refresh_detours(
              config, config.lists->at("explicit_inherited")) ==
          std::vector<std::string>{"primary", "backup_a", "backup_b"});

    const auto reparsed = parse_test_config(nlohmann::json(config).dump());
    REQUIRE(reparsed.list_refresh.has_value());
    REQUIRE(reparsed.list_refresh->fallback_detours.has_value());
    CHECK(*reparsed.list_refresh->fallback_detours ==
          std::vector<std::string>{"backup_a", "backup_b"});
    REQUIRE(reparsed.lists->at("explicit_inherited")
                .refresh_detour_mode.has_value());
    CHECK(*reparsed.lists->at("explicit_inherited")
               .refresh_detour_mode ==
          ListRefreshDetourMode::INHERIT);
}

TEST_CASE("list refresh parse errors preserve their field paths") {
    const auto wrong_global_type = parse_issues(R"({
        "list_refresh":"proxy"
    })");
    CHECK(find_issue(wrong_global_type, "list_refresh") != nullptr);

    const auto wrong_mode_type = parse_issues(R"({
        "lists":{"remote":{
            "url":"https://example.test/list.txt",
            "refresh_detour_mode":true
        }}
    })");
    CHECK(find_issue(
              wrong_mode_type,
              "lists.remote.refresh_detour_mode") != nullptr);

    const auto unknown_mode = parse_issues(R"({
        "lists":{"remote":{
            "url":"https://example.test/list.txt",
            "refresh_detour_mode":"automatic"
        }}
    })");
    const auto* issue = find_issue(
        unknown_mode,
        "lists.remote.refresh_detour_mode");
    REQUIRE(issue != nullptr);
    CHECK(issue->message.find("inherit, override") != std::string::npos);
}

TEST_CASE("legacy per-list refresh chain remains an override when global routing is configured") {
    const auto config = parse_test_config(R"({
        "outbounds":[
            {"tag":"global","type":"interface","interface":"eth0"},
            {"tag":"legacy","type":"interface","interface":"eth1"},
            {"tag":"legacy_backup","type":"table","table":202}
        ],
        "list_refresh":{"detour":"global"},
        "lists":{"remote":{
            "url":"https://example.test/list.txt",
            "detour":"legacy",
            "fallback_detours":["legacy_backup"]
        }}
    })");

    const auto& remote = config.lists->at("remote");
    CHECK_FALSE(remote.refresh_detour_mode.has_value());
    CHECK(effective_list_refresh_detour_mode(remote) ==
          ListRefreshDetourMode::OVERRIDE);
    CHECK(effective_list_refresh_detours(config, remote) ==
          std::vector<std::string>{"legacy", "legacy_backup"});

    const auto serialized = nlohmann::json(config);
    CHECK(serialized.at("lists")
              .at("remote")
              .at("refresh_detour_mode")
              .is_null());
}

TEST_CASE("explicit list refresh override replaces the global chain") {
    const auto config = parse_test_config(R"({
        "outbounds":[
            {"tag":"global","type":"interface","interface":"eth0"},
            {"tag":"special","type":"interface","interface":"eth1"},
            {"tag":"special_backup","type":"table","table":203}
        ],
        "list_refresh":{"detour":"global"},
        "lists":{"remote":{
            "url":"https://example.test/list.txt",
            "refresh_detour_mode":"override",
            "detour":"special",
            "fallback_detours":["special_backup"]
        }}
    })");

    const auto& remote = config.lists->at("remote");
    CHECK(effective_list_refresh_detour_mode(remote) ==
          ListRefreshDetourMode::OVERRIDE);
    CHECK(effective_list_refresh_detours(config, remote) ==
          std::vector<std::string>{"special", "special_backup"});
}

TEST_CASE("list refresh route validation rejects ambiguous or unroutable policies") {
    const auto global_without_primary = validate_issues(R"({
        "outbounds":[
            {"tag":"backup","type":"interface","interface":"eth1"}
        ],
        "list_refresh":{"fallback_detours":["backup"]}
    })");
    CHECK(find_issue(
              global_without_primary,
              "list_refresh.fallback_detours") != nullptr);

    const auto global_duplicate = validate_issues(R"({
        "outbounds":[
            {"tag":"primary","type":"interface","interface":"eth0"}
        ],
        "list_refresh":{
            "detour":"primary",
            "fallback_detours":["primary"]
        }
    })");
    CHECK(find_issue(
              global_duplicate,
              "list_refresh.fallback_detours[0]") != nullptr);

    const auto inherit_with_local_chain = validate_issues(R"({
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"eth0"}
        ],
        "lists":{"remote":{
            "url":"https://example.test/list.txt",
            "refresh_detour_mode":"inherit",
            "detour":"vpn"
        }}
    })");
    CHECK(find_issue(
              inherit_with_local_chain,
              "lists.remote.refresh_detour_mode") != nullptr);

    const auto override_without_primary = validate_issues(R"({
        "lists":{"remote":{
            "url":"https://example.test/list.txt",
            "refresh_detour_mode":"override"
        }}
    })");
    CHECK(find_issue(
              override_without_primary,
              "lists.remote.detour") != nullptr);

    const auto mode_on_inline_list = validate_issues(R"({
        "lists":{"inline":{
            "domains":["example.test"],
            "refresh_detour_mode":"inherit"
        }}
    })");
    CHECK(find_issue(
              mode_on_inline_list,
              "lists.inline.refresh_detour_mode") != nullptr);

    const auto unroutable_global = validate_issues(R"({
        "outbounds":[{"tag":"blocked","type":"blackhole"}],
        "list_refresh":{"detour":"blocked"}
    })");
    CHECK(find_issue(
              unroutable_global,
              "list_refresh.detour") != nullptr);
}

TEST_CASE("legacy config without aliases or stable rule ids round-trips") {
    const auto parsed = parse_test_config(R"({
        "lists":{"legacy":{"domains":["example.com"]}},
        "outbounds":[
            {"tag":"wan","type":"interface","interface":"eth0"}
        ],
        "route":{"rules":[
            {"list":["legacy"],"outbound":"wan"}
        ]},
        "dns":{
            "servers":[{"tag":"plain","address":"1.1.1.1"}],
            "fallback":["plain"],
            "rules":[{"list":["legacy"],"server":"plain"}]
        }
    })");

    REQUIRE(parsed.lists.has_value());
    CHECK_FALSE(parsed.lists->at("legacy").display_name.has_value());
    REQUIRE(parsed.outbounds.has_value());
    CHECK_FALSE(parsed.outbounds->front().display_name.has_value());
    REQUIRE(parsed.route.has_value());
    REQUIRE(parsed.route->rules.has_value());
    CHECK_FALSE(parsed.route->rules->front().id.has_value());
    CHECK_FALSE(parsed.route->rules->front().display_name.has_value());
    REQUIRE(parsed.dns.has_value());
    REQUIRE(parsed.dns->servers.has_value());
    CHECK_FALSE(parsed.dns->servers->front().display_name.has_value());
    REQUIRE(parsed.dns->rules.has_value());
    CHECK_FALSE(parsed.dns->rules->front().id.has_value());
    CHECK_FALSE(parsed.dns->rules->front().display_name.has_value());

    const auto reparsed = parse_test_config(nlohmann::json(parsed).dump());
    CHECK(reparsed.route->rules->front().outbound == "wan");
    REQUIRE(reparsed.route->rules->front().list.has_value());
    CHECK(reparsed.route->rules->front().list->front() == "legacy");
    CHECK(reparsed.dns->rules->front().server == "plain");
}

TEST_CASE("UI preferences round-trip hidden native interfaces and plain DNS templates") {
    const auto config = parse_test_config(R"({
        "ui_preferences": {
            "hidden_native_interface_ids": ["Wireguard0", "OpenVPN1"],
            "plain_dns_templates": [
                {
                    "name": "Office DNS",
                    "primary_ipv4": "192.0.2.53",
                    "secondary_ipv4": "192.0.2.54"
                }
            ]
        }
    })");

    REQUIRE(config.ui_preferences.has_value());
    REQUIRE(config.ui_preferences->hidden_native_interface_ids.has_value());
    CHECK(config.ui_preferences->hidden_native_interface_ids->size() == 2);
    REQUIRE(config.ui_preferences->plain_dns_templates.has_value());
    REQUIRE(config.ui_preferences->plain_dns_templates->size() == 1);
    CHECK(config.ui_preferences->plain_dns_templates->front().name ==
          "Office DNS");

    const auto serialized = nlohmann::json(config);
    CHECK(serialized.at("ui_preferences")
              .at("plain_dns_templates")
              .at(0)
              .at("primary_ipv4") == "192.0.2.53");
    CHECK_NOTHROW(parse_test_config(serialized.dump()));
}

TEST_CASE("hidden native interface preferences permit stale inventory ids") {
    const auto config = parse_test_config(R"({
        "ui_preferences": {
            "hidden_native_interface_ids": ["FormerTunnel", "Wireguard0"]
        }
    })");

    REQUIRE(config.ui_preferences.has_value());
    REQUIRE(config.ui_preferences->hidden_native_interface_ids.has_value());
    CHECK(*config.ui_preferences->hidden_native_interface_ids ==
          std::vector<std::string>{"FormerTunnel", "Wireguard0"});

    const auto reparsed = parse_test_config(nlohmann::json(config).dump());
    REQUIRE(reparsed.ui_preferences.has_value());
    REQUIRE(reparsed.ui_preferences->hidden_native_interface_ids.has_value());
    CHECK(*reparsed.ui_preferences->hidden_native_interface_ids ==
          std::vector<std::string>{"FormerTunnel", "Wireguard0"});
}

TEST_CASE("native VPN service policies round-trip with stable NDMS ids") {
    const auto config = parse_test_config(R"({
        "route": {
            "internal_vpn_services": [
                {
                    "service_id": "ndms-crypto-map:RemoteUsers",
                    "process_clients": true
                },
                {
                    "service_id": "ndms-service:sstp-server",
                    "process_clients": false
                }
            ]
        }
    })");

    REQUIRE(config.route.has_value());
    REQUIRE(config.route->internal_vpn_services.has_value());
    REQUIRE(config.route->internal_vpn_services->size() == 2U);
    CHECK(config.route->internal_vpn_services->at(0).service_id ==
          "ndms-crypto-map:RemoteUsers");
    CHECK(config.route->internal_vpn_services->at(0).process_clients);
    CHECK_FALSE(config.route->internal_vpn_services->at(1).process_clients);

    const auto reparsed = parse_test_config(nlohmann::json(config).dump());
    REQUIRE(reparsed.route->internal_vpn_services.has_value());
    CHECK(reparsed.route->internal_vpn_services->at(1).service_id ==
          "ndms-service:sstp-server");
}

TEST_CASE("native VPN service policies reject duplicates and invalid ids") {
    const auto duplicate = validate_issues(R"({
        "route": {
            "internal_vpn_services": [
                {
                    "service_id": "ndms-service:sstp-server",
                    "process_clients": true
                },
                {
                    "service_id": "ndms-service:sstp-server",
                    "process_clients": false
                }
            ]
        }
    })");
    CHECK(find_issue(
              duplicate,
              "route.internal_vpn_services[1].service_id") != nullptr);

    const auto invalid = parse_issues(R"({
        "route": {
            "internal_vpn_services": [
                {
                    "service_id": "ndms service with spaces",
                    "process_clients": true
                }
            ]
        }
    })");
    CHECK(find_issue(
              invalid,
              "route.internal_vpn_services[0].service_id") != nullptr);

    const auto non_ascii = parse_issues(R"({
        "route": {
            "internal_vpn_services": [
                {
                    "service_id": "ndms-service:сервер",
                    "process_clients": true
                }
            ]
        }
    })");
    CHECK(find_issue(
              non_ascii,
              "route.internal_vpn_services[0].service_id") != nullptr);

    const auto wrong_type = parse_issues(R"({
        "route": {
            "internal_vpn_services": [
                {
                    "service_id": "ndms-service:sstp-server",
                    "process_clients": "yes"
                }
            ]
        }
    })");
    CHECK(find_issue(
              wrong_type,
              "route.internal_vpn_services[0].process_clients") != nullptr);
}

TEST_CASE("native VPN service policy count is bounded") {
    nlohmann::json config;
    config["route"]["internal_vpn_services"] = nlohmann::json::array();
    for (std::size_t index = 0; index < 33U; ++index) {
        config["route"]["internal_vpn_services"].push_back({
            {"service_id", "ndms-service:test-" + std::to_string(index)},
            {"process_clients", true},
        });
    }

    const auto issues = parse_issues(config.dump());
    CHECK(find_issue(
              issues,
              "route.internal_vpn_services") != nullptr);
}

TEST_CASE("UI preferences reject invalid or duplicate hidden native interface ids") {
    const auto invalid = validate_issues(R"({
        "ui_preferences": {
            "hidden_native_interface_ids": ["Wireguard0", "Wireguard0", " "]
        }
    })");

    CHECK(find_issue(
              invalid,
              "ui_preferences.hidden_native_interface_ids[1]") != nullptr);
    CHECK(find_issue(
              invalid,
              "ui_preferences.hidden_native_interface_ids[2]") != nullptr);
}

TEST_CASE("UI preferences enforce hidden native interface count bound") {
    nlohmann::json json;
    json["ui_preferences"]["hidden_native_interface_ids"] =
        nlohmann::json::array();
    for (size_t index = 0; index < 129; ++index) {
        json["ui_preferences"]["hidden_native_interface_ids"].push_back(
            "Tunnel" + std::to_string(index));
    }

    const auto issues = validate_issues(json.dump());
    CHECK(find_issue(
              issues,
              "ui_preferences.hidden_native_interface_ids") != nullptr);
}

TEST_CASE("plain DNS templates require unique names and valid distinct IPv4 addresses") {
    const auto issues = validate_issues(R"({
        "ui_preferences": {
            "plain_dns_templates": [
                {
                    "name": "Office DNS",
                    "primary_ipv4": "192.0.2.53",
                    "secondary_ipv4": "192.0.2.53"
                },
                {
                    "name": "office dns",
                    "primary_ipv4": "999.0.2.53"
                }
            ]
        }
    })");

    CHECK(find_issue(
              issues,
              "ui_preferences.plain_dns_templates[0].secondary_ipv4") != nullptr);
    CHECK(find_issue(
              issues,
              "ui_preferences.plain_dns_templates[1].name") != nullptr);
    CHECK(find_issue(
              issues,
              "ui_preferences.plain_dns_templates[1].primary_ipv4") != nullptr);
}

TEST_CASE("plain DNS templates enforce count bound") {
    nlohmann::json json;
    json["ui_preferences"]["plain_dns_templates"] = nlohmann::json::array();
    for (size_t index = 0; index < 33; ++index) {
        json["ui_preferences"]["plain_dns_templates"].push_back({
            {"name", "DNS " + std::to_string(index)},
            {"primary_ipv4", "192.0.2." + std::to_string(index + 1)},
        });
    }

    const auto issues = validate_issues(json.dump());
    CHECK(find_issue(
              issues,
              "ui_preferences.plain_dns_templates") != nullptr);
}

TEST_CASE("list display_name is not a routing reference") {
    CHECK_NOTHROW(parse_test_config(R"({
        "lists":{"ai":{"display_name":"Сервисы ИИ","domains":["example.com"]}},
        "outbounds":[{"tag":"wan","type":"interface","interface":"eth0"}],
        "route":{"rules":[{"list":["ai"],"outbound":"wan"}]}
    })"));

    const auto issues = validate_issues(R"({
        "lists":{"ai":{"display_name":"Сервисы ИИ","domains":["example.com"]}},
        "outbounds":[{"tag":"wan","type":"interface","interface":"eth0"}],
        "route":{"rules":[{"list":["Сервисы ИИ"],"outbound":"wan"}]}
    })");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "route.rules[0].list[0]");
    CHECK(issues[0].message.find("unknown list") != std::string::npos);
}

TEST_CASE("friendly names and stable rule ids round-trip independently") {
    const auto parsed = parse_test_config(R"({
        "lists":{
            "ai":{"display_name":"Сервисы ИИ","domains":["example.com"]}
        },
        "outbounds":[
            {"tag":"vpn","display_name":"Основной VPN","type":"interface","interface":"wg0"}
        ],
        "route":{"rules":[
            {"id":"route_ai","display_name":"ИИ через VPN","list":["ai"],"outbound":"vpn"}
        ]},
        "dns":{
            "servers":[
                {"tag":"secure_dns","display_name":"Безопасный DNS","address":"1.1.1.1"}
            ],
            "fallback":["secure_dns"],
            "rules":[
                {"id":"dns_ai","display_name":"DNS для ИИ","list":["ai"],"server":"secure_dns"}
            ]
        }
    })");

    REQUIRE(parsed.outbounds.has_value());
    REQUIRE(parsed.outbounds->at(0).display_name.has_value());
    CHECK(*parsed.outbounds->at(0).display_name == "Основной VPN");
    REQUIRE(parsed.route.has_value());
    REQUIRE(parsed.route->rules.has_value());
    REQUIRE(parsed.route->rules->at(0).id.has_value());
    CHECK(*parsed.route->rules->at(0).id == "route_ai");
    CHECK(*parsed.route->rules->at(0).display_name == "ИИ через VPN");
    REQUIRE(parsed.dns->servers.has_value());
    CHECK(*parsed.dns->servers->at(0).display_name == "Безопасный DNS");
    REQUIRE(parsed.dns->rules.has_value());
    CHECK(*parsed.dns->rules->at(0).id == "dns_ai");
    CHECK(*parsed.dns->rules->at(0).display_name == "DNS для ИИ");

    const auto reparsed = parse_test_config(nlohmann::json(parsed).dump());
    REQUIRE(reparsed.route.has_value());
    REQUIRE(reparsed.route->rules.has_value());
    CHECK(*reparsed.route->rules->at(0).display_name == "ИИ через VPN");
    CHECK(*reparsed.dns->rules->at(0).display_name == "DNS для ИИ");
}

TEST_CASE("stable routing and DNS rule ids must be unique") {
    const auto route_issues = validate_issues(R"({
        "lists":{"matched":{"domains":["example.test"]}},
        "outbounds":[{"tag":"wan","type":"interface","interface":"eth0"}],
        "route":{"rules":[
            {"id":"same_rule","list":["matched"],"outbound":"wan"},
            {"id":"same_rule","list":["matched"],"outbound":"wan"}
        ]}
    })");
    CHECK(find_issue(route_issues, "route.rules[1].id") != nullptr);

    const auto dns_issues = validate_issues(R"({
        "dns":{
            "servers":[{"tag":"dns","address":"1.1.1.1"}],
            "fallback":["dns"],
            "rules":[
                {"id":"same_dns","list":[],"server":"dns"},
                {"id":"same_dns","list":[],"server":"dns"}
            ]
        }
    })");
    CHECK(find_issue(dns_issues, "dns.rules[1].id") != nullptr);
}

// =============================================================================
// DNS server detour validation
// =============================================================================

static const std::string kDnsDetourBase = R"({
    "outbounds": [
        {"tag": "vpn", "type": "interface", "interface": "wg0"},
        {"tag": "vpn_table", "type": "table", "table": 100},
        {"tag": "urltest1", "type": "urltest", "url": "http://example.com",
         "outbound_groups": [{"outbounds": ["vpn"]}]},
        {"tag": "blackhole1", "type": "blackhole"},
        {"tag": "ignore1", "type": "ignore"}
    ]
})";

TEST_CASE("dns detour: valid interface outbound") {
    std::string json = R"({"outbounds":[{"tag":"vpn","type":"interface","interface":"wg0"}],
        "dns":{"servers":[{"tag":"vpn_dns","address":"10.8.0.1","detour":"vpn"}],"fallback":["vpn_dns"]}})";
    CHECK_NOTHROW(parse_test_config(json));
}

TEST_CASE("dns detour: valid table outbound") {
    std::string json = R"({"outbounds":[{"tag":"tbl","type":"table","table":100}],
        "dns":{"servers":[{"tag":"tbl_dns","address":"10.8.0.2","detour":"tbl"}],"fallback":["tbl_dns"]}})";
    CHECK_NOTHROW(parse_test_config(json));
}

TEST_CASE("dns detour: valid urltest outbound") {
    std::string json = R"({"outbounds":[
        {"tag":"vpn","type":"interface","interface":"wg0"},
        {"tag":"ut","type":"urltest","url":"http://example.com","outbound_groups":[{"outbounds":["vpn"]}]}
    ],"dns":{"servers":[{"tag":"ut_dns","address":"10.8.0.3","detour":"ut"}],"fallback":["ut_dns"]}})";
    CHECK_NOTHROW(parse_test_config(json));
}

TEST_CASE("urltest URL is required and limited to HTTP(S)") {
    const std::string prefix = R"({"outbounds":[{"tag":"vpn","type":"interface","interface":"wg0"},)";
    const std::string suffix = R"({"tag":"ut","type":"urltest","outbound_groups":[{"outbounds":["vpn"]}]}]})";
    CHECK_THROWS_AS(parse_test_config(prefix + suffix), ConfigError);
    CHECK_THROWS_AS(parse_test_config(prefix + R"({"tag":"ut","type":"urltest","url":"file:///tmp/x","outbound_groups":[{"outbounds":["vpn"]}]}]})"), ConfigError);
    CHECK_THROWS_AS(parse_test_config(prefix + R"({"tag":"ut","type":"urltest","url":"ftp://example.test/x","outbound_groups":[{"outbounds":["vpn"]}]}]})"), ConfigError);
    CHECK_NOTHROW(parse_test_config(prefix + R"({"tag":"ut","type":"urltest","url":"https://example.test/x","outbound_groups":[{"outbounds":["vpn"]}]}]})"));
}

TEST_CASE("urltest selection mode defaults to latency and accepts priority") {
    const auto default_config = parse_test_config(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut","type":"urltest","url":"https://example.test/x",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ]
    })");
    REQUIRE(default_config.outbounds.has_value());
    REQUIRE(default_config.outbounds->size() == 2);
    CHECK_FALSE(default_config.outbounds->at(1).selection_mode.has_value());

    const auto priority_config = parse_test_config(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut","type":"urltest","url":"https://example.test/x",
             "selection_mode":"priority",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ]
    })");
    REQUIRE(priority_config.outbounds.has_value());
    REQUIRE(priority_config.outbounds->at(1).selection_mode.has_value());
    CHECK(*priority_config.outbounds->at(1).selection_mode ==
          UrltestSelectionMode::PRIORITY);

    CHECK_THROWS_AS(parse_test_config(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut","type":"urltest","url":"https://example.test/x",
             "selection_mode":"unknown",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ]
    })"), ConfigError);
}

TEST_CASE("conntrack_on_switch is accepted only for urltest outbounds") {
    const auto preserve = parse_test_config(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut","type":"urltest","url":"https://example.test/x",
             "conntrack_on_switch":"preserve",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ]
    })");
    REQUIRE(preserve.outbounds.has_value());
    REQUIRE(preserve.outbounds->at(1).conntrack_on_switch.has_value());
    CHECK(*preserve.outbounds->at(1).conntrack_on_switch ==
          ConntrackOnSwitch::PRESERVE);

    const auto delete_mode = parse_test_config(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut","type":"urltest","url":"https://example.test/x",
             "conntrack_on_switch":"delete",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ]
    })");
    REQUIRE(delete_mode.outbounds.has_value());
    REQUIRE(delete_mode.outbounds->at(1).conntrack_on_switch.has_value());
    CHECK(*delete_mode.outbounds->at(1).conntrack_on_switch ==
          ConntrackOnSwitch::DELETE);

    const auto failure_only = parse_test_config(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut","type":"urltest","url":"https://example.test/x",
             "selection_mode":"priority",
             "conntrack_on_switch":"delete_on_failure",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ]
    })");
    REQUIRE(failure_only.outbounds.has_value());
    REQUIRE(failure_only.outbounds->at(1).conntrack_on_switch.has_value());
    CHECK(*failure_only.outbounds->at(1).conntrack_on_switch ==
          ConntrackOnSwitch::DELETE_ON_FAILURE);

    const auto latency_failure_only = validate_issues(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut","type":"urltest","url":"https://example.test/x",
             "conntrack_on_switch":"delete_on_failure",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ]
    })");
    CHECK(find_issue(
              latency_failure_only,
              "outbounds.ut.conntrack_on_switch") != nullptr);

    const auto issues = validate_issues(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0",
             "conntrack_on_switch":"preserve"}
        ]
    })");
    CHECK(find_issue(issues, "outbounds.vpn.conntrack_on_switch") != nullptr);
}

TEST_CASE("conntrack delete mode rejects child marks shared with unrelated traffic") {
    const auto direct_route_issues = validate_issues(R"({
        "lists":{"matched":{"domains":["example.test"]}},
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut","type":"urltest","url":"https://example.test/x",
             "conntrack_on_switch":"delete",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ],
        "route":{"rules":[
            {"list":["matched"],"outbound":"vpn"}
        ]}
    })");
    CHECK(find_issue(
              direct_route_issues,
              "outbounds.ut.conntrack_on_switch") != nullptr);

    const auto shared_group_issues = validate_issues(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut1","type":"urltest","url":"https://example.test/x",
             "conntrack_on_switch":"delete",
             "outbound_groups":[{"outbounds":["vpn"]}]},
            {"tag":"ut2","type":"urltest","url":"https://example.test/y",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ]
    })");
    CHECK(find_issue(
              shared_group_issues,
              "outbounds.ut1.conntrack_on_switch") != nullptr);

    const auto nested_group_issues = validate_issues(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"inner","type":"urltest","url":"https://example.test/inner",
             "outbound_groups":[{"outbounds":["vpn"]}]},
            {"tag":"outer","type":"urltest","url":"https://example.test/outer",
             "conntrack_on_switch":"delete",
             "outbound_groups":[{"outbounds":["inner"]}]}
        ]
    })");
    CHECK(find_issue(
              nested_group_issues,
              "outbounds.outer.conntrack_on_switch") != nullptr);

    const auto list_detour_issues = validate_issues(R"({
        "lists":{
            "matched":{
                "url":"https://example.test/list.txt",
                "detour":"vpn"
            }
        },
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut","type":"urltest","url":"https://example.test/x",
             "conntrack_on_switch":"delete",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ]
    })");
    CHECK(find_issue(
              list_detour_issues,
              "outbounds.ut.conntrack_on_switch") != nullptr);
}

TEST_CASE("failure-only conntrack cleanup may share a failed leaf mark") {
    const auto config = parse_test_config(R"({
        "lists":{
            "matched":{
                "url":"https://example.test/list.txt",
                "detour":"vpn"
            }
        },
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"ut","type":"urltest","url":"https://example.test/x",
             "selection_mode":"priority",
             "conntrack_on_switch":"delete_on_failure",
             "outbound_groups":[{"outbounds":["vpn"]}]},
            {"tag":"other","type":"urltest","url":"https://example.test/y",
             "outbound_groups":[{"outbounds":["vpn"]}]}
        ],
        "route":{"rules":[
            {"list":["matched"],"outbound":"vpn"}
        ]}
    })");
    REQUIRE(config.outbounds.has_value());
    CHECK(config.outbounds->at(1).conntrack_on_switch ==
          ConntrackOnSwitch::DELETE_ON_FAILURE);
}

TEST_CASE("urltest numeric fields reject unsafe lower bounds with exact paths") {
    const auto issues = validate_issues(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"backup","type":"interface","interface":"wg1"},
            {
                "tag":"ut",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "interval_ms":0,
                "probe_timeout_ms":0,
                "tolerance_ms":-1,
                "retry":{"attempts":0,"interval_ms":-1},
                "circuit_breaker":{
                    "failure_threshold":0,
                    "success_threshold":0,
                    "timeout_ms":-1,
                    "half_open_max_requests":0
                },
                "outbound_groups":[
                    {"weight":0,"outbounds":["vpn"]},
                    {"weight":-1,"outbounds":["backup"]}
                ]
            }
        ]
    })");

    CHECK(find_issue(issues, "outbounds.ut.interval_ms") != nullptr);
    CHECK(find_issue(issues, "outbounds.ut.probe_timeout_ms") != nullptr);
    CHECK(find_issue(issues, "outbounds.ut.tolerance_ms") != nullptr);
    CHECK(find_issue(issues, "outbounds.ut.retry.attempts") != nullptr);
    CHECK(find_issue(issues, "outbounds.ut.retry.interval_ms") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.circuit_breaker.failure_threshold") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.circuit_breaker.success_threshold") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.circuit_breaker.timeout_ms") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.circuit_breaker.half_open_max_requests") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.outbound_groups[0].weight") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.outbound_groups[1].weight") != nullptr);
}

TEST_CASE("urltest numeric fields reject values that overflow runtime types") {
    const auto issues = validate_issues(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {
                "tag":"ut",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "interval_ms":4294967296,
                "probe_timeout_ms":4294967296,
                "tolerance_ms":4294967296,
                "retry":{"attempts":1001,"interval_ms":4294967296},
                "circuit_breaker":{
                    "failure_threshold":2147483648,
                    "success_threshold":4294967296,
                    "timeout_ms":4294967296,
                    "half_open_max_requests":4294967296
                },
                "outbound_groups":[{"weight":4294967296,"outbounds":["vpn"]}]
            }
        ]
    })");

    CHECK(find_issue(issues, "outbounds.ut.interval_ms") != nullptr);
    CHECK(find_issue(issues, "outbounds.ut.probe_timeout_ms") != nullptr);
    CHECK(find_issue(issues, "outbounds.ut.tolerance_ms") != nullptr);
    CHECK(find_issue(issues, "outbounds.ut.retry.attempts") != nullptr);
    CHECK(find_issue(issues, "outbounds.ut.retry.interval_ms") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.circuit_breaker.failure_threshold") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.circuit_breaker.success_threshold") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.circuit_breaker.timeout_ms") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.circuit_breaker.half_open_max_requests") != nullptr);
    CHECK(find_issue(
              issues,
              "outbounds.ut.outbound_groups[0].weight") != nullptr);
}

TEST_CASE("urltest numeric validation preserves meaningful zero values") {
    CHECK_NOTHROW(parse_test_config(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {
                "tag":"ut",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "interval_ms":1,
                "probe_timeout_ms":1,
                "tolerance_ms":0,
                "retry":{"attempts":1,"interval_ms":0},
                "circuit_breaker":{
                    "failure_threshold":1,
                    "success_threshold":1,
                    "timeout_ms":0,
                    "half_open_max_requests":1
                },
                "outbound_groups":[{"weight":1,"outbounds":["vpn"]}]
            }
        ]
    })"));
}

TEST_CASE("urltest rejects duplicate children within and across groups") {
    const auto issues = validate_issues(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {
                "tag":"ut",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "outbound_groups":[
                    {"outbounds":["vpn","vpn"]},
                    {"outbounds":["vpn"]}
                ]
            }
        ]
    })");

    const auto* same_group =
        find_issue(issues, "outbounds.ut.outbound_groups[0].outbounds[1]");
    REQUIRE(same_group != nullptr);
    CHECK(same_group->message.find(
              "outbounds.ut.outbound_groups[0].outbounds[0]") !=
          std::string::npos);

    const auto* other_group =
        find_issue(issues, "outbounds.ut.outbound_groups[1].outbounds[0]");
    REQUIRE(other_group != nullptr);
    CHECK(other_group->message.find(
              "outbounds.ut.outbound_groups[0].outbounds[0]") !=
          std::string::npos);
}

TEST_CASE("urltest permits blackhole fallback but rejects ignore child") {
    const auto issues = validate_issues(R"({
        "outbounds": [
            {"tag":"drop","type":"blackhole"},
            {"tag":"pass","type":"ignore"},
            {
                "tag":"ut",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "outbound_groups":[{"outbounds":["drop","pass"]}]
            }
        ]
    })");

    CHECK(find_issue(
              issues,
              "outbounds.ut.outbound_groups[0].outbounds[0]") == nullptr);
    const auto* ignore_issue =
        find_issue(issues, "outbounds.ut.outbound_groups[0].outbounds[1]");
    REQUIRE(ignore_issue != nullptr);
    CHECK(ignore_issue->message.find("not an interface") != std::string::npos);
}

TEST_CASE("outbound tags must be unique and report the duplicate index") {
    const auto issues = validate_issues(R"({
        "outbounds": [
            {"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"vpn","type":"interface","interface":"wg1"}
        ]
    })");

    const auto* duplicate = find_issue(issues, "outbounds[1].tag");
    REQUIRE(duplicate != nullptr);
    CHECK(duplicate->message.find("outbounds[0].tag") != std::string::npos);
}

TEST_CASE("urltest rejects self, mutual, and long cyclic references") {
    const auto self_issues = validate_issues(R"({
        "outbounds": [
            {
                "tag":"self",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "outbound_groups":[{"outbounds":["self"]}]
            }
        ]
    })");
    CHECK(find_issue(
              self_issues,
              "outbounds.self.outbound_groups[0].outbounds[0]") != nullptr);

    const auto mutual_issues = validate_issues(R"({
        "outbounds": [
            {
                "tag":"a",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "outbound_groups":[{"outbounds":["b"]}]
            },
            {
                "tag":"b",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "outbound_groups":[{"outbounds":["a"]}]
            }
        ]
    })");
    CHECK(find_issue(
              mutual_issues,
              "outbounds.b.outbound_groups[0].outbounds[0]") != nullptr);

    const auto long_issues = validate_issues(R"({
        "outbounds": [
            {
                "tag":"a",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "outbound_groups":[{"outbounds":["b"]}]
            },
            {
                "tag":"b",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "outbound_groups":[{"outbounds":["c"]}]
            },
            {
                "tag":"c",
                "type":"urltest",
                "url":"https://example.test/generate_204",
                "outbound_groups":[{"outbounds":["a"]}]
            }
        ]
    })");
    CHECK(find_issue(
              long_issues,
              "outbounds.c.outbound_groups[0].outbounds[0]") != nullptr);
}

TEST_CASE("dns detour: unknown outbound tag is rejected") {
    std::string json = R"({"outbounds":[{"tag":"vpn","type":"interface","interface":"wg0"}],
        "dns":{"servers":[{"tag":"vpn_dns","address":"10.8.0.1","detour":"nonexistent"}],"fallback":["vpn_dns"]}})";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("dns detour: blackhole outbound is rejected") {
    std::string json = R"({"outbounds":[{"tag":"bh","type":"blackhole"}],
        "dns":{"servers":[{"tag":"bh_dns","address":"10.8.0.1","detour":"bh"}],"fallback":["bh_dns"]}})";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("dns detour: ignore outbound is rejected") {
    std::string json = R"({"outbounds":[{"tag":"ig","type":"ignore"}],
        "dns":{"servers":[{"tag":"ig_dns","address":"10.8.0.1","detour":"ig"}],"fallback":["ig_dns"]}})";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("dns detour: no detour field is accepted") {
    std::string json = R"({"dns":{"servers":[{"tag":"plain_dns","address":"8.8.8.8"}],"fallback":["plain_dns"]}})";
    CHECK_NOTHROW(parse_test_config(json));
}

TEST_CASE("dns fallback: parser diagnostics include precise path for type error") {
    const auto issues = parse_issues(R"({"dns":{"fallback":"quad9"}})");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "$");
    CHECK(issues[0].message.find("/dns/fallback") != std::string::npos);
    CHECK(issues[0].message.find("type must be array") != std::string::npos);
}

TEST_CASE("parse_config accepts JSON comments") {
    const std::string json = R"({
        // daemon settings
        "daemon": {
            "strict_enforcement": false
        },
        /* dns settings */
        "dns": {
            "servers": [
                {"tag":"quad9","address":"9.9.9.9"}
            ],
            "fallback": ["quad9"]
        }
    })";

    CHECK_NOTHROW(parse_test_config(json));
}

TEST_CASE("dns servers: duplicate tag is rejected") {
    std::string json = R"({
        "dns":{
            "servers":[
                {"tag":"dup_dns","address":"8.8.8.8"},
                {"tag":"dup_dns","address":"1.1.1.1"}
            ],
            "fallback":["dup_dns"]
        }
    })";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("dns servers: keenetic type is rejected on KeeneticOS 2.x") {
    SystemInfoTestGuard guard;
    set_system_info_for_tests(SystemInfo{
        .os_type = "keenetic",
        .os_version = "2.16.D.12.0-12",
        .build_variant = "keenetic",
    });

    const auto issues = validate_issues(R"({
        "dns":{
            "servers":[{"tag":"router_dns","type":"keenetic"}],
            "fallback":["router_dns"],
            "system_resolver":{"address":"127.0.0.1"}
        }
    })");

    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "dns.servers.router_dns.type");
    CHECK(issues[0].message.find("requires KeeneticOS 3.x or newer") != std::string::npos);
    CHECK(issues[0].message.find("2.16.D.12.0-12") != std::string::npos);
}

TEST_CASE("dns servers: keenetic type is accepted on KeeneticOS 3.x") {
    SystemInfoTestGuard guard;
    set_system_info_for_tests(SystemInfo{
        .os_type = "keenetic",
        .os_version = "3.9.0",
        .build_variant = "keenetic",
    });

    CHECK_NOTHROW(parse_test_config(R"({
        "dns":{
            "servers":[{"tag":"router_dns","type":"keenetic"}],
            "fallback":["router_dns"],
            "system_resolver":{"address":"127.0.0.1"}
        }
    })"));
}

#ifdef USE_KEENETIC_API
TEST_CASE("dns servers: at most one keenetic type server is allowed") {
    std::string json = R"({
        "dns":{
            "servers":[
                {"tag":"keen_a","type":"keenetic"},
                {"tag":"keen_b","type":"keenetic"}
            ],
            "fallback":["keen_a"]
        }
    })";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}
#endif

TEST_CASE("route rule enabled: parse and serialize cover true false omitted and null") {
    const auto cfg_true = parse_test_config(R"({
        "lists":{"ads":{"domains":["example.com"]}},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],
        "route":{"rules":[{"enabled":true,"list":["ads"],"outbound":"vpn"}]}
    })");
    REQUIRE(cfg_true.route.has_value());
    REQUIRE(cfg_true.route->rules.has_value());
    REQUIRE(cfg_true.route->rules->size() == 1);
    CHECK(cfg_true.route->rules->at(0).enabled == std::optional<bool>(true));
    const nlohmann::json json_true = cfg_true;
    CHECK(json_true["route"]["rules"][0]["enabled"] == true);

    const auto cfg_false = parse_test_config(R"({
        "lists":{"ads":{"domains":["example.com"]}},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],
        "route":{"rules":[{"enabled":false,"list":["ads"],"outbound":"vpn"}]}
    })");
    REQUIRE(cfg_false.route.has_value());
    REQUIRE(cfg_false.route->rules.has_value());
    REQUIRE(cfg_false.route->rules->size() == 1);
    CHECK(cfg_false.route->rules->at(0).enabled == std::optional<bool>(false));
    const nlohmann::json json_false = cfg_false;
    CHECK(json_false["route"]["rules"][0]["enabled"] == false);

    const auto cfg_omitted = parse_test_config(R"({
        "lists":{"ads":{"domains":["example.com"]}},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],
        "route":{"rules":[{"list":["ads"],"outbound":"vpn"}]}
    })");
    REQUIRE(cfg_omitted.route.has_value());
    REQUIRE(cfg_omitted.route->rules.has_value());
    REQUIRE(cfg_omitted.route->rules->size() == 1);
    CHECK_FALSE(cfg_omitted.route->rules->at(0).enabled.has_value());
    const nlohmann::json json_omitted = cfg_omitted;
    CHECK(json_omitted["route"]["rules"][0]["enabled"].is_null());

    const auto cfg_null = parse_test_config(R"({
        "lists":{"ads":{"domains":["example.com"]}},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],
        "route":{"rules":[{"enabled":null,"list":["ads"],"outbound":"vpn"}]}
    })");
    REQUIRE(cfg_null.route.has_value());
    REQUIRE(cfg_null.route->rules.has_value());
    REQUIRE(cfg_null.route->rules->size() == 1);
    CHECK_FALSE(cfg_null.route->rules->at(0).enabled.has_value());
    const nlohmann::json json_null = cfg_null;
    CHECK(json_null["route"]["rules"][0]["enabled"].is_null());
}

TEST_CASE("dns rule enabled: parse and serialize cover true false omitted and null") {
    const auto cfg_true = parse_test_config(R"({
        "lists":{"ads":{"domains":["example.com"]}},
        "dns":{
            "servers":[{"tag":"vpn_dns","address":"10.8.0.1"}],
            "fallback":["vpn_dns"],
            "rules":[{"enabled":true,"list":["ads"],"server":"vpn_dns"}]
        }
    })");
    REQUIRE(cfg_true.dns.has_value());
    REQUIRE(cfg_true.dns->rules.has_value());
    REQUIRE(cfg_true.dns->rules->size() == 1);
    CHECK(cfg_true.dns->rules->at(0).enabled == std::optional<bool>(true));
    const nlohmann::json json_true = cfg_true;
    CHECK(json_true["dns"]["rules"][0]["enabled"] == true);

    const auto cfg_false = parse_test_config(R"({
        "lists":{"ads":{"domains":["example.com"]}},
        "dns":{
            "servers":[{"tag":"vpn_dns","address":"10.8.0.1"}],
            "fallback":["vpn_dns"],
            "rules":[{"enabled":false,"list":["ads"],"server":"vpn_dns"}]
        }
    })");
    REQUIRE(cfg_false.dns.has_value());
    REQUIRE(cfg_false.dns->rules.has_value());
    REQUIRE(cfg_false.dns->rules->size() == 1);
    CHECK(cfg_false.dns->rules->at(0).enabled == std::optional<bool>(false));
    const nlohmann::json json_false = cfg_false;
    CHECK(json_false["dns"]["rules"][0]["enabled"] == false);

    const auto cfg_omitted = parse_test_config(R"({
        "lists":{"ads":{"domains":["example.com"]}},
        "dns":{
            "servers":[{"tag":"vpn_dns","address":"10.8.0.1"}],
            "fallback":["vpn_dns"],
            "rules":[{"list":["ads"],"server":"vpn_dns"}]
        }
    })");
    REQUIRE(cfg_omitted.dns.has_value());
    REQUIRE(cfg_omitted.dns->rules.has_value());
    REQUIRE(cfg_omitted.dns->rules->size() == 1);
    CHECK_FALSE(cfg_omitted.dns->rules->at(0).enabled.has_value());
    const nlohmann::json json_omitted = cfg_omitted;
    CHECK(json_omitted["dns"]["rules"][0]["enabled"].is_null());

    const auto cfg_null = parse_test_config(R"({
        "lists":{"ads":{"domains":["example.com"]}},
        "dns":{
            "servers":[{"tag":"vpn_dns","address":"10.8.0.1"}],
            "fallback":["vpn_dns"],
            "rules":[{"enabled":null,"list":["ads"],"server":"vpn_dns"}]
        }
    })");
    REQUIRE(cfg_null.dns.has_value());
    REQUIRE(cfg_null.dns->rules.has_value());
    REQUIRE(cfg_null.dns->rules->size() == 1);
    CHECK_FALSE(cfg_null.dns->rules->at(0).enabled.has_value());
    const nlohmann::json json_null = cfg_null;
    CHECK(json_null["dns"]["rules"][0]["enabled"].is_null());
}

TEST_CASE("dns servers: duplicate server definition is rejected") {
    std::string json = R"({
        "dns":{
            "servers":[
                {"tag":"dns_a","address":"8.8.8.8"},
                {"tag":"dns_b","address":"8.8.8.8"}
            ],
            "fallback":["dns_a"]
        }
    })";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE(
    "dns servers: canonical static endpoint on different detours is rejected") {
    std::string json = R"({
        "outbounds":[
            {"tag":"proxy_a","type":"interface","interface":"tun0"},
            {"tag":"proxy_b","type":"interface","interface":"tun1"}
        ],
        "dns":{
            "servers":[
                {"tag":"dns_a","address":"8.8.8.8","detour":"proxy_a"},
                {"tag":"dns_b","address":"8.8.8.8:53","detour":"proxy_b"}
            ],
            "fallback":["dns_a"]
        }
    })";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("dns servers: ambiguous leading-zero IPv4 endpoint is rejected") {
    CHECK_THROWS_AS(
        parse_test_config(R"({
            "dns":{
                "servers":[
                    {"tag":"dns_a","address":"008.008.008.008"}
                ],
                "fallback":["dns_a"]
            }
        })"),
        ConfigError);
}

TEST_CASE(
    "dns servers: equivalent IPv6 spellings on different detours are rejected") {
    std::string json = R"({
        "outbounds":[
            {"tag":"proxy_a","type":"interface","interface":"tun0"},
            {"tag":"proxy_b","type":"interface","interface":"tun1"}
        ],
        "dns":{
            "servers":[
                {
                    "tag":"dns_a",
                    "address":"[2001:0DB8:0000:0000:0000:0000:0000:0001]:53",
                    "detour":"proxy_a"
                },
                {
                    "tag":"dns_b",
                    "address":"2001:db8::1",
                    "detour":"proxy_b"
                }
            ],
            "fallback":["dns_a"]
        }
    })";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("dns servers: same IPv6 address on distinct ports is accepted") {
    CHECK_NOTHROW(parse_test_config(R"({
        "dns":{
            "servers":[
                {"tag":"dns_a","address":"[2001:db8::1]:53"},
                {"tag":"dns_b","address":"[2001:0DB8:0:0:0:0:0:1]:5353"}
            ],
            "fallback":["dns_a"]
        }
    })"));
}

TEST_CASE("outbound tag: uppercase is rejected") {
    std::string json = R"({"outbounds":[{"tag":"Vpn","type":"interface","interface":"wg0"}]})";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("dns tag: uppercase is rejected") {
    std::string json = R"({"dns":{"servers":[{"tag":"Dns_1","address":"8.8.8.8"}],"fallback":["Dns_1"]}})";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("dns test server: valid listen parses") {
    std::string json = R"({"dns":{"dns_test_server":{"listen":"127.0.0.88:53"}}})";
    auto cfg = parse_test_config(json);
    REQUIRE(cfg.dns.has_value());
    REQUIRE(cfg.dns->dns_test_server.has_value());
    CHECK(cfg.dns->dns_test_server->listen == "127.0.0.88:53");
    CHECK(!cfg.dns->dns_test_server->answer_ipv4.has_value());
}

TEST_CASE("dns test server: explicit answer IPv4 parses") {
    std::string json = R"({"dns":{"dns_test_server":{"listen":"127.0.0.88:53","answer_ipv4":"127.0.0.99"}}})";
    auto cfg = parse_test_config(json);
    REQUIRE(cfg.dns.has_value());
    REQUIRE(cfg.dns->dns_test_server.has_value());
    CHECK(cfg.dns->dns_test_server->answer_ipv4.value_or("") == "127.0.0.99");
}

TEST_CASE("dns test server: invalid listen is rejected") {
    std::string json = R"({"dns":{"dns_test_server":{"listen":"not-an-ip:53"}}})";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("dns test server: ipv6 listen is rejected") {
    std::string json = R"({"dns":{"dns_test_server":{"listen":"[::1]:53"}}})";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("dns test server: invalid answer IPv4 is rejected") {
    std::string json = R"({"dns":{"dns_test_server":{"listen":"127.0.0.88:53","answer_ipv4":"example.com"}}})";
    CHECK_THROWS_AS(parse_test_config(json), ConfigError);
}

TEST_CASE("config validation: accepts system_resolver") {
    auto cfg = parse_test_config(R"({
        "dns": {
            "servers": [{"tag":"plain_dns","address":"8.8.8.8"}],
            "fallback": ["plain_dns"],
            "system_resolver": {
                "address": "127.0.0.1"
            }
        }
    })");

    CHECK_NOTHROW(validate_config(cfg));
}

TEST_CASE("config validation: rejects missing system_resolver") {
    auto cfg = parse_config(R"({
        "dns": {
            "servers": [
                {"tag":"plain_dns","address":"8.8.8.8"}
            ],
            "fallback": ["plain_dns"]
        }
    })");

    try {
        validate_config(cfg);
        FAIL("Expected ConfigValidationError");
    } catch (const ConfigValidationError& e) {
        REQUIRE(e.issues().size() == 1);
        CHECK(e.issues().front().path == "dns.system_resolver");
        CHECK(e.issues().front().message == "dns.system_resolver must be present");
    }
}

TEST_CASE("config validation: allows missing fallback") {
    auto cfg = parse_config(R"({
        "dns": {
            "servers": [{"tag":"plain_dns","address":"8.8.8.8"}],
            "system_resolver": {
                "address": "127.0.0.1"
            }
        }
    })");

    CHECK_NOTHROW(validate_config(cfg));
}

TEST_CASE("config validation: allows empty fallback array") {
    auto cfg = parse_config(R"({
        "dns": {
            "servers": [{"tag":"plain_dns","address":"8.8.8.8"}],
            "fallback": [],
            "system_resolver": {
                "address": "127.0.0.1"
            }
        }
    })");

    CHECK_NOTHROW(validate_config(cfg));
}

TEST_CASE("config validation: rejects unknown fallback tag") {
    auto cfg = parse_config(R"({
        "dns": {
            "servers": [{"tag":"plain_dns","address":"8.8.8.8"}],
            "fallback": ["missing_dns"],
            "system_resolver": {
                "address": "127.0.0.1"
            }
        }
    })");

    CHECK_THROWS_AS(validate_config(cfg), ConfigValidationError);
}

TEST_CASE("config validation: rejects duplicate fallback tag") {
    auto cfg = parse_config(R"({
        "dns": {
            "servers": [{"tag":"plain_dns","address":"8.8.8.8"}],
            "fallback": ["plain_dns", "plain_dns"],
            "system_resolver": {
                "address": "127.0.0.1"
            }
        }
    })");

    CHECK_THROWS_AS(validate_config(cfg), ConfigValidationError);
}

TEST_CASE("config validation: collects empty system_resolver fields") {
    Config cfg;
    cfg.dns = DnsConfig{};
    DnsServer fallback_server;
    fallback_server.tag = "default_dns";
    fallback_server.address = "127.0.0.1";
    cfg.dns->servers = std::vector<DnsServer>{fallback_server};
    cfg.dns->fallback = std::vector<std::string>{"default_dns"};
    api::SystemResolver resolver{};
    cfg.dns->system_resolver = resolver;

    try {
        validate_config(cfg);
        FAIL("Expected ConfigValidationError");
    } catch (const ConfigValidationError& e) {
        REQUIRE(e.issues().size() == 1);
        CHECK(e.issues()[0].path == "dns.system_resolver.address");
        CHECK(e.issues()[0].message == "dns.system_resolver.address must not be empty");
    }
}

TEST_CASE("config validation: accepts legacy system_resolver.type and ignores it") {
    auto cfg = parse_config(R"({
        "dns": {
            "servers": [{"tag":"plain_dns","address":"8.8.8.8"}],
            "fallback": ["plain_dns"],
            "system_resolver": {
                "type": "dnsmasq-ipset",
                "address": "127.0.0.1"
            }
        }
    })");

    CHECK_NOTHROW(validate_config(cfg));
    REQUIRE(cfg.dns.has_value());
    REQUIRE(cfg.dns->system_resolver.has_value());
    CHECK(cfg.dns->system_resolver->address == "127.0.0.1");
}

TEST_CASE("strict enforcement: daemon default parses") {
    std::string json = R"({"daemon":{"strict_enforcement":true}})";
    auto cfg = parse_test_config(json);
    REQUIRE(cfg.daemon.has_value());
    CHECK(cfg.daemon->strict_enforcement.value_or(false));
}

TEST_CASE("daemon max_file_size_bytes: parses and is returned") {
    std::string json = R"({"daemon":{"max_file_size_bytes":123456}})";
    auto cfg = parse_test_config(json);
    REQUIRE(cfg.daemon.has_value());
    CHECK(cfg.daemon->max_file_size_bytes.value_or(0) == 123456);
    CHECK(max_file_size_bytes(cfg) == 123456);
}

TEST_CASE("daemon max_file_size_bytes: default is 8 MiB") {
    auto cfg = parse_test_config(R"({})");
    CHECK(max_file_size_bytes(cfg) == 8 * 1024 * 1024);
}

TEST_CASE("daemon max_file_size_bytes: zero is rejected") {
    CHECK_THROWS_AS(parse_test_config(R"({"daemon":{"max_file_size_bytes":0}})"),
                    ConfigValidationError);
}

TEST_CASE("strict enforcement: outbound override parses") {
    std::string json = R"({
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"wg0","strict_enforcement":true}
        ]
    })";
    auto cfg = parse_test_config(json);
    REQUIRE(cfg.outbounds.has_value());
    REQUIRE(cfg.outbounds->size() == 1);
    CHECK(cfg.outbounds->front().strict_enforcement.value_or(false));
}

// =============================================================================
// Route rule port/address validation
// =============================================================================

TEST_CASE("route rule: valid port and address filters are accepted") {
    std::string json = R"({
        "route":{"rules":[
            {"list":["ads"],"outbound":"vpn","dscp":46,"src_port":"80,443","dest_port":"!10000-20000","src_addr":"10.0.0.1,2001:db8::1","dest_addr":"!192.168.0.0/16"}
        ]}
    })";
    CHECK_NOTHROW(parse_config(json));
}

TEST_CASE("route rule: at least one condition is required") {
    std::string json = R"({
        "route":{"rules":[
            {"list":[],"outbound":"vpn"}
        ]}
    })";
    const auto issues = parse_issues(json);
    REQUIRE_FALSE(issues.empty());
    CHECK(issues.front().path == "route.rules[0]");
}

TEST_CASE("route rule: list is optional when another condition is present") {
    std::string json = R"({
        "route":{"rules":[
            {"outbound":"vpn","src_addr":"10.0.0.1"}
        ]}
    })";
    CHECK_NOTHROW(parse_config(json));
}

TEST_CASE("route rule: dscp-only rule is accepted") {
    std::string json = R"({
        "route":{"rules":[
            {"outbound":"vpn","dscp":46}
        ]}
    })";
    CHECK_NOTHROW(parse_config(json));
}

TEST_CASE("route rule: dscp bounds are enforced") {
    auto low_issues = parse_issues(R"({"route":{"rules":[{"outbound":"vpn","dscp":0}]}})");
    REQUIRE_FALSE(low_issues.empty());
    CHECK(low_issues.front().path == "route.rules[0].dscp");

    auto high_issues = parse_issues(R"({"route":{"rules":[{"outbound":"vpn","dscp":64}]}})");
    REQUIRE_FALSE(high_issues.empty());
    CHECK(high_issues.front().path == "route.rules[0].dscp");

    auto type_issues = parse_issues(R"({"route":{"rules":[{"outbound":"vpn","dscp":"46"}]}})");
    REQUIRE_FALSE(type_issues.empty());
    CHECK(type_issues.front().path == "route.rules[0].dscp");
}

TEST_CASE("route rule: firewall criteria carries dscp") {
    auto cfg = parse_config(R"({"route":{"rules":[{"outbound":"vpn","dscp":63}]}})");
    REQUIRE(cfg.route.has_value());
    REQUIRE(cfg.route->rules.has_value());
    auto criteria = build_firewall_rule_criteria(cfg.route->rules->front());
    REQUIRE(criteria.dscp.has_value());
    CHECK(*criteria.dscp == 63);
}

TEST_CASE("route rule: invalid src_port reports route.rules[0].src_port") {
    std::string json = R"({"route":{"rules":[{"list":["ads"],"outbound":"vpn","src_port":"1,,2"}]}})";
    const auto issues = parse_issues(json);
    REQUIRE_FALSE(issues.empty());
    CHECK(issues.front().path == "route.rules[0].src_port");
}

TEST_CASE("route rule: invalid dest_port range reports route.rules[0].dest_port") {
    std::string json = R"({"route":{"rules":[{"list":["ads"],"outbound":"vpn","dest_port":"9000-8000"}]}})";
    const auto issues = parse_issues(json);
    REQUIRE_FALSE(issues.empty());
    CHECK(issues.front().path == "route.rules[0].dest_port");
}

TEST_CASE("route rule: invalid src_addr reports route.rules[0].src_addr") {
    std::string json = R"({"route":{"rules":[{"list":["ads"],"outbound":"vpn","src_addr":"not-an-ip"}]}})";
    const auto issues = parse_issues(json);
    REQUIRE_FALSE(issues.empty());
    CHECK(issues.front().path == "route.rules[0].src_addr");
}

TEST_CASE("route rule: invalid dest_addr reports route.rules[0].dest_addr") {
    std::string json = R"({"route":{"rules":[{"list":["ads"],"outbound":"vpn","dest_addr":",10.0.0.0/8"}]}})";
    const auto issues = parse_issues(json);
    REQUIRE_FALSE(issues.empty());
    CHECK(issues.front().path == "route.rules[0].dest_addr");
}

TEST_CASE("route rule: iptables rejects multiport src_port combined with dest_port") {
    const auto issues = validate_issues(R"({
        "daemon":{"firewall_backend":"iptables"},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],
        "route":{"rules":[
            {"outbound":"vpn","src_port":"555,666","dest_port":"555-666"}
        ]}
    })");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "route.rules[0].src_port");
    CHECK(issues[0].message.find("This is a xt_multiport module limitation") != std::string::npos);
}

TEST_CASE("route rule: iptables rejects multiport dest_port combined with src_port") {
    const auto issues = validate_issues(R"({
        "daemon":{"firewall_backend":"iptables"},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],
        "route":{"rules":[
            {"outbound":"vpn","src_port":"555-666","dest_port":"555,666"}
        ]}
    })");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "route.rules[0].dest_port");
}

TEST_CASE("route rule: iptables allows src_port and dest_port ranges together") {
    CHECK_NOTHROW(parse_test_config(R"({
        "daemon":{"firewall_backend":"iptables"},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],
        "route":{"rules":[
            {"outbound":"vpn","src_port":"555-666","dest_port":"777-888"}
        ]}
    })"));
}

TEST_CASE("route rule: nftables allows mixed multiport and dest_port") {
    CHECK_NOTHROW(parse_test_config(R"({
        "daemon":{"firewall_backend":"nftables"},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],
        "route":{"rules":[
            {"outbound":"vpn","src_port":"555,666","dest_port":"555-666"}
        ]}
    })"));
}

TEST_CASE("route rule: auto allows mixed multiport and dest_port") {
    CHECK_NOTHROW(parse_test_config(R"({
        "daemon":{"firewall_backend":"auto"},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],
        "route":{"rules":[
            {"outbound":"vpn","src_port":"555,666","dest_port":"555-666"}
        ]}
    })"));
}

TEST_CASE("route inbound_interfaces: omitted is accepted") {
    CHECK_NOTHROW(parse_test_config(R"({"lists":{"ads":{"domains":["example.com"]}},"outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],"route":{"rules":[{"list":["ads"],"outbound":"vpn"}]}})"));
}

TEST_CASE("route inbound_interfaces: empty array is accepted") {
    CHECK_NOTHROW(parse_test_config(R"({"lists":{"ads":{"domains":["example.com"]}},"outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],"route":{"inbound_interfaces":[],"rules":[{"list":["ads"],"outbound":"vpn"}]}})"));
}

TEST_CASE("route inbound_interfaces: valid entries are parsed") {
    auto cfg = parse_test_config(
        R"({"lists":{"ads":{"domains":["example.com"]}},"outbounds":[{"tag":"vpn","type":"interface","interface":"eth0"}],"route":{"inbound_interfaces":["br0","wg0"],"rules":[{"list":["ads"],"outbound":"vpn"}]}})");
    REQUIRE(cfg.route.has_value());
    REQUIRE(cfg.route->inbound_interfaces.has_value());
    CHECK(cfg.route->inbound_interfaces->size() == 2);
    CHECK(cfg.route->inbound_interfaces->at(0) == "br0");
    CHECK(cfg.route->inbound_interfaces->at(1) == "wg0");
}

TEST_CASE("route inbound_interfaces: non-array is rejected") {
    const auto issues = parse_issues(
        R"({"route":{"inbound_interfaces":"br0","rules":[{"list":["ads"],"outbound":"vpn"}]}})");
    REQUIRE_FALSE(issues.empty());
    CHECK(issues.front().path == "route.inbound_interfaces");
}

TEST_CASE("route inbound_interfaces: non-string entry is rejected") {
    const auto issues = parse_issues(
        R"({"route":{"inbound_interfaces":["br0",42],"rules":[{"list":["ads"],"outbound":"vpn"}]}})");
    REQUIRE_FALSE(issues.empty());
    CHECK(issues.front().path == "route.inbound_interfaces[1]");
}

TEST_CASE("route inbound_interfaces: blank entry is rejected") {
    const auto issues = parse_issues(
        R"({"route":{"inbound_interfaces":["br0","   "],"rules":[{"list":["ads"],"outbound":"vpn"}]}})");
    REQUIRE_FALSE(issues.empty());
    CHECK(issues.front().path == "route.inbound_interfaces[1]");
}

TEST_CASE("route inbound_interfaces: duplicate entry is rejected") {
    const auto issues = parse_issues(
        R"({"route":{"inbound_interfaces":["br0","br0"],"rules":[{"list":["ads"],"outbound":"vpn"}]}})");
    REQUIRE_FALSE(issues.empty());
    CHECK(issues.front().path == "route.inbound_interfaces[1]");
}

TEST_CASE("route inbound_interfaces: restore control characters are rejected") {
    const auto issues = parse_issues(
        "{\"route\":{\"inbound_interfaces\":[\"br0\\n-A KeenPbrTable -j DROP\"],"
        "\"rules\":[{\"list\":[\"ads\"],\"outbound\":\"vpn\"}]}}");
    REQUIRE_FALSE(issues.empty());
    CHECK(issues.front().path == "route.inbound_interfaces[0]");
}

TEST_CASE("route inbound_interfaces: Linux-invalid names are rejected") {
    for (const std::string& iface : {".", "..", "bad/name", "bad:name",
                                     "bad name", "bad\"name", "bad\\name",
                                     "eth+", "0123456789abcdef"}) {
        const auto issues = parse_issues(
            "{\"route\":{\"inbound_interfaces\":[" +
            nlohmann::json(iface).dump() +
            "],\"rules\":[{\"list\":[\"ads\"],\"outbound\":\"vpn\"}]}}");
        CAPTURE(iface);
        REQUIRE_FALSE(issues.empty());
        CHECK(issues.front().path == "route.inbound_interfaces[0]");
    }
}

TEST_CASE("route inbound_interfaces: valid future interface need not exist") {
    CHECK_NOTHROW(parse_test_config(
        R"({"route":{"inbound_interfaces":["vpn_future@1"],"rules":[]}})"));
}

TEST_CASE("route internal_vpn_servers: omitted preserves legacy config") {
    const auto config =
        parse_test_config(R"({"route":{"inbound_interfaces":["br0"],"rules":[]}})");
    REQUIRE(config.route.has_value());
    CHECK_FALSE(config.route->internal_vpn_servers.has_value());
}

TEST_CASE("route internal_vpn_servers: strict values round-trip") {
    const auto config = parse_test_config(R"({
        "route":{
            "internal_vpn_servers":[
                {
                    "interface":"nwg0",
                    "ndms_id":"WireguardServer0",
                    "process_clients":true
                },
                {"interface":"OpenVPN1","process_clients":false}
            ],
            "rules":[]
        }
    })");

    REQUIRE(config.route.has_value());
    REQUIRE(config.route->internal_vpn_servers.has_value());
    REQUIRE(config.route->internal_vpn_servers->size() == 2);
    CHECK(config.route->internal_vpn_servers->at(0).interface == "nwg0");
    CHECK(
        config.route->internal_vpn_servers->at(0).ndms_id ==
        std::optional<std::string>{"WireguardServer0"});
    CHECK(config.route->internal_vpn_servers->at(0).process_clients);
    CHECK(config.route->internal_vpn_servers->at(1).interface == "OpenVPN1");
    CHECK_FALSE(
        config.route->internal_vpn_servers->at(1).ndms_id.has_value());
    CHECK_FALSE(config.route->internal_vpn_servers->at(1).process_clients);

    const auto serialized = nlohmann::json(config);
    CHECK(serialized.at("route")
              .at("internal_vpn_servers")
              .at(1)
              .at("process_clients") == false);
    const auto reparsed = parse_test_config(serialized.dump());
    REQUIRE(reparsed.route->internal_vpn_servers.has_value());
    CHECK(reparsed.route->internal_vpn_servers->at(0).interface == "nwg0");
    CHECK(
        reparsed.route->internal_vpn_servers->at(0).ndms_id ==
        std::optional<std::string>{"WireguardServer0"});
    CHECK_FALSE(
        reparsed.route->internal_vpn_servers->at(1).process_clients);
}

TEST_CASE("route internal_vpn_servers: array and object shapes are strict") {
    const auto non_array = parse_issues(
        R"({"route":{"internal_vpn_servers":"nwg0","rules":[]}})");
    CHECK(find_issue(non_array, "route.internal_vpn_servers") != nullptr);

    const auto non_object = parse_issues(
        R"({"route":{"internal_vpn_servers":["nwg0"],"rules":[]}})");
    CHECK(find_issue(
              non_object, "route.internal_vpn_servers[0]") != nullptr);
}

TEST_CASE("route internal_vpn_servers: required fields are strict") {
    const auto missing_interface = parse_issues(R"({
        "route":{"internal_vpn_servers":[{"process_clients":true}],"rules":[]}
    })");
    CHECK(find_issue(
              missing_interface,
              "route.internal_vpn_servers[0].interface") != nullptr);

    const auto missing_process = parse_issues(R"({
        "route":{"internal_vpn_servers":[{"interface":"nwg0"}],"rules":[]}
    })");
    CHECK(find_issue(
              missing_process,
              "route.internal_vpn_servers[0].process_clients") != nullptr);

    const auto string_process = parse_issues(R"({
        "route":{"internal_vpn_servers":[
            {"interface":"nwg0","process_clients":"false"}
        ],"rules":[]}
    })");
    CHECK(find_issue(
              string_process,
              "route.internal_vpn_servers[0].process_clients") != nullptr);
}

TEST_CASE("route internal_vpn_servers: interface names reuse Linux validation") {
    for (const std::string& interface :
         {"bad/name", "bad name", "eth+", "0123456789abcdef"}) {
        const auto issues = parse_issues(
            "{\"route\":{\"internal_vpn_servers\":[{\"interface\":" +
            nlohmann::json(interface).dump() +
            ",\"process_clients\":true}],\"rules\":[]}}");
        CAPTURE(interface);
        CHECK(find_issue(
                  issues,
                  "route.internal_vpn_servers[0].interface") != nullptr);
    }
}

TEST_CASE("route internal_vpn_servers: duplicate interfaces are rejected") {
    const auto issues = parse_issues(R"({
        "route":{"internal_vpn_servers":[
            {"interface":"nwg0","process_clients":true},
            {"interface":"nwg0","process_clients":false}
        ],"rules":[]}
    })");
    CHECK(find_issue(
              issues,
              "route.internal_vpn_servers[1].interface") != nullptr);
}

TEST_CASE("route internal_vpn_servers: stable ids are strict and unique") {
    const auto invalid = parse_issues(R"({
        "route":{"internal_vpn_servers":[
            {
                "interface":"nwg0",
                "ndms_id":" Wireguard0 ",
                "process_clients":true
            }
        ],"rules":[]}
    })");
    CHECK(find_issue(
              invalid,
              "route.internal_vpn_servers[0].ndms_id") != nullptr);

    const auto duplicate = parse_issues(R"({
        "route":{"internal_vpn_servers":[
            {
                "interface":"nwg0",
                "ndms_id":"WireguardServer",
                "process_clients":true
            },
            {
                "interface":"nwg1",
                "ndms_id":"WireguardServer",
                "process_clients":false
            }
        ],"rules":[]}
    })");
    CHECK(find_issue(
              duplicate,
              "route.internal_vpn_servers[1].ndms_id") != nullptr);
}

TEST_CASE("route internal_vpn_servers: OpenAPI maximum is enforced") {
    nlohmann::json servers = nlohmann::json::array();
    for (size_t index = 0; index < 129; ++index) {
        servers.push_back({
            {"interface", "v" + std::to_string(index)},
            {"process_clients", true},
        });
    }
    nlohmann::json config{
        {"route", {
            {"internal_vpn_servers", std::move(servers)},
            {"rules", nlohmann::json::array()},
        }},
    };
    const auto issues = parse_issues(config.dump());
    CHECK(find_issue(issues, "route.internal_vpn_servers") != nullptr);
}

TEST_CASE("interface outbound: strict iptables interface names are accepted") {
    for (const std::string& iface :
         {"eth0", "nwg2", "vpn_future@1", "br-lan.10", "_managed"}) {
        CAPTURE(iface);
        CHECK_NOTHROW(parse_test_config(
            "{\"outbounds\":[{\"tag\":\"vpn\",\"type\":\"interface\","
            "\"interface\":" +
            nlohmann::json(iface).dump() + "}],\"route\":{\"rules\":[]}}"));
    }
}

TEST_CASE("interface outbound: restore metacharacters and wildcard suffix are rejected") {
    for (const std::string& iface :
         {"bad\"name", "bad\\name", "eth+"}) {
        const auto issues = validate_issues(
            "{\"outbounds\":[{\"tag\":\"vpn\",\"type\":\"interface\","
            "\"interface\":" +
            nlohmann::json(iface).dump() + "}],\"route\":{\"rules\":[]}}");
        CAPTURE(iface);
        const auto issue = std::find_if(
            issues.begin(), issues.end(),
            [](const ConfigValidationIssue& candidate) {
                return candidate.path == "outbounds.vpn.interface";
            });
        REQUIRE(issue != issues.end());
        CHECK(issue->message.find("valid iptables interface name") !=
              std::string::npos);
    }
}

// =============================================================================
// is_reserved_table
// =============================================================================

TEST_CASE("is_reserved_table: table 0 (unspec) is reserved") {
    CHECK(is_reserved_table(0));
}

TEST_CASE("is_reserved_table: table 128 (prelocal) is reserved") {
    CHECK(is_reserved_table(128));
}

TEST_CASE("is_reserved_table: tables 250-260 are reserved") {
    for (uint32_t id = 250; id <= 260; ++id) {
        CHECK(is_reserved_table(id));
    }
}

TEST_CASE("is_reserved_table: tables 32000+ are reserved") {
    CHECK(is_reserved_table(32000));
    CHECK(is_reserved_table(32767));
    CHECK(is_reserved_table(65535));
}

TEST_CASE("is_reserved_table: safe values are not reserved") {
    CHECK_FALSE(is_reserved_table(1));
    CHECK_FALSE(is_reserved_table(100));
    CHECK_FALSE(is_reserved_table(127));
    CHECK_FALSE(is_reserved_table(129));
    CHECK_FALSE(is_reserved_table(249));
    CHECK_FALSE(is_reserved_table(261));
    CHECK_FALSE(is_reserved_table(31999));
}

// =============================================================================
// iproute.table_start validation
// =============================================================================

TEST_CASE("iproute.table_start: default (no iproute section) is accepted") {
    CHECK_NOTHROW(parse_test_config(R"({})"));
}

TEST_CASE("iproute.table_start: value 150 is accepted") {
    CHECK_NOTHROW(parse_test_config(R"({"iproute":{"table_start":150}})"));
}

TEST_CASE("iproute.table_start: value 249 is accepted") {
    CHECK_NOTHROW(parse_test_config(R"({"iproute":{"table_start":249}})"));
}

TEST_CASE("iproute.table_start: value 261 is accepted") {
    CHECK_NOTHROW(parse_test_config(R"({"iproute":{"table_start":261}})"));
}

TEST_CASE("iproute.table_start: value 31999 is accepted") {
    CHECK_NOTHROW(parse_test_config(R"({"iproute":{"table_start":31999}})"));
}

TEST_CASE("iproute.table_start: value 0 is rejected") {
    CHECK_THROWS_AS(parse_test_config(R"({"iproute":{"table_start":0}})"), ConfigError);
}

TEST_CASE("iproute.table_start: value 128 (prelocal) is rejected") {
    CHECK_THROWS_AS(parse_test_config(R"({"iproute":{"table_start":128}})"), ConfigError);
}

TEST_CASE("iproute.table_start: value 250 is rejected") {
    CHECK_THROWS_AS(parse_test_config(R"({"iproute":{"table_start":250}})"), ConfigError);
}

TEST_CASE("iproute.table_start: value 255 (local) is rejected") {
    CHECK_THROWS_AS(parse_test_config(R"({"iproute":{"table_start":255}})"), ConfigError);
}

TEST_CASE("iproute.table_start: value 260 is rejected") {
    CHECK_THROWS_AS(parse_test_config(R"({"iproute":{"table_start":260}})"), ConfigError);
}

TEST_CASE("iproute.table_start: value 32000 is rejected") {
    CHECK_THROWS_AS(parse_test_config(R"({"iproute":{"table_start":32000}})"), ConfigError);
}

TEST_CASE("iproute.table_start: non-integer value is rejected") {
    CHECK_THROWS_AS(
        parse_test_config(R"({"iproute":{"table_start":"400abc"}})"),
        ConfigValidationError
    );
    CHECK_THROWS_AS(
        parse_test_config(R"({"iproute":{"table_start":400.5}})"),
        ConfigValidationError
    );
}

// =============================================================================

TEST_CASE("fwmark mask: single F nibble is accepted during config parsing") {
    const std::string json = R"({
        "fwmark": {
            "mask": "0x000F0000"
        }
    })";

    CHECK_NOTHROW(parse_test_config(json));
}

TEST_CASE("fwmark mask: multiple consecutive F nibbles are accepted during config parsing") {
    const std::string json = R"({
        "fwmark": {
            "mask": "0x0FFF0000"
        }
    })";

    CHECK_NOTHROW(parse_test_config(json));
}

TEST_CASE("fwmark mask: non-consecutive F nibbles are rejected during config parsing") {
    const std::string json = R"({
        "fwmark": {
            "mask": "0x0F0F0000"
        }
    })";

    CHECK_THROWS_AS(parse_test_config(json), ConfigValidationError);
}

TEST_CASE("fwmark mask: validator rejects more routable outbounds than mask allows") {
    nlohmann::json config;
    config["fwmark"] = {
        {"mask", "0x0000F000"}
    };
    config["outbounds"] = nlohmann::json::array();

    for (int i = 0; i < 17; ++i) {
        config["outbounds"].push_back({
            {"tag", "wan" + std::to_string(i)},
            {"type", "interface"},
            {"interface", "wg" + std::to_string(i)}
        });
    }

    const auto issues = validate_issues(config.dump());
    REQUIRE_FALSE(issues.empty());

    bool saw_capacity_error = false;
    for (const auto& issue : issues) {
        if (issue.path != "outbounds") {
            continue;
        }

        if (issue.message.find("maximum 16 supported with current fwmark.mask") !=
            std::string::npos) {
            saw_capacity_error = true;
            break;
        }
    }

    CHECK(saw_capacity_error);
}

TEST_CASE("fwmark start and mask: non-string values are rejected during config parsing") {
    CHECK_THROWS_AS(parse_test_config(R"({"fwmark":{"start":65536}})"), ConfigValidationError);
    CHECK_THROWS_AS(parse_test_config(R"({"fwmark":{"mask":16711680}})"), ConfigValidationError);
}

TEST_CASE("config parsing returns all collected validation errors") {
    const std::string json = R"({
        "lists_autoupdate": {
            "enabled": true
        },
        "fwmark": {
            "mask": "0xFFFF0001"
        },
        "lists": {
            "bad-list": {}
        }
    })";

    try {
        (void)parse_test_config(json);
        FAIL("Expected ConfigValidationError");
    } catch (const ConfigValidationError& e) {
        CHECK(e.issues().size() >= 3);

        bool saw_cron_error = false;
        bool saw_fwmark_error = false;
        bool saw_list_error = false;

        for (const auto& issue : e.issues()) {
            if (issue.path == "lists_autoupdate.cron") {
                saw_cron_error = true;
            }
            if (issue.path == "fwmark.mask") {
                saw_fwmark_error = true;
            }
            if (issue.path == "lists.bad-list") {
                saw_list_error = true;
            }
        }

        CHECK(saw_cron_error);
        CHECK(saw_fwmark_error);
        CHECK(saw_list_error);
    }
}

TEST_CASE("daemon.firewall_verify_max_bytes: accepts positive value") {
    auto cfg = parse_test_config(R"({"daemon":{"firewall_verify_max_bytes":131072}})");
    REQUIRE(cfg.daemon.has_value());
    REQUIRE(cfg.daemon->firewall_verify_max_bytes.has_value());
    CHECK(*cfg.daemon->firewall_verify_max_bytes == 131072);
}

TEST_CASE("daemon.firewall_verify_max_bytes: rejects non-integer value") {
    const auto issues = parse_issues(R"({"daemon":{"firewall_verify_max_bytes":"131072"}})");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "daemon.firewall_verify_max_bytes");
}

TEST_CASE("daemon.firewall_verify_max_bytes: rejects negative value") {
    CHECK_THROWS_AS(parse_test_config(R"({"daemon":{"firewall_verify_max_bytes":-1}})"), ConfigError);
}

TEST_CASE("daemon.firewall_backend: defaults to auto when absent") {
    auto cfg = parse_test_config(R"({"daemon":{}})");
    CHECK(firewall_backend_preference(cfg) == FirewallBackendPreference::auto_detect);
}

TEST_CASE("daemon.firewall_backend: accepts auto") {
    auto cfg = parse_test_config(R"({"daemon":{"firewall_backend":"auto"}})");
    CHECK(firewall_backend_preference(cfg) == FirewallBackendPreference::auto_detect);
}

TEST_CASE("daemon.firewall_backend: accepts iptables") {
    auto cfg = parse_test_config(R"({"daemon":{"firewall_backend":"iptables"}})");
    CHECK(firewall_backend_preference(cfg) == FirewallBackendPreference::iptables);
}

TEST_CASE("daemon.firewall_backend: accepts nftables") {
    auto cfg = parse_test_config(R"({"daemon":{"firewall_backend":"nftables"}})");
    CHECK(firewall_backend_preference(cfg) == FirewallBackendPreference::nftables);
}

TEST_CASE("daemon.firewall_backend: rejects non-string value") {
    const auto issues = parse_issues(R"({"daemon":{"firewall_backend":true}})");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "daemon.firewall_backend");
}

TEST_CASE("daemon.firewall_backend: rejects unsupported value") {
    CHECK_THROWS_AS(parse_test_config(R"({"daemon":{"firewall_backend":"pf"}})"), ConfigError);
}

TEST_CASE("daemon.skip_marked_packets: defaults to true behavior when absent") {
    auto cfg = parse_test_config(R"({"daemon":{}})");
    REQUIRE(cfg.daemon.has_value());
    CHECK_FALSE(cfg.daemon->skip_marked_packets.has_value());
}

TEST_CASE("daemon.skip_marked_packets: accepts true") {
    auto cfg = parse_test_config(R"({"daemon":{"skip_marked_packets":true}})");
    REQUIRE(cfg.daemon.has_value());
    REQUIRE(cfg.daemon->skip_marked_packets.has_value());
    CHECK(*cfg.daemon->skip_marked_packets);
}

TEST_CASE("daemon.skip_marked_packets: accepts false") {
    auto cfg = parse_test_config(R"({"daemon":{"skip_marked_packets":false}})");
    REQUIRE(cfg.daemon.has_value());
    REQUIRE(cfg.daemon->skip_marked_packets.has_value());
    CHECK_FALSE(*cfg.daemon->skip_marked_packets);
}

TEST_CASE("daemon.skip_marked_packets: accepts null") {
    auto cfg = parse_test_config(R"({"daemon":{"skip_marked_packets":null}})");
    REQUIRE(cfg.daemon.has_value());
    CHECK_FALSE(cfg.daemon->skip_marked_packets.has_value());
}

TEST_CASE("daemon.skip_marked_packets: rejects non-boolean value") {
    const auto issues = parse_issues(R"({"daemon":{"skip_marked_packets":"yes"}})");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "daemon.skip_marked_packets");
}

TEST_CASE("daemon.clear_dynamic_sets_on_apply: accepts explicit policy") {
    auto enabled = parse_test_config(
        R"({"daemon":{"clear_dynamic_sets_on_apply":true}})");
    auto disabled = parse_test_config(
        R"({"daemon":{"clear_dynamic_sets_on_apply":false}})");
    REQUIRE(enabled.daemon->clear_dynamic_sets_on_apply.has_value());
    REQUIRE(disabled.daemon->clear_dynamic_sets_on_apply.has_value());
    CHECK(*enabled.daemon->clear_dynamic_sets_on_apply);
    CHECK_FALSE(*disabled.daemon->clear_dynamic_sets_on_apply);
}

TEST_CASE("daemon.clear_dynamic_sets_on_apply: null uses default behavior") {
    auto cfg = parse_test_config(
        R"({"daemon":{"clear_dynamic_sets_on_apply":null}})");
    REQUIRE(cfg.daemon.has_value());
    CHECK_FALSE(cfg.daemon->clear_dynamic_sets_on_apply.has_value());
}

TEST_CASE("daemon.clear_dynamic_sets_on_apply: rejects non-boolean value") {
    const auto issues = parse_issues(
        R"({"daemon":{"clear_dynamic_sets_on_apply":"yes"}})");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "daemon.clear_dynamic_sets_on_apply");
}

TEST_CASE(
    "daemon.reconnect_unmarked_flows_on_routing_change: accepts explicit policy") {
    auto enabled = parse_test_config(
        R"({"daemon":{"reconnect_unmarked_flows_on_routing_change":true}})");
    auto disabled = parse_test_config(
        R"({"daemon":{"reconnect_unmarked_flows_on_routing_change":false}})");
    REQUIRE(
        enabled.daemon->reconnect_unmarked_flows_on_routing_change.has_value());
    REQUIRE(
        disabled.daemon->reconnect_unmarked_flows_on_routing_change.has_value());
    CHECK(*enabled.daemon->reconnect_unmarked_flows_on_routing_change);
    CHECK_FALSE(*disabled.daemon->reconnect_unmarked_flows_on_routing_change);
}

TEST_CASE(
    "daemon.reconnect_unmarked_flows_on_routing_change: null uses default behavior") {
    auto cfg = parse_test_config(
        R"({"daemon":{"reconnect_unmarked_flows_on_routing_change":null}})");
    REQUIRE(cfg.daemon.has_value());
    CHECK_FALSE(
        cfg.daemon->reconnect_unmarked_flows_on_routing_change.has_value());
}

TEST_CASE(
    "daemon.reconnect_unmarked_flows_on_routing_change: rejects non-boolean value") {
    const auto issues = parse_issues(
        R"({"daemon":{"reconnect_unmarked_flows_on_routing_change":"yes"}})");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path ==
          "daemon.reconnect_unmarked_flows_on_routing_change");
}

TEST_CASE(
    "daemon strong reconnect list selection accepts configured unique lists") {
    const auto cfg = parse_test_config(R"({
        "lists":{"whatsapp_ip":{"ip_cidrs":["31.13.64.0/18"]}},
        "daemon":{
            "reconnect_owned_flows_on_routing_change_lists":["whatsapp_ip"]
        }
    })");
    REQUIRE(cfg.daemon.has_value());
    REQUIRE(
        cfg.daemon->reconnect_owned_flows_on_routing_change_lists.has_value());
    CHECK(
        *cfg.daemon->reconnect_owned_flows_on_routing_change_lists ==
        std::vector<std::string>{"whatsapp_ip"});
}

TEST_CASE(
    "daemon strong reconnect list selection preserves explicit empty opt-out") {
    const auto cfg = parse_test_config(R"({
        "daemon":{"reconnect_owned_flows_on_routing_change_lists":[]}
    })");
    REQUIRE(cfg.daemon.has_value());
    REQUIRE(
        cfg.daemon->reconnect_owned_flows_on_routing_change_lists.has_value());
    CHECK(cfg.daemon->reconnect_owned_flows_on_routing_change_lists->empty());
}

TEST_CASE(
    "daemon strong reconnect list selection rejects malformed references") {
    const auto wrong_type = parse_issues(R"({
        "daemon":{"reconnect_owned_flows_on_routing_change_lists":"all"}
    })");
    REQUIRE(wrong_type.size() == 1U);
    CHECK(
        wrong_type.front().path ==
        "daemon.reconnect_owned_flows_on_routing_change_lists");

    const auto non_string = parse_issues(R"({
        "daemon":{"reconnect_owned_flows_on_routing_change_lists":[7]}
    })");
    REQUIRE(non_string.size() == 1U);
    CHECK(
        non_string.front().path ==
        "daemon.reconnect_owned_flows_on_routing_change_lists[0]");

    const auto unknown = validate_issues(R"({
        "daemon":{
            "reconnect_owned_flows_on_routing_change_lists":["missing"]
        }
    })");
    REQUIRE(unknown.size() == 1U);
    CHECK(
        unknown.front().path ==
        "daemon.reconnect_owned_flows_on_routing_change_lists[0]");

    const auto duplicate = validate_issues(R"({
        "lists":{"whatsapp_ip":{"ip_cidrs":["31.13.64.0/18"]}},
        "daemon":{
            "reconnect_owned_flows_on_routing_change_lists":[
                "whatsapp_ip", "whatsapp_ip"
            ]
        }
    })");
    REQUIRE(duplicate.size() == 1U);
    CHECK(
        duplicate.front().path ==
        "daemon.reconnect_owned_flows_on_routing_change_lists[1]");
}

TEST_CASE("daemon.ipv6_enabled: defaults to true behavior when absent") {
    auto cfg = parse_test_config(R"({"daemon":{}})");
    REQUIRE(cfg.daemon.has_value());
    CHECK_FALSE(cfg.daemon->ipv6_enabled.has_value());
}

TEST_CASE("daemon.ipv6_enabled: accepts false") {
    auto cfg = parse_test_config(R"({"daemon":{"ipv6_enabled":false}})");
    REQUIRE(cfg.daemon.has_value());
    REQUIRE(cfg.daemon->ipv6_enabled.has_value());
    CHECK_FALSE(*cfg.daemon->ipv6_enabled);
}

TEST_CASE("daemon.ipv6_enabled: accepts null") {
    auto cfg = parse_test_config(R"({"daemon":{"ipv6_enabled":null}})");
    REQUIRE(cfg.daemon.has_value());
    CHECK_FALSE(cfg.daemon->ipv6_enabled.has_value());
}

TEST_CASE("daemon.ipv6_enabled: rejects non-boolean value") {
    const auto issues = parse_issues(R"({"daemon":{"ipv6_enabled":"yes"}})");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "daemon.ipv6_enabled");
}

TEST_CASE("route rule: unknown outbound tag is rejected") {
    const auto issues = validate_issues(R"({
        "lists":{"blocked":{"ip_cidrs":["10.0.0.0/8"]}},
        "outbounds":[{"tag":"wan","type":"interface","interface":"eth0"}],
        "route":{"rules":[{"list":["blocked"],"outbound":"missing"}]}
    })");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "route.rules[0].outbound");
    CHECK(issues[0].message.find("unknown outbound") != std::string::npos);
}

TEST_CASE("route rule: unknown list name is rejected") {
    const auto issues = validate_issues(R"({
        "lists":{"blocked":{"ip_cidrs":["10.0.0.0/8"]}},
        "outbounds":[{"tag":"wan","type":"interface","interface":"eth0"}],
        "route":{"rules":[{"list":["ghost"],"outbound":"wan"}]}
    })");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "route.rules[0].list[0]");
    CHECK(issues[0].message.find("unknown list") != std::string::npos);
}

TEST_CASE("dns rule: unknown server tag is rejected") {
    const auto issues = validate_issues(R"({
        "lists":{"domains":{"domains":["example.com"]}},
        "dns":{
            "servers":[{"tag":"main","address":"1.1.1.1"}],
            "fallback":["main"],
            "rules":[{"list":["domains"],"server":"missing"}]
        }
    })");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "dns.rules[0].server");
    CHECK(issues[0].message.find("unknown DNS server") != std::string::npos);
}

TEST_CASE("dns rule: unknown list name is rejected") {
    const auto issues = validate_issues(R"({
        "lists":{"domains":{"domains":["example.com"]}},
        "dns":{
            "servers":[{"tag":"main","address":"1.1.1.1"}],
            "fallback":["main"],
            "rules":[{"list":["ghost"],"server":"main"}]
        }
    })");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "dns.rules[0].list[0]");
    CHECK(issues[0].message.find("unknown list") != std::string::npos);
}

TEST_CASE("interface outbound: empty interface name is rejected") {
    const auto issues = validate_issues(R"({
        "outbounds":[{"tag":"wan","type":"interface","interface":""}]
    })");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "outbounds.wan.interface");
}
