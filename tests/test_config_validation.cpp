#include <doctest/doctest.h>

#include "../src/config/config.hpp"
#include "../src/api/config_validation_json.hpp"
#include "../src/config/config_migration.hpp"
#include "../src/config/json_validation.hpp"
#include "../src/config/routing_state.hpp"
#include "../src/util/system_info.hpp"
#include "../src/util/display_name.hpp"

#include <nlohmann/json.hpp>
#include <limits>
#include <set>
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

TEST_CASE("specialized config causes survive validation serialization and generated DTOs") {
    struct Example {
        nlohmann::json patch;
        std::string path;
        std::string code;
        std::map<std::string, std::string> params;
    };
    const std::vector<Example> examples{
        {{{"route", {{"rules", nlohmann::json::array({
            {{"outbound", "wan"}, {"src_port", "9000-8000"}}
        })}}}}, "route.rules[0].src_port", "config.port.range_order", {}},
        {{{"dns", {{"servers", nlohmann::json::array({
            {{"tag", "primary"}, {"address", "invalid'\naddress"}}
        })}}}}, "dns.servers.primary.address", "config.dns.address", {}},
        {{{"lists", {{"example", {{"domains", {"example.org"}},
            {"display_name", std::string(81U, 'x')}}}}}},
            "lists.example.display_name", "config.name.too_long", {{"max", "80"}}},
    };
    for (const auto& example : examples) {
        CAPTURE(example.path);
        nlohmann::json document{
            {"outbounds", nlohmann::json::array({
                {{"tag", "wan"}, {"type", "interface"}, {"interface", "eth0"}}
            })},
            {"dns", {
                {"servers", nlohmann::json::array({
                    {{"tag", "primary"}, {"address", "1.1.1.1"}}
                })},
                {"fallback", {"primary"}},
                {"system_resolver", {{"address", "1.1.1.1"}}}
            }}
        };
        document.merge_patch(example.patch);
        bool found = false;
        try {
            const auto config = parse_config(document.dump());
            validate_config(config);
        } catch (const ConfigValidationError& failure) {
            const auto serialized = serialize_config_validation_issues(failure.issues());
            for (const auto& item : serialized) {
                if (item.at("path") != example.path) continue;
                found = true;
                CHECK(item.at("code") == example.code);
                const auto dto = item.get<api::ValidationErrorElement>();
                CHECK(dto.path == example.path);
                CHECK(dto.code == example.code);
                CHECK_FALSE(dto.message.empty());
                const auto roundtrip = nlohmann::json(dto).get<api::ValidationErrorElement>();
                CHECK(roundtrip.path == dto.path);
                CHECK(roundtrip.message == dto.message);
                CHECK(roundtrip.code == dto.code);
                CHECK(roundtrip.params == dto.params);
                if (example.params.empty()) {
                    CHECK_FALSE(item.contains("params"));
                    CHECK_FALSE(dto.params.has_value());
                } else {
                    REQUIRE(dto.params.has_value());
                    CHECK(*dto.params == example.params);
                }
            }
        }
        CHECK(found);
    }
}

TEST_CASE("config migration: versionless and explicit v1 raw documents preserve their fields") {
    // Synthetic boundary fixture, not a claimed historical released config.
    nlohmann::json legacy = {
        {"daemon", {{"strict_enforcement", false}}},
        {"future_extension", {{"order", {3, 1, 2}}, {"nullable", nullptr}}},
        {"lists", {{"custom", {{"domains", {"example.org"}},
                                  {"extension", {true, "kept"}}}}}},
    };
    SUBCASE("missing version means v1") {}
    SUBCASE("explicit v1 follows the same migration") { legacy["schema_version"] = 1; }
    const auto original = legacy;
    const auto migrated = migrate_config_json(legacy);
    CHECK(legacy == original);
    CHECK(migrated.at("schema_version") == kCurrentConfigSchemaVersion);
    auto expected = original;
    expected["schema_version"] = kCurrentConfigSchemaVersion;
    CHECK(migrated == expected);
    CHECK(migrate_config_json(migrated) == migrated);
}

TEST_CASE("config migration: current version is idempotent and default DTO writes current version") {
    const nlohmann::json current = {
        {"schema_version", kCurrentConfigSchemaVersion},
        {"unrecognized", {{"preserve", true}}},
    };
    CHECK(migrate_config_json(current) == current);
    Config default_constructed;
    CHECK(default_constructed.schema_version == kCurrentConfigSchemaVersion);
    CHECK(nlohmann::json(default_constructed).at("schema_version") == kCurrentConfigSchemaVersion);
    CHECK(parse_config("{}").schema_version == kCurrentConfigSchemaVersion);
    CHECK(parse_config(R"({"schema_version":1})").schema_version == kCurrentConfigSchemaVersion);
}

TEST_CASE("config migration: invalid version values are not coerced or treated as legacy") {
    for (const nlohmann::json& value : {
             nlohmann::json(nullptr), nlohmann::json(false), nlohmann::json("2"),
             nlohmann::json(2.0), nlohmann::json(0), nlohmann::json(-1),
             nlohmann::json::array(), nlohmann::json::object()}) {
        const nlohmann::json document = {{"schema_version", value}};
        try {
            (void)parse_config(document.dump());
            FAIL("invalid schema_version accepted");
        } catch (const ConfigValidationError& error) {
            REQUIRE(error.issues().size() == 1);
            CHECK(error.issues().front().path == "schema_version");
            CHECK(error.issues().front().message == "schema_version must be a positive integer");
            CHECK(error.issues().front().code == "config.schema_version.invalid");
            CHECK(error.issues().front().params.empty());
        }
    }
    for (const char* document : {"null", "[]", "false", "1"}) {
        CHECK_THROWS_AS(parse_config(document), ConfigValidationError);
    }
}

TEST_CASE("config migration: future version has a distinct error before field validation") {
    for (const auto version : {kCurrentConfigSchemaVersion + 1,
                               std::numeric_limits<std::uint64_t>::max()}) {
        const nlohmann::json future = {
            {"schema_version", version},
            {"fwmark", {{"mask", false}}},
        };
        try {
            (void)parse_config(future.dump());
            FAIL("future configuration accepted");
        } catch (const ConfigSchemaVersionError& error) {
            CHECK(error.source_version() == version);
            CHECK(error.supported_version() == kCurrentConfigSchemaVersion);
            REQUIRE(error.issues().size() == 1);
            CHECK(error.issues().front().path == "schema_version");
            CHECK(error.issues().front().message.find(std::to_string(version)) != std::string::npos);
            CHECK(error.issues().front().message.find("Update keen-pbr-sb") != std::string::npos);
            CHECK(error.issues().front().code == "config.schema_version.unsupported");
            CHECK(error.issues().front().params == std::map<std::string, std::string>{
                {"version", std::to_string(version)},
                {"supported", std::to_string(kCurrentConfigSchemaVersion)},
            });
        }
    }
}

TEST_CASE("config migration: known routing and DNS fields survive load and reload") {
    const auto legacy = parse_test_config(R"({
        "daemon":{"strict_enforcement":false,"ipv6_enabled":true},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"wg0",
                      "display_name":"Example VPN","strict_enforcement":false}],
        "lists":{"example":{"domains":["example.org"],"ip_cidrs":["192.0.2.0/24"]}},
        "route":{"rules":[{"list":["example"],"outbound":"vpn"}]}
    })");
    const nlohmann::json serialized = legacy;
    CHECK(serialized.at("schema_version") == kCurrentConfigSchemaVersion);
    const auto reloaded = parse_and_validate_config(serialized.dump());
    CHECK(nlohmann::json(reloaded) == serialized);
    CHECK(reloaded.daemon->strict_enforcement == false);
    CHECK(reloaded.outbounds->front().display_name == "Example VPN");
    CHECK(reloaded.route->rules->front().outbound == "vpn");
}

TEST_CASE("config migration: unknown extensions survive raw and typed projection") {
    const nlohmann::json raw = {{"unknown_extension", {{"note", "synthetic"}}}};
    CHECK(migrate_config_json(raw).contains("unknown_extension"));
    CHECK(nlohmann::json(parse_config(raw.dump())).at("unknown_extension") == raw.at("unknown_extension"));
}

TEST_CASE("config migration: typed validation accepts only the current migrated version") {
    auto config = parse_test_config("{}");
    for (const auto version : {0, 1}) {
        config.schema_version = version;
        CHECK_THROWS_AS(validate_config(config), ConfigValidationError);
    }
    config.schema_version = static_cast<std::int64_t>(kCurrentConfigSchemaVersion + 1);
    CHECK_THROWS_AS(validate_config(config), ConfigSchemaVersionError);
    config.schema_version = static_cast<std::int64_t>(kCurrentConfigSchemaVersion);
    CHECK_NOTHROW(validate_config(config));
}

TEST_CASE("inline IP import normalizes changed lists and deduplicates canonical first occurrences") {
    const auto previous = parse_test_config(R"({"lists":{"kept":{"ip_cidrs":["old-invalid"]}}})");
    auto candidate = previous;
    ListConfig added;
    added.ip_cidrs = std::vector<std::string>{
        "# first comment", " ", "192.168.7.199/24", "192.168.7.9/24",
        "192.0.2.1/32", "192.0.2.1", "2001:0DB8::1/128", "2001:db8::1",
        "::FFFF:C000:0280/128", "::ffff:192.0.2.128", " \t# last comment",
        "0.0.0.0/0", "::/0",
    };
    candidate.lists->emplace("added", std::move(added));
    normalize_changed_list_ip_cidrs(candidate, previous);
    CHECK(candidate.lists->at("added").ip_cidrs == std::vector<std::string>{
        "192.168.7.0/24", "192.0.2.1", "2001:db8::1", "::ffff:192.0.2.128",
        "0.0.0.0/0", "::/0",
    });
    CHECK(candidate.lists->at("kept").ip_cidrs == previous.lists->at("kept").ip_cidrs);
    CHECK_NOTHROW(validate_config(candidate));
}

TEST_CASE("inline IP import errors retain original indexes and do not partially normalize candidate") {
    const auto previous = parse_test_config("{}");
    auto candidate = previous;
    candidate.lists = std::map<std::string, ListConfig>{};
    (*candidate.lists)["first"].ip_cidrs = std::vector<std::string>{"192.168.7.9/24"};
    (*candidate.lists)["later"].ip_cidrs = std::vector<std::string>{
        "# skipped", "192.0.2.1/32", "192.0.2.1", " ",
        "001.2.3.4", "not-an-ip.example", "192.0.2.1/33",
    };
    const nlohmann::json before = candidate;
    try {
        normalize_changed_list_ip_cidrs(candidate, previous);
        FAIL("invalid changed IP entries accepted");
    } catch (const ConfigValidationError& error) {
        REQUIRE(error.issues().size() == 3);
        CHECK(error.issues()[0].path == "lists.later.ip_cidrs[4]");
        CHECK(error.issues()[0].message == "IPv4 addresses must not contain leading zeros");
        CHECK(error.issues()[0].code == "config.ip_cidr.leading_zeros");
        CHECK(error.issues()[1].path == "lists.later.ip_cidrs[5]");
        CHECK(error.issues()[1].message == "IP/CIDR address is invalid");
        CHECK(error.issues()[1].code == "config.ip_cidr.invalid_address");
        CHECK(error.issues()[2].path == "lists.later.ip_cidrs[6]");
        CHECK(error.issues()[2].message == "IP/CIDR prefix length is invalid");
        CHECK(error.issues()[2].code == "config.ip_cidr.invalid_prefix");
        for (const auto& issue : error.issues()) CHECK(issue.params.empty());
    }
    CHECK(nlohmann::json(candidate) == before);
}

TEST_CASE("inline IP import leaves unchanged legacy values alone but validates a copied new list") {
    const auto previous = parse_test_config(R"({"lists":{"legacy":{"ip_cidrs":["old-invalid","001.2.3.4"]}}})");
    auto candidate = previous;
    candidate.daemon = DaemonConfig{};
    candidate.daemon->strict_enforcement = false;
    CHECK_NOTHROW(normalize_changed_list_ip_cidrs(candidate, previous));
    CHECK(candidate.lists->at("legacy").ip_cidrs == previous.lists->at("legacy").ip_cidrs);
    candidate.lists->emplace("new_copy", candidate.lists->at("legacy"));
    CHECK_THROWS_AS(normalize_changed_list_ip_cidrs(candidate, previous), ConfigValidationError);
}

TEST_CASE("inline IP import permits removing a vector and skips blank comment entries") {
    const auto previous = parse_test_config(R"({"lists":{"example":{"ip_cidrs":["old-invalid"],"domains":["example.org"]}}})");
    auto candidate = previous;
    candidate.lists->at("example").ip_cidrs = std::vector<std::string>{"", "  # comment", "\t\r"};
    CHECK_NOTHROW(normalize_changed_list_ip_cidrs(candidate, previous));
    REQUIRE(candidate.lists->at("example").ip_cidrs.has_value());
    CHECK(candidate.lists->at("example").ip_cidrs->empty());
    CHECK_NOTHROW(validate_config(candidate));
    candidate.lists->at("example").ip_cidrs.reset();
    CHECK_NOTHROW(normalize_changed_list_ip_cidrs(candidate, previous));
    CHECK_FALSE(candidate.lists->at("example").ip_cidrs.has_value());
}

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

TEST_CASE("Firefox DoH canary accepts nullable booleans and preserves explicit settings") {
    struct Case {
        const char* document;
        std::optional<bool> explicit_value;
    };
    const std::vector<Case> cases{
        {R"({})", std::nullopt},
        {R"({"dns":null})", std::nullopt},
        {R"({"dns":{}})", std::nullopt},
        {R"({"dns":{"firefox_doh_canary":null}})", std::nullopt},
        {R"({"dns":{"firefox_doh_canary":true}})", true},
        {R"({"dns":{"firefox_doh_canary":false}})", false},
    };
    for (const auto& fixture : cases) {
        CAPTURE(fixture.document);
        const auto config = parse_test_config(fixture.document);
        REQUIRE(config.dns.has_value());
        CHECK(config.dns->firefox_doh_canary == fixture.explicit_value);
        CHECK(config.dns->firefox_doh_canary.value_or(true) ==
              fixture.explicit_value.value_or(true));

        const nlohmann::json dto = config;
        const auto dto_roundtrip = parse_test_config(dto.dump());
        REQUIRE(dto_roundtrip.dns.has_value());
        CHECK(dto_roundtrip.dns->firefox_doh_canary == fixture.explicit_value);

        const auto persisted_text = serialize_config_document(config);
        const auto persisted = nlohmann::json::parse(persisted_text);
        REQUIRE(persisted.contains("dns"));
        if (fixture.explicit_value.has_value()) {
            REQUIRE(persisted["dns"].contains("firefox_doh_canary"));
            CHECK(persisted["dns"]["firefox_doh_canary"] ==
                  *fixture.explicit_value);
        } else {
            CHECK_FALSE(persisted["dns"].contains("firefox_doh_canary"));
        }
        const auto restored = parse_test_config(persisted_text);
        REQUIRE(restored.dns.has_value());
        CHECK(restored.dns->firefox_doh_canary == fixture.explicit_value);
    }
}

TEST_CASE("Firefox DoH canary rejects other JSON types with the existing boolean issue") {
    const std::vector<nlohmann::json> values{
        "false", "", 0, 1, 1.5,
        nlohmann::json::object(), nlohmann::json::array()};
    for (const auto& value : values) {
        CAPTURE(value.dump());
        const nlohmann::json document{
            {"dns", {{"firefox_doh_canary", value}}}};
        const auto issues = parse_issues(document.dump());
        REQUIRE(issues.size() == 1U);
        CHECK(issues[0].path == "dns.firefox_doh_canary");
        CHECK(issues[0].message == "dns.firefox_doh_canary must be a boolean");
        CHECK(issues[0].code == "config.value.boolean");
        CHECK(issues[0].params.empty());
        const auto wire = serialize_config_validation_issues(issues);
        REQUIRE(wire.size() == 1U);
        const auto dto = wire[0].get<api::ValidationErrorElement>();
        CHECK(dto.path == "dns.firefox_doh_canary");
        CHECK(dto.code == "config.value.boolean");
        CHECK(dto.message == issues[0].message);
    }

    const auto ordered = parse_issues(R"({
        "daemon":{"ipv6_enabled":"invalid"},
        "dns":{"firefox_doh_canary":"invalid"}
    })");
    REQUIRE(ordered.size() == 2U);
    CHECK(ordered[0].path == "daemon.ipv6_enabled");
    CHECK(ordered[0].message == "daemon.ipv6_enabled must be a boolean");
    CHECK(ordered[1].path == "dns.firefox_doh_canary");
    CHECK(ordered[1].message == "dns.firefox_doh_canary must be a boolean");
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

TEST_CASE("structured config validation: scalar types preserve their original messages") {
    const auto issues = parse_issues(R"({"daemon":{
        "max_file_size_bytes":"not-a-number",
        "firewall_backend":123,
        "ipv6_enabled":"not-a-boolean"
    }})");
    REQUIRE(issues.size() == 3);
    const auto* integer = find_issue(issues, "daemon.max_file_size_bytes");
    REQUIRE(integer != nullptr);
    CHECK(integer->message == "daemon.max_file_size_bytes must be an integer");
    CHECK(integer->code == "config.value.integer");
    const auto* string = find_issue(issues, "daemon.firewall_backend");
    REQUIRE(string != nullptr);
    CHECK(string->message == "daemon.firewall_backend must be a string");
    CHECK(string->code == "config.value.string");
    const auto* boolean = find_issue(issues, "daemon.ipv6_enabled");
    REQUIRE(boolean != nullptr);
    CHECK(boolean->message == "daemon.ipv6_enabled must be a boolean");
    CHECK(boolean->code == "config.value.boolean");
    for (const auto& issue : issues) CHECK(issue.params.empty());
}

TEST_CASE("structured config validation: numeric metadata describes constraints not input values") {
    const auto issues = validate_issues(R"({
        "daemon":{"firewall_verify_max_bytes":-1,"max_file_size_bytes":0,"ipset_maxelem":0},
        "lists":{"custom":{"ip_cidrs":["192.0.2.0/24"],
            "shrink_policy":{"min_previous_entries":-1,"min_retained_fraction":1.5}}},
        "outbounds":[{"tag":"vpn","type":"interface","interface":"wg0"},
            {"tag":"group","type":"urltest","url":"https://example.org/",
             "interval_ms":0,"outbound_groups":[{"outbounds":["vpn"]}]}]
    })");
    REQUIRE(issues.size() == 6);
    const auto* nonnegative = find_issue(issues, "daemon.firewall_verify_max_bytes");
    REQUIRE(nonnegative != nullptr);
    CHECK(nonnegative->code == "config.value.non_negative");
    CHECK(nonnegative->message == "daemon.firewall_verify_max_bytes must be >= 0");
    const auto* positive = find_issue(issues, "daemon.max_file_size_bytes");
    REQUIRE(positive != nullptr);
    CHECK(positive->code == "config.value.positive");
    CHECK(positive->message == "daemon.max_file_size_bytes must be greater than 0");
    const auto* fraction = find_issue(issues, "lists.custom.shrink_policy.min_retained_fraction");
    REQUIRE(fraction != nullptr);
    CHECK(fraction->code == "config.value.fraction");
    CHECK(fraction->message == "lists.custom.shrink_policy.min_retained_fraction must be a finite number between 0 and 1");
    const auto* previous = find_issue(issues, "lists.custom.shrink_policy.min_previous_entries");
    REQUIRE(previous != nullptr);
    CHECK(previous->code == "config.value.non_negative");
    for (const auto* issue : {nonnegative, positive, fraction, previous}) CHECK(issue->params.empty());
    for (const auto* path : {"daemon.ipset_maxelem", "outbounds.group.interval_ms"}) {
        const auto* range = find_issue(issues, path);
        REQUIRE(range != nullptr);
        CHECK(range->code == "config.value.range");
        CHECK(range->message == std::string(path) + " must be between 1 and 4294967295");
        CHECK(range->params == std::map<std::string, std::string>{{"min", "1"}, {"max", "4294967295"}});
    }
    for (const auto& dscp : {nlohmann::json("bad"), nlohmann::json(64)}) {
        const auto raw = nlohmann::json{{"route", {{"rules", {{{"dscp", dscp}, {"outbound", "vpn"}}}}}}};
        const auto invalid = parse_issues(raw.dump());
        REQUIRE(invalid.size() == 1);
        CHECK(invalid.front().path == "route.rules[0].dscp");
        CHECK(invalid.front().code == (dscp.is_string() ? "config.value.integer_range" : "config.value.range"));
        CHECK(invalid.front().params == std::map<std::string, std::string>{{"min", "1"}, {"max", "63"}});
    }
}

TEST_CASE("structured config validation: tags and missing required fields do not expose values in params") {
    const auto required = validate_issues(list_config_json(""));
    REQUIRE(required.size() == 1);
    CHECK(required.front().code == "config.value.required");
    CHECK(required.front().message == "List name must not be empty");
    CHECK(required.front().params.empty());
    const auto invalid = validate_issues(list_config_json("BadName"));
    REQUIRE(invalid.size() == 1);
    CHECK(invalid.front().code == "config.tag.invalid");
    CHECK(invalid.front().params.empty());
    const auto too_long = validate_issues(list_config_json(std::string(25, 'a')));
    REQUIRE(too_long.size() == 2);
    CHECK(too_long.front().code == "config.tag.too_long");
    CHECK(too_long.front().params == std::map<std::string, std::string>{{"max", "24"}});
    CHECK(too_long.back().code == "config.tag.invalid");
    const auto empty_reference = validate_issues(R"({
        "route":{"rules":[{"src_addr":"192.0.2.1","outbound":""}]}
    })");
    REQUIRE(empty_reference.size() == 1);
    CHECK(empty_reference.front().code == "config.value.required");
    CHECK(empty_reference.front().message == "route.rules[0].outbound must not be empty");
    const auto cron = validate_issues(R"({"lists_autoupdate":{"enabled":true}})");
    REQUIRE(cron.size() == 1);
    CHECK(cron.front().code == "config.value.required");
    CHECK(cron.front().message == "lists_autoupdate.cron is required when enabled");
}

TEST_CASE("structured config validation: legacy issue text is not classified into codes") {
    const ConfigValidationIssue legacy{"custom.path", "custom.path must be an integer"};
    CHECK(legacy.code.empty());
    CHECK(legacy.params.empty());
    const ConfigValidationError old_error({legacy});
    CHECK(std::string(old_error.what()) == legacy.message);
    const ConfigValidationError coded_error({{legacy.path, legacy.message, "config.value.integer", {}}});
    CHECK(std::string(coded_error.what()) == legacy.message);
    const auto malformed = parse_issues("{");
    REQUIRE(malformed.size() == 1);
    CHECK(malformed.front().code == "config.json.syntax");
    CHECK(malformed.front().params.empty());
    auto stale = parse_test_config("{}");
    stale.schema_version = 1;
    try {
        validate_config(stale);
        FAIL("unmigrated typed configuration accepted");
    } catch (const ConfigValidationError& error) {
        REQUIRE(error.issues().size() == 1);
        CHECK(error.issues().front().code == "config.schema_version.migration_required");
        CHECK(error.issues().front().params == std::map<std::string, std::string>{{"supported", "2"}});
    }
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

    // delete_on_failure is legal in latency mode too: a latency group retires
    // an unhealthy child for the same reason a priority group does, and since
    // failure-only cleanup became the unset default, the old priority-only
    // restriction would forbid writing down what the default already does.
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
              "outbounds.ut.conntrack_on_switch") == nullptr);

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
    const auto issues = parse_issues(R"({"schema_version":2,"dns":{"fallback":"quad9"}})");
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

TEST_CASE("dns servers: direct domain bindings survive config round trip") {
    const auto cfg = parse_test_config(R"({
        "dns": {
            "servers": [{"tag":"dns","address":"192.0.2.53",
                         "domains":["*.YouTube.com.","youtube.com","_sip._tcp.example.com"]}],
            "fallback": ["dns"]
        }
    })");
    REQUIRE(cfg.dns->servers->front().domains.has_value());
    CHECK(cfg.dns->servers->front().domains->size() == 3);
    const nlohmann::json encoded = cfg;
    CHECK(encoded.at("dns").at("servers").at(0).at("domains").at(0) ==
          "*.YouTube.com.");
    CHECK_NOTHROW(parse_test_config(encoded.dump()));
}

TEST_CASE("list shrink policy absent null and empty preserve default thresholds") {
    const auto absent = parse_test_config(list_config_json("remote"));
    CHECK_FALSE(absent.lists->at("remote").shrink_policy.has_value());
    const auto null_policy = parse_test_config(list_config_json("remote",
        R"({"url":"https://example.test/list.txt","shrink_policy":null})"));
    CHECK_FALSE(null_policy.lists->at("remote").shrink_policy.has_value());
    for (const auto& policy : {std::string("{}"),
                              std::string(R"({"min_previous_entries":null,"min_retained_fraction":null})")}) {
        const auto config = parse_test_config(list_config_json("remote",
            "{\"url\":\"https://example.test/list.txt\",\"shrink_policy\":" + policy + "}"));
        const auto& parsed = config.lists->at("remote").shrink_policy;
        REQUIRE(parsed.has_value());
        CHECK_FALSE(parsed->min_previous_entries.has_value());
        CHECK_FALSE(parsed->min_retained_fraction.has_value());
        CHECK(parsed->min_previous_entries.value_or(50) == 50);
        CHECK(parsed->min_retained_fraction.value_or(0.5) == 0.5);
        const auto reparsed = parse_test_config(nlohmann::json(config).dump());
        CHECK_FALSE(reparsed.lists->at("remote").shrink_policy->min_previous_entries.has_value());
        CHECK_FALSE(reparsed.lists->at("remote").shrink_policy->min_retained_fraction.has_value());
    }
}

TEST_CASE("list shrink policy accepts finite inclusive bounds") {
    for (const auto minimum : {int64_t{0}, int64_t{50}, std::numeric_limits<int64_t>::max()}) {
        for (const auto fraction : {0.0, 0.5, 1.0}) {
            const nlohmann::json list = {
                {"url", "https://example.test/list.txt"},
                {"shrink_policy", {{"min_previous_entries", minimum},
                                    {"min_retained_fraction", fraction}}}};
            const auto config = parse_test_config(list_config_json("remote", list.dump()));
            const auto& policy = *config.lists->at("remote").shrink_policy;
            CHECK(policy.min_previous_entries == minimum);
            CHECK(policy.min_retained_fraction == fraction);
        }
    }
}

TEST_CASE("list shrink policy rejects malformed fields without losing source paths") {
    for (const auto& policy : {nlohmann::json(true), nlohmann::json(2),
                              nlohmann::json("automatic"), nlohmann::json::array()}) {
        const nlohmann::json list = {{"url", "https://example.test/list.txt"}, {"shrink_policy", policy}};
        CHECK(find_issue(parse_issues(list_config_json("remote", list.dump())),
                         "lists.remote.shrink_policy") != nullptr);
    }
    for (const auto& minimum : {nlohmann::json(true), nlohmann::json(1.5),
                               nlohmann::json("50"),
                               nlohmann::json(std::numeric_limits<uint64_t>::max())}) {
        const nlohmann::json list = {{"url", "https://example.test/list.txt"},
            {"shrink_policy", {{"min_previous_entries", minimum}}}};
        CHECK(find_issue(parse_issues(list_config_json("remote", list.dump())),
                         "lists.remote.shrink_policy.min_previous_entries") != nullptr);
    }
    for (const auto& fraction : {nlohmann::json(true), nlohmann::json("0.5"), nlohmann::json::array()}) {
        const nlohmann::json list = {{"url", "https://example.test/list.txt"},
            {"shrink_policy", {{"min_retained_fraction", fraction}}}};
        CHECK(find_issue(parse_issues(list_config_json("remote", list.dump())),
                         "lists.remote.shrink_policy.min_retained_fraction") != nullptr);
    }
}

TEST_CASE("list shrink policy validates hidden source fields and numeric ranges") {
    for (const auto& source : {nlohmann::json{{"url", "https://example.test/list.txt"}},
                               nlohmann::json{{"ip_cidrs", {"10.0.0.1"}}}}) {
        auto list = source;
        list["shrink_policy"] = {{"min_previous_entries", -1}};
        CHECK(find_issue(validate_issues(list_config_json("remote", list.dump())),
                         "lists.remote.shrink_policy.min_previous_entries") != nullptr);
        for (const auto fraction : {-0.001, 1.001}) {
            list["shrink_policy"] = {{"min_retained_fraction", fraction}};
            CHECK(find_issue(validate_issues(list_config_json("remote", list.dump())),
                             "lists.remote.shrink_policy.min_retained_fraction") != nullptr);
        }
    }
}

TEST_CASE("list shrink policy rejects nonfinite typed fractions") {
    for (const auto fraction : {std::numeric_limits<double>::quiet_NaN(),
                               std::numeric_limits<double>::infinity(),
                               -std::numeric_limits<double>::infinity()}) {
        auto config = parse_test_config(list_config_json("remote"));
        config.lists->at("remote").shrink_policy = api::ShrinkPolicy{};
        config.lists->at("remote").shrink_policy->min_retained_fraction = fraction;
        std::vector<ConfigValidationIssue> issues;
        try {
            validate_config(config);
        } catch (const ConfigValidationError& error) {
            issues = error.issues();
        }
        CHECK(find_issue(issues, "lists.remote.shrink_policy.min_retained_fraction") != nullptr);
    }
}

TEST_CASE("dns servers: malformed direct domains report the exact field") {
    for (const std::string& domain : std::vector<std::string>{
             "", "https://example.com", "example.com/path", "192.0.2.53",
             "::1", ".example.com", "example.com..", "a..com", "-bad.com",
             "bad-.com", "x*.com", "example.com\nserver=8.8.8.8",
             std::string(64, 'a') + ".com"}) {
        CAPTURE(domain);
        auto config = nlohmann::json::parse(R"({"dns": {
            "servers": [{"tag":"dns","address":"192.0.2.53"}],
            "fallback": ["dns"]
        }})");
        config["dns"]["servers"][0]["domains"] = {domain};
        const auto issues = validate_issues(config.dump());
        CHECK(find_issue(issues, "dns.servers.dns.domains.0") != nullptr);
    }
}

TEST_CASE("dns servers: legacy and empty domain bindings remain valid") {
    for (const std::string& suffix : {std::string{}, std::string{",\"domains\":[]"}}) {
        CHECK_NOTHROW(parse_test_config(
            "{\"dns\":{\"servers\":[{\"tag\":\"dns\",\"address\":\"192.0.2.53\"" +
            suffix + "}],\"fallback\":[\"dns\"]}}"));
    }
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

TEST_CASE(
    "dns servers: keenetic type is accepted when KeeneticOS version is temporarily unknown") {
    SystemInfoTestGuard guard;
    set_system_info_for_tests(SystemInfo{
        .os_type = "keenetic",
        .os_version = "unknown",
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
// Route rule failure policy validation
// =============================================================================

static nlohmann::json failure_policy_config() {
    return nlohmann::json::parse(R"({
        "outbounds":[
            {"tag":"primary","type":"interface","interface":"wg0"},
            {"tag":"backup","type":"interface","interface":"wg1"},
            {"tag":"table_backup","type":"table","table":201},
            {"tag":"group_backup","type":"urltest","url":"https://example.test/check",
             "outbound_groups":[{"outbounds":["backup"]}]},
            {"tag":"drop","type":"blackhole"},
            {"tag":"direct","type":"ignore"}
        ],
        "route":{"rules":[{"outbound":"primary","src_addr":"192.0.2.10"}]}
    })");
}

TEST_CASE("route failure policy: absent and null preserve legacy inheritance on round trip") {
    for (bool explicit_null : {false, true}) {
        auto input = failure_policy_config();
        if (explicit_null) {
            input["route"]["rules"][0]["failure_policy"] = nullptr;
            input["route"]["rules"][0]["fallback_outbound"] = nullptr;
        }
        input["daemon"]["strict_enforcement"] = true;
        input["outbounds"][0]["strict_enforcement"] = false;
        const auto parsed = parse_test_config(input.dump());
        REQUIRE(parsed.route.has_value());
        REQUIRE(parsed.route->rules.has_value());
        const auto& rule = parsed.route->rules->front();
        CHECK_FALSE(rule.failure_policy.has_value());
        CHECK(rule.failure_policy.value_or(api::FailurePolicy::INHERIT) == api::FailurePolicy::INHERIT);
        CHECK_FALSE(rule.fallback_outbound.has_value());
        const nlohmann::json encoded = parsed;
        CHECK(encoded["route"]["rules"][0]["failure_policy"].is_null());
        CHECK(encoded["route"]["rules"][0]["fallback_outbound"].is_null());
        CHECK(encoded["daemon"]["strict_enforcement"] == true);
        CHECK(encoded["outbounds"][0]["strict_enforcement"] == false);
        const auto round_trip = parse_test_config(encoded.dump());
        CHECK_FALSE(round_trip.route->rules->front().failure_policy.has_value());
    }
}

TEST_CASE("route failure policy: explicit modes round-trip without changing the configured primary") {
    for (const std::string policy : {"inherit", "block", "fallback"}) {
        auto input = failure_policy_config();
        auto& rule = input["route"]["rules"][0];
        rule["failure_policy"] = policy;
        rule["enabled"] = false;
        if (policy == "fallback") rule["fallback_outbound"] = "backup";
        const auto parsed = parse_test_config(input.dump());
        const nlohmann::json encoded = parsed;
        CHECK(encoded["route"]["rules"][0]["failure_policy"] == policy);
        CHECK(encoded["route"]["rules"][0]["outbound"] == "primary");
        CHECK(encoded["route"]["rules"][0]["enabled"] == false);
        if (policy == "fallback") {
            CHECK(encoded["route"]["rules"][0]["fallback_outbound"] == "backup");
        }
        CHECK_NOTHROW(parse_test_config(encoded.dump()));
    }
}

TEST_CASE("route failure policy: interface and urltest targets require no live health at save") {
    for (const std::string primary : {"primary", "group_backup"}) {
        for (const std::string backup : {"backup", "group_backup"}) {
            if (primary == backup) continue;
            auto input = failure_policy_config();
            auto& rule = input["route"]["rules"][0];
            rule["outbound"] = primary;
            rule["failure_policy"] = "fallback";
            rule["fallback_outbound"] = backup;
            CHECK_NOTHROW(parse_test_config(input.dump()));
        }
    }
}

TEST_CASE("route failure policy: malformed mode and fallback types have exact parse paths") {
    for (const auto& invalid : std::vector<nlohmann::json>{true, 3, "unknown", "", nlohmann::json::object()}) {
        auto input = failure_policy_config();
        input["route"]["rules"][0]["failure_policy"] = invalid;
        const auto issues = parse_issues(input.dump());
        REQUIRE(issues.size() == 1U);
        CHECK(issues.front().path == "route.rules[0].failure_policy");
    }
    for (const auto& invalid : std::vector<nlohmann::json>{true, 3, nlohmann::json::array()}) {
        auto input = failure_policy_config();
        input["route"]["rules"][0]["fallback_outbound"] = invalid;
        const auto issues = parse_issues(input.dump());
        REQUIRE(issues.size() == 1U);
        CHECK(issues.front().path == "route.rules[0].fallback_outbound");
    }
}

TEST_CASE("route failure policy: fallback requires a configured target") {
    for (const auto& fallback : std::vector<nlohmann::json>{nullptr, "", "missing", " backup "}) {
        auto input = failure_policy_config();
        input["route"]["rules"][0]["failure_policy"] = "fallback";
        input["route"]["rules"][0]["fallback_outbound"] = fallback;
        const auto issues = validate_issues(input.dump());
        REQUIRE(issues.size() == 1U);
        CHECK(issues.front().path == "route.rules[0].fallback_outbound");
    }
    auto missing = failure_policy_config();
    missing["route"]["rules"][0]["failure_policy"] = "fallback";
    CHECK(find_issue(validate_issues(missing.dump()), "route.rules[0].fallback_outbound") != nullptr);
}

TEST_CASE("route failure policy: explicit modes require the exact configured primary") {
    for (const std::string primary : {"missing", " primary ", " table_backup "}) {
        auto input = failure_policy_config();
        input["route"]["rules"][0]["failure_policy"] = "block";
        input["route"]["rules"][0]["outbound"] = primary;
        const auto issues = validate_issues(input.dump());
        REQUIRE(issues.size() == 1U);
        CHECK(issues.front().path == "route.rules[0].outbound");
    }
}

TEST_CASE("route failure policy: table ignore and blackhole keep inherited behavior only") {
    for (const std::string primary : {"table_backup", "drop", "direct"}) {
        for (const std::string policy : {"block", "fallback"}) {
            auto input = failure_policy_config();
            auto& rule = input["route"]["rules"][0];
            rule["outbound"] = primary;
            rule["failure_policy"] = policy;
            if (policy == "fallback") rule["fallback_outbound"] = "backup";
            const auto issues = validate_issues(input.dump());
            REQUIRE(issues.size() == 1U);
            CHECK(issues.front().path == "route.rules[0].failure_policy");
        }
        auto inherited = failure_policy_config();
        inherited["route"]["rules"][0]["outbound"] = primary;
        CHECK_NOTHROW(parse_test_config(inherited.dump()));
        inherited["route"]["rules"][0]["failure_policy"] = "inherit";
        CHECK_NOTHROW(parse_test_config(inherited.dump()));
    }
}

TEST_CASE("route failure policy: fallback must differ from primary and be routable") {
    for (const std::string fallback : {"primary", "table_backup", "drop", "direct"}) {
        auto input = failure_policy_config();
        input["route"]["rules"][0]["failure_policy"] = "fallback";
        input["route"]["rules"][0]["fallback_outbound"] = fallback;
        const auto issues = validate_issues(input.dump());
        REQUIRE(issues.size() == 1U);
        CHECK(issues.front().path == "route.rules[0].fallback_outbound");
    }
}

TEST_CASE("route failure policy: unused nonempty fallback cannot be silently retained") {
    for (const auto& policy : std::vector<nlohmann::json>{nullptr, "inherit", "block"}) {
        auto input = failure_policy_config();
        input["route"]["rules"][0]["failure_policy"] = policy;
        input["route"]["rules"][0]["fallback_outbound"] = "backup";
        const auto issues = validate_issues(input.dump());
        REQUIRE(issues.size() == 1U);
        CHECK(issues.front().path == "route.rules[0].fallback_outbound");
        input["route"]["rules"][0]["fallback_outbound"] = "";
        CHECK_NOTHROW(parse_test_config(input.dump()));
    }
}

TEST_CASE("route failure policy: rule fallback participates in existing conntrack ownership rules") {
    for (const std::string mode : {"delete", "delete_on_failure", "preserve"}) {
        auto input = failure_policy_config();
        input["outbounds"][3]["conntrack_on_switch"] = mode;
        input["route"]["rules"][0]["failure_policy"] = "fallback";
        input["route"]["rules"][0]["fallback_outbound"] = "backup";
        const auto issues = validate_issues(input.dump());
        if (mode == "delete") {
            REQUIRE(issues.size() == 1U);
            CHECK(issues.front().path == "outbounds.group_backup.conntrack_on_switch");
        } else {
            CHECK(issues.empty());
        }
    }
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
        {"start", "0x00001000"},
        {"mask", "0x0000F000"}
    };
    config["outbounds"] = nlohmann::json::array();

    for (int i = 0; i < 16; ++i) {
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

        if (issue.message.find("maximum 15 supported with current fwmark.mask") !=
            std::string::npos) {
            saw_capacity_error = true;
            break;
        }
    }

    CHECK(saw_capacity_error);
}

TEST_CASE("fwmark mask: boundary allocation never aliases unmarked traffic") {
    FwmarkConfig fwmark;
    fwmark.start = "0x00001000";
    fwmark.mask = "0x0000F000";

    std::vector<Outbound> outbounds;
    for (int i = 0; i < 15; ++i) {
        Outbound outbound;
        outbound.tag = "wan" + std::to_string(i);
        outbound.type = OutboundType::INTERFACE;
        outbound.interface = "wg" + std::to_string(i);
        outbounds.push_back(std::move(outbound));
    }

    const auto marks = allocate_outbound_marks(fwmark, outbounds);
    REQUIRE(marks.size() == 15);

    std::set<uint32_t> masked_marks;
    for (const auto& [tag, mark] : marks) {
        CAPTURE(tag);
        CAPTURE(mark);
        const uint32_t masked_mark = mark & 0x0000F000u;
        CHECK(masked_mark != 0);
        CHECK(masked_marks.insert(masked_mark).second);
    }
}

TEST_CASE("fwmark start: zero masked value is rejected") {
    FwmarkConfig fwmark;
    fwmark.start = "0x00010000";
    fwmark.mask = "0x0000F000";

    Outbound outbound;
    outbound.tag = "wan";
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = "wg0";

    CHECK_THROWS_WITH_AS(
        allocate_outbound_marks(fwmark, {outbound}),
        "fwmark.start must select a non-zero value within fwmark.mask",
        ConfigError);
}

TEST_CASE("fwmark start and mask: current format requires strings during config parsing") {
    CHECK_THROWS_AS(parse_test_config(R"({"schema_version":2,"fwmark":{"start":65536}})"), ConfigValidationError);
    CHECK_THROWS_AS(parse_test_config(R"({"schema_version":2,"fwmark":{"mask":16711680}})"), ConfigValidationError);
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

TEST_CASE("daemon.meta_udp443_policy: omitted and null use balanced default") {
    for (const auto* input : {
             R"({"daemon":{}})",
             R"({"daemon":{"meta_udp443_policy":null}})",
         }) {
        const auto cfg = parse_test_config(input);
        REQUIRE(cfg.daemon.has_value());
        CHECK(
            cfg.daemon->meta_udp443_policy.value_or(
                api::MetaUdp443Policy::BALANCED) ==
            api::MetaUdp443Policy::BALANCED);
    }
}

TEST_CASE("daemon.meta_udp443_policy: explicit policies round-trip") {
    for (const auto& [value, expected] :
         std::vector<std::pair<std::string, api::MetaUdp443Policy>>{
             {"balanced", api::MetaUdp443Policy::BALANCED},
             {"messages_first", api::MetaUdp443Policy::MESSAGES_FIRST},
         }) {
        const auto parsed = parse_test_config(
            nlohmann::json{
                {"daemon", {{"meta_udp443_policy", value}}},
            }
                .dump());
        REQUIRE(parsed.daemon.has_value());
        REQUIRE(parsed.daemon->meta_udp443_policy.has_value());
        CHECK(*parsed.daemon->meta_udp443_policy == expected);

        const auto serialized = nlohmann::json(parsed);
        CHECK(serialized.at("daemon").at("meta_udp443_policy") == value);

        const auto reparsed = parse_test_config(serialized.dump());
        REQUIRE(reparsed.daemon->meta_udp443_policy.has_value());
        CHECK(*reparsed.daemon->meta_udp443_policy == expected);
    }
}

TEST_CASE("daemon.meta_udp443_policy: rejects malformed values") {
    const auto unsupported = parse_issues(
        R"({"daemon":{"meta_udp443_policy":"calls_first"}})");
    REQUIRE(unsupported.size() == 1U);
    CHECK(unsupported.front().path == "daemon.meta_udp443_policy");

    const auto wrong_type =
        parse_issues(R"({"daemon":{"meta_udp443_policy":true}})");
    REQUIRE(wrong_type.size() == 1U);
    CHECK(wrong_type.front().path == "daemon.meta_udp443_policy");
}

TEST_CASE("daemon PPE de-offload defaults stay fail-safe when omitted or null") {
    for (const auto* input : {
             R"({"daemon":{}})",
             R"({"daemon":{"ppe_deoffload_mode":null,"ppe_deoffload_quic_enabled":null}})",
         }) {
        const auto cfg = parse_test_config(input);
        REQUIRE(cfg.daemon.has_value());
        CHECK_FALSE(cfg.daemon->ppe_deoffload_mode.has_value());
        CHECK_FALSE(cfg.daemon->ppe_deoffload_quic_enabled.has_value());
    }
}

TEST_CASE("daemon PPE de-offload policy round-trips explicit values") {
    for (const auto& [value, expected] :
         std::vector<std::pair<std::string, api::PpeDeoffloadMode>>{
             {"off", api::PpeDeoffloadMode::OFF},
             {"auto", api::PpeDeoffloadMode::AUTO},
         }) {
        const auto parsed = parse_test_config(
            nlohmann::json{
                {"daemon",
                 {{"ppe_deoffload_mode", value},
                  {"ppe_deoffload_quic_enabled", value == "auto"}}},
            }
                .dump());
        REQUIRE(parsed.daemon.has_value());
        REQUIRE(parsed.daemon->ppe_deoffload_mode.has_value());
        REQUIRE(parsed.daemon->ppe_deoffload_quic_enabled.has_value());
        CHECK(*parsed.daemon->ppe_deoffload_mode == expected);
        CHECK(*parsed.daemon->ppe_deoffload_quic_enabled == (value == "auto"));

        const auto serialized = nlohmann::json(parsed);
        CHECK(serialized.at("daemon").at("ppe_deoffload_mode") == value);
        CHECK(serialized.at("daemon").at("ppe_deoffload_quic_enabled") ==
              (value == "auto"));
    }
}

TEST_CASE("daemon PPE de-offload policy rejects malformed values") {
    const auto unsupported = parse_issues(
        R"({"daemon":{"ppe_deoffload_mode":"on"}})");
    REQUIRE(unsupported.size() == 1U);
    CHECK(unsupported.front().path == "daemon.ppe_deoffload_mode");

    const auto wrong_mode_type = parse_issues(
        R"({"daemon":{"ppe_deoffload_mode":true}})");
    REQUIRE(wrong_mode_type.size() == 1U);
    CHECK(wrong_mode_type.front().path == "daemon.ppe_deoffload_mode");

    const auto wrong_quic_type = parse_issues(
        R"({"daemon":{"ppe_deoffload_quic_enabled":"yes"}})");
    REQUIRE(wrong_quic_type.size() == 1U);
    CHECK(wrong_quic_type.front().path ==
          "daemon.ppe_deoffload_quic_enabled");
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

TEST_CASE("daemon.reuse_static_sets_on_runtime_refresh: explicit, null, and junk") {
    auto enabled = parse_test_config(
        R"({"daemon":{"reuse_static_sets_on_runtime_refresh":true}})");
    auto disabled = parse_test_config(
        R"({"daemon":{"reuse_static_sets_on_runtime_refresh":false}})");
    REQUIRE(enabled.daemon->reuse_static_sets_on_runtime_refresh.has_value());
    REQUIRE(disabled.daemon->reuse_static_sets_on_runtime_refresh.has_value());
    CHECK(*enabled.daemon->reuse_static_sets_on_runtime_refresh);
    CHECK_FALSE(*disabled.daemon->reuse_static_sets_on_runtime_refresh);

    // Null means "the default", which the daemon resolves to true; the
    // parsed config itself keeps the absence.
    auto defaulted = parse_test_config(
        R"({"daemon":{"reuse_static_sets_on_runtime_refresh":null}})");
    REQUIRE(defaulted.daemon.has_value());
    CHECK_FALSE(
        defaulted.daemon->reuse_static_sets_on_runtime_refresh.has_value());

    const auto issues = parse_issues(
        R"({"daemon":{"reuse_static_sets_on_runtime_refresh":"yes"}})");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "daemon.reuse_static_sets_on_runtime_refresh");
}

TEST_CASE("daemon ipset capacities accept positive values and null defaults") {
    const auto configured = parse_test_config(
        R"({"daemon":{"ipset_hashsize":1024,"ipset_maxelem":131072}})");
    REQUIRE(configured.daemon.has_value());
    CHECK(configured.daemon->ipset_hashsize == 1024);
    CHECK(configured.daemon->ipset_maxelem == 131072);

    const auto defaults = parse_test_config(
        R"({"daemon":{"ipset_hashsize":null,"ipset_maxelem":null}})");
    REQUIRE(defaults.daemon.has_value());
    CHECK_FALSE(defaults.daemon->ipset_hashsize.has_value());
    CHECK_FALSE(defaults.daemon->ipset_maxelem.has_value());
}

TEST_CASE("daemon ipset capacities reject invalid values") {
    for (const auto& field : {"ipset_hashsize", "ipset_maxelem"}) {
        for (const auto& value : {"0", "-1", "4294967296"}) {
            const auto issues = validate_issues(
                std::string("{\"daemon\":{\"") + field + "\":" + value + "}}");
            REQUIRE(issues.size() == 1);
            CHECK(issues[0].path == std::string("daemon.") + field);
        }
    }

    const auto hashsize_overflow = validate_issues(
        R"({"daemon":{"ipset_hashsize":2147483649}})");
    REQUIRE(hashsize_overflow.size() == 1);
    CHECK(hashsize_overflow[0].path == "daemon.ipset_hashsize");

    const auto wrong_types = parse_issues(
        R"({"daemon":{"ipset_hashsize":"1024","ipset_maxelem":1.5}})");
    REQUIRE(wrong_types.size() == 2);
    CHECK(wrong_types[0].path == "daemon.ipset_hashsize");
    CHECK(wrong_types[1].path == "daemon.ipset_maxelem");
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

TEST_CASE("retired WhatsApp TCP reset source key stays opaque without enabling a runtime setting") {
    const auto cfg = parse_test_config(R"({
        "daemon":{
            "experimental_whatsapp_tcp_reset_sources":[
                "192.168.1.117", "10.8.0.2"
            ]
        }
    })");
    REQUIRE(cfg.daemon.has_value());

    const nlohmann::json serialized = cfg;
    REQUIRE(serialized.contains("daemon"));
    // Lossless saves retain this retired setting only as unknown JSON. It has
    // no typed field or runtime consumer and must not map to the replacement.
    CHECK(cfg.daemon->_config_unknown_fields.at(
        "experimental_whatsapp_tcp_reset_sources") ==
        nlohmann::json::array({"192.168.1.117", "10.8.0.2"}));
    CHECK(serialized["daemon"]["experimental_whatsapp_tcp_reset_sources"] ==
        cfg.daemon->_config_unknown_fields.at("experimental_whatsapp_tcp_reset_sources"));
    CHECK_FALSE(cfg.daemon->reconnect_owned_flows_on_routing_change_lists.has_value());
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
    CHECK(issues[0].code == "config.reference.outbound_missing");
    CHECK(issues[0].params.empty());
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
    CHECK(issues[0].code == "config.reference.list_missing");
    CHECK(issues[0].params.empty());
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
    CHECK(issues[0].code == "config.reference.dns_server_missing");
    CHECK(issues[0].params.empty());
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
    CHECK(issues[0].code == "config.reference.list_missing");
    CHECK(issues[0].params.empty());
}

TEST_CASE("interface outbound: empty interface name is rejected") {
    const auto issues = validate_issues(R"({
        "outbounds":[{"tag":"wan","type":"interface","interface":""}]
    })");
    REQUIRE(issues.size() == 1);
    CHECK(issues[0].path == "outbounds.wan.interface");
}

// Найдено фаззингом `keen-pbr-fuzz-config`: числовой литерал с огромной
// экспонентой синтаксически корректен, и nlohmann бросает на нём `out_of_range`
// (406), а не `parse_error`. Мимо узкого catch исключение уходило наружу и
// роняло демон вместо понятной ошибки валидации.
TEST_CASE("parse_config rejects numeric overflow as a validation error") {
    const std::string document =
        R"({"outbounds":[],"lists":{},"x":7777777777777777e777777777777777777777})";

    CHECK_THROWS_AS(keen_pbr3::parse_config(document),
                    keen_pbr3::ConfigValidationError);
}

TEST_CASE("JSON metadata preserves parse diagnostics including numeric overflow") {
    struct Case { const char* document; const char* code; int id; };
    const Case cases[] = {
        {"{", "config.json.syntax", 101},
        {R"({"outbounds":[],"lists":{},"x":7777777777777777e777777777777777777777})",
            "config.json.number_overflow", 406},
    };
    for (const auto& item : cases) {
        CAPTURE(item.document);
        std::string original_message;
        try {
            const auto unexpected = nlohmann::json::parse(item.document, nullptr, true, true);
            static_cast<void>(unexpected);
            FAIL("malformed JSON unexpectedly parsed");
        } catch (const nlohmann::json::exception& error) {
            CHECK(error.id == item.id);
            original_message = std::string("Invalid JSON: ") + error.what();
        }
        REQUIRE_FALSE(original_message.empty());
        try {
            static_cast<void>(parse_config(item.document));
            FAIL("malformed configuration unexpectedly parsed");
        } catch (const ConfigValidationError& error) {
            REQUIRE(error.issues().size() == 1);
            const auto& issue = error.issues().front();
            CHECK(issue.path == "$");
            CHECK(issue.message == original_message);
            CHECK(std::string(error.what()) == original_message);
            CHECK(issue.code == item.code);
            CHECK(issue.params.empty());
        }
    }
}

TEST_CASE("JSON metadata preserves generated decode diagnostics and required field behavior") {
    struct Case { const char* document; const char* code; int id; };
    const Case cases[] = {
        {R"({"outbounds":[{"tag":17,"type":"ignore"}]})", "config.json.type", 302},
        {R"({"outbounds":[{"type":"ignore"}]})", "config.json.missing_field", 403},
        {R"({"outbounds":[{"tag":"wan","type":"unsupported"}]})", "config.json.decode", 0},
    };
    for (const auto& item : cases) {
        CAPTURE(item.document);
        std::string original_message;
        try {
            const auto migrated = migrate_config_json(nlohmann::json::parse(item.document));
            static_cast<void>(migrated.get<Config>());
            FAIL("invalid DTO unexpectedly decoded");
        } catch (const nlohmann::json::exception& error) {
            CHECK(error.id == item.id);
            original_message = error.what();
        } catch (const std::exception& error) {
            CHECK(item.id == 0);
            original_message = error.what();
        }
        REQUIRE_FALSE(original_message.empty());
        try {
            static_cast<void>(parse_config(item.document));
            FAIL("invalid configuration unexpectedly decoded");
        } catch (const ConfigValidationError& error) {
            REQUIRE(error.issues().size() == 1);
            const auto& issue = error.issues().front();
            CHECK(issue.path == "$");
            CHECK(issue.message == original_message);
            CHECK(std::string(error.what()) == original_message);
            CHECK(issue.code == item.code);
            CHECK(issue.params.empty());
        }
    }
}

TEST_CASE("JSON root-object metadata preserves every existing rejected root shape") {
    for (const char* document : {"null", "[]", "false", "1", "\"text\""}) {
        CAPTURE(document);
        const auto issues = parse_issues(document);
        REQUIRE(issues.size() == 1);
        CHECK(issues.front().path == "$");
        CHECK(issues.front().message == "Configuration must be a JSON object");
        CHECK(issues.front().code == "config.json.object");
        CHECK(issues.front().params.empty());
        CHECK(std::string(ConfigValidationError(issues).what()) == "Configuration must be a JSON object");
        try {
            static_cast<void>(migrate_config_json(nlohmann::json::parse(document)));
            FAIL("non-object migration unexpectedly accepted");
        } catch (const ConfigValidationError& error) {
            REQUIRE(error.issues().size() == 1);
            CHECK(error.issues().front().code == "config.json.object");
            CHECK(std::string(error.what()) == "Configuration must be a JSON object");
        }
    }
}

TEST_CASE("JSON metadata helper preserves caller redaction and never classifies exception text") {
    for (const char* misleading : {
            "[json.exception.parse_error.101] parse error",
            "[json.exception.out_of_range.406] number overflow",
            "Cannot deserialize to enumeration \"OutboundType\""}) {
        const std::runtime_error error(misleading);
        const auto issue = make_json_validation_issue("request", "Original fixed diagnostic", error);
        CHECK(issue.path == "request");
        CHECK(issue.message == "Original fixed diagnostic");
        CHECK(issue.code == "config.json.decode");
        CHECK(issue.params.empty());
    }
    try {
        static_cast<void>(nlohmann::json::array().at(0));
        FAIL("out-of-bounds array access unexpectedly accepted");
    } catch (const nlohmann::json::out_of_range& error) {
        CHECK(error.id == 401);
        const auto issue = make_json_validation_issue("request", "Keep this fixed message", error);
        CHECK(issue.code == "config.json.decode");
        CHECK(issue.message == "Keep this fixed message");
        CHECK(issue.params.empty());
    }
}

TEST_CASE("JSON metadata keeps comments defaults legacy migration and unknown fields accepted") {
    const auto empty = parse_config("{}");
    CHECK(empty.schema_version == kCurrentConfigSchemaVersion);
    CHECK(nlohmann::json(parse_config("{/* comment */}")) == nlohmann::json(empty));
    const std::string with_comments = R"(
        // Older configuration, comments intentionally remain supported.
        {
            "fwmark":{"start":65536,"mask":16711680},
            "dns":{"fallback":"default_dns"},
            "outbounds":[{"tag":"wan","type":"ignore"}],
            "x-preserved":{"value":17,"nested":[true,null]}
        } // trailing comment
    )";
    const auto raw = nlohmann::json::parse(with_comments, nullptr, true, true);
    const auto parsed = parse_config(with_comments);
    const nlohmann::json result = parsed;
    CHECK(result == nlohmann::json(parse_config(raw.dump())));
    CHECK(result.at("schema_version") == kCurrentConfigSchemaVersion);
    CHECK(result.at("fwmark").at("start") == "0x00010000");
    CHECK(result.at("fwmark").at("mask") == "0x00FF0000");
    CHECK(result.at("dns").at("fallback") == nlohmann::json::array({"default_dns"}));
    CHECK(result.at("x-preserved") == raw.at("x-preserved"));
    REQUIRE(parsed.outbounds.has_value());
    REQUIRE(parsed.outbounds->size() == 1);
    CHECK(parsed.outbounds->front().type == OutboundType::IGNORE);
}

TEST_CASE("JSON decode metadata does not precede existing ordered field validation") {
    const auto issues = parse_issues(R"({
        "daemon":{"max_file_size_bytes":"not-a-number","ipv6_enabled":"not-a-boolean"},
        "outbounds":[{"type":"ignore"}]
    })");
    REQUIRE(issues.size() == 2);
    CHECK(issues[0].path == "daemon.max_file_size_bytes");
    CHECK(issues[0].message == "daemon.max_file_size_bytes must be an integer");
    CHECK(issues[0].code == "config.value.integer");
    CHECK(issues[1].path == "daemon.ipv6_enabled");
    CHECK(issues[1].message == "daemon.ipv6_enabled must be a boolean");
    CHECK(issues[1].code == "config.value.boolean");
}

TEST_CASE("JSON validation producer codes survive the real serializer and generated DTO") {
    struct Case { const char* document; const char* code; };
    const Case cases[] = {
        {"{", "config.json.syntax"},
        {R"({"x":1e9999})", "config.json.number_overflow"},
        {R"({"outbounds":[{"tag":17,"type":"ignore"}]})", "config.json.type"},
        {R"({"outbounds":[{"type":"ignore"}]})", "config.json.missing_field"},
        {"[]", "config.json.object"},
        {R"({"outbounds":[{"tag":"wan","type":"unsupported"}]})", "config.json.decode"},
    };
    for (const auto& item : cases) {
        const auto issues = parse_issues(item.document);
        REQUIRE(issues.size() == 1);
        const auto wire = serialize_config_validation_issues(issues);
        REQUIRE(wire.size() == 1);
        CHECK_FALSE(wire.at(0).contains("params"));
        const auto dto = wire.at(0).get<api::ValidationErrorElement>();
        CHECK(dto.path == "$");
        CHECK(dto.message == issues.front().message);
        CHECK(dto.code == item.code);
        CHECK_FALSE(dto.params.has_value());
        // Generated DTOs render an absent optional as null; the HTTP helper
        // intentionally omits it. Compare decoded fields, not JSON bytes.
        const auto roundtrip = nlohmann::json(dto).get<api::ValidationErrorElement>();
        CHECK(roundtrip.path == dto.path);
        CHECK(roundtrip.message == dto.message);
        CHECK(roundtrip.code == dto.code);
        CHECK_FALSE(roundtrip.params.has_value());
    }
}

TEST_CASE("specialized validation metadata preserves port errors and accepted boundaries") {
    struct Case { const char* value; const char* code; const char* message; };
    const Case cases[] = {
        {"!", "config.port.list", "Use comma-separated ports or ranges."},
        {",1", "config.port.list", "Use comma-separated ports or ranges."},
        {"1,", "config.port.list", "Use comma-separated ports or ranges."},
        {"1,,2", "config.port.list", "Use comma-separated ports or ranges."},
        {"1-2-3", "config.port.range", "Port ranges must use valid ports such as 8000-9000."},
        {"0-1", "config.port.range", "Port ranges must use valid ports such as 8000-9000."},
        {"1-65536", "config.port.range", "Port ranges must use valid ports such as 8000-9000."},
        {"2-1", "config.port.range_order", "Port range start must be less than or equal to end."},
        {"0", "config.port.number", "Ports must be integers between 1 and 65535."},
        {"65536", "config.port.number", "Ports must be integers between 1 and 65535."},
        {"word", "config.port.number", "Ports must be integers between 1 and 65535."},
    };
    for (const char* field : {"src_port", "dest_port"}) {
        auto document = nlohmann::json::parse(R"({"route":{"rules":[{"src_addr":"192.0.2.1","outbound":"vpn"}]}})");
        for (const auto& item : cases) {
            CAPTURE(field);
            CAPTURE(item.value);
            document["route"]["rules"][0][field] = item.value;
            const auto issues = parse_issues(document.dump());
            REQUIRE(issues.size() == 1);
            CHECK(issues[0].path == std::string("route.rules[0].") + field);
            CHECK(issues[0].message == item.message);
            CHECK(issues[0].code == item.code);
            CHECK(issues[0].params.empty());
        }
        for (const char* value : {"", " ", "1", "65535", "1-65535", "!1-65535", " 0001, 65535 "}) {
            document["route"]["rules"][0][field] = value;
            CHECK_NOTHROW(parse_config(document.dump()));
        }
        document["route"]["rules"][0][field] = nullptr;
        CHECK_NOTHROW(parse_config(document.dump()));
    }
}

TEST_CASE("specialized validation metadata preserves address errors and accepted boundaries") {
    const std::string invalid_message = "Addresses must be valid IPv4 or IPv6 hosts or CIDR ranges, for example 10.0.0.1, 10.0.0.0/8, or 2001:db8::/32.";
    for (const char* field : {"src_addr", "dest_addr"}) {
        auto document = nlohmann::json::parse(R"({"route":{"rules":[{"dscp":1,"outbound":"vpn"}]}})");
        for (const char* value : {"!", ",192.0.2.1", "192.0.2.1,", "not-an-ip", "2001:db8::/129"}) {
            CAPTURE(field);
            CAPTURE(value);
            document["route"]["rules"][0][field] = value;
            const auto issues = parse_issues(document.dump());
            REQUIRE(issues.size() == 1);
            const bool list_error = std::string(value) == "!" || value[0] == ',' || std::string(value).back() == ',';
            CHECK(issues[0].path == std::string("route.rules[0].") + field);
            CHECK(issues[0].message == (list_error ? "Use comma-separated IP addresses or CIDRs." : invalid_message));
            CHECK(issues[0].code == (list_error ? "config.address.list" : "config.address.invalid"));
            CHECK(issues[0].params.empty());
        }
        for (const char* value : {"", " ", "0.0.0.0/0", "::/0", "192.0.2.1,2001:db8::1", "!192.168.0.0/16"}) {
            document["route"]["rules"][0][field] = value;
            CHECK_NOTHROW(parse_config(document.dump()));
        }
        document["route"]["rules"][0][field] = nullptr;
        CHECK_NOTHROW(parse_config(document.dump()));
    }
}

TEST_CASE("specialized validation metadata leaves route issue ordering and texts unchanged") {
    const auto issues = parse_issues(R"({"route":{"rules":[
        {"outbound":"vpn"},
        {"outbound":"vpn","src_port":"!","dest_port":"2-1","src_addr":"bad","dest_addr":",192.0.2.1"}
    ]}})");
    REQUIRE(issues.size() == 5);
    CHECK(issues[0].path == "route.rules[0]");
    CHECK(issues[0].message == "Route rule must include at least one condition: list, dscp, src_port, dest_port, src_addr, or dest_addr.");
    CHECK(issues[0].code == "config.route.condition_required");
    CHECK(issues[1].path == "route.rules[1].src_port");
    CHECK(issues[1].code == "config.port.list");
    CHECK(issues[2].path == "route.rules[1].dest_port");
    CHECK(issues[2].code == "config.port.range_order");
    CHECK(issues[3].path == "route.rules[1].src_addr");
    CHECK(issues[3].code == "config.address.invalid");
    CHECK(issues[4].path == "route.rules[1].dest_addr");
    CHECK(issues[4].code == "config.address.list");
    for (const auto& issue : issues) CHECK(issue.params.empty());
    for (const char* condition : {"\"list\":[\"custom\"]", "\"dscp\":1", "\"src_port\":\"1\"", "\"dest_port\":\"65535\"", "\"src_addr\":\"::1\"", "\"dest_addr\":\"192.0.2.1\""}) {
        CHECK_NOTHROW(parse_config(std::string("{\"route\":{\"rules\":[{\"outbound\":\"vpn\",") + condition + "}]}}"));
    }
}

TEST_CASE("specialized validation metadata uses display-name enum causes and existing Unicode limit") {
    struct Case { std::string value; const char* code; const char* suffix; };
    const Case cases[] = {
        {std::string("\xc0\xaf", 2), "config.name.encoding", " must be valid UTF-8"},
        {"name\nline", "config.name.controls", " must not contain ASCII control characters"},
        {std::string("name\xc2\x80", 6), "config.name.controls", " must not contain C1 or bidirectional control characters"},
        {std::string("name\xe2\x80\xae", 7), "config.name.controls", " must not contain C1 or bidirectional control characters"},
        {"  ", "config.value.required", " must contain a non-whitespace character"},
        {std::string(display_name::MAX_CODE_POINTS + 1U, 'a'), "config.name.too_long", " must not exceed 80 Unicode code points"},
    };
    for (const auto& item : cases) {
        auto config = parse_test_config(R"({"lists":{"custom":{"domains":["example.org"]}}})");
        config.lists->at("custom").display_name = item.value;
        try {
            validate_config(config);
            FAIL("invalid display name accepted");
        } catch (const ConfigValidationError& error) {
            REQUIRE(error.issues().size() == 1);
            const auto& issue = error.issues()[0];
            CHECK(issue.path == "lists.custom.display_name");
            CHECK(issue.message == std::string("List display name") + item.suffix);
            CHECK(issue.code == item.code);
            if (issue.code == "config.name.too_long")
                CHECK(issue.params == std::map<std::string, std::string>{{"max", std::to_string(display_name::MAX_CODE_POINTS)}});
            else CHECK(issue.params.empty());
        }
    }
    auto config = parse_test_config(R"({"lists":{"custom":{"domains":["example.org"]}}})");
    std::string boundary;
    for (std::size_t index = 0; index < display_name::MAX_CODE_POINTS; ++index) boundary += "\xc3\xa9";
    config.lists->at("custom").display_name = boundary;
    CHECK_NOTHROW(validate_config(config));
    config.lists->at("custom").display_name = " surrounding whitespace remains allowed ";
    CHECK_NOTHROW(validate_config(config));
    config.lists->at("custom").display_name.reset();
    CHECK_NOTHROW(validate_config(config));
}

TEST_CASE("specialized validation metadata forwards DNS parser causes without classifying text") {
    struct Case { const char* address; const char* code; const char* reason; };
    const Case cases[] = {
        {"8.8.8.8:abc", "config.dns.port_number", "non-numeric port"},
        {"8.8.8.8:4294967296", "config.dns.port_number", "non-numeric port"},
        {"8.8.8.8:65536", "config.dns.port_range", "port out of range 1-65535"},
        {"[::1", "config.dns.closing_bracket", "missing closing ']'"},
        {"[::1]x", "config.dns.port_separator", "expected ':' after ']'"},
        {"not-an-ip", "config.dns.address", "not a valid IPv4 or IPv6 address"},
    };
    auto document = nlohmann::json::parse(R"({"dns":{"servers":[{"tag":"default_dns","address":"127.0.0.1"}]}})");
    for (const auto& item : cases) {
        document["dns"]["servers"][0]["address"] = item.address;
        const auto issues = validate_issues(document.dump());
        REQUIRE(issues.size() == 1);
        CHECK(issues[0].path == "dns.servers.default_dns.address");
        CHECK(issues[0].message == std::string("Invalid DNS server address: '") + item.address + "' (" + item.reason + ")");
        CHECK(issues[0].code == item.code);
        CHECK(issues[0].params.empty());
    }
    document["dns"]["servers"][0]["address"] = "";
    const auto required = validate_issues(document.dump());
    REQUIRE(required.size() == 1);
    CHECK(required[0].path == "dns.servers.default_dns.address");
    CHECK(required[0].message == "dns.servers[\"default_dns\"].address is required for type='static'");
    CHECK(required[0].code == "config.value.required");
    CHECK(required[0].params.empty());
    for (const char* address : {"8.8.8.8:1", "8.8.8.8:65535", "[2001:0DB8::1]:53", "::1"}) {
        document["dns"]["servers"][0]["address"] = address;
        CHECK_NOTHROW(parse_test_config(document.dump()));
    }
}

TEST_CASE("specialized validation metadata distinguishes DNS domains and plain IPv4 templates") {
    const auto issues = validate_issues(R"({
        "ui_preferences":{"plain_dns_templates":[{"name":"Plain","primary_ipv4":"bad","secondary_ipv4":"bad"}]},
        "dns":{"servers":[{"tag":"default_dns","address":"127.0.0.1","domains":["https://example.org"]}]}
    })");
    REQUIRE(issues.size() == 4);
    CHECK(issues[0].path == "ui_preferences.plain_dns_templates[0].primary_ipv4");
    CHECK(issues[0].message == "Plain DNS template primary_ipv4 must be a valid IPv4 address");
    CHECK(issues[0].code == "config.address.ipv4");
    CHECK(issues[1].path == "ui_preferences.plain_dns_templates[0].secondary_ipv4");
    CHECK(issues[1].message == "Plain DNS template secondary_ipv4 must be a valid IPv4 address");
    CHECK(issues[1].code == "config.address.ipv4");
    CHECK(issues[2].path == "ui_preferences.plain_dns_templates[0].secondary_ipv4");
    CHECK(issues[2].message == "Plain DNS template secondary_ipv4 must differ from primary_ipv4");
    CHECK(issues[2].code == "config.dns.different");
    CHECK(issues[3].path == "dns.servers.default_dns.domains.0");
    CHECK(issues[3].message == "Enter a DNS domain without a URL scheme, path or IP address");
    CHECK(issues[3].code == "config.dns.domain");
    for (const auto& issue : issues) CHECK(issue.params.empty());
    CHECK_NOTHROW(parse_test_config(R"({
        "ui_preferences":{"plain_dns_templates":[{"name":"Plain","primary_ipv4":"192.0.2.1","secondary_ipv4":"192.0.2.2"}]},
        "dns":{"servers":[{"tag":"default_dns","address":"127.0.0.1","domains":["*.Example.ORG."]}]}
    })"));
}

TEST_CASE("specialized validation metadata retains URL scheme and fallback reason distinctions") {
    auto document = failure_policy_config();
    document["outbounds"][3]["url"] = "ftp://example.org/check";
    const auto url_issues = validate_issues(document.dump());
    REQUIRE(url_issues.size() == 1);
    CHECK(url_issues[0].path == "outbounds.group_backup.url");
    CHECK(url_issues[0].message == "Urltest URL must use the http or https scheme");
    CHECK(url_issues[0].code == "config.url.scheme");
    CHECK(url_issues[0].params.empty());
    struct Case { const char* fallback; const char* mode; const char* code; const char* message; };
    const Case cases[] = {
        {"primary", "fallback", "config.route.fallback_different", "Fallback outbound must differ from the primary outbound"},
        {"drop", "fallback", "config.route.fallback_routable", "Fallback outbound must be an interface or urltest outbound"},
        {"backup", "inherit", "config.route.fallback_mode", "fallback_outbound is only used when failure_policy is fallback"},
        {"", "fallback", "config.value.required", "route.rules[0].fallback_outbound is required when failure_policy is fallback"},
    };
    for (const auto& item : cases) {
        document = failure_policy_config();
        document["route"]["rules"][0]["failure_policy"] = item.mode;
        document["route"]["rules"][0]["fallback_outbound"] = item.fallback;
        const auto errors = validate_issues(document.dump());
        REQUIRE(errors.size() == 1);
        CHECK(errors[0].path == "route.rules[0].fallback_outbound");
        CHECK(errors[0].message == item.message);
        CHECK(errors[0].code == item.code);
        CHECK(errors[0].params.empty());
    }
    document = failure_policy_config();
    document["outbounds"][3]["url"] = "HTTPS://example.org/check";
    document["route"]["rules"][0]["failure_policy"] = "fallback";
    document["route"]["rules"][0]["fallback_outbound"] = "backup";
    CHECK_NOTHROW(parse_test_config(document.dump()));
}

namespace {

void check_finished_metadata_wire(const std::vector<ConfigValidationIssue>& issues) {
    const auto wire = serialize_config_validation_issues(issues);
    REQUIRE(wire.size() == issues.size());
    for (std::size_t index = 0; index < issues.size(); ++index) {
        const auto& issue = issues[index];
        CAPTURE(issue.path);
        CAPTURE(issue.message);
        REQUIRE_FALSE(issue.code.empty());
        const auto dto = wire.at(index).get<api::ValidationErrorElement>();
        CHECK(dto.path == issue.path);
        CHECK(dto.message == issue.message);
        CHECK(dto.code == issue.code);
        if (issue.params.empty()) {
            CHECK_FALSE(dto.params.has_value());
            CHECK_FALSE(wire.at(index).contains("params"));
        } else {
            REQUIRE(dto.params.has_value());
            CHECK(*dto.params == issue.params);
        }
        const auto decoded = nlohmann::json(dto).get<api::ValidationErrorElement>();
        CHECK(decoded.path == dto.path);
        CHECK(decoded.message == dto.message);
        CHECK(decoded.code == dto.code);
        CHECK(decoded.params == dto.params);
    }
}

void check_finished_metadata_issue(
    const std::vector<ConfigValidationIssue>& issues,
    const std::string& path, const std::string& code,
    const std::string& message = {}) {
    CAPTURE(path);
    CAPTURE(code);
    const auto found = std::find_if(issues.begin(), issues.end(), [&](const auto& issue) {
        return issue.path == path && issue.code == code &&
               (message.empty() || issue.message == message);
    });
    REQUIRE(found != issues.end());
    check_finished_metadata_wire(issues);
}

std::vector<ConfigValidationIssue> finished_typed_issues(const Config& config) {
    try {
        validate_config(config);
        return {};
    } catch (const ConfigValidationError& error) {
        return error.issues();
    }
}

nlohmann::json finished_metadata_base() {
    return nlohmann::json::parse(R"({
        "lists":{"matched":{"domains":["example.test"]}},
        "outbounds":[
            {"tag":"wan","type":"interface","interface":"eth0"},
            {"tag":"other","type":"interface","interface":"eth1"},
            {"tag":"drop","type":"blackhole"},
            {"tag":"skip","type":"ignore"},
            {"tag":"group","type":"urltest","url":"https://example.test/",
             "outbound_groups":[{"outbounds":["wan"]}]}
        ],
        "dns":{"servers":[{"tag":"default_dns","address":"127.0.0.1"}],
               "fallback":["default_dns"],"system_resolver":{"address":"127.0.0.1"}}
    })");
}

} // namespace

TEST_CASE("finished metadata covers list provenance source cron and download constraints") {
    struct Case { const char* document; const char* path; const char* code; const char* message; };
    const Case cases[] = {
        {R"({"lists":{"empty":{}}})", "lists.empty", "config.list.source_required",
         "List 'empty' must have at least one of: url, domains, ip_cidrs, file"},
        {R"({"lists":{"bad":{"domains":["example.test"],"catalog_identity":"BAD"}}})",
         "lists.bad.catalog_identity", "config.catalog_identity.invalid",
         "lists.bad.catalog_identity must be a lowercase SHA-256 digest"},
        {R"({"list_refresh":{"fallback_detours":["missing"]}})",
         "list_refresh.fallback_detours", "config.download.primary_required",
         "list_refresh.fallback_detours requires an explicit primary detour"},
        {R"({"outbounds":[{"tag":"drop","type":"blackhole"}],"list_refresh":{"detour":"drop"}})",
         "list_refresh.detour", "config.outbound.routing_table_required",
         "list_refresh.detour: outbound 'drop' has no routable download table"},
        {R"({"lists":{"local":{"domains":["example.test"],"refresh_detour_mode":"inherit"}}})",
         "lists.local.refresh_detour_mode", "config.download.url_required",
         "lists.local.refresh_detour_mode is only valid for URL-backed lists"},
        {R"({"outbounds":[{"tag":"wan","type":"table","table":150}],"lists":{"remote":{
            "url":"http://example.test/list","refresh_detour_mode":"inherit","detour":"wan"}}})",
         "lists.remote.refresh_detour_mode", "config.download.inherit_conflict",
         "lists.remote cannot inherit the global download route while local detours are configured"},
        {R"({"lists":{"remote":{"url":"http://example.test/list","refresh_detour_mode":"override"}}})",
         "lists.remote.detour", "config.value.required",
         "lists.remote.detour is required when refresh_detour_mode is override"},
        {R"({"outbounds":[{"tag":"wan","type":"table","table":150}],
             "list_refresh":{"detour":"wan","fallback_detours":["wan","missing",""]}})",
         "list_refresh.fallback_detours[0]", "config.value.duplicate",
         "list_refresh.fallback_detours[0] repeats outbound tag 'wan'"},
        {R"({"daemon":{"reconnect_owned_flows_on_routing_change_lists":["missing"]}})",
         "daemon.reconnect_owned_flows_on_routing_change_lists[0]", "config.reference.list_missing",
         "daemon.reconnect_owned_flows_on_routing_change_lists[0] references unknown list 'missing'"},
    };
    for (const auto& item : cases) {
        const auto issues = validate_issues(item.document);
        check_finished_metadata_issue(issues, item.path, item.code, item.message);
    }
    const auto cron = validate_issues(R"({"lists_autoupdate":{"cron":"invalid"}})");
    REQUIRE(cron.size() == 1);
    check_finished_metadata_issue(cron, "lists_autoupdate.cron", "config.cron.invalid");
    CHECK(cron.front().message.find("lists_autoupdate.cron: ") == 0);

    auto document = finished_metadata_base();
    const std::string digest(64, 'a');
    document["lists"]["matched"]["catalog_identity"] = digest;
    document["lists"]["second"] = {{"domains", {"second.test"}}, {"catalog_identity", digest}};
    const auto duplicate = validate_issues(document.dump());
    REQUIRE(duplicate.size() == 1);
    check_finished_metadata_issue(duplicate, "lists.second.catalog_identity", "config.value.duplicate",
        "lists.second.catalog_identity duplicates catalogue provenance first declared at lists.matched.catalog_identity");
    document["lists"]["second"]["catalog_identity"] = std::string(64, 'b');
    document["lists"]["remote"] = {{"url", "http://192.0.2.1/list"}, {"detour", "group"}};
    CHECK_NOTHROW(parse_test_config(document.dump()));

    document["list_refresh"] = {{"detour", "wan"}, {"fallback_detours", {"other", "group", "wan", "other"}}};
    const auto limited = validate_issues(document.dump());
    check_finished_metadata_issue(limited, "list_refresh.fallback_detours", "config.value.too_many");
    const auto* limit = find_issue(limited, "list_refresh.fallback_detours");
    REQUIRE(limit != nullptr);
    CHECK(limit->params == std::map<std::string, std::string>{{"max", "3"}});
}

TEST_CASE("finished metadata covers interface urltest and rule target constraints") {
    struct Case { const char* document; const char* path; const char* code; const char* message; };
    const Case cases[] = {
        {R"({"outbounds":[{"tag":"wan","type":"interface"}]})", "outbounds.wan.interface", "config.value.required",
         "Interface outbound 'wan' requires a non-empty interface name"},
        {R"({"outbounds":[{"tag":"wan","type":"interface","interface":"bad/name"}]})",
         "outbounds.wan.interface", "config.interface.invalid", ""},
        {R"({"outbounds":[{"tag":"wan","type":"interface","interface":"eth0","gateway":"bad","gateway6":"bad"}]})",
         "outbounds.wan.gateway6", "config.address.ipv6", "Interface outbound 'wan' gateway6 must be a valid IPv6 address"},
        {R"({"outbounds":[{"tag":"wan","type":"interface","interface":"eth0","conntrack_on_switch":"delete"}]})",
         "outbounds.wan.conntrack_on_switch", "config.conntrack.urltest_only", "conntrack_on_switch is only valid for urltest outbounds"},
        {R"({"outbounds":[{"tag":"group","type":"urltest"}]})", "outbounds.group.url", "config.value.required",
         "Urltest outbound 'group' requires a URL"},
        {R"({"outbounds":[{"tag":"group","type":"urltest","url":"http://example.test"}]})",
         "outbounds.group.outbound_groups", "config.value.non_empty_array", "Urltest outbound 'group' 'outbound_groups' array must not be empty"},
        {R"({"outbounds":[{"tag":"group","type":"urltest","url":"http://example.test","outbound_groups":[{"outbounds":[]}]}]})",
         "outbounds.group.outbound_groups[0].outbounds", "config.value.non_empty_array", "Urltest outbound 'group' outbound_group has empty 'outbounds' array"},
        {R"({"outbounds":[{"tag":"group","type":"urltest","url":"http://example.test","outbound_groups":[{"outbounds":["group"]}]}]})",
         "outbounds.group.outbound_groups[0].outbounds[0]", "config.urltest.cycle", "Urltest outbound 'group' creates a cyclic reference to urltest outbound 'group'"},
        {R"({"outbounds":[{"tag":"skip","type":"ignore"},{"tag":"group","type":"urltest","url":"http://example.test","outbound_groups":[{"outbounds":["skip"]}]}]})",
         "outbounds.group.outbound_groups[0].outbounds[0]", "config.urltest.child_type",
         "Urltest outbound 'group' references outbound 'skip' which is not an interface, table, blackhole, or urltest outbound"},
    };
    for (const auto& item : cases) {
        check_finished_metadata_issue(validate_issues(item.document), item.path, item.code, item.message);
    }
    auto document = finished_metadata_base();
    document["route"]["rules"] = {{{"list", {"matched"}}, {"outbound", " wan "}, {"failure_policy", "block"}}};
    check_finished_metadata_issue(validate_issues(document.dump()), "route.rules[0].outbound", "config.route.primary_exact",
        "A rule failure policy requires an exact configured primary outbound tag");
    document["route"]["rules"][0]["outbound"] = "drop";
    check_finished_metadata_issue(validate_issues(document.dump()), "route.rules[0].failure_policy", "config.route.primary_routable",
        "A rule failure policy requires an interface or urltest primary outbound");
    document["route"]["rules"][0]["outbound"] = "group";
    CHECK_NOTHROW(parse_test_config(document.dump()));
    document["route"]["rules"][0]["failure_policy"] = "fallback";
    document["route"]["rules"][0]["fallback_outbound"] = "absent";
    check_finished_metadata_issue(validate_issues(document.dump()), "route.rules[0].fallback_outbound", "config.reference.outbound_missing",
        "route.rules[0] references unknown fallback outbound tag 'absent'");
}

TEST_CASE("finished metadata covers raw internal VPN shapes without changing field order") {
    struct Case { const char* document; const char* path; const char* code; const char* message; };
    const Case cases[] = {
        {R"({"route":{"internal_vpn_servers":false}})", "route.internal_vpn_servers", "config.value.object_array",
         "route.internal_vpn_servers must be an array of objects"},
        {R"({"route":{"internal_vpn_servers":[false]}})", "route.internal_vpn_servers[0]", "config.value.object",
         "route.internal_vpn_servers[0] must be an object"},
        {R"({"route":{"internal_vpn_servers":[{}]}})", "route.internal_vpn_servers[0].interface", "config.value.string",
         "route.internal_vpn_servers[0].interface must be a string"},
        {R"({"route":{"internal_vpn_servers":[{"interface":"wg0","ndms_id":7,"process_clients":true}]}})",
         "route.internal_vpn_servers[0].ndms_id", "config.value.string", "route.internal_vpn_servers[0].ndms_id must be a string"},
        {R"({"route":{"internal_vpn_services":false}})", "route.internal_vpn_services", "config.value.object_array",
         "route.internal_vpn_services must be an array of objects"},
        {R"({"route":{"internal_vpn_services":[false]}})", "route.internal_vpn_services[0]", "config.value.object",
         "route.internal_vpn_services[0] must be an object"},
        {R"({"route":{"internal_vpn_services":[{}]}})", "route.internal_vpn_services[0].service_id", "config.value.string",
         "route.internal_vpn_services[0].service_id must be a string"},
        {R"({"route":{"internal_vpn_services":[{"service_id":"bad/name","process_clients":false}]}})",
         "route.internal_vpn_services[0].service_id", "config.vpn.service_id",
         "route.internal_vpn_services[0].service_id must be 1-128 ASCII letters, digits, dot, underscore, colon or hyphen"},
    };
    for (const auto& item : cases) {
        check_finished_metadata_issue(parse_issues(item.document), item.path, item.code, item.message);
    }
    const auto ordered = parse_issues(R"({"route":{"internal_vpn_servers":[{}],"internal_vpn_services":[{}]}})");
    REQUIRE(ordered.size() == 4);
    CHECK(ordered[0].path == "route.internal_vpn_servers[0].interface");
    CHECK(ordered[0].code == "config.value.string");
    CHECK(ordered[1].path == "route.internal_vpn_servers[0].process_clients");
    CHECK(ordered[1].code == "config.value.boolean");
    CHECK(ordered[2].path == "route.internal_vpn_services[0].service_id");
    CHECK(ordered[2].code == "config.value.string");
    CHECK(ordered[3].path == "route.internal_vpn_services[0].process_clients");
    CHECK(ordered[3].code == "config.value.boolean");
    check_finished_metadata_wire(ordered);
}

TEST_CASE("finished metadata keeps raw and typed internal VPN validation equivalent") {
    auto document = finished_metadata_base();
    document["route"]["internal_vpn_servers"] = {
        {{"interface", "wg0"}, {"ndms_id", "Native0"}, {"process_clients", true}}
    };
    document["route"]["internal_vpn_services"] = {
        {{"service_id", "vpn:server-0"}, {"process_clients", true}}
    };
    const auto valid = parse_test_config(document.dump());
    struct Case { std::string value; const char* code; const char* suffix; };
    const Case cases[] = {
        {" Native0 ", "config.identifier.whitespace", " must be a non-blank identifier without surrounding whitespace"},
        {std::string(129, 'n'), "config.name.too_long", " must not exceed 128 Unicode code points"},
        {std::string("Native\x01", 7), "config.name.controls", " must not contain control characters"},
        {std::string("\xC3\x28", 2), "config.name.encoding", " must be valid UTF-8"},
    };
    for (const auto& item : cases) {
        auto candidate = valid;
        candidate.route->internal_vpn_servers->front().ndms_id = item.value;
        const auto typed = finished_typed_issues(candidate);
        REQUIRE(typed.size() == 1);
        check_finished_metadata_issue(typed, "route.internal_vpn_servers[0].ndms_id", item.code,
            std::string("route.internal_vpn_servers[0].ndms_id") + item.suffix);
        if (std::string(item.code) == "config.name.too_long") {
            CHECK(typed.front().params == std::map<std::string, std::string>{{"max", "128"}});
        }
        if (std::string(item.code) != "config.name.encoding") {
            const auto raw = parse_issues(nlohmann::json(candidate).dump());
            REQUIRE(raw.size() == typed.size());
            CHECK(raw.front().path == typed.front().path);
            CHECK(raw.front().message == typed.front().message);
            CHECK(raw.front().code == typed.front().code);
            CHECK(raw.front().params == typed.front().params);
        }
    }
    auto duplicate = valid;
    duplicate.route->internal_vpn_servers->push_back(duplicate.route->internal_vpn_servers->front());
    duplicate.route->internal_vpn_services->push_back(duplicate.route->internal_vpn_services->front());
    const auto typed_duplicates = finished_typed_issues(duplicate);
    const auto raw_duplicates = parse_issues(nlohmann::json(duplicate).dump());
    REQUIRE(typed_duplicates.size() == 3);
    REQUIRE(raw_duplicates.size() == typed_duplicates.size());
    for (std::size_t index = 0; index < typed_duplicates.size(); ++index) {
        CHECK(typed_duplicates[index].code == "config.value.duplicate");
        CHECK(raw_duplicates[index].path == typed_duplicates[index].path);
        CHECK(raw_duplicates[index].message == typed_duplicates[index].message);
        CHECK(raw_duplicates[index].code == typed_duplicates[index].code);
    }
    check_finished_metadata_wire(typed_duplicates);

    auto boundaries = valid;
    boundaries.route->internal_vpn_servers->clear();
    boundaries.route->internal_vpn_services->clear();
    for (std::size_t index = 0; index < 128; ++index) {
        auto server = valid.route->internal_vpn_servers->front();
        server.interface = "v" + std::to_string(index);
        server.ndms_id = "Native" + std::to_string(index);
        boundaries.route->internal_vpn_servers->push_back(server);
    }
    for (std::size_t index = 0; index < 32; ++index) {
        auto service = valid.route->internal_vpn_services->front();
        service.service_id = "vpn:" + std::to_string(index);
        boundaries.route->internal_vpn_services->push_back(service);
    }
    CHECK_NOTHROW(validate_config(boundaries));
    CHECK_NOTHROW(parse_test_config(nlohmann::json(boundaries).dump()));
    auto extra_server = valid.route->internal_vpn_servers->front();
    extra_server.interface = "v128";
    extra_server.ndms_id = "Native128";
    boundaries.route->internal_vpn_servers->push_back(extra_server);
    auto extra_service = valid.route->internal_vpn_services->front();
    extra_service.service_id = "vpn:32";
    boundaries.route->internal_vpn_services->push_back(extra_service);
    const auto limited = finished_typed_issues(boundaries);
    REQUIRE(limited.size() == 2);
    CHECK(limited[0].code == "config.value.too_many");
    CHECK(limited[0].params == std::map<std::string, std::string>{{"max", "128"}});
    CHECK(limited[1].code == "config.value.too_many");
    CHECK(limited[1].params == std::map<std::string, std::string>{{"max", "32"}});
    check_finished_metadata_wire(limited);
    boundaries = valid;
    boundaries.route->internal_vpn_services->front().service_id = "bad/name";
    check_finished_metadata_issue(finished_typed_issues(boundaries), "route.internal_vpn_services[0].service_id", "config.vpn.service_id");
}

TEST_CASE("finished metadata preserves fwmark table multiport and migration diagnostics") {
    struct Case { const char* document; const char* path; const char* code; const char* message; };
    const Case cases[] = {
        {R"({"fwmark":{"start":"invalid"}})", "fwmark.start", "config.fwmark.start_invalid",
         "fwmark.start must be a hexadecimal string with 0x prefix"},
        {R"({"fwmark":{"mask":"0x00000000"}})", "fwmark.mask", "config.fwmark.mask_invalid", "fwmark.mask must not be zero"},
        {R"({"fwmark":{"start":"0x00010000","mask":"0x0000F000"}})", "outbounds", "config.fwmark.allocation",
         "fwmark.start must select a non-zero value within fwmark.mask"},
        {R"({"iproute":{"table_start":255}})", "iproute.table_start", "config.iproute.reserved",
         "iproute.table_start 255 is reserved. Use a different value (e.g. 150)."},
    };
    for (const auto& item : cases) {
        const auto issues = validate_issues(item.document);
        REQUIRE(issues.size() == 1);
        check_finished_metadata_issue(issues, item.path, item.code, item.message);
    }
    auto document = finished_metadata_base();
    document["daemon"]["firewall_backend"] = "iptables";
    document["route"]["rules"] = {{{"src_port", "444,555"}, {"dest_port", "443"}, {"outbound", "wan"}}};
    const auto multiport = validate_issues(document.dump());
    REQUIRE(multiport.size() == 1);
    CHECK(multiport.front().code == "config.route.multiport_combo");
    CHECK(multiport.front().message == "When you use port lists (e.g. 444,555) you can't combine src_port and dest_port condition. This is a xt_multiport module limitation. Consider using nftables firewall backend or create multiple rules.");
    check_finished_metadata_wire(multiport);
    document["daemon"]["firewall_backend"] = "nftables";
    CHECK_NOTHROW(parse_test_config(document.dump()));
    auto old = parse_test_config(finished_metadata_base().dump());
    old.schema_version = 1;
    const auto migration = finished_typed_issues(old);
    REQUIRE(migration.size() == 1);
    check_finished_metadata_issue(migration, "schema_version", "config.schema_version.migration_required",
        "Configuration must be migrated to schema version 2 before validation");
    CHECK(migration.front().params == std::map<std::string, std::string>{{"supported", "2"}});
}

TEST_CASE("finished metadata covers DNS references duplicates resolver and probe errors") {
    auto document = finished_metadata_base();
    document["dns"]["servers"].push_back({{"tag", "default_dns"}, {"address", "192.0.2.53"}});
    const auto tag = validate_issues(document.dump());
    REQUIRE(tag.size() == 1);
    check_finished_metadata_issue(tag, "dns.servers.default_dns.tag", "config.value.duplicate",
        "Duplicate DNS server tag \"default_dns\"");
    document["dns"]["servers"][1] = {{"tag", "second_dns"}, {"address", "127.0.0.1:53"}};
    const auto definition = validate_issues(document.dump());
    REQUIRE(definition.size() == 1);
    check_finished_metadata_issue(definition, "dns.servers.second_dns", "config.value.duplicate",
        "DNS server \"second_dns\" duplicates an existing DNS server definition (same type/address)");

    document = finished_metadata_base();
    document["dns"]["servers"][0]["detour"] = "drop";
    check_finished_metadata_issue(validate_issues(document.dump()), "dns.servers.default_dns.detour", "config.outbound.routing_table_required",
        "dns.servers[\"default_dns\"].detour: outbound \"drop\" has no routing table");
    document["dns"]["servers"][0]["detour"] = "absent";
    check_finished_metadata_issue(validate_issues(document.dump()), "dns.servers.default_dns.detour", "config.reference.outbound_missing",
        "dns.servers[\"default_dns\"].detour: unknown outbound tag \"absent\"");
    document["dns"]["servers"][0]["detour"] = "group";
    CHECK_NOTHROW(parse_test_config(document.dump()));
    document["dns"]["fallback"] = {"", "default_dns", "default_dns", "absent"};
    const auto fallback = validate_issues(document.dump());
    REQUIRE(fallback.size() == 3);
    CHECK(fallback[0].path == "dns.fallback.0");
    CHECK(fallback[0].code == "config.value.required");
    CHECK(fallback[0].message == "dns.fallback[0] must not be empty");
    CHECK(fallback[1].path == "dns.fallback.2");
    CHECK(fallback[1].code == "config.value.duplicate");
    CHECK(fallback[1].message == "dns.fallback[2] duplicates DNS server tag \"default_dns\"");
    CHECK(fallback[2].path == "dns.fallback.3");
    CHECK(fallback[2].code == "config.reference.dns_server_missing");
    CHECK(fallback[2].message == "dns.fallback[3] references unknown DNS server tag \"absent\"");
    check_finished_metadata_wire(fallback);

    document = finished_metadata_base();
    document["dns"]["rules"] = {{{"list", nlohmann::json::array()}, {"server", "default_dns"}}};
    check_finished_metadata_issue(validate_issues(document.dump()), "dns.rules[0].list", "config.value.non_empty_array",
        "dns.rules[0].list must include at least one list name");
    document = finished_metadata_base();
    document["dns"]["dns_test_server"] = {{"listen", "[::1]:53"}};
    check_finished_metadata_issue(validate_issues(document.dump()), "dns.dns_test_server", "config.dns.probe_invalid",
        "dns.dns_test_server: DNS test server listen address must be IPv4: [::1]:53");
    document["dns"]["dns_test_server"] = {{"listen", "127.0.0.88:53"}, {"answer_ipv4", "192.0.2.53"}};
    CHECK_NOTHROW(parse_test_config(document.dump()));

    auto missing = parse_test_config(finished_metadata_base().dump());
    missing.dns->system_resolver->address.clear();
    check_finished_metadata_issue(finished_typed_issues(missing), "dns.system_resolver.address", "config.value.required",
        "dns.system_resolver.address must not be empty");
    missing.dns->system_resolver.reset();
    check_finished_metadata_issue(finished_typed_issues(missing), "dns.system_resolver", "config.value.required",
        "dns.system_resolver must be present");
    missing.dns.reset();
    check_finished_metadata_issue(finished_typed_issues(missing), "dns.system_resolver", "config.value.required",
        "dns.system_resolver must be present");
}

TEST_CASE("finished metadata preserves DNS capability and typed enum branches") {
    SystemInfoTestGuard guard;
    SystemInfo info;
    info.os_type = "keenetic";
    info.os_version = "2.16.D.12.0-12";
    info.build_variant = "keenetic";
    set_system_info_for_tests(info);
    auto config = parse_test_config(finished_metadata_base().dump());
    config.dns->servers->front().type = api::DnsServerType::KEENETIC;
    config.dns->servers->front().address.reset();
    const auto unsupported = finished_typed_issues(config);
    check_finished_metadata_issue(unsupported, "dns.servers.default_dns.type", "config.dns.keenetic_version",
        "dns.servers[\"default_dns\"].type='keenetic' requires KeeneticOS 3.x or newer; detected 2.16.D.12.0-12");
#ifndef USE_KEENETIC_API
    check_finished_metadata_issue(unsupported, "dns.servers.default_dns.type", "config.dns.keenetic_build",
        "dns.servers[\"default_dns\"].type='keenetic' requires build with USE_KEENETIC_API=ON");
#endif
    info.os_version = "4.0.0";
    set_system_info_for_tests(info);
#ifdef USE_KEENETIC_API
    CHECK_NOTHROW(validate_config(config));
#endif
    config.dns->servers->front().address = "192.0.2.53";
    check_finished_metadata_issue(finished_typed_issues(config), "dns.servers.default_dns.address", "config.dns.keenetic_address",
        "dns.servers[\"default_dns\"].address must not be set for type='keenetic' (resolved via RCI)");
    config.dns->servers->front().address.reset();
    auto second = config.dns->servers->front();
    second.tag = "second_dns";
    config.dns->servers->push_back(second);
    check_finished_metadata_issue(finished_typed_issues(config), "dns.servers", "config.dns.keenetic_limit",
        "at most one dns.servers entry may use type='keenetic'");
    config.dns->servers->resize(1);
    config.dns->servers->front().type = static_cast<api::DnsServerType>(999);
    check_finished_metadata_issue(finished_typed_issues(config), "dns.servers.default_dns.type", "config.dns.type",
        "dns.servers[\"default_dns\"].type must be one of: static, keenetic");
}

TEST_CASE("finished metadata keeps conntrack ownership diagnostics ordered and accepted modes unchanged") {
    auto document = finished_metadata_base();
    auto nested = document["outbounds"][4];
    nested["tag"] = "nested";
    document["outbounds"].push_back(nested);
    document["outbounds"][4]["outbound_groups"][0]["outbounds"] = {"nested"};
    document["outbounds"][4]["conntrack_on_switch"] = "delete_on_failure";
    const auto nested_errors = validate_issues(document.dump());
    REQUIRE(nested_errors.size() == 1);
    check_finished_metadata_issue(nested_errors, "outbounds.group.conntrack_on_switch", "config.conntrack.nested",
        "conntrack_on_switch='delete_on_failure' does not support nested urltest child 'nested'; use 'preserve' for nested selectors");
    document["outbounds"][4]["conntrack_on_switch"] = "preserve";
    CHECK_NOTHROW(parse_test_config(document.dump()));

    document = finished_metadata_base();
    auto shared = document["outbounds"][4];
    shared["tag"] = "shared";
    document["outbounds"].push_back(shared);
    document["outbounds"][4]["conntrack_on_switch"] = "delete";
    const auto shared_errors = validate_issues(document.dump());
    REQUIRE(shared_errors.size() == 1);
    check_finished_metadata_issue(shared_errors, "outbounds.group.conntrack_on_switch", "config.conntrack.shared_child",
        "conntrack_on_switch='delete' requires exclusive child marks, but outbound 'wan' is shared by multiple urltest selectors");
    document["outbounds"][4]["conntrack_on_switch"] = "delete_on_failure";
    CHECK_NOTHROW(parse_test_config(document.dump()));

    document = finished_metadata_base();
    document["outbounds"][4]["conntrack_on_switch"] = "delete";
    document["route"]["rules"] = {{{"list", {"matched"}}, {"outbound", "wan"}}};
    document["dns"]["servers"][0]["detour"] = "wan";
    document["lists"]["remote"] = {{"url", "https://example.test/list"}, {"detour", "wan"}};
    const auto direct = validate_issues(document.dump());
    REQUIRE(direct.size() == 3);
    CHECK(direct[0].code == "config.conntrack.route_child");
    CHECK(direct[0].message == "conntrack_on_switch='delete' cannot use child 'wan' because a routing rule also references it directly");
    CHECK(direct[1].code == "config.conntrack.dns_child");
    CHECK(direct[1].message == "conntrack_on_switch='delete' cannot use child 'wan' because a DNS server also references it directly");
    CHECK(direct[2].code == "config.conntrack.list_child");
    CHECK(direct[2].message == "conntrack_on_switch='delete' cannot use child 'wan' because a URL list download also references it directly");
    for (const auto& issue : direct) {
        CHECK(issue.path == "outbounds.group.conntrack_on_switch");
        CHECK(issue.params.empty());
    }
    check_finished_metadata_wire(direct);
    document["outbounds"][4]["conntrack_on_switch"] = "delete_on_failure";
    CHECK_NOTHROW(parse_test_config(document.dump()));
    document["outbounds"][4]["conntrack_on_switch"] = "preserve";
    CHECK_NOTHROW(parse_test_config(document.dump()));
}
