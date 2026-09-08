#include <doctest/doctest.h>

#include "../src/config/config.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

using CompleteMetadataParams = std::map<std::string, std::string>;

Config complete_metadata_base() {
    auto config = parse_config(R"({
        "outbounds":[
            {"tag":"wan","type":"interface","interface":"eth0"},
            {"tag":"backup","type":"interface","interface":"eth1"}],
        "lists":{"remote":{"url":"https://example.test/list.txt"}},
        "route":{"rules":[{"outbound":"wan","src_addr":"192.0.2.0/24"}]}
    })");
    if (!config.dns) config.dns = DnsConfig{};
    DnsServer server;
    server.tag = "default_dns";
    server.address = "127.0.0.1";
    config.dns->servers = std::vector<DnsServer>{server};
    config.dns->fallback = std::vector<std::string>{"default_dns"};
    api::SystemResolver resolver;
    resolver.address = "127.0.0.1";
    config.dns->system_resolver = resolver;
    validate_config(config);
    return config;
}

std::vector<ConfigValidationIssue> complete_metadata_parse_issues(
    const nlohmann::json& document) {
    try {
        (void)parse_config(document.dump());
    } catch (const ConfigValidationError& error) {
        return error.issues();
    }
    return {};
}

std::vector<ConfigValidationIssue> complete_metadata_typed_issues(
    const Config& config) {
    try {
        validate_config(config);
    } catch (const ConfigValidationError& error) {
        return error.issues();
    }
    return {};
}

void complete_metadata_expect(
    const std::vector<ConfigValidationIssue>& issues,
    const std::string& path,
    const std::string& code,
    const CompleteMetadataParams& params = {},
    const std::string& message = {}) {
    CAPTURE(path);
    CAPTURE(code);
    for (const auto& issue : issues) CHECK_FALSE(issue.code.empty());
    const auto found = std::find_if(issues.begin(), issues.end(), [&](const auto& issue) {
        return issue.path == path && issue.code == code;
    });
    REQUIRE(found != issues.end());
    CHECK(found->params == params);
    if (!message.empty()) CHECK(found->message == message);
}

std::string complete_metadata_unicode_name(std::size_t count) {
    std::string value;
    for (std::size_t index = 0; index < count; ++index) value += "\xD0\x96";
    return value;
}

PlainDnsTemplate complete_metadata_template(std::string name, std::string address) {
    PlainDnsTemplate value;
    value.name = std::move(name);
    value.primary_ipv4 = std::move(address);
    return value;
}

} // namespace

TEST_CASE("complete config metadata codes raw early-field failures") {
    struct Example {
        const char* pointer;
        nlohmann::json value;
        const char* path;
        const char* code;
        CompleteMetadataParams params{};
        std::string message{};
    };
    const std::vector<Example> examples{
        {"/daemon/meta_udp443_policy", "other", "daemon.meta_udp443_policy",
         "config.daemon.meta_udp443_policy", {},
         "daemon.meta_udp443_policy must be one of: balanced, messages_first"},
        {"/daemon/meta_udp443_policy", 1, "daemon.meta_udp443_policy", "config.value.string"},
        {"/daemon/ppe_deoffload_mode", "other", "daemon.ppe_deoffload_mode",
         "config.daemon.ppe_deoffload_mode", {}, "daemon.ppe_deoffload_mode must be one of: off, auto"},
        {"/daemon/ppe_deoffload_mode", false, "daemon.ppe_deoffload_mode", "config.value.string"},
        {"/route/rules/0/failure_policy", "other", "route.rules[0].failure_policy",
         "config.route.failure_policy"},
        {"/route/rules/0/failure_policy", 7, "route.rules[0].failure_policy", "config.value.string"},
        {"/route/rules/0/fallback_outbound", false, "route.rules[0].fallback_outbound", "config.value.string"},
        {"/lists/remote/refresh_detour_mode", "other", "lists.remote.refresh_detour_mode",
         "config.list.refresh_detour_mode"},
        {"/lists/remote/refresh_detour_mode", 1, "lists.remote.refresh_detour_mode", "config.value.string"},
        {"/fwmark/start", 65536, "fwmark.start", "config.value.hex", {},
         "fwmark.start must be a string in hex format (e.g. 0x00010000)"},
        {"/fwmark/mask", true, "fwmark.mask", "config.value.hex"},
        {"/daemon/reconnect_owned_flows_on_routing_change_lists", "remote",
         "daemon.reconnect_owned_flows_on_routing_change_lists", "config.value.string_array"},
        {"/daemon/reconnect_owned_flows_on_routing_change_lists", nlohmann::json::array({"remote", 7}),
         "daemon.reconnect_owned_flows_on_routing_change_lists[1]", "config.value.string_array"},
        {"/route/inbound_interfaces", "br0", "route.inbound_interfaces", "config.value.string_array"},
        {"/route/inbound_interfaces", nlohmann::json::array({7}),
         "route.inbound_interfaces[0]", "config.value.string"},
        {"/route/inbound_interfaces", nlohmann::json::array({" \t"}),
         "route.inbound_interfaces[0]", "config.value.required", {},
         "route.inbound_interfaces[0] must not be blank"},
        {"/route/inbound_interfaces", nlohmann::json::array({"bad/name"}),
         "route.inbound_interfaces[0]", "config.interface.invalid"},
        {"/route/inbound_interfaces", nlohmann::json::array({"br0", "br0"}),
         "route.inbound_interfaces[1]", "config.value.duplicate", {},
         "route.inbound_interfaces[1] duplicates interface 'br0'"},
        {"/list_refresh", false, "list_refresh", "config.value.object"},
        {"/lists/remote/shrink_policy", nlohmann::json::array(),
         "lists.remote.shrink_policy", "config.value.object"},
        {"/lists/remote/shrink_policy", {{"min_previous_entries", "12"}},
         "lists.remote.shrink_policy.min_previous_entries", "config.value.integer"},
        {"/lists/remote/shrink_policy",
         {{"min_previous_entries", std::numeric_limits<std::uint64_t>::max()}},
         "lists.remote.shrink_policy.min_previous_entries", "config.value.integer_range",
         {{"min", "-9223372036854775808"}, {"max", "9223372036854775807"}},
         "lists.remote.shrink_policy.min_previous_entries must be a signed 64-bit integer"},
        {"/lists/remote/shrink_policy", {{"min_retained_fraction", "0.5"}},
         "lists.remote.shrink_policy.min_retained_fraction", "config.value.number"},
    };
    const nlohmann::json base = complete_metadata_base();
    for (const auto& example : examples) {
        CAPTURE(example.pointer);
        auto document = base;
        document[nlohmann::json::json_pointer(example.pointer)] = example.value;
        complete_metadata_expect(complete_metadata_parse_issues(document),
            example.path, example.code, example.params, example.message);
    }
}

TEST_CASE("complete config metadata preserves raw failure order and messages") {
    nlohmann::json document = complete_metadata_base();
    document["daemon"]["meta_udp443_policy"] = "other";
    document["daemon"]["ppe_deoffload_mode"] = "other";
    const auto issues = complete_metadata_parse_issues(document);
    REQUIRE(issues.size() == 2U);
    CHECK(issues[0].path == "daemon.meta_udp443_policy");
    CHECK(issues[0].message == "daemon.meta_udp443_policy must be one of: balanced, messages_first");
    CHECK(issues[1].path == "daemon.ppe_deoffload_mode");
    CHECK(issues[1].message == "daemon.ppe_deoffload_mode must be one of: off, auto");
}

TEST_CASE("complete config metadata accepts existing early-field values") {
    const nlohmann::json base = complete_metadata_base();
    for (const auto& policy : {"balanced", "messages_first"}) {
        for (const auto& mode : {"off", "auto"}) {
            auto document = base;
            document["daemon"]["meta_udp443_policy"] = policy;
            document["daemon"]["ppe_deoffload_mode"] = mode;
            document["fwmark"]["start"] = "0x00010000";
            document["route"]["inbound_interfaces"] = {"br0", "eth0"};
            document["daemon"]["reconnect_owned_flows_on_routing_change_lists"] = {"remote"};
            document["lists"]["remote"]["shrink_policy"] = {
                {"min_previous_entries", std::numeric_limits<std::int64_t>::max()},
                {"min_retained_fraction", 0.5}};
            CHECK_NOTHROW(validate_config(parse_config(document.dump())));
        }
    }
    for (const auto& policy : {"inherit", "block", "fallback"}) {
        auto document = base;
        auto& rule = document["route"]["rules"][0];
        rule["failure_policy"] = policy;
        if (std::string(policy) == "fallback") rule["fallback_outbound"] = "backup";
        CHECK_NOTHROW(validate_config(parse_config(document.dump())));
    }
    for (const auto& mode : {"inherit", "override"}) {
        auto document = base;
        document["lists"]["remote"]["refresh_detour_mode"] = mode;
        if (std::string(mode) == "override") document["lists"]["remote"]["detour"] = "wan";
        CHECK_NOTHROW(validate_config(parse_config(document.dump())));
    }
    auto document = base;
    document["list_refresh"] = nullptr;
    document["lists"]["remote"]["shrink_policy"] = nullptr;
    document["daemon"]["meta_udp443_policy"] = nullptr;
    document["daemon"]["ppe_deoffload_mode"] = nullptr;
    CHECK_NOTHROW(validate_config(parse_config(document.dump())));
}

TEST_CASE("complete config metadata codes typed hidden native identifiers") {
    struct Example {
        std::vector<std::string> values;
        std::size_t index;
        const char* code;
        CompleteMetadataParams params{};
    };
    const std::vector<Example> examples{
        {{std::string("\xC3\x28", 2)}, 0, "config.name.encoding"},
        {{""}, 0, "config.identifier.whitespace"},
        {{" Wireguard0"}, 0, "config.identifier.whitespace"},
        {{complete_metadata_unicode_name(129)}, 0, "config.name.too_long", {{"max", "128"}}},
        {{"Wireguard\n0"}, 0, "config.name.controls"},
        {{"Wireguard0", "Wireguard0"}, 1, "config.value.duplicate"},
    };
    for (const auto& example : examples) {
        auto config = complete_metadata_base();
        config.ui_preferences = UiPreferencesConfig{};
        config.ui_preferences->hidden_native_interface_ids = example.values;
        complete_metadata_expect(complete_metadata_typed_issues(config),
            "ui_preferences.hidden_native_interface_ids[" + std::to_string(example.index) + "]",
            example.code, example.params);
    }
}

TEST_CASE("complete config metadata keeps hidden identifier limits inclusive") {
    auto config = complete_metadata_base();
    config.ui_preferences = UiPreferencesConfig{};
    std::vector<std::string> ids{complete_metadata_unicode_name(128)};
    for (std::size_t index = 1; index < 128; ++index) ids.push_back("Wireguard" + std::to_string(index));
    config.ui_preferences->hidden_native_interface_ids = ids;
    CHECK_NOTHROW(validate_config(config));
    config.ui_preferences->hidden_native_interface_ids->push_back("OneMore");
    complete_metadata_expect(complete_metadata_typed_issues(config),
        "ui_preferences.hidden_native_interface_ids", "config.value.too_many", {{"max", "128"}},
        "ui_preferences.hidden_native_interface_ids must not contain more than 128 entries");
}

TEST_CASE("complete config metadata codes typed plain DNS names") {
    struct Example {
        std::string name;
        const char* code;
        CompleteMetadataParams params{};
    };
    const std::vector<Example> examples{
        {std::string("\xC3\x28", 2), "config.name.encoding"},
        {"", "config.value.required"},
        {" Office DNS", "config.identifier.whitespace"},
        {"Office\nDNS", "config.name.controls"},
        {complete_metadata_unicode_name(81), "config.name.too_long", {{"max", "80"}}},
    };
    for (const auto& example : examples) {
        auto config = complete_metadata_base();
        config.ui_preferences = UiPreferencesConfig{};
        config.ui_preferences->plain_dns_templates = std::vector<PlainDnsTemplate>{
            complete_metadata_template(example.name, "192.0.2.53")};
        complete_metadata_expect(complete_metadata_typed_issues(config),
            "ui_preferences.plain_dns_templates[0].name", example.code, example.params);
    }
}

TEST_CASE("complete config metadata distinguishes duplicate DNS names and definitions") {
    auto config = complete_metadata_base();
    config.ui_preferences = UiPreferencesConfig{};
    SUBCASE("names compare without ASCII case") {
        config.ui_preferences->plain_dns_templates = std::vector<PlainDnsTemplate>{
            complete_metadata_template("Office DNS", "192.0.2.53"),
            complete_metadata_template("office dns", "192.0.2.54")};
        complete_metadata_expect(complete_metadata_typed_issues(config),
            "ui_preferences.plain_dns_templates[1].name", "config.value.duplicate", {},
            "Plain DNS template name 'office dns' is duplicated");
    }
    SUBCASE("same endpoints with different names remain duplicates") {
        config.ui_preferences->plain_dns_templates = std::vector<PlainDnsTemplate>{
            complete_metadata_template("Office DNS", "192.0.2.53"),
            complete_metadata_template("Other DNS", "192.0.2.53")};
        complete_metadata_expect(complete_metadata_typed_issues(config),
            "ui_preferences.plain_dns_templates[1]", "config.dns.template_duplicate", {},
            "Plain DNS template duplicates an existing resolver definition");
    }
}

TEST_CASE("complete config metadata keeps plain DNS template limits inclusive") {
    auto config = complete_metadata_base();
    config.ui_preferences = UiPreferencesConfig{};
    std::vector<PlainDnsTemplate> templates;
    for (std::size_t index = 0; index < 32; ++index) {
        templates.push_back(complete_metadata_template(
            index == 0 ? complete_metadata_unicode_name(80) : "DNS " + std::to_string(index),
            "192.0.2." + std::to_string(index + 1)));
    }
    config.ui_preferences->plain_dns_templates = templates;
    CHECK_NOTHROW(validate_config(config));
    config.ui_preferences->plain_dns_templates->push_back(
        complete_metadata_template("One more", "192.0.2.33"));
    complete_metadata_expect(complete_metadata_typed_issues(config),
        "ui_preferences.plain_dns_templates", "config.value.too_many", {{"max", "32"}},
        "ui_preferences.plain_dns_templates must not contain more than 32 entries");
}

} // namespace keen_pbr3
