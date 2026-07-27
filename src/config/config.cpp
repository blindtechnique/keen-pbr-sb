#include "config.hpp"
#include "addr_spec.hpp"
#include "routing_state.hpp"
#include "../util/display_name.hpp"
#include "../util/system_info.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <net/if.h>
#include <set>
#include <sstream>

#include <nlohmann/json.hpp>

#include "../dns/dns_probe_server.hpp"
#include "../util/cron.hpp"

namespace keen_pbr3 {

using json = nlohmann::json;

namespace {

bool is_valid_ipv4_address(const std::string& ip) {
    in_addr addr{};
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

bool is_valid_ipv6_address(const std::string& ip) {
    in6_addr addr{};
    return inet_pton(AF_INET6, ip.c_str(), &addr) == 1;
}

bool is_http_url(const std::string& url) {
    const auto separator = url.find("://");
    if (separator == std::string::npos || separator + 3 >= url.size()) return false;

    std::string scheme = url.substr(0, separator);
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return scheme == "http" || scheme == "https";
}

void add_issue(std::vector<ConfigValidationIssue>& issues,
               std::string path,
               std::string message) {
    issues.push_back({std::move(path), std::move(message)});
}

void validate_optional_integer_field(const json& root,
                                     const char* parent_key,
                                     const char* child_key,
                                     const std::string& path,
                                     std::vector<ConfigValidationIssue>& issues) {
    const auto parent_it = root.find(parent_key);
    if (parent_it == root.end() || !parent_it->is_object()) {
        return;
    }

    const auto child_it = parent_it->find(child_key);
    if (child_it == parent_it->end() || child_it->is_null()) {
        return;
    }

    if (!child_it->is_number_integer()) {
        add_issue(issues, path, path + " must be an integer");
    }
}

void validate_optional_string_field(const json& root,
                                    const char* parent_key,
                                    const char* child_key,
                                    const std::string& path,
                                    std::vector<ConfigValidationIssue>& issues) {
    const auto parent_it = root.find(parent_key);
    if (parent_it == root.end() || !parent_it->is_object()) {
        return;
    }

    const auto child_it = parent_it->find(child_key);
    if (child_it == parent_it->end() || child_it->is_null()) {
        return;
    }

    if (!child_it->is_string()) {
        add_issue(issues, path, path + " must be a string");
    }
}

void validate_optional_boolean_field(const json& root,
                                     const char* parent_key,
                                     const char* child_key,
                                     const std::string& path,
                                     std::vector<ConfigValidationIssue>& issues) {
    const auto parent_it = root.find(parent_key);
    if (parent_it == root.end() || !parent_it->is_object()) {
        return;
    }

    const auto child_it = parent_it->find(child_key);
    if (child_it == parent_it->end() || child_it->is_null()) {
        return;
    }

    if (!child_it->is_boolean()) {
        add_issue(issues, path, path + " must be a boolean");
    }
}

void validate_optional_hex_string_field(const json& root,
                                        const char* parent_key,
                                        const char* child_key,
                                        const std::string& path,
                                        std::vector<ConfigValidationIssue>& issues) {
    const auto parent_it = root.find(parent_key);
    if (parent_it == root.end() || !parent_it->is_object()) {
        return;
    }

    const auto child_it = parent_it->find(child_key);
    if (child_it == parent_it->end() || child_it->is_null()) {
        return;
    }

    if (!child_it->is_string()) {
        add_issue(issues, path, path + " must be a string in hex format (e.g. 0x00010000)");
    }
}

std::string trim_copy(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\n\r\f\v");
    if (begin == std::string::npos) {
        return {};
    }

    const auto end = value.find_last_not_of(" \t\n\r\f\v");
    return value.substr(begin, end - begin + 1);
}

bool is_valid_iptables_interface_name(const std::string& interface_name) {
    if (interface_name.empty() || trim_copy(interface_name).empty() ||
        interface_name.size() >= IFNAMSIZ || interface_name == "." ||
        interface_name == ".." || interface_name.back() == '+') {
        return false;
    }

    return std::none_of(
        interface_name.begin(),
        interface_name.end(),
        [](unsigned char ch) {
            return ch == '/' || ch == ':' || ch == '"' || ch == '\\' ||
                   std::isspace(ch) != 0 || std::iscntrl(ch) != 0;
        });
}

std::string iptables_interface_name_requirement(const std::string& path) {
    return path +
           " must be a valid iptables interface name (shorter than IFNAMSIZ, "
           "without '/', ':', quotes, backslashes, whitespace, or control "
           "characters, and not ending in '+')";
}

FirewallBackendPreference to_firewall_backend_preference(api::DaemonConfigFirewallBackend backend) {
    switch (backend) {
        case api::DaemonConfigFirewallBackend::AUTO:
            return FirewallBackendPreference::auto_detect;
        case api::DaemonConfigFirewallBackend::IPTABLES:
            return FirewallBackendPreference::iptables;
        case api::DaemonConfigFirewallBackend::NFTABLES:
            return FirewallBackendPreference::nftables;
    }

    throw std::runtime_error("Unexpected daemon.firewall_backend value");
}

bool parse_uint_in_range(const std::string& raw, int min_value, int max_value, int& out) {
    if (raw.empty()) {
        return false;
    }

    long long value = 0;
    for (char c : raw) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }

        value = value * 10 + (c - '0');
        if (value > std::numeric_limits<int>::max()) {
            return false;
        }
    }

    if (value < min_value || value > max_value) {
        return false;
    }

    out = static_cast<int>(value);
    return true;
}

constexpr size_t IPSET_MAX_NAME = 31;
constexpr size_t IPSET_PREFIX_LEN = 7; // len("kpbr4d_")
constexpr size_t MAX_TAG_LEN = IPSET_MAX_NAME - IPSET_PREFIX_LEN; // 24
constexpr size_t MAX_HIDDEN_NATIVE_INTERFACE_IDS = 128;
constexpr size_t MAX_NATIVE_INTERFACE_ID_CODE_POINTS = 128;
constexpr size_t MAX_PLAIN_DNS_TEMPLATES = 32;

void validate_display_name(
    std::vector<ConfigValidationIssue>& issues,
    const std::string& path,
    const std::string& kind,
    const std::optional<std::string>& display_name) {
    if (!display_name.has_value()) return;
    switch (keen_pbr3::display_name::validate(*display_name, false)) {
        case keen_pbr3::display_name::ValidationError::none:
            return;
        case keen_pbr3::display_name::ValidationError::invalid_utf8:
            add_issue(issues, path, kind + " must be valid UTF-8");
            return;
        case keen_pbr3::display_name::ValidationError::ascii_control:
            add_issue(
                issues, path,
                kind + " must not contain ASCII control characters");
            return;
        case keen_pbr3::display_name::ValidationError::c1_or_bidirectional_control:
            add_issue(
                issues, path,
                kind +
                    " must not contain C1 or bidirectional control characters");
            return;
        case keen_pbr3::display_name::ValidationError::whitespace_only:
            add_issue(
                issues, path,
                kind + " must contain a non-whitespace character");
            return;
        case keen_pbr3::display_name::ValidationError::too_long:
            add_issue(
                issues, path,
                kind + " must not exceed " +
                    std::to_string(keen_pbr3::display_name::MAX_CODE_POINTS) +
                    " Unicode code points");
            return;
    }
}

std::string ascii_lower_copy(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

void validate_ui_preferences(
    std::vector<ConfigValidationIssue>& issues,
    const std::optional<UiPreferencesConfig>& preferences) {
    if (!preferences.has_value()) return;

    const auto hidden_ids =
        preferences->hidden_native_interface_ids.value_or(
            std::vector<std::string>{});
    if (hidden_ids.size() > MAX_HIDDEN_NATIVE_INTERFACE_IDS) {
        add_issue(
            issues,
            "ui_preferences.hidden_native_interface_ids",
            "ui_preferences.hidden_native_interface_ids must not contain more than " +
                std::to_string(MAX_HIDDEN_NATIVE_INTERFACE_IDS) + " entries");
    }

    std::set<std::string> seen_hidden_ids;
    for (size_t index = 0; index < hidden_ids.size(); ++index) {
        const auto& interface_id = hidden_ids[index];
        const std::string path =
            "ui_preferences.hidden_native_interface_ids[" +
            std::to_string(index) + "]";
        const auto summary = display_name::summarize_utf8(interface_id);
        if (!summary.has_value()) {
            add_issue(issues, path, path + " must be valid UTF-8");
        } else if (!summary->has_non_whitespace ||
                   trim_copy(interface_id) != interface_id) {
            add_issue(
                issues,
                path,
                path + " must be a non-blank identifier without surrounding whitespace");
        } else if (summary->code_points >
                   MAX_NATIVE_INTERFACE_ID_CODE_POINTS) {
            add_issue(
                issues,
                path,
                path + " must not exceed " +
                    std::to_string(MAX_NATIVE_INTERFACE_ID_CODE_POINTS) +
                    " Unicode code points");
        } else if (summary->has_ascii_control) {
            add_issue(issues, path, path + " must not contain control characters");
        }

        if (!seen_hidden_ids.insert(interface_id).second) {
            add_issue(
                issues, path,
                path + " duplicates native interface id '" + interface_id + "'");
        }
    }

    const auto templates =
        preferences->plain_dns_templates.value_or(
            std::vector<PlainDnsTemplate>{});
    if (templates.size() > MAX_PLAIN_DNS_TEMPLATES) {
        add_issue(
            issues,
            "ui_preferences.plain_dns_templates",
            "ui_preferences.plain_dns_templates must not contain more than " +
                std::to_string(MAX_PLAIN_DNS_TEMPLATES) + " entries");
    }

    std::set<std::string> seen_names;
    std::set<std::string> seen_definitions;
    for (size_t index = 0; index < templates.size(); ++index) {
        const auto& dns_template = templates[index];
        const std::string path =
            "ui_preferences.plain_dns_templates[" +
            std::to_string(index) + "]";

        validate_display_name(
            issues,
            path + ".name",
            "Plain DNS template name",
            std::optional<std::string>{dns_template.name});
        if (trim_copy(dns_template.name) != dns_template.name) {
            add_issue(
                issues,
                path + ".name",
                "Plain DNS template name must not contain surrounding whitespace");
        }

        if (!is_valid_ipv4_address(dns_template.primary_ipv4)) {
            add_issue(
                issues,
                path + ".primary_ipv4",
                "Plain DNS template primary_ipv4 must be a valid IPv4 address");
        }
        if (dns_template.secondary_ipv4.has_value() &&
            !is_valid_ipv4_address(*dns_template.secondary_ipv4)) {
            add_issue(
                issues,
                path + ".secondary_ipv4",
                "Plain DNS template secondary_ipv4 must be a valid IPv4 address");
        }
        if (dns_template.secondary_ipv4.has_value() &&
            *dns_template.secondary_ipv4 == dns_template.primary_ipv4) {
            add_issue(
                issues,
                path + ".secondary_ipv4",
                "Plain DNS template secondary_ipv4 must differ from primary_ipv4");
        }

        const std::string normalized_name =
            ascii_lower_copy(trim_copy(dns_template.name));
        if (!seen_names.insert(normalized_name).second) {
            add_issue(
                issues,
                path + ".name",
                "Plain DNS template name '" + dns_template.name +
                    "' is duplicated");
        }

        const std::string definition =
            dns_template.primary_ipv4 + "|" +
            dns_template.secondary_ipv4.value_or("");
        if (!seen_definitions.insert(definition).second) {
            add_issue(
                issues,
                path,
                "Plain DNS template duplicates an existing resolver definition");
        }
    }
}

bool is_valid_tag(const std::string& value) {
    if (value.empty() || value.size() > MAX_TAG_LEN) {
        return false;
    }

    const unsigned char first = static_cast<unsigned char>(value[0]);
    if (first < 'a' || first > 'z') {
        return false;
    }

    for (size_t i = 1; i < value.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(value[i]);
        const bool valid = (c >= 'a' && c <= 'z') ||
                           (c >= '0' && c <= '9') ||
                           c == '_';
        if (!valid) {
            return false;
        }
    }

    return true;
}

void validate_tag(std::vector<ConfigValidationIssue>& issues,
                  const std::string& path,
                  const std::string& kind,
                  const std::string& value) {
    if (value.empty()) {
        add_issue(issues, path, kind + " must not be empty");
        return;
    }

    if (value.size() > MAX_TAG_LEN) {
        add_issue(issues, path,
                  kind + " '" + value + "' is too long: " +
                      std::to_string(value.size()) + " chars, maximum is " +
                      std::to_string(MAX_TAG_LEN));
    }

    if (!is_valid_tag(value)) {
        add_issue(issues, path,
                  kind + " '" + value +
                      "' must match naming convention [a-z][a-z0-9_]*");
    }
}

std::set<std::string> collect_list_names(const Config& cfg) {
    std::set<std::string> names;
    for (const auto& [name, _] : cfg.lists.value_or(std::map<std::string, ListConfig>{})) {
        names.insert(name);
    }
    return names;
}

std::set<std::string> collect_outbound_tags(const std::vector<Outbound>& outbounds) {
    std::set<std::string> tags;
    for (const auto& outbound : outbounds) {
        tags.insert(outbound.tag);
    }
    return tags;
}

void validate_required_reference(std::vector<ConfigValidationIssue>& issues,
                                 const std::set<std::string>& known_refs,
                                 const std::string& path,
                                 const std::string& owner_path,
                                 const std::string& value,
                                 const std::string& ref_kind) {
    const std::string ref = trim_copy(value);
    if (ref.empty()) {
        add_issue(issues, path, path + " must not be empty");
        return;
    }

    if (known_refs.find(ref) == known_refs.end()) {
        add_issue(issues, path, owner_path + " references unknown " + ref_kind + " '" + ref + "'");
    }
}

void validate_rule_list_references(std::vector<ConfigValidationIssue>& issues,
                                   const std::set<std::string>& known_lists,
                                   const std::string& rule_path,
                                   const std::vector<std::string>& list_refs) {
    for (size_t i = 0; i < list_refs.size(); ++i) {
        validate_required_reference(issues,
                                    known_lists,
                                    rule_path + ".list[" + std::to_string(i) + "]",
                                    rule_path,
                                    list_refs[i],
                                    "list");
    }
}

std::optional<std::string> validate_port_spec(const std::optional<std::string>& value) {
    if (!value.has_value()) {
        return std::nullopt;
    }

    const std::string normalized = trim_copy(*value);
    if (normalized.empty()) {
        return std::nullopt;
    }

    const std::string content = normalized[0] == '!' ? normalized.substr(1) : normalized;
    if (content.empty() || content.front() == ',' || content.back() == ',') {
        return std::string("Use comma-separated ports or ranges.");
    }

    std::stringstream ss(content);
    std::string token;
    while (std::getline(ss, token, ',')) {
        const std::string part = trim_copy(token);
        if (part.empty()) {
            return std::string("Use comma-separated ports or ranges.");
        }

        const auto dash = part.find('-');
        if (dash != std::string::npos) {
            if (part.find('-', dash + 1) != std::string::npos) {
                return std::string("Port ranges must use valid ports such as 8000-9000.");
            }

            const std::string start_part = trim_copy(part.substr(0, dash));
            const std::string end_part = trim_copy(part.substr(dash + 1));
            int start = 0;
            int end = 0;
            if (!parse_uint_in_range(start_part, 1, 65535, start) ||
                !parse_uint_in_range(end_part, 1, 65535, end)) {
                return std::string("Port ranges must use valid ports such as 8000-9000.");
            }

            if (start > end) {
                return std::string("Port range start must be less than or equal to end.");
            }

            continue;
        }

        int port = 0;
        if (!parse_uint_in_range(part, 1, 65535, port)) {
            return std::string("Ports must be integers between 1 and 65535.");
        }
    }

    return std::nullopt;
}

std::optional<std::string> validate_address_spec(const std::optional<std::string>& value) {
    if (!value.has_value()) {
        return std::nullopt;
    }

    const std::string normalized = trim_copy(*value);
    if (normalized.empty()) {
        return std::nullopt;
    }

    const std::string content = normalized[0] == '!' ? normalized.substr(1) : normalized;
    if (content.empty() || content.front() == ',' || content.back() == ',') {
        return std::string("Use comma-separated IP addresses or CIDRs.");
    }

    try {
        (void)parse_addr_spec(normalized);
    } catch (const std::invalid_argument&) {
        return std::string("Addresses must be valid IPv4 or IPv6 hosts or CIDR ranges, for example 10.0.0.1, 10.0.0.0/8, or 2001:db8::/32.");
    }

    return std::nullopt;
}

std::optional<std::string> get_optional_string_field(const json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || it->is_null() || !it->is_string()) {
        return std::nullopt;
    }

    return it->get<std::string>();
}

bool rule_has_list_condition(const json& rule) {
    const auto list_it = rule.find("list");
    if (list_it == rule.end() || !list_it->is_array()) {
        return false;
    }

    for (const auto& value : *list_it) {
        if (value.is_string() && !trim_copy(value.get<std::string>()).empty()) {
            return true;
        }
    }

    return false;
}

bool rule_has_string_condition(const json& rule, const char* key) {
    const auto value = get_optional_string_field(rule, key);
    return value.has_value() && !trim_copy(*value).empty();
}

bool rule_has_present_condition(const json& rule, const char* key) {
    const auto it = rule.find(key);
    return it != rule.end() && !it->is_null();
}

void validate_dscp_field(const json& rule,
                         const std::string& rule_path,
                         std::vector<ConfigValidationIssue>& issues) {
    const auto it = rule.find("dscp");
    if (it == rule.end() || it->is_null()) {
        return;
    }

    const std::string path = rule_path + ".dscp";
    if (!it->is_number_integer()) {
        add_issue(issues, path, path + " must be an integer between 1 and 63");
        return;
    }

    const int value = it->get<int>();
    if (value < 1 || value > 63) {
        add_issue(issues, path, path + " must be between 1 and 63");
    }
}

std::optional<PortSpecKind> classify_optional_port_spec(const std::optional<std::string>& value) {
    if (!value.has_value()) {
        return std::nullopt;
    }

    const std::string normalized = trim_copy(*value);
    if (normalized.empty()) {
        return std::nullopt;
    }

    const std::string content =
        normalized[0] == '!' ? trim_copy(normalized.substr(1)) : normalized;
    if (content.empty()) {
        return std::nullopt;
    }

    return parse_port_spec(content).kind();
}

void validate_route_rule_specs(const json& root, std::vector<ConfigValidationIssue>& issues) {
    const auto route_it = root.find("route");
    if (route_it == root.end() || !route_it->is_object()) {
        return;
    }

    const auto rules_it = route_it->find("rules");
    if (rules_it == route_it->end() || !rules_it->is_array()) {
        return;
    }

    for (size_t index = 0; index < rules_it->size(); ++index) {
        const auto& rule = rules_it->at(index);
        if (!rule.is_object()) {
            continue;
        }

        const std::string rule_path = "route.rules[" + std::to_string(index) + "]";
        const bool has_any_condition =
            rule_has_list_condition(rule) ||
            rule_has_present_condition(rule, "dscp") ||
            rule_has_string_condition(rule, "src_port") ||
            rule_has_string_condition(rule, "dest_port") ||
            rule_has_string_condition(rule, "src_addr") ||
            rule_has_string_condition(rule, "dest_addr");

        if (!has_any_condition) {
            add_issue(issues,
                      rule_path,
                      "Route rule must include at least one condition: list, dscp, src_port, dest_port, src_addr, or dest_addr.");
        }

        validate_dscp_field(rule, rule_path, issues);

        if (auto error = validate_port_spec(get_optional_string_field(rule, "src_port"))) {
            add_issue(issues, rule_path + ".src_port", *error);
        }

        if (auto error = validate_port_spec(get_optional_string_field(rule, "dest_port"))) {
            add_issue(issues, rule_path + ".dest_port", *error);
        }

        if (auto error = validate_address_spec(get_optional_string_field(rule, "src_addr"))) {
            add_issue(issues, rule_path + ".src_addr", *error);
        }

        if (auto error = validate_address_spec(get_optional_string_field(rule, "dest_addr"))) {
            add_issue(issues, rule_path + ".dest_addr", *error);
        }
    }
}

bool route_rule_uses_unsupported_iptables_multiport_combo(const RouteRule& rule) {
    const auto src_kind = classify_optional_port_spec(rule.src_port);
    const auto dst_kind = classify_optional_port_spec(rule.dest_port);
    if (!src_kind.has_value() || !dst_kind.has_value()) {
        return false;
    }

    return *src_kind == PortSpecKind::List || *dst_kind == PortSpecKind::List;
}

std::string route_rule_unsupported_iptables_multiport_path(size_t rule_index,
                                                           const RouteRule& rule) {
    const auto src_kind = classify_optional_port_spec(rule.src_port);
    if (src_kind.has_value() && *src_kind == PortSpecKind::List) {
        return "route.rules[" + std::to_string(rule_index) + "].src_port";
    }

    return "route.rules[" + std::to_string(rule_index) + "].dest_port";
}

void validate_route_inbound_interfaces(const json& root, std::vector<ConfigValidationIssue>& issues) {
    const auto route_it = root.find("route");
    if (route_it == root.end() || !route_it->is_object()) {
        return;
    }

    const auto inbound_it = route_it->find("inbound_interfaces");
    if (inbound_it == route_it->end() || inbound_it->is_null()) {
        return;
    }

    if (!inbound_it->is_array()) {
        add_issue(issues, "route.inbound_interfaces", "route.inbound_interfaces must be an array of strings");
        return;
    }

    std::set<std::string> seen_interfaces;
    for (size_t index = 0; index < inbound_it->size(); ++index) {
        const auto& iface_value = inbound_it->at(index);
        const std::string iface_path =
            "route.inbound_interfaces[" + std::to_string(index) + "]";

        if (!iface_value.is_string()) {
            add_issue(issues, iface_path, iface_path + " must be a string");
            continue;
        }

        const std::string iface = iface_value.get<std::string>();
        if (trim_copy(iface).empty()) {
            add_issue(issues, iface_path, iface_path + " must not be blank");
            continue;
        }

        if (!is_valid_iptables_interface_name(iface)) {
            add_issue(issues, iface_path,
                      iptables_interface_name_requirement(iface_path));
            continue;
        }

        if (!seen_interfaces.insert(iface).second) {
            add_issue(issues, iface_path,
                      iface_path + " duplicates interface '" + iface + "'");
        }
    }
}

} // namespace

ConfigValidationError::ConfigValidationError(std::vector<ConfigValidationIssue> issues)
    : ConfigError(build_message(issues))
    , issues_(std::move(issues)) {}

std::string ConfigValidationError::build_message(
    const std::vector<ConfigValidationIssue>& issues) {
    if (issues.empty()) {
        return "Config validation failed";
    }

    if (issues.size() == 1) {
        return issues.front().message;
    }

    return "Config validation failed with " + std::to_string(issues.size()) + " errors";
}

static uint32_t normalized_fwmark_mask(uint32_t mask) {
    const uint32_t lowest = mask & (~mask + 1);
    return mask / lowest;
}

static bool has_consecutive_full_f_nibbles(uint32_t normalized_mask) {
    if (normalized_mask == 0) {
        return false;
    }

    while (normalized_mask != 0) {
        if ((normalized_mask & 0xF) != 0xF) {
            return false;
        }
        normalized_mask >>= 4;
    }

    return true;
}

static uint32_t fwmark_mask_mark_capacity(uint32_t mask) {
    return normalized_fwmark_mask(mask) + 1;
}

// Validate that the fwmark mask has one or more consecutive hex nibbles set to F.
static void validate_fwmark_mask(uint32_t mask) {
    if (mask == 0) {
        throw ConfigError("fwmark.mask must not be zero");
    }

    const uint32_t lowest = mask & (~mask + 1);

    int bit_pos = 0;
    uint32_t tmp = lowest;
    while (tmp > 1) {
        tmp >>= 1;
        ++bit_pos;
    }
    if (bit_pos % 4 != 0) {
        std::ostringstream oss;
        oss << "fwmark.mask must be aligned to nibble boundaries "
            << "(e.g. 0x000F0000, 0x00FF0000), got 0x"
            << std::hex << std::setfill('0') << std::setw(8) << mask;
        throw ConfigError(oss.str());
    }

    if (!has_consecutive_full_f_nibbles(normalized_fwmark_mask(mask))) {
        std::ostringstream oss;
        oss << "fwmark.mask must have one or more consecutive hex nibbles set to F "
            << "(e.g. 0x000F0000, 0x00FF0000, 0x0FFF0000), got 0x"
            << std::hex << std::setfill('0') << std::setw(8) << mask;
        throw ConfigError(oss.str());
    }
}

uint32_t parse_fwmark_hex_or_throw(const std::optional<std::string>& raw,
                                   uint32_t default_value,
                                   const std::string& path) {
    if (!raw.has_value()) {
        return default_value;
    }

    const std::string value = trim_copy(*raw);
    if (value.empty()) {
        throw ConfigError(path + " must not be empty");
    }

    if (value.size() < 3 || value[0] != '0' || (value[1] != 'x' && value[1] != 'X')) {
        throw ConfigError(path + " must be a hexadecimal string with 0x prefix");
    }

    for (size_t i = 2; i < value.size(); ++i) {
        if (!std::isxdigit(static_cast<unsigned char>(value[i]))) {
            throw ConfigError(path + " must contain only hexadecimal digits");
        }
    }

    unsigned long parsed = 0;
    try {
        parsed = std::stoul(value, nullptr, 16);
    } catch (const std::exception&) {
        throw ConfigError(path + " must be a valid 32-bit hexadecimal value");
    }

    if (parsed > std::numeric_limits<uint32_t>::max()) {
        throw ConfigError(path + " must fit into 32 bits (max 0xFFFFFFFF)");
    }

    return static_cast<uint32_t>(parsed);
}

uint32_t parse_fwmark_start_or_throw(const FwmarkConfig& fwmark_cfg) {
    return parse_fwmark_hex_or_throw(fwmark_cfg.start, 0x00010000, "fwmark.start");
}

uint32_t parse_fwmark_mask_or_throw(const FwmarkConfig& fwmark_cfg) {
    return parse_fwmark_hex_or_throw(fwmark_cfg.mask, 0x00FF0000, "fwmark.mask");
}

Config parse_config(const std::string& json_str) {
    Config cfg;
    json parsed_json;
    std::vector<ConfigValidationIssue> issues;

    try {
        parsed_json = json::parse(json_str, nullptr, true, true);
    } catch (const json::parse_error& e) {
        throw ConfigValidationError(std::vector<ConfigValidationIssue>{
            {"$", std::string("Invalid JSON: ") + e.what()}
        });
    }

    validate_optional_hex_string_field(
        parsed_json, "fwmark", "start", "fwmark.start", issues);
    validate_optional_hex_string_field(
        parsed_json, "fwmark", "mask", "fwmark.mask", issues);
    validate_optional_integer_field(
        parsed_json, "iproute", "table_start", "iproute.table_start", issues);
    validate_optional_integer_field(
        parsed_json, "daemon", "firewall_verify_max_bytes",
        "daemon.firewall_verify_max_bytes", issues);
    validate_optional_integer_field(
        parsed_json, "daemon", "max_file_size_bytes", "daemon.max_file_size_bytes", issues);
    validate_optional_string_field(
        parsed_json, "daemon", "firewall_backend", "daemon.firewall_backend", issues);
    validate_optional_boolean_field(
        parsed_json, "daemon", "skip_marked_packets", "daemon.skip_marked_packets", issues);
    validate_optional_boolean_field(
        parsed_json, "daemon", "clear_dynamic_sets_on_apply",
        "daemon.clear_dynamic_sets_on_apply", issues);
    validate_optional_boolean_field(
        parsed_json, "daemon", "ipv6_enabled", "daemon.ipv6_enabled", issues);
    validate_route_rule_specs(parsed_json, issues);
    validate_route_inbound_interfaces(parsed_json, issues);

    if (!issues.empty()) {
        throw ConfigValidationError(std::move(issues));
    }

    try {
        cfg = parsed_json.get<Config>();
    } catch (const json::exception& e) {
        throw ConfigValidationError(std::vector<ConfigValidationIssue>{
            {"$", e.what()}
        });
    } catch (const std::exception& e) {
        throw ConfigValidationError(std::vector<ConfigValidationIssue>{
            {"$", e.what()}
        });
    }

    return cfg;
}

namespace {

constexpr int64_t kMaxUrltestUint32Value =
    static_cast<int64_t>(std::numeric_limits<uint32_t>::max());
constexpr int64_t kMaxUrltestGroupWeight =
    static_cast<int64_t>(std::numeric_limits<uint32_t>::max());
constexpr int64_t kMaxUrltestRetryAttempts = 1000;
constexpr int64_t kMaxCircuitFailureThreshold =
    static_cast<int64_t>(std::numeric_limits<int>::max());

void validate_optional_integer_range(
    std::vector<ConfigValidationIssue>& issues,
    const std::string& path,
    const std::optional<int64_t>& value,
    int64_t minimum,
    int64_t maximum) {
    if (!value.has_value()) {
        return;
    }

    if (*value < minimum || *value > maximum) {
        add_issue(
            issues,
            path,
            path + " must be between " + std::to_string(minimum) + " and " +
                std::to_string(maximum));
    }
}

struct UrltestReference {
    std::string target_tag;
    std::string path;
};

void validate_urltest_cycles(
    std::vector<ConfigValidationIssue>& issues,
    const std::map<std::string, std::vector<UrltestReference>>& graph) {
    enum class VisitState {
        unvisited,
        visiting,
        visited,
    };

    std::map<std::string, VisitState> states;
    for (const auto& [tag, unused] : graph) {
        (void)unused;
        states.emplace(tag, VisitState::unvisited);
    }

    struct VisitFrame {
        std::string tag;
        size_t next_reference{0};
    };

    for (const auto& [tag, unused] : graph) {
        (void)unused;
        if (states[tag] != VisitState::unvisited) {
            continue;
        }

        states[tag] = VisitState::visiting;
        std::vector<VisitFrame> stack{{tag, 0}};
        while (!stack.empty()) {
            auto& frame = stack.back();
            const auto& references = graph.at(frame.tag);
            if (frame.next_reference >= references.size()) {
                states[frame.tag] = VisitState::visited;
                stack.pop_back();
                continue;
            }

            const auto& reference = references[frame.next_reference++];
            const auto state_it = states.find(reference.target_tag);
            if (state_it == states.end()) {
                continue;
            }

            if (state_it->second == VisitState::visiting) {
                add_issue(
                    issues,
                    reference.path,
                    "Urltest outbound '" + frame.tag +
                        "' creates a cyclic reference to urltest outbound '" +
                        reference.target_tag + "'");
                continue;
            }

            if (state_it->second == VisitState::unvisited) {
                state_it->second = VisitState::visiting;
                stack.push_back({reference.target_tag, 0});
            }
        }
    }
}

} // namespace

void validate_config(const Config& cfg) {
    std::vector<ConfigValidationIssue> issues;

    validate_ui_preferences(issues, cfg.ui_preferences);

    if (cfg.daemon && cfg.daemon->firewall_verify_max_bytes.has_value() &&
        *cfg.daemon->firewall_verify_max_bytes < 0) {
        add_issue(issues, "daemon.firewall_verify_max_bytes",
                  "daemon.firewall_verify_max_bytes must be >= 0");
    }

    if (cfg.daemon && cfg.daemon->max_file_size_bytes.has_value() &&
        *cfg.daemon->max_file_size_bytes <= 0) {
        add_issue(issues, "daemon.max_file_size_bytes",
                  "daemon.max_file_size_bytes must be greater than 0");
    }

    if (cfg.lists_autoupdate) {
        const bool enabled = cfg.lists_autoupdate->enabled.value_or(false);
        const std::string cron = cfg.lists_autoupdate->cron.value_or("");
        if (enabled && cron.empty()) {
            add_issue(issues, "lists_autoupdate.cron",
                      "lists_autoupdate.cron is required when enabled");
        }
        if (!cron.empty()) {
            try {
                cron_validate(cron);
            } catch (const std::invalid_argument& e) {
                add_issue(issues, "lists_autoupdate.cron",
                          std::string("lists_autoupdate.cron: ") + e.what());
            }
        }
    }

    for (const auto& [name, list_cfg] : cfg.lists.value_or(std::map<std::string, ListConfig>{})) {
        const std::string list_path = name.empty() ? "lists" : "lists." + name;
        validate_tag(issues, list_path, "List name", name);
        validate_display_name(
            issues,
            list_path + ".display_name",
            "List display name",
            list_cfg.display_name);

        const bool has_url = list_cfg.url.has_value();
        const bool has_file = list_cfg.file.has_value();
        const bool has_cidrs =
            list_cfg.ip_cidrs.has_value() && !list_cfg.ip_cidrs->empty();
        const bool has_domains =
            list_cfg.domains.has_value() && !list_cfg.domains->empty();
        if (!has_url && !has_file && !has_cidrs && !has_domains) {
            add_issue(issues, list_path,
                      "List '" + name +
                          "' must have at least one of: url, domains, ip_cidrs, file");
        }
    }

    const auto& outbounds = cfg.outbounds.value_or(std::vector<Outbound>{});
    std::map<std::string, const Outbound*> outbounds_by_tag;
    std::map<std::string, size_t> first_outbound_indexes;
    std::map<std::string, std::vector<UrltestReference>> urltest_graph;
    for (size_t outbound_index = 0; outbound_index < outbounds.size();
         ++outbound_index) {
        const auto& outbound = outbounds[outbound_index];
        const auto [first_index_it, inserted] =
            first_outbound_indexes.emplace(outbound.tag, outbound_index);
        if (!inserted) {
            const std::string path =
                "outbounds[" + std::to_string(outbound_index) + "].tag";
            add_issue(
                issues,
                path,
                path + " duplicates outbound tag '" + outbound.tag +
                    "' first declared at outbounds[" +
                    std::to_string(first_index_it->second) + "].tag");
        }

        outbounds_by_tag.emplace(outbound.tag, &outbound);
        if (outbound.type == OutboundType::URLTEST) {
            urltest_graph.emplace(outbound.tag, std::vector<UrltestReference>{});
        }
    }

    for (const auto& ob : outbounds) {
        validate_tag(issues, "outbounds." + ob.tag + ".tag", "Outbound tag", ob.tag);
        validate_display_name(
            issues,
            "outbounds." + ob.tag + ".display_name",
            "Outbound display name",
            ob.display_name);
        if (ob.type != OutboundType::URLTEST &&
            ob.conntrack_on_switch.has_value()) {
            add_issue(
                issues,
                "outbounds." + ob.tag + ".conntrack_on_switch",
                "conntrack_on_switch is only valid for urltest outbounds");
        }

        if (ob.type == OutboundType::INTERFACE) {
            const std::string iface = trim_copy(ob.interface.value_or(""));
            const std::string interface_path =
                "outbounds." + ob.tag + ".interface";
            if (iface.empty()) {
                add_issue(issues,
                          interface_path,
                          "Interface outbound '" + ob.tag +
                              "' requires a non-empty interface name");
            } else if (!is_valid_iptables_interface_name(
                           ob.interface.value_or(""))) {
                add_issue(
                    issues,
                    interface_path,
                    iptables_interface_name_requirement(interface_path));
            }
            if (ob.gateway.has_value() && !is_valid_ipv4_address(*ob.gateway)) {
                add_issue(issues,
                          "outbounds." + ob.tag + ".gateway",
                          "Interface outbound '" + ob.tag +
                              "' gateway must be a valid IPv4 address");
            }
            if (ob.gateway6.has_value() && !is_valid_ipv6_address(*ob.gateway6)) {
                add_issue(issues,
                          "outbounds." + ob.tag + ".gateway6",
                          "Interface outbound '" + ob.tag +
                              "' gateway6 must be a valid IPv6 address");
            }
        }

        if (ob.type != OutboundType::URLTEST) continue;

        if (!ob.url.has_value() || ob.url->empty()) {
            add_issue(issues, "outbounds." + ob.tag + ".url",
                      "Urltest outbound '" + ob.tag + "' requires a URL");
        } else if (!is_http_url(*ob.url)) {
            add_issue(issues, "outbounds." + ob.tag + ".url",
                      "Urltest URL must use the http or https scheme");
        }

        const std::string outbound_path = "outbounds." + ob.tag;
        validate_optional_integer_range(
            issues,
            outbound_path + ".interval_ms",
            ob.interval_ms,
            1,
            kMaxUrltestUint32Value);
        validate_optional_integer_range(
            issues,
            outbound_path + ".probe_timeout_ms",
            ob.probe_timeout_ms,
            1,
            kMaxUrltestUint32Value);
        validate_optional_integer_range(
            issues,
            outbound_path + ".tolerance_ms",
            ob.tolerance_ms,
            0,
            kMaxUrltestUint32Value);

        if (ob.retry.has_value()) {
            validate_optional_integer_range(
                issues,
                outbound_path + ".retry.attempts",
                ob.retry->attempts,
                1,
                kMaxUrltestRetryAttempts);
            validate_optional_integer_range(
                issues,
                outbound_path + ".retry.interval_ms",
                ob.retry->interval_ms,
                0,
                kMaxUrltestUint32Value);
        }

        if (ob.circuit_breaker.has_value()) {
            validate_optional_integer_range(
                issues,
                outbound_path + ".circuit_breaker.failure_threshold",
                ob.circuit_breaker->failure_threshold,
                1,
                kMaxCircuitFailureThreshold);
            validate_optional_integer_range(
                issues,
                outbound_path + ".circuit_breaker.success_threshold",
                ob.circuit_breaker->success_threshold,
                1,
                kMaxUrltestUint32Value);
            validate_optional_integer_range(
                issues,
                outbound_path + ".circuit_breaker.timeout_ms",
                ob.circuit_breaker->timeout_ms,
                0,
                kMaxUrltestUint32Value);
            validate_optional_integer_range(
                issues,
                outbound_path + ".circuit_breaker.half_open_max_requests",
                ob.circuit_breaker->half_open_max_requests,
                1,
                kMaxUrltestUint32Value);
        }

        if (!ob.outbound_groups.has_value() || ob.outbound_groups->empty()) {
            add_issue(issues, "outbounds." + ob.tag + ".outbound_groups",
                      "Urltest outbound '" + ob.tag +
                          "' 'outbound_groups' array must not be empty");
            continue;
        }

        std::map<std::string, std::string> first_child_paths;
        for (size_t group_index = 0; group_index < ob.outbound_groups->size(); ++group_index) {
            const auto& group = ob.outbound_groups->at(group_index);
            const std::string group_path =
                "outbounds." + ob.tag + ".outbound_groups[" + std::to_string(group_index) + "]";

            if (group.outbounds.empty()) {
                add_issue(issues, group_path + ".outbounds",
                          "Urltest outbound '" + ob.tag +
                              "' outbound_group has empty 'outbounds' array");
            }

            validate_optional_integer_range(
                issues,
                group_path + ".weight",
                group.weight,
                1,
                kMaxUrltestGroupWeight);

            for (size_t child_index = 0; child_index < group.outbounds.size();
                 ++child_index) {
                const auto& ref_tag = group.outbounds[child_index];
                const std::string child_path =
                    group_path + ".outbounds[" + std::to_string(child_index) + "]";

                auto [first_path_it, inserted] =
                    first_child_paths.emplace(ref_tag, child_path);
                if (!inserted) {
                    add_issue(
                        issues,
                        child_path,
                        "Urltest outbound '" + ob.tag + "' repeats outbound '" +
                            ref_tag + "' first declared at " + first_path_it->second);
                }

                const auto target_it = outbounds_by_tag.find(ref_tag);
                if (target_it == outbounds_by_tag.end()) {
                    add_issue(
                        issues,
                        child_path,
                        "Urltest outbound '" + ob.tag +
                            "' references unknown outbound tag '" + ref_tag + "'");
                    continue;
                }

                const auto& target = *target_it->second;
                // A group may also nest another group: routing follows the
                // chain of selections down to a leaf interface.
                if (target.type != OutboundType::INTERFACE &&
                    target.type != OutboundType::TABLE &&
                    target.type != OutboundType::BLACKHOLE &&
                    target.type != OutboundType::URLTEST) {
                    add_issue(
                        issues,
                        child_path,
                        "Urltest outbound '" + ob.tag +
                            "' references outbound '" + ref_tag +
                            "' which is not an interface, table, blackhole, "
                            "or urltest outbound");
                }

                if (target.type == OutboundType::URLTEST) {
                    urltest_graph[ob.tag].push_back({ref_tag, child_path});
                }
            }
        }
    }
    validate_urltest_cycles(issues, urltest_graph);

    const auto list_names = collect_list_names(cfg);
    const auto outbound_tags = collect_outbound_tags(outbounds);
    const auto& route_rules =
        cfg.route.value_or(RouteConfig{}).rules.value_or(std::vector<RouteRule>{});
    std::map<std::string, size_t> first_route_rule_ids;
    for (size_t rule_index = 0; rule_index < route_rules.size(); ++rule_index) {
        const auto& rule = route_rules[rule_index];
        const std::string rule_path = "route.rules[" + std::to_string(rule_index) + "]";

        if (rule.id.has_value()) {
            validate_tag(
                issues,
                rule_path + ".id",
                "Route rule id",
                *rule.id);
            const auto [first_it, inserted] =
                first_route_rule_ids.emplace(*rule.id, rule_index);
            if (!inserted) {
                add_issue(
                    issues,
                    rule_path + ".id",
                    "Route rule id '" + *rule.id +
                        "' duplicates route.rules[" +
                        std::to_string(first_it->second) + "].id");
            }
        }
        validate_display_name(
            issues,
            rule_path + ".display_name",
            "Route rule display name",
            rule.display_name);

        validate_required_reference(issues,
                                    outbound_tags,
                                    rule_path + ".outbound",
                                    rule_path,
                                    rule.outbound,
                                    "outbound tag");
        validate_rule_list_references(issues, list_names, rule_path, route_rule_lists(rule));
    }

    const FwmarkConfig fwmark_cfg = cfg.fwmark.value_or(FwmarkConfig{});
    bool fwmark_start_valid = true;
    try {
        (void)parse_fwmark_start_or_throw(fwmark_cfg);
    } catch (const ConfigError& e) {
        fwmark_start_valid = false;
        add_issue(issues, "fwmark.start", e.what());
    }

    uint32_t fwmark_mask = 0;
    bool fwmark_mask_valid = true;
    try {
        fwmark_mask = parse_fwmark_mask_or_throw(fwmark_cfg);
        validate_fwmark_mask(fwmark_mask);
    } catch (const ConfigError& e) {
        fwmark_mask_valid = false;
        add_issue(issues, "fwmark.mask", e.what());
    }

    if (fwmark_start_valid && fwmark_mask_valid) {
        try {
            (void)allocate_outbound_marks(fwmark_cfg, outbounds);
        } catch (const ConfigError& e) {
            add_issue(issues, "outbounds", e.what());
        }
    }

    {
        const uint32_t table_start = static_cast<uint32_t>(
            cfg.iproute.value_or(IprouteConfig{}).table_start.value_or(150));
        if (is_reserved_table(table_start)) {
            add_issue(issues, "iproute.table_start",
                      "iproute.table_start " + std::to_string(table_start) +
                          " is reserved. Use a different value (e.g. 150).");
        }
    }

    if (firewall_backend_preference(cfg) == FirewallBackendPreference::iptables) {
        for (size_t i = 0; i < route_rules.size(); ++i) {
            const auto& rule = route_rules[i];
            if (!route_rule_uses_unsupported_iptables_multiport_combo(rule)) {
                continue;
            }

            add_issue(
                issues,
                route_rule_unsupported_iptables_multiport_path(i, rule),
                "When you use port lists (e.g. 444,555) you can't combine src_port and dest_port condition. This is a xt_multiport module limitation. Consider using nftables firewall backend or create multiple rules.");
        }
    }

    if (cfg.dns.has_value()) {
        const SystemInfo system_info = cached_system_info();
        const auto& dns_servers = cfg.dns->servers.value_or(std::vector<DnsServer>{});
        std::set<std::string> dns_server_tags;
        std::set<std::string> dns_server_identities;
        size_t keenetic_servers_count = 0;
        for (const auto& srv : dns_servers) {
            validate_tag(issues, "dns.servers." + srv.tag + ".tag", "DNS server tag", srv.tag);
            validate_display_name(
                issues,
                "dns.servers." + srv.tag + ".display_name",
                "DNS server display name",
                srv.display_name);
            if (!dns_server_tags.insert(srv.tag).second) {
                add_issue(issues, "dns.servers." + srv.tag + ".tag",
                          "Duplicate DNS server tag \"" + srv.tag + "\"");
            }

            const auto srv_type = srv.type.value_or(api::DnsServerType::STATIC);
            const std::string srv_addr = srv.address.value_or("");
            const std::string srv_identity =
                std::to_string(static_cast<int>(srv_type)) + "|" + srv_addr;
            if (!dns_server_identities.insert(srv_identity).second) {
                add_issue(issues, "dns.servers." + srv.tag,
                          "DNS server \"" + srv.tag +
                              "\" duplicates an existing DNS server definition (same type/address)");
            }

            if (srv_type == api::DnsServerType::KEENETIC) {
                ++keenetic_servers_count;
#ifndef USE_KEENETIC_API
                add_issue(issues, "dns.servers." + srv.tag + ".type",
                          "dns.servers[\"" + srv.tag +
                              "\"].type='keenetic' requires build with USE_KEENETIC_API=ON");
#endif
                if (system_info.os_type == "keenetic" &&
                    !system_info.os_version.empty() &&
                    !keenetic_version_supports_encrypted_dns(system_info.os_version)) {
                    add_issue(issues, "dns.servers." + srv.tag + ".type",
                              "dns.servers[\"" + srv.tag +
                                  "\"].type='keenetic' requires KeeneticOS 3.x or newer; detected " +
                                  system_info.os_version);
                }
                if (srv.address.has_value() && !srv.address->empty()) {
                    add_issue(issues, "dns.servers." + srv.tag + ".address",
                              "dns.servers[\"" + srv.tag +
                                  "\"].address must not be set for type='keenetic' (resolved via RCI)");
                }
            } else if (srv_type == api::DnsServerType::STATIC) {
                if (!srv.address.has_value() || srv.address->empty()) {
                    add_issue(issues, "dns.servers." + srv.tag + ".address",
                              "dns.servers[\"" + srv.tag +
                                  "\"].address is required for type='static'");
                }
            } else {
                add_issue(issues, "dns.servers." + srv.tag + ".type",
                          "dns.servers[\"" + srv.tag +
                              "\"].type must be one of: static, keenetic");
            }

            if (!srv.detour.has_value()) continue;

            const std::string& dtag = srv.detour.value();
            bool found = false;
            for (const auto& ob : outbounds) {
                if (ob.tag != dtag) {
                    continue;
                }

                found = true;
                if (ob.type == OutboundType::BLACKHOLE ||
                    ob.type == OutboundType::IGNORE) {
                    add_issue(
                        issues,
                        "dns.servers." + srv.tag + ".detour",
                        "dns.servers[\"" + srv.tag + "\"].detour: outbound \""
                            + dtag + "\" has no routing table");
                }
                break;
            }

            if (!found) {
                add_issue(
                    issues,
                    "dns.servers." + srv.tag + ".detour",
                    "dns.servers[\"" + srv.tag + "\"].detour: unknown outbound tag \""
                        + dtag + "\"");
            }
        }
        if (keenetic_servers_count > 1) {
            add_issue(
                issues,
                "dns.servers",
                "at most one dns.servers entry may use type='keenetic'");
        }

        if (cfg.dns->fallback.has_value()) {
            std::set<std::string> seen_fallback_tags;
            for (size_t i = 0; i < cfg.dns->fallback->size(); ++i) {
                const std::string& fallback_tag = (*cfg.dns->fallback)[i];
                const std::string path = "dns.fallback." + std::to_string(i);

                if (fallback_tag.empty()) {
                    add_issue(issues, path,
                              "dns.fallback[" + std::to_string(i) + "] must not be empty");
                    continue;
                }

                if (!seen_fallback_tags.insert(fallback_tag).second) {
                    add_issue(issues, path,
                              "dns.fallback[" + std::to_string(i) +
                                  "] duplicates DNS server tag \"" + fallback_tag + "\"");
                }

                if (dns_server_tags.find(fallback_tag) == dns_server_tags.end()) {
                    add_issue(issues, path,
                              "dns.fallback[" + std::to_string(i) +
                                  "] references unknown DNS server tag \"" + fallback_tag + "\"");
                }
            }
        }

        if (cfg.dns->system_resolver.has_value()) {
            const auto& resolver = *cfg.dns->system_resolver;

            if (resolver.address.empty()) {
                add_issue(issues, "dns.system_resolver.address",
                          "dns.system_resolver.address must not be empty");
            }
        } else {
            add_issue(issues, "dns.system_resolver",
                      "dns.system_resolver must be present");
        }

        const auto dns_rules = cfg.dns->rules.value_or(std::vector<DnsRule>{});
        std::map<std::string, size_t> first_dns_rule_ids;
        for (size_t rule_index = 0; rule_index < dns_rules.size(); ++rule_index) {
            const auto& rule = dns_rules[rule_index];
            const std::string rule_path = "dns.rules[" + std::to_string(rule_index) + "]";

            if (rule.id.has_value()) {
                validate_tag(
                    issues,
                    rule_path + ".id",
                    "DNS rule id",
                    *rule.id);
                const auto [first_it, inserted] =
                    first_dns_rule_ids.emplace(*rule.id, rule_index);
                if (!inserted) {
                    add_issue(
                        issues,
                        rule_path + ".id",
                        rule_path + ".id duplicates DNS rule id '" +
                            *rule.id + "' first declared at dns.rules[" +
                            std::to_string(first_it->second) + "].id");
                }
            }
            validate_display_name(
                issues,
                rule_path + ".display_name",
                "DNS rule display name",
                rule.display_name);
            validate_required_reference(issues,
                                        dns_server_tags,
                                        rule_path + ".server",
                                        rule_path,
                                        rule.server,
                                        "DNS server tag");
            if (rule.list.empty()) {
                add_issue(issues,
                          rule_path + ".list",
                          rule_path + ".list must include at least one list name");
            } else {
                validate_rule_list_references(issues, list_names, rule_path, rule.list);
            }
        }

        if (cfg.dns->dns_test_server.has_value()) {
            try {
                const auto& test_cfg = *cfg.dns->dns_test_server;
                const std::string* answer_ip =
                    test_cfg.answer_ipv4 ? &*test_cfg.answer_ipv4 : nullptr;
                (void)parse_dns_probe_server_settings(test_cfg.listen, answer_ip);
            } catch (const std::exception& e) {
                add_issue(issues, "dns.dns_test_server",
                          std::string("dns.dns_test_server: ") + e.what());
            }
        }
    } else {
        add_issue(issues, "dns.system_resolver",
                  "dns.system_resolver must be present");
    }

    // Deleting conntrack entries by a selected child's fwmark is safe only
    // when that mark belongs exclusively to one urltest selector. Otherwise a
    // failover could also terminate unrelated flows routed directly through
    // the same child. Preserve mode has no such ownership restriction.
    std::map<std::string, std::set<std::string>> urltest_parents_by_child;
    for (const auto& outbound : outbounds) {
        if (outbound.type != OutboundType::URLTEST ||
            !outbound.outbound_groups.has_value()) {
            continue;
        }
        for (const auto& group : *outbound.outbound_groups) {
            for (const auto& child_tag : group.outbounds) {
                urltest_parents_by_child[child_tag].insert(outbound.tag);
            }
        }
    }

    std::set<std::string> directly_routed_outbounds;
    for (const auto& rule : route_rules) {
        directly_routed_outbounds.insert(rule.outbound);
    }

    std::set<std::string> direct_dns_detours;
    if (cfg.dns.has_value()) {
        for (const auto& server :
             cfg.dns->servers.value_or(std::vector<DnsServer>{})) {
            if (server.detour.has_value()) {
                direct_dns_detours.insert(*server.detour);
            }
        }
    }

    for (const auto& outbound : outbounds) {
        if (outbound.type != OutboundType::URLTEST ||
            outbound.conntrack_on_switch.value_or(
                ConntrackOnSwitch::PRESERVE) != ConntrackOnSwitch::DELETE ||
            !outbound.outbound_groups.has_value()) {
            continue;
        }

        const std::string mode_path =
            "outbounds." + outbound.tag + ".conntrack_on_switch";
        std::set<std::string> checked_children;
        for (const auto& group : *outbound.outbound_groups) {
            for (const auto& child_tag : group.outbounds) {
                if (!checked_children.insert(child_tag).second) {
                    continue;
                }

                const auto child_it = outbounds_by_tag.find(child_tag);
                if (child_it != outbounds_by_tag.end() &&
                    child_it->second->type == OutboundType::URLTEST) {
                    add_issue(
                        issues,
                        mode_path,
                        "conntrack_on_switch='delete' does not support nested "
                        "urltest child '" + child_tag +
                            "'; use 'preserve' for nested selectors");
                }

                const auto parents_it =
                    urltest_parents_by_child.find(child_tag);
                if (parents_it != urltest_parents_by_child.end() &&
                    parents_it->second.size() > 1) {
                    add_issue(
                        issues,
                        mode_path,
                        "conntrack_on_switch='delete' requires exclusive child "
                        "marks, but outbound '" + child_tag +
                            "' is shared by multiple urltest selectors");
                }
                if (directly_routed_outbounds.count(child_tag) > 0) {
                    add_issue(
                        issues,
                        mode_path,
                        "conntrack_on_switch='delete' cannot use child '" +
                            child_tag +
                            "' because a routing rule also references it "
                            "directly");
                }
                if (direct_dns_detours.count(child_tag) > 0) {
                    add_issue(
                        issues,
                        mode_path,
                        "conntrack_on_switch='delete' cannot use child '" +
                            child_tag +
                            "' because a DNS server also references it "
                            "directly");
                }
            }
        }
    }

    if (!issues.empty()) {
        throw ConfigValidationError(std::move(issues));
    }
}

size_t max_file_size_bytes(const Config& config) {
    const auto bytes = config.daemon.value_or(DaemonConfig{})
                           .max_file_size_bytes.value_or(
                               static_cast<int64_t>(kDefaultMaxFileSizeBytes));
    return static_cast<size_t>(bytes);
}

FirewallBackendPreference firewall_backend_preference(const Config& config) {
    if (!config.daemon || !config.daemon->firewall_backend.has_value()) {
        return FirewallBackendPreference::auto_detect;
    }

    return to_firewall_backend_preference(*config.daemon->firewall_backend);
}

Config parse_and_validate_config(const std::string& json_str) {
    Config config = parse_config(json_str);
    validate_config(config);
    return config;
}

OutboundMarkMap allocate_outbound_marks(const FwmarkConfig& fwmark_cfg,
                                         const std::vector<Outbound>& outbounds) {
    uint32_t mask  = parse_fwmark_mask_or_throw(fwmark_cfg);
    uint32_t start = parse_fwmark_start_or_throw(fwmark_cfg);

    validate_fwmark_mask(mask);

    uint32_t lowest_bit = mask & (~mask + 1);
    uint32_t step = lowest_bit;

    const uint32_t max_marks = fwmark_mask_mark_capacity(mask);

    std::vector<const Outbound*> routable_outbounds;
    routable_outbounds.reserve(outbounds.size());
    for (const auto& outbound : outbounds) {
        if (outbound.type == OutboundType::INTERFACE ||
            outbound.type == OutboundType::TABLE ||
            outbound.type == OutboundType::URLTEST) {
            routable_outbounds.push_back(&outbound);
        }
    }
    std::sort(
        routable_outbounds.begin(),
        routable_outbounds.end(),
        [](const Outbound* lhs, const Outbound* rhs) {
            return lhs->tag < rhs->tag;
        });

    OutboundMarkMap mark_map;
    uint32_t current_mark = start;
    uint32_t count = 0;

    for (const auto* outbound : routable_outbounds) {
        if (count >= max_marks) {
            throw ConfigError(
                "Too many routable outbounds: maximum " + std::to_string(max_marks) +
                " supported with current fwmark.mask");
        }

        mark_map[outbound->tag] = current_mark;
        current_mark += step;
        ++count;
    }

    return mark_map;
}

uint32_t fwmark_start_value(const FwmarkConfig& fwmark_cfg) {
    return parse_fwmark_start_or_throw(fwmark_cfg);
}

uint32_t fwmark_mask_value(const FwmarkConfig& fwmark_cfg) {
    const uint32_t mask = parse_fwmark_mask_or_throw(fwmark_cfg);
    validate_fwmark_mask(mask);
    return mask;
}

} // namespace keen_pbr3
