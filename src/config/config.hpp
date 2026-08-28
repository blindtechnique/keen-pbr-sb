#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "../api/generated/api_types.hpp"
#include "../firewall/firewall.hpp"

namespace keen_pbr3 {

namespace api {

// Entware GCC 8 with the old string ABI does not mark std::string move
// assignment (and therefore aggregate std::swap) noexcept, although move
// construction is noexcept. Config publication must exchange both exact
// generations inside a no-throw checkpoint. Relocate the two complete objects
// using only operations the target toolchain proves cannot throw. ConfigObject
// is transparently replaceable by an object of the same type, so existing
// names and references designate the replacements under C++17 lifetime rules.
inline void swap(ConfigObject& left, ConfigObject& right) noexcept {
    static_assert(std::is_nothrow_move_constructible_v<ConfigObject>);
    static_assert(std::is_nothrow_destructible_v<ConfigObject>);
    if (std::addressof(left) == std::addressof(right)) return;

    void* const left_storage = static_cast<void*>(std::addressof(left));
    void* const right_storage = static_cast<void*>(std::addressof(right));
    ConfigObject saved(std::move(left));
    left.~ConfigObject();
    ::new (left_storage) ConfigObject(std::move(right));
    right.~ConfigObject();
    ::new (right_storage) ConfigObject(std::move(saved));
}

} // namespace api

class ConfigError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct ConfigValidationIssue {
    std::string path;
    std::string message;
};

class ConfigValidationError : public ConfigError {
public:
    explicit ConfigValidationError(std::vector<ConfigValidationIssue> issues);

    const std::vector<ConfigValidationIssue>& issues() const noexcept {
        return issues_;
    }

private:
    static std::string build_message(const std::vector<ConfigValidationIssue>& issues);

    std::vector<ConfigValidationIssue> issues_;
};

// Type aliases: map generated QuickType names to conventional keen-pbr names.
// All config structs now live in api:: with full from_json/to_json support.
using Config               = api::ConfigObject;
using DaemonConfig         = api::Daemon;
using ApiConfig            = api::ApiConfig;
using Outbound             = api::OutboundElement;
using OutboundType         = api::OutboundType;  // enum: INTERFACE, TABLE, BLACKHOLE, IGNORE, URLTEST
using UrltestSelectionMode = api::SelectionMode; // enum: LATENCY, PRIORITY
using ConntrackOnSwitch    = api::ConntrackOnSwitch;
using OutboundGroup        = api::OutboundGroupElement;
using RetryConfig          = api::Retry;
using CircuitBreakerConfig = api::CircuitBreakerConfig;
using ListConfig           = api::ListConfigValue;
using DnsServer            = api::DnsServerElement;
using DnsTestServer        = api::DnsTestServer;
using DnsRule              = api::DnsRuleElement;
using DnsConfig            = api::Dns;
using RouteRule            = api::RouteRuleElement;
using InternalVpnServer    = api::InternalVpnServerElement;
using InternalVpnService   = api::InternalVpnServiceElement;
using RouteConfig          = api::Route;
using FwmarkConfig         = api::Fwmark;
using IprouteConfig        = api::Iproute;
using ListsAutoupdateConfig = api::ListsAutoupdate;
using ListRefreshConfig     = api::ListRefresh;
using ListRefreshDetourMode = api::RefreshDetourMode;
using PlainDnsTemplate      = api::PlainDnsTemplateElement;
using UiPreferencesConfig   = api::UiPreferences;
// Note: DnsRule.list (not .lists) and RouteRule.list (not .lists) match JSON keys.

constexpr std::size_t kDefaultMaxFileSizeBytes = std::size_t{8} * 1024U * 1024U; // 8 MiB

inline const std::vector<std::string>& route_rule_lists(const RouteRule& rule) {
    static const std::vector<std::string> empty;
    return rule.list ? *rule.list : empty;
}

inline bool route_rule_enabled(const RouteRule& rule) {
    return rule.enabled.value_or(true);
}

// Keep this predicate aligned with validate_route_rule_specs(). Protocol is a
// modifier for a real match condition, not a standalone condition by itself.
inline bool route_rule_has_non_list_match_condition(
    const RouteRule& rule) {
    return rule.dscp.has_value() ||
           rule.src_port.has_value() ||
           rule.dest_port.has_value() ||
           rule.src_addr.has_value() ||
           rule.dest_addr.has_value();
}

inline bool dns_rule_enabled(const DnsRule& rule) {
    return rule.enabled.value_or(true);
}

// --- JSON deserialization and validation ---

Config parse_config(const std::string& json_str);
void validate_config(const Config& config);
Config parse_and_validate_config(const std::string& json_str);
size_t max_file_size_bytes(const Config& config);
FirewallBackendPreference firewall_backend_preference(const Config& config);

// Resolves the URL-list download policy without rewriting legacy configs.
// An omitted mode keeps an existing per-list detour as an override and
// otherwise inherits the global list_refresh chain.
ListRefreshDetourMode effective_list_refresh_detour_mode(
    const ListConfig& list_config);
std::vector<std::string> configured_list_refresh_detours(
    const ListRefreshConfig& refresh_config);
std::vector<std::string> effective_list_refresh_detours(
    const Config& config,
    const ListConfig& list_config);

// --- Fwmark allocation ---

// Maps every routable outbound tag, including urltest selectors, to its
// assigned fwmark value. Blackhole and ignore outbounds do not consume marks.
using OutboundMarkMap = std::map<std::string, uint32_t>;

// Validates fwmark.mask and assigns sequential fwmarks to interface, table,
// and urltest outbounds. Blackhole and ignore outbounds do not get marks.
// Throws ConfigError if mask is invalid or too many outbounds for the mark space.
OutboundMarkMap allocate_outbound_marks(const FwmarkConfig& fwmark_cfg,
                                         const std::vector<Outbound>& outbounds);

uint32_t fwmark_start_value(const FwmarkConfig& fwmark_cfg);
uint32_t fwmark_mask_value(const FwmarkConfig& fwmark_cfg);

} // namespace keen_pbr3
