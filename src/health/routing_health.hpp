#pragma once

#include "../firewall/firewall.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class CheckStatus {
    ok,
    missing,
    mismatch
};

struct FirewallChainCheck {
    bool chain_present{false};
    bool prerouting_hook_present{false};
    std::string detail;
};

struct FirewallRuleCheck {
    std::string set_name;
    std::string action;
    std::optional<uint32_t> expected_fwmark;
    std::optional<uint32_t> actual_fwmark;
    CheckStatus status{CheckStatus::missing};
    std::string detail;
};

struct RouteTableCheck {
    uint32_t table_id{0};
    std::string outbound_tag;
    std::optional<std::string> expected_destination;
    std::optional<std::string> expected_interface;
    std::optional<std::string> expected_gateway;
    std::optional<uint32_t> expected_metric;
    std::optional<std::string> expected_route_type;
    bool table_exists{false};
    bool default_route_present{false};
    bool interface_matches{false};
    bool gateway_matches{false};
    CheckStatus status{CheckStatus::missing};
    std::string detail;
};

struct PolicyRuleCheck {
    uint32_t fwmark{0};
    uint32_t fwmask{0};
    uint32_t expected_table{0};
    uint32_t priority{0};
    bool rule_present_v4{false};
    bool rule_present_v6{false};
    CheckStatus status{CheckStatus::missing};
    std::string detail;
};

// The system-auth verdict as the web server sees it. Carried as plain values
// so the health layer never has to link against the auth machinery just to
// report what it concluded.
struct SystemAuthHealthSnapshot {
    std::string state;
    std::string detail;
    std::int64_t forwarded_failures_per_window{0};
};

struct RoutingHealthReport {
    bool overall_ok{false};
    std::optional<FirewallBackend> firewall_backend;
    // State of the owned TTL bypass rule. Reported separately from the
    // overall verdict on purpose: neither "the firmware chain is absent" nor
    // "a kernel match is missing" is a keen-pbr fault, and folding either into
    // a global DEGRADED would train the operator to ignore the flag that also
    // reports a chain being rewritten underneath us.
    std::string ttl_bypass_state;
    std::string ttl_bypass_detail;
    std::optional<PpeDeoffloadSnapshot> ppe_deoffload;
    // Whether the router's own authentication is proven usable in place of the
    // password in auth.json. Like the TTL bypass above, kept out of the overall
    // verdict: none of its refusals is a routing fault, and degrading the whole
    // report for them would teach the operator to skip the field.
    std::string system_auth_state;
    std::string system_auth_detail;
    std::optional<std::int64_t> system_auth_forwarded_failures_per_window;
    FirewallChainCheck firewall_chain;
    std::vector<FirewallRuleCheck> firewall_rules;
    std::vector<RouteTableCheck> route_tables;
    std::vector<PolicyRuleCheck> policy_rules;
    std::string error;
};

} // namespace keen_pbr3
