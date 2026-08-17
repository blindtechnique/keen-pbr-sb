#pragma once

#include "../cache/cache_manager.hpp"
#include "../config/config.hpp"
#include "../routing/firewall_state.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {

using RoutingTestDeadline = std::chrono::steady_clock::time_point;
inline constexpr auto kRoutingTestOperationTimeout =
    std::chrono::seconds{45};
inline constexpr auto kRoutingTestResponseSendTimeout =
    std::chrono::seconds{5};
inline constexpr auto kRoutingTestClientResponseTimeout =
    std::chrono::seconds{60};
static_assert(
    kRoutingTestOperationTimeout +
        kRoutingTestResponseSendTimeout <
    kRoutingTestClientResponseTimeout,
    "routing test server deadlines must finish before the client timeout");

class RoutingTestTimeoutError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class RoutingMatchEvaluation {
    Matched,
    NotMatched,
    InsufficientContext,
};

const char* routing_match_evaluation_code(
    RoutingMatchEvaluation evaluation) noexcept;

struct ListMatchInfo {
    std::string list_name;
    std::string via; // specific entry that triggered match: an IP, CIDR, or domain
};

struct TestRoutingEntry {
    std::string ip;
    std::optional<ListMatchInfo> list_match;
    std::string expected_outbound; // rule outbound tag, or "(default)"
    std::string actual_outbound;   // tag, "(default)", or "(unknown)" if kernel check unavailable
    bool ok;
    RoutingMatchEvaluation evaluation{RoutingMatchEvaluation::NotMatched};
    std::vector<std::string> unknown_conditions;
};

struct RuleIpDiagnostic {
    std::string ip;
    bool in_lists{false};
    std::optional<ListMatchInfo> list_match;
    // true/false when checked against live firewall set, null when unavailable.
    std::optional<bool> in_ipset;
    RoutingMatchEvaluation evaluation{RoutingMatchEvaluation::NotMatched};
    std::vector<std::string> unknown_conditions;
};

struct RuleDiagnostic {
    int rule_index{0};
    RouteRule rule;
    std::string outbound;
    std::string interface_name; // "-" when unknown/not applicable
    bool target_in_lists{false};
    std::optional<ListMatchInfo> target_match;
    std::vector<RuleIpDiagnostic> ip_rows;
};

struct TestRoutingResult {
    std::string target;
    bool is_domain{false};
    std::vector<std::string> resolved_ips;
    std::vector<TestRoutingEntry> entries;
    std::vector<RuleDiagnostic> rule_diagnostics;
    bool no_matching_rule{false};
    std::optional<std::string> dns_error;
    std::vector<std::string> warnings;
    bool unapplied_draft{false};
};

// Compute expected (config+cache) and actual (kernel ipset/nftset) routing for
// target. Daemon callers pass the backend captured with realized_rule_states;
// offline callers may omit it and retain tool autodetection.
TestRoutingResult compute_test_routing(const Config& config,
                                        const CacheManager& cache,
                                        const std::string& target,
                                        const std::vector<RuleState>* realized_rule_states = nullptr,
                                        std::optional<RoutingTestDeadline> deadline = std::nullopt,
                                        std::optional<FirewallBackend> realized_firewall_backend = std::nullopt);

#ifdef KEEN_PBR3_TESTING
// Deterministic failure seams for exception-safety regressions. Each injected
// failure is consumed once.
void inject_test_routing_worker_creation_failure(std::size_t worker_index);
void inject_test_routing_dns_socket_failure();
#endif

// Print table and return 0 if all entries match, 1 otherwise.
int run_test_routing_command(const Config& config,
                              const CacheManager& cache,
                              const std::string& target);

// Render a test-routing response obtained from the daemon control socket.
int run_test_routing_command(const nlohmann::json& response);

} // namespace keen_pbr3
