#pragma once

#include "../http/http_transport.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct TestRoutingResult;
struct RuleState;
struct FibQuery;
struct FibAnswer;
namespace api { struct ConfigObject; }

// One row of a user-started comparison, never a persistent health task.
struct RoutingProbeOptions {
    std::string url;
    std::string family{"ipv4"};
    std::string path{"policy"};
    std::string outbound;
};

bool valid_routing_probe_options(const std::string& target,
                                 const RoutingProbeOptions& options);

enum class RoutingHttpProbeStatus { Answered, Failed, NotApplicable, Unavailable };
enum class RoutingHttpProbeReason {
    HttpResponse, ContextRequired, NoRoute, DestinationChanged, BlockedRoute,
    BindingFailed, TlsError, Timeout, ConnectionFailed, UnsupportedTarget,
    TransportError, BudgetExhausted, ResponseLimit,
};

struct RoutingHttpProbe {
    RoutingHttpProbeStatus status{RoutingHttpProbeStatus::Unavailable};
    RoutingHttpProbeReason reason{RoutingHttpProbeReason::TransportError};
    std::string ip;
    std::string url;
    std::string interface;
    std::int64_t attempted_at{0};
    std::int64_t timeout_ms{0};
    std::optional<std::uint32_t> fwmark;
    std::optional<std::uint32_t> table;
    std::optional<long> http_status;
    std::optional<std::int64_t> elapsed_ms;
    // Both values are cumulative from transfer start, not phase durations.
    std::optional<std::int64_t> connect_ms;
    std::optional<std::int64_t> tls_ms;
    std::optional<std::string> connected_ip;
};

// Exactly one explicit HEAD to one address from the freshly computed result.
// The URL keeps the original host for Host/SNI; the address, full mark and
// interface are pinned from server observations, never supplied by the client.
// This observes router-originated traffic, not client PREROUTING processing.
RoutingHttpProbe probe_routing_http(
    const TestRoutingResult& result, const std::vector<RuleState>& realized,
    const std::string& requested_ip, std::chrono::steady_clock::time_point deadline,
    HttpTransport& transport, const std::string& url = {});

RoutingHttpProbe probe_routing_http_path(
    const TestRoutingResult& result, const std::vector<RuleState>& realized,
    const api::ConfigObject& config, const std::map<std::string, std::uint32_t>& marks,
    const RoutingProbeOptions& options, std::chrono::steady_clock::time_point deadline,
    HttpTransport& transport, const std::function<FibAnswer(const FibQuery&)>& fib_lookup);

} // namespace keen_pbr3
