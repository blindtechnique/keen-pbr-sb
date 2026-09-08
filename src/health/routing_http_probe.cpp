#include "routing_http_probe.hpp"

#include "../cmd/test_routing.hpp"
#include "../config/list_parser.hpp"

#include <algorithm>
#include <array>
#include <arpa/inet.h>

namespace keen_pbr3 {
namespace {
using Clock = std::chrono::steady_clock;

std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::optional<std::string> canonical_ip(const std::string& value) {
    if (value.empty() || value.find('\0') != std::string::npos) return std::nullopt;
    std::array<unsigned char, 16> address{};
    int family = AF_INET;
    if (inet_pton(family, value.c_str(), address.data()) != 1) {
        family = AF_INET6;
        if (inet_pton(family, value.c_str(), address.data()) != 1) return std::nullopt;
    }
    std::array<char, INET6_ADDRSTRLEN> text{};
    if (!inet_ntop(family, address.data(), text.data(), text.size())) return std::nullopt;
    return std::string(text.data());
}

RoutingHttpProbeReason error_reason(HttpTransportError::Reason reason) {
    switch (reason) {
        case HttpTransportError::Reason::timeout: return RoutingHttpProbeReason::Timeout;
        case HttpTransportError::Reason::tls: return RoutingHttpProbeReason::TlsError;
        case HttpTransportError::Reason::connect: return RoutingHttpProbeReason::ConnectionFailed;
        case HttpTransportError::Reason::mark: return RoutingHttpProbeReason::BindingFailed;
        case HttpTransportError::Reason::response_limit: return RoutingHttpProbeReason::ResponseLimit;
        case HttpTransportError::Reason::resolve:
        case HttpTransportError::Reason::other: return RoutingHttpProbeReason::TransportError;
    }
    return RoutingHttpProbeReason::TransportError;
}
} // namespace

RoutingHttpProbe probe_routing_http(
    const TestRoutingResult& result, const std::vector<RuleState>& realized,
    const std::string& requested_ip, Clock::time_point deadline, HttpTransport& transport) {
    RoutingHttpProbe observation;
    observation.ip = requested_ip;
    const auto address = canonical_ip(requested_ip);
    if (!address) {
        observation.status = RoutingHttpProbeStatus::NotApplicable;
        observation.reason = RoutingHttpProbeReason::UnsupportedTarget;
        return observation;
    }
    observation.ip = *address;
    const auto entry = std::find_if(result.entries.begin(), result.entries.end(),
        [&](const TestRoutingEntry& item) { return canonical_ip(item.ip) == address; });
    if (entry == result.entries.end()) {
        observation.reason = RoutingHttpProbeReason::DestinationChanged;
        return observation;
    }

    const auto literal = canonical_ip(result.target);
    std::string host;
    if (literal) {
        if (*literal != *address) {
            observation.reason = RoutingHttpProbeReason::DestinationChanged;
            return observation;
        }
        host = literal->find(':') == std::string::npos ? *literal : "[" + *literal + "]";
    } else {
        // List normalization also accepts wildcard lists, which are not HTTP
        // hosts. Do not turn a supplied URL/path/userinfo into another target.
        const auto domain = result.target.find('*') == std::string::npos
            ? ListParser::normalize_domain(result.target) : std::nullopt;
        if (!domain) {
            observation.status = RoutingHttpProbeStatus::NotApplicable;
            observation.reason = RoutingHttpProbeReason::UnsupportedTarget;
            return observation;
        }
        host = *domain;
        for (char& ch : host) {
            if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    observation.url = "https://" + host + "/";
    if (entry->evaluation == RoutingMatchEvaluation::InsufficientContext ||
        entry->actual_outbound.empty() || entry->actual_outbound == "(unknown)") {
        observation.status = RoutingHttpProbeStatus::NotApplicable;
        observation.reason = RoutingHttpProbeReason::ContextRequired;
        return observation;
    }

    const int family = address->find(':') == std::string::npos ? AF_INET : AF_INET6;
    std::uint32_t mark = 0;
    if (entry->actual_rule_index) {
        const auto rule = std::find_if(realized.begin(), realized.end(),
            [&](const RuleState& candidate) { return candidate.rule_index == *entry->actual_rule_index; });
        if (rule == realized.end() || rule->action_type == RuleActionType::Skip) {
            observation.reason = RoutingHttpProbeReason::ContextRequired;
            return observation;
        }
        if (rule->action_type == RuleActionType::Drop) {
            observation.status = RoutingHttpProbeStatus::NotApplicable;
            observation.reason = RoutingHttpProbeReason::BlockedRoute;
            return observation;
        }
        if (rule->action_type == RuleActionType::Mark) {
            mark = rule->mark_for_family(family);
            if (mark == 0 || !entry->fib.fwmark || *entry->fib.fwmark != mark) {
                observation.reason = RoutingHttpProbeReason::NoRoute;
                return observation;
            }
        } else if (entry->fib.fwmark.value_or(0) != 0) {
            observation.reason = RoutingHttpProbeReason::ContextRequired;
            return observation;
        }
    } else if (entry->actual_outbound != "(default)" || entry->fib.fwmark.value_or(0) != 0) {
        observation.reason = RoutingHttpProbeReason::ContextRequired;
        return observation;
    }
    observation.fwmark = mark;
    observation.table = entry->fib.table;
    observation.interface = entry->fib.interface;
    if (entry->fib.verdict != RoutingFibVerdict::Resolved || entry->fib.interface.empty()) {
        observation.reason = RoutingHttpProbeReason::NoRoute;
        return observation;
    }

    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
    if (remaining.count() <= 0) {
        observation.reason = RoutingHttpProbeReason::BudgetExhausted;
        return observation;
    }
    HttpTransportRequest request;
    request.url = observation.url;
    request.fwmark = mark;
    request.bind_interface = observation.interface;
    request.timeout_ms = static_cast<long>(std::min<std::int64_t>(5000, remaining.count()));
    request.user_agent = "keen-pbr-sb routing diagnostic";
    request.head_only = true;
    request.follow_redirects = false;
    request.max_redirects = 0;
    request.discard_body = true;
    request.max_header_size = 16U * 1024U;
    if (!literal) {
        // IPv6 ADDRESS is supported by old router curl; an IPv6 HOST key is
        // not, so literal IPv6 URLs deliberately need no RESOLVE entry.
        request.resolve_entries.push_back(host + ":443:" +
            (family == AF_INET6 ? "[" + *address + "]" : *address));
    }
    request.destination_filter = [address](const std::string& connected) {
        return canonical_ip(connected) == address;
    };
    const auto started = Clock::now();
    observation.attempted_at = now_seconds();
    try {
        const auto response = transport.perform(request);
        observation.elapsed_ms = response.elapsed.count();
        if (response.connect_elapsed) observation.connect_ms = response.connect_elapsed->count();
        if (response.tls_elapsed) observation.tls_ms = response.tls_elapsed->count();
        if (response.primary_ip) observation.connected_ip = canonical_ip(*response.primary_ip);
        if (response.status_code >= 100 && response.status_code <= 599) {
            observation.status = RoutingHttpProbeStatus::Answered;
            observation.reason = RoutingHttpProbeReason::HttpResponse;
            observation.http_status = response.status_code;
        } else {
            observation.status = RoutingHttpProbeStatus::Failed;
            observation.reason = RoutingHttpProbeReason::TransportError;
        }
    } catch (const HttpTransportBindError&) {
        observation.status = RoutingHttpProbeStatus::Failed;
        observation.reason = RoutingHttpProbeReason::BindingFailed;
    } catch (const HttpTransportError& error) {
        observation.status = RoutingHttpProbeStatus::Failed;
        observation.reason = error_reason(error.reason());
    } catch (...) {
        // Optional HTTP evidence never discards the DNS/rule/FIB result.
        observation.status = RoutingHttpProbeStatus::Failed;
        observation.reason = RoutingHttpProbeReason::TransportError;
    }
    if (!observation.elapsed_ms) {
        observation.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
    }
    return observation;
}

} // namespace keen_pbr3
