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

std::optional<std::string> probe_host(const std::string& target) {
    if (auto ip = canonical_ip(target)) {
        return ip->find(':') == std::string::npos ? *ip : "[" + *ip + "]";
    }
    if (target.find('*') != std::string::npos || target.find('\0') != std::string::npos)
        return std::nullopt;
    auto domain = ListParser::normalize_domain(target);
    if (!domain) return std::nullopt;
    for (char& ch : *domain) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    return domain;
}

bool valid_probe_url(const std::string& target, const std::string& url) {
    const auto host = probe_host(target);
    if (!host || url.size() > 2048) return false;
    if (url.empty()) return true;
    // Only a same-host HTTPS resource on 443; no credentials, fragments,
    // alternate ports, backslash authority ambiguities or control characters.
    for (const unsigned char ch : url) if (ch <= 32 || ch == 127 || ch == '\\') return false;
    if (url.rfind("https://", 0) != 0 || url.find('#') != std::string::npos) return false;
    const auto end = url.find_first_of("/?", 8);
    auto authority = url.substr(8, end == std::string::npos ? end : end - 8);
    for (char& ch : authority) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    return authority == *host;
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

bool valid_routing_probe_options(const std::string& target, const RoutingProbeOptions& options) {
    return !options.url.empty() && valid_probe_url(target, options.url) &&
        (options.family == "ipv4" || options.family == "ipv6") &&
        (options.path == "policy" || options.path == "direct" || options.path == "outbound") &&
        (options.path == "outbound" ? !options.outbound.empty() && options.outbound.size() <= 24
                                    : options.outbound.empty());
}

RoutingHttpProbe probe_routing_http(
    const TestRoutingResult& result, const std::vector<RuleState>& realized,
    const std::string& requested_ip, Clock::time_point deadline, HttpTransport& transport,
    const std::string& url) {
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
    if (!valid_probe_url(result.target, url)) {
        observation.status = RoutingHttpProbeStatus::NotApplicable;
        observation.reason = RoutingHttpProbeReason::UnsupportedTarget;
        return observation;
    }
    observation.url = url.empty() ? "https://" + host + "/" : url;
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
    observation.timeout_ms = request.timeout_ms;
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

RoutingHttpProbe probe_routing_http_path(
    const TestRoutingResult& result, const std::vector<RuleState>& realized,
    const Config& config, const OutboundMarkMap& marks, const RoutingProbeOptions& options,
    Clock::time_point deadline, HttpTransport& transport,
    const std::function<FibAnswer(const FibQuery&)>& fib_lookup) {
    RoutingHttpProbe unavailable;
    unavailable.url = options.url;
    if (!valid_routing_probe_options(result.target, options)) {
        unavailable.reason = RoutingHttpProbeReason::UnsupportedTarget;
        return unavailable;
    }
    const auto entry = std::find_if(result.entries.begin(), result.entries.end(), [&](const auto& item) {
        const auto address = canonical_ip(item.ip);
        return address && (address->find(':') != std::string::npos) == (options.family == "ipv6");
    });
    if (entry == result.entries.end()) {
        unavailable.reason = RoutingHttpProbeReason::DestinationChanged;
        return unavailable; // DNS error/no address of this family stays in result.
    }
    if (options.path == "policy") {
        return probe_routing_http(result, realized, entry->ip, deadline, transport, options.url);
    }
    unavailable.ip = entry->ip;
    // A selected egress is a separate experiment, not a rewrite of the rule
    // evaluation and not evidence that client traffic used this path.
    std::uint32_t mark = 0;
    std::string device;
    if (options.path == "outbound") {
        if (!config.outbounds) {
            unavailable.reason = RoutingHttpProbeReason::NoRoute;
            return unavailable;
        }
        const auto outbound = std::find_if(config.outbounds->begin(), config.outbounds->end(),
            [&](const auto& item) { return item.tag == options.outbound; });
        const auto assigned = marks.find(options.outbound);
        if (outbound == config.outbounds->end() || outbound->type != OutboundType::INTERFACE ||
            !outbound->interface || outbound->interface->empty() || assigned == marks.end() ||
            assigned->second == 0) {
            unavailable.reason = RoutingHttpProbeReason::NoRoute;
            return unavailable;
        }
        mark = assigned->second;
        device = *outbound->interface;
    }
    if (Clock::now() >= deadline || !fib_lookup) {
        unavailable.reason = RoutingHttpProbeReason::BudgetExhausted;
        return unavailable;
    }
    const auto answer = fib_lookup(FibQuery{entry->ip, mark});
    if (answer.verdict != FibVerdict::resolved || answer.interface.empty() ||
        (!device.empty() && answer.interface != device)) {
        unavailable.reason = RoutingHttpProbeReason::NoRoute;
        return unavailable; // Never turn a missing VPN route into a WAN success.
    }
    TestRoutingResult selected;
    selected.target = result.target;
    TestRoutingEntry row{};
    row.ip = entry->ip;
    row.actual_outbound = mark == 0 ? "(default)" : options.outbound;
    row.evaluation = RoutingMatchEvaluation::Matched;
    row.fib.verdict = RoutingFibVerdict::Resolved;
    row.fib.fwmark = mark;
    row.fib.table = answer.table;
    row.fib.interface = answer.interface;
    std::vector<RuleState> selection;
    if (mark != 0) {
        RuleState rule{};
        rule.rule_index = 0;
        rule.action_type = RuleActionType::Mark;
        rule.fwmark = mark;
        row.actual_rule_index = 0;
        selection.push_back(rule);
    }
    selected.entries.push_back(std::move(row));
    return probe_routing_http(selected, selection, entry->ip, deadline, transport, options.url);
}

} // namespace keen_pbr3
