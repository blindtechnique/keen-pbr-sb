#include <doctest/doctest.h>

#include "../src/health/routing_http_probe.hpp"
#include "../src/cmd/test_routing.hpp"

#include <chrono>
#include <functional>
#include <stdexcept>

namespace keen_pbr3 {
namespace {
using ProbeClock = std::chrono::steady_clock;

class RoutingProbeTransport final : public HttpTransport {
public:
    int calls{0};
    HttpTransportRequest request;
    std::function<HttpTransportResponse(const HttpTransportRequest&)> handler;
    HttpTransportResponse perform(const HttpTransportRequest& value) override {
        ++calls;
        request = value;
        if (handler) return handler(value);
        HttpTransportResponse response;
        response.status_code = 204;
        response.elapsed = std::chrono::milliseconds(34);
        response.primary_ip = "203.0.113.8";
        response.connect_elapsed = std::chrono::milliseconds(12);
        response.tls_elapsed = std::chrono::milliseconds(22);
        return response;
    }
};

TestRoutingResult probe_result(std::string ip = "203.0.113.8") {
    TestRoutingResult result;
    result.target = "Example.COM.";
    result.is_domain = true;
    result.resolved_ips = {ip};
    TestRoutingEntry entry;
    entry.ip = std::move(ip);
    entry.expected_outbound = "other";
    entry.actual_outbound = "vpn";
    entry.ok = false; // HTTP follows actual routing, even if configuration differs.
    entry.expected_rule_index = 2;
    entry.actual_rule_index = 7;
    entry.evaluation = RoutingMatchEvaluation::Matched;
    entry.fib.verdict = RoutingFibVerdict::Resolved;
    entry.fib.fwmark = 0x8040001U;
    entry.fib.table = 152U;
    entry.fib.interface = "nwg1";
    result.entries.push_back(entry);
    return result;
}

std::vector<RuleState> probe_rules() {
    RuleState other{};
    other.rule_index = 2;
    other.action_type = RuleActionType::Mark;
    other.fwmark = 0x20000;
    RuleState actual{};
    actual.rule_index = 7;
    actual.action_type = RuleActionType::Mark;
    actual.fwmark = 0x8040001U;
    actual.fwmark_ipv6 = 0x8060001U;
    // Captured indices are not vector positions and not expected rule 2.
    return {actual, other};
}

auto probe_deadline() { return ProbeClock::now() + std::chrono::seconds(30); }
} // namespace

TEST_CASE("routing HTTP pins one actual marked IP with host SNI and bounded HEAD") {
    RoutingProbeTransport transport;
    transport.handler = [](const HttpTransportRequest&) {
        HttpTransportResponse response;
        response.status_code = 403;
        response.elapsed = std::chrono::milliseconds(34);
        response.primary_ip = "203.0.113.8";
        response.connect_elapsed = std::chrono::milliseconds(12);
        response.tls_elapsed = std::chrono::milliseconds(22);
        return response;
    };
    const auto result = probe_result();
    const auto observation = probe_routing_http(result, probe_rules(), "203.0.113.8", probe_deadline(), transport);
    REQUIRE(transport.calls == 1);
    CHECK(transport.request.url == "https://example.com/");
    CHECK(transport.request.resolve_entries == std::vector<std::string>{"example.com:443:203.0.113.8"});
    CHECK(transport.request.head_only);
    CHECK_FALSE(transport.request.follow_redirects);
    CHECK(transport.request.max_redirects == 0);
    CHECK(transport.request.headers.empty());
    CHECK(transport.request.bind_interface == "nwg1");
    CHECK(transport.request.fwmark == 0x8040001U);
    CHECK(transport.request.timeout_ms == 5000);
    CHECK(transport.request.max_header_size == 16384);
    REQUIRE(static_cast<bool>(transport.request.destination_filter));
    CHECK(transport.request.destination_filter("203.0.113.8"));
    CHECK_FALSE(transport.request.destination_filter("203.0.113.80"));
    CHECK_FALSE(transport.request.destination_filter("::ffff:203.0.113.8"));
    CHECK_FALSE(transport.request.destination_filter(std::string("203.0.113.8\0x", 13)));
    CHECK(observation.status == RoutingHttpProbeStatus::Answered);
    CHECK(observation.reason == RoutingHttpProbeReason::HttpResponse);
    CHECK(observation.http_status == 403);
    CHECK(observation.fwmark == 0x8040001U);
    CHECK(observation.table == 152U);
    CHECK(observation.elapsed_ms == 34);
    CHECK(observation.connect_ms == 12);
    CHECK(observation.tls_ms == 22);
    CHECK(observation.connected_ip == "203.0.113.8");
    CHECK(observation.attempted_at > 0);
    CHECK_FALSE(result.entries.front().ok);
}

TEST_CASE("routing HTTP canonicalizes IPv6 and avoids unsupported IPv6 resolve host keys") {
    RoutingProbeTransport transport;
    auto result = probe_result("2001:DB8:0:0::8");
    result.entries.front().fib.fwmark = 0x8060001U;
    bool literal = false;
    SUBCASE("domain keeps hostname and pins bracketed IPv6 address") {}
    SUBCASE("IPv6 literal URL needs no resolve entry") {
        literal = true;
        result.target = "2001:DB8::8";
        result.is_domain = false;
    }
    const auto observation = probe_routing_http(result, probe_rules(), "2001:db8::8", probe_deadline(), transport);
    REQUIRE(transport.calls == 1);
    CHECK(observation.ip == "2001:db8::8");
    CHECK(observation.fwmark == 0x8060001U);
    CHECK(transport.request.destination_filter("2001:db8:0:0:0:0:0:8"));
    CHECK_FALSE(transport.request.destination_filter("2001:db8::80"));
    if (literal) {
        CHECK(transport.request.url == "https://[2001:db8::8]/");
        CHECK(transport.request.resolve_entries.empty());
    } else {
        CHECK(transport.request.url == "https://example.com/");
        CHECK(transport.request.resolve_entries == std::vector<std::string>{"example.com:443:[2001:db8::8]"});
    }
}

TEST_CASE("routing HTTP supports conclusive default and pass with an unmarked bound request") {
    RoutingProbeTransport transport;
    auto result = probe_result();
    auto rules = probe_rules();
    auto& entry = result.entries.front();
    entry.fib.fwmark.reset();
    entry.fib.interface = "ppp0";
    SUBCASE("ordinary default route has no actual rule index") {
        entry.actual_rule_index.reset();
        entry.actual_outbound = "(default)";
        entry.evaluation = RoutingMatchEvaluation::NotMatched;
        result.target = "203.0.113.8";
    }
    SUBCASE("pass is an actual rule with no routing mark") {
        rules.front().action_type = RuleActionType::Pass;
    }
    const auto observation = probe_routing_http(result, rules, "203.0.113.8", probe_deadline(), transport);
    CHECK(transport.calls == 1);
    CHECK(transport.request.fwmark == 0);
    CHECK(transport.request.bind_interface == "ppp0");
    CHECK(observation.fwmark == 0);
    CHECK(observation.status == RoutingHttpProbeStatus::Answered);
}

TEST_CASE("routing HTTP skips blocked unknown missing and inconsistent captured routing") {
    RoutingProbeTransport transport;
    auto result = probe_result();
    auto rules = probe_rules();
    auto reason = RoutingHttpProbeReason::ContextRequired;
    SUBCASE("DROP does not bypass the firewall by creating router traffic") {
        rules.front().action_type = RuleActionType::Drop;
        result.entries.front().fib.verdict = RoutingFibVerdict::NotApplicable;
        reason = RoutingHttpProbeReason::BlockedRoute;
    }
    SUBCASE("unknown source or port cannot imply TCP 443 rule match") {
        result.entries.front().evaluation = RoutingMatchEvaluation::InsufficientContext;
    }
    SUBCASE("unknown actual route") { result.entries.front().actual_outbound = "(unknown)"; }
    SUBCASE("captured actual index not present") { rules.erase(rules.begin()); }
    SUBCASE("FIB has no route") {
        result.entries.front().fib.verdict = RoutingFibVerdict::Unroutable;
        reason = RoutingHttpProbeReason::NoRoute;
    }
    SUBCASE("no interface to attribute the connection") {
        result.entries.front().fib.interface.clear();
        reason = RoutingHttpProbeReason::NoRoute;
    }
    SUBCASE("captured family mark is not the FIB mark") {
        result.entries.front().fib.fwmark = 0x20000;
        reason = RoutingHttpProbeReason::NoRoute;
    }
    const auto observation = probe_routing_http(result, rules, "203.0.113.8", probe_deadline(), transport);
    CHECK(transport.calls == 0);
    CHECK(observation.reason == reason);
    CHECK(observation.attempted_at == 0);
    CHECK_FALSE(observation.http_status.has_value());
    CHECK_FALSE(observation.elapsed_ms.has_value());
}

TEST_CASE("routing HTTP reports changed DNS separately and rejects URL credentials paths or wildcard hosts") {
    RoutingProbeTransport transport;
    auto result = probe_result();
    result.entries.clear();
    auto observation = probe_routing_http(result, probe_rules(), "2001:DB8::8", probe_deadline(), transport);
    CHECK(observation.ip == "2001:db8::8");
    CHECK(observation.reason == RoutingHttpProbeReason::DestinationChanged);
    CHECK(observation.status == RoutingHttpProbeStatus::Unavailable);
    for (const auto& target : {"https://example.com/private", "user:pass@example.com", "*.example.com", "example.com:8443", "example.com/path"}) {
        result = probe_result();
        result.target = target;
        observation = probe_routing_http(result, probe_rules(), "203.0.113.8", probe_deadline(), transport);
        CHECK(observation.reason == RoutingHttpProbeReason::UnsupportedTarget);
        CHECK(observation.url.empty());
    }
    for (const auto& address : {"203.0.113.8/32", "203.0.113.999", "2001:db8:::8", "example.com"}) {
        observation = probe_routing_http(probe_result(), probe_rules(), address, probe_deadline(), transport);
        CHECK(observation.reason == RoutingHttpProbeReason::UnsupportedTarget);
    }
    CHECK(transport.calls == 0);
}

TEST_CASE("routing HTTP shares the caller deadline without sleeps or zero curl timeout") {
    RoutingProbeTransport transport;
    const auto expired = probe_routing_http(probe_result(), probe_rules(), "203.0.113.8", ProbeClock::now(), transport);
    CHECK(expired.reason == RoutingHttpProbeReason::BudgetExhausted);
    CHECK(expired.attempted_at == 0);
    CHECK(transport.calls == 0);
    const auto bounded = probe_routing_http(probe_result(), probe_rules(), "203.0.113.8",
        ProbeClock::now() + std::chrono::seconds(1), transport);
    CHECK(transport.calls == 1);
    CHECK(transport.request.timeout_ms > 0);
    CHECK(transport.request.timeout_ms <= 1000);
    CHECK(bounded.status == RoutingHttpProbeStatus::Answered);
}

TEST_CASE("routing HTTP maps typed errors without parsing text or changing routing result") {
    const std::vector<std::pair<HttpTransportError::Reason, RoutingHttpProbeReason>> cases{
        {HttpTransportError::Reason::timeout, RoutingHttpProbeReason::Timeout},
        {HttpTransportError::Reason::tls, RoutingHttpProbeReason::TlsError},
        {HttpTransportError::Reason::connect, RoutingHttpProbeReason::ConnectionFailed},
        {HttpTransportError::Reason::mark, RoutingHttpProbeReason::BindingFailed},
        {HttpTransportError::Reason::response_limit, RoutingHttpProbeReason::ResponseLimit},
        {HttpTransportError::Reason::resolve, RoutingHttpProbeReason::TransportError},
        {HttpTransportError::Reason::other, RoutingHttpProbeReason::TransportError},
    };
    const auto result = probe_result();
    for (const auto& item : cases) {
        RoutingProbeTransport transport;
        transport.handler = [&](const HttpTransportRequest&) -> HttpTransportResponse {
            throw HttpTransportError("The same text for every category", item.first);
        };
        const auto observation = probe_routing_http(result, probe_rules(), "203.0.113.8", probe_deadline(), transport);
        CHECK(transport.calls == 1);
        CHECK(observation.status == RoutingHttpProbeStatus::Failed);
        CHECK(observation.reason == item.second);
        CHECK(observation.elapsed_ms.has_value());
        CHECK_FALSE(observation.http_status.has_value());
        CHECK(result.entries.front().actual_rule_index == 7);
        CHECK(result.entries.front().fib.fwmark == 0x8040001U);
    }
    RoutingProbeTransport transport;
    transport.handler = [](const HttpTransportRequest&) -> HttpTransportResponse { throw HttpTransportBindError("bind"); };
    CHECK(probe_routing_http(result, probe_rules(), "203.0.113.8", probe_deadline(), transport).reason == RoutingHttpProbeReason::BindingFailed);
    transport.handler = [](const HttpTransportRequest&) -> HttpTransportResponse { throw std::runtime_error("unexpected adapter failure"); };
    CHECK(probe_routing_http(result, probe_rules(), "203.0.113.8", probe_deadline(), transport).reason == RoutingHttpProbeReason::TransportError);
}

TEST_CASE("routing HTTP treats redirects and HEAD refusal as answers not body fetches") {
    for (const long status : {301L, 405L, 503L}) {
        RoutingProbeTransport transport;
        transport.handler = [status](const HttpTransportRequest&) {
            HttpTransportResponse response;
            response.status_code = status;
            response.headers["location"] = "https://other.example/private";
            return response;
        };
        const auto observation = probe_routing_http(probe_result(), probe_rules(), "203.0.113.8", probe_deadline(), transport);
        CHECK(transport.calls == 1);
        CHECK(observation.status == RoutingHttpProbeStatus::Answered);
        CHECK(observation.http_status == status);
        CHECK_FALSE(transport.request.follow_redirects);
        CHECK(transport.request.head_only);
    }
}
} // namespace keen_pbr3
