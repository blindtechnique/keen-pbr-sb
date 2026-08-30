#include "../src/health/differential_probe.hpp"

#include <doctest/doctest.h>

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

// Answers according to the device the caller pinned the request to, which is
// the only thing that distinguishes the two legs.
class ScriptedTransport final : public HttpTransport {
public:
    using Answer = std::function<HttpTransportResponse()>;

    std::map<std::string, Answer> by_interface;
    std::vector<HttpTransportRequest> seen;

    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        seen.push_back(request);
        const auto it = by_interface.find(request.bind_interface);
        if (it == by_interface.end()) {
            throw HttpTransportError("connection timed out");
        }
        return it->second();
    }
};

HttpTransportResponse ok(const long status = 200) {
    HttpTransportResponse response;
    response.status_code = status;
    return response;
}

HttpTransportResponse redirect_to(const std::string& location) {
    HttpTransportResponse response;
    response.status_code = 302;
    response.headers["location"] = location;
    return response;
}

ScriptedTransport::Answer answering(const long status) {
    return [status] { return ok(status); };
}

ScriptedTransport::Answer refusing(const std::string& message) {
    return [message]() -> HttpTransportResponse {
        throw HttpTransportError(message);
    };
}

ScriptedTransport::Answer unbindable() {
    return []() -> HttpTransportResponse {
        throw HttpTransportBindError("SO_BINDTODEVICE: No such device");
    };
}

DifferentialProbeRequest probe_for(const std::string& url = "https://example.com/") {
    DifferentialProbeRequest request;
    request.url = url;
    request.direct = DifferentialPath{0U, "eth3"};
    request.tunnel = DifferentialPath{0x10000U, "nwg1"};
    return request;
}

constexpr auto kReachable = PathOutcome::reachable;
constexpr auto kUnreachable = PathOutcome::unreachable;
constexpr auto kUnattributed = PathOutcome::unattributed;

}  // namespace

TEST_CASE("differential: only silence in front and an answer behind earns a route") {
    CHECK(classify_differential({kUnreachable, kReachable}) ==
          DifferentialVerdict::blocked_here);
    CHECK(differential_verdict_justifies_tunnel(DifferentialVerdict::blocked_here));
}

TEST_CASE("differential: a target that answers nowhere is not a routing problem") {
    // The trap the whole file exists for. nfqws2's counters look identical for
    // a blocked site and a dead one; sending a dead one through a tunnel hides
    // an outage behind a routing change and never recovers on its own.
    const auto verdict = classify_differential({kUnreachable, kUnreachable});

    CHECK(verdict == DifferentialVerdict::down_everywhere);
    CHECK_FALSE(differential_verdict_justifies_tunnel(verdict));
}

TEST_CASE("differential: a target that already answers needs nothing") {
    const auto verdict = classify_differential({kReachable, kReachable});

    CHECK(verdict == DifferentialVerdict::works_without_help);
    CHECK_FALSE(differential_verdict_justifies_tunnel(verdict));
}

TEST_CASE("differential: a silent tunnel says nothing about the target") {
    const auto verdict = classify_differential({kReachable, kUnreachable});

    CHECK(verdict == DifferentialVerdict::tunnel_broken);
    CHECK_FALSE(differential_verdict_justifies_tunnel(verdict));
}

TEST_CASE("differential: one unprovable leg voids the comparison") {
    // An unattributed leg is not a weak failure to be averaged in - it means we
    // cannot say which path was measured, so neither can the verdict.
    for (const auto other : {kReachable, kUnreachable, kUnattributed}) {
        CHECK(classify_differential({kUnattributed, other}) ==
              DifferentialVerdict::inconclusive);
        CHECK(classify_differential({other, kUnattributed}) ==
              DifferentialVerdict::inconclusive);
    }
    CHECK_FALSE(
        differential_verdict_justifies_tunnel(DifferentialVerdict::inconclusive));
}

TEST_CASE("differential: nothing but blocked_here may move traffic") {
    for (const auto verdict :
         {DifferentialVerdict::down_everywhere,
          DifferentialVerdict::works_without_help,
          DifferentialVerdict::tunnel_broken,
          DifferentialVerdict::inconclusive}) {
        CHECK_FALSE(differential_verdict_justifies_tunnel(verdict));
    }
}

TEST_CASE("differential: a refusal from the server is still an answer") {
    // Reachability is not success. URLTester requires 2xx and is right to, but
    // here a 403 proves the packets arrived - which is the entire question.
    ScriptedTransport transport;
    for (const auto status : {200, 204, 301, 403, 404, 500}) {
        transport.by_interface["eth3"] = answering(status);
        const auto leg = probe_one_path(transport, "https://example.com/",
                                        DifferentialPath{0U, "eth3"}, 1000U);
        CHECK(leg.outcome == kReachable);
        CHECK(leg.status_code == status);
    }
}

TEST_CASE("differential: a redirect to somebody else is interference, not an answer") {
    // The one failure shape nfqws2 itself calls DPI-specific. Following it
    // would land on the interceptor's page and score it as reachable.
    ScriptedTransport transport;
    transport.by_interface["eth3"] = [] {
        return redirect_to("http://blocked.example.gov/notice");
    };

    const auto leg = probe_one_path(transport, "https://example.com/",
                                    DifferentialPath{0U, "eth3"}, 1000U);

    CHECK(leg.outcome == kUnreachable);
    CHECK(leg.detail.find("blocked.example.gov") != std::string::npos);
    CHECK_FALSE(transport.seen.empty());
    // Following it would have destroyed the evidence.
    CHECK(transport.seen.front().max_redirects == 0);
}

TEST_CASE("differential: a redirect to the same host is ordinary") {
    ScriptedTransport transport;
    transport.by_interface["eth3"] = [] {
        return redirect_to("https://example.com/en/");
    };

    const auto leg = probe_one_path(transport, "http://example.com/",
                                    DifferentialPath{0U, "eth3"}, 1000U);

    CHECK(leg.outcome == kReachable);
}

TEST_CASE("differential: an ordinary move to www is not interference") {
    // Caught on the owner's router, not in review: facebook.com - blocked, in
    // nfqws2's own hostlist, and working through it - answers 301 to
    // www.facebook.com. Comparing hosts exactly called that a block.
    ScriptedTransport transport;
    transport.by_interface["eth3"] = [] {
        return redirect_to("https://www.facebook.com/");
    };

    const auto leg = probe_one_path(transport, "https://facebook.com/",
                                    DifferentialPath{0U, "eth3"}, 1000U);

    CHECK(leg.outcome == kReachable);
}

TEST_CASE("differential: a move between subdomains of one site is ordinary too") {
    ScriptedTransport transport;
    transport.by_interface["eth3"] = [] {
        return redirect_to("https://cdn.example.com/asset");
    };

    const auto leg = probe_one_path(transport, "https://images.example.com/",
                                    DifferentialPath{0U, "eth3"}, 1000U);

    CHECK(leg.outcome == kReachable);
}

TEST_CASE("differential: a redirect with nowhere named is not called interference") {
    ScriptedTransport transport;
    transport.by_interface["eth3"] = answering(302);

    const auto leg = probe_one_path(transport, "https://example.com/",
                                    DifferentialPath{0U, "eth3"}, 1000U);

    CHECK(leg.outcome == kReachable);
}

TEST_CASE("differential: a probe that could not be pinned proves nothing") {
    // The trap that turns a health check into a liar: reading a bind failure as
    // a failure of the target.
    ScriptedTransport transport;
    transport.by_interface["nwg1"] = unbindable();

    const auto leg = probe_one_path(transport, "https://example.com/",
                                    DifferentialPath{0x10000U, "nwg1"}, 1000U);

    CHECK(leg.outcome == kUnattributed);
    CHECK(leg.detail.find("nwg1") != std::string::npos);
}

TEST_CASE("differential: a leg with no device is refused before it leaves") {
    ScriptedTransport transport;
    transport.by_interface["eth3"] = answering(200);

    const auto leg = probe_one_path(transport, "https://example.com/",
                                    DifferentialPath{0x10000U, ""}, 1000U);

    CHECK(leg.outcome == kUnattributed);
    // A mark alone would have measured whatever routing picked, and nothing
    // afterwards could tell us which path that was.
    CHECK(transport.seen.empty());
}

TEST_CASE("differential: a transport error is the target's silence") {
    ScriptedTransport transport;
    transport.by_interface["eth3"] = refusing("TLS handshake failed");

    const auto leg = probe_one_path(transport, "https://example.com/",
                                    DifferentialPath{0U, "eth3"}, 1000U);

    CHECK(leg.outcome == kUnreachable);
    CHECK(leg.detail.find("TLS") != std::string::npos);
}

TEST_CASE("differential: the blocked case, end to end") {
    ScriptedTransport transport;
    transport.by_interface["eth3"] = refusing("connection reset by peer");
    transport.by_interface["nwg1"] = answering(200);

    const auto report = run_differential_probe(transport, probe_for());

    CHECK(report.verdict == DifferentialVerdict::blocked_here);
    CHECK(report.direct.outcome == kUnreachable);
    CHECK(report.tunnel.outcome == kReachable);
    REQUIRE(transport.seen.size() == 2U);
    CHECK(transport.seen[0].bind_interface == "eth3");
    CHECK(transport.seen[0].fwmark == 0U);
    CHECK(transport.seen[1].bind_interface == "nwg1");
    CHECK(transport.seen[1].fwmark == 0x10000U);
}

TEST_CASE("differential: an advertising endpoint nobody blocks stays put") {
    // What the naive list would have routed: it fails on the provider because
    // something local drops it, and it fails through the tunnel too.
    ScriptedTransport transport;
    transport.by_interface["eth3"] = refusing("connection refused");
    transport.by_interface["nwg1"] = refusing("connection refused");

    const auto report = run_differential_probe(
        transport, probe_for("https://pagead2.googlesyndication.com/"));

    CHECK(report.verdict == DifferentialVerdict::down_everywhere);
    CHECK_FALSE(differential_verdict_justifies_tunnel(report.verdict));
}

TEST_CASE("differential: a broken tunnel does not become a blocked site") {
    ScriptedTransport transport;
    transport.by_interface["eth3"] = answering(200);
    transport.by_interface["nwg1"] = refusing("no route to host");

    const auto report = run_differential_probe(transport, probe_for());

    CHECK(report.verdict == DifferentialVerdict::tunnel_broken);
}

TEST_CASE("differential: an unpinnable direct leg voids the whole answer") {
    ScriptedTransport transport;
    transport.by_interface["eth3"] = unbindable();
    transport.by_interface["nwg1"] = answering(200);

    const auto report = run_differential_probe(transport, probe_for());

    // Without this rule the pair would read as blocked_here and move traffic.
    CHECK(report.verdict == DifferentialVerdict::inconclusive);
    CHECK_FALSE(differential_verdict_justifies_tunnel(report.verdict));
}

TEST_CASE("differential: host extraction survives the shapes a URL comes in") {
    CHECK(differential_url_host("https://example.com/") == "example.com");
    CHECK(differential_url_host("https://Example.COM:8443/x?y=1") == "example.com");
    CHECK(differential_url_host("http://user:pw@example.com/") == "example.com");
    CHECK(differential_url_host("https://[2001:db8::1]:443/") == "2001:db8::1");
    CHECK(differential_url_host("example.com/path") == "example.com");
    CHECK(differential_url_host("").empty());
    CHECK(differential_url_host("https://").empty());
}

TEST_CASE("differential: every verdict has a name to show") {
    CHECK(std::string{differential_verdict_name(DifferentialVerdict::blocked_here)} ==
          "blocked_here");
    CHECK(std::string{differential_verdict_name(DifferentialVerdict::down_everywhere)} ==
          "down_everywhere");
    CHECK(std::string{differential_verdict_name(DifferentialVerdict::works_without_help)} ==
          "works_without_help");
    CHECK(std::string{differential_verdict_name(DifferentialVerdict::tunnel_broken)} ==
          "tunnel_broken");
    CHECK(std::string{differential_verdict_name(DifferentialVerdict::inconclusive)} ==
          "inconclusive");
}


TEST_CASE("shape: a name that is filtered while its address carries traffic") {
    // nfqws2's ground. Answering to a substituted name, or over plain HTTP,
    // proves the packets reach the address - so what is being filtered is what
    // is written on them, and desync has something to disguise.
    CHECK(classify_block_shape_from_legs(kUnreachable, kReachable, kUnreachable) ==
          BlockShape::name_based);
    CHECK(classify_block_shape_from_legs(kUnreachable, kUnreachable, kReachable) ==
          BlockShape::name_based);
}

TEST_CASE("shape: an address that dies whatever name is presented") {
    // Measured by hand on the owner's router: thumbnails.libretro.com failed
    // over TLS with its real name and with example.com substituted, while
    // plain HTTP to the same address answered in 0.13s. That mixture is
    // name_based by the rule above - the interesting case is when HTTP dies
    // too, and then no desync can help.
    CHECK(classify_block_shape_from_legs(kUnreachable, kUnreachable,
                                         kUnreachable) ==
          BlockShape::address_based);
}

TEST_CASE("shape: a direct leg that answered has nothing to classify") {
    CHECK(classify_block_shape_from_legs(kReachable, kUnreachable, kUnreachable) ==
          BlockShape::unknown);
}

TEST_CASE("shape: a leg that could not prove its path names nothing") {
    CHECK(classify_block_shape_from_legs(kUnattributed, kReachable, kReachable) ==
          BlockShape::unknown);
    // Both substitutes unprovable: the direct leg failed, but nothing says why.
    CHECK(classify_block_shape_from_legs(kUnreachable, kUnattributed,
                                         kUnattributed) == BlockShape::unknown);
}

TEST_CASE("shape: every shape has a name to show") {
    CHECK(std::string{block_shape_name(BlockShape::name_based)} == "name_based");
    CHECK(std::string{block_shape_name(BlockShape::address_based)} ==
          "address_based");
    CHECK(std::string{block_shape_name(BlockShape::unreachable)} == "unreachable");
    CHECK(std::string{block_shape_name(BlockShape::unknown)} == "unknown");
}

}  // namespace keen_pbr3
