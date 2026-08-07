#include <doctest/doctest.h>

#include "../src/health/interface_probe.hpp"

#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

// Records what the probe asked the network for, and answers however the test
// needs, so no real interface or server is involved.
class RecordingTransport final : public HttpTransport {
public:
    std::vector<HttpTransportRequest> requests;
    bool fail{false};

    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        requests.push_back(request);
        if (fail) {
            throw HttpTransportError("HTTP request failed: Connection timed out");
        }
        HttpTransportResponse response;
        response.status_code = 204;
        response.elapsed = std::chrono::milliseconds(163);
        return response;
    }
};

// The production retry waits 500 ms between attempts. Tests take a single
// attempt so the failure path costs no wall-clock time.
RetryConfig single_attempt() {
    RetryConfig retry;
    retry.attempts = 1;
    retry.interval_ms = 0;
    return retry;
}

} // namespace

TEST_CASE("interface probe pins each request to the outbound's own device") {
    auto transport = std::make_shared<RecordingTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());

    probe.probe({InterfaceProbe::Target{"moooawg", 0x30000, "nwg1"}});

    REQUIRE_FALSE(transport->requests.empty());
    CHECK(transport->requests.front().bind_interface == "nwg1");
    CHECK(transport->requests.front().fwmark == 0x30000);

    const auto result = probe.result_for("moooawg");
    REQUIRE(result.has_value());
    CHECK(result->success);
    CHECK(result->attributed);
    CHECK(result->latency_ms == 163);
}

// An outbound shape with no device to bind to cannot be measured: the mark
// alone would fall through to main and report the router's own WAN.
TEST_CASE("interface probe marks a result unattributed when it cannot pin it") {
    auto transport = std::make_shared<RecordingTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());

    probe.probe({InterfaceProbe::Target{"shapeless", 0x40000, ""}});

    REQUIRE_FALSE(transport->requests.empty());
    CHECK(transport->requests.front().bind_interface.empty());

    const auto result = probe.result_for("shapeless");
    REQUIRE(result.has_value());
    // The request itself succeeded, but it proves nothing about the outbound.
    CHECK(result->success);
    CHECK_FALSE(result->attributed);
}

TEST_CASE("interface probe records a pinned failure as a failure") {
    auto transport = std::make_shared<RecordingTransport>();
    transport->fail = true;
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());

    probe.probe({InterfaceProbe::Target{"dead_tunnel", 0x80000, "hy1"}});

    const auto result = probe.result_for("dead_tunnel");
    REQUIRE(result.has_value());
    CHECK_FALSE(result->success);
    CHECK(result->attributed);
    CHECK_FALSE(result->error.empty());
}

// The signal the failover group acts on: a member that was carrying traffic
// stops answering.
TEST_CASE("interface probe reports a verified transport going down") {
    auto transport = std::make_shared<RecordingTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());
    const InterfaceProbe::Target target{"tunnel", 0x80000, "hy1"};

    CHECK(probe.probe({target}).empty());

    transport->fail = true;
    const auto transitioned = probe.probe({target});
    REQUIRE(transitioned.size() == 1);
    CHECK(transitioned.front() == "tunnel");

    // ...and coming back is a transition too, or the group never returns to it.
    transport->fail = false;
    const auto recovered = probe.probe({target});
    REQUIRE(recovered.size() == 1);
    CHECK(recovered.front() == "tunnel");
}

TEST_CASE("interface probe reports losing attribution as a transition") {
    auto transport = std::make_shared<RecordingTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());

    // A verified transport establishes the baseline.
    const auto baseline =
        probe.probe({InterfaceProbe::Target{"tunnel", 0x80000, "hy1"}});
    CHECK(baseline.empty());

    // The same tag can no longer be pinned. The previous green must stop
    // being trusted, so the failover group is told to re-test.
    const auto transitioned =
        probe.probe({InterfaceProbe::Target{"tunnel", 0x80000, ""}});
    REQUIRE(transitioned.size() == 1);
    CHECK(transitioned.front() == "tunnel");
}

TEST_CASE("interface probe keeps a steady verified transport quiet") {
    auto transport = std::make_shared<RecordingTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());

    const InterfaceProbe::Target target{"tunnel", 0x80000, "hy1"};
    CHECK(probe.probe({target}).empty());
    CHECK(probe.probe({target}).empty());
}

TEST_CASE("interface probe stamps every result with its measurement time") {
    auto transport = std::make_shared<RecordingTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());
    const auto before = std::chrono::steady_clock::now();

    probe.probe({InterfaceProbe::Target{"tunnel", 0x80000, "hy1"}});

    const auto result = probe.result_for("tunnel");
    REQUIRE(result.has_value());
    // Every stored result must carry a real stamp. The freshness check relies
    // on it, and steady_clock's epoch is boot time on Linux, so an unstamped
    // result would read as current during the first minute of uptime.
    CHECK(result->measured_at >= before);
    CHECK(result->measured_at <= std::chrono::steady_clock::now());
}
