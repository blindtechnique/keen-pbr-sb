#include <doctest/doctest.h>

#include "../src/health/interface_probe.hpp"
#include "../src/health/runtime_outbound_state.hpp"

#include <functional>
#include <new>
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
    std::function<HttpTransportResponse(const HttpTransportRequest&)>
        responder;

    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        requests.push_back(request);
        if (responder) {
            return responder(request);
        }
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

TEST_CASE("interface probe does not publish a measurement before guarded commit") {
    auto transport = std::make_shared<RecordingTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());

    const auto observations = probe.measure(
        {InterfaceProbe::Target{"tunnel", 0x80000, "hy1"}});

    REQUIRE(observations.size() == 1);
    CHECK_FALSE(probe.result_for("tunnel").has_value());

    CHECK(probe.commit(observations).empty());
    const auto result = probe.result_for("tunnel");
    REQUIRE(result.has_value());
    CHECK(result->success);
    CHECK(result->attributed);
}

TEST_CASE("interface probe commit publishes identity and result atomically after allocation failure") {
    InterfaceProbe probe;
    const InterfaceProbe::Target original{
        "friendly", 0x80000, "hy1"};

    InterfaceProbeResult healthy;
    healthy.success = true;
    healthy.attributed = true;
    healthy.latency_ms = 41;
    healthy.error = "old-complete-result";
    CHECK_FALSE(probe.commit_observation({original, healthy}));

    auto replacement = original;
    replacement.fwmark = 0x90000;
    replacement.interface = "hy2";
    InterfaceProbeResult down;
    down.success = false;
    down.attributed = true;
    down.error = std::string(4096, 'x');

    probe.fail_next_commit_after_prepare_for_testing();
    CHECK_THROWS_AS(
        probe.commit_observation({replacement, down}),
        std::bad_alloc);

    // A failed replacement must leave both halves of the old publication
    // intact. In particular, the friendly tag cannot expose the new health
    // under the old identity (or vice versa).
    const auto old_exact = probe.result_for(original);
    REQUIRE(old_exact.has_value());
    CHECK(old_exact->success);
    CHECK(old_exact->attributed);
    CHECK(old_exact->latency_ms == 41);
    CHECK(old_exact->error == "old-complete-result");
    CHECK_FALSE(probe.result_for(replacement).has_value());

    // Retrying the same observation must still see the real green -> down
    // edge. A partial first publication used to consume this transition and
    // strand URLTEST until its normal interval.
    CHECK(probe.commit_observation({replacement, down}));
    CHECK_FALSE(probe.result_for(original).has_value());
    const auto replacement_exact = probe.result_for(replacement);
    REQUIRE(replacement_exact.has_value());
    CHECK_FALSE(replacement_exact->success);
    CHECK(replacement_exact->attributed);
    CHECK(replacement_exact->error == down.error);
}

// Regression for the live Keenetic failure: a round used to measure every
// target first and publish the whole batch only after several later 5-second
// timeouts. The next round could therefore cross the 60-second freshness
// boundary while its new early success was still hidden in the batch, making
// a working AWG route alternate HEALTHY -> UNKNOWN -> HEALTHY.
TEST_CASE("interface probe publishes an early success before later timeouts expire the previous round") {
    using runtime_outbound_detail::ProbeVerdict;
    using runtime_outbound_detail::classify_interface_probe;
    using runtime_outbound_detail::kInterfaceProbeFreshnessLimit;

    auto transport = std::make_shared<RecordingTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());

    auto now = std::chrono::steady_clock::time_point{
        std::chrono::seconds{1000}};
    probe.set_clock([&now] { return now; });

    const std::vector<InterfaceProbe::Target> targets{
        InterfaceProbe::Target{"early_awg", 0x30000, "nwg1"},
        InterfaceProbe::Target{"slow_dead", 0x90000, "kpbrdead"},
    };

    std::optional<InterfaceProbeResult> first_round_early;
    int slow_attempt = 0;
    bool prior_sample_was_stale = false;
    bool current_sample_was_verified = false;
    transport->responder =
        [&](const HttpTransportRequest& request) -> HttpTransportResponse {
        if (request.bind_interface == "nwg1") {
            HttpTransportResponse response;
            response.status_code = 204;
            response.elapsed = std::chrono::milliseconds{250};
            return response;
        }

        ++slow_attempt;
        if (slow_attempt == 1) {
            // The first sweep is slow but still shorter than the freshness
            // window, matching the live router's mix of working and timed-out
            // children.
            now += std::chrono::seconds{35};
        } else {
            // During the next slow tail, the previous round's early sample is
            // now older than 60 seconds. The promptly published sample from
            // this round is only 26 seconds old and must remain authoritative.
            now += std::chrono::seconds{26};
            prior_sample_was_stale =
                first_round_early.has_value() &&
                classify_interface_probe(first_round_early, now) ==
                    ProbeVerdict::Unverifiable;

            const auto current = probe.result_for("early_awg");
            current_sample_was_verified =
                current.has_value() &&
                classify_interface_probe(current, now) ==
                    ProbeVerdict::Verified;
            now += std::chrono::seconds{9};
        }
        throw HttpTransportError(
            "HTTP request failed: Connection timed out");
    };

    const auto publish = [&probe](InterfaceProbe::Observation observation) {
        (void)probe.commit_observation(observation);
        return true;
    };

    CHECK(probe.measure_each(targets, publish));
    first_round_early = probe.result_for("early_awg");
    REQUIRE(first_round_early.has_value());

    CHECK(probe.measure_each(targets, publish));
    CHECK(slow_attempt == 2);
    CHECK(prior_sample_was_stale);
    CHECK(current_sample_was_verified);
    const auto current = probe.result_for("early_awg");
    REQUIRE(current.has_value());
    CHECK(now - current->measured_at < kInterfaceProbeFreshnessLimit);
}

TEST_CASE("interface probe stops before another blocking target when publication is rejected") {
    auto transport = std::make_shared<RecordingTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());
    const std::vector<InterfaceProbe::Target> targets{
        InterfaceProbe::Target{"first", 0x30000, "nwg1"},
        InterfaceProbe::Target{"must_not_run", 0x60000, "nwg3"},
    };

    int publications = 0;
    CHECK_FALSE(probe.measure_each(
        targets,
        [&publications](InterfaceProbe::Observation) {
            ++publications;
            return false;
        }));
    CHECK(publications == 1);
    REQUIRE(transport->requests.size() == 1);
    CHECK(transport->requests.front().bind_interface == "nwg1");
}

TEST_CASE("interface probe snapshot fence rejects a reused tag") {
    const std::vector<InterfaceProbe::Target> measured{
        InterfaceProbe::Target{"friendly", 0x80000, "hy1"}};

    CHECK(interface_probe_snapshot_is_current(12, 12, measured, measured));

    auto changed_mark = measured;
    changed_mark.front().fwmark = 0x90000;
    CHECK_FALSE(interface_probe_snapshot_is_current(
        12, 12, measured, changed_mark));

    auto changed_device = measured;
    changed_device.front().interface = "hy2";
    CHECK_FALSE(interface_probe_snapshot_is_current(
        12, 12, measured, changed_device));

    CHECK_FALSE(interface_probe_snapshot_is_current(
        12, 13, measured, measured));

    CHECK(interface_probe_target_is_current(
        12, 12, measured.front(), measured));
    CHECK_FALSE(interface_probe_target_is_current(
        12, 13, measured.front(), measured));
    CHECK_FALSE(interface_probe_target_is_current(
        12, 12, measured.front(), changed_mark));
    CHECK_FALSE(interface_probe_target_is_current(
        12, 12, measured.front(), changed_device));
}

TEST_CASE("interface probe exact lookup never lends health to a reused tag") {
    auto transport = std::make_shared<RecordingTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());

    const InterfaceProbe::Target original{
        "friendly", 0x80000, "hy1"};
    probe.probe({original});
    REQUIRE(probe.result_for(original).has_value());

    auto changed_mark = original;
    changed_mark.fwmark = 0x90000;
    auto changed_device = original;
    changed_device.interface = "hy2";
    CHECK_FALSE(probe.result_for(changed_mark).has_value());
    CHECK_FALSE(probe.result_for(changed_device).has_value());

    // The next round removes the obsolete storage as well; production lookup
    // was already safe before this cleanup because it uses exact identity.
    probe.retain_only({changed_device});
    CHECK_FALSE(probe.result_for("friendly").has_value());
}
