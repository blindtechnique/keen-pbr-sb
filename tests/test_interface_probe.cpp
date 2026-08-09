#include <doctest/doctest.h>

#include "../src/health/interface_probe.hpp"
#include "../src/health/runtime_outbound_state.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <functional>
#include <initializer_list>
#include <mutex>
#include <new>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
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

// A deterministic transport for concurrency tests. Every request announces
// its start and then waits for the test to release that exact interface.
class GatedInterfaceTransport final : public HttpTransport {
public:
    HttpTransportResponse perform(
        const HttpTransportRequest& request) override {
        const auto interface = request.bind_interface;
        bool fail = false;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            started_.push_back(interface);
            ++active_;
            peak_active_ = std::max(peak_active_, active_);
            condition_.notify_all();
            condition_.wait(lock, [&]() {
                return release_all_ || released_.count(interface) != 0;
            });
            fail = failures_.count(interface) != 0;
            --active_;
            completed_.push_back(interface);
            condition_.notify_all();
        }

        if (fail) {
            throw std::runtime_error(
                "synthetic worker failure for " + interface);
        }
        HttpTransportResponse response;
        response.status_code = 204;
        response.elapsed = std::chrono::milliseconds{10};
        return response;
    }

    void fail_when_released(const std::string& interface) {
        std::lock_guard<std::mutex> lock(mutex_);
        failures_.insert(interface);
    }

    void release(const std::string& interface) {
        std::lock_guard<std::mutex> lock(mutex_);
        released_.insert(interface);
        condition_.notify_all();
    }

    void release_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        release_all_ = true;
        condition_.notify_all();
    }

    bool wait_until_started(
        const std::string& interface,
        std::chrono::milliseconds timeout = std::chrono::seconds{5}) {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, timeout, [&]() {
            return std::find(
                       started_.begin(), started_.end(), interface) !=
                   started_.end();
        });
    }

    bool wait_until_started_count(
        std::size_t count,
        std::chrono::milliseconds timeout = std::chrono::seconds{5}) {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, timeout, [&]() {
            return started_.size() >= count;
        });
    }

    bool wait_until_idle(
        std::chrono::milliseconds timeout = std::chrono::seconds{5}) {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, timeout, [&]() {
            return active_ == 0;
        });
    }

    std::vector<std::string> started() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return started_;
    }

    std::size_t peak_active() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return peak_active_;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::vector<std::string> started_;
    std::vector<std::string> completed_;
    std::set<std::string> released_;
    std::set<std::string> failures_;
    std::size_t active_{0};
    std::size_t peak_active_{0};
    bool release_all_{false};
};

class ReleaseGatedTransportOnExit {
public:
    explicit ReleaseGatedTransportOnExit(
        std::shared_ptr<GatedInterfaceTransport> transport)
        : transport_(std::move(transport)) {}

    ~ReleaseGatedTransportOnExit() { transport_->release_all(); }

private:
    std::shared_ptr<GatedInterfaceTransport> transport_;
};

std::vector<InterfaceProbe::Target> interface_targets(
    std::initializer_list<const char*> interfaces) {
    std::vector<InterfaceProbe::Target> targets;
    targets.reserve(interfaces.size());
    std::uint32_t mark = 0x30000;
    for (const auto* interface : interfaces) {
        targets.push_back(InterfaceProbe::Target{
            std::string{"target_"} + interface,
            mark,
            interface,
        });
        mark += 0x10000;
    }
    return targets;
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
    probe.set_max_parallel_probes(1);

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
    probe.set_max_parallel_probes(0);
    CHECK(probe.max_parallel_probes() == 1);
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

TEST_CASE("interface probe publishes prompt serialized completion order") {
    auto transport = std::make_shared<GatedInterfaceTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());
    probe.set_max_parallel_probes(2);
    const auto targets = interface_targets({"A", "B", "C"});

    std::mutex published_mutex;
    std::condition_variable published_condition;
    std::vector<std::string> published;
    std::optional<std::thread::id> publisher_thread;
    bool one_publisher_thread = true;

    auto round = std::async(std::launch::async, [&]() {
        return probe.measure_each(
            targets,
            [&](InterfaceProbe::Observation observation) {
                std::lock_guard<std::mutex> lock(published_mutex);
                if (!publisher_thread) {
                    publisher_thread = std::this_thread::get_id();
                } else if (*publisher_thread != std::this_thread::get_id()) {
                    one_publisher_thread = false;
                }
                published.push_back(observation.target.interface);
                published_condition.notify_all();
                return true;
            });
    });
    ReleaseGatedTransportOnExit release_on_exit(transport);

    REQUIRE(transport->wait_until_started("A"));
    REQUIRE(transport->wait_until_started("B"));
    transport->release("B");
    {
        std::unique_lock<std::mutex> lock(published_mutex);
        REQUIRE(published_condition.wait_for(
            lock, std::chrono::seconds{5}, [&]() {
                return published.size() >= 1;
            }));
        CHECK(published == std::vector<std::string>{"B"});
    }

    // B's acknowledgement promptly frees that worker to start C even while A
    // is still blocked, but C cannot overtake A until the test releases it.
    REQUIRE(transport->wait_until_started("C"));
    transport->release("A");
    {
        std::unique_lock<std::mutex> lock(published_mutex);
        REQUIRE(published_condition.wait_for(
            lock, std::chrono::seconds{5}, [&]() {
                return published.size() >= 2;
            }));
        CHECK(published == std::vector<std::string>{"B", "A"});
    }
    transport->release("C");

    REQUIRE(round.wait_for(std::chrono::seconds{5}) ==
            std::future_status::ready);
    CHECK(round.get());
    CHECK(published == std::vector<std::string>{"B", "A", "C"});
    CHECK(one_publisher_thread);
    CHECK(transport->wait_until_idle());
}

TEST_CASE("interface probe sink rejection stops claims and joins in-flight workers") {
    auto transport = std::make_shared<GatedInterfaceTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());
    probe.set_max_parallel_probes(2);
    const auto targets = interface_targets({"A", "B", "C", "D"});

    std::mutex sink_mutex;
    std::condition_variable sink_condition;
    bool sink_called = false;
    std::atomic<int> publications{0};
    auto round = std::async(std::launch::async, [&]() {
        return probe.measure_each(
            targets,
            [&](InterfaceProbe::Observation) {
                ++publications;
                {
                    std::lock_guard<std::mutex> lock(sink_mutex);
                    sink_called = true;
                }
                sink_condition.notify_all();
                return false;
            });
    });
    ReleaseGatedTransportOnExit release_on_exit(transport);

    REQUIRE(transport->wait_until_started("A"));
    REQUIRE(transport->wait_until_started("B"));
    transport->release("B");
    {
        std::unique_lock<std::mutex> lock(sink_mutex);
        REQUIRE(sink_condition.wait_for(
            lock, std::chrono::seconds{5}, [&]() {
                return sink_called;
            }));
    }

    CHECK(round.wait_for(std::chrono::milliseconds{50}) ==
          std::future_status::timeout);
    CHECK(transport->started().size() == 2);
    transport->release("A");
    REQUIRE(round.wait_for(std::chrono::seconds{5}) ==
            std::future_status::ready);
    CHECK_FALSE(round.get());
    CHECK(publications.load() == 1);
    CHECK(transport->started().size() == 2);
    CHECK(transport->wait_until_idle());
}

TEST_CASE("interface probe sink exception stops claims and is rethrown after join") {
    auto transport = std::make_shared<GatedInterfaceTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());
    probe.set_max_parallel_probes(2);
    const auto targets = interface_targets({"A", "B", "C", "D"});

    std::mutex sink_mutex;
    std::condition_variable sink_condition;
    bool sink_called = false;
    auto round = std::async(std::launch::async, [&]() {
        return probe.measure_each(
            targets,
            [&](InterfaceProbe::Observation) -> bool {
                {
                    std::lock_guard<std::mutex> lock(sink_mutex);
                    sink_called = true;
                }
                sink_condition.notify_all();
                throw std::runtime_error("synthetic sink failure");
            });
    });
    ReleaseGatedTransportOnExit release_on_exit(transport);

    REQUIRE(transport->wait_until_started("A"));
    REQUIRE(transport->wait_until_started("B"));
    transport->release("B");
    {
        std::unique_lock<std::mutex> lock(sink_mutex);
        REQUIRE(sink_condition.wait_for(
            lock, std::chrono::seconds{5}, [&]() {
                return sink_called;
            }));
    }

    CHECK(round.wait_for(std::chrono::milliseconds{50}) ==
          std::future_status::timeout);
    CHECK(transport->started().size() == 2);
    transport->release("A");
    REQUIRE(round.wait_for(std::chrono::seconds{5}) ==
            std::future_status::ready);
    CHECK_THROWS_WITH_AS(
        round.get(), "synthetic sink failure", std::runtime_error);
    CHECK(transport->started().size() == 2);
    CHECK(transport->wait_until_idle());
}

TEST_CASE("interface probe worker exception fails the round without synthetic down") {
    auto transport = std::make_shared<GatedInterfaceTransport>();
    transport->fail_when_released("bad");
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());
    probe.set_max_parallel_probes(2);
    const auto targets = interface_targets({"bad", "slow"});

    std::vector<std::string> published;
    auto round = std::async(std::launch::async, [&]() {
        return probe.measure_each(
            targets,
            [&](InterfaceProbe::Observation observation) {
                published.push_back(observation.target.interface);
                return true;
            });
    });
    ReleaseGatedTransportOnExit release_on_exit(transport);

    REQUIRE(transport->wait_until_started("bad"));
    REQUIRE(transport->wait_until_started("slow"));
    transport->release("bad");
    CHECK(round.wait_for(std::chrono::milliseconds{50}) ==
          std::future_status::timeout);
    CHECK(transport->started().size() == 2);
    transport->release("slow");
    REQUIRE(round.wait_for(std::chrono::seconds{5}) ==
            std::future_status::ready);
    CHECK_THROWS_WITH_AS(
        round.get(),
        "synthetic worker failure for bad",
        std::runtime_error);
    // A healthy result that linearized before the worker fault may be
    // published, but the throwing target must never be synthesized as DOWN.
    CHECK(std::find(published.begin(), published.end(), "bad") ==
          published.end());
    CHECK(published.size() <= 1);
    CHECK(transport->started().size() == 2);
    CHECK(transport->wait_until_idle());
}

TEST_CASE("interface probe partial worker creation publishes nothing and joins") {
    auto transport = std::make_shared<GatedInterfaceTransport>();
    transport->release_all();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());
    probe.set_max_parallel_probes(2);
    const auto targets = interface_targets({"A", "B"});

    std::atomic<int> publications{0};
    probe.fail_worker_creation_at_for_testing(1);
    CHECK_THROWS_WITH_AS(
        probe.measure_each(
            targets,
            [&](InterfaceProbe::Observation) {
                ++publications;
                return true;
            }),
        "synthetic interface probe worker creation failure",
        std::runtime_error);
    CHECK(publications.load() == 0);
    CHECK(transport->wait_until_idle());

    // The fault is one-shot and a later round owns a fresh worker group.
    CHECK(probe.measure_each(
        targets,
        [&](InterfaceProbe::Observation) {
            ++publications;
            return true;
        }));
    CHECK(publications.load() == 2);
    CHECK(transport->wait_until_idle());
}

TEST_CASE("interface probe hard caps concurrent workers at four") {
    auto transport = std::make_shared<GatedInterfaceTransport>();
    InterfaceProbe probe(transport);
    probe.set_retry(single_attempt());
    probe.set_max_parallel_probes(99);
    CHECK(probe.max_parallel_probes() == 4);
    const auto targets =
        interface_targets({"A", "B", "C", "D", "E", "F"});

    std::atomic<int> publications{0};
    auto round = std::async(std::launch::async, [&]() {
        return probe.measure_each(
            targets,
            [&](InterfaceProbe::Observation) {
                ++publications;
                return true;
            });
    });
    ReleaseGatedTransportOnExit release_on_exit(transport);

    REQUIRE(transport->wait_until_started_count(4));
    CHECK(transport->peak_active() == 4);
    CHECK(transport->started().size() == 4);
    transport->release_all();
    REQUIRE(round.wait_for(std::chrono::seconds{5}) ==
            std::future_status::ready);
    CHECK(round.get());
    CHECK(publications.load() == 6);
    CHECK(transport->peak_active() == 4);
    CHECK(transport->wait_until_idle());
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
