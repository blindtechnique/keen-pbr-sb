#include <doctest/doctest.h>

#include "../src/health/interface_probe.hpp"
#include "../src/health/runtime_outbound_state.hpp"
#include "../src/util/blocking_executor.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <vector>

using namespace keen_pbr3;
using namespace std::chrono_literals;

#ifdef WITH_API
namespace {

// Long downloads, domain scans and URLTEST batches share these two workers.
// Occupy them deterministically, without a router, real network or timed sleep.
class OccupiedBulkPool {
private:
    std::mutex mutex_;
    std::condition_variable condition_;
    int started_{0};
    bool released_{false};

public:
    BlockingExecutor executor{2, 64};

    OccupiedBulkPool() {
        for (int i = 0; i < 2; ++i) {
            executor.try_post("held-bulk-I/O", [this] {
                std::unique_lock<std::mutex> lock(mutex_);
                ++started_;
                condition_.notify_all();
                condition_.wait(lock, [this] { return released_; });
            });
        }
    }

    ~OccupiedBulkPool() {
        release();
        executor.shutdown();
    }

    bool wait_until_occupied() {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, 5s, [this] { return started_ == 2; });
    }

    void release() {
        std::lock_guard<std::mutex> lock(mutex_);
        released_ = true;
        condition_.notify_all();
    }
};

class TunnelTransport final : public HttpTransport {
public:
    std::atomic<bool> selected_is_up{false};

    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        if (request.bind_interface == "selected" && !selected_is_up.load()) {
            throw HttpTransportError("Connection timed out on selected tunnel");
        }
        HttpTransportResponse response;
        response.status_code = 204;
        response.elapsed = 37ms;
        return response;
    }
};

const std::vector<InterfaceProbe::Target> targets{
    {"healthy-a", 0x10000, "nwg1"},
    {"healthy-b", 0x20000, "nwg2"},
    {"healthy-c", 0x30000, "tun3"},
    {"selected-tunnel", 0x40000, "selected"},
};

void configure_probe(InterfaceProbe& probe, std::atomic<int64_t>& seconds) {
    RetryConfig retry;
    retry.attempts = 1;
    retry.interval_ms = 0;
    probe.set_retry(retry);
    probe.set_clock([&seconds] {
        return std::chrono::steady_clock::time_point{
            std::chrono::seconds{seconds.load()}};
    });
}

} // namespace

TEST_CASE("shared bulk queue reproduces global interface health starvation") {
    using namespace runtime_outbound_detail;
    std::atomic<int64_t> seconds{1000};
    auto transport = std::make_shared<TunnelTransport>();
    InterfaceProbe probe(transport);
    configure_probe(probe, seconds);
    probe.probe(targets);
    const auto baseline = probe.result_for(targets.front());
    REQUIRE(baseline);
    const auto freshness = interface_probe_freshness_limit(targets.size());

    OccupiedBulkPool bulk;
    REQUIRE(bulk.wait_until_occupied());
    auto manual = bulk.executor.submit("targeted-interface-probe:selected", [&] {
        probe.commit_observation(probe.measure_one(targets.back()));
    });
    auto round = bulk.executor.submit("interface-probe", [&] { probe.probe(targets); });

    // Advance only the evidence clock. Both confirmed occupied workers are
    // unable to claim the queued jobs, regardless of elapsed scheduler ticks.
    seconds += freshness.count() + 1;
    CHECK(manual.wait_for(0ms) == std::future_status::timeout);
    CHECK(round.wait_for(0ms) == std::future_status::timeout);
    CHECK(probe.result_for(targets.front())->measured_at == baseline->measured_at);
    for (std::size_t i = 0; i < 3; ++i) {
        CHECK(classify_interface_probe(
                  probe.result_for(targets[i]),
                  std::chrono::steady_clock::time_point{std::chrono::seconds{seconds.load()}},
                  freshness) == ProbeVerdict::Unverifiable);
    }

    bulk.release();
    REQUIRE(round.wait_for(5s) == std::future_status::ready);
    round.get();
    REQUIRE(manual.wait_for(5s) == std::future_status::ready);
    manual.get();
    CHECK(probe.result_for(targets.front())->measured_at > baseline->measured_at);
}

TEST_CASE("reserved interface rounds keep neighbours fresh while a manual probe waits") {
    using namespace runtime_outbound_detail;
    std::atomic<int64_t> seconds{1000};
    auto transport = std::make_shared<TunnelTransport>();
    InterfaceProbe probe(transport);
    configure_probe(probe, seconds);
    probe.probe(targets);
    const auto freshness = interface_probe_freshness_limit(targets.size());

    // Same bounded queue as Daemon. Python checks the actual worker wiring
    // and retirement in all teardown paths.
    BlockingExecutor regular{1, 1};
    OccupiedBulkPool bulk;
    REQUIRE(bulk.wait_until_occupied());
    auto manual = bulk.executor.submit("targeted-interface-probe:selected", [&] {
        probe.commit_observation(probe.measure_one(targets.back()));
    });

    std::size_t cursor = 0;
    for (int tick = 0; tick < 8; ++tick) {
        seconds += 20;
        const auto now = std::chrono::steady_clock::time_point{
            std::chrono::seconds{seconds.load()}};
        const auto rotation = select_interface_probe_rotation(targets, cursor, 2);
        cursor = rotation.next_cursor;
        auto round = regular.submit("interface-probe", [&, slice = rotation.slice] {
            return probe.measure_each(slice, [&](InterfaceProbe::Observation observation) {
                probe.commit_observation(observation);
                return true;
            });
        });
        REQUIRE(round.wait_for(5s) == std::future_status::ready);
        CHECK(round.get());
        CHECK(manual.wait_for(0ms) == std::future_status::timeout);
        for (const auto& target : rotation.slice) {
            REQUIRE(probe.result_for(target));
            CHECK(probe.result_for(target)->measured_at == now);
        }
        for (std::size_t i = 0; i < 3; ++i) {
            CHECK(classify_interface_probe(probe.result_for(targets[i]), now, freshness) ==
                  ProbeVerdict::Verified);
        }
        CHECK(classify_interface_probe(probe.result_for(targets.back()), now, freshness) ==
              ProbeVerdict::Failed);
    }

    const std::vector<InterfaceProbe::Observation> neighbours_before_manual{
        {targets[0], *probe.result_for(targets[0])},
        {targets[1], *probe.result_for(targets[1])},
        {targets[2], *probe.result_for(targets[2])},
    };
    bulk.release();
    REQUIRE(manual.wait_for(5s) == std::future_status::ready);
    manual.get();
    REQUIRE(probe.result_for(targets.back()));
    CHECK_FALSE(probe.result_for(targets.back())->success);
    for (const auto& before : neighbours_before_manual) {
        const auto after = probe.result_for(before.target);
        REQUIRE(after);
        CHECK(after->measured_at == before.result.measured_at);
        CHECK(after->success == before.result.success);
        CHECK(after->latency_ms == before.result.latency_ms);
    }

    // Recovery affects only this target; no state clear, freshness extension
    // or restart is involved.
    transport->selected_is_up = true;
    seconds += 1;
    auto recovered = bulk.executor.submit("targeted-interface-probe:selected", [&] {
        probe.commit_observation(probe.measure_one(targets.back()));
    });
    REQUIRE(recovered.wait_for(5s) == std::future_status::ready);
    recovered.get();
    CHECK(probe.result_for(targets.back())->success);
    for (const auto& before : neighbours_before_manual) {
        const auto after = probe.result_for(before.target);
        REQUIRE(after);
        CHECK(after->measured_at == before.result.measured_at);
        CHECK(after->success == before.result.success);
        CHECK(after->latency_ms == before.result.latency_ms);
    }
}
#endif
