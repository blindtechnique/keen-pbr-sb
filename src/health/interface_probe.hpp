#pragma once

// Latency for every outbound interface, not just the members of a failover
// group.
//
// urltest already probes the children it chooses between, which left standalone
// interfaces - and native WireGuard or AmneziaWG tunnels the firmware brings up
// - with no figure at all. Probing everything with the same HTTP request makes
// the numbers comparable across transports.
//
// A mark on its own does not make the answer attributable. Policy rules for
// non-strict outbounds carry no companion blackhole, so when the outbound's
// table holds no usable default the lookup continues to main and the probe
// measures the router's own WAN connectivity - which is always up. The probe
// therefore also binds the socket to the outbound's device, and records
// whether it was able to: an unattributed result proves nothing about the
// transport and must never be published as health.

#include "url_tester.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace keen_pbr3 {

struct InterfaceProbeResult {
    uint32_t latency_ms{0};
    bool success{false};
    // True when the request was pinned to the outbound's own device, so the
    // outcome describes that transport rather than whatever routing the mark
    // happened to select. False leaves the outbound unverifiable.
    bool attributed{false};
    std::string error;
    std::chrono::steady_clock::time_point measured_at{};
};

class InterfaceProbe {
public:
    InterfaceProbe() = default;
    // Lets a test drive the probe against a modelled transport instead of the
    // host's own network. A shared injected transport must support concurrent
    // perform() calls; an injected clock may be invoked concurrently too.
    // Configure this probe before starting a round: setters are not a
    // concurrent mutation API.
    explicit InterfaceProbe(std::shared_ptr<HttpTransport> transport)
        : tester_(std::move(transport)) {}

    // Default probe target matches the one urltest uses, so a transport cannot
    // look fast here and slow there purely because of the endpoint.
    static constexpr const char* kDefaultUrl =
        "https://www.gstatic.com/generate_204";

    struct Target {
        std::string tag;
        uint32_t fwmark{0};
        // Device to pin the probe to. Empty means the outbound shape offers
        // nothing to bind to, and the result is reported unattributed.
        std::string interface;
    };

    // A network observation is deliberately separate from publication. The
    // daemon may replace the active routing generation while a slow HTTPS
    // request is in flight; committing that old answer under a reused tag
    // would make the new transport inherit stale health.
    struct Observation {
        Target target;
        InterfaceProbeResult result;
    };

    void set_url(std::string url) { url_ = std::move(url); }
    void set_timeout(std::chrono::milliseconds timeout) { timeout_ = timeout; }
    void set_clock(
        std::function<std::chrono::steady_clock::time_point()> clock) {
        clock_ = std::move(clock);
    }
    // A second attempt absorbs a single dropped packet without declaring a
    // working tunnel dead. Injectable so a test can exercise the failure path
    // without waiting out the retry interval.
    void set_retry(RetryConfig retry) { retry_ = std::move(retry); }

    // The production coordinator publishes results as they complete, but the
    // router must never turn one health round into an unbounded TLS burst.
    // Four is the hard ceiling; zero keeps the explicit sequential mode.
    void set_max_parallel_probes(std::size_t width) noexcept {
        const auto normalized = width == 0 ? std::size_t{1} : width;
        max_parallel_probes_.store(
            normalized > kMaxParallelProbes
                ? kMaxParallelProbes
                : normalized,
            std::memory_order_relaxed);
    }
    std::size_t max_parallel_probes() const noexcept {
        return max_parallel_probes_.load(std::memory_order_relaxed);
    }

    // Runs one round of probes. Blocking: callers put it on the daemon's
    // blocking executor rather than the event loop. Returns tags whose
    // reachability changed since the previous completed probe; the first
    // observation only establishes a baseline.
    std::vector<std::string> probe(const std::vector<Target>& targets);

    // Split form used by the daemon's generation-fenced async coordinator.
    // The single-target form lets the coordinator publish an early result
    // before later, slow targets finish. Both measure() overloads perform
    // blocking I/O but do not mutate published state; commit() is cheap and
    // may therefore run on the control loop after the caller has revalidated
    // the runtime generation and target identity.
    Observation measure_one(const Target& target);
    std::vector<Observation> measure(const std::vector<Target>& targets);
    // Measure with bounded concurrency and hand each result to the caller on
    // this coordinating thread, serialized in completion order. Returning
    // false (or throwing) stops new target claims, joins the already in-flight
    // probes, and prevents any later result publication.
    bool measure_each(
        const std::vector<Target>& targets,
        const std::function<bool(Observation)>& observation_sink);
    bool commit_observation(const Observation& observation);
    std::vector<std::string> commit(
        const std::vector<Observation>& observations);

#ifdef KEEN_PBR3_TESTING
    // Deterministic strong-publication seam. The injected failure occurs
    // after the complete tag/identity/result candidate has been prepared but
    // before any published state is changed.
    void fail_next_commit_after_prepare_for_testing();
    // One-shot partial pthread-create fault seam. Index one means one worker
    // was created successfully and creation of the second must fail.
    void fail_worker_creation_at_for_testing(
        std::size_t worker_index) noexcept;
#endif

    std::optional<InterfaceProbeResult> result_for(const std::string& tag) const;
    std::optional<InterfaceProbeResult> result_for(
        const Target& expected_target) const;

    // Drops results for outbounds that no longer exist, so a renamed tag does
    // not keep reporting a latency measured for something else.
    // Retain only observations belonging to the exact current tag/mark/device
    // identity. Reusing a friendly tag for another transport must not inherit
    // the previous transport's health.
    void retain_only(const std::vector<Target>& targets);

private:
    static constexpr std::size_t kMaxParallelProbes{4};

    struct PublishedObservation {
        Target target;
        InterfaceProbeResult result;
    };

    using PublishedObservationPtr =
        std::shared_ptr<const PublishedObservation>;

    static_assert(
        std::is_nothrow_swappable_v<PublishedObservationPtr>,
        "published interface observation pointers must support atomic replacement");

    using PublishedObservations =
        std::map<std::string, PublishedObservationPtr>;

    static RetryConfig default_retry() {
        RetryConfig retry;
        retry.attempts = 2;
        retry.interval_ms = 500;
        return retry;
    }

    std::string url_{kDefaultUrl};
    std::chrono::milliseconds timeout_{5000};
    RetryConfig retry_{default_retry()};
    std::function<std::chrono::steady_clock::time_point()> clock_{
        [] { return std::chrono::steady_clock::now(); }};
    std::atomic<std::size_t> max_parallel_probes_{
        kMaxParallelProbes};
    mutable std::mutex mutex_;
    PublishedObservations published_observations_;
#ifdef KEEN_PBR3_TESTING
    bool fail_next_commit_after_prepare_{false};
    std::atomic<std::ptrdiff_t> fail_worker_creation_at_{-1};
#endif
    URLTester tester_;
};

// A probe answer is publishable only for the exact routing generation and
// target identity it measured. Tags alone are insufficient because an apply
// may reuse a friendly tag with a different mark or device.
bool interface_probe_snapshot_is_current(
    std::uint64_t expected_runtime_generation,
    std::uint64_t current_runtime_generation,
    const std::vector<InterfaceProbe::Target>& expected_targets,
    const std::vector<InterfaceProbe::Target>& current_targets) noexcept;

// Per-result publication uses the narrower fence: the runtime generation must
// still match and this exact tag/mark/device tuple must still be configured.
// Other targets are allowed to finish later in the same sequential round.
bool interface_probe_target_is_current(
    std::uint64_t expected_runtime_generation,
    std::uint64_t current_runtime_generation,
    const InterfaceProbe::Target& expected_target,
    const std::vector<InterfaceProbe::Target>& current_targets) noexcept;

} // namespace keen_pbr3
