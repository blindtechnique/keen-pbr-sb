#pragma once

#ifdef WITH_API

#include "../api/generated/api_types.hpp"
#include "../config/config.hpp"
#include "../routing/netlink.hpp"
#include "../routing/urltest_manager.hpp"
#include "interface_probe.hpp"

#include <chrono>
#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

namespace runtime_outbound_detail {

// A failed URL test carries latency_ms=0 as the result type's default value.
// Treat that value as absent rather than publishing a misleading zero-latency
// measurement through the runtime inventory.
std::optional<int64_t> latency_from_urltest_result(
    const URLTestResult& result) noexcept;

// What a probe result is allowed to say about an outbound.
//
// An installed route proves only that keen-pbr wrote what the config asked
// for. It says nothing about the server on the far side: a tunnel device
// stays UP after its remote endpoint is deleted, so route shape alone reports
// a dead transport as working. Health therefore follows probe evidence, and
// evidence that cannot be attributed or is no longer current yields an honest
// unknown rather than a green.
enum class ProbeVerdict {
    Verified,      // pinned to the outbound's device, recent, and it answered
    Failed,        // pinned to the outbound's device, recent, and it did not
    Unverifiable,  // missing, unattributed, or too old to describe now
};

// Three probe intervals. One missed round is ordinary jitter; three means the
// figure no longer describes the current state and must stop rendering as
// current health.
constexpr std::chrono::seconds kInterfaceProbeFreshnessLimit{60};

ProbeVerdict classify_interface_probe(
    const std::optional<InterfaceProbeResult>& probe,
    std::chrono::steady_clock::time_point now,
    std::chrono::steady_clock::duration freshness_limit =
        kInterfaceProbeFreshnessLimit) noexcept;

} // namespace runtime_outbound_detail

using UrltestStateLookupFn = std::function<std::optional<UrltestState>(const std::string&)>;
// Latency measured for a plain interface outbound, which urltest never covers.
using InterfaceProbeLookupFn =
    std::function<std::optional<InterfaceProbeResult>(const std::string&)>;

// Takes the route-dump interface rather than NetlinkManager: the builder only
// reads routes, and narrowing the dependency lets the health verdict be tested
// against modelled kernel state instead of the host's own interfaces.
api::RuntimeOutboundsResponse build_runtime_outbounds_response(
    const Config& config,
    RouteNetlinkOperations& netlink,
    const UrltestStateLookupFn& urltest_state_lookup,
    const InterfaceProbeLookupFn& interface_probe_lookup,
    std::chrono::steady_clock::time_point now =
        std::chrono::steady_clock::now());

} // namespace keen_pbr3

#endif // WITH_API
