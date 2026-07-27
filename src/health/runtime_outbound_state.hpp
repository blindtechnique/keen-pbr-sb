#pragma once

#ifdef WITH_API

#include "../api/generated/api_types.hpp"
#include "../config/config.hpp"
#include "../routing/netlink.hpp"
#include "../routing/urltest_manager.hpp"
#include "interface_probe.hpp"

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

} // namespace runtime_outbound_detail

using UrltestStateLookupFn = std::function<std::optional<UrltestState>(const std::string&)>;
// Latency measured for a plain interface outbound, which urltest never covers.
using InterfaceProbeLookupFn =
    std::function<std::optional<InterfaceProbeResult>(const std::string&)>;

api::RuntimeOutboundsResponse build_runtime_outbounds_response(
    const Config& config,
    NetlinkManager& netlink,
    const UrltestStateLookupFn& urltest_state_lookup,
    const InterfaceProbeLookupFn& interface_probe_lookup);

} // namespace keen_pbr3

#endif // WITH_API
