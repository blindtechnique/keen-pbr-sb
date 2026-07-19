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
