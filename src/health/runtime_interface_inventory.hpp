#pragma once

#ifdef WITH_API

#include "../api/generated/api_types.hpp"
#include "../routing/netlink.hpp"
#include "../runtime/interface_traffic_sampler.hpp"
#include "../runtime/interface_uptime_anchor.hpp"

#include <chrono>

namespace keen_pbr3 {

// True only for a link the kernel actually reports as carrying, not merely one
// that is administratively enabled. IFF_UP on its own is a configuration
// statement and would mark a dead tunnel as up for as long as it stays
// configured.
bool interface_link_is_up(const DumpedInterface& dumped);

// `uptime_anchors`, when supplied, both receives the link state observed in
// this dump and supplies the confirmed up-transition rendered on each entry.
// It is deliberately a caller-owned store rather than builder-local state: the
// anchor has to outlive every individual inventory build, otherwise a UI
// refresh would restart the uptime it is trying to display.
api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response(
    std::vector<DumpedInterface> dumped_interfaces,
    const InterfaceTrafficSampler* traffic_sampler = nullptr,
    InterfaceUptimeAnchorStore* uptime_anchors = nullptr,
    std::chrono::system_clock::time_point observed_at =
        std::chrono::system_clock::now());

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response(
    NetlinkManager& netlink,
    const InterfaceTrafficSampler* traffic_sampler = nullptr,
    InterfaceUptimeAnchorStore* uptime_anchors = nullptr);

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response_or_empty(
    NetlinkManager& netlink,
    const InterfaceTrafficSampler* traffic_sampler = nullptr,
    InterfaceUptimeAnchorStore* uptime_anchors = nullptr);

} // namespace keen_pbr3

#endif // WITH_API
