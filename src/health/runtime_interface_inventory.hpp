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
//
// The caller is responsible for opening the round with begin_round() BEFORE
// folding in any firmware observation. This builder only reports and observes
// link state; it deliberately does not drop vanished interfaces itself, since
// doing so here would race a concurrent build on another API worker.
//
// `observed_at` and `wall_now` are read as a pair by the caller. Anchors are
// kept on the steady clock and converted here, so a wall-clock step moves the
// published instant without changing the elapsed time it stands for.
api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response(
    std::vector<DumpedInterface> dumped_interfaces,
    const InterfaceTrafficSampler* traffic_sampler = nullptr,
    InterfaceUptimeAnchorStore* uptime_anchors = nullptr,
    InterfaceUptimeAnchorStore::TimePoint observed_at =
        InterfaceUptimeAnchorStore::Clock::now(),
    std::chrono::system_clock::time_point wall_now =
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
