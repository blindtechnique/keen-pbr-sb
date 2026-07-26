#pragma once

#ifdef WITH_API

#include "../api/generated/api_types.hpp"
#include "../routing/netlink.hpp"
#include "../runtime/interface_traffic_sampler.hpp"

namespace keen_pbr3 {

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response(
    std::vector<DumpedInterface> dumped_interfaces,
    const InterfaceTrafficSampler* traffic_sampler = nullptr);

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response(
    NetlinkManager& netlink,
    const InterfaceTrafficSampler* traffic_sampler = nullptr);

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response_or_empty(
    NetlinkManager& netlink,
    const InterfaceTrafficSampler* traffic_sampler = nullptr);

} // namespace keen_pbr3

#endif // WITH_API
