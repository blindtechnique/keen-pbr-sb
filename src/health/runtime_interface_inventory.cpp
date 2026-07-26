#ifdef WITH_API

#include "runtime_interface_inventory.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <utility>

namespace keen_pbr3 {

namespace {

api::RuntimeInterfaceInventoryStatusEnum map_interface_status(bool admin_up) {
    return admin_up
        ? api::RuntimeInterfaceInventoryStatusEnum::UP
        : api::RuntimeInterfaceInventoryStatusEnum::DOWN;
}

api::RuntimeInterfaceInventoryEntry build_runtime_interface_inventory_entry(
    DumpedInterface dumped,
    const InterfaceTrafficSampler* traffic_sampler) {
    api::RuntimeInterfaceInventoryEntry entry;
    entry.name = std::move(dumped.name);
    entry.status = map_interface_status(dumped.admin_up);
    entry.admin_up = dumped.admin_up;

    if (dumped.oper_state.has_value()) {
        entry.oper_state = std::move(dumped.oper_state);
    }
    if (dumped.carrier.has_value()) {
        entry.carrier = dumped.carrier;
    }
    if (!dumped.ipv4_addresses.empty()) {
        entry.ipv4_addresses = std::move(dumped.ipv4_addresses);
    }
    if (!dumped.ipv6_addresses.empty()) {
        entry.ipv6_addresses = std::move(dumped.ipv6_addresses);
    }

    if (traffic_sampler != nullptr) {
        const auto snapshot = traffic_sampler->snapshot(entry.name);
        if (snapshot) {
            const auto to_api_integer = [](uint64_t value) {
                constexpr auto maximum =
                    static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
                return static_cast<int64_t>(std::min(value, maximum));
            };

            api::Traffic traffic;
            traffic.rx_bytes = to_api_integer(snapshot->latest.rx_bytes);
            traffic.tx_bytes = to_api_integer(snapshot->latest.tx_bytes);
            if (snapshot->latest.rx_bits_per_second) {
                traffic.rx_bits_per_second = to_api_integer(
                    *snapshot->latest.rx_bits_per_second);
            }
            if (snapshot->latest.tx_bits_per_second) {
                traffic.tx_bits_per_second = to_api_integer(
                    *snapshot->latest.tx_bits_per_second);
            }

            const auto newest_time = snapshot->latest.sampled_at;
            traffic.history.reserve(snapshot->history.size());
            for (const auto& retained : snapshot->history) {
                api::RuntimeInterfaceTrafficPointElement point;
                const auto age = newest_time > retained.sampled_at
                    ? newest_time - retained.sampled_at
                    : InterfaceTrafficSampler::Clock::duration::zero();
                point.age_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(age)
                        .count();
                point.rx_bits_per_second = to_api_integer(
                    retained.rx_bits_per_second.value_or(0));
                point.tx_bits_per_second = to_api_integer(
                    retained.tx_bits_per_second.value_or(0));
                traffic.history.push_back(std::move(point));
            }
            entry.traffic = std::move(traffic);
        }
    }

    return entry;
}

} // namespace

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response(
    std::vector<DumpedInterface> dumped_interfaces,
    const InterfaceTrafficSampler* traffic_sampler) {
    api::RuntimeInterfaceInventoryResponse response;

    for (auto& dumped : dumped_interfaces) {
        response.interfaces.push_back(
            build_runtime_interface_inventory_entry(
                std::move(dumped), traffic_sampler));
    }

    return response;
}

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response(
    NetlinkManager& netlink,
    const InterfaceTrafficSampler* traffic_sampler) {
    return build_runtime_interface_inventory_response(
        netlink.dump_interfaces(), traffic_sampler);
}

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response_or_empty(
    NetlinkManager& netlink,
    const InterfaceTrafficSampler* traffic_sampler) {
    try {
        return build_runtime_interface_inventory_response(
            netlink, traffic_sampler);
    } catch (const NetlinkError&) {
        return api::RuntimeInterfaceInventoryResponse{};
    }
}

} // namespace keen_pbr3

#endif // WITH_API
