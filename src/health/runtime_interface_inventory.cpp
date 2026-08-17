#ifdef WITH_API

#include "runtime_interface_inventory.hpp"

#include "../util/time_utils.hpp"

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

api::LinkUptimeSource map_uptime_source(InterfaceUptimeSource source) {
    return source == InterfaceUptimeSource::firmware
        ? api::LinkUptimeSource::FIRMWARE
        : api::LinkUptimeSource::OBSERVED;
}

api::RuntimeInterfaceInventoryEntry build_runtime_interface_inventory_entry(
    DumpedInterface dumped,
    const InterfaceTrafficSampler* traffic_sampler,
    InterfaceUptimeAnchorStore* uptime_anchors,
    InterfaceUptimeAnchorStore::TimePoint observed_at,
    std::chrono::system_clock::time_point wall_now) {
    // Read before any member of `dumped` is moved from.
    const bool link_up = interface_link_is_up(dumped);

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

    if (uptime_anchors != nullptr) {
        uptime_anchors->observe_link_state(entry.name, link_up, observed_at);
        if (const auto anchor = uptime_anchors->anchor(entry.name)) {
            // The anchor is a steady instant; only the elapsed time it stands
            // for is meaningful. Expressing it in wall time here, from the
            // pair the caller read together, means an NTP step relocates the
            // published instant instead of inflating the uptime by the size
            // of the step - which on a router with no RTC is hours.
            const auto elapsed =
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    observed_at - anchor->up_since);
            entry.link_up_since_unix_ms = unix_timestamp_ms(wall_now - elapsed);
            entry.link_uptime_source = map_uptime_source(anchor->source);
        }
        // No anchor means no confirmed transition is known. Both fields stay
        // absent so the client renders "unknown"; filling in a fallback here
        // is what would turn daemon uptime into a fake interface uptime.
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
            // Previously left unset, so every inventory response shipped a
            // null here and the client filled the gap with the batch stamp -
            // which made a stalled interface indistinguishable from a live
            // one. This is the instant this interface was last read.
            traffic.sampled_at_unix_ms =
                unix_timestamp_ms(snapshot->latest.observed_at);
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

bool interface_link_is_up(const DumpedInterface& dumped) {
    if (!dumped.admin_up) {
        return false;
    }
    if (dumped.carrier) {
        return *dumped.carrier;
    }
    if (dumped.oper_state) {
        // Point-to-point tunnel devices routinely report "unknown" because
        // they implement no carrier at all. Refusing that would mark every
        // WireGuard and TUN link permanently down here. The firmware counter,
        // which does distinguish a dead tunnel, overrides this fallback
        // wherever it is available.
        return *dumped.oper_state == "up" || *dumped.oper_state == "unknown";
    }
    return false;
}

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response(
    std::vector<DumpedInterface> dumped_interfaces,
    const InterfaceTrafficSampler* traffic_sampler,
    InterfaceUptimeAnchorStore* uptime_anchors,
    InterfaceUptimeAnchorStore::TimePoint observed_at,
    std::chrono::system_clock::time_point wall_now) {
    api::RuntimeInterfaceInventoryResponse response;

    for (auto& dumped : dumped_interfaces) {
        response.interfaces.push_back(
            build_runtime_interface_inventory_entry(
                std::move(dumped), traffic_sampler, uptime_anchors,
                observed_at, wall_now));
    }

    return response;
}

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response(
    NetlinkManager& netlink,
    const InterfaceTrafficSampler* traffic_sampler,
    InterfaceUptimeAnchorStore* uptime_anchors) {
    return build_runtime_interface_inventory_response(
        netlink.dump_interfaces(), traffic_sampler, uptime_anchors,
        InterfaceUptimeAnchorStore::Clock::now(),
        std::chrono::system_clock::now());
}

api::RuntimeInterfaceInventoryResponse build_runtime_interface_inventory_response_or_empty(
    NetlinkManager& netlink,
    const InterfaceTrafficSampler* traffic_sampler,
    InterfaceUptimeAnchorStore* uptime_anchors) {
    try {
        return build_runtime_interface_inventory_response(
            netlink, traffic_sampler, uptime_anchors);
    } catch (const NetlinkError&) {
        return api::RuntimeInterfaceInventoryResponse{};
    }
}

} // namespace keen_pbr3

#endif // WITH_API
