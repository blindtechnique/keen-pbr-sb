#ifdef WITH_API

#include "runtime_outbound_state.hpp"

#include "../config/routing_state.hpp"
#include "../health/circuit_breaker.hpp"

#include <algorithm>
#include <iterator>
#include <netinet/in.h>
#include <limits>
#include <map>
#include <vector>

namespace keen_pbr3 {

namespace runtime_outbound_detail {

std::optional<int64_t> latency_from_urltest_result(
    const URLTestResult& result) noexcept {
    if (!result.success) {
        return std::nullopt;
    }
    return static_cast<int64_t>(result.latency_ms);
}

ProbeVerdict classify_interface_probe(
    const std::optional<InterfaceProbeResult>& probe,
    std::chrono::steady_clock::time_point now,
    std::chrono::steady_clock::duration freshness_limit) noexcept {
    if (!probe.has_value()) {
        return ProbeVerdict::Unverifiable;
    }
    // An unpinned probe follows whatever the mark selects. When the outbound's
    // table has no usable default that is the WAN, so the answer describes the
    // router, not this transport.
    if (!probe->attributed) {
        return ProbeVerdict::Unverifiable;
    }
    // Every stored result is stamped by InterfaceProbe::probe, so measured_at
    // is only ever the default on a value nobody measured. Do not lean on the
    // default reading as old: steady_clock's epoch is boot time on Linux, so
    // within the first minute of uptime it would read as current instead.
    if (now - probe->measured_at > freshness_limit) {
        return ProbeVerdict::Unverifiable;
    }
    return probe->success ? ProbeVerdict::Verified : ProbeVerdict::Failed;
}

} // namespace runtime_outbound_detail

namespace {

const Outbound* find_outbound(const std::vector<Outbound>& outbounds,
                              const std::string& tag) {
    for (const auto& outbound : outbounds) {
        if (outbound.tag == tag) {
            return &outbound;
        }
    }
    return nullptr;
}

uint32_t safe_table_id(uint32_t table_start, uint32_t offset) {
    uint32_t id = table_start;
    uint32_t count = 0;
    while (true) {
        if (!is_reserved_table(id)) {
            if (count == offset) {
                return id;
            }
            ++count;
        }
        ++id;
    }
}

std::vector<const Outbound*> ordered_urltest_children(const std::vector<Outbound>& outbounds,
                                                      const Outbound& urltest) {
    std::vector<const Outbound*> ordered;
    if (!urltest.outbound_groups.has_value()) {
        return ordered;
    }

    struct GroupRef {
        size_t index;
        int64_t weight;
    };

    std::vector<GroupRef> groups;
    groups.reserve(urltest.outbound_groups->size());
    for (size_t index = 0; index < urltest.outbound_groups->size(); ++index) {
        groups.push_back({index, urltest.outbound_groups->at(index).weight.value_or(1)});
    }

    std::stable_sort(groups.begin(), groups.end(), [](const GroupRef& lhs, const GroupRef& rhs) {
        return lhs.weight < rhs.weight;
    });

    for (const auto& group : groups) {
        for (const auto& child_tag : urltest.outbound_groups->at(group.index).outbounds) {
            const Outbound* child = find_outbound(outbounds, child_tag);
            if (child) {
                ordered.push_back(child);
            }
        }
    }

    return ordered;
}

const DumpedRoute* find_primary_default_route(const std::vector<DumpedRoute>& routes) {
    const DumpedRoute* primary = nullptr;
    uint32_t best_metric = std::numeric_limits<uint32_t>::max();

    for (const auto& route : routes) {
        if (route.destination != "default" || route.blackhole || route.unreachable) {
            continue;
        }

        if (primary == nullptr || route.metric < best_metric) {
            primary = &route;
            best_metric = route.metric;
        }
    }

    return primary;
}

std::vector<DumpedRoute> routes_for_table(const std::vector<DumpedRoute>& routes,
                                          uint32_t table_id) {
    std::vector<DumpedRoute> result;
    std::copy_if(routes.begin(), routes.end(), std::back_inserter(result),
                 [table_id](const DumpedRoute& route) {
                     return route.table == table_id;
                 });
    return result;
}

bool route_matches_outbound(const DumpedRoute& route, const Outbound& outbound) {
    if (route.destination != "default" || route.blackhole || route.unreachable) {
        return false;
    }

    if (outbound.type != OutboundType::INTERFACE) {
        return false;
    }

    if (!route.interface.has_value() || route.interface != outbound.interface) {
        return false;
    }

    if (route.family == AF_INET && outbound.gateway.has_value()) {
        return route.gateway == outbound.gateway;
    }

    if (route.family == AF_INET6 && outbound.gateway6.has_value()) {
        return route.gateway == outbound.gateway6;
    }

    return true;
}

api::RuntimeInterfaceStatusEnum map_urltest_child_status(
    const Outbound& child,
    bool reachable,
    bool is_active,
    const std::optional<UrltestState>& urltest_state) {
    if (!child.interface.has_value()) {
        return api::RuntimeInterfaceStatusEnum::UNKNOWN;
    }

    if (is_active) {
        return api::RuntimeInterfaceStatusEnum::ACTIVE;
    }

    if (!reachable) {
        return api::RuntimeInterfaceStatusEnum::UNAVAILABLE;
    }

    if (!urltest_state.has_value()) {
        return api::RuntimeInterfaceStatusEnum::BACKUP;
    }

    const auto result_it = urltest_state->last_results.find(child.tag);
    const auto breaker_it = urltest_state->circuit_breakers.find(child.tag);
    const bool breaker_open =
        breaker_it != urltest_state->circuit_breakers.end() &&
        breaker_it->second.state(child.tag) == CircuitState::open;

    if (breaker_open) {
        return api::RuntimeInterfaceStatusEnum::UNAVAILABLE;
    }

    if (result_it == urltest_state->last_results.end()) {
        return api::RuntimeInterfaceStatusEnum::UNKNOWN;
    }

    if (result_it->second.success) {
        return api::RuntimeInterfaceStatusEnum::BACKUP;
    }

    return api::RuntimeInterfaceStatusEnum::DEGRADED;
}

api::ResolverLiveStatus derive_overall_status(
    const std::vector<api::RuntimeInterfaceState>& interfaces,
    bool has_active_interface,
    bool has_live_route) {
    if (has_active_interface) {
        return api::ResolverLiveStatus::HEALTHY;
    }

    bool has_backup = false;
    bool has_degraded = false;

    for (const auto& interface_state : interfaces) {
        if (interface_state.status == api::RuntimeInterfaceStatusEnum::BACKUP) {
            has_backup = true;
        } else if (interface_state.status == api::RuntimeInterfaceStatusEnum::DEGRADED) {
            has_degraded = true;
        }
    }

    if (has_live_route && (has_backup || has_degraded)) {
        return api::ResolverLiveStatus::DEGRADED;
    }

    if (has_backup) {
        return api::ResolverLiveStatus::DEGRADED;
    }

    if (has_degraded) {
        return api::ResolverLiveStatus::DEGRADED;
    }

    if (!interfaces.empty()) {
        return api::ResolverLiveStatus::UNAVAILABLE;
    }

    return has_live_route
        ? api::ResolverLiveStatus::HEALTHY
        : api::ResolverLiveStatus::UNKNOWN;
}

std::optional<uint32_t> outbound_table_id(const Config& config,
                                          const std::vector<Outbound>& outbounds,
                                          const std::string& outbound_tag) {
    const uint32_t table_start = static_cast<uint32_t>(
        config.iproute.value_or(IprouteConfig{}).table_start.value_or(150));

    uint32_t table_offset = 0;
    for (const auto& outbound : outbounds) {
        const bool routable =
            (outbound.type == OutboundType::INTERFACE ||
             outbound.type == OutboundType::TABLE ||
             outbound.type == OutboundType::URLTEST);
        if (!routable) {
            continue;
        }

        uint32_t table_id = 0;
        if (outbound.type == OutboundType::TABLE) {
            table_id = static_cast<uint32_t>(outbound.table.value_or(0));
        } else {
            table_id = safe_table_id(table_start, table_offset);
        }
        ++table_offset;

        if (outbound.tag == outbound_tag) {
            return table_id;
        }
    }

    return std::nullopt;
}

api::RuntimeOutboundStateElement build_interface_outbound_state(
    const Config& config,
    const Outbound& outbound,
    const std::vector<DumpedRoute>& all_routes,
    const std::vector<DumpedRoute>& main_table_routes,
    const InterfaceProbeLookupFn& interface_probe_lookup,
    std::chrono::steady_clock::time_point now) {
    api::RuntimeOutboundStateElement state;
    state.tag = outbound.tag;
    state.type = outbound.type;

    const auto table_id = outbound_table_id(config, config.outbounds.value_or(std::vector<Outbound>{}), outbound.tag);
    std::vector<DumpedRoute> routes;
    if (table_id.has_value()) {
        routes = routes_for_table(all_routes, *table_id);
    }
    const DumpedRoute* primary_route = find_primary_default_route(routes);

    api::RuntimeInterfaceState interface_state;
    interface_state.outbound_tag = outbound.tag;
    interface_state.interface_name = outbound.interface;
    const bool reachable =
        is_interface_outbound_reachable(outbound, main_table_routes);
    // "active" says which route is installed and selected. That is a fact
    // about configuration, not about the far end, so it selects the member
    // label but never the health verdict.
    const bool active = primary_route != nullptr && route_matches_outbound(*primary_route, outbound);

    std::optional<InterfaceProbeResult> probe;
    if (interface_probe_lookup) {
        probe = interface_probe_lookup(outbound.tag);
    }
    const auto verdict =
        runtime_outbound_detail::classify_interface_probe(probe, now);

    if (verdict == runtime_outbound_detail::ProbeVerdict::Verified) {
        interface_state.latency_ms = static_cast<int64_t>(probe->latency_ms);
    } else if (probe.has_value() && probe->attributed && !probe->error.empty()) {
        interface_state.detail = probe->error;
    }

    switch (verdict) {
        case runtime_outbound_detail::ProbeVerdict::Verified:
            interface_state.status = active
                ? api::RuntimeInterfaceStatusEnum::ACTIVE
                : api::RuntimeInterfaceStatusEnum::BACKUP;
            state.status = api::ResolverLiveStatus::HEALTHY;
            break;
        case runtime_outbound_detail::ProbeVerdict::Failed:
            // The tunnel device can be UP with nothing behind it, and a probe
            // pinned to this device still outranks the installed route - but
            // only about what it measured. One endpoint did not answer once.
            //
            // While the interface is there and its route is installed, that is
            // "recent checks failed", which is what the contract already calls
            // degraded: openapi.yaml says "interface exists but recent checks
            // failed". Reporting unavailable instead turns a single pinned
            // gstatic timeout into a claim that this transport has no exit at
            // all, and the dashboard then says so in the header.
            //
            // The urltest path has drawn this line for a while and is the model
            // here: a reachable child whose last result failed is degraded, and
            // unavailable is kept for one that is unreachable or whose breaker
            // has opened - a confirmed combination rather than a single miss.
            // Plain interfaces have no breaker yet, so the confirmed
            // combination available here is the probe failing with no route to
            // the device at all.
            if (reachable || active) {
                interface_state.status =
                    api::RuntimeInterfaceStatusEnum::DEGRADED;
                state.status = api::ResolverLiveStatus::DEGRADED;
            } else {
                interface_state.status =
                    api::RuntimeInterfaceStatusEnum::UNAVAILABLE;
                state.status = api::ResolverLiveStatus::UNAVAILABLE;
            }
            break;
        case runtime_outbound_detail::ProbeVerdict::Unverifiable:
            // Nothing here is proof of carriage. Say so instead of showing a
            // green that was never measured.
            interface_state.status =
                reachable || active
                    ? api::RuntimeInterfaceStatusEnum::UNKNOWN
                    : api::RuntimeInterfaceStatusEnum::UNAVAILABLE;
            state.status = reachable || active
                               ? api::ResolverLiveStatus::UNKNOWN
                               : api::ResolverLiveStatus::UNAVAILABLE;
            break;
    }

    if (interface_state.detail == std::nullopt) {
        if (!reachable && !active) {
            interface_state.detail = std::string("interface is not reachable from the main routing table");
        } else if (verdict ==
                   runtime_outbound_detail::ProbeVerdict::Unverifiable) {
            interface_state.detail = std::string(
                "cannot verify: no attributable probe result for this outbound");
        } else if (!active && primary_route == nullptr) {
            interface_state.detail = std::string("no active default route is installed in the outbound table");
        }
    }

    state.interfaces = std::vector<api::RuntimeInterfaceState>{interface_state};
    return state;
}

api::RuntimeOutboundStateElement build_table_outbound_state(const Config& config,
                                                            const Outbound& outbound,
                                                            const std::vector<DumpedRoute>& all_routes) {
    api::RuntimeOutboundStateElement state;
    state.tag = outbound.tag;
    state.type = outbound.type;

    const auto table_id = outbound_table_id(config, config.outbounds.value_or(std::vector<Outbound>{}), outbound.tag);
    std::vector<DumpedRoute> routes;
    if (table_id.has_value()) {
        routes = routes_for_table(all_routes, *table_id);
    }
    const DumpedRoute* primary_route = find_primary_default_route(routes);

    state.status = primary_route != nullptr
        ? api::ResolverLiveStatus::HEALTHY
        : api::ResolverLiveStatus::UNKNOWN;
    return state;
}

api::RuntimeOutboundStateElement build_urltest_outbound_state(const Config& config,
                                                              const Outbound& outbound,
                                                              const std::vector<DumpedRoute>& all_routes,
                                                              const std::vector<DumpedRoute>& main_table_routes,
                                                              const UrltestStateLookupFn& urltest_state_lookup,
                                                              const InterfaceProbeLookupFn& interface_probe_lookup,
                                                              std::chrono::steady_clock::time_point now) {
    api::RuntimeOutboundStateElement state;
    state.tag = outbound.tag;
    state.type = outbound.type;

    const auto all_outbounds = config.outbounds.value_or(std::vector<Outbound>{});
    const auto children = ordered_urltest_children(all_outbounds, outbound);
    const auto table_id = outbound_table_id(config, all_outbounds, outbound.tag);

    std::vector<DumpedRoute> routes;
    if (table_id.has_value()) {
        routes = routes_for_table(all_routes, *table_id);
    }
    const DumpedRoute* primary_route = find_primary_default_route(routes);

    const auto urltest_state = urltest_state_lookup(outbound.tag);
    std::string live_active_child_tag;

    if (primary_route != nullptr) {
        for (const Outbound* child : children) {
            if (child != nullptr && route_matches_outbound(*primary_route, *child)) {
                live_active_child_tag = child->tag;
                break;
            }
        }
    }

    std::vector<api::RuntimeInterfaceState> interfaces;
    interfaces.reserve(children.size());

    for (const Outbound* child : children) {
        if (child == nullptr) {
            continue;
        }

        api::RuntimeInterfaceState interface_state;
        interface_state.outbound_tag = child->tag;
        interface_state.interface_name = child->interface;
        const bool reachable =
            child->type == OutboundType::INTERFACE
                ? is_interface_outbound_reachable(*child, main_table_routes)
                : false;
        const bool is_active = !live_active_child_tag.empty() && live_active_child_tag == child->tag;
        interface_state.status = map_urltest_child_status(*child, reachable, is_active, urltest_state);

        if (urltest_state.has_value()) {
            const auto result_it = urltest_state->last_results.find(child->tag);
            if (result_it != urltest_state->last_results.end()) {
                interface_state.latency_ms =
                    runtime_outbound_detail::latency_from_urltest_result(
                        result_it->second);
                if (!result_it->second.error.empty()) {
                    interface_state.detail = result_it->second.error;
                }
            }
        }

        if (interface_state.latency_ms == std::nullopt && interface_probe_lookup) {
            const auto probe = interface_probe_lookup(child->tag);
            // Only an attributed, current measurement belongs to this child.
            // An unpinned probe may have travelled the WAN, and publishing its
            // latency here would make a dead member look fast.
            if (runtime_outbound_detail::classify_interface_probe(probe, now) ==
                runtime_outbound_detail::ProbeVerdict::Verified) {
                interface_state.latency_ms = static_cast<int64_t>(probe->latency_ms);
            }
        }

        if (interface_state.detail == std::nullopt &&
            interface_state.status == api::RuntimeInterfaceStatusEnum::UNAVAILABLE &&
            child->type == OutboundType::INTERFACE) {
            interface_state.detail = std::string("interface is not reachable from the main routing table");
        }

        interfaces.push_back(std::move(interface_state));
    }

    state.interfaces = std::move(interfaces);

    if (primary_route != nullptr &&
        urltest_state.has_value() &&
        !urltest_state->selected_outbound.empty() &&
        !live_active_child_tag.empty() &&
        urltest_state->selected_outbound != live_active_child_tag) {
        state.detail = "live route selection differs from urltest manager selection";
    }

    state.status = derive_overall_status(
        state.interfaces,
        !live_active_child_tag.empty(),
        primary_route != nullptr);
    return state;
}

} // namespace

api::RuntimeOutboundsResponse build_runtime_outbounds_response(
    const Config& config,
    RouteNetlinkOperations& netlink,
    const UrltestStateLookupFn& urltest_state_lookup,
    const InterfaceProbeLookupFn& interface_probe_lookup,
    std::chrono::steady_clock::time_point now) {
    api::RuntimeOutboundsResponse response;
    const auto outbounds = config.outbounds.value_or(std::vector<Outbound>{});
    const auto all_routes = netlink.dump_routes();
    const auto main_table_routes = routes_for_table(all_routes, 254);
    response.outbounds.reserve(outbounds.size());

    for (const auto& outbound : outbounds) {
        switch (outbound.type) {
            case OutboundType::INTERFACE:
                response.outbounds.push_back(build_interface_outbound_state(
                    config, outbound, all_routes, main_table_routes,
                    interface_probe_lookup, now));
                break;
            case OutboundType::TABLE:
                response.outbounds.push_back(
                    build_table_outbound_state(config, outbound, all_routes));
                break;
            case OutboundType::URLTEST:
                response.outbounds.push_back(
                    build_urltest_outbound_state(config, outbound,
                                                 all_routes, main_table_routes,
                                                 urltest_state_lookup,
                                                 interface_probe_lookup, now));
                break;
            case OutboundType::BLACKHOLE:
            case OutboundType::IGNORE: {
                api::RuntimeOutboundStateElement state;
                state.tag = outbound.tag;
                state.type = outbound.type;
                state.status = api::ResolverLiveStatus::HEALTHY;
                response.outbounds.push_back(std::move(state));
                break;
            }
        }
    }

    return response;
}

} // namespace keen_pbr3

#endif // WITH_API
