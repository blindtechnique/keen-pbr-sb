#pragma once

#include "config.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class RouteFailureHealth { unknown, healthy, degraded, unavailable, link_unavailable };
using RouteFailureHealthSnapshot = std::map<std::string, RouteFailureHealth>;

// A pinned HTTP request proves carriage when it succeeds, but its failure
// describes only that endpoint. It is not evidence that the transport has no
// route or that its remote peer is unavailable.
inline RouteFailureHealth route_failure_probe_health(bool attributed, bool success) {
    if (!attributed) return RouteFailureHealth::unknown;
    return success ? RouteFailureHealth::healthy : RouteFailureHealth::degraded;
}

inline bool route_failure_is_unavailable(RouteFailureHealth health) {
    return health == RouteFailureHealth::unavailable ||
           health == RouteFailureHealth::link_unavailable;
}

inline bool route_failure_is_usable(RouteFailureHealth health) {
    // A failed endpoint check degrades the observation, not the still-present
    // path. The worker's existing live link/gateway check overrides it before
    // classification; missing or unattributed evidence remains unknown.
    return health == RouteFailureHealth::healthy ||
           health == RouteFailureHealth::degraded;
}

inline std::vector<std::string> route_failure_group_children(const Outbound& outbound) {
    std::vector<std::string> children;
    for (const auto& group : outbound.outbound_groups.value_or(std::vector<OutboundGroup>{})) {
        children.insert(children.end(), group.outbounds.begin(), group.outbounds.end());
    }
    return children;
}

inline bool route_failure_policies_enabled(const Config& config) {
    if (!config.route || !config.route->rules) return false;
    return std::any_of(config.route->rules->begin(), config.route->rules->end(),
        [](const RouteRule& rule) {
            return rule.enabled.value_or(true) &&
                rule.failure_policy.value_or(api::FailurePolicy::INHERIT) !=
                    api::FailurePolicy::INHERIT;
        });
}

// Link/gateway absence is immediate evidence, stronger than a cached successful
// HTTPS observation. An available link alone does not prove a working tunnel.
inline void merge_route_failure_link_health(
    RouteFailureHealthSnapshot& health,
    const std::map<std::string, bool>& reachability) {
    for (const auto& entry : reachability) {
        if (!entry.second) health[entry.first] = RouteFailureHealth::link_unavailable;
    }
}

inline RouteFailureHealth route_failure_health_for(
    const std::string& tag,
    const std::vector<Outbound>& outbounds,
    const std::map<std::string, std::string>* selections,
    const RouteFailureHealthSnapshot* health,
    unsigned depth = 0) {
    if (!health || depth > 8) return RouteFailureHealth::unknown;
    const auto outbound = std::find_if(outbounds.begin(), outbounds.end(),
        [&tag](const Outbound& candidate) { return candidate.tag == tag; });
    if (outbound == outbounds.end()) return RouteFailureHealth::unknown;
    if (outbound->type == OutboundType::BLACKHOLE) {
        return RouteFailureHealth::unavailable;
    }
    if (outbound->type != OutboundType::INTERFACE &&
        outbound->type != OutboundType::URLTEST) {
        return RouteFailureHealth::unknown;
    }
    if (outbound->type == OutboundType::URLTEST && selections) {
        const auto selected = selections->find(tag);
        if (selected != selections->end() && !selected->second.empty()) {
            const auto children = route_failure_group_children(*outbound);
            if (std::find(children.begin(), children.end(), selected->second) == children.end()) {
                return RouteFailureHealth::unknown;
            }
            const auto child = route_failure_health_for(
                selected->second, outbounds, selections, health, depth + 1);
            if (child == RouteFailureHealth::link_unavailable) return child;
            const auto selected_outbound = std::find_if(outbounds.begin(), outbounds.end(),
                [&selected](const Outbound& candidate) { return candidate.tag == selected->second; });
            // A group's existing selector owns its health decision. Its bound
            // direct-child result must not compete with an independently timed
            // InterfaceProbe sample. A live missing link still overrides it.
            if (selected_outbound == outbounds.end() ||
                selected_outbound->type != OutboundType::INTERFACE) {
                return child;
            }
            const auto group_result = health->find(tag);
            return group_result != health->end() &&
                   group_result->second != RouteFailureHealth::unknown
                ? group_result->second : child;
        } else {
            const auto found = health->find(tag);
            if (found != health->end() && found->second == RouteFailureHealth::unavailable) {
                return RouteFailureHealth::unavailable;
            }
            const auto children = route_failure_group_children(*outbound);
            const bool all_failed = !children.empty() && std::all_of(
                children.begin(), children.end(), [&](const std::string& child) {
                    return route_failure_is_unavailable(route_failure_health_for(
                        child, outbounds, selections, health, depth + 1));
                });
            return all_failed ? RouteFailureHealth::unavailable : RouteFailureHealth::unknown;
        }
    } else if (outbound->type == OutboundType::URLTEST) {
        return RouteFailureHealth::unknown;
    }
    const auto found = health->find(tag);
    return found == health->end() ? RouteFailureHealth::unknown : found->second;
}

struct RouteFailureTarget {
    std::string outbound_tag;
    bool drop{false};
};

// This selects only the classifier for this rule. It never changes a shared
// outbound table, group selection, strict-enforcement setting or conntrack.
inline RouteFailureTarget select_route_failure_target(
    const RouteRule& rule,
    const std::vector<Outbound>& outbounds,
    const std::map<std::string, std::string>* selections,
    const RouteFailureHealthSnapshot* health) {
    const auto policy = rule.failure_policy.value_or(api::FailurePolicy::INHERIT);
    if (policy == api::FailurePolicy::INHERIT ||
        !route_failure_is_unavailable(route_failure_health_for(
            rule.outbound, outbounds, selections, health))) {
        return {rule.outbound, false};
    }
    if (policy == api::FailurePolicy::FALLBACK && rule.fallback_outbound &&
        route_failure_is_usable(route_failure_health_for(
            *rule.fallback_outbound, outbounds, selections, health))) {
        return {*rule.fallback_outbound, false};
    }
    return {{}, true};
}

} // namespace keen_pbr3
