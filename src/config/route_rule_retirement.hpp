#pragma once

#include "config.hpp"
#include <algorithm>
#include <set>

namespace keen_pbr3 {

inline bool route_rule_still_present(const RouteRule& rule, const Config& next) {
    if (!next.route || !next.route->rules) return false;
    return std::any_of(next.route->rules->begin(), next.route->rules->end(), [&](const RouteRule& candidate) {
        return rule.id && candidate.id ? rule.id == candidate.id
            : nlohmann::json(rule) == nlohmann::json(candidate);
    });
}

// Retire only the DNS bindings attached to removed routing rules. A DNS rule
// shared by multiple list/rule owners is narrowed rather than blindly deleted.
// Legacy catalogue bindings predate explicit provenance: recognize only their
// catalogue lists and matching DNS detour, never an unrelated DNS server.
inline void retire_route_dns_bindings(Config& next, const Config& previous) {
    if (!previous.route || !previous.route->rules || !next.dns || !next.dns->rules) return;
    std::vector<DnsRule> kept;
    const auto old_servers = previous.dns ? previous.dns->servers.value_or(std::vector<DnsServer>{}) : std::vector<DnsServer>{};
    for (auto dns : *next.dns->rules) {
        std::set<std::string> affected;
        auto owners = dns.route_rule_ids.value_or(std::vector<std::string>{});
        for (const auto& route : *previous.route->rules) {
            if (route_rule_still_present(route, next)) continue;
            bool linked = route.id && std::find(owners.begin(), owners.end(), *route.id) != owners.end();
            if (!dns.route_rule_ids && previous.lists) {
                const auto server = std::find_if(old_servers.begin(), old_servers.end(), [&](const DnsServer& item) { return item.tag == dns.server; });
                linked = server != old_servers.end() && server->detour == std::optional<std::string>{route.outbound} &&
                    !dns.list.empty() && std::all_of(dns.list.begin(), dns.list.end(), [&](const std::string& id) {
                        const auto list = previous.lists->find(id);
                        const auto& names = route_rule_lists(route);
                        return list != previous.lists->end() && list->second.catalog_identity.has_value() &&
                            std::find(names.begin(), names.end(), id) != names.end();
                    });
            }
            if (!linked) continue;
            const auto& names = route_rule_lists(route);
            affected.insert(names.begin(), names.end());
            if (route.id) owners.erase(std::remove(owners.begin(), owners.end(), *route.id), owners.end());
        }
        if (affected.empty()) { kept.push_back(std::move(dns)); continue; }
        // Another routing rule may still intentionally use the same list.
        if (next.route && next.route->rules) {
            for (const auto& route : *next.route->rules) {
                for (const auto& list : route_rule_lists(route)) {
                    if (affected.erase(list) != 0U && route.id &&
                        std::find(owners.begin(), owners.end(), *route.id) == owners.end()) owners.push_back(*route.id);
                }
            }
        }
        dns.list.erase(std::remove_if(dns.list.begin(), dns.list.end(), [&](const std::string& id) { return affected.count(id) != 0U; }), dns.list.end());
        if (dns.list.empty()) continue;
        if (owners.empty()) dns.route_rule_ids.reset();
        else dns.route_rule_ids = std::move(owners);
        kept.push_back(std::move(dns));
    }
    next.dns->rules = std::move(kept);
}

} // namespace keen_pbr3
