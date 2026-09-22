#ifdef WITH_API
#include "handler_rule_counters.hpp"

#include <algorithm>
#include <chrono>
#include <map>

namespace keen_pbr3 {

api::RuleCountersResponse build_rule_counters_response(
    const Config& applied, bool unapplied_draft,
    const RoutingFirewallEvidenceLookup& lookup) {
    constexpr std::size_t limit = 128;
    api::RuleCountersResponse response;
    response.captured_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    response.unapplied_draft = unapplied_draft;
    response.total = 0;
    response.truncated = false;
    if (!applied.route || !applied.route->rules) return response;
    const auto& configured = *applied.route->rules;
    response.total = static_cast<std::int64_t>(configured.size());
    response.truncated = configured.size() > limit;
    std::map<std::string, std::string> names;
    if (applied.outbounds) {
        for (const auto& outbound : *applied.outbounds) {
            const auto name = outbound.display_name.value_or("");
            names[outbound.tag] = name.empty() ? outbound.tag : name;
        }
    }
    std::vector<FirewallClassifierQuery> queries;
    for (std::size_t index = 0; index < std::min(configured.size(), limit); ++index) {
        const auto& rule = configured[index];
        decltype(response.rules)::value_type entry;
        entry.rule_index = static_cast<std::int64_t>(index);
        entry.name = rule.display_name.value_or("");
        entry.outbound = rule.outbound;
        const auto name = names.find(rule.outbound);
        entry.outbound_name = name == names.end() ? rule.outbound : name->second;
        entry.enabled = route_rule_enabled(rule);
        FirewallClassifierEvidence initial;
        initial.status = entry.enabled ? FirewallCounterStatus::Unavailable
                                       : FirewallCounterStatus::NotApplicable;
        entry.ipv4 = to_api_routing_firewall_evidence(initial);
        entry.ipv6 = entry.ipv4;
        if (entry.enabled) {
            queries.push_back({index, AF_INET});
            queries.push_back({index, AF_INET6});
        }
        response.rules.push_back(std::move(entry));
    }
    if (!lookup || queries.empty()) return response;
    try {
        // One invocation: the collector shares at most two iptables reads or
        // one nft read across ALL rules, rather than shelling out per row.
        const auto observations = lookup(queries);
        if (observations.size() != queries.size()) return response;
        for (std::size_t index = 0; index < queries.size(); ++index) {
            const auto& query = queries[index];
            auto& row = response.rules.at(query.rule_index);
            auto& evidence = query.family == AF_INET ? row.ipv4 : row.ipv6;
            evidence = to_api_routing_firewall_evidence(observations[index]);
        }
    } catch (...) {
        // Missing evidence is not zero traffic, an unhealthy route, or a
        // reason to start/reconcile anything. Preserve the applied labels.
    }
    return response;
}

void register_rule_counters_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/routing/counters", [&ctx]() -> std::string {
        if (!ctx.get_rule_counters_fn) throw ApiError("Rule counters unavailable", 503);
        return nlohmann::json(ctx.get_rule_counters_fn()).dump();
    });
}

} // namespace keen_pbr3
#endif
