#pragma once

#include "firewall_state.hpp"
#include <algorithm>
#include <functional>
#include <set>

namespace keen_pbr3 {

// conntrack stores marks, not routing-table ids. Retire the old rule's table
// marks (including previously selected group leaves), never all router flows.
inline std::vector<std::uint32_t> retired_rule_conntrack_marks(
    const Config& previous, const Config& next,
    const std::vector<RuleState>& applied, const OutboundMarkMap& old_marks) {
    if (!previous.route || !previous.route->rules) return {};
    const auto next_rules = next.route ? next.route->rules.value_or(std::vector<RouteRule>{}) : std::vector<RouteRule>{};
    const auto equivalent = [](const RouteRule& a, const RouteRule& b) {
        auto left = nlohmann::json(a), right = nlohmann::json(b);
        for (const auto* field : {"id", "display_name"}) { left.erase(field); right.erase(field); }
        return left == right;
    };
    std::set<std::size_t> retired;
    std::set<std::string> tags;
    for (std::size_t index = 0; index < previous.route->rules->size(); ++index) {
        const auto& rule = previous.route->rules->at(index);
        if (!route_rule_enabled(rule)) continue;
        const bool retained = std::any_of(next_rules.begin(), next_rules.end(), [&](const RouteRule& candidate) {
            return route_rule_enabled(candidate) &&
                (!rule.id || !candidate.id || rule.id == candidate.id) && equivalent(rule, candidate);
        });
        if (retained) continue;
        retired.insert(index);
        tags.insert(rule.outbound);
        if (rule.fallback_outbound) tags.insert(*rule.fallback_outbound);
    }
    const auto mask = fwmark_mask_value(previous.fwmark.value_or(FwmarkConfig{}));
    std::set<std::uint32_t> marks;
    const auto add = [&](std::uint32_t mark) {
        mark &= mask;
        if (mark != 0U) marks.insert(mark);
    };
    for (const auto& rule : applied) {
        if (retired.count(rule.rule_index) == 0U || rule.action_type != RuleActionType::Mark) continue;
        add(rule.fwmark);
        add(rule.mark_for_family(AF_INET6));
    }
    const auto outbounds = previous.outbounds.value_or(std::vector<Outbound>{});
    std::set<std::string> visited;
    std::function<void(const std::string&)> collect = [&](const std::string& tag) {
        if (!visited.insert(tag).second) return;
        const auto found = old_marks.find(tag);
        if (found != old_marks.end()) add(found->second);
        const auto outbound = std::find_if(outbounds.begin(), outbounds.end(), [&](const Outbound& item) { return item.tag == tag; });
        if (outbound != outbounds.end() && outbound->outbound_groups) {
            for (const auto& group : *outbound->outbound_groups)
                for (const auto& child : group.outbounds) collect(child);
        }
    };
    for (const auto& tag : tags) collect(tag);
    return {marks.begin(), marks.end()};
}

} // namespace keen_pbr3
