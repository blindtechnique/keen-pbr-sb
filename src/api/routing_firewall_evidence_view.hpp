#pragma once

#include "../cmd/test_routing.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <functional>
#include <limits>
#include <map>
#include <vector>

namespace keen_pbr3 {

using RoutingFirewallEvidenceLookup = std::function<
    std::vector<FirewallClassifierEvidence>(const std::vector<FirewallClassifierQuery>&)>;

// Build one query per realized rule/family, retaining all physical classifiers
// of that rule. The config-based list_match is intentionally not a filter.
inline void attach_routing_firewall_evidence(
    std::vector<TestRoutingEntry>& entries,
    const std::vector<RuleState>& realized_rules,
    const RoutingFirewallEvidenceLookup& lookup) {
    std::vector<FirewallClassifierQuery> queries;
    std::map<std::pair<std::size_t, int>, std::size_t> unique_queries;
    const auto no_query = std::numeric_limits<std::size_t>::max();
    std::vector<std::size_t> entry_queries(entries.size(), no_query);
    for (std::size_t index = 0; index < entries.size(); ++index) {
        auto& entry = entries[index];
        entry.firewall_counters.emplace();
        entry.firewall_counters->status = FirewallCounterStatus::NotApplicable;
        if (!entry.actual_rule_index ||
            entry.evaluation == RoutingMatchEvaluation::InsufficientContext ||
            entry.actual_outbound.empty() || entry.actual_outbound == "(unknown)" ||
            entry.ip.find('\0') != std::string::npos) {
            continue;
        }
        in_addr address4{};
        in6_addr address6{};
        int family = AF_UNSPEC;
        if (::inet_pton(AF_INET, entry.ip.c_str(), &address4) == 1) family = AF_INET;
        else if (::inet_pton(AF_INET6, entry.ip.c_str(), &address6) == 1) family = AF_INET6;
        else continue;

        entry.firewall_counters->status = FirewallCounterStatus::Unavailable;
        // rule_index is an index into the captured config, not the position in
        // this possibly pruned/reordered vector of realized rules.
        if (std::none_of(realized_rules.begin(), realized_rules.end(),
                [&](const RuleState& rule) { return rule.rule_index == *entry.actual_rule_index; })) {
            continue;
        }
        const auto key = std::make_pair(*entry.actual_rule_index, family);
        const auto inserted = unique_queries.emplace(key, queries.size());
        if (inserted.second) queries.push_back({key.first, key.second});
        entry_queries[index] = inserted.first->second;
    }
    if (queries.empty() || !lookup) return;

    std::vector<FirewallClassifierEvidence> observed;
    try {
        observed = lookup(queries);
    } catch (...) {
        // A failed optional read must not erase DNS/FIB/list results or retry.
        return;
    }
    if (observed.size() != queries.size()) return;
    for (std::size_t index = 0; index < entries.size(); ++index) {
        if (entry_queries[index] != no_query) {
            entries[index].firewall_counters = observed[entry_queries[index]];
        }
    }
}

inline api::FirewallCounters to_api_routing_firewall_evidence(
    const FirewallClassifierEvidence& evidence) {
    api::FirewallCounters result;
    result.scope = api::RoutingTestFirewallCountersScope::PREROUTING;
    result.status = api::RoutingTestFirewallCountersStatus::UNAVAILABLE;
    switch (evidence.status) {
        case FirewallCounterStatus::Observed:
            result.status = api::RoutingTestFirewallCountersStatus::OBSERVED;
            break;
        case FirewallCounterStatus::Unavailable:
            break;
        case FirewallCounterStatus::NotApplicable:
            result.status = api::RoutingTestFirewallCountersStatus::NOT_APPLICABLE;
            break;
        case FirewallCounterStatus::Ambiguous:
            result.status = api::RoutingTestFirewallCountersStatus::AMBIGUOUS;
            break;
    }
    result.snapshot_at = evidence.snapshot_at;
    result.total = static_cast<std::int64_t>(evidence.total);
    result.truncated = evidence.truncated;
    result.rules.reserve(evidence.rules.size());
    for (const auto& rule : evidence.rules) {
        api::RoutingTestFirewallCounterElement item;
        item.family = rule.family == AF_INET6 ? api::Family::IPV6 : api::Family::IPV4;
        item.table = rule.table;
        item.chain = rule.chain;
        item.position = static_cast<std::int64_t>(rule.position);
        item.action = api::RoutingTestFirewallCounterAction::MARK;
        if (rule.action == "drop") item.action = api::RoutingTestFirewallCounterAction::DROP;
        else if (rule.action == "pass") item.action = api::RoutingTestFirewallCounterAction::PASS;
        item.set_name = rule.set_name;
        if (rule.fwmark) item.fwmark = static_cast<std::int64_t>(*rule.fwmark);
        if (rule.fwmask) item.fwmask = static_cast<std::int64_t>(*rule.fwmask);
        item.packets = std::to_string(rule.packets);
        item.bytes = std::to_string(rule.bytes);
        result.rules.push_back(std::move(item));
    }
    return result;
}

} // namespace keen_pbr3
