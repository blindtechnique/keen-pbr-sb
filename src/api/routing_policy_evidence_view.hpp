#pragma once

#include "../cmd/test_routing.hpp"
#include "../routing/policy_rule_evidence.hpp"

#include <arpa/inet.h>
#include <functional>
#include <optional>
#include <vector>

namespace keen_pbr3 {

enum class RoutingPolicyEvidenceStatus { NotApplicable, Unavailable, Observed };

struct RoutingPolicyEvidenceView {
    RoutingPolicyEvidenceStatus status{RoutingPolicyEvidenceStatus::NotApplicable};
    PolicyRuleEvidence evidence;
};

using RoutingPolicySnapshotLookup = std::function<PolicyRuleSnapshot(int family)>;

// Per-request projection: a family's bounded kernel snapshot is read at most
// once, even when several resolved addresses share it or that read fails.
inline std::vector<RoutingPolicyEvidenceView> collect_routing_policy_evidence(
    const std::vector<TestRoutingEntry>& entries,
    const RoutingPolicySnapshotLookup& lookup) {
    std::vector<RoutingPolicyEvidenceView> result(entries.size());
    std::optional<PolicyRuleSnapshot> ipv4, ipv6;
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        if (entry.evaluation == RoutingMatchEvaluation::InsufficientContext ||
            entry.actual_outbound.empty() || entry.actual_outbound == "(unknown)" ||
            entry.fib.verdict == RoutingFibVerdict::NotApplicable ||
            entry.ip.find('\0') != std::string::npos) {
            continue;
        }
        in_addr address4{};
        in6_addr address6{};
        int family = AF_UNSPEC;
        if (::inet_pton(AF_INET, entry.ip.c_str(), &address4) == 1) family = AF_INET;
        else if (::inet_pton(AF_INET6, entry.ip.c_str(), &address6) == 1) family = AF_INET6;
        else continue;

        auto& view = result[index];
        view.status = RoutingPolicyEvidenceStatus::Unavailable;
        auto& cached = family == AF_INET ? ipv4 : ipv6;
        if (!cached) {
            // Engage before calling an injected adapter so a failed read is
            // not retried for every address. Production preserves attempt time.
            cached.emplace();
            try {
                if (lookup) *cached = lookup(family);
            } catch (...) {
                // Optional evidence never invalidates a completed routing test.
            }
        }
        try {
            // A conclusive unmarked/default path queries mark zero. Do not mask
            // an existing realized mark: foreign bits can select an RPDB rule.
            view.evidence = select_policy_rule_evidence(
                *cached, family, entry.fib.fwmark.value_or(0U));
            if (view.evidence.available) view.status = RoutingPolicyEvidenceStatus::Observed;
        } catch (...) {
            view.evidence = {};
            view.evidence.snapshot_at = cached->snapshot_at;
        }
    }
    return result;
}

inline api::PolicyRules to_api_routing_policy_evidence(
    const RoutingPolicyEvidenceView& view) {
    api::PolicyRules result;
    result.status = api::RoutingTestPolicyRulesStatus::NOT_APPLICABLE;
    if (view.status == RoutingPolicyEvidenceStatus::Observed) {
        result.status = api::RoutingTestPolicyRulesStatus::OBSERVED;
    } else if (view.status == RoutingPolicyEvidenceStatus::Unavailable) {
        result.status = api::RoutingTestPolicyRulesStatus::UNAVAILABLE;
    }
    result.snapshot_at = view.evidence.snapshot_at;
    result.total = static_cast<std::int64_t>(view.evidence.total);
    result.truncated = view.evidence.truncated;
    result.rules.reserve(view.evidence.rules.size());
    for (const auto& rule : view.evidence.rules) {
        api::RoutingTestPolicyRuleElement item;
        item.family = rule.family == AF_INET6 ? api::Family::IPV6 : api::Family::IPV4;
        item.priority = static_cast<std::int64_t>(rule.priority);
        item.table = static_cast<std::int64_t>(rule.table);
        item.fwmark = static_cast<std::int64_t>(rule.fwmark);
        item.fwmask = static_cast<std::int64_t>(rule.fwmask);
        item.details_complete = rule.exact_identity_representable;
        result.rules.push_back(std::move(item));
    }
    return result;
}

} // namespace keen_pbr3
