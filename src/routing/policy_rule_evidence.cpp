#include "policy_rule_evidence.hpp"

#include <algorithm>
#include <chrono>

namespace keen_pbr3 {

PolicyRuleSnapshot policy_rule_evidence_detail::capture_policy_rule_snapshot(
    int family, std::int64_t snapshot_at, PolicyRuleDump dump) noexcept {
    PolicyRuleSnapshot snapshot;
    snapshot.snapshot_at = snapshot_at;
    try {
        if (dump) {
            snapshot.rules = dump(family);
            snapshot.available = true;
        }
    } catch (...) {
        snapshot.rules.clear();
        snapshot.available = false;
    }
    return snapshot;
}

PolicyRuleSnapshot system_policy_rule_snapshot(int family) noexcept {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return policy_rule_evidence_detail::capture_policy_rule_snapshot(
        family, now, &netlink_detail::dump_policy_rules_read_only);
}

PolicyRuleEvidence select_policy_rule_evidence(
    const PolicyRuleSnapshot& snapshot, int family, std::uint32_t query_mark) {
    PolicyRuleEvidence evidence;
    evidence.available = snapshot.available;
    evidence.snapshot_at = snapshot.snapshot_at;
    if (!snapshot.available) return evidence;

    for (const auto& rule : snapshot.rules) {
        if (rule.family != family) continue;
        if (!rule.exact_identity_representable ||
            (query_mark & rule.fwmask) == (rule.fwmark & rule.fwmask)) {
            evidence.rules.push_back(rule);
        }
    }
    // Kernel dump order breaks equal-priority ties; do not invent a preference.
    std::stable_sort(evidence.rules.begin(), evidence.rules.end(),
        [](const DumpedRule& left, const DumpedRule& right) {
            return left.priority < right.priority;
        });
    evidence.total = evidence.rules.size();
    constexpr std::size_t response_limit = 32U;
    evidence.truncated = evidence.total > response_limit;
    if (evidence.truncated) evidence.rules.resize(response_limit);
    return evidence;
}

} // namespace keen_pbr3
