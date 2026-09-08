#pragma once

#include "netlink.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace keen_pbr3 {

struct PolicyRuleSnapshot {
    bool available{false};
    std::int64_t snapshot_at{0}; // Unix seconds: time of the read attempt.
    std::vector<DumpedRule> rules;
};

struct PolicyRuleEvidence {
    bool available{false};
    std::int64_t snapshot_at{0};
    std::size_t total{0}; // Relevant rows before the response limit.
    bool truncated{false};
    std::vector<DumpedRule> rules;
};

// Complete kernel inventory or unavailable, never a partial successful read.
PolicyRuleSnapshot system_policy_rule_snapshot(int family) noexcept;

// Retains compatible exact rules and ALL inexact rules of the requested family.
// Additional selectors, inversion and non-lookup actions make applicability
// uncertain. Priority order is evidence, not a claim of a winning rule/table.
PolicyRuleEvidence select_policy_rule_evidence(
    const PolicyRuleSnapshot& snapshot, int family, std::uint32_t query_mark);

namespace policy_rule_evidence_detail {

using PolicyRuleDump = std::vector<DumpedRule> (*)(int family);

// Injectable read boundary for error tests; uses the same no-partial contract.
PolicyRuleSnapshot capture_policy_rule_snapshot(
    int family, std::int64_t snapshot_at, PolicyRuleDump dump) noexcept;

} // namespace policy_rule_evidence_detail
} // namespace keen_pbr3
