#pragma once

#include <set>
#include <vector>

#include "netlink.hpp"

namespace keen_pbr3 {

namespace policy_rule_detail {

bool rule_matches_live(const RuleSpec& expected, const DumpedRule& actual);

// Policy rules have no owner protocol. A stale rule is considered generated
// only when its shape, current mark namespace, and a protocol-186 route in its
// target table all corroborate prior keen-pbr ownership.
std::vector<RuleSpec> find_orphaned_generated_rules(
    const std::vector<RuleSpec>& desired,
    const std::vector<DumpedRule>& live,
    const std::set<uint32_t>& corroborated_route_tables);

} // namespace policy_rule_detail

// Manages installed ip policy rules, tracking them for duplicate avoidance and cleanup.
// Uses NetlinkManager for actual kernel operations.
class PolicyRuleManager {
public:
    // If dry_run is true, add()/clear() only track specs and skip netlink ops.
    explicit PolicyRuleManager(RuleNetlinkOperations& netlink, bool dry_run = false);
    ~PolicyRuleManager();

    // Non-copyable
    PolicyRuleManager(const PolicyRuleManager&) = delete;
    PolicyRuleManager& operator=(const PolicyRuleManager&) = delete;

    // Add a policy rule. If an identical rule is already tracked, this is a no-op.
    void add(const RuleSpec& spec);

    // Remove a specific policy rule. If not tracked, this is a no-op.
    void remove(const RuleSpec& spec);

    // Install missing rules before removing obsolete rules tracked by this
    // process. Live kernel state is reconciled as well: firmware can discard
    // one concrete family while the logical dual-stack rule remains tracked.
    // Existing foreign rules are observed, not claimed.
    void reconcile(const std::vector<RuleSpec>& desired);
    void add_missing(const std::vector<RuleSpec>& desired);
    void remove_obsolete(const std::vector<RuleSpec>& desired);
    void remove_orphaned_generated(
        const std::vector<RuleSpec>& desired,
        const std::set<uint32_t>& corroborated_route_tables);

    // Exact desired rules can safely be adopted only after the complete
    // route+rule generation commits and protocol-186 route evidence exists.
    void adopt_live_generated_desired(
        const std::vector<RuleSpec>& desired,
        const std::set<uint32_t>& corroborated_route_tables) noexcept;

    // Adopt an independently reconciled desired snapshot without taking
    // ownership of pre-existing kernel rules.
    void adopt_desired(const std::vector<RuleSpec>& desired);

    // Remove all installed policy rules (shutdown cleanup).
    void clear();

    // Number of currently tracked rules.
    size_t size() const { return rules_.size(); }

    // Read-only access to the tracked rules.
    const std::vector<RuleSpec>& get_rules() const { return rules_; }

private:
    RuleNetlinkOperations& netlink_;
    bool dry_run_{false};
    std::vector<RuleSpec> rules_;
    // Concrete-family rules created by this process and safe to delete.
    std::vector<RuleSpec> owned_rules_;

    // Check if an identical rule is already tracked.
    bool is_tracked(const RuleSpec& spec) const;
};

} // namespace keen_pbr3
