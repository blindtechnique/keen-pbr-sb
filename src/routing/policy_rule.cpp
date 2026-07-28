#include "policy_rule.hpp"

#include <algorithm>
#include <netinet/in.h>

#include "../log/logger.hpp"

namespace keen_pbr3 {

namespace {

bool rules_equal(const RuleSpec& a, const RuleSpec& b) {
    return a.fwmark == b.fwmark &&
           a.fwmask == b.fwmask &&
           a.table == b.table &&
           a.priority == b.priority &&
           a.family == b.family;
}

bool rule_covers_family(const RuleSpec& rule,
                        const RuleSpec& concrete) {
    return rule.fwmark == concrete.fwmark &&
           rule.fwmask == concrete.fwmask &&
           rule.table == concrete.table &&
           rule.priority == concrete.priority &&
           (rule.family == 0 || rule.family == concrete.family);
}

bool rule_matches_live(const RuleSpec& expected, const DumpedRule& actual) {
    return expected.fwmark == actual.fwmark &&
           expected.fwmask == actual.fwmask &&
           expected.table == actual.table &&
           expected.priority == actual.priority &&
           expected.family == actual.family;
}

std::vector<RuleSpec> missing_live_rules(
    const std::vector<RuleSpec>& desired,
    const std::vector<DumpedRule>& live) {
    std::vector<RuleSpec> missing;
    for (const auto& logical : desired) {
        const int dual_stack_families[] = {AF_INET, AF_INET6};
        const int* begin = dual_stack_families;
        const int* end = dual_stack_families + 2;
        int single_family = logical.family;
        if (logical.family != 0) {
            begin = &single_family;
            end = begin + 1;
        }

        for (auto family = begin; family != end; ++family) {
            RuleSpec concrete = logical;
            concrete.family = *family;
            const bool present = std::any_of(
                live.begin(),
                live.end(),
                [&](const DumpedRule& candidate) {
                    return rule_matches_live(concrete, candidate);
                });
            if (!present) {
                missing.push_back(concrete);
            }
        }
    }
    return missing;
}

} // anonymous namespace

PolicyRuleManager::PolicyRuleManager(RuleNetlinkOperations& netlink, bool dry_run)
    : netlink_(netlink),
      dry_run_(dry_run) {}

PolicyRuleManager::~PolicyRuleManager() {
    // Best-effort cleanup on destruction
    try {
        clear();
    } catch (const std::exception& e) {
        Logger::instance().error("PolicyRuleManager cleanup failed during destruction: {}",
                                 e.what());
    } catch (...) {
        Logger::instance().error(
            "PolicyRuleManager cleanup failed during destruction: unknown error");
    }
}

bool PolicyRuleManager::is_tracked(const RuleSpec& spec) const {
    return std::any_of(rules_.begin(), rules_.end(),
                       [&](const RuleSpec& r) { return rules_equal(r, spec); });
}

void PolicyRuleManager::add(const RuleSpec& spec) {
    if (is_tracked(spec)) {
        return;
    }
    if (!dry_run_) {
        const int families[] = {AF_INET, AF_INET6};
        const int* begin = families;
        const int* end = families + 2;
        int single_family = spec.family;
        if (spec.family != 0) {
            begin = &single_family;
            end = begin + 1;
        }

        std::vector<RuleSpec> newly_owned;
        try {
            for (auto family = begin; family != end; ++family) {
                if (netlink_.add_rule_for_family(spec, *family) ==
                    RuleAddResult::Created) {
                    RuleSpec concrete = spec;
                    concrete.family = *family;
                    newly_owned.push_back(concrete);
                }
            }
        } catch (...) {
            for (auto it = newly_owned.rbegin(); it != newly_owned.rend(); ++it) {
                try {
                    netlink_.delete_rule_for_family(*it, it->family);
                } catch (const std::exception& e) {
                    Logger::instance().error(
                        "Failed to roll back policy rule family {}: {}",
                        it->family, e.what());
                }
            }
            throw;
        }
        owned_rules_.insert(
            owned_rules_.end(), newly_owned.begin(), newly_owned.end());
    }
    rules_.push_back(spec);
}

void PolicyRuleManager::remove(const RuleSpec& spec) {
    auto it = std::find_if(rules_.begin(), rules_.end(),
                           [&](const RuleSpec& r) { return rules_equal(r, spec); });
    if (it == rules_.end()) {
        return;
    }
    if (!dry_run_) {
        for (auto owned = owned_rules_.begin(); owned != owned_rules_.end();) {
            const bool same_logical_rule =
                owned->fwmark == spec.fwmark &&
                owned->fwmask == spec.fwmask &&
                owned->table == spec.table &&
                owned->priority == spec.priority;
            if (same_logical_rule &&
                (spec.family == 0 || spec.family == owned->family)) {
                // Reconciliation can change the representation of the same
                // policy from a concrete IPv4 rule to family=0 (or back) when
                // effective IPv6 support changes. The replacement is tracked
                // before the obsolete representation is removed. Transfer
                // ownership to that replacement instead of deleting a kernel
                // family which is still desired.
                const bool still_covered = std::any_of(
                    rules_.begin(),
                    rules_.end(),
                    [&](const RuleSpec& candidate) {
                        return &candidate != &*it &&
                               rule_covers_family(candidate, *owned);
                    });
                if (still_covered) {
                    ++owned;
                    continue;
                }
                try {
                    netlink_.delete_rule_for_family(*owned, owned->family);
                } catch (const std::exception& e) {
                    Logger::instance().error(
                        "Failed to delete policy rule family {}: {}",
                        owned->family, e.what());
                    return;
                }
                owned = owned_rules_.erase(owned);
            } else {
                ++owned;
            }
        }
    }
    rules_.erase(it);
}

void PolicyRuleManager::reconcile(const std::vector<RuleSpec>& desired) {
    add_missing(desired);
    remove_obsolete(desired);
}

void PolicyRuleManager::add_missing(const std::vector<RuleSpec>& desired) {
    if (!dry_run_) {
        const auto live = netlink_.dump_policy_rules();
        const auto missing = missing_live_rules(desired, live);

        for (const auto& concrete : missing) {
            RuleSpec logical = concrete;
            logical.family = 0;
            if (!is_tracked(logical) && !is_tracked(concrete)) {
                continue;
            }

            // The live snapshot proves that any previously owned instance has
            // vanished. Drop that stale ownership before recreating it: if an
            // identical foreign rule wins the race, AlreadyPresent must remain
            // foreign and must not be deleted during shutdown.
            owned_rules_.erase(
                std::remove_if(
                    owned_rules_.begin(),
                    owned_rules_.end(),
                    [&](const RuleSpec& owned) {
                        return rules_equal(owned, concrete);
                    }),
                owned_rules_.end());

            if (netlink_.add_rule_for_family(concrete, concrete.family) !=
                RuleAddResult::Created) {
                continue;
            }

            const bool already_owned = std::any_of(
                owned_rules_.begin(),
                owned_rules_.end(),
                [&](const RuleSpec& owned) {
                    return rules_equal(owned, concrete);
                });
            if (!already_owned) {
                owned_rules_.push_back(concrete);
            }
            Logger::instance().info(
                "Restoring vanished managed policy rule (table={}, fwmark={}, mask={}, priority={}, family={})",
                concrete.table,
                concrete.fwmark,
                concrete.fwmask,
                concrete.priority,
                concrete.family);
        }
    }

    for (const RuleSpec& rule : desired) {
        add(rule);
    }
}

void PolicyRuleManager::remove_obsolete(const std::vector<RuleSpec>& desired) {
    const std::vector<RuleSpec> current = rules_;
    for (const RuleSpec& rule : current) {
        const bool still_desired = std::any_of(desired.begin(), desired.end(),
                                               [&](const RuleSpec& candidate) {
                                                   return rules_equal(rule, candidate);
                                               });
        if (!still_desired) {
            remove(rule);
        }
    }
}

void PolicyRuleManager::adopt_desired(const std::vector<RuleSpec>& desired) {
    rules_ = desired;
    owned_rules_.clear();
}

void PolicyRuleManager::clear() {
    // Remove in reverse order (last added first)
    for (auto it = owned_rules_.rbegin(); it != owned_rules_.rend(); ++it) {
        try {
            if (!dry_run_) {
                netlink_.delete_rule_for_family(*it, it->family);
            }
        } catch (const std::exception& e) {
            Logger::instance().error(
                "Failed to delete policy rule during clear() (table={}, fwmark={}, mask={}, priority={}, family={}): {}",
                it->table,
                it->fwmark,
                it->fwmask,
                it->priority,
                it->family,
                e.what());
        } catch (...) {
            Logger::instance().error(
                "Failed to delete policy rule during clear() (table={}, fwmark={}, mask={}, priority={}, family={}): unknown error",
                it->table,
                it->fwmark,
                it->fwmask,
                it->priority,
                it->family);
        }
    }
    owned_rules_.clear();
    rules_.clear();
}

} // namespace keen_pbr3
