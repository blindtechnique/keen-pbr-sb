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

bool logical_rule_present_live(const RuleSpec& logical,
                               const std::vector<DumpedRule>& live) {
    return std::any_of(
        live.begin(), live.end(), [&](const DumpedRule& actual) {
            if (logical.family != 0 && logical.family != actual.family) {
                return false;
            }
            RuleSpec concrete = logical;
            concrete.family = actual.family;
            // Route-anchor safety only needs the visible dependency tuple.
            // A live rule with selectors which DumpedRule cannot represent
            // exactly still targets this table and must keep it protected.
            return policy_rule_detail::rule_matches_live(concrete, actual);
        });
}

bool logical_rule_has_uncovered_live_family(
    const RuleSpec& logical,
    const std::vector<DumpedRule>& live,
    const std::vector<RuleSpec>& tracked,
    const RuleSpec* excluded) {
    return std::any_of(
        live.begin(), live.end(), [&](const DumpedRule& actual) {
            if (logical.family != 0 && logical.family != actual.family) {
                return false;
            }
            RuleSpec concrete = logical;
            concrete.family = actual.family;
            if (!policy_rule_detail::rule_matches_live(concrete, actual)) {
                return false;
            }
            return std::none_of(
                tracked.begin(), tracked.end(), [&](const RuleSpec& candidate) {
                    return &candidate != excluded &&
                           rule_covers_family(candidate, concrete);
                });
        });
}

} // anonymous namespace

namespace policy_rule_detail {

bool rule_matches_live(const RuleSpec& expected, const DumpedRule& actual) {
    // Compatibility matcher for the existing PolicyRuleManager. Exact
    // transactions additionally require DumpedRule representability before
    // treating this visible tuple as an owned kernel identity.
    return expected.fwmark == actual.fwmark &&
           expected.fwmask == actual.fwmask &&
           expected.table == actual.table &&
           expected.priority == actual.priority &&
           expected.family == actual.family;
}

std::vector<RuleSpec> find_orphaned_generated_rules(
    const std::vector<RuleSpec>& desired,
    const std::vector<DumpedRule>& live,
    const std::set<uint32_t>& corroborated_route_tables) {
    std::vector<RuleSpec> orphaned;
    for (const auto& candidate : live) {
        if ((candidate.family != AF_INET && candidate.family != AF_INET6) ||
            candidate.priority != candidate.table ||
            corroborated_route_tables.count(candidate.table) == 0) {
            continue;
        }

        const bool collides_with_current_mark = std::any_of(
            desired.begin(), desired.end(), [&](const RuleSpec& expected) {
                return expected.fwmark == candidate.fwmark &&
                       expected.fwmask == candidate.fwmask;
            });
        if (!collides_with_current_mark) {
            continue;
        }

        const bool exact_desired = std::any_of(
            desired.begin(), desired.end(), [&](const RuleSpec& expected) {
                RuleSpec concrete = expected;
                concrete.family = candidate.family;
                return (expected.family == 0 ||
                        expected.family == candidate.family) &&
                       rule_matches_live(concrete, candidate);
            });
        if (exact_desired) {
            continue;
        }

        RuleSpec spec;
        spec.fwmark = candidate.fwmark;
        spec.fwmask = candidate.fwmask;
        spec.table = candidate.table;
        spec.priority = candidate.priority;
        spec.family = candidate.family;
        orphaned.push_back(spec);
    }
    return orphaned;
}

} // namespace policy_rule_detail

namespace {

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
                    return policy_rule_detail::rule_matches_live(
                        concrete, candidate);
                });
            if (!present) {
                missing.push_back(concrete);
            }
        }
    }
    return missing;
}

} // anonymous namespace

PolicyRuleManager::PolicyRuleManager(
    RuleNetlinkOperations& netlink,
    bool dry_run,
    bool cleanup_on_destruction)
    : netlink_(netlink),
      dry_run_(dry_run),
      cleanup_on_destruction_(cleanup_on_destruction) {}

PolicyRuleManager::~PolicyRuleManager() {
    if (!cleanup_on_destruction_) return;
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
        std::vector<RuleSpec> rollback_uncertain;
        const auto family_count =
            static_cast<std::size_t>(end - begin);
        // All ledger storage is reserved before the first kernel write. A
        // failed family add followed by an ambiguous rollback must still be
        // representable without allocating in the recovery path.
        newly_owned.reserve(family_count);
        rollback_uncertain.reserve(family_count);
        owned_rules_.reserve(owned_rules_.size() + family_count);
        rules_.reserve(rules_.size() + 1U);
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
                bool rollback_known = true;
                try {
                    netlink_.delete_rule_for_family(*it, it->family);
                } catch (const std::exception& e) {
                    Logger::instance().error(
                        "Failed to roll back policy rule family {}: {}",
                        it->family, e.what());
                    rollback_known = false;
                } catch (...) {
                    Logger::instance().error(
                        "Failed to roll back policy rule family {}: "
                        "unknown error",
                        it->family);
                    rollback_known = false;
                }
                if (!rollback_known) rollback_uncertain.push_back(*it);
            }
            if (!rollback_uncertain.empty()) {
                owned_rules_.insert(
                    owned_rules_.end(),
                    rollback_uncertain.begin(),
                    rollback_uncertain.end());
                rules_.push_back(spec);
            }
            throw;
        }
        owned_rules_.insert(
            owned_rules_.end(), newly_owned.begin(), newly_owned.end());
    }
    rules_.push_back(spec);
}

bool PolicyRuleManager::remove(const RuleSpec& spec) {
    auto it = std::find_if(rules_.begin(), rules_.end(),
                           [&](const RuleSpec& r) { return rules_equal(r, spec); });
    if (it == rules_.end()) {
        return true;
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
                    return false;
                }
                owned = owned_rules_.erase(owned);
            } else {
                ++owned;
            }
        }

        try {
            const auto live = netlink_.dump_policy_rules();
            if (logical_rule_has_uncovered_live_family(
                    spec, live, rules_, &*it)) {
                Logger::instance().warn(
                    "Policy rule remains live after owned-family cleanup; "
                    "retaining route-table dependency (table={}, fwmark={}, "
                    "mask={}, priority={})",
                    spec.table,
                    spec.fwmark,
                    spec.fwmask,
                    spec.priority);
                return false;
            }
        } catch (const std::exception& error) {
            Logger::instance().warn(
                "Could not prove policy-rule absence after cleanup; "
                "retaining route-table dependency (table={}, fwmark={}, "
                "mask={}, priority={}): {}",
                spec.table,
                spec.fwmark,
                spec.fwmask,
                spec.priority,
                error.what());
            return false;
        }
    }
    rules_.erase(it);
    return true;
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

std::set<uint32_t> PolicyRuleManager::remove_obsolete(
    const std::vector<RuleSpec>& desired) {
    std::set<uint32_t> uncertain_tables;
    const std::vector<RuleSpec> current = rules_;
    for (const RuleSpec& rule : current) {
        const bool still_desired = std::any_of(desired.begin(), desired.end(),
                                               [&](const RuleSpec& candidate) {
                                                   return rules_equal(rule, candidate);
                                               });
        if (!still_desired) {
            if (!remove(rule)) {
                uncertain_tables.insert(rule.table);
            }
        }
    }
    return uncertain_tables;
}

std::set<uint32_t> PolicyRuleManager::remove_orphaned_generated(
    const std::vector<RuleSpec>& desired,
    const std::set<uint32_t>& corroborated_route_tables) {
    if (dry_run_ || corroborated_route_tables.empty()) {
        return {};
    }

    std::set<uint32_t> uncertain_tables;
    std::vector<RuleSpec> orphaned;
    try {
        orphaned = policy_rule_detail::find_orphaned_generated_rules(
            desired, netlink_.dump_policy_rules(), corroborated_route_tables);
    } catch (const std::exception& error) {
        Logger::instance().warn(
            "Could not inspect stale managed policy rules: {}", error.what());
        // Without a complete rule inventory, do not retire any route which
        // supplied ownership/dependency evidence for this cleanup pass.
        return corroborated_route_tables;
    }
    for (const auto& rule : orphaned) {
        const bool tracked_by_this_process = std::any_of(
            rules_.begin(), rules_.end(), [&](const RuleSpec& tracked) {
                return rule_covers_family(tracked, rule);
            });
        if (tracked_by_this_process) {
            // remove_obsolete() owns the normal in-process generation change
            // and retains its existing rollback/ownership semantics.
            continue;
        }
        try {
            netlink_.delete_rule_for_family(rule, rule.family);
            Logger::instance().info(
                "Removed stale managed policy rule (table={}, fwmark={}, mask={}, priority={}, family={})",
                rule.table,
                rule.fwmark,
                rule.fwmask,
                rule.priority,
                rule.family);
        } catch (const std::exception& error) {
            // The committed desired generation is already complete. Keep
            // stale cleanup convergent and retryable instead of rolling that
            // generation back because one exact delete raced firmware.
            Logger::instance().warn(
                "Could not remove stale managed policy rule "
                "(table={}, fwmark={}, mask={}, priority={}, family={}): {}",
                rule.table,
                rule.fwmark,
                rule.fwmask,
                rule.priority,
                rule.family,
                error.what());
            uncertain_tables.insert(rule.table);
        }
    }
    return uncertain_tables;
}

std::set<uint32_t>
PolicyRuleManager::protect_route_tables_with_live_rules(
    const std::vector<RouteSpec>& candidate_routes,
    const std::set<uint32_t>& additional_candidate_tables,
    const std::vector<RuleSpec>& accounted_rules) {
    std::set<uint32_t> candidates = additional_candidate_tables;
    for (const auto& route : candidate_routes) {
        candidates.insert(route.table);
    }
    if (dry_run_ || candidates.empty()) {
        return {};
    }

    std::vector<DumpedRule> live;
    try {
        live = netlink_.dump_policy_rules();
    } catch (const std::exception& error) {
        Logger::instance().warn(
            "Could not inspect live policy-rule dependencies before route "
            "cleanup; protecting every candidate table: {}",
            error.what());
        return candidates;
    } catch (...) {
        Logger::instance().warn(
            "Could not inspect live policy-rule dependencies before route "
            "cleanup; protecting every candidate table: unknown error");
        return candidates;
    }

    std::set<uint32_t> protected_tables;
    for (const auto& rule : live) {
        if (candidates.count(rule.table) == 0U) {
            continue;
        }
        const bool accounted = std::any_of(
            accounted_rules.begin(),
            accounted_rules.end(),
            [&](const RuleSpec& logical) {
                if (logical.family != 0 &&
                    logical.family != rule.family) {
                    return false;
                }
                RuleSpec concrete = logical;
                concrete.family = rule.family;
                return policy_rule_detail::rule_matches_live(
                    concrete, rule);
            });
        if (!accounted) protected_tables.insert(rule.table);
    }
    return protected_tables;
}

void PolicyRuleManager::adopt_live_generated_desired(
    const std::vector<RuleSpec>& desired,
    const std::set<uint32_t>& corroborated_route_tables) noexcept {
    if (dry_run_ || corroborated_route_tables.empty()) {
        return;
    }
    try {
        const auto live = netlink_.dump_policy_rules();
        auto committed = owned_rules_;
        for (const auto& logical : desired) {
            if (corroborated_route_tables.count(logical.table) == 0) {
                continue;
            }
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
                    live.begin(), live.end(), [&](const DumpedRule& actual) {
                        return policy_rule_detail::rule_matches_live(
                            concrete, actual);
                    });
                const bool already_owned = std::any_of(
                    committed.begin(), committed.end(),
                    [&](const RuleSpec& candidate) {
                        return rules_equal(candidate, concrete);
                    });
                if (present && !already_owned) {
                    committed.push_back(concrete);
                }
            }
        }
        owned_rules_.swap(committed);
    } catch (const std::exception& error) {
        Logger::instance().warn(
            "Could not adopt exact live managed policy rules after commit: {}",
            error.what());
    } catch (...) {
        Logger::instance().warn(
            "Could not adopt exact live managed policy rules after commit: "
            "unknown error");
    }
}

void PolicyRuleManager::adopt_desired(const std::vector<RuleSpec>& desired) {
    rules_ = desired;
    owned_rules_.clear();
}

std::set<uint32_t> PolicyRuleManager::clear() {
    std::set<uint32_t> uncertain_tables;
    std::vector<RuleSpec> retained_owned;
    retained_owned.reserve(owned_rules_.size());

    // Remove in reverse order (last added first)
    for (auto it = owned_rules_.rbegin(); it != owned_rules_.rend(); ++it) {
        bool deleted = true;
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
            deleted = false;
        } catch (...) {
            Logger::instance().error(
                "Failed to delete policy rule during clear() (table={}, fwmark={}, mask={}, priority={}, family={}): unknown error",
                it->table,
                it->fwmark,
                it->fwmask,
                it->priority,
                it->family);
            deleted = false;
        }
        if (!deleted) {
            retained_owned.push_back(*it);
            uncertain_tables.insert(it->table);
        }
    }
    std::reverse(retained_owned.begin(), retained_owned.end());

    std::vector<DumpedRule> live;
    bool live_inventory_known = dry_run_;
    if (!dry_run_) {
        try {
            live = netlink_.dump_policy_rules();
            live_inventory_known = true;
        } catch (const std::exception& error) {
            Logger::instance().warn(
                "Could not prove policy-rule absence during clear(); "
                "retaining all route-table dependencies: {}",
                error.what());
        } catch (...) {
            Logger::instance().warn(
                "Could not prove policy-rule absence during clear(); "
                "retaining all route-table dependencies: unknown error");
        }
    }

    std::vector<RuleSpec> retained_logical;
    retained_logical.reserve(rules_.size());
    for (const auto& logical : rules_) {
        const bool has_uncertain_owned_family = std::any_of(
            retained_owned.begin(),
            retained_owned.end(),
            [&](const RuleSpec& owned) {
                return rule_covers_family(logical, owned);
            });
        const bool has_live_family =
            live_inventory_known &&
            logical_rule_present_live(logical, live);
        if (has_uncertain_owned_family || has_live_family ||
            !live_inventory_known) {
            retained_logical.push_back(logical);
            uncertain_tables.insert(logical.table);
        }
    }

    owned_rules_.swap(retained_owned);
    rules_.swap(retained_logical);
    return uncertain_tables;
}

} // namespace keen_pbr3
