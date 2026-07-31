#include "list_delete_planner.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {
namespace {

using ReplacementMap =
    std::map<std::string, std::optional<std::string>>;

ReplacementMap validate_targets(
    const Config& source,
    const std::vector<ListDeleteTarget>& targets) {
    if (targets.empty()) {
        throw std::invalid_argument(
            "At least one list delete target is required");
    }
    if (!source.lists.has_value()) {
        throw std::invalid_argument(
            "Cannot delete a list from an empty configuration");
    }

    ReplacementMap replacements;
    for (const auto& target : targets) {
        if (target.list_id.empty()) {
            throw std::invalid_argument(
                "List delete target id must not be empty");
        }
        if (source.lists->find(target.list_id) ==
            source.lists->end()) {
            throw std::invalid_argument(
                "List delete target does not exist: " +
                target.list_id);
        }
        if (!replacements
                 .emplace(
                     target.list_id,
                     target.replacement_list_id)
                 .second) {
            throw std::invalid_argument(
                "Duplicate list delete target: " +
                target.list_id);
        }
    }

    for (const auto& [list_id, replacement] : replacements) {
        if (!replacement.has_value()) continue;
        if (replacement->empty()) {
            throw std::invalid_argument(
                "Replacement list id must not be empty");
        }
        if (*replacement == list_id) {
            throw std::invalid_argument(
                "A deleted list cannot replace itself: " +
                list_id);
        }
        if (replacements.find(*replacement) !=
            replacements.end()) {
            throw std::invalid_argument(
                "Replacement list is also selected for deletion: " +
                *replacement);
        }
        if (source.lists->find(*replacement) ==
            source.lists->end()) {
            throw std::invalid_argument(
                "Replacement list does not exist: " +
                *replacement);
        }
    }
    return replacements;
}

std::vector<std::string> rewrite_list_references(
    const std::vector<std::string>& original,
    const ReplacementMap& replacements,
    std::size_t& rebound_references) {
    std::set<std::string> retained_originals;
    for (const auto& list_id : original) {
        if (replacements.find(list_id) ==
            replacements.end()) {
            retained_originals.insert(list_id);
        }
    }

    std::set<std::string> inserted_replacements;
    std::vector<std::string> rewritten;
    rewritten.reserve(original.size());
    for (const auto& list_id : original) {
        const auto target = replacements.find(list_id);
        if (target == replacements.end()) {
            rewritten.push_back(list_id);
            continue;
        }
        if (!target->second.has_value()) continue;

        ++rebound_references;
        const auto& replacement = *target->second;
        if (retained_originals.find(replacement) !=
                retained_originals.end() ||
            !inserted_replacements.insert(replacement).second) {
            continue;
        }
        rewritten.push_back(replacement);
    }
    return rewritten;
}

} // namespace

ListDeletePlan plan_list_delete(
    const Config& source,
    const std::vector<ListDeleteTarget>& targets) {
    const ReplacementMap replacements =
        validate_targets(source, targets);

    ListDeletePlan plan;
    plan.config = source;
    plan.summary.deleted_lists.reserve(targets.size());
    for (const auto& target : targets) {
        plan.summary.deleted_lists.push_back(target.list_id);
    }

    if (plan.config.route && plan.config.route->rules) {
        std::vector<RouteRule> rewritten_rules;
        rewritten_rules.reserve(plan.config.route->rules->size());
        for (auto rule : *plan.config.route->rules) {
            if (!rule.list.has_value()) {
                rewritten_rules.push_back(std::move(rule));
                continue;
            }

            const auto rewritten = rewrite_list_references(
                *rule.list,
                replacements,
                plan.summary.rebound_references);
            if (rewritten == *rule.list) {
                rewritten_rules.push_back(std::move(rule));
                continue;
            }
            if (rewritten.empty() &&
                !route_rule_has_non_list_match_condition(rule)) {
                ++plan.summary.removed_route_rules;
                continue;
            }

            if (rewritten.empty()) {
                rule.list.reset();
            } else {
                rule.list = rewritten;
            }
            ++plan.summary.updated_route_rules;
            rewritten_rules.push_back(std::move(rule));
        }
        plan.config.route->rules = std::move(rewritten_rules);
    }

    if (plan.config.dns && plan.config.dns->rules) {
        std::vector<DnsRule> rewritten_rules;
        rewritten_rules.reserve(plan.config.dns->rules->size());
        for (auto rule : *plan.config.dns->rules) {
            const auto rewritten = rewrite_list_references(
                rule.list,
                replacements,
                plan.summary.rebound_references);
            if (rewritten == rule.list) {
                rewritten_rules.push_back(std::move(rule));
                continue;
            }
            if (rewritten.empty()) {
                ++plan.summary.removed_dns_rules;
                continue;
            }

            rule.list = rewritten;
            ++plan.summary.updated_dns_rules;
            rewritten_rules.push_back(std::move(rule));
        }
        plan.config.dns->rules = std::move(rewritten_rules);
    }

    for (const auto& [list_id, replacement] : replacements) {
        (void)replacement;
        plan.config.lists->erase(list_id);
    }
    if (plan.config.lists->empty()) {
        plan.config.lists.reset();
    }
    return plan;
}

} // namespace keen_pbr3
