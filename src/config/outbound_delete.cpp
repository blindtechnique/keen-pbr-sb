#include "outbound_delete.hpp"

#include "dependency_analysis.hpp"

#include <algorithm>
#include <optional>
#include <vector>

namespace keen_pbr3 {
bool interface_outbounds_are_unreferenced(
    const Config& config, const std::string& kernel_interface) {
    if (kernel_interface.empty()) return false;
    std::vector<DependencyTarget> targets;
    if (config.outbounds) {
        for (const auto& outbound : *config.outbounds) {
            if (outbound.type == OutboundType::INTERFACE &&
                outbound.interface == kernel_interface) {
                targets.push_back({DependencyEntityKind::Outbound, outbound.tag, false});
            }
        }
    }
    return targets.empty() || analyze_dependencies(config, targets).references.empty();
}

namespace {

void remove_fallback_detours(
    std::optional<std::vector<std::string>>& fallbacks,
    const std::set<std::string>& deleted_tags) {
    if (!fallbacks) return;
    const auto previous_size = fallbacks->size();
    fallbacks->erase(
        std::remove_if(fallbacks->begin(), fallbacks->end(),
                       [&](const std::string& tag) {
                           return deleted_tags.count(tag) != 0;
                       }),
        fallbacks->end());
    if (previous_size != fallbacks->size() && fallbacks->empty()) {
        fallbacks.reset();
    }
}

} // namespace

Config remove_outbound_dependencies(
    const Config& config, const std::set<std::string>& requested_tags) {
    std::vector<DependencyTarget> requested;
    if (config.outbounds) {
        for (const auto& outbound : *config.outbounds) {
            if ((outbound.type == OutboundType::INTERFACE ||
                 outbound.type == OutboundType::URLTEST) &&
                requested_tags.count(outbound.tag) != 0) {
                requested.push_back(
                    {DependencyEntityKind::Outbound, outbound.tag, false});
            }
        }
    }
    if (requested.empty()) return config;

    std::set<std::string> deleted_tags;
    for (const auto& target : analyze_dependencies(config, requested).targets) {
        if (target.kind == DependencyEntityKind::Outbound) {
            deleted_tags.insert(target.id);
        }
    }

    Config result = config;
    auto& outbounds = *result.outbounds;
    outbounds.erase(
        std::remove_if(outbounds.begin(), outbounds.end(),
                       [&](const Outbound& outbound) {
                           return deleted_tags.count(outbound.tag) != 0;
                       }),
        outbounds.end());
    for (auto& outbound : outbounds) {
        if (outbound.type != OutboundType::URLTEST ||
            !outbound.outbound_groups) {
            continue;
        }
        auto& groups = *outbound.outbound_groups;
        for (auto& group : groups) {
            group.outbounds.erase(
                std::remove_if(group.outbounds.begin(), group.outbounds.end(),
                               [&](const std::string& tag) {
                                   return deleted_tags.count(tag) != 0;
                               }),
                group.outbounds.end());
        }
        groups.erase(
            std::remove_if(groups.begin(), groups.end(),
                           [](const OutboundGroup& group) {
                               return group.outbounds.empty();
                           }),
            groups.end());
    }

    if (result.route && result.route->rules) {
        auto& rules = *result.route->rules;
        rules.erase(
            std::remove_if(rules.begin(), rules.end(),
                           [&](const RouteRule& rule) {
                               return deleted_tags.count(rule.outbound) != 0;
                           }),
            rules.end());
        for (auto& rule : rules) {
            if (rule.failure_policy == api::FailurePolicy::FALLBACK &&
                rule.fallback_outbound &&
                deleted_tags.count(*rule.fallback_outbound) != 0) {
                rule.failure_policy = api::FailurePolicy::BLOCK;
                rule.fallback_outbound.reset();
            }
        }
    }
    if (result.dns && result.dns->servers) {
        for (auto& server : *result.dns->servers) {
            if (server.detour && deleted_tags.count(*server.detour) != 0) {
                server.detour.reset();
            }
        }
    }
    if (result.lists) {
        for (auto& entry : *result.lists) {
            auto& list = entry.second;
            if (list.detour && deleted_tags.count(*list.detour) != 0) {
                list.detour.reset();
                list.fallback_detours.reset();
                list.refresh_detour_mode.reset();
            } else {
                remove_fallback_detours(list.fallback_detours, deleted_tags);
            }
        }
    }
    if (result.list_refresh) {
        auto& refresh = *result.list_refresh;
        if (refresh.detour && deleted_tags.count(*refresh.detour) != 0) {
            // Clear the deleted route policy, not future settings belonging
            // to this surviving list-refresh object.
            refresh.detour.reset();
            refresh.fallback_detours.reset();
        } else {
            remove_fallback_detours(refresh.fallback_detours, deleted_tags);
        }
    }
    return result;
}

InterfaceOutboundDeletePlan plan_native_interface_outbound_delete(
    const Config& config, const std::string& kernel_interface) {
    InterfaceOutboundDeletePlan plan{config, {}, false};
    if (kernel_interface.empty() || !config.outbounds) return plan;
    for (const auto& outbound : *config.outbounds) {
        if (outbound.type == OutboundType::INTERFACE &&
            outbound.interface == kernel_interface)
            plan.tags.insert(outbound.tag);
    }
    if (plan.tags.empty()) return plan;
    for (const auto& outbound : *config.outbounds) {
        if (outbound.type != OutboundType::URLTEST || !outbound.outbound_groups)
            continue;
        for (const auto& group : *outbound.outbound_groups)
            for (const auto& tag : group.outbounds)
                if (plan.tags.count(tag)) {
                    plan.used_by_group = true;
                    return plan;
                }
    }
    plan.config = remove_outbound_dependencies(config, plan.tags);
    return plan;
}

} // namespace keen_pbr3
