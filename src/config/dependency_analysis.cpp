#include "dependency_analysis.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace keen_pbr3 {
namespace {

using TargetKey = std::pair<DependencyEntityKind, std::string>;

bool has_non_list_route_condition(const RouteRule& rule) {
    return rule.proto.has_value() || rule.dscp.has_value() ||
           rule.src_port.has_value() || rule.dest_port.has_value() ||
           rule.src_addr.has_value() || rule.dest_addr.has_value();
}

bool target_exists(const Config& config, const DependencyTarget& target) {
    switch (target.kind) {
    case DependencyEntityKind::List:
        return config.lists &&
               config.lists->find(target.id) != config.lists->end();
    case DependencyEntityKind::Outbound:
        if (!config.outbounds) return false;
        return std::any_of(
            config.outbounds->begin(),
            config.outbounds->end(),
            [&](const Outbound& outbound) { return outbound.tag == target.id; });
    case DependencyEntityKind::DnsServer:
        if (!config.dns || !config.dns->servers) return false;
        return std::any_of(
            config.dns->servers->begin(),
            config.dns->servers->end(),
            [&](const DnsServer& server) { return server.tag == target.id; });
    }
    return false;
}

void add_reference(
    DependencyAnalysis& analysis,
    std::set<std::tuple<DependencyEntityKind,
                        std::string,
                        DependencyDependentKind,
                        std::string,
                        DependencyRelation>>& seen,
    DependencyReference reference) {
    const auto key = std::make_tuple(reference.target.kind,
                                     reference.target.id,
                                     reference.dependent_kind,
                                     reference.dependent_id,
                                     reference.relation);
    if (seen.insert(key).second) {
        analysis.references.push_back(std::move(reference));
    }
}

std::vector<std::string> remaining_members(
    const OutboundGroup& group,
    const std::set<std::string>& removed_outbounds) {
    std::vector<std::string> result;
    std::copy_if(group.outbounds.begin(),
                 group.outbounds.end(),
                 std::back_inserter(result),
                 [&](const std::string& tag) {
                     return removed_outbounds.find(tag) ==
                            removed_outbounds.end();
                 });
    return result;
}

} // namespace

DependencyAnalysis analyze_dependencies(
    const Config& config,
    const std::vector<DependencyTarget>& requested_targets) {
    if (requested_targets.empty()) {
        throw std::invalid_argument("At least one dependency target is required");
    }

    DependencyAnalysis analysis;
    std::set<TargetKey> seen_targets;
    std::set<std::string> removed_lists;
    std::set<std::string> removed_outbounds;
    std::set<std::string> removed_dns_servers;

    for (const auto& requested : requested_targets) {
        DependencyTarget target{requested.kind, requested.id, false};
        if (target.id.empty()) {
            throw std::invalid_argument("Dependency target id must not be empty");
        }
        if (!target_exists(config, target)) {
            throw std::invalid_argument(
                "Dependency target does not exist: " + target.id);
        }
        if (!seen_targets.emplace(target.kind, target.id).second) continue;

        analysis.targets.push_back(target);
        switch (target.kind) {
        case DependencyEntityKind::List:
            removed_lists.insert(target.id);
            break;
        case DependencyEntityKind::Outbound:
            removed_outbounds.insert(target.id);
            break;
        case DependencyEntityKind::DnsServer:
            removed_dns_servers.insert(target.id);
            break;
        }
    }

    const auto& outbounds =
        config.outbounds.value_or(std::vector<Outbound>{});
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& outbound : outbounds) {
            if (outbound.type != OutboundType::URLTEST ||
                removed_outbounds.find(outbound.tag) != removed_outbounds.end()) {
                continue;
            }

            bool has_remaining_group = false;
            if (outbound.outbound_groups) {
                for (const auto& group : *outbound.outbound_groups) {
                    if (!remaining_members(group, removed_outbounds).empty()) {
                        has_remaining_group = true;
                        break;
                    }
                }
            }
            if (has_remaining_group) continue;

            removed_outbounds.insert(outbound.tag);
            if (seen_targets.emplace(DependencyEntityKind::Outbound,
                                     outbound.tag)
                    .second) {
                analysis.targets.push_back(
                    {DependencyEntityKind::Outbound, outbound.tag, true});
            }
            changed = true;
        }
    }

    std::set<std::tuple<DependencyEntityKind,
                        std::string,
                        DependencyDependentKind,
                        std::string,
                        DependencyRelation>>
        seen_references;

    const auto& route_rules =
        config.route && config.route->rules
            ? *config.route->rules
            : std::vector<RouteRule>{};
    for (std::size_t index = 0; index < route_rules.size(); ++index) {
        const auto& rule = route_rules[index];
        const auto rule_id = std::to_string(index);

        std::size_t removed_list_count = 0;
        for (const auto& list_name : route_rule_lists(rule)) {
            if (removed_lists.find(list_name) == removed_lists.end()) continue;
            ++removed_list_count;
            add_reference(
                analysis,
                seen_references,
                {{DependencyEntityKind::List, list_name, false},
                 DependencyDependentKind::RoutingRule,
                 rule_id,
                 DependencyRelation::UsesList,
                 DependencyConsequence::Modify,
                 "route.rules[" + rule_id + "].list",
                 "/routing-rules/" + rule_id + "/edit"});
        }
        if (removed_list_count > 0 &&
            removed_list_count == route_rule_lists(rule).size() &&
            !has_non_list_route_condition(rule)) {
            for (auto& reference : analysis.references) {
                if (reference.dependent_kind ==
                        DependencyDependentKind::RoutingRule &&
                    reference.dependent_id == rule_id &&
                    reference.relation == DependencyRelation::UsesList) {
                    reference.consequence = DependencyConsequence::Delete;
                }
            }
        }

        if (removed_outbounds.find(rule.outbound) !=
            removed_outbounds.end()) {
            add_reference(
                analysis,
                seen_references,
                {{DependencyEntityKind::Outbound, rule.outbound, false},
                 DependencyDependentKind::RoutingRule,
                 rule_id,
                 DependencyRelation::RoutesTo,
                 DependencyConsequence::Delete,
                 "route.rules[" + rule_id + "].outbound",
                 "/routing-rules/" + rule_id + "/edit"});
        }
    }

    if (config.dns && config.dns->rules) {
        for (std::size_t index = 0; index < config.dns->rules->size(); ++index) {
            const auto& rule = config.dns->rules->at(index);
            const auto rule_id = std::to_string(index);
            std::size_t removed_list_count = 0;
            for (const auto& list_name : rule.list) {
                if (removed_lists.find(list_name) == removed_lists.end()) {
                    continue;
                }
                ++removed_list_count;
                add_reference(
                    analysis,
                    seen_references,
                    {{DependencyEntityKind::List, list_name, false},
                     DependencyDependentKind::DnsRule,
                     rule_id,
                     DependencyRelation::UsesList,
                     DependencyConsequence::Modify,
                     "dns.rules[" + rule_id + "].list",
                     "/dns-rules/" + rule_id + "/edit"});
            }
            if (removed_list_count > 0 &&
                removed_list_count == rule.list.size()) {
                for (auto& reference : analysis.references) {
                    if (reference.dependent_kind ==
                            DependencyDependentKind::DnsRule &&
                        reference.dependent_id == rule_id &&
                        reference.relation == DependencyRelation::UsesList) {
                        reference.consequence = DependencyConsequence::Delete;
                    }
                }
            }
            if (removed_dns_servers.find(rule.server) !=
                removed_dns_servers.end()) {
                add_reference(
                    analysis,
                    seen_references,
                    {{DependencyEntityKind::DnsServer, rule.server, false},
                     DependencyDependentKind::DnsRule,
                     rule_id,
                     DependencyRelation::UsesDnsServer,
                     DependencyConsequence::Delete,
                     "dns.rules[" + rule_id + "].server",
                     "/dns-rules/" + rule_id + "/edit"});
            }
        }
    }

    if (config.dns && config.dns->servers) {
        for (const auto& server : *config.dns->servers) {
            if (!server.detour ||
                removed_outbounds.find(*server.detour) ==
                    removed_outbounds.end()) {
                continue;
            }
            add_reference(
                analysis,
                seen_references,
                {{DependencyEntityKind::Outbound, *server.detour, false},
                 DependencyDependentKind::DnsServer,
                 server.tag,
                 DependencyRelation::DetoursVia,
                 DependencyConsequence::Disconnect,
                 "dns.servers[" + server.tag + "].detour",
                 "/dns-servers/" + server.tag + "/edit"});
        }
    }

    if (config.dns && config.dns->fallback) {
        for (const auto& server_tag : *config.dns->fallback) {
            if (removed_dns_servers.find(server_tag) ==
                removed_dns_servers.end()) {
                continue;
            }
            add_reference(
                analysis,
                seen_references,
                {{DependencyEntityKind::DnsServer, server_tag, false},
                 DependencyDependentKind::DnsFallback,
                 server_tag,
                 DependencyRelation::FallbackTo,
                 DependencyConsequence::Modify,
                 "dns.fallback",
                 "/dns-servers"});
        }
    }

    if (config.lists) {
        for (const auto& [list_name, list] : *config.lists) {
            if (!list.detour ||
                removed_outbounds.find(*list.detour) ==
                    removed_outbounds.end()) {
                continue;
            }
            add_reference(
                analysis,
                seen_references,
                {{DependencyEntityKind::Outbound, *list.detour, false},
                 DependencyDependentKind::List,
                 list_name,
                 DependencyRelation::DetoursVia,
                 DependencyConsequence::Disconnect,
                 "lists." + list_name + ".detour",
                 "/lists/" + list_name + "/edit"});
        }
    }

    for (const auto& outbound : outbounds) {
        const auto cascaded_target = std::find_if(
            analysis.targets.begin(),
            analysis.targets.end(),
            [&](const DependencyTarget& target) {
                return target.kind == DependencyEntityKind::Outbound &&
                       target.id == outbound.tag && target.cascaded;
            });
        if (cascaded_target == analysis.targets.end() ||
            !outbound.outbound_groups) {
            continue;
        }
        for (std::size_t group_index = 0;
             group_index < outbound.outbound_groups->size();
             ++group_index) {
            const auto& group = outbound.outbound_groups->at(group_index);
            for (const auto& member : group.outbounds) {
                const auto requested_member = std::find_if(
                    analysis.targets.begin(),
                    analysis.targets.end(),
                    [&](const DependencyTarget& target) {
                        return target.kind == DependencyEntityKind::Outbound &&
                               target.id == member && !target.cascaded;
                    });
                if (requested_member == analysis.targets.end()) continue;

                add_reference(
                    analysis,
                    seen_references,
                    {*requested_member,
                     DependencyDependentKind::OutboundGroup,
                     outbound.tag,
                     DependencyRelation::ContainsMember,
                     DependencyConsequence::Delete,
                     "outbounds[" + outbound.tag + "].outbound_groups[" +
                         std::to_string(group_index) + "]",
                     "/outbounds/" + outbound.tag + "/edit"});
            }
        }
    }

    for (const auto& outbound : outbounds) {
        if (outbound.type != OutboundType::URLTEST ||
            removed_outbounds.find(outbound.tag) != removed_outbounds.end() ||
            !outbound.outbound_groups) {
            continue;
        }
        for (std::size_t group_index = 0;
             group_index < outbound.outbound_groups->size();
             ++group_index) {
            const auto& group = outbound.outbound_groups->at(group_index);
            const auto group_id =
                outbound.tag + ":" + std::to_string(group_index);
            for (const auto& member : group.outbounds) {
                if (removed_outbounds.find(member) ==
                    removed_outbounds.end()) {
                    continue;
                }
                add_reference(
                    analysis,
                    seen_references,
                    {{DependencyEntityKind::Outbound, member, false},
                     DependencyDependentKind::OutboundGroup,
                     group_id,
                     DependencyRelation::ContainsMember,
                     DependencyConsequence::Modify,
                     "outbounds[" + outbound.tag + "].outbound_groups[" +
                         std::to_string(group_index) + "]",
                     "/outbounds/" + outbound.tag + "/edit"});
            }
        }
    }

    analysis.safe_to_delete =
        analysis.references.empty() &&
        std::none_of(analysis.targets.begin(),
                     analysis.targets.end(),
                     [](const DependencyTarget& target) {
                         return target.cascaded;
                     });
    for (auto& reference : analysis.references) {
        const auto target = std::find_if(
            analysis.targets.begin(),
            analysis.targets.end(),
            [&](const DependencyTarget& candidate) {
                return candidate.kind == reference.target.kind &&
                       candidate.id == reference.target.id;
            });
        if (target != analysis.targets.end()) {
            reference.target.cascaded = target->cascaded;
        }
    }
    return analysis;
}

} // namespace keen_pbr3
