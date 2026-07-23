#ifdef WITH_API

#include "handler_dependency_analysis.hpp"

#include "../config/dependency_analysis.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>
#include <tuple>

namespace keen_pbr3 {
namespace {

DependencyEntityKind to_internal(api::DependencyEntityKind kind) {
    switch (kind) {
    case api::DependencyEntityKind::LIST:
        return DependencyEntityKind::List;
    case api::DependencyEntityKind::OUTBOUND:
        return DependencyEntityKind::Outbound;
    case api::DependencyEntityKind::DNS_SERVER:
        return DependencyEntityKind::DnsServer;
    }
    throw std::invalid_argument("Unsupported dependency target kind");
}

api::DependencyEntityKind to_api(DependencyEntityKind kind) {
    switch (kind) {
    case DependencyEntityKind::List:
        return api::DependencyEntityKind::LIST;
    case DependencyEntityKind::Outbound:
        return api::DependencyEntityKind::OUTBOUND;
    case DependencyEntityKind::DnsServer:
        return api::DependencyEntityKind::DNS_SERVER;
    }
    throw std::invalid_argument("Unsupported dependency target kind");
}

api::DependencyRelation to_api(DependencyRelation relation) {
    switch (relation) {
    case DependencyRelation::UsesList:
        return api::DependencyRelation::USES_LIST;
    case DependencyRelation::RoutesTo:
        return api::DependencyRelation::ROUTES_TO;
    case DependencyRelation::DetoursVia:
        return api::DependencyRelation::DETOURS_VIA;
    case DependencyRelation::ContainsMember:
        return api::DependencyRelation::CONTAINS_MEMBER;
    case DependencyRelation::UsesDnsServer:
        return api::DependencyRelation::USES_DNS_SERVER;
    case DependencyRelation::FallbackTo:
        return api::DependencyRelation::FALLBACK_TO;
    }
    throw std::invalid_argument("Unsupported dependency relation");
}

api::DependencyConsequence to_api(DependencyConsequence consequence) {
    switch (consequence) {
    case DependencyConsequence::Modify:
        return api::DependencyConsequence::MODIFY;
    case DependencyConsequence::Delete:
        return api::DependencyConsequence::DELETE;
    case DependencyConsequence::Disconnect:
        return api::DependencyConsequence::DISCONNECT;
    }
    throw std::invalid_argument("Unsupported dependency consequence");
}

api::DependencyDependentKind to_api(DependencyDependentKind kind) {
    switch (kind) {
    case DependencyDependentKind::RoutingRule:
        return api::DependencyDependentKind::ROUTING_RULE;
    case DependencyDependentKind::DnsRule:
        return api::DependencyDependentKind::DNS_RULE;
    case DependencyDependentKind::DnsServer:
        return api::DependencyDependentKind::DNS_SERVER;
    case DependencyDependentKind::OutboundGroup:
        return api::DependencyDependentKind::OUTBOUND_GROUP;
    case DependencyDependentKind::List:
        return api::DependencyDependentKind::LIST;
    case DependencyDependentKind::DnsFallback:
        return api::DependencyDependentKind::DNS_FALLBACK;
    }
    throw std::invalid_argument("Unsupported dependent kind");
}

api::DependencyTarget to_api(const DependencyTarget& target) {
    api::DependencyTarget result;
    result.kind = to_api(target.kind);
    result.id = target.id;
    result.cascaded = target.cascaded;
    return result;
}

DependencyAnalysis analyze_request(
    const Config& config,
    const std::vector<DependencyTarget>& targets,
    bool independent) {
    if (!independent) return analyze_dependencies(config, targets);

    DependencyAnalysis merged;
    std::set<std::tuple<DependencyEntityKind, std::string>> seen_targets;
    std::set<std::tuple<DependencyEntityKind,
                        std::string,
                        DependencyDependentKind,
                        std::string,
                        DependencyRelation>>
        seen_references;
    for (const auto& target : targets) {
        const auto partial = analyze_dependencies(config, {target});
        merged.safe_to_delete =
            merged.safe_to_delete && partial.safe_to_delete;
        for (const auto& affected : partial.targets) {
            const auto key = std::make_tuple(affected.kind, affected.id);
            const auto existing = std::find_if(
                merged.targets.begin(),
                merged.targets.end(),
                [&](const DependencyTarget& candidate) {
                    return candidate.kind == affected.kind &&
                           candidate.id == affected.id;
                });
            if (seen_targets.insert(key).second) {
                merged.targets.push_back(affected);
            } else if (existing != merged.targets.end() &&
                       !affected.cascaded) {
                existing->cascaded = false;
            }
        }
        for (const auto& reference : partial.references) {
            const auto key = std::make_tuple(reference.target.kind,
                                             reference.target.id,
                                             reference.dependent_kind,
                                             reference.dependent_id,
                                             reference.relation);
            if (seen_references.insert(key).second) {
                merged.references.push_back(reference);
            }
        }
    }
    return merged;
}

} // namespace

api::DependencyAnalysisResponse build_dependency_analysis_response(
    const Config& config,
    const api::DependencyAnalysisRequest& request) {
    std::vector<DependencyTarget> targets;
    targets.reserve(request.targets.size());
    for (const auto& target : request.targets) {
        targets.push_back({to_internal(target.kind), target.id, false});
    }

    const auto analysis = analyze_request(
        config,
        targets,
        request.independent.value_or(false));
    api::DependencyAnalysisResponse response;
    response.safe_to_delete = analysis.safe_to_delete;
    response.targets.reserve(analysis.targets.size());
    for (const auto& target : analysis.targets) {
        response.targets.push_back(to_api(target));
    }
    response.references.reserve(analysis.references.size());
    for (const auto& reference : analysis.references) {
        api::DependencyReference item;
        item.target = to_api(reference.target);
        item.dependent_kind = to_api(reference.dependent_kind);
        item.dependent_id = reference.dependent_id;
        item.relation = to_api(reference.relation);
        item.consequence = to_api(reference.consequence);
        item.path = reference.path;
        if (!reference.href.empty()) item.href = reference.href;
        response.references.push_back(std::move(item));
    }
    return response;
}

void register_dependency_analysis_handler(ApiServer& server, ApiContext& ctx) {
    server.post(
        "/api/config/dependencies",
        [&ctx](const std::string& body) -> std::string {
            try {
                const auto request =
                    nlohmann::json::parse(body)
                        .get<api::DependencyAnalysisRequest>();
                return nlohmann::json(build_dependency_analysis_response(
                                          ctx.get_visible_config(),
                                          request))
                    .dump();
            } catch (const nlohmann::json::exception& error) {
                throw ApiError(
                    std::string("Invalid dependency analysis request: ") +
                        error.what(),
                    400);
            } catch (const std::invalid_argument& error) {
                throw ApiError(error.what(), 400);
            }
        });
}

} // namespace keen_pbr3

#endif // WITH_API
