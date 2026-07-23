#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/handler_dependency_analysis.hpp"

#include <algorithm>

namespace keen_pbr3 {

TEST_CASE("dependency API mapper preserves cascade and typed references") {
    Config config;

    Outbound vpn;
    vpn.tag = "vpn";
    vpn.type = OutboundType::INTERFACE;
    vpn.interface = "tun0";
    Outbound automatic;
    automatic.tag = "automatic";
    automatic.type = OutboundType::URLTEST;
    OutboundGroup group;
    group.outbounds = {"vpn"};
    automatic.outbound_groups = std::vector<OutboundGroup>{group};
    config.outbounds = std::vector<Outbound>{vpn, automatic};

    RouteRule rule;
    rule.outbound = "automatic";
    RouteConfig route;
    route.rules = std::vector<RouteRule>{rule};
    config.route = route;

    api::DependencyAnalysisTargetRequest target;
    target.kind = api::DependencyEntityKind::OUTBOUND;
    target.id = "vpn";
    api::DependencyAnalysisRequest request;
    request.targets = {target};

    const auto response =
        build_dependency_analysis_response(config, request);

    CHECK_FALSE(response.safe_to_delete);
    REQUIRE(response.targets.size() == 2);
    CHECK(response.targets[1].id == "automatic");
    CHECK(response.targets[1].cascaded);
    CHECK(std::any_of(
        response.references.begin(),
        response.references.end(),
        [](const api::DependencyReference& reference) {
            return reference.dependent_kind ==
                       api::DependencyDependentKind::ROUTING_RULE &&
                   reference.consequence ==
                       api::DependencyConsequence::DELETE;
        }));
}

} // namespace keen_pbr3

#endif // WITH_API
