#include <doctest/doctest.h>

#include "../src/config/dependency_analysis.hpp"

#include <algorithm>

namespace keen_pbr3 {
namespace {

Config dependency_fixture() {
    Config config;

    ListConfig ai;
    ai.domains = std::vector<std::string>{"example.ai"};
    ai.detour = "vpn";
    ai.fallback_detours = std::vector<std::string>{"backup"};
    ListConfig media;
    media.domains = std::vector<std::string>{"example.video"};
    config.lists = std::map<std::string, ListConfig>{
        {"ai", ai},
        {"media", media},
    };

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
    Outbound backup;
    backup.tag = "backup";
    backup.type = OutboundType::INTERFACE;
    backup.interface = "tun1";
    config.outbounds = std::vector<Outbound>{vpn, backup, automatic};

    RouteRule list_only;
    list_only.list = std::vector<std::string>{"ai"};
    list_only.outbound = "automatic";
    RouteRule mixed;
    mixed.list = std::vector<std::string>{"ai", "media"};
    mixed.proto = "tcp";
    mixed.outbound = "vpn";
    RouteConfig route;
    route.rules = std::vector<RouteRule>{list_only, mixed};
    config.route = route;

    DnsServer remote;
    remote.tag = "remote";
    remote.address = "1.1.1.1";
    remote.detour = "vpn";
    DnsRule dns_rule;
    dns_rule.list = {"ai"};
    dns_rule.server = "remote";
    DnsConfig dns;
    dns.servers = std::vector<DnsServer>{remote};
    dns.rules = std::vector<DnsRule>{dns_rule};
    dns.fallback = std::vector<std::string>{"remote"};
    config.dns = dns;

    return config;
}

bool has_reference(const DependencyAnalysis& analysis,
                   DependencyDependentKind dependent_kind,
                   const std::string& dependent_id,
                   DependencyConsequence consequence) {
    return std::any_of(
        analysis.references.begin(),
        analysis.references.end(),
        [&](const DependencyReference& reference) {
            return reference.dependent_kind == dependent_kind &&
                   reference.dependent_id == dependent_id &&
                   reference.consequence == consequence;
        });
}

const DependencyReference* find_reference(
    const DependencyAnalysis& analysis,
    DependencyDependentKind dependent_kind,
    const std::string& dependent_id,
    DependencyConsequence consequence) {
    const auto it = std::find_if(
        analysis.references.begin(),
        analysis.references.end(),
        [&](const DependencyReference& reference) {
            return reference.dependent_kind == dependent_kind &&
                   reference.dependent_id == dependent_id &&
                   reference.consequence == consequence;
        });
    return it == analysis.references.end() ? nullptr : &*it;
}

} // namespace

TEST_CASE("outbound dependency analysis includes list fallback detours") {
    const auto analysis = analyze_dependencies(
        dependency_fixture(),
        {{DependencyEntityKind::Outbound, "backup", false}});

    CHECK(has_reference(
        analysis,
        DependencyDependentKind::List,
        "ai",
        DependencyConsequence::Modify));
}

TEST_CASE("outbound dependency analysis includes global list refresh primary and fallback") {
    auto config = dependency_fixture();
    ListRefreshConfig refresh;
    refresh.detour = "vpn";
    refresh.fallback_detours = std::vector<std::string>{"backup"};
    config.list_refresh = refresh;

    const auto primary_analysis = analyze_dependencies(
        config,
        {{DependencyEntityKind::Outbound, "vpn", false}});
    const auto* primary = find_reference(
        primary_analysis,
        DependencyDependentKind::ListRefresh,
        "global",
        DependencyConsequence::Disconnect);
    REQUIRE(primary != nullptr);
    CHECK(primary->relation == DependencyRelation::DetoursVia);
    CHECK(primary->path == "list_refresh.detour");
    CHECK(primary->href == "/general?tab=general");

    const auto fallback_analysis = analyze_dependencies(
        config,
        {{DependencyEntityKind::Outbound, "backup", false}});
    const auto* fallback = find_reference(
        fallback_analysis,
        DependencyDependentKind::ListRefresh,
        "global",
        DependencyConsequence::Modify);
    REQUIRE(fallback != nullptr);
    CHECK(fallback->relation == DependencyRelation::DetoursVia);
    CHECK(fallback->path == "list_refresh.fallback_detours[0]");
    CHECK(fallback->href == "/general?tab=general");
}

TEST_CASE("list dependency analysis distinguishes modified and deleted rules") {
    const auto analysis = analyze_dependencies(
        dependency_fixture(),
        {{DependencyEntityKind::List, "ai", false}});

    CHECK_FALSE(analysis.safe_to_delete);
    CHECK(has_reference(
        analysis,
        DependencyDependentKind::RoutingRule,
        "0",
        DependencyConsequence::Delete));
    CHECK(has_reference(
        analysis,
        DependencyDependentKind::RoutingRule,
        "1",
        DependencyConsequence::Modify));
    CHECK(has_reference(
        analysis,
        DependencyDependentKind::DnsRule,
        "0",
        DependencyConsequence::Delete));
}

TEST_CASE(
    "protocol alone does not preserve a route rule after its list is deleted") {
    auto config = dependency_fixture();
    REQUIRE(config.route.has_value());
    REQUIRE(config.route->rules.has_value());
    config.route->rules->at(0).proto = "udp";

    const auto analysis = analyze_dependencies(
        config,
        {{DependencyEntityKind::List, "ai", false}});

    CHECK(has_reference(
        analysis,
        DependencyDependentKind::RoutingRule,
        "0",
        DependencyConsequence::Delete));
}

TEST_CASE("outbound dependency analysis includes urltest cascade and detours") {
    const auto analysis = analyze_dependencies(
        dependency_fixture(),
        {{DependencyEntityKind::Outbound, "vpn", false}});

    const auto cascaded = std::find_if(
        analysis.targets.begin(),
        analysis.targets.end(),
        [](const DependencyTarget& target) {
            return target.id == "automatic" && target.cascaded;
        });
    REQUIRE(cascaded != analysis.targets.end());
    CHECK(has_reference(
        analysis,
        DependencyDependentKind::RoutingRule,
        "0",
        DependencyConsequence::Delete));
    CHECK(has_reference(
        analysis,
        DependencyDependentKind::RoutingRule,
        "1",
        DependencyConsequence::Delete));
    CHECK(has_reference(
        analysis,
        DependencyDependentKind::DnsServer,
        "remote",
        DependencyConsequence::Disconnect));
    CHECK(has_reference(
        analysis,
        DependencyDependentKind::List,
        "ai",
        DependencyConsequence::Disconnect));
}

TEST_CASE("dns server dependency analysis includes rules and fallback") {
    const auto analysis = analyze_dependencies(
        dependency_fixture(),
        {{DependencyEntityKind::DnsServer, "remote", false}});

    CHECK(has_reference(
        analysis,
        DependencyDependentKind::DnsRule,
        "0",
        DependencyConsequence::Delete));
    CHECK(has_reference(
        analysis,
        DependencyDependentKind::DnsFallback,
        "remote",
        DependencyConsequence::Modify));
}

TEST_CASE("dependency analysis rejects unknown targets") {
    CHECK_THROWS_AS(
        analyze_dependencies(
            dependency_fixture(),
            {{DependencyEntityKind::List, "missing", false}}),
        std::invalid_argument);
}

} // namespace keen_pbr3
