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
    config.outbounds = std::vector<Outbound>{vpn, automatic};

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

} // namespace

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
