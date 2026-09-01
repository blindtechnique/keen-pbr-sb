#include <doctest/doctest.h>

#include "../src/daemon/internal_vpn_resolution_cache.hpp"

#include <functional>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

InternalVpnServer server(
    std::string interface_name,
    std::string ndms_id,
    bool process_clients = true) {
    InternalVpnServer result;
    result.interface = std::move(interface_name);
    result.ndms_id = std::move(ndms_id);
    result.process_clients = process_clients;
    return result;
}

InternalVpnRuntimeTarget target(std::string prefix) {
    InternalVpnRuntimeTarget result;
    result.stable_id = prefix + "-stable";
    result.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    result.process_clients = true;
    result.bound_interface_id = prefix + "-bound";
    result.interface = prefix + "-interface";
    result.verified_ingress_interfaces = {prefix + "-ingress"};
    result.verified_bridge_ingress_interfaces = {
        {prefix + "-bridge", prefix + "-bridge-port"},
    };
    result.dns_redirect_bypass_ingress_v4 = {prefix + "-dns-bypass-v4"};
    result.dns_redirect_bypass_ingress_v6 = {prefix + "-dns-bypass-v6"};
    result.dns_redirect_local_destinations_v4 = {"192.0.2.1/32"};
    result.dns_redirect_local_destinations_v6 = {"2001:db8::1/128"};
    result.source_cidrs_v4 = {"10.1.0.0/24"};
    result.source_cidrs_v6 = {"2001:db8:1::/64"};
    return result;
}

DumpedInterface live_interface(std::string name) {
    DumpedInterface result;
    result.name = std::move(name);
    result.admin_up = true;
    return result;
}

Config server_config(const InternalVpnServer& configured) {
    Config result;
    RouteConfig route;
    route.internal_vpn_servers =
        std::vector<InternalVpnServer>{configured};
    result.route = std::move(route);
    return result;
}

Config service_config(
    std::string service_id,
    bool process_clients = true) {
    Config result;
    RouteConfig route;
    InternalVpnService policy;
    policy.service_id = std::move(service_id);
    policy.process_clients = process_clients;
    route.internal_vpn_services =
        std::vector<InternalVpnService>{std::move(policy)};
    result.route = std::move(route);
    return result;
}

InternalVpnRuntimeResolution server_resolution(
    InternalVpnRuntimeResolutionState state,
    std::vector<InternalVpnServer> verified,
    std::vector<std::string> retain = {}) {
    InternalVpnRuntimeResolution result;
    result.state = state;
    result.verified_includes_for_lkg = std::move(verified);
    result.retain_verified_include_ndms_ids = std::move(retain);
    return result;
}

InternalVpnServiceRuntimeResolution service_resolution(
    InternalVpnRuntimeResolutionState state,
    std::vector<InternalVpnRuntimeTarget> verified,
    std::vector<std::string> retain = {}) {
    InternalVpnServiceRuntimeResolution result;
    result.state = state;
    result.verified_includes_for_lkg = std::move(verified);
    result.retain_verified_include_service_ids = std::move(retain);
    return result;
}

NdmsCatalogSnapshot fresh_server_snapshot(
    std::string id,
    std::string firmware_interface_name) {
    NdmsCatalogSnapshot result;
    result.status = NdmsCatalogCacheStatus::fresh;
    result.catalog.firmware_available = true;
    NdmsTunnelInterface tunnel;
    tunnel.id = std::move(id);
    tunnel.firmware_interface_name = std::move(firmware_interface_name);
    tunnel.kind = NdmsTunnelKind::amnezia_wireguard;
    tunnel.internal_vpn_server_candidate = true;
    result.catalog.tunnels.push_back(std::move(tunnel));
    return result;
}

NdmsVpnServerServiceSnapshot fresh_service_snapshot(
    std::string id,
    std::string bound_interface_id,
    std::string source_cidr) {
    NdmsVpnServerServiceSnapshot result;
    result.status = NdmsCatalogCacheStatus::fresh;
    result.catalog.firmware_available = true;
    NdmsVpnServerService service;
    service.id = std::move(id);
    service.kind = NdmsVpnServerServiceKind::ikev2;
    service.enabled = true;
    service.bound_interface_id = std::move(bound_interface_id);
    service.source_cidrs_v4.push_back(std::move(source_cidr));
    result.catalog.services.push_back(std::move(service));
    return result;
}

static_assert(noexcept(
    std::declval<InternalVpnResolutionCache&>().exchange_active(
        std::declval<std::vector<InternalVpnServer>&>(),
        std::declval<std::vector<InternalVpnRuntimeTarget>&>())));

} // namespace

TEST_CASE("internal VPN resolution cache exchanges one exact active pair") {
    InternalVpnResolutionCache cache;

    std::vector<InternalVpnServer> base_servers{
        server("nwg1", "base-server"),
    };
    std::vector<InternalVpnRuntimeTarget> base_targets{
        target("base"),
    };
    cache.exchange_active(base_servers, base_targets);
    CHECK(base_servers.empty());
    CHECK(base_targets.empty());

    const std::vector<InternalVpnServer> expected_base_servers{
        server("nwg1", "base-server"),
    };
    const std::vector<InternalVpnRuntimeTarget> expected_base_targets{
        target("base"),
    };
    CHECK(cache.active_matches(
        expected_base_servers, expected_base_targets));

    std::vector<InternalVpnServer> candidate_servers{
        server("nwg7", "candidate-server"),
    };
    std::vector<InternalVpnRuntimeTarget> candidate_targets{
        target("candidate"),
    };
    cache.exchange_active(candidate_servers, candidate_targets);

    CHECK(cache.active_matches(
        {server("nwg7", "candidate-server")},
        {target("candidate")}));
    REQUIRE(candidate_servers.size() == 1U);
    CHECK(candidate_servers.front().interface == "nwg1");
    REQUIRE(candidate_targets.size() == 1U);
    CHECK(candidate_targets.front().stable_id == "base-stable");

    cache.exchange_active(candidate_servers, candidate_targets);
    CHECK(cache.active_matches(
        expected_base_servers, expected_base_targets));
    REQUIRE(candidate_servers.size() == 1U);
    CHECK(candidate_servers.front().interface == "nwg7");
    REQUIRE(candidate_targets.size() == 1U);
    CHECK(candidate_targets.front().stable_id == "candidate-stable");
}

TEST_CASE("internal VPN active equality covers every runtime selector field") {
    InternalVpnResolutionCache cache;
    std::vector<InternalVpnServer> active_servers{
        server("nwg4", "server-4"),
    };
    std::vector<InternalVpnRuntimeTarget> active_targets{
        target("active"),
    };
    cache.exchange_active(active_servers, active_targets);

    const auto expected_servers = cache.active_servers();
    const auto expected_targets = cache.active_service_targets();
    REQUIRE(cache.active_matches(expected_servers, expected_targets));

    const std::vector<std::pair<
        const char*,
        std::function<void(InternalVpnServer&)>>>
        server_mutations{
            {"interface", [](auto& value) { value.interface += "-changed"; }},
            {"ndms_id", [](auto& value) { value.ndms_id = "changed-id"; }},
            {"process_clients", [](auto& value) {
                 value.process_clients = !value.process_clients;
             }},
        };
    for (std::size_t index = 0U;
         index < server_mutations.size();
         ++index) {
        CAPTURE(server_mutations[index].first);
        auto changed = expected_servers;
        server_mutations[index].second(changed.front());
        CHECK_FALSE(cache.active_matches(changed, expected_targets));
    }

    const std::vector<std::pair<
        const char*,
        std::function<void(InternalVpnRuntimeTarget&)>>>
        target_mutations{
            {"stable_id", [](auto& value) { value.stable_id += "-changed"; }},
            {"match_kind", [](auto& value) {
                 value.match_kind = InternalVpnRuntimeMatchKind::interface;
             }},
            {"process_clients", [](auto& value) {
                 value.process_clients = !value.process_clients;
             }},
            {"bound_interface_id", [](auto& value) {
                 value.bound_interface_id = "changed-bound";
             }},
            {"interface", [](auto& value) {
                 value.interface = "changed-interface";
             }},
            {"verified_ingress_interfaces", [](auto& value) {
                 value.verified_ingress_interfaces.push_back("changed-ingress");
             }},
            {"verified_bridge_ingress_interfaces", [](auto& value) {
                 value.verified_bridge_ingress_interfaces.push_back(
                     {"changed-bridge", "changed-port"});
             }},
            {"dns_redirect_bypass_ingress_v4", [](auto& value) {
                 value.dns_redirect_bypass_ingress_v4.push_back("changed-v4");
             }},
            {"dns_redirect_bypass_ingress_v6", [](auto& value) {
                 value.dns_redirect_bypass_ingress_v6.push_back("changed-v6");
             }},
            {"dns_redirect_local_destinations_v4", [](auto& value) {
                 value.dns_redirect_local_destinations_v4.push_back(
                     "198.51.100.1/32");
             }},
            {"dns_redirect_local_destinations_v6", [](auto& value) {
                 value.dns_redirect_local_destinations_v6.push_back(
                     "2001:db8:ffff::1/128");
             }},
            {"source_cidrs_v4", [](auto& value) {
                 value.source_cidrs_v4.push_back("10.2.0.0/24");
             }},
            {"source_cidrs_v6", [](auto& value) {
                 value.source_cidrs_v6.push_back("2001:db8:2::/64");
             }},
        };
    for (std::size_t index = 0U;
         index < target_mutations.size();
         ++index) {
        CAPTURE(target_mutations[index].first);
        auto changed = expected_targets;
        target_mutations[index].second(changed.front());
        CHECK_FALSE(cache.active_matches(expected_servers, changed));
    }
}

TEST_CASE("internal VPN resolution cache preserves empty and legacy server semantics") {
    InternalVpnResolutionCache cache;
    NdmsCatalogSnapshot unavailable;
    unavailable.status = NdmsCatalogCacheStatus::unavailable;

    const auto empty = cache.resolve_servers(Config{}, unavailable, {});
    CHECK(empty.state == InternalVpnRuntimeResolutionState::verified);
    CHECK(empty.effective_servers.empty());

    InternalVpnServer legacy;
    legacy.interface = "nwg0";
    legacy.process_clients = true;
    const auto resolved = cache.resolve_servers(
        server_config(legacy),
        unavailable,
        {live_interface("lo"), live_interface("nwg0")});
    CHECK(resolved.state == InternalVpnRuntimeResolutionState::verified);
    REQUIRE(resolved.effective_servers.size() == 1U);
    CHECK(resolved.effective_servers.front().interface == "nwg0");
    CHECK(resolved.verified_includes_for_lkg.empty());
}

TEST_CASE("internal VPN server resolution retains only verified includes") {
    InternalVpnResolutionCache cache;
    const auto config = server_config(server("nwg0", "ServerA"));
    const auto live = std::vector<DumpedInterface>{
        live_interface("lo"),
        live_interface("nwg0"),
        live_interface("nwg5"),
    };

    const auto verified = cache.resolve_servers(
        config,
        fresh_server_snapshot("ServerA", "Wireguard5"),
        live);
    CHECK(verified.state == InternalVpnRuntimeResolutionState::verified);
    REQUIRE(verified.effective_servers.size() == 1U);
    CHECK(verified.effective_servers.front().interface == "nwg5");
    cache.update_verified_servers(verified);

    NdmsCatalogSnapshot stale;
    stale.status = NdmsCatalogCacheStatus::stale;
    const auto retained = cache.resolve_servers(config, stale, live);
    CHECK(
        retained.state ==
        InternalVpnRuntimeResolutionState::retained_verified_includes);
    REQUIRE(retained.effective_servers.size() == 1U);
    CHECK(retained.effective_servers.front().interface == "nwg5");
    CHECK(retained.effective_servers.front().process_clients);

    auto bypass_config = config;
    bypass_config.route->internal_vpn_servers->front().process_clients = false;
    const auto bypass = cache.resolve_servers(bypass_config, stale, live);
    CHECK(bypass.state == InternalVpnRuntimeResolutionState::degraded);
    CHECK(bypass.effective_servers.empty());
}

TEST_CASE("authoritative native VPN removal revokes the verified server cache") {
    InternalVpnResolutionCache cache;
    const auto config = server_config(server("nwg0", "ServerA"));
    const auto live = std::vector<DumpedInterface>{
        live_interface("lo"),
        live_interface("nwg5"),
    };
    const auto verified = cache.resolve_servers(
        config,
        fresh_server_snapshot("ServerA", "Wireguard5"),
        live);
    cache.update_verified_servers(verified);
    REQUIRE(cache.snapshot_verified_servers().size() == 1U);

    NdmsCatalogSnapshot removed;
    removed.status = NdmsCatalogCacheStatus::fresh;
    removed.catalog.firmware_available = true;
    const auto authoritative_negative =
        cache.resolve_servers(config, removed, live);
    CHECK(
        authoritative_negative.state ==
        InternalVpnRuntimeResolutionState::authoritative_negative);
    CHECK(authoritative_negative.effective_servers.empty());
    cache.update_verified_servers(authoritative_negative);
    CHECK(cache.snapshot_verified_servers().empty());
}

TEST_CASE("internal VPN service resolution refreshes live IKE ingress") {
    InternalVpnResolutionCache cache;
    const std::string service_id =
        "ndms-crypto-map:ikev2:VirtualIPServerIKE2";
    auto bridge = live_interface("br0");
    bridge.ipv4_addresses = {"192.168.1.1/24"};
    auto xfrms = live_interface("xfrms1");
    const std::vector<DumpedInterface> live{
        std::move(bridge),
        std::move(xfrms),
    };

    const auto verified = cache.resolve_services(
        service_config(service_id),
        fresh_service_snapshot(
            service_id, "Bridge0", "172.20.8.0/23"),
        live);
    CHECK(verified.state == InternalVpnRuntimeResolutionState::verified);
    REQUIRE(verified.effective_targets.size() == 1U);
    const auto& resolved = verified.effective_targets.front();
    CHECK(resolved.interface == std::optional<std::string>{"br0"});
    CHECK(
        resolved.verified_ingress_interfaces ==
        std::vector<std::string>{"xfrms1"});
    CHECK(
        resolved.dns_redirect_bypass_ingress_v4 ==
        std::vector<std::string>{"xfrms1"});
    CHECK(resolved.dns_redirect_bypass_ingress_v6.empty());

    cache.update_verified_service_targets(verified);
    NdmsVpnServerServiceSnapshot stale;
    stale.status = NdmsCatalogCacheStatus::stale;
    const auto retained = cache.resolve_services(
        service_config(service_id), stale, live);
    CHECK(
        retained.state ==
        InternalVpnRuntimeResolutionState::retained_verified_includes);
    REQUIRE(retained.effective_targets.size() == 1U);
    CHECK(retained.effective_targets.front().process_clients);

    const auto bypass = cache.resolve_services(
        service_config(service_id, false), stale, live);
    CHECK(bypass.state == InternalVpnRuntimeResolutionState::degraded);
    CHECK(bypass.effective_targets.empty());
}

TEST_CASE(
    "stale OpenConnect mode change retains the verified pool and rechecks "
    "the live oc peer") {
    InternalVpnResolutionCache cache;
    const std::string service_id = "ndms-service:oc-server";

    auto lan = live_interface("br0");
    lan.ipv4_addresses = {"192.168.1.1/24"};
    auto session = live_interface("oc7");
    session.carrier = true;
    session.ipv4_addresses = {"172.16.5.1/32"};
    session.ipv4_peer_addresses = {"172.16.5.42/32"};
    const std::vector<DumpedInterface> live{lan, session};

    auto fresh = fresh_service_snapshot(
        service_id, "Bridge0", "172.16.5.0/24");
    fresh.catalog.services.front().kind =
        NdmsVpnServerServiceKind::openconnect;
    const auto verified = cache.resolve_services(
        service_config(service_id), fresh, live);
    REQUIRE(verified.effective_targets.size() == 1U);
    CHECK(verified.effective_targets.front().process_clients);
    cache.update_verified_service_targets(verified);

    NdmsVpnServerServiceSnapshot stale;
    stale.status = NdmsCatalogCacheStatus::stale;
    const auto disabled = cache.resolve_services(
        service_config(service_id, false), stale, live);
    CHECK(
        disabled.state ==
        InternalVpnRuntimeResolutionState::
            retained_verified_includes);
    REQUIRE(disabled.effective_targets.size() == 1U);
    const auto& target = disabled.effective_targets.front();
    CHECK_FALSE(target.process_clients);
    CHECK(
        target.source_cidrs_v4 ==
        std::vector<std::string>{"172.16.5.0/24"});
    CHECK(
        target.verified_ingress_interfaces ==
        std::vector<std::string>{"oc7"});

    NdmsVpnServerServiceSnapshot partial;
    partial.status = NdmsCatalogCacheStatus::fresh;
    partial.catalog.firmware_available = true;
    partial.catalog.unresolved_service_ids = {service_id};
    const auto partial_disabled = cache.resolve_services(
        service_config(service_id, false), partial, live);
    CHECK(
        partial_disabled.state ==
        InternalVpnRuntimeResolutionState::authoritative_negative);
    REQUIRE(partial_disabled.effective_targets.size() == 1U);
    CHECK_FALSE(
        partial_disabled.effective_targets.front().process_clients);
    CHECK(
        partial_disabled.effective_targets.front()
            .verified_ingress_interfaces ==
        std::vector<std::string>{"oc7"});

    auto mismatched = session;
    mismatched.ipv4_peer_addresses = {"172.31.5.42/32"};
    const auto no_peer = cache.resolve_services(
        service_config(service_id, false),
        partial,
        {lan, mismatched});
    REQUIRE(no_peer.effective_targets.size() == 1U);
    CHECK(
        no_peer.effective_targets.front()
            .verified_ingress_interfaces.empty());
}

TEST_CASE("internal VPN resolution cache forwards exact verified publication") {
    InternalVpnResolutionCache cache;
    cache.update_verified_servers(server_resolution(
        InternalVpnRuntimeResolutionState::verified,
        {server("nwg1", "server-1")}));
    cache.update_verified_service_targets(service_resolution(
        InternalVpnRuntimeResolutionState::verified,
        {target("service-1")}));

    cache.update_verified_servers(server_resolution(
        InternalVpnRuntimeResolutionState::degraded,
        {server("nwg2", "ignored-server")}));
    cache.update_verified_service_targets(service_resolution(
        InternalVpnRuntimeResolutionState::
            retained_verified_includes,
        {target("ignored-service")}));
    REQUIRE(cache.snapshot_verified_servers().size() == 1U);
    CHECK(cache.snapshot_verified_servers().front().interface == "nwg1");
    REQUIRE(cache.snapshot_verified_service_targets().size() == 1U);
    CHECK(
        cache.snapshot_verified_service_targets().front().stable_id ==
        "service-1-stable");

    auto publication = cache.prepare_verified_publication(
        server_resolution(
            InternalVpnRuntimeResolutionState::authoritative_negative,
            {server("nwg9", "server-9")}),
        service_resolution(
            InternalVpnRuntimeResolutionState::authoritative_negative,
            {target("service-9")}));
    cache.exchange_verified_publication(publication);
    REQUIRE(cache.snapshot_verified_servers().size() == 1U);
    CHECK(cache.snapshot_verified_servers().front().interface == "nwg9");
    REQUIRE(cache.snapshot_verified_service_targets().size() == 1U);
    CHECK(
        cache.snapshot_verified_service_targets().front().stable_id ==
        "service-9-stable");
    REQUIRE(publication.servers.size() == 1U);
    CHECK(publication.servers.front().interface == "nwg1");
    REQUIRE(publication.service_targets.size() == 1U);
    CHECK(publication.service_targets.front().stable_id == "service-1-stable");

    cache.exchange_verified_publication(publication);
    REQUIRE(cache.snapshot_verified_servers().size() == 1U);
    CHECK(cache.snapshot_verified_servers().front().interface == "nwg1");
    REQUIRE(cache.snapshot_verified_service_targets().size() == 1U);
    CHECK(
        cache.snapshot_verified_service_targets().front().stable_id ==
        "service-1-stable");
}

} // namespace keen_pbr3
