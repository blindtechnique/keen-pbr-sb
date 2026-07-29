#include <doctest/doctest.h>

#include "config/routing_state.hpp"
#include "keenetic/internal_vpn_service_resolver.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

NdmsVpnServerService service(
    std::string id,
    bool enabled,
    std::vector<std::string> source_cidrs,
    std::optional<std::string> bound_interface_id = std::nullopt) {
    NdmsVpnServerService result;
    result.id = std::move(id);
    result.enabled = enabled;
    result.bound_interface_id = std::move(bound_interface_id);
    for (auto& cidr : source_cidrs) {
        (cidr.find(':') == std::string::npos
             ? result.source_cidrs_v4
             : result.source_cidrs_v6)
            .push_back(std::move(cidr));
    }
    return result;
}

InternalVpnService policy(
    std::string id,
    bool process_clients) {
    InternalVpnService result;
    result.service_id = std::move(id);
    result.process_clients = process_clients;
    return result;
}

nlohmann::json live_like_service_config() {
    return {{"message", {
        "crypto ike policy VPNL2TPServer",
        "    mode ikev1",
        "crypto ike policy VirtualIPServerIKE2",
        "    mode ikev2",
        "crypto map VPNL2TPServer",
        "    set-profile VPNL2TPServer",
        "    l2tp-server range 172.16.2.33 172.16.2.233",
        "    l2tp-server interface Bridge0",
        "    l2tp-server enable",
        "    enable",
        "crypto map VirtualIPServerIKE2",
        "    set-profile VirtualIPServerIKE2",
        "    virtual-ip range 172.20.8.1 172.20.9.0",
        "    virtual-ip interface Bridge0",
        "    virtual-ip enable",
        "    enable",
        "sstp-server",
        "    interface Bridge0",
        "    pool-range 172.16.1.33 200",
        "service sstp-server",
        "oc-server",
        "    interface Bridge0",
        "    pool-range 172.30.4.17 12",
        "service oc-server",
    }}};
}

} // namespace

TEST_CASE("service resolver inherits the global ingress mode") {
    Config default_all;
    CHECK(internal_vpn_service_default_process_clients(default_all));

    Config explicit_all;
    explicit_all.route = RouteConfig{};
    explicit_all.route->inbound_interfaces =
        std::vector<std::string>{};
    CHECK(internal_vpn_service_default_process_clients(explicit_all));

    Config allowlisted;
    allowlisted.route = RouteConfig{};
    allowlisted.route->inbound_interfaces =
        std::vector<std::string>{"Bridge0"};
    CHECK_FALSE(
        internal_vpn_service_default_process_clients(allowlisted));
}

TEST_CASE(
    "authoritative service inventory suppresses duplicate legacy interfaces") {
    InternalVpnServer l2tp;
    l2tp.interface = "L2tp0";
    l2tp.ndms_id = "L2TP0";
    l2tp.process_clients = false;

    InternalVpnServer wireguard;
    wireguard.interface = "nwg0";
    wireguard.ndms_id = "Wireguard0";

    NdmsInterfaceCatalog interface_catalog;
    NdmsTunnelInterface l2tp_tunnel;
    l2tp_tunnel.id = "L2TP0";
    l2tp_tunnel.kind = NdmsTunnelKind::l2tp;
    interface_catalog.tunnels.push_back(l2tp_tunnel);
    NdmsTunnelInterface wireguard_tunnel;
    wireguard_tunnel.id = "Wireguard0";
    wireguard_tunnel.kind = NdmsTunnelKind::wireguard;
    interface_catalog.tunnels.push_back(wireguard_tunnel);

    NdmsVpnServerServiceCatalog service_catalog;
    service_catalog.firmware_available = true;
    auto l2tp_service = service(
        "ndms-crypto-map:l2tp:server",
        true,
        {"172.16.0.0/24"},
        "L2tp0");
    l2tp_service.kind = NdmsVpnServerServiceKind::l2tp;
    service_catalog.services.push_back(l2tp_service);

    const auto authoritative =
        prefer_authoritative_internal_vpn_service_inventory(
            {l2tp, wireguard},
            interface_catalog,
            service_catalog,
            /*service_catalog_authoritative=*/true);
    REQUIRE(authoritative.size() == 1U);
    CHECK(authoritative.front().ndms_id ==
          std::optional<std::string>{"Wireguard0"});

    const auto fallback =
        prefer_authoritative_internal_vpn_service_inventory(
            {l2tp, wireguard},
            interface_catalog,
            service_catalog,
            /*service_catalog_authoritative=*/false);
    CHECK(fallback.size() == 2U);

    NdmsVpnServerServiceCatalog incomplete_service_catalog;
    incomplete_service_catalog.firmware_available = true;
    incomplete_service_catalog.unresolved_service_ids = {
        "ndms-crypto-map:l2tp:server",
    };
    const auto incomplete =
        prefer_authoritative_internal_vpn_service_inventory(
            {l2tp, wireguard},
            interface_catalog,
            incomplete_service_catalog,
            /*service_catalog_authoritative=*/true);
    REQUIRE(incomplete.size() == 1U);
    CHECK(
        incomplete.front().ndms_id ==
        std::optional<std::string>{"Wireguard0"});
}

TEST_CASE("default-all ingress protects connected LAN networks but ignores dynamic host endpoints") {
    Config config;
    DumpedInterface loopback;
    loopback.name = "lo";
    loopback.ipv4_addresses = {"127.0.0.1/8"};
    loopback.ipv6_addresses = {"::1/128"};

    DumpedInterface lan;
    lan.name = "br0";
    lan.ipv4_addresses = {"192.168.1.1/24"};
    lan.ipv6_addresses = {"fd00:1::1/64"};

    DumpedInterface point_to_point;
    point_to_point.name = "ppp0";
    point_to_point.ipv4_addresses = {"172.16.2.33/32"};
    point_to_point.ipv6_addresses = {"2001:db8::33/128"};

    const auto protected_cidrs =
        internal_vpn_protected_inbound_cidrs(
            config, {loopback, lan, point_to_point});
    CHECK(
        protected_cidrs ==
        std::vector<std::string>{
            "192.168.1.1/24",
            "fd00:1::1/64",
        });

    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    catalog.services = {
        service("ndms-service:sstp-server", true,
                {"192.168.1.128/25"}),
        service("ndms-crypto-map:ike2", true,
                {"172.16.2.0/24"}),
    };
    const auto resolution = resolve_internal_vpn_service_policies(
        {},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true,
        protected_cidrs);

    CHECK_FALSE(resolution.complete());
    REQUIRE(resolution.effective_targets.size() == 1);
    CHECK(resolution.effective_targets.front().stable_id ==
          "ndms-crypto-map:ike2");
    REQUIRE(resolution.issues.size() == 1);
    CHECK(
        resolution.issues.front().error ==
        InternalVpnServiceResolutionError::
            source_pool_overlaps_inbound_network);
}

TEST_CASE("explicit ingress protects every address on selected interfaces") {
    Config config;
    config.route = RouteConfig{};
    config.route->inbound_interfaces =
        std::vector<std::string>{"nwg0"};

    DumpedInterface selected;
    selected.name = "nwg0";
    selected.ipv4_addresses = {"10.10.0.1/32"};

    DumpedInterface other;
    other.name = "br0";
    other.ipv4_addresses = {"192.168.1.1/24"};

    CHECK(
        internal_vpn_protected_inbound_cidrs(
            config, {selected, other}) ==
        std::vector<std::string>{"10.10.0.1/32"});
}

TEST_CASE("service resolver applies inherited policy to fresh inventory") {
    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    catalog.services = {
        service("ndms-service:sstp-server", true,
                {"172.16.1.0/24"}, "Sstp0"),
        service("ndms-crypto-map:ike2", true,
                {"172.20.8.0/23"}, "Ike0"),
    };

    const auto result = resolve_internal_vpn_service_policies(
        {},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true);

    REQUIRE(result.complete());
    REQUIRE(result.effective_targets.size() == 2);
    CHECK(result.effective_targets[0].process_clients);
    CHECK(result.effective_targets[1].process_clients);
    CHECK(result.verified_includes_for_lkg.size() == 2);
}

TEST_CASE("service resolver treats saved rows as overrides") {
    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    catalog.services = {
        service("ndms-service:sstp-server", true,
                {"172.16.1.0/24"}, "Sstp0"),
        service("ndms-crypto-map:ike2", true,
                {"172.20.8.0/23"}, "Ike0"),
    };

    const auto result = resolve_internal_vpn_service_policies(
        {policy("ndms-service:sstp-server", true)},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/false,
        InternalVpnInboundObservation{
            {"Sstp0", "Ike0"},
            {},
        });

    REQUIRE(result.complete());
    REQUIRE(result.effective_targets.size() == 2);
    CHECK(result.effective_targets[0].process_clients);
    CHECK_FALSE(result.effective_targets[1].process_clients);
    REQUIRE(result.verified_includes_for_lkg.size() == 1);
    CHECK(result.verified_includes_for_lkg.front().stable_id ==
          "ndms-service:sstp-server");
}

TEST_CASE("service resolver rejects missing disabled and duplicate overrides") {
    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    catalog.services = {
        service("ndms-service:sstp-server", false,
                {"172.16.1.0/24"}),
    };

    const auto result = resolve_internal_vpn_service_policies(
        {
            policy("ndms-service:sstp-server", true),
            policy("ndms-service:sstp-server", false),
            policy("ndms-crypto-map:missing", true),
        },
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true);

    CHECK_FALSE(result.complete());
    CHECK(result.effective_targets.empty());
    CHECK(result.issues.size() == 3);
}

TEST_CASE("service resolver rejects nested client source pools") {
    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    catalog.services = {
        service("ndms-crypto-map:ike2", true,
                {"172.20.8.0/23"}),
        service("ndms-service:sstp-server", true,
                {"172.20.8.0/24"}),
    };

    const auto result = resolve_internal_vpn_service_policies(
        {},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true);

    CHECK_FALSE(result.complete());
    CHECK(result.effective_targets.empty());
    REQUIRE(result.issues.size() == 2);
    CHECK(result.issues[0].error ==
          InternalVpnServiceResolutionError::overlapping_source_pool);
    CHECK(result.issues[1].error ==
          InternalVpnServiceResolutionError::overlapping_source_pool);
}

TEST_CASE("overlapping service pools never let an earlier bypass win") {
    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    catalog.services = {
        service("ndms-service:sstp-server", true,
                {"172.16.1.0/24"}, "Sstp0"),
        service("ndms-crypto-map:ike2", true,
                {"172.16.1.128/25"}, "Ike0"),
    };

    const auto result = resolve_internal_vpn_service_policies(
        {
            policy("ndms-service:sstp-server", false),
            policy("ndms-crypto-map:ike2", true),
        },
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true,
        InternalVpnInboundObservation{
            {"Sstp0", "Ike0"},
            {},
        });

    CHECK_FALSE(result.complete());
    CHECK(result.effective_targets.empty());
    CHECK(result.verified_includes_for_lkg.empty());
    REQUIRE(result.issues.size() == 2);
}

TEST_CASE(
    "service pool may overlap its own verified ingress network") {
    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    catalog.services = {
        service(
            "ndms-service:sstp-server",
            true,
            {"172.16.1.0/24"},
            "Sstp0"),
    };
    const InternalVpnInboundObservation observation{
        {"Sstp0", "br0"},
        {
            {"Sstp0", "172.16.1.1/24"},
            {"br0", "192.168.1.1/24"},
        },
    };

    const auto result = resolve_internal_vpn_service_policies(
        {},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true,
        observation);

    REQUIRE(result.complete());
    REQUIRE(result.effective_targets.size() == 1U);
    CHECK(
        result.effective_targets.front().bound_interface_id ==
        std::optional<std::string>{"Sstp0"});
    CHECK(
        result.effective_targets.front().interface ==
        std::optional<std::string>{"Sstp0"});
}

TEST_CASE(
    "authoritative non-overlapping source pool bypasses dynamic ingress") {
    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    catalog.services = {
        service(
            "ndms-service:sstp-server",
            true,
            {"172.16.1.0/24"},
            "Sstp0"),
    };

    const auto result = resolve_internal_vpn_service_policies(
        {policy("ndms-service:sstp-server", false)},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true,
        InternalVpnInboundObservation{
            {"br0"},
            {{"br0", "192.168.1.1/24"}},
        });

    REQUIRE(result.complete());
    REQUIRE(result.effective_targets.size() == 1U);
    CHECK_FALSE(result.effective_targets.front().process_clients);
    CHECK_FALSE(result.effective_targets.front().interface.has_value());
    CHECK(result.effective_targets.front().source_cidrs_v4 ==
          std::vector<std::string>{"172.16.1.0/24"});
}

TEST_CASE(
    "firmware LAN binding never grants a pooled service bypass") {
    const auto catalog = parse_ndms_vpn_server_service_catalog(
        live_like_service_config());
    const auto result = resolve_internal_vpn_service_policies(
        {policy("ndms-service:sstp-server", false)},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true,
        InternalVpnInboundObservation{
            {"br0", "eth3"},
            {{"br0", "192.168.1.1/24"}},
        });

    REQUIRE(result.complete());
    const auto target = std::find_if(
        result.effective_targets.begin(),
        result.effective_targets.end(),
        [](const auto& item) {
            return item.stable_id ==
                   "ndms-service:sstp-server";
        });
    REQUIRE(target != result.effective_targets.end());
    CHECK(target->bound_interface_id ==
          std::optional<std::string>{"Bridge0"});
    CHECK(target->interface ==
          std::optional<std::string>{"br0"});
    CHECK_FALSE(target->process_clients);

    const auto prefilter =
        build_firewall_global_prefilter_for_runtime_targets(
            Config{}, result.effective_targets);
    CHECK(prefilter.bypass_source_selectors_v4.empty());
    CHECK(prefilter.bypass_source_selectors_v6.empty());
}

TEST_CASE(
    "numbered NDMS binding remains diagnostic when client ingress is dynamic") {
    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    catalog.services = {
        service(
            "ndms-service:sstp-server",
            true,
            {"172.16.1.0/24"},
            "OpenVPN3"),
    };

    const auto verified = resolve_internal_vpn_service_policies(
        {policy("ndms-service:sstp-server", false)},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true,
        InternalVpnInboundObservation{{"ovpn3"}, {}});
    REQUIRE(verified.complete());
    REQUIRE(verified.effective_targets.size() == 1U);
    CHECK(verified.effective_targets.front().interface ==
          std::optional<std::string>{"ovpn3"});

    const auto dynamic = resolve_internal_vpn_service_policies(
        {policy("ndms-service:sstp-server", false)},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true,
        InternalVpnInboundObservation{{"ovpn2"}, {}});
    REQUIRE(dynamic.complete());
    REQUIRE(dynamic.effective_targets.size() == 1U);
    CHECK_FALSE(dynamic.effective_targets.front().interface.has_value());
    CHECK(dynamic.effective_targets.front().source_cidrs_v4 ==
          std::vector<std::string>{"172.16.1.0/24"});
}

TEST_CASE("service pools overlapping an inbound LAN network fail closed") {
    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    catalog.services = {
        service("ndms-service:sstp-server", true,
                {"172.16.1.0/24"}),
        service("ndms-crypto-map:ike2", true,
                {"172.20.8.0/23"}),
    };

    const auto result = resolve_internal_vpn_service_policies(
        {},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true,
        {
            // Netlink reports interface addresses, not normalized networks.
            "172.16.1.1/24",
            "192.168.1.1/24",
        });

    CHECK_FALSE(result.complete());
    REQUIRE(result.effective_targets.size() == 1);
    CHECK(result.effective_targets.front().stable_id ==
          "ndms-crypto-map:ike2");
    REQUIRE(result.issues.size() == 1);
    CHECK(result.issues.front().error ==
          InternalVpnServiceResolutionError::
              source_pool_overlaps_inbound_network);
}

TEST_CASE("stale service inventory retains verified includes but never bypass") {
    const auto candidate = resolve_internal_vpn_service_policies(
        {policy("ndms-service:sstp-server", false)},
        NdmsVpnServerServiceCatalog{},
        /*catalog_authoritative=*/false,
        /*default_process_clients=*/true);

    InternalVpnRuntimeTarget inherited;
    inherited.stable_id = "ndms-crypto-map:ike2";
    inherited.match_kind =
        InternalVpnRuntimeMatchKind::source_pool;
    inherited.process_clients = true;
    inherited.source_cidrs_v4 = {"172.20.8.0/23"};

    InternalVpnRuntimeTarget explicit_bypass = inherited;
    explicit_bypass.stable_id = "ndms-service:sstp-server";
    explicit_bypass.source_cidrs_v4 = {"172.16.1.0/24"};

    const auto generation =
        select_internal_vpn_service_generation(
            {policy("ndms-service:sstp-server", false)},
            candidate,
            {inherited, explicit_bypass},
            /*default_process_clients=*/true);

    CHECK(generation.source ==
          InternalVpnServiceGenerationSource::
              retained_previous_includes);
    REQUIRE(generation.effective_targets.size() == 1);
    CHECK(generation.effective_targets.front().stable_id ==
          "ndms-crypto-map:ike2");
}

TEST_CASE(
    "one incomplete live service retains only its exact verified include") {
    const auto baseline_catalog =
        parse_ndms_vpn_server_service_catalog(
            live_like_service_config());
    const auto baseline = resolve_internal_vpn_service_policies(
        {},
        baseline_catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true);
    REQUIRE(baseline.complete());
    REQUIRE(baseline.verified_includes_for_lkg.size() == 4U);

    auto malformed = live_like_service_config();
    auto& lines = malformed["message"];
    const auto l2tp_range = std::find(
        lines.begin(),
        lines.end(),
        nlohmann::json(
            "    l2tp-server range 172.16.2.33 172.16.2.233"));
    REQUIRE(l2tp_range != lines.end());
    lines.erase(l2tp_range);
    const auto partial_catalog =
        parse_ndms_vpn_server_service_catalog(malformed);
    CHECK(
        partial_catalog.unresolved_service_ids ==
        std::vector<std::string>{
            "ndms-crypto-map:l2tp:VPNL2TPServer"});

    const auto partial = resolve_internal_vpn_service_policies(
        {},
        partial_catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true);
    CHECK_FALSE(partial.complete());
    CHECK(partial.effective_targets.size() == 3U);
    CHECK(
        partial.retain_verified_include_service_ids ==
        std::vector<std::string>{
            "ndms-crypto-map:l2tp:VPNL2TPServer"});

    const auto generation =
        select_internal_vpn_service_generation(
            {},
            partial,
            baseline.verified_includes_for_lkg,
            /*default_process_clients=*/true);
    CHECK(
        generation.source ==
        InternalVpnServiceGenerationSource::
            verified_partial_candidate);
    REQUIRE(generation.effective_targets.size() == 4U);
    const auto retained = std::find_if(
        generation.effective_targets.begin(),
        generation.effective_targets.end(),
        [](const auto& target) {
            return target.stable_id ==
                   "ndms-crypto-map:l2tp:VPNL2TPServer";
        });
    REQUIRE(retained != generation.effective_targets.end());
    CHECK(retained->process_clients);
    const auto baseline_l2tp = std::find_if(
        baseline.verified_includes_for_lkg.begin(),
        baseline.verified_includes_for_lkg.end(),
        [](const auto& target) {
            return target.stable_id ==
                   "ndms-crypto-map:l2tp:VPNL2TPServer";
        });
    REQUIRE(
        baseline_l2tp !=
        baseline.verified_includes_for_lkg.end());
    CHECK(
        retained->source_cidrs_v4 ==
        baseline_l2tp->source_cidrs_v4);
    const auto merged_lkg =
        merge_internal_vpn_service_verified_includes_lkg(
            baseline.verified_includes_for_lkg,
            partial.verified_includes_for_lkg,
            partial.retain_verified_include_service_ids);
    REQUIRE(merged_lkg.size() == 4U);
    CHECK(std::any_of(
        merged_lkg.begin(),
        merged_lkg.end(),
        [](const auto& target) {
            return target.stable_id ==
                   "ndms-crypto-map:l2tp:VPNL2TPServer";
        }));

    const auto bypass_candidate =
        resolve_internal_vpn_service_policies(
            {policy(
                "ndms-crypto-map:l2tp:VPNL2TPServer",
                false)},
            partial_catalog,
            /*catalog_authoritative=*/true,
            /*default_process_clients=*/true);
    CHECK(
        bypass_candidate
            .retain_verified_include_service_ids.empty());
    const auto bypass_generation =
        select_internal_vpn_service_generation(
            {policy(
                "ndms-crypto-map:l2tp:VPNL2TPServer",
                false)},
            bypass_candidate,
            baseline.verified_includes_for_lkg,
            /*default_process_clients=*/true);
    CHECK(bypass_generation.effective_targets.size() == 3U);
    CHECK(std::none_of(
        bypass_generation.effective_targets.begin(),
        bypass_generation.effective_targets.end(),
        [](const auto& target) {
            return target.stable_id ==
                   "ndms-crypto-map:l2tp:VPNL2TPServer";
        }));
    const auto bypass_lkg =
        merge_internal_vpn_service_verified_includes_lkg(
            baseline.verified_includes_for_lkg,
            bypass_candidate.verified_includes_for_lkg,
            bypass_candidate.retain_verified_include_service_ids);
    REQUIRE(bypass_lkg.size() == 3U);
    CHECK(std::none_of(
        bypass_lkg.begin(),
        bypass_lkg.end(),
        [](const auto& target) {
            return target.stable_id ==
                   "ndms-crypto-map:l2tp:VPNL2TPServer";
        }));
}

TEST_CASE("missing firmware availability is never treated as authoritative") {
    const auto candidate = resolve_internal_vpn_service_policies(
        {},
        NdmsVpnServerServiceCatalog{},
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true);

    CHECK_FALSE(candidate.complete());
    CHECK(candidate.retain_all_verified_includes);
    REQUIRE(candidate.issues.size() == 1);
    CHECK(candidate.issues.front().error ==
          InternalVpnServiceResolutionError::catalog_not_authoritative);
}

TEST_CASE("authoritative removal does not retain a vanished service") {
    NdmsVpnServerServiceCatalog catalog;
    catalog.firmware_available = true;
    const auto candidate = resolve_internal_vpn_service_policies(
        {policy("ndms-crypto-map:gone", true)},
        catalog,
        /*catalog_authoritative=*/true,
        /*default_process_clients=*/true);

    InternalVpnRuntimeTarget previous;
    previous.stable_id = "ndms-crypto-map:gone";
    previous.match_kind =
        InternalVpnRuntimeMatchKind::source_pool;
    previous.process_clients = true;
    previous.source_cidrs_v4 = {"172.20.8.0/23"};

    const auto generation =
        select_internal_vpn_service_generation(
            {policy("ndms-crypto-map:gone", true)},
            candidate,
            {previous},
            /*default_process_clients=*/true);
    CHECK(generation.effective_targets.empty());
    CHECK(generation.source ==
          InternalVpnServiceGenerationSource::empty_fail_closed);
}
