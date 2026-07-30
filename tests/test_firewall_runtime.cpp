#include <doctest/doctest.h>

#include "../src/firewall/firewall_runtime.hpp"

#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

InternalVpnRuntimeTarget service_target(
    std::string stable_id,
    bool process_clients,
    std::vector<std::string> source_cidrs_v4,
    std::vector<std::string> source_cidrs_v6 = {}) {
    InternalVpnRuntimeTarget target;
    target.stable_id = std::move(stable_id);
    target.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    target.process_clients = process_clients;
    target.source_cidrs_v4 = std::move(source_cidrs_v4);
    target.source_cidrs_v6 = std::move(source_cidrs_v6);
    return target;
}

} // namespace

TEST_CASE(
    "Native VPN direct egress covers SSTP L2TP and IKEv1 in both modes") {
    const auto disabled = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/false,
        {"172.16.1.33/32", "172.16.1.34/31", ""});
    const auto enabled = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/true,
        {"172.16.1.33/32", "172.16.1.36/30"});
    const auto l2tp_disabled = service_target(
        "ndms-crypto-map:l2tp:VPNL2TPServer",
        /*process_clients=*/false,
        {"172.16.2.33/32", "172.16.2.34/31"});
    const auto l2tp_enabled = service_target(
        "ndms-crypto-map:l2tp:SharedRemoteAccess",
        /*process_clients=*/true,
        {"172.16.2.36/30", "172.16.1.33/32"});
    const auto ikev1_disabled = service_target(
        "ndms-crypto-map:ikev1:VirtualIPServer",
        /*process_clients=*/false,
        {"172.20.0.1/32", "172.20.0.2/31"});
    const auto ikev1_enabled = service_target(
        "ndms-crypto-map:ikev1:SharedIPsecAccess",
        /*process_clients=*/true,
        {"172.20.0.4/30", "172.16.1.33/32"});

    const auto selectors =
        select_native_vpn_direct_egress_snat_selectors(
        {disabled,
         enabled,
         l2tp_disabled,
         l2tp_enabled,
         ikev1_disabled,
         ikev1_enabled},
        {"eth3", "eth3", "", "ppp0"});

    CHECK(
        selectors ==
        std::vector<FirewallSourceEgressSnatSelector>{
            {"eth3", "172.16.1.33/32"},
            {"eth3", "172.16.1.34/31"},
            {"eth3", "172.16.1.36/30"},
            {"eth3", "172.16.2.33/32"},
            {"eth3", "172.16.2.34/31"},
            {"eth3", "172.16.2.36/30"},
            {"eth3", "172.20.0.1/32"},
            {"eth3", "172.20.0.2/31"},
            {"eth3", "172.20.0.4/30"},
            {"ppp0", "172.16.1.33/32"},
            {"ppp0", "172.16.1.34/31"},
            {"ppp0", "172.16.1.36/30"},
            {"ppp0", "172.16.2.33/32"},
            {"ppp0", "172.16.2.34/31"},
            {"ppp0", "172.16.2.36/30"},
            {"ppp0", "172.20.0.1/32"},
            {"ppp0", "172.20.0.2/31"},
            {"ppp0", "172.20.0.4/30"},
        });
}

TEST_CASE(
    "Native VPN direct egress IDs are strict and leave stable paths out") {
    const auto ikev2 = service_target(
        "ndms-crypto-map:ikev2:VirtualIPServerIKE2",
        /*process_clients=*/true,
        {"172.20.8.0/23"});
    const auto wireguard = service_target(
        "ndms-interface:Wireguard0",
        /*process_clients=*/true,
        {"10.10.0.0/24"});
    const auto similarly_named = service_target(
        "ndms-service:sstp-server-backup",
        /*process_clients=*/false,
        {"172.30.0.0/24"});
    const auto empty_l2tp_name = service_target(
        "ndms-crypto-map:l2tp:",
        /*process_clients=*/true,
        {"172.31.0.0/24"});
    const auto wrong_l2tp_namespace = service_target(
        "ndms-crypto-map:l2tp-backup:VPNL2TPServer",
        /*process_clients=*/true,
        {"172.31.1.0/24"});
    const auto empty_ikev1_name = service_target(
        "ndms-crypto-map:ikev1:",
        /*process_clients=*/true,
        {"172.31.3.0/24"});
    const auto wrong_ikev1_namespace = service_target(
        "ndms-crypto-map:ikev1-backup:VirtualIPServer",
        /*process_clients=*/true,
        {"172.31.4.0/24"});
    const auto generic_ike_namespace = service_target(
        "ndms-crypto-map:ike:VirtualIPServer",
        /*process_clients=*/true,
        {"172.31.5.0/24"});
    const auto case_variant_ikev1 = service_target(
        "ndms-crypto-map:IKEV1:VirtualIPServer",
        /*process_clients=*/true,
        {"172.31.7.0/24"});
    const auto ikev1_ipv6_only = service_target(
        "ndms-crypto-map:ikev1:IPv6Only",
        /*process_clients=*/true,
        {},
        {"2001:db8:20::/64"});
    const auto legacy_l2tp_interface = service_target(
        "ndms-interface:L2TP0",
        /*process_clients=*/true,
        {"172.31.2.0/24"});
    const auto legacy_ipsec_interface = service_target(
        "ndms-interface:Ipsec0",
        /*process_clients=*/true,
        {"172.31.6.0/24"});
    const auto sstp_ipv6_only = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/true,
        {},
        {"2001:db8:16::/64"});

    CHECK(
        select_native_vpn_direct_egress_snat_selectors(
            {ikev2,
             wireguard,
             similarly_named,
             empty_l2tp_name,
             wrong_l2tp_namespace,
             empty_ikev1_name,
             wrong_ikev1_namespace,
             generic_ike_namespace,
             case_variant_ikev1,
             ikev1_ipv6_only,
             legacy_l2tp_interface,
             legacy_ipsec_interface,
             sstp_ipv6_only},
            {"eth3"})
            .empty());
}

TEST_CASE("Native VPN direct egress selection requires a current WAN") {
    const auto sstp = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/false,
        {"172.16.1.33/32"});

    CHECK(
        select_native_vpn_direct_egress_snat_selectors(
            {sstp}, {})
            .empty());
}

TEST_CASE(
    "Native VPN direct egress cleanup changes only affected source pools") {
    const std::vector<FirewallSourceEgressSnatSelector> sstp{
        {"eth3", "172.16.1.32/27"}};
    const std::vector<FirewallSourceEgressSnatSelector> with_l2tp{
        {"eth3", "172.16.1.32/27"},
        {"eth3", "172.16.2.32/27"}};

    CHECK(
        changed_native_vpn_direct_egress_source_cidrs(
            sstp, with_l2tp) ==
        std::vector<std::string>{"172.16.2.32/27"});
    CHECK(
        changed_native_vpn_direct_egress_source_cidrs(
            with_l2tp,
            {{"eth3", "172.16.2.32/27"},
             {"eth3", "172.16.1.32/27"}})
            .empty());
}

TEST_CASE(
    "Native VPN direct egress cleanup tracks pool and WAN changes exactly") {
    CHECK(
        changed_native_vpn_direct_egress_source_cidrs(
            {{"eth3", "172.16.2.32/27"}},
            {{"eth3", "172.16.2.64/27"}}) ==
        std::vector<std::string>{
            "172.16.2.32/27", "172.16.2.64/27"});
    CHECK(
        changed_native_vpn_direct_egress_source_cidrs(
            {{"eth3", "172.16.2.32/27"}},
            {{"ppp0", "172.16.2.32/27"}}) ==
        std::vector<std::string>{"172.16.2.32/27"});
}
