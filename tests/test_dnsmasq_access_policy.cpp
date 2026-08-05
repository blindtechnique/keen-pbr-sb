#include <doctest/doctest.h>

#include "../src/dns/dnsmasq_access_policy.hpp"
#include "../src/keenetic/internal_vpn_ingress_resolver.hpp"

#include <algorithm>

using namespace keen_pbr3;

TEST_CASE("dnsmasq access policy stays implicit without verified VPN servers") {
    CHECK(build_dnsmasq_trusted_interfaces({}, {}).empty());
}

TEST_CASE("dnsmasq access policy covers verified native and pooled VPN ingress") {
    InternalVpnServer wireguard{};
    wireguard.interface = "nwg0";

    InternalVpnRuntimeTarget ikev2;
    ikev2.stable_id =
        "ndms-crypto-map:ikev2:VirtualIPServerIKE2";
    ikev2.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    ikev2.interface = "br0";

    InternalVpnRuntimeTarget sstp;
    sstp.stable_id = "ndms-service:sstp-server";
    sstp.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    sstp.process_clients = true;
    sstp.interface = "br0";
    sstp.source_cidrs_v4 = {"172.16.1.0/24"};

    DumpedInterface server_sstp_bridge;
    server_sstp_bridge.name = "sstp-bridge";

    DumpedInterface sstp_bridge_port;
    sstp_bridge_port.name = "sstp-peer-link";
    sstp_bridge_port.master_interface = "sstp-bridge";

    DumpedInterface lan_bridge_port;
    lan_bridge_port.name = "sstp-br-link";
    lan_bridge_port.master_interface = "br0";

    DumpedInterface lan_bridge;
    lan_bridge.name = "br0";

    DumpedInterface server_peer;
    server_peer.name = "sstp8";
    server_peer.master_interface = "sstp-bridge";
    server_peer.ipv4_peer_addresses = {"172.16.1.33/32"};

    DumpedInterface outbound_peer;
    outbound_peer.name = "ppp0";
    // Deliberately overlaps the server pool: an address alone must never
    // identify a server-owned ingress interface.
    outbound_peer.ipv4_peer_addresses = {"172.16.1.44/32"};

    DumpedInterface ike_server1;
    ike_server1.name = "xfrms1";

    DumpedInterface ike_server2;
    ike_server2.name = "xfrms2";

    DumpedInterface unrelated_xfrm;
    unrelated_xfrm.name = "xfrms3";

    std::vector<InternalVpnRuntimeTarget> targets{ikev2, sstp};
    refresh_internal_vpn_service_ingress_interfaces(
        targets,
        {
            server_sstp_bridge,
            sstp_bridge_port,
            lan_bridge_port,
            lan_bridge,
            server_peer,
            outbound_peer,
            ike_server1,
            ike_server2,
            unrelated_xfrm,
        });

    CHECK(
        build_dnsmasq_trusted_interfaces({wireguard}, targets) ==
        std::vector<std::string>{
            "br*",
            "nwg0",
            "xfrms1",
            "xfrms2",
        });
}

TEST_CASE("dnsmasq access policy resolves bridged SSTP at its L3 ingress") {
    InternalVpnRuntimeTarget sstp;
    sstp.stable_id = "ndms-service:sstp-server";
    sstp.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    sstp.process_clients = true;
    sstp.interface = "br0";
    sstp.source_cidrs_v4 = {"172.16.1.0/24"};

    DumpedInterface bridge;
    bridge.name = "sstp-bridge";
    DumpedInterface peer_link;
    peer_link.name = "sstp-peer-link";
    peer_link.master_interface = "sstp-bridge";
    DumpedInterface br_link;
    br_link.name = "sstp-br-link";
    br_link.master_interface = "br0";
    DumpedInterface lan;
    lan.name = "br0";
    DumpedInterface session;
    session.name = "sstp4";
    session.admin_up = true;
    session.carrier = true;
    session.master_interface = "sstp-bridge";
    session.ipv4_peer_addresses = {"172.16.1.44/32"};

    std::vector<InternalVpnRuntimeTarget> targets{sstp};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {bridge, peer_link, br_link, lan, session});
    CHECK(
        targets.front().verified_ingress_interfaces ==
        std::vector<std::string>{"br0"});
    // br* already covers the verified br0 listener without a duplicate line.
    CHECK(
        build_dnsmasq_trusted_interfaces({}, targets) ==
        std::vector<std::string>{"br*"});

    // SSTP may be bound to any Keenetic segment. Never hardcode br0.
    sstp.interface = "br1";
    br_link.master_interface = "br1";
    lan.name = "br1";
    targets = {sstp};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {bridge, peer_link, br_link, lan, session});
    CHECK(
        targets.front().verified_ingress_interfaces ==
        std::vector<std::string>{"br1"});

    // A shared bridge plus a source address does not prove that a packet came
    // from SSTP. Exclusion therefore fails closed until the firewall can also
    // match the physical bridge ingress.
    sstp.process_clients = false;
    targets = {sstp};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {bridge, peer_link, br_link, lan, session});
    CHECK(targets.front().verified_ingress_interfaces.empty());
    CHECK(
        targets.front().verified_bridge_ingress_interfaces ==
        std::vector<InternalVpnVerifiedBridgeIngress>{
            {"br1", "sstp-br-link"}});

    // A direct, non-bridged SSTP peer remains an exact L3 ingress.
    sstp.interface.reset();
    targets = {sstp};
    session.master_interface.reset();
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {session});
    CHECK(
        targets.front().verified_ingress_interfaces ==
        std::vector<std::string>{"sstp4"});
    CHECK(targets.front().verified_bridge_ingress_interfaces.empty());

    // Keenetic may keep the bridge/veth scaffold while the active SSTP peer
    // is a direct point-to-point interface. That stale scaffold must not
    // introduce a physdev rule into the firewall transaction.
    sstp.interface = "br0";
    br_link.master_interface = "br0";
    lan.name = "br0";
    targets = {sstp};
    DumpedInterface direct_session;
    direct_session.name = "sstp0";
    direct_session.admin_up = true;
    direct_session.carrier = true;
    direct_session.ipv4_peer_addresses = {"172.16.1.33/32"};
    refresh_internal_vpn_service_ingress_interfaces(
        targets,
        {
            bridge,
            peer_link,
            br_link,
            lan,
            direct_session,
        });
    CHECK(
        targets.front().verified_ingress_interfaces ==
        std::vector<std::string>{"sstp0"});
    CHECK(targets.front().verified_bridge_ingress_interfaces.empty());

    // The complete persistent bridge/veth scaffold without an active sstpN
    // session is not a live bridged ingress either.
    targets = {sstp};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {bridge, peer_link, br_link, lan});
    CHECK(targets.front().verified_ingress_interfaces.empty());
    CHECK(targets.front().verified_bridge_ingress_interfaces.empty());

    // A half-created veth topology must not grant a shared bridge bypass.
    sstp.interface = "br0";
    targets = {sstp};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {bridge, peer_link, lan});
    CHECK(targets.front().verified_ingress_interfaces.empty());
    CHECK(targets.front().verified_bridge_ingress_interfaces.empty());
}

TEST_CASE("dnsmasq access policy ignores unsafe interface text") {
    // `{}` здесь по привычке, а не по необходимости: с тех пор генератор
    // API-типов сам инициализирует скалярные поля. До этого `InternalVpnServer x;`
    // оставлял `process_clients` неопределённым, и UBSan ловил на копировании
    // «load of value 49, which is not a valid value for type bool».
    InternalVpnServer unsafe{};
    unsafe.interface = "nwg0\ninterface=eth3";
    InternalVpnServer wildcard{};
    wildcard.interface = "eth*";

    CHECK(
        build_dnsmasq_trusted_interfaces({unsafe, wildcard}, {}) ==
        std::vector<std::string>{"br*"});
}

TEST_CASE("dnsmasq access policy follows exact live server peers") {
    InternalVpnRuntimeTarget l2tp;
    l2tp.stable_id = "ndms-crypto-map:l2tp:RemoteAccess";
    l2tp.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    l2tp.source_cidrs_v4 = {"172.16.2.32/27"};

    DumpedInterface server_peer;
    server_peer.name = "l2tp7";
    server_peer.ipv4_peer_addresses = {"172.16.2.33/32"};

    DumpedInterface client_tunnel;
    client_tunnel.name = "ppp0";
    client_tunnel.ipv4_peer_addresses = {"172.16.2.34/32"};

    std::vector<InternalVpnRuntimeTarget> targets{l2tp};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {server_peer, client_tunnel});
    CHECK(
        build_dnsmasq_trusted_interfaces({}, targets) ==
        std::vector<std::string>{"br*", "l2tp7"});

    refresh_internal_vpn_service_ingress_interfaces(
        targets, {client_tunnel});
    CHECK(
        build_dnsmasq_trusted_interfaces({}, targets) ==
        std::vector<std::string>{"br*"});
}

TEST_CASE(
    "addressless IKE ingress bypasses DNS redirect only until it has a "
    "usable local address") {
    InternalVpnRuntimeTarget ikev2;
    ikev2.stable_id =
        "ndms-crypto-map:ikev2:VirtualIPServerIKE2";
    ikev2.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    ikev2.process_clients = true;
    ikev2.source_cidrs_v4 = {"172.20.8.0/23"};
    ikev2.source_cidrs_v6 = {"2001:db8:20::/64"};

    DumpedInterface xfrms;
    xfrms.name = "xfrms1";
    xfrms.ipv6_addresses = {"fe80::1/64"};

    std::vector<InternalVpnRuntimeTarget> targets{ikev2};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {xfrms});
    CHECK(
        targets.front().verified_ingress_interfaces ==
        std::vector<std::string>{"xfrms1"});
    CHECK(
        targets.front().dns_redirect_bypass_ingress_v4 ==
        std::vector<std::string>{"xfrms1"});
    // A link-local IPv6 address cannot receive a redirect for the server's
    // client pool and therefore remains DNS-unsafe.
    CHECK(
        targets.front().dns_redirect_bypass_ingress_v6 ==
        std::vector<std::string>{"xfrms1"});

    xfrms.ipv4_addresses = {"10.0.0.1/32"};
    xfrms.ipv6_addresses = {"2001:db8::1/128"};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {xfrms});
    CHECK(targets.front().dns_redirect_bypass_ingress_v4.empty());
    CHECK(targets.front().dns_redirect_bypass_ingress_v6.empty());
}

TEST_CASE(
    "addressless non-IKE service ingress never receives DNS-only bypass") {
    InternalVpnRuntimeTarget l2tp;
    l2tp.stable_id =
        "ndms-crypto-map:l2tp:VirtualIPServerL2TP";
    l2tp.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    l2tp.process_clients = true;
    l2tp.source_cidrs_v4 = {"172.16.2.32/27"};

    DumpedInterface peer;
    peer.name = "l2tp7";
    peer.ipv4_peer_addresses = {"172.16.2.33/32"};

    std::vector<InternalVpnRuntimeTarget> targets{l2tp};
    refresh_internal_vpn_service_ingress_interfaces(
        targets, {peer});
    CHECK(
        targets.front().verified_ingress_interfaces ==
        std::vector<std::string>{"l2tp7"});
    CHECK(targets.front().dns_redirect_bypass_ingress_v4.empty());
    CHECK(targets.front().dns_redirect_bypass_ingress_v6.empty());
}

TEST_CASE("dnsmasq access policy never emits VPN wildcard selectors") {
    InternalVpnRuntimeTarget ike;
    ike.stable_id = "ndms-crypto-map:ikev2:RemoteAccess";
    InternalVpnRuntimeTarget l2tp;
    l2tp.stable_id = "ndms-crypto-map:l2tp:RemoteAccess";
    InternalVpnRuntimeTarget sstp;
    sstp.stable_id = "ndms-service:sstp-server";
    InternalVpnRuntimeTarget openconnect;
    openconnect.stable_id = "ndms-service:oc-server";

    const auto interfaces = build_dnsmasq_trusted_interfaces(
        {}, {ike, l2tp, sstp, openconnect});
    CHECK(interfaces == std::vector<std::string>{"br*"});
    CHECK(
        std::none_of(
            interfaces.begin(),
            interfaces.end(),
            [](const auto& interface) {
                return
                    interface == "xfrms*" ||
                    interface == "l2tp*" ||
                    interface == "sstp*" ||
                    interface == "oc*";
            }));
}
