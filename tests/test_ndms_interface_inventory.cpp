#include <doctest/doctest.h>

#include "keenetic/ndms_interface_inventory.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>

using namespace keen_pbr3;

TEST_CASE("NDMS inventory excludes non-tunnel interfaces") {
    const auto payload = nlohmann::json{
        {"Bridge0",
         {{"type", "Bridge"},
          {"interface-name", "br0"},
          {"description", "Home"}}},
        {"WifiMaster0/AccessPoint0",
         {{"type", "AccessPoint"},
          {"interface-name", "wl0"},
          {"description", "Wi-Fi"}}},
        {"Wireguard2",
         {{"type", "Wireguard"},
          {"interface-name", "wg2"},
          {"description", "Office VPN"},
          {"connected", "yes"},
          {"link", true}}},
    };

    const auto catalog = parse_ndms_interface_catalog(payload);
    CHECK(catalog.firmware_available);
    CHECK(catalog.names.size() == 3);
    REQUIRE(catalog.tunnels.size() == 1);
    CHECK(catalog.tunnels[0].id == "Wireguard2");
    CHECK(catalog.tunnels[0].kernel_name == "wg2");
    CHECK(catalog.tunnels[0].kind == NdmsTunnelKind::wireguard);
    CHECK(catalog.tunnels[0].connected == true);
    CHECK(catalog.tunnels[0].link == true);
}

TEST_CASE("NDMS inventory recognizes supported tunnels and strict proxies") {
    const auto payload = nlohmann::json{
        {"Wireguard2",
         {{"type", "Tunnel"},
          {"interface-name", "nwg2"},
          {"description", "AWG"}}},
        {"Vpn0",
         {{"type", "OpenVPN"},
          {"interface-name", "ovpn0"}}},
        {"Proxy0",
         {{"type", "Proxy"},
          {"proxy-type", "SOCKS5"},
          {"interface-name", "proxy0"}}},
        {"UnknownProxy",
         {{"type", "Proxy"},
          {"interface-name", "proxy1"}}},
    };

    const auto catalog = parse_ndms_interface_catalog(payload);
    REQUIRE(catalog.tunnels.size() == 3);
    const auto contains = [&catalog](NdmsTunnelKind kind) {
        return std::any_of(
            catalog.tunnels.begin(),
            catalog.tunnels.end(),
            [kind](const auto& tunnel) {
                return tunnel.kind == kind;
            });
    };
    CHECK(contains(NdmsTunnelKind::amnezia_wireguard));
    CHECK(contains(NdmsTunnelKind::openvpn));
    CHECK(contains(NdmsTunnelKind::socks5_proxy));
}

TEST_CASE("NDMS inventory tolerates firmware boolean variants") {
    const auto payload = nlohmann::json{
        {"Vpn0",
         {{"type", "SSTP"},
          {"interface-name", "sstp0"},
          {"connected", false},
          {"link", "down"}}},
    };

    const auto catalog = parse_ndms_interface_catalog(payload);
    REQUIRE(catalog.tunnels.size() == 1);
    CHECK(catalog.tunnels[0].connected == false);
    CHECK(catalog.tunnels[0].link == false);
}
