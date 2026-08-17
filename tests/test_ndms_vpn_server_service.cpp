#include <doctest/doctest.h>

#include "keenetic/ndms_vpn_server_service.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

const NdmsVpnServerService* find_service(
    const NdmsVpnServerServiceCatalog& catalog,
    const std::string& id) {
    const auto found = std::find_if(
        catalog.services.begin(),
        catalog.services.end(),
        [&id](const auto& service) {
            return service.id == id;
        });
    return found == catalog.services.end() ? nullptr : &*found;
}

nlohmann::json live_like_running_config() {
    return {{"message", {
        "crypto ike policy VPNL2TPServer",
        "    mode ikev1",
        "crypto ike policy VirtualIPServer",
        "    mode ikev1",
        "crypto ike policy VirtualIPServerIKE2",
        "    mode ikev2",
        "crypto map VPNL2TPServer",
        "    set-profile VPNL2TPServer",
        "    virtual-ip no enable",
        "    l2tp-server range 172.16.2.33 172.16.2.233",
        "    l2tp-server interface Bridge0",
        "    l2tp-server enable",
        "    enable",
        "crypto map VirtualIPServer",
        "    set-profile VirtualIPServer",
        "    virtual-ip range 172.20.0.1 172.20.1.0",
        "    virtual-ip interface Bridge0",
        "    virtual-ip enable",
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

TEST_CASE("NDMS address ranges become a minimal canonical CIDR cover") {
    CHECK(ndms_address_range_to_cidrs(
              "192.0.2.7", "192.0.2.7") ==
          std::vector<std::string>{"192.0.2.7/32"});

    const auto cidrs = ndms_address_range_to_cidrs(
        "172.16.2.33", "172.16.2.233");
    REQUIRE(cidrs.size() == 10);
    CHECK(cidrs.front() == "172.16.2.33/32");
    CHECK(cidrs.back() == "172.16.2.232/31");

    CHECK(ndms_address_range_to_cidrs(
              "2001:db8::4", "2001:db8::7") ==
          std::vector<std::string>{"2001:db8::4/126"});
}

TEST_CASE("NDMS address range parser rejects ambiguous input") {
    CHECK_THROWS(ndms_address_range_to_cidrs(
        "192.0.2.10", "192.0.2.1"));
    CHECK_THROWS(ndms_address_range_to_cidrs(
        "192.0.2.1", "2001:db8::1"));
    CHECK_THROWS(ndms_address_range_to_cidrs(
        "2001:0db8::1", "2001:db8::2"));
    CHECK_THROWS(ndms_address_range_to_cidrs(
        "10.0.0.0", "10.1.0.0"));
}

TEST_CASE("NDMS running config discovers every supported pooled VPN server") {
    const auto catalog =
        parse_ndms_vpn_server_service_catalog(
            live_like_running_config());

    CHECK(catalog.firmware_available);
    REQUIRE(catalog.services.size() == 5);

    const auto* l2tp =
        find_service(
            catalog,
            "ndms-crypto-map:l2tp:VPNL2TPServer");
    REQUIRE(l2tp != nullptr);
    CHECK(l2tp->kind == NdmsVpnServerServiceKind::l2tp);
    CHECK(l2tp->enabled);
    CHECK(l2tp->bound_interface_id ==
          std::optional<std::string>{"Bridge0"});
    CHECK(l2tp->source_cidrs_v4.front() ==
          "172.16.2.33/32");
    CHECK_FALSE(l2tp->inventory_revision.empty());

    const auto* ikev2 = find_service(
        catalog,
        "ndms-crypto-map:ikev2:VirtualIPServerIKE2");
    REQUIRE(ikev2 != nullptr);
    CHECK(ikev2->kind == NdmsVpnServerServiceKind::ikev2);
    CHECK(ikev2->enabled);
    const auto* ikev1 = find_service(
        catalog,
        "ndms-crypto-map:ikev1:VirtualIPServer");
    REQUIRE(ikev1 != nullptr);
    CHECK(ikev1->kind == NdmsVpnServerServiceKind::ikev1);
    CHECK(ikev1->source_cidrs_v4.front() ==
          "172.20.0.1/32");

    const auto* sstp =
        find_service(catalog, "ndms-service:sstp-server");
    REQUIRE(sstp != nullptr);
    CHECK(sstp->kind == NdmsVpnServerServiceKind::sstp);
    CHECK(sstp->enabled);
    CHECK(sstp->source_cidrs_v4.front() ==
          "172.16.1.33/32");

    const auto* openconnect =
        find_service(catalog, "ndms-service:oc-server");
    REQUIRE(openconnect != nullptr);
    CHECK(openconnect->kind ==
          NdmsVpnServerServiceKind::openconnect);
    CHECK(openconnect->enabled);
    CHECK(openconnect->source_cidrs_v4.front() ==
          "172.30.4.17/32");
    CHECK(openconnect->source_cidrs_v4.back() ==
          "172.30.4.28/32");
}

TEST_CASE("NDMS pooled server ranges are not tied to a fixed subnet") {
    auto config = live_like_running_config();
    auto& lines = config["message"];
    const auto range = std::find(
        lines.begin(),
        lines.end(),
        nlohmann::json(
            "    l2tp-server range 172.16.2.33 172.16.2.233"));
    REQUIRE(range != lines.end());
    *range = "    l2tp-server range 198.51.100.9 7";

    const auto catalog =
        parse_ndms_vpn_server_service_catalog(config);
    const auto* l2tp =
        find_service(
            catalog,
            "ndms-crypto-map:l2tp:VPNL2TPServer");
    REQUIRE(l2tp != nullptr);
    CHECK(l2tp->source_cidrs_v4 ==
          std::vector<std::string>{
              "198.51.100.9/32",
              "198.51.100.10/31",
              "198.51.100.12/30"});
}

TEST_CASE("NDMS VPN inventory revision excludes secret-bearing lines") {
    auto first = live_like_running_config();
    auto second = live_like_running_config();
    first["message"].insert(
        first["message"].begin() + 11,
        "    password first-secret");
    second["message"].insert(
        second["message"].begin() + 11,
        "    password second-secret");

    const auto first_catalog =
        parse_ndms_vpn_server_service_catalog(first);
    const auto second_catalog =
        parse_ndms_vpn_server_service_catalog(second);
    REQUIRE(first_catalog.services.size() ==
            second_catalog.services.size());
    for (std::size_t index = 0;
         index < first_catalog.services.size();
         ++index) {
        CHECK(first_catalog.services[index].inventory_revision ==
              second_catalog.services[index].inventory_revision);
    }
}

TEST_CASE(
    "NDMS service parser omits one incomplete service without hiding inventory") {
    auto config = live_like_running_config();
    auto& lines = config["message"];
    const auto range = std::find(
        lines.begin(),
        lines.end(),
        nlohmann::json(
            "    l2tp-server range 172.16.2.33 172.16.2.233"));
    REQUIRE(range != lines.end());
    lines.erase(range);
    const auto catalog =
        parse_ndms_vpn_server_service_catalog(config);
    CHECK(catalog.firmware_available);
    CHECK(catalog.services.size() == 4U);
    CHECK(
        find_service(
            catalog,
            "ndms-crypto-map:l2tp:VPNL2TPServer") ==
        nullptr);
    CHECK(
        catalog.unresolved_service_ids ==
        std::vector<std::string>{
            "ndms-crypto-map:l2tp:VPNL2TPServer"});
    CHECK(
        find_service(
            catalog,
            "ndms-crypto-map:ikev2:VirtualIPServerIKE2") !=
        nullptr);
    CHECK_THROWS(
        parse_ndms_vpn_server_service_catalog(
            nlohmann::json{{"message", {17}}}));
}

TEST_CASE(
    "NDMS parser discovers L2TP and IKE independently in one crypto map") {
    const nlohmann::json config = {{"message", {
        "crypto ike policy SharedProfile",
        "    mode ikev2",
        "crypto map SharedRemoteAccess",
        "    set-profile SharedProfile",
        "    l2tp-server range 172.16.2.33 2",
        "    l2tp-server interface L2tp0",
        "    l2tp-server enable",
        "    virtual-ip range 172.20.8.1 2",
        "    virtual-ip interface Ipsec0",
        "    virtual-ip enable",
        "    enable",
    }}};

    const auto catalog =
        parse_ndms_vpn_server_service_catalog(config);
    REQUIRE(catalog.services.size() == 2U);
    const auto* l2tp = find_service(
        catalog,
        "ndms-crypto-map:l2tp:SharedRemoteAccess");
    const auto* ikev2 = find_service(
        catalog,
        "ndms-crypto-map:ikev2:SharedRemoteAccess");
    REQUIRE(l2tp != nullptr);
    REQUIRE(ikev2 != nullptr);
    CHECK(l2tp->bound_interface_id == "L2tp0");
    CHECK(ikev2->bound_interface_id == "Ipsec0");
}
