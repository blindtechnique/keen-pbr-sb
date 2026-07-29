#include <doctest/doctest.h>

#include "keenetic/ndms_interface_inventory.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

const NdmsTunnelInterface* find_tunnel(const NdmsInterfaceCatalog& catalog,
                                       const std::string& id) {
    const auto found = std::find_if(
        catalog.tunnels.begin(),
        catalog.tunnels.end(),
        [&id](const auto& tunnel) {
            return tunnel.id == id;
        });
    return found == catalog.tunnels.end() ? nullptr : &*found;
}

} // namespace

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
          {"interface-name", "Wireguard2"},
          {"description", "Office VPN"},
          {"connected", "yes"},
          {"link", true}}},
    };

    const auto unresolved = parse_ndms_interface_catalog(payload);
    CHECK(unresolved.names.empty());
    CHECK(unresolved.interface_metadata.size() == 3);
    REQUIRE(unresolved.tunnels.size() == 1);
    CHECK_FALSE(unresolved.tunnels[0].kernel_name.has_value());

    const auto catalog =
        resolve_ndms_kernel_names(unresolved, {"br0", "wl0", "nwg2"});
    CHECK(catalog.firmware_available);
    CHECK(catalog.names.size() == 3);
    REQUIRE(catalog.tunnels.size() == 1);
    CHECK(catalog.tunnels[0].id == "Wireguard2");
    CHECK(catalog.tunnels[0].firmware_interface_name == "Wireguard2");
    CHECK(catalog.tunnels[0].kernel_name ==
          std::optional<std::string>{"nwg2"});
    CHECK(catalog.tunnels[0].kind == NdmsTunnelKind::wireguard);
    CHECK(catalog.tunnels[0].role == NdmsInterfaceRole::unknown);
    CHECK(catalog.tunnels[0].connected == true);
    CHECK(catalog.tunnels[0].link == true);
    CHECK(catalog.names.at("nwg2").at("firmware_interface_name") ==
          "Wireguard2");
}

TEST_CASE("NDMS inventory classifies only complete allowlisted tokens") {
    const auto payload = nlohmann::json{
        {"NotWireguard",
         {{"type", "NotWireguard"},
          {"interface-name", "bad0"}}},
        {"OpenVpnBackup",
         {{"type", "OpenVPNBackup"},
          {"interface-name", "bad1"}}},
        {"IpsecHelper",
         {{"protocol", "ipsec-helper"},
          {"interface-name", "bad2"}}},
        {"AnyConnectSuffix",
         {{"subtype", "anyconnect-client"},
          {"interface-name", "bad3"}}},
        {"UnicodePrefix",
         {{"type", "ЖWireguard"},
          {"interface-name", "bad4"}}},
        {"NwgPrefixOnly",
         {{"type", "Tunnel"},
          {"interface-name", "nwg8"}}},
        {"WireguardNameOnly",
         {{"type", "Tunnel"},
          {"interface-name", "Wireguard98"}}},
        {"BridgeWithProtocol",
         {{"type", "Bridge"},
          {"protocol", "Wireguard"},
          {"interface-name", "bad5"}}},
        {"BridgeNamedWireguard",
         {{"type", "Bridge"},
          {"interface-name", "Wireguard99"}}},
        {"SeparatedToken",
         {{"type", "Wireg-uard"},
          {"interface-name", "bad6"}}},
        {"ConflictingTokens",
         {{"type", "OpenVPN"},
          {"protocol", "Wireguard"},
          {"interface-name", "bad7"}}},
        {"ValidWireguard",
         {{"type", "Wireguard"},
          {"interface-name", "wg-valid"}}},
        {"ValidOpenVpn",
         {{"protocol", "OPENVPN"},
          {"interface-name", "ovpn-valid"}}},
        {"ValidIke",
         {{"subtype", "IKEv2"},
          {"interface-name", "ike-valid"}}},
    };

    const auto catalog = parse_ndms_interface_catalog(payload);
    REQUIRE(catalog.tunnels.size() == 3);
    REQUIRE(find_tunnel(catalog, "ValidWireguard") != nullptr);
    CHECK(find_tunnel(catalog, "ValidWireguard")->kind ==
          NdmsTunnelKind::wireguard);
    REQUIRE(find_tunnel(catalog, "ValidOpenVpn") != nullptr);
    CHECK(find_tunnel(catalog, "ValidOpenVpn")->kind ==
          NdmsTunnelKind::openvpn);
    REQUIRE(find_tunnel(catalog, "ValidIke") != nullptr);
    CHECK(find_tunnel(catalog, "ValidIke")->kind == NdmsTunnelKind::ike);
}

TEST_CASE("NDMS inventory requires an exact Proxy type and proxy subtype") {
    const auto payload = nlohmann::json{
        {"Socks",
         {{"type", "Proxy"},
          {"proxy-type", "SOCKS5"},
          {"interface-name", "proxy0"}}},
        {"Https",
         {{"type", "proxy"},
          {"proxy-type", "HTTPS-proxy"},
          {"interface-name", "proxy1"}}},
        {"Http",
         {{"type", "PROXY"},
          {"proxy-type", "http"},
          {"interface-name", "proxy2"}}},
        {"WrongParent",
         {{"type", "ReverseProxy"},
          {"proxy-type", "SOCKS5"},
          {"interface-name", "proxy3"}}},
        {"WrongSubtype",
         {{"type", "Proxy"},
          {"proxy-type", "SOCKS50"},
          {"interface-name", "proxy4"}}},
        {"MissingSubtype",
         {{"type", "Proxy"},
          {"interface-name", "proxy5"}}},
        {"ProxyWithTunnelProtocol",
         {{"type", "Proxy"},
          {"protocol", "Wireguard"},
          {"interface-name", "proxy6"}}},
        {"SeparatedParent",
         {{"type", "P-r-o-x-y"},
          {"proxy-type", "SOCKS5"},
          {"interface-name", "proxy7"}}},
        {"SeparatedSubtype",
         {{"type", "Proxy"},
          {"proxy-type", "S_O_C_K_S_5"},
          {"interface-name", "proxy8"}}},
    };

    const auto catalog = parse_ndms_interface_catalog(payload);
    REQUIRE(catalog.tunnels.size() == 3);
    REQUIRE(find_tunnel(catalog, "Socks") != nullptr);
    CHECK(find_tunnel(catalog, "Socks")->kind ==
          NdmsTunnelKind::socks5_proxy);
    REQUIRE(find_tunnel(catalog, "Https") != nullptr);
    CHECK(find_tunnel(catalog, "Https")->kind ==
          NdmsTunnelKind::https_proxy);
    REQUIRE(find_tunnel(catalog, "Http") != nullptr);
    CHECK(find_tunnel(catalog, "Http")->kind ==
          NdmsTunnelKind::http_proxy);
}

TEST_CASE("NDMS inventory keeps malformed records from discarding the catalog") {
    const auto payload = nlohmann::json{
        {"Malformed",
         {{"type", nlohmann::json::array({"Wireguard"})},
          {"subtype", 17},
          {"protocol", nullptr},
          {"proxy-type", nlohmann::json::object()},
          {"interface-name", 42},
          {"description", nlohmann::json::array()},
          {"connected", nlohmann::json::object()},
          {"link", 1}}},
        {"Valid",
         {{"type", "SSTP"},
          {"interface-name", "Sstp0"},
          {"description", "Рабочий туннель 東京"}}},
        {"ScalarEntry", 123},
    };

    const auto catalog =
        parse_ndms_interface_catalog(payload, {"Malformed", "Sstp0"});
    CHECK(catalog.firmware_available);
    CHECK(catalog.names.size() == 2);
    CHECK(catalog.names.at("Malformed").at("label") == "Malformed");
    CHECK_FALSE(catalog.names.at("Malformed").contains("connected"));
    CHECK_FALSE(catalog.names.at("Malformed").contains("link"));
    REQUIRE(catalog.tunnels.size() == 1);
    CHECK(catalog.tunnels[0].id == "Valid");
    CHECK(catalog.tunnels[0].label == "Рабочий туннель 東京");
}

TEST_CASE("NDMS inventory preserves known booleans and omits unknown strings") {
    const auto payload = nlohmann::json{
        {"KnownFalse",
         {{"type", "SSTP"},
          {"interface-name", "Sstp0"},
          {"connected", false},
          {"link", " DOWN "}}},
        {"KnownTrue",
         {{"type", "L2TP"},
          {"interface-name", "L2tp0"},
          {"connected", "Connected"},
          {"link", "ON"}}},
        {"Unknown",
         {{"type", "OpenVPN"},
          {"interface-name", "OpenVpn0"},
          {"connected", "sometimes"},
          {"link", "unknown"}}},
    };

    const auto catalog = parse_ndms_interface_catalog(payload);
    REQUIRE(catalog.tunnels.size() == 3);
    REQUIRE(find_tunnel(catalog, "KnownFalse") != nullptr);
    CHECK(find_tunnel(catalog, "KnownFalse")->connected == false);
    CHECK(find_tunnel(catalog, "KnownFalse")->link == false);
    REQUIRE(find_tunnel(catalog, "KnownTrue") != nullptr);
    CHECK(find_tunnel(catalog, "KnownTrue")->connected == true);
    CHECK(find_tunnel(catalog, "KnownTrue")->link == true);
    REQUIRE(find_tunnel(catalog, "Unknown") != nullptr);
    CHECK_FALSE(find_tunnel(catalog, "Unknown")->connected.has_value());
    CHECK_FALSE(find_tunnel(catalog, "Unknown")->link.has_value());
}

TEST_CASE("NDMS resolver only returns observed runtime interface names") {
    const std::vector<std::string> runtime_names{
        "eth3",
        "Wireguard5",
        "nwg2",
        "nwg5",
        "ppp0",
        "tun0",
    };

    CHECK(resolve_ndms_kernel_name("eth3", runtime_names) ==
          std::optional<std::string>{"eth3"});
    CHECK(resolve_ndms_kernel_name("Wireguard5", runtime_names) ==
          std::optional<std::string>{"Wireguard5"});
    CHECK(resolve_ndms_kernel_name("Wireguard2", runtime_names) ==
          std::optional<std::string>{"nwg2"});
    CHECK_FALSE(
        resolve_ndms_kernel_name("Wireguard7", runtime_names).has_value());
    CHECK_FALSE(resolve_ndms_kernel_name("Ppp0", runtime_names).has_value());
    CHECK_FALSE(resolve_ndms_kernel_name("Tunnel0", runtime_names).has_value());
    CHECK_FALSE(resolve_ndms_kernel_name("MyWireguard2", runtime_names)
                    .has_value());
}

TEST_CASE("NDMS keeps unresolved strict records and maps real Keenetic Wireguard") {
    const auto payload = nlohmann::json{
        {"Wireguard2",
         {{"type", "Wireguard"},
          {"interface-name", "Wireguard2"},
          {"description", "Keenetic WG"}}},
        {"OpenVpn0",
         {{"type", "OpenVPN"},
          {"interface-name", "OpenVpn0"}}},
        {"Amnezia0",
         {{"type", "Amnezia WireGuard"},
          {"interface-name", "Amnezia0"}}},
        {"OpenVpnNamedWireguard",
         {{"type", "OpenVPN"},
          {"interface-name", "Wireguard7"}}},
        {"BridgeNamedWireguard",
         {{"type", "Bridge"},
          {"interface-name", "Wireguard8"}}},
    };

    const auto catalog = parse_ndms_interface_catalog(
        payload,
        {"nwg2", "nwg7", "nwg8", "tun0"});
    REQUIRE(catalog.tunnels.size() == 4);

    const auto* wireguard = find_tunnel(catalog, "Wireguard2");
    REQUIRE(wireguard != nullptr);
    CHECK(wireguard->firmware_interface_name == "Wireguard2");
    CHECK(wireguard->kernel_name == std::optional<std::string>{"nwg2"});
    CHECK(wireguard->kind == NdmsTunnelKind::wireguard);

    const auto* openvpn = find_tunnel(catalog, "OpenVpn0");
    REQUIRE(openvpn != nullptr);
    CHECK_FALSE(openvpn->kernel_name.has_value());

    const auto* amnezia = find_tunnel(catalog, "Amnezia0");
    REQUIRE(amnezia != nullptr);
    CHECK(amnezia->kind == NdmsTunnelKind::amnezia_wireguard);
    CHECK_FALSE(amnezia->kernel_name.has_value());

    const auto* named_openvpn =
        find_tunnel(catalog, "OpenVpnNamedWireguard");
    REQUIRE(named_openvpn != nullptr);
    CHECK_FALSE(named_openvpn->kernel_name.has_value());
    CHECK_FALSE(catalog.names.contains("nwg7"));
    CHECK_FALSE(catalog.names.contains("nwg8"));
}

TEST_CASE("NDMS role accepts only exact non-conflicting role fields") {
    const auto payload = nlohmann::json{
        {"Client",
         {{"type", "Wireguard"},
          {"interface-name", "Client"},
          {"role", " CLIENT "}}},
        {"Server",
         {{"type", "Wireguard"},
          {"interface-name", "Server"},
          {"mode", "server"},
          {"interface-role", "SERVER"}}},
        {"Missing",
         {{"type", "Wireguard"},
          {"interface-name", "Missing"}}},
        {"Suffix",
         {{"type", "Wireguard"},
          {"interface-name", "Suffix"},
          {"role", "client-mode"}}},
        {"Malformed",
         {{"type", "Wireguard"},
          {"interface-name", "Malformed"},
          {"role", true},
          {"interface-role", "client"}}},
        {"Conflict",
         {{"type", "Wireguard"},
          {"interface-name", "Conflict"},
          {"role", "client"},
          {"mode", "server"}}},
    };

    const auto catalog = parse_ndms_interface_catalog(payload);
    REQUIRE(catalog.tunnels.size() == 6);
    REQUIRE(find_tunnel(catalog, "Client") != nullptr);
    CHECK(find_tunnel(catalog, "Client")->role == NdmsInterfaceRole::client);
    REQUIRE(find_tunnel(catalog, "Server") != nullptr);
    CHECK(find_tunnel(catalog, "Server")->role == NdmsInterfaceRole::server);
    for (const auto* id : {"Missing", "Suffix", "Malformed", "Conflict"}) {
        REQUIRE(find_tunnel(catalog, id) != nullptr);
        CHECK(find_tunnel(catalog, id)->role == NdmsInterfaceRole::unknown);
    }
    CHECK(std::string{ndms_interface_role_name(NdmsInterfaceRole::client)} ==
          "client");
    CHECK(std::string{ndms_interface_role_name(NdmsInterfaceRole::server)} ==
          "server");
    CHECK(std::string{ndms_interface_role_name(NdmsInterfaceRole::unknown)} ==
          "unknown");
}

TEST_CASE("NDMS role-less WireGuard server candidates are fail-closed") {
    const auto candidate = [](nlohmann::json entry) {
        const auto catalog = parse_ndms_interface_catalog(
            nlohmann::json{{"Candidate", std::move(entry)}});
        const auto* tunnel = find_tunnel(catalog, "Candidate");
        REQUIRE(tunnel != nullptr);
        return std::pair{
            tunnel->internal_vpn_server_candidate,
            tunnel->internal_vpn_server_role_confirmation_required,
        };
    };
    const auto shaped_ipv4 = [] {
        return nlohmann::json{
            {"type", "Wireguard"},
            {"interface-name", "Wireguard0"},
            {"global", false},
            {"address", "10.10.0.1"},
            {"mask", "255.255.255.0"},
        };
    };

    CHECK(candidate(shaped_ipv4()) == std::pair{true, true});

    auto cidr = shaped_ipv4();
    cidr["address"] = "10.10.0.1/24";
    cidr.erase("mask");
    CHECK(candidate(cidr) == std::pair{true, true});

    auto ipv6 = shaped_ipv4();
    ipv6["address"] = "fd00::1/64";
    ipv6.erase("mask");
    CHECK(candidate(ipv6) == std::pair{true, true});

    for (const auto& [field, value] :
         std::vector<std::pair<std::string, nlohmann::json>>{
             {"global", true},
             {"global", "down"},
             {"global", "off"},
             {"global", nullptr},
             {"global", 0},
             {"defaultgw", true},
             {"default-route", true},
             {"default-gateway", true},
         }) {
        auto rejected = shaped_ipv4();
        rejected[field] = value;
        CHECK(candidate(rejected) == std::pair{false, false});
    }

    auto missing_global = shaped_ipv4();
    missing_global.erase("global");
    CHECK(candidate(missing_global) == std::pair{false, false});

    for (const auto* address :
         {"10.10.0.1/32",
          "10.10.0.1/31",
          "10.10.0.1/0",
          "fd00::1/128",
          "fd00::1/127",
          "fd00::1/0"}) {
        auto rejected = shaped_ipv4();
        rejected["address"] = address;
        rejected.erase("mask");
        CHECK(candidate(rejected) == std::pair{false, false});
    }

    auto non_contiguous_mask = shaped_ipv4();
    non_contiguous_mask["mask"] = "255.0.255.0";
    CHECK(candidate(non_contiguous_mask) == std::pair{false, false});

    auto huge_mask = shaped_ipv4();
    huge_mask["mask"] = std::uint64_t{4294967296ULL};
    CHECK(candidate(huge_mask) == std::pair{false, false});

    for (const auto& role_fields :
         std::vector<nlohmann::json>{
             nlohmann::json{{"role", "client"}},
             nlohmann::json{{"role", "unknown"}},
             nlohmann::json{{"role", 17}},
             nlohmann::json{{"role", "client"}, {"mode", "server"}},
         }) {
        auto rejected = shaped_ipv4();
        rejected.update(role_fields);
        CHECK(candidate(rejected) == std::pair{false, false});
    }

    auto typed_server = nlohmann::json{
        {"type", "Wireguard"},
        {"interface-name", "Wireguard0"},
        {"role", "server"},
    };
    CHECK(candidate(typed_server) == std::pair{true, false});

    auto typed_client_with_shape = shaped_ipv4();
    typed_client_with_shape["role"] = "client";
    CHECK(candidate(typed_client_with_shape) == std::pair{false, false});

    for (const auto& malformed_discriminator :
         std::vector<nlohmann::json>{
             nlohmann::json{
                 {"type", 17},
                 {"protocol", "Wireguard"},
                 {"interface-name", "Wireguard0"},
                 {"role", "server"},
             },
             nlohmann::json{
                 {"type", "Wireguard"},
                 {"protocol", nlohmann::json::object()},
                 {"interface-name", "Wireguard0"},
                 {"role", "server"},
             },
         }) {
        const auto catalog = parse_ndms_interface_catalog(
            nlohmann::json{{"MalformedCandidate", malformed_discriminator}});
        CHECK(find_tunnel(catalog, "MalformedCandidate") == nullptr);
    }
}

TEST_CASE("NDMS server guard changes alter the inventory revision") {
    auto payload = nlohmann::json{
        {"Candidate",
         {
             {"type", "Wireguard"},
             {"interface-name", "Wireguard0"},
             {"global", false},
             {"address", "10.10.0.1/24"},
         }},
    };
    const auto baseline =
        parse_ndms_interface_catalog(payload).tunnels.front().inventory_revision;

    for (const auto* field :
         {"global",
          "defaultgw",
          "default-route",
          "default-gateway",
          "address",
          "mask",
          "role",
          "mode",
          "interface-role"}) {
        auto changed = payload;
        changed["Candidate"][field] =
            std::string{"changed-"} + field;
        CHECK(
            parse_ndms_interface_catalog(changed)
                .tunnels.front()
                .inventory_revision != baseline);
    }
}

TEST_CASE("NDMS duplicate selection is deterministic") {
    const auto payload = nlohmann::json{
        {"ZDuplicate",
         {{"type", "Wireguard"},
          {"interface-name", "Wireguard9"},
          {"description", "Later"}}},
        {"ADuplicate",
         {{"type", "Wireguard"},
          {"interface-name", "Wireguard9"},
          {"description", "First"}}},
        {"ZKernelAlias",
         {{"type", "OpenVPN"},
          {"interface-name", "nwg4"},
          {"description", "Later kernel alias"}}},
        {"AKernelMapping",
         {{"type", "Wireguard"},
          {"interface-name", "Wireguard4"},
          {"description", "First kernel mapping"}}},
    };

    const auto catalog =
        parse_ndms_interface_catalog(payload, {"nwg4", "nwg9"});
    REQUIRE(catalog.tunnels.size() == 2);
    REQUIRE(find_tunnel(catalog, "ADuplicate") != nullptr);
    CHECK(find_tunnel(catalog, "ADuplicate")->label == "First");
    REQUIRE(find_tunnel(catalog, "AKernelMapping") != nullptr);
    CHECK(find_tunnel(catalog, "AKernelMapping")->kernel_name ==
          std::optional<std::string>{"nwg4"});
    CHECK(catalog.names.at("nwg9").at("id") == "ADuplicate");
    CHECK(catalog.names.at("nwg4").at("id") == "AKernelMapping");
}
