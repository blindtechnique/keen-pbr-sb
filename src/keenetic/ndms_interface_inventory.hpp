#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class NdmsTunnelKind {
    amnezia_wireguard,
    wireguard,
    openvpn,
    ike,
    l2tp,
    sstp,
    openconnect,
    http_proxy,
    https_proxy,
    socks5_proxy,
};

struct NdmsTunnelInterface {
    std::string id;
    std::string kernel_name;
    std::string label;
    std::string firmware_type;
    NdmsTunnelKind kind{NdmsTunnelKind::wireguard};
    std::optional<bool> connected;
    std::optional<bool> link;
};

struct NdmsInterfaceCatalog {
    bool firmware_available{false};
    std::vector<NdmsTunnelInterface> tunnels;
    nlohmann::json names;
};

// Parses /rci/show/interface defensively. Only explicit tunnel and proxy types
// enter `tunnels`; bridges, VLANs, switch ports and Wi-Fi interfaces remain in
// the name map but can never be mistaken for a mutable VPN object.
NdmsInterfaceCatalog parse_ndms_interface_catalog(
    const nlohmann::json& interfaces);

const char* ndms_tunnel_kind_name(NdmsTunnelKind kind) noexcept;

} // namespace keen_pbr3
