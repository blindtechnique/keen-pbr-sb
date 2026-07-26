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

enum class NdmsInterfaceRole {
    client,
    server,
    unknown,
};

struct NdmsTunnelInterface {
    std::string id;
    std::string firmware_interface_name;
    std::optional<std::string> kernel_name;
    std::string label;
    std::string firmware_type;
    NdmsTunnelKind kind{NdmsTunnelKind::wireguard};
    NdmsInterfaceRole role{NdmsInterfaceRole::unknown};
    std::optional<bool> connected;
    std::optional<bool> link;
    // SHA-256 of a strict allowlist of non-secret structural NDMS fields.
    // Volatile live state, endpoints and credential-bearing fields never
    // participate in this observation token.
    std::string inventory_revision;
};

struct NdmsInterfaceMetadata {
    std::string id;
    std::string firmware_interface_name;
    std::string label;
    std::string firmware_type;
    std::optional<bool> connected;
    std::optional<bool> link;
};

struct NdmsInterfaceCatalog {
    bool firmware_available{false};
    // Cached, validated firmware metadata for every interface. Runtime kernel
    // resolution is intentionally a separate pure pass.
    std::vector<NdmsInterfaceMetadata> interface_metadata;
    std::vector<NdmsTunnelInterface> tunnels;
    // Compatibility view keyed only by a kernel interface name observed in
    // the runtime-name input. It is empty on an unresolved catalog.
    nlohmann::json names;
};

// Parses /rci/show/interface defensively. Only explicit tunnel and proxy types
// enter `tunnels`; bridges, VLANs, switch ports and Wi-Fi interfaces remain in
// the name map but can never be mistaken for a mutable VPN object.
NdmsInterfaceCatalog parse_ndms_interface_catalog(
    const nlohmann::json& interfaces);

// Parsing remains pure: callers provide the interface names that currently
// exist in the kernel. A firmware name is resolved only by an exact match, or
// by the WireguardN -> nwgN mapping observed on KeeneticOS 5.1.1 when that
// nwgN candidate is actually present.
NdmsInterfaceCatalog parse_ndms_interface_catalog(
    const nlohmann::json& interfaces,
    const std::vector<std::string>& runtime_interface_names);

std::optional<std::string> resolve_ndms_kernel_name(
    const std::string& firmware_interface_name,
    const std::vector<std::string>& runtime_interface_names);

NdmsInterfaceCatalog resolve_ndms_kernel_names(
    const NdmsInterfaceCatalog& catalog,
    const std::vector<std::string>& runtime_interface_names);

const char* ndms_tunnel_kind_name(NdmsTunnelKind kind) noexcept;
const char* ndms_interface_role_name(NdmsInterfaceRole role) noexcept;

} // namespace keen_pbr3
