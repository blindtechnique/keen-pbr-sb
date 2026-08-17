#pragma once

#include <nlohmann/json.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
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

inline constexpr std::size_t kNdmsWireguardCatalogSlotCount = 127U;

enum class NdmsWireguardCatalogSlotState : std::uint8_t {
    absent,
    occupied,
    unsafe,
};

// Fixed, non-secret evidence for the measured Wireguard0..Wireguard126
// firmware namespace. An occupied slot has exactly one structurally valid RCI
// claimant. Unsafe means the parser observed a scalar record, duplicate,
// conflicting identity or another malformed claim that must not be collapsed
// into the UI inventory's deterministic duplicate winner.
struct NdmsWireguardCatalogSlotEvidence {
    NdmsWireguardCatalogSlotState state{
        NdmsWireguardCatalogSlotState::absent};
    // Domain-separated SHA-256 over the canonical slot, exact RCI record id,
    // effective firmware interface name and the existing non-secret structural
    // allowlist. Empty for absent and unsafe slots.
    std::string structural_revision;
};

struct NdmsTunnelInterface {
    std::string id;
    std::string firmware_interface_name;
    std::optional<std::string> kernel_name;
    std::string label;
    std::string firmware_type;
    NdmsTunnelKind kind{NdmsTunnelKind::wireguard};
    NdmsInterfaceRole role{NdmsInterfaceRole::unknown};
    // True only when the read-only NDMS record is safe to offer as an
    // internal VPN-server policy target. For WG/AWG, KeeneticOS 5.1.1 does
    // not report a client/server role, so this additionally requires an
    // explicitly non-global interface, no default gateway and a non-host
    // local subnet. The UI must still obtain an explicit user confirmation.
    bool internal_vpn_server_candidate{false};
    bool internal_vpn_server_role_confirmation_required{false};
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
    // Whole seconds since this interface last came up, as maintained by the
    // firmware. It is the only up-transition record that outlives a keen-pbr
    // restart, and 0 is the firmware stating the interface is not up.
    // Intentionally excluded from NdmsTunnelInterface::inventory_revision.
    std::optional<std::int64_t> uptime_seconds;
};

struct NdmsInterfaceCatalog {
    bool firmware_available{false};
    // Cached, validated firmware metadata for every interface. Runtime kernel
    // resolution is intentionally a separate pure pass.
    std::vector<NdmsInterfaceMetadata> interface_metadata;
    std::vector<NdmsTunnelInterface> tunnels;
    // Mutation/recovery consumers must require this flag and reject every
    // unsafe slot. Runtime kernel resolution copies this raw-firmware evidence
    // unchanged; connected/link/uptime never participate in its revisions.
    std::array<
        NdmsWireguardCatalogSlotEvidence,
        kNdmsWireguardCatalogSlotCount>
        wireguard_slots{};
    bool wireguard_slot_evidence_complete{false};
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
