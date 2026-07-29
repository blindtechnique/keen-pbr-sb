#pragma once

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class NdmsVpnServerServiceKind : std::uint8_t {
    l2tp,
    ikev1,
    ikev2,
    sstp,
    openconnect,
};

struct NdmsVpnServerService {
    // Stable identity owned by keen-pbr. It is derived only from the NDMS
    // service kind and the validated firmware object name, never from an
    // ephemeral kernel interface.
    std::string id;
    std::string label;
    NdmsVpnServerServiceKind kind{NdmsVpnServerServiceKind::l2tp};
    bool enabled{false};
    std::optional<std::string> bound_interface_id;
    std::vector<std::string> source_cidrs_v4;
    std::vector<std::string> source_cidrs_v6;
    // SHA-256 of a strict non-secret structural projection.
    std::string inventory_revision;
};

struct NdmsVpnServerServiceCatalog {
    bool firmware_available{false};
    std::vector<NdmsVpnServerService> services;
    // Stable identities that were present in the current running-config but
    // could not be verified independently (for example because one pool
    // range was missing or malformed). The rest of the catalog remains
    // authoritative; runtime may retain only the exact previously verified
    // process_clients=true target for one of these identities.
    std::vector<std::string> unresolved_service_ids;
};

// Convert one inclusive address range into the smallest canonical CIDR cover.
// Both addresses must be canonical members of the same IP family. Invalid,
// reversed, or pathologically large input is rejected.
std::vector<std::string> ndms_address_range_to_cidrs(
    const std::string& first,
    const std::string& last);

// Pure, bounded, fail-closed parser for /rci/show/running-config. Only the
// allowlisted structural commands needed for L2TP, IKEv1/IKEv2, SSTP and
// OpenConnect discovery are retained. Credential-bearing or unrelated lines
// are never copied into the result, revision hash, or exception text.
NdmsVpnServerServiceCatalog parse_ndms_vpn_server_service_catalog(
    const nlohmann::json& running_config);

const char* ndms_vpn_server_service_kind_name(
    NdmsVpnServerServiceKind kind) noexcept;

} // namespace keen_pbr3
