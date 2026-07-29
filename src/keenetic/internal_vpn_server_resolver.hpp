#pragma once

#include "../config/config.hpp"
#include "ndms_interface_inventory.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class InternalVpnServerResolutionError : std::uint8_t {
    legacy_interface_missing,
    catalog_not_authoritative,
    stable_id_missing,
    unsupported_kind,
    unsupported_role,
    kernel_interface_unresolved,
    duplicate_kernel_interface,
};

struct InternalVpnServerResolutionIssue {
    InternalVpnServerResolutionError error{
        InternalVpnServerResolutionError::kernel_interface_unresolved};
    std::string interface;
    std::string ndms_id;
};

struct InternalVpnServerResolution {
    // Runtime-only copies. Persisted configuration is never rewritten when an
    // NDMS stable identity resolves to a new kernel interface name.
    std::vector<InternalVpnServer> effective_servers;
    // Conservative fallback used only when the complete generation cannot be
    // verified. It can force an exact-live interface into processing, but can
    // never install a process_clients=false bypass from an unverified
    // identity. If the intended ingress itself is unresolved, the caller must
    // report degraded operation rather than claim full fail-closed coverage.
    std::vector<InternalVpnServer> safe_degraded_servers;
    // Freshly verified stable include bindings from this observation. Unlike
    // effective_servers, this remains useful when another configured identity
    // failed authoritatively: the daemon can replace its include-only LKG with
    // the successful subset instead of either retaining a revoked binding or
    // dropping an unrelated verified server.
    std::vector<InternalVpnServer> verified_includes_for_lkg;
    // Stable include identities whose current observation is inconclusive.
    // Their previously verified binding may be retained per identity even
    // when an unrelated legacy/stable row failed authoritatively.
    std::vector<std::string> retain_verified_include_ndms_ids;
    std::vector<InternalVpnServerResolutionIssue> issues;

    bool complete() const noexcept {
        return issues.empty();
    }
};

enum class InternalVpnServerGenerationSource : std::uint8_t {
    verified_candidate,
    retained_previous,
    safe_degraded_candidate,
    unavailable,
};

struct InternalVpnServerGeneration {
    std::vector<InternalVpnServer> effective_servers;
    InternalVpnServerGenerationSource source{
        InternalVpnServerGenerationSource::unavailable};

    bool usable() const noexcept {
        return source != InternalVpnServerGenerationSource::unavailable;
    }
};

// Pure resolution pass. The caller owns catalog refresh and live netlink
// inventory collection, which keeps RCI/network I/O out of the control loop.
//
// Rows without ndms_id remain backward compatible and use their exact saved
// interface only while it exists. Stable rows accept verified native VPN
// server records from a fresh catalog only. WireGuard/AmneziaWG may use their
// verified firmware-name mapping; OpenVPN/IKE/L2TP/SSTP/OpenConnect require an
// exact live kernel match. HTTP/HTTPS/SOCKS proxies are never ingress VPN
// servers. A saved or previous kernel name is never promoted to a new verified
// identity merely because that name currently exists: KeeneticOS can reuse
// kernel names after delete/recreate and renumber operations.
InternalVpnServerResolution resolve_internal_vpn_server_policies(
    const std::vector<InternalVpnServer>& configured,
    const NdmsInterfaceCatalog& catalog,
    bool catalog_authoritative,
    const std::vector<std::string>& runtime_interface_names);

// Stable NDMS identities require a catalog observation. Empty and legacy-only
// policies resolve entirely from the live kernel inventory and must not add a
// loopback RCI request (or its timeout) to startup.
bool internal_vpn_server_policies_require_ndms_catalog(
    const std::vector<InternalVpnServer>& configured) noexcept;

// An incomplete observation may retain previously verified stable
// process_clients=true bindings that still have the same configured identity
// and policy when that identity's own observation is inconclusive. A verified
// binding takes precedence over the saved-name degraded fallback, because the
// old kernel name may have been reused after a rename. A
// process_clients=false bypass is never retained without a fresh NDMS
// observation. The caller must pass only its verified include-only LKG;
// unverified/legacy generations are not valid input here.
InternalVpnServerGeneration select_internal_vpn_server_generation(
    const std::vector<InternalVpnServer>& configured,
    const InternalVpnServerResolution& candidate,
    const std::vector<InternalVpnServer>& previous_effective);

// Build the next verified include-only cache. Fresh bindings always win.
// Previous bindings are retained only for stable identities whose current
// observation is explicitly inconclusive, and never when their kernel
// interface is already occupied by a freshly verified identity.
std::vector<InternalVpnServer> merge_internal_vpn_verified_includes_lkg(
    const std::vector<InternalVpnServer>& previous,
    const std::vector<InternalVpnServer>& freshly_verified,
    const std::vector<std::string>& retain_ndms_ids);

std::string describe_internal_vpn_server_resolution_issue(
    const InternalVpnServerResolutionIssue& issue);

} // namespace keen_pbr3
