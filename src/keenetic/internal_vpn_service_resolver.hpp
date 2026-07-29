#pragma once

#include "internal_vpn_runtime_target.hpp"
#include "ndms_interface_inventory.hpp"
#include "ndms_vpn_server_service.hpp"
#include "../routing/netlink.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class InternalVpnServiceResolutionError : std::uint8_t {
    catalog_not_authoritative,
    stable_id_missing,
    service_disabled,
    source_pool_unresolved,
    duplicate_service_id,
    overlapping_source_pool,
    source_pool_overlaps_inbound_network,
    source_pool_bypass_unverified_ingress,
};

struct InternalVpnServiceResolutionIssue {
    InternalVpnServiceResolutionError error{
        InternalVpnServiceResolutionError::source_pool_unresolved};
    std::string service_id;
};

struct InternalVpnServiceResolution {
    std::vector<InternalVpnRuntimeTarget> effective_targets;
    // Only process_clients=true targets are eligible for LKG retention.
    // Exclusions are never retained from a stale firmware observation.
    std::vector<InternalVpnRuntimeTarget> verified_includes_for_lkg;
    std::vector<std::string> retain_verified_include_service_ids;
    bool retain_all_verified_includes{false};
    std::vector<InternalVpnServiceResolutionIssue> issues;

    bool complete() const noexcept {
        return issues.empty();
    }
};

enum class InternalVpnServiceGenerationSource : std::uint8_t {
    verified_candidate,
    verified_partial_candidate,
    retained_previous_includes,
    empty_fail_closed,
};

struct InternalVpnServiceGeneration {
    std::vector<InternalVpnRuntimeTarget> effective_targets;
    InternalVpnServiceGenerationSource source{
        InternalVpnServiceGenerationSource::empty_fail_closed};
};

// Match the legacy ingress policy: without a non-empty explicit allowlist,
// all ingress is processed; with one, newly discovered service pools inherit
// bypass until the user adds an override.
bool internal_vpn_service_default_process_clients(
    const Config& config) noexcept;

struct InternalVpnProtectedInboundNetwork {
    std::string interface;
    std::string cidr;
};

struct InternalVpnInboundObservation {
    std::vector<std::string> verified_interfaces;
    std::vector<InternalVpnProtectedInboundNetwork> protected_networks;
};

// The running-config service inventory is authoritative for pooled
// L2TP/IKE/SSTP/OpenConnect servers. Older KeeneticOS observations may expose
// the same server through /rci/show/interface as well. While a fresh service
// record exists, suppress that legacy interface selector so one server cannot
// install two conflicting process/bypass policies. The saved interface policy
// is retained and becomes a fallback again if the service record disappears.
std::vector<InternalVpnServer>
prefer_authoritative_internal_vpn_service_inventory(
    const std::vector<InternalVpnServer>& interface_servers,
    const NdmsInterfaceCatalog& interface_catalog,
    const NdmsVpnServerServiceCatalog& service_catalog,
    bool service_catalog_authoritative);

InternalVpnInboundObservation internal_vpn_inbound_observation(
    const Config& config,
    const std::vector<DumpedInterface>& interfaces);

// Protect configured ingress networks from being reclassified as a VPN client
// source pool. In the legacy "all ingress" mode, connected non-host networks
// are authoritative; dynamic point-to-point /32 and /128 endpoints are not.
std::vector<std::string> internal_vpn_protected_inbound_cidrs(
    const Config& config,
    const std::vector<DumpedInterface>& interfaces);

InternalVpnServiceResolution resolve_internal_vpn_service_policies(
    const std::vector<InternalVpnService>& configured,
    const NdmsVpnServerServiceCatalog& catalog,
    bool catalog_authoritative,
    bool default_process_clients,
    const std::vector<std::string>& protected_inbound_cidrs = {});

InternalVpnServiceResolution resolve_internal_vpn_service_policies(
    const std::vector<InternalVpnService>& configured,
    const NdmsVpnServerServiceCatalog& catalog,
    bool catalog_authoritative,
    bool default_process_clients,
    const InternalVpnInboundObservation& inbound_observation);

InternalVpnServiceGeneration select_internal_vpn_service_generation(
    const std::vector<InternalVpnService>& configured,
    const InternalVpnServiceResolution& candidate,
    const std::vector<InternalVpnRuntimeTarget>& previous_verified_includes,
    bool default_process_clients);

std::vector<InternalVpnRuntimeTarget>
merge_internal_vpn_service_verified_includes_lkg(
    const std::vector<InternalVpnRuntimeTarget>& previous,
    const std::vector<InternalVpnRuntimeTarget>& freshly_verified,
    const std::vector<std::string>& retain_service_ids);

std::string describe_internal_vpn_service_resolution_issue(
    const InternalVpnServiceResolutionIssue& issue);

} // namespace keen_pbr3
