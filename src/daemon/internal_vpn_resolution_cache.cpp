#include "internal_vpn_resolution_cache.hpp"

#include "../keenetic/internal_vpn_ingress_resolver.hpp"
#include "../keenetic/internal_vpn_server_resolver.hpp"
#include "../keenetic/internal_vpn_service_resolver.hpp"
#include "../log/logger.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace keen_pbr3 {
namespace {

bool same_servers(
    const std::vector<InternalVpnServer>& lhs,
    const std::vector<InternalVpnServer>& rhs) noexcept {
    return lhs.size() == rhs.size() &&
           std::equal(
               lhs.begin(),
               lhs.end(),
               rhs.begin(),
               [](const InternalVpnServer& left,
                  const InternalVpnServer& right) {
                   return left.interface == right.interface &&
                          left.ndms_id == right.ndms_id &&
                          left.process_clients == right.process_clients;
               });
}

bool same_service_targets(
    const std::vector<InternalVpnRuntimeTarget>& lhs,
    const std::vector<InternalVpnRuntimeTarget>& rhs) noexcept {
    return lhs.size() == rhs.size() &&
           std::equal(
               lhs.begin(),
               lhs.end(),
               rhs.begin(),
               [](const auto& left, const auto& right) {
                   return left.stable_id == right.stable_id &&
                          left.match_kind == right.match_kind &&
                          left.process_clients == right.process_clients &&
                          left.bound_interface_id ==
                              right.bound_interface_id &&
                          left.interface == right.interface &&
                          left.verified_ingress_interfaces ==
                              right.verified_ingress_interfaces &&
                          left.verified_bridge_ingress_interfaces ==
                              right.verified_bridge_ingress_interfaces &&
                          left.dns_redirect_bypass_ingress_v4 ==
                              right.dns_redirect_bypass_ingress_v4 &&
                          left.dns_redirect_bypass_ingress_v6 ==
                              right.dns_redirect_bypass_ingress_v6 &&
                          left.dns_redirect_local_destinations_v4 ==
                              right.dns_redirect_local_destinations_v4 &&
                          left.dns_redirect_local_destinations_v6 ==
                              right.dns_redirect_local_destinations_v6 &&
                          left.source_cidrs_v4 == right.source_cidrs_v4 &&
                          left.source_cidrs_v6 == right.source_cidrs_v6;
               });
}

} // namespace

bool InternalVpnResolutionCache::active_matches(
    const std::vector<InternalVpnServer>& servers,
    const std::vector<InternalVpnRuntimeTarget>& service_targets) const
    noexcept {
    return same_servers(active_servers_, servers) &&
           same_service_targets(active_service_targets_, service_targets);
}

InternalVpnRuntimeResolution InternalVpnResolutionCache::resolve_servers(
    const Config& config,
    const NdmsCatalogSnapshot& snapshot,
    const std::vector<DumpedInterface>& live_interfaces) const {
    const auto configured = config.route.has_value()
        ? config.route->internal_vpn_servers.value_or(
              std::vector<InternalVpnServer>{})
        : std::vector<InternalVpnServer>{};
    if (configured.empty()) {
        return {{}, InternalVpnRuntimeResolutionState::verified};
    }

    std::vector<std::string> runtime_interface_names;
    runtime_interface_names.reserve(live_interfaces.size());
    for (const auto& interface : live_interfaces) {
        runtime_interface_names.push_back(interface.name);
    }

    auto resolution = resolve_internal_vpn_server_policies(
        configured,
        snapshot.catalog,
        snapshot.status == NdmsCatalogCacheStatus::fresh,
        runtime_interface_names);

    if (!resolution.complete()) {
        std::string detail;
        for (const auto& issue : resolution.issues) {
            if (!detail.empty()) detail += "; ";
            detail += describe_internal_vpn_server_resolution_issue(issue);
        }
        auto generation = select_internal_vpn_server_generation(
            configured, resolution, verified_lkg_.snapshot_servers());
        if (!generation.usable()) {
            throw InternalVpnResolutionError(
                "Native VPN server policy has no verified runtime generation: " +
                detail);
        }
        const bool authoritative_negative = std::any_of(
            resolution.issues.begin(),
            resolution.issues.end(),
            [](const InternalVpnServerResolutionIssue& issue) {
                return issue.error !=
                       InternalVpnServerResolutionError::
                           catalog_not_authoritative;
            });
        if (authoritative_negative) {
            Logger::instance().warn(
                "Native VPN server inventory is incomplete; continuing with "
                "a conservative degraded policy (unverified bypasses are "
                "disabled; an unresolved included server may be temporarily "
                "outside keen-pbr processing): {}",
                detail);
        } else if (
            generation.source ==
            InternalVpnServerGenerationSource::retained_previous) {
            Logger::instance().info(
                "Native VPN server inventory is temporarily inconclusive; "
                "retaining previously verified include-only bindings while "
                "dropping every unverified bypass: {}",
                detail);
        } else {
            Logger::instance().info(
                "Native VPN server inventory is temporarily unavailable; "
                "continuing with a conservative live-name policy while an "
                "authoritative refresh is pending (unverified bypasses remain "
                "disabled): {}",
                detail);
        }
        return {
            std::move(generation.effective_servers),
            authoritative_negative
                ? InternalVpnRuntimeResolutionState::authoritative_negative
                : generation.source ==
                          InternalVpnServerGenerationSource::retained_previous
                    ? InternalVpnRuntimeResolutionState::
                          retained_verified_includes
                    : InternalVpnRuntimeResolutionState::degraded,
            std::move(resolution.verified_includes_for_lkg),
            std::move(resolution.retain_verified_include_ndms_ids),
        };
    }
    return {
        std::move(resolution.effective_servers),
        InternalVpnRuntimeResolutionState::verified,
        std::move(resolution.verified_includes_for_lkg),
        std::move(resolution.retain_verified_include_ndms_ids),
    };
}

InternalVpnServiceRuntimeResolution
InternalVpnResolutionCache::resolve_services(
    const Config& config,
    const NdmsVpnServerServiceSnapshot& snapshot,
    const std::vector<DumpedInterface>& live_interfaces) const {
    if (!config_requires_internal_vpn_service_inventory(config)) {
        return {{}, InternalVpnRuntimeResolutionState::verified};
    }
    const auto route = config.route.value_or(RouteConfig{});
    const auto configured = route.internal_vpn_services.value_or(
        std::vector<InternalVpnService>{});
    const bool default_process_clients =
        internal_vpn_service_default_process_clients(config);
    auto resolution = resolve_internal_vpn_service_policies(
        configured,
        snapshot.catalog,
        snapshot.status == NdmsCatalogCacheStatus::fresh,
        default_process_clients,
        internal_vpn_inbound_observation(config, live_interfaces));
    auto generation = select_internal_vpn_service_generation(
        configured,
        resolution,
        verified_lkg_.snapshot_service_targets(),
        default_process_clients);
    refresh_internal_vpn_service_ingress_interfaces(
        generation.effective_targets, live_interfaces);

    InternalVpnRuntimeResolutionState state =
        InternalVpnRuntimeResolutionState::verified;
    if (!resolution.complete()) {
        std::string detail;
        for (const auto& issue : resolution.issues) {
            if (!detail.empty()) detail += "; ";
            detail += describe_internal_vpn_service_resolution_issue(issue);
        }
        const bool authoritative_negative = std::any_of(
            resolution.issues.begin(),
            resolution.issues.end(),
            [](const auto& issue) {
                return issue.error !=
                       InternalVpnServiceResolutionError::
                           catalog_not_authoritative;
            });
        if (authoritative_negative) {
            state = InternalVpnRuntimeResolutionState::authoritative_negative;
            Logger::instance().warn(
                "Native VPN service inventory is incomplete; every "
                "unverified source-pool bypass is disabled: {}",
                detail);
        } else if (
            generation.source ==
            InternalVpnServiceGenerationSource::retained_previous_includes) {
            state = InternalVpnRuntimeResolutionState::
                retained_verified_includes;
            Logger::instance().info(
                "Native VPN service inventory is temporarily unavailable; "
                "retaining only previously verified include pools: {}",
                detail);
        } else {
            state = InternalVpnRuntimeResolutionState::degraded;
            Logger::instance().info(
                "Native VPN service inventory is temporarily unavailable; "
                "no unverified source-pool bypass is active while an "
                "authoritative refresh is pending: {}",
                detail);
        }
    }

    return {
        std::move(generation.effective_targets),
        state,
        std::move(resolution.verified_includes_for_lkg),
        std::move(resolution.retain_verified_include_service_ids),
    };
}

void InternalVpnResolutionCache::update_verified_servers(
    const InternalVpnRuntimeResolution& resolution) noexcept {
    try {
        verified_lkg_.update_servers(resolution);
    } catch (const std::exception& error) {
        try {
            Logger::instance().warn(
                "Could not publish native VPN verified-binding cache: {}. "
                "The committed runtime generation remains active.",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().warn(
                "Could not publish native VPN verified-binding cache. "
                "The committed runtime generation remains active.");
        } catch (...) {
        }
    }
}

void InternalVpnResolutionCache::update_verified_service_targets(
    const InternalVpnServiceRuntimeResolution& resolution) noexcept {
    try {
        verified_lkg_.update_service_targets(resolution);
    } catch (const std::exception& error) {
        try {
            Logger::instance().warn(
                "Could not publish native VPN service verified-pool cache: "
                "{}. The committed runtime generation remains active.",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().warn(
                "Could not publish native VPN service verified-pool cache. "
                "The committed runtime generation remains active.");
        } catch (...) {
        }
    }
}

} // namespace keen_pbr3
