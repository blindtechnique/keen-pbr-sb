#include "internal_vpn_server_resolver.hpp"

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <utility>

namespace keen_pbr3 {

namespace {

bool is_supported_kind(const NdmsTunnelInterface& tunnel) {
    switch (tunnel.kind) {
    case NdmsTunnelKind::wireguard:
    case NdmsTunnelKind::amnezia_wireguard:
    case NdmsTunnelKind::openvpn:
    case NdmsTunnelKind::ike:
    case NdmsTunnelKind::l2tp:
    case NdmsTunnelKind::sstp:
    case NdmsTunnelKind::openconnect:
        return true;
    case NdmsTunnelKind::http_proxy:
    case NdmsTunnelKind::https_proxy:
    case NdmsTunnelKind::socks5_proxy:
        return false;
    }
    return false;
}

bool runtime_interface_exists(
    const std::set<std::string>& runtime_names,
    const std::string& interface_name) {
    return !interface_name.empty() &&
           runtime_names.find(interface_name) != runtime_names.end();
}

InternalVpnServer resolved_copy(const InternalVpnServer& configured,
                                std::string kernel_interface) {
    auto resolved = configured;
    resolved.interface = std::move(kernel_interface);
    return resolved;
}

std::string policy_identity(const InternalVpnServer& server) {
    if (server.ndms_id.has_value()) {
        return "stable:" + *server.ndms_id;
    }
    return "legacy:" + server.interface;
}

} // namespace

InternalVpnServerResolution resolve_internal_vpn_server_policies(
    const std::vector<InternalVpnServer>& configured,
    const NdmsInterfaceCatalog& unresolved_catalog,
    bool catalog_authoritative,
    const std::vector<std::string>& runtime_interface_names) {
    InternalVpnServerResolution result;
    result.effective_servers.reserve(configured.size());

    const std::set<std::string> runtime_names(
        runtime_interface_names.begin(), runtime_interface_names.end());
    const auto catalog =
        resolve_ndms_kernel_names(unresolved_catalog, runtime_interface_names);

    std::map<std::string, const NdmsTunnelInterface*> tunnel_by_id;
    for (const auto& tunnel : catalog.tunnels) {
        tunnel_by_id.emplace(tunnel.id, &tunnel);
    }

    std::set<std::string> resolved_kernel_interfaces;
    std::set<std::string> safe_degraded_interfaces;
    for (const auto& server : configured) {
        std::optional<std::string> kernel_interface;
        const auto add_safe_degraded =
            [&](const std::string& interface_name) {
                if (!server.process_clients ||
                    !runtime_interface_exists(
                        runtime_names, interface_name) ||
                    !safe_degraded_interfaces.insert(interface_name).second) {
                    return;
                }
                result.safe_degraded_servers.push_back(
                    resolved_copy(server, interface_name));
            };

        if (!server.ndms_id.has_value()) {
            if (runtime_interface_exists(runtime_names, server.interface)) {
                kernel_interface = server.interface;
            } else {
                result.issues.push_back({
                    InternalVpnServerResolutionError::
                        legacy_interface_missing,
                    server.interface,
                    {},
                });
                continue;
            }
        } else {
            if (!catalog_authoritative) {
                add_safe_degraded(server.interface);
                if (server.process_clients) {
                    result.retain_verified_include_ndms_ids.push_back(
                        *server.ndms_id);
                }
                result.issues.push_back({
                    InternalVpnServerResolutionError::
                        catalog_not_authoritative,
                    server.interface,
                    *server.ndms_id,
                });
                continue;
            }

            const auto found = tunnel_by_id.find(*server.ndms_id);
            if (found == tunnel_by_id.end()) {
                result.issues.push_back({
                    InternalVpnServerResolutionError::stable_id_missing,
                    server.interface,
                    *server.ndms_id,
                });
                continue;
            } else {
                const auto& tunnel = *found->second;
                if (!is_supported_kind(tunnel)) {
                    result.issues.push_back({
                        InternalVpnServerResolutionError::unsupported_kind,
                        server.interface,
                        *server.ndms_id,
                    });
                    continue;
                }
                if (!tunnel.internal_vpn_server_candidate) {
                    result.issues.push_back({
                        InternalVpnServerResolutionError::unsupported_role,
                        server.interface,
                        *server.ndms_id,
                    });
                    continue;
                }

                kernel_interface = tunnel.kernel_name;
                if (!kernel_interface.has_value()) {
                    result.issues.push_back({
                        InternalVpnServerResolutionError::
                            kernel_interface_unresolved,
                        server.interface,
                        *server.ndms_id,
                    });
                    continue;
                }
            }
        }

        if (!resolved_kernel_interfaces.insert(*kernel_interface).second) {
            add_safe_degraded(*kernel_interface);
            result.issues.push_back({
                InternalVpnServerResolutionError::
                    duplicate_kernel_interface,
                *kernel_interface,
                server.ndms_id.value_or(std::string{}),
            });
            continue;
        }
        auto effective =
            resolved_copy(server, std::move(*kernel_interface));
        if (catalog_authoritative && effective.ndms_id.has_value() &&
            effective.process_clients) {
            result.verified_includes_for_lkg.push_back(effective);
        }
        if (effective.process_clients &&
            safe_degraded_interfaces.insert(effective.interface).second) {
            result.safe_degraded_servers.push_back(effective);
        }
        result.effective_servers.push_back(std::move(effective));
    }

    return result;
}

bool internal_vpn_server_policies_require_ndms_catalog(
    const std::vector<InternalVpnServer>& configured) noexcept {
    return std::any_of(
        configured.begin(),
        configured.end(),
        [](const InternalVpnServer& server) {
            return server.ndms_id.has_value();
        });
}

InternalVpnServerGeneration select_internal_vpn_server_generation(
    const std::vector<InternalVpnServer>& configured,
    const InternalVpnServerResolution& candidate,
    const std::vector<InternalVpnServer>& previous_effective) {
    if (candidate.complete()) {
        return {
            candidate.effective_servers,
            InternalVpnServerGenerationSource::verified_candidate,
        };
    }

    std::set<std::string> configured_includes;
    for (const auto& server : configured) {
        if (server.ndms_id.has_value() && server.process_clients) {
            configured_includes.insert(policy_identity(server));
        }
    }

    std::set<std::string> retainable_stable_identities;
    for (const auto& ndms_id :
         candidate.retain_verified_include_ndms_ids) {
        retainable_stable_identities.insert("stable:" + ndms_id);
    }

    std::vector<InternalVpnServer> selected;
    std::set<std::string> selected_identities;
    std::set<std::string> selected_interfaces;
    bool retained_verified_include = false;
    for (const auto& previous : previous_effective) {
        if (!previous.process_clients || !previous.ndms_id.has_value() ||
            configured_includes.find(policy_identity(previous)) ==
                configured_includes.end() ||
            retainable_stable_identities.find(policy_identity(previous)) ==
                retainable_stable_identities.end() ||
            selected_interfaces.find(previous.interface) !=
                selected_interfaces.end()) {
            continue;
        }
        selected_identities.insert(policy_identity(previous));
        selected_interfaces.insert(previous.interface);
        selected.push_back(previous);
        retained_verified_include = true;
    }

    // Add conservative live-name fallbacks only after verified bindings. This
    // prevents a reused old kernel name from shadowing the verified current
    // interface for the same stable identity.
    for (const auto& server : candidate.safe_degraded_servers) {
        if (selected_identities.find(policy_identity(server)) !=
                selected_identities.end() ||
            selected_interfaces.find(server.interface) !=
                selected_interfaces.end()) {
            continue;
        }
        selected_identities.insert(policy_identity(server));
        selected_interfaces.insert(server.interface);
        selected.push_back(server);
    }

    return {
        std::move(selected),
        retained_verified_include
            ? InternalVpnServerGenerationSource::retained_previous
            : InternalVpnServerGenerationSource::safe_degraded_candidate,
    };
}

std::vector<InternalVpnServer> merge_internal_vpn_verified_includes_lkg(
    const std::vector<InternalVpnServer>& previous,
    const std::vector<InternalVpnServer>& freshly_verified,
    const std::vector<std::string>& retain_ndms_ids) {
    std::vector<InternalVpnServer> next = freshly_verified;
    std::set<std::string> retained_ids(
        retain_ndms_ids.begin(), retain_ndms_ids.end());
    std::set<std::string> selected_ids;
    std::set<std::string> selected_interfaces;
    for (const auto& server : next) {
        if (server.ndms_id.has_value()) {
            selected_ids.insert(*server.ndms_id);
        }
        selected_interfaces.insert(server.interface);
    }
    for (const auto& server : previous) {
        if (!server.process_clients || !server.ndms_id.has_value() ||
            retained_ids.find(*server.ndms_id) == retained_ids.end() ||
            selected_ids.find(*server.ndms_id) != selected_ids.end() ||
            selected_interfaces.find(server.interface) !=
                selected_interfaces.end()) {
            continue;
        }
        selected_ids.insert(*server.ndms_id);
        selected_interfaces.insert(server.interface);
        next.push_back(server);
    }
    return next;
}

std::string describe_internal_vpn_server_resolution_issue(
    const InternalVpnServerResolutionIssue& issue) {
    const auto identity = issue.ndms_id.empty()
        ? "'" + issue.interface + "'"
        : "NDMS id '" + issue.ndms_id + "'";
    switch (issue.error) {
    case InternalVpnServerResolutionError::legacy_interface_missing:
        return "Native VPN server interface " + identity +
               " does not exist in the live kernel inventory";
    case InternalVpnServerResolutionError::catalog_not_authoritative:
        return "Native VPN server " + identity +
               " cannot be rebound until a fresh NDMS inventory is available";
    case InternalVpnServerResolutionError::stable_id_missing:
        return "Native VPN server " + identity +
               " is missing from the current NDMS inventory";
    case InternalVpnServerResolutionError::unsupported_kind:
        return "Native VPN server " + identity +
               " is not a supported ingress VPN interface";
    case InternalVpnServerResolutionError::unsupported_role:
        return "Native VPN interface " + identity +
               " is not verified as a server";
    case InternalVpnServerResolutionError::kernel_interface_unresolved:
        return "Native VPN server " + identity +
               " has no verified live kernel interface";
    case InternalVpnServerResolutionError::duplicate_kernel_interface:
        return "Native VPN server " + identity +
               " resolves to duplicate kernel interface '" +
               issue.interface + "'";
    }
    return "Native VPN server resolution failed";
}

} // namespace keen_pbr3
