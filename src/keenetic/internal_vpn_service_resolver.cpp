#include "internal_vpn_service_resolver.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <tuple>
#include <utility>

namespace keen_pbr3 {
namespace {

InternalVpnRuntimeTarget resolved_target(
    const InternalVpnService& configured,
    const NdmsVpnServerService& service) {
    InternalVpnRuntimeTarget target;
    target.stable_id = service.id;
    target.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    target.process_clients = configured.process_clients;
    target.bound_interface_id = service.bound_interface_id;
    target.source_cidrs_v4 = service.source_cidrs_v4;
    target.source_cidrs_v6 = service.source_cidrs_v6;
    return target;
}

bool target_has_source_pool(
    const InternalVpnRuntimeTarget& target) {
    return target.match_kind ==
               InternalVpnRuntimeMatchKind::source_pool &&
           (!target.source_cidrs_v4.empty() ||
            !target.source_cidrs_v6.empty());
}

struct ParsedCidr {
    int family{AF_UNSPEC};
    std::array<std::uint8_t, 16> bytes{};
    std::uint8_t prefix{0};
    std::size_t size{0};
};

std::optional<ParsedCidr> parse_cidr(
    const std::string& value,
    bool require_canonical_network = true) {
    const auto slash = value.find('/');
    if (slash == std::string::npos ||
        value.find('/', slash + 1U) != std::string::npos) {
        return std::nullopt;
    }
    ParsedCidr result;
    const auto address = value.substr(0, slash);
    in_addr ipv4{};
    in6_addr ipv6{};
    if (inet_pton(AF_INET, address.c_str(), &ipv4) == 1) {
        result.family = AF_INET;
        result.size = 4U;
        std::copy_n(
            reinterpret_cast<const std::uint8_t*>(&ipv4),
            result.size,
            result.bytes.begin());
    } else if (
        inet_pton(AF_INET6, address.c_str(), &ipv6) == 1) {
        result.family = AF_INET6;
        result.size = 16U;
        std::copy_n(
            reinterpret_cast<const std::uint8_t*>(&ipv6),
            result.size,
            result.bytes.begin());
    } else {
        return std::nullopt;
    }

    unsigned int prefix = 0U;
    const auto prefix_text = value.substr(slash + 1U);
    const auto parsed = std::from_chars(
        prefix_text.data(),
        prefix_text.data() + prefix_text.size(),
        prefix);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != prefix_text.data() + prefix_text.size() ||
        prefix > result.size * 8U) {
        return std::nullopt;
    }
    result.prefix = static_cast<std::uint8_t>(prefix);

    for (std::size_t bit = prefix; bit < result.size * 8U; ++bit) {
        const auto byte = bit / 8U;
        const auto mask = static_cast<std::uint8_t>(
            1U << (7U - (bit % 8U)));
        if (require_canonical_network &&
            (result.bytes[byte] & mask) != 0U) {
            return std::nullopt;
        }
        result.bytes[byte] &= static_cast<std::uint8_t>(~mask);
    }
    return result;
}

std::optional<std::vector<ParsedCidr>> parsed_pool(
    const InternalVpnRuntimeTarget& target) {
    std::vector<ParsedCidr> result;
    result.reserve(
        target.source_cidrs_v4.size() +
        target.source_cidrs_v6.size());
    for (const auto* family :
         {&target.source_cidrs_v4, &target.source_cidrs_v6}) {
        for (const auto& value : *family) {
            auto parsed = parse_cidr(value);
            if (!parsed) return std::nullopt;
            result.push_back(*parsed);
        }
    }
    return result;
}

bool cidrs_overlap(
    const ParsedCidr& left,
    const ParsedCidr& right) {
    if (left.family != right.family) return false;
    const auto shared_prefix =
        std::min(left.prefix, right.prefix);
    for (std::size_t bit = 0U; bit < shared_prefix; ++bit) {
        const auto byte = bit / 8U;
        const auto mask = static_cast<std::uint8_t>(
            1U << (7U - (bit % 8U)));
        if ((left.bytes[byte] & mask) !=
            (right.bytes[byte] & mask)) {
            return false;
        }
    }
    return true;
}

bool pool_overlaps(
    const std::vector<ParsedCidr>& selected,
    const std::vector<ParsedCidr>& candidate) {
    return std::any_of(
        candidate.begin(),
        candidate.end(),
        [&selected](const auto& right) {
            return std::any_of(
                selected.begin(),
                selected.end(),
                [&right](const auto& left) {
                    return cidrs_overlap(left, right);
                });
        });
}

bool is_host_only_interface_address(const std::string& cidr) {
    const auto slash = cidr.rfind('/');
    if (slash == std::string::npos) return false;
    const auto prefix = cidr.substr(slash + 1U);
    return (cidr.find(':') == std::string::npos && prefix == "32") ||
           (cidr.find(':') != std::string::npos && prefix == "128");
}

bool has_decimal_suffix(
    const std::string& value,
    std::string_view prefix) {
    return value.size() > prefix.size() &&
           value.compare(0U, prefix.size(), prefix) == 0 &&
           std::all_of(
               value.begin() + static_cast<std::ptrdiff_t>(prefix.size()),
               value.end(),
               [](const char character) {
                   return character >= '0' && character <= '9';
               });
}

std::optional<std::string> verified_bound_kernel_interface(
    const std::optional<std::string>& bound_interface_id,
    const std::set<std::string>& verified_interfaces) {
    if (!bound_interface_id || bound_interface_id->empty()) {
        return std::nullopt;
    }
    if (verified_interfaces.find(*bound_interface_id) !=
        verified_interfaces.end()) {
        return *bound_interface_id;
    }

    // NDMS running-config uses firmware object names while Netlink exposes
    // kernel names. Keep this mapping deliberately small and deterministic:
    // a candidate is accepted only when that exact kernel interface exists in
    // the current Netlink dump.
    const std::array<
        std::pair<std::string_view, std::string_view>,
        3> numbered_mappings{{
        {"Bridge", "br"},
        {"Wireguard", "nwg"},
        {"OpenVPN", "ovpn"},
    }};
    for (const auto& [firmware_prefix, kernel_prefix] :
         numbered_mappings) {
        if (!has_decimal_suffix(
                *bound_interface_id, firmware_prefix)) {
            continue;
        }
        const auto candidate =
            std::string{kernel_prefix} +
            bound_interface_id->substr(firmware_prefix.size());
        if (verified_interfaces.find(candidate) !=
            verified_interfaces.end()) {
            return candidate;
        }
    }
    return std::nullopt;
}

std::optional<NdmsTunnelKind> legacy_tunnel_kind(
    NdmsVpnServerServiceKind kind) {
    switch (kind) {
    case NdmsVpnServerServiceKind::l2tp:
        return NdmsTunnelKind::l2tp;
    case NdmsVpnServerServiceKind::ikev1:
    case NdmsVpnServerServiceKind::ikev2:
        return NdmsTunnelKind::ike;
    case NdmsVpnServerServiceKind::sstp:
        return NdmsTunnelKind::sstp;
    case NdmsVpnServerServiceKind::openconnect:
        return NdmsTunnelKind::openconnect;
    }
    return std::nullopt;
}

std::optional<NdmsTunnelKind> unresolved_legacy_tunnel_kind(
    std::string_view service_id) {
    const auto starts_with =
        [service_id](std::string_view prefix) {
            return service_id.size() >= prefix.size() &&
                   service_id.compare(
                       0U, prefix.size(), prefix) == 0;
        };
    if (starts_with("ndms-crypto-map:l2tp:")) {
        return NdmsTunnelKind::l2tp;
    }
    if (starts_with("ndms-crypto-map:ikev1:") ||
        starts_with("ndms-crypto-map:ikev2:")) {
        return NdmsTunnelKind::ike;
    }
    if (service_id == "ndms-service:sstp-server") {
        return NdmsTunnelKind::sstp;
    }
    if (service_id == "ndms-service:oc-server") {
        return NdmsTunnelKind::openconnect;
    }
    return std::nullopt;
}

} // namespace

bool internal_vpn_service_default_process_clients(
    const Config& config) noexcept {
    const auto route = config.route.value_or(RouteConfig{});
    return !route.inbound_interfaces.has_value() ||
           route.inbound_interfaces->empty();
}

std::vector<InternalVpnServer>
prefer_authoritative_internal_vpn_service_inventory(
    const std::vector<InternalVpnServer>& interface_servers,
    const NdmsInterfaceCatalog& interface_catalog,
    const NdmsVpnServerServiceCatalog& service_catalog,
    bool service_catalog_authoritative) {
    if (!service_catalog_authoritative ||
        !service_catalog.firmware_available ||
        (service_catalog.services.empty() &&
         service_catalog.unresolved_service_ids.empty())) {
        return interface_servers;
    }

    std::set<NdmsTunnelKind> authoritative_kinds;
    std::set<std::string> authoritative_bound_interfaces;
    for (const auto& service : service_catalog.services) {
        if (const auto kind = legacy_tunnel_kind(service.kind)) {
            authoritative_kinds.insert(*kind);
        }
        if (service.bound_interface_id.has_value() &&
            !service.bound_interface_id->empty()) {
            authoritative_bound_interfaces.insert(
                *service.bound_interface_id);
        }
    }
    for (const auto& service_id :
         service_catalog.unresolved_service_ids) {
        if (const auto kind =
                unresolved_legacy_tunnel_kind(service_id)) {
            authoritative_kinds.insert(*kind);
        }
    }

    std::map<std::string, const NdmsTunnelInterface*> tunnel_by_id;
    for (const auto& tunnel : interface_catalog.tunnels) {
        tunnel_by_id.emplace(tunnel.id, &tunnel);
    }

    std::vector<InternalVpnServer> result;
    result.reserve(interface_servers.size());
    for (const auto& server : interface_servers) {
        bool superseded =
            authoritative_bound_interfaces.find(server.interface) !=
            authoritative_bound_interfaces.end();
        if (!superseded && server.ndms_id.has_value()) {
            const auto found = tunnel_by_id.find(*server.ndms_id);
            superseded =
                found != tunnel_by_id.end() &&
                authoritative_kinds.find(found->second->kind) !=
                    authoritative_kinds.end();
        }
        if (!superseded) {
            result.push_back(server);
        }
    }
    return result;
}

std::vector<std::string> internal_vpn_protected_inbound_cidrs(
    const Config& config,
    const std::vector<DumpedInterface>& interfaces) {
    const auto observation =
        internal_vpn_inbound_observation(config, interfaces);
    std::vector<std::string> result;
    result.reserve(observation.protected_networks.size());
    for (const auto& network : observation.protected_networks) {
        result.push_back(network.cidr);
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

InternalVpnInboundObservation internal_vpn_inbound_observation(
    const Config& config,
    const std::vector<DumpedInterface>& interfaces) {
    const auto route = config.route.value_or(RouteConfig{});
    const bool explicit_allowlist =
        route.inbound_interfaces.has_value() &&
        !route.inbound_interfaces->empty();
    std::set<std::string> selected_interfaces;
    if (explicit_allowlist) {
        selected_interfaces.insert(
            route.inbound_interfaces->begin(),
            route.inbound_interfaces->end());
    }

    InternalVpnInboundObservation result;
    for (const auto& interface : interfaces) {
        if (!interface.name.empty()) {
            result.verified_interfaces.push_back(interface.name);
        }
        if (explicit_allowlist &&
            selected_interfaces.find(interface.name) ==
                selected_interfaces.end()) {
            continue;
        }
        if (!explicit_allowlist && interface.name == "lo") {
            continue;
        }

        const auto append = [&](const std::vector<std::string>& addresses) {
            for (const auto& address : addresses) {
                if (!explicit_allowlist &&
                    is_host_only_interface_address(address)) {
                    continue;
                }
                result.protected_networks.push_back(
                    {interface.name, address});
            }
        };
        append(interface.ipv4_addresses);
        append(interface.ipv6_addresses);
    }
    std::sort(
        result.verified_interfaces.begin(),
        result.verified_interfaces.end());
    result.verified_interfaces.erase(
        std::unique(
            result.verified_interfaces.begin(),
            result.verified_interfaces.end()),
        result.verified_interfaces.end());
    std::sort(
        result.protected_networks.begin(),
        result.protected_networks.end(),
        [](const auto& left, const auto& right) {
            return std::tie(left.interface, left.cidr) <
                   std::tie(right.interface, right.cidr);
        });
    result.protected_networks.erase(
        std::unique(
            result.protected_networks.begin(),
            result.protected_networks.end(),
            [](const auto& left, const auto& right) {
                return left.interface == right.interface &&
                       left.cidr == right.cidr;
            }),
        result.protected_networks.end());
    return result;
}

InternalVpnServiceResolution resolve_internal_vpn_service_policies(
    const std::vector<InternalVpnService>& configured,
    const NdmsVpnServerServiceCatalog& catalog,
    bool catalog_authoritative,
    bool default_process_clients,
    const std::vector<std::string>& protected_inbound_cidrs) {
    InternalVpnInboundObservation observation;
    observation.protected_networks.reserve(
        protected_inbound_cidrs.size());
    for (const auto& cidr : protected_inbound_cidrs) {
        observation.protected_networks.push_back({"", cidr});
    }
    return resolve_internal_vpn_service_policies(
        configured,
        catalog,
        catalog_authoritative,
        default_process_clients,
        observation);
}

InternalVpnServiceResolution resolve_internal_vpn_service_policies(
    const std::vector<InternalVpnService>& configured,
    const NdmsVpnServerServiceCatalog& catalog,
    bool catalog_authoritative,
    bool default_process_clients,
    const InternalVpnInboundObservation& inbound_observation) {
    InternalVpnServiceResolution result;
    result.effective_targets.reserve(catalog.services.size());

    std::map<std::string, const NdmsVpnServerService*> service_by_id;
    for (const auto& service : catalog.services) {
        service_by_id.emplace(service.id, &service);
    }

    std::set<std::string> configured_ids;
    std::map<std::string, bool> overrides;
    struct ParsedProtectedNetwork {
        std::string interface;
        ParsedCidr cidr;
    };
    std::vector<ParsedProtectedNetwork> protected_cidrs;
    protected_cidrs.reserve(
        inbound_observation.protected_networks.size());
    for (const auto& network : inbound_observation.protected_networks) {
        if (auto parsed = parse_cidr(
                network.cidr,
                /*require_canonical_network=*/false)) {
            protected_cidrs.push_back(
                {network.interface, *parsed});
        }
    }
    const std::set<std::string> verified_interfaces(
        inbound_observation.verified_interfaces.begin(),
        inbound_observation.verified_interfaces.end());
    const std::set<std::string> unresolved_service_ids(
        catalog.unresolved_service_ids.begin(),
        catalog.unresolved_service_ids.end());
    for (const auto& policy : configured) {
        if (!configured_ids.insert(policy.service_id).second) {
            result.issues.push_back({
                InternalVpnServiceResolutionError::duplicate_service_id,
                policy.service_id,
            });
            continue;
        }
        overrides.emplace(policy.service_id, policy.process_clients);
    }

    if (!catalog_authoritative || !catalog.firmware_available) {
        result.retain_all_verified_includes = true;
        result.issues.push_back({
            InternalVpnServiceResolutionError::catalog_not_authoritative,
            {},
        });
        return result;
    }

    for (const auto& [service_id, process_clients] : overrides) {
        (void)process_clients;
        const auto found = service_by_id.find(service_id);
        if (found == service_by_id.end()) {
            if (unresolved_service_ids.find(service_id) !=
                unresolved_service_ids.end()) {
                if (process_clients) {
                    result.retain_verified_include_service_ids.push_back(
                        service_id);
                }
                result.issues.push_back({
                    InternalVpnServiceResolutionError::
                        source_pool_unresolved,
                    service_id,
                });
                continue;
            }
            result.issues.push_back({
                InternalVpnServiceResolutionError::stable_id_missing,
                service_id,
            });
            continue;
        }
        if (!found->second->enabled) {
            result.issues.push_back({
                InternalVpnServiceResolutionError::service_disabled,
                service_id,
            });
        }
    }

    struct Candidate {
        InternalVpnRuntimeTarget target;
        std::vector<ParsedCidr> cidrs;
    };
    std::vector<Candidate> candidates;
    candidates.reserve(catalog.services.size());
    for (const auto& service : catalog.services) {
        if (!service.enabled) {
            continue;
        }
        InternalVpnService policy;
        policy.process_clients =
            overrides.count(service.id) != 0U
                ? overrides.at(service.id)
                : default_process_clients;
        policy.service_id = service.id;
        auto target = resolved_target(policy, service);
        target.interface = verified_bound_kernel_interface(
            target.bound_interface_id, verified_interfaces);
        const auto target_cidrs = parsed_pool(target);
        if (!target_has_source_pool(target) || !target_cidrs) {
            result.issues.push_back({
                InternalVpnServiceResolutionError::
                    source_pool_unresolved,
                policy.service_id,
            });
            continue;
        }
        const bool overlaps_foreign_inbound = std::any_of(
            protected_cidrs.begin(),
            protected_cidrs.end(),
            [&target, &target_cidrs](const auto& protected_network) {
                if (target.interface.has_value() &&
                    protected_network.interface == *target.interface) {
                    return false;
                }
                return std::any_of(
                    target_cidrs->begin(),
                    target_cidrs->end(),
                    [&protected_network](const auto& candidate) {
                        return cidrs_overlap(
                            protected_network.cidr, candidate);
                    });
            });
        if (overlaps_foreign_inbound) {
            result.issues.push_back({
                InternalVpnServiceResolutionError::
                    source_pool_overlaps_inbound_network,
                policy.service_id,
            });
            continue;
        }
        if (!target.process_clients && !target.interface.has_value()) {
            result.issues.push_back({
                InternalVpnServiceResolutionError::
                    source_pool_bypass_unverified_ingress,
                policy.service_id,
            });
            continue;
        }
        candidates.push_back({
            std::move(target),
            std::move(*target_cidrs),
        });
    }

    for (const auto& service_id : unresolved_service_ids) {
        if (configured_ids.find(service_id) != configured_ids.end()) {
            continue;
        }
        if (default_process_clients) {
            result.retain_verified_include_service_ids.push_back(
                service_id);
        }
        result.issues.push_back({
            InternalVpnServiceResolutionError::source_pool_unresolved,
            service_id,
        });
    }
    std::sort(
        result.retain_verified_include_service_ids.begin(),
        result.retain_verified_include_service_ids.end());
    result.retain_verified_include_service_ids.erase(
        std::unique(
            result.retain_verified_include_service_ids.begin(),
            result.retain_verified_include_service_ids.end()),
        result.retain_verified_include_service_ids.end());

    std::vector<bool> conflicted(candidates.size(), false);
    for (std::size_t left = 0U; left < candidates.size(); ++left) {
        for (std::size_t right = left + 1U;
             right < candidates.size();
             ++right) {
            if (pool_overlaps(
                    candidates[left].cidrs,
                    candidates[right].cidrs)) {
                conflicted[left] = true;
                conflicted[right] = true;
            }
        }
    }

    for (std::size_t index = 0U; index < candidates.size(); ++index) {
        auto& target = candidates[index].target;
        if (conflicted[index]) {
            result.issues.push_back({
                InternalVpnServiceResolutionError::
                    overlapping_source_pool,
                target.stable_id,
            });
            continue;
        }
        if (target.process_clients) {
            result.verified_includes_for_lkg.push_back(target);
        }
        result.effective_targets.push_back(std::move(target));
    }
    return result;
}

InternalVpnServiceGeneration select_internal_vpn_service_generation(
    const std::vector<InternalVpnService>& configured,
    const InternalVpnServiceResolution& candidate,
    const std::vector<InternalVpnRuntimeTarget>& previous_verified_includes,
    bool default_process_clients) {
    if (candidate.complete()) {
        return {
            candidate.effective_targets,
            InternalVpnServiceGenerationSource::verified_candidate,
        };
    }
    if (!candidate.retain_all_verified_includes &&
        candidate.retain_verified_include_service_ids.empty()) {
        return {
            candidate.effective_targets,
            candidate.effective_targets.empty()
                ? InternalVpnServiceGenerationSource::empty_fail_closed
                : InternalVpnServiceGenerationSource::
                      verified_partial_candidate,
        };
    }

    std::map<std::string, bool> overrides;
    for (const auto& policy : configured) {
        overrides.emplace(policy.service_id, policy.process_clients);
    }
    std::set<std::string> retain_ids(
        candidate.retain_verified_include_service_ids.begin(),
        candidate.retain_verified_include_service_ids.end());

    std::vector<InternalVpnRuntimeTarget> retained =
        candidate.effective_targets;
    std::set<std::string> selected_ids;
    std::vector<ParsedCidr> selected_cidrs;
    for (const auto& target : retained) {
        const auto target_cidrs = parsed_pool(target);
        if (!target_cidrs) continue;
        selected_ids.insert(target.stable_id);
        selected_cidrs.insert(
            selected_cidrs.end(),
            target_cidrs->begin(),
            target_cidrs->end());
    }
    for (const auto& target : previous_verified_includes) {
        const auto target_cidrs = parsed_pool(target);
        if (!target.process_clients ||
            !target_has_source_pool(target) ||
            !target_cidrs ||
            !(overrides.count(target.stable_id) != 0U
                  ? overrides.at(target.stable_id)
                  : default_process_clients) ||
            (!candidate.retain_all_verified_includes &&
             retain_ids.find(target.stable_id) == retain_ids.end()) ||
            !selected_ids.insert(target.stable_id).second ||
            pool_overlaps(selected_cidrs, *target_cidrs)) {
            continue;
        }
        selected_cidrs.insert(
            selected_cidrs.end(),
            target_cidrs->begin(),
            target_cidrs->end());
        retained.push_back(target);
    }
    const bool retained_previous =
        retained.size() > candidate.effective_targets.size();
    const auto source = retained.empty()
        ? InternalVpnServiceGenerationSource::empty_fail_closed
        : (candidate.effective_targets.empty() && retained_previous
               ? InternalVpnServiceGenerationSource::
                     retained_previous_includes
               : InternalVpnServiceGenerationSource::
                     verified_partial_candidate);
    return {std::move(retained), source};
}

std::vector<InternalVpnRuntimeTarget>
merge_internal_vpn_service_verified_includes_lkg(
    const std::vector<InternalVpnRuntimeTarget>& previous,
    const std::vector<InternalVpnRuntimeTarget>& freshly_verified,
    const std::vector<std::string>& retain_service_ids) {
    std::vector<InternalVpnRuntimeTarget> result;
    std::set<std::string> selected_ids;
    std::vector<ParsedCidr> selected_cidrs;

    for (const auto& target : freshly_verified) {
        const auto target_cidrs = parsed_pool(target);
        if (!target.process_clients ||
            !target_has_source_pool(target) ||
            !target_cidrs ||
            !selected_ids.insert(target.stable_id).second ||
            pool_overlaps(selected_cidrs, *target_cidrs)) {
            continue;
        }
        selected_cidrs.insert(
            selected_cidrs.end(),
            target_cidrs->begin(),
            target_cidrs->end());
        result.push_back(target);
    }

    const std::set<std::string> retain_ids(
        retain_service_ids.begin(), retain_service_ids.end());
    for (const auto& target : previous) {
        const auto target_cidrs = parsed_pool(target);
        if (!target.process_clients ||
            !target_has_source_pool(target) ||
            !target_cidrs ||
            retain_ids.find(target.stable_id) == retain_ids.end() ||
            !selected_ids.insert(target.stable_id).second ||
            pool_overlaps(selected_cidrs, *target_cidrs)) {
            continue;
        }
        selected_cidrs.insert(
            selected_cidrs.end(),
            target_cidrs->begin(),
            target_cidrs->end());
        result.push_back(target);
    }
    return result;
}

std::string describe_internal_vpn_service_resolution_issue(
    const InternalVpnServiceResolutionIssue& issue) {
    const auto identity = "NDMS VPN service '" + issue.service_id + "'";
    switch (issue.error) {
    case InternalVpnServiceResolutionError::catalog_not_authoritative:
        return identity +
               " cannot be rebound until a fresh NDMS service inventory is available";
    case InternalVpnServiceResolutionError::stable_id_missing:
        return identity + " is missing from the current NDMS inventory";
    case InternalVpnServiceResolutionError::service_disabled:
        return identity + " is disabled in KeeneticOS";
    case InternalVpnServiceResolutionError::source_pool_unresolved:
        return identity + " has no verified client source pool";
    case InternalVpnServiceResolutionError::duplicate_service_id:
        return identity + " is configured more than once";
    case InternalVpnServiceResolutionError::overlapping_source_pool:
        return identity + " overlaps another configured VPN client source pool";
    case InternalVpnServiceResolutionError::
        source_pool_overlaps_inbound_network:
        return identity +
               " overlaps a configured inbound interface network";
    case InternalVpnServiceResolutionError::
        source_pool_bypass_unverified_ingress:
        return identity +
               " cannot bypass routing without a verified ingress interface";
    }
    return "Native VPN service resolution failed";
}

} // namespace keen_pbr3
