#include "internal_vpn_ingress_resolver.hpp"

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace keen_pbr3 {
namespace {

bool starts_with(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() &&
           value.compare(0U, prefix.size(), prefix) == 0;
}

bool has_decimal_suffix(
    std::string_view value,
    std::string_view prefix) {
    return value.size() > prefix.size() &&
           starts_with(value, prefix) &&
           std::all_of(
               value.begin() +
                   static_cast<std::ptrdiff_t>(prefix.size()),
               value.end(),
               [](const unsigned char character) {
                   return character >= '0' && character <= '9';
               });
}

struct ParsedNetwork {
    int family{AF_UNSPEC};
    std::array<std::uint8_t, 16> bytes{};
    std::uint8_t prefix{0};
};

std::optional<ParsedNetwork> parse_network(std::string_view value) {
    const auto slash = value.find('/');
    const auto address = std::string{
        value.substr(
            0U,
            slash == std::string_view::npos ? value.size() : slash)};
    ParsedNetwork result;
    result.family =
        address.find(':') == std::string::npos ? AF_INET : AF_INET6;
    const unsigned int max_prefix =
        result.family == AF_INET ? 32U : 128U;
    unsigned int prefix = max_prefix;
    if (slash != std::string_view::npos) {
        const auto prefix_text = value.substr(slash + 1U);
        if (prefix_text.empty() ||
            !std::all_of(
                prefix_text.begin(),
                prefix_text.end(),
                [](const unsigned char character) {
                    return character >= '0' && character <= '9';
                })) {
            return std::nullopt;
        }
        try {
            prefix = static_cast<unsigned int>(
                std::stoul(std::string{prefix_text}));
        } catch (...) {
            return std::nullopt;
        }
        if (prefix > max_prefix) {
            return std::nullopt;
        }
    }
    if (inet_pton(
            result.family,
            address.c_str(),
            result.bytes.data()) != 1) {
        return std::nullopt;
    }
    result.prefix = static_cast<std::uint8_t>(prefix);
    return result;
}

bool network_contains(
    const ParsedNetwork& network,
    const ParsedNetwork& candidate) {
    if (network.family != candidate.family) {
        return false;
    }
    const auto full_bytes = network.prefix / 8U;
    const auto partial_bits = network.prefix % 8U;
    for (std::size_t index = 0; index < full_bytes; ++index) {
        if (network.bytes[index] != candidate.bytes[index]) {
            return false;
        }
    }
    if (partial_bits == 0U) {
        return true;
    }
    const auto mask = static_cast<std::uint8_t>(
        0xffU << (8U - partial_bits));
    return
        (network.bytes[full_bytes] & mask) ==
        (candidate.bytes[full_bytes] & mask);
}

bool address_belongs_to_any_pool(
    const std::string& address,
    const std::vector<std::string>& pools) {
    const auto parsed_address = parse_network(address);
    if (!parsed_address) {
        return false;
    }
    return std::any_of(
        pools.begin(),
        pools.end(),
        [&parsed_address](const auto& pool) {
            const auto parsed_pool = parse_network(pool);
            return parsed_pool &&
                   network_contains(*parsed_pool, *parsed_address);
        });
}

bool interface_peer_belongs_to_target(
    const DumpedInterface& interface,
    const InternalVpnRuntimeTarget& target) {
    const auto any_address_matches = [](const auto& addresses,
                                        const auto& pools) {
        return std::any_of(
            addresses.begin(),
            addresses.end(),
            [&pools](const auto& address) {
                return address_belongs_to_any_pool(address, pools);
            });
    };
    return
        any_address_matches(
            interface.ipv4_peer_addresses,
            target.source_cidrs_v4) ||
        any_address_matches(
            interface.ipv6_peer_addresses,
            target.source_cidrs_v6);
}

bool is_ike_service(std::string_view stable_id) {
    return starts_with(stable_id, "ndms-crypto-map:ikev1:") ||
           starts_with(stable_id, "ndms-crypto-map:ikev2:");
}

bool is_l2tp_service(std::string_view stable_id) {
    return starts_with(stable_id, "ndms-crypto-map:l2tp:");
}

bool is_sstp_service(std::string_view stable_id) {
    return stable_id == "ndms-service:sstp-server";
}

bool is_server_peer_name(
    const InternalVpnRuntimeTarget& target,
    std::string_view interface) {
    if (is_l2tp_service(target.stable_id)) {
        return has_decimal_suffix(interface, "l2tp");
    }
    if (is_sstp_service(target.stable_id)) {
        return has_decimal_suffix(interface, "sstp");
    }
    // Keenetic's OpenConnect server interface ownership is not exposed by
    // the authoritative inventory yet. Fail closed instead of guessing from
    // oc*/tun* names or from a source address alone.
    return false;
}

bool is_fixed_ike_server_interface(std::string_view interface) {
    // KeeneticOS 5.x creates these two fixed internal XFRM devices for
    // remote-access IPsec. Do not generalize to xfrms*: future/client XFRM
    // devices must not silently acquire server privileges.
    return interface == "xfrms1" || interface == "xfrms2";
}

const DumpedInterface* find_interface(
    const std::vector<DumpedInterface>& interfaces,
    std::string_view name) {
    const auto it = std::find_if(
        interfaces.begin(),
        interfaces.end(),
        [name](const auto& interface) {
            return interface.name == name;
        });
    return it == interfaces.end() ? nullptr : &*it;
}

bool interface_has_master(
    const std::vector<DumpedInterface>& interfaces,
    std::string_view interface,
    std::string_view master) {
    const auto* found = find_interface(interfaces, interface);
    return found != nullptr &&
           found->master_interface.has_value() &&
           *found->master_interface == master;
}

std::optional<std::string> sstp_bridge_l3_interface(
    const InternalVpnRuntimeTarget& target,
    const std::vector<DumpedInterface>& interfaces) {
    // Keenetic terminates SSTP sessions on an isolated L2 bridge and joins it
    // to the LAN bridge through a veth pair:
    //
    //   sstpN -> sstp-bridge/sstp-peer-link
    //         -> sstp-br-link/bound brN -> L3 PREROUTING
    //
    // iptables/nft see the bound BridgeN kernel interface, not sstp-bridge,
    // as the routed input interface. The BridgeN -> brN mapping was already
    // verified against live NDMS inventory by the service resolver.
    if (!target.interface.has_value() ||
        find_interface(interfaces, *target.interface) == nullptr ||
        find_interface(interfaces, "sstp-bridge") == nullptr ||
        !interface_has_master(
            interfaces, "sstp-peer-link", "sstp-bridge") ||
        !interface_has_master(
            interfaces, "sstp-br-link", *target.interface)) {
        return std::nullopt;
    }
    return target.interface;
}

} // namespace

std::vector<std::string> resolve_internal_vpn_service_ingress_interfaces(
    const InternalVpnRuntimeTarget& target,
    const std::vector<DumpedInterface>& live_interfaces) {
    if (target.match_kind != InternalVpnRuntimeMatchKind::source_pool) {
        return {};
    }

    std::vector<std::string> result;
    const auto sstp_bridge_l3 =
        is_sstp_service(target.stable_id)
            ? sstp_bridge_l3_interface(target, live_interfaces)
            : std::nullopt;
    for (const auto& interface : live_interfaces) {
        if (is_ike_service(target.stable_id) &&
            is_fixed_ike_server_interface(interface.name)) {
            result.push_back(interface.name);
            continue;
        }
        if (is_server_peer_name(target, interface.name) &&
            interface_peer_belongs_to_target(interface, target)) {
            if (is_sstp_service(target.stable_id) &&
                interface.master_interface ==
                    std::optional<std::string>{"sstp-bridge"}) {
                if (sstp_bridge_l3 && target.process_clients) {
                    result.push_back(*sstp_bridge_l3);
                }
                // An enslaved SSTP peer never reaches L3 PREROUTING under its
                // own name. A source pool plus shared BridgeN is not enough to
                // prove per-packet SSTP ownership: a LAN host could spoof the
                // pool source. Until both firewall backends support a verified
                // physical bridge-port selector, process_clients=false fails
                // closed for bridged SSTP instead of installing that bypass.
            } else {
                result.push_back(interface.name);
            }
        }
    }
    // The bridge exists before the first client peer. Keep the verified L3
    // ingress stable across SSTP connect/disconnect cycles for processed
    // clients and resolver ACL generation.
    if (sstp_bridge_l3 && target.process_clients) {
        result.push_back(*sstp_bridge_l3);
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

void refresh_internal_vpn_service_ingress_interfaces(
    std::vector<InternalVpnRuntimeTarget>& targets,
    const std::vector<DumpedInterface>& live_interfaces) {
    for (auto& target : targets) {
        target.verified_ingress_interfaces =
            resolve_internal_vpn_service_ingress_interfaces(
                target, live_interfaces);
    }
}

bool internal_vpn_service_interface_may_affect_ingress(
    std::string_view interface) noexcept {
    return interface == "xfrms1" ||
           interface == "xfrms2" ||
           interface == "sstp-bridge" ||
           interface == "sstp-br-link" ||
           interface == "sstp-peer-link" ||
           has_decimal_suffix(interface, "l2tp") ||
           has_decimal_suffix(interface, "sstp");
}

} // namespace keen_pbr3
