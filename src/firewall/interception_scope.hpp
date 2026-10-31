#pragma once

#include "firewall.hpp"
#include "../keenetic/internal_vpn_runtime_target.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <tuple>

namespace keen_pbr3 {

inline bool interception_interface_valid(const std::string& name) {
    return !name.empty() && name.size() <= 15 && name != "lo" && name.front() != '-' &&
        std::all_of(name.begin(), name.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':';
        });
}

inline std::optional<std::string> interception_prefix(const std::string& input, uint8_t family) {
    if (input.empty() || input.size() > 64 || (family != 4 && family != 6)) return {};
    const auto slash = input.find('/');
    const auto host = input.substr(0, slash);
    const unsigned bits = family == 4 ? 32 : 128;
    unsigned prefix = bits;
    if (slash != std::string::npos) {
        const auto suffix = input.substr(slash + 1);
        if (suffix.empty() || suffix.size() > 3 ||
            !std::all_of(suffix.begin(), suffix.end(), [](char c) { return c >= '0' && c <= '9'; })) return {};
        prefix = 0;
        for (char c : suffix) prefix = prefix * 10 + static_cast<unsigned>(c - '0');
        if (prefix > bits) return {};
    }
    std::array<unsigned char, 16> address{};
    const int af = family == 4 ? AF_INET : AF_INET6;
    if (inet_pton(af, host.c_str(), address.data()) != 1) return {};
    for (unsigned bit = prefix; bit < bits; ++bit)
        address[bit / 8] &= static_cast<unsigned char>(~(1U << (7 - bit % 8)));
    char text[INET6_ADDRSTRLEN]{};
    if (!inet_ntop(af, address.data(), text, sizeof(text))) return {};
    return std::string(text) + "/" + std::to_string(prefix);
}

// Empty allowlist never means WAN capture. Native additions must come from
// verified runtime inventory, not persisted pool guesses. DNS REDIRECT
// exceptions are not capture exceptions: learning never changes the resolver.
inline InterceptionClientScope interception_client_scope(
    const FirewallGlobalPrefilter& scope,
    const std::vector<InternalVpnRuntimeTarget>& verified_targets = {}, bool ipv6 = true) {
    InterceptionClientScope result;
    const auto add_interface = [&](auto& selectors, const std::string& name) {
        if (!interception_interface_valid(name)) return;
        selectors.push_back({4, name, {}});
        if (ipv6) selectors.push_back({6, name, {}});
    };
    const auto add_pool = [&](auto& selectors, const std::string& name,
                              const std::string& cidr, uint8_t family, bool exclude) {
        if (!interception_interface_valid(name) || (family == 6 && !ipv6)) return;
        const auto prefix = interception_prefix(cidr, family);
        // Invalid exclusions omit that interface/family; invalid inclusions
        // cannot become a wildcard. Native /0 is not client-pool authority.
        if (!prefix) { if (exclude) selectors.push_back({family, name, {}}); return; }
        const bool all = *prefix == "0.0.0.0/0" || *prefix == "::/0";
        if (all && !exclude) return;
        selectors.push_back({family, name, all ? "" : *prefix});
    };
    if (scope.inbound_interfaces)
        for (const auto& name : *scope.inbound_interfaces) add_interface(result.include, name);
    for (const auto& name : scope.bypass_inbound_interfaces) add_interface(result.exclude, name);
    const auto exclusions = [&](const auto& selectors, uint8_t family) {
        for (const auto& selector : selectors)
            add_pool(result.exclude, selector.interface, selector.cidr, family, true);
    };
    exclusions(scope.bypass_source_selectors_v4, 4);
    exclusions(scope.bypass_source_selectors_v6, 6);
    // The ingress physdev selector cannot be reused on a DNS reply. Exclude
    // its pool on the shared bridge, not the entire bridge or all LAN clients.
    exclusions(scope.bypass_bridge_source_selectors_v4, 4);
    exclusions(scope.bypass_bridge_source_selectors_v6, 6);
    for (const auto& target : verified_targets) {
        auto& selectors = target.process_clients ? result.include : result.exclude;
        if (target.match_kind == InternalVpnRuntimeMatchKind::interface) {
            if (target.interface) add_interface(selectors, *target.interface);
            continue;
        }
        for (const auto& name : target.verified_ingress_interfaces) {
            for (const auto& cidr : target.source_cidrs_v4)
                add_pool(selectors, name, cidr, 4, !target.process_clients);
            for (const auto& cidr : target.source_cidrs_v6)
                add_pool(selectors, name, cidr, 6, !target.process_clients);
        }
        if (!target.process_clients) for (const auto& ingress : target.verified_bridge_ingress_interfaces) {
            for (const auto& cidr : target.source_cidrs_v4)
                add_pool(result.exclude, ingress.interface, cidr, 4, true);
            for (const auto& cidr : target.source_cidrs_v6)
                add_pool(result.exclude, ingress.interface, cidr, 6, true);
        }
        // A bridge binding alone cannot authorize capture of the whole LAN.
        // Bridged clients require an explicitly selected bridge for now.
    }
    const auto normalize = [](auto& selectors) {
        const auto key = [](const auto& s) { return std::tie(s.family, s.interface, s.cidr); };
        std::sort(selectors.begin(), selectors.end(), [&](const auto& a, const auto& b) { return key(a) < key(b); });
        selectors.erase(std::unique(selectors.begin(), selectors.end(), [&](const auto& a, const auto& b) {
            return key(a) == key(b);
        }), selectors.end());
        const auto original = selectors;
        selectors.erase(std::remove_if(selectors.begin(), selectors.end(), [&](const auto& s) {
            return !s.cidr.empty() && std::any_of(original.begin(), original.end(), [&](const auto& other) {
                return other.family == s.family && other.interface == s.interface && other.cidr.empty();
            });
        }), selectors.end());
    };
    normalize(result.include);
    normalize(result.exclude);
    result.include.erase(std::remove_if(result.include.begin(), result.include.end(), [&](const auto& s) {
        return std::any_of(result.exclude.begin(), result.exclude.end(), [&](const auto& other) {
            return other.family == s.family && other.interface == s.interface &&
                (other.cidr.empty() || other.cidr == s.cidr);
        });
    }), result.include.end());
    return result;
}

inline std::vector<std::string> interception_interfaces(const InterceptionClientScope& scope) {
    std::vector<std::string> result;
    for (const auto& selector : scope.include) result.push_back(selector.interface);
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

} // namespace keen_pbr3
