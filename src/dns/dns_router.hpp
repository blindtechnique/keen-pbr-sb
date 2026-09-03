#pragma once

#include "../config/config.hpp"
#include "dns_server.hpp"
#include "keenetic_dns.hpp"

#include <map>
#include <optional>
#include <string>

namespace keen_pbr3 {

class DnsServerRegistry {
public:
    // Construct from DNS config.
    // Parses all DNS server definitions and validates tags.
    explicit DnsServerRegistry(
        const DnsConfig& dns_config,
        const std::optional<KeeneticDnsSnapshot>& keenetic_snapshot = std::nullopt);

    std::vector<const DnsServerConfig*> get_servers(const std::string& tag) const;

    // Get fallback server configs in configured order.
    std::vector<const DnsServerConfig*> fallback_servers() const;

    // Get the routable endpoints that must receive this server's detour mark.
    // For a Keenetic server this includes selected domain-scoped public
    // upstreams, but never publishes them as ordinary fallback resolvers.
    std::vector<const DnsServerConfig*> detour_servers(
        const std::string& tag) const;

    // Domain-scoped entries imported from Keenetic are global resolver
    // policy. Publish them only when the Keenetic server participates in the
    // global fallback chain, not merely because it is defined for one rule.
    bool keenetic_fallback_enabled() const noexcept {
        return keenetic_fallback_enabled_;
    }

    // Snapshot used to construct this registry.  The dnsmasq generator reads
    // static entries and upstream metadata from this exact same generation.
    const std::optional<KeeneticDnsSnapshot>& keenetic_snapshot() const noexcept {
        return keenetic_snapshot_;
    }

private:
    std::map<std::string, std::vector<DnsServerConfig>> servers_;
    std::map<std::string, std::vector<DnsServerConfig>> detour_servers_;
    std::vector<std::string> fallback_tags_;
    std::optional<KeeneticDnsSnapshot> keenetic_snapshot_;
    bool keenetic_fallback_enabled_{false};
};

} // namespace keen_pbr3
