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

    // Snapshot used to construct this registry.  The dnsmasq generator reads
    // static entries and upstream metadata from this exact same generation.
    const std::optional<KeeneticDnsSnapshot>& keenetic_snapshot() const noexcept {
        return keenetic_snapshot_;
    }

private:
    std::map<std::string, std::vector<DnsServerConfig>> servers_;
    std::vector<std::string> fallback_tags_;
    std::optional<KeeneticDnsSnapshot> keenetic_snapshot_;
};

} // namespace keen_pbr3
