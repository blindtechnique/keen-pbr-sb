#pragma once

#include "../config/config.hpp"
#include "dns_server.hpp"
#include "dns_balancer.hpp"
#include "keenetic_dns.hpp"

#include <map>
#include <optional>
#include <string>

namespace keen_pbr3 {

class DnsServerRegistry {
public:
    using ReservePort = std::function<std::shared_ptr<DnsProxyPort>(std::size_t)>;
    // Construct from DNS config.
    // Parses all DNS server definitions and validates tags.
    explicit DnsServerRegistry(
        const DnsConfig& dns_config,
        const std::optional<KeeneticDnsSnapshot>& keenetic_snapshot = std::nullopt,
        const ReservePort& reserve_port = {});

    std::vector<const DnsServerConfig*> get_servers(const std::string& tag) const;

    // Get fallback server configs in configured order.
    std::vector<const DnsServerConfig*> fallback_servers() const;

    // Published dnsmasq targets: a single plain server stays direct; DoH or
    // several servers share one UDP/TCP forwarder, in configured order.
    const std::vector<DnsServerConfig>& fallback_targets() const { return fallback_targets_; }
    const std::vector<DnsServerConfig>& list_targets(const std::string& list) const;
    const std::vector<DnsServerConfig>& direct_targets(const std::string& tag) const;
    const std::vector<DnsBalancerGroup>& proxy_groups() const { return proxy_groups_; }
    const std::vector<DnsBalancerUpstream>& bootstrap_servers() const { return bootstrap_; }
    bool proxy_uses_doh() const;

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
    std::vector<DnsServerConfig> make_targets(const std::vector<std::string>& tags,
                                              const ReservePort& reserve_port);
    std::map<std::string, std::vector<DnsServerConfig>> servers_;
    std::map<std::string, std::vector<DnsServerConfig>> detour_servers_;
    std::vector<std::string> fallback_tags_;
    std::optional<KeeneticDnsSnapshot> keenetic_snapshot_;
    bool keenetic_fallback_enabled_{false};
    std::vector<DnsServerConfig> fallback_targets_;
    std::map<std::string, std::vector<DnsServerConfig>> list_targets_;
    std::map<std::string, std::vector<DnsServerConfig>> direct_targets_;
    std::vector<DnsBalancerGroup> proxy_groups_;
    std::vector<DnsBalancerUpstream> bootstrap_;
};

} // namespace keen_pbr3
