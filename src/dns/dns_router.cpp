#include "dns_router.hpp"

#include <algorithm>
#include <utility>

namespace keen_pbr3 {

namespace {

bool is_loopback(const std::string& address) {
    return address.rfind("127.", 0) == 0 || address == "::1";
}

void append_unique_endpoint(std::vector<DnsServerConfig>& endpoints,
                            DnsServerConfig endpoint) {
    const auto duplicate = std::find_if(
        endpoints.begin(), endpoints.end(),
        [&endpoint](const DnsServerConfig& existing) {
            return existing.resolved_ip == endpoint.resolved_ip &&
                   existing.port == endpoint.port;
        });
    if (duplicate == endpoints.end()) {
        endpoints.push_back(std::move(endpoint));
    }
}

} // namespace

DnsServerRegistry::DnsServerRegistry(
    const DnsConfig& dns_config,
    const std::optional<KeeneticDnsSnapshot>& keenetic_snapshot)
    : fallback_tags_(dns_config.fallback.value_or(std::vector<std::string>{})) {
    std::vector<std::string> keenetic_server_tags;

    // Parse all DNS server definitions into DnsServerConfig
    for (const auto& server : dns_config.servers.value_or(std::vector<DnsServer>{})) {
        const auto server_type = server.type.value_or(api::DnsServerType::STATIC);
        if (server_type == api::DnsServerType::KEENETIC) {
            keenetic_server_tags.push_back(server.tag);
            const bool is_fallback = std::find(
                fallback_tags_.begin(), fallback_tags_.end(), server.tag) !=
                fallback_tags_.end();
            if (!keenetic_snapshot) {
                throw DnsError(
                    "DNS server '" + server.tag +
                    "' requires a prepared Keenetic DNS snapshot");
            }
            if (keenetic_snapshot->addresses.empty()) {
                throw DnsError(
                    "DNS server '" + server.tag +
                    "' received a Keenetic DNS snapshot without upstream addresses");
            }
            if (!keenetic_snapshot_) {
                keenetic_snapshot_ = keenetic_snapshot;
            }
            for (const auto& resolved_address : keenetic_snapshot_->addresses) {
                auto resolved =
                    parse_dns_server(server.tag, resolved_address, server.detour);
                servers_[server.tag].push_back(resolved);
                if (server.detour.has_value() &&
                    !is_loopback(resolved.resolved_ip)) {
                    append_unique_endpoint(
                        detour_servers_[server.tag], std::move(resolved));
                }
            }
            if (is_fallback && server.detour.has_value()) {
                for (const auto& scoped :
                     keenetic_snapshot_->scoped_upstreams) {
                    auto resolved = parse_dns_server(
                        server.tag, scoped.address, server.detour);
                    if (!is_loopback(resolved.resolved_ip)) {
                        append_unique_endpoint(
                            detour_servers_[server.tag],
                            std::move(resolved));
                    }
                }
            }
        } else if (server_type == api::DnsServerType::STATIC) {
            if (!server.address.has_value()) {
                throw DnsError("DNS server '" + server.tag + "' is missing address");
            }
            auto resolved =
                parse_dns_server(server.tag, *server.address, server.detour);
            servers_[server.tag].push_back(resolved);
            if (server.detour.has_value()) {
                append_unique_endpoint(
                    detour_servers_[server.tag], std::move(resolved));
            }
        } else {
            throw DnsError("DNS server '" + server.tag + "' has unsupported type");
        }
    }

    keenetic_fallback_enabled_ = std::any_of(
        fallback_tags_.begin(),
        fallback_tags_.end(),
        [&keenetic_server_tags](const std::string& fallback_tag) {
            return std::find(
                       keenetic_server_tags.begin(),
                       keenetic_server_tags.end(),
                       fallback_tag) != keenetic_server_tags.end();
        });

    // Validate that fallback server tags exist
    for (const auto& fallback_tag : fallback_tags_) {
        if (servers_.find(fallback_tag) == servers_.end()) {
            throw DnsError("DNS fallback server tag not found: '" + fallback_tag + "'");
        }
    }

    // Validate that all rule server tags exist
    for (const auto& rule : dns_config.rules.value_or(std::vector<DnsRule>{})) {
        if (!dns_rule_enabled(rule)) {
            continue;
        }
        if (servers_.find(rule.server) == servers_.end()) {
            throw DnsError("DNS rule references unknown server tag: '" + rule.server + "'");
        }
    }
}

std::vector<const DnsServerConfig*> DnsServerRegistry::get_servers(const std::string& tag) const {
    std::vector<const DnsServerConfig*> resolved_servers;
    auto it = servers_.find(tag);
    if (it == servers_.end()) {
        return resolved_servers;
    }
    resolved_servers.reserve(it->second.size());
    for (const auto& server : it->second) {
        resolved_servers.push_back(&server);
    }
    return resolved_servers;
}

std::vector<const DnsServerConfig*> DnsServerRegistry::fallback_servers() const {
    std::vector<const DnsServerConfig*> fallback_servers;
    for (const auto& fallback_tag : fallback_tags_) {
        const auto resolved_servers = get_servers(fallback_tag);
        fallback_servers.insert(fallback_servers.end(),
                                resolved_servers.begin(),
                                resolved_servers.end());
    }
    return fallback_servers;
}

std::vector<const DnsServerConfig*> DnsServerRegistry::detour_servers(
    const std::string& tag) const {
    std::vector<const DnsServerConfig*> resolved_servers;
    const auto it = detour_servers_.find(tag);
    if (it == detour_servers_.end()) {
        return resolved_servers;
    }
    resolved_servers.reserve(it->second.size());
    for (const auto& server : it->second) {
        resolved_servers.push_back(&server);
    }
    return resolved_servers;
}

} // namespace keen_pbr3
