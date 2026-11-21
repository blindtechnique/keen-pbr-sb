#include "dns_router.hpp"
#include "doh_plan.hpp"

#include <algorithm>
#include <iterator>
#include <set>
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
    const std::optional<KeeneticDnsSnapshot>& keenetic_snapshot,
    const ReservePort& reserve_port)
    : fallback_tags_(dns_config.fallback.value_or(std::vector<std::string>{})) {
    std::vector<std::string> keenetic_server_tags;
    const auto doh_plan = make_doh_plan(dns_config);
    bootstrap_ = doh_plan.bootstrap;

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
        } else if (server_type == api::DnsServerType::DOH) {
            DnsServerConfig endpoint;
            endpoint.tag = server.tag;
            endpoint.address = *server.address; // validated by make_doh_plan
            endpoint.doh_url = *server.address;
            endpoint.ips = server.ips.value_or(std::vector<std::string>{});
            endpoint.detour = server.detour;
            servers_[server.tag].push_back(std::move(endpoint));
            // Only the owned HTTPS socket receives SO_MARK. Never classify all
            // port-443 traffic to this resolver's address as DNS traffic.
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
        const auto tags = dns_rule_server_tags(rule);
        if (tags.empty()) throw DnsError("DNS rule has no servers");
        for (const auto& tag : tags) {
            if (servers_.find(tag) == servers_.end()) {
                throw DnsError("DNS rule references unknown server tag: '" + tag + "'");
            }
        }
    }

    // Use the same deterministic plan for hashing, streaming and activation.
    // Preserve our existing first-enabled-rule priority, rather than merging
    // later rules into an earlier rule's DNS policy.
    fallback_targets_ = make_targets(fallback_tags_, reserve_port);
    std::map<std::string, std::vector<std::string>> list_tags;
    for (const auto& rule : dns_config.rules.value_or(std::vector<DnsRule>{})) {
        if (!dns_rule_enabled(rule)) continue;
        for (const auto& list : rule.list)
            list_tags.emplace(list, dns_rule_server_tags(rule));
    }
    for (const auto& [list, tags] : list_tags)
        list_targets_[list] = make_targets(tags, reserve_port);
    std::set<std::string> direct_tags;
    for (const auto& server : dns_config.servers.value_or(std::vector<DnsServer>{}))
        if (server.domains && !server.domains->empty()) direct_tags.insert(server.tag);
    for (const auto& tag : direct_tags)
        direct_targets_[tag] = make_targets({tag}, reserve_port);
}

std::vector<DnsServerConfig> DnsServerRegistry::make_targets(
    const std::vector<std::string>& tags, const ReservePort& reserve_port) {
    std::vector<DnsBalancerUpstream> upstreams;
    std::vector<DnsServerConfig> resolver_self_targets;
    const DnsServerConfig* single = nullptr;
    for (const auto& tag : tags) {
        for (const auto* server : get_servers(tag)) {
            // dnsmasq ignores its own loopback:53 targets. Do not turn that
            // harmless legacy entry into a recursive query through our proxy.
            // Firmware DoT/DoH forwarders on other loopback ports stay usable.
            if (!server->is_doh() && server->port == 53 && is_loopback(server->resolved_ip)) {
                resolver_self_targets.push_back(*server);
                continue;
            }
            auto upstream = server->is_doh()
                ? DnsBalancerUpstream::doh(server->doh_url, server->detour.value_or(""), server->ips)
                : DnsBalancerUpstream::plain(server->resolved_ip, server->port);
            // Plain DNS continues to use the existing destination/port detour
            // rules, including Keenetic's effective per-family group choice.
            upstream.name = tag;
            if (std::find(upstreams.begin(), upstreams.end(), upstream) == upstreams.end()) {
                upstreams.push_back(std::move(upstream));
                single = server;
            }
        }
    }
    // With no external endpoint, retain the old direct dnsmasq configuration;
    // do not invent a resolver or create a listener that points at itself.
    if (upstreams.empty()) return resolver_self_targets;
    for (const auto& upstream : upstreams) {
        if (upstream.kind == DnsBalancerUpstreamKind::Plain &&
            upstream.ip == kDnsProxyListenIp && upstream.port >= kDnsProxyFirstPort &&
            upstream.port < kDnsProxyFirstPort + kDnsProxyPortCount)
            throw DnsError("A DNS group cannot forward back into the managed proxy",
                           "config.dns.proxy_loop");
    }
    if (upstreams.size() == 1 && !single->is_doh()) return {*single};

    auto group = std::find_if(proxy_groups_.begin(), proxy_groups_.end(),
        [&](const DnsBalancerGroup& existing) { return existing.upstreams == upstreams; });
    if (group == proxy_groups_.end()) {
        if (proxy_groups_.size() >= kDnsBalancerMaxGroups)
            throw DnsError("At most 32 distinct DNS forwarder groups are supported",
                           "config.dns.proxy_limit");
        // Validation and offline rendering are deterministic and do no network I/O.
        // A live resolver generation instead pins a real UDP/TCP pair at this point.
        auto binding = reserve_port ? reserve_port(proxy_groups_.size()) : nullptr;
        const auto port = binding ? binding->number() :
            static_cast<std::uint16_t>(kDnsProxyFirstPort + proxy_groups_.size());
        proxy_groups_.push_back({port, std::move(upstreams), std::move(binding)});
        group = std::prev(proxy_groups_.end());
    }
    auto target = parse_dns_server("", kDnsProxyListenIp, std::nullopt);
    target.port = group->port;
    target.runtime_proxy = true;
    return {std::move(target)};
}

const std::vector<DnsServerConfig>& DnsServerRegistry::list_targets(const std::string& list) const {
    static const std::vector<DnsServerConfig> empty;
    const auto it = list_targets_.find(list);
    return it == list_targets_.end() ? empty : it->second;
}

const std::vector<DnsServerConfig>& DnsServerRegistry::direct_targets(const std::string& tag) const {
    static const std::vector<DnsServerConfig> empty;
    const auto it = direct_targets_.find(tag);
    return it == direct_targets_.end() ? empty : it->second;
}

bool DnsServerRegistry::proxy_uses_doh() const {
    for (const auto& group : proxy_groups_)
        for (const auto& upstream : group.upstreams)
            if (upstream.kind == DnsBalancerUpstreamKind::Doh) return true;
    return false;
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
