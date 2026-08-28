#include "runtime_resolver_generation_snapshot.hpp"

#include "../dns/dns_router.hpp"
#include "../lists/list_streamer.hpp"

#include <keen-pbr/version.hpp>

#include <map>
#include <stdexcept>

namespace keen_pbr3 {

ResolverGenerationSnapshot build_runtime_resolver_generation_snapshot(
    const RuntimeResolverGenerationInput& input) {
    if (!input.list_cache_snapshot) {
        throw std::invalid_argument(
            "runtime resolver generation requires a pinned list snapshot");
    }
    if (input.list_max_file_size_bytes == 0) {
        throw std::invalid_argument(
            "runtime resolver generation requires a non-zero list size limit");
    }

    ResolverGenerationSnapshot snapshot;
    snapshot.config = input.config;
    snapshot.keenetic_dns = input.keenetic_dns;
    snapshot.list_cache_snapshot = input.list_cache_snapshot;
    snapshot.resolver_type = input.resolver_type;
    snapshot.ipv6_policy = input.ipv6_policy;
    snapshot.trusted_dns_interfaces = input.trusted_dns_interfaces;
    snapshot.generation = input.generation;

    ListStreamer streamer(
        input.list_max_file_size_bytes,
        snapshot.list_cache_snapshot);
    const DnsConfig dns_cfg =
        snapshot.config.dns.value_or(DnsConfig{});
    DnsServerRegistry dns_registry(
        dns_cfg, snapshot.keenetic_dns.snapshot);
    // DnsmasqGenerator retains references while computing the hash. Keep
    // optional defaults alive for the complete call.
    const RouteConfig route_cfg =
        snapshot.config.route.value_or(RouteConfig{});
    const std::map<std::string, ListConfig> lists =
        snapshot.config.lists.value_or(
            std::map<std::string, ListConfig>{});
    DnsmasqGenerator generator(
        dns_registry,
        streamer,
        route_cfg,
        dns_cfg,
        lists,
        snapshot.resolver_type,
        KEEN_PBR3_VERSION_FULL_STRING,
        snapshot.ipv6_policy,
        snapshot.trusted_dns_interfaces);
    snapshot.expected_hash = generator.compute_config_hash();
    return snapshot;
}

} // namespace keen_pbr3
