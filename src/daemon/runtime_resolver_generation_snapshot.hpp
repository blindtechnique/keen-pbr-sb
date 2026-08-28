#pragma once

#include "../config/config.hpp"
#include "../dns/dnsmasq_gen.hpp"
#include "../dns/keenetic_dns.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct ResolverGenerationSnapshot {
    Config config;
    KeeneticDnsCacheView keenetic_dns;
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot;
    ResolverType resolver_type;
    ResolverIpv6Policy ipv6_policy;
    std::vector<std::string> trusted_dns_interfaces;
    std::string expected_hash;
    std::uint64_t generation{0};
    std::uint64_t stream_epoch{0};
};

// Complete immutable input for one resolver generation. The builder below
// must not consult Daemon, a live CacheManager, the Keenetic cache or kernel
// capability probes: a prepared config candidate can therefore be hashed
// before it becomes the active runtime generation.
struct RuntimeResolverGenerationInput {
    Config config;
    KeeneticDnsCacheView keenetic_dns;
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot;
    std::size_t list_max_file_size_bytes{0};
    ResolverType resolver_type{ResolverType::DNSMASQ_IPSET};
    ResolverIpv6Policy ipv6_policy;
    std::vector<std::string> trusted_dns_interfaces;
    std::uint64_t generation{0};
};

// Builds the complete resolver snapshot and its canonical hash solely from
// the explicit input. A pinned list generation is mandatory; there is no live
// CacheManager fallback at this worker-safe boundary.
ResolverGenerationSnapshot build_runtime_resolver_generation_snapshot(
    const RuntimeResolverGenerationInput& input);

} // namespace keen_pbr3
