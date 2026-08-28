#include <doctest/doctest.h>

#include "../src/daemon/runtime_resolver_generation_snapshot.hpp"

#include <memory>
#include <string>
#include <vector>

using namespace keen_pbr3;

TEST_CASE("runtime resolver generation is built only from its candidate input") {
    const auto pinned_lists =
        std::make_shared<ListCacheGenerationSnapshot>();

    DnsServer keenetic_server;
    keenetic_server.tag = "keenetic";
    keenetic_server.type = api::DnsServerType::KEENETIC;
    DnsConfig dns;
    dns.servers = std::vector<DnsServer>{keenetic_server};
    dns.fallback = std::vector<std::string>{"keenetic"};

    RuntimeResolverGenerationInput candidate;
    candidate.config.dns = dns;
    candidate.keenetic_dns.snapshot = KeeneticDnsSnapshot{
        {"192.0.2.53"},
        {},
        {{"candidate.example", "192.0.2.80"}}};
    candidate.keenetic_dns.status = KeeneticDnsCacheStatus::fresh;
    candidate.keenetic_dns.generation = 41U;
    candidate.list_cache_snapshot = pinned_lists;
    candidate.list_max_file_size_bytes = 1024U * 1024U;
    candidate.resolver_type = ResolverType::DNSMASQ_NFTSET;
    candidate.ipv6_policy =
        ResolverIpv6Policy::explicitly_disabled();
    candidate.trusted_dns_interfaces = {"Wireguard9"};
    candidate.generation = 77U;

    const auto prepared =
        build_runtime_resolver_generation_snapshot(candidate);

    REQUIRE(prepared.config.dns.has_value());
    REQUIRE(prepared.keenetic_dns.snapshot.has_value());
    CHECK(prepared.keenetic_dns.snapshot->addresses ==
          std::vector<std::string>{"192.0.2.53"});
    CHECK(prepared.keenetic_dns.generation == 41U);
    CHECK(prepared.list_cache_snapshot.get() == pinned_lists.get());
    CHECK(prepared.resolver_type == ResolverType::DNSMASQ_NFTSET);
    CHECK_FALSE(prepared.ipv6_policy.targets_enabled);
    CHECK(prepared.ipv6_policy.suppress_aaaa);
    CHECK(prepared.trusted_dns_interfaces ==
          std::vector<std::string>{"Wireguard9"});
    CHECK(prepared.generation == 77U);
    CHECK(prepared.stream_epoch == 0U);
    CHECK(prepared.expected_hash.size() == 32U);

    auto other_candidate = candidate;
    other_candidate.keenetic_dns.snapshot->addresses = {"198.51.100.53"};
    other_candidate.trusted_dns_interfaces = {"Wireguard10"};
    other_candidate.generation = 88U;
    const auto other_prepared =
        build_runtime_resolver_generation_snapshot(other_candidate);

    CHECK(other_prepared.generation == 88U);
    CHECK(other_prepared.keenetic_dns.snapshot->addresses ==
          std::vector<std::string>{"198.51.100.53"});
    CHECK(other_prepared.expected_hash != prepared.expected_hash);
    CHECK(prepared.keenetic_dns.snapshot->addresses ==
          std::vector<std::string>{"192.0.2.53"});
    CHECK(prepared.trusted_dns_interfaces ==
          std::vector<std::string>{"Wireguard9"});
}
