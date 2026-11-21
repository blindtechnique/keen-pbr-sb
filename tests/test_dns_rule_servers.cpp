#include <doctest/doctest.h>

#include "../src/cache/cache_manager.hpp"
#include "../src/config/route_rule_retirement.hpp"
#include "../src/dns/dnsmasq_gen.hpp"
#include "../src/lists/list_streamer.hpp"

#include <sstream>
#include <algorithm>

using namespace keen_pbr3;

namespace {
DnsConfig multi_dns() {
    DnsServer first;
    first.tag = "primary";
    first.address = "1.1.1.1";
    first.detour = "vpn";
    DnsServer second;
    second.tag = "backup";
    second.address = "9.9.9.9:5353";
    second.detour = "vpn";
    DnsRule rule;
    rule.list = {"ai"};
    rule.servers = std::vector<std::string>{"primary", "backup"};
    rule.id = "ai_dns";
    rule.route_rule_ids = std::vector<std::string>{"ai_route"};
    DnsConfig config;
    config.servers = std::vector<DnsServer>{first, second};
    config.rules = std::vector<DnsRule>{rule};
    return config;
}

std::string generated_dns(const DnsConfig& dns, bool hash_only = false) {
    CacheManager cache("/nonexistent/dns-multi-test");
    ListStreamer streamer(cache);
    DnsServerRegistry registry(dns);
    ListConfig list;
    list.domains = std::vector<std::string>{"example.org"};
    std::map<std::string, ListConfig> lists{{"ai", list}};
    RouteConfig route;
    DnsmasqGenerator generator(registry, streamer, route, dns, lists);
    if (hash_only) return generator.compute_config_hash();
    std::ostringstream output;
    generator.generate(output);
    return output.str();
}
}

TEST_CASE("DNS server selections preserve legacy and explicit empty semantics") {
    const auto old = nlohmann::json{{"list", {"ai"}}, {"server", "primary"}}.get<DnsRule>();
    CHECK(dns_rule_server_tags(old) == std::vector<std::string>{"primary"});
    auto modern = old;
    modern.server.reset();
    modern.servers = std::vector<std::string>{"primary", "backup"};
    CHECK(dns_rule_server_tags(modern) == std::vector<std::string>{"primary", "backup"});
    CHECK(dns_rule_server_tags(nlohmann::json(modern).get<DnsRule>()) == dns_rule_server_tags(modern));
    modern.server = "primary";
    modern.servers = std::vector<std::string>{};
    CHECK(dns_rule_server_tags(modern).empty());
}

TEST_CASE("DNS publishes one group target and preserves every selected server's detour") {
    auto dns = multi_dns();
    const auto output = generated_dns(dns);
    CHECK(output.find("server=/example.org/127.0.0.89#15355\n") != std::string::npos);
    CHECK(output.find("server=/example.org/1.1.1.1\n") == std::string::npos);
    CHECK(output.find("server=/example.org/9.9.9.9#5353\n") == std::string::npos);
    DnsServerRegistry registry(dns);
    for (const auto& tag : dns_rule_server_tags(dns.rules->front())) {
        const auto targets = registry.detour_servers(tag);
        REQUIRE(targets.size() == 1);
        CHECK(targets.front()->detour == std::optional<std::string>{"vpn"});
    }
    dns.rules->front().enabled = false;
    CHECK(generated_dns(dns).find("server=/example.org/") == std::string::npos);
}

TEST_CASE("DNS group hash tracks underlying plain addresses and order even at the same proxy port") {
    auto dns = multi_dns();
    const auto original = generated_dns(dns, true);
    dns.servers->front().address = "1.0.0.1";
    CHECK(generated_dns(dns, true) != original);
    CHECK(generated_dns(dns).find("server=/example.org/127.0.0.89#15355\n") != std::string::npos);
    const auto changed = generated_dns(dns, true);
    std::reverse(dns.rules->front().servers->begin(), dns.rules->front().servers->end());
    CHECK(generated_dns(dns, true) != changed);
}

TEST_CASE("DNS grouped fallback preserves only direct upstream records for STOP") {
    auto dns = multi_dns();
    dns.servers->front().detour.reset();
    dns.fallback = std::vector<std::string>{"primary", "backup"};
    const auto output = generated_dns(dns);
    CHECK(output.find("\nserver=127.0.0.89#15355\n") != std::string::npos);
    CHECK(output.find("# keen-pbr direct-fallback server=1.1.1.1\n") != std::string::npos);
    CHECK(output.find("# keen-pbr direct-fallback server=9.9.9.9") == std::string::npos);
    CHECK(output.find("# keen-pbr direct-fallback server=127.") == std::string::npos);
}

TEST_CASE("DNS legacy to single-array migration keeps generated configuration identical") {
    auto dns = multi_dns();
    dns.rules->front().servers.reset();
    dns.rules->front().server = "primary";
    const auto old_output = generated_dns(dns, true);
    dns.rules->front().server.reset();
    dns.rules->front().servers = std::vector<std::string>{"primary"};
    CHECK(generated_dns(dns, true) == old_output);
}

TEST_CASE("DNS keeps existing first-rule priority and direct domain bindings") {
    auto dns = multi_dns();
    auto later = dns.rules->front();
    later.servers = std::vector<std::string>{"backup"};
    dns.rules->front().servers = std::vector<std::string>{"primary"};
    dns.rules->push_back(later);
    CHECK(generated_dns(dns).find("server=/example.org/9.9.9.9#5353") == std::string::npos);
    dns.servers->at(1).domains = std::vector<std::string>{"example.org"};
    const auto output = generated_dns(dns);
    CHECK(output.find("server=/example.org/9.9.9.9#5353") != std::string::npos);
    CHECK(output.find("server=/example.org/1.1.1.1") == std::string::npos);
}

TEST_CASE("DNS route deletion retires attached multi-server rule") {
    Config previous;
    previous.dns = multi_dns();
    RouteRule route;
    route.id = "ai_route";
    route.list = std::vector<std::string>{"ai"};
    route.outbound = "vpn";
    previous.route = RouteConfig{};
    previous.route->rules = std::vector<RouteRule>{route};
    Config next = previous;
    next.route->rules->clear();
    retire_route_dns_bindings(next, previous);
    CHECK(next.dns->rules->empty());
    CHECK(previous.dns->rules->size() == 1);
}

TEST_CASE("DoH generation hash tracks HTTPS pins and bootstrap, and STOP fallback excludes proxy") {
    auto dns = multi_dns();
    auto& server = dns.servers->front();
    server.type = api::DnsServerType::DOH;
    server.address = "https://dns.example/dns-query";
    server.detour.reset();
    server.ips = std::vector<std::string>{"1.1.1.1"};
    dns.fallback = std::vector<std::string>{"primary", "backup"};
    const auto text = generated_dns(dns);
    CHECK(text.find("server=127.0.0.89#15355") != std::string::npos);
    CHECK(text.find("# keen-pbr direct-fallback server=127.0.0.89") == std::string::npos);
    const auto before = generated_dns(dns, true);
    server.ips = std::vector<std::string>{"1.0.0.1"};
    CHECK(generated_dns(dns, true) != before);
    server.ips.reset();
    dns.bootstrap = std::vector<std::string>{"backup"};
    const auto boot_before = generated_dns(dns, true);
    dns.servers->back().address = "8.8.8.8";
    CHECK(generated_dns(dns, true) != boot_before);
}

TEST_CASE("DNS missing secondary server is not silently ignored") {
    auto dns = multi_dns();
    dns.rules->front().servers->push_back("missing");
    CHECK_THROWS_AS((void)DnsServerRegistry(dns), DnsError);
    dns.rules->front().servers = std::vector<std::string>{};
    dns.rules->front().server = "primary";
    CHECK_THROWS_AS((void)DnsServerRegistry(dns), DnsError);
}
