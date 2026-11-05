#include <doctest/doctest.h>
#include "../src/dns/doh_plan.hpp"
#include "../src/dns/dns_router.hpp"
#include "../src/dns/dns_proxy_runtime.hpp"
#include "../src/dns/doh_bootstrap.hpp"
#include "../src/dns/dns_client.hpp"
#include "fake_dns_server.hpp"

using namespace keen_pbr3;
using namespace std::chrono_literals;

namespace {
class ForeignListener {
public:
    ForeignListener(int type, std::uint16_t port) : fd_(::socket(AF_INET, type | SOCK_CLOEXEC, 0)) {
        REQUIRE(fd_ >= 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        address.sin_port = htons(port);
        const int rc = ::bind(fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
        bound_ = rc == 0;
        // A real LLMNR service can already own this port on a developer machine.
        REQUIRE((rc == 0 || errno == EADDRINUSE));
        if (rc == 0 && type == SOCK_STREAM) REQUIRE(::listen(fd_, 1) == 0);
    }
    ~ForeignListener() { ::close(fd_); }
    bool bound() const { return bound_; }
    ForeignListener(const ForeignListener&) = delete;
    ForeignListener& operator=(const ForeignListener&) = delete;
private:
    int fd_;
    bool bound_{false};
};
} // namespace

TEST_CASE("DNS proxy starts beside the Keenetic SMB wildcard UDP listener") {
    using namespace fake_dns;
    ForeignListener smb(SOCK_DGRAM, 5355);
    ForeignListener occupied_udp(SOCK_DGRAM, kDnsProxyFirstPort);
    ForeignListener occupied_tcp(SOCK_STREAM, kDnsProxyFirstPort + 1);
    const bool udp_half_was_free = ForeignListener(SOCK_DGRAM, kDnsProxyFirstPort + 1).bound();
    // A truncated response makes the client retry on the very same port over TCP.
    auto reply = [](const Bytes& q, bool tcp) {
        return make_reply(q, 0, {a_rr("192.0.2.8")}, !tcp);
    };
    FakeDnsServer first(reply), second(reply);
    auto dns = nlohmann::json::parse(R"({
      "servers":[{"tag":"a","address":"127.0.0.1"},{"tag":"b","address":"127.0.0.1"}],
      "fallback":["a","b"], "rules":[{"list":["example"],"servers":["a","b"]}]
    })").get<DnsConfig>();
    dns.servers->at(0).address = "127.0.0.1:" + std::to_string(first.port());
    dns.servers->at(1).address = "127.0.0.1:" + std::to_string(second.port());
    DnsProxyRuntime runtime;
    const auto registry = runtime.prepare_registry(dns);
    REQUIRE(registry->proxy_groups().size() == 1);
    const auto port = registry->fallback_targets().at(0).port;
    CHECK(port >= kDnsProxyFirstPort + 2);
    if (udp_half_was_free) {
        ForeignListener unused_half(SOCK_DGRAM, kDnsProxyFirstPort + 1);
        CHECK(unused_half.bound()); // TCP collision released the partial UDP reservation
    }
    ForeignListener second_smb(SOCK_DGRAM, 5355);
    CHECK_FALSE(second_smb.bound());
    CHECK(port == registry->list_targets("example").at(0).port);
    CHECK(port == runtime.prepare_registry(dns)->proxy_groups().at(0).port);
    auto query = [&] { return dns_query(kDnsProxyListenIp, port, "host.example",
                                        kDnsTypeA, kDnsClassIN, 1000ms); };
    REQUIRE(runtime.apply(registry->proxy_groups(), {}, [&] {
        const auto answer = query();
        CHECK(answer.status == DnsQueryStatus::Ok);
        CHECK(answer.via_tcp);
        CHECK(answer.addresses == std::vector<std::string>{"192.0.2.8"});
        return 0;
    }) == 0);
    auto candidate = registry->proxy_groups();
    std::reverse(candidate[0].upstreams.begin(), candidate[0].upstreams.end());
    CHECK(runtime.apply(candidate, {}, [] { return 7; }) == 7);
    CHECK(query().status == DnsQueryStatus::Ok);
    runtime.stop();
    // Even a retained resolver snapshot must not keep STOP's UDP listener open.
    CHECK(query().status == DnsQueryStatus::NetworkError);
}

TEST_CASE("exhausted DNS port range leaves a working group alone and needs no port for direct DNS") {
    DnsProxyRuntime runtime;
    const auto dns = nlohmann::json::parse(R"({
      "servers":[{"tag":"a","address":"192.0.2.1"},{"tag":"b","address":"192.0.2.2"}],
      "fallback":["a","b"]
    })").get<DnsConfig>();
    const auto current = runtime.prepare_registry(dns);
    REQUIRE(runtime.apply(current->proxy_groups(), {}, [] { return 0; }) == 0);
    std::vector<std::unique_ptr<ForeignListener>> occupied;
    for (std::size_t i = 0; i < kDnsProxyPortCount; ++i) {
        auto port = static_cast<std::uint16_t>(kDnsProxyFirstPort + i);
        if (port != current->proxy_groups()[0].port)
            occupied.emplace_back(std::make_unique<ForeignListener>(SOCK_DGRAM, port));
    }
    auto two = dns;
    two.rules.emplace(1);
    two.rules->at(0).list = {"reverse"};
    two.rules->at(0).servers = std::vector<std::string>{"b", "a"};
    CHECK_THROWS_AS(runtime.prepare_registry(two), std::runtime_error);
    CHECK(runtime.prepare_registry(dns)->proxy_groups()[0].binding == current->proxy_groups()[0].binding);
    auto direct = dns;
    direct.fallback = std::vector<std::string>{"a"};
    CHECK(runtime.prepare_registry(direct)->proxy_groups().empty());
}

static DnsConfig doh_config() {
    return nlohmann::json::parse(R"({
      "bootstrap":["plain"],
      "servers":[
        {"tag":"cloud","type":"doh","address":"https://dns.example/dns-query","detour":"vpn"},
        {"tag":"plain","address":"9.9.9.9"}],
      "fallback":["cloud"]
    })").get<DnsConfig>();
}

TEST_CASE("DoH plan is deterministic and never marks the local endpoint") {
    auto dns = doh_config();
    const auto plan = make_doh_plan(dns);
    REQUIRE(plan.groups.size() == 1);
    CHECK(plan.groups[0].upstreams[0].detour == "vpn");
    CHECK(plan.bootstrap[0].ip == "9.9.9.9");
    std::reverse(dns.servers->begin(), dns.servers->end());
    CHECK(make_doh_plan(dns).groups == plan.groups);
    DnsServerRegistry registry(dns);
    REQUIRE(registry.fallback_targets().size() == 1);
    CHECK(registry.fallback_targets()[0].runtime_proxy);
    CHECK_FALSE(registry.fallback_targets()[0].detour.has_value());
    CHECK(registry.detour_servers("cloud").empty());
}

TEST_CASE("DNS forwarding plan shares ordered groups across fallback lists and direct pins") {
    auto dns = nlohmann::json::parse(R"({
      "servers":[{"tag":"a","address":"1.1.1.1"},
                 {"tag":"b","address":"9.9.9.9:5353","detour":"vpn"}],
      "fallback":["a","b"],
      "rules":[{"list":["one","two"],"servers":["a","b"]},
               {"list":["reverse"],"servers":["b","a"]},
               {"list":["one"],"servers":["b"]},
               {"list":["off"],"enabled":false,"servers":["missing"]}]
    })").get<DnsConfig>();
    DnsServerRegistry registry(dns);
    REQUIRE(registry.proxy_groups().size() == 2);
    CHECK(registry.fallback_targets()[0].port == registry.list_targets("one")[0].port);
    CHECK(registry.list_targets("one")[0].port == registry.list_targets("two")[0].port);
    CHECK(registry.list_targets("one")[0].port != registry.list_targets("reverse")[0].port);
    CHECK(registry.proxy_groups()[0].upstreams[0].ip == "1.1.1.1");
    CHECK(registry.proxy_groups()[0].upstreams[1].port == 5353);
    CHECK(registry.detour_servers("b")[0]->detour == std::optional<std::string>{"vpn"});
    CHECK(registry.list_targets("off").empty());
    CHECK_FALSE(registry.proxy_uses_doh());
    std::reverse(dns.servers->begin(), dns.servers->end());
    CHECK(DnsServerRegistry(dns).proxy_groups() == registry.proxy_groups());
}

TEST_CASE("DNS forwarding plan leaves single plain DNS direct and does not bind unused DoH") {
    auto dns = doh_config();
    dns.fallback = std::vector<std::string>{"plain"};
    DnsServerRegistry registry(dns);
    CHECK(registry.proxy_groups().empty());
    CHECK_FALSE(registry.proxy_uses_doh());
    CHECK(registry.fallback_targets()[0].resolved_ip == "9.9.9.9");
    CHECK_FALSE(registry.fallback_targets()[0].runtime_proxy);
    dns.servers->front().domains = std::vector<std::string>{"example.org"};
    DnsServerRegistry pinned(dns);
    REQUIRE(pinned.proxy_groups().size() == 1);
    CHECK(pinned.direct_targets("cloud")[0].runtime_proxy);
    CHECK(pinned.proxy_uses_doh());
}

TEST_CASE("DNS forwarding plan combines real DoH upstreams with plain DNS rather than nested proxies") {
    auto dns = doh_config();
    dns.fallback = std::vector<std::string>{"cloud", "plain"};
    DnsServerRegistry registry(dns);
    REQUIRE(registry.proxy_groups().size() == 1);
    const auto& upstreams = registry.proxy_groups()[0].upstreams;
    REQUIRE(upstreams.size() == 2);
    CHECK(upstreams[0].kind == DnsBalancerUpstreamKind::Doh);
    CHECK(upstreams[0].url == "https://dns.example/dns-query");
    CHECK(upstreams[0].detour == "vpn");
    CHECK(upstreams[1].ip == "9.9.9.9");
    CHECK(registry.bootstrap_servers()[0].ip == "9.9.9.9");
}

TEST_CASE("DNS forwarding plan uses the pinned Keenetic snapshot without leaking scoped resolvers") {
    auto dns = nlohmann::json::parse(R"({
      "servers":[{"tag":"system","type":"keenetic","detour":"vpn"}],
      "fallback":["system"],"rules":[{"list":["one"],"server":"system"}]
    })").get<DnsConfig>();
    KeeneticDnsSnapshot snapshot;
    snapshot.addresses = {"1.1.1.1", "9.9.9.9"};
    KeeneticDnsScopedUpstreamEntry scoped;
    scoped.domain = "internal.example";
    scoped.address = "192.0.2.53";
    snapshot.scoped_upstreams.push_back(scoped);
    DnsServerRegistry first(dns, snapshot);
    REQUIRE(first.proxy_groups().size() == 1);
    REQUIRE(first.proxy_groups()[0].upstreams.size() == 2);
    CHECK(first.detour_servers("system").size() == 3);
    snapshot.addresses = {"8.8.8.8", "9.9.9.9"};
    DnsServerRegistry second(dns, snapshot);
    CHECK(first.proxy_groups()[0].upstreams[0].ip == "1.1.1.1");
    CHECK(second.proxy_groups()[0].upstreams[0].ip == "8.8.8.8");
}

TEST_CASE("DNS forwarding groups reject a loop into their managed listener range") {
    auto dns = doh_config();
    dns.fallback = std::vector<std::string>{"plain", "cloud"};
    dns.servers->back().address = "127.0.0.89:15482";
    dns.bootstrap.reset();
    dns.servers->front().ips = std::vector<std::string>{"1.1.1.1"};
    CHECK_THROWS_AS((void)DnsServerRegistry(dns), DnsError);
}

TEST_CASE("DNS groups never send back to dnsmasq but keep firmware loopback endpoints") {
    auto dns = nlohmann::json::parse(R"({
      "servers":[{"tag":"self","address":"127.0.0.1"},
                 {"tag":"self6","address":"[::1]:53"},
                 {"tag":"firmware","address":"127.0.0.1:40508"},
                 {"tag":"external","address":"9.9.9.9"}],
      "fallback":["self","self6","firmware","external"]
    })").get<DnsConfig>();
    DnsServerRegistry registry(dns);
    REQUIRE(registry.proxy_groups().size() == 1);
    REQUIRE(registry.proxy_groups()[0].upstreams.size() == 2);
    CHECK(registry.proxy_groups()[0].upstreams[0].port == 40508);
    CHECK(registry.proxy_groups()[0].upstreams[1].ip == "9.9.9.9");
    CHECK(registry.fallback_servers().size() == 4); // raw STOP policy is unchanged
    dns.fallback = std::vector<std::string>{"self"};
    DnsServerRegistry legacy(dns);
    CHECK(legacy.proxy_groups().empty());
    REQUIRE(legacy.fallback_targets().size() == 1);
    CHECK(legacy.fallback_targets()[0].resolved_ip == "127.0.0.1");
}

TEST_CASE("Plain DNS group works without DoH settings and falls through SERVFAIL on a real query") {
    using namespace fake_dns;
    std::atomic<int> failed_hits{0}, good_hits{0};
    FakeDnsServer failed([&](const Bytes& q, bool) { ++failed_hits; return make_reply(q, 2, {}); });
    FakeDnsServer good([&](const Bytes& q, bool) { ++good_hits; return make_reply(q, 0, {a_rr("192.0.2.8")}); });
    DnsConfig dns;
    DnsServer a, b;
    a.tag = "a"; a.address = "127.0.0.1:" + std::to_string(failed.port());
    b.tag = "b"; b.address = "127.0.0.1:" + std::to_string(good.port());
    dns.servers = std::vector<DnsServer>{a, b};
    dns.fallback = std::vector<std::string>{"a", "b"};
    DnsServerRegistry registry(dns);
    auto groups = registry.proxy_groups();
    REQUIRE(groups.size() == 1);
    groups[0].port = unused_udp_port(); // no fixed test ports
    DnsBalancerSettings settings;
    settings.listen_ip = "127.0.0.1";
    DnsProxyRuntime runtime;
    CHECK(runtime.apply(groups, settings, [] { return 0; }) == 0);
    const auto result = dns_query("127.0.0.1", groups[0].port, "host.example", kDnsTypeA, kDnsClassIN, 500ms);
    CHECK(result.status == DnsQueryStatus::Ok);
    CHECK(result.addresses == std::vector<std::string>{"192.0.2.8"});
    CHECK(failed_hits == 1);
    CHECK(good_hits == 1);
    runtime.stop();
}

TEST_CASE("DoH plan requires explicit nonrecursive bootstrap or numeric pins") {
    auto dns = doh_config();
    dns.bootstrap.reset();
    CHECK_THROWS_AS(make_doh_plan(dns), DnsError);
    (*dns.servers)[0].ips = std::vector<std::string>{"1.1.1.1"};
    CHECK_NOTHROW(make_doh_plan(dns));
    (*dns.servers)[0].ips = std::vector<std::string>{"1.1.1.1:53"};
    CHECK_THROWS_AS(make_doh_plan(dns), DnsError);
    dns = doh_config();
    (*dns.servers)[1].address = "127.0.0.1";
    CHECK_THROWS_AS(make_doh_plan(dns), DnsError);
    dns = doh_config();
    dns.bootstrap = std::vector<std::string>{"cloud"};
    CHECK_THROWS_AS(make_doh_plan(dns), DnsError);
    CHECK(DohBootstrap::resolve("localhost", {}).empty());
}

TEST_CASE("DoH URL rejects credentials fragments insecure schemes and invalid ports") {
    for (const auto& url : {"http://dns.example/dns-query", "https://a:b@dns.example/",
                           "https://dns.example/#x", "https://dns.example:0/",
                           "https://dns.example:65536/"}) {
        CHECK_THROWS_AS(doh_url_host(url), DnsError);
    }
    CHECK(doh_url_host("https://[2001:db8::1]:443/dns-query") == "2001:db8::1");
    CHECK_THROWS_AS(doh_url_host(std::string("https://dns.example/") + '\0' + "suffix"), DnsError);
    CHECK_THROWS_AS(doh_url_host(std::string("https://dns.example/") + '\x01'), DnsError);
    CHECK_FALSE(doh_numeric_host(std::string("192.0.2.53") + '\0' + "suffix"));
}

TEST_CASE("Bootstrap stop cancels an outstanding lookup instead of waiting for timeout") {
    FakeDnsServer silent([](const fake_dns::Bytes&, bool) { return fake_dns::Bytes{}; });
    DohBootstrap bootstrap([] {});
    bootstrap.set_servers({DnsBalancerUpstream::plain("127.0.0.1", silent.port())});
    bootstrap.request("dns.example");
    std::this_thread::sleep_for(50ms);
    const auto begin = std::chrono::steady_clock::now();
    bootstrap.stop();
    CHECK(std::chrono::steady_clock::now() - begin < 500ms);
}

TEST_CASE("DNS proxy is ready before publication and restores previous config on hook failure") {
    using namespace fake_dns;
    FakeDnsServer upstream([](const Bytes& q, bool) { return make_reply(q, 0, {a_rr("192.0.2.7")}); });
    const auto port = unused_udp_port();
    const std::vector<DnsBalancerGroup> groups{{port, {DnsBalancerUpstream::plain("127.0.0.1", upstream.port())}}};
    DnsBalancerSettings settings;
    settings.listen_ip = "127.0.0.1";
    DnsProxyRuntime runtime;
    auto query = [&] { return dns_query("127.0.0.1", port, "host.example", kDnsTypeA, kDnsClassIN, 300ms); };
    CHECK(runtime.apply(groups, settings, [&] { CHECK(query().status == DnsQueryStatus::Ok); return 0; }) == 0);
    auto replacement = groups;
    replacement[0].upstreams[0].port = unused_udp_port();
    CHECK(runtime.apply(replacement, settings, [] { return 7; }) == 7);
    CHECK(query().status == DnsQueryStatus::Ok);
    auto occupied = groups;
    occupied[0].port = upstream.port();
    bool hook_called = false;
    CHECK_THROWS_AS(runtime.apply(occupied, settings, [&] {
        hook_called = true;
        return 0;
    }), std::runtime_error);
    CHECK_FALSE(hook_called);
    CHECK(query().status == DnsQueryStatus::Ok);
    CHECK(runtime.apply({}, {}, [&] { CHECK(query().status == DnsQueryStatus::Ok); return 0; }) == 0);
    CHECK(query().status == DnsQueryStatus::NetworkError);
    CHECK(runtime.apply(groups, settings, [] { return 0; }) == 0);
    CHECK(runtime.deactivate([&] {
        CHECK(query().status == DnsQueryStatus::Ok);
        return 7;
    }) == 7);
    CHECK(query().status == DnsQueryStatus::NetworkError);
    CHECK(runtime.apply(groups, settings, [] { return 0; }) == 0);
    CHECK_THROWS_AS(runtime.deactivate([]() -> int {
        throw std::runtime_error("hook failed");
    }), std::runtime_error);
    CHECK(query().status == DnsQueryStatus::NetworkError);
    runtime.stop();
}
