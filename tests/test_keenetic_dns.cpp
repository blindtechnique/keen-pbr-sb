#include <doctest/doctest.h>

#include "../src/dns/keenetic_dns.hpp"
#include "../src/config/config.hpp"

#include <chrono>
#include <future>
#include <stdexcept>
#include <thread>

using namespace keen_pbr3;

namespace {

struct KeeneticDnsTestStateGuard {
    KeeneticDnsTestStateGuard() { reset_keenetic_dns_test_state(); }
    ~KeeneticDnsTestStateGuard() { reset_keenetic_dns_test_state(); }
};

std::string keenetic_dns_response(const std::string& address) {
    return std::string(R"({
      "proxy-status": [
        {
          "proxy-name": "System",
          "proxy-config": "dns_server = )") + address + R"( .\n"
        }
      ]
    })";
}

} // namespace

TEST_CASE("keenetic dns: parse address from RCI System policy") {
    SUBCASE("ignores domain-scoped entries in real System payload shape") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "rpc_port = 54321\nrpc_ttl = 10000\nrpc_wait = 10000\ntimeout = 7000\nproceed = 500\nstat_file = /var/ndnproxymain.stat\nstat_time = 10000\nrr_port = 40901\ndns_server = 203.0.113.10 provider.example\ndns_server = 203.0.113.11 provider.example\ndns_server = 127.0.0.1:40508 . # https://dns-a.example/dns-query@dnsm\ndns_server = 127.0.0.1:40509 . # https://dns-b.example/dns-query@dnsm\nstatic_a = host.example 198.51.100.180 1\nnorebind_ctl = on\ndns_tcp_port = 53\ndns_udp_port = 53\n"
            },
            {
              "proxy-name": "Policy0",
              "proxy-config": "timeout = 7000\ndns_server = 127.0.0.1:40524 . # https://dns-a.example/dns-query@dnsm\n"
            }
          ]
        })";

        CHECK(extract_keenetic_dns_snapshot_from_rci(json).addresses
              == std::vector<std::string>{"127.0.0.1:40508", "127.0.0.1:40509"});
    }

    SUBCASE("extracts static a and aaaa entries from System policy") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "dns_server = 127.0.0.1:40508 . # https://dns-b.example/dns-query@dnsm\nstatic_a = host.example 198.51.100.180 1\nstatic_aaaa = host.example 2001:db8::125 1\nstatic_a = *.lan.example 192.0.2.10 0\nstatic_a = *.x 192.0.2.11 0\n"
            }
          ]
        })";

        const KeeneticDnsSnapshot snapshot = extract_keenetic_dns_snapshot_from_rci(json);
        REQUIRE(snapshot.addresses.size() == 1);
        CHECK(snapshot.addresses[0] == "127.0.0.1:40508");
        REQUIRE(snapshot.upstreams.size() == 1);
        CHECK(snapshot.upstreams[0].kind == "DoH");
        CHECK(snapshot.upstreams[0].target == "https://dns-b.example/dns-query");
        REQUIRE(snapshot.static_entries.size() == 4);
        CHECK(snapshot.static_entries[0].domain == "host.example");
        CHECK(snapshot.static_entries[0].address == "198.51.100.180");
        CHECK(snapshot.static_entries[1].domain == "host.example");
        CHECK(snapshot.static_entries[1].address == "2001:db8::125");
        CHECK(snapshot.static_entries[2].domain == "*.lan.example");
        CHECK(snapshot.static_entries[2].address == "192.0.2.10");
        CHECK(snapshot.static_entries[3].domain == "*.x");
        CHECK(snapshot.static_entries[3].address == "192.0.2.11");
    }

    SUBCASE("rejects System policy with only domain-scoped dns_server entries") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "dns_server = 203.0.113.11 provider.example\n"
            }
          ]
        })";

        CHECK_THROWS_AS(extract_keenetic_dns_snapshot_from_rci(json), KeeneticDnsError);
    }

    SUBCASE("extracts ipv4 dns_server line with trailing doh comment") {
        const std::string json = R"({
          "proxy-status": [
            {"proxy-name":"Guest","proxy-config":"dns_server = 192.0.2.8\n"},
            {"proxy-name":"System","proxy-config":"dns_server = 127.0.0.1:40500 # https://dns-a.example/dns-query@dnsm\n"}
          ]
        })";

        CHECK(extract_keenetic_dns_snapshot_from_rci(json).addresses
              == std::vector<std::string>{"127.0.0.1:40500"});
    }

    SUBCASE("extracts first dns_server directive from realistic multi-line policy") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-enabled": true,
              "proxy-config": "# system dns policy\ncache-size = 2048\nlisten = 127.0.0.1:53\n  dns_server = 127.0.0.1:40500   # https://bootstrap-dns.example/dns-query@bootstrap\nbootstrap_server = 192.0.2.1\n"
            },
            {
              "proxy-name": "Guest",
              "proxy-config": "dns_server = 192.0.2.9\n"
            }
          ]
        })";

        CHECK(extract_keenetic_dns_snapshot_from_rci(json).addresses
              == std::vector<std::string>{"127.0.0.1:40500"});
    }

    SUBCASE("ignores bracketed ipv6 dns_server address with port") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "dns_server = [2001:db8::53]:853 # tls://resolver.example\ndns_server = 127.0.0.1:40508 . # https://dns-a.example/dns-query@dnsm\n"
            }
          ]
        })";

        CHECK(extract_keenetic_dns_snapshot_from_rci(json).addresses
              == std::vector<std::string>{"127.0.0.1:40508"});
    }

    SUBCASE("skips bare ipv6 address followed by routing domain in favor of unscoped doh") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "dns_server = 2001:db8::8888 provider.example\ndns_server = 127.0.0.1:40508 . # https://dns-a.example/dns-query@dnsm\n"
            }
          ]
        })";

        CHECK(extract_keenetic_dns_snapshot_from_rci(json).addresses
              == std::vector<std::string>{"127.0.0.1:40508"});
    }

    SUBCASE("extracts plain dns_server line with dot routing suffix") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "dns_server = 198.51.100.10 .\ndns_server = 198.51.100.11 .\n"
            }
          ]
        })";

        CHECK(extract_keenetic_dns_snapshot_from_rci(json).addresses
              == std::vector<std::string>{"198.51.100.10", "198.51.100.11"});
    }

    SUBCASE("extracts localhost dot server with dot comment") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "dns_server = 127.0.0.1:40500 . # tls://dot.example\ndns_server = 127.0.0.1:40508 . # https://dns-b.example/dns-query@dnsm\n"
            }
          ]
        })";

        CHECK(extract_keenetic_dns_snapshot_from_rci(json).addresses
              == std::vector<std::string>{"127.0.0.1:40500", "127.0.0.1:40508"});
    }

    SUBCASE("prefers all unscoped dot and doh servers over plaintext servers") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "dns_server = 198.51.100.10 .\ndns_server = 127.0.0.1:40500 . # tls://dot.example\ndns_server = 127.0.0.1:40508 . # https://dns-b.example/dns-query@dnsm\n"
            }
          ]
        })";

        const KeeneticDnsSnapshot snapshot = extract_keenetic_dns_snapshot_from_rci(json);
        REQUIRE(snapshot.addresses == std::vector<std::string>{"127.0.0.1:40500", "127.0.0.1:40508"});
        REQUIRE(snapshot.upstreams.size() == 2);
        CHECK(snapshot.upstreams[0].kind == "DoT");
        CHECK(snapshot.upstreams[0].target == "tls://dot.example");
        CHECK(snapshot.upstreams[1].kind == "DoH");
        CHECK(snapshot.upstreams[1].target == "https://dns-b.example/dns-query");
    }

    SUBCASE("treats dns_server comment as the only upstream metadata source") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "rpc_port = 54321\nrr_port = 40901\ndns_server = 127.0.0.1:40500 . # 8.8.8.8@dns.google\ndns_server = 127.0.0.1:40501 . # 8.8.4.4@dns.google\ndns_server = 127.0.0.1:40508 . # https://dns.google/dns-query@dnsm\ndns_server = 127.0.0.1:40509 . # https://dns.quad9.net/dns-query@dnsm\n",
              "proxy-tls": {
                "server-tls": [
                  {
                    "address": "8.8.8.8",
                    "sni": "dns.google",
                    "spki": "",
                    "interface": "",
                    "domain": ""
                  },
                  {
                    "address": "8.8.4.4",
                    "sni": "dns.google",
                    "spki": "",
                    "interface": "",
                    "domain": ""
                  }
                ]
              },
              "proxy-https": {
                "server-https": [
                  {
                    "uri": "https://dns.google/dns-query",
                    "format": "dnsm",
                    "spki": "",
                    "interface": "",
                    "domain": ""
                  },
                  {
                    "uri": "https://dns.quad9.net/dns-query",
                    "format": "dnsm",
                    "spki": "",
                    "interface": "",
                    "domain": ""
                  }
                ]
              }
            }
          ]
        })";

        const KeeneticDnsSnapshot snapshot = extract_keenetic_dns_snapshot_from_rci(json);
        REQUIRE(snapshot.addresses == std::vector<std::string>{
                                        "127.0.0.1:40500",
                                        "127.0.0.1:40501",
                                        "127.0.0.1:40508",
                                        "127.0.0.1:40509"});
        REQUIRE(snapshot.upstreams.size() == 4);
        CHECK(snapshot.upstreams[0].kind == "DoT");
        CHECK(snapshot.upstreams[0].target == "tls://dns.google");
        CHECK(snapshot.upstreams[1].kind == "DoT");
        CHECK(snapshot.upstreams[1].target == "tls://dns.google");
        CHECK(snapshot.upstreams[2].kind == "DoH");
        CHECK(snapshot.upstreams[2].target == "https://dns.google/dns-query");
        CHECK(snapshot.upstreams[3].kind == "DoH");
        CHECK(snapshot.upstreams[3].target == "https://dns.quad9.net/dns-query");
    }

    SUBCASE("ignores ipv6 dns_server upstreams but keeps static aaaa entries") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "rpc_port = 54321\nrpc_ttl = 10000\nrpc_wait = 10000\ntimeout = 7000\nproceed = 500\nstat_file = /var/ndnproxymain.stat\nstat_time = 10000\ndns_server = 192.168.0.1 .\ndns_server = fe80::1%10 .\nstatic_a = my.keenetic.net 78.47.125.180\nstatic_aaaa = my.keenetic.net 2001:2:7847:1251:feee:ed78:4712:5180\nstatic_aaaa = host-a.keenetic.name 2001:2:7847:1251:feee:ed78:4712:5180\nstatic_a = host-a.keenetic.name 78.47.125.180\nstatic_a = ha.host-a.keenetic.name 78.47.125.180\nstatic_aaaa = ha.host-a.keenetic.name 2001:2:7847:1251:feee:ed78:4712:5180\nstatic_a = tokenized-host.keenetic.io 78.47.125.180\nstatic_aaaa = tokenized-host.keenetic.io 2001:2:7847:1251:feee:ed78:4712:5180\nnorebind_ctl = on\nnorebind_ip4net = 10.1.30.1:24\nnorebind_ip4net = 192.168.2.1:24\nnorebind_ip4net = 192.168.7.1:24\nnorebind_ip4net = 255.255.255.255:32\nset-profile-ip 127.0.0.1 0\nset-profile-ip ::1 0\ndns_tcp_port = 53\ndns_udp_port = 53\n"
            }
          ]
        })";

        const KeeneticDnsSnapshot snapshot = extract_keenetic_dns_snapshot_from_rci(json);
        REQUIRE(snapshot.addresses == std::vector<std::string>{"192.168.0.1"});
        REQUIRE(snapshot.upstreams.size() == 1);
        CHECK(snapshot.upstreams[0].address == "192.168.0.1");
        CHECK(snapshot.upstreams[0].kind == "Plain");
        REQUIRE(snapshot.static_entries.size() == 8);
        CHECK(snapshot.static_entries[0].domain == "my.keenetic.net");
        CHECK(snapshot.static_entries[0].address == "78.47.125.180");
        CHECK(snapshot.static_entries[1].domain == "my.keenetic.net");
        CHECK(snapshot.static_entries[1].address == "2001:2:7847:1251:feee:ed78:4712:5180");
    }

    SUBCASE("falls back to all unscoped plaintext servers when no unscoped encrypted servers exist") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "dns_server = 198.51.100.10 .\ndns_server = 198.51.100.11 .\ndns_server = 127.0.0.1:40500 domain.example.com # tls://dot.example\n"
            }
          ]
        })";

        const KeeneticDnsSnapshot snapshot = extract_keenetic_dns_snapshot_from_rci(json);
        REQUIRE(snapshot.addresses == std::vector<std::string>{"198.51.100.10", "198.51.100.11"});
    }

    SUBCASE("ignores domain-scoped plaintext and dot entries from real RCI payload") {
        const std::string json = R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "rpc_port = 54321\nrpc_ttl = 10000\nrpc_wait = 10000\ntimeout = 7000\nproceed = 500\nstat_file = /var/ndnproxymain.stat\nstat_time = 10000\nrr_port = 40901\ndns_server = 198.51.100.20 scoped-a.example\ndns_server = 198.51.100.21 scoped-a.example\ndns_server = 127.0.0.1:40500 domain.example.com # dot-scoped.example\ndns_server = 127.0.0.1:40508 . # https://doh-a.example/dns-query@dnsm\ndns_server = 127.0.0.1:40509 . # https://doh-b.example/dns-query@dnsm\nstatic_a = host.example 198.51.100.180 1\nnorebind_ctl = on\ndns_tcp_port = 53\ndns_udp_port = 53\n"
            },
            {
              "proxy-name": "Policy0",
              "proxy-config": "timeout = 7000\ndns_server = 127.0.0.1:40516 domain.example.com # dot-scoped.example\ndns_server = 127.0.0.1:40524 . # https://doh-a.example/dns-query@dnsm\ndns_server = 127.0.0.1:40525 . # https://doh-b.example/dns-query@dnsm\n"
            },
            {
              "proxy-name": "Policy1",
              "proxy-config": "timeout = 7000\ndns_server = 198.51.100.20 scoped-a.example\ndns_server = 198.51.100.21 scoped-a.example\ndns_server = 127.0.0.1:40532 domain.example.com # dot-scoped.example\ndns_server = 127.0.0.1:40540 . # https://doh-a.example/dns-query@dnsm\ndns_server = 127.0.0.1:40541 . # https://doh-b.example/dns-query@dnsm\n"
            }
          ]
        })";

        CHECK(extract_keenetic_dns_snapshot_from_rci(json).addresses
              == std::vector<std::string>{"127.0.0.1:40508", "127.0.0.1:40509"});
    }
}

TEST_CASE("keenetic dns: invalid RCI response is rejected") {
    SUBCASE("empty proxy-status array") {
        CHECK_THROWS_AS(extract_keenetic_dns_snapshot_from_rci(R"({"proxy-status":[]})"),
                        KeeneticDnsError);
    }

    SUBCASE("missing proxy-status array") {
        CHECK_THROWS_AS(extract_keenetic_dns_snapshot_from_rci(R"({"status":[]})"),
                        KeeneticDnsError);
    }

    SUBCASE("System policy without proxy-config string") {
        CHECK_THROWS_AS(extract_keenetic_dns_snapshot_from_rci(
                            R"({"proxy-status":[{"proxy-name":"System","proxy-config":{}}]})"),
                        KeeneticDnsError);
    }

    SUBCASE("System policy without dns_server directive") {
        CHECK_THROWS_AS(extract_keenetic_dns_snapshot_from_rci(
                            R"({"proxy-status":[{"proxy-name":"System","proxy-config":"listen = 127.0.0.1:53\ncache-size = 2048\n"}]})"),
                        KeeneticDnsError);
    }

    SUBCASE("System policy with only domain-scoped dns_server directives") {
        CHECK_THROWS_AS(extract_keenetic_dns_snapshot_from_rci(
                            R"({"proxy-status":[{"proxy-name":"System","proxy-config":"dns_server = 203.0.113.10 provider.example\ndns_server = 127.0.0.1:40500 domain.example.com # tls://resolver.example\n"}]})"),
                        KeeneticDnsError);
    }

    SUBCASE("System policy with invalid dns_server address") {
        CHECK_THROWS_AS(extract_keenetic_dns_snapshot_from_rci(
                            R"({"proxy-status":[{"proxy-name":"System","proxy-config":"dns_server = not-an-ip"}]})"),
                        KeeneticDnsError);
    }
}

TEST_CASE("keenetic dns: cache refresh semantics") {
    KeeneticDnsTestStateGuard guard;

    auto now = std::chrono::steady_clock::time_point{};
    set_keenetic_dns_now_fn_for_tests([&now]() {
        return now;
    });

    int fetch_count = 0;
    set_keenetic_dns_fetcher_for_tests([&fetch_count]() {
        ++fetch_count;
        return std::string(R"({
          "proxy-status": [
            {
              "proxy-name": "System",
              "proxy-config": "dns_server = 203.0.113.10 .\n"
            }
          ]
        })");
    });

    SUBCASE("uses cached value while ttl is fresh") {
        CHECK(resolve_keenetic_dns_addresses() == std::vector<std::string>{"203.0.113.10"});
        CHECK(fetch_count == 1);

        now += std::chrono::minutes(4);
        CHECK(resolve_keenetic_dns_addresses() == std::vector<std::string>{"203.0.113.10"});
        CHECK(fetch_count == 1);
    }

    SUBCASE("falls back to cached value when stale refresh fails") {
        const KeeneticDnsRefreshResult initial =
            refresh_keenetic_dns_address_cache(false);
        REQUIRE(initial.snapshot.has_value());
        CHECK(initial.snapshot->addresses ==
              std::vector<std::string>{"203.0.113.10"});
        CHECK(initial.generation > 0);
        CHECK(fetch_count == 1);

        now += std::chrono::minutes(6);
        set_keenetic_dns_fetcher_for_tests([&fetch_count]() -> std::string {
            ++fetch_count;
            throw KeeneticDnsError("simulated RCI outage");
        });

        const KeeneticDnsRefreshResult result = refresh_keenetic_dns_address_cache(false);
        CHECK(result.status == KeeneticDnsRefreshStatus::FETCH_FAILED_USED_CACHE);
        CHECK(result.addresses == std::vector<std::string>{"203.0.113.10"});
        REQUIRE(result.snapshot.has_value());
        CHECK(result.snapshot->addresses ==
              std::vector<std::string>{"203.0.113.10"});
        CHECK(result.generation > initial.generation);
        CHECK(fetch_count == 2);
        CHECK(resolve_keenetic_dns_addresses() == std::vector<std::string>{"203.0.113.10"});
    }

    SUBCASE("reports updated only when forced refresh changes address") {
        CHECK(resolve_keenetic_dns_addresses() == std::vector<std::string>{"203.0.113.10"});
        CHECK(fetch_count == 1);

        set_keenetic_dns_fetcher_for_tests([&fetch_count]() {
            ++fetch_count;
            return std::string(R"({
              "proxy-status": [
                {
                  "proxy-name": "System",
                  "proxy-config": "dns_server = 203.0.113.11 .\n"
                }
              ]
            })");
        });

        const KeeneticDnsRefreshResult result = refresh_keenetic_dns_address_cache(true);
        CHECK(result.status == KeeneticDnsRefreshStatus::UPDATED);
        CHECK(result.addresses == std::vector<std::string>{"203.0.113.11"});
        CHECK(resolve_keenetic_dns_addresses() == std::vector<std::string>{"203.0.113.11"});
    }

    SUBCASE("reports updated when forced refresh changes static entries") {
        const KeeneticDnsRefreshResult initial =
            refresh_keenetic_dns_address_cache(false);
        REQUIRE(initial.snapshot.has_value());
        CHECK(initial.snapshot->addresses ==
              std::vector<std::string>{"203.0.113.10"});
        CHECK(fetch_count == 1);
        CHECK(get_keenetic_static_dns_entries().empty());

        set_keenetic_dns_fetcher_for_tests([&fetch_count]() {
            ++fetch_count;
            return std::string(R"({
              "proxy-status": [
                {
                  "proxy-name": "System",
                  "proxy-config": "dns_server = 203.0.113.10 .\nstatic_a = host.example 198.51.100.180 1\n"
                }
              ]
            })");
        });

        const KeeneticDnsRefreshResult result = refresh_keenetic_dns_address_cache(true);
        CHECK(result.status == KeeneticDnsRefreshStatus::UPDATED);
        CHECK(result.addresses == std::vector<std::string>{"203.0.113.10"});
        REQUIRE(result.snapshot.has_value());
        CHECK(result.generation > initial.generation);
        CHECK(result.snapshot->addresses ==
              std::vector<std::string>{"203.0.113.10"});
        REQUIRE(result.snapshot->upstreams.size() == 1);
        CHECK(result.snapshot->upstreams[0].address == "203.0.113.10");
        CHECK(result.snapshot->upstreams[0].kind == "Plain");
        REQUIRE(result.snapshot->static_entries.size() == 1);
        CHECK(result.snapshot->static_entries[0].domain == "host.example");
        CHECK(result.snapshot->static_entries[0].address == "198.51.100.180");
        REQUIRE(get_keenetic_static_dns_entries().size() == 1);
        CHECK(get_keenetic_static_dns_entries()[0].domain == "host.example");
        CHECK(get_keenetic_static_dns_entries()[0].address == "198.51.100.180");
    }

    SUBCASE("fails without cache when initial fetch fails") {
        set_keenetic_dns_fetcher_for_tests([]() -> std::string {
            throw KeeneticDnsError("simulated initial failure");
        });

        const KeeneticDnsRefreshResult result = refresh_keenetic_dns_address_cache(true);
        CHECK(result.status == KeeneticDnsRefreshStatus::FETCH_FAILED_NO_CACHE);
        CHECK(result.addresses.empty());
        CHECK_FALSE(result.snapshot.has_value());
        CHECK(result.generation > 0);
        CHECK_THROWS_AS(resolve_keenetic_dns_addresses(true), KeeneticDnsError);
    }
}

TEST_CASE("keenetic dns cache: peek does not wait for an in-flight fetch") {
    std::promise<void> fetch_started;
    std::promise<void> release_fetch;
    auto release = release_fetch.get_future().share();

    KeeneticDnsCache cache([&]() {
        fetch_started.set_value();
        release.wait();
        return keenetic_dns_response("203.0.113.20");
    });

    auto refresh = std::async(std::launch::async, [&]() {
        return cache.force_refresh();
    });
    fetch_started.get_future().wait();

    auto peek = std::async(std::launch::async, [&]() {
        return cache.peek();
    });
    REQUIRE(peek.wait_for(std::chrono::milliseconds(100)) ==
            std::future_status::ready);
    const auto while_fetching = peek.get();
    CHECK(while_fetching.status == KeeneticDnsCacheStatus::unavailable);
    CHECK_FALSE(while_fetching.snapshot.has_value());

    release_fetch.set_value();
    const auto refreshed = refresh.get();
    REQUIRE(refreshed.snapshot.has_value());
    CHECK(refreshed.snapshot->addresses ==
          std::vector<std::string>{"203.0.113.20"});
}

TEST_CASE("keenetic dns cache: concurrent forced refreshes are single-flight") {
    std::promise<void> fetch_started;
    std::promise<void> release_fetch;
    auto release = release_fetch.get_future().share();
    int fetch_count = 0;

    KeeneticDnsCache cache([&]() {
        ++fetch_count;
        fetch_started.set_value();
        release.wait();
        return keenetic_dns_response("203.0.113.21");
    });

    auto first = std::async(std::launch::async, [&]() {
        return cache.force_refresh();
    });
    fetch_started.get_future().wait();
    auto second = std::async(std::launch::async, [&]() {
        return cache.force_refresh();
    });

    CHECK(second.wait_for(std::chrono::milliseconds(50)) ==
          std::future_status::timeout);
    release_fetch.set_value();

    const auto first_result = first.get();
    const auto second_result = second.get();
    CHECK(fetch_count == 1);
    REQUIRE(first_result.snapshot.has_value());
    REQUIRE(second_result.snapshot.has_value());
    CHECK(first_result.generation == second_result.generation);
    CHECK(first_result.snapshot->addresses ==
          std::vector<std::string>{"203.0.113.21"});
    CHECK(second_result.snapshot->addresses ==
          std::vector<std::string>{"203.0.113.21"});
}

TEST_CASE("keenetic dns cache: sequential successful forced refreshes refetch") {
    int fetch_count = 0;
    KeeneticDnsCache cache([&]() {
        ++fetch_count;
        return keenetic_dns_response(
            fetch_count == 1 ? "203.0.113.22" : "203.0.113.23");
    });

    const auto first = cache.force_refresh();
    const auto second = cache.force_refresh();

    CHECK(fetch_count == 2);
    REQUIRE(first.snapshot.has_value());
    REQUIRE(second.snapshot.has_value());
    CHECK(first.snapshot->addresses ==
          std::vector<std::string>{"203.0.113.22"});
    CHECK(second.snapshot->addresses ==
          std::vector<std::string>{"203.0.113.23"});
}

TEST_CASE("keenetic dns cache: invalidation rejects an older in-flight result") {
    std::promise<void> fetch_started;
    std::promise<void> release_fetch;
    auto release = release_fetch.get_future().share();
    int fetch_count = 0;

    KeeneticDnsCache cache([&]() {
        ++fetch_count;
        if (fetch_count == 1) {
            fetch_started.set_value();
            release.wait();
            return keenetic_dns_response("203.0.113.30");
        }
        return keenetic_dns_response("203.0.113.31");
    });

    auto old_refresh = std::async(std::launch::async, [&]() {
        return cache.force_refresh();
    });
    fetch_started.get_future().wait();
    cache.invalidate();

    auto current_refresh = std::async(std::launch::async, [&]() {
        return cache.get();
    });
    CHECK(current_refresh.wait_for(std::chrono::milliseconds(50)) ==
          std::future_status::timeout);

    release_fetch.set_value();
    (void)old_refresh.get();
    const auto current_result = current_refresh.get();
    CHECK(fetch_count == 2);
    REQUIRE(current_result.snapshot.has_value());
    CHECK(current_result.snapshot->addresses ==
          std::vector<std::string>{"203.0.113.31"});
    CHECK(current_result.status == KeeneticDnsCacheStatus::fresh);
}

TEST_CASE("keenetic dns cache: failed refresh keeps LKG and is retry-throttled") {
    auto now = KeeneticDnsCache::Clock::time_point{};
    int fetch_count = 0;
    KeeneticDnsCache cache(
        [&]() {
            ++fetch_count;
            if (fetch_count == 1) {
                return keenetic_dns_response("203.0.113.40");
            }
            throw KeeneticDnsError("simulated RCI outage");
        },
        std::chrono::minutes(5),
        std::chrono::seconds(5),
        [&]() { return now; });

    REQUIRE(cache.get().snapshot.has_value());
    now += std::chrono::minutes(6);

    const auto failed = cache.get();
    CHECK(fetch_count == 2);
    CHECK(failed.status == KeeneticDnsCacheStatus::stale);
    REQUIRE(failed.snapshot.has_value());
    CHECK(failed.snapshot->addresses ==
          std::vector<std::string>{"203.0.113.40"});
    CHECK(failed.error == "simulated RCI outage");

    const auto throttled = cache.get();
    CHECK(fetch_count == 2);
    CHECK(throttled.status == KeeneticDnsCacheStatus::stale);

    now += std::chrono::seconds(5);
    (void)cache.get();
    CHECK(fetch_count == 3);
}

#ifndef USE_KEENETIC_API
TEST_CASE("config: type=keenetic rejected when feature disabled") {
    const std::string json = R"({
      "dns": {
        "servers": [
          {"tag": "keenetic-dns", "type": "keenetic"}
        ]
      }
    })";
    CHECK_THROWS_AS(parse_and_validate_config(json), ConfigValidationError);
}
#endif
