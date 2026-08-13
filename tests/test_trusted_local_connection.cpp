#include <doctest/doctest.h>

#include "api/trusted_local_connection.hpp"

#include <chrono>
#include <optional>
#include <string>

using namespace keen_pbr3;

namespace {

TrustedLocalConnectionSnapshot ipv4_snapshot() {
    return {
        {"192.168.50.1"},
        {{"br0", "192.168.50.1", "255.255.255.0", true, false}},
    };
}

std::optional<TrustedLocalRouteProof> ipv4_route(
    const std::string_view remote = "192.168.50.24",
    const std::string_view local = "192.168.50.1") {
    return TrustedLocalRouteProof{
        std::string{local}, std::string{remote}, "br0", true, true};
}

} // namespace

TEST_CASE("trusted local connection requires exact NDMS and same-link proof") {
    const auto snapshot = ipv4_snapshot();
    CHECK(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.1", false, snapshot, ipv4_route()));
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.51.24", "192.168.50.1", false, snapshot,
        ipv4_route("192.168.51.24")));
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.2", false, snapshot,
        ipv4_route("192.168.50.24", "192.168.50.2")));

    auto down = snapshot;
    down.interface_addresses.front().up = false;
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.1", false, down, ipv4_route()));

    auto ambiguous = snapshot;
    ambiguous.interface_addresses.push_back(
        {"eth9", "192.168.50.1", "255.255.255.0", true, false});
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.1", false, ambiguous,
        ipv4_route()));
}

TEST_CASE("trusted local connection requires a direct link route on the same interface") {
    const auto snapshot = ipv4_snapshot();
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.1", false, snapshot, std::nullopt));

    auto route = *ipv4_route();
    route.interface_name = "wg0";
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.1", false, snapshot, route));
    route = *ipv4_route();
    route.direct = false;
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.1", false, snapshot, route));
    route = *ipv4_route();
    route.scope_allows_connected_prefix = false;
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.1", false, snapshot, route));
    route = *ipv4_route();
    route.source_address = "192.168.50.2";
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.1", false, snapshot, route));
}

TEST_CASE("private ranges, CGNAT and forwarding headers grant no authority") {
    const auto snapshot = ipv4_snapshot();
    CHECK_FALSE(trusted_local_connection_is_proven(
        "10.0.0.24", "10.0.0.1", false, snapshot,
        ipv4_route("10.0.0.24", "10.0.0.1")));
    CHECK_FALSE(trusted_local_connection_is_proven(
        "100.64.0.24", "100.64.0.1", false, snapshot,
        ipv4_route("100.64.0.24", "100.64.0.1")));
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.1", true, snapshot, ipv4_route()));
    CHECK_FALSE(trusted_local_connection_is_proven(
        "192.168.50.24", "192.168.50.1", false, {}, ipv4_route()));
}

TEST_CASE("IPv6 and mapped IPv4 peers use the proven interface network") {
    const TrustedLocalConnectionSnapshot ipv6{
        {"fd42:1::1"},
        {{"br1", "fd42:1::1", "ffff:ffff:ffff:ffff::", true, false}},
    };
    CHECK(trusted_local_connection_is_proven(
        "fd42:1::25", "fd42:1::1", false, ipv6,
        TrustedLocalRouteProof{
            "fd42:1::1", "fd42:1::25", "br1", true, true}));
    CHECK_FALSE(trusted_local_connection_is_proven(
        "fd42:2::25", "fd42:1::1", false, ipv6,
        TrustedLocalRouteProof{
            "fd42:1::1", "fd42:2::25", "br1", true, true}));

    CHECK(trusted_local_connection_is_proven(
        "::ffff:192.168.50.24",
        "::ffff:192.168.50.1",
        false,
        ipv4_snapshot(),
        TrustedLocalRouteProof{
            "192.168.50.1", "192.168.50.24", "br0", true, true}));
}

TEST_CASE("loopback and link-local peers never grant browser import authority") {
    CHECK_FALSE(trusted_local_connection_is_proven(
        "127.0.0.1", "127.0.0.1", false, {}, std::nullopt));
    CHECK_FALSE(trusted_local_connection_is_proven(
        "::1", "::1", false, {}, std::nullopt));
    CHECK_FALSE(trusted_local_connection_is_proven(
        "169.254.1.2", "169.254.1.1", false, ipv4_snapshot(),
        TrustedLocalRouteProof{
            "169.254.1.1", "169.254.1.2", "br0", true, true}));
    CHECK_FALSE(trusted_local_connection_is_proven(
        "fe80::2", "fe80::1", false, {},
        TrustedLocalRouteProof{
            "fe80::1", "fe80::2", "br0", true, true}));
}

TEST_CASE("trusted local discovery is cached for a bounded TTL") {
    using namespace std::chrono_literals;
    auto now = TrustedLocalConnectionCache::Clock::time_point{};
    int loads = 0;
    TrustedLocalConnectionCache cache(
        [&]() -> std::optional<TrustedLocalConnectionSnapshot> {
            ++loads;
            return ipv4_snapshot();
        },
        60s,
        [&] { return now; },
        [](const std::string_view remote,
           const std::string_view local) {
            return ipv4_route(remote, local);
        });

    auto decision =
        cache.evaluate("192.168.50.24", "192.168.50.1", false);
    CHECK(decision.trusted);
    CHECK(decision.evidence_generation == 1U);
    CHECK(decision.valid_for == 60s);
    decision = cache.evaluate("192.168.50.25", "192.168.50.1", false);
    CHECK(decision.trusted);
    CHECK(decision.evidence_generation == 1U);
    CHECK(loads == 1);
    now += 59s;
    decision = cache.evaluate("192.168.50.26", "192.168.50.1", false);
    CHECK(decision.trusted);
    CHECK(decision.valid_for == 1s);
    CHECK(loads == 1);
    now += 1s;
    decision = cache.evaluate("192.168.50.27", "192.168.50.1", false);
    CHECK(decision.trusted);
    CHECK(decision.evidence_generation == 2U);
    CHECK(loads == 2);

    // An attacker-controlled forwarding header is denied before the loader.
    cache.invalidate();
    CHECK_FALSE(cache.evaluate(
        "192.168.50.24", "192.168.50.1", true).trusted);
    CHECK(loads == 2);
}

TEST_CASE("WAN, forwarded and expired evidence fail before credential use") {
    using namespace std::chrono_literals;
    auto now = TrustedLocalConnectionCache::Clock::time_point{};
    int loads = 0;
    int routes = 0;
    bool direct_lan_route = false;
    TrustedLocalConnectionCache cache(
        [&]() -> std::optional<TrustedLocalConnectionSnapshot> {
            ++loads;
            return ipv4_snapshot();
        },
        60s,
        [&] { return now; },
        [&](const std::string_view remote,
            const std::string_view local)
            -> std::optional<TrustedLocalRouteProof> {
            ++routes;
            return direct_lan_route ? ipv4_route(remote, local)
                                    : std::nullopt;
        });

    // A WAN/gateway route is rejected without spending an NDMS read.
    CHECK_FALSE(cache.evaluate(
        "203.0.113.24", "203.0.113.1", false, true).trusted);
    CHECK(routes == 1);
    CHECK(loads == 0);

    // Forwarding identity headers are denied before route or NDMS lookup.
    CHECK_FALSE(cache.evaluate(
        "192.168.50.24", "192.168.50.1", true, true).trusted);
    CHECK(routes == 1);
    CHECK(loads == 0);

    direct_lan_route = true;
    auto decision = cache.evaluate(
        "192.168.50.24", "192.168.50.1", false, true);
    CHECK(decision.trusted);
    CHECK(decision.valid_for == 5s);
    CHECK(loads == 1);
    const auto first_generation = decision.evidence_generation;

    // Credential-bearing requests share evidence inside the five-second
    // anti-flood freshness window.
    decision = cache.evaluate(
        "192.168.50.24", "192.168.50.1", false, true);
    CHECK(decision.trusted);
    CHECK(decision.valid_for == 5s);
    CHECK(loads == 1);
    CHECK(decision.evidence_generation == first_generation);

    now += 5s;
    decision = cache.evaluate(
        "192.168.50.24", "192.168.50.1", false, true);
    CHECK(decision.trusted);
    CHECK(decision.valid_for == 5s);
    CHECK(loads == 2);
    CHECK(decision.evidence_generation > first_generation);

    now += 60s;
    direct_lan_route = false;
    CHECK_FALSE(cache.evaluate(
        "192.168.50.24", "192.168.50.1", false).trusted);
}
