#include <doctest/doctest.h>

#include "../src/firewall/firewall_runtime.hpp"

#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

InternalVpnRuntimeTarget service_target(
    std::string stable_id,
    bool process_clients,
    std::vector<std::string> source_cidrs_v4,
    std::vector<std::string> source_cidrs_v6 = {}) {
    InternalVpnRuntimeTarget target;
    target.stable_id = std::move(stable_id);
    target.match_kind = InternalVpnRuntimeMatchKind::source_pool;
    target.process_clients = process_clients;
    target.source_cidrs_v4 = std::move(source_cidrs_v4);
    target.source_cidrs_v6 = std::move(source_cidrs_v6);
    return target;
}

} // namespace

TEST_CASE(
    "SSTP direct egress selection covers both policy modes and deduplicates") {
    const auto disabled = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/false,
        {"172.16.1.33/32", "172.16.1.34/31", ""});
    const auto enabled = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/true,
        {"172.16.1.33/32", "172.16.1.36/30"});

    const auto selectors = select_sstp_direct_egress_snat_selectors(
        {disabled, enabled},
        {"eth3", "eth3", "", "ppp0"});

    CHECK(
        selectors ==
        std::vector<FirewallSourceEgressSnatSelector>{
            {"eth3", "172.16.1.33/32"},
            {"eth3", "172.16.1.34/31"},
            {"eth3", "172.16.1.36/30"},
            {"ppp0", "172.16.1.33/32"},
            {"ppp0", "172.16.1.34/31"},
            {"ppp0", "172.16.1.36/30"},
        });
}

TEST_CASE(
    "SSTP direct egress selection is exact and leaves IKE out of scope") {
    const auto ikev2 = service_target(
        "ndms-crypto-map:ikev2:VirtualIPServerIKE2",
        /*process_clients=*/true,
        {"172.20.8.0/23"});
    const auto similarly_named = service_target(
        "ndms-service:sstp-server-backup",
        /*process_clients=*/false,
        {"172.30.0.0/24"});
    const auto sstp_ipv6_only = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/true,
        {},
        {"2001:db8:16::/64"});

    CHECK(
        select_sstp_direct_egress_snat_selectors(
            {ikev2, similarly_named, sstp_ipv6_only},
            {"eth3"})
            .empty());

    // The selection is source-scoped to SSTP; it neither consumes nor mutates
    // the established IKEv2 runtime target.
    CHECK(ikev2.stable_id ==
          "ndms-crypto-map:ikev2:VirtualIPServerIKE2");
    CHECK(ikev2.source_cidrs_v4 ==
          std::vector<std::string>{"172.20.8.0/23"});
    CHECK(ikev2.process_clients);
}

TEST_CASE("SSTP direct egress selection requires a current WAN") {
    const auto sstp = service_target(
        "ndms-service:sstp-server",
        /*process_clients=*/false,
        {"172.16.1.33/32"});

    CHECK(
        select_sstp_direct_egress_snat_selectors({sstp}, {}).empty());
}
