#include <doctest/doctest.h>

#include "firewall/firewall_cleanup_absence.hpp"

#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

FirewallOwnedCleanupProbeView complete(
    std::string_view source,
    std::string_view output = {}) {
    return {source, true, output};
}

FirewallOwnedCleanupInspection inspect(
    std::vector<FirewallOwnedCleanupProbeView> tables,
    FirewallOwnedCleanupProbeView ipsets = complete("ipset list -name"),
    FirewallOwnedMarkerObservation marker =
        FirewallOwnedMarkerObservation::absent) {
    return inspect_iptables_owned_cleanup_absence(
        tables, ipsets, marker);
}

} // namespace

TEST_CASE("complete empty firewall inventory proves strict cleanup") {
    const auto result = inspect({
        complete("iptables raw"),
        complete("iptables mangle", "-P PREROUTING ACCEPT\n"),
        complete("iptables filter"),
        complete("iptables nat"),
        complete("ip6tables raw"),
        complete("ip6tables mangle"),
        complete("ip6tables filter"),
        complete("ip6tables nat"),
    });
    CHECK(result.verified_absent());
    CHECK(result.detail.empty());
}

TEST_CASE("any incomplete table or ipset observation fails closed") {
    auto result = inspect({{"iptables mangle", false, {}}});
    CHECK(result.state == FirewallOwnedCleanupState::observation_failed);
    CHECK_FALSE(result.verified_absent());

    result = inspect(
        {complete("iptables mangle")},
        {"ipset list -name", false, {}});
    CHECK(result.state == FirewallOwnedCleanupState::observation_failed);
}

TEST_CASE("owned chains NAT and exact reset residue block cleanup proof") {
    for (const auto residue : {
             "-N KeenPbrTable\n",
             "-N KeenPbrDnsRdr\n",
             "-N KeenPbrSnat\n",
             "-N KeenPbrTcpRst\n",
             "-A PREROUTING -j KeenPbrRaw\n",
             "-N KpPpeV1a2b\n",
         }) {
        const auto result = inspect({complete("iptables", residue)});
        CHECK(result.state ==
              FirewallOwnedCleanupState::owned_artifacts_present);
    }
}

TEST_CASE("TTL and PPE hooks in firmware-owned chains block proof") {
    for (const auto residue : {
             "-A _NDM_POSTROUTING_TTL -m comment --comment "
             "keen-pbr-sb:ttl-bypass -j RETURN\n",
             "-A PREROUTING -m comment --comment "
             "keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4\n",
         }) {
        const auto result = inspect({complete("iptables mangle", residue)});
        CHECK(result.state ==
              FirewallOwnedCleanupState::owned_artifacts_present);
    }
}

TEST_CASE("all managed ipset generations and classes block proof") {
    for (const auto name : {
             "kpbr4_list", "kpbr6_list",
             "kpbr4s_list", "kpbr6s_list",
             "kpbr4S_list", "kpbr6S_list",
             "kpbr4d_list", "kpbr6d_list",
             "kpbr4m_list", "kpbr6m_list",
         }) {
        const std::string inventory = std::string{name} + "\n";
        const auto result = inspect(
            {complete("iptables mangle")},
            complete("ipset list -name", inventory));
        CHECK(result.state ==
              FirewallOwnedCleanupState::owned_artifacts_present);
    }

    const auto unrelated = inspect(
        {complete("iptables mangle")},
        complete("ipset list -name", "user_set\r\n"));
    CHECK(unrelated.verified_absent());
}

TEST_CASE("PPE marker remains ownership and invalid marker is ambiguity") {
    auto result = inspect(
        {complete("iptables mangle")},
        complete("ipset list -name"),
        FirewallOwnedMarkerObservation::present);
    CHECK(result.state ==
          FirewallOwnedCleanupState::owned_artifacts_present);

    result = inspect(
        {complete("iptables mangle")},
        complete("ipset list -name"),
        FirewallOwnedMarkerObservation::invalid);
    CHECK(result.state == FirewallOwnedCleanupState::observation_failed);
}

TEST_CASE("nft absence proof rejects missing executable and incomplete reads") {
    CHECK(nft_owned_table_absence_proven(
        1, false, false, false,
        "Error: No such file or directory"));
    CHECK(nft_owned_table_absence_proven(
        1, false, false, false,
        "table inet KeenPbrTable does not exist"));
    CHECK(nft_owned_table_absence_proven(
        1, false, false, false,
        "table inet KeenPbrTable not found"));

    CHECK_FALSE(nft_owned_table_absence_proven(
        127, false, false, false,
        "nft: not found"));
    CHECK_FALSE(nft_owned_table_absence_proven(
        1, true, false, false,
        "No such file or directory"));
    CHECK_FALSE(nft_owned_table_absence_proven(
        1, false, true, false,
        "No such file or directory"));
    CHECK_FALSE(nft_owned_table_absence_proven(
        1, false, false, true,
        "No such file or directory"));
    CHECK_FALSE(nft_owned_table_absence_proven(
        0, false, false, false, {}));
    CHECK_FALSE(nft_owned_table_absence_proven(
        1, false, false, false,
        "unrelated object not found"));
}

TEST_CASE("iptables table proof accepts exact unsupported table only") {
    CHECK(iptables_owned_table_probe_complete(
        0, false, false, false, false));
    CHECK(iptables_owned_table_probe_complete(
        3, false, false, false, true));

    CHECK_FALSE(iptables_owned_table_probe_complete(
        127, false, false, false, true));
    CHECK_FALSE(iptables_owned_table_probe_complete(
        3, false, false, false, false));
    CHECK_FALSE(iptables_owned_table_probe_complete(
        3, true, false, false, true));
    CHECK_FALSE(iptables_owned_table_probe_complete(
        3, false, true, false, true));
    CHECK_FALSE(iptables_owned_table_probe_complete(
        3, false, false, true, true));
}
