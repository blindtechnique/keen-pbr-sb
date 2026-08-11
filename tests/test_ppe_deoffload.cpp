#include <doctest/doctest.h>

#include "firewall/ppe_deoffload.hpp"

#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

// Exactly the contract measured on a live Keenetic: PPE target registered,
// connskip present, ppe_enabled=1, NFQUEUE rules in mangle, nfqws2 running.
PpeDeoffloadInputs measured_router() {
    PpeDeoffloadInputs inputs;
    inputs.ppe_target_available = true;
    inputs.connskip_match_available = true;
    inputs.backend = FirewallBackend::iptables;
    inputs.nfqueue_active = true;
    inputs.ppe_sysctl_enabled = true;
    inputs.tcp_ports = {"80", "443", "8443"};
    inputs.quic_ports = {"443", "49152:65535"};
    return inputs;
}

} // namespace

TEST_CASE("the measured live contract is admissible") {
    const auto assessment = evaluate_ppe_deoffload(measured_router());

    CHECK(assessment.state == PpeDeoffloadState::admissible);
    CHECK(assessment.tcp_eligible);
    CHECK(assessment.quic_eligible);
}

TEST_CASE("every precondition is required on its own") {
    SUBCASE("no PPE target") {
        auto inputs = measured_router();
        inputs.ppe_target_available = false;
        CHECK(evaluate_ppe_deoffload(inputs).state ==
              PpeDeoffloadState::ppe_target_missing);
    }
    SUBCASE("no connskip match") {
        auto inputs = measured_router();
        inputs.connskip_match_available = false;
        // Without it the only alternative would be disabling offload
        // wholesale, which is explicitly not on the table.
        CHECK(evaluate_ppe_deoffload(inputs).state ==
              PpeDeoffloadState::connskip_match_missing);
    }
    SUBCASE("nftables backend") {
        auto inputs = measured_router();
        inputs.backend = FirewallBackend::nftables;
        CHECK(evaluate_ppe_deoffload(inputs).state ==
              PpeDeoffloadState::backend_incompatible);
    }
    SUBCASE("nothing being enqueued") {
        auto inputs = measured_router();
        inputs.nfqueue_active = false;
        CHECK(evaluate_ppe_deoffload(inputs).state ==
              PpeDeoffloadState::nfqueue_inactive);
    }
    SUBCASE("PPE already off") {
        auto inputs = measured_router();
        inputs.ppe_sysctl_enabled = false;
        CHECK(evaluate_ppe_deoffload(inputs).state ==
              PpeDeoffloadState::ppe_already_disabled);
    }
}

TEST_CASE("PPE already off never becomes a reason to switch it on") {
    auto inputs = measured_router();
    inputs.ppe_sysctl_enabled = false;

    const auto assessment = evaluate_ppe_deoffload(inputs);

    // The assessment reports and stops. Turning hardware acceleration back on
    // to make our own feature applicable would be a system-wide change nobody
    // asked for, and the roadmap says the sysctl stays as it is.
    CHECK(assessment.state == PpeDeoffloadState::ppe_already_disabled);
    CHECK_FALSE(assessment.tcp_eligible);
    CHECK_FALSE(assessment.quic_eligible);
}

TEST_CASE("TCP and QUIC are decided independently") {
    SUBCASE("only TCP ports") {
        auto inputs = measured_router();
        inputs.quic_ports.clear();
        const auto assessment = evaluate_ppe_deoffload(inputs);
        CHECK(assessment.state == PpeDeoffloadState::admissible);
        CHECK(assessment.tcp_eligible);
        // One having ports must not enable the other.
        CHECK_FALSE(assessment.quic_eligible);
    }
    SUBCASE("only QUIC ports") {
        auto inputs = measured_router();
        inputs.tcp_ports.clear();
        const auto assessment = evaluate_ppe_deoffload(inputs);
        CHECK(assessment.state == PpeDeoffloadState::admissible);
        CHECK_FALSE(assessment.tcp_eligible);
        CHECK(assessment.quic_eligible);
    }
}

TEST_CASE("no ports at all is a refusal, not an empty success") {
    auto inputs = measured_router();
    inputs.tcp_ports.clear();
    inputs.quic_ports.clear();

    const auto assessment = evaluate_ppe_deoffload(inputs);

    // Empty is not the same as "no ports needed": it means we could not read
    // the active strategy, and de-offloading for a port set nfqws2 no longer
    // watches is throughput lost for nothing.
    CHECK(assessment.state == PpeDeoffloadState::strategy_ports_unavailable);
    CHECK_FALSE(assessment.tcp_eligible);
    CHECK_FALSE(assessment.quic_eligible);
}

TEST_CASE("every refusal explains itself") {
    const std::vector<PpeDeoffloadInputs> refusals = [] {
        std::vector<PpeDeoffloadInputs> cases;
        auto no_target = measured_router();
        no_target.ppe_target_available = false;
        cases.push_back(no_target);
        auto no_match = measured_router();
        no_match.connskip_match_available = false;
        cases.push_back(no_match);
        auto nft = measured_router();
        nft.backend = FirewallBackend::nftables;
        cases.push_back(nft);
        auto idle = measured_router();
        idle.nfqueue_active = false;
        cases.push_back(idle);
        return cases;
    }();

    for (const auto& inputs : refusals) {
        const auto assessment = evaluate_ppe_deoffload(inputs);
        CHECK(assessment.state != PpeDeoffloadState::admissible);
        // A refusal an operator cannot act on is only marginally better than
        // silence.
        CHECK_FALSE(assessment.detail.empty());
    }
}

TEST_CASE("state names are stable for reporting") {
    CHECK(std::string(ppe_deoffload_state_name(
              PpeDeoffloadState::admissible)) == "admissible");
    CHECK(std::string(ppe_deoffload_state_name(
              PpeDeoffloadState::ppe_already_disabled)) ==
          "ppe_already_disabled");
    CHECK(std::string(ppe_deoffload_state_name(
              PpeDeoffloadState::strategy_ports_unavailable)) ==
          "strategy_ports_unavailable");
}

} // namespace keen_pbr3
