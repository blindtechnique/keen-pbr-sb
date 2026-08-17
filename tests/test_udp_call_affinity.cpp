#include <doctest/doctest.h>

#include "runtime/udp_call_affinity.hpp"

#include <chrono>
#include <set>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

ConntrackExactForwardedFlow udp_flow(
    std::string destination,
    std::uint16_t destination_port,
    std::uint32_t mark,
    std::uint64_t original_packets,
    std::uint64_t original_bytes,
    std::uint64_t reply_packets = 0U,
    std::uint64_t reply_bytes = 0U,
    bool assured = false,
    bool seen_reply = false,
    std::string source = "192.168.1.44") {
    ConntrackExactForwardedFlow flow;
    flow.family = ConntrackFlowFamily::Ipv4;
    flow.protocol = ConntrackFlowProtocol::Udp;
    flow.source = std::move(source);
    flow.destination = std::move(destination);
    flow.source_port = static_cast<std::uint16_t>(
        30000U + destination_port % 20000U);
    flow.destination_port = destination_port;
    flow.mark = mark;
    flow.original = {original_packets, original_bytes};
    flow.reply = {reply_packets, reply_bytes};
    flow.assured = assured;
    flow.seen_reply = seen_reply;
    return flow;
}

ConntrackExactForwardedFlow seed(std::uint64_t packets,
                                 std::uint64_t reply_packets) {
    return udp_flow(
        "157.240.253.142",
        443,
        0x00070000U,
        packets,
        packets * 900U,
        reply_packets,
        reply_packets * 700U,
        true,
        true);
}

ConntrackExactForwardedFlow tcp_seed(
    std::uint64_t packets,
    std::uint64_t reply_packets,
    ConntrackTcpState state = ConntrackTcpState::Established) {
    auto flow = seed(packets, reply_packets);
    flow.protocol = ConntrackFlowProtocol::Tcp;
    flow.tcp_state = state;
    return flow;
}

std::vector<ConntrackExactForwardedFlow> call_candidates(
    std::uint64_t packets) {
    return {
        udp_flow("64.176.66.4", 443, 0U, packets, packets * 1200U),
        udp_flow("13.38.106.0", 53, 0U, packets, packets * 1200U),
        udp_flow("37.46.119.30", 22, 0U, packets, packets * 1200U),
        udp_flow("130.195.209.69", 554, 0U, packets, packets * 1200U),
    };
}

std::vector<ConntrackExactForwardedFlow> call_candidates(
    std::uint64_t packets,
    std::size_t count) {
    auto flows = call_candidates(packets);
    flows.resize(count);
    return flows;
}

const IdleStallScanStatus trustworthy_status{};
const IdleStallEpoch epoch{7U, 3U};
const std::vector<UdpCallAffinityTarget> targets{
    {"meta_whatsapp_ip", 0x00070000U}};

} // namespace

TEST_CASE("four peers need two correlated burst observations") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};

    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(3U),
        start).empty());

    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(5U),
        start + std::chrono::seconds{5}).empty());
    CHECK(detector.needs_fast_followup(
        start + std::chrono::seconds{5}));

    const auto decisions = detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(7U),
        start + std::chrono::seconds{7});

    REQUIRE(decisions.size() == 4U);
    std::set<std::uint16_t> ports;
    for (const auto& decision : decisions) {
        CHECK(decision.source == "192.168.1.44");
        CHECK(decision.list_name == "meta_whatsapp_ip");
        CHECK(decision.fwmark == 0x00070000U);
        CHECK_FALSE(decision.refresh_only);
        REQUIRE(decision.baseline_flows.size() == 1U);
        CHECK(decision.destination_port ==
              decision.baseline_flows.front().destination_port);
        ports.insert(
            decision.baseline_flows.front().destination_port);
    }
    CHECK(ports == std::set<std::uint16_t>{22U, 53U, 443U, 554U});
    CHECK_FALSE(detector.needs_fast_followup(
        start + std::chrono::seconds{7}));
}

TEST_CASE("first UDP seed snapshot survives a completed signalling burst") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};

    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(3U),
        start).empty());
    CHECK(detector.needs_fast_followup(start));

    // The trusted :443 counters no longer move, but the exact unanswered
    // probes continue. The provisional first snapshot must keep only the
    // bounded observation context, then require two fresh peer bursts.
    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(5U),
        start + std::chrono::seconds{2}).empty());
    const auto decisions = detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(7U),
        start + std::chrono::seconds{4});
    REQUIRE(decisions.size() == 4U);
}

TEST_CASE("first TCP seed snapshot survives a completed signalling burst") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};

    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {tcp_seed(10U, 12U)}, call_candidates(3U), start).empty());
    CHECK(detector.needs_fast_followup(start));
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {tcp_seed(10U, 12U)}, call_candidates(5U),
        start + std::chrono::seconds{2}).empty());
    const auto decisions = detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {tcp_seed(10U, 12U)}, call_candidates(7U),
        start + std::chrono::seconds{4});
    REQUIRE(decisions.size() == 4U);
}

TEST_CASE("one two and three peer calls promote after three bursts") {
    const auto start = UdpCallAffinityDetector::TimePoint{};
    for (std::size_t peer_count = 1U; peer_count <= 3U; ++peer_count) {
        CAPTURE(peer_count);
        UdpCallAffinityDetector detector;
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(10U, 12U)}, call_candidates(3U, peer_count),
            start).empty());
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(5U, peer_count),
            start + std::chrono::seconds{5}).empty());
        CHECK(detector.needs_fast_followup(
            start + std::chrono::seconds{5}));
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(7U, peer_count),
            start + std::chrono::seconds{7}).empty());
        CHECK(detector.needs_fast_followup(
            start + std::chrono::seconds{7}));

        const auto decisions = detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(9U, peer_count),
            start + std::chrono::seconds{9});
        CHECK(decisions.size() == peer_count);
        CHECK_FALSE(detector.needs_fast_followup(
            start + std::chrono::seconds{9}));
    }
}

TEST_CASE("progressing ordinary WhatsApp messages do not grant call affinity") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(3U, 2U),
        start);

    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(30U, 32U)},
        call_candidates(6U, 2U),
        start + std::chrono::seconds{5}).empty());
    CHECK(detector.needs_fast_followup(
        start + std::chrono::seconds{5}));

    // The unrelated retries stop growing on the next observation. That break
    // discards their partial confirmation even though messaging itself keeps
    // the authoritative seed busy.
    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(40U, 42U)},
        {},
        start + std::chrono::seconds{7}).empty());
    CHECK_FALSE(detector.needs_fast_followup(
        start + std::chrono::seconds{7}));
}

TEST_CASE("four low-volume UDP retries do not look like a call burst") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    auto initial = call_candidates(3U);
    for (auto& flow : initial) {
        flow.original.bytes = 300U;
    }
    detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        initial,
        start);

    auto low_volume = initial;
    for (auto& flow : low_volume) {
        ++flow.original.packets;
        flow.original.bytes += 32U;
    }
    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(30U, 32U)},
        low_volume,
        start + std::chrono::seconds{5}).empty());
    CHECK_FALSE(detector.needs_fast_followup(
        start + std::chrono::seconds{5}));
}

TEST_CASE("small one-packet call probes can build a sustained streak") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    const auto probe = [](std::uint64_t packets) {
        auto flow = udp_flow(
            "64.176.66.4", 443, 0U, packets, packets * 96U);
        return std::vector<ConntrackExactForwardedFlow>{std::move(flow)};
    };

    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(10U, 12U)}, probe(1U), start).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, probe(2U),
        start + std::chrono::seconds{5}).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, probe(3U),
        start + std::chrono::seconds{7}).empty());
    const auto decisions = detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, probe(4U),
        start + std::chrono::seconds{9});
    REQUIRE(decisions.size() == 1U);
    CHECK(decisions.front().destination == "64.176.66.4");
}

TEST_CASE("sparse call probes retain a bounded streak across quiet scans") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    const auto probe = [](std::uint64_t packets) {
        return std::vector<ConntrackExactForwardedFlow>{udp_flow(
            "64.176.66.4", 3478U, 0U, packets, packets * 96U)};
    };

    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(10U, 12U)}, probe(1U), start).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, probe(2U),
        start + std::chrono::seconds{5}).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, probe(2U),
        start + std::chrono::seconds{7}).empty());
    CHECK(detector.needs_fast_followup(
        start + std::chrono::seconds{7}));
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, probe(3U),
        start + std::chrono::seconds{10}).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, probe(3U),
        start + std::chrono::seconds{12}).empty());
    const auto decisions = detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, probe(4U),
        start + std::chrono::seconds{15});
    REQUIRE(decisions.size() == 1U);
    CHECK(decisions.front().destination_port == 3478U);
}

TEST_CASE("same peer address keeps UDP destination ports independent") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    const auto peers = [](std::uint64_t packets) {
        return std::vector<ConntrackExactForwardedFlow>{
            udp_flow("64.176.66.4", 3478U, 0U, packets, packets * 96U),
            udp_flow("64.176.66.4", 3479U, 0U, packets, packets * 96U),
        };
    };

    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(10U, 12U)}, peers(1U), start).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, peers(2U),
        start + std::chrono::seconds{5}).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, peers(3U),
        start + std::chrono::seconds{7}).empty());
    const auto decisions = detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, peers(4U),
        start + std::chrono::seconds{9});
    REQUIRE(decisions.size() == 2U);
    std::set<std::uint16_t> ports;
    for (const auto& decision : decisions) {
        ports.insert(decision.destination_port);
    }
    CHECK(ports == std::set<std::uint16_t>{3478U, 3479U});
}

TEST_CASE("replied port does not authorize or veto an unanswered peer port") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    const auto peers = [](std::uint64_t packets) {
        auto replied = udp_flow(
            "64.176.66.4", 3478U, 0U, packets, packets * 96U,
            packets, packets * 80U, true, true);
        auto unanswered = udp_flow(
            "64.176.66.4", 3479U, 0U, packets, packets * 96U);
        return std::vector<ConntrackExactForwardedFlow>{
            std::move(replied), std::move(unanswered)};
    };

    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(10U, 12U)}, peers(1U), start).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, peers(2U),
        start + std::chrono::seconds{5}).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, peers(3U),
        start + std::chrono::seconds{7}).empty());
    const auto decisions = detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, peers(4U),
        start + std::chrono::seconds{9});
    REQUIRE(decisions.size() == 1U);
    CHECK(decisions.front().destination_port == 3479U);
}

TEST_CASE("foreign mark bits coexist with owned WhatsApp affinity") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    constexpr std::uint32_t foreign = 0x01000000U;
    const auto marked_seed = [](std::uint64_t packets,
                                std::uint64_t replies) {
        auto flow = seed(packets, replies);
        flow.mark |= foreign;
        return flow;
    };
    const auto candidate = [](std::uint64_t packets) {
        return std::vector<ConntrackExactForwardedFlow>{udp_flow(
            "64.176.66.4", 3478U, foreign,
            packets, packets * 96U)};
    };

    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {marked_seed(10U, 12U)}, candidate(1U), start).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {marked_seed(16U, 18U)}, candidate(2U),
        start + std::chrono::seconds{5}).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {marked_seed(16U, 18U)}, candidate(3U),
        start + std::chrono::seconds{7}).empty());
    const auto decisions = detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {marked_seed(16U, 18U)}, candidate(4U),
        start + std::chrono::seconds{9});
    REQUIRE(decisions.size() == 1U);
    CHECK(decisions.front().fwmark == 0x00070000U);
    REQUIRE(decisions.front().baseline_flows.size() == 1U);
    CHECK(decisions.front().baseline_flows.front().mark == foreign);
}

TEST_CASE("overlapping semantic views are charged once to the detector cap") {
    UdpCallAffinityDetectorOptions options;
    options.max_tracked_flows = 2U;
    UdpCallAffinityDetector detector{options};
    const auto start = UdpCallAffinityDetector::TimePoint{};
    const auto source_view = [](std::uint64_t seed_packets,
                                std::uint64_t replies,
                                std::uint64_t candidate_packets) {
        return std::vector<ConntrackExactForwardedFlow>{
            seed(seed_packets, replies),
            udp_flow(
                "64.176.66.4",
                443,
                0U,
                candidate_packets,
                candidate_packets * 96U),
        };
    };

    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(10U, 12U)}, source_view(10U, 12U, 1U), start).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, source_view(16U, 18U, 2U),
        start + std::chrono::seconds{5}).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, source_view(16U, 18U, 3U),
        start + std::chrono::seconds{7}).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, source_view(16U, 18U, 4U),
        start + std::chrono::seconds{9}).size() == 1U);
}

TEST_CASE("pre-existing non-growing UDP flow cannot build a streak") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    const auto existing = call_candidates(5U, 1U);

    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(10U, 12U)}, existing, start).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(16U, 18U)}, existing,
        start + std::chrono::seconds{5}).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {seed(22U, 24U)}, existing,
        start + std::chrono::seconds{7}).empty());
    CHECK_FALSE(detector.needs_fast_followup(
        start + std::chrono::seconds{7}));
}

TEST_CASE("candidate streak resets on a break regression and epoch change") {
    const auto start = UdpCallAffinityDetector::TimePoint{};

    SUBCASE("break") {
        UdpCallAffinityDetector detector;
        detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(10U, 12U)}, call_candidates(3U, 1U), start);
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(5U, 1U),
            start + std::chrono::seconds{5}).empty());
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(7U, 1U),
            start + std::chrono::seconds{7}).empty());
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, {},
            start + std::chrono::seconds{9}).empty());
        CHECK_FALSE(detector.needs_fast_followup(
            start + std::chrono::seconds{9}));
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(9U, 1U),
            start + std::chrono::seconds{11}).empty());
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(11U, 1U),
            start + std::chrono::seconds{13}).empty());
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(13U, 1U),
            start + std::chrono::seconds{15}).size() == 1U);
    }

    SUBCASE("counter regression") {
        UdpCallAffinityDetector detector;
        detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(10U, 12U)}, call_candidates(3U, 1U), start);
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(5U, 1U),
            start + std::chrono::seconds{5}).empty());
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(7U, 1U),
            start + std::chrono::seconds{7}).empty());
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(3U, 1U),
            start + std::chrono::seconds{9}).empty());
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(5U, 1U),
            start + std::chrono::seconds{11}).empty());
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(7U, 1U),
            start + std::chrono::seconds{13}).size() == 1U);
    }

    SUBCASE("epoch") {
        UdpCallAffinityDetector detector;
        detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(10U, 12U)}, call_candidates(3U, 1U), start);
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(5U, 1U),
            start + std::chrono::seconds{5}).empty());
        CHECK(detector.observe(
            epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(7U, 1U),
            start + std::chrono::seconds{7}).empty());

        const IdleStallEpoch next_epoch{8U, 1U};
        CHECK(detector.observe(
            next_epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(10U, 12U)}, call_candidates(9U, 1U),
            start + std::chrono::seconds{9}).empty());
        CHECK(detector.needs_fast_followup(
            start + std::chrono::seconds{9}));
        CHECK(detector.observe(
            next_epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(11U, 1U),
            start + std::chrono::seconds{11}).empty());
        CHECK(detector.observe(
            next_epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(13U, 1U),
            start + std::chrono::seconds{13}).empty());
        CHECK(detector.observe(
            next_epoch, trustworthy_status, 0x00FF0000U, targets,
            {seed(16U, 18U)}, call_candidates(15U, 1U),
            start + std::chrono::seconds{15}).size() == 1U);
    }
}

TEST_CASE("same source does not combine IPv4 and IPv6 fan-out") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    const auto mixed_seeds = [](std::uint64_t packets,
                                std::uint64_t replies) {
        auto ipv4 = seed(packets, replies);
        ipv4.source = "dual-stack-client";
        auto ipv6 = seed(packets, replies);
        ipv6.family = ConntrackFlowFamily::Ipv6;
        ipv6.source = "dual-stack-client";
        ipv6.destination = "2a03:2880:f10d:83:face:b00c:0:25de";
        return std::vector<ConntrackExactForwardedFlow>{ipv4, ipv6};
    };
    const auto mixed_candidates = [](std::uint64_t packets) {
        auto flows = call_candidates(packets);
        for (auto& flow : flows) {
            flow.source = "dual-stack-client";
        }
        flows[2].family = ConntrackFlowFamily::Ipv6;
        flows[2].destination = "2606:4700:4700::1111";
        flows[3].family = ConntrackFlowFamily::Ipv6;
        flows[3].destination = "2001:4860:4860::8888";
        return flows;
    };

    detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        mixed_seeds(10U, 12U), mixed_candidates(3U), start);
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        mixed_seeds(16U, 18U), mixed_candidates(5U),
        start + std::chrono::seconds{5}).empty());
    // If the family were omitted from SourceKey, these two plus two would look
    // like a four-peer fast fan-out and promote here.
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        mixed_seeds(16U, 18U), mixed_candidates(7U),
        start + std::chrono::seconds{7}).empty());

    const auto decisions = detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        mixed_seeds(16U, 18U), mixed_candidates(9U),
        start + std::chrono::seconds{9});
    REQUIRE(decisions.size() == 4U);
    CHECK(std::count_if(
              decisions.begin(), decisions.end(), [](const auto& decision) {
                  return decision.family == ConntrackFlowFamily::Ipv4;
              }) == 2);
    CHECK(std::count_if(
              decisions.begin(), decisions.end(), [](const auto& decision) {
                  return decision.family == ConntrackFlowFamily::Ipv6;
              }) == 2);
}

TEST_CASE("established TCP 443 is a seed fallback but never a candidate") {
    const auto start = UdpCallAffinityDetector::TimePoint{};
    CHECK(udp_call_affinity_seed_sources(
              {tcp_seed(10U, 12U)}, targets, 0x00FF0000U) ==
          std::vector<std::string>{"192.168.1.44"});
    CHECK(udp_call_affinity_seed_sources(
              {tcp_seed(10U, 12U, ConntrackTcpState::SynSent)},
              targets,
              0x00FF0000U)
              .empty());

    UdpCallAffinityDetector no_udp_burst;
    no_udp_burst.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {tcp_seed(10U, 12U)}, {}, start);
    CHECK(no_udp_burst.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {tcp_seed(16U, 18U)}, {},
        start + std::chrono::seconds{5}).empty());
    CHECK_FALSE(no_udp_burst.needs_fast_followup(
        start + std::chrono::seconds{5}));

    UdpCallAffinityDetector fallback;
    fallback.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {tcp_seed(10U, 12U)}, call_candidates(3U, 1U), start);
    CHECK(fallback.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {tcp_seed(16U, 18U)}, call_candidates(5U, 1U),
        start + std::chrono::seconds{5}).empty());
    CHECK(fallback.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {tcp_seed(16U, 18U)}, call_candidates(7U, 1U),
        start + std::chrono::seconds{7}).empty());
    const auto promoted = fallback.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        {tcp_seed(16U, 18U)}, call_candidates(9U, 1U),
        start + std::chrono::seconds{9});
    REQUIRE(promoted.size() == 1U);
    CHECK(promoted.front().baseline_flows.front().protocol ==
          ConntrackFlowProtocol::Udp);
}

TEST_CASE("WhatsApp call affinity requires a burst and the same client") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        {udp_flow("64.176.66.4", 443, 0U, 3U, 3600U)},
        start);

    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        {udp_flow("64.176.66.4", 443, 0U, 5U, 6000U)},
        start + std::chrono::seconds{5}).empty());

    UdpCallAffinityDetector other_client_detector;
    other_client_detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(3U),
        start);
    auto other_client = call_candidates(5U);
    for (auto& flow : other_client) {
        flow.source = "192.168.1.45";
    }
    CHECK(other_client_detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        other_client,
        start + std::chrono::seconds{5}).empty());
}

TEST_CASE("two clients build independent call contexts") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    const auto seeds = [](std::uint64_t packets,
                          std::uint64_t replies) {
        auto first = seed(packets, replies);
        auto second = seed(packets, replies);
        second.source = "192.168.1.45";
        second.source_port = 40443U;
        return std::vector<ConntrackExactForwardedFlow>{first, second};
    };
    const auto candidates = [](std::uint64_t packets) {
        auto first = udp_flow(
            "64.176.66.4", 443, 0U, packets, packets * 96U);
        auto second = udp_flow(
            "13.38.106.0",
            53,
            0U,
            packets,
            packets * 96U,
            0U,
            0U,
            false,
            false,
            "192.168.1.45");
        return std::vector<ConntrackExactForwardedFlow>{first, second};
    };

    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        seeds(10U, 12U), candidates(1U), start).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        seeds(16U, 18U), candidates(2U),
        start + std::chrono::seconds{5}).empty());
    CHECK(detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        seeds(16U, 18U), candidates(3U),
        start + std::chrono::seconds{7}).empty());
    const auto decisions = detector.observe(
        epoch, trustworthy_status, 0x00FF0000U, targets,
        seeds(16U, 18U), candidates(4U),
        start + std::chrono::seconds{9});
    REQUIRE(decisions.size() == 2U);
    CHECK(decisions[0].source != decisions[1].source);
}

TEST_CASE("active unowned media refreshes the 90 second peer lease") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(3U),
        start);
    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(5U),
        start + std::chrono::seconds{5}).empty());
    const auto promoted = detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(7U),
        start + std::chrono::seconds{7});
    REQUIRE(promoted.size() == 4U);
    for (const auto& decision : promoted) {
        CHECK(detector.confirm_installed(
            decision, start + std::chrono::seconds{7}));
    }

    auto media = udp_flow(
        "64.176.66.4", 443, 0x00000041U,
        20U, 24000U, 18U, 18000U, true, true);
    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        {media},
        start + std::chrono::seconds{10}).empty());

    media.original = {30U, 36000U};
    media.reply = {28U, 28000U};
    const auto refresh = detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        {media},
        start + std::chrono::seconds{40});
    REQUIRE(refresh.size() == 1U);
    CHECK(refresh.front().refresh_only);
    REQUIRE(refresh.front().baseline_flows.size() == 1U);
    CHECK(refresh.front().baseline_flows.front().destination_port ==
          refresh.front().destination_port);
    CHECK(detector.confirm_installed(
        refresh.front(), start + std::chrono::seconds{40}));

    CHECK_FALSE(detector.retained_guard_sources(
        start + std::chrono::seconds{120}).empty());
    CHECK(detector.retained_guard_sources(
        start + std::chrono::seconds{131}).empty());
}

TEST_CASE("failed affinity refresh preserves the previous confirmed lease") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(3U),
        start);
    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(5U),
        start + std::chrono::seconds{5}).empty());
    const auto promoted = detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(7U),
        start + std::chrono::seconds{7});
    REQUIRE_FALSE(promoted.empty());
    for (const auto& decision : promoted) {
        REQUIRE(decision.confirmation_token != 0U);
        REQUIRE(detector.confirm_installed(
            decision, start + std::chrono::seconds{7}));
    }

    auto media = udp_flow(
        "64.176.66.4", 443U, 0x00000041U,
        20U, 24000U, 18U, 18000U, true, true);
    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        {media},
        start + std::chrono::seconds{10}).empty());
    media.original = {30U, 36000U};
    media.reply = {28U, 28000U};
    const auto refresh = detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        {media},
        start + std::chrono::seconds{40});
    REQUIRE(refresh.size() == 1U);
    REQUIRE(refresh.front().refresh_only);
    REQUIRE(refresh.front().confirmation_token != 0U);

    detector.release_failed(refresh.front());
    CHECK_FALSE(detector.retained_guard_peers(
        start + std::chrono::seconds{96}).empty());
    CHECK(detector.retained_guard_peers(
        start + std::chrono::seconds{97}).empty());
    CHECK_FALSE(detector.confirm_installed(
        refresh.front(), start + std::chrono::seconds{40}));
}

TEST_CASE(
    "unrelated source-wide UDP cannot protect stale WhatsApp signalling") {
    auto unrelated_baseline = udp_flow(
        "1.1.1.1", 443U, 0U, 10U, 1000U, 10U, 1000U, true, true);
    auto unrelated_current = unrelated_baseline;
    unrelated_current.original = {20U, 4000U};
    unrelated_current.reply = {20U, 4000U};

    CHECK(active_udp_media_guard_sources(
              {unrelated_baseline},
              {},
              {unrelated_current},
              {},
              0x00FF0000U,
              {0x00070000U})
              .empty());

    const UdpCallAffinityGuardPeer retained_peer{
        ConntrackFlowFamily::Ipv4,
        "192.168.1.44",
        "64.176.66.4",
        3478U,
        0x00070000U};
    auto retained_unchanged = udp_flow(
        retained_peer.destination,
        retained_peer.destination_port,
        0U,
        20U,
        4000U,
        20U,
        4000U,
        true,
        true);
    CHECK(active_udp_media_guard_sources(
              {unrelated_baseline, retained_unchanged},
              {},
              {unrelated_current, retained_unchanged},
              {retained_peer},
              0x00FF0000U,
              {0x00070000U})
              .empty());
}

TEST_CASE(
    "covered WhatsApp UDP guards without affinity publication and exact "
    "retained peers guard outside coverage") {
    auto covered_baseline = udp_flow(
        "157.240.253.142",
        443U,
        0x00070000U,
        10U,
        1000U,
        10U,
        1000U,
        true,
        true);
    auto covered_current = covered_baseline;
    covered_current.original = {11U, 1200U};
    covered_current.reply = {11U, 1200U};
    const auto covered_sources = active_udp_media_guard_sources(
        {covered_baseline},
        {covered_current},
        {},
        {},
        0x00FF0000U,
        {0x00070000U});
    const std::set<std::pair<ConntrackFlowFamily, std::string>>
        expected_covered_sources{
            {ConntrackFlowFamily::Ipv4, "192.168.1.44"}};
    CHECK(covered_sources == expected_covered_sources);

    const UdpCallAffinityGuardPeer retained_peer{
        ConntrackFlowFamily::Ipv4,
        "192.168.1.45",
        "64.176.66.4",
        3478U,
        0x00070000U};
    auto peer_baseline = udp_flow(
        retained_peer.destination,
        retained_peer.destination_port,
        0x41U,
        20U,
        4000U,
        20U,
        4000U,
        true,
        true,
        retained_peer.source);
    auto peer_current = peer_baseline;
    peer_current.original = {22U, 4400U};
    peer_current.reply = {22U, 4400U};
    const auto peer_sources = active_udp_media_guard_sources(
        {peer_baseline},
        {},
        {peer_current},
        {retained_peer},
        0x00FF0000U,
        {0x00070000U});
    const std::set<std::pair<ConntrackFlowFamily, std::string>>
        expected_peer_sources{
            {ConntrackFlowFamily::Ipv4, "192.168.1.45"}};
    CHECK(peer_sources == expected_peer_sources);

    // A new exact promoted peer is trustworthy even when it appeared between
    // the two bounded snapshots.
    CHECK(active_udp_media_guard_sources(
              {},
              {},
              {peer_current},
              {retained_peer},
              0x00FF0000U,
              {0x00070000U}) == peer_sources);

    auto wrong_mark = peer_current;
    wrong_mark.mark = 0x00060041U;
    CHECK(active_udp_media_guard_sources(
              {},
              {},
              {wrong_mark},
              {retained_peer},
              0x00FF0000U,
              {0x00070000U})
              .empty());

    auto wrong_covered_mark = covered_current;
    wrong_covered_mark.mark = 0x00060000U;
    CHECK(active_udp_media_guard_sources(
              {covered_baseline},
              {wrong_covered_mark},
              {},
              {},
              0x00FF0000U,
              {0x00070000U})
              .empty());
}

TEST_CASE("retained call guard exposes only exact unexpired promoted peers") {
    UdpCallAffinityDetector detector;
    const auto start = UdpCallAffinityDetector::TimePoint{};
    detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(3U),
        start);
    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(5U),
        start + std::chrono::seconds{5}).empty());
    const auto promoted = detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(7U),
        start + std::chrono::seconds{7});
    REQUIRE_FALSE(promoted.empty());
    CHECK(detector.retained_guard_peers(
        start + std::chrono::seconds{7}).empty());
    const auto selected = std::find_if(
        promoted.begin(), promoted.end(), [](const auto& decision) {
            return decision.destination == "64.176.66.4" &&
                   decision.destination_port == 443U;
    });
    REQUIRE(selected != promoted.end());
    REQUIRE(selected->confirmation_token != 0U);
    REQUIRE(detector.confirm_installed(
        *selected, start + std::chrono::seconds{7}));

    const std::vector<UdpCallAffinityGuardPeer> expected{
        {ConntrackFlowFamily::Ipv4,
         "192.168.1.44",
         "64.176.66.4",
         443U,
         0x00070000U}};
    CHECK(detector.retained_guard_peers(
              start + std::chrono::seconds{8}) == expected);
    // A late failure/duplicate completion for an already consumed token has no
    // authority to revoke or extend the confirmed lease.
    detector.release_failed(*selected);
    CHECK(detector.retained_guard_peers(
              start + std::chrono::seconds{8}) == expected);
    CHECK_FALSE(detector.confirm_installed(
        *selected, start + std::chrono::seconds{8}));
    CHECK_FALSE(detector.retained_guard_peers(
        start + std::chrono::seconds{96}).empty());
    CHECK(detector.retained_guard_peers(
        start + std::chrono::seconds{97}).empty());

    detector.reset();
    CHECK(detector.retained_guard_peers(
        start + std::chrono::seconds{9}).empty());
    // A completion from before reset cannot repopulate guard authority.
    CHECK_FALSE(detector.confirm_installed(
        *selected, start + std::chrono::seconds{9}));
    CHECK(detector.retained_guard_peers(
        start + std::chrono::seconds{9}).empty());

    // Even if the same exact peer is reserved again after reset, the old
    // completion token cannot consume the new reservation.
    detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(3U),
        start + std::chrono::seconds{10});
    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(5U),
        start + std::chrono::seconds{15}).empty());
    const auto replacement = detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(7U),
        start + std::chrono::seconds{17});
    const auto replacement_selected = std::find_if(
        replacement.begin(), replacement.end(), [](const auto& decision) {
            return decision.destination == "64.176.66.4" &&
                   decision.destination_port == 443U;
        });
    REQUIRE(replacement_selected != replacement.end());
    REQUIRE(replacement_selected->confirmation_token !=
            selected->confirmation_token);
    CHECK_FALSE(detector.confirm_installed(
        *selected, start + std::chrono::seconds{17}));
    detector.release_failed(*selected);
    REQUIRE(detector.confirm_installed(
        *replacement_selected, start + std::chrono::seconds{17}));
    CHECK(detector.retained_guard_peers(
              start + std::chrono::seconds{18}) == expected);
}

TEST_CASE("failed pair insertion releases its global retry budget") {
    UdpCallAffinityDetectorOptions options;
    options.max_pairs_per_rate_window = 1U;
    UdpCallAffinityDetector detector{options};
    const auto start = UdpCallAffinityDetector::TimePoint{};
    detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(10U, 12U)},
        call_candidates(3U),
        start);
    CHECK(detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(5U),
        start + std::chrono::seconds{5}).empty());
    const auto first = detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(7U),
        start + std::chrono::seconds{7});
    REQUIRE(first.size() == 1U);
    detector.release_failed(first.front());

    const auto retry = detector.observe(
        epoch,
        trustworthy_status,
        0x00FF0000U,
        targets,
        {seed(16U, 18U)},
        call_candidates(9U),
        start + std::chrono::seconds{9});
    REQUIRE(retry.size() == 1U);
    CHECK(retry.front().destination == first.front().destination);
}

TEST_CASE("ambiguous WhatsApp outbound marks fail closed") {
    RuleState first{};
    first.action_type = RuleActionType::Mark;
    first.fwmark = 0x00070000U;
    first.list_names = {"meta_whatsapp_ip"};
    first.set_names = {"kpbr4s_meta_whatsapp_ip"};

    RuleState second = first;
    second.fwmark = 0x00080000U;

    CHECK(active_udp_call_affinity_targets(
        {"meta_whatsapp_ip"}, {first, second}, 0x00FF0000U).empty());
}

TEST_CASE("call affinity is limited to the packaged WhatsApp companion") {
    Config config;
    config.daemon = DaemonConfig{};
    ListConfig whatsapp;
    whatsapp.catalog_identity = kWhatsappIpCatalogIdentity;
    ListConfig ordinary;
    config.lists = std::map<std::string, ListConfig>{
        {"meta_whatsapp_ip", whatsapp},
        {"ordinary_messages", ordinary},
    };

    CHECK(whatsapp_call_affinity_list_names(config) ==
          std::set<std::string>{"meta_whatsapp_ip"});

    config.lists->at("meta_whatsapp_ip").catalog_identity.reset();
    CHECK(whatsapp_call_affinity_list_names(config).empty());
    config.lists->at("meta_whatsapp_ip").catalog_identity =
        kWhatsappIpCatalogIdentity;

    config.daemon->reconnect_owned_flows_on_routing_change_lists =
        std::vector<std::string>{};
    CHECK(whatsapp_call_affinity_list_names(config).empty());
}

TEST_CASE(
    "WhatsApp latency provenance ignores name spoofing copies and manual lists") {
    Config config;
    config.daemon = DaemonConfig{};

    ListConfig packaged;
    packaged.catalog_identity = kWhatsappIpCatalogIdentity;
    ListConfig copied;
    ListConfig spoofed_named_like_whatsapp;
    ListConfig manual;
    config.lists = std::map<std::string, ListConfig>{
        {"catalog_entry_42", packaged},
        {"meta_whatsapp_ip_copy", copied},
        {"whatsapp", spoofed_named_like_whatsapp},
        {"manual_meta_networks", manual},
    };

    CHECK(whatsapp_call_affinity_list_names(config) ==
          std::set<std::string>{"catalog_entry_42"});

    config.daemon->reconnect_owned_flows_on_routing_change_lists =
        std::vector<std::string>{
            "meta_whatsapp_ip_copy", "whatsapp", "manual_meta_networks"};
    CHECK(whatsapp_call_affinity_list_names(config).empty());

    config.daemon->reconnect_owned_flows_on_routing_change_lists =
        std::vector<std::string>{"catalog_entry_42"};
    config.daemon->reconnect_unmarked_flows_on_routing_change = false;
    CHECK(whatsapp_call_affinity_list_names(config).empty());
}
