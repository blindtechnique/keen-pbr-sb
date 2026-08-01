#include <doctest/doctest.h>

#include "runtime/idle_stall_detector.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

constexpr std::uint32_t kOwnedMask = 0x00FF0000U;

IdleStallDetector::TimePoint at(std::chrono::seconds elapsed) {
    return IdleStallDetector::TimePoint{} + elapsed;
}

IdleStallFlowSample tcp_sample(
    std::string source,
    std::string destination,
    std::uint16_t source_port,
    std::uint64_t original_packets,
    std::uint64_t original_bytes,
    std::uint64_t reply_packets,
    std::uint64_t reply_bytes,
    std::uint32_t mark = 0U,
    bool fastnat = false) {
    return IdleStallFlowSample{
        IdleStallFlowKey{
            IdleStallAddressFamily::ipv4,
            IdleStallProtocol::tcp,
            std::move(source),
            std::move(destination),
            source_port,
            443,
            mark},
        IdleStallFlowCounters{
            original_packets,
            original_bytes,
            reply_packets,
            reply_bytes},
        IdleStallFlowReadiness::tcp_established,
        fastnat};
}

IdleStallFlowSample udp_sample(
    std::string source,
    std::string destination,
    std::uint16_t source_port,
    std::uint64_t original_packets,
    std::uint64_t original_bytes,
    std::uint64_t reply_packets,
    std::uint64_t reply_bytes,
    std::uint32_t mark = 0U) {
    return IdleStallFlowSample{
        IdleStallFlowKey{
            IdleStallAddressFamily::ipv4,
            IdleStallProtocol::udp,
            std::move(source),
            std::move(destination),
            source_port,
            443,
            mark},
        IdleStallFlowCounters{
            original_packets,
            original_bytes,
            reply_packets,
            reply_bytes},
        IdleStallFlowReadiness::udp_assured,
        false};
}

IdleStallScan scan(
    std::vector<IdleStallFlowSample> flows,
    std::uint64_t runtime_generation = 1U,
    std::uint64_t coverage_generation = 1U) {
    return IdleStallScan{
        IdleStallEpoch{runtime_generation, coverage_generation},
        kOwnedMask,
        IdleStallScanStatus{},
        std::move(flows)};
}

bool contains_source(
    const std::vector<IdleStallDeleteDecision>& decisions,
    const std::string& source) {
    return std::any_of(
        decisions.begin(),
        decisions.end(),
        [&](const IdleStallDeleteDecision& decision) {
            return decision.flow.source == source;
        });
}

} // namespace

TEST_CASE("IdleStallDetector establishes a baseline and keeps healthy progress") {
    IdleStallDetector detector;
    const auto initial = tcp_sample(
        "192.168.1.44", "31.13.66.10", 41000, 10, 1000, 10, 1000);

    CHECK(detector.observe(scan({initial}), at(0s)).empty());
    CHECK(detector.tracked_flow_count() == 1U);
    CHECK(detector.observe(scan({initial}), at(90s)).empty());

    auto healthy = initial;
    healthy.counters.original_packets += 4;
    healthy.counters.original_bytes += 800;
    healthy.counters.reply_packets += 5;
    healthy.counters.reply_bytes += 1200;
    CHECK(detector.observe(scan({healthy}), at(91s)).empty());
    CHECK(detector.observe(scan({healthy}), at(120s)).empty());
}

TEST_CASE(
    "IdleStallDetector ignores bidirectional tiny keepalives and confirms an application stall") {
    IdleStallDetector detector;
    auto flow = tcp_sample(
        "192.168.1.44", "31.13.66.10", 41000, 10, 1000, 10, 1000);
    CHECK(detector.observe(scan({flow}), at(0s)).empty());

    // The measured stale socket exchanges only tiny control packets. They
    // must update the counter baseline without resetting the configured
    // 30-second application-idle age.
    for (const auto elapsed : {10s, 20s, 30s}) {
        flow.counters.original_packets += 2;
        flow.counters.original_bytes += 141;
        flow.counters.reply_packets += 2;
        flow.counters.reply_bytes += 145;
        CHECK(detector.observe(scan({flow}), at(elapsed)).empty());
    }

    flow.counters.original_packets += 5;
    flow.counters.original_bytes += 600;
    flow.counters.reply_packets += 2;
    flow.counters.reply_bytes += 145;
    CHECK(detector.observe(scan({flow}), at(31s)).empty());

    flow.counters.original_packets += 1;
    flow.counters.original_bytes += 120;
    flow.counters.reply_packets += 1;
    flow.counters.reply_bytes += 100;
    CHECK(detector.observe(scan({flow}), at(35s)).empty());

    const auto decisions = detector.observe(scan({flow}), at(36s));
    REQUIRE(decisions.size() == 1U);
    CHECK(decisions.front().flow == flow.key);
    CHECK(decisions.front().reason ==
          IdleStallDecisionReason::idle_request_without_reply);
}

TEST_CASE(
    "IdleStallDetector proactively rotates an idle keepalive-only FASTNAT TCP flow") {
    IdleStallDetector detector;
    auto flow = tcp_sample(
        "192.168.1.44",
        "31.13.66.10",
        41000,
        10,
        1000,
        10,
        1000,
        0U,
        true);
    CHECK(detector.observe(scan({flow}), at(0s)).empty());

    flow.counters.original_packets += 2;
    flow.counters.original_bytes += 141;
    flow.counters.reply_packets += 2;
    flow.counters.reply_bytes += 145;
    const auto decisions = detector.observe(scan({flow}), at(30s));
    REQUIRE(decisions.size() == 1U);
    CHECK(decisions.front().flow == flow.key);
    CHECK(decisions.front().reason ==
          IdleStallDecisionReason::idle_fastnat_rotation);
}

TEST_CASE(
    "IdleStallDetector keeps non-FASTNAT and disabled FASTNAT idle flows") {
    auto ordinary = tcp_sample(
        "192.168.1.44", "31.13.66.10", 41000,
        10, 1000, 10, 1000);
    IdleStallDetector ordinary_detector;
    CHECK(ordinary_detector.observe(scan({ordinary}), at(0s)).empty());
    CHECK(ordinary_detector.observe(scan({ordinary}), at(90s)).empty());

    auto fastnat = ordinary;
    fastnat.fastnat = true;
    IdleStallDetectorOptions options;
    options.rotate_idle_fastnat_tcp = false;
    IdleStallDetector disabled_detector(options);
    CHECK(disabled_detector.observe(scan({fastnat}), at(0s)).empty());
    CHECK(disabled_detector.observe(scan({fastnat}), at(90s)).empty());
}

TEST_CASE(
    "IdleStallDetector does not rotate a dormant FASTNAT flow without a keepalive") {
    IdleStallDetector detector;
    const auto flow = tcp_sample(
        "192.168.1.44",
        "31.13.66.10",
        41000,
        10,
        1000,
        10,
        1000,
        0U,
        true);
    CHECK(detector.observe(scan({flow}), at(0s)).empty());
    CHECK(detector.observe(scan({flow}), at(90s)).empty());
}

TEST_CASE(
    "IdleStallDetector does not rotate FASTNAT on one-way tiny activity") {
    IdleStallDetector detector;
    auto flow = tcp_sample(
        "192.168.1.44",
        "31.13.66.10",
        41000,
        10,
        1000,
        10,
        1000,
        0U,
        true);
    CHECK(detector.observe(scan({flow}), at(0s)).empty());

    flow.counters.original_packets += 2;
    flow.counters.original_bytes += 141;
    CHECK(detector.observe(scan({flow}), at(90s)).empty());
}

TEST_CASE("IdleStallDetector applies the configured keepalive byte threshold") {
    IdleStallDetectorOptions options;
    options.tiny_keepalive_max_bytes_per_direction = 100U;
    IdleStallDetector detector(options);
    auto flow = tcp_sample(
        "192.168.1.44",
        "31.13.66.10",
        41000,
        10,
        1000,
        10,
        1000,
        0U,
        true);
    CHECK(detector.observe(scan({flow}), at(0s)).empty());

    flow.counters.original_packets += 2;
    flow.counters.original_bytes += 141;
    flow.counters.reply_packets += 2;
    flow.counters.reply_bytes += 145;
    CHECK(detector.observe(scan({flow}), at(90s)).empty());

    // Both directional deltas are larger than the configured threshold, so
    // they are application progress and restart the idle age.
    flow.counters.original_packets += 2;
    flow.counters.original_bytes += 141;
    flow.counters.reply_packets += 2;
    flow.counters.reply_bytes += 145;
    CHECK(detector.observe(scan({flow}), at(91s)).empty());
}

TEST_CASE("IdleStallDetector cancels a suspect on real reply progress") {
    IdleStallDetector detector;
    auto flow = tcp_sample(
        "192.168.1.44", "31.13.66.10", 41000, 10, 1000, 10, 1000);
    CHECK(detector.observe(scan({flow}), at(0s)).empty());
    CHECK(detector.observe(scan({flow}), at(90s)).empty());

    flow.counters.original_packets += 4;
    flow.counters.original_bytes += 600;
    CHECK(detector.observe(scan({flow}), at(91s)).empty());

    flow.counters.reply_packets += 4;
    flow.counters.reply_bytes += 600;
    CHECK(detector.observe(scan({flow}), at(99s)).empty());
    CHECK(detector.observe(scan({flow}), at(120s)).empty());
}

TEST_CASE("IdleStallDetector resets continuity when runtime or coverage changes") {
    IdleStallDetector detector;
    auto flow = tcp_sample(
        "192.168.1.44", "31.13.66.10", 41000, 10, 1000, 10, 1000);
    CHECK(detector.observe(scan({flow}), at(0s)).empty());
    CHECK(detector.observe(scan({flow}), at(90s)).empty());
    flow.counters.original_bytes += 600;
    flow.counters.original_packets += 4;
    CHECK(detector.observe(scan({flow}), at(91s)).empty());

    CHECK(detector.observe(scan({flow}, 2U, 1U), at(99s)).empty());
    CHECK(detector.observe(scan({flow}, 2U, 1U), at(120s)).empty());

    flow.counters.original_bytes += 600;
    flow.counters.original_packets += 4;
    CHECK(detector.observe(scan({flow}, 2U, 1U), at(190s)).empty());
    CHECK(detector.observe(scan({flow}, 2U, 2U), at(198s)).empty());
    CHECK(detector.observe(scan({flow}, 2U, 2U), at(210s)).empty());
}

TEST_CASE(
    "IdleStallDetector protects every flow of a source with active UDP media") {
    IdleStallDetector detector;
    auto signalling = tcp_sample(
        "192.168.1.44", "31.13.66.10", 41000, 10, 1000, 10, 1000);
    auto media = udp_sample(
        "192.168.1.44", "31.13.66.20", 42000, 100, 10000, 100, 10000);
    CHECK(detector.observe(scan({signalling, media}), at(0s)).empty());
    CHECK(detector.observe(scan({signalling, media}), at(90s)).empty());

    signalling.counters.original_packets += 5;
    signalling.counters.original_bytes += 800;
    media.counters.original_packets += 5;
    media.counters.original_bytes += 800;
    media.counters.reply_packets += 5;
    media.counters.reply_bytes += 800;
    CHECK(detector.observe(scan({signalling, media}), at(91s)).empty());
    CHECK(detector.observe(scan({signalling, media}), at(99s)).empty());

    // The guard expired and the old suspect was discarded. Only a fresh
    // post-idle request may create another suspect.
    CHECK(detector.observe(scan({signalling, media}), at(121s)).empty());
    signalling.counters.original_packets += 5;
    signalling.counters.original_bytes += 800;
    CHECK(detector.observe(scan({signalling, media}), at(122s)).empty());
    const auto decisions =
        detector.observe(scan({signalling, media}), at(127s));
    REQUIRE(decisions.size() == 1U);
    CHECK(decisions.front().flow == signalling.key);
}

TEST_CASE("IdleStallDetector accepts only zero or exclusively owned marks") {
    IdleStallDetector detector;
    auto unmarked = tcp_sample(
        "192.168.1.40", "31.13.66.10", 41000, 10, 1000, 10, 1000, 0U);
    auto owned = tcp_sample(
        "192.168.1.41", "31.13.66.11", 41001, 10, 1000, 10, 1000,
        0x00010000U);
    auto foreign = tcp_sample(
        "192.168.1.42", "31.13.66.12", 41002, 10, 1000, 10, 1000,
        0xA5000000U);
    auto mixed = tcp_sample(
        "192.168.1.43", "31.13.66.13", 41003, 10, 1000, 10, 1000,
        0xA5010000U);
    std::vector<IdleStallFlowSample> flows{
        unmarked, owned, foreign, mixed};
    CHECK(detector.observe(scan(flows), at(0s)).empty());
    CHECK(detector.observe(scan(flows), at(90s)).empty());
    for (auto& flow : flows) {
        flow.counters.original_packets += 4;
        flow.counters.original_bytes += 600;
    }
    CHECK(detector.observe(scan(flows), at(91s)).empty());
    const auto decisions = detector.observe(scan(flows), at(99s));
    REQUIRE(decisions.size() == 2U);
    CHECK(contains_source(decisions, "192.168.1.40"));
    CHECK(contains_source(decisions, "192.168.1.41"));
    CHECK_FALSE(contains_source(decisions, "192.168.1.42"));
    CHECK_FALSE(contains_source(decisions, "192.168.1.43"));
}

TEST_CASE("IdleStallDetector applies source cooldown across exact tuples") {
    IdleStallDetector detector;
    auto first = tcp_sample(
        "192.168.1.44", "31.13.66.10", 41000, 10, 1000, 10, 1000);
    auto second = tcp_sample(
        "192.168.1.44", "31.13.66.11", 41001, 10, 1000, 10, 1000);
    std::vector<IdleStallFlowSample> flows{first, second};
    CHECK(detector.observe(scan(flows), at(0s)).empty());
    CHECK(detector.observe(scan(flows), at(90s)).empty());
    for (auto& flow : flows) {
        flow.counters.original_packets += 4;
        flow.counters.original_bytes += 600;
    }
    CHECK(detector.observe(scan(flows), at(91s)).empty());
    const auto first_decisions = detector.observe(scan(flows), at(99s));
    REQUIRE(first_decisions.size() == 1U);
    CHECK(detector.acknowledge_delete_result(
        first_decisions.front(), true, at(99s)));

    CHECK(detector.observe(scan(flows), at(129s)).empty());
    flows[1].counters.original_packets += 4;
    flows[1].counters.original_bytes += 600;
    CHECK(detector.observe(scan(flows), at(130s)).empty());
    CHECK(detector.observe(scan(flows), at(138s)).size() == 1U);
}

TEST_CASE(
    "IdleStallDetector retries without cooldown after an exact delete failure") {
    IdleStallDetector detector;
    auto flow = tcp_sample(
        "192.168.1.44", "31.13.66.10", 41000, 10, 1000, 10, 1000);
    CHECK(detector.observe(scan({flow}), at(0s)).empty());
    CHECK(detector.observe(scan({flow}), at(90s)).empty());
    flow.counters.original_packets += 4;
    flow.counters.original_bytes += 600;
    CHECK(detector.observe(scan({flow}), at(91s)).empty());

    const auto failed_attempt = detector.observe(scan({flow}), at(99s));
    REQUIRE(failed_attempt.size() == 1U);
    CHECK(detector.acknowledge_delete_result(
        failed_attempt.front(), false, at(99s)));

    const auto retry = detector.observe(scan({flow}), at(100s));
    REQUIRE(retry.size() == 1U);
    CHECK(retry.front().flow == failed_attempt.front().flow);
    CHECK(retry.front().attempt_id != failed_attempt.front().attempt_id);
    CHECK(detector.acknowledge_delete_result(
        retry.front(), true, at(100s)));

    // Only the successful retry starts the per-source cooldown.
    CHECK(detector.observe(scan({flow}), at(101s)).empty());
}

TEST_CASE(
    "IdleStallDetector charges the global rate window only on successful delete") {
    IdleStallDetectorOptions options;
    options.max_decisions_per_scan = 1U;
    options.max_decisions_per_rate_window = 1U;
    IdleStallDetector detector(options);
    auto first = tcp_sample(
        "192.168.1.40", "31.13.66.10", 41000, 10, 1000, 10, 1000);
    auto second = tcp_sample(
        "192.168.1.41", "31.13.66.11", 41001, 10, 1000, 10, 1000);
    std::vector<IdleStallFlowSample> flows{first, second};
    CHECK(detector.observe(scan(flows), at(0s)).empty());
    CHECK(detector.observe(scan(flows), at(90s)).empty());
    for (auto& flow : flows) {
        flow.counters.original_packets += 4;
        flow.counters.original_bytes += 600;
    }
    CHECK(detector.observe(scan(flows), at(91s)).empty());

    const auto failed_attempt = detector.observe(scan(flows), at(99s));
    REQUIRE(failed_attempt.size() == 1U);
    CHECK(detector.acknowledge_delete_result(
        failed_attempt.front(), false, at(99s)));

    // Recover the failed-attempt flow. The other source must still receive
    // the single global slot because a failed delete consumed no token.
    for (auto& flow : flows) {
        if (flow.key == failed_attempt.front().flow) {
            flow.counters.reply_packets += 4;
            flow.counters.reply_bytes += 600;
        }
    }
    const auto successful_attempt = detector.observe(scan(flows), at(100s));
    REQUIRE(successful_attempt.size() == 1U);
    CHECK_FALSE(successful_attempt.front().flow ==
                failed_attempt.front().flow);
    CHECK(detector.acknowledge_delete_result(
        successful_attempt.front(), true, at(100s)));

    // The successful delete committed the only token in the window.
    CHECK(detector.observe(scan(flows), at(101s)).empty());
}

TEST_CASE("IdleStallDetector rejects stale and duplicate delete acknowledgments") {
    IdleStallDetector detector;
    auto flow = tcp_sample(
        "192.168.1.44", "31.13.66.10", 41000, 10, 1000, 10, 1000);
    CHECK(detector.observe(scan({flow}), at(0s)).empty());
    CHECK(detector.observe(scan({flow}), at(90s)).empty());
    flow.counters.original_packets += 4;
    flow.counters.original_bytes += 600;
    CHECK(detector.observe(scan({flow}), at(91s)).empty());
    const auto decisions = detector.observe(scan({flow}), at(99s));
    REQUIRE(decisions.size() == 1U);

    auto stale = decisions.front();
    ++stale.attempt_id;
    CHECK_FALSE(detector.acknowledge_delete_result(stale, true, at(99s)));
    CHECK(detector.acknowledge_delete_result(
        decisions.front(), false, at(99s)));
    CHECK_FALSE(detector.acknowledge_delete_result(
        decisions.front(), true, at(99s)));
}

TEST_CASE("IdleStallDetector bounds decisions per scan and globally") {
    IdleStallDetector detector;
    std::vector<IdleStallFlowSample> flows;
    for (std::uint16_t index = 0; index < 10; ++index) {
        flows.push_back(tcp_sample(
            "192.168.1." + std::to_string(20 + index),
            "31.13.66." + std::to_string(20 + index),
            static_cast<std::uint16_t>(41000 + index),
            10,
            1000,
            10,
            1000));
    }
    CHECK(detector.observe(scan(flows), at(0s)).empty());
    CHECK(detector.observe(scan(flows), at(90s)).empty());
    for (auto& flow : flows) {
        flow.counters.original_packets += 4;
        flow.counters.original_bytes += 600;
    }
    CHECK(detector.observe(scan(flows), at(91s)).empty());
    for (const auto elapsed : {99s, 104s, 109s, 114s}) {
        const auto decisions = detector.observe(scan(flows), at(elapsed));
        REQUIRE(decisions.size() == 2U);
        for (const auto& decision : decisions) {
            CHECK(detector.acknowledge_delete_result(
                decision, true, at(elapsed)));
        }
    }
    CHECK(detector.observe(scan(flows), at(119s)).empty());

    // The global cap is fail-closed: expiration does not release a latent
    // deletion without another post-idle application request.
    CHECK(detector.observe(scan(flows), at(160s)).empty());
}

TEST_CASE("IdleStallDetector fails closed on incomplete observations") {
    for (std::size_t flag = 0; flag < 4; ++flag) {
        IdleStallDetector detector;
        auto flow = tcp_sample(
            "192.168.1.44", "31.13.66.10", 41000,
            10, 1000, 10, 1000);
        CHECK(detector.observe(scan({flow}), at(0s)).empty());
        CHECK(detector.observe(scan({flow}), at(90s)).empty());
        flow.counters.original_packets += 4;
        flow.counters.original_bytes += 600;
        CHECK(detector.observe(scan({flow}), at(91s)).empty());

        auto incomplete = scan({flow});
        if (flag == 0U) incomplete.status.snapshot_complete = false;
        if (flag == 1U) incomplete.status.counters_available = false;
        if (flag == 2U) incomplete.status.local_scope_complete = false;
        if (flag == 3U) incomplete.status.coverage_complete = false;
        CHECK(detector.observe(incomplete, at(99s)).empty());
        CHECK(detector.tracked_flow_count() == 0U);

        CHECK(detector.observe(scan({flow}), at(100s)).empty());
        CHECK(detector.observe(scan({flow}), at(120s)).empty());
    }
}

} // namespace keen_pbr3
