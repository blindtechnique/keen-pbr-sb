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

IdleStallDetector::TimePoint at(std::chrono::milliseconds elapsed) {
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
    bool fastnat = false,
    IdleStallRecoveryPolicy recovery_policy =
        IdleStallRecoveryPolicy::standard) {
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
        fastnat,
        recovery_policy};
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
        false,
        IdleStallRecoveryPolicy::standard};
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

IdleStallScan preventive_scan(
    std::vector<IdleStallFlowSample> flows,
    std::string opted_in_source) {
    auto result = scan(std::move(flows));
    result.preventive_tcp_reset_sources.insert(
        std::move(opted_in_source));
    return result;
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
    "IdleStallDetector gives only the packaged WhatsApp policy a one-second confirmation") {
    auto official = tcp_sample(
        "192.168.1.44",
        "31.13.66.10",
        41000,
        10,
        1000,
        10,
        1000,
        0U,
        false,
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion);
    IdleStallDetector official_detector;
    CHECK(official_detector.observe(scan({official}), at(0s)).empty());
    official.counters.original_packets += 4;
    official.counters.original_bytes += 600;
    CHECK(official_detector.observe(scan({official}), at(31s)).empty());
    CHECK(official_detector.take_whatsapp_fast_followup_delay() ==
          std::optional<std::chrono::seconds>{1s});
    CHECK_FALSE(
        official_detector.take_whatsapp_fast_followup_delay().has_value());
    CHECK(official_detector.observe(
        scan({official}), at(31s + 999ms)).empty());
    const auto official_decisions =
        official_detector.observe(scan({official}), at(32s));
    REQUIRE(official_decisions.size() == 1U);
    CHECK_FALSE(
        official_detector.take_whatsapp_fast_followup_delay().has_value());

    auto ordinary = tcp_sample(
        "192.168.1.45", "31.13.66.11", 41001,
        10, 1000, 10, 1000);
    IdleStallDetector ordinary_detector;
    CHECK(ordinary_detector.observe(scan({ordinary}), at(0s)).empty());
    ordinary.counters.original_packets += 4;
    ordinary.counters.original_bytes += 600;
    CHECK(ordinary_detector.observe(scan({ordinary}), at(31s)).empty());
    CHECK_FALSE(
        ordinary_detector.take_whatsapp_fast_followup_delay().has_value());
    CHECK(ordinary_detector.observe(scan({ordinary}), at(32s)).empty());
    CHECK(ordinary_detector.observe(
        scan({ordinary}), at(35s + 999ms)).empty());
    REQUIRE(ordinary_detector.observe(scan({ordinary}), at(36s)).size() ==
            1U);
}

TEST_CASE(
    "IdleStallDetector rotates an opted-in packaged WhatsApp 2/2 tuple after a full quiet threshold") {
    const auto whatsapp_policy =
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion;
    const auto frozen = tcp_sample(
        "192.168.1.117",
        "157.240.241.60",
        52341,
        2,
        141,
        2,
        145,
        0x00030000U,
        false,
        whatsapp_policy);
    IdleStallDetector detector;

    CHECK(detector.observe(
        preventive_scan({frozen}, frozen.key.source), at(0s)).empty());
    CHECK(detector.observe(
        preventive_scan({frozen}, frozen.key.source), at(29s)).empty());
    const auto decisions = detector.observe(
        preventive_scan({frozen}, frozen.key.source), at(30s));
    REQUIRE(decisions.size() == 1U);
    CHECK(decisions.front().flow == frozen.key);
    CHECK(decisions.front().reason ==
          IdleStallDecisionReason::idle_opt_in_tcp_reset_rotation);
}

TEST_CASE(
    "IdleStallDetector keeps preventive WhatsApp rotation explicit and tiny") {
    const auto whatsapp_policy =
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion;
    const auto opted_in_source = std::string{"192.168.1.117"};
    const auto unlisted = tcp_sample(
        "192.168.1.118", "157.240.241.60", 52342,
        2, 141, 2, 145, 0x00030000U, false, whatsapp_policy);
    const auto ordinary = tcp_sample(
        opted_in_source, "157.240.241.61", 52343,
        2, 141, 2, 145, 0x00030000U);
    const auto large = tcp_sample(
        opted_in_source, "157.240.241.62", 52344,
        5, 513, 2, 145, 0x00030000U, false, whatsapp_policy);
    const auto markless = tcp_sample(
        opted_in_source, "157.240.241.63", 52345,
        2, 141, 2, 145, 0U, false, whatsapp_policy);
    auto other_port = tcp_sample(
        opted_in_source, "157.240.241.64", 52346,
        2, 141, 2, 145, 0x00030000U, false, whatsapp_policy);
    other_port.key.destination_port = 5222U;

    for (const auto& flow :
         {unlisted, ordinary, large, markless, other_port}) {
        IdleStallDetector detector;
        CHECK(detector.observe(
            preventive_scan({flow}, opted_in_source), at(0s)).empty());
        CHECK(detector.observe(
            preventive_scan({flow}, opted_in_source), at(30s)).empty());
    }
}

TEST_CASE(
    "IdleStallDetector restarts the preventive quiet age on any counter change") {
    const auto whatsapp_policy =
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion;
    auto flow = tcp_sample(
        "192.168.1.117", "157.240.241.60", 52341,
        2, 141, 2, 145, 0x00030000U, false, whatsapp_policy);
    IdleStallDetector detector;
    CHECK(detector.observe(
        preventive_scan({flow}, flow.key.source), at(0s)).empty());

    ++flow.counters.original_packets;
    flow.counters.original_bytes += 20;
    CHECK(detector.observe(
        preventive_scan({flow}, flow.key.source), at(20s)).empty());
    CHECK(detector.observe(
        preventive_scan({flow}, flow.key.source), at(30s)).empty());
    REQUIRE(detector.observe(
        preventive_scan({flow}, flow.key.source), at(50s)).size() == 1U);
}

TEST_CASE(
    "IdleStallDetector blocks preventive reset while the source has active UDP media") {
    const auto whatsapp_policy =
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion;
    const auto signalling = tcp_sample(
        "192.168.1.117", "157.240.241.60", 52341,
        2, 141, 2, 145, 0x00030000U, false, whatsapp_policy);
    auto media = udp_sample(
        signalling.key.source, "157.240.241.61", 40000,
        100, 10000, 100, 10000, 0x00030000U);
    IdleStallDetector detector;
    CHECK(detector.observe(
        preventive_scan(
            {signalling, media}, signalling.key.source),
        at(0s)).empty());

    ++media.counters.original_packets;
    media.counters.original_bytes += 120;
    ++media.counters.reply_packets;
    media.counters.reply_bytes += 120;
    CHECK(detector.observe(
        preventive_scan(
            {signalling, media}, signalling.key.source),
        at(30s)).empty());
}

TEST_CASE(
    "IdleStallDetector cancels packaged WhatsApp confirmation on reply or active UDP media") {
    const auto whatsapp_policy =
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion;
    auto replied = tcp_sample(
        "192.168.1.44", "31.13.66.10", 41000,
        10, 1000, 10, 1000, 0U, false, whatsapp_policy);
    IdleStallDetector reply_detector;
    CHECK(reply_detector.observe(scan({replied}), at(0s)).empty());
    replied.counters.original_packets += 4;
    replied.counters.original_bytes += 600;
    CHECK(reply_detector.observe(scan({replied}), at(31s)).empty());
    REQUIRE(reply_detector.take_whatsapp_fast_followup_delay().has_value());
    replied.counters.reply_packets += 4;
    replied.counters.reply_bytes += 600;
    CHECK(reply_detector.observe(
        scan({replied}), at(31s + 999ms)).empty());
    CHECK_FALSE(
        reply_detector.take_whatsapp_fast_followup_delay().has_value());
    CHECK(reply_detector.observe(scan({replied}), at(40s)).empty());

    auto signalling = tcp_sample(
        "192.168.1.46", "31.13.66.12", 41002,
        10, 1000, 10, 1000, 0U, false, whatsapp_policy);
    auto media = udp_sample(
        "192.168.1.46", "31.13.66.20", 42000,
        100, 10000, 100, 10000);
    IdleStallDetector media_detector;
    CHECK(media_detector.observe(scan({signalling, media}), at(0s)).empty());
    signalling.counters.original_packets += 4;
    signalling.counters.original_bytes += 600;
    CHECK(media_detector.observe(scan({signalling, media}), at(31s)).empty());
    REQUIRE(media_detector.take_whatsapp_fast_followup_delay().has_value());
    media.counters.original_packets += 1;
    media.counters.original_bytes += 120;
    media.counters.reply_packets += 1;
    media.counters.reply_bytes += 120;
    CHECK(media_detector.observe(
        scan({signalling, media}), at(31s + 999ms)).empty());
    CHECK_FALSE(
        media_detector.take_whatsapp_fast_followup_delay().has_value());
    CHECK(media_detector.observe(scan({signalling, media}), at(40s)).empty());
}

TEST_CASE(
    "IdleStallDetector preserves the 256-byte keepalive boundary for WhatsApp") {
    auto flow = tcp_sample(
        "192.168.1.44",
        "31.13.66.10",
        41000,
        10,
        1000,
        10,
        1000,
        0U,
        false,
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion);
    IdleStallDetector detector;
    CHECK(detector.observe(scan({flow}), at(0s)).empty());

    flow.counters.original_packets += 1;
    flow.counters.original_bytes += 256;
    CHECK(detector.observe(scan({flow}), at(31s)).empty());
    CHECK_FALSE(detector.take_whatsapp_fast_followup_delay().has_value());

    flow.counters.original_packets += 1;
    flow.counters.original_bytes += 1;
    CHECK(detector.observe(scan({flow}), at(31s + 500ms)).empty());
    CHECK_FALSE(detector.take_whatsapp_fast_followup_delay().has_value());

    flow.counters.original_packets += 1;
    flow.counters.original_bytes += 257;
    CHECK(detector.observe(scan({flow}), at(32s)).empty());
    CHECK(detector.take_whatsapp_fast_followup_delay() ==
          std::optional<std::chrono::seconds>{1s});
}

TEST_CASE(
    "IdleStallDetector retains a WhatsApp follow-up beside a ready ordinary decision") {
    auto ordinary = tcp_sample(
        "192.168.1.40", "31.13.66.10", 41000,
        10, 1000, 10, 1000);
    auto whatsapp = tcp_sample(
        "192.168.1.44",
        "31.13.66.11",
        41001,
        10,
        1000,
        10,
        1000,
        0U,
        false,
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion);
    IdleStallDetector detector;
    CHECK(detector.observe(scan({ordinary, whatsapp}), at(0s)).empty());

    ordinary.counters.original_packets += 4;
    ordinary.counters.original_bytes += 600;
    CHECK(detector.observe(scan({ordinary, whatsapp}), at(31s)).empty());

    whatsapp.counters.original_packets += 4;
    whatsapp.counters.original_bytes += 600;
    const auto decisions =
        detector.observe(scan({ordinary, whatsapp}), at(36s));
    REQUIRE(decisions.size() == 1U);
    CHECK(decisions.front().flow == ordinary.key);
    CHECK(detector.take_whatsapp_fast_followup_delay() ==
          std::optional<std::chrono::seconds>{1s});
    CHECK_FALSE(detector.take_whatsapp_fast_followup_delay().has_value());
}

TEST_CASE(
    "IdleStallDetector clears WhatsApp follow-up on policy or authority reset") {
    auto flow = tcp_sample(
        "192.168.1.44",
        "31.13.66.10",
        41000,
        10,
        1000,
        10,
        1000,
        0U,
        false,
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion);
    IdleStallDetector policy_detector;
    CHECK(policy_detector.observe(scan({flow}), at(0s)).empty());
    flow.counters.original_packets += 4;
    flow.counters.original_bytes += 600;
    CHECK(policy_detector.observe(scan({flow}), at(31s)).empty());
    flow.recovery_policy = IdleStallRecoveryPolicy::standard;
    CHECK(policy_detector.observe(
        scan({flow}), at(31s + 500ms)).empty());
    CHECK_FALSE(
        policy_detector.take_whatsapp_fast_followup_delay().has_value());
    CHECK(policy_detector.observe(scan({flow}), at(40s)).empty());

    flow.recovery_policy =
        IdleStallRecoveryPolicy::packaged_whatsapp_ip_companion;
    IdleStallDetector authority_detector;
    CHECK(authority_detector.observe(scan({flow}), at(0s)).empty());
    flow.counters.original_packets += 4;
    flow.counters.original_bytes += 600;
    CHECK(authority_detector.observe(scan({flow}), at(31s)).empty());
    auto incomplete = scan({flow});
    incomplete.status.coverage_complete = false;
    CHECK(authority_detector.observe(incomplete, at(31s + 500ms)).empty());
    CHECK_FALSE(
        authority_detector.take_whatsapp_fast_followup_delay().has_value());
    CHECK(authority_detector.tracked_flow_count() == 0U);

    flow.counters.original_packets += 4;
    flow.counters.original_bytes += 600;
    IdleStallDetector reset_detector;
    CHECK(reset_detector.observe(scan({flow}), at(0s)).empty());
    flow.counters.original_packets += 4;
    flow.counters.original_bytes += 600;
    CHECK(reset_detector.observe(scan({flow}), at(31s)).empty());
    reset_detector.reset();
    CHECK_FALSE(
        reset_detector.take_whatsapp_fast_followup_delay().has_value());
    CHECK(reset_detector.tracked_flow_count() == 0U);
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
