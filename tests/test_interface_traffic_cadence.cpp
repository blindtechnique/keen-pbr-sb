#include <doctest/doctest.h>

#include "runtime/interface_traffic_cadence.hpp"

#include <cstdint>

namespace keen_pbr3 {

namespace {

// Drives `rounds` consecutive ticks in which nothing ever changes, and returns
// how many of them actually took a reading.
std::uint32_t sample_count_over_idle_ticks(InterfaceTrafficCadence& cadence,
                                           std::uint32_t ticks) {
    std::uint32_t sampled = 0;
    for (std::uint32_t tick = 0; tick < ticks; ++tick) {
        if (cadence.begin_tick()) {
            ++sampled;
            cadence.end_round(false);
        }
    }
    return sampled;
}

} // namespace

TEST_CASE("a fresh cadence samples every tick") {
    InterfaceTrafficCadence cadence;

    CHECK(cadence.divider() == InterfaceTrafficCadence::kFastDivider);
    for (int tick = 0; tick < 4; ++tick) {
        CHECK(cadence.begin_tick());
        cadence.end_round(true);
    }
}

TEST_CASE("a link that keeps moving is never slowed down") {
    InterfaceTrafficCadence cadence;

    for (int tick = 0; tick < 200; ++tick) {
        REQUIRE(cadence.begin_tick());
        cadence.end_round(true);
    }

    CHECK(cadence.divider() == InterfaceTrafficCadence::kFastDivider);
}

TEST_CASE("a single quiet round does not stretch the interval") {
    InterfaceTrafficCadence cadence;

    REQUIRE(cadence.begin_tick());
    cadence.end_round(false);

    // One unchanged round is ordinary even on a busy link; reacting to it
    // would make the cadence oscillate instead of adapt.
    CHECK(cadence.divider() == InterfaceTrafficCadence::kFastDivider);
    CHECK(cadence.begin_tick());
}

TEST_CASE("sustained silence stretches the interval step by step") {
    InterfaceTrafficCadence cadence;

    for (std::uint32_t round = 0;
         round < InterfaceTrafficCadence::kIdleRoundsBeforeBackoff; ++round) {
        REQUIRE(cadence.begin_tick());
        cadence.end_round(false);
    }

    CHECK(cadence.divider() == InterfaceTrafficCadence::kFastDivider + 1);
}

TEST_CASE("the interval never stretches past the bound") {
    InterfaceTrafficCadence cadence;

    // Far more idle ticks than the ladder has steps.
    sample_count_over_idle_ticks(cadence, 5'000);

    // Detection latency is bounded by this: an idle interface that starts
    // moving is noticed within kMaxDivider ticks, never later.
    CHECK(cadence.divider() == InterfaceTrafficCadence::kMaxDivider);
}

TEST_CASE("a stretched cadence really does skip ticks") {
    InterfaceTrafficCadence cadence;

    sample_count_over_idle_ticks(cadence, 5'000);
    REQUIRE(cadence.divider() == InterfaceTrafficCadence::kMaxDivider);

    const auto sampled = sample_count_over_idle_ticks(cadence, 100);

    // The point of the backoff is fewer counter reads, not merely a smaller
    // number in a field. 100 ticks at the maximum divider is 20 readings.
    CHECK(sampled == 100 / InterfaceTrafficCadence::kMaxDivider);
}

TEST_CASE("the first sign of movement restores the fast rate outright") {
    InterfaceTrafficCadence cadence;

    sample_count_over_idle_ticks(cadence, 5'000);
    REQUIRE(cadence.divider() == InterfaceTrafficCadence::kMaxDivider);

    // Walk to the next tick that reads, and let it observe traffic.
    while (!cadence.begin_tick()) {
    }
    cadence.end_round(true);

    // Stepping back down instead would keep a link that has just come alive
    // at a stretched rate for several more rounds - exactly when its readings
    // matter most.
    CHECK(cadence.divider() == InterfaceTrafficCadence::kFastDivider);
    CHECK(cadence.begin_tick());
}

TEST_CASE("reset restores the fast rate and samples immediately") {
    InterfaceTrafficCadence cadence;

    sample_count_over_idle_ticks(cadence, 5'000);
    REQUIRE(cadence.divider() == InterfaceTrafficCadence::kMaxDivider);

    cadence.reset();

    // Someone just opened a screen. Making them wait out a stretched interval
    // for the first reading is the failure this exists to prevent.
    CHECK(cadence.divider() == InterfaceTrafficCadence::kFastDivider);
    CHECK(cadence.begin_tick());
}

} // namespace keen_pbr3
