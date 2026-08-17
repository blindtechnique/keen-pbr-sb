#include "interface_traffic_cadence.hpp"

#include <algorithm>

namespace keen_pbr3 {

bool InterfaceTrafficCadence::begin_tick() {
    if (++ticks_since_sample_ < divider_) {
        return false;
    }
    ticks_since_sample_ = 0;
    return true;
}

void InterfaceTrafficCadence::end_round(bool anything_changed) {
    if (anything_changed) {
        // Snap back outright rather than stepping down. Stepping would keep
        // sampling a link that has just started moving at a stretched rate for
        // several more rounds, which is precisely when the readings matter.
        idle_rounds_ = 0;
        divider_ = kFastDivider;
        return;
    }

    if (++idle_rounds_ < kIdleRoundsBeforeBackoff) {
        return;
    }
    idle_rounds_ = 0;
    divider_ = std::min(divider_ + 1, kMaxDivider);
}

void InterfaceTrafficCadence::reset() {
    divider_ = kFastDivider;
    ticks_since_sample_ = 0;
    idle_rounds_ = 0;
}

} // namespace keen_pbr3
