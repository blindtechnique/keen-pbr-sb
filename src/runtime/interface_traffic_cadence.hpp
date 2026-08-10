#pragma once

#include <cstdint>

namespace keen_pbr3 {

// Decides which ticks of the fixed-rate sampling timer actually take a
// reading.
//
// Cadence is expressed as a divider over a fast tick rather than as a
// changing interval because the scheduler can only create and cancel timers,
// not retune a live one. Skipping ticks achieves the same effective rate
// without tearing the timer down and rebuilding it underneath a running
// round.
//
// The policy is deliberately asymmetric. Backing off is slow and bounded,
// because every skipped tick is detection latency: a burst that starts during
// a stretched interval is noticed late. Returning to the fast rate is
// immediate - the first reading that shows any movement restores it outright
// rather than stepping back down - so the cost of guessing wrong is one
// stretched interval, not a slow recovery.
//
// Note what this does NOT have to handle: nobody watching at all. The caller
// already stops sampling entirely when the SSE stream has no subscribers, so
// this only ever chooses between fast and slow for a dashboard someone
// actually has open.
class InterfaceTrafficCadence {
public:
    // One tick is the sampling timer's fixed period.
    static constexpr std::uint32_t kFastDivider = 1;
    // Five ticks at the two-second timer is a ten-second worst case before an
    // idle interface that starts moving is noticed.
    static constexpr std::uint32_t kMaxDivider = 5;
    // How many consecutive unchanged rounds justify stretching one step. A
    // single quiet round is normal even on a busy link.
    static constexpr std::uint32_t kIdleRoundsBeforeBackoff = 5;

    // Call exactly once per timer tick. Returns true when this tick should
    // take a reading.
    bool begin_tick();

    // Call after a round that actually read counters. `anything_changed` is
    // true when at least one sampled interface reported a change in the state
    // clients can see.
    void end_round(bool anything_changed);

    // Returns to the fast rate immediately. Called when the set of watched
    // interfaces changes: someone just opened a screen and is waiting for it
    // to fill in, which is the worst possible moment to be mid-backoff.
    void reset();

    std::uint32_t divider() const { return divider_; }

private:
    std::uint32_t divider_{kFastDivider};
    std::uint32_t ticks_since_sample_{0};
    std::uint32_t idle_rounds_{0};
};

} // namespace keen_pbr3
