#pragma once

// Taking an entry back out again.
//
// Every NFQUEUE rule that feeds nfqws2 is bound to the provider's device -
// `-o eth3` and `-i eth3` on the owner's router. The moment a host is routed
// into a tunnel its packets stop passing that device, so nfqws2 never sees it
// again: no new failures, no recovery, no evidence of any kind. The signal that
// justified the entry is destroyed by acting on it. Left alone, such a list only
// grows, and a year later it carries domains that have worked directly for
// months with nothing able to notice.
//
// The way out is that the differential probe does not read the routing table at
// all - it binds each leg to a device. So an entry can be re-examined exactly
// as it was judged in the first place, without unrouting it, without touching
// the configuration, and without a moment of disruption for anyone.
//
// What this file holds is the decision made on the answer, which needs to be
// harder to move than the answer itself:
//
//   - a verdict that proves nothing must not push an entry either way;
//   - one direct success must not retire an entry, because DPI does miss
//     connections and a site that answers once may be silent the next minute;
//   - an entry that has been retired once and came back must be harder to
//     retire the second time, or a flapping site will be added and removed
//     forever.
//
// Retirement is a proposal, not an act. The probe runs from the router, and a
// LAN client's forwarded packets do not take exactly the router's path; that is
// close enough to judge by and not close enough to move somebody's traffic on
// silently.

#include "differential_probe.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace keen_pbr3 {

enum class ReviewAction {
    // Still needs the tunnel.
    keep,
    // It answered directly often enough to be offered back. A proposal for the
    // operator, never a removal.
    propose_retirement,
    // The answer said nothing about this entry. Change nothing, including the
    // counters.
    hold,
};

struct ReviewRecord {
    std::string host;
    // Consecutive verdicts where the target answered directly.
    std::uint32_t direct_successes{0};
    // Consecutive verdicts that confirmed the block. Drives how rarely we look.
    std::uint32_t blocked_confirmations{0};
    // How many times this host has already been retired and come back. Each
    // round makes the next retirement harder.
    std::uint32_t retirements{0};
    DifferentialVerdict last{DifferentialVerdict::inconclusive};
};

struct ReviewPolicy {
    // Consecutive direct successes needed the first time. Raised by one for
    // every previous retirement of the same host.
    std::uint32_t retire_after{3};
    // Ceiling for that growth, so a genuinely flapping host settles at a fixed
    // cost rather than becoming unretirable.
    std::uint32_t max_retire_after{8};
    // How soon to look again when nothing has changed.
    std::chrono::minutes base_interval{60};
    // Doubling stops here.
    std::chrono::minutes max_interval{1440};
};

// Applies one probe verdict to a record and says what to do. The record is
// updated in place; a `hold` leaves every counter untouched.
ReviewAction review_step(ReviewRecord& record,
                         DifferentialVerdict verdict,
                         const ReviewPolicy& policy) noexcept;

// How long to wait before probing this entry again.
//
// Confirmations make the interval double, because an entry the provider has
// blocked ten times running is not about to change; a single direct success
// pulls it straight back to the base interval, because that is the one moment
// the answer is worth chasing.
std::chrono::minutes next_review_interval(const ReviewRecord& record,
                                          const ReviewPolicy& policy) noexcept;

// The threshold this host has to clear right now, given how often it has been
// retired before.
std::uint32_t effective_retire_after(const ReviewRecord& record,
                                     const ReviewPolicy& policy) noexcept;

// Called when the operator accepts a proposal, so the next round starts from a
// higher bar. Kept separate from review_step because accepting is the
// operator's act, not the probe's.
void note_retirement(ReviewRecord& record) noexcept;

const char* review_action_name(ReviewAction action) noexcept;

}  // namespace keen_pbr3
