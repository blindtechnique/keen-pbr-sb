#include "entry_review.hpp"

#include <algorithm>

namespace keen_pbr3 {

namespace {

// Doubling past this would overflow the shift long before it reaches
// max_interval on any sane policy.
constexpr std::uint32_t kMaxDoublings = 16U;

}  // namespace

std::uint32_t effective_retire_after(const ReviewRecord& record,
                                     const ReviewPolicy& policy) noexcept {
    const auto floor_value = policy.retire_after == 0U ? 1U : policy.retire_after;
    const auto ceiling = std::max(floor_value, policy.max_retire_after);
    const auto raised = floor_value + record.retirements;
    return raised > ceiling ? ceiling : raised;
}

ReviewAction review_step(ReviewRecord& record,
                         const DifferentialVerdict verdict,
                         const ReviewPolicy& policy) noexcept {
    switch (verdict) {
        case DifferentialVerdict::works_without_help: {
            record.last = verdict;
            record.blocked_confirmations = 0U;
            if (record.direct_successes < UINT32_MAX) ++record.direct_successes;
            return record.direct_successes >= effective_retire_after(record, policy)
                       ? ReviewAction::propose_retirement
                       : ReviewAction::keep;
        }
        case DifferentialVerdict::blocked_here: {
            record.last = verdict;
            // One confirmed block undoes the whole run towards retirement: the
            // successes were consecutive by definition, and they are not any
            // more.
            record.direct_successes = 0U;
            if (record.blocked_confirmations < UINT32_MAX) {
                ++record.blocked_confirmations;
            }
            return ReviewAction::keep;
        }
        case DifferentialVerdict::down_everywhere:
        case DifferentialVerdict::tunnel_broken:
        case DifferentialVerdict::inconclusive:
            break;
    }

    // Nothing was learned about this entry.
    //
    // down_everywhere is an outage at the target, tunnel_broken is a fault in
    // the transport, and inconclusive means a leg could not prove which path it
    // took. Letting any of them touch the counters would let an outage retire
    // an entry - or a broken tunnel confirm a block that nobody measured.
    return ReviewAction::hold;
}

std::chrono::minutes next_review_interval(const ReviewRecord& record,
                                          const ReviewPolicy& policy) noexcept {
    const auto base = policy.base_interval.count() <= 0
                          ? std::chrono::minutes{1}
                          : policy.base_interval;
    const auto cap = policy.max_interval < base ? base : policy.max_interval;

    // A host that just answered directly is the one worth chasing: come back at
    // the base interval so the run of confirmations finishes quickly instead of
    // dragging over days.
    if (record.direct_successes > 0U) return base;

    const auto doublings = std::min(record.blocked_confirmations, kMaxDoublings);
    auto minutes = base.count();
    for (std::uint32_t i = 0U; i < doublings; ++i) {
        if (minutes >= cap.count()) break;
        minutes *= 2;
    }
    return std::chrono::minutes{std::min(minutes, cap.count())};
}

void note_retirement(ReviewRecord& record) noexcept {
    if (record.retirements < UINT32_MAX) ++record.retirements;
    record.direct_successes = 0U;
    record.blocked_confirmations = 0U;
    record.last = DifferentialVerdict::works_without_help;
}

const char* review_action_name(const ReviewAction action) noexcept {
    switch (action) {
        case ReviewAction::keep:
            return "keep";
        case ReviewAction::propose_retirement:
            return "propose_retirement";
        case ReviewAction::hold:
            break;
    }
    return "hold";
}

}  // namespace keen_pbr3
