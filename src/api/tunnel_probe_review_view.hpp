#pragma once

#include "generated/api_types.hpp"
#include "../health/tunnel_probe_review.hpp"
#include <algorithm>
#include <limits>

namespace keen_pbr3 {

// A proposal belongs to one measured ISP/tunnel context and current membership.
// An old sidecar is history, not permission to label a different path healthy.
inline void append_tunnel_probe_review_view(
    api::TunnelProbeHostsResponse& response,
    const TunnelProbeReviewState& state,
    const std::string& current_context,
    bool readable) {
    response.reviews = std::vector<api::TunnelProbeHostReview>{};
    response.review_available = readable && !current_context.empty() &&
                                state.context == current_context;
    response.review_limited = response.routed.size() > kTunnelProbeReviewMaxEntries;
    if (!*response.review_available) return;
    for (const auto& entry : filter_tunnel_probe_reviews(
             state, response.routed, response.excluded)) {
        api::TunnelProbeHostReview item;
        item.host = entry.record.host;
        item.direct_successes = entry.record.direct_successes;
        item.required_successes = effective_retire_after(entry.record, ReviewPolicy{});
        item.suggested = entry.eligible &&
            entry.last_observation == DifferentialVerdict::works_without_help;
        if (entry.last_checked_unix_ms != 0U)
            item.last_checked_unix_ms = static_cast<int64_t>(std::min(
                entry.last_checked_unix_ms, static_cast<std::uint64_t>(std::numeric_limits<int64_t>::max())));
        if (entry.next_due_unix_ms != 0U)
            item.next_check_unix_ms = static_cast<int64_t>(std::min(
                entry.next_due_unix_ms, static_cast<std::uint64_t>(std::numeric_limits<int64_t>::max())));
        response.reviews->push_back(std::move(item));
    }
}

} // namespace keen_pbr3
