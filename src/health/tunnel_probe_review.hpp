#pragma once

#include "entry_review.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace keen_pbr3 {

inline constexpr std::size_t kTunnelProbeReviewMaxEntries = 512U;
inline constexpr std::size_t kTunnelProbeReviewMaxBytes = 384U * 1024U;

struct TunnelProbeReviewEntry {
    ReviewRecord record;
    bool active{false};
    bool eligible{false};
    // Unlike ReviewRecord::last, this records inconclusive observations too.
    DifferentialVerdict last_observation{DifferentialVerdict::inconclusive};
    std::uint64_t last_checked_unix_ms{0};
    std::uint64_t next_due_unix_ms{0};
    std::uint64_t updated_at_unix_ms{0};
};

struct TunnelProbeReviewState {
    std::string context;
    std::vector<TunnelProbeReviewEntry> entries;
    // Current routed membership exceeds the finite review capacity. Ordinary
    // pruning of old inactive retirement history is not an operational error.
    bool limited{false};
};

// Shared only by local list/sidecar read-modify-write operations. Callers never
// hold it while probing, reading nfqws logs, refreshing routing or publishing.
// Functions below do not lock it, so one caller can group related file writes.
std::mutex& tunnel_probe_list_io_mutex();

std::string tunnel_probe_review_path(const std::string& list_file);
std::string tunnel_probe_review_context(const std::string& outbound_tag,
                                       const std::string& interface,
                                       const std::string& isp_interface,
                                       const std::string& list_name,
                                       const std::string& list_file);

// Missing sidecar is a normal empty history. Corrupt/oversized/unreadable
// metadata returns an empty state and an error; callers may still edit lists.
TunnelProbeReviewState load_tunnel_probe_review(
    const std::string& list_file, std::string& error);
bool save_tunnel_probe_review(const std::string& list_file,
                             const TunnelProbeReviewState& state,
                             std::string& error);

// Refresh membership before choosing due entries and again after network I/O.
// Changing ISP/tunnel/list context clears old verdicts, not retirement history.
// Excluded or no-longer-routed hosts remain inactive bounded history only.
// Returns true only when persistent metadata changed (idle passes need no write).
bool sync_tunnel_probe_review(TunnelProbeReviewState& state,
                              const std::string& context,
                              const std::vector<std::string>& routed,
                              const std::vector<std::string>& excluded,
                              std::uint64_t now_unix_ms);

std::vector<std::string> due_tunnel_probe_reviews(
    const TunnelProbeReviewState& state, std::uint64_t now_unix_ms,
    std::size_t limit);

// Read-only API view, restricted to current membership without needing ISP
// discovery. This does not activate historical entries or publish proposals.
std::vector<TunnelProbeReviewEntry> filter_tunnel_probe_reviews(
    const TunnelProbeReviewState& state,
    const std::vector<std::string>& routed,
    const std::vector<std::string>& excluded);

// Apply one due observation to a current active entry. Caller re-loads and
// syncs fresh lists/context after probing under the short file I/O mutex.
bool observe_tunnel_probe_review(
    TunnelProbeReviewState& state, const std::string& context,
    const std::string& host, DifferentialVerdict verdict,
    std::uint64_t now_unix_ms, const ReviewPolicy& policy = {});

// Explicit user removal: keep the retirement count, clear the proposal and
// deactivate this entry. Never modifies the routed or excluded list itself.
void note_tunnel_probe_review_removal(TunnelProbeReviewState& state,
                                    const std::string& host,
                                    std::uint64_t now_unix_ms);

} // namespace keen_pbr3
