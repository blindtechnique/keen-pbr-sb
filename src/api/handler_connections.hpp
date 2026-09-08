#pragma once

#ifdef WITH_API
#include "handlers.hpp"
#include <cstddef>
#include <cstdint>
#include <istream>
#include <map>
#include <vector>
namespace keen_pbr3 {
namespace connection_detail {
struct HistoryEntry {
    std::string protocol, state, source, destination, route;
    uint16_t source_port{0}, destination_port{0};
    uint32_t mark{0};
    std::int64_t first_seen{0}, last_seen{0};
    bool active{true};
    // Distinct from active: a TCP TIME_WAIT row may still be in /proc,
    // whereas a retained CLOSED history row is not current kernel evidence.
    bool observed_in_snapshot{false};
};
using History = std::map<std::string, HistoryEntry>;
struct SnapshotObservation {
    bool available{false};
    std::int64_t snapshot_at{0};
    bool truncated{false};
};
// Merge one readable /proc snapshot into the existing bounded RAM history.
// This stream seam is also used by the parser/retention regression tests.
void update_history(History& history, std::istream& input,
                    const std::map<uint32_t, std::string>& route_names,
                    uint32_t mark_mask, std::int64_t timestamp,
                    SnapshotObservation* observation = nullptr);
}
struct RoutingConnectionsSnapshot {
    bool snapshot_available{false};
    std::int64_t snapshot_at{0};
    // Matches in the existing bounded current snapshot, not the full kernel
    // table when truncated. An empty partial snapshot proves no absence.
    std::size_t total{0};
    bool truncated{false};
    std::vector<connection_detail::HistoryEntry> rows;
};
namespace connection_detail {
// Pure projection of one observed snapshot; never includes retained history.
RoutingConnectionsSnapshot select_routing_connections(
    const History& history, const SnapshotObservation& observation,
    const std::vector<std::string>& destination_ips);
}
// Read-only reuse of the existing /proc snapshot and its two-second cache.
// No device-name/NDMS or DNS query is performed for these raw observations.
RoutingConnectionsSnapshot get_routing_connections(
    const Config& config, const std::vector<std::string>& destination_ips);
void register_connections_handler(ApiServer& server, ApiContext& ctx);
// Marks the cached /proc snapshot stale after a kernel conntrack event. Cursor
// snapshots remain immutable; only the next first-page query is refreshed.
void invalidate_connections_snapshot();
}
#endif
