#pragma once

#include <vector>

#include "netlink.hpp"

namespace keen_pbr3 {

// Manages installed kernel routes, tracking them for duplicate avoidance and cleanup.
// Uses NetlinkManager for actual kernel operations.
class RouteTable {
public:
    // If dry_run is true, add()/clear() only track specs and skip netlink ops.
    explicit RouteTable(NetlinkManager& netlink, bool dry_run = false);
    ~RouteTable();

    // Non-copyable
    RouteTable(const RouteTable&) = delete;
    RouteTable& operator=(const RouteTable&) = delete;

    // Add a route. If an identical route is already tracked, this is a no-op.
    void add(const RouteSpec& spec);

    // Remove a specific route. If not tracked, this is a no-op.
    void remove(const RouteSpec& spec);

    // Install missing routes before removing obsolete routes tracked by this
    // process. This keeps the old forwarding path available while a new one
    // is being installed.
    void reconcile(const std::vector<RouteSpec>& desired);
    void add_missing(const std::vector<RouteSpec>& desired);
    void remove_obsolete(const std::vector<RouteSpec>& desired);

    // Remove all installed routes (shutdown cleanup).
    void clear();

    // Number of currently tracked routes.
    size_t size() const { return routes_.size(); }

    // Read-only access to the tracked routes.
    const std::vector<RouteSpec>& get_routes() const { return routes_; }

private:
    NetlinkManager& netlink_;
    bool dry_run_{false};
    std::vector<RouteSpec> routes_;

    // Check if an identical route is already tracked.
    bool is_tracked(const RouteSpec& spec) const;
};

} // namespace keen_pbr3
