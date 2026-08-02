#pragma once

#include <chrono>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "netlink.hpp"

namespace keen_pbr3 {

enum class RouteReconcileMode {
    Strict,
    DeferredRepair,
};

namespace route_table_detail {

// Linux normalizes an IPv6 route without an explicit priority to metric 1024,
// while IPv4 keeps metric 0. Treat those two IPv6 representations as the same
// route without weakening metric matching for weighted urltest routes.
bool route_metric_matches_live(const RouteSpec& expected,
                               const DumpedRoute& actual);

// Exact identity used by the runtime reconciler. Metrics and the reserved
// protocol are part of the identity because urltest intentionally keeps
// several default routes through the same interface with different metrics.
bool route_matches_live(const RouteSpec& expected, const DumpedRoute& actual);

std::vector<RouteSpec> find_missing_live_routes(
    const std::vector<RouteSpec>& desired,
    const std::vector<DumpedRoute>& live);

enum class RouteRepairLogDecision {
    Info,
    Warning,
    Suppress,
};

struct RouteRepairRateState {
    std::deque<std::chrono::steady_clock::time_point> recent_repairs;
    std::optional<std::chrono::steady_clock::time_point> last_warning;
};

// A single successful repair is routine self-healing. Three repairs of the
// same route inside five minutes indicate an external owner or a flapping
// interface and deserve one warning, then silence for five minutes.
RouteRepairLogDecision record_route_repair(
    RouteRepairRateState& state,
    std::chrono::steady_clock::time_point now);

} // namespace route_table_detail

// Manages installed kernel routes, tracking them for duplicate avoidance and cleanup.
// Uses NetlinkManager for actual kernel operations.
class RouteTable {
public:
    using Clock = std::chrono::steady_clock;
    using InterfaceReadinessProbe =
        std::function<netlink_detail::InterfaceAdminState(const std::string&)>;
    using NowFunction = std::function<Clock::time_point()>;

    // If dry_run is true, add()/clear() only track specs and skip netlink ops.
    explicit RouteTable(
        RouteNetlinkOperations& netlink,
        bool dry_run = false,
        InterfaceReadinessProbe interface_readiness_probe = {},
        NowFunction now = {});
    ~RouteTable();

    // Non-copyable
    RouteTable(const RouteTable&) = delete;
    RouteTable& operator=(const RouteTable&) = delete;

    // Add a route. If an identical route is already tracked, this is a no-op.
    void add(const RouteSpec& spec);

    // Remove a specific route. If not tracked, this is a no-op.
    void remove(const RouteSpec& spec);

    // Install missing routes before removing obsolete routes tracked by this
    // process. Live kernel state is reconciled as well: firmware interface
    // restarts may discard a route without updating this process' inventory.
    // This keeps the old forwarding path available while a new one is being
    // installed.
    void reconcile(
        const std::vector<RouteSpec>& desired,
        RouteReconcileMode mode = RouteReconcileMode::Strict);
    void add_missing(
        const std::vector<RouteSpec>& desired,
        RouteReconcileMode mode = RouteReconcileMode::Strict);
    void remove_obsolete(const std::vector<RouteSpec>& desired);

    // Replace the tracked desired snapshot without mutating netlink. Existing
    // kernel objects are observed, not claimed, until this process creates a
    // replacement itself.
    void adopt_desired(const std::vector<RouteSpec>& desired);

    // An explicit kernel UP transition is stronger than a pending retry
    // deadline. Clear only the matching interface's backoff so its routes are
    // eligible for the immediate event-driven reconciliation.
    void notify_interface_up(const std::string& interface_name);

    // Remove all installed routes (shutdown cleanup).
    void clear();

    // Number of currently tracked routes.
    size_t size() const { return routes_.size(); }

    // Read-only access to the tracked routes.
    const std::vector<RouteSpec>& get_routes() const { return routes_; }

private:
    struct RouteRepairRecord {
        RouteSpec route;
        route_table_detail::RouteRepairRateState rate;
        std::size_t consecutive_deferrals{0};
        std::optional<Clock::time_point> retry_after;
    };

    RouteNetlinkOperations& netlink_;
    bool dry_run_{false};
    InterfaceReadinessProbe interface_readiness_probe_;
    NowFunction now_;
    std::vector<RouteSpec> routes_;
    std::vector<RouteSpec> owned_routes_;
    std::vector<RouteRepairRecord> repair_records_;

    // Check if an identical route is already tracked.
    bool is_tracked(const RouteSpec& spec) const;
    route_table_detail::RouteRepairLogDecision record_repair(
        const RouteSpec& spec);
    RouteRepairRecord& repair_record(const RouteSpec& spec);
    bool repair_retry_due(const RouteSpec& spec) const;
    void defer_repair(const RouteSpec& spec);
    void reset_repair_backoff(const RouteSpec& spec);
    RouteAddResult add_route_checked(const RouteSpec& spec);
    void forget_owned_route(const RouteSpec& spec);
    void forget_repair_record(const RouteSpec& spec);
};

} // namespace keen_pbr3
