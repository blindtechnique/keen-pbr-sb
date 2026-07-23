#include "route_table.hpp"

#include "../log/logger.hpp"

#include <algorithm>

namespace keen_pbr3 {

namespace {

bool routes_equal(const RouteSpec& a, const RouteSpec& b) {
    return a.destination == b.destination &&
           a.table == b.table &&
           a.interface == b.interface &&
           a.gateway == b.gateway &&
           a.blackhole == b.blackhole &&
           a.unreachable == b.unreachable &&
           a.family == b.family &&
           a.metric == b.metric &&
           a.protocol == b.protocol;
}

} // anonymous namespace

RouteTable::RouteTable(NetlinkManager& netlink, bool dry_run)
    : netlink_(netlink),
      dry_run_(dry_run) {}

RouteTable::~RouteTable() {
    // Best-effort cleanup on destruction
    try {
        clear();
    } catch (const std::exception& e) {
        Logger::instance().error("RouteTable cleanup failed during destruction: {}",
                                 e.what());
    } catch (...) {
        Logger::instance().error("RouteTable cleanup failed during destruction: unknown error");
    }
}

bool RouteTable::is_tracked(const RouteSpec& spec) const {
    return std::any_of(routes_.begin(), routes_.end(),
                       [&](const RouteSpec& r) { return routes_equal(r, spec); });
}

void RouteTable::add(const RouteSpec& spec) {
    if (is_tracked(spec)) {
        return;
    }
    if (!dry_run_) {
        netlink_.add_route(spec);
    }
    routes_.push_back(spec);
}

void RouteTable::remove(const RouteSpec& spec) {
    auto it = std::find_if(routes_.begin(), routes_.end(),
                           [&](const RouteSpec& r) { return routes_equal(r, spec); });
    if (it == routes_.end()) {
        return;
    }
    if (!dry_run_) {
        try {
            netlink_.delete_route(spec);
        } catch (const std::exception& e) {
            Logger::instance().error(
                "Failed to delete route (dst={}, table={}, iface={}, gw={}, metric={}, blackhole={}, unreachable={}): {}",
                spec.destination,
                spec.table,
                spec.interface.value_or("(none)"),
                spec.gateway.value_or("(none)"),
                spec.metric,
                spec.blackhole,
                spec.unreachable,
                e.what());
            return;
        }
    }
    routes_.erase(it);
}

void RouteTable::reconcile(const std::vector<RouteSpec>& desired) {
    add_missing(desired);
    remove_obsolete(desired);
}

void RouteTable::add_missing(const std::vector<RouteSpec>& desired) {
    for (const RouteSpec& route : desired) {
        add(route);
    }
}

void RouteTable::remove_obsolete(const std::vector<RouteSpec>& desired) {
    const std::vector<RouteSpec> current = routes_;
    for (const RouteSpec& route : current) {
        const bool still_desired = std::any_of(desired.begin(), desired.end(),
                                               [&](const RouteSpec& candidate) {
                                                   return routes_equal(route, candidate);
                                               });
        if (!still_desired) {
            remove(route);
        }
    }
}

void RouteTable::clear() {
    // Never flush a whole numeric table: Keenetic or another package may own
    // unrelated routes there. Only delete objects created and tracked by this
    // RouteTable instance, in reverse order like policy-rule cleanup.
    const std::vector<RouteSpec> tracked = routes_;
    for (auto it = tracked.rbegin(); it != tracked.rend(); ++it) {
        remove(*it);
    }
}

} // namespace keen_pbr3
