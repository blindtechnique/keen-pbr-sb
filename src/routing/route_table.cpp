#include "route_table.hpp"

#include "../log/logger.hpp"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <sys/socket.h>

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

namespace route_table_detail {

bool route_metric_matches_live(const RouteSpec& expected,
                               const DumpedRoute& actual) {
    if (expected.metric == actual.metric) {
        return true;
    }
    return expected.metric == 0 &&
           actual.metric == 1024 &&
           (expected.family == AF_INET6 || actual.family == AF_INET6);
}

bool route_matches_live(const RouteSpec& expected, const DumpedRoute& actual) {
    return expected.destination == actual.destination &&
           expected.table == actual.table &&
           expected.interface == actual.interface &&
           expected.gateway == actual.gateway &&
           expected.blackhole == actual.blackhole &&
           expected.unreachable == actual.unreachable &&
           (expected.family == 0 || expected.family == actual.family) &&
           route_metric_matches_live(expected, actual) &&
           expected.protocol == actual.protocol;
}

std::vector<RouteSpec> find_missing_live_routes(
    const std::vector<RouteSpec>& desired,
    const std::vector<DumpedRoute>& live) {
    std::vector<RouteSpec> missing;
    for (const auto& route : desired) {
        const bool present = std::any_of(
            live.begin(),
            live.end(),
            [&](const DumpedRoute& candidate) {
                return route_matches_live(route, candidate);
            });
        if (!present) {
            missing.push_back(route);
        }
    }
    return missing;
}

RouteRepairLogDecision record_route_repair(
    RouteRepairRateState& state,
    std::chrono::steady_clock::time_point now) {
    constexpr auto window = std::chrono::minutes{5};
    constexpr auto warning_cooldown = std::chrono::minutes{5};
    constexpr std::size_t warning_threshold = 3;

    if (!state.recent_repairs.empty() &&
        now < state.recent_repairs.back()) {
        state.recent_repairs.clear();
        state.last_warning.reset();
    }
    while (!state.recent_repairs.empty() &&
           now - state.recent_repairs.front() > window) {
        state.recent_repairs.pop_front();
    }
    state.recent_repairs.push_back(now);
    while (state.recent_repairs.size() > warning_threshold) {
        state.recent_repairs.pop_front();
    }

    if (state.recent_repairs.size() < warning_threshold) {
        return RouteRepairLogDecision::Info;
    }
    if (!state.last_warning.has_value() ||
        now < *state.last_warning ||
        now - *state.last_warning >= warning_cooldown) {
        state.last_warning = now;
        return RouteRepairLogDecision::Warning;
    }
    return RouteRepairLogDecision::Suppress;
}

} // namespace route_table_detail

RouteTable::RouteTable(RouteNetlinkOperations& netlink, bool dry_run)
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

route_table_detail::RouteRepairLogDecision RouteTable::record_repair(
    const RouteSpec& spec) {
    auto it = std::find_if(
        repair_records_.begin(),
        repair_records_.end(),
        [&](const RouteRepairRecord& record) {
            return routes_equal(record.route, spec);
        });
    if (it == repair_records_.end()) {
        repair_records_.push_back({spec, {}});
        it = std::prev(repair_records_.end());
    }
    return route_table_detail::record_route_repair(
        it->rate, std::chrono::steady_clock::now());
}

void RouteTable::forget_repair_record(const RouteSpec& spec) {
    repair_records_.erase(
        std::remove_if(
            repair_records_.begin(),
            repair_records_.end(),
            [&](const RouteRepairRecord& record) {
                return routes_equal(record.route, spec);
            }),
        repair_records_.end());
}

void RouteTable::add(const RouteSpec& spec) {
    if (is_tracked(spec)) {
        return;
    }
    bool owned = dry_run_;
    if (!dry_run_) {
        owned = netlink_.add_route(spec) == RouteAddResult::Created;
    }
    routes_.push_back(spec);
    if (owned) {
        owned_routes_.push_back(spec);
    }
}

void RouteTable::remove(const RouteSpec& spec) {
    auto it = std::find_if(routes_.begin(), routes_.end(),
                           [&](const RouteSpec& r) { return routes_equal(r, spec); });
    if (it == routes_.end()) {
        return;
    }
    auto owned_it = std::find_if(
        owned_routes_.begin(), owned_routes_.end(),
        [&](const RouteSpec& route) { return routes_equal(route, spec); });
    if (!dry_run_ && owned_it != owned_routes_.end()) {
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
    if (owned_it != owned_routes_.end()) {
        owned_routes_.erase(owned_it);
    }
    forget_repair_record(spec);
    routes_.erase(it);
}

void RouteTable::reconcile(const std::vector<RouteSpec>& desired) {
    add_missing(desired);
    remove_obsolete(desired);
}

void RouteTable::add_missing(const std::vector<RouteSpec>& desired) {
    if (!dry_run_) {
        const auto live = netlink_.dump_routes();
        const auto missing_live =
            route_table_detail::find_missing_live_routes(desired, live);

        for (const auto& route : missing_live) {
            if (!is_tracked(route)) {
                continue;
            }

            if (netlink_.add_route(route) == RouteAddResult::Created) {
                const auto log_decision = record_repair(route);
                if (log_decision ==
                    route_table_detail::RouteRepairLogDecision::Info) {
                    Logger::instance().info(
                        "Restoring vanished managed route (dst={}, table={}, iface={}, gw={}, metric={}, protocol={})",
                        route.destination,
                        route.table,
                        route.interface.value_or("(none)"),
                        route.gateway.value_or("(none)"),
                        route.metric,
                        static_cast<unsigned>(route.protocol));
                } else if (
                    log_decision ==
                    route_table_detail::RouteRepairLogDecision::Warning) {
                    Logger::instance().warn(
                        "Managed route repeatedly vanished and was restored; check for a flapping interface or competing route owner (dst={}, table={}, iface={}, gw={}, metric={}, protocol={})",
                        route.destination,
                        route.table,
                        route.interface.value_or("(none)"),
                        route.gateway.value_or("(none)"),
                        route.metric,
                        static_cast<unsigned>(route.protocol));
                }
                const bool already_owned = std::any_of(
                    owned_routes_.begin(), owned_routes_.end(),
                    [&](const RouteSpec& candidate) {
                        return routes_equal(candidate, route);
                    });
                if (!already_owned) {
                    owned_routes_.push_back(route);
                }
            }
        }
    }

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

void RouteTable::adopt_desired(const std::vector<RouteSpec>& desired) {
    routes_ = desired;
    owned_routes_.clear();
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
