#include "route_table.hpp"

#include "../log/logger.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <iterator>
#include <set>
#include <sys/socket.h>
#include <utility>

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

bool route_requires_interface_readiness(const RouteSpec& route) {
    return !route.blackhole &&
           !route.unreachable &&
           route.interface.has_value() &&
           !route.interface->empty();
}

bool interface_is_unavailable(
    netlink_detail::InterfaceAdminState state) {
    return state == netlink_detail::InterfaceAdminState::Unknown ||
           state == netlink_detail::InterfaceAdminState::Missing ||
           state == netlink_detail::InterfaceAdminState::Down;
}

std::string route_interface_unavailable_message(const RouteSpec& route) {
    return "Route interface is not ready: " +
           route.interface.value_or("(none)") +
           " (dst=" + route.destination +
           ", table=" + std::to_string(route.table) + ")";
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

bool route_occupies_same_slot(const RouteSpec& expected,
                              const DumpedRoute& actual) {
    return expected.destination == actual.destination &&
           expected.table == actual.table &&
           (expected.family == 0 || expected.family == actual.family) &&
           route_metric_matches_live(expected, actual);
}

RouteSpec route_spec_from_live(const DumpedRoute& route) {
    RouteSpec spec;
    spec.destination = route.destination;
    spec.table = route.table;
    spec.interface = route.interface;
    spec.gateway = route.gateway;
    spec.blackhole = route.blackhole;
    spec.unreachable = route.unreachable;
    spec.family = route.family;
    spec.metric = route.metric;
    spec.protocol = route.protocol;
    return spec;
}

bool is_generated_route_candidate(const DumpedRoute& route) {
    constexpr uint32_t prelocal_table = 128;
    constexpr uint32_t reserved_low = 250;
    constexpr uint32_t reserved_high = 260;
    constexpr uint32_t system_table_start = 32000;
    return route.protocol == KEEN_PBR_GENERATED_ROUTE_PROTOCOL &&
           route.table != 0 &&
           route.table != prelocal_table &&
           (route.table < reserved_low || route.table > reserved_high) &&
           route.table < system_table_start;
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

RouteTable::RouteTable(
    RouteNetlinkOperations& netlink,
    bool dry_run,
    InterfaceReadinessProbe interface_readiness_probe,
    NowFunction now)
    : netlink_(netlink),
      dry_run_(dry_run),
      interface_readiness_probe_(
          interface_readiness_probe
              ? std::move(interface_readiness_probe)
              : InterfaceReadinessProbe{
                    netlink_detail::query_interface_admin_state}),
      now_(now ? std::move(now)
               : NowFunction{[]() { return Clock::now(); }}) {}

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
    auto& record = repair_record(spec);
    return route_table_detail::record_route_repair(record.rate, now_());
}

RouteTable::RouteRepairRecord& RouteTable::repair_record(
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
    return *it;
}

bool RouteTable::repair_retry_due(const RouteSpec& spec) const {
    const auto it = std::find_if(
        repair_records_.begin(),
        repair_records_.end(),
        [&](const RouteRepairRecord& record) {
            return routes_equal(record.route, spec);
        });
    return it == repair_records_.end() ||
           !it->retry_after.has_value() ||
           now_() >= *it->retry_after;
}

void RouteTable::defer_repair(const RouteSpec& spec) {
    static constexpr std::array<std::chrono::seconds, 7> delays{
        std::chrono::seconds{1},
        std::chrono::seconds{2},
        std::chrono::seconds{4},
        std::chrono::seconds{8},
        std::chrono::seconds{16},
        std::chrono::seconds{32},
        std::chrono::seconds{60},
    };
    auto& record = repair_record(spec);
    const auto delay_index = std::min(
        record.consecutive_deferrals, delays.size() - 1);
    record.retry_after = now_() + delays[delay_index];
    if (record.consecutive_deferrals < delays.size() - 1) {
        ++record.consecutive_deferrals;
    }
}

void RouteTable::reset_repair_backoff(const RouteSpec& spec) {
    const auto it = std::find_if(
        repair_records_.begin(),
        repair_records_.end(),
        [&](const RouteRepairRecord& record) {
            return routes_equal(record.route, spec);
        });
    if (it == repair_records_.end()) {
        return;
    }
    it->consecutive_deferrals = 0;
    it->retry_after.reset();
}

RouteTable::RouteInstallOutcome RouteTable::add_route_checked(
    const RouteSpec& spec) {
    const bool needs_interface =
        route_requires_interface_readiness(spec);
    if (needs_interface && interface_is_unavailable(
            interface_readiness_probe_(*spec.interface))) {
        throw RouteInterfaceUnavailableError(
            route_interface_unavailable_message(spec));
    }

    try {
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (netlink_.add_route(spec) == RouteAddResult::Created) {
                return RouteInstallOutcome::Created;
            }

            // EEXIST is not success by itself. It may be the exact route left
            // by a previous keen-pbr process, an obsolete keen-pbr route
            // through another urltest member, or a genuinely foreign route.
            const auto live = netlink_.dump_routes(spec.family);
            const auto exact = std::find_if(
                live.begin(), live.end(), [&](const DumpedRoute& candidate) {
                    return route_table_detail::route_matches_live(
                        spec, candidate);
                });
            if (exact != live.end() &&
                spec.protocol == KEEN_PBR_GENERATED_ROUTE_PROTOCOL) {
                return RouteInstallOutcome::AlreadyManaged;
            }

            std::vector<DumpedRoute> collisions;
            std::copy_if(
                live.begin(),
                live.end(),
                std::back_inserter(collisions),
                [&](const DumpedRoute& candidate) {
                    return route_table_detail::route_occupies_same_slot(
                        spec, candidate);
                });
            if (collisions.empty()) {
                if (attempt == 0) {
                    // The object disappeared between EEXIST and the dump.
                    // Retry once; never expose a rule for an empty table.
                    continue;
                }
                throw NetlinkError(
                    "Route disappeared while resolving an EEXIST race "
                    "(dst=" + spec.destination +
                    ", table=" + std::to_string(spec.table) +
                    ", metric=" + std::to_string(spec.metric) + ")");
            }

            const bool all_managed =
                spec.protocol == KEEN_PBR_GENERATED_ROUTE_PROTOCOL &&
                std::all_of(
                    collisions.begin(),
                    collisions.end(),
                    [](const DumpedRoute& candidate) {
                        return candidate.protocol ==
                               KEEN_PBR_GENERATED_ROUTE_PROTOCOL;
                    });
            if (!all_managed) {
                throw NetlinkError(
                    "Refusing to replace a foreign route occupying the "
                    "keen-pbr slot (dst=" + spec.destination +
                    ", table=" + std::to_string(spec.table) +
                    ", metric=" + std::to_string(spec.metric) + ")");
            }

            std::vector<RouteSpec> previous;
            previous.reserve(collisions.size());
            std::transform(
                collisions.begin(),
                collisions.end(),
                std::back_inserter(previous),
                route_table_detail::route_spec_from_live);
            // Allocate rollback state before changing the kernel.
            pending_replacements_.push_back({spec, std::move(previous)});
            try {
                netlink_.replace_route(spec);
                const auto replaced = netlink_.dump_routes(spec.family);
                const bool verified = std::any_of(
                    replaced.begin(),
                    replaced.end(),
                    [&](const DumpedRoute& candidate) {
                        return route_table_detail::route_matches_live(
                            spec, candidate);
                    });
                if (!verified) {
                    throw NetlinkError(
                        "Managed route replacement did not reach the "
                        "requested postcondition (dst=" + spec.destination +
                        ", table=" + std::to_string(spec.table) +
                        ", metric=" + std::to_string(spec.metric) + ")");
                }
            } catch (...) {
                (void)restore_pending_replacement(spec);
                throw;
            }
            return RouteInstallOutcome::ReplacedManaged;
        }
        throw NetlinkError("Unreachable route installation state");
    } catch (const RouteInterfaceUnavailableError&) {
        throw;
    } catch (...) {
        // Close the readiness-check/netlink TOCTOU window. A route can pass
        // the pre-check and lose its TUN/WireGuard link before RTM_NEWROUTE.
        if (needs_interface && interface_is_unavailable(
                interface_readiness_probe_(*spec.interface))) {
            throw RouteInterfaceUnavailableError(
                route_interface_unavailable_message(spec));
        }
        throw;
    }
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

void RouteTable::forget_owned_route(const RouteSpec& spec) {
    owned_routes_.erase(
        std::remove_if(
            owned_routes_.begin(),
            owned_routes_.end(),
            [&](const RouteSpec& route) {
                return routes_equal(route, spec);
            }),
        owned_routes_.end());
}

void RouteTable::add(const RouteSpec& spec) {
    if (is_tracked(spec)) {
        return;
    }
    bool owned = dry_run_;
    if (!dry_run_) {
        const auto outcome = add_route_checked(spec);
        owned = outcome == RouteInstallOutcome::Created ||
                outcome == RouteInstallOutcome::ReplacedManaged;
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
        const bool has_pending_replacement = std::any_of(
            pending_replacements_.begin(),
            pending_replacements_.end(),
            [&](const PendingReplacement& pending) {
                return routes_equal(pending.installed, spec);
            });
        if (has_pending_replacement) {
            if (!restore_pending_replacement(spec)) {
                return;
            }
        } else {
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
    }
    if (owned_it != owned_routes_.end()) {
        owned_routes_.erase(owned_it);
    }
    forget_repair_record(spec);
    routes_.erase(it);
}

void RouteTable::reconcile(const std::vector<RouteSpec>& desired,
                           RouteReconcileMode mode) {
    add_missing(desired, mode);
    finalize_pending_replacements();
    remove_obsolete(desired);
    adopt_live_generated_desired(desired);
}

void RouteTable::add_missing(const std::vector<RouteSpec>& desired,
                             RouteReconcileMode mode) {
    // Deferred state can exist for a route that never reached routes_. Prune
    // obsolete records before any installation attempt, because a different
    // new route may throw transactionally and postpone remove_obsolete().
    // Production intentionally calls add_missing(), applies policy rules,
    // then calls remove_obsolete(), so this phase must own the pruning.
    repair_records_.erase(
        std::remove_if(
            repair_records_.begin(),
            repair_records_.end(),
            [&](const RouteRepairRecord& record) {
                return std::none_of(
                    desired.begin(),
                    desired.end(),
                    [&](const RouteSpec& route) {
                        return routes_equal(record.route, route);
                    });
            }),
        repair_records_.end());

    if (!dry_run_) {
        const auto live = netlink_.dump_routes();

        for (const auto& route : desired) {
            if (!is_tracked(route)) {
                continue;
            }
            const bool present = std::any_of(
                live.begin(),
                live.end(),
                [&](const DumpedRoute& candidate) {
                    return route_table_detail::route_matches_live(
                        route, candidate);
                });
            if (present) {
                reset_repair_backoff(route);
            }
        }

        const auto missing_live =
            route_table_detail::find_missing_live_routes(desired, live);

        for (const auto& route : missing_live) {
            if (!is_tracked(route)) {
                continue;
            }

            // A live dump confirmed that the object previously created by
            // this process no longer exists. Drop that old ownership before
            // any retry: an AlreadyPresent result below belongs to whoever
            // won the replacement race and must never be deleted by us.
            forget_owned_route(route);

            if (mode == RouteReconcileMode::DeferredRepair &&
                !repair_retry_due(route)) {
                continue;
            }

            RouteInstallOutcome result;
            try {
                result = add_route_checked(route);
            } catch (const RouteInterfaceUnavailableError&) {
                if (mode == RouteReconcileMode::Strict) {
                    throw;
                }
                // A tracked route vanished with its interface. Keep the
                // desired ownership record, but wait for the per-route
                // deadline or an explicit UP event instead of spinning.
                defer_repair(route);
                continue;
            }

            if (result == RouteInstallOutcome::Created ||
                result == RouteInstallOutcome::ReplacedManaged) {
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
            }
            if (result == RouteInstallOutcome::Created ||
                result == RouteInstallOutcome::ReplacedManaged) {
                const bool already_owned = std::any_of(
                    owned_routes_.begin(), owned_routes_.end(),
                    [&](const RouteSpec& candidate) {
                        return routes_equal(candidate, route);
                    });
                if (!already_owned) {
                    owned_routes_.push_back(route);
                }
            }
            if (mode == RouteReconcileMode::DeferredRepair) {
                // Arm a cooldown even after Created: if firmware or a
                // competing owner removes the route again before a later live
                // dump observes it as stable, repeated successful repair must
                // still back off. AlreadyPresent is cooled and stays foreign.
                defer_repair(route);
            } else {
                reset_repair_backoff(route);
            }
        }
    }

    for (const RouteSpec& route : desired) {
        if (is_tracked(route)) {
            continue;
        }

        if (mode == RouteReconcileMode::DeferredRepair &&
            !repair_retry_due(route)) {
            // Preserve the transactional contract for a route that has never
            // been installed: the caller must not continue with policy rules
            // or firewall state that points at a missing table. At the same
            // time, avoid probing the same unavailable interface on every
            // maintenance pass while its per-route deadline is active.
            throw RouteInterfaceUnavailableError(
                "route installation is waiting for its interface retry deadline");
        }

        try {
            add(route);
            reset_repair_backoff(route);
        } catch (const RouteInterfaceUnavailableError&) {
            if (mode == RouteReconcileMode::DeferredRepair) {
                defer_repair(route);
            }
            throw;
        }
    }
}

bool RouteTable::restore_pending_replacement(
    const RouteSpec& installed) noexcept {
    const auto pending = std::find_if(
        pending_replacements_.begin(),
        pending_replacements_.end(),
        [&](const PendingReplacement& candidate) {
            return routes_equal(candidate.installed, installed);
        });
    if (pending == pending_replacements_.end()) {
        return false;
    }

    try {
        if (pending->previous.empty()) {
            netlink_.delete_route(installed);
        } else {
            netlink_.replace_route(pending->previous.front());
            for (auto previous = std::next(pending->previous.begin());
                 previous != pending->previous.end(); ++previous) {
                (void)netlink_.add_route(*previous);
            }
        }
        pending_replacements_.erase(pending);
        return true;
    } catch (const std::exception& error) {
        Logger::instance().error(
            "Failed to restore the previous managed route generation "
            "(dst={}, table={}, metric={}): {}",
            installed.destination,
            installed.table,
            installed.metric,
            error.what());
    } catch (...) {
        Logger::instance().error(
            "Failed to restore the previous managed route generation "
            "(dst={}, table={}, metric={}): unknown error",
            installed.destination,
            installed.table,
            installed.metric);
    }
    return false;
}

void RouteTable::finalize_pending_replacements() noexcept {
    pending_replacements_.clear();
}

void RouteTable::rollback_pending_replacements() noexcept {
    std::vector<RouteSpec> installed;
    installed.reserve(pending_replacements_.size());
    std::transform(
        pending_replacements_.rbegin(),
        pending_replacements_.rend(),
        std::back_inserter(installed),
        [](const PendingReplacement& pending) {
            return pending.installed;
        });

    for (const auto& route : installed) {
        if (restore_pending_replacement(route)) {
            forget_owned_route(route);
        }
    }
}

void RouteTable::adopt_live_generated_desired(
    const std::vector<RouteSpec>& desired) noexcept {
    if (dry_run_) {
        return;
    }
    try {
        const auto live = netlink_.dump_routes();
        auto committed = owned_routes_;
        for (const auto& expected : desired) {
            if (expected.protocol != KEEN_PBR_GENERATED_ROUTE_PROTOCOL) {
                continue;
            }
            const bool present = std::any_of(
                live.begin(), live.end(), [&](const DumpedRoute& actual) {
                    return route_table_detail::route_matches_live(
                        expected, actual);
                });
            const bool already_owned = std::any_of(
                committed.begin(), committed.end(),
                [&](const RouteSpec& candidate) {
                    return routes_equal(candidate, expected);
                });
            if (present && !already_owned) {
                committed.push_back(expected);
            }
        }
        owned_routes_.swap(committed);
    } catch (const std::exception& error) {
        Logger::instance().warn(
            "Could not adopt exact live managed routes after commit: {}",
            error.what());
    } catch (...) {
        Logger::instance().warn(
            "Could not adopt exact live managed routes after commit: "
            "unknown error");
    }
}

void RouteTable::adopt_generated_orphans(
    const std::vector<RouteSpec>& desired) {
    if (!dry_run_) {
        // A daemon restart loses in-memory ownership, but protocol 186 remains
        // in the kernel. Adopt only unexpected protocol-marked objects and let
        // the existing exact-delete path retire them. Never flush a table.
        std::vector<DumpedRoute> live;
        try {
            live = netlink_.dump_routes();
        } catch (const std::exception& error) {
            Logger::instance().warn(
                "Could not inspect protocol-186 routes for orphan cleanup: {}",
                error.what());
            return;
        }
        for (const auto& actual : live) {
            if (!route_table_detail::is_generated_route_candidate(actual)) {
                continue;
            }
            const bool still_desired = std::any_of(
                desired.begin(), desired.end(), [&](const RouteSpec& candidate) {
                    return route_table_detail::route_matches_live(
                        candidate, actual);
                });
            if (still_desired) {
                continue;
            }

            const RouteSpec orphan =
                route_table_detail::route_spec_from_live(actual);
            if (!is_tracked(orphan)) {
                routes_.push_back(orphan);
            }
            const bool already_owned = std::any_of(
                owned_routes_.begin(),
                owned_routes_.end(),
                [&](const RouteSpec& candidate) {
                    return routes_equal(candidate, orphan);
                });
            if (!already_owned) {
                owned_routes_.push_back(orphan);
            }
        }
    }
}

void RouteTable::remove_obsolete(const std::vector<RouteSpec>& desired) {
    adopt_generated_orphans(desired);

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

std::set<uint32_t> RouteTable::live_generated_route_tables() const {
    std::set<uint32_t> tables;
    if (dry_run_) {
        return tables;
    }
    for (const auto& route : netlink_.dump_routes()) {
        if (route_table_detail::is_generated_route_candidate(route)) {
            tables.insert(route.table);
        }
    }
    return tables;
}

void RouteTable::adopt_desired(const std::vector<RouteSpec>& desired) {
    routes_ = desired;
    owned_routes_.clear();
    repair_records_.clear();
    pending_replacements_.clear();
}

void RouteTable::notify_interface_up(const std::string& interface_name) {
    if (interface_name.empty()) {
        return;
    }
    for (auto& record : repair_records_) {
        if (record.route.interface == interface_name) {
            record.consecutive_deferrals = 0;
            record.retry_after.reset();
        }
    }
}

void RouteTable::clear() {
    // clear() is also the rollback path. Never adopt arbitrary live
    // protocol-186 objects here: a failed generation must preserve the
    // previously committed generation. Recovered state is adopted explicitly
    // only after the complete route+rule transaction succeeds.
    const std::vector<RouteSpec> tracked = routes_;
    for (auto it = tracked.rbegin(); it != tracked.rend(); ++it) {
        remove(*it);
    }
    repair_records_.clear();
}

} // namespace keen_pbr3
