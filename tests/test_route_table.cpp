#include <doctest/doctest.h>

#include "../src/routing/route_table.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <functional>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

class FakeRouteNetlink : public RouteNetlinkOperations {
public:
    RouteAddResult add_route(const RouteSpec& spec) override {
        added.push_back(spec);
        if (add_hook) {
            return add_hook(spec);
        }
        if (fail_add) {
            throw std::runtime_error("injected failure");
        }
        return add_result;
    }

    void replace_route(const RouteSpec& spec) override {
        replaced.push_back(spec);
        live.erase(
            std::remove_if(
                live.begin(), live.end(), [&](const DumpedRoute& candidate) {
                    return route_table_detail::route_occupies_same_slot(
                        spec, candidate);
                }),
            live.end());
        live.push_back(live_route_value(spec));
    }

    void delete_route(const RouteSpec& spec) override {
        deleted.push_back(spec);
        live.erase(
            std::remove_if(
                live.begin(), live.end(), [&](const DumpedRoute& candidate) {
                    return route_table_detail::route_matches_live(
                        spec, candidate);
                }),
            live.end());
    }

    std::vector<DumpedRoute> dump_routes(int) override {
        return live;
    }

    RouteAddResult add_result{RouteAddResult::Created};
    bool fail_add{false};
    std::function<RouteAddResult(const RouteSpec&)> add_hook;
    std::vector<RouteSpec> added;
    std::vector<RouteSpec> replaced;
    std::vector<RouteSpec> deleted;
    std::vector<DumpedRoute> live;

private:
    static DumpedRoute live_route_value(const RouteSpec& spec) {
        DumpedRoute value;
        value.destination = spec.destination;
        value.table = spec.table;
        value.interface = spec.interface;
        value.gateway = spec.gateway;
        value.blackhole = spec.blackhole;
        value.unreachable = spec.unreachable;
        value.family = spec.family;
        value.metric = spec.metric;
        value.protocol = spec.protocol;
        return value;
    }
};

RouteSpec route(std::string destination, std::uint32_t table) {
    RouteSpec value;
    value.destination = std::move(destination);
    value.table = table;
    value.blackhole = true;
    return value;
}

RouteSpec interface_route(std::string destination,
                          std::uint32_t table,
                          std::string interface) {
    RouteSpec value;
    value.destination = std::move(destination);
    value.table = table;
    value.interface = std::move(interface);
    return value;
}

DumpedRoute live_route(const RouteSpec& route) {
    DumpedRoute value;
    value.destination = route.destination;
    value.table = route.table;
    value.interface = route.interface;
    value.gateway = route.gateway;
    value.blackhole = route.blackhole;
    value.unreachable = route.unreachable;
    value.family = route.family;
    value.metric = route.metric;
    value.protocol = route.protocol;
    return value;
}

} // namespace

TEST_CASE("RouteTable deletes only routes created by this process") {
    FakeRouteNetlink netlink;
    RouteTable routes(netlink);

    const auto owned = route("default", 150);
    routes.add(owned);
    netlink.add_result = RouteAddResult::AlreadyPresent;
    const auto foreign = route("192.0.2.0/24", 150);
    netlink.live.push_back(live_route(foreign));
    routes.add(foreign);

    REQUIRE(routes.get_routes().size() == 2);
    routes.clear();
    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front().destination == owned.destination);
}

TEST_CASE("RouteTable remove preserves an identical pre-existing route") {
    FakeRouteNetlink netlink;
    netlink.add_result = RouteAddResult::AlreadyPresent;
    RouteTable routes(netlink);
    const auto foreign = route("default", 150);
    netlink.live.push_back(live_route(foreign));
    routes.add(foreign);
    routes.remove(foreign);

    CHECK(netlink.deleted.empty());
    CHECK(routes.get_routes().empty());
}

TEST_CASE("RouteTable propagates route installation failures") {
    FakeRouteNetlink netlink;
    netlink.fail_add = true;
    RouteTable routes(netlink);

    CHECK_THROWS(routes.add(route("default", 150)));
    CHECK(routes.get_routes().empty());
}

TEST_CASE("new interface route remains transactional while link is down") {
    FakeRouteNetlink netlink;
    std::size_t readiness_checks = 0;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) {
            ++readiness_checks;
            return netlink_detail::InterfaceAdminState::Down;
        });

    const auto expected = interface_route("default", 153, "tun0");
    CHECK_THROWS_AS(
        routes.add(expected), RouteInterfaceUnavailableError);
    CHECK(readiness_checks == 1);
    CHECK(netlink.added.empty());
    CHECK(routes.get_routes().empty());
}

TEST_CASE("unknown interface readiness fails closed before netlink") {
    FakeRouteNetlink netlink;
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Unknown;
        });

    CHECK_THROWS_AS(
        routes.add(interface_route("default", 153, "tun0")),
        RouteInterfaceUnavailableError);
    CHECK(netlink.added.empty());
    CHECK(routes.get_routes().empty());
}

TEST_CASE("new route keeps transactional failure while deferred retries back off") {
    using Clock = RouteTable::Clock;

    FakeRouteNetlink netlink;
    auto now = Clock::time_point{} + std::chrono::hours{1};
    auto state = netlink_detail::InterfaceAdminState::Down;
    std::size_t readiness_checks = 0;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) {
            ++readiness_checks;
            return state;
        },
        [&]() { return now; });
    const auto expected = interface_route("default", 153, "tun0");

    CHECK_THROWS_AS(
        routes.reconcile({expected}, RouteReconcileMode::DeferredRepair),
        RouteInterfaceUnavailableError);
    CHECK(readiness_checks == 1);
    CHECK(netlink.added.empty());
    CHECK(routes.get_routes().empty());

    now += std::chrono::milliseconds{999};
    CHECK_THROWS_AS(
        routes.reconcile({expected}, RouteReconcileMode::DeferredRepair),
        RouteInterfaceUnavailableError);
    CHECK(readiness_checks == 1);

    now += std::chrono::milliseconds{1};
    CHECK_THROWS_AS(
        routes.reconcile({expected}, RouteReconcileMode::DeferredRepair),
        RouteInterfaceUnavailableError);
    CHECK(readiness_checks == 2);

    state = netlink_detail::InterfaceAdminState::Up;
    routes.notify_interface_up("tun0");
    CHECK_NOTHROW(
        routes.reconcile({expected}, RouteReconcileMode::DeferredRepair));
    CHECK(readiness_checks == 3);
    CHECK(netlink.added.size() == 1);
    CHECK(routes.get_routes().size() == 1);
}

TEST_CASE("tracked route repair backs off independently while link is down") {
    using Clock = RouteTable::Clock;

    FakeRouteNetlink netlink;
    auto now = Clock::time_point{} + std::chrono::hours{1};
    auto state = netlink_detail::InterfaceAdminState::Up;
    std::size_t readiness_checks = 0;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) {
            ++readiness_checks;
            return state;
        },
        [&]() { return now; });
    const auto expected = interface_route("default", 153, "tun0");
    routes.add(expected);
    netlink.added.clear();
    state = netlink_detail::InterfaceAdminState::Down;

    routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
    const auto checks_after_first_deferral = readiness_checks;
    REQUIRE(checks_after_first_deferral == 2);
    CHECK(netlink.added.empty());

    constexpr std::array<std::chrono::seconds, 7> delays{
        std::chrono::seconds{1},
        std::chrono::seconds{2},
        std::chrono::seconds{4},
        std::chrono::seconds{8},
        std::chrono::seconds{16},
        std::chrono::seconds{32},
        std::chrono::seconds{60},
    };
    std::size_t expected_checks = checks_after_first_deferral;
    for (const auto delay : delays) {
        now += delay - std::chrono::milliseconds{1};
        routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
        CHECK(readiness_checks == expected_checks);
        now += std::chrono::milliseconds{1};
        routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
        ++expected_checks;
        CHECK(readiness_checks == expected_checks);
        CHECK(netlink.added.empty());
    }

    now += std::chrono::seconds{59};
    routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
    CHECK(readiness_checks == expected_checks);
    now += std::chrono::seconds{1};
    routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
    CHECK(readiness_checks == expected_checks + 1);
}

TEST_CASE("strict reconciliation never hides an unavailable tracked route") {
    FakeRouteNetlink netlink;
    auto state = netlink_detail::InterfaceAdminState::Up;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) { return state; });
    const auto expected = interface_route("default", 153, "tun0");
    routes.add(expected);
    netlink.added.clear();
    state = netlink_detail::InterfaceAdminState::Down;

    CHECK_THROWS_AS(
        routes.reconcile({expected}, RouteReconcileMode::Strict),
        RouteInterfaceUnavailableError);
    CHECK(netlink.added.empty());
    CHECK(routes.get_routes().size() == 1);
}

TEST_CASE("typed netlink disappearance is deferred only in repair mode") {
    FakeRouteNetlink netlink;
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        });
    const auto expected = interface_route("default", 153, "tun0");
    routes.add(expected);
    netlink.added.clear();
    netlink.add_hook = [](const RouteSpec&) -> RouteAddResult {
        throw RouteInterfaceUnavailableError("interface vanished");
    };

    CHECK_NOTHROW(routes.reconcile(
        {expected}, RouteReconcileMode::DeferredRepair));
    REQUIRE(netlink.added.size() == 1);
    CHECK_NOTHROW(routes.reconcile(
        {expected}, RouteReconcileMode::DeferredRepair));
    CHECK(netlink.added.size() == 1);
}

TEST_CASE("typed netlink disappearance propagates in strict mode") {
    FakeRouteNetlink netlink;
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        });
    const auto expected = interface_route("default", 153, "tun0");
    routes.add(expected);
    netlink.added.clear();
    netlink.add_hook = [](const RouteSpec&) -> RouteAddResult {
        throw RouteInterfaceUnavailableError("interface vanished");
    };

    CHECK_THROWS_AS(
        routes.reconcile({expected}, RouteReconcileMode::Strict),
        RouteInterfaceUnavailableError);
    CHECK(netlink.added.size() == 1);
}

TEST_CASE("deferred repair does not hide permanent netlink errors") {
    FakeRouteNetlink netlink;
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        });
    const auto expected = interface_route("default", 153, "tun0");
    routes.add(expected);
    netlink.added.clear();
    netlink.fail_add = true;

    CHECK_THROWS_WITH(
        routes.reconcile(
            {expected}, RouteReconcileMode::DeferredRepair),
        "injected failure");
}

TEST_CASE("interface UP resets only matching route repair backoff") {
    using Clock = RouteTable::Clock;

    FakeRouteNetlink netlink;
    auto now = Clock::time_point{} + std::chrono::hours{1};
    auto state = netlink_detail::InterfaceAdminState::Up;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) { return state; },
        [&]() { return now; });
    const auto first = interface_route("default", 153, "tun0");
    const auto second = interface_route("default", 154, "tun1");
    routes.add(first);
    routes.add(second);
    netlink.added.clear();
    state = netlink_detail::InterfaceAdminState::Down;
    routes.reconcile({first, second}, RouteReconcileMode::DeferredRepair);

    state = netlink_detail::InterfaceAdminState::Up;
    routes.notify_interface_up("tun0");
    routes.reconcile({first, second}, RouteReconcileMode::DeferredRepair);

    REQUIRE(netlink.added.size() == 1);
    CHECK(netlink.added.front().interface == first.interface);
}

TEST_CASE("live route observation clears a pending repair deadline") {
    using Clock = RouteTable::Clock;

    FakeRouteNetlink netlink;
    auto now = Clock::time_point{} + std::chrono::hours{1};
    auto state = netlink_detail::InterfaceAdminState::Up;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) { return state; },
        [&]() { return now; });
    const auto expected = interface_route("default", 153, "tun0");
    routes.add(expected);
    netlink.added.clear();

    state = netlink_detail::InterfaceAdminState::Down;
    routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
    netlink.live = {live_route(expected)};
    routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);

    netlink.live.clear();
    state = netlink_detail::InterfaceAdminState::Up;
    routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
    CHECK(netlink.added.size() == 1);
}

TEST_CASE("successful repair is cooled down until observed live") {
    using Clock = RouteTable::Clock;

    FakeRouteNetlink netlink;
    auto now = Clock::time_point{} + std::chrono::hours{1};
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        },
        [&]() { return now; });
    const auto expected = interface_route("default", 153, "tun0");
    routes.add(expected);
    netlink.added.clear();

    routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
    REQUIRE(netlink.added.size() == 1);
    routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
    CHECK(netlink.added.size() == 1);

    now += std::chrono::seconds{1};
    routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
    CHECK(netlink.added.size() == 2);
}

TEST_CASE("competing replacement is never claimed or deleted") {
    FakeRouteNetlink netlink;
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        });
    const auto expected = interface_route("default", 153, "tun0");
    routes.add(expected);
    netlink.add_hook = [&](const RouteSpec& spec) {
        netlink.live.push_back(live_route(spec));
        return RouteAddResult::AlreadyPresent;
    };
    netlink.added.clear();

    routes.add_missing({expected}, RouteReconcileMode::DeferredRepair);
    routes.add_missing({expected}, RouteReconcileMode::DeferredRepair);
    routes.clear();

    CHECK(netlink.added.size() == 1);
    CHECK(netlink.deleted.empty());
}

TEST_CASE("removing obsolete route clears deferred retry state") {
    using Clock = RouteTable::Clock;

    FakeRouteNetlink netlink;
    auto now = Clock::time_point{} + std::chrono::hours{1};
    auto state = netlink_detail::InterfaceAdminState::Up;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) { return state; },
        [&]() { return now; });
    const auto expected = interface_route("default", 153, "tun0");
    routes.add(expected);
    state = netlink_detail::InterfaceAdminState::Down;
    routes.reconcile({expected}, RouteReconcileMode::DeferredRepair);
    routes.reconcile({}, RouteReconcileMode::DeferredRepair);

    state = netlink_detail::InterfaceAdminState::Up;
    netlink.added.clear();
    routes.add(expected);
    CHECK(netlink.added.size() == 1);
}

TEST_CASE("removing never-installed desired route clears pending retry state") {
    using Clock = RouteTable::Clock;

    FakeRouteNetlink netlink;
    auto now = Clock::time_point{} + std::chrono::hours{1};
    auto state = netlink_detail::InterfaceAdminState::Down;
    std::size_t readiness_checks = 0;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) {
            ++readiness_checks;
            return state;
        },
        [&]() { return now; });
    const auto expected = interface_route("default", 153, "tun0");

    CHECK_THROWS_AS(
        routes.reconcile({expected}, RouteReconcileMode::DeferredRepair),
        RouteInterfaceUnavailableError);
    CHECK(readiness_checks == 1);
    CHECK_NOTHROW(routes.reconcile({}, RouteReconcileMode::DeferredRepair));

    state = netlink_detail::InterfaceAdminState::Up;
    CHECK_NOTHROW(
        routes.reconcile({expected}, RouteReconcileMode::DeferredRepair));
    CHECK(readiness_checks == 2);
    CHECK(netlink.added.size() == 1);
    CHECK(routes.get_routes().size() == 1);
}

TEST_CASE("new failing desired route cannot retain obsolete pending backoff") {
    using Clock = RouteTable::Clock;

    FakeRouteNetlink netlink;
    auto now = Clock::time_point{} + std::chrono::hours{1};
    auto state = netlink_detail::InterfaceAdminState::Down;
    std::size_t readiness_checks = 0;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) {
            ++readiness_checks;
            return state;
        },
        [&]() { return now; });
    const auto old_route = interface_route("default", 153, "tun0");
    const auto replacement = interface_route("default", 154, "tun1");

    CHECK_THROWS_AS(
        routes.add_missing({old_route}, RouteReconcileMode::DeferredRepair),
        RouteInterfaceUnavailableError);
    CHECK_THROWS_AS(
        routes.add_missing(
            {replacement}, RouteReconcileMode::DeferredRepair),
        RouteInterfaceUnavailableError);
    CHECK(readiness_checks == 2);

    state = netlink_detail::InterfaceAdminState::Up;
    CHECK_NOTHROW(
        routes.add_missing(
            {old_route}, RouteReconcileMode::DeferredRepair));
    CHECK(readiness_checks == 3);
    CHECK(netlink.added.size() == 1);
}

TEST_CASE("clear removes pending state for a never-installed route") {
    FakeRouteNetlink netlink;
    auto state = netlink_detail::InterfaceAdminState::Down;
    std::size_t readiness_checks = 0;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) {
            ++readiness_checks;
            return state;
        });
    const auto expected = interface_route("default", 153, "tun0");

    CHECK_THROWS_AS(
        routes.reconcile({expected}, RouteReconcileMode::DeferredRepair),
        RouteInterfaceUnavailableError);
    routes.clear();
    state = netlink_detail::InterfaceAdminState::Up;
    CHECK_NOTHROW(
        routes.reconcile({expected}, RouteReconcileMode::DeferredRepair));
    CHECK(readiness_checks == 2);
    CHECK(netlink.added.size() == 1);
}

TEST_CASE("route add TOCTOU converts a vanished interface to transient error") {
    FakeRouteNetlink netlink;
    std::size_t readiness_checks = 0;
    netlink.fail_add = true;
    RouteTable routes(
        netlink,
        false,
        [&](const std::string&) {
            ++readiness_checks;
            return readiness_checks == 1
                ? netlink_detail::InterfaceAdminState::Up
                : netlink_detail::InterfaceAdminState::Missing;
        });

    CHECK_THROWS_AS(
        routes.add(interface_route("default", 153, "tun0")),
        RouteInterfaceUnavailableError);
    CHECK(readiness_checks == 2);
    CHECK(routes.get_routes().empty());
}

TEST_CASE("permanent route add error is not hidden by readiness handling") {
    FakeRouteNetlink netlink;
    netlink.fail_add = true;
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        });

    CHECK_THROWS_WITH(
        routes.add(interface_route("default", 153, "tun0")),
        "injected failure");
    CHECK(routes.get_routes().empty());
}

TEST_CASE("RouteTable reconciliation adds replacements before removing obsolete routes") {
    FakeRouteNetlink netlink;
    RouteTable routes(netlink);
    const auto old_route = route("192.0.2.0/24", 150);
    const auto new_route = route("198.51.100.0/24", 150);
    routes.add(old_route);
    netlink.added.clear();

    routes.reconcile({new_route});

    REQUIRE(netlink.added.size() == 1);
    CHECK(netlink.added.front().destination == new_route.destination);
    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front().destination == old_route.destination);
    CHECK(routes.get_routes().size() == 1);
}

TEST_CASE("RouteTable failed reconcile keeps the installed prefix and obsolete routes") {
    FakeRouteNetlink netlink;
    RouteTable routes(netlink);
    const auto old_first = route("192.0.2.0/24", 150);
    const auto old_second = route("198.51.100.0/24", 151);
    const auto new_first = route("203.0.113.0/25", 152);
    const auto failing = route("203.0.113.128/26", 153);
    const auto never_attempted = route("203.0.113.192/26", 154);

    routes.add(old_first);
    routes.add(old_second);
    netlink.added.clear();
    netlink.add_hook = [&](const RouteSpec& spec) {
        if (spec.destination == failing.destination) {
            throw std::runtime_error("injected batch failure");
        }
        return RouteAddResult::Created;
    };

    CHECK_THROWS_WITH(
        routes.reconcile({new_first, failing, never_attempted}),
        "injected batch failure");

    REQUIRE(netlink.added.size() == 2);
    CHECK(netlink.added[0].destination == new_first.destination);
    CHECK(netlink.added[1].destination == failing.destination);
    CHECK(netlink.deleted.empty());
    const auto installed = routes.get_routes();
    REQUIRE(installed.size() == 3);
    const auto contains_destination = [&](const std::string& destination) {
        return std::any_of(
            installed.begin(), installed.end(), [&](const RouteSpec& spec) {
                return spec.destination == destination;
            });
    };
    CHECK(contains_destination(old_first.destination));
    CHECK(contains_destination(old_second.destination));
    CHECK(contains_destination(new_first.destination));

    // The successful prefix is intentionally not rolled back.  Shutdown
    // cleanup still owns it and removes all owned routes in reverse order.
    netlink.add_hook = {};
    routes.clear();

    REQUIRE(netlink.deleted.size() == 3);
    CHECK(netlink.deleted[0].destination == new_first.destination);
    CHECK(netlink.deleted[1].destination == old_second.destination);
    CHECK(netlink.deleted[2].destination == old_first.destination);
}

TEST_CASE("RouteTable treats protocol as route identity") {
    FakeRouteNetlink netlink;
    RouteTable routes(netlink);
    auto generated = route("default", 150);
    auto foreign = generated;
    foreign.protocol = 4;

    routes.add(generated);
    routes.add(foreign);

    CHECK(routes.get_routes().size() == 2);
}

TEST_CASE("RouteTable adopts desired state without claiming ownership") {
    FakeRouteNetlink netlink;
    RouteTable routes(netlink);
    const auto expected = route("default", 150);

    routes.adopt_desired({expected});
    routes.clear();

    CHECK(netlink.deleted.empty());
}

TEST_CASE("RouteTable adopts an exact restart route only after commit") {
    FakeRouteNetlink netlink;
    netlink.add_result = RouteAddResult::AlreadyPresent;
    const auto expected = route("default", 153);
    netlink.live.push_back(live_route(expected));
    {
        RouteTable uncommitted(netlink);
        uncommitted.add(expected);
        uncommitted.clear();
    }

    CHECK(netlink.deleted.empty());
    REQUIRE(netlink.live.size() == 1);

    RouteTable committed(netlink);
    committed.add(expected);
    committed.finalize_pending_replacements();
    committed.adopt_live_generated_desired({expected});
    committed.clear();

    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front().table == expected.table);
}

TEST_CASE("RouteTable atomically replaces a stale managed route slot") {
    FakeRouteNetlink netlink;
    netlink.add_result = RouteAddResult::AlreadyPresent;
    auto expected = interface_route("default", 154, "nwg1");
    expected.family = AF_INET;
    auto stale = expected;
    stale.interface = "nwg3";
    netlink.live.push_back(live_route(stale));
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        });

    routes.add(expected);

    REQUIRE(netlink.replaced.size() == 1);
    CHECK(netlink.replaced.front().interface == expected.interface);
    REQUIRE(netlink.live.size() == 1);
    CHECK(route_table_detail::route_matches_live(expected, netlink.live.front()));
}

TEST_CASE("RouteTable restores a replaced route when the generation rolls back") {
    FakeRouteNetlink netlink;
    netlink.add_result = RouteAddResult::AlreadyPresent;
    auto expected = interface_route("default", 154, "nwg1");
    expected.family = AF_INET;
    auto stale = expected;
    stale.interface = "nwg3";
    netlink.live.push_back(live_route(stale));
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        });

    routes.add(expected);
    routes.clear();

    REQUIRE(netlink.replaced.size() == 2);
    CHECK(netlink.replaced.front().interface == expected.interface);
    CHECK(netlink.replaced.back().interface == stale.interface);
    REQUIRE(netlink.live.size() == 1);
    CHECK(route_table_detail::route_matches_live(stale, netlink.live.front()));
}

TEST_CASE("RouteTable never accepts a vanished EEXIST route as installed") {
    FakeRouteNetlink netlink;
    netlink.add_result = RouteAddResult::AlreadyPresent;
    const auto expected = route("default", 154);
    RouteTable routes(netlink);

    CHECK_THROWS_AS(routes.add(expected), NetlinkError);
    CHECK(netlink.added.size() == 2);
    CHECK(routes.size() == 0);
}

TEST_CASE("RouteTable refuses to replace a foreign route slot") {
    FakeRouteNetlink netlink;
    netlink.add_result = RouteAddResult::AlreadyPresent;
    auto expected = interface_route("default", 154, "nwg1");
    expected.family = AF_INET;
    auto foreign = expected;
    foreign.interface = "nwg3";
    foreign.protocol = 4;
    netlink.live.push_back(live_route(foreign));
    RouteTable routes(
        netlink,
        false,
        [](const std::string&) {
            return netlink_detail::InterfaceAdminState::Up;
        });

    CHECK_THROWS_AS(routes.add(expected), NetlinkError);
    CHECK(netlink.replaced.empty());
    REQUIRE(netlink.live.size() == 1);
    CHECK(netlink.live.front().protocol == 4);
}

TEST_CASE("RouteTable sweeps only orphaned protocol-marked routes") {
    FakeRouteNetlink netlink;
    const auto managed = route("default", 153);
    auto foreign = route("default", 154);
    foreign.protocol = 4;
    netlink.live = {live_route(managed), live_route(foreign)};
    RouteTable routes(netlink);

    routes.remove_obsolete({});

    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front().table == managed.table);
    REQUIRE(netlink.live.size() == 1);
    CHECK(netlink.live.front().table == foreign.table);
}

TEST_CASE("RouteTable never sweeps a protocol-marked reserved table") {
    FakeRouteNetlink netlink;
    const auto reserved = route("default", 254);
    netlink.live.push_back(live_route(reserved));
    RouteTable routes(netlink);

    routes.remove_obsolete({});

    CHECK(netlink.deleted.empty());
    REQUIRE(netlink.live.size() == 1);
    CHECK(netlink.live.front().table == 254);
}

TEST_CASE("RouteTable claims a tracked route recreated after it vanishes") {
    FakeRouteNetlink netlink;
    RouteTable routes(netlink);
    const auto expected = route("default", 150);
    netlink.live.push_back(live_route(expected));
    netlink.add_result = RouteAddResult::AlreadyPresent;
    routes.add(expected);

    netlink.add_result = RouteAddResult::Created;
    netlink.live.clear();
    routes.reconcile({expected});
    routes.clear();

    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front().destination == expected.destination);
}

TEST_CASE("managed route repair warning is thresholded and rate limited") {
    using Decision = route_table_detail::RouteRepairLogDecision;
    using Clock = std::chrono::steady_clock;

    route_table_detail::RouteRepairRateState state;
    const auto started = Clock::time_point{} + std::chrono::hours{1};

    CHECK(route_table_detail::record_route_repair(state, started) ==
          Decision::Info);
    CHECK(route_table_detail::record_route_repair(
              state, started + std::chrono::minutes{1}) ==
          Decision::Info);
    CHECK(route_table_detail::record_route_repair(
              state, started + std::chrono::minutes{2}) ==
          Decision::Warning);
    CHECK(route_table_detail::record_route_repair(
              state, started + std::chrono::minutes{3}) ==
          Decision::Suppress);
    CHECK(route_table_detail::record_route_repair(
              state, started + std::chrono::minutes{7}) ==
          Decision::Warning);
}

TEST_CASE("managed route repair burst expires back to informational state") {
    using Decision = route_table_detail::RouteRepairLogDecision;
    using Clock = std::chrono::steady_clock;

    route_table_detail::RouteRepairRateState state;
    const auto started = Clock::time_point{} + std::chrono::hours{1};
    REQUIRE(route_table_detail::record_route_repair(state, started) ==
            Decision::Info);
    REQUIRE(route_table_detail::record_route_repair(
                state, started + std::chrono::seconds{1}) ==
            Decision::Info);
    REQUIRE(route_table_detail::record_route_repair(
                state, started + std::chrono::seconds{2}) ==
            Decision::Warning);

    CHECK(route_table_detail::record_route_repair(
              state, started + std::chrono::minutes{8}) ==
          Decision::Info);
}

} // namespace keen_pbr3
