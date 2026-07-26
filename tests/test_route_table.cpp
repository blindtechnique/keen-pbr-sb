#include <doctest/doctest.h>

#include "../src/routing/route_table.hpp"

#include <chrono>
#include <stdexcept>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

class FakeRouteNetlink : public RouteNetlinkOperations {
public:
    RouteAddResult add_route(const RouteSpec& spec) override {
        added.push_back(spec);
        if (fail_add) {
            throw std::runtime_error("injected failure");
        }
        return add_result;
    }

    void delete_route(const RouteSpec& spec) override {
        deleted.push_back(spec);
    }

    std::vector<DumpedRoute> dump_routes(int) override {
        return live;
    }

    RouteAddResult add_result{RouteAddResult::Created};
    bool fail_add{false};
    std::vector<RouteSpec> added;
    std::vector<RouteSpec> deleted;
    std::vector<DumpedRoute> live;
};

RouteSpec route(std::string destination, std::uint32_t table) {
    RouteSpec value;
    value.destination = std::move(destination);
    value.table = table;
    value.blackhole = true;
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

TEST_CASE("RouteTable claims a tracked route recreated after it vanishes") {
    FakeRouteNetlink netlink;
    netlink.add_result = RouteAddResult::AlreadyPresent;
    RouteTable routes(netlink);
    const auto expected = route("default", 150);
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
