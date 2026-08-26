#include "../src/routing/interface_monitor.hpp"
#include "../src/daemon/daemon.hpp"

#include <doctest/doctest.h>

#include <linux/rtnetlink.h>
#include <sys/socket.h>

namespace keen_pbr3 {

TEST_CASE("InterfaceMonitor reconnect rebuilds usable netlink socket") {
    std::unique_ptr<InterfaceMonitor> monitor;
    try {
        monitor = std::make_unique<InterfaceMonitor>(
            [](const InterfaceMonitor::Event&) {});
    } catch (const InterfaceMonitorError& e) {
        (void)e;
        return;
    }

    CHECK(monitor->fd() >= 0);
    CHECK_NOTHROW(monitor->handle_events());

    CHECK_NOTHROW(monitor->reconnect());
    CHECK(monitor->fd() >= 0);
    CHECK_NOTHROW(monitor->handle_events());
}

TEST_CASE("InterfaceMonitor classifies link creation and deletion as topology changes") {
    const auto created = InterfaceMonitor::describe_link_transition(
        "nwg8", true, std::nullopt, true);
    CHECK(created.interface_name == "nwg8");
    CHECK(created.topology_changed);
    CHECK_FALSE(created.administrative_state_changed);
    CHECK(created.is_up);

    const auto deleted = InterfaceMonitor::describe_link_transition(
        "nwg7", false, true, false);
    CHECK(deleted.interface_name == "nwg7");
    CHECK(deleted.topology_changed);
    CHECK_FALSE(deleted.administrative_state_changed);
    CHECK_FALSE(deleted.is_up);

    const auto state_change = InterfaceMonitor::describe_link_transition(
        "nwg6", true, false, true);
    CHECK_FALSE(state_change.topology_changed);
    CHECK(state_change.administrative_state_changed);
    CHECK(state_change.is_up);

    const auto duplicate = InterfaceMonitor::describe_link_transition(
        "nwg6", true, true, true);
    CHECK_FALSE(duplicate.topology_changed);
    CHECK_FALSE(duplicate.administrative_state_changed);

    const auto renamed =
        InterfaceMonitor::describe_indexed_link_transition(
            "nwg9", true, std::string{"nwg7"}, true, true);
    CHECK(renamed.interface_name == "nwg9");
    CHECK(renamed.topology_changed);
    CHECK_FALSE(renamed.administrative_state_changed);

    const auto name_reused_by_new_index =
        InterfaceMonitor::describe_indexed_link_transition(
            "nwg7", true, std::nullopt, std::nullopt, true);
    CHECK(name_reused_by_new_index.topology_changed);
    CHECK_FALSE(name_reused_by_new_index.administrative_state_changed);
}

TEST_CASE("InterfaceMonitor observation gaps require runtime resynchronization") {
    InterfaceMonitor::Event gap{};
    gap.observation_gap = true;
    CHECK(interface_event_requires_runtime_observation(gap));
}

TEST_CASE("InterfaceMonitor fences only main-table IPv4 and IPv6 route changes") {
    const auto ipv4 = InterfaceMonitor::describe_route_transition(
        RT_TABLE_MAIN, AF_INET);
    REQUIRE(ipv4.has_value());
    CHECK(ipv4->route_changed);
    CHECK(interface_event_requires_runtime_observation(*ipv4));

    const auto ipv6 = InterfaceMonitor::describe_route_transition(
        RT_TABLE_MAIN, AF_INET6);
    REQUIRE(ipv6.has_value());
    CHECK(ipv6->route_changed);

    CHECK_FALSE(InterfaceMonitor::describe_route_transition(
        100U, AF_INET).has_value());
    CHECK_FALSE(InterfaceMonitor::describe_route_transition(
        RT_TABLE_MAIN, AF_UNSPEC).has_value());
}

} // namespace keen_pbr3
