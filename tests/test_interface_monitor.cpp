#include "../src/routing/interface_monitor.hpp"
#include "../src/daemon/daemon.hpp"

#include <doctest/doctest.h>

#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
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
    CHECK_FALSE(ipv4->default_route_changed);
    CHECK(interface_event_requires_runtime_observation(*ipv4));

    const auto ipv6 = InterfaceMonitor::describe_route_transition(
        RT_TABLE_MAIN, AF_INET6);
    REQUIRE(ipv6.has_value());
    CHECK(ipv6->route_changed);

    CHECK_FALSE(InterfaceMonitor::describe_route_transition(
        100U, AF_INET).has_value());
    CHECK_FALSE(InterfaceMonitor::describe_route_transition(
        RT_TABLE_MAIN, AF_UNSPEC).has_value());

    for (const auto family : {AF_INET, AF_INET6}) {
        const auto default_route = InterfaceMonitor::describe_route_transition(
            RT_TABLE_MAIN, family, true);
        REQUIRE(default_route.has_value());
        CHECK(default_route->route_changed);
        CHECK(default_route->default_route_changed);
        CHECK_FALSE(default_route->neighbor_changed);
        CHECK(interface_event_requires_runtime_observation(*default_route));
        CHECK_FALSE(InterfaceMonitor::describe_route_transition(
            100U, family, true).has_value());
    }
}

namespace {

InterfaceMonitor::NeighborObservation neighbor_observation(
    std::uint32_t identity = 1U) {
    InterfaceMonitor::NeighborObservation observation;
    observation.address_family = AF_INET;
    observation.interface_index = 2U;
    observation.address = std::string{
        static_cast<char>(192), static_cast<char>(168),
        static_cast<char>((identity >> 8U) & 0xffU),
        static_cast<char>(identity & 0xffU)};
    observation.link_address = std::string("\x02\x11\x22\x33\x44\x55", 6U);
    observation.state = NUD_REACHABLE;
    return observation;
}

} // namespace

TEST_CASE("InterfaceMonitor neighbor hints ignore reachability refresh noise") {
    InterfaceMonitor::NeighborHintTracker tracker;
    auto observation = neighbor_observation();
    CHECK(tracker.observe(observation));
    CHECK(tracker.size() == 1U);
    for (const auto state : {NUD_REACHABLE, NUD_STALE, NUD_DELAY,
                             NUD_PROBE, NUD_NOARP, NUD_PERMANENT}) {
        observation.state = static_cast<std::uint16_t>(state);
        CHECK_FALSE(tracker.observe(observation));
    }

    observation.state = NUD_FAILED;
    observation.link_address.clear();
    CHECK(tracker.observe(observation));
    CHECK_FALSE(tracker.observe(observation));
    observation = neighbor_observation();
    CHECK(tracker.observe(observation));
    CHECK_FALSE(tracker.observe(observation));
    observation.link_address.back() = static_cast<char>(0x66);
    CHECK(tracker.observe(observation));
    CHECK_FALSE(tracker.observe(observation));

    observation.present = false;
    CHECK(tracker.observe(observation));
    CHECK(tracker.size() == 0U);
    // Deletion of a neighbor predating monitor startup is still a hint.
    CHECK(tracker.observe(observation));
    observation.present = true;
    CHECK(tracker.observe(observation));

    InterfaceMonitor::Event hint;
    hint.neighbor_changed = true;
    CHECK_FALSE(interface_event_requires_runtime_observation(hint));
}

TEST_CASE("InterfaceMonitor neighbor identity includes interface and IPv6 address") {
    InterfaceMonitor::NeighborHintTracker tracker;
    auto observation = neighbor_observation();
    CHECK(tracker.observe(observation));
    ++observation.interface_index;
    CHECK(tracker.observe(observation));
    observation.address_family = AF_INET6;
    observation.address = std::string(16U, '\0');
    observation.address[0] = static_cast<char>(0xfe);
    observation.address[1] = static_cast<char>(0x80);
    observation.address.back() = 1;
    CHECK(tracker.observe(observation));
    observation.state = NUD_STALE;
    CHECK_FALSE(tracker.observe(observation));
    observation.address.back() = 2;
    CHECK(tracker.observe(observation));
    CHECK(tracker.size() == 4U);
    tracker.clear();
    CHECK(tracker.size() == 0U);
    CHECK(tracker.observe(observation));
}

TEST_CASE("InterfaceMonitor neighbor hints reject non-IP and unresolved noise") {
    InterfaceMonitor::NeighborHintTracker tracker;
    auto observation = neighbor_observation();
    observation.state = NUD_INCOMPLETE;
    observation.link_address.clear();
    CHECK_FALSE(tracker.observe(observation));
    observation.state = NUD_FAILED;
    CHECK(tracker.observe(observation));
    tracker.clear();

    for (const auto family : {AF_UNSPEC, AF_BRIDGE}) {
        observation = neighbor_observation();
        observation.address_family = family;
        CHECK_FALSE(tracker.observe(observation));
    }
    observation = neighbor_observation();
    observation.interface_index = 0U;
    CHECK_FALSE(tracker.observe(observation));
    observation = neighbor_observation();
    observation.address.pop_back();
    CHECK_FALSE(tracker.observe(observation));
    observation = neighbor_observation();
    observation.link_address.assign(33U, 'x');
    CHECK_FALSE(tracker.observe(observation));
    for (const auto first : {224U, 239U}) {
        observation = neighbor_observation();
        observation.address[0] = static_cast<char>(first);
        CHECK_FALSE(tracker.observe(observation));
        observation.present = false;
        CHECK_FALSE(tracker.observe(observation));
    }
    observation = neighbor_observation();
    observation.address.assign(4U, static_cast<char>(0xff));
    CHECK_FALSE(tracker.observe(observation));
    observation.address.assign(4U, '\0');
    CHECK_FALSE(tracker.observe(observation));
    observation.address_family = AF_INET6;
    observation.address.assign(16U, '\0');
    CHECK_FALSE(tracker.observe(observation));
    observation.address[0] = static_cast<char>(0xff);
    observation.address.back() = 1;
    CHECK_FALSE(tracker.observe(observation));
    CHECK(tracker.size() == 0U);
}

TEST_CASE("InterfaceMonitor neighbor hint tracking is bounded and reusable") {
    InterfaceMonitor::NeighborHintTracker tracker;
    for (std::uint32_t identity = 1U;
         identity <= InterfaceMonitor::NeighborHintTracker::max_entries;
         ++identity) {
        CHECK(tracker.observe(neighbor_observation(identity)));
    }
    CHECK(tracker.size() == InterfaceMonitor::NeighborHintTracker::max_entries);
    CHECK_FALSE(tracker.observe(neighbor_observation(1U)));
    CHECK(tracker.observe(neighbor_observation(2049U)));
    CHECK(tracker.size() == InterfaceMonitor::NeighborHintTracker::max_entries);
    CHECK_FALSE(tracker.observe(neighbor_observation(2049U)));
    CHECK(tracker.observe(neighbor_observation(1U)));
    CHECK(tracker.size() == InterfaceMonitor::NeighborHintTracker::max_entries);
    auto deleted = neighbor_observation(100U);
    deleted.present = false;
    CHECK(tracker.observe(deleted));
    CHECK(tracker.size() == InterfaceMonitor::NeighborHintTracker::max_entries - 1U);
    CHECK(tracker.observe(neighbor_observation(100U)));
    CHECK(tracker.size() == InterfaceMonitor::NeighborHintTracker::max_entries);
    tracker.clear();
    CHECK(tracker.size() == 0U);
}

} // namespace keen_pbr3
