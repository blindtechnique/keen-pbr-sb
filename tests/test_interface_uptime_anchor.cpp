#include <doctest/doctest.h>

#include "runtime/interface_uptime_anchor.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

using Clock = InterfaceUptimeAnchorStore::Clock;
using TimePoint = InterfaceUptimeAnchorStore::TimePoint;

// A fixed, arbitrary wall instant. Nothing in the store reads the real clock,
// so every case below is deterministic.
TimePoint base() {
    return TimePoint{std::chrono::seconds{1'754'812'800}};
}

TimePoint at(std::int64_t offset_seconds) {
    return base() + std::chrono::seconds{offset_seconds};
}

} // namespace

TEST_CASE("first sighting of an already-up interface yields no anchor") {
    InterfaceUptimeAnchorStore store;

    store.observe_link_state("nwg1", true, at(0));

    // The daemon cannot know when a link that was already up came up. Anything
    // other than "unknown" here would be this process's own start time wearing
    // an interface label, which is exactly the defect this store prevents.
    CHECK_FALSE(store.anchor("nwg1").has_value());
}

TEST_CASE("a down-to-up transition anchors at the edge") {
    InterfaceUptimeAnchorStore store;

    store.observe_link_state("nwg1", false, at(0));
    store.observe_link_state("nwg1", true, at(10));

    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(10));
    CHECK(anchor->source == InterfaceUptimeSource::observed);
}

TEST_CASE("re-observing an unchanged up link never moves the anchor") {
    InterfaceUptimeAnchorStore store;

    store.observe_link_state("nwg1", false, at(0));
    store.observe_link_state("nwg1", true, at(10));
    for (std::int64_t tick = 11; tick < 60; ++tick) {
        store.observe_link_state("nwg1", true, at(tick));
    }

    // Every inventory rebuild re-observes the same link. If that moved the
    // anchor, a UI refresh would restart the uptime it is trying to display.
    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(10));
}

TEST_CASE("link down drops the anchor") {
    InterfaceUptimeAnchorStore store;

    store.observe_link_state("nwg1", false, at(0));
    store.observe_link_state("nwg1", true, at(10));
    store.observe_link_state("nwg1", false, at(20));

    CHECK_FALSE(store.anchor("nwg1").has_value());
}

TEST_CASE("firmware uptime anchors an interface the daemon never saw come up") {
    InterfaceUptimeAnchorStore store;

    // The whole point of the firmware source: this link came up long before
    // the daemon started, so no netlink edge for it exists anywhere.
    store.observe_firmware_uptime("nwg1", 3600, at(0));

    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(-3600));
    CHECK(anchor->source == InterfaceUptimeSource::firmware);
}

TEST_CASE("firmware re-derivation within tolerance leaves the anchor still") {
    InterfaceUptimeAnchorStore store;

    store.observe_firmware_uptime("nwg1", 3600, at(0));
    // A later poll of a counter that ticks in whole seconds re-derives an
    // instant a second or two away. Latching it again would make the rendered
    // uptime jump backwards and forwards on every single poll.
    store.observe_firmware_uptime("nwg1", 3629, at(30));
    store.observe_firmware_uptime("nwg1", 3662, at(60));

    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(-3600));
}

TEST_CASE("firmware disagreement beyond tolerance is a flap and re-anchors") {
    InterfaceUptimeAnchorStore store;

    store.observe_firmware_uptime("nwg1", 3600, at(0));
    store.observe_firmware_uptime("nwg1", 12, at(60));

    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(48));
}

TEST_CASE("firmware zero means not up and clears the anchor") {
    InterfaceUptimeAnchorStore store;

    store.observe_firmware_uptime("nwg1", 3600, at(0));
    store.observe_firmware_uptime("nwg1", 0, at(30));

    CHECK_FALSE(store.anchor("nwg1").has_value());
}

TEST_CASE("a stale firmware snapshot cannot undo a newer edge") {
    InterfaceUptimeAnchorStore store;

    store.observe_link_state("nwg1", false, at(100));
    store.observe_link_state("nwg1", true, at(110));

    // The NDMS catalog is served from a cache that can lag by a whole TTL.
    // This snapshot was read before the flap and still reports the previous
    // lifetime; applying it would resurrect an uptime that no longer exists.
    store.observe_firmware_uptime("nwg1", 3600, at(90));

    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(110));
    CHECK(anchor->source == InterfaceUptimeSource::observed);
}

TEST_CASE("a dead tunnel that stays up in the kernel gets no invented anchor") {
    InterfaceUptimeAnchorStore store;

    // A WireGuard device is administratively up and reports operstate
    // "unknown" for as long as it exists, including while the tunnel itself is
    // dead. The firmware is the only party that can tell the difference.
    store.observe_firmware_uptime("nwg0", 0, at(0));
    store.observe_link_state("nwg0", true, at(1));
    store.observe_link_state("nwg0", true, at(3));

    // Without firmware authority the second observation would read as a
    // down-to-up edge and the dead tunnel would claim it had just connected.
    CHECK_FALSE(store.anchor("nwg0").has_value());
}

TEST_CASE("firmware upgrades the provenance of an anchor first seen over netlink") {
    InterfaceUptimeAnchorStore store;

    store.observe_link_state("nwg1", false, at(0));
    store.observe_link_state("nwg1", true, at(10));
    store.observe_firmware_uptime("nwg1", 20, at(30));

    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    // The instant stays where the precise netlink edge put it, but the source
    // becomes the one that will still be there after a restart.
    CHECK(anchor->up_since == at(10));
    CHECK(anchor->source == InterfaceUptimeSource::firmware);
}

TEST_CASE("a kernel-visible down still retracts a firmware anchor") {
    InterfaceUptimeAnchorStore store;

    store.observe_firmware_uptime("nwg1", 3600, at(0));
    store.observe_link_state("nwg1", false, at(10));

    // Firmware authority prevents inventing an up-transition, not reporting a
    // link that is demonstrably gone.
    CHECK_FALSE(store.anchor("nwg1").has_value());
}

TEST_CASE("retain_only drops interfaces that no longer exist") {
    InterfaceUptimeAnchorStore store;

    store.observe_firmware_uptime("nwg1", 3600, at(0));
    store.observe_firmware_uptime("nwg2", 1800, at(0));
    REQUIRE(store.size() == 2);

    store.retain_only(std::vector<std::string>{"nwg1"});

    CHECK(store.size() == 1);
    CHECK(store.anchor("nwg1").has_value());
    CHECK_FALSE(store.anchor("nwg2").has_value());
}

TEST_CASE("a recreated interface does not inherit the previous lifetime") {
    InterfaceUptimeAnchorStore store;

    store.observe_firmware_uptime("nwg1", 3600, at(0));
    // The tunnel is deleted...
    store.retain_only(std::vector<std::string>{});
    // ...and recreated under the same name, now up in the kernel.
    store.observe_link_state("nwg1", true, at(60));

    // A fresh entry has never been seen down, so there is no confirmed
    // transition to report - and certainly not the vanished device's.
    CHECK_FALSE(store.anchor("nwg1").has_value());
}

TEST_CASE("an unknown interface has no anchor") {
    InterfaceUptimeAnchorStore store;

    CHECK_FALSE(store.anchor("nwg9").has_value());
    CHECK(store.size() == 0);
}

} // namespace keen_pbr3
