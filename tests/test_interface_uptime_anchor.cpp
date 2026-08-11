#include <doctest/doctest.h>

#include "runtime/interface_uptime_anchor.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

using Store = InterfaceUptimeAnchorStore;
using TimePoint = Store::TimePoint;

// A fixed, arbitrary steady instant. Nothing in the store reads a real clock,
// so every case below is deterministic.
TimePoint base() {
    return TimePoint{std::chrono::hours{1000}};
}

TimePoint at(std::int64_t offset_seconds) {
    return base() + std::chrono::seconds{offset_seconds};
}

std::vector<std::string> present(std::vector<std::string> names) {
    return names;
}

} // namespace

TEST_CASE("first sighting of an already-up interface yields no anchor") {
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

    store.observe_link_state("nwg1", true, at(0));

    // The daemon cannot know when a link that was already up came up. Anything
    // other than "unknown" here would be this process's own start time wearing
    // an interface label, which is exactly the defect this store prevents.
    CHECK_FALSE(store.anchor("nwg1").has_value());
}

TEST_CASE("a down-to-up transition anchors at the edge") {
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

    store.observe_link_state("nwg1", false, at(0));
    store.observe_link_state("nwg1", true, at(10));

    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(10));
    CHECK(anchor->source == InterfaceUptimeSource::observed);
}

TEST_CASE("re-observing an unchanged up link never moves the anchor") {
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

    store.observe_link_state("nwg1", false, at(0));
    store.observe_link_state("nwg1", true, at(10));
    for (std::int64_t tick = 11; tick < 60; ++tick) {
        store.begin_round(present({"nwg1"}), at(tick));
        store.observe_link_state("nwg1", true, at(tick));
    }

    // Every inventory rebuild re-observes the same link. If that moved the
    // anchor, a UI refresh would restart the uptime it is trying to display.
    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(10));
}

TEST_CASE("link down drops the anchor") {
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

    store.observe_link_state("nwg1", false, at(0));
    store.observe_link_state("nwg1", true, at(10));
    store.observe_link_state("nwg1", false, at(20));

    CHECK_FALSE(store.anchor("nwg1").has_value());
}

TEST_CASE("firmware uptime anchors an interface the daemon never saw come up") {
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

    // The whole point of the firmware source: this link came up long before
    // the daemon started, so no netlink edge for it exists anywhere.
    store.observe_firmware_uptime("nwg1", 3600, at(0));

    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(-3600));
    CHECK(anchor->source == InterfaceUptimeSource::firmware);
}

TEST_CASE("firmware re-derivation within tolerance leaves the anchor still") {
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

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
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

    store.observe_firmware_uptime("nwg1", 3600, at(0));
    store.observe_firmware_uptime("nwg1", 12, at(60));

    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(48));
}

TEST_CASE("firmware zero means not up and clears the anchor") {
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

    store.observe_firmware_uptime("nwg1", 3600, at(0));
    store.observe_firmware_uptime("nwg1", 0, at(30));

    CHECK_FALSE(store.anchor("nwg1").has_value());
}

TEST_CASE("a stale firmware snapshot cannot undo a newer edge") {
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

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

TEST_CASE("a recreated interface never inherits the dead one's firmware uptime") {
    Store store;

    // A tunnel that has been up for an hour, with a catalog read at t=0.
    store.begin_round(present({"nwg0"}), at(0));
    store.observe_firmware_uptime("nwg0", 3600, at(0));
    REQUIRE(store.anchor("nwg0").has_value());

    // It is deleted: this round's netlink dump no longer lists it.
    store.begin_round(present({}), at(50));
    // ...and recreated seconds later under the same name.
    store.begin_round(present({"nwg0"}), at(60));

    // The catalog cache is STILL serving the pre-deletion snapshot, which
    // says this name has been up for an hour. It describes a device that no
    // longer exists, and applying it would show an hour of uptime for a
    // tunnel that came up seconds ago.
    store.observe_firmware_uptime("nwg0", 3600, at(0));

    CHECK_FALSE(store.anchor("nwg0").has_value());
}

TEST_CASE("a fresh firmware read after recreation is accepted") {
    Store store;

    store.begin_round(present({"nwg0"}), at(0));
    store.observe_firmware_uptime("nwg0", 3600, at(0));
    store.begin_round(present({}), at(50));
    store.begin_round(present({"nwg0"}), at(60));

    // Rejecting the stale snapshot must not wedge the interface: a catalog
    // read after the interface reappeared is exactly what should fill it in.
    store.observe_firmware_uptime("nwg0", 30, at(90));

    const auto anchor = store.anchor("nwg0");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(60));
    CHECK(anchor->source == InterfaceUptimeSource::firmware);
}

TEST_CASE("a dead tunnel that stays up in the kernel gets no invented anchor") {
    Store store;
    store.begin_round(present({"nwg0"}), at(0));

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
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

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
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

    store.observe_firmware_uptime("nwg1", 3600, at(0));
    store.observe_link_state("nwg1", false, at(10));

    // Firmware authority prevents inventing an up-transition, not reporting a
    // link that is demonstrably gone.
    CHECK_FALSE(store.anchor("nwg1").has_value());
}

TEST_CASE("begin_round drops interfaces that no longer exist") {
    Store store;
    store.begin_round(present({"nwg1", "nwg2"}), at(0));

    store.observe_firmware_uptime("nwg1", 3600, at(0));
    store.observe_firmware_uptime("nwg2", 1800, at(0));
    REQUIRE(store.size() == 2);

    store.begin_round(present({"nwg1"}), at(10));

    CHECK(store.size() == 1);
    CHECK(store.anchor("nwg1").has_value());
    CHECK_FALSE(store.anchor("nwg2").has_value());
}

TEST_CASE("begin_round leaves a surviving interface's anchor alone") {
    Store store;
    store.begin_round(present({"nwg1"}), at(0));
    store.observe_firmware_uptime("nwg1", 3600, at(0));

    for (std::int64_t tick = 1; tick < 40; ++tick) {
        store.begin_round(present({"nwg1"}), at(tick));
    }

    // Opening a round is not an observation. If it reset first_seen or the
    // anchor, every inventory build would restart the uptime.
    const auto anchor = store.anchor("nwg1");
    REQUIRE(anchor.has_value());
    CHECK(anchor->up_since == at(-3600));
}

TEST_CASE("an interface outside the round is not observed at all") {
    Store store;
    store.begin_round(present({"nwg1"}), at(0));

    store.observe_link_state("nwg9", true, at(0));
    store.observe_firmware_uptime("nwg9", 3600, at(0));

    // The firmware knows about interfaces the kernel does not currently have.
    // Creating state for them here would resurrect entries begin_round just
    // dropped, and would publish an interface the dump does not contain.
    CHECK_FALSE(store.anchor("nwg9").has_value());
    CHECK(store.size() == 1);
}

TEST_CASE("an unknown interface has no anchor") {
    Store store;

    CHECK_FALSE(store.anchor("nwg9").has_value());
    CHECK(store.size() == 0);
}

} // namespace keen_pbr3
