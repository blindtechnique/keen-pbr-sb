#include "../src/util/network_routes.hpp"

#include <doctest/doctest.h>

TEST_CASE("default route interfaces are unique and ordered by metric") {
    const auto interfaces = keen_pbr3::parse_default_route_interfaces(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "nwg1\t00000000\t00000000\t0000\t0\t0\t1\t00000000\n"
        "eth4\t00000000\t0101A8C0\t0003\t0\t0\t20\t00000000\n"
        "eth3\t00000000\t0101A8C0\t0003\t0\t0\t10\t00000000\n"
        "eth3\t00000000\t0101A8C0\t0003\t0\t0\t30\t00000000\n"
        "br0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n");

    REQUIRE(interfaces.size() == 2);
    CHECK(interfaces[0] == "eth3");
    CHECK(interfaces[1] == "eth4");
}
