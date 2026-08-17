#include "../src/routing/netlink.hpp"

#include <doctest/doctest.h>
#include <netlink/errno.h>

namespace keen_pbr3 {

TEST_CASE("route delete treats an already absent kernel object as success") {
    CHECK(netlink_detail::route_delete_target_absent(-NLE_OBJ_NOTFOUND));
    CHECK(netlink_detail::route_delete_target_absent(-NLE_NODEV));
}

TEST_CASE("route delete keeps actionable libnl errors") {
    CHECK_FALSE(netlink_detail::route_delete_target_absent(-NLE_BUSY));
    CHECK_FALSE(netlink_detail::route_delete_target_absent(-NLE_PERM));
    CHECK_FALSE(netlink_detail::route_delete_target_absent(0));
}

} // namespace keen_pbr3
