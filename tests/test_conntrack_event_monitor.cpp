#include <doctest/doctest.h>

#include "connections/conntrack_event_monitor.hpp"

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>

#include <array>
#include <cstring>

using namespace keen_pbr3;

TEST_CASE("conntrack monitor subscribes to lifecycle multicast groups") {
    const auto groups = conntrack_multicast_groups();
    CHECK((groups & (1U << (NFNLGRP_CONNTRACK_NEW - 1U))) != 0);
    CHECK((groups & (1U << (NFNLGRP_CONNTRACK_UPDATE - 1U))) != 0);
    CHECK((groups & (1U << (NFNLGRP_CONNTRACK_DESTROY - 1U))) != 0);
}

TEST_CASE("conntrack monitor counts only conntrack lifecycle messages") {
    std::array<nlmsghdr, 4> messages{};
    for (auto& message : messages) {
        message.nlmsg_len = sizeof(nlmsghdr);
    }
    messages[0].nlmsg_type =
        (NFNL_SUBSYS_CTNETLINK << 8U) | IPCTNL_MSG_CT_NEW;
    messages[1].nlmsg_type =
        (NFNL_SUBSYS_CTNETLINK << 8U) | IPCTNL_MSG_CT_DELETE;
    messages[2].nlmsg_type =
        (NFNL_SUBSYS_CTNETLINK_EXP << 8U) | IPCTNL_MSG_CT_NEW;
    messages[3].nlmsg_type = NLMSG_DONE;

    CHECK(count_conntrack_messages(messages.data(),
                                  sizeof(messages)) == 2);
    CHECK(count_conntrack_messages(nullptr, 0) == 0);
}
