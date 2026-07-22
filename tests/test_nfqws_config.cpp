#include "../src/util/nfqws_config.hpp"

#include <doctest/doctest.h>

TEST_CASE("nfqws comparison ignores only IPV6_ENABLED assignment") {
    const std::string base =
        "ISP_INTERFACE=\"eth3\"\nIPV6_ENABLED=0\nNFQUEUE_NUM=300\n";
    const std::string ipv6_changed =
        "ISP_INTERFACE=\"eth3\"\n  IPV6_ENABLED = 1\r\nNFQUEUE_NUM=300\n";
    const std::string meaningful_change =
        "ISP_INTERFACE=\"eth4\"\nIPV6_ENABLED=0\nNFQUEUE_NUM=300\n";

    CHECK(keen_pbr3::nfqws_config_without_ipv6_toggle(base) ==
          keen_pbr3::nfqws_config_without_ipv6_toggle(ipv6_changed));
    CHECK(keen_pbr3::nfqws_config_without_ipv6_toggle(base) !=
          keen_pbr3::nfqws_config_without_ipv6_toggle(meaningful_change));
}

TEST_CASE("nfqws built-in strategy receives all WAN interfaces") {
    const auto rendered = keen_pbr3::nfqws_config_with_isp_interfaces(
        "# provider\nISP_INTERFACE=\"eth3\"\nNFQUEUE_NUM=300\n",
        {"eth4", "eth5"});
    CHECK(rendered ==
          "# provider\nISP_INTERFACE=\"eth4 eth5\"\nNFQUEUE_NUM=300\n");
}

TEST_CASE("nfqws custom strategy is unchanged without detected WAN") {
    const std::string content = "ISP_INTERFACE=\"manual0\"\n";
    CHECK(keen_pbr3::nfqws_config_with_isp_interfaces(content, {}) == content);
}
