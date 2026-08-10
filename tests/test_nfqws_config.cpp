#include "../src/util/nfqws_config.hpp"

#include <doctest/doctest.h>

#include <fstream>
#include <iterator>

namespace {

std::string read_generated_strategy(const std::string& name) {
    std::ifstream input(std::string(KEEN_PBR_NFQWS_STRATEGY_ROOT) + "/" +
                        name + "/nfqws2.conf");
    REQUIRE(input.good());
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

void replace_once(std::string& content,
                  const std::string& needle,
                  const std::string& replacement = {}) {
    const auto offset = content.find(needle);
    REQUIRE(offset != std::string::npos);
    content.replace(offset, needle.size(), replacement);
}

} // namespace

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

TEST_CASE("nfqws pre-telemetry active profile keeps its built-in identity") {
    const std::string old_profile =
        "# generated\n"
        "NFQWS_BASE_ARGS=\"--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua\n"
        "                 --lua-init=@/opt/etc/nfqws2/lua/zapret-auto.lua\n"
        "                 --blob=tls:@/opt/etc/nfqws2/blobs/tls.bin\"\n"
        "NFQWS_ARGS=\"--filter-tcp=443\"\n";
    const std::string current_profile =
        "# generated\n"
        "NFQWS_BASE_ARGS=\"--writable=/var/run/keen-pbr-nfqws --lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua\n"
        "                 --lua-init=@/opt/etc/nfqws2/lua/zapret-auto.lua\n"
        "                 --lua-init=@/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua\n"
        "                 --blob=tls:@/opt/etc/nfqws2/blobs/tls.bin\"\n"
        "NFQWS_ARGS=\"--filter-tcp=443\"\n";

    CHECK(keen_pbr3::nfqws_config_strategy_identity(old_profile) ==
          keen_pbr3::nfqws_config_strategy_identity(current_profile));
    CHECK_FALSE(
        keen_pbr3::nfqws_config_has_owned_rotator_telemetry(old_profile));
    CHECK(
        keen_pbr3::nfqws_config_has_owned_rotator_telemetry(current_profile));
}

TEST_CASE("nfqws identity keeps every non-owned config delta") {
    const std::string current_profile =
        "NFQWS_BASE_ARGS=\"--writable=/var/run/keen-pbr-nfqws --lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua\n"
        "                 --lua-init=@/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua\"\n"
        "NFQUEUE_NUM=300\n";
    auto changed = current_profile;
    const auto queue = changed.find("NFQUEUE_NUM=300");
    REQUIRE(queue != std::string::npos);
    changed.replace(queue, std::string("NFQUEUE_NUM=300").size(),
                    "NFQUEUE_NUM=301");

    CHECK(keen_pbr3::nfqws_config_strategy_identity(current_profile) !=
          keen_pbr3::nfqws_config_strategy_identity(changed));

    const std::string comment_only =
        "# NFQWS_BASE_ARGS=\"--writable=/var/run/keen-pbr-nfqws "
        "--lua-init=@/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua\"\n";
    CHECK(keen_pbr3::nfqws_config_strategy_identity(comment_only) ==
          comment_only);
}

TEST_CASE("nfqws identity contract follows the generated built-in profile") {
    const auto generated = read_generated_strategy("01 safe");
    auto legacy = generated;
    replace_once(
        legacy,
        "NFQWS_BASE_ARGS=\"--writable=/var/run/keen-pbr-nfqws ",
        "NFQWS_BASE_ARGS=\"");
    replace_once(
        legacy,
        "\n                 --lua-init=@/opt/var/lib/keen-pbr/"
        "nfqws-rotator-telemetry-v1.lua");

    CHECK(keen_pbr3::nfqws_config_has_owned_rotator_telemetry(generated));
    CHECK_FALSE(keen_pbr3::nfqws_config_has_owned_rotator_telemetry(legacy));
    CHECK(keen_pbr3::nfqws_config_strategy_identity(generated) == legacy);

    auto lookalike = generated;
    replace_once(
        lookalike,
        "\n                 --lua-init=@/opt/var/lib/keen-pbr/"
        "nfqws-rotator-telemetry-v1.lua",
        "\n                --lua-init=@/opt/var/lib/keen-pbr/"
        "nfqws-rotator-telemetry-v1.lua");
    CHECK_FALSE(
        keen_pbr3::nfqws_config_has_owned_rotator_telemetry(lookalike));
    CHECK(keen_pbr3::nfqws_config_strategy_identity(lookalike) != legacy);
}
