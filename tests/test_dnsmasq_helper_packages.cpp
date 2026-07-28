#include <doctest/doctest.h>

#include <array>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>

#ifndef KEEN_PBR_KEENETIC_DNSMASQ_HELPER_PATH
#define KEEN_PBR_KEENETIC_DNSMASQ_HELPER_PATH \
    "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/dnsmasq.sh"
#endif

#ifndef KEEN_PBR_OPENWRT_DNSMASQ_HELPER_PATH
#define KEEN_PBR_OPENWRT_DNSMASQ_HELPER_PATH \
    "packages/openwrt/keen-pbr/files/usr/lib/keen-pbr/dnsmasq.sh"
#endif

#ifndef KEEN_PBR_DEBIAN_DNSMASQ_HELPER_PATH
#define KEEN_PBR_DEBIAN_DNSMASQ_HELPER_PATH \
    "packages/debian/files/usr/lib/keen-pbr/dnsmasq.sh"
#endif

namespace {

std::string read_helper(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to read dnsmasq helper: " + path);
    }
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};
}

} // namespace

TEST_CASE("packaged dnsmasq helpers delegate backend selection to the daemon") {
    const std::array<std::string, 3> helper_paths{
        KEEN_PBR_KEENETIC_DNSMASQ_HELPER_PATH,
        KEEN_PBR_OPENWRT_DNSMASQ_HELPER_PATH,
        KEEN_PBR_DEBIAN_DNSMASQ_HELPER_PATH,
    };

    for (const auto& path : helper_paths) {
        CAPTURE(path);
        const auto helper = read_helper(path);

        CHECK(
            helper.find("generate-resolver-config dnsmasq") !=
            std::string::npos);
        CHECK(helper.find("dnsmasq-ipset") == std::string::npos);
        CHECK(helper.find("dnsmasq-nftset") == std::string::npos);
        CHECK(helper.find("resolver_type()") == std::string::npos);
    }
}
