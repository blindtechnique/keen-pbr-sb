#include <doctest/doctest.h>

#include <array>
#include <filesystem>
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

#ifndef KEEN_PBR_OPENWRT_UCI_HELPER_PATH
#define KEEN_PBR_OPENWRT_UCI_HELPER_PATH \
    "packages/openwrt/keen-pbr/files/usr/lib/keen-pbr/uci.sh"
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
        CHECK(helper.find("MANAGED_CONFIG_FILE") != std::string::npos);
        CHECK(helper.find("refresh_managed_config") != std::string::npos);
        CHECK(helper.find("resolver_config_has_upstream") != std::string::npos);
        CHECK(helper.find("resolver_config_is_active") != std::string::npos);
        CHECK(helper.find("# keen-pbr resolver state: active") !=
              std::string::npos);
        CHECK(helper.find("last complete") != std::string::npos);
        CHECK(helper.find("mv -f \"$MANAGED_CONFIG_TMP\"") !=
              std::string::npos);
    }
}

TEST_CASE("OpenWrt dnsmasq jail can execute and persist the managed helper") {
    const auto dnsmasq_helper =
        read_helper(KEEN_PBR_OPENWRT_DNSMASQ_HELPER_PATH);
    const auto uci_helper = read_helper(KEEN_PBR_OPENWRT_UCI_HELPER_PATH);
    const auto package_root =
        std::filesystem::path(KEEN_PBR_OPENWRT_DNSMASQ_HELPER_PATH)
            .parent_path()
            .parent_path()
            .parent_path()
            .parent_path()
            .parent_path();
    const auto package_makefile =
        read_helper((package_root / "Makefile").string());

    CHECK(dnsmasq_helper.find(
              "STATE_DIR=\"${KEEN_PBR_STATE_DIR:-/var/run/dnsmasq/keen-pbr}\"") !=
          std::string::npos);
    CHECK(uci_helper.find(
              "DNSMASQ_HELPER=\"/usr/lib/keen-pbr/dnsmasq.sh\"") !=
          std::string::npos);
    CHECK(uci_helper.find(
              "JAIL_MOUNTS=\"$KEEN_PBR_BIN $DNSMASQ_HELPER $CONFIG_DIR $CACHE_DIR\"") !=
          std::string::npos);
    CHECK(package_makefile.find(
              "-DKEEN_PBR_CONTROL_SOCKET:STRING=/var/run/dnsmasq/keen-pbr/control.sock") !=
          std::string::npos);
}
