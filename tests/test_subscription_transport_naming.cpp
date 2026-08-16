#include <doctest/doctest.h>

#include "../src/config/subscription_transport_naming.hpp"

#include <set>
#include <string>

namespace keen_pbr3 {

TEST_CASE("the interface prefix matches the manual creation dialog") {
    // Mirrors transportInterfacePrefix in frontend/src/lib/technical-id.ts.
    // The rule exists so an imported transport is indistinguishable from a
    // hand-made one; a second naming scheme would make provenance readable
    // from the interface name.
    struct Sample {
        const char* scheme;
        const char* prefix;
    };
    const Sample samples[] = {
        {"vless", "vless"},   {"vmess", "vmess"},
        {"hysteria2", "hys"}, {"hy2", "hys"},
        {"ss", "ss"},         {"trojan", "trojan"},
        {"tuic", "tuic"},     {"naive", "naive"},
        {"naive+quic", "naive"}, {"naive+https", "naive"},
        {"socks", "socks"},   {"socks5", "socks"},
        {"http", "http"},     {"https", "http"},
        {"anytls", "proxy"},  {"", "proxy"},
    };
    for (const auto& sample : samples) {
        CHECK(subscription_interface_prefix(sample.scheme) == sample.prefix);
    }
}

TEST_CASE("a derived interface takes the first free sequence number") {
    CHECK(derive_subscription_interface("vless", {}) == "vless1");
    CHECK(derive_subscription_interface(
              "vless", {"vless1"}) == "vless2");
    CHECK(derive_subscription_interface(
              "vless", {"vless1", "vless2", "vless4"}) == "vless3");
}

TEST_CASE("tags occupy the same namespace as interfaces") {
    // The frontend reserves identity against both sets: a tag and an
    // interface share one namespace in the operator's head even though the
    // schema keeps them apart.
    CHECK(derive_subscription_interface(
              "trojan", {"trojan1"}) == "trojan2");
    // "trojan1" here is a *tag* of some existing transport; the derived
    // interface must still avoid it.
}

TEST_CASE("a derived interface always satisfies the interface pattern") {
    const std::string name = derive_subscription_interface("hysteria2", {});
    CHECK(name == "hys1");
    CHECK(name.size() <= 15U);
    for (const char ch : name) {
        const bool allowed =
            (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-';
        CHECK(allowed);
    }
}

} // namespace keen_pbr3
