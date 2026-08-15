#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_target_evidence.hpp"

#include <string>

namespace keen_pbr3 {

namespace {

using Reason = NdmsNativeTargetReadFailure::Reason;

// Byte-shape captured from the live NC-1812 on 2026-08-16 via
// show/rc/interface/Wireguard0 and show/interface/Wireguard0, with
// operator-identifying values replaced and the exact structure, key names and
// value types preserved.
//
// The peer's preshared-key is NOT redacted away here: the firmware really
// does return it, and that is precisely what the secret guard must catch.
const char* kMeasuredConfig = R"({
  "description": "measured description",
  "dyndns": {"nobind": false},
  "security-level": {"private": true},
  "ip": {"address": {"address": "10.0.0.1", "mask": "255.255.255.0"},
         "mtu": "1324", "tcp": {"adjust-mss": {"pmtu": true}},
         "name-servers": true},
  "ipv6": {"address": [{"auto": false}], "prefix": [{"auto": false}],
           "name-servers": true},
  "wireguard": {"listen-port": {"port": 42731},
                "peer": [{"key": "cGVlcktleUJhc2U2NFZhbHVlRXhhbXBsZT0=",
                          "comment": "peer",
                          "preshared-key": "cHNrQmFzZTY0VmFsdWVFeGFtcGxlPQ==",
                          "allow-ips": [{"address": "10.0.0.1",
                                         "mask": "255.255.255.255"}]}]},
  "up": true
})";

// The same document with the peer's preshared-key removed - the shape a
// future firmware or a filtered read would present.
const char* kConfigWithoutSecrets = R"({
  "description": "measured description",
  "dyndns": {"nobind": false},
  "ip": {"address": {"address": "10.0.0.1", "mask": "255.255.255.0"},
         "mtu": "1324"},
  "wireguard": {"listen-port": {"port": 42731},
                "peer": [{"key": "cGVlcktleUJhc2U2NFZhbHVlRXhhbXBsZT0=",
                          "comment": "peer"}]},
  "up": true
})";

const char* kMeasuredStatus = R"({
  "id": "Wireguard0", "index": 0, "interface-name": "Wireguard0",
  "type": "Wireguard", "description": "measured description",
  "traits": ["Ip", "Ip6", "Wireguard"],
  "link": "down", "connected": "no", "state": "up", "mtu": 1324,
  "tx-queue-length": 50, "admin-only": false,
  "address": "10.0.0.1", "mask": "255.255.255.0", "uptime": 0,
  "global": false, "security-level": "private", "ipv6": {},
  "wireguard": {"public-key": "cHVibGljS2V5QmFzZTY0VmFsdWU9",
                "listen-port": 42731, "status": "up",
                "peer": [{"public-key": "cGVlclB1YmxpY0Jhc2U2NFZhbHVlPQ==",
                          "local-port": 42731, "rxbytes": 0, "txbytes": 0,
                          "online": false, "enabled": true, "fwmark": 0}]},
  "summary": {"layer": {"conf": "running", "link": "pending"}}
})";

nlohmann::json config() {
    return nlohmann::json::parse(kConfigWithoutSecrets);
}
nlohmann::json status() { return nlohmann::json::parse(kMeasuredStatus); }
nlohmann::json empty_asc() { return nlohmann::json::parse("{}"); }

} // namespace

TEST_CASE("the measured documents yield usable evidence") {
    const auto result = build_ndms_native_target_evidence(
        "Wireguard0", config(), status(), empty_asc());
    REQUIRE(result.evidence.has_value());
    CHECK_FALSE(result.failure.has_value());
    CHECK(result.evidence->interface_name == "Wireguard0");
    // Measured: link "down" while state is "up" - the firmware distinguishes
    // an administratively enabled interface from a carrier, and only the
    // carrier authorizes an exact-owned delete.
    CHECK(result.evidence->link_down);
    CHECK(result.evidence->full_revision.rfind("ndms-rci-full-v1-", 0U) ==
          0U);
    CHECK(result.evidence->full_revision.size() ==
          std::string("ndms-rci-full-v1-").size() + 64U);
    // Measured discriminator: plain WireGuard answers "{}" for ASC.
    CHECK_FALSE(result.amnezia);
}

TEST_CASE("the firmware really returns a preshared key, and that stops us") {
    // Not hypothetical: this is the live shape of
    // show/rc/interface/Wireguard0 measured on 2026-08-16. Sanitizing it away
    // and carrying on would put peer secrets into a revision digest and into
    // whatever logs the caller keeps; refusing is the only safe answer, and
    // it is why the caller must read a filtered document.
    const auto result = build_ndms_native_target_evidence(
        "Wireguard0", nlohmann::json::parse(kMeasuredConfig), status(),
        empty_asc());
    REQUIRE(result.failure.has_value());
    CHECK(result.failure->reason == Reason::secret_material_present);
    CHECK_FALSE(result.evidence.has_value());
}

TEST_CASE("both documents must agree they describe this interface") {
    auto other = status();
    other["id"] = "Wireguard6";
    other["interface-name"] = "Wireguard6";
    // Evidence attached to the wrong target is evidence aimed at deleting the
    // wrong interface.
    CHECK(build_ndms_native_target_evidence("Wireguard0", config(), other,
                                            empty_asc())
              .failure->reason == Reason::identity_mismatch);

    auto anonymous = status();
    anonymous.erase("id");
    anonymous.erase("interface-name");
    CHECK(build_ndms_native_target_evidence("Wireguard0", config(),
                                            anonymous, empty_asc())
              .failure->reason == Reason::identity_mismatch);

    for (const char* name : {"wireguard0", "Wireguard05", "Wireguard127"}) {
        CHECK(build_ndms_native_target_evidence(name, config(), status(),
                                                empty_asc())
                  .failure->reason == Reason::identity_mismatch);
    }
}

TEST_CASE("a link state we cannot read is never called down") {
    for (const char* value : {"", "unknown", "DOWN", "pending"}) {
        auto unreadable = status();
        unreadable["link"] = value;
        const auto result = build_ndms_native_target_evidence(
            "Wireguard0", config(), unreadable, empty_asc());
        REQUIRE(result.failure.has_value());
        CHECK(result.failure->reason == Reason::link_state_unknown);
    }
    auto carrier = status();
    carrier["link"] = "up";
    const auto up = build_ndms_native_target_evidence(
        "Wireguard0", config(), carrier, empty_asc());
    REQUIRE(up.evidence.has_value());
    CHECK_FALSE(up.evidence->link_down);
}

TEST_CASE("a non-WireGuard document is refused outright") {
    auto zerotier = status();
    zerotier["type"] = "ZeroTier";
    CHECK(build_ndms_native_target_evidence("Wireguard0", config(),
                                            zerotier, empty_asc())
              .failure->reason == Reason::type_not_wireguard);
    CHECK(build_ndms_native_target_evidence(
              "Wireguard0", nlohmann::json::array(), status(), empty_asc())
              .failure->reason == Reason::config_not_object);
    CHECK(build_ndms_native_target_evidence("Wireguard0", config(),
                                            nlohmann::json("text"),
                                            empty_asc())
              .failure->reason == Reason::status_not_object);
}

TEST_CASE("the revision is stable, and moves when the interface moves") {
    const auto baseline = build_ndms_native_target_evidence(
        "Wireguard0", config(), status(), empty_asc());
    const auto repeated = build_ndms_native_target_evidence(
        "Wireguard0", config(), status(), empty_asc());
    REQUIRE(baseline.evidence.has_value());
    CHECK(baseline.evidence->full_revision ==
          repeated.evidence->full_revision);

    auto edited = config();
    edited["wireguard"]["listen-port"]["port"] = 42732;
    CHECK(build_ndms_native_target_evidence("Wireguard0", edited, status(),
                                            empty_asc())
              .evidence->full_revision !=
          baseline.evidence->full_revision);

    auto renamed = status();
    renamed["description"] = "renamed by the operator";
    CHECK(build_ndms_native_target_evidence("Wireguard0", config(),
                                            renamed, empty_asc())
              .evidence->full_revision !=
          baseline.evidence->full_revision);

    // A live counter must NOT move the revision: it changes every read, and a
    // revision that moved with it could never match across two probes.
    auto busy = status();
    busy["uptime"] = 4242;
    busy["wireguard"]["peer"][0]["rxbytes"] = 991;
    CHECK(build_ndms_native_target_evidence("Wireguard0", config(), busy,
                                            empty_asc())
              .evidence->full_revision ==
          baseline.evidence->full_revision);
}

TEST_CASE("a non-empty ASC is the measured AmneziaWG discriminator") {
    const auto amnezia = build_ndms_native_target_evidence(
        "Wireguard0", config(), status(),
        nlohmann::json::parse(R"({"jc": 4, "jmin": 40})"));
    REQUIRE(amnezia.evidence.has_value());
    // Reported from evidence, never inferred from a name.
    CHECK(amnezia.amnezia);
}

} // namespace keen_pbr3
