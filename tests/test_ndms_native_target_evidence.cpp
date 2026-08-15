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

// Measured on WG4: the AmneziaWG parameter set, values as strings, h1..h4 as
// ranges. i1 is truncated here - its length is irrelevant to classification.
const char* kMeasuredAmneziaAsc = R"({
  "jc": "5", "jmin": "8", "jmax": "120", "s1": "47", "s2": "83",
  "h1": "118216543-118249247", "h2": "634794136-634842665",
  "h3": "1487164881-1487208055", "h4": "2130401938-2130405751",
  "s3": "24", "s4": "12", "i1": "<b 0xc0000000010b285e6327>"
})";

// Measured by asking the ASC endpoint about a slot that does not exist. Not
// empty, and not a protocol: an emptiness test reads this as AmneziaWG.
const char* kMeasuredAscErrorEnvelope = R"({
  "status": [
    {
      "status": "error",
      "code": "6553609",
      "ident": "Wireguard::Interface",
      "message": "unable to find Wireguard5 in \"Wireguard::Interface\"."
    }
  ]
})";

nlohmann::json config() {
    return nlohmann::json::parse(kConfigWithoutSecrets);
}
nlohmann::json status() { return nlohmann::json::parse(kMeasuredStatus); }
nlohmann::json empty_asc() { return nlohmann::json::parse("{}"); }
nlohmann::json amnezia_asc() {
    return nlohmann::json::parse(kMeasuredAmneziaAsc);
}

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
    REQUIRE(result.asc_class.has_value());
    CHECK(*result.asc_class == NdmsNativeAscClass::plain_wireguard);
}

TEST_CASE("the firmware really returns a preshared key, and that stops us") {
    // Not hypothetical: this is the live shape of
    // show/rc/interface/Wireguard0 measured on 2026-08-16, and the sweep over
    // the router's five occupied slots found a preshared-key in every one.
    // Sanitizing it away and carrying on would put peer secrets into a
    // revision digest and into whatever logs the caller keeps; refusing is the
    // only safe answer, and it is why the caller must read a filtered
    // document.
    const auto result = build_ndms_native_target_evidence(
        "Wireguard0", nlohmann::json::parse(kMeasuredConfig), status(),
        empty_asc());
    REQUIRE(result.failure.has_value());
    CHECK(result.failure->reason == Reason::secret_material_present);
    CHECK_FALSE(result.evidence.has_value());

    // ...and the preshared key alone is what stops us. The measured document
    // also carries security-level.private, which a bare substring match on key
    // names would have counted too - so without this the refusal above is
    // over-determined and proves nothing about the secret.
    auto without_key = nlohmann::json::parse(kMeasuredConfig);
    without_key["wireguard"]["peer"][0].erase("preshared-key");
    REQUIRE(without_key.contains("security-level"));
    REQUIRE(without_key["security-level"]["private"] == true);
    const auto allowed = build_ndms_native_target_evidence(
        "Wireguard0", without_key, status(), empty_asc());
    CHECK_FALSE(allowed.failure.has_value());

    // Measured on the live router: Wireguard0 is security-level private while
    // Wireguard1-4 are public. Counting a boolean flag would have refused one
    // interface over its access level while identical neighbours passed.
    auto flag_only = config();
    flag_only["security-level"] = {{"private", true}};
    CHECK_FALSE(build_ndms_native_target_evidence("Wireguard0", flag_only,
                                                  status(), empty_asc())
                    .failure.has_value());

    // The narrowing is by value type, not by key name: anything under such a
    // key that could actually hold material still refuses.
    for (const auto& value :
         {nlohmann::json("material"), nlohmann::json::object({{"k", "v"}}),
          nlohmann::json::array({"material"})}) {
        auto carrying = config();
        carrying["security-level"] = {{"private", value}};
        CHECK(build_ndms_native_target_evidence("Wireguard0", carrying,
                                                status(), empty_asc())
                  .failure->reason == Reason::secret_material_present);
    }
}

TEST_CASE("an ASC that is not a protocol is refused, never called Amnezia") {
    // Measured: the endpoint answers an absent interface with a non-empty
    // object carrying an RCI error envelope. Classifying by non-emptiness -
    // which is what this module did until the live sweep - reads that as
    // AmneziaWG, and a transient error on a live plain interface would have
    // silently changed its protocol.
    const auto envelope = build_ndms_native_target_evidence(
        "Wireguard0", config(), status(),
        nlohmann::json::parse(kMeasuredAscErrorEnvelope));
    REQUIRE(envelope.failure.has_value());
    CHECK(envelope.failure->reason == Reason::asc_not_classifiable);
    CHECK_FALSE(envelope.asc_class.has_value());

    // Neither is a shape we have never measured.
    for (const auto& unknown :
         {nlohmann::json::parse(R"({"unexpected": 1})"),
          nlohmann::json::parse(R"({"jc": "5"})"), nlohmann::json::array(),
          nlohmann::json("text")}) {
        CHECK(build_ndms_native_target_evidence("Wireguard0", config(),
                                                status(), unknown)
                  .failure->reason == Reason::asc_not_classifiable);
    }
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

TEST_CASE("the measured AmneziaWG parameter set is the discriminator") {
    // Measured on Wireguard1: an AmneziaWG interface carries its parameters in
    // BOTH reads - a wireguard.asc block in the config document and the same
    // values from the dedicated ASC endpoint.
    auto awg_config = config();
    awg_config["wireguard"]["asc"] = amnezia_asc();

    const auto amnezia = build_ndms_native_target_evidence(
        "Wireguard0", awg_config, status(), amnezia_asc());
    REQUIRE(amnezia.evidence.has_value());
    // Reported from evidence, never inferred from a name.
    REQUIRE(amnezia.asc_class.has_value());
    CHECK(*amnezia.asc_class == NdmsNativeAscClass::amnezia_wg);

    // Because the config carries the block too, converting an interface
    // between the protocols moves the revision - the CAS notices, without the
    // revision having to digest the separate ASC read.
    const auto plain = build_ndms_native_target_evidence(
        "Wireguard0", config(), status(), empty_asc());
    CHECK(amnezia.evidence->full_revision != plain.evidence->full_revision);
    REQUIRE(plain.asc_class.has_value());
    CHECK(*plain.asc_class == NdmsNativeAscClass::plain_wireguard);
}

} // namespace keen_pbr3
