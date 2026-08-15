#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_secret_redaction.hpp"

#include <string>

namespace keen_pbr3 {

namespace {

// The measured shape of show/rc/interface/Wireguard0, with the peer's
// preshared-key kept: that is the value the redactor exists to handle.
const char* kMeasuredConfig = R"({
  "description": "measured description",
  "security-level": {"private": true},
  "ip": {"address": {"address": "10.0.0.1", "mask": "255.255.255.0"}},
  "wireguard": {"listen-port": {"port": 42731},
                "peer": [{"key": "cGVlcktleUJhc2U2NFZhbHVlRXhhbXBsZT0=",
                          "comment": "peer",
                          "preshared-key": "cHNrQmFzZTY0VmFsdWVFeGFtcGxlPQ=="
                         }]},
  "up": true
})";

const std::string kPresharedKey = "cHNrQmFzZTY0VmFsdWVFeGFtcGxlPQ==";

nlohmann::json measured() { return nlohmann::json::parse(kMeasuredConfig); }

std::string psk_of(const nlohmann::json& document) {
    return document["wireguard"]["peer"][0]["preshared-key"];
}

} // namespace

TEST_CASE("the secret leaves the document and its absence is not silent") {
    const auto redacted = redact_ndms_secret_material(measured(),
                                                      "Wireguard5");
    // Gone from the bytes entirely - not merely from the field we expected.
    CHECK(redacted.dump().find(kPresharedKey) == std::string::npos);
    // ...and replaced, not dropped: a dropped key is a key whose rotation the
    // revision could never notice.
    REQUIRE(redacted["wireguard"]["peer"][0].contains("preshared-key"));
    CHECK(is_ndms_secret_redaction_marker(psk_of(redacted)));
}

TEST_CASE("everything that is not a secret survives byte for byte") {
    auto expected = measured();
    const auto redacted = redact_ndms_secret_material(expected, "Wireguard5");
    expected["wireguard"]["peer"][0]["preshared-key"] = psk_of(redacted);
    // The whole document, compared at once: a redactor that quietly reordered,
    // retyped or dropped anything else would fail here.
    CHECK(redacted == expected);
    // Including the one measured key the name test matches but which cannot
    // hold material.
    CHECK(redacted["security-level"]["private"] == true);
    CHECK(redacted["wireguard"]["peer"][0]["key"] ==
          "cGVlcktleUJhc2U2NFZhbHVlRXhhbXBsZT0=");
}

TEST_CASE("a rotated secret moves the marker, an unchanged one does not") {
    const auto before = redact_ndms_secret_material(measured(), "Wireguard5");
    CHECK(psk_of(before) ==
          psk_of(redact_ndms_secret_material(measured(), "Wireguard5")));

    auto rotated = measured();
    rotated["wireguard"]["peer"][0]["preshared-key"] = "cm90YXRlZEtleVZhbHVl";
    // The point of digesting rather than dropping: a compare-and-swap over a
    // redacted document must still call a rotated interface changed.
    CHECK(psk_of(redact_ndms_secret_material(rotated, "Wireguard5")) !=
          psk_of(before));
}

TEST_CASE("the marker is bound to the interface and to its own path") {
    const auto here = redact_ndms_secret_material(measured(), "Wireguard5");
    // The same preshared key on two interfaces must not produce equal markers:
    // equal markers would publish that the two share it.
    CHECK(psk_of(redact_ndms_secret_material(measured(), "Wireguard6")) !=
          psk_of(here));

    // And a secret moved to another field is a changed document.
    auto moved = measured();
    moved["wireguard"]["peer"][0].erase("preshared-key");
    moved["wireguard"]["peer"][0]["secret-spare"] = kPresharedKey;
    CHECK(moved["wireguard"]["peer"][0]["secret-spare"] != psk_of(here));
    const auto moved_redacted =
        redact_ndms_secret_material(moved, "Wireguard5");
    CHECK(is_ndms_secret_redaction_marker(
        moved_redacted["wireguard"]["peer"][0]["secret-spare"]));
    CHECK(moved_redacted["wireguard"]["peer"][0]["secret-spare"] !=
          psk_of(here));
}

TEST_CASE("everything beneath a secret-naming key is covered, not just it") {
    nlohmann::json nested = {
        {"private", {{"inner", {{"deeper", "material"}}}}},
        {"secrets", nlohmann::json::array({"one", "two"})}};
    const auto redacted = redact_ndms_secret_material(nested, "Wireguard5");
    CHECK(redacted.dump().find("material") == std::string::npos);
    CHECK(redacted.dump().find("one") == std::string::npos);
    CHECK(is_ndms_secret_redaction_marker(
        redacted["private"]["inner"]["deeper"]));
    CHECK(is_ndms_secret_redaction_marker(redacted["secrets"][0]));
    CHECK(redacted["secrets"][0] != redacted["secrets"][1]);
}

TEST_CASE("only the exact marker shape counts as one") {
    const auto real =
        psk_of(redact_ndms_secret_material(measured(), "Wireguard5"));
    REQUIRE(is_ndms_secret_redaction_marker(real));

    // A shape check, not an authenticity one: a marker with one hex digit
    // changed is still a marker. It has to be - the checker cannot recompute a
    // digest it has no secret for. What it buys is that a caller who forgot to
    // redact, or wrote the wrong shape, is caught; a caller who forges a
    // well-formed marker has simply chosen a different revision for itself.
    auto tampered = real;
    tampered[tampered.size() - 1U] =
        tampered[tampered.size() - 1U] == 'a' ? 'b' : 'a';
    CHECK(is_ndms_secret_redaction_marker(tampered));

    // Shape failures, each of which an attacker or a sloppy caller could
    // produce by hand.
    CHECK_FALSE(is_ndms_secret_redaction_marker(""));
    CHECK_FALSE(is_ndms_secret_redaction_marker(kPresharedKey));
    CHECK_FALSE(is_ndms_secret_redaction_marker(real.substr(0U,
                                                            real.size() - 1U)));
    CHECK_FALSE(is_ndms_secret_redaction_marker(real + "0"));
    CHECK_FALSE(is_ndms_secret_redaction_marker("kpbr-redacted-v2-" +
                                                real.substr(17U)));
    // Uppercase hex is a different string and must not pass: two spellings of
    // one marker would be two revisions for one interface.
    auto upper = real;
    for (auto& ch : upper) {
        if (ch >= 'a' && ch <= 'f') ch = static_cast<char>(ch - 32);
    }
    CHECK_FALSE(is_ndms_secret_redaction_marker(upper));
}

TEST_CASE("redacting twice is redacting once") {
    const auto once = redact_ndms_secret_material(measured(), "Wireguard5");
    // A marker is a string under a secret-naming key, so a second pass would
    // digest it again - and a caller that redacted defensively would then
    // produce a different revision for an unchanged interface.
    CHECK(redact_ndms_secret_material(once, "Wireguard5") == once);
}

TEST_CASE("the name predicate is the one the evidence builder uses") {
    for (const char* key : {"private-key", "PresharedKey", "preshared-key",
                            "SECRET", "x-secret-y", "private"}) {
        CHECK(ndms_key_could_name_a_secret(key));
    }
    for (const char* key :
         {"key", "public-key", "security-level", "comment", "listen-port"}) {
        CHECK_FALSE(ndms_key_could_name_a_secret(key));
    }
}

} // namespace keen_pbr3
