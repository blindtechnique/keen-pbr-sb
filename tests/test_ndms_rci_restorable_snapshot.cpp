#include <doctest/doctest.h>

#include "keenetic/ndms_rci_restorable_snapshot.hpp"
#include "util/base64.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

std::string wg_key(const char fill) {
    return base64_encode(std::string(32U, fill));
}

NdmsTunnelInterface client_interface() {
    NdmsTunnelInterface interface;
    interface.id = "tunnel-primary";
    interface.firmware_interface_name = "Wireguard7";
    interface.kernel_name = "nwg7";
    interface.kind = NdmsTunnelKind::amnezia_wireguard;
    interface.role = NdmsInterfaceRole::client;
    return interface;
}

NdmsRciSnapshotDocument document(
    const nlohmann::json& body,
    const std::string& firmware_name = "Wireguard7") {
    return {
        firmware_name,
        {200, "application/json; charset=utf-8", body.dump()},
    };
}

nlohmann::json valid_rc(
    const std::string& peer_public_key,
    const std::string& preshared_key) {
    return {
        {"description", "Основной AWG"},
        {"up", true},
        {"ip",
         {{"address",
           nlohmann::json::array({
               {{"address", "10.8.0.2"},
                {"mask", "255.255.255.0"}},
               {{"address", "fd00::2"}, {"mask", "64"}},
           })},
          {"mtu", "1420"}}},
        {"wireguard",
         {{"listen-port", {{"port", 51820}}},
          {"peer",
           nlohmann::json::array({
               {{"key", peer_public_key},
                {"preshared-key", preshared_key},
                {"connect", {{"via", "ISP"}}},
                {"allow-ips",
                 nlohmann::json::array({
                     {{"address", "0.0.0.0"},
                      {"mask", "0.0.0.0"}},
                     {{"address", "::"}, {"mask", "0"}},
                 })},
                {"keepalive-interval", {{"interval", 25}}}},
           })}}},
        // RC never supplies the private key. A similarly named unknown field
        // must not override the separately acquired secret.
        {"private-key", "not-the-kernel-private-key"},
    };
}

nlohmann::json valid_runtime(
    const std::string& peer_public_key) {
    return {
        {"id", "tunnel-primary"},
        {"interface-name", "nwg7"},
        {"type", "Wireguard"},
        {"wireguard",
         {{"peer",
           nlohmann::json::array({
               {{"public-key", peer_public_key},
                {"remote-endpoint-address", "203.0.113.8"},
                {"remote-port", 443},
                {"via", "ISP-runtime"}},
           })}}},
    };
}

nlohmann::json valid_asc() {
    return {
        {"jc", "4"},
        {"jmin", "40"},
        {"jmax", "70"},
        {"s1", "100"},
        {"s2", "200"},
        {"h1", "123456"},
        {"h2", "223456"},
        {"h3", "323456"},
        {"h4", "423456"},
        {"s3", "300"},
        {"s4", "400"},
        {"i1", "<r 8><c><t>"},
        {"i2", ""},
        {"i3", ""},
        {"i4", ""},
        {"i5", ""},
    };
}

NdmsRciRestorableSnapshotInput valid_input(
    const std::string& private_key,
    const std::string& peer_public_key,
    const std::string& preshared_key) {
    return {
        document(valid_rc(peer_public_key, preshared_key)),
        document(valid_runtime(peer_public_key)),
        document(valid_asc()),
        NdmsRciSecret(private_key),
    };
}

std::string snapshot_error(
    NdmsRciRestorableSnapshotInput input,
    const NdmsTunnelInterface& expected = client_interface()) {
    try {
        static_cast<void>(
            parse_ndms_rci_restorable_snapshot(
                std::move(input),
                expected));
    } catch (const NdmsRciRestorableSnapshotError& error) {
        return error.what();
    }
    return {};
}

} // namespace

static_assert(!std::is_copy_constructible_v<NdmsRciSecret>);
static_assert(!std::is_copy_assignable_v<NdmsRciSecret>);
static_assert(std::is_move_constructible_v<NdmsRciSecret>);
static_assert(!std::is_copy_constructible_v<
              NdmsRciRestorableSnapshot>);

TEST_CASE("NDMS restorable snapshot composes RC, runtime, ASC and a separate private key") {
    const auto private_key = wg_key('P');
    const auto peer_key = wg_key('K');
    const auto psk = wg_key('S');

    auto snapshot = parse_ndms_rci_restorable_snapshot(
        valid_input(private_key, peer_key, psk),
        client_interface());

    CHECK(snapshot.interface_id == "tunnel-primary");
    CHECK(snapshot.firmware_interface_name == "Wireguard7");
    CHECK(snapshot.kind == NdmsTunnelKind::amnezia_wireguard);
    CHECK(snapshot.description ==
          std::optional<std::string>{"Основной AWG"});
    CHECK(snapshot.enabled == std::optional<bool>{true});
    CHECK(snapshot.mtu == std::optional<std::uint32_t>{1420U});
    CHECK(snapshot.listen_port ==
          std::optional<std::uint16_t>{51820U});
    CHECK(snapshot.addresses ==
          std::vector<std::string>{
              "10.8.0.2/24",
              "fd00::2/64",
          });
    CHECK(snapshot.private_key.reveal_for_restore() == private_key);

    REQUIRE(snapshot.asc.has_value());
    CHECK(snapshot.asc->jc == 4U);
    CHECK(snapshot.asc->jmin == 40U);
    CHECK(snapshot.asc->jmax == 70U);
    CHECK(snapshot.asc->s3 == std::optional<std::uint32_t>{300U});
    CHECK(snapshot.asc->s4 == std::optional<std::uint32_t>{400U});
    CHECK(snapshot.asc->i1 ==
          std::optional<std::string>{"<r 8><c><t>"});

    REQUIRE(snapshot.peers.size() == 1U);
    const auto& peer = snapshot.peers.front();
    CHECK(peer.public_key == peer_key);
    REQUIRE(peer.preshared_key.has_value());
    CHECK(peer.preshared_key->reveal_for_restore() == psk);
    CHECK(peer.endpoint == "203.0.113.8:443");
    // Static RC is authoritative; runtime only supplements missing values.
    CHECK(peer.via_interface == std::optional<std::string>{"ISP"});
    CHECK(peer.allowed_ips ==
          std::vector<std::string>{"0.0.0.0/0", "::/0"});
    CHECK(peer.persistent_keepalive ==
          std::optional<std::uint16_t>{25U});

    CHECK(snapshot.full_revision.rfind("ndms-rci-full-v1-", 0U) == 0U);
    CHECK(snapshot.full_revision.size() == 81U);
    CHECK(snapshot.full_revision.find(private_key) == std::string::npos);
    CHECK(snapshot.full_revision.find(psk) == std::string::npos);
    CHECK(snapshot.full_revision.find("not-the-kernel-private-key") ==
          std::string::npos);
}

TEST_CASE("NDMS restorable snapshot full revision covers secret changes without exposing secrets") {
    const auto peer_key = wg_key('K');
    const auto psk = wg_key('S');
    const auto first_secret = wg_key('A');
    const auto second_secret = wg_key('B');

    const auto first =
        parse_ndms_rci_restorable_snapshot(
            valid_input(first_secret, peer_key, psk),
            client_interface());
    const auto second =
        parse_ndms_rci_restorable_snapshot(
            valid_input(second_secret, peer_key, psk),
            client_interface());

    CHECK(first.full_revision != second.full_revision);
    CHECK(first.full_revision.find(first_secret) == std::string::npos);
    CHECK(second.full_revision.find(second_secret) == std::string::npos);
}

TEST_CASE("NDMS restorable snapshot is client-only and verifies the tagged interface identity") {
    const auto private_key = wg_key('P');
    const auto peer_key = wg_key('K');
    const auto psk = wg_key('S');

    SUBCASE("server role fails closed") {
        auto expected = client_interface();
        expected.role = NdmsInterfaceRole::server;
        CHECK(snapshot_error(
                  valid_input(private_key, peer_key, psk),
                  expected) ==
              "NDMS RCI restorable snapshots support client interfaces only");
    }

    SUBCASE("unknown role fails closed") {
        auto expected = client_interface();
        expected.role = NdmsInterfaceRole::unknown;
        CHECK_THROWS_AS(
            parse_ndms_rci_restorable_snapshot(
                valid_input(private_key, peer_key, psk),
                expected),
            NdmsRciRestorableSnapshotError);
    }

    SUBCASE("wrong source tag fails before parsing body") {
        auto input = valid_input(private_key, peer_key, psk);
        input.rc_interface.firmware_interface_name = "Wireguard8";
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI snapshot source identity does not match the requested interface");
    }

    SUBCASE("unsupported tunnel kind fails closed") {
        auto expected = client_interface();
        expected.kind = NdmsTunnelKind::openvpn;
        CHECK(snapshot_error(
                  valid_input(private_key, peer_key, psk),
                  expected) ==
              "NDMS RCI restorable snapshot kind is unsupported");
    }

    SUBCASE("AWG requires its separately acquired ASC document") {
        auto input = valid_input(private_key, peer_key, psk);
        input.asc.reset();
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI AmneziaWG snapshot is missing ASC data");
    }

    SUBCASE("plain WG rejects unexpected ASC data") {
        auto expected = client_interface();
        expected.kind = NdmsTunnelKind::wireguard;
        CHECK(snapshot_error(
                  valid_input(private_key, peer_key, psk),
                  expected) ==
              "NDMS RCI plain WireGuard snapshot contains unexpected ASC data");
    }
}

TEST_CASE("NDMS restorable snapshot fails closed when rollback material is incomplete") {
    const auto private_key = wg_key('P');
    const auto peer_key = wg_key('K');
    const auto psk = wg_key('S');

    SUBCASE("private key is missing or malformed") {
        const auto message = snapshot_error(
            valid_input("private-secret-that-must-not-leak",
                        peer_key,
                        psk));
        CHECK(message == "NDMS RCI private key is missing or invalid");
        CHECK(message.find("private-secret") == std::string::npos);
    }

    SUBCASE("client endpoint must be present in RC or runtime") {
        auto input = valid_input(private_key, peer_key, psk);
        input.runtime_interface.reset();
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI client peer endpoint is missing");
    }

    SUBCASE("allowed IPs cannot be empty") {
        auto input = valid_input(private_key, peer_key, psk);
        auto rc = valid_rc(peer_key, psk);
        rc["wireguard"]["peer"][0]["allow-ips"] =
            nlohmann::json::array();
        input.rc_interface = document(rc);
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI peer allowed IPs are invalid");
    }

    SUBCASE("malformed PSK error never contains credential material") {
        const std::string malformed = "peer-secret-do-not-log";
        auto input = valid_input(private_key, peer_key, psk);
        auto rc = valid_rc(peer_key, malformed);
        input.rc_interface = document(rc);
        const auto message = snapshot_error(std::move(input));
        CHECK(message == "NDMS RCI peer preshared key is invalid");
        CHECK(message.find(malformed) == std::string::npos);
    }

    SUBCASE("endpoint rejects URL-like and injection-shaped hosts") {
        auto input = valid_input(private_key, peer_key, psk);
        input.runtime_interface.reset();
        auto rc = valid_rc(peer_key, psk);
        rc["wireguard"]["peer"][0]["endpoint"] = {
            {"address", "vpn.example/path:443"},
        };
        input.rc_interface = document(rc);
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI peer endpoint is invalid");
    }
}

TEST_CASE("NDMS restorable snapshot rejects malformed response and partial ASC without leaking bodies") {
    const auto private_key = wg_key('P');
    const auto peer_key = wg_key('K');
    const auto psk = wg_key('S');

    SUBCASE("invalid JSON") {
        auto input = valid_input(private_key, peer_key, psk);
        const std::string secret = "credential-in-malformed-json";
        input.rc_interface.response.body =
            "{\"description\":\"" + secret;
        const auto message = snapshot_error(std::move(input));
        CHECK(message ==
              "NDMS RCI snapshot response contains invalid JSON");
        CHECK(message.find(secret) == std::string::npos);
    }

    SUBCASE("extended ASC fields are an atomic pair") {
        auto input = valid_input(private_key, peer_key, psk);
        auto asc = valid_asc();
        asc.erase("s4");
        input.asc = document(asc);
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI ASC extended parameters are incomplete");
    }

    SUBCASE("nested RCI errors are rejected without leaking details") {
        auto input = valid_input(private_key, peer_key, psk);
        auto rc = valid_rc(peer_key, psk);
        const std::string secret = "nested-secret-detail";
        rc["wireguard"]["diagnostic"]["result"]["error"] = {
            {"message", secret},
        };
        input.rc_interface = document(rc);
        const auto message = snapshot_error(std::move(input));
        CHECK(message ==
              "NDMS RCI snapshot request reported an error");
        CHECK(message.find(secret) == std::string::npos);
    }

    SUBCASE("nonzero numeric status fails closed") {
        auto input = valid_input(private_key, peer_key, psk);
        auto rc = valid_rc(peer_key, psk);
        rc["diagnostic"]["status"] = 7;
        input.rc_interface = document(rc);
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI snapshot returned a failing status code");
    }

    SUBCASE("unknown explicit status token fails closed") {
        auto input = valid_input(private_key, peer_key, psk);
        auto rc = valid_rc(peer_key, psk);
        rc["diagnostic"]["status"] = "maybe";
        input.rc_interface = document(rc);
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI snapshot returned an unknown status token");
    }

    SUBCASE("nested status arrays use strict record semantics") {
        auto input = valid_input(private_key, peer_key, psk);
        auto rc = valid_rc(peer_key, psk);
        rc["diagnostic"]["status"] =
            nlohmann::json::array({
                {{"status", "ok"}, {"code", 0}},
                {{"status", "failed"}},
            });
        input.rc_interface = document(rc);
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI snapshot request reported a failed status");
    }

    SUBCASE("nonzero nested result code fails closed") {
        auto input = valid_input(private_key, peer_key, psk);
        auto rc = valid_rc(peer_key, psk);
        rc["diagnostic"]["status"] = {
            {"result", "ok"},
            {"code", 3},
        };
        input.rc_interface = document(rc);
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI snapshot returned a failing result code");
    }

    SUBCASE("status objects without an explicit result fail closed") {
        auto input = valid_input(private_key, peer_key, psk);
        auto rc = valid_rc(peer_key, psk);
        rc["diagnostic"]["status"] = {
            {"message", "not a status result"},
        };
        input.rc_interface = document(rc);
        CHECK(snapshot_error(std::move(input)) ==
              "NDMS RCI snapshot status entry has no result");
    }
}
