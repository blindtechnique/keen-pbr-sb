#include <doctest/doctest.h>

#include "crypto/sha256.hpp"
#include "keenetic/ndms_native_tunnel_import.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <new>
#include <string>
#include <type_traits>

using namespace keen_pbr3;

namespace {

std::string key(const char value) {
    // 32 identical bytes have a deterministic, canonical base64 encoding.
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string raw(32U, value);
    std::string output;
    for (std::size_t offset = 0U; offset < raw.size(); offset += 3U) {
        const auto first = static_cast<unsigned char>(raw[offset]);
        const bool second_present = offset + 1U < raw.size();
        const bool third_present = offset + 2U < raw.size();
        const auto second = second_present
            ? static_cast<unsigned char>(raw[offset + 1U]) : 0U;
        const auto third = third_present
            ? static_cast<unsigned char>(raw[offset + 2U]) : 0U;
        const std::uint32_t block =
            (static_cast<std::uint32_t>(first) << 16U) |
            (static_cast<std::uint32_t>(second) << 8U) |
            static_cast<std::uint32_t>(third);
        output.push_back(alphabet[(block >> 18U) & 0x3FU]);
        output.push_back(alphabet[(block >> 12U) & 0x3FU]);
        output.push_back(second_present
                             ? alphabet[(block >> 6U) & 0x3FU] : '=');
        output.push_back(third_present ? alphabet[block & 0x3FU] : '=');
    }
    return output;
}

std::string wg_conf() {
    return
        "# exported client\n"
        "[Interface]\n"
        "Address = 10.8.0.2/32, fd00::2/128\n"
        "PrivateKey = " + key('P') + "\n"
        "DNS = 1.1.1.1, 2606:4700:4700::1111\n"
        "ListenPort = 51820\n"
        "MTU = 1420\n"
        "\n"
        "[Peer]\n"
        "PublicKey = " + key('K') + "\n"
        "PresharedKey = " + key('S') + "\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "Endpoint = vpn.example.test:443\n"
        "PersistentKeepalive = 25\n";
}

std::string awg_conf() {
    auto value = wg_conf();
    const auto insert = value.find("\n\n[Peer]");
    value.insert(
        insert,
        "\nJc = 4\nJmin = 40\nJmax = 70\n"
        "S1 = 100\nS2 = 200\nS3 = 300\nS4 = 400\n"
        "H1 = 101010101\nH2 = 202020202\n"
        "H3 = 303030303\nH4 = 404040404\n"
        "I1 = <r 8><c><t>\nI5 = <b 0x10>\n");
    return value;
}

NdmsNativeTunnelImportErrorCode rejected_code(std::string input) {
    try {
        static_cast<void>(
            parse_ndms_native_tunnel_import(std::move(input)));
    } catch (const NdmsNativeTunnelImportError& error) {
        CHECK(std::string(error.what()) ==
              std::string{"native tunnel import rejected: "} +
                  ndms_native_tunnel_import_error_code_name(error.code()));
        return error.code();
    }
    FAIL("input was accepted");
    return NdmsNativeTunnelImportErrorCode::invalid_field;
}

} // namespace

static_assert(!std::is_copy_constructible_v<
              NdmsNativeTunnelImportSecret>);
static_assert(std::is_move_constructible_v<
              NdmsNativeTunnelImportSecret>);
static_assert(!std::is_copy_constructible_v<
              NdmsNativeTunnelImport>);
static_assert(!std::is_copy_constructible_v<Sha256>);
static_assert(!std::is_copy_assignable_v<Sha256>);
static_assert(!std::is_move_constructible_v<Sha256>);
static_assert(!std::is_move_assignable_v<Sha256>);

TEST_CASE("strict WireGuard conf produces a redacted preview") {
    const auto private_key = key('P');
    const auto psk = key('S');
    auto parsed = parse_ndms_native_tunnel_import(wg_conf());
    CHECK(parsed.source ==
          NdmsNativeTunnelImportSource::wireguard_conf);
    CHECK(parsed.kind == NdmsNativeTunnelImportKind::wireguard);
    CHECK(parsed.addresses.size() == 2U);
    CHECK(parsed.dns_servers.size() == 2U);
    CHECK(parsed.private_key.reveal_for_typed_rci() == private_key);
    REQUIRE(parsed.peers.size() == 1U);
    REQUIRE(parsed.peers[0].preshared_key.has_value());
    CHECK(parsed.peers[0].preshared_key->reveal_for_typed_rci() == psk);

    const auto preview =
        build_ndms_native_tunnel_import_preview(parsed);
    CHECK(preview.kind == NdmsNativeTunnelImportKind::wireguard);
    CHECK(preview.address_count == 2U);
    CHECK(preview.dns_count == 2U);
    CHECK(preview.peer_count == 1U);
    CHECK(preview.allowed_ip_count == 2U);
    CHECK(preview.endpoint_host ==
          std::optional<std::string>{"vpn.example.test"});
    CHECK(preview.endpoint_port ==
          std::optional<std::uint16_t>{443U});
    CHECK(preview.persistent_keepalive ==
          std::optional<std::uint16_t>{25U});
    CHECK(preview.has_private_key);
    CHECK(preview.preshared_key_count == 1U);
    CHECK(preview.amnezia_parameter_names.empty());
    CHECK(preview.revision.rfind("ndms-native-import-v1-", 0U) == 0U);
    CHECK(preview.revision.find(private_key) == std::string::npos);
    CHECK(preview.revision.find(psk) == std::string::npos);
}

TEST_CASE("AmneziaWG extensions are complete and visible only by name") {
    auto parsed = parse_ndms_native_tunnel_import(awg_conf());
    CHECK(parsed.kind == NdmsNativeTunnelImportKind::amnezia_wireguard);
    REQUIRE(parsed.awg.has_value());
    CHECK(parsed.awg->jc == 4U);
    CHECK(parsed.awg->s3 == std::optional<std::uint32_t>{300U});
    CHECK(parsed.awg->i1 ==
          std::optional<std::string>{"<r 8><c><t>"});

    const auto preview =
        build_ndms_native_tunnel_import_preview(parsed);
    CHECK(preview.amnezia_parameter_names ==
          std::vector<std::string>{
              "Jc", "Jmin", "Jmax", "S1", "S2",
              "H1", "H2", "H3", "H4", "S3", "S4",
              "I1", "I5"});
}

TEST_CASE("parser rejects executable, unknown, duplicate and URI input precisely") {
    SUBCASE("dangerous directive") {
        auto input = wg_conf();
        input.insert(input.find("\n\n[Peer]"),
                     "\nPostUp = echo secret\n");
        CHECK(rejected_code(input) ==
              NdmsNativeTunnelImportErrorCode::dangerous_directive);
    }
    SUBCASE("unknown directive") {
        auto input = wg_conf();
        input.insert(input.find("\n\n[Peer]"), "\nFwMark = 42\n");
        CHECK(rejected_code(input) ==
              NdmsNativeTunnelImportErrorCode::unknown_field);
    }
    SUBCASE("duplicate PrivateKey returns only the stable error") {
        auto input = wg_conf();
        const auto duplicate = key('X');
        input.insert(input.find("\nDNS"),
                     "\nPrivateKey = " + duplicate);
        CHECK(rejected_code(input) ==
              NdmsNativeTunnelImportErrorCode::duplicate_field);
    }
    SUBCASE("final duplicate PresharedKey returns only the stable error") {
        auto input = wg_conf();
        REQUIRE(!input.empty());
        REQUIRE(input.back() == '\n');
        input += "PresharedKey = " + key('X');
        REQUIRE(input.back() != '\n');
        CHECK(rejected_code(input) ==
              NdmsNativeTunnelImportErrorCode::duplicate_field);
    }
    SUBCASE("unknown section") {
        CHECK(rejected_code(wg_conf() + "\n[Route]\nFoo = bar\n") ==
              NdmsNativeTunnelImportErrorCode::unknown_section);
    }
    SUBCASE("wireguard URI is not a conf alias") {
        CHECK(rejected_code("wireguard://" + key('P')) ==
              NdmsNativeTunnelImportErrorCode::unsupported_uri);
    }
}

TEST_CASE("errors and revision never echo rejected secret input") {
    const std::string secret = "super-sensitive-private-key-material";
    auto input = wg_conf();
    const auto offset = input.find(key('P'));
    input.replace(offset, key('P').size(), secret);
    try {
        static_cast<void>(parse_ndms_native_tunnel_import(input));
        FAIL("invalid key was accepted");
    } catch (const NdmsNativeTunnelImportError& error) {
        CHECK(std::string(error.what()).find(secret) == std::string::npos);
        CHECK(std::string(error.what()) ==
              "native tunnel import rejected: invalid_field");
    }
}

TEST_CASE("late malformed key bytes are rejected before secret decoding") {
    for (const auto index : {std::size_t{41U}, std::size_t{42U}}) {
        auto malformed = key('P');
        malformed[index] = '!';
        auto input = wg_conf();
        const auto offset = input.find(key('P'));
        REQUIRE(offset != std::string::npos);
        input.replace(offset, malformed.size(), malformed);
        CAPTURE(index);
        CHECK(rejected_code(input) ==
              NdmsNativeTunnelImportErrorCode::invalid_field);
    }

    SUBCASE("base64-valid but non-canonical tail sextet is rejected") {
        auto malformed = key('P');
        malformed[42] = 'B';
        auto input = wg_conf();
        const auto offset = input.find(key('P'));
        REQUIRE(offset != std::string::npos);
        input.replace(offset, malformed.size(), malformed);
        CHECK(rejected_code(input) ==
              NdmsNativeTunnelImportErrorCode::invalid_field);
    }

    SUBCASE("the final padding byte is mandatory") {
        auto malformed = key('P');
        malformed[43] = 'A';
        auto input = wg_conf();
        const auto offset = input.find(key('P'));
        REQUIRE(offset != std::string::npos);
        input.replace(offset, malformed.size(), malformed);
        CHECK(rejected_code(input) ==
              NdmsNativeTunnelImportErrorCode::invalid_field);
    }

    SUBCASE("every canonical tail sextet is accepted") {
        for (const char tail : std::string_view{"AEIMQUYcgkosw048"}) {
            auto canonical = key('P');
            canonical[42] = tail;
            auto input = wg_conf();
            const auto offset = input.find(key('P'));
            REQUIRE(offset != std::string::npos);
            input.replace(offset, canonical.size(), canonical);
            CAPTURE(tail);
            CHECK_NOTHROW(parse_ndms_native_tunnel_import(
                std::move(input)));
        }
    }

    SUBCASE("standalone high byte is invalid UTF-8, never locale base64") {
        auto malformed = key('P');
        malformed[41] = static_cast<char>(0xC0U);
        auto input = wg_conf();
        const auto offset = input.find(key('P'));
        REQUIRE(offset != std::string::npos);
        input.replace(offset, malformed.size(), malformed);
        CHECK(rejected_code(input) ==
              NdmsNativeTunnelImportErrorCode::invalid_encoding);
    }

    SUBCASE("valid UTF-8 high bytes are not locale base64 characters") {
        auto malformed = key('P');
        // U+9000 is the valid UTF-8 sequence E9 80 80. It preserves the key's
        // byte length while proving every high byte is rejected as non-ASCII.
        malformed[39] = static_cast<char>(0xE9U);
        malformed[40] = static_cast<char>(0x80U);
        malformed[41] = static_cast<char>(0x80U);
        auto input = wg_conf();
        const auto offset = input.find(key('P'));
        REQUIRE(offset != std::string::npos);
        input.replace(offset, malformed.size(), malformed);
        CHECK(rejected_code(input) ==
              NdmsNativeTunnelImportErrorCode::invalid_field);
    }
}

TEST_CASE("UTF-8 BOM parsing preserves a full-allocation wipe boundary") {
    const auto psk = key('S');
    auto input = std::string{"\xEF\xBB\xBF"}
        + "[Interface]\nAddress=10.0.0.2/32\nPrivateKey=" + key('P')
        + "\n[Peer]\nPublicKey=" + key('K')
        + "\nAllowedIPs=0.0.0.0/0\nEndpoint=host.test:443"
          "\nPresharedKey=" + psk;
    REQUIRE(input.back() != '\n');
    const auto parsed = parse_ndms_native_tunnel_import(std::move(input));
    CHECK(parsed.peers.size() == 1U);
    CHECK(parsed.kind == NdmsNativeTunnelImportKind::wireguard);
    REQUIRE(parsed.peers.front().preshared_key.has_value());
    CHECK(parsed.peers.front().preshared_key->reveal_for_typed_rci() ==
          psk);
}

TEST_CASE("SHA-256 state is non-copyable and wiped at destruction") {
    alignas(Sha256) std::array<unsigned char, sizeof(Sha256)> storage{};
    storage.fill(0xA5U);
    auto* hasher = new (storage.data()) Sha256();
    const auto private_key = key('P');
    hasher->update(private_key);
    CHECK(hasher->hex_digest() == Sha256::hex(private_key));
    hasher->~Sha256();
    CHECK(std::all_of(
        storage.begin(), storage.end(),
        [](const unsigned char byte) { return byte == 0U; }));
}

TEST_CASE("parser bounds raw input, lines and peer count") {
    CHECK(rejected_code(std::string(
              kNdmsNativeTunnelImportMaximumBytes + 1U, 'x')) ==
          NdmsNativeTunnelImportErrorCode::input_too_large);

    auto long_line = wg_conf();
    long_line.insert(long_line.find("\n\n[Peer]"),
                     "\n# " + std::string(9000U, 'a'));
    CHECK(rejected_code(long_line) ==
          NdmsNativeTunnelImportErrorCode::limit_exceeded);

    std::string too_many_peers =
        "[Interface]\nAddress=10.0.0.2/32\nPrivateKey=" + key('P') +
        "\n";
    for (std::size_t index = 0U; index < 65U; ++index) {
        too_many_peers +=
            "[Peer]\nPublicKey=" + key('K') +
            "\nAllowedIPs=0.0.0.0/0\nEndpoint=host.test:443\n";
    }
    CHECK(rejected_code(too_many_peers) ==
          NdmsNativeTunnelImportErrorCode::limit_exceeded);
}

TEST_CASE("URI imports stay disabled until their parser can wipe all allocations") {
    CHECK(rejected_code("vpn://AAAAAA") ==
          NdmsNativeTunnelImportErrorCode::unsupported_uri);
    CHECK(rejected_code("wireguard://not-standard") ==
          NdmsNativeTunnelImportErrorCode::unsupported_uri);
}
