#include <doctest/doctest.h>
#include <nlohmann/json.hpp>
#include <zlib.h>

#include "keenetic/ndms_native_import_request.hpp"
#include "keenetic/ndms_native_import_identity.hpp"

#include <cstdint>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

using namespace keen_pbr3;

namespace {

void wipe(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : &value[0];
    for (std::size_t index = 0U;
         bytes != nullptr && index < value.size(); ++index) {
        bytes[index] = '\0';
    }
    value.clear();
}

class WipeGuard {
public:
    explicit WipeGuard(std::string& value) noexcept : value_(value) {}
    ~WipeGuard() { wipe(value_); }

private:
    std::string& value_;
};

std::string base64_encode_for_test(const std::string_view input) {
    constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((input.size() + 2U) / 3U) * 4U);
    for (std::size_t offset = 0U; offset < input.size(); offset += 3U) {
        const auto first = static_cast<std::uint8_t>(input[offset]);
        const bool has_second = offset + 1U < input.size();
        const bool has_third = offset + 2U < input.size();
        const auto second = has_second
            ? static_cast<std::uint8_t>(input[offset + 1U]) : 0U;
        const auto third = has_third
            ? static_cast<std::uint8_t>(input[offset + 2U]) : 0U;
        const std::uint32_t block =
            (static_cast<std::uint32_t>(first) << 16U) |
            (static_cast<std::uint32_t>(second) << 8U) |
            static_cast<std::uint32_t>(third);
        output.push_back(alphabet[(block >> 18U) & 0x3FU]);
        output.push_back(alphabet[(block >> 12U) & 0x3FU]);
        output.push_back(has_second
            ? alphabet[(block >> 6U) & 0x3FU] : '=');
        output.push_back(has_third ? alphabet[block & 0x3FU] : '=');
    }
    return output;
}

std::string key(const char value) {
    const std::string raw(32U, value);
    return base64_encode_for_test(raw);
}

std::string wg_conf() {
    return
        "# Name = ../../caller-controlled\n"
        "; filename = attacker.conf\n"
        "[Interface]\n"
        "Address = 10.8.0.2/32\n"
        "PrivateKey = " + key('P') + "\n"
        "DNS = 1.1.1.1\n"
        "ListenPort = 51820\n"
        "MTU = 1420\n"
        "\n"
        "[Peer]\n"
        "PublicKey = " + key('K') + "\n"
        "PresharedKey = " + key('S') + "\n"
        "AllowedIPs = 0.0.0.0/0, 10.0.0.0/8\n"
        "Endpoint = vpn.example.test:443\n"
        "PersistentKeepalive = 25\n";
}

std::string awg_conf() {
    auto value = wg_conf();
    const auto peer = value.find("\n\n[Peer]");
    REQUIRE(peer != std::string::npos);
    value.insert(
        peer,
        "\nJc = 4\nJmin = 40\nJmax = 70\n"
        "S1 = 100\nS2 = 200\nS3 = 300\nS4 = 400\n"
        "H1 = 101010101\nH2 = 202020202\n"
        "H3 = 303030303\nH4 = 404040404\n"
        "I1 = <r 8><c><t>\nI5 = <b 0x10>\n");
    return value;
}

std::string zero_base_awg_conf() {
    auto value = wg_conf();
    const auto peer = value.find("\n\n[Peer]");
    REQUIRE(peer != std::string::npos);
    value.insert(
        peer,
        "\nJc = 0\nJmin = 0\nJmax = 0\n"
        "S1 = 0\nS2 = 0\n"
        "H1 =\nH2 =\nH3 =\nH4 =\n"
        "I1 = <b 0x0102>\n");
    return value;
}

std::string base64url(const std::string& input) {
    constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve((input.size() * 4U + 2U) / 3U);
    std::uint32_t accumulator = 0U;
    unsigned bits = 0U;
    for (const auto character : input) {
        accumulator = (accumulator << 8U) |
            static_cast<unsigned char>(character);
        bits += 8U;
        while (bits >= 6U) {
            bits -= 6U;
            output.push_back(alphabet[(accumulator >> bits) & 0x3FU]);
            accumulator &= bits == 0U ? 0U : ((1U << bits) - 1U);
        }
    }
    if (bits != 0U) {
        output.push_back(
            alphabet[(accumulator << (6U - bits)) & 0x3FU]);
    }
    return output;
}

std::string qcompress_uri(const std::string& input) {
    uLongf compressed_size = compressBound(
        static_cast<uLong>(input.size()));
    std::string compressed(4U + compressed_size, '\0');
    WipeGuard compressed_guard(compressed);
    const auto size = static_cast<std::uint32_t>(input.size());
    compressed[0] = static_cast<char>((size >> 24U) & 0xFFU);
    compressed[1] = static_cast<char>((size >> 16U) & 0xFFU);
    compressed[2] = static_cast<char>((size >> 8U) & 0xFFU);
    compressed[3] = static_cast<char>(size & 0xFFU);
    REQUIRE(compress2(
                reinterpret_cast<Bytef*>(&compressed[4]),
                &compressed_size,
                reinterpret_cast<const Bytef*>(input.data()),
                static_cast<uLong>(input.size()), 8) == Z_OK);
    compressed.resize(4U + compressed_size);
    return "vpn://" + base64url(compressed);
}

std::string wireguard_vpn_uri() {
    const nlohmann::json last_config{
        {"config", wg_conf()}, {"mtu", "1420"}, {"port", 51820},
    };
    const nlohmann::json envelope{
        {"containers", nlohmann::json::array({
            {{"container", "amnezia-wireguard"},
             {"wireguard", {{"last_config", last_config.dump()}}}},
        })},
    };
    return qcompress_uri(envelope.dump());
}

class CapturingSecretSink final : public NdmsNativeSecretBodySink {
public:
    explicit CapturingSecretSink(const std::size_t expected_size) {
        body_.reserve(expected_size);
    }
    ~CapturingSecretSink() override { wipe(body_); }

    bool write_secret_body_chunk(const std::string_view chunk) override {
        body_.append(chunk.data(), chunk.size());
        ++chunks_;
        return true;
    }

    const std::string& body() const noexcept { return body_; }
    std::size_t chunks() const noexcept { return chunks_; }

private:
    std::string body_;
    std::size_t chunks_{0U};
};

class RejectingSecretSink final : public NdmsNativeSecretBodySink {
public:
    explicit RejectingSecretSink(const std::size_t accepted_chunks)
        : accepted_chunks_(accepted_chunks) {}

    bool write_secret_body_chunk(std::string_view) override {
        return seen_++ < accepted_chunks_;
    }

private:
    std::size_t accepted_chunks_{0U};
    std::size_t seen_{0U};
};

class ThrowingSecretSink final : public NdmsNativeSecretBodySink {
public:
    bool write_secret_body_chunk(std::string_view) override {
        throw std::runtime_error("synthetic transport failure");
    }
};

NdmsNativeWireguardImportRequestErrorCode request_error(
    std::string input) {
    try {
        static_cast<void>(
            make_ndms_native_wireguard_import_request(std::move(input)));
    } catch (const NdmsNativeWireguardImportRequestError& error) {
        CHECK(std::string(error.what()) ==
              std::string{"native WireGuard import request rejected: "} +
                  ndms_native_wireguard_import_request_error_code_name(
                      error.code()));
        return error.code();
    }
    FAIL("request was accepted");
    return NdmsNativeWireguardImportRequestErrorCode::unsupported_source;
}

} // namespace

static_assert(!std::is_copy_constructible_v<
              NdmsNativeWireguardImportRequest>);
static_assert(!std::is_copy_assignable_v<
              NdmsNativeWireguardImportRequest>);
static_assert(std::is_nothrow_move_constructible_v<
              NdmsNativeWireguardImportRequest>);
static_assert(std::is_nothrow_move_assignable_v<
              NdmsNativeWireguardImportRequest>);
static_assert(!std::is_convertible_v<
              NdmsNativeWireguardImportRequest, std::string>);
static_assert(std::is_invocable_v<
              decltype(&make_ndms_native_wireguard_import_request),
              std::string>);
static_assert(!std::is_invocable_v<
              decltype(&make_ndms_native_wireguard_import_request),
              std::string&>);
static_assert(!std::is_invocable_v<
              decltype(&make_ndms_native_wireguard_import_request),
              std::string, std::string>);

TEST_CASE("native WG request is an exact canonical stock batch") {
    const auto private_key = key('P');
    const auto public_key = key('K');
    const auto preshared_key = key('S');
    auto request = make_ndms_native_wireguard_import_request(wg_conf());

    CHECK(request.operation() == "interface.wireguard.import");
    CHECK(request.kind() == NdmsNativeTunnelImportKind::wireguard);
    CHECK(std::regex_match(
        std::string(request.marker()),
        std::regex{"^kpbr-ni-v1-[0-9a-f]{32}$"}));
    CHECK(valid_ndms_native_import_transaction_id(
        request.transaction_id()));
    CHECK(valid_ndms_native_import_marker(
        request.marker(), request.transaction_id()));
    CHECK(ndms_native_import_transaction_id_from_marker(
              request.marker()) == request.transaction_id());
    CHECK(request.filename() ==
          std::string(request.marker()) + ".conf");
    CHECK(request.candidate_revision().rfind(
              "ndms-native-import-v1-", 0U) == 0U);
    CHECK(request.candidate_revision().size() ==
          std::string_view{"ndms-native-import-v1-"}.size() + 64U);
    CHECK(request.has_pending_secret_body());

    std::string canonical =
        "# Name = " + std::string(request.marker()) + "\n"
        "[Interface]\n"
        "PrivateKey = " + private_key + "\n"
        "Address = 10.8.0.2/32\n"
        "DNS = 1.1.1.1\n"
        "ListenPort = 51820\n"
        "MTU = 1420\n"
        "\n[Peer]\n"
        "PublicKey = " + public_key + "\n"
        "PresharedKey = " + preshared_key + "\n"
        "Endpoint = vpn.example.test:443\n"
        "AllowedIPs = 0.0.0.0/0, 10.0.0.0/8\n"
        "PersistentKeepalive = 25\n";
    WipeGuard canonical_guard(canonical);
    auto encoded = base64_encode_for_test(canonical);
    WipeGuard encoded_guard(encoded);
    std::string expected =
        "[{\"interface\":{\"wireguard\":{\"import\":{\"import\":\"" +
        encoded + "\",\"name\":\"\",\"filename\":\"" +
        std::string(request.filename()) + "\"}}}}]";
    WipeGuard expected_guard(expected);

    CapturingSecretSink sink(request.content_length());
    CHECK(request.write_stock_rci_body_once(sink));
    CHECK(sink.body() == expected);
    CHECK(sink.body().size() == request.content_length());
    CHECK(sink.chunks() >= 5U);
    CHECK_FALSE(request.has_pending_secret_body());
    CHECK(sink.body().find("caller-controlled") == std::string::npos);
    CHECK(sink.body().find("attacker.conf") == std::string::npos);
    CHECK(sink.body().find("\"up\"") == std::string::npos);
    CHECK(sink.body().find("\"system\"") == std::string::npos);

    CHECK_THROWS_WITH_AS(
        request.write_stock_rci_body_once(sink),
        "native WireGuard import request rejected: already_consumed",
        NdmsNativeWireguardImportRequestError);
}

TEST_CASE("native AWG request emits complete base and extended parameters") {
    auto request = make_ndms_native_wireguard_import_request(awg_conf());
    CHECK(request.kind() ==
          NdmsNativeTunnelImportKind::amnezia_wireguard);
    std::string canonical =
        "# Name = " + std::string(request.marker()) + "\n"
        "[Interface]\n"
        "PrivateKey = " + key('P') + "\n"
        "Address = 10.8.0.2/32\n"
        "DNS = 1.1.1.1\n"
        "ListenPort = 51820\n"
        "MTU = 1420\n"
        "Jc = 4\nJmin = 40\nJmax = 70\n"
        "S1 = 100\nS2 = 200\n"
        "H1 = 101010101\nH2 = 202020202\n"
        "H3 = 303030303\nH4 = 404040404\n"
        "S3 = 300\nS4 = 400\n"
        "I1 = <r 8><c><t>\nI5 = <b 0x10>\n"
        "\n[Peer]\n"
        "PublicKey = " + key('K') + "\n"
        "PresharedKey = " + key('S') + "\n"
        "Endpoint = vpn.example.test:443\n"
        "AllowedIPs = 0.0.0.0/0, 10.0.0.0/8\n"
        "PersistentKeepalive = 25\n";
    WipeGuard canonical_guard(canonical);
    auto encoded = base64_encode_for_test(canonical);
    WipeGuard encoded_guard(encoded);
    std::string expected =
        "[{\"interface\":{\"wireguard\":{\"import\":{\"import\":\"" +
        encoded + "\",\"name\":\"\",\"filename\":\"" +
        std::string(request.filename()) + "\"}}}}]";
    WipeGuard expected_guard(expected);

    CapturingSecretSink sink(request.content_length());
    CHECK(request.write_stock_rci_body_once(sink));
    CHECK(sink.body() == expected);
    CHECK_FALSE(request.has_pending_secret_body());
}

TEST_CASE("native AWG request fills extended S3 and S4 when signatures need them") {
    auto request =
        make_ndms_native_wireguard_import_request(zero_base_awg_conf());
    std::string canonical =
        "# Name = " + std::string(request.marker()) + "\n"
        "[Interface]\n"
        "PrivateKey = " + key('P') + "\n"
        "Address = 10.8.0.2/32\n"
        "DNS = 1.1.1.1\n"
        "ListenPort = 51820\n"
        "MTU = 1420\n"
        "Jc = 0\nJmin = 0\nJmax = 0\n"
        "S1 = 0\nS2 = 0\n"
        "H1 = \nH2 = \nH3 = \nH4 = \n"
        "S3 = 0\nS4 = 0\n"
        "I1 = <b 0x0102>\n"
        "\n[Peer]\n"
        "PublicKey = " + key('K') + "\n"
        "PresharedKey = " + key('S') + "\n"
        "Endpoint = vpn.example.test:443\n"
        "AllowedIPs = 0.0.0.0/0, 10.0.0.0/8\n"
        "PersistentKeepalive = 25\n";
    WipeGuard canonical_guard(canonical);
    auto encoded = base64_encode_for_test(canonical);
    WipeGuard encoded_guard(encoded);
    std::string expected =
        "[{\"interface\":{\"wireguard\":{\"import\":{\"import\":\"" +
        encoded + "\",\"name\":\"\",\"filename\":\"" +
        std::string(request.filename()) + "\"}}}}]";
    WipeGuard expected_guard(expected);

    CapturingSecretSink sink(request.content_length());
    CHECK(request.write_stock_rci_body_once(sink));
    CHECK(sink.body() == expected);
    CHECK_FALSE(request.has_pending_secret_body());
}

TEST_CASE("native WG and AWG requests still reject URI envelopes") {
    CHECK(request_error(wireguard_vpn_uri()) ==
          NdmsNativeWireguardImportRequestErrorCode::unsupported_source);
}

TEST_CASE("native WG request bounds raw input before parsing") {
    try {
        static_cast<void>(make_ndms_native_wireguard_import_request(
            std::string(
                kNdmsNativeWireguardImportRequestMaximumBytes + 1U,
                'x')));
        FAIL("oversized input was accepted");
    } catch (const NdmsNativeTunnelImportError& error) {
        CHECK(error.code() ==
              NdmsNativeTunnelImportErrorCode::input_too_large);
        CHECK(std::string(error.what()) ==
              "native tunnel import rejected: input_too_large");
    }
}

TEST_CASE("native WG request wipes its secret after every sink outcome") {
    SUBCASE("adopted caller allocation on success") {
        auto raw = wg_conf();
        auto request =
            make_ndms_native_wireguard_import_request(std::move(raw));
        CHECK(raw.empty());
        RejectingSecretSink sink(0U);
        CHECK_FALSE(request.write_stock_rci_body_once(sink));
    }

    SUBCASE("adopted caller allocation on parse failure") {
        auto raw = wg_conf();
        const auto endpoint = raw.find("vpn.example.test:443");
        REQUIRE(endpoint != std::string::npos);
        raw.replace(endpoint, std::string{"vpn.example.test:443"}.size(),
                    "invalid endpoint");
        CHECK_THROWS_AS(
            make_ndms_native_wireguard_import_request(std::move(raw)),
            NdmsNativeTunnelImportError);
        CHECK(raw.empty());
    }

    SUBCASE("sink rejection") {
        auto request =
            make_ndms_native_wireguard_import_request(wg_conf());
        RejectingSecretSink sink(1U);
        CHECK_FALSE(request.write_stock_rci_body_once(sink));
        CHECK_FALSE(request.has_pending_secret_body());
    }

    SUBCASE("sink exception") {
        auto request =
            make_ndms_native_wireguard_import_request(wg_conf());
        ThrowingSecretSink sink;
        CHECK_THROWS_WITH(
            request.write_stock_rci_body_once(sink),
            "synthetic transport failure");
        CHECK_FALSE(request.has_pending_secret_body());
    }

    SUBCASE("AWG sink rejection") {
        auto raw = awg_conf();
        auto request =
            make_ndms_native_wireguard_import_request(std::move(raw));
        CHECK(raw.empty());
        RejectingSecretSink sink(2U);
        CHECK_FALSE(request.write_stock_rci_body_once(sink));
        CHECK_FALSE(request.has_pending_secret_body());
    }
}

TEST_CASE("native WG request move transfers the only secret lifetime") {
    auto source = make_ndms_native_wireguard_import_request(wg_conf());
    const auto marker = std::string(source.marker());
    const auto size = source.content_length();
    auto destination = std::move(source);

    CHECK_FALSE(source.has_pending_secret_body());
    CHECK(source.content_length() == 0U);
    CHECK(destination.has_pending_secret_body());
    CHECK(destination.marker() == marker);
    CHECK(destination.content_length() == size);

    RejectingSecretSink sink(0U);
    CHECK_FALSE(destination.write_stock_rci_body_once(sink));
    CHECK_FALSE(destination.has_pending_secret_body());
}
