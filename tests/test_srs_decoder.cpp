#include "../src/lists/srs_decoder.hpp"

#include <doctest/doctest.h>

#include <zlib.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

using Bytes = std::vector<std::uint8_t>;

void write_uvarint(Bytes& output, std::uint64_t value) {
    while (value >= 0x80U) {
        output.push_back(static_cast<std::uint8_t>(value) | 0x80U);
        value >>= 7U;
    }
    output.push_back(static_cast<std::uint8_t>(value));
}

void write_be64(Bytes& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void set_bit(std::vector<std::uint64_t>& words, std::size_t bit, bool value) {
    while (words.size() <= bit / 64U) {
        words.push_back(0);
    }
    if (value) {
        words[bit / 64U] |= std::uint64_t{1} << (bit % 64U);
    }
}

std::string reverse_ascii(std::string value) {
    std::reverse(value.begin(), value.end());
    return value;
}

Bytes succinct_matcher(std::vector<std::string> keys) {
    std::sort(keys.begin(), keys.end());
    struct QueueItem {
        std::size_t start;
        std::size_t end;
        std::size_t column;
    };
    std::vector<QueueItem> queue{{0, keys.size(), 0}};
    std::vector<std::uint64_t> leaves;
    std::vector<std::uint64_t> bitmap;
    Bytes labels;
    std::size_t bitmap_index = 0;

    for (std::size_t node = 0; node < queue.size(); ++node) {
        auto item = queue[node];
        if (item.start < item.end &&
            item.column == keys[item.start].size()) {
            ++item.start;
            set_bit(leaves, node, true);
        }
        for (std::size_t index = item.start; index < item.end;) {
            const std::size_t first = index;
            while (index < item.end &&
                   keys[index][item.column] == keys[first][item.column]) {
                ++index;
            }
            queue.push_back({first, index, item.column + 1U});
            labels.push_back(static_cast<std::uint8_t>(keys[first][item.column]));
            set_bit(bitmap, bitmap_index++, false);
        }
        set_bit(bitmap, bitmap_index++, true);
    }

    Bytes output;
    output.push_back(0); // succinct-set format version
    write_uvarint(output, leaves.size());
    for (const auto value : leaves) {
        write_be64(output, value);
    }
    write_uvarint(output, bitmap.size());
    for (const auto value : bitmap) {
        write_be64(output, value);
    }
    write_uvarint(output, labels.size());
    output.insert(output.end(), labels.begin(), labels.end());
    return output;
}

Bytes default_domain_rule(const std::vector<std::string>& encoded_keys,
                          bool invert = false,
                          bool add_network_constraint = false,
                          bool add_domain_regex = false) {
    Bytes output{0, 2}; // default rule, domain item
    const auto matcher = succinct_matcher(encoded_keys);
    output.insert(output.end(), matcher.begin(), matcher.end());
    if (add_network_constraint) {
        output.push_back(1); // network
        write_uvarint(output, 1);
        write_uvarint(output, 3);
        output.insert(output.end(), {'t', 'c', 'p'});
    }
    if (add_domain_regex) {
        output.push_back(4); // domain_regex
        write_uvarint(output, 1);
        write_uvarint(output, 9);
        output.insert(output.end(), {'^', 'a', 'i', '\\', '.', 't', 'e', 's', 't'});
    }
    output.push_back(0xFF);
    output.push_back(invert ? 1 : 0);
    return output;
}

using Address = std::vector<std::uint8_t>;

Bytes default_ip_rule(
    const std::vector<std::pair<Address, Address>>& ranges,
    bool source = false) {
    Bytes output{0, static_cast<std::uint8_t>(source ? 5 : 6)};
    output.push_back(1); // IP-set format version
    write_be64(output, ranges.size());
    for (const auto& range : ranges) {
        write_uvarint(output, range.first.size());
        output.insert(output.end(), range.first.begin(), range.first.end());
        write_uvarint(output, range.second.size());
        output.insert(output.end(), range.second.begin(), range.second.end());
    }
    output.push_back(0xFF);
    output.push_back(0);
    return output;
}

Bytes logical_rule(std::uint8_t mode,
                   const std::vector<Bytes>& children,
                   bool invert = false) {
    Bytes output{1, mode};
    write_uvarint(output, children.size());
    for (const auto& child : children) {
        output.insert(output.end(), child.begin(), child.end());
    }
    output.push_back(invert ? 1 : 0);
    return output;
}

Bytes srs_file(std::uint8_t version,
               const std::vector<Bytes>& rules,
               const Bytes& payload_suffix = {}) {
    Bytes payload;
    write_uvarint(payload, rules.size());
    for (const auto& rule : rules) {
        payload.insert(payload.end(), rule.begin(), rule.end());
    }
    payload.insert(payload.end(), payload_suffix.begin(), payload_suffix.end());

    uLongf compressed_size = compressBound(static_cast<uLong>(payload.size()));
    Bytes compressed(compressed_size);
    REQUIRE(compress2(compressed.data(),
                      &compressed_size,
                      payload.data(),
                      static_cast<uLong>(payload.size()),
                      Z_BEST_COMPRESSION) == Z_OK);
    compressed.resize(compressed_size);

    Bytes result{'S', 'R', 'S', version};
    result.insert(result.end(), compressed.begin(), compressed.end());
    return result;
}

SrsDecodeResult decode(const Bytes& bytes,
                       const SrsDecodeLimits& limits = {}) {
    const std::string data(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    std::istringstream input(data, std::ios::binary);
    return decode_srs(input, limits);
}

std::string decode_error(const Bytes& bytes,
                         const SrsDecodeLimits& limits = {}) {
    try {
        (void)decode(bytes, limits);
    } catch (const SrsDecodeError& error) {
        return error.what();
    }
    return {};
}

SrsDecodeErrorKind decode_error_kind(const Bytes& bytes) {
    try {
        (void)decode(bytes);
    } catch (const SrsDecodeError& error) {
        return error.kind();
    }
    return SrsDecodeErrorKind::InvalidData;
}

} // namespace

TEST_CASE("SRS decoder supports versions 1 through 5") {
    for (std::uint8_t version = 1; version <= 5; ++version) {
        const auto result = decode(srs_file(
            version,
            {default_domain_rule({reverse_ascii("version.example")})}));
        CHECK(result.version == version);
        CHECK(result.domains == std::vector<std::string>{"version.example"});
    }
}

TEST_CASE("SRS v1 legacy suffix pair is recovered without duplicate exact domain") {
    const auto result = decode(srs_file(
        1,
        {default_domain_rule({
            reverse_ascii("example.com"),
            reverse_ascii(std::string("\r") + ".example.com"),
        })}));

    CHECK(result.domains.empty());
    CHECK(result.domain_suffixes == std::vector<std::string>{"example.com"});
}

TEST_CASE("SRS v2 root suffix marker and exact domains are recovered") {
    const auto result = decode(srs_file(
        2,
        {default_domain_rule({
            reverse_ascii("api.example.com"),
            reverse_ascii(std::string("\n") + "example.net"),
        })}));

    CHECK(result.domains == std::vector<std::string>{"api.example.com"});
    CHECK(result.domain_suffixes == std::vector<std::string>{"example.net"});
}

TEST_CASE("SRS IP ranges are converted to a minimal CIDR cover") {
    const Address ipv4_from{192, 0, 2, 10};
    const Address ipv4_to{192, 0, 2, 13};
    const Address ipv6_from{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const Address ipv6_to{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};

    const auto result = decode(srs_file(
        2,
        {default_ip_rule({
            {ipv4_from, ipv4_to},
            {ipv6_from, ipv6_to},
        })}));

    CHECK(result.ip_cidrs ==
          std::vector<std::string>{
              "192.0.2.10/31",
              "192.0.2.12/31",
              "2001:db8::/126",
          });
}

TEST_CASE("SRS constrained and inverted rules never broaden the output") {
    const auto plain = default_domain_rule({reverse_ascii("plain.example")});
    const auto inverted = default_domain_rule(
        {reverse_ascii("inverted.example")}, true);
    const auto constrained = default_domain_rule(
        {reverse_ascii("tcp-only.example")}, false, true);
    const auto and_rule = logical_rule(
        0,
        {
            default_domain_rule({reverse_ascii("and-a.example")}),
            default_domain_rule({reverse_ascii("and-b.example")}),
        });
    const auto or_rule = logical_rule(1, {plain, inverted});

    const auto result =
        decode(srs_file(2, {or_rule, constrained, and_rule}));

    CHECK(result.domains == std::vector<std::string>{"plain.example"});
    CHECK(result.unsupported_fields == 1);
    CHECK(result.inverted_rules == 1);
    CHECK(result.skipped_rules == 3);
}

TEST_CASE("SRS keeps representable destination alternatives") {
    const auto result = decode(srs_file(
        2,
        {default_domain_rule(
            {reverse_ascii("plain.example")}, false, false, true)}));

    CHECK(result.domains == std::vector<std::string>{"plain.example"});
    CHECK(result.unsupported_fields == 1);
    CHECK(result.skipped_rules == 0);
}

TEST_CASE("SRS combines domain and IP destination alternatives") {
    auto rule = default_domain_rule({reverse_ascii("plain.example")});
    rule.pop_back(); // invert
    rule.pop_back(); // final
    const auto ip_item = default_ip_rule(
        {{{192, 0, 2, 1}, {192, 0, 2, 1}}});
    rule.insert(rule.end(), ip_item.begin() + 1, ip_item.end());

    const auto result = decode(srs_file(2, {rule}));
    CHECK(result.domains == std::vector<std::string>{"plain.example"});
    CHECK(result.ip_cidrs == std::vector<std::string>{"192.0.2.1/32"});
    CHECK(result.unsupported_fields == 0);
    CHECK(result.skipped_rules == 0);
}

TEST_CASE("SRS source IP ranges are validated but counted as unsupported") {
    const auto result = decode(srs_file(
        2,
        {default_ip_rule({{{10, 0, 0, 1}, {10, 0, 0, 1}}}, true)}));

    CHECK(result.ip_cidrs.empty());
    CHECK(result.unsupported_fields == 1);
    CHECK(result.skipped_rules == 1);
}

TEST_CASE("SRS decoder rejects malformed header version and zlib data") {
    CHECK(decode_error(Bytes{'S', 'R'}).find("header is truncated") !=
          std::string::npos);
    CHECK(decode_error(Bytes{'B', 'A', 'D', 2, 0}).find("magic") !=
          std::string::npos);
    CHECK(decode_error(Bytes{'S', 'R', 'S', 0, 0}).find("version") !=
          std::string::npos);
    CHECK(decode_error(Bytes{'S', 'R', 'S', 6, 0}).find("version") !=
          std::string::npos);
    CHECK(decode_error_kind(Bytes{'S', 'R', 'S', 0, 0}) ==
          SrsDecodeErrorKind::InvalidData);
    CHECK(decode_error_kind(Bytes{'S', 'R', 'S', 6, 0}) ==
          SrsDecodeErrorKind::UnsupportedVersion);
    CHECK(decode_error(Bytes{'S', 'R', 'S', 2, 1, 2, 3}).find("zlib") !=
          std::string::npos);
}

TEST_CASE("SRS decoder rejects truncation and trailing streams") {
    auto truncated = srs_file(
        2,
        {default_domain_rule({reverse_ascii("truncated.example")})});
    truncated.pop_back();
    CHECK(decode_error(truncated).find("truncated") != std::string::npos);

    auto trailing_compressed = srs_file(2, {});
    trailing_compressed.push_back(0);
    CHECK(decode_error(trailing_compressed).find("trailing compressed") !=
          std::string::npos);

    const auto trailing_payload = srs_file(2, {}, Bytes{0});
    CHECK(decode_error(trailing_payload).find("trailing decompressed") !=
          std::string::npos);
}

TEST_CASE("SRS decoder stops decompression bombs before parsing") {
    SrsDecodeLimits limits;
    limits.max_decompressed_bytes = 64;
    const Bytes repeated(8192, 0);
    const auto error = decode_error(srs_file(2, {}, repeated), limits);
    CHECK(error.find("decompressed payload exceeds limit") != std::string::npos);
}

TEST_CASE("SRS decoder applies count string trie and IP range limits") {
    SUBCASE("trie node limit fits decoder index") {
        if constexpr (sizeof(std::size_t) > sizeof(std::uint32_t)) {
            SrsDecodeLimits limits;
            limits.max_trie_nodes =
                static_cast<std::size_t>(
                    std::numeric_limits<std::uint32_t>::max()) +
                1U;
            const auto error = decode_error(srs_file(2, {}), limits);
            CHECK(error.find("trie node limit exceeds decoder index range") !=
                  std::string::npos);
        } else {
            CHECK(true);
        }
    }

    SUBCASE("rule count") {
        SrsDecodeLimits limits;
        limits.max_rules = 1;
        const auto error = decode_error(
            srs_file(2, {
                default_domain_rule({reverse_ascii("one.example")}),
                default_domain_rule({reverse_ascii("two.example")}),
            }),
            limits);
        CHECK(error.find("rule count exceeds limit") != std::string::npos);
    }

    SUBCASE("string length") {
        SrsDecodeLimits limits;
        limits.max_string_bytes = 2;
        Bytes network_rule{0, 1};
        write_uvarint(network_rule, 1);
        write_uvarint(network_rule, 3);
        network_rule.insert(network_rule.end(), {'t', 'c', 'p'});
        network_rule.insert(network_rule.end(), {0xFF, 0});
        const auto error = decode_error(
            srs_file(2, {network_rule}),
            limits);
        CHECK(error.find("length exceeds limit") != std::string::npos);
    }

    SUBCASE("trie labels") {
        SrsDecodeLimits limits;
        limits.max_trie_labels = 2;
        const auto error = decode_error(
            srs_file(
                2,
                {default_domain_rule({reverse_ascii("large.example")})}),
            limits);
        CHECK(error.find("labels byte count exceeds limit") != std::string::npos);
    }

    SUBCASE("decoded output bytes") {
        SrsDecodeLimits limits;
        limits.max_output_string_bytes = 4;
        const auto error = decode_error(
            srs_file(
                2,
                {default_domain_rule({reverse_ascii("large.example")})}),
            limits);
        CHECK(error.find("output string data exceeds limit") !=
              std::string::npos);
    }

    SUBCASE("IP ranges") {
        SrsDecodeLimits limits;
        limits.max_ip_ranges = 1;
        const auto error = decode_error(
            srs_file(
                2,
                {default_ip_rule({
                    {{10, 0, 0, 1}, {10, 0, 0, 1}},
                    {{10, 0, 0, 2}, {10, 0, 0, 2}},
                })}),
            limits);
        CHECK(error.find("range count exceeds limit") != std::string::npos);
    }
}

TEST_CASE("SRS decoder rejects malformed trie and IP ranges descriptively") {
    SUBCASE("trie edge mismatch") {
        Bytes malformed_matcher;
        malformed_matcher.push_back(0);
        write_uvarint(malformed_matcher, 1);
        write_be64(malformed_matcher, 0);
        write_uvarint(malformed_matcher, 1);
        write_be64(malformed_matcher, 1); // root delimiter, but one label follows
        write_uvarint(malformed_matcher, 1);
        malformed_matcher.push_back('x');

        Bytes rule{0, 2};
        rule.insert(rule.end(), malformed_matcher.begin(), malformed_matcher.end());
        rule.insert(rule.end(), {0xFF, 0});
        const auto error = decode_error(srs_file(2, {rule}));
        CHECK(error.find("more edges than labels") != std::string::npos);
    }

    SUBCASE("reversed IP range") {
        const auto error = decode_error(srs_file(
            2,
            {default_ip_rule({{{10, 0, 0, 9}, {10, 0, 0, 1}}})}));
        CHECK(error.find("ends before it starts") != std::string::npos);
    }
}

TEST_CASE("SRS skips subdomain-only suffixes that keen-pbr cannot represent") {
    const auto result = decode(srs_file(
        2,
        {default_domain_rule({
            reverse_ascii("plain.example"),
            reverse_ascii(std::string("\r") + ".sub.example"),
        })}));

    CHECK(result.domains == std::vector<std::string>{"plain.example"});
    CHECK(result.domain_suffixes.empty());
    CHECK(result.unsupported_fields == 1);
}
