#include "local_password_hash.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr const char* kPrefix = "kpbr-pbkdf2-sha256-v1";

void secure_zero(void* memory, const std::size_t length) noexcept {
    auto* bytes = static_cast<volatile unsigned char*>(memory);
    for (std::size_t index = 0U; index < length; ++index) bytes[index] = 0U;
}

bool constant_time_equal(const std::string& left, const std::string& right) {
    std::size_t difference = left.size() ^ right.size();
    const std::size_t length = std::max(left.size(), right.size());
    for (std::size_t index = 0U; index < length; ++index) {
        const unsigned char a =
            index < left.size() ? static_cast<unsigned char>(left[index]) : 0U;
        const unsigned char b =
            index < right.size() ? static_cast<unsigned char>(right[index])
                                 : 0U;
        difference |= static_cast<std::size_t>(a ^ b);
    }
    return difference == 0U;
}

bool lowercase_hex(const std::string& value) noexcept {
    if (value.empty() || value.size() % 2U != 0U) return false;
    return std::all_of(value.begin(), value.end(), [](const char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

std::string hex_of(const std::array<std::uint8_t, 32>& bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output;
    output.reserve(bytes.size() * 2U);
    for (const std::uint8_t byte : bytes) {
        output.push_back(kHex[byte >> 4U]);
        output.push_back(kHex[byte & 0x0FU]);
    }
    return output;
}

// HMAC-SHA256. The key is the password, so both padded key blocks are wiped
// before returning: they are the password xored with a constant.
std::array<std::uint8_t, 32> hmac_sha256(const std::string& key,
                                         const std::uint8_t* message,
                                         const std::size_t message_length) {
    std::array<std::uint8_t, 64> block{};
    if (key.size() > block.size()) {
        Sha256 shortener;
        shortener.update(key);
        const auto shortened = shortener.digest();
        std::copy(shortened.begin(), shortened.end(), block.begin());
    } else {
        std::copy(key.begin(), key.end(), block.begin());
    }

    std::array<std::uint8_t, 64> inner_pad{};
    std::array<std::uint8_t, 64> outer_pad{};
    for (std::size_t index = 0U; index < block.size(); ++index) {
        inner_pad[index] = static_cast<std::uint8_t>(block[index] ^ 0x36U);
        outer_pad[index] = static_cast<std::uint8_t>(block[index] ^ 0x5CU);
    }

    Sha256 inner;
    inner.update(inner_pad.data(), inner_pad.size());
    inner.update(message, message_length);
    const auto inner_digest = inner.digest();

    Sha256 outer;
    outer.update(outer_pad.data(), outer_pad.size());
    outer.update(inner_digest.data(), inner_digest.size());
    const auto result = outer.digest();

    secure_zero(block.data(), block.size());
    secure_zero(inner_pad.data(), inner_pad.size());
    secure_zero(outer_pad.data(), outer_pad.size());
    return result;
}

// PBKDF2 with dkLen == hLen, so exactly one block and no outer loop.
std::array<std::uint8_t, 32> pbkdf2_sha256(const std::string& password,
                                           const std::string& salt,
                                           const std::uint32_t iterations) {
    std::vector<std::uint8_t> seed(salt.begin(), salt.end());
    // INT(1), big-endian, as the block index.
    seed.push_back(0U);
    seed.push_back(0U);
    seed.push_back(0U);
    seed.push_back(1U);

    auto block = hmac_sha256(password, seed.data(), seed.size());
    auto accumulator = block;
    for (std::uint32_t round = 1U; round < iterations; ++round) {
        block = hmac_sha256(password, block.data(), block.size());
        for (std::size_t index = 0U; index < accumulator.size(); ++index) {
            accumulator[index] ^= block[index];
        }
    }
    secure_zero(block.data(), block.size());
    return accumulator;
}

struct DecodedHash {
    std::uint32_t iterations{0U};
    std::string salt_hex;
    std::string digest_hex;
};

bool decode(const std::string& stored, DecodedHash& decoded) {
    const std::string prefix = std::string(kPrefix) + "$";
    if (stored.compare(0U, prefix.size(), prefix) != 0) return false;

    const auto first = stored.find('$', prefix.size());
    if (first == std::string::npos) return false;
    const auto second = stored.find('$', first + 1U);
    if (second == std::string::npos) return false;
    // A fourth field would mean this is not the format it claims to be.
    if (stored.find('$', second + 1U) != std::string::npos) return false;

    const std::string iterations_text =
        stored.substr(prefix.size(), first - prefix.size());
    if (iterations_text.empty() ||
        iterations_text.find_first_not_of("0123456789") !=
            std::string::npos ||
        iterations_text.size() > 9U) {
        return false;
    }
    decoded.iterations = static_cast<std::uint32_t>(
        std::strtoul(iterations_text.c_str(), nullptr, 10));
    if (decoded.iterations == 0U) return false;

    decoded.salt_hex = stored.substr(first + 1U, second - first - 1U);
    decoded.digest_hex = stored.substr(second + 1U);
    if (!lowercase_hex(decoded.salt_hex) ||
        decoded.salt_hex.size() < kLocalPasswordSaltBytes * 2U) {
        return false;
    }
    // SHA-256 output, exactly.
    return lowercase_hex(decoded.digest_hex) &&
           decoded.digest_hex.size() == 64U;
}

} // namespace

const char* local_password_verdict_name(
    const LocalPasswordVerdict verdict) noexcept {
    switch (verdict) {
    case LocalPasswordVerdict::matched:
        return "matched";
    case LocalPasswordVerdict::mismatched:
        return "mismatched";
    case LocalPasswordVerdict::matched_legacy_plaintext:
        return "matched_legacy_plaintext";
    case LocalPasswordVerdict::mismatched_legacy_plaintext:
        return "mismatched_legacy_plaintext";
    case LocalPasswordVerdict::unusable:
        return "unusable";
    }
    return "unusable";
}

bool local_password_hash_encoded(const std::string& stored) noexcept {
    DecodedHash decoded;
    return decode(stored, decoded);
}

std::string local_password_derive_hex(const std::string& password,
                                      const std::string& salt,
                                      const std::uint32_t iterations) {
    if (iterations == 0U) return {};
    return hex_of(pbkdf2_sha256(password, salt, iterations));
}

std::string encode_local_password_hash(const std::string& password,
                                       const std::string& salt_hex,
                                       const std::uint32_t iterations) {
    if (iterations == 0U || !lowercase_hex(salt_hex) ||
        salt_hex.size() < kLocalPasswordSaltBytes * 2U) {
        return {};
    }
    // The salt is carried as its text. Two installs never share one, which is
    // all a salt has to do, and keeping it textual means the encoded line is
    // the whole story with no second decoding step to get wrong.
    return std::string(kPrefix) + "$" + std::to_string(iterations) + "$" +
           salt_hex + "$" +
           local_password_derive_hex(password, salt_hex, iterations);
}

LocalPasswordVerdict verify_local_password(const std::string& stored,
                                           const std::string& password) {
    // The marker alone is enough to claim the format; the separator is not
    // required. A stored value that begins with it and then fails to decode is
    // corruption, and a corrupted hash must not become a password whose shape
    // an attacker already knows. The cost is that no password may begin with
    // this exact marker, which is a fair trade for closing that door.
    const std::string marker(kPrefix);
    const bool claims_to_be_a_hash =
        stored.compare(0U, marker.size(), marker) == 0;

    DecodedHash decoded;
    if (!decode(stored, decoded)) {
        // Something that announced itself as a derived key and is not one is
        // refused. Falling back to comparing it as a password would turn a
        // corrupted hash into a credential whose shape an attacker knows.
        if (claims_to_be_a_hash) return LocalPasswordVerdict::unusable;
        return constant_time_equal(stored, password)
                   ? LocalPasswordVerdict::matched_legacy_plaintext
                   : LocalPasswordVerdict::mismatched_legacy_plaintext;
    }

    const std::string digest = local_password_derive_hex(
        password, decoded.salt_hex, decoded.iterations);
    return constant_time_equal(digest, decoded.digest_hex)
               ? LocalPasswordVerdict::matched
               : LocalPasswordVerdict::mismatched;
}

} // namespace keen_pbr3
