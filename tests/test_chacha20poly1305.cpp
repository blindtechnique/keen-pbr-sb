#include <doctest/doctest.h>

#include "../src/crypto/chacha20poly1305.hpp"

#include <cstring>
#include <string>

namespace keen_pbr3 {

namespace {

std::string hex(const std::string& bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    for (const unsigned char ch : bytes) {
        out.push_back(digits[ch >> 4U]);
        out.push_back(digits[ch & 0x0fU]);
    }
    return out;
}

// RFC 8439 §2.8.2 fixtures.
const std::string kPlaintext =
    "Ladies and Gentlemen of the class of '99: If I could offer you "
    "only one tip for the future, sunscreen would be it.";

void rfc_key(unsigned char (&key)[kChaCha20Poly1305KeyBytes]) {
    for (unsigned i = 0U; i < 32U; ++i)
        key[i] = static_cast<unsigned char>(0x80U + i);
}

void rfc_nonce(unsigned char (&nonce)[kChaCha20Poly1305NonceBytes]) {
    const unsigned char bytes[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                                     0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
    std::memcpy(nonce, bytes, sizeof(bytes));
}

const std::string kAad{"\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7",
                       12U};

} // namespace

TEST_CASE("the RFC 8439 AEAD vector is reproduced exactly") {
    unsigned char key[kChaCha20Poly1305KeyBytes];
    unsigned char nonce[kChaCha20Poly1305NonceBytes];
    rfc_key(key);
    rfc_nonce(nonce);

    const auto sealed = chacha20poly1305_seal(key, nonce, kAad, kPlaintext);
    REQUIRE(sealed.size() ==
            kPlaintext.size() + kChaCha20Poly1305TagBytes);

    // The RFC's ciphertext begins d31a8d34648e60db and its tag is exact.
    CHECK(hex(sealed.substr(0U, 8U)) == "d31a8d34648e60db");
    CHECK(hex(sealed.substr(sealed.size() - 16U)) ==
          "1ae10b594f09e26a7e902ecbd0600691");

    const auto opened = chacha20poly1305_open(key, nonce, kAad, sealed);
    REQUIRE(opened.has_value());
    CHECK(*opened == kPlaintext);
}

TEST_CASE("one flipped bit anywhere is a refusal, not a partial plaintext") {
    unsigned char key[kChaCha20Poly1305KeyBytes];
    unsigned char nonce[kChaCha20Poly1305NonceBytes];
    rfc_key(key);
    rfc_nonce(nonce);
    const auto sealed = chacha20poly1305_seal(key, nonce, kAad, kPlaintext);

    for (const std::size_t position :
         {std::size_t{0U}, sealed.size() / 2U, sealed.size() - 1U}) {
        auto tampered = sealed;
        tampered[position] = static_cast<char>(tampered[position] ^ 0x01);
        CHECK_FALSE(
            chacha20poly1305_open(key, nonce, kAad, tampered).has_value());
    }
    // The AAD binds: same bytes, different context, refused.
    CHECK_FALSE(
        chacha20poly1305_open(key, nonce, "other-context", sealed)
            .has_value());
    // A truncated input cannot even hold a tag.
    CHECK_FALSE(chacha20poly1305_open(key, nonce, kAad, "short")
                    .has_value());
}

TEST_CASE("sizes at and around the block boundary round-trip") {
    unsigned char key[kChaCha20Poly1305KeyBytes] = {1};
    unsigned char nonce[kChaCha20Poly1305NonceBytes] = {2};
    for (const std::size_t size :
         {std::size_t{0U}, std::size_t{1U}, std::size_t{15U},
          std::size_t{16U}, std::size_t{17U}, std::size_t{63U},
          std::size_t{64U}, std::size_t{65U}, std::size_t{257U}}) {
        std::string plaintext(size, '\0');
        for (std::size_t i = 0U; i < size; ++i)
            plaintext[i] = static_cast<char>(i * 7U + 3U);
        const auto sealed =
            chacha20poly1305_seal(key, nonce, "aad", plaintext);
        const auto opened =
            chacha20poly1305_open(key, nonce, "aad", sealed);
        REQUIRE(opened.has_value());
        CHECK(*opened == plaintext);
    }
}

} // namespace keen_pbr3
