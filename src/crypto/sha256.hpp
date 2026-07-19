#pragma once

// Small self-contained SHA-256. Only used to answer the Keenetic web
// authentication challenge, so a full crypto dependency is not worth pulling in.

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace keen_pbr3 {

class Sha256 {
public:
    Sha256() { reset(); }

    void update(const void* data, size_t length) {
        const auto* bytes = static_cast<const uint8_t*>(data);
        for (size_t index = 0; index < length; ++index) {
            buffer_[buffer_length_++] = bytes[index];
            if (buffer_length_ == 64) {
                transform(buffer_.data());
                bit_length_ += 512;
                buffer_length_ = 0;
            }
        }
    }

    void update(const std::string& text) { update(text.data(), text.size()); }

    std::string hex_digest() {
        std::array<uint8_t, 32> digest{};
        finish(digest.data());

        static constexpr char kHex[] = "0123456789abcdef";
        std::string output;
        output.reserve(64);
        for (const uint8_t byte : digest) {
            output.push_back(kHex[byte >> 4]);
            output.push_back(kHex[byte & 0x0F]);
        }
        return output;
    }

    static std::string hex(const std::string& text) {
        Sha256 hasher;
        hasher.update(text);
        return hasher.hex_digest();
    }

private:
    void reset() {
        buffer_length_ = 0;
        bit_length_ = 0;
        state_ = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    }

    static uint32_t rotr(uint32_t value, uint32_t bits) {
        return (value >> bits) | (value << (32 - bits));
    }

    void transform(const uint8_t* chunk) {
        static constexpr uint32_t kRoundConstants[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
            0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

        uint32_t words[64];
        for (int index = 0; index < 16; ++index) {
            words[index] = (static_cast<uint32_t>(chunk[index * 4]) << 24) |
                           (static_cast<uint32_t>(chunk[index * 4 + 1]) << 16) |
                           (static_cast<uint32_t>(chunk[index * 4 + 2]) << 8) |
                           static_cast<uint32_t>(chunk[index * 4 + 3]);
        }
        for (int index = 16; index < 64; ++index) {
            const uint32_t s0 = rotr(words[index - 15], 7) ^
                                rotr(words[index - 15], 18) ^ (words[index - 15] >> 3);
            const uint32_t s1 = rotr(words[index - 2], 17) ^
                                rotr(words[index - 2], 19) ^ (words[index - 2] >> 10);
            words[index] = words[index - 16] + s0 + words[index - 7] + s1;
        }

        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

        for (int index = 0; index < 64; ++index) {
            const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const uint32_t choose = (e & f) ^ (~e & g);
            const uint32_t temp1 = h + s1 + choose + kRoundConstants[index] + words[index];
            const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temp2 = s0 + majority;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    void finish(uint8_t* digest) {
        const uint64_t total_bits = bit_length_ + static_cast<uint64_t>(buffer_length_) * 8;
        size_t index = buffer_length_;

        buffer_[index++] = 0x80;
        if (index > 56) {
            while (index < 64) buffer_[index++] = 0;
            transform(buffer_.data());
            index = 0;
        }
        while (index < 56) buffer_[index++] = 0;

        for (int shift = 7; shift >= 0; --shift) {
            buffer_[index++] = static_cast<uint8_t>(total_bits >> (shift * 8));
        }
        transform(buffer_.data());

        for (int word = 0; word < 8; ++word) {
            for (int byte = 0; byte < 4; ++byte) {
                digest[word * 4 + byte] =
                    static_cast<uint8_t>(state_[word] >> ((3 - byte) * 8));
            }
        }
    }

    std::array<uint32_t, 8> state_{};
    std::array<uint8_t, 64> buffer_{};
    size_t buffer_length_{0};
    uint64_t bit_length_{0};
};

} // namespace keen_pbr3
