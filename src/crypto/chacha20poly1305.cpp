#include "chacha20poly1305.hpp"

#include <cstring>

namespace keen_pbr3 {

namespace {

// --- ChaCha20 (RFC 8439 §2.3) ---

inline std::uint32_t rotl32(const std::uint32_t value,
                            const unsigned bits) {
    return (value << bits) | (value >> (32U - bits));
}

inline void quarter_round(std::uint32_t& a, std::uint32_t& b,
                          std::uint32_t& c, std::uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16U);
    c += d; b ^= c; b = rotl32(b, 12U);
    a += b; d ^= a; d = rotl32(d, 8U);
    c += d; b ^= c; b = rotl32(b, 7U);
}

inline std::uint32_t load_le32(const unsigned char* bytes) {
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

inline void store_le32(unsigned char* bytes, const std::uint32_t value) {
    bytes[0] = static_cast<unsigned char>(value);
    bytes[1] = static_cast<unsigned char>(value >> 8U);
    bytes[2] = static_cast<unsigned char>(value >> 16U);
    bytes[3] = static_cast<unsigned char>(value >> 24U);
}

void chacha20_block(
    const unsigned char (&key)[kChaCha20Poly1305KeyBytes],
    const std::uint32_t counter,
    const unsigned char (&nonce)[kChaCha20Poly1305NonceBytes],
    unsigned char (&out)[64]) {
    std::uint32_t state[16];
    state[0] = 0x61707865U;
    state[1] = 0x3320646eU;
    state[2] = 0x79622d32U;
    state[3] = 0x6b206574U;
    for (unsigned i = 0U; i < 8U; ++i)
        state[4U + i] = load_le32(key + i * 4U);
    state[12] = counter;
    for (unsigned i = 0U; i < 3U; ++i)
        state[13U + i] = load_le32(nonce + i * 4U);

    std::uint32_t working[16];
    std::memcpy(working, state, sizeof(state));
    for (unsigned round = 0U; round < 10U; ++round) {
        quarter_round(working[0], working[4], working[8], working[12]);
        quarter_round(working[1], working[5], working[9], working[13]);
        quarter_round(working[2], working[6], working[10], working[14]);
        quarter_round(working[3], working[7], working[11], working[15]);
        quarter_round(working[0], working[5], working[10], working[15]);
        quarter_round(working[1], working[6], working[11], working[12]);
        quarter_round(working[2], working[7], working[8], working[13]);
        quarter_round(working[3], working[4], working[9], working[14]);
    }
    for (unsigned i = 0U; i < 16U; ++i)
        store_le32(out + i * 4U, working[i] + state[i]);
}

std::string chacha20_xor(
    const unsigned char (&key)[kChaCha20Poly1305KeyBytes],
    std::uint32_t counter,
    const unsigned char (&nonce)[kChaCha20Poly1305NonceBytes],
    const std::string_view input) {
    std::string output(input.size(), '\0');
    unsigned char block[64];
    std::size_t offset = 0U;
    while (offset < input.size()) {
        chacha20_block(key, counter++, nonce, block);
        const std::size_t chunk =
            input.size() - offset < 64U ? input.size() - offset : 64U;
        for (std::size_t i = 0U; i < chunk; ++i) {
            output[offset + i] = static_cast<char>(
                static_cast<unsigned char>(input[offset + i]) ^
                block[i]);
        }
        offset += chunk;
    }
    return output;
}

// --- Poly1305 (RFC 8439 §2.5), 26-bit limbs ---
//
// The prime 2^130-5 does not fit any machine integer, __int128 included - a
// first draft here tried and would have been undefined behaviour before it
// was wrong. Five 26-bit limbs are the classical representation: products of
// 26-bit limbs stay far inside 64 bits, and the fold uses 2^130 ≡ 5.

struct Poly1305 {
    std::uint32_t r[5];
    std::uint32_t h[5]{};
    std::uint32_t pad[4];

    explicit Poly1305(const unsigned char (&otk)[32]) {
        // r, clamped per the RFC, split into 26-bit limbs.
        const std::uint32_t t0 = load_le32(otk + 0) & 0x0fffffffU;
        const std::uint32_t t1 = load_le32(otk + 4) & 0x0ffffffcU;
        const std::uint32_t t2 = load_le32(otk + 8) & 0x0ffffffcU;
        const std::uint32_t t3 = load_le32(otk + 12) & 0x0ffffffcU;
        r[0] = t0 & 0x3ffffffU;
        r[1] = ((t0 >> 26U) | (t1 << 6U)) & 0x3ffffffU;
        r[2] = ((t1 >> 20U) | (t2 << 12U)) & 0x3ffffffU;
        r[3] = ((t2 >> 14U) | (t3 << 18U)) & 0x3ffffffU;
        r[4] = t3 >> 8U;
        for (unsigned i = 0U; i < 4U; ++i)
            pad[i] = load_le32(otk + 16U + i * 4U);
    }

    void block(const unsigned char* bytes, const std::size_t size) {
        unsigned char buffer[17] = {};
        std::memcpy(buffer, bytes, size);
        buffer[size] = 1U;  // the RFC's high bit, byte-positioned

        const std::uint32_t t0 = load_le32(buffer + 0);
        const std::uint32_t t1 = load_le32(buffer + 4);
        const std::uint32_t t2 = load_le32(buffer + 8);
        const std::uint32_t t3 = load_le32(buffer + 12);
        h[0] += t0 & 0x3ffffffU;
        h[1] += ((t0 >> 26U) | (t1 << 6U)) & 0x3ffffffU;
        h[2] += ((t1 >> 20U) | (t2 << 12U)) & 0x3ffffffU;
        h[3] += ((t2 >> 14U) | (t3 << 18U)) & 0x3ffffffU;
        h[4] += (t3 >> 8U) |
                (static_cast<std::uint32_t>(buffer[16]) << 24U);

        // h *= r (mod 2^130-5): limb products fit 64 bits; the i>=5 terms
        // wrap through 2^130 ≡ 5.
        std::uint64_t d[5];
        for (unsigned i = 0U; i < 5U; ++i) {
            d[i] = 0U;
            for (unsigned j = 0U; j < 5U; ++j) {
                const std::uint64_t product =
                    static_cast<std::uint64_t>(h[j]) *
                    (j <= i ? r[i - j] : 5U * r[i + 5U - j]);
                d[i] += product;
            }
        }
        std::uint64_t carry = 0U;
        for (unsigned i = 0U; i < 5U; ++i) {
            d[i] += carry;
            carry = d[i] >> 26U;
            h[i] = static_cast<std::uint32_t>(d[i]) & 0x3ffffffU;
        }
        h[0] += static_cast<std::uint32_t>(carry) * 5U;
        h[1] += h[0] >> 26U;
        h[0] &= 0x3ffffffU;
    }

    // The MAC is over one continuous stream, so partial input is buffered
    // until a full 16-byte block exists. The first draft put the padding bit
    // after every update() call instead of after every block of the stream -
    // the standalone RFC vector passed by the accident of its length
    // splitting into aligned chunks, and the AEAD vector caught it: a 12-byte
    // AAD got its bit at byte 12 where the RFC's padded stream has it at 16.
    unsigned char pending[16];
    std::size_t pending_size{0U};

    void update(const unsigned char* bytes, std::size_t size) {
        while (size > 0U) {
            const std::size_t take =
                size < 16U - pending_size ? size : 16U - pending_size;
            std::memcpy(pending + pending_size, bytes, take);
            pending_size += take;
            bytes += take;
            size -= take;
            if (pending_size == 16U) {
                block(pending, 16U);
                pending_size = 0U;
            }
        }
    }

    void tag(unsigned char (&out)[kChaCha20Poly1305TagBytes]) {
        if (pending_size > 0U) {
            block(pending, pending_size);
            pending_size = 0U;
        }
        // Full carry, then the constant-time select of h vs h - p.
        std::uint32_t carry = h[1] >> 26U;
        h[1] &= 0x3ffffffU;
        for (unsigned i = 2U; i < 5U; ++i) {
            h[i] += carry;
            carry = h[i] >> 26U;
            h[i] &= 0x3ffffffU;
        }
        h[0] += carry * 5U;
        carry = h[0] >> 26U;
        h[0] &= 0x3ffffffU;
        h[1] += carry;

        std::uint32_t g[5];
        std::uint32_t borrow = 5U;
        for (unsigned i = 0U; i < 5U; ++i) {
            g[i] = h[i] + borrow;
            borrow = g[i] >> 26U;
            g[i] &= 0x3ffffffU;
        }
        // borrow==1 means h+5 overflowed 2^130, i.e. h >= p: take g.
        const std::uint32_t mask = borrow == 0U ? 0U : 0xffffffffU;
        for (unsigned i = 0U; i < 5U; ++i)
            h[i] = (h[i] & ~mask) | (g[i] & mask);

        // Serialize to four 32-bit words and add the pad with carry.
        std::uint64_t words[4];
        words[0] = (static_cast<std::uint64_t>(h[0]) |
                    (static_cast<std::uint64_t>(h[1]) << 26U)) &
                   0xffffffffU;
        words[1] = ((static_cast<std::uint64_t>(h[1]) >> 6U) |
                    (static_cast<std::uint64_t>(h[2]) << 20U)) &
                   0xffffffffU;
        words[2] = ((static_cast<std::uint64_t>(h[2]) >> 12U) |
                    (static_cast<std::uint64_t>(h[3]) << 14U)) &
                   0xffffffffU;
        words[3] = ((static_cast<std::uint64_t>(h[3]) >> 18U) |
                    (static_cast<std::uint64_t>(h[4]) << 8U)) &
                   0xffffffffU;
        std::uint64_t sum_carry = 0U;
        for (unsigned i = 0U; i < 4U; ++i) {
            const std::uint64_t sum = words[i] + pad[i] + sum_carry;
            store_le32(out + i * 4U,
                       static_cast<std::uint32_t>(sum));
            sum_carry = sum >> 32U;
        }
    }
};

void poly1305_pad16(Poly1305& mac, const std::size_t size) {
    static const unsigned char zeros[16] = {};
    if (size % 16U != 0U) mac.update(zeros, 16U - size % 16U);
}

void poly1305_le64(Poly1305& mac, const std::uint64_t value) {
    unsigned char bytes[8];
    for (unsigned i = 0U; i < 8U; ++i)
        bytes[i] = static_cast<unsigned char>(value >> (8U * i));
    mac.update(bytes, 8U);
}

void aead_tag(const unsigned char (&key)[kChaCha20Poly1305KeyBytes],
              const unsigned char (&nonce)[kChaCha20Poly1305NonceBytes],
              const std::string_view aad,
              const std::string_view ciphertext,
              unsigned char (&tag)[kChaCha20Poly1305TagBytes]) {
    unsigned char block[64];
    chacha20_block(key, 0U, nonce, block);
    unsigned char otk[32];
    std::memcpy(otk, block, 32U);

    Poly1305 mac(otk);
    mac.update(reinterpret_cast<const unsigned char*>(aad.data()),
               aad.size());
    poly1305_pad16(mac, aad.size());
    mac.update(
        reinterpret_cast<const unsigned char*>(ciphertext.data()),
        ciphertext.size());
    poly1305_pad16(mac, ciphertext.size());
    poly1305_le64(mac, aad.size());
    poly1305_le64(mac, ciphertext.size());
    mac.tag(tag);
}

} // namespace

std::string chacha20poly1305_seal(
    const unsigned char (&key)[kChaCha20Poly1305KeyBytes],
    const unsigned char (&nonce)[kChaCha20Poly1305NonceBytes],
    const std::string_view aad,
    const std::string_view plaintext) {
    auto sealed = chacha20_xor(key, 1U, nonce, plaintext);
    unsigned char tag[kChaCha20Poly1305TagBytes];
    aead_tag(key, nonce, aad, sealed, tag);
    sealed.append(reinterpret_cast<const char*>(tag), sizeof(tag));
    return sealed;
}

std::optional<std::string> chacha20poly1305_open(
    const unsigned char (&key)[kChaCha20Poly1305KeyBytes],
    const unsigned char (&nonce)[kChaCha20Poly1305NonceBytes],
    const std::string_view aad,
    const std::string_view sealed) {
    if (sealed.size() < kChaCha20Poly1305TagBytes) return std::nullopt;
    const auto ciphertext =
        sealed.substr(0U, sealed.size() - kChaCha20Poly1305TagBytes);
    unsigned char expected[kChaCha20Poly1305TagBytes];
    aead_tag(key, nonce, aad, ciphertext, expected);

    const auto* supplied = reinterpret_cast<const unsigned char*>(
        sealed.data() + ciphertext.size());
    unsigned char difference = 0U;
    for (unsigned i = 0U; i < kChaCha20Poly1305TagBytes; ++i)
        difference = static_cast<unsigned char>(
            difference | (expected[i] ^ supplied[i]));
    if (difference != 0U) return std::nullopt;
    return chacha20_xor(key, 1U, nonce, ciphertext);
}

} // namespace keen_pbr3
