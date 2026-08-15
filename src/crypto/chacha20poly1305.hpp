#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace keen_pbr3 {

// ChaCha20-Poly1305 AEAD exactly as RFC 8439 specifies it, implemented here
// because the build deliberately links no TLS library and the tree has no
// cipher at all - only digests. Nothing in this file is invented: the
// construction, the constants and the byte orders are the RFC's, and the unit
// tests are the RFC's own vectors, which is the only reason a hand-written
// implementation of a cipher is defensible.
//
// Intended consumer: the native-import secret snapshot, which must hold VPN
// private keys at rest on a removable USB drive. Not intended as a general
// crypto surface; no other module should grow a dependency on this without
// the same justification.

inline constexpr std::size_t kChaCha20Poly1305KeyBytes = 32U;
inline constexpr std::size_t kChaCha20Poly1305NonceBytes = 12U;
inline constexpr std::size_t kChaCha20Poly1305TagBytes = 16U;

// Seal: ciphertext || 16-byte tag. The nonce is the caller's problem and the
// caller's invariant: one key must never see the same nonce twice, which the
// snapshot store satisfies by drawing every nonce from the kernel CSPRNG.
std::string chacha20poly1305_seal(
    const unsigned char (&key)[kChaCha20Poly1305KeyBytes],
    const unsigned char (&nonce)[kChaCha20Poly1305NonceBytes],
    std::string_view aad,
    std::string_view plaintext);

// Open: nullopt on any failure - short input, wrong tag - with no partial
// plaintext ever returned. The tag comparison is constant-time.
std::optional<std::string> chacha20poly1305_open(
    const unsigned char (&key)[kChaCha20Poly1305KeyBytes],
    const unsigned char (&nonce)[kChaCha20Poly1305NonceBytes],
    std::string_view aad,
    std::string_view sealed);

} // namespace keen_pbr3
