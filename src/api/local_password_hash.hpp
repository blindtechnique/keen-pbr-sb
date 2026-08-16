#pragma once

#include <cstdint>
#include <string>

namespace keen_pbr3 {

// Stores the local WebUI password as a derived key instead of as itself.
//
// The local provider is not going away: the owner keeps it as the recovery
// path for when Keenetic or Entware authentication is unreachable, so whatever
// it stores, it stores permanently. Until now it stored the password verbatim
// in /opt/etc/keen-pbr/auth.json and compared it verbatim, which also put a
// copy into every rescue snapshot that captures the managed file set. Mode
// 0600 and root ownership are the only thing between that file and anyone who
// reads it, and the roadmap's own requirement for this item is that the
// password is not kept in storage.
//
// PBKDF2-HMAC-SHA256, not a memory-hard KDF. That is a deliberate trade and
// worth naming: Argon2id would resist a GPU far better, but it means a new
// third-party dependency on a cross-compiled aarch64 target, while SHA-256 is
// already in the tree. What this buys is that the stored value is no longer
// the password. The iteration count is chosen so a login stays well inside the
// time an operator waits, on a router whose CPU is also routing packets, and
// it is recorded in the encoding so it can be raised later without invalidating
// what is already stored.
//
// Encoded form, one line, self-describing:
//
//     kpbr-pbkdf2-sha256-v1$<iterations>$<salt-hex>$<digest-hex>
//
// auth.json carries this representation in a separate `password_format`
// member. That discriminator is required: an existing plaintext password is
// allowed to begin with the encoding marker, and guessing its representation
// from the password bytes would lock that owner out. The low-level verifier
// still reports legacy values for compatibility, but persistence callers must
// select the branch from the explicit format field.

inline constexpr char kLocalPasswordHashFormat[] =
    "kpbr-pbkdf2-sha256-v1";

// Measured, not estimated: on the NC-1812 (ARMv8, three cores available to
// Entware) this costs 475 ms, reproducible to 0.2% across runs while the
// router carried live traffic. 30000 would be 238 ms and 120000 would be
// 948 ms - the last is long enough that an operator reads the login page as
// hung. A login is rate-limited to three failures per 100 s, so the worst an
// attacker can spend of the daemon's CPU on this path is about 1.4%.
inline constexpr std::uint32_t kLocalPasswordHashIterations = 60000U;
// The encoded cost is data read from disk, so it needs a ceiling. 120000 was
// measured at 948 ms on the target router; larger or corrupted values must not
// turn one login attempt into an unbounded CPU stall. Raising the production
// cost later must raise this reviewed ceiling deliberately as well.
inline constexpr std::uint32_t kLocalPasswordHashMaximumIterations = 120000U;
// 16 bytes. Enough that two installs never share a salt, small enough that the
// encoded line stays readable.
inline constexpr std::size_t kLocalPasswordSaltBytes = 16U;

enum class LocalPasswordVerdict : std::uint8_t {
    // Matched a stored derived key.
    matched,
    mismatched,
    // Matched a stored plaintext password predating this module. The caller
    // must treat this as a successful login and as a credential still to be
    // upgraded - it is not an error, but it is not a resting state either.
    matched_legacy_plaintext,
    mismatched_legacy_plaintext,
    // The stored value announces itself as a derived key and then fails to be
    // one: wrong field count, a bad iteration count, malformed hex. Refused
    // rather than fallen back to a plaintext comparison, or a corrupted hash
    // would silently become a password anyone could guess the shape of.
    unusable,
};

const char* local_password_verdict_name(
    LocalPasswordVerdict verdict) noexcept;

// Whether a stored value is in the encoded form. False for a plaintext
// password, and false for a damaged encoding - see `unusable` above.
bool local_password_hash_encoded(const std::string& stored) noexcept;

// PBKDF2-HMAC-SHA256 with dkLen == 32, as lowercase hex. `salt` is used as
// bytes exactly as given. Exposed so the derivation can be checked against the
// published test vectors rather than only against itself: a homemade KDF that
// is subtly not the one it claims to be still round-trips perfectly.
std::string local_password_derive_hex(const std::string& password,
                                      const std::string& salt,
                                      std::uint32_t iterations);

// Derives the stored form. `salt_hex` must be lowercase hex of at least
// kLocalPasswordSaltBytes bytes and `iterations` must be within the reviewed
// cost ceiling; returns an empty string otherwise, which callers must treat as
// a failure to store rather than as a value to write.
std::string encode_local_password_hash(const std::string& password,
                                       const std::string& salt_hex,
                                       std::uint32_t iterations);

// Constant-time in the comparison, and in the plaintext branch too.
LocalPasswordVerdict verify_local_password(const std::string& stored,
                                           const std::string& password);

} // namespace keen_pbr3
