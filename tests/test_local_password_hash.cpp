#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/local_password_hash.hpp"

#include <string>

namespace keen_pbr3 {

namespace {

using Verdict = LocalPasswordVerdict;

// 32 hex characters: kLocalPasswordSaltBytes worth, the minimum accepted.
const std::string kSalt = "0123456789abcdef0123456789abcdef";
const std::string kOtherSalt = "fedcba9876543210fedcba9876543210";

} // namespace

TEST_CASE("the derivation is PBKDF2-HMAC-SHA256 and not merely reproducible") {
    // Published vectors, because a homemade KDF that is subtly not the one it
    // claims to be still round-trips against itself perfectly. These are the
    // SHA-256 vectors from RFC 7914 section 11.
    CHECK(local_password_derive_hex("password", "salt", 1U) ==
          "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    CHECK(local_password_derive_hex("password", "salt", 2U) ==
          "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    CHECK(local_password_derive_hex("password", "salt", 4096U) ==
          "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
}

TEST_CASE("a password longer than one HMAC block still derives correctly") {
    // Exercises the key-shortening branch of HMAC, which is the one place a
    // hand-written implementation silently diverges.
    const std::string long_password(100U, 'p');
    const std::string derived =
        local_password_derive_hex(long_password, "salt", 16U);
    CHECK(derived.size() == 64U);
    CHECK(derived != local_password_derive_hex(std::string(99U, 'p'),
                                               "salt", 16U));
}

TEST_CASE("a stored credential is not the password") {
    const std::string stored =
        encode_local_password_hash("hunter2", kSalt, 1000U);
    REQUIRE_FALSE(stored.empty());
    CHECK(stored.find("hunter2") == std::string::npos);
    CHECK(local_password_hash_encoded(stored));
    CHECK(verify_local_password(stored, "hunter2") == Verdict::matched);
    CHECK(verify_local_password(stored, "hunter3") == Verdict::mismatched);
    CHECK(verify_local_password(stored, "") == Verdict::mismatched);
}

TEST_CASE("two installs with the same password do not share a stored value") {
    const std::string first =
        encode_local_password_hash("same", kSalt, 1000U);
    const std::string second =
        encode_local_password_hash("same", kOtherSalt, 1000U);
    REQUIRE_FALSE(first.empty());
    REQUIRE_FALSE(second.empty());
    CHECK(first != second);
    CHECK(verify_local_password(first, "same") == Verdict::matched);
    CHECK(verify_local_password(second, "same") == Verdict::matched);
}

TEST_CASE("the iteration count is part of the stored value, not the code") {
    // A count raised later must not invalidate what is already stored.
    const std::string cheap =
        encode_local_password_hash("hunter2", kSalt, 10U);
    const std::string dear =
        encode_local_password_hash("hunter2", kSalt, 5000U);
    CHECK(cheap != dear);
    CHECK(verify_local_password(cheap, "hunter2") == Verdict::matched);
    CHECK(verify_local_password(dear, "hunter2") == Verdict::matched);
    CHECK(cheap.find("$10$") != std::string::npos);
    CHECK(dear.find("$5000$") != std::string::npos);
}

TEST_CASE("a password from before hashing existed still opens the door") {
    // Refusing it would lock the operator out of their own router. It is
    // accepted and reported as what it is, so the state can be surfaced
    // instead of silently carried.
    CHECK(verify_local_password("hunter2", "hunter2") ==
          Verdict::matched_legacy_plaintext);
    CHECK(verify_local_password("hunter2", "hunter3") ==
          Verdict::mismatched_legacy_plaintext);
    CHECK_FALSE(local_password_hash_encoded("hunter2"));
}

TEST_CASE("a damaged derived key never falls back to a plaintext comparison") {
    // The defect this exists to prevent: a truncated or corrupted hash being
    // compared as though it were a password, turning a stored credential into
    // one whose shape an attacker already knows.
    const std::string valid =
        encode_local_password_hash("hunter2", kSalt, 1000U);
    REQUIRE_FALSE(valid.empty());

    const std::string damaged[] = {
        "kpbr-pbkdf2-sha256-v1",
        "kpbr-pbkdf2-sha256-v1$",
        "kpbr-pbkdf2-sha256-v1$1000$" + kSalt,
        // Iteration count of zero: no derivation happened.
        "kpbr-pbkdf2-sha256-v1$0$" + kSalt + "$" + std::string(64U, 'a'),
        "kpbr-pbkdf2-sha256-v1$abc$" + kSalt + "$" + std::string(64U, 'a'),
        // Salt too short to be one.
        "kpbr-pbkdf2-sha256-v1$1000$0123$" + std::string(64U, 'a'),
        // Digest that is not a SHA-256 output.
        "kpbr-pbkdf2-sha256-v1$1000$" + kSalt + "$" + std::string(63U, 'a'),
        "kpbr-pbkdf2-sha256-v1$1000$" + kSalt + "$" + std::string(64U, 'A'),
        // A field too many.
        valid + "$extra",
        // Truncated body of an otherwise well-formed value.
        valid.substr(0U, valid.size() - 1U),
    };
    for (const auto& stored : damaged) {
        CHECK_FALSE(local_password_hash_encoded(stored));
        CHECK(verify_local_password(stored, "hunter2") == Verdict::unusable);
        // ...and above all, offering the stored text back as the password does
        // not open it either.
        CHECK(verify_local_password(stored, stored) == Verdict::unusable);
    }
}

TEST_CASE("a salt that is not one is refused rather than used") {
    for (const std::string& salt :
         {std::string{}, std::string("0123456789abcdef"),
          std::string("0123456789ABCDEF0123456789ABCDEF"),
          std::string("0123456789abcdef0123456789abcdeg"),
          std::string("0123456789abcdef0123456789abcde")}) {
        CHECK(encode_local_password_hash("hunter2", salt, 1000U).empty());
    }
    CHECK(encode_local_password_hash("hunter2", kSalt, 0U).empty());
    // The accepted minimum is exactly kLocalPasswordSaltBytes.
    CHECK(kSalt.size() == kLocalPasswordSaltBytes * 2U);
    CHECK_FALSE(encode_local_password_hash("hunter2", kSalt, 1U).empty());
}

TEST_CASE("the production iteration count is stored with what it derived") {
    const std::string stored = encode_local_password_hash(
        "hunter2", kSalt, kLocalPasswordHashIterations);
    REQUIRE_FALSE(stored.empty());
    CHECK(stored.find(
              "$" + std::to_string(kLocalPasswordHashIterations) + "$") !=
          std::string::npos);
    CHECK(verify_local_password(stored, "hunter2") == Verdict::matched);
}

TEST_CASE("every verdict has a name") {
    for (const auto verdict :
         {Verdict::matched, Verdict::mismatched,
          Verdict::matched_legacy_plaintext,
          Verdict::mismatched_legacy_plaintext, Verdict::unusable}) {
        CHECK(std::string(local_password_verdict_name(verdict)).size() > 0U);
    }
}

} // namespace keen_pbr3

#endif // WITH_API
