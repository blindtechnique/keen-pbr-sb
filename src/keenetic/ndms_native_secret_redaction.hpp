#pragma once

#include <nlohmann/json.hpp>

#include <string>

namespace keen_pbr3 {

// Turns a raw RCI document into one that may be hashed, logged and diffed.
//
// Measured on NC-1812: show/rc/interface/WireguardN returns every peer's
// preshared-key, on all five occupied slots. The evidence builder refuses such
// a document outright - correctly, because a revision digest and any
// diagnostic dump derived from it would otherwise carry peer secrets. That
// refusal leaves the builder unusable until something produces a secret-free
// document, and this is that something.
//
// Dropping the secret would be simpler and wrong: a rotated preshared key
// would then be invisible to the revision, so a compare-and-swap would call
// a changed interface unchanged. Instead each secret value is replaced by a
// digest of itself, bound to the interface and to its own path in the
// document. The revision still moves when the secret moves; the secret itself
// never reaches the digest input, a log, or a diff.
//
// The binding matters in both directions: without the path, moving a secret
// from one field to another would leave the document byte-identical; without
// the interface name, the same preshared key on two interfaces would produce
// equal markers and quietly reveal that they share it.

// The only string a secret-naming key is allowed to hold downstream.
extern const char kNdmsSecretRedactionPrefix[];

// True for a key whose value could name secret material. Deliberately a
// substring match: an unknown future key must be refused, not missed. Shared
// with the evidence builder so the producer and the checker cannot drift.
bool ndms_key_could_name_a_secret(const std::string& key);

// True only for the exact marker shape: the prefix followed by 64 lowercase
// hex digits. Anything else under a secret-naming key is still refused.
bool is_ndms_secret_redaction_marker(const std::string& value);

// Replaces every value under a secret-naming key with its marker, recursively,
// preserving the rest of the document byte for byte. Booleans, numbers and
// nulls are left alone - they cannot carry material, and the measured
// documents contain one such key (security-level.private) that is an access
// level, not a secret.
nlohmann::json redact_ndms_secret_material(const nlohmann::json& document,
                                           const std::string& interface_name);

} // namespace keen_pbr3
