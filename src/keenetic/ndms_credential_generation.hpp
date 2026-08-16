#pragma once

#include <cstdint>
#include <string>

namespace keen_pbr3 {

// Turns a read of NDMS `show/rc/user` into a credential generation, so an
// external change to the router password can revoke the sessions it issued.
//
// Roadmap item 5 asks for a *measured* authority for that revocation. Measured
// on NC-1812 (5.1.1) on 2026-08-16: `show/rc/user` answers from loopback with
// a 1405-byte JSON document carrying per-user password material, and its
// digest was byte-identical across reads 20 s apart on a router carrying live
// traffic. So the document is a revision of the credential state and nothing
// else - it does not drift on its own.
//
// The document itself is a secret: it contains the admin's password hashes.
// It is digested and dropped; neither the document nor the digest is logged.
// A digest is a fingerprint of the credential state, and there is no reason to
// emit it anywhere.
//
// Validation is positive - the document must prove it is a user document -
// rather than negative. Measured on the same firmware: `show/rc/...` answers
// an absent path with HTTP 404 and an *empty* body, unlike the ASC endpoint
// elsewhere in this codebase which answers with a JSON error envelope. Two
// endpoint families, two shapes; a rule written against either one would be
// wrong about the other. Requiring the document to look like what it claims to
// be is wrong about neither.

enum class NdmsCredentialGenerationVerdict : std::uint8_t {
    // The document proved itself and yielded a digest.
    known,
    // No usable document: the read failed, the body was empty, it was not
    // JSON, it was not shaped like a user document, or it carried no password
    // material at all.
    //
    // That last case is deliberately not `known`. A document with no password
    // material cannot witness a password change, so digesting it would produce
    // a generation that stays stable across exactly the event this exists to
    // catch - the silent inertness that is worse than an absent feature,
    // because the absent feature does not claim to be working.
    unreadable,
};

struct NdmsCredentialGeneration {
    NdmsCredentialGenerationVerdict verdict{
        NdmsCredentialGenerationVerdict::unreadable};
    // Lowercase SHA-256 hex of the exact document bytes. Empty unless known.
    std::string digest;
};

enum class NdmsCredentialChange : std::uint8_t {
    unchanged,
    changed,
    // Cannot tell. A failed read is not evidence that nothing changed, and it
    // is not evidence that something did. The caller must neither revoke - a
    // firmware hiccup logging every operator out is a self-inflicted outage -
    // nor treat the absent reading as the new baseline, or a change that
    // happened during the outage would be swallowed when the read recovers.
    unknown,
};

const char* ndms_credential_generation_verdict_name(
    NdmsCredentialGenerationVerdict verdict) noexcept;
const char* ndms_credential_change_name(
    NdmsCredentialChange change) noexcept;

// `document` is the exact response body; an empty string means the read
// failed, which is a legitimate input and not an error.
NdmsCredentialGeneration ndms_credential_generation(
    const std::string& document);

// The caller's contract, in two lines and no more:
//   revoke the session cohort iff this returns `changed`;
//   replace the stored generation iff `current.verdict == known`.
NdmsCredentialChange ndms_credential_change(
    const NdmsCredentialGeneration& previous,
    const NdmsCredentialGeneration& current) noexcept;

} // namespace keen_pbr3
