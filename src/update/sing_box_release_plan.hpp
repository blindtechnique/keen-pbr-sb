#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Turns a GitHub release document into the two URLs an install needs, and
// decides whether what came back may be installed at all.
//
// This is the half of the install that has to be right rather than merely
// working, so it is pure: given the release JSON, the asset list and the
// checksums text, it answers with a plan or a refusal, and a test can put any
// of those in front of it without a network.
//
// The rule the shell installer does not have: a release without a checksums
// file is REFUSED, not installed unverified. install.sh verifies only
// `if [ -n "$checksums_url" ]`, so a release that publishes no checksums
// installs anyway. That is defensible for a command an operator typed
// themselves; it is not defensible for a button in a browser, which must be
// at least as strict as the manual path and never softer.

enum class SingBoxReleaseVerdict : std::uint8_t {
    // Both URLs found, checksum present and well formed.
    ready,
    // The release document did not parse, or is not the shape GitHub returns.
    release_unreadable,
    // No asset named exactly for this version and architecture.
    archive_missing,
    // The release publishes no checksums file. Refused rather than installed
    // unverified.
    checksums_missing,
    // A checksums file that does not name our archive, or names it with
    // something that is not a SHA-256 digest.
    checksum_unusable,
    // The archive was fetched and does not match the published digest.
    checksum_mismatch,
};

const char* sing_box_release_verdict_name(
    SingBoxReleaseVerdict verdict) noexcept;

struct SingBoxReleasePlan {
    SingBoxReleaseVerdict verdict{
        SingBoxReleaseVerdict::release_unreadable};
    std::string archive_url;
    std::string checksums_url;
    // Exactly the file name the digest must be published for.
    std::string archive_name;
};

// The asset file name for a release, e.g.
// "sing-box-1.13.14-linux-arm64.tar.gz".
std::string sing_box_archive_name(const std::string& version,
                                  const std::string& asset_architecture);

// Reads a GitHub release document. `version` and `asset_architecture` name the
// exact archive; anything else in the release is ignored.
SingBoxReleasePlan plan_sing_box_release(const std::string& release_json,
                                         const std::string& version,
                                         const std::string& asset_architecture);

// The digest published for `archive_name`, as lowercase hex, or empty when the
// file does not name it or names it unusably. The format is one entry per
// line: "<digest>  <name>", with an optional '*' before the name for the
// binary-mode convention sha256sum writes.
std::string published_archive_digest(const std::string& checksums_text,
                                     const std::string& archive_name);

// The final gate before anything is unpacked. `actual_digest` is the SHA-256
// of the bytes that were fetched.
SingBoxReleaseVerdict verify_sing_box_archive(
    const std::string& checksums_text,
    const std::string& archive_name,
    const std::string& actual_digest);

} // namespace keen_pbr3
