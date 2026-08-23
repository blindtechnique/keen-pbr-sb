#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// One stanza of an opkg `Packages` index - the part of it that identifies an
// exact IPK. The feed is the only place that publishes a component's bytes
// with a digest, so this is what "exact" means for an external component:
// the file the feed names, with the size and SHA-256 the feed promises.
struct FeedPackageEntry {
    std::string package;
    std::string version;
    std::string filename;
    std::uint64_t size{0};
    std::string sha256;

    // Complete enough to fetch and verify. A stanza missing any of these
    // identifies nothing and is skipped rather than half-trusted.
    bool identifies_ipk() const noexcept {
        return !package.empty() && !version.empty() &&
               !filename.empty() && size != 0 && sha256.size() == 64;
    }
};

// Parses the text of an opkg Packages index (already decompressed). Stanzas
// are separated by blank lines; only the identifying fields are read, and
// anything unreadable is dropped rather than guessed at. Never throws.
std::vector<FeedPackageEntry> parse_opkg_packages_index(
    const std::string& text);

// Inflates a gzip stream into a string, refusing to grow past `max_bytes`.
// Throws std::runtime_error on a corrupt stream or when the limit is hit:
// a feed index that does not fit the budget is not one to act on.
std::string gunzip_to_string(const std::string& compressed,
                             std::size_t max_bytes);

// The entry for exactly this package and version, if the feed still lists
// it. Feeds such as nfqws2-keenetic publish only their latest version, so
// the answer for an installed version is "yes" for exactly as long as no
// newer release has replaced it - which is why retention must happen at
// install time and not when a rollback is wanted.
std::optional<FeedPackageEntry> find_feed_entry(
    const std::vector<FeedPackageEntry>& entries,
    const std::string& package,
    const std::string& version);

// What the retention store holds for one slot.
struct RetainedIpk {
    std::string version;
    std::string sha256;
    std::uint64_t size{0};
    std::string filename;
};

enum class IpkRetentionAction {
    // The store already holds this exact version with this digest.
    already_retained,
    // The feed lists the installed version: fetch it now and keep it.
    retain_now,
    // The feed no longer lists the installed version. Its exact bytes cannot
    // be obtained any more; whatever the store holds stays as is.
    unavailable,
};

// Decides whether the installed version's IPK must be fetched for retention.
// Pure: the feed index and the store manifest are inputs, not files.
IpkRetentionAction decide_ipk_retention(
    const std::string& installed_version,
    const std::optional<RetainedIpk>& retained_current,
    const std::optional<FeedPackageEntry>& feed_entry);

// True when `candidate` sorts after `installed` by its leading numeric
// components (up to three, "1.2.4" style). Anything unparseable compares as
// zero, so a malformed version is never "newer" than a real one.
bool feed_version_newer(const std::string& candidate,
                        const std::string& installed) noexcept;

} // namespace keen_pbr3
