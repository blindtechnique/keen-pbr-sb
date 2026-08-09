#pragma once

#include "../config/config.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Resolves an input path used by the candidate.  Returning nullopt means that
// the path is unavailable.  Returning another path lets the dry-run use a
// read-only packaged asset before it is installed into the live nfqws tree.
using NfqwsPathResolver =
    std::function<std::optional<std::string>(const std::string&)>;

// Parses (but never sources) the Keenetic nfqws2 configuration and validates
// the structural invariants which can be checked without invoking nfqws2.
// The parser follows shell assignment quoting closely enough for the shipped
// format: variable references expand in unquoted and double-quoted values,
// while single-quoted references remain literal.
std::vector<ConfigValidationIssue> validate_nfqws_candidate(
    const std::string& content,
    const NfqwsPathResolver& resolve_path = {});

// Reproduces nfqws2-keenetic's _startup_args profile order for the engine's
// --dry-run mode.  Runtime-only flags are included when they are present in the
// candidate, and input paths are rewritten through resolve_path.
std::vector<std::string> build_nfqws_dry_run_args(
    const std::string& content,
    int fallback_queue_number = 300,
    const NfqwsPathResolver& resolve_path = {});

struct NfqwsBinaryIdentity {
    std::uint64_t device{0};
    std::uint64_t inode{0};
    std::uint64_t size{0};
    std::int64_t mtime_seconds{0};
    std::int64_t mtime_nanoseconds{0};
    std::int64_t ctime_seconds{0};
    std::int64_t ctime_nanoseconds{0};

    bool operator==(const NfqwsBinaryIdentity& other) const noexcept;
    bool operator!=(const NfqwsBinaryIdentity& other) const noexcept {
        return !(*this == other);
    }
};

enum class NfqwsDryRunCapability {
    supported,
    unsupported,
    unavailable,
};

using NfqwsBinaryIdentityReader =
    std::function<std::optional<NfqwsBinaryIdentity>(const std::string&)>;
using NfqwsHelpProbe =
    std::function<std::optional<std::string>(const std::string&)>;

// Capability results are cached only for an exact binary identity.  Replacing
// nfqws2 in-place or through opkg therefore forces a new help probe instead of
// inheriting a stale process-lifetime decision.
class NfqwsDryRunCapabilityCache {
public:
    NfqwsDryRunCapability detect(
        const std::string& binary,
        const NfqwsBinaryIdentityReader& read_identity,
        const NfqwsHelpProbe& probe_help);

private:
    std::mutex mutex_;
    std::optional<NfqwsBinaryIdentity> identity_;
    std::string binary_;
    NfqwsDryRunCapability capability_{NfqwsDryRunCapability::unavailable};
};

} // namespace keen_pbr3
