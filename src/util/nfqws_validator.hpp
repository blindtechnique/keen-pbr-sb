#pragma once

#include "../config/config.hpp"

#include <cstddef>
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

// A canonical port interval used by the PPE hand-off.  `first == last`
// represents one port.  Intervals are sorted, non-overlapping and coalesced,
// so consumers never have to interpret the original shell text.
struct NfqwsPpePortRange {
    std::uint16_t first{0};
    std::uint16_t last{0};

    bool operator==(const NfqwsPpePortRange& other) const noexcept {
        return first == other.first && last == other.last;
    }
    bool operator!=(const NfqwsPpePortRange& other) const noexcept {
        return !(*this == other);
    }
};

// xt_multiport has 15 uint16 slots.  A single port consumes one slot; an
// inclusive range consumes two.  `tcp_chunks` below is packed by this cost,
// not by vector length.
inline constexpr std::size_t kNfqwsPpeMultiportSlotsPerChunk = 15U;
inline constexpr std::size_t kNfqwsPpeMaxTcpChunks = 16U;

// Fail-closed description of the traffic that the *validated* active nfqws
// configuration can process.  The firewall layer may use only an available
// contract; `reason` is intentionally populated for every unavailable result.
//
// QUIC is a boolean rather than a general UDP selector by design.  The only
// UDP PPE contract admitted in v1 is exactly destination port 443 from
// NFQWS_ARGS_QUIC.  NFQWS_ARGS_UDP and custom/WebRTC UDP profiles never widen
// it.
struct NfqwsPpePortContract {
    bool available{false};
    std::string reason;
    int queue_number{300};
    std::vector<NfqwsPpePortRange> tcp_ranges;
    std::vector<std::vector<NfqwsPpePortRange>> tcp_chunks;
    bool quic_udp_443{false};
};

// Parses (but never sources) the Keenetic nfqws2 configuration and validates
// the structural invariants which can be checked without invoking nfqws2.
// The parser follows shell assignment quoting closely enough for the shipped
// format: variable references expand in unquoted and double-quoted values,
// while single-quoted references remain literal.
std::vector<ConfigValidationIssue> validate_nfqws_candidate(
    const std::string& content,
    const NfqwsPathResolver& resolve_path = {});

// Parses and validates once, then derives a bounded, canonical PPE selector
// from the same parsed candidate.  TCP filters from action-bearing active
// profiles must exactly match TCP_PORTS.  Empty, malformed, ambiguous or
// over-complex candidates are returned as unavailable instead of being
// guessed at.
NfqwsPpePortContract extract_nfqws_ppe_port_contract(
    const std::string& content,
    const NfqwsPathResolver& resolve_path = {});

// Derives the same bounded selector from a live /proc/<pid>/cmdline argv.
// This intentionally ignores strategy implementation details but proves the
// queue and traffic selector shape that PPE relies on.  The runtime observer
// compares it with the file-derived contract before publishing availability.
NfqwsPpePortContract extract_nfqws_ppe_port_contract_from_argv(
    const std::vector<std::string>& argv);

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
