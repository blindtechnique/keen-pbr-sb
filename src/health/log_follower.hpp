#pragma once

// Reading a log that keeps being written to, without reading it twice and
// without reading it all.
//
// nfqws2's --hostlist-auto-debug file was 1.75 MB after a few days on the
// owner's router and grows for as long as the daemon runs. Re-reading it every
// pass would cost the router more than the feature is worth; remembering only
// an offset is wrong the first time the file is rotated or truncated, because
// an offset into a new file points at the middle of a line of somebody else's
// text.
//
// So the position carries a fingerprint of the beginning of the file as well as
// an offset, and the decision of where to read from is a rule of its own -
// separate from any filesystem, so it can be tested rather than observed.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct LogPosition {
    // Where the last pass stopped.
    std::uint64_t offset{0};
    // The first bytes of the file as they were then. A rotated file almost
    // always begins differently; a file that begins the same way and is at
    // least as long as before is the same file, still growing.
    std::string fingerprint;
    // Whatever came after the last newline, kept so a line split across two
    // passes is delivered once and whole.
    std::string partial_line;
};

enum class FollowDecision {
    // The file grew and begins as it did: read from the remembered offset.
    resume,
    // Rotated, truncated or replaced: read from the beginning, and drop the
    // partial line, which belonged to a file that no longer exists.
    restart,
    // Nothing has been added.
    nothing_new,
};

// The whole rule, with no file in sight.
//
// `current_fingerprint` must be taken the same way every time - the same number
// of leading bytes - or a file will look replaced whenever the reader changes
// its mind about how much to look at.
FollowDecision decide_follow(const LogPosition& previous,
                             std::uint64_t current_size,
                             const std::string& current_fingerprint) noexcept;

struct FollowedLines {
    std::vector<std::string> lines;
    // Advanced past what was consumed, carrying the new partial line.
    LogPosition position;
    // True when the file had to be re-read from the beginning. Callers that
    // count things should know that what follows is not a continuation.
    bool restarted{false};
    // True when the pass stopped at its byte budget rather than at the end of
    // the file. The next pass continues; nothing is lost, but a caller that
    // expected to be caught up is not.
    bool truncated_by_budget{false};
    // True when a fragment with no newline in it grew past what any real line
    // can be and was thrown away. Without this a single corrupt write - or a
    // binary file handed to us by mistake - would grow the carried fragment
    // pass after pass until the router had no memory left.
    bool dropped_oversize_fragment{false};
};

// Longest fragment carried between passes. A line of this log is a timestamp, a
// host, a profile, a client and a short message; anything past this is not one.
constexpr std::size_t kMaxPartialLine = 8192U;

// Splits a chunk that starts at `position.offset` into complete lines, keeping
// the trailing fragment for next time.
//
// `budget` bounds how much of `chunk` is consumed in one pass, because the
// router this runs on had 134 MiB free: a reader that has been away for a day
// must not turn the whole backlog into strings at once.
FollowedLines split_followed_lines(const LogPosition& position,
                                   const std::string& chunk,
                                   std::size_t budget);

// How many leading bytes make up a fingerprint. Small enough to read cheaply,
// long enough that two different runs of nfqws2 do not share it: the first line
// carries a timestamp.
constexpr std::size_t kLogFingerprintBytes = 256U;

}  // namespace keen_pbr3
