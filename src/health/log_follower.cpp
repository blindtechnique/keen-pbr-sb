#include "log_follower.hpp"

#include <algorithm>

namespace keen_pbr3 {

FollowDecision decide_follow(const LogPosition& previous,
                             const std::uint64_t current_size,
                             const std::string& current_fingerprint) noexcept {
    // A first pass has nothing to compare against and everything to read.
    if (previous.fingerprint.empty() && previous.offset == 0U) {
        return current_size == 0U ? FollowDecision::nothing_new
                                  : FollowDecision::restart;
    }

    // The file no longer begins the way it did. Rotation renames the old file
    // and starts a new one; whatever the offset used to mean, it does not mean
    // it here.
    if (previous.fingerprint != current_fingerprint) return FollowDecision::restart;

    // Shorter than where we stopped: truncated in place, which some log
    // rotators do rather than renaming.
    if (current_size < previous.offset) return FollowDecision::restart;

    if (current_size == previous.offset) return FollowDecision::nothing_new;
    return FollowDecision::resume;
}

FollowedLines split_followed_lines(const LogPosition& position,
                                   const std::string& chunk,
                                   const std::size_t budget) {
    FollowedLines result;
    result.position.fingerprint = position.fingerprint;

    const auto consumed = std::min(chunk.size(), budget);
    result.truncated_by_budget = consumed < chunk.size();

    // What was left over last time belongs in front of whatever arrived now.
    std::string pending = position.partial_line;
    pending.append(chunk, 0U, consumed);

    std::size_t start = 0U;
    while (true) {
        const auto newline = pending.find('\n', start);
        if (newline == std::string::npos) break;
        auto line = pending.substr(start, newline - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) result.lines.push_back(std::move(line));
        start = newline + 1U;
    }

    auto remainder = pending.substr(start);
    if (remainder.size() > kMaxPartialLine) {
        // Nothing in this log is this long. Carrying it would mean carrying it
        // again next pass, and the pass after that.
        remainder.clear();
        result.dropped_oversize_fragment = true;
    }
    result.position.partial_line = std::move(remainder);
    result.position.offset = position.offset + consumed;
    return result;
}

}  // namespace keen_pbr3
