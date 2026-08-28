#include "probe_candidates.hpp"

#include <algorithm>
#include <array>

namespace keen_pbr3 {

namespace {

constexpr const char* kSeparator = " : ";

std::vector<std::string> split_fields(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t start = 0U;
    while (start <= line.size()) {
        const auto position = line.find(kSeparator, start);
        if (position == std::string::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, position - start));
        start = position + 3U;
    }
    return fields;
}

bool looks_like_host(const std::string& value) noexcept {
    if (value.empty() || value.size() > 253U) return false;
    if (value.find(' ') != std::string::npos) return false;
    if (value.find('.') == std::string::npos) return false;
    if (value.front() == '.' || value.back() == '.') return false;
    for (const unsigned char c : value) {
        const bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                             (c >= '0' && c <= '9') || c == '.' || c == '-' ||
                             c == '_';
        if (!allowed) return false;
    }
    return true;
}

bool contains(const std::string& haystack, const char* needle) noexcept {
    return haystack.find(needle) != std::string::npos;
}

NfqwsEvidence classify_message(const std::string& message) noexcept {
    // Order matters: "fail counter reset. website is working." also contains
    // "fail counter", and reading it as a failure would keep a recovered host
    // in the queue forever.
    if (contains(message, "website is working")) return NfqwsEvidence::recovered;
    if (contains(message, "redirect to another domain")) return NfqwsEvidence::redirect;
    if (contains(message, "retrans threshold reached")) {
        return NfqwsEvidence::retransmissions;
    }
    if (contains(message, "udp_in")) return NfqwsEvidence::one_sided_udp;
    if (contains(message, "incoming RST")) return NfqwsEvidence::incoming_reset;
    if (contains(message, "adding to")) return NfqwsEvidence::adopted;
    return NfqwsEvidence::other;
}

int rank_of(const ProbeCandidate& candidate) noexcept {
    if (candidate.dpi_specific) return 3;
    if (candidate.adopted_by_nfqws) return 2;
    return 1;
}

}  // namespace

bool nfqws_evidence_is_failure(const NfqwsEvidence evidence) noexcept {
    switch (evidence) {
        case NfqwsEvidence::redirect:
        case NfqwsEvidence::retransmissions:
        case NfqwsEvidence::one_sided_udp:
        case NfqwsEvidence::incoming_reset:
            return true;
        case NfqwsEvidence::adopted:
        case NfqwsEvidence::recovered:
        case NfqwsEvidence::other:
            break;
    }
    return false;
}

const char* nfqws_evidence_name(const NfqwsEvidence evidence) noexcept {
    switch (evidence) {
        case NfqwsEvidence::redirect:
            return "redirect";
        case NfqwsEvidence::retransmissions:
            return "retransmissions";
        case NfqwsEvidence::one_sided_udp:
            return "one_sided_udp";
        case NfqwsEvidence::incoming_reset:
            return "incoming_reset";
        case NfqwsEvidence::adopted:
            return "adopted";
        case NfqwsEvidence::recovered:
            return "recovered";
        case NfqwsEvidence::other:
            break;
    }
    return "other";
}

bool parse_nfqws_log_line(const std::string& line, NfqwsLogEvent& event) noexcept {
    const auto fields = split_fields(line);
    // timestamp, host, profile, client, proto, message
    if (fields.size() < 3U) return false;
    if (!looks_like_host(fields[1])) return false;
    event.host = fields[1];
    event.evidence = classify_message(fields.back());
    return true;
}

ProbeCandidate* ProbeCandidateQueue::find(const std::string& host) {
    const auto it = std::find_if(
        candidates_.begin(), candidates_.end(),
        [&host](const ProbeCandidate& candidate) { return candidate.host == host; });
    return it == candidates_.end() ? nullptr : &*it;
}

void ProbeCandidateQueue::drop_weakest() {
    if (candidates_.empty()) return;
    const auto weakest = std::min_element(
        candidates_.begin(), candidates_.end(),
        [](const ProbeCandidate& left, const ProbeCandidate& right) {
            const auto left_rank = rank_of(left);
            const auto right_rank = rank_of(right);
            if (left_rank != right_rank) return left_rank < right_rank;
            if (left.failures != right.failures) return left.failures < right.failures;
            return left.host > right.host;
        });
    candidates_.erase(weakest);
}

void ProbeCandidateQueue::observe(const NfqwsLogEvent& event) {
    if (event.host.empty()) return;

    if (event.evidence == NfqwsEvidence::recovered) {
        // It started working. Whatever it was, it is not a candidate now, and
        // leaving it queued would send a working site through a tunnel.
        const auto it = std::remove_if(
            candidates_.begin(), candidates_.end(),
            [&event](const ProbeCandidate& candidate) {
                return candidate.host == event.host;
            });
        candidates_.erase(it, candidates_.end());
        return;
    }

    const bool failure = nfqws_evidence_is_failure(event.evidence);
    const bool adopted = event.evidence == NfqwsEvidence::adopted;
    if (!failure && !adopted) return;

    // Asked last, because it is the expensive question and most lines are for
    // hosts we have already seen.
    auto* existing = find(event.host);
    if (existing == nullptr) {
        if (covered_ && covered_(event.host)) return;
        if (candidates_.size() >= cap_) drop_weakest();
        candidates_.push_back(ProbeCandidate{event.host, 0U, false, false});
        existing = &candidates_.back();
    }

    if (failure) ++existing->failures;
    if (adopted) existing->adopted_by_nfqws = true;
    if (event.evidence == NfqwsEvidence::redirect) existing->dpi_specific = true;
}

std::vector<ProbeCandidate> ProbeCandidateQueue::ranked() const {
    auto ordered = candidates_;
    std::sort(ordered.begin(), ordered.end(),
              [](const ProbeCandidate& left, const ProbeCandidate& right) {
                  const auto left_rank = rank_of(left);
                  const auto right_rank = rank_of(right);
                  if (left_rank != right_rank) return left_rank > right_rank;
                  if (left.failures != right.failures) {
                      return left.failures > right.failures;
                  }
                  return left.host < right.host;
              });
    return ordered;
}

}  // namespace keen_pbr3
