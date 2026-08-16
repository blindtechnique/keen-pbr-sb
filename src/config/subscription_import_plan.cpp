#include "subscription_import_plan.hpp"

#include "../crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>

namespace keen_pbr3 {

namespace {

std::string lowercased(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](const unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });
    return value;
}

std::string trimmed_copy(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n\f\v");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n\f\v");
    return value.substr(begin, end - begin + 1U);
}

// Standard and URL-safe alphabets, padding optional. Subscription providers
// use every combination of the four, and a body we decline to decode is
// reported to the operator as an unreadable subscription.
bool base64_decode(const std::string& value, std::string& decoded) {
    decoded.clear();
    std::uint32_t accumulator = 0U;
    int bits = 0;
    std::size_t symbols = 0U;
    for (const unsigned char ch : value) {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue;
        if (ch == '=') continue;
        int digit = -1;
        if (ch >= 'A' && ch <= 'Z') {
            digit = ch - 'A';
        } else if (ch >= 'a' && ch <= 'z') {
            digit = ch - 'a' + 26;
        } else if (ch >= '0' && ch <= '9') {
            digit = ch - '0' + 52;
        } else if (ch == '+' || ch == '-') {
            digit = 62;
        } else if (ch == '/' || ch == '_') {
            digit = 63;
        } else {
            return false;
        }
        accumulator = (accumulator << 6U) | static_cast<std::uint32_t>(digit);
        bits += 6;
        ++symbols;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(
                static_cast<char>((accumulator >> bits) & 0xFFU));
        }
    }
    // A single leftover symbol encodes six bits and cannot complete a byte;
    // that is a truncated body, not a short one.
    return symbols == 0U || symbols % 4U != 1U;
}

bool scheme_character(const unsigned char ch) noexcept {
    return std::isalnum(ch) != 0 || ch == '+' || ch == '-' || ch == '.';
}

// The scheme of a line, lowercased, or empty when the line is not a URI.
std::string line_scheme(const std::string& line) {
    const auto colon = line.find(':');
    if (colon == std::string::npos || colon == 0U) return {};
    if (std::isalpha(static_cast<unsigned char>(line.front())) == 0) return {};
    for (std::size_t i = 0U; i < colon; ++i) {
        if (!scheme_character(static_cast<unsigned char>(line[i]))) return {};
    }
    if (line.compare(colon, 3U, "://") != 0) return {};
    return lowercased(line.substr(0U, colon));
}

struct DocumentLine {
    std::string text;
    // Line in the decoded document, counting the blanks and comments that were
    // dropped. An operator chasing a mislabelled entry looks at the document
    // their provider serves, not at our filtered view of it.
    std::size_t number;
};

std::vector<DocumentLine> candidate_lines(const std::string& text) {
    std::vector<DocumentLine> lines;
    std::size_t begin = 0U;
    std::size_t number = 0U;
    while (begin <= text.size()) {
        auto end = text.find('\n', begin);
        if (end == std::string::npos) end = text.size();
        ++number;
        const std::string line = trimmed_copy(text.substr(begin, end - begin));
        // '#' starts a comment only at the start of a line: inside a link it
        // introduces the remark.
        if (!line.empty() && line.front() != '#') {
            lines.push_back(DocumentLine{line, number});
        }
        if (end == text.size()) break;
        begin = end + 1U;
    }
    return lines;
}

bool looks_like_link_list(const std::vector<DocumentLine>& lines) noexcept {
    for (const auto& line : lines) {
        if (!line_scheme(line.text).empty()) return true;
    }
    return false;
}

int hex_value(const unsigned char ch) noexcept {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

std::string percent_decoded(const std::string& value) {
    std::string decoded;
    decoded.reserve(value.size());
    for (std::size_t i = 0U; i < value.size(); ++i) {
        if (value[i] == '%' && i + 2U < value.size()) {
            const int high = hex_value(static_cast<unsigned char>(value[i + 1U]));
            const int low = hex_value(static_cast<unsigned char>(value[i + 2U]));
            if (high >= 0 && low >= 0) {
                decoded.push_back(
                    static_cast<char>((high << 4) | low));
                i += 2U;
                continue;
            }
        }
        decoded.push_back(value[i]);
    }
    return decoded;
}

// Drops characters that let a label lie about itself. A bidirectional override
// inside a remark can make a preview render an endpoint the import will not
// use, which is the one thing a preview must not do; C0/C1 controls corrupt
// the surrounding UI instead.
std::string without_deceptive_controls(const std::string& value) {
    std::string clean;
    clean.reserve(value.size());
    for (std::size_t i = 0U; i < value.size(); ++i) {
        const auto byte = static_cast<unsigned char>(value[i]);
        if (byte < 0x20U || byte == 0x7FU) continue;
        // U+0080..U+009F
        if (byte == 0xC2U && i + 1U < value.size()) {
            const auto next = static_cast<unsigned char>(value[i + 1U]);
            if (next >= 0x80U && next <= 0x9FU) {
                ++i;
                continue;
            }
        }
        if (byte == 0xE2U && i + 2U < value.size()) {
            const auto second = static_cast<unsigned char>(value[i + 1U]);
            const auto third = static_cast<unsigned char>(value[i + 2U]);
            // U+200E, U+200F and U+202A..U+202E
            const bool marks_or_embedding =
                second == 0x80U &&
                (third == 0x8EU || third == 0x8FU ||
                 (third >= 0xAAU && third <= 0xAEU));
            // U+2066..U+2069
            const bool isolates =
                second == 0x81U && third >= 0xA6U && third <= 0xA9U;
            if (marks_or_embedding || isolates) {
                i += 2U;
                continue;
            }
        }
        clean.push_back(value[i]);
    }
    return clean;
}

struct LinkParts {
    std::string scheme;
    std::string endpoint;
    std::string remark;
    // The link with its fragment removed: two entries that differ only in
    // their label are the same proxy.
    std::string identity;
};

LinkParts split_link(const std::string& link) {
    LinkParts parts;
    parts.scheme = line_scheme(link);
    if (parts.scheme.empty()) return parts;

    const auto hash = link.find('#');
    parts.identity =
        hash == std::string::npos ? link : link.substr(0U, hash);
    if (hash != std::string::npos) {
        parts.remark = without_deceptive_controls(
            percent_decoded(link.substr(hash + 1U)));
    }

    const auto authority_begin = parts.scheme.size() + 3U;
    auto authority_end =
        parts.identity.find_first_of("/?", authority_begin);
    if (authority_end == std::string::npos) {
        authority_end = parts.identity.size();
    }
    const std::string authority = parts.identity.substr(
        authority_begin, authority_end - authority_begin);

    // vmess puts the whole outbound - the UUID included - in a base64 payload
    // where the authority would be. ss has a legacy form that does the same.
    // Neither is opened here, and neither may be shown: publishing that blob
    // as an "endpoint" would publish the credential with it.
    const auto at = authority.rfind('@');
    if (parts.scheme == "vmess") return parts;
    if (parts.scheme == "ss" && at == std::string::npos) return parts;

    parts.endpoint =
        at == std::string::npos ? authority : authority.substr(at + 1U);
    return parts;
}

std::string uniquified_tag(const std::string& base,
                           const std::set<std::string>& taken) {
    if (taken.count(base) == 0U) return base;
    for (std::size_t suffix = 2U; suffix <= kSubscriptionMaximumEntries + 1U;
         ++suffix) {
        const std::string tail = "_" + std::to_string(suffix);
        // Truncating the base rather than the suffix: an over-long candidate
        // must still satisfy the tag pattern, and a dropped suffix would
        // silently reintroduce the collision it exists to break.
        std::string head = base;
        if (head.size() + tail.size() > kSubscriptionMaximumTagLength) {
            head = head.substr(
                0U, kSubscriptionMaximumTagLength - tail.size());
        }
        while (!head.empty() && head.back() == '_') head.pop_back();
        if (head.empty()) head = "sub";
        const std::string candidate = head + tail;
        if (taken.count(candidate) == 0U) return candidate;
    }
    return {};
}

} // namespace

const char* subscription_document_kind_name(
    const SubscriptionDocumentKind kind) noexcept {
    switch (kind) {
    case SubscriptionDocumentKind::link_list:
        return "link_list";
    case SubscriptionDocumentKind::base64_link_list:
        return "base64_link_list";
    case SubscriptionDocumentKind::json_document:
        return "json_document";
    case SubscriptionDocumentKind::empty:
        return "empty";
    case SubscriptionDocumentKind::unrecognized:
        return "unrecognized";
    case SubscriptionDocumentKind::too_large:
        return "too_large";
    }
    return "unrecognized";
}

const char* subscription_candidate_disposition_name(
    const SubscriptionCandidateDisposition disposition) noexcept {
    switch (disposition) {
    case SubscriptionCandidateDisposition::importable:
        return "importable";
    case SubscriptionCandidateDisposition::duplicate_in_document:
        return "duplicate_in_document";
    case SubscriptionCandidateDisposition::already_configured:
        return "already_configured";
    case SubscriptionCandidateDisposition::tag_conflict:
        return "tag_conflict";
    case SubscriptionCandidateDisposition::scheme_not_supported:
        return "scheme_not_supported";
    case SubscriptionCandidateDisposition::malformed:
        return "malformed";
    }
    return "malformed";
}

bool subscription_scheme_supported(const std::string& scheme) noexcept {
    // Mirrors parseShareLink in
    // extensions/transport-manager/internal/transport/share_link.go. Note that
    // http and https are proxy schemes there, so a bare web URL on a line of a
    // subscription is an HTTP proxy entry, not a nested subscription.
    static const std::array<const char*, 15> supported = {
        "vless", "vmess", "trojan", "ss", "hysteria2",
        "hy2", "tuic", "anytls", "naive", "naive+https",
        "naive+quic", "socks", "socks5", "http", "https",
    };
    return std::any_of(supported.begin(), supported.end(),
                       [&scheme](const char* value) {
                           return scheme == value;
                       });
}

std::string derive_subscription_tag(const std::string& remark,
                                    const std::size_t position) {
    std::string tag;
    tag.reserve(remark.size());
    for (const unsigned char ch : remark) {
        if (std::isalnum(ch) != 0 && ch < 0x80U) {
            tag.push_back(static_cast<char>(std::tolower(ch)));
        } else if (!tag.empty() && tag.back() != '_') {
            tag.push_back('_');
        }
    }
    // The pattern requires a leading letter, so a remark of "01 Netherlands"
    // cannot keep its number. Dropping the leading run is better than
    // prefixing one: the result still reads as the label it came from.
    const auto first_letter = tag.find_first_of("abcdefghijklmnopqrstuvwxyz");
    if (first_letter == std::string::npos) {
        return "sub_" + std::to_string(position);
    }
    tag = tag.substr(first_letter);
    if (tag.size() > kSubscriptionMaximumTagLength) {
        tag = tag.substr(0U, kSubscriptionMaximumTagLength);
    }
    while (!tag.empty() && tag.back() == '_') tag.pop_back();
    if (tag.empty()) return "sub_" + std::to_string(position);
    return tag;
}

std::string subscription_link_fingerprint(const std::string& link) {
    const std::string trimmed = trimmed_copy(link);
    if (trimmed.empty()) return {};
    const auto hash = trimmed.find('#');
    const std::string identity =
        hash == std::string::npos ? trimmed : trimmed.substr(0U, hash);
    if (identity.empty()) return {};
    return Sha256::hex(identity);
}

SubscriptionImportPlan plan_subscription_import(
    const std::string& body,
    const std::set<std::string>& existing_tags,
    const std::set<std::string>& existing_link_fingerprints) {
    SubscriptionImportPlan plan;

    if (body.size() > kSubscriptionMaximumBytes) {
        plan.kind = SubscriptionDocumentKind::too_large;
        return plan;
    }

    const std::string head = trimmed_copy(body);
    if (head.empty()) {
        plan.kind = SubscriptionDocumentKind::empty;
        return plan;
    }
    if (head.front() == '{' || head.front() == '[') {
        // A sing-box configuration document. Recognized so the operator is
        // told what they pasted rather than that it was unreadable; importing
        // outbound objects is a separate contract from importing links.
        plan.kind = SubscriptionDocumentKind::json_document;
        return plan;
    }

    auto lines = candidate_lines(body);
    plan.kind = SubscriptionDocumentKind::link_list;
    if (!looks_like_link_list(lines)) {
        std::string decoded;
        if (base64_decode(body, decoded)) {
            auto decoded_lines = candidate_lines(decoded);
            if (looks_like_link_list(decoded_lines)) {
                lines = std::move(decoded_lines);
                plan.kind = SubscriptionDocumentKind::base64_link_list;
            } else if (trimmed_copy(decoded).empty()) {
                plan.kind = SubscriptionDocumentKind::empty;
                return plan;
            } else {
                plan.kind = SubscriptionDocumentKind::unrecognized;
                return plan;
            }
        } else {
            plan.kind = SubscriptionDocumentKind::unrecognized;
            return plan;
        }
    }

    if (lines.empty()) {
        plan.kind = SubscriptionDocumentKind::empty;
        return plan;
    }
    if (lines.size() > kSubscriptionMaximumEntries) {
        plan.kind = SubscriptionDocumentKind::too_large;
        plan.candidates.clear();
        return plan;
    }

    std::set<std::string> assigned_tags = existing_tags;
    std::map<std::string, std::size_t> first_occurrence;

    for (std::size_t index = 0U; index < lines.size(); ++index) {
        const std::string& link = lines[index].text;
        const LinkParts parts = split_link(link);

        SubscriptionCandidate candidate;
        candidate.source_line = lines[index].number;
        candidate.scheme = parts.scheme;
        candidate.endpoint = parts.endpoint;
        candidate.remark = parts.remark;

        if (parts.scheme.empty()) {
            candidate.disposition =
                SubscriptionCandidateDisposition::malformed;
        } else if (!subscription_scheme_supported(parts.scheme)) {
            candidate.disposition =
                SubscriptionCandidateDisposition::scheme_not_supported;
        } else {
            const auto seen = first_occurrence.find(parts.identity);
            if (seen != first_occurrence.end()) {
                candidate.disposition =
                    SubscriptionCandidateDisposition::duplicate_in_document;
                candidate.duplicate_of = seen->second;
            } else if (existing_link_fingerprints.count(
                           Sha256::hex(parts.identity)) != 0U) {
                first_occurrence.emplace(parts.identity, index);
                candidate.disposition =
                    SubscriptionCandidateDisposition::already_configured;
            } else {
                first_occurrence.emplace(parts.identity, index);
                const std::string base = derive_subscription_tag(
                    parts.remark, candidate.source_line);
                if (existing_tags.count(base) != 0U) {
                    // An existing transport already owns this name and is not
                    // this link. Renaming it silently would hide that the
                    // operator's own naming has collided with the provider's.
                    candidate.disposition =
                        SubscriptionCandidateDisposition::tag_conflict;
                    candidate.suggested_tag = base;
                } else {
                    const std::string unique =
                        uniquified_tag(base, assigned_tags);
                    if (unique.empty()) {
                        candidate.disposition =
                            SubscriptionCandidateDisposition::tag_conflict;
                        candidate.suggested_tag = base;
                    } else {
                        assigned_tags.insert(unique);
                        candidate.suggested_tag = unique;
                        candidate.disposition =
                            SubscriptionCandidateDisposition::importable;
                    }
                }
            }
        }

        plan.candidates.push_back(std::move(candidate));
        plan.links.push_back(link);
    }

    return plan;
}

} // namespace keen_pbr3
