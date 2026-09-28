#include "list_preview.hpp"

#include "../config/list_parser.hpp"
#include "list_streamer.hpp"
#include "srs_decoder.hpp"

#include <algorithm>
#include <set>
#include <sstream>

namespace keen_pbr3 {
namespace {
std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) value.remove_suffix(1);
    return value;
}

bool plain_utf8(std::string_view text) {
    for (std::size_t index = 0; index < text.size();) {
        const auto first = static_cast<unsigned char>(text[index]);
        if (first < 0x80U) {
            if ((first < 0x20U && first != '\t' && first != '\r' && first != '\n') || first == 0x7fU) return false;
            ++index;
            continue;
        }
        const std::size_t count = first >= 0xc2U && first <= 0xdfU ? 2U :
                                  first >= 0xe0U && first <= 0xefU ? 3U :
                                  first >= 0xf0U && first <= 0xf4U ? 4U : 0U;
        if (count == 0U || index + count > text.size()) return false;
        for (std::size_t tail = 1; tail < count; ++tail) {
            const auto byte = static_cast<unsigned char>(text[index + tail]);
            if (byte < 0x80U || byte > 0xbfU) return false;
        }
        const auto second = static_cast<unsigned char>(text[index + 1U]);
        if ((first == 0xe0U && second < 0xa0U) || (first == 0xedU && second >= 0xa0U) ||
            (first == 0xf0U && second < 0x90U) || (first == 0xf4U && second >= 0x90U)) return false;
        index += count;
    }
    return true;
}

std::string error_value(std::string_view value) {
    auto size = std::min<std::size_t>(160U, value.size());
    // Input is already valid UTF-8: do not cut a multibyte character midway.
    while (size < value.size() && size > 0U &&
           (static_cast<unsigned char>(value[size]) & 0xc0U) == 0x80U) --size;
    return std::string(value.substr(0, size));
}

bool structured_first_entry(std::string_view value) {
    if (value.empty()) return false;
    if (value.front() == '{' || value.front() == '[' || value == "---" ||
        value.rfind("- ", 0) == 0) return true;
    // YAML mappings require whitespace after ':', unlike IPv6 literals.
    return value.find(": ") != std::string_view::npos ||
           value == "payload:" || value == "rules:" || value == "rule-set:";
}

const char* invalid_code(std::string_view value) {
    const bool looks_ip = value.find(':') != std::string_view::npos ||
                          value.find('/') != std::string_view::npos ||
                          value.find_first_not_of("0123456789.") == std::string_view::npos;
    if (!looks_ip) return "invalid_entry";
    ListParser::IpCidrError error;
    (void)ListParser::normalize_ip_or_cidr(value, &error);
    switch (error) {
    case ListParser::IpCidrError::leading_zeros: return "leading_zeros";
    case ListParser::IpCidrError::invalid_prefix: return "invalid_prefix";
    case ListParser::IpCidrError::invalid_address: return "invalid_address";
    case ListParser::IpCidrError::none: return "invalid_entry";
    }
    return "invalid_entry";
}
} // namespace

ListPreviewResult preview_list_text(std::string_view text) {
    ListPreviewResult result;
    if (text.size() > kListPreviewMaxBytes) {
        result.status = "too_large";
        result.complete = false;
        return result;
    }
    if (!plain_utf8(text)) {
        result.status = "unsupported_format";
        result.complete = false;
        return result;
    }
    std::set<std::string> seen;
    bool first_entry = true;
    for (std::size_t cursor = 0; cursor < text.size();) {
        if (result.lines == static_cast<std::int64_t>(kListPreviewMaxLines)) {
            result.complete = false;
            result.limit_reason = "line_limit";
            break;
        }
        const auto newline = text.find('\n', cursor);
        const auto end = newline == std::string_view::npos ? text.size() : newline;
        const auto raw_line = text.substr(cursor, end - cursor);
        const auto value = trim(raw_line);
        cursor = newline == std::string_view::npos ? text.size() : newline + 1U;
        ++result.lines;
        // The ordinary file reader limits raw bytes before trimming. Preserve
        // that boundary here, including overlong comments or padding.
        if (raw_line.size() > ListStreamer::kMaxLineBytes) {
            ++result.invalid_entries;
            if (result.errors.size() < kListPreviewSampleSize)
                result.errors.push_back({result.lines, "line_too_long", error_value(value)});
            else result.errors_limited = true;
            result.complete = false;
            result.limit_reason = "line_too_long";
            break;
        }
        if (value.empty() || value.front() == '#') {
            ++result.ignored_lines;
            continue;
        }
        if (first_entry && structured_first_entry(value)) {
            result = ListPreviewResult{};
            result.status = "unsupported_format";
            result.complete = false;
            return result;
        }
        first_entry = false;
        FunctionalVisitor visitor([&](EntryType type, std::string_view normalized) {
            ++result.valid_entries;
            std::string canonical(normalized);
            std::string family;
            if (type == EntryType::Domain) {
                std::transform(canonical.begin(), canonical.end(), canonical.begin(), [](unsigned char ch) {
                    return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch);
                });
                family = "domain";
            } else family = canonical.find(':') == std::string::npos ? "ipv4" : "ipv6";
            if (!seen.insert(canonical).second) { ++result.duplicates; return; }
            ++result.unique_entries;
            if (family == "ipv4") ++result.ipv4;
            else if (family == "ipv6") ++result.ipv6;
            else ++result.domains;
            if (result.entries.size() < kListPreviewSampleSize)
                result.entries.push_back({result.lines, std::move(canonical), std::move(family)});
            else result.entries_limited = true;
        });
        if (!ListParser::classify_entry(value, visitor)) {
            ++result.invalid_entries;
            if (result.errors.size() < kListPreviewSampleSize)
                result.errors.push_back({result.lines, invalid_code(value), error_value(value)});
            else result.errors_limited = true;
        }
    }
    return result;
}

ListPreviewResult preview_list_srs(const std::string& data) {
    ListPreviewResult result;
    result.source_format = "srs";
    if (data.size() > kListPreviewMaxBytes) {
        result.status = "too_large";
        result.complete = false;
        return result;
    }
    try {
        SrsDecodeLimits limits;
        limits.max_compressed_bytes = kListPreviewMaxBytes;
        limits.max_decompressed_bytes = 8U * kListPreviewMaxBytes;
        limits.max_output_entries = kListPreviewMaxLines;
        limits.max_output_string_bytes = kListPreviewMaxBytes;
        limits.max_values = kListPreviewMaxLines;
        limits.max_total_string_bytes = kListPreviewMaxBytes;
        limits.max_trie_nodes = 500001U;
        limits.max_trie_labels = 500000U;
        std::istringstream input(data);
        const auto decoded = decode_srs(input, limits);
        std::string text;
        const auto append = [&](const std::string& value) {
            if (text.size() + value.size() + 1U > kListPreviewMaxBytes)
                throw SrsDecodeError("converted SRS exceeds preview limit");
            text += value;
            text += '\n';
        };
        // Use the cache loader's normalization, including rejection of
        // already-prefixed domains; never preview entries runtime would skip.
        std::vector<ListPreviewError> invalid;
        std::int64_t invalid_count = 0;
        std::int64_t record = 0;
        const auto append_domain = [&](const std::string& value, bool suffix) {
            ++record;
            const auto normalized = ListParser::normalize_domain(value);
            if (value.rfind("*.", 0) == 0 || (!value.empty() && value.front() == '.') || !normalized) {
                ++invalid_count;
                if (invalid.size() < kListPreviewSampleSize)
                    invalid.push_back({record, "invalid_entry", error_value(value)});
                append("");
            } else append((suffix ? "*." : "") + *normalized);
        };
        for (const auto& domain : decoded.domains) append_domain(domain, false);
        for (const auto& suffix : decoded.domain_suffixes) append_domain(suffix, true);
        for (const auto& cidr : decoded.ip_cidrs) append(cidr);
        result = preview_list_text(text);
        result.invalid_entries += invalid_count;
        result.ignored_lines -= invalid_count;
        result.errors = std::move(invalid);
        result.errors_limited = invalid_count > static_cast<std::int64_t>(kListPreviewSampleSize);
        result.source_format = "srs";
        result.srs_version = decoded.version;
        result.unsupported_fields = static_cast<std::int64_t>(decoded.unsupported_fields);
        result.skipped_rules = static_cast<std::int64_t>(decoded.skipped_rules);
        result.inverted_rules = static_cast<std::int64_t>(decoded.inverted_rules);
        if (decoded.unsupported_fields || decoded.skipped_rules || decoded.inverted_rules) {
            result.complete = false;
            result.limit_reason = "srs_partial";
        }
    } catch (const SrsDecodeError& error) {
        result.complete = false;
        result.srs_version = error.version();
        result.limit_reason = error.kind() == SrsDecodeErrorKind::UnsupportedVersion
            ? "srs_version" : "srs_decode_failed";
    }
    return result;
}

} // namespace keen_pbr3
