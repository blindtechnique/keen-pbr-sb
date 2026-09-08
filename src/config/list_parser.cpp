#include "list_parser.hpp"
#include "../log/logger.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>

namespace keen_pbr3 {

static std::string_view trim(std::string_view sv) {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r')) {
        sv.remove_suffix(1);
    }
    return sv;
}

static std::string format_entry_for_log(std::string_view entry) {
    constexpr std::size_t kMaxLoggedBytes = 256;
    std::string result;
    result.reserve(std::min(entry.size(), kMaxLoggedBytes) + 2);
    result.push_back('\'');
    const std::size_t length = std::min(entry.size(), kMaxLoggedBytes);
    for (std::size_t index = 0; index < length; ++index) {
        const unsigned char ch = static_cast<unsigned char>(entry[index]);
        switch (ch) {
            case '\\': result += "\\\\"; break;
            case '\'': result += "\\'"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (ch < 0x20 || ch == 0x7f) {
                    constexpr char hex[] = "0123456789abcdef";
                    result += "\\x";
                    result.push_back(hex[ch >> 4]);
                    result.push_back(hex[ch & 0x0f]);
                } else {
                    result.push_back(static_cast<char>(ch));
                }
        }
    }
    if (entry.size() > length) result += "...";
    result.push_back('\'');
    return result;
}

const char* ListParser::ip_cidr_error_message(IpCidrError error) noexcept {
    switch (error) {
    case IpCidrError::none: return "";
    case IpCidrError::leading_zeros: return "IPv4 addresses must not contain leading zeros";
    case IpCidrError::invalid_address: return "IP/CIDR address is invalid";
    case IpCidrError::invalid_prefix: return "IP/CIDR prefix length is invalid";
    }
    return "IP/CIDR address is invalid";
}

std::optional<std::string> ListParser::normalize_ip_or_cidr(
    std::string_view entry, IpCidrError* error) {
    if (error) *error = IpCidrError::none;
    const auto fail = [&](IpCidrError reason) -> std::optional<std::string> {
        if (error) *error = reason;
        return std::nullopt;
    };
    entry = trim(entry);
    if (entry.empty() || entry.find('\0') != std::string_view::npos) {
        return fail(IpCidrError::invalid_address);
    }
    const auto slash = entry.find('/');
    const auto host = entry.substr(0, slash);
    const int family = host.find(':') == std::string_view::npos ? AF_INET : AF_INET6;
    // Most remote entries are domains: avoid allocating an address string or
    // invoking inet_pton for a hostname that the domain branch will handle.
    if (family == AF_INET && host.find_first_not_of("0123456789.") != std::string_view::npos) {
        return fail(IpCidrError::invalid_address);
    }
    if (host.find('.') != std::string_view::npos) {
        // Also cover the dotted IPv4 tail in IPv4-mapped IPv6 literals.
        const auto colon = host.rfind(':');
        const auto dotted = colon == std::string_view::npos ? host : host.substr(colon + 1);
        std::size_t start = 0;
        while (start < dotted.size()) {
            const auto dot = dotted.find('.', start);
            const auto part = dotted.substr(start,
                dot == std::string_view::npos ? dot : dot - start);
            if (part.size() > 1 && part.front() == '0' &&
                std::all_of(part.begin(), part.end(), [](char ch) { return ch >= '0' && ch <= '9'; })) {
                return fail(IpCidrError::leading_zeros);
            }
            if (dot == std::string_view::npos) break;
            start = dot + 1;
        }
    }

    std::array<unsigned char, 16> address{};
    const std::string host_text(host);
    if (inet_pton(family, host_text.c_str(), address.data()) != 1) {
        return fail(IpCidrError::invalid_address);
    }
    const unsigned max_prefix = family == AF_INET ? 32U : 128U;
    unsigned prefix = max_prefix;
    if (slash != std::string_view::npos) {
        const auto suffix = entry.substr(slash + 1);
        const auto [end, result] = std::from_chars(suffix.data(), suffix.data() + suffix.size(), prefix);
        if (result != std::errc{} || end != suffix.data() + suffix.size() || prefix > max_prefix) {
            return fail(IpCidrError::invalid_prefix);
        }
    }
    for (unsigned byte = 0; byte < max_prefix / 8U; ++byte) {
        const unsigned first_bit = byte * 8U;
        if (prefix <= first_bit) address[byte] = 0;
        else if (prefix < first_bit + 8U) {
            address[byte] &= static_cast<unsigned char>(0xffU << (8U - (prefix - first_bit)));
        }
    }
    std::array<char, INET6_ADDRSTRLEN> text{};
    if (!inet_ntop(family, address.data(), text.data(), text.size())) {
        return fail(IpCidrError::invalid_address);
    }
    std::string normalized(text.data());
    if (prefix != max_prefix) normalized += "/" + std::to_string(prefix);
    return normalized;
}

std::optional<std::string> ListParser::normalize_domain(std::string_view s) {
    if (s.empty()) return std::nullopt;
    if (s.size() >= 2 && s.substr(0, 2) == "*.") s.remove_prefix(2);
    if (!s.empty() && s.back() == '.') s.remove_suffix(1);
    if (s.empty() || s.back() == '.' || s.size() > 253) return std::nullopt;

    bool has_alpha = false;
    std::size_t label_start = 0;
    while (label_start < s.size()) {
        const std::size_t dot = s.find('.', label_start);
        const std::size_t label_end =
            dot == std::string_view::npos ? s.size() : dot;
        const std::size_t label_size = label_end - label_start;
        if (label_size == 0 || label_size > 63) return std::nullopt;
        if (s[label_start] == '-' || s[label_end - 1] == '-') {
            return std::nullopt;
        }

        for (std::size_t index = label_start; index < label_end; ++index) {
            const char c = s[index];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                has_alpha = true;
            } else if ((c >= '0' && c <= '9') || c == '-' || c == '_') {
                // DNS-compatible service labels may contain underscores.
            } else {
                return std::nullopt;
            }
        }
        if (dot == std::string_view::npos) break;
        label_start = dot + 1;
    }

    if (!has_alpha) return std::nullopt;
    return std::string(s);
}

bool ListParser::classify_entry(std::string_view entry, ListEntryVisitor& visitor) {
    if (const auto normalized = normalize_ip_or_cidr(entry)) {
        const auto type = normalized->find('/') == std::string::npos ? EntryType::Ip : EntryType::Cidr;
        visitor.on_entry(type, *normalized);
        return true;
    }
    if (auto domain = normalize_domain(entry)) {
        visitor.on_entry(EntryType::Domain, *domain);
        return true;
    }
    return false;
}

void ListParser::stream_parse(std::istream& input,
                              ListEntryVisitor& visitor,
                              std::string_view source_name) {
    std::string line;
    std::size_t line_number = 0;
    ParseContext context;
    while (std::getline(input, line)) {
        ++line_number;
        parse_line(line, visitor, source_name, line_number, &context);
    }
}

void ListParser::parse_line(std::string_view line,
                            ListEntryVisitor& visitor,
                            std::string_view source_name,
                            std::size_t line_number,
                            ParseContext* context) {
    const auto value = trim(line);
    if (value.empty() || value.front() == '#') return;
    if (!classify_entry(value, visitor) &&
        (!context || context->log_invalid_entries)) {
        constexpr std::size_t kMaxDetailedInvalidEntries = 5;
        const std::size_t count = context ? ++context->invalid_entry_count : 1;
        if (count > kMaxDetailedInvalidEntries + 1) return;
        if (count == kMaxDetailedInvalidEntries + 1) {
            Logger::instance().warn(
                "Too many invalid list entries in {}; further entries will be skipped without warnings",
                source_name.empty() ? std::string("list source")
                                    : std::string(source_name));
            return;
        }
        Logger::instance().warn(
            "Skipping invalid list entry {} in {} at line {}",
            format_entry_for_log(value),
            source_name.empty() ? std::string("list source")
                                : std::string(source_name),
            line_number);
    }
}

} // namespace keen_pbr3
