#include "list_source_decoder.hpp"

#include "../config/list_parser.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>
#include <set>

namespace keen_pbr3 {
namespace {
using Json = nlohmann::json;

std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r'))
        value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r'))
        value.remove_suffix(1);
    return value;
}

bool valid_utf8(std::string_view value, std::size_t& invalid_offset) {
    for (std::size_t index = 0; index < value.size();) {
        invalid_offset = index;
        const auto first = static_cast<unsigned char>(value[index]);
        if (first < 0x80U) {
            if ((first < 0x20U && first != '\t' && first != '\r' && first != '\n') || first == 0x7fU)
                return false;
            ++index;
            continue;
        }
        const std::size_t count = first >= 0xc2U && first <= 0xdfU ? 2U :
            first >= 0xe0U && first <= 0xefU ? 3U : first >= 0xf0U && first <= 0xf4U ? 4U : 0U;
        if (count == 0U || index + count > value.size()) return false;
        for (std::size_t tail = 1; tail < count; ++tail) {
            const auto byte = static_cast<unsigned char>(value[index + tail]);
            if (byte < 0x80U || byte > 0xbfU) return false;
        }
        const auto second = static_cast<unsigned char>(value[index + 1U]);
        if ((first == 0xe0U && second < 0xa0U) || (first == 0xedU && second >= 0xa0U) ||
            (first == 0xf0U && second < 0x90U) || (first == 0xf4U && second >= 0x90U)) return false;
        index += count;
    }
    return true;
}

std::string excerpt(std::string_view value) {
    std::size_t bytes = std::min<std::size_t>(160U, value.size());
    while (bytes > 0U && bytes < value.size() &&
           (static_cast<unsigned char>(value[bytes]) & 0xc0U) == 0x80U) --bytes;
    return std::string(value.substr(0, bytes));
}

std::int64_t line_at(std::string_view body, std::size_t offset) {
    offset = std::min(offset, body.size());
    return 1 + static_cast<std::int64_t>(std::count(body.begin(), body.begin() + offset, '\n'));
}

const char* invalid_code(std::string_view value) {
    const bool looks_ip = value.find(':') != std::string_view::npos ||
        value.find('/') != std::string_view::npos ||
        value.find_first_not_of("0123456789.") == std::string_view::npos;
    if (!looks_ip) return "invalid_entry";
    ListParser::IpCidrError reason;
    (void)ListParser::normalize_ip_or_cidr(value, &reason);
    switch (reason) {
    case ListParser::IpCidrError::leading_zeros: return "leading_zeros";
    case ListParser::IpCidrError::invalid_prefix: return "invalid_prefix";
    case ListParser::IpCidrError::invalid_address: return "invalid_address";
    case ListParser::IpCidrError::none: return "invalid_entry";
    }
    return "invalid_entry";
}

class DecodeContext {
public:
    ListSourceDecodeResult result;
    bool stopped{false};

    void error(std::int64_t line, const char* code, std::string_view value = {}) {
        result.complete = false;
        if (result.errors.size() < kListSourceMaxErrors)
            result.errors.push_back({line, code, excerpt(value)});
        else result.errors_limited = true;
    }

    bool limit(std::int64_t line, const char* code, const char* reason,
               std::string_view value = {}) {
        error(line, code, value);
        result.limit_reason = reason;
        stopped = true;
        return false;
    }

    bool entry(std::string_view raw, std::int64_t line) {
        if (result.input_entries >= static_cast<std::int64_t>(kListSourceMaxEntries))
            return limit(line, "entry_limit", "entry_limit");
        ++result.input_entries;
        if (raw.size() > kListSourceMaxLineBytes) {
            ++result.invalid_entries;
            return limit(line, "line_too_long", "line_too_long", raw);
        }
        const auto value = trim(raw);
        bool output_ok = true;
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
            if (!seen_.insert(canonical).second) { ++result.duplicates; return; }
            if (canonical.size() + 1U > kListSourceMaxBytes - result.text.size()) {
                output_ok = limit(line, "output_limit", "output_limit");
                return;
            }
            result.text += canonical;
            result.text += '\n';
            if (family == "domain") ++result.domains;
            else if (family == "ipv4") ++result.ipv4;
            else ++result.ipv6;
            result.entries.push_back({line, std::move(canonical), std::move(family)});
        });
        if (!ListParser::classify_entry(value, visitor)) {
            ++result.invalid_entries;
            error(line, invalid_code(value), value);
        }
        return output_ok;
    }

private:
    std::set<std::string> seen_;
};

// SAX rejects nested arrays/objects immediately, before a DOM can allocate an
// attacker-controlled tree. nlohmann remains the only JSON syntax/string
// decoder. The small cursor tracks positions in the already-validated flat
// string array; it does not independently accept JSON syntax.
class JsonArrayReader final : public nlohmann::json_sax<Json> {
public:
    JsonArrayReader(std::string_view body, DecodeContext& context)
        : body_(body), context_(context) {
        if (body_.substr(0, 3) == "\xef\xbb\xbf") cursor_ = 3;
    }
    bool null() override { return wrong_type(); }
    bool boolean(bool) override { return wrong_type(); }
    bool number_integer(number_integer_t) override { return wrong_type(); }
    bool number_unsigned(number_unsigned_t) override { return wrong_type(); }
    bool number_float(number_float_t, const string_t&) override { return wrong_type(); }
    bool binary(binary_t&) override { return wrong_type(); }
    bool key(string_t&) override { return wrong_type(); }
    bool start_object(std::size_t) override { return wrong_type(); }
    bool end_object() override { return wrong_type(); }
    bool start_array(std::size_t) override {
        if (array_) return wrong_type();
        array_ = true;
        skip_separators();
        ++cursor_; // The SAX parser has consumed the opening '['.
        return true;
    }
    bool end_array() override {
        skip_separators();
        ++cursor_;
        return true;
    }
    bool string(string_t& value) override {
        if (!array_) return wrong_type();
        skip_separators();
        const auto line = line_;
        ++cursor_; // Opening quote of the validated token.
        while (cursor_ < body_.size()) {
            const auto ch = body_[cursor_++];
            if (ch == '\\' && cursor_ < body_.size()) ++cursor_;
            else if (ch == '"') break;
        }
        return context_.entry(value, line);
    }
    bool parse_error(std::size_t position, const std::string&,
                     const nlohmann::detail::exception&) override {
        context_.error(line_at(body_, position == 0U ? 0U : position - 1U), "json_syntax");
        return false;
    }

private:
    void skip_separators() {
        while (cursor_ < body_.size() && (body_[cursor_] == ' ' || body_[cursor_] == '\t' ||
               body_[cursor_] == '\r' || body_[cursor_] == '\n' || body_[cursor_] == ',')) {
            if (body_[cursor_] == '\n') ++line_;
            ++cursor_;
        }
    }
    bool wrong_type() {
        skip_separators();
        if (array_) {
            if (context_.result.input_entries >= static_cast<std::int64_t>(kListSourceMaxEntries))
                return context_.limit(line_, "entry_limit", "entry_limit");
            ++context_.result.input_entries;
            ++context_.result.invalid_entries;
        }
        context_.error(line_, array_ ? "json_entry_type" : "json_root_array");
        return false;
    }
    std::string_view body_;
    DecodeContext& context_;
    std::size_t cursor_{0};
    std::int64_t line_{1};
    bool array_{false};
};

bool only_comment(std::string_view suffix) {
    if (!suffix.empty() && suffix.front() != ' ' && suffix.front() != '\t' && suffix.front() != '\r')
        return false;
    suffix = trim(suffix);
    return suffix.empty() || suffix.front() == '#';
}

std::string_view without_plain_comment(std::string_view value) {
    for (std::size_t index = 0; index < value.size(); ++index)
        if (value[index] == '#' && (index == 0U || value[index - 1U] == ' ' || value[index - 1U] == '\t'))
            return trim(value.substr(0, index));
    return trim(value);
}

bool implicit_nonstring(std::string_view value) {
    std::string lower(value);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
        return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch);
    });
    if (lower == "true" || lower == "false" || lower == "null" || lower == "~") return true;
    if (lower.size() > 2U && lower[0] == '0' && (lower[1] == 'x' || lower[1] == 'o')) {
        const auto digits = std::string_view(lower).substr(2);
        if (digits.find_first_not_of(lower[1] == 'x' ? "0123456789abcdef" : "01234567") == std::string_view::npos)
            return true;
    }
    // Strings are the only accepted YAML values. Recognize JSON-compatible
    // number spellings without inventing another numeric parser.
    if (!value.empty() && (value.front() == '-' || (value.front() >= '0' && value.front() <= '9'))) {
        const auto parsed = Json::parse(value.begin(), value.end(), nullptr, false);
        return parsed.is_number();
    }
    return false;
}

std::optional<std::string> yaml_scalar(std::string_view source, std::int64_t line,
                                       DecodeContext& context) {
    source = trim(source);
    if (source.empty() || source.front() == '#') {
        context.error(line, "yaml_syntax", source);
        return std::nullopt;
    }
    if (source.front() == '\'' || source.front() == '"') {
        const char quote = source.front();
        std::string single;
        for (std::size_t cursor = 1; cursor < source.size(); ++cursor) {
            const char ch = source[cursor];
            if (quote == '"' && ch == '\\') { ++cursor; continue; }
            if (ch != quote) { if (quote == '\'') single += ch; continue; }
            if (quote == '\'' && cursor + 1U < source.size() && source[cursor + 1U] == '\'') {
                single += '\'';
                ++cursor;
                continue;
            }
            if (!only_comment(source.substr(cursor + 1U))) break;
            if (quote == '\'') return single;
            const auto parsed = Json::parse(source.begin(), source.begin() + cursor + 1U, nullptr, false);
            if (parsed.is_string()) return parsed.get<std::string>();
            break;
        }
        context.error(line, "yaml_syntax", source);
        return std::nullopt;
    }
    const auto value = without_plain_comment(source);
    // Explicitly unsupported YAML features and classical routing expressions.
    // Quoted native "*." domain values remain supported by ListParser.
    if (value.empty() || value.find_first_of("!&*|>{}[,") == 0U ||
        value.front() == '?' || value.front() == ':' || value.rfind("- ", 0) == 0 ||
        value.find(": ") != std::string_view::npos || value.find(":\t") != std::string_view::npos ||
        value.find(',') != std::string_view::npos || implicit_nonstring(value)) {
        context.error(line, "yaml_unsupported", value);
        return std::nullopt;
    }
    return std::string(value);
}

void decode_lines(std::string_view body, bool yaml, DecodeContext& context) {
    bool payload = false;
    bool any_yaml_item = false;
    std::optional<std::size_t> item_indent;
    std::int64_t line = 0;
    for (std::size_t cursor = 0; cursor < body.size() && !context.stopped;) {
        const auto newline = body.find('\n', cursor);
        const auto end = newline == std::string_view::npos ? body.size() : newline;
        auto raw = body.substr(cursor, end - cursor);
        cursor = newline == std::string_view::npos ? body.size() : newline + 1U;
        ++line;
        if (raw.size() > kListSourceMaxLineBytes) {
            context.limit(line, "line_too_long", "line_too_long", trim(raw));
            break;
        }
        if (yaml && line == 1 && raw.substr(0, 3) == "\xef\xbb\xbf") raw.remove_prefix(3);
        auto value = trim(raw);
        if (value.empty() || value.front() == '#') { ++context.result.ignored_lines; continue; }
        if (!yaml) { context.entry(value, line); continue; }
        std::size_t indentation = 0;
        while (indentation < raw.size() && raw[indentation] == ' ') ++indentation;
        if (indentation < raw.size() && raw[indentation] == '\t') {
            context.error(line, "yaml_syntax", value);
            return;
        }
        if (without_plain_comment(value) == "---" || without_plain_comment(value) == "..." || value.front() == '%') {
            context.error(line, "yaml_unsupported", value);
            return;
        }
        if (!payload) {
            if (indentation != 0U || without_plain_comment(value) != "payload:") {
                context.error(line, "yaml_payload_required", value);
                return;
            }
            payload = true;
            continue;
        }
        if (value.size() < 2U || value.front() != '-' || (value[1] != ' ' && value[1] != '\t') ||
            (item_indent && *item_indent != indentation)) {
            context.error(line, "yaml_unsupported", value);
            return;
        }
        if (!item_indent) item_indent = indentation;
        any_yaml_item = true;
        const auto scalar = yaml_scalar(value.substr(2), line, context);
        if (!scalar) return;
        context.entry(*scalar, line);
    }
    if (yaml && !context.stopped) {
        if (!payload) context.error(1, "yaml_payload_required");
        else if (!any_yaml_item) context.error(std::max<std::int64_t>(1, line), "yaml_syntax");
    }
}
} // namespace

ListSourceDecodeResult decode_list_source(std::string_view body, std::string_view format) {
    DecodeContext context;
    std::size_t invalid_offset = 0;
    if (!valid_list_source_format(format)) context.error(1, "unsupported_format");
    else if (body.size() > kListSourceMaxBytes) context.limit(1, "too_large", "byte_limit");
    else if (!valid_utf8(body, invalid_offset)) context.error(line_at(body, invalid_offset), "invalid_encoding");
    else {
        context.result.lines = static_cast<std::int64_t>(std::count(body.begin(), body.end(), '\n')) +
            (!body.empty() && body.back() != '\n' ? 1 : 0);
        if (format == "json-array") {
            JsonArrayReader reader(body, context);
            (void)Json::sax_parse(body.begin(), body.end(), &reader);
        } else decode_lines(body, format == "yaml-payload", context);
    }
    if (!context.result.complete) context.result.text.clear();
    return std::move(context.result);
}

} // namespace keen_pbr3
