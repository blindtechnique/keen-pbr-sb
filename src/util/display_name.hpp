#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace keen_pbr3::display_name {

constexpr std::size_t MAX_CODE_POINTS = 80;

enum class ValidationError {
    none,
    invalid_utf8,
    ascii_control,
    c1_or_bidirectional_control,
    whitespace_only,
    too_long,
};

struct Utf8Summary {
    std::size_t code_points{0};
    bool has_non_whitespace{false};
    bool has_ascii_control{false};
    bool has_c1_or_bidirectional_control{false};
};

inline bool is_unicode_whitespace(std::uint32_t code_point) {
    return (code_point >= 0x09U && code_point <= 0x0DU) ||
           code_point == 0x20U || code_point == 0x85U ||
           code_point == 0xA0U || code_point == 0x1680U ||
           (code_point >= 0x2000U && code_point <= 0x200AU) ||
           code_point == 0x2028U || code_point == 0x2029U ||
           code_point == 0x202FU || code_point == 0x205FU ||
           code_point == 0x3000U;
}

inline bool is_c1_or_bidirectional_control(std::uint32_t code_point) {
    return (code_point >= 0x80U && code_point <= 0x9FU) ||
           code_point == 0x061CU ||
           code_point == 0x200EU ||
           code_point == 0x200FU ||
           (code_point >= 0x202AU && code_point <= 0x202EU) ||
           (code_point >= 0x2066U && code_point <= 0x2069U);
}

inline std::optional<Utf8Summary> summarize_utf8(std::string_view value) {
    Utf8Summary summary;
    for (std::size_t offset = 0; offset < value.size();) {
        const auto first = static_cast<unsigned char>(value[offset]);
        std::size_t length = 0;
        std::uint32_t code_point = 0;
        if (first <= 0x7FU) {
            length = 1;
            code_point = first;
        } else if (first >= 0xC2U && first <= 0xDFU) {
            length = 2;
            code_point = first & 0x1FU;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            length = 3;
            code_point = first & 0x0FU;
        } else if (first >= 0xF0U && first <= 0xF4U) {
            length = 4;
            code_point = first & 0x07U;
        } else {
            return std::nullopt;
        }

        if (offset + length > value.size()) return std::nullopt;
        for (std::size_t index = 1; index < length; ++index) {
            const auto continuation =
                static_cast<unsigned char>(value[offset + index]);
            if ((continuation & 0xC0U) != 0x80U) return std::nullopt;
            code_point = (code_point << 6U) | (continuation & 0x3FU);
        }

        if (length == 3) {
            const auto second =
                static_cast<unsigned char>(value[offset + 1]);
            if ((first == 0xE0U && second < 0xA0U) ||
                (first == 0xEDU && second > 0x9FU)) {
                return std::nullopt;
            }
        } else if (length == 4) {
            const auto second =
                static_cast<unsigned char>(value[offset + 1]);
            if ((first == 0xF0U && second < 0x90U) ||
                (first == 0xF4U && second > 0x8FU)) {
                return std::nullopt;
            }
        }

        offset += length;
        ++summary.code_points;
        summary.has_non_whitespace =
            summary.has_non_whitespace || !is_unicode_whitespace(code_point);
        summary.has_ascii_control =
            summary.has_ascii_control ||
            code_point < 0x20U || code_point == 0x7FU;
        summary.has_c1_or_bidirectional_control =
            summary.has_c1_or_bidirectional_control ||
            is_c1_or_bidirectional_control(code_point);
    }
    return summary;
}

inline ValidationError validate(std::string_view value, bool allow_empty) {
    if (value.empty() && allow_empty) return ValidationError::none;

    const auto summary = summarize_utf8(value);
    if (!summary.has_value()) return ValidationError::invalid_utf8;
    if (summary->has_ascii_control) return ValidationError::ascii_control;
    if (summary->has_c1_or_bidirectional_control) {
        return ValidationError::c1_or_bidirectional_control;
    }
    if (!summary->has_non_whitespace) {
        return ValidationError::whitespace_only;
    }
    if (summary->code_points > MAX_CODE_POINTS) {
        return ValidationError::too_long;
    }
    return ValidationError::none;
}

inline bool is_valid(std::string_view value, bool allow_empty = false) {
    return validate(value, allow_empty) == ValidationError::none;
}

} // namespace keen_pbr3::display_name
