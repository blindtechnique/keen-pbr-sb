#pragma once

#include <cctype>
#include <string>

namespace keen_pbr3::query_text {

// Shared with connection search: ASCII and Russian case folding does not
// depend on an installed host locale or introduce a new Unicode dependency.
inline std::string lower_search_text(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (std::size_t index = 0; index < value.size(); ++index) {
        const auto current = static_cast<unsigned char>(value[index]);
        if (current < 0x80U) {
            result.push_back(static_cast<char>(std::tolower(current)));
            continue;
        }
        if (index + 1 < value.size() && current == 0xD0U) {
            const auto next = static_cast<unsigned char>(value[index + 1]);
            if (next == 0x81U) { // Ё
                result.push_back(static_cast<char>(0xD1U));
                result.push_back(static_cast<char>(0x91U));
                ++index;
                continue;
            }
            if (next >= 0x90U && next <= 0x9FU) { // А-П
                result.push_back(static_cast<char>(0xD0U));
                result.push_back(static_cast<char>(next + 0x20U));
                ++index;
                continue;
            }
            if (next >= 0xA0U && next <= 0xAFU) { // Р-Я
                result.push_back(static_cast<char>(0xD1U));
                result.push_back(static_cast<char>(next - 0x20U));
                ++index;
                continue;
            }
        }
        result.push_back(static_cast<char>(current));
    }
    return result;
}

} // namespace keen_pbr3::query_text
