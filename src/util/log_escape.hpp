#pragma once

#include <algorithm>
#include <string>
#include <string_view>

namespace keen_pbr3 {

// Traffic-derived strings must not inject newlines or terminal control bytes
// into a diagnostic record. Adapted from upstream keen-pbr 413331c.
inline std::string log_escape(std::string_view value) {
    static constexpr char hex[] = "0123456789abcdef";
    constexpr std::size_t limit = 255;
    std::string out;
    out.reserve(std::min(value.size(), limit) + 3);
    for (std::size_t i = 0; i < value.size() && i < limit; ++i) {
        const auto byte = static_cast<unsigned char>(value[i]);
        if (byte == '\\') {
            out += "\\\\";
        } else if (byte >= 0x20 && byte <= 0x7e) {
            out += static_cast<char>(byte);
        } else {
            out += "\\x";
            out += hex[byte >> 4];
            out += hex[byte & 0xf];
        }
    }
    if (value.size() > limit) out += "...";
    return out;
}

} // namespace keen_pbr3
