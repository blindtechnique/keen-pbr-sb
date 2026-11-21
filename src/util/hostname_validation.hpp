#pragma once
#include <string_view>
namespace keen_pbr3 {
// Wire names used by the DNS response parser (ASCII only).
inline bool is_valid_dns_name(std::string_view name) {
    if (name.empty() || name.size() > 253) return false;
    for (unsigned char c : name) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '*'))
            return false;
    }
    return true;
}
} // namespace keen_pbr3
