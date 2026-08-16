#include "subscription_transport_naming.hpp"

#include <algorithm>
#include <cctype>

namespace keen_pbr3 {

namespace {

// The scheme with everything that is not a letter or digit removed, matching
// the frontend's normalization ("naive+quic" -> "naivequic").
std::string normalized_scheme(const std::string& scheme) {
    std::string normalized;
    normalized.reserve(scheme.size());
    for (const unsigned char ch : scheme) {
        if (std::isalnum(ch) != 0) {
            normalized.push_back(
                static_cast<char>(std::tolower(ch)));
        }
    }
    return normalized;
}

} // namespace

std::string subscription_interface_prefix(const std::string& scheme) {
    const std::string normalized = normalized_scheme(scheme);
    // Mirrors transportInterfacePrefix in frontend/src/lib/technical-id.ts;
    // the frontend's own tests pin that side.
    if (normalized == "vless") return "vless";
    if (normalized == "vmess") return "vmess";
    if (normalized == "hysteria" || normalized == "hysteria2" ||
        normalized == "hy2") {
        return "hys";
    }
    if (normalized == "shadowsocks" || normalized == "ss") return "ss";
    if (normalized == "trojan") return "trojan";
    if (normalized == "tuic") return "tuic";
    if (normalized == "naive" || normalized == "naivehttps" ||
        normalized == "naivequic") {
        return "naive";
    }
    if (normalized == "wireguard" || normalized == "wg") return "wg";
    if (normalized == "socks" || normalized == "socks5") return "socks";
    if (normalized == "http" || normalized == "https") return "http";
    if (normalized == "ssh") return "ssh";
    return "proxy";
}

std::string derive_subscription_interface(
    const std::string& scheme,
    const std::set<std::string>& taken) {
    const std::string prefix = subscription_interface_prefix(scheme);
    for (unsigned sequence = 1U; sequence < 100000U; ++sequence) {
        std::string candidate = prefix + std::to_string(sequence);
        // The interface pattern allows at most 15 characters; the longest
        // prefix is six, so truncation only fires on absurd sequence numbers,
        // and when it does the uniqueness check still judges the final form.
        if (candidate.size() > 15U) candidate.resize(15U);
        if (taken.count(candidate) == 0U) return candidate;
    }
    return {};
}

} // namespace keen_pbr3
