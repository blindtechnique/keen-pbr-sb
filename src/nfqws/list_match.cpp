#include "list_match.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <limits>
#include <string_view>

namespace keen_pbr3::nfqws {

namespace {

std::string trim(std::string value) {
    const auto not_space = [](unsigned char character) {
        return std::isspace(character) == 0;
    };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
                value.end());
    return value;
}

std::string lower(std::string value) {
    for (auto& character : value) {
        character = static_cast<char>(
            std::tolower(static_cast<unsigned char>(character)));
    }
    return value;
}

std::string_view trim_view(std::string_view value) {
    const auto is_space = [](unsigned char character) {
        return std::isspace(character) != 0;
    };
    while (!value.empty() &&
           is_space(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1U);
    }
    while (!value.empty() &&
           is_space(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1U);
    }
    return value;
}

bool checked_add(std::size_t left,
                 std::size_t right,
                 std::size_t& result) noexcept {
    if (right > std::numeric_limits<std::size_t>::max() - left) return false;
    result = left + right;
    return true;
}

struct ParsedPrefix {
    int family{0};
    std::array<unsigned char, 16> bytes{};
    int bits{0};
};

// Accepts "10.0.0.0/8", "2001:db8::/32" and a bare address, which is its own
// full-length prefix. Anything else is not a prefix and must not be guessed at.
std::optional<ParsedPrefix> parse_prefix(const std::string& entry) {
    const auto slash = entry.find('/');
    const auto address =
        slash == std::string::npos ? entry : entry.substr(0, slash);
    if (address.empty()) return std::nullopt;

    ParsedPrefix parsed;
    if (address.find(':') != std::string::npos) {
        if (inet_pton(AF_INET6, address.c_str(), parsed.bytes.data()) != 1) {
            return std::nullopt;
        }
        parsed.family = AF_INET6;
        parsed.bits = 128;
    } else {
        if (inet_pton(AF_INET, address.c_str(), parsed.bytes.data()) != 1) {
            return std::nullopt;
        }
        parsed.family = AF_INET;
        parsed.bits = 32;
    }

    if (slash != std::string::npos) {
        const auto text = entry.substr(slash + 1U);
        if (text.empty()) return std::nullopt;
        int bits = 0;
        for (const unsigned char character : text) {
            if (character < '0' || character > '9') return std::nullopt;
            bits = bits * 10 + (character - '0');
            if (bits > 128) return std::nullopt;
        }
        const int limit = parsed.family == AF_INET6 ? 128 : 32;
        if (bits > limit) return std::nullopt;
        parsed.bits = bits;
    }
    return parsed;
}

bool prefix_contains(const ParsedPrefix& prefix, const ParsedPrefix& address) {
    // A v4 address inside a v6 prefix is not a match, whatever the bytes say.
    if (prefix.family != address.family) return false;
    const int whole_bytes = prefix.bits / 8;
    const int spare_bits = prefix.bits % 8;
    if (whole_bytes > 0 &&
        std::memcmp(prefix.bytes.data(),
                    address.bytes.data(),
                    static_cast<std::size_t>(whole_bytes)) != 0) {
        return false;
    }
    if (spare_bits == 0) return true;
    const auto mask = static_cast<unsigned char>(0xFFU << (8 - spare_bits));
    return (prefix.bytes[static_cast<std::size_t>(whole_bytes)] & mask) ==
           (address.bytes[static_cast<std::size_t>(whole_bytes)] & mask);
}

} // namespace

bool role_includes(ListRole role) noexcept {
    return role == ListRole::hostlist || role == ListRole::hostlist_auto ||
           role == ListRole::ipset;
}

bool role_is_hostlist(ListRole role) noexcept {
    return role == ListRole::hostlist || role == ListRole::hostlist_auto ||
           role == ListRole::hostlist_exclude;
}

std::vector<ListReference> parse_list_references(
    const std::vector<std::string>& arguments) {
    // Longest first for clarity. Each comparison is an exact token prefix, so
    // --hostlist-exclude can never be mistaken for --hostlist.
    static const std::vector<std::pair<std::string, ListRole>> kFlags{
        {"--hostlist-exclude=", ListRole::hostlist_exclude},
        {"--hostlist-auto=", ListRole::hostlist_auto},
        {"--hostlist=", ListRole::hostlist},
        {"--ipset-exclude=", ListRole::ipset_exclude},
        {"--ipset=", ListRole::ipset},
    };

    std::vector<ListReference> references;
    for (const auto& argument : arguments) {
        for (const auto& [flag, role] : kFlags) {
            if (argument.rfind(flag, 0) != 0) continue;
            auto path = argument.substr(flag.size());
            if (path.empty()) break;
            const bool already = std::any_of(
                references.begin(), references.end(),
                [&](const ListReference& existing) {
                    return existing.path == path && existing.role == role;
                });
            if (!already) references.push_back(ListReference{path, role});
            break;
        }
    }
    return references;
}

std::vector<std::string> parse_hostlist(const std::string& contents) {
    auto parsed = parse_hostlist_bounded(
        contents,
        std::numeric_limits<std::size_t>::max(),
        std::numeric_limits<std::size_t>::max(),
        std::numeric_limits<std::size_t>::max());
    return parsed ? std::move(parsed->entries) : std::vector<std::string>{};
}

std::optional<BoundedHostlist> parse_hostlist_bounded(
    const std::string& contents,
    std::size_t max_entries,
    std::size_t max_normalized_characters,
    std::size_t max_conservative_bytes) {
    BoundedHostlist parsed;
    std::size_t string_storage_bytes = 0;
    std::size_t offset = 0;
    constexpr std::size_t kAllocatorAllowance = 2U * sizeof(void*);

    while (offset < contents.size()) {
        const auto newline = contents.find('\n', offset);
        const auto end = newline == std::string::npos ? contents.size()
                                                       : newline;
        auto entry = trim_view(
            std::string_view(contents).substr(offset, end - offset));
        offset = newline == std::string::npos ? contents.size()
                                               : newline + 1U;
        if (entry.empty() || entry.front() == '#') continue;
        if (parsed.entries.size() >= max_entries) return std::nullopt;

        std::size_t next_normalized = 0;
        if (!checked_add(parsed.normalized_characters,
                         entry.size(),
                         next_normalized) ||
            next_normalized > max_normalized_characters) {
            return std::nullopt;
        }

        parsed.entries.emplace_back(entry);
        const auto& stored = parsed.entries.back();
        std::size_t stored_bytes = 0;
        if (!checked_add(stored.capacity(), 1U, stored_bytes) ||
            !checked_add(stored_bytes,
                         kAllocatorAllowance,
                         stored_bytes) ||
            !checked_add(string_storage_bytes,
                         stored_bytes,
                         string_storage_bytes)) {
            return std::nullopt;
        }
        std::size_t vector_bytes = 0;
        if (parsed.entries.capacity() >
            std::numeric_limits<std::size_t>::max() /
                sizeof(std::string)) {
            return std::nullopt;
        }
        vector_bytes = parsed.entries.capacity() * sizeof(std::string);
        if (!checked_add(vector_bytes,
                         string_storage_bytes,
                         parsed.conservative_bytes) ||
            parsed.conservative_bytes > max_conservative_bytes) {
            return std::nullopt;
        }
        parsed.normalized_characters = next_normalized;
    }
    return parsed;
}

std::optional<HostlistMatch> match_hostlist(
    const std::vector<std::string>& entries,
    const std::string& domain) {
    const auto needle = lower(trim(domain));
    if (needle.empty()) return std::nullopt;

    std::optional<HostlistMatch> best;
    for (const auto& raw : entries) {
        const auto entry = lower(raw);
        if (entry.empty()) continue;

        bool covers = false;
        bool exact = false;
        if (entry == needle) {
            covers = true;
            exact = true;
        } else if (needle.size() > entry.size() &&
                   needle.compare(needle.size() - entry.size(),
                                  entry.size(),
                                  entry) == 0 &&
                   needle[needle.size() - entry.size() - 1U] == '.') {
            // The dot is what keeps "youtube.com" from covering
            // "notyoutube.com": a suffix test alone would report the wrong
            // entry as the reason traffic is handled.
            covers = true;
        }
        if (!covers) continue;

        // Longer means more specific, and an exact hit beats any parent.
        if (!best || exact ||
            (!best->exact && raw.size() > best->entry.size())) {
            best = HostlistMatch{raw, exact};
            if (exact) break;
        }
    }
    return best;
}

std::optional<HostlistMatch> match_ipset(
    const std::vector<std::string>& entries,
    const std::string& ip) {
    const auto address = parse_prefix(trim(ip));
    if (!address) return std::nullopt;
    // A queried address is a single host; a prefix in the query position would
    // mean something this function does not answer.
    if (address->bits != (address->family == AF_INET6 ? 128 : 32)) {
        return std::nullopt;
    }

    std::optional<HostlistMatch> best;
    int best_bits = -1;
    for (const auto& raw : entries) {
        const auto prefix = parse_prefix(trim(raw));
        if (!prefix || !prefix_contains(*prefix, *address)) continue;
        // Narrowest wins: /32 out of a /8 is the entry that decided this.
        if (prefix->bits > best_bits) {
            best_bits = prefix->bits;
            const bool exact =
                prefix->bits == (prefix->family == AF_INET6 ? 128 : 32);
            best = HostlistMatch{raw, exact};
        }
    }
    return best;
}

} // namespace keen_pbr3::nfqws
