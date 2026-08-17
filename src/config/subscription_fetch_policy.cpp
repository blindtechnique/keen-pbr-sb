#include "subscription_fetch_policy.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace keen_pbr3 {

namespace {

std::string lowercased(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](const unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });
    return value;
}

SubscriptionDestinationVerdict judge_ipv4(const in_addr& address) noexcept {
    const auto host = ntohl(address.s_addr);
    const auto octet = [host](const unsigned shift) {
        return static_cast<std::uint8_t>((host >> shift) & 0xFFU);
    };
    const auto first = octet(24U);
    const auto second = octet(16U);
    const auto third = octet(8U);

    if (host == 0U) return SubscriptionDestinationVerdict::unspecified;
    if (first == 127U) return SubscriptionDestinationVerdict::loopback;
    if (first == 10U) return SubscriptionDestinationVerdict::private_network;
    if (first == 172U && second >= 16U && second <= 31U) {
        return SubscriptionDestinationVerdict::private_network;
    }
    if (first == 192U && second == 168U) {
        return SubscriptionDestinationVerdict::private_network;
    }
    // 169.254.0.0/16 - link local, and the address family cloud metadata
    // services live on. On this router it is also where an unconfigured
    // interface lands.
    if (first == 169U && second == 254U) {
        return SubscriptionDestinationVerdict::link_local;
    }
    // 100.64.0.0/10 carrier-grade NAT: not the operator's own network, but
    // not the public internet either, and reachable from a router.
    if (first == 100U && second >= 64U && second <= 127U) {
        return SubscriptionDestinationVerdict::private_network;
    }
    if (first >= 224U && first <= 239U) {
        return SubscriptionDestinationVerdict::multicast_or_broadcast;
    }
    if (host == 0xFFFFFFFFU) {
        return SubscriptionDestinationVerdict::multicast_or_broadcast;
    }
    // 0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24,
    // 203.0.113.0/24 and 240.0.0.0/4 are all special-use. None of them is a
    // place a subscription legitimately lives.
    if (first == 0U) return SubscriptionDestinationVerdict::reserved;
    if (first == 192U && second == 0U) {
        return SubscriptionDestinationVerdict::reserved;
    }
    // 192.88.99.0/24 - the deprecated 6to4 relay anycast block. It is not a
    // public destination even though it sits outside the broader 192.0/16
    // protocol-assignment block above.
    if (first == 192U && second == 88U && third == 99U) {
        return SubscriptionDestinationVerdict::reserved;
    }
    if (first == 198U && (second == 18U || second == 19U)) {
        return SubscriptionDestinationVerdict::reserved;
    }
    if (first == 198U && second == 51U) {
        return SubscriptionDestinationVerdict::reserved;
    }
    if (first == 203U && second == 0U) {
        return SubscriptionDestinationVerdict::reserved;
    }
    if (first >= 240U) return SubscriptionDestinationVerdict::reserved;
    return SubscriptionDestinationVerdict::allowed;
}

SubscriptionDestinationVerdict judge_ipv6(const in6_addr& address) noexcept {
    const auto* bytes = address.s6_addr;
    const auto all_zero_prefix = [bytes](const std::size_t count) {
        for (std::size_t i = 0U; i < count; ++i) {
            if (bytes[i] != 0U) return false;
        }
        return true;
    };

    if (all_zero_prefix(16U)) {
        return SubscriptionDestinationVerdict::unspecified;
    }
    if (all_zero_prefix(15U) && bytes[15] == 1U) {
        return SubscriptionDestinationVerdict::loopback;
    }
    if (bytes[0] == 0xFFU) {
        return SubscriptionDestinationVerdict::multicast_or_broadcast;
    }
    // fe80::/10 link local.
    if (bytes[0] == 0xFEU && (bytes[1] & 0xC0U) == 0x80U) {
        return SubscriptionDestinationVerdict::link_local;
    }
    // fc00::/7 unique local.
    if ((bytes[0] & 0xFEU) == 0xFCU) {
        return SubscriptionDestinationVerdict::unique_local;
    }
    // ::ffff:0:0/96 - an IPv4 address wearing an IPv6 coat. Judged as the
    // IPv4 address it actually is, or this is a one-line bypass of every rule
    // above.
    if (all_zero_prefix(10U) && bytes[10] == 0xFFU && bytes[11] == 0xFFU) {
        in_addr mapped{};
        std::uint32_t raw = 0U;
        for (std::size_t i = 12U; i < 16U; ++i) {
            raw = (raw << 8U) | bytes[i];
        }
        mapped.s_addr = htonl(raw);
        return judge_ipv4(mapped);
    }
    // 2002::/16 6to4 and 64:ff9b::/96 NAT64 embed IPv4 too; both are ways to
    // reach an address this policy would otherwise judge.
    if (bytes[0] == 0x20U && bytes[1] == 0x02U) {
        in_addr embedded{};
        std::uint32_t raw = 0U;
        for (std::size_t i = 2U; i < 6U; ++i) {
            raw = (raw << 8U) | bytes[i];
        }
        embedded.s_addr = htonl(raw);
        const auto verdict = judge_ipv4(embedded);
        return verdict == SubscriptionDestinationVerdict::allowed
                   ? SubscriptionDestinationVerdict::allowed
                   : verdict;
    }
    if (bytes[0] == 0x00U && bytes[1] == 0x64U && bytes[2] == 0xFFU &&
        bytes[3] == 0x9BU) {
        in_addr embedded{};
        std::uint32_t raw = 0U;
        for (std::size_t i = 12U; i < 16U; ++i) {
            raw = (raw << 8U) | bytes[i];
        }
        embedded.s_addr = htonl(raw);
        const auto verdict = judge_ipv4(embedded);
        return verdict == SubscriptionDestinationVerdict::allowed
                   ? SubscriptionDestinationVerdict::allowed
                   : verdict;
    }

    // Native public IPv6 unicast is allocated from 2000::/3. Rejecting
    // everything else closes deprecated site-local (fec0::/10), discard-only
    // (100::/64), IPv4-compatible and future/reserved space instead of
    // silently treating every syntactically valid IPv6 address as public.
    // IPv4-mapped, 6to4 and NAT64 were handled above because their embedded
    // IPv4 destination is the authority.
    if ((bytes[0] & 0xE0U) != 0x20U) {
        return SubscriptionDestinationVerdict::reserved;
    }

    // IETF protocol assignments under 2001::/23 (including Teredo,
    // benchmarking and ORCHID) and documentation prefixes are special-use,
    // not subscription origins. 3ffe::/16 is the retired 6bone block and
    // 3fff::/20 is documentation space.
    if (bytes[0] == 0x20U && bytes[1] == 0x01U &&
        (bytes[2] <= 0x01U ||
         (bytes[2] == 0x0DU && bytes[3] == 0xB8U))) {
        return SubscriptionDestinationVerdict::reserved;
    }
    if (bytes[0] == 0x3FU && bytes[1] == 0xFEU) {
        return SubscriptionDestinationVerdict::reserved;
    }
    if (bytes[0] == 0x3FU && bytes[1] == 0xFFU &&
        (bytes[2] & 0xF0U) == 0x00U) {
        return SubscriptionDestinationVerdict::reserved;
    }
    return SubscriptionDestinationVerdict::allowed;
}

} // namespace

SubscriptionDestinationVerdict subscription_destination_permitted(
    const std::string& address) noexcept {
    if (address.empty()) {
        return SubscriptionDestinationVerdict::unparsable;
    }
    // A scope suffix (fe80::1%br0) is stripped before parsing; the address in
    // front of it is what decides, and it is link-local anyway. Keep this
    // allocation-free: the function is noexcept and is called from libcurl's
    // socket callback, so an allocating substr() would turn memory pressure
    // into std::terminate instead of a fail-closed refusal.
    const auto scope = address.find('%');
    std::array<char, INET6_ADDRSTRLEN> scoped_address{};
    const char* bare = address.c_str();
    if (scope != std::string::npos) {
        if (scope == 0U || scope >= scoped_address.size()) {
            return SubscriptionDestinationVerdict::unparsable;
        }
        std::memcpy(scoped_address.data(), address.data(), scope);
        scoped_address[scope] = '\0';
        bare = scoped_address.data();
    }

    in_addr v4{};
    if (::inet_pton(AF_INET, bare, &v4) == 1) {
        return judge_ipv4(v4);
    }
    in6_addr v6{};
    if (::inet_pton(AF_INET6, bare, &v6) == 1) {
        return judge_ipv6(v6);
    }
    // Not an address at all. This function is the last gate before a
    // connection, so anything it cannot understand is refused.
    return SubscriptionDestinationVerdict::unparsable;
}

SubscriptionUrlVerdict classify_subscription_url(const std::string& url) {
    // The scheme is read up to the first colon, not up to "://". Schemes that
    // carry their payload inline - data:, javascript: - have no authority at
    // all, and reporting those as merely malformed would hide the actual
    // reason they are refused.
    const auto colon = url.find(':');
    if (colon == std::string::npos || colon == 0U) {
        return SubscriptionUrlVerdict::malformed;
    }
    const auto scheme = lowercased(url.substr(0U, colon));
    const bool scheme_token_valid =
        (std::isalpha(static_cast<unsigned char>(scheme.front())) != 0) &&
        std::all_of(scheme.begin(), scheme.end(),
                    [](const unsigned char ch) {
                        return std::isalnum(ch) != 0 || ch == '+' ||
                               ch == '-' || ch == '.';
                    });
    if (!scheme_token_valid) return SubscriptionUrlVerdict::malformed;
    if (scheme != "http" && scheme != "https") {
        return SubscriptionUrlVerdict::scheme_not_allowed;
    }
    if (url.compare(colon, 3U, "://") != 0) {
        return SubscriptionUrlVerdict::malformed;
    }

    const auto authority_begin = colon + 3U;
    auto authority_end = url.find_first_of("/?#", authority_begin);
    if (authority_end == std::string::npos) authority_end = url.size();
    const auto authority =
        url.substr(authority_begin, authority_end - authority_begin);
    if (authority.empty()) return SubscriptionUrlVerdict::malformed;

    // Everything before an '@' is userinfo. Checked before the host is even
    // extracted, because "http://user:pass@host/" would otherwise parse as a
    // perfectly ordinary URL with a secret in it.
    if (authority.find('@') != std::string::npos) {
        return SubscriptionUrlVerdict::credentials_in_url;
    }

    std::string host = authority;
    if (!host.empty() && host.front() == '[') {
        // Bracketed IPv6 literal.
        const auto close = host.find(']');
        if (close == std::string::npos) return SubscriptionUrlVerdict::malformed;
        host = host.substr(1U, close - 1U);
    } else {
        const auto colon = host.find(':');
        if (colon != std::string::npos) host = host.substr(0U, colon);
    }
    if (host.empty()) return SubscriptionUrlVerdict::malformed;

    // Only literal addresses are judged here. A hostname is left to stage 2 at
    // connect time - resolving it now would produce an answer that the later
    // connection is under no obligation to reuse.
    const auto destination = subscription_destination_permitted(host);
    if (destination == SubscriptionDestinationVerdict::unparsable) {
        return SubscriptionUrlVerdict::allowed;
    }
    return destination == SubscriptionDestinationVerdict::allowed
               ? SubscriptionUrlVerdict::allowed
               : SubscriptionUrlVerdict::destination_not_permitted;
}

const char* subscription_url_verdict_name(
    const SubscriptionUrlVerdict verdict) noexcept {
    switch (verdict) {
    case SubscriptionUrlVerdict::allowed:
        return "allowed";
    case SubscriptionUrlVerdict::scheme_not_allowed:
        return "scheme_not_allowed";
    case SubscriptionUrlVerdict::credentials_in_url:
        return "credentials_in_url";
    case SubscriptionUrlVerdict::destination_not_permitted:
        return "destination_not_permitted";
    case SubscriptionUrlVerdict::malformed:
        return "malformed";
    }
    return "malformed";
}

const char* subscription_destination_verdict_name(
    const SubscriptionDestinationVerdict verdict) noexcept {
    switch (verdict) {
    case SubscriptionDestinationVerdict::allowed:
        return "allowed";
    case SubscriptionDestinationVerdict::loopback:
        return "loopback";
    case SubscriptionDestinationVerdict::private_network:
        return "private_network";
    case SubscriptionDestinationVerdict::link_local:
        return "link_local";
    case SubscriptionDestinationVerdict::unique_local:
        return "unique_local";
    case SubscriptionDestinationVerdict::multicast_or_broadcast:
        return "multicast_or_broadcast";
    case SubscriptionDestinationVerdict::unspecified:
        return "unspecified";
    case SubscriptionDestinationVerdict::reserved:
        return "reserved";
    case SubscriptionDestinationVerdict::unparsable:
        return "unparsable";
    }
    return "unparsable";
}

} // namespace keen_pbr3
