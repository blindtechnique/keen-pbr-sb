#include "trusted_local_connection.hpp"

#ifdef WITH_API

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <set>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr auto kCredentialSnapshotMaximumAge = std::chrono::seconds{5};

struct ParsedAddress {
    int family{AF_UNSPEC};
    std::array<std::uint8_t, 16> bytes{};
    std::size_t size{0U};
};

std::optional<ParsedAddress> parse_address(
    const std::string_view value) noexcept {
    if (value.empty() || value.find('%') != std::string_view::npos) {
        return std::nullopt;
    }
    const std::string text{value};
    ParsedAddress parsed;
    in_addr ipv4{};
    if (inet_pton(AF_INET, text.c_str(), &ipv4) == 1) {
        parsed.family = AF_INET;
        parsed.size = sizeof(ipv4);
        std::memcpy(parsed.bytes.data(), &ipv4, sizeof(ipv4));
        return parsed;
    }

    in6_addr ipv6{};
    if (inet_pton(AF_INET6, text.c_str(), &ipv6) != 1) {
        return std::nullopt;
    }
    if (IN6_IS_ADDR_V4MAPPED(&ipv6)) {
        parsed.family = AF_INET;
        parsed.size = sizeof(in_addr);
        std::memcpy(parsed.bytes.data(), &ipv6.s6_addr[12], sizeof(in_addr));
        return parsed;
    }
    parsed.family = AF_INET6;
    parsed.size = sizeof(ipv6);
    std::memcpy(parsed.bytes.data(), &ipv6, sizeof(ipv6));
    return parsed;
}

bool equal_address(const ParsedAddress& left,
                   const ParsedAddress& right) noexcept {
    return left.family == right.family && left.size == right.size &&
           std::equal(left.bytes.begin(),
                      left.bytes.begin() +
                          static_cast<std::ptrdiff_t>(left.size),
                      right.bytes.begin());
}

bool loopback_address(const ParsedAddress& address) noexcept {
    if (address.family == AF_INET) return address.bytes[0] == 127U;
    if (address.family != AF_INET6) return false;
    return std::all_of(address.bytes.begin(), address.bytes.end() - 1,
                       [](const std::uint8_t byte) { return byte == 0U; }) &&
           address.bytes.back() == 1U;
}

bool unusable_peer_address(const ParsedAddress& address) noexcept {
    if (address.family == AF_INET) {
        return (address.bytes[0] == 0U) ||
               (address.bytes[0] == 169U && address.bytes[1] == 254U) ||
               (address.bytes[0] >= 224U);
    }
    if (address.family != AF_INET6) return true;
    const bool unspecified = std::all_of(
        address.bytes.begin(), address.bytes.end(),
        [](const std::uint8_t byte) { return byte == 0U; });
    const bool link_local =
        address.bytes[0] == 0xfeU && (address.bytes[1] & 0xc0U) == 0x80U;
    return unspecified || link_local || address.bytes[0] == 0xffU;
}

bool contiguous_netmask(const ParsedAddress& mask) noexcept {
    bool saw_zero = false;
    for (std::size_t index = 0U; index < mask.size; ++index) {
        for (int bit = 7; bit >= 0; --bit) {
            const bool set =
                (mask.bytes[index] & (1U << static_cast<unsigned int>(bit))) !=
                0U;
            if (!set) {
                saw_zero = true;
            } else if (saw_zero) {
                return false;
            }
        }
    }
    return true;
}

bool same_network(const ParsedAddress& left,
                  const ParsedAddress& right,
                  const ParsedAddress& mask) noexcept {
    if (left.family != right.family || left.family != mask.family ||
        left.size != right.size || left.size != mask.size ||
        !contiguous_netmask(mask)) {
        return false;
    }
    for (std::size_t index = 0U; index < left.size; ++index) {
        if ((left.bytes[index] & mask.bytes[index]) !=
            (right.bytes[index] & mask.bytes[index])) {
            return false;
        }
    }
    return true;
}

std::string numeric_address(const sockaddr* address) {
    if (address == nullptr) return {};
    std::array<char, INET6_ADDRSTRLEN> text{};
    const void* bytes = nullptr;
    int family = address->sa_family;
    if (family == AF_INET) {
        bytes = &reinterpret_cast<const sockaddr_in*>(address)->sin_addr;
    } else if (family == AF_INET6) {
        bytes = &reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr;
    } else {
        return {};
    }
    return inet_ntop(family, bytes, text.data(), text.size()) != nullptr
               ? std::string{text.data()}
               : std::string{};
}

class SocketHandle final {
public:
    explicit SocketHandle(const int value) noexcept : value_(value) {}
    ~SocketHandle() {
        if (value_ >= 0) close(value_);
    }
    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;
    int get() const noexcept { return value_; }

private:
    int value_{-1};
};

bool append_route_attribute(nlmsghdr& header,
                            const std::size_t capacity,
                            const std::uint16_t type,
                            const ParsedAddress& address) noexcept {
    const auto offset = NLMSG_ALIGN(header.nlmsg_len);
    const auto attribute_size = RTA_LENGTH(address.size);
    const auto required = offset + RTA_ALIGN(attribute_size);
    if (required > capacity) return false;
    auto* attribute = reinterpret_cast<rtattr*>(
        reinterpret_cast<std::uint8_t*>(&header) + offset);
    attribute->rta_type = type;
    attribute->rta_len = static_cast<unsigned short>(attribute_size);
    std::memcpy(RTA_DATA(attribute), address.bytes.data(), address.size);
    header.nlmsg_len = static_cast<std::uint32_t>(required);
    return true;
}

std::chrono::seconds remaining_seconds_rounded_up(
    const TrustedLocalConnectionCache::Clock::time_point now,
    const TrustedLocalConnectionCache::Clock::time_point expiry) noexcept {
    if (expiry <= now) return {};
    const auto milliseconds = std::chrono::duration_cast<
        std::chrono::milliseconds>(expiry - now);
    const auto rounded = (milliseconds.count() + 999LL) / 1000LL;
    return std::chrono::seconds{std::max<long long>(1LL, rounded)};
}

} // namespace

bool trusted_local_connection_is_proven(
    const std::string_view remote_address,
    const std::string_view local_address,
    const bool has_forwarding_headers,
    const TrustedLocalConnectionSnapshot& snapshot,
    const std::optional<TrustedLocalRouteProof>& route) noexcept {
    if (has_forwarding_headers) return false;
    const auto remote = parse_address(remote_address);
    const auto local = parse_address(local_address);
    if (!remote || !local || remote->family != local->family ||
        unusable_peer_address(*remote) || unusable_peer_address(*local) ||
        loopback_address(*remote) || loopback_address(*local)) {
        return false;
    }

    const bool ndms_verified = std::any_of(
        snapshot.verified_private_management_addresses.begin(),
        snapshot.verified_private_management_addresses.end(),
        [&](const std::string& address) {
            const auto candidate = parse_address(address);
            return candidate && equal_address(*candidate, *local);
        });
    if (!ndms_verified) return false;

    // More than one live link claiming the destination address is ambiguous.
    // Deduplicate identical getifaddrs rows, but never choose between distinct
    // interfaces or masks.
    std::set<std::string> matching_networks;
    std::set<std::string> on_link_networks;
    std::string matching_interface_name;
    for (const auto& interface : snapshot.interface_addresses) {
        if (!interface.up || interface.loopback ||
            interface.interface_name.empty()) {
            continue;
        }
        const auto interface_address = parse_address(interface.address);
        const auto netmask = parse_address(interface.netmask);
        if (!interface_address || !netmask ||
            !equal_address(*interface_address, *local) ||
            interface_address->family != netmask->family ||
            !contiguous_netmask(*netmask)) {
            continue;
        }
        const auto identity =
            interface.interface_name + "\n" + interface.address + "\n" +
            interface.netmask;
        matching_networks.insert(identity);
        matching_interface_name = interface.interface_name;
        if (same_network(*remote, *local, *netmask)) {
            on_link_networks.insert(identity);
        }
    }
    if (matching_networks.size() != 1U || on_link_networks.size() != 1U ||
        !route || !route->direct ||
        !route->scope_allows_connected_prefix ||
        route->interface_name != matching_interface_name) {
        return false;
    }
    const auto route_source = parse_address(route->source_address);
    const auto route_destination = parse_address(route->destination_address);
    return route_source && route_destination &&
           equal_address(*route_source, *local) &&
           equal_address(*route_destination, *remote);
}

std::vector<TrustedLocalInterfaceAddress>
system_trusted_local_interface_addresses() {
    ifaddrs* raw = nullptr;
    if (getifaddrs(&raw) != 0) return {};

    std::vector<TrustedLocalInterfaceAddress> result;
    for (const auto* current = raw; current != nullptr;
         current = current->ifa_next) {
        if (current->ifa_name == nullptr || current->ifa_addr == nullptr ||
            current->ifa_netmask == nullptr ||
            (current->ifa_addr->sa_family != AF_INET &&
             current->ifa_addr->sa_family != AF_INET6)) {
            continue;
        }
        auto address = numeric_address(current->ifa_addr);
        auto netmask = numeric_address(current->ifa_netmask);
        if (address.empty() || netmask.empty()) continue;
        result.push_back({
            current->ifa_name,
            std::move(address),
            std::move(netmask),
            (current->ifa_flags & IFF_UP) != 0,
            (current->ifa_flags & IFF_LOOPBACK) != 0,
        });
    }
    freeifaddrs(raw);
    return result;
}

std::optional<TrustedLocalRouteProof> system_trusted_local_route_proof(
    const std::string_view remote_address,
    const std::string_view local_address) noexcept {
    const auto remote = parse_address(remote_address);
    const auto local = parse_address(local_address);
    if (!remote || !local || remote->family != local->family ||
        unusable_peer_address(*remote) || unusable_peer_address(*local) ||
        loopback_address(*remote) || loopback_address(*local)) {
        return std::nullopt;
    }

    const SocketHandle socket_handle{
        socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)};
    if (socket_handle.get() < 0) return std::nullopt;
    const timeval timeout{0, 250000};
    if (setsockopt(socket_handle.get(), SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) != 0) {
        return std::nullopt;
    }

    alignas(nlmsghdr) std::array<std::uint8_t, 512> request_bytes{};
    auto& header = *reinterpret_cast<nlmsghdr*>(request_bytes.data());
    header.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    header.nlmsg_type = RTM_GETROUTE;
    header.nlmsg_flags = NLM_F_REQUEST;
    static std::atomic<std::uint32_t> sequence{1U};
    header.nlmsg_seq = sequence.fetch_add(1U, std::memory_order_relaxed);
    if (header.nlmsg_seq == 0U) {
        header.nlmsg_seq = sequence.fetch_add(1U, std::memory_order_relaxed);
    }
    auto& message = *reinterpret_cast<rtmsg*>(NLMSG_DATA(&header));
    message.rtm_family = static_cast<unsigned char>(remote->family);
    message.rtm_dst_len = static_cast<unsigned char>(remote->size * 8U);
    message.rtm_src_len = static_cast<unsigned char>(local->size * 8U);
    message.rtm_table = RT_TABLE_UNSPEC;
    message.rtm_protocol = RTPROT_UNSPEC;
    message.rtm_scope = RT_SCOPE_UNIVERSE;
    message.rtm_type = RTN_UNSPEC;
    if (!append_route_attribute(
            header, request_bytes.size(), RTA_DST, *remote) ||
        !append_route_attribute(
            header, request_bytes.size(), RTA_SRC, *local)) {
        return std::nullopt;
    }

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (sendto(socket_handle.get(), request_bytes.data(), header.nlmsg_len, 0,
               reinterpret_cast<const sockaddr*>(&kernel),
               sizeof(kernel)) != static_cast<ssize_t>(header.nlmsg_len)) {
        return std::nullopt;
    }

    alignas(nlmsghdr) std::array<std::uint8_t, 16384> response{};
    sockaddr_nl sender{};
    iovec vector{response.data(), response.size()};
    msghdr received{};
    received.msg_name = &sender;
    received.msg_namelen = sizeof(sender);
    received.msg_iov = &vector;
    received.msg_iovlen = 1U;
    const auto size = recvmsg(socket_handle.get(), &received, 0);
    if (size <= 0 || (received.msg_flags & MSG_TRUNC) != 0 ||
        received.msg_namelen != sizeof(sender) || sender.nl_pid != 0U) {
        return std::nullopt;
    }

    std::optional<TrustedLocalRouteProof> proof;
    int remaining = static_cast<int>(size);
    for (auto* current = reinterpret_cast<nlmsghdr*>(response.data());
         NLMSG_OK(current, remaining);
         current = NLMSG_NEXT(current, remaining)) {
        if (current->nlmsg_seq != header.nlmsg_seq) continue;
        if (current->nlmsg_type == NLMSG_ERROR ||
            current->nlmsg_type == NLMSG_DONE) {
            if (current->nlmsg_type == NLMSG_ERROR) return std::nullopt;
            continue;
        }
        if (current->nlmsg_type != RTM_NEWROUTE || proof ||
            current->nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg))) {
            return std::nullopt;
        }
        const auto* route_message =
            reinterpret_cast<const rtmsg*>(NLMSG_DATA(current));
        if (route_message->rtm_family != remote->family ||
            route_message->rtm_type != RTN_UNICAST ||
            (route_message->rtm_scope != RT_SCOPE_LINK &&
             route_message->rtm_scope != RT_SCOPE_UNIVERSE)) {
            return std::nullopt;
        }

        std::optional<int> output_index;
        bool indirect = false;
        int attributes_length = RTM_PAYLOAD(current);
        for (auto* attribute = RTM_RTA(route_message);
             RTA_OK(attribute, attributes_length);
             attribute = RTA_NEXT(attribute, attributes_length)) {
            if (attribute->rta_type == RTA_GATEWAY ||
                attribute->rta_type == RTA_VIA ||
                attribute->rta_type == RTA_MULTIPATH ||
                attribute->rta_type == RTA_NEWDST ||
                attribute->rta_type == RTA_ENCAP ||
                attribute->rta_type == RTA_ENCAP_TYPE) {
                indirect = true;
            }
            if (attribute->rta_type != RTA_OIF) continue;
            if (output_index || RTA_PAYLOAD(attribute) != sizeof(int)) {
                return std::nullopt;
            }
            int value = 0;
            std::memcpy(&value, RTA_DATA(attribute), sizeof(value));
            if (value <= 0) return std::nullopt;
            output_index = value;
        }
        if (!output_index || indirect) return std::nullopt;
        std::array<char, IF_NAMESIZE> interface_name{};
        if (if_indextoname(
                static_cast<unsigned int>(*output_index),
                interface_name.data()) == nullptr) {
            return std::nullopt;
        }
        proof = TrustedLocalRouteProof{
            std::string{local_address},
            std::string{remote_address},
            std::string{interface_name.data()},
            true,
            true,
        };
    }
    if (remaining != 0) return std::nullopt;
    return proof;
}

TrustedLocalConnectionCache::TrustedLocalConnectionCache(
    Loader loader,
    const std::chrono::seconds ttl,
    Now now,
    RouteLookup route_lookup)
    : loader_(std::move(loader)),
      route_lookup_(std::move(route_lookup)),
      ttl_(ttl > std::chrono::seconds::zero()
               ? ttl
               : std::chrono::seconds{1}),
      now_(std::move(now)) {}

TrustedLocalConnectionDecision TrustedLocalConnectionCache::evaluate(
    const std::string_view remote_address,
    const std::string_view local_address,
    const bool has_forwarding_headers,
    const bool require_credential_freshness) {
    // Headers are attacker-controlled and can never improve the verdict. Do
    // not spend a cached/uncached NDMS read on a request already known unsafe.
    if (has_forwarding_headers) return {};
    if (!route_lookup_) return {};
    const auto route = route_lookup_(remote_address, local_address);
    if (!route || !route->direct ||
        !route->scope_allows_connected_prefix) {
        return {};
    }

    std::optional<TrustedLocalConnectionSnapshot> snapshot;
    std::uint64_t generation = 0U;
    std::chrono::seconds valid_for{};
    {
        const std::lock_guard lock(mutex_);
        const auto now = now_ ? now_() : Clock::now();
        const bool credential_snapshot_stale =
            require_credential_freshness && loaded_ &&
            now >= refreshed_at_ + kCredentialSnapshotMaximumAge;
        if (!loaded_ || now >= refresh_after_ || credential_snapshot_stale) {
            snapshot_ = loader_ ? loader_() : std::nullopt;
            loaded_ = true;
            refreshed_at_ = now;
            refresh_after_ = now + ttl_;
            if (++evidence_generation_ == 0U) ++evidence_generation_;
        }
        snapshot = snapshot_;
        generation = evidence_generation_;
        auto evidence_expiry = refresh_after_;
        if (require_credential_freshness) {
            evidence_expiry = std::min(
                evidence_expiry,
                refreshed_at_ + kCredentialSnapshotMaximumAge);
        }
        valid_for = remaining_seconds_rounded_up(now, evidence_expiry);
    }
    if (!snapshot || valid_for <= std::chrono::seconds::zero()) {
        return {};
    }
    const bool trusted = trusted_local_connection_is_proven(
        remote_address, local_address, false, *snapshot, route);
    return TrustedLocalConnectionDecision{
        trusted,
        trusted ? generation : 0U,
        trusted ? valid_for : std::chrono::seconds{},
    };
}

void TrustedLocalConnectionCache::invalidate() {
    const std::lock_guard lock(mutex_);
    snapshot_.reset();
    loaded_ = false;
    refreshed_at_ = {};
    refresh_after_ = {};
}

} // namespace keen_pbr3

#endif // WITH_API
