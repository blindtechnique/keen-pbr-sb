#include "fib_lookup.hpp"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <climits>
#include <cstring>

namespace keen_pbr3 {

namespace {

struct ParsedDestination {
    int family{AF_UNSPEC};
    std::array<std::uint8_t, 16> bytes{};
    std::size_t size{0U};
};

std::optional<ParsedDestination> parse_destination(
    const std::string& value) noexcept {
    if (value.empty() || value.size() >= INET6_ADDRSTRLEN) return std::nullopt;
    ParsedDestination parsed;
    if (inet_pton(AF_INET, value.c_str(), parsed.bytes.data()) == 1) {
        parsed.family = AF_INET;
        parsed.size = 4U;
        return parsed;
    }
    if (inet_pton(AF_INET6, value.c_str(), parsed.bytes.data()) == 1) {
        parsed.family = AF_INET6;
        parsed.size = 16U;
        return parsed;
    }
    return std::nullopt;
}

class SocketHandle {
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

bool append_attribute(nlmsghdr& header,
                      const std::size_t capacity,
                      const std::uint16_t type,
                      const void* data,
                      const std::size_t length) noexcept {
    const auto offset = NLMSG_ALIGN(header.nlmsg_len);
    const auto attribute_size = RTA_LENGTH(length);
    const auto required = offset + RTA_ALIGN(attribute_size);
    if (required > capacity) return false;
    auto* attribute = reinterpret_cast<rtattr*>(
        reinterpret_cast<std::uint8_t*>(&header) + offset);
    attribute->rta_type = type;
    attribute->rta_len = static_cast<unsigned short>(attribute_size);
    std::memcpy(RTA_DATA(attribute), data, length);
    header.nlmsg_len = static_cast<std::uint32_t>(required);
    return true;
}

FibAnswer no_verdict(std::string detail) noexcept {
    FibAnswer answer;
    answer.verdict = FibVerdict::unavailable;
    answer.detail = std::move(detail);
    return answer;
}

bool refusing_route_type(const unsigned char type) noexcept {
    return type == RTN_UNREACHABLE || type == RTN_BLACKHOLE ||
           type == RTN_PROHIBIT || type == RTN_THROW;
}

}  // namespace

FibAnswer parse_fib_reply(const void* bytes,
                          const std::size_t size,
                          const std::uint32_t sequence,
                          const int family,
                          const std::optional<std::uint32_t> requested_mark)
    noexcept {
    if (bytes == nullptr || size == 0U ||
        size > static_cast<std::size_t>(INT_MAX)) {
        return no_verdict("the kernel returned nothing");
    }

    int remaining = static_cast<int>(size);
    // Read-only walk; the macros need a mutable pointer to do their arithmetic.
    auto* current =
        const_cast<nlmsghdr*>(static_cast<const nlmsghdr*>(bytes));
    for (; NLMSG_OK(current, remaining); current = NLMSG_NEXT(current, remaining)) {
        if (current->nlmsg_seq != sequence) continue;
        if (current->nlmsg_type == NLMSG_ERROR) {
            if (current->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
                return no_verdict("the kernel refused the question");
            }
            const auto* failure =
                static_cast<const nlmsgerr*>(NLMSG_DATA(current));
            if (failure->error == 0) continue;
            const int code = failure->error < 0 ? -failure->error : failure->error;
            return no_verdict(std::string{"the kernel refused the question: "} +
                              std::strerror(code));
        }
        if (current->nlmsg_type == NLMSG_DONE) continue;
        if (current->nlmsg_type != RTM_NEWROUTE) continue;
        if (current->nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg))) {
            return no_verdict("the kernel's answer was too short to read");
        }

        const auto* route = static_cast<const rtmsg*>(NLMSG_DATA(current));
        if (family != AF_UNSPEC && route->rtm_family != family) continue;

        std::optional<int> output_index;
        std::optional<std::uint32_t> table;
        std::optional<std::uint32_t> echoed_mark;
        int attributes_length = RTM_PAYLOAD(current);
        for (auto* attribute = RTM_RTA(const_cast<rtmsg*>(route));
             RTA_OK(attribute, attributes_length);
             attribute = RTA_NEXT(attribute, attributes_length)) {
            switch (attribute->rta_type) {
                case RTA_OIF: {
                    if (RTA_PAYLOAD(attribute) != sizeof(int)) break;
                    int value = 0;
                    std::memcpy(&value, RTA_DATA(attribute), sizeof(value));
                    if (value > 0) output_index = value;
                    break;
                }
                case RTA_TABLE: {
                    if (RTA_PAYLOAD(attribute) != sizeof(std::uint32_t)) break;
                    std::uint32_t value = 0;
                    std::memcpy(&value, RTA_DATA(attribute), sizeof(value));
                    table = value;
                    break;
                }
                case RTA_MARK: {
                    if (RTA_PAYLOAD(attribute) != sizeof(std::uint32_t)) break;
                    std::uint32_t value = 0;
                    std::memcpy(&value, RTA_DATA(attribute), sizeof(value));
                    echoed_mark = value;
                    break;
                }
                default:
                    break;
            }
        }
        if (!table && route->rtm_table != RT_TABLE_UNSPEC) {
            table = route->rtm_table;
        }

        // The echo rule. Without it an old kernel would answer confidently
        // about a packet we never asked about - see the header.
        if (requested_mark && *requested_mark != 0U &&
            (!echoed_mark || *echoed_mark != *requested_mark)) {
            auto answer = no_verdict(
                "this kernel does not report the packet mark back, so its "
                "answer describes unmarked traffic and cannot be trusted here");
            answer.table = table;
            return answer;
        }

        if (refusing_route_type(route->rtm_type)) {
            FibAnswer answer;
            answer.verdict = FibVerdict::unroutable;
            answer.table = table;
            answer.detail =
                "the kernel refuses to route this packet - a kill-switch looks "
                "exactly like this";
            return answer;
        }

        if (!output_index) {
            auto answer = no_verdict(
                "the kernel answered without naming an outgoing interface");
            answer.table = table;
            return answer;
        }

        std::array<char, IF_NAMESIZE> interface_name{};
        if (if_indextoname(static_cast<unsigned int>(*output_index),
                           interface_name.data()) == nullptr) {
            auto answer = no_verdict(
                "the kernel named an interface index that no longer exists");
            answer.table = table;
            return answer;
        }

        FibAnswer answer;
        answer.verdict = FibVerdict::resolved;
        answer.interface = interface_name.data();
        answer.table = table;
        return answer;
    }

    return no_verdict("the kernel did not answer the question that was asked");
}

FibAnswer system_fib_lookup(const FibQuery& query) noexcept {
    const auto destination = parse_destination(query.destination);
    if (!destination) {
        return no_verdict("not an address this can ask about");
    }

    const SocketHandle socket_handle{
        socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)};
    if (socket_handle.get() < 0) {
        return no_verdict("no netlink socket");
    }
    const timeval timeout{0, 250000};
    if (setsockopt(socket_handle.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0) {
        return no_verdict("no netlink socket");
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
    message.rtm_family = static_cast<unsigned char>(destination->family);
    message.rtm_dst_len = static_cast<unsigned char>(destination->size * 8U);
    message.rtm_table = RT_TABLE_UNSPEC;
    message.rtm_protocol = RTPROT_UNSPEC;
    message.rtm_scope = RT_SCOPE_UNIVERSE;
    message.rtm_type = RTN_UNSPEC;

    if (!append_attribute(header, request_bytes.size(), RTA_DST,
                          destination->bytes.data(), destination->size)) {
        return no_verdict("the question did not fit in a netlink message");
    }
    if (query.fwmark) {
        const std::uint32_t mark = *query.fwmark;
        if (!append_attribute(header, request_bytes.size(), RTA_MARK, &mark,
                              sizeof(mark))) {
            return no_verdict("the question did not fit in a netlink message");
        }
    }

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (sendto(socket_handle.get(), request_bytes.data(), header.nlmsg_len, 0,
               reinterpret_cast<const sockaddr*>(&kernel),
               sizeof(kernel)) != static_cast<ssize_t>(header.nlmsg_len)) {
        return no_verdict("the question could not be sent to the kernel");
    }

    alignas(nlmsghdr) std::array<std::uint8_t, 8192> response{};
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
        return no_verdict("the kernel did not answer in time");
    }

    return parse_fib_reply(response.data(), static_cast<std::size_t>(size),
                           header.nlmsg_seq, destination->family, query.fwmark);
}

}  // namespace keen_pbr3
