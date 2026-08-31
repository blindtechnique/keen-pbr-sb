#include "netlink.hpp"
#include "policy_rule.hpp"
#include "raw_rtnetlink_codec.hpp"
#include "route_table.hpp"

#include "../log/logger.hpp"
#include "../util/format_compat.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <linux/fib_rules.h>
#include <iterator>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <map>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <netlink/cache.h>
#include <netlink/errno.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/rule.h>
#include <netlink/route/nexthop.h>

namespace keen_pbr3 {

namespace netlink_detail {

InterfaceAdminState query_interface_admin_state(
    const std::string& interface_name) noexcept {
    if (interface_name.empty() || interface_name.size() >= IFNAMSIZ) {
        return InterfaceAdminState::Missing;
    }

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return InterfaceAdminState::Unknown;
    }

    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    const int rc = ioctl(fd, SIOCGIFFLAGS, &ifr);
    const int saved_errno = errno;
    close(fd);
    if (rc < 0) {
        if (saved_errno == ENODEV || saved_errno == ENXIO ||
            saved_errno == ENOENT) {
            return InterfaceAdminState::Missing;
        }
        return InterfaceAdminState::Unknown;
    }

    return (ifr.ifr_flags & IFF_UP) != 0
        ? InterfaceAdminState::Up
        : InterfaceAdminState::Down;
}

bool route_delete_target_absent(int error_code) noexcept {
    return error_code == -NLE_OBJ_NOTFOUND || error_code == -NLE_NODEV;
}

} // namespace netlink_detail

namespace {

// Convert an nl_addr to its canonical string form, preserving prefix length.
std::string nl_addr_to_str(struct nl_addr* addr) {
    if (!addr) return "";
    char buf[128];
    nl_addr2str(addr, buf, sizeof(buf));
    return buf;
}

// RAII wrapper for nl_cache
struct CacheDeleter {
    void operator()(struct nl_cache* c) const {
        if (c) nl_cache_free(c);
    }
};
using CachePtr = std::unique_ptr<struct nl_cache, CacheDeleter>;

// Parse an IP address string to nl_addr, auto-detecting family.
// For CIDR notation (e.g., "10.0.0.0/8"), the prefix length is preserved.
// For plain IPs, uses host prefix length (32 for v4, 128 for v6).
struct NlAddrDeleter {
    void operator()(struct nl_addr* a) const {
        if (a) nl_addr_put(a);
    }
};
using NlAddrPtr = std::unique_ptr<struct nl_addr, NlAddrDeleter>;

NlAddrPtr parse_addr(const std::string& addr_str, int hint_family = AF_UNSPEC) {
    struct nl_addr* addr = nullptr;
    int err = nl_addr_parse(addr_str.c_str(), hint_family, &addr);
    if (err < 0) {
        throw NetlinkError("Failed to parse address '" + addr_str + "': " +
                           nl_geterror(err));
    }
    return NlAddrPtr(addr);
}

int detect_family(const std::string& addr_str) {
    if (addr_str.find(':') != std::string::npos) {
        return AF_INET6;
    }
    return AF_INET;
}

// RAII wrapper for rtnl_route
struct RouteDeleter {
    void operator()(struct rtnl_route* r) const {
        if (r) rtnl_route_put(r);
    }
};
using RoutePtr = std::unique_ptr<struct rtnl_route, RouteDeleter>;

// RAII wrapper for rtnl_nexthop
struct NexthopDeleter {
    void operator()(struct rtnl_nexthop* nh) const {
        if (nh) rtnl_route_nh_free(nh);
    }
};
using NexthopPtr = std::unique_ptr<struct rtnl_nexthop, NexthopDeleter>;

// RAII wrapper for rtnl_rule
struct RuleDeleter {
    void operator()(struct rtnl_rule* r) const {
        if (r) rtnl_rule_put(r);
    }
};
using RulePtr = std::unique_ptr<struct rtnl_rule, RuleDeleter>;

class RawNetlinkSocketHandle final {
public:
    explicit RawNetlinkSocketHandle(int value) noexcept : value_(value) {}
    ~RawNetlinkSocketHandle() {
        if (value_ >= 0) close(value_);
    }
    RawNetlinkSocketHandle(const RawNetlinkSocketHandle&) = delete;
    RawNetlinkSocketHandle& operator=(
        const RawNetlinkSocketHandle&) = delete;
    RawNetlinkSocketHandle(
        RawNetlinkSocketHandle&& other) noexcept
        : value_(other.value_) {
        other.value_ = -1;
    }
    RawNetlinkSocketHandle& operator=(
        RawNetlinkSocketHandle&& other) noexcept {
        if (this == &other) return *this;
        if (value_ >= 0) close(value_);
        value_ = other.value_;
        other.value_ = -1;
        return *this;
    }

    int get() const noexcept { return value_; }

private:
    int value_{-1};
};

struct RawInterfaceNames final {
    std::vector<std::string> names;
    std::vector<RawRtnetlinkInterfaceName> views;
};

RawInterfaceNames snapshot_raw_interface_names() {
    RawInterfaceNames result;
    struct if_nameindex* raw = if_nameindex();
    if (raw == nullptr) return result;

    struct InterfaceNameList final {
        explicit InterfaceNameList(struct if_nameindex* value) noexcept
            : value(value) {}
        ~InterfaceNameList() {
            if (value != nullptr) if_freenameindex(value);
        }
        struct if_nameindex* value;
    } retained{raw};

    for (auto* current = raw;
         current->if_index != 0U && current->if_name != nullptr;
         ++current) {
        result.names.emplace_back(current->if_name);
    }
    result.views.reserve(result.names.size());
    std::size_t index = 0U;
    for (auto* current = raw;
         current->if_index != 0U && current->if_name != nullptr;
         ++current, ++index) {
        result.views.push_back(
            RawRtnetlinkInterfaceName{
                static_cast<std::uint32_t>(current->if_index),
                result.names[index].c_str()});
    }
    return result;
}

std::uint32_t next_raw_rtnetlink_sequence() noexcept {
    static std::atomic<std::uint32_t> sequence{1U};
    auto value = sequence.fetch_add(1U, std::memory_order_relaxed);
    if (value == 0U) {
        value = sequence.fetch_add(1U, std::memory_order_relaxed);
    }
    return value;
}

struct RawDumpSocket final {
    RawNetlinkSocketHandle handle{-1};
    std::uint32_t port_id{0U};
    std::uint32_t sequence{0U};
};

class NetlinkManagerExactTransactionLease final
    : public ExactRoutingTransactionLease {
public:
    explicit NetlinkManagerExactTransactionLease(
        std::recursive_mutex& mutex)
        : lock_(mutex) {}

private:
    std::unique_lock<std::recursive_mutex> lock_;
};

RawDumpSocket open_raw_dump_socket(
    std::uint16_t message_type,
    int family) {
    RawDumpSocket socket_state;
    socket_state.handle = RawNetlinkSocketHandle{
        socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)};
    if (socket_state.handle.get() < 0) {
        throw NetlinkError(
            std::string{"Failed to open raw rtnetlink socket: "} +
            std::strerror(errno));
    }

    const timeval timeout{1, 0};
    if (setsockopt(
            socket_state.handle.get(),
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            sizeof(timeout)) != 0) {
        throw NetlinkError(
            std::string{"Failed to configure raw rtnetlink timeout: "} +
            std::strerror(errno));
    }

    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    if (bind(
            socket_state.handle.get(),
            reinterpret_cast<const sockaddr*>(&local),
            sizeof(local)) != 0) {
        throw NetlinkError(
            std::string{"Failed to bind raw rtnetlink socket: "} +
            std::strerror(errno));
    }
    socklen_t local_size = sizeof(local);
    if (getsockname(
            socket_state.handle.get(),
            reinterpret_cast<sockaddr*>(&local),
            &local_size) != 0 ||
        local_size != sizeof(local) ||
        local.nl_family != AF_NETLINK ||
        local.nl_pid == 0U) {
        throw NetlinkError(
            "Failed to resolve raw rtnetlink port identity");
    }
    socket_state.port_id = local.nl_pid;
    socket_state.sequence = next_raw_rtnetlink_sequence();

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    const auto send_request = [&](const void* request,
                                  std::size_t request_size) {
        const auto* header =
            static_cast<const nlmsghdr*>(request);
        const auto sent = sendto(
            socket_state.handle.get(),
            request,
            request_size,
            0,
            reinterpret_cast<const sockaddr*>(&kernel),
            sizeof(kernel));
        if (sent != static_cast<ssize_t>(request_size) ||
            header->nlmsg_len != request_size) {
            throw NetlinkError(
                std::string{"Failed to request raw rtnetlink inventory: "} +
                std::strerror(errno));
        }
    };
    const auto initialize_header = [&](nlmsghdr& header,
                                       std::size_t payload_size) {
        header.nlmsg_len = NLMSG_LENGTH(payload_size);
        header.nlmsg_type = message_type;
        header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        header.nlmsg_seq = socket_state.sequence;
        header.nlmsg_pid = socket_state.port_id;
    };

    if (message_type == RTM_GETROUTE) {
        struct RawRouteDumpRequest final {
            nlmsghdr header;
            rtmsg route;
        } request{};
        initialize_header(request.header, sizeof(request.route));
        request.route.rtm_family =
            static_cast<unsigned char>(family);
        send_request(&request, request.header.nlmsg_len);
    } else if (message_type == RTM_GETRULE) {
        struct RawRuleDumpRequest final {
            nlmsghdr header;
            fib_rule_hdr rule;
        } request{};
        initialize_header(request.header, sizeof(request.rule));
        request.rule.family =
            static_cast<unsigned char>(family);
        send_request(&request, request.header.nlmsg_len);
    } else {
        throw NetlinkError(
            "Unsupported raw rtnetlink inventory request");
    }
    return socket_state;
}

std::string raw_dump_failure(
    const char* kind,
    RawRtnetlinkDumpState state,
    int kernel_error) {
    if (state == RawRtnetlinkDumpState::kernel_error &&
        kernel_error != 0) {
        const int code =
            kernel_error < 0 ? -kernel_error : kernel_error;
        return keen_pbr3::format(
            "Raw rtnetlink {} dump failed: {}",
            kind,
            std::strerror(code));
    }
    return keen_pbr3::format(
        "Raw rtnetlink {} dump is incomplete (state={})",
        kind,
        static_cast<int>(state));
}

std::vector<DumpedRoute> dump_raw_routes(int family) {
    auto socket_state = open_raw_dump_socket(RTM_GETROUTE, family);
    const auto interfaces = snapshot_raw_interface_names();
    RawRtnetlinkDumpOptions options;
    options.sequence = socket_state.sequence;
    options.port_id = socket_state.port_id;
    options.interface_names = interfaces.views.data();
    options.interface_name_count = interfaces.views.size();

    std::vector<DumpedRoute> result;
    for (;;) {
        alignas(nlmsghdr) std::array<std::uint8_t, 65536> response{};
        sockaddr_nl sender{};
        iovec vector{response.data(), response.size()};
        msghdr received{};
        received.msg_name = &sender;
        received.msg_namelen = sizeof(sender);
        received.msg_iov = &vector;
        received.msg_iovlen = 1U;
        const auto size = recvmsg(
            socket_state.handle.get(), &received, 0);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0 || (received.msg_flags & MSG_TRUNC) != 0 ||
            received.msg_namelen != sizeof(sender) ||
            sender.nl_pid != 0U) {
            throw NetlinkError(
                "Raw rtnetlink route dump did not complete");
        }
        auto block = parse_raw_rtnetlink_route_dump_block(
            response.data(), static_cast<std::size_t>(size), options);
        if (block.state != RawRtnetlinkDumpState::more &&
            block.state != RawRtnetlinkDumpState::done) {
            throw NetlinkError(raw_dump_failure(
                "route", block.state, block.kernel_error));
        }
        result.insert(
            result.end(),
            std::make_move_iterator(block.routes.begin()),
            std::make_move_iterator(block.routes.end()));
        if (block.state == RawRtnetlinkDumpState::done) return result;
    }
}

std::vector<DumpedRule> dump_raw_rules(int family) {
    auto socket_state = open_raw_dump_socket(RTM_GETRULE, family);
    RawRtnetlinkDumpOptions options;
    options.sequence = socket_state.sequence;
    options.port_id = socket_state.port_id;

    std::vector<DumpedRule> result;
    for (;;) {
        alignas(nlmsghdr) std::array<std::uint8_t, 65536> response{};
        sockaddr_nl sender{};
        iovec vector{response.data(), response.size()};
        msghdr received{};
        received.msg_name = &sender;
        received.msg_namelen = sizeof(sender);
        received.msg_iov = &vector;
        received.msg_iovlen = 1U;
        const auto size = recvmsg(
            socket_state.handle.get(), &received, 0);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0 || (received.msg_flags & MSG_TRUNC) != 0 ||
            received.msg_namelen != sizeof(sender) ||
            sender.nl_pid != 0U) {
            throw NetlinkError(
                "Raw rtnetlink rule dump did not complete");
        }
        auto block = parse_raw_rtnetlink_rule_dump_block(
            response.data(), static_cast<std::size_t>(size), options);
        if (block.state != RawRtnetlinkDumpState::more &&
            block.state != RawRtnetlinkDumpState::done) {
            throw NetlinkError(raw_dump_failure(
                "rule", block.state, block.kernel_error));
        }
        result.insert(
            result.end(),
            std::make_move_iterator(block.rules.begin()),
            std::make_move_iterator(block.rules.end()));
        if (block.state == RawRtnetlinkDumpState::done) return result;
    }
}

int route_family(const RouteSpec& spec) {
    if (spec.family != 0) {
        return spec.family;
    }
    if (spec.destination == "default") {
        return AF_INET;
    }
    return detect_family(spec.destination);
}

// Build the exact libnl object used by add/replace/delete. A missing output
// interface is transient for installation, while deletion is already complete
// because Linux removes routes when their interface vanishes.
RoutePtr build_route(const RouteSpec& spec,
                     bool missing_interface_means_absent = false) {
    const int family = route_family(spec);
    RoutePtr route(rtnl_route_alloc());
    if (!route) {
        throw NetlinkError("Failed to allocate route object");
    }

    rtnl_route_set_family(route.get(), family);
    rtnl_route_set_scope(route.get(), RT_SCOPE_UNIVERSE);
    if (spec.table != 0) {
        rtnl_route_set_table(route.get(), spec.table);
    }
    // Zero is part of route identity: urltest keeps metric-zero primary and
    // metric-N fallbacks in the same table.
    rtnl_route_set_priority(route.get(), spec.metric);
    rtnl_route_set_protocol(route.get(), spec.protocol);

    if (spec.destination == "default") {
        NlAddrPtr dst = parse_addr(
            family == AF_INET6 ? "::/0" : "0.0.0.0/0", family);
        rtnl_route_set_dst(route.get(), dst.get());
    } else {
        NlAddrPtr dst = parse_addr(spec.destination, family);
        rtnl_route_set_dst(route.get(), dst.get());
    }

    if (spec.blackhole) {
        rtnl_route_set_type(route.get(), RTN_BLACKHOLE);
        return route;
    }
    if (spec.unreachable) {
        rtnl_route_set_type(route.get(), RTN_UNREACHABLE);
        return route;
    }

    // Route type is part of exact delete identity.  Leaving it unset makes an
    // RTM_DELROUTE request a wildcard over foreign same-slot route types.
    rtnl_route_set_type(route.get(), RTN_UNICAST);

    NexthopPtr nh(rtnl_route_nh_alloc());
    if (!nh) {
        throw NetlinkError("Failed to allocate nexthop object");
    }
    if (spec.interface) {
        const unsigned int ifindex = if_nametoindex(spec.interface->c_str());
        if (ifindex == 0) {
            if (missing_interface_means_absent) {
                return {};
            }
            throw RouteInterfaceUnavailableError(
                "Interface not found: " + *spec.interface);
        }
        rtnl_route_nh_set_ifindex(nh.get(), static_cast<int>(ifindex));
    }
    if (spec.gateway) {
        NlAddrPtr gw = parse_addr(*spec.gateway, family);
        rtnl_route_nh_set_gateway(nh.get(), gw.get());
    }
    rtnl_route_add_nexthop(route.get(), nh.release());
    return route;
}

} // anonymous namespace

struct NetlinkManager::Impl {
    struct nl_sock* sock{nullptr};

    Impl() {
        sock = nl_socket_alloc();
        if (!sock) {
            throw NetlinkError("Failed to allocate netlink socket");
        }
        int err = nl_connect(sock, NETLINK_ROUTE);
        if (err < 0) {
#ifdef KEEN_PBR3_TESTING
            nl_socket_free(sock);
            sock = nullptr;
            return;
#else
            nl_socket_free(sock);
            throw NetlinkError(std::string("Failed to connect netlink socket: ") +
                               nl_geterror(err));
#endif
        }
    }

    ~Impl() {
        if (sock) {
            nl_close(sock);
            nl_socket_free(sock);
        }
    }
};

NetlinkManager::NetlinkManager() : impl_(std::make_unique<Impl>()) {}

NetlinkManager::~NetlinkManager() = default;

bool NetlinkManager::supports_exact_route_transaction() const noexcept {
    return true;
}

bool NetlinkManager::supports_exact_rule_transaction() const noexcept {
    return true;
}

std::unique_ptr<ExactRoutingTransactionLease>
NetlinkManager::acquire_exact_transaction_lease() {
    return std::make_unique<NetlinkManagerExactTransactionLease>(
        exact_transaction_mutex_);
}

RouteAddResult NetlinkManager::add_route(const RouteSpec& spec) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);
    KPBR_LOCK_GUARD(mutex_);
    const int family = route_family(spec);
    RoutePtr route = build_route(spec);

    int err = rtnl_route_add(impl_->sock, route.get(), NLM_F_CREATE | NLM_F_EXCL);
    if (err < 0) {
        if (err == -NLE_EXIST) {
            return RouteAddResult::AlreadyPresent;
        }
        if (err == -NLE_NODEV) {
            throw RouteInterfaceUnavailableError(keen_pbr3::format(
                "Route interface is unavailable: {} (dst={}, table={}, iface={})",
                nl_geterror(err),
                spec.destination,
                spec.table,
                spec.interface.value_or("(none)")));
        }
        throw NetlinkError(keen_pbr3::format(
            "Failed to add route: {} (dst={}, table={}, iface={}, gw={}, family={}, blackhole={})",
            nl_geterror(err),
            spec.destination,
            spec.table,
            spec.interface.value_or("(none)"),
            spec.gateway.value_or("(none)"),
            family,
            spec.blackhole));
    }
    return RouteAddResult::Created;
}

void NetlinkManager::replace_route(const RouteSpec& spec) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);
    KPBR_LOCK_GUARD(mutex_);
    const int family = route_family(spec);
    RoutePtr route = build_route(spec);

    const int err = rtnl_route_add(
        impl_->sock, route.get(), NLM_F_CREATE | NLM_F_REPLACE);
    if (err < 0) {
        if (err == -NLE_NODEV) {
            throw RouteInterfaceUnavailableError(keen_pbr3::format(
                "Route interface is unavailable during replacement: {} (dst={}, table={}, iface={})",
                nl_geterror(err),
                spec.destination,
                spec.table,
                spec.interface.value_or("(none)")));
        }
        throw NetlinkError(keen_pbr3::format(
            "Failed to replace managed route: {} (dst={}, table={}, iface={}, gw={}, family={}, metric={})",
            nl_geterror(err),
            spec.destination,
            spec.table,
            spec.interface.value_or("(none)"),
            spec.gateway.value_or("(none)"),
            family,
            spec.metric));
    }
}

void NetlinkManager::delete_route(const RouteSpec& spec) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);
    KPBR_LOCK_GUARD(mutex_);
    RoutePtr route = build_route(spec, true);
    if (!route) {
        return;
    }

    int err = rtnl_route_delete(impl_->sock, route.get(), 0);
    if (err < 0) {
        if (netlink_detail::route_delete_target_absent(err)) {
            return;
        }
        throw NetlinkError(std::string("Failed to delete route: ") + nl_geterror(err));
    }
}

RouteExactDeleteResult NetlinkManager::delete_route_if_exact(
    const RouteSpec& expected) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);

    const auto live = dump_raw_routes(route_family(expected));
    const DumpedRoute* match = nullptr;
    std::size_t slot_count = 0U;
    for (const auto& candidate : live) {
        if (!route_table_detail::route_occupies_same_slot(
                expected, candidate)) {
            continue;
        }
        ++slot_count;
        if (candidate.exact_identity_representable &&
            route_table_detail::route_matches_live(expected, candidate)) {
            match = &candidate;
        }
    }
    if (slot_count == 0U) {
        return RouteExactDeleteResult::AlreadyAbsent;
    }
    if (slot_count != 1U || match == nullptr) {
        return RouteExactDeleteResult::PreconditionMismatch;
    }

    // Delete the concrete image observed under the combined route+rule lease.
    // In particular this carries IPv6's materialized metric 1024 instead of
    // sending metric zero, which RTM_DELROUTE otherwise treats as a wildcard.
    delete_route(route_table_detail::route_spec_from_live(*match));

    const auto after = dump_raw_routes(route_family(expected));
    const bool slot_still_occupied = std::any_of(
        after.begin(), after.end(), [&](const DumpedRoute& candidate) {
            return route_table_detail::route_occupies_same_slot(
                expected, candidate);
        });
    if (slot_still_occupied) {
        throw NetlinkError(
            "Exact route delete did not produce an empty kernel slot");
    }
    return RouteExactDeleteResult::Deleted;
}

RouteExactReplaceResult NetlinkManager::replace_route_if_exact(
    const RouteSpec& expected,
    const RouteSpec& replacement) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);

    const int expected_family = route_family(expected);
    const int replacement_family = route_family(replacement);
    const auto normalized_metric = [](const RouteSpec& route) {
        return route_family(route) == AF_INET6 && route.metric == 0U
            ? 1024U
            : route.metric;
    };
    if (expected.destination != replacement.destination ||
        expected.table != replacement.table ||
        expected_family != replacement_family ||
        normalized_metric(expected) != normalized_metric(replacement)) {
        return RouteExactReplaceResult::PreconditionMismatch;
    }

    const auto live = dump_raw_routes(expected_family);
    const DumpedRoute* match = nullptr;
    std::size_t slot_count = 0U;
    for (const auto& candidate : live) {
        if (!route_table_detail::route_occupies_same_slot(
                expected, candidate)) {
            continue;
        }
        ++slot_count;
        if (candidate.exact_identity_representable &&
            route_table_detail::route_matches_live(expected, candidate)) {
            match = &candidate;
        }
    }
    if (slot_count != 1U || match == nullptr) {
        return RouteExactReplaceResult::PreconditionMismatch;
    }

    // Keep the kernel slot continuously populated: a single RTM_NEWROUTE
    // REPLACE updates the prevalidated route while the keen-pbr route/rule
    // writer lease is held. The raw post-read below verifies the result.
    replace_route(replacement);

    const auto after = dump_raw_routes(replacement_family);
    std::size_t replacement_slot_count = 0U;
    bool replacement_present = false;
    for (const auto& candidate : after) {
        if (!route_table_detail::route_occupies_same_slot(
                replacement, candidate)) {
            continue;
        }
        ++replacement_slot_count;
        replacement_present = replacement_present ||
            (candidate.exact_identity_representable &&
             route_table_detail::route_matches_live(
                 replacement, candidate));
    }
    if (replacement_slot_count != 1U || !replacement_present) {
        throw NetlinkError(
            "Exact route replacement could not be re-observed");
    }
    return RouteExactReplaceResult::Replaced;
}

void NetlinkManager::flush_routes_in_table(uint32_t table_id, int family) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);
    KPBR_LOCK_GUARD(mutex_);

    struct nl_cache* raw_cache = nullptr;
    int err = rtnl_route_alloc_cache(impl_->sock, family, 0, &raw_cache);
    if (err < 0) {
        throw NetlinkError(std::string("Failed to alloc route cache: ") +
                           nl_geterror(err));
    }
    CachePtr cache(raw_cache);

    std::vector<RoutePtr> routes_to_delete;
    nl_cache_foreach(cache.get(), [](struct nl_object* obj, void* arg) {
        auto* routes = static_cast<std::vector<RoutePtr>*>(arg);
        auto* route = reinterpret_cast<struct rtnl_route*>(obj);
        if (rtnl_route_get_table(route) == 0) {
            return;
        }
        rtnl_route_get(route);
        routes->emplace_back(route);
    }, &routes_to_delete);

    for (auto& route : routes_to_delete) {
        if (rtnl_route_get_table(route.get()) != table_id) {
            continue;
        }
        try {
            int delete_err = rtnl_route_delete(impl_->sock, route.get(), 0);
            if (delete_err < 0) {
                throw NetlinkError(std::string("Failed to delete route during flush: ") +
                                   nl_geterror(delete_err));
            }
        } catch (const std::exception& e) {
            Logger::instance().warn("flush_routes_in_table: failed to delete route in table {}: {}",
                                    table_id, e.what());
        } catch (...) {
            Logger::instance().warn("flush_routes_in_table: failed to delete route in table {} (unknown error)",
                                    table_id);
        }
    }
}

RuleAddResult NetlinkManager::add_rule_for_family(const RuleSpec& spec, int family) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);
    KPBR_LOCK_GUARD(mutex_);

    RulePtr rule(rtnl_rule_alloc());
    if (!rule) {
        throw NetlinkError("Failed to allocate rule object");
    }

    rtnl_rule_set_family(rule.get(), family);
    rtnl_rule_set_table(rule.get(), spec.table);
    rtnl_rule_set_mark(rule.get(), spec.fwmark);
    rtnl_rule_set_mask(rule.get(), spec.fwmask);

    if (spec.priority != 0) {
        rtnl_rule_set_prio(rule.get(), spec.priority);
    }

    rtnl_rule_set_action(rule.get(), FR_ACT_TO_TBL);

    const int err = rtnl_rule_add(impl_->sock, rule.get(), NLM_F_CREATE | NLM_F_EXCL);
    if (err == -NLE_EXIST) {
        return RuleAddResult::AlreadyPresent;
    }
    if (err < 0) {
        throw NetlinkError(std::string("Failed to add rule (family ") +
                           std::to_string(family) + "): " + nl_geterror(err));
    }
    return RuleAddResult::Created;
}

void NetlinkManager::delete_rule_for_family(const RuleSpec& spec, int family) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);
    KPBR_LOCK_GUARD(mutex_);

    RulePtr rule(rtnl_rule_alloc());
    if (!rule) {
        throw NetlinkError("Failed to allocate rule object");
    }

    rtnl_rule_set_family(rule.get(), family);
    rtnl_rule_set_table(rule.get(), spec.table);
    rtnl_rule_set_mark(rule.get(), spec.fwmark);
    rtnl_rule_set_mask(rule.get(), spec.fwmask);

    if (spec.priority != 0) {
        rtnl_rule_set_prio(rule.get(), spec.priority);
    }

    rtnl_rule_set_action(rule.get(), FR_ACT_TO_TBL);

    const int err = rtnl_rule_delete(impl_->sock, rule.get(), 0);
    if (err < 0) {
        if (netlink_detail::route_delete_target_absent(err)) {
            return;
        }
        throw NetlinkError(std::string("Failed to delete rule (family ") +
                           std::to_string(family) + "): " + nl_geterror(err));
    }
}

RuleExactDeleteResult NetlinkManager::delete_rule_if_exact(
    const RuleSpec& spec,
    int family) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);
    if (family != AF_INET && family != AF_INET6) {
        return RuleExactDeleteResult::PreconditionMismatch;
    }

    RuleSpec expected = spec;
    expected.family = family;
    const auto live = dump_raw_rules(family);
    const DumpedRule* match = nullptr;
    std::size_t identity_count = 0U;
    for (const auto& candidate : live) {
        if (!policy_rule_detail::rule_matches_live(expected, candidate)) {
            continue;
        }
        ++identity_count;
        if (candidate.exact_identity_representable) {
            match = &candidate;
        }
    }
    if (identity_count == 0U) {
        return RuleExactDeleteResult::AlreadyAbsent;
    }
    if (identity_count != 1U || match == nullptr) {
        return RuleExactDeleteResult::PreconditionMismatch;
    }

    delete_rule_for_family(expected, family);

    const auto after = dump_raw_rules(family);
    const bool still_present = std::any_of(
        after.begin(), after.end(), [&](const DumpedRule& candidate) {
            return policy_rule_detail::rule_matches_live(
                expected, candidate);
        });
    if (still_present) {
        throw NetlinkError(
            "Exact policy-rule delete could not be re-observed");
    }
    return RuleExactDeleteResult::Deleted;
}

std::vector<DumpedRoute> NetlinkManager::dump_routes(int family) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);
    return dump_raw_routes(family);
}

std::vector<DumpedRoute> NetlinkManager::dump_routes_in_table(uint32_t table_id,
                                                              int family) {
    auto routes = dump_routes(family);
    routes.erase(
        std::remove_if(routes.begin(), routes.end(),
                       [table_id](const DumpedRoute& route) {
                           return route.table != table_id;
                       }),
        routes.end());
    return routes;
}

std::vector<DumpedRule> NetlinkManager::dump_policy_rules(int family) {
    std::lock_guard<std::recursive_mutex> exact_guard(
        exact_transaction_mutex_);
    return dump_raw_rules(family);
}

std::vector<DumpedInterface> NetlinkManager::dump_interfaces() {
    KPBR_LOCK_GUARD(mutex_);

    struct nl_cache* raw_link_cache = nullptr;
    int err = rtnl_link_alloc_cache(impl_->sock, AF_UNSPEC, &raw_link_cache);
    if (err < 0) {
        throw NetlinkError(std::string("Failed to alloc link cache: ") +
                           nl_geterror(err));
    }
    CachePtr link_cache(raw_link_cache);

    struct nl_cache* raw_addr_cache = nullptr;
    err = rtnl_addr_alloc_cache(impl_->sock, &raw_addr_cache);
    if (err < 0) {
        throw NetlinkError(std::string("Failed to alloc address cache: ") +
                           nl_geterror(err));
    }
    CachePtr addr_cache(raw_addr_cache);

    std::map<int, DumpedInterface> interfaces_by_index;

    nl_cache_foreach(link_cache.get(), [](struct nl_object* obj, void* arg) {
        auto* interfaces = static_cast<std::map<int, DumpedInterface>*>(arg);
        auto* link = reinterpret_cast<struct rtnl_link*>(obj);

        const int ifindex = rtnl_link_get_ifindex(link);
        const char* ifname = rtnl_link_get_name(link);
        if (ifindex <= 0 || ifname == nullptr || *ifname == '\0') {
            return;
        }

        DumpedInterface dumped;
        dumped.name = ifname;
        dumped.admin_up = (rtnl_link_get_flags(link) & IFF_UP) != 0;

        const int oper_state = rtnl_link_get_operstate(link);
        if (oper_state >= 0) {
            char oper_state_buf[32];
            const char* rendered = rtnl_link_operstate2str(
                oper_state,
                oper_state_buf,
                sizeof(oper_state_buf));
            if (rendered != nullptr && *rendered != '\0') {
                dumped.oper_state = rendered;
            }
        }

        const int carrier = rtnl_link_get_carrier(link);
        if (carrier >= 0) {
            dumped.carrier = carrier > 0;
        }

        interfaces->insert_or_assign(ifindex, std::move(dumped));
    }, &interfaces_by_index);

    // Resolve bridge/master ownership in a second pass: libnl does not
    // guarantee that the master link appears before its port in the cache.
    nl_cache_foreach(link_cache.get(), [](struct nl_object* obj, void* arg) {
        auto* interfaces = static_cast<std::map<int, DumpedInterface>*>(arg);
        auto* link = reinterpret_cast<struct rtnl_link*>(obj);
        const int ifindex = rtnl_link_get_ifindex(link);
        const int master_ifindex = rtnl_link_get_master(link);
        if (ifindex <= 0 || master_ifindex <= 0) {
            return;
        }
        const auto interface_it = interfaces->find(ifindex);
        const auto master_it = interfaces->find(master_ifindex);
        if (interface_it == interfaces->end() ||
            master_it == interfaces->end()) {
            return;
        }
        interface_it->second.master_interface =
            master_it->second.name;
    }, &interfaces_by_index);

    nl_cache_foreach(addr_cache.get(), [](struct nl_object* obj, void* arg) {
        auto* interfaces = static_cast<std::map<int, DumpedInterface>*>(arg);
        auto* addr = reinterpret_cast<struct rtnl_addr*>(obj);

        const int ifindex = rtnl_addr_get_ifindex(addr);
        if (ifindex <= 0) {
            return;
        }

        struct nl_addr* local = rtnl_addr_get_local(addr);
        if (!local) {
            return;
        }
        struct nl_addr* peer = rtnl_addr_get_peer(addr);

        auto interface_it = interfaces->find(ifindex);
        if (interface_it == interfaces->end()) {
            char ifname[IF_NAMESIZE];
            if (!if_indextoname(static_cast<unsigned int>(ifindex), ifname)) {
                return;
            }

            DumpedInterface dumped;
            dumped.name = ifname;
            interface_it = interfaces->insert({ifindex, std::move(dumped)}).first;
        }

        const std::string rendered = nl_addr_to_str(local);
        if (rendered.empty()) {
            return;
        }

        switch (nl_addr_get_family(local)) {
        case AF_INET:
            interface_it->second.ipv4_addresses.push_back(rendered);
            if (peer != nullptr) {
                const std::string rendered_peer = nl_addr_to_str(peer);
                if (!rendered_peer.empty() && rendered_peer != rendered) {
                    interface_it->second.ipv4_peer_addresses.push_back(
                        rendered_peer);
                }
            }
            break;
        case AF_INET6:
            interface_it->second.ipv6_addresses.push_back(rendered);
            if (peer != nullptr) {
                const std::string rendered_peer = nl_addr_to_str(peer);
                if (!rendered_peer.empty() && rendered_peer != rendered) {
                    interface_it->second.ipv6_peer_addresses.push_back(
                        rendered_peer);
                }
            }
            break;
        default:
            break;
        }
    }, &interfaces_by_index);

    std::vector<DumpedInterface> result;
    result.reserve(interfaces_by_index.size());
    for (auto& [ifindex, dumped] : interfaces_by_index) {
        (void)ifindex;
        std::sort(dumped.ipv4_addresses.begin(), dumped.ipv4_addresses.end());
        std::sort(dumped.ipv6_addresses.begin(), dumped.ipv6_addresses.end());
        std::sort(
            dumped.ipv4_peer_addresses.begin(),
            dumped.ipv4_peer_addresses.end());
        dumped.ipv4_peer_addresses.erase(
            std::unique(
                dumped.ipv4_peer_addresses.begin(),
                dumped.ipv4_peer_addresses.end()),
            dumped.ipv4_peer_addresses.end());
        std::sort(
            dumped.ipv6_peer_addresses.begin(),
            dumped.ipv6_peer_addresses.end());
        dumped.ipv6_peer_addresses.erase(
            std::unique(
                dumped.ipv6_peer_addresses.begin(),
                dumped.ipv6_peer_addresses.end()),
            dumped.ipv6_peer_addresses.end());
        result.push_back(std::move(dumped));
    }

    std::sort(result.begin(), result.end(), [](const DumpedInterface& lhs, const DumpedInterface& rhs) {
        return lhs.name < rhs.name;
    });

    return result;
}

} // namespace keen_pbr3
