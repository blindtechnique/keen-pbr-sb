#include "interface_monitor.hpp"

#include "../log/logger.hpp"
#include "../util/format_compat.hpp"

#include <cerrno>
#include <algorithm>
#include <ifaddrs.h>
#include <cstring>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <sys/socket.h>
#include <unordered_map>

#include <netlink/attr.h>
#include <netlink/errno.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

namespace keen_pbr3 {

namespace {

constexpr int kLinkAttributeMax = IFLA_MAX + 1;

} // namespace

struct InterfaceMonitor::Impl {
    struct ObservedInterface {
        std::string name;
        bool is_up{false};
    };

    explicit Impl(InterfaceStateCallback callback)
        : callback(std::move(callback)) {}

    ~Impl() {
        close_socket();
    }

    static int on_nl_message(struct nl_msg* msg, void* arg) {
        auto* impl = static_cast<Impl*>(arg);
        if (!impl) {
            return NL_OK;
        }

        impl->handle_message(msg);
        return NL_OK;
    }

    void handle_message(struct nl_msg* msg) {
        if (!msg || !callback) {
            return;
        }

        struct nlmsghdr* hdr = nlmsg_hdr(msg);
        if (!hdr) {
            return;
        }

        if (hdr->nlmsg_type == RTM_NEWNEIGH ||
            hdr->nlmsg_type == RTM_DELNEIGH) {
            if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(ndmsg))) return;
            auto* neighbor = static_cast<ndmsg*>(nlmsg_data(hdr));
            // AF_BRIDGE is an FDB notification, not an IP neighbor hint.
            if (neighbor->ndm_family != AF_INET &&
                neighbor->ndm_family != AF_INET6) return;
            struct nlattr* attrs[NDA_MAX + 1] = {};
            if (nlmsg_parse(hdr, sizeof(*neighbor), attrs, NDA_MAX,
                            nullptr) < 0 || attrs[NDA_DST] == nullptr) return;
            const auto address_bytes = nla_len(attrs[NDA_DST]);
            const auto expected_bytes =
                neighbor->ndm_family == AF_INET ? 4 : 16;
            if (address_bytes != expected_bytes) return;
            NeighborObservation observation;
            observation.address_family = neighbor->ndm_family;
            if (neighbor->ndm_ifindex <= 0) return;
            observation.interface_index =
                static_cast<std::uint32_t>(neighbor->ndm_ifindex);
            observation.address.assign(
                static_cast<const char*>(nla_data(attrs[NDA_DST])),
                static_cast<std::size_t>(address_bytes));
            if (attrs[NDA_LLADDR] != nullptr) {
                const auto link_bytes = nla_len(attrs[NDA_LLADDR]);
                if (link_bytes < 0 || link_bytes > 32) return;
                observation.link_address.assign(
                    static_cast<const char*>(nla_data(attrs[NDA_LLADDR])),
                    static_cast<std::size_t>(link_bytes));
            }
            observation.state = neighbor->ndm_state;
            observation.present = hdr->nlmsg_type == RTM_NEWNEIGH;
            if (neighbors.observe(observation)) {
                Event event;
                event.neighbor_changed = true;
                callback(event);
            }
            return;
        }

        if (hdr->nlmsg_type == RTM_NEWROUTE ||
            hdr->nlmsg_type == RTM_DELROUTE) {
            auto* route = static_cast<rtmsg*>(nlmsg_data(hdr));
            if (!route) return;

            std::uint32_t table = route->rtm_table;
            struct nlattr* attrs[RTA_MAX + 1] = {};
            if (nlmsg_parse(
                    hdr,
                    sizeof(*route),
                    attrs,
                    RTA_MAX,
                    nullptr) >= 0 &&
                attrs[RTA_TABLE] != nullptr) {
                table = nla_get_u32(attrs[RTA_TABLE]);
            }
            const auto event =
                InterfaceMonitor::describe_route_transition(
                    table, route->rtm_family, route->rtm_dst_len == 0);
            if (event.has_value()) callback(*event);
            return;
        }

        if (hdr->nlmsg_type == RTM_NEWADDR || hdr->nlmsg_type == RTM_DELADDR) {
            auto* addr = static_cast<ifaddrmsg*>(nlmsg_data(hdr));
            if (!addr ||
                (addr->ifa_family != AF_INET && addr->ifa_family != AF_INET6)) {
                return;
            }
            char name[IF_NAMESIZE] = {};
            if (if_indextoname(addr->ifa_index, name) != nullptr) {
                callback(Event{
                    std::string(name),
                    false,
                    false,
                    true,
                    false,
                });
            }
            return;
        }

        if (hdr->nlmsg_type != RTM_NEWLINK &&
            hdr->nlmsg_type != RTM_DELLINK) {
            return;
        }

        auto* if_info = static_cast<ifinfomsg*>(nlmsg_data(hdr));
        if (!if_info) {
            return;
        }

        struct nlattr* attrs[kLinkAttributeMax] = {};
        const int parse_err = nlmsg_parse(hdr,
                                          sizeof(*if_info),
                                          attrs,
                                          IFLA_MAX,
                                          nullptr);
        if (parse_err < 0 || attrs[IFLA_IFNAME] == nullptr) {
            return;
        }

        const char* if_name_raw = static_cast<const char*>(nla_data(attrs[IFLA_IFNAME]));
        if (!if_name_raw || *if_name_raw == '\0') {
            return;
        }

        const std::string interface_name(if_name_raw);
        const bool is_up = (hdr->nlmsg_type == RTM_NEWLINK) && ((if_info->ifi_flags & IFF_UP) != 0);

        const auto interface_index =
            static_cast<unsigned int>(if_info->ifi_index);
        const auto previous = interface_state.find(interface_index);
        const auto previous_name =
            previous == interface_state.end()
                ? std::optional<std::string>{}
                : std::optional<std::string>{previous->second.name};
        const auto previous_is_up =
            previous == interface_state.end()
                ? std::optional<bool>{}
                : std::optional<bool>{previous->second.is_up};
        auto event = InterfaceMonitor::describe_indexed_link_transition(
            interface_name,
            hdr->nlmsg_type == RTM_NEWLINK,
            previous_name,
            previous_is_up,
            is_up);
        if (hdr->nlmsg_type == RTM_DELLINK) {
            interface_state.erase(interface_index);
        } else {
            interface_state[interface_index] =
                ObservedInterface{interface_name, is_up};
        }
        callback(event);
    }

    void close_socket() {
        if (!socket) {
            return;
        }
        nl_close(socket);
        nl_socket_free(socket);
        socket = nullptr;
    }

    void setup_socket() {
        close_socket();

        socket = nl_socket_alloc();
        if (!socket) {
            throw InterfaceMonitorError("Failed to allocate netlink socket for interface monitor");
        }

        int err = nl_connect(socket, NETLINK_ROUTE);
        if (err < 0) {
            close_socket();
            throw InterfaceMonitorError(
                format("Failed to connect interface monitor netlink socket: {}", nl_geterror(err)));
        }

        err = nl_socket_add_memberships(socket,
                                        RTNLGRP_LINK,
                                        RTNLGRP_IPV4_IFADDR,
                                        RTNLGRP_IPV6_IFADDR,
                                        RTNLGRP_IPV4_ROUTE,
                                        RTNLGRP_IPV6_ROUTE,
                                        0);
        if (err < 0) {
            close_socket();
            throw InterfaceMonitorError(
                format("Failed to subscribe interface monitor to link group: {}", nl_geterror(err)));
        }

#ifdef WITH_API
        // Hotspot acceleration is optional. Older kernels must retain their
        // established link/address/route monitor when this group is absent.
        err = nl_socket_add_memberships(socket, RTNLGRP_NEIGH, 0);
        if (err < 0) {
            Logger::instance().verbose(
                "Neighbor notifications are unavailable; hotspot metadata keeps its TTL fallback: {}",
                nl_geterror(err));
        }
#endif

        // libnl defaults to 32 KB each way. The firmware brings interfaces up
        // and down in bursts - most visibly during our own update - and the
        // kernel then overruns the socket buffer and answers ENOBUFS, which
        // libnl reports as "Out of memory". A megabyte absorbs those bursts.
        err = nl_socket_set_buffer_size(socket, 1024 * 1024, 1024 * 1024);
        if (err < 0) {
            // Not fatal: the default size still works, it just overruns sooner.
            Logger::instance().verbose(
                "Could not enlarge the interface monitor netlink buffer: {}",
                nl_geterror(err));
        }

        nl_socket_set_nonblocking(socket);
        nl_socket_disable_seq_check(socket);
        nl_socket_modify_cb(socket,
                            NL_CB_VALID,
                            NL_CB_CUSTOM,
                            &InterfaceMonitor::Impl::on_nl_message,
                            this);

        interface_state.clear();
        neighbors.clear();
        struct ifaddrs* interfaces = nullptr;
        if (getifaddrs(&interfaces) == 0) {
            for (auto* current = interfaces; current != nullptr;
                 current = current->ifa_next) {
                if (current->ifa_name != nullptr) {
                    const auto interface_index =
                        if_nametoindex(current->ifa_name);
                    if (interface_index != 0) {
                        interface_state[interface_index] =
                            ObservedInterface{
                                current->ifa_name,
                                (current->ifa_flags & IFF_UP) != 0,
                            };
                    }
                }
            }
            freeifaddrs(interfaces);
        }
    }

    InterfaceStateCallback callback;
    struct nl_sock* socket{nullptr};
    std::unordered_map<unsigned int, ObservedInterface> interface_state;
    NeighborHintTracker neighbors;
};

bool InterfaceMonitor::NeighborHintTracker::observe(
    const NeighborObservation& observation) {
    const bool ipv4 = observation.address_family == AF_INET;
    const bool ipv6 = observation.address_family == AF_INET6;
    if ((!ipv4 && !ipv6) || observation.interface_index == 0U ||
        observation.address.size() != (ipv4 ? 4U : 16U) ||
        observation.link_address.size() > 32U) return false;
    const auto first = static_cast<unsigned char>(observation.address[0]);
    const bool all_zero = std::all_of(
        observation.address.begin(), observation.address.end(),
        [](char byte) { return byte == 0; });
    const bool ipv4_broadcast = ipv4 && std::all_of(
        observation.address.begin(), observation.address.end(),
        [](char byte) { return static_cast<unsigned char>(byte) == 255U; });
    if (all_zero || ipv4_broadcast ||
        (ipv4 && (first & 0xf0U) == 0xe0U) ||
        (ipv6 && first == 0xffU)) return false;

    const Key key{observation.address_family, observation.interface_index,
                  observation.address};
    auto previous = entries_.find(key);
    if (!observation.present) {
        if (previous != entries_.end()) {
            entries_.erase(previous);
            const auto position = std::find(
                insertion_order_.begin(), insertion_order_.end(), key);
            if (position != insertion_order_.end()) {
                insertion_order_.erase(position);
            }
        }
        // A deleted neighbor can predate the monitor's startup/reconnect.
        return true;
    }
    const bool failed = (observation.state & NUD_FAILED) != 0U;
    const bool resolved = !observation.link_address.empty() &&
        (observation.state & (NUD_REACHABLE | NUD_STALE | NUD_DELAY |
                              NUD_PROBE | NUD_NOARP | NUD_PERMANENT)) != 0U;
    if (!failed && !resolved) return false;
    if (previous == entries_.end()) {
        if (entries_.size() >= max_entries) {
            entries_.erase(insertion_order_.front());
            insertion_order_.pop_front();
        }
        insertion_order_.push_back(key);
        try {
            entries_.emplace(key, State{observation.link_address, failed});
        } catch (...) {
            insertion_order_.pop_back();
            throw;
        }
        return true;
    }
    const bool changed = previous->second.failed != failed ||
        (!observation.link_address.empty() &&
         previous->second.link_address != observation.link_address);
    if (!observation.link_address.empty()) {
        previous->second.link_address = observation.link_address;
    }
    previous->second.failed = failed;
    return changed;
}

void InterfaceMonitor::NeighborHintTracker::clear() noexcept {
    entries_.clear();
    insertion_order_.clear();
}

InterfaceMonitor::InterfaceMonitor(InterfaceStateCallback callback)
    : impl_(std::make_unique<Impl>(std::move(callback))) {
    impl_->setup_socket();
}

InterfaceMonitor::~InterfaceMonitor() = default;

InterfaceMonitor::Event InterfaceMonitor::describe_link_transition(
    std::string interface_name,
    bool link_present,
    std::optional<bool> previous_is_up,
    bool is_up) {
    const auto previous_interface_name =
        previous_is_up.has_value()
            ? std::optional<std::string>{interface_name}
            : std::optional<std::string>{};
    return describe_indexed_link_transition(
        std::move(interface_name),
        link_present,
        previous_interface_name,
        previous_is_up,
        is_up);
}

InterfaceMonitor::Event InterfaceMonitor::describe_indexed_link_transition(
    std::string interface_name,
    bool link_present,
    std::optional<std::string> previous_interface_name,
    std::optional<bool> previous_is_up,
    bool is_up) {
    const bool same_identity_name =
        previous_interface_name.has_value() &&
        *previous_interface_name == interface_name;
    const bool topology_changed =
        !link_present || !same_identity_name;
    const bool administrative_state_changed =
        link_present &&
        same_identity_name &&
        previous_is_up.has_value() &&
        *previous_is_up != is_up;
    return Event{
        std::move(interface_name),
        administrative_state_changed,
        link_present && is_up,
        false,
        topology_changed,
    };
}

std::optional<InterfaceMonitor::Event>
InterfaceMonitor::describe_route_transition(
    std::uint32_t table,
    int address_family,
    bool default_route) {
    if (table != RT_TABLE_MAIN ||
        (address_family != AF_INET && address_family != AF_INET6)) {
        return std::nullopt;
    }
    Event event;
    event.route_changed = true;
    event.default_route_changed = default_route;
    return event;
}

int InterfaceMonitor::fd() const {
    if (!impl_ || !impl_->socket) {
        throw InterfaceMonitorError("Interface monitor socket is not initialized");
    }
    return nl_socket_get_fd(impl_->socket);
}

void InterfaceMonitor::handle_events() {
    if (!impl_ || !impl_->socket) {
        return;
    }

    while (true) {
        int err = nl_recvmsgs_default(impl_->socket);
        if (err == 0) {
            continue;
        }

        if (err == -NLE_AGAIN || errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }

        // ENOBUFS is not a failure, it is a gap: the kernel dropped events we
        // were too slow to read. The socket stays usable, so there is nothing
        // to reopen - and reopening here would invalidate the descriptor the
        // event loop is polling. Report an observation gap to the daemon so it
        // revokes cached NDMS authority and schedules a fresh topology read;
        // outbound probes do not rebuild the native-interface inventory.
        if (err == -NLE_NOMEM || errno == ENOBUFS) {
            impl_->neighbors.clear();
            Logger::instance().info(
                "Interface monitor fell behind and lost some link events; "
                "requesting a fresh topology observation");
            if (impl_->callback) {
                impl_->callback(Event{
                    {},
                    false,
                    false,
                    false,
                    false,
                    true,
                });
            }
            break;
        }

        throw InterfaceMonitorError(
            format("Failed to receive interface monitor netlink messages: {}", nl_geterror(err)));
    }
}

void InterfaceMonitor::reconnect() {
    if (!impl_) {
        return;
    }

    impl_->setup_socket();
}

} // namespace keen_pbr3
