#include "interface_monitor.hpp"

#include "../log/logger.hpp"
#include "../util/format_compat.hpp"

#include <cerrno>
#include <cstring>
#include <net/if.h>
#include <linux/rtnetlink.h>
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

        impl->handle_link_message(msg);
        return NL_OK;
    }

    void handle_link_message(struct nl_msg* msg) {
        if (!msg || !callback) {
            return;
        }

        struct nlmsghdr* hdr = nlmsg_hdr(msg);
        if (!hdr) {
            return;
        }

        if (hdr->nlmsg_type != RTM_NEWLINK && hdr->nlmsg_type != RTM_DELLINK) {
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

        const auto previous = interface_state.find(interface_name);
        if (previous != interface_state.end() && previous->second == is_up) {
            return;
        }

        interface_state[interface_name] = is_up;
        callback(interface_name, is_up);
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

        err = nl_socket_add_memberships(socket, RTNLGRP_LINK, 0);
        if (err < 0) {
            close_socket();
            throw InterfaceMonitorError(
                format("Failed to subscribe interface monitor to link group: {}", nl_geterror(err)));
        }

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
    }

    InterfaceStateCallback callback;
    struct nl_sock* socket{nullptr};
    std::unordered_map<std::string, bool> interface_state;
};

InterfaceMonitor::InterfaceMonitor(InterfaceStateCallback callback)
    : impl_(std::make_unique<Impl>(std::move(callback))) {
    impl_->setup_socket();
}

InterfaceMonitor::~InterfaceMonitor() = default;

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
        // event loop is polling. Later events still arrive, and the interface
        // probe re-reads the real state every 20 seconds anyway, so a missed
        // link change corrects itself without troubling the user.
        if (err == -NLE_NOMEM || errno == ENOBUFS) {
            Logger::instance().verbose(
                "Interface monitor fell behind and lost some link events; "
                "state will be picked up by the next probe");
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
