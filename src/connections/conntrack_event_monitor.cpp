#include "conntrack_event_monitor.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <stdexcept>

namespace keen_pbr3 {

namespace {

constexpr std::size_t receive_buffer_size = 64U * 1024U;

std::string system_error(const char* operation) {
    return std::string(operation) + ": " + std::strerror(errno);
}

} // namespace

std::uint32_t conntrack_multicast_groups() noexcept {
    return (1U << (NFNLGRP_CONNTRACK_NEW - 1U)) |
           (1U << (NFNLGRP_CONNTRACK_UPDATE - 1U)) |
           (1U << (NFNLGRP_CONNTRACK_DESTROY - 1U));
}

std::uint64_t count_conntrack_messages(const void* data,
                                       std::size_t size) noexcept {
    if (data == nullptr || size < sizeof(nlmsghdr)) return 0;

    std::uint64_t count = 0;
    auto remaining = static_cast<int>(size);
    for (auto* header =
             reinterpret_cast<const nlmsghdr*>(data);
         NLMSG_OK(header, remaining);
         header = NLMSG_NEXT(header, remaining)) {
        if (header->nlmsg_type == NLMSG_ERROR ||
            header->nlmsg_type == NLMSG_DONE) {
            continue;
        }
        if (NFNL_SUBSYS_ID(header->nlmsg_type) != NFNL_SUBSYS_CTNETLINK) {
            continue;
        }
        const auto message_type = NFNL_MSG_TYPE(header->nlmsg_type);
        if (message_type == IPCTNL_MSG_CT_NEW ||
            message_type == IPCTNL_MSG_CT_DELETE) {
            ++count;
        }
    }
    return count;
}

ConntrackEventMonitor::ConntrackEventMonitor() {
    fd_ = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (fd_ < 0) {
        error_ = system_error("socket(NETLINK_NETFILTER) failed");
        return;
    }

    const int flags = fcntl(fd_, F_GETFL, 0);
    if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0 ||
        fcntl(fd_, F_SETFD, FD_CLOEXEC) < 0) {
        error_ = system_error("setting conntrack socket flags failed");
        close(fd_);
        fd_ = -1;
        return;
    }

    int receive_buffer = static_cast<int>(receive_buffer_size);
    (void)setsockopt(fd_,
                     SOL_SOCKET,
                     SO_RCVBUF,
                     &receive_buffer,
                     sizeof(receive_buffer));

    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    address.nl_groups = conntrack_multicast_groups();
    if (bind(fd_,
             reinterpret_cast<const sockaddr*>(&address),
             sizeof(address)) < 0) {
        error_ = system_error("binding conntrack multicast groups failed");
        close(fd_);
        fd_ = -1;
    }
}

ConntrackEventMonitor::~ConntrackEventMonitor() {
    if (fd_ >= 0) close(fd_);
}

bool ConntrackEventMonitor::available() const noexcept {
    return fd_ >= 0;
}

int ConntrackEventMonitor::fd() const noexcept {
    return fd_;
}

const std::string& ConntrackEventMonitor::error() const noexcept {
    return error_;
}

std::uint64_t ConntrackEventMonitor::drain() {
    if (fd_ < 0) return 0;

    std::array<std::byte, receive_buffer_size> buffer{};
    std::uint64_t count = 0;
    while (true) {
        const auto received = recv(fd_,
                                   buffer.data(),
                                   buffer.size(),
                                   MSG_DONTWAIT);
        if (received > 0) {
            count += count_conntrack_messages(
                buffer.data(),
                static_cast<std::size_t>(received));
            continue;
        }
        if (received == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        if (errno == EINTR) continue;
        throw std::runtime_error(system_error(
            "reading conntrack netlink events failed"));
    }
    return count;
}

} // namespace keen_pbr3
