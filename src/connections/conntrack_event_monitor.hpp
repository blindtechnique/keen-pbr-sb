#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace keen_pbr3 {

// Lightweight kernel event source for the connections page. The monitor owns
// one non-blocking NETLINK_NETFILTER socket and is driven by Daemon's epoll
// loop, so it does not add a worker thread or periodically scan conntrack.
class ConntrackEventMonitor {
public:
    ConntrackEventMonitor();
    ~ConntrackEventMonitor();

    ConntrackEventMonitor(const ConntrackEventMonitor&) = delete;
    ConntrackEventMonitor& operator=(const ConntrackEventMonitor&) = delete;
    ConntrackEventMonitor(ConntrackEventMonitor&&) = delete;
    ConntrackEventMonitor& operator=(ConntrackEventMonitor&&) = delete;

    bool available() const noexcept;
    int fd() const noexcept;
    const std::string& error() const noexcept;

    // Drains all currently queued netlink datagrams and returns the number of
    // conntrack NEW/UPDATE/DESTROY messages observed.
    std::uint64_t drain();

private:
    int fd_{-1};
    std::string error_;
};

std::uint32_t conntrack_multicast_groups() noexcept;
std::uint64_t count_conntrack_messages(const void* data,
                                       std::size_t size) noexcept;

} // namespace keen_pbr3
