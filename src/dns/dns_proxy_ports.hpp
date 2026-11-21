#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

namespace keen_pbr3 {

inline constexpr const char* kDnsProxyListenIp = "127.0.0.89";
// Never claim 5355, even when Keenetic's SMB/LLMNR server starts after us.
inline constexpr std::uint16_t kDnsProxyFirstPort = 15355;
inline constexpr std::size_t kDnsProxyPortCount = 128;
inline constexpr std::size_t kDnsBalancerMaxGroups = 32;
static_assert(kDnsProxyPortCount >= kDnsBalancerMaxGroups &&
              kDnsProxyFirstPort + kDnsProxyPortCount <= 65536);

// The same port is pinned for hashing, dnsmasq output and activation. A real
// UDP socket and a listening TCP socket reserve it, not a probe followed by
// a close/rebind race. The worker uses duplicates of these very sockets.
class DnsProxyPort {
public:
    ~DnsProxyPort();
    std::uint16_t number() const noexcept { return port_; }
    int duplicate_sockets(int& udp, int& tcp);

private:
    friend class DnsProxyPorts;
    explicit DnsProxyPort(std::uint16_t port) : port_(port) {}
    int bind_pair(); // caller holds mutex_ (or the object is not yet shared)
    void release();
    const std::uint16_t port_;
    std::mutex mutex_;
    int udp_{-1};
    int tcp_{-1};
};

class DnsProxyPorts {
public:
    ~DnsProxyPorts() { release_all(); }
    std::shared_ptr<DnsProxyPort> reserve(std::size_t group_index);
    // STOP must also close reservations held by old generation snapshots.
    void release_all();

private:
    std::mutex mutex_;
    std::array<std::weak_ptr<DnsProxyPort>, kDnsBalancerMaxGroups> slots_{};
    std::array<std::weak_ptr<DnsProxyPort>, kDnsProxyPortCount> ports_{};
};

} // namespace keen_pbr3
