#include "dns_proxy_ports.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/socket.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {
void close_socket(int& fd) {
    if (fd >= 0) ::close(fd);
    fd = -1;
}
}

DnsProxyPort::~DnsProxyPort() {
    close_socket(udp_);
    close_socket(tcp_);
}

void DnsProxyPort::release() {
    std::lock_guard<std::mutex> lock(mutex_);
    close_socket(udp_);
    close_socket(tcp_);
}

int DnsProxyPort::bind_pair() {
    if (udp_ >= 0) return 0;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port_);
    if (::inet_pton(AF_INET, kDnsProxyListenIp, &address.sin_addr) != 1) return EINVAL;
    const auto* addr = reinterpret_cast<const sockaddr*>(&address);
    // No SO_REUSEPORT or wildcard bind: never share a foreign listener.
    udp_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (udp_ < 0) return errno;
    if (::bind(udp_, addr, sizeof(address)) == 0) {
        tcp_ = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (tcp_ >= 0 && ::bind(tcp_, addr, sizeof(address)) == 0 &&
            ::listen(tcp_, 16) == 0) return 0;
    }
    const int error = errno;
    close_socket(udp_);
    close_socket(tcp_);
    return error;
}

int DnsProxyPort::duplicate_sockets(int& udp, int& tcp) {
    std::lock_guard<std::mutex> lock(mutex_);
    // A snapshot retained across STOP may only resume on its exact port.
    if (const int error = bind_pair()) return error;
    udp = ::fcntl(udp_, F_DUPFD_CLOEXEC, 0);
    if (udp < 0) return errno;
    tcp = ::fcntl(tcp_, F_DUPFD_CLOEXEC, 0);
    if (tcp >= 0) return 0;
    const int error = errno;
    close_socket(udp);
    return error;
}

std::shared_ptr<DnsProxyPort> DnsProxyPorts::reserve(std::size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= slots_.size()) throw std::out_of_range("Too many DNS proxy listeners");
    auto available = [](const std::shared_ptr<DnsProxyPort>& port) {
        std::lock_guard<std::mutex> port_lock(port->mutex_);
        const int error = port->bind_pair();
        if (error == EADDRINUSE) return false;
        if (error) throw std::system_error(error, std::generic_category(),
            "Reserve DNS proxy UDP/TCP port " + std::to_string(port->number()));
        return true;
    };
    if (auto existing = slots_[index].lock(); existing && available(existing)) return existing;
    for (std::size_t i = 0; i < ports_.size(); ++i) {
        if (!ports_[i].expired()) continue; // another slot or a pending rollback
        auto candidate = std::shared_ptr<DnsProxyPort>(new DnsProxyPort(
            static_cast<std::uint16_t>(kDnsProxyFirstPort + i)));
        if (!available(candidate)) continue;
        ports_[i] = slots_[index] = candidate;
        return candidate;
    }
    throw std::runtime_error("No free UDP/TCP port for the DNS proxy on " +
        std::string(kDnsProxyListenIp) + " in " + std::to_string(kDnsProxyFirstPort) +
        "-" + std::to_string(kDnsProxyFirstPort + kDnsProxyPortCount - 1));
}

void DnsProxyPorts::release_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : ports_) if (auto port = entry.lock()) port->release();
}

} // namespace keen_pbr3
