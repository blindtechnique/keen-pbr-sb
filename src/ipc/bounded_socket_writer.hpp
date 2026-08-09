#pragma once

#include "control_protocol.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <string>
#include <sys/socket.h>

namespace keen_pbr3::ipc {

// Send one complete control response without allowing a slow/non-reading peer
// to retain a worker indefinitely. The descriptor stays nonblocking after
// this call; routing-test workers close it immediately afterwards.
inline void send_all_bounded_nonblocking(
    int fd,
    const char* data,
    std::size_t size,
    std::chrono::milliseconds timeout) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 ||
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        throw ControlProtocolError(
            "control socket nonblocking setup failed: " +
            std::string(std::strerror(errno)));
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::size_t written = 0;
    while (written < size) {
        if (std::chrono::steady_clock::now() >= deadline) {
            throw ControlProtocolError(
                "control socket response timeout");
        }

        const ssize_t count = ::send(
            fd,
            data + written,
            size - written,
            MSG_NOSIGNAL | MSG_DONTWAIT);
        if (count > 0) {
            written += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK)) {
            const auto remaining =
                std::chrono::ceil<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now());
            if (remaining.count() <= 0) {
                throw ControlProtocolError(
                    "control socket response timeout");
            }
            const int timeout_ms = static_cast<int>(
                std::min<std::int64_t>(
                    remaining.count(),
                    std::numeric_limits<int>::max()));
            pollfd descriptor{fd, POLLOUT, 0};
            const int result = ::poll(&descriptor, 1, timeout_ms);
            if (result < 0 && errno == EINTR) {
                continue;
            }
            if (result == 0) {
                throw ControlProtocolError(
                    "control socket response timeout");
            }
            if (result < 0) {
                throw ControlProtocolError(
                    "control socket response poll failed: " +
                    std::string(std::strerror(errno)));
            }
            if ((descriptor.revents & POLLOUT) == 0) {
                throw ControlProtocolError(
                    "control socket closed during response");
            }
            continue;
        }
        throw ControlProtocolError(
            "control socket write failed: " +
            std::string(std::strerror(errno)));
    }
}

} // namespace keen_pbr3::ipc
