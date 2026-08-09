#include "control_client.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <ostream>
#include <utility>

namespace keen_pbr3::ipc {
namespace {

constexpr std::size_t kResolverStreamChunkBytes = 16U * 1024U;
using Deadline = std::chrono::steady_clock::time_point;

class UniqueFd {
public:
    explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}
    ~UniqueFd() {
        if (fd_ >= 0) ::close(fd_);
    }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept
        : fd_(std::exchange(other.fd_, -1)) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) ::close(fd_);
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }
    int get() const noexcept { return fd_; }

private:
    int fd_;
};

Deadline deadline_after(int timeout_ms) {
    if (timeout_ms <= 0) {
        return std::chrono::steady_clock::now();
    }
    return std::chrono::steady_clock::now() +
           std::chrono::milliseconds(timeout_ms);
}

int remaining_timeout_ms(Deadline deadline) {
    const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) {
        return 0;
    }
    return static_cast<int>(std::min<std::int64_t>(
        remaining.count(), std::numeric_limits<int>::max()));
}

[[noreturn]] void throw_timeout(const char* phase) {
    throw ControlTimeoutError(
        "control socket timeout during " + std::string(phase));
}

void wait_for(int fd, short events, Deadline deadline, const char* phase) {
    while (true) {
        const int timeout_ms = remaining_timeout_ms(deadline);
        if (timeout_ms == 0) {
            throw_timeout(phase);
        }

        pollfd descriptor{fd, events, 0};
        const int result = ::poll(&descriptor, 1, timeout_ms);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result == 0) {
            throw_timeout(phase);
        }
        if (result < 0) {
            throw ControlProtocolError(
                "control socket poll failed: " +
                std::string(strerror(errno)));
        }
        if ((descriptor.revents & events) != 0) {
            return;
        }
        throw ControlProtocolError("control socket closed");
    }
}

void wait_before_connect_retry(Deadline deadline) {
    // AF_UNIX reports EAGAIN, rather than EINPROGRESS, when a nonblocking
    // listener backlog is full. There is no listener fd available to poll
    // here, so retry with a short deadline-bounded backoff.
    while (true) {
        const int remaining_ms = remaining_timeout_ms(deadline);
        if (remaining_ms == 0) {
            throw_timeout("connect");
        }
        const int result =
            ::poll(nullptr, 0, std::min(remaining_ms, 10));
        if (result == 0) {
            return;
        }
        if (result < 0 && errno != EINTR) {
            throw ControlProtocolError(
                "control socket connect retry failed: " +
                std::string(strerror(errno)));
        }
    }
}

void write_all(int fd,
               const std::string& data,
               Deadline deadline,
               const char* phase) {
    std::size_t written = 0;
    while (written < data.size()) {
        if (remaining_timeout_ms(deadline) == 0) {
            throw_timeout(phase);
        }
        const ssize_t count =
            ::send(fd,
                   data.data() + written,
                   data.size() - written,
                   MSG_NOSIGNAL);
        if (count > 0) {
            written += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            wait_for(fd, POLLOUT, deadline, phase);
            continue;
        }
        if (count <= 0) {
            throw ControlProtocolError(
                "control socket write failed: " +
                std::string(strerror(errno)));
        }
    }
}

std::string read_exact(int fd,
                       std::size_t size,
                       Deadline deadline,
                       const char* phase) {
    std::string result(size, '\0');
    std::size_t received = 0;
    while (received < size) {
        if (remaining_timeout_ms(deadline) == 0) {
            throw_timeout(phase);
        }
        const ssize_t count =
            ::recv(fd, result.data() + received, size - received, 0);
        if (count > 0) {
            received += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            wait_for(fd, POLLIN, deadline, phase);
            continue;
        }
        if (count <= 0) {
            throw ControlProtocolError("control socket read failed");
        }
    }
    return result;
}

UniqueFd connect_control_socket(const std::string& socket_path,
                                Deadline deadline) {
    if (socket_path.empty() ||
        socket_path.size() >= sizeof(sockaddr_un::sun_path)) {
        throw ControlProtocolError("control socket path is invalid");
    }
    UniqueFd fd(
        ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (fd.get() < 0) {
        throw ControlProtocolError(
            "control socket create failed: " +
            std::string(strerror(errno)));
    }
    const int flags = ::fcntl(fd.get(), F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd.get(), F_SETFL, flags | O_NONBLOCK) != 0) {
        throw ControlProtocolError(
            "control socket nonblocking setup failed: " +
            std::string(strerror(errno)));
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path,
                socket_path.c_str(),
                socket_path.size() + 1);
    while (true) {
        if (remaining_timeout_ms(deadline) == 0) {
            throw_timeout("connect");
        }

        if (::connect(fd.get(),
                      reinterpret_cast<const sockaddr*>(&address),
                      sizeof(address)) == 0 ||
            errno == EISCONN) {
            return fd;
        }

        const int connect_error = errno;
        if (connect_error == EINTR) {
            continue;
        }
        if (connect_error == EAGAIN ||
            connect_error == EWOULDBLOCK) {
            wait_before_connect_retry(deadline);
            continue;
        }
        if (connect_error != EINPROGRESS &&
            connect_error != EALREADY) {
            throw ControlProtocolError(
                "control socket unavailable: " +
                std::string(strerror(connect_error)));
        }

        wait_for(fd.get(), POLLOUT, deadline, "connect");
        int socket_error = 0;
        socklen_t socket_error_size = sizeof(socket_error);
        if (::getsockopt(fd.get(),
                         SOL_SOCKET,
                         SO_ERROR,
                         &socket_error,
                         &socket_error_size) != 0) {
            throw ControlProtocolError(
                "control socket connect check failed: " +
                std::string(strerror(errno)));
        }
        if (socket_error == 0) {
            return fd;
        }
        if (socket_error == EINPROGRESS ||
            socket_error == EALREADY ||
            socket_error == EAGAIN ||
            socket_error == EWOULDBLOCK) {
            continue;
        }
        throw ControlProtocolError(
            "control socket unavailable: " +
            std::string(strerror(socket_error)));
    }
}

nlohmann::json read_response_envelope(int fd,
                                      Deadline deadline,
                                      const char* phase) {
    const std::string header =
        read_exact(fd, sizeof(std::uint32_t), deadline, phase);
    std::uint32_t length = 0;
    std::memcpy(&length, header.data(), sizeof(length));
    const std::size_t payload_size = ntohl(length);
    if (payload_size > kMaxControlMessageBytes) {
        throw ControlProtocolError(
            "control response exceeds maximum size");
    }
    return decode_message(
        header + read_exact(fd, payload_size, deadline, phase));
}

} // namespace

nlohmann::json request_control(const std::string& socket_path,
                               const nlohmann::json& request,
                               int connect_timeout_ms,
                               int response_timeout_ms) {
    validate_request_envelope(request);
    const Deadline request_deadline = deadline_after(connect_timeout_ms);
    auto fd = connect_control_socket(socket_path, request_deadline);
    write_all(fd.get(),
              encode_message(request),
              request_deadline,
              "request");
    const int effective_response_timeout =
        response_timeout_ms < 0 ? connect_timeout_ms : response_timeout_ms;
    return read_response_envelope(
        fd.get(), deadline_after(effective_response_timeout), "response");
}

void stream_control(const std::string& socket_path,
                    const nlohmann::json& request,
                    std::ostream& output,
                    int idle_timeout_ms,
                    int connect_timeout_ms) {
    validate_request_envelope(request);
    bool active_bytes_streamed = false;
    try {
        const int effective_connect_timeout =
            connect_timeout_ms < 0 ? idle_timeout_ms : connect_timeout_ms;
        const Deadline request_deadline =
            deadline_after(effective_connect_timeout);
        auto fd = connect_control_socket(socket_path, request_deadline);
        write_all(fd.get(),
                  encode_message(request),
                  request_deadline,
                  "stream request");
        const auto response =
            read_response_envelope(
                fd.get(), deadline_after(idle_timeout_ms), "stream response");
        if (!response.value("ok", false)) {
            const auto code =
                response.value("error", nlohmann::json::object())
                    .value("code", "daemon_error");
            throw ControlStreamError(code, false);
        }
        if (!response.value("stream", false)) {
            throw ControlStreamError("protocol_error", false);
        }

        while (true) {
            const std::string length_frame =
                read_exact(fd.get(),
                           sizeof(std::uint32_t),
                           deadline_after(idle_timeout_ms),
                           "stream chunk");
            std::uint32_t length = 0;
            std::memcpy(&length,
                        length_frame.data(),
                        sizeof(length));
            const std::size_t chunk_size = ntohl(length);
            if (chunk_size == 0) break;
            if (chunk_size > kResolverStreamChunkBytes) {
                throw ControlStreamError(
                    "protocol_error", active_bytes_streamed);
            }
            const std::string chunk =
                read_exact(fd.get(),
                           chunk_size,
                           deadline_after(idle_timeout_ms),
                           "stream chunk");
            output.write(
                chunk.data(),
                static_cast<std::streamsize>(chunk.size()));
            output.flush();
            if (!output) {
                throw ControlStreamError(
                    "stdout_error", active_bytes_streamed);
            }
            active_bytes_streamed = true;
        }
    } catch (const ControlStreamError&) {
        throw;
    } catch (const ControlProtocolError& error) {
        throw ControlStreamError(
            error.what(), active_bytes_streamed);
    }
}

} // namespace keen_pbr3::ipc
