#include "control_client.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ostream>
#include <utility>

namespace keen_pbr3::ipc {
namespace {

constexpr std::size_t kResolverStreamChunkBytes = 16U * 1024U;

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

void wait_for(int fd, short events, int timeout_ms) {
    pollfd descriptor{fd, events, 0};
    int result = 0;
    do {
        result = ::poll(&descriptor, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);

    if (result == 0) {
        throw ControlProtocolError("control socket timeout");
    }
    if (result < 0) {
        throw ControlProtocolError(
            "control socket poll failed: " + std::string(strerror(errno)));
    }
    if ((descriptor.revents & events) == 0) {
        throw ControlProtocolError("control socket closed");
    }
}

void write_all(int fd, const std::string& data, int timeout_ms) {
    std::size_t written = 0;
    while (written < data.size()) {
        wait_for(fd, POLLOUT, timeout_ms);
        const ssize_t count =
            ::send(fd,
                   data.data() + written,
                   data.size() - written,
                   MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            throw ControlProtocolError(
                "control socket write failed: " +
                std::string(strerror(errno)));
        }
        written += static_cast<std::size_t>(count);
    }
}

std::string read_exact(int fd, std::size_t size, int timeout_ms) {
    std::string result(size, '\0');
    std::size_t received = 0;
    while (received < size) {
        wait_for(fd, POLLIN, timeout_ms);
        const ssize_t count =
            ::recv(fd, result.data() + received, size - received, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            throw ControlProtocolError("control socket read failed");
        }
        received += static_cast<std::size_t>(count);
    }
    return result;
}

UniqueFd connect_control_socket(const std::string& socket_path) {
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
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path,
                socket_path.c_str(),
                socket_path.size() + 1);
    if (::connect(fd.get(),
                  reinterpret_cast<const sockaddr*>(&address),
                  sizeof(address)) != 0) {
        throw ControlProtocolError(
            "control socket unavailable: " +
            std::string(strerror(errno)));
    }
    return fd;
}

nlohmann::json read_response_envelope(int fd, int timeout_ms) {
    const std::string header =
        read_exact(fd, sizeof(std::uint32_t), timeout_ms);
    std::uint32_t length = 0;
    std::memcpy(&length, header.data(), sizeof(length));
    const std::size_t payload_size = ntohl(length);
    if (payload_size > kMaxControlMessageBytes) {
        throw ControlProtocolError(
            "control response exceeds maximum size");
    }
    return decode_message(
        header + read_exact(fd, payload_size, timeout_ms));
}

} // namespace

nlohmann::json request_control(const std::string& socket_path,
                               const nlohmann::json& request,
                               int timeout_ms) {
    validate_request_envelope(request);
    auto fd = connect_control_socket(socket_path);
    write_all(fd.get(), encode_message(request), timeout_ms);
    return read_response_envelope(fd.get(), timeout_ms);
}

void stream_control(const std::string& socket_path,
                    const nlohmann::json& request,
                    std::ostream& output,
                    int idle_timeout_ms) {
    validate_request_envelope(request);
    bool active_bytes_streamed = false;
    try {
        auto fd = connect_control_socket(socket_path);
        write_all(fd.get(), encode_message(request), idle_timeout_ms);
        const auto response =
            read_response_envelope(fd.get(), idle_timeout_ms);
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
                           idle_timeout_ms);
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
                read_exact(fd.get(), chunk_size, idle_timeout_ms);
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
