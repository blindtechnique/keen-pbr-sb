#include "ipc_control_service.hpp"

#include "bounded_socket_writer.hpp"
#include "control_protocol.hpp"
#include "../log/logger.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <grp.h>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

namespace keen_pbr3::ipc {

namespace {

constexpr std::size_t kMaxPendingControlClients = 64U;
constexpr std::size_t kMaxControlRequestBytes = 4U * 1024U;
constexpr auto kControlIngressTimeout = std::chrono::seconds{1};
constexpr auto kControlResponseSendTimeout = std::chrono::seconds{1};

bool peer_has_group(const IpcControlRequest& request, gid_t group_id) {
    if (group_id == static_cast<gid_t>(-1)) return false;
    if (request.peer_gid == group_id) return true;

    std::ifstream status(
        "/proc/" + std::to_string(request.peer_pid) + "/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("Groups:", 0) != 0) continue;
        std::istringstream groups(line.substr(7));
        unsigned long group = 0;
        while (groups >> group) {
            if (group == static_cast<unsigned long>(group_id)) {
                return true;
            }
        }
        break;
    }
    return false;
}

} // namespace

IpcControlService::~IpcControlService() {
    stop();
}

void IpcControlService::start(
    std::string socket_path,
    WakeControlLoop wake_control_loop) {
    start_with_ownership(
        std::move(socket_path), std::move(wake_control_loop),
        static_cast<uid_t>(0), static_cast<gid_t>(0), true);
}

#ifdef KEEN_PBR3_TESTING
void IpcControlService::start(
    std::string socket_path,
    WakeControlLoop wake_control_loop,
    const IpcControlServiceTestHooks hooks) {
    const bool current_owner = hooks.allow_current_process_owner;
    start_with_ownership(
        std::move(socket_path), std::move(wake_control_loop),
        current_owner ? ::geteuid() : static_cast<uid_t>(0),
        current_owner ? ::getegid() : static_cast<gid_t>(0),
        !current_owner);
}
#endif

void IpcControlService::start_with_ownership(
    std::string socket_path,
    WakeControlLoop wake_control_loop,
    const uid_t socket_owner,
    const gid_t socket_group,
    const bool resolve_control_group) {
    if (!wake_control_loop) {
        throw std::runtime_error(
            "control wake callback is required");
    }
    if (active() || control_fd_ >= 0 || accept_thread_.joinable()) {
        throw std::runtime_error("control socket is already running");
    }

    socket_path_ = std::move(socket_path);
    wake_control_loop_ = std::move(wake_control_loop);
    try {
        if (socket_path_.empty() ||
            socket_path_.size() >= sizeof(sockaddr_un::sun_path)) {
            throw std::runtime_error("control socket path is invalid");
        }

        const auto parent =
            std::filesystem::path(socket_path_).parent_path();
        std::error_code directory_error;
        std::filesystem::create_directories(parent, directory_error);
        if (directory_error) {
            throw std::runtime_error(
                "failed to create control socket directory: " +
                directory_error.message());
        }

        const group* control_group =
            resolve_control_group ? ::getgrnam("keen-pbr") : nullptr;
        if (control_group != nullptr) {
            control_group_id_ = control_group->gr_gid;
            if (::chown(
                    parent.c_str(), socket_owner, control_group_id_) != 0) {
                throw std::runtime_error(
                    "failed to assign control socket directory group: " +
                    std::string(strerror(errno)));
            }
        } else {
            control_group_id_ = static_cast<gid_t>(-1);
            Logger::instance().info(
                "Optional keen-pbr group is absent; control socket is root-only");
        }
        if (::chmod(parent.c_str(), 0750) != 0) {
            throw std::runtime_error(
                "failed to set control socket directory mode: " +
                std::string(strerror(errno)));
        }

        struct stat existing {};
        if (::lstat(socket_path_.c_str(), &existing) == 0) {
            if (!S_ISSOCK(existing.st_mode) ||
                ::unlink(socket_path_.c_str()) != 0) {
                throw std::runtime_error(
                    "unsafe stale control socket path");
            }
        } else if (errno != ENOENT) {
            throw std::runtime_error(
                "failed to inspect control socket path: " +
                std::string(strerror(errno)));
        }

        control_fd_ =
            ::socket(AF_UNIX,
                     SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                     0);
        if (control_fd_ < 0) {
            throw std::runtime_error(
                "control socket create failed: " +
                std::string(strerror(errno)));
        }

        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path,
                    socket_path_.c_str(),
                    socket_path_.size() + 1);
        const gid_t effective_socket_group =
            control_group_id_ == static_cast<gid_t>(-1)
                ? socket_group
                : control_group_id_;
        const mode_t socket_mode =
            control_group_id_ == static_cast<gid_t>(-1) ? 0600 : 0660;
        if (::bind(control_fd_,
                   reinterpret_cast<const sockaddr*>(&address),
                   sizeof(address)) != 0 ||
            ::listen(control_fd_, 16) != 0 ||
            ::chown(
                socket_path_.c_str(),
                socket_owner,
                effective_socket_group) != 0 ||
            ::chmod(socket_path_.c_str(), socket_mode) != 0) {
            throw std::runtime_error(
                "control socket setup failed: " +
                std::string(strerror(errno)));
        }

        accept_running_.store(true, std::memory_order_release);
        accept_thread_ =
            std::thread([this] { run_acceptor(); });
    } catch (...) {
        stop();
        throw;
    }
}

void IpcControlService::run_acceptor() noexcept {
    struct PendingClient {
        int fd{-1};
        std::string frame;
        std::optional<std::size_t> expected_size;
        std::chrono::steady_clock::time_point deadline;
    };

    std::vector<PendingClient> pending;
    pending.reserve(kMaxPendingControlClients);
    const auto reject = [](int fd,
                           std::string_view code,
                           std::string_view message) {
        send_response_and_close(
            fd,
            {{"protocol_version", kControlProtocolVersion},
             {"request_id", nullptr},
             {"ok", false},
             {"error", {{"code", code}, {"message", message}}}});
    };

    while (accept_running_.load(std::memory_order_acquire)) {
        std::vector<pollfd> poll_fds;
        poll_fds.reserve(pending.size() + 1U);
        poll_fds.push_back({control_fd_, POLLIN, 0});
        for (const auto& client : pending) {
            poll_fds.push_back({client.fd, POLLIN, 0});
        }

        const int ready =
            ::poll(poll_fds.data(), poll_fds.size(), 100);
        if (ready < 0) {
            if (errno == EINTR) continue;
            if (accept_running_.load(std::memory_order_acquire)) {
                try {
                    Logger::instance().error(
                        "control socket acceptor poll failed: {}",
                        strerror(errno));
                } catch (...) {
                }
            }
            break;
        }

        if (!poll_fds.empty() &&
            (poll_fds.front().revents & POLLIN) != 0) {
            while (accept_running_.load(std::memory_order_acquire)) {
                const int client = ::accept4(
                    control_fd_,
                    nullptr,
                    nullptr,
                    SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (client < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    if (errno == EINTR) continue;
                    if (accept_running_.load(
                            std::memory_order_acquire)) {
                        try {
                            Logger::instance().error(
                                "control socket accept failed: {}",
                                strerror(errno));
                        } catch (...) {
                        }
                    }
                    break;
                }

                std::size_t completed_count = 0;
                {
                    KPBR_LOCK_GUARD(accepted_clients_mutex_);
                    completed_count = accepted_clients_.size();
                }
                if (pending.size() + completed_count >=
                    kMaxPendingControlClients) {
                    reject(
                        client,
                        "busy",
                        "control ingress queue is full");
                    continue;
                }
                pending.push_back(
                    {client,
                     {},
                     std::nullopt,
                     std::chrono::steady_clock::now() +
                         kControlIngressTimeout});
            }
        }

        const auto now = std::chrono::steady_clock::now();
        for (std::size_t index = pending.size(); index-- > 0;) {
            auto& client = pending[index];
            short revents = 0;
            if (poll_fds.size() > index + 1U) {
                revents = poll_fds[index + 1U].revents;
            }
            bool failed = false;
            bool complete = false;

            if ((revents & POLLIN) != 0) {
                char buffer[4096];
                for (;;) {
                    const ssize_t count = ::recv(
                        client.fd, buffer, sizeof(buffer), 0);
                    if (count > 0) {
                        client.frame.append(
                            buffer, static_cast<std::size_t>(count));
                        if (!client.expected_size.has_value() &&
                            client.frame.size() >=
                                sizeof(std::uint32_t)) {
                            std::uint32_t network_size = 0;
                            std::memcpy(
                                &network_size,
                                client.frame.data(),
                                sizeof(network_size));
                            const std::size_t payload_size =
                                ntohl(network_size);
                            if (payload_size >
                                kMaxControlRequestBytes) {
                                failed = true;
                                break;
                            }
                            client.expected_size =
                                sizeof(network_size) + payload_size;
                        }
                        if (client.expected_size.has_value() &&
                            client.frame.size() >=
                                *client.expected_size) {
                            complete =
                                client.frame.size() ==
                                *client.expected_size;
                            failed = !complete;
                            break;
                        }
                        continue;
                    }
                    if (count == 0) {
                        failed = true;
                        break;
                    }
                    if (errno == EINTR) continue;
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        failed = true;
                    }
                    break;
                }
            }
            if (!complete &&
                ((revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
                 now >= client.deadline)) {
                failed = true;
            }
            if (!complete && !failed) continue;

            const int fd = client.fd;
            std::string frame = std::move(client.frame);
            pending.erase(
                pending.begin() + static_cast<std::ptrdiff_t>(index));
            if (failed) {
                reject(
                    fd,
                    "protocol_error",
                    "incomplete control request");
                continue;
            }

            nlohmann::json request = nlohmann::json::object();
            try {
                ucred peer{};
                socklen_t peer_length = sizeof(peer);
                if (::getsockopt(
                        fd,
                        SOL_SOCKET,
                        SO_PEERCRED,
                        &peer,
                        &peer_length) != 0) {
                    throw ControlProtocolError(
                        "unable to verify control peer");
                }
                request = decode_message(frame);
                validate_request_envelope(request);

                const int flags = ::fcntl(fd, F_GETFL, 0);
                if (flags < 0 ||
                    ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
                    throw ControlProtocolError(
                        "unable to prepare control response socket");
                }
                timeval timeout{5, 0};
                if (::setsockopt(
                        fd,
                        SOL_SOCKET,
                        SO_SNDTIMEO,
                        &timeout,
                        sizeof(timeout)) != 0) {
                    throw ControlProtocolError(
                        "unable to bound control response socket");
                }

                bool queued = false;
                {
                    KPBR_LOCK_GUARD(accepted_clients_mutex_);
                    if (accept_running_.load(
                            std::memory_order_acquire) &&
                        accepted_clients_.size() <
                            kMaxPendingControlClients) {
                        accepted_clients_.push_back(
                            {fd,
                             peer.pid,
                             peer.uid,
                             peer.gid,
                             std::move(request)});
                        queued = true;
                    }
                }
                if (!queued) {
                    reject(
                        fd,
                        "busy",
                        "control dispatch queue is unavailable");
                    continue;
                }
                try {
                    if (wake_control_loop_) {
                        wake_control_loop_();
                    }
                } catch (const std::exception& error) {
                    try {
                        Logger::instance().error(
                            "control socket wake failed: {}",
                            error.what());
                    } catch (...) {
                    }
                } catch (...) {
                    try {
                        Logger::instance().error(
                            "control socket wake failed: unknown error");
                    } catch (...) {
                    }
                }
            } catch (const std::exception& error) {
                send_response_and_close(
                    fd,
                    make_error_response(
                        request, "protocol_error", error.what()));
            }
        }
    }

    for (const auto& client : pending) {
        ::close(client.fd);
    }
}

void IpcControlService::stop() noexcept {
    accept_running_.store(false, std::memory_order_release);
    if (control_fd_ >= 0) {
        (void)::shutdown(control_fd_, SHUT_RDWR);
    }
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    if (control_fd_ >= 0) {
        ::close(control_fd_);
        control_fd_ = -1;
    }
    {
        KPBR_LOCK_GUARD(accepted_clients_mutex_);
        for (const auto& client : accepted_clients_) {
            ::close(client.fd);
        }
        accepted_clients_.clear();
    }
    control_group_id_ = static_cast<gid_t>(-1);
    if (!socket_path_.empty()) {
        struct stat metadata {};
        if (::lstat(socket_path_.c_str(), &metadata) == 0 &&
            S_ISSOCK(metadata.st_mode)) {
            (void)::unlink(socket_path_.c_str());
        }
        socket_path_.clear();
    }
    wake_control_loop_ = {};
}

bool IpcControlService::active() const noexcept {
    return accept_running_.load(std::memory_order_acquire);
}

std::optional<IpcControlRequest>
IpcControlService::try_take_request() {
    KPBR_LOCK_GUARD(accepted_clients_mutex_);
    if (accepted_clients_.empty()) return std::nullopt;
    IpcControlRequest request =
        std::move(accepted_clients_.front());
    accepted_clients_.pop_front();
    return request;
}

bool IpcControlService::peer_is_control_group_member(
    const IpcControlRequest& request) const {
    return peer_has_group(request, control_group_id_);
}

void IpcControlService::send_response_and_close(
    int fd,
    const nlohmann::json& response) noexcept {
    try {
        const auto frame = encode_message(response);
        send_all_bounded_nonblocking(
            fd,
            frame.data(),
            frame.size(),
            std::chrono::duration_cast<std::chrono::milliseconds>(
                kControlResponseSendTimeout));
    } catch (const std::exception& error) {
        try {
            Logger::instance().warn(
                "control response failed: {}", error.what());
        } catch (...) {
        }
    }
    ::close(fd);
}

} // namespace keen_pbr3::ipc
