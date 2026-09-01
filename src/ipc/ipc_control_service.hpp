#pragma once

#include "../util/traced_mutex.hpp"

#include <atomic>
#include <deque>
#include <functional>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <thread>
#include <sys/types.h>

namespace keen_pbr3::ipc {

struct IpcControlRequest {
    // Sole descriptor ownership belongs to the service while this request is
    // queued. try_take_request() transfers that ownership to the control-loop
    // dispatcher, which must close it or hand it to exactly one async worker.
    int fd{-1};
    pid_t peer_pid{0};
    uid_t peer_uid{0};
    gid_t peer_gid{0};
    nlohmann::json request;
};

// Owns the Unix control-socket transport and its ingress thread. Operation
// dispatch deliberately remains on Daemon's serialized control loop: this
// service only validates frames, captures peer credentials and transfers one
// accepted descriptor at a time across that existing boundary.
class IpcControlService final {
public:
    using WakeControlLoop = std::function<void()>;

    IpcControlService() = default;
    ~IpcControlService();

    IpcControlService(const IpcControlService&) = delete;
    IpcControlService& operator=(const IpcControlService&) = delete;

    void start(std::string socket_path, WakeControlLoop wake_control_loop);
    void stop() noexcept;

    bool active() const noexcept;
    std::optional<IpcControlRequest> try_take_request();
    bool peer_is_control_group_member(
        const IpcControlRequest& request) const;

    static void send_response_and_close(
        int fd,
        const nlohmann::json& response) noexcept;

private:
    void run_acceptor() noexcept;

    int control_fd_{-1};
    gid_t control_group_id_{static_cast<gid_t>(-1)};
    std::string socket_path_;
    WakeControlLoop wake_control_loop_;
    std::atomic<bool> accept_running_{false};
    std::thread accept_thread_;
    TracedMutex accepted_clients_mutex_;
    std::deque<IpcControlRequest> accepted_clients_
        GUARDED_BY(accepted_clients_mutex_);
};

} // namespace keen_pbr3::ipc
