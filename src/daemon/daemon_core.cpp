#include "daemon.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <ctime>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <future>
#include <grp.h>
#include <map>
#include <nlohmann/json.hpp>
#include <ostream>
#include <signal.h>
#include <set>
#include <sstream>
#include <string_view>
#include <streambuf>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

#include <keen-pbr/version.hpp>

#include "../cache/cache_manager.hpp"
#include "../cmd/test_routing.hpp"
#include "../dns/dns_router.hpp"
#include "../dns/dnsmasq_access_policy.hpp"
#include "../dns/dnsmasq_gen.hpp"
#include "../firewall/firewall.hpp"
#include "../firewall/firewall_runtime.hpp"
#include "../firewall/firewall_verifier.hpp"
#include "../health/routing_health_checker.hpp"
#include "../ipc/control_protocol.hpp"
#include "../ipc/bounded_socket_writer.hpp"
#include "../keenetic/internal_vpn_server_resolver.hpp"
#include "../keenetic/internal_vpn_service_resolver.hpp"
#include "../keenetic/internal_vpn_runtime_generation.hpp"
#include "../keenetic/ndms_catalog_cache.hpp"
#include "../keenetic/ndms_native_interface_read_production.hpp"
#include "../keenetic/ndms_native_ownership_reconcile.hpp"
#include "../keenetic/ndms_vpn_server_service_cache.hpp"
#include "../lists/list_streamer.hpp"
#include "../log/logger.hpp"
#include "../runtime/meta_udp_443_policy.hpp"
#include "../util/daemon_signals.hpp"
#include "../util/ipv6_support.hpp"
#include "../util/time_utils.hpp"
#include "../dns/dns_probe_server.hpp" // IWYU pragma: keep
#include "scheduler.hpp"

#ifdef WITH_API
#include "../api/handlers.hpp"
#include "../api/handler_remote_access.hpp" // IWYU pragma: keep
#include "../api/server.hpp"
#include "../api/sse_broadcaster.hpp"
#include "../api/status_stream.hpp"
#include "../connections/conntrack_event_monitor.hpp"
#endif

namespace keen_pbr3 {

namespace {

constexpr auto OWNED_SNAT_HEALTH_INTERVAL =
    std::chrono::seconds{60};
#ifdef WITH_API
constexpr auto REMOTE_ACCESS_RECOVERY_WATCHDOG_INTERVAL =
    std::chrono::seconds{60};
#endif
constexpr auto INTERFACE_MONITOR_RECONNECT_RETRY_DELAY = std::chrono::seconds{5};
constexpr std::size_t kResolverStreamChunkBytes = 16U * 1024U;
constexpr std::array<std::chrono::seconds, 6>
    RUNTIME_FIREWALL_RETRY_DELAYS{
        std::chrono::seconds{1},
        std::chrono::seconds{2},
        std::chrono::seconds{4},
        std::chrono::seconds{8},
        std::chrono::seconds{16},
        std::chrono::seconds{32},
    };

#ifndef KEEN_PBR_CONTROL_SOCKET
#define KEEN_PBR_CONTROL_SOCKET "/run/keen-pbr/control.sock"
#endif

void send_all(int fd, const char* data, std::size_t size) {
    std::size_t written = 0;
    while (written < size) {
        const ssize_t count =
            ::send(fd, data + written, size - written, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            throw ipc::ControlProtocolError(
                "control socket write failed: " +
                std::string(strerror(errno)));
        }
        written += static_cast<std::size_t>(count);
    }
}

void receive_all(int fd, char* data, std::size_t size) {
    std::size_t received = 0;
    while (received < size) {
        const ssize_t count =
            ::recv(fd, data + received, size - received, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            throw ipc::ControlProtocolError(
                "truncated control request");
        }
        received += static_cast<std::size_t>(count);
    }
}

class UniqueSocketFd {
public:
    explicit UniqueSocketFd(int fd) noexcept : fd_(fd) {}

    ~UniqueSocketFd() noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    UniqueSocketFd(const UniqueSocketFd&) = delete;
    UniqueSocketFd& operator=(const UniqueSocketFd&) = delete;

    int get() const noexcept { return fd_; }

private:
    int fd_{-1};
};

class SocketStreamBuffer final : public std::streambuf {
public:
    explicit SocketStreamBuffer(int fd) : fd_(fd) {
        setp(buffer_.data(), buffer_.data() + buffer_.size());
    }

    ~SocketStreamBuffer() override { (void)sync(); }

protected:
    int overflow(int character) override {
        if (flush_buffer() != 0) return traits_type::eof();
        if (character != traits_type::eof()) {
            *pptr() = static_cast<char>(character);
            pbump(1);
        }
        return character;
    }

    std::streamsize xsputn(const char* data,
                           std::streamsize size) override {
        std::streamsize written = 0;
        while (written < size) {
            if (pptr() == epptr() && flush_buffer() != 0) break;
            const auto capacity =
                static_cast<std::streamsize>(epptr() - pptr());
            const auto chunk = std::min(capacity, size - written);
            std::memcpy(
                pptr(), data + written, static_cast<std::size_t>(chunk));
            pbump(static_cast<int>(chunk));
            written += chunk;
        }
        return written;
    }

    int sync() override { return flush_buffer(); }

private:
    int flush_buffer() {
        const auto size =
            static_cast<std::size_t>(pptr() - pbase());
        if (size == 0) return 0;
        try {
            const std::uint32_t length =
                htonl(static_cast<std::uint32_t>(size));
            send_all(fd_,
                     reinterpret_cast<const char*>(&length),
                     sizeof(length));
            send_all(fd_, pbase(), size);
        } catch (...) {
            return -1;
        }
        setp(buffer_.data(), buffer_.data() + buffer_.size());
        return 0;
    }

    int fd_;
    std::array<char, kResolverStreamChunkBytes> buffer_{};
};

std::string resolver_runtime_reason(
    const RuntimeStateSnapshot& snapshot) {
    switch (snapshot.runtime_state) {
    case RuntimeState::starting:
        return "runtime_starting";
    case RuntimeState::stopped:
        return "runtime_stopped";
    case RuntimeState::broken:
        return "runtime_broken";
    case RuntimeState::shutting_down:
        return "runtime_shutting_down";
    default:
        return "daemon_error";
    }
}

bool peer_has_group(const ucred& peer, gid_t group_id) {
    if (peer.gid == group_id) return true;

    std::ifstream status(
        "/proc/" + std::to_string(peer.pid) + "/status");
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

std::int64_t steady_duration_ms(std::chrono::steady_clock::time_point started_at) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at).count();
}

nlohmann::json list_refresh_task_json(
    const ListRefreshTaskSnapshot& task) {
    nlohmann::json result{
        {"task_id", task.id},
        {"state", list_refresh_task_status_name(task.status)},
        {"created_at", task.created_at},
        {"updated_at", task.updated_at},
        {"started_at", task.started_at},
        {"finished_at", task.finished_at},
        {"total", task.total},
        {"completed", task.completed},
        {"current", task.current},
        {"cancel_requested", task.cancel_requested},
        {"revision", task.revision},
        {"refreshed_lists", nlohmann::json::array()},
        {"changed_lists", nlohmann::json::array()},
        {"failed_lists", nlohmann::json::array()},
        {"reloaded", false},
        {"error", ""},
    };
    if (task.terminal_result) {
        const auto& terminal = *task.terminal_result;
        result["refreshed_lists"] =
            terminal.refresh_result.refreshed_lists;
        result["changed_lists"] =
            terminal.refresh_result.changed_lists;
        result["failed_lists"] =
            terminal.refresh_result.failed_lists;
        result["reloaded"] = terminal.reloaded;
        result["error"] = terminal.error;
    }
    return result;
}

} // namespace

std::string get_outbound_tag(const Outbound& ob) {
    return ob.tag;
}

const Outbound* find_outbound(const std::vector<Outbound>& outbounds,
                              const std::string& tag) {
    for (const auto& ob : outbounds) {
        if (ob.tag == tag) {
            return &ob;
        }
    }
    return nullptr;
}

Daemon::Daemon(Config config,
               std::string config_path,
               DaemonOptions opts,
               HookCommandExecutor hook_command_executor)
    : config_store_(config)
    , list_service_(config.daemon.value_or(DaemonConfig{}).cache_dir.value_or("/var/cache/keen-pbr"),
                    max_file_size_bytes(config))
    , ndms_native_import_wal_store_(
          "/opt/var/lib/keen-pbr/native-import-wal")
    , ndms_native_ownership_store_(
          "/opt/var/lib/keen-pbr/native-import-ownership")
    , config_(std::move(config))
    , config_path_(std::move(config_path))
    , opts_(std::move(opts))
    , firewall_(create_firewall(firewall_backend_preference(config_),
                                opts_.use_raw_prerouting))
    , interface_monitor_(std::make_unique<InterfaceMonitor>(
          [this](const InterfaceMonitor::Event& event) {
              handle_interface_event(event);
          }))
    , netlink_()
    , route_table_(netlink_)
    , policy_rules_(netlink_)
    , firewall_state_()
    , url_tester_()
    , outbound_marks_(allocate_outbound_marks(config_.fwmark.value_or(FwmarkConfig{}),
                                              config_.outbounds.value_or(std::vector<Outbound>{})))
    , keenetic_dns_refresh_coordinator_(
          resolver_io_executor_,
          periodic_task_metrics_,
          []() {
              return refresh_keenetic_dns_address_cache(
                  /*force_refresh=*/true);
          },
          [this](std::function<void()> task) {
              return post_control_task(
                  std::move(task), "keenetic-dns-refresh-commit");
          },
          [this](std::uint64_t generation,
                 const KeeneticDnsRefreshResult& result) {
              return commit_keenetic_dns_refresh_result(
                  generation, result);
          })
    , hook_command_executor_(std::move(hook_command_executor))
    , resolver_stream_coordinator_(
          resolver_hook_executor_,
          [this](std::function<void()> task) {
              return post_control_task(
                  std::move(task), "resolver-stream-recovery-commit");
          },
          [this](const ResolverStreamOperation& operation,
                 const ResolverStreamResult& result) {
              complete_resolver_reload_retry_attempt(operation, result);
          })
{
    if (!hook_command_executor_) {
        hook_command_executor_ = default_hook_command_executor;
    }

    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        throw DaemonError("epoll_create1 failed: " + std::string(strerror(errno)));
    }

    setup_signals();
    setup_control_channel();

    const int64_t verify_max_bytes = config_.daemon.value_or(DaemonConfig{})
        .firewall_verify_max_bytes.value_or(static_cast<int64_t>(DEFAULT_FIREWALL_VERIFY_CAPTURE_MAX_BYTES));
    set_firewall_verifier_capture_max_bytes(static_cast<size_t>(verify_max_bytes));

    firewall_state_.set_outbound_marks(outbound_marks_);
    firewall_state_.set_fwmark_mask(fwmark_mask_value(config_.fwmark.value_or(FwmarkConfig{})));
    list_service_.ensure_dir();
    scheduler_ = std::make_unique<Scheduler>(*this);

#ifdef WITH_API
    // DNS diagnostics are interactive and should have only one live probe.
    // Combined with four runtime streams this leaves worker capacity for the
    // REST API even on the minimum eight-thread cpp-httplib pool.
    // Browsers may keep the old EventSource alive briefly while reconnecting
    // after a daemon restart. A single-slot broadcaster turns that harmless
    // overlap into a false "DNS event stream unavailable" result.
    dns_test_broadcaster_ = std::make_unique<SseBroadcaster>(128, 4);
    list_refresh_tasks_.set_publish_callback(
        [this](const ListRefreshTaskSnapshot& task) {
            if (status_stream_) {
                status_stream_->publish_list_refresh(
                    list_refresh_task_json(task));
            }
        });
#endif
    // Acquire ownership before touching the shared control-socket path. A
    // second instance must fail without unlinking the live daemon's socket.
    write_pid_file();
    setup_ipc_control_socket();
}

Daemon::~Daemon() {
    const auto cleanup_step = [](
                                  std::string_view label,
                                  auto&& step) noexcept {
        try {
            step();
        } catch (const std::exception& error) {
            try {
                Logger::instance().error(
                    "Daemon destruction step '{}' failed: {}",
                    label,
                    error.what());
            } catch (...) {
            }
        } catch (...) {
            try {
                Logger::instance().error(
                    "Daemon destruction step '{}' failed: unknown error",
                    label);
            } catch (...) {
            }
        }
    };

    // Cleanup is deliberately stepwise. A failed scheduler cancellation or
    // diagnostic close must never skip the coordinator drain and executor
    // shutdown that protect callbacks from observing partially destroyed
    // Daemon members.
#ifdef WITH_API
    cleanup_step("cancel remote-access recovery watchdog", [this] {
        cancel_remote_access_recovery_watchdog();
    });
    cleanup_step("reset remote-access retry bridge", [this] {
        reset_remote_access_retry_bridge();
    });
#endif
    cleanup_step("close runtime mutation admission", [this] {
        runtime_mutation_admission_.shutdown();
    });
    cleanup_step("close routing test admission", [this] {
        routing_test_admission_.shutdown();
    });
    cleanup_step("stop SIGHUP reload coordinator", [this] {
        sighup_reload_coordinator_.stop();
    });
    cleanup_step("cancel resolver reload retry", [this] {
        cancel_resolver_reload_retry();
    });
    cleanup_step("stop resolver stream coordinator", [this] {
        resolver_stream_coordinator_.request_stop();
    });
    cleanup_step("stop Keenetic DNS refresh coordinator", [this] {
        keenetic_dns_refresh_coordinator_.stop();
    });
    cleanup_step("cancel active list refresh", [this] {
        list_refresh_tasks_.request_cancel_active();
    });
    cleanup_step("invalidate URLTEST work", [this] {
        if (urltest_manager_) {
            urltest_manager_->clear();
        }
    });
    cleanup_step("cancel scheduled work", [this] {
        cancel_owned_conntrack_cleanup_retry();
        scheduler_->cancel_all();
    });
    cleanup_step("discard queued blocking work", [this] {
        blocking_executor_.cancel_pending();
    });
    cleanup_step("drain resolver stream recovery", [this] {
        quiesce_resolver_stream_recovery();
    });
    cleanup_step("drain runtime mutations", [this] {
        quiesce_runtime_mutations();
    });
    cleanup_step("close posted control task gate", [this] {
        {
            KPBR_LOCK_GUARD(control_tasks_mutex_);
            accept_posted_control_tasks_.store(
                false, std::memory_order_release);
        }
    });
    cleanup_step("drain posted control tasks", [this] {
        if (control_fd_ >= 0) {
            handle_control_commands();
        }
    });
    cleanup_step("stop resolver hook executor", [this] {
        resolver_hook_executor_.cancel_pending_and_shutdown();
    });
    cleanup_step("stop resolver stream executor", [this] {
        resolver_stream_executor_.cancel_pending_and_shutdown();
    });
    cleanup_step("stop resolver I/O executor", [this] {
        resolver_io_executor_.cancel_pending_and_shutdown();
    });
    cleanup_step("stop routing test executor", [this] {
        routing_test_executor_.cancel_pending_and_shutdown();
    });
    cleanup_step("stop blocking executor", [this] {
        blocking_executor_.cancel_pending_and_shutdown();
    });
    cleanup_step("close control channel", [this] {
        if (control_fd_ >= 0) {
            epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, control_fd_, nullptr);
            close(control_fd_);
            control_fd_ = -1;
        }
    });
    cleanup_step("remove IPC control socket", [this] {
        remove_ipc_control_socket();
    });
    cleanup_step("close signal channel", [this] {
        if (signal_fd_ >= 0) {
            epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, signal_fd_, nullptr);
            close(signal_fd_);
            signal_fd_ = -1;
        }
    });
    cleanup_step("close epoll", [this] {
        if (epoll_fd_ >= 0) {
            close(epoll_fd_);
            epoll_fd_ = -1;
        }
    });
    cleanup_step("restore signal mask", [] {
        unblock_daemon_signals_for_current_thread();
    });
}

void Daemon::setup_control_channel() {
    control_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (control_fd_ < 0) {
        throw DaemonError("eventfd failed: " + std::string(strerror(errno)));
    }

    struct epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = control_fd_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, control_fd_, &ev) < 0) {
        throw DaemonError("epoll_ctl add control_fd failed: " + std::string(strerror(errno)));
    }
}

void Daemon::setup_ipc_control_socket() {
    ipc_control_socket_path_ = KEEN_PBR_CONTROL_SOCKET;
    if (ipc_control_socket_path_.empty() ||
        ipc_control_socket_path_.size() >=
            sizeof(sockaddr_un::sun_path)) {
        throw DaemonError("control socket path is invalid");
    }

    const auto parent =
        std::filesystem::path(ipc_control_socket_path_).parent_path();
    std::error_code directory_error;
    std::filesystem::create_directories(parent, directory_error);
    if (directory_error) {
        throw DaemonError(
            "failed to create control socket directory: " +
            directory_error.message());
    }

    const group* control_group = ::getgrnam("keen-pbr");
    if (control_group != nullptr) {
        ipc_control_group_id_ = control_group->gr_gid;
        if (::chown(parent.c_str(), 0, ipc_control_group_id_) != 0) {
            throw DaemonError(
                "failed to assign control socket directory group: " +
                std::string(strerror(errno)));
        }
    } else {
        ipc_control_group_id_ = static_cast<gid_t>(-1);
        Logger::instance().info(
            "Optional keen-pbr group is absent; control socket is root-only");
    }
    if (::chmod(parent.c_str(), 0750) != 0) {
        throw DaemonError(
            "failed to set control socket directory mode: " +
            std::string(strerror(errno)));
    }

    struct stat existing {};
    if (::lstat(ipc_control_socket_path_.c_str(), &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode) ||
            ::unlink(ipc_control_socket_path_.c_str()) != 0) {
            throw DaemonError("unsafe stale control socket path");
        }
    } else if (errno != ENOENT) {
        throw DaemonError(
            "failed to inspect control socket path: " +
            std::string(strerror(errno)));
    }

    ipc_control_fd_ =
        ::socket(AF_UNIX,
                 SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                 0);
    if (ipc_control_fd_ < 0) {
        throw DaemonError(
            "control socket create failed: " +
            std::string(strerror(errno)));
    }

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path,
                ipc_control_socket_path_.c_str(),
                ipc_control_socket_path_.size() + 1);
    const gid_t socket_group =
        ipc_control_group_id_ == static_cast<gid_t>(-1)
            ? static_cast<gid_t>(0)
            : ipc_control_group_id_;
    const mode_t socket_mode =
        ipc_control_group_id_ == static_cast<gid_t>(-1) ? 0600 : 0660;
    if (::bind(ipc_control_fd_,
               reinterpret_cast<const sockaddr*>(&address),
               sizeof(address)) != 0 ||
        ::listen(ipc_control_fd_, 16) != 0 ||
        ::chown(ipc_control_socket_path_.c_str(), 0, socket_group) != 0 ||
        ::chmod(ipc_control_socket_path_.c_str(), socket_mode) != 0) {
        const std::string error = strerror(errno);
        remove_ipc_control_socket();
        throw DaemonError("control socket setup failed: " + error);
    }

    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = ipc_control_fd_;
    if (::epoll_ctl(
            epoll_fd_, EPOLL_CTL_ADD, ipc_control_fd_, &event) != 0) {
        const std::string error = strerror(errno);
        remove_ipc_control_socket();
        throw DaemonError(
            "failed to register control socket: " + error);
    }
}

void Daemon::remove_ipc_control_socket() noexcept {
    if (ipc_control_fd_ >= 0) {
        if (epoll_fd_ >= 0) {
            (void)::epoll_ctl(
                epoll_fd_, EPOLL_CTL_DEL, ipc_control_fd_, nullptr);
        }
        ::close(ipc_control_fd_);
        ipc_control_fd_ = -1;
    }
    ipc_control_group_id_ = static_cast<gid_t>(-1);
    if (!ipc_control_socket_path_.empty()) {
        struct stat metadata {};
        if (::lstat(ipc_control_socket_path_.c_str(), &metadata) == 0 &&
            S_ISSOCK(metadata.st_mode)) {
            (void)::unlink(ipc_control_socket_path_.c_str());
        }
        ipc_control_socket_path_.clear();
    }
}

void Daemon::handle_ipc_control_socket() {
    while (true) {
        const int client =
            ::accept4(ipc_control_fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            throw DaemonError(
                "control socket accept failed: " +
                std::string(strerror(errno)));
        }

        timeval timeout{5, 0};
        (void)::setsockopt(
            client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void)::setsockopt(
            client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        nlohmann::json request = nlohmann::json::object();
        nlohmann::json response;
        bool stream_dispatched = false;
        try {
            ucred peer{};
            socklen_t peer_length = sizeof(peer);
            if (::getsockopt(client,
                             SOL_SOCKET,
                             SO_PEERCRED,
                             &peer,
                             &peer_length) != 0) {
                throw ipc::ControlProtocolError(
                    "unable to verify control peer");
            }

            std::uint32_t length = 0;
            receive_all(
                client, reinterpret_cast<char*>(&length), sizeof(length));
            const std::size_t payload_size = ntohl(length);
            if (payload_size > ipc::kMaxControlMessageBytes) {
                throw ipc::ControlProtocolError(
                    "control message exceeds maximum size");
            }
            std::string frame(sizeof(length) + payload_size, '\0');
            std::memcpy(frame.data(), &length, sizeof(length));
            receive_all(client,
                        frame.data() + sizeof(length),
                        payload_size);
            request = ipc::decode_message(frame);
            ipc::validate_request_envelope(request);

            const std::string operation =
                request.at("operation").get<std::string>();
            const bool resolver_hook_inflight =
                ipc_resolver_hook_inflight_.load(
                    std::memory_order_acquire);
            const bool resolver_read_only_operation =
                operation == "status" ||
                operation == "resolver-config-hash";
            const bool root_peer = peer.uid == 0;
            const bool list_control_operation =
                operation == "download" ||
                operation == "download-status" ||
                operation == "download-cancel";
            const bool list_update_member =
                ipc_control_group_id_ != static_cast<gid_t>(-1) &&
                peer_has_group(peer, ipc_control_group_id_) &&
                list_control_operation;
            if (!root_peer && !list_update_member) {
                throw ipc::ControlProtocolError(
                    "control peer is not authorized for this operation");
            }

            const bool supported =
                operation == "status" ||
                operation == "resolver-config-hash" ||
                operation == "download" ||
                operation == "download-status" ||
                operation == "download-cancel" ||
                operation == "test-routing" ||
                operation == "generate-resolver-config";
            if (!supported) {
                response = ipc::make_error_response(
                    request,
                    "unsupported_operation",
                    "unsupported control operation");
            } else if (
                resolver_hook_inflight &&
                operation != "generate-resolver-config" &&
                !resolver_read_only_operation) {
                response = ipc::make_error_response(
                    request,
                    "busy",
                    "mutating control operations are unavailable during "
                    "resolver reload");
            } else if (operation == "test-routing") {
                const std::string target =
                    request.value("target", "");
                if (target.empty()) {
                    throw ipc::ControlProtocolError(
                        "test-routing requires a target");
                }
                const RoutingTestDeadline operation_deadline =
                    std::chrono::steady_clock::now() +
                    kRoutingTestOperationTimeout;
                auto admitted =
                    routing_test_admission_.try_acquire();
                if (!admitted.has_value()) {
                    response = ipc::make_error_response(
                        request,
                        "busy",
                        "too many routing tests are already running");
                } else {
                    auto snapshot = capture_routing_test_snapshot();
                    const auto request_snapshot = request;
                    const bool queued =
                        routing_test_executor_.try_post(
                            "ipc-test-routing",
                            [this,
                             client,
                             request_snapshot,
                             target,
                             operation_deadline,
                             snapshot = std::move(snapshot),
                             lease = std::move(*admitted)]() mutable {
                                UniqueSocketFd client_socket(client);
                                (void)lease;
                                nlohmann::json worker_response;
                                try {
                                    auto result = compute_test_routing(
                                        snapshot.config,
                                        list_service_.cache_manager(),
                                        target,
                                        &snapshot.realized_rules,
                                        operation_deadline,
                                        snapshot.firewall_backend);
                                    result.unapplied_draft =
                                        snapshot.unapplied_draft;
                                    if (result.unapplied_draft) {
                                        result.warnings.push_back(
                                            "An unapplied draft exists; diagnostics use the active applied configuration.");
                                    }

                                    nlohmann::json entries =
                                        nlohmann::json::array();
                                    for (const auto& entry :
                                         result.entries) {
                                        nlohmann::json entry_json = {
                                            {"ip", entry.ip},
                                            {"expected_outbound",
                                             entry.expected_outbound},
                                            {"actual_outbound",
                                             entry.actual_outbound},
                                            {"ok", entry.ok},
                                            {"evaluation",
                                             routing_match_evaluation_code(
                                                 entry.evaluation)},
                                            {"unknown_conditions",
                                             entry.unknown_conditions},
                                        };
                                        if (entry.list_match.has_value()) {
                                            entry_json["list_match"] = {
                                                {"list",
                                                 entry.list_match->list_name},
                                                {"via",
                                                 entry.list_match->via},
                                            };
                                        }
                                        entries.push_back(
                                            std::move(entry_json));
                                    }
                                    worker_response = {
                                        {"protocol_version",
                                         ipc::kControlProtocolVersion},
                                        {"request_id",
                                         request_snapshot.at("request_id")},
                                        {"ok", true},
                                        {"result",
                                         {{"target", result.target},
                                          {"config_scope", "active"},
                                          {"unapplied_draft",
                                           result.unapplied_draft},
                                          {"resolved_ips",
                                           result.resolved_ips},
                                          {"entries",
                                           std::move(entries)},
                                          {"warnings", result.warnings},
                                          {"dns_error",
                                           result.dns_error}}},
                                    };
                                } catch (const RoutingTestTimeoutError& error) {
                                    worker_response =
                                        ipc::make_error_response(
                                            request_snapshot,
                                            "timeout",
                                            error.what());
                                } catch (const std::exception& error) {
                                    worker_response =
                                        ipc::make_error_response(
                                            request_snapshot,
                                            "daemon_error",
                                            error.what());
                                } catch (...) {
                                    worker_response =
                                        ipc::make_error_response(
                                            request_snapshot,
                                            "daemon_error",
                                            "routing test failed with an unknown error");
                                }

                                try {
                                    const auto frame =
                                        ipc::encode_message(
                                            worker_response);
                                    ipc::send_all_bounded_nonblocking(
                                        client_socket.get(),
                                        frame.data(),
                                        frame.size(),
                                        kRoutingTestResponseSendTimeout);
                                } catch (const std::exception& error) {
                                    Logger::instance().warn(
                                        "test-routing control response failed: {}",
                                        error.what());
                                }
                            });
                    if (queued) {
                        stream_dispatched = true;
                    } else {
                        response = ipc::make_error_response(
                            request,
                            "busy",
                            "routing test executor queue is full");
                    }
                }
            } else if (operation == "generate-resolver-config") {
                const RuntimeState runtime_state =
                    runtime_state_machine_.state();
                // This pointer is immutable and is captured on the control
                // loop before any stream admission. A visibly broken runtime
                // may still serve its committed LKG only while routing is
                // genuinely active; stopped/shutdown and missing snapshots
                // stay fail-closed.
                const auto committed_resolver_generation =
                    resolver_generation_snapshot_;
                const bool committed_snapshot_available =
                    committed_resolver_generation &&
                    committed_resolver_generation->list_cache_snapshot;
                const std::string resolver_attempt_id =
                    request.value("resolver_attempt_id", "");
                bool exact_activation_stream_authorized = false;
                if (!resolver_attempt_id.empty() &&
                    is_valid_resolver_attempt_id(resolver_attempt_id)) {
                    KPBR_LOCK_GUARD(resolver_stream_attempt_mutex_);
                    exact_activation_stream_authorized =
                        active_resolver_stream_attempt_id_ ==
                            resolver_attempt_id &&
                        active_resolver_stream_generation_ &&
                        active_resolver_stream_generation_ ==
                            committed_resolver_generation &&
                        inactive_resolver_activation_generation_ ==
                            committed_resolver_generation &&
                        committed_resolver_generation->stream_epoch != 0U;
                }
                const bool resolver_generation_available =
                    resolver_lkg_stream_available(
                        runtime_state,
                        routing_runtime_active_,
                        committed_snapshot_available,
                        exact_activation_stream_authorized);
                if (!resolver_generation_available) {
                    const auto runtime_snapshot =
                        runtime_state_store_.snapshot();
                    response = ipc::make_error_response(
                        request,
                        resolver_runtime_reason(runtime_snapshot),
                        "resolver runtime is not active");
                } else {
                    std::shared_ptr<const ResolverGenerationSnapshot>
                        generation;
                    bool correlated_attempt = false;
                    std::string selection_error;
                    if (!resolver_attempt_id.empty() &&
                        !is_valid_resolver_attempt_id(
                            resolver_attempt_id)) {
                        selection_error = "resolver_attempt_invalid";
                    } else {
                        KPBR_LOCK_GUARD(
                            resolver_stream_attempt_mutex_);
                        if (!active_resolver_stream_attempt_id_.empty()) {
                            if (resolver_attempt_id.empty()) {
                                selection_error =
                                    "resolver_stream_busy";
                            } else if (
                                resolver_attempt_id !=
                                active_resolver_stream_attempt_id_) {
                                selection_error =
                                    "resolver_attempt_mismatch";
                            } else {
                                generation =
                                    active_resolver_stream_generation_;
                                if (!generation ||
                                    generation !=
                                        committed_resolver_generation) {
                                    selection_error =
                                        "resolver_generation_unavailable";
                                } else {
                                    correlated_attempt = true;
                                }
                            }
                        } else {
                            // A valid token left in tmpfs by an older helper
                            // is an ordinary manual stream after the matching
                            // attempt has ended. It may read the current
                            // generation, but cannot acknowledge any hook.
                            generation = committed_resolver_generation;
                        }
                    }
                    if (!selection_error.empty()) {
                        response = ipc::make_error_response(
                            request,
                            selection_error,
                            selection_error == "resolver_stream_busy"
                                ? "a resolver stream is already in progress"
                                : (selection_error ==
                                           "resolver_generation_unavailable"
                                       ? "the committed resolver generation "
                                         "is no longer current"
                                       : "resolver attempt does not match "
                                         "the active stream"));
                    } else if (!generation) {
                        response = ipc::make_error_response(
                            request,
                            "resolver_generation_unavailable",
                            "resolver generation is not available");
                    } else {
                    const Config& active_config = generation->config;
                    const auto dns_config =
                        active_config.dns.value_or(DnsConfig{});
                    const auto cache_dir =
                        active_config.daemon.value_or(DaemonConfig{})
                            .cache_dir.value_or("/var/cache/keen-pbr");
                    const auto requested_resolver =
                        request.value("resolver", "dnsmasq");
                    const auto type =
                        requested_resolver == "dnsmasq-ipset"
                            ? ResolverType::DNSMASQ_IPSET
                            : (requested_resolver == "dnsmasq-nftset"
                                   ? ResolverType::DNSMASQ_NFTSET
                                   : generation->resolver_type);
                    const auto request_id =
                        request.at("request_id").get<std::string>();
                    const bool queued =
                        resolver_stream_executor_.try_post(
                        "generate-resolver-config",
                        [this,
                         client,
                         generation,
                         dns_config,
                         cache_dir,
                         type,
                         request_id,
                         resolver_attempt_id,
                         correlated_attempt] {
                            bool stream_started = false;
                            bool stream_completed = false;
                            try {
                                const Config& active_config =
                                    generation->config;
                                CacheManager cache(
                                    cache_dir,
                                    max_file_size_bytes(active_config));
                                const RouteConfig empty_route_config;
                                const std::map<std::string, ListConfig>
                                    empty_lists;
                                const std::vector<RouteRule>
                                    empty_route_rules;
                                const std::vector<DnsRule> empty_dns_rules;
                                const RouteConfig& route_config =
                                    active_config.route.has_value()
                                        ? *active_config.route
                                        : empty_route_config;
                                const auto& lists =
                                    active_config.lists.has_value()
                                        ? *active_config.lists
                                        : empty_lists;
                                const auto& route_rules =
                                    route_config.rules.has_value()
                                        ? *route_config.rules
                                        : empty_route_rules;
                                const auto& dns_rules =
                                    dns_config.rules.has_value()
                                        ? *dns_config.rules
                                        : empty_dns_rules;
                                if (!generation->list_cache_snapshot) {
                                    throw ipc::ControlProtocolError(
                                        "resolver_generation_cache_unavailable");
                                }
                                std::set<std::string> referenced_lists;
                                for (const auto& rule : route_rules) {
                                    if (!route_rule_enabled(rule)) continue;
                                    for (const auto& list_name :
                                         route_rule_lists(rule)) {
                                        referenced_lists.insert(list_name);
                                    }
                                }
                                for (const auto& rule : dns_rules) {
                                    if (!dns_rule_enabled(rule)) continue;
                                    for (const auto& list_name : rule.list) {
                                        referenced_lists.insert(list_name);
                                    }
                                }
                                for (const auto& list_name :
                                     referenced_lists) {
                                    const auto list =
                                        lists.find(list_name);
                                    if (list == lists.end()) continue;
                                    if (list->second.url.has_value()) {
                                        if (!generation->list_cache_snapshot
                                                 ->contains(list_name)) {
                                            throw ipc::ControlProtocolError(
                                                "active_list_cache_mismatch");
                                        }
                                        if (generation->list_cache_snapshot
                                                ->find(list_name) == nullptr) {
                                            throw ipc::ControlProtocolError(
                                                "list_cache_missing");
                                        }
                                    }
                                    if (list->second.file.has_value() &&
                                        !std::filesystem::is_regular_file(
                                            list->second.file.value())) {
                                        throw ipc::ControlProtocolError(
                                            "active_list_cache_mismatch");
                                    }
                                }

                                const auto header = ipc::encode_message(
                                    {{"protocol_version",
                                      ipc::kControlProtocolVersion},
                                     {"request_id", request_id},
                                     {"ok", true},
                                     {"stream", true}});
                                send_all(
                                    client, header.data(), header.size());
                                stream_started = true;

                                SocketStreamBuffer buffer(client);
                                std::ostream output(&buffer);
                                output
                                    << "# keen-pbr resolver state: active\n";
                                ListStreamer streamer(
                                    cache,
                                    generation->list_cache_snapshot);
                                DnsServerRegistry registry(
                                    dns_config,
                                    generation->keenetic_dns.snapshot);
                                DnsmasqGenerator generator(
                                    registry,
                                    streamer,
                                    route_config,
                                    dns_config,
                                    lists,
                                    type,
                                    KEEN_PBR3_VERSION_FULL_STRING,
                                    generation->ipv6_policy,
                                    generation->trusted_dns_interfaces);
                                generator.generate(output);
                                output
                                    << "txt-record=resolver-state.keen.pbr,"
                                    << std::time(nullptr)
                                    << "|active|runtime_active\n";
                                output.flush();
                                if (!output) {
                                    throw ipc::ControlProtocolError(
                                        "resolver stream write failed");
                                }
                                const std::uint32_t end_of_stream = 0;
                                send_all(
                                    client,
                                    reinterpret_cast<const char*>(
                                        &end_of_stream),
                                    sizeof(end_of_stream));
                                stream_completed = true;
                            } catch (const std::exception& error) {
                                if (!stream_started) {
                                    try {
                                        const auto error_response =
                                            ipc::make_error_response(
                                                {{"request_id", request_id}},
                                                error.what(),
                                                error.what());
                                        const auto error_frame =
                                            ipc::encode_message(
                                                error_response);
                                        send_all(client,
                                                 error_frame.data(),
                                                 error_frame.size());
                                    } catch (...) {
                                    }
                                } else {
                                    Logger::instance().warn(
                                        "resolver config stream failed: {}",
                                        error.what());
                                }
                            }
                            ::close(client);
                            if (stream_completed && correlated_attempt) {
                                bool still_exact = false;
                                {
                                    KPBR_LOCK_GUARD(
                                        resolver_stream_attempt_mutex_);
                                    still_exact =
                                        active_resolver_stream_attempt_id_ ==
                                            resolver_attempt_id &&
                                        active_resolver_stream_generation_ ==
                                            generation;
                                }
                                if (still_exact) {
                                    resolver_stream_completed_epoch_.store(
                                        generation->stream_epoch,
                                        std::memory_order_release);
                                    resolver_stream_coordinator_
                                        .notify_stream_completed(
                                            resolver_attempt_id,
                                            generation->stream_epoch);
                                }
                            }
                        });
                    if (queued) {
                        stream_dispatched = true;
                    } else {
                        response = ipc::make_error_response(
                            request,
                            "daemon_error",
                            "resolver stream executor is unavailable");
                    }
                    }
                }
            } else if (operation == "download") {
                const bool reload = request.value("reload", false);
                if (request.value("task_response", false)) {
                    const auto start = start_remote_list_refresh_task(
                        reload, "ipc");
                    if (!start.accepted) {
                        response = ipc::make_error_response(
                            request,
                            start.error == "busy" ? "busy" : "daemon_error",
                            start.error == "busy"
                                ? "another list refresh is in progress"
                                : start.error);
                    } else {
                        response = {
                            {"protocol_version",
                             ipc::kControlProtocolVersion},
                            {"request_id", request.at("request_id")},
                            {"ok", true},
                            {"result", list_refresh_task_json(start.task)},
                        };
                    }
                } else {
                    // Protocol-v1 callers need a terminal response, but the
                    // network operation must not run on the event-loop thread.
                    // Start the same bounded task and let a second executor
                    // slot wait for its terminal snapshot before replying in
                    // the legacy wire shape.
                    const auto start = start_remote_list_refresh_task(
                        reload, "ipc-legacy");
                    if (!start.accepted) {
                        response = ipc::make_error_response(
                            request,
                            start.error == "busy" ? "busy" : "daemon_error",
                            start.error == "busy"
                                ? "another list refresh is in progress"
                                : start.error);
                    } else {
                        const auto task_id = start.task.id;
                        const auto request_id =
                            request.at("request_id").get<std::string>();
                        const bool queued = blocking_executor_.try_post(
                            "ipc-legacy-list-refresh-response",
                            [this, client, task_id, request_id] {
                                nlohmann::json terminal_response;
                                try {
                                    std::optional<ListRefreshTaskSnapshot> task;
                                    do {
                                        std::this_thread::sleep_for(
                                            std::chrono::milliseconds(50));
                                        task = list_refresh_tasks_.find(task_id);
                                    } while (
                                        task &&
                                        !list_refresh_task_status_is_terminal(
                                            task->status));

                                    if (!task || !task->terminal_result) {
                                        terminal_response =
                                            ipc::make_error_response(
                                                {{"request_id", request_id}},
                                                "daemon_error",
                                                "list refresh task disappeared");
                                    } else {
                                        const auto& terminal =
                                            *task->terminal_result;
                                        const auto& refresh =
                                            terminal.refresh_result;
                                        const bool ok =
                                            task->status ==
                                                ListRefreshTaskStatus::Succeeded &&
                                            refresh.failed_lists.empty();
                                        terminal_response = {
                                            {"protocol_version",
                                             ipc::kControlProtocolVersion},
                                            {"request_id", request_id},
                                            {"ok", ok},
                                            {"result",
                                             {{"refreshed_lists",
                                               refresh.refreshed_lists},
                                              {"changed_lists",
                                               refresh.changed_lists},
                                              {"failed_lists",
                                               refresh.failed_lists},
                                              {"reloaded",
                                               terminal.reloaded}}},
                                        };
                                    }
                                    const auto frame =
                                        ipc::encode_message(terminal_response);
                                    send_all(
                                        client, frame.data(), frame.size());
                                } catch (const std::exception& error) {
                                    Logger::instance().warn(
                                        "legacy list refresh response failed: {}",
                                        error.what());
                                }
                                ::close(client);
                            });
                        if (queued) {
                            stream_dispatched = true;
                        } else {
                            (void)list_refresh_tasks_.request_cancel(task_id);
                            response = ipc::make_error_response(
                                request,
                                "daemon_error",
                                "list refresh response executor is unavailable");
                        }
                    }
                }
            } else if (operation == "download-status" ||
                       operation == "download-cancel") {
                const auto task_id = request.value("task_id", "");
                if (task_id.empty()) {
                    throw ipc::ControlProtocolError(
                        operation + " requires a task_id");
                }
                auto task = list_refresh_tasks_.find(task_id);
                if (!task) {
                    response = ipc::make_error_response(
                        request,
                        "not_found",
                        "list refresh task was not found");
                } else {
                    bool cancel_accepted = false;
                    if (operation == "download-cancel" &&
                        !list_refresh_task_status_is_terminal(
                            task->status)) {
                        cancel_accepted =
                            list_refresh_tasks_.request_cancel(task_id);
                        task = list_refresh_tasks_.find(task_id);
                    }
                    response = {
                        {"protocol_version",
                         ipc::kControlProtocolVersion},
                        {"request_id", request.at("request_id")},
                        {"ok", true},
                        {"result", list_refresh_task_json(*task)},
                    };
                    if (operation == "download-cancel") {
                        response["result"]["cancel_accepted"] =
                            cancel_accepted;
                    }
                }
            } else if (operation == "status") {
                const auto snapshot =
                    runtime_state_store_.snapshot();
                RoutingHealthReport routing_health;
                if (snapshot.runtime_state == RuntimeState::starting) {
                    routing_health.firewall_backend =
                        firewall_->backend();
                    routing_health.firewall_chain.detail =
                        "routing runtime initialization is in progress";
                } else {
                    routing_health = build_routing_health_report(
                        firewall_->backend(),
                        firewall_->uses_raw_prerouting(),
                        snapshot.firewall_state,
                        snapshot.route_specs,
                        snapshot.policy_rule_specs,
                        netlink_);
                }
                // Filled from the live backend rather than recomputed here:
                // the state is what the last apply actually observed, and
                // re-inspecting the chain from a status request would both
                // duplicate the writer and answer a different question.
                routing_health.ttl_bypass_state =
                    firewall_->ttl_bypass_state_name();
                routing_health.ttl_bypass_detail =
                    firewall_->ttl_bypass_state_detail();
                routing_health.ppe_deoffload =
                    firewall_->ppe_deoffload_snapshot();
                response = {
                    {"protocol_version",
                     ipc::kControlProtocolVersion},
                    {"request_id", request.at("request_id")},
                    {"ok", true},
                    {"result",
                     {{"runtime_state",
                       runtime_state_name(snapshot.runtime_state)},
                      {"config_path", config_path_},
                      {"config", config_store_.active_config()},
                      {"routing_health",
                       routing_health_report_to_json(
                           routing_health)},
                      {"runtime_state_reason",
                       snapshot.runtime_state_reason},
                      {"routing_runtime_active",
                       snapshot.routing_runtime_active},
                      {"resolver_config_hash",
                       snapshot.resolver_config_hash}}},
                };
            } else {
                const auto snapshot =
                    runtime_state_store_.snapshot();
                response = {
                    {"protocol_version",
                     ipc::kControlProtocolVersion},
                    {"request_id", request.at("request_id")},
                    {"ok", true},
                    {"result",
                     {{"resolver_config_hash",
                       snapshot.resolver_config_hash}}},
                };
            }
        } catch (const std::exception& error) {
            response = ipc::make_error_response(
                request, "protocol_error", error.what());
        }

        if (!stream_dispatched) {
            try {
                const auto frame = ipc::encode_message(response);
                send_all(client, frame.data(), frame.size());
            } catch (const std::exception& error) {
                Logger::instance().warn(
                    "control response failed: {}", error.what());
            }
            ::close(client);
        }
    }
}

void Daemon::wake_control_loop() {
    const uint64_t inc = 1;
    ssize_t n = -1;
    do {
        n = write(control_fd_, &inc, sizeof(inc));
    } while (n < 0 && errno == EINTR);
    // EAGAIN means the eventfd already contains a wake token, so the newly
    // queued task is covered by an existing readable edge.
    if (n < 0 && errno == EAGAIN) {
        return;
    }
    if (n != static_cast<ssize_t>(sizeof(inc))) {
        throw DaemonError("eventfd write failed: " + std::string(strerror(errno)));
    }
}

bool Daemon::cancel_control_task_if_still_queued(
    const daemon_detail::ControlTaskAdmissionHandle& token) noexcept {
    try {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        return daemon_detail::erase_exact_control_task_if_still_queued(
            control_tasks_, token, &ControlTask::admission_token);
    } catch (...) {
        // If exact rollback cannot obtain queue authority, do not claim that
        // the task was cancelled. The event loop may already own it.
        return false;
    }
}

void Daemon::quiesce_runtime_mutations() noexcept {
    auto next_warning = std::chrono::steady_clock::now() +
        std::chrono::seconds{5};
    while (!runtime_mutation_admission_.wait_for_idle_for(
        std::chrono::milliseconds{10})) {
        try {
            // An admitted resolver hook may still be waiting for dnsmasq's
            // config-script IPC request, while an API/SIGHUP writer may be
            // waiting for its terminal control callback. Keep both channels
            // alive until the exact mutation lease is returned, including
            // startup rollback where event_loop_active_ was never set.
            if (ipc_control_fd_ >= 0) {
                handle_ipc_control_socket();
            }
            if (control_fd_ >= 0) {
                handle_control_commands();
            }
        } catch (const std::exception& error) {
            try {
                Logger::instance().error(
                    "Runtime mutation shutdown drain failed: {}",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
            try {
                Logger::instance().error(
                    "Runtime mutation shutdown drain failed: unknown error");
            } catch (...) {
            }
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= next_warning) {
            try {
                const auto active = runtime_mutation_admission_.active();
                Logger::instance().warn(
                    "Waiting for admitted runtime mutation '{}' to finish",
                    active.has_value()
                        ? active->label
                        : std::string{"unknown"});
            } catch (...) {
            }
            next_warning = now + std::chrono::seconds{5};
        }
    }
}

void Daemon::quiesce_resolver_stream_recovery() noexcept {
    auto next_warning = std::chrono::steady_clock::now() +
        std::chrono::seconds{5};
    while (!resolver_stream_coordinator_.wait_for_idle_for(
        std::chrono::milliseconds{10})) {
        try {
            if (ipc_control_fd_ >= 0) {
                handle_ipc_control_socket();
            }
            if (control_fd_ >= 0) {
                handle_control_commands();
            }
        } catch (const std::exception& error) {
            try {
                Logger::instance().error(
                    "Resolver recovery shutdown drain failed: {}",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= next_warning) {
            try {
                Logger::instance().warn(
                    "Waiting for the accepted resolver recovery hook to "
                    "finish");
            } catch (...) {
            }
            next_warning = now + std::chrono::seconds{5};
        }
    }
}

bool Daemon::is_event_loop_thread() const {
    return event_loop_thread_id_.load(std::memory_order_relaxed) == std::this_thread::get_id();
}

void Daemon::enqueue_control_task(std::function<void()> task,
                                  bool wait_for_completion,
                                  const std::string& label,
                                  bool require_active_event_loop) {
    if (!task) {
        return;
    }

    const auto effective_label = label.empty() ? std::string("control-task") : label;
    const TraceId trace_id = ensure_trace_id();
    auto run_inline = [task = std::move(task), effective_label, trace_id]() mutable {
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        try {
            Logger::instance().trace(
                "control_task_start", "label={} mode=inline", effective_label);
        } catch (...) {
        }
        try {
            task();
            try {
                Logger::instance().trace(
                    "control_task_end",
                    "label={} mode=inline duration_ms={}",
                    effective_label,
                    steady_duration_ms(started_at));
            } catch (...) {
            }
        } catch (const std::exception& e) {
            try {
                Logger::instance().trace(
                    "control_task_error",
                    "label={} mode=inline duration_ms={} error={}",
                    effective_label,
                    steady_duration_ms(started_at),
                    e.what());
            } catch (...) {
            }
            throw;
        } catch (...) {
            try {
                Logger::instance().trace(
                    "control_task_error",
                    "label={} mode=inline duration_ms={} error=unknown",
                    effective_label,
                    steady_duration_ms(started_at));
            } catch (...) {
            }
            throw;
        }
    };

    if (!event_loop_active_.load(std::memory_order_acquire) ||
        event_loop_thread_id_.load(std::memory_order_relaxed) == std::thread::id{}) {
        if (require_active_event_loop) {
            throw DaemonError("control loop is not running");
        }
        run_inline();
        return;
    }

    if (event_loop_thread_id_.load(std::memory_order_relaxed) == std::this_thread::get_id()) {
        run_inline();
        return;
    }

    // This optimistic check keeps shutdown rejection out of the allocation
    // path. Shutdown closes the same gate under control_tasks_mutex_; the
    // mandatory in-lock recheck below is the actual linearization point.
    if (!accept_posted_control_tasks_.load(std::memory_order_acquire)) {
        throw DaemonError("control task admission is closed");
    }

    std::shared_ptr<std::promise<void>> completion;
    std::future<void> completion_future;
    std::function<void()> queued_callback;
    if (wait_for_completion) {
        completion = std::make_shared<std::promise<void>>();
        completion_future = completion->get_future();
        queued_callback =
            [cmd = std::move(run_inline), completion]() mutable {
                try {
                    cmd();
                    completion->set_value();
                } catch (...) {
                    completion->set_exception(std::current_exception());
                }
            };
    } else {
        queued_callback = std::move(run_inline);
    }

    const auto admission_token =
        std::make_shared<const daemon_detail::ControlTaskAdmissionToken>();
    auto queued_task = std::make_unique<ControlTask>(ControlTask{
        .callback = std::move(queued_callback),
        .label = effective_label,
        .trace_id = trace_id,
        .admission_token = admission_token,
    });
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        if (!daemon_detail::publish_control_task_if_admitted(
                control_tasks_,
                accept_posted_control_tasks_.load(
                    std::memory_order_acquire),
                std::move(queued_task))) {
            // The task never crossed the ownership boundary. In the waiting
            // case stack unwinding destroys every promise owner, so the
            // private future cannot become a stranded shutdown wait.
            throw DaemonError("control task admission closed during shutdown");
        }
    }
    try {
        Logger::instance().trace("control_task_enqueue",
                                 "label={} wait={}",
                                 effective_label,
                                 wait_for_completion ? "true" : "false");
    } catch (...) {
    }

    try {
        wake_control_loop();
    } catch (const std::exception& error) {
        const auto wake_failure = std::current_exception();
        if (cancel_control_task_if_still_queued(admission_token)) {
            // Exact rollback restored caller ownership. Complete the private
            // promise as well, then report rejection; no queued callback can
            // subsequently act on a descriptor the caller releases.
            if (completion) {
                try {
                    completion->set_exception(wake_failure);
                } catch (...) {
                }
            }
            std::rethrow_exception(wake_failure);
        }

        // The event loop already swapped this exact token out of the queue.
        // Its callback is authoritative; returning a wake error would cause
        // callers such as Scheduler to release resources still owned by it.
        try {
            Logger::instance().error(
                "Control task '{}' wake failed after the event loop claimed "
                "the task: {}",
                effective_label,
                error.what());
        } catch (...) {
        }
    } catch (...) {
        const auto wake_failure = std::current_exception();
        if (cancel_control_task_if_still_queued(admission_token)) {
            if (completion) {
                try {
                    completion->set_exception(wake_failure);
                } catch (...) {
                }
            }
            std::rethrow_exception(wake_failure);
        }
        try {
            Logger::instance().error(
                "Control task '{}' wake failed after the event loop claimed "
                "the task: unknown error",
                effective_label);
        } catch (...) {
        }
    }

    if (wait_for_completion) {
        // A claimed callback settles this future with its actual result. In
        // particular, task-body exceptions remain visible to the caller and
        // are never mistaken for a wake failure.
        completion_future.get();
    }
}

bool Daemon::post_control_task(std::function<void()> task, const std::string& label) {
    if (!task) return false;
    if (!accept_posted_control_tasks_.load(std::memory_order_acquire)) {
        Logger::instance().trace("control_task_skip",
                                 "label={} reason=posted_tasks_disabled",
                                 label.empty() ? "post-control-task" : label);
        return false;
    }

    const auto effective_label = label.empty() ? std::string("post-control-task") : label;
    const TraceId trace_id = ensure_trace_id();
    auto traced_task = [task = std::move(task), effective_label, trace_id]() mutable {
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        // Diagnostic logging must never decide whether an already-admitted
        // control task runs. In particular, an allocation failure while
        // formatting a trace event must not strand asynchronous ownership.
        try {
            Logger::instance().trace(
                "control_task_start", "label={} mode=posted", effective_label);
        } catch (...) {
        }
        try {
            task();
            try {
                Logger::instance().trace(
                    "control_task_end",
                    "label={} mode=posted duration_ms={}",
                    effective_label,
                    steady_duration_ms(started_at));
            } catch (...) {
            }
        } catch (const std::exception& e) {
            try {
                Logger::instance().trace(
                    "control_task_error",
                    "label={} mode=posted duration_ms={} error={}",
                    effective_label,
                    steady_duration_ms(started_at),
                    e.what());
            } catch (...) {
            }
            throw;
        } catch (...) {
            try {
                Logger::instance().trace(
                    "control_task_error",
                    "label={} mode=posted duration_ms={} error=unknown",
                    effective_label,
                    steady_duration_ms(started_at));
            } catch (...) {
            }
            throw;
        }
    };

    auto queued_task = std::make_unique<ControlTask>(ControlTask{
        .callback = std::move(traced_task),
        .label = effective_label,
        .trace_id = trace_id,
        .admission_token = {},
    });
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        // Serialize admission with shutdown. The optimistic check above keeps
        // the normal rejection path cheap; this second check prevents a task
        // from being queued after shutdown disabled deferred commits.
        if (!accept_posted_control_tasks_.load(
                std::memory_order_acquire)) {
            return false;
        }
        control_tasks_.push_back(std::move(queued_task));
    }
    try {
        Logger::instance().trace("control_task_enqueue",
                                 "label={} wait=false mode=post",
                                 effective_label);
    } catch (...) {
    }
    try {
        wake_control_loop();
    } catch (const std::exception& error) {
        // Ownership has already moved into control_tasks_. Returning false or
        // throwing here would let an asynchronous producer release its
        // lifetime while the queued callback still captures it. Keep the
        // enqueue authoritative; another epoll event or shutdown drain will
        // service the callback.
        try {
            Logger::instance().error(
                "Posted control task '{}' was queued but the control-loop "
                "wake failed: {}",
                effective_label,
                error.what());
        } catch (...) {
        }
    } catch (...) {
        // The callback is already owned by control_tasks_. Keep the enqueue
        // authoritative even when the wake or its diagnostics fail.
    }
    return true;
}

void Daemon::enqueue_control_command(std::function<void()> command,
                                     bool wait_for_completion,
                                     const std::string& label) {
    enqueue_control_task(std::move(command), wait_for_completion, label);
}

void Daemon::handle_control_commands() {
    uint64_t counter = 0;
    while (read(control_fd_, &counter, sizeof(counter)) > 0) {
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        throw DaemonError("eventfd read failed: " + std::string(strerror(errno)));
    }

    std::vector<ControlTaskOwner> commands;
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        commands.swap(control_tasks_);
    }

    for (auto& command : commands) {
        try {
            command->callback();
        } catch (const std::exception& error) {
            // One failed deferred callback must not discard the remaining
            // batch. Resolver and lifecycle completions may own single-flight
            // leases which are returned only by their callback.
            try {
                Logger::instance().error(
                    "Control task '{}' failed: {}",
                    command->label.empty()
                        ? "control-task"
                        : command->label,
                    error.what());
            } catch (...) {
            }
        } catch (...) {
            try {
                Logger::instance().error(
                    "Control task '{}' failed: unknown error",
                    command->label.empty()
                        ? "control-task"
                        : command->label);
            } catch (...) {
            }
        }
    }
}

void Daemon::setup_signals() {
    block_daemon_signals_for_current_thread();
    sigset_t mask = daemon_signal_mask();

    signal_fd_ = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd_ < 0) {
        throw DaemonError("signalfd failed: " + std::string(strerror(errno)));
    }

    struct epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = signal_fd_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, signal_fd_, &ev) < 0) {
        throw DaemonError("epoll_ctl add signalfd failed: " + std::string(strerror(errno)));
    }
}

void Daemon::handle_signal() {
    bool terminate_requested = false;
    bool full_refresh_requested = false;
    bool nat_refresh_requested = false;
    bool reload_requested = false;

    // signalfd is nonblocking. Inspect the complete queued batch before
    // dispatching any non-terminal work so SIGUSR1/2 queued beside SIGTERM
    // cannot reopen runtime work during shutdown.
    for (;;) {
        struct signalfd_siginfo info{};
        const ssize_t n = read(signal_fd_, &info, sizeof(info));
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        if (n != sizeof(info)) {
            break;
        }
        switch (info.ssi_signo) {
        case SIGTERM:
        case SIGINT:
            terminate_requested = true;
            break;
        case SIGUSR1:
            full_refresh_requested = true;
            break;
        case SIGUSR2:
            nat_refresh_requested = true;
            break;
        case SIGHUP:
            reload_requested = true;
            break;
        default:
            break;
        }
    }

    if (terminate_requested) {
        // Close writer admission at the terminal signal boundary, not later
        // in the shutdown tail. Events already returned in this epoll batch
        // must not begin a new config or routing-test operation.
        runtime_mutation_admission_.shutdown();
        routing_test_admission_.shutdown();
        running_.store(false, std::memory_order_release);
        return;
    }
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    if (full_refresh_requested) {
        handle_sigusr1();
    }
    if (nat_refresh_requested) {
        handle_sigusr2();
    }
    if (reload_requested) {
        handle_sighup();
    }
}

void Daemon::handle_sigusr1() {
    auto& log = Logger::instance();
    log.info("SIGUSR1: scheduling full firewall refresh...");
    schedule_netfilter_runtime_refresh(NetfilterRefreshReason::full);
}

void Daemon::handle_sigusr2() {
    auto& log = Logger::instance();
    log.info("SIGUSR2: scheduling NAT firewall refresh...");
    schedule_netfilter_runtime_refresh(NetfilterRefreshReason::nat_only);
}

void Daemon::schedule_owned_snat_health_check() {
    if (owned_snat_health_task_id_ >= 0) {
        return;
    }
    owned_snat_health_task_id_ = scheduler_->schedule_repeating(
        OWNED_SNAT_HEALTH_INTERVAL,
        [this]() { check_owned_snat_health(); },
        "owned-snat-health");
}

void Daemon::cancel_owned_snat_health_check() {
    if (owned_snat_health_task_id_ < 0) {
        return;
    }
    scheduler_->cancel(owned_snat_health_task_id_);
    owned_snat_health_task_id_ = -1;
}

void Daemon::check_owned_snat_health() {
    if (should_run_periodic_netfilter_refresh(
            netfilter_refresh_task_id_ >= 0,
            pending_netfilter_refresh_reasons_ != 0U)) {
        // A failed timer installation retains the exact full/NAT reason bits.
        // Repair the main firewall generation before any companion subsystem;
        // a verified central refresh will then request remote-access recovery.
        reconcile_pending_netfilter_runtime_refresh();
        return;
    }
    const std::uint64_t failed_completion_serial =
        meta_udp443_cleanup_completion_admission_failed_serial_.exchange(
            0U, std::memory_order_acq_rel);
    if (failed_completion_serial != 0U) {
        if (pending_meta_udp443_cleanup_.has_value() &&
            meta_udp443_failed_completion_matches_pending(
                failed_completion_serial,
                pending_meta_udp443_cleanup_->schedule_serial)) {
            pending_meta_udp443_cleanup_->worker_inflight = false;
            report_meta_udp443_degraded(
                "an exact-cleanup worker completion could not be admitted to "
                "the control loop; the durable plan will be retried");
        }
    }
    const bool runtime_retry_pending =
        runtime_firewall_retry_.retry_pending();
    const bool netfilter_refresh_pending =
        netfilter_refresh_task_id_ >= 0 ||
        pending_netfilter_refresh_reasons_ != 0;
    const auto current_runtime_generation =
        runtime_generation_.load(std::memory_order_acquire);
    const bool urltest_recovery_without_timer =
        should_run_periodic_urltest_firewall_recovery(
            routing_runtime_active_,
            urltest_after_firewall_gate_.waiting_for(
                current_runtime_generation),
            runtime_retry_pending,
            netfilter_refresh_pending);
    if (urltest_recovery_without_timer) {
        // Scheduler admission itself can fail after a transient URLTEST
        // publication. This repeating control-loop task is the independent
        // durable owner: a closed gate can therefore never wait forever for
        // another external netfilter event.
        auto task_metrics =
            periodic_task_metrics_.begin("owned-snat-health");
        try {
            const bool recovered =
                refresh_iproute_and_firewall_runtime(
                    0,
                    std::nullopt,
                    std::nullopt,
                    /*schedule_catalog_refresh=*/false,
                    runtime_firewall_retry_
                        .pending_owned_snat_recovery());
            if (recovered) {
                task_metrics.success();
            } else {
                task_metrics.failure(
                    "URLTEST firewall recovery did not converge");
            }
        } catch (const std::exception& error) {
            task_metrics.failure(error.what());
            Logger::instance().info(
                "Periodic URLTEST firewall recovery could not install its "
                "next retry owner: {}",
                error.what());
        } catch (...) {
            task_metrics.failure(
                "URLTEST firewall recovery failed with an unknown error");
        }
        return;
    }
    const bool resolver_recovery_without_timer =
        should_run_periodic_resolver_reload_recovery(
            routing_runtime_active_,
            resolver_reload_retry_task_id_ >= 0,
            resolver_reload_retry_pending_,
            resolver_after_firewall_gate_.waiting_for(
                current_runtime_generation),
            resolver_reload_retry_pending_generation_,
            current_runtime_generation);
    if (resolver_recovery_without_timer) {
        const auto attempt = resolver_reload_retry_pending_attempt_;
        const auto generation =
            resolver_reload_retry_pending_generation_;
        resolver_reload_retry_pending_ = false;
        resolver_reload_retry_pending_attempt_ = 0U;
        resolver_reload_retry_pending_generation_ = 0U;
        start_resolver_reload_retry_attempt(attempt, generation);
        return;
    }
    const bool recovery_pending =
        runtime_retry_pending ||
        runtime_firewall_retry_.owned_snat_recovery_pending();
    if (!routing_runtime_active_ ||
        recovery_pending ||
        netfilter_refresh_pending) {
        periodic_task_metrics_.record_skipped(
            "owned-snat-health",
            !routing_runtime_active_
                ? "routing runtime is inactive"
                : "netfilter recovery is already pending");
        return;
    }

    // Reuse this already serialized control-loop cadence for PPE liveness.
    // A fresh NFQWS observation detects external init/process/queue changes;
    // a semantic counter read validates that the installed graph still equals
    // the published one. Either drift source coalesces into the existing FULL
    // netfilter refresh owner. API/IPC getters remain passive.
    const auto stored_ppe_desired = firewall_->ppe_deoffload_desired();
    const bool configured_ppe_auto =
        config_.daemon.value_or(DaemonConfig{})
            .ppe_deoffload_mode.value_or(api::PpeDeoffloadMode::OFF) ==
        api::PpeDeoffloadMode::AUTO;
    const bool ppe_liveness_owned = configured_ppe_auto ||
        stored_ppe_desired.mode == PpeDeoffloadMode::automatic;
    bool ppe_desired_drift = false;
    try {
        const auto observed_ppe_desired =
            observe_ppe_deoffload_desired(config_);
        ppe_desired_drift =
            !ppe_deoffload_desired_semantically_equal(
                stored_ppe_desired, observed_ppe_desired);
    } catch (...) {
        // An auto-mode observer failure cannot prove the old active contract.
        // Let the normal full-refresh/retry path establish cleanup or a fresh
        // graph; off mode is intentionally a no-observation path.
        ppe_desired_drift = configured_ppe_auto;
    }
    if (should_schedule_periodic_ppe_full_refresh(
            routing_runtime_active_,
            recovery_pending,
            netfilter_refresh_pending,
            ppe_liveness_owned,
            ppe_desired_drift,
            /*live_graph_semantic_drift=*/false)) {
        schedule_netfilter_runtime_refresh(NetfilterRefreshReason::full);
        periodic_task_metrics_.record_skipped(
            "owned-snat-health",
            "PPE active-runtime contract drift scheduled a full refresh");
        return;
    }

    const auto ppe_observation =
        firewall_->refresh_ppe_deoffload_observation();
    if (should_schedule_periodic_ppe_full_refresh(
            routing_runtime_active_,
            recovery_pending,
            netfilter_refresh_pending,
            ppe_liveness_owned,
            /*desired_contract_drift=*/false,
            ppe_observation ==
                PpeObservationRefreshResult::semantic_drift)) {
        schedule_netfilter_runtime_refresh(NetfilterRefreshReason::full);
        periodic_task_metrics_.record_skipped(
            "owned-snat-health",
            "PPE live graph drift scheduled a full refresh");
        return;
    }

    auto task_metrics =
        periodic_task_metrics_.begin("owned-snat-health");
    OwnedSnatState state = OwnedSnatState::unknown;
    OwnedForwardUdpRejectState meta_state =
        OwnedForwardUdpRejectState::unknown;
    try {
        state = firewall_->inspect_owned_snat_state();
        meta_state = firewall_->inspect_forward_udp_reject_state();
    } catch (const std::exception& error) {
        // This is a fallback guard, not an alert source. An inspection error
        // must neither disrupt the event loop nor emit one message per tick.
        task_metrics.failure(error.what());
        return;
    } catch (...) {
        task_metrics.failure("owned SNAT inspection failed");
        return;
    }
    const auto meta_selection = resolve_meta_udp_443_policy_selection(
        config_,
        firewall_state_.get_rules(),
        firewall_state_.get_fwmark_mask());
    const bool messages_first_active = meta_selection.active();
    const bool fastnat_disabled =
        !messages_first_active || fastnat_is_disabled_or_unavailable();
    const bool repair_snat = should_run_periodic_snat_repair(
            routing_runtime_active_,
            recovery_pending,
            netfilter_refresh_pending,
            state);
    const bool repair_meta =
        should_run_periodic_forward_udp_reject_repair(
            routing_runtime_active_,
            recovery_pending,
            netfilter_refresh_pending,
            messages_first_active,
            fastnat_disabled,
            meta_state);
    if (should_resume_pending_meta_udp443_cleanup(
            messages_first_active,
            fastnat_disabled,
            meta_state,
            meta_udp443_cleanup_retry_task_id_,
            pending_meta_udp443_cleanup_.has_value(),
            pending_meta_udp443_cleanup_.has_value() &&
                pending_meta_udp443_cleanup_->worker_inflight)) {
        const auto& pending = *pending_meta_udp443_cleanup_;
        schedule_meta_udp443_activation_cleanup_retry(
            pending.plan,
            pending.runtime_generation,
            pending.cleanup_epoch,
            pending.attempt);
        if (meta_udp443_cleanup_retry_task_id_ < 0) {
            task_metrics.failure(
                "Meta UDP/443 exact cleanup retry could not be scheduled");
            return;
        }
    }
    if (messages_first_active && !fastnat_disabled) {
        // Reapplying the filter cannot repair a bypass outside netfilter and
        // would discard the durable exact-cleanup plan at apply entry. Keep
        // the current committed policy and pending plan intact until the init
        // layer or firmware restores verified FastNAT-off traversal.
        report_meta_udp443_degraded(
            "FastNAT is enabled while messages-first is active");
        task_metrics.failure(
            "Meta UDP/443 policy requires FastNAT to remain disabled");
        return;
    }
    if (!repair_snat && !repair_meta) {
        if (meta_state == OwnedForwardUdpRejectState::unknown) {
            task_metrics.failure(
                "Meta UDP/443 policy health could not be inspected");
            return;
        }
        task_metrics.noop();
        return;
    }

    if (repair_meta) {
        report_meta_udp443_degraded(
            !fastnat_disabled
                ? "FastNAT is enabled while messages-first is active"
                : (meta_state == OwnedForwardUdpRejectState::missing
                       ? "the owned first FORWARD hook or rule is missing"
                       : "owned UDP/443 blocking artifacts are stale"));
    }
    Logger::instance().info(
        "Periodic owned-firewall health check detected drift; repairing {}{}.",
        repair_snat ? "SNAT" : "",
        repair_meta
            ? (repair_snat ? " and Meta UDP/443" : "Meta UDP/443")
            : "");
    const bool repaired = refresh_iproute_and_firewall_runtime(
        0,
        std::nullopt,
        std::nullopt,
        /*schedule_catalog_refresh=*/false,
        OwnedSnatRecovery{
            /*requested=*/repair_snat,
            /*missing_observed=*/false});
    if (repaired) {
        task_metrics.success();
    } else {
        task_metrics.failure("owned SNAT repair did not converge");
    }
}

void Daemon::reconcile_pending_netfilter_runtime_refresh() noexcept {
    const std::uint8_t reasons = pending_netfilter_refresh_reasons_;
    if (reasons == 0U) {
        netfilter_refresh_batch_started_at_.reset();
        return;
    }
    pending_netfilter_refresh_reasons_ = 0U;
    netfilter_refresh_batch_started_at_.reset();

    try {
        const bool full_refresh =
            (reasons &
             static_cast<std::uint8_t>(NetfilterRefreshReason::full)) != 0U;
        const bool nat_refresh =
            (reasons &
             static_cast<std::uint8_t>(NetfilterRefreshReason::nat_only)) != 0U;
        const bool snat_health_check = full_refresh || nat_refresh;
        const char* reason_label =
            full_refresh && nat_refresh
                ? "full+nat"
                : (full_refresh ? "full" : "nat");

        Logger::instance().info(
            "Netfilter event: applying {} runtime refresh...",
            reason_label);
        if (nat_refresh && runtime_firewall_retry_.retry_pending()) {
            // Do not coalesce away a confirmed firmware NAT rebuild behind an
            // older generic recovery. Replace that retry with an immediate
            // attempt whose bounded chain verifies SNAT health.
            cancel_runtime_firewall_retry();
        }
        const bool targeted_urltest_recovery_pending =
            urltest_after_firewall_gate_.waiting_for(
                runtime_generation_.load(std::memory_order_acquire));
        const bool runtime_refreshed =
            refresh_iproute_and_firewall_runtime(
                0,
                std::nullopt,
                std::nullopt,
                /*schedule_catalog_refresh=*/true,
                OwnedSnatRecovery{
                    /*requested=*/snat_health_check,
                    /*missing_observed=*/false});

        // A nat-only repair must not turn one firmware table rebuild into a
        // burst of remote health probes. Full/mangle refreshes preserve the
        // historical SIGUSR1 behaviour, but only after reconciliation.
        if (should_trigger_broad_urltest_probe_after_netfilter_refresh(
                runtime_refreshed,
                full_refresh,
                targeted_urltest_recovery_pending) &&
            urltest_manager_) {
            Logger::instance().info(
                "Netfilter event: probing urltest endpoints...");
            for (const auto& ob :
                 config_.outbounds.value_or(std::vector<Outbound>{})) {
                if (ob.type == OutboundType::URLTEST) {
                    urltest_manager_->trigger_immediate_test(ob.tag);
                }
            }
        }
        if (runtime_refreshed) {
            Logger::instance().info(
                "Netfilter event: {} runtime refresh complete.",
                reason_label);
        } else {
            Logger::instance().info(
                "Netfilter event: {} runtime refresh deferred or coalesced "
                "with recovery.",
                reason_label);
        }
    } catch (const std::exception& error) {
        // Scheduler/fd/allocation faults in a secondary recovery path must not
        // escape the signal callback and terminate the daemon. Retain the exact
        // source bits; the independent periodic health owner will retry them.
        pending_netfilter_refresh_reasons_ |= reasons;
        try {
            Logger::instance().info(
                "Netfilter runtime refresh remains pending after an internal "
                "recovery error: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        pending_netfilter_refresh_reasons_ |= reasons;
    }
}

void Daemon::schedule_netfilter_runtime_refresh(
    NetfilterRefreshReason reason) noexcept {
    pending_netfilter_refresh_reasons_ |=
        static_cast<std::uint8_t>(reason);
    const bool full_refresh_pending =
        (pending_netfilter_refresh_reasons_ &
         static_cast<std::uint8_t>(NetfilterRefreshReason::full)) != 0U;
    const auto schedule = plan_netfilter_refresh(
        std::chrono::steady_clock::now(),
        netfilter_refresh_batch_started_at_,
        full_refresh_pending);
    netfilter_refresh_batch_started_at_ = schedule.batch_started_at;
    const std::uint64_t schedule_serial =
        ++netfilter_refresh_schedule_serial_;
    try {
        if (netfilter_refresh_task_id_ >= 0) {
            // Invalidate the callback and relinquish the id before cancel().
            // Scheduler::cancel can erase its entry and then throw while
            // removing the fd; retaining that id would wedge every later
            // health check behind a timer that no longer exists.
            const int stale_task_id = netfilter_refresh_task_id_;
            netfilter_refresh_task_id_ = -1;
            scheduler_->cancel(stale_task_id);
        }

        netfilter_refresh_task_id_ = scheduler_->schedule_oneshot(
            schedule.delay,
            [this, schedule_serial]() {
                if (!netfilter_refresh_callback_is_current(
                    schedule_serial,
                    netfilter_refresh_schedule_serial_)) {
                    return;
                }
                netfilter_refresh_task_id_ = -1;
                reconcile_pending_netfilter_runtime_refresh();
            },
            "netfilter-runtime-refresh");
    } catch (const std::exception& error) {
        // No callback with this serial owns the work. Keep its exact reason
        // bits for the independent periodic owner. Do not reconcile inline:
        // post-publication callers can still hold the main firewall mutation
        // lock, and recursive apply would deadlock that safety boundary.
        netfilter_refresh_task_id_ = -1;
        netfilter_refresh_batch_started_at_.reset();
        try {
            Logger::instance().info(
                "Netfilter refresh timer could not be installed: {}. "
                "The periodic runtime health owner retained the refresh.",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        netfilter_refresh_task_id_ = -1;
        netfilter_refresh_batch_started_at_.reset();
    }
}

#ifdef WITH_API
void Daemon::schedule_remote_access_recovery_watchdog() {
    if (remote_access_recovery_watchdog_task_id_ >= 0) return;
    if (!scheduler_) {
        throw std::logic_error(
            "remote-access recovery watchdog requires a scheduler");
    }
    remote_access_recovery_watchdog_task_id_ =
        scheduler_->schedule_repeating(
            REMOTE_ACCESS_RECOVERY_WATCHDOG_INTERVAL,
            [this]() { resume_unscheduled_remote_access_retry(); },
            "remote-access-recovery-watchdog");
}

void Daemon::cancel_remote_access_recovery_watchdog() noexcept {
    if (remote_access_recovery_watchdog_task_id_ < 0) return;
    const int task_id = remote_access_recovery_watchdog_task_id_;
    remote_access_recovery_watchdog_task_id_ = -1;
    if (!scheduler_) return;
    try {
        scheduler_->cancel(task_id);
    } catch (const std::exception& error) {
        try {
            Logger::instance().info(
                "Remote-access recovery watchdog cancellation failed: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
    }
}

void Daemon::setup_remote_access_retry_bridge() {
    const auto bridge_epoch =
        remote_access_retry_bridge_epoch_.fetch_add(
            1U, std::memory_order_acq_rel) + 1U;
    set_remote_access_retry_scheduler(
        [this, bridge_epoch](const RemoteAccessRetryHint& hint) {
            const bool posted = post_control_task(
                [this, hint, bridge_epoch]() {
                    if (remote_access_retry_bridge_epoch_.load(
                            std::memory_order_acquire) != bridge_epoch) {
                        return;
                    }
                    schedule_remote_access_retry(hint);
                },
                "remote-access-retry-hint");
            if (!posted) {
                throw std::runtime_error(
                    "daemon control loop is not accepting remote-access "
                    "recovery work");
            }
        });
}

void Daemon::reset_remote_access_retry_bridge() noexcept {
    remote_access_retry_bridge_epoch_.fetch_add(
        1U, std::memory_order_acq_rel);
    try {
        reset_remote_access_retry_scheduler();
    } catch (...) {
    }
    ++remote_access_retry_schedule_serial_;
    unscheduled_remote_access_retry_generation_.reset();
    if (remote_access_retry_task_id_ < 0 || !scheduler_) {
        remote_access_retry_task_id_ = -1;
        return;
    }
    const int task_id = remote_access_retry_task_id_;
    remote_access_retry_task_id_ = -1;
    try {
        scheduler_->cancel(task_id);
    } catch (const std::exception& error) {
        try {
            Logger::instance().info(
                "Remote-access retry cancellation failed: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
    }
}

void Daemon::schedule_remote_access_retry(
    const RemoteAccessRetryHint& hint) {
    if (!hint.schedule || hint.generation == 0U || !scheduler_) {
        return;
    }
    const auto status = remote_access_runtime_status();
    if (status.desired_generation != hint.generation) {
        if (unscheduled_remote_access_retry_generation_ ==
            hint.generation) {
            unscheduled_remote_access_retry_generation_.reset();
        }
        return;
    }

    const std::uint64_t schedule_serial =
        ++remote_access_retry_schedule_serial_;
    if (remote_access_retry_task_id_ >= 0) {
        const int stale_task_id = remote_access_retry_task_id_;
        remote_access_retry_task_id_ = -1;
        try {
            scheduler_->cancel(stale_task_id);
        } catch (const std::exception& error) {
            try {
                Logger::instance().info(
                    "Replacing remote-access retry after timer cancellation "
                    "reported an error: {}",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
        }
    }

    if (hint.delay <= std::chrono::milliseconds{0}) {
        // A zero timerfd interval is disarmed on Linux. The bridge callback
        // has already posted us onto the control loop, so execute this
        // deferred/trailing generation directly and let its result publish
        // the next non-zero retry hint when needed.
        const std::string listen =
            config_.api.has_value()
                ? config_.api->listen.value_or(std::string{})
                : std::string{};
        unscheduled_remote_access_retry_generation_.reset();
        try {
            (void)retry_remote_access_reconcile(
                hint.generation, listen);
        } catch (...) {
            unscheduled_remote_access_retry_generation_ =
                hint.generation;
        }
        return;
    }

    unscheduled_remote_access_retry_generation_ = hint.generation;
    try {
        remote_access_retry_task_id_ = scheduler_->schedule_oneshot(
            hint.delay,
            [this, hint, schedule_serial]() {
                if (schedule_serial !=
                    remote_access_retry_schedule_serial_) {
                    return;
                }
                remote_access_retry_task_id_ = -1;
                if (!running_.load(std::memory_order_acquire)) {
                    return;
                }
                const std::string listen =
                    config_.api.has_value()
                        ? config_.api->listen.value_or(std::string{})
                        : std::string{};
                try {
                    (void)retry_remote_access_reconcile(
                        hint.generation, listen);
                } catch (...) {
                    unscheduled_remote_access_retry_generation_ =
                        hint.generation;
                }
            },
            hint.maintenance
                ? "remote-access-maintenance-retry"
                : "remote-access-retry");
    } catch (const std::exception& error) {
        remote_access_retry_task_id_ = -1;
        try {
            Logger::instance().info(
                "Remote-access recovery timer could not be installed: {}. "
                "The periodic runtime health owner will retry it.",
                error.what());
        } catch (...) {
        }
        return;
    }
    if (remote_access_retry_task_id_ >= 0) {
        unscheduled_remote_access_retry_generation_.reset();
    }
}

void Daemon::resume_unscheduled_remote_access_retry() noexcept {
    std::optional<std::uint64_t> generation =
        unscheduled_remote_access_retry_generation_;
    try {
        const auto status = remote_access_runtime_status();
        if (generation.has_value() &&
            status.desired_generation != *generation) {
            unscheduled_remote_access_retry_generation_.reset();
            generation.reset();
        }
        if (!should_run_periodic_remote_access_recovery(
                remote_access_retry_task_id_ >= 0,
                generation.has_value(),
                status.desired_generation != 0U,
                status.recovery_owned)) {
            return;
        }
        generation = status.desired_generation;
        const std::string listen =
            config_.api.has_value()
                ? config_.api->listen.value_or(std::string{})
                : std::string{};
        unscheduled_remote_access_retry_generation_.reset();
        (void)retry_remote_access_reconcile(*generation, listen);
    } catch (const std::exception& error) {
        if (generation.has_value()) {
            unscheduled_remote_access_retry_generation_ = *generation;
        }
        try {
            Logger::instance().info(
                "Periodic remote-access recovery remains deferred: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        if (generation.has_value()) {
            unscheduled_remote_access_retry_generation_ = *generation;
        }
    }
}

void Daemon::request_remote_access_reconcile_from_control(
    std::string_view source) noexcept {
    try {
        const auto status = remote_access_runtime_status();
        const bool retry_owns_next_attempt =
            should_coalesce_remote_access_runtime_refresh(
                remote_access_retry_task_id_ >= 0,
                unscheduled_remote_access_retry_generation_.has_value(),
                status.desired_generation != 0U,
                status.state == RemoteAccessRuntimeState::pending ||
                    status.state == RemoteAccessRuntimeState::degraded,
                status.recovery_owned);
        if (retry_owns_next_attempt) {
            Logger::instance().trace(
                "remote_access_refresh_coalesced",
                "source={} generation={} reason=recovery_already_owned",
                source,
                status.desired_generation);
            return;
        }
        const std::string listen =
            config_.api.has_value()
                ? config_.api->listen.value_or(std::string{})
                : std::string{};
        (void)refresh_remote_access_reconcile(listen);
    } catch (const std::exception& error) {
        try {
            Logger::instance().error(
                "Cannot request remote-access firewall reconciliation after "
                "{}: {}",
                source,
                error.what());
        } catch (...) {
        }
    } catch (...) {
    }
}
#endif

Daemon::RoutingTestSnapshot Daemon::capture_routing_test_snapshot() {
    if (!is_event_loop_thread()) {
        throw std::logic_error(
            "routing test snapshot must be captured on the control loop");
    }
    const auto active = config_store_.active_snapshot();
    return RoutingTestSnapshot{
        active.config,
        firewall_state_.get_rules(),
        firewall_->backend(),
        config_store_.config_is_draft(),
    };
}

void Daemon::schedule_netfilter_runtime_refresh_noexcept(
    NetfilterRefreshReason reason,
    const char* failure_detail) noexcept {
    (void)failure_detail;
    schedule_netfilter_runtime_refresh(reason);
}

void Daemon::handle_sighup() {
    auto& log = Logger::instance();
    const auto request = sighup_reload_coordinator_.request();
    if (request.status == ConfigReloadRequestStatus::coalesced) {
        log.info(
            "SIGHUP: reload preparation is already in progress; "
            "coalescing one trailing reload");
        return;
    }
    if (request.status == ConfigReloadRequestStatus::stopped) {
        log.verbose(
            "SIGHUP: reload ignored because the daemon is shutting down");
        return;
    }
    const ConfigReloadClaim claim = request.claim;

    std::shared_ptr<RuntimeMutationAdmission::Lease> mutation_lease;
    try {
        // SIGHUP is another configuration writer. Serialize it with API
        // staging and transactional commits so a disk reload cannot replace
        // the active ConfigStore snapshot after a catalogue preview has been
        // revalidated but before that candidate is committed.
        auto admitted = runtime_mutation_admission_.try_acquire(
            "sighup-reload");
        if (!admitted.has_value()) {
            const auto active = runtime_mutation_admission_.active();
            log.warn(
                "SIGHUP: reload deferred because runtime mutation '{}' is "
                "already in progress",
                active.has_value() ? active->label : std::string{"unknown"});
            defer_sighup_reload(claim);
            return;
        }
        mutation_lease =
            std::make_shared<RuntimeMutationAdmission::Lease>(
                std::move(*admitted));

        // A disk reload must not make an in-memory draft disappear or apply a
        // different generation behind it. Check before admitting any worker
        // work, while the runtime mutation lease is held.
        if (config_store_.config_is_draft()) {
            log.warn(
                "SIGHUP: reload rejected because a configuration draft is "
                "staged; save or discard the draft first");
            (void)sighup_reload_coordinator_.cancel(claim);
            complete_sighup_reload(
                claim,
                mutation_lease,
                /*allow_coalesced_rerun=*/false);
            return;
        }

        const std::string config_path = config_path_;
        const Config rollback_config = config_store_.active_config();
        const std::uint64_t expected_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const TraceId trace_id = ensure_trace_id();
        log.info("SIGHUP: scheduling full reload preparation...");
        const bool enqueued = blocking_executor_.try_post(
            "sighup-reload-prepare",
            [this,
             config_path,
             rollback_config,
             claim,
             mutation_lease,
             expected_runtime_generation,
             trace_id]() mutable {
                bool posted = false;
                try {
                    // Keep the outermost worker boundary ahead of every
                    // allocation and trace-context installation. If any of
                    // those operations throws, the worker still releases the
                    // prepare claim and the API config-operation gate below.
                    ScopedTraceContext trace_scope(trace_id);
                    auto prepared =
                        std::make_shared<PreparedRuntimeInputs>();
                    auto rollback_prepared =
                        std::make_shared<PreparedRuntimeInputs>();
                    std::string preparation_error;

                    try {
                        std::ifstream input(config_path);
                        if (!input.is_open()) {
                            throw DaemonError(
                                "Cannot open config file: " + config_path);
                        }

                        std::ostringstream serialized;
                        serialized << input.rdbuf();
                        if (input.bad()) {
                            throw DaemonError(
                                "Cannot read config file: " + config_path);
                        }

                        Config next_config = parse_config(serialized.str());
                        validate_config(next_config);
                        *prepared = prepare_runtime_inputs(
                            next_config,
                            RemoteListPreparationMode::RefreshAll);
                        *rollback_prepared = prepare_runtime_inputs(
                            rollback_config,
                            RemoteListPreparationMode::None);
                    } catch (const std::exception& error) {
                        preparation_error = error.what();
                    } catch (...) {
                        preparation_error =
                            "unknown disk reload preparation error";
                    }

                    posted = post_control_task(
                        [this,
                         prepared,
                         rollback_prepared,
                         claim,
                         mutation_lease,
                         expected_runtime_generation,
                         preparation_error =
                             std::move(preparation_error)]() mutable {
                            const auto commit_claim =
                                sighup_reload_coordinator_.claim_commit(
                                    claim);
                            if (commit_claim ==
                                ConfigReloadCommitStatus::lost) {
                                return;
                            }
                            bool allow_coalesced_rerun =
                                commit_claim !=
                                ConfigReloadCommitStatus::stopped;
                            try {
                                // This is the callback's outermost boundary
                                // after commit ownership is claimed. Every
                                // allocation, copy and log operation stays
                                // inside it, and the single completion below
                                // releases both coordinator and API gate.
                                auto& commit_log = Logger::instance();
                                if (commit_claim ==
                                    ConfigReloadCommitStatus::superseded) {
                                    commit_log.info(
                                        "SIGHUP: prepared reload was "
                                        "superseded; reading the latest file "
                                        "generation");
                                } else if (
                                    commit_claim ==
                                    ConfigReloadCommitStatus::stopped) {
                                    commit_log.verbose(
                                        "SIGHUP: prepared reload discarded "
                                        "because the daemon is shutting "
                                        "down");
                                } else if (
                                    runtime_generation_.load(
                                        std::memory_order_acquire) !=
                                        expected_runtime_generation) {
                                    // A runtime/list commit advanced while the
                                    // worker was blocked. Re-prepare all
                                    // derived inputs and the exact rollback
                                    // snapshot from that committed generation.
                                    (void)sighup_reload_coordinator_.request();
                                    commit_log.info(
                                        "SIGHUP: prepared reload is stale "
                                        "after an active runtime generation "
                                        "change; scheduling "
                                        "a fresh preparation");
                                } else if (!preparation_error.empty()) {
                                    commit_log.error(
                                        "SIGHUP: reload preparation failed: "
                                        "{}",
                                        preparation_error);
                                } else {
                                    // The shared Keenetic DNS cache may have
                                    // advanced while the worker was preparing
                                    // either candidate. Rollback must restore
                                    // the exact event-loop-owned committed
                                    // snapshot, not that newer observational
                                    // cache value.
                                    rollback_prepared->keenetic_dns =
                                        active_keenetic_dns_;
                                    if (prepared->keenetic_dns.snapshot &&
                                        active_keenetic_dns_.generation >
                                            prepared->keenetic_dns.generation) {
                                        // A periodic observation can advance
                                        // while SIGHUP performs remote I/O.
                                        // Its immutable view is safe to splice
                                        // into a candidate that still uses
                                        // Keenetic DNS. Do not re-run all
                                        // RefreshAll work, and do not attach it
                                        // to a candidate switching away from
                                        // Keenetic DNS (no snapshot).
                                        prepared->keenetic_dns =
                                            active_keenetic_dns_;
                                    }
                                    try {
                                        apply_prepared_runtime_inputs(
                                            std::move(*prepared));
                                        commit_log.info(
                                            "SIGHUP: full reload complete");
                                    } catch (
                                        const std::exception& apply_error) {
                                        try {
                                            apply_prepared_runtime_inputs(
                                                std::move(
                                                    *rollback_prepared));
                                            commit_log.warn(
                                                "SIGHUP: reload failed; "
                                                "previous runtime was "
                                                "restored: {}",
                                                apply_error.what());
                                        } catch (
                                            const std::exception&
                                                rollback_error) {
                                            commit_log.error(
                                                "SIGHUP: reload failed and "
                                                "rollback could not restore "
                                                "the previous runtime: {}; "
                                                "rollback error: {}",
                                                apply_error.what(),
                                                rollback_error.what());
                                        } catch (...) {
                                            commit_log.error(
                                                "SIGHUP: reload failed and "
                                                "rollback could not restore "
                                                "the previous runtime: {}; "
                                                "rollback error: unknown",
                                                apply_error.what());
                                        }
                                    } catch (...) {
                                        try {
                                            apply_prepared_runtime_inputs(
                                                std::move(
                                                    *rollback_prepared));
                                            commit_log.warn(
                                                "SIGHUP: reload failed with "
                                                "an unknown error; previous "
                                                "runtime was restored");
                                        } catch (
                                            const std::exception&
                                                rollback_error) {
                                            commit_log.error(
                                                "SIGHUP: reload failed with "
                                                "an unknown error and "
                                                "rollback could not restore "
                                                "the previous runtime: {}",
                                                rollback_error.what());
                                        } catch (...) {
                                            commit_log.error(
                                                "SIGHUP: reload failed with "
                                                "an unknown error and "
                                                "rollback also failed with "
                                                "an unknown error");
                                        }
                                    }
                                }
                            } catch (const std::exception& commit_error) {
                                try {
                                    Logger::instance().error(
                                        "SIGHUP: reload commit callback "
                                        "failed: {}",
                                        commit_error.what());
                                } catch (...) {
                                }
                            } catch (...) {
                                try {
                                    Logger::instance().error(
                                        "SIGHUP: reload commit callback "
                                        "failed with an unknown error");
                                } catch (...) {
                                }
                            }

                            complete_sighup_reload(
                                claim,
                                mutation_lease,
                                allow_coalesced_rerun);
                        },
                        "sighup-reload-commit");
                } catch (const std::exception& worker_error) {
                    try {
                        Logger::instance().error(
                            "SIGHUP: reload worker failed before handing off "
                            "to the control loop: {}",
                            worker_error.what());
                    } catch (...) {
                    }
                } catch (...) {
                    try {
                        Logger::instance().error(
                            "SIGHUP: reload worker failed before handing off "
                            "to the control loop: unknown error");
                    } catch (...) {
                    }
                }

                if (!posted) {
                    // Shutdown closes control-task admission before draining
                    // the blocking executor. post_control_task() can also
                    // throw after queueing, so release only when this worker
                    // atomically cancels the prepare claim before a queued
                    // callback claims commit.
                    if (sighup_reload_coordinator_.cancel(claim)) {
                        complete_sighup_reload(
                            claim,
                            mutation_lease,
                            /*allow_coalesced_rerun=*/false);
                    }
                }
            },
            trace_id);
        if (!enqueued) {
            log.error(
                "SIGHUP: reload rejected because the blocking executor is "
                "unavailable");
            if (sighup_reload_coordinator_.cancel(claim)) {
                complete_sighup_reload(
                    claim,
                    mutation_lease,
                    /*allow_coalesced_rerun=*/false);
            }
        }
    } catch (const std::exception& e) {
        if (sighup_reload_coordinator_.cancel(claim)) {
            complete_sighup_reload(
                claim,
                mutation_lease,
                /*allow_coalesced_rerun=*/false);
        }
        log.error("SIGHUP: reload rejected: {}", e.what());
    } catch (...) {
        if (sighup_reload_coordinator_.cancel(claim)) {
            complete_sighup_reload(
                claim,
                mutation_lease,
                /*allow_coalesced_rerun=*/false);
        }
        log.error("SIGHUP: reload rejected: unknown error");
    }
}

void Daemon::defer_sighup_reload(ConfigReloadClaim claim) {
    auto abandon = [this, claim]() noexcept {
        if (sighup_reload_coordinator_.cancel(claim)) {
            (void)sighup_reload_coordinator_.complete(claim);
        }
    };

    const bool queued = blocking_executor_.try_post(
        "sighup-runtime-mutation-wait",
        [this, claim, abandon]() mutable {
            if (!runtime_mutation_admission_.wait_until_idle()) {
                abandon();
                return;
            }

            bool posted = false;
            try {
                posted = post_control_task(
                    [this, claim]() {
                        if (!sighup_reload_coordinator_.cancel(claim)) {
                            return;
                        }
                        const auto completion =
                            sighup_reload_coordinator_.complete(claim);
                        if (completion.owned) {
                            // The original request, plus any SIGHUP coalesced
                            // while it waited, is represented by this one
                            // fresh generation. If another mutation won the
                            // race after the idle observation, handle_sighup()
                            // defers again.
                            handle_sighup();
                        }
                    },
                    "sighup-runtime-mutation-resume");
            } catch (const std::exception& error) {
                try {
                    Logger::instance().error(
                        "SIGHUP: cannot post deferred runtime mutation: {}",
                        error.what());
                } catch (...) {
                }
            } catch (...) {
                try {
                    Logger::instance().error(
                        "SIGHUP: cannot post deferred runtime mutation: "
                        "unknown error");
                } catch (...) {
                }
            }
            if (!posted) {
                // post_control_task() may throw after queueing. The worker and
                // callback therefore race through the same coordinator claim;
                // exactly one side can cancel it and own completion.
                abandon();
            }
        });
    if (queued) {
        return;
    }

    if (!accept_posted_control_tasks_.load(std::memory_order_acquire)) {
        abandon();
        return;
    }

    try {
        scheduler_->schedule_oneshot(
            std::chrono::milliseconds{100},
            [this, claim]() { defer_sighup_reload(claim); },
            "sighup-runtime-mutation-wait-retry");
    } catch (const std::exception& error) {
        Logger::instance().error(
            "SIGHUP: cannot schedule runtime mutation wait: {}",
            error.what());
        abandon();
    }
}

void Daemon::complete_sighup_reload(
    ConfigReloadClaim claim,
    std::shared_ptr<RuntimeMutationAdmission::Lease> mutation_lease,
    bool allow_coalesced_rerun) noexcept {
    const auto completion =
        sighup_reload_coordinator_.complete(claim);
    if (!completion.owned) {
        return;
    }
    // Release before starting a coalesced reload. All shared references point
    // to this same move-only lease, and release() is token-checked and
    // idempotent for the single completion owner selected above.
    if (mutation_lease) {
        mutation_lease->release();
    }

    if (!completion.rerun_requested || !allow_coalesced_rerun ||
        !accept_posted_control_tasks_.load(std::memory_order_acquire) ||
        !running_.load(std::memory_order_acquire)) {
        return;
    }

    try {
        Logger::instance().info(
            "SIGHUP: starting the coalesced trailing reload");
        handle_sighup();
    } catch (const std::exception& error) {
        try {
            Logger::instance().error(
                "SIGHUP: coalesced reload could not start: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().error(
                "SIGHUP: coalesced reload could not start: unknown error");
        } catch (...) {
        }
    }
}

bool Daemon::refresh_iproute_and_firewall_runtime(
    std::size_t retry_attempt,
    std::optional<InternalVpnRuntimeResolution>
        prepared_internal_vpn_resolution,
    std::optional<InternalVpnServiceRuntimeResolution>
        prepared_internal_vpn_service_resolution,
    bool schedule_catalog_refresh,
    OwnedSnatRecovery snat_recovery) {
    auto& log = Logger::instance();
    if (!routing_runtime_active_) {
        log.verbose(
            "Skipping runtime routing/firewall refresh because routing is stopped.");
        return false;
    }
    const auto admission = runtime_firewall_retry_.begin_attempt(
        retry_attempt, std::move(snat_recovery));
    snat_recovery = admission.snat_recovery;
    if (admission.coalesced) {
        log.verbose(
            "Coalescing runtime routing/firewall refresh with the pending "
            "recovery retry.");
        return false;
    }
    try {
        // Interface notifications are handled on the control loop. Re-resolve
        // against live netlink names using only the shared cache snapshot;
        // never perform an NDMS HTTP request here.
        const auto internal_vpn_resolution =
            prepared_internal_vpn_resolution.has_value()
                ? std::move(*prepared_internal_vpn_resolution)
                : prepare_internal_vpn_server_resolution_from_cache();
        const auto internal_vpn_service_resolution =
            prepared_internal_vpn_service_resolution.has_value()
                ? std::move(*prepared_internal_vpn_service_resolution)
                : prepare_internal_vpn_service_resolution_from_cache();
        // This can be an ordinary managed-WAN event after the catalog TTL,
        // not only a native-VPN event. Cache-only reconciliation remains
        // immediate; the central lifecycle invariant puts the authoritative
        // RCI observation on the blocking executor.
        if (schedule_catalog_refresh) {
            schedule_internal_vpn_catalog_refresh_if_needed(
                internal_vpn_resolution.state,
                internal_vpn_service_resolution.state);
        }
        const auto next_resolver_access_policy =
            build_dnsmasq_trusted_interfaces(
                internal_vpn_resolution.effective_servers,
                internal_vpn_service_resolution.effective_targets);
        const auto current_resolver_access_policy =
            resolver_generation_snapshot_
                ? resolver_generation_snapshot_->trusted_dns_interfaces
                : build_dnsmasq_trusted_interfaces(
                    resolved_internal_vpn_servers_,
                    resolved_internal_vpn_service_targets_);
        const bool resolver_access_policy_changed =
            current_resolver_access_policy !=
            next_resolver_access_policy;
        // A firewall-only repair must stay on the list generation already
        // committed to dnsmasq. If no committed generation exists, promote
        // this pass to a paired firewall/resolver transaction on one newly
        // captured generation.
        const bool resolver_generation_missing =
            !resolver_generation_snapshot_ ||
            !resolver_generation_snapshot_->list_cache_snapshot;
        const bool resolver_refresh_required =
            resolver_access_policy_changed || resolver_generation_missing;
        const auto list_cache_snapshot =
            resolver_refresh_required
                ? capture_relevant_list_cache_generation(config_)
                : resolver_generation_snapshot_->list_cache_snapshot;
        InternalVpnRuntimeGenerationTransaction
            internal_vpn_generation(
                resolved_internal_vpn_servers_,
                internal_vpn_resolution.effective_servers);
        InternalVpnRuntimeTargetGenerationTransaction
            internal_vpn_service_generation(
                resolved_internal_vpn_service_targets_,
                internal_vpn_service_resolution.effective_targets);
        const OwnedSnatState snat_before =
            snat_recovery.requested
                ? firewall_->inspect_owned_snat_state()
                : OwnedSnatState::unknown;
        snat_recovery =
            observe_owned_snat_state(
                std::move(snat_recovery),
                snat_before,
                snat_before == OwnedSnatState::missing
                    ? std::optional<OwnedConntrackCleanupSnapshot>{
                          snapshot_owned_conntrack_marks()}
                    : std::nullopt);
        snat_recovery =
            runtime_firewall_retry_.retain_recovery(
                std::move(snat_recovery));
        reconcile_static_routing(RouteReconcileMode::DeferredRepair);
        apply_firewall(
            FirewallApplyMode::PreserveSets,
            list_cache_snapshot);
        const OwnedSnatState inspected_snat_after =
            snat_recovery.requested
                ? firewall_->inspect_owned_snat_state()
                : OwnedSnatState::unknown;
        snat_recovery =
            observe_owned_snat_state(
                std::move(snat_recovery),
                inspected_snat_after,
                inspected_snat_after == OwnedSnatState::missing
                    ? std::optional<OwnedConntrackCleanupSnapshot>{
                          snapshot_owned_conntrack_marks()}
                    : std::nullopt);
        snat_recovery =
            runtime_firewall_retry_.retain_recovery(
                std::move(snat_recovery));
        const OwnedSnatState snat_after = inspected_snat_after;
        if (snat_recovery.requested &&
            snat_after != OwnedSnatState::healthy) {
            throw TransientFirewallError(
                snat_after == OwnedSnatState::missing
                    ? "tunnel SNAT scaffold is missing after runtime repair"
                    : (snat_after == OwnedSnatState::stale
                           ? "tunnel SNAT scaffold is stale after runtime "
                             "repair"
                           : "tunnel SNAT scaffold could not be inspected "
                             "after runtime repair"));
        }
        internal_vpn_generation.commit();
        internal_vpn_service_generation.commit();
        update_internal_vpn_verified_includes_lkg(
            internal_vpn_resolution);
        update_internal_vpn_service_verified_includes_lkg(
            internal_vpn_service_resolution);
        const auto current_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const bool resolver_waits_for_firewall =
            resolver_after_firewall_gate_.waiting_for(
                current_runtime_generation);
        if (resolver_refresh_required) {
            // Firewall B is now authoritative. Publish the matching prepared
            // resolver generation even while the recovery gate is closed;
            // the gate delays only the external dnsmasq stream. Its eventual
            // release will therefore retry B rather than the previous A.
            apply_started_ts_.store(
                unix_timestamp_now_seconds(), std::memory_order_release);
            commit_resolver_generation_snapshot(
                make_resolver_generation_snapshot(
                    list_cache_snapshot));
        }
        if (resolver_refresh_required && !resolver_waits_for_firewall) {
            // A live NDMS catalog refresh can add, remove or rename a dynamic
            // SSTP/IKE/L2TP/OpenConnect ingress without changing config.json.
            // Firewall and the in-memory inventory have already committed, so
            // publish the matching dnsmasq interface ACL as the same runtime
            // generation. A resolver failure must not roll back working
            // forwarding; the bounded resolver reconciler will converge it.
            cancel_resolver_reload_retry();
            if (resolver_stream_coordinator_.in_flight()) {
                log.verbose(
                    "Native VPN DNS access policy committed while a resolver "
                    "recovery stream was active; scheduling one trailing "
                    "resolver convergence pass");
                schedule_resolver_reload_retry(
                    0, current_runtime_generation);
            } else {
                try {
                    if (run_system_resolver_hook_stream_prepared(
                            "reload", /*rebuild_snapshot=*/false)) {
                        if (acknowledge_verified_resolver_reload(
                                current_runtime_generation)) {
                            // The resolver proof is complete independently of
                            // later conntrack/remote-access tail work. Publish
                            // the exact resolver-owned recovery now so a tail
                            // exception cannot leave a stale broken reason.
                            publish_runtime_state();
                        }
                        refresh_resolver_config_hash_actual_async();
                    } else {
                        log.info(
                            "Native VPN DNS access policy did not converge "
                            "during runtime refresh; scheduling a bounded "
                            "resolver retry.");
                        schedule_resolver_reload_retry(
                            0,
                            runtime_generation_.load(
                                std::memory_order_acquire));
                    }
                } catch (const std::exception& error) {
                    log.info(
                        "Native VPN DNS access policy refresh was deferred: "
                        "{}",
                        error.what());
                    schedule_resolver_reload_retry(
                        0,
                        runtime_generation_.load(
                            std::memory_order_acquire));
                }
            }
        }
        if (should_cleanup_conntrack_after_snat_repair(
                snat_recovery, snat_after)) {
            if (snat_recovery.cleanup_snapshot.has_value()) {
                // This event is rare and serialized on the control loop. A
                // bounded synchronous cleanup is intentional: it is the
                // generation barrier that prevents an old numerical mark
                // from being deleted after a concurrent config save reuses
                // it for a different outbound.
                cleanup_owned_conntrack_snapshot(
                    *snat_recovery.cleanup_snapshot,
                    "after verified tunnel SNAT recovery");
                log.info(
                    "Tunnel SNAT was restored after a firmware firewall "
                    "rebuild; retired the affected "
                    "keen-pbr-marked flows.");
            }
        }
        runtime_firewall_retry_.complete_attempt(
            /*succeeded=*/true, snat_recovery);
        release_urltest_firewall_recovery(
            current_runtime_generation);
        if (resolver_after_firewall_gate_.release(
                current_runtime_generation)) {
            schedule_resolver_reload_retry(
                0, current_runtime_generation);
        }
        runtime_firewall_incidents_.clear();
#ifdef WITH_API
        request_remote_access_reconcile_from_control(
            "verified firewall refresh");
#endif
        publish_runtime_state();
        log.info("Runtime iproute and firewall refresh complete.");
        return true;
    } catch (const RouteInterfaceUnavailableError& e) {
        // A TUN/WireGuard link may disappear between the desired-state
        // snapshot and RTM_NEWROUTE. This is transient runtime churn, not a
        // broken configuration and not a user-facing permanent incident. Do
        // not create a second retry timer: a kernel UP event resets per-route
        // backoff and the existing interface probe is the observation-gap
        // fallback. If this pass also owns a pending SNAT repair, keep that
        // request on the existing coalescing runtime-retry coordinator so a
        // missed UP event cannot leave SNAT recovery latched forever.
        log.verbose(
            "Runtime route reconciliation is waiting for an interface: {}",
            e.what());
        runtime_firewall_retry_.complete_attempt(
            /*succeeded=*/false, snat_recovery);
        const auto current_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const bool urltest_recovery_pending =
            urltest_after_firewall_gate_.waiting_for(
                current_runtime_generation);
        if (urltest_recovery_pending &&
            retry_attempt >= RUNTIME_FIREWALL_RETRY_DELAYS.size()) {
            for (const auto& tag :
                 urltest_after_firewall_gate_.pending_tags(
                     current_runtime_generation)) {
                const auto incident =
                    urltest_apply_incidents_.record_failure(
                        tag, /*notify_immediately=*/true);
                if (incident.notify) {
                    log.error(
                        "Urltest '{}' firewall recovery is still waiting for "
                        "a route after {} bounded retries: {}. The previous "
                        "cursor remains active and quiet maintenance will "
                        "continue in the background.",
                        tag,
                        retry_attempt,
                        e.what());
                }
            }
        }
        if (runtime_firewall_retry_.route_unavailable_retry_required() ||
            urltest_recovery_pending) {
            schedule_runtime_firewall_retry(
                retry_attempt,
                current_runtime_generation,
                snat_recovery);
        }
        return false;
    } catch (const TransientFirewallError& e) {
        runtime_firewall_retry_.complete_attempt(
            /*succeeded=*/false, snat_recovery);
        if (retry_attempt >= RUNTIME_FIREWALL_RETRY_DELAYS.size()) {
            const auto current_runtime_generation =
                runtime_generation_.load(std::memory_order_acquire);
            const bool urltest_recovery_pending =
                urltest_after_firewall_gate_.waiting_for(
                    current_runtime_generation);
            if (snat_recovery.requested || urltest_recovery_pending) {
                if (urltest_recovery_pending) {
                    // This bounded-chain boundary is the sole owner of the
                    // URLTEST bell.  Initial deferral must not advance or
                    // consume the per-selector notification latch.
                    for (const auto& tag :
                         urltest_after_firewall_gate_.pending_tags(
                             current_runtime_generation)) {
                        const auto incident =
                            urltest_apply_incidents_.record_failure(
                                tag, /*notify_immediately=*/true);
                        if (incident.notify) {
                            log.error(
                                "Urltest '{}' firewall recovery failed after "
                                "{} bounded retries: {}. The previous cursor "
                                "remains active and quiet maintenance will "
                                "continue in the background.",
                                tag,
                                retry_attempt,
                                e.what());
                        }
                    }
                }
                // Keep one quiet, capped maintenance retry alive while the
                // desired SNAT contract or a restored URLTEST cursor is still
                // awaiting proof. Netfilter hooks can be lost during firmware
                // service restarts; recovery must not depend on another event.
                log.info(
                    "Runtime firewall recovery remains pending after {} "
                    "bounded retries: {}. A maintenance retry will continue "
                    "in the background.",
                    retry_attempt,
                    e.what());
                schedule_runtime_firewall_retry(
                    retry_attempt,
                    current_runtime_generation,
                    snat_recovery);
            } else {
                const auto incident =
                    runtime_firewall_incidents_.record_failure(
                        "runtime-firewall-reconciliation",
                        /*notify_immediately=*/true);
                if (incident.notify) {
                    log.error(
                        "Runtime routing/firewall reconciliation failed after "
                        "{} retries: {}. The last committed runtime generation "
                        "remains active; inspect firewall diagnostics before "
                        "retrying Apply.",
                        retry_attempt,
                        e.what());
                } else {
                    log.info(
                        "Runtime routing/firewall reconciliation is still "
                        "unavailable after {} retries: {}. The existing "
                        "notification remains active.",
                        retry_attempt,
                        e.what());
                }
            }
            return false;
        }
        log.info(
            "Runtime iproute and firewall refresh deferred: {}", e.what());
        schedule_runtime_firewall_retry(
            retry_attempt,
            runtime_generation_.load(std::memory_order_acquire),
            snat_recovery);
        return false;
    } catch (const std::exception& e) {
        runtime_firewall_retry_.complete_attempt(
            /*succeeded=*/false, snat_recovery);
        // A permanent rule/configuration failure is actionable and must remain
        // visible to the user. Stable-ID changes also retain a bounded retry:
        // the generation guard has restored the previous in-memory map, so
        // kernel and memory still describe the same previous generation.
        const bool retry =
            config_has_native_vpn_catalog_policy(config_) &&
            retry_attempt < RUNTIME_FIREWALL_RETRY_DELAYS.size();
        const auto current_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const bool urltest_recovery_failed_permanently =
            urltest_after_firewall_gate_.waiting_for(
                current_runtime_generation);
        const auto failed_urltest_tags =
            urltest_after_firewall_gate_.pending_tags(
                current_runtime_generation);
        if (urltest_recovery_failed_permanently) {
            // A typed transient keeps the last committed runtime serving
            // while recovery is pending. A non-transient failure during that
            // proof is different: keep the permanent broken reason visible,
            // while the actually active last committed routing/LKG remains
            // available until an explicit stop performs full cleanup.
            urltest_after_firewall_gate_.reset();
            try {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    "urltest firewall recovery failed permanently");
                publish_runtime_state();
            } catch (...) {
            }
            // Use the same per-selector latch that owns bounded transient
            // exhaustion.  Escalating a maintenance attempt to permanent
            // state updates health, but cannot mint a second bell for the
            // same gated incident.
            for (const auto& tag : failed_urltest_tags) {
                const auto incident =
                    urltest_apply_incidents_.record_failure(
                        tag, /*notify_immediately=*/true);
                if (incident.notify) {
                    log.error(
                        "Urltest '{}' firewall recovery failed permanently: "
                        "{}. Runtime state is broken because the restored "
                        "kernel generation could not be verified.",
                        tag,
                        e.what());
                } else {
                    log.info(
                        "Urltest '{}' firewall recovery became permanent: "
                        "{}. Its existing notification remains active.",
                        tag,
                        e.what());
                }
            }
        } else {
            const auto incident =
                runtime_firewall_incidents_.record_failure(
                    "runtime-firewall-reconciliation",
                    /*notify_immediately=*/true);
            if (incident.notify) {
                if (retry) {
                    log.error(
                        "Runtime routing/firewall reconciliation failed: {}. A "
                        "bounded retry will verify whether the failure clears. "
                        "The last committed runtime generation remains active.",
                        e.what());
                } else {
                    log.error(
                        "Runtime routing/firewall reconciliation failed "
                        "permanently: {}. The last committed runtime generation "
                        "remains active; inspect firewall diagnostics before "
                        "retrying Apply.",
                        e.what());
                }
            } else {
                log.info(
                    "Runtime routing/firewall reconciliation remains failed: "
                    "{}. The existing notification remains active.",
                    e.what());
            }
        }
        if (retry && !urltest_recovery_failed_permanently) {
            schedule_runtime_firewall_retry(
                retry_attempt,
                runtime_generation_.load(std::memory_order_acquire),
                snat_recovery);
        }
        return false;
    }
}

void Daemon::cancel_runtime_firewall_retry() {
    runtime_firewall_retry_.cancel(
        [this](int task_id) { scheduler_->cancel(task_id); });
}

void Daemon::schedule_runtime_firewall_retry(
    std::size_t attempt,
    std::uint64_t runtime_generation,
    OwnedSnatRecovery snat_recovery) {
    const auto retry_plan = runtime_firewall_retry_.schedule(
        attempt,
        runtime_generation,
        RUNTIME_FIREWALL_RETRY_DELAYS.size(),
        std::move(snat_recovery),
        [this, attempt](const RuntimeFirewallRetryPlan& plan,
                        auto callback) {
            const auto delay = plan.maintenance
                ? std::chrono::seconds{60}
                : RUNTIME_FIREWALL_RETRY_DELAYS[attempt];
            return scheduler_->schedule_oneshot(
                delay,
                std::move(callback),
                "runtime-firewall-retry");
        },
        [this](std::uint64_t expected_generation) {
            const bool current = runtime_recovery_is_current(
                routing_runtime_active_,
                expected_generation,
                runtime_generation_.load(std::memory_order_acquire));
            if (!current) {
                Logger::instance().verbose(
                    "Discarding stale runtime firewall recovery retry.");
            }
            return current;
        },
        [this](std::size_t next_attempt,
               OwnedSnatRecovery scheduled_snat_recovery) {
            refresh_iproute_and_firewall_runtime(
                next_attempt,
                std::nullopt,
                std::nullopt,
                /*schedule_catalog_refresh=*/true,
                std::move(scheduled_snat_recovery));
        },
        urltest_after_firewall_gate_.waiting_for(runtime_generation));
    if (!retry_plan.schedule) {
        return;
    }
    const auto delay = retry_plan.maintenance
        ? std::chrono::seconds{60}
        : RUNTIME_FIREWALL_RETRY_DELAYS[attempt];
    if (retry_plan.maintenance) {
        Logger::instance().verbose(
            "Persistent firewall maintenance recovery scheduled in {}s.",
            delay.count());
    } else {
        Logger::instance().info(
            "Runtime firewall recovery retry {} scheduled in {}s.",
            retry_plan.next_attempt,
            delay.count());
    }
}

void Daemon::handle_interface_event(const InterfaceMonitor::Event& event) {
    auto& log = Logger::instance();
#ifdef WITH_API
    teardown_conntrack_events();
    if (status_stream_) {
        status_stream_->reconcile();
    }
    // Default-route publication and address churn are prerequisites of the
    // independent remote-access policy even when this interface is unrelated
    // to keen-pbr routing rules.
    request_remote_access_reconcile_from_control("interface event");
#endif
    if (!interface_event_requires_runtime_observation(event) ||
        !routing_runtime_active_) {
        return;
    }
    if (event.observation_gap) {
        recover_internal_vpn_catalog_after_observation_gap();
        return;
    }
    if (event.is_up &&
        (event.administrative_state_changed || event.topology_changed)) {
        // The kernel just made this link usable. Let only its deferred route
        // repairs bypass their remaining backoff before the event-driven
        // reconciliation below; unrelated/flapping links stay isolated.
        route_table_.notify_interface_up(event.interface_name);
    }
    const bool reconcile_immediately =
        interface_event_affects_managed_runtime(
            config_,
            resolved_internal_vpn_servers_,
            resolved_internal_vpn_service_targets_,
            event.interface_name);
    const bool refresh_stable_catalog =
        config_has_stable_internal_vpn_server_policy(config_);
    const bool refresh_service_catalog =
        config_requires_internal_vpn_service_inventory(config_);
    if (!reconcile_immediately &&
        !refresh_stable_catalog &&
        !refresh_service_catalog) {
        return;
    }
    if (!reconcile_immediately) {
        // A new kernel name after NDMS renumbering is not yet present in the
        // persisted/effective rows. A topology event can be the only rename
        // notification Linux emits, so revoke the pre-rename catalog before
        // scheduling its asynchronous replacement. Address/state churn on an
        // unrelated WAN/LAN interface still leaves cache authority intact.
        if (event.topology_changed) {
            if (refresh_stable_catalog) {
                shared_ndms_catalog_cache().invalidate();
            }
            if (refresh_service_catalog) {
                shared_ndms_vpn_server_service_cache().invalidate();
            }
        }
        schedule_internal_vpn_catalog_refresh();
        return;
    }

    if (event.topology_changed) {
        log.info(
            "Interface {} topology changed, runtime observation triggered",
            event.interface_name);
    } else if (event.address_changed) {
        log.info("Interface {} address changed, iproute and firewall refresh triggered",
                 event.interface_name);
    } else {
        log.info("Interface {} state changed to {}, iproute and firewall refresh triggered",
                 event.interface_name,
                 event.is_up ? "UP" : "DOWN");
    }
    const auto configured_internal_servers = config_.route.has_value()
        ? config_.route->internal_vpn_servers.value_or(
              std::vector<InternalVpnServer>{})
        : std::vector<InternalVpnServer>{};
    const bool is_internal_vpn_event = std::any_of(
        resolved_internal_vpn_servers_.begin(),
        resolved_internal_vpn_servers_.end(),
        [&event](const InternalVpnServer& server) {
            return server.interface == event.interface_name;
        }) ||
        std::any_of(
            configured_internal_servers.begin(),
            configured_internal_servers.end(),
            [&event](const InternalVpnServer& server) {
                return server.interface == event.interface_name;
            });
    if (refresh_stable_catalog && is_internal_vpn_event) {
        // The cache may still be within its normal TTL, but an interface event
        // can mean NDMS renumbered or reused the old kernel name. Revoke its
        // authority before the immediate cache-only reconcile. The worker
        // below will restore authority only after a fresh RCI observation.
        shared_ndms_catalog_cache().invalidate();
    }
    if (refresh_service_catalog && event.topology_changed) {
        shared_ndms_vpn_server_service_cache().invalidate();
    }
    refresh_iproute_and_firewall_runtime();
    // A stable NDMS identity may keep the same id while KeeneticOS renumbers
    // its current kernel interface. Refresh on a bounded worker after the
    // immediate cache-only reconciliation; never block the control loop.
    if ((refresh_stable_catalog && is_internal_vpn_event) ||
        (refresh_service_catalog && event.topology_changed)) {
        schedule_internal_vpn_catalog_refresh();
    }
}

void Daemon::recover_internal_vpn_catalog_after_observation_gap() {
    if (!routing_runtime_active_ ||
        !config_has_native_vpn_catalog_policy(config_)) {
        return;
    }
    recover_internal_vpn_after_observation_gap(
        // A netlink observation gap revokes the authority of the current
        // stable-id mapping. The include-only LKG is intentionally retained by
        // the runtime resolver.
        [this]() {
            if (config_has_stable_internal_vpn_server_policy(config_)) {
                shared_ndms_catalog_cache().invalidate();
            }
            if (config_requires_internal_vpn_service_inventory(config_)) {
                shared_ndms_vpn_server_service_cache().invalidate();
            }
        },
        // A previously scheduled retry may describe the pre-gap generation
        // and must not suppress this safety-critical reconciliation.
        [this]() { cancel_runtime_firewall_retry(); },
        // Reconcile from the invalidated cache immediately so an unverified
        // process_clients=false bypass cannot remain active. Suppress the
        // implicit catalog request here: the explicit final stage below gives
        // ENOBUFS and reconnect recovery one deterministic lifecycle order.
        [this]() {
            refresh_iproute_and_firewall_runtime(
                0,
                std::nullopt,
                std::nullopt,
                /*schedule_catalog_refresh=*/false);
        },
        // The single-flight gate coalesces this request with any refresh that
        // was already in flight and hands it to one immediate rerun.
        [this]() { schedule_internal_vpn_catalog_refresh(); });
}

void Daemon::handle_interface_monitor_events(uint32_t events) {
    constexpr uint32_t relevant_events = EPOLLIN | EPOLLERR | EPOLLHUP;
    if ((events & relevant_events) == 0) {
        return;
    }
    if (!interface_monitor_) {
        return;
    }

    if ((events & (EPOLLERR | EPOLLHUP)) != 0 && (events & EPOLLIN) == 0) {
        Logger::instance().error("Interface monitor fd reported epoll error/hangup");
        reconnect_interface_monitor();
        return;
    }

    try {
        interface_monitor_->handle_events();
    } catch (const std::exception& e) {
        Logger::instance().error("Interface monitor event handling failed: {}", e.what());
        reconnect_interface_monitor();
    }
}

void Daemon::register_interface_monitor_fd() {
    if (!interface_monitor_) {
        return;
    }

    const int fd = interface_monitor_->fd();
    add_fd(fd,
           EPOLLIN,
           [this](uint32_t events) { handle_interface_monitor_events(events); },
           true,
           "interface-monitor");
    interface_monitor_fd_ = fd;
}

void Daemon::unregister_interface_monitor_fd() {
    if (!interface_monitor_fd_) {
        return;
    }

    remove_fd(*interface_monitor_fd_, true, "interface-monitor");
    interface_monitor_fd_.reset();
}

void Daemon::schedule_interface_monitor_reconnect_retry() {
    if (!scheduler_ || interface_monitor_reconnect_task_id_ >= 0) {
        return;
    }

    interface_monitor_reconnect_task_id_ = scheduler_->schedule_oneshot(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            INTERFACE_MONITOR_RECONNECT_RETRY_DELAY),
        [this]() {
            interface_monitor_reconnect_task_id_ = -1;
            reconnect_interface_monitor();
        },
        "interface-monitor-reconnect");
}

void Daemon::reconnect_interface_monitor() {
    enqueue_control_task([this]() {
        if (!interface_monitor_) {
            return;
        }

        unregister_interface_monitor_fd();

        try {
            interface_monitor_->reconnect();
            register_interface_monitor_fd();
            Logger::instance().warn("Interface monitor reconnected after netlink error");
            // Events may have been lost while the socket was unavailable.
            // Treat every successful reconnect as an observation gap instead
            // of trusting a potentially stale NDMS-id to kernel-name mapping.
            recover_internal_vpn_catalog_after_observation_gap();
        } catch (const std::exception& e) {
            Logger::instance().error("Interface monitor reconnect failed: {}", e.what());
            schedule_interface_monitor_reconnect_retry();
        }
    }, false, "interface-monitor-reconnect");
}

void Daemon::add_fd(int fd,
                    uint32_t events,
                    FdCallback cb,
                    bool wait_for_completion,
                    const std::string& label) {
    enqueue_control_task([this, fd, events, cb = std::move(cb)]() mutable {
        KPBR_LOCK_GUARD(fd_entries_mutex_);
        // Build the complete callback registry candidate before exposing the
        // fd to epoll. After EPOLL_CTL_ADD succeeds, publication is one
        // no-throw swap, so allocation failure cannot leave an untracked live
        // registration or erase the stale callback prematurely.
        publish_fd_entry_after_successful_epoll_add(
            fd_entries_,
            FdEntry{fd, std::move(cb)},
            [this, fd, events]() {
                struct epoll_event ev{};
                ev.events = events;
                ev.data.fd = fd;
                if (epoll_ctl(
                        epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
                    throw DaemonError(
                        "epoll_ctl add fd failed: " +
                        std::string(strerror(errno)));
                }
            });
    }, wait_for_completion, label.empty() ? "add-fd" : label);
}

void Daemon::remove_fd(int fd,
                       bool wait_for_completion,
                       const std::string& label) {
    enqueue_control_task([this, fd]() {
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);

        KPBR_LOCK_GUARD(fd_entries_mutex_);
        fd_entries_.erase(
            std::remove_if(fd_entries_.begin(), fd_entries_.end(),
                           [fd](const FdEntry& e) { return e.fd == fd; }),
            fd_entries_.end());
    }, wait_for_completion, label.empty() ? "remove-fd" : label);
}

void Daemon::dispatch_event_fd(int fd, uint32_t events) {
    if (fd == ipc_control_fd_) {
        if ((events & EPOLLIN) != 0U) {
            handle_ipc_control_socket();
        }
        return;
    }
    if (fd == signal_fd_) {
        handle_signal();
        return;
    }
    if (fd == control_fd_) {
        handle_control_commands();
        return;
    }

    FdCallback callback;
    {
        KPBR_LOCK_GUARD(fd_entries_mutex_);
        for (auto& entry : fd_entries_) {
            if (entry.fd == fd) {
                callback = entry.callback;
                break;
            }
        }
    }
    if (callback) {
        callback(events);
    }
}

void Daemon::run_event_loop() {
    constexpr int MAX_EVENTS = 16;
    struct epoll_event events[MAX_EVENTS];

    while (running_.load(std::memory_order_acquire)) {
        int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw DaemonError("epoll_wait failed: " + std::string(strerror(errno)));
        }

        bool signal_event_present = false;
        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == signal_fd_) {
                signal_event_present = true;
                // signalfd is drained in one pass. Give terminal signals
                // priority over every control, timer, API and netlink event
                // returned by this same unordered epoll batch.
                dispatch_event_fd(events[i].data.fd, events[i].events);
                break;
            }
        }
        if (!event_batch_allows_non_signal_dispatch(
                signal_event_present,
                running_.load(std::memory_order_acquire))) {
            continue;
        }

        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == signal_fd_) {
                continue;
            }
            dispatch_event_fd(events[i].data.fd, events[i].events);
            if (!running_.load(std::memory_order_acquire)) {
                break;
            }
        }
    }
}

void Daemon::run() {
    auto& log = Logger::instance();

    try {
        auto native_import_readiness =
            NdmsNativeImportJournalReadinessState::unavailable;
        try {
            // Before the inventory is judged: a process that died between
            // creating its WAL temporary and renaming it into place leaves a
            // name the inventory reads as unsafe, and without this sweep the
            // startup report below would say "unsafe" until the first write -
            // which the unsafe inventory itself refuses. The sweep is
            // noexcept, removes only this store's own dead-owner temporaries,
            // and an absent store is simply not its problem.
            ndms_native_import_wal_store_.sweep_orphaned_temporaries();
            const auto native_import_inventory =
                ndms_native_import_wal_store_.try_inventory();
            native_import_readiness =
                summarize_ndms_native_import_readiness(
                    native_import_inventory);

            // The removal crash window closes here and only here. A tunnel
            // deleted by an operator whose process then died leaves a durable
            // claim over a slot that is now free; the live caller learns of it
            // from removed_claim_survived, and nothing else would ever notice.
            // Skip unless this exact bounded snapshot proves a ready, empty
            // WAL. Busy, unsafe, I/O-failed and absent stores are unknown for
            // mutation authority even though `absent` is a useful report-only
            // state while the writer remains disabled. The recovery dispatcher
            // retracts its own claim, and a second remover racing it would turn
            // that retirement into a failure.
            const bool transaction_in_flight_or_unknown =
                !ndms_native_import_inventory_permits_ownership_reconciliation(
                    native_import_inventory);
            const auto reconciled =
                reconcile_ndms_native_ownership_claims(
                    ndms_native_ownership_store_,
                    transaction_in_flight_or_unknown,
                    ndms_native_interface_read_production_dependencies());
            if (!reconciled.store_readable) {
                log.warn(
                    "Native import ownership claims could not be read; "
                    "stale claims cannot be retired this boot.");
            } else if (!reconciled.retired.empty() ||
                       !reconciled.unresolved.empty()) {
                // Counts only. An interface name is not a secret, but the
                // surrounding report has been deliberately redacted since the
                // journal observation above and there is no reason to widen it
                // here.
                log.info(
                    "Native import ownership reconciliation: examined={} "
                    "retired={} unresolved={}",
                    reconciled.claims_examined,
                    reconciled.retired.size(),
                    reconciled.unresolved.size());
            }
        } catch (...) {
            // Startup inventory is observational. Even an unexpected local
            // allocation/runtime failure must fail the report closed without
            // taking down the already-working routing daemon.
        }
        ndms_native_import_journal_readiness_.store(
            native_import_readiness, std::memory_order_release);
        // Deliberately log only the collapsed enum. Inventory entries can
        // contain transaction identifiers and filenames, neither of which
        // belongs in the API or routine daemon logs.
        log.info(
            "Native import WAL startup observation: state={} (report-only; "
            "writer and recovery remain disabled).",
            ndms_native_import_journal_readiness_state_name(
                native_import_readiness));

    // Startup happens before the event loop. It is the one lifecycle point
    // where a bounded shared-cache refresh may safely query loopback NDMS.
    // Prime Keenetic DNS explicitly before the first route/firewall mutation;
    // all runtime consumers below are cache-only and share this exact view.
    active_keenetic_dns_ = prepare_keenetic_dns_view(
        config_,
        /*allow_refresh=*/true,
        /*force_refresh=*/true);
    auto internal_vpn_resolution =
        resolve_internal_vpn_servers_for_runtime(
            config_,
            true,
            snapshot_internal_vpn_verified_includes_lkg());
    const auto internal_vpn_resolution_state =
        internal_vpn_resolution.state;
    auto internal_vpn_service_resolution =
        resolve_internal_vpn_services_for_runtime(
            config_,
            true,
            snapshot_internal_vpn_service_verified_includes_lkg());
    const auto internal_vpn_service_resolution_state =
        internal_vpn_service_resolution.state;
    std::optional<InternalVpnRuntimeGenerationTransaction>
        internal_vpn_generation;
    internal_vpn_generation.emplace(
        resolved_internal_vpn_servers_,
        internal_vpn_resolution.effective_servers);
    std::optional<InternalVpnRuntimeTargetGenerationTransaction>
        internal_vpn_service_generation;
    internal_vpn_service_generation.emplace(
        resolved_internal_vpn_service_targets_,
        internal_vpn_service_resolution.effective_targets);
    setup_static_routing();
    log.info("Static routing tables and ip rules installed.");

    log.info("Startup lists: checking local cache; only missing remote lists will be downloaded.");
    const auto relevant_lists = collect_relevant_list_names(config_);
    const auto dns_relevant_lists = collect_dns_relevant_list_names(config_);
    RemoteListRefreshControl refresh_control;
    refresh_control.cache_commit = make_guarded_cache_commit_callback();
    const RemoteListsRefreshResult refresh_result =
        list_service_.download_uncached(
            config_,
            outbound_marks_,
            &relevant_lists,
            &dns_relevant_lists,
            refresh_control);

    if (!refresh_result.cached_lists.empty()) {
        log.info("Startup lists: using cached list(s): {}", format_list_names(refresh_result.cached_lists));
    }
    if (!refresh_result.changed_lists.empty()) {
        log.info("Startup lists: downloaded missing list(s): {}", format_list_names(refresh_result.changed_lists));
    } else if (refresh_result.refreshed_lists.empty() && refresh_result.failed_lists.empty()) {
        log.info("Startup lists: all remote lists are available locally; no downloads needed.");
    }
    if (!refresh_result.unchanged_lists.empty()) {
        log.info("Startup lists: downloaded list(s) were unchanged: {}",
                 format_list_names(refresh_result.unchanged_lists));
    }
    if (!refresh_result.failed_lists.empty()) {
        log.warn("Startup lists: failed to download missing list(s): {}",
                 format_list_names(refresh_result.failed_lists));
    }

    // From this point through the initial firewall retries and resolver
    // stream, both consumers must observe the exact same remote-list bodies.
    auto startup_list_cache_snapshot =
        capture_relevant_list_cache_generation(config_);

    // Applying rules must never abort startup. At boot the firmware holds the
    // xtables lock while it brings interfaces up, so this can legitimately fail;
    // coming up without rules and retrying beats leaving the router with no
    // service at all, because a running daemon can still be reached and fixed.
    bool startup_firewall_generation_committed = false;
    try {
        retry_hot_apply_firewall(
            [this, &startup_list_cache_snapshot]() {
                // A previous daemon generation may still own working chains
                // after a crash or package replacement. Keep them live until
                // this generation reaches an atomic COMMIT.
                apply_firewall(
                    FirewallApplyMode::PreserveSets,
                    startup_list_cache_snapshot);
            },
            [](std::chrono::milliseconds delay) {
                std::this_thread::sleep_for(delay);
            },
            [](std::size_t retry,
               std::chrono::milliseconds delay,
               const TransientFirewallError& error) {
                Logger::instance().info(
                    "Initial firewall replacement deferred after a concurrent "
                    "firmware change: {}. Retry {} in {}ms.",
                    error.what(),
                    retry,
                    delay.count());
            });
        cleanup_owned_conntrack_marks(
            "after initial firewall activation");
        startup_firewall_generation_committed = true;
        log.info("Firewall rules and routing applied.");
    } catch (const TransientFirewallError& e) {
        // The previous daemon's atomic firewall generation may still be the
        // one forwarding. Do not let the new process describe its uncommitted
        // candidate as active while the delayed retry is pending.
        internal_vpn_generation.reset();
        internal_vpn_service_generation.reset();
        // This is expected while NDMS is still publishing its firewall after
        // boot. schedule_startup_firewall_retry() emits one actionable error
        // only if bounded recovery is exhausted.
        log.info("Firewall rules are not ready at startup: {}. "
                 "The service continues and will retry shortly.", e.what());
        schedule_startup_firewall_retry(
            1, std::nullopt, startup_list_cache_snapshot);
    } catch (const std::exception& e) {
        internal_vpn_generation.reset();
        internal_vpn_service_generation.reset();
        // Invalid rules, missing helpers and other permanent faults will not
        // normally improve by repeating the same transaction. A stable-ID
        // candidate is the exception: until it commits, an older retained
        // kernel generation may still be forwarding, so keep the existing
        // bounded recovery rather than stranding the candidate indefinitely.
        log.error("Firewall apply failed permanently at startup: {}", e.what());
        if (config_has_native_vpn_catalog_policy(config_)) {
            schedule_startup_firewall_retry(
                1, std::nullopt, startup_list_cache_snapshot);
        }
    }

    schedule_lists_autoupdate();
    schedule_interface_probe();
    schedule_catalog_refresh();

    if (refresh_result.any_dns_relevant_changed()) {
        log.info("Startup lists: DNS-relevant list(s) changed ({}); reloading system resolver.",
                 format_list_names(refresh_result.dns_relevant_changed_lists));
    } else {
        log.info(
            "Startup resolver: reloading managed configuration after the control socket became available.");
    }
    // The Keenetic init script starts dnsmasq before the daemon so startup can
    // still resolve remote list hosts. At that point the control socket is not
    // available and dnsmasq intentionally loads the fallback configuration.
    // Always reload once more from the live daemon; otherwise a cache-complete
    // startup can remain on fallback DNS indefinitely.
    apply_started_ts_.store(unix_timestamp_now_seconds(), std::memory_order_release);
    commit_resolver_generation_snapshot(
        make_resolver_generation_snapshot(
            startup_list_cache_snapshot));
    if (!run_system_resolver_hook_stream_prepared(
            "reload", /*rebuild_snapshot=*/false)) {
        throw DaemonError(
            "system resolver reload did not complete its configuration stream");
    }
    // resolver_generation_snapshot_ now owns the active lease. Do not keep an
    // extra startup reference alive for the complete daemon event loop.
    startup_list_cache_snapshot.reset();
    // Publish a verified include-only LKG only after the initial route and
    // firewall transaction has actually committed. A transient startup
    // firewall failure is recovered by refresh_iproute_and_firewall_runtime(),
    // which performs the same commit after its successful retry.
    if (startup_firewall_generation_committed) {
        internal_vpn_generation->commit();
        internal_vpn_service_generation->commit();
        update_internal_vpn_verified_includes_lkg(
            internal_vpn_resolution);
        update_internal_vpn_service_verified_includes_lkg(
            internal_vpn_service_resolution);
        internal_vpn_generation.reset();
        internal_vpn_service_generation.reset();
    }
    routing_runtime_active_ = true;
    reset_idle_stall_observer(/*schedule_if_eligible=*/true);
    schedule_owned_snat_health_check();
    schedule_keenetic_dns_refresh();
    transition_runtime_or_throw(RuntimeState::running, "startup complete");
    publish_runtime_state();

    setup_dns_probe();

    register_interface_monitor_fd();

#ifdef WITH_API
    setup_api();
#endif

    // Async runtime probes commit through post_control_task(). Accept their
    // results before starting any probe, but keep event_loop_active_ false
    // until every fallible startup step has completed. This lets fast native
    // URLTest children queue their first result without exposing a half-started
    // daemon to synchronous control requests.
    accept_posted_control_tasks_.store(true, std::memory_order_release);
#ifdef WITH_API
    // Retry hints can originate on API worker threads. Register the bridge
    // only after posted control work is admitted, then create the startup
    // desired-state generation through the same reconciler used everywhere.
    setup_remote_access_retry_bridge();
    schedule_remote_access_recovery_watchdog();
    request_remote_access_reconcile_from_control("startup");
#endif
    if (internal_vpn_resolution_requires_catalog_refresh(
            config_, internal_vpn_resolution_state) ||
        (config_requires_internal_vpn_service_inventory(config_) &&
         internal_vpn_service_resolution_state !=
             InternalVpnRuntimeResolutionState::verified)) {
        // The initial bounded observation may fail transiently. Start the
        // retrying worker only after posted control tasks are accepted, so a
        // fast loopback response cannot be lost before the event loop starts.
        schedule_internal_vpn_catalog_refresh_if_needed(
            internal_vpn_resolution_state,
            internal_vpn_service_resolution_state);
    }
    register_urltest_outbounds();
    refresh_resolver_config_hash_actual_async();
    probe_interfaces_now();
    } catch (...) {
        // Startup installs owned kernel state before dnsmasq proves that it
        // consumed the matching resolver generation. Any failure before the
        // event loop starts must therefore unwind every owned subsystem; the
        // normal shutdown tail below is never reached in this path.
        log.error("Daemon startup failed; rolling back partial runtime state.");
#ifdef WITH_API
        cancel_remote_access_recovery_watchdog();
        reset_remote_access_retry_bridge();
#endif
        runtime_mutation_admission_.shutdown();
        routing_test_admission_.shutdown();
        sighup_reload_coordinator_.stop();
        cancel_resolver_reload_retry();
        resolver_stream_coordinator_.request_stop();
        keenetic_dns_refresh_coordinator_.stop();
        cancel_idle_stall_observer();
        cancel_meta_udp443_activation_cleanup();
        cancel_owned_conntrack_cleanup_retry();
        list_refresh_tasks_.request_cancel_active();
        runtime_generation_.fetch_add(1, std::memory_order_acq_rel);
        if (urltest_manager_) {
            try {
                urltest_manager_->clear();
            } catch (const std::exception& cleanup_error) {
                log.error("Startup rollback: urltest cleanup failed: {}",
                          cleanup_error.what());
            }
        }
        scheduler_->cancel_all();
        // A queued SIGHUP preparation already owns its mutation lease. Drop
        // queued callbacks before waiting for that lease, while active workers
        // can still publish their ordinary completion through the control loop.
        blocking_executor_.cancel_pending();
        quiesce_resolver_stream_recovery();
        quiesce_runtime_mutations();
        {
            KPBR_LOCK_GUARD(control_tasks_mutex_);
            accept_posted_control_tasks_.store(
                false, std::memory_order_release);
        }
        if (control_fd_ >= 0) {
            handle_control_commands();
        }
#ifdef WITH_API
        if (status_stream_) {
            status_stream_->close_all();
        }
        if (dns_test_broadcaster_) {
            dns_test_broadcaster_->close_all();
        }
        if (api_server_) {
            api_server_->stop();
        }
        try {
            teardown_conntrack_events();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: conntrack cleanup failed: {}",
                      cleanup_error.what());
        }
        remove_remote_access_rules(
            RemoteAccessRemovalMode::expected_teardown);
#endif
        routing_test_executor_.cancel_pending_and_shutdown();
        blocking_executor_.cancel_pending_and_shutdown();
        try {
            unregister_interface_monitor_fd();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: interface monitor cleanup failed: {}",
                      cleanup_error.what());
        }
        try {
            teardown_dns_probe();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: DNS probe cleanup failed: {}",
                      cleanup_error.what());
        }
        try {
            policy_rules_.clear();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: policy-rule cleanup failed: {}",
                      cleanup_error.what());
        }
        try {
            route_table_.clear();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: route cleanup failed: {}",
                      cleanup_error.what());
        }
        try {
            KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
            firewall_->cleanup();
            committed_meta_udp443_fwmark_.reset();
            committed_meta_udp443_owned_mask_ = 0U;
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: firewall cleanup failed: {}",
                      cleanup_error.what());
        }
        try {
            if (!run_system_resolver_hook("deactivate")) {
                log.error(
                    "Startup rollback: resolver fallback activation failed.");
            }
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: resolver fallback activation failed: {}",
                      cleanup_error.what());
        }
        routing_runtime_active_ = false;
        resolver_sync_.runtime_stopped();
        try {
            transition_runtime_or_throw(
                RuntimeState::broken, "startup failed and was rolled back");
            publish_runtime_state();
        } catch (const std::exception& state_error) {
            log.error("Startup rollback: state publication failed: {}",
                      state_error.what());
        }
        try {
            remove_pid_file();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: PID cleanup failed: {}",
                      cleanup_error.what());
        }
        throw;
    }

    log.info("Daemon running. PID: {}", getpid());

    running_.store(true, std::memory_order_release);
    event_loop_thread_id_.store(std::this_thread::get_id(), std::memory_order_relaxed);
    event_loop_active_.store(true, std::memory_order_release);

    run_event_loop();

#ifdef WITH_API
    // Fence retry callbacks while posted-control admission and Scheduler are
    // still alive. No API worker may retain a Daemon capture past this point.
    cancel_remote_access_recovery_watchdog();
    reset_remote_access_retry_bridge();
#endif
    // Stop the continuous forwarded-flow observer before closing admission to
    // the control loop or tearing down API/conntrack state.  An in-flight
    // observation is generation-fenced, but disabling it here also prevents a
    // late exact delete from racing normal shutdown.
    cancel_idle_stall_observer();
    cancel_meta_udp443_activation_cleanup();
    runtime_mutation_admission_.shutdown();
    routing_test_admission_.shutdown();
    sighup_reload_coordinator_.stop();
    cancel_resolver_reload_retry();
    resolver_stream_coordinator_.request_stop();
    keenetic_dns_refresh_coordinator_.stop();
    list_refresh_tasks_.request_cancel_active();
    // Invalidate timer/probe generations before coordinator quiescence. A
    // queued SIGHUP preparation can already own the mutation lease, so discard
    // unclaimed blocking work before waiting for that lease to return.
    if (urltest_manager_) {
        urltest_manager_->clear();
    }
    cancel_owned_conntrack_cleanup_retry();
    scheduler_->cancel_all();
    blocking_executor_.cancel_pending();
    // Admission is closed before quiescence, so new HTTP/SIGHUP writers are
    // rejected. Existing owners keep their token and may finish through the
    // control queue while this thread still owns the event-loop state.
    quiesce_resolver_stream_recovery();
    quiesce_runtime_mutations();
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        accept_posted_control_tasks_.store(
            false, std::memory_order_release);
    }
    handle_control_commands();
    event_loop_active_.store(false, std::memory_order_release);
    event_loop_thread_id_.store(std::thread::id{}, std::memory_order_relaxed);

    log.info("Shutting down...");
    transition_runtime_or_throw(RuntimeState::shutting_down, "daemon shutdown requested");
    publish_runtime_state();

#ifdef WITH_API
    if (status_stream_) {
        status_stream_->close_all();
    }
    if (dns_test_broadcaster_) {
        dns_test_broadcaster_->close_all();
    }
    if (api_server_) {
        api_server_->stop();
    }
    teardown_conntrack_events();
    remove_remote_access_rules(
        RemoteAccessRemovalMode::expected_teardown);
#endif

    // Stop accepting API work before retiring workers. Otherwise a handler can
    // enqueue against an executor that has already been shut down.
    resolver_hook_executor_.cancel_pending_and_shutdown();
    resolver_stream_executor_.cancel_pending_and_shutdown();
    resolver_io_executor_.cancel_pending_and_shutdown();
    routing_test_executor_.cancel_pending_and_shutdown();
    blocking_executor_.cancel_pending_and_shutdown();

    teardown_dns_probe();

    policy_rules_.clear();
    route_table_.clear();
    firewall_->cleanup();
    committed_meta_udp443_fwmark_.reset();
    committed_meta_udp443_owned_mask_ = 0U;
    routing_runtime_active_ = false;
    transition_runtime_or_throw(RuntimeState::stopped, "daemon shutdown complete");
    remove_pid_file();
}

void Daemon::stop() {
    list_refresh_tasks_.request_cancel_active();
    runtime_mutation_admission_.shutdown();
    routing_test_admission_.shutdown();
    sighup_reload_coordinator_.stop();
    resolver_stream_coordinator_.request_stop();
    running_.store(false, std::memory_order_release);
    if (control_fd_ >= 0) {
        try {
            wake_control_loop();
        } catch (...) {
            // stop() is a best-effort wake path and must remain noexcept to
            // callers. Closing the fd during teardown already wakes epoll.
        }
    }
}

bool Daemon::running() const {
    return running_.load(std::memory_order_acquire);
}

void Daemon::write_pid_file() {
    const auto pid_file = config_.daemon.value_or(DaemonConfig{}).pid_file.value_or("");
    try {
        pid_file_.acquire(pid_file);
    } catch (const std::exception& error) {
        throw DaemonError(error.what());
    }
}

void Daemon::remove_pid_file() {
    pid_file_.remove();
}

} // namespace keen_pbr3
