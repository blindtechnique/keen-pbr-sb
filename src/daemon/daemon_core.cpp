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
#include <grp.h>
#include <map>
#include <nlohmann/json.hpp>
#include <ostream>
#include <signal.h>
#include <set>
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
#include "../firewall/firewall_verifier.hpp"
#include "../health/routing_health_checker.hpp"
#include "../ipc/control_protocol.hpp"
#include "../keenetic/internal_vpn_server_resolver.hpp"
#include "../keenetic/internal_vpn_service_resolver.hpp"
#include "../keenetic/internal_vpn_runtime_generation.hpp"
#include "../keenetic/ndms_catalog_cache.hpp"
#include "../keenetic/ndms_vpn_server_service_cache.hpp"
#include "../lists/list_streamer.hpp"
#include "../log/logger.hpp"
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

constexpr auto NETFILTER_REFRESH_DEBOUNCE_DELAY =
    std::chrono::milliseconds{400};
constexpr auto OWNED_SNAT_HEALTH_INTERVAL =
    std::chrono::seconds{60};
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
    , hook_command_executor_(std::move(hook_command_executor))
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
    try {
        {
            KPBR_LOCK_GUARD(control_tasks_mutex_);
            accept_posted_control_tasks_.store(
                false, std::memory_order_release);
        }
        list_refresh_tasks_.request_cancel_active();
        resolver_hook_executor_.shutdown();
        resolver_stream_executor_.shutdown();
        resolver_io_executor_.shutdown();
        blocking_executor_.shutdown();

        if (control_fd_ >= 0) {
            epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, control_fd_, nullptr);
            close(control_fd_);
            control_fd_ = -1;
        }
        remove_ipc_control_socket();
        if (signal_fd_ >= 0) {
            epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, signal_fd_, nullptr);
            close(signal_fd_);
            signal_fd_ = -1;
        }
        if (epoll_fd_ >= 0) {
            close(epoll_fd_);
            epoll_fd_ = -1;
        }

        unblock_daemon_signals_for_current_thread();
    } catch (const std::exception& e) {
        Logger::instance().error("Daemon destruction cleanup failed: {}", e.what());
    } catch (...) {
        Logger::instance().error("Daemon destruction cleanup failed: unknown error");
    }
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
                const auto result = compute_test_routing(
                    config_store_.active_config(),
                    list_service_.cache_manager(),
                    target);
                nlohmann::json entries = nlohmann::json::array();
                for (const auto& entry : result.entries) {
                    entries.push_back(
                        {{"ip", entry.ip},
                         {"expected_outbound", entry.expected_outbound},
                         {"actual_outbound", entry.actual_outbound},
                         {"ok", entry.ok}});
                }
                response = {
                    {"protocol_version", ipc::kControlProtocolVersion},
                    {"request_id", request.at("request_id")},
                    {"ok", !result.dns_error.has_value()},
                    {"result",
                     {{"target", result.target},
                      {"resolved_ips", result.resolved_ips},
                      {"entries", std::move(entries)},
                      {"warnings", result.warnings},
                      {"dns_error", result.dns_error}}},
                };
            } else if (operation == "generate-resolver-config") {
                const RuntimeState runtime_state =
                    runtime_state_machine_.state();
                const bool resolver_generation_available =
                    runtime_state == RuntimeState::starting ||
                    runtime_state == RuntimeState::running ||
                    runtime_state == RuntimeState::restart_required ||
                    runtime_state == RuntimeState::applying;
                if (!resolver_generation_available) {
                    const auto runtime_snapshot =
                        runtime_state_store_.snapshot();
                    response = ipc::make_error_response(
                        request,
                        resolver_runtime_reason(runtime_snapshot),
                        "resolver runtime is not active");
                } else if (!resolver_generation_snapshot_) {
                    response = ipc::make_error_response(
                        request,
                        "resolver_generation_unavailable",
                        "resolver generation is not available");
                } else {
                    // Capture the exact candidate generation that requested
                    // the reload. The committed ConfigStore can still contain
                    // the previous generation until transactional apply ends.
                    const auto generation = resolver_generation_snapshot_;
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
                         request_id] {
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
                                    if (list->second.url.has_value() &&
                                        !cache.has_cache(list_name)) {
                                        throw ipc::ControlProtocolError(
                                            "list_cache_missing");
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
                                ListStreamer streamer(cache);
                                DnsServerRegistry registry(dns_config);
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
                            if (stream_completed) {
                                resolver_stream_completed_epoch_.store(
                                    generation->stream_epoch,
                                    std::memory_order_release);
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
    ssize_t n = write(control_fd_, &inc, sizeof(inc));
    if (n < 0 && errno != EAGAIN) {
        throw DaemonError("eventfd write failed: " + std::string(strerror(errno)));
    }
}

bool Daemon::is_event_loop_thread() const {
    return event_loop_thread_id_.load(std::memory_order_relaxed) == std::this_thread::get_id();
}

void Daemon::enqueue_control_task(std::function<void()> task,
                                  bool wait_for_completion,
                                  const std::string& label) {
    if (!task) {
        return;
    }

    const auto effective_label = label.empty() ? std::string("control-task") : label;
    const TraceId trace_id = ensure_trace_id();
    auto run_inline = [task = std::move(task), effective_label, trace_id]() mutable {
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        Logger::instance().trace("control_task_start", "label={} mode=inline", effective_label);
        try {
            task();
            Logger::instance().trace("control_task_end",
                                     "label={} mode=inline duration_ms={}",
                                     effective_label,
                                     steady_duration_ms(started_at));
        } catch (const std::exception& e) {
            Logger::instance().trace("control_task_error",
                                     "label={} mode=inline duration_ms={} error={}",
                                     effective_label,
                                     steady_duration_ms(started_at),
                                     e.what());
            throw;
        } catch (...) {
            Logger::instance().trace("control_task_error",
                                     "label={} mode=inline duration_ms={} error=unknown",
                                     effective_label,
                                     steady_duration_ms(started_at));
            throw;
        }
    };

    if (!event_loop_active_.load(std::memory_order_acquire) ||
        event_loop_thread_id_.load(std::memory_order_relaxed) == std::thread::id{}) {
        run_inline();
        return;
    }

    if (event_loop_thread_id_.load(std::memory_order_relaxed) == std::this_thread::get_id()) {
        run_inline();
        return;
    }

    if (wait_for_completion) {
        auto done = std::make_shared<std::promise<void>>();
        auto fut = done->get_future();
        {
            KPBR_LOCK_GUARD(control_tasks_mutex_);
            control_tasks_.push_back(ControlTask{
                .callback = [cmd = std::move(run_inline), done]() mutable {
                try {
                    cmd();
                    done->set_value();
                } catch (...) {
                    done->set_exception(std::current_exception());
                }
                },
                .label = effective_label,
                .trace_id = trace_id,
            });
        }
        Logger::instance().trace("control_task_enqueue",
                                 "label={} wait=true",
                                 effective_label);
        wake_control_loop();
        fut.get();
        return;
    }

    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        control_tasks_.push_back(ControlTask{
            .callback = std::move(run_inline),
            .label = effective_label,
            .trace_id = trace_id,
        });
    }
    Logger::instance().trace("control_task_enqueue",
                             "label={} wait=false",
                             effective_label);
    wake_control_loop();
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
        Logger::instance().trace("control_task_start", "label={} mode=posted", effective_label);
        try {
            task();
            Logger::instance().trace("control_task_end",
                                     "label={} mode=posted duration_ms={}",
                                     effective_label,
                                     steady_duration_ms(started_at));
        } catch (const std::exception& e) {
            Logger::instance().trace("control_task_error",
                                     "label={} mode=posted duration_ms={} error={}",
                                     effective_label,
                                     steady_duration_ms(started_at),
                                     e.what());
            throw;
        } catch (...) {
            Logger::instance().trace("control_task_error",
                                     "label={} mode=posted duration_ms={} error=unknown",
                                     effective_label,
                                     steady_duration_ms(started_at));
            throw;
        }
    };

    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        // Serialize admission with shutdown. The optimistic check above keeps
        // the normal rejection path cheap; this second check prevents a task
        // from being queued after shutdown disabled deferred commits.
        if (!accept_posted_control_tasks_.load(
                std::memory_order_acquire)) {
            return false;
        }
        control_tasks_.push_back(ControlTask{
            .callback = std::move(traced_task),
            .label = effective_label,
            .trace_id = trace_id,
        });
    }
    Logger::instance().trace("control_task_enqueue",
                             "label={} wait=false mode=post",
                             effective_label);
    wake_control_loop();
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

    std::vector<ControlTask> commands;
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        commands.swap(control_tasks_);
    }

    for (auto& command : commands) {
        command.callback();
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
    struct signalfd_siginfo info{};
    ssize_t n = read(signal_fd_, &info, sizeof(info));
    if (n != sizeof(info)) {
        return;
    }

    switch (info.ssi_signo) {
    case SIGTERM:
    case SIGINT:
        running_.store(false, std::memory_order_release);
        break;
    case SIGUSR1:
        handle_sigusr1();
        break;
    case SIGUSR2:
        handle_sigusr2();
        break;
    case SIGHUP:
        handle_sighup();
        break;
    default:
        break;
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
    const bool recovery_pending =
        runtime_firewall_retry_task_id_ >= 0 ||
        pending_owned_snat_recovery_.requested;
    const bool netfilter_refresh_pending =
        netfilter_refresh_task_id_ >= 0 ||
        pending_netfilter_refresh_reasons_ != 0;
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

    auto task_metrics =
        periodic_task_metrics_.begin("owned-snat-health");
    OwnedSnatState state = OwnedSnatState::unknown;
    try {
        state = firewall_->inspect_owned_snat_state();
    } catch (const std::exception& error) {
        // This is a fallback guard, not an alert source. An inspection error
        // must neither disrupt the event loop nor emit one message per tick.
        task_metrics.failure(error.what());
        return;
    } catch (...) {
        task_metrics.failure("owned SNAT inspection failed");
        return;
    }
    if (!should_run_periodic_snat_repair(
            routing_runtime_active_,
            recovery_pending,
            netfilter_refresh_pending,
            state)) {
        task_metrics.noop();
        return;
    }

    Logger::instance().info(
        "Periodic SNAT health check detected a {} owned scaffold; "
        "repairing it.",
        state == OwnedSnatState::missing ? "missing" : "stale");
    const bool repaired = refresh_iproute_and_firewall_runtime(
        0,
        std::nullopt,
        std::nullopt,
        /*schedule_catalog_refresh=*/false,
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/false});
    if (repaired) {
        task_metrics.success();
    } else {
        task_metrics.failure("owned SNAT repair did not converge");
    }
}

void Daemon::schedule_netfilter_runtime_refresh(
    NetfilterRefreshReason reason) {
    pending_netfilter_refresh_reasons_ |=
        static_cast<std::uint8_t>(reason);
    if (netfilter_refresh_task_id_ >= 0) {
        scheduler_->cancel(netfilter_refresh_task_id_);
        netfilter_refresh_task_id_ = -1;
    }

    netfilter_refresh_task_id_ = scheduler_->schedule_oneshot(
        NETFILTER_REFRESH_DEBOUNCE_DELAY,
        [this]() {
            netfilter_refresh_task_id_ = -1;
            const std::uint8_t reasons =
                pending_netfilter_refresh_reasons_;
            pending_netfilter_refresh_reasons_ = 0;
            const bool full_refresh =
                (reasons &
                 static_cast<std::uint8_t>(
                     NetfilterRefreshReason::full)) != 0;
            const bool nat_refresh =
                (reasons &
                 static_cast<std::uint8_t>(
                     NetfilterRefreshReason::nat_only)) != 0;
            const bool snat_health_check =
                full_refresh || nat_refresh;
            const char* reason_label =
                full_refresh && nat_refresh
                    ? "full+nat"
                    : (full_refresh ? "full" : "nat");

            Logger::instance().info(
                "Netfilter event: applying {} runtime refresh...",
                reason_label);
            if (nat_refresh &&
                runtime_firewall_retry_task_id_ >= 0) {
                // Do not coalesce away a confirmed firmware NAT rebuild behind
                // an older generic recovery. Replace that retry with an
                // immediate attempt whose bounded retry chain remembers that
                // SNAT health must be verified.
                cancel_runtime_firewall_retry();
            }
            const bool runtime_refreshed =
                refresh_iproute_and_firewall_runtime(
                    0,
                    std::nullopt,
                    std::nullopt,
                    /*schedule_catalog_refresh=*/true,
                    OwnedSnatRecovery{
                        /*requested=*/snat_health_check,
                        /*missing_observed=*/false});

            // A nat-only repair must not turn one firmware table rebuild into
            // a burst of remote health probes. Full/mangle refreshes preserve
            // the historical SIGUSR1 behaviour, but only after the runtime
            // generation was actually reconciled.
            if (runtime_refreshed && full_refresh && urltest_manager_) {
                Logger::instance().info(
                    "Netfilter event: probing urltest endpoints...");
                for (const auto& ob : config_.outbounds.value_or(std::vector<Outbound>{})) {
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
                    "Netfilter event: {} runtime refresh deferred or "
                    "coalesced with recovery.",
                    reason_label);
            }
        },
        "netfilter-runtime-refresh");
}

void Daemon::handle_sighup() {
    auto& log = Logger::instance();
    log.info("SIGHUP: full reload starting...");
#ifdef WITH_API
    bool operation_started = false;
#endif
    try {
#ifdef WITH_API
        // SIGHUP is another configuration writer. Serialize it with API
        // staging and transactional commits so a disk reload cannot replace
        // the active ConfigStore snapshot after a catalogue preview has been
        // revalidated but before that candidate is committed.
        begin_config_operation_or_throw(
            ConfigOperationState::Reloading,
            "sighup-reload",
            false,
            false);
        operation_started = true;
        if (config_store_.config_is_draft()) {
            log.warn(
                "SIGHUP: reload deferred because a configuration draft is "
                "staged; save or discard the draft first.");
            finish_config_operation();
            operation_started = false;
            return;
        }
#endif
        reload_from_disk();
#ifdef WITH_API
        finish_config_operation();
        operation_started = false;
#endif
        log.info("SIGHUP: full reload complete.");
    } catch (const std::exception& e) {
#ifdef WITH_API
        if (operation_started) {
            finish_config_operation();
        }
#endif
        log.error("SIGHUP: reload failed: {}", e.what());
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
    pending_owned_snat_recovery_ =
        merge_owned_snat_recovery(
            pending_owned_snat_recovery_, snat_recovery);
    snat_recovery = pending_owned_snat_recovery_;
    if (runtime_recovery_request_should_coalesce(
            retry_attempt,
            runtime_firewall_retry_task_id_ >= 0)) {
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
        pending_owned_snat_recovery_ = snat_recovery;
        reconcile_static_routing(RouteReconcileMode::DeferredRepair);
        apply_firewall(FirewallApplyMode::PreserveSets);
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
        pending_owned_snat_recovery_ = snat_recovery;
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
        if (resolver_access_policy_changed) {
            // A live NDMS catalog refresh can add, remove or rename a dynamic
            // SSTP/IKE/L2TP/OpenConnect ingress without changing config.json.
            // Firewall and the in-memory inventory have already committed, so
            // publish the matching dnsmasq interface ACL as the same runtime
            // generation. A resolver failure must not roll back working
            // forwarding; the bounded resolver reconciler will converge it.
            apply_started_ts_.store(
                unix_timestamp_now_seconds(), std::memory_order_release);
            cancel_resolver_reload_retry();
            try {
                update_resolver_config_hash();
                if (run_system_resolver_hook_reload()) {
                    refresh_resolver_config_hash_actual_async();
                } else {
                    log.info(
                        "Native VPN DNS access policy did not converge during "
                        "runtime refresh; scheduling a bounded resolver retry.");
                    schedule_resolver_reload_retry(
                        0,
                        runtime_generation_.load(
                            std::memory_order_acquire));
                }
            } catch (const std::exception& error) {
                log.info(
                    "Native VPN DNS access policy refresh was deferred: {}",
                    error.what());
                schedule_resolver_reload_retry(
                    0,
                    runtime_generation_.load(std::memory_order_acquire));
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
        if (snat_recovery.requested) {
            pending_owned_snat_recovery_ = {};
        }
        runtime_firewall_incidents_.clear();
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
        if (snat_recovery.requested) {
            schedule_runtime_firewall_retry(
                retry_attempt,
                runtime_generation_.load(std::memory_order_acquire),
                snat_recovery);
        }
        return false;
    } catch (const TransientFirewallError& e) {
        if (retry_attempt >= RUNTIME_FIREWALL_RETRY_DELAYS.size()) {
            if (snat_recovery.requested) {
                // Keep one quiet, capped maintenance retry alive while the
                // desired SNAT contract is still missing. Netfilter hooks can
                // be lost during firmware service restarts; recovery must not
                // depend on receiving another external event.
                log.info(
                    "Runtime firewall recovery remains pending after {} "
                    "bounded retries: {}. A maintenance retry will continue "
                    "in the background.",
                    retry_attempt,
                    e.what());
                schedule_runtime_firewall_retry(
                    retry_attempt,
                    runtime_generation_.load(std::memory_order_acquire),
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
        // A permanent rule/configuration failure is actionable and must remain
        // visible to the user. Stable-ID changes also retain a bounded retry:
        // the generation guard has restored the previous in-memory map, so
        // kernel and memory still describe the same previous generation.
        const bool retry =
            config_has_native_vpn_catalog_policy(config_) &&
            retry_attempt < RUNTIME_FIREWALL_RETRY_DELAYS.size();
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
                "Runtime routing/firewall reconciliation remains failed: {}. "
                "The existing notification remains active.",
                e.what());
        }
        if (retry) {
            schedule_runtime_firewall_retry(
                retry_attempt,
                runtime_generation_.load(std::memory_order_acquire),
                snat_recovery);
        }
        return false;
    }
}

void Daemon::cancel_runtime_firewall_retry() {
    if (runtime_firewall_retry_task_id_ < 0) {
        return;
    }
    scheduler_->cancel(runtime_firewall_retry_task_id_);
    runtime_firewall_retry_task_id_ = -1;
}

void Daemon::schedule_runtime_firewall_retry(
    std::size_t attempt,
    std::uint64_t runtime_generation,
    OwnedSnatRecovery snat_recovery) {
    if (runtime_firewall_retry_task_id_ >= 0) {
        return;
    }
    const auto retry_plan = plan_runtime_firewall_retry(
        attempt,
        RUNTIME_FIREWALL_RETRY_DELAYS.size(),
        snat_recovery.requested);
    if (!retry_plan.schedule) {
        return;
    }
    const auto delay = retry_plan.maintenance
        ? std::chrono::seconds{60}
        : RUNTIME_FIREWALL_RETRY_DELAYS[attempt];
    runtime_firewall_retry_task_id_ = scheduler_->schedule_oneshot(
        delay,
        [this,
         next_attempt = retry_plan.next_attempt,
         runtime_generation,
         snat_recovery]() {
            runtime_firewall_retry_task_id_ = -1;
            if (!runtime_recovery_is_current(
                    routing_runtime_active_,
                    runtime_generation,
                    runtime_generation_.load(std::memory_order_acquire))) {
                Logger::instance().verbose(
                    "Discarding stale runtime firewall recovery retry.");
                return;
            }
            refresh_iproute_and_firewall_runtime(
                next_attempt,
                std::nullopt,
                std::nullopt,
                /*schedule_catalog_refresh=*/true,
                snat_recovery);
        },
        "runtime-firewall-retry");
    if (retry_plan.maintenance) {
        Logger::instance().verbose(
            "SNAT maintenance recovery scheduled in {}s.",
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
        struct epoll_event ev{};
        ev.events = events;
        ev.data.fd = fd;
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
            throw DaemonError("epoll_ctl add fd failed: " + std::string(strerror(errno)));
        }

        KPBR_LOCK_GUARD(fd_entries_mutex_);
        fd_entries_.push_back({fd, std::move(cb)});
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

        for (int i = 0; i < nfds; ++i) {
            dispatch_event_fd(events[i].data.fd, events[i].events);
        }
    }
}

void Daemon::run() {
    auto& log = Logger::instance();

    try {
    // Startup happens before the event loop. It is the one lifecycle point
    // where a bounded shared-cache refresh may safely query loopback NDMS.
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

    // Applying rules must never abort startup. At boot the firmware holds the
    // xtables lock while it brings interfaces up, so this can legitimately fail;
    // coming up without rules and retrying beats leaving the router with no
    // service at all, because a running daemon can still be reached and fixed.
    bool startup_firewall_generation_committed = false;
    try {
        retry_hot_apply_firewall(
            [this]() {
                // A previous daemon generation may still own working chains
                // after a crash or package replacement. Keep them live until
                // this generation reaches an atomic COMMIT.
                apply_firewall(FirewallApplyMode::PreserveSets);
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
        schedule_startup_firewall_retry();
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
            schedule_startup_firewall_retry();
        }
    }

    schedule_lists_autoupdate();
    schedule_interface_probe();
    schedule_catalog_refresh();
#ifdef WITH_API
    apply_remote_access_rules(config_.api.has_value()
                                  ? config_.api->listen.value_or(std::string{})
                                  : std::string{});
#endif

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
    update_resolver_config_hash();
    if (!run_system_resolver_hook_reload()) {
        throw DaemonError(
            "system resolver reload did not complete its configuration stream");
    }
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
        {
            KPBR_LOCK_GUARD(control_tasks_mutex_);
            accept_posted_control_tasks_.store(
                false, std::memory_order_release);
        }
        cancel_idle_stall_observer();
        cancel_owned_conntrack_cleanup_retry();
        runtime_generation_.fetch_add(1, std::memory_order_acq_rel);
        scheduler_->cancel_all();
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
        remove_remote_access_rules();
#endif
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
        if (urltest_manager_) {
            try {
                urltest_manager_->clear();
            } catch (const std::exception& cleanup_error) {
                log.error("Startup rollback: urltest cleanup failed: {}",
                          cleanup_error.what());
            }
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

    // Stop the continuous forwarded-flow observer before closing admission to
    // the control loop or tearing down API/conntrack state.  An in-flight
    // observation is generation-fenced, but disabling it here also prevents a
    // late exact delete from racing normal shutdown.
    cancel_idle_stall_observer();
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        accept_posted_control_tasks_.store(
            false, std::memory_order_release);
    }
    list_refresh_tasks_.request_cancel_active();
    // Admission is closed before the final drain, so a worker cannot enqueue a
    // cache/runtime commit after the event loop has stopped processing tasks.
    // Drain everything admitted before the gate closed while this thread still
    // owns the control-loop state.
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
    remove_remote_access_rules();
#endif

    // Stop accepting API work before draining workers. Otherwise a handler can
    // enqueue against an executor that has already been shut down.
    resolver_hook_executor_.shutdown();
    resolver_stream_executor_.shutdown();
    resolver_io_executor_.shutdown();
    blocking_executor_.shutdown();

    teardown_dns_probe();

    if (urltest_manager_) {
        urltest_manager_->clear();
    }
    cancel_owned_conntrack_cleanup_retry();
    scheduler_->cancel_all();
    policy_rules_.clear();
    route_table_.clear();
    firewall_->cleanup();
    routing_runtime_active_ = false;
    transition_runtime_or_throw(RuntimeState::stopped, "daemon shutdown complete");
    remove_pid_file();
}

void Daemon::stop() {
    list_refresh_tasks_.request_cancel_active();
    running_.store(false, std::memory_order_release);
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
