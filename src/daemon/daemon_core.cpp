#include "daemon.hpp"

#include "../keenetic/ndms_native_writer_lease.hpp"

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
#include <limits>
#include <map>
#include <new>
#include <nlohmann/json.hpp>
#include <ostream>
#include <poll.h>
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
#include <type_traits>
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
#include "runtime_firewall_operation_owner.hpp"
#include "runtime_route_health_plan.hpp"
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
constexpr std::size_t kMaxPendingControlClients = 64U;
constexpr std::size_t kMaxControlRequestBytes = 4U * 1024U;
constexpr auto kControlIngressTimeout = std::chrono::seconds{1};
constexpr auto kControlResponseSendTimeout =
    std::chrono::seconds{1};
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

void send_control_response_and_close(
    int fd,
    const nlohmann::json& response) noexcept {
    try {
        const auto frame = ipc::encode_message(response);
        ipc::send_all_bounded_nonblocking(
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

struct RuntimeFirewallStartRollbackResult;

struct DaemonRuntimeFirewallOperationState final
    : RuntimeFirewallOperationDomainState {
    enum class PreworkerFailureKind : std::uint8_t {
        none,
        admission_contention,
        route_unavailable,
        preparation_failure,
        transport_rejected,
    };

    struct CorePublication final {
        bool prepared{false};
        bool committed{false};
        std::vector<RuleState> rules;
        AppliedListContentState list_content_state;
        std::map<std::string, ListSetUsage> list_usage;
        std::map<std::string, std::string> list_fingerprints;
        std::vector<InternalVpnServer> internal_vpn_servers;
        std::vector<InternalVpnRuntimeTarget> internal_vpn_service_targets;
        std::vector<FirewallSourceEgressSnatSelector>
            native_vpn_direct_egress_snat_selectors;
        std::optional<std::uint32_t> committed_meta_fwmark;
        std::uint32_t committed_meta_owned_mask{0U};
    };

    enum class LifecycleTailPhase : std::uint8_t {
        not_started,
        in_flight,
        completed,
    };

    InternalVpnRuntimeResolution internal_vpn_resolution;
    InternalVpnServiceRuntimeResolution internal_vpn_service_resolution;
    std::vector<std::string> lifecycle_trusted_dns_interfaces;
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot;
    bool resolver_refresh_required{false};
    // A foreground lifecycle operation is complete only after the committed
    // firewall generation and its resolver stream have both been verified.
    // Ordinary background refreshes retain their best-effort resolver tail.
    bool lifecycle_resolver_verified{false};
    std::string lifecycle_failure_detail;
    LifecycleTailPhase lifecycle_resolver_phase{
        LifecycleTailPhase::not_started};
    std::string lifecycle_resolver_attempt_id;
    std::uint64_t lifecycle_resolver_stream_epoch{0U};
    LifecycleTailPhase lifecycle_start_rollback_phase{
        LifecycleTailPhase::not_started};
    std::shared_ptr<RuntimeFirewallStartRollbackResult>
        lifecycle_start_rollback_result;
    std::size_t lifecycle_start_rollback_handoff_rejections{0U};
    bool lifecycle_start_candidate_published{false};
    bool lifecycle_start_finalized{false};
    bool lifecycle_start_post_success_finished{false};
    bool lifecycle_start_failure_detail_prepared{false};
    std::string lifecycle_start_rollback_detail;
    bool preworker_side_effects_armed{false};
    std::optional<PendingMetaUdp443ActivationCleanup>
        previous_meta_cleanup;
    std::uint64_t meta_cleanup_epoch{0U};

    CorePublication core_publication;
    std::optional<MetaUdp443ActivationPlan>
        candidate_meta_activation_plan;
    std::optional<OwnedSnatRecovery> processed_snat_recovery;
    OwnedSnatState inspected_snat_after{OwnedSnatState::unknown};
    bool worker_result_valid{false};
    bool worker_failure_transient{false};
    std::string worker_failure_detail;
    bool core_published{false};
    bool internal_vpn_lkg_published{false};
    bool resolver_generation_published{false};
    bool resolver_tail_finished{false};
    bool meta_tail_finished{false};
    bool conntrack_tail_finished{false};
    bool runtime_tail_finished{false};
    RuntimeFirewallImmediateCompletionIntent immediate_completion_intent;
    PreworkerFailureKind preworker_failure_kind{
        PreworkerFailureKind::none};
    std::string preworker_failure_detail;
    bool preworker_failure_policy_finished{false};
    bool suppress_coordinator_rerun{false};
    bool preworker_urltest_permanent_started{false};
    std::vector<std::string> preworker_failed_urltest_tags;
    std::shared_ptr<RuntimeRouteMutationCheckpoint>
        route_mutation_checkpoint;
};

struct RuntimeFirewallStartRollbackResult final {
    std::atomic<bool> ready{false};
    bool routing_cleared{false};
    bool firewall_cleared{false};
    bool resolver_deactivated{false};
    std::string detail;
};

static_assert(
    std::is_nothrow_move_assignable_v<
        DaemonRuntimeFirewallOperationState::CorePublication>,
    "the runtime firewall core checkpoint must commit without throwing");
static_assert(
    std::is_nothrow_move_assignable_v<
        std::optional<MetaUdp443ActivationPlan>>,
    "the runtime firewall Meta checkpoint must commit without throwing");
static_assert(
    std::is_nothrow_move_assignable_v<std::optional<OwnedSnatRecovery>>,
    "the runtime firewall SNAT checkpoint must commit without throwing");

DaemonRuntimeFirewallOperationState& runtime_firewall_domain_state(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context) {
    if (!context || !context->domain_state) {
        throw std::logic_error(
            "runtime firewall operation has no domain state");
    }
    return static_cast<DaemonRuntimeFirewallOperationState&>(
        *context->domain_state);
}

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
          "/opt/etc/keen-pbr/native-import-wal")
    , ndms_native_delete_wal_store_(
          "/opt/etc/keen-pbr/native-delete-wal")
    , ndms_native_ownership_store_(
          "/opt/etc/keen-pbr/native-import-ownership")
    , ndms_native_observation_store_(
          "/opt/etc/keen-pbr/native-mutation")
    , ndms_native_secret_snapshot_store_(
          "/opt/etc/keen-pbr/native-import-secrets/snapshot.key",
          "/opt/etc/keen-pbr/native-import-snapshots")
    , config_(std::move(config))
    , config_path_(std::move(config_path))
    , opts_(std::move(opts))
    , firewall_(create_firewall(
          firewall_backend_preference(config_),
          RawPreroutingMode{opts_.use_raw_prerouting,
                            opts_.use_raw6_prerouting}))
    , interface_monitor_(std::make_unique<InterfaceMonitor>(
          [this](const InterfaceMonitor::Event& event) {
              handle_interface_event(event);
          }))
    , netlink_()
    , routing_operation_owner_(netlink_, netlink_)
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

    RuntimeFirewallOperationOwner::Callbacks firewall_owner_callbacks;
    firewall_owner_callbacks.create_domain_state = [] {
        return std::make_shared<DaemonRuntimeFirewallOperationState>();
    };
    firewall_owner_callbacks.post_control =
        [this](std::function<void()> task, std::string label) {
            return post_control_task(std::move(task), std::move(label));
        };
    firewall_owner_callbacks.schedule_oneshot =
        [this](std::chrono::milliseconds delay,
               std::function<void()> task,
               std::string label) {
            return scheduler_->schedule_oneshot(
                delay, std::move(task), std::move(label));
        };
    firewall_owner_callbacks.schedule_repeating =
        [this](std::chrono::milliseconds interval,
               std::function<void()> task,
               std::string label) {
            return scheduler_->schedule_repeating(
                interval, std::move(task), std::move(label));
        };
    firewall_owner_callbacks.cancel_scheduled =
        [this](int task_id) { scheduler_->cancel(task_id); };
    firewall_owner_callbacks.runtime_is_current =
        [this](std::uint64_t expected_generation,
               RuntimeFirewallLifecycleKind lifecycle_kind) {
            const bool current =
                runtime_firewall_lifecycle_generation_is_current(
                    lifecycle_kind, expected_generation);
            if (!current) {
                Logger::instance().verbose(
                    "Discarding stale runtime firewall recovery retry.");
            }
            return current;
        };
    firewall_owner_callbacks.urltest_waiting =
        [this](std::uint64_t generation) {
            return urltest_after_firewall_gate_.waiting_for(generation);
        };
    firewall_owner_callbacks.dispatch_attempt =
        [this](std::shared_ptr<RuntimeFirewallOperationContext> context,
               RuntimeFirewallOperationClaim claim,
               OwnedSnatRecovery recovery,
               PreparedNativeVpnCatalogPtr catalog,
               bool schedule_catalog_refresh) {
            dispatch_runtime_firewall_worker_attempt(
                context,
                claim,
                std::move(recovery),
                std::move(catalog),
                schedule_catalog_refresh);
        };
    firewall_owner_callbacks.drain_terminal =
        [this](std::shared_ptr<RuntimeFirewallOperationContext> context,
               bool shutdown) {
            drain_runtime_firewall_terminal(context, shutdown);
        };
    firewall_owner_callbacks.active_mutation_label = [this] {
        const auto active = runtime_mutation_admission_.active();
        return active.has_value()
            ? active->label
            : std::string{"unknown"};
    };
    runtime_firewall_owner_ =
        std::make_shared<RuntimeFirewallOperationOwner>(
            runtime_firewall_retry_,
            std::move(firewall_owner_callbacks));

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
    cleanup_step("cancel nfqws boot recovery", [this] {
        cancel_nfqws_boot_recovery();
        cancel_nfqws_retention_backfill();
    });
    cleanup_step("cancel remote-access recovery watchdog", [this] {
        cancel_remote_access_recovery_watchdog();
    });
    cleanup_step("reset remote-access retry bridge", [this] {
        reset_remote_access_retry_bridge();
    });
#endif
    cleanup_step("fence runtime firewall shutdown", [this] {
        runtime_firewall_owner_->request_shutdown();
    });
    cleanup_step("close runtime mutation admission", [this] {
        runtime_mutation_admission_.shutdown();
    });
    cleanup_step("cancel runtime firewall retry", [this] {
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->cancel_retry();
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
        runtime_firewall_owner_->cancel_pending_work();
        runtime_firewall_owner_->pump_terminal_for_shutdown();
        blocking_executor_.cancel_pending();
    });
    cleanup_step("drain resolver stream recovery", [this] {
        quiesce_resolver_stream_recovery();
    });
    cleanup_step("drain runtime mutations", [this] {
        quiesce_runtime_mutations();
    });
    cleanup_step("stop runtime firewall executor", [this] {
        runtime_firewall_owner_->shutdown_executor();
        runtime_firewall_owner_->pump_terminal_for_shutdown();
    });
    cleanup_step("retire runtime firewall owner", [this] {
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->cancel_retry();
        scheduler_->cancel_all();
        runtime_firewall_owner_->reset_active();
    });
    // Stop ingress while the eventfd wake target is still alive. Otherwise an
    // acceptor finishing a frame during teardown could write to a descriptor
    // which has already been closed and reused by another subsystem.
    cleanup_step("remove IPC control socket", [this] {
        remove_ipc_control_socket();
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

    ipc_accept_running_.store(true, std::memory_order_release);
    try {
        ipc_accept_thread_ =
            std::thread([this] { run_ipc_control_acceptor(); });
    } catch (...) {
        ipc_accept_running_.store(false, std::memory_order_release);
        remove_ipc_control_socket();
        throw;
    }
}

void Daemon::run_ipc_control_acceptor() noexcept {
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
        send_control_response_and_close(
            fd,
            {{"protocol_version", ipc::kControlProtocolVersion},
             {"request_id", nullptr},
             {"ok", false},
             {"error", {{"code", code}, {"message", message}}}});
    };

    while (ipc_accept_running_.load(std::memory_order_acquire)) {
        std::vector<pollfd> poll_fds;
        poll_fds.reserve(pending.size() + 1U);
        poll_fds.push_back({ipc_control_fd_, POLLIN, 0});
        for (const auto& client : pending) {
            poll_fds.push_back({client.fd, POLLIN, 0});
        }

        const int ready =
            ::poll(poll_fds.data(), poll_fds.size(), 100);
        if (ready < 0) {
            if (errno == EINTR) continue;
            if (ipc_accept_running_.load(std::memory_order_acquire)) {
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
            while (ipc_accept_running_.load(std::memory_order_acquire)) {
                const int client = ::accept4(
                    ipc_control_fd_,
                    nullptr,
                    nullptr,
                    SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (client < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    if (errno == EINTR) continue;
                    if (ipc_accept_running_.load(
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
                    KPBR_LOCK_GUARD(ipc_accepted_clients_mutex_);
                    completed_count = ipc_accepted_clients_.size();
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
                    throw ipc::ControlProtocolError(
                        "unable to verify control peer");
                }
                request = ipc::decode_message(frame);
                ipc::validate_request_envelope(request);

                const int flags = ::fcntl(fd, F_GETFL, 0);
                if (flags < 0 ||
                    ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
                    throw ipc::ControlProtocolError(
                        "unable to prepare control response socket");
                }
                timeval timeout{5, 0};
                if (::setsockopt(
                        fd,
                        SOL_SOCKET,
                        SO_SNDTIMEO,
                        &timeout,
                        sizeof(timeout)) != 0) {
                    throw ipc::ControlProtocolError(
                        "unable to bound control response socket");
                }

                bool queued = false;
                {
                    KPBR_LOCK_GUARD(ipc_accepted_clients_mutex_);
                    if (ipc_accept_running_.load(
                            std::memory_order_acquire) &&
                        ipc_accepted_clients_.size() <
                            kMaxPendingControlClients) {
                        ipc_accepted_clients_.push_back(
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
                    wake_control_loop();
                } catch (const std::exception& error) {
                    try {
                        Logger::instance().error(
                            "control socket wake failed: {}",
                            error.what());
                    } catch (...) {
                    }
                }
            } catch (const std::exception& error) {
                send_control_response_and_close(
                    fd,
                    ipc::make_error_response(
                        request, "protocol_error", error.what()));
            }
        }
    }

    for (const auto& client : pending) {
        ::close(client.fd);
    }
}

void Daemon::remove_ipc_control_socket() noexcept {
    ipc_accept_running_.store(false, std::memory_order_release);
    if (ipc_control_fd_ >= 0) {
        (void)::shutdown(ipc_control_fd_, SHUT_RDWR);
    }
    if (ipc_accept_thread_.joinable()) {
        ipc_accept_thread_.join();
    }
    if (ipc_control_fd_ >= 0) {
        ::close(ipc_control_fd_);
        ipc_control_fd_ = -1;
    }
    {
        KPBR_LOCK_GUARD(ipc_accepted_clients_mutex_);
        for (const auto& client : ipc_accepted_clients_) {
            ::close(client.fd);
        }
        ipc_accepted_clients_.clear();
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
        IpcControlRequest accepted;
        {
            KPBR_LOCK_GUARD(ipc_accepted_clients_mutex_);
            if (ipc_accepted_clients_.empty()) return;
            accepted = std::move(ipc_accepted_clients_.front());
            ipc_accepted_clients_.pop_front();
        }
        const int client = accepted.fd;
        nlohmann::json request = std::move(accepted.request);
        nlohmann::json response;
        bool stream_dispatched = false;
        try {
            ucred peer{};
            peer.pid = accepted.peer_pid;
            peer.uid = accepted.peer_uid;
            peer.gid = accepted.peer_gid;

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
                        routing_runtime_active(),
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
                        firewall_->raw_prerouting_mode(),
                        snapshot.firewall_state,
                        snapshot.route_specs,
                        snapshot.policy_rule_specs,
                        netlink_,
                        snapshot.routing_inventory_complete &&
                            snapshot.routing_kernel_state_known);
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
            send_control_response_and_close(client, response);
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
    runtime_firewall_owner_->pump_terminal_for_shutdown();
    auto next_warning = std::chrono::steady_clock::now() +
        std::chrono::seconds{5};
    while (!runtime_mutation_admission_.wait_for_idle_for(
        std::chrono::milliseconds{10})) {
        try {
            runtime_firewall_owner_->pump_terminal_for_shutdown();
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
            runtime_firewall_owner_->pump_terminal_for_shutdown();
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
    runtime_firewall_owner_->pump_terminal_for_shutdown();
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

    // Ingress frames are read and validated by the dedicated acceptor. Drain
    // them before unrelated deferred work so a ready CLI request is not left
    // behind a potentially expensive control callback.
    handle_ipc_control_socket();

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
        runtime_firewall_owner_->request_shutdown();
        runtime_mutation_admission_.shutdown();
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->cancel_retry();
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
            routing_runtime_active(),
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
        (void)refresh_iproute_and_firewall_runtime(
            0,
            {},
            /*schedule_catalog_refresh=*/false,
            runtime_firewall_retry_
                .pending_owned_snat_recovery(),
            RuntimeFirewallImmediateCompletionIntent::
                periodic_urltest(std::move(task_metrics)));
        return;
    }
    const bool owned_snat_recovery_without_timer =
        should_run_periodic_owned_snat_firewall_recovery(
            routing_runtime_active(),
            runtime_firewall_retry_.owned_snat_recovery_pending(),
            runtime_retry_pending,
            netfilter_refresh_pending);
    if (owned_snat_recovery_without_timer) {
        // A pre-claim transport rejection can leave the exact SNAT recovery
        // latched without a one-shot timer. This existing periodic owner is
        // the maintenance cadence after the bounded immediate chain ends.
        auto task_metrics =
            periodic_task_metrics_.begin("owned-snat-health");
        (void)refresh_iproute_and_firewall_runtime(
            0,
            {},
            /*schedule_catalog_refresh=*/false,
            runtime_firewall_retry_.pending_owned_snat_recovery(),
            RuntimeFirewallImmediateCompletionIntent::
                periodic_owned_firewall(std::move(task_metrics)));
        return;
    }
    const bool resolver_recovery_without_timer =
        should_run_periodic_resolver_reload_recovery(
            routing_runtime_active(),
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
    if (!routing_runtime_active() ||
        recovery_pending ||
        netfilter_refresh_pending) {
        periodic_task_metrics_.record_skipped(
            "owned-snat-health",
            !routing_runtime_active()
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
            routing_runtime_active(),
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
            routing_runtime_active(),
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
            routing_runtime_active(),
            recovery_pending,
            netfilter_refresh_pending,
            state);
    const bool repair_meta =
        should_run_periodic_forward_udp_reject_repair(
            routing_runtime_active(),
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
    (void)refresh_iproute_and_firewall_runtime(
        0,
        {},
        /*schedule_catalog_refresh=*/false,
        OwnedSnatRecovery{
            /*requested=*/repair_snat,
            /*missing_observed=*/false},
        RuntimeFirewallImmediateCompletionIntent::
            periodic_owned_firewall(std::move(task_metrics)));
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
        if (runtime_firewall_owner_->foreground_lifecycle_pending()) {
            // START/restart already owns the one exact writer lease. Retain
            // this firmware event behind that chain instead of cancelling its
            // timer or dropping the source merely because routing has not yet
            // reached active state.
            runtime_firewall_owner_->defer(
                /*attempt=*/0U,
                runtime_generation_.load(std::memory_order_acquire),
                {},
                /*schedule_catalog_refresh=*/true,
                OwnedSnatRecovery{
                    /*requested=*/snat_health_check,
                    /*missing_observed=*/false});
            Logger::instance().info(
                "Netfilter event: {} runtime refresh was retained behind "
                "the active lifecycle operation.",
                reason_label);
            return;
        }
        if (nat_refresh && runtime_firewall_retry_.retry_pending()) {
            // Do not coalesce away a confirmed firmware NAT rebuild behind an
            // older generic recovery. Replace that retry with an immediate
            // attempt whose bounded chain verifies SNAT health.
            runtime_firewall_owner_->cancel_retry();
        }
        const bool targeted_urltest_recovery_pending =
            urltest_after_firewall_gate_.waiting_for(
                runtime_generation_.load(std::memory_order_acquire));
        const auto runtime_refresh_disposition =
            refresh_iproute_and_firewall_runtime(
                0,
                {},
                /*schedule_catalog_refresh=*/true,
                OwnedSnatRecovery{
                    /*requested=*/snat_health_check,
                    /*missing_observed=*/false},
                RuntimeFirewallImmediateCompletionIntent::netfilter(
                    full_refresh,
                    targeted_urltest_recovery_pending));

        if (runtime_refresh_disposition ==
            RuntimeFirewallImmediateDisposition::rejected) {
            const bool runtime_active = routing_runtime_active();
            const bool owner_shutdown =
                runtime_firewall_owner_->shutdown_requested();
            pending_netfilter_refresh_reasons_ =
                retain_netfilter_refresh_reasons_after_immediate_disposition(
                    pending_netfilter_refresh_reasons_,
                    reasons,
                    runtime_refresh_disposition,
                    runtime_active,
                    owner_shutdown);
            if (runtime_active && !owner_shutdown) {
                // Re-arm the existing bounded debounce owner. This does not
                // re-send configuration inline and preserves both FULL and
                // NAT source bits from the same firmware burst.
                schedule_netfilter_runtime_refresh(
                    full_refresh ? NetfilterRefreshReason::full
                                 : NetfilterRefreshReason::nat_only);
                Logger::instance().info(
                    "Netfilter event: {} runtime refresh was not accepted; "
                    "the exact source event remains scheduled.",
                    reason_label);
            } else {
                Logger::instance().verbose(
                    "Netfilter event: {} runtime refresh was ignored because "
                    "routing is stopped or the firewall owner is shutting "
                    "down.",
                    reason_label);
            }
        } else if (runtime_refresh_disposition ==
                   RuntimeFirewallImmediateDisposition::handed_off) {
            Logger::instance().info(
                "Netfilter event: {} runtime refresh handed to the firewall "
                "worker.",
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
    const auto active = config_store_.pin_active_snapshot();
    return RoutingTestSnapshot{
        active->config,
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
        const auto rollback_snapshot =
            config_store_.pin_active_snapshot();
        const std::uint64_t expected_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const TraceId trace_id = ensure_trace_id();
        log.info("SIGHUP: scheduling full reload preparation...");
        const bool enqueued = blocking_executor_.try_post(
            "sighup-reload-prepare",
            [this,
             config_path,
             rollback_snapshot,
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
                            rollback_snapshot->config,
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

RuntimeFirewallImmediateDisposition
Daemon::refresh_iproute_and_firewall_runtime(
    std::size_t retry_attempt,
    PreparedNativeVpnCatalogPtr prepared_native_vpn_catalog,
    bool schedule_catalog_refresh,
    OwnedSnatRecovery snat_recovery,
    RuntimeFirewallImmediateCompletionIntent completion_intent) {
    std::shared_ptr<DaemonRuntimeFirewallOperationState> state;
    try {
        state = std::make_shared<DaemonRuntimeFirewallOperationState>();
    } catch (...) {
        (void)completion_intent.settle(
            RuntimeFirewallImmediateTerminalOutcome::not_verified);
        return RuntimeFirewallImmediateDisposition::rejected;
    }
    state->immediate_completion_intent = std::move(completion_intent);
    if (!routing_runtime_active()) {
        (void)state->immediate_completion_intent.settle(
            RuntimeFirewallImmediateTerminalOutcome::not_verified);
        return RuntimeFirewallImmediateDisposition::rejected;
    }

    const auto current_generation =
        runtime_generation_.load(std::memory_order_acquire);
    RuntimeFirewallImmediateDisposition disposition{
        RuntimeFirewallImmediateDisposition::rejected};
    try {
        disposition = runtime_firewall_owner_->start_immediate(
            retry_attempt,
            current_generation,
            std::move(snat_recovery),
            std::move(prepared_native_vpn_catalog),
            schedule_catalog_refresh,
            state);
    } catch (...) {
        (void)state->immediate_completion_intent.settle(
            RuntimeFirewallImmediateTerminalOutcome::not_verified);
        return RuntimeFirewallImmediateDisposition::rejected;
    }
    if (disposition !=
        RuntimeFirewallImmediateDisposition::handed_off) {
        // No operation context accepted this invocation. Preserve the former
        // synchronous false outcome locally; the intent must never attach to
        // the active/trailing operation or one of its successors.
        (void)state->immediate_completion_intent.settle(
            RuntimeFirewallImmediateTerminalOutcome::not_verified);
    }
    return disposition;
}

bool Daemon::runtime_firewall_lifecycle_generation_is_current(
    RuntimeFirewallLifecycleKind lifecycle_kind,
    std::uint64_t expected_generation) const noexcept {
    bool active = false;
    try {
        active = routing_runtime_active();
    } catch (...) {
        // This predicate is called from coordinator/watchdog noexcept
        // boundaries. A failed state-store lock is never evidence that a
        // generation is current.
        return false;
    }
    const bool exact_start_in_progress =
        runtime_firewall_lifecycle_is_start(lifecycle_kind) &&
        !active &&
        runtime_state_machine_.state() == RuntimeState::starting;
    return (active || exact_start_in_progress) &&
           expected_generation ==
               runtime_generation_.load(std::memory_order_acquire);
}

#ifdef WITH_API
void Daemon::begin_preowned_runtime_firewall_start(
    std::unique_ptr<RuntimeMutationAdmission::Lease> mutation_lease,
    RuntimeFirewallLifecycleCompletion::Source completion) {
    auto rejection_source = completion;
    const auto settle_rejection = [&rejection_source](
        std::string_view detail) noexcept {
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = false;
        terminal.commit_ambiguous = false;
        try {
            terminal.detail.assign(detail.data(), detail.size());
        } catch (...) {
        }
        (void)rejection_source.settle(std::move(terminal));
    };

    if (!mutation_lease || !static_cast<bool>(*mutation_lease) ||
        !runtime_mutation_admission_.owns(*mutation_lease)) {
        mutation_lease.reset();
        settle_rejection(
            "runtime start did not receive its exact mutation lease");
        throw DaemonError(
            "Runtime start lost its mutation admission before owner handoff");
    }
    if (routing_runtime_active()) {
        mutation_lease.reset();
        settle_rejection("routing runtime is already active");
        throw DaemonError("Routing runtime is already started");
    }

    // This is the only Keenetic DNS preflight for START. It is deliberately
    // cache-only and happens before state publication or any kernel mutation.
    KeeneticDnsCacheView prepared_keenetic_dns;
    try {
        prepared_keenetic_dns = prepare_keenetic_dns_view(
            config_, /*allow_refresh=*/false);
    } catch (const std::exception& error) {
        mutation_lease.reset();
        settle_rejection(error.what());
        throw;
    } catch (...) {
        mutation_lease.reset();
        settle_rejection("cache-only Keenetic DNS preparation failed");
        throw;
    }

    auto previous_keenetic_dns = active_keenetic_dns_;
    auto previous_urltest_selections =
        firewall_state_.get_urltest_selections();
    auto state = std::make_shared<DaemonRuntimeFirewallOperationState>();
    bool start_state_published = false;
    bool start_inputs_installed = false;

    const auto fail_before_handoff = [
        this,
        &previous_keenetic_dns,
        &previous_urltest_selections,
        &start_state_published,
        &start_inputs_installed,
        &mutation_lease,
        &settle_rejection](std::string_view detail) noexcept {
        if (start_inputs_installed) {
            try {
                using std::swap;
                swap(active_keenetic_dns_, previous_keenetic_dns);
            } catch (...) {
            }
            try {
                firewall_state_.swap_urltest_selections(
                    previous_urltest_selections);
            } catch (...) {
            }
            if (urltest_manager_) {
                try {
                    urltest_manager_->clear();
                } catch (...) {
                }
            }
        }
        try {
            cancel_idle_stall_observer();
        } catch (...) {
        }
        try {
            cancel_owned_snat_health_check();
        } catch (...) {
        }
        try {
            runtime_state_store_.set_routing_runtime_active(false);
        } catch (...) {
        }
        if (start_state_published) {
            try {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    "runtime start owner handoff failed");
                publish_runtime_state();
            } catch (...) {
            }
        }
        // Release exact mutation admission before waking the API waiter. All
        // operations above are catch-all guarded, so settlement cannot be
        // skipped by an ancillary cleanup failure.
        mutation_lease.reset();
        settle_rejection(detail);
    };

    RuntimeFirewallOperationOwner::PreownedImmediateStartResult result;
    try {
        cancel_idle_stall_observer();
        cancel_meta_udp443_activation_cleanup();
        cancel_owned_snat_health_check();
        cancel_owned_conntrack_cleanup_retry();
        cancel_resolver_reload_retry();
        urltest_after_firewall_gate_.reset();
        runtime_firewall_owner_->cancel_retry();
        runtime_firewall_retry_.clear_owned_snat_recovery();

        transition_runtime_or_throw(
            RuntimeState::starting, "runtime start requested");
        // The state machine has already changed even when publication throws;
        // the pre-handoff failure path must therefore move it to broken.
        start_state_published = true;
        publish_runtime_state();

        const auto generation =
            runtime_generation_.fetch_add(
                1U, std::memory_order_acq_rel) + 1U;
        active_keenetic_dns_ = std::move(prepared_keenetic_dns);
        start_inputs_installed = true;
        normalize_urltest_selections();
        register_urltest_outbounds();

        result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            generation,
            {},
            {},
            /*schedule_catalog_refresh=*/false,
            state,
            runtime_mutation_admission_,
            std::move(mutation_lease),
            std::move(completion),
            RuntimeFirewallLifecycleKind::start_from_stopped);
    } catch (const std::exception& error) {
        fail_before_handoff(error.what());
        throw;
    } catch (...) {
        fail_before_handoff(
            "runtime firewall owner rejected start during handoff");
        throw;
    }

    if (result.disposition !=
        RuntimeFirewallImmediateDisposition::handed_off) {
        fail_before_handoff(
            "runtime firewall owner already has an exact operation");
        throw DaemonError(
            "Runtime start was not admitted by the firewall owner");
    }

    rejection_source = {};
    try {
        Logger::instance().info(
            "Runtime start handed to the asynchronous firewall owner.");
    } catch (...) {
    }
}

void Daemon::begin_preowned_runtime_firewall_restart(
    std::unique_ptr<RuntimeMutationAdmission::Lease> mutation_lease,
    RuntimeFirewallLifecycleCompletion::Source completion) {
    auto rejection_source = completion;
    const auto settle_rejection = [&rejection_source](
        std::string_view detail) noexcept {
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = false;
        terminal.commit_ambiguous = false;
        try {
            terminal.detail.assign(detail.data(), detail.size());
        } catch (...) {
        }
        (void)rejection_source.settle(std::move(terminal));
    };

    if (!mutation_lease || !static_cast<bool>(*mutation_lease) ||
        !runtime_mutation_admission_.owns(*mutation_lease)) {
        mutation_lease.reset();
        settle_rejection(
            "runtime restart did not receive its exact mutation lease");
        throw DaemonError(
            "Runtime restart lost its mutation admission before owner handoff");
    }
    if (!routing_runtime_active()) {
        mutation_lease.reset();
        settle_rejection("routing runtime is stopped");
        throw DaemonError("Routing runtime is stopped");
    }

    // A timer-only background retry owns no mutation lease. Retire that timer
    // before the foreground operation is admitted, while preserving the
    // coordinator's exact pending SNAT recovery payload for this attempt.
    OwnedSnatRecovery pending_snat_recovery;
    std::shared_ptr<DaemonRuntimeFirewallOperationState> state;
    try {
        pending_snat_recovery =
            runtime_firewall_retry_.pending_owned_snat_recovery();
        runtime_firewall_owner_->cancel_retry();
        state =
            std::make_shared<DaemonRuntimeFirewallOperationState>();
    } catch (const std::exception& error) {
        mutation_lease.reset();
        settle_rejection(error.what());
        throw;
    } catch (...) {
        mutation_lease.reset();
        settle_rejection(
            "runtime restart preparation failed before owner handoff");
        throw;
    }

    RuntimeFirewallOperationOwner::PreownedImmediateStartResult result;
    try {
        result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            runtime_generation_.load(std::memory_order_acquire),
            pending_snat_recovery,
            {},
            /*schedule_catalog_refresh=*/true,
            state,
            runtime_mutation_admission_,
            std::move(mutation_lease),
            std::move(completion),
            RuntimeFirewallLifecycleKind::restart_active);
    } catch (...) {
        result.unaccepted_lease.reset();
        mutation_lease.reset();
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = false;
        terminal.commit_ambiguous = false;
        try {
            terminal.detail =
                "runtime firewall owner rejected restart during handoff";
        } catch (...) {
        }
        (void)rejection_source.settle(std::move(terminal));
        throw;
    }

    if (result.disposition !=
        RuntimeFirewallImmediateDisposition::handed_off) {
        // Destroying the exact returned lease below releases admission. The
        // copied source publishes a precise terminal instead of relying on
        // the conservative source-abandonment fallback.
        result.unaccepted_lease.reset();
        mutation_lease.reset();
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = false;
        terminal.commit_ambiguous = false;
        try {
            terminal.detail =
                "runtime firewall owner already has an exact operation";
        } catch (...) {
        }
        (void)rejection_source.settle(std::move(terminal));
        throw DaemonError(
            "Runtime restart was not admitted by the firewall owner");
    }

    // The owner now carries both the physical lease and completion source.
    // Release this extra producer and leave the control loop immediately.
    rejection_source = {};
    try {
        cancel_resolver_reload_retry();
    } catch (...) {
        // The accepted owner remains authoritative. Its resolver tail will
        // observe any still-running stream and schedule a fresh retry.
    }
    try {
        Logger::instance().info(
            "Runtime restart handed to the asynchronous firewall owner.");
    } catch (...) {
    }
}
#endif

void Daemon::dispatch_runtime_firewall_worker_attempt(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context,
    RuntimeFirewallOperationClaim queued_claim,
    OwnedSnatRecovery snat_recovery_input,
    PreparedNativeVpnCatalogPtr prepared_native_vpn_catalog,
    bool schedule_catalog_refresh) {
    if (!context || !runtime_firewall_owner_->is_active(context)) {
        runtime_firewall_owner_->terminate_before_worker(
            context,
            queued_claim,
            RuntimeFirewallOperationContext::SuccessorMode::
                defer_same_attempt,
            /*force_rerun=*/true);
        return;
    }
    auto& state = runtime_firewall_domain_state(context);

    context->queued_claim = queued_claim;
    context->submitted_snat_recovery = std::move(snat_recovery_input);
    auto& snat_recovery = context->submitted_snat_recovery;
    context->prepared_native_vpn_catalog =
        prepared_native_vpn_catalog;
    context->schedule_catalog_refresh = schedule_catalog_refresh;
    context->successor_attempt = queued_claim.attempt;
    context->successor_runtime_generation =
        queued_claim.runtime_generation;
    context->successor_schedule_catalog_refresh =
        schedule_catalog_refresh;
    // Until the worker publishes and control proves success, every
    // pre-worker loss keeps the exact attempt. This also covers executor
    // rejection, whose queue envelope owns the sole terminalization.
    context->successor_mode =
        RuntimeFirewallOperationContext::SuccessorMode::
            defer_same_attempt;
    // Arm before any fallible preparation. Admission contention, input
    // allocation and executor rejection all publish a durable pre-worker
    // terminal and need the same independent drain fallback.
    if (!runtime_firewall_owner_->arm_completion_watchdog(context)) {
        runtime_firewall_owner_->terminate_before_worker(
            context,
            queued_claim,
            RuntimeFirewallOperationContext::SuccessorMode::
                defer_same_attempt,
            /*force_rerun=*/true);
        // No asynchronous fallback exists when watchdog registration fails.
        // We are still on the control loop and no worker has been queued, so
        // consume the exact coordinator terminal synchronously.
        drain_runtime_firewall_terminal(context, /*shutdown=*/false);
        return;
    }

    const auto terminalize_before_worker = [this, &context, queued_claim](
        RuntimeFirewallOperationContext::SuccessorMode successor_mode,
        bool force_rerun) {
        runtime_firewall_owner_->terminate_before_worker(
            context, queued_claim, successor_mode, force_rerun);
    };

    if (!runtime_firewall_lifecycle_generation_is_current(
            context->lifecycle_kind,
            queued_claim.runtime_generation)) {
        terminalize_before_worker(
            RuntimeFirewallOperationContext::SuccessorMode::none,
            /*force_rerun=*/false);
        return;
    }

    std::optional<RuntimeMutationAdmission::Lease> mutation_lease;
    if (!context->retained_mutation_lease) {
        try {
            mutation_lease = runtime_mutation_admission_.try_acquire(
                "runtime-firewall-worker");
        } catch (const std::exception& error) {
        state.preworker_failure_kind =
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                preparation_failure;
        try {
            state.preworker_failure_detail = error.what();
        } catch (...) {
            state.preworker_failure_detail =
                "runtime mutation admission failed";
        }
        const bool retry_required =
            runtime_firewall_preworker_retry_required(
                snat_recovery.requested,
                config_has_native_vpn_catalog_policy(config_),
                urltest_after_firewall_gate_.waiting_for(
                    queued_claim.runtime_generation),
                queued_claim.attempt,
                RUNTIME_FIREWALL_RETRY_DELAYS.size());
        state.suppress_coordinator_rerun = !retry_required;
        terminalize_before_worker(
            retry_required
                ? RuntimeFirewallOperationContext::SuccessorMode::
                      reschedule_retry
                : RuntimeFirewallOperationContext::SuccessorMode::none,
            /*force_rerun=*/retry_required);
            return;
        } catch (...) {
        state.preworker_failure_kind =
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                preparation_failure;
        try {
            state.preworker_failure_detail =
                "runtime mutation admission failed with an unknown error";
        } catch (...) {
        }
        const bool retry_required =
            runtime_firewall_preworker_retry_required(
                snat_recovery.requested,
                config_has_native_vpn_catalog_policy(config_),
                urltest_after_firewall_gate_.waiting_for(
                    queued_claim.runtime_generation),
                queued_claim.attempt,
                RUNTIME_FIREWALL_RETRY_DELAYS.size());
        state.suppress_coordinator_rerun = !retry_required;
        terminalize_before_worker(
            retry_required
                ? RuntimeFirewallOperationContext::SuccessorMode::
                      reschedule_retry
                : RuntimeFirewallOperationContext::SuccessorMode::none,
            /*force_rerun=*/retry_required);
            return;
        }
        if (!mutation_lease.has_value()) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    admission_contention;
            state.preworker_failure_detail =
                "runtime mutation admission is busy";
            terminalize_before_worker(
                RuntimeFirewallOperationContext::SuccessorMode::
                    defer_same_attempt,
                /*force_rerun=*/true);
            return;
        }
    }

    try {
        const bool lifecycle_start =
            runtime_firewall_lifecycle_is_start(
                context->lifecycle_kind);
        state.internal_vpn_resolution =
            prepared_native_vpn_catalog
            ? prepared_native_vpn_catalog->interface_resolution
            : prepare_internal_vpn_server_resolution_from_cache();
        state.internal_vpn_service_resolution =
            prepared_native_vpn_catalog
            ? prepared_native_vpn_catalog->service_resolution
            : prepare_internal_vpn_service_resolution_from_cache();
        if (prepared_native_vpn_catalog) {
            context->schedule_catalog_refresh =
                prepared_native_vpn_catalog->schedule_catalog_refresh;
            context->successor_schedule_catalog_refresh =
                context->schedule_catalog_refresh;
        }
        if (context->schedule_catalog_refresh) {
            schedule_internal_vpn_catalog_refresh_if_needed(
                state.internal_vpn_resolution.state,
                state.internal_vpn_service_resolution.state);
        }

        state.lifecycle_trusted_dns_interfaces =
            build_dnsmasq_trusted_interfaces(
                state.internal_vpn_resolution.effective_servers,
                state.internal_vpn_service_resolution.effective_targets);
        const auto& next_resolver_access_policy =
            state.lifecycle_trusted_dns_interfaces;
        const auto current_resolver_access_policy =
            resolver_generation_snapshot_
            ? resolver_generation_snapshot_->trusted_dns_interfaces
            : build_dnsmasq_trusted_interfaces(
                  resolved_internal_vpn_servers_,
                  resolved_internal_vpn_service_targets_);
        state.resolver_refresh_required =
            runtime_firewall_lifecycle_is_foreground(
                context->lifecycle_kind) ||
            current_resolver_access_policy != next_resolver_access_policy ||
            !resolver_generation_snapshot_ ||
            !resolver_generation_snapshot_->list_cache_snapshot;
        if (lifecycle_start) {
            // START activates the already-pinned resolver/list generation.
            // Requiring activation is not authority to advance remote bodies.
            state.list_cache_snapshot =
                resolver_generation_snapshot_ &&
                        resolver_generation_snapshot_->list_cache_snapshot
                    ? resolver_generation_snapshot_->list_cache_snapshot
                    : capture_relevant_list_cache_generation(config_);
        } else {
            state.list_cache_snapshot = state.resolver_refresh_required
                ? capture_relevant_list_cache_generation(config_)
                : resolver_generation_snapshot_->list_cache_snapshot;
        }

        RuntimeFirewallWorkerAttemptInput worker_input;
        auto& transaction = worker_input.transaction;
        transaction.operation_serial = queued_claim.serial;
        transaction.runtime_generation = queued_claim.runtime_generation;
        transaction.config = config_;
        transaction.outbound_marks = outbound_marks_;
        transaction.urltest_selections =
            firewall_state_.get_urltest_selections();
        transaction.effective_internal_vpn_servers =
            state.internal_vpn_resolution.effective_servers;
        transaction.effective_internal_vpn_targets =
            internal_vpn_interface_runtime_targets(
                transaction.effective_internal_vpn_servers);
        transaction.effective_internal_vpn_targets.insert(
            transaction.effective_internal_vpn_targets.end(),
            state.internal_vpn_service_resolution.effective_targets.begin(),
            state.internal_vpn_service_resolution.effective_targets.end());
        transaction.candidate_native_vpn_direct_egress_snat_selectors =
            select_native_vpn_direct_egress_snat_selectors(
                transaction.effective_internal_vpn_targets);
        transaction.committed_meta_udp443_fwmark =
            committed_meta_udp443_fwmark_;
        transaction.committed_meta_udp443_owned_mask =
            committed_meta_udp443_owned_mask_;
        transaction.list_max_file_size_bytes =
            max_file_size_bytes(config_);
        transaction.list_cache_snapshot = state.list_cache_snapshot;
        transaction.requested_list_fingerprints =
            state.list_cache_snapshot
            ? state.list_cache_snapshot->fingerprints()
            : std::map<std::string, std::string>{};
        transaction.requested_mode =
            runtime_firewall_lifecycle_is_foreground(
                context->lifecycle_kind)
            ? FirewallApplyMode::PreserveSets
            : runtime_refresh_firewall_mode();
        transaction.udp_call_affinity_ipset_available =
            opts_.udp_call_affinity_ipset_available;
        transaction.keenetic_dns_snapshot = active_keenetic_dns_.snapshot;
        transaction.previous_rules = firewall_state_.get_rules();
        transaction.previous_list_usage = applied_list_usage_;
        transaction.previous_list_content_state =
            applied_list_content_state_;
        transaction.previous_list_fingerprints =
            applied_list_fingerprints_;
        transaction.previous_native_vpn_direct_egress_snat_selectors =
            applied_native_vpn_direct_egress_snat_selectors_;

        worker_input.route_health_request.operation_serial =
            queued_claim.serial;
        worker_input.route_health_request.runtime_generation =
            queued_claim.runtime_generation;
        worker_input.route_health_request.route_epoch =
            routing_observation_epoch_.load(std::memory_order_acquire);
        worker_input.route_health_request.config = transaction.config;
        worker_input.route_health_request.outbound_marks =
            transaction.outbound_marks;
        worker_input.route_health_request.urltest_selections =
            transaction.urltest_selections;
        worker_input.route_reconcile_mode =
            runtime_firewall_lifecycle_is_foreground(
                context->lifecycle_kind)
            ? RouteReconcileMode::Strict
            : RouteReconcileMode::DeferredRepair;
        worker_input.route_mutation_checkpoint =
            std::make_shared<RuntimeRouteMutationCheckpoint>();
        state.route_mutation_checkpoint =
            worker_input.route_mutation_checkpoint;

        std::weak_ptr<RuntimeFirewallOperationContext> weak_context{
            context};
        context->pump_worker_checkpoint = [this, weak_context]() noexcept {
            const auto retained = weak_context.lock();
            if (!retained) return;
            pump_runtime_route_health_checkpoint(retained);
        };
        const auto route_mutation_checkpoint =
            worker_input.route_mutation_checkpoint;
        context->cancel_worker_checkpoint =
            [route_mutation_checkpoint]() noexcept {
                (void)route_mutation_checkpoint->cancel();
            };

        const auto route_config = config_.route.value_or(RouteConfig{});
        const bool has_explicit_inbound_scope =
            route_config.inbound_interfaces.has_value() &&
            !route_config.inbound_interfaces->empty();
        const bool has_native_vpn_bypass = std::any_of(
            transaction.effective_internal_vpn_servers.begin(),
            transaction.effective_internal_vpn_servers.end(),
            [](const InternalVpnServer& server) {
                return !server.process_clients;
            }) || std::any_of(
            transaction.effective_internal_vpn_targets.begin(),
            transaction.effective_internal_vpn_targets.end(),
            [](const InternalVpnRuntimeTarget& target) {
                return !target.process_clients;
            });
        transaction.forwarded_scope_allows_unmarked_cleanup =
            !has_explicit_inbound_scope && !has_native_vpn_bypass;

        worker_input.inspect_owned_snat = snat_recovery.requested;
        if (worker_input.inspect_owned_snat) {
            worker_input.pre_mutation_owned_conntrack_cleanup_snapshot =
                snapshot_owned_conntrack_marks();
        }
        worker_input.cleanup_owned_conntrack_after_commit =
            lifecycle_start;

        if (!lifecycle_start) {
            state.previous_meta_cleanup = pending_meta_udp443_cleanup_;
        }
        cancel_idle_stall_observer();
        cancel_meta_udp443_activation_cleanup();
        if (!lifecycle_start) {
            state.preworker_side_effects_armed = true;
        }
        state.meta_cleanup_epoch = meta_udp443_cleanup_epoch_.load(
            std::memory_order_acquire);

        auto worker_input_snapshot =
            std::make_shared<const RuntimeFirewallWorkerAttemptInput>(
                std::move(worker_input));
        std::unique_ptr<RuntimeMutationAdmission::Lease> lease_owner;
        if (mutation_lease.has_value()) {
            lease_owner =
                std::make_unique<RuntimeMutationAdmission::Lease>(
                    std::move(*mutation_lease));
        }
        state.preworker_failure_kind =
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                transport_rejected;
        state.preworker_failure_detail =
            "runtime firewall worker queue rejected the exact attempt";
        RuntimeFirewallOperationOwner::WorkerRunner worker_runner{
            [this](
                const RuntimeFirewallWorkerAttemptInput& input,
                const RuntimeFirewallDelayedWorker::RunningClaim&)
                -> RuntimeFirewallWorkerAttemptResultPtr {
                SystemRuntimeRouteHealthServices route_health_services{
                    netlink_};
                return
                    execute_runtime_firewall_worker_attempt_durable_with_route_preparation(
                    input,
                    route_health_services,
                    [this, &input](const RuntimeRouteHealthPlan& plan,
                                   RouteReconcileMode reconcile_mode) {
                        RuntimeRouteWorkerMutationResult result;
                        const auto exact_worker_input =
                            plan.operation_serial ==
                                input.route_health_request.operation_serial &&
                            plan.runtime_generation ==
                                input.route_health_request.runtime_generation &&
                            plan.route_epoch ==
                                input.route_health_request.route_epoch &&
                            plan.operation_serial ==
                                input.transaction.operation_serial &&
                            plan.runtime_generation ==
                                input.transaction.runtime_generation;
                        const auto current_generation =
                            runtime_generation_.load(
                                std::memory_order_acquire);
                        const auto current_route_epoch =
                            routing_observation_epoch_.load(
                                std::memory_order_acquire);
                        if (runtime_firewall_owner_->shutdown_requested()) {
                            result.ack = RuntimeRouteMutationAck::shutdown;
                            return result;
                        }
                        if (!exact_worker_input ||
                            current_generation != plan.runtime_generation ||
                            current_route_epoch != plan.route_epoch) {
                            result.ack = RuntimeRouteMutationAck::stale;
                            return result;
                        }

                        try {
                            // This is the production off-loop routing write.
                            // The combined owner serializes both manager
                            // ledgers; no Daemon RouteTable/PolicyRuleManager
                            // escape remains.
                            const auto inventory =
                                routing_operation_owner_.
                                    reconcile_compatibility_generation(
                                    plan.routing.routes,
                                    plan.routing.rules,
                                    reconcile_mode,
                                    [this, &plan]() {
                                        return !runtime_firewall_owner_
                                                    ->shutdown_requested() &&
                                            runtime_generation_.load(
                                                std::memory_order_acquire) ==
                                                plan.runtime_generation &&
                                            routing_observation_epoch_.load(
                                                std::memory_order_acquire) ==
                                                plan.route_epoch;
                                    });
                            if (!inventory) {
                                result.ack = runtime_firewall_owner_
                                                     ->shutdown_requested()
                                    ? RuntimeRouteMutationAck::shutdown
                                    : RuntimeRouteMutationAck::stale;
                                return result;
                            }
                            if (classify_runtime_routing_inventory(inventory) !=
                                RuntimeRoutingInventoryAuthority::
                                    authoritative) {
                                // A conservative preimage or an unknown
                                // delete effect is not sufficient admission
                                // evidence for the firewall generation. The
                                // typed stale result keeps one coalesced retry
                                // and never replays the route body itself.
                                result.ack = RuntimeRouteMutationAck::stale;
                                try {
                                    result.failure_detail =
                                        "runtime routing inventory requires "
                                        "a fresh authoritative "
                                        "reconciliation";
                                } catch (...) {
                                }
                                return result;
                            }
                            if (runtime_firewall_owner_
                                    ->shutdown_requested()) {
                                result.ack =
                                    RuntimeRouteMutationAck::shutdown;
                            } else if (
                                runtime_generation_.load(
                                    std::memory_order_acquire) !=
                                    plan.runtime_generation ||
                                routing_observation_epoch_.load(
                                    std::memory_order_acquire) !=
                                    plan.route_epoch) {
                                result.ack =
                                    RuntimeRouteMutationAck::stale;
                            } else {
                                result.ack =
                                    RuntimeRouteMutationAck::applied;
                            }
                        } catch (const std::bad_alloc&) {
                            result.ack = RuntimeRouteMutationAck::stale;
                            try {
                                result.failure_detail =
                                    "runtime route mutation could not "
                                    "allocate its terminal evidence";
                            } catch (...) {
                            }
                        } catch (const RouteInterfaceUnavailableError& error) {
                            result.ack =
                                RuntimeRouteMutationAck::route_unavailable;
                            try {
                                result.failure_detail = error.what();
                            } catch (...) {
                            }
                        } catch (const std::exception& error) {
                            result.ack =
                                classify_runtime_routing_inventory(
                                    routing_operation_owner_.snapshot()) ==
                                        RuntimeRoutingInventoryAuthority::
                                            authoritative
                                ? RuntimeRouteMutationAck::mutation_failed
                                : RuntimeRouteMutationAck::stale;
                            try {
                                result.failure_detail = error.what();
                            } catch (...) {
                            }
                        } catch (...) {
                            result.ack =
                                classify_runtime_routing_inventory(
                                    routing_operation_owner_.snapshot()) ==
                                        RuntimeRoutingInventoryAuthority::
                                            authoritative
                                ? RuntimeRouteMutationAck::mutation_failed
                                : RuntimeRouteMutationAck::stale;
                            try {
                                result.failure_detail =
                                    "runtime route mutation failed with an "
                                    "unknown error";
                            } catch (...) {
                            }
                        }
                        return result;
                    },
                    [this, &input]() {
                        // Route observation, mutation and the control-only
                        // publication rendezvous have already completed.
                        // Hold this lock only for firewall/conntrack.
                        KPBR_UNIQUE_LOCK(
                            affinity_mutation_lock,
                            udp_call_affinity_mutation_mutex_);
                        return execute_runtime_firewall_worker_attempt(
                            input,
                            *firewall_,
                            conntrack_manager_,
                            netlink_);
                    });
            }};
        const bool enqueued = context->retained_mutation_lease
            ? runtime_firewall_owner_->enqueue_worker_with_retained_lease(
                  context,
                  queued_claim,
                  std::move(worker_input_snapshot),
                  std::move(worker_runner))
            : runtime_firewall_owner_->enqueue_worker(
                  context,
                  queued_claim,
                  std::move(worker_input_snapshot),
                  std::move(lease_owner),
                  std::move(worker_runner));
        if (enqueued) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    none;
            state.preworker_failure_detail.clear();
        }
        // On rejection the destroyed queue envelope publishes the exact
        // queued_abandoned terminal and returns the mutation lease. Do not
        // manufacture a second terminal here.
    } catch (const RouteInterfaceUnavailableError& error) {
        state.preworker_failure_kind =
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                route_unavailable;
        try {
            state.preworker_failure_detail = error.what();
        } catch (...) {
            state.preworker_failure_detail =
                "runtime route interface is unavailable";
        }
        const bool retry_required =
            snat_recovery.requested ||
            urltest_after_firewall_gate_.waiting_for(
                queued_claim.runtime_generation);
        terminalize_before_worker(
            retry_required
                ? RuntimeFirewallOperationContext::SuccessorMode::
                      reschedule_retry
                : RuntimeFirewallOperationContext::SuccessorMode::none,
            /*force_rerun=*/retry_required);
    } catch (const std::exception& error) {
        const bool transport_rejected =
            state.preworker_failure_kind ==
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                transport_rejected;
        if (!transport_rejected) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
        }
        try {
            state.preworker_failure_detail = error.what();
        } catch (...) {
            state.preworker_failure_detail =
                "runtime firewall input preparation failed";
        }
        if (context->worker_operation) {
            context->worker_operation.reset();
        } else {
            const bool retry_required = transport_rejected ||
                (!runtime_firewall_lifecycle_is_start(
                     context->lifecycle_kind) &&
                 runtime_firewall_preworker_retry_required(
                    snat_recovery.requested,
                    config_has_native_vpn_catalog_policy(config_),
                    urltest_after_firewall_gate_.waiting_for(
                        queued_claim.runtime_generation),
                    queued_claim.attempt,
                    RUNTIME_FIREWALL_RETRY_DELAYS.size()));
            if (!transport_rejected) {
                state.suppress_coordinator_rerun = !retry_required;
            }
            terminalize_before_worker(
                transport_rejected
                    ? RuntimeFirewallOperationContext::SuccessorMode::
                          defer_same_attempt
                    : (retry_required
                           ? RuntimeFirewallOperationContext::SuccessorMode::
                                 reschedule_retry
                           : RuntimeFirewallOperationContext::SuccessorMode::
                                 none),
                /*force_rerun=*/retry_required);
        }
    } catch (...) {
        const bool transport_rejected =
            state.preworker_failure_kind ==
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                transport_rejected;
        if (!transport_rejected) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            try {
                state.preworker_failure_detail =
                    "runtime firewall input preparation failed with an "
                    "unknown error";
            } catch (...) {
            }
        }
        if (context->worker_operation) {
            // If no queue envelope was made, Operation destruction performs
            // the only exact queued-claim terminalization. If an envelope was
            // already made, its shared state owns the same one-shot action.
            context->worker_operation.reset();
        } else {
            const bool retry_required = transport_rejected ||
                (!runtime_firewall_lifecycle_is_start(
                     context->lifecycle_kind) &&
                 runtime_firewall_preworker_retry_required(
                    snat_recovery.requested,
                    config_has_native_vpn_catalog_policy(config_),
                    urltest_after_firewall_gate_.waiting_for(
                        queued_claim.runtime_generation),
                    queued_claim.attempt,
                    RUNTIME_FIREWALL_RETRY_DELAYS.size()));
            if (!transport_rejected) {
                state.suppress_coordinator_rerun = !retry_required;
            }
            terminalize_before_worker(
                transport_rejected
                    ? RuntimeFirewallOperationContext::SuccessorMode::
                          defer_same_attempt
                    : (retry_required
                           ? RuntimeFirewallOperationContext::SuccessorMode::
                                 reschedule_retry
                           : RuntimeFirewallOperationContext::SuccessorMode::
                                 none),
                /*force_rerun=*/retry_required);
        }
        try {
            Logger::instance().error(
                "Runtime firewall worker input could not be queued; the "
                "exact attempt will be deferred without consuming retry "
                "budget.");
        } catch (...) {
        }
    }
}

void Daemon::pump_runtime_route_health_checkpoint(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context)
    noexcept {
    if (!context || !runtime_firewall_owner_->is_active(context)) return;
    // The pump is a watchdog/shutdown seam and is declared noexcept. Avoid
    // the throwing domain-state accessor even though every production
    // context is created with this exact state type.
    if (!context->domain_state) return;
    auto& state = static_cast<DaemonRuntimeFirewallOperationState&>(
        *context->domain_state);
    const auto checkpoint = state.route_mutation_checkpoint;
    if (!checkpoint ||
        checkpoint->state() !=
            RuntimeRouteMutationCheckpointState::plan_ready) {
        return;
    }

    auto claim = checkpoint->try_claim_control();
    if (!claim.has_value()) return;
    const auto plan = claim->plan();
    if (!plan) {
        (void)claim->acknowledge(
            RuntimeRouteMutationAck::mutation_failed);
        return;
    }

    const bool shutting_down =
        runtime_firewall_owner_->shutdown_requested() ||
        !runtime_firewall_lifecycle_generation_is_current(
            context->lifecycle_kind,
            plan->runtime_generation);
    if (shutting_down) {
        (void)claim->acknowledge(RuntimeRouteMutationAck::shutdown);
        return;
    }

    const bool exact_context =
        context->queued_claim.serial == plan->operation_serial &&
        context->queued_claim.runtime_generation ==
            plan->runtime_generation &&
        plan->runtime_generation ==
            runtime_generation_.load(std::memory_order_acquire) &&
        plan->route_epoch ==
            routing_observation_epoch_.load(std::memory_order_acquire) &&
        context->worker_input &&
        context->worker_input->route_health_request.operation_serial ==
            plan->operation_serial &&
        context->worker_input->route_health_request.runtime_generation ==
            plan->runtime_generation &&
        context->worker_input->route_health_request.route_epoch ==
            plan->route_epoch;
    if (!exact_context) {
        (void)claim->acknowledge(RuntimeRouteMutationAck::stale);
        return;
    }

    // The route/rule mutation already completed in the worker and released
    // the combined owner. This control boundary only revalidates the exact
    // context, publishes its observation metadata and lets firewall proceed.
    try {
        log_ipv6_support_decision_once(plan->ipv6_decision);
    } catch (...) {
    }
    (void)claim->acknowledge(RuntimeRouteMutationAck::applied);
}

void Daemon::trigger_broad_urltest_probe_noexcept() noexcept {
    if (!urltest_manager_) return;
    try {
        Logger::instance().info(
            "Netfilter event: probing urltest endpoints after verified "
            "firewall publication...");
    } catch (...) {
    }
    if (!config_.outbounds.has_value()) return;
    for (const auto& outbound : *config_.outbounds) {
        if (outbound.type != OutboundType::URLTEST) continue;
        try {
            urltest_manager_->trigger_immediate_test(outbound.tag);
        } catch (const std::exception& error) {
            try {
                Logger::instance().info(
                    "Netfilter event: urltest '{}' probe could not be "
                    "started: {}",
                    outbound.tag,
                    error.what());
            } catch (...) {
            }
        } catch (...) {
        }
    }
}

bool Daemon::begin_runtime_firewall_lifecycle_resolver(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context)
    noexcept {
    const bool lifecycle_start = context &&
        runtime_firewall_lifecycle_is_start(context->lifecycle_kind);
    const bool lifecycle_restart = context &&
        runtime_firewall_lifecycle_is_restart(context->lifecycle_kind);
    if (!context || !runtime_firewall_owner_->is_active(context) ||
        (!lifecycle_start && !lifecycle_restart) ||
        !context->domain_state) {
        return false;
    }
    auto& state = static_cast<DaemonRuntimeFirewallOperationState&>(
        *context->domain_state);
    using Phase = DaemonRuntimeFirewallOperationState::
        LifecycleTailPhase;
    if (lifecycle_restart && !state.resolver_refresh_required) {
        state.lifecycle_resolver_verified = true;
        state.lifecycle_resolver_phase = Phase::completed;
        return false;
    }
    if (state.lifecycle_resolver_phase == Phase::in_flight) {
        const bool coordinator_in_flight =
            resolver_stream_coordinator_.in_flight();
        bool exact_stream_in_flight = false;
        if (coordinator_in_flight) {
            KPBR_LOCK_GUARD(resolver_stream_attempt_mutex_);
            exact_stream_in_flight =
                active_resolver_stream_attempt_id_ ==
                    state.lifecycle_resolver_attempt_id &&
                active_resolver_stream_generation_ &&
                active_resolver_stream_generation_->stream_epoch ==
                    state.lifecycle_resolver_stream_epoch;
        }
        if (exact_stream_in_flight) {
            return true;
        }
        // A rejected control handoff retires the coordinator claim without
        // invoking its control-only completion. The terminal watchdog is the
        // durable fallback: once the exact stream is no longer in flight it
        // converts that lost handoff into a failed lifecycle resolver tail.
        state.lifecycle_resolver_verified = false;
        state.lifecycle_resolver_phase = Phase::completed;
        try {
            state.lifecycle_failure_detail = lifecycle_start
                ? "resolver activation completion was not published"
                : "resolver reload completion was not published";
        } catch (...) {
        }
        return false;
    }
    if (state.lifecycle_resolver_phase == Phase::completed) {
        return false;
    }

    const auto fail = [&state](std::string_view detail) noexcept {
        state.lifecycle_resolver_verified = false;
        state.lifecycle_resolver_phase = Phase::completed;
        try {
            state.lifecycle_failure_detail.assign(
                detail.data(), detail.size());
        } catch (...) {
        }
    };

    // The active attempt id/generation are the IPC stream authority. Never
    // overwrite another coordinator claim before request() can reject us as
    // busy; the coordinator releases its lifetime before reporting idle.
    if (resolver_stream_coordinator_.in_flight()) {
        fail(lifecycle_start
                 ? "resolver activation coordinator is busy"
                 : "resolver reload coordinator is busy");
        return false;
    }

    try {
        if (!state.list_cache_snapshot) {
            fail(lifecycle_start
                     ? "runtime start resolver list generation is unavailable"
                     : "runtime restart resolver list generation is unavailable");
            return false;
        }
        if (!state.resolver_generation_published) {
            apply_started_ts_.store(
                unix_timestamp_now_seconds(),
                std::memory_order_release);
            commit_resolver_generation_snapshot(
                make_resolver_generation_snapshot(
                    state.list_cache_snapshot,
                    state.lifecycle_trusted_dns_interfaces));
            state.resolver_generation_published = true;
        }
        if (!resolver_generation_snapshot_) {
            fail("lifecycle resolver generation was not published");
            return false;
        }

        auto generation = std::make_shared<ResolverGenerationSnapshot>(
            *resolver_generation_snapshot_);
        generation->stream_epoch =
            resolver_stream_epoch_.fetch_add(
                1U, std::memory_order_acq_rel) + 1U;
        const std::string attempt_id = generate_resolver_attempt_id();
        state.lifecycle_resolver_attempt_id = attempt_id;
        state.lifecycle_resolver_stream_epoch =
            generation->stream_epoch;
        const auto args = build_system_resolver_hook_args(
            generation->config,
            lifecycle_start
                ? runtime_start_resolver_action()
                : std::string_view{"reload"},
            attempt_id);
        if (args.empty()) {
            state.lifecycle_resolver_verified = true;
            state.lifecycle_resolver_phase = Phase::completed;
            return false;
        }

        auto lifetime = std::make_shared<ResolverStreamAttemptLifetime>(
            ipc_resolver_hook_inflight_,
            nullptr,
            generation,
            [this, attempt_id, lifecycle_start]() noexcept {
                KPBR_LOCK_GUARD(resolver_stream_attempt_mutex_);
                if (active_resolver_stream_attempt_id_ == attempt_id) {
                    active_resolver_stream_attempt_id_.clear();
                    active_resolver_stream_generation_.reset();
                    if (lifecycle_start) {
                        inactive_resolver_activation_generation_.reset();
                    }
                }
            });
        resolver_generation_snapshot_ = generation;
        {
            KPBR_LOCK_GUARD(resolver_stream_attempt_mutex_);
            active_resolver_stream_attempt_id_ = attempt_id;
            active_resolver_stream_generation_ = generation;
            if (lifecycle_start) {
                inactive_resolver_activation_generation_ = generation;
            }
        }

        std::weak_ptr<RuntimeFirewallOperationContext> weak_context{
            context};
        ResolverStreamOperation operation;
        operation.runtime_generation =
            context->queued_claim.runtime_generation;
        operation.retry_attempt = context->queued_claim.attempt;
        operation.stream_epoch = generation->stream_epoch;
        operation.attempt_id = attempt_id;
        operation.timeout = std::chrono::seconds{15};
        operation.lifetime = std::move(lifetime);
        operation.invoke_hook = [this, args]() {
            KPBR_LOCK_GUARD(system_resolver_hook_mutex_);
            return hook_command_executor_(args);
        };
        operation.completion =
            [this, weak_context](
                const ResolverStreamOperation& completed_operation,
                const ResolverStreamResult& result) noexcept {
                const auto retained = weak_context.lock();
                if (!retained ||
                    !runtime_firewall_owner_->is_active(retained) ||
                    !retained->domain_state) {
                    return;
                }
                auto& completed_state =
                    static_cast<DaemonRuntimeFirewallOperationState&>(
                        *retained->domain_state);
                using CompletedPhase =
                    DaemonRuntimeFirewallOperationState::
                        LifecycleTailPhase;
                if (completed_state.lifecycle_resolver_phase !=
                    CompletedPhase::in_flight) {
                    return;
                }
                const bool exact =
                    runtime_firewall_lifecycle_generation_is_current(
                        retained->lifecycle_kind,
                        completed_operation.runtime_generation) &&
                    completed_operation.attempt_id ==
                        completed_state
                            .lifecycle_resolver_attempt_id &&
                    completed_operation.stream_epoch ==
                        completed_state
                            .lifecycle_resolver_stream_epoch &&
                    resolver_generation_snapshot_ &&
                    resolver_generation_snapshot_->stream_epoch ==
                        completed_operation.stream_epoch;
                completed_state.lifecycle_resolver_verified =
                    exact && result.completed &&
                    result.hook_exit_code == 0;
                if (!completed_state.lifecycle_resolver_verified) {
                    try {
                        completed_state.lifecycle_failure_detail =
                            result.error.empty()
                                ? (runtime_firewall_lifecycle_is_start(
                                       retained->lifecycle_kind)
                                       ? "resolver activation did not publish "
                                         "the expected configuration stream"
                                       : "resolver reload did not publish the "
                                         "expected configuration stream")
                                : result.error;
                    } catch (...) {
                    }
                }
                completed_state.lifecycle_resolver_phase =
                    CompletedPhase::completed;
                runtime_firewall_owner_->request_terminal_drain(
                    retained);
            };

        const auto requested =
            resolver_stream_coordinator_.request(std::move(operation));
        if (requested ==
            ResolverStreamCoordinator::RequestResult::started) {
            state.lifecycle_resolver_phase = Phase::in_flight;
            return true;
        }
        if (requested ==
            ResolverStreamCoordinator::RequestResult::busy) {
            fail(lifecycle_start
                     ? "resolver activation coordinator is busy"
                     : "resolver reload coordinator is busy");
        } else {
            fail(lifecycle_start
                     ? "resolver activation worker rejected the operation"
                     : "resolver reload worker rejected the operation");
        }
    } catch (const std::exception& error) {
        fail(error.what());
    } catch (...) {
        fail(lifecycle_start
                 ? "resolver activation failed with an unknown error"
                 : "resolver reload failed with an unknown error");
    }
    return false;
}

bool Daemon::begin_runtime_firewall_start_rollback(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context)
    noexcept {
    if (!context || !runtime_firewall_owner_->is_active(context) ||
        !runtime_firewall_lifecycle_is_start(context->lifecycle_kind) ||
        !context->domain_state) {
        return false;
    }
    auto& state = static_cast<DaemonRuntimeFirewallOperationState&>(
        *context->domain_state);
    using Phase = DaemonRuntimeFirewallOperationState::
        LifecycleTailPhase;
    if (state.lifecycle_start_rollback_phase == Phase::completed) {
        return false;
    }
    if (state.lifecycle_start_rollback_phase == Phase::in_flight) {
        const auto result = state.lifecycle_start_rollback_result;
        if (!result ||
            !result->ready.load(std::memory_order_acquire)) {
            return true;
        }
        try {
            state.lifecycle_start_rollback_detail = result->detail;
        } catch (...) {
        }
        state.lifecycle_start_rollback_phase = Phase::completed;
        return false;
    }

    const auto reject_handoff = [&state](std::string_view detail) noexcept {
        state.lifecycle_start_rollback_result.reset();
        state.lifecycle_start_rollback_phase = Phase::not_started;
        if (state.lifecycle_start_rollback_handoff_rejections <
            kRuntimeFirewallStartRollbackHandoffRetryLimit) {
            ++state.lifecycle_start_rollback_handoff_rejections;
        }
        const bool retry =
            runtime_firewall_start_rollback_handoff_retry_available(
                state.lifecycle_start_rollback_handoff_rejections);
        try {
            state.lifecycle_start_rollback_detail.assign(
                detail.data(), detail.size());
            if (!retry) {
                if (!state.lifecycle_start_rollback_detail.empty()) {
                    state.lifecycle_start_rollback_detail += "; ";
                }
                state.lifecycle_start_rollback_detail +=
                    "rollback worker transport retry limit exhausted; "
                    "kernel cleanup was not verified";
            }
        } catch (...) {
        }
        if (!retry) {
            // The exact START terminal now proceeds through the ordinary
            // inactive+broken publication. Never report cleanup success when
            // the dedicated rollback executor did not accept the task.
            state.lifecycle_start_rollback_phase = Phase::completed;
        }
        return retry;
    };

    try {
        auto result =
            std::make_shared<RuntimeFirewallStartRollbackResult>();
        const auto deactivate_args = build_system_resolver_hook_args(
            config_, "deactivate");
        std::weak_ptr<RuntimeFirewallOperationContext> weak_context{
            context};
        state.lifecycle_start_rollback_result = result;
        state.lifecycle_start_rollback_phase = Phase::in_flight;

        const bool queued = runtime_firewall_owner_->enqueue_auxiliary(
            context,
            "runtime-start-rollback",
            [this, result, deactivate_args, weak_context]() mutable {
                const auto append_failure = [result](
                    const char* stage,
                    std::string_view detail) noexcept {
                    try {
                        if (!result->detail.empty()) {
                            result->detail += "; ";
                        }
                        result->detail += stage;
                        if (!detail.empty()) {
                            result->detail += ": ";
                            result->detail.append(
                                detail.data(), detail.size());
                        }
                    } catch (...) {
                    }
                };

                try {
                    const auto inventory =
                        routing_operation_owner_.clear();
                    result->routing_cleared =
                        classify_runtime_routing_inventory(inventory) ==
                            RuntimeRoutingInventoryAuthority::authoritative &&
                        inventory->routes.empty() &&
                        inventory->rules.empty() &&
                        inventory->outcome ==
                            RuntimeRoutingOperationOutcome::cleared;
                    if (!result->routing_cleared) {
                        append_failure(
                            "routing cleanup",
                            "kernel removal was not authoritatively verified");
                    }
                } catch (const std::exception& error) {
                    append_failure("routing cleanup", error.what());
                } catch (...) {
                    append_failure(
                        "routing cleanup", "unknown error");
                }

                try {
                    KPBR_LOCK_GUARD(
                        udp_call_affinity_mutation_mutex_);
                    firewall_->cleanup();
                    result->firewall_cleared = true;
                } catch (const std::exception& error) {
                    append_failure("firewall cleanup", error.what());
                } catch (...) {
                    append_failure(
                        "firewall cleanup", "unknown error");
                }

                try {
                    if (deactivate_args.empty()) {
                        result->resolver_deactivated = true;
                    } else {
                        KPBR_LOCK_GUARD(system_resolver_hook_mutex_);
                        result->resolver_deactivated =
                            hook_command_executor_(deactivate_args) == 0;
                        if (!result->resolver_deactivated) {
                            append_failure(
                                "resolver deactivate",
                                "hook returned a non-zero status");
                        }
                    }
                } catch (const std::exception& error) {
                    append_failure(
                        "resolver deactivate", error.what());
                } catch (...) {
                    append_failure(
                        "resolver deactivate", "unknown error");
                }

                result->ready.store(true, std::memory_order_release);
                (void)post_control_task(
                    [this, weak_context]() noexcept {
                        const auto retained = weak_context.lock();
                        if (retained) {
                            runtime_firewall_owner_
                                ->request_terminal_drain(retained);
                        }
                    },
                    "runtime-start-rollback-complete");
            });
        if (queued) return true;

        // Keep the exact terminal and lease parked. The bounded terminal
        // watchdog will retry the auxiliary handoff; finalizing without
        // clearing routes/firewall/resolver would falsely report a rollback.
        return reject_handoff(
            "runtime start rollback worker rejected the operation");
    } catch (const std::exception& error) {
        return reject_handoff(error.what());
    } catch (...) {
        return reject_handoff(
            "runtime start rollback could not be queued");
    }
}

void Daemon::drain_runtime_firewall_terminal(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context,
    bool shutdown) {
    if (!context || !context->terminal_owner ||
        !runtime_firewall_owner_->is_active(context)) {
        return;
    }
    auto& state = runtime_firewall_domain_state(context);

    auto drain = context->terminal_owner->try_begin_drain();
    if (!drain.has_value()) return;

    const auto capture_completion = [this, &context](
        const RuntimeFirewallOperationCompletion& source) {
        if (context->completion_captured) {
            if (context->worker_commit_ambiguous) return;

            // Netfilter/NAT events can arrive while this exact terminal is
            // parked on resolver activation or START rollback. Fold their
            // recovery payload into the already durable completion instead
            // of merely setting force_successor and losing SNAT inspection.
            (void)absorb_trailing_runtime_firewall_completion(
                context->completion,
                context->trailing_snat_recovery,
                context->trailing_prepared_native_vpn_catalog,
                context->force_successor);
            return;
        }
        auto captured = source;
        // Pre-worker terminal transfer deliberately leaves the recovery in
        // the coordinator. Snapshot it before closing the one-shot owner so
        // a rejected queue cannot drop an owned-SNAT repair request.
        if (!captured.snat_recovery.requested) {
            captured.snat_recovery =
                runtime_firewall_retry_.pending_owned_snat_recovery();
        }
        // Once COMMIT was entered without a proven result, neither an older
        // prepared candidate nor an event that arrived before the ambiguity
        // may replay it. The full netfilter resnapshot owner is armed below
        // and will create a fresh operation only after observing the backend.
        if (!context->worker_commit_ambiguous) {
            (void)absorb_trailing_runtime_firewall_completion(
                captured,
                context->trailing_snat_recovery,
                context->trailing_prepared_native_vpn_catalog,
                context->force_successor);
        }
        context->completion = std::move(captured);
        context->completion_captured = true;
        context->trailing_snat_recovery = {};
        context->trailing_prepared_native_vpn_catalog.reset();
    };

    const auto restore_preworker_control_state =
        [this, &state, shutdown]() {
            if (!state.preworker_side_effects_armed) return;
            if (!shutdown) {
                reset_idle_stall_observer(
                    /*schedule_if_eligible=*/true);
                const auto current_generation =
                    runtime_generation_.load(std::memory_order_acquire);
                if (state.previous_meta_cleanup.has_value() &&
                    state.previous_meta_cleanup->runtime_generation ==
                        current_generation) {
                    schedule_meta_udp443_activation_cleanup_retry(
                        state.previous_meta_cleanup->plan,
                        current_generation,
                        meta_udp443_cleanup_epoch_.load(
                            std::memory_order_acquire),
                        state.previous_meta_cleanup->attempt);
                }
            }
            state.preworker_side_effects_armed = false;
        };

    const auto settle_immediate_completion =
        [this, &state](
            RuntimeFirewallImmediateTerminalOutcome outcome) noexcept {
            const auto settlement =
                state.immediate_completion_intent.settle(outcome);
            if (settlement.status ==
                RuntimeFirewallImmediateCompletionIntent::SettleStatus::
                    retry) {
                return false;
            }
            if (settlement.broad_urltest_probe_claimed) {
                trigger_broad_urltest_probe_noexcept();
            }
            return true;
        };

    const auto absorb_retained_mutation_lease =
        [&context, &drain]() noexcept {
            // A retry after a fallible settlement may already have returned
            // the exact token to this context. Never ask the terminal owner
            // for it twice and never replace one physical authority.
            if (context->retained_mutation_lease) return true;
            auto returned = drain->take_retained_mutation_lease();
            if (returned) {
                context->retained_mutation_lease = std::move(returned);
            }
            return true;
        };

    const auto settle_lifecycle_completion =
        [&context, &state](
            RuntimeFirewallLifecycleOutcome outcome) noexcept {
            if (!context->lifecycle_completion) return;
            RuntimeFirewallLifecycleTerminal terminal;
            terminal.outcome = outcome;
            terminal.committed = state.core_publication.committed;
            terminal.commit_ambiguous =
                context->worker_commit_ambiguous;
            terminal.transient = state.worker_failure_transient ||
                (runtime_firewall_lifecycle_is_foreground(
                     context->lifecycle_kind) &&
                 state.core_publication.committed &&
                 !state.lifecycle_resolver_verified);
            try {
                terminal.detail = state.lifecycle_failure_detail.empty()
                    ? state.worker_failure_detail
                    : state.lifecycle_failure_detail;
            } catch (...) {
                // Outcome and commit authority are sufficient for the caller;
                // diagnostic allocation must not strand the completion.
            }
            (void)context->lifecycle_completion.settle(
                std::move(terminal));
        };

    const auto finalize_start_broken =
        [this, &context, &state](std::string_view detail) noexcept {
            if (!runtime_firewall_lifecycle_is_start(
                    context->lifecycle_kind) ||
                state.lifecycle_start_finalized) {
                return state.lifecycle_start_finalized;
            }
            if (!state.lifecycle_start_failure_detail_prepared) {
                try {
                    auto prepared = state.lifecycle_failure_detail.empty()
                        ? std::string{detail}
                        : state.lifecycle_failure_detail;
                    if (!state.lifecycle_start_rollback_detail.empty()) {
                        if (!prepared.empty()) {
                            prepared += "; ";
                        }
                        prepared += "rollback: ";
                        prepared += state.lifecycle_start_rollback_detail;
                    }
                    state.lifecycle_failure_detail.swap(prepared);
                    state.lifecycle_start_failure_detail_prepared = true;
                } catch (...) {
                }
            }
            // These are ancillary cleanup signals. None may turn a handled
            // START failure into std::terminate or prevent the mandatory
            // inactive+broken publication below from being retried.
            try {
                cancel_idle_stall_observer();
            } catch (...) {
            }
            try {
                cancel_meta_udp443_activation_cleanup();
            } catch (...) {
            }
            try {
                cancel_owned_snat_health_check();
            } catch (...) {
            }
            try {
                cancel_owned_conntrack_cleanup_retry();
            } catch (...) {
            }
            try {
                cancel_resolver_reload_retry();
            } catch (...) {
            }
            try {
                cancel_internal_vpn_catalog_refresh_retry();
            } catch (...) {
            }
            try {
                urltest_after_firewall_gate_.reset();
            } catch (...) {
            }
            try {
                resolver_after_firewall_gate_.reset();
            } catch (...) {
            }
            if (urltest_manager_) {
                try {
                    urltest_manager_->clear();
                } catch (...) {
                }
            }
            try {
                clear_exact_tcp_reset_cleanup_ownership();
            } catch (...) {
            }
            committed_meta_udp443_fwmark_.reset();
            committed_meta_udp443_owned_mask_ = 0U;
            try {
                refresh_resolver_config_hash_actual_async();
            } catch (...) {
            }

            bool inactive_published = false;
            try {
                runtime_state_store_.set_routing_runtime_active(false);
                inactive_published = true;
            } catch (const std::exception& error) {
                try {
                    Logger::instance().error(
                        "Failed to publish inactive runtime start state: {}",
                        error.what());
                } catch (...) {
                }
            } catch (...) {
            }

            bool broken_transitioned = false;
            try {
                transition_runtime_or_throw(
                    RuntimeState::broken, "runtime start failed");
                broken_transitioned =
                    runtime_state_machine_.state() == RuntimeState::broken;
            } catch (const std::exception& error) {
                try {
                    Logger::instance().error(
                        "Failed to enter broken runtime start state: {}",
                        error.what());
                } catch (...) {
                }
            } catch (...) {
            }

            bool snapshot_published = false;
            if (inactive_published && broken_transitioned) {
                try {
                    publish_runtime_state();
                    snapshot_published = true;
                } catch (const std::exception& error) {
                    try {
                        Logger::instance().error(
                            "Failed to publish broken runtime start state: {}",
                            error.what());
                    } catch (...) {
                    }
                } catch (...) {
                }
            }
            state.lifecycle_start_finalized =
                inactive_published && broken_transitioned &&
                snapshot_published;
            return state.lifecycle_start_finalized;
        };

    const auto finish_preworker_failure_policy =
        [this, &context, &state, shutdown]() {
            if (state.preworker_failure_policy_finished) return;
            if (shutdown) {
                state.preworker_failure_policy_finished = true;
                return;
            }

            const auto kind = context->foreground_transport_exhausted
                ? DaemonRuntimeFirewallOperationState::
                      PreworkerFailureKind::transport_rejected
                : state.preworker_failure_kind;
            if (kind == DaemonRuntimeFirewallOperationState::
                            PreworkerFailureKind::transport_rejected &&
                !runtime_firewall_owner_->
                    note_foreground_transport_rejection(context)) {
                const bool preserve_active_restart_recovery =
                    runtime_firewall_lifecycle_is_restart(
                        context->lifecycle_kind);
                context->successor_mode = preserve_active_restart_recovery
                    ? RuntimeFirewallOperationContext::SuccessorMode::
                          defer_same_attempt
                    : RuntimeFirewallOperationContext::SuccessorMode::none;
                context->force_successor =
                    preserve_active_restart_recovery;
                state.suppress_coordinator_rerun =
                    !preserve_active_restart_recovery;
                try {
                    state.lifecycle_failure_detail =
                        "runtime firewall worker transport retry limit "
                        "was exhausted";
                } catch (...) {
                }
            }
            if (runtime_firewall_lifecycle_is_start(
                    context->lifecycle_kind)) {
                try {
                    if (state.lifecycle_failure_detail.empty()) {
                        state.lifecycle_failure_detail =
                            context->foreground_transport_exhausted
                            ? "runtime start worker transport retry limit "
                              "was exhausted"
                            : (state.preworker_failure_detail.empty()
                                   ? "runtime start failed before worker "
                                     "handoff"
                                   : state.preworker_failure_detail);
                    }
                } catch (...) {
                }
                state.preworker_failure_policy_finished = true;
                return;
            }

            const auto generation = context->queued_claim.runtime_generation;
            const auto attempt = context->queued_claim.attempt;
            const bool urltest_pending =
                urltest_after_firewall_gate_.waiting_for(generation);
            if (kind == DaemonRuntimeFirewallOperationState::
                            PreworkerFailureKind::route_unavailable) {
                Logger::instance().verbose(
                    "Runtime route reconciliation is waiting for an "
                    "interface: {}",
                    state.preworker_failure_detail);
                if (urltest_pending &&
                    attempt >= RUNTIME_FIREWALL_RETRY_DELAYS.size()) {
                    for (const auto& tag :
                         urltest_after_firewall_gate_.pending_tags(
                             generation)) {
                        const auto incident =
                            urltest_apply_incidents_.record_failure(
                                tag, /*notify_immediately=*/true);
                        if (incident.notify) {
                            Logger::instance().error(
                                "Urltest '{}' firewall recovery is still "
                                "waiting for a route after {} bounded "
                                "retries: {}. The previous cursor remains "
                                "active.",
                                tag,
                                attempt,
                                state.preworker_failure_detail);
                        }
                    }
                }
            } else if (
                kind == DaemonRuntimeFirewallOperationState::
                            PreworkerFailureKind::preparation_failure) {
                if (urltest_pending ||
                    state.preworker_urltest_permanent_started) {
                    if (!state.preworker_urltest_permanent_started) {
                        auto failed_tags =
                            urltest_after_firewall_gate_.pending_tags(
                                generation);
                        state.preworker_failed_urltest_tags.assign(
                            failed_tags.begin(), failed_tags.end());
                        urltest_after_firewall_gate_.reset();
                        state.preworker_urltest_permanent_started = true;
                    }
                    try {
                        transition_runtime_or_throw(
                            RuntimeState::broken,
                            "urltest firewall recovery failed permanently");
                        publish_runtime_state();
                    } catch (...) {
                    }
                    for (const auto& tag :
                         state.preworker_failed_urltest_tags) {
                        const auto incident =
                            urltest_apply_incidents_.record_failure(
                                tag, /*notify_immediately=*/true);
                        if (incident.notify) {
                            Logger::instance().error(
                                "Urltest '{}' firewall recovery failed "
                                "permanently before worker handoff: {}. "
                                "Runtime state is broken while the last "
                                "verified kernel generation remains active.",
                                tag,
                                state.preworker_failure_detail);
                        }
                    }
                } else {
                    const bool retry =
                        context->successor_mode ==
                        RuntimeFirewallOperationContext::SuccessorMode::
                            reschedule_retry;
                    const auto incident =
                        runtime_firewall_incidents_.record_failure(
                            "runtime-firewall-reconciliation",
                            /*notify_immediately=*/true);
                    if (incident.notify) {
                        Logger::instance().error(
                            retry
                                ? "Runtime routing/firewall preparation "
                                  "failed: {}. A bounded retry will verify "
                                  "whether the failure clears."
                                : "Runtime routing/firewall preparation "
                                  "failed permanently: {}. The last "
                                  "committed runtime generation remains "
                                  "active.",
                            state.preworker_failure_detail);
                    }
                }
            } else if (
                kind == DaemonRuntimeFirewallOperationState::
                            PreworkerFailureKind::transport_rejected) {
                Logger::instance().info(
                    "Runtime firewall worker handoff was rejected; the exact "
                    "attempt remains deferred without consuming retry "
                    "budget.");
            } else if (
                kind == DaemonRuntimeFirewallOperationState::
                            PreworkerFailureKind::admission_contention) {
                Logger::instance().verbose(
                    "Runtime firewall worker is waiting behind another "
                    "runtime mutation.");
            }
            state.preworker_failure_policy_finished = true;
        };

    const auto finish_context =
        [this,
         &context,
         &state,
         &settle_lifecycle_completion,
         shutdown]() {
        if (!context->completion_captured) return;

        // Terminal shutdown never creates a successor. Retire the one-shot
        // owner before touching any potentially allocating recovery payload;
        // admission is already closed and the dedicated executor is being
        // drained by the lifecycle owner.
        if (shutdown) {
            runtime_firewall_owner_->cancel_completion_watchdog();
            runtime_firewall_owner_->reset_if_active(context);
            context->retained_mutation_lease.reset();
            settle_lifecycle_completion(
                RuntimeFirewallLifecycleOutcome::shutdown);
            return;
        }

        auto successor_mode = context->successor_mode;
        auto successor_attempt = context->successor_attempt;
        auto successor_generation =
            context->successor_runtime_generation != 0U
            ? context->successor_runtime_generation
            : context->queued_claim.runtime_generation;
        auto successor_recovery =
            std::move(context->completion.snat_recovery);
        auto successor_catalog =
            context->completion.next_prepared_catalog;
        if (!successor_catalog && !context->worker_succeeded &&
            !context->worker_commit_ambiguous) {
            successor_catalog = context->prepared_native_vpn_catalog;
        }
        bool schedule_catalog_refresh =
            context->successor_schedule_catalog_refresh;
        if (successor_catalog) {
            if (successor_generation != 0U &&
                successor_catalog->runtime_generation <
                    successor_generation) {
                // A catalog-less observation can already represent a newer
                // runtime generation. Never let an older prepared candidate
                // downgrade that retained intent; the successor must build a
                // fresh cache-only snapshot for the newer generation.
                successor_catalog.reset();
            } else {
                schedule_catalog_refresh =
                    successor_catalog->schedule_catalog_refresh;
            }
            if (successor_catalog &&
                successor_catalog->runtime_generation >
                    successor_generation) {
                successor_generation =
                    successor_catalog->runtime_generation;
                successor_attempt = 0U;
            }
        }

        // An ambiguous COMMIT has exactly one legal continuation: a fresh
        // backend resnapshot. Do not let a pre-existing trailing intent turn
        // it back into same-attempt replay in this finalizer.
        if (context->worker_commit_ambiguous) {
            successor_mode =
                RuntimeFirewallOperationContext::SuccessorMode::none;
            successor_catalog.reset();
            successor_recovery = {};
        }
        const bool completion_requests_rerun =
            runtime_firewall_terminal_requests_successor(
                context->worker_commit_ambiguous,
                context->completion.rerun_requested,
                context->force_successor,
                state.suppress_coordinator_rerun);
        if (successor_mode ==
                RuntimeFirewallOperationContext::SuccessorMode::none &&
            completion_requests_rerun) {
            successor_mode =
                RuntimeFirewallOperationContext::SuccessorMode::
                    defer_same_attempt;
        }

        const bool lifecycle_verified_success =
            context->worker_succeeded &&
            (!runtime_firewall_lifecycle_is_foreground(
                 context->lifecycle_kind) ||
             state.lifecycle_resolver_verified);
        // A source event which arrived during a successful foreground
        // lifecycle must survive after START changes state to running. Settle
        // and release the foreground request, then launch that trailing work
        // as an ordinary background successor.
        const bool detach_verified_foreground =
            runtime_firewall_lifecycle_is_foreground(
                context->lifecycle_kind) &&
            lifecycle_verified_success &&
            successor_mode !=
                RuntimeFirewallOperationContext::SuccessorMode::none;
        const bool detach_failed_restart_recovery =
            context->foreground_transport_exhausted &&
            runtime_firewall_lifecycle_is_restart(
                context->lifecycle_kind) &&
            successor_mode !=
                RuntimeFirewallOperationContext::SuccessorMode::none;
        const bool detach_foreground =
            detach_verified_foreground ||
            detach_failed_restart_recovery;
        const auto successor_lifecycle_kind =
            detach_foreground
            ? RuntimeFirewallLifecycleKind::background
            : context->lifecycle_kind;
        if (!runtime_firewall_lifecycle_generation_is_current(
                successor_lifecycle_kind,
                successor_generation) ||
            successor_mode ==
                RuntimeFirewallOperationContext::SuccessorMode::none) {
            runtime_firewall_owner_->cancel_completion_watchdog();
            runtime_firewall_owner_->reset_if_active(context);
            context->retained_mutation_lease.reset();
            settle_lifecycle_completion(
                lifecycle_verified_success
                    ? RuntimeFirewallLifecycleOutcome::verified_success
                    : RuntimeFirewallLifecycleOutcome::not_verified);
            return;
        }

        if (successor_generation == 0U) {
            successor_generation =
                runtime_generation_.load(std::memory_order_acquire);
        }
        if (!runtime_firewall_lifecycle_generation_is_current(
                successor_lifecycle_kind,
                successor_generation)) {
            runtime_firewall_owner_->cancel_completion_watchdog();
            runtime_firewall_owner_->reset_if_active(context);
            context->retained_mutation_lease.reset();
            settle_lifecycle_completion(
                RuntimeFirewallLifecycleOutcome::not_verified);
            return;
        }

        // Retain the exact successor before closing the one-shot terminal
        // context. Its SNAT snapshot/catalog then survive allocation or timer
        // registration failure while a fresh owner is being created.
        const bool retained =
            runtime_firewall_owner_->retain_pending_successor(
                context,
                successor_mode,
                successor_attempt,
                successor_generation,
                std::move(successor_recovery),
                std::move(successor_catalog),
                schedule_catalog_refresh,
                detach_foreground);
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->reset_if_active(context);
        if (!retained) {
            context->retained_mutation_lease.reset();
            settle_lifecycle_completion(
                lifecycle_verified_success
                    ? RuntimeFirewallLifecycleOutcome::verified_success
                    : RuntimeFirewallLifecycleOutcome::not_verified);
            Logger::instance().error(
                "Could not retain the exact runtime firewall successor; a "
                "fresh netfilter resnapshot was requested.");
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "runtime firewall successor ownership collision");
            return;
        }

        if (detach_foreground) {
            context->retained_mutation_lease.reset();
            settle_lifecycle_completion(
                lifecycle_verified_success
                    ? RuntimeFirewallLifecycleOutcome::verified_success
                    : RuntimeFirewallLifecycleOutcome::not_verified);
        }
        try {
            (void)runtime_firewall_owner_->launch_pending_successor();
        } catch (const std::exception& error) {
            try {
                Logger::instance().error(
                    "Could not arm the retained runtime firewall successor: "
                    "{}",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
        }
    };

    if (drain->kind() ==
        RuntimeFirewallDelayedTerminalOwner::DrainKind::coordinator) {
        const auto* terminal = drain->coordinator_terminal();
        if (!terminal || !terminal->owned) return;
        capture_completion(*terminal);
        restore_preworker_control_state();
        finish_preworker_failure_policy();
        if (!shutdown && runtime_firewall_lifecycle_is_start(
                context->lifecycle_kind) &&
            context->successor_mode ==
                RuntimeFirewallOperationContext::SuccessorMode::none) {
            if (begin_runtime_firewall_start_rollback(context)) {
                drain->park_until_wake();
                return;
            }
            if (!finalize_start_broken(
                    "runtime start ended before worker handoff")) {
                drain->park_until_wake();
                return;
            }
        }
        if (!absorb_retained_mutation_lease()) return;
        if (!settle_immediate_completion(
                shutdown
                    ? RuntimeFirewallImmediateTerminalOutcome::shutdown
                    : RuntimeFirewallImmediateTerminalOutcome::
                          not_verified)) {
            return;
        }
        if (!drain->finish_coordinator_terminal()) return;
        finish_context();
        return;
    }

    const auto* terminal = drain->worker_terminal();
    if (!terminal) return;
    if (terminal->status ==
        RuntimeFirewallDelayedWorker::TerminalStatus::queued_abandoned) {
        if (!terminal->coordinator_completion.has_value() ||
            !terminal->coordinator_completion->owned) {
            return;
        }
        capture_completion(*terminal->coordinator_completion);
        restore_preworker_control_state();
        finish_preworker_failure_policy();
        if (!shutdown && runtime_firewall_lifecycle_is_start(
                context->lifecycle_kind) &&
            context->successor_mode ==
                RuntimeFirewallOperationContext::SuccessorMode::none) {
            if (begin_runtime_firewall_start_rollback(context)) {
                drain->park_until_wake();
                return;
            }
            if (!finalize_start_broken(
                    "runtime start worker queue was abandoned")) {
                drain->park_until_wake();
                return;
            }
        }
        if (!absorb_retained_mutation_lease()) return;
        if (!settle_immediate_completion(
                shutdown
                    ? RuntimeFirewallImmediateTerminalOutcome::shutdown
                    : RuntimeFirewallImmediateTerminalOutcome::
                          not_verified)) {
            return;
        }
        if (!drain->finish_worker_terminal()) return;
        finish_context();
        return;
    }

    if (!terminal->running_claim.has_value() ||
        !terminal->mutation_lease) {
        // A bare pre-worker lost_claim waits for the coordinator terminal;
        // try_begin_drain() normally filters it before reaching this branch.
        return;
    }

    // begin_worker() was crossed, so a later application/backend retry starts
    // with a fresh transport budget. Only consecutive pre-worker rejections
    // are bounded by the foreground handoff limit.
    context->foreground_transport_rejections = 0U;
    const RuntimeFirewallWorkerAttemptResult* worker_result =
        terminal->result.get();
    const bool retained_worker_lease =
        terminal->mutation_lease.return_policy ==
        RuntimeFirewallDelayedWorker::MutationLeaseReturnPolicy::
            return_to_operation_owner;
    if (!state.core_publication.prepared) {
        DaemonRuntimeFirewallOperationState::CorePublication publication;
        std::optional<MetaUdp443ActivationPlan> candidate_meta_plan;
        OwnedSnatRecovery processed_recovery =
            context->submitted_snat_recovery;
        OwnedSnatState inspected_snat_after = OwnedSnatState::unknown;
        bool result_valid =
            terminal->status ==
                RuntimeFirewallDelayedWorker::TerminalStatus::result &&
            worker_result != nullptr &&
            worker_result->transaction.operation_serial ==
                context->queued_claim.serial &&
            worker_result->transaction.runtime_generation ==
                context->queued_claim.runtime_generation &&
            context->worker_input &&
            context->worker_input->transaction.operation_serial ==
                context->queued_claim.serial &&
            context->worker_input->transaction.runtime_generation ==
                context->queued_claim.runtime_generation;
        const bool current_generation =
            runtime_firewall_lifecycle_generation_is_current(
                context->lifecycle_kind,
                context->queued_claim.runtime_generation);

        bool commit_ambiguous =
            terminal->status !=
                RuntimeFirewallDelayedWorker::TerminalStatus::result ||
            worker_result == nullptr;
        bool transient_failure = !result_valid;
        std::string failure_detail;
        if (terminal->status ==
                RuntimeFirewallDelayedWorker::TerminalStatus::exception &&
            terminal->exception) {
            try {
                std::rethrow_exception(terminal->exception);
            } catch (const std::exception& error) {
                failure_detail = error.what();
            } catch (...) {
                failure_detail =
                    "runtime firewall worker threw a non-standard exception";
            }
        } else if (terminal->status ==
                   RuntimeFirewallDelayedWorker::TerminalStatus::
                       missing_result) {
            failure_detail =
                "runtime firewall worker returned no terminal result";
        } else if (terminal->status ==
                   RuntimeFirewallDelayedWorker::TerminalStatus::lost_claim) {
            failure_detail =
                "runtime firewall worker lost its exact operation claim";
        } else if (!result_valid) {
            failure_detail =
                "runtime firewall worker returned mismatched operation "
                "identity";
        }

        if (result_valid) {
            commit_ambiguous =
                worker_result->transaction.commit_entered &&
                !worker_result->transaction.committed();
            const auto& route_preparation =
                worker_result->route_preparation;
            if (route_preparation.required &&
                (!route_preparation.observation_succeeded ||
                 !route_preparation.worker_mutation_ack.has_value() ||
                 *route_preparation.worker_mutation_ack !=
                     RuntimeRouteMutationAck::applied ||
                 !route_preparation.checkpoint_published ||
                 !route_preparation.mutation_ack.has_value() ||
                 *route_preparation.mutation_ack !=
                     RuntimeRouteMutationAck::applied)) {
                // Route observation/mutation is a pre-COMMIT admission
                // boundary. It is never ambiguous and must not permit the
                // firewall transaction to run against an unacknowledged
                // desired route generation.
                commit_ambiguous = false;
                if (!route_preparation.observation_succeeded) {
                    transient_failure = true;
                    failure_detail =
                        route_preparation.observation_failure.detail;
                    if (failure_detail.empty()) {
                        failure_detail =
                            "runtime route observation did not complete";
                    }
                } else if (
                    !route_preparation.worker_mutation_ack.has_value()) {
                    transient_failure = true;
                    failure_detail =
                        "runtime route plan did not enter its combined "
                        "worker owner";
                } else if (
                    *route_preparation.worker_mutation_ack !=
                        RuntimeRouteMutationAck::applied) {
                    failure_detail =
                        route_preparation.worker_mutation_failure_detail;
                    switch (*route_preparation.worker_mutation_ack) {
                    case RuntimeRouteMutationAck::applied:
                        break;
                    case RuntimeRouteMutationAck::stale:
                        transient_failure = true;
                        if (failure_detail.empty()) {
                            failure_detail =
                                "runtime route observation became stale "
                                "before worker mutation";
                        }
                        break;
                    case RuntimeRouteMutationAck::route_unavailable:
                        transient_failure = false;
                        if (failure_detail.empty()) {
                            failure_detail =
                                "runtime route interface is unavailable";
                        }
                        break;
                    case RuntimeRouteMutationAck::mutation_failed:
                        transient_failure = false;
                        if (failure_detail.empty()) {
                            failure_detail =
                                "runtime route worker mutation failed";
                        }
                        break;
                    case RuntimeRouteMutationAck::shutdown:
                        transient_failure = false;
                        if (failure_detail.empty()) {
                            failure_detail =
                                "runtime route mutation stopped during "
                                "shutdown";
                        }
                        break;
                    }
                } else if (!route_preparation.checkpoint_published) {
                    transient_failure = true;
                    failure_detail =
                        "runtime route result could not enter its control "
                        "publication checkpoint";
                } else if (!route_preparation.mutation_ack.has_value()) {
                    transient_failure = true;
                    failure_detail =
                        "runtime route checkpoint returned no acknowledgement";
                } else {
                    switch (*route_preparation.mutation_ack) {
                    case RuntimeRouteMutationAck::applied:
                        break;
                    case RuntimeRouteMutationAck::stale:
                        transient_failure = true;
                        failure_detail =
                            "runtime route observation became stale before "
                            "publication";
                        break;
                    case RuntimeRouteMutationAck::route_unavailable:
                        transient_failure = false;
                        failure_detail =
                            "runtime route publication reported an "
                            "unexpected interface failure";
                        break;
                    case RuntimeRouteMutationAck::mutation_failed:
                        transient_failure = false;
                        failure_detail =
                            "runtime route publication failed";
                        break;
                    case RuntimeRouteMutationAck::shutdown:
                        transient_failure = false;
                        failure_detail =
                            "runtime route publication stopped during "
                            "shutdown";
                        break;
                    }
                }
            } else if (worker_result->transaction.failure.has_value()) {
                failure_detail =
                    worker_result->transaction.failure->message;
                transient_failure =
                    worker_result->transaction.failure->kind ==
                    RuntimeFirewallBackendFailureKind::transient_firewall;
            } else if (!worker_result->transaction_executed) {
                transient_failure = true;
                if (worker_result->owned_snat_before.failure.failed()) {
                    failure_detail =
                        worker_result->owned_snat_before.failure.message;
                } else {
                    failure_detail =
                        "runtime firewall backend transaction was not "
                        "admitted after its required observation";
                }
            }
        }

        const bool committed_candidate =
            result_valid && current_generation && !shutdown &&
            worker_result->transaction.committed();
        if (committed_candidate) {
            const auto& committed =
                *worker_result->transaction.committed_firewall;
            publication.rules = committed.rule_states;
            publication.list_content_state =
                committed.list_content_state;
            publication.list_usage = committed.list_usage;
            publication.list_fingerprints =
                context->worker_input->transaction
                    .requested_list_fingerprints;
            publication.internal_vpn_servers =
                state.internal_vpn_resolution.effective_servers;
            publication.internal_vpn_service_targets =
                state.internal_vpn_service_resolution.effective_targets;
            publication.native_vpn_direct_egress_snat_selectors =
                context->worker_input->transaction
                    .candidate_native_vpn_direct_egress_snat_selectors;
            candidate_meta_plan =
                worker_result->transaction.meta_activation_plan;
            if (candidate_meta_plan.has_value()) {
                publication.committed_meta_fwmark =
                    candidate_meta_plan->expected_fwmark;
                publication.committed_meta_owned_mask =
                    candidate_meta_plan->owned_mask;
            }
            publication.committed = true;
        }

        bool snat_healthy = true;
        if (processed_recovery.requested) {
            OwnedSnatState before = OwnedSnatState::unknown;
            if (result_valid &&
                worker_result->owned_snat_before.state.has_value() &&
                !worker_result->owned_snat_before.failure.failed()) {
                before = *worker_result->owned_snat_before.state;
            }
            std::optional<OwnedConntrackCleanupSnapshot> exact_snapshot;
            if (before == OwnedSnatState::missing && result_valid &&
                worker_result
                    ->pre_mutation_owned_conntrack_cleanup_snapshot
                    .has_value() &&
                worker_result
                    ->pre_mutation_owned_conntrack_cleanup_snapshot
                    ->valid() &&
                worker_result
                    ->pre_mutation_owned_conntrack_cleanup_snapshot
                    ->runtime_generation ==
                    context->queued_claim.runtime_generation) {
                exact_snapshot = worker_result
                    ->pre_mutation_owned_conntrack_cleanup_snapshot;
            }
            processed_recovery = observe_owned_snat_state(
                std::move(processed_recovery),
                before,
                std::move(exact_snapshot));

            if (result_valid &&
                worker_result->owned_snat_after.state.has_value() &&
                !worker_result->owned_snat_after.failure.failed()) {
                inspected_snat_after =
                    *worker_result->owned_snat_after.state;
            }
            processed_recovery = observe_owned_snat_state(
                std::move(processed_recovery),
                inspected_snat_after);
            snat_healthy =
                inspected_snat_after == OwnedSnatState::healthy;
            if (!snat_healthy) {
                transient_failure = true;
                if (failure_detail.empty()) {
                    failure_detail =
                        "tunnel SNAT scaffold was not healthy after the "
                        "runtime firewall transaction";
                }
            }
        }

        const bool worker_succeeded =
            publication.committed && snat_healthy;
        if (!worker_succeeded && failure_detail.empty()) {
            failure_detail = commit_ambiguous
                ? "runtime firewall COMMIT outcome is ambiguous"
                : "runtime firewall transaction did not commit";
        }

        const bool lifecycle_start =
            runtime_firewall_lifecycle_is_start(
                context->lifecycle_kind);
        const bool retryable_failure = lifecycle_start
            ? transient_failure
            : (transient_failure ||
               processed_recovery.requested ||
               (context->worker_input &&
                config_has_native_vpn_catalog_policy(
                    context->worker_input->transaction.config)) ||
               urltest_after_firewall_gate_.waiting_for(
                   context->queued_claim.runtime_generation));
        const bool bounded_retry_required =
            !worker_succeeded &&
            !commit_ambiguous &&
            retryable_failure &&
            (!lifecycle_start ||
             runtime_firewall_start_retry_available(
                 context->queued_claim.attempt));

        // The target GCC 8 old-string ABI does not promise nothrow move
        // assignment. Commit that sole fallible context field while the
        // checkpoint is still visibly unprepared. If it throws, the drain
        // guard re-arms and the complete local preparation is recomputed.
        state.worker_failure_detail = std::move(failure_detail);

        // Every context write below is covered by the static nothrow contract
        // above or is scalar. Publish prepared=true only inside this tail so a
        // retry can never observe a partially committed core checkpoint.
        publication.prepared = true;
        state.core_publication = std::move(publication);
        state.candidate_meta_activation_plan =
            std::move(candidate_meta_plan);
        state.processed_snat_recovery =
            std::move(processed_recovery);
        state.inspected_snat_after = inspected_snat_after;
        context->worker_succeeded = worker_succeeded;
        state.worker_result_valid = result_valid;
        context->worker_commit_ambiguous = commit_ambiguous;
        state.worker_failure_transient = transient_failure;
        context->successor_mode = bounded_retry_required
            ? RuntimeFirewallOperationContext::SuccessorMode::
                  reschedule_retry
            : RuntimeFirewallOperationContext::SuccessorMode::none;
    }

    if (!drain->begin_worker_control(runtime_firewall_retry_)) return;

    const bool lifecycle_start =
        runtime_firewall_lifecycle_is_start(context->lifecycle_kind);
    const auto publish_core_candidate = [this, &state]() noexcept {
        if (state.core_published) return true;
        auto& publication = state.core_publication;
        if (!publication.committed) return true;

        firewall_state_.swap_rules(publication.rules);
        applied_list_content_state_.static_destinations.swap(
            publication.list_content_state.static_destinations);
        applied_list_content_state_.domain_entry_lists.swap(
            publication.list_content_state.domain_entry_lists);
        applied_list_content_state_.truncated_static_destination_lists.swap(
            publication.list_content_state
                .truncated_static_destination_lists);
        applied_list_usage_.swap(publication.list_usage);
        applied_list_fingerprints_.swap(
            publication.list_fingerprints);
        resolved_internal_vpn_servers_.swap(
            publication.internal_vpn_servers);
        resolved_internal_vpn_service_targets_.swap(
            publication.internal_vpn_service_targets);
        applied_native_vpn_direct_egress_snat_selectors_.swap(
            publication.native_vpn_direct_egress_snat_selectors);
        committed_meta_udp443_fwmark_ =
            publication.committed_meta_fwmark;
        committed_meta_udp443_owned_mask_ =
            publication.committed_meta_owned_mask;
        state.core_published = true;
        return true;
    };

    if (!drain->publish_worker_control([
            lifecycle_start,
            &publish_core_candidate]() noexcept {
            return lifecycle_start
                ? true
                : publish_core_candidate();
        })) {
        return;
    }

    if (!shutdown && state.core_published &&
        !state.internal_vpn_lkg_published) {
        update_internal_vpn_verified_includes_lkg(
            state.internal_vpn_resolution);
        update_internal_vpn_service_verified_includes_lkg(
            state.internal_vpn_service_resolution);
        state.internal_vpn_lkg_published = true;
    }

    if (!shutdown && lifecycle_start &&
        !state.lifecycle_start_candidate_published) {
        // START keeps its candidate private until resolver activate publishes
        // the exact expected stream. Meta/idle work is likewise deferred.
    } else if (!shutdown && state.core_published &&
        !state.meta_tail_finished) {
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
        const auto current_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const auto cleanup_epoch =
            meta_udp443_cleanup_epoch_.load(std::memory_order_acquire);
        const bool filter_healthy =
            worker_result != nullptr &&
            worker_result->forward_udp_reject_after_commit.state ==
                std::optional<OwnedForwardUdpRejectState>{
                    OwnedForwardUdpRejectState::healthy} &&
            !worker_result->forward_udp_reject_after_commit.failure.failed();
        const bool fastnat_healthy =
            !state.candidate_meta_activation_plan.has_value() ||
            (worker_result != nullptr &&
             worker_result->fastnat_after_commit
                     .disabled_or_unavailable ==
                 std::optional<bool>{true} &&
             !worker_result->fastnat_after_commit.failure.failed());

        if (state.candidate_meta_activation_plan.has_value() &&
            fastnat_healthy && filter_healthy) {
            meta_udp443_incidents_.reset("meta-udp443-activation");
            schedule_meta_udp443_activation_cleanup_retry(
                *state.candidate_meta_activation_plan,
                current_generation,
                cleanup_epoch,
                /*attempt=*/0U);
        } else if (
            state.candidate_meta_activation_plan.has_value()) {
            report_meta_udp443_degraded(
                !fastnat_healthy
                    ? "FastNAT was re-enabled during delayed firewall "
                      "publication"
                    : "the exact owned first FORWARD hook could not be "
                      "reverified after delayed publication");
            schedule_meta_udp443_activation_cleanup_retry(
                *state.candidate_meta_activation_plan,
                current_generation,
                cleanup_epoch,
                /*attempt=*/1U);
            if (fastnat_healthy) {
                schedule_netfilter_runtime_refresh_noexcept(
                    NetfilterRefreshReason::full,
                    "could not repair delayed Meta UDP/443 publication");
            }
        } else if (filter_healthy) {
            meta_udp443_incidents_.reset("meta-udp443-activation");
        } else {
            report_meta_udp443_degraded(
                "balanced mode could not verify absence of owned UDP/443 "
                "artifacts after delayed publication");
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "could not clean stale balanced-mode Meta UDP/443 "
                "artifacts");
        }
        state.meta_tail_finished = true;
        state.preworker_side_effects_armed = false;
    } else if (!shutdown && !state.core_published &&
               !state.meta_tail_finished) {
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
        const auto current_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const bool publication_may_have_changed =
            context->worker_commit_ambiguous ||
            (worker_result != nullptr &&
             meta_udp443_publication_may_have_changed(
                 worker_result->meta_publication_epoch_before,
                 worker_result->meta_publication_epoch_after));
        if (should_restore_pending_meta_udp443_cleanup_after_apply_failure(
                state.previous_meta_cleanup.has_value(),
                state.previous_meta_cleanup.has_value()
                    ? state.previous_meta_cleanup->runtime_generation
                    : 0U,
                current_generation,
                publication_may_have_changed)) {
            schedule_meta_udp443_activation_cleanup_retry(
                state.previous_meta_cleanup->plan,
                current_generation,
                meta_udp443_cleanup_epoch_.load(
                    std::memory_order_acquire),
                state.previous_meta_cleanup->attempt);
        } else if (publication_may_have_changed) {
            report_meta_udp443_degraded(
                "delayed firewall COMMIT outcome is ambiguous; exact Meta "
                "cleanup authority was discarded");
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "could not resnapshot Meta UDP/443 after an ambiguous "
                "delayed COMMIT");
        }
        state.meta_tail_finished = true;
        state.preworker_side_effects_armed = false;
    }

    if (!shutdown && lifecycle_start &&
        !state.resolver_tail_finished) {
        if (!context->worker_succeeded) {
            state.lifecycle_resolver_verified = false;
            state.resolver_tail_finished = true;
        } else {
            if (begin_runtime_firewall_lifecycle_resolver(context)) {
                drain->park_until_wake();
                return;
            }
            state.resolver_tail_finished = true;
            if (state.lifecycle_resolver_verified) {
                if (!publish_core_candidate()) return;
                state.lifecycle_start_candidate_published = true;
                // Re-enter once so the ordinary internal-VPN and Meta tails
                // observe only the now-verified published candidate.
                return;
            }
        }
    } else if (!shutdown && !lifecycle_start &&
               state.core_published &&
               !state.resolver_tail_finished) {
        const auto current_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const bool resolver_waits_for_firewall =
            resolver_after_firewall_gate_.waiting_for(
                current_generation);
        const bool foreground_lifecycle =
            runtime_firewall_lifecycle_is_foreground(
                context->lifecycle_kind);
        bool lifecycle_resolver_verified =
            runtime_firewall_restart_resolver_initially_verified(
                context->lifecycle_kind,
                state.resolver_refresh_required,
                resolver_waits_for_firewall);
        if (state.resolver_refresh_required &&
            !state.resolver_generation_published) {
            apply_started_ts_.store(
                unix_timestamp_now_seconds(),
                std::memory_order_release);
            commit_resolver_generation_snapshot(
                make_resolver_generation_snapshot(
                    state.list_cache_snapshot));
            state.resolver_generation_published = true;
        }
        if (state.resolver_refresh_required &&
            !resolver_waits_for_firewall) {
            cancel_resolver_reload_retry();
            if (foreground_lifecycle) {
                if (begin_runtime_firewall_lifecycle_resolver(context)) {
                    drain->park_until_wake();
                    return;
                }
                lifecycle_resolver_verified =
                    state.lifecycle_resolver_verified;
                if (lifecycle_resolver_verified) {
                    if (acknowledge_verified_resolver_reload(
                            current_generation)) {
                        publish_runtime_state();
                    }
                    refresh_resolver_config_hash_actual_async();
                } else {
                    schedule_resolver_reload_retry(
                        0, current_generation);
                }
            } else if (resolver_stream_coordinator_.in_flight()) {
                schedule_resolver_reload_retry(
                    0, current_generation);
            } else {
                try {
                    if (run_system_resolver_hook_stream_prepared(
                            "reload", /*rebuild_snapshot=*/false)) {
                        lifecycle_resolver_verified = true;
                        if (acknowledge_verified_resolver_reload(
                                current_generation)) {
                            publish_runtime_state();
                        }
                        refresh_resolver_config_hash_actual_async();
                    } else {
                        schedule_resolver_reload_retry(
                            0, current_generation);
                    }
                } catch (const std::exception& error) {
                    lifecycle_resolver_verified = false;
                    Logger::instance().info(
                        "Native VPN DNS access policy refresh was deferred: "
                        "{}",
                        error.what());
                    schedule_resolver_reload_retry(
                        0, current_generation);
                } catch (...) {
                    lifecycle_resolver_verified = false;
                    schedule_resolver_reload_retry(
                        0, current_generation);
                }
            }
        } else if (foreground_lifecycle &&
                   resolver_waits_for_firewall) {
            state.lifecycle_failure_detail =
                "resolver reload remains gated behind firewall recovery";
        }
        if (foreground_lifecycle) {
            state.lifecycle_resolver_verified =
                lifecycle_resolver_verified;
        }
        state.resolver_tail_finished = true;
    }

    if (!shutdown && !state.conntrack_tail_finished) {
        if (state.worker_result_valid && worker_result != nullptr &&
            worker_result->native_direct_egress_source_cleanup
                .failure.failed()) {
            Logger::instance().info(
                "Delayed native VPN source-flow cleanup was incomplete: {}",
                worker_result->native_direct_egress_source_cleanup
                    .failure.message);
        }
        if (context->worker_succeeded &&
            state.processed_snat_recovery.has_value() &&
            should_cleanup_conntrack_after_snat_repair(
                *state.processed_snat_recovery,
                state.inspected_snat_after) &&
            state.processed_snat_recovery->cleanup_snapshot
                .has_value() &&
            state.processed_snat_recovery->cleanup_snapshot
                    ->runtime_generation ==
                runtime_generation_.load(std::memory_order_acquire)) {
            const auto& snapshot =
                *state.processed_snat_recovery->cleanup_snapshot;
            schedule_owned_conntrack_cleanup_retry(
                snapshot,
                ordered_owned_conntrack_marks(snapshot));
        }
        state.conntrack_tail_finished = true;
    }

    if (!shutdown && !state.runtime_tail_finished) {
        const auto current_generation =
            runtime_generation_.load(std::memory_order_acquire);
        if (lifecycle_start) {
            bool successor_pending =
                context->successor_mode !=
                RuntimeFirewallOperationContext::SuccessorMode::none;
            const bool route_epoch_current =
                context->worker_input &&
                context->worker_input->route_health_request.route_epoch !=
                    0U &&
                context->worker_input->route_health_request.route_epoch ==
                    routing_observation_epoch_.load(
                        std::memory_order_acquire);
            if (context->worker_succeeded && !route_epoch_current) {
                // Interface events are serialized on this control loop, so
                // this is the last exact fence before publishing running.
                // A changed topology after the worker route checkpoint is a
                // non-ambiguous fresh-snapshot request, not a verified START.
                context->worker_succeeded = false;
                const bool retry_available =
                    runtime_firewall_start_retry_available(
                        context->queued_claim.attempt);
                context->successor_mode = retry_available
                    ? RuntimeFirewallOperationContext::SuccessorMode::
                          reschedule_retry
                    : RuntimeFirewallOperationContext::SuccessorMode::none;
                context->force_successor = retry_available;
                successor_pending = retry_available;
                state.worker_failure_transient = retry_available;
                state.worker_failure_detail =
                    "runtime route observation changed before START "
                    "publication";
            }
            const bool verified_start =
                context->worker_succeeded &&
                state.lifecycle_resolver_verified &&
                state.lifecycle_start_candidate_published &&
                state.core_published;
            if (verified_start) {
                bool publication_failed = false;
                if (!state.lifecycle_start_finalized) {
                    try {
                        runtime_state_store_.set_routing_runtime_active(true);
                        if (runtime_state_machine_.state() !=
                            RuntimeState::running) {
                            transition_runtime_or_throw(
                                RuntimeState::running,
                                "runtime start complete");
                        }
                        publish_runtime_state();
                        state.lifecycle_start_finalized = true;
                    } catch (const std::exception& error) {
                        publication_failed = true;
                        try {
                            state.lifecycle_failure_detail =
                                std::string{
                                    "runtime start state publication failed: "} +
                                error.what();
                        } catch (...) {
                        }
                    } catch (...) {
                        publication_failed = true;
                        try {
                            state.lifecycle_failure_detail =
                                "runtime start state publication failed";
                        } catch (...) {
                        }
                    }
                }

                if (publication_failed) {
                    context->worker_succeeded = false;
                    if (begin_runtime_firewall_start_rollback(context)) {
                        drain->park_until_wake();
                        return;
                    }
                    if (!finalize_start_broken(
                            state.lifecycle_failure_detail)) {
                        drain->park_until_wake();
                        return;
                    }
                } else if (!state.lifecycle_start_post_success_finished) {
                    // All remaining work is ancillary. A scheduler, notifier
                    // or logger failure must not replay the already-published
                    // START transition or strand its exact completion.
                    try {
                        reset_idle_stall_observer(
                            /*schedule_if_eligible=*/true);
                    } catch (...) {
                    }
                    try {
                        schedule_owned_snat_health_check();
                    } catch (...) {
                    }
                    try {
                        schedule_internal_vpn_catalog_refresh_if_needed(
                            state.internal_vpn_resolution.state,
                            state.internal_vpn_service_resolution.state);
                    } catch (...) {
                    }
                    try {
                        runtime_firewall_incidents_.clear();
                    } catch (...) {
                    }
#ifdef WITH_API
                    try {
                        request_remote_access_reconcile_from_control(
                            "runtime start");
                    } catch (...) {
                    }
#endif
                    try {
                        schedule_keenetic_dns_refresh();
                    } catch (...) {
                    }
                    try {
                        refresh_resolver_config_hash_actual_async();
                    } catch (...) {
                    }
                    try {
                        Logger::instance().info(
                            "Routing runtime started.");
                    } catch (...) {
                    }
                    try {
                        if (worker_result != nullptr) {
                            const auto& cleanup =
                                worker_result
                                    ->post_commit_owned_conntrack_cleanup;
                            if (cleanup.attempted &&
                                cleanup.snapshot.has_value()) {
                                if (cleanup.summary.command_unavailable) {
                                    warn_conntrack_unavailable_once();
                                }
                                auto remaining =
                                    cleanup.summary.remaining_marks;
                                if (cleanup.failure.failed() &&
                                    remaining.empty()) {
                                    remaining =
                                        ordered_owned_conntrack_marks(
                                            *cleanup.snapshot);
                                }
                                if (!cleanup.summary.command_unavailable &&
                                    !remaining.empty()) {
                                    schedule_owned_conntrack_cleanup_retry(
                                        *cleanup.snapshot,
                                        std::move(remaining));
                                }
                            }
                        }
                    } catch (...) {
                    }
                    state.lifecycle_start_post_success_finished = true;
                }
            } else if (successor_pending &&
                       !context->worker_commit_ambiguous) {
                try {
                    Logger::instance().info(
                        "Runtime start firewall attempt remains pending: {}",
                        state.worker_failure_detail);
                } catch (...) {
                }
            } else {
                if (begin_runtime_firewall_start_rollback(context)) {
                    drain->park_until_wake();
                    return;
                }
                if (!finalize_start_broken(
                        state.lifecycle_failure_detail.empty()
                            ? std::string_view{state.worker_failure_detail}
                            : std::string_view{
                                  state.lifecycle_failure_detail})) {
                    drain->park_until_wake();
                    return;
                }
            }
        } else if (context->worker_succeeded) {
            release_urltest_firewall_recovery(current_generation);
            if (resolver_after_firewall_gate_.release(
                    current_generation)) {
                schedule_resolver_reload_retry(
                    0, current_generation);
            }
            runtime_firewall_incidents_.clear();
#ifdef WITH_API
            request_remote_access_reconcile_from_control(
                "verified delayed firewall refresh");
#endif
            publish_runtime_state();
            Logger::instance().info(
                "Delayed runtime firewall refresh complete.");
        } else {
            // Firewall remains on its verified LKG, but route preparation may
            // already have committed either an authoritative new generation
            // or a conservative recovery ledger. Publish that exact pairing
            // on every failed terminal; otherwise health/API can keep the
            // previous route snapshot merely because the new one is complete.
            try {
                publish_runtime_state();
            } catch (const std::exception& error) {
                try {
                    Logger::instance().warn(
                        "Could not publish runtime state after failed "
                        "routing/firewall reconciliation: {}",
                        error.what());
                } catch (...) {
                }
            } catch (...) {
            }
            const auto incident =
                runtime_firewall_incidents_.record_failure(
                    "runtime-firewall-reconciliation",
                    /*notify_immediately=*/
                        !state.worker_failure_transient);
            if (state.worker_failure_transient) {
                Logger::instance().info(
                    "Delayed runtime firewall refresh remains pending: {}",
                    state.worker_failure_detail);
            } else if (incident.notify) {
                Logger::instance().error(
                    "Delayed runtime firewall refresh failed: {}. The last "
                    "verified daemon snapshot remains active while a bounded "
                    "retry resnapshots the backend.",
                    state.worker_failure_detail);
            }
            if (context->worker_commit_ambiguous) {
                schedule_netfilter_runtime_refresh_noexcept(
                    NetfilterRefreshReason::full,
                    "ambiguous delayed runtime firewall COMMIT");
            }
        }
        state.runtime_tail_finished = true;
    }

    if (!state.processed_snat_recovery.has_value()) {
        state.processed_snat_recovery =
            context->submitted_snat_recovery;
    }
    const bool lifecycle_verified =
        !lifecycle_start ||
        (state.lifecycle_start_finalized &&
         state.lifecycle_resolver_verified &&
         routing_runtime_active());
    if (!drain->complete_worker_control(
            runtime_firewall_retry_,
            !shutdown && context->worker_succeeded &&
                lifecycle_verified,
            *state.processed_snat_recovery)) {
        return;
    }
    const auto* completion = drain->worker_control_completion();
    if (!completion || !completion->owned) return;
    capture_completion(*completion);
    if (retained_worker_lease) {
        if (!absorb_retained_mutation_lease()) return;
    } else if (!drain->release_worker_lease()) {
        return;
    }
    if (!settle_immediate_completion(
            shutdown
                ? RuntimeFirewallImmediateTerminalOutcome::shutdown
                : (context->worker_succeeded && lifecycle_verified
                       ? RuntimeFirewallImmediateTerminalOutcome::
                             verified_success
                       : RuntimeFirewallImmediateTerminalOutcome::
                             not_verified))) {
        return;
    }
    if (!drain->finish_worker_terminal()) return;
    finish_context();
}

void Daemon::handle_interface_event(const InterfaceMonitor::Event& event) {
    if (event.route_changed) {
        // The route-health worker consumes main-table reachability. A route
        // event invalidates that immutable plan and also retains one generic
        // successor. If the current worker already crossed its route ack,
        // the owner coalesces this refresh behind the terminal instead of
        // losing the event. It must not masquerade as link/topology churn or
        // trigger native-catalog work.
        routing_observation_epoch_.fetch_add(
            1U, std::memory_order_acq_rel);
        if (routing_runtime_active()) {
            (void)refresh_iproute_and_firewall_runtime(
                0U,
                {},
                /*schedule_catalog_refresh=*/false);
        }
        return;
    }
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
    if (!interface_event_requires_runtime_observation(event)) {
        return;
    }
    routing_observation_epoch_.fetch_add(1U, std::memory_order_acq_rel);
    if (!routing_runtime_active()) return;
    if (event.observation_gap) {
        recover_internal_vpn_catalog_after_observation_gap();
        return;
    }
    if (event.is_up &&
        (event.administrative_state_changed || event.topology_changed)) {
        // The kernel just made this link usable. Let only its deferred route
        // repairs bypass their remaining backoff before the event-driven
        // reconciliation below; unrelated/flapping links stay isolated.
        routing_operation_owner_.notify_interface_up(
            event.interface_name);
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
    if (!routing_runtime_active() ||
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
        [this]() { runtime_firewall_owner_->cancel_retry(); },
        // Reconcile from the invalidated cache immediately so an unverified
        // process_clients=false bypass cannot remain active. Suppress the
        // implicit catalog request here: the explicit final stage below gives
        // ENOBUFS and reconnect recovery one deterministic lifecycle order.
        [this]() {
            refresh_iproute_and_firewall_runtime(
                0,
                {},
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
#if defined(USE_KEENETIC_API) && defined(WITH_API)
        auto native_import_readiness =
            NdmsNativeImportJournalReadinessState::unavailable;
        auto native_delete_readiness =
            NdmsNativeDeleteWalReadiness::unsafe;
        auto native_mutation_admission =
            NdmsNativeMutationAdmissionState::unavailable;
        try {
            // Startup reconciliation uses the same established lock order as
            // every request. Publishing a cross-WAL clean hint from two
            // unlocked reads would let another cooperating process transition
            // between them and create a torn admission view.
            auto maintenance = std::make_unique<MaintenanceCoordinator>(
                "ndms-native-startup-reconciliation");
            auto runtime = runtime_mutation_admission_.try_acquire(
                "ndms-native-startup-reconciliation");
            if (!runtime.has_value()) {
                throw std::runtime_error(
                    "native startup runtime mutation admission is busy");
            }
            auto writer = admit_ndms_native_writer(
                ndms_native_observation_store_.state_directory(),
                std::move(maintenance),
                std::move(*runtime));
            if (writer.state != NdmsNativeWriterAdmissionState::admitted) {
                throw std::runtime_error(
                    "native startup writer admission failed");
            }
            // Before the inventory is judged: a process that died between
            // creating its WAL temporary and renaming it into place leaves a
            // name the inventory reads as unsafe, and without this sweep the
            // startup report below would say "unsafe" until the first write -
            // which the unsafe inventory itself refuses. The sweep is
            // noexcept, removes only this store's own dead-owner temporaries,
            // and an absent store is simply not its problem.
            ndms_native_import_wal_store_.sweep_orphaned_temporaries();
            ndms_native_delete_wal_store_.sweep_orphaned_temporaries();
            native_delete_readiness =
                ndms_native_delete_wal_store_.readiness();
            const auto native_import_inventory =
                ndms_native_import_wal_store_.try_inventory();
            native_import_readiness =
                summarize_ndms_native_import_readiness(
                    native_import_inventory);
            native_mutation_admission =
                summarize_ndms_native_mutation_admission(
                    native_import_inventory,
                    native_delete_readiness);

            // The removal crash window closes here and only here. A tunnel
            // deleted by an operator whose process then died leaves a durable
            // claim over a slot that is now free; the live caller learns of it
            // from removed_claim_survived, and nothing else would ever notice.
            // Skip unless this exact bounded snapshot proves a ready, empty
            // WAL. Busy, unsafe, I/O-failed and absent stores are unknown for
            // ownership retirement: `absent` is sufficient for a new writer
            // to publish exclusively, but it does not prove that no historical
            // claim still needs recovery. The recovery dispatcher retracts its
            // own claim, and a second remover racing it would turn that
            // retirement into a failure.
            const bool transaction_in_flight_or_unknown =
                !ndms_native_import_inventory_permits_ownership_reconciliation(
                    native_import_inventory);
            const auto reconciled =
                reconcile_ndms_native_ownership_claims(
                    ndms_native_ownership_store_,
                    transaction_in_flight_or_unknown,
                    ndms_native_interface_read_production_dependencies(),
                    native_delete_readiness);
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
            writer.lease.verify_held();
            ndms_native_import_journal_readiness_.store(
                native_import_readiness, std::memory_order_release);
            ndms_native_mutation_admission_.store(
                native_mutation_admission, std::memory_order_release);
        } catch (...) {
            // Startup inventory is observational. Even an unexpected local
            // allocation/runtime failure must fail the report closed without
            // taking down the already-working routing daemon.
            native_import_readiness =
                NdmsNativeImportJournalReadinessState::unavailable;
            native_mutation_admission =
                NdmsNativeMutationAdmissionState::unavailable;
            ndms_native_import_journal_readiness_.store(
                native_import_readiness, std::memory_order_release);
            ndms_native_mutation_admission_.store(
                native_mutation_admission, std::memory_order_release);
        }
        // Deliberately log only the collapsed enum. Inventory entries can
        // contain transaction identifiers and filenames, neither of which
        // belongs in the API or routine daemon logs.
        log.info(
            "Native import WAL startup observation: state={} (report-only; "
            "every operation still reacquires maintenance, runtime and "
            "cooperative native-writer guards).",
            ndms_native_import_journal_readiness_state_name(
                native_import_readiness));
        log.info(
            "Native delete WAL startup observation: state={} (report-only; "
            "ownership reconciliation requires clean cross-kind state).",
            ndms_native_delete_wal_readiness_name(
                native_delete_readiness));
        log.info(
            "Native mutation pre-body admission: state={} (redacted hint; "
            "the coordinator still reacquires and rechecks authority).",
            ndms_native_mutation_admission_state_name(
                native_mutation_admission));
#endif

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
    bool startup_firewall_recovery_needed = false;
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
        // boot. The shared runtime owner retains the one bounded recovery
        // operation until it reaches an exact terminal outcome.
        log.info("Firewall rules are not ready at startup: {}. "
                 "The service continues and will retry shortly.", e.what());
        startup_firewall_recovery_needed = true;
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
            startup_firewall_recovery_needed = true;
        }
    }

    if (startup_firewall_recovery_needed) {
        try {
            runtime_firewall_owner_->schedule(
                /*attempt=*/0U,
                runtime_generation_.load(std::memory_order_acquire),
                /*snat_recovery=*/{},
                /*prepared_catalog=*/{});
        } catch (const std::exception& error) {
            // Startup must remain available even if timer registration or an
            // owner-side allocation fails. Periodic health reconciliation can
            // still observe and repair the missing firewall generation.
            try {
                log.error(
                    "Could not hand off startup firewall recovery: {}. "
                    "The service continues without the delayed attempt.",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
            try {
                log.error(
                    "Could not hand off startup firewall recovery: unknown "
                    "error. The service continues without the delayed "
                    "attempt.");
            } catch (...) {
            }
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
    runtime_state_store_.set_routing_runtime_active(true);
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
    // An nfqws2 package transaction interrupted by the reboot is acted on
    // once the event loop runs and S80 has let go of the maintenance lease.
    schedule_nfqws_boot_recovery(0);
    schedule_nfqws_retention_backfill(0);
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
        cancel_nfqws_boot_recovery();
        cancel_nfqws_retention_backfill();
        cancel_remote_access_recovery_watchdog();
        reset_remote_access_retry_bridge();
#endif
        runtime_firewall_owner_->request_shutdown();
        runtime_mutation_admission_.shutdown();
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->cancel_retry();
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
        runtime_firewall_owner_->cancel_pending_work();
        runtime_firewall_owner_->pump_terminal_for_shutdown();
        blocking_executor_.cancel_pending();
        quiesce_resolver_stream_recovery();
        quiesce_runtime_mutations();
        runtime_firewall_owner_->shutdown_executor();
        runtime_firewall_owner_->pump_terminal_for_shutdown();
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->cancel_retry();
        scheduler_->cancel_all();
        runtime_firewall_owner_->reset_active();
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
            (void)routing_operation_owner_.clear();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: routing cleanup failed: {}",
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
        runtime_state_store_.set_routing_runtime_active(false);
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
    cancel_nfqws_boot_recovery();
    cancel_nfqws_retention_backfill();
    cancel_remote_access_recovery_watchdog();
    reset_remote_access_retry_bridge();
#endif
    // Stop the continuous forwarded-flow observer before closing admission to
    // the control loop or tearing down API/conntrack state.  An in-flight
    // observation is generation-fenced, but disabling it here also prevents a
    // late exact delete from racing normal shutdown.
    cancel_idle_stall_observer();
    cancel_meta_udp443_activation_cleanup();
    runtime_firewall_owner_->request_shutdown();
    runtime_mutation_admission_.shutdown();
    runtime_firewall_owner_->cancel_completion_watchdog();
    runtime_firewall_owner_->cancel_retry();
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
    runtime_firewall_owner_->cancel_pending_work();
    runtime_firewall_owner_->pump_terminal_for_shutdown();
    blocking_executor_.cancel_pending();
    // Admission is closed before quiescence, so new HTTP/SIGHUP writers are
    // rejected. Existing owners keep their token and may finish through the
    // control queue while this thread still owns the event-loop state.
    quiesce_resolver_stream_recovery();
    quiesce_runtime_mutations();
    runtime_firewall_owner_->shutdown_executor();
    runtime_firewall_owner_->pump_terminal_for_shutdown();
    runtime_firewall_owner_->cancel_completion_watchdog();
    runtime_firewall_owner_->cancel_retry();
    scheduler_->cancel_all();
    runtime_firewall_owner_->reset_active();
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

    (void)routing_operation_owner_.clear();
    firewall_->cleanup();
    committed_meta_udp443_fwmark_.reset();
    committed_meta_udp443_owned_mask_ = 0U;
    runtime_state_store_.set_routing_runtime_active(false);
    transition_runtime_or_throw(RuntimeState::stopped, "daemon shutdown complete");
    remove_pid_file();
}

void Daemon::stop() {
    list_refresh_tasks_.request_cancel_active();
    runtime_firewall_owner_->request_shutdown();
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
