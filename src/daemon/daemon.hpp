#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <sys/types.h>

#include "../config/config.hpp"
#include "../dns/dns_txt_client.hpp"
#include "config_store.hpp"
#include "../health/interface_probe.hpp"
#include "pid_file.hpp"
#include "../health/url_tester.hpp"
#include "../routing/interface_monitor.hpp"
#include "../routing/firewall_state.hpp"
#include "../routing/netlink.hpp"
#include "../routing/policy_rule.hpp"
#include "../routing/route_table.hpp"
#include "../runtime/lifecycle_operation.hpp"
#include "../runtime/conntrack_manager.hpp"
#include "../runtime/interface_traffic_sampler.hpp"
#include "../runtime/runtime_state_machine.hpp"
#include "../firewall/firewall.hpp"
#include "../util/blocking_executor.hpp"
#include "../util/ipv6_support.hpp"
#include "../util/traced_mutex.hpp"
#include "list_service.hpp"
#include "runtime_recovery_policy.hpp"
#include "runtime_state_store.hpp"
#include "resolver_sync_state_machine.hpp"
#include "system_resolver_hook.hpp"

namespace keen_pbr3 {

class Firewall;
class Scheduler;
class UrltestManager;
struct UrltestSelectionChange;
class DnsProbeServer;
struct DnsProbeEvent;
class ConntrackEventMonitor;
enum class ResolverType;

#ifdef WITH_API
enum class ConfigOperationState : uint8_t;
class ApiServer;
struct ApiContext;
class SseBroadcaster;
class StatusStream;
struct ConfigApplyResult;
struct ListRefreshOperationResult;

struct InterfaceTrafficTargetPlan {
    std::set<std::string> reported;
    std::set<std::string> removed;
};

inline InterfaceTrafficTargetPlan plan_interface_traffic_targets(
    const std::set<std::string>& active,
    const std::set<std::string>& previously_sampled) {
    InterfaceTrafficTargetPlan plan;
    plan.reported = active;
    plan.reported.insert(
        previously_sampled.begin(), previously_sampled.end());
    for (const auto& name : previously_sampled) {
        if (active.find(name) == active.end()) {
            plan.removed.insert(name);
        }
    }
    return plan;
}

inline std::vector<std::string> interface_traffic_targets_from_config(
    const Config& config) {
    std::vector<std::string> interface_names;
    if (!config.outbounds) {
        return interface_names;
    }
    interface_names.reserve(config.outbounds->size());
    for (const auto& outbound : *config.outbounds) {
        if (outbound.type == OutboundType::INTERFACE &&
            outbound.interface) {
            interface_names.push_back(*outbound.interface);
        }
    }
    return interface_names;
}
#endif

class DaemonError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Callback for file descriptor events
using FdCallback = std::function<void(uint32_t events)>;

// Options controlling daemon runtime behavior
struct DaemonOptions {
    bool no_api{false};
    bool use_raw_prerouting{false};
};

struct ListsRefreshExecutionResult {
    RemoteListsRefreshResult refresh_result;
    bool reloaded{false};
};

struct PreparedRuntimeInputs {
    Config config;
    OutboundMarkMap outbound_marks;
    bool remote_lists_refreshed{false};
};

enum class RemoteListPreparationMode {
    None,
    MissingOrInvalid,
    RefreshAll,
};

struct ResolverGenerationSnapshot {
    Config config;
    ResolverType resolver_type;
    ResolverIpv6Policy ipv6_policy;
    std::string expected_hash;
    std::uint64_t generation{0};
    std::uint64_t stream_epoch{0};
};

// Helper to get tag from any outbound variant
std::string get_outbound_tag(const Outbound& ob);

// Find an outbound by tag, returning pointer or nullptr
const Outbound* find_outbound(const std::vector<Outbound>& outbounds,
                               const std::string& tag);

// Epoll-based daemon that owns all runtime subsystems.
// Handles signal dispatch, routing, firewall, urltest, and API lifecycle.
class Daemon {
public:
    Daemon(Config config,
           std::string config_path,
           DaemonOptions opts,
           HookCommandExecutor hook_command_executor = default_hook_command_executor);
    ~Daemon();

    // Non-copyable, non-movable
    Daemon(const Daemon&) = delete;
    Daemon& operator=(const Daemon&) = delete;
    Daemon(Daemon&&) = delete;
    Daemon& operator=(Daemon&&) = delete;

    // Register an additional file descriptor for epoll monitoring.
    void add_fd(int fd,
                uint32_t events,
                FdCallback cb,
                bool wait_for_completion = true,
                const std::string& label = "");

    // Remove a previously registered file descriptor.
    void remove_fd(int fd,
                   bool wait_for_completion = true,
                   const std::string& label = "");

    // Serialize execution of control operations in event loop.
    void enqueue_control_task(std::function<void()> task,
                              bool wait_for_completion = false,
                              const std::string& label = "");

    // Backward-compatible alias for enqueue_control_task.
    void enqueue_control_command(std::function<void()> command,
                                 bool wait_for_completion = false,
                                 const std::string& label = "");

    // Post a task to the event loop, always deferred to the next iteration.
    // Unlike enqueue_control_task, never executes inline even when called from
    // the event loop thread. Safe to call while holding any lock — the posted
    // task only runs after the current event-loop iteration completes and all
    // caller locks have been released. Use this for callbacks that must not
    // run re-entrantly inside the current controller action.
    void post_control_task(std::function<void()> task,
                           const std::string& label = "");

    // Run the daemon lifecycle: startup, event loop, shutdown.
    void run();

    // Request the event loop to stop.
    void stop();

    // Returns true if the daemon is currently running.
    bool running() const;

private:
    // control loop and fd registration
    void setup_signals();
    void handle_signal();
    void setup_control_channel();
    void handle_control_commands();
    void setup_ipc_control_socket();
    void handle_ipc_control_socket();
    void remove_ipc_control_socket() noexcept;
    void wake_control_loop();
    bool is_event_loop_thread() const;

    // Signal handlers
    void handle_sigusr1();
    void schedule_sigusr1_runtime_refresh();
    void handle_sighup();
    void handle_interface_monitor_events(uint32_t events);
    void reconnect_interface_monitor();
    void register_interface_monitor_fd();
    void unregister_interface_monitor_fd();
    void schedule_interface_monitor_reconnect_retry();
    void handle_interface_event(const InterfaceMonitor::Event& event);
    bool is_interface_outbound_in_use(const std::string& interface_name) const;
    void refresh_iproute_and_firewall_runtime(std::size_t retry_attempt = 0);
    void schedule_runtime_firewall_retry(std::size_t attempt,
                                         std::uint64_t runtime_generation);
    void cancel_runtime_firewall_retry();
    void dispatch_event_fd(int fd, uint32_t events);
    void run_event_loop();

    // lifecycle and runtime apply
    void setup_static_routing();
    void reconcile_static_routing();
    // Runtime callers must deliberately choose preserving or destructive
    // semantics; an omitted mode is a compile-time error.
    void apply_firewall(FirewallApplyMode mode);
    void normalize_urltest_selections();
    void register_urltest_outbounds();
    void handle_urltest_selection_change(
        const UrltestSelectionChange& change,
        std::uint64_t expected_runtime_generation);
    void commit_urltest_probe_results(const std::string& urltest_tag,
                                      std::uint64_t probe_generation,
                                      std::map<std::string, URLTestResult> results,
                                      TraceId trace_id);
    void apply_config(Config config, bool refresh_remote_lists = true);
    void apply_prepared_runtime_inputs(PreparedRuntimeInputs prepared);
    PreparedRuntimeInputs prepare_runtime_inputs(const Config& config,
                                                  RemoteListPreparationMode list_mode =
                                                      RemoteListPreparationMode::RefreshAll);
    void apply_config_with_rollback(const Config& next_config,
                                    bool& rolled_back,
                                    bool refresh_remote_lists = true);
    void reload_from_disk();
    void start_routing_runtime();
    void stop_routing_runtime();
    void restart_routing_runtime();
    bool routing_runtime_active() const;
    void warn_conntrack_unavailable_once();
    bool run_system_resolver_hook(std::string_view action,
                                  bool manage_ipc_gate = true);
    bool run_system_resolver_hook_stream(std::string_view action);
    bool run_system_resolver_hook_reload();
    bool wait_for_resolver_stream_epoch(std::uint64_t expected_epoch,
                                        std::chrono::milliseconds timeout);
    void schedule_lists_autoupdate();
    // Re-applies rules after a failed startup attempt, backing off each time.
    void schedule_startup_firewall_retry(
        int attempt = 1,
        std::optional<std::uint64_t> runtime_generation = std::nullopt);
    // Periodic HTTP probe of every interface outbound.
    void schedule_interface_probe();
    // Weekly refresh of the ready-made list catalogue.
    void schedule_catalog_refresh();
    // Runs a probe round immediately, for the manual refresh button.
    void probe_interfaces_now();
    ListsRefreshExecutionResult execute_remote_list_refresh(
        const std::set<std::string>* target_lists = nullptr,
        std::string_view source = "service");
    void refresh_lists_and_maybe_reload();
    void refresh_lists_and_maybe_reload_async(std::string source = "autoupdate");
    void commit_lists_refresh_async_result(Config config_snapshot,
                                           bool runtime_active_snapshot,
                                           std::uint64_t generation,
                                           std::optional<RemoteListsRefreshResult> refresh_result,
                                           std::string error,
                                           std::string source,
                                           TraceId trace_id);

    // PID file management
    void write_pid_file();
    void remove_pid_file();

    // state publication and resolver sync
    void refresh_resolver_config_hash_actual_async();
    void maybe_schedule_resolver_config_hash_actual_refresh();
    void schedule_resolver_config_hash_actual_retry();
    void schedule_keenetic_dns_refresh();
    bool refresh_keenetic_dns_cache(bool force_refresh);
    void reset_resolver_actual_state();
    void commit_resolver_hash_probe_result(const std::string& resolver_addr,
                                           std::uint64_t generation,
                                           std::optional<ResolverConfigHashProbeResult> probe_result,
                                           std::optional<std::int64_t> probe_completed_ts,
                                           TraceId trace_id);

#ifdef WITH_API
    // API integration
    void setup_api();
    void finish_config_operation();
    void begin_config_operation_or_throw(ConfigOperationState state,
                                         const char* reason,
                                         bool require_runtime_running,
                                         bool require_runtime_stopped);
    ConfigApplyResult apply_validated_config_via_control_task(
        Config config,
        std::string saved_config_json);
    void run_runtime_control_operation_or_throw(const std::string& label,
                                                const char* operation_name,
                                                std::function<void()> task);
    ListRefreshOperationResult refresh_lists_via_api(std::optional<std::string> requested_name);
    void setup_conntrack_events();
    void handle_conntrack_events(uint32_t events);
    void publish_conntrack_revision();
    void teardown_conntrack_events();
    void schedule_interface_traffic_sampling();
    void sample_interface_traffic_now();
    void replace_interface_traffic_targets(
        std::string source,
        std::vector<std::string> interface_names);
    void refresh_interface_traffic_config_targets(const Config& config);
#endif

    // DNS probe integration
    void setup_dns_probe();
    void teardown_dns_probe();
    void handle_dns_probe_query_event(const DnsProbeEvent& event);
    void handle_dns_probe_udp_events(uint32_t events);
    void handle_dns_probe_tcp_listener_events(uint32_t events);
    void handle_dns_probe_tcp_client_events(int client_fd, uint32_t events);
    void handle_dns_probe_tcp_timer_events(uint32_t events);

    ResolverSyncStateMachine resolver_sync_;
    // Timestamp captured when /api/config/save apply starts (server authoritative).
    std::atomic<std::int64_t> apply_started_ts_{0};

    // Recompute resolver_config_hash_ from current config/cache state
    void update_resolver_config_hash();
    ResolverGenerationSnapshot make_resolver_generation_snapshot();
    // Schedule (or reschedule) the periodic refresh of resolver_config_hash_actual_.
    void schedule_resolver_config_hash_actual_refresh();
    void schedule_resolver_config_hash_actual_after(
        std::chrono::seconds delay,
        const char* task_name);
    RuntimeStateSnapshot build_runtime_state_snapshot() const;
    void publish_runtime_state(bool reconcile_status_stream = true);
    void transition_runtime_or_throw(RuntimeState next, const char* reason);

    // Lists autoupdate state
    int lists_autoupdate_task_id_{-1};
    // Periodic refresh task for cached Keenetic DNS server values.
    int keenetic_dns_refresh_task_id_{-1};
    // Single timer for either the steady resolver poll or convergence retry.
    int resolver_config_hash_actual_task_id_{-1};
    // Exponential retry step for resolver convergence probes.
    std::uint32_t resolver_config_hash_actual_retry_attempt_{0};
    // Debounced runtime refresh triggered by SIGUSR1.
    int sigusr1_refresh_task_id_{-1};
    // One bounded retry chain for races with NDMS firewall publication.
    int runtime_firewall_retry_task_id_{-1};
    // Retry task for interface monitor netlink reconnect after failure.
    int interface_monitor_reconnect_task_id_{-1};

    // Epoll state
    int epoll_fd_{-1};
    int signal_fd_{-1};
    std::atomic<bool> running_{false};
    std::atomic<std::thread::id> event_loop_thread_id_{};
    std::atomic<bool> event_loop_active_{false};
    std::atomic<bool> accept_posted_control_tasks_{false};

    struct FdEntry {
        int fd;
        FdCallback callback;
    };
    mutable TracedMutex fd_entries_mutex_;
    std::vector<FdEntry> fd_entries_ GUARDED_BY(fd_entries_mutex_);

    PidFile pid_file_;
    int control_fd_{-1};
    int ipc_control_fd_{-1};
    gid_t ipc_control_group_id_{static_cast<gid_t>(-1)};
    std::string ipc_control_socket_path_;
    struct ControlTask {
        std::function<void()> callback;
        std::string label;
        TraceId trace_id{0};
    };
    TracedMutex control_tasks_mutex_;
    std::vector<ControlTask> control_tasks_ GUARDED_BY(control_tasks_mutex_);

#ifdef WITH_API
    TracedMutex config_op_mutex_;
    std::condition_variable_any config_op_cv_;
    std::atomic<ConfigOperationState> config_op_state_{static_cast<ConfigOperationState>(0)};
#endif

    // Snapshot stores
    ConfigStore config_store_;
    ListService list_service_;
    RuntimeStateStore runtime_state_store_;
    LifecycleOperationStore lifecycle_operation_store_;
    LifecycleOperationCoordinator lifecycle_operations_{lifecycle_operation_store_};
    RuntimeStateMachine runtime_state_machine_;

    // Event-loop-owned controller state
    Config config_;
    std::string config_path_;
    DaemonOptions opts_;

    // Subsystems
    std::unique_ptr<Firewall> firewall_;
    std::unique_ptr<InterfaceMonitor> interface_monitor_;
    std::optional<int> interface_monitor_fd_;
    NetlinkManager netlink_;
    RouteTable route_table_;
    PolicyRuleManager policy_rules_;
    FirewallState firewall_state_;
    ConntrackManager conntrack_manager_;
    bool conntrack_unavailable_warning_emitted_{false};
    URLTester url_tester_;
    // Latency for every interface outbound, including native tunnels the
    // firmware owns and standalone outbounds urltest never looks at.
    InterfaceProbe interface_probe_;
    OutboundMarkMap outbound_marks_;
    std::unique_ptr<Scheduler> scheduler_;
    std::unique_ptr<UrltestManager> urltest_manager_;
    RuntimeIncidentLatch urltest_apply_incidents_{3};
    BlockingExecutor blocking_executor_{2, 64};
    // Resolver hooks can synchronously request a generated configuration.
    // Keep command execution, streaming and TXT probes on independent queues.
    BlockingExecutor resolver_hook_executor_{1, 16};
    BlockingExecutor resolver_stream_executor_{1, 16};
    BlockingExecutor resolver_io_executor_{1, 32};
    std::atomic<std::uint64_t> runtime_generation_{1};
    std::atomic<bool> remote_list_refresh_inflight_{false};
    std::atomic<bool> ipc_mutation_inflight_{false};
    std::atomic<bool> ipc_resolver_hook_inflight_{false};
    std::atomic<bool> resolver_hash_refresh_inflight_{false};
    std::atomic<std::uint64_t> resolver_stream_epoch_{0};
    std::atomic<std::uint64_t> resolver_stream_completed_epoch_{0};
    TracedMutex system_resolver_hook_mutex_;
    // A resolver generation hashes and streams the same immutable view of
    // list-cache files. Remote refreshes take the exclusive side; the reload
    // coordinator and its stream worker share the read side.
    TracedSharedMutex resolver_cache_snapshot_mutex_;
    // One immutable generation is shared with the stream worker. This avoids
    // copying the full configuration (including large inline lists) once in
    // the IPC handler and again into the worker closure.
    std::shared_ptr<const ResolverGenerationSnapshot>
        resolver_generation_snapshot_;
    // Multiple open pages can request the same manual probe at once. Keep at
    // most one queued/running round so a weak router never forks duplicate
    // health checks for a single click or refresh cycle.
    std::atomic<bool> manual_probe_inflight_{false};

#ifdef WITH_API
    std::unique_ptr<ApiServer> api_server_;
    std::unique_ptr<ApiContext> api_ctx_;
    std::unique_ptr<SseBroadcaster> dns_test_broadcaster_;
    std::unique_ptr<StatusStream> status_stream_;
    std::unique_ptr<ConntrackEventMonitor> conntrack_event_monitor_;
    InterfaceTrafficSampler interface_traffic_sampler_;
    std::mutex interface_traffic_targets_mutex_;
    std::map<std::string, std::set<std::string>>
        interface_traffic_targets_by_source_;
    std::set<std::string> traffic_sampled_interfaces_;
    bool traffic_sampling_active_{false};
    std::uint64_t conntrack_revision_{0};
    int conntrack_publish_task_id_{-1};
#endif

    std::unique_ptr<DnsProbeServer> dns_probe_server_;
    HookCommandExecutor hook_command_executor_;
    bool routing_runtime_active_{true};
};

} // namespace keen_pbr3
