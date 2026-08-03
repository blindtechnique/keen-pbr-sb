#pragma once

#include <algorithm>
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
#include "../dns/keenetic_dns.hpp"
#include "../dns/dns_txt_client.hpp"
#include "config_store.hpp"
#include "config_reload_coordinator.hpp"
#include "keenetic_dns_refresh_coordinator.hpp"
#include "../health/interface_probe.hpp"
#include "pid_file.hpp"
#include "../health/url_tester.hpp"
#include "../keenetic/internal_vpn_ingress_resolver.hpp"
#include "../keenetic/internal_vpn_runtime_target.hpp"
#include "../lists/list_set_usage.hpp"
#include "../routing/interface_monitor.hpp"
#include "../routing/firewall_state.hpp"
#include "../routing/netlink.hpp"
#include "../routing/policy_rule.hpp"
#include "../routing/route_table.hpp"
#include "../runtime/lifecycle_operation.hpp"
#include "../runtime/list_refresh_task.hpp"
#include "../runtime/periodic_task_metrics.hpp"
#include "../runtime/conntrack_manager.hpp"
#include "../runtime/idle_stall_detector.hpp"
#include "../runtime/udp_call_affinity.hpp"
#include "../runtime/interface_traffic_sampler.hpp"
#include "../runtime/runtime_state_machine.hpp"
#include "../runtime/runtime_mutation_admission.hpp"
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
struct NdmsCatalogSnapshot;
struct NdmsVpnServerServiceSnapshot;
enum class ResolverType;

#ifdef WITH_API
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
    // The init script probes the optional three-dimensional ipset type. A
    // missing legacy-kernel feature must disable only the iptables call
    // overlay, never the ordinary list-routing service.
    bool udp_call_affinity_ipset_available{true};
};

struct ListsRefreshExecutionResult {
    RemoteListsRefreshResult refresh_result;
    bool reloaded{false};
};

struct RemoteListRefreshTaskStartResult {
    bool accepted{false};
    ListRefreshTaskSnapshot task;
    std::string error;
};

enum class InternalVpnRuntimeResolutionState : std::uint8_t {
    verified,
    retained_verified_includes,
    degraded,
    authoritative_negative,
};

enum class NetfilterRefreshReason : std::uint8_t {
    full = 1U << 0U,
    nat_only = 1U << 1U,
};

struct InternalVpnRuntimeResolution {
    std::vector<InternalVpnServer> effective_servers;
    InternalVpnRuntimeResolutionState state{
        InternalVpnRuntimeResolutionState::degraded};
    std::vector<InternalVpnServer> verified_includes_for_lkg;
    std::vector<std::string> retain_verified_include_ndms_ids;
};

struct InternalVpnServiceRuntimeResolution {
    std::vector<InternalVpnRuntimeTarget> effective_targets;
    InternalVpnRuntimeResolutionState state{
        InternalVpnRuntimeResolutionState::degraded};
    std::vector<InternalVpnRuntimeTarget> verified_includes_for_lkg;
    std::vector<std::string> retain_verified_include_service_ids;
};

struct PreparedRuntimeInputs {
    Config config;
    OutboundMarkMap outbound_marks;
    // Exact immutable Keenetic DNS view prepared before the serialized
    // runtime commit. Firewall and resolver generation must consume this
    // value rather than observing the mutable shared RCI cache themselves.
    KeeneticDnsCacheView keenetic_dns;
    InternalVpnRuntimeResolution internal_vpn_resolution;
    InternalVpnServiceRuntimeResolution internal_vpn_service_resolution;
    bool remote_lists_refreshed{false};
};

enum class RemoteListPreparationMode {
    None,
    MissingOrInvalid,
    RefreshAll,
};

inline bool interface_event_requires_runtime_observation(
    const InterfaceMonitor::Event& event) {
    return event.observation_gap ||
           event.administrative_state_changed ||
           event.address_changed ||
           event.topology_changed;
}

inline bool interface_event_affects_managed_runtime(
    const Config& config,
    const std::vector<InternalVpnServer>& effective_internal_vpn_servers,
    const std::vector<InternalVpnRuntimeTarget>&
        effective_internal_vpn_service_targets,
    const std::string& interface_name) {
    const auto outbounds =
        config.outbounds.value_or(std::vector<Outbound>{});
    const bool is_managed_outbound = std::any_of(
        outbounds.begin(),
        outbounds.end(),
        [&interface_name](const Outbound& outbound) {
            return outbound.type == OutboundType::INTERFACE &&
                   outbound.interface.has_value() &&
                   *outbound.interface == interface_name;
        });
    const auto configured_internal_servers = config.route.has_value()
        ? config.route->internal_vpn_servers.value_or(
              std::vector<InternalVpnServer>{})
        : std::vector<InternalVpnServer>{};
    const auto matches_interface =
        [&interface_name](const InternalVpnServer& server) {
            return server.interface == interface_name;
        };
    const bool is_internal_vpn_interface =
        std::any_of(
            configured_internal_servers.begin(),
            configured_internal_servers.end(),
            matches_interface) ||
        std::any_of(
            effective_internal_vpn_servers.begin(),
            effective_internal_vpn_servers.end(),
            matches_interface);
    const bool service_inventory_configured =
        config.route.has_value() &&
        (!config.route->internal_vpn_services
              .value_or(std::vector<InternalVpnService>{})
              .empty() ||
         (config.route->inbound_interfaces.has_value() &&
          !config.route->inbound_interfaces->empty()));
    const bool is_internal_vpn_service_interface =
        std::any_of(
            effective_internal_vpn_service_targets.begin(),
             effective_internal_vpn_service_targets.end(),
             [&interface_name](const auto& target) {
                 const bool direct_ingress =
                     std::find(
                         target.verified_ingress_interfaces.begin(),
                         target.verified_ingress_interfaces.end(),
                         interface_name) !=
                     target.verified_ingress_interfaces.end();
                 const bool bridge_ingress =
                     std::any_of(
                         target.verified_bridge_ingress_interfaces.begin(),
                         target.verified_bridge_ingress_interfaces.end(),
                         [&interface_name](const auto& ingress) {
                             return ingress.interface == interface_name ||
                                    ingress.bridge_port == interface_name;
                         });
                 return direct_ingress || bridge_ingress;
             }) ||
        (service_inventory_configured &&
         internal_vpn_service_interface_may_affect_ingress(
             interface_name));
    return is_managed_outbound ||
           is_internal_vpn_interface ||
           is_internal_vpn_service_interface;
}

inline bool interface_event_affects_managed_runtime(
    const Config& config,
    const std::vector<InternalVpnServer>& effective_internal_vpn_servers,
    const std::string& interface_name) {
    return interface_event_affects_managed_runtime(
        config,
        effective_internal_vpn_servers,
        {},
        interface_name);
}

inline bool interface_event_affects_managed_runtime(
    const Config& config,
    const std::string& interface_name) {
    return interface_event_affects_managed_runtime(
        config, {}, {}, interface_name);
}

inline bool config_has_stable_internal_vpn_server_policy(
    const Config& config) {
    const auto configured_internal_servers = config.route.has_value()
        ? config.route->internal_vpn_servers.value_or(
              std::vector<InternalVpnServer>{})
        : std::vector<InternalVpnServer>{};
    return std::any_of(
        configured_internal_servers.begin(),
        configured_internal_servers.end(),
        [](const InternalVpnServer& server) {
            return server.ndms_id.has_value();
        });
}

inline bool config_requires_internal_vpn_service_inventory(
    const Config& config) {
    if (!config.route.has_value()) {
        return false;
    }
    const auto services = config.route->internal_vpn_services.value_or(
        std::vector<InternalVpnService>{});
    if (!services.empty()) {
        return true;
    }
    // With an explicit ingress allowlist, unconfigured native service pools
    // inherit bypass. They must be observed to keep a shared Home/Bridge
    // ingress from accidentally opting those clients into keen-pbr.
    return config.route->inbound_interfaces.has_value() &&
           !config.route->inbound_interfaces->empty();
}

inline bool config_has_native_vpn_catalog_policy(
    const Config& config) {
    return config_has_stable_internal_vpn_server_policy(config) ||
           config_requires_internal_vpn_service_inventory(config);
}

inline bool internal_vpn_resolution_requires_catalog_refresh(
    const Config& config,
    InternalVpnRuntimeResolutionState state) {
    return config_has_stable_internal_vpn_server_policy(config) &&
           state != InternalVpnRuntimeResolutionState::verified;
}

struct ResolverGenerationSnapshot {
    Config config;
    KeeneticDnsCacheView keenetic_dns;
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot;
    ResolverType resolver_type;
    ResolverIpv6Policy ipv6_policy;
    std::vector<std::string> trusted_dns_interfaces;
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
    // Returns false only when deferred control commits are already disabled
    // (startup rollback/shutdown) or the callback is empty. Callers which own
    // single-flight state can therefore release it without relying on a
    // completion callback that was never queued.
    bool post_control_task(std::function<void()> task,
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
    void handle_sigusr2();
    void schedule_netfilter_runtime_refresh(NetfilterRefreshReason reason);
    void schedule_owned_snat_health_check();
    void cancel_owned_snat_health_check();
    void check_owned_snat_health();
    void quiesce_runtime_mutations() noexcept;
    void handle_sighup();
    void defer_sighup_reload(ConfigReloadClaim claim);
    void complete_sighup_reload(ConfigReloadClaim claim,
                                std::shared_ptr<RuntimeMutationAdmission::Lease>
                                    mutation_lease,
                                bool allow_coalesced_rerun) noexcept;
    void handle_interface_monitor_events(uint32_t events);
    void reconnect_interface_monitor();
    void register_interface_monitor_fd();
    void unregister_interface_monitor_fd();
    void schedule_interface_monitor_reconnect_retry();
    void recover_internal_vpn_catalog_after_observation_gap();
    void handle_interface_event(const InterfaceMonitor::Event& event);
    bool refresh_iproute_and_firewall_runtime(
        std::size_t retry_attempt = 0,
        std::optional<InternalVpnRuntimeResolution>
            prepared_internal_vpn_resolution = std::nullopt,
        std::optional<InternalVpnServiceRuntimeResolution>
            prepared_internal_vpn_service_resolution = std::nullopt,
        bool schedule_catalog_refresh = true,
        OwnedSnatRecovery snat_recovery = {});
    void schedule_runtime_firewall_retry(std::size_t attempt,
                                         std::uint64_t runtime_generation,
                                         OwnedSnatRecovery snat_recovery);
    void cancel_runtime_firewall_retry();
    void schedule_resolver_reload_retry(std::size_t attempt,
                                        std::uint64_t runtime_generation);
    void cancel_resolver_reload_retry();
    void dispatch_event_fd(int fd, uint32_t events);
    void run_event_loop();

    // lifecycle and runtime apply
    void setup_static_routing();
    void reconcile_static_routing(RouteReconcileMode mode);
    // Runtime callers must deliberately choose preserving or destructive
    // semantics; an omitted mode is a compile-time error.
    void apply_firewall(
        FirewallApplyMode mode,
        std::shared_ptr<const ListCacheGenerationSnapshot>
            list_cache_snapshot = nullptr);
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
    void execute_committed_stale_flow_reconnect(
        std::uint64_t committed_runtime_generation,
        bool previous_runtime_active,
        bool exact_forwarded_scope,
        std::uint32_t owned_mask,
        const ConntrackDestinationRetirementCoverage& normal_coverage,
        const ConntrackDestinationRetirementCoverage& aggressive_coverage)
        noexcept;
    void reset_idle_stall_observer(bool schedule_if_eligible) noexcept;
    void cancel_idle_stall_observer() noexcept;
    void schedule_idle_stall_observer_after(
        std::chrono::seconds delay) noexcept;
    void run_idle_stall_observer() noexcept;
    void commit_idle_stall_observation(
        std::uint64_t expected_runtime_generation,
        std::uint64_t expected_coverage_generation,
        std::uint32_t owned_mask,
        ConntrackFlowObservation observation,
        std::vector<std::string> observed_local_interface_addresses,
        std::vector<std::string> destination_selectors,
        std::vector<UdpCallAffinityTarget> call_affinity_targets,
        bool ipv6_enabled,
        bool coverage_complete,
        std::string failure_detail);
    void dispatch_udp_call_affinity_mutations(
        std::uint64_t expected_runtime_generation,
        std::uint64_t expected_coverage_generation,
        std::uint32_t owned_mask,
        bool ipv6_enabled,
        UdpCallAffinityDetector::TimePoint decision_deadline,
        std::vector<UdpCallAffinityDecision> decisions);
    PreparedRuntimeInputs prepare_runtime_inputs(const Config& config,
                                                  RemoteListPreparationMode list_mode =
                                                      RemoteListPreparationMode::RefreshAll);
    KeeneticDnsCacheView prepare_keenetic_dns_view(
        const Config& config,
        bool allow_refresh,
        bool force_refresh = false) const;
    InternalVpnRuntimeResolution resolve_internal_vpn_servers_for_runtime(
        const Config& config,
        bool allow_catalog_refresh,
        const std::vector<InternalVpnServer>& previous_effective = {});
    InternalVpnRuntimeResolution resolve_internal_vpn_servers_for_runtime(
        const Config& config,
        const NdmsCatalogSnapshot& snapshot,
        const std::vector<InternalVpnServer>& previous_effective = {});
    std::vector<InternalVpnServer>
    snapshot_internal_vpn_verified_includes_lkg() const;
    void update_internal_vpn_verified_includes_lkg(
        const InternalVpnRuntimeResolution& resolution) noexcept;
    InternalVpnRuntimeResolution
    prepare_internal_vpn_server_resolution_from_cache();
    InternalVpnServiceRuntimeResolution
    resolve_internal_vpn_services_for_runtime(
        const Config& config,
        bool allow_catalog_refresh,
        const std::vector<InternalVpnRuntimeTarget>&
            previous_verified_includes = {});
    InternalVpnServiceRuntimeResolution
    resolve_internal_vpn_services_for_runtime(
        const Config& config,
        const NdmsVpnServerServiceSnapshot& snapshot,
        const std::vector<InternalVpnRuntimeTarget>&
            previous_verified_includes = {});
    std::vector<InternalVpnRuntimeTarget>
    snapshot_internal_vpn_service_verified_includes_lkg() const;
    void update_internal_vpn_service_verified_includes_lkg(
        const InternalVpnServiceRuntimeResolution& resolution) noexcept;
    InternalVpnServiceRuntimeResolution
    prepare_internal_vpn_service_resolution_from_cache();
    void schedule_internal_vpn_catalog_refresh();
    void schedule_internal_vpn_catalog_refresh_if_needed(
        InternalVpnRuntimeResolutionState interface_state,
        InternalVpnRuntimeResolutionState service_state =
            InternalVpnRuntimeResolutionState::verified);
    void schedule_internal_vpn_catalog_refresh_retry(
        std::uint64_t runtime_generation);
    void cancel_internal_vpn_catalog_refresh_retry();
    void apply_config_with_rollback(const Config& next_config,
                                    bool& rolled_back,
                                    bool refresh_remote_lists = true);
    void start_routing_runtime();
    void stop_routing_runtime();
    void restart_routing_runtime();
    bool routing_runtime_active() const;
    OwnedConntrackCleanupSnapshot
    snapshot_owned_conntrack_marks() const;
    void warn_conntrack_unavailable_once();
    ConntrackCleanupSummary cleanup_owned_conntrack_snapshot(
        const OwnedConntrackCleanupSnapshot& snapshot,
        const char* context,
        bool allow_retry = true);
    void cleanup_owned_conntrack_marks(const char* context);
    void reconcile_native_vpn_direct_egress_conntrack(
        const std::vector<FirewallSourceEgressSnatSelector>& selectors);
    void schedule_owned_conntrack_cleanup_retry(
        const OwnedConntrackCleanupSnapshot& snapshot,
        std::vector<std::uint32_t> remaining_marks,
        std::size_t no_progress_attempt = 0);
    void run_owned_conntrack_cleanup_retry();
    void cancel_owned_conntrack_cleanup_retry();
    void complete_pending_snat_recovery_before_generation_change();
    bool run_system_resolver_hook(std::string_view action,
                                  bool manage_ipc_gate = true);
    bool run_system_resolver_hook_stream(std::string_view action);
    // Stream the already prepared resolver generation. Its list-cache lease
    // pins every remote body until the worker and post-stream verification
    // have completed, without holding a daemon lock across the IPC wait.
    bool run_system_resolver_hook_stream_prepared(
        std::string_view action,
        bool rebuild_snapshot);
    bool run_system_resolver_hook_reload();
    bool wait_for_resolver_stream_epoch(std::uint64_t expected_epoch,
                                        std::chrono::milliseconds timeout);
    void schedule_lists_autoupdate();
    // Re-applies rules after a failed startup attempt, backing off each time.
    void schedule_startup_firewall_retry(
        int attempt = 1,
        std::optional<std::uint64_t> runtime_generation = std::nullopt,
        std::shared_ptr<const ListCacheGenerationSnapshot>
            list_cache_snapshot = nullptr);
    // Periodic HTTP probe of every interface outbound.
    void schedule_interface_probe();
    // Weekly refresh of the ready-made list catalogue.
    void schedule_catalog_refresh();
    // Runs a probe round immediately, for the manual refresh button.
    void probe_interfaces_now();
    CacheCommitCallback make_guarded_cache_commit_callback();
    void refresh_lists_and_maybe_reload_async(
        std::string source = "autoupdate");
    RemoteListRefreshTaskStartResult start_remote_list_refresh_task(
        bool reload,
        std::string source);
    void commit_remote_list_refresh_task_result(
        std::string task_id,
        ListRefreshCancellationToken cancellation,
        Config config_snapshot,
        bool runtime_active_snapshot,
        std::uint64_t generation,
        bool reload,
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
    void schedule_keenetic_dns_refresh();
    bool commit_keenetic_dns_refresh_result(
        std::uint64_t generation,
        const KeeneticDnsRefreshResult& result);
    void reset_resolver_actual_state();
    void commit_resolver_hash_probe_result(const std::string& resolver_addr,
                                           std::uint64_t generation,
                                           std::optional<ResolverConfigHashProbeResult> probe_result,
                                           std::optional<std::int64_t> probe_completed_ts,
                                           TraceId trace_id,
                                           std::shared_ptr<PeriodicTaskRunToken>
                                               task_metrics);

#ifdef WITH_API
    // API integration
    void setup_api();
    RuntimeMutationAdmission::Lease acquire_runtime_mutation_or_throw(
        std::string label,
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
    void commit_resolver_generation_snapshot(
        ResolverGenerationSnapshot snapshot);
    std::shared_ptr<const ListCacheGenerationSnapshot>
    capture_relevant_list_cache_generation(const Config& config) const;
    ResolverGenerationSnapshot make_resolver_generation_snapshot(
        std::shared_ptr<const ListCacheGenerationSnapshot>
            list_cache_snapshot = nullptr);
    // Schedule (or reschedule) the periodic refresh of resolver_config_hash_actual_.
    void schedule_resolver_config_hash_actual_refresh();
    void schedule_resolver_config_hash_actual_after(
        std::chrono::seconds delay,
        const char* task_name);
    RuntimeStateSnapshot build_runtime_state_snapshot() const;
    void publish_runtime_state();
    void transition_runtime_or_throw(RuntimeState next, const char* reason);

    // Lists autoupdate state
    int lists_autoupdate_task_id_{-1};
    // Periodic refresh task for cached Keenetic DNS server values.
    int keenetic_dns_refresh_task_id_{-1};
    // Single timer for either the steady resolver poll or convergence retry.
    int resolver_config_hash_actual_task_id_{-1};
    // Exponential retry step for resolver convergence probes.
    std::uint32_t resolver_config_hash_actual_retry_attempt_{0};
    // One debounce window coalesces firmware mangle/full and nat-only events.
    int netfilter_refresh_task_id_{-1};
    std::uint8_t pending_netfilter_refresh_reasons_{0};
    // Low-frequency fallback for firmware NAT rebuilds that do not invoke the
    // netfilter hook. The callback runs on the control/event-loop thread.
    int owned_snat_health_task_id_{-1};
    // One bounded retry chain for races with NDMS firewall publication. The
    // coordinator owns its timer slot and the latched owned-SNAT request.
    RuntimeFirewallRetryCoordinator runtime_firewall_retry_;
    // Best-effort targeted conntrack retirement can be incomplete under a
    // short embedded-router command budget. Retain only exact owned marks and
    // retry them on this runtime generation; never flush global conntrack.
    int owned_conntrack_cleanup_retry_task_id_{-1};
    std::optional<OwnedConntrackCleanupRetry>
        pending_owned_conntrack_cleanup_retry_;
    // Separate bounded repair chain for a resolver hook that failed after
    // routing/firewall COMMIT. A firewall retry cannot repair dnsmasq.
    int resolver_reload_retry_task_id_{-1};
    // A failed Keenetic DNS rollback must restore firewall before resolver
    // bytes may advance. Unlike retry_pending(), this generation latch remains
    // set after bounded firewall retries are exhausted and is released only by
    // a verified successful firewall reconciliation or a new runtime generation.
    ResolverAfterFirewallRecoveryGate resolver_after_firewall_gate_;
    // Retry task for interface monitor netlink reconnect after failure.
    int interface_monitor_reconnect_task_id_{-1};
    // Bounded one-shot observer for a client reusing a long-idle forwarded
    // flow which no longer receives replies. It is armed only for explicitly
    // selected strong-reconnect lists and never performs a broad conntrack
    // flush. All detector state belongs to the control/event-loop thread.
    int idle_stall_observer_task_id_{-1};
    IdleStallDetector idle_stall_detector_;
    UdpCallAffinityDetector udp_call_affinity_detector_;
    std::vector<std::string> idle_stall_destination_selectors_;
    std::vector<std::string> udp_call_affinity_destination_selectors_;
    std::atomic<bool> idle_stall_observer_enabled_{false};
    std::atomic<bool> idle_stall_observer_inflight_{false};
    // Pair publication and exact conntrack retirement execute on the bounded
    // worker pool. Detector reservations remain control-loop owned while this
    // single-flight mutation is outstanding.
    std::atomic<bool> udp_call_affinity_mutation_inflight_{false};
    // Serializes the worker's live pair/conntrack mutation with every
    // firewall apply or cleanup lifecycle boundary. Generation fences decide
    // whether queued work is still eligible after acquiring this barrier.
    TracedMutex udp_call_affinity_mutation_mutex_;
    std::atomic<std::uint64_t> idle_stall_coverage_generation_{1};

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

    // Snapshot stores
    ConfigStore config_store_;
    ListService list_service_;
    RuntimeStateStore runtime_state_store_;
    LifecycleOperationStore lifecycle_operation_store_;
    LifecycleOperationCoordinator lifecycle_operations_{lifecycle_operation_store_};
    ListRefreshTaskCoordinator list_refresh_tasks_;
    RuntimeStateMachine runtime_state_machine_;

    // Event-loop-owned controller state
    Config config_;
    // Event-loop-owned DNS snapshot committed with config_. The shared DNS
    // cache is observational/prepare state only and may advance on a stale
    // worker; active runtime consumers must never read it directly.
    KeeneticDnsCacheView active_keenetic_dns_;
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
    // Effective content analyzed immediately before the current firewall
    // generation was populated. This follows normalized list entries rather
    // than URL/file metadata and retains only a bounded static selector set.
    AppliedListContentState applied_list_content_state_;
    ConntrackManager conntrack_manager_;
    bool conntrack_unavailable_warning_emitted_{false};
    URLTester url_tester_;
    // Latency for every interface outbound, including native tunnels the
    // firmware owns and standalone outbounds urltest never looks at.
    InterfaceProbe interface_probe_;
    OutboundMarkMap outbound_marks_;
    // Runtime-only mapping from stable NDMS identities to current kernel
    // ingress names. Persisted configuration remains unchanged.
    std::vector<InternalVpnServer> resolved_internal_vpn_servers_;
    // API preparation runs outside the control loop. It may reuse only a
    // thread-safe, previously verified, include-only stable binding. Exclusion
    // bypasses and degraded/legacy observations are never stored here.
    mutable TracedMutex internal_vpn_lkg_mutex_;
    std::vector<InternalVpnServer>
        internal_vpn_verified_includes_lkg_
            GUARDED_BY(internal_vpn_lkg_mutex_);
    std::vector<InternalVpnRuntimeTarget>
        resolved_internal_vpn_service_targets_;
    // Last source-scoped native VPN SNAT contract committed to the firewall.
    // A contract change retires only flows from the changed source pools so
    // old un-NATed conntrack entries cannot mask a successful repair.
    std::vector<FirewallSourceEgressSnatSelector>
        applied_native_vpn_direct_egress_snat_selectors_;
    std::vector<InternalVpnRuntimeTarget>
        internal_vpn_service_verified_includes_lkg_
            GUARDED_BY(internal_vpn_lkg_mutex_);
    // Registered before scheduler/executor members so their reverse-order
    // destruction completes before this pull-only metrics registry is freed.
    PeriodicTaskMetricsRegistry periodic_task_metrics_{
        std::vector<std::string>{
            "resolver-hash-refresh",
            "keenetic-dns-refresh",
            "owned-snat-health",
            "interface-probe",
            "interface-traffic-sample",
        }};
    std::unique_ptr<Scheduler> scheduler_;
    std::unique_ptr<UrltestManager> urltest_manager_;
    RuntimeIncidentLatch urltest_apply_incidents_{3};
    // Event-loop-owned notification latches. Recovery itself is controlled by
    // the existing generation-fenced retry state machines; these latches only
    // prevent transient or repeated failures from flooding the WebUI bell.
    RuntimeIncidentLatch runtime_firewall_incidents_{1};
    RuntimeIncidentLatch internal_vpn_catalog_incidents_{5};
    BlockingExecutor blocking_executor_{2, 64};
    // Resolver hooks can synchronously request a generated configuration.
    // Keep command execution, streaming and TXT probes on independent queues.
    BlockingExecutor resolver_hook_executor_{1, 16};
    BlockingExecutor resolver_stream_executor_{1, 16};
    BlockingExecutor resolver_io_executor_{1, 32};
    std::atomic<std::uint64_t> runtime_generation_{1};
    KeeneticDnsRefreshCoordinator keenetic_dns_refresh_coordinator_;
    std::atomic<bool> ipc_resolver_hook_inflight_{false};
    std::atomic<bool> resolver_hash_refresh_inflight_{false};
    // One authority admits every externally requested runtime mutation. API
    // requests own move-only leases; asynchronous SIGHUP shares one lease
    // until the reload coordinator chooses its single completion owner.
    RuntimeMutationAdmission runtime_mutation_admission_;
    ConfigReloadCoordinator sighup_reload_coordinator_;
    CoalescedSingleFlightGate internal_vpn_catalog_refresh_gate_;
    int internal_vpn_catalog_refresh_retry_task_id_{-1};
    std::size_t internal_vpn_catalog_refresh_retry_attempt_{0};
    std::atomic<std::uint64_t> resolver_stream_epoch_{0};
    std::atomic<std::uint64_t> resolver_stream_completed_epoch_{0};
    TracedMutex system_resolver_hook_mutex_;
    // Legacy cache-publication serialization. Resolver/firewall consumers no
    // longer hold the shared side while dnsmasq performs its IPC stream: each
    // transaction owns an immutable CacheManager generation lease instead.
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
