#pragma once

#ifdef WITH_API

#include "generated/api_types.hpp"

#include "../cmd/test_routing.hpp"
#include "../config/config.hpp"
#include "../daemon/config_store.hpp"
#include "../health/routing_health.hpp"
#include "../keenetic/ndms_native_cooperative_delete.hpp"
#include "../keenetic/ndms_native_import_readiness.hpp"
#include "../keenetic/ndms_native_cooperative_import.hpp"
#include "../keenetic/ndms_native_inventory_projection.hpp"
#include "../log/logger.hpp"
#include "../runtime/lifecycle_operation.hpp"
#include "../runtime/runtime_mutation_admission.hpp"
#include "../update/maintenance_lock.hpp"
#include "sse_broadcaster.hpp"
#include "status_stream.hpp"
#include "server.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

struct ConfigApplyResult {
    bool applied{false};
    bool rolled_back{false};
    std::optional<std::int64_t> apply_started_ts;
    std::string error;
    // Preparation happens before the control/event-loop task mutates routes,
    // firewall state, or resolver state. A preparation failure therefore
    // leaves the previously healthy runtime intact; callers must distinguish
    // that proven state from an apply whose rollback could not be verified.
    bool runtime_unchanged{false};
};

struct ServiceHealthState {
    api::HealthResponseStatus status{api::HealthResponseStatus::STOPPED};
    std::string runtime_state{"starting"};
    std::string runtime_state_reason;
    std::string os_type{"unknown"};
    std::string os_version{"unknown"};
    std::string build_variant{"unknown"};
    std::string resolver_config_hash;
    std::string resolver_config_hash_actual;
    std::optional<std::int64_t> resolver_config_hash_actual_ts;
    api::ResolverLiveStatus resolver_live_status{api::ResolverLiveStatus::UNKNOWN};
    api::ResolverConfigProbeStatus resolver_config_probe_status{api::ResolverConfigProbeStatus::UNKNOWN};
    std::optional<std::int64_t> resolver_last_probe_ts;
    std::optional<std::int64_t> apply_started_ts;
    std::optional<api::ResolverConfigSyncState> resolver_config_sync_state;
    bool config_is_draft{false};
    std::optional<LifecycleOperationSnapshot> lifecycle_operation;
};

struct ListRefreshOperationResult {
    std::vector<std::string> refreshed_lists;
    std::vector<std::string> changed_lists;
    std::vector<std::string> failed_lists;
    bool reloaded{false};
    std::string message;
};

// Context struct holding thread-safe accessors to daemon runtime state.
struct ApiContext {
    // Own the path. Tests and embedders often construct the context from a
    // temporary path string; retaining a reference here would leave the API
    // with a dangling recovery target.
    std::string config_path;
    SseBroadcaster& dns_test_broadcaster;

    std::function<Config()> get_visible_config_fn;
    std::function<bool()> config_is_draft_fn;
    std::function<void(Config, std::string)> stage_config_fn;
    std::function<std::optional<std::pair<Config, std::string>>()> get_staged_config_snapshot_fn;
    std::function<void()> clear_staged_config_fn;
    std::function<void(const Config&)> validate_candidate_config_fn;
    std::function<ServiceHealthState()> get_service_health_fn;
    std::function<RoutingHealthReport()> get_routing_health_fn;
    std::function<api::RuntimeOutboundsResponse()> get_runtime_outbounds_fn;
    std::function<api::RuntimeInterfaceInventoryResponse()> get_runtime_interfaces_fn;
    std::function<std::map<std::string, api::ListRefreshStateValue>(const Config&)>
        get_list_refresh_state_map_fn;
    std::function<TestRoutingResult(const std::string&)> compute_test_routing_fn;

    std::function<void()> begin_save_operation_fn;
    std::function<void()> finish_config_operation_fn;

    // Callbacks that mutate daemon runtime state from event loop.
    std::function<ConfigApplyResult(Config, std::string)> enqueue_apply_validated_config_fn;
    std::function<void()> start_runtime_fn;
    std::function<void()> stop_runtime_fn;
    std::function<void()> restart_runtime_fn;
    std::function<ListRefreshOperationResult(std::optional<std::string>)> refresh_lists_fn;
    StatusStream* status_stream{nullptr};
    LifecycleOperationCoordinator* lifecycle_operations{nullptr};
    std::function<void(std::string, std::vector<std::string>)>
        replace_interface_traffic_targets_fn;
    std::function<int(const std::string&)> restart_restore_service_fn;
    std::function<std::unique_ptr<MaintenanceLease>(std::string)>
        maintenance_lease_factory_fn;
    // Fail-closed stop used while a save operation already owns the config
    // operation state. Production wiring must not try to acquire a second
    // Reloading operation, otherwise the emergency stop self-deadlocks.
    std::function<void()> emergency_quiesce_runtime_fn;
    // Catalog setup uses one visible snapshot identity. Mutations are
    // serialized by the same config-operation guard as ordinary staging.
    std::function<VisibleConfigSnapshot()> get_visible_config_snapshot_fn;
    // Tail callback preserves positional aggregate initializers used by
    // embedders. Production wiring supplies the atomic draft/base snapshot.
    std::function<std::optional<StagedConfigSnapshot>()>
        get_staged_config_cas_snapshot_fn;
    // Narrow setup endpoints compare and replace the visible config under the
    // ConfigStore mutex. A separate snapshot check followed by stage_config()
    // would allow an active reload to race between the two calls.
    std::function<bool(
        const std::string&,
        Config,
        std::string)> stage_config_if_visible_revision_fn;
    // Companion mode switches wait for process + TUN + owned runtime rules.
    // Tests shorten this bounded poll without weakening production defaults.
    std::size_t transport_runtime_ready_wait_attempts{60U};
    std::uint32_t transport_runtime_ready_wait_interval_ms{250U};
    // Tail callbacks preserve positional aggregate initializers used by tests
    // and embedders. Periodic metrics are pull-only and intentionally do not
    // participate in HealthResponse, RuntimeInventory, or StatusStream
    // reconciliation.
    std::function<api::PeriodicTaskMetricsResponse()>
        get_diagnostic_tasks_fn;
    // Production uses a move-only runtime mutation lease.  Keeping this tail
    // callback optional preserves aggregate initializers used by tests and
    // embedders while ensuring that an individual request, rather than the
    // daemon, owns the exact claim it must release.
    std::function<RuntimeMutationAdmission::Lease(
        std::string,
        bool,
        bool)> acquire_runtime_mutation_fn;
    // Tail callback for the same reason as the two above. The system-auth
    // verdict belongs to the web server rather than the routing daemon, so it
    // is annotated onto the routing report instead of being produced with it.
    // Left unset - by tests, by embedders, by the daemon before the web server
    // exists - the fields are simply omitted.
    std::function<std::optional<SystemAuthHealthSnapshot>()>
        get_system_auth_health_fn;
    // Successful nfqws service/strategy mutations must re-evaluate the PPE
    // de-offload graph from the active process contract.  The HTTP worker may
    // only request the existing coalesced control-loop reconciliation; it
    // never runs firewall commands itself.  Optional tail placement preserves
    // aggregate initializers used by tests and embedders.
    std::function<bool()> request_netfilter_runtime_refresh_fn;
    // Optional tail callback exposes only the daemon's redacted, atomic boot
    // observation. It must never inspect disk or authorize mutation. An
    // absent callback means the feature remains dormant.
    std::function<NdmsNativeImportJournalReadinessState()>
        get_ndms_native_import_readiness_fn;
    // The reservation callback acquires the complete ordered
    // maintenance/runtime/native-writer chain before the server allocates or
    // reads a sensitive body. The same opaque token is retained by the server
    // through response/error handling and passed to the execution callback,
    // so a second request cannot consume its one-shot secret and lose a race
    // only afterwards.
    std::function<std::shared_ptr<SensitiveRequestReservation>()>
        reserve_ndms_native_import_fn;
    // Adopts the only raw secret string under the exact reservation above and
    // returns the coordinator's redacted result; the API layer neither
    // retries nor serializes internals.
    std::function<NdmsNativeCooperativeImportResult(
        std::string&&,
        NdmsNativeExternalWriterRaceAcceptance,
        const std::shared_ptr<SensitiveRequestReservation>&)>
        run_ndms_native_import_fn;
    // A recovery reservation uses the same ordered maintenance/runtime/native
    // writer chain as a fresh import, but it must admit an unfinished safe
    // import WAL so the coordinator can complete forward bookkeeping.
    std::function<std::shared_ptr<SensitiveRequestReservation>()>
        reserve_ndms_native_import_recovery_fn;
    std::function<NdmsNativeCooperativeImportResumeResult(
        const std::shared_ptr<SensitiveRequestReservation>&)>
        resume_ndms_native_import_fn;
    // Native delete uses the same complete ordered reservation as import.
    // Acquiring it before body admission prevents a losing request from
    // consuming its selector/consent evidence, while the cooperative delete
    // coordinator remains the final WAL/ownership/dependency gate.
    std::function<std::shared_ptr<SensitiveRequestReservation>()>
        reserve_ndms_native_delete_fn;
    std::function<NdmsNativeCooperativeDeleteResult(
        const NdmsNativeCooperativeDeleteRequest&,
        const std::shared_ptr<SensitiveRequestReservation>&)>
        run_ndms_native_delete_fn;
    std::function<NdmsNativeCooperativeDeleteResult(
        const NdmsNativeCooperativeDeleteResumeAcknowledgement&,
        const std::shared_ptr<SensitiveRequestReservation>&)>
        resume_ndms_native_delete_fn;
    // Recomputed for every GET from one already-resolved catalogue.  The
    // callback may inspect only bounded redacted ownership/WAL state and must
    // not decrypt snapshots, scan dependencies, contact NDMS or write disk.
    // The handler validates the entire projection before exposing any row.
    std::function<NdmsNativeInventoryProjection(
        const std::vector<NdmsTunnelInterface>&,
        bool)>
        observe_ndms_native_inventory_projection_fn;

    Config get_visible_config() const {
        return get_visible_config_fn();
    }

    bool config_is_draft() const {
        return config_is_draft_fn();
    }

    std::optional<std::pair<Config, std::string>> get_staged_config_snapshot() const {
        return get_staged_config_snapshot_fn();
    }

    void clear_staged_config() const {
        clear_staged_config_fn();
    }

    void stage_config(Config config, std::string staged_config_json) const {
        stage_config_fn(std::move(config), std::move(staged_config_json));
    }

    VisibleConfigSnapshot get_visible_config_snapshot() const {
        if (!get_visible_config_snapshot_fn) {
            throw std::runtime_error(
                "Atomic visible config snapshots are unavailable");
        }
        return get_visible_config_snapshot_fn();
    }

    VisibleConfigSnapshot get_visible_config_state() const {
        if (get_visible_config_snapshot_fn) {
            return get_visible_config_snapshot_fn();
        }
        // Compatibility for embedders predating the atomic snapshot callback.
        // Production always takes the single-lock path above.
        return VisibleConfigSnapshot{
            get_visible_config(),
            config_is_draft(),
            {},
        };
    }

    std::optional<StagedConfigSnapshot>
    get_staged_config_cas_snapshot() const {
        if (get_staged_config_cas_snapshot_fn) {
            return get_staged_config_cas_snapshot_fn();
        }
        const auto legacy = get_staged_config_snapshot();
        if (!legacy.has_value()) {
            return std::nullopt;
        }
        return StagedConfigSnapshot{
            legacy->first,
            legacy->second,
            {},
            {},
        };
    }

    bool stage_config_if_visible_revision(
        const std::string& expected_visible_revision,
        Config config,
        std::string staged_config_json) const {
        if (!stage_config_if_visible_revision_fn) {
            throw std::runtime_error(
                "Atomic config compare-and-stage is unavailable");
        }
        return stage_config_if_visible_revision_fn(
            expected_visible_revision,
            std::move(config),
            std::move(staged_config_json));
    }

    void validate_candidate_config(const Config& config) const {
        validate_candidate_config_fn(config);
    }

    ServiceHealthState get_service_health() const {
        return get_service_health_fn();
    }

    RoutingHealthReport get_routing_health() const {
        auto report = get_routing_health_fn();
        if (get_system_auth_health_fn) {
            if (const auto snapshot = get_system_auth_health_fn()) {
                report.system_auth_state = snapshot->state;
                report.system_auth_detail = snapshot->detail;
                report.system_auth_forwarded_failures_per_window =
                    snapshot->forwarded_failures_per_window;
            }
        }
        return report;
    }

    api::RuntimeOutboundsResponse get_runtime_outbounds() const {
        return get_runtime_outbounds_fn();
    }

    api::RuntimeInterfaceInventoryResponse get_runtime_interfaces() const {
        return get_runtime_interfaces_fn();
    }

    std::map<std::string, api::ListRefreshStateValue> get_list_refresh_state_map(
        const Config& config) const {
        return get_list_refresh_state_map_fn(config);
    }

    TestRoutingResult compute_test_routing(const std::string& target) const {
        return compute_test_routing_fn(target);
    }

    void begin_save_operation() const {
        begin_save_operation_fn();
    }

    void finish_config_operation() const {
        finish_config_operation_fn();
    }

    ConfigApplyResult enqueue_apply_validated_config(
        Config config,
        std::string saved_config_json) const {
        return enqueue_apply_validated_config_fn(
            std::move(config),
            std::move(saved_config_json));
    }

    void start_runtime() const {
        start_runtime_fn();
    }

    void stop_runtime() const {
        stop_runtime_fn();
    }

    void emergency_quiesce_runtime() const {
        if (emergency_quiesce_runtime_fn) {
            emergency_quiesce_runtime_fn();
            return;
        }
        // Tests and embedders predating the dedicated callback keep the safe
        // behavior, provided their stop callback does not re-enter the config
        // operation state machine.
        stop_runtime_fn();
    }

    void restart_runtime() const {
        restart_runtime_fn();
    }

    ListRefreshOperationResult refresh_lists(
        const std::optional<std::string>& requested_name) const {
        return refresh_lists_fn(requested_name);
    }

    void replace_interface_traffic_targets(
        std::string source,
        std::vector<std::string> interface_names) const {
        if (replace_interface_traffic_targets_fn) {
            replace_interface_traffic_targets_fn(
                std::move(source), std::move(interface_names));
        }
    }

    std::unique_ptr<MaintenanceLease> acquire_maintenance_lease(
        std::string operation) const {
        if (!maintenance_lease_factory_fn) {
            return std::make_unique<MaintenanceCoordinator>(
                std::move(operation));
        }
        auto lease =
            maintenance_lease_factory_fn(std::move(operation));
        if (!lease) {
            throw std::runtime_error(
                "Maintenance lease factory returned no lease");
        }
        return lease;
    }

    api::PeriodicTaskMetricsResponse get_diagnostic_tasks() const {
        if (get_diagnostic_tasks_fn) {
            return get_diagnostic_tasks_fn();
        }
        api::PeriodicTaskMetricsResponse response;
        response.capacity = 0;
        response.tracked = 0;
        return response;
    }

    bool request_netfilter_runtime_refresh() const {
        return request_netfilter_runtime_refresh_fn &&
               request_netfilter_runtime_refresh_fn();
    }
};

// Request-scoped compatibility wrapper.  Production owns an unforgeable
// mutation lease; older tests/embedders retain the paired callbacks until
// their aggregate contexts are migrated.  The fallback is never selected by
// the daemon wiring.
class ApiRuntimeMutationGuard final {
public:
    ApiRuntimeMutationGuard(ApiContext& context,
                            std::string label,
                            bool require_runtime_running = false,
                            bool require_runtime_stopped = false)
        : context_(context) {
        if (context_.acquire_runtime_mutation_fn) {
            lease_.emplace(
                context_.acquire_runtime_mutation_fn(
                    std::move(label),
                    require_runtime_running,
                    require_runtime_stopped));
            if (!static_cast<bool>(*lease_)) {
                throw std::runtime_error(
                    "Runtime mutation admission returned an empty lease");
            }
            return;
        }

        context_.begin_save_operation();
        legacy_active_ = true;
    }

    ~ApiRuntimeMutationGuard() noexcept {
        if (!active()) {
            return;
        }
        try {
            finish();
        } catch (const std::exception& error) {
            Logger::instance().error(
                "Cannot release runtime mutation operation: {}",
                error.what());
        } catch (...) {
            Logger::instance().error(
                "Cannot release runtime mutation operation: unknown error");
        }
    }

    ApiRuntimeMutationGuard(const ApiRuntimeMutationGuard&) = delete;
    ApiRuntimeMutationGuard& operator=(const ApiRuntimeMutationGuard&) = delete;

    void finish() {
        if (lease_.has_value()) {
            lease_->release();
            lease_.reset();
            return;
        }
        if (legacy_active_) {
            context_.finish_config_operation();
            legacy_active_ = false;
        }
    }

private:
    bool active() const noexcept {
        return lease_.has_value() || legacy_active_;
    }

    ApiContext& context_;
    std::optional<RuntimeMutationAdmission::Lease> lease_;
    bool legacy_active_{false};
};

// Register all API endpoint handlers on the given ApiServer.
//   GET  /api/health/service  - daemon version/status + resolver/config summary
//   POST /api/service/start   - start routing runtime and activate dnsmasq hook
//   POST /api/service/stop    - stop routing runtime and deactivate dnsmasq hook
//   POST /api/service/restart - restart routing runtime and activate dnsmasq hook
//   POST /api/lists/refresh   - refresh one or all URL-backed lists
//   GET  /api/config          - return current config and draft status
//   POST /api/config          - validate + stage config in memory
//   POST /api/config/dependencies - analyze references before mutation
//   POST /api/config/save     - persist staged config and apply it
//   POST /api/config/discard  - drop the staged draft without applying it
//   GET  /api/health/routing  - routing and firewall health verification
//   GET  /api/runtime/outbounds - live outbound/interface runtime state
//   GET  /api/runtime/interfaces - live system interface inventory
//   GET  /api/runtime/inventory - unified service/outbound/interface snapshot
//   GET  /api/diagnostics/tasks - pull-only periodic task counters
//   GET  /api/transports       - transport manager runtime state
//   POST /api/transports       - start or stop a managed transport
//   GET  /api/transports/config - editable transport definitions
//   POST /api/transports/config - create, update, or delete a transport
//   POST /api/routing/test    - test expected/actual routing for an IP or domain
//   POST /api/connections/query - filtered cursor page of conntrack history
void register_api_handlers(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
