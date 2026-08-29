#include "daemon.hpp"
#include "api_runtime_lifecycle.hpp"

#ifdef WITH_API

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <future>
#include <limits>
#include <sys/epoll.h>
#include <thread>

#include "../api/handlers.hpp"
#include "../api/handler_connections.hpp"
#include "../api/handler_health_service.hpp"
#include "../api/handler_nfqws.hpp"
#include "../api/server.hpp"
#include "../api/status_stream.hpp"
#include "../connections/conntrack_event_monitor.hpp"
#include "../config/routing_state.hpp"
#include "../dns/dns_router.hpp"
#include "../dns/dnsmasq_gen.hpp"
#include "../util/ipv6_support.hpp"
#include "../health/routing_health_checker.hpp"
#include "../health/runtime_interface_inventory.hpp"
#include "../keenetic/ndms_catalog_cache.hpp"
#include "../keenetic/ndms_interface_management.hpp"
#include "../keenetic/ndms_interface_inventory.hpp"
#include "../keenetic/ndms_native_config_dependencies.hpp"
#include "../keenetic/ndms_native_cooperative_delete.hpp"
#include "../keenetic/ndms_native_cooperative_import.hpp"
#include "../keenetic/ndms_native_fresh_import_preflight.hpp"
#include "../keenetic/ndms_native_inventory_projection.hpp"
#include "../keenetic/ndms_native_tombstone_forget.hpp"
#include "../keenetic/ndms_native_writer_lease.hpp"
#include "../health/runtime_outbound_state.hpp"
#include "../api/handler_runtime_inventory.hpp"
#include "../api/handler_diagnostic_tasks.hpp"
#include "../lists/list_streamer.hpp"
#include "../log/logger.hpp"
#include "../util/system_info.hpp"
#include "../util/time_utils.hpp"
#include "scheduler.hpp"
#include "runtime_firewall_operation_owner.hpp"

#ifndef KEEN_PBR_FRONTEND_ROOT
#define KEEN_PBR_FRONTEND_ROOT "/usr/share/keen-pbr/frontend"
#endif

namespace keen_pbr3 {

namespace {

constexpr auto conntrack_publish_delay = std::chrono::milliseconds{500};
constexpr auto interface_traffic_sample_interval = std::chrono::seconds{2};

#ifdef USE_KEENETIC_API
class NativeImportBodyWipeGuard final {
public:
    explicit NativeImportBodyWipeGuard(std::string& value) noexcept
        : value_(value) {}

    ~NativeImportBodyWipeGuard() noexcept {
        volatile char* cursor = value_.empty() ? nullptr : value_.data();
        for (std::size_t index = 0U;
             cursor != nullptr && index < value_.size(); ++index) {
            cursor[index] = 0;
        }
        value_.clear();
    }

    NativeImportBodyWipeGuard(const NativeImportBodyWipeGuard&) = delete;
    NativeImportBodyWipeGuard& operator=(
        const NativeImportBodyWipeGuard&) = delete;

private:
    std::string& value_;
};

NdmsNativeCooperativeImportResult blocked_native_import(
    const NdmsNativeCooperativeImportStop stop,
    const NdmsNativeExternalWriterRaceAcceptance acceptance) noexcept {
    NdmsNativeCooperativeImportResult result;
    result.stop = stop;
    result.external_ndms_writer_race_accepted =
        acceptance ==
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted;
    return result;
}

NdmsNativeCooperativeImportResumeResult blocked_native_import_recovery(
    const NdmsNativeCooperativeImportResumeStop stop,
    const NdmsNativeExternalWriterRaceAcceptance acceptance) noexcept {
    NdmsNativeCooperativeImportResumeResult result;
    result.stop = stop;
    result.external_ndms_writer_race_accepted =
        acceptance ==
        NdmsNativeExternalWriterRaceAcceptance::owner_accepted;
    return result;
}

NdmsNativeCooperativeDeleteResult blocked_native_delete(
    const NdmsNativeCooperativeDeleteStop stop) noexcept {
    NdmsNativeCooperativeDeleteResult result;
    result.stop = stop;
    return result;
}

NdmsNativeTombstoneForgetResult blocked_native_tombstone_forget(
    const NdmsNativeTombstoneForgetStop stop,
    const std::string& interface_name) noexcept {
    NdmsNativeTombstoneForgetResult result;
    result.stop = stop;
    result.interface_name = interface_name;
    return result;
}

enum class NativeMutationReservationPurpose : std::uint8_t {
    new_import,
    import_recovery,
    new_delete,
    delete_recovery,
    tombstone_forget,
    lifecycle,
};

class NativeMutationRequestReservation final
    : public SensitiveRequestReservation {
public:
    NativeMutationRequestReservation(
        const void* owner,
        const NativeMutationReservationPurpose purpose,
        NdmsNativeWriterLease&& writer,
        NdmsNativeImportWalStore& import_wal,
        NdmsNativeDeleteWalStore& delete_wal,
        std::atomic<NdmsNativeImportJournalReadinessState>&
            import_readiness,
        std::atomic<NdmsNativeMutationAdmissionState>&
            mutation_admission) noexcept
        : owner_(owner),
          purpose_(purpose),
          writer_(std::move(writer)),
          import_wal_(import_wal),
          delete_wal_(delete_wal),
          import_readiness_(import_readiness),
          mutation_admission_(mutation_admission) {}

    ~NativeMutationRequestReservation() noexcept override {
        // Refresh while the cooperative writer is still held. Member
        // destruction releases the writer only after this body returns, so a
        // second request can never observe "admitted" between the two WAL
        // reads or before the first request has fully left the API callback.
        try {
            writer_.verify_held();
            const auto delete_readiness = delete_wal_.readiness();
            const auto inventory = import_wal_.try_inventory();
            writer_.verify_held();
            const auto import_state =
                summarize_ndms_native_import_readiness(inventory);
            const auto mutation_state =
                summarize_ndms_native_mutation_admission(
                    inventory, delete_readiness);
            import_readiness_.store(
                import_state, std::memory_order_release);
            mutation_admission_.store(
                mutation_state, std::memory_order_release);
        } catch (...) {
            import_readiness_.store(
                NdmsNativeImportJournalReadinessState::unavailable,
                std::memory_order_release);
            mutation_admission_.store(
                NdmsNativeMutationAdmissionState::unavailable,
                std::memory_order_release);
        }
    }

    bool owned_by(
        const void* owner,
        const NativeMutationReservationPurpose purpose) const noexcept {
        return owner_ == owner && purpose_ == purpose;
    }

    NdmsNativeWriterLease& writer() noexcept { return writer_; }

private:
    const void* owner_{nullptr};
    NativeMutationReservationPurpose purpose_{
        NativeMutationReservationPurpose::new_import};
    NdmsNativeWriterLease writer_;
    NdmsNativeImportWalStore& import_wal_;
    NdmsNativeDeleteWalStore& delete_wal_;
    std::atomic<NdmsNativeImportJournalReadinessState>&
        import_readiness_;
    std::atomic<NdmsNativeMutationAdmissionState>&
        mutation_admission_;
};
#endif

std::int64_t interface_traffic_timestamp_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t interface_traffic_api_integer(std::uint64_t value) {
    constexpr auto maximum =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    return static_cast<std::int64_t>(std::min(value, maximum));
}

} // namespace

api::RuntimeInterfaceInventoryResponse
Daemon::build_runtime_interface_inventory_with_uptime() {
    // Stamp the round before its netlink dump.  Concurrent workers can finish
    // in the opposite order from the one in which their snapshots started;
    // begin_round uses this instant to reject a late, older snapshot as a
    // whole.  The wall/steady pair is also kept together so publication never
    // derives elapsed time across an RTC step.
    const auto observed_at = InterfaceUptimeAnchorStore::Clock::now();
    const auto wall_now = std::chrono::system_clock::now();

    std::vector<DumpedInterface> dumped;
    try {
        dumped = netlink_.dump_interfaces();
    } catch (const NetlinkError&) {
        return api::RuntimeInterfaceInventoryResponse{};
    }

    std::vector<std::string> runtime_names;
    runtime_names.reserve(dumped.size());
    for (const auto& item : dumped) {
        runtime_names.push_back(item.name);
    }
    // Open the round before folding in any firmware observation. Ordering is
    // load-bearing: begin_round records when each interface entered the set,
    // and a cached catalog read before that instant describes a previous
    // lifetime of a reused name.
    interface_uptime_anchors_.begin_round(runtime_names, observed_at);

    // peek(), never get(): this runs on an HTTP worker and on the SSE
    // reconcile path, and a blocking loopback RCI request there would stall
    // both. A cold catalog simply leaves the firmware anchor unavailable,
    // which the entry then reports as unknown instead of guessing.
    const auto ndms = shared_ndms_catalog_cache().peek();
    if (ndms.observed_at) {
        for (const auto& metadata : ndms.catalog.interface_metadata) {
            if (!metadata.uptime_seconds) {
                continue;
            }
            const auto kernel_name = resolve_ndms_kernel_name(
                metadata.firmware_interface_name, runtime_names);
            if (!kernel_name) {
                continue;
            }
            // Stamped with the instant the catalog was read, not with now:
            // this snapshot can be a whole cache TTL old, and dating it to now
            // would shorten every uptime it carries by that lag.
            interface_uptime_anchors_.observe_firmware_uptime(
                *kernel_name, *metadata.uptime_seconds, *ndms.observed_at);
        }
    }

    return build_runtime_interface_inventory_response(
        std::move(dumped),
        &interface_traffic_sampler_,
        &interface_uptime_anchors_,
        observed_at,
        wall_now);
}

void Daemon::sample_interface_traffic_now() {
    if (!status_stream_ || !status_stream_->has_subscribers()) {
        const bool sampling_stopped =
            traffic_sampling_active_ ||
            !traffic_sampled_interfaces_.empty();
        if (sampling_stopped) {
            interface_traffic_sampler_.clear_all();
            traffic_sampled_interfaces_.clear();
            traffic_sampling_active_ = false;
            // The next viewer must not inherit the backoff this one left
            // behind, or a freshly opened dashboard would sit blank for the
            // length of a stretched interval.
            interface_traffic_cadence_.reset();
            periodic_task_metrics_.record_skipped(
                "interface-traffic-sample",
                "status stream has no subscribers");
        }
        return;
    }

    auto task_metrics =
        periodic_task_metrics_.begin("interface-traffic-sample");
    try {
        std::set<std::string> target_interfaces;
        {
            std::lock_guard<std::mutex> lock(
                interface_traffic_targets_mutex_);
            for (const auto& [source, interfaces] :
                 interface_traffic_targets_by_source_) {
                (void)source;
                target_interfaces.insert(
                    interfaces.begin(), interfaces.end());
            }
        }

        if (target_interfaces.empty()) {
            if (traffic_sampling_active_ ||
                !traffic_sampled_interfaces_.empty()) {
                interface_traffic_sampler_.clear_all();
                traffic_sampled_interfaces_.clear();
                traffic_sampling_active_ = false;
            }
            interface_traffic_cadence_.reset();
            task_metrics.noop();
            return;
        }

        // A changed target set means a screen was just opened or closed. That
        // is the worst possible moment to be mid-backoff, so it both restores
        // the fast rate and guarantees this tick takes a reading.
        const bool targets_changed =
            target_interfaces != traffic_sampled_interfaces_;
        if (targets_changed) {
            interface_traffic_cadence_.reset();
        }
        if (!interface_traffic_cadence_.begin_tick()) {
            // Nothing has moved for a while. Skipping the read is the whole
            // point of the backoff; publishing an empty batch here would undo
            // it by waking every subscriber anyway.
            task_metrics.noop();
            return;
        }

        const auto target_plan = plan_interface_traffic_targets(
            target_interfaces, traffic_sampled_interfaces_);
        bool anything_changed = targets_changed;
        nlohmann::json interfaces = nlohmann::json::array();
        for (const auto& interface_name : target_plan.reported) {
            if (target_plan.removed.find(interface_name) !=
                target_plan.removed.end()) {
                interface_traffic_sampler_.clear(interface_name);
                interfaces.push_back(
                    nlohmann::json{
                        {"name", interface_name},
                        {"available", false},
                        {"reset", false},
                    });
                continue;
            }

            const auto result =
                interface_traffic_sampler_.sample(interface_name);
            anything_changed = anything_changed || result.state_changed;
            const bool unavailable =
                result.status ==
                    InterfaceTrafficSampler::SampleStatus::Unavailable ||
                result.status ==
                    InterfaceTrafficSampler::SampleStatus::InvalidInterfaceName;
            nlohmann::json entry{
                {"name", interface_name},
                {"available", !unavailable},
                {"reset",
                 result.status ==
                     InterfaceTrafficSampler::SampleStatus::CounterReset},
            };
            if (result.point) {
                // The instant this interface's own counters were read. Emitted
                // only alongside a real reading, so an interface that was
                // skipped or failed this round carries no timestamp at all
                // rather than borrowing the round's and looking as fresh as
                // the ones that succeeded.
                entry["observed_at_unix_ms"] =
                    unix_timestamp_ms(result.point->observed_at);
                entry["rx_bytes"] =
                    interface_traffic_api_integer(result.point->rx_bytes);
                entry["tx_bytes"] =
                    interface_traffic_api_integer(result.point->tx_bytes);
                if (result.point->rx_bits_per_second) {
                    entry["rx_bits_per_second"] =
                        interface_traffic_api_integer(
                            *result.point->rx_bits_per_second);
                }
                if (result.point->tx_bits_per_second) {
                    entry["tx_bits_per_second"] =
                        interface_traffic_api_integer(
                            *result.point->tx_bits_per_second);
                }
            }
            interfaces.push_back(std::move(entry));
        }

        interface_traffic_cadence_.end_round(anything_changed);
        traffic_sampled_interfaces_ = target_interfaces;
        traffic_sampling_active_ = true;
        status_stream_->publish_interface_traffic(
            nlohmann::json{
                {"sampled_at_unix_ms", interface_traffic_timestamp_ms()},
                {"interfaces", std::move(interfaces)},
            });
        task_metrics.success();
    } catch (const std::exception& error) {
        task_metrics.failure(error.what());
        throw;
    } catch (...) {
        task_metrics.failure("interface traffic sampling failed");
        throw;
    }
}

void Daemon::replace_interface_traffic_targets(
    std::string source,
    std::vector<std::string> interface_names) {
    std::set<std::string> valid_names;
    for (auto& name : interface_names) {
        if (InterfaceTrafficSampler::is_valid_interface_name(name)) {
            valid_names.insert(std::move(name));
        }
    }
    std::lock_guard<std::mutex> lock(interface_traffic_targets_mutex_);
    interface_traffic_targets_by_source_[std::move(source)] =
        std::move(valid_names);
}

void Daemon::refresh_interface_traffic_config_targets(
    const Config& config) {
    replace_interface_traffic_targets(
        "active-config", interface_traffic_targets_from_config(config));
}

void Daemon::schedule_interface_traffic_sampling() {
    scheduler_->schedule_repeating(
        interface_traffic_sample_interval,
        [this]() {
            sample_interface_traffic_now();
        },
        "interface-traffic-sample");
}

void Daemon::setup_conntrack_events() {
    replace_api_conntrack_monitor_for_retry(
        [this]() { teardown_conntrack_events(); },
        [this]() {
            conntrack_event_monitor_ =
                std::make_unique<ConntrackEventMonitor>();
        });

    api::ConnectionEventState state;
    state.revision = static_cast<std::int64_t>(conntrack_revision_);
    state.changed_at = 0;
    state.available = conntrack_event_monitor_->available();
    status_stream_->publish_connections(state);

    if (!conntrack_event_monitor_->available()) {
        Logger::instance().warn(
            "Conntrack event stream unavailable; WebUI will use slow fallback polling: {}",
            conntrack_event_monitor_->error());
        conntrack_event_monitor_.reset();
        return;
    }

    const int fd = conntrack_event_monitor_->fd();
    try {
        add_fd(
            fd,
            EPOLLIN | EPOLLERR | EPOLLHUP,
            [this](std::uint32_t events) { handle_conntrack_events(events); },
            true,
            "conntrack-events");
    } catch (const std::exception& error) {
        Logger::instance().warn(
            "Could not register conntrack event stream; WebUI will use slow fallback polling: {}",
            error.what());
        conntrack_event_monitor_.reset();
        state.available = false;
        status_stream_->publish_connections(std::move(state));
        return;
    }
    Logger::instance().info(
        "Conntrack event stream enabled for real-time connection updates");
}

void Daemon::handle_conntrack_events(std::uint32_t events) {
    if (!conntrack_event_monitor_) return;

    try {
        if ((events & EPOLLIN) != 0) {
            const auto count = conntrack_event_monitor_->drain();
            if (count > 0) {
                conntrack_revision_ += count;
                invalidate_connections_snapshot();
                if (conntrack_publish_task_id_ < 0) {
                    conntrack_publish_task_id_ = scheduler_->schedule_oneshot(
                        conntrack_publish_delay,
                        [this]() {
                            conntrack_publish_task_id_ = -1;
                            publish_conntrack_revision();
                        },
                        "conntrack-sse-coalesce");
                }
            }
        }
        if ((events & (EPOLLERR | EPOLLHUP)) != 0) {
            throw std::runtime_error(
                "conntrack netlink socket reported an error");
        }
    } catch (const std::exception& error) {
        Logger::instance().warn(
            "Conntrack event stream stopped; WebUI will use slow fallback polling: {}",
            error.what());
        api::ConnectionEventState state;
        state.revision = static_cast<std::int64_t>(conntrack_revision_);
        state.changed_at = unix_timestamp_now_seconds();
        state.available = false;
        status_stream_->publish_connections(std::move(state));
        teardown_conntrack_events();
    }
}

void Daemon::publish_conntrack_revision() {
    if (!status_stream_ || !conntrack_event_monitor_) return;
    api::ConnectionEventState state;
    state.revision = static_cast<std::int64_t>(conntrack_revision_);
    state.changed_at = unix_timestamp_now_seconds();
    state.available = true;
    status_stream_->publish_connections(std::move(state));
}

void Daemon::teardown_conntrack_events() noexcept {
    if (conntrack_publish_task_id_ >= 0) {
        const int task_id = conntrack_publish_task_id_;
        conntrack_publish_task_id_ = -1;
        try {
            scheduler_->cancel(task_id);
        } catch (...) {
        }
    }
    if (!conntrack_event_monitor_) return;
    const int fd = conntrack_event_monitor_->fd();
    try {
        remove_fd(fd, true, "conntrack-events");
    } catch (...) {
        // Closing the socket below retires the kernel epoll registration. Also
        // remove the callback record directly so a descriptor reuse cannot
        // dispatch an already-returned event through stale conntrack state.
        if (epoll_fd_ >= 0) {
            (void)epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
        }
        try {
            KPBR_LOCK_GUARD(fd_entries_mutex_);
            fd_entries_.erase(
                std::remove_if(
                    fd_entries_.begin(),
                    fd_entries_.end(),
                    [fd](const FdEntry& entry) {
                        return entry.fd == fd;
                    }),
                fd_entries_.end());
        } catch (...) {
        }
    }
    conntrack_event_monitor_.reset();
}

RuntimeMutationAdmission::Lease
Daemon::acquire_runtime_mutation_or_throw(
    std::string label,
    bool require_runtime_running,
    bool require_runtime_stopped) {
    auto lease = runtime_mutation_admission_.try_acquire(label);
    if (!lease.has_value()) {
        const auto active = runtime_mutation_admission_.active();
        const std::string detail = active.has_value() && !active->label.empty()
            ? ": " + active->label
            : std::string{};
        throw ApiError(
            "Another runtime mutation is already in progress" + detail,
            409);
    }

    const auto runtime_snapshot = runtime_state_store_.snapshot();
    if (runtime_snapshot.runtime_state == RuntimeState::starting ||
        runtime_snapshot.runtime_state == RuntimeState::shutting_down) {
        throw ApiError("Routing runtime initialization or shutdown is in progress", 409);
    }
    const bool runtime_running = runtime_snapshot.routing_runtime_active;
    if (require_runtime_running && !runtime_running) {
        throw ApiError("Routing runtime is stopped; start it first", 409);
    }
    if (require_runtime_stopped && runtime_running) {
        throw ApiError("Routing runtime is already started", 409);
    }

    Logger::instance().trace(
        "runtime_mutation_admitted",
        "token={} label={}",
        lease->token(),
        label);
    return std::move(*lease);
}

void Daemon::run_runtime_control_operation_or_throw(const std::string& label,
                                                    const char* operation_name,
                                                    std::function<void()> task) {
    enqueue_control_task(
        [task = std::move(task), operation_name]() {
            try {
                task();
            } catch (const std::exception& e) {
                Logger::instance().error("{} task failed: {}", operation_name, e.what());
                throw;
            }
        },
        true,
        label);
}

void Daemon::start_routing_runtime_with_lease(
    RuntimeMutationAdmission::Lease lease) {
    if (is_event_loop_thread()) {
        throw DaemonError(
            "Runtime start completion cannot wait on the control loop");
    }

    auto completion = RuntimeFirewallLifecycleCompletion::create();
    auto lease_owner =
        std::make_unique<RuntimeMutationAdmission::Lease>(std::move(lease));
    auto completion_source = std::move(completion.source);

    // Only the short owner handoff is synchronous. The HTTP worker, never the
    // control loop, waits for route/firewall/resolver verification below.
    enqueue_control_task(
        [this, &lease_owner, &completion_source]() mutable {
            begin_preowned_runtime_firewall_start(
                std::move(lease_owner),
                std::move(completion_source));
        },
        true,
        "api-start-runtime-owner",
        true);

    const auto terminal = completion.wait.wait();
    if (terminal.outcome ==
        RuntimeFirewallLifecycleOutcome::verified_success) {
        return;
    }

    std::string message;
    if (terminal.outcome == RuntimeFirewallLifecycleOutcome::shutdown) {
        message = "Runtime start was interrupted by daemon shutdown";
    } else if (terminal.commit_ambiguous) {
        message =
            "Runtime start result is ambiguous; firewall commit could not "
            "be verified";
    } else {
        message = "Runtime start did not reach a verified running state";
    }
    if (!terminal.detail.empty()) {
        message += ": " + terminal.detail;
    }
    throw DaemonError(std::move(message));
}

void Daemon::restart_routing_runtime_with_lease(
    RuntimeMutationAdmission::Lease lease) {
    if (is_event_loop_thread()) {
        throw DaemonError(
            "Runtime restart completion cannot wait on the control loop");
    }

    auto completion = RuntimeFirewallLifecycleCompletion::create();
    auto lease_owner =
        std::make_unique<RuntimeMutationAdmission::Lease>(std::move(lease));
    auto completion_source = std::move(completion.source);

    // This wait covers only admission into the asynchronous owner. The
    // control task must not wait for firewall/resolver completion: the HTTP
    // worker performs that wait below while the event loop remains free to
    // drain worker terminals and successor attempts.
    enqueue_control_task(
        [this, &lease_owner, &completion_source]() mutable {
            begin_preowned_runtime_firewall_restart(
                std::move(lease_owner),
                std::move(completion_source));
        },
        true,
        "api-restart-runtime-owner",
        true);

    const auto terminal = completion.wait.wait();
    if (terminal.outcome ==
        RuntimeFirewallLifecycleOutcome::verified_success) {
        return;
    }

    std::string message;
    if (terminal.outcome == RuntimeFirewallLifecycleOutcome::shutdown) {
        message = "Runtime restart was interrupted by daemon shutdown";
    } else if (terminal.committed && !terminal.commit_ambiguous) {
        message =
            "Runtime firewall restart committed, but post-commit verification "
            "did not complete";
    } else if (terminal.commit_ambiguous) {
        message =
            "Runtime restart result is ambiguous; firewall commit could not "
            "be verified";
    } else {
        message = "Runtime restart did not reach a verified result";
    }
    if (!terminal.detail.empty()) {
        message += ": " + terminal.detail;
    }
    throw DaemonError(std::move(message));
}

ConfigApplyResult Daemon::apply_validated_config_via_control_task(
    Config config,
    std::string saved_config_json,
    ConfigGenerationFence generation_fence) {
    auto result = std::make_shared<ConfigApplyResult>();
    auto prepared = std::make_shared<PreparedRuntimeInputs>();
    auto rollback_prepared = std::make_shared<PreparedRuntimeInputs>();

    const auto active_snapshot = config_store_.pin_active_snapshot();
    const Config& active_config = active_snapshot->config;
    const bool refresh_remote_lists_after_apply =
        remote_list_sources_changed(active_config, config);

    try {
        *prepared = prepare_runtime_inputs(
            config,
            RemoteListPreparationMode::MissingOrInvalid);
        *rollback_prepared = prepare_runtime_inputs(
            active_config,
            RemoteListPreparationMode::None);
    } catch (const std::exception& e) {
        result->error = e.what();
        result->runtime_unchanged = true;
        Logger::instance().error("Prepare staged config task failed: {}", e.what());
        return *result;
    }

    enqueue_control_task(
        [this,
         result,
         prepared,
         rollback_prepared,
         refresh_remote_lists_after_apply,
         generation_fence,
         saved_config_json = std::move(saved_config_json)]() mutable {
            *result = apply_prepared_validated_config_on_control_loop(
                std::move(*prepared),
                std::move(*rollback_prepared),
                refresh_remote_lists_after_apply,
                std::move(saved_config_json),
                generation_fence);
        },
        true,
        "api-apply-config");
    return *result;
}

ConfigApplyResult
Daemon::apply_prepared_validated_config_on_control_loop(
    PreparedRuntimeInputs prepared,
    PreparedRuntimeInputs rollback_prepared,
    bool refresh_remote_lists_after_apply,
    std::string saved_config_json,
    ConfigGenerationFence generation_fence) {
    ConfigApplyResult result;
    const std::int64_t apply_started_ts = unix_timestamp_now_seconds();
    result.apply_started_ts = apply_started_ts;
    apply_started_ts_.store(apply_started_ts, std::memory_order_release);

    try {
        // Rollback must restore the exact DNS snapshot that belongs to the
        // currently committed runtime generation. The shared prepare cache
        // may have advanced after both candidates were prepared.
        rollback_prepared.keenetic_dns = active_keenetic_dns_;
        apply_prepared_runtime_inputs(
            std::move(prepared), generation_fence);
        result.applied = true;
        result.rolled_back = false;
        result.runtime_unchanged = false;
        config_store_.clear_staged_if_matches(saved_config_json);
        if (refresh_remote_lists_after_apply) {
            refresh_lists_and_maybe_reload_async("post-apply");
        }
    } catch (const std::exception& error) {
        result.error = error.what();
        Logger::instance().error(
            "Apply staged config task failed: {}", error.what());

        try {
            // Rollback remains on the established synchronous fence until its
            // own lifecycle is migrated. It must never inherit the verified
            // fence of the candidate which just failed.
            apply_prepared_runtime_inputs(std::move(rollback_prepared));
            result.rolled_back = true;
        } catch (const std::exception& rollback_error) {
            result.rolled_back = false;
            Logger::instance().error(
                "Rollback to previous config failed: {}",
                rollback_error.what());
        } catch (...) {
            result.rolled_back = false;
            Logger::instance().error(
                "Rollback to previous config failed: unknown error");
        }
    }
    return result;
}

ConfigApplyResult
Daemon::apply_validated_config_via_control_task_with_lease_return(
    Config config,
    std::string saved_config_json,
    RuntimeMutationAdmission::Lease& lease) {
    struct ExactLeaseReturn final {
        RuntimeMutationAdmission::Lease& destination;
        RuntimeMutationAdmission::Lease& owner;

        ~ExactLeaseReturn() noexcept {
            destination = std::move(owner);
        }
    };

    RuntimeMutationAdmission::Lease owner{std::move(lease)};
    const ExactLeaseReturn return_exact{lease, owner};
    const auto expected_lease_token = owner.token();

    if (is_event_loop_thread()) {
        ConfigApplyResult result;
        result.error =
            "Configuration pre-apply cannot wait on the control loop";
        result.runtime_unchanged = true;
        return result;
    }

    struct PreapplyLeaseSlot final {
        std::unique_ptr<RuntimeMutationAdmission::Lease> lease;
    };

    std::shared_ptr<ConfigApplyResult> result;
    std::shared_ptr<PreparedRuntimeInputs> prepared;
    std::shared_ptr<PreparedRuntimeInputs> rollback_prepared;
    std::shared_ptr<std::string> saved_config;
    ActiveConfigSnapshotHandle base_active_snapshot;
    std::shared_ptr<PreapplyLeaseSlot> returned;
    RuntimeFirewallLifecycleCompletion::Pair completion;
    RuntimeFirewallPreownedTerminalContinuation continuation;
    std::shared_ptr<RuntimeFirewallPreownedTerminalContinuation>
        final_continuation_slot;
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease_owner;
    bool refresh_remote_lists_after_apply = false;
    try {
        // Everything through lease_owner is private request setup. No
        // control-loop callback can observe it yet, so any exception here is
        // a clean rejection and ExactLeaseReturn restores the exact writer.
        result = std::make_shared<ConfigApplyResult>();
        prepared = std::make_shared<PreparedRuntimeInputs>();
        rollback_prepared = std::make_shared<PreparedRuntimeInputs>();
        saved_config =
            std::make_shared<std::string>(std::move(saved_config_json));
        base_active_snapshot = config_store_.pin_active_snapshot();
        const Config& active_config = base_active_snapshot->config;
        refresh_remote_lists_after_apply =
            remote_list_sources_changed(active_config, config);
        *prepared = prepare_runtime_inputs(
            config,
            RemoteListPreparationMode::MissingOrInvalid);
        *rollback_prepared = prepare_runtime_inputs(
            active_config,
            RemoteListPreparationMode::None);
        completion = RuntimeFirewallLifecycleCompletion::create();
        returned = std::make_shared<PreapplyLeaseSlot>();
        const auto apply_started_ts = unix_timestamp_now_seconds();
        result->apply_started_ts = apply_started_ts;
        auto completion_source = std::move(completion.source);
        RuntimeFirewallPreownedTerminalContinuation final_continuation{
            [this,
             returned,
             result,
             refresh_remote_lists_after_apply,
             expected_lease_token,
             completion_source = std::move(completion_source)](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact) mutable
                noexcept {
                bool request_post_apply_list_refresh = false;
                try {
                    const bool exact_lease_returned = exact &&
                        static_cast<bool>(*exact) &&
                        exact->token() == expected_lease_token &&
                        runtime_mutation_admission_.owns(*exact);
                    if (!exact_lease_returned) {
                        result->error =
                            "Configuration apply did not return its exact "
                            "mutation lease";
                        result->runtime_unchanged = false;
                    } else if (
                        terminal.outcome ==
                            RuntimeFirewallLifecycleOutcome::verified_success &&
                        !terminal.commit_ambiguous) {
                        const auto kind =
                            terminal.observed_config_identity
                            ? terminal.observed_config_identity->kind
                            : ConfigTerminalOperationKind::config_preapply;
                        if (kind ==
                            ConfigTerminalOperationKind::candidate) {
                            result->applied = true;
                            result->rolled_back = false;
                            result->runtime_unchanged = false;
                            result->error.clear();
                            request_post_apply_list_refresh =
                                refresh_remote_lists_after_apply;
                        } else if (
                            kind ==
                            ConfigTerminalOperationKind::rollback) {
                            result->applied = false;
                            result->rolled_back = true;
                            result->runtime_unchanged = false;
                            result->error = terminal.detail.empty()
                                ? "Configuration candidate was rolled back"
                                : terminal.detail;
                        } else {
                            result->error =
                                "Configuration generation returned an "
                                "unexpected terminal identity";
                            result->runtime_unchanged = false;
                        }
                    } else {
                        result->error = terminal.detail.empty()
                            ? "Configuration apply was not verified"
                            : terminal.detail;
                        result->runtime_unchanged =
                            terminal.outcome ==
                                RuntimeFirewallLifecycleOutcome::not_verified &&
                            terminal.previous_generation_certainly_retained &&
                            !terminal.committed &&
                            !terminal.commit_ambiguous;
                    }
                } catch (const std::exception& error) {
                    try {
                        result->error = error.what();
                    } catch (...) {
                    }
                    result->runtime_unchanged = false;
                } catch (...) {
                    try {
                        result->error =
                            "Configuration apply continuation failed";
                    } catch (...) {
                    }
                    result->runtime_unchanged = false;
                }
                returned->lease = std::move(exact);
                (void)completion_source.settle(std::move(terminal));
                // The result, exact lease and waiter are authoritative before
                // any ancillary work is attempted. A list refresh can then
                // fail or defer without relabelling an already-published
                // candidate or extending its writer authority.
                if (request_post_apply_list_refresh) {
                    try {
                        refresh_lists_and_maybe_reload_async(
                            "post-apply");
                    } catch (const std::exception& error) {
                        try {
                            Logger::instance().info(
                                "Post-configuration list refresh was "
                                "deferred after the candidate had already "
                                "been published: {}",
                                error.what());
                        } catch (...) {
                        }
                    } catch (...) {
                        try {
                            Logger::instance().info(
                                "Post-configuration list refresh was "
                                "deferred after the candidate had already "
                                "been published");
                        } catch (...) {
                        }
                    }
                }
            }};
        final_continuation_slot =
            std::make_shared<RuntimeFirewallPreownedTerminalContinuation>(
                std::move(final_continuation));
        continuation = RuntimeFirewallPreownedTerminalContinuation{
            [this,
             prepared,
             rollback_prepared,
             saved_config,
             base_active_snapshot,
             expected_lease_token,
             final_continuation_slot](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact) mutable
                noexcept {
                const bool exact_lease_returned = exact &&
                    static_cast<bool>(*exact) &&
                    exact->token() == expected_lease_token &&
                    runtime_mutation_admission_.owns(*exact);
                if (exact_lease_returned &&
                    terminal.outcome ==
                        RuntimeFirewallLifecycleOutcome::verified_success &&
                    !terminal.commit_ambiguous) {
                    begin_preowned_runtime_firewall_config_apply(
                        std::move(exact),
                        base_active_snapshot,
                        std::move(*prepared),
                        std::move(*rollback_prepared),
                        std::move(*saved_config),
                        std::move(*final_continuation_slot));
                    return;
                }
                if (!exact_lease_returned) {
                    terminal.outcome =
                        RuntimeFirewallLifecycleOutcome::not_verified;
                    terminal.previous_generation_certainly_retained = false;
                    try {
                        terminal.detail =
                            "Configuration pre-apply did not return its "
                            "exact mutation lease";
                    } catch (...) {
                    }
                }
                final_continuation_slot->invoke(
                    std::move(terminal), std::move(exact));
            }};
        lease_owner = std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(owner));
    } catch (const std::exception& error) {
        ConfigApplyResult setup_failure;
        setup_failure.runtime_unchanged = true;
        try {
            setup_failure.error = error.what();
        } catch (...) {
        }
        try {
            Logger::instance().error(
                "Configuration pre-apply setup failed: {}", error.what());
        } catch (...) {
        }
        return setup_failure;
    } catch (...) {
        ConfigApplyResult setup_failure;
        setup_failure.runtime_unchanged = true;
        try {
            setup_failure.error =
                "Configuration pre-apply setup failed";
        } catch (...) {
        }
        try {
            Logger::instance().error(
                "Configuration pre-apply setup failed: unknown error");
        } catch (...) {
        }
        return setup_failure;
    }
    std::optional<RuntimeFirewallImmediateDisposition> disposition;
    bool handoff_task_completed = false;
    std::exception_ptr handoff_failure;
    try {
        // Only this short ownership handoff is synchronous. The API worker,
        // never the control loop, waits for the typed terminal below.
        enqueue_control_task(
            [this,
             &lease_owner,
             &continuation,
             &disposition,
             &handoff_task_completed,
             &handoff_failure]() mutable {
                try {
                    disposition =
                        begin_preowned_runtime_firewall_config_preapply(
                            lease_owner, continuation);
                } catch (...) {
                    handoff_failure = std::current_exception();
                }
                handoff_task_completed = true;
            },
            true,
            "api-config-preapply-owner",
            true);
    } catch (...) {
        handoff_failure = std::current_exception();
    }

    if (!handoff_task_completed) {
        if (lease_owner) {
            owner = std::move(*lease_owner);
        }
        ConfigApplyResult result;
        result.error =
            "Configuration pre-apply owner handoff did not complete";
        result.runtime_unchanged = true;
        return result;
    }

    if (handoff_failure) {
        const bool exact_lease_still_unaccepted =
            lease_owner && static_cast<bool>(*lease_owner) &&
            lease_owner->token() == expected_lease_token &&
            runtime_mutation_admission_.owns(*lease_owner);
        if (exact_lease_still_unaccepted) {
            owner = std::move(*lease_owner);
        }
        result->error =
            "Configuration pre-apply owner handoff failed";
        // The task may fail while copying its private recovery snapshot,
        // before start_immediate_preowned consumes the token. The still-live
        // exact token proves that case clean. Once it has moved, conservatively
        // keep WAL/recovery because part of the firewall transaction may have
        // run before the exception surfaced.
        result->runtime_unchanged = exact_lease_still_unaccepted;
        return *result;
    }

    if (!disposition.has_value()) {
        // No active generation needs a pre-apply fence. Keep the same exact
        // mutation lease and hand the staged candidate directly to the
        // typed stopped-bootstrap owner; the HTTP worker still waits on the
        // same one-shot terminal below.
        if (!lease_owner || !static_cast<bool>(*lease_owner)) {
            result->error =
                "Configuration pre-apply lost its inactive-runtime lease";
            result->runtime_unchanged = false;
            return *result;
        }
        if (!final_continuation_slot ||
            !static_cast<bool>(*final_continuation_slot)) {
            owner = std::move(*lease_owner);
            result->error =
                "Configuration bootstrap continuation is unavailable";
            result->runtime_unchanged = true;
            return *result;
        }
        begin_preowned_runtime_firewall_config_bootstrap(
            std::move(lease_owner),
            base_active_snapshot,
            std::move(*prepared),
            std::move(*rollback_prepared),
            std::move(*saved_config),
            std::move(*final_continuation_slot));
        disposition = RuntimeFirewallImmediateDisposition::handed_off;
    }

    if (*disposition !=
        RuntimeFirewallImmediateDisposition::handed_off) {
        if (lease_owner) {
            owner = std::move(*lease_owner);
        }
        result->error = "Configuration pre-apply owner is busy";
        result->runtime_unchanged = true;
        return *result;
    }

    try {
        (void)completion.wait.wait();
    } catch (...) {
        // settle() stores the exact lease before waking this waiter. A
        // terminal string copy may still throw under allocation pressure,
        // but that must not turn a returned physical token into an emergency
        // release or a second acquisition.
        if (returned->lease &&
            static_cast<bool>(*returned->lease) &&
            returned->lease->token() == expected_lease_token &&
            runtime_mutation_admission_.owns(*returned->lease)) {
            owner = std::move(*returned->lease);
        }
        result->runtime_unchanged = false;
        try {
            result->error =
                "Configuration pre-apply completion could not be read";
        } catch (...) {
        }
        return *result;
    }
    if (!returned->lease ||
        !static_cast<bool>(*returned->lease) ||
        returned->lease->token() != expected_lease_token ||
        !runtime_mutation_admission_.owns(*returned->lease)) {
        result->error =
            "Configuration pre-apply did not return its exact mutation lease";
        result->runtime_unchanged = false;
        return *result;
    }
    owner = std::move(*returned->lease);
    return *result;
}

ListRefreshOperationResult Daemon::refresh_lists_via_api(std::optional<std::string> requested_name) {
    if (is_event_loop_thread()) {
        throw ApiError(
            "List refresh completion cannot wait on the control loop", 503);
    }
    auto mutation = acquire_runtime_mutation_or_throw(
        "refresh-lists", false, false);
    const auto expected_lease_token = mutation.token();
    if (config_store_.config_is_draft()) {
        throw ApiError("List refresh is unavailable while a draft config is staged", 409);
    }

    const auto active_snapshot = config_store_.pin_active_snapshot();
    const Config& config_snapshot = active_snapshot->config;
    const OutboundMarkMap& marks_snapshot = active_snapshot->outbound_marks;
    const bool runtime_active_snapshot = runtime_state_store_.snapshot().routing_runtime_active;
    const auto target_selection = select_remote_list_targets(config_snapshot, requested_name);
    if (!target_selection.ok()) {
        switch (target_selection.error) {
        case RemoteListTargetSelectionError::NotFound:
            throw ApiError("Requested list was not found", 404);
        case RemoteListTargetSelectionError::NotRemote:
            throw ApiError("Requested list is not URL-backed", 400);
        case RemoteListTargetSelectionError::None:
            break;
        }
    }

    // Preserve the currently published runtime inputs before the durable
    // list cache can change. If the candidate cannot be verified, the owner
    // must roll back to these exact pre-refresh inputs rather than rebuilding
    // a nominal rollback from the already-updated cache.
    std::shared_ptr<PreparedRuntimeInputs> rollback_prepared;
    if (runtime_active_snapshot) {
        rollback_prepared = std::make_shared<PreparedRuntimeInputs>(
            prepare_runtime_inputs(
                config_snapshot,
                RemoteListPreparationMode::None));
    }

    {
        const std::set<std::string> relevant_lists = collect_relevant_list_names(config_snapshot);
        const std::set<std::string> dns_relevant_lists = collect_dns_relevant_list_names(config_snapshot);
        const std::set<std::string> target_lists(target_selection.list_names.begin(),
                                                 target_selection.list_names.end());
        RemoteListRefreshControl control;
        control.cache_commit = make_guarded_cache_commit_callback();
        RemoteListsRefreshResult refresh_result =
            list_service_.refresh_remote_lists(
                config_snapshot,
                marks_snapshot,
                &relevant_lists,
                requested_name ? &target_lists : nullptr,
                &dns_relevant_lists,
                control);

        if (!refresh_result.changed_lists.empty()) {
            Logger::instance().info("Lists refresh (api): updated list(s): {}",
                                    format_list_names(refresh_result.changed_lists));
        } else if (!refresh_result.failed_lists.empty()) {
            Logger::instance().warn("Lists refresh (api): failed list(s): {}",
                                    format_list_names(refresh_result.failed_lists));
        } else {
            Logger::instance().info("Lists refresh (api): all checked list(s) are up-to-date.");
        }

        ListRefreshOperationResult operation_result;
        operation_result.refreshed_lists = refresh_result.refreshed_lists;
        operation_result.changed_lists = refresh_result.changed_lists;
        operation_result.failed_lists = refresh_result.failed_lists;

        const bool reload_required =
            should_reload_runtime_after_list_refresh(
                runtime_active_snapshot, refresh_result);
        if (!reload_required) {
            if (!target_selection.ok()) {
                return operation_result;
            }
            if (operation_result.refreshed_lists.empty()) {
                operation_result.message = "No URL-backed lists to refresh";
            } else if (!operation_result.failed_lists.empty()) {
                operation_result.message = "Lists refreshed with failures";
            } else if (operation_result.changed_lists.empty()) {
                operation_result.message = "Lists refreshed; no updates found";
            } else if (refresh_result.any_relevant_changed()) {
                operation_result.message =
                    "Lists refreshed; runtime is stopped so changes will apply on next start";
            } else {
                operation_result.message = "Lists refreshed";
            }
            return operation_result;
        }

        const auto schedule_force_reconcile = [this]() noexcept {
            try {
                enqueue_control_task(
                    [this]() {
                        schedule_deferred_list_refresh(
                            "api-refresh-recovery",
                            runtime_generation_.load(std::memory_order_acquire),
                            true);
                    },
                    false,
                    "api-refresh-lists-recovery",
                    true);
            } catch (const std::exception& error) {
                try {
                    Logger::instance().error(
                        "Could not schedule forced list-cache reconciliation: {}",
                        error.what());
                } catch (...) {
                }
            } catch (...) {
                try {
                    Logger::instance().error(
                        "Could not schedule forced list-cache reconciliation");
                } catch (...) {
                }
            }
        };

        std::shared_ptr<PreparedRuntimeInputs> candidate_prepared;
        try {
            candidate_prepared = std::make_shared<PreparedRuntimeInputs>(
                prepare_runtime_inputs(
                    active_snapshot->config,
                    RemoteListPreparationMode::None));
        } catch (const std::exception& error) {
            mutation.release();
            schedule_force_reconcile();
            Logger::instance().error(
                "Lists refresh (api) candidate preparation failed after "
                "the cache commit: {}",
                error.what());
            operation_result.message =
                "Lists refreshed; runtime reload preparation failed and recovery was scheduled";
            return operation_result;
        }

        struct ReturnedLeaseSlot final {
            std::unique_ptr<RuntimeMutationAdmission::Lease> lease;
        };
        auto returned = std::make_shared<ReturnedLeaseSlot>();
        auto completion = RuntimeFirewallLifecycleCompletion::create();
        auto completion_source = std::move(completion.source);
        RuntimeMutationLeaseHandoff handoff{
            std::make_unique<RuntimeMutationAdmission::Lease>(
                std::move(mutation))};

        bool stale_runtime = false;
        const auto generation = runtime_generation_.load(std::memory_order_acquire);
        bool owner_started = false;
        bool handoff_task_completed = false;
        std::string handoff_error;

        try {
            enqueue_control_task(
            [this,
             &owner_started,
             &handoff_task_completed,
             &handoff_error,
             &stale_runtime,
             active_snapshot,
             candidate_prepared,
             rollback_prepared,
             returned,
             completion_source = std::move(completion_source),
             handoff,
             expected_lease_token,
             generation]() mutable {
                handoff_task_completed = true;
                if (generation != runtime_generation_.load(std::memory_order_acquire)) {
                    stale_runtime = true;
                    Logger::instance().trace("lists_refresh_skip",
                                             "source=api reason=stale_runtime generation={}",
                                             generation);
                    return;
                }

                auto taken = handoff.take();
                if (!taken) {
                    handoff_error =
                        "API list refresh could not take its exact mutation lease";
                    return;
                }

                RuntimeFirewallPreownedTerminalContinuation continuation{
                    [this,
                     returned,
                     completion_source = std::move(completion_source),
                     expected_lease_token](
                        RuntimeFirewallLifecycleTerminal terminal,
                        std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                        mutable noexcept {
                        try {
                            if (!exact || !static_cast<bool>(*exact) ||
                                exact->token() != expected_lease_token ||
                                !runtime_mutation_admission_.owns(*exact)) {
                                terminal.outcome =
                                    RuntimeFirewallLifecycleOutcome::not_verified;
                                terminal.previous_generation_certainly_retained =
                                    false;
                                terminal.detail =
                                    "API list refresh did not return its exact mutation lease";
                            }
                        } catch (...) {
                            terminal.outcome =
                                RuntimeFirewallLifecycleOutcome::not_verified;
                            terminal.previous_generation_certainly_retained = false;
                        }
                        returned->lease = std::move(exact);
                        (void)completion_source.settle(std::move(terminal));
                    }};
                begin_preowned_runtime_firewall_active_reload(
                    std::move(taken.lease),
                    active_snapshot,
                    std::move(*candidate_prepared),
                    std::move(*rollback_prepared),
                    std::move(continuation));
                owner_started = true;
            },
            true,
            "api-refresh-lists-owner",
            true);
        } catch (const std::exception& error) {
            handoff_error = error.what();
        } catch (...) {
            handoff_error = "unknown owner handoff failure";
        }

        if (!owner_started) {
            auto reclaimed = handoff.take();
            if (reclaimed) {
                reclaimed.lease.reset();
            }
            schedule_force_reconcile();
            if (!handoff_task_completed) {
                operation_result.message =
                    "Lists refreshed; runtime owner handoff failed and recovery was scheduled";
            } else if (stale_runtime) {
                operation_result.message =
                    "Lists refreshed; runtime changed and recovery was scheduled";
            } else {
                operation_result.message = handoff_error.empty()
                    ? "Lists refreshed; runtime reload was deferred"
                    : "Lists refreshed; runtime owner rejected the reload and recovery was scheduled";
            }
            return operation_result;
        }

        RuntimeFirewallLifecycleTerminal terminal;
        try {
            terminal = completion.wait.wait();
        } catch (const std::exception& error) {
            if (returned->lease) {
                returned->lease.reset();
            }
            schedule_force_reconcile();
            Logger::instance().error(
                "Lists refresh (api) terminal could not be read: {}",
                error.what());
            operation_result.message =
                "Lists refreshed; runtime result was not available";
            return operation_result;
        }

        const bool exact_lease_returned =
            returned->lease && static_cast<bool>(*returned->lease) &&
            returned->lease->token() == expected_lease_token &&
            runtime_mutation_admission_.owns(*returned->lease);
        const bool candidate_published =
            exact_lease_returned &&
            terminal.outcome ==
                RuntimeFirewallLifecycleOutcome::verified_success &&
            !terminal.commit_ambiguous &&
            terminal.observed_config_identity &&
            terminal.observed_config_identity->kind ==
                ConfigTerminalOperationKind::candidate &&
            (terminal.committed || terminal.candidate_noop_verified);
        const bool rollback_verified =
            exact_lease_returned &&
            terminal.outcome ==
                RuntimeFirewallLifecycleOutcome::verified_success &&
            !terminal.commit_ambiguous &&
            terminal.observed_config_identity &&
            terminal.observed_config_identity->kind ==
                ConfigTerminalOperationKind::rollback &&
            (terminal.committed || terminal.candidate_noop_verified);

        operation_result.reloaded = candidate_published;
        if (returned->lease) {
            returned->lease.reset();
        }
        if (!candidate_published) {
            // The durable cache is already newer than the published runtime.
            // Release an exact returned writer first. If ownership was lost,
            // the deferred path still waits for admission before its bounded
            // reconcile against the current generation.
            schedule_force_reconcile();
        }

        if (!target_selection.ok()) {
            return operation_result;
        }
        if (!operation_result.refreshed_lists.size()) {
            operation_result.message = "No URL-backed lists to refresh";
        } else if (!operation_result.failed_lists.empty()) {
            operation_result.message = "Lists refreshed with failures";
        } else if (stale_runtime) {
            operation_result.message =
                "Lists refreshed; runtime changed before reload could be applied";
        } else if (operation_result.changed_lists.empty()) {
            operation_result.message = "Lists refreshed; no updates found";
        } else if (operation_result.reloaded) {
            operation_result.message = "Lists refreshed and runtime reloaded";
        } else if (rollback_verified) {
            operation_result.message =
                "Lists refreshed; runtime reload was rolled back and recovery was scheduled";
        } else if (exact_lease_returned) {
            operation_result.message =
                "Lists refreshed; runtime reload was not verified and recovery was scheduled";
        } else if (refresh_result.any_relevant_changed()) {
            operation_result.message =
                "Lists refreshed; runtime reload did not return its owner lease and recovery was scheduled";
        } else {
            operation_result.message = "Lists refreshed";
        }

        return operation_result;
    }
}

TestRoutingResult Daemon::run_api_routing_test(
    const std::string& target) {
    if (!event_loop_active_.load(std::memory_order_acquire)) {
        throw ApiError(
            "Routing diagnostics are unavailable until the control loop is running",
            503);
    }
    const RoutingTestDeadline operation_deadline =
        std::chrono::steady_clock::now() +
        kRoutingTestOperationTimeout;
    auto admitted = routing_test_admission_.try_acquire();
    if (!admitted.has_value()) {
        throw ApiError(
            "Too many routing tests are already running", 503);
    }

    auto snapshot_promise =
        std::make_shared<std::promise<RoutingTestSnapshot>>();
    auto snapshot_future = snapshot_promise->get_future();
    bool snapshot_posted = false;
    try {
        snapshot_posted = post_control_task(
            [this, snapshot_promise]() {
                try {
                    snapshot_promise->set_value(
                        capture_routing_test_snapshot());
                } catch (...) {
                    try {
                        snapshot_promise->set_exception(
                            std::current_exception());
                    } catch (...) {
                    }
                }
            },
            "api-test-routing-snapshot");
    } catch (const std::exception& error) {
        throw ApiError(
            std::string("Routing diagnostics snapshot is unavailable: ") +
                error.what(),
            503);
    }
    if (!snapshot_posted) {
        throw ApiError(
            "Routing diagnostics snapshot queue is unavailable", 503);
    }

    if (snapshot_future.wait_until(operation_deadline) !=
        std::future_status::ready) {
        throw ApiError(
            "Routing diagnostics snapshot deadline exceeded", 504);
    }
    std::shared_ptr<RoutingTestSnapshot> snapshot;
    try {
        snapshot = std::make_shared<RoutingTestSnapshot>(
            snapshot_future.get());
    } catch (const std::exception& error) {
        throw ApiError(
            std::string("Routing diagnostics snapshot failed: ") +
                error.what(),
            503);
    }

    auto promise = std::make_shared<std::promise<TestRoutingResult>>();
    auto future = promise->get_future();
    bool queued = false;
    try {
        queued = routing_test_executor_.try_post(
            "api-test-routing",
            [this,
             snapshot,
             target,
             promise,
             operation_deadline,
             lease = std::move(*admitted)]() mutable {
                (void)lease;
                try {
                    auto result = compute_test_routing(
                        snapshot->config,
                        list_service_.cache_manager(),
                        target,
                        &snapshot->realized_rules,
                        operation_deadline,
                        snapshot->firewall_backend);
                    result.unapplied_draft =
                        snapshot->unapplied_draft;
                    if (result.unapplied_draft) {
                        result.warnings.push_back(
                            "An unapplied draft exists; diagnostics use the active applied configuration.");
                    }
                    promise->set_value(std::move(result));
                } catch (...) {
                    try {
                        promise->set_exception(
                            std::current_exception());
                    } catch (...) {
                    }
                }
            });
    } catch (const std::exception& error) {
        throw ApiError(
            std::string("Routing test executor is unavailable: ") +
                error.what(),
            503);
    }
    if (!queued) {
        throw ApiError("Routing test executor queue is full", 503);
    }
    try {
        return future.get();
    } catch (const RoutingTestTimeoutError& error) {
        throw ApiError(error.what(), 504);
    }
}

void Daemon::setup_api() {
    // A previous bounded attempt may have reached any point below. Always
    // begin from an empty API ownership set; this is also a no-op on the first
    // startup attempt.
    if (!config_.api || !config_.api->enabled.value_or(false) || opts_.no_api) {
        retire_api_runtime_resources();
        return;
    }

    run_api_setup_with_strong_rollback(
        [this]() {

    api_server_ = std::make_unique<ApiServer>(*config_.api);

    api_ctx_ = std::make_unique<ApiContext>(ApiContext{
        config_path_,
        *dns_test_broadcaster_,
        [this]() {
            return config_store_.visible_config();
        },
        [this]() {
            return config_store_.config_is_draft();
        },
        [this](Config staged_config, std::string staged_config_json) {
            config_store_.stage_config(std::move(staged_config), std::move(staged_config_json));
            if (status_stream_) {
                status_stream_->reconcile();
            }
        },
        [this]() -> std::optional<std::pair<Config, std::string>> {
            return config_store_.staged_snapshot();
        },
        [this]() {
            config_store_.clear_staged();
            if (status_stream_) {
                status_stream_->reconcile();
            }
        },
        [this](const Config& config) {
            validate_config(config);

            const auto active_pid_file = config_store_.active_config()
                .daemon.value_or(DaemonConfig{}).pid_file.value_or("");
            const auto candidate_pid_file = config.daemon.value_or(DaemonConfig{})
                .pid_file.value_or("");
            if (candidate_pid_file != active_pid_file) {
                throw ConfigValidationError(std::vector<ConfigValidationIssue>{{
                    "daemon.pid_file",
                    "daemon.pid_file cannot be changed while the daemon is running",
                }});
            }

            const auto marks = allocate_outbound_marks(
                config.fwmark.value_or(FwmarkConfig{}),
                config.outbounds.value_or(std::vector<Outbound>{}));
            const auto runtime_snapshot = runtime_state_store_.snapshot();
            const auto& urltest_selections = runtime_snapshot.firewall_state.get_urltest_selections();

            (void)build_fw_rule_states(config, marks, &urltest_selections);

            ListStreamer streamer(list_service_.cache_manager());
            const DnsConfig dns_cfg = config.dns.value_or(DnsConfig{});
            const auto keenetic_dns = prepare_keenetic_dns_view(
                config,
                /*allow_refresh=*/true);
            DnsServerRegistry dns_registry(
                dns_cfg, keenetic_dns.snapshot);
            const Ipv6SupportDecision ipv6_decision = resolve_ipv6_support(config);
            log_ipv6_support_decision_once(ipv6_decision);
            (void)DnsmasqGenerator::compute_config_hash(
                dns_registry,
                streamer,
                config.route.value_or(RouteConfig{}),
                dns_cfg,
                config.lists.value_or(std::map<std::string, ListConfig>{}),
                KEEN_PBR3_VERSION_FULL_STRING,
                resolver_ipv6_policy(ipv6_decision));
        },
        [this]() {
            const auto runtime_snapshot = runtime_state_store_.snapshot();
            const auto& system_info = cached_system_info();
            ServiceHealthState service_health;
            service_health.status = runtime_snapshot.routing_runtime_active
                ? api::HealthResponseStatus::RUNNING
                : api::HealthResponseStatus::STOPPED;
            service_health.runtime_state =
                runtime_state_name(runtime_snapshot.runtime_state);
            service_health.runtime_state_reason =
                runtime_snapshot.runtime_state_reason;
            service_health.os_type = system_info.os_type;
            service_health.os_version = system_info.os_version;
            service_health.build_variant = system_info.build_variant;
            service_health.resolver_config_hash = runtime_snapshot.resolver_config_hash;
            service_health.resolver_config_hash_actual = runtime_snapshot.resolver_config_hash_actual;
            service_health.resolver_config_hash_actual_ts = runtime_snapshot.resolver_config_hash_actual_ts;
            service_health.resolver_live_status = runtime_snapshot.resolver_live_status;
            service_health.resolver_config_probe_status =
                runtime_snapshot.resolver_config_probe_status;
            service_health.resolver_last_probe_ts = runtime_snapshot.resolver_last_probe_ts;
            service_health.apply_started_ts = runtime_snapshot.apply_started_ts;
            service_health.resolver_config_sync_state =
                runtime_snapshot.resolver_config_sync_state;
            service_health.config_is_draft = config_store_.config_is_draft();
            service_health.lifecycle_operation = lifecycle_operation_store_.snapshot();
            return service_health;
        },
        [this]() {
            const auto check_once = [this]() {
                const auto runtime_snapshot = runtime_state_store_.snapshot();
                auto report = build_routing_health_report(
                    firewall_->backend(),
                    firewall_->raw_prerouting_mode(),
                    runtime_snapshot.firewall_state,
                    runtime_snapshot.route_specs,
                    runtime_snapshot.policy_rule_specs,
                    netlink_,
                    runtime_snapshot.routing_inventory_complete &&
                        runtime_snapshot.routing_kernel_state_known);
                // From the live backend: this is what the last apply observed.
                // Re-inspecting the firmware chain on a health request would
                // both duplicate the writer and answer a different question.
                report.ttl_bypass_state = firewall_->ttl_bypass_state_name();
                report.ttl_bypass_detail =
                    firewall_->ttl_bypass_state_detail();
                report.ppe_deoffload = firewall_->ppe_deoffload_snapshot();
                return report;
            };

            auto report = check_once();
            if (!report.overall_ok) {
                // A route transaction and its published runtime snapshot are
                // observed through different kernel/userspace interfaces. A
                // reader can therefore catch the tiny convergence window and
                // compare the new route against the previous snapshot. Require
                // the mismatch to survive a second complete read before
                // exposing it as a fault; persistent faults are unchanged.
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                report = check_once();
            }
            return report;
        },
        [this]() {
            const auto active_snapshot =
                config_store_.pin_active_snapshot();
            const Config& config_snapshot = active_snapshot->config;
            const auto runtime_snapshot = runtime_state_store_.snapshot();

            return build_runtime_outbounds_response(
                config_snapshot,
                netlink_,
                [&runtime_snapshot](const std::string& tag) -> std::optional<UrltestState> {
                    auto it = runtime_snapshot.urltest_states.find(tag);
                    if (it == runtime_snapshot.urltest_states.end()) {
                        return std::nullopt;
                    }
                    return it->second;
                },
                [this, active_snapshot, &config_snapshot](
                    const std::string& tag)
                    -> std::optional<InterfaceProbeResult> {
                    if (!config_snapshot.outbounds.has_value()) {
                        return std::nullopt;
                    }
                    const auto& outbounds = *config_snapshot.outbounds;
                    const auto stable_outbound = std::find_if(
                        outbounds.begin(),
                        outbounds.end(),
                        [&tag](const Outbound& candidate) {
                            return candidate.tag == tag &&
                                   candidate.type == OutboundType::INTERFACE;
                        });
                    const auto& marks =
                        active_snapshot->outbound_marks;
                    const auto mark = marks.find(tag);
                    if (stable_outbound == outbounds.end() ||
                        mark == marks.end()) {
                        return std::nullopt;
                    }
                    return interface_probe_.result_for(
                        InterfaceProbe::Target{
                            tag,
                            mark->second,
                            stable_outbound->interface.value_or(
                                std::string{})});
                });
        },
        [this]() {
            return build_runtime_interface_inventory_with_uptime();
        },
        [this](const Config& config) {
            return build_list_refresh_state_map(config, list_service_.cache_manager());
        },
        [this](const std::string& target) {
            return run_api_routing_test(target);
        },
        []() {
            throw std::logic_error(
                "Legacy config-operation admission reached production wiring");
        },
        []() {},
        [this](Config config, std::string saved_config_json) -> ConfigApplyResult {
            return apply_validated_config_via_control_task(std::move(config),
                                                           std::move(saved_config_json));
        },
        []() {
            throw std::logic_error(
                "Production runtime start requires exact lease handoff");
        },
        [this]() {
            run_runtime_control_operation_or_throw("api-stop-runtime",
                                                   "Stop routing runtime",
                                                   [this]() { stop_routing_runtime(); });
        },
        []() {
            throw std::logic_error(
                "Production runtime restart requires exact lease handoff");
        },
        [this](std::optional<std::string> requested_name) {
            return refresh_lists_via_api(requested_name);
        },
        nullptr,
        &lifecycle_operations_,
    });
    api_ctx_->get_diagnostic_tasks_fn = [this]() {
        return build_diagnostic_tasks_response(periodic_task_metrics_);
    };
    api_ctx_->acquire_runtime_mutation_fn =
        [this](std::string label,
               bool require_runtime_running,
               bool require_runtime_stopped) {
            return acquire_runtime_mutation_or_throw(
                std::move(label),
                require_runtime_running,
                require_runtime_stopped);
        };
    api_ctx_->validate_runtime_mutation_lease_fn =
        [this](const RuntimeMutationAdmission::Lease& lease) noexcept {
            return runtime_mutation_admission_.owns(lease);
        };
    api_ctx_->try_acquire_runtime_mutation_handoff_gate_fn =
        [this](const RuntimeMutationAdmission::Lease& lease) noexcept {
            return runtime_mutation_admission_
                .try_acquire_handoff_gate(lease);
        };
    api_ctx_->enqueue_apply_validated_config_with_lease_return_fn =
        [this](Config config,
               std::string saved_config_json,
               RuntimeMutationAdmission::Lease& lease) {
            return apply_validated_config_via_control_task_with_lease_return(
                std::move(config),
                std::move(saved_config_json),
                lease);
        };
    api_ctx_->start_runtime_with_lease_fn =
        [this](RuntimeMutationAdmission::Lease lease) {
            start_routing_runtime_with_lease(std::move(lease));
        };
    api_ctx_->restart_runtime_with_lease_fn =
        [this](RuntimeMutationAdmission::Lease lease) {
            restart_routing_runtime_with_lease(std::move(lease));
        };
    status_stream_ = std::make_unique<StatusStream>([this]() {
        return build_runtime_inventory(*api_ctx_);
    });
    api_ctx_->status_stream = status_stream_.get();
    api_ctx_->emergency_quiesce_runtime_fn =
        [this]() {
            // The config-save handler already owns the runtime mutation lease.
            // Do not call the public stop callback here: it would try to
            // acquire a second lease and reject the fail-closed stop as
            // self-conflicting.
            enqueue_control_task(
                [this]() { stop_routing_runtime(); },
                true,
                "config-save-emergency-quiesce");
        };
    api_ctx_->get_visible_config_snapshot_fn =
        [this]() {
            return config_store_.visible_snapshot();
        };
    api_ctx_->get_staged_config_cas_snapshot_fn =
        [this]() {
            return config_store_.staged_cas_snapshot();
        };
    api_ctx_->stage_config_if_visible_revision_fn =
        [this](
            const std::string& expected_visible_revision,
            Config staged_config,
            std::string staged_config_json) {
            const bool staged =
                config_store_.stage_config_if_visible_revision(
                    expected_visible_revision,
                    std::move(staged_config),
                    std::move(staged_config_json));
            if (staged && status_stream_) {
                status_stream_->reconcile();
            }
            return staged;
        };
    api_ctx_->replace_interface_traffic_targets_fn =
        [this](std::string source, std::vector<std::string> names) {
            replace_interface_traffic_targets(
                std::move(source), std::move(names));
        };
    api_ctx_->request_netfilter_runtime_refresh_fn = [this]() {
        bool admitted = false;
        try {
            enqueue_control_task(
                [this, &admitted]() {
                    schedule_netfilter_runtime_refresh(
                        NetfilterRefreshReason::full);
                    // The scheduler owns a retained reason before publishing
                    // its timer.  Even timer admission failure is therefore
                    // recoverable by the existing periodic control owner.
                    admitted = true;
                },
                /*wait_for_completion=*/true,
                "nfqws-ppe-netfilter-refresh",
                /*require_active_event_loop=*/true);
        } catch (...) {
            // During startup rollback or shutdown the HTTP worker must never
            // fall back to inline firewall work.  Final daemon cleanup owns
            // the graph in that window; report that no runtime refresh was
            // admitted instead.
            return false;
        }
        return admitted;
    };
#ifdef USE_KEENETIC_API
    api_ctx_->get_ndms_native_import_readiness_fn = [this]() noexcept {
        return ndms_native_import_journal_readiness_.load(
            std::memory_order_acquire);
    };
    api_ctx_->observe_ndms_native_inventory_projection_fn =
        [this](
            const std::vector<NdmsTunnelInterface>& interfaces,
            const bool catalog_fresh) {
            const auto ownership =
                ndms_native_ownership_store_.inspect_bounded_read_only();
            const auto import_inventory =
                ndms_native_import_wal_store_.try_inventory();
            const auto import_readiness =
                summarize_ndms_native_import_readiness(import_inventory);
            const auto delete_readiness =
                ndms_native_delete_wal_store_.readiness();
            return project_ndms_native_inventory(
                interfaces,
                catalog_fresh,
                ownership,
                import_readiness,
                delete_readiness);
        };
    const auto reserve_native_mutation =
        [this](
            const char* label,
            const NativeMutationReservationPurpose purpose,
            const bool require_clean_journals)
        -> std::shared_ptr<SensitiveRequestReservation> {
        const auto publish_unavailable = [this]() noexcept {
            ndms_native_import_journal_readiness_.store(
                NdmsNativeImportJournalReadinessState::unavailable,
                std::memory_order_release);
            ndms_native_mutation_admission_.store(
                NdmsNativeMutationAdmissionState::unavailable,
                std::memory_order_release);
        };
        try {
            // Existing production order is load-bearing:
            // maintenance -> runtime admission -> native cross-process flock.
            auto maintenance = std::make_unique<MaintenanceCoordinator>(
                label);
            auto runtime = acquire_runtime_mutation_or_throw(
                label, false, false);
            auto writer = admit_ndms_native_writer(
                ndms_native_observation_store_.state_directory(),
                std::move(maintenance),
                std::move(runtime));
            if (writer.state !=
                NdmsNativeWriterAdmissionState::admitted) {
                Logger::instance().warn(
                    "Native VPN operation was not started: writer admission {}",
                    ndms_native_writer_admission_state_name(writer.state));
                publish_unavailable();
                return {};
            }

            writer.lease.verify_held();
            ndms_native_import_wal_store_.sweep_orphaned_temporaries();
            ndms_native_delete_wal_store_.sweep_orphaned_temporaries();
            const auto delete_readiness =
                ndms_native_delete_wal_store_.readiness();
            const auto inventory =
                ndms_native_import_wal_store_.try_inventory();
            writer.lease.verify_held();

            const auto import_state =
                summarize_ndms_native_import_readiness(inventory);
            const auto mutation_state =
                summarize_ndms_native_mutation_admission(
                    inventory, delete_readiness);
            ndms_native_import_journal_readiness_.store(
                import_state, std::memory_order_release);
            if (require_clean_journals &&
                mutation_state !=
                    NdmsNativeMutationAdmissionState::admitted) {
                ndms_native_mutation_admission_.store(
                    mutation_state, std::memory_order_release);
                return {};
            }

            // While this exact token is live, every other request must see a
            // fail-closed report even though both journals were just clean.
            ndms_native_mutation_admission_.store(
                NdmsNativeMutationAdmissionState::blocked,
                std::memory_order_release);
            return std::make_shared<NativeMutationRequestReservation>(
                this,
                purpose,
                std::move(writer.lease),
                ndms_native_import_wal_store_,
                ndms_native_delete_wal_store_,
                ndms_native_import_journal_readiness_,
                ndms_native_mutation_admission_);
        } catch (...) {
            // Never upgrade readiness from separately observed WALs without
            // the complete ordered writer chain.
            publish_unavailable();
            return {};
        }
    };

    const auto read_native_dependency_snapshot =
        [this]() -> std::optional<NdmsNativeConfigDependencySnapshot> {
        return config_store_.project_active_and_staged(
            [](const Config& active,
               const std::optional<Config>& staged)
                -> std::optional<NdmsNativeConfigDependencySnapshot> {
                NdmsNativeConfigDependencySnapshot snapshot;
                snapshot.active =
                    project_ndms_native_config_dependencies(active);
                if (staged.has_value()) {
                    snapshot.staged =
                        project_ndms_native_config_dependencies(*staged);
                }
                return snapshot;
            });
    };

    api_ctx_->reserve_ndms_native_import_fn =
        [this, reserve_native_mutation,
         read_native_dependency_snapshot]() {
            auto opaque_reservation = reserve_native_mutation(
                "ndms-native-import",
                NativeMutationReservationPurpose::new_import,
                true);
            auto* reservation = dynamic_cast<
                NativeMutationRequestReservation*>(
                    opaque_reservation.get());
            if (reservation == nullptr ||
                !reservation->owned_by(
                    this,
                    NativeMutationReservationPurpose::new_import)) {
                return std::shared_ptr<SensitiveRequestReservation>{};
            }
            try {
                reservation->writer().verify_held();
                NdmsNativeConfigDependencyProvider dependencies{
                    read_native_dependency_snapshot};
                NdmsNativeFreshImportPreflight preflight{
                    ndms_native_import_wal_store_,
                    ndms_native_delete_wal_store_,
                    ndms_native_ownership_store_,
                    ndms_native_secret_snapshot_store_,
                    dependencies};
                const auto result = preflight.check_before_secret_take(
                    reservation->writer());
                if (!result.secret_body_may_be_taken()) {
                    Logger::instance().warn(
                        "Native VPN import was not started: preflight {} ({})",
                        ndms_native_fresh_import_preflight_status_name(
                            result.status),
                        ndms_native_fresh_import_preflight_stop_name(
                            result.stop));
                    return std::shared_ptr<SensitiveRequestReservation>{};
                }
                return opaque_reservation;
            } catch (...) {
                return std::shared_ptr<SensitiveRequestReservation>{};
            }
        };
    api_ctx_->run_ndms_native_import_fn =
        [this](
            std::string&& raw_configuration,
            const std::string& display_name,
            const NdmsNativeExternalWriterRaceAcceptance acceptance,
            const std::shared_ptr<SensitiveRequestReservation>&
                opaque_reservation) {
            NativeImportBodyWipeGuard raw_guard{raw_configuration};
            auto* reservation = dynamic_cast<
                NativeMutationRequestReservation*>(
                    opaque_reservation.get());
            if (reservation == nullptr ||
                !reservation->owned_by(
                    this,
                    NativeMutationReservationPurpose::new_import)) {
                return blocked_native_import(
                    NdmsNativeCooperativeImportStop::
                        cooperative_writer_admission_failed,
                    acceptance);
            }
            try {
                reservation->writer().verify_held();
                NdmsNativeCooperativeImportCoordinator coordinator{
                    ndms_native_observation_store_,
                    ndms_native_import_wal_store_,
                    ndms_native_delete_wal_store_,
                    ndms_native_secret_snapshot_store_,
                    ndms_native_ownership_store_};
                return coordinator.import_once(
                    reservation->writer(),
                    std::move(raw_configuration),
                    acceptance,
                    display_name);
            } catch (...) {
                return blocked_native_import(
                    NdmsNativeCooperativeImportStop::unexpected_failure,
                    acceptance);
            }
        };

    api_ctx_->reserve_ndms_native_import_recovery_fn =
        [reserve_native_mutation]() {
            return reserve_native_mutation(
                "ndms-native-import-recovery",
                NativeMutationReservationPurpose::import_recovery,
                false);
        };
    api_ctx_->resume_ndms_native_import_fn =
        [this](
            const NdmsNativeExternalWriterRaceAcceptance acceptance,
            const std::shared_ptr<SensitiveRequestReservation>&
                opaque_reservation) {
            auto* reservation = dynamic_cast<
                NativeMutationRequestReservation*>(
                    opaque_reservation.get());
            if (reservation == nullptr ||
                !reservation->owned_by(
                    this,
                    NativeMutationReservationPurpose::import_recovery)) {
                return blocked_native_import_recovery(
                    NdmsNativeCooperativeImportResumeStop::writer_missing,
                    acceptance);
            }
            try {
                reservation->writer().verify_held();
                NdmsNativeCooperativeImportCoordinator coordinator{
                    ndms_native_observation_store_,
                    ndms_native_import_wal_store_,
                    ndms_native_delete_wal_store_,
                    ndms_native_secret_snapshot_store_,
                    ndms_native_ownership_store_};
                return coordinator.resume_once(
                    reservation->writer(), acceptance);
            } catch (...) {
                return blocked_native_import_recovery(
                    NdmsNativeCooperativeImportResumeStop::
                        unexpected_failure,
                    acceptance);
            }
        };

    api_ctx_->reserve_ndms_native_delete_fn =
        [reserve_native_mutation]() {
            return reserve_native_mutation(
                "ndms-native-delete",
                NativeMutationReservationPurpose::new_delete,
                false);
        };
    api_ctx_->run_ndms_native_delete_fn =
        [this, read_native_dependency_snapshot](
            const NdmsNativeCooperativeDeleteRequest& request,
            const std::shared_ptr<SensitiveRequestReservation>&
                opaque_reservation) {
            auto* reservation = dynamic_cast<
                NativeMutationRequestReservation*>(
                    opaque_reservation.get());
            if (reservation == nullptr ||
                !reservation->owned_by(
                    this,
                    NativeMutationReservationPurpose::new_delete)) {
                return blocked_native_delete(
                    NdmsNativeCooperativeDeleteStop::writer_missing);
            }
            try {
                reservation->writer().verify_held();
                NdmsNativeConfigDependencyProvider dependencies{
                    read_native_dependency_snapshot};
                NdmsNativeCooperativeDeleteCoordinator coordinator{
                    ndms_native_observation_store_,
                    ndms_native_import_wal_store_,
                    ndms_native_delete_wal_store_,
                    ndms_native_secret_snapshot_store_,
                    ndms_native_ownership_store_,
                    dependencies};
                auto result = coordinator.delete_once(
                    reservation->writer(), request);
                Logger::instance().info(
                    "Native VPN delete {}: status={}, stop={}",
                    request.interface_name,
                    ndms_native_cooperative_delete_status_name(
                        result.status),
                    ndms_native_cooperative_delete_stop_name(result.stop));
                if (result.request_may_have_been_dispatched ||
                    result.status ==
                        NdmsNativeCooperativeDeleteStatus::
                            save_acknowledged_unverified) {
                    shared_ndms_catalog_cache().invalidate();
                }
                return result;
            } catch (...) {
                return blocked_native_delete(
                    NdmsNativeCooperativeDeleteStop::unexpected_failure);
            }
        };
    api_ctx_->reserve_ndms_native_delete_recovery_fn =
        [reserve_native_mutation]() {
            return reserve_native_mutation(
                "ndms-native-delete-recovery",
                NativeMutationReservationPurpose::delete_recovery,
                false);
        };
    api_ctx_->resume_ndms_native_delete_fn =
        [this, read_native_dependency_snapshot](
            const NdmsNativeCooperativeDeleteResumeAcknowledgement&
                acknowledgement,
            const std::shared_ptr<SensitiveRequestReservation>&
                opaque_reservation) {
            auto* reservation = dynamic_cast<
                NativeMutationRequestReservation*>(
                    opaque_reservation.get());
            if (reservation == nullptr ||
                !reservation->owned_by(
                    this,
                    NativeMutationReservationPurpose::delete_recovery)) {
                return blocked_native_delete(
                    NdmsNativeCooperativeDeleteStop::writer_missing);
            }
            try {
                reservation->writer().verify_held();
                NdmsNativeConfigDependencyProvider dependencies{
                    read_native_dependency_snapshot};
                NdmsNativeCooperativeDeleteCoordinator coordinator{
                    ndms_native_observation_store_,
                    ndms_native_import_wal_store_,
                    ndms_native_delete_wal_store_,
                    ndms_native_secret_snapshot_store_,
                    ndms_native_ownership_store_,
                    dependencies};
                auto result = coordinator.resume_once(
                    reservation->writer(), acknowledgement);
                if (result.request_may_have_been_dispatched ||
                    result.status ==
                        NdmsNativeCooperativeDeleteStatus::
                            save_acknowledged_unverified) {
                    shared_ndms_catalog_cache().invalidate();
                }
                return result;
            } catch (...) {
                return blocked_native_delete(
                    NdmsNativeCooperativeDeleteStop::unexpected_failure);
            }
        };
    api_ctx_->reserve_ndms_native_tombstone_forget_fn =
        [reserve_native_mutation]() {
            return reserve_native_mutation(
                "ndms-native-tombstone-forget",
                NativeMutationReservationPurpose::tombstone_forget,
                false);
        };
    api_ctx_->run_ndms_native_tombstone_forget_fn =
        [this, read_native_dependency_snapshot](
            const NdmsNativeTombstoneForgetRequest& request,
            const std::shared_ptr<SensitiveRequestReservation>&
                opaque_reservation) {
            auto* reservation = dynamic_cast<
                NativeMutationRequestReservation*>(
                    opaque_reservation.get());
            if (reservation == nullptr ||
                !reservation->owned_by(
                    this,
                    NativeMutationReservationPurpose::
                        tombstone_forget)) {
                return blocked_native_tombstone_forget(
                    NdmsNativeTombstoneForgetStop::writer_missing,
                    request.interface_name);
            }
            try {
                reservation->writer().verify_held();
                NdmsNativeConfigDependencyProvider dependencies{
                    read_native_dependency_snapshot};
                NdmsNativeTombstoneForgetCoordinator coordinator{
                    ndms_native_import_wal_store_,
                    ndms_native_delete_wal_store_,
                    ndms_native_secret_snapshot_store_,
                    ndms_native_ownership_store_,
                    dependencies};
                auto result = coordinator.forget_once(
                    reservation->writer(), request);
                Logger::instance().info(
                    "Native VPN tombstone forget {}: status={}, stop={}, "
                    "snapshot={}, tombstone={}",
                    request.interface_name,
                    ndms_native_tombstone_forget_status_name(
                        result.status),
                    ndms_native_tombstone_forget_stop_name(result.stop),
                    ndms_native_tombstone_forget_artifact_state_name(
                        result.snapshot_state),
                    ndms_native_tombstone_forget_artifact_state_name(
                        result.tombstone_state));
                return result;
            } catch (...) {
                return blocked_native_tombstone_forget(
                    NdmsNativeTombstoneForgetStop::unexpected_failure,
                    request.interface_name);
            }
        };
    api_ctx_->run_ndms_native_interface_lifecycle_fn =
        [this, reserve_native_mutation](
            std::string interface_name,
            const NdmsNativeInterfaceLifecycleAction action) {
            NdmsNativeInterfaceLifecycleResult unavailable;
            auto opaque_reservation = reserve_native_mutation(
                "ndms-native-interface-lifecycle",
                NativeMutationReservationPurpose::lifecycle,
                false);
            auto* reservation = dynamic_cast<
                NativeMutationRequestReservation*>(
                    opaque_reservation.get());
            if (reservation == nullptr ||
                !reservation->owned_by(
                    this,
                    NativeMutationReservationPurpose::lifecycle)) {
                return unavailable;
            }
            try {
                reservation->writer().verify_held();
                NdmsNativeLibcurlExactMutationBackend backend;
                NdmsNativeInterfaceLifecycleCoordinator coordinator{
                    backend};
                auto result = coordinator.apply_once(
                    reservation->writer(),
                    std::move(interface_name),
                    action);
                if (result.request_may_have_been_dispatched ||
                    result.status ==
                        NdmsNativeInterfaceLifecycleStatus::completed) {
                    shared_ndms_catalog_cache().invalidate();
                }
                return result;
            } catch (...) {
                return unavailable;
            }
        };
#endif
    refresh_interface_traffic_config_targets(config_);
    lifecycle_operation_store_.set_publish_callback([this]() {
        if (status_stream_) status_stream_->reconcile();
    });
    setup_conntrack_events();
    register_api_handlers(*api_server_, *api_ctx_);

    // Latency with its measurement age. Kept out of the generated runtime
    // types on purpose: a stale figure that looks live is worse than one
    // labelled "measured 12 s ago", and the age belongs to the probe rather
    // than to the outbound state schema.
    api_server_->get("/api/system/probes", [this]() -> std::string {
        const auto active_snapshot =
            config_store_.pin_active_snapshot();
        const Config& config_snapshot = active_snapshot->config;
        const auto now = std::chrono::steady_clock::now();

        nlohmann::json response;
        response["interval_seconds"] = 20;
        nlohmann::json probes = nlohmann::json::object();

        for (const auto& outbound :
             config_snapshot.outbounds.value_or(std::vector<Outbound>{})) {
            if (outbound.type != OutboundType::INTERFACE) {
                continue;
            }
            const auto& marks = active_snapshot->outbound_marks;
            const auto mark = marks.find(outbound.tag);
            if (mark == marks.end()) {
                continue;
            }
            const auto result = interface_probe_.result_for(
                InterfaceProbe::Target{
                    outbound.tag,
                    mark->second,
                    outbound.interface.value_or(std::string{})});
            if (!result.has_value()) {
                continue;
            }
            nlohmann::json entry;
            entry["success"] = result->success;
            // Without this the reader cannot tell a measurement of the tunnel
            // from a measurement of the router's own WAN.
            entry["attributed"] = result->attributed;
            entry["latency_ms"] = result->latency_ms;
            entry["age_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(
                                       now - result->measured_at).count();
            if (!result->error.empty()) {
                entry["error"] = result->error;
            }
            if (outbound.interface.has_value()) {
                entry["interface"] = *outbound.interface;
            }
            probes[outbound.tag] = std::move(entry);
        }

        response["probes"] = std::move(probes);
        return response.dump();
    });

    // Manual "measure now": the scheduled round is deliberately unhurried, so
    // there has to be a way to ask for a fresh figure on the spot.
    api_server_->post(
        "/api/system/probes/run",
        [this](const std::string& request_body) -> std::string {
        // An optional {"tag": "..."} narrows this to one outbound. Without it
        // the endpoint keeps its original meaning - the whole coalesced round -
        // so an older frontend and any script calling it keep working.
        std::string requested_tag;
        if (!request_body.empty()) {
            try {
                const auto request = nlohmann::json::parse(request_body);
                if (request.is_object()) {
                    const auto tag = request.find("tag");
                    if (tag != request.end() && tag->is_string()) {
                        requested_tag = tag->get<std::string>();
                    }
                }
            } catch (const nlohmann::json::exception&) {
                throw ApiError("invalid probe request JSON", 400);
            }
        }

        if (!requested_tag.empty()) {
            // Target discovery reads config_ and outbound_marks_, which are
            // owned by the event-loop thread.  The HTTP worker may run beside
            // a config reload, so admission and the immutable target snapshot
            // must be taken on that owner thread as one control operation.
            bool started = false;
            try {
                enqueue_control_task(
                    [this, &requested_tag, &started]() {
                        started = start_targeted_interface_probe(requested_tag);
                    },
                    /*wait_for_completion=*/true,
                    "targeted-interface-probe-admission:" + requested_tag,
                    /*require_active_event_loop=*/true);
            } catch (...) {
                started = false;
            }
            nlohmann::json response;
            response["ok"] = true;
            // False here means the tag is unknown, already being probed, or
            // the daemon could not take the work. The caller needs to know
            // that so it can stop a spinner for a probe that never started.
            response["scheduled"] = started;
            response["tag"] = requested_tag;
            return response.dump();
        }

        const auto admission =
            interface_probe_gate_.request(/*manual=*/true);
        bool scheduled = admission.manual_accepted;
        if (admission.launch) {
            bool posted = false;
            try {
                posted = post_control_task(
                    [this]() { start_interface_probe_round(); },
                    "manual-interface-probe");
            } catch (...) {
                // std::function/control-queue allocation may fail before the
                // task owns the admitted round. Never leave the manual gate
                // permanently busy in that case.
                (void)interface_probe_gate_.abort();
                scheduled = false;
            }
            if (!posted) {
                (void)interface_probe_gate_.abort();
                scheduled = false;
            }
        }
        nlohmann::json response;
        response["ok"] = true;
        response["scheduled"] = scheduled;
        return response.dump();
    });

    const std::filesystem::path frontend_root(KEEN_PBR_FRONTEND_ROOT);
    const std::filesystem::path frontend_index = frontend_root / "index.html";
    std::filesystem::path frontend_index_gzip = frontend_index;
    frontend_index_gzip += ".gz";
    const bool has_frontend_root =
        std::filesystem::is_directory(frontend_root) &&
        (std::filesystem::is_regular_file(frontend_index) ||
         std::filesystem::is_regular_file(frontend_index_gzip));
    if (!has_frontend_root) {
        Logger::instance().warn(
            "API enabled but frontend root is unavailable: {} (missing directory or index.html(.gz)). API endpoints will remain available.",
            frontend_root.string());
    } else if (!api_server_->register_static_root(frontend_root.string())) {
        Logger::instance().warn(
            "Failed to register frontend static root: {}. API endpoints will remain available.",
            frontend_root.string());
    } else {
        Logger::instance().info("Frontend static root: {}", frontend_root.string());
    }

    const std::string listen_addr = config_.api->listen.value_or("0.0.0.0:12121");
    Logger::instance().info("Starting REST API on {}", listen_addr);
    try {
        api_server_->start();
        Logger::instance().info("REST API listening on {}", listen_addr);
        schedule_interface_traffic_sampling();
    } catch (const ApiError& e) {
        Logger::instance().error("REST API startup failed on {}: {}", listen_addr, e.what());
        throw;
    } catch (const std::exception& e) {
        Logger::instance().error("Unexpected REST API startup failure on {}: {}",
                                 listen_addr,
                                 e.what());
        throw;
    }
        },
        [this]() noexcept {
            // Callers never observe a failed setup with a live listener,
            // handler context, conntrack fd, or fd callback record.
            retire_api_runtime_resources();
        });
}

void Daemon::retire_api_runtime_resources() noexcept {
    retire_api_runtime_in_dependency_order(
        [this]() noexcept { api_server_.reset(); },
        [this]() noexcept { api_ctx_.reset(); },
        [this]() noexcept { teardown_conntrack_events(); });
}

namespace {

// First look 15 s after startup: S80 usually observes our PID file and
// releases the lifecycle lease within seconds. Then back off; after the last
// entry the attempt is abandoned and the journal stays, exactly as visible
// as before this task existed - the web page keeps saying the operation did
// not finish.
constexpr std::array<std::chrono::seconds, 6> kNfqwsBootRecoveryDelays{
    std::chrono::seconds{15},  std::chrono::seconds{30},
    std::chrono::seconds{60},  std::chrono::seconds{120},
    std::chrono::seconds{300}, std::chrono::seconds{600},
};

} // namespace

void Daemon::schedule_nfqws_boot_recovery(std::size_t attempt) {
    if (!api_ctx_ || !scheduler_) return;
    if (attempt >= kNfqwsBootRecoveryDelays.size()) {
        Logger::instance().warn(
            "nfqws2 boot recovery could not run within {} attempts (the "
            "maintenance lease stayed busy, or the worker pool was "
            "saturated); an interrupted package transaction, if any, is "
            "left for the operator",
            attempt);
        return;
    }
    cancel_nfqws_boot_recovery();
    const auto schedule_serial = ++nfqws_boot_recovery_schedule_serial_;
    const auto delay = kNfqwsBootRecoveryDelays[attempt];
    try {
        nfqws_boot_recovery_task_id_ = scheduler_->schedule_oneshot(
            delay,
            [this, attempt, schedule_serial]() {
                if (schedule_serial != nfqws_boot_recovery_schedule_serial_) {
                    return;
                }
                nfqws_boot_recovery_task_id_ = -1;
                if (!running_.load(std::memory_order_acquire) || !api_ctx_) {
                    return;
                }
                // opkg may run for minutes: never on the control loop. The
                // worker hands the verdict back through a posted task, and
                // only a busy lease schedules another look.
                const bool posted = blocking_executor_.try_post(
                    "nfqws-boot-recovery",
                    [this, attempt, schedule_serial]() {
                        const auto result = run_nfqws_boot_recovery(*api_ctx_);
                        if (result.outcome ==
                            NfqwsBootRecoveryOutcome::lease_busy) {
                            (void)post_control_task(
                                [this, attempt, schedule_serial]() {
                                    if (schedule_serial !=
                                        nfqws_boot_recovery_schedule_serial_) {
                                        return;
                                    }
                                    schedule_nfqws_boot_recovery(attempt + 1);
                                },
                                "nfqws-boot-recovery-retry");
                            return;
                        }
                        if (result.outcome !=
                            NfqwsBootRecoveryOutcome::nothing_to_do) {
                            Logger::instance().info(
                                "nfqws2 boot recovery: plan={} outcome={} "
                                "journal_cleared={} ({})",
                                result.plan,
                                nfqws_boot_recovery_outcome_name(
                                    result.outcome),
                                result.journal_cleared,
                                result.reason);
                        }
                    });
                if (!posted) {
                    // The pool is saturated right after start; try again on
                    // the next delay rather than losing the look entirely,
                    // and say so - the give-up message must not blame the
                    // lease for attempts that never ran.
                    Logger::instance().info(
                        "nfqws2 boot recovery: worker pool busy, attempt {} "
                        "re-armed",
                        attempt);
                    schedule_nfqws_boot_recovery(attempt + 1);
                }
            },
            "nfqws-boot-recovery");
    } catch (const std::exception& error) {
        nfqws_boot_recovery_task_id_ = -1;
        Logger::instance().info(
            "nfqws2 boot recovery timer could not be installed: {}",
            error.what());
    }
}

void Daemon::cancel_nfqws_boot_recovery() noexcept {
    ++nfqws_boot_recovery_schedule_serial_;
    if (nfqws_boot_recovery_task_id_ < 0) return;
    const int task_id = nfqws_boot_recovery_task_id_;
    nfqws_boot_recovery_task_id_ = -1;
    if (!scheduler_) return;
    try {
        scheduler_->cancel(task_id);
    } catch (...) {
    }
}


namespace {

// The retention backfill starts after boot recovery has had its first two
// looks: both take the same maintenance lease, and losing the race only
// costs a retry, but there is no reason to spend one. The tail is longer
// than boot recovery's because nothing here is urgent - the bytes it keeps
// matter at the next upgrade, not at this boot - while giving up quietly is
// fine: the next daemon start looks again.
constexpr std::array<std::chrono::seconds, 5> kNfqwsRetentionDelays{
    std::chrono::seconds{90},  std::chrono::seconds{180},
    std::chrono::seconds{420}, std::chrono::seconds{900},
    std::chrono::seconds{1800},
};

} // namespace

void Daemon::schedule_nfqws_retention_backfill(std::size_t attempt) {
    if (!api_ctx_ || !scheduler_) return;
    if (attempt >= kNfqwsRetentionDelays.size()) {
        // Deliberately not naming the lease: the attempts that got here may
        // have been spent on a busy lease, a saturated worker pool or a
        // package manager that could not reach the feed, and a message that
        // picks one sends the operator looking in the wrong place.
        Logger::instance().info(
            "nfqws2 retention backfill did not complete within {} attempts; "
            "the next daemon start looks again",
            attempt);
        return;
    }
    cancel_nfqws_retention_backfill();
    const auto schedule_serial = ++nfqws_retention_backfill_schedule_serial_;
    const auto delay = kNfqwsRetentionDelays[attempt];
    try {
        nfqws_retention_backfill_task_id_ = scheduler_->schedule_oneshot(
            delay,
            [this, attempt, schedule_serial]() {
                if (schedule_serial !=
                    nfqws_retention_backfill_schedule_serial_) {
                    return;
                }
                nfqws_retention_backfill_task_id_ = -1;
                if (!running_.load(std::memory_order_acquire) || !api_ctx_) {
                    return;
                }
                // opkg refreshes feeds and may download megabytes: never on
                // the control loop.
                const bool posted = blocking_executor_.try_post(
                    "nfqws-retention-backfill",
                    [this, attempt, schedule_serial]() {
                        // The queue may have held this while the daemon
                        // began stopping, and cancel cannot reach a task a
                        // worker already claimed: shutdown would then wait
                        // out an opkg run nobody is waiting for.
                        if (!running_.load(std::memory_order_acquire) ||
                            schedule_serial !=
                                nfqws_retention_backfill_schedule_serial_) {
                            return;
                        }
                        const auto result =
                            run_nfqws_retention_backfill(*api_ctx_);
                        // Busy says nothing about the feed, and a failed
                        // attempt says nothing permanent either - a router
                        // that boots before its WAN is up fails the first
                        // look and must get a later one. Only a real answer
                        // (retained, unavailable, nothing_to_do) ends the
                        // chain.
                        if (result.outcome ==
                                NfqwsRetentionBackfillOutcome::lease_busy ||
                            result.outcome ==
                                NfqwsRetentionBackfillOutcome::failed) {
                            (void)post_control_task(
                                [this, attempt, schedule_serial]() {
                                    if (schedule_serial !=
                                        nfqws_retention_backfill_schedule_serial_) {
                                        return;
                                    }
                                    schedule_nfqws_retention_backfill(
                                        attempt + 1);
                                },
                                "nfqws-retention-backfill-retry");
                        }
                        if (result.outcome !=
                            NfqwsRetentionBackfillOutcome::nothing_to_do) {
                            Logger::instance().info(
                                "nfqws2 retention backfill: version={} "
                                "outcome={}",
                                result.version,
                                nfqws_retention_backfill_outcome_name(
                                    result.outcome));
                        }
                    });
                if (!posted) {
                    Logger::instance().info(
                        "nfqws2 retention backfill: worker pool busy, "
                        "attempt {} re-armed",
                        attempt);
                    schedule_nfqws_retention_backfill(attempt + 1);
                }
            },
            "nfqws-retention-backfill");
    } catch (const std::exception& error) {
        nfqws_retention_backfill_task_id_ = -1;
        Logger::instance().info(
            "nfqws2 retention backfill timer could not be installed: {}",
            error.what());
    }
}

void Daemon::cancel_nfqws_retention_backfill() noexcept {
    ++nfqws_retention_backfill_schedule_serial_;
    if (nfqws_retention_backfill_task_id_ < 0) return;
    const int task_id = nfqws_retention_backfill_task_id_;
    nfqws_retention_backfill_task_id_ = -1;
    if (!scheduler_) return;
    try {
        scheduler_->cancel(task_id);
    } catch (...) {
    }
}
} // namespace keen_pbr3

#endif
