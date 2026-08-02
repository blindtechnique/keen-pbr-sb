#include "daemon.hpp"

#ifdef WITH_API

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <sys/epoll.h>
#include <thread>

#include "../api/handlers.hpp"
#include "../api/handler_connections.hpp"
#include "../api/handler_health_service.hpp"
#include "../api/server.hpp"
#include "../api/status_stream.hpp"
#include "../connections/conntrack_event_monitor.hpp"
#include "../config/routing_state.hpp"
#include "../dns/dns_router.hpp"
#include "../dns/dnsmasq_gen.hpp"
#include "../util/ipv6_support.hpp"
#include "../health/routing_health_checker.hpp"
#include "../health/runtime_interface_inventory.hpp"
#include "../health/runtime_outbound_state.hpp"
#include "../api/handler_runtime_inventory.hpp"
#include "../api/handler_diagnostic_tasks.hpp"
#include "../lists/list_streamer.hpp"
#include "../log/logger.hpp"
#include "../util/system_info.hpp"
#include "../util/time_utils.hpp"
#include "scheduler.hpp"

#ifndef KEEN_PBR_FRONTEND_ROOT
#define KEEN_PBR_FRONTEND_ROOT "/usr/share/keen-pbr/frontend"
#endif

namespace keen_pbr3 {

namespace {

constexpr auto conntrack_publish_delay = std::chrono::milliseconds{500};
constexpr auto interface_traffic_sample_interval = std::chrono::seconds{2};

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

const char* config_operation_state_name(ConfigOperationState state) {
    switch (state) {
    case ConfigOperationState::Idle:
        return "idle";
    case ConfigOperationState::Saving:
        return "saving";
    case ConfigOperationState::Reloading:
        return "reloading";
    }
    return "unknown";
}

} // namespace

void Daemon::sample_interface_traffic_now() {
    if (!status_stream_ || !status_stream_->has_subscribers()) {
        const bool sampling_stopped =
            traffic_sampling_active_ ||
            !traffic_sampled_interfaces_.empty();
        if (sampling_stopped) {
            interface_traffic_sampler_.clear_all();
            traffic_sampled_interfaces_.clear();
            traffic_sampling_active_ = false;
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
            task_metrics.noop();
            return;
        }

        const auto target_plan = plan_interface_traffic_targets(
            target_interfaces, traffic_sampled_interfaces_);
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
    conntrack_event_monitor_ = std::make_unique<ConntrackEventMonitor>();

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

void Daemon::teardown_conntrack_events() {
    if (conntrack_publish_task_id_ >= 0) {
        scheduler_->cancel(conntrack_publish_task_id_);
        conntrack_publish_task_id_ = -1;
    }
    if (!conntrack_event_monitor_) return;
    remove_fd(
        conntrack_event_monitor_->fd(),
        true,
        "conntrack-events");
    conntrack_event_monitor_.reset();
}

void Daemon::finish_config_operation() {
    KPBR_LOCK_GUARD(config_op_mutex_);
    config_op_state_.store(ConfigOperationState::Idle, std::memory_order_release);
    Logger::instance().trace("config_operation_state",
                             "state={} reason=finish",
                             config_operation_state_name(ConfigOperationState::Idle));
    config_op_cv_.notify_all();
}

void Daemon::begin_config_operation_or_throw(ConfigOperationState state,
                                             const char* reason,
                                             bool require_runtime_running,
                                             bool require_runtime_stopped) {
    KPBR_UNIQUE_LOCK(lock, config_op_mutex_);
    if (config_op_state_.load(std::memory_order_acquire) != ConfigOperationState::Idle) {
        throw ApiError("Another config operation is already in progress", 409);
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

    config_op_state_.store(state, std::memory_order_release);
    Logger::instance().trace("config_operation_state",
                             "state={} reason={}",
                             config_operation_state_name(state),
                             reason);
}

void Daemon::run_runtime_control_operation_or_throw(const std::string& label,
                                                    const char* operation_name,
                                                    std::function<void()> task) {
    try {
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
    } catch (...) {
        finish_config_operation();
        throw;
    }

    finish_config_operation();
}

ConfigApplyResult Daemon::apply_validated_config_via_control_task(
    Config config,
    std::string saved_config_json) {
    auto result = std::make_shared<ConfigApplyResult>();
    auto prepared = std::make_shared<PreparedRuntimeInputs>();
    auto rollback_prepared = std::make_shared<PreparedRuntimeInputs>();

    const Config active_config = config_store_.active_config();
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

    const std::int64_t apply_started_ts = unix_timestamp_now_seconds();
    result->apply_started_ts = apply_started_ts;
    apply_started_ts_.store(apply_started_ts, std::memory_order_release);

    enqueue_control_task(
        [this,
         result,
         prepared,
         rollback_prepared,
         refresh_remote_lists_after_apply,
         saved_config_json = std::move(saved_config_json)]() mutable {
            try {
                apply_prepared_runtime_inputs(std::move(*prepared));
                result->applied = true;
                result->rolled_back = false;
                result->runtime_unchanged = false;
                config_store_.clear_staged_if_matches(saved_config_json);
                if (refresh_remote_lists_after_apply) {
                    refresh_lists_and_maybe_reload_async("post-apply");
                }
            } catch (const std::exception& e) {
                result->error = e.what();
                Logger::instance().error("Apply staged config task failed: {}", e.what());

                try {
                    apply_prepared_runtime_inputs(std::move(*rollback_prepared));
                    result->rolled_back = true;
                } catch (const std::exception& rollback_error) {
                    result->rolled_back = false;
                    Logger::instance().error("Rollback to previous config failed: {}",
                                             rollback_error.what());
                } catch (...) {
                    result->rolled_back = false;
                    Logger::instance().error("Rollback to previous config failed: unknown error");
                }
            }
        },
        true,
        "api-apply-config");
    return *result;
}

ListRefreshOperationResult Daemon::refresh_lists_via_api(std::optional<std::string> requested_name) {
    begin_config_operation_or_throw(ConfigOperationState::Reloading,
                                    "refresh-lists",
                                    false,
                                    false);
    if (config_store_.config_is_draft()) {
        finish_config_operation();
        throw ApiError("List refresh is unavailable while a draft config is staged", 409);
    }

    const Config config_snapshot = config_store_.active_config();
    const auto marks_snapshot = allocate_outbound_marks(
        config_snapshot.fwmark.value_or(FwmarkConfig{}),
        config_snapshot.outbounds.value_or(std::vector<Outbound>{}));
    const bool runtime_active_snapshot = runtime_state_store_.snapshot().routing_runtime_active;
    const auto target_selection = select_remote_list_targets(config_snapshot, requested_name);
    if (!target_selection.ok()) {
        finish_config_operation();
        switch (target_selection.error) {
        case RemoteListTargetSelectionError::NotFound:
            throw ApiError("Requested list was not found", 404);
        case RemoteListTargetSelectionError::NotRemote:
            throw ApiError("Requested list is not URL-backed", 400);
        case RemoteListTargetSelectionError::None:
            break;
        }
    }

    try {
        const std::set<std::string> relevant_lists = collect_relevant_list_names(config_snapshot);
        const std::set<std::string> dns_relevant_lists = collect_dns_relevant_list_names(config_snapshot);
        const std::set<std::string> target_lists(target_selection.list_names.begin(),
                                                 target_selection.list_names.end());
        RemoteListRefreshControl control;
        control.cache_commit = make_guarded_cache_commit_callback();
        const RemoteListsRefreshResult refresh_result =
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

        bool reloaded = false;
        bool stale_runtime = false;
        const auto generation = runtime_generation_.load(std::memory_order_acquire);

        enqueue_control_task(
            [this,
             &reloaded,
             &stale_runtime,
             config_snapshot,
             generation,
             runtime_active_snapshot,
             refresh_result]() mutable {
                if (generation != runtime_generation_.load(std::memory_order_acquire)) {
                    stale_runtime = true;
                    Logger::instance().trace("lists_refresh_skip",
                                             "source=api reason=stale_runtime generation={}",
                                             generation);
                    return;
                }

                if (should_reload_runtime_after_list_refresh(runtime_active_snapshot,
                                                            refresh_result)) {
                    bool rolled_back = false;
                    apply_config_with_rollback(
                        config_snapshot, rolled_back, false);
                    reloaded = true;
                }
            },
            true,
            "api-refresh-lists-commit");

        ListRefreshOperationResult operation_result;
        operation_result.refreshed_lists = std::move(refresh_result.refreshed_lists);
        operation_result.changed_lists = std::move(refresh_result.changed_lists);
        operation_result.failed_lists = std::move(refresh_result.failed_lists);
        operation_result.reloaded = reloaded;

        finish_config_operation();

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
        } else if (refresh_result.any_relevant_changed()) {
            operation_result.message =
                "Lists refreshed; runtime is stopped so changes will apply on next start";
        } else {
            operation_result.message = "Lists refreshed";
        }

        return operation_result;
    } catch (...) {
        finish_config_operation();
        throw;
    }
}

void Daemon::setup_api() {
    if (!config_.api || !config_.api->enabled.value_or(false) || opts_.no_api) return;

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
            DnsServerRegistry dns_registry(dns_cfg);
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
                return build_routing_health_report(
                    firewall_->backend(),
                    firewall_->uses_raw_prerouting(),
                    runtime_snapshot.firewall_state,
                    runtime_snapshot.route_specs,
                    runtime_snapshot.policy_rule_specs,
                    netlink_);
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
            const Config config_snapshot = config_store_.active_config();
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
                [this](const std::string& tag) -> std::optional<InterfaceProbeResult> {
                    return interface_probe_.result_for(tag);
                });
        },
        [this]() {
            return build_runtime_interface_inventory_response_or_empty(
                netlink_, &interface_traffic_sampler_);
        },
        [this](const Config& config) {
            return build_list_refresh_state_map(config, list_service_.cache_manager());
        },
        [this](const std::string& target) {
            const Config visible_config = config_store_.visible_config();
            return compute_test_routing(visible_config, list_service_.cache_manager(), target);
        },
        [this]() {
            begin_config_operation_or_throw(ConfigOperationState::Saving,
                                            "begin-save",
                                            false,
                                            false);
        },
        [this]() {
            finish_config_operation();
        },
        [this](Config config, std::string saved_config_json) -> ConfigApplyResult {
            return apply_validated_config_via_control_task(std::move(config),
                                                           std::move(saved_config_json));
        },
        [this]() {
            begin_config_operation_or_throw(ConfigOperationState::Reloading,
                                            "start-runtime",
                                            false,
                                            true);
            run_runtime_control_operation_or_throw("api-start-runtime",
                                                   "Start routing runtime",
                                                   [this]() { start_routing_runtime(); });
        },
        [this]() {
            begin_config_operation_or_throw(ConfigOperationState::Reloading,
                                            "stop-runtime",
                                            true,
                                            false);
            run_runtime_control_operation_or_throw("api-stop-runtime",
                                                   "Stop routing runtime",
                                                   [this]() { stop_routing_runtime(); });
        },
        [this]() {
            begin_config_operation_or_throw(ConfigOperationState::Reloading,
                                            "restart-runtime",
                                            true,
                                            false);
            run_runtime_control_operation_or_throw("api-restart-runtime",
                                                   "Restart routing runtime",
                                                   [this]() { restart_routing_runtime(); });
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
    status_stream_ = std::make_unique<StatusStream>([this]() {
        return build_runtime_inventory(*api_ctx_);
    });
    api_ctx_->status_stream = status_stream_.get();
    api_ctx_->emergency_quiesce_runtime_fn =
        [this]() {
            // The config-save handler already owns ConfigOperationState::Saving.
            // Do not call the public stop callback here: it would try to acquire
            // Reloading and reject the fail-closed stop as self-conflicting.
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
        const Config config_snapshot = config_store_.active_config();
        const auto now = std::chrono::steady_clock::now();

        nlohmann::json response;
        response["interval_seconds"] = 20;
        nlohmann::json probes = nlohmann::json::object();

        for (const auto& outbound :
             config_snapshot.outbounds.value_or(std::vector<Outbound>{})) {
            if (outbound.type != OutboundType::INTERFACE) {
                continue;
            }
            const auto result = interface_probe_.result_for(outbound.tag);
            if (!result.has_value()) {
                continue;
            }
            nlohmann::json entry;
            entry["success"] = result->success;
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
    api_server_->post("/api/system/probes/run", [this]() -> std::string {
        bool expected = false;
        const bool scheduled = manual_probe_inflight_.compare_exchange_strong(expected, true);
        if (scheduled) {
            post_control_task([this]() {
                try {
                    probe_interfaces_now();
                } catch (...) {
                    manual_probe_inflight_.store(false);
                    throw;
                }
                manual_probe_inflight_.store(false);
            });
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
}

} // namespace keen_pbr3

#endif
