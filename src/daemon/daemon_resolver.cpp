#include "daemon.hpp"
#include "runtime_firewall_operation_owner.hpp"

#include "../dns/dnsmasq_access_policy.hpp"
#include "../dns/keenetic_dns.hpp"
#include "../dns/dns_txt_client.hpp"
#include "../log/logger.hpp"
#ifdef WITH_API
#include "../api/status_stream.hpp"
#endif
#include "../util/ipv6_support.hpp"
#include "../util/time_utils.hpp"
#include "scheduler.hpp"

#include <fmt/ranges.h>

#include <type_traits>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr auto kResolverConfigHashActualRefreshInterval = std::chrono::seconds{60};

bool config_uses_keenetic_dns(const std::optional<DnsConfig>& dns_config) {
    return dns_config.has_value() &&
           dns_config_uses_keenetic_server(*dns_config);
}

bool log_keenetic_dns_refresh_result(
    const KeeneticDnsRefreshResult& result) {
    auto& log = Logger::instance();
    switch (result.status) {
    case KeeneticDnsRefreshStatus::UPDATED:
        if (!result.addresses.empty()) {
            log.info("Keenetic DNS refreshed: {}",
                     fmt::join(result.addresses, ", "));
        }
        return true;
    case KeeneticDnsRefreshStatus::UNCHANGED:
        return false;
    case KeeneticDnsRefreshStatus::FETCH_FAILED_USED_CACHE: {
        const std::string value_suffix =
            result.addresses.size() > 1 ? "s: "
            : (result.addresses.empty() ? "" : ": ");
        log.warn("Keenetic DNS refresh failed; reusing cached value{}{}",
                 value_suffix,
                 fmt::join(result.addresses, ", "));
        if (!result.error.empty()) {
            log.warn("Keenetic DNS refresh error: {}", result.error);
        }
        return false;
    }
    case KeeneticDnsRefreshStatus::FETCH_FAILED_NO_CACHE:
        if (!result.error.empty()) {
            log.warn("Keenetic DNS refresh failed with no cached value: {}",
                     result.error);
        }
        return false;
    }

    return false;
}

} // namespace

std::shared_ptr<const ListCacheGenerationSnapshot>
Daemon::capture_relevant_list_cache_generation(const Config& config) const {
    const auto relevant_lists = collect_relevant_list_names(config);
    return list_service_.cache_manager().capture_generation(
        std::vector<std::string>(
            relevant_lists.begin(), relevant_lists.end()));
}

ResolverGenerationSnapshot Daemon::make_resolver_generation_snapshot(
    std::shared_ptr<const ListCacheGenerationSnapshot>
        list_cache_snapshot,
    std::optional<std::vector<std::string>>
        trusted_dns_interfaces_override,
    const KeeneticDnsCacheView* keenetic_dns_override) {
    if (!list_cache_snapshot) {
        list_cache_snapshot =
            capture_relevant_list_cache_generation(config_);
    }
    const ResolverType resolver_type =
        firewall_->backend() == FirewallBackend::nftables
            ? ResolverType::DNSMASQ_NFTSET
            : ResolverType::DNSMASQ_IPSET;
    const Ipv6SupportDecision ipv6_decision =
        resolve_ipv6_support(config_);
    log_ipv6_support_decision_once(ipv6_decision);
    auto trusted_dns_interfaces =
        select_dnsmasq_trusted_interfaces(
            std::move(trusted_dns_interfaces_override),
            resolved_internal_vpn_servers_,
            resolved_internal_vpn_service_targets_);
    RuntimeResolverGenerationInput input;
    input.config = config_;
    input.keenetic_dns = keenetic_dns_override
        ? *keenetic_dns_override
        : active_keenetic_dns_;
    input.list_cache_snapshot = std::move(list_cache_snapshot);
    input.list_max_file_size_bytes = max_file_size_bytes(config_);
    input.resolver_type = resolver_type;
    input.ipv6_policy = resolver_ipv6_policy(ipv6_decision);
    input.trusted_dns_interfaces =
        std::move(trusted_dns_interfaces);
    input.generation =
        runtime_generation_.load(std::memory_order_acquire);
    return build_runtime_resolver_generation_snapshot(input);
}

void Daemon::update_resolver_config_hash() {
    commit_resolver_generation_snapshot(
        make_resolver_generation_snapshot());
}

void Daemon::commit_resolver_generation_snapshot(
    ResolverGenerationSnapshot prepared_snapshot) {
    auto snapshot = std::make_shared<ResolverGenerationSnapshot>(
        std::move(prepared_snapshot));
    const std::string resolver_config_hash = snapshot->expected_hash;
    resolver_generation_snapshot_ = std::move(snapshot);
    resolver_config_hash_actual_retry_attempt_ = 0;
    resolver_sync_.expected_hash_updated(resolver_config_hash);
    const std::int64_t apply_started_ts =
        apply_started_ts_.load(std::memory_order_acquire);
    if (apply_started_ts > 0) {
        resolver_sync_.apply_started(apply_started_ts, resolver_config_hash);
    }
    Logger::instance().info("Resolver config hash: {}", resolver_config_hash);
}

RuntimeStateSnapshot Daemon::build_runtime_state_snapshot() const {
    RuntimeStateSnapshot snapshot;
    snapshot.firewall_state = firewall_state_;
    const auto routing_inventory = routing_operation_owner_.snapshot();
    if (routing_inventory) {
        snapshot.route_specs = routing_inventory->routes;
        snapshot.policy_rule_specs = routing_inventory->rules;
        snapshot.routing_inventory_complete =
            routing_inventory->inventory_complete;
        snapshot.routing_kernel_state_known =
            routing_inventory->kernel_state_known;
    } else {
        snapshot.routing_inventory_complete = false;
        snapshot.routing_kernel_state_known = false;
    }
    const auto resolver_snapshot = resolver_sync_.snapshot(unix_timestamp_now_seconds());
    snapshot.resolver_config_hash = resolver_snapshot.expected_hash;
    snapshot.resolver_config_hash_actual = resolver_snapshot.actual_hash;
    snapshot.resolver_config_hash_actual_ts = resolver_snapshot.actual_ts;
    snapshot.resolver_config_sync_state = resolver_snapshot.sync_state;
    snapshot.resolver_config_probe_status = resolver_snapshot.probe_status;
    snapshot.resolver_live_status = resolver_snapshot.live_status;
    snapshot.resolver_last_probe_ts = resolver_snapshot.last_probe_ts;
    snapshot.apply_started_ts = resolver_snapshot.apply_started_ts;
    // routing_runtime_active is deliberately absent: the store owns it and
    // carries it across publishes, so this builder cannot answer for it and
    // cannot forget to.
    snapshot.runtime_state = runtime_state_machine_.state();
    snapshot.runtime_state_reason = runtime_state_machine_.reason();

    if (urltest_manager_) {
        for (const auto& outbound : config_.outbounds.value_or(std::vector<Outbound>{})) {
            if (outbound.type != OutboundType::URLTEST) {
                continue;
            }
            auto state = urltest_manager_->get_state(outbound.tag);
            if (state.has_value()) {
                snapshot.urltest_states.emplace(outbound.tag, std::move(*state));
            }
        }
    }

    return snapshot;
}

void Daemon::transition_runtime_or_throw(RuntimeState next, const char* reason) {
    const auto previous = runtime_state_machine_.state();
    if (previous == next) return;
    std::string error;
    if (!runtime_state_machine_.transition(next, reason, error)) {
        throw DaemonError(error);
    }
    // The one choke point every runtime ownership change passes through, and
    // the only place its reason reaches the log. Never throws: several
    // callers transition from catch blocks, and a transition that succeeded
    // must not be un-happened by a logging failure.
    try {
        if (classify_runtime_transition_log(previous, next) ==
            RuntimeTransitionLogSeverity::warn) {
            Logger::instance().warn("Runtime state {} -> {}: {}",
                                    runtime_state_name(previous),
                                    runtime_state_name(next), reason);
        } else {
            Logger::instance().info("Runtime state {} -> {}: {}",
                                    runtime_state_name(previous),
                                    runtime_state_name(next), reason);
        }
    } catch (...) {
    }
}

void Daemon::publish_runtime_state() {
    Logger::instance().trace(
        "runtime_state_publish",
        "routing_runtime_active={} runtime_state={} reason={}",
        routing_runtime_active() ? "true" : "false",
        runtime_state_name(runtime_state_machine_.state()),
        runtime_state_machine_.reason());
    runtime_state_store_.publish(build_runtime_state_snapshot());
#ifdef WITH_API
    if (status_stream_) {
        status_stream_->reconcile();
    }
#endif
}

void Daemon::schedule_resolver_config_hash_actual_refresh() {
    schedule_resolver_config_hash_actual_after(
        kResolverConfigHashActualRefreshInterval,
        "resolver-config-hash-actual");
}

void Daemon::schedule_resolver_config_hash_actual_after(
    std::chrono::seconds delay,
    const char* task_name) {
    if (resolver_config_hash_actual_task_id_ >= 0) {
        scheduler_->cancel(resolver_config_hash_actual_task_id_);
    }
    resolver_config_hash_actual_task_id_ = scheduler_->schedule_oneshot(
        delay,
        [this]() {
            resolver_config_hash_actual_task_id_ = -1;
            maybe_schedule_resolver_config_hash_actual_refresh();
        },
        task_name);
}

void Daemon::schedule_keenetic_dns_refresh() {
    if (keenetic_dns_refresh_admission_retry_task_id_ >= 0) {
        scheduler_->cancel(keenetic_dns_refresh_admission_retry_task_id_);
        keenetic_dns_refresh_admission_retry_task_id_ = -1;
    }
    if (keenetic_dns_refresh_task_id_ >= 0) {
        scheduler_->cancel(keenetic_dns_refresh_task_id_);
        keenetic_dns_refresh_task_id_ = -1;
    }

    if (!config_uses_keenetic_dns(config_.dns)) {
        return;
    }

    keenetic_dns_refresh_task_id_ = scheduler_->schedule_repeating(
        std::chrono::minutes{5},
        [this]() {
            post_control_task([this]() {
                if (!routing_runtime_active() ||
                    !config_uses_keenetic_dns(config_.dns)) {
                    return;
                }
                request_keenetic_dns_refresh();
            }, "keenetic-dns-refresh");
        },
        "keenetic-dns-refresh");
}

void Daemon::request_keenetic_dns_refresh() {
    if (!routing_runtime_active() ||
        !config_uses_keenetic_dns(config_.dns)) {
        return;
    }

    const auto generation =
        runtime_generation_.load(std::memory_order_acquire);
    auto admitted = runtime_mutation_admission_.try_acquire(
        "keenetic-dns-refresh");
    if (!admitted.has_value()) {
        schedule_deferred_keenetic_dns_refresh(generation);
        return;
    }

    RuntimeMutationLeaseHandoff mutation_lease{
        std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(*admitted))};
    const auto request = keenetic_dns_refresh_coordinator_.request(
        generation, mutation_lease);
    if (request == KeeneticDnsRefreshCoordinator::RequestResult::rejected) {
        Logger::instance().verbose(
            "Keenetic DNS refresh worker rejected generation {}.",
            generation);
        schedule_deferred_keenetic_dns_refresh(generation);
    }
}

void Daemon::schedule_deferred_keenetic_dns_refresh(
    std::uint64_t runtime_generation) {
    if (keenetic_dns_refresh_admission_retry_task_id_ >= 0) {
        return;
    }

    constexpr auto kAdmissionRetryDelay = std::chrono::seconds{1};
    const int task_id = scheduler_->schedule_oneshot(
        kAdmissionRetryDelay,
        [this, runtime_generation]() {
            keenetic_dns_refresh_admission_retry_task_id_ = -1;
            if (!runtime_recovery_is_current(
                    routing_runtime_active(),
                    runtime_generation,
                    runtime_generation_.load(std::memory_order_acquire)) ||
                !config_uses_keenetic_dns(config_.dns)) {
                return;
            }
            request_keenetic_dns_refresh();
        },
        "keenetic-dns-refresh-admission-retry");
    if (task_id < 0) {
        Logger::instance().error(
            "Keenetic DNS admission retry was rejected; no runtime cursor "
            "was changed.");
        return;
    }
    keenetic_dns_refresh_admission_retry_task_id_ = task_id;
    const auto active = runtime_mutation_admission_.active();
    Logger::instance().verbose(
        "Keenetic DNS refresh deferred behind runtime mutation '{}'.",
        active.has_value() ? active->label : std::string{"unknown"});
}

bool Daemon::commit_keenetic_dns_refresh_result(
    std::uint64_t generation,
    const KeeneticDnsRefreshResult& result,
    const RuntimeMutationLeaseHandoff& mutation_lease) {
    if (generation != runtime_generation_.load(std::memory_order_acquire) ||
        !routing_runtime_active() ||
        !config_uses_keenetic_dns(config_.dns)) {
        return false;
    }

    (void)log_keenetic_dns_refresh_result(result);
    if (!result.snapshot.has_value()) {
        return true;
    }

    const bool runtime_snapshot_changed =
        !active_keenetic_dns_.snapshot.has_value() ||
        !keenetic_dns_snapshots_equal(
            *active_keenetic_dns_.snapshot,
            *result.snapshot);
    const KeeneticDnsCacheView refreshed_view{
        result.snapshot,
        result.status == KeeneticDnsRefreshStatus::FETCH_FAILED_USED_CACHE
            ? KeeneticDnsCacheStatus::stale
            : KeeneticDnsCacheStatus::fresh,
        result.status == KeeneticDnsRefreshStatus::UPDATED ||
            result.status == KeeneticDnsRefreshStatus::UNCHANGED,
        result.status == KeeneticDnsRefreshStatus::UPDATED,
        result.generation,
        result.error,
    };
    if (!runtime_snapshot_changed) {
        // Even when bytes did not change, retain the true refresh outcome for
        // diagnostics. A failed refresh that reused the LKG must not continue
        // to advertise a fresh runtime view.
        active_keenetic_dns_ = refreshed_view;
        return true;
    }

    if (resolver_stream_coordinator_.in_flight()) {
        // A recovery hook is still streaming its pinned resolver generation.
        // Do not start a second synchronous stream after mutating firewall:
        // that would fail the IPC gate and force a pointless double rollback.
        // Keep only one pending observation. Re-requesting the DNS
        // coordinator from its own commit callback would create an immediate
        // fetch/commit loop for the full lifetime of the resolver stream.
        keenetic_dns_refresh_deferred_by_resolver_stream_ = true;
        Logger::instance().verbose(
            "Deferring changed Keenetic DNS state until the active resolver "
            "recovery stream completes");
        return false;
    }

    // From this point the control callback may only prepare immutable
    // candidate state and transfer its exact writer. Firewall, route and
    // resolver mutations are owned asynchronously by the typed lifecycle.
    auto taken = mutation_lease.take();
    if (!taken ||
        !runtime_mutation_admission_.owns(*taken.lease)) {
        Logger::instance().error(
            "Keenetic DNS refresh lost its exact mutation lease before "
            "firewall owner handoff");
        return false;
    }

    const auto list_cache_snapshot =
        capture_relevant_list_cache_generation(config_);
    auto lease = std::move(taken.lease);
    if (!begin_preowned_runtime_firewall_keenetic_dns_refresh(
            generation,
            refreshed_view,
            list_cache_snapshot,
            lease)) {
        // Rejection leaves the exact token in `lease`; its destruction
        // releases admission before the coordinator can launch a trailing
        // observation. No kernel or resolver body was submitted.
        Logger::instance().verbose(
            "Keenetic DNS firewall owner rejected the private candidate");
        lease.reset();
        schedule_netfilter_runtime_refresh_noexcept(
            NetfilterRefreshReason::full,
            "Keenetic DNS owner handoff rejected after maintenance fence");
        return false;
    }
    return true;
}

void Daemon::reset_resolver_actual_state() {
    resolver_sync_.resolver_not_configured();
}

void Daemon::commit_resolver_hash_probe_result(
    const std::string& resolver_addr,
    std::uint64_t generation,
    std::optional<ResolverConfigHashProbeResult> probe_result,
    std::optional<std::int64_t> probe_completed_ts,
    TraceId trace_id,
    std::shared_ptr<PeriodicTaskRunToken> task_metrics) {
    const bool posted = post_control_task(
        [this,
         resolver_addr,
         generation,
         probe_result = std::move(probe_result),
         probe_completed_ts,
         trace_id,
         task_metrics]() mutable {
            ScopedTraceContext trace_scope_inner(trace_id);
            resolver_hash_refresh_inflight_.store(false, std::memory_order_release);

            if (generation != runtime_generation_.load(std::memory_order_acquire)) {
                if (task_metrics) {
                    task_metrics->skipped("stale runtime generation");
                }
                Logger::instance().trace("resolver_hash_refresh_skip",
                                         "resolver={} generation={} reason=stale_runtime",
                                         resolver_addr,
                                         generation);
                schedule_resolver_config_hash_actual_after(
                    std::chrono::seconds{1},
                    "resolver-config-hash-stale-generation-retry");
                return;
            }

            const std::int64_t now_ts = unix_timestamp_now_seconds();
            const auto previous_snapshot =
                resolver_sync_.snapshot(now_ts);
            if (probe_result.has_value() &&
                probe_result->status == ResolverConfigHashProbeStatus::SUCCESS) {
                resolver_sync_.probe_succeeded(probe_result->parsed_value.hash,
                                               probe_result->parsed_value.ts,
                                               probe_completed_ts);
                if (previous_snapshot.actual_hash !=
                    probe_result->parsed_value.hash) {
                    Logger::instance().verbose(
                        "Resolver config hash (actual): {}",
                        probe_result->parsed_value.hash);
                }
            } else if (probe_result.has_value()) {
                resolver_sync_.probe_failed(probe_result->status, probe_completed_ts);
                // The probe already retried; a first failure after that is
                // still ordinary UDP life and does not belong in front of the
                // user. Only a run of them says the resolver is really out.
                const bool persistent =
                    resolver_sync_.consecutive_probe_failures() >=
                    ResolverSyncStateMachine::kFailuresBeforeClearing;
                switch (probe_result->status) {
                case ResolverConfigHashProbeStatus::QUERY_FAILED:
                    if (persistent) {
                        Logger::instance().warn(
                            "Resolver does not answer the config hash query via {} ({} attempts): {}",
                            resolver_addr,
                            resolver_sync_.consecutive_probe_failures(),
                            probe_result->error);
                    } else {
                        Logger::instance().verbose(
                            "Resolver config hash query did not answer via {}: {}; will retry",
                            resolver_addr,
                            probe_result->error);
                    }
                    break;
                case ResolverConfigHashProbeStatus::NO_USABLE_TXT:
                    if (persistent) {
                        Logger::instance().warn(
                            "Resolver config hash TXT is missing via {} ({} attempts); clearing actual value",
                            resolver_addr,
                            resolver_sync_.consecutive_probe_failures());
                    } else {
                        Logger::instance().verbose(
                            "Resolver config hash TXT is not there yet via {}; will retry",
                            resolver_addr);
                    }
                    break;
                case ResolverConfigHashProbeStatus::INVALID_TXT:
                    Logger::instance().warn(
                        "Resolver config hash TXT is invalid via {}: {}; clearing actual value",
                        resolver_addr,
                        probe_result->raw_txt.value_or("<empty>"));
                    break;
                case ResolverConfigHashProbeStatus::SUCCESS:
                    break;
                }
            }
            const auto resolver_snapshot = resolver_sync_.snapshot(now_ts);
            const ResolverProbeCommitPlan commit_plan =
                plan_resolver_probe_commit(
                    previous_snapshot,
                    resolver_snapshot,
                    resolver_config_hash_actual_retry_attempt_);
            if (commit_plan.report_stale_txt_observation) {
                Logger::instance().verbose(
                    "Resolver config hash TXT is older than current apply; using live actual value "
                    "(resolver={}, txt_ts={}, apply_started_ts={})",
                    resolver_addr,
                    *resolver_snapshot.actual_ts,
                    *resolver_snapshot.apply_started_ts);
            }
            resolver_config_hash_actual_retry_attempt_ =
                commit_plan.next_retry_attempt;
            if (commit_plan.schedule_convergence_retry) {
                schedule_resolver_config_hash_actual_after(
                    commit_plan.convergence_retry_delay,
                    "resolver-config-hash-actual-retry");
            } else {
                schedule_resolver_config_hash_actual_refresh();
            }
            if (commit_plan.publish_runtime_state) {
                publish_runtime_state();
            }
            if (task_metrics) {
                if (probe_result.has_value() &&
                    probe_result->status ==
                        ResolverConfigHashProbeStatus::SUCCESS) {
                    if (commit_plan.publish_runtime_state) {
                        task_metrics->success();
                    } else {
                        task_metrics->noop();
                    }
                } else {
                    const std::string error =
                        probe_result.has_value() && !probe_result->error.empty()
                            ? probe_result->error
                            : "resolver hash probe did not succeed";
                    task_metrics->failure(error);
                }
            }
        },
        "resolver-hash-refresh-commit");
    if (!posted && task_metrics) {
        resolver_hash_refresh_inflight_.store(false, std::memory_order_release);
        task_metrics->skipped("control loop is not accepting commits");
    }
}

void Daemon::refresh_resolver_config_hash_actual_async() {
    const auto dns_cfg_opt = config_.dns;
    if (!routing_runtime_active() ||
        !dns_cfg_opt.has_value() ||
        !dns_cfg_opt->system_resolver.has_value()) {
        periodic_task_metrics_.record_skipped(
            "resolver-hash-refresh",
            !routing_runtime_active()
                ? "routing runtime is inactive"
                : "system resolver is not configured");
        if (!routing_runtime_active()) {
            resolver_sync_.runtime_stopped();
        } else {
            reset_resolver_actual_state();
        }
        publish_runtime_state();
        return;
    }

    const std::string resolver_addr = dns_cfg_opt->system_resolver->address;
    if (resolver_addr.empty()) {
        periodic_task_metrics_.record_skipped(
            "resolver-hash-refresh", "resolver address is empty");
        reset_resolver_actual_state();
        publish_runtime_state();
        return;
    }

    bool expected = false;
    if (!resolver_hash_refresh_inflight_.compare_exchange_strong(expected,
                                                                 true,
                                                                 std::memory_order_acq_rel)) {
        periodic_task_metrics_.record_skipped(
            "resolver-hash-refresh", "probe is already in flight");
        Logger::instance().trace("resolver_hash_refresh_skip", "reason=inflight");
        schedule_resolver_config_hash_actual_after(
            std::chrono::seconds{1},
            "resolver-config-hash-inflight-retry");
        return;
    }

    const auto generation = runtime_generation_.load(std::memory_order_acquire);
    const TraceId trace_id = ensure_trace_id();
    auto task_metrics = std::make_shared<PeriodicTaskRunToken>(
        periodic_task_metrics_.begin("resolver-hash-refresh"));
    const bool enqueued = resolver_io_executor_.try_post(
        "resolver-config-hash-actual",
        [this,
         resolver_addr,
         generation,
         trace_id,
         task_metrics]() mutable {
            ScopedTraceContext trace_scope(trace_id);
            std::optional<ResolverConfigHashProbeResult> probe_result;
            std::optional<std::int64_t> probe_completed_ts;

            Logger::instance().trace("resolver_hash_refresh_start",
                                     "resolver={} generation={}",
                                     resolver_addr,
                                     generation);
            try {
                probe_result = query_resolver_config_hash_txt(
                    resolver_addr,
                    "config-hash.keen.pbr",
                    std::chrono::milliseconds(2000));
                if (probe_result->status ==
                    ResolverConfigHashProbeStatus::SUCCESS) {
                    std::string resolver_state_error;
                    const auto resolver_state_txt = query_dns_txt_record(
                        resolver_addr,
                        "resolver-state.keen.pbr",
                        std::chrono::milliseconds(500),
                        &resolver_state_error);
                    if (resolver_state_txt.has_value()) {
                        const auto resolver_state =
                            parse_resolver_state_txt(*resolver_state_txt);
                        if (resolver_state.mode ==
                            ResolverRuntimeMode::FALLBACK) {
                            probe_result->status =
                                ResolverConfigHashProbeStatus::INVALID_TXT;
                            probe_result->raw_txt = *resolver_state_txt;
                            probe_result->error =
                                "Resolver is serving fallback configuration";
                            Logger::instance().warn(
                                "Resolver is serving fallback configuration via {}: {}",
                                resolver_addr,
                                resolver_state.reason.empty()
                                    ? "unknown reason"
                                    : resolver_state.reason);
                        }
                    }
                }
                probe_completed_ts = unix_timestamp_now_seconds();
            } catch (const std::exception& e) {
                ResolverConfigHashProbeResult failed_result;
                failed_result.status = ResolverConfigHashProbeStatus::QUERY_FAILED;
                failed_result.error = e.what();
                probe_result = std::move(failed_result);
                probe_completed_ts = unix_timestamp_now_seconds();
            }

            commit_resolver_hash_probe_result(resolver_addr,
                                              generation,
                                              std::move(probe_result),
                                              probe_completed_ts,
                                              trace_id,
                                              task_metrics);
        },
        trace_id);

    if (!enqueued) {
        resolver_hash_refresh_inflight_.store(false, std::memory_order_release);
        task_metrics->skipped("resolver executor is unavailable");
        Logger::instance().trace("resolver_hash_refresh_skip",
                                 "reason=executor_unavailable");
        schedule_resolver_config_hash_actual_after(
            std::chrono::seconds{1},
            "resolver-config-hash-executor-retry");
    }
}

void Daemon::maybe_schedule_resolver_config_hash_actual_refresh() {
    if (resolver_hash_refresh_inflight_.load(std::memory_order_acquire)) {
        Logger::instance().trace("resolver_hash_refresh_skip", "reason=inflight");
        schedule_resolver_config_hash_actual_after(
            std::chrono::seconds{1},
            "resolver-config-hash-inflight-retry");
        return;
    }
    refresh_resolver_config_hash_actual_async();
}

} // namespace keen_pbr3
