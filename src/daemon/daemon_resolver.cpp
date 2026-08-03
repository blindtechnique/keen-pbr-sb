#include "daemon.hpp"

#include "../dns/dns_router.hpp"
#include "../dns/dnsmasq_access_policy.hpp"
#include "../dns/keenetic_dns.hpp"
#include "../dns/dns_txt_client.hpp"
#include "../dns/dnsmasq_gen.hpp"
#include "../lists/list_streamer.hpp"
#include "../log/logger.hpp"
#ifdef WITH_API
#include "../api/status_stream.hpp"
#endif
#include "../util/ipv6_support.hpp"
#include "../util/time_utils.hpp"
#include "scheduler.hpp"

#include <fmt/ranges.h>

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

ResolverGenerationSnapshot Daemon::make_resolver_generation_snapshot() {
    ResolverGenerationSnapshot snapshot;
    snapshot.config = config_;
    snapshot.keenetic_dns = active_keenetic_dns_;
    snapshot.resolver_type =
        firewall_->backend() == FirewallBackend::nftables
            ? ResolverType::DNSMASQ_NFTSET
            : ResolverType::DNSMASQ_IPSET;
    const DnsConfig dns_cfg = snapshot.config.dns.value_or(DnsConfig{});
    const Ipv6SupportDecision ipv6_decision =
        resolve_ipv6_support(snapshot.config);
    log_ipv6_support_decision_once(ipv6_decision);
    snapshot.ipv6_policy = resolver_ipv6_policy(ipv6_decision);
    snapshot.trusted_dns_interfaces =
        build_dnsmasq_trusted_interfaces(
            resolved_internal_vpn_servers_,
            resolved_internal_vpn_service_targets_);
    snapshot.generation =
        runtime_generation_.load(std::memory_order_acquire);
    ListStreamer streamer(list_service_.cache_manager());
    DnsServerRegistry dns_registry(
        dns_cfg, snapshot.keenetic_dns.snapshot);
    // DnsmasqGenerator retains references while computing the hash. Keep
    // optional defaults alive for the complete call.
    const RouteConfig route_cfg =
        snapshot.config.route.value_or(RouteConfig{});
    const std::map<std::string, ListConfig> lists =
        snapshot.config.lists.value_or(
            std::map<std::string, ListConfig>{});
    DnsmasqGenerator generator(
        dns_registry,
        streamer,
        route_cfg,
        dns_cfg,
        lists,
        snapshot.resolver_type,
        KEEN_PBR3_VERSION_FULL_STRING,
        snapshot.ipv6_policy,
        snapshot.trusted_dns_interfaces);
    snapshot.expected_hash = generator.compute_config_hash();
    return snapshot;
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
    snapshot.route_specs = route_table_.get_routes();
    snapshot.policy_rule_specs = policy_rules_.get_rules();
    const auto resolver_snapshot = resolver_sync_.snapshot(unix_timestamp_now_seconds());
    snapshot.resolver_config_hash = resolver_snapshot.expected_hash;
    snapshot.resolver_config_hash_actual = resolver_snapshot.actual_hash;
    snapshot.resolver_config_hash_actual_ts = resolver_snapshot.actual_ts;
    snapshot.resolver_config_sync_state = resolver_snapshot.sync_state;
    snapshot.resolver_config_probe_status = resolver_snapshot.probe_status;
    snapshot.resolver_live_status = resolver_snapshot.live_status;
    snapshot.resolver_last_probe_ts = resolver_snapshot.last_probe_ts;
    snapshot.apply_started_ts = resolver_snapshot.apply_started_ts;
    snapshot.routing_runtime_active = routing_runtime_active_;
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
    if (runtime_state_machine_.state() == next) return;
    std::string error;
    if (!runtime_state_machine_.transition(next, reason, error)) {
        throw DaemonError(error);
    }
}

void Daemon::publish_runtime_state() {
    Logger::instance().trace(
        "runtime_state_publish",
        "routing_runtime_active={} runtime_state={} reason={}",
        routing_runtime_active_ ? "true" : "false",
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
                if (!routing_runtime_active_ ||
                    !config_uses_keenetic_dns(config_.dns)) {
                    return;
                }
                (void)keenetic_dns_refresh_coordinator_.request(
                    runtime_generation_.load(std::memory_order_acquire));
            }, "keenetic-dns-refresh");
        },
        "keenetic-dns-refresh");
}

bool Daemon::commit_keenetic_dns_refresh_result(
    std::uint64_t generation,
    const KeeneticDnsRefreshResult& result) {
    if (generation != runtime_generation_.load(std::memory_order_acquire) ||
        !routing_runtime_active_ ||
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

    // Pin the complete remote-list generation across firewall consumption,
    // resolver hashing/streaming and any rollback. Cache publications take
    // the exclusive side, so neither consumer can observe a split generation.
    KPBR_SHARED_LOCK(cache_snapshot, resolver_cache_snapshot_mutex_);

    const KeeneticDnsCacheView previous = active_keenetic_dns_;
    const auto previous_resolver_generation =
        resolver_generation_snapshot_;
    const ResolverSyncCheckpoint previous_resolver_sync =
        resolver_sync_.checkpoint();
    const std::uint32_t previous_resolver_retry_attempt =
        resolver_config_hash_actual_retry_attempt_;
    const std::int64_t previous_apply_started_ts =
        apply_started_ts_.load(std::memory_order_acquire);
    const bool firewall_snapshot_changed =
        !previous.snapshot.has_value() ||
        previous.snapshot->addresses != result.snapshot->addresses;
    const std::string previous_resolver_hash =
        resolver_sync_.snapshot(unix_timestamp_now_seconds()).expected_hash;
    active_keenetic_dns_ = refreshed_view;

    bool resolver_hash_changed = false;
    try {
        // Keenetic DNS addresses participate in OUTPUT/PREROUTING detour
        // marks, so resolver-only reload would publish a split generation.
        // Reuse the existing atomic firewall transaction, then stream the
        // resolver from the same committed immutable snapshot.
        if (firewall_snapshot_changed) {
            retry_hot_apply_firewall(
                [this]() {
                    apply_firewall(FirewallApplyMode::PreserveSets);
                },
                [](std::chrono::milliseconds delay) {
                    std::this_thread::sleep_for(delay);
                },
                [](std::size_t retry,
                   std::chrono::milliseconds delay,
                   const TransientFirewallError& error) {
                    Logger::instance().info(
                        "Keenetic DNS firewall refresh deferred after a "
                        "concurrent firmware change: {}. Retry {} in {}ms.",
                        error.what(), retry, delay.count());
                });
        }
        auto resolver_generation =
            make_resolver_generation_snapshot();
        resolver_hash_changed =
            resolver_generation.expected_hash != previous_resolver_hash;
        if (resolver_hash_changed) {
            apply_started_ts_.store(
                unix_timestamp_now_seconds(), std::memory_order_release);
        }
        commit_resolver_generation_snapshot(
            std::move(resolver_generation));
        if (resolver_hash_changed) {
            if (!run_system_resolver_hook_stream_locked(
                    "reload", /*rebuild_snapshot=*/false)) {
                throw DaemonError(
                    "Keenetic DNS resolver reload did not complete its configuration stream");
            }
            refresh_resolver_config_hash_actual_async();
        }
        publish_runtime_state();
        return true;
    } catch (...) {
        // A refresh is observational until both firewall and resolver agree.
        // Restore the previously committed view; the coordinator will record
        // the failed commit and the next bounded refresh may retry it.
        active_keenetic_dns_ = previous;
        resolver_sync_.restore(previous_resolver_sync);
        resolver_config_hash_actual_retry_attempt_ =
            previous_resolver_retry_attempt;
        apply_started_ts_.store(
            previous_apply_started_ts, std::memory_order_release);
        bool firewall_recovery_pending = false;
        bool resolver_recovery_pending = false;
        try {
            // A list refresh may have published a new immutable cache body
            // immediately before this shared boundary was acquired. Rebuild
            // the previous DNS view over that pinned list generation instead
            // of claiming an exact historical rollback that the snapshot does
            // not materialize.
            retry_hot_apply_firewall(
                [this]() {
                    apply_firewall(FirewallApplyMode::PreserveSets);
                },
                [](std::chrono::milliseconds delay) {
                    std::this_thread::sleep_for(delay);
                },
                [](std::size_t,
                   std::chrono::milliseconds,
                   const TransientFirewallError&) {});
        } catch (const std::exception& rollback_error) {
            firewall_recovery_pending = true;
            Logger::instance().error(
                "Failed to restore the previous Keenetic DNS firewall "
                "generation; bounded runtime recovery is pending: {}",
                rollback_error.what());
        } catch (...) {
            firewall_recovery_pending = true;
            Logger::instance().error(
                "Failed to restore the previous Keenetic DNS firewall "
                "generation; bounded runtime recovery is pending");
        }
        if (!firewall_recovery_pending) {
            try {
                auto rollback_generation =
                    make_resolver_generation_snapshot();
                commit_resolver_generation_snapshot(
                    std::move(rollback_generation));
                resolver_recovery_pending =
                    !run_system_resolver_hook_stream_locked(
                        "reload", /*rebuild_snapshot=*/false);
            } catch (const std::exception& rollback_error) {
                resolver_recovery_pending = true;
                Logger::instance().error(
                    "Failed to restore the previous Keenetic DNS resolver "
                    "generation; bounded resolver recovery is pending: {}",
                    rollback_error.what());
            } catch (...) {
                resolver_recovery_pending = true;
                Logger::instance().error(
                    "Failed to restore the previous Keenetic DNS resolver "
                    "generation; bounded resolver recovery is pending");
            }
        } else {
            // Keep the last fully committed resolver snapshot until firewall
            // recovery has had a chance to publish the matching list/DNS
            // generation. The bounded resolver retry will then rebuild it.
            resolver_generation_snapshot_ = previous_resolver_generation;
            resolver_recovery_pending = true;
        }
        const auto current_generation =
            runtime_generation_.load(std::memory_order_acquire);
        if (firewall_recovery_pending) {
            resolver_after_firewall_gate_.wait_for(current_generation);
            schedule_runtime_firewall_retry(
                0, current_generation, OwnedSnatRecovery{});
        } else if (resolver_recovery_pending) {
            schedule_resolver_reload_retry(0, current_generation);
        }
        if (firewall_recovery_pending || resolver_recovery_pending) {
            refresh_resolver_config_hash_actual_async();
            publish_runtime_state();
        }
        throw;
    }
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
    if (!routing_runtime_active_ ||
        !dns_cfg_opt.has_value() ||
        !dns_cfg_opt->system_resolver.has_value()) {
        periodic_task_metrics_.record_skipped(
            "resolver-hash-refresh",
            !routing_runtime_active_
                ? "routing runtime is inactive"
                : "system resolver is not configured");
        if (!routing_runtime_active_) {
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
