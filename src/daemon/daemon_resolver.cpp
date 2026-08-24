#include "daemon.hpp"
#include "keenetic_dns_refresh_transaction.hpp"

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
        list_cache_snapshot) {
    ResolverGenerationSnapshot snapshot;
    snapshot.config = config_;
    snapshot.keenetic_dns = active_keenetic_dns_;
    if (!list_cache_snapshot) {
        list_cache_snapshot =
            capture_relevant_list_cache_generation(snapshot.config);
    }
    snapshot.list_cache_snapshot = std::move(list_cache_snapshot);
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
    ListStreamer streamer(
        list_service_.cache_manager(), snapshot.list_cache_snapshot);
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

    auto mutation_lease =
        std::make_shared<RuntimeMutationAdmission::Lease>(
            std::move(*admitted));
    const auto request = keenetic_dns_refresh_coordinator_.request(
        generation, mutation_lease);
    if (request == KeeneticDnsRefreshCoordinator::RequestResult::rejected) {
        mutation_lease.reset();
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
    const KeeneticDnsRefreshResult& result) {
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

    // Capture once from the single-writer CacheManager. The immutable lease
    // keeps every selected body alive while candidate apply, dnsmasq stream
    // and rollback run, without blocking an unrelated list publication for
    // the complete resolver IPC wait.
    const auto list_cache_snapshot =
        capture_relevant_list_cache_generation(config_);

    KeeneticDnsCacheView previous = active_keenetic_dns_;
    auto previous_resolver_generation =
        resolver_generation_snapshot_;
    ResolverSyncCheckpoint previous_resolver_sync =
        resolver_sync_.checkpoint();
    ResolverSyncCheckpoint rollback_resolver_sync =
        previous_resolver_sync;
    const std::uint32_t previous_resolver_retry_attempt =
        resolver_config_hash_actual_retry_attempt_;
    const std::int64_t previous_apply_started_ts =
        apply_started_ts_.load(std::memory_order_acquire);
    const bool firewall_snapshot_changed =
        !previous.snapshot.has_value() ||
        previous.snapshot->addresses != result.snapshot->addresses;
    const std::string previous_resolver_hash =
        resolver_sync_.snapshot(unix_timestamp_now_seconds()).expected_hash;
    KeeneticDnsCacheView candidate_view = refreshed_view;
    static_assert(
        std::is_nothrow_swappable_v<KeeneticDnsCacheView>,
        "Keenetic DNS transaction requires noexcept cache-view restore");
    bool resolver_hash_changed = false;
    bool rollback_resolver_hash_changed = false;
    const auto transaction = run_keenetic_dns_refresh_transaction(
        firewall_snapshot_changed,
        [this, &candidate_view]() noexcept {
            using std::swap;
            swap(active_keenetic_dns_, candidate_view);
        },
        [this, &list_cache_snapshot]() {
            // Keenetic DNS addresses participate in OUTPUT/PREROUTING detour
            // marks, so a changed address snapshot must reach firewall before
            // the matching resolver generation is streamed. Do not run the
            // hot-retry sleeps from this control-loop callback: one bounded
            // attempt establishes the transaction result, while the existing
            // generation-fenced runtime recovery owns any later retries.
            apply_firewall(
                FirewallApplyMode::PreserveSets,
                list_cache_snapshot);
        },
        [this,
         &list_cache_snapshot,
         &resolver_hash_changed,
         &previous_resolver_hash](bool& resolver_stream_attempted) {
            auto resolver_generation =
                make_resolver_generation_snapshot(list_cache_snapshot);
            resolver_hash_changed =
                resolver_generation.expected_hash != previous_resolver_hash;
            if (resolver_hash_changed) {
                apply_started_ts_.store(
                    unix_timestamp_now_seconds(),
                    std::memory_order_release);
            }
            commit_resolver_generation_snapshot(
                std::move(resolver_generation));
            if (resolver_hash_changed) {
                resolver_stream_attempted = true;
                if (!run_system_resolver_hook_stream_prepared(
                        "reload", /*rebuild_snapshot=*/false)) {
                    throw DaemonError(
                        "Keenetic DNS resolver reload did not complete its configuration stream");
                }
            }
        },
        [this,
         &previous,
         &previous_resolver_generation,
         &previous_resolver_sync,
         previous_resolver_retry_attempt,
         previous_apply_started_ts]() noexcept {
            using std::swap;
            swap(active_keenetic_dns_, previous);
            resolver_generation_snapshot_.swap(
                previous_resolver_generation);
            resolver_sync_.restore(std::move(previous_resolver_sync));
            resolver_config_hash_actual_retry_attempt_ =
                previous_resolver_retry_attempt;
            apply_started_ts_.store(
                previous_apply_started_ts,
                std::memory_order_release);
        },
        [this, &list_cache_snapshot]() {
            // A list refresh may have published a new immutable cache body
            // immediately before this transaction captured its lease. Rebuild
            // the previous DNS view over that pinned list generation instead
            // of claiming an exact historical list rollback. Rollback also
            // gets one immediate attempt; a failure is handed to the same
            // generation-fenced recovery chain instead of sleeping here.
            apply_firewall(
                FirewallApplyMode::PreserveSets,
                list_cache_snapshot);
        },
        [this,
         &list_cache_snapshot,
         &rollback_resolver_sync,
         &rollback_resolver_hash_changed,
         &previous_resolver_hash,
         previous_resolver_retry_attempt,
         previous_apply_started_ts]() {
            const std::int64_t rollback_started_ts =
                unix_timestamp_now_seconds();
            apply_started_ts_.store(
                rollback_started_ts, std::memory_order_release);
            resolver_sync_.apply_started(
                rollback_started_ts, previous_resolver_hash);
            const auto restore_observation = [this,
                                              &rollback_resolver_sync,
                                              previous_resolver_retry_attempt,
                                              previous_apply_started_ts]()
                                                 noexcept {
                resolver_sync_.restore(
                    std::move(rollback_resolver_sync));
                resolver_config_hash_actual_retry_attempt_ =
                    previous_resolver_retry_attempt;
                apply_started_ts_.store(
                    previous_apply_started_ts,
                    std::memory_order_release);
            };
            try {
                auto rollback_generation =
                    make_resolver_generation_snapshot(
                        list_cache_snapshot);
                rollback_resolver_hash_changed =
                    rollback_generation.expected_hash !=
                    previous_resolver_hash;
                if (!rollback_resolver_hash_changed) {
                    rollback_resolver_sync.expected_hash =
                        rollback_generation.expected_hash;
                }
                commit_resolver_generation_snapshot(
                    std::move(rollback_generation));
                if (!run_system_resolver_hook_stream_prepared(
                        "reload", /*rebuild_snapshot=*/false)) {
                    throw DaemonError(
                        "Previous Keenetic DNS resolver generation did not complete its configuration stream");
                }
            } catch (...) {
                const std::exception_ptr rollback_failure =
                    std::current_exception();
                // The candidate stream and its rollback are both uncertain.
                // Do not restore a historical CONVERGED observation while
                // dnsmasq may contain either (or partial) bytes. The bounded
                // resolver retry and actual-hash probe own convergence now.
                resolver_sync_.probe_failed(
                    ResolverConfigHashProbeStatus::QUERY_FAILED,
                    rollback_started_ts);
                std::rethrow_exception(rollback_failure);
            }
            // Streaming the rollback is an external repair, not a new user
            // apply. Preserve the previous probe/backoff observations instead
            // of resetting them through commit_resolver_generation_snapshot().
            if (!rollback_resolver_hash_changed) {
                restore_observation();
            }
        });

    if (transaction.committed) {
        if (resolver_hash_changed) {
            refresh_resolver_config_hash_actual_async();
        }
        publish_runtime_state();
        return true;
    }

    const auto describe_failure = [](const std::exception_ptr& failure) {
        if (!failure) {
            return std::string{"unknown error"};
        }
        try {
            std::rethrow_exception(failure);
        } catch (const std::exception& error) {
            return std::string{error.what()};
        } catch (...) {
            return std::string{"unknown error"};
        }
    };

    const auto current_generation =
        runtime_generation_.load(std::memory_order_acquire);
    if (transaction.recovery ==
            KeeneticDnsRefreshRecovery::firewall_only ||
        transaction.recovery ==
            KeeneticDnsRefreshRecovery::firewall_then_resolver) {
        try {
            Logger::instance().error(
                "Failed to restore the previous Keenetic DNS firewall "
                "generation; bounded runtime recovery is pending: {}",
                describe_failure(transaction.recovery_failure));
        } catch (...) {
        }
    } else if (transaction.recovery ==
               KeeneticDnsRefreshRecovery::resolver_only) {
        try {
            Logger::instance().error(
                "Failed to restore the previous Keenetic DNS resolver "
                "generation; bounded resolver recovery is pending: {}",
                describe_failure(transaction.recovery_failure));
        } catch (...) {
        }
    } else if (transaction.recovery_failure) {
        try {
            Logger::instance().error(
                "Failed to restore the previous Keenetic DNS in-memory "
                "generation: {}",
                describe_failure(transaction.recovery_failure));
        } catch (...) {
        }
    }

    const std::exception_ptr recovery_dispatch_failure =
        dispatch_keenetic_dns_refresh_recovery(
            transaction.recovery,
            [this, current_generation]() noexcept {
                const bool already_waiting =
                    resolver_after_firewall_gate_.waiting_for(
                        current_generation);
                resolver_after_firewall_gate_.wait_for(
                    current_generation);
                return !already_waiting;
            },
            [this, current_generation]() noexcept {
                (void)resolver_after_firewall_gate_.release(
                    current_generation);
            },
            [this, current_generation]() {
                schedule_runtime_firewall_retry(
                    0, current_generation, OwnedSnatRecovery{});
            },
            [this, current_generation]() {
                schedule_resolver_reload_retry(
                    0, current_generation);
            });
    if (recovery_dispatch_failure) {
        try {
            const auto incident =
                runtime_firewall_incidents_.record_failure(
                    "keenetic-dns-refresh-recovery-dispatch",
                    /*notify_immediately=*/true);
            if (incident.notify) {
                Logger::instance().error(
                    "Keenetic DNS recovery could not be scheduled: {}. "
                    "The original refresh failure remains authoritative; "
                    "runtime diagnostics are degraded until the next "
                    "reconciliation.",
                    describe_failure(recovery_dispatch_failure));
            }
        } catch (...) {
        }
    }

    const bool resolver_observation_changed =
        transaction.recovery ==
            KeeneticDnsRefreshRecovery::firewall_then_resolver ||
        transaction.recovery ==
            KeeneticDnsRefreshRecovery::resolver_only ||
        rollback_resolver_hash_changed;
    if (resolver_observation_changed) {
        try {
            refresh_resolver_config_hash_actual_async();
        } catch (...) {
            try {
                Logger::instance().error(
                    "Keenetic DNS recovery could not schedule its actual-hash probe: {}",
                    describe_failure(std::current_exception()));
            } catch (...) {
            }
        }
    }
    if (transaction.recovery != KeeneticDnsRefreshRecovery::none ||
        rollback_resolver_hash_changed || recovery_dispatch_failure) {
        try {
            publish_runtime_state();
        } catch (...) {
            try {
                Logger::instance().error(
                    "Keenetic DNS recovery state publication failed: {}",
                    describe_failure(std::current_exception()));
            } catch (...) {
            }
        }
    }
    if (transaction.primary_failure) {
        std::rethrow_exception(transaction.primary_failure);
    }
    throw DaemonError("Keenetic DNS refresh transaction failed");
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
