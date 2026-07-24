#include "daemon.hpp"

#include "../dns/dns_router.hpp"
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

namespace keen_pbr3 {

namespace {

constexpr auto kResolverConfigHashActualRefreshInterval = std::chrono::seconds{60};

bool dns_config_uses_keenetic_server(const std::optional<DnsConfig>& dns_cfg_opt) {
    if (!dns_cfg_opt.has_value()) {
        return false;
    }

    for (const auto& server : dns_cfg_opt->servers.value_or(std::vector<DnsServer>{})) {
        if (server.type.value_or(api::DnsServerType::STATIC) == api::DnsServerType::KEENETIC) {
            return true;
        }
    }

    return false;
}

} // namespace

ResolverGenerationSnapshot Daemon::make_resolver_generation_snapshot() {
    ResolverGenerationSnapshot snapshot;
    snapshot.config = config_;
    snapshot.resolver_type =
        firewall_->backend() == FirewallBackend::nftables
            ? ResolverType::DNSMASQ_NFTSET
            : ResolverType::DNSMASQ_IPSET;
    const DnsConfig dns_cfg = snapshot.config.dns.value_or(DnsConfig{});
    const Ipv6SupportDecision ipv6_decision =
        resolve_ipv6_support(snapshot.config);
    log_ipv6_support_decision_once(ipv6_decision);
    snapshot.ipv6_enabled = ipv6_decision.enabled;
    snapshot.generation =
        runtime_generation_.load(std::memory_order_acquire);
    ListStreamer streamer(list_service_.cache_manager());
    DnsServerRegistry dns_registry(dns_cfg);
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
        snapshot.ipv6_enabled);
    snapshot.expected_hash = generator.compute_config_hash();
    return snapshot;
}

void Daemon::update_resolver_config_hash() {
    auto snapshot = std::make_shared<ResolverGenerationSnapshot>(
        make_resolver_generation_snapshot());
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

void Daemon::publish_runtime_state(bool reconcile_status_stream) {
    Logger::instance().trace(
        "runtime_state_publish",
        "routing_runtime_active={} runtime_state={} reason={}",
        routing_runtime_active_ ? "true" : "false",
        runtime_state_name(runtime_state_machine_.state()),
        runtime_state_machine_.reason());
    runtime_state_store_.publish(build_runtime_state_snapshot());
#ifdef WITH_API
    if (reconcile_status_stream && status_stream_) {
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

    if (!dns_config_uses_keenetic_server(config_.dns)) {
        return;
    }

    keenetic_dns_refresh_task_id_ = scheduler_->schedule_repeating(
        std::chrono::minutes{5},
        [this]() {
            post_control_task([this]() {
                if (!routing_runtime_active_) {
                    return;
                }
                if (refresh_keenetic_dns_cache(true)) {
                    const std::int64_t apply_started_ts = unix_timestamp_now_seconds();
                    apply_started_ts_.store(apply_started_ts, std::memory_order_release);
                    update_resolver_config_hash();
                    (void)run_system_resolver_hook_reload();
                    refresh_resolver_config_hash_actual_async();
                    publish_runtime_state();
                }
            }, "keenetic-dns-refresh");
        },
        "keenetic-dns-refresh");
}

bool Daemon::refresh_keenetic_dns_cache(bool force_refresh) {
    if (!dns_config_uses_keenetic_server(config_.dns)) {
        return false;
    }

    const KeeneticDnsRefreshResult result = refresh_keenetic_dns_address_cache(force_refresh);
    auto& log = Logger::instance();

    switch (result.status) {
    case KeeneticDnsRefreshStatus::UPDATED:
        if (!result.addresses.empty()) {
            log.info("Keenetic DNS refreshed: {}", fmt::join(result.addresses, ", "));
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
            log.warn("Keenetic DNS refresh failed with no cached value: {}", result.error);
        }
        return false;
    }

    return false;
}

void Daemon::schedule_resolver_config_hash_actual_retry() {
    const auto delay = resolver_convergence_retry_delay(
        resolver_config_hash_actual_retry_attempt_);
    if (resolver_config_hash_actual_retry_attempt_ < 6) {
        ++resolver_config_hash_actual_retry_attempt_;
    }
    schedule_resolver_config_hash_actual_after(
        delay,
        "resolver-config-hash-actual-retry");
}

void Daemon::reset_resolver_actual_state() {
    resolver_sync_.resolver_not_configured();
}

void Daemon::commit_resolver_hash_probe_result(
    const std::string& resolver_addr,
    std::uint64_t generation,
    std::optional<ResolverConfigHashProbeResult> probe_result,
    std::optional<std::int64_t> probe_completed_ts,
    TraceId trace_id) {
    post_control_task(
        [this,
         resolver_addr,
         generation,
         probe_result = std::move(probe_result),
         probe_completed_ts,
         trace_id]() mutable {
            ScopedTraceContext trace_scope_inner(trace_id);
            resolver_hash_refresh_inflight_.store(false, std::memory_order_release);

            if (generation != runtime_generation_.load(std::memory_order_acquire)) {
                Logger::instance().trace("resolver_hash_refresh_skip",
                                         "resolver={} generation={} reason=stale_runtime",
                                         resolver_addr,
                                         generation);
                schedule_resolver_config_hash_actual_after(
                    std::chrono::seconds{1},
                    "resolver-config-hash-stale-generation-retry");
                return;
            }

            const std::int64_t apply_started_ts =
                apply_started_ts_.load(std::memory_order_acquire);
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
                if (probe_result->parsed_value.ts.has_value() &&
                    apply_started_ts > 0 &&
                    *probe_result->parsed_value.ts < apply_started_ts &&
                    previous_snapshot.expected_hash !=
                        probe_result->parsed_value.hash) {
                    Logger::instance().verbose(
                        "Resolver config hash TXT is older than current apply; using live actual value "
                        "(resolver={}, txt_ts={}, apply_started_ts={})",
                        resolver_addr,
                        *probe_result->parsed_value.ts,
                        apply_started_ts);
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
            if (resolver_snapshot.sync_state ==
                api::ResolverConfigSyncState::CONVERGING) {
                schedule_resolver_config_hash_actual_retry();
            } else {
                resolver_config_hash_actual_retry_attempt_ = 0;
                schedule_resolver_config_hash_actual_refresh();
            }
            publish_runtime_state(
                !resolver_sync_semantically_equal(previous_snapshot,
                                                  resolver_snapshot));
        },
        "resolver-hash-refresh-commit");
}

void Daemon::refresh_resolver_config_hash_actual_async() {
    const auto dns_cfg_opt = config_.dns;
    if (!routing_runtime_active_ ||
        !dns_cfg_opt.has_value() ||
        !dns_cfg_opt->system_resolver.has_value()) {
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
        reset_resolver_actual_state();
        publish_runtime_state();
        return;
    }

    bool expected = false;
    if (!resolver_hash_refresh_inflight_.compare_exchange_strong(expected,
                                                                 true,
                                                                 std::memory_order_acq_rel)) {
        Logger::instance().trace("resolver_hash_refresh_skip", "reason=inflight");
        schedule_resolver_config_hash_actual_after(
            std::chrono::seconds{1},
            "resolver-config-hash-inflight-retry");
        return;
    }

    const auto generation = runtime_generation_.load(std::memory_order_acquire);
    const TraceId trace_id = ensure_trace_id();
    const bool enqueued = resolver_io_executor_.try_post(
        "resolver-config-hash-actual",
        [this, resolver_addr, generation, trace_id]() mutable {
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
                                              trace_id);
        },
        trace_id);

    if (!enqueued) {
        resolver_hash_refresh_inflight_.store(false, std::memory_order_release);
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
