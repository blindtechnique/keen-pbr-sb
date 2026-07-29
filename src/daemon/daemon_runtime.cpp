#include "daemon.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <future>
#include <map>
#include <set>
#include <sstream>
#include <thread>

#include "../config/routing_state.hpp"
#include "../firewall/firewall.hpp"
#include "../firewall/firewall_runtime.hpp"
#include "../keenetic/internal_vpn_server_resolver.hpp"
#include "../keenetic/internal_vpn_runtime_generation.hpp"
#include "../keenetic/ndms_catalog_cache.hpp"
#include "../log/logger.hpp"
#include "../routing/urltest_manager.hpp"
#ifdef WITH_API
#include "../api/handler_catalog.hpp"
#include "../api/handler_remote_access.hpp"
#include "../api/status_stream.hpp"
#endif
#include "../util/ipv6_support.hpp"
#include "../util/time_utils.hpp"
#include "../util/cron.hpp"
#include "scheduler.hpp"
#include "resolver_health.hpp"
#include "system_resolver_hook.hpp"

namespace keen_pbr3 {

namespace {

constexpr std::array<std::chrono::seconds, 5>
    INTERNAL_VPN_CATALOG_RETRY_DELAYS{
        std::chrono::seconds{5},
        std::chrono::seconds{10},
        std::chrono::seconds{20},
        std::chrono::seconds{30},
        std::chrono::seconds{60},
    };
constexpr std::array<std::chrono::seconds, 5>
    RESOLVER_RELOAD_RETRY_DELAYS{
        std::chrono::seconds{1},
        std::chrono::seconds{2},
        std::chrono::seconds{4},
        std::chrono::seconds{8},
        std::chrono::seconds{16},
    };

class ResolverIpcGate {
public:
    explicit ResolverIpcGate(std::atomic<bool>& flag) : flag_(flag) {
        if (flag_.exchange(true, std::memory_order_acq_rel)) {
            throw DaemonError("system resolver operation is already in progress");
        }
    }

    ~ResolverIpcGate() {
        flag_.store(false, std::memory_order_release);
    }

    ResolverIpcGate(const ResolverIpcGate&) = delete;
    ResolverIpcGate& operator=(const ResolverIpcGate&) = delete;

private:
    std::atomic<bool>& flag_;
};

bool urltest_contains_child(const Outbound& urltest,
                            const std::string& child_tag) {
    for (const auto& group :
         urltest.outbound_groups.value_or(std::vector<OutboundGroup>{})) {
        if (std::find(group.outbounds.begin(),
                      group.outbounds.end(),
                      child_tag) != group.outbounds.end()) {
            return true;
        }
    }
    return false;
}

bool same_internal_vpn_runtime_servers(
    const std::vector<InternalVpnServer>& lhs,
    const std::vector<InternalVpnServer>& rhs) {
    return lhs.size() == rhs.size() &&
           std::equal(
               lhs.begin(),
               lhs.end(),
               rhs.begin(),
               [](const InternalVpnServer& left,
                  const InternalVpnServer& right) {
                   return left.interface == right.interface &&
                          left.ndms_id == right.ndms_id &&
                          left.process_clients == right.process_clients;
               });
}

} // namespace

bool Daemon::run_system_resolver_hook(std::string_view action,
                                      bool manage_ipc_gate) {
    auto& log = Logger::instance();

    const auto args = build_system_resolver_hook_args(config_, action);
    if (args.empty()) {
        return true;
    }

    std::string command;
    for (std::size_t index = 0; index < args.size(); ++index) {
        if (index != 0) command += ' ';
        command += args[index];
    }

    auto execute_hook = [this, args] {
        KPBR_LOCK_GUARD(system_resolver_hook_mutex_);
        return hook_command_executor_(args);
    };

    std::optional<ResolverIpcGate> gate;
    if (manage_ipc_gate) {
        gate.emplace(ipc_resolver_hook_inflight_);
    }

    int exit_code = 0;
    const bool pump_control_socket =
        is_event_loop_thread() ||
        !event_loop_active_.load(std::memory_order_acquire);
    if (pump_control_socket) {
        auto hook_result = resolver_hook_executor_.submit(
            "system-resolver-hook-command", std::move(execute_hook));
        while (hook_result.wait_for(std::chrono::milliseconds{10}) !=
               std::future_status::ready) {
            handle_ipc_control_socket();
        }
        exit_code = hook_result.get();
    } else {
        exit_code = execute_hook();
    }

    if (exit_code != 0) {
        log.warn("System resolver hook failed (exit code: {}): {}",
                 exit_code,
                 command);
        return false;
    }

    log.info("System resolver hook complete: {}", command);
    return true;
}

bool Daemon::run_system_resolver_hook_stream(
    std::string_view action) {
    if (build_system_resolver_hook_args(config_, action).empty()) {
        return true;
    }

    // Keep the cache revision stable from hash calculation through the final
    // streamed byte. Remote list downloads use the exclusive side.
    KPBR_SHARED_LOCK(cache_snapshot, resolver_cache_snapshot_mutex_);
    update_resolver_config_hash();
    auto generation = std::make_shared<ResolverGenerationSnapshot>(
        *resolver_generation_snapshot_);
    generation->stream_epoch =
        resolver_stream_epoch_.fetch_add(1, std::memory_order_acq_rel) + 1;
    resolver_generation_snapshot_ = generation;
    const std::uint64_t expected_epoch =
        generation->stream_epoch;
    ResolverIpcGate gate(ipc_resolver_hook_inflight_);
    if (!run_system_resolver_hook(action, false)) {
        return false;
    }
    if (!wait_for_resolver_stream_epoch(
            expected_epoch, std::chrono::seconds{15})) {
        Logger::instance().warn(
            "System resolver hook completed without the expected dnsmasq "
            "configuration stream (epoch={})",
            expected_epoch);
        return false;
    }

    // Lists and DNS cache files remain live on disk while streaming. Refresh
    // the expected hash only after the completed stream boundary.
    update_resolver_config_hash();
    return true;
}

bool Daemon::run_system_resolver_hook_reload() {
    return run_system_resolver_hook_stream("reload");
}

bool Daemon::wait_for_resolver_stream_epoch(
    std::uint64_t expected_epoch,
    std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (resolver_stream_completed_epoch_.load(
                std::memory_order_acquire) == expected_epoch) {
            return true;
        }
        if (is_event_loop_thread() ||
            !event_loop_active_.load(std::memory_order_acquire)) {
            handle_ipc_control_socket();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return resolver_stream_completed_epoch_.load(
               std::memory_order_acquire) == expected_epoch;
}

bool Daemon::routing_runtime_active() const {
    return runtime_state_store_.snapshot().routing_runtime_active;
}

void Daemon::warn_conntrack_unavailable_once() {
    if (conntrack_unavailable_warning_emitted_) {
        return;
    }
    conntrack_unavailable_warning_emitted_ = true;
    Logger::instance().warn(
        "Best-effort conntrack cleanup is unavailable because the conntrack "
        "utility is not installed; existing flows may keep their previous "
        "path until they expire");
}

void Daemon::cleanup_owned_conntrack_marks(const char* context) {
    std::set<uint32_t> owned_marks;
    for (const auto& [tag, mark] : outbound_marks_) {
        (void)tag;
        owned_marks.insert(mark);
    }
    if (owned_marks.empty()) {
        return;
    }

    const uint32_t owned_mask =
        fwmark_mask_value(config_.fwmark.value_or(FwmarkConfig{}));
    try {
        const auto cleanup =
            conntrack_manager_.delete_marks(owned_marks, owned_mask);
        if (cleanup.command_unavailable) {
            warn_conntrack_unavailable_once();
        }
        if (cleanup.failed == 0U) {
            return;
        }
        Logger::instance().info(
            "Best-effort conntrack cleanup failed for {} owned mark(s) {}; "
            "existing flows may keep their previous path until they expire",
            cleanup.failed,
            context);
    } catch (const std::exception& error) {
        Logger::instance().info(
            "Best-effort conntrack cleanup {} raised an error: {}; existing "
            "flows may keep their previous path until they expire",
            context,
            error.what());
    }
}

void Daemon::stop_routing_runtime() {
    auto& log = Logger::instance();
    cancel_runtime_firewall_retry();
    cancel_resolver_reload_retry();
    cancel_internal_vpn_catalog_refresh_retry();
    if (!routing_runtime_active_) {
        if (runtime_state_machine_.state() != RuntimeState::stopped) {
            transition_runtime_or_throw(RuntimeState::stopped, "inactive runtime stopped");
            publish_runtime_state();
        }
        return;
    }

    runtime_generation_.fetch_add(1, std::memory_order_acq_rel);

    if (urltest_manager_) {
        urltest_manager_->clear();
    }
    urltest_apply_incidents_.clear();
    cleanup_owned_conntrack_marks("while stopping routing");
    policy_rules_.clear();
    route_table_.clear();
    firewall_->cleanup();
    if (keenetic_dns_refresh_task_id_ >= 0) {
        scheduler_->cancel(keenetic_dns_refresh_task_id_);
        keenetic_dns_refresh_task_id_ = -1;
    }

    const bool resolver_deactivated =
        run_system_resolver_hook("deactivate");

    // Routing and firewall teardown has already happened. Publish the real
    // state even when dnsmasq fallback activation fails; reporting "running"
    // here would leave restart callers and the UI with a false liveness state.
    routing_runtime_active_ = false;
    transition_runtime_or_throw(RuntimeState::stopped, "runtime stopped");
    refresh_resolver_config_hash_actual_async();
    publish_runtime_state();
    log.info("Routing runtime stopped.");

    if (!resolver_deactivated) {
        throw DaemonError("System resolver deactivate hook failed");
    }
}

void Daemon::start_routing_runtime() {
    auto& log = Logger::instance();
    if (routing_runtime_active_) {
        return;
    }

    transition_runtime_or_throw(RuntimeState::starting, "runtime start requested");
    publish_runtime_state();

    try {
        runtime_generation_.fetch_add(1, std::memory_order_acq_rel);

        const auto internal_vpn_resolution =
            prepare_internal_vpn_server_resolution_from_cache();
        InternalVpnRuntimeGenerationTransaction internal_vpn_generation(
            resolved_internal_vpn_servers_,
            internal_vpn_resolution.effective_servers);
        normalize_urltest_selections();
        setup_static_routing();
        register_urltest_outbounds();
        (void)refresh_keenetic_dns_cache(true);
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
                    "Routing start firewall apply deferred after a concurrent "
                    "firmware change: {}. Retry {} in {}ms.",
                    error.what(),
                    retry,
                    delay.count());
            });

        // A previous daemon crash or a transiently missing SNAT hook can leave
        // keen-pbr-marked conntrack entries without a usable NAT mapping.
        // Reinstall the complete firewall first, then retire only our marked
        // flows so the clients reconnect through the current route and SNAT.
        // Do this on a cold start only: transactional restarts intentionally
        // preserve established connections.
        cleanup_owned_conntrack_marks(
            "after cold-start firewall activation");

        apply_started_ts_.store(
            unix_timestamp_now_seconds(), std::memory_order_release);
        update_resolver_config_hash();
        if (!run_system_resolver_hook_stream(
                runtime_start_resolver_action())) {
            throw DaemonError("System resolver activation hook failed");
        }

        internal_vpn_generation.commit();
        update_internal_vpn_verified_includes_lkg(
            internal_vpn_resolution);
        routing_runtime_active_ = true;
        schedule_internal_vpn_catalog_refresh_if_needed(
            internal_vpn_resolution.state);
        transition_runtime_or_throw(RuntimeState::running, "runtime start complete");
        schedule_keenetic_dns_refresh();
        refresh_resolver_config_hash_actual_async();
        publish_runtime_state();
        log.info("Routing runtime started.");
    } catch (...) {
        // A start failure may happen at any point after routes or firewall
        // state were installed. Roll every owned subsystem back, not only the
        // resolver hook, so health and the kernel cannot disagree.
        if (urltest_manager_) {
            try {
                urltest_manager_->clear();
            } catch (const std::exception& cleanup_error) {
                log.error("Failed to clear urltest state after start failure: {}",
                          cleanup_error.what());
            }
        }
        try {
            policy_rules_.clear();
        } catch (const std::exception& cleanup_error) {
            log.error("Failed to clean policy rules after start failure: {}",
                      cleanup_error.what());
        }
        try {
            route_table_.clear();
        } catch (const std::exception& cleanup_error) {
            log.error("Failed to clean routes after start failure: {}",
                      cleanup_error.what());
        }
        try {
            firewall_->cleanup();
        } catch (const std::exception& cleanup_error) {
            log.error("Failed to clean firewall after start failure: {}",
                      cleanup_error.what());
        }
        if (!run_system_resolver_hook("deactivate")) {
            log.warn("System resolver fallback recovery failed");
        }
        routing_runtime_active_ = false;
        refresh_resolver_config_hash_actual_async();
        try {
            transition_runtime_or_throw(RuntimeState::broken, "runtime start failed");
            publish_runtime_state();
        } catch (const std::exception& state_error) {
            log.error("Failed to publish broken runtime state: {}", state_error.what());
        }
        throw;
    }
}

void Daemon::restart_routing_runtime() {
    if (!routing_runtime_active_) {
        throw DaemonError("Routing runtime is stopped");
    }

    auto& log = Logger::instance();
    const auto previous_apply_started =
        apply_started_ts_.load(std::memory_order_acquire);
    const ResolverSyncCheckpoint previous_resolver_sync =
        resolver_sync_.checkpoint();

    transition_runtime_or_throw(
        RuntimeState::applying, "transactional runtime restart requested");
    publish_runtime_state();

    bool kernel_generation_committed = false;
    try {
        // This is a same-config replacement. Keeping the generation stable is
        // required so a URLTEST transition already committed by the probe
        // manager cannot be discarded while its control task is queued.
        cancel_runtime_firewall_retry();
        cancel_resolver_reload_retry();
        const auto internal_vpn_resolution =
            prepare_internal_vpn_server_resolution_from_cache();
        InternalVpnRuntimeGenerationTransaction internal_vpn_generation(
            resolved_internal_vpn_servers_,
            internal_vpn_resolution.effective_servers);

        apply_runtime_replacement(
            [this]() {
                // Recreate missing routes first and retire obsolete owned
                // entries only after their replacements exist.
                reconcile_static_routing();
            },
            [this]() {
                // PreserveSets keeps the currently committed firewall
                // generation forwarding until the replacement transaction
                // itself has reached COMMIT.
                apply_firewall(FirewallApplyMode::PreserveSets);
            },
            [](std::chrono::milliseconds delay) {
                std::this_thread::sleep_for(delay);
            },
            [](std::size_t retry,
               std::chrono::milliseconds delay,
               const TransientFirewallError& error) {
                Logger::instance().info(
                    "Runtime restart firewall replacement deferred after a "
                    "concurrent firmware change: {}. Retry {} in {}ms.",
                    error.what(),
                    retry,
                    delay.count());
            },
            [this,
             &log,
             &internal_vpn_generation,
             &internal_vpn_resolution,
             &kernel_generation_committed]() {
                // apply_runtime_replacement invokes this callback only after
                // the firewall transaction reached COMMIT. Publish the
                // matching in-memory ingress generation at that boundary,
                // before the secondary resolver reload can fail.
                internal_vpn_generation.commit();
                update_internal_vpn_verified_includes_lkg(
                    internal_vpn_resolution);
                kernel_generation_committed = true;
                apply_started_ts_.store(
                    unix_timestamp_now_seconds(),
                    std::memory_order_release);
                update_resolver_config_hash();
                if (run_system_resolver_hook_reload()) {
                    return;
                }

                // dnsmasq can finish its own firmware-triggered reload just
                // after our stream deadline. Retry the live reload once
                // without deactivating the currently forwarding runtime.
                log.info(
                    "Resolver reload did not converge during runtime restart; "
                    "retrying once without tearing down routing.");
                std::this_thread::sleep_for(std::chrono::milliseconds{250});
                if (!run_system_resolver_hook_reload()) {
                    throw DaemonError(
                        "System resolver reload hook failed during runtime "
                        "restart");
                }
            });

        routing_runtime_active_ = true;
        schedule_internal_vpn_catalog_refresh_if_needed(
            internal_vpn_resolution.state);
        refresh_resolver_config_hash_actual_async();
        transition_runtime_or_throw(
            RuntimeState::running, "transactional runtime restart complete");
        publish_runtime_state();
        log.info(
            "Routing runtime restarted in place without a forwarding teardown.");
    } catch (const std::exception& error) {
        // A failure before firewall COMMIT leaves the previous generation
        // authoritative. A later resolver-hook failure leaves the newly
        // committed firewall and matching in-memory ingress generation active.
        if (!kernel_generation_committed) {
            apply_started_ts_.store(
                previous_apply_started, std::memory_order_release);
            resolver_sync_.restore(previous_resolver_sync);
        }
        routing_runtime_active_ = true;
        if (!kernel_generation_committed &&
            config_has_stable_internal_vpn_server_policy(config_)) {
            // Keep a bounded retry pending so either a pre-COMMIT failure or a
            // post-COMMIT resolver failure converges without waiting for an
            // unrelated interface event.
            schedule_runtime_firewall_retry(
                0,
                runtime_generation_.load(std::memory_order_acquire));
        }
        if (kernel_generation_committed) {
            schedule_resolver_reload_retry(
                0,
                runtime_generation_.load(std::memory_order_acquire));
        }
        try {
            transition_runtime_or_throw(
                RuntimeState::running,
                kernel_generation_committed
                    ? "runtime restart committed; resolver reload pending"
                    : "runtime restart failed; previous runtime retained");
            refresh_resolver_config_hash_actual_async();
            publish_runtime_state();
        } catch (const std::exception& state_error) {
            log.error(
                "Failed to publish retained runtime after restart failure: {}",
                state_error.what());
        }
        throw DaemonError(
            std::string(
                kernel_generation_committed
                    ? "Routing runtime replacement was committed, but its "
                      "resolver reload failed; retry is scheduled: "
                    : "Routing runtime restart failed; the previous runtime "
                      "remains active: ") +
            error.what());
    }
}

void Daemon::setup_static_routing() {
    const Ipv6SupportDecision ipv6_decision = resolve_ipv6_support(config_);
    log_ipv6_support_decision_once(ipv6_decision);
    const auto main_table_routes = netlink_.dump_routes_in_table(254);
    populate_routing_state(
        config_,
        outbound_marks_,
        route_table_,
        policy_rules_,
        [&main_table_routes](const Outbound& outbound) {
            return is_interface_outbound_reachable(outbound, main_table_routes);
        },
        &firewall_state_.get_urltest_selections(),
        ipv6_decision.enabled);
}

void Daemon::reconcile_static_routing() {
    const Ipv6SupportDecision ipv6_decision = resolve_ipv6_support(config_);
    log_ipv6_support_decision_once(ipv6_decision);
    RouteTable desired_routes(netlink_, true);
    PolicyRuleManager desired_rules(netlink_, true);
    const auto main_table_routes = netlink_.dump_routes_in_table(254);
    populate_routing_state(
        config_,
        outbound_marks_,
        desired_routes,
        desired_rules,
        [&main_table_routes](const Outbound& outbound) {
            return is_interface_outbound_reachable(outbound, main_table_routes);
        },
        &firewall_state_.get_urltest_selections(),
        ipv6_decision.enabled);

    // The URLTest policy rule does not change on a selected-child switch, but
    // its route does. Add all desired routes first so marked traffic never
    // observes an empty table, then retire only obsolete owned state.
    route_table_.add_missing(desired_routes.get_routes());
    policy_rules_.add_missing(desired_rules.get_rules());
    policy_rules_.remove_obsolete(desired_rules.get_rules());
    route_table_.remove_obsolete(desired_routes.get_routes());
}

void Daemon::apply_firewall(FirewallApplyMode mode) {
    firewall_state_.set_rules(apply_runtime_firewall(
        config_,
        outbound_marks_,
        firewall_state_.get_urltest_selections(),
        list_service_.cache_manager(),
        *firewall_,
        mode,
        &resolved_internal_vpn_servers_));

#ifdef WITH_API
    // The firmware reapplies its own firewall on every network event and drops
    // rules it does not own, so the remote access hole has to be restored
    // alongside ours rather than only once at startup.
    apply_remote_access_rules(config_.api.has_value()
                                  ? config_.api->listen.value_or(std::string{})
                                  : std::string{});
#endif
}

void Daemon::normalize_urltest_selections() {
    const auto current = firewall_state_.get_urltest_selections();
    std::map<std::string, std::string> normalized;

    for (const auto& outbound :
         config_.outbounds.value_or(std::vector<Outbound>{})) {
        if (outbound.type != OutboundType::URLTEST) {
            continue;
        }
        const auto selection = current.find(outbound.tag);
        if (selection == current.end()) {
            continue;
        }
        if (urltest_contains_child(outbound, selection->second) &&
            outbound_marks_.find(selection->second) != outbound_marks_.end()) {
            normalized.emplace(selection->first, selection->second);
            continue;
        }
        Logger::instance().info(
            "Dropping retained urltest selection '{}' for '{}': child is no "
            "longer configured or routable",
            selection->second,
            outbound.tag);
    }

    firewall_state_.set_urltest_selections(std::move(normalized));
}

void Daemon::handle_urltest_selection_change(
    const UrltestSelectionChange& change,
    std::uint64_t expected_runtime_generation) {
    post_control_task([this, change, expected_runtime_generation]() {
        auto& log = Logger::instance();
        const auto current_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        if (expected_runtime_generation != current_runtime_generation) {
            log.info(
                "Ignoring stale urltest transition for '{}': runtime "
                "generation changed from {} to {}",
                change.urltest_tag,
                expected_runtime_generation,
                current_runtime_generation);
            return;
        }
        const auto reason =
            change.reason == UrltestSelectionChangeReason::previous_unhealthy
                ? "previous_unhealthy"
                : (change.reason ==
                           UrltestSelectionChangeReason::healthy_rebalance
                       ? "healthy_rebalance"
                       : "initial");
        log.info(
            "Urltest '{}' selected outbound: '{}' (previous='{}', reason={})",
            change.urltest_tag,
            change.new_child_tag,
            change.previous_child_tag,
            reason);

        std::optional<uint32_t> retired_mark;
        const auto outbounds =
            config_.outbounds.value_or(std::vector<Outbound>{});
        const auto urltest_it = std::find_if(
            outbounds.begin(),
            outbounds.end(),
            [&change](const Outbound& outbound) {
                return outbound.tag == change.urltest_tag &&
                       outbound.type == OutboundType::URLTEST;
            });
        if (urltest_it == outbounds.end() || !urltest_manager_) {
            log.info(
                "Ignoring stale urltest transition for '{}': selector is no "
                "longer configured",
                change.urltest_tag);
            return;
        }

        const auto previous_selections =
            firewall_state_.get_urltest_selections();
        const auto& selections = previous_selections;
        const auto old_selection_it = selections.find(change.urltest_tag);
        const std::string applied_previous =
            old_selection_it != selections.end()
                ? old_selection_it->second
                : std::string{};
        if (applied_previous != change.previous_child_tag) {
            log.info(
                "Ignoring stale urltest transition for '{}': applied "
                "selection is '{}', event expected '{}'",
                change.urltest_tag,
                applied_previous,
                change.previous_child_tag);
            return;
        }

        // Selection-change tasks preserve the order in which control-loop
        // probe commits enqueue them. Do not compare this event with the
        // manager's newest selection: a later probe can already have committed
        // P -> B -> C while the queued P -> B transition is still waiting.
        // Skipping P -> B in that case would also make B -> C fail its
        // applied_previous guard and leave the kernel on P. The firewall
        // selection is the transactional cursor for this ordered stream.

        const auto cleanup_mode =
            urltest_it->conntrack_on_switch.value_or(
                ConntrackOnSwitch::PRESERVE);
        const bool cleanup_retired_flows =
            cleanup_mode == ConntrackOnSwitch::DELETE ||
            (cleanup_mode == ConntrackOnSwitch::DELETE_ON_FAILURE &&
             change.reason ==
                 UrltestSelectionChangeReason::previous_unhealthy);
        if (cleanup_retired_flows &&
            !change.previous_child_tag.empty() &&
            change.previous_child_tag != change.new_child_tag) {
            const auto old_mark_it =
                outbound_marks_.find(change.previous_child_tag);
            if (old_mark_it != outbound_marks_.end()) {
                retired_mark = old_mark_it->second;
            }
        }

        firewall_state_.set_urltest_selection(
            change.urltest_tag, change.new_child_tag);
        bool runtime_rebuilt = false;
        try {
            reconcile_static_routing();
            apply_firewall(FirewallApplyMode::PreserveSets);
            runtime_rebuilt = true;
            urltest_apply_incidents_.reset(change.urltest_tag);
            log.info("Routing and firewall rebuilt after urltest change.");
        } catch (const std::exception& e) {
            // A failed candidate switch is transactional: the previous
            // selection stays authoritative until the kernel accepts the new
            // generation. This recovery detail is useful in the journal but
            // is not an actionable user notification.
            log.info(
                "Routing/firewall did not accept the urltest change: {}; "
                "restoring the previously applied selection",
                e.what());
            firewall_state_.set_urltest_selections(previous_selections);
            const bool manager_synchronized =
                urltest_manager_->synchronize_selected(
                    change.urltest_tag, applied_previous);
            if (!manager_synchronized) {
                log.info(
                    "Failed to synchronize urltest '{}' with restored "
                    "selection '{}'",
                    change.urltest_tag,
                    applied_previous);
            }

            try {
                reconcile_static_routing();
                apply_firewall(FirewallApplyMode::PreserveSets);
                log.info(
                    "Urltest '{}' switch to '{}' was rolled back; the next "
                    "probe may retry it",
                    change.urltest_tag,
                    change.new_child_tag);
                const auto incident =
                    urltest_apply_incidents_.record_failure(
                        change.urltest_tag);
                if (incident.notify) {
                    log.error(
                        "Urltest '{}' could not converge after {} consecutive "
                        "probe rounds; the previous kernel route remains "
                        "active{}",
                        change.urltest_tag,
                        incident.consecutive_failures,
                        manager_synchronized
                            ? ""
                            : ", but the selector state also requires attention");
                }
            } catch (const std::exception& rollback_error) {
                log.info(
                    "Failed to restore routing/firewall after urltest '{}' "
                    "switch failure: {}",
                    change.urltest_tag,
                    rollback_error.what());
                try {
                    transition_runtime_or_throw(
                        RuntimeState::broken,
                        "urltest selection rollback failed");
                } catch (const std::exception& state_error) {
                    log.info(
                        "Failed to publish broken state after urltest rollback "
                        "failure: {}",
                        state_error.what());
                }
                const auto incident =
                    urltest_apply_incidents_.record_failure(
                        change.urltest_tag,
                        /*notify_immediately=*/true);
                if (incident.notify) {
                    log.error(
                        "Urltest '{}' could not restore the previously active "
                        "kernel route after a failed switch; routing requires "
                        "attention",
                        change.urltest_tag);
                }
            }
        }
        if (runtime_rebuilt && retired_mark.has_value()) {
            const uint32_t owned_mask =
                fwmark_mask_value(config_.fwmark.value_or(FwmarkConfig{}));
            const auto cleanup =
                conntrack_manager_.delete_mark(*retired_mark, owned_mask);
            if (cleanup == ConntrackCleanupResult::CommandUnavailable) {
                warn_conntrack_unavailable_once();
            } else if (cleanup == ConntrackCleanupResult::Failed) {
                log.info(
                    "Failed to remove conntrack entries for retired urltest "
                    "mark {:#x}/{:#x}; existing flows may stay on the previous "
                    "path until they expire",
                    *retired_mark,
                    owned_mask);
            }
        }
        // Publish the best live kernel state. On success this exposes the new
        // child; after a failed switch it exposes the restored applied child
        // (or the broken state when even rollback could not converge).
        publish_runtime_state();
    }, "urltest-selection-change:" + change.urltest_tag);
}

void Daemon::commit_urltest_probe_results(const std::string& urltest_tag,
                                          std::uint64_t probe_generation,
                                          std::map<std::string, URLTestResult> results,
                                          TraceId trace_id) {
    post_control_task(
        [this,
         urltest_tag,
         probe_generation,
         results = std::move(results),
         trace_id]() mutable {
            ScopedTraceContext trace_scope(trace_id);
            if (!urltest_manager_) {
                Logger::instance().trace("urltest_commit_skip",
                                         "tag={} generation={} reason=missing_manager",
                                         urltest_tag,
                                         probe_generation);
                return;
            }
            const bool selection_changed =
                urltest_manager_->commit_probe_results(urltest_tag,
                                                       probe_generation,
                                                       std::move(results));
            // A changed selection has a dedicated control task which first
            // reconciles the route and then publishes one coherent snapshot.
            // Unchanged latency/health results can be published immediately.
            if (!selection_changed) {
                publish_runtime_state();
            }
        },
        "urltest-commit:" + urltest_tag);
}

void Daemon::register_urltest_outbounds() {
    if (!urltest_manager_) {
        urltest_manager_ = std::make_unique<UrltestManager>(
            url_tester_,
            outbound_marks_,
            *scheduler_,
            blocking_executor_,
            [this](const UrltestSelectionChange& change) {
                handle_urltest_selection_change(
                    change,
                    runtime_generation_.load(std::memory_order_acquire));
            },
            [this](const std::string& urltest_tag,
                   std::uint64_t probe_generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId trace_id) mutable {
                Logger::instance().trace("urltest_commit_enqueue",
                                         "tag={} generation={}",
                                         urltest_tag,
                                         probe_generation);
                commit_urltest_probe_results(urltest_tag,
                                             probe_generation,
                                             std::move(results),
                                             trace_id);
            });
    }

    for (const auto& ob : config_.outbounds.value_or(std::vector<Outbound>{})) {
        if (ob.type == OutboundType::URLTEST) {
            const auto& selections =
                firewall_state_.get_urltest_selections();
            const auto retained = selections.find(ob.tag);
            urltest_manager_->register_urltest(
                ob,
                retained != selections.end() ? retained->second
                                             : std::string{});
        }
    }
}

void Daemon::probe_interfaces_now() {
    const auto outbounds = config_.outbounds.value_or(std::vector<Outbound>{});

    std::vector<InterfaceProbe::Target> targets;
    std::vector<std::string> known_tags;
    for (const auto& outbound : outbounds) {
        if (outbound.type != OutboundType::INTERFACE) {
            continue;
        }
        const auto mark_it = outbound_marks_.find(outbound.tag);
        if (mark_it == outbound_marks_.end()) {
            continue;
        }
        targets.push_back({outbound.tag, mark_it->second});
        known_tags.push_back(outbound.tag);
    }

    interface_probe_.retain_only(known_tags);

    if (targets.empty()) {
        return;
    }
    // Probing blocks on the network, so it must not run on the event loop.
    blocking_executor_.try_post("interface-probe", [this, targets]() {
        auto transitioned_tags = interface_probe_.probe(targets);
        post_control_task(
            [this, transitioned_tags = std::move(transitioned_tags)]() {
                if (urltest_manager_ && !transitioned_tags.empty()) {
                    const auto affected_urltests = find_affected_urltests(
                        config_.outbounds.value_or(std::vector<Outbound>{}),
                        transitioned_tags);
                    for (const auto& urltest_tag : affected_urltests) {
                        Logger::instance().trace(
                            "urltest_transition_probe",
                            "tag={} changed_children={}",
                            urltest_tag,
                            transitioned_tags.size());
                        urltest_manager_->trigger_immediate_test(urltest_tag);
                    }
                }
                if (routing_runtime_active_) {
                    // Keenetic may recreate a tunnel route without changing
                    // its administrative UP state. Reconcile the owned policy
                    // tables after the regular probe so vanished urltest
                    // fallback routes heal without a service restart.
                    reconcile_static_routing();
                }
#ifdef WITH_API
                if (status_stream_) {
                    status_stream_->reconcile();
                }
#endif
            },
            "interface-probe-status");
    });
}

void Daemon::schedule_catalog_refresh() {
#ifdef WITH_API
    // Once a day the scheduler asks; the refresh itself only downloads when the
    // cached copy is older than a week. Checking daily means a router that was
    // off for a while catches up promptly instead of waiting a full week.
    constexpr auto kInterval = std::chrono::hours(24);

    scheduler_->schedule_oneshot(
        kInterval,
        [this]() {
            // Resolve the detour on every run rather than caching it: the user
            // may have added the tunnel that finally reaches GitHub since the
            // last attempt.
            uint32_t mark = 0;
            const auto detour = catalog_detour();
            if (!detour.empty()) {
                const auto it = outbound_marks_.find(detour);
                if (it != outbound_marks_.end()) {
                    mark = it->second;
                }
            }
            blocking_executor_.try_post("catalog-refresh", [mark]() {
                refresh_catalog_if_stale(/*force=*/false, mark);
            });
            schedule_catalog_refresh();
        },
        "catalog-refresh");
#endif
}

void Daemon::schedule_interface_probe() {
    // Twenty seconds keeps the figure feeling live without turning every
    // tunnel into a permanent TLS handshake generator: each probe is a full
    // HTTPS request, and network latency does not change faster than this.
    constexpr auto kInterval = std::chrono::seconds(20);

    scheduler_->schedule_oneshot(
        kInterval,
        [this]() {
            probe_interfaces_now();
            schedule_interface_probe();
        },
        "interface-probe");
}

void Daemon::schedule_startup_firewall_retry(
    int attempt,
    std::optional<std::uint64_t> expected_generation) {
    // Backing off matters here: the contention that caused the failure is the
    // firmware settling after boot, and it clears on its own within seconds.
    constexpr int kMaxAttempts = 6;
    const auto delay = std::chrono::seconds{5 * attempt};
    const auto generation = expected_generation.value_or(
        runtime_generation_.load(std::memory_order_acquire));

    scheduler_->schedule_oneshot(
        delay,
        [this, attempt, generation]() {
            auto& log = Logger::instance();
            if (!runtime_recovery_is_current(
                    routing_runtime_active_,
                    generation,
                    runtime_generation_.load(std::memory_order_acquire))) {
                log.verbose(
                    "Discarding stale startup firewall recovery retry.");
                return;
            }
            try {
                const auto internal_vpn_resolution =
                    prepare_internal_vpn_server_resolution_from_cache();
                InternalVpnRuntimeGenerationTransaction
                    internal_vpn_generation(
                        resolved_internal_vpn_servers_,
                        internal_vpn_resolution.effective_servers);
                schedule_internal_vpn_catalog_refresh_if_needed(
                    internal_vpn_resolution.state);
                apply_firewall(FirewallApplyMode::PreserveSets);
                cleanup_owned_conntrack_marks(
                    "after delayed startup firewall activation");
                update_internal_vpn_verified_includes_lkg(
                    internal_vpn_resolution);
                internal_vpn_generation.commit();
                log.info("Firewall rules and routing applied on retry {}.", attempt);
            } catch (const TransientFirewallError& e) {
                if (attempt >= kMaxAttempts) {
                    log.error("Giving up on applying firewall rules after {} retries: {}",
                              attempt, e.what());
                    return;
                }
                log.info("Firewall retry {} failed: {}. Trying again.", attempt, e.what());
                schedule_startup_firewall_retry(attempt + 1, generation);
            } catch (const std::exception& e) {
                if (config_has_stable_internal_vpn_server_policy(config_) &&
                    attempt < kMaxAttempts) {
                    log.info(
                        "Stable native VPN generation retry {} failed: {}. "
                        "Keeping the previous generation and trying again.",
                        attempt,
                        e.what());
                    schedule_startup_firewall_retry(
                        attempt + 1, generation);
                } else {
                    log.error(
                        "Firewall recovery stopped after a permanent failure: {}",
                        e.what());
                }
            }
        },
        "startup-firewall-retry");

    Logger::instance().info("Firewall apply retry {} scheduled in {}s.",
                            attempt, delay.count());
}

void Daemon::schedule_lists_autoupdate() {
    if (!config_.lists_autoupdate) return;
    if (!config_.lists_autoupdate->enabled.value_or(false)) return;
    const auto& expr = config_.lists_autoupdate->cron.value_or("");
    auto next = cron_next(expr);
    const auto now = std::chrono::system_clock::now();
    auto delay = std::chrono::ceil<std::chrono::seconds>(next - now);
    if (delay.count() < 1) delay = std::chrono::seconds{1};
    lists_autoupdate_task_id_ = scheduler_->schedule_oneshot(
        delay,
        [this]() {
            refresh_lists_and_maybe_reload_async();
        },
        "lists-autoupdate");
    Logger::instance().info("Lists autoupdate scheduled (next: ~{}s)", delay.count());
}

ListsRefreshExecutionResult Daemon::execute_remote_list_refresh(
    const std::set<std::string>* target_lists,
    std::string_view source) {
    auto& log = Logger::instance();
    ListsRefreshExecutionResult result;
    const auto relevant_lists = collect_relevant_list_names(config_);
    const auto dns_relevant_lists = collect_dns_relevant_list_names(config_);
    {
        KPBR_SHARED_UNIQUE_LOCK(
            cache_write,
            resolver_cache_snapshot_mutex_);
        result.refresh_result =
            list_service_.refresh_remote_lists(
                config_,
                outbound_marks_,
                &relevant_lists,
                target_lists,
                &dns_relevant_lists);
    }

    if (!result.refresh_result.changed_lists.empty()) {
        log.info("Lists refresh ({}): updated list(s): {}", source,
                 format_list_names(result.refresh_result.changed_lists));
    } else if (!result.refresh_result.failed_lists.empty()) {
        log.warn("Lists refresh ({}): failed list(s): {}", source,
                 format_list_names(result.refresh_result.failed_lists));
    } else {
        log.info("Lists refresh ({}): all checked list(s) are up-to-date.", source);
    }

    if (should_reload_runtime_after_list_refresh(routing_runtime_active_, result.refresh_result)) {
        log.info("Lists refresh ({}): relevant list(s) changed ({}), reloading runtime",
                 source,
                 format_list_names(result.refresh_result.relevant_changed_lists));
        bool rolled_back = false;
        apply_config_with_rollback(config_, rolled_back, false);
        result.reloaded = true;
        return result;
    }

    if (result.refresh_result.any_relevant_changed()) {
        log.info("Lists refresh: relevant list(s) changed ({}), but runtime is stopped",
                 format_list_names(result.refresh_result.relevant_changed_lists));
    } else if (result.refresh_result.any_changed()) {
        log.info("Lists refresh: updated list(s) did not affect runtime config: {}",
                 format_list_names(result.refresh_result.changed_lists));
    } else if (result.refresh_result.any_failed()) {
        log.warn("Lists refresh: failed to refresh list(s): {}",
                 format_list_names(result.refresh_result.failed_lists));
    } else {
        log.info("Lists refresh: no list updates");
    }

    return result;
}

void Daemon::refresh_lists_and_maybe_reload() {
    auto& log = Logger::instance();
    log.info("Lists autoupdate: checking for updated lists");

    try {
        const auto result = execute_remote_list_refresh(nullptr, "autoupdate");
        if (!result.reloaded) {
            schedule_lists_autoupdate();
        }
    } catch (const std::exception& e) {
        log.error("Lists autoupdate failed: {}", e.what());
        schedule_lists_autoupdate();
    }
}

void Daemon::commit_lists_refresh_async_result(
    Config config_snapshot,
    bool runtime_active_snapshot,
    std::uint64_t generation,
    std::optional<RemoteListsRefreshResult> refresh_result,
    std::string error,
    std::string source,
    TraceId trace_id) {
    post_control_task(
        [this,
         config_snapshot = std::move(config_snapshot),
         runtime_active_snapshot,
         generation,
         refresh_result = std::move(refresh_result),
         error = std::move(error),
         source = std::move(source),
         trace_id]() mutable {
            ScopedTraceContext trace_scope_inner(trace_id);
            remote_list_refresh_inflight_.store(false, std::memory_order_release);

            if (generation != runtime_generation_.load(std::memory_order_acquire)) {
                Logger::instance().trace("lists_refresh_skip",
                                         "source={} generation={} reason=stale_runtime",
                                         source,
                                         generation);
                schedule_lists_autoupdate();
                return;
            }

            if (!error.empty()) {
                Logger::instance().error("Lists refresh ({}) failed: {}", source, error);
                schedule_lists_autoupdate();
                return;
            }

            ListsRefreshExecutionResult result;
            result.refresh_result = std::move(*refresh_result);

            if (!result.refresh_result.changed_lists.empty()) {
                Logger::instance().info("Lists refresh ({}): updated list(s): {}",
                                        source,
                                        format_list_names(result.refresh_result.changed_lists));
            } else if (!result.refresh_result.failed_lists.empty()) {
                Logger::instance().warn("Lists refresh ({}): failed list(s): {}",
                                        source,
                                        format_list_names(result.refresh_result.failed_lists));
            } else {
                Logger::instance().info(
                    "Lists refresh ({}): all checked list(s) are up-to-date.",
                    source);
            }

            if (should_reload_runtime_after_list_refresh(runtime_active_snapshot,
                                                        result.refresh_result)) {
                Logger::instance().info(
                    "Lists refresh ({}): relevant list(s) changed ({}), reloading runtime",
                    source,
                    format_list_names(result.refresh_result.relevant_changed_lists));
                try {
                    bool rolled_back = false;
                    apply_config_with_rollback(
                        config_snapshot, rolled_back, false);
                    result.reloaded = true;
                } catch (const std::exception& e) {
                    Logger::instance().error("Lists refresh ({}) reload failed: {}",
                                             source,
                                             e.what());
                    schedule_lists_autoupdate();
                    return;
                }
            } else if (result.refresh_result.any_relevant_changed()) {
                Logger::instance().info(
                    "Lists refresh: relevant list(s) changed ({}), but runtime is stopped",
                    format_list_names(result.refresh_result.relevant_changed_lists));
            } else if (result.refresh_result.any_changed()) {
                Logger::instance().info(
                    "Lists refresh: updated list(s) did not affect runtime config: {}",
                    format_list_names(result.refresh_result.changed_lists));
            } else if (result.refresh_result.any_failed()) {
                Logger::instance().warn("Lists refresh: failed to refresh list(s): {}",
                                        format_list_names(result.refresh_result.failed_lists));
            } else {
                Logger::instance().info("Lists refresh: no list updates");
            }

            if (!result.reloaded) {
                schedule_lists_autoupdate();
            }
        },
        "lists-refresh-commit");
}

void Daemon::refresh_lists_and_maybe_reload_async(std::string source) {
    auto& log = Logger::instance();
    log.info("Lists refresh ({}): checking for updates", source);

    bool expected = false;
    if (!remote_list_refresh_inflight_.compare_exchange_strong(expected,
                                                               true,
                                                               std::memory_order_acq_rel)) {
        Logger::instance().trace("lists_refresh_skip",
                                 "source={} reason=inflight",
                                 source);
        return;
    }

    const Config config_snapshot = config_;
    const OutboundMarkMap marks_snapshot = outbound_marks_;
    const bool runtime_active_snapshot = routing_runtime_active_;
    const auto relevant_lists = collect_relevant_list_names(config_snapshot);
    const auto dns_relevant_lists = collect_dns_relevant_list_names(config_snapshot);
    const auto generation = runtime_generation_.load(std::memory_order_acquire);
    const TraceId trace_id = ensure_trace_id();
    const std::string executor_label = "lists-refresh-" + source;

    const bool enqueued = blocking_executor_.try_post(
        executor_label,
        [this,
         config_snapshot,
         marks_snapshot,
         runtime_active_snapshot,
         relevant_lists,
         dns_relevant_lists,
         generation,
         source,
         trace_id]() mutable {
            ScopedTraceContext trace_scope(trace_id);
            std::optional<RemoteListsRefreshResult> refresh_result;
            std::string error;

            Logger::instance().trace("lists_refresh_start",
                                     "source={} generation={}",
                                     source,
                                     generation);
            try {
                {
                    KPBR_SHARED_UNIQUE_LOCK(
                        cache_write,
                        resolver_cache_snapshot_mutex_);
                    refresh_result = list_service_.refresh_remote_lists(
                        config_snapshot,
                        marks_snapshot,
                        &relevant_lists,
                        nullptr,
                        &dns_relevant_lists);
                }
            } catch (const std::exception& e) {
                error = e.what();
            }

            commit_lists_refresh_async_result(config_snapshot,
                                              runtime_active_snapshot,
                                              generation,
                                              std::move(refresh_result),
                                              std::move(error),
                                              std::move(source),
                                              trace_id);
        },
        trace_id);

    if (!enqueued) {
        remote_list_refresh_inflight_.store(false, std::memory_order_release);
        Logger::instance().trace("lists_refresh_skip",
                                 "source={} reason=executor_unavailable",
                                 source);
        schedule_lists_autoupdate();
    }
}

PreparedRuntimeInputs Daemon::prepare_runtime_inputs(const Config& config,
                                                     RemoteListPreparationMode list_mode) {
    TraceSpan span("prepare-runtime-inputs");
    validate_config(config);

    PreparedRuntimeInputs prepared;
    prepared.config = config;
    prepared.outbound_marks = allocate_outbound_marks(
        config.fwmark.value_or(FwmarkConfig{}),
        config.outbounds.value_or(std::vector<Outbound>{}));
    const bool preparing_on_control_loop =
        event_loop_active_.load(std::memory_order_acquire) &&
        is_event_loop_thread();
    prepared.internal_vpn_resolution =
        resolve_internal_vpn_servers_for_runtime(
            config,
            !preparing_on_control_loop,
            snapshot_internal_vpn_verified_includes_lkg());

    if (list_mode != RemoteListPreparationMode::None) {
        KPBR_SHARED_UNIQUE_LOCK(
            cache_write,
            resolver_cache_snapshot_mutex_);
        if (list_mode == RemoteListPreparationMode::MissingOrInvalid) {
            const auto result = list_service_.download_uncached(
                prepared.config,
                prepared.outbound_marks);
            std::vector<std::string> unavailable_lists;
            for (const auto& name : result.failed_lists) {
                if (!prepared.config.lists) {
                    unavailable_lists.push_back(name);
                    continue;
                }
                const auto list = prepared.config.lists->find(name);
                if (list == prepared.config.lists->end() ||
                    !list->second.url.has_value() ||
                    !list_service_.cache_manager().has_current_cache(
                        name, *list->second.url)) {
                    unavailable_lists.push_back(name);
                }
            }
            if (!unavailable_lists.empty()) {
                throw DaemonError(
                    "Remote list cache is unavailable for the current source: " +
                    format_list_names(unavailable_lists));
            }
        } else {
            (void)list_service_.refresh_remote_lists(
                prepared.config,
                prepared.outbound_marks);
        }
        prepared.remote_lists_refreshed = true;
    }

    return prepared;
}

InternalVpnRuntimeResolution
Daemon::resolve_internal_vpn_servers_for_runtime(
    const Config& config,
    bool allow_catalog_refresh,
    const std::vector<InternalVpnServer>& previous_effective) {
    const auto configured = config.route.has_value()
        ? config.route->internal_vpn_servers.value_or(
              std::vector<InternalVpnServer>{})
        : std::vector<InternalVpnServer>{};
    if (configured.empty()) {
        return {
            {},
            InternalVpnRuntimeResolutionState::verified,
        };
    }
    if (!internal_vpn_server_policies_require_ndms_catalog(configured)) {
        // Legacy exact-interface policies only need the live netlink
        // inventory. Do not add an RCI HTTP timeout to cross-platform startup.
        return resolve_internal_vpn_servers_for_runtime(
            config,
            NdmsCatalogSnapshot{},
            previous_effective);
    }

    auto& cache = shared_ndms_catalog_cache();
    const auto snapshot =
        allow_catalog_refresh ? cache.force_refresh() : cache.peek();
    return resolve_internal_vpn_servers_for_runtime(
        config,
        snapshot,
        previous_effective);
}

InternalVpnRuntimeResolution
Daemon::resolve_internal_vpn_servers_for_runtime(
    const Config& config,
    const NdmsCatalogSnapshot& snapshot,
    const std::vector<InternalVpnServer>& previous_effective) {
    const auto configured = config.route.has_value()
        ? config.route->internal_vpn_servers.value_or(
              std::vector<InternalVpnServer>{})
        : std::vector<InternalVpnServer>{};
    if (configured.empty()) {
        return {
            {},
            InternalVpnRuntimeResolutionState::verified,
        };
    }

    std::vector<std::string> runtime_interface_names;
    for (const auto& interface : netlink_.dump_interfaces()) {
        runtime_interface_names.push_back(interface.name);
    }

    auto resolution = resolve_internal_vpn_server_policies(
        configured,
        snapshot.catalog,
        snapshot.status == NdmsCatalogCacheStatus::fresh,
        runtime_interface_names);

    if (!resolution.complete()) {
        std::string detail;
        for (const auto& issue : resolution.issues) {
            if (!detail.empty()) detail += "; ";
            detail += describe_internal_vpn_server_resolution_issue(issue);
        }
        auto generation = select_internal_vpn_server_generation(
            configured, resolution, previous_effective);
        if (!generation.usable()) {
            throw DaemonError(
                "Native VPN server policy has no verified runtime generation: " +
                detail);
        }
        if (generation.source ==
            InternalVpnServerGenerationSource::retained_previous) {
            Logger::instance().info(
                "Native VPN server inventory is temporarily inconclusive; "
                "retaining previously verified include-only bindings while "
                "dropping every unverified bypass: {}",
                detail);
        } else {
            Logger::instance().warn(
                "Native VPN server inventory is incomplete; continuing with "
                "a conservative degraded policy (unverified bypasses are "
                "disabled; an unresolved included server may be temporarily "
                "outside keen-pbr processing): {}",
                detail);
        }
        const bool authoritative_negative = std::any_of(
            resolution.issues.begin(),
            resolution.issues.end(),
            [](const InternalVpnServerResolutionIssue& issue) {
                return issue.error !=
                       InternalVpnServerResolutionError::
                           catalog_not_authoritative;
            });
        return {
            std::move(generation.effective_servers),
            authoritative_negative
                ? InternalVpnRuntimeResolutionState::
                      authoritative_negative
                : generation.source ==
                          InternalVpnServerGenerationSource::
                              retained_previous
                    ? InternalVpnRuntimeResolutionState::
                          retained_verified_includes
                    : InternalVpnRuntimeResolutionState::degraded,
            std::move(resolution.verified_includes_for_lkg),
            std::move(resolution.retain_verified_include_ndms_ids),
        };
    }
    return {
        std::move(resolution.effective_servers),
        InternalVpnRuntimeResolutionState::verified,
        std::move(resolution.verified_includes_for_lkg),
        std::move(resolution.retain_verified_include_ndms_ids),
    };
}

std::vector<InternalVpnServer>
Daemon::snapshot_internal_vpn_verified_includes_lkg() const {
    KPBR_LOCK_GUARD(internal_vpn_lkg_mutex_);
    return internal_vpn_verified_includes_lkg_;
}

void Daemon::update_internal_vpn_verified_includes_lkg(
    const InternalVpnRuntimeResolution& resolution) noexcept {
    try {
        if (resolution.state !=
                InternalVpnRuntimeResolutionState::verified &&
            resolution.state !=
                InternalVpnRuntimeResolutionState::authoritative_negative) {
            return;
        }
        KPBR_LOCK_GUARD(internal_vpn_lkg_mutex_);
        internal_vpn_verified_includes_lkg_ =
            merge_internal_vpn_verified_includes_lkg(
                internal_vpn_verified_includes_lkg_,
                resolution.verified_includes_for_lkg,
                resolution.retain_verified_include_ndms_ids);
    } catch (const std::exception& error) {
        try {
            Logger::instance().warn(
                "Could not publish native VPN verified-binding cache: {}. "
                "The committed runtime generation remains active.",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().warn(
                "Could not publish native VPN verified-binding cache. "
                "The committed runtime generation remains active.");
        } catch (...) {
        }
    }
}

InternalVpnRuntimeResolution
Daemon::prepare_internal_vpn_server_resolution_from_cache() {
    return resolve_internal_vpn_servers_for_runtime(
        config_,
        false,
        snapshot_internal_vpn_verified_includes_lkg());
}

void Daemon::schedule_internal_vpn_catalog_refresh() {
    const auto configured = config_.route.has_value()
        ? config_.route->internal_vpn_servers.value_or(
              std::vector<InternalVpnServer>{})
        : std::vector<InternalVpnServer>{};
    const bool has_stable_identity = std::any_of(
        configured.begin(),
        configured.end(),
        [](const InternalVpnServer& server) {
            return server.ndms_id.has_value();
        });
    if (!has_stable_identity) {
        return;
    }
    if (!internal_vpn_catalog_refresh_gate_.request()) {
        return;
    }

    const bool enqueued = blocking_executor_.try_post(
        "internal-vpn-ndms-refresh",
        [this]() {
            // force_refresh() is single-flight and rate-limited by the cache;
            // this worker is the only place where an interface event may lead
            // to loopback RCI/network I/O.
            auto snapshot =
                shared_ndms_catalog_cache().force_refresh();
            post_control_task(
                [this, worker_snapshot = std::move(snapshot)]() {
                    // Finish the single-flight generation only on the control
                    // loop. A topology event observed while the worker was
                    // blocked becomes one immediate replacement generation;
                    // no invalidation is dropped and no parallel RCI fetch is
                    // started.
                    const bool rerun_requested =
                        internal_vpn_catalog_refresh_gate_.complete();
                    const bool rerun_is_valid =
                        rerun_requested &&
                        routing_runtime_active_ &&
                        config_has_stable_internal_vpn_server_policy(config_);
                    if (rerun_is_valid) {
                        schedule_internal_vpn_catalog_refresh();
                    }

                    if (!routing_runtime_active_ ||
                        !config_has_stable_internal_vpn_server_policy(
                            config_)) {
                        return;
                    }
                    if (worker_snapshot.status !=
                            NdmsCatalogCacheStatus::fresh ||
                        !worker_snapshot.refreshed) {
                        if (!rerun_is_valid) {
                            schedule_internal_vpn_catalog_refresh_retry(
                                runtime_generation_.load(
                                    std::memory_order_acquire));
                        }
                        return;
                    }
                    // Re-read the shared cache on the control loop. Another
                    // interface event may have invalidated the worker's
                    // successful observation before this commit ran. The
                    // cache-only snapshot also makes this commit valid after
                    // a concurrent API apply changed runtime_generation_: it
                    // resolves the current config, never the worker's old one.
                    const auto snapshot =
                        shared_ndms_catalog_cache().peek();
                    if (snapshot.status !=
                        NdmsCatalogCacheStatus::fresh) {
                        if (!rerun_is_valid) {
                            schedule_internal_vpn_catalog_refresh_retry(
                                runtime_generation_.load(
                                    std::memory_order_acquire));
                        }
                        return;
                    }
                    cancel_internal_vpn_catalog_refresh_retry();
                    auto resolution =
                        resolve_internal_vpn_servers_for_runtime(
                            config_,
                            snapshot,
                            snapshot_internal_vpn_verified_includes_lkg());
                    const bool changed =
                        !same_internal_vpn_runtime_servers(
                            resolved_internal_vpn_servers_,
                            resolution.effective_servers);
                    if (!changed) {
                        // No kernel replacement is needed, so publishing the
                        // newly verified LKG cannot diverge from forwarding.
                        update_internal_vpn_verified_includes_lkg(
                            resolution);
                        publish_runtime_state();
                        return;
                    }
                    // Do not publish candidate resolved/LKG state here. Pass
                    // the prepared authoritative observation into the sole
                    // generation transaction: it commits memory only after
                    // route/firewall succeeds and restores the previous map
                    // on every failure path.
                    refresh_iproute_and_firewall_runtime(
                        0, std::move(resolution));
                },
                "internal-vpn-ndms-refresh-commit");
        });
    if (!enqueued) {
        const bool rerun_requested =
            internal_vpn_catalog_refresh_gate_.complete();
        Logger::instance().verbose(
            "Skipping native VPN NDMS refresh because the blocking executor "
            "is unavailable");
        if (rerun_requested &&
            routing_runtime_active_ &&
            config_has_stable_internal_vpn_server_policy(config_)) {
            schedule_internal_vpn_catalog_refresh();
            return;
        }
        schedule_internal_vpn_catalog_refresh_retry(
            runtime_generation_.load(std::memory_order_acquire));
    }
}

void Daemon::schedule_internal_vpn_catalog_refresh_if_needed(
    InternalVpnRuntimeResolutionState state) {
    // Central lifecycle invariant: no cache-only, non-authoritative stable-ID
    // generation may remain active without a pending authoritative refresh.
    // The helper is deliberately a no-op before activation so failed starts do
    // not leave workers targeting a runtime that never committed.
    if (!routing_runtime_active_ ||
        !internal_vpn_resolution_requires_catalog_refresh(config_, state)) {
        return;
    }
    schedule_internal_vpn_catalog_refresh();
}

void Daemon::schedule_internal_vpn_catalog_refresh_retry(
    std::uint64_t runtime_generation) {
    if (!scheduler_ ||
        internal_vpn_catalog_refresh_retry_task_id_ >= 0 ||
        !runtime_recovery_is_current(
            routing_runtime_active_,
            runtime_generation,
            runtime_generation_.load(std::memory_order_acquire))) {
        return;
    }

    const auto delay = INTERNAL_VPN_CATALOG_RETRY_DELAYS[
        std::min(
            internal_vpn_catalog_refresh_retry_attempt_,
            INTERNAL_VPN_CATALOG_RETRY_DELAYS.size() - 1)];
    ++internal_vpn_catalog_refresh_retry_attempt_;
    internal_vpn_catalog_refresh_retry_task_id_ =
        scheduler_->schedule_oneshot(
            delay,
            [this, runtime_generation]() {
                internal_vpn_catalog_refresh_retry_task_id_ = -1;
                if (!runtime_recovery_is_current(
                        routing_runtime_active_,
                        runtime_generation,
                        runtime_generation_.load(
                            std::memory_order_acquire))) {
                    return;
                }
                schedule_internal_vpn_catalog_refresh();
            },
            "internal-vpn-ndms-refresh-retry");
}

void Daemon::cancel_internal_vpn_catalog_refresh_retry() {
    internal_vpn_catalog_refresh_retry_attempt_ = 0;
    if (!scheduler_ ||
        internal_vpn_catalog_refresh_retry_task_id_ < 0) {
        return;
    }
    scheduler_->cancel(internal_vpn_catalog_refresh_retry_task_id_);
    internal_vpn_catalog_refresh_retry_task_id_ = -1;
}

void Daemon::cancel_resolver_reload_retry() {
    if (resolver_reload_retry_task_id_ < 0) {
        return;
    }
    scheduler_->cancel(resolver_reload_retry_task_id_);
    resolver_reload_retry_task_id_ = -1;
}

void Daemon::schedule_resolver_reload_retry(
    std::size_t attempt,
    std::uint64_t runtime_generation) {
    if (resolver_reload_retry_task_id_ >= 0 ||
        attempt >= RESOLVER_RELOAD_RETRY_DELAYS.size()) {
        return;
    }

    const auto delay = RESOLVER_RELOAD_RETRY_DELAYS[attempt];
    resolver_reload_retry_task_id_ = scheduler_->schedule_oneshot(
        delay,
        [this, attempt, runtime_generation]() {
            resolver_reload_retry_task_id_ = -1;
            if (!routing_runtime_active_ ||
                runtime_generation !=
                    runtime_generation_.load(std::memory_order_acquire)) {
                Logger::instance().verbose(
                    "Discarding stale resolver reload recovery retry.");
                return;
            }

            bool reloaded = false;
            try {
                update_resolver_config_hash();
                reloaded = run_system_resolver_hook_reload();
            } catch (const std::exception& error) {
                Logger::instance().info(
                    "Resolver reload recovery attempt {} failed: {}",
                    attempt + 1,
                    error.what());
            }
            if (reloaded) {
                refresh_resolver_config_hash_actual_async();
                publish_runtime_state();
                Logger::instance().info(
                    "Resolver reload recovered after committed runtime "
                    "replacement.");
                return;
            }

            if (attempt + 1 < RESOLVER_RELOAD_RETRY_DELAYS.size()) {
                schedule_resolver_reload_retry(
                    attempt + 1, runtime_generation);
            } else {
                Logger::instance().error(
                    "Resolver reload did not recover after {} bounded "
                    "attempts; routing remains active but DNS needs attention.",
                    RESOLVER_RELOAD_RETRY_DELAYS.size());
                refresh_resolver_config_hash_actual_async();
                publish_runtime_state();
            }
        },
        "resolver-reload-recovery");
    Logger::instance().info(
        "Resolver reload recovery attempt {} scheduled in {}s.",
        attempt + 1,
        delay.count());
}

void Daemon::apply_prepared_runtime_inputs(PreparedRuntimeInputs prepared) {
    if (event_loop_active_.load(std::memory_order_acquire) && !is_event_loop_thread()) {
        throw DaemonError("apply_prepared_runtime_inputs must run on the control/event-loop thread");
    }

    // Preparing an API save runs outside the control loop. An interface event
    // may invalidate the NDMS catalog after preparation but before this queued
    // apply starts. Re-resolve from the cache-only snapshot on the serialized
    // control loop so an old prepared process_clients=false binding can never
    // reintroduce a bypass after its identity lost authority.
    if (config_has_stable_internal_vpn_server_policy(prepared.config)) {
        prepared.internal_vpn_resolution =
            resolve_internal_vpn_servers_for_runtime(
                prepared.config,
                false,
                snapshot_internal_vpn_verified_includes_lkg());
    }
    transition_runtime_or_throw(RuntimeState::applying, "configuration apply started");
    publish_runtime_state();

    try {
    runtime_generation_.fetch_add(1, std::memory_order_acq_rel);
    cancel_runtime_firewall_retry();
    cancel_resolver_reload_retry();
    cancel_internal_vpn_catalog_refresh_retry();

    if (lists_autoupdate_task_id_ >= 0) {
        scheduler_->cancel(lists_autoupdate_task_id_);
        lists_autoupdate_task_id_ = -1;
    }
    if (keenetic_dns_refresh_task_id_ >= 0) {
        scheduler_->cancel(keenetic_dns_refresh_task_id_);
        keenetic_dns_refresh_task_id_ = -1;
    }
    if (resolver_config_hash_actual_task_id_ >= 0) {
        scheduler_->cancel(resolver_config_hash_actual_task_id_);
        resolver_config_hash_actual_task_id_ = -1;
    }
    // The effective vector is moved into the active runtime below. Keep the
    // small verified-resolution value intact until the complete staged apply
    // succeeds, otherwise publishing the LKG after the move would
    // accidentally clear it.
    const auto internal_vpn_lkg_update =
        prepared.internal_vpn_resolution;
    outbound_marks_ = std::move(prepared.outbound_marks);
    resolved_internal_vpn_servers_ =
        std::move(
            prepared.internal_vpn_resolution.effective_servers);
    config_ = std::move(prepared.config);
    firewall_state_.set_outbound_marks(outbound_marks_);
    firewall_state_.set_fwmark_mask(fwmark_mask_value(config_.fwmark.value_or(FwmarkConfig{})));
    normalize_urltest_selections();

    teardown_dns_probe();

    if (urltest_manager_) {
        urltest_manager_->clear();
    }
    urltest_apply_incidents_.clear();
    // Reconcile in place: install replacement routes/rules before removing
    // obsolete owned state. Clearing first creates a visible traffic gap on
    // every configuration save and makes failover briefly lose its path.
    reconcile_static_routing();
    register_urltest_outbounds();
    (void)refresh_keenetic_dns_cache(true);
    retry_hot_apply_firewall(
        [this]() {
            // apply_firewall rebuilds the complete pending transaction on
            // every call. A retry therefore never reuses the one-shot backend
            // state from the failed attempt.
            apply_firewall(FirewallApplyMode::PreserveSets);
        },
        [](std::chrono::milliseconds delay) {
            std::this_thread::sleep_for(delay);
        },
        [](std::size_t retry,
           std::chrono::milliseconds delay,
           const TransientFirewallError& error) {
            Logger::instance().info(
                "Hot configuration firewall apply deferred after a "
                "concurrent firmware change: {}. Retry {} in {}ms.",
                error.what(),
                retry,
                delay.count());
        });
    schedule_keenetic_dns_refresh();
    schedule_lists_autoupdate();
    update_resolver_config_hash();
    setup_dns_probe();
    const auto resolver_snapshot =
        resolver_sync_.snapshot(unix_timestamp_now_seconds());
    if (resolver_reload_required(resolver_snapshot.expected_hash,
                                 resolver_snapshot.actual_hash,
                                 resolver_snapshot.live_status)) {
        if (!run_system_resolver_hook_reload()) {
            throw DaemonError(
                "system resolver reload did not complete its configuration stream");
        }
    } else {
        Logger::instance().info(
            "Skipping dnsmasq reload: resolver configuration is unchanged and healthy");
    }
    refresh_resolver_config_hash_actual_async();
    // Publish the new LKG only after every routing/firewall/resolver phase has
    // succeeded. A failed staged apply must leave the active generation's LKG
    // intact for rollback preparation.
    update_internal_vpn_verified_includes_lkg(
        internal_vpn_lkg_update);
    config_store_.replace_active(config_, outbound_marks_);
#ifdef WITH_API
    refresh_interface_traffic_config_targets(config_);
#endif
    routing_runtime_active_ = true;
    schedule_internal_vpn_catalog_refresh_if_needed(
        internal_vpn_lkg_update.state);
    transition_runtime_or_throw(RuntimeState::running, "configuration apply complete");
    publish_runtime_state();
    } catch (...) {
        routing_runtime_active_ = false;
        try {
            transition_runtime_or_throw(RuntimeState::broken, "configuration apply failed");
            publish_runtime_state();
        } catch (const std::exception& state_error) {
            Logger::instance().error(
                "Failed to publish broken runtime state after config apply: {}",
                state_error.what());
        }
        throw;
    }
}

void Daemon::apply_config(Config config, bool refresh_remote_lists) {
    if (event_loop_active_.load(std::memory_order_acquire) && !is_event_loop_thread()) {
        throw DaemonError("apply_config must run on the control/event-loop thread");
    }

    apply_prepared_runtime_inputs(prepare_runtime_inputs(
        config,
        refresh_remote_lists ? RemoteListPreparationMode::RefreshAll
                             : RemoteListPreparationMode::None));
}

void Daemon::apply_config_with_rollback(const Config& next_config,
                                        bool& rolled_back,
                                        bool refresh_remote_lists) {
    Config previous_config = config_;

    try {
        apply_config(next_config, refresh_remote_lists);
        rolled_back = false;
    } catch (...) {
        try {
            apply_config(previous_config, false);
            rolled_back = true;
            Logger::instance().warn(
                "Configuration apply failed; previous runtime was restored");
        } catch (const std::exception& rollback_error) {
            Logger::instance().error("Rollback to previous config failed: {}", rollback_error.what());
            rolled_back = false;
        } catch (...) {
            Logger::instance().error("Rollback to previous config failed: unknown error");
            rolled_back = false;
        }
        throw;
    }
}

void Daemon::reload_from_disk() {
    std::ifstream ifs(config_path_);
    if (!ifs.is_open()) {
        throw DaemonError("Cannot open config file: " + config_path_);
    }

    std::ostringstream ss;
    ss << ifs.rdbuf();
    Config next_config = parse_config(ss.str());
    validate_config(next_config);
    bool rolled_back = false;
    apply_config_with_rollback(next_config, rolled_back);
}

} // namespace keen_pbr3
