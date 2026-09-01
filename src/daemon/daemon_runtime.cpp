#include "daemon.hpp"
#include "runtime_firewall_operation_owner.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <future>
#include <iterator>
#include <map>
#include <set>
#include <thread>
#include <unistd.h>

#include "../config/routing_state.hpp"
#include "../firewall/firewall.hpp"
#include "../firewall/firewall_runtime.hpp"
#include "../keenetic/internal_vpn_ingress_resolver.hpp"
#include "../keenetic/internal_vpn_server_resolver.hpp"
#include "../keenetic/internal_vpn_service_resolver.hpp"
#include "../keenetic/internal_vpn_runtime_generation.hpp"
#include "../keenetic/ndms_catalog_cache.hpp"
#include "../keenetic/ndms_vpn_server_service_cache.hpp"
#include "../log/logger.hpp"
#include "../routing/urltest_manager.hpp"
#include "../runtime/meta_udp_443_policy.hpp"
#include "../runtime/meta_udp_443_activation_contract.hpp"
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
constexpr auto RESOLVER_RELOAD_MAINTENANCE_DELAY =
    std::chrono::seconds{60};
constexpr std::size_t OWNED_CONNTRACK_CLEANUP_RETRY_BATCH_SIZE = 4U;
constexpr auto OWNED_CONNTRACK_CLEANUP_RETRY_BUDGET =
    std::chrono::milliseconds{750};
constexpr auto IDLE_STALL_ACTIVE_SCAN_INTERVAL =
    std::chrono::seconds{5};
constexpr auto IDLE_STALL_QUIET_SCAN_INTERVAL =
    std::chrono::seconds{30};
// The exact reset rule must outlive the conntrack delete long enough to catch
// the client's next retransmit, but it must never become persistent policy.
constexpr auto EXPERIMENTAL_TCP_RESET_RULE_TTL =
    std::chrono::seconds{7};
constexpr std::array<std::chrono::milliseconds, 3>
    EXPERIMENTAL_TCP_RESET_CLEANUP_RETRY_DELAYS{
        std::chrono::seconds{1},
        std::chrono::seconds{2},
        std::chrono::seconds{4},
    };
constexpr auto EXPERIMENTAL_TCP_RESET_CLEANUP_MAINTENANCE_DELAY =
    std::chrono::seconds{30};
// Catalog presence alone uses a moderate discovery cadence. Once matching
// traffic appears, the existing five-second active cadence takes over; this
// avoids a permanent high-frequency conntrack parse on otherwise idle routers.
constexpr auto UDP_CALL_AFFINITY_DISCOVERY_SCAN_INTERVAL =
    std::chrono::seconds{10};
constexpr auto UDP_CALL_AFFINITY_FAST_SCAN_INTERVAL =
    std::chrono::seconds{2};
constexpr auto UDP_CALL_AFFINITY_MUTATION_DEADLINE =
    std::chrono::seconds{10};
constexpr std::size_t IDLE_STALL_MAX_FLOWS = 256U;
constexpr std::size_t IDLE_STALL_MAX_DESTINATION_CIDRS = 1024U;
constexpr std::size_t IDLE_STALL_MAX_SNAPSHOT_BYTES =
    2U * 1024U * 1024U;
constexpr std::size_t IDLE_STALL_MAX_SNAPSHOT_LINES = 8192U;
constexpr std::uint64_t IDLE_STALL_APPLICATION_REPLY_BYTES = 256U;
constexpr std::size_t META_UDP443_ACTIVATION_BATCH_SIZE = 4U;
constexpr auto META_UDP443_ACTIVATION_BATCH_BUDGET =
    std::chrono::seconds{4};
constexpr std::array<std::chrono::seconds, 3>
    META_UDP443_ACTIVATION_RETRY_DELAYS{
        std::chrono::seconds{1},
        std::chrono::seconds{2},
        std::chrono::seconds{5},
    };
constexpr auto META_UDP443_ACTIVATION_MAINTENANCE_RETRY_DELAY =
    std::chrono::minutes{1};

void require_authoritative_runtime_routing(
    const RuntimeRoutingInventorySnapshotPtr& inventory,
    const char* operation) {
    const auto authority =
        classify_runtime_routing_inventory(inventory);
    if (authority == RuntimeRoutingInventoryAuthority::authoritative) {
        return;
    }

    const char* reason = "routing inventory is missing";
    if (authority ==
        RuntimeRoutingInventoryAuthority::inventory_incomplete) {
        reason = "routing inventory publication is incomplete";
    } else if (
        authority ==
        RuntimeRoutingInventoryAuthority::kernel_state_unknown) {
        reason = "routing kernel state is not proven";
    }
    throw TransientFirewallError(
        std::string(operation != nullptr ? operation : "routing") +
        " remains pending: " + reason);
}

ConntrackFlowObservationOptions idle_stall_observation_options(
    bool ipv6_enabled,
    bool packaged_whatsapp_only) {
    ConntrackFlowObservationOptions options;
    options.ipv6_enabled = ipv6_enabled;
    options.max_flows = IDLE_STALL_MAX_FLOWS;
    options.max_destination_input_cidrs =
        IDLE_STALL_MAX_DESTINATION_CIDRS;
    options.max_snapshot_bytes = IDLE_STALL_MAX_SNAPSHOT_BYTES;
    options.max_snapshot_lines = IDLE_STALL_MAX_SNAPSHOT_LINES;
    options.allow_foreign_mark_bits_for_media = true;
    if (packaged_whatsapp_only) {
        // Filter both views before they claim the shared flow budget. This is
        // the common office path: unrelated Meta sessions cannot make the
        // exact TCP/443 candidate first-N dependent, while UDP/443 and the
        // derived source-wide view still protect active media.
        options.ordinary_tcp_destination_port = 443U;
        options.media_seed_destination_port = 443U;
    }
    return options;
}

std::vector<InterfaceProbe::Target> collect_interface_probe_targets(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    std::vector<std::string>* known_tags = nullptr) {
    std::vector<InterfaceProbe::Target> targets;
    for (const auto& outbound :
         config.outbounds.value_or(std::vector<Outbound>{})) {
        if (outbound.type != OutboundType::INTERFACE) {
            continue;
        }
        const auto mark_it = outbound_marks.find(outbound.tag);
        if (mark_it == outbound_marks.end()) {
            continue;
        }
        targets.push_back({outbound.tag,
                           mark_it->second,
                           outbound.interface.value_or(std::string())});
        if (known_tags != nullptr) {
            known_tags->push_back(outbound.tag);
        }
    }
    return targets;
}

std::vector<std::string> local_interface_addresses_from(
    const std::vector<DumpedInterface>& interfaces) {
    std::vector<std::string> addresses;
    for (const auto& interface : interfaces) {
        addresses.insert(addresses.end(),
                         interface.ipv4_addresses.begin(),
                         interface.ipv4_addresses.end());
        addresses.insert(addresses.end(),
                         interface.ipv6_addresses.begin(),
                         interface.ipv6_addresses.end());
    }
    std::sort(addresses.begin(), addresses.end());
    addresses.erase(
        std::unique(addresses.begin(), addresses.end()),
        addresses.end());
    return addresses;
}

IdleStallFlowKey idle_stall_key_from(
    const ConntrackExactForwardedFlow& flow) {
    return IdleStallFlowKey{
        flow.family == ConntrackFlowFamily::Ipv6
            ? IdleStallAddressFamily::ipv6
            : IdleStallAddressFamily::ipv4,
        flow.protocol == ConntrackFlowProtocol::Udp
            ? IdleStallProtocol::udp
            : IdleStallProtocol::tcp,
        flow.source,
        flow.destination,
        flow.source_port,
        flow.destination_port,
        flow.mark};
}

IdleStallFlowSample idle_stall_sample_from(
    const ConntrackExactForwardedFlow& flow,
    IdleStallRecoveryPolicy recovery_policy =
        IdleStallRecoveryPolicy::standard) {
    IdleStallFlowReadiness readiness =
        IdleStallFlowReadiness::ineligible;
    if (flow.protocol == ConntrackFlowProtocol::Tcp &&
        flow.tcp_state == ConntrackTcpState::Established) {
        readiness = IdleStallFlowReadiness::tcp_established;
    } else if (flow.protocol == ConntrackFlowProtocol::Udp &&
               flow.assured) {
        readiness = IdleStallFlowReadiness::udp_assured;
    }
    return IdleStallFlowSample{
        idle_stall_key_from(flow),
        IdleStallFlowCounters{
            flow.original.packets,
            flow.original.bytes,
            flow.reply.packets,
            flow.reply.bytes},
        readiness,
        flow.fastnat,
        recovery_policy};
}

struct IdleStallPendingDelete {
    IdleStallDeleteDecision decision;
    ConntrackExactForwardedFlow flow;
};

enum class UdpCallAffinityRevalidationMode {
    BeforePublication,
    RefreshBeforePublication,
    AfterPublication,
};

bool same_forwarded_five_tuple(
    const ConntrackExactForwardedFlow& left,
    const ConntrackExactForwardedFlow& right) noexcept {
    return left.family == right.family &&
           left.protocol == right.protocol &&
           left.source == right.source &&
           left.destination == right.destination &&
           left.source_port == right.source_port &&
           left.destination_port == right.destination_port;
}

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

} // namespace

bool Daemon::fastnat_is_disabled_or_unavailable() {
    return system_fastnat_is_disabled_or_unavailable();
}

bool Daemon::run_system_resolver_hook(std::string_view action,
                                      bool manage_ipc_gate,
                                      std::string_view attempt_id) {
    auto& log = Logger::instance();

    const auto args =
        build_system_resolver_hook_args(active_config_snapshot_->config, action, attempt_id);
    if (args.empty()) {
        return true;
    }

    std::string command;
    for (std::size_t index = 0; index < args.size(); ++index) {
        if (index != 0) command += ' ';
        command += index == 2 ? "<resolver-attempt>" : args[index];
    }

    auto execute_hook = [this, args] {
        KPBR_LOCK_GUARD(system_resolver_hook_mutex_);
        return hook_command_executor_(args);
    };

    std::optional<ResolverIpcGate> gate;
    if (manage_ipc_gate) {
        gate.emplace(resolver_stream_attempt_owner_);
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
            handle_ipc_control_requests();
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
    if (build_system_resolver_hook_args(active_config_snapshot_->config, action).empty()) {
        return true;
    }

    return run_system_resolver_hook_stream_prepared(
        action, /*rebuild_snapshot=*/true);
}

bool Daemon::run_system_resolver_hook_stream_prepared(
    std::string_view action,
    bool rebuild_snapshot,
    bool inactive_activation_authority) {
    if (build_system_resolver_hook_args(active_config_snapshot_->config, action).empty()) {
        return true;
    }

    if (rebuild_snapshot) {
        update_resolver_config_hash();
    }
    if (!resolver_generation_snapshot_) {
        Logger::instance().error(
            "Cannot stream a committed resolver generation: snapshot is unavailable");
        return false;
    }
    auto generation = std::make_shared<ResolverGenerationSnapshot>(
        *resolver_generation_snapshot_);
    resolver_stream_attempt_owner_.assign_next_stream_epoch(*generation);
    const std::uint64_t expected_epoch = generation->stream_epoch;
    const std::string attempt_id = generate_resolver_attempt_id();
    auto lifetime = resolver_stream_attempt_owner_.acquire_lifetime(
        attempt_id, generation);
    resolver_generation_snapshot_ = generation;
    resolver_stream_attempt_owner_.publish_active(
        lifetime, inactive_activation_authority);
    if (!run_system_resolver_hook(action, false, attempt_id)) {
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

    if (rebuild_snapshot) {
        // Local files and inline configuration are not generation files. Read
        // them again after the stream, but keep the exact same pinned remote
        // bodies so a concurrent list refresh cannot masquerade as a local
        // source change or move expected_hash ahead of what dnsmasq consumed.
        commit_resolver_generation_snapshot(
            make_resolver_generation_snapshot(
                generation->list_cache_snapshot));
    }
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
        if (resolver_stream_attempt_owner_.completed_stream_epoch() ==
            expected_epoch) {
            return true;
        }
        if (is_event_loop_thread() ||
            !event_loop_active_.load(std::memory_order_acquire)) {
            handle_ipc_control_requests();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return resolver_stream_attempt_owner_.completed_stream_epoch() ==
        expected_epoch;
}


bool Daemon::routing_runtime_active() const {
    // The store owns this outright now: reading the whole snapshot to get one
    // bool copied the route and rule vectors and the urltest map on every
    // event that asks.
    return runtime_state_store_.routing_runtime_active();
}

void Daemon::warn_conntrack_unavailable_once() {
    if (!conntrack_cleanup_coordinator_.note_command_unavailable()) {
        return;
    }
    Logger::instance().warn(
        "Best-effort conntrack cleanup is unavailable because the conntrack "
        "utility is not installed; existing flows may keep their previous "
        "path until they expire");
}

OwnedConntrackCleanupSnapshot
Daemon::snapshot_owned_conntrack_marks() const {
    return make_owned_conntrack_cleanup_snapshot(
        runtime_generation_.load(std::memory_order_acquire),
        active_config_snapshot_->config,
        active_config_snapshot_->outbound_marks,
        firewall_state_.get_rules(),
        firewall_state_.get_urltest_selections());
}

void Daemon::reconcile_native_vpn_direct_egress_conntrack(
    const std::vector<FirewallSourceEgressSnatSelector>& selectors) {
    const auto& committed = conntrack_cleanup_coordinator_
        .committed_native_vpn_direct_egress_snat_selectors();
    if (selectors == committed) {
        return;
    }

    const auto affected_sources =
        changed_native_vpn_direct_egress_source_cidrs(
            committed,
            selectors);
    conntrack_cleanup_coordinator_
        .commit_native_vpn_direct_egress_snat_selectors(selectors);
    if (affected_sources.empty()) {
        return;
    }

    const auto cleanup = conntrack_manager_.delete_ipv4_source_cidrs(
        affected_sources,
        ConntrackSourceCleanupOptions{
            std::chrono::seconds{4},
            /*max_source_cidrs=*/32U});
    if (cleanup.command_unavailable) {
        Logger::instance().info(
            "Native VPN direct-egress SNAT changed, but targeted conntrack "
            "cleanup is unavailable; existing flows will converge as they "
            "expire");
        return;
    }
    if (cleanup.failed != 0U || cleanup.skipped != 0U) {
        Logger::instance().info(
            "Native VPN direct-egress SNAT changed; targeted conntrack cleanup "
            "left {} failed and {} skipped source selector(s)",
            cleanup.failed,
            cleanup.skipped);
    }
}

void Daemon::dispatch_owned_conntrack_cleanup_retry(
    OwnedConntrackCleanupRetry retry) noexcept {
    const auto requeue = [this, &retry]() noexcept {
        try {
            conntrack_cleanup_coordinator_.schedule_retry(retry);
        } catch (const std::exception& error) {
            try {
                Logger::instance().info(
                    "Best-effort conntrack cleanup retry dispatch failed: {}",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
            try {
                Logger::instance().info(
                    "Best-effort conntrack cleanup retry dispatch failed: "
                    "unknown error");
            } catch (...) {
            }
        }
    };
    try {
        if (!owned_conntrack_cleanup_retry_is_current(
                routing_runtime_active(),
                retry,
                runtime_generation_.load(std::memory_order_acquire))) {
            return;
        }
    } catch (...) {
        requeue();
        return;
    }
    try {
        RuntimeOwnedConntrackCleanupPointMutationTarget operation;
        operation.retry = retry;
        RuntimeBackgroundPointMutationTarget target;
        target.kind =
            RuntimeBackgroundPointMutationKind::
                owned_conntrack_cleanup;
        target.target_serial = ++background_point_mutation_serial_;
        if (target.target_serial == 0U) {
            target.target_serial = ++background_point_mutation_serial_;
        }
        target.payload = std::move(operation);
        auto transaction = std::make_shared<
            RuntimeBackgroundPointMutationTransaction>(
            std::move(target));
        if (!transaction->valid()) {
            throw std::runtime_error(
                "invalid owned conntrack cleanup target");
        }
        auto admitted = runtime_mutation_admission_.try_acquire(
            "owned-conntrack-cleanup-point");
        if (!admitted.has_value()) {
            throw TransientFirewallError(
                "runtime mutation owner is busy");
        }
        auto lease = std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(*admitted));
        const auto expected_lease_token = lease->token();
        RuntimeFirewallPreownedTerminalContinuation continuation{
            [this, transaction, expected_lease_token](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                const auto& operation = std::get<
                    RuntimeOwnedConntrackCleanupPointMutationTarget>(
                    transaction->target.payload);
                const auto& retry = operation.retry;
                const bool lease_returned =
                    exact && static_cast<bool>(*exact) &&
                    exact->token() == expected_lease_token &&
                    runtime_mutation_admission_.owns(*exact);
                bool current = false;
                try {
                    current =
                        terminal.outcome !=
                            RuntimeFirewallLifecycleOutcome::shutdown &&
                        owned_conntrack_cleanup_retry_is_current(
                            routing_runtime_active(),
                            retry,
                            runtime_generation_.load(
                                std::memory_order_acquire));
                } catch (...) {}
                const bool typed =
                    lease_returned &&
                    transaction->typed_identity_valid &&
                    transaction->result &&
                    transaction->result->control_publishable() &&
                    transaction->result->target ==
                        transaction->target &&
                    std::holds_alternative<
                        RuntimeOwnedConntrackCleanupPointMutationResult>(
                        transaction->result->payload);
                try {
                    if (!typed) {
                        if (current) {
                            conntrack_cleanup_coordinator_.schedule_retry(
                                retry);
                        }
                    } else if (current) {
                        auto cleanup = std::get<
                            RuntimeOwnedConntrackCleanupPointMutationResult>(
                            transaction->result->payload).cleanup;
                        if (cleanup.command_unavailable) {
                            warn_conntrack_unavailable_once();
                        } else if (!cleanup.remaining_marks.empty()) {
                            conntrack_cleanup_coordinator_
                                .schedule_remaining(
                                    retry,
                                    std::move(cleanup.remaining_marks));
                        }
                    }
                } catch (...) {}
            }};
        if (begin_preowned_runtime_firewall_background_point_mutation(
                lease, transaction, continuation)) {
            return;
        }
        lease.reset();
    } catch (...) {}
    requeue();
}

void Daemon::setup_static_routing() {
    const Ipv6SupportDecision ipv6_decision = resolve_ipv6_support(active_config_snapshot_->config);
    log_ipv6_support_decision_once(ipv6_decision);
    const auto main_table_routes = netlink_.dump_routes_in_table(254);
    OutboundReachabilitySnapshot reachability;
    for (const auto& outbound :
         active_config_snapshot_->config.outbounds.value_or(std::vector<Outbound>{})) {
        if (outbound.type != OutboundType::INTERFACE ||
            reachability.count(outbound.tag) != 0U) {
            continue;
        }
        reachability.emplace(
            outbound.tag,
            is_interface_outbound_reachable(
                outbound, main_table_routes));
    }
    const auto plan = plan_routing_state(
        active_config_snapshot_->config,
        active_config_snapshot_->outbound_marks,
        reachability,
        &firewall_state_.get_urltest_selections(),
        ipv6_decision.enabled);
    const auto inventory =
        routing_operation_owner_.populate_initial_generation(
            plan.routes, plan.rules);
    require_authoritative_runtime_routing(
        inventory, "initial static routing");
}

void Daemon::reconcile_static_routing(RouteReconcileMode mode) {
    const Ipv6SupportDecision ipv6_decision = resolve_ipv6_support(active_config_snapshot_->config);
    log_ipv6_support_decision_once(ipv6_decision);
    const auto main_table_routes = netlink_.dump_routes_in_table(254);
    OutboundReachabilitySnapshot reachability;
    for (const auto& outbound :
         active_config_snapshot_->config.outbounds.value_or(std::vector<Outbound>{})) {
        if (outbound.type != OutboundType::INTERFACE ||
            reachability.count(outbound.tag) != 0U) {
            continue;
        }
        reachability.emplace(
            outbound.tag,
            is_interface_outbound_reachable(outbound, main_table_routes));
    }
    const auto plan = plan_routing_state(
        active_config_snapshot_->config,
        active_config_snapshot_->outbound_marks,
        reachability,
        &firewall_state_.get_urltest_selections(),
        ipv6_decision.enabled);

    reconcile_static_routing(plan, mode);
}

void Daemon::reconcile_static_routing(
    const PlannedRoutingState& plan,
    RouteReconcileMode mode) {

    // The URLTest policy rule does not change on a selected-child switch, but
    // its route does. Add all desired routes first so marked traffic never
    // observes an empty table, then retire only obsolete owned state.
    const auto inventory =
        routing_operation_owner_.reconcile_compatibility_generation(
            plan.routes,
            plan.rules,
            mode);
    require_authoritative_runtime_routing(
        inventory, "static routing reconciliation");
}

std::optional<MetaUdp443ActivationPlan>
Daemon::prepare_meta_udp443_activation_or_throw(
    const std::vector<RuleState>& candidate_rules,
    const AppliedListContentState& candidate_list_content_state,
    bool forwarded_scope_allows_unmarked_cleanup) {
    // Preserve the historical inactive fast path: it performed no large
    // policy snapshot allocation and no backend observation. Active delayed
    // work receives the owned copy below; the free contract deliberately
    // validates selection again at its trust boundary.
    const auto owned_mask = fwmark_mask_value(
        active_config_snapshot_->config.fwmark.value_or(FwmarkConfig{}));
    if (!resolve_meta_udp_443_policy_selection(
             active_config_snapshot_->config, candidate_rules, owned_mask).active()) {
        return std::nullopt;
    }

    MetaUdp443ActivationInput input;
    input.config = active_config_snapshot_->config;
    input.candidate_rules = candidate_rules;
    input.candidate_list_content_state = candidate_list_content_state;
    input.forwarded_scope_allows_unmarked_cleanup =
        forwarded_scope_allows_unmarked_cleanup;
    input.committed_fwmark = committed_meta_udp443_fwmark_;
    input.committed_owned_mask = committed_meta_udp443_owned_mask_;
    try {
        return keen_pbr3::prepare_meta_udp443_activation_or_throw(
            input, conntrack_manager_, netlink_);
    } catch (const MetaUdp443ActivationError& error) {
        // Preserve the member function's existing exception contract for all
        // current synchronous callers while the worker-safe free contract
        // remains independent of DaemonError.
        throw DaemonError(error.what());
    }
}

void Daemon::report_meta_udp443_degraded(
    std::string_view detail) noexcept {
    try {
        const auto incident = meta_udp443_incidents_.record_failure(
            "meta-udp443-activation", /*notify_immediately=*/true);
        if (incident.notify) {
            Logger::instance().error(
                "Meta/WhatsApp UDP/443 policy state is degraded: {}. "
                "The service will perform a bounded recovery without "
                "broadening the affected traffic scope.",
                detail);
        } else {
            Logger::instance().info(
                "Meta/WhatsApp messages-first recovery remains degraded: {}",
                detail);
        }
    } catch (...) {
    }
}

void Daemon::cancel_meta_udp443_activation_cleanup() noexcept {
    meta_udp443_cleanup_epoch_.fetch_add(1U, std::memory_order_acq_rel);
    ++meta_udp443_cleanup_schedule_serial_;
    pending_meta_udp443_cleanup_.reset();
    meta_udp443_cleanup_completion_admission_failed_serial_.store(
        0U, std::memory_order_release);
    try {
        if (meta_udp443_cleanup_retry_task_id_ >= 0 && scheduler_) {
            scheduler_->cancel(meta_udp443_cleanup_retry_task_id_);
            meta_udp443_cleanup_retry_task_id_ = -1;
        }
    } catch (...) {
        // The epoch is the deletion authority. Even if timer cancellation
        // itself fails during shutdown, the queued callback is stale and its
        // worker fence prevents every exact mutation.
        meta_udp443_cleanup_retry_task_id_ = -1;
    }
}

void Daemon::schedule_meta_udp443_activation_cleanup_retry(
    const MetaUdp443ActivationPlan& plan,
    std::uint64_t expected_runtime_generation,
    std::uint64_t cleanup_epoch,
    std::size_t attempt) noexcept {
    try {
        MetaUdp443ActivationPlan durable_copy = plan;
        schedule_meta_udp443_activation_cleanup_retry(
            std::move(durable_copy),
            expected_runtime_generation,
            cleanup_epoch,
            attempt);
    } catch (...) {
        // An existing pending plan remains authoritative when this is a retry.
        // Initial publication always transfers its already-allocated plan via
        // the rvalue overload below, so it never depends on a post-COMMIT copy.
        report_meta_udp443_degraded(
            "could not copy the bounded exact-cleanup plan for retry");
    }
}

void Daemon::schedule_meta_udp443_activation_cleanup_retry(
    MetaUdp443ActivationPlan&& plan,
    std::uint64_t expected_runtime_generation,
    std::uint64_t cleanup_epoch,
    std::size_t attempt) noexcept {
    if (!scheduler_ || !meta_udp443_cleanup_authority_matches(
            expected_runtime_generation,
            runtime_generation_.load(std::memory_order_acquire),
            cleanup_epoch,
            meta_udp443_cleanup_epoch_.load(std::memory_order_acquire))) {
        return;
    }
    try {
        const bool maintenance =
            attempt > META_UDP443_ACTIVATION_RETRY_DELAYS.size();
        if (maintenance) {
            report_meta_udp443_degraded(
                "bounded exact cleanup retries made no progress; remaining "
                "exact tuples are retained for a quiet generation-fenced "
                "maintenance retry");
        }
        const auto delay = maintenance
            ? std::chrono::duration_cast<std::chrono::milliseconds>(
                  META_UDP443_ACTIVATION_MAINTENANCE_RETRY_DELAY)
            : (attempt == 0U
                   ? meta_udp443_initial_cleanup_delay()
                   : std::chrono::duration_cast<std::chrono::milliseconds>(
                         META_UDP443_ACTIVATION_RETRY_DELAYS[std::min(
                             attempt - 1U,
                             META_UDP443_ACTIVATION_RETRY_DELAYS.size() -
                                 1U)]));
        const std::size_t dispatch_attempt = maintenance ? 0U : attempt;
        const std::uint64_t schedule_serial =
            ++meta_udp443_cleanup_schedule_serial_;
        // Build the replacement before invalidating the old timer, then keep
        // it as the sole durable event-loop-owned plan through timer and
        // worker admission. The timer captures only scalar authority; a lost
        // completion post therefore leaves this bounded plan available to the
        // periodic health task instead of losing it.
        PendingMetaUdp443ActivationCleanup replacement{
            std::move(plan),
            expected_runtime_generation,
            cleanup_epoch,
            attempt,
            schedule_serial,
            false};
        pending_meta_udp443_cleanup_ = std::move(replacement);
        if (meta_udp443_cleanup_retry_task_id_ >= 0) {
            const int stale_task_id =
                meta_udp443_cleanup_retry_task_id_;
            meta_udp443_cleanup_retry_task_id_ = -1;
            scheduler_->cancel(stale_task_id);
        }
        meta_udp443_cleanup_retry_task_id_ = scheduler_->schedule_oneshot(
            delay,
            [this,
             expected_runtime_generation,
             cleanup_epoch,
             dispatch_attempt,
             schedule_serial]() mutable {
                if (schedule_serial !=
                        meta_udp443_cleanup_schedule_serial_ ||
                    !pending_meta_udp443_cleanup_.has_value() ||
                    pending_meta_udp443_cleanup_->schedule_serial !=
                        schedule_serial) {
                    return;
                }
                meta_udp443_cleanup_retry_task_id_ = -1;
                pending_meta_udp443_cleanup_->worker_inflight = true;
                dispatch_meta_udp443_activation_cleanup(
                    expected_runtime_generation,
                    cleanup_epoch,
                    dispatch_attempt,
                    schedule_serial);
            },
            maintenance
                ? "meta-udp443-exact-cleanup-maintenance"
                : "meta-udp443-exact-cleanup-retry");
    } catch (const std::exception& error) {
        (void)error;
        meta_udp443_cleanup_retry_task_id_ = -1;
        report_meta_udp443_degraded(
            "could not schedule exact cleanup retry");
    } catch (...) {
        meta_udp443_cleanup_retry_task_id_ = -1;
        report_meta_udp443_degraded(
            "could not schedule exact cleanup retry");
    }
}

void Daemon::dispatch_meta_udp443_activation_cleanup(
    std::uint64_t expected_runtime_generation,
    std::uint64_t cleanup_epoch,
    std::size_t attempt,
    std::uint64_t schedule_serial) noexcept {
    if (!meta_udp443_cleanup_authority_matches(
            expected_runtime_generation,
            runtime_generation_.load(std::memory_order_acquire),
            cleanup_epoch,
            meta_udp443_cleanup_epoch_.load(
                std::memory_order_acquire))) {
        if (pending_meta_udp443_cleanup_.has_value() &&
            pending_meta_udp443_cleanup_->schedule_serial ==
                schedule_serial) {
            pending_meta_udp443_cleanup_.reset();
        }
        return;
    }
    if (!pending_meta_udp443_cleanup_.has_value() ||
        pending_meta_udp443_cleanup_->schedule_serial !=
            schedule_serial) {
        return;
    }
    try {
        RuntimeMetaUdp443CleanupPointMutationTarget operation;
        operation.runtime_generation = expected_runtime_generation;
        operation.cleanup_epoch = cleanup_epoch;
        operation.attempt = attempt;
        operation.plan = pending_meta_udp443_cleanup_->plan;
        RuntimeBackgroundPointMutationTarget target;
        target.kind =
            RuntimeBackgroundPointMutationKind::meta_udp443_cleanup;
        target.target_serial = schedule_serial;
        target.payload = std::move(operation);
        auto transaction = std::make_shared<
            RuntimeBackgroundPointMutationTransaction>(
            std::move(target));
        if (!transaction->valid()) {
            throw std::runtime_error("invalid Meta cleanup target");
        }
        auto admitted = runtime_mutation_admission_.try_acquire(
            "meta-udp443-cleanup-point");
        if (!admitted.has_value()) {
            throw TransientFirewallError(
                "runtime mutation owner is busy");
        }
        auto lease = std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(*admitted));
        const auto expected_lease_token = lease->token();
        RuntimeFirewallPreownedTerminalContinuation continuation{
            [this, transaction, expected_runtime_generation,
             cleanup_epoch, attempt, schedule_serial,
             expected_lease_token](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                try {
                if (!pending_meta_udp443_cleanup_.has_value() ||
                    pending_meta_udp443_cleanup_->schedule_serial !=
                        schedule_serial) {
                    return;
                }
                pending_meta_udp443_cleanup_->worker_inflight = false;
                const bool lease_returned =
                    exact && static_cast<bool>(*exact) &&
                    exact->token() == expected_lease_token &&
                    runtime_mutation_admission_.owns(*exact);
                const bool typed =
                    lease_returned &&
                    transaction->typed_identity_valid &&
                    transaction->result &&
                    transaction->result->control_publishable() &&
                    transaction->result->target ==
                        transaction->target &&
                    std::holds_alternative<
                        RuntimeMetaUdp443CleanupPointMutationResult>(
                        transaction->result->payload);
                const auto& operation = std::get<
                    RuntimeMetaUdp443CleanupPointMutationTarget>(
                    transaction->target.payload);
                auto plan = operation.plan;
                if (!meta_udp443_cleanup_authority_matches(
                        expected_runtime_generation,
                        runtime_generation_.load(
                            std::memory_order_acquire),
                        cleanup_epoch,
                        meta_udp443_cleanup_epoch_.load(
                            std::memory_order_acquire))) {
                    pending_meta_udp443_cleanup_.reset();
                    return;
                }
                if (!typed ||
                    terminal.outcome ==
                        RuntimeFirewallLifecycleOutcome::shutdown) {
                    report_meta_udp443_degraded(
                        "exact cleanup returned no typed result");
                    schedule_meta_udp443_activation_cleanup_retry(
                        std::move(plan),
                        expected_runtime_generation,
                        cleanup_epoch,
                        attempt + 1U);
                    return;
                }
                const auto& output = std::get<
                    RuntimeMetaUdp443CleanupPointMutationResult>(
                    transaction->result->payload);
                auto cleanup = output.cleanup;
                if (cleanup.generation_changed) {
                    pending_meta_udp443_cleanup_.reset();
                    return;
                }
                if (!output.worker_failure.empty()) {
                    report_meta_udp443_degraded(
                        "exact activation cleanup failed: " +
                        output.worker_failure);
                    plan.exact_flows =
                        std::move(cleanup.remaining_flows);
                    schedule_meta_udp443_activation_cleanup_retry(
                        std::move(plan),
                        expected_runtime_generation,
                        cleanup_epoch,
                        attempt + 1U);
                    return;
                }
                if (!output.fastnat_before ||
                    !output.fastnat_after ||
                    output.before !=
                        OwnedForwardUdpRejectState::healthy ||
                    output.after !=
                        OwnedForwardUdpRejectState::healthy) {
                    report_meta_udp443_degraded(
                        !output.fastnat_before ||
                                !output.fastnat_after
                            ? "FastNAT is no longer verified disabled"
                            : "the owned Meta UDP filter contract "
                              "changed during cleanup");
                    plan.exact_flows =
                        std::move(cleanup.remaining_flows);
                    schedule_meta_udp443_activation_cleanup_retry(
                        std::move(plan),
                        expected_runtime_generation,
                        cleanup_epoch,
                        attempt + 1U);
                    if (output.fastnat_before &&
                        output.fastnat_after) {
                        schedule_netfilter_runtime_refresh_noexcept(
                            NetfilterRefreshReason::full,
                            "could not schedule repair of the owned "
                            "Meta UDP/443 filter contract");
                    }
                    return;
                }
                if (cleanup.complete()) {
                    pending_meta_udp443_cleanup_.reset();
                    meta_udp443_incidents_.reset(
                        "meta-udp443-activation");
                    if (cleanup.attempted != 0U) {
                        Logger::instance().info(
                            "Meta/WhatsApp messages-first policy "
                            "retired {} exact pre-existing UDP/443 "
                            "flow(s)",
                            cleanup.attempted);
                    }
                    return;
                }
                plan.exact_flows =
                    std::move(cleanup.remaining_flows);
                const std::size_t unavailable =
                    cleanup.command_unavailable ? 1U : 0U;
                const bool made_progress =
                    cleanup.attempted >
                    cleanup.failed + unavailable;
                if (!made_progress) {
                    report_meta_udp443_degraded(
                        cleanup.command_unavailable
                            ? "the conntrack utility became unavailable"
                            : "one or more exact UDP/443 tuples "
                              "could not be retired");
                }
                schedule_meta_udp443_activation_cleanup_retry(
                    std::move(plan),
                    expected_runtime_generation,
                    cleanup_epoch,
                    made_progress ? 0U : attempt + 1U);
                } catch (...) {
                    try {
                        if (pending_meta_udp443_cleanup_.has_value() &&
                            pending_meta_udp443_cleanup_->
                                schedule_serial == schedule_serial) {
                            pending_meta_udp443_cleanup_->
                                worker_inflight = false;
                            const auto pending =
                                *pending_meta_udp443_cleanup_;
                            schedule_meta_udp443_activation_cleanup_retry(
                                pending.plan,
                                expected_runtime_generation,
                                cleanup_epoch,
                                attempt + 1U);
                        }
                    } catch (...) {
                        if (pending_meta_udp443_cleanup_.has_value() &&
                            pending_meta_udp443_cleanup_->
                                schedule_serial == schedule_serial) {
                            pending_meta_udp443_cleanup_->
                                worker_inflight = false;
                        }
                    }
                }
            }};
        if (begin_preowned_runtime_firewall_background_point_mutation(
                lease, transaction, continuation)) {
            return;
        }
        lease.reset();
    } catch (...) {
        report_meta_udp443_degraded(
            "could not admit exact cleanup to the mutation owner");
    }
    if (pending_meta_udp443_cleanup_.has_value() &&
        pending_meta_udp443_cleanup_->schedule_serial ==
            schedule_serial) {
        pending_meta_udp443_cleanup_->worker_inflight = false;
        const auto pending = *pending_meta_udp443_cleanup_;
        schedule_meta_udp443_activation_cleanup_retry(
            pending.plan,
            expected_runtime_generation,
            cleanup_epoch,
            attempt + 1U);
    }
}

FirewallApplyMode Daemon::runtime_refresh_firewall_mode() const {
    const auto daemon_config = active_config_snapshot_->config.daemon.value_or(DaemonConfig{});
    return daemon_config.reuse_static_sets_on_runtime_refresh.value_or(true)
        ? FirewallApplyMode::RulesOnly
        : FirewallApplyMode::PreserveSets;
}

void Daemon::apply_firewall(
    FirewallApplyMode mode,
    std::shared_ptr<const ListCacheGenerationSnapshot>
        list_cache_snapshot,
    bool force_clear_dynamic_sets) {
    // Every synchronous firewall writer shares the same routing admission
    // contract, including delayed startup/SNAT/DNS paths which do not call a
    // routing reconciler in the same stack. The worker path has its own typed
    // checkpoint and does not enter this method.
    require_authoritative_runtime_routing(
        routing_operation_owner_.snapshot(),
        "firewall apply routing admission");

    // Every backend apply may flush the runtime-only pair sets. Invalidate the
    // observer epoch before touching live chains so an outstanding worker can
    // never acknowledge an old pair after a URLTest or recovery rebuild.
    cancel_idle_stall_observer();
    auto previous_meta_cleanup =
        pending_meta_udp443_cleanup_;
    cancel_meta_udp443_activation_cleanup();
    // Snapshot the backend's exact Meta publication boundary independently
    // from ordinary mangle/NAT work. A changed epoch after an exception is
    // deliberately ambiguous: the filter may have committed before its
    // command result or post-COMMIT verification failed.
    const auto meta_publication_epoch_before =
        firewall_->meta_udp443_publication_epoch();
    bool meta_policy_committed = false;
    std::optional<MetaUdp443ActivationPlan> meta_activation;

    try {

    KPBR_UNIQUE_LOCK(
        affinity_mutation_lock,
        udp_call_affinity_mutation_mutex_);
    const auto interface_snapshot =
        shared_ndms_catalog_cache().peek();
    const auto service_snapshot =
        shared_ndms_vpn_server_service_cache().peek();
    const auto& active_internal_vpn_servers =
        internal_vpn_resolution_cache_.active_servers();
    const auto& active_internal_vpn_service_targets =
        internal_vpn_resolution_cache_.active_service_targets();
    const auto effective_interface_servers =
        prefer_authoritative_internal_vpn_service_inventory(
            active_internal_vpn_servers,
            interface_snapshot.catalog,
            service_snapshot.catalog,
            service_snapshot.status ==
                NdmsCatalogCacheStatus::fresh);
    auto runtime_targets =
        internal_vpn_interface_runtime_targets(
            effective_interface_servers);
    runtime_targets.insert(
        runtime_targets.end(),
        active_internal_vpn_service_targets.begin(),
        active_internal_vpn_service_targets.end());
    const auto native_vpn_direct_egress_snat_selectors =
        select_native_vpn_direct_egress_snat_selectors(
            runtime_targets);
    if (!list_cache_snapshot) {
        list_cache_snapshot =
            capture_relevant_list_cache_generation(active_config_snapshot_->config);
    }

    // RulesOnly reuses the live sets, which is only true to do while the
    // lists those sets were loaded from are byte-for-byte the ones this
    // refresh would have streamed. Compare digests, not assumptions: a
    // refresh that races a list download must stream, and this is where it
    // finds out. Downgrading here is silent by design - it is the ordinary
    // path, not an error.
    const auto requested_fingerprints = list_cache_snapshot
        ? list_cache_snapshot->fingerprints()
        : std::map<std::string, std::string>{};
    FirewallApplyMode effective_mode = mode;
    if (effective_mode == FirewallApplyMode::RulesOnly &&
        (applied_list_fingerprints_.empty() ||
         requested_fingerprints != applied_list_fingerprints_)) {
        Logger::instance().verbose(
            "Firewall refresh streams lists: cache generation differs from "
            "the one the live sets were loaded from");
        effective_mode = FirewallApplyMode::PreserveSets;
    }

    const auto stage_with = [&](FirewallApplyMode stage_mode) {
        PreviousRuntimeFirewall previous;
        if (stage_mode == FirewallApplyMode::RulesOnly) {
            previous.rule_states = &firewall_state_.get_rules();
            previous.list_usage = &applied_list_usage_;
            previous.list_content_state = &applied_list_content_state_;
        }
        return stage_runtime_firewall(
            active_config_snapshot_->config,
            active_config_snapshot_->outbound_marks,
            firewall_state_.get_urltest_selections(),
            list_service_.cache_manager(),
            *firewall_,
            stage_mode,
            &effective_interface_servers,
            &runtime_targets,
            &native_vpn_direct_egress_snat_selectors,
            opts_.udp_call_affinity_ipset_available,
            active_keenetic_dns_.snapshot,
            list_cache_snapshot,
            force_clear_dynamic_sets,
            previous);
    };
    // One fallback, at most: a RulesOnly preflight that fails has touched
    // nothing, so restaging with PreserveSets is the same transaction the
    // daemon always used to run. A second RulesOnly failure is impossible by
    // construction and a PreserveSets failure is a real error.
    StagedRuntimeFirewall staged;
    try {
        staged = stage_with(effective_mode);
    } catch (const FirewallRulesOnlyError& error) {
        if (effective_mode != FirewallApplyMode::RulesOnly) throw;
        // An NDMS netfilter rebuild leaving the dispatchers in need of
        // repair is routine, and this very fallback repairs it - the
        // operator's bell must not present a designed self-heal as a
        // warning. A refusal about the daemon's own bookkeeping is one.
        if (error.external_repair()) {
            Logger::instance().info(
                "Set-reusing firewall refresh is not possible, streaming "
                "lists instead: {}",
                error.what());
        } else {
            Logger::instance().warn(
                "Set-reusing firewall refresh hit an unexpected refusal, "
                "streaming lists instead: {}",
                error.what());
        }
        effective_mode = FirewallApplyMode::PreserveSets;
        staged = stage_with(effective_mode);
    }
    // The backend may already have repaired its ordinary mangle dispatcher
    // during prepare_apply(). Meta-specific preflight still completes before
    // any Meta filter publication or exact conntrack deletion, so failure
    // leaves the previously committed Meta policy authoritative.
    const auto route_config = active_config_snapshot_->config.route.value_or(RouteConfig{});
    const bool has_explicit_inbound_scope =
        route_config.inbound_interfaces.has_value() &&
        !route_config.inbound_interfaces->empty();
    const bool has_native_vpn_bypass = std::any_of(
        effective_interface_servers.begin(),
        effective_interface_servers.end(),
        [](const InternalVpnServer& server) {
            return !server.process_clients;
        }) || std::any_of(
        runtime_targets.begin(),
        runtime_targets.end(),
        [](const InternalVpnRuntimeTarget& target) {
            return internal_vpn_target_bypasses_routing(target);
        });
    meta_activation = prepare_meta_udp443_activation_or_throw(
        staged.rule_states,
        staged.list_content_state,
        !has_explicit_inbound_scope && !has_native_vpn_bypass);

    staged = commit_runtime_firewall_with_rules_only_fallback(
        *firewall_,
        std::move(staged),
        [&](const FirewallRulesOnlyError& error) {
            // The backend's own preflight (a reused set missing, a schema that
            // drifted, dispatchers that need repair) fires before it mutates
            // anything, so the kernel is exactly as it was. Restage the full
            // transaction and run the Meta preflight again over it: the
            // content state is now freshly read rather than carried over.
            if (error.external_repair()) {
                Logger::instance().info(
                    "Set-reusing firewall refresh was refused by the backend, "
                    "streaming lists instead: {}",
                    error.what());
            } else {
                Logger::instance().warn(
                    "Set-reusing firewall refresh hit an unexpected backend "
                    "refusal, streaming lists instead: {}",
                    error.what());
            }
            effective_mode = FirewallApplyMode::PreserveSets;
            auto fallback = stage_with(effective_mode);
            meta_activation = prepare_meta_udp443_activation_or_throw(
                fallback.rule_states,
                fallback.list_content_state,
                !has_explicit_inbound_scope && !has_native_vpn_bypass);
            return fallback;
        });
    meta_policy_committed = true;
    if (meta_activation.has_value()) {
        committed_meta_udp443_fwmark_ =
            meta_activation->expected_fwmark;
        committed_meta_udp443_owned_mask_ =
            meta_activation->owned_mask;
    } else {
        committed_meta_udp443_fwmark_.reset();
        committed_meta_udp443_owned_mask_ = 0U;
    }
    OwnedForwardUdpRejectState meta_filter_health =
        OwnedForwardUdpRejectState::unknown;
    try {
        meta_filter_health =
            firewall_->inspect_forward_udp_reject_state();
    } catch (...) {
        // The filter generation already committed. Treat an inspection fault
        // as degraded post-commit state and let the durable repair path
        // converge; never throw an "old generation retained" lie.
        report_meta_udp443_degraded(
            "post-publication Meta UDP/443 inspection failed");
    }
    const bool meta_fastnat_healthy =
        !meta_activation.has_value() ||
        fastnat_is_disabled_or_unavailable();

    auto candidate_rules = std::move(staged.rule_states);
    auto candidate_list_content_state =
        std::move(staged.list_content_state);
    firewall_state_.set_rules(std::move(candidate_rules));
    applied_list_content_state_ =
        std::move(candidate_list_content_state);
    applied_list_usage_ = std::move(staged.list_usage);
    // Under RulesOnly the sets were not reloaded, so the digests they were
    // loaded from are the ones already recorded - and those equal the
    // requested ones, or the mode would have been downgraded above.
    applied_list_fingerprints_ = requested_fingerprints;
    reconcile_native_vpn_direct_egress_conntrack(
        native_vpn_direct_egress_snat_selectors);

    affinity_mutation_lock.unlock();

    // Re-arm only after the replacement firewall transaction has committed
    // successfully, but before transferring
    // the already-allocated exact-cleanup plan into durable scheduler state.
    // A failure here reaches the post-COMMIT catch with the candidate plan
    // still intact.
    reset_idle_stall_observer(/*schedule_if_eligible=*/true);

    const auto current_runtime_generation =
        runtime_generation_.load(std::memory_order_acquire);
    const auto cleanup_epoch = meta_udp443_cleanup_epoch_.load(
        std::memory_order_acquire);
    if (meta_activation.has_value() && meta_fastnat_healthy &&
        meta_filter_health == OwnedForwardUdpRejectState::healthy) {
        // A successful retry has replaced and reverified the filter
        // generation. Clear a prior publication incident now; any later
        // exact-cleanup failure records a fresh incident with its own detail.
        meta_udp443_incidents_.reset("meta-udp443-activation");
        // The exact deletion is irreversible. Queue even the initial attempt
        // through the scheduler so it cannot run until the enclosing
        // config/resolver/persistence transaction has returned to the event
        // loop. A later rollback re-enters apply_firewall(), cancels this
        // epoch and leaves every old tuple intact.
        schedule_meta_udp443_activation_cleanup_retry(
            std::move(*meta_activation),
            current_runtime_generation,
            cleanup_epoch,
            /*attempt=*/0U);
    } else if (meta_activation.has_value()) {
        report_meta_udp443_degraded(
            !meta_fastnat_healthy
                ? "FastNAT was re-enabled during firewall publication"
                : "the exact owned first FORWARD hook could not be reverified");
        schedule_meta_udp443_activation_cleanup_retry(
            std::move(*meta_activation),
            current_runtime_generation,
            cleanup_epoch,
            /*attempt=*/1U);
        if (meta_fastnat_healthy) {
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "could not schedule repair after Meta UDP/443 "
                "post-publication verification failed");
        }
    } else if (meta_filter_health ==
               OwnedForwardUdpRejectState::healthy) {
        meta_udp443_incidents_.reset("meta-udp443-activation");
    } else {
        report_meta_udp443_degraded(
            "balanced mode could not verify absence of owned UDP/443 "
            "blocking artifacts");
        schedule_netfilter_runtime_refresh_noexcept(
            NetfilterRefreshReason::full,
            "could not schedule cleanup of stale balanced-mode Meta "
            "UDP/443 artifacts");
    }

    } catch (...) {
        std::string firewall_failure_detail{
            "unknown non-standard firewall exception"};
        try {
            throw;
        } catch (const std::exception& error) {
            try {
                firewall_failure_detail = error.what();
            } catch (...) {
            }
        } catch (...) {
        }
        // Same-generation repair/restart must not lose a durable activation
        // plan merely because staging failed before Firewall::apply(). Once
        // that ambiguous boundary was entered, however, old selectors are no
        // longer deletion authority: a backend can publish and then throw
        // during post-COMMIT verification.
        const auto current_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const auto meta_publication_epoch_after =
            firewall_->meta_udp443_publication_epoch();
        const bool meta_publication_may_have_changed =
            keen_pbr3::meta_udp443_publication_may_have_changed(
                meta_publication_epoch_before,
                meta_publication_epoch_after);
        if (should_restore_pending_meta_udp443_cleanup_after_apply_failure(
                previous_meta_cleanup.has_value(),
                previous_meta_cleanup.has_value()
                    ? previous_meta_cleanup->runtime_generation
                    : 0U,
                current_generation,
                meta_publication_may_have_changed)) {
            schedule_meta_udp443_activation_cleanup_retry(
                std::move(previous_meta_cleanup->plan),
                current_generation,
                meta_udp443_cleanup_epoch_.load(
                    std::memory_order_acquire),
                previous_meta_cleanup->attempt);
        } else if (
            should_retain_candidate_meta_udp443_cleanup_after_apply_failure(
                meta_policy_committed,
                meta_activation.has_value())) {
            // A later companion step failed after candidate publication. Keep
            // only the freshly preflighted candidate selectors; the deferred
            // timer remains behind the enclosing transaction boundary and a
            // rollback invalidates its epoch before it can delete anything.
            schedule_meta_udp443_activation_cleanup_retry(
                std::move(*meta_activation),
                current_generation,
                meta_udp443_cleanup_epoch_.load(
                    std::memory_order_acquire),
                /*attempt=*/1U);
        } else if (
            should_report_ambiguous_meta_udp443_publication_failure(
                meta_policy_committed,
                meta_publication_epoch_before,
                meta_publication_epoch_after)) {
            // Publication outcome is unknown. Do not delete under either old
            // or candidate selectors; a fresh full apply must rebuild and
            // verify authority before producing a new exact-cleanup plan.
            try {
                report_meta_udp443_degraded(keen_pbr3::format(
                    "firewall apply failed after entering the Meta UDP/443 "
                    "publication boundary; exact cleanup authority was "
                    "discarded; underlying firewall error: {}",
                    firewall_failure_detail));
            } catch (...) {
                report_meta_udp443_degraded(
                    "firewall apply failed after entering the Meta UDP/443 "
                    "publication boundary; exact cleanup authority was "
                    "discarded; underlying firewall error could not be "
                    "recorded");
            }
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "could not schedule fresh Meta UDP/443 reconciliation after "
                "an ambiguous firewall publication failure");
        }
        throw;
    }
}

void Daemon::normalize_urltest_selections() {
    const auto current = firewall_state_.get_urltest_selections();
    std::map<std::string, std::string> normalized;

    for (const auto& outbound :
         active_config_snapshot_->config.outbounds.value_or(std::vector<Outbound>{})) {
        if (outbound.type != OutboundType::URLTEST) {
            continue;
        }
        const auto selection = current.find(outbound.tag);
        if (selection == current.end()) {
            continue;
        }
        if (urltest_contains_child(outbound, selection->second) &&
            active_config_snapshot_->outbound_marks.find(
                selection->second) !=
                active_config_snapshot_->outbound_marks.end()) {
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

void Daemon::defer_urltest_switch_to_firewall_recovery(
    const UrltestSelectionChange& change,
    std::uint64_t runtime_generation,
    std::string_view phase,
    std::string_view detail) noexcept {
    try {
        urltest_after_firewall_gate_.wait_for(
            runtime_generation, change.urltest_tag);
        // Admission is not an incident attempt.  The central bounded retry
        // chain owns the only notification decision; consuming the latch here
        // could reach its threshold while discarding Decision::notify and
        // leave a permanently gated selector silent forever.
        Logger::instance().info(
            "Urltest '{}' {} hit transient firmware churn: {}. The previous "
            "cursor is restored; the central firewall reconciler now owns "
            "recovery.",
            change.urltest_tag,
            phase,
            detail);
    } catch (const std::exception& error) {
        try {
            transition_runtime_or_throw(
                RuntimeState::broken,
                "urltest firewall recovery admission failed");
            publish_runtime_state();
            Logger::instance().error(
                "Urltest '{}' recovery could not be admitted: {}",
                change.urltest_tag,
                error.what());
        } catch (...) {
        }
        return;
    } catch (...) {
        try {
            transition_runtime_or_throw(
                RuntimeState::broken,
                "urltest firewall recovery admission failed");
            publish_runtime_state();
        } catch (...) {
        }
        return;
    }

    try {
        (void)refresh_iproute_and_firewall_runtime(
            0,
            {},
            /*schedule_catalog_refresh=*/false);
    } catch (const std::exception& error) {
        // The gate remains closed. A later netfilter event can retry without
        // admitting another URLTEST switch; a successfully installed central
        // timer would already own the normal persistent path.
        try {
            Logger::instance().info(
                "Urltest '{}' central firewall recovery could not be "
                "scheduled: {}",
                change.urltest_tag,
                error.what());
        } catch (...) {
        }
    } catch (...) {
    }
}

void Daemon::resume_urltest_firewall_recovery(
    std::uint64_t runtime_generation) noexcept {
    try {
        if (!routing_runtime_active() ||
            runtime_firewall_owner_->shutdown_requested() ||
            runtime_generation !=
                runtime_generation_.load(std::memory_order_acquire) ||
            !urltest_after_firewall_gate_.waiting_for(
                runtime_generation)) {
            return;
        }

        // The gate already owns the exact selector set. This is only a wake
        // for the existing central reconciler after a foreground or typed
        // owner returned its physical lease; it creates no second retry
        // policy and never replays a URLTEST candidate.
        (void)refresh_iproute_and_firewall_runtime(
            0,
            {},
            /*schedule_catalog_refresh=*/false);
    } catch (...) {
        // Periodic runtime health observes the same generation gate and is
        // the existing fallback if this immediate owner admission fails.
    }
}

void Daemon::release_urltest_firewall_recovery(
    std::uint64_t runtime_generation) noexcept {
    auto urltest_tags =
        urltest_after_firewall_gate_.release(runtime_generation);
    if (urltest_tags.empty()) {
        return;
    }
    for (const auto& urltest_tag : urltest_tags) {
        try {
            urltest_apply_incidents_.reset(urltest_tag);
            if (urltest_manager_) {
                // External-health requests are durable and coalesce with an
                // inflight probe, giving this selector exactly one trailing
                // convergence pass after the firewall proof succeeds.
                urltest_manager_->trigger_external_health_test(urltest_tag);
            }
        } catch (...) {
        }
    }
}

bool Daemon::handle_urltest_selection_change(
    const UrltestSelectionChange& change,
    std::uint64_t expected_runtime_generation) {
    if (!is_event_loop_thread()) {
        try {
            Logger::instance().error(
                "Refusing urltest '{}' transition outside the control loop",
                change.urltest_tag);
        } catch (...) {
        }
        return false;
    }

    try {
        auto& log = Logger::instance();
        const auto current_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        if (expected_runtime_generation != current_runtime_generation) {
            try {
                log.info(
                    "Ignoring stale urltest transition for '{}': runtime "
                    "generation changed from {} to {}",
                    change.urltest_tag,
                    expected_runtime_generation,
                    current_runtime_generation);
            } catch (...) {
            }
            return false;
        }

        if (urltest_after_firewall_gate_.waiting_for(
                current_runtime_generation)) {
            // Preserve every affected selector in the recovery payload, but
            // do not let this probe publish while the restored generation is
            // still awaiting a complete routing/firewall proof.
            urltest_after_firewall_gate_.wait_for(
                current_runtime_generation, change.urltest_tag);
            try {
                log.info(
                    "Holding urltest '{}' transition until central firewall "
                    "recovery verifies generation {}",
                    change.urltest_tag,
                    current_runtime_generation);
            } catch (...) {
            }
            return false;
        }

        const auto outbounds =
            active_config_snapshot_->config.outbounds.value_or(std::vector<Outbound>{});
        const auto urltest_it = std::find_if(
            outbounds.begin(),
            outbounds.end(),
            [&change](const Outbound& outbound) {
                return outbound.tag == change.urltest_tag &&
                       outbound.type == OutboundType::URLTEST;
            });
        if (urltest_it == outbounds.end() || !urltest_manager_) {
            try {
                log.info(
                    "Ignoring stale urltest transition for '{}': selector is "
                    "no longer configured",
                    change.urltest_tag);
            } catch (...) {
            }
            return false;
        }

        // Build both the candidate and rollback cursor before publishing
        // anything. swap_urltest_selections() is noexcept; after its first
        // call this local map owns the exact previously applied state.
        auto candidate_selections =
            firewall_state_.get_urltest_selections();
        const auto old_selection_it =
            candidate_selections.find(change.urltest_tag);
        const std::string applied_previous =
            old_selection_it != candidate_selections.end()
                ? old_selection_it->second
                : std::string{};

        if (applied_previous != change.previous_child_tag) {
            // The kernel/firewall cursor is authoritative. Resolve an already
            // divergent manager to it without applying a stale transition;
            // returning true tells the manager that the controller owns this
            // resolution. The durable request below supplies the one fresh
            // probe which can now retry the unapplied candidate.
            const bool synchronized =
                urltest_manager_->synchronize_selected_if_generation(
                    change.urltest_tag,
                    change.probe_generation,
                    applied_previous);
            if (synchronized) {
                // This callback resolved the stale manager cursor, but it did
                // not apply change.new_child_tag. Keep one durable follow-up
                // pending while the current generation is still inflight so
                // the freshly synchronized cursor is tested and converged
                // without waiting for the normal URLTEST interval.
                urltest_manager_->trigger_external_health_test(
                    change.urltest_tag);
            }
            try {
                if (synchronized) {
                    log.info(
                        "Resolved stale urltest transition for '{}': applied "
                        "selection is '{}', event expected '{}'",
                        change.urltest_tag,
                        applied_previous,
                        change.previous_child_tag);
                } else {
                    transition_runtime_or_throw(
                        RuntimeState::broken,
                        "urltest applied selection is not a configured child");
                    log.error(
                        "Urltest '{}' applied selection '{}' is not a current "
                        "child; routing requires attention",
                        change.urltest_tag,
                        applied_previous);
                }
            } catch (...) {
            }
            return synchronized;
        }

        auto rollback_selections = candidate_selections;
        candidate_selections[change.urltest_tag] = change.new_child_tag;

        std::optional<uint32_t> retired_mark;
        // Whether the retired child is itself a selector matters only for the
        // unset default: explicit delete modes already refused nested children
        // at validation, and the default must not exceed what an explicit
        // config may say.
        bool previous_child_is_selector = false;
        if (!change.previous_child_tag.empty() &&
            active_config_snapshot_->config.outbounds.has_value()) {
            for (const auto& outbound : *active_config_snapshot_->config.outbounds) {
                if (outbound.tag == change.previous_child_tag) {
                    previous_child_is_selector =
                        outbound.type == OutboundType::URLTEST;
                    break;
                }
            }
        }
        const bool cleanup_retired_flows =
            should_cleanup_retired_urltest_flows(
                urltest_it->conntrack_on_switch,
                change.reason,
                previous_child_is_selector);
        if (cleanup_retired_flows &&
            !change.previous_child_tag.empty() &&
            change.previous_child_tag != change.new_child_tag) {
            const auto old_mark_it =
                active_config_snapshot_->outbound_marks.find(
                    change.previous_child_tag);
            if (old_mark_it !=
                active_config_snapshot_->outbound_marks.end()) {
                retired_mark = old_mark_it->second;
            }
        }

        auto runtime_mutation = runtime_mutation_admission_.try_acquire(
            "urltest-selection-change");
        if (!runtime_mutation.has_value()) {
            const auto active = runtime_mutation_admission_.active();
            log.verbose(
                "Urltest '{}' transition deferred behind runtime mutation "
                "'{}'.",
                change.urltest_tag,
                active.has_value()
                    ? active->label
                    : std::string{"unknown"});

            // The kernel cursor never moved. Resolve the manager's private
            // probe candidate back to that cursor and let the already
            // existing firewall recovery gate own one trailing pass after
            // the current writer finishes. A fresh external-health request
            // here would reset its retry budget on every rejection and turn
            // a long startup mutation into an endless probe loop.
            const bool old_cursor_retained =
                urltest_manager_->synchronize_selected_if_generation(
                    change.urltest_tag,
                    change.probe_generation,
                    applied_previous);
            if (!old_cursor_retained) {
                return false;
            }
            defer_urltest_switch_to_firewall_recovery(
                change,
                current_runtime_generation,
                "writer admission",
                active.has_value()
                    ? std::string_view{active->label}
                    : std::string_view{"unknown runtime mutation"});
            return true;
        }

        const auto list_cache_snapshot =
            capture_relevant_list_cache_generation(active_config_snapshot_->config);
        auto mutation_lease =
            std::make_unique<RuntimeMutationAdmission::Lease>(
                std::move(*runtime_mutation));
        const bool handed_off =
            begin_preowned_runtime_firewall_urltest_selection(
                mutation_lease,
                change,
                std::move(candidate_selections),
                std::move(rollback_selections),
                list_cache_snapshot,
                retired_mark);
        if (!handed_off) {
            log.verbose(
                "Urltest '{}' typed firewall transition was not admitted; "
                "the previous selection remains authoritative.",
                change.urltest_tag);

            // start_immediate_preowned() returned the exact lease. Release it
            // before asking the central owner for a fresh background pass;
            // otherwise recovery would be queued behind our own token.
            mutation_lease.reset();
            const bool old_cursor_retained =
                urltest_manager_->synchronize_selected_if_generation(
                    change.urltest_tag,
                    change.probe_generation,
                    applied_previous);
            if (!old_cursor_retained) {
                return false;
            }
            defer_urltest_switch_to_firewall_recovery(
                change,
                current_runtime_generation,
                "typed owner admission",
                "the runtime firewall owner rejected the candidate handoff");
            return true;
        }

        // on_change() is still inside the exact manager probe callback. The
        // owner now holds the asynchronous transition; restore the callback's
        // candidate cursor to the verified child before returning. Only the
        // typed terminal may publish new_child_tag.
        const bool old_cursor_retained =
            urltest_manager_->synchronize_selected_if_generation(
                change.urltest_tag,
                change.probe_generation,
                applied_previous);
        if (!old_cursor_retained) {
            log.info(
                "Urltest '{}' probe generation changed while its typed "
                "firewall candidate was admitted; the candidate will roll "
                "back instead of publishing a stale selection.",
                change.urltest_tag);
            return false;
        }
        return true;
    } catch (const std::exception& error) {
        try {
            Logger::instance().error(
                "Urltest '{}' transition preparation failed: {}",
                change.urltest_tag,
                error.what());
        } catch (...) {
        }
        return false;
    } catch (...) {
        return false;
    }
}

bool Daemon::commit_urltest_probe_results(
    const std::string& urltest_tag,
    std::uint64_t probe_generation,
    std::map<std::string, URLTestResult> results,
    TraceId trace_id) {
    return post_control_task(
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
            // The synchronous controller callback resolves the route while
            // this exact probe remains single-flight. Publish only after the
            // manager has committed or restored its cursor and cleared that
            // ownership, for one coherent runtime snapshot.
            (void)selection_changed;
            publish_runtime_state();
        },
        "urltest-commit:" + urltest_tag);
}

void Daemon::register_urltest_outbounds() {
    const auto active_generation = active_config_snapshot_;
    const UrltestMarksGenerationHandle marks_generation(
        active_generation,
        &active_generation->outbound_marks);
    if (!urltest_manager_) {
        urltest_manager_ = std::make_unique<UrltestManager>(
            url_tester_,
            marks_generation,
            *scheduler_,
            blocking_executor_,
            [this](const UrltestSelectionChange& change) {
                return handle_urltest_selection_change(
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
                return commit_urltest_probe_results(urltest_tag,
                                                    probe_generation,
                                                    std::move(results),
                                                    trace_id);
            });
    } else {
        urltest_manager_->replace_marks_generation(
            marks_generation);
    }

    UrltestDirectChildInterfaceMap direct_child_interfaces;
    for (const auto& ob :
         active_generation->config.outbounds.value_or(
             std::vector<Outbound>{})) {
        if (ob.type == OutboundType::INTERFACE && ob.interface.has_value() &&
            !ob.interface->empty()) {
            direct_child_interfaces.emplace(ob.tag, *ob.interface);
        }
    }

    for (const auto& ob :
         active_generation->config.outbounds.value_or(
             std::vector<Outbound>{})) {
        if (ob.type == OutboundType::URLTEST) {
            const auto& selections =
                firewall_state_.get_urltest_selections();
            const auto retained = selections.find(ob.tag);
            urltest_manager_->register_urltest(
                ob,
                retained != selections.end() ? retained->second
                                             : std::string{},
                direct_child_interfaces);
        }
    }
}

void Daemon::probe_interfaces_now() noexcept {
    const auto admission = interface_probe_gate_.request(/*manual=*/false);
    if (!admission.launch) {
        try {
            Logger::instance().trace(
                "interface_probe_coalesced",
                "trigger=scheduled_or_startup");
        } catch (...) {
        }
        return;
    }
    // Only once this tick actually owns a round. Setting it before admission
    // would leave the flag standing when the request coalesced, and the next
    // manual refresh would quietly measure a slice instead of everything.
    interface_probe_round_rotates_ = true;
    start_interface_probe_round();
}

bool Daemon::start_targeted_interface_probe(const std::string& tag) noexcept {
    try {
        const auto generation = active_config_snapshot_;
        const auto targets = collect_interface_probe_targets(
            generation->config, generation->outbound_marks);
        const auto found = std::find_if(
            targets.begin(), targets.end(),
            [&tag](const InterfaceProbe::Target& candidate) {
                return candidate.tag == tag;
            });
        if (found == targets.end()) {
            // Unknown, or not an interface outbound. Saying so beats probing
            // nothing and reporting success.
            return false;
        }
        const auto target = *found;

        auto lease = targeted_probe_admission_.acquire(tag);
        if (!lease.admitted()) return false;

        const auto expected_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);

        // NOTE: no retain_only() here, unlike the round path. This measures
        // one target and must leave every other outbound's published health
        // exactly as it found it.
        const bool posted = blocking_executor_.try_post(
            "targeted-interface-probe:" + tag,
            [this, target, expected_runtime_generation,
             lease = std::make_shared<TargetedProbeAdmission::Lease>(
                 std::move(lease))]() mutable {
                InterfaceProbe::Observation observation;
                try {
                    observation = interface_probe_.measure_one(target);
                } catch (...) {
                    // The lease dies with this lambda, so the row becomes
                    // clickable again rather than staying stuck.
                    return;
                }
                (void)post_control_task(
                    [this, target, expected_runtime_generation,
                     observation = std::move(observation), lease]() {
                        try {
                            const auto current_targets =
                                collect_interface_probe_targets(
                                    active_config_snapshot_->config,
                                    active_config_snapshot_
                                        ->outbound_marks);
                            // The config may have been reloaded while we were
                            // on the network. Publishing then would attach a
                            // latency measured for one transport to whatever
                            // now answers to that tag.
                            if (!interface_probe_target_is_current(
                                    expected_runtime_generation,
                                    runtime_generation_.load(
                                        std::memory_order_acquire),
                                    target,
                                    current_targets)) {
                                return;
                            }
                            std::vector<std::string> affected_urltests;
                            if (urltest_manager_) {
                                affected_urltests = find_affected_urltests(
                                    active_config_snapshot_->config.outbounds.value_or(
                                        std::vector<Outbound>{}),
                                    {target.tag});
                            }
                            const bool transitioned =
                                interface_probe_.commit_observation(
                                    observation);
                            if (urltest_manager_ && transitioned) {
                                for (const auto& urltest_tag :
                                     affected_urltests) {
                                    urltest_manager_
                                        ->trigger_external_health_test(
                                            urltest_tag);
                                }
                            }
#ifdef WITH_API
                            if (status_stream_) {
                                try {
                                    status_stream_->reconcile();
                                } catch (...) {
                                }
                            }
#endif
                        } catch (const std::exception& error) {
                            try {
                                Logger::instance().info(
                                    "Targeted probe result for '{}' could "
                                    "not be published: {}",
                                    target.tag,
                                    error.what());
                            } catch (...) {
                            }
                        } catch (...) {
                        }
                    },
                    "targeted-interface-probe-result:" + target.tag);
            });

        // try_post may have refused without taking the lambda, in which case
        // the lease above is still ours and releases on scope exit.
        return posted;
    } catch (...) {
        return false;
    }
}

void Daemon::start_interface_probe_round() noexcept {
    const bool failure_retry_round =
        interface_probe_failure_retry_.consume_for_round();
    try {
        start_interface_probe_round_impl(failure_retry_round);
    } catch (const std::exception& error) {
        // Admission happens before target snapshots, metrics tokens and queue
        // closures allocate. Any of those may throw, including a recursively
        // launched trailing round, so the outer boundary must always release
        // the gate rather than leave it permanently in-flight.
        (void)interface_probe_gate_.abort();
        try {
            Logger::instance().info(
                "Interface probe round could not be started: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        (void)interface_probe_gate_.abort();
        try {
            Logger::instance().info(
                "Interface probe round could not be started: unknown error");
        } catch (...) {
        }
    }
}

void Daemon::start_interface_probe_round_impl(
    bool failure_retry_round) {
    const auto generation = active_config_snapshot_;
    const auto configured_targets = collect_interface_probe_targets(
        generation->config, generation->outbound_marks);
    const auto expected_runtime_generation =
        runtime_generation_.load(std::memory_order_acquire);

    // Always the complete set. retain_only prunes to what it is given, so
    // handing it a rotation slice would drop every target absent from this
    // tick - the health of eight outbounds erased as a side effect of probing
    // two.
    interface_probe_.retain_only(configured_targets);

    // A periodic tick measures a slice; a manual round and a failure retry
    // measure everything. The operator asking for a refresh wants the screen
    // to be right, and a retry exists precisely because the previous full
    // attempt did not land.
    auto targets = configured_targets;
    if (interface_probe_round_rotates_ && !failure_retry_round) {
        auto rotation = select_interface_probe_rotation(
            configured_targets, interface_probe_cursor_);
        interface_probe_cursor_ = rotation.next_cursor;
        targets = std::move(rotation.slice);
    }
    // Consumed: the next round is full unless a scheduler tick says otherwise.
    interface_probe_round_rotates_ = false;

    if (targets.empty()) {
        auto task_metrics =
            periodic_task_metrics_.begin("interface-probe");
        task_metrics.noop();
        complete_interface_probe_round();
        return;
    }
    auto task_metrics = std::make_shared<PeriodicTaskRunToken>(
        periodic_task_metrics_.begin("interface-probe"));
    auto publication_failed =
        std::make_shared<std::atomic<bool>>(false);
    // Probing blocks on the network, so it must not run on the event loop.
    bool enqueued = false;
    try {
        enqueued = blocking_executor_.try_post(
            "interface-probe",
            [this,
             targets,
             expected_runtime_generation,
             failure_retry_round,
             publication_failed,
             task_metrics]() {
            auto abort_gate = [this](Daemon*) noexcept {
                (void)interface_probe_gate_.abort();
            };
            std::unique_ptr<Daemon, decltype(abort_gate)> gate_guard(
                this, abort_gate);
            std::string probe_error;
            try {
                const bool all_results_posted =
                    interface_probe_.measure_each(
                        targets,
                        [this,
                         expected_runtime_generation,
                         publication_failed](
                            InterfaceProbe::Observation observation) {
                    const auto target = observation.target;
                    return post_control_task(
                        [this,
                         target,
                         expected_runtime_generation,
                         observation = std::move(observation),
                         publication_failed]() {
                            try {
                                const auto current_targets =
                                    collect_interface_probe_targets(
                                        active_config_snapshot_->config,
                                        active_config_snapshot_
                                            ->outbound_marks);
                                if (!interface_probe_target_is_current(
                                        expected_runtime_generation,
                                        runtime_generation_.load(
                                            std::memory_order_acquire),
                                        target,
                                        current_targets)) {
                                    return;
                                }

                                // Resolve the dependent selectors before the
                                // observation consumes its transition edge.
                                // An allocation failure here leaves the old
                                // observation authoritative, so the trailing
                                // interface round can retry the same edge.
                                std::vector<std::string>
                                    affected_urltests;
                                if (urltest_manager_) {
                                    affected_urltests =
                                        find_affected_urltests(
                                            active_config_snapshot_->config.outbounds.value_or(
                                                std::vector<Outbound>{}),
                                            {target.tag});
                                }
                                const bool transitioned =
                                    interface_probe_.commit_observation(
                                        observation);
                                if (urltest_manager_ && transitioned) {
                                    for (const auto& urltest_tag :
                                         affected_urltests) {
                                        urltest_manager_
                                            ->trigger_external_health_test(
                                                urltest_tag);
                                        try {
                                            Logger::instance().trace(
                                                "urltest_transition_probe",
                                                "tag={} changed_children=1",
                                                urltest_tag);
                                        } catch (...) {
                                        }
                                    }
                                }
#ifdef WITH_API
                                if (status_stream_) {
                                    try {
                                        status_stream_->reconcile();
                                    } catch (const std::exception& error) {
                                        try {
                                            Logger::instance().trace(
                                                "interface_probe_status_skip",
                                                "tag={} error={}",
                                                target.tag,
                                                error.what());
                                        } catch (...) {
                                        }
                                    } catch (...) {
                                    }
                                }
#endif
                            } catch (const std::exception& error) {
                                publication_failed->store(
                                    true, std::memory_order_release);
                                try {
                                    Logger::instance().info(
                                        "Interface probe result for '{}' "
                                        "could not be published: {}",
                                        target.tag,
                                        error.what());
                                } catch (...) {
                                }
                            } catch (...) {
                                publication_failed->store(
                                    true, std::memory_order_release);
                                try {
                                    Logger::instance().info(
                                        "Interface probe result for '{}' "
                                        "could not be published: unknown "
                                        "error",
                                        target.tag);
                                } catch (...) {
                                }
                            }
                        },
                        "interface-probe-result:" + target.tag);
                        });
                if (!all_results_posted) {
                    probe_error =
                        "control loop is not accepting probe results";
                }
            } catch (const std::exception& error) {
                probe_error = error.what();
            } catch (...) {
                probe_error = "interface probe failed";
            }
            bool posted = false;
            try {
                posted = post_control_task(
                    [this,
                     targets,
                     expected_runtime_generation,
                     failure_retry_round,
                     probe_error = std::move(probe_error),
                     publication_failed,
                     task_metrics]() {
                    const bool accepting_commits =
                        accept_posted_control_tasks_.load(
                            std::memory_order_acquire);
                    const bool result_publication_failed =
                        publication_failed->load(
                            std::memory_order_acquire);
                    bool authority_failed =
                        result_publication_failed || !probe_error.empty();
                    bool snapshot_known = false;
                    bool snapshot_current = false;
                    bool request_trailing = false;

                    try {
                        const auto current_targets =
                            collect_interface_probe_targets(
                                active_config_snapshot_->config,
                                active_config_snapshot_
                                    ->outbound_marks);
                        snapshot_current =
                            interface_probe_snapshot_is_current(
                                expected_runtime_generation,
                                runtime_generation_.load(
                                    std::memory_order_acquire),
                                targets,
                                current_targets);
                        snapshot_known = true;
                    } catch (const std::exception& error) {
                        authority_failed = true;
                        try {
                            task_metrics->failure(error.what());
                        } catch (...) {
                        }
                    } catch (...) {
                        authority_failed = true;
                        try {
                            task_metrics->failure(
                                "interface probe commit failed");
                        } catch (...) {
                        }
                    }

                    if (snapshot_known && !snapshot_current) {
                        // Every per-result task used the narrow fence. Hand
                        // one fresh full snapshot to the existing coalescing
                        // gate, but do not consume the failure-retry budget of
                        // this obsolete round.
                        request_trailing = accepting_commits;
                        try {
                            task_metrics->skipped(
                                "stale runtime generation or probe targets");
                        } catch (...) {
                        }
                    } else if (snapshot_known) {
                        if (!probe_error.empty()) {
                            try {
                                task_metrics->failure(probe_error);
                            } catch (...) {
                            }
                        } else {
                            std::string reconciliation_error;
                            if (routing_runtime_active()) {
                                // Keenetic may recreate a tunnel route without
                                // changing administrative UP. Route this
                                // repair through the one coalescing runtime
                                // worker instead of opening a synchronous
                                // writer between worker mutation and its
                                // control-loop publication checkpoint.
                                try {
                                    const auto disposition =
                                        refresh_iproute_and_firewall_runtime(
                                            0,
                                            {},
                                            /*schedule_catalog_refresh=*/
                                                false);
                                    if (disposition ==
                                        RuntimeFirewallImmediateDisposition::
                                            rejected) {
                                        reconciliation_error =
                                            "central runtime routing refresh "
                                            "was not accepted";
                                    }
                                } catch (const std::exception& error) {
                                    reconciliation_error = error.what();
                                    try {
                                        Logger::instance().info(
                                            "Interface-probe central runtime "
                                            "refresh was deferred: "
                                            "{}",
                                            error.what());
                                    } catch (...) {
                                    }
                                }
                            }
#ifdef WITH_API
                            if (status_stream_) {
                                try {
                                    status_stream_->reconcile();
                                } catch (const std::exception& error) {
                                    try {
                                        Logger::instance().trace(
                                            "interface_probe_status_skip",
                                            "phase=round error={}",
                                            error.what());
                                    } catch (...) {
                                    }
                                } catch (...) {
                                }
                            }
#endif
                            try {
                                if (result_publication_failed) {
                                    task_metrics->failure(
                                        "one or more interface probe results "
                                        "could not be published");
                                } else if (
                                    reconciliation_error.empty()) {
                                    task_metrics->success();
                                } else {
                                    task_metrics->failure(
                                        reconciliation_error);
                                }
                            } catch (...) {
                            }
                        }
                    }

                    const bool failure_retry_eligible =
                        accepting_commits &&
                        (!snapshot_known || snapshot_current);
                    if (authority_failed &&
                        interface_probe_failure_retry_.request(
                            failure_retry_round,
                            failure_retry_eligible)) {
                        request_trailing = true;
                    }
                    if (request_trailing) {
                        try {
                            (void)interface_probe_gate_.request(
                                /*manual=*/false);
                        } catch (...) {
                        }
                    }
                    complete_interface_probe_round();
                    },
                    "interface-probe-status");
            } catch (const std::exception& error) {
                // The worker no longer owns a usable control-loop handoff.
                // Release both periodic and manual admission before recording
                // the failure, even if metrics allocation were to fail.
                gate_guard.reset();
                try {
                    task_metrics->failure(error.what());
                } catch (...) {
                }
                return;
            } catch (...) {
                gate_guard.reset();
                try {
                    task_metrics->failure(
                        "interface probe control handoff failed");
                } catch (...) {
                }
                return;
            }
            if (!posted) {
                gate_guard.reset();
                try {
                    task_metrics->skipped(
                        "control loop is not accepting commits");
                } catch (...) {
                }
                return;
            }
            // The queued completion callback now owns exactly one release of
            // this round. No worker exception may abort it after admission.
            (void)gate_guard.release();
            });
    } catch (const std::exception& error) {
        // Capturing the worker closure and queue insertion may allocate. A
        // failed handoff must release the already admitted round.
        (void)interface_probe_gate_.abort();
        task_metrics->failure(error.what());
        return;
    } catch (...) {
        (void)interface_probe_gate_.abort();
        task_metrics->failure("interface probe executor handoff failed");
        return;
    }
    if (!enqueued) {
        task_metrics->skipped("blocking executor is unavailable");
        (void)interface_probe_gate_.abort();
    }
}

void Daemon::complete_interface_probe_round() noexcept {
    const auto completion = interface_probe_gate_.complete();
    if (completion.launch_trailing) {
        start_interface_probe_round();
    }
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
                const auto it =
                    active_config_snapshot_->outbound_marks.find(detour);
                if (it !=
                    active_config_snapshot_->outbound_marks.end()) {
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

    // A repeating timer owns periodic liveness independently of an
    // individual probe round. A coalesced tick or any fenced callback failure
    // therefore cannot silently remove the next 20-second observation.
    scheduler_->schedule_repeating(
        kInterval,
        [this]() {
            probe_interfaces_now();
        },
        "interface-probe");
}

void Daemon::schedule_lists_autoupdate() {
    // This method is also called after a post-apply refresh completes. Replace
    // the previous one-shot instead of accumulating duplicate timers.
    if (lists_autoupdate_task_id_ >= 0) {
        scheduler_->cancel(lists_autoupdate_task_id_);
        lists_autoupdate_task_id_ = -1;
    }
    if (!active_config_snapshot_->config.lists_autoupdate) return;
    if (!active_config_snapshot_->config.lists_autoupdate->enabled.value_or(false)) return;
    const auto& expr = active_config_snapshot_->config.lists_autoupdate->cron.value_or("");
    auto next = cron_next(expr);
    const auto now = std::chrono::system_clock::now();
    auto delay = std::chrono::ceil<std::chrono::seconds>(next - now);
    if (delay.count() < 1) delay = std::chrono::seconds{1};
    lists_autoupdate_task_id_ = scheduler_->schedule_oneshot(
        delay,
        [this]() {
            lists_autoupdate_task_id_ = -1;
            refresh_lists_and_maybe_reload_async();
        },
        "lists-autoupdate");
    Logger::instance().info("Lists autoupdate scheduled (next: ~{}s)", delay.count());
}

CacheCommitCallback Daemon::make_guarded_cache_commit_callback() {
    return [this](const std::function<void()>& commit) {
        KPBR_SHARED_UNIQUE_LOCK(
            cache_commit,
            resolver_cache_snapshot_mutex_);
        commit();
    };
}

void Daemon::commit_remote_list_refresh_task_result(
    std::string task_id,
    ListRefreshCancellationToken cancellation,
    std::uint64_t generation,
    bool reload,
    std::optional<RemoteListsRefreshResult> refresh_result,
    std::string error,
    std::string source,
    TraceId trace_id) {
    const bool reschedule = source == "autoupdate" || source == "post-apply";
    const std::string fallback_task_id = task_id;
    const ListRefreshCancellationToken fallback_cancellation = cancellation;
    auto completion_result =
        std::make_shared<std::optional<RemoteListsRefreshResult>>(
            std::move(refresh_result));
    const bool posted = post_control_task(
        [this,
         task_id = std::move(task_id),
         cancellation = std::move(cancellation),
         generation,
         reload,
         completion_result,
         error = std::move(error),
         source = std::move(source),
         trace_id,
         reschedule]() mutable {
            ScopedTraceContext trace_scope_inner(trace_id);
            auto& refresh_result = *completion_result;
            const bool force_reconcile =
                list_refresh_tasks_.force_reconcile_requested(task_id);

            const auto schedule_next = [this, reschedule]() {
                if (reschedule) schedule_lists_autoupdate();
            };
            const auto finish_cancelled = [&]() {
                (void)list_refresh_tasks_.finish_cancelled(
                    task_id,
                    "list refresh cancelled",
                    refresh_result.value_or(RemoteListsRefreshResult{}));
                schedule_next();
            };
            const auto finish_failed = [&](std::string message) {
                (void)list_refresh_tasks_.fail(
                    task_id,
                    std::move(message),
                    refresh_result.value_or(RemoteListsRefreshResult{}));
                schedule_next();
            };
            struct ListRefreshReconcileCompletion final {
                std::string task_id;
                ListRefreshCancellationToken cancellation;
                RemoteListsRefreshResult refresh_result;
                std::string refresh_error;
                std::string source;
                bool reschedule{false};
                std::uint64_t expected_lease_token{0U};
            };

            const auto schedule_forced_reconcile =
                [this](const std::string& retry_source) noexcept {
                try {
                    schedule_deferred_list_refresh(
                        retry_source,
                        runtime_generation_.load(
                            std::memory_order_acquire),
                        /*force_reconcile=*/true);
                } catch (const std::exception& retry_error) {
                    try {
                        Logger::instance().error(
                            "Lists refresh forced reconcile could not be "
                            "scheduled: {}",
                            retry_error.what());
                    } catch (...) {
                    }
                } catch (...) {
                    try {
                        Logger::instance().error(
                            "Lists refresh forced reconcile could not be "
                            "scheduled");
                    } catch (...) {
                    }
                }
            };

            const auto start_runtime_reconcile =
                [this,
                 &task_id,
                 &cancellation,
                 &source,
                 reschedule,
                 schedule_forced_reconcile](
                    RemoteListsRefreshResult committed,
                    std::string completion_error) {
                std::shared_ptr<ListRefreshReconcileCompletion> state;
                try {
                    state =
                        std::make_shared<ListRefreshReconcileCompletion>();
                    state->task_id = task_id;
                    state->cancellation = cancellation;
                    state->source = source;
                    state->reschedule = reschedule;
                    state->refresh_error = std::move(completion_error);
                    state->refresh_result = std::move(committed);
                } catch (const std::exception& setup_error) {
                    const bool cancelled =
                        cancellation.cancellation_requested();
                    if (cancelled) {
                        (void)list_refresh_tasks_.finish_cancelled(
                            task_id,
                            "list refresh cancelled after committing "
                            "completed lists",
                            std::move(committed),
                            false);
                    } else {
                        (void)list_refresh_tasks_.fail(
                            task_id,
                            setup_error.what(),
                            std::move(committed),
                            false);
                    }
                    schedule_forced_reconcile(source);
                    return;
                } catch (...) {
                    if (cancellation.cancellation_requested()) {
                        (void)list_refresh_tasks_.finish_cancelled(
                            task_id,
                            "list refresh cancelled after committing "
                            "completed lists",
                            std::move(committed),
                            false);
                    } else {
                        (void)list_refresh_tasks_.fail(
                            task_id,
                            "failed to prepare committed list reconcile",
                            std::move(committed),
                            false);
                    }
                    schedule_forced_reconcile(source);
                    return;
                }

                const auto fail_before_owner =
                    [this,
                     state,
                     schedule_forced_reconcile](
                        std::string message,
                        std::unique_ptr<
                            RuntimeMutationAdmission::Lease> exact) {
                    try {
                        if (state->cancellation.cancellation_requested()) {
                            (void)list_refresh_tasks_.finish_cancelled(
                                state->task_id,
                                "list refresh cancelled after committing "
                                "completed lists",
                                std::move(state->refresh_result),
                                false);
                        } else {
                            (void)list_refresh_tasks_.fail(
                                state->task_id,
                                std::move(message),
                                std::move(state->refresh_result),
                                false);
                        }
                    } catch (...) {
                    }
                    exact.reset();
                    schedule_forced_reconcile(state->source);
                };

                const bool applying =
                    list_refresh_tasks_.mark_applying(state->task_id);
                if (!applying &&
                    !state->cancellation.cancellation_requested()) {
                    fail_before_owner(
                        "list refresh task left the running state before "
                        "runtime reconcile",
                        {});
                    return;
                }

                ActiveConfigSnapshotHandle base_active_snapshot;
                PreparedRuntimeInputs candidate;
                PreparedRuntimeInputs rollback;
                try {
                    base_active_snapshot =
                        config_store_.pin_active_snapshot();
                    if (!base_active_snapshot) {
                        fail_before_owner(
                            "active configuration snapshot is unavailable",
                            {});
                        return;
                    }
                    // The worker has already atomically committed cache files.
                    // Candidate preparation therefore sees the new immutable
                    // cache generation. The active-reload transaction replaces
                    // rollback resolver/list inputs with its exact published
                    // generation before either firewall phase starts.
                    candidate = prepare_runtime_inputs(
                        base_active_snapshot->config,
                        RemoteListPreparationMode::None);
                    rollback = prepare_runtime_inputs(
                        base_active_snapshot->config,
                        RemoteListPreparationMode::None);
                } catch (const std::exception& preparation_error) {
                    fail_before_owner(
                        std::string{
                            "failed to prepare committed list reconcile: "} +
                            preparation_error.what(),
                        {});
                    return;
                } catch (...) {
                    fail_before_owner(
                        "failed to prepare committed list reconcile",
                        {});
                    return;
                }

                auto taken = list_refresh_tasks_.take_mutation_lease(
                    state->task_id);
                if (!taken || !taken.lease ||
                    !runtime_mutation_admission_.owns(*taken.lease)) {
                    fail_before_owner(
                        "committed list reconcile did not receive its exact "
                        "mutation lease",
                        std::move(taken.lease));
                    return;
                }
                state->expected_lease_token = taken.lease->token();

                try {
                    RuntimeFirewallPreownedTerminalContinuation continuation{
                        [this,
                         state,
                         schedule_forced_reconcile](
                            RuntimeFirewallLifecycleTerminal terminal,
                            std::unique_ptr<
                                RuntimeMutationAdmission::Lease> exact) mutable
                            noexcept {
                            const bool exact_lease_returned = exact &&
                                static_cast<bool>(*exact) &&
                                exact->token() ==
                                    state->expected_lease_token &&
                                runtime_mutation_admission_.owns(*exact);
                            const bool verified_terminal =
                                terminal.outcome ==
                                    RuntimeFirewallLifecycleOutcome::
                                        verified_success &&
                                !terminal.commit_ambiguous &&
                                terminal.observed_config_identity.has_value();
                            const bool candidate_published =
                                exact_lease_returned && verified_terminal &&
                                terminal.observed_config_identity->kind ==
                                    ConfigTerminalOperationKind::candidate &&
                                (terminal.committed ||
                                 terminal.candidate_noop_verified);
                            const bool rollback_verified =
                                exact_lease_returned && verified_terminal &&
                                terminal.observed_config_identity->kind ==
                                    ConfigTerminalOperationKind::rollback &&
                                (terminal.committed ||
                                 terminal.candidate_noop_verified);

                            std::string owner_error;
                            try {
                                if (!exact_lease_returned) {
                                    owner_error =
                                        "runtime reconcile did not return its "
                                        "exact mutation lease";
                                } else if (rollback_verified) {
                                    owner_error = terminal.detail.empty()
                                        ? "committed list reconcile was "
                                          "rolled back"
                                        : terminal.detail;
                                } else if (!candidate_published) {
                                    owner_error = terminal.detail.empty()
                                        ? "committed list reconcile terminal "
                                          "is unknown"
                                        : terminal.detail;
                                }

                                if (state->cancellation.
                                        cancellation_requested()) {
                                    std::string cancellation_error =
                                        "list refresh cancelled after "
                                        "committing completed lists";
                                    if (!candidate_published &&
                                        !owner_error.empty()) {
                                        cancellation_error += ": ";
                                        cancellation_error += owner_error;
                                    }
                                    (void)list_refresh_tasks_.
                                        finish_cancelled(
                                            state->task_id,
                                            std::move(cancellation_error),
                                            std::move(
                                                state->refresh_result),
                                            candidate_published);
                                } else if (!candidate_published) {
                                    (void)list_refresh_tasks_.fail(
                                        state->task_id,
                                        std::move(owner_error),
                                        std::move(state->refresh_result),
                                        false);
                                } else if (!state->refresh_error.empty()) {
                                    (void)list_refresh_tasks_.fail(
                                        state->task_id,
                                        std::move(state->refresh_error),
                                        std::move(state->refresh_result),
                                        true);
                                } else if (
                                    state->refresh_result.any_failed()) {
                                    const std::string message =
                                        "failed to refresh list(s): " +
                                        format_list_names(
                                            state->refresh_result.
                                                failed_lists);
                                    (void)list_refresh_tasks_.fail(
                                        state->task_id,
                                        message,
                                        std::move(state->refresh_result),
                                        true);
                                } else {
                                    (void)list_refresh_tasks_.succeed(
                                        state->task_id,
                                        std::move(state->refresh_result),
                                        true);
                                }
                            } catch (...) {
                                try {
                                    (void)list_refresh_tasks_.fail(
                                        state->task_id,
                                        "committed list reconcile "
                                        "continuation failed",
                                        std::move(state->refresh_result),
                                        candidate_published);
                                } catch (...) {
                                }
                            }

                            // Task terminal publication is complete. Return
                            // global mutation admission before installing
                            // either retry/cadence scheduler work.
                            exact.reset();
                            if (!candidate_published) {
                                schedule_forced_reconcile(state->source);
                            } else if (state->reschedule) {
                                try {
                                    schedule_lists_autoupdate();
                                } catch (...) {
                                }
                            }
                        }};
                    begin_preowned_runtime_firewall_active_reload(
                        std::move(taken.lease),
                        std::move(base_active_snapshot),
                        std::move(candidate),
                        std::move(rollback),
                        std::move(continuation));
                } catch (const std::exception& owner_error) {
                    fail_before_owner(
                        owner_error.what(), std::move(taken.lease));
                } catch (...) {
                    fail_before_owner(
                        "committed list reconcile owner setup failed",
                        std::move(taken.lease));
                }
            };

            // A callback admitted immediately before shutdown may still be in
            // the final control-loop drain. Cache files are already safe for
            // the next startup, but mutating DNS/firewall/runtime here would
            // race teardown and could enqueue fresh network work.
            if (finish_list_refresh_if_shutting_down(
                    accept_posted_control_tasks_.load(
                        std::memory_order_acquire),
                    list_refresh_tasks_,
                    task_id,
                    refresh_result)) {
                return;
            }

            if (generation != runtime_generation_.load(std::memory_order_acquire)) {
                Logger::instance().trace("lists_refresh_skip",
                                         "source={} generation={} reason=stale_runtime",
                                         source,
                                         generation);
                if (!refresh_result ||
                    (!refresh_result->any_changed() && !force_reconcile)) {
                    if (cancellation.cancellation_requested()) {
                        finish_cancelled();
                    } else {
                        finish_failed(
                            "runtime changed while lists were being refreshed");
                    }
                    return;
                }

                RemoteListsRefreshResult committed =
                    std::move(*refresh_result);
                refresh_result.reset();
                if (should_reconcile_committed_list_cache(
                        reload,
                        force_reconcile,
                        routing_runtime_active(),
                        committed.any_changed())) {
                    start_runtime_reconcile(
                        std::move(committed), error);
                    return;
                }

                bool reloaded = false;
                if (cancellation.cancellation_requested()) {
                    (void)list_refresh_tasks_.finish_cancelled(
                        task_id,
                        "list refresh cancelled after committing completed lists",
                        std::move(committed),
                        reloaded);
                } else if (!error.empty() || committed.any_failed()) {
                    const std::string message = !error.empty()
                        ? error
                        : "failed to refresh list(s): " +
                              format_list_names(committed.failed_lists);
                    (void)list_refresh_tasks_.fail(
                        task_id,
                        message,
                        std::move(committed),
                        reloaded);
                } else {
                    (void)list_refresh_tasks_.succeed(
                        task_id, std::move(committed), reloaded);
                }
                schedule_next();
                return;
            }

            if (cancellation.cancellation_requested() &&
                (!refresh_result ||
                 (!refresh_result->any_changed() && !force_reconcile))) {
                finish_cancelled();
                return;
            }

            if (!refresh_result) {
                if (cancellation.cancellation_requested()) {
                    finish_cancelled();
                    return;
                }
                const std::string message = error.empty()
                    ? "list refresh completed without a result"
                    : error;
                Logger::instance().error(
                    "Lists refresh ({}) failed: {}", source, message);
                finish_failed(message);
                return;
            }

            if (cancellation.cancellation_requested()) {
                RemoteListsRefreshResult committed =
                    std::move(*refresh_result);
                refresh_result.reset();
                if (should_reconcile_committed_list_cache(
                        reload,
                        force_reconcile,
                        routing_runtime_active(),
                        committed.any_changed())) {
                    start_runtime_reconcile(
                        std::move(committed), error);
                    return;
                }
                (void)list_refresh_tasks_.finish_cancelled(
                    task_id,
                    "list refresh cancelled after committing completed lists",
                    std::move(committed),
                    false);
                schedule_next();
                return;
            }

            ListsRefreshExecutionResult result;
            result.refresh_result = std::move(*refresh_result);
            refresh_result.reset();

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

            if (!error.empty()) {
                if (should_reconcile_committed_list_cache(
                        reload,
                        force_reconcile,
                        routing_runtime_active(),
                        result.refresh_result.any_changed())) {
                    start_runtime_reconcile(
                        std::move(result.refresh_result), error);
                    return;
                }
                Logger::instance().error(
                    "Lists refresh ({}) failed: {}",
                    source,
                    error);
                (void)list_refresh_tasks_.fail(
                    task_id,
                    error,
                    std::move(result.refresh_result),
                    false);
                schedule_next();
                return;
            }
            if (force_reconcile &&
                should_reconcile_committed_list_cache(
                    reload,
                    force_reconcile,
                    routing_runtime_active(),
                    result.refresh_result.any_changed())) {
                Logger::instance().info(
                    "Lists refresh ({}): applying an upgraded reload request "
                    "against the current runtime generation",
                    source);
                start_runtime_reconcile(
                    std::move(result.refresh_result), error);
                return;
            } else if (reload && should_reload_runtime_after_list_refresh(
                                     routing_runtime_active(),
                                     result.refresh_result)) {
                Logger::instance().info(
                    "Lists refresh ({}): relevant list(s) changed ({}), reloading runtime",
                    source,
                    format_list_names(result.refresh_result.relevant_changed_lists));
                start_runtime_reconcile(
                    std::move(result.refresh_result), error);
                return;
            } else if (result.refresh_result.any_relevant_changed()) {
                Logger::instance().info(
                    (reload || force_reconcile)
                        ? "Lists refresh: relevant list(s) changed ({}), but runtime is stopped"
                        : "Lists refresh: relevant list(s) changed ({}); runtime reload was not requested",
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

            if (cancellation.cancellation_requested()) {
                (void)list_refresh_tasks_.finish_cancelled(
                    task_id,
                    "list refresh cancelled after committing completed lists",
                    std::move(result.refresh_result),
                    result.reloaded);
            } else if (result.refresh_result.any_failed()) {
                const std::string message =
                    "failed to refresh list(s): " +
                    format_list_names(result.refresh_result.failed_lists);
                (void)list_refresh_tasks_.fail(
                    task_id,
                    message,
                    std::move(result.refresh_result),
                    result.reloaded);
            } else {
                (void)list_refresh_tasks_.succeed(
                    task_id,
                    std::move(result.refresh_result),
                    result.reloaded);
            }
            schedule_next();
        },
        "lists-refresh-commit");

    if (!posted) {
        const auto partial =
            completion_result->value_or(RemoteListsRefreshResult{});
        if (fallback_cancellation.cancellation_requested()) {
            (void)list_refresh_tasks_.finish_cancelled(
                fallback_task_id, "daemon is shutting down", partial);
        } else {
            (void)list_refresh_tasks_.fail(
                fallback_task_id,
                "list refresh result could not be committed",
                partial);
        }
    }
}

RemoteListRefreshTaskStartResult Daemon::start_remote_list_refresh_task(
    bool reload,
    std::string source,
    bool force_reconcile) {
    auto& log = Logger::instance();

    if (!accept_posted_control_tasks_.load(std::memory_order_acquire)) {
        return {false, {}, "daemon is shutting down"};
    }

    std::optional<RuntimeMutationLeaseHandoff>
        mutation_lease_handoff;
    if (reload) {
        auto admitted = runtime_mutation_admission_.try_acquire(
            "lists-refresh-" + source);
        if (!admitted.has_value()) {
            const bool retain_force = merge_list_refresh_force_reconcile(
                force_reconcile,
                list_refresh_tasks_.active().has_value());
            return {false, {}, "busy", retain_force};
        }
        mutation_lease_handoff.emplace(
            std::make_unique<
                RuntimeMutationAdmission::Lease>(
                    std::move(*admitted)));
    }

    const auto active_generation = active_config_snapshot_;
    const auto& config_snapshot = active_generation->config;
    const auto target_selection =
        select_remote_list_targets(config_snapshot, std::nullopt);
    if (!target_selection.ok()) {
        return {false, {}, "failed to select remote lists"};
    }

    auto started = list_refresh_tasks_.begin(
        target_selection.list_names.size(),
        std::move(mutation_lease_handoff),
        /*upgrade_active=*/reload,
        /*force_new=*/force_reconcile);
    if (started.coalesced) {
        Logger::instance().trace(
            "lists_refresh_upgrade",
            "source={} task_id={} reconcile=current",
            source,
            started.task.id);
        if (source == "autoupdate" || source == "post-apply") {
            // The active task keeps its original source, so preserve this
            // caller's cron ownership now instead of waiting for its terminal
            // callback to schedule a cadence it does not know about.
            schedule_lists_autoupdate();
        }
        return {true, std::move(started.task), {}};
    }
    if (!started.accepted) {
        Logger::instance().trace("lists_refresh_skip",
                                 "source={} reason=inflight",
                                 source);
        return {
            false,
            std::move(started.task),
            "busy",
            merge_list_refresh_force_reconcile(
                force_reconcile, /*incoming=*/true)};
    }

    log.info("Lists refresh ({}): checking for updates", source);
    const std::string task_id = started.task.id;
    const ListRefreshCancellationToken cancellation = started.cancellation;
    const auto relevant_lists = collect_relevant_list_names(config_snapshot);
    const auto dns_relevant_lists = collect_dns_relevant_list_names(config_snapshot);
    const auto generation = runtime_generation_.load(std::memory_order_acquire);
    const TraceId trace_id = ensure_trace_id();
    const std::string executor_label = "lists-refresh-" + source;

    const bool enqueued = blocking_executor_.try_post(
        executor_label,
        [this,
         task_id,
         cancellation,
         active_generation,
         relevant_lists,
         dns_relevant_lists,
         generation,
         reload,
         source,
         trace_id]() mutable {
            ScopedTraceContext trace_scope(trace_id);
            std::optional<RemoteListsRefreshResult> refresh_result;
            std::string error;

            if (!list_refresh_tasks_.mark_running(task_id)) {
                return;
            }
            Logger::instance().trace("lists_refresh_start",
                                     "source={} generation={} task_id={}",
                                     source,
                                     generation,
                                     task_id);
            try {
                RemoteListRefreshControl control;
                control.cancellation = cancellation.shared_flag();
                control.progress = [this, task_id](
                                       const RemoteListRefreshProgress& progress) {
                    std::optional<std::string> current;
                    if (!progress.list_name.empty()) {
                        current = progress.list_name;
                    }
                    (void)list_refresh_tasks_.update_progress(
                        task_id,
                        progress.completed,
                        std::move(current));
                };
                control.cache_commit =
                    make_guarded_cache_commit_callback();
                refresh_result = list_service_.refresh_remote_lists(
                    active_generation->config,
                    active_generation->outbound_marks,
                    &relevant_lists,
                    nullptr,
                    &dns_relevant_lists,
                    control);
            } catch (const RemoteListRefreshCancelled& e) {
                refresh_result = e.partial_result();
                error = e.what();
            } catch (const std::exception& e) {
                error = e.what();
            }

            commit_remote_list_refresh_task_result(
                task_id,
                cancellation,
                generation,
                reload,
                std::move(refresh_result),
                std::move(error),
                std::move(source),
                trace_id);
        },
        trace_id);

    if (!enqueued) {
        const std::string error = "list refresh executor is unavailable";
        (void)list_refresh_tasks_.fail(task_id, error);
        Logger::instance().trace("lists_refresh_skip",
                                 "source={} reason=executor_unavailable",
                                 source);
        const auto failed = list_refresh_tasks_.find(task_id);
        return {false, failed.value_or(started.task), error};
    }

    return {true, std::move(started.task), {}};
}

void Daemon::refresh_lists_and_maybe_reload_async(
    std::string source,
    bool force_reconcile) {
    const bool reschedule = source == "autoupdate" || source == "post-apply";
    const auto start = start_remote_list_refresh_task(
        true, source, force_reconcile);
    if (!start.accepted) {
        if (start.error == "busy" &&
            (reschedule || start.force_reconcile)) {
            schedule_deferred_list_refresh(
                std::move(source),
                runtime_generation_.load(std::memory_order_acquire),
                start.force_reconcile);
        } else if (reschedule) {
            schedule_lists_autoupdate();
        }
    }
}

void Daemon::schedule_deferred_list_refresh(
    std::string source,
    std::uint64_t runtime_generation,
    bool force_reconcile) {
    lists_runtime_mutation_retry_force_reconcile_ =
        merge_list_refresh_force_reconcile(
            lists_runtime_mutation_retry_force_reconcile_,
            force_reconcile);
    if (lists_runtime_mutation_retry_task_id_ >= 0) {
        const int stale_task_id =
            lists_runtime_mutation_retry_task_id_;
        lists_runtime_mutation_retry_task_id_ = -1;
        try {
            scheduler_->cancel(stale_task_id);
        } catch (const std::exception& error) {
            // Scheduler invalidates the entry before fd cleanup can throw.
            // Keep the OR-merged force bit and install the replacement intent.
            try {
                Logger::instance().verbose(
                    "Lists refresh retry cleanup reported '{}'; replacing "
                    "the intent without dropping forced reconciliation.",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
        }
    }

    constexpr auto kAdmissionRetryDelay = std::chrono::seconds{1};
    const int task_id = scheduler_->schedule_oneshot(
        kAdmissionRetryDelay,
        [this,
         source = std::move(source),
         runtime_generation]() mutable {
            lists_runtime_mutation_retry_task_id_ = -1;
            const bool deferred_force_reconcile =
                lists_runtime_mutation_retry_force_reconcile_;
            lists_runtime_mutation_retry_force_reconcile_ = false;
            const bool accepting_control_tasks =
                accept_posted_control_tasks_.load(
                    std::memory_order_acquire);
            const auto current_runtime_generation =
                runtime_generation_.load(std::memory_order_acquire);
            if (!accepting_control_tasks ||
                (!deferred_force_reconcile &&
                 runtime_generation != current_runtime_generation)) {
                return;
            }
            // A normal delayed refresh belongs to its exact generation. A
            // forced reconcile instead represents durable cache data that
            // cannot be rolled back; rebind it to the current generation.
            refresh_lists_and_maybe_reload_async(
                std::move(source), deferred_force_reconcile);
        },
        "lists-refresh-admission-retry");
    if (task_id < 0) {
        lists_runtime_mutation_retry_force_reconcile_ = false;
        Logger::instance().error(
            "Lists refresh admission retry was rejected; no runtime cursor "
            "was changed.");
        return;
    }
    lists_runtime_mutation_retry_task_id_ = task_id;
    const auto active = runtime_mutation_admission_.active();
    Logger::instance().verbose(
        "Lists refresh deferred behind runtime mutation '{}'.",
        active.has_value() ? active->label : std::string{"unknown"});
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
    prepared.keenetic_dns = prepare_keenetic_dns_view(
        config,
        /*allow_refresh=*/!preparing_on_control_loop);
    prepared.internal_vpn_resolution =
        resolve_internal_vpn_servers_for_runtime(
            config, !preparing_on_control_loop);
    prepared.internal_vpn_service_resolution =
        resolve_internal_vpn_services_for_runtime(
            config, !preparing_on_control_loop);

    if (list_mode != RemoteListPreparationMode::None) {
        RemoteListRefreshControl control;
        control.cache_commit = make_guarded_cache_commit_callback();
        if (list_mode == RemoteListPreparationMode::MissingOrInvalid) {
            const auto result = list_service_.download_uncached(
                prepared.config,
                prepared.outbound_marks,
                nullptr,
                nullptr,
                control);
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
                prepared.outbound_marks,
                nullptr,
                nullptr,
                nullptr,
                control);
        }
        prepared.remote_lists_refreshed = true;
    }

    return prepared;
}

KeeneticDnsCacheView Daemon::prepare_keenetic_dns_view(
    const Config& config,
    bool allow_refresh,
    bool force_refresh) const {
    const DnsConfig dns_config = config.dns.value_or(DnsConfig{});
    if (!dns_config_uses_keenetic_server(dns_config)) {
        return {};
    }

#ifdef USE_KEENETIC_API
    auto& cache = shared_keenetic_dns_cache();
    const KeeneticDnsCacheView view = allow_refresh
        ? (force_refresh ? cache.force_refresh() : cache.get())
        : cache.peek();
    if (!view.snapshot.has_value()) {
        throw KeeneticDnsError(
            view.error.empty()
                ? "Keenetic DNS snapshot is unavailable; refresh it before applying the runtime configuration"
                : view.error);
    }
    return view;
#else
    (void)allow_refresh;
    (void)force_refresh;
    throw KeeneticDnsError(
        "DNS server type 'keenetic' requires build with USE_KEENETIC_API=ON");
#endif
}

InternalVpnRuntimeResolution
Daemon::resolve_internal_vpn_servers_for_runtime(
    const Config& config,
    bool allow_catalog_refresh) {
    const auto configured = config.route.has_value()
        ? config.route->internal_vpn_servers.value_or(
              std::vector<InternalVpnServer>{})
        : std::vector<InternalVpnServer>{};
    if (configured.empty()) {
        return internal_vpn_resolution_cache_.resolve_servers(
            config, NdmsCatalogSnapshot{}, {});
    }
    if (!internal_vpn_server_policies_require_ndms_catalog(configured)) {
        // Legacy exact-interface policies only need the live netlink
        // inventory. Do not add an RCI HTTP timeout to cross-platform startup.
        return resolve_internal_vpn_servers_for_runtime(
            config, NdmsCatalogSnapshot{});
    }

    auto& cache = shared_ndms_catalog_cache();
    const auto snapshot =
        allow_catalog_refresh ? cache.force_refresh() : cache.peek();
    return resolve_internal_vpn_servers_for_runtime(config, snapshot);
}

InternalVpnRuntimeResolution
Daemon::resolve_internal_vpn_servers_for_runtime(
    const Config& config,
    const NdmsCatalogSnapshot& snapshot) {
    try {
        return internal_vpn_resolution_cache_.resolve_servers(
            config, snapshot, netlink_.dump_interfaces());
    } catch (const InternalVpnResolutionError& error) {
        throw DaemonError(error.what());
    }
}

InternalVpnRuntimeResolution
Daemon::prepare_internal_vpn_server_resolution_from_cache() {
    return resolve_internal_vpn_servers_for_runtime(
        active_config_snapshot_->config, false);
}

InternalVpnServiceRuntimeResolution
Daemon::resolve_internal_vpn_services_for_runtime(
    const Config& config,
    bool allow_catalog_refresh) {
    if (!config_requires_internal_vpn_service_inventory(config)) {
        return internal_vpn_resolution_cache_.resolve_services(
            config, NdmsVpnServerServiceSnapshot{}, {});
    }
    auto& cache = shared_ndms_vpn_server_service_cache();
    const auto snapshot =
        allow_catalog_refresh ? cache.force_refresh() : cache.peek();
    return resolve_internal_vpn_services_for_runtime(config, snapshot);
}

InternalVpnServiceRuntimeResolution
Daemon::resolve_internal_vpn_services_for_runtime(
    const Config& config,
    const NdmsVpnServerServiceSnapshot& snapshot) {
    return internal_vpn_resolution_cache_.resolve_services(
        config, snapshot, netlink_.dump_interfaces());
}

InternalVpnServiceRuntimeResolution
Daemon::prepare_internal_vpn_service_resolution_from_cache() {
    return resolve_internal_vpn_services_for_runtime(
        active_config_snapshot_->config, false);
}

void Daemon::schedule_internal_vpn_catalog_refresh() {
    const bool needs_interface_catalog =
        config_has_stable_internal_vpn_server_policy(active_config_snapshot_->config);
    const bool needs_service_catalog =
        config_requires_internal_vpn_service_inventory(active_config_snapshot_->config);
    if (!needs_interface_catalog && !needs_service_catalog) {
        return;
    }
    if (!internal_vpn_catalog_refresh_gate_.request()) {
        return;
    }

    const bool enqueued = blocking_executor_.try_post(
        "internal-vpn-ndms-refresh",
        [this, needs_interface_catalog, needs_service_catalog]() {
            // force_refresh() is single-flight and rate-limited by the cache;
            // this worker is the only place where an interface event may lead
            // to loopback RCI/network I/O.
            std::optional<NdmsCatalogSnapshot> interface_snapshot;
            std::optional<NdmsVpnServerServiceSnapshot> service_snapshot;
            if (needs_interface_catalog) {
                interface_snapshot =
                    shared_ndms_catalog_cache().force_refresh();
            }
            if (needs_service_catalog) {
                service_snapshot =
                    shared_ndms_vpn_server_service_cache().force_refresh();
            }
            post_control_task(
                [this,
                 worker_interface_snapshot =
                     std::move(interface_snapshot),
                 worker_service_snapshot =
                     std::move(service_snapshot)]() {
                    // Finish the single-flight generation only on the control
                    // loop. A topology event observed while the worker was
                    // blocked becomes one immediate replacement generation;
                    // no invalidation is dropped and no parallel RCI fetch is
                    // started.
                    const bool rerun_requested =
                        internal_vpn_catalog_refresh_gate_.complete();
                    const bool rerun_is_valid =
                        rerun_requested &&
                        routing_runtime_active() &&
                        config_has_native_vpn_catalog_policy(active_config_snapshot_->config);
                    if (rerun_is_valid) {
                        schedule_internal_vpn_catalog_refresh();
                    }

                    if (!routing_runtime_active() ||
                        !config_has_native_vpn_catalog_policy(active_config_snapshot_->config)) {
                        return;
                    }
                    const bool current_needs_interface =
                        config_has_stable_internal_vpn_server_policy(active_config_snapshot_->config);
                    const bool current_needs_service =
                        config_requires_internal_vpn_service_inventory(
                            active_config_snapshot_->config);
                    const bool worker_is_fresh =
                        (!current_needs_interface ||
                         (worker_interface_snapshot.has_value() &&
                          worker_interface_snapshot->status ==
                              NdmsCatalogCacheStatus::fresh &&
                          worker_interface_snapshot->refreshed)) &&
                        (!current_needs_service ||
                         (worker_service_snapshot.has_value() &&
                          worker_service_snapshot->status ==
                              NdmsCatalogCacheStatus::fresh &&
                          worker_service_snapshot->refreshed));
                    if (!worker_is_fresh) {
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
                    const auto interface_snapshot =
                        shared_ndms_catalog_cache().peek();
                    const auto service_snapshot =
                        shared_ndms_vpn_server_service_cache().peek();
                    if ((current_needs_interface &&
                         interface_snapshot.status !=
                             NdmsCatalogCacheStatus::fresh) ||
                        (current_needs_service &&
                         service_snapshot.status !=
                             NdmsCatalogCacheStatus::fresh)) {
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
                            active_config_snapshot_->config,
                            interface_snapshot);
                    auto service_resolution =
                        resolve_internal_vpn_services_for_runtime(
                            active_config_snapshot_->config,
                            service_snapshot);
                    if (internal_vpn_resolution_cache_.active_matches(
                            resolution.effective_servers,
                            service_resolution.effective_targets)) {
                        // No kernel replacement is needed, so publishing the
                        // newly verified LKG cannot diverge from forwarding.
                        internal_vpn_resolution_cache_.update_verified_servers(
                            resolution);
                        internal_vpn_resolution_cache_
                            .update_verified_service_targets(
                                service_resolution);
                        publish_runtime_state();
                        return;
                    }
                    // Do not publish candidate resolved/LKG state here. Pass
                    // the prepared authoritative observation into the sole
                    // generation transaction: it commits memory only after
                    // route/firewall succeeds and restores the previous map
                    // on every failure path.
                    auto prepared_catalog =
                        std::make_shared<const PreparedNativeVpnCatalog>(
                            PreparedNativeVpnCatalog{
                                runtime_generation_.load(
                                    std::memory_order_acquire),
                                std::move(resolution),
                                std::move(service_resolution),
                                /*schedule_catalog_refresh=*/true});
                    const auto catalog_generation =
                        prepared_catalog->runtime_generation;
                    const auto disposition =
                        refresh_iproute_and_firewall_runtime(
                            0, std::move(prepared_catalog));
                    if (disposition ==
                            RuntimeFirewallImmediateDisposition::rejected &&
                        !runtime_firewall_owner_->shutdown_requested()) {
                        // No transport owner accepted the authoritative
                        // candidate. Request a fresh catalog generation via
                        // the existing bounded catalog retry owner.
                        schedule_internal_vpn_catalog_refresh_retry(
                            catalog_generation);
                    }
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
            routing_runtime_active() &&
            config_has_native_vpn_catalog_policy(active_config_snapshot_->config)) {
            schedule_internal_vpn_catalog_refresh();
            return;
        }
        schedule_internal_vpn_catalog_refresh_retry(
            runtime_generation_.load(std::memory_order_acquire));
    }
}

void Daemon::schedule_internal_vpn_catalog_refresh_if_needed(
    InternalVpnRuntimeResolutionState interface_state,
    InternalVpnRuntimeResolutionState service_state) {
    // Central lifecycle invariant: no cache-only, non-authoritative stable-ID
    // generation may remain active without a pending authoritative refresh.
    // The helper is deliberately a no-op before activation so failed starts do
    // not leave workers targeting a runtime that never committed.
    const bool interface_needs_refresh =
        internal_vpn_resolution_requires_catalog_refresh(
            active_config_snapshot_->config, interface_state);
    const bool service_needs_refresh =
        config_requires_internal_vpn_service_inventory(active_config_snapshot_->config) &&
        service_state != InternalVpnRuntimeResolutionState::verified;
    if (!routing_runtime_active() ||
        (!interface_needs_refresh && !service_needs_refresh)) {
        return;
    }
    schedule_internal_vpn_catalog_refresh();
}

void Daemon::schedule_internal_vpn_catalog_refresh_retry(
    std::uint64_t runtime_generation) {
    if (!scheduler_ ||
        internal_vpn_catalog_refresh_retry_task_id_ >= 0 ||
        !runtime_recovery_is_current(
            routing_runtime_active(),
            runtime_generation,
            runtime_generation_.load(std::memory_order_acquire))) {
        return;
    }

    const auto incident =
        internal_vpn_catalog_incidents_.record_failure(
            "native-vpn-ndms-catalog");
    if (incident.notify) {
        Logger::instance().warn(
            "{} authoritative native VPN inventory refresh attempts could "
            "not produce a fresh catalog. keen-pbr is keeping its conservative "
            "verified/live-name policy, unverified bypasses remain disabled, "
            "and background recovery will continue.",
            incident.consecutive_failures);
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
                        routing_runtime_active(),
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
    internal_vpn_catalog_incidents_.clear();
    if (!scheduler_ ||
        internal_vpn_catalog_refresh_retry_task_id_ < 0) {
        return;
    }
    scheduler_->cancel(internal_vpn_catalog_refresh_retry_task_id_);
    internal_vpn_catalog_refresh_retry_task_id_ = -1;
}

void Daemon::cancel_resolver_reload_retry() {
    // Invalidate before cancellation. Scheduler::cancel() may race a callback
    // which has already been dequeued; its serial check must fail before it
    // can clear a successor's timer slot.
    ++resolver_reload_retry_schedule_serial_;
    resolver_reload_retry_pending_ = false;
    resolver_reload_retry_pending_attempt_ = 0U;
    resolver_reload_retry_pending_generation_ = 0U;
    // Do not clear the generation-keyed incident here. A same-generation
    // firewall refresh may cancel and re-arm resolver work; clearing would
    // mint a second bell for the same unresolved incident. Verified resolver
    // success resets its exact key, while a new runtime generation uses a new
    // key naturally.
    if (!scheduler_ || resolver_reload_retry_task_id_ < 0) {
        return;
    }
    const int task_id = resolver_reload_retry_task_id_;
    resolver_reload_retry_task_id_ = -1;
    scheduler_->cancel(task_id);
}

void Daemon::schedule_resolver_reload_retry(
    std::size_t attempt,
    std::uint64_t runtime_generation) {
    const auto decline = classify_resolver_reload_schedule(
        scheduler_ != nullptr,
        resolver_reload_retry_task_id_ >= 0,
        routing_runtime_active(),
        runtime_generation,
        runtime_generation_.load(std::memory_order_acquire));
    if (decline != ResolverReloadScheduleDecline::scheduled) {
        // Every branch here used to return in silence. When the declined call
        // is the one that would have armed maintenance, the resolver stops
        // retrying for good and the log's last word on the subject is the
        // bounded chain's exhaustion - which is exactly how an operator ends
        // up with a resolver stuck on its fallback and nothing to read.
        if (resolver_reload_schedule_decline_is_notable(decline)) {
            try {
                Logger::instance().warn(
                    "Resolver reload retry (attempt {}) was not scheduled: {}",
                    attempt,
                    resolver_reload_schedule_decline_name(decline));
            } catch (...) {
            }
        }
        return;
    }

    const auto plan = plan_resolver_reload_retry(
        attempt,
        RESOLVER_RELOAD_RETRY_DELAYS,
        RESOLVER_RELOAD_MAINTENANCE_DELAY);
    const std::uint64_t schedule_serial =
        ++resolver_reload_retry_schedule_serial_;
    resolver_reload_retry_pending_ = true;
    resolver_reload_retry_pending_attempt_ = plan.attempt;
    resolver_reload_retry_pending_generation_ = runtime_generation;
    try {
        resolver_reload_retry_task_id_ = scheduler_->schedule_oneshot(
            plan.delay,
            [this, plan, runtime_generation, schedule_serial]() {
                if (schedule_serial !=
                    resolver_reload_retry_schedule_serial_) {
                    return;
                }
                resolver_reload_retry_task_id_ = -1;
                resolver_reload_retry_pending_ = false;
                resolver_reload_retry_pending_attempt_ = 0U;
                resolver_reload_retry_pending_generation_ = 0U;
                if (!runtime_recovery_is_current(
                        routing_runtime_active(),
                        runtime_generation,
                        runtime_generation_.load(
                            std::memory_order_acquire))) {
                    return;
                }
                // Resolver bytes must never advance ahead of a failed
                // firewall rollback. This explicit generation latch remains
                // closed even after bounded firewall retries are exhausted;
                // the successful firewall reconciliation schedules a fresh
                // resolver attempt.
                if (resolver_after_firewall_gate_.waiting_for(
                        runtime_generation)) {
                    Logger::instance().verbose(
                        "Holding resolver reload recovery until firewall "
                        "generation {} has converged.",
                        runtime_generation);
                    return;
                }
                start_resolver_reload_retry_attempt(
                    plan.attempt, runtime_generation);
            },
            "resolver-reload-recovery");
    } catch (const std::exception& error) {
        resolver_reload_retry_task_id_ = -1;
        try {
            Logger::instance().info(
                "Resolver reload retry timer could not be installed; the "
                "periodic runtime health owner retained generation {}: {}",
                runtime_generation,
                error.what());
        } catch (...) {
        }
        return;
    } catch (...) {
        resolver_reload_retry_task_id_ = -1;
        return;
    }
    try {
        if (plan.maintenance) {
            Logger::instance().verbose(
                "Resolver reload maintenance scheduled in {}s for runtime "
                "generation {}.",
                plan.delay.count(),
                runtime_generation);
        } else {
            Logger::instance().info(
                "Resolver reload recovery attempt {} scheduled in {}s.",
                plan.attempt + 1,
                plan.delay.count());
        }
    } catch (...) {
        // The timer and retained intent already own recovery. Diagnostics
        // must not abort the caller before it records the incident/state.
    }
}

void Daemon::start_resolver_reload_retry_attempt(
    std::size_t attempt,
    std::uint64_t runtime_generation) {
    const bool maintenance_attempt =
        attempt >= RESOLVER_RELOAD_RETRY_DELAYS.size();
    if (!routing_runtime_active() ||
        runtime_generation !=
            runtime_generation_.load(std::memory_order_acquire)) {
        Logger::instance().verbose(
            "Discarding stale resolver reload recovery retry.");
        return;
    }

    if (resolver_stream_coordinator_.in_flight()) {
        Logger::instance().verbose(
            "Resolver reload recovery is already in progress; deferring "
            "attempt {} without consuming retry budget.",
            attempt + 1);
        schedule_resolver_reload_retry(attempt, runtime_generation);
        return;
    }

    auto admitted = runtime_mutation_admission_.try_acquire(
        "resolver-reload-recovery");
    if (!admitted.has_value()) {
        const auto active = runtime_mutation_admission_.active();
        Logger::instance().verbose(
            "Resolver reload recovery deferred behind runtime mutation '{}'.",
            active.has_value() ? active->label : std::string{"unknown"});
        schedule_resolver_reload_retry(attempt, runtime_generation);
        return;
    }

    auto mutation_lease =
        std::make_shared<RuntimeMutationAdmission::Lease>(
            std::move(*admitted));
    try {
        if (!resolver_generation_snapshot_ ||
            !resolver_generation_snapshot_->list_cache_snapshot) {
            throw DaemonError(
                "Committed resolver generation is unavailable");
        }

        auto generation = std::make_shared<ResolverGenerationSnapshot>(
            *resolver_generation_snapshot_);
        resolver_stream_attempt_owner_.assign_next_stream_epoch(
            *generation);
        const std::string attempt_id = generate_resolver_attempt_id();
        const auto args = build_system_resolver_hook_args(
            generation->config, "reload", attempt_id);
        if (args.empty()) {
            ResolverStreamOperation operation;
            operation.runtime_generation = runtime_generation;
            operation.retry_attempt = attempt;
            // No hook means no stream was published. Treat the no-op as an
            // immediate recovery without fencing it against an unpublished
            // epoch, otherwise completion would continuously reschedule it.
            operation.stream_epoch = 0;
            operation.attempt_id = attempt_id;
            complete_resolver_reload_retry_attempt(
                operation,
                ResolverStreamResult{true, 0, {}});
            return;
        }

        auto lifetime = resolver_stream_attempt_owner_.acquire_lifetime(
            attempt_id, generation, mutation_lease);
        resolver_generation_snapshot_ = generation;
        resolver_stream_attempt_owner_.publish_active(lifetime);

        ResolverStreamOperation operation;
        operation.runtime_generation = runtime_generation;
        operation.retry_attempt = attempt;
        operation.stream_epoch = generation->stream_epoch;
        operation.attempt_id = attempt_id;
        operation.timeout = std::chrono::seconds{15};
        operation.lifetime = std::move(lifetime);
        operation.invoke_hook = [this, args]() {
            KPBR_LOCK_GUARD(system_resolver_hook_mutex_);
            return hook_command_executor_(args);
        };

        const auto request =
            resolver_stream_coordinator_.request(std::move(operation));
        if (request == ResolverStreamCoordinator::RequestResult::busy) {
            Logger::instance().verbose(
                "Resolver reload recovery handoff was busy; deferring "
                "attempt {} without consuming retry budget.",
                attempt + 1);
            schedule_resolver_reload_retry(attempt, runtime_generation);
        } else if (
            request == ResolverStreamCoordinator::RequestResult::rejected) {
            if (maintenance_attempt) {
                Logger::instance().verbose(
                    "Resolver reload maintenance was rejected by the worker "
                    "coordinator");
            } else {
                Logger::instance().info(
                    "Resolver reload recovery attempt {} was rejected by "
                    "the worker coordinator",
                    attempt + 1);
            }
            ResolverStreamOperation rejected_operation;
            rejected_operation.runtime_generation = runtime_generation;
            rejected_operation.retry_attempt = attempt;
            rejected_operation.stream_epoch = generation->stream_epoch;
            complete_resolver_reload_retry_attempt(
                rejected_operation,
                ResolverStreamResult{
                    false,
                    -1,
                    "resolver stream worker rejected the operation"});
        }
    } catch (const std::exception& error) {
        if (maintenance_attempt) {
            Logger::instance().verbose(
                "Resolver reload maintenance could not start: {}",
                error.what());
        } else {
            Logger::instance().info(
                "Resolver reload recovery attempt {} could not start: {}",
                attempt + 1,
                error.what());
        }
        ResolverStreamOperation operation;
        operation.runtime_generation = runtime_generation;
        operation.retry_attempt = attempt;
        complete_resolver_reload_retry_attempt(
            operation,
            ResolverStreamResult{false, -1, error.what()});
    }
}

void Daemon::complete_resolver_reload_retry_attempt(
    const ResolverStreamOperation& operation,
    const ResolverStreamResult& result) noexcept {
    try {
        const auto current_generation =
            runtime_generation_.load(std::memory_order_acquire);
        if (operation.runtime_generation != current_generation ||
            !routing_runtime_active()) {
            Logger::instance().verbose(
                "Discarding stale resolver reload recovery completion.");
            keenetic_dns_refresh_deferred_by_resolver_stream_ = false;
            return;
        }

        if (operation.stream_epoch != 0 &&
            (!resolver_generation_snapshot_ ||
             resolver_generation_snapshot_->stream_epoch !=
                 operation.stream_epoch)) {
            Logger::instance().verbose(
                "Resolver generation changed during recovery; scheduling "
                "the latest committed generation.");
            schedule_resolver_reload_retry(0, current_generation);
            return;
        }

        const bool maintenance_attempt =
            operation.retry_attempt >=
                RESOLVER_RELOAD_RETRY_DELAYS.size();
        if (!result.completed && !result.error.empty()) {
            if (maintenance_attempt) {
                Logger::instance().verbose(
                    "Resolver reload maintenance did not converge: {}",
                    result.error);
            } else {
                Logger::instance().info(
                    "Resolver reload recovery attempt {} failed: {}",
                    operation.retry_attempt + 1,
                    result.error);
            }
        }
        const auto outcome = evaluate_resolver_reload_retry(
            routing_runtime_active(),
            operation.runtime_generation,
            current_generation,
            operation.retry_attempt,
            RESOLVER_RELOAD_RETRY_DELAYS.size(),
            [&result]() { return result.completed; });

        if (outcome == ResolverReloadRetryOutcome::stale_generation) {
            return;
        }
        if (outcome == ResolverReloadRetryOutcome::recovered) {
            acknowledge_verified_resolver_reload(
                operation.runtime_generation);
            refresh_resolver_config_hash_actual_async();
            publish_runtime_state();
            Logger::instance().info(
                "Resolver reload recovered after committed runtime "
                "replacement.");
            resume_deferred_keenetic_dns_refresh();
            return;
        }
        if (outcome == ResolverReloadRetryOutcome::retry) {
            schedule_resolver_reload_retry(
                operation.retry_attempt + 1,
                operation.runtime_generation);
            return;
        }

        // Arm the durable-in-process successor before diagnostics/state
        // publication. An allocation or observer failure below must not be
        // able to terminate the only liveness chain.
        schedule_resolver_reload_retry(
            RESOLVER_RELOAD_RETRY_DELAYS.size(),
            operation.runtime_generation);

        const std::string incident_key =
            "resolver-reload:" +
            std::to_string(operation.runtime_generation);
        RuntimeIncidentLatch::Decision incident;
        if (!maintenance_attempt) {
            // The bounded chain owns the one operator-visible incident.
            // Minute-by-minute maintenance failures stay diagnostic-only and
            // do not grow a counter or mint another bell.
            incident =
                resolver_reload_incidents_.record_failure(incident_key);
        }
        if (incident.notify) {
            // Recorded before the transition and independently of it. The
            // transition below can only publish this chain's reason when the
            // runtime is still running; during a real boot something else has
            // usually broken it seconds earlier, and a recovery keyed only on
            // that reason could then never fire again.
            resolver_reload_latched_ = true;
            Logger::instance().error(
                "Resolver reload did not recover after {} bounded attempts; "
                "routing remains active and quiet maintenance will retry "
                "every {}s.",
                RESOLVER_RELOAD_RETRY_DELAYS.size(),
                RESOLVER_RELOAD_MAINTENANCE_DELAY.count());
            if (runtime_state_machine_.state() == RuntimeState::running) {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    kResolverReloadExhaustedRuntimeReason.data());
            } else {
                Logger::instance().warn(
                    "Resolver latch recorded while the runtime was already "
                    "held by another owner for: {}",
                    runtime_state_machine_.reason());
            }
        }
        refresh_resolver_config_hash_actual_async();
        if (incident.notify) {
            publish_runtime_state();
        }
        resume_deferred_keenetic_dns_refresh();
    } catch (const std::exception& error) {
        try {
            Logger::instance().error(
                "Resolver reload recovery completion failed: {}",
                error.what());
        } catch (...) {
        }
        resume_deferred_keenetic_dns_refresh();
    } catch (...) {
        resume_deferred_keenetic_dns_refresh();
    }
}

bool Daemon::acknowledge_verified_resolver_reload(
    std::uint64_t runtime_generation) {
    const auto current_generation =
        runtime_generation_.load(std::memory_order_acquire);
    if (!routing_runtime_active() || runtime_generation != current_generation) {
        return false;
    }

    resolver_reload_incidents_.reset(
        "resolver-reload:" + std::to_string(runtime_generation));

    const auto runtime_recovery_action = plan_resolver_runtime_recovery(
        routing_runtime_active(),
        runtime_state_machine_.state(),
        runtime_state_machine_.reason(),
        resolver_reload_latched_);
    if (runtime_recovery_action == ResolverRuntimeRecoveryAction::preserve) {
        return false;
    }
    if (runtime_recovery_action ==
        ResolverRuntimeRecoveryAction::clear_resolver_latch_only) {
        // The resolver is healthy again, but the runtime is broken for a
        // reason this chain did not write and must not overwrite. Retire our
        // own latch and say so - otherwise the only trace of a resolver that
        // recovered under someone else's broken runtime is silence.
        resolver_reload_latched_ = false;
        try {
            Logger::instance().warn(
                "Resolver reload recovered, but the runtime stays broken for "
                "an unrelated reason: {}",
                runtime_state_machine_.reason());
        } catch (...) {
        }
        return false;
    }
    resolver_reload_latched_ = false;

    // Both broken -> applying and running -> applying are legal. No
    // intermediate publication occurs: this bridge replaces only the exact
    // resolver-owned reason, while unrelated broken states remain untouched.
    transition_runtime_or_throw(
        RuntimeState::applying,
        "verified resolver recovery publication");
    transition_runtime_or_throw(
        RuntimeState::running,
        kResolverReloadRecoveredRuntimeReason.data());
    return true;
}

void Daemon::resume_deferred_keenetic_dns_refresh() noexcept {
    if (!keenetic_dns_refresh_deferred_by_resolver_stream_) {
        return;
    }
    keenetic_dns_refresh_deferred_by_resolver_stream_ = false;

    try {
        const bool queued = post_control_task(
            [this]() {
                // This callback runs in the next control-loop batch, after
                // ResolverStreamCoordinator has retired its claim and
                // released the IPC/admission lifetime.
                if (resolver_stream_coordinator_.in_flight()) {
                    keenetic_dns_refresh_deferred_by_resolver_stream_ = true;
                    return;
                }
                if (!routing_runtime_active() || !active_config_snapshot_->config.dns.has_value() ||
                    !dns_config_uses_keenetic_server(*active_config_snapshot_->config.dns)) {
                    return;
                }
                request_keenetic_dns_refresh();
            },
            "keenetic-dns-refresh-after-resolver-recovery");
        if (!queued && routing_runtime_active()) {
            keenetic_dns_refresh_deferred_by_resolver_stream_ = true;
        }
    } catch (const std::exception& error) {
        keenetic_dns_refresh_deferred_by_resolver_stream_ = true;
        try {
            Logger::instance().error(
                "Could not queue deferred Keenetic DNS refresh: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        keenetic_dns_refresh_deferred_by_resolver_stream_ = true;
    }
}

void Daemon::cancel_idle_stall_observer() noexcept {
    idle_stall_supervisor_.cancel();
}

void Daemon::schedule_idle_stall_observer_after(
    std::chrono::seconds delay) noexcept {
    try {
        idle_stall_supervisor_.schedule_after(
            delay, routing_runtime_active());
    } catch (...) {
        idle_stall_supervisor_.cancel();
    }
}

bool Daemon::schedule_exact_tcp_reset_cleanup(
    const FirewallExactTcpResetRule& rule,
    std::uint64_t expected_runtime_generation,
    std::size_t attempt) noexcept {
    if (!scheduler_ || expected_runtime_generation == 0U ||
        !running_.load(std::memory_order_acquire) ||
        !routing_runtime_active() ||
        runtime_generation_.load(std::memory_order_acquire) !=
            expected_runtime_generation ||
        attempt >
            EXPERIMENTAL_TCP_RESET_CLEANUP_RETRY_DELAYS.size() + 1U) {
        return false;
    }

    const bool maintenance =
        attempt > EXPERIMENTAL_TCP_RESET_CLEANUP_RETRY_DELAYS.size();
    const auto delay = maintenance
        ? std::chrono::duration_cast<std::chrono::milliseconds>(
              EXPERIMENTAL_TCP_RESET_CLEANUP_MAINTENANCE_DELAY)
        : (attempt == 0U
               ? std::chrono::duration_cast<std::chrono::milliseconds>(
                     EXPERIMENTAL_TCP_RESET_RULE_TTL)
               : EXPERIMENTAL_TCP_RESET_CLEANUP_RETRY_DELAYS[attempt - 1U]);
    const std::uint64_t schedule_serial =
        ++exact_tcp_reset_cleanup_schedule_serial_;

    // Re-arming an identical exact rule transfers ownership to the newest
    // window. The serial invalidates the old callback even if cancelling its
    // timer fails after the scheduler has already consumed the entry.
    auto existing = std::find_if(
        pending_exact_tcp_reset_cleanups_.begin(),
        pending_exact_tcp_reset_cleanups_.end(),
        [&rule](const auto& pending) { return pending.rule == rule; });
    if (existing != pending_exact_tcp_reset_cleanups_.end()) {
        if (existing->worker_inflight) {
            return false;
        }
        const int stale_task_id = existing->task_id;
        existing->runtime_generation = expected_runtime_generation;
        existing->attempt = attempt;
        existing->schedule_serial = schedule_serial;
        existing->task_id = -1;
        if (stale_task_id >= 0) {
            try {
                scheduler_->cancel(stale_task_id);
            } catch (...) {
            }
        }
    } else {
        try {
            pending_exact_tcp_reset_cleanups_.push_back(
                PendingExactTcpResetCleanup{
                    rule,
                    expected_runtime_generation,
                     attempt,
                     schedule_serial,
                     -1,
                     false});
        } catch (...) {
            return false;
        }
    }

    try {
        const int task_id = scheduler_->schedule_oneshot(
            delay,
            [this, schedule_serial]() noexcept {
                run_exact_tcp_reset_cleanup(schedule_serial);
            },
            attempt == 0U
                ? "experimental-whatsapp-tcp-reset-cleanup"
                : (maintenance
                       ? "experimental-whatsapp-tcp-reset-cleanup-maintenance"
                       : "experimental-whatsapp-tcp-reset-cleanup-retry"));
        const auto published = std::find_if(
            pending_exact_tcp_reset_cleanups_.begin(),
            pending_exact_tcp_reset_cleanups_.end(),
            [schedule_serial](const auto& pending) {
                return pending.schedule_serial == schedule_serial;
            });
        if (published == pending_exact_tcp_reset_cleanups_.end()) {
            try {
                scheduler_->cancel(task_id);
            } catch (...) {
            }
            return false;
        }
        published->task_id = task_id;
        return true;
    } catch (...) {
        const auto unpublished = std::find_if(
            pending_exact_tcp_reset_cleanups_.begin(),
            pending_exact_tcp_reset_cleanups_.end(),
            [schedule_serial](const auto& pending) {
                return pending.schedule_serial == schedule_serial;
            });
        if (unpublished != pending_exact_tcp_reset_cleanups_.end()) {
            // Retain exact rule ownership even when timer publication fails.
            // The active observer will re-arm this dormant entry, while a
            // lifecycle generation change must synchronously drain it.
            unpublished->task_id = -1;
        }
        return false;
    }
}

void Daemon::forget_exact_tcp_reset_cleanup(
    const FirewallExactTcpResetRule& rule) noexcept {
    const auto pending = std::find_if(
        pending_exact_tcp_reset_cleanups_.begin(),
        pending_exact_tcp_reset_cleanups_.end(),
        [&rule](const auto& candidate) { return candidate.rule == rule; });
    if (pending == pending_exact_tcp_reset_cleanups_.end()) {
        return;
    }
    const int task_id = pending->task_id;
    pending_exact_tcp_reset_cleanups_.erase(pending);
    if (task_id >= 0 && scheduler_) {
        try {
            scheduler_->cancel(task_id);
        } catch (...) {
        }
    }
}

void Daemon::resume_exact_tcp_reset_cleanups() noexcept {
    try {
        std::vector<PendingExactTcpResetCleanup> dormant;
        for (const auto& pending : pending_exact_tcp_reset_cleanups_) {
            if (pending.task_id < 0 && !pending.worker_inflight &&
                pending.runtime_generation ==
                    runtime_generation_.load(std::memory_order_acquire)) {
                dormant.push_back(pending);
            }
        }
        for (const auto& pending : dormant) {
            const std::size_t attempt = std::max(
                pending.attempt,
                EXPERIMENTAL_TCP_RESET_CLEANUP_RETRY_DELAYS.size() + 1U);
            (void)schedule_exact_tcp_reset_cleanup(
                pending.rule, pending.runtime_generation, attempt);
        }
    } catch (...) {
    }
}

void Daemon::fence_exact_tcp_reset_cleanups_for_stop() noexcept {
    for (auto& pending : pending_exact_tcp_reset_cleanups_) {
        const int task_id = std::exchange(pending.task_id, -1);
        // Invalidate a callback which the scheduler may already have moved
        // out of its timer queue. The immutable rule record remains owned
        // until the typed STOP worker proves the whole backend chain absent.
        pending.schedule_serial = ++exact_tcp_reset_cleanup_schedule_serial_;
        if (task_id >= 0 && scheduler_) {
            try {
                scheduler_->cancel(task_id);
            } catch (...) {
            }
        }
    }
}

std::optional<std::uint64_t> Daemon::reserve_exact_tcp_reset_cleanup(
    const FirewallExactTcpResetRule& rule,
    std::uint64_t expected_runtime_generation) noexcept {
    if (!scheduler_ || expected_runtime_generation == 0U ||
        !running_.load(std::memory_order_acquire) ||
        runtime_generation_.load(std::memory_order_acquire) !=
            expected_runtime_generation) {
        return std::nullopt;
    }
    const auto existing = std::find_if(
        pending_exact_tcp_reset_cleanups_.begin(),
        pending_exact_tcp_reset_cleanups_.end(),
        [&rule](const auto& pending) { return pending.rule == rule; });
    if (existing != pending_exact_tcp_reset_cleanups_.end()) {
        return std::nullopt;
    }
    try {
        const auto serial = ++exact_tcp_reset_cleanup_schedule_serial_;
        pending_exact_tcp_reset_cleanups_.push_back(
            PendingExactTcpResetCleanup{
                rule,
                expected_runtime_generation,
                0U,
                serial,
                -1,
                true});
        return serial;
    } catch (...) {
        return std::nullopt;
    }
}

bool Daemon::begin_idle_stall_exact_tcp_reset_point(
    std::uint64_t expected_runtime_generation,
    std::uint64_t expected_coverage_generation,
    std::uint32_t owned_mask,
    IdleStallDeleteDecision decision,
    ConntrackExactForwardedFlow flow) noexcept {
    if (flow.family != ConntrackFlowFamily::Ipv4 ||
        flow.protocol != ConntrackFlowProtocol::Tcp ||
        flow.tcp_state !=
            std::optional<ConntrackTcpState>{
                ConntrackTcpState::Established} ||
        flow.destination_port != 443U || flow.mark == 0U ||
        owned_mask == 0U || (flow.mark & owned_mask) == 0U ||
        (flow.mark & ~owned_mask) != 0U) {
        return false;
    }

    FirewallExactTcpResetRule rule{
        flow.source,
        flow.destination,
        flow.source_port,
        flow.destination_port,
        flow.mark};
    const auto target_serial = reserve_exact_tcp_reset_cleanup(
        rule, expected_runtime_generation);
    if (!target_serial.has_value()) {
        return false;
    }

    const auto abandon_reservation = [this, &rule, target_serial]() noexcept {
        const auto current = std::find_if(
            pending_exact_tcp_reset_cleanups_.begin(),
            pending_exact_tcp_reset_cleanups_.end(),
            [target_serial](const auto& candidate) {
                return candidate.schedule_serial == *target_serial;
            });
        if (current != pending_exact_tcp_reset_cleanups_.end()) {
            current->worker_inflight = false;
            forget_exact_tcp_reset_cleanup(rule);
        }
    };

    try {
        auto admitted = runtime_mutation_admission_.try_acquire(
            "exact-whatsapp-tcp-reset-point");
        if (!admitted.has_value()) {
            abandon_reservation();
            return false;
        }
        auto lease = std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(*admitted));
        const auto expected_lease_token = lease->token();

        RuntimeExactTcpResetPointMutationTarget target;
        target.kind = RuntimeExactTcpResetPointMutationKind::
            install_then_delete_exact_flow;
        target.runtime_generation = expected_runtime_generation;
        target.coverage_generation = expected_coverage_generation;
        target.target_serial = *target_serial;
        target.rule = rule;
        target.exact_flow = flow;
        target.owned_mask = owned_mask;
        if (!target.valid()) {
            lease.reset();
            abandon_reservation();
            return false;
        }

        RuntimeFirewallPreownedTerminalContinuation continuation{
            [this,
             rule,
             decision,
             expected_runtime_generation,
             expected_coverage_generation,
             target_serial = *target_serial,
             expected_lease_token](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                const bool exact_lease_returned = exact &&
                        static_cast<bool>(*exact) &&
                        exact->token() == expected_lease_token &&
                        runtime_mutation_admission_.owns(*exact);
                const bool succeeded = exact_lease_returned &&
                        terminal.outcome ==
                            RuntimeFirewallLifecycleOutcome::
                                verified_success &&
                        terminal.committed &&
                        !terminal.commit_ambiguous;
                try {
                    const auto current = std::find_if(
                        pending_exact_tcp_reset_cleanups_.begin(),
                        pending_exact_tcp_reset_cleanups_.end(),
                        [target_serial,
                         expected_runtime_generation,
                         &rule](const auto& candidate) {
                            return candidate.schedule_serial ==
                                       target_serial &&
                                   candidate.runtime_generation ==
                                       expected_runtime_generation &&
                                   candidate.rule == rule;
                        });
                    if (current !=
                        pending_exact_tcp_reset_cleanups_.end()) {
                        current->worker_inflight = false;
                        if (terminal.outcome ==
                            RuntimeFirewallLifecycleOutcome::shutdown) {
                            // STOP''s strict owned-firewall cleanup now owns
                            // the tail; keep the exact ledger record dormant.
                        } else if (succeeded) {
                            (void)schedule_exact_tcp_reset_cleanup(
                                rule,
                                expected_runtime_generation,
                                /*attempt=*/0U);
                        } else if (!exact_lease_returned ||
                                   terminal.commit_ambiguous) {
                            (void)schedule_exact_tcp_reset_cleanup(
                                rule,
                                expected_runtime_generation,
                                /*attempt=*/1U);
                        } else {
                            forget_exact_tcp_reset_cleanup(rule);
                        }
                    }
                } catch (...) {
                    // Keep the exact ledger record fail-closed. A later
                    // observer/generation drain can resume its cleanup.
                }
                try {
                    idle_stall_supervisor_.idle_detector().
                        acknowledge_delete_result(
                        decision,
                        succeeded,
                        IdleStallDetector::Clock::now());
                } catch (...) {
                    // Detector bookkeeping must never suppress the observer
                    // follow-up after the owned terminal has completed.
                }
                try {
                    if (terminal.outcome !=
                            RuntimeFirewallLifecycleOutcome::shutdown &&
                        running_.load(std::memory_order_acquire) &&
                        routing_runtime_active() &&
                        idle_stall_supervisor_.enabled() &&
                        runtime_generation_.load(
                            std::memory_order_acquire) ==
                            expected_runtime_generation &&
                        idle_stall_supervisor_.current_coverage(
                            expected_coverage_generation)) {
                        const auto fast_followup =
                            idle_stall_supervisor_.idle_detector().
                                take_whatsapp_fast_followup_delay();
                        schedule_idle_stall_observer_after(
                            fast_followup.value_or(
                                IDLE_STALL_ACTIVE_SCAN_INTERVAL));
                    }
                } catch (...) {
                }
                exact.reset();
                if (succeeded) {
                    try {
                        Logger::instance().info(
                            "Rotated one frozen WhatsApp TCP tuple with an "
                            "exact short-lived reset");
                    } catch (...) {
                    }
                }
            }};
        if (begin_preowned_runtime_firewall_exact_tcp_reset_point(
                lease, std::move(target), continuation)) {
            return true;
        }
        lease.reset();
        abandon_reservation();
        return false;
    } catch (...) {
        abandon_reservation();
        return false;
    }
}

bool Daemon::begin_idle_stall_exact_cleanup_point(
    std::uint64_t expected_runtime_generation,
    std::uint64_t expected_coverage_generation,
    std::uint32_t owned_mask,
    std::vector<RuntimeIdleStallExactCleanupPointMutationWork> work,
    std::vector<IdleStallDeleteDecision> all_decisions,
    std::size_t media_protected,
    std::size_t recovered_or_replaced) noexcept {
    if (work.empty()) return false;
    try {
        RuntimeIdleStallExactCleanupPointMutationTarget operation;
        operation.runtime_generation = expected_runtime_generation;
        operation.coverage_generation = expected_coverage_generation;
        operation.owned_mask = owned_mask;
        operation.work = std::move(work);
        RuntimeBackgroundPointMutationTarget target;
        target.kind =
            RuntimeBackgroundPointMutationKind::
                idle_stall_exact_cleanup;
        target.target_serial = ++background_point_mutation_serial_;
        if (target.target_serial == 0U) {
            target.target_serial = ++background_point_mutation_serial_;
        }
        target.payload = std::move(operation);
        auto transaction = std::make_shared<
            RuntimeBackgroundPointMutationTransaction>(
            std::move(target));
        if (!transaction->valid()) return false;
        auto admitted = runtime_mutation_admission_.try_acquire(
            "idle-stall-exact-cleanup-point");
        if (!admitted.has_value()) return false;
        auto lease = std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(*admitted));
        const auto expected_lease_token = lease->token();
        RuntimeFirewallPreownedTerminalContinuation continuation{
            [this, transaction, all_decisions = std::move(all_decisions),
             expected_runtime_generation,
             expected_coverage_generation,
             media_protected, recovered_or_replaced,
             expected_lease_token](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                const bool lease_returned =
                    exact && static_cast<bool>(*exact) &&
                    exact->token() == expected_lease_token &&
                    runtime_mutation_admission_.owns(*exact);
                bool current = false;
                try {
                    current =
                        terminal.outcome !=
                            RuntimeFirewallLifecycleOutcome::shutdown &&
                        running_.load(std::memory_order_acquire) &&
                        routing_runtime_active() &&
                        idle_stall_supervisor_.enabled() &&
                        runtime_generation_.load(
                            std::memory_order_acquire) ==
                            expected_runtime_generation &&
                        idle_stall_supervisor_.current_coverage(
                            expected_coverage_generation);
                } catch (...) {}
                const bool typed =
                    lease_returned &&
                    transaction->typed_identity_valid &&
                    transaction->result &&
                    transaction->result->control_publishable() &&
                    transaction->result->target ==
                        transaction->target &&
                    std::holds_alternative<
                        RuntimeIdleStallExactCleanupPointMutationResult>(
                        transaction->result->payload);
                std::size_t succeeded = 0U;
                std::size_t failed = 0U;
                bool command_unavailable = false;
                std::set<std::uint64_t> acknowledged;
                const auto acknowledge =
                    [this, &acknowledged](
                        const IdleStallDeleteDecision& decision,
                        bool success) noexcept {
                        try {
                            idle_stall_supervisor_.idle_detector().
                                acknowledge_delete_result(
                                decision, success,
                                IdleStallDetector::Clock::now());
                            acknowledged.insert(decision.attempt_id);
                        } catch (...) {}
                    };
                if (typed && current) {
                    const auto& output = std::get<
                        RuntimeIdleStallExactCleanupPointMutationResult>(
                        transaction->result->payload);
                    command_unavailable = output.command_unavailable;
                    for (const auto& outcome : output.outcomes) {
                        const bool success =
                            outcome.attempted &&
                            outcome.cleanup_result ==
                                ConntrackCleanupResult::Succeeded;
                        acknowledge(outcome.decision, success);
                        success ? ++succeeded : ++failed;
                    }
                }
                for (const auto& decision : all_decisions) {
                    if (acknowledged.count(decision.attempt_id) == 0U) {
                        acknowledge(decision, false);
                    }
                }
                if (current) {
                    try {
                        if (succeeded != 0U) {
                            Logger::instance().info(
                                "Recovered {} exact idle forwarded flow(s) "
                                "after their reply path stopped progressing",
                                succeeded);
                        } else if (command_unavailable) {
                            Logger::instance().info(
                                "Idle forwarded-flow recovery is unavailable "
                                "because conntrack could not be run");
                        } else if (failed != 0U) {
                            Logger::instance().info(
                                "Idle forwarded-flow recovery left {} exact "
                                "flow deletion(s) incomplete",
                                failed);
                        } else if (media_protected != 0U ||
                                   recovered_or_replaced != 0U) {
                            Logger::instance().trace(
                                "idle_stall_delete_skip",
                                "generation={} protected={} recovered={}",
                                expected_runtime_generation,
                                media_protected,
                                recovered_or_replaced);
                        }
                        const auto fast_followup =
                            idle_stall_supervisor_.idle_detector().
                                take_whatsapp_fast_followup_delay();
                        schedule_idle_stall_observer_after(
                            fast_followup.value_or(
                                IDLE_STALL_ACTIVE_SCAN_INTERVAL));
                    } catch (...) {}
                }
                exact.reset();
            }};
        if (begin_preowned_runtime_firewall_background_point_mutation(
                lease, transaction, continuation)) {
            return true;
        }
        lease.reset();
    } catch (...) {}
    return false;
}

void Daemon::clear_exact_tcp_reset_cleanup_ownership() noexcept {
    for (const auto& pending : pending_exact_tcp_reset_cleanups_) {
        if (pending.task_id >= 0 && scheduler_) {
            try {
                scheduler_->cancel(pending.task_id);
            } catch (...) {
            }
        }
    }
    pending_exact_tcp_reset_cleanups_.clear();
}

void Daemon::run_exact_tcp_reset_cleanup(
    std::uint64_t schedule_serial) noexcept {
    const auto pending = std::find_if(
        pending_exact_tcp_reset_cleanups_.begin(),
        pending_exact_tcp_reset_cleanups_.end(),
        [schedule_serial](const auto& candidate) {
            return candidate.schedule_serial == schedule_serial;
        });
    if (pending == pending_exact_tcp_reset_cleanups_.end()) {
        return;
    }

    pending->task_id = -1;
    if (pending->worker_inflight) {
        return;
    }
    FirewallExactTcpResetRule rule;
    try {
        rule = pending->rule;
    } catch (...) {
        // Keep the consumed timer's ownership record dormant. The next
        // observer pass or lifecycle drain will retry without broadening it.
        pending->task_id = -1;
        return;
    }
    const std::uint64_t expected_runtime_generation =
        pending->runtime_generation;
    const std::size_t attempt = pending->attempt;

    // Apply/stop owns cleanup once the runtime generation changes. Together
    // with the serial lookup above, this prevents an old callback from
    // deleting a newly armed identical rule.
    if (!running_.load(std::memory_order_acquire) ||
        !routing_runtime_active() ||
        runtime_generation_.load(std::memory_order_acquire) !=
            expected_runtime_generation) {
        pending_exact_tcp_reset_cleanups_.erase(pending);
        return;
    }

    // A delayed runtime-firewall operation owns the backend from its timer
    // claim through worker completion and control publication. Never make the
    // event loop wait for that worker's backend barrier: retain this exact
    // generation/rule record as dormant instead. The observer is re-armed
    // only after the replacement generation has been published and will then
    // resume the cleanup through resume_exact_tcp_reset_cleanups().
    if (runtime_firewall_retry_.retry_pending()) {
        pending->task_id = -1;
        return;
    }

    const std::size_t next_attempt =
        attempt < EXPERIMENTAL_TCP_RESET_CLEANUP_RETRY_DELAYS.size()
        ? attempt + 1U
        : EXPERIMENTAL_TCP_RESET_CLEANUP_RETRY_DELAYS.size() + 1U;
    std::optional<RuntimeMutationAdmission::Lease> admitted;
    try {
        admitted = runtime_mutation_admission_.try_acquire(
            "exact-tcp-reset-cleanup");
    } catch (...) {
    }
    if (!admitted.has_value()) {
        (void)schedule_exact_tcp_reset_cleanup(
            rule, expected_runtime_generation, next_attempt);
        return;
    }

    try {
        auto lease = std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(*admitted));
        const auto expected_lease_token = lease->token();
        pending->worker_inflight = true;
        RuntimeExactTcpResetPointMutationTarget target;
        target.kind = RuntimeExactTcpResetPointMutationKind::remove_rule;
        target.runtime_generation = expected_runtime_generation;
        target.target_serial = schedule_serial;
        target.rule = rule;
        RuntimeFirewallPreownedTerminalContinuation continuation{
            [this,
             rule,
             schedule_serial,
             expected_runtime_generation,
             next_attempt,
             expected_lease_token](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                try {
                    const bool exact_lease_returned = exact &&
                        static_cast<bool>(*exact) &&
                        exact->token() == expected_lease_token &&
                        runtime_mutation_admission_.owns(*exact);
                    const auto current = std::find_if(
                        pending_exact_tcp_reset_cleanups_.begin(),
                        pending_exact_tcp_reset_cleanups_.end(),
                        [schedule_serial,
                         expected_runtime_generation,
                         &rule](const auto& candidate) {
                            return candidate.schedule_serial ==
                                       schedule_serial &&
                                   candidate.runtime_generation ==
                                       expected_runtime_generation &&
                                   candidate.rule == rule;
                        });
                    if (current !=
                        pending_exact_tcp_reset_cleanups_.end()) {
                        current->worker_inflight = false;
                    }
                    const bool removed = exact_lease_returned &&
                        terminal.outcome ==
                            RuntimeFirewallLifecycleOutcome::
                                verified_success &&
                        !terminal.commit_ambiguous;
                    if (removed) {
                        forget_exact_tcp_reset_cleanup(rule);
                    } else if (
                        terminal.outcome !=
                            RuntimeFirewallLifecycleOutcome::shutdown &&
                        current !=
                            pending_exact_tcp_reset_cleanups_.end() &&
                        running_.load(std::memory_order_acquire) &&
                        routing_runtime_active() &&
                        runtime_generation_.load(
                            std::memory_order_acquire) ==
                            expected_runtime_generation) {
                        (void)schedule_exact_tcp_reset_cleanup(
                            rule,
                            expected_runtime_generation,
                            next_attempt);
                    }
                } catch (...) {
                }
                exact.reset();
            }};
        if (begin_preowned_runtime_firewall_exact_tcp_reset_point(
                lease, std::move(target), continuation)) {
            return;
        }
        const auto current = std::find_if(
            pending_exact_tcp_reset_cleanups_.begin(),
            pending_exact_tcp_reset_cleanups_.end(),
            [schedule_serial](const auto& candidate) {
                return candidate.schedule_serial == schedule_serial;
            });
        if (current != pending_exact_tcp_reset_cleanups_.end()) {
            current->worker_inflight = false;
        }
        lease.reset();
    } catch (...) {
        const auto current = std::find_if(
            pending_exact_tcp_reset_cleanups_.begin(),
            pending_exact_tcp_reset_cleanups_.end(),
            [schedule_serial](const auto& candidate) {
                return candidate.schedule_serial == schedule_serial;
            });
        if (current != pending_exact_tcp_reset_cleanups_.end()) {
            current->worker_inflight = false;
        }
    }
    (void)schedule_exact_tcp_reset_cleanup(
        rule, expected_runtime_generation, next_attempt);
}

void Daemon::reset_idle_stall_observer(
    bool schedule_if_eligible) noexcept {
    try {
        const bool enable =
            schedule_if_eligible &&
            routing_runtime_active() &&
            idle_stall_observer_requested(
                active_config_snapshot_->config);
        // The first short observation only establishes whether relevant
        // flows exist. Subsequent empty scans back off to 30 seconds.
        idle_stall_supervisor_.reset(
            enable, IDLE_STALL_ACTIVE_SCAN_INTERVAL);
    } catch (...) {
        idle_stall_supervisor_.cancel();
    }
}

void Daemon::run_idle_stall_observer() noexcept {
    try {
        if (!routing_runtime_active() ||
            !idle_stall_supervisor_.enabled() ||
            !idle_stall_observer_requested(active_config_snapshot_->config)) {
            cancel_idle_stall_observer();
            return;
        }
        resume_exact_tcp_reset_cleanups();

        std::set<std::string> configured_list_names;
        if (reconnect_unmarked_flows_on_routing_change_enabled(active_config_snapshot_->config)) {
            configured_list_names =
                reconnect_owned_flows_on_routing_change_list_names(active_config_snapshot_->config);
        }
        const bool preventive_guard_available =
            preventive_whatsapp_media_guard_available(
                firewall_->backend(),
                opts_.udp_call_affinity_ipset_available);
        const auto preventive_guard_lists =
            preventive_whatsapp_media_guard_list_names(active_config_snapshot_->config);
        // The preventive actuator is deliberately iptables-only. On nft the
        // packaged list contributes no automatic observation scope, so it
        // remains inert instead of falling back to a broad delete.
        if (preventive_guard_available) {
            configured_list_names.insert(
                preventive_guard_lists.begin(),
                preventive_guard_lists.end());
        }
        const auto selected_list_names =
            active_destination_only_reconnect_list_names(
                configured_list_names,
                firewall_state_.get_rules());
        if (selected_list_names.empty()) {
            cancel_idle_stall_observer();
            return;
        }
        auto whatsapp_call_affinity_lists =
            whatsapp_call_affinity_list_names(active_config_snapshot_->config);
        if (preventive_guard_available) {
            whatsapp_call_affinity_lists.insert(
                preventive_guard_lists.begin(),
                preventive_guard_lists.end());
        }
        auto whatsapp_latency_list_names = whatsapp_call_affinity_lists;
        for (auto iterator = whatsapp_latency_list_names.begin();
             iterator != whatsapp_latency_list_names.end();) {
            if (selected_list_names.count(*iterator) == 0U) {
                iterator = whatsapp_latency_list_names.erase(iterator);
            } else {
                ++iterator;
            }
        }
        for (auto iterator = whatsapp_call_affinity_lists.begin();
             iterator != whatsapp_call_affinity_lists.end();) {
            if (selected_list_names.count(*iterator) == 0U) {
                iterator = whatsapp_call_affinity_lists.erase(iterator);
            } else {
                ++iterator;
            }
        }
        std::set<std::string> active_preventive_guard_lists;
        std::set_intersection(
            preventive_guard_lists.begin(),
            preventive_guard_lists.end(),
            selected_list_names.begin(),
            selected_list_names.end(),
            std::inserter(active_preventive_guard_lists,
                          active_preventive_guard_lists.end()));
        const auto trusted_whatsapp_targets =
            active_udp_call_affinity_targets(
                whatsapp_latency_list_names,
                firewall_state_.get_rules(),
                firewall_state_.get_fwmark_mask());
        auto call_affinity_targets =
            firewall_->backend() == FirewallBackend::iptables &&
                    !opts_.udp_call_affinity_ipset_available
                ? std::vector<UdpCallAffinityTarget>{}
                : trusted_whatsapp_targets;
        std::set<std::uint32_t> trusted_whatsapp_marks;
        for (const auto& target : trusted_whatsapp_targets) {
            trusted_whatsapp_marks.insert(target.fwmark);
        }

        const auto coverage =
            collect_conntrack_destination_retirement_coverage(
                destination_retirement_plan_for_lists(
                    selected_list_names),
                applied_list_content_state_);
        std::vector<std::string> destination_selectors =
            coverage.destination_selectors;
        std::sort(destination_selectors.begin(),
                  destination_selectors.end());
        destination_selectors.erase(
            std::unique(destination_selectors.begin(),
                        destination_selectors.end()),
            destination_selectors.end());

        const bool coverage_complete =
            !coverage.partial() && !destination_selectors.empty() &&
            !runtime_recovery_detail::contains_global_destination_selector(
                coverage);
        if (!coverage_complete) {
            idle_stall_supervisor_.invalidate_incomplete_scope();
            schedule_idle_stall_observer_after(
                IDLE_STALL_QUIET_SCAN_INTERVAL);
            return;
        }

        // Classification for the one-shot latency follow-up is provenance
        // based and independent of whether the optional ipset-backed call
        // affinity feature is available. Only the immutable packaged
        // WhatsApp IP companion may contribute this exact-flow subset.
        std::vector<std::string> whatsapp_destination_selectors;
        if (!whatsapp_latency_list_names.empty()) {
            const auto whatsapp_coverage =
                collect_conntrack_destination_retirement_coverage(
                    destination_retirement_plan_for_lists(
                        whatsapp_latency_list_names),
                    applied_list_content_state_);
            whatsapp_destination_selectors =
                whatsapp_coverage.destination_selectors;
            std::sort(
                whatsapp_destination_selectors.begin(),
                whatsapp_destination_selectors.end());
            whatsapp_destination_selectors.erase(
                std::unique(
                    whatsapp_destination_selectors.begin(),
                    whatsapp_destination_selectors.end()),
                whatsapp_destination_selectors.end());
            const bool whatsapp_coverage_complete =
                !whatsapp_coverage.partial() &&
                !whatsapp_destination_selectors.empty() &&
                !runtime_recovery_detail::
                    contains_global_destination_selector(
                        whatsapp_coverage);
            if (!whatsapp_coverage_complete) {
                call_affinity_targets.clear();
                trusted_whatsapp_marks.clear();
                whatsapp_destination_selectors.clear();
                idle_stall_supervisor_.reset_affinity_detector();
            }
        }
        const auto owned_mask = firewall_state_.get_fwmark_mask();
        const bool preventive_whatsapp_authorized =
            preventive_guard_available &&
            !active_preventive_guard_lists.empty() &&
            trusted_whatsapp_marks.size() == 1U && owned_mask != 0U &&
            *trusted_whatsapp_marks.begin() != 0U &&
            (*trusted_whatsapp_marks.begin() & ~owned_mask) == 0U;
        const bool packaged_whatsapp_only_observation =
            preventive_whatsapp_authorized &&
            selected_list_names == active_preventive_guard_lists;
        const std::optional<std::uint32_t> preventive_owned_mark =
            preventive_whatsapp_authorized
            ? std::optional<std::uint32_t>{
                  *trusted_whatsapp_marks.begin()}
            : std::nullopt;
        idle_stall_supervisor_.update_observation_scope(
            destination_selectors,
            whatsapp_destination_selectors,
            preventive_owned_mark,
            packaged_whatsapp_only_observation);
        const auto affinity_snapshot_time =
            UdpCallAffinityDetector::Clock::now();
        const auto retained_affinity_sources =
            call_affinity_targets.empty()
            ? std::vector<std::string>{}
            : idle_stall_supervisor_.affinity_detector().
                  retained_guard_sources(
                  affinity_snapshot_time);
        const auto runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const auto coverage_generation =
            idle_stall_supervisor_.coverage_generation();
        const bool ipv6_enabled = resolve_ipv6_support(active_config_snapshot_->config).enabled;
        if (runtime_generation == 0U || coverage_generation == 0U ||
            owned_mask == 0U) {
            idle_stall_supervisor_.reset_detectors();
            schedule_idle_stall_observer_after(
                IDLE_STALL_QUIET_SCAN_INTERVAL);
            return;
        }

        if (!idle_stall_supervisor_.try_begin_inflight()) {
            schedule_idle_stall_observer_after(
                IDLE_STALL_ACTIVE_SCAN_INTERVAL);
            return;
        }

        const TraceId trace_id = ensure_trace_id();
        const bool enqueued = blocking_executor_.try_post(
            "idle-stall-conntrack-scan",
            [this,
             runtime_generation,
             coverage_generation,
             owned_mask,
             ipv6_enabled,
             coverage_complete,
             call_affinity_targets,
             retained_affinity_sources,
             trusted_whatsapp_marks,
             preventive_whatsapp_authorized,
             packaged_whatsapp_only_observation,
             whatsapp_destination_selectors,
             destination_selectors =
                 std::move(destination_selectors)]() mutable {
                auto inflight_guard =
                    idle_stall_supervisor_.adopt_inflight();
                ConntrackFlowObservation observation;
                std::vector<std::string> local_interface_addresses;
                std::string failure_detail;

                const auto generation_is_current = [this,
                                                     runtime_generation,
                                                     coverage_generation]() {
                    return idle_stall_supervisor_.enabled() &&
                           runtime_generation_.load(
                               std::memory_order_acquire) ==
                               runtime_generation &&
                           idle_stall_supervisor_.current_coverage(
                               coverage_generation);
                };

                try {
                    if (generation_is_current()) {
                        local_interface_addresses =
                            local_interface_addresses_from(
                                netlink_.dump_interfaces());
                    }
                    // This is the last fence before the bounded /proc scan.
                    if (generation_is_current()) {
                        observation = conntrack_manager_.
                            observe_forwarded_destination_flows(
                                destination_selectors,
                                local_interface_addresses,
                                owned_mask,
                                idle_stall_observation_options(
                                    ipv6_enabled,
                                    packaged_whatsapp_only_observation),
                                retained_affinity_sources,
                                whatsapp_destination_selectors,
                                trusted_whatsapp_marks);
                    }
                } catch (const std::exception& error) {
                    failure_detail = error.what();
                    observation.snapshot_unavailable = true;
                } catch (...) {
                    failure_detail = "unknown observation error";
                    observation.snapshot_unavailable = true;
                }

                const bool commit_posted = post_control_task(
                    [this,
                     runtime_generation,
                     coverage_generation,
                     owned_mask,
                     observation = std::move(observation),
                     local_interface_addresses =
                         std::move(local_interface_addresses),
                     destination_selectors =
                         std::move(destination_selectors),
                      whatsapp_destination_selectors =
                          std::move(whatsapp_destination_selectors),
                      call_affinity_targets =
                          std::move(call_affinity_targets),
                      trusted_whatsapp_marks =
                          std::move(trusted_whatsapp_marks),
                      preventive_whatsapp_authorized,
                      packaged_whatsapp_only_observation,
                      ipv6_enabled,
                     coverage_complete,
                     failure_detail =
                         std::move(failure_detail)]() mutable {
                        try {
                            commit_idle_stall_observation(
                                runtime_generation,
                                coverage_generation,
                                owned_mask,
                                std::move(observation),
                                std::move(local_interface_addresses),
                                std::move(destination_selectors),
                                std::move(whatsapp_destination_selectors),
                                std::move(call_affinity_targets),
                                std::move(trusted_whatsapp_marks),
                                preventive_whatsapp_authorized,
                                packaged_whatsapp_only_observation,
                                ipv6_enabled,
                                coverage_complete,
                                std::move(failure_detail));
                        } catch (const std::exception& error) {
                            idle_stall_supervisor_.finish_inflight();
                            idle_stall_supervisor_.reset_detectors();
                            Logger::instance().info(
                                "Idle forwarded-flow observation commit "
                                "failed closed: {}",
                                error.what());
                            schedule_idle_stall_observer_after(
                                IDLE_STALL_QUIET_SCAN_INTERVAL);
                        } catch (...) {
                            idle_stall_supervisor_.finish_inflight();
                            idle_stall_supervisor_.reset_detectors();
                            schedule_idle_stall_observer_after(
                                IDLE_STALL_QUIET_SCAN_INTERVAL);
                        }
                    },
                    "idle-stall-observation-commit");
                if (commit_posted) {
                    // The control-loop commit now owns single-flight release.
                    inflight_guard.release();
                }
            },
            trace_id);

        if (!enqueued) {
            idle_stall_supervisor_.finish_inflight();
            schedule_idle_stall_observer_after(
                IDLE_STALL_ACTIVE_SCAN_INTERVAL);
        }
    } catch (const std::exception& error) {
        idle_stall_supervisor_.finish_inflight();
        idle_stall_supervisor_.reset_detectors();
        Logger::instance().info(
            "Idle forwarded-flow observation failed closed: {}",
            error.what());
        schedule_idle_stall_observer_after(
            IDLE_STALL_QUIET_SCAN_INTERVAL);
    } catch (...) {
        idle_stall_supervisor_.finish_inflight();
        idle_stall_supervisor_.reset_detectors();
        schedule_idle_stall_observer_after(
            IDLE_STALL_QUIET_SCAN_INTERVAL);
    }
}

void Daemon::execute_runtime_background_point_mutation(
    const RuntimeBackgroundPointMutationTarget& target,
    RuntimeBackgroundPointMutationResult& result) noexcept {
    if (!target.valid() ||
        runtime_firewall_owner_->shutdown_requested()) {
        return;
    }

    try {
        switch (target.kind) {
        case RuntimeBackgroundPointMutationKind::udp_call_affinity: {
            const auto& operation =
                std::get<RuntimeUdpCallAffinityPointMutationTarget>(
                    target.payload);
            RuntimeUdpCallAffinityPointMutationResult typed;
            typed.outcomes.reserve(operation.work.size());
            for (const auto& item : operation.work) {
                RuntimeUdpCallAffinityPointMutationOutcome outcome;
                outcome.decision = item.decision;
                typed.outcomes.push_back(std::move(outcome));
            }
            result.payload = std::move(typed);
            auto& output =
                std::get<RuntimeUdpCallAffinityPointMutationResult>(
                    result.payload);

            const auto generation_is_current =
                [this, &operation]() noexcept {
                    return running_.load(std::memory_order_acquire) &&
                           idle_stall_supervisor_.enabled() &&
                           runtime_generation_.load(
                               std::memory_order_acquire) ==
                               operation.runtime_generation &&
                           idle_stall_supervisor_.current_coverage(
                               operation.coverage_generation);
            };
            KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
            if (!generation_is_current() || !firewall_) {
                result.completed = true;
                return;
            }
            result.generation_revalidated = true;

            const auto revalidate_decision =
                [this,
                 &operation,
                 &generation_is_current](
                    const UdpCallAffinityDecision& decision,
                    UdpCallAffinityRevalidationMode mode)
                    -> std::optional<
                        std::vector<ConntrackExactForwardedFlow>> {
                if (!generation_is_current() ||
                    UdpCallAffinityDetector::Clock::now() >=
                        operation.decision_deadline) {
                    return std::nullopt;
                }
                try {
                    const auto local_addresses =
                        local_interface_addresses_from(
                            netlink_.dump_interfaces());
                    if (local_addresses.empty()) {
                        return std::nullopt;
                    }
                    const std::vector<std::string> destinations{
                        decision.destination};
                    const std::vector<std::string> sources{
                        decision.source};
                    const auto current = conntrack_manager_.
                        observe_forwarded_destination_flows(
                            destinations,
                            local_addresses,
                            operation.owned_mask,
                            ConntrackFlowObservationOptions{
                                operation.ipv6_enabled,
                                IDLE_STALL_MAX_FLOWS,
                                IDLE_STALL_MAX_DESTINATION_CIDRS,
                                IDLE_STALL_MAX_SNAPSHOT_BYTES,
                                IDLE_STALL_MAX_SNAPSHOT_LINES,
                                /*allow_foreign_mark_bits_for_media=*/true},
                            sources);
                    if (!generation_is_current() ||
                        UdpCallAffinityDetector::Clock::now() >=
                            operation.decision_deadline ||
                        current.snapshot_unavailable ||
                        current.snapshot_truncated ||
                        current.line_limit_reached ||
                        current.flow_limit_reached ||
                        current.local_address_scope_missing ||
                        current.destination_input_truncated ||
                        current.invalid_destination_selectors != 0U ||
                        current.invalid_media_guard_sources != 0U ||
                        current.invalid_owned_mask) {
                        return std::nullopt;
                    }

                    if (mode ==
                        UdpCallAffinityRevalidationMode::
                            BeforePublication) {
                        const bool peer_became_ambiguous = std::any_of(
                            current.source_wide_udp_flows.begin(),
                            current.source_wide_udp_flows.end(),
                            [&decision, &operation](
                                const auto& candidate) {
                                if (candidate.family != decision.family ||
                                    candidate.source != decision.source ||
                                    candidate.destination_port !=
                                        decision.destination_port ||
                                    candidate.destination !=
                                        decision.destination) {
                                    return false;
                                }
                                return (candidate.mark &
                                            operation.owned_mask) != 0U ||
                                       candidate.assured ||
                                       candidate.seen_reply ||
                                       candidate.reply.packets != 0U ||
                                       candidate.reply.bytes != 0U;
                            });
                        if (peer_became_ambiguous) {
                            return std::vector<
                                ConntrackExactForwardedFlow>{};
                        }
                    }

                    std::vector<ConntrackExactForwardedFlow>
                        revalidated_flows;
                    revalidated_flows.reserve(
                        decision.baseline_flows.size());
                    for (const auto& baseline :
                         decision.baseline_flows) {
                        const auto live = std::find_if(
                            current.source_wide_udp_flows.begin(),
                            current.source_wide_udp_flows.end(),
                            [&baseline,
                             &decision,
                             mode,
                             &operation](const auto& candidate) {
                                if (!same_forwarded_five_tuple(
                                        candidate, baseline)) {
                                    return false;
                                }
                                if (mode ==
                                    UdpCallAffinityRevalidationMode::
                                        BeforePublication) {
                                    return candidate.mark ==
                                           baseline.mark;
                                }
                                const auto owned_mark =
                                    candidate.mark &
                                    operation.owned_mask;
                                return owned_mark == 0U ||
                                       owned_mark == decision.fwmark;
                            });
                        const bool mark_is_allowed =
                            live !=
                                current.source_wide_udp_flows.end() &&
                            ((mode ==
                                  UdpCallAffinityRevalidationMode::
                                      BeforePublication &&
                              live->mark == baseline.mark) ||
                             (mode !=
                                  UdpCallAffinityRevalidationMode::
                                      BeforePublication &&
                              (((live->mark &
                                  operation.owned_mask) == 0U) ||
                               ((live->mark &
                                 operation.owned_mask) ==
                                decision.fwmark))));
                        const bool refresh_still_active =
                            live !=
                                current.source_wide_udp_flows.end() &&
                            live->protocol ==
                                ConntrackFlowProtocol::Udp &&
                            mark_is_allowed && live->assured &&
                            live->seen_reply &&
                            live->original.packets >=
                                baseline.original.packets &&
                            live->original.bytes >=
                                baseline.original.bytes &&
                            live->reply.packets >=
                                baseline.reply.packets &&
                            live->reply.bytes >=
                                baseline.reply.bytes;
                        const bool still_unanswered =
                            live !=
                                current.source_wide_udp_flows.end() &&
                            live->protocol ==
                                ConntrackFlowProtocol::Udp &&
                            mark_is_allowed && !live->assured &&
                            !live->seen_reply &&
                            live->reply.packets == 0U &&
                            live->reply.bytes == 0U &&
                            live->original.packets >=
                                baseline.original.packets &&
                            live->original.bytes >=
                                baseline.original.bytes;
                        if ((mode ==
                                 UdpCallAffinityRevalidationMode::
                                     RefreshBeforePublication &&
                             refresh_still_active) ||
                            (mode !=
                                 UdpCallAffinityRevalidationMode::
                                     RefreshBeforePublication &&
                             still_unanswered)) {
                            revalidated_flows.push_back(*live);
                        }
                    }
                    return revalidated_flows;
                } catch (...) {
                    return std::nullopt;
                }
            };

            for (std::size_t index = 0U;
                 index < output.outcomes.size();
                 ++index) {
                if (!generation_is_current()) break;
                auto& outcome = output.outcomes[index];
                if (UdpCallAffinityDetector::Clock::now() >=
                    operation.decision_deadline) {
                    outcome.deadline_expired = true;
                    continue;
                }
                const auto before_publication = revalidate_decision(
                    outcome.decision,
                    outcome.decision.refresh_only
                        ? UdpCallAffinityRevalidationMode::
                              RefreshBeforePublication
                        : UdpCallAffinityRevalidationMode::
                              BeforePublication);
                if (!before_publication.has_value()) {
                    if (!generation_is_current()) break;
                    if (UdpCallAffinityDetector::Clock::now() >=
                        operation.decision_deadline) {
                        outcome.deadline_expired = true;
                    } else {
                        outcome.revalidation_failed = true;
                    }
                    continue;
                }
                if (before_publication->empty()) continue;
                if (!generation_is_current()) break;
                if (UdpCallAffinityDetector::Clock::now() >=
                    operation.decision_deadline) {
                    outcome.deadline_expired = true;
                    continue;
                }

                outcome.publication_attempted = true;
                FirewallUdpPeerMutationResult publication;
                try {
                    publication = firewall_->add_udp_peer(
                        operation.work[index].set_name,
                        outcome.decision.source,
                        outcome.decision.destination_port,
                        outcome.decision.destination);
                } catch (...) {
                    // The backend may have crossed into ipset/nft before an
                    // exception escaped. Without a typed proof, preserve
                    // recovery authority instead of claiming a no-op.
                    publication.mutation_boundary_entered = true;
                }
                result.mutation_boundary_entered =
                    result.mutation_boundary_entered ||
                    publication.mutation_boundary_entered;
                outcome.installed = publication.publication_verified;
                outcome.publication_ambiguous =
                    publication.ambiguous();
                if (!outcome.installed ||
                    outcome.decision.refresh_only ||
                    output.conntrack_unavailable) {
                    continue;
                }
                if (!generation_is_current()) break;
                if (UdpCallAffinityDetector::Clock::now() >=
                    operation.decision_deadline) {
                    outcome.deadline_expired = true;
                    continue;
                }

                const auto after_publication = revalidate_decision(
                    outcome.decision,
                    UdpCallAffinityRevalidationMode::
                        AfterPublication);
                if (!after_publication.has_value()) {
                    if (!generation_is_current()) break;
                    if (UdpCallAffinityDetector::Clock::now() >=
                        operation.decision_deadline) {
                        outcome.deadline_expired = true;
                    } else {
                        outcome.revalidation_failed = true;
                    }
                    continue;
                }
                outcome.revalidated_flows = *after_publication;
                for (const auto& flow :
                     outcome.revalidated_flows) {
                    if (!generation_is_current()) break;
                    if (UdpCallAffinityDetector::Clock::now() >=
                        operation.decision_deadline) {
                        outcome.deadline_expired = true;
                        break;
                    }
                    result.mutation_boundary_entered = true;
                    ConntrackCleanupResult cleanup =
                        ConntrackCleanupResult::Failed;
                    try {
                        cleanup = conntrack_manager_.
                            delete_exact_forwarded_flow(
                                flow,
                                operation.owned_mask,
                                outcome.decision.fwmark);
                    } catch (...) {
                        ++outcome.failed_flows;
                        continue;
                    }
                    if (cleanup ==
                        ConntrackCleanupResult::Succeeded) {
                        ++outcome.retired_flows;
                    } else if (
                        cleanup ==
                        ConntrackCleanupResult::
                            CommandUnavailable) {
                        output.conntrack_unavailable = true;
                        ++outcome.failed_flows;
                        break;
                    } else {
                        ++outcome.failed_flows;
                    }
                }
            }
            result.completed = true;
            return;
        }
        case RuntimeBackgroundPointMutationKind::
                idle_stall_exact_cleanup: {
            const auto& operation = std::get<
                RuntimeIdleStallExactCleanupPointMutationTarget>(
                target.payload);
            RuntimeIdleStallExactCleanupPointMutationResult typed;
            typed.outcomes.reserve(operation.work.size());
            for (const auto& item : operation.work) {
                RuntimeIdleStallExactCleanupPointMutationOutcome outcome;
                outcome.decision = item.decision;
                outcome.flow = item.flow;
                typed.outcomes.push_back(std::move(outcome));
            }
            result.payload = std::move(typed);
            auto& output = std::get<
                RuntimeIdleStallExactCleanupPointMutationResult>(
                result.payload);
            const auto generation_is_current =
                [this, &operation]() noexcept {
                    return running_.load(std::memory_order_acquire) &&
                        idle_stall_supervisor_.enabled() &&
                        runtime_generation_.load(
                            std::memory_order_acquire) ==
                            operation.runtime_generation &&
                        idle_stall_supervisor_.current_coverage(
                            operation.coverage_generation);
                };
            KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
            if (!generation_is_current()) {
                result.completed = true;
                return;
            }
            result.generation_revalidated = true;
            for (std::size_t index = 0U;
                 index < operation.work.size();
                 ++index) {
                if (!generation_is_current()) break;
                const auto& item = operation.work[index];
                auto& outcome = output.outcomes[index];
                const auto observed =
                    conntrack_manager_.observe_exact_forwarded_flow(
                        item.flow, operation.owned_mask);
                if (observed.status !=
                        ConntrackExactFlowObservationStatus::Observed ||
                    !observed.flow.has_value() ||
                    !runtime_background_same_exact_flow_selector(
                        *observed.flow, item.flow) ||
                    observed.flow->original.packets <
                        item.flow.original.packets ||
                    observed.flow->original.bytes <
                        item.flow.original.bytes ||
                    observed.flow->reply.packets <
                        item.flow.reply.packets ||
                    observed.flow->reply.bytes <
                        item.flow.reply.bytes ||
                    observed.flow->reply.bytes -
                            item.flow.reply.bytes >
                        IDLE_STALL_APPLICATION_REPLY_BYTES) {
                    continue;
                }
                const bool state_eligible =
                    (observed.flow->protocol ==
                         ConntrackFlowProtocol::Tcp &&
                     observed.flow->tcp_state ==
                         std::optional<ConntrackTcpState>{
                             ConntrackTcpState::Established}) ||
                    (observed.flow->protocol ==
                         ConntrackFlowProtocol::Udp &&
                     observed.flow->assured);
                if (!state_eligible) continue;
                outcome.attempted = true;
                result.mutation_boundary_entered = true;
                try {
                    outcome.cleanup_result = conntrack_manager_.
                        delete_exact_forwarded_flow(
                            *observed.flow, operation.owned_mask);
                } catch (...) {
                    outcome.cleanup_result =
                        ConntrackCleanupResult::Failed;
                }
                if (outcome.cleanup_result ==
                    ConntrackCleanupResult::CommandUnavailable) {
                    output.command_unavailable = true;
                    break;
                }
            }
            result.completed = true;
            return;
        }
        case RuntimeBackgroundPointMutationKind::meta_udp443_cleanup: {
            const auto& operation = std::get<
                RuntimeMetaUdp443CleanupPointMutationTarget>(
                target.payload);
            result.payload =
                RuntimeMetaUdp443CleanupPointMutationResult{};
            auto& output = std::get<
                RuntimeMetaUdp443CleanupPointMutationResult>(
                result.payload);
            auto plan = operation.plan;
            const auto still_current =
                [this, &operation]() noexcept {
                    return meta_udp443_cleanup_authority_matches(
                        operation.runtime_generation,
                        runtime_generation_.load(
                            std::memory_order_acquire),
                        operation.cleanup_epoch,
                        meta_udp443_cleanup_epoch_.load(
                            std::memory_order_acquire));
                };
            try {
                KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
                if (!still_current() || !firewall_) {
                    output.cleanup.remaining_flows =
                        plan.exact_flows;
                    output.cleanup.generation_changed =
                        !still_current();
                    result.completed = true;
                    return;
                }
                result.generation_revalidated = true;
                output.before =
                    firewall_->inspect_forward_udp_reject_state();
                output.fastnat_before =
                    fastnat_is_disabled_or_unavailable();
                if (still_current() && output.fastnat_before &&
                    output.before ==
                        OwnedForwardUdpRejectState::healthy) {
                    const auto local_addresses =
                        local_interface_addresses_from(
                            netlink_.dump_interfaces());
                    const auto observation = conntrack_manager_.
                        observe_forwarded_destination_flows(
                            plan.destination_selectors,
                            local_addresses,
                            plan.owned_mask,
                            meta_udp443_activation_observation_options(
                                plan.ipv6_enabled),
                            {},
                            plan.destination_selectors,
                            {});
                    const auto candidates =
                        select_meta_udp_443_cleanup_candidates(
                            observation,
                            plan.cleanup_owned_marks,
                            plan.owned_mask,
                            plan.allow_unmarked_cleanup);
                    if (!candidates.complete) {
                        output.worker_failure =
                            "post-publication exact UDP/443 snapshot "
                            "is incomplete";
                        output.cleanup.remaining_flows =
                            plan.exact_flows;
                    } else {
                        plan.exact_flows = candidates.flows;
                        if (!plan.exact_flows.empty()) {
                            result.mutation_boundary_entered = true;
                        }
                        output.cleanup = conntrack_manager_.
                            delete_exact_forwarded_flows(
                                plan.exact_flows,
                                plan.owned_mask,
                                plan.cleanup_owned_marks,
                                ConntrackExactFlowCleanupOptions{
                                    META_UDP443_ACTIVATION_BATCH_BUDGET,
                                    META_UDP443_ACTIVATION_BATCH_SIZE},
                                still_current);
                    }
                } else {
                    output.cleanup.remaining_flows =
                        plan.exact_flows;
                    output.cleanup.generation_changed =
                        !still_current();
                }
                if (still_current()) {
                    output.after =
                        firewall_->inspect_forward_udp_reject_state();
                    output.fastnat_after =
                        fastnat_is_disabled_or_unavailable();
                }
            } catch (const std::exception& error) {
                try { output.worker_failure = error.what(); }
                catch (...) {
                    output.worker_failure =
                        "exact cleanup worker failure";
                }
                output.cleanup.remaining_flows = plan.exact_flows;
            } catch (...) {
                output.worker_failure =
                    "unknown exact cleanup worker failure";
                output.cleanup.remaining_flows = plan.exact_flows;
            }
            result.completed = true;
            return;
        }
        case RuntimeBackgroundPointMutationKind::
                owned_conntrack_cleanup: {
            const auto& operation = std::get<
                RuntimeOwnedConntrackCleanupPointMutationTarget>(
                target.payload);
            result.payload =
                RuntimeOwnedConntrackCleanupPointMutationResult{};
            auto& output = std::get<
                RuntimeOwnedConntrackCleanupPointMutationResult>(
                result.payload);
            KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
            bool active = false;
            try { active = routing_runtime_active(); }
            catch (...) {}
            if (!active ||
                runtime_generation_.load(std::memory_order_acquire) !=
                    operation.retry.snapshot.runtime_generation) {
                output.cleanup.remaining_marks =
                    operation.retry.ordered_marks;
                result.completed = true;
                return;
            }
            result.generation_revalidated = true;
            result.mutation_boundary_entered = true;
            try {
                output.cleanup =
                    conntrack_manager_.delete_marks_ordered(
                        operation.retry.ordered_marks,
                        operation.retry.snapshot.owned_mask,
                        ConntrackCleanupOptions{
                            operation.retry.snapshot.ipv6_enabled,
                            OWNED_CONNTRACK_CLEANUP_RETRY_BUDGET,
                            OWNED_CONNTRACK_CLEANUP_RETRY_BATCH_SIZE});
            } catch (...) {
                output.cleanup.failed =
                    operation.retry.ordered_marks.size();
                output.cleanup.remaining_marks =
                    operation.retry.ordered_marks;
            }
            result.completed = true;
            return;
        }
        }
    } catch (...) {
    }
}

void Daemon::dispatch_udp_call_affinity_mutations(
    std::uint64_t expected_runtime_generation,
    std::uint64_t expected_coverage_generation,
    std::uint32_t owned_mask,
    bool ipv6_enabled,
    UdpCallAffinityDetector::TimePoint decision_deadline,
    std::vector<UdpCallAffinityDecision> decisions) {
    if (decisions.empty()) return;
    const auto release_decisions = [this, &decisions]() noexcept {
        for (const auto& decision : decisions) {
            try {
                idle_stall_supervisor_.affinity_detector().
                    release_failed(decision);
            }
            catch (...) {}
        }
    };
    const auto generation_is_current =
        [this, expected_runtime_generation,
         expected_coverage_generation]() noexcept {
            try {
                return running_.load(std::memory_order_acquire) &&
                    routing_runtime_active() &&
                    idle_stall_supervisor_.enabled() &&
                    runtime_generation_.load(std::memory_order_acquire) ==
                        expected_runtime_generation &&
                    idle_stall_supervisor_.current_coverage(
                        expected_coverage_generation);
            } catch (...) { return false; }
        };
    if (!generation_is_current() || !firewall_) {
        release_decisions();
        return;
    }
    try {
        RuntimeUdpCallAffinityPointMutationTarget operation;
        operation.runtime_generation = expected_runtime_generation;
        operation.coverage_generation = expected_coverage_generation;
        operation.owned_mask = owned_mask;
        operation.ipv6_enabled = ipv6_enabled;
        operation.decision_deadline = decision_deadline;
        operation.work.reserve(decisions.size());
        for (const auto& decision : decisions) {
            const int family =
                decision.family == ConntrackFlowFamily::Ipv6
                ? AF_INET6 : AF_INET;
            operation.work.push_back(
                RuntimeUdpCallAffinityPointMutationWork{
                    decision,
                    firewall_->media_affinity_set_name(
                        decision.list_name, family)});
        }
        RuntimeBackgroundPointMutationTarget target;
        target.kind =
            RuntimeBackgroundPointMutationKind::udp_call_affinity;
        target.target_serial = ++background_point_mutation_serial_;
        if (target.target_serial == 0U) {
            target.target_serial = ++background_point_mutation_serial_;
        }
        target.payload = std::move(operation);
        auto transaction = std::make_shared<
            RuntimeBackgroundPointMutationTransaction>(
            std::move(target));
        if (!transaction->valid()) {
            release_decisions();
            return;
        }
        auto admitted = runtime_mutation_admission_.try_acquire(
            "udp-call-affinity-point-mutation");
        if (!admitted.has_value()) {
            release_decisions();
            return;
        }
        auto lease = std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(*admitted));
        const auto expected_lease_token = lease->token();
        RuntimeFirewallPreownedTerminalContinuation continuation{
            [this, transaction, expected_runtime_generation,
             expected_coverage_generation, expected_lease_token](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                const auto& operation = std::get<
                    RuntimeUdpCallAffinityPointMutationTarget>(
                    transaction->target.payload);
                const auto release_all = [this, &operation]() noexcept {
                    for (const auto& item : operation.work) {
                        try {
                            idle_stall_supervisor_.affinity_detector().
                                release_failed(item.decision);
                        } catch (...) {}
                    }
                };
                const bool lease_returned =
                    exact && static_cast<bool>(*exact) &&
                    exact->token() == expected_lease_token &&
                    runtime_mutation_admission_.owns(*exact);
                bool current = false;
                try {
                    current =
                        terminal.outcome !=
                            RuntimeFirewallLifecycleOutcome::shutdown &&
                        running_.load(std::memory_order_acquire) &&
                        routing_runtime_active() &&
                        idle_stall_supervisor_.enabled() &&
                        runtime_generation_.load(
                            std::memory_order_acquire) ==
                            expected_runtime_generation &&
                        idle_stall_supervisor_.current_coverage(
                            expected_coverage_generation);
                } catch (...) {}
                const bool typed =
                    lease_returned &&
                    transaction->typed_identity_valid &&
                    transaction->result &&
                    transaction->result->control_publishable() &&
                    transaction->result->target ==
                        transaction->target &&
                    std::holds_alternative<
                        RuntimeUdpCallAffinityPointMutationResult>(
                        transaction->result->payload);
                if (terminal.commit_ambiguous ||
                    (transaction->result &&
                     transaction->result->
                         unsafe_publication_possible())) {
                    schedule_netfilter_runtime_refresh_noexcept(
                        NetfilterRefreshReason::full,
                        "could not schedule recovery after an "
                        "ambiguous UDP peer publication");
                    release_all();
                    exact.reset();
                    return;
                }
                if (!typed || !current) {
                    release_all();
                    exact.reset();
                    return;
                }
                const auto& output = std::get<
                    RuntimeUdpCallAffinityPointMutationResult>(
                    transaction->result->payload);
                std::size_t installed = 0U;
                std::size_t refreshed = 0U;
                std::size_t retired = 0U;
                std::size_t failures = 0U;
                const auto completed_at =
                    UdpCallAffinityDetector::Clock::now();
                for (const auto& outcome : output.outcomes) {
                    retired += outcome.retired_flows;
                    failures += outcome.failed_flows;
                    if (outcome.installed) {
                        bool accepted = false;
                        try {
                            accepted = idle_stall_supervisor_.
                                affinity_detector().
                                confirm_installed(
                                    outcome.decision, completed_at);
                        } catch (...) {
                            idle_stall_supervisor_.
                                reset_affinity_detector();
                        }
                        if (accepted) {
                            outcome.decision.refresh_only
                                ? ++refreshed : ++installed;
                        }
                    } else {
                        try {
                            idle_stall_supervisor_.affinity_detector().
                                release_failed(outcome.decision);
                        } catch (...) {}
                    }
                }
                try {
                    if (installed != 0U) {
                        Logger::instance().info(
                            "Activated {} short-lived WhatsApp call peer "
                            "pair(s) and retired {} exact stale flow(s)",
                            installed, retired);
                    }
                    if (refreshed != 0U) {
                        Logger::instance().verbose(
                            "Refreshed {} active WhatsApp call peer lease(s)",
                            refreshed);
                    }
                    if (output.conntrack_unavailable || failures != 0U) {
                        Logger::instance().info(
                            "WhatsApp call peer affinity left {} exact "
                            "stale-flow retirement(s) incomplete",
                            failures);
                    }
                } catch (...) {}
                exact.reset();
            }};
        if (begin_preowned_runtime_firewall_background_point_mutation(
                lease, transaction, continuation)) {
            return;
        }
        lease.reset();
        release_decisions();
    } catch (...) {
        release_decisions();
    }
}

void Daemon::commit_idle_stall_observation(
    std::uint64_t expected_runtime_generation,
    std::uint64_t expected_coverage_generation,
    std::uint32_t owned_mask,
    ConntrackFlowObservation observation,
    std::vector<std::string> observed_local_interface_addresses,
    std::vector<std::string> destination_selectors,
    std::vector<std::string> whatsapp_destination_selectors,
    std::vector<UdpCallAffinityTarget> call_affinity_targets,
    std::set<std::uint32_t> trusted_whatsapp_marks,
    bool preventive_whatsapp_authorized,
    bool packaged_whatsapp_only_observation,
    bool ipv6_enabled,
    bool coverage_complete,
    std::string failure_detail) {
    const auto generation_is_current = [this,
                                        expected_runtime_generation,
                                        expected_coverage_generation]() {
        return routing_runtime_active() &&
               runtime_generation_.load(std::memory_order_acquire) ==
                   expected_runtime_generation &&
               idle_stall_supervisor_.current_coverage(
                   expected_coverage_generation);
    };
    if (!generation_is_current()) {
        idle_stall_supervisor_.finish_inflight();
        return;
    }

    if (!failure_detail.empty()) {
        Logger::instance().trace(
            "idle_stall_observation_skip",
            "generation={} reason={}",
            expected_runtime_generation,
            failure_detail);
    }

    IdleStallScan scan;
    scan.epoch = IdleStallEpoch{
        expected_runtime_generation,
        expected_coverage_generation};
    scan.owned_mark_mask = owned_mask;
    scan.status.snapshot_complete =
        !observation.snapshot_unavailable &&
        !observation.snapshot_truncated &&
        !observation.line_limit_reached &&
        !observation.flow_limit_reached;
    scan.status.counters_available = true;
    scan.status.local_scope_complete =
        !observation.local_address_scope_missing &&
        !observed_local_interface_addresses.empty();
    scan.status.coverage_complete =
        coverage_complete &&
        !observation.destination_input_truncated &&
        observation.invalid_destination_selectors == 0U &&
        observation.invalid_media_seed_destination_selectors == 0U &&
        observation.invalid_media_seed_candidate_records == 0U &&
        !observation.media_seed_destination_input_truncated &&
        observation.invalid_media_guard_sources == 0U &&
        !observation.invalid_owned_mask;
    if (preventive_whatsapp_authorized &&
        preventive_whatsapp_media_guard_available(
            firewall_->backend(),
            opts_.udp_call_affinity_ipset_available) &&
        trusted_whatsapp_marks.size() == 1U) {
        const auto trusted_mark = *trusted_whatsapp_marks.begin();
        if (trusted_mark != 0U && owned_mask != 0U &&
            (trusted_mark & ~owned_mask) == 0U) {
            scan.preventive_tcp_reset_owned_mark = trusted_mark;
        }
    }
    std::set<IdleStallFlowKey> whatsapp_latency_flow_keys;
    for (const auto& flow : observation.media_seed_flows) {
        whatsapp_latency_flow_keys.insert(idle_stall_key_from(flow));
    }
    scan.flows.reserve(observation.flows.size());
    for (const auto& flow : observation.flows) {
        const auto key = idle_stall_key_from(flow);
        scan.flows.push_back(idle_stall_sample_from(
            flow,
            (packaged_whatsapp_only_observation ||
             whatsapp_latency_flow_keys.count(key) != 0U)
                ? IdleStallRecoveryPolicy::
                      packaged_whatsapp_ip_companion
                : IdleStallRecoveryPolicy::standard));
    }

    const auto observation_time = UdpCallAffinityDetector::Clock::now();
    std::vector<UdpCallAffinityDecision> affinity_decisions;
    try {
        affinity_decisions =
            idle_stall_supervisor_.affinity_detector().observe(
            scan.epoch,
            scan.status,
            owned_mask,
            call_affinity_targets,
            observation.media_seed_flows,
            observation.source_wide_udp_flows,
            observation_time);
    } catch (const std::exception& error) {
        idle_stall_supervisor_.reset_affinity_detector();
        Logger::instance().info(
            "UDP call affinity detector failed closed: {}",
            error.what());
    } catch (...) {
        idle_stall_supervisor_.reset_affinity_detector();
    }
    const bool affinity_fast_followup =
        idle_stall_supervisor_.affinity_detector().needs_fast_followup(
            observation_time);
    const bool affinity_discovery_enabled =
        !call_affinity_targets.empty();

    // A classifier publication completion can land on the control loop while
    // the blocking conntrack snapshot is in progress. Recompute exact guard
    // authority after observe() so that a newly confirmed call peer is visible
    // to the final live revalidation, while an expired/reset peer is not.
    auto retained_affinity_peers = call_affinity_targets.empty()
        ? std::vector<UdpCallAffinityGuardPeer>{}
        : idle_stall_supervisor_.affinity_detector().
              retained_guard_peers(
              observation_time);

    dispatch_udp_call_affinity_mutations(
        expected_runtime_generation,
        expected_coverage_generation,
        owned_mask,
        ipv6_enabled,
        observation_time + UDP_CALL_AFFINITY_MUTATION_DEADLINE,
        std::move(affinity_decisions));

    std::vector<IdleStallDeleteDecision> decisions;
    try {
        decisions = idle_stall_supervisor_.idle_detector().observe(
            scan, observation_time);
    } catch (const std::exception& error) {
        idle_stall_supervisor_.reset_idle_detector();
        Logger::instance().info(
            "Idle forwarded-flow detector failed closed: {}",
            error.what());
    } catch (...) {
        idle_stall_supervisor_.reset_idle_detector();
    }
    const bool relevant_flows_observed =
        !observation.flows.empty() ||
        !observation.source_wide_udp_flows.empty();
    if (decisions.empty()) {
        const auto whatsapp_fast_followup =
            idle_stall_supervisor_.idle_detector().
                take_whatsapp_fast_followup_delay();
        idle_stall_supervisor_.finish_inflight();
        // A bounded/truncated snapshot cannot produce a safe decision. Back
        // off instead of reparsing the same oversized conntrack table every
        // five seconds on a small router.
        auto next_interval = IDLE_STALL_QUIET_SCAN_INTERVAL;
        if (scan.status.trustworthy()) {
            if (whatsapp_fast_followup.has_value()) {
                next_interval = *whatsapp_fast_followup;
            } else if (affinity_fast_followup) {
                next_interval = UDP_CALL_AFFINITY_FAST_SCAN_INTERVAL;
            } else if (relevant_flows_observed ||
                       idle_stall_supervisor_.idle_detector().
                           tracked_flow_count() != 0U) {
                next_interval = IDLE_STALL_ACTIVE_SCAN_INTERVAL;
            } else if (affinity_discovery_enabled) {
                next_interval =
                    UDP_CALL_AFFINITY_DISCOVERY_SCAN_INTERVAL;
            }
        }
        schedule_idle_stall_observer_after(next_interval);
        return;
    }

    std::vector<IdleStallPendingDelete> pending_deletes;
    std::vector<ConntrackExactForwardedFlow> media_baselines;
    pending_deletes.reserve(decisions.size());
    for (const auto& flow : observation.media_seed_flows) {
        if (flow.protocol == ConntrackFlowProtocol::Udp && flow.assured) {
            media_baselines.push_back(flow);
        }
    }
    for (const auto& flow : observation.source_wide_udp_flows) {
        const bool exact_retained_peer = std::any_of(
            retained_affinity_peers.begin(),
            retained_affinity_peers.end(),
            [&flow, owned_mask](const auto& peer) {
                return udp_call_affinity_detail::guard_peer_matches(
                    peer, flow, owned_mask);
            });
        if (flow.protocol == ConntrackFlowProtocol::Udp && flow.assured &&
            exact_retained_peer) {
            const bool duplicate = std::any_of(
                media_baselines.begin(),
                media_baselines.end(),
                [&flow](const auto& candidate) {
                    return udp_call_affinity_detail::same_exact_flow(
                        candidate, flow);
                });
            if (!duplicate) {
                media_baselines.push_back(flow);
            }
        }
    }
    for (const auto& decision : decisions) {
        const auto flow = std::find_if(
            observation.flows.begin(),
            observation.flows.end(),
            [&decision](const ConntrackExactForwardedFlow& candidate) {
                return idle_stall_key_from(candidate) == decision.flow;
            });
        if (flow != observation.flows.end()) {
            pending_deletes.push_back(
                IdleStallPendingDelete{decision, *flow});
        }
    }
    const auto release_pending_decisions = [this, &decisions]() {
        const auto now = IdleStallDetector::Clock::now();
        for (const auto& decision : decisions) {
            idle_stall_supervisor_.idle_detector().
                acknowledge_delete_result(
                decision, false, now);
        }
    };
    if (pending_deletes.empty() || !generation_is_current()) {
        release_pending_decisions();
        idle_stall_supervisor_.finish_inflight();
        const auto fast_followup =
            idle_stall_supervisor_.idle_detector().
                take_whatsapp_fast_followup_delay();
        const auto next_interval =
            fast_followup.value_or(IDLE_STALL_ACTIVE_SCAN_INTERVAL);
        schedule_idle_stall_observer_after(next_interval);
        return;
    }
    std::set<std::pair<ConntrackFlowFamily, std::string>> pending_sources;
    for (const auto& pending : pending_deletes) {
        pending_sources.emplace(pending.flow.family, pending.flow.source);
    }
    std::vector<std::string> media_guard_sources;
    media_guard_sources.reserve(retained_affinity_peers.size());
    for (const auto& peer : retained_affinity_peers) {
        if (pending_sources.count({peer.family, peer.source}) != 0U) {
            media_guard_sources.push_back(peer.source);
        }
    }
    std::sort(media_guard_sources.begin(), media_guard_sources.end());
    media_guard_sources.erase(
        std::unique(media_guard_sources.begin(), media_guard_sources.end()),
        media_guard_sources.end());

    const TraceId trace_id = ensure_trace_id();
    const bool enqueued = blocking_executor_.try_post(
        "idle-stall-exact-delete",
        [this,
         expected_runtime_generation,
         expected_coverage_generation,
         owned_mask,
         pending_deletes = std::move(pending_deletes),
         media_baselines = std::move(media_baselines),
         media_guard_sources = std::move(media_guard_sources),
         retained_affinity_peers = std::move(retained_affinity_peers),
         destination_selectors = std::move(destination_selectors),
         whatsapp_destination_selectors =
             std::move(whatsapp_destination_selectors),
         trusted_whatsapp_marks = std::move(trusted_whatsapp_marks),
         packaged_whatsapp_only_observation,
         ipv6_enabled,
         observed_local_interface_addresses =
             std::move(observed_local_interface_addresses)]() mutable {
            auto inflight_guard =
                idle_stall_supervisor_.adopt_inflight();
            std::size_t media_protected = 0U;
            std::size_t recovered_or_replaced = 0U;
            bool live_scope_changed = false;
            std::vector<IdleStallDeleteDecision> all_decisions;
            all_decisions.reserve(pending_deletes.size());
            for (const auto& pending : pending_deletes) {
                all_decisions.push_back(pending.decision);
            }

            const auto generation_is_current = [this,
                                                 expected_runtime_generation,
                                                 expected_coverage_generation]() {
                return runtime_generation_.load(
                           std::memory_order_acquire) ==
                           expected_runtime_generation &&
                       idle_stall_supervisor_.current_coverage(
                           expected_coverage_generation);
            };

            try {
                if (!generation_is_current()) {
                    live_scope_changed = true;
                } else {
                    const auto current_local_interface_addresses =
                        local_interface_addresses_from(
                            netlink_.dump_interfaces());
                    live_scope_changed =
                        current_local_interface_addresses.empty() ||
                        current_local_interface_addresses !=
                            observed_local_interface_addresses;
                    if (!live_scope_changed && generation_is_current()) {
                        const auto current_observation = conntrack_manager_.
                            observe_forwarded_destination_flows(
                                destination_selectors,
                                current_local_interface_addresses,
                                owned_mask,
                                idle_stall_observation_options(
                                    ipv6_enabled,
                                    packaged_whatsapp_only_observation),
                                media_guard_sources,
                                whatsapp_destination_selectors,
                                trusted_whatsapp_marks);
                        live_scope_changed =
                            current_observation.snapshot_unavailable ||
                            current_observation.snapshot_truncated ||
                            current_observation.line_limit_reached ||
                            current_observation.flow_limit_reached ||
                            current_observation.local_address_scope_missing ||
                            current_observation.destination_input_truncated ||
                            current_observation.invalid_owned_mask ||
                            current_observation.
                                    media_seed_destination_input_truncated ||
                            current_observation.
                                    invalid_media_guard_sources != 0U ||
                            current_observation.
                                    invalid_destination_selectors != 0U ||
                            current_observation.
                                    invalid_media_seed_destination_selectors !=
                                0U ||
                            current_observation.
                                    invalid_media_seed_candidate_records !=
                                0U;

                        std::set<std::pair<ConntrackFlowFamily, std::string>>
                            protected_sources;
                        if (!live_scope_changed) {
                            protected_sources =
                                active_udp_media_guard_sources(
                                    media_baselines,
                                    current_observation.media_seed_flows,
                                    current_observation.
                                        source_wide_udp_flows,
                                    retained_affinity_peers,
                                    owned_mask,
                                    trusted_whatsapp_marks);
                        }

                        if (!live_scope_changed) {
                            pending_deletes.erase(
                                std::remove_if(
                                    pending_deletes.begin(),
                                    pending_deletes.end(),
                                    [&protected_sources,
                                     &media_protected](const auto& pending) {
                                        if (protected_sources.count(
                                                {pending.flow.family,
                                                 pending.flow.source}) == 0U) {
                                            return false;
                                        }
                                        ++media_protected;
                                        return true;
                                    }),
                                pending_deletes.end());

                            std::vector<IdleStallPendingDelete>
                                still_stalled;
                            still_stalled.reserve(pending_deletes.size());
                            for (auto& pending : pending_deletes) {
                                const auto current = std::find_if(
                                    current_observation.flows.begin(),
                                    current_observation.flows.end(),
                                    [&pending](const auto& observed) {
                                        return idle_stall_key_from(observed) ==
                                               idle_stall_key_from(
                                                   pending.flow);
                                    });
                                const bool current_state_eligible =
                                    current !=
                                        current_observation.flows.end() &&
                                    ((current->protocol ==
                                          ConntrackFlowProtocol::Tcp &&
                                      current->tcp_state ==
                                          ConntrackTcpState::Established) ||
                                     (current->protocol ==
                                          ConntrackFlowProtocol::Udp &&
                                      current->assured));
                                const bool preventive_tuple_still_frozen =
                                    pending.decision.reason !=
                                        IdleStallDecisionReason::
                                            idle_packaged_whatsapp_tcp_reset_rotation ||
                                    (current !=
                                         current_observation.flows.end() &&
                                     current->family ==
                                         ConntrackFlowFamily::Ipv4 &&
                                     current->protocol ==
                                         ConntrackFlowProtocol::Tcp &&
                                     current->destination_port == 443U &&
                                     current->mark != 0U &&
                                     current->original.packets ==
                                         pending.flow.original.packets &&
                                     current->original.bytes ==
                                         pending.flow.original.bytes &&
                                     current->reply.packets ==
                                         pending.flow.reply.packets &&
                                     current->reply.bytes ==
                                         pending.flow.reply.bytes);
                                if (!current_state_eligible ||
                                    !preventive_tuple_still_frozen ||
                                    current->original.packets <
                                        pending.flow.original.packets ||
                                    current->original.bytes <
                                        pending.flow.original.bytes ||
                                    current->reply.packets <
                                        pending.flow.reply.packets ||
                                    current->reply.bytes <
                                        pending.flow.reply.bytes ||
                                    current->reply.bytes -
                                            pending.flow.reply.bytes >
                                        IDLE_STALL_APPLICATION_REPLY_BYTES) {
                                    ++recovered_or_replaced;
                                    continue;
                                }
                                // Delete the freshly revalidated object, not
                                // the older scan copy. This preserves its
                                // current TCP state and exact full mark.
                                pending.flow = *current;
                                still_stalled.push_back(std::move(pending));
                            }
                            pending_deletes = std::move(still_stalled);
                        }
                    }
                }
            } catch (...) {
                live_scope_changed = true;
            }

            const bool completion_posted = post_control_task(
                [this,
                 expected_runtime_generation,
                 expected_coverage_generation,
                 owned_mask,
                 pending_deletes = std::move(pending_deletes),
                 all_decisions = std::move(all_decisions),
                 media_protected,
                 recovered_or_replaced,
                 live_scope_changed]() mutable {
                    idle_stall_supervisor_.finish_inflight();
                    const auto generation_is_current = [this,
                                                        expected_runtime_generation,
                                                        expected_coverage_generation]() {
                        return running_.load(std::memory_order_acquire) &&
                               routing_runtime_active() &&
                               runtime_generation_.load(
                                   std::memory_order_acquire) ==
                                   expected_runtime_generation &&
                               idle_stall_supervisor_.current_coverage(
                                   expected_coverage_generation);
                    };
                    if (!generation_is_current()) {
                        return;
                    }

                    std::size_t succeeded = 0U;
                    std::size_t preventive_resets = 0U;
                    std::size_t failed = 0U;
                    bool command_unavailable = false;
                    std::set<std::uint64_t> acknowledged_attempts;
                    const auto acknowledge =
                        [this, &acknowledged_attempts](
                            const IdleStallDeleteDecision& decision,
                            bool delete_succeeded) {
                            idle_stall_supervisor_.idle_detector().
                                acknowledge_delete_result(
                                decision,
                                delete_succeeded,
                                IdleStallDetector::Clock::now());
                            acknowledged_attempts.insert(decision.attempt_id);
                        };
                    if (!live_scope_changed) {
                        const auto reset_point = std::find_if(
                            pending_deletes.begin(),
                            pending_deletes.end(),
                            [](const auto& pending) {
                                return pending.decision.reason ==
                                    IdleStallDecisionReason::
                                        idle_packaged_whatsapp_tcp_reset_rotation;
                            });
                        if (reset_point != pending_deletes.end() &&
                            begin_idle_stall_exact_tcp_reset_point(
                                expected_runtime_generation,
                                expected_coverage_generation,
                                owned_mask,
                                reset_point->decision,
                                reset_point->flow)) {
                            // One exact point mutation owns the physical
                            // writer until its terminal. Release every other
                            // detector reservation now; the continuation
                            // acknowledges this exact target and schedules the
                            // next observation only after the lease returns.
                            for (const auto& decision : all_decisions) {
                                if (decision.attempt_id !=
                                    reset_point->decision.attempt_id) {
                                    acknowledge(decision, false);
                                }
                            }
                            return;
                        }

                        // Never fall back to a direct firewall writer. A
                        // rejected/extra reset candidate is released and will
                        // be reconsidered from a fresh observation.
                        pending_deletes.erase(
                            std::remove_if(
                                pending_deletes.begin(),
                                pending_deletes.end(),
                                [&acknowledge, &failed](const auto& pending) {
                                    if (pending.decision.reason !=
                                        IdleStallDecisionReason::
                                            idle_packaged_whatsapp_tcp_reset_rotation) {
                                        return false;
                                    }
                                    ++failed;
                                    acknowledge(pending.decision, false);
                                    return true;
                                }),
                            pending_deletes.end());

                        std::vector<
                            RuntimeIdleStallExactCleanupPointMutationWork>
                            point_work;
                        point_work.reserve(pending_deletes.size());
                        for (const auto& pending : pending_deletes) {
                            point_work.push_back({
                                pending.decision, pending.flow});
                        }
                        if (!point_work.empty() &&
                            begin_idle_stall_exact_cleanup_point(
                                expected_runtime_generation,
                                expected_coverage_generation,
                                owned_mask,
                                std::move(point_work),
                                all_decisions,
                                media_protected,
                                recovered_or_replaced)) {
                            return;
                        }
                    }

                    // Media protection, a recovered/replaced tuple, command
                    // failure, or a changed scope must release the detector's
                    // reservation without consuming cooldown/rate tokens.
                    for (const auto& decision : all_decisions) {
                        if (acknowledged_attempts.count(
                                decision.attempt_id) == 0U) {
                            acknowledge(decision, false);
                        }
                    }

                    if (!running_.load(std::memory_order_acquire) ||
                        !routing_runtime_active() ||
                        runtime_generation_.load(
                            std::memory_order_acquire) !=
                            expected_runtime_generation ||
                        !idle_stall_supervisor_.current_coverage(
                            expected_coverage_generation)) {
                        return;
                    }
                    if (succeeded != 0U) {
                        if (preventive_resets != 0U) {
                            Logger::instance().info(
                                "Rotated {} frozen WhatsApp TCP "
                                "tuple(s) with exact short-lived reset; {} "
                                "total idle flow(s) recovered",
                                preventive_resets,
                                succeeded);
                        } else {
                            Logger::instance().info(
                                "Recovered {} exact idle forwarded flow(s) "
                                "after their reply path stopped progressing",
                                succeeded);
                        }
                    } else if (command_unavailable) {
                        Logger::instance().info(
                            "Idle forwarded-flow recovery is unavailable "
                            "because the conntrack utility could not be run");
                    } else if (failed != 0U) {
                        Logger::instance().info(
                            "Idle forwarded-flow recovery left {} exact "
                            "flow deletion(s) incomplete; no broad cleanup "
                            "was attempted",
                            failed);
                    } else if (media_protected != 0U) {
                        Logger::instance().trace(
                            "idle_stall_delete_skip",
                            "generation={} reason=active_udp_media "
                            "protected={}",
                            expected_runtime_generation,
                            media_protected);
                    } else if (recovered_or_replaced != 0U) {
                        Logger::instance().trace(
                            "idle_stall_delete_skip",
                            "generation={} reason=flow_recovered_or_replaced "
                            "count={}",
                            expected_runtime_generation,
                            recovered_or_replaced);
                    } else if (live_scope_changed) {
                        Logger::instance().trace(
                            "idle_stall_delete_skip",
                            "generation={} reason=live_scope_changed",
                            expected_runtime_generation);
                    }
                    const auto fast_followup =
                        idle_stall_supervisor_.idle_detector().
                            take_whatsapp_fast_followup_delay();
                    const auto next_interval = fast_followup.value_or(
                        IDLE_STALL_ACTIVE_SCAN_INTERVAL);
                    schedule_idle_stall_observer_after(next_interval);
                },
                "idle-stall-delete-commit");
            if (completion_posted) {
                inflight_guard.release();
            }
        },
        trace_id);

    if (!enqueued) {
        release_pending_decisions();
        idle_stall_supervisor_.finish_inflight();
        const auto fast_followup =
            idle_stall_supervisor_.idle_detector().
                take_whatsapp_fast_followup_delay();
        const auto next_interval =
            fast_followup.value_or(IDLE_STALL_ACTIVE_SCAN_INTERVAL);
        schedule_idle_stall_observer_after(next_interval);
    }
}

void Daemon::execute_committed_stale_flow_reconnect(
    std::uint64_t committed_runtime_generation,
    bool previous_runtime_active,
    bool exact_forwarded_scope,
    std::uint32_t owned_mask,
    const ConntrackDestinationRetirementCoverage& normal_coverage,
    const ConntrackDestinationRetirementCoverage& aggressive_coverage)
    noexcept {
    try {
        if (!previous_runtime_active) {
            return;
        }

        if (normal_coverage.partial() || aggressive_coverage.partial()) {
            Logger::instance().info(
                "Targeted routing-policy conntrack retirement has partial "
                "coverage: normal={}/{} and stronger={}/{} domain-backed/"
                "statically-truncated changed list(s); only observed flows "
                "for tracked static destinations are eligible for immediate "
                "reconnection",
                normal_coverage.domain_backed_list_names.size(),
                normal_coverage.truncated_static_list_names.size(),
                aggressive_coverage.domain_backed_list_names.size(),
                aggressive_coverage.truncated_static_list_names.size());
        }

        StaleFlowReconnectRequest request;
        request.expected_runtime_generation = committed_runtime_generation;
        request.normal = normal_coverage;
        request.aggressive = aggressive_coverage;
        request.exact_forwarded_scope = exact_forwarded_scope;

        std::optional<ConntrackForwardedFlowCleanupSummary> cleanup_summary;
        std::string failure_detail;
        const auto execution = run_stale_flow_reconnect_if_committed(
            RuntimeReconnectCommitState::committed,
            request,
            [this]() noexcept {
                return routing_runtime_active();
            },
            [this]() noexcept {
                return runtime_generation_.load(std::memory_order_acquire);
            },
            [this, &failure_detail]() {
                try {
                    std::vector<std::string> local_interface_addresses;
                    for (const auto& interface : netlink_.dump_interfaces()) {
                        local_interface_addresses.insert(
                            local_interface_addresses.end(),
                            interface.ipv4_addresses.begin(),
                            interface.ipv4_addresses.end());
                        local_interface_addresses.insert(
                            local_interface_addresses.end(),
                            interface.ipv6_addresses.begin(),
                            interface.ipv6_addresses.end());
                    }
                    return local_interface_addresses;
                } catch (const std::exception& error) {
                    failure_detail = error.what();
                    throw;
                } catch (...) {
                    failure_detail = "unknown live-scope preparation error";
                    throw;
                }
            },
            [this, owned_mask, &cleanup_summary, &failure_detail](
                const std::vector<std::string>& local_interface_addresses,
                const StaleFlowReconnectRequest& reconnect_request) {
                try {
                    cleanup_summary =
                        conntrack_manager_.delete_forwarded_destination_flows(
                            reconnect_request.normal.destination_selectors,
                            reconnect_request.aggressive.
                                destination_selectors,
                            local_interface_addresses,
                            owned_mask,
                            ConntrackForwardedFlowCleanupOptions{
                                resolve_ipv6_support(active_config_snapshot_->config).enabled,
                                std::chrono::seconds{2},
                                /*max_flows=*/256U,
                                /*max_destination_input_cidrs=*/1024U,
                                /*max_snapshot_bytes=*/2U * 1024U * 1024U,
                                /*max_snapshot_lines=*/8192U});
                } catch (const std::exception& error) {
                    failure_detail = error.what();
                    throw;
                } catch (...) {
                    failure_detail = "unknown targeted conntrack cleanup error";
                    throw;
                }
            });

        switch (execution) {
        case StaleFlowReconnectExecution::completed: {
            if (!cleanup_summary.has_value()) {
                Logger::instance().info(
                    "Targeted routing-policy conntrack retirement failed "
                    "closed because no cleanup result was produced; existing "
                    "flows will converge as they expire");
                return;
            }
            const auto& cleanup = *cleanup_summary;
            if (cleanup.command_unavailable) {
                warn_conntrack_unavailable_once();
            } else if (cleanup.snapshot_unavailable ||
                       cleanup.local_address_scope_missing ||
                       cleanup.invalid_owned_mask) {
                Logger::instance().info(
                    "Targeted routing-policy conntrack retirement failed "
                    "closed because its live forwarded-flow scope was not "
                    "authoritative; existing flows will converge as they "
                    "expire");
            } else if (cleanup.failed != 0U || cleanup.skipped != 0U ||
                       cleanup.budget_exhausted ||
                       cleanup.snapshot_truncated ||
                       cleanup.destination_input_truncated) {
                Logger::instance().info(
                    "Targeted routing-policy conntrack retirement matched "
                    "{} exact forwarded flow(s), attempted {}, left {} "
                    "failed and {} skipped; remaining flows will converge "
                    "as they expire",
                    cleanup.matched,
                    cleanup.attempted,
                    cleanup.failed,
                    cleanup.skipped);
            } else if (cleanup.attempted != 0U) {
                Logger::instance().info(
                    "Targeted routing-policy conntrack retirement "
                    "reconnected {} exact forwarded flow(s) after a "
                    "committed policy change",
                    cleanup.attempted);
            }
            return;
        }
        case StaleFlowReconnectExecution::skipped_inexact_forwarded_scope:
            Logger::instance().info(
                "Targeted routing-policy conntrack retirement was skipped "
                "because the active inbound/native-VPN policy cannot be "
                "represented by an exact forwarded-flow selector; existing "
                "flows will converge as they expire");
            return;
        case StaleFlowReconnectExecution::skipped_inactive_runtime:
        case StaleFlowReconnectExecution::skipped_stale_generation:
        case StaleFlowReconnectExecution::skipped_generation_changed:
            Logger::instance().info(
                "Targeted routing-policy conntrack retirement was skipped "
                "because the committed runtime generation is no longer "
                "current; existing flows will converge as they expire");
            return;
        case StaleFlowReconnectExecution::skipped_invalid_generation:
        case StaleFlowReconnectExecution::skipped_global_destination_scope:
            Logger::instance().info(
                "Targeted routing-policy conntrack retirement failed closed "
                "because its destination scope was not safely bounded; "
                "existing flows will converge as they expire");
            return;
        case StaleFlowReconnectExecution::failed:
            if (!failure_detail.empty()) {
                Logger::instance().info(
                    "Targeted routing-policy conntrack retirement was "
                    "skipped: {}. Existing flows will converge as they expire",
                    failure_detail);
            } else {
                Logger::instance().info(
                    "Targeted routing-policy conntrack retirement was "
                    "skipped by an unknown error; existing flows will "
                    "converge as they expire");
            }
            return;
        case StaleFlowReconnectExecution::skipped_not_committed:
        case StaleFlowReconnectExecution::skipped_empty_plan:
            return;
        }
    } catch (const std::exception& error) {
        try {
            Logger::instance().info(
                "Targeted routing-policy conntrack retirement was skipped: "
                "{}. Existing flows will converge as they expire",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().info(
                "Targeted routing-policy conntrack retirement was skipped by "
                "an unknown error; existing flows will converge as they expire");
        } catch (...) {
        }
    }
}



} // namespace keen_pbr3
