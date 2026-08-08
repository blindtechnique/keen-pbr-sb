#include "daemon.hpp"

#include <algorithm>
#include <array>
#include <future>
#include <iterator>
#include <map>
#include <set>
#include <thread>

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
#ifdef WITH_API
#include "../api/handler_catalog.hpp"
#include "../api/handler_remote_access.hpp"
#include "../api/status_stream.hpp"
#endif
#include "../util/ipv6_support.hpp"
#include "../util/time_utils.hpp"
#include "../util/cron.hpp"
#include "scheduler.hpp"
#include "owned_conntrack_cleanup_operation.hpp"
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
constexpr std::array<std::chrono::seconds, 5>
    OWNED_CONNTRACK_CLEANUP_RETRY_DELAYS{
        std::chrono::seconds{2},
        std::chrono::seconds{4},
        std::chrono::seconds{8},
        std::chrono::seconds{16},
        std::chrono::seconds{30},
    };
constexpr std::size_t OWNED_CONNTRACK_CLEANUP_RETRY_BATCH_SIZE = 4U;
constexpr auto OWNED_CONNTRACK_CLEANUP_RETRY_BUDGET =
    std::chrono::milliseconds{750};
constexpr auto OWNED_CONNTRACK_CLEANUP_COMPLETION_WATCHDOG =
    std::chrono::seconds{2};
constexpr auto IDLE_STALL_ACTIVE_SCAN_INTERVAL =
    std::chrono::seconds{5};
constexpr auto IDLE_STALL_QUIET_SCAN_INTERVAL =
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

struct UdpCallAffinityMutationWork {
    UdpCallAffinityDecision decision;
    std::string set_name;
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

struct UdpCallAffinityMutationOutcome {
    UdpCallAffinityDecision decision;
    std::vector<ConntrackExactForwardedFlow> revalidated_flows;
    bool publication_attempted{false};
    bool installed{false};
    bool revalidation_failed{false};
    bool deadline_expired{false};
    std::size_t retired_flows{0U};
    std::size_t failed_flows{0U};
};

class AtomicFlagResetGuard {
public:
    explicit AtomicFlagResetGuard(std::atomic<bool>& flag) noexcept
        : flag_(flag) {}

    ~AtomicFlagResetGuard() {
        if (armed_) {
            flag_.store(false, std::memory_order_release);
        }
    }

    AtomicFlagResetGuard(const AtomicFlagResetGuard&) = delete;
    AtomicFlagResetGuard& operator=(const AtomicFlagResetGuard&) = delete;

    void release() noexcept {
        armed_ = false;
    }

private:
    std::atomic<bool>& flag_;
    bool armed_{true};
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

class ResolverStreamAttemptLifetime {
public:
    ResolverStreamAttemptLifetime(
        std::atomic<bool>& ipc_gate,
        std::shared_ptr<RuntimeMutationAdmission::Lease> mutation_lease,
        std::shared_ptr<const ResolverGenerationSnapshot> generation,
        std::function<void()> clear_active)
        : ipc_gate_(ipc_gate),
          mutation_lease_(std::move(mutation_lease)),
          generation_(std::move(generation)),
          clear_active_(std::move(clear_active)) {}

    ~ResolverStreamAttemptLifetime() noexcept {
        try {
            if (clear_active_) {
                clear_active_();
            }
        } catch (...) {
        }
    }

    ResolverStreamAttemptLifetime(
        const ResolverStreamAttemptLifetime&) = delete;
    ResolverStreamAttemptLifetime& operator=(
        const ResolverStreamAttemptLifetime&) = delete;

private:
    ResolverIpcGate ipc_gate_;
    std::shared_ptr<RuntimeMutationAdmission::Lease> mutation_lease_;
    std::shared_ptr<const ResolverGenerationSnapshot> generation_;
    std::function<void()> clear_active_;
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

bool same_internal_vpn_runtime_targets(
    const std::vector<InternalVpnRuntimeTarget>& lhs,
    const std::vector<InternalVpnRuntimeTarget>& rhs) {
    return lhs.size() == rhs.size() &&
           std::equal(
               lhs.begin(),
               lhs.end(),
               rhs.begin(),
               [](const auto& left, const auto& right) {
                   return left.stable_id == right.stable_id &&
                          left.match_kind == right.match_kind &&
                          left.process_clients == right.process_clients &&
                          left.bound_interface_id ==
                              right.bound_interface_id &&
                          left.interface == right.interface &&
                          left.verified_ingress_interfaces ==
                              right.verified_ingress_interfaces &&
                          left.verified_bridge_ingress_interfaces ==
                              right.verified_bridge_ingress_interfaces &&
                          left.dns_redirect_bypass_ingress_v4 ==
                              right.dns_redirect_bypass_ingress_v4 &&
                          left.dns_redirect_bypass_ingress_v6 ==
                              right.dns_redirect_bypass_ingress_v6 &&
                          left.source_cidrs_v4 == right.source_cidrs_v4 &&
                          left.source_cidrs_v6 == right.source_cidrs_v6;
               });
}

} // namespace

bool Daemon::run_system_resolver_hook(std::string_view action,
                                      bool manage_ipc_gate,
                                      std::string_view attempt_id) {
    auto& log = Logger::instance();

    const auto args =
        build_system_resolver_hook_args(config_, action, attempt_id);
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

    return run_system_resolver_hook_stream_prepared(
        action, /*rebuild_snapshot=*/true);
}

bool Daemon::run_system_resolver_hook_stream_prepared(
    std::string_view action,
    bool rebuild_snapshot) {
    if (build_system_resolver_hook_args(config_, action).empty()) {
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
    generation->stream_epoch =
        resolver_stream_epoch_.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::uint64_t expected_epoch = generation->stream_epoch;
    const std::string attempt_id = generate_resolver_attempt_id();
    auto lifetime = std::make_shared<ResolverStreamAttemptLifetime>(
        ipc_resolver_hook_inflight_,
        nullptr,
        generation,
        [this, attempt_id]() noexcept {
            KPBR_LOCK_GUARD(resolver_stream_attempt_mutex_);
            if (active_resolver_stream_attempt_id_ == attempt_id) {
                active_resolver_stream_attempt_id_.clear();
                active_resolver_stream_generation_.reset();
            }
        });
    resolver_generation_snapshot_ = generation;
    {
        KPBR_LOCK_GUARD(resolver_stream_attempt_mutex_);
        active_resolver_stream_attempt_id_ = attempt_id;
        active_resolver_stream_generation_ = generation;
    }
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

OwnedConntrackCleanupSnapshot
Daemon::snapshot_owned_conntrack_marks() const {
    OwnedConntrackCleanupSnapshot snapshot;
    snapshot.runtime_generation =
        runtime_generation_.load(std::memory_order_acquire);
    snapshot.owned_mask =
        fwmark_mask_value(config_.fwmark.value_or(FwmarkConfig{}));
    snapshot.ipv6_enabled = resolve_ipv6_support(config_).enabled;

    const auto add_mark = [&](uint32_t mark, bool priority) {
        if ((mark & snapshot.owned_mask) != 0U) {
            snapshot.marks.insert(mark);
            if (priority) {
                snapshot.priority_marks.insert(mark);
            }
        }
    };
    const auto add_tag = [&](const std::string& tag, bool priority) {
        const auto mark = outbound_marks_.find(tag);
        if (mark != outbound_marks_.end()) {
            add_mark(mark->second, priority);
        }
    };

    // First retire marks that actively carried forwarded or resolver traffic.
    for (const auto& rule : firewall_state_.get_rules()) {
        if (rule.action_type == RuleActionType::Mark) {
            add_mark(rule.fwmark, /*priority=*/true);
        }
    }
    const auto& selections = firewall_state_.get_urltest_selections();
    const auto& outbounds =
        config_.outbounds.value_or(std::vector<Outbound>{});
    if (config_.dns.has_value()) {
        for (const auto& server :
             config_.dns->servers.value_or(std::vector<DnsServer>{})) {
            if (!server.detour.has_value()) {
                continue;
            }
            std::string effective_tag = *server.detour;
            const auto outbound = std::find_if(
                outbounds.begin(),
                outbounds.end(),
                [&effective_tag](const Outbound& candidate) {
                    return candidate.tag == effective_tag;
                });
            if (outbound != outbounds.end() &&
                outbound->type == OutboundType::URLTEST) {
                const auto selected = selections.find(effective_tag);
                if (selected != selections.end() &&
                    !selected->second.empty()) {
                    effective_tag = selected->second;
                }
            }
            add_tag(effective_tag, /*priority=*/true);
        }
    }

    // Interface marks are used by health probes even when no route rule
    // currently references them. Remote-list detours use SO_MARK directly,
    // including the literal urltest mark when a list points at a selector.
    for (const auto& outbound : outbounds) {
        if (outbound.type == OutboundType::INTERFACE) {
            add_tag(outbound.tag, /*priority=*/false);
        }
    }
    if (config_.lists.has_value()) {
        for (const auto& [name, list] : *config_.lists) {
            (void)name;
            if (!list.url.has_value()) {
                continue;
            }
            for (const auto& detour :
                 effective_list_refresh_detours(config_, list)) {
                add_tag(detour, /*priority=*/false);
            }
        }
    }
    for (const auto& [urltest, selected] : selections) {
        (void)urltest;
        add_tag(selected, /*priority=*/false);
    }
    return snapshot;
}

void Daemon::cleanup_owned_conntrack_marks(const char* context) {
    const auto snapshot = snapshot_owned_conntrack_marks();
    if (!snapshot.valid()) {
        return;
    }
    (void)cleanup_owned_conntrack_snapshot(snapshot, context);
}

void Daemon::reconcile_native_vpn_direct_egress_conntrack(
    const std::vector<FirewallSourceEgressSnatSelector>& selectors) {
    if (selectors == applied_native_vpn_direct_egress_snat_selectors_) {
        return;
    }

    const auto affected_sources =
        changed_native_vpn_direct_egress_source_cidrs(
            applied_native_vpn_direct_egress_snat_selectors_,
            selectors);
    applied_native_vpn_direct_egress_snat_selectors_ = selectors;
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

ConntrackCleanupSummary Daemon::cleanup_owned_conntrack_snapshot(
    const OwnedConntrackCleanupSnapshot& snapshot,
    const char* context,
    bool allow_retry) {
    ConntrackCleanupSummary cleanup;
    if (!snapshot.valid()) {
        return cleanup;
    }
    std::vector<uint32_t> ordered_marks;
    ordered_marks.reserve(snapshot.marks.size());
    ordered_marks.insert(
        ordered_marks.end(),
        snapshot.priority_marks.begin(),
        snapshot.priority_marks.end());
    for (const auto mark : snapshot.marks) {
        if (snapshot.priority_marks.count(mark) == 0U) {
            ordered_marks.push_back(mark);
        }
    }
    try {
        cleanup =
            conntrack_manager_.delete_marks_ordered(
                ordered_marks,
                snapshot.owned_mask,
                ConntrackCleanupOptions{
                    snapshot.ipv6_enabled,
                    std::chrono::seconds{4}});
        if (cleanup.command_unavailable) {
            warn_conntrack_unavailable_once();
        }
        if (cleanup.failed == 0U &&
            cleanup.skipped == 0U) {
            return cleanup;
        }
        Logger::instance().info(
            "Best-effort conntrack cleanup left {} failed and {} skipped "
            "owned mark(s) {}; "
            "existing flows may keep their previous path until they expire",
            cleanup.failed,
            cleanup.skipped,
            context);
    } catch (const std::exception& error) {
        cleanup.failed = ordered_marks.size();
        cleanup.remaining_marks = ordered_marks;
        Logger::instance().info(
            "Best-effort conntrack cleanup {} raised an error: {}; existing "
            "flows may keep their previous path until they expire",
            context,
            error.what());
    }
    if (allow_retry &&
        !cleanup.command_unavailable &&
        !cleanup.remaining_marks.empty()) {
        schedule_owned_conntrack_cleanup_retry(
            snapshot,
            cleanup.remaining_marks);
    }
    return cleanup;
}

void Daemon::schedule_owned_conntrack_cleanup_retry(
    const OwnedConntrackCleanupSnapshot& source_snapshot,
    std::vector<std::uint32_t> remaining_marks,
    std::size_t no_progress_attempt) {
    if (!source_snapshot.valid() || remaining_marks.empty()) {
        return;
    }

    std::vector<std::uint32_t> filtered_marks;
    std::set<std::uint32_t> seen;
    filtered_marks.reserve(remaining_marks.size());
    for (const auto mark : remaining_marks) {
        if ((mark & source_snapshot.owned_mask) != 0U &&
            seen.insert(mark).second) {
            filtered_marks.push_back(mark);
        }
    }
    if (filtered_marks.empty()) {
        return;
    }

    OwnedConntrackCleanupSnapshot filtered_snapshot = source_snapshot;
    filtered_snapshot.marks = std::set<std::uint32_t>{
        filtered_marks.begin(), filtered_marks.end()};
    for (auto it = filtered_snapshot.priority_marks.begin();
         it != filtered_snapshot.priority_marks.end();) {
        if (filtered_snapshot.marks.count(*it) == 0U) {
            it = filtered_snapshot.priority_marks.erase(it);
        } else {
            ++it;
        }
    }
    OwnedConntrackCleanupRetry candidate{
        std::move(filtered_snapshot),
        std::move(filtered_marks),
        no_progress_attempt};

    if (pending_owned_conntrack_cleanup_retry_.has_value()) {
        auto& pending = *pending_owned_conntrack_cleanup_retry_;
        if (pending.snapshot.runtime_generation ==
                candidate.snapshot.runtime_generation &&
            pending.snapshot.owned_mask == candidate.snapshot.owned_mask) {
            std::set<std::uint32_t> pending_marks{
                pending.ordered_marks.begin(),
                pending.ordered_marks.end()};
            for (const auto mark : candidate.ordered_marks) {
                if (pending_marks.insert(mark).second) {
                    pending.ordered_marks.push_back(mark);
                    pending.snapshot.marks.insert(mark);
                    if (candidate.snapshot.priority_marks.count(mark) != 0U) {
                        pending.snapshot.priority_marks.insert(mark);
                    }
                }
            }
            pending.snapshot.ipv6_enabled =
                pending.snapshot.ipv6_enabled ||
                candidate.snapshot.ipv6_enabled;
            pending.no_progress_attempt =
                std::min(
                    pending.no_progress_attempt,
                    candidate.no_progress_attempt);
        } else {
            cancel_owned_conntrack_cleanup_retry();
            pending_owned_conntrack_cleanup_retry_ = std::move(candidate);
        }
    } else {
        pending_owned_conntrack_cleanup_retry_ = std::move(candidate);
    }

    arm_owned_conntrack_cleanup_retry_timer();
}

void Daemon::arm_owned_conntrack_cleanup_retry_timer() {
    if (owned_conntrack_cleanup_retry_task_id_ >= 0 ||
        active_owned_conntrack_cleanup_operation_ ||
        !pending_owned_conntrack_cleanup_retry_.has_value()) {
        return;
    }
    const auto attempt =
        pending_owned_conntrack_cleanup_retry_->no_progress_attempt;
    if (attempt >= OWNED_CONNTRACK_CLEANUP_RETRY_DELAYS.size()) {
        Logger::instance().info(
            "Best-effort conntrack cleanup exhausted its targeted retry "
            "budget; remaining owned flows will expire naturally.");
        pending_owned_conntrack_cleanup_retry_.reset();
        return;
    }
    owned_conntrack_cleanup_retry_task_id_ = scheduler_->schedule_oneshot(
        OWNED_CONNTRACK_CLEANUP_RETRY_DELAYS[attempt],
        [this]() {
            owned_conntrack_cleanup_retry_task_id_ = -1;
            run_owned_conntrack_cleanup_retry();
        },
        "owned-conntrack-cleanup-retry");
}

void Daemon::arm_owned_conntrack_cleanup_completion_watchdog(
    const std::shared_ptr<OwnedConntrackCleanupOperation>& operation) {
    if (!operation ||
        operation != active_owned_conntrack_cleanup_operation_ ||
        owned_conntrack_cleanup_retry_task_id_ >= 0) {
        return;
    }
    owned_conntrack_cleanup_retry_task_id_ = scheduler_->schedule_oneshot(
        OWNED_CONNTRACK_CLEANUP_COMPLETION_WATCHDOG,
        [this, operation]() {
            owned_conntrack_cleanup_retry_task_id_ = -1;
            complete_owned_conntrack_cleanup_operation(operation);
        },
        "owned-conntrack-cleanup-completion-watchdog");
}

void Daemon::run_owned_conntrack_cleanup_retry() {
    if (active_owned_conntrack_cleanup_operation_) {
        arm_owned_conntrack_cleanup_completion_watchdog(
            active_owned_conntrack_cleanup_operation_);
        return;
    }
    if (!pending_owned_conntrack_cleanup_retry_.has_value()) {
        return;
    }
    auto retry = std::move(*pending_owned_conntrack_cleanup_retry_);
    pending_owned_conntrack_cleanup_retry_.reset();
    if (!owned_conntrack_cleanup_retry_is_current(
            routing_runtime_active_,
            retry,
            runtime_generation_.load(std::memory_order_acquire))) {
        return;
    }

    auto operation =
        std::make_shared<OwnedConntrackCleanupOperation>(std::move(retry));
    active_owned_conntrack_cleanup_operation_ = operation;
    try {
        arm_owned_conntrack_cleanup_completion_watchdog(operation);
    } catch (...) {
        operation->cancel();
        active_owned_conntrack_cleanup_operation_.reset();
        pending_owned_conntrack_cleanup_retry_ = operation->retry();
        throw;
    }

    const auto trace_id = ensure_trace_id();
    bool enqueued = false;
    try {
        enqueued = blocking_executor_.try_post(
            "owned-conntrack-cleanup-retry",
            [this, operation]() {
                const auto post_completion = [this, operation]() noexcept {
                    bool posted = false;
                    try {
                        posted = post_control_task(
                            [this, operation]() {
                                complete_owned_conntrack_cleanup_operation(
                                    operation);
                            },
                            "owned-conntrack-cleanup-retry-complete");
                    } catch (const std::exception& error) {
                        try {
                            Logger::instance().info(
                                "Best-effort conntrack cleanup completion "
                                "handoff failed: {}",
                                error.what());
                        } catch (...) {
                        }
                    } catch (...) {
                        try {
                            Logger::instance().info(
                                "Best-effort conntrack cleanup completion "
                                "handoff failed: unknown error");
                        } catch (...) {
                        }
                    }
                    if (!posted &&
                        !accept_posted_control_tasks_.load(
                            std::memory_order_acquire)) {
                        operation->release_mutation_lease();
                    }
                };

                if (operation->cancelled()) {
                    return;
                }

                std::optional<RuntimeMutationAdmission::Lease> admitted;
                try {
                    // Foreground API/SIGHUP work wins while this retry is
                    // merely waiting behind unrelated blocking jobs. The
                    // lease begins only when the worker is ready to touch
                    // conntrack.
                    admitted = runtime_mutation_admission_.try_acquire(
                        "owned-conntrack-cleanup-retry");
                } catch (...) {
                    if (operation->finish(
                            OwnedConntrackCleanupOperationStatus::busy)) {
                        post_completion();
                    }
                    return;
                }
                if (!admitted.has_value()) {
                    if (operation->finish(
                            OwnedConntrackCleanupOperationStatus::busy)) {
                        post_completion();
                    }
                    return;
                }

                auto mutation_lease =
                    std::make_shared<RuntimeMutationAdmission::Lease>(
                        std::move(*admitted));
                if (operation->cancelled()) {
                    mutation_lease->release();
                    return;
                }

                const auto& worker_retry = operation->retry();
                if (worker_retry.snapshot.runtime_generation !=
                    runtime_generation_.load(std::memory_order_acquire)) {
                    if (!operation->finish(
                            OwnedConntrackCleanupOperationStatus::stale,
                            {},
                            mutation_lease)) {
                        mutation_lease->release();
                        return;
                    }
                    post_completion();
                    return;
                }

                ConntrackCleanupSummary cleanup;
                try {
                    cleanup = conntrack_manager_.delete_marks_ordered(
                        worker_retry.ordered_marks,
                        worker_retry.snapshot.owned_mask,
                        ConntrackCleanupOptions{
                            worker_retry.snapshot.ipv6_enabled,
                            OWNED_CONNTRACK_CLEANUP_RETRY_BUDGET,
                            OWNED_CONNTRACK_CLEANUP_RETRY_BATCH_SIZE});
                } catch (...) {
                    cleanup.failed = worker_retry.ordered_marks.size();
                    cleanup.remaining_marks = worker_retry.ordered_marks;
                }
                if (!operation->finish(
                        OwnedConntrackCleanupOperationStatus::completed,
                        std::move(cleanup),
                        mutation_lease)) {
                    mutation_lease->release();
                    return;
                }
                post_completion();
            },
            trace_id);
    } catch (const std::exception& error) {
        Logger::instance().info(
            "Best-effort conntrack cleanup dispatch failed: {}",
            error.what());
    } catch (...) {
        Logger::instance().info(
            "Best-effort conntrack cleanup dispatch failed: unknown error");
    }
    if (enqueued) {
        return;
    }

    if (owned_conntrack_cleanup_retry_task_id_ >= 0) {
        scheduler_->cancel(owned_conntrack_cleanup_retry_task_id_);
        owned_conntrack_cleanup_retry_task_id_ = -1;
    }
    operation->cancel();
    if (active_owned_conntrack_cleanup_operation_ == operation) {
        active_owned_conntrack_cleanup_operation_.reset();
    }
    const auto rejected_retry = operation->retry();
    schedule_owned_conntrack_cleanup_retry(
        rejected_retry.snapshot,
        rejected_retry.ordered_marks,
        rejected_retry.no_progress_attempt);
}

void Daemon::complete_owned_conntrack_cleanup_operation(
    const std::shared_ptr<OwnedConntrackCleanupOperation>& operation) {
    if (!operation ||
        operation != active_owned_conntrack_cleanup_operation_) {
        return;
    }

    auto result = operation->take_result();
    if (!result.has_value()) {
        arm_owned_conntrack_cleanup_completion_watchdog(operation);
        return;
    }

    if (owned_conntrack_cleanup_retry_task_id_ >= 0) {
        scheduler_->cancel(owned_conntrack_cleanup_retry_task_id_);
        owned_conntrack_cleanup_retry_task_id_ = -1;
    }
    const auto retry = operation->retry();
    active_owned_conntrack_cleanup_operation_.reset();
    operation->cancel();

    const bool current = owned_conntrack_cleanup_retry_is_current(
        routing_runtime_active_,
        retry,
        runtime_generation_.load(std::memory_order_acquire));
    // Keep mutation ownership until the control loop has either committed the
    // terminal outcome or safely re-queued the exact remaining selectors.
    // The local shared lease releases automatically on every exit path,
    // including a scheduler exception.
    auto mutation_lease = std::move(result->mutation_lease);

    try {
        if (result->status ==
                OwnedConntrackCleanupOperationStatus::busy) {
            if (current) {
                schedule_owned_conntrack_cleanup_retry(
                    retry.snapshot,
                    retry.ordered_marks,
                    retry.no_progress_attempt);
            }
        } else if (
            result->status ==
                OwnedConntrackCleanupOperationStatus::completed &&
            current) {
            if (result->cleanup.command_unavailable) {
                warn_conntrack_unavailable_once();
            } else if (!result->cleanup.remaining_marks.empty()) {
                const bool made_progress =
                    result->cleanup.remaining_marks.size() <
                    retry.ordered_marks.size();
                const auto next_attempt = made_progress
                    ? 0U
                    : retry.no_progress_attempt + 1U;
                schedule_owned_conntrack_cleanup_retry(
                    retry.snapshot,
                    std::move(result->cleanup.remaining_marks),
                    next_attempt);
            }
        }
    } catch (const std::exception& error) {
        Logger::instance().info(
            "Best-effort conntrack cleanup retry completion failed: {}",
            error.what());
    } catch (...) {
        Logger::instance().info(
            "Best-effort conntrack cleanup retry completion failed: "
            "unknown error");
    }
    arm_owned_conntrack_cleanup_retry_timer();
}

std::optional<OwnedConntrackCleanupRetry>
Daemon::take_active_owned_conntrack_cleanup_retry() {
    if (!active_owned_conntrack_cleanup_operation_) {
        return std::nullopt;
    }
    auto operation = active_owned_conntrack_cleanup_operation_;
    active_owned_conntrack_cleanup_operation_.reset();
    operation->cancel();
    if (owned_conntrack_cleanup_retry_task_id_ >= 0) {
        scheduler_->cancel(owned_conntrack_cleanup_retry_task_id_);
        owned_conntrack_cleanup_retry_task_id_ = -1;
    }
    return operation->retry();
}

void Daemon::cancel_owned_conntrack_cleanup_retry() {
    if (owned_conntrack_cleanup_retry_task_id_ >= 0) {
        scheduler_->cancel(owned_conntrack_cleanup_retry_task_id_);
        owned_conntrack_cleanup_retry_task_id_ = -1;
    }
    pending_owned_conntrack_cleanup_retry_.reset();
    (void)take_active_owned_conntrack_cleanup_retry();
}

void Daemon::complete_pending_snat_recovery_before_generation_change() {
    // An earlier verified repair may have restored the SNAT scaffold while
    // its exact conntrack retirement remained incomplete. That remainder is
    // independent of the coordinator's pending SNAT recovery: it must be
    // drained before
    // numerical marks can be reused by a newer generation.
    std::vector<OwnedConntrackCleanupRetry> cleanup_retries;
    if (auto active_retry =
            take_active_owned_conntrack_cleanup_retry();
        active_retry.has_value()) {
        cleanup_retries.push_back(std::move(*active_retry));
    }
    if (pending_owned_conntrack_cleanup_retry_.has_value()) {
        cleanup_retries.push_back(
            std::move(*pending_owned_conntrack_cleanup_retry_));
        pending_owned_conntrack_cleanup_retry_.reset();
    }
    if (owned_conntrack_cleanup_retry_task_id_ >= 0) {
        scheduler_->cancel(owned_conntrack_cleanup_retry_task_id_);
        owned_conntrack_cleanup_retry_task_id_ = -1;
    }

    bool cleanup_incomplete = false;
    for (const auto& retry : cleanup_retries) {
        if (retry.snapshot.runtime_generation ==
            runtime_generation_.load(std::memory_order_acquire)) {
            const auto cleanup = cleanup_owned_conntrack_snapshot(
                retry.snapshot,
                "before configuration generation change",
                /*allow_retry=*/false);
            if (!cleanup.remaining_marks.empty()) {
                schedule_owned_conntrack_cleanup_retry(
                    retry.snapshot,
                    cleanup.remaining_marks,
                    retry.no_progress_attempt);
                cleanup_incomplete = true;
            }
        }
    }
    if (cleanup_incomplete) {
        throw TransientFirewallError(
            "owned conntrack cleanup is incomplete before configuration "
            "generation change");
    }

    if (!runtime_firewall_retry_.owned_snat_recovery_pending()) {
        return;
    }

    auto recovery = runtime_firewall_retry_.pending_owned_snat_recovery();
    const auto before = firewall_->inspect_owned_snat_state();
    recovery = observe_owned_snat_state(
        std::move(recovery),
        before,
        before == OwnedSnatState::missing
            ? std::optional<OwnedConntrackCleanupSnapshot>{
                  snapshot_owned_conntrack_marks()}
            : std::nullopt);
    if (before == OwnedSnatState::unknown) {
        throw TransientFirewallError(
            "tunnel SNAT state is unavailable before configuration "
            "generation change");
    }
    if (before == OwnedSnatState::missing) {
        const auto list_cache_snapshot =
            resolver_generation_snapshot_ &&
                    resolver_generation_snapshot_->list_cache_snapshot
                ? resolver_generation_snapshot_->list_cache_snapshot
                : capture_relevant_list_cache_generation(config_);
        retry_hot_apply_firewall(
            [this, &list_cache_snapshot]() {
                apply_firewall(
                    FirewallApplyMode::PreserveSets,
                    list_cache_snapshot);
            },
            [](std::chrono::milliseconds delay) {
                std::this_thread::sleep_for(delay);
            },
            [](std::size_t retry,
               std::chrono::milliseconds delay,
               const TransientFirewallError& error) {
                Logger::instance().info(
                    "Pre-apply SNAT repair deferred after a concurrent "
                    "firmware change: {}. Retry {} in {}ms.",
                    error.what(),
                    retry,
                    delay.count());
            });
        if (firewall_->inspect_owned_snat_state() !=
            OwnedSnatState::healthy) {
            throw TransientFirewallError(
                "tunnel SNAT could not be verified before configuration "
                "generation change");
        }
    }

    // This is the only synchronous hot cleanup path. It is a strict barrier
    // before outbound marks can be reassigned to the next configuration.
    if (recovery.missing_observed &&
        recovery.cleanup_snapshot.has_value()) {
        const auto cleanup = cleanup_owned_conntrack_snapshot(
            *recovery.cleanup_snapshot,
            "before configuration generation change",
            /*allow_retry=*/false);
        if (!cleanup.remaining_marks.empty()) {
            // Keep the exact old-generation selectors retryable, but do not
            // let the caller publish a generation which may reuse their
            // numerical marks. The next apply can proceed only after this
            // targeted cleanup has converged; global conntrack is never
            // flushed.
            schedule_owned_conntrack_cleanup_retry(
                *recovery.cleanup_snapshot,
                cleanup.remaining_marks);
            throw TransientFirewallError(
                "owned conntrack cleanup is incomplete before configuration "
                "generation change");
        }
    }
    runtime_firewall_retry_.clear_owned_snat_recovery();
    cancel_runtime_firewall_retry();
}

void Daemon::stop_routing_runtime() {
    auto& log = Logger::instance();
    cancel_idle_stall_observer();
    cancel_owned_snat_health_check();
    cancel_owned_conntrack_cleanup_retry();
    cancel_runtime_firewall_retry();
    runtime_firewall_retry_.clear_owned_snat_recovery();
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

    {
        KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
        if (urltest_manager_) {
            urltest_manager_->clear();
        }
        urltest_apply_incidents_.clear();
        cleanup_owned_conntrack_marks("while stopping routing");
        cancel_owned_conntrack_cleanup_retry();
        policy_rules_.clear();
        route_table_.clear();
        firewall_->cleanup();
    }
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
        schedule_owned_snat_health_check();
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
        return;
    }

    // A stopped runtime already has a prepared cache from cold start or the
    // last staged apply. Starting on the event loop must never perform RCI
    // I/O; fail before kernel mutation if no usable snapshot exists.
    const KeeneticDnsCacheView prepared_keenetic_dns =
        prepare_keenetic_dns_view(
            config_,
            /*allow_refresh=*/false);

    cancel_idle_stall_observer();
    transition_runtime_or_throw(RuntimeState::starting, "runtime start requested");
    publish_runtime_state();

    try {
        cancel_owned_conntrack_cleanup_retry();
        runtime_generation_.fetch_add(1, std::memory_order_acq_rel);

        const auto internal_vpn_resolution =
            prepare_internal_vpn_server_resolution_from_cache();
        const auto internal_vpn_service_resolution =
            prepare_internal_vpn_service_resolution_from_cache();
        InternalVpnRuntimeGenerationTransaction internal_vpn_generation(
            resolved_internal_vpn_servers_,
            internal_vpn_resolution.effective_servers);
        InternalVpnRuntimeTargetGenerationTransaction
            internal_vpn_service_generation(
                resolved_internal_vpn_service_targets_,
                internal_vpn_service_resolution.effective_targets);
        active_keenetic_dns_ = prepared_keenetic_dns;
        normalize_urltest_selections();
        setup_static_routing();
        register_urltest_outbounds();
        // A URLTest switch changes only the selected route. Keep the firewall
        // on the list generation already committed to dnsmasq; a separate
        // list-refresh transaction owns advancing both consumers together.
        const auto list_cache_snapshot =
            resolver_generation_snapshot_ &&
                    resolver_generation_snapshot_->list_cache_snapshot
                ? resolver_generation_snapshot_->list_cache_snapshot
                : capture_relevant_list_cache_generation(config_);
        retry_hot_apply_firewall(
            [this, &list_cache_snapshot]() {
                apply_firewall(
                    FirewallApplyMode::PreserveSets,
                    list_cache_snapshot);
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
        commit_resolver_generation_snapshot(
            make_resolver_generation_snapshot(list_cache_snapshot));
        if (!run_system_resolver_hook_stream_prepared(
                runtime_start_resolver_action(),
                /*rebuild_snapshot=*/false)) {
            throw DaemonError("System resolver activation hook failed");
        }

        internal_vpn_generation.commit();
        internal_vpn_service_generation.commit();
        update_internal_vpn_verified_includes_lkg(
            internal_vpn_resolution);
        update_internal_vpn_service_verified_includes_lkg(
            internal_vpn_service_resolution);
        routing_runtime_active_ = true;
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
        schedule_owned_snat_health_check();
        schedule_internal_vpn_catalog_refresh_if_needed(
            internal_vpn_resolution.state,
            internal_vpn_service_resolution.state);
        // A successful full lifecycle boundary supersedes any earlier
        // reconciliation incident. Without resetting the notification latch,
        // a later independent firewall failure with the same key would remain
        // hidden from the WebUI bell.
        runtime_firewall_incidents_.clear();
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
            KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
            firewall_->cleanup();
        } catch (const std::exception& cleanup_error) {
            log.error("Failed to clean firewall after start failure: {}",
                      cleanup_error.what());
        }
        if (!run_system_resolver_hook("deactivate")) {
            log.warn("System resolver fallback recovery failed");
        }
        routing_runtime_active_ = false;
        cancel_idle_stall_observer();
        cancel_owned_snat_health_check();
        cancel_owned_conntrack_cleanup_retry();
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
    cancel_idle_stall_observer();
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
        if (!runtime_firewall_retry_.owned_snat_recovery_pending()) {
            cancel_runtime_firewall_retry();
        }
        cancel_resolver_reload_retry();
        const auto internal_vpn_resolution =
            prepare_internal_vpn_server_resolution_from_cache();
        const auto internal_vpn_service_resolution =
            prepare_internal_vpn_service_resolution_from_cache();
        InternalVpnRuntimeGenerationTransaction internal_vpn_generation(
            resolved_internal_vpn_servers_,
            internal_vpn_resolution.effective_servers);
        InternalVpnRuntimeTargetGenerationTransaction
            internal_vpn_service_generation(
                resolved_internal_vpn_service_targets_,
                internal_vpn_service_resolution.effective_targets);
        const auto list_cache_snapshot =
            capture_relevant_list_cache_generation(config_);

        apply_runtime_replacement(
            [this]() {
                // Recreate missing routes first and retire obsolete owned
                // entries only after their replacements exist.
                reconcile_static_routing(RouteReconcileMode::Strict);
            },
            [this, &list_cache_snapshot]() {
                // PreserveSets keeps the currently committed firewall
                // generation forwarding until the replacement transaction
                // itself has reached COMMIT.
                apply_firewall(
                    FirewallApplyMode::PreserveSets,
                    list_cache_snapshot);
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
             &internal_vpn_service_generation,
             &internal_vpn_resolution,
             &internal_vpn_service_resolution,
             &list_cache_snapshot,
             &kernel_generation_committed]() {
                // apply_runtime_replacement invokes this callback only after
                // the firewall transaction reached COMMIT. Publish the
                // matching in-memory ingress generation at that boundary,
                // before the secondary resolver reload can fail.
                internal_vpn_generation.commit();
                internal_vpn_service_generation.commit();
                update_internal_vpn_verified_includes_lkg(
                    internal_vpn_resolution);
                update_internal_vpn_service_verified_includes_lkg(
                    internal_vpn_service_resolution);
                kernel_generation_committed = true;
                apply_started_ts_.store(
                    unix_timestamp_now_seconds(),
                    std::memory_order_release);
                commit_resolver_generation_snapshot(
                    make_resolver_generation_snapshot(
                        list_cache_snapshot));
                if (run_system_resolver_hook_stream_prepared(
                        "reload", /*rebuild_snapshot=*/false)) {
                    return;
                }

                // dnsmasq can finish its own firmware-triggered reload just
                // after our stream deadline. Retry the live reload once
                // without deactivating the currently forwarding runtime.
                log.info(
                    "Resolver reload did not converge during runtime restart; "
                    "retrying once without tearing down routing.");
                std::this_thread::sleep_for(std::chrono::milliseconds{250});
                if (!run_system_resolver_hook_stream_prepared(
                        "reload", /*rebuild_snapshot=*/false)) {
                    throw DaemonError(
                        "System resolver reload hook failed during runtime "
                        "restart");
                }
            });

        routing_runtime_active_ = true;
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
        schedule_internal_vpn_catalog_refresh_if_needed(
            internal_vpn_resolution.state,
            internal_vpn_service_resolution.state);
        refresh_resolver_config_hash_actual_async();
        // The replacement firewall generation is committed and the runtime is
        // healthy again. Re-arm the incident latch for a future, independent
        // reconciliation failure.
        runtime_firewall_incidents_.clear();
        transition_runtime_or_throw(
            RuntimeState::running, "transactional runtime restart complete");
        publish_runtime_state();
        if (runtime_firewall_retry_.owned_snat_recovery_pending() &&
            !runtime_firewall_retry_.retry_pending()) {
            (void)refresh_iproute_and_firewall_runtime(
                0,
                std::nullopt,
                std::nullopt,
                /*schedule_catalog_refresh=*/false,
                runtime_firewall_retry_.pending_owned_snat_recovery());
        }
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
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
        if (!kernel_generation_committed &&
            config_has_native_vpn_catalog_policy(config_)) {
            // Keep a bounded retry pending so either a pre-COMMIT failure or a
            // post-COMMIT resolver failure converges without waiting for an
            // unrelated interface event.
            schedule_runtime_firewall_retry(
                0,
                runtime_generation_.load(std::memory_order_acquire),
                OwnedSnatRecovery{});
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

void Daemon::reconcile_static_routing(RouteReconcileMode mode) {
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
    reconcile_kernel_routing_state(
        route_table_,
        policy_rules_,
        desired_routes.get_routes(),
        desired_rules.get_rules(),
        mode);
}

void Daemon::apply_firewall(
    FirewallApplyMode mode,
    std::shared_ptr<const ListCacheGenerationSnapshot>
        list_cache_snapshot) {
    // Every backend apply may flush the runtime-only pair sets. Invalidate the
    // observer epoch before touching live chains so an outstanding worker can
    // never acknowledge an old pair after a URLTest or recovery rebuild.
    cancel_idle_stall_observer();

    KPBR_UNIQUE_LOCK(
        affinity_mutation_lock,
        udp_call_affinity_mutation_mutex_);
    const auto interface_snapshot =
        shared_ndms_catalog_cache().peek();
    const auto service_snapshot =
        shared_ndms_vpn_server_service_cache().peek();
    const auto effective_interface_servers =
        prefer_authoritative_internal_vpn_service_inventory(
            resolved_internal_vpn_servers_,
            interface_snapshot.catalog,
            service_snapshot.catalog,
            service_snapshot.status ==
                NdmsCatalogCacheStatus::fresh);
    auto runtime_targets =
        internal_vpn_interface_runtime_targets(
            effective_interface_servers);
    runtime_targets.insert(
        runtime_targets.end(),
        resolved_internal_vpn_service_targets_.begin(),
        resolved_internal_vpn_service_targets_.end());
    const auto native_vpn_direct_egress_snat_selectors =
        select_native_vpn_direct_egress_snat_selectors(
            runtime_targets);
    if (!list_cache_snapshot) {
        list_cache_snapshot =
            capture_relevant_list_cache_generation(config_);
    }
    AppliedListContentState candidate_list_content_state;
    auto candidate_rules = apply_runtime_firewall(
        config_,
        outbound_marks_,
        firewall_state_.get_urltest_selections(),
        list_service_.cache_manager(),
        *firewall_,
        mode,
        &effective_interface_servers,
        &runtime_targets,
        &native_vpn_direct_egress_snat_selectors,
        &candidate_list_content_state,
        opts_.udp_call_affinity_ipset_available,
        active_keenetic_dns_.snapshot,
        std::move(list_cache_snapshot));
    firewall_state_.set_rules(std::move(candidate_rules));
    applied_list_content_state_ =
        std::move(candidate_list_content_state);
    reconcile_native_vpn_direct_egress_conntrack(
        native_vpn_direct_egress_snat_selectors);

#ifdef WITH_API
    // The firmware reapplies its own firewall on every network event and drops
    // rules it does not own, so the remote access hole has to be restored
    // alongside ours rather than only once at startup.
    apply_remote_access_rules(config_.api.has_value()
                                  ? config_.api->listen.value_or(std::string{})
                                  : std::string{});
#endif
    affinity_mutation_lock.unlock();

    // Re-arm only after the replacement firewall transaction and its remote
    // access companion have committed successfully. A failed apply remains
    // fail-closed and its caller may retry the whole transaction.
    reset_idle_stall_observer(/*schedule_if_eligible=*/true);
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

        const auto list_cache_snapshot =
            capture_relevant_list_cache_generation(config_);
        firewall_state_.set_urltest_selection(
            change.urltest_tag, change.new_child_tag);
        bool runtime_rebuilt = false;
        try {
            reconcile_static_routing(RouteReconcileMode::Strict);
            apply_firewall(
                FirewallApplyMode::PreserveSets,
                list_cache_snapshot);
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
                reconcile_static_routing(RouteReconcileMode::Strict);
                apply_firewall(
                    FirewallApplyMode::PreserveSets,
                    list_cache_snapshot);
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
        targets.push_back({outbound.tag,
                           mark_it->second,
                           outbound.interface.value_or(std::string())});
        known_tags.push_back(outbound.tag);
    }

    interface_probe_.retain_only(known_tags);

    if (targets.empty()) {
        auto task_metrics =
            periodic_task_metrics_.begin("interface-probe");
        task_metrics.noop();
        return;
    }
    auto task_metrics = std::make_shared<PeriodicTaskRunToken>(
        periodic_task_metrics_.begin("interface-probe"));
    // Probing blocks on the network, so it must not run on the event loop.
    const bool enqueued = blocking_executor_.try_post(
        "interface-probe",
        [this, targets, task_metrics]() {
            std::vector<std::string> transitioned_tags;
            try {
                transitioned_tags = interface_probe_.probe(targets);
            } catch (const std::exception& error) {
                task_metrics->failure(error.what());
                return;
            } catch (...) {
                task_metrics->failure("interface probe failed");
                return;
            }
            const bool posted = post_control_task(
                [this,
                 transitioned_tags = std::move(transitioned_tags),
                 task_metrics]() {
                    std::string reconciliation_error;
                    if (urltest_manager_ && !transitioned_tags.empty()) {
                        const auto affected_urltests = find_affected_urltests(
                            config_.outbounds.value_or(
                                std::vector<Outbound>{}),
                            transitioned_tags);
                        for (const auto& urltest_tag : affected_urltests) {
                            Logger::instance().trace(
                                "urltest_transition_probe",
                                "tag={} changed_children={}",
                                urltest_tag,
                                transitioned_tags.size());
                            urltest_manager_->trigger_immediate_test(
                                urltest_tag);
                        }
                    }
                    if (routing_runtime_active_) {
                        // Keenetic may recreate a tunnel route without
                        // changing its administrative UP state. Reconcile the
                        // owned policy tables after the regular probe so
                        // vanished urltest fallback routes heal without a
                        // service restart.
                        try {
                            reconcile_static_routing(
                                RouteReconcileMode::DeferredRepair);
                        } catch (const RouteInterfaceUnavailableError& error) {
                            // A not-yet-ready new route remains transactional,
                            // but a periodic probe must not immediately repeat
                            // it or turn ordinary tunnel churn into a bell
                            // incident. UP events and the next probe are
                            // existing retry sources.
                            Logger::instance().verbose(
                                "Interface-probe route reconciliation is "
                                "waiting for its interface: {}",
                                error.what());
                        } catch (const std::exception& error) {
                            // Posted control tasks must never let a transient
                            // or permanent netlink failure escape into the
                            // daemon event loop. Hand the uncommon hard failure
                            // to the existing bounded runtime recovery
                            // coordinator.
                            Logger::instance().info(
                                "Interface-probe route reconciliation was "
                                "deferred: {}",
                                error.what());
                            reconciliation_error = error.what();
                            (void)refresh_iproute_and_firewall_runtime(
                                0,
                                std::nullopt,
                                std::nullopt,
                                /*schedule_catalog_refresh=*/false);
                        }
                    }
#ifdef WITH_API
                    if (status_stream_) {
                        status_stream_->reconcile();
                    }
#endif
                    if (reconciliation_error.empty()) {
                        task_metrics->success();
                    } else {
                        task_metrics->failure(reconciliation_error);
                    }
                },
                "interface-probe-status");
            if (!posted) {
                task_metrics->skipped(
                    "control loop is not accepting commits");
            }
        });
    if (!enqueued) {
        task_metrics->skipped("blocking executor is unavailable");
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
    std::optional<std::uint64_t> expected_generation,
    std::shared_ptr<const ListCacheGenerationSnapshot>
        list_cache_snapshot) {
    // Backing off matters here: the contention that caused the failure is the
    // firmware settling after boot, and it clears on its own within seconds.
    constexpr int kMaxAttempts = 6;
    const auto delay = std::chrono::seconds{5 * attempt};
    const auto generation = expected_generation.value_or(
        runtime_generation_.load(std::memory_order_acquire));
    if (!list_cache_snapshot) {
        list_cache_snapshot =
            capture_relevant_list_cache_generation(config_);
    }

    scheduler_->schedule_oneshot(
        delay,
        [this, attempt, generation,
         list_cache_snapshot = std::move(list_cache_snapshot)]() {
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
                const auto internal_vpn_service_resolution =
                    prepare_internal_vpn_service_resolution_from_cache();
                InternalVpnRuntimeGenerationTransaction
                    internal_vpn_generation(
                        resolved_internal_vpn_servers_,
                        internal_vpn_resolution.effective_servers);
                InternalVpnRuntimeTargetGenerationTransaction
                    internal_vpn_service_generation(
                        resolved_internal_vpn_service_targets_,
                        internal_vpn_service_resolution.effective_targets);
                schedule_internal_vpn_catalog_refresh_if_needed(
                    internal_vpn_resolution.state,
                    internal_vpn_service_resolution.state);
                apply_firewall(
                    FirewallApplyMode::PreserveSets,
                    list_cache_snapshot);
                cleanup_owned_conntrack_marks(
                    "after delayed startup firewall activation");
                internal_vpn_generation.commit();
                internal_vpn_service_generation.commit();
                update_internal_vpn_verified_includes_lkg(
                    internal_vpn_resolution);
                update_internal_vpn_service_verified_includes_lkg(
                    internal_vpn_service_resolution);
                log.info("Firewall rules and routing applied on retry {}.", attempt);
            } catch (const TransientFirewallError& e) {
                if (attempt >= kMaxAttempts) {
                    log.error("Giving up on applying firewall rules after {} retries: {}",
                              attempt, e.what());
                    return;
                }
                log.info("Firewall retry {} failed: {}. Trying again.", attempt, e.what());
                schedule_startup_firewall_retry(
                    attempt + 1, generation, list_cache_snapshot);
            } catch (const std::exception& e) {
                if (config_has_native_vpn_catalog_policy(config_) &&
                    attempt < kMaxAttempts) {
                    log.info(
                        "Stable native VPN generation retry {} failed: {}. "
                        "Keeping the previous generation and trying again.",
                        attempt,
                        e.what());
                    schedule_startup_firewall_retry(
                        attempt + 1, generation, list_cache_snapshot);
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
    // This method is also called after a post-apply refresh completes. Replace
    // the previous one-shot instead of accumulating duplicate timers.
    if (lists_autoupdate_task_id_ >= 0) {
        scheduler_->cancel(lists_autoupdate_task_id_);
        lists_autoupdate_task_id_ = -1;
    }
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
    Config config_snapshot,
    bool runtime_active_snapshot,
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
         config_snapshot = std::move(config_snapshot),
         runtime_active_snapshot,
         generation,
         reload,
         completion_result,
         error = std::move(error),
         source = std::move(source),
         trace_id,
         reschedule]() mutable {
            ScopedTraceContext trace_scope_inner(trace_id);
            auto& refresh_result = *completion_result;

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
            const auto reconcile_committed_cache = [this, reload, &source](
                RemoteListsRefreshResult& committed,
                bool& reloaded) -> std::optional<std::string> {
                if (!reload || !routing_runtime_active_ ||
                    !committed.any_changed()) {
                    return std::nullopt;
                }
                try {
                    // Cache writes are already durable enough for the next
                    // startup and cannot be undone here. Re-apply the current
                    // configuration (never the worker's stale snapshot) so a
                    // subsequent HTTP 304 cannot leave live routing/DNS on
                    // the previous list contents.
                    const Config current_config = config_;
                    bool rolled_back = false;
                    apply_config_with_rollback(
                        current_config, rolled_back, false);
                    reloaded = true;
                    Logger::instance().info(
                        "Lists refresh ({}): reconciled committed cache "
                        "against the current runtime generation",
                        source);
                    return std::nullopt;
                } catch (const std::exception& reconcile_error) {
                    return std::string(
                               "failed to reconcile committed list cache: ") +
                           reconcile_error.what();
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
                if (!refresh_result || !refresh_result->any_changed()) {
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
                bool reloaded = false;
                if (const auto reconcile_error =
                        reconcile_committed_cache(committed, reloaded)) {
                    (void)list_refresh_tasks_.fail(
                        task_id,
                        *reconcile_error,
                        std::move(committed),
                        reloaded);
                } else if (cancellation.cancellation_requested()) {
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
                (!refresh_result || !refresh_result->any_changed())) {
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
            if (!error.empty() &&
                !cancellation.cancellation_requested()) {
                Logger::instance().error(
                    "Lists refresh ({}) failed: {}", source, error);
                finish_failed(error);
                return;
            }

            if (cancellation.cancellation_requested()) {
                RemoteListsRefreshResult committed =
                    std::move(*refresh_result);
                refresh_result.reset();
                bool reloaded = false;
                if (const auto reconcile_error =
                        reconcile_committed_cache(committed, reloaded)) {
                    (void)list_refresh_tasks_.fail(
                        task_id,
                        *reconcile_error,
                        std::move(committed),
                        reloaded);
                } else {
                    (void)list_refresh_tasks_.finish_cancelled(
                        task_id,
                        "list refresh cancelled after committing completed lists",
                        std::move(committed),
                        reloaded);
                }
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

            if (reload && should_reload_runtime_after_list_refresh(
                              runtime_active_snapshot,
                              result.refresh_result)) {
                Logger::instance().info(
                    "Lists refresh ({}): relevant list(s) changed ({}), reloading runtime",
                    source,
                    format_list_names(result.refresh_result.relevant_changed_lists));
                if (!list_refresh_tasks_.mark_applying(task_id)) {
                    if (cancellation.cancellation_requested()) {
                        if (const auto reconcile_error =
                                reconcile_committed_cache(
                                    result.refresh_result,
                                    result.reloaded)) {
                            (void)list_refresh_tasks_.fail(
                                task_id,
                                *reconcile_error,
                                std::move(result.refresh_result),
                                result.reloaded);
                        } else {
                            (void)list_refresh_tasks_.finish_cancelled(
                                task_id,
                                "list refresh cancelled after committing completed lists",
                                std::move(result.refresh_result),
                                result.reloaded);
                        }
                    } else {
                        (void)list_refresh_tasks_.fail(
                            task_id,
                            "list refresh task left the running state before apply",
                            std::move(result.refresh_result),
                            result.reloaded);
                    }
                    schedule_next();
                    return;
                }
                try {
                    bool rolled_back = false;
                    apply_config_with_rollback(config_snapshot, rolled_back, false);
                    result.reloaded = true;
                } catch (const std::exception& e) {
                    const std::string message = e.what();
                    Logger::instance().error(
                        "Lists refresh ({}) reload failed: {}", source, message);
                    (void)list_refresh_tasks_.fail(
                        task_id,
                        message,
                        std::move(result.refresh_result),
                        result.reloaded);
                    schedule_next();
                    return;
                }
            } else if (result.refresh_result.any_relevant_changed()) {
                Logger::instance().info(
                    reload
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
    std::string source) {
    auto& log = Logger::instance();

    if (!accept_posted_control_tasks_.load(std::memory_order_acquire)) {
        return {false, {}, "daemon is shutting down"};
    }

    const Config config_snapshot = config_;
    const auto target_selection =
        select_remote_list_targets(config_snapshot, std::nullopt);
    if (!target_selection.ok()) {
        return {false, {}, "failed to select remote lists"};
    }

    auto started = list_refresh_tasks_.begin(target_selection.list_names.size());
    if (!started.accepted) {
        Logger::instance().trace("lists_refresh_skip",
                                 "source={} reason=inflight",
                                 source);
        return {false, std::move(started.task), "busy"};
    }

    log.info("Lists refresh ({}): checking for updates", source);
    const std::string task_id = started.task.id;
    const ListRefreshCancellationToken cancellation = started.cancellation;
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
         task_id,
         cancellation,
         config_snapshot,
         marks_snapshot,
         runtime_active_snapshot,
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
                    config_snapshot,
                    marks_snapshot,
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
                config_snapshot,
                runtime_active_snapshot,
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

void Daemon::refresh_lists_and_maybe_reload_async(std::string source) {
    const bool reschedule = source == "autoupdate" || source == "post-apply";
    const auto start = start_remote_list_refresh_task(true, source);
    if (!start.accepted && reschedule) {
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
    prepared.keenetic_dns = prepare_keenetic_dns_view(
        config,
        /*allow_refresh=*/!preparing_on_control_loop);
    prepared.internal_vpn_resolution =
        resolve_internal_vpn_servers_for_runtime(
            config,
            !preparing_on_control_loop,
            snapshot_internal_vpn_verified_includes_lkg());
    prepared.internal_vpn_service_resolution =
        resolve_internal_vpn_services_for_runtime(
            config,
            !preparing_on_control_loop,
            snapshot_internal_vpn_service_verified_includes_lkg());

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
        const bool authoritative_negative = std::any_of(
            resolution.issues.begin(),
            resolution.issues.end(),
            [](const InternalVpnServerResolutionIssue& issue) {
                return issue.error !=
                       InternalVpnServerResolutionError::
                           catalog_not_authoritative;
            });
        if (authoritative_negative) {
            Logger::instance().warn(
                "Native VPN server inventory is incomplete; continuing with "
                "a conservative degraded policy (unverified bypasses are "
                "disabled; an unresolved included server may be temporarily "
                "outside keen-pbr processing): {}",
                detail);
        } else if (
            generation.source ==
            InternalVpnServerGenerationSource::retained_previous) {
            Logger::instance().info(
                "Native VPN server inventory is temporarily inconclusive; "
                "retaining previously verified include-only bindings while "
                "dropping every unverified bypass: {}",
                detail);
        } else {
            Logger::instance().info(
                "Native VPN server inventory is temporarily unavailable; "
                "continuing with a conservative live-name policy while an "
                "authoritative refresh is pending (unverified bypasses remain "
                "disabled): {}",
                detail);
        }
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

InternalVpnServiceRuntimeResolution
Daemon::resolve_internal_vpn_services_for_runtime(
    const Config& config,
    bool allow_catalog_refresh,
    const std::vector<InternalVpnRuntimeTarget>&
        previous_verified_includes) {
    if (!config_requires_internal_vpn_service_inventory(config)) {
        return {
            {},
            InternalVpnRuntimeResolutionState::verified,
        };
    }
    auto& cache = shared_ndms_vpn_server_service_cache();
    const auto snapshot =
        allow_catalog_refresh ? cache.force_refresh() : cache.peek();
    return resolve_internal_vpn_services_for_runtime(
        config, snapshot, previous_verified_includes);
}

InternalVpnServiceRuntimeResolution
Daemon::resolve_internal_vpn_services_for_runtime(
    const Config& config,
    const NdmsVpnServerServiceSnapshot& snapshot,
    const std::vector<InternalVpnRuntimeTarget>&
        previous_verified_includes) {
    if (!config_requires_internal_vpn_service_inventory(config)) {
        return {
            {},
            InternalVpnRuntimeResolutionState::verified,
        };
    }
    const auto route = config.route.value_or(RouteConfig{});
    const auto configured = route.internal_vpn_services.value_or(
        std::vector<InternalVpnService>{});
    const bool default_process_clients =
        internal_vpn_service_default_process_clients(config);
    const auto live_interfaces = netlink_.dump_interfaces();
    auto resolution = resolve_internal_vpn_service_policies(
        configured,
        snapshot.catalog,
        snapshot.status == NdmsCatalogCacheStatus::fresh,
        default_process_clients,
        internal_vpn_inbound_observation(
            config, live_interfaces));
    auto generation = select_internal_vpn_service_generation(
        configured,
        resolution,
        previous_verified_includes,
        default_process_clients);
    refresh_internal_vpn_service_ingress_interfaces(
        generation.effective_targets, live_interfaces);

    InternalVpnRuntimeResolutionState state =
        InternalVpnRuntimeResolutionState::verified;
    if (!resolution.complete()) {
        std::string detail;
        for (const auto& issue : resolution.issues) {
            if (!detail.empty()) detail += "; ";
            detail += describe_internal_vpn_service_resolution_issue(issue);
        }
        const bool authoritative_negative = std::any_of(
            resolution.issues.begin(),
            resolution.issues.end(),
            [](const auto& issue) {
                return issue.error !=
                       InternalVpnServiceResolutionError::
                           catalog_not_authoritative;
            });
        if (authoritative_negative) {
            state =
                InternalVpnRuntimeResolutionState::authoritative_negative;
            Logger::instance().warn(
                "Native VPN service inventory is incomplete; every "
                "unverified source-pool bypass is disabled: {}",
                detail);
        } else if (
            generation.source ==
            InternalVpnServiceGenerationSource::
                retained_previous_includes) {
            state =
                InternalVpnRuntimeResolutionState::
                    retained_verified_includes;
            Logger::instance().info(
                "Native VPN service inventory is temporarily unavailable; "
                "retaining only previously verified include pools: {}",
                detail);
        } else {
            state = InternalVpnRuntimeResolutionState::degraded;
            Logger::instance().info(
                "Native VPN service inventory is temporarily unavailable; "
                "no unverified source-pool bypass is active while an "
                "authoritative refresh is pending: {}",
                detail);
        }
    }

    return {
        std::move(generation.effective_targets),
        state,
        std::move(resolution.verified_includes_for_lkg),
        std::move(resolution.retain_verified_include_service_ids),
    };
}

std::vector<InternalVpnRuntimeTarget>
Daemon::snapshot_internal_vpn_service_verified_includes_lkg() const {
    KPBR_LOCK_GUARD(internal_vpn_lkg_mutex_);
    return internal_vpn_service_verified_includes_lkg_;
}

void Daemon::update_internal_vpn_service_verified_includes_lkg(
    const InternalVpnServiceRuntimeResolution& resolution) noexcept {
    try {
        if (resolution.state !=
                InternalVpnRuntimeResolutionState::verified &&
            resolution.state !=
                InternalVpnRuntimeResolutionState::authoritative_negative) {
            return;
        }
        KPBR_LOCK_GUARD(internal_vpn_lkg_mutex_);
        internal_vpn_service_verified_includes_lkg_ =
            merge_internal_vpn_service_verified_includes_lkg(
                internal_vpn_service_verified_includes_lkg_,
                resolution.verified_includes_for_lkg,
                resolution.retain_verified_include_service_ids);
    } catch (const std::exception& error) {
        try {
            Logger::instance().warn(
                "Could not publish native VPN service verified-pool cache: "
                "{}. The committed runtime generation remains active.",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().warn(
                "Could not publish native VPN service verified-pool cache. "
                "The committed runtime generation remains active.");
        } catch (...) {
        }
    }
}

InternalVpnServiceRuntimeResolution
Daemon::prepare_internal_vpn_service_resolution_from_cache() {
    return resolve_internal_vpn_services_for_runtime(
        config_,
        false,
        snapshot_internal_vpn_service_verified_includes_lkg());
}

void Daemon::schedule_internal_vpn_catalog_refresh() {
    const bool needs_interface_catalog =
        config_has_stable_internal_vpn_server_policy(config_);
    const bool needs_service_catalog =
        config_requires_internal_vpn_service_inventory(config_);
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
                        routing_runtime_active_ &&
                        config_has_native_vpn_catalog_policy(config_);
                    if (rerun_is_valid) {
                        schedule_internal_vpn_catalog_refresh();
                    }

                    if (!routing_runtime_active_ ||
                        !config_has_native_vpn_catalog_policy(config_)) {
                        return;
                    }
                    const bool current_needs_interface =
                        config_has_stable_internal_vpn_server_policy(config_);
                    const bool current_needs_service =
                        config_requires_internal_vpn_service_inventory(
                            config_);
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
                            config_,
                            interface_snapshot,
                            snapshot_internal_vpn_verified_includes_lkg());
                    auto service_resolution =
                        resolve_internal_vpn_services_for_runtime(
                            config_,
                            service_snapshot,
                            snapshot_internal_vpn_service_verified_includes_lkg());
                    const bool interface_changed =
                        !same_internal_vpn_runtime_servers(
                            resolved_internal_vpn_servers_,
                            resolution.effective_servers);
                    const bool service_changed =
                        !same_internal_vpn_runtime_targets(
                            resolved_internal_vpn_service_targets_,
                            service_resolution.effective_targets);
                    if (!interface_changed && !service_changed) {
                        // No kernel replacement is needed, so publishing the
                        // newly verified LKG cannot diverge from forwarding.
                        update_internal_vpn_verified_includes_lkg(
                            resolution);
                        update_internal_vpn_service_verified_includes_lkg(
                            service_resolution);
                        publish_runtime_state();
                        return;
                    }
                    // Do not publish candidate resolved/LKG state here. Pass
                    // the prepared authoritative observation into the sole
                    // generation transaction: it commits memory only after
                    // route/firewall succeeds and restores the previous map
                    // on every failure path.
                    refresh_iproute_and_firewall_runtime(
                        0,
                        std::move(resolution),
                        std::move(service_resolution));
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
            config_has_native_vpn_catalog_policy(config_)) {
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
            config_, interface_state);
    const bool service_needs_refresh =
        config_requires_internal_vpn_service_inventory(config_) &&
        service_state != InternalVpnRuntimeResolutionState::verified;
    if (!routing_runtime_active_ ||
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
            routing_runtime_active_,
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
    internal_vpn_catalog_incidents_.clear();
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
            // Resolver bytes must never advance ahead of a failed firewall
            // rollback. This explicit generation latch remains closed even
            // after bounded firewall retries are exhausted; the successful
            // firewall reconciliation schedules a fresh resolver attempt.
            if (resolver_after_firewall_gate_.waiting_for(
                    runtime_generation)) {
                Logger::instance().verbose(
                    "Holding resolver reload recovery until firewall "
                    "generation {} has converged.",
                    runtime_generation);
                return;
            }
            start_resolver_reload_retry_attempt(
                attempt, runtime_generation);
        },
        "resolver-reload-recovery");
    Logger::instance().info(
        "Resolver reload recovery attempt {} scheduled in {}s.",
        attempt + 1,
        delay.count());
}

void Daemon::start_resolver_reload_retry_attempt(
    std::size_t attempt,
    std::uint64_t runtime_generation) {
    if (!routing_runtime_active_ ||
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
        generation->stream_epoch =
            resolver_stream_epoch_.fetch_add(
                1, std::memory_order_acq_rel) + 1;
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

        auto lifetime = std::make_shared<ResolverStreamAttemptLifetime>(
            ipc_resolver_hook_inflight_,
            mutation_lease,
            generation,
            [this, attempt_id]() noexcept {
                KPBR_LOCK_GUARD(resolver_stream_attempt_mutex_);
                if (active_resolver_stream_attempt_id_ == attempt_id) {
                    active_resolver_stream_attempt_id_.clear();
                    active_resolver_stream_generation_.reset();
                }
            });
        resolver_generation_snapshot_ = generation;
        {
            KPBR_LOCK_GUARD(resolver_stream_attempt_mutex_);
            active_resolver_stream_attempt_id_ = attempt_id;
            active_resolver_stream_generation_ = generation;
        }

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
            Logger::instance().info(
                "Resolver reload recovery attempt {} was rejected by the "
                "worker coordinator",
                attempt + 1);
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
        Logger::instance().info(
            "Resolver reload recovery attempt {} could not start: {}",
            attempt + 1,
            error.what());
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
            !routing_runtime_active_) {
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

        if (!result.completed && !result.error.empty()) {
            Logger::instance().info(
                "Resolver reload recovery attempt {} failed: {}",
                operation.retry_attempt + 1,
                result.error);
        }
        const auto outcome = evaluate_resolver_reload_retry(
            routing_runtime_active_,
            operation.runtime_generation,
            current_generation,
            operation.retry_attempt,
            RESOLVER_RELOAD_RETRY_DELAYS.size(),
            [&result]() { return result.completed; });

        if (outcome == ResolverReloadRetryOutcome::stale_generation) {
            return;
        }
        if (outcome == ResolverReloadRetryOutcome::recovered) {
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

        Logger::instance().error(
            "Resolver reload did not recover after {} bounded attempts; "
            "routing remains active but DNS needs attention.",
            RESOLVER_RELOAD_RETRY_DELAYS.size());
        refresh_resolver_config_hash_actual_async();
        publish_runtime_state();
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
                if (!routing_runtime_active_ || !config_.dns.has_value() ||
                    !dns_config_uses_keenetic_server(*config_.dns)) {
                    return;
                }
                (void)keenetic_dns_refresh_coordinator_.request(
                    runtime_generation_.load(std::memory_order_acquire));
            },
            "keenetic-dns-refresh-after-resolver-recovery");
        if (!queued && routing_runtime_active_) {
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
    idle_stall_observer_enabled_.store(false, std::memory_order_release);
    try {
        if (scheduler_ && idle_stall_observer_task_id_ >= 0) {
            scheduler_->cancel(idle_stall_observer_task_id_);
        }
    } catch (...) {
    }
    idle_stall_observer_task_id_ = -1;
    idle_stall_detector_.reset();
    udp_call_affinity_detector_.reset();
    idle_stall_destination_selectors_.clear();
    udp_call_affinity_destination_selectors_.clear();
    idle_stall_coverage_generation_.fetch_add(
        1U, std::memory_order_acq_rel);
}

void Daemon::schedule_idle_stall_observer_after(
    std::chrono::seconds delay) noexcept {
    try {
        if (!scheduler_ ||
            !idle_stall_observer_enabled_.load(
                std::memory_order_acquire) ||
            !routing_runtime_active_) {
            return;
        }
        if (idle_stall_observer_task_id_ >= 0) {
            scheduler_->cancel(idle_stall_observer_task_id_);
            idle_stall_observer_task_id_ = -1;
        }
        idle_stall_observer_task_id_ = scheduler_->schedule_oneshot(
            std::chrono::duration_cast<std::chrono::milliseconds>(delay),
            [this]() {
                idle_stall_observer_task_id_ = -1;
                run_idle_stall_observer();
            },
            "idle-stall-observer");
    } catch (const std::exception& error) {
        idle_stall_observer_task_id_ = -1;
        idle_stall_observer_enabled_.store(
            false, std::memory_order_release);
        idle_stall_detector_.reset();
        udp_call_affinity_detector_.reset();
        idle_stall_destination_selectors_.clear();
        udp_call_affinity_destination_selectors_.clear();
        idle_stall_coverage_generation_.fetch_add(
            1U, std::memory_order_acq_rel);
        try {
            Logger::instance().info(
                "Idle forwarded-flow observer was not scheduled: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        idle_stall_observer_task_id_ = -1;
        idle_stall_observer_enabled_.store(
            false, std::memory_order_release);
        idle_stall_detector_.reset();
        udp_call_affinity_detector_.reset();
        idle_stall_destination_selectors_.clear();
        udp_call_affinity_destination_selectors_.clear();
        idle_stall_coverage_generation_.fetch_add(
            1U, std::memory_order_acq_rel);
    }
}

void Daemon::reset_idle_stall_observer(
    bool schedule_if_eligible) noexcept {
    cancel_idle_stall_observer();
    if (!schedule_if_eligible || !routing_runtime_active_ ||
        !reconnect_unmarked_flows_on_routing_change_enabled(config_) ||
        reconnect_owned_flows_on_routing_change_list_names(config_).empty()) {
        return;
    }
    idle_stall_observer_enabled_.store(true, std::memory_order_release);
    // The first short observation only establishes whether relevant flows
    // exist. Subsequent empty scans back off to the 30-second quiet interval.
    schedule_idle_stall_observer_after(IDLE_STALL_ACTIVE_SCAN_INTERVAL);
}

void Daemon::run_idle_stall_observer() noexcept {
    try {
        if (!routing_runtime_active_ ||
            !idle_stall_observer_enabled_.load(
                std::memory_order_acquire) ||
            !reconnect_unmarked_flows_on_routing_change_enabled(config_)) {
            cancel_idle_stall_observer();
            return;
        }

        const auto configured_list_names =
            reconnect_owned_flows_on_routing_change_list_names(config_);
        const auto selected_list_names =
            active_destination_only_reconnect_list_names(
                configured_list_names,
                firewall_state_.get_rules());
        if (selected_list_names.empty()) {
            cancel_idle_stall_observer();
            return;
        }
        auto whatsapp_latency_list_names =
            whatsapp_call_affinity_list_names(config_);
        for (auto iterator = whatsapp_latency_list_names.begin();
             iterator != whatsapp_latency_list_names.end();) {
            if (selected_list_names.count(*iterator) == 0U) {
                iterator = whatsapp_latency_list_names.erase(iterator);
            } else {
                ++iterator;
            }
        }
        auto call_affinity_targets =
            firewall_->backend() == FirewallBackend::iptables &&
                    !opts_.udp_call_affinity_ipset_available
                ? std::vector<UdpCallAffinityTarget>{}
                : active_udp_call_affinity_targets(
                      whatsapp_latency_list_names,
                      firewall_state_.get_rules(),
                      firewall_state_.get_fwmark_mask());

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
            idle_stall_detector_.reset();
            udp_call_affinity_detector_.reset();
            idle_stall_destination_selectors_.clear();
            udp_call_affinity_destination_selectors_.clear();
            idle_stall_coverage_generation_.fetch_add(
                1U, std::memory_order_acq_rel);
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
                whatsapp_destination_selectors.clear();
                udp_call_affinity_detector_.reset();
            }
        }
        const bool idle_observation_scope_changed =
            destination_selectors != idle_stall_destination_selectors_ ||
            whatsapp_destination_selectors !=
                udp_call_affinity_destination_selectors_;
        if (idle_observation_scope_changed) {
            idle_stall_detector_.reset();
            udp_call_affinity_detector_.reset();
            idle_stall_destination_selectors_ = destination_selectors;
            udp_call_affinity_destination_selectors_ =
                whatsapp_destination_selectors;
            idle_stall_coverage_generation_.fetch_add(
                1U, std::memory_order_acq_rel);
        }
        const auto retained_affinity_sources =
            call_affinity_targets.empty()
            ? std::vector<std::string>{}
            : udp_call_affinity_detector_.retained_guard_sources(
                  UdpCallAffinityDetector::Clock::now());

        const auto runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const auto coverage_generation =
            idle_stall_coverage_generation_.load(
                std::memory_order_acquire);
        const auto owned_mask = firewall_state_.get_fwmark_mask();
        const bool ipv6_enabled = resolve_ipv6_support(config_).enabled;
        if (runtime_generation == 0U || coverage_generation == 0U ||
            owned_mask == 0U) {
            idle_stall_detector_.reset();
            udp_call_affinity_detector_.reset();
            schedule_idle_stall_observer_after(
                IDLE_STALL_QUIET_SCAN_INTERVAL);
            return;
        }

        bool expected = false;
        if (!idle_stall_observer_inflight_.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
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
             whatsapp_destination_selectors,
             destination_selectors =
                 std::move(destination_selectors)]() mutable {
                AtomicFlagResetGuard inflight_guard(
                    idle_stall_observer_inflight_);
                ConntrackFlowObservation observation;
                std::vector<std::string> local_interface_addresses;
                std::string failure_detail;

                const auto generation_is_current = [this,
                                                     runtime_generation,
                                                     coverage_generation]() {
                    return idle_stall_observer_enabled_.load(
                               std::memory_order_acquire) &&
                           runtime_generation_.load(
                               std::memory_order_acquire) ==
                               runtime_generation &&
                           idle_stall_coverage_generation_.load(
                               std::memory_order_acquire) ==
                               coverage_generation;
                };

                try {
                    if (generation_is_current()) {
                        local_interface_addresses =
                            local_interface_addresses_from(
                                netlink_.dump_interfaces());
                    }
                    // This is the last fence before the bounded /proc scan.
                    if (generation_is_current()) {
                        std::set<std::uint32_t> call_affinity_marks;
                        for (const auto& target : call_affinity_targets) {
                            call_affinity_marks.insert(target.fwmark);
                        }
                        observation = conntrack_manager_.
                            observe_forwarded_destination_flows(
                                destination_selectors,
                                local_interface_addresses,
                                owned_mask,
                                ConntrackFlowObservationOptions{
                                    ipv6_enabled,
                                    IDLE_STALL_MAX_FLOWS,
                                    IDLE_STALL_MAX_DESTINATION_CIDRS,
                                    IDLE_STALL_MAX_SNAPSHOT_BYTES,
                                    IDLE_STALL_MAX_SNAPSHOT_LINES,
                                    /*allow_foreign_mark_bits_for_media=*/true},
                                retained_affinity_sources,
                                whatsapp_destination_selectors,
                                call_affinity_marks);
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
                     call_affinity_targets =
                         std::move(call_affinity_targets),
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
                                std::move(call_affinity_targets),
                                ipv6_enabled,
                                coverage_complete,
                                std::move(failure_detail));
                        } catch (const std::exception& error) {
                            idle_stall_observer_inflight_.store(
                                false, std::memory_order_release);
                            idle_stall_detector_.reset();
                            udp_call_affinity_detector_.reset();
                            Logger::instance().info(
                                "Idle forwarded-flow observation commit "
                                "failed closed: {}",
                                error.what());
                            schedule_idle_stall_observer_after(
                                IDLE_STALL_QUIET_SCAN_INTERVAL);
                        } catch (...) {
                            idle_stall_observer_inflight_.store(
                                false, std::memory_order_release);
                            idle_stall_detector_.reset();
                            udp_call_affinity_detector_.reset();
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
            idle_stall_observer_inflight_.store(
                false, std::memory_order_release);
            schedule_idle_stall_observer_after(
                IDLE_STALL_ACTIVE_SCAN_INTERVAL);
        }
    } catch (const std::exception& error) {
        idle_stall_observer_inflight_.store(
            false, std::memory_order_release);
        idle_stall_detector_.reset();
        udp_call_affinity_detector_.reset();
        Logger::instance().info(
            "Idle forwarded-flow observation failed closed: {}",
            error.what());
        schedule_idle_stall_observer_after(
            IDLE_STALL_QUIET_SCAN_INTERVAL);
    } catch (...) {
        idle_stall_observer_inflight_.store(
            false, std::memory_order_release);
        idle_stall_detector_.reset();
        udp_call_affinity_detector_.reset();
        schedule_idle_stall_observer_after(
            IDLE_STALL_QUIET_SCAN_INTERVAL);
    }
}

void Daemon::dispatch_udp_call_affinity_mutations(
    std::uint64_t expected_runtime_generation,
    std::uint64_t expected_coverage_generation,
    std::uint32_t owned_mask,
    bool ipv6_enabled,
    UdpCallAffinityDetector::TimePoint decision_deadline,
    std::vector<UdpCallAffinityDecision> decisions) {
    if (decisions.empty()) {
        return;
    }

    const auto release_decisions = [this, &decisions]() {
        for (const auto& decision : decisions) {
            udp_call_affinity_detector_.release_failed(decision);
        }
    };
    const auto generation_is_current = [this,
                                        expected_runtime_generation,
                                        expected_coverage_generation]() {
        return running_.load(std::memory_order_acquire) &&
               routing_runtime_active_ &&
               idle_stall_observer_enabled_.load(
                   std::memory_order_acquire) &&
               runtime_generation_.load(std::memory_order_acquire) ==
                   expected_runtime_generation &&
               idle_stall_coverage_generation_.load(
                   std::memory_order_acquire) ==
                   expected_coverage_generation;
    };
    if (!generation_is_current() || !firewall_) {
        release_decisions();
        return;
    }

    bool expected = false;
    if (!udp_call_affinity_mutation_inflight_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        // The earlier batch owns the exact pairs it reserved. Release this
        // later observation so it may be reconsidered after that batch ends.
        release_decisions();
        return;
    }
    AtomicFlagResetGuard dispatch_guard(
        udp_call_affinity_mutation_inflight_);

    std::vector<UdpCallAffinityMutationWork> work;
    work.reserve(decisions.size());
    for (const auto& decision : decisions) {
        const int family = decision.family == ConntrackFlowFamily::Ipv6
            ? AF_INET6
            : AF_INET;
        const std::string set_name = firewall_->media_affinity_set_name(
            decision.list_name, family);
        work.push_back(UdpCallAffinityMutationWork{
            decision,
            set_name});
    }

    const TraceId trace_id = ensure_trace_id();
    const bool enqueued = blocking_executor_.try_post(
        "udp-call-affinity-mutation",
        [this,
         expected_runtime_generation,
         expected_coverage_generation,
         owned_mask,
         ipv6_enabled,
         decision_deadline,
         work = std::move(work)]() mutable {
            AtomicFlagResetGuard inflight_guard(
                udp_call_affinity_mutation_inflight_);
            const auto generation_is_current = [this,
                                                 expected_runtime_generation,
                                                 expected_coverage_generation]() {
                // Worker code may consult only atomics. The control-owned
                // routing_runtime_active_ flag is checked before dispatch and
                // again by the posted control-loop completion.
                return running_.load(std::memory_order_acquire) &&
                       idle_stall_observer_enabled_.load(
                           std::memory_order_acquire) &&
                       runtime_generation_.load(
                           std::memory_order_acquire) ==
                           expected_runtime_generation &&
                       idle_stall_coverage_generation_.load(
                           std::memory_order_acquire) ==
                           expected_coverage_generation;
            };

            std::vector<UdpCallAffinityMutationOutcome> outcomes;
            outcomes.reserve(work.size());
            for (auto& item : work) {
                outcomes.push_back(UdpCallAffinityMutationOutcome{
                    std::move(item.decision)});
            }

            bool conntrack_unavailable = false;
            {
                // The lifecycle path cancels the observer epoch before taking
                // this same barrier. Therefore queued work must re-check all
                // atomic fences only after it has exclusive mutation access.
                KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);

                const auto revalidate_decision =
                    [this,
                     owned_mask,
                     ipv6_enabled,
                     decision_deadline,
                     &generation_is_current](
                        const UdpCallAffinityDecision& decision,
                        UdpCallAffinityRevalidationMode mode)
                        -> std::optional<
                            std::vector<ConntrackExactForwardedFlow>> {
                    if (!generation_is_current() ||
                        UdpCallAffinityDetector::Clock::now() >=
                            decision_deadline) {
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
                                owned_mask,
                                ConntrackFlowObservationOptions{
                                    ipv6_enabled,
                                    IDLE_STALL_MAX_FLOWS,
                                    IDLE_STALL_MAX_DESTINATION_CIDRS,
                                    IDLE_STALL_MAX_SNAPSHOT_BYTES,
                                    IDLE_STALL_MAX_SNAPSHOT_LINES,
                                    /*allow_foreign_mark_bits_for_media=*/true},
                                sources);
                        if (!generation_is_current() ||
                            UdpCallAffinityDetector::Clock::now() >=
                                decision_deadline ||
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

                        if (mode == UdpCallAffinityRevalidationMode::
                                BeforePublication) {
                            const bool peer_became_ambiguous = std::any_of(
                                current.source_wide_udp_flows.begin(),
                                current.source_wide_udp_flows.end(),
                                [&decision, owned_mask](const auto& candidate) {
                                    if (candidate.family != decision.family ||
                                        candidate.source != decision.source ||
                                        candidate.destination_port !=
                                            decision.destination_port ||
                                        candidate.destination !=
                                            decision.destination) {
                                        return false;
                                    }
                                    return
                                           (candidate.mark & owned_mask) != 0U ||
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
                                 owned_mask](
                                    const auto& candidate) {
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
                                    if (mode ==
                                        UdpCallAffinityRevalidationMode::
                                            RefreshBeforePublication) {
                                        const auto owned_mark =
                                            candidate.mark & owned_mask;
                                        return owned_mark == 0U ||
                                               owned_mark == decision.fwmark;
                                    }
                                    const auto owned_mark =
                                        candidate.mark & owned_mask;
                                    return owned_mark == 0U ||
                                           owned_mark == decision.fwmark;
                                });
                            const bool mark_is_allowed =
                                live !=
                                    current.source_wide_udp_flows.end() &&
                                ((mode == UdpCallAffinityRevalidationMode::
                                              BeforePublication &&
                                  live->mark == baseline.mark) ||
                                 (mode == UdpCallAffinityRevalidationMode::
                                              AfterPublication &&
                                  ((live->mark & owned_mask) == 0U ||
                                   (live->mark & owned_mask) ==
                                       decision.fwmark)) ||
                                 (mode == UdpCallAffinityRevalidationMode::
                                              RefreshBeforePublication &&
                                  ((live->mark & owned_mask) == 0U ||
                                   (live->mark & owned_mask) ==
                                       decision.fwmark)));
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
                            if ((mode == UdpCallAffinityRevalidationMode::
                                             RefreshBeforePublication &&
                                 refresh_still_active) ||
                                (mode != UdpCallAffinityRevalidationMode::
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
                     index < outcomes.size();
                     ++index) {
                    if (!generation_is_current()) {
                        break;
                    }
                    auto& outcome = outcomes[index];
                    if (UdpCallAffinityDetector::Clock::now() >=
                        decision_deadline) {
                        outcome.deadline_expired = true;
                        continue;
                    }

                    {
                        const auto before_publication = revalidate_decision(
                            outcome.decision,
                            outcome.decision.refresh_only
                                ? UdpCallAffinityRevalidationMode::
                                      RefreshBeforePublication
                                : UdpCallAffinityRevalidationMode::
                                      BeforePublication);
                        if (!before_publication.has_value()) {
                            if (!generation_is_current()) {
                                break;
                            }
                            if (UdpCallAffinityDetector::Clock::now() >=
                                decision_deadline) {
                                outcome.deadline_expired = true;
                            } else {
                                outcome.revalidation_failed = true;
                            }
                            continue;
                        }
                        if (before_publication->empty()) {
                            continue;
                        }
                    }

                    if (!generation_is_current()) {
                        break;
                    }
                    if (UdpCallAffinityDetector::Clock::now() >=
                        decision_deadline) {
                        outcome.deadline_expired = true;
                        continue;
                    }
                    outcome.publication_attempted = true;
                    try {
                        outcome.installed = firewall_->add_udp_peer(
                            work[index].set_name,
                            outcome.decision.source,
                            outcome.decision.destination_port,
                            outcome.decision.destination);
                    } catch (...) {
                        outcome.installed = false;
                    }
                    if (!outcome.installed ||
                        outcome.decision.refresh_only ||
                        conntrack_unavailable) {
                        continue;
                    }
                    if (!generation_is_current()) {
                        break;
                    }
                    if (UdpCallAffinityDetector::Clock::now() >=
                        decision_deadline) {
                        outcome.deadline_expired = true;
                        continue;
                    }

                    // Publishing the UDP peer tuple can immediately make a retried
                    // tuple acquire the intended mark without replacing its
                    // old direct-WAN NAT binding. Re-read the exact 5-tuple
                    // without using mark as identity; only an empty or intended
                    // owned mark, still unanswered and unassured, may be
                    // retired with its current full-width exact mark selector.
                    const auto after_publication =
                        revalidate_decision(
                            outcome.decision,
                            UdpCallAffinityRevalidationMode::
                                AfterPublication);
                    if (!after_publication.has_value()) {
                        if (!generation_is_current()) {
                            break;
                        }
                        if (UdpCallAffinityDetector::Clock::now() >=
                            decision_deadline) {
                            outcome.deadline_expired = true;
                        } else {
                            outcome.revalidation_failed = true;
                        }
                        continue;
                    }
                    outcome.revalidated_flows = *after_publication;

                    for (const auto& flow : outcome.revalidated_flows) {
                        if (!generation_is_current()) {
                            break;
                        }
                        if (UdpCallAffinityDetector::Clock::now() >=
                            decision_deadline) {
                            outcome.deadline_expired = true;
                            break;
                        }
                        ConntrackCleanupResult result =
                            ConntrackCleanupResult::Failed;
                        try {
                            result = conntrack_manager_.
                                delete_exact_forwarded_flow(
                                    flow,
                                    owned_mask,
                                    outcome.decision.fwmark);
                        } catch (...) {
                            ++outcome.failed_flows;
                            continue;
                        }
                        if (result ==
                            ConntrackCleanupResult::Succeeded) {
                            ++outcome.retired_flows;
                        } else if (result ==
                                   ConntrackCleanupResult::CommandUnavailable) {
                            conntrack_unavailable = true;
                            ++outcome.failed_flows;
                            break;
                        } else {
                            ++outcome.failed_flows;
                        }
                    }
                }
            }

            const bool completion_posted = post_control_task(
                [this,
                 expected_runtime_generation,
                 expected_coverage_generation,
                 outcomes = std::move(outcomes),
                 conntrack_unavailable]() mutable {
                    udp_call_affinity_mutation_inflight_.store(
                        false, std::memory_order_release);
                    const bool generation_is_current =
                        running_.load(std::memory_order_acquire) &&
                        routing_runtime_active_ &&
                        idle_stall_observer_enabled_.load(
                            std::memory_order_acquire) &&
                        runtime_generation_.load(
                            std::memory_order_acquire) ==
                            expected_runtime_generation &&
                        idle_stall_coverage_generation_.load(
                            std::memory_order_acquire) ==
                            expected_coverage_generation;
                    if (!generation_is_current) {
                        return;
                    }

                    std::size_t installed = 0U;
                    std::size_t refreshed = 0U;
                    std::size_t retired = 0U;
                    std::size_t pair_failures = 0U;
                    std::size_t flow_failures = 0U;
                    std::size_t deadline_expirations = 0U;
                    std::size_t revalidation_skips = 0U;
                    const auto completed_at =
                        UdpCallAffinityDetector::Clock::now();
                    for (const auto& outcome : outcomes) {
                        retired += outcome.retired_flows;
                        flow_failures += outcome.failed_flows;
                        deadline_expirations +=
                            outcome.deadline_expired ? 1U : 0U;
                        revalidation_skips +=
                            outcome.revalidation_failed ? 1U : 0U;
                        if (outcome.installed) {
                            // The expiring kernel pair is authoritative once
                            // published. A best-effort exact retirement
                            // failure must not erase the detector lease and
                            // cause duplicate promotion attempts.
                            udp_call_affinity_detector_.confirm_installed(
                                outcome.decision, completed_at);
                            if (outcome.decision.refresh_only) {
                                ++refreshed;
                            } else {
                                ++installed;
                            }
                        } else {
                            udp_call_affinity_detector_.release_failed(
                                outcome.decision);
                            if (outcome.publication_attempted) {
                                ++pair_failures;
                            }
                        }
                    }
                    if (deadline_expirations != 0U ||
                        revalidation_skips != 0U) {
                        Logger::instance().trace(
                            "udp_call_affinity_mutation_skip",
                            "generation={} deadline_expired={} "
                            "revalidation_failed={}",
                            expected_runtime_generation,
                            deadline_expirations,
                            revalidation_skips);
                    }

                    if (installed != 0U) {
                        Logger::instance().info(
                            "Activated {} short-lived WhatsApp call peer "
                            "pair(s) and retired {} revalidated direct-WAN "
                            "flow(s)",
                            installed,
                            retired);
                    } else if (pair_failures != 0U) {
                        Logger::instance().info(
                            "WhatsApp call peer affinity left {} pair "
                            "publication(s) inactive; no unverified "
                            "conntrack flow was removed",
                            pair_failures);
                    }
                    if (refreshed != 0U) {
                        Logger::instance().verbose(
                            "Refreshed {} active WhatsApp call peer lease(s)",
                            refreshed);
                    }
                    if (conntrack_unavailable) {
                        Logger::instance().info(
                            "WhatsApp call peer rules were activated, but "
                            "exact stale-flow retirement is unavailable "
                            "because conntrack could not be run");
                    } else if (flow_failures != 0U) {
                        Logger::instance().info(
                            "WhatsApp call peer affinity left {} exact "
                            "stale-flow retirement(s) incomplete; no broad "
                            "cleanup was attempted",
                            flow_failures);
                    }
                },
                "udp-call-affinity-mutation-commit");
            if (completion_posted) {
                inflight_guard.release();
            }
        },
        trace_id);

    if (enqueued) {
        dispatch_guard.release();
    } else {
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
    std::vector<UdpCallAffinityTarget> call_affinity_targets,
    bool ipv6_enabled,
    bool coverage_complete,
    std::string failure_detail) {
    const auto generation_is_current = [this,
                                        expected_runtime_generation,
                                        expected_coverage_generation]() {
        return routing_runtime_active_ &&
               idle_stall_observer_enabled_.load(
                   std::memory_order_acquire) &&
               runtime_generation_.load(std::memory_order_acquire) ==
                   expected_runtime_generation &&
               idle_stall_coverage_generation_.load(
                   std::memory_order_acquire) ==
                   expected_coverage_generation;
    };
    if (!generation_is_current()) {
        idle_stall_observer_inflight_.store(
            false, std::memory_order_release);
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
        !observation.media_seed_destination_input_truncated &&
        observation.invalid_media_guard_sources == 0U &&
        !observation.invalid_owned_mask;
    std::set<IdleStallFlowKey> whatsapp_latency_flow_keys;
    for (const auto& flow : observation.media_seed_flows) {
        whatsapp_latency_flow_keys.insert(idle_stall_key_from(flow));
    }
    scan.flows.reserve(observation.flows.size());
    for (const auto& flow : observation.flows) {
        const auto key = idle_stall_key_from(flow);
        scan.flows.push_back(idle_stall_sample_from(
            flow,
            whatsapp_latency_flow_keys.count(key) != 0U
                ? IdleStallRecoveryPolicy::
                      packaged_whatsapp_ip_companion
                : IdleStallRecoveryPolicy::standard));
    }

    const auto observation_time = UdpCallAffinityDetector::Clock::now();
    std::vector<UdpCallAffinityDecision> affinity_decisions;
    try {
        affinity_decisions = udp_call_affinity_detector_.observe(
            scan.epoch,
            scan.status,
            owned_mask,
            call_affinity_targets,
            observation.media_seed_flows,
            observation.source_wide_udp_flows,
            observation_time);
    } catch (const std::exception& error) {
        udp_call_affinity_detector_.reset();
        Logger::instance().info(
            "UDP call affinity detector failed closed: {}",
            error.what());
    } catch (...) {
        udp_call_affinity_detector_.reset();
    }
    const bool affinity_fast_followup =
        udp_call_affinity_detector_.needs_fast_followup(
            observation_time);
    const bool affinity_discovery_enabled =
        !call_affinity_targets.empty();

    dispatch_udp_call_affinity_mutations(
        expected_runtime_generation,
        expected_coverage_generation,
        owned_mask,
        ipv6_enabled,
        observation_time + UDP_CALL_AFFINITY_MUTATION_DEADLINE,
        std::move(affinity_decisions));

    std::vector<IdleStallDeleteDecision> decisions;
    try {
        decisions = idle_stall_detector_.observe(
            scan, observation_time);
    } catch (const std::exception& error) {
        idle_stall_detector_.reset();
        Logger::instance().info(
            "Idle forwarded-flow detector failed closed: {}",
            error.what());
    } catch (...) {
        idle_stall_detector_.reset();
    }
    const bool relevant_flows_observed =
        !observation.flows.empty() ||
        !observation.source_wide_udp_flows.empty();
    if (decisions.empty()) {
        const auto whatsapp_fast_followup =
            idle_stall_detector_.take_whatsapp_fast_followup_delay();
        idle_stall_observer_inflight_.store(
            false, std::memory_order_release);
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
                       idle_stall_detector_.tracked_flow_count() != 0U) {
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
    for (const auto& flow : observation.flows) {
        if (flow.protocol == ConntrackFlowProtocol::Udp && flow.assured) {
            media_baselines.push_back(flow);
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
            idle_stall_detector_.acknowledge_delete_result(
                decision, false, now);
        }
    };
    if (pending_deletes.empty() || !generation_is_current()) {
        release_pending_decisions();
        idle_stall_observer_inflight_.store(
            false, std::memory_order_release);
        const auto fast_followup =
            idle_stall_detector_.take_whatsapp_fast_followup_delay();
        const auto next_interval =
            fast_followup.value_or(IDLE_STALL_ACTIVE_SCAN_INTERVAL);
        schedule_idle_stall_observer_after(next_interval);
        return;
    }
    std::vector<std::string> media_guard_sources;
    media_guard_sources.reserve(pending_deletes.size());
    for (const auto& pending : pending_deletes) {
        media_guard_sources.push_back(pending.flow.source);
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
         destination_selectors = std::move(destination_selectors),
         ipv6_enabled,
         observed_local_interface_addresses =
             std::move(observed_local_interface_addresses)]() mutable {
            AtomicFlagResetGuard inflight_guard(
                idle_stall_observer_inflight_);
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
                return idle_stall_observer_enabled_.load(
                           std::memory_order_acquire) &&
                       runtime_generation_.load(
                           std::memory_order_acquire) ==
                           expected_runtime_generation &&
                       idle_stall_coverage_generation_.load(
                           std::memory_order_acquire) ==
                           expected_coverage_generation;
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
                                ConntrackFlowObservationOptions{
                                    ipv6_enabled,
                                    IDLE_STALL_MAX_FLOWS,
                                    IDLE_STALL_MAX_DESTINATION_CIDRS,
                                    IDLE_STALL_MAX_SNAPSHOT_BYTES,
                                    IDLE_STALL_MAX_SNAPSHOT_LINES,
                                    /*allow_foreign_mark_bits_for_media=*/true},
                                media_guard_sources);
                        live_scope_changed =
                            current_observation.snapshot_unavailable ||
                            current_observation.snapshot_truncated ||
                            current_observation.line_limit_reached ||
                            current_observation.flow_limit_reached ||
                            current_observation.local_address_scope_missing ||
                            current_observation.destination_input_truncated ||
                            current_observation.invalid_owned_mask ||
                            current_observation.
                                    invalid_media_guard_sources != 0U ||
                            current_observation.
                                    invalid_destination_selectors != 0U;

                        std::set<std::pair<ConntrackFlowFamily, std::string>>
                            protected_sources;
                        if (!live_scope_changed) {
                            for (const auto& current :
                                 current_observation.
                                     source_wide_udp_flows) {
                                if (current.protocol !=
                                        ConntrackFlowProtocol::Udp ||
                                    !current.assured) {
                                    continue;
                                }
                                const auto baseline = std::find_if(
                                    media_baselines.begin(),
                                    media_baselines.end(),
                                    [&current](const auto& candidate) {
                                        return idle_stall_key_from(candidate) ==
                                               idle_stall_key_from(current);
                                    });
                                const bool new_bidirectional_media =
                                    baseline == media_baselines.end() &&
                                    current.original.packets != 0U &&
                                    current.reply.packets != 0U;
                                const bool existing_media_progressed =
                                    baseline != media_baselines.end() &&
                                    (current.original.packets >
                                         baseline->original.packets ||
                                     current.original.bytes >
                                         baseline->original.bytes) &&
                                    (current.reply.packets >
                                         baseline->reply.packets ||
                                     current.reply.bytes >
                                         baseline->reply.bytes);
                                if (new_bidirectional_media ||
                                    existing_media_progressed) {
                                    protected_sources.emplace(
                                        current.family, current.source);
                                }
                            }
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
                                if (!current_state_eligible ||
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
                    idle_stall_observer_inflight_.store(
                        false, std::memory_order_release);
                    const auto generation_is_current = [this,
                                                        expected_runtime_generation,
                                                        expected_coverage_generation]() {
                        return running_.load(std::memory_order_acquire) &&
                               routing_runtime_active_ &&
                               idle_stall_observer_enabled_.load(
                                   std::memory_order_acquire) &&
                               runtime_generation_.load(
                                   std::memory_order_acquire) ==
                                   expected_runtime_generation &&
                               idle_stall_coverage_generation_.load(
                                   std::memory_order_acquire) ==
                                   expected_coverage_generation;
                    };
                    if (!generation_is_current()) {
                        return;
                    }

                    std::size_t succeeded = 0U;
                    std::size_t failed = 0U;
                    bool command_unavailable = false;
                    std::set<std::uint64_t> acknowledged_attempts;
                    const auto acknowledge =
                        [this, &acknowledged_attempts](
                            const IdleStallDeleteDecision& decision,
                            bool delete_succeeded) {
                            idle_stall_detector_.acknowledge_delete_result(
                                decision,
                                delete_succeeded,
                                IdleStallDetector::Clock::now());
                            acknowledged_attempts.insert(decision.attempt_id);
                        };

                    if (!live_scope_changed) {
                        // Exact deletion is deliberately serialized on the
                        // control loop. Apply/stop tasks cannot change the
                        // committed runtime generation between this final
                        // fence and the irreversible 5-tuple operation.
                        for (const auto& pending : pending_deletes) {
                            if (!generation_is_current()) {
                                live_scope_changed = true;
                                break;
                            }
                            ConntrackCleanupResult result =
                                ConntrackCleanupResult::Failed;
                            try {
                                result = conntrack_manager_.
                                    delete_exact_forwarded_flow(
                                        pending.flow, owned_mask);
                            } catch (...) {
                                ++failed;
                                acknowledge(pending.decision, false);
                                continue;
                            }
                            if (result ==
                                ConntrackCleanupResult::Succeeded) {
                                ++succeeded;
                                acknowledge(pending.decision, true);
                            } else if (result ==
                                       ConntrackCleanupResult::
                                           CommandUnavailable) {
                                command_unavailable = true;
                                acknowledge(pending.decision, false);
                                break;
                            } else {
                                ++failed;
                                acknowledge(pending.decision, false);
                            }
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
                        !routing_runtime_active_ ||
                        !idle_stall_observer_enabled_.load(
                            std::memory_order_acquire) ||
                        runtime_generation_.load(
                            std::memory_order_acquire) !=
                            expected_runtime_generation ||
                        idle_stall_coverage_generation_.load(
                            std::memory_order_acquire) !=
                            expected_coverage_generation) {
                        return;
                    }
                    if (succeeded != 0U) {
                        Logger::instance().info(
                            "Recovered {} exact idle forwarded flow(s) after "
                            "their reply path stopped progressing",
                            succeeded);
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
                        idle_stall_detector_.
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
        idle_stall_observer_inflight_.store(
            false, std::memory_order_release);
        const auto fast_followup =
            idle_stall_detector_.take_whatsapp_fast_followup_delay();
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
                return routing_runtime_active_;
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
                                resolve_ipv6_support(config_).enabled,
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
    if (config_requires_internal_vpn_service_inventory(prepared.config)) {
        prepared.internal_vpn_service_resolution =
            resolve_internal_vpn_services_for_runtime(
                prepared.config,
                false,
                snapshot_internal_vpn_service_verified_includes_lkg());
    }

    const auto has_restricted_forwarded_scope = [](
        const Config& config,
        const std::vector<InternalVpnServer>& internal_vpn_servers,
        const std::vector<InternalVpnRuntimeTarget>& internal_vpn_targets) {
        const auto route_config = config.route.value_or(RouteConfig{});
        const bool has_explicit_inbound_scope =
            route_config.inbound_interfaces.has_value() &&
            !route_config.inbound_interfaces->empty();
        const bool has_native_vpn_bypass = std::any_of(
            internal_vpn_servers.begin(), internal_vpn_servers.end(),
            [](const InternalVpnServer& server) {
                return !server.process_clients;
            }) || std::any_of(
            internal_vpn_targets.begin(), internal_vpn_targets.end(),
            [](const InternalVpnRuntimeTarget& target) {
                return !target.process_clients;
            });
        return has_explicit_inbound_scope || has_native_vpn_bypass;
    };
    const bool previous_runtime_active = routing_runtime_active_;
    const bool reconnect_unmarked_flows_on_routing_change =
        reconnect_unmarked_flows_on_routing_change_enabled(prepared.config);
    const auto previous_owned_reconnect_list_names =
        reconnect_owned_flows_on_routing_change_list_names(config_);
    const auto current_owned_reconnect_list_names =
        reconnect_owned_flows_on_routing_change_list_names(prepared.config);
    std::set<std::string> newly_enabled_owned_reconnect_list_names;
    std::set_difference(
        current_owned_reconnect_list_names.begin(),
        current_owned_reconnect_list_names.end(),
        previous_owned_reconnect_list_names.begin(),
        previous_owned_reconnect_list_names.end(),
        std::inserter(
            newly_enabled_owned_reconnect_list_names,
            newly_enabled_owned_reconnect_list_names.end()));
    const bool previous_forwarded_scope_restricted =
        has_restricted_forwarded_scope(
            config_,
            resolved_internal_vpn_servers_,
            resolved_internal_vpn_service_targets_);
    const AppliedRoutingSignature previous_routing_signature{
        firewall_state_.get_fwmark_mask(),
        firewall_state_.get_rules(),
    };
    const AppliedListContentState previous_list_content_state =
        applied_list_content_state_;
    // Repair and retire any flows from a previously observed SNAT loss before
    // publishing `applying` or reassigning numerical marks. A transient
    // firmware race here must reject the save while the old runtime remains
    // active, not falsely publish a broken state.
    complete_pending_snat_recovery_before_generation_change();

    transition_runtime_or_throw(RuntimeState::applying, "configuration apply started");
    publish_runtime_state();

    try {
    cancel_idle_stall_observer();
    cancel_owned_conntrack_cleanup_retry();
    const auto applying_runtime_generation =
        runtime_generation_.fetch_add(1, std::memory_order_acq_rel) + 1U;
    resolver_after_firewall_gate_.reset();
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
    const auto internal_vpn_service_lkg_update =
        prepared.internal_vpn_service_resolution;
    outbound_marks_ = std::move(prepared.outbound_marks);
    resolved_internal_vpn_servers_ =
        std::move(
            prepared.internal_vpn_resolution.effective_servers);
    resolved_internal_vpn_service_targets_ =
        std::move(
            prepared.internal_vpn_service_resolution.effective_targets);
    active_keenetic_dns_ = std::move(prepared.keenetic_dns);
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
    reconcile_static_routing(RouteReconcileMode::Strict);
    register_urltest_outbounds();
    const auto list_cache_snapshot =
        capture_relevant_list_cache_generation(config_);
    retry_hot_apply_firewall(
        [this, &list_cache_snapshot]() {
            // apply_firewall rebuilds the complete pending transaction on
            // every call. A retry therefore never reuses the one-shot backend
            // state from the failed attempt.
            apply_firewall(
                FirewallApplyMode::PreserveSets,
                list_cache_snapshot);
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
    commit_resolver_generation_snapshot(
        make_resolver_generation_snapshot(list_cache_snapshot));
    setup_dns_probe();
    const auto resolver_snapshot =
        resolver_sync_.snapshot(unix_timestamp_now_seconds());
    if (resolver_reload_required(resolver_snapshot.expected_hash,
                                 resolver_snapshot.actual_hash,
                                 resolver_snapshot.live_status)) {
        if (!run_system_resolver_hook_stream_prepared(
                "reload", /*rebuild_snapshot=*/false)) {
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
    update_internal_vpn_service_verified_includes_lkg(
        internal_vpn_service_lkg_update);
    config_store_.replace_active(config_, outbound_marks_);
#ifdef WITH_API
    refresh_interface_traffic_config_targets(config_);
#endif
    routing_runtime_active_ = true;
    schedule_internal_vpn_catalog_refresh_if_needed(
        internal_vpn_lkg_update.state,
        internal_vpn_service_lkg_update.state);
    transition_runtime_or_throw(RuntimeState::running, "configuration apply complete");
    publish_runtime_state();
    if (runtime_firewall_retry_.owned_snat_recovery_pending()) {
        // The transactional save may have replaced the firewall while a
        // firmware-NAT recovery retry was pending. Reconcile once against the
        // newly committed generation so the latched missing-SNAT observation
        // still reaches verified conntrack cleanup.
        (void)refresh_iproute_and_firewall_runtime(
            0,
            std::nullopt,
            std::nullopt,
            /*schedule_catalog_refresh=*/false,
            runtime_firewall_retry_.pending_owned_snat_recovery());
    }
    // Conntrack retirement is irreversible. Keep it as the final, no-throw
    // phase after the replacement has been persisted, published and fully
    // reconciled. If an earlier phase throws, the caller can restore the
    // previous generation without having already destroyed its live flows.
    const AppliedRoutingSignature current_routing_signature{
        firewall_state_.get_fwmark_mask(),
        firewall_state_.get_rules(),
    };
    const bool current_forwarded_scope_restricted =
        has_restricted_forwarded_scope(
            config_,
            resolved_internal_vpn_servers_,
            resolved_internal_vpn_service_targets_);
    ConntrackDestinationRetirementCoverage destination_coverage;
    ConntrackDestinationRetirementCoverage owned_destination_coverage;
    if (previous_runtime_active &&
        reconnect_unmarked_flows_on_routing_change) {
        std::set<std::string> changed_list_names;
        for (const auto& [list_name, current_destinations] :
             applied_list_content_state_.static_destinations) {
            const auto previous =
                previous_list_content_state.static_destinations.find(
                    list_name);
            if (previous ==
                    previous_list_content_state.static_destinations.end() ||
                previous->second != current_destinations) {
                changed_list_names.insert(list_name);
            }
        }
        for (const auto& list_name :
             applied_list_content_state_.domain_entry_lists) {
            if (previous_list_content_state.domain_entry_lists.count(
                    list_name) == 0U) {
                changed_list_names.insert(list_name);
            }
        }
        for (const auto& list_name :
             applied_list_content_state_.
                 truncated_static_destination_lists) {
            if (previous_list_content_state.
                    truncated_static_destination_lists.count(list_name) ==
                0U) {
                changed_list_names.insert(list_name);
            }
        }
        const std::vector<RuleState> no_previous_rules;
        const auto& comparison_rules =
            previous_forwarded_scope_restricted &&
                !current_forwarded_scope_restricted
            ? no_previous_rules
            : previous_routing_signature.firewall_rules;
        const auto destination_plan = plan_conntrack_destination_retirement(
            comparison_rules,
            current_routing_signature.firewall_rules,
            changed_list_names);
        destination_coverage =
            collect_conntrack_destination_retirement_coverage(
                destination_plan,
                applied_list_content_state_);

        const auto owned_reconnect_lists =
            plan_conntrack_owned_destination_reconnect(
                previous_routing_signature.firewall_rules,
                current_routing_signature.firewall_rules,
                current_owned_reconnect_list_names,
                changed_list_names,
                newly_enabled_owned_reconnect_list_names);
        if (!owned_reconnect_lists.empty()) {
            const auto owned_plan =
                destination_retirement_plan_for_lists(
                    owned_reconnect_lists);
            // Include both sides of a list-content transition. Otherwise an
            // address removed by a refresh could keep an already marked UDP
            // flow pinned to the obsolete route until its natural timeout.
            owned_destination_coverage =
                merge_conntrack_destination_retirement_coverage(
                    collect_conntrack_destination_retirement_coverage(
                        owned_plan,
                        applied_list_content_state_),
                    collect_conntrack_destination_retirement_coverage(
                        owned_plan,
                        previous_list_content_state));
        }
    }
    execute_committed_stale_flow_reconnect(
        applying_runtime_generation,
        previous_runtime_active,
        !current_forwarded_scope_restricted,
        current_routing_signature.owned_mask,
        destination_coverage,
        owned_destination_coverage);
    reset_idle_stall_observer(/*schedule_if_eligible=*/true);
    } catch (...) {
        routing_runtime_active_ = false;
        cancel_idle_stall_observer();
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
    const KeeneticDnsCacheView previous_keenetic_dns =
        active_keenetic_dns_;

    try {
        apply_config(next_config, refresh_remote_lists);
        rolled_back = false;
    } catch (...) {
        try {
            auto rollback = prepare_runtime_inputs(
                previous_config,
                RemoteListPreparationMode::None);
            rollback.keenetic_dns = previous_keenetic_dns;
            apply_prepared_runtime_inputs(std::move(rollback));
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

} // namespace keen_pbr3
