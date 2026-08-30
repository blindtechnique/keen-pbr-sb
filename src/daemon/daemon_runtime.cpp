#include "daemon.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <fstream>
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
#include "../health/differential_probe.hpp"
#include "../health/nfqws_scan_source.hpp"
#include "../http/http_transport.hpp"
#include "../log/logger.hpp"
#include "../routing/urltest_manager.hpp"
#include "../runtime/meta_udp_443_policy.hpp"
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
constexpr auto RESOLVER_RELOAD_MAINTENANCE_DELAY =
    std::chrono::seconds{60};
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
constexpr std::size_t META_UDP443_ACTIVATION_MAX_FLOWS = 256U;
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

ConntrackFlowObservationOptions meta_udp443_observation_options(
    bool ipv6_enabled) {
    ConntrackFlowObservationOptions options;
    options.ipv6_enabled = ipv6_enabled;
    options.max_flows = META_UDP443_ACTIVATION_MAX_FLOWS;
    options.max_destination_input_cidrs =
        IDLE_STALL_MAX_DESTINATION_CIDRS;
    options.max_snapshot_bytes = IDLE_STALL_MAX_SNAPSHOT_BYTES;
    options.max_snapshot_lines = IDLE_STALL_MAX_SNAPSHOT_LINES;
    options.allow_foreign_mark_bits_for_media = true;
    options.include_ordinary_destination_flows = false;
    options.media_seed_udp_destination_port = 443U;
    return options;
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
                          left.dns_redirect_local_destinations_v4 ==
                              right.dns_redirect_local_destinations_v4 &&
                          left.dns_redirect_local_destinations_v6 ==
                              right.dns_redirect_local_destinations_v6 &&
                          left.source_cidrs_v4 == right.source_cidrs_v4 &&
                          left.source_cidrs_v6 == right.source_cidrs_v6;
               });
}

} // namespace

bool Daemon::fastnat_is_disabled_or_unavailable() {
    constexpr std::array<const char*, 2> paths{
        "/proc/sys/net/netfilter/nf_conntrack_fastnat",
        "/proc/sys/net/ipv4/netfilter/ip_conntrack_fastnat",
    };
    for (const char* path : paths) {
        std::ifstream input(path);
        if (!input) {
            if (::access(path, F_OK) == 0) {
                return false;
            }
            continue;
        }
        std::string value;
        std::string extra;
        if (!(input >> value) || (input >> extra) || value != "0") {
            return false;
        }
    }
    // Kernels without either control do not provide Keenetic FastNAT and are
    // therefore already on the ordinary netfilter path.
    return true;
}

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
    bool rebuild_snapshot,
    bool inactive_activation_authority) {
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
                inactive_resolver_activation_generation_.reset();
            }
        });
    resolver_generation_snapshot_ = generation;
    {
        KPBR_LOCK_GUARD(resolver_stream_attempt_mutex_);
        active_resolver_stream_attempt_id_ = attempt_id;
        active_resolver_stream_generation_ = generation;
        inactive_resolver_activation_generation_ =
            inactive_activation_authority ? generation : nullptr;
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
    // The store owns this outright now: reading the whole snapshot to get one
    // bool copied the route and rule vectors and the urltest map on every
    // event that asks.
    return runtime_state_store_.routing_runtime_active();
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
            routing_runtime_active(),
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
        routing_runtime_active(),
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
    // Do not cross the generation boundary until short-lived exact reset
    // policy is verified absent; a failed drain retains its maintenance timer.
    if (!drain_exact_tcp_reset_cleanups_before_generation_change()) {
        resume_exact_tcp_reset_cleanups();
        throw TransientFirewallError(
            "exact TCP reset cleanup is incomplete before runtime stop");
    }
    cancel_idle_stall_observer();
    cancel_meta_udp443_activation_cleanup();
    cancel_owned_snat_health_check();
    cancel_owned_conntrack_cleanup_retry();
    cancel_runtime_firewall_retry();
    runtime_firewall_retry_.clear_owned_snat_recovery();
    urltest_after_firewall_gate_.reset();
    cancel_resolver_reload_retry();
    cancel_internal_vpn_catalog_refresh_retry();
    if (!routing_runtime_active()) {
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
        clear_exact_tcp_reset_cleanup_ownership();
        committed_meta_udp443_fwmark_.reset();
        committed_meta_udp443_owned_mask_ = 0U;
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
    runtime_state_store_.set_routing_runtime_active(false);
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
    if (routing_runtime_active()) {
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
        urltest_after_firewall_gate_.reset();
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
                /*rebuild_snapshot=*/false,
                /*inactive_activation_authority=*/true)) {
            throw DaemonError("System resolver activation hook failed");
        }

        internal_vpn_generation.commit();
        internal_vpn_service_generation.commit();
        update_internal_vpn_verified_includes_lkg(
            internal_vpn_resolution);
        update_internal_vpn_service_verified_includes_lkg(
            internal_vpn_service_resolution);
        runtime_state_store_.set_routing_runtime_active(true);
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
#ifdef WITH_API
        request_remote_access_reconcile_from_control("runtime start");
#endif
        schedule_keenetic_dns_refresh();
        refresh_resolver_config_hash_actual_async();
        publish_runtime_state();
        log.info("Routing runtime started.");
    } catch (...) {
        // A start failure may happen at any point after routes or firewall
        // state were installed. Roll every owned subsystem back, not only the
        // resolver hook, so health and the kernel cannot disagree.
        // Invalidate the deferred Meta cleanup before removing its filter:
        // the timer may otherwise become runnable after this catch and delete
        // exact tuples for a runtime which never reached the started state.
        cancel_meta_udp443_activation_cleanup();
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
            committed_meta_udp443_fwmark_.reset();
            committed_meta_udp443_owned_mask_ = 0U;
        } catch (const std::exception& cleanup_error) {
            log.error("Failed to clean firewall after start failure: {}",
                      cleanup_error.what());
        }
        if (!run_system_resolver_hook("deactivate")) {
            log.warn("System resolver fallback recovery failed");
        }
        runtime_state_store_.set_routing_runtime_active(false);
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
    if (!routing_runtime_active()) {
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

        runtime_state_store_.set_routing_runtime_active(true);
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
        acknowledge_verified_resolver_reload(
            runtime_generation_.load(std::memory_order_acquire));
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
        runtime_state_store_.set_routing_runtime_active(true);
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
                    ? kResolverReloadPendingRuntimeReason.data()
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

std::optional<MetaUdp443ActivationPlan>
Daemon::prepare_meta_udp443_activation_or_throw(
    const std::vector<RuleState>& candidate_rules,
    const AppliedListContentState& candidate_list_content_state,
    bool forwarded_scope_allows_unmarked_cleanup) {
    const auto owned_mask = fwmark_mask_value(
        config_.fwmark.value_or(FwmarkConfig{}));
    const auto selection = resolve_meta_udp_443_policy_selection(
        config_, candidate_rules, owned_mask);
    if (!selection.active()) {
        return std::nullopt;
    }
    if (!fastnat_is_disabled_or_unavailable()) {
        throw DaemonError(
            "daemon.meta_udp443_policy=messages_first requires verified "
            "FastNAT-off packet traversal");
    }

    std::set<std::uint32_t> cleanup_owned_marks{selection.fwmark};
    if (committed_meta_udp443_fwmark_.has_value()) {
        if (committed_meta_udp443_owned_mask_ != owned_mask) {
            throw DaemonError(
                "Meta UDP/443 messages-first cannot change the fwmark mask "
                "while the policy is active; switch to balanced first");
        }
        if (*committed_meta_udp443_fwmark_ == 0U ||
            (*committed_meta_udp443_fwmark_ & ~owned_mask) != 0U) {
            throw DaemonError(
                "Meta UDP/443 messages-first cannot prove the previously "
                "committed route mark for exact activation cleanup");
        }
        cleanup_owned_marks.insert(*committed_meta_udp443_fwmark_);
    }
    const bool ipv6_enabled = resolve_ipv6_support(config_).enabled;
    const auto capability =
        conntrack_manager_.probe_exact_cleanup_capability(ipv6_enabled);
    if (capability == ConntrackCleanupResult::CommandUnavailable) {
        throw DaemonError(
            "daemon.meta_udp443_policy=messages_first requires the "
            "conntrack utility for exact activation cleanup");
    }
    if (capability != ConntrackCleanupResult::Succeeded) {
        throw DaemonError(
            "daemon.meta_udp443_policy=messages_first could not verify "
            "the exact conntrack cleanup capability");
    }

    const std::set<std::string> list_names(
        selection.list_names.begin(), selection.list_names.end());
    auto coverage = collect_conntrack_destination_retirement_coverage(
        destination_retirement_plan_for_lists(list_names),
        candidate_list_content_state);
    std::sort(
        coverage.destination_selectors.begin(),
        coverage.destination_selectors.end());
    coverage.destination_selectors.erase(
        std::unique(
            coverage.destination_selectors.begin(),
            coverage.destination_selectors.end()),
        coverage.destination_selectors.end());
    if (coverage.partial() || coverage.destination_selectors.empty() ||
        runtime_recovery_detail::contains_global_destination_selector(
            coverage)) {
        throw DaemonError(
            "Meta UDP/443 messages-first policy requires complete "
            "authoritative activation cleanup coverage before publication");
    }

    const auto local_addresses = local_interface_addresses_from(
        netlink_.dump_interfaces());
    const auto observation_options =
        meta_udp443_observation_options(ipv6_enabled);
    const auto observation =
        conntrack_manager_.observe_forwarded_destination_flows(
            coverage.destination_selectors,
            local_addresses,
            owned_mask,
            observation_options,
            {},
            coverage.destination_selectors,
            {});
    const auto candidates = select_meta_udp_443_cleanup_candidates(
        observation,
        cleanup_owned_marks,
        owned_mask,
        selection.allow_unmarked_cleanup &&
            forwarded_scope_allows_unmarked_cleanup);
    if (!candidates.complete) {
        throw DaemonError(
            "Meta UDP/443 messages-first policy requires a complete exact "
            "conntrack activation snapshot before publication");
    }

    return MetaUdp443ActivationPlan{
        selection.fwmark,
        owned_mask,
        std::move(cleanup_owned_marks),
        std::move(coverage.destination_selectors),
        ipv6_enabled,
        selection.allow_unmarked_cleanup &&
            forwarded_scope_allows_unmarked_cleanup,
        std::move(candidates.flows)};
}

void Daemon::report_meta_udp443_degraded(
    const std::string& detail) noexcept {
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
    const auto generation_is_current = [this,
                                        expected_runtime_generation,
                                        cleanup_epoch]() {
        return meta_udp443_cleanup_authority_matches(
            expected_runtime_generation,
            runtime_generation_.load(std::memory_order_acquire),
            cleanup_epoch,
            meta_udp443_cleanup_epoch_.load(
                std::memory_order_acquire));
    };
    if (!generation_is_current()) {
        if (pending_meta_udp443_cleanup_.has_value() &&
            pending_meta_udp443_cleanup_->schedule_serial ==
                schedule_serial) {
            pending_meta_udp443_cleanup_.reset();
        }
        return;
    }
    MetaUdp443ActivationPlan plan;
    try {
        if (!pending_meta_udp443_cleanup_.has_value() ||
            pending_meta_udp443_cleanup_->schedule_serial !=
                schedule_serial) {
            return;
        }
        plan = pending_meta_udp443_cleanup_->plan;
    } catch (...) {
        // The durable event-loop-owned plan remains intact. A later periodic
        // health tick can retry after transient allocation pressure clears.
        report_meta_udp443_degraded(
            "could not admit the bounded exact-cleanup plan to the worker");
        if (pending_meta_udp443_cleanup_.has_value() &&
            pending_meta_udp443_cleanup_->schedule_serial ==
                schedule_serial) {
            pending_meta_udp443_cleanup_->worker_inflight = false;
        }
        return;
    }
    bool queued = false;
    try {
        queued = blocking_executor_.try_post(
        "meta-udp443-exact-cleanup",
        [this,
         plan = std::move(plan),
         expected_runtime_generation,
         cleanup_epoch,
         attempt,
         schedule_serial]() mutable {
            struct CompletionAdmissionFailureGuard {
                std::atomic<std::uint64_t>& failed_serial;
                std::uint64_t schedule_serial;
                bool armed{true};

                ~CompletionAdmissionFailureGuard() noexcept {
                    if (armed) {
                        publish_newest_meta_udp443_failed_completion_serial(
                            failed_serial, schedule_serial);
                    }
                }
            } completion_admission_guard{
                meta_udp443_cleanup_completion_admission_failed_serial_,
                schedule_serial};
            ConntrackExactFlowCleanupSummary cleanup;
            OwnedForwardUdpRejectState before =
                OwnedForwardUdpRejectState::unknown;
            OwnedForwardUdpRejectState after =
                OwnedForwardUdpRejectState::unknown;
            bool fastnat_before = false;
            bool fastnat_after = false;
            std::string worker_failure;
            const auto still_current = [this,
                                        expected_runtime_generation,
                                        cleanup_epoch]() {
                return meta_udp443_cleanup_authority_matches(
                    expected_runtime_generation,
                    runtime_generation_.load(std::memory_order_acquire),
                    cleanup_epoch,
                    meta_udp443_cleanup_epoch_.load(
                        std::memory_order_acquire));
            };

            try {
                // Apply/stop cancels the epoch before taking this barrier.
                // At most four exact commands can delay that lifecycle path,
                // while no firewall fields race with an in-flight rebuild.
                KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
                if (still_current()) {
                    before = firewall_->inspect_forward_udp_reject_state();
                    fastnat_before =
                        fastnat_is_disabled_or_unavailable();
                }
                if (still_current() && fastnat_before &&
                    before == OwnedForwardUdpRejectState::healthy) {
                    const auto post_publication_local_addresses =
                        local_interface_addresses_from(
                            netlink_.dump_interfaces());
                    const auto post_publication_observation =
                        conntrack_manager_.observe_forwarded_destination_flows(
                            plan.destination_selectors,
                            post_publication_local_addresses,
                            plan.owned_mask,
                            meta_udp443_observation_options(
                                plan.ipv6_enabled),
                            {},
                            plan.destination_selectors,
                            {});
                    const auto post_publication_candidates =
                        select_meta_udp_443_cleanup_candidates(
                            post_publication_observation,
                            plan.cleanup_owned_marks,
                            plan.owned_mask,
                            plan.allow_unmarked_cleanup);
                    if (!post_publication_candidates.complete) {
                        worker_failure =
                            "post-publication exact UDP/443 snapshot is "
                            "incomplete";
                        cleanup.remaining_flows = plan.exact_flows;
                    } else {
                        // A complete fresh snapshot is authoritative for all
                        // currently live exact candidates. Replacing the
                        // retained plan prevents permanent delete failures
                        // plus connection churn from growing it without
                        // bound; the observer itself caps this set at 256.
                        plan.exact_flows =
                            post_publication_candidates.flows;
                        cleanup = conntrack_manager_.
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
                    cleanup.remaining_flows = plan.exact_flows;
                    cleanup.generation_changed = !still_current();
                }
                if (still_current()) {
                    after = firewall_->inspect_forward_udp_reject_state();
                    fastnat_after =
                        fastnat_is_disabled_or_unavailable();
                }
            } catch (const std::exception& error) {
                worker_failure = error.what();
                cleanup.remaining_flows = plan.exact_flows;
            } catch (...) {
                worker_failure = "unknown exact cleanup worker failure";
                cleanup.remaining_flows = plan.exact_flows;
            }

            bool posted = false;
            try {
                posted = post_control_task(
                [this,
                 plan = std::move(plan),
                 cleanup = std::move(cleanup),
                 worker_failure = std::move(worker_failure),
                 before,
                 after,
                 fastnat_before,
                 fastnat_after,
                 expected_runtime_generation,
                 cleanup_epoch,
                 attempt,
                 schedule_serial]() mutable {
                    if (!pending_meta_udp443_cleanup_.has_value() ||
                        pending_meta_udp443_cleanup_->schedule_serial !=
                            schedule_serial) {
                        return;
                    }
                    pending_meta_udp443_cleanup_->worker_inflight = false;
                    std::uint64_t failed_serial = schedule_serial;
                    (void)meta_udp443_cleanup_completion_admission_failed_serial_
                        .compare_exchange_strong(
                            failed_serial,
                            0U,
                            std::memory_order_acq_rel,
                            std::memory_order_acquire);
                    if (!meta_udp443_cleanup_authority_matches(
                            expected_runtime_generation,
                            runtime_generation_.load(
                                std::memory_order_acquire),
                            cleanup_epoch,
                            meta_udp443_cleanup_epoch_.load(
                                std::memory_order_acquire)) ||
                        cleanup.generation_changed) {
                        pending_meta_udp443_cleanup_.reset();
                        return;
                    }
                    if (!worker_failure.empty()) {
                        report_meta_udp443_degraded(
                            "exact activation cleanup failed: " +
                            worker_failure);
                        plan.exact_flows =
                            std::move(cleanup.remaining_flows);
                        schedule_meta_udp443_activation_cleanup_retry(
                            std::move(plan),
                            expected_runtime_generation,
                            cleanup_epoch,
                            attempt + 1U);
                        return;
                    }
                    if (!fastnat_before || !fastnat_after ||
                        before != OwnedForwardUdpRejectState::healthy ||
                        after != OwnedForwardUdpRejectState::healthy) {
                        report_meta_udp443_degraded(
                            !fastnat_before || !fastnat_after
                                ? "FastNAT is no longer verified disabled"
                                : "the owned first FORWARD hook or exact rule "
                                  "contract changed during activation");
                        plan.exact_flows =
                            std::move(cleanup.remaining_flows);
                        if (!fastnat_before || !fastnat_after) {
                            // A firewall rebuild cannot make FastNAT traverse
                            // FORWARD and would cancel this durable exact plan.
                            // Retain it until init/firmware restores FastNAT
                            // off, then retry under the same generation fence.
                            schedule_meta_udp443_activation_cleanup_retry(
                                std::move(plan),
                                expected_runtime_generation,
                                cleanup_epoch,
                                attempt + 1U);
                        } else {
                            schedule_meta_udp443_activation_cleanup_retry(
                                std::move(plan),
                                expected_runtime_generation,
                                cleanup_epoch,
                                attempt + 1U);
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
                                "Meta/WhatsApp messages-first policy retired "
                                "{} exact pre-existing UDP/443 flow(s)",
                                cleanup.attempted);
                        }
                        return;
                    }

                    plan.exact_flows =
                        std::move(cleanup.remaining_flows);
                    const std::size_t unavailable_attempts =
                        cleanup.command_unavailable ? 1U : 0U;
                    const bool made_progress =
                        cleanup.attempted >
                        cleanup.failed + unavailable_attempts;
                    const bool clean_batch_continuation =
                        cleanup.batch_limit_reached &&
                        cleanup.failed == 0U &&
                        !cleanup.command_unavailable &&
                        !cleanup.generation_changed && made_progress;
                    if (!clean_batch_continuation) {
                        report_meta_udp443_degraded(
                            cleanup.command_unavailable
                                ? "the conntrack utility became unavailable"
                                : (cleanup.budget_exhausted
                                       ? "the bounded exact cleanup time "
                                         "budget was exhausted"
                                       : "one or more exact UDP/443 tuples "
                                         "could not be retired"));
                    }
                    schedule_meta_udp443_activation_cleanup_retry(
                        std::move(plan),
                        expected_runtime_generation,
                        cleanup_epoch,
                        made_progress ? 0U : attempt + 1U);
                },
                    "meta-udp443-exact-cleanup-complete");
            } catch (...) {
                posted = false;
            }
            if (posted) {
                completion_admission_guard.armed = false;
            }
            if (!posted) {
                Logger::instance().info(
                    "Meta UDP/443 cleanup completion was not admitted; the "
                    "durable bounded plan remains pending for retry");
            }
        });
    } catch (const std::exception& error) {
        (void)error;
        report_meta_udp443_degraded(
            "could not queue exact cleanup");
    } catch (...) {
        report_meta_udp443_degraded(
            "could not queue exact cleanup");
    }
    if (!queued) {
        report_meta_udp443_degraded(
            "the blocking executor queue is full");
        if (pending_meta_udp443_cleanup_.has_value() &&
            pending_meta_udp443_cleanup_->schedule_serial ==
                schedule_serial) {
            pending_meta_udp443_cleanup_->worker_inflight = false;
            const auto& pending = *pending_meta_udp443_cleanup_;
            schedule_meta_udp443_activation_cleanup_retry(
                pending.plan,
                expected_runtime_generation,
                cleanup_epoch,
                attempt + 1U);
        }
    }
}

FirewallApplyMode Daemon::runtime_refresh_firewall_mode() const {
    const auto daemon_config = config_.daemon.value_or(DaemonConfig{});
    return daemon_config.reuse_static_sets_on_runtime_refresh.value_or(true)
        ? FirewallApplyMode::RulesOnly
        : FirewallApplyMode::PreserveSets;
}

void Daemon::apply_firewall(
    FirewallApplyMode mode,
    std::shared_ptr<const ListCacheGenerationSnapshot>
        list_cache_snapshot,
    bool force_clear_dynamic_sets) {
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
            config_,
            outbound_marks_,
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
    const auto route_config = config_.route.value_or(RouteConfig{});
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
            return !target.process_clients;
        });
    meta_activation = prepare_meta_udp443_activation_or_throw(
        staged.rule_states,
        staged.list_content_state,
        !has_explicit_inbound_scope && !has_native_vpn_bypass);

    try {
        commit_runtime_firewall(*firewall_, staged);
    } catch (const FirewallRulesOnlyError& error) {
        // The backend's own preflight (a reused set missing, a schema that
        // drifted, dispatchers that need repair) fires before it mutates
        // anything, so the kernel is exactly as it was. Restage the full
        // transaction and run the Meta preflight again over it: the content
        // state is now freshly read rather than carried over.
        if (staged.mode != FirewallApplyMode::RulesOnly) throw;
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
        staged = stage_with(effective_mode);
        meta_activation = prepare_meta_udp443_activation_or_throw(
            staged.rule_states,
            staged.list_content_state,
            !has_explicit_inbound_scope && !has_native_vpn_bypass);
        commit_runtime_firewall(*firewall_, staged);
    }
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
            std::nullopt,
            std::nullopt,
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
            config_.outbounds.value_or(std::vector<Outbound>{});
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

        candidate_selections[change.urltest_tag] = change.new_child_tag;

        std::optional<uint32_t> retired_mark;
        // Whether the retired child is itself a selector matters only for the
        // unset default: explicit delete modes already refused nested children
        // at validation, and the default must not exceed what an explicit
        // config may say.
        bool previous_child_is_selector = false;
        if (!change.previous_child_tag.empty() &&
            config_.outbounds.has_value()) {
            for (const auto& outbound : *config_.outbounds) {
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
                outbound_marks_.find(change.previous_child_tag);
            if (old_mark_it != outbound_marks_.end()) {
                retired_mark = old_mark_it->second;
            }
        }

        const auto list_cache_snapshot =
            capture_relevant_list_cache_generation(config_);
        firewall_state_.swap_urltest_selections(candidate_selections);

        const auto mark_permanent_rollback_failure =
            [this](std::string_view) noexcept {
                urltest_after_firewall_gate_.reset();
                try {
                    transition_runtime_or_throw(
                        RuntimeState::broken,
                        "urltest selection rollback failed");
                    publish_runtime_state();
                } catch (...) {
                }
            };

        try {
            reconcile_static_routing(RouteReconcileMode::Strict);
            apply_firewall(
                runtime_refresh_firewall_mode(),
                list_cache_snapshot);
        } catch (const TransientFirewallError& apply_error) {
            // The candidate may have been partially published. Restore the
            // authoritative in-memory cursor first; only the central full
            // reconciler may now prove and release this generation.
            firewall_state_.swap_urltest_selections(candidate_selections);
            defer_urltest_switch_to_firewall_recovery(
                change,
                current_runtime_generation,
                "candidate apply",
                apply_error.what());
            return false;
        } catch (const std::exception& apply_error) {
            // Restore the in-memory cursor before diagnostics or any other
            // fallible work, then restore the corresponding kernel state.
            firewall_state_.swap_urltest_selections(candidate_selections);
            bool rollback_verified = false;
            try {
                reconcile_static_routing(RouteReconcileMode::Strict);
                apply_firewall(
                    runtime_refresh_firewall_mode(),
                    list_cache_snapshot);
                rollback_verified = true;
            } catch (const TransientFirewallError& rollback_error) {
                defer_urltest_switch_to_firewall_recovery(
                    change,
                    current_runtime_generation,
                    "rollback",
                    rollback_error.what());
                return false;
            } catch (const std::exception& rollback_error) {
                mark_permanent_rollback_failure(rollback_error.what());
            } catch (...) {
                mark_permanent_rollback_failure("unknown error");
            }

            try {
                const auto incident =
                    urltest_apply_incidents_.record_failure(
                        change.urltest_tag,
                        /*notify_immediately=*/!rollback_verified);
                log.info(
                    "Routing/firewall did not accept urltest '{}' change to "
                    "'{}': {}. Previous intent '{}' was {}",
                    change.urltest_tag,
                    change.new_child_tag,
                    apply_error.what(),
                    applied_previous,
                    rollback_verified ? "restored" : "left in broken state");
                if (incident.notify) {
                    log.error(
                        "Urltest '{}' could not converge after {} consecutive "
                        "probe rounds; routing requires attention",
                        change.urltest_tag,
                        incident.consecutive_failures);
                }
            } catch (...) {
            }
            // The manager still owns this exact inflight generation and will
            // restore previous_child_tag, clear it, and allow a later retry.
            return false;
        } catch (...) {
            firewall_state_.swap_urltest_selections(candidate_selections);
            bool rollback_verified = false;
            std::string rollback_detail;
            try {
                reconcile_static_routing(RouteReconcileMode::Strict);
                apply_firewall(
                    runtime_refresh_firewall_mode(),
                    list_cache_snapshot);
                rollback_verified = true;
            } catch (const TransientFirewallError& rollback_error) {
                defer_urltest_switch_to_firewall_recovery(
                    change,
                    current_runtime_generation,
                    "rollback after unknown candidate failure",
                    rollback_error.what());
                return false;
            } catch (const std::exception& rollback_error) {
                rollback_detail = rollback_error.what();
                mark_permanent_rollback_failure(rollback_error.what());
            } catch (...) {
                rollback_detail = "unknown rollback error";
                mark_permanent_rollback_failure("unknown error");
            }
            try {
                const auto incident =
                    urltest_apply_incidents_.record_failure(
                        change.urltest_tag,
                        /*notify_immediately=*/!rollback_verified);
                if (incident.notify) {
                    if (rollback_verified) {
                        log.error(
                            "Urltest '{}' candidate apply failed with an "
                            "unknown error; the previous intent was restored",
                            change.urltest_tag);
                    } else {
                        log.error(
                            "Urltest '{}' candidate apply and rollback "
                            "failed permanently: {}",
                            change.urltest_tag,
                            rollback_detail);
                    }
                } else {
                    log.info(
                        "Urltest '{}' candidate apply failed with an unknown "
                        "error; the previous intent was {}",
                        change.urltest_tag,
                        rollback_verified ? "restored" : "left broken");
                }
            } catch (...) {
            }
            return false;
        }

        // The candidate is now the verified kernel and in-memory cursor.
        // Everything below is post-commit follow-up: failures must not make
        // the manager roll back a successfully applied selection.
        try {
            urltest_apply_incidents_.reset(change.urltest_tag);
        } catch (...) {
        }

        if (retired_mark.has_value()) {
            try {
                const uint32_t owned_mask = fwmark_mask_value(
                    config_.fwmark.value_or(FwmarkConfig{}));
                const auto cleanup = conntrack_manager_.delete_mark(
                    *retired_mark, owned_mask);
                if (cleanup == ConntrackCleanupResult::CommandUnavailable) {
                    warn_conntrack_unavailable_once();
                } else if (cleanup == ConntrackCleanupResult::Failed) {
                    log.info(
                        "Failed to remove conntrack entries for retired "
                        "urltest mark {:#x}/{:#x}; a bounded retry is "
                        "scheduled",
                        *retired_mark,
                        owned_mask);
                    // A one-shot failure here used to be final (upstream
                    // f58e4b58 fixed the same hole with its own retry map).
                    // The fork already owns a bounded, generation-fenced
                    // retry for owned-mark cleanup; hand the mark to it
                    // instead of growing a second retry mechanism. A runtime
                    // generation change cancels the retry, which is correct:
                    // the rebuild it implies re-runs cleanup from a fresh
                    // snapshot anyway.
                    OwnedConntrackCleanupSnapshot snapshot;
                    snapshot.runtime_generation =
                        runtime_generation_.load(std::memory_order_acquire);
                    snapshot.owned_mask = owned_mask;
                    snapshot.ipv6_enabled =
                        resolve_ipv6_support(config_).enabled;
                    snapshot.marks.insert(*retired_mark);
                    // The retired child carried live forwarded traffic;
                    // that is what the priority tier is for.
                    snapshot.priority_marks.insert(*retired_mark);
                    schedule_owned_conntrack_cleanup_retry(
                        snapshot, {*retired_mark});
                }
            } catch (...) {
            }
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
    if (!urltest_manager_) {
        urltest_manager_ = std::make_unique<UrltestManager>(
            url_tester_,
            outbound_marks_,
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
        const auto targets =
            collect_interface_probe_targets(config_, outbound_marks_);
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
                                    config_, outbound_marks_);
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
                                    config_.outbounds.value_or(
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
    const auto configured_targets = collect_interface_probe_targets(
        config_, outbound_marks_);
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
                                        config_, outbound_marks_);
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
                                            config_.outbounds.value_or(
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
                                config_, outbound_marks_);
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
                                // changing administrative UP. Reconcile once,
                                // after all per-target observations have been
                                // published.
                                try {
                                    reconcile_static_routing(
                                        RouteReconcileMode::DeferredRepair);
                                } catch (
                                    const RouteInterfaceUnavailableError&
                                        error) {
                                    try {
                                        Logger::instance().verbose(
                                            "Interface-probe route "
                                            "reconciliation is waiting for "
                                            "its interface: {}",
                                            error.what());
                                    } catch (...) {
                                    }
                                } catch (const std::exception& error) {
                                    reconciliation_error = error.what();
                                    try {
                                        Logger::instance().info(
                                            "Interface-probe route "
                                            "reconciliation was deferred: "
                                            "{}",
                                            error.what());
                                    } catch (...) {
                                    }
                                    try {
                                        (void)
                                            refresh_iproute_and_firewall_runtime(
                                                0,
                                                std::nullopt,
                                                std::nullopt,
                                                /*schedule_catalog_refresh=*/
                                                    false);
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

void Daemon::schedule_tunnel_probe() {
    // The interval belongs to the configuration, so the timer cannot simply be
    // armed with it: both the interval and the switch may change while the
    // daemon runs. Ticking once a minute and letting the pass decide whether
    // it is due costs one resolve per minute and lets either take effect
    // without a restart.
    constexpr auto kTick = std::chrono::minutes(1);

    scheduler_->schedule_repeating(
        kTick,
        [this]() {
            const auto resolved = resolve_tunnel_probe_setup(config_);
            if (!resolved.setup.has_value()) return;

            const auto now = std::chrono::steady_clock::now();
            const auto due = std::chrono::milliseconds(
                static_cast<std::int64_t>(resolved.setup->interval_ms));
            if (tunnel_probe_last_pass_.has_value() &&
                now - *tunnel_probe_last_pass_ < due) {
                return;
            }

            // A pass is minutes of real requests and the timer does not wait
            // for it. Without this a slow pass would be joined by the next.
            if (tunnel_probe_running_.exchange(true)) return;
            tunnel_probe_last_pass_ = now;

            const bool posted = blocking_executor_.try_post(
                "tunnel-probe",
                [this, config = config_]() { run_tunnel_probe_pass(config); });
            if (!posted) tunnel_probe_running_.store(false);
        },
        "tunnel-probe");
}

void Daemon::run_tunnel_probe_pass(const Config& config) noexcept {
    auto& log = Logger::instance();
    try {
        if (!tunnel_probe_task_) {
            TunnelProbeTask::Io io;
            io.read_file = [](const std::string& path) {
                return read_whole_file(path);
            };
            io.write_file = [](const std::string& path,
                               const std::string& contents) {
                std::ofstream out(path, std::ios::binary | std::ios::trunc);
                if (!out.is_open()) return false;
                out << contents;
                out.flush();
                return out.good();
            };
            io.run_probe = [](const DifferentialProbeRequest& request) {
                auto transport = default_http_transport();
                return run_differential_probe(*transport, request);
            };
            io.on_list_changed = [this](const TunnelProbeSetup&) {
                // A list file is read when the firewall is applied, so new
                // hosts do nothing until one happens. This runs on a worker
                // thread, so hop back to the control loop to ask for it.
                post_control_task(
                    [this]() {
                        schedule_netfilter_runtime_refresh(
                            NetfilterRefreshReason::full);
                    },
                    "tunnel-probe-list-refresh");
            };
            tunnel_probe_task_ =
                std::make_unique<TunnelProbeTask>(std::move(io));
        }

        const auto outcome = tunnel_probe_task_->run(config);
        // A pass that refused because the automation is off is the ordinary
        // case and says nothing worth a line; everything else does.
        if (outcome.refusal != TunnelProbeRefusal::disabled) {
            log.info("Tunnel probe: {}", TunnelProbeTask::describe(outcome));
        }
    } catch (const std::exception& error) {
        try {
            log.error("Tunnel probe pass failed: {}", error.what());
        } catch (...) {
        }
    } catch (...) {
    }
    tunnel_probe_running_.store(false);
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
                    routing_runtime_active(),
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
#ifdef WITH_API
                request_remote_access_reconcile_from_control(
                    "startup firewall recovery");
#endif
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
                if (!reload || !routing_runtime_active() ||
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
    const bool runtime_active_snapshot = routing_runtime_active();
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
                        routing_runtime_active() &&
                        config_has_native_vpn_catalog_policy(config_);
                    if (rerun_is_valid) {
                        schedule_internal_vpn_catalog_refresh();
                    }

                    if (!routing_runtime_active() ||
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
            routing_runtime_active() &&
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
                if (!routing_runtime_active() || !config_.dns.has_value() ||
                    !dns_config_uses_keenetic_server(*config_.dns)) {
                    return;
                }
                (void)keenetic_dns_refresh_coordinator_.request(
                    runtime_generation_.load(std::memory_order_acquire));
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
    idle_stall_preventive_owned_mark_.reset();
    idle_stall_packaged_whatsapp_only_observation_ = false;
    idle_stall_coverage_generation_.fetch_add(
        1U, std::memory_order_acq_rel);
}

void Daemon::schedule_idle_stall_observer_after(
    std::chrono::seconds delay) noexcept {
    try {
        if (!scheduler_ ||
            !idle_stall_observer_enabled_.load(
                std::memory_order_acquire) ||
            !routing_runtime_active()) {
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
        idle_stall_preventive_owned_mark_.reset();
        idle_stall_packaged_whatsapp_only_observation_ = false;
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
        idle_stall_preventive_owned_mark_.reset();
        idle_stall_packaged_whatsapp_only_observation_ = false;
        idle_stall_coverage_generation_.fetch_add(
            1U, std::memory_order_acq_rel);
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
                    -1});
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
            if (pending.task_id < 0 &&
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

bool Daemon::drain_exact_tcp_reset_cleanups_before_generation_change()
    noexcept {
    std::size_t index = 0U;
    while (index < pending_exact_tcp_reset_cleanups_.size()) {
        bool removed = false;
        try {
            removed = firewall_ && firewall_->remove_exact_tcp_reset(
                pending_exact_tcp_reset_cleanups_[index].rule);
        } catch (...) {
            removed = false;
        }
        if (!removed) {
            ++index;
            continue;
        }
        const int task_id =
            pending_exact_tcp_reset_cleanups_[index].task_id;
        pending_exact_tcp_reset_cleanups_.erase(
            pending_exact_tcp_reset_cleanups_.begin() +
            static_cast<std::ptrdiff_t>(index));
        if (task_id >= 0 && scheduler_) {
            try {
                scheduler_->cancel(task_id);
            } catch (...) {
            }
        }
    }
    return pending_exact_tcp_reset_cleanups_.empty();
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

    bool removed = false;
    try {
        removed = firewall_ && firewall_->remove_exact_tcp_reset(rule);
    } catch (...) {
        removed = false;
    }
    if (removed) {
        pending_exact_tcp_reset_cleanups_.erase(pending);
        return;
    }

    const std::size_t next_attempt =
        attempt < EXPERIMENTAL_TCP_RESET_CLEANUP_RETRY_DELAYS.size()
        ? attempt + 1U
        : EXPERIMENTAL_TCP_RESET_CLEANUP_RETRY_DELAYS.size() + 1U;
    if (attempt == EXPERIMENTAL_TCP_RESET_CLEANUP_RETRY_DELAYS.size()) {
        try {
            Logger::instance().error(
                "Exact WhatsApp TCP reset rule cleanup did not verify after "
                "bounded retries; a quiet generation-fenced maintenance "
                "retry remains armed until apply/stop cleanup");
        } catch (...) {
        }
    }
    (void)schedule_exact_tcp_reset_cleanup(
        rule, expected_runtime_generation, next_attempt);
}

void Daemon::reset_idle_stall_observer(
    bool schedule_if_eligible) noexcept {
    cancel_idle_stall_observer();
    if (!schedule_if_eligible || !routing_runtime_active() ||
        !idle_stall_observer_requested(config_)) {
        return;
    }
    idle_stall_observer_enabled_.store(true, std::memory_order_release);
    // The first short observation only establishes whether relevant flows
    // exist. Subsequent empty scans back off to the 30-second quiet interval.
    schedule_idle_stall_observer_after(IDLE_STALL_ACTIVE_SCAN_INTERVAL);
}

void Daemon::run_idle_stall_observer() noexcept {
    try {
        if (!routing_runtime_active() ||
            !idle_stall_observer_enabled_.load(
                std::memory_order_acquire) ||
            !idle_stall_observer_requested(config_)) {
            cancel_idle_stall_observer();
            return;
        }
        resume_exact_tcp_reset_cleanups();

        std::set<std::string> configured_list_names;
        if (reconnect_unmarked_flows_on_routing_change_enabled(config_)) {
            configured_list_names =
                reconnect_owned_flows_on_routing_change_list_names(config_);
        }
        const bool preventive_guard_available =
            preventive_whatsapp_media_guard_available(
                firewall_->backend(),
                opts_.udp_call_affinity_ipset_available);
        const auto preventive_guard_lists =
            preventive_whatsapp_media_guard_list_names(config_);
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
            whatsapp_call_affinity_list_names(config_);
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
                trusted_whatsapp_marks.clear();
                whatsapp_destination_selectors.clear();
                udp_call_affinity_detector_.reset();
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
        const bool idle_observation_scope_changed =
            destination_selectors != idle_stall_destination_selectors_ ||
            whatsapp_destination_selectors !=
                udp_call_affinity_destination_selectors_ ||
            preventive_owned_mark != idle_stall_preventive_owned_mark_ ||
            packaged_whatsapp_only_observation !=
                idle_stall_packaged_whatsapp_only_observation_;
        if (idle_observation_scope_changed) {
            idle_stall_detector_.reset();
            udp_call_affinity_detector_.reset();
            idle_stall_destination_selectors_ = destination_selectors;
            udp_call_affinity_destination_selectors_ =
                whatsapp_destination_selectors;
            idle_stall_preventive_owned_mark_ = preventive_owned_mark;
            idle_stall_packaged_whatsapp_only_observation_ =
                packaged_whatsapp_only_observation;
            idle_stall_coverage_generation_.fetch_add(
                1U, std::memory_order_acq_rel);
        }
        const auto affinity_snapshot_time =
            UdpCallAffinityDetector::Clock::now();
        const auto retained_affinity_sources =
            call_affinity_targets.empty()
            ? std::vector<std::string>{}
            : udp_call_affinity_detector_.retained_guard_sources(
                  affinity_snapshot_time);
        const auto runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const auto coverage_generation =
            idle_stall_coverage_generation_.load(
                std::memory_order_acquire);
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
             trusted_whatsapp_marks,
             preventive_whatsapp_authorized,
             packaged_whatsapp_only_observation,
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
               routing_runtime_active() &&
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
                // routing_runtime_active() flag is checked before dispatch and
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
                        routing_runtime_active() &&
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
                            bool confirmation_accepted = false;
                            try {
                                confirmation_accepted =
                                    udp_call_affinity_detector_.
                                        confirm_installed(
                                            outcome.decision,
                                            completed_at);
                            } catch (...) {
                                // Kernel publication may have succeeded, but
                                // an in-memory authority update that cannot be
                                // represented safely must fail closed.
                                udp_call_affinity_detector_.reset();
                            }
                            if (confirmation_accepted) {
                                if (outcome.decision.refresh_only) {
                                    ++refreshed;
                                } else {
                                    ++installed;
                                }
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

    // A classifier publication completion can land on the control loop while
    // the blocking conntrack snapshot is in progress. Recompute exact guard
    // authority after observe() so that a newly confirmed call peer is visible
    // to the final live revalidation, while an expired/reset peer is not.
    auto retained_affinity_peers = call_affinity_targets.empty()
        ? std::vector<UdpCallAffinityGuardPeer>{}
        : udp_call_affinity_detector_.retained_guard_peers(
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
                    idle_stall_observer_inflight_.store(
                        false, std::memory_order_release);
                    const auto generation_is_current = [this,
                                                        expected_runtime_generation,
                                                        expected_coverage_generation]() {
                        return running_.load(std::memory_order_acquire) &&
                               routing_runtime_active() &&
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
                    std::size_t preventive_resets = 0U;
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
                    const auto retire_exact_tcp_reset =
                        [this, expected_runtime_generation](
                            const FirewallExactTcpResetRule& rule) noexcept {
                            bool removed = false;
                            try {
                                removed = firewall_ &&
                                    firewall_->remove_exact_tcp_reset(rule);
                            } catch (...) {
                                removed = false;
                            }
                            if (!removed) {
                                (void)schedule_exact_tcp_reset_cleanup(
                                    rule,
                                    expected_runtime_generation,
                                    /*attempt=*/1U);
                            } else {
                                forget_exact_tcp_reset_cleanup(rule);
                            }
                            return removed;
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
                            std::optional<FirewallExactTcpResetRule>
                                installed_reset_rule;
                            if (pending.decision.reason ==
                                IdleStallDecisionReason::
                                    idle_packaged_whatsapp_tcp_reset_rotation) {
                                if (pending.flow.family !=
                                        ConntrackFlowFamily::Ipv4 ||
                                    pending.flow.protocol !=
                                        ConntrackFlowProtocol::Tcp ||
                                    pending.flow.mark == 0U || !scheduler_) {
                                    ++failed;
                                    acknowledge(pending.decision, false);
                                    continue;
                                }
                                FirewallExactTcpResetRule reset_rule{
                                    pending.flow.source,
                                    pending.flow.destination,
                                    pending.flow.source_port,
                                    pending.flow.destination_port,
                                    pending.flow.mark};
                                FirewallExactTcpResetResult install_result =
                                    FirewallExactTcpResetResult::failed;
                                try {
                                    install_result = firewall_->
                                        install_exact_tcp_reset(reset_rule);
                                } catch (...) {
                                    install_result =
                                        FirewallExactTcpResetResult::failed;
                                }
                                if (install_result !=
                                    FirewallExactTcpResetResult::installed) {
                                    // A backend may have committed the exact
                                    // rule and then lost its read-only proof.
                                    // Never leave that uncertain publication
                                    // without both backend rollback and this
                                    // independent best-effort cleanup attempt.
                                    (void)retire_exact_tcp_reset(reset_rule);
                                    ++failed;
                                    acknowledge(pending.decision, false);
                                    continue;
                                }
                                try {
                                    if (!schedule_exact_tcp_reset_cleanup(
                                            reset_rule,
                                            expected_runtime_generation,
                                            /*attempt=*/0U)) {
                                        throw std::runtime_error(
                                            "could not own exact TCP reset "
                                            "cleanup timer");
                                    }
                                    installed_reset_rule =
                                        std::move(reset_rule);
                                } catch (...) {
                                    (void)retire_exact_tcp_reset(reset_rule);
                                    ++failed;
                                    acknowledge(pending.decision, false);
                                    continue;
                                }
                            }
                            try {
                                result = conntrack_manager_.
                                    delete_exact_forwarded_flow(
                                        pending.flow, owned_mask);
                            } catch (...) {
                                if (installed_reset_rule.has_value()) {
                                    (void)retire_exact_tcp_reset(
                                        *installed_reset_rule);
                                }
                                ++failed;
                                acknowledge(pending.decision, false);
                                continue;
                            }
                            if (result ==
                                ConntrackCleanupResult::Succeeded) {
                                ++succeeded;
                                if (installed_reset_rule.has_value()) {
                                    ++preventive_resets;
                                }
                                acknowledge(pending.decision, true);
                            } else if (result ==
                                       ConntrackCleanupResult::
                                           CommandUnavailable) {
                                if (installed_reset_rule.has_value()) {
                                    (void)retire_exact_tcp_reset(
                                        *installed_reset_rule);
                                }
                                command_unavailable = true;
                                acknowledge(pending.decision, false);
                                break;
                            } else {
                                if (installed_reset_rule.has_value()) {
                                    (void)retire_exact_tcp_reset(
                                        *installed_reset_rule);
                                }
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
                        !routing_runtime_active() ||
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
    const bool previous_runtime_active = routing_runtime_active();
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
    const auto firewall_apply_policy = firewall_config_apply_policy(
        firewall_->backend(), config_, prepared.config);
    if (firewall_apply_policy.force_clear_dynamic_sets) {
        Logger::instance().warn(
            "iptables IPSet capacity changed; recreating keen-pbr sets and "
            "clearing dnsmasq-learned entries");
    }
    // Repair and retire any flows from a previously observed SNAT loss before
    // publishing `applying` or reassigning numerical marks. A transient
    // firmware race here must reject the save while the old runtime remains
    // active, not falsely publish a broken state.
    complete_pending_snat_recovery_before_generation_change();
    if (!drain_exact_tcp_reset_cleanups_before_generation_change()) {
        resume_exact_tcp_reset_cleanups();
        throw TransientFirewallError(
            "exact TCP reset cleanup is incomplete before configuration "
            "generation change");
    }

    transition_runtime_or_throw(RuntimeState::applying, "configuration apply started");
    publish_runtime_state();

    try {
    cancel_idle_stall_observer();
    cancel_owned_conntrack_cleanup_retry();
    const auto applying_runtime_generation =
        runtime_generation_.fetch_add(1, std::memory_order_acq_rel) + 1U;
    resolver_after_firewall_gate_.reset();
    urltest_after_firewall_gate_.reset();
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
        [this, &list_cache_snapshot, &firewall_apply_policy]() {
            // apply_firewall rebuilds the complete pending transaction on
            // every call. A retry therefore never reuses the one-shot backend
            // state from the failed attempt.
            apply_firewall(
                firewall_apply_policy.mode,
                list_cache_snapshot,
                firewall_apply_policy.force_clear_dynamic_sets);
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
                "reload",
                /*rebuild_snapshot=*/false,
                /*inactive_activation_authority=*/
                    !previous_runtime_active)) {
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
    runtime_state_store_.set_routing_runtime_active(true);
    schedule_internal_vpn_catalog_refresh_if_needed(
        internal_vpn_lkg_update.state,
        internal_vpn_service_lkg_update.state);
    transition_runtime_or_throw(RuntimeState::running, "configuration apply complete");
#ifdef WITH_API
    request_remote_access_reconcile_from_control("configuration apply");
#endif
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
        runtime_state_store_.set_routing_runtime_active(false);
        cancel_idle_stall_observer();
        cancel_meta_udp443_activation_cleanup();
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
