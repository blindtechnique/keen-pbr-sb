#include "daemon.hpp"
#include "api_runtime_lifecycle.hpp"
#include "keenetic_dns_firewall_lifecycle_policy.hpp"

#include "../keenetic/ndms_native_writer_lease.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <ctime>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <future>
#include <grp.h>
#include <iterator>
#include <limits>
#include <map>
#include <new>
#include <nlohmann/json.hpp>
#include <ostream>
#include <poll.h>
#include <signal.h>
#include <set>
#include <sstream>
#include <string_view>
#include <streambuf>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <type_traits>
#include <unistd.h>

#include <keen-pbr/version.hpp>

#include "../cache/cache_manager.hpp"
#include "../cmd/test_routing.hpp"
#include "../dns/dns_router.hpp"
#include "../dns/dnsmasq_access_policy.hpp"
#include "../dns/dnsmasq_gen.hpp"
#include "../firewall/firewall.hpp"
#include "../firewall/firewall_runtime.hpp"
#include "../firewall/firewall_verifier.hpp"
#include "../health/routing_health_checker.hpp"
#include "../ipc/control_protocol.hpp"
#include "../ipc/bounded_socket_writer.hpp"
#include "../keenetic/internal_vpn_server_resolver.hpp"
#include "../keenetic/internal_vpn_service_resolver.hpp"
#include "../keenetic/internal_vpn_runtime_generation.hpp"
#include "../keenetic/ndms_catalog_cache.hpp"
#include "../keenetic/ndms_native_interface_read_production.hpp"
#include "../keenetic/ndms_native_ownership_reconcile.hpp"
#include "../keenetic/ndms_vpn_server_service_cache.hpp"
#include "../lists/list_streamer.hpp"
#include "../log/logger.hpp"
#include "../routing/urltest_manager.hpp"
#include "../runtime/meta_udp_443_policy.hpp"
#include "../util/daemon_signals.hpp"
#include "../util/ipv6_support.hpp"
#include "../util/time_utils.hpp"
#include "../dns/dns_probe_server.hpp" // IWYU pragma: keep
#include "runtime_firewall_generation_input.hpp"
#include "runtime_firewall_lifecycle_resolver_attempt.hpp"
#include "runtime_firewall_core_publication.hpp"
#include "runtime_firewall_conntrack_tail_plan.hpp"
#include "runtime_firewall_meta_tail_plan.hpp"
#include "runtime_firewall_operation_owner.hpp"
#include "runtime_firewall_publication_tail_progress.hpp"
#include "runtime_firewall_resolver_tail_plan.hpp"
#include "runtime_firewall_tail_effect_dispatch.hpp"
#include "runtime_firewall_terminal_tail_plan.hpp"
#include "runtime_resolver_publication.hpp"
#include "runtime_cold_boot_publication.hpp"
#include "runtime_cold_boot_terminal_policy.hpp"
#include "owned_conntrack_cleanup_operation.hpp"
#include "runtime_route_health_plan.hpp"
#include "runtime_urltest_terminal_orchestrator.hpp"
#include "scheduler.hpp"

#ifdef WITH_API
#include "../api/handlers.hpp"
#include "../api/handler_remote_access.hpp" // IWYU pragma: keep
#include "../api/server.hpp"
#include "../api/sse_broadcaster.hpp"
#include "../api/status_stream.hpp"
#include "../connections/conntrack_event_monitor.hpp"
#endif

namespace keen_pbr3 {

namespace {

constexpr auto OWNED_SNAT_HEALTH_INTERVAL =
    std::chrono::seconds{60};
#ifdef WITH_API
constexpr auto REMOTE_ACCESS_RECOVERY_WATCHDOG_INTERVAL =
    std::chrono::seconds{60};
#endif
constexpr auto INTERFACE_MONITOR_RECONNECT_RETRY_DELAY = std::chrono::seconds{5};
constexpr std::size_t kResolverStreamChunkBytes = 16U * 1024U;
constexpr std::size_t kMaxPendingControlClients = 64U;
constexpr std::size_t kMaxControlRequestBytes = 4U * 1024U;
constexpr auto kControlIngressTimeout = std::chrono::seconds{1};
constexpr auto kControlResponseSendTimeout =
    std::chrono::seconds{1};
constexpr std::array<std::chrono::seconds, 6>
    RUNTIME_FIREWALL_RETRY_DELAYS{
        std::chrono::seconds{1},
        std::chrono::seconds{2},
        std::chrono::seconds{4},
        std::chrono::seconds{8},
        std::chrono::seconds{16},
        std::chrono::seconds{32},
    };
#ifndef KEEN_PBR_CONTROL_SOCKET
#define KEEN_PBR_CONTROL_SOCKET "/run/keen-pbr/control.sock"
#endif

void send_all(int fd, const char* data, std::size_t size) {
    std::size_t written = 0;
    while (written < size) {
        const ssize_t count =
            ::send(fd, data + written, size - written, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            throw ipc::ControlProtocolError(
                "control socket write failed: " +
                std::string(strerror(errno)));
        }
        written += static_cast<std::size_t>(count);
    }
}

void send_control_response_and_close(
    int fd,
    const nlohmann::json& response) noexcept {
    try {
        const auto frame = ipc::encode_message(response);
        ipc::send_all_bounded_nonblocking(
            fd,
            frame.data(),
            frame.size(),
            std::chrono::duration_cast<std::chrono::milliseconds>(
                kControlResponseSendTimeout));
    } catch (const std::exception& error) {
        try {
            Logger::instance().warn(
                "control response failed: {}", error.what());
        } catch (...) {
        }
    }
    ::close(fd);
}

class UniqueSocketFd {
public:
    explicit UniqueSocketFd(int fd) noexcept : fd_(fd) {}

    ~UniqueSocketFd() noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    UniqueSocketFd(const UniqueSocketFd&) = delete;
    UniqueSocketFd& operator=(const UniqueSocketFd&) = delete;

    int get() const noexcept { return fd_; }

private:
    int fd_{-1};
};

class SocketStreamBuffer final : public std::streambuf {
public:
    explicit SocketStreamBuffer(int fd) : fd_(fd) {
        setp(buffer_.data(), buffer_.data() + buffer_.size());
    }

    ~SocketStreamBuffer() override { (void)sync(); }

protected:
    int overflow(int character) override {
        if (flush_buffer() != 0) return traits_type::eof();
        if (character != traits_type::eof()) {
            *pptr() = static_cast<char>(character);
            pbump(1);
        }
        return character;
    }

    std::streamsize xsputn(const char* data,
                           std::streamsize size) override {
        std::streamsize written = 0;
        while (written < size) {
            if (pptr() == epptr() && flush_buffer() != 0) break;
            const auto capacity =
                static_cast<std::streamsize>(epptr() - pptr());
            const auto chunk = std::min(capacity, size - written);
            std::memcpy(
                pptr(), data + written, static_cast<std::size_t>(chunk));
            pbump(static_cast<int>(chunk));
            written += chunk;
        }
        return written;
    }

    int sync() override { return flush_buffer(); }

private:
    int flush_buffer() {
        const auto size =
            static_cast<std::size_t>(pptr() - pbase());
        if (size == 0) return 0;
        try {
            const std::uint32_t length =
                htonl(static_cast<std::uint32_t>(size));
            send_all(fd_,
                     reinterpret_cast<const char*>(&length),
                     sizeof(length));
            send_all(fd_, pbase(), size);
        } catch (...) {
            return -1;
        }
        setp(buffer_.data(), buffer_.data() + buffer_.size());
        return 0;
    }

    int fd_;
    std::array<char, kResolverStreamChunkBytes> buffer_{};
};

std::string resolver_runtime_reason(
    const RuntimeStateSnapshot& snapshot) {
    switch (snapshot.runtime_state) {
    case RuntimeState::starting:
        return "runtime_starting";
    case RuntimeState::stopped:
        return "runtime_stopped";
    case RuntimeState::broken:
        return "runtime_broken";
    case RuntimeState::shutting_down:
        return "runtime_shutting_down";
    default:
        return "daemon_error";
    }
}

bool peer_has_group(const ucred& peer, gid_t group_id) {
    if (peer.gid == group_id) return true;

    std::ifstream status(
        "/proc/" + std::to_string(peer.pid) + "/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("Groups:", 0) != 0) continue;
        std::istringstream groups(line.substr(7));
        unsigned long group = 0;
        while (groups >> group) {
            if (group == static_cast<unsigned long>(group_id)) {
                return true;
            }
        }
        break;
    }
    return false;
}

std::int64_t steady_duration_ms(std::chrono::steady_clock::time_point started_at) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at).count();
}

nlohmann::json list_refresh_task_json(
    const ListRefreshTaskSnapshot& task) {
    nlohmann::json result{
        {"task_id", task.id},
        {"state", list_refresh_task_status_name(task.status)},
        {"created_at", task.created_at},
        {"updated_at", task.updated_at},
        {"started_at", task.started_at},
        {"finished_at", task.finished_at},
        {"total", task.total},
        {"completed", task.completed},
        {"current", task.current},
        {"cancel_requested", task.cancel_requested},
        {"revision", task.revision},
        {"refreshed_lists", nlohmann::json::array()},
        {"changed_lists", nlohmann::json::array()},
        {"failed_lists", nlohmann::json::array()},
        {"reloaded", false},
        {"error", ""},
    };
    if (task.terminal_result) {
        const auto& terminal = *task.terminal_result;
        result["refreshed_lists"] =
            terminal.refresh_result.refreshed_lists;
        result["changed_lists"] =
            terminal.refresh_result.changed_lists;
        result["failed_lists"] =
            terminal.refresh_result.failed_lists;
        result["reloaded"] = terminal.reloaded;
        result["error"] = terminal.error;
    }
    return result;
}

} // namespace

struct RuntimeFirewallStartRollbackResult;
struct DaemonUrltestSelectionTransaction;
struct DaemonKeeneticDnsRefreshTransaction;

struct DaemonColdBootTransaction final {
    PreparedNativeVpnCatalogPtr prepared_native_vpn_catalog;
    std::shared_ptr<const ListCacheGenerationSnapshot>
        list_cache_snapshot;
    RuntimeRoutingInventorySnapshotPtr route_preimage;
    InternalVpnRuntimeResolutionState interface_resolution_state{
        InternalVpnRuntimeResolutionState::degraded};
    InternalVpnRuntimeResolutionState service_resolution_state{
        InternalVpnRuntimeResolutionState::degraded};
    std::uint64_t runtime_generation{0U};
    std::uint64_t mutation_lease_token{0U};
    std::uint64_t active_attempt_identity{0U};
    std::size_t completed_candidate_bodies{0U};
    std::size_t dispatch_rejections{0U};
    std::size_t rollback_handoff_rejections{0U};
    std::size_t rollback_body_failures{0U};
    std::size_t service_open_attempts{0U};
    bool route_mutation_acknowledged{false};
    bool exact_route_checkpoint_verified{false};
    bool startup_services_opened{false};
};

struct DaemonRuntimeFirewallOperationState final
    : RuntimeFirewallOperationDomainState {
    enum class PreworkerFailureKind : std::uint8_t {
        none,
        admission_contention,
        route_unavailable,
        preparation_failure,
        transport_rejected,
    };

    using CorePublication = RuntimeFirewallCorePublication;

    enum class LifecycleTailPhase : std::uint8_t {
        not_started,
        in_flight,
        completed,
    };

    InternalVpnRuntimeResolution internal_vpn_resolution;
    InternalVpnServiceRuntimeResolution internal_vpn_service_resolution;
    std::vector<std::string> lifecycle_trusted_dns_interfaces;
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot;
    bool resolver_refresh_required{false};
    // A foreground lifecycle operation is complete only after the committed
    // firewall generation and its resolver stream have both been verified.
    // Ordinary background refreshes retain their best-effort resolver tail.
    bool lifecycle_resolver_verified{false};
    std::string lifecycle_failure_detail;
    RuntimeFirewallLifecycleResolverAttempt lifecycle_resolver_attempt;
    LifecycleTailPhase lifecycle_start_rollback_phase{
        LifecycleTailPhase::not_started};
    std::shared_ptr<RuntimeFirewallStartRollbackResult>
        lifecycle_start_rollback_result;
    std::size_t lifecycle_start_rollback_handoff_rejections{0U};
    bool lifecycle_start_failure_detail_prepared{false};
    std::string lifecycle_start_rollback_detail;
    bool preworker_side_effects_armed{false};
    std::optional<PendingMetaUdp443ActivationCleanup>
        previous_meta_cleanup;

    CorePublication core_publication;
    std::optional<MetaUdp443ActivationPlan>
        candidate_meta_activation_plan;
    std::optional<OwnedSnatRecovery> processed_snat_recovery;
    OwnedSnatState inspected_snat_after{OwnedSnatState::unknown};
    bool worker_result_valid{false};
    bool worker_failure_transient{false};
    std::string worker_failure_detail;
    RuntimeFirewallPublicationTailProgress publication_tail;
    RuntimeFirewallImmediateCompletionIntent immediate_completion_intent;
    PreworkerFailureKind preworker_failure_kind{
        PreworkerFailureKind::none};
    std::string preworker_failure_detail;
    bool preworker_failure_policy_finished{false};
    bool suppress_coordinator_rerun{false};
    bool preworker_urltest_permanent_started{false};
    std::vector<std::string> preworker_failed_urltest_tags;
    std::shared_ptr<RuntimeRouteMutationCheckpoint>
        route_mutation_checkpoint;
    std::shared_ptr<DaemonConfigGenerationTransaction>
        config_generation_transaction;
    std::shared_ptr<DaemonUrltestSelectionTransaction>
        urltest_selection_transaction;
    std::shared_ptr<DaemonKeeneticDnsRefreshTransaction>
        keenetic_dns_refresh_transaction;
    std::shared_ptr<DaemonColdBootTransaction> cold_boot_transaction;
    std::uint64_t cold_boot_mutation_lease_token{0U};
    std::optional<RuntimeStopCleanupTarget> stop_cleanup_target;
    std::optional<RuntimeExactTcpResetPointMutationTarget>
        exact_tcp_reset_point_target;
    std::uint64_t exact_tcp_reset_point_mutation_lease_token{0U};
    std::shared_ptr<RuntimeBackgroundPointMutationTransaction>
        background_point_mutation_transaction;
    std::uint64_t background_point_mutation_lease_token{0U};
    bool stop_cleanup_generation_advanced{false};
    std::optional<ConfigTerminalOperationIdentity>
        config_operation_identity;
    std::shared_ptr<const ResolverGenerationSnapshot>
        private_resolver_generation;
};

// One staged save or active-runtime reload owns this object from the verified
// old-generation pre-apply fence until either candidate publication or exact
// rollback has completed. Kernel/resolver candidates may advance while every
// published Daemon/ConfigStore cursor remains on base_runtime_generation.
struct DaemonConfigGenerationTransaction final {
    RuntimeConfigGenerationPublicationMode publication_mode{
        RuntimeConfigGenerationPublicationMode::staged_save};
    PreparedRuntimeInputs candidate;
    PreparedRuntimeInputs rollback;
    PreparedActiveConfigCommit active_commit;
    PreparedActiveRuntimeReloadCommit active_runtime_reload_commit;
    FirewallConfigApplyPolicy candidate_firewall_policy;
    FirewallConfigApplyPolicy rollback_firewall_policy;
    OutboundMarkMap candidate_firewall_outbound_marks;
    std::map<std::string, std::string> candidate_urltest_selections;
    std::map<std::string, std::string> rollback_urltest_selections;
    std::shared_ptr<const ListCacheGenerationSnapshot>
        candidate_list_cache_snapshot;
    std::shared_ptr<const ListCacheGenerationSnapshot>
        rollback_list_cache_snapshot;
    std::shared_ptr<const ResolverGenerationSnapshot>
        candidate_resolver_generation;
    std::shared_ptr<const ResolverGenerationSnapshot>
        rollback_resolver_generation;
    ResolverSyncCheckpoint candidate_resolver_sync;
    DaemonRuntimeFirewallOperationState::CorePublication
        candidate_core_publication;
    std::optional<MetaUdp443ActivationPlan> candidate_meta_activation_plan;
    std::optional<MetaUdp443ActivationPlan> rollback_meta_activation_plan;
    ConntrackDestinationRetirementCoverage candidate_normal_retirement;
    ConntrackDestinationRetirementCoverage candidate_aggressive_retirement;
    std::vector<std::string> candidate_native_source_cleanup_cidrs;
    ConntrackDestinationRetirementCoverage rollback_normal_retirement;
    ConntrackDestinationRetirementCoverage rollback_aggressive_retirement;
    std::vector<std::string> rollback_native_source_cleanup_cidrs;
    RuntimeFirewallPreownedTerminalContinuation final_continuation;
    ConfigTerminalOperationIdentity candidate_identity;
    ConfigTerminalOperationIdentity rollback_identity;
    std::uint64_t base_runtime_generation{0U};
    std::uint64_t candidate_runtime_generation{0U};
    std::uint64_t mutation_lease_token{0U};
    std::uint64_t candidate_route_epoch{0U};
    std::uint64_t rollback_route_epoch{0U};
    std::int64_t apply_started_ts{0};
    bool candidate_core_publication_ready{false};
    bool candidate_firewall_preimage_is_base{false};
    bool candidate_meta_filter_healthy{false};
    bool candidate_meta_fastnat_healthy{false};
    bool rollback_meta_filter_healthy{false};
    bool rollback_meta_fastnat_healthy{false};
    bool previous_runtime_active{false};
    bool candidate_forwarded_scope_exact{false};
    bool rollback_forwarded_scope_exact{false};
    bool meta_cleanup_invalidated{false};
    bool rollback_tail_scheduled{false};
    bool rollback_cleanup_scope_prepared{false};
    OwnedSnatRecovery post_terminal_snat_recovery;
    bool post_terminal_refresh_required{false};
    bool post_terminal_full_refresh{false};
    bool candidate_resolver_may_have_changed{false};
    bool candidate_published{false};
    std::string candidate_failure_detail;
};

// One URLTEST selection owns this transaction from its exact probe callback
// until either the private candidate is published or the old selection is
// reverified by an exact rollback. The manager and FirewallState selection
// cursors remain on rollback_selections throughout the worker phases.
struct DaemonUrltestSelectionTransaction final {
    UrltestSelectionChange change;
    std::map<std::string, std::string> candidate_selections;
    std::map<std::string, std::string> rollback_selections;
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot;
    DaemonRuntimeFirewallOperationState::CorePublication
        candidate_core_publication;
    DaemonRuntimeFirewallOperationState::CorePublication
        rollback_core_publication;
    std::optional<MetaUdp443ActivationPlan> candidate_meta_activation_plan;
    std::optional<MetaUdp443ActivationPlan> rollback_meta_activation_plan;
    std::optional<std::uint32_t> retired_mark;
    RuntimeUrltestTerminalOrchestrator terminal_orchestrator;
    std::uint64_t runtime_generation{0U};
    std::uint64_t mutation_lease_token{0U};
    bool candidate_core_publication_ready{false};
    bool rollback_core_publication_ready{false};
    bool candidate_meta_filter_healthy{false};
    bool candidate_meta_fastnat_healthy{false};
    bool rollback_meta_filter_healthy{false};
    bool rollback_meta_fastnat_healthy{false};
    // The old delayed Meta cleanup epoch and idle/call-affinity observer are
    // invalidated before the first private candidate is queued. A verified
    // candidate/rollback installs replacement maintenance; a clean
    // pre-COMMIT rejection requests one fresh published-state reconciliation.
    bool maintenance_fence_invalidated{false};
    bool candidate_published{false};
    std::string candidate_failure_detail;
};

// One periodic Keenetic DNS observation owns this private transaction from
// exact admission through either verified candidate publication, a verified
// candidate+resolver rollback, or fail-closed recovery. Published DNS,
// firewall and resolver cursors stay on the previous generation throughout
// both worker phases.
struct DaemonKeeneticDnsRefreshTransaction final {
    KeeneticDnsFirewallTerminalOrchestrator terminal_orchestrator;
    KeeneticDnsCacheView candidate_view;
    KeeneticDnsCacheView rollback_view;
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot;
    std::shared_ptr<const ResolverGenerationSnapshot>
        candidate_resolver_generation;
    std::shared_ptr<const ResolverGenerationSnapshot>
        rollback_resolver_generation;
    std::shared_ptr<const ResolverGenerationSnapshot>
        published_resolver_generation;
    ResolverSyncCheckpoint published_resolver_sync;
    ResolverSyncCheckpoint candidate_resolver_sync;
    DaemonRuntimeFirewallOperationState::CorePublication
        candidate_core_publication;
    DaemonRuntimeFirewallOperationState::CorePublication
        rollback_core_publication;
    std::optional<MetaUdp443ActivationPlan> candidate_meta_activation_plan;
    std::optional<MetaUdp443ActivationPlan> rollback_meta_activation_plan;
    std::uint64_t runtime_generation{0U};
    std::uint64_t mutation_lease_token{0U};
    std::uint32_t published_resolver_retry_attempt{0U};
    std::int64_t published_apply_started_ts{0};
    std::int64_t candidate_apply_started_ts{0};
    bool candidate_core_publication_ready{false};
    bool rollback_core_publication_ready{false};
    bool candidate_meta_filter_healthy{false};
    bool candidate_meta_fastnat_healthy{false};
    bool rollback_meta_filter_healthy{false};
    bool rollback_meta_fastnat_healthy{false};
    bool candidate_route_firewall_commit_proven{false};
    bool candidate_exact_rollback_available{false};
    bool candidate_firewall_preimage_is_base{false};
    bool maintenance_fence_invalidated{false};
    bool candidate_published{false};
    std::string candidate_failure_detail;
};

static_assert(
    std::is_nothrow_swappable_v<Config> &&
        std::is_nothrow_swappable_v<OutboundMarkMap> &&
        std::is_nothrow_swappable_v<KeeneticDnsCacheView>,
    "config generation publication requires no-throw prepared-state swaps");

std::map<std::string, std::string>
normalized_urltest_selections_for_config(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::map<std::string, std::string>& current) {
    std::map<std::string, std::string> normalized;
    for (const auto& outbound :
         config.outbounds.value_or(std::vector<Outbound>{})) {
        if (outbound.type != OutboundType::URLTEST) continue;
        const auto selection = current.find(outbound.tag);
        if (selection == current.end()) continue;
        const auto groups = outbound.outbound_groups.value_or(
            std::vector<OutboundGroup>{});
        const bool contains_child = std::any_of(
            groups.begin(),
            groups.end(),
            [&selection](const OutboundGroup& group) {
                return std::find(
                           group.outbounds.begin(),
                           group.outbounds.end(),
                           selection->second) != group.outbounds.end();
            });
        if (contains_child &&
            outbound_marks.find(selection->second) !=
                outbound_marks.end()) {
            normalized.emplace(selection->first, selection->second);
        }
    }
    return normalized;
}

bool config_forwarded_scope_restricted(
    const Config& config,
    const std::vector<InternalVpnServer>& internal_vpn_servers,
    const std::vector<InternalVpnRuntimeTarget>& internal_vpn_targets) {
    const auto route_config = config.route.value_or(RouteConfig{});
    const bool explicit_inbound_scope =
        route_config.inbound_interfaces.has_value() &&
        !route_config.inbound_interfaces->empty();
    const bool native_vpn_bypass = std::any_of(
        internal_vpn_servers.begin(),
        internal_vpn_servers.end(),
        [](const InternalVpnServer& server) {
            return !server.process_clients;
        }) || std::any_of(
        internal_vpn_targets.begin(),
        internal_vpn_targets.end(),
        [](const InternalVpnRuntimeTarget& target) {
            return !target.process_clients;
        });
    return explicit_inbound_scope || native_vpn_bypass;
}

struct ConfigTransitionCleanupPlan final {
    bool forwarded_scope_exact{false};
    std::vector<std::string> native_source_cleanup_cidrs;
    ConntrackDestinationRetirementCoverage normal_retirement;
    ConntrackDestinationRetirementCoverage aggressive_retirement;
};

ConfigTransitionCleanupPlan prepare_config_transition_cleanup_plan(
    bool previous_runtime_active,
    const Config& previous_config,
    const std::vector<RuleState>& previous_rules,
    const AppliedListContentState& previous_list_content,
    const std::vector<FirewallSourceEgressSnatSelector>&
        previous_native_snat_selectors,
    const std::vector<InternalVpnServer>& previous_internal_vpn_servers,
    const std::vector<InternalVpnRuntimeTarget>&
        previous_internal_vpn_targets,
    const Config& next_config,
    const DaemonRuntimeFirewallOperationState::CorePublication&
        next_publication) {
    ConfigTransitionCleanupPlan result;
    const bool previous_forwarded_scope_restricted =
        config_forwarded_scope_restricted(
            previous_config,
            previous_internal_vpn_servers,
            previous_internal_vpn_targets);
    const bool next_forwarded_scope_restricted =
        config_forwarded_scope_restricted(
            next_config,
            next_publication.internal_vpn_servers,
            next_publication.internal_vpn_service_targets);
    result.forwarded_scope_exact = !next_forwarded_scope_restricted;
    result.native_source_cleanup_cidrs =
        changed_native_vpn_direct_egress_source_cidrs(
            previous_native_snat_selectors,
            next_publication.native_vpn_direct_egress_snat_selectors);

    if (!previous_runtime_active ||
        !reconnect_unmarked_flows_on_routing_change_enabled(next_config)) {
        return result;
    }

    const auto previous_owned_lists =
        reconnect_owned_flows_on_routing_change_list_names(previous_config);
    const auto next_owned_lists =
        reconnect_owned_flows_on_routing_change_list_names(next_config);
    std::set<std::string> newly_enabled_owned_lists;
    std::set_difference(
        next_owned_lists.begin(),
        next_owned_lists.end(),
        previous_owned_lists.begin(),
        previous_owned_lists.end(),
        std::inserter(
            newly_enabled_owned_lists,
            newly_enabled_owned_lists.end()));

    std::set<std::string> changed_list_names;
    for (const auto& [list_name, next_destinations] :
         next_publication.list_content_state.static_destinations) {
        const auto previous =
            previous_list_content.static_destinations.find(list_name);
        if (previous == previous_list_content.static_destinations.end() ||
            previous->second != next_destinations) {
            changed_list_names.insert(list_name);
        }
    }
    for (const auto& [list_name, previous_destinations] :
         previous_list_content.static_destinations) {
        const auto next =
            next_publication.list_content_state.static_destinations.find(
                list_name);
        if (next ==
                next_publication.list_content_state.static_destinations.end() ||
            next->second != previous_destinations) {
            changed_list_names.insert(list_name);
        }
    }
    for (const auto& list_name :
         next_publication.list_content_state.domain_entry_lists) {
        if (previous_list_content.domain_entry_lists.count(list_name) == 0U) {
            changed_list_names.insert(list_name);
        }
    }
    for (const auto& list_name : previous_list_content.domain_entry_lists) {
        if (next_publication.list_content_state.domain_entry_lists.count(
                list_name) == 0U) {
            changed_list_names.insert(list_name);
        }
    }
    for (const auto& list_name :
         next_publication.list_content_state
             .truncated_static_destination_lists) {
        if (previous_list_content.truncated_static_destination_lists.count(
                list_name) == 0U) {
            changed_list_names.insert(list_name);
        }
    }
    for (const auto& list_name :
         previous_list_content.truncated_static_destination_lists) {
        if (next_publication.list_content_state
                .truncated_static_destination_lists.count(list_name) == 0U) {
            changed_list_names.insert(list_name);
        }
    }

    const std::vector<RuleState> no_previous_rules;
    const auto& comparison_rules =
        previous_forwarded_scope_restricted &&
            !next_forwarded_scope_restricted
        ? no_previous_rules
        : previous_rules;
    const auto normal_plan =
        plan_conntrack_destination_retirement(
            comparison_rules,
            next_publication.rules,
            changed_list_names);
    result.normal_retirement =
        merge_conntrack_destination_retirement_coverage(
            collect_conntrack_destination_retirement_coverage(
                normal_plan,
                next_publication.list_content_state),
            collect_conntrack_destination_retirement_coverage(
                normal_plan,
                previous_list_content));

    const auto owned_reconnect_lists =
        plan_conntrack_owned_destination_reconnect(
            previous_rules,
            next_publication.rules,
            next_owned_lists,
            changed_list_names,
            newly_enabled_owned_lists);
    if (!owned_reconnect_lists.empty()) {
        const auto owned_plan =
            destination_retirement_plan_for_lists(
                owned_reconnect_lists);
        result.aggressive_retirement =
            merge_conntrack_destination_retirement_coverage(
                collect_conntrack_destination_retirement_coverage(
                    owned_plan,
                    next_publication.list_content_state),
                collect_conntrack_destination_retirement_coverage(
                    owned_plan,
                    previous_list_content));
    }
    return result;
}

struct RuntimeFirewallStartRollbackResult final {
    std::atomic<bool> ready{false};
    bool routing_cleared{false};
    bool firewall_cleared{false};
    bool resolver_deactivated{false};
    std::string detail;
};

static_assert(
    std::is_nothrow_move_assignable_v<
        DaemonRuntimeFirewallOperationState::CorePublication>,
    "the runtime firewall core checkpoint must commit without throwing");
static_assert(
    std::is_nothrow_move_assignable_v<
        std::optional<MetaUdp443ActivationPlan>>,
    "the runtime firewall Meta checkpoint must commit without throwing");
static_assert(
    std::is_nothrow_move_assignable_v<std::optional<OwnedSnatRecovery>>,
    "the runtime firewall SNAT checkpoint must commit without throwing");

DaemonRuntimeFirewallOperationState& runtime_firewall_domain_state(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context) {
    if (!context || !context->domain_state) {
        throw std::logic_error(
            "runtime firewall operation has no domain state");
    }
    return static_cast<DaemonRuntimeFirewallOperationState&>(
        *context->domain_state);
}

std::string get_outbound_tag(const Outbound& ob) {
    return ob.tag;
}

const Outbound* find_outbound(const std::vector<Outbound>& outbounds,
                              const std::string& tag) {
    for (const auto& ob : outbounds) {
        if (ob.tag == tag) {
            return &ob;
        }
    }
    return nullptr;
}

void Daemon::publish_runtime_firewall_core_checkpoint(
    RuntimeFirewallCorePublication& publication,
    RuntimeFirewallCoreMetaPublication meta_publication) noexcept {
    publish_runtime_firewall_core(
        RuntimeFirewallCorePublicationTarget{
            firewall_state_,
            applied_list_content_state_,
            applied_list_usage_,
            applied_list_fingerprints_,
            resolved_internal_vpn_servers_,
            resolved_internal_vpn_service_targets_,
            applied_native_vpn_direct_egress_snat_selectors_,
            committed_meta_udp443_fwmark_,
            committed_meta_udp443_owned_mask_},
        publication,
        meta_publication);
}

void Daemon::publish_runtime_resolver_checkpoint(
    std::shared_ptr<const ResolverGenerationSnapshot>& generation,
    ResolverSyncCheckpoint& sync,
    std::uint32_t retry_attempt,
    std::int64_t apply_started_ts,
    RuntimeResolverGenerationPublication generation_publication) noexcept {
    keen_pbr3::publish_runtime_resolver_checkpoint(
        RuntimeResolverPublicationTarget{
            resolver_generation_snapshot_,
            resolver_sync_,
            resolver_config_hash_actual_retry_attempt_,
            apply_started_ts_},
        RuntimeResolverPublicationSource{
            generation,
            sync,
            retry_attempt,
            apply_started_ts},
        generation_publication);
}

Daemon::Daemon(Config config,
               std::string config_path,
               DaemonOptions opts,
               HookCommandExecutor hook_command_executor)
    : config_store_(config)
    , list_service_(config.daemon.value_or(DaemonConfig{}).cache_dir.value_or("/var/cache/keen-pbr"),
                    max_file_size_bytes(config))
    , ndms_native_import_wal_store_(
          "/opt/etc/keen-pbr/native-import-wal")
    , ndms_native_delete_wal_store_(
          "/opt/etc/keen-pbr/native-delete-wal")
    , ndms_native_ownership_store_(
          "/opt/etc/keen-pbr/native-import-ownership")
    , ndms_native_observation_store_(
          "/opt/etc/keen-pbr/native-mutation")
    , ndms_native_secret_snapshot_store_(
          "/opt/etc/keen-pbr/native-import-secrets/snapshot.key",
          "/opt/etc/keen-pbr/native-import-snapshots")
    , config_(std::move(config))
    , config_path_(std::move(config_path))
    , opts_(std::move(opts))
    , firewall_(create_firewall(
          firewall_backend_preference(config_),
          RawPreroutingMode{opts_.use_raw_prerouting,
                            opts_.use_raw6_prerouting}))
    , interface_monitor_(std::make_unique<InterfaceMonitor>(
          [this](const InterfaceMonitor::Event& event) {
              handle_interface_event(event);
          }))
    , netlink_()
    , routing_operation_owner_(netlink_, netlink_)
    , firewall_state_()
    , url_tester_()
    , outbound_marks_(allocate_outbound_marks(config_.fwmark.value_or(FwmarkConfig{}),
                                              config_.outbounds.value_or(std::vector<Outbound>{})))
    , keenetic_dns_refresh_coordinator_(
          resolver_io_executor_,
          periodic_task_metrics_,
          []() {
              return refresh_keenetic_dns_address_cache(
                  /*force_refresh=*/true);
          },
          [this](std::function<void()> task) {
              return post_control_task(
                  std::move(task), "keenetic-dns-refresh-commit");
          },
          [this](std::uint64_t generation,
                 const KeeneticDnsRefreshResult& result,
                 const RuntimeMutationLeaseHandoff& mutation_lease) {
               return commit_keenetic_dns_refresh_result(
                   generation, result, mutation_lease);
           })
    , hook_command_executor_(std::move(hook_command_executor))
    , resolver_stream_coordinator_(
          resolver_hook_executor_,
          [this](std::function<void()> task) {
              return post_control_task(
                  std::move(task), "resolver-stream-recovery-commit");
          },
          [this](const ResolverStreamOperation& operation,
                 const ResolverStreamResult& result) {
              complete_resolver_reload_retry_attempt(operation, result);
          })
{
    if (!hook_command_executor_) {
        hook_command_executor_ = default_hook_command_executor;
    }

    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        throw DaemonError("epoll_create1 failed: " + std::string(strerror(errno)));
    }

    setup_signals();
    setup_control_channel();

    const int64_t verify_max_bytes = config_.daemon.value_or(DaemonConfig{})
        .firewall_verify_max_bytes.value_or(static_cast<int64_t>(DEFAULT_FIREWALL_VERIFY_CAPTURE_MAX_BYTES));
    set_firewall_verifier_capture_max_bytes(static_cast<size_t>(verify_max_bytes));

    firewall_state_.set_outbound_marks(outbound_marks_);
    firewall_state_.set_fwmark_mask(fwmark_mask_value(config_.fwmark.value_or(FwmarkConfig{})));
    list_service_.ensure_dir();
    scheduler_ = std::make_unique<Scheduler>(*this);

    RuntimeFirewallOperationOwner::Callbacks firewall_owner_callbacks;
    firewall_owner_callbacks.create_domain_state = [] {
        return std::make_shared<DaemonRuntimeFirewallOperationState>();
    };
    firewall_owner_callbacks.post_control =
        [this](std::function<void()> task, std::string label) {
            return post_control_task(std::move(task), std::move(label));
        };
    firewall_owner_callbacks.schedule_oneshot =
        [this](std::chrono::milliseconds delay,
               std::function<void()> task,
               std::string label) {
            return scheduler_->schedule_oneshot(
                delay, std::move(task), std::move(label));
        };
    firewall_owner_callbacks.schedule_repeating =
        [this](std::chrono::milliseconds interval,
               std::function<void()> task,
               std::string label) {
            return scheduler_->schedule_repeating(
                interval, std::move(task), std::move(label));
        };
    firewall_owner_callbacks.cancel_scheduled =
        [this](int task_id) { scheduler_->cancel(task_id); };
    firewall_owner_callbacks.runtime_is_current =
        [this](std::uint64_t expected_generation,
               RuntimeFirewallLifecycleKind lifecycle_kind) {
            const bool current =
                runtime_firewall_lifecycle_generation_is_current(
                    lifecycle_kind, expected_generation);
            if (!current) {
                Logger::instance().verbose(
                    "Discarding stale runtime firewall recovery retry.");
            }
            return current;
        };
    firewall_owner_callbacks.urltest_waiting =
        [this](std::uint64_t generation) {
            return urltest_after_firewall_gate_.waiting_for(generation);
        };
    firewall_owner_callbacks.dispatch_attempt =
        [this](std::shared_ptr<RuntimeFirewallOperationContext> context,
               RuntimeFirewallOperationClaim claim,
               OwnedSnatRecovery recovery,
               PreparedNativeVpnCatalogPtr catalog,
               bool schedule_catalog_refresh) {
            dispatch_runtime_firewall_worker_attempt(
                context,
                claim,
                std::move(recovery),
                std::move(catalog),
                schedule_catalog_refresh);
        };
    firewall_owner_callbacks.drain_terminal =
        [this](std::shared_ptr<RuntimeFirewallOperationContext> context,
               bool shutdown) {
            drain_runtime_firewall_terminal(context, shutdown);
        };
    firewall_owner_callbacks.active_mutation_label = [this] {
        const auto active = runtime_mutation_admission_.active();
        return active.has_value()
            ? active->label
            : std::string{"unknown"};
    };
    runtime_firewall_owner_ =
        std::make_shared<RuntimeFirewallOperationOwner>(
            runtime_firewall_retry_,
            std::move(firewall_owner_callbacks));

#ifdef WITH_API
    // DNS diagnostics are interactive and should have only one live probe.
    // Combined with four runtime streams this leaves worker capacity for the
    // REST API even on the minimum eight-thread cpp-httplib pool.
    // Browsers may keep the old EventSource alive briefly while reconnecting
    // after a daemon restart. A single-slot broadcaster turns that harmless
    // overlap into a false "DNS event stream unavailable" result.
    dns_test_broadcaster_ = std::make_unique<SseBroadcaster>(128, 4);
    list_refresh_tasks_.set_publish_callback(
        [this](const ListRefreshTaskSnapshot& task) {
            if (status_stream_) {
                status_stream_->publish_list_refresh(
                    list_refresh_task_json(task));
            }
        });
#endif
    // Acquire ownership before touching the shared control-socket path. A
    // second instance must fail without unlinking the live daemon's socket.
    write_pid_file();
    setup_ipc_control_socket();
}

Daemon::~Daemon() {
    const auto cleanup_step = [](
                                  std::string_view label,
                                  auto&& step) noexcept {
        try {
            step();
        } catch (const std::exception& error) {
            try {
                Logger::instance().error(
                    "Daemon destruction step '{}' failed: {}",
                    label,
                    error.what());
            } catch (...) {
            }
        } catch (...) {
            try {
                Logger::instance().error(
                    "Daemon destruction step '{}' failed: unknown error",
                    label);
            } catch (...) {
            }
        }
    };

    // Cleanup is deliberately stepwise. A failed scheduler cancellation or
    // diagnostic close must never skip the coordinator drain and executor
    // shutdown that protect callbacks from observing partially destroyed
    // Daemon members.
#ifdef WITH_API
    cleanup_step("retire API runtime", [this] {
        retire_api_runtime_resources();
    });
    cleanup_step("cancel nfqws boot recovery", [this] {
        cancel_nfqws_boot_recovery();
        cancel_nfqws_retention_backfill();
    });
    cleanup_step("cancel remote-access recovery watchdog", [this] {
        cancel_remote_access_recovery_watchdog();
    });
    cleanup_step("reset remote-access retry bridge", [this] {
        reset_remote_access_retry_bridge();
    });
#endif
    cleanup_step("fence runtime firewall shutdown", [this] {
        runtime_firewall_owner_->request_shutdown();
    });
    cleanup_step("close runtime mutation admission", [this] {
        runtime_mutation_admission_.shutdown();
    });
    cleanup_step("cancel runtime firewall retry", [this] {
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->cancel_retry();
    });
    cleanup_step("close routing test admission", [this] {
        routing_test_admission_.shutdown();
    });
    cleanup_step("stop SIGHUP reload coordinator", [this] {
        sighup_reload_coordinator_.stop();
    });
    cleanup_step("cancel resolver reload retry", [this] {
        cancel_resolver_reload_retry();
    });
    cleanup_step("stop resolver stream coordinator", [this] {
        resolver_stream_coordinator_.request_stop();
    });
    cleanup_step("stop Keenetic DNS refresh coordinator", [this] {
        keenetic_dns_refresh_coordinator_.stop();
    });
    cleanup_step("cancel active list refresh", [this] {
        list_refresh_tasks_.request_cancel_active();
    });
    cleanup_step("invalidate URLTEST work", [this] {
        if (urltest_manager_) {
            urltest_manager_->clear();
        }
    });
    cleanup_step("cancel scheduled work", [this] {
        cancel_owned_conntrack_cleanup_retry();
        scheduler_->cancel_all();
    });
    cleanup_step("discard queued blocking work", [this] {
        runtime_firewall_owner_->cancel_pending_work();
        runtime_firewall_owner_->pump_terminal_for_shutdown();
        blocking_executor_.cancel_pending();
    });
    cleanup_step("drain resolver stream recovery", [this] {
        quiesce_resolver_stream_recovery();
    });
    cleanup_step("drain runtime mutations", [this] {
        quiesce_runtime_mutations();
    });
    cleanup_step("stop runtime firewall executor", [this] {
        runtime_firewall_owner_->shutdown_executor();
        runtime_firewall_owner_->pump_terminal_for_shutdown();
    });
    cleanup_step("retire runtime firewall owner", [this] {
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->cancel_retry();
        scheduler_->cancel_all();
        runtime_firewall_owner_->reset_active();
    });
    // Stop ingress while the eventfd wake target is still alive. Otherwise an
    // acceptor finishing a frame during teardown could write to a descriptor
    // which has already been closed and reused by another subsystem.
    cleanup_step("remove IPC control socket", [this] {
        remove_ipc_control_socket();
    });
    cleanup_step("close posted control task gate", [this] {
        {
            KPBR_LOCK_GUARD(control_tasks_mutex_);
            accept_posted_control_tasks_.store(
                false, std::memory_order_release);
        }
    });
    cleanup_step("drain posted control tasks", [this] {
        if (control_fd_ >= 0) {
            handle_control_commands();
        }
    });
    cleanup_step("stop resolver hook executor", [this] {
        resolver_hook_executor_.cancel_pending_and_shutdown();
    });
    cleanup_step("stop resolver stream executor", [this] {
        resolver_stream_executor_.cancel_pending_and_shutdown();
    });
    cleanup_step("stop resolver I/O executor", [this] {
        resolver_io_executor_.cancel_pending_and_shutdown();
    });
    cleanup_step("stop routing test executor", [this] {
        routing_test_executor_.cancel_pending_and_shutdown();
    });
    cleanup_step("stop blocking executor", [this] {
        blocking_executor_.cancel_pending_and_shutdown();
    });
    cleanup_step("close control channel", [this] {
        if (control_fd_ >= 0) {
            epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, control_fd_, nullptr);
            close(control_fd_);
            control_fd_ = -1;
        }
    });
    cleanup_step("close signal channel", [this] {
        if (signal_fd_ >= 0) {
            epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, signal_fd_, nullptr);
            close(signal_fd_);
            signal_fd_ = -1;
        }
    });
    cleanup_step("close epoll", [this] {
        if (epoll_fd_ >= 0) {
            close(epoll_fd_);
            epoll_fd_ = -1;
        }
    });
    cleanup_step("restore signal mask", [] {
        unblock_daemon_signals_for_current_thread();
    });
}

void Daemon::setup_control_channel() {
    control_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (control_fd_ < 0) {
        throw DaemonError("eventfd failed: " + std::string(strerror(errno)));
    }

    struct epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = control_fd_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, control_fd_, &ev) < 0) {
        throw DaemonError("epoll_ctl add control_fd failed: " + std::string(strerror(errno)));
    }
}

void Daemon::setup_ipc_control_socket() {
    ipc_control_socket_path_ = KEEN_PBR_CONTROL_SOCKET;
    if (ipc_control_socket_path_.empty() ||
        ipc_control_socket_path_.size() >=
            sizeof(sockaddr_un::sun_path)) {
        throw DaemonError("control socket path is invalid");
    }

    const auto parent =
        std::filesystem::path(ipc_control_socket_path_).parent_path();
    std::error_code directory_error;
    std::filesystem::create_directories(parent, directory_error);
    if (directory_error) {
        throw DaemonError(
            "failed to create control socket directory: " +
            directory_error.message());
    }

    const group* control_group = ::getgrnam("keen-pbr");
    if (control_group != nullptr) {
        ipc_control_group_id_ = control_group->gr_gid;
        if (::chown(parent.c_str(), 0, ipc_control_group_id_) != 0) {
            throw DaemonError(
                "failed to assign control socket directory group: " +
                std::string(strerror(errno)));
        }
    } else {
        ipc_control_group_id_ = static_cast<gid_t>(-1);
        Logger::instance().info(
            "Optional keen-pbr group is absent; control socket is root-only");
    }
    if (::chmod(parent.c_str(), 0750) != 0) {
        throw DaemonError(
            "failed to set control socket directory mode: " +
            std::string(strerror(errno)));
    }

    struct stat existing {};
    if (::lstat(ipc_control_socket_path_.c_str(), &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode) ||
            ::unlink(ipc_control_socket_path_.c_str()) != 0) {
            throw DaemonError("unsafe stale control socket path");
        }
    } else if (errno != ENOENT) {
        throw DaemonError(
            "failed to inspect control socket path: " +
            std::string(strerror(errno)));
    }

    ipc_control_fd_ =
        ::socket(AF_UNIX,
                 SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                 0);
    if (ipc_control_fd_ < 0) {
        throw DaemonError(
            "control socket create failed: " +
            std::string(strerror(errno)));
    }

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path,
                ipc_control_socket_path_.c_str(),
                ipc_control_socket_path_.size() + 1);
    const gid_t socket_group =
        ipc_control_group_id_ == static_cast<gid_t>(-1)
            ? static_cast<gid_t>(0)
            : ipc_control_group_id_;
    const mode_t socket_mode =
        ipc_control_group_id_ == static_cast<gid_t>(-1) ? 0600 : 0660;
    if (::bind(ipc_control_fd_,
               reinterpret_cast<const sockaddr*>(&address),
               sizeof(address)) != 0 ||
        ::listen(ipc_control_fd_, 16) != 0 ||
        ::chown(ipc_control_socket_path_.c_str(), 0, socket_group) != 0 ||
        ::chmod(ipc_control_socket_path_.c_str(), socket_mode) != 0) {
        const std::string error = strerror(errno);
        remove_ipc_control_socket();
        throw DaemonError("control socket setup failed: " + error);
    }

    ipc_accept_running_.store(true, std::memory_order_release);
    try {
        ipc_accept_thread_ =
            std::thread([this] { run_ipc_control_acceptor(); });
    } catch (...) {
        ipc_accept_running_.store(false, std::memory_order_release);
        remove_ipc_control_socket();
        throw;
    }
}

void Daemon::run_ipc_control_acceptor() noexcept {
    struct PendingClient {
        int fd{-1};
        std::string frame;
        std::optional<std::size_t> expected_size;
        std::chrono::steady_clock::time_point deadline;
    };

    std::vector<PendingClient> pending;
    pending.reserve(kMaxPendingControlClients);
    const auto reject = [](int fd,
                           std::string_view code,
                           std::string_view message) {
        send_control_response_and_close(
            fd,
            {{"protocol_version", ipc::kControlProtocolVersion},
             {"request_id", nullptr},
             {"ok", false},
             {"error", {{"code", code}, {"message", message}}}});
    };

    while (ipc_accept_running_.load(std::memory_order_acquire)) {
        std::vector<pollfd> poll_fds;
        poll_fds.reserve(pending.size() + 1U);
        poll_fds.push_back({ipc_control_fd_, POLLIN, 0});
        for (const auto& client : pending) {
            poll_fds.push_back({client.fd, POLLIN, 0});
        }

        const int ready =
            ::poll(poll_fds.data(), poll_fds.size(), 100);
        if (ready < 0) {
            if (errno == EINTR) continue;
            if (ipc_accept_running_.load(std::memory_order_acquire)) {
                try {
                    Logger::instance().error(
                        "control socket acceptor poll failed: {}",
                        strerror(errno));
                } catch (...) {
                }
            }
            break;
        }

        if (!poll_fds.empty() &&
            (poll_fds.front().revents & POLLIN) != 0) {
            while (ipc_accept_running_.load(std::memory_order_acquire)) {
                const int client = ::accept4(
                    ipc_control_fd_,
                    nullptr,
                    nullptr,
                    SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (client < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    if (errno == EINTR) continue;
                    if (ipc_accept_running_.load(
                            std::memory_order_acquire)) {
                        try {
                            Logger::instance().error(
                                "control socket accept failed: {}",
                                strerror(errno));
                        } catch (...) {
                        }
                    }
                    break;
                }

                std::size_t completed_count = 0;
                {
                    KPBR_LOCK_GUARD(ipc_accepted_clients_mutex_);
                    completed_count = ipc_accepted_clients_.size();
                }
                if (pending.size() + completed_count >=
                    kMaxPendingControlClients) {
                    reject(
                        client,
                        "busy",
                        "control ingress queue is full");
                    continue;
                }
                pending.push_back(
                    {client,
                     {},
                     std::nullopt,
                     std::chrono::steady_clock::now() +
                         kControlIngressTimeout});
            }
        }

        const auto now = std::chrono::steady_clock::now();
        for (std::size_t index = pending.size(); index-- > 0;) {
            auto& client = pending[index];
            short revents = 0;
            if (poll_fds.size() > index + 1U) {
                revents = poll_fds[index + 1U].revents;
            }
            bool failed = false;
            bool complete = false;

            if ((revents & POLLIN) != 0) {
                char buffer[4096];
                for (;;) {
                    const ssize_t count = ::recv(
                        client.fd, buffer, sizeof(buffer), 0);
                    if (count > 0) {
                        client.frame.append(
                            buffer, static_cast<std::size_t>(count));
                        if (!client.expected_size.has_value() &&
                            client.frame.size() >=
                                sizeof(std::uint32_t)) {
                            std::uint32_t network_size = 0;
                            std::memcpy(
                                &network_size,
                                client.frame.data(),
                                sizeof(network_size));
                            const std::size_t payload_size =
                                ntohl(network_size);
                            if (payload_size >
                                kMaxControlRequestBytes) {
                                failed = true;
                                break;
                            }
                            client.expected_size =
                                sizeof(network_size) + payload_size;
                        }
                        if (client.expected_size.has_value() &&
                            client.frame.size() >=
                                *client.expected_size) {
                            complete =
                                client.frame.size() ==
                                *client.expected_size;
                            failed = !complete;
                            break;
                        }
                        continue;
                    }
                    if (count == 0) {
                        failed = true;
                        break;
                    }
                    if (errno == EINTR) continue;
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        failed = true;
                    }
                    break;
                }
            }
            if (!complete &&
                ((revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
                 now >= client.deadline)) {
                failed = true;
            }
            if (!complete && !failed) continue;

            const int fd = client.fd;
            std::string frame = std::move(client.frame);
            pending.erase(
                pending.begin() + static_cast<std::ptrdiff_t>(index));
            if (failed) {
                reject(
                    fd,
                    "protocol_error",
                    "incomplete control request");
                continue;
            }

            nlohmann::json request = nlohmann::json::object();
            try {
                ucred peer{};
                socklen_t peer_length = sizeof(peer);
                if (::getsockopt(
                        fd,
                        SOL_SOCKET,
                        SO_PEERCRED,
                        &peer,
                        &peer_length) != 0) {
                    throw ipc::ControlProtocolError(
                        "unable to verify control peer");
                }
                request = ipc::decode_message(frame);
                ipc::validate_request_envelope(request);

                const int flags = ::fcntl(fd, F_GETFL, 0);
                if (flags < 0 ||
                    ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
                    throw ipc::ControlProtocolError(
                        "unable to prepare control response socket");
                }
                timeval timeout{5, 0};
                if (::setsockopt(
                        fd,
                        SOL_SOCKET,
                        SO_SNDTIMEO,
                        &timeout,
                        sizeof(timeout)) != 0) {
                    throw ipc::ControlProtocolError(
                        "unable to bound control response socket");
                }

                bool queued = false;
                {
                    KPBR_LOCK_GUARD(ipc_accepted_clients_mutex_);
                    if (ipc_accept_running_.load(
                            std::memory_order_acquire) &&
                        ipc_accepted_clients_.size() <
                            kMaxPendingControlClients) {
                        ipc_accepted_clients_.push_back(
                            {fd,
                             peer.pid,
                             peer.uid,
                             peer.gid,
                             std::move(request)});
                        queued = true;
                    }
                }
                if (!queued) {
                    reject(
                        fd,
                        "busy",
                        "control dispatch queue is unavailable");
                    continue;
                }
                try {
                    wake_control_loop();
                } catch (const std::exception& error) {
                    try {
                        Logger::instance().error(
                            "control socket wake failed: {}",
                            error.what());
                    } catch (...) {
                    }
                }
            } catch (const std::exception& error) {
                send_control_response_and_close(
                    fd,
                    ipc::make_error_response(
                        request, "protocol_error", error.what()));
            }
        }
    }

    for (const auto& client : pending) {
        ::close(client.fd);
    }
}

void Daemon::remove_ipc_control_socket() noexcept {
    ipc_accept_running_.store(false, std::memory_order_release);
    if (ipc_control_fd_ >= 0) {
        (void)::shutdown(ipc_control_fd_, SHUT_RDWR);
    }
    if (ipc_accept_thread_.joinable()) {
        ipc_accept_thread_.join();
    }
    if (ipc_control_fd_ >= 0) {
        ::close(ipc_control_fd_);
        ipc_control_fd_ = -1;
    }
    {
        KPBR_LOCK_GUARD(ipc_accepted_clients_mutex_);
        for (const auto& client : ipc_accepted_clients_) {
            ::close(client.fd);
        }
        ipc_accepted_clients_.clear();
    }
    ipc_control_group_id_ = static_cast<gid_t>(-1);
    if (!ipc_control_socket_path_.empty()) {
        struct stat metadata {};
        if (::lstat(ipc_control_socket_path_.c_str(), &metadata) == 0 &&
            S_ISSOCK(metadata.st_mode)) {
            (void)::unlink(ipc_control_socket_path_.c_str());
        }
        ipc_control_socket_path_.clear();
    }
}

void Daemon::handle_ipc_control_socket() {
    while (true) {
        IpcControlRequest accepted;
        {
            KPBR_LOCK_GUARD(ipc_accepted_clients_mutex_);
            if (ipc_accepted_clients_.empty()) return;
            accepted = std::move(ipc_accepted_clients_.front());
            ipc_accepted_clients_.pop_front();
        }
        const int client = accepted.fd;
        nlohmann::json request = std::move(accepted.request);
        nlohmann::json response;
        bool stream_dispatched = false;
        try {
            ucred peer{};
            peer.pid = accepted.peer_pid;
            peer.uid = accepted.peer_uid;
            peer.gid = accepted.peer_gid;

            const std::string operation =
                request.at("operation").get<std::string>();
            const bool resolver_hook_inflight =
                resolver_stream_attempt_owner_.ipc_gate_in_flight();
            const bool resolver_read_only_operation =
                operation == "status" ||
                operation == "resolver-config-hash";
            const bool root_peer = peer.uid == 0;
            const bool list_control_operation =
                operation == "download" ||
                operation == "download-status" ||
                operation == "download-cancel";
            const bool list_update_member =
                ipc_control_group_id_ != static_cast<gid_t>(-1) &&
                peer_has_group(peer, ipc_control_group_id_) &&
                list_control_operation;
            if (!root_peer && !list_update_member) {
                throw ipc::ControlProtocolError(
                    "control peer is not authorized for this operation");
            }

            const bool supported =
                operation == "status" ||
                operation == "resolver-config-hash" ||
                operation == "download" ||
                operation == "download-status" ||
                operation == "download-cancel" ||
                operation == "test-routing" ||
                operation == "generate-resolver-config";
            if (!supported) {
                response = ipc::make_error_response(
                    request,
                    "unsupported_operation",
                    "unsupported control operation");
            } else if (
                resolver_hook_inflight &&
                operation != "generate-resolver-config" &&
                !resolver_read_only_operation) {
                response = ipc::make_error_response(
                    request,
                    "busy",
                    "mutating control operations are unavailable during "
                    "resolver reload");
            } else if (operation == "test-routing") {
                const std::string target =
                    request.value("target", "");
                if (target.empty()) {
                    throw ipc::ControlProtocolError(
                        "test-routing requires a target");
                }
                const RoutingTestDeadline operation_deadline =
                    std::chrono::steady_clock::now() +
                    kRoutingTestOperationTimeout;
                auto admitted =
                    routing_test_admission_.try_acquire();
                if (!admitted.has_value()) {
                    response = ipc::make_error_response(
                        request,
                        "busy",
                        "too many routing tests are already running");
                } else {
                    auto snapshot = capture_routing_test_snapshot();
                    const auto request_snapshot = request;
                    const bool queued =
                        routing_test_executor_.try_post(
                            "ipc-test-routing",
                            [this,
                             client,
                             request_snapshot,
                             target,
                             operation_deadline,
                             snapshot = std::move(snapshot),
                             lease = std::move(*admitted)]() mutable {
                                UniqueSocketFd client_socket(client);
                                (void)lease;
                                nlohmann::json worker_response;
                                try {
                                    auto result = compute_test_routing(
                                        snapshot.config,
                                        list_service_.cache_manager(),
                                        target,
                                        &snapshot.realized_rules,
                                        operation_deadline,
                                        snapshot.firewall_backend);
                                    result.unapplied_draft =
                                        snapshot.unapplied_draft;
                                    if (result.unapplied_draft) {
                                        result.warnings.push_back(
                                            "An unapplied draft exists; diagnostics use the active applied configuration.");
                                    }

                                    nlohmann::json entries =
                                        nlohmann::json::array();
                                    for (const auto& entry :
                                         result.entries) {
                                        nlohmann::json entry_json = {
                                            {"ip", entry.ip},
                                            {"expected_outbound",
                                             entry.expected_outbound},
                                            {"actual_outbound",
                                             entry.actual_outbound},
                                            {"ok", entry.ok},
                                            {"evaluation",
                                             routing_match_evaluation_code(
                                                 entry.evaluation)},
                                            {"unknown_conditions",
                                             entry.unknown_conditions},
                                        };
                                        if (entry.list_match.has_value()) {
                                            entry_json["list_match"] = {
                                                {"list",
                                                 entry.list_match->list_name},
                                                {"via",
                                                 entry.list_match->via},
                                            };
                                        }
                                        entries.push_back(
                                            std::move(entry_json));
                                    }
                                    worker_response = {
                                        {"protocol_version",
                                         ipc::kControlProtocolVersion},
                                        {"request_id",
                                         request_snapshot.at("request_id")},
                                        {"ok", true},
                                        {"result",
                                         {{"target", result.target},
                                          {"config_scope", "active"},
                                          {"unapplied_draft",
                                           result.unapplied_draft},
                                          {"resolved_ips",
                                           result.resolved_ips},
                                          {"entries",
                                           std::move(entries)},
                                          {"warnings", result.warnings},
                                          {"dns_error",
                                           result.dns_error}}},
                                    };
                                } catch (const RoutingTestTimeoutError& error) {
                                    worker_response =
                                        ipc::make_error_response(
                                            request_snapshot,
                                            "timeout",
                                            error.what());
                                } catch (const std::exception& error) {
                                    worker_response =
                                        ipc::make_error_response(
                                            request_snapshot,
                                            "daemon_error",
                                            error.what());
                                } catch (...) {
                                    worker_response =
                                        ipc::make_error_response(
                                            request_snapshot,
                                            "daemon_error",
                                            "routing test failed with an unknown error");
                                }

                                try {
                                    const auto frame =
                                        ipc::encode_message(
                                            worker_response);
                                    ipc::send_all_bounded_nonblocking(
                                        client_socket.get(),
                                        frame.data(),
                                        frame.size(),
                                        kRoutingTestResponseSendTimeout);
                                } catch (const std::exception& error) {
                                    Logger::instance().warn(
                                        "test-routing control response failed: {}",
                                        error.what());
                                }
                            });
                    if (queued) {
                        stream_dispatched = true;
                    } else {
                        response = ipc::make_error_response(
                            request,
                            "busy",
                            "routing test executor queue is full");
                    }
                }
            } else if (operation == "generate-resolver-config") {
                const RuntimeState runtime_state =
                    runtime_state_machine_.state();
                // This pointer is immutable and is captured on the control
                // loop before any stream admission. A visibly broken runtime
                // may still serve its committed LKG only while routing is
                // genuinely active; stopped/shutdown and missing snapshots
                // stay fail-closed.
                const auto committed_resolver_generation =
                    resolver_generation_snapshot_;
                const std::string resolver_attempt_id =
                    request.value("resolver_attempt_id", "");
                RuntimeResolverStreamSelection selection;
                std::shared_ptr<const ResolverGenerationSnapshot>
                    inactive_activation_generation;
                std::string selection_error;
                if (!resolver_attempt_id.empty() &&
                    !is_valid_resolver_attempt_id(
                        resolver_attempt_id)) {
                    selection_error = "resolver_attempt_invalid";
                } else {
                    const auto active =
                        resolver_stream_attempt_owner_.select(
                            resolver_attempt_id,
                            committed_resolver_generation);
                    selection = active.selection;
                    inactive_activation_generation =
                        active.inactive_activation_generation;
                    if (selection.error !=
                        RuntimeResolverStreamSelectionError::none) {
                        selection_error.assign(
                            runtime_resolver_stream_selection_error_code(
                                selection.error));
                    }
                }
                const bool resolver_generation_available =
                    selection_error.empty() &&
                    runtime_resolver_stream_selection_available(
                        runtime_state,
                        routing_runtime_active(),
                        selection,
                        committed_resolver_generation,
                        inactive_activation_generation);
                if (!selection_error.empty()) {
                    response = ipc::make_error_response(
                        request,
                        selection_error,
                        selection_error == "resolver_stream_busy"
                            ? "a resolver stream is already in progress"
                            : (selection_error ==
                                       "resolver_generation_unavailable"
                                   ? "the committed resolver generation "
                                     "is no longer current"
                                   : "resolver attempt does not match "
                                     "the active stream"));
                } else if (!resolver_generation_available) {
                    const auto runtime_snapshot =
                        runtime_state_store_.snapshot();
                    response = ipc::make_error_response(
                        request,
                        resolver_runtime_reason(runtime_snapshot),
                        "resolver runtime is not active");
                } else {
                    auto generation = selection.generation;
                    const bool correlated_attempt =
                        selection.correlated_attempt;
                    if (!generation) {
                        response = ipc::make_error_response(
                            request,
                            "resolver_generation_unavailable",
                            "resolver generation is not available");
                    } else {
                    const Config& active_config = generation->config;
                    const auto dns_config =
                        active_config.dns.value_or(DnsConfig{});
                    const auto cache_dir =
                        active_config.daemon.value_or(DaemonConfig{})
                            .cache_dir.value_or("/var/cache/keen-pbr");
                    const auto requested_resolver =
                        request.value("resolver", "dnsmasq");
                    const auto type =
                        requested_resolver == "dnsmasq-ipset"
                            ? ResolverType::DNSMASQ_IPSET
                            : (requested_resolver == "dnsmasq-nftset"
                                   ? ResolverType::DNSMASQ_NFTSET
                                   : generation->resolver_type);
                    const auto request_id =
                        request.at("request_id").get<std::string>();
                    const bool queued =
                        resolver_stream_executor_.try_post(
                        "generate-resolver-config",
                        [this,
                         client,
                         generation,
                         dns_config,
                         cache_dir,
                         type,
                         request_id,
                         resolver_attempt_id,
                         correlated_attempt] {
                            bool stream_started = false;
                            bool stream_completed = false;
                            try {
                                const Config& active_config =
                                    generation->config;
                                CacheManager cache(
                                    cache_dir,
                                    max_file_size_bytes(active_config));
                                const RouteConfig empty_route_config;
                                const std::map<std::string, ListConfig>
                                    empty_lists;
                                const std::vector<RouteRule>
                                    empty_route_rules;
                                const std::vector<DnsRule> empty_dns_rules;
                                const RouteConfig& route_config =
                                    active_config.route.has_value()
                                        ? *active_config.route
                                        : empty_route_config;
                                const auto& lists =
                                    active_config.lists.has_value()
                                        ? *active_config.lists
                                        : empty_lists;
                                const auto& route_rules =
                                    route_config.rules.has_value()
                                        ? *route_config.rules
                                        : empty_route_rules;
                                const auto& dns_rules =
                                    dns_config.rules.has_value()
                                        ? *dns_config.rules
                                        : empty_dns_rules;
                                if (!generation->list_cache_snapshot) {
                                    throw ipc::ControlProtocolError(
                                        "resolver_generation_cache_unavailable");
                                }
                                std::set<std::string> referenced_lists;
                                for (const auto& rule : route_rules) {
                                    if (!route_rule_enabled(rule)) continue;
                                    for (const auto& list_name :
                                         route_rule_lists(rule)) {
                                        referenced_lists.insert(list_name);
                                    }
                                }
                                for (const auto& rule : dns_rules) {
                                    if (!dns_rule_enabled(rule)) continue;
                                    for (const auto& list_name : rule.list) {
                                        referenced_lists.insert(list_name);
                                    }
                                }
                                for (const auto& list_name :
                                     referenced_lists) {
                                    const auto list =
                                        lists.find(list_name);
                                    if (list == lists.end()) continue;
                                    if (list->second.url.has_value()) {
                                        if (!generation->list_cache_snapshot
                                                 ->contains(list_name)) {
                                            throw ipc::ControlProtocolError(
                                                "active_list_cache_mismatch");
                                        }
                                        if (generation->list_cache_snapshot
                                                ->find(list_name) == nullptr) {
                                            throw ipc::ControlProtocolError(
                                                "list_cache_missing");
                                        }
                                    }
                                    if (list->second.file.has_value() &&
                                        !std::filesystem::is_regular_file(
                                            list->second.file.value())) {
                                        throw ipc::ControlProtocolError(
                                            "active_list_cache_mismatch");
                                    }
                                }

                                const auto header = ipc::encode_message(
                                    {{"protocol_version",
                                      ipc::kControlProtocolVersion},
                                     {"request_id", request_id},
                                     {"ok", true},
                                     {"stream", true}});
                                send_all(
                                    client, header.data(), header.size());
                                stream_started = true;

                                SocketStreamBuffer buffer(client);
                                std::ostream output(&buffer);
                                output
                                    << "# keen-pbr resolver state: active\n";
                                ListStreamer streamer(
                                    cache,
                                    generation->list_cache_snapshot);
                                DnsServerRegistry registry(
                                    dns_config,
                                    generation->keenetic_dns.snapshot);
                                DnsmasqGenerator generator(
                                    registry,
                                    streamer,
                                    route_config,
                                    dns_config,
                                    lists,
                                    type,
                                    KEEN_PBR3_VERSION_FULL_STRING,
                                    generation->ipv6_policy,
                                    generation->trusted_dns_interfaces);
                                generator.generate(output);
                                output
                                    << "txt-record=resolver-state.keen.pbr,"
                                    << std::time(nullptr)
                                    << "|active|runtime_active\n";
                                output.flush();
                                if (!output) {
                                    throw ipc::ControlProtocolError(
                                        "resolver stream write failed");
                                }
                                const std::uint32_t end_of_stream = 0;
                                send_all(
                                    client,
                                    reinterpret_cast<const char*>(
                                        &end_of_stream),
                                    sizeof(end_of_stream));
                                stream_completed = true;
                            } catch (const std::exception& error) {
                                if (!stream_started) {
                                    try {
                                        const auto error_response =
                                            ipc::make_error_response(
                                                {{"request_id", request_id}},
                                                error.what(),
                                                error.what());
                                        const auto error_frame =
                                            ipc::encode_message(
                                                error_response);
                                        send_all(client,
                                                 error_frame.data(),
                                                 error_frame.size());
                                    } catch (...) {
                                    }
                                } else {
                                    Logger::instance().warn(
                                        "resolver config stream failed: {}",
                                        error.what());
                                }
                            }
                            ::close(client);
                            if (stream_completed && correlated_attempt) {
                                if (resolver_stream_attempt_owner_
                                        .record_completed_if_exact(
                                            resolver_attempt_id,
                                            generation->stream_epoch,
                                            generation)) {
                                    resolver_stream_coordinator_
                                        .notify_stream_completed(
                                            resolver_attempt_id,
                                            generation->stream_epoch);
                                }
                            }
                        });
                    if (queued) {
                        stream_dispatched = true;
                    } else {
                        response = ipc::make_error_response(
                            request,
                            "daemon_error",
                            "resolver stream executor is unavailable");
                    }
                    }
                }
            } else if (operation == "download") {
                const bool reload = request.value("reload", false);
                if (request.value("task_response", false)) {
                    const auto start = start_remote_list_refresh_task(
                        reload, "ipc");
                    if (!start.accepted) {
                        response = ipc::make_error_response(
                            request,
                            start.error == "busy" ? "busy" : "daemon_error",
                            start.error == "busy"
                                ? "another list refresh is in progress"
                                : start.error);
                    } else {
                        response = {
                            {"protocol_version",
                             ipc::kControlProtocolVersion},
                            {"request_id", request.at("request_id")},
                            {"ok", true},
                            {"result", list_refresh_task_json(start.task)},
                        };
                    }
                } else {
                    // Protocol-v1 callers need a terminal response, but the
                    // network operation must not run on the event-loop thread.
                    // Start the same bounded task and let a second executor
                    // slot wait for its terminal snapshot before replying in
                    // the legacy wire shape.
                    const auto start = start_remote_list_refresh_task(
                        reload, "ipc-legacy");
                    if (!start.accepted) {
                        response = ipc::make_error_response(
                            request,
                            start.error == "busy" ? "busy" : "daemon_error",
                            start.error == "busy"
                                ? "another list refresh is in progress"
                                : start.error);
                    } else {
                        const auto task_id = start.task.id;
                        const auto request_id =
                            request.at("request_id").get<std::string>();
                        const bool queued = blocking_executor_.try_post(
                            "ipc-legacy-list-refresh-response",
                            [this, client, task_id, request_id] {
                                nlohmann::json terminal_response;
                                try {
                                    std::optional<ListRefreshTaskSnapshot> task;
                                    do {
                                        std::this_thread::sleep_for(
                                            std::chrono::milliseconds(50));
                                        task = list_refresh_tasks_.find(task_id);
                                    } while (
                                        task &&
                                        !list_refresh_task_status_is_terminal(
                                            task->status));

                                    if (!task || !task->terminal_result) {
                                        terminal_response =
                                            ipc::make_error_response(
                                                {{"request_id", request_id}},
                                                "daemon_error",
                                                "list refresh task disappeared");
                                    } else {
                                        const auto& terminal =
                                            *task->terminal_result;
                                        const auto& refresh =
                                            terminal.refresh_result;
                                        const bool ok =
                                            task->status ==
                                                ListRefreshTaskStatus::Succeeded &&
                                            refresh.failed_lists.empty();
                                        terminal_response = {
                                            {"protocol_version",
                                             ipc::kControlProtocolVersion},
                                            {"request_id", request_id},
                                            {"ok", ok},
                                            {"result",
                                             {{"refreshed_lists",
                                               refresh.refreshed_lists},
                                              {"changed_lists",
                                               refresh.changed_lists},
                                              {"failed_lists",
                                               refresh.failed_lists},
                                              {"reloaded",
                                               terminal.reloaded}}},
                                        };
                                    }
                                    const auto frame =
                                        ipc::encode_message(terminal_response);
                                    send_all(
                                        client, frame.data(), frame.size());
                                } catch (const std::exception& error) {
                                    Logger::instance().warn(
                                        "legacy list refresh response failed: {}",
                                        error.what());
                                }
                                ::close(client);
                            });
                        if (queued) {
                            stream_dispatched = true;
                        } else {
                            (void)list_refresh_tasks_.request_cancel(task_id);
                            response = ipc::make_error_response(
                                request,
                                "daemon_error",
                                "list refresh response executor is unavailable");
                        }
                    }
                }
            } else if (operation == "download-status" ||
                       operation == "download-cancel") {
                const auto task_id = request.value("task_id", "");
                if (task_id.empty()) {
                    throw ipc::ControlProtocolError(
                        operation + " requires a task_id");
                }
                auto task = list_refresh_tasks_.find(task_id);
                if (!task) {
                    response = ipc::make_error_response(
                        request,
                        "not_found",
                        "list refresh task was not found");
                } else {
                    bool cancel_accepted = false;
                    if (operation == "download-cancel" &&
                        !list_refresh_task_status_is_terminal(
                            task->status)) {
                        cancel_accepted =
                            list_refresh_tasks_.request_cancel(task_id);
                        task = list_refresh_tasks_.find(task_id);
                    }
                    response = {
                        {"protocol_version",
                         ipc::kControlProtocolVersion},
                        {"request_id", request.at("request_id")},
                        {"ok", true},
                        {"result", list_refresh_task_json(*task)},
                    };
                    if (operation == "download-cancel") {
                        response["result"]["cancel_accepted"] =
                            cancel_accepted;
                    }
                }
            } else if (operation == "status") {
                const auto snapshot =
                    runtime_state_store_.snapshot();
                RoutingHealthReport routing_health;
                if (snapshot.runtime_state == RuntimeState::starting) {
                    routing_health.firewall_backend =
                        firewall_->backend();
                    routing_health.firewall_chain.detail =
                        "routing runtime initialization is in progress";
                } else {
                    routing_health = build_routing_health_report(
                        firewall_->backend(),
                        firewall_->raw_prerouting_mode(),
                        snapshot.firewall_state,
                        snapshot.route_specs,
                        snapshot.policy_rule_specs,
                        netlink_,
                        snapshot.routing_inventory_complete &&
                            snapshot.routing_kernel_state_known);
                }
                // Filled from the live backend rather than recomputed here:
                // the state is what the last apply actually observed, and
                // re-inspecting the chain from a status request would both
                // duplicate the writer and answer a different question.
                routing_health.ttl_bypass_state =
                    firewall_->ttl_bypass_state_name();
                routing_health.ttl_bypass_detail =
                    firewall_->ttl_bypass_state_detail();
                routing_health.ppe_deoffload =
                    firewall_->ppe_deoffload_snapshot();
                response = {
                    {"protocol_version",
                     ipc::kControlProtocolVersion},
                    {"request_id", request.at("request_id")},
                    {"ok", true},
                    {"result",
                     {{"runtime_state",
                       runtime_state_name(snapshot.runtime_state)},
                      {"config_path", config_path_},
                      {"config", config_store_.active_config()},
                      {"routing_health",
                       routing_health_report_to_json(
                           routing_health)},
                      {"runtime_state_reason",
                       snapshot.runtime_state_reason},
                      {"routing_runtime_active",
                       snapshot.routing_runtime_active},
                      {"resolver_config_hash",
                       snapshot.resolver_config_hash}}},
                };
            } else {
                const auto snapshot =
                    runtime_state_store_.snapshot();
                response = {
                    {"protocol_version",
                     ipc::kControlProtocolVersion},
                    {"request_id", request.at("request_id")},
                    {"ok", true},
                    {"result",
                     {{"resolver_config_hash",
                       snapshot.resolver_config_hash}}},
                };
            }
        } catch (const std::exception& error) {
            response = ipc::make_error_response(
                request, "protocol_error", error.what());
        }

        if (!stream_dispatched) {
            send_control_response_and_close(client, response);
        }
    }
}

void Daemon::wake_control_loop() {
    const uint64_t inc = 1;
    ssize_t n = -1;
    do {
        n = write(control_fd_, &inc, sizeof(inc));
    } while (n < 0 && errno == EINTR);
    // EAGAIN means the eventfd already contains a wake token, so the newly
    // queued task is covered by an existing readable edge.
    if (n < 0 && errno == EAGAIN) {
        return;
    }
    if (n != static_cast<ssize_t>(sizeof(inc))) {
        throw DaemonError("eventfd write failed: " + std::string(strerror(errno)));
    }
}

bool Daemon::cancel_control_task_if_still_queued(
    const daemon_detail::ControlTaskAdmissionHandle& token) noexcept {
    try {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        return daemon_detail::erase_exact_control_task_if_still_queued(
            control_tasks_, token, &ControlTask::admission_token);
    } catch (...) {
        // If exact rollback cannot obtain queue authority, do not claim that
        // the task was cancelled. The event loop may already own it.
        return false;
    }
}

void Daemon::quiesce_runtime_mutations() noexcept {
    runtime_firewall_owner_->pump_terminal_for_shutdown();
    auto next_warning = std::chrono::steady_clock::now() +
        std::chrono::seconds{5};
    while (!runtime_mutation_admission_.wait_for_idle_for(
        std::chrono::milliseconds{10})) {
        try {
            runtime_firewall_owner_->pump_terminal_for_shutdown();
            // An admitted resolver hook may still be waiting for dnsmasq's
            // config-script IPC request, while an API/SIGHUP writer may be
            // waiting for its terminal control callback. Keep both channels
            // alive until the exact mutation lease is returned, including
            // startup rollback where event_loop_active_ was never set.
            if (ipc_control_fd_ >= 0) {
                handle_ipc_control_socket();
            }
            if (control_fd_ >= 0) {
                handle_control_commands();
            }
            runtime_firewall_owner_->pump_terminal_for_shutdown();
        } catch (const std::exception& error) {
            try {
                Logger::instance().error(
                    "Runtime mutation shutdown drain failed: {}",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
            try {
                Logger::instance().error(
                    "Runtime mutation shutdown drain failed: unknown error");
            } catch (...) {
            }
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= next_warning) {
            try {
                const auto active = runtime_mutation_admission_.active();
                Logger::instance().warn(
                    "Waiting for admitted runtime mutation '{}' to finish",
                    active.has_value()
                        ? active->label
                        : std::string{"unknown"});
            } catch (...) {
            }
            next_warning = now + std::chrono::seconds{5};
        }
    }
    runtime_firewall_owner_->pump_terminal_for_shutdown();
}

void Daemon::quiesce_resolver_stream_recovery() noexcept {
    auto next_warning = std::chrono::steady_clock::now() +
        std::chrono::seconds{5};
    while (!resolver_stream_coordinator_.wait_for_idle_for(
        std::chrono::milliseconds{10})) {
        try {
            if (ipc_control_fd_ >= 0) {
                handle_ipc_control_socket();
            }
            if (control_fd_ >= 0) {
                handle_control_commands();
            }
        } catch (const std::exception& error) {
            try {
                Logger::instance().error(
                    "Resolver recovery shutdown drain failed: {}",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= next_warning) {
            try {
                Logger::instance().warn(
                    "Waiting for the accepted resolver recovery hook to "
                    "finish");
            } catch (...) {
            }
            next_warning = now + std::chrono::seconds{5};
        }
    }
}

bool Daemon::is_event_loop_thread() const {
    return event_loop_thread_id_.load(std::memory_order_relaxed) == std::this_thread::get_id();
}

void Daemon::enqueue_control_task(std::function<void()> task,
                                  bool wait_for_completion,
                                  const std::string& label,
                                  bool require_active_event_loop) {
    if (!task) {
        return;
    }

    const auto effective_label = label.empty() ? std::string("control-task") : label;
    const TraceId trace_id = ensure_trace_id();
    auto run_inline = [task = std::move(task), effective_label, trace_id]() mutable {
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        try {
            Logger::instance().trace(
                "control_task_start", "label={} mode=inline", effective_label);
        } catch (...) {
        }
        try {
            task();
            try {
                Logger::instance().trace(
                    "control_task_end",
                    "label={} mode=inline duration_ms={}",
                    effective_label,
                    steady_duration_ms(started_at));
            } catch (...) {
            }
        } catch (const std::exception& e) {
            try {
                Logger::instance().trace(
                    "control_task_error",
                    "label={} mode=inline duration_ms={} error={}",
                    effective_label,
                    steady_duration_ms(started_at),
                    e.what());
            } catch (...) {
            }
            throw;
        } catch (...) {
            try {
                Logger::instance().trace(
                    "control_task_error",
                    "label={} mode=inline duration_ms={} error=unknown",
                    effective_label,
                    steady_duration_ms(started_at));
            } catch (...) {
            }
            throw;
        }
    };

    if (!event_loop_active_.load(std::memory_order_acquire) ||
        event_loop_thread_id_.load(std::memory_order_relaxed) == std::thread::id{}) {
        if (require_active_event_loop) {
            throw DaemonError("control loop is not running");
        }
        run_inline();
        return;
    }

    if (event_loop_thread_id_.load(std::memory_order_relaxed) == std::this_thread::get_id()) {
        run_inline();
        return;
    }

    // This optimistic check keeps shutdown rejection out of the allocation
    // path. Shutdown closes the same gate under control_tasks_mutex_; the
    // mandatory in-lock recheck below is the actual linearization point.
    if (!accept_posted_control_tasks_.load(std::memory_order_acquire)) {
        throw DaemonError("control task admission is closed");
    }

    std::shared_ptr<std::promise<void>> completion;
    std::future<void> completion_future;
    std::function<void()> queued_callback;
    if (wait_for_completion) {
        completion = std::make_shared<std::promise<void>>();
        completion_future = completion->get_future();
        queued_callback =
            [cmd = std::move(run_inline), completion]() mutable {
                try {
                    cmd();
                    completion->set_value();
                } catch (...) {
                    completion->set_exception(std::current_exception());
                }
            };
    } else {
        queued_callback = std::move(run_inline);
    }

    const auto admission_token =
        std::make_shared<const daemon_detail::ControlTaskAdmissionToken>();
    auto queued_task = std::make_unique<ControlTask>(ControlTask{
        .callback = std::move(queued_callback),
        .label = effective_label,
        .trace_id = trace_id,
        .admission_token = admission_token,
    });
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        if (!daemon_detail::publish_control_task_if_admitted(
                control_tasks_,
                accept_posted_control_tasks_.load(
                    std::memory_order_acquire),
                std::move(queued_task))) {
            // The task never crossed the ownership boundary. In the waiting
            // case stack unwinding destroys every promise owner, so the
            // private future cannot become a stranded shutdown wait.
            throw DaemonError("control task admission closed during shutdown");
        }
    }
    try {
        Logger::instance().trace("control_task_enqueue",
                                 "label={} wait={}",
                                 effective_label,
                                 wait_for_completion ? "true" : "false");
    } catch (...) {
    }

    try {
        wake_control_loop();
    } catch (const std::exception& error) {
        const auto wake_failure = std::current_exception();
        if (cancel_control_task_if_still_queued(admission_token)) {
            // Exact rollback restored caller ownership. Complete the private
            // promise as well, then report rejection; no queued callback can
            // subsequently act on a descriptor the caller releases.
            if (completion) {
                try {
                    completion->set_exception(wake_failure);
                } catch (...) {
                }
            }
            std::rethrow_exception(wake_failure);
        }

        // The event loop already swapped this exact token out of the queue.
        // Its callback is authoritative; returning a wake error would cause
        // callers such as Scheduler to release resources still owned by it.
        try {
            Logger::instance().error(
                "Control task '{}' wake failed after the event loop claimed "
                "the task: {}",
                effective_label,
                error.what());
        } catch (...) {
        }
    } catch (...) {
        const auto wake_failure = std::current_exception();
        if (cancel_control_task_if_still_queued(admission_token)) {
            if (completion) {
                try {
                    completion->set_exception(wake_failure);
                } catch (...) {
                }
            }
            std::rethrow_exception(wake_failure);
        }
        try {
            Logger::instance().error(
                "Control task '{}' wake failed after the event loop claimed "
                "the task: unknown error",
                effective_label);
        } catch (...) {
        }
    }

    if (wait_for_completion) {
        // A claimed callback settles this future with its actual result. In
        // particular, task-body exceptions remain visible to the caller and
        // are never mistaken for a wake failure.
        completion_future.get();
    }
}

bool Daemon::post_control_task(std::function<void()> task, const std::string& label) {
    if (!task) return false;
    if (!accept_posted_control_tasks_.load(std::memory_order_acquire)) {
        Logger::instance().trace("control_task_skip",
                                 "label={} reason=posted_tasks_disabled",
                                 label.empty() ? "post-control-task" : label);
        return false;
    }

    const auto effective_label = label.empty() ? std::string("post-control-task") : label;
    const TraceId trace_id = ensure_trace_id();
    auto traced_task = [task = std::move(task), effective_label, trace_id]() mutable {
        ScopedTraceContext trace_scope(trace_id);
        const auto started_at = std::chrono::steady_clock::now();
        // Diagnostic logging must never decide whether an already-admitted
        // control task runs. In particular, an allocation failure while
        // formatting a trace event must not strand asynchronous ownership.
        try {
            Logger::instance().trace(
                "control_task_start", "label={} mode=posted", effective_label);
        } catch (...) {
        }
        try {
            task();
            try {
                Logger::instance().trace(
                    "control_task_end",
                    "label={} mode=posted duration_ms={}",
                    effective_label,
                    steady_duration_ms(started_at));
            } catch (...) {
            }
        } catch (const std::exception& e) {
            try {
                Logger::instance().trace(
                    "control_task_error",
                    "label={} mode=posted duration_ms={} error={}",
                    effective_label,
                    steady_duration_ms(started_at),
                    e.what());
            } catch (...) {
            }
            throw;
        } catch (...) {
            try {
                Logger::instance().trace(
                    "control_task_error",
                    "label={} mode=posted duration_ms={} error=unknown",
                    effective_label,
                    steady_duration_ms(started_at));
            } catch (...) {
            }
            throw;
        }
    };

    auto queued_task = std::make_unique<ControlTask>(ControlTask{
        .callback = std::move(traced_task),
        .label = effective_label,
        .trace_id = trace_id,
        .admission_token = {},
    });
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        // Serialize admission with shutdown. The optimistic check above keeps
        // the normal rejection path cheap; this second check prevents a task
        // from being queued after shutdown disabled deferred commits.
        if (!accept_posted_control_tasks_.load(
                std::memory_order_acquire)) {
            return false;
        }
        control_tasks_.push_back(std::move(queued_task));
    }
    try {
        Logger::instance().trace("control_task_enqueue",
                                 "label={} wait=false mode=post",
                                 effective_label);
    } catch (...) {
    }
    try {
        wake_control_loop();
    } catch (const std::exception& error) {
        // Ownership has already moved into control_tasks_. Returning false or
        // throwing here would let an asynchronous producer release its
        // lifetime while the queued callback still captures it. Keep the
        // enqueue authoritative; another epoll event or shutdown drain will
        // service the callback.
        try {
            Logger::instance().error(
                "Posted control task '{}' was queued but the control-loop "
                "wake failed: {}",
                effective_label,
                error.what());
        } catch (...) {
        }
    } catch (...) {
        // The callback is already owned by control_tasks_. Keep the enqueue
        // authoritative even when the wake or its diagnostics fail.
    }
    return true;
}

void Daemon::enqueue_control_command(std::function<void()> command,
                                     bool wait_for_completion,
                                     const std::string& label) {
    enqueue_control_task(std::move(command), wait_for_completion, label);
}

void Daemon::handle_control_commands() {
    uint64_t counter = 0;
    while (read(control_fd_, &counter, sizeof(counter)) > 0) {
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        throw DaemonError("eventfd read failed: " + std::string(strerror(errno)));
    }

    // Ingress frames are read and validated by the dedicated acceptor. Drain
    // them before unrelated deferred work so a ready CLI request is not left
    // behind a potentially expensive control callback.
    handle_ipc_control_socket();

    std::vector<ControlTaskOwner> commands;
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        commands.swap(control_tasks_);
    }

    for (auto& command : commands) {
        try {
            command->callback();
        } catch (const std::exception& error) {
            // One failed deferred callback must not discard the remaining
            // batch. Resolver and lifecycle completions may own single-flight
            // leases which are returned only by their callback.
            try {
                Logger::instance().error(
                    "Control task '{}' failed: {}",
                    command->label.empty()
                        ? "control-task"
                        : command->label,
                    error.what());
            } catch (...) {
            }
        } catch (...) {
            try {
                Logger::instance().error(
                    "Control task '{}' failed: unknown error",
                    command->label.empty()
                        ? "control-task"
                        : command->label);
            } catch (...) {
            }
        }
    }
}

void Daemon::setup_signals() {
    block_daemon_signals_for_current_thread();
    sigset_t mask = daemon_signal_mask();

    signal_fd_ = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd_ < 0) {
        throw DaemonError("signalfd failed: " + std::string(strerror(errno)));
    }

    struct epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = signal_fd_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, signal_fd_, &ev) < 0) {
        throw DaemonError("epoll_ctl add signalfd failed: " + std::string(strerror(errno)));
    }
}

bool Daemon::run_process_shutdown_cleanup() noexcept {
    bool stop_callbacks_fenced = false;
    try {
        // Admission idleness alone is insufficient: a background owner can
        // be parked before acquiring its lease. Retire those envelopes first
        // and prove both owner slots empty before consuming the one-shot
        // internal cleanup admission.
        runtime_firewall_owner_->prepare_for_process_cleanup();
        bool owner_ready = false;
        for (std::size_t attempt = 0U;
             attempt < 250U && !owner_ready;
             ++attempt) {
            runtime_firewall_owner_->pump_terminal_for_shutdown();
            const bool admission_idle =
                runtime_mutation_admission_.wait_for_idle_for(
                    std::chrono::milliseconds{0});
            owner_ready = runtime_shutdown_cleanup_owner_ready(
                admission_idle,
                static_cast<bool>(
                    runtime_firewall_owner_->active_context()),
                runtime_firewall_owner_->pending_successor());
            if (!owner_ready) {
                try {
                    if (ipc_control_fd_ >= 0) handle_ipc_control_socket();
                    if (control_fd_ >= 0) handle_control_commands();
                } catch (...) {
                }
                std::this_thread::sleep_for(
                    std::chrono::milliseconds{10});
            }
        }
        if (!runtime_shutdown_cleanup_owner_ready(
                owner_ready,
                static_cast<bool>(runtime_firewall_owner_->active_context()),
                runtime_firewall_owner_->pending_successor())) {
            Logger::instance().error(
                "Process STOP cleanup could not obtain an idle typed owner");
            return false;
        }

        auto admitted =
            runtime_mutation_admission_.try_acquire_shutdown_cleanup(
                "process-shutdown-stop-cleanup");
        if (!admitted.has_value()) {
            Logger::instance().error(
                "Process STOP cleanup one-shot admission was rejected");
            return false;
        }
        auto lease = std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(*admitted));
        const auto expected_token = lease->token();
        auto completion = RuntimeFirewallLifecycleCompletion::create();
        auto completion_source = std::move(completion.source);
        RuntimeFirewallPreownedTerminalContinuation continuation{
            [this,
             expected_token,
             completion_source = std::move(completion_source)](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                mutable noexcept {
                // Shutdown quiescence waits for the admission to become idle;
                // release only after TerminalOwner supplied its exact proof.
                if (!runtime_stop_cleanup_exact_lease_returned(
                        runtime_mutation_admission_,
                        expected_token,
                        exact)) {
                    terminal.outcome =
                        RuntimeFirewallLifecycleOutcome::not_verified;
                    terminal.commit_ambiguous = true;
                    try {
                        terminal.detail =
                            "process STOP owner did not return its exact lease";
                    } catch (...) {
                    }
                }
                exact.reset();
                (void)completion_source.settle(std::move(terminal));
            }};

        RuntimeStopCleanupTarget target;
        target.intent = RuntimeStopCleanupIntent::process_shutdown;
        target.runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        target.cleanup_conntrack = false;
        target.deactivate_resolver = true;
        target.maximum_attempts = 3U;
        fence_exact_tcp_reset_cleanups_for_stop();
        stop_callbacks_fenced = true;
        if (!begin_preowned_runtime_firewall_stop_cleanup(
                lease, std::move(target), continuation)) {
            resume_exact_tcp_reset_cleanups();
            stop_callbacks_fenced = false;
            lease.reset();
            Logger::instance().error(
                "Process STOP cleanup owner handoff was rejected");
            return false;
        }
        stop_callbacks_fenced = false;

        // This control/event-loop thread pumps typed worker terminals and the
        // resolver IPC rendezvous; it never waits on its own queue.
        quiesce_runtime_mutations();
        const auto terminal = completion.wait.try_get();
        if (!terminal.has_value() || terminal->outcome !=
                RuntimeFirewallLifecycleOutcome::verified_success) {
            Logger::instance().error(
                "Process STOP cleanup did not reach a verified terminal{}{}",
                terminal.has_value() && !terminal->detail.empty()
                    ? ": "
                    : "",
                terminal.has_value() ? terminal->detail : "missing result");
            return false;
        }
        return true;
    } catch (const std::exception& error) {
        if (stop_callbacks_fenced) {
            resume_exact_tcp_reset_cleanups();
            stop_callbacks_fenced = false;
        }
        try {
            Logger::instance().error(
                "Process STOP cleanup failed: {}", error.what());
        } catch (...) {
        }
    } catch (...) {
        if (stop_callbacks_fenced) {
            resume_exact_tcp_reset_cleanups();
            stop_callbacks_fenced = false;
        }
        try {
            Logger::instance().error(
                "Process STOP cleanup failed with an unknown error");
        } catch (...) {
        }
    }
    return false;
}

void Daemon::handle_signal() {
    bool terminate_requested = false;
    bool full_refresh_requested = false;
    bool nat_refresh_requested = false;
    bool reload_requested = false;

    // signalfd is nonblocking. Inspect the complete queued batch before
    // dispatching any non-terminal work so SIGUSR1/2 queued beside SIGTERM
    // cannot reopen runtime work during shutdown.
    for (;;) {
        struct signalfd_siginfo info{};
        const ssize_t n = read(signal_fd_, &info, sizeof(info));
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        if (n != sizeof(info)) {
            break;
        }
        switch (info.ssi_signo) {
        case SIGTERM:
        case SIGINT:
            terminate_requested = true;
            break;
        case SIGUSR1:
            full_refresh_requested = true;
            break;
        case SIGUSR2:
            nat_refresh_requested = true;
            break;
        case SIGHUP:
            reload_requested = true;
            break;
        default:
            break;
        }
    }

    if (terminate_requested) {
        // Close writer admission at the terminal signal boundary, not later
        // in the shutdown tail. Events already returned in this epoll batch
        // must not begin a new config or routing-test operation.
        runtime_mutation_admission_.shutdown();
        routing_test_admission_.shutdown();
        running_.store(false, std::memory_order_release);
        return;
    }
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    if (full_refresh_requested) {
        handle_sigusr1();
    }
    if (nat_refresh_requested) {
        handle_sigusr2();
    }
    if (reload_requested) {
        handle_sighup();
    }
}

void Daemon::handle_sigusr1() {
    auto& log = Logger::instance();
    log.info("SIGUSR1: scheduling full firewall refresh...");
    schedule_netfilter_runtime_refresh(NetfilterRefreshReason::full);
}

void Daemon::handle_sigusr2() {
    auto& log = Logger::instance();
    log.info("SIGUSR2: scheduling NAT firewall refresh...");
    schedule_netfilter_runtime_refresh(NetfilterRefreshReason::nat_only);
}

void Daemon::schedule_owned_snat_health_check() {
    if (owned_snat_health_task_id_ >= 0) {
        return;
    }
    owned_snat_health_task_id_ = scheduler_->schedule_repeating(
        OWNED_SNAT_HEALTH_INTERVAL,
        [this]() { check_owned_snat_health(); },
        "owned-snat-health");
}

void Daemon::cancel_owned_snat_health_check() {
    if (owned_snat_health_task_id_ < 0) {
        return;
    }
    scheduler_->cancel(owned_snat_health_task_id_);
    owned_snat_health_task_id_ = -1;
}

void Daemon::check_owned_snat_health() {
    if (should_run_periodic_netfilter_refresh(
            netfilter_refresh_task_id_ >= 0,
            pending_netfilter_refresh_reasons_ != 0U)) {
        // A failed timer installation retains the exact full/NAT reason bits.
        // Repair the main firewall generation before any companion subsystem;
        // a verified central refresh will then request remote-access recovery.
        reconcile_pending_netfilter_runtime_refresh();
        return;
    }
    const std::uint64_t failed_completion_serial =
        meta_udp443_cleanup_completion_admission_failed_serial_.exchange(
            0U, std::memory_order_acq_rel);
    if (failed_completion_serial != 0U) {
        if (pending_meta_udp443_cleanup_.has_value() &&
            meta_udp443_failed_completion_matches_pending(
                failed_completion_serial,
                pending_meta_udp443_cleanup_->schedule_serial)) {
            pending_meta_udp443_cleanup_->worker_inflight = false;
            report_meta_udp443_degraded(
                "an exact-cleanup worker completion could not be admitted to "
                "the control loop; the durable plan will be retried");
        }
    }
    const bool runtime_retry_pending =
        runtime_firewall_retry_.retry_pending();
    const bool netfilter_refresh_pending =
        netfilter_refresh_task_id_ >= 0 ||
        pending_netfilter_refresh_reasons_ != 0;
    const auto current_runtime_generation =
        runtime_generation_.load(std::memory_order_acquire);
    const bool urltest_recovery_without_timer =
        should_run_periodic_urltest_firewall_recovery(
            routing_runtime_active(),
            urltest_after_firewall_gate_.waiting_for(
                current_runtime_generation),
            runtime_retry_pending,
            netfilter_refresh_pending);
    if (urltest_recovery_without_timer) {
        // Scheduler admission itself can fail after a transient URLTEST
        // publication. This repeating control-loop task is the independent
        // durable owner: a closed gate can therefore never wait forever for
        // another external netfilter event.
        auto task_metrics =
            periodic_task_metrics_.begin("owned-snat-health");
        (void)refresh_iproute_and_firewall_runtime(
            0,
            {},
            /*schedule_catalog_refresh=*/false,
            runtime_firewall_retry_
                .pending_owned_snat_recovery(),
            RuntimeFirewallImmediateCompletionIntent::
                periodic_urltest(std::move(task_metrics)));
        return;
    }
    const bool owned_snat_recovery_without_timer =
        should_run_periodic_owned_snat_firewall_recovery(
            routing_runtime_active(),
            runtime_firewall_retry_.owned_snat_recovery_pending(),
            runtime_retry_pending,
            netfilter_refresh_pending);
    if (owned_snat_recovery_without_timer) {
        // A pre-claim transport rejection can leave the exact SNAT recovery
        // latched without a one-shot timer. This existing periodic owner is
        // the maintenance cadence after the bounded immediate chain ends.
        auto task_metrics =
            periodic_task_metrics_.begin("owned-snat-health");
        (void)refresh_iproute_and_firewall_runtime(
            0,
            {},
            /*schedule_catalog_refresh=*/false,
            runtime_firewall_retry_.pending_owned_snat_recovery(),
            RuntimeFirewallImmediateCompletionIntent::
                periodic_owned_firewall(std::move(task_metrics)));
        return;
    }
    const bool resolver_recovery_without_timer =
        should_run_periodic_resolver_reload_recovery(
            routing_runtime_active(),
            resolver_reload_retry_task_id_ >= 0,
            resolver_reload_retry_pending_,
            resolver_after_firewall_gate_.waiting_for(
                current_runtime_generation),
            resolver_reload_retry_pending_generation_,
            current_runtime_generation);
    if (resolver_recovery_without_timer) {
        const auto attempt = resolver_reload_retry_pending_attempt_;
        const auto generation =
            resolver_reload_retry_pending_generation_;
        resolver_reload_retry_pending_ = false;
        resolver_reload_retry_pending_attempt_ = 0U;
        resolver_reload_retry_pending_generation_ = 0U;
        start_resolver_reload_retry_attempt(attempt, generation);
        return;
    }
    const bool recovery_pending =
        runtime_retry_pending ||
        runtime_firewall_retry_.owned_snat_recovery_pending();
    if (!routing_runtime_active() ||
        recovery_pending ||
        netfilter_refresh_pending) {
        periodic_task_metrics_.record_skipped(
            "owned-snat-health",
            !routing_runtime_active()
                ? "routing runtime is inactive"
                : "netfilter recovery is already pending");
        return;
    }

    // Reuse this already serialized control-loop cadence for PPE liveness.
    // A fresh NFQWS observation detects external init/process/queue changes;
    // a semantic counter read validates that the installed graph still equals
    // the published one. Either drift source coalesces into the existing FULL
    // netfilter refresh owner. API/IPC getters remain passive.
    const auto stored_ppe_desired = firewall_->ppe_deoffload_desired();
    const bool configured_ppe_auto =
        config_.daemon.value_or(DaemonConfig{})
            .ppe_deoffload_mode.value_or(api::PpeDeoffloadMode::OFF) ==
        api::PpeDeoffloadMode::AUTO;
    const bool ppe_liveness_owned = configured_ppe_auto ||
        stored_ppe_desired.mode == PpeDeoffloadMode::automatic;
    bool ppe_desired_drift = false;
    try {
        const auto observed_ppe_desired =
            observe_ppe_deoffload_desired(config_);
        ppe_desired_drift =
            !ppe_deoffload_desired_semantically_equal(
                stored_ppe_desired, observed_ppe_desired);
    } catch (...) {
        // An auto-mode observer failure cannot prove the old active contract.
        // Let the normal full-refresh/retry path establish cleanup or a fresh
        // graph; off mode is intentionally a no-observation path.
        ppe_desired_drift = configured_ppe_auto;
    }
    if (should_schedule_periodic_ppe_full_refresh(
            routing_runtime_active(),
            recovery_pending,
            netfilter_refresh_pending,
            ppe_liveness_owned,
            ppe_desired_drift,
            /*live_graph_semantic_drift=*/false)) {
        schedule_netfilter_runtime_refresh(NetfilterRefreshReason::full);
        periodic_task_metrics_.record_skipped(
            "owned-snat-health",
            "PPE active-runtime contract drift scheduled a full refresh");
        return;
    }

    const auto ppe_observation =
        firewall_->refresh_ppe_deoffload_observation();
    if (should_schedule_periodic_ppe_full_refresh(
            routing_runtime_active(),
            recovery_pending,
            netfilter_refresh_pending,
            ppe_liveness_owned,
            /*desired_contract_drift=*/false,
            ppe_observation ==
                PpeObservationRefreshResult::semantic_drift)) {
        schedule_netfilter_runtime_refresh(NetfilterRefreshReason::full);
        periodic_task_metrics_.record_skipped(
            "owned-snat-health",
            "PPE live graph drift scheduled a full refresh");
        return;
    }

    auto task_metrics =
        periodic_task_metrics_.begin("owned-snat-health");
    OwnedSnatState state = OwnedSnatState::unknown;
    OwnedForwardUdpRejectState meta_state =
        OwnedForwardUdpRejectState::unknown;
    try {
        state = firewall_->inspect_owned_snat_state();
        meta_state = firewall_->inspect_forward_udp_reject_state();
    } catch (const std::exception& error) {
        // This is a fallback guard, not an alert source. An inspection error
        // must neither disrupt the event loop nor emit one message per tick.
        task_metrics.failure(error.what());
        return;
    } catch (...) {
        task_metrics.failure("owned SNAT inspection failed");
        return;
    }
    const auto meta_selection = resolve_meta_udp_443_policy_selection(
        config_,
        firewall_state_.get_rules(),
        firewall_state_.get_fwmark_mask());
    const bool messages_first_active = meta_selection.active();
    const bool fastnat_disabled =
        !messages_first_active || fastnat_is_disabled_or_unavailable();
    const bool repair_snat = should_run_periodic_snat_repair(
            routing_runtime_active(),
            recovery_pending,
            netfilter_refresh_pending,
            state);
    const bool repair_meta =
        should_run_periodic_forward_udp_reject_repair(
            routing_runtime_active(),
            recovery_pending,
            netfilter_refresh_pending,
            messages_first_active,
            fastnat_disabled,
            meta_state);
    if (should_resume_pending_meta_udp443_cleanup(
            messages_first_active,
            fastnat_disabled,
            meta_state,
            meta_udp443_cleanup_retry_task_id_,
            pending_meta_udp443_cleanup_.has_value(),
            pending_meta_udp443_cleanup_.has_value() &&
                pending_meta_udp443_cleanup_->worker_inflight)) {
        const auto& pending = *pending_meta_udp443_cleanup_;
        schedule_meta_udp443_activation_cleanup_retry(
            pending.plan,
            pending.runtime_generation,
            pending.cleanup_epoch,
            pending.attempt);
        if (meta_udp443_cleanup_retry_task_id_ < 0) {
            task_metrics.failure(
                "Meta UDP/443 exact cleanup retry could not be scheduled");
            return;
        }
    }
    if (messages_first_active && !fastnat_disabled) {
        // Reapplying the filter cannot repair a bypass outside netfilter and
        // would discard the durable exact-cleanup plan at apply entry. Keep
        // the current committed policy and pending plan intact until the init
        // layer or firmware restores verified FastNAT-off traversal.
        report_meta_udp443_degraded(
            "FastNAT is enabled while messages-first is active");
        task_metrics.failure(
            "Meta UDP/443 policy requires FastNAT to remain disabled");
        return;
    }
    if (!repair_snat && !repair_meta) {
        if (meta_state == OwnedForwardUdpRejectState::unknown) {
            task_metrics.failure(
                "Meta UDP/443 policy health could not be inspected");
            return;
        }
        task_metrics.noop();
        return;
    }

    if (repair_meta) {
        report_meta_udp443_degraded(
            !fastnat_disabled
                ? "FastNAT is enabled while messages-first is active"
                : (meta_state == OwnedForwardUdpRejectState::missing
                       ? "the owned first FORWARD hook or rule is missing"
                       : "owned UDP/443 blocking artifacts are stale"));
    }
    Logger::instance().info(
        "Periodic owned-firewall health check detected drift; repairing {}{}.",
        repair_snat ? "SNAT" : "",
        repair_meta
            ? (repair_snat ? " and Meta UDP/443" : "Meta UDP/443")
            : "");
    (void)refresh_iproute_and_firewall_runtime(
        0,
        {},
        /*schedule_catalog_refresh=*/false,
        OwnedSnatRecovery{
            /*requested=*/repair_snat,
            /*missing_observed=*/false},
        RuntimeFirewallImmediateCompletionIntent::
            periodic_owned_firewall(std::move(task_metrics)));
}

void Daemon::reconcile_pending_netfilter_runtime_refresh() noexcept {
    const std::uint8_t reasons = pending_netfilter_refresh_reasons_;
    if (reasons == 0U) {
        netfilter_refresh_batch_started_at_.reset();
        return;
    }
    pending_netfilter_refresh_reasons_ = 0U;
    netfilter_refresh_batch_started_at_.reset();

    try {
        const bool full_refresh =
            (reasons &
             static_cast<std::uint8_t>(NetfilterRefreshReason::full)) != 0U;
        const bool nat_refresh =
            (reasons &
             static_cast<std::uint8_t>(NetfilterRefreshReason::nat_only)) != 0U;
        const bool snat_health_check = full_refresh || nat_refresh;
        const char* reason_label =
            full_refresh && nat_refresh
                ? "full+nat"
                : (full_refresh ? "full" : "nat");

        Logger::instance().info(
            "Netfilter event: applying {} runtime refresh...",
            reason_label);
        if (runtime_firewall_owner_->foreground_lifecycle_pending()) {
            // START/restart already owns the one exact writer lease. Retain
            // this firmware event behind that chain instead of cancelling its
            // timer or dropping the source merely because routing has not yet
            // reached active state.
            runtime_firewall_owner_->defer(
                /*attempt=*/0U,
                runtime_generation_.load(std::memory_order_acquire),
                {},
                /*schedule_catalog_refresh=*/true,
                OwnedSnatRecovery{
                    /*requested=*/snat_health_check,
                    /*missing_observed=*/false});
            Logger::instance().info(
                "Netfilter event: {} runtime refresh was retained behind "
                "the active lifecycle operation.",
                reason_label);
            return;
        }
        if (nat_refresh && runtime_firewall_retry_.retry_pending()) {
            // Do not coalesce away a confirmed firmware NAT rebuild behind an
            // older generic recovery. Replace that retry with an immediate
            // attempt whose bounded chain verifies SNAT health.
            runtime_firewall_owner_->cancel_retry();
        }
        const bool targeted_urltest_recovery_pending =
            urltest_after_firewall_gate_.waiting_for(
                runtime_generation_.load(std::memory_order_acquire));
        const auto runtime_refresh_disposition =
            refresh_iproute_and_firewall_runtime(
                0,
                {},
                /*schedule_catalog_refresh=*/true,
                OwnedSnatRecovery{
                    /*requested=*/snat_health_check,
                    /*missing_observed=*/false},
                RuntimeFirewallImmediateCompletionIntent::netfilter(
                    full_refresh,
                    targeted_urltest_recovery_pending));

        if (runtime_refresh_disposition ==
            RuntimeFirewallImmediateDisposition::rejected) {
            const bool runtime_active = routing_runtime_active();
            const bool owner_shutdown =
                runtime_firewall_owner_->shutdown_requested();
            pending_netfilter_refresh_reasons_ =
                retain_netfilter_refresh_reasons_after_immediate_disposition(
                    pending_netfilter_refresh_reasons_,
                    reasons,
                    runtime_refresh_disposition,
                    runtime_active,
                    owner_shutdown);
            if (runtime_active && !owner_shutdown) {
                // Re-arm the existing bounded debounce owner. This does not
                // re-send configuration inline and preserves both FULL and
                // NAT source bits from the same firmware burst.
                schedule_netfilter_runtime_refresh(
                    full_refresh ? NetfilterRefreshReason::full
                                 : NetfilterRefreshReason::nat_only);
                Logger::instance().info(
                    "Netfilter event: {} runtime refresh was not accepted; "
                    "the exact source event remains scheduled.",
                    reason_label);
            } else {
                Logger::instance().verbose(
                    "Netfilter event: {} runtime refresh was ignored because "
                    "routing is stopped or the firewall owner is shutting "
                    "down.",
                    reason_label);
            }
        } else if (runtime_refresh_disposition ==
                   RuntimeFirewallImmediateDisposition::handed_off) {
            Logger::instance().info(
                "Netfilter event: {} runtime refresh handed to the firewall "
                "worker.",
                reason_label);
        } else {
            Logger::instance().info(
                "Netfilter event: {} runtime refresh deferred or coalesced "
                "with recovery.",
                reason_label);
        }
    } catch (const std::exception& error) {
        // Scheduler/fd/allocation faults in a secondary recovery path must not
        // escape the signal callback and terminate the daemon. Retain the exact
        // source bits; the independent periodic health owner will retry them.
        pending_netfilter_refresh_reasons_ |= reasons;
        try {
            Logger::instance().info(
                "Netfilter runtime refresh remains pending after an internal "
                "recovery error: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        pending_netfilter_refresh_reasons_ |= reasons;
    }
}

void Daemon::schedule_netfilter_runtime_refresh(
    NetfilterRefreshReason reason) noexcept {
    pending_netfilter_refresh_reasons_ |=
        static_cast<std::uint8_t>(reason);
    const bool full_refresh_pending =
        (pending_netfilter_refresh_reasons_ &
         static_cast<std::uint8_t>(NetfilterRefreshReason::full)) != 0U;
    const auto schedule = plan_netfilter_refresh(
        std::chrono::steady_clock::now(),
        netfilter_refresh_batch_started_at_,
        full_refresh_pending);
    netfilter_refresh_batch_started_at_ = schedule.batch_started_at;
    const std::uint64_t schedule_serial =
        ++netfilter_refresh_schedule_serial_;
    try {
        if (netfilter_refresh_task_id_ >= 0) {
            // Invalidate the callback and relinquish the id before cancel().
            // Scheduler::cancel can erase its entry and then throw while
            // removing the fd; retaining that id would wedge every later
            // health check behind a timer that no longer exists.
            const int stale_task_id = netfilter_refresh_task_id_;
            netfilter_refresh_task_id_ = -1;
            scheduler_->cancel(stale_task_id);
        }

        netfilter_refresh_task_id_ = scheduler_->schedule_oneshot(
            schedule.delay,
            [this, schedule_serial]() {
                if (!netfilter_refresh_callback_is_current(
                    schedule_serial,
                    netfilter_refresh_schedule_serial_)) {
                    return;
                }
                netfilter_refresh_task_id_ = -1;
                reconcile_pending_netfilter_runtime_refresh();
            },
            "netfilter-runtime-refresh");
    } catch (const std::exception& error) {
        // No callback with this serial owns the work. Keep its exact reason
        // bits for the independent periodic owner. Do not reconcile inline:
        // post-publication callers can still hold the main firewall mutation
        // lock, and recursive apply would deadlock that safety boundary.
        netfilter_refresh_task_id_ = -1;
        netfilter_refresh_batch_started_at_.reset();
        try {
            Logger::instance().info(
                "Netfilter refresh timer could not be installed: {}. "
                "The periodic runtime health owner retained the refresh.",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        netfilter_refresh_task_id_ = -1;
        netfilter_refresh_batch_started_at_.reset();
    }
}

#ifdef WITH_API
void Daemon::schedule_remote_access_recovery_watchdog() {
    if (remote_access_recovery_watchdog_task_id_ >= 0) return;
    if (!scheduler_) {
        throw std::logic_error(
            "remote-access recovery watchdog requires a scheduler");
    }
    remote_access_recovery_watchdog_task_id_ =
        scheduler_->schedule_repeating(
            REMOTE_ACCESS_RECOVERY_WATCHDOG_INTERVAL,
            [this]() { resume_unscheduled_remote_access_retry(); },
            "remote-access-recovery-watchdog");
}

void Daemon::cancel_remote_access_recovery_watchdog() noexcept {
    if (remote_access_recovery_watchdog_task_id_ < 0) return;
    const int task_id = remote_access_recovery_watchdog_task_id_;
    remote_access_recovery_watchdog_task_id_ = -1;
    if (!scheduler_) return;
    try {
        scheduler_->cancel(task_id);
    } catch (const std::exception& error) {
        try {
            Logger::instance().info(
                "Remote-access recovery watchdog cancellation failed: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
    }
}

void Daemon::setup_remote_access_retry_bridge() {
    const auto bridge_epoch =
        remote_access_retry_bridge_epoch_.fetch_add(
            1U, std::memory_order_acq_rel) + 1U;
    set_remote_access_retry_scheduler(
        [this, bridge_epoch](const RemoteAccessRetryHint& hint) {
            const bool posted = post_control_task(
                [this, hint, bridge_epoch]() {
                    if (remote_access_retry_bridge_epoch_.load(
                            std::memory_order_acquire) != bridge_epoch) {
                        return;
                    }
                    schedule_remote_access_retry(hint);
                },
                "remote-access-retry-hint");
            if (!posted) {
                throw std::runtime_error(
                    "daemon control loop is not accepting remote-access "
                    "recovery work");
            }
        });
}

void Daemon::reset_remote_access_retry_bridge() noexcept {
    remote_access_retry_bridge_epoch_.fetch_add(
        1U, std::memory_order_acq_rel);
    try {
        reset_remote_access_retry_scheduler();
    } catch (...) {
    }
    ++remote_access_retry_schedule_serial_;
    unscheduled_remote_access_retry_generation_.reset();
    if (remote_access_retry_task_id_ < 0 || !scheduler_) {
        remote_access_retry_task_id_ = -1;
        return;
    }
    const int task_id = remote_access_retry_task_id_;
    remote_access_retry_task_id_ = -1;
    try {
        scheduler_->cancel(task_id);
    } catch (const std::exception& error) {
        try {
            Logger::instance().info(
                "Remote-access retry cancellation failed: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
    }
}

void Daemon::schedule_remote_access_retry(
    const RemoteAccessRetryHint& hint) {
    if (!hint.schedule || hint.generation == 0U || !scheduler_) {
        return;
    }
    const auto status = remote_access_runtime_status();
    if (status.desired_generation != hint.generation) {
        if (unscheduled_remote_access_retry_generation_ ==
            hint.generation) {
            unscheduled_remote_access_retry_generation_.reset();
        }
        return;
    }

    const std::uint64_t schedule_serial =
        ++remote_access_retry_schedule_serial_;
    if (remote_access_retry_task_id_ >= 0) {
        const int stale_task_id = remote_access_retry_task_id_;
        remote_access_retry_task_id_ = -1;
        try {
            scheduler_->cancel(stale_task_id);
        } catch (const std::exception& error) {
            try {
                Logger::instance().info(
                    "Replacing remote-access retry after timer cancellation "
                    "reported an error: {}",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
        }
    }

    if (hint.delay <= std::chrono::milliseconds{0}) {
        // A zero timerfd interval is disarmed on Linux. The bridge callback
        // has already posted us onto the control loop, so execute this
        // deferred/trailing generation directly and let its result publish
        // the next non-zero retry hint when needed.
        const std::string listen =
            config_.api.has_value()
                ? config_.api->listen.value_or(std::string{})
                : std::string{};
        unscheduled_remote_access_retry_generation_.reset();
        try {
            (void)retry_remote_access_reconcile(
                hint.generation, listen);
        } catch (...) {
            unscheduled_remote_access_retry_generation_ =
                hint.generation;
        }
        return;
    }

    unscheduled_remote_access_retry_generation_ = hint.generation;
    try {
        remote_access_retry_task_id_ = scheduler_->schedule_oneshot(
            hint.delay,
            [this, hint, schedule_serial]() {
                if (schedule_serial !=
                    remote_access_retry_schedule_serial_) {
                    return;
                }
                remote_access_retry_task_id_ = -1;
                if (!running_.load(std::memory_order_acquire)) {
                    return;
                }
                const std::string listen =
                    config_.api.has_value()
                        ? config_.api->listen.value_or(std::string{})
                        : std::string{};
                try {
                    (void)retry_remote_access_reconcile(
                        hint.generation, listen);
                } catch (...) {
                    unscheduled_remote_access_retry_generation_ =
                        hint.generation;
                }
            },
            hint.maintenance
                ? "remote-access-maintenance-retry"
                : "remote-access-retry");
    } catch (const std::exception& error) {
        remote_access_retry_task_id_ = -1;
        try {
            Logger::instance().info(
                "Remote-access recovery timer could not be installed: {}. "
                "The periodic runtime health owner will retry it.",
                error.what());
        } catch (...) {
        }
        return;
    }
    if (remote_access_retry_task_id_ >= 0) {
        unscheduled_remote_access_retry_generation_.reset();
    }
}

void Daemon::resume_unscheduled_remote_access_retry() noexcept {
    std::optional<std::uint64_t> generation =
        unscheduled_remote_access_retry_generation_;
    try {
        const auto status = remote_access_runtime_status();
        if (generation.has_value() &&
            status.desired_generation != *generation) {
            unscheduled_remote_access_retry_generation_.reset();
            generation.reset();
        }
        if (!should_run_periodic_remote_access_recovery(
                remote_access_retry_task_id_ >= 0,
                generation.has_value(),
                status.desired_generation != 0U,
                status.recovery_owned)) {
            return;
        }
        generation = status.desired_generation;
        const std::string listen =
            config_.api.has_value()
                ? config_.api->listen.value_or(std::string{})
                : std::string{};
        unscheduled_remote_access_retry_generation_.reset();
        (void)retry_remote_access_reconcile(*generation, listen);
    } catch (const std::exception& error) {
        if (generation.has_value()) {
            unscheduled_remote_access_retry_generation_ = *generation;
        }
        try {
            Logger::instance().info(
                "Periodic remote-access recovery remains deferred: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        if (generation.has_value()) {
            unscheduled_remote_access_retry_generation_ = *generation;
        }
    }
}

void Daemon::request_remote_access_reconcile_from_control(
    std::string_view source) noexcept {
    try {
        const auto status = remote_access_runtime_status();
        const bool retry_owns_next_attempt =
            should_coalesce_remote_access_runtime_refresh(
                remote_access_retry_task_id_ >= 0,
                unscheduled_remote_access_retry_generation_.has_value(),
                status.desired_generation != 0U,
                status.state == RemoteAccessRuntimeState::pending ||
                    status.state == RemoteAccessRuntimeState::degraded,
                status.recovery_owned);
        if (retry_owns_next_attempt) {
            Logger::instance().trace(
                "remote_access_refresh_coalesced",
                "source={} generation={} reason=recovery_already_owned",
                source,
                status.desired_generation);
            return;
        }
        const std::string listen =
            config_.api.has_value()
                ? config_.api->listen.value_or(std::string{})
                : std::string{};
        (void)refresh_remote_access_reconcile(listen);
    } catch (const std::exception& error) {
        try {
            Logger::instance().error(
                "Cannot request remote-access firewall reconciliation after "
                "{}: {}",
                source,
                error.what());
        } catch (...) {
        }
    } catch (...) {
    }
}
#endif

Daemon::RoutingTestSnapshot Daemon::capture_routing_test_snapshot() {
    if (!is_event_loop_thread()) {
        throw std::logic_error(
            "routing test snapshot must be captured on the control loop");
    }
    const auto active = config_store_.pin_active_snapshot();
    return RoutingTestSnapshot{
        active->config,
        firewall_state_.get_rules(),
        firewall_->backend(),
        config_store_.config_is_draft(),
    };
}

void Daemon::schedule_netfilter_runtime_refresh_noexcept(
    NetfilterRefreshReason reason,
    const char* failure_detail) noexcept {
    (void)failure_detail;
    schedule_netfilter_runtime_refresh(reason);
}

void Daemon::handle_sighup() {
    auto& log = Logger::instance();
    const auto request = sighup_reload_coordinator_.request();
    if (request.status == ConfigReloadRequestStatus::coalesced) {
        log.info(
            "SIGHUP: reload preparation is already in progress; "
            "coalescing one trailing reload");
        return;
    }
    if (request.status == ConfigReloadRequestStatus::stopped) {
        log.verbose(
            "SIGHUP: reload ignored because the daemon is shutting down");
        return;
    }
    const ConfigReloadClaim claim = request.claim;

    RuntimeMutationLeaseHandoff mutation_lease;
    try {
        // SIGHUP is another configuration writer. Serialize it with API
        // staging and transactional commits so a disk reload cannot replace
        // the active ConfigStore snapshot after a catalogue preview has been
        // revalidated but before that candidate is committed.
        auto admitted = runtime_mutation_admission_.try_acquire(
            "sighup-reload");
        if (!admitted.has_value()) {
            const auto active = runtime_mutation_admission_.active();
            log.warn(
                "SIGHUP: reload deferred because runtime mutation '{}' is "
                "already in progress",
                active.has_value() ? active->label : std::string{"unknown"});
            defer_sighup_reload(claim);
            return;
        }
        const auto expected_lease_token = admitted->token();
        mutation_lease = RuntimeMutationLeaseHandoff{
            std::make_unique<RuntimeMutationAdmission::Lease>(
                std::move(*admitted))};

        // A disk reload must not make an in-memory draft disappear or apply a
        // different generation behind it. Check before admitting any worker
        // work, while the runtime mutation lease is held.
        if (config_store_.config_is_draft()) {
            log.warn(
                "SIGHUP: reload rejected because a configuration draft is "
                "staged; save or discard the draft first");
            (void)sighup_reload_coordinator_.cancel(claim);
            auto exact = mutation_lease.take();
            complete_sighup_reload(
                claim,
                std::move(exact.lease),
                /*allow_coalesced_rerun=*/false);
            return;
        }

        const std::string config_path = config_path_;
        const auto rollback_snapshot =
            config_store_.pin_active_snapshot();
        const std::uint64_t expected_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const TraceId trace_id = ensure_trace_id();
        log.info("SIGHUP: scheduling full reload preparation...");
        const bool enqueued = blocking_executor_.try_post(
            "sighup-reload-prepare",
            [this,
             config_path,
             rollback_snapshot,
             claim,
             mutation_lease,
             expected_lease_token,
             expected_runtime_generation,
             trace_id]() mutable {
                bool posted = false;
                try {
                    // Keep the outermost worker boundary ahead of every
                    // allocation and trace-context installation. If any of
                    // those operations throws, the worker still releases the
                    // prepare claim and the API config-operation gate below.
                    ScopedTraceContext trace_scope(trace_id);
                    auto prepared =
                        std::make_shared<PreparedRuntimeInputs>();
                    auto rollback_prepared =
                        std::make_shared<PreparedRuntimeInputs>();
                    std::string preparation_error;

                    try {
                        std::ifstream input(config_path);
                        if (!input.is_open()) {
                            throw DaemonError(
                                "Cannot open config file: " + config_path);
                        }

                        std::ostringstream serialized;
                        serialized << input.rdbuf();
                        if (input.bad()) {
                            throw DaemonError(
                                "Cannot read config file: " + config_path);
                        }

                        Config next_config = parse_config(serialized.str());
                        validate_config(next_config);
                        *prepared = prepare_runtime_inputs(
                            next_config,
                            RemoteListPreparationMode::RefreshAll);
                        *rollback_prepared = prepare_runtime_inputs(
                            rollback_snapshot->config,
                            RemoteListPreparationMode::None);
                    } catch (const std::exception& error) {
                        preparation_error = error.what();
                    } catch (...) {
                        preparation_error =
                            "unknown disk reload preparation error";
                    }

                    posted = post_control_task(
                        [this,
                         prepared,
                         rollback_prepared,
                         rollback_snapshot,
                         claim,
                         mutation_lease,
                         expected_lease_token,
                         expected_runtime_generation,
                         preparation_error =
                             std::move(preparation_error)]() mutable {
                            const auto commit_claim =
                                sighup_reload_coordinator_.claim_commit(
                                    claim);
                            if (commit_claim ==
                                ConfigReloadCommitStatus::lost) {
                                return;
                            }
                            bool allow_coalesced_rerun =
                                commit_claim !=
                                ConfigReloadCommitStatus::stopped;
                            const auto schedule_cache_reconcile =
                                [this]() noexcept {
                                    if (!accept_posted_control_tasks_.load(
                                            std::memory_order_acquire) ||
                                        !running_.load(
                                            std::memory_order_acquire)) {
                                        return;
                                    }
                                    try {
                                        schedule_deferred_list_refresh(
                                            "sighup-cache-recovery",
                                            runtime_generation_.load(
                                                std::memory_order_acquire),
                                            /*force_reconcile=*/true);
                                    } catch (const std::exception& error) {
                                        try {
                                            Logger::instance().error(
                                                "SIGHUP: could not schedule "
                                                "list-cache recovery: {}",
                                                error.what());
                                        } catch (...) {
                                        }
                                    } catch (...) {
                                        try {
                                            Logger::instance().error(
                                                "SIGHUP: could not schedule "
                                                "list-cache recovery");
                                        } catch (...) {
                                        }
                                    }
                                };
                            bool force_cache_reconcile = false;
                            try {
                                // This is the callback's outermost boundary
                                // after commit ownership is claimed. Every
                                // allocation, copy and log operation stays
                                // inside it, and the single completion below
                                // releases both coordinator and API gate.
                                auto& commit_log = Logger::instance();
                                if (commit_claim ==
                                    ConfigReloadCommitStatus::superseded) {
                                    commit_log.info(
                                        "SIGHUP: prepared reload was "
                                        "superseded; reading the latest file "
                                        "generation");
                                } else if (
                                    commit_claim ==
                                    ConfigReloadCommitStatus::stopped) {
                                    commit_log.verbose(
                                        "SIGHUP: prepared reload discarded "
                                        "because the daemon is shutting "
                                        "down");
                                } else if (
                                    runtime_generation_.load(
                                        std::memory_order_acquire) !=
                                        expected_runtime_generation) {
                                    // A runtime/list commit advanced while the
                                    // worker was blocked. Re-prepare all
                                    // derived inputs and the exact rollback
                                    // snapshot from that committed generation.
                                    (void)sighup_reload_coordinator_.request();
                                    commit_log.info(
                                        "SIGHUP: prepared reload is stale "
                                        "after an active runtime generation "
                                        "change; scheduling "
                                        "a fresh preparation");
                                } else if (!preparation_error.empty()) {
                                    force_cache_reconcile = true;
                                    commit_log.error(
                                        "SIGHUP: reload preparation failed: "
                                        "{}",
                                        preparation_error);
                                } else {
                                    // The shared Keenetic DNS cache may have
                                    // advanced while the worker was preparing
                                    // either candidate. Rollback must restore
                                    // the exact event-loop-owned committed
                                    // snapshot, not that newer observational
                                    // cache value.
                                    rollback_prepared->keenetic_dns =
                                        active_keenetic_dns_;
                                    if (prepared->keenetic_dns.snapshot &&
                                        active_keenetic_dns_.generation >
                                            prepared->keenetic_dns.generation) {
                                        // A periodic observation can advance
                                        // while SIGHUP performs remote I/O.
                                        // Its immutable view is safe to splice
                                        // into a candidate that still uses
                                        // Keenetic DNS. Do not re-run all
                                        // RefreshAll work, and do not attach it
                                        // to a candidate switching away from
                                        // Keenetic DNS (no snapshot).
                                        prepared->keenetic_dns =
                                            active_keenetic_dns_;
                                    }
                                    RuntimeFirewallPreownedTerminalContinuation
                                        final_continuation{
                                            [this,
                                             claim,
                                             expected_lease_token,
                                             allow_coalesced_rerun,
                                             schedule_cache_reconcile](
                                                RuntimeFirewallLifecycleTerminal
                                                    terminal,
                                                std::unique_ptr<
                                                    RuntimeMutationAdmission::
                                                        Lease>
                                                    exact) mutable noexcept {
                                                const bool
                                                    exact_lease_returned =
                                                        exact &&
                                                        static_cast<bool>(
                                                            *exact) &&
                                                        exact->token() ==
                                                            expected_lease_token &&
                                                        runtime_mutation_admission_
                                                            .owns(*exact);
                                                const bool
                                                    candidate_published =
                                                        exact_lease_returned &&
                                                        terminal.outcome ==
                                                            RuntimeFirewallLifecycleOutcome::
                                                                verified_success &&
                                                        !terminal
                                                             .commit_ambiguous &&
                                                        terminal
                                                            .observed_config_identity &&
                                                        terminal
                                                                .observed_config_identity
                                                                ->kind ==
                                                            ConfigTerminalOperationKind::
                                                                candidate &&
                                                        (terminal.committed ||
                                                         terminal
                                                             .candidate_noop_verified);
                                                try {
                                                    auto& terminal_log =
                                                        Logger::instance();
                                                    const auto terminal_kind =
                                                        terminal
                                                            .observed_config_identity
                                                        ? terminal
                                                              .observed_config_identity
                                                              ->kind
                                                        : ConfigTerminalOperationKind::
                                                              config_preapply;
                                                    const bool
                                                        verified_unambiguous =
                                                            terminal.outcome ==
                                                                RuntimeFirewallLifecycleOutcome::
                                                                    verified_success &&
                                                            !terminal
                                                                 .commit_ambiguous;
                                                    if (!exact_lease_returned) {
                                                        terminal_log.error(
                                                            "SIGHUP: reload "
                                                            "did not return "
                                                            "its exact "
                                                            "mutation lease");
                                                    } else if (
                                                        candidate_published) {
                                                        terminal_log.info(
                                                            "SIGHUP: full "
                                                            "reload complete");
                                                    } else if (
                                                        verified_unambiguous &&
                                                        terminal_kind ==
                                                            ConfigTerminalOperationKind::
                                                                rollback &&
                                                        (terminal.committed ||
                                                         terminal
                                                             .candidate_noop_verified)) {
                                                        if (terminal.detail
                                                                .empty()) {
                                                            terminal_log.warn(
                                                                "SIGHUP: "
                                                                "reload "
                                                                "failed; "
                                                                "previous "
                                                                "runtime was "
                                                                "restored");
                                                        } else {
                                                            terminal_log.warn(
                                                                "SIGHUP: "
                                                                "reload "
                                                                "failed; "
                                                                "previous "
                                                                "runtime was "
                                                                "restored: "
                                                                "{}",
                                                                terminal
                                                                    .detail);
                                                        }
                                                    } else if (
                                                        terminal.detail
                                                            .empty()) {
                                                        terminal_log.error(
                                                            "SIGHUP: reload "
                                                            "was not "
                                                            "verified");
                                                    } else {
                                                        terminal_log.error(
                                                            "SIGHUP: reload "
                                                            "was not "
                                                            "verified: {}",
                                                            terminal.detail);
                                                    }
                                                } catch (...) {
                                                }
                                                complete_sighup_reload(
                                                    claim,
                                                    std::move(exact),
                                                    allow_coalesced_rerun);
                                                if (!candidate_published) {
                                                    schedule_cache_reconcile();
                                                }
                                            }};
                                    PreparedRuntimeInputs candidate{
                                        std::move(*prepared)};
                                    PreparedRuntimeInputs rollback{
                                        std::move(*rollback_prepared)};
                                    auto exact = mutation_lease.take();
                                    if (!exact) {
                                        commit_log.error(
                                            "SIGHUP: reload commit owner "
                                            "could not take its exact "
                                            "mutation lease");
                                        complete_sighup_reload(
                                            claim,
                                            std::move(exact.lease),
                                            allow_coalesced_rerun);
                                        schedule_cache_reconcile();
                                        return;
                                    }
                                    begin_preowned_runtime_firewall_active_reload(
                                        std::move(exact.lease),
                                        rollback_snapshot,
                                        std::move(candidate),
                                        std::move(rollback),
                                        std::move(final_continuation));
                                    return;
                                }
                            } catch (const std::exception& commit_error) {
                                force_cache_reconcile =
                                    commit_claim ==
                                    ConfigReloadCommitStatus::claimed;
                                try {
                                    Logger::instance().error(
                                        "SIGHUP: reload commit callback "
                                        "failed: {}",
                                        commit_error.what());
                                } catch (...) {
                                }
                            } catch (...) {
                                force_cache_reconcile =
                                    commit_claim ==
                                    ConfigReloadCommitStatus::claimed;
                                try {
                                    Logger::instance().error(
                                        "SIGHUP: reload commit callback "
                                        "failed with an unknown error");
                                } catch (...) {
                                }
                            }
                            auto exact = mutation_lease.take();
                            complete_sighup_reload(
                                claim,
                                std::move(exact.lease),
                                allow_coalesced_rerun);
                            if (force_cache_reconcile) {
                                schedule_cache_reconcile();
                            }
                        },
                        "sighup-reload-commit");
                } catch (const std::exception& worker_error) {
                    try {
                        Logger::instance().error(
                            "SIGHUP: reload worker failed before handing off "
                            "to the control loop: {}",
                            worker_error.what());
                    } catch (...) {
                    }
                } catch (...) {
                    try {
                        Logger::instance().error(
                            "SIGHUP: reload worker failed before handing off "
                            "to the control loop: unknown error");
                    } catch (...) {
                    }
                }

                if (!posted) {
                    // Shutdown closes control-task admission before draining
                    // the blocking executor. post_control_task() can also
                    // throw after queueing, so release only when this worker
                    // atomically cancels the prepare claim before a queued
                    // callback claims commit.
                    if (sighup_reload_coordinator_.cancel(claim)) {
                        auto exact = mutation_lease.take();
                        complete_sighup_reload(
                            claim,
                            std::move(exact.lease),
                            /*allow_coalesced_rerun=*/false);
                    }
                }
            },
            trace_id);
        if (!enqueued) {
            log.error(
                "SIGHUP: reload rejected because the blocking executor is "
                "unavailable");
            if (sighup_reload_coordinator_.cancel(claim)) {
                auto exact = mutation_lease.take();
                complete_sighup_reload(
                    claim,
                    std::move(exact.lease),
                    /*allow_coalesced_rerun=*/false);
            }
        }
    } catch (const std::exception& e) {
        if (sighup_reload_coordinator_.cancel(claim)) {
            auto exact = mutation_lease.take();
            complete_sighup_reload(
                claim,
                std::move(exact.lease),
                /*allow_coalesced_rerun=*/false);
        }
        log.error("SIGHUP: reload rejected: {}", e.what());
    } catch (...) {
        if (sighup_reload_coordinator_.cancel(claim)) {
            auto exact = mutation_lease.take();
            complete_sighup_reload(
                claim,
                std::move(exact.lease),
                /*allow_coalesced_rerun=*/false);
        }
        log.error("SIGHUP: reload rejected: unknown error");
    }
}

void Daemon::defer_sighup_reload(ConfigReloadClaim claim) {
    auto abandon = [this, claim]() noexcept {
        if (sighup_reload_coordinator_.cancel(claim)) {
            (void)sighup_reload_coordinator_.complete(claim);
        }
    };

    const bool queued = blocking_executor_.try_post(
        "sighup-runtime-mutation-wait",
        [this, claim, abandon]() mutable {
            if (!runtime_mutation_admission_.wait_until_idle()) {
                abandon();
                return;
            }

            bool posted = false;
            try {
                posted = post_control_task(
                    [this, claim]() {
                        if (!sighup_reload_coordinator_.cancel(claim)) {
                            return;
                        }
                        const auto completion =
                            sighup_reload_coordinator_.complete(claim);
                        if (completion.owned) {
                            // The original request, plus any SIGHUP coalesced
                            // while it waited, is represented by this one
                            // fresh generation. If another mutation won the
                            // race after the idle observation, handle_sighup()
                            // defers again.
                            handle_sighup();
                        }
                    },
                    "sighup-runtime-mutation-resume");
            } catch (const std::exception& error) {
                try {
                    Logger::instance().error(
                        "SIGHUP: cannot post deferred runtime mutation: {}",
                        error.what());
                } catch (...) {
                }
            } catch (...) {
                try {
                    Logger::instance().error(
                        "SIGHUP: cannot post deferred runtime mutation: "
                        "unknown error");
                } catch (...) {
                }
            }
            if (!posted) {
                // post_control_task() may throw after queueing. The worker and
                // callback therefore race through the same coordinator claim;
                // exactly one side can cancel it and own completion.
                abandon();
            }
        });
    if (queued) {
        return;
    }

    if (!accept_posted_control_tasks_.load(std::memory_order_acquire)) {
        abandon();
        return;
    }

    try {
        scheduler_->schedule_oneshot(
            std::chrono::milliseconds{100},
            [this, claim]() { defer_sighup_reload(claim); },
            "sighup-runtime-mutation-wait-retry");
    } catch (const std::exception& error) {
        Logger::instance().error(
            "SIGHUP: cannot schedule runtime mutation wait: {}",
            error.what());
        abandon();
    }
}

void Daemon::complete_sighup_reload(
    ConfigReloadClaim claim,
    std::unique_ptr<RuntimeMutationAdmission::Lease> mutation_lease,
    bool allow_coalesced_rerun) noexcept {
    const auto completion =
        sighup_reload_coordinator_.complete(claim);
    if (!completion.owned) {
        return;
    }
    // Destroy the exact unique lease before starting a coalesced reload so
    // the trailing request can acquire fresh writer admission.
    mutation_lease.reset();

    if (!completion.rerun_requested || !allow_coalesced_rerun ||
        !accept_posted_control_tasks_.load(std::memory_order_acquire) ||
        !running_.load(std::memory_order_acquire)) {
        return;
    }

    try {
        Logger::instance().info(
            "SIGHUP: starting the coalesced trailing reload");
        handle_sighup();
    } catch (const std::exception& error) {
        try {
            Logger::instance().error(
                "SIGHUP: coalesced reload could not start: {}",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().error(
                "SIGHUP: coalesced reload could not start: unknown error");
        } catch (...) {
        }
    }
}

RuntimeFirewallImmediateDisposition
Daemon::refresh_iproute_and_firewall_runtime(
    std::size_t retry_attempt,
    PreparedNativeVpnCatalogPtr prepared_native_vpn_catalog,
    bool schedule_catalog_refresh,
    OwnedSnatRecovery snat_recovery,
    RuntimeFirewallImmediateCompletionIntent completion_intent) {
    std::shared_ptr<DaemonRuntimeFirewallOperationState> state;
    try {
        state = std::make_shared<DaemonRuntimeFirewallOperationState>();
    } catch (...) {
        (void)completion_intent.settle(
            RuntimeFirewallImmediateTerminalOutcome::not_verified);
        return RuntimeFirewallImmediateDisposition::rejected;
    }
    state->immediate_completion_intent = std::move(completion_intent);
    if (!routing_runtime_active()) {
        (void)state->immediate_completion_intent.settle(
            RuntimeFirewallImmediateTerminalOutcome::not_verified);
        return RuntimeFirewallImmediateDisposition::rejected;
    }

    const auto current_generation =
        runtime_generation_.load(std::memory_order_acquire);
    RuntimeFirewallImmediateDisposition disposition{
        RuntimeFirewallImmediateDisposition::rejected};
    try {
        disposition = runtime_firewall_owner_->start_immediate(
            retry_attempt,
            current_generation,
            std::move(snat_recovery),
            std::move(prepared_native_vpn_catalog),
            schedule_catalog_refresh,
            state);
    } catch (...) {
        (void)state->immediate_completion_intent.settle(
            RuntimeFirewallImmediateTerminalOutcome::not_verified);
        return RuntimeFirewallImmediateDisposition::rejected;
    }
    if (disposition !=
        RuntimeFirewallImmediateDisposition::handed_off) {
        // No operation context accepted this invocation. Preserve the former
        // synchronous false outcome locally; the intent must never attach to
        // the active/trailing operation or one of its successors.
        (void)state->immediate_completion_intent.settle(
            RuntimeFirewallImmediateTerminalOutcome::not_verified);
    }
    return disposition;
}

bool Daemon::runtime_firewall_lifecycle_generation_is_current(
    RuntimeFirewallLifecycleKind lifecycle_kind,
    std::uint64_t expected_generation) const noexcept {
    bool active = false;
    try {
        active = routing_runtime_active();
    } catch (...) {
        // This predicate is called from coordinator/watchdog noexcept
        // boundaries. A failed state-store lock is never evidence that a
        // generation is current.
        return false;
    }
    if (runtime_firewall_lifecycle_is_stop_cleanup(lifecycle_kind)) {
        // STOP owns the exact admission lease and may be used by process
        // shutdown even when the public runtime is already inactive. Its
        // immutable cleanup target always names the currently published
        // generation; stale owned kernel artifacts still have to be proven
        // absent before shutdown can retire the owner/executor.
        return expected_generation ==
            runtime_generation_.load(std::memory_order_acquire);
    }
    const bool exact_start_in_progress =
        runtime_firewall_lifecycle_activates_stopped_runtime(
            lifecycle_kind) &&
        !active &&
        runtime_state_machine_.state() == RuntimeState::starting;
    return (active || exact_start_in_progress) &&
           expected_generation ==
               runtime_generation_.load(std::memory_order_acquire);
}

bool Daemon::begin_preowned_runtime_firewall_stop_cleanup(
    std::unique_ptr<RuntimeMutationAdmission::Lease>& lease,
    RuntimeStopCleanupTarget target,
    RuntimeFirewallPreownedTerminalContinuation& continuation) noexcept {
    if (!lease || !static_cast<bool>(*lease) ||
        !runtime_mutation_admission_.owns(*lease) || !continuation ||
        target.runtime_generation == 0U ||
        target.runtime_generation !=
            runtime_generation_.load(std::memory_order_acquire) ||
        runtime_firewall_owner_->shutdown_requested() ||
        runtime_firewall_owner_->active_context() ||
        runtime_firewall_owner_->pending_successor()) {
        return false;
    }

    try {
        auto state =
            std::make_shared<DaemonRuntimeFirewallOperationState>();
        state->stop_cleanup_target = std::move(target);
        auto result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            state->stop_cleanup_target->runtime_generation,
            {},
            {},
            /*schedule_catalog_refresh=*/false,
            state,
            runtime_mutation_admission_,
            std::move(lease),
            {},
            RuntimeFirewallLifecycleKind::stop_cleanup,
            std::move(continuation));
        if (result.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off) {
            return true;
        }
        lease = std::move(result.unaccepted_lease);
        continuation = std::move(result.unaccepted_continuation);
    } catch (...) {
    }
    return false;
}

bool Daemon::begin_preowned_runtime_firewall_exact_tcp_reset_point(
    std::unique_ptr<RuntimeMutationAdmission::Lease>& lease,
    RuntimeExactTcpResetPointMutationTarget target,
    RuntimeFirewallPreownedTerminalContinuation& continuation) noexcept {
    bool runtime_active = false;
    try {
        runtime_active = routing_runtime_active();
    } catch (...) {
        return false;
    }
    if (!lease || !static_cast<bool>(*lease) ||
        !runtime_mutation_admission_.owns(*lease) || !continuation ||
        !target.valid() ||
        target.runtime_generation !=
            runtime_generation_.load(std::memory_order_acquire) ||
        !runtime_active ||
        (target.kind ==
             RuntimeExactTcpResetPointMutationKind::
                 install_then_delete_exact_flow &&
         (!idle_stall_observer_enabled_.load(std::memory_order_acquire) ||
          target.coverage_generation !=
              idle_stall_coverage_generation_.load(
                  std::memory_order_acquire))) ||
        runtime_firewall_owner_->shutdown_requested() ||
        runtime_firewall_owner_->active_context() ||
        runtime_firewall_owner_->pending_successor()) {
        return false;
    }

    try {
        auto state =
            std::make_shared<DaemonRuntimeFirewallOperationState>();
        state->exact_tcp_reset_point_target = std::move(target);
        state->exact_tcp_reset_point_mutation_lease_token = lease->token();
        auto result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            state->exact_tcp_reset_point_target->runtime_generation,
            {},
            {},
            /*schedule_catalog_refresh=*/false,
            state,
            runtime_mutation_admission_,
            std::move(lease),
            {},
            RuntimeFirewallLifecycleKind::exact_tcp_reset_point_mutation,
            std::move(continuation));
        if (result.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off) {
            return true;
        }
        lease = std::move(result.unaccepted_lease);
        continuation = std::move(result.unaccepted_continuation);
    } catch (...) {
    }
    return false;
}

bool Daemon::begin_preowned_runtime_firewall_background_point_mutation(
    std::unique_ptr<RuntimeMutationAdmission::Lease>& lease,
    const std::shared_ptr<RuntimeBackgroundPointMutationTransaction>&
        transaction,
    RuntimeFirewallPreownedTerminalContinuation& continuation) noexcept {
    bool runtime_active = false;
    try {
        runtime_active = routing_runtime_active();
    } catch (...) {
        return false;
    }
    if (!lease || !static_cast<bool>(*lease) ||
        !runtime_mutation_admission_.owns(*lease) || !continuation ||
        !transaction || !transaction->valid() ||
        transaction->target.runtime_generation() !=
            runtime_generation_.load(std::memory_order_acquire) ||
        !runtime_active || runtime_firewall_owner_->shutdown_requested() ||
        runtime_firewall_owner_->active_context() ||
        runtime_firewall_owner_->pending_successor()) {
        return false;
    }

    try {
        auto state =
            std::make_shared<DaemonRuntimeFirewallOperationState>();
        state->background_point_mutation_transaction = transaction;
        state->background_point_mutation_lease_token = lease->token();
        auto result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            transaction->target.runtime_generation(),
            {},
            {},
            /*schedule_catalog_refresh=*/false,
            state,
            runtime_mutation_admission_,
            std::move(lease),
            {},
            RuntimeFirewallLifecycleKind::background_point_mutation,
            std::move(continuation));
        if (result.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off) {
            return true;
        }
        lease = std::move(result.unaccepted_lease);
        continuation = std::move(result.unaccepted_continuation);
    } catch (...) {
    }
    return false;
}

bool Daemon::begin_preowned_runtime_firewall_cold_boot(
    const std::shared_ptr<DaemonColdBootTransaction>& transaction,
    std::unique_ptr<RuntimeMutationAdmission::Lease>& lease,
    PreparedNativeVpnCatalogPtr prepared_native_vpn_catalog,
    std::shared_ptr<const ListCacheGenerationSnapshot>
        startup_list_cache_snapshot,
    RuntimeFirewallPreownedTerminalContinuation& continuation) noexcept {
    if (!transaction || !lease || !static_cast<bool>(*lease) ||
        lease->token() != transaction->mutation_lease_token ||
        !runtime_mutation_admission_.owns(*lease) || !continuation ||
        !startup_list_cache_snapshot ||
        runtime_firewall_owner_->shutdown_requested() ||
        runtime_firewall_owner_->active_context() ||
        runtime_firewall_owner_->pending_successor()) {
        return false;
    }

    bool runtime_active = true;
    try {
        runtime_active = routing_runtime_active();
    } catch (...) {
        return false;
    }
    if (runtime_active ||
        runtime_state_machine_.state() != RuntimeState::starting) {
        return false;
    }

    const auto generation =
        runtime_generation_.load(std::memory_order_acquire);
    if (prepared_native_vpn_catalog &&
        prepared_native_vpn_catalog->runtime_generation != generation) {
        return false;
    }

    try {
        auto state =
            std::make_shared<DaemonRuntimeFirewallOperationState>();
        state->cold_boot_transaction = transaction;
        state->cold_boot_mutation_lease_token = lease->token();
        // The startup owner consumes one immutable list generation.  The
        // dispatch path must not rebuild it after the lease hand-off.
        state->list_cache_snapshot =
            std::move(startup_list_cache_snapshot);
        auto result = runtime_firewall_owner_->start_immediate_preowned(
            transaction->completed_candidate_bodies,
            generation,
            {},
            std::move(prepared_native_vpn_catalog),
            /*schedule_catalog_refresh=*/false,
            state,
            runtime_mutation_admission_,
            std::move(lease),
            {},
            RuntimeFirewallLifecycleKind::cold_boot,
            std::move(continuation));
        if (result.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off) {
            return true;
        }
        lease = std::move(result.unaccepted_lease);
        continuation = std::move(result.unaccepted_continuation);
    } catch (...) {
    }
    return false;
}

void Daemon::start_runtime_cold_boot_attempt(
    const std::shared_ptr<DaemonColdBootTransaction>& transaction)
    noexcept {
    if (!transaction || transaction->startup_services_opened ||
        runtime_firewall_owner_->shutdown_requested()) {
        return;
    }
    if (transaction->runtime_generation !=
        runtime_generation_.load(std::memory_order_acquire)) {
        try {
            runtime_state_store_.set_routing_runtime_active(false);
            if (runtime_state_machine_.state() == RuntimeState::running ||
                runtime_state_machine_.state() == RuntimeState::starting) {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    "cold-boot generation became stale before admission");
            }
            publish_runtime_state();
        } catch (...) {
        }
        open_runtime_cold_boot_services(
            transaction, /*runtime_ready=*/false);
        return;
    }
    const auto consume_dispatch_budget = [transaction]() noexcept {
        if (transaction->dispatch_rejections <
            kRuntimeFirewallStartBoundedRetryCount) {
            ++transaction->dispatch_rejections;
        }
    };
    if (plan_runtime_cold_boot_candidate_budget(
            transaction->completed_candidate_bodies,
            kRuntimeFirewallStartBoundedRetryCount)
            .dispatch ==
        RuntimeColdBootCandidateBudgetDispatch::exhausted) {
        schedule_runtime_cold_boot_recovery(
            transaction, "cold-boot candidate budget is exhausted");
        return;
    }

    std::unique_ptr<RuntimeMutationAdmission::Lease> lease;
    try {
        auto acquired = runtime_mutation_admission_.try_acquire(
            "runtime-cold-boot");
        if (acquired.has_value()) {
            lease = std::make_unique<RuntimeMutationAdmission::Lease>(
                std::move(*acquired));
        }
    } catch (...) {
    }
    if (!lease) {
        consume_dispatch_budget();
        schedule_runtime_cold_boot_recovery(
            transaction, "cold-boot mutation admission is busy");
        return;
    }

    RuntimeRoutingInventorySnapshotPtr route_preimage;
    try {
        route_preimage = routing_operation_owner_.snapshot();
    } catch (...) {
    }
    if (classify_runtime_routing_inventory(route_preimage) !=
        RuntimeRoutingInventoryAuthority::authoritative) {
        lease.reset();
        consume_dispatch_budget();
        schedule_runtime_cold_boot_recovery(
            transaction, "cold-boot routing preimage is not authoritative");
        return;
    }
    transaction->route_preimage = std::move(route_preimage);
    transaction->mutation_lease_token = lease->token();
    transaction->route_mutation_acknowledged = false;
    transaction->exact_route_checkpoint_verified = false;
    ++transaction->active_attempt_identity;
    if (transaction->active_attempt_identity == 0U) {
        ++transaction->active_attempt_identity;
    }
    const auto attempt_identity = transaction->active_attempt_identity;
    const auto candidate_attempt =
        transaction->completed_candidate_bodies;

    try {
        runtime_state_store_.set_routing_runtime_active(false);
        if (runtime_state_machine_.state() == RuntimeState::broken) {
            transition_runtime_or_throw(
                RuntimeState::starting,
                "cold-boot recovery attempt admitted");
        }
        publish_runtime_state();
    } catch (...) {
        lease.reset();
        consume_dispatch_budget();
        schedule_runtime_cold_boot_recovery(
            transaction, "cold-boot starting state could not be published");
        return;
    }

    RuntimeFirewallPreownedTerminalContinuation continuation;
    try {
        continuation = RuntimeFirewallPreownedTerminalContinuation{
            [this, transaction, attempt_identity, candidate_attempt](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                complete_runtime_cold_boot_attempt(
                    transaction,
                    attempt_identity,
                    candidate_attempt,
                    std::move(terminal),
                    std::move(exact));
            }};
    } catch (...) {
        lease.reset();
        consume_dispatch_budget();
        schedule_runtime_cold_boot_recovery(
            transaction, "cold-boot terminal allocation failed");
        return;
    }

    if (begin_preowned_runtime_firewall_cold_boot(
            transaction,
            lease,
            transaction->prepared_native_vpn_catalog,
            transaction->list_cache_snapshot,
            continuation)) {
        transaction->dispatch_rejections = 0U;
        return;
    }

    // Handoff rejection did not mutate the candidate. Release the exact
    // writer before scheduling a fresh admission attempt.
    lease.reset();
    continuation = {};
    consume_dispatch_budget();
    schedule_runtime_cold_boot_recovery(
        transaction, "cold-boot firewall owner rejected the handoff");
}

void Daemon::complete_runtime_cold_boot_attempt(
    const std::shared_ptr<DaemonColdBootTransaction>& transaction,
    std::uint64_t attempt_identity,
    std::size_t candidate_attempt,
    RuntimeFirewallLifecycleTerminal terminal,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    if (!transaction) return;
    if (transaction->completed_candidate_bodies <= candidate_attempt) {
        if (transaction->dispatch_rejections <
            kRuntimeFirewallStartBoundedRetryCount) {
            ++transaction->dispatch_rejections;
        }
    } else {
        transaction->dispatch_rejections = 0U;
    }
    const bool terminal_transient = terminal.transient;
    const bool terminal_ambiguous = terminal.commit_ambiguous;
    RuntimeColdBootCandidateAction action =
        RuntimeColdBootCandidateAction::request_fresh_recovery;
    try {
        const bool exact_lease_owned =
            lease && static_cast<bool>(*lease) &&
            lease->token() == transaction->mutation_lease_token &&
            attempt_identity == transaction->active_attempt_identity &&
            runtime_mutation_admission_.owns(*lease);
        const bool generation_current =
            transaction->runtime_generation ==
            runtime_generation_.load(std::memory_order_acquire);
        const auto route_after = routing_operation_owner_.snapshot();
        const bool authoritative_route_snapshots =
            classify_runtime_routing_inventory(transaction->route_preimage) ==
                RuntimeRoutingInventoryAuthority::authoritative &&
            classify_runtime_routing_inventory(route_after) ==
                RuntimeRoutingInventoryAuthority::authoritative;
        const bool route_candidate_mutated =
            authoritative_route_snapshots &&
            route_after->revision != transaction->route_preimage->revision;
        const bool exact_route_checkpoint_verified =
            authoritative_route_snapshots &&
            transaction->exact_route_checkpoint_verified;
        bool running_publication_succeeded = false;
        try {
            running_publication_succeeded =
                routing_runtime_active() &&
                runtime_state_machine_.state() == RuntimeState::running;
        } catch (...) {
        }

        RuntimeColdBootCandidateEvidence evidence;
        evidence.exact_lease_owned = exact_lease_owned;
        evidence.runtime_generation_current = generation_current;
        evidence.exact_route_checkpoint_verified =
            exact_route_checkpoint_verified;
        evidence.route_candidate_mutated = route_candidate_mutated;
        evidence.resolver_terminal_verified =
            terminal.outcome ==
                RuntimeFirewallLifecycleOutcome::verified_success &&
            terminal.committed && !terminal.commit_ambiguous;
        evidence.running_publication_succeeded =
            running_publication_succeeded;
        evidence.terminal = std::move(terminal);
        action = plan_runtime_cold_boot_candidate_terminal(evidence);
    } catch (...) {
        // Without complete terminal evidence, a route/firewall mutation may
        // already exist. Never turn that unknown state into a fresh rollback
        // baseline merely because evidence preparation failed.
        action = RuntimeColdBootCandidateAction::finish_available_degraded;
    }

    if (action == RuntimeColdBootCandidateAction::publish_running) {
        lease.reset();
        transaction->completed_candidate_bodies = 0U;
        open_runtime_cold_boot_services(transaction, /*runtime_ready=*/true);
        return;
    }
    if (action == RuntimeColdBootCandidateAction::
                      retain_previous_and_finish_available) {
        lease.reset();
        if (terminal_transient) {
            schedule_runtime_cold_boot_recovery(
                transaction, "transient clean cold-boot failure");
            return;
        }
        open_runtime_cold_boot_services(transaction, /*runtime_ready=*/false);
        return;
    }
    if (action == RuntimeColdBootCandidateAction::finish_shutdown) {
        lease.reset();
        return;
    }
    if (action ==
        RuntimeColdBootCandidateAction::finish_available_degraded) {
        lease.reset();
        try {
            runtime_state_store_.set_routing_runtime_active(false);
            if (runtime_state_machine_.state() == RuntimeState::running ||
                runtime_state_machine_.state() == RuntimeState::starting) {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    "cold-boot terminal lost exact mutation authority");
            }
            publish_runtime_state();
        } catch (...) {
        }
        open_runtime_cold_boot_services(
            transaction, /*runtime_ready=*/false);
        return;
    }
    if (action == RuntimeColdBootCandidateAction::
                      start_exact_route_rollback) {
        start_runtime_cold_boot_rollback(
            transaction,
            RuntimeColdBootRollbackKind::route_preimage,
            std::move(lease));
        return;
    }
    if (action == RuntimeColdBootCandidateAction::start_full_rollback) {
        start_runtime_cold_boot_rollback(
            transaction,
            RuntimeColdBootRollbackKind::stopped_runtime,
            std::move(lease));
        return;
    }

    // Ambiguous or stale terminals are not replay authority. Drop the exact
    // lease first; the bounded timer below must acquire a new observation.
    lease.reset();
    schedule_runtime_cold_boot_recovery(
        transaction,
        terminal_ambiguous
            ? "cold-boot firewall COMMIT is ambiguous"
            : "cold-boot terminal requires a fresh observation");
}

void Daemon::start_runtime_cold_boot_rollback(
    const std::shared_ptr<DaemonColdBootTransaction>& transaction,
    RuntimeColdBootRollbackKind rollback_kind,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    const bool shutdown = runtime_firewall_owner_->shutdown_requested();
    const bool generation_current = transaction &&
        transaction->runtime_generation ==
            runtime_generation_.load(std::memory_order_acquire);
    const bool exact = transaction && lease && static_cast<bool>(*lease) &&
        lease->token() == transaction->mutation_lease_token &&
        runtime_mutation_admission_.owns(*lease) && generation_current;
    if (!exact || shutdown) {
        lease.reset();
        if (shutdown) return;
        try {
            runtime_state_store_.set_routing_runtime_active(false);
            if (runtime_state_machine_.state() == RuntimeState::running ||
                runtime_state_machine_.state() == RuntimeState::starting) {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    "cold-boot rollback lost exact authority");
            }
            publish_runtime_state();
        } catch (...) {
        }
        open_runtime_cold_boot_services(
            transaction, /*runtime_ready=*/false);
        return;
    }

    struct RollbackResult final {
        std::atomic<bool> body_finished{false};
        std::atomic<bool> control_claimed{false};
        bool verified{false};
        std::string detail;
        int completion_watchdog_task_id{-1};
    };
    std::shared_ptr<RollbackResult> result;
    std::shared_ptr<
        std::unique_ptr<RuntimeMutationAdmission::Lease>> lease_holder;
    RuntimeRoutingInventorySnapshotPtr preimage;
    try {
        result = std::make_shared<RollbackResult>();
        lease_holder = std::make_shared<
            std::unique_ptr<RuntimeMutationAdmission::Lease>>();
        preimage = transaction->route_preimage;
        *lease_holder = std::move(lease);
    } catch (...) {
        lease.reset();
        try {
            runtime_state_store_.set_routing_runtime_active(false);
            if (runtime_state_machine_.state() == RuntimeState::running ||
                runtime_state_machine_.state() == RuntimeState::starting) {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    "cold-boot rollback allocation failed");
            }
            publish_runtime_state();
        } catch (...) {
        }
        open_runtime_cold_boot_services(
            transaction, /*runtime_ready=*/false);
        return;
    }

    // Arm the control-loop completion before the blocking body can run.  The
    // worker therefore never has to transfer the exact lease through a
    // fallible post_control_task() after mutating routes/firewall state.  A
    // repeating timer is only a readiness watchdog; the body itself remains
    // serialized on BlockingExecutor.
    try {
        const int completion_watchdog_task_id =
            scheduler_->schedule_repeating(
                kRuntimeFirewallStartRetryDelays.front(),
                [this,
                 transaction,
                 rollback_kind,
                 result,
                 lease_holder]() noexcept {
                    if (result->control_claimed.load(
                            std::memory_order_acquire)) {
                        try {
                            if (result->completion_watchdog_task_id >= 0) {
                                scheduler_->cancel(
                                    result->completion_watchdog_task_id);
                            }
                        } catch (...) {
                        }
                        return;
                    }
                    if (!result->body_finished.load(
                            std::memory_order_acquire) ||
                        result->control_claimed.exchange(
                            true, std::memory_order_acq_rel)) {
                        return;
                    }
                    try {
                        if (result->completion_watchdog_task_id >= 0) {
                            scheduler_->cancel(
                                result->completion_watchdog_task_id);
                        }
                    } catch (...) {
                    }

                    auto returned_lease = std::move(*lease_holder);
                    const bool current = transaction &&
                        transaction->runtime_generation ==
                            runtime_generation_.load(
                                std::memory_order_acquire) &&
                        !runtime_firewall_owner_->shutdown_requested();
                    const bool exact_returned = returned_lease &&
                        static_cast<bool>(*returned_lease) &&
                        returned_lease->token() ==
                            transaction->mutation_lease_token &&
                        runtime_mutation_admission_.owns(*returned_lease);
                    if (!result->verified &&
                        transaction->rollback_body_failures <
                            kRuntimeFirewallStartRollbackHandoffRetryLimit) {
                        ++transaction->rollback_body_failures;
                    }
                    const auto dispatch =
                        plan_runtime_cold_boot_rollback_recovery(
                            exact_returned,
                            current,
                            result->verified,
                            transaction->rollback_body_failures,
                            kRuntimeFirewallStartRollbackHandoffRetryLimit);

                    if (dispatch ==
                        RuntimeColdBootRollbackRecoveryDispatch::
                            retry_same_authority) {
                        *lease_holder = std::move(returned_lease);
                        const auto delay =
                            kRuntimeFirewallStartRetryDelays[
                                std::min(
                                    transaction->rollback_body_failures - 1U,
                                    kRuntimeFirewallStartRetryDelays.size() -
                                        1U)];
                        try {
                            const int task_id = scheduler_->schedule_oneshot(
                                delay,
                                [this,
                                 transaction,
                                 rollback_kind,
                                 lease_holder]() noexcept {
                                    auto exact_retry =
                                        std::move(*lease_holder);
                                    start_runtime_cold_boot_rollback(
                                        transaction,
                                        rollback_kind,
                                        std::move(exact_retry));
                                },
                                "runtime-cold-boot-rollback-body-retry");
                            if (!runtime_cold_boot_scheduler_task_accepted(
                                    task_id)) {
                                throw DaemonError(
                                    "cold-boot rollback body retry was rejected");
                            }
                            return;
                        } catch (...) {
                            returned_lease = std::move(*lease_holder);
                        }
                    }

                    returned_lease.reset();
                    try {
                        runtime_state_store_.set_routing_runtime_active(false);
                        if (runtime_state_machine_.state() ==
                                RuntimeState::running ||
                            runtime_state_machine_.state() ==
                                RuntimeState::starting) {
                            transition_runtime_or_throw(
                                RuntimeState::broken,
                                dispatch ==
                                        RuntimeColdBootRollbackRecoveryDispatch::
                                            release_and_schedule_fresh
                                    ? "cold-boot candidate rolled back"
                                    : "cold-boot rollback could not be verified");
                        }
                        publish_runtime_state();
                    } catch (...) {
                    }

                    if (dispatch ==
                        RuntimeColdBootRollbackRecoveryDispatch::
                            release_and_schedule_fresh) {
                        transaction->rollback_body_failures = 0U;
                        schedule_runtime_cold_boot_recovery(
                            transaction,
                            "cold-boot rollback verified; fresh observation required");
                        return;
                    }
                    if (!runtime_firewall_owner_->shutdown_requested()) {
                        open_runtime_cold_boot_services(
                            transaction, /*runtime_ready=*/false);
                    }
                },
                "runtime-cold-boot-rollback-completion-watchdog");
        if (!runtime_cold_boot_scheduler_task_accepted(
                completion_watchdog_task_id)) {
            throw DaemonError(
                "cold-boot rollback completion watchdog was rejected");
        }
        result->completion_watchdog_task_id =
            completion_watchdog_task_id;
    } catch (...) {
        ++transaction->rollback_handoff_rejections;
        const bool retry_current = transaction->runtime_generation ==
                runtime_generation_.load(std::memory_order_acquire) &&
            !runtime_firewall_owner_->shutdown_requested();
        const bool retry_exact = *lease_holder &&
            static_cast<bool>(**lease_holder) &&
            (*lease_holder)->token() == transaction->mutation_lease_token &&
            runtime_mutation_admission_.owns(**lease_holder);
        const auto dispatch = plan_runtime_cold_boot_rollback_recovery(
            retry_exact,
            retry_current,
            /*rollback_verified=*/false,
            transaction->rollback_handoff_rejections,
            kRuntimeFirewallStartRollbackHandoffRetryLimit);
        if (dispatch ==
            RuntimeColdBootRollbackRecoveryDispatch::retry_same_authority) {
            auto exact_retry = std::move(*lease_holder);
            start_runtime_cold_boot_rollback(
                transaction, rollback_kind, std::move(exact_retry));
            return;
        }
        auto returned_lease = std::move(*lease_holder);
        returned_lease.reset();
        try {
            runtime_state_store_.set_routing_runtime_active(false);
            if (runtime_state_machine_.state() == RuntimeState::running ||
                runtime_state_machine_.state() == RuntimeState::starting) {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    "cold-boot rollback watchdog could not be armed");
            }
            publish_runtime_state();
        } catch (...) {
        }
        open_runtime_cold_boot_services(
            transaction, /*runtime_ready=*/false);
        return;
    }

    bool queued = false;
    try {
        queued = blocking_executor_.try_post(
            rollback_kind == RuntimeColdBootRollbackKind::route_preimage
                ? "runtime-cold-boot-route-rollback"
                : "runtime-cold-boot-full-rollback",
            [this,
             transaction,
             rollback_kind,
             result,
             lease_holder,
             preimage]() noexcept {
                const auto fail = [result](std::string_view detail) noexcept {
                    try {
                        result->detail.assign(detail.data(), detail.size());
                    } catch (...) {
                    }
                };
                try {
                    if (rollback_kind ==
                        RuntimeColdBootRollbackKind::route_preimage) {
                        if (classify_runtime_routing_inventory(preimage) !=
                            RuntimeRoutingInventoryAuthority::authoritative) {
                            fail("cold-boot route preimage is not authoritative");
                        } else {
                            const auto restored = routing_operation_owner_
                                .reconcile_compatibility_generation(
                                    preimage->routes,
                                    preimage->rules,
                                    RouteReconcileMode::Strict,
                                    [this, transaction]() {
                                        return !runtime_firewall_owner_
                                                    ->shutdown_requested() &&
                                            transaction->runtime_generation ==
                                                runtime_generation_.load(
                                                    std::memory_order_acquire);
                                    });
                            result->verified =
                                classify_runtime_routing_inventory(restored) ==
                                    RuntimeRoutingInventoryAuthority::
                                        authoritative &&
                                restored->outcome ==
                                    RuntimeRoutingOperationOutcome::
                                        compatibility_converged;
                            if (!result->verified) {
                                fail("cold-boot route preimage restore was not verified");
                            }
                        }
                    } else {
                        const auto cleared = routing_operation_owner_.clear();
                        const bool routing_cleared =
                            classify_runtime_routing_inventory(cleared) ==
                                RuntimeRoutingInventoryAuthority::
                                    authoritative &&
                            cleared->routes.empty() &&
                            cleared->rules.empty() &&
                            cleared->phase ==
                                RuntimeRoutingMutationPhase::cleared &&
                            cleared->outcome ==
                                RuntimeRoutingOperationOutcome::cleared;
                        bool firewall_cleared = false;
                        bool resolver_deactivated = false;
                        {
                            KPBR_LOCK_GUARD(
                                udp_call_affinity_mutation_mutex_);
                            firewall_cleared =
                                firewall_->cleanup_and_inspect_owned()
                                    .verified_absent();
                        }
                        const auto deactivate_args =
                            build_system_resolver_hook_args(
                                config_, "deactivate");
                        if (deactivate_args.empty()) {
                            resolver_deactivated = true;
                        } else {
                            KPBR_LOCK_GUARD(system_resolver_hook_mutex_);
                            resolver_deactivated =
                                hook_command_executor_(deactivate_args) == 0;
                        }
                        result->verified = routing_cleared &&
                            firewall_cleared && resolver_deactivated;
                        if (!result->verified) {
                            fail("cold-boot stopped-runtime rollback was not verified");
                        }
                    }
                } catch (const std::exception& error) {
                    fail(error.what());
                } catch (...) {
                    fail("cold-boot rollback failed with an unknown error");
                }
                result->body_finished.store(
                    true, std::memory_order_release);
            });
    } catch (...) {
        queued = false;
    }
    if (queued) {
        transaction->rollback_handoff_rejections = 0U;
        return;
    }

    try {
        if (result->completion_watchdog_task_id >= 0) {
            scheduler_->cancel(result->completion_watchdog_task_id);
        }
    } catch (...) {
    }
    result->control_claimed.store(true, std::memory_order_release);
    ++transaction->rollback_handoff_rejections;
    const bool retry_current = transaction->runtime_generation ==
            runtime_generation_.load(std::memory_order_acquire) &&
        !runtime_firewall_owner_->shutdown_requested();
    const bool retry_exact = *lease_holder &&
        static_cast<bool>(**lease_holder) &&
        (*lease_holder)->token() == transaction->mutation_lease_token &&
        runtime_mutation_admission_.owns(**lease_holder);
    const auto handoff_dispatch = plan_runtime_cold_boot_rollback_recovery(
        retry_exact,
        retry_current,
        /*rollback_verified=*/false,
        transaction->rollback_handoff_rejections,
        kRuntimeFirewallStartRollbackHandoffRetryLimit);
    if (handoff_dispatch ==
        RuntimeColdBootRollbackRecoveryDispatch::retry_same_authority) {
        const auto delay = kRuntimeFirewallStartRetryDelays[
            std::min(
                transaction->rollback_handoff_rejections - 1U,
                kRuntimeFirewallStartRetryDelays.size() - 1U)];
        try {
            const int task_id = scheduler_->schedule_oneshot(
                delay,
                [this,
                 transaction,
                 rollback_kind,
                 lease_holder]() noexcept {
                    auto exact = std::move(*lease_holder);
                    start_runtime_cold_boot_rollback(
                        transaction,
                        rollback_kind,
                        std::move(exact));
                },
                "runtime-cold-boot-rollback-handoff-retry");
            if (!runtime_cold_boot_scheduler_task_accepted(task_id)) {
                throw DaemonError(
                    "cold-boot rollback handoff retry was rejected");
            }
            return;
        } catch (...) {
        }
    }

    // The exact rollback never ran. Releasing authority is unavoidable, but
    // it is not permission to snapshot the mutated candidate as a new base.
    auto returned_lease = std::move(*lease_holder);
    returned_lease.reset();
    try {
        runtime_state_store_.set_routing_runtime_active(false);
        if (runtime_state_machine_.state() == RuntimeState::running ||
            runtime_state_machine_.state() == RuntimeState::starting) {
            transition_runtime_or_throw(
                RuntimeState::broken,
                "cold-boot rollback handoff exhausted");
        }
        publish_runtime_state();
    } catch (...) {
    }
    open_runtime_cold_boot_services(
        transaction, /*runtime_ready=*/false);
}

void Daemon::schedule_runtime_cold_boot_recovery(
    const std::shared_ptr<DaemonColdBootTransaction>& transaction,
    const char* detail) noexcept {
    if (!transaction || transaction->startup_services_opened ||
        runtime_firewall_owner_->shutdown_requested()) {
        return;
    }
    const auto budget = plan_runtime_cold_boot_candidate_budget(
        transaction->completed_candidate_bodies,
        kRuntimeFirewallStartBoundedRetryCount);
    const bool dispatch_retry_available =
        transaction->dispatch_rejections == 0U ||
        runtime_firewall_preapply_preworker_retry_available(
            transaction->dispatch_rejections);
    const auto recovery_dispatch =
        plan_runtime_cold_boot_fresh_recovery_dispatch(
            /*recovery_required=*/true,
            /*exact_lease_still_owned=*/false,
            budget.dispatch !=
                    RuntimeColdBootCandidateBudgetDispatch::exhausted &&
                dispatch_retry_available);
    if (recovery_dispatch ==
        RuntimeColdBootRecoveryDispatch::finish_available_degraded) {
        try {
            runtime_state_store_.set_routing_runtime_active(false);
            if (runtime_state_machine_.state() == RuntimeState::running ||
                runtime_state_machine_.state() == RuntimeState::starting) {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    "cold-boot recovery budget exhausted");
            }
            publish_runtime_state();
            Logger::instance().error(
                "Cold-boot recovery exhausted its bounded retry budget: {}",
                detail ? detail : "unknown failure");
        } catch (...) {
        }
        open_runtime_cold_boot_services(
            transaction, /*runtime_ready=*/false);
        return;
    }
    if (recovery_dispatch !=
        RuntimeColdBootRecoveryDispatch::schedule_with_backoff) {
        return;
    }
    const auto backoff_index = transaction->dispatch_rejections != 0U
        ? std::min(
              transaction->dispatch_rejections - 1U,
              kRuntimeFirewallStartRetryDelays.size() - 1U)
        : budget.backoff_index;
    const auto delay =
        kRuntimeFirewallStartRetryDelays[backoff_index];
    try {
        const int task_id = scheduler_->schedule_oneshot(
            delay,
            [this, transaction]() noexcept {
                start_runtime_cold_boot_attempt(transaction);
            },
            "runtime-cold-boot-fresh-recovery");
        if (!runtime_cold_boot_scheduler_task_accepted(task_id)) {
            throw DaemonError(
                "cold-boot fresh recovery timer was rejected");
        }
        Logger::instance().info(
            "Cold-boot recovery will take a fresh observation in {}ms: {}",
            delay.count(),
            detail ? detail : "retry requested");
    } catch (...) {
        transaction->completed_candidate_bodies =
            kRuntimeFirewallStartBoundedRetryCount;
        schedule_runtime_cold_boot_recovery(
            transaction, "cold-boot recovery timer could not be armed");
    }
}

void Daemon::open_runtime_cold_boot_services(
    const std::shared_ptr<DaemonColdBootTransaction>& transaction,
    bool runtime_ready) noexcept {
    if (!transaction ||
        !runtime_cold_boot_services_may_open(
            runtime_firewall_owner_->shutdown_requested(),
            transaction->startup_services_opened)) {
        return;
    }

#ifdef WITH_API
    try {
        setup_api();
    } catch (const std::exception& error) {
        try {
            Logger::instance().error(
                "Cold-boot diagnostics/API startup failed: {}",
                error.what());
        } catch (...) {
        }
        ++transaction->service_open_attempts;
        if (!runtime_firewall_owner_->shutdown_requested() &&
            transaction->service_open_attempts <
                kRuntimeFirewallStartBoundedRetryCount) {
            const auto delay = kRuntimeFirewallStartRetryDelays[
                std::min(
                    transaction->service_open_attempts - 1U,
                    kRuntimeFirewallStartRetryDelays.size() - 1U)];
            try {
                const int task_id = scheduler_->schedule_oneshot(
                    delay,
                    [this, transaction, runtime_ready]() noexcept {
                        open_runtime_cold_boot_services(
                            transaction, runtime_ready);
                    },
                    "runtime-cold-boot-service-open-retry");
                if (!runtime_cold_boot_scheduler_task_accepted(task_id)) {
                    throw DaemonError(
                        "cold-boot service retry was rejected");
                }
                return;
            } catch (...) {
            }
        }
        if (!runtime_ready) {
            try {
                runtime_state_store_.set_routing_runtime_active(false);
                if (runtime_state_machine_.state() == RuntimeState::running ||
                    runtime_state_machine_.state() ==
                        RuntimeState::starting) {
                    transition_runtime_or_throw(
                        RuntimeState::broken,
                        "cold-boot diagnostics/API startup failed");
                }
                publish_runtime_state();
            } catch (...) {
            }
        }
        return;
    } catch (...) {
        try {
            Logger::instance().error(
                "Cold-boot diagnostics/API startup failed with an unknown "
                "error");
        } catch (...) {
        }
        ++transaction->service_open_attempts;
        if (!runtime_firewall_owner_->shutdown_requested() &&
            transaction->service_open_attempts <
                kRuntimeFirewallStartBoundedRetryCount) {
            const auto delay = kRuntimeFirewallStartRetryDelays[
                std::min(
                    transaction->service_open_attempts - 1U,
                    kRuntimeFirewallStartRetryDelays.size() - 1U)];
            try {
                const int task_id = scheduler_->schedule_oneshot(
                    delay,
                    [this, transaction, runtime_ready]() noexcept {
                        open_runtime_cold_boot_services(
                            transaction, runtime_ready);
                    },
                    "runtime-cold-boot-service-open-retry");
                if (!runtime_cold_boot_scheduler_task_accepted(task_id)) {
                    throw DaemonError(
                        "cold-boot service retry was rejected");
                }
                return;
            } catch (...) {
            }
        }
        if (!runtime_ready) {
            try {
                runtime_state_store_.set_routing_runtime_active(false);
                if (runtime_state_machine_.state() == RuntimeState::running ||
                    runtime_state_machine_.state() ==
                        RuntimeState::starting) {
                    transition_runtime_or_throw(
                        RuntimeState::broken,
                        "cold-boot diagnostics/API startup failed");
                }
                publish_runtime_state();
            } catch (...) {
            }
        }
        return;
    }
#endif

    const bool post_setup_service_gate_open =
        runtime_cold_boot_services_may_open(
            runtime_firewall_owner_->shutdown_requested(),
            transaction->startup_services_opened);
#ifdef WITH_API
    if (!retain_api_runtime_after_setup_if_gate_open(
            post_setup_service_gate_open,
            [this]() noexcept { retire_api_runtime_resources(); })) {
        return;
    }
#else
    if (!post_setup_service_gate_open) {
        return;
    }
#endif

    // Only a successfully opened diagnostics/API boundary retires cold-boot
    // service admission. A transient bind/allocation failure above remains a
    // bounded, visible startup failure instead of a false one-shot success.
    transaction->startup_services_opened = true;
    transaction->service_open_attempts = 0U;

    const auto step = [](const char* label, auto&& callback) noexcept {
        try {
            callback();
        } catch (const std::exception& error) {
            try {
                Logger::instance().error(
                    "Cold-boot service '{}' failed: {}", label, error.what());
            } catch (...) {
            }
        } catch (...) {
            try {
                Logger::instance().error(
                    "Cold-boot service '{}' failed", label);
            } catch (...) {
            }
        }
    };

    step("DNS probe", [this] { setup_dns_probe(); });
    step("interface monitor", [this] { register_interface_monitor_fd(); });
#ifdef WITH_API
    step("remote-access bridge", [this] {
        setup_remote_access_retry_bridge();
        schedule_remote_access_recovery_watchdog();
        request_remote_access_reconcile_from_control("cold boot");
        schedule_nfqws_boot_recovery(0);
        schedule_nfqws_retention_backfill(0);
    });
#endif
    step("list autoupdate", [this] { schedule_lists_autoupdate(); });
    step("interface probes", [this] { schedule_interface_probe(); });
    step("catalog refresh", [this] { schedule_catalog_refresh(); });
    step("tunnel probe", [this] { schedule_tunnel_probe(); });

    if (runtime_ready) {
        step("runtime maintenance", [this, transaction] {
            reset_idle_stall_observer(/*schedule_if_eligible=*/true);
            schedule_owned_snat_health_check();
            schedule_keenetic_dns_refresh();
            if (internal_vpn_resolution_requires_catalog_refresh(
                    config_, transaction->interface_resolution_state) ||
                (config_requires_internal_vpn_service_inventory(config_) &&
                 transaction->service_resolution_state !=
                     InternalVpnRuntimeResolutionState::verified)) {
                schedule_internal_vpn_catalog_refresh_if_needed(
                    transaction->interface_resolution_state,
                    transaction->service_resolution_state);
            }
            register_urltest_outbounds();
            refresh_resolver_config_hash_actual_async();
            probe_interfaces_now();
        });
    } else {
        try {
            (void)runtime_firewall_incidents_.record_failure(
                "runtime-cold-boot",
                /*notify_immediately=*/true);
            publish_runtime_state();
        } catch (...) {
        }
    }

    try {
        Logger::instance().info(
            runtime_ready
                ? "Daemon startup route/firewall/resolver generation is verified."
                : "Daemon control and diagnostics are available; startup "
                  "routing generation remains degraded.");
    } catch (...) {
    }
}

bool Daemon::begin_preowned_runtime_firewall_keenetic_dns_refresh(
    std::uint64_t generation,
    KeeneticDnsCacheView candidate_view,
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot,
    std::unique_ptr<RuntimeMutationAdmission::Lease>& lease) noexcept {
    if (!lease || !static_cast<bool>(*lease) ||
        !runtime_mutation_admission_.owns(*lease) ||
        !runtime_firewall_lifecycle_generation_is_current(
            RuntimeFirewallLifecycleKind::keenetic_dns_candidate,
            generation) ||
        runtime_firewall_owner_->shutdown_requested() ||
        runtime_firewall_owner_->active_context() ||
        runtime_firewall_owner_->pending_successor() ||
        !list_cache_snapshot ||
        !resolver_generation_snapshot_ ||
        resolver_generation_snapshot_->generation != generation ||
        !resolver_generation_snapshot_->list_cache_snapshot ||
        list_cache_snapshot->fingerprints() !=
            resolver_generation_snapshot_
                ->list_cache_snapshot->fingerprints()) {
        return false;
    }

    try {
        auto transaction =
            std::make_shared<DaemonKeeneticDnsRefreshTransaction>();
        transaction->candidate_view = std::move(candidate_view);
        transaction->rollback_view = active_keenetic_dns_;
        transaction->list_cache_snapshot =
            resolver_generation_snapshot_->list_cache_snapshot;
        transaction->published_resolver_generation =
            resolver_generation_snapshot_;
        transaction->published_resolver_sync =
            resolver_sync_.checkpoint();
        transaction->published_resolver_retry_attempt =
            resolver_config_hash_actual_retry_attempt_;
        transaction->published_apply_started_ts =
            apply_started_ts_.load(std::memory_order_acquire);
        transaction->runtime_generation = generation;
        transaction->mutation_lease_token = lease->token();
        if (!transaction->terminal_orchestrator.begin(
                transaction->mutation_lease_token)) {
            return false;
        }

        auto candidate_generation =
            make_resolver_generation_snapshot(
                transaction->list_cache_snapshot,
                resolver_generation_snapshot_
                    ->trusted_dns_interfaces,
                &transaction->candidate_view);
        transaction->candidate_resolver_generation =
            std::make_shared<ResolverGenerationSnapshot>(
                std::move(candidate_generation));
        transaction->rollback_resolver_generation =
            transaction->published_resolver_generation;
        transaction->candidate_apply_started_ts =
            unix_timestamp_now_seconds();
        transaction->candidate_resolver_sync =
            transaction->published_resolver_sync;
        transaction->candidate_resolver_sync.expected_hash =
            transaction->candidate_resolver_generation->expected_hash;
        transaction->candidate_resolver_sync.apply_started_ts =
            transaction->candidate_apply_started_ts;
        transaction->candidate_resolver_sync.runtime_active = true;
        transaction->candidate_resolver_sync.resolver_configured = true;
        transaction->candidate_resolver_sync
            .consecutive_probe_failures = 0;

        RuntimeFirewallPreownedTerminalContinuation continuation{
            [this, transaction](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                complete_preowned_runtime_firewall_keenetic_dns_candidate(
                    transaction,
                    std::move(terminal),
                    std::move(exact));
            }};

        // Fence delayed Meta/idle writers before the private firewall
        // generation enters its route checkpoint. The exact mutation lease
        // remains the sole cross-phase writer authority.
        cancel_idle_stall_observer();
        cancel_meta_udp443_activation_cleanup();
        transaction->maintenance_fence_invalidated = true;
        {
            KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
        }

        return start_preowned_runtime_firewall_keenetic_dns_phase(
            transaction,
            RuntimeFirewallLifecycleKind::keenetic_dns_candidate,
            lease,
            continuation);
    } catch (...) {
        return false;
    }
}

bool Daemon::start_preowned_runtime_firewall_keenetic_dns_phase(
    const std::shared_ptr<DaemonKeeneticDnsRefreshTransaction>& transaction,
    RuntimeFirewallLifecycleKind lifecycle_kind,
    std::unique_ptr<RuntimeMutationAdmission::Lease>& lease,
    RuntimeFirewallPreownedTerminalContinuation& continuation) noexcept {
    if (!transaction ||
        !runtime_firewall_lifecycle_is_keenetic_dns_generation(
            lifecycle_kind) ||
        !lease || !static_cast<bool>(*lease) ||
        lease->token() != transaction->mutation_lease_token ||
        !runtime_mutation_admission_.owns(*lease) ||
        !runtime_firewall_lifecycle_generation_is_current(
            lifecycle_kind, transaction->runtime_generation) ||
        runtime_firewall_owner_->shutdown_requested()) {
        return false;
    }

    try {
        auto state =
            std::make_shared<DaemonRuntimeFirewallOperationState>();
        state->keenetic_dns_refresh_transaction = transaction;
        auto result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            transaction->runtime_generation,
            {},
            {},
            /*schedule_catalog_refresh=*/false,
            state,
            runtime_mutation_admission_,
            std::move(lease),
            {},
            lifecycle_kind,
            std::move(continuation));
        if (result.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off) {
            return true;
        }
        lease = std::move(result.unaccepted_lease);
        continuation = std::move(result.unaccepted_continuation);
    } catch (...) {
    }
    return false;
}

void Daemon::complete_preowned_runtime_firewall_keenetic_dns_candidate(
    const std::shared_ptr<DaemonKeeneticDnsRefreshTransaction>& transaction,
    RuntimeFirewallLifecycleTerminal terminal,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    if (!transaction) return;

    const std::uint64_t observed_lease_token =
        lease && static_cast<bool>(*lease) ? lease->token() : 0U;
    const bool exact_lease_owned =
        lease && static_cast<bool>(*lease) &&
        lease->token() == transaction->mutation_lease_token &&
        runtime_mutation_admission_.owns(*lease);
    const bool generation_current =
        runtime_generation_.load(std::memory_order_acquire) ==
        transaction->runtime_generation;
    if (!terminal.detail.empty()) {
        try {
            transaction->candidate_failure_detail = terminal.detail;
        } catch (...) {
        }
    }

    const bool candidate_terminal_verified =
        terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        terminal.committed && !terminal.commit_ambiguous &&
        exact_lease_owned && generation_current &&
        transaction->terminal_orchestrator.resolver_stream_verified(
            observed_lease_token);
    const bool candidate_publication_succeeded =
        candidate_terminal_verified &&
        publish_prepared_runtime_firewall_keenetic_dns_candidate(
            transaction);
    const auto action =
        transaction->terminal_orchestrator.complete_candidate(
        KeeneticDnsCandidateTerminalEvidence{
            terminal.outcome,
            terminal.committed,
            terminal.commit_ambiguous,
            terminal.previous_generation_certainly_retained,
            exact_lease_owned,
            generation_current,
            transaction->candidate_firewall_preimage_is_base,
            transaction->candidate_core_publication_ready &&
                transaction->candidate_route_firewall_commit_proven &&
                !runtime_firewall_owner_->shutdown_requested(),
            candidate_publication_succeeded,
            transaction->candidate_exact_rollback_available,
        },
        observed_lease_token);
    if (action ==
        KeeneticDnsCandidateTerminalAction::publish_candidate) {
        terminal.previous_generation_certainly_retained = false;
        finish_preowned_runtime_firewall_keenetic_dns_refresh(
            transaction, std::move(terminal), std::move(lease));
        return;
    }
    if (action ==
        KeeneticDnsCandidateTerminalAction::finish_clean_precommit) {
        terminal.previous_generation_certainly_retained = true;
        finish_preowned_runtime_firewall_keenetic_dns_refresh(
            transaction, std::move(terminal), std::move(lease));
        return;
    }
    if (action ==
        KeeneticDnsCandidateTerminalAction::request_fresh_recovery) {
        terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.previous_generation_certainly_retained = false;
        finish_preowned_runtime_firewall_keenetic_dns_refresh(
            transaction, std::move(terminal), std::move(lease));
        return;
    }

    RuntimeFirewallPreownedTerminalContinuation continuation;
    try {
        continuation = RuntimeFirewallPreownedTerminalContinuation{
            [this, transaction](
                RuntimeFirewallLifecycleTerminal rollback_terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                complete_preowned_runtime_firewall_keenetic_dns_rollback(
                    transaction,
                    std::move(rollback_terminal),
                    std::move(exact));
            }};
    } catch (...) {
        (void)transaction->terminal_orchestrator.complete_rollback(
            terminal,
            exact_lease_owned,
            generation_current,
            /*rollback_publication_succeeded=*/false,
            observed_lease_token);
        terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.previous_generation_certainly_retained = false;
        finish_preowned_runtime_firewall_keenetic_dns_refresh(
            transaction, std::move(terminal), std::move(lease));
        return;
    }

    if (!start_preowned_runtime_firewall_keenetic_dns_phase(
            transaction,
            RuntimeFirewallLifecycleKind::keenetic_dns_rollback,
            lease,
            continuation)) {
        (void)transaction->terminal_orchestrator.complete_rollback(
            terminal,
            exact_lease_owned,
            generation_current,
            /*rollback_publication_succeeded=*/false,
            observed_lease_token);
        terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.previous_generation_certainly_retained = false;
        try {
            terminal.detail =
                "exact Keenetic DNS rollback owner was not admitted";
        } catch (...) {
        }
        finish_preowned_runtime_firewall_keenetic_dns_refresh(
            transaction, std::move(terminal), std::move(lease));
    }
}

void Daemon::complete_preowned_runtime_firewall_keenetic_dns_rollback(
    const std::shared_ptr<DaemonKeeneticDnsRefreshTransaction>& transaction,
    RuntimeFirewallLifecycleTerminal terminal,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    if (!transaction) return;
    const std::uint64_t observed_lease_token =
        lease && static_cast<bool>(*lease) ? lease->token() : 0U;
    const bool exact_lease_owned =
        lease && static_cast<bool>(*lease) &&
        lease->token() == transaction->mutation_lease_token &&
        runtime_mutation_admission_.owns(*lease);
    const bool generation_current =
        runtime_generation_.load(std::memory_order_acquire) ==
        transaction->runtime_generation;
    const bool rollback_terminal_verified =
        terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        terminal.committed && !terminal.commit_ambiguous &&
        exact_lease_owned && generation_current &&
        transaction->terminal_orchestrator.resolver_stream_verified(
            observed_lease_token);
    const bool rollback_publication_succeeded =
        rollback_terminal_verified &&
        publish_prepared_runtime_firewall_keenetic_dns_rollback(
            transaction);
    const bool verified =
        transaction->terminal_orchestrator.complete_rollback(
            terminal,
            exact_lease_owned,
            generation_current,
            rollback_publication_succeeded,
            observed_lease_token) ==
        KeeneticDnsRollbackTerminalAction::finish_verified_rollback;
    terminal.previous_generation_certainly_retained = verified;
    if (verified) {
        try {
            terminal.detail = transaction->candidate_failure_detail;
        } catch (...) {
        }
    } else {
        terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        try {
            const auto detail = terminal.detail;
            terminal.detail =
                "Keenetic DNS rollback was not verified";
            if (!detail.empty()) {
                terminal.detail += ": ";
                terminal.detail += detail;
            }
        } catch (...) {
        }
    }
    finish_preowned_runtime_firewall_keenetic_dns_refresh(
        transaction, std::move(terminal), std::move(lease));
}

bool Daemon::publish_prepared_runtime_firewall_keenetic_dns_candidate(
    const std::shared_ptr<DaemonKeeneticDnsRefreshTransaction>& transaction)
    noexcept {
    if (!transaction) return false;
    return publish_keenetic_dns_generation_if_current(
        [this, &transaction]() noexcept {
            return !transaction->candidate_published &&
                transaction->candidate_core_publication_ready &&
                transaction->candidate_resolver_generation &&
                runtime_generation_.load(std::memory_order_acquire) ==
                    transaction->runtime_generation &&
                resolver_generation_snapshot_ ==
                    transaction->published_resolver_generation &&
                active_keenetic_dns_.status ==
                    transaction->rollback_view.status &&
                active_keenetic_dns_.refreshed ==
                    transaction->rollback_view.refreshed &&
                active_keenetic_dns_.changed ==
                    transaction->rollback_view.changed &&
                active_keenetic_dns_.generation ==
                    transaction->rollback_view.generation &&
                active_keenetic_dns_.error ==
                    transaction->rollback_view.error &&
                active_keenetic_dns_.snapshot.has_value() ==
                    transaction->rollback_view.snapshot.has_value() &&
                (!active_keenetic_dns_.snapshot.has_value() ||
                 keenetic_dns_snapshots_equal(
                     *active_keenetic_dns_.snapshot,
                     *transaction->rollback_view.snapshot));
        },
        [this, &transaction]() noexcept {
        auto& publication = transaction->candidate_core_publication;
        using std::swap;
        swap(active_keenetic_dns_, transaction->candidate_view);
        publish_runtime_firewall_core_checkpoint(
            publication,
            RuntimeFirewallCoreMetaPublication::retain_candidate);
        publish_runtime_resolver_checkpoint(
            transaction->candidate_resolver_generation,
            transaction->candidate_resolver_sync,
            /*retry_attempt=*/0U,
            transaction->candidate_apply_started_ts,
            RuntimeResolverGenerationPublication::retain_source);
        transaction->candidate_published = true;
        });
}

bool Daemon::publish_prepared_runtime_firewall_keenetic_dns_rollback(
    const std::shared_ptr<DaemonKeeneticDnsRefreshTransaction>& transaction)
    noexcept {
    if (!transaction) return false;
    return publish_keenetic_dns_generation_if_current(
        [this, &transaction]() noexcept {
            return !transaction->candidate_published &&
                transaction->rollback_core_publication_ready &&
                transaction->rollback_resolver_generation &&
                runtime_generation_.load(std::memory_order_acquire) ==
                    transaction->runtime_generation &&
                resolver_generation_snapshot_ ==
                    transaction->published_resolver_generation &&
                active_keenetic_dns_.status ==
                    transaction->rollback_view.status &&
                active_keenetic_dns_.refreshed ==
                    transaction->rollback_view.refreshed &&
                active_keenetic_dns_.changed ==
                    transaction->rollback_view.changed &&
                active_keenetic_dns_.generation ==
                    transaction->rollback_view.generation &&
                active_keenetic_dns_.error ==
                    transaction->rollback_view.error &&
                active_keenetic_dns_.snapshot.has_value() ==
                    transaction->rollback_view.snapshot.has_value() &&
                (!active_keenetic_dns_.snapshot.has_value() ||
                 keenetic_dns_snapshots_equal(
                     *active_keenetic_dns_.snapshot,
                     *transaction->rollback_view.snapshot));
        },
        [this, &transaction]() noexcept {
        auto& publication = transaction->rollback_core_publication;
        publish_runtime_firewall_core_checkpoint(
            publication,
            RuntimeFirewallCoreMetaPublication::retain_candidate);
        publish_runtime_resolver_checkpoint(
            transaction->rollback_resolver_generation,
            transaction->published_resolver_sync,
            transaction->published_resolver_retry_attempt,
            transaction->published_apply_started_ts,
            RuntimeResolverGenerationPublication::retain_source);
        });
}

void Daemon::finish_preowned_runtime_firewall_keenetic_dns_refresh(
    const std::shared_ptr<DaemonKeeneticDnsRefreshTransaction>& transaction,
    RuntimeFirewallLifecycleTerminal terminal,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    if (!transaction) return;
    const bool shutdown =
        terminal.outcome == RuntimeFirewallLifecycleOutcome::shutdown ||
        runtime_firewall_owner_->shutdown_requested();
    const bool candidate_published = transaction->candidate_published;
    const bool previous_generation_verified =
        !candidate_published &&
        terminal.previous_generation_certainly_retained;
    const bool rollback_verified =
        previous_generation_verified &&
        transaction->rollback_core_publication_ready;
    const bool clean_candidate_rejection =
        previous_generation_verified && !rollback_verified;
    const bool recovery_required =
        !shutdown && !candidate_published &&
        !previous_generation_verified;

    const auto finish_meta_tail =
        [this, transaction](
            const std::optional<MetaUdp443ActivationPlan>& plan,
            bool fastnat_healthy,
            bool filter_healthy) noexcept {
            try {
                const auto cleanup_epoch =
                    meta_udp443_cleanup_epoch_.load(
                        std::memory_order_acquire);
                if (plan.has_value()) {
                    schedule_meta_udp443_activation_cleanup_retry(
                        *plan,
                        transaction->runtime_generation,
                        cleanup_epoch,
                        fastnat_healthy && filter_healthy ? 0U : 1U);
                } else if (filter_healthy) {
                    meta_udp443_incidents_.reset(
                        "meta-udp443-activation");
                }
            } catch (...) {
            }
        };
    if (!shutdown && candidate_published) {
        finish_meta_tail(
            transaction->candidate_meta_activation_plan,
            transaction->candidate_meta_fastnat_healthy,
            transaction->candidate_meta_filter_healthy);
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
    } else if (!shutdown && rollback_verified) {
        finish_meta_tail(
            transaction->rollback_meta_activation_plan,
            transaction->rollback_meta_fastnat_healthy,
            transaction->rollback_meta_filter_healthy);
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
    }

    // The typed DNS transaction ends here. No fresh recovery owner, resolver
    // retry or state publication is started until the physical writer token
    // has been released.
    lease.reset();
    const bool recovery_dispatch_allowed =
        transaction->terminal_orchestrator
            .fresh_recovery_dispatch_allowed(
            recovery_required,
            lease && static_cast<bool>(*lease));
    const bool maintenance_refresh_required =
        !shutdown && clean_candidate_rejection &&
        transaction->maintenance_fence_invalidated;

    if (maintenance_refresh_required) {
        schedule_netfilter_runtime_refresh_noexcept(
            NetfilterRefreshReason::full,
            "Keenetic DNS clean rejection invalidated runtime maintenance");
    }
    if (recovery_dispatch_allowed) {
        resolver_after_firewall_gate_.wait_for(
            transaction->runtime_generation);
        try {
            runtime_firewall_owner_->schedule(
                0U, transaction->runtime_generation, OwnedSnatRecovery{});
        } catch (...) {
            (void)resolver_after_firewall_gate_.release(
                transaction->runtime_generation);
        }
        schedule_resolver_reload_retry(
            0U, transaction->runtime_generation);
    }
    if (!shutdown && !recovery_dispatch_allowed &&
        !maintenance_refresh_required) {
        resume_urltest_firewall_recovery(
            transaction->runtime_generation);
    }
    if (!shutdown &&
        (candidate_published || rollback_verified ||
         recovery_required)) {
        try {
            refresh_resolver_config_hash_actual_async();
        } catch (...) {
        }
    }
    try {
        publish_runtime_state();
    } catch (...) {
    }
}

bool Daemon::begin_preowned_runtime_firewall_urltest_selection(
    std::unique_ptr<RuntimeMutationAdmission::Lease>& lease,
    const UrltestSelectionChange& change,
    std::map<std::string, std::string> candidate_selections,
    std::map<std::string, std::string> rollback_selections,
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot,
    std::optional<std::uint32_t> retired_mark) noexcept {
    if (!lease || !static_cast<bool>(*lease) ||
        !runtime_mutation_admission_.owns(*lease) ||
        runtime_firewall_owner_->shutdown_requested()) {
        return false;
    }

    std::shared_ptr<DaemonUrltestSelectionTransaction> transaction;
    try {
        transaction =
            std::make_shared<DaemonUrltestSelectionTransaction>();
        transaction->change = change;
        transaction->candidate_selections =
            std::move(candidate_selections);
        transaction->rollback_selections =
            std::move(rollback_selections);
        transaction->list_cache_snapshot =
            std::move(list_cache_snapshot);
        transaction->retired_mark = retired_mark;
        transaction->runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        transaction->mutation_lease_token = lease->token();

        RuntimeFirewallPreownedTerminalContinuation continuation{
            [this, transaction](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                complete_preowned_runtime_firewall_urltest_candidate(
                    transaction,
                    std::move(terminal),
                    std::move(exact));
            }};

        // Fence every delayed writer which can touch runtime-only Meta or
        // call-affinity state before the first private URLTEST generation.
        // Both cancel operations advance their epochs. Taking the shared
        // mutation barrier afterwards waits out an already-running exact
        // pair/cleanup worker, so candidate and rollback COMMIT have one
        // exclusive writer boundary.
        cancel_idle_stall_observer();
        cancel_meta_udp443_activation_cleanup();
        transaction->maintenance_fence_invalidated = true;
        {
            KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
        }
        const auto terminal_start =
            transaction->terminal_orchestrator.begin_candidate(
                RuntimeUrltestMetaFence{
                    meta_udp443_cleanup_epoch_.load(
                        std::memory_order_acquire),
                    /*delayed_cleanup_invalidated=*/true,
                    /*mutation_barrier_crossed=*/true});
        if (!terminal_start.contains(
                RuntimeUrltestTerminalEffect::start_candidate)) {
            throw DaemonError(
                "URLTEST terminal owner rejected its maintenance fence");
        }
        const bool handed_off =
            start_preowned_runtime_firewall_urltest_phase(
            transaction,
            RuntimeFirewallLifecycleKind::urltest_candidate,
            lease,
            continuation);
        if (!handed_off) {
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "URLTEST owner rejected after maintenance fence");
        }
        return handed_off;
    } catch (...) {
        // Cancellation is deliberately irreversible: once either epoch was
        // advanced, only a fresh published-state generation may recreate the
        // old maintenance. The caller still owns the exact lease here, so the
        // request coalesces behind it and runs after return.
        if (transaction && transaction->maintenance_fence_invalidated) {
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "URLTEST candidate could not fence runtime maintenance");
        }
        return false;
    }
}

bool Daemon::start_preowned_runtime_firewall_urltest_phase(
    const std::shared_ptr<DaemonUrltestSelectionTransaction>& transaction,
    RuntimeFirewallLifecycleKind lifecycle_kind,
    std::unique_ptr<RuntimeMutationAdmission::Lease>& lease,
    RuntimeFirewallPreownedTerminalContinuation& continuation) noexcept {
    if (!transaction ||
        !runtime_firewall_lifecycle_is_urltest_generation(lifecycle_kind) ||
        !lease || !static_cast<bool>(*lease) ||
        lease->token() != transaction->mutation_lease_token ||
        !runtime_mutation_admission_.owns(*lease) ||
        !runtime_firewall_lifecycle_generation_is_current(
            lifecycle_kind, transaction->runtime_generation) ||
        runtime_firewall_owner_->shutdown_requested()) {
        return false;
    }

    try {
        auto state =
            std::make_shared<DaemonRuntimeFirewallOperationState>();
        state->urltest_selection_transaction = transaction;
        auto result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            transaction->runtime_generation,
            {},
            {},
            /*schedule_catalog_refresh=*/false,
            state,
            runtime_mutation_admission_,
            std::move(lease),
            {},
            lifecycle_kind,
            std::move(continuation));
        if (result.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off) {
            return true;
        }
        lease = std::move(result.unaccepted_lease);
        continuation = std::move(result.unaccepted_continuation);
    } catch (...) {
    }
    return false;
}

void Daemon::complete_preowned_runtime_firewall_urltest_candidate(
    const std::shared_ptr<DaemonUrltestSelectionTransaction>& transaction,
    RuntimeFirewallLifecycleTerminal terminal,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    if (!transaction) return;

    const bool exact_lease_owned = lease && static_cast<bool>(*lease) &&
        lease->token() == transaction->mutation_lease_token &&
        runtime_mutation_admission_.owns(*lease);
    const bool runtime_generation_current =
        runtime_generation_.load(std::memory_order_acquire) ==
        transaction->runtime_generation;
    bool manager_generation_current = false;
    try {
        const auto state = urltest_manager_
            ? urltest_manager_->get_state(transaction->change.urltest_tag)
            : std::nullopt;
        manager_generation_current = state.has_value() &&
            state->generation == transaction->change.probe_generation &&
            state->selected_outbound ==
                transaction->change.previous_child_tag;
    } catch (...) {
    }

    if (!terminal.detail.empty()) {
        try {
            transaction->candidate_failure_detail = terminal.detail;
        } catch (...) {
        }
    }

    UrltestCandidateEvidence evidence;
    evidence.exact_lease_owned = exact_lease_owned;
    evidence.runtime_generation_current = runtime_generation_current;
    evidence.manager_generation_current = manager_generation_current;
    evidence.exact_rollback_available = exact_lease_owned &&
        runtime_generation_current &&
        !runtime_firewall_owner_->shutdown_requested();
    evidence.terminal = std::move(terminal);

    const auto policy_action = plan_urltest_candidate_terminal(evidence);
    const bool exact_route_checkpoint_verified =
        evidence.terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        evidence.terminal.committed &&
        !evidence.terminal.commit_ambiguous;
    const bool combined_publication_succeeded =
        transaction->terminal_orchestrator
            .candidate_publication_admitted(
                evidence, exact_route_checkpoint_verified) &&
        publish_prepared_runtime_firewall_urltest_candidate(transaction);
    const auto terminal_transition =
        transaction->terminal_orchestrator.complete_candidate(
            evidence,
            exact_route_checkpoint_verified,
            combined_publication_succeeded);

    if (terminal_transition.contains(
            RuntimeUrltestTerminalEffect::
                publish_manager_and_firewall_candidate)) {
        finish_preowned_runtime_firewall_urltest_selection(
            transaction,
            std::move(evidence.terminal),
            std::move(lease));
        return;
    }
    if (policy_action == UrltestCandidateAction::publish_candidate) {
        try {
            transaction->candidate_failure_detail =
                "verified URLTEST candidate could not publish its exact cursor";
        } catch (...) {
        }
    }

    if (terminal_transition.contains(
            RuntimeUrltestTerminalEffect::release_exact_lease)) {
        if (terminal_transition.contains(
                RuntimeUrltestTerminalEffect::request_recovery)) {
            evidence.terminal.previous_generation_certainly_retained = false;
        }
        finish_preowned_runtime_firewall_urltest_selection(
            transaction,
            std::move(evidence.terminal),
            std::move(lease));
        return;
    }

    if (!terminal_transition.contains(
            RuntimeUrltestTerminalEffect::start_exact_rollback)) {
        evidence.terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        evidence.terminal.previous_generation_certainly_retained = false;
        finish_preowned_runtime_firewall_urltest_selection(
            transaction,
            std::move(evidence.terminal),
            std::move(lease));
        return;
    }

    RuntimeFirewallPreownedTerminalContinuation rollback_continuation;
    try {
        rollback_continuation =
            RuntimeFirewallPreownedTerminalContinuation{
                [this, transaction](
                    RuntimeFirewallLifecycleTerminal rollback_terminal,
                    std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                    noexcept {
                    complete_preowned_runtime_firewall_urltest_rollback(
                        transaction,
                        std::move(rollback_terminal),
                        std::move(exact));
                }};
    } catch (...) {
        evidence.terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        evidence.terminal.previous_generation_certainly_retained = false;
        finish_preowned_runtime_firewall_urltest_selection(
            transaction,
            std::move(evidence.terminal),
            std::move(lease));
        return;
    }

    if (!start_preowned_runtime_firewall_urltest_phase(
            transaction,
            RuntimeFirewallLifecycleKind::urltest_rollback,
            lease,
            rollback_continuation)) {
        evidence.terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        evidence.terminal.previous_generation_certainly_retained = false;
        try {
            evidence.terminal.detail =
                "exact URLTEST rollback owner was not admitted";
        } catch (...) {
        }
        finish_preowned_runtime_firewall_urltest_selection(
            transaction,
            std::move(evidence.terminal),
            std::move(lease));
    }
}

void Daemon::complete_preowned_runtime_firewall_urltest_rollback(
    const std::shared_ptr<DaemonUrltestSelectionTransaction>& transaction,
    RuntimeFirewallLifecycleTerminal terminal,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    if (!transaction) return;

    UrltestRollbackEvidence evidence;
    evidence.exact_lease_owned = lease && static_cast<bool>(*lease) &&
        lease->token() == transaction->mutation_lease_token &&
        runtime_mutation_admission_.owns(*lease);
    evidence.runtime_generation_current =
        runtime_generation_.load(std::memory_order_acquire) ==
        transaction->runtime_generation;
    evidence.terminal = std::move(terminal);

    const bool exact_route_checkpoint_verified =
        evidence.terminal.outcome ==
            RuntimeFirewallLifecycleOutcome::verified_success &&
        evidence.terminal.committed &&
        !evidence.terminal.commit_ambiguous;
    const bool combined_publication_succeeded =
        transaction->terminal_orchestrator
            .rollback_publication_admitted(
                evidence, exact_route_checkpoint_verified) &&
        publish_prepared_runtime_firewall_urltest_rollback(transaction);
    const auto terminal_transition =
        transaction->terminal_orchestrator.complete_rollback(
            evidence,
            exact_route_checkpoint_verified,
            combined_publication_succeeded);
    const bool verified = terminal_transition.contains(
        RuntimeUrltestTerminalEffect::
            publish_manager_and_firewall_rollback);
    evidence.terminal.previous_generation_certainly_retained = verified;
    if (verified) {
        try {
            evidence.terminal.detail =
                transaction->candidate_failure_detail;
        } catch (...) {
        }
    } else {
        evidence.terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        try {
            const auto detail = evidence.terminal.detail;
            evidence.terminal.detail = "URLTEST rollback was not verified";
            if (!detail.empty()) {
                evidence.terminal.detail += ": ";
                evidence.terminal.detail += detail;
            }
        } catch (...) {
        }
    }
    finish_preowned_runtime_firewall_urltest_selection(
        transaction,
        std::move(evidence.terminal),
        std::move(lease));
}

bool Daemon::publish_prepared_runtime_firewall_urltest_candidate(
    const std::shared_ptr<DaemonUrltestSelectionTransaction>& transaction)
    noexcept {
    if (!transaction || transaction->candidate_published ||
        !transaction->candidate_core_publication_ready ||
        runtime_generation_.load(std::memory_order_acquire) !=
            transaction->runtime_generation ||
        !urltest_manager_) {
        return false;
    }

    try {
        // The generation-fenced manager swap is the only fallible publication
        // step. Every Daemon publication below is a no-throw swap/scalar
        // commit, so the new selection cannot be left half-published.
        if (!urltest_manager_->synchronize_selected_if_generation(
                transaction->change.urltest_tag,
                transaction->change.probe_generation,
                transaction->change.new_child_tag)) {
            return false;
        }

        auto& publication = transaction->candidate_core_publication;
        publish_runtime_firewall_core_checkpoint(
            publication,
            RuntimeFirewallCoreMetaPublication::retain_candidate);
        firewall_state_.swap_urltest_selections(
            transaction->candidate_selections);
        transaction->candidate_published = true;
        return true;
    } catch (...) {
        return false;
    }
}

bool Daemon::publish_prepared_runtime_firewall_urltest_rollback(
    const std::shared_ptr<DaemonUrltestSelectionTransaction>& transaction)
    noexcept {
    if (!transaction || !transaction->rollback_core_publication_ready ||
        runtime_generation_.load(std::memory_order_acquire) !=
            transaction->runtime_generation ||
        !urltest_manager_) {
        return false;
    }

    auto& publication = transaction->rollback_core_publication;
    return publish_runtime_urltest_cursor_pair(
        [this, &transaction]() {
            return urltest_manager_->synchronize_selected_if_generation(
                transaction->change.urltest_tag,
                transaction->change.probe_generation,
                transaction->change.previous_child_tag);
        },
        [this, &transaction, &publication]() {
            publish_runtime_firewall_core_checkpoint(
                publication,
                RuntimeFirewallCoreMetaPublication::retain_candidate);
            firewall_state_.swap_urltest_selections(
                transaction->rollback_selections);
        });
}

void Daemon::finish_preowned_runtime_firewall_urltest_selection(
    const std::shared_ptr<DaemonUrltestSelectionTransaction>& transaction,
    RuntimeFirewallLifecycleTerminal terminal,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    if (!transaction) return;
    const bool shutdown = terminal.outcome ==
        RuntimeFirewallLifecycleOutcome::shutdown ||
        runtime_firewall_owner_->shutdown_requested();
    const bool candidate_published = transaction->candidate_published;
    const bool previous_generation_verified = !candidate_published &&
        terminal.previous_generation_certainly_retained;
    const bool rollback_verified = previous_generation_verified &&
        transaction->rollback_core_publication_ready;
    const bool clean_candidate_rejection = previous_generation_verified &&
        !transaction->rollback_core_publication_ready;
    const bool recovery_required = !shutdown && !candidate_published &&
        !previous_generation_verified;

    const auto finish_meta_tail =
        [this, transaction](
            const std::optional<MetaUdp443ActivationPlan>& plan,
            bool fastnat_healthy,
            bool filter_healthy) noexcept {
            try {
                const auto cleanup_epoch = transaction
                    ->terminal_orchestrator.meta_fence().cleanup_epoch;
                if (plan.has_value()) {
                    if (fastnat_healthy && filter_healthy) {
                        meta_udp443_incidents_.reset(
                            "meta-udp443-activation");
                        schedule_meta_udp443_activation_cleanup_retry(
                            *plan,
                            transaction->runtime_generation,
                            cleanup_epoch,
                            /*attempt=*/0U);
                    } else {
                        report_meta_udp443_degraded(
                            !fastnat_healthy
                                ? "FastNAT was re-enabled during URLTEST "
                                  "selection publication"
                                : "the exact owned first FORWARD hook could "
                                  "not be reverified after URLTEST selection");
                        schedule_meta_udp443_activation_cleanup_retry(
                            *plan,
                            transaction->runtime_generation,
                            cleanup_epoch,
                            /*attempt=*/1U);
                    }
                } else if (filter_healthy) {
                    meta_udp443_incidents_.reset(
                        "meta-udp443-activation");
                }
            } catch (...) {
            }
        };

    if (!shutdown && candidate_published) {
        finish_meta_tail(
            transaction->candidate_meta_activation_plan,
            transaction->candidate_meta_fastnat_healthy,
            transaction->candidate_meta_filter_healthy);
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
        if (transaction->retired_mark.has_value() &&
            runtime_generation_.load(std::memory_order_acquire) ==
                transaction->runtime_generation) {
            try {
                const auto owned_mask = fwmark_mask_value(
                    config_.fwmark.value_or(FwmarkConfig{}));
                const auto cleanup = conntrack_manager_.delete_mark(
                    *transaction->retired_mark, owned_mask);
                if (cleanup ==
                    ConntrackCleanupResult::CommandUnavailable) {
                    warn_conntrack_unavailable_once();
                } else if (cleanup == ConntrackCleanupResult::Failed) {
                    OwnedConntrackCleanupSnapshot snapshot;
                    snapshot.runtime_generation =
                        transaction->runtime_generation;
                    snapshot.owned_mask = owned_mask;
                    snapshot.ipv6_enabled =
                        resolve_ipv6_support(config_).enabled;
                    snapshot.marks.insert(*transaction->retired_mark);
                    snapshot.priority_marks.insert(
                        *transaction->retired_mark);
                    schedule_owned_conntrack_cleanup_retry(
                        snapshot, {*transaction->retired_mark});
                }
            } catch (...) {
            }
        }
        try {
            urltest_apply_incidents_.reset(
                transaction->change.urltest_tag);
        } catch (...) {
        }
    } else if (!shutdown && rollback_verified) {
        finish_meta_tail(
            transaction->rollback_meta_activation_plan,
            transaction->rollback_meta_fastnat_healthy,
            transaction->rollback_meta_filter_healthy);
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
    }

    // This tail still belongs to the typed URLTEST operation. Return its exact
    // admission before starting a fresh probe or central recovery owner.
    lease.reset();
    const bool maintenance_refresh_required =
        !shutdown && clean_candidate_rejection &&
        transaction->maintenance_fence_invalidated;

    if (maintenance_refresh_required) {
        // Candidate was rejected before either route or firewall publication,
        // but the old maintenance epochs were already invalidated. Recreate
        // them from a fresh authoritative published-state snapshot; never
        // replay the private URLTEST body.
        schedule_netfilter_runtime_refresh_noexcept(
            NetfilterRefreshReason::full,
            "URLTEST clean rejection invalidated runtime maintenance");
    }

    if (!shutdown && !candidate_published) {
        try {
            const auto incident = urltest_apply_incidents_.record_failure(
                transaction->change.urltest_tag,
                /*notify_immediately=*/recovery_required);
            if (incident.notify) {
                Logger::instance().error(
                    recovery_required
                        ? "Urltest '{}' candidate and exact rollback were not "
                          "verified: {}"
                        : "Urltest '{}' candidate was rejected; the previous "
                          "selection remains verified: {}",
                    transaction->change.urltest_tag,
                    terminal.detail);
            }
        } catch (...) {
        }
    }

    try {
        publish_runtime_state();
    } catch (...) {
    }

    if (recovery_required) {
        defer_urltest_switch_to_firewall_recovery(
            transaction->change,
            transaction->runtime_generation,
            "typed candidate/rollback",
            terminal.detail);
    } else if (!shutdown && !candidate_published && urltest_manager_) {
        try {
            urltest_manager_->trigger_external_health_test(
                transaction->change.urltest_tag);
        } catch (...) {
        }
    }
    if (!shutdown && !recovery_required &&
        !maintenance_refresh_required) {
        resume_urltest_firewall_recovery(
            transaction->runtime_generation);
    }
}

#ifdef WITH_API
void Daemon::begin_preowned_runtime_firewall_start(
    std::unique_ptr<RuntimeMutationAdmission::Lease> mutation_lease,
    RuntimeFirewallLifecycleCompletion::Source completion) {
    auto rejection_source = completion;
    const auto settle_rejection = [&rejection_source](
        std::string_view detail) noexcept {
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = false;
        terminal.commit_ambiguous = false;
        try {
            terminal.detail.assign(detail.data(), detail.size());
        } catch (...) {
        }
        (void)rejection_source.settle(std::move(terminal));
    };

    if (!mutation_lease || !static_cast<bool>(*mutation_lease) ||
        !runtime_mutation_admission_.owns(*mutation_lease)) {
        mutation_lease.reset();
        settle_rejection(
            "runtime start did not receive its exact mutation lease");
        throw DaemonError(
            "Runtime start lost its mutation admission before owner handoff");
    }
    if (routing_runtime_active()) {
        mutation_lease.reset();
        settle_rejection("routing runtime is already active");
        throw DaemonError("Routing runtime is already started");
    }

    // This is the only Keenetic DNS preflight for START. It is deliberately
    // cache-only and happens before state publication or any kernel mutation.
    KeeneticDnsCacheView prepared_keenetic_dns;
    try {
        prepared_keenetic_dns = prepare_keenetic_dns_view(
            config_, /*allow_refresh=*/false);
    } catch (const std::exception& error) {
        mutation_lease.reset();
        settle_rejection(error.what());
        throw;
    } catch (...) {
        mutation_lease.reset();
        settle_rejection("cache-only Keenetic DNS preparation failed");
        throw;
    }

    auto previous_keenetic_dns = active_keenetic_dns_;
    auto previous_urltest_selections =
        firewall_state_.get_urltest_selections();
    auto state = std::make_shared<DaemonRuntimeFirewallOperationState>();
    bool start_state_published = false;
    bool start_inputs_installed = false;

    const auto fail_before_handoff = [
        this,
        &previous_keenetic_dns,
        &previous_urltest_selections,
        &start_state_published,
        &start_inputs_installed,
        &mutation_lease,
        &settle_rejection](std::string_view detail) noexcept {
        if (start_inputs_installed) {
            try {
                using std::swap;
                swap(active_keenetic_dns_, previous_keenetic_dns);
            } catch (...) {
            }
            try {
                firewall_state_.swap_urltest_selections(
                    previous_urltest_selections);
            } catch (...) {
            }
            if (urltest_manager_) {
                try {
                    urltest_manager_->clear();
                } catch (...) {
                }
            }
        }
        try {
            cancel_idle_stall_observer();
        } catch (...) {
        }
        try {
            cancel_owned_snat_health_check();
        } catch (...) {
        }
        try {
            runtime_state_store_.set_routing_runtime_active(false);
        } catch (...) {
        }
        if (start_state_published) {
            try {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    "runtime start owner handoff failed");
                publish_runtime_state();
            } catch (...) {
            }
        }
        // Release exact mutation admission before waking the API waiter. All
        // operations above are catch-all guarded, so settlement cannot be
        // skipped by an ancillary cleanup failure.
        mutation_lease.reset();
        settle_rejection(detail);
    };

    RuntimeFirewallOperationOwner::PreownedImmediateStartResult result;
    try {
        cancel_idle_stall_observer();
        cancel_meta_udp443_activation_cleanup();
        cancel_owned_snat_health_check();
        cancel_owned_conntrack_cleanup_retry();
        cancel_resolver_reload_retry();
        urltest_after_firewall_gate_.reset();
        runtime_firewall_owner_->cancel_retry();
        runtime_firewall_retry_.clear_owned_snat_recovery();

        transition_runtime_or_throw(
            RuntimeState::starting, "runtime start requested");
        // The state machine has already changed even when publication throws;
        // the pre-handoff failure path must therefore move it to broken.
        start_state_published = true;
        publish_runtime_state();

        const auto generation =
            runtime_generation_.fetch_add(
                1U, std::memory_order_acq_rel) + 1U;
        active_keenetic_dns_ = std::move(prepared_keenetic_dns);
        start_inputs_installed = true;
        normalize_urltest_selections();
        register_urltest_outbounds();

        result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            generation,
            {},
            {},
            /*schedule_catalog_refresh=*/false,
            state,
            runtime_mutation_admission_,
            std::move(mutation_lease),
            std::move(completion),
            RuntimeFirewallLifecycleKind::start_from_stopped);
    } catch (const std::exception& error) {
        fail_before_handoff(error.what());
        throw;
    } catch (...) {
        fail_before_handoff(
            "runtime firewall owner rejected start during handoff");
        throw;
    }

    if (result.disposition !=
        RuntimeFirewallImmediateDisposition::handed_off) {
        fail_before_handoff(
            "runtime firewall owner already has an exact operation");
        throw DaemonError(
            "Runtime start was not admitted by the firewall owner");
    }

    rejection_source = {};
    try {
        Logger::instance().info(
            "Runtime start handed to the asynchronous firewall owner.");
    } catch (...) {
    }
}

void Daemon::begin_preowned_runtime_firewall_restart(
    std::unique_ptr<RuntimeMutationAdmission::Lease> mutation_lease,
    RuntimeFirewallLifecycleCompletion::Source completion) {
    auto rejection_source = completion;
    const auto settle_rejection = [&rejection_source](
        std::string_view detail) noexcept {
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = false;
        terminal.commit_ambiguous = false;
        try {
            terminal.detail.assign(detail.data(), detail.size());
        } catch (...) {
        }
        (void)rejection_source.settle(std::move(terminal));
    };

    if (!mutation_lease || !static_cast<bool>(*mutation_lease) ||
        !runtime_mutation_admission_.owns(*mutation_lease)) {
        mutation_lease.reset();
        settle_rejection(
            "runtime restart did not receive its exact mutation lease");
        throw DaemonError(
            "Runtime restart lost its mutation admission before owner handoff");
    }
    if (!routing_runtime_active()) {
        mutation_lease.reset();
        settle_rejection("routing runtime is stopped");
        throw DaemonError("Routing runtime is stopped");
    }

    // A timer-only background retry owns no mutation lease. Retire that timer
    // before the foreground operation is admitted, while preserving the
    // coordinator's exact pending SNAT recovery payload for this attempt.
    OwnedSnatRecovery pending_snat_recovery;
    std::shared_ptr<DaemonRuntimeFirewallOperationState> state;
    try {
        pending_snat_recovery =
            runtime_firewall_retry_.pending_owned_snat_recovery();
        runtime_firewall_owner_->cancel_retry();
        state =
            std::make_shared<DaemonRuntimeFirewallOperationState>();
    } catch (const std::exception& error) {
        mutation_lease.reset();
        settle_rejection(error.what());
        throw;
    } catch (...) {
        mutation_lease.reset();
        settle_rejection(
            "runtime restart preparation failed before owner handoff");
        throw;
    }

    RuntimeFirewallOperationOwner::PreownedImmediateStartResult result;
    try {
        result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            runtime_generation_.load(std::memory_order_acquire),
            pending_snat_recovery,
            {},
            /*schedule_catalog_refresh=*/true,
            state,
            runtime_mutation_admission_,
            std::move(mutation_lease),
            std::move(completion),
            RuntimeFirewallLifecycleKind::restart_active);
    } catch (...) {
        result.unaccepted_lease.reset();
        mutation_lease.reset();
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = false;
        terminal.commit_ambiguous = false;
        try {
            terminal.detail =
                "runtime firewall owner rejected restart during handoff";
        } catch (...) {
        }
        (void)rejection_source.settle(std::move(terminal));
        throw;
    }

    if (result.disposition !=
        RuntimeFirewallImmediateDisposition::handed_off) {
        // Destroying the exact returned lease below releases admission. The
        // copied source publishes a precise terminal instead of relying on
        // the conservative source-abandonment fallback.
        result.unaccepted_lease.reset();
        mutation_lease.reset();
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = false;
        terminal.commit_ambiguous = false;
        try {
            terminal.detail =
                "runtime firewall owner already has an exact operation";
        } catch (...) {
        }
        (void)rejection_source.settle(std::move(terminal));
        throw DaemonError(
            "Runtime restart was not admitted by the firewall owner");
    }

    // The owner now carries both the physical lease and completion source.
    // Release this extra producer and leave the control loop immediately.
    rejection_source = {};
    try {
        cancel_resolver_reload_retry();
    } catch (...) {
        // The accepted owner remains authoritative. Its resolver tail will
        // observe any still-running stream and schedule a fresh retry.
    }
    try {
        Logger::instance().info(
            "Runtime restart handed to the asynchronous firewall owner.");
    } catch (...) {
    }
}

std::optional<RuntimeFirewallImmediateDisposition>
Daemon::begin_preowned_runtime_firewall_config_preapply(
    std::unique_ptr<RuntimeMutationAdmission::Lease>& mutation_lease,
    RuntimeFirewallPreownedTerminalContinuation& continuation) {
    if (!mutation_lease || !static_cast<bool>(*mutation_lease) ||
        !runtime_mutation_admission_.owns(*mutation_lease) ||
        !continuation) {
        return RuntimeFirewallImmediateDisposition::rejected;
    }
    if (!routing_runtime_active()) {
        return std::nullopt;
    }
    if (runtime_firewall_owner_->shutdown_requested()) {
        return RuntimeFirewallImmediateDisposition::rejected;
    }
    const auto generation =
        runtime_generation_.load(std::memory_order_acquire);
    const auto committed_resolver_generation =
        resolver_generation_snapshot_;
    if (!committed_resolver_generation ||
        !committed_resolver_generation->list_cache_snapshot ||
        committed_resolver_generation->generation != generation) {
        // Exact rollback inputs are a prerequisite, not something to
        // reconstruct after the pre-apply worker has already repaired SNAT.
        // Leave the physical writer lease and every runtime owner untouched.
        return RuntimeFirewallImmediateDisposition::rejected;
    }

    OwnedSnatRecovery recovery =
        runtime_firewall_retry_.pending_owned_snat_recovery();
    // Config pre-apply is itself a strict current-generation SNAT
    // verification request. Mark it requested even when no earlier netfilter
    // event was latched so a verified terminal clears the exact coordinator
    // payload instead of leaving its broad snapshot behind.
    recovery.requested = true;
    const auto merge_cleanup_retry = [&recovery, generation](
        const OwnedConntrackCleanupRetry& retry) {
        if (!retry.valid() ||
            retry.snapshot.runtime_generation != generation) {
            return;
        }
        auto exact_remainder =
            owned_conntrack_cleanup_retry_remainder(retry);
        if (recovery.cleanup_snapshot.has_value()) {
            recovery.cleanup_snapshot =
                merge_owned_conntrack_cleanup_snapshot(
                    std::move(*recovery.cleanup_snapshot),
                    std::move(exact_remainder));
        } else {
            recovery.cleanup_snapshot =
                std::move(exact_remainder);
        }
    };
    if (active_owned_conntrack_cleanup_operation_) {
        merge_cleanup_retry(
            active_owned_conntrack_cleanup_operation_->retry());
    }
    if (pending_owned_conntrack_cleanup_retry_.has_value()) {
        merge_cleanup_retry(*pending_owned_conntrack_cleanup_retry_);
    }

    const bool background_timer_was_pending =
        runtime_firewall_retry_.retry_pending();
    runtime_firewall_owner_->cancel_retry();
    if (runtime_firewall_owner_->active_context() ||
        runtime_firewall_owner_->pending_successor()) {
        if (background_timer_was_pending) {
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "config pre-apply could not replace background timer");
        }
        return RuntimeFirewallImmediateDisposition::rejected;
    }

    RuntimeFirewallOperationOwner::PreownedImmediateStartResult result;
    try {
        auto state =
            std::make_shared<DaemonRuntimeFirewallOperationState>();
        result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            generation,
            std::move(recovery),
            {},
            /*schedule_catalog_refresh=*/false,
            state,
            runtime_mutation_admission_,
            std::move(mutation_lease),
            {},
            RuntimeFirewallLifecycleKind::config_preapply,
            std::move(continuation));
    } catch (...) {
        if (background_timer_was_pending) {
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "config pre-apply construction failed after timer replacement");
        }
        throw;
    }
    if (result.disposition ==
        RuntimeFirewallImmediateDisposition::handed_off) {
        // The accepted owner now carries the merged mandatory exact
        // remainder. Retire the old timer/operation before either can observe
        // admission after the request eventually crosses its generation.
        if (owned_conntrack_cleanup_retry_task_id_ >= 0) {
            const auto task_id =
                std::exchange(owned_conntrack_cleanup_retry_task_id_, -1);
            try {
                scheduler_->cancel(task_id);
            } catch (...) {
                // The callback is harmless after both durable retry slots are
                // cleared below: it observes no pending/active operation.
            }
        }
        pending_owned_conntrack_cleanup_retry_.reset();
        auto previous_cleanup =
            std::move(active_owned_conntrack_cleanup_operation_);
        if (previous_cleanup) previous_cleanup->cancel();
        return result.disposition;
    }

    mutation_lease = std::move(result.unaccepted_lease);
    continuation = std::move(result.unaccepted_continuation);
    if (background_timer_was_pending) {
        schedule_netfilter_runtime_refresh_noexcept(
            NetfilterRefreshReason::full,
            "config pre-apply owner rejected after timer replacement");
    }
    return RuntimeFirewallImmediateDisposition::rejected;
}

void Daemon::begin_preowned_runtime_firewall_config_apply(
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease,
    ActiveConfigSnapshotHandle base_active_snapshot,
    PreparedRuntimeInputs candidate,
    PreparedRuntimeInputs rollback,
    std::string saved_config_json,
    RuntimeFirewallPreownedTerminalContinuation final_continuation)
    noexcept {
    begin_preowned_runtime_firewall_config_generation(
        RuntimeConfigGenerationPublicationMode::staged_save,
        std::move(lease),
        std::move(base_active_snapshot),
        std::move(candidate),
        std::move(rollback),
        std::move(saved_config_json),
        std::move(final_continuation));
}

void Daemon::begin_preowned_runtime_firewall_config_bootstrap(
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease,
    ActiveConfigSnapshotHandle base_active_snapshot,
    PreparedRuntimeInputs candidate,
    PreparedRuntimeInputs rollback,
    std::string saved_config_json,
    RuntimeFirewallPreownedTerminalContinuation final_continuation)
    noexcept {
    begin_preowned_runtime_firewall_config_generation(
        RuntimeConfigGenerationPublicationMode::
            staged_bootstrap_from_stopped,
        std::move(lease),
        std::move(base_active_snapshot),
        std::move(candidate),
        std::move(rollback),
        std::move(saved_config_json),
        std::move(final_continuation));
}

void Daemon::begin_preowned_runtime_firewall_active_reload(
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease,
    ActiveConfigSnapshotHandle base_active_snapshot,
    PreparedRuntimeInputs candidate,
    PreparedRuntimeInputs rollback,
    RuntimeFirewallPreownedTerminalContinuation final_continuation)
    noexcept {
    begin_preowned_runtime_firewall_config_generation(
        RuntimeConfigGenerationPublicationMode::active_runtime_reload,
        std::move(lease),
        std::move(base_active_snapshot),
        std::move(candidate),
        std::move(rollback),
        {},
        std::move(final_continuation));
}

void Daemon::begin_preowned_runtime_firewall_config_generation(
    RuntimeConfigGenerationPublicationMode publication_mode,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease,
    ActiveConfigSnapshotHandle base_active_snapshot,
    PreparedRuntimeInputs candidate,
    PreparedRuntimeInputs rollback,
    std::string staged_serialized,
    RuntimeFirewallPreownedTerminalContinuation final_continuation)
    noexcept {
    const bool bootstrap_from_stopped = publication_mode ==
        RuntimeConfigGenerationPublicationMode::
            staged_bootstrap_from_stopped;
    const auto reject = [this, bootstrap_from_stopped](
        RuntimeFirewallPreownedTerminalContinuation continuation,
        std::unique_ptr<RuntimeMutationAdmission::Lease> exact,
        std::string_view detail,
        bool previous_retained) noexcept {
        RuntimeFirewallLifecycleTerminal terminal;
        terminal.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
        terminal.committed = false;
        terminal.commit_ambiguous = false;
        terminal.previous_generation_certainly_retained =
            previous_retained;
        try {
            terminal.detail.assign(detail.data(), detail.size());
        } catch (...) {
        }
        if (bootstrap_from_stopped) {
            try {
                if (!routing_runtime_active() &&
                    runtime_state_machine_.state() ==
                        RuntimeState::starting) {
                    transition_runtime_or_throw(
                        RuntimeState::stopped,
                        "stopped configuration bootstrap rejected");
                    publish_runtime_state();
                }
            } catch (...) {
                terminal.previous_generation_certainly_retained = false;
                try {
                    transition_runtime_or_throw(
                        RuntimeState::broken,
                        "stopped configuration bootstrap rejection state "
                        "could not be published");
                    publish_runtime_state();
                } catch (...) {
                }
            }
        }
        if (continuation) {
            continuation.invoke(
                std::move(terminal), std::move(exact));
        }
    };

    if (!lease || !static_cast<bool>(*lease) ||
        !runtime_mutation_admission_.owns(*lease) ||
        !base_active_snapshot || !final_continuation) {
        reject(
            std::move(final_continuation), std::move(lease),
            "configuration candidate did not receive its exact prepared "
            "authority",
            true);
        return;
    }
    const bool runtime_active = routing_runtime_active();
    if ((bootstrap_from_stopped ? runtime_active : !runtime_active) ||
        runtime_firewall_owner_->shutdown_requested()) {
        reject(
            std::move(final_continuation), std::move(lease),
            bootstrap_from_stopped
                ? "configuration bootstrap requires a stopped runtime"
                : "configuration candidate requires an active runtime owner",
            true);
        return;
    }
    if (!pending_exact_tcp_reset_cleanups_.empty()) {
        reject(
            std::move(final_continuation), std::move(lease),
            "exact TCP reset cleanup is still pending before the next "
            "configuration generation",
            true);
        return;
    }

    std::shared_ptr<DaemonConfigGenerationTransaction> transaction;
    try {
        if (config_store_.pin_active_snapshot() != base_active_snapshot) {
            reject(
                std::move(final_continuation), std::move(lease),
                "active configuration changed before candidate admission",
                true);
            return;
        }
        if (publication_mode ==
                RuntimeConfigGenerationPublicationMode::staged_save ||
            publication_mode ==
                RuntimeConfigGenerationPublicationMode::
                    staged_bootstrap_from_stopped) {
            const auto staged = config_store_.staged_snapshot();
            if (!staged || staged->second != staged_serialized) {
                reject(
                    std::move(final_continuation), std::move(lease),
                    "staged configuration changed before candidate "
                    "admission",
                    true);
                return;
            }
        }
        const auto base_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const auto committed_resolver_generation =
            resolver_generation_snapshot_;
        if (!bootstrap_from_stopped &&
            (!committed_resolver_generation ||
             !committed_resolver_generation->list_cache_snapshot ||
             committed_resolver_generation->generation !=
                 base_runtime_generation)) {
            reject(
                std::move(final_continuation), std::move(lease),
                "active runtime has no exact committed resolver/list "
                "snapshot for configuration rollback",
                true);
            return;
        }

        // Rebind only the candidate from the current cache-only NDMS view.
        // Rollback below is the exact already-published generation, not a
        // newly interpreted version of the old JSON.
        if (config_has_stable_internal_vpn_server_policy(
                candidate.config)) {
            candidate.internal_vpn_resolution =
                resolve_internal_vpn_servers_for_runtime(
                    candidate.config,
                    false,
                    snapshot_internal_vpn_verified_includes_lkg());
        }
        if (config_requires_internal_vpn_service_inventory(
                candidate.config)) {
            candidate.internal_vpn_service_resolution =
                resolve_internal_vpn_services_for_runtime(
                    candidate.config,
                    false,
                    snapshot_internal_vpn_service_verified_includes_lkg());
        }

        if (!bootstrap_from_stopped) {
            rollback.config = config_;
            rollback.outbound_marks = outbound_marks_;
            rollback.keenetic_dns =
                committed_resolver_generation->keenetic_dns;
            rollback.internal_vpn_resolution.effective_servers =
                resolved_internal_vpn_servers_;
            rollback.internal_vpn_service_resolution.effective_targets =
                resolved_internal_vpn_service_targets_;
        }

        transaction =
            std::make_shared<DaemonConfigGenerationTransaction>();
        // From this point every failure must return the exact lease through
        // the initiating waiter. Move the continuation before any resolver/
        // list preparation which may allocate or throw.
        transaction->publication_mode = publication_mode;
        transaction->final_continuation =
            std::move(final_continuation);
        transaction->base_runtime_generation =
            base_runtime_generation;
        transaction->candidate_runtime_generation =
            transaction->base_runtime_generation + 1U;
        transaction->mutation_lease_token = lease->token();
        transaction->apply_started_ts =
            unix_timestamp_now_seconds();
        transaction->previous_runtime_active =
            routing_runtime_active();
        transaction->candidate_firewall_policy =
            firewall_config_apply_policy(
                firewall_->backend(), config_, candidate.config);
        transaction->rollback_firewall_policy =
            firewall_config_apply_policy(
                firewall_->backend(), candidate.config, rollback.config);
        transaction->candidate_firewall_outbound_marks =
            candidate.outbound_marks;
        const auto current_urltest_selections =
            firewall_state_.get_urltest_selections();
        transaction->candidate_urltest_selections =
            normalized_urltest_selections_for_config(
                candidate.config,
                candidate.outbound_marks,
                current_urltest_selections);
        transaction->rollback_urltest_selections =
            current_urltest_selections;
        transaction->candidate_list_cache_snapshot =
            capture_relevant_list_cache_generation(candidate.config);
        if (!bootstrap_from_stopped) {
            transaction->rollback_list_cache_snapshot =
                committed_resolver_generation->list_cache_snapshot;
        }

        const auto make_private_resolver_generation = [this](
            const PreparedRuntimeInputs& prepared,
            std::shared_ptr<const ListCacheGenerationSnapshot> list_snapshot,
            std::vector<std::string> trusted_interfaces,
            std::uint64_t generation) {
            RuntimeResolverGenerationInput input;
            input.config = prepared.config;
            input.keenetic_dns = prepared.keenetic_dns;
            input.list_cache_snapshot = std::move(list_snapshot);
            input.list_max_file_size_bytes =
                max_file_size_bytes(prepared.config);
            input.resolver_type =
                firewall_->backend() == FirewallBackend::nftables
                    ? ResolverType::DNSMASQ_NFTSET
                    : ResolverType::DNSMASQ_IPSET;
            input.ipv6_policy = resolver_ipv6_policy(
                resolve_ipv6_support(prepared.config));
            input.trusted_dns_interfaces =
                std::move(trusted_interfaces);
            input.generation = generation;
            return std::make_shared<const ResolverGenerationSnapshot>(
                build_runtime_resolver_generation_snapshot(input));
        };

        transaction->candidate_resolver_generation =
            make_private_resolver_generation(
                candidate,
                transaction->candidate_list_cache_snapshot,
                build_dnsmasq_trusted_interfaces(
                    candidate.internal_vpn_resolution.effective_servers,
                    candidate.internal_vpn_service_resolution
                        .effective_targets),
                transaction->candidate_runtime_generation);
        if (!bootstrap_from_stopped) {
            transaction->rollback_resolver_generation =
                committed_resolver_generation;
        }

        transaction->candidate_resolver_sync =
            resolver_sync_.checkpoint();
        transaction->candidate_resolver_sync.expected_hash =
            transaction->candidate_resolver_generation->expected_hash;
        transaction->candidate_resolver_sync.apply_started_ts =
            transaction->apply_started_ts;
        transaction->candidate_resolver_sync.consecutive_probe_failures = 0;
        transaction->candidate_resolver_sync.runtime_active = true;
        transaction->candidate_resolver_sync.resolver_configured = true;

        switch (publication_mode) {
        case RuntimeConfigGenerationPublicationMode::staged_save:
        case RuntimeConfigGenerationPublicationMode::
                 staged_bootstrap_from_stopped:
            transaction->active_commit =
                ConfigStore::prepare_active_commit(
                    std::move(base_active_snapshot),
                    candidate.config,
                    candidate.outbound_marks,
                    std::move(staged_serialized));
            break;
        case RuntimeConfigGenerationPublicationMode::active_runtime_reload:
            transaction->active_runtime_reload_commit =
                ConfigStore::prepare_active_runtime_reload_commit(
                    std::move(base_active_snapshot),
                    candidate.config,
                    candidate.outbound_marks);
            break;
        }
        transaction->candidate = std::move(candidate);
        transaction->rollback = std::move(rollback);
    } catch (const std::exception& error) {
        reject(
            transaction
                ? std::move(transaction->final_continuation)
                : std::move(final_continuation),
            std::move(lease), error.what(), true);
        return;
    } catch (...) {
        reject(
            transaction
                ? std::move(transaction->final_continuation)
                : std::move(final_continuation),
            std::move(lease),
            "configuration candidate preparation failed", true);
        return;
    }

    RuntimeFirewallPreownedTerminalContinuation continuation;
    try {
        continuation = RuntimeFirewallPreownedTerminalContinuation{
            [this, transaction](
                RuntimeFirewallLifecycleTerminal terminal,
                std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                noexcept {
                complete_preowned_runtime_firewall_config_candidate(
                    transaction,
                    std::move(terminal),
                    std::move(exact));
            }};
    } catch (...) {
        reject(
            std::move(transaction->final_continuation),
            std::move(lease),
            "configuration candidate continuation could not be prepared",
            true);
        return;
    }
    try {
        // Invalidate the old generation's delayed Meta cleanup before any
        // private candidate can touch the firewall. Taking the same barrier
        // after the epoch bump waits out an already-running exact cleanup;
        // no old selector can then race candidate or rollback COMMIT.
        cancel_meta_udp443_activation_cleanup();
        transaction->meta_cleanup_invalidated = true;
        {
            KPBR_LOCK_GUARD(udp_call_affinity_mutation_mutex_);
        }
    } catch (...) {
        if (!bootstrap_from_stopped) {
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "configuration candidate could not fence Meta cleanup");
        }
        reject(
            std::move(transaction->final_continuation),
            std::move(lease),
            "configuration candidate could not fence delayed Meta cleanup",
            true);
        return;
    }
    if (bootstrap_from_stopped) {
        try {
            runtime_firewall_owner_->cancel_retry();
            if (runtime_firewall_owner_->active_context() ||
                runtime_firewall_owner_->pending_successor()) {
                reject(
                    std::move(transaction->final_continuation),
                    std::move(lease),
                    "configuration bootstrap owner is busy",
                    true);
                return;
            }
            transition_runtime_or_throw(
                RuntimeState::starting,
                "stopped configuration bootstrap started");
            publish_runtime_state();
        } catch (const std::exception& error) {
            reject(
                std::move(transaction->final_continuation),
                std::move(lease), error.what(), true);
            return;
        } catch (...) {
            reject(
                std::move(transaction->final_continuation),
                std::move(lease),
                "configuration bootstrap state could not be published",
                true);
            return;
        }
    }
    const auto lifecycle_kind = bootstrap_from_stopped
        ? RuntimeFirewallLifecycleKind::config_bootstrap_from_stopped
        : RuntimeFirewallLifecycleKind::config_candidate;
    if (!start_preowned_runtime_firewall_config_phase(
            transaction,
            lifecycle_kind,
            lease,
            continuation)) {
        if (!bootstrap_from_stopped) {
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "configuration candidate owner rejected after Meta cleanup "
                "invalidation");
        }
        reject(
            std::move(transaction->final_continuation),
            std::move(lease),
            "configuration candidate owner did not accept the operation",
            true);
    }
}

bool Daemon::start_preowned_runtime_firewall_config_phase(
    const std::shared_ptr<DaemonConfigGenerationTransaction>& transaction,
    RuntimeFirewallLifecycleKind lifecycle_kind,
    std::unique_ptr<RuntimeMutationAdmission::Lease>& lease,
    RuntimeFirewallPreownedTerminalContinuation& continuation) noexcept {
    if (!transaction || !lease || !static_cast<bool>(*lease) ||
        lease->token() != transaction->mutation_lease_token ||
        !runtime_mutation_admission_.owns(*lease) || !continuation ||
        !runtime_firewall_lifecycle_is_config_generation(lifecycle_kind) ||
        runtime_generation_.load(std::memory_order_acquire) !=
            transaction->base_runtime_generation ||
        runtime_firewall_owner_->shutdown_requested()) {
        return false;
    }
    try {
        auto state =
            std::make_shared<DaemonRuntimeFirewallOperationState>();
        state->config_generation_transaction = transaction;
        auto result = runtime_firewall_owner_->start_immediate_preowned(
            0U,
            transaction->base_runtime_generation,
            {},
            {},
            /*schedule_catalog_refresh=*/false,
            state,
            runtime_mutation_admission_,
            std::move(lease),
            {},
            lifecycle_kind,
            std::move(continuation));
        if (result.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off) {
            return true;
        }
        lease = std::move(result.unaccepted_lease);
        continuation =
            std::move(result.unaccepted_continuation);
    } catch (...) {
    }
    return false;
}

void Daemon::complete_preowned_runtime_firewall_config_candidate(
    const std::shared_ptr<DaemonConfigGenerationTransaction>& transaction,
    RuntimeFirewallLifecycleTerminal terminal,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    if (!transaction) return;
    const bool exact_lease_owned = lease && static_cast<bool>(*lease) &&
        lease->token() == transaction->mutation_lease_token &&
        runtime_mutation_admission_.owns(*lease);
    ConfigCandidateEvidence evidence;
    evidence.expected_identity = transaction->candidate_identity;
    evidence.exact_lease_owned = exact_lease_owned;
    evidence.published_generation_current =
        runtime_generation_.load(std::memory_order_acquire) ==
        transaction->base_runtime_generation;
    evidence.terminal = std::move(terminal);
    const bool bootstrap_from_stopped = transaction->publication_mode ==
        RuntimeConfigGenerationPublicationMode::
            staged_bootstrap_from_stopped;
    evidence.exact_rollback_available = !bootstrap_from_stopped &&
        exact_lease_owned &&
        transaction->rollback_resolver_generation &&
        !runtime_firewall_owner_->shutdown_requested();

    if (!evidence.terminal.detail.empty()) {
        try {
            transaction->candidate_failure_detail =
                evidence.terminal.detail;
        } catch (...) {
        }
    }
    if (bootstrap_from_stopped) {
        auto completion = complete_config_bootstrap_publication(
            std::move(evidence),
            [this, transaction]() noexcept {
                return publish_prepared_runtime_firewall_config_candidate(
                    transaction);
            });
        if (completion.commit_attempted &&
            !completion.candidate_published) {
            try {
                transaction->candidate_failure_detail =
                    "candidate was verified in the router but its exact "
                    "ConfigStore publication was rejected";
                completion.terminal.detail =
                    transaction->candidate_failure_detail;
            } catch (...) {
            }
        }
        finish_preowned_runtime_firewall_config_apply(
            transaction,
            std::move(completion.terminal),
            std::move(lease));
        return;
    }
    const auto action = plan_config_candidate_terminal(evidence);
    if (action == ConfigCandidateAction::publish_candidate) {
        if (publish_prepared_runtime_firewall_config_candidate(
                transaction)) {
            finish_preowned_runtime_firewall_config_apply(
                transaction,
                std::move(evidence.terminal),
                std::move(lease));
            return;
        }
        try {
            transaction->candidate_failure_detail =
                "candidate was verified in the router but its exact "
                "ConfigStore publication was rejected";
        } catch (...) {
        }
    } else if (action ==
               ConfigCandidateAction::reject_runtime_unchanged) {
        finish_preowned_runtime_firewall_config_apply(
            transaction,
            std::move(evidence.terminal),
            std::move(lease));
        return;
    } else if (action == ConfigCandidateAction::recovery_required) {
        evidence.terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        evidence.terminal.previous_generation_certainly_retained = false;
        finish_preowned_runtime_firewall_config_apply(
            transaction,
            std::move(evidence.terminal),
            std::move(lease));
        return;
    }

    RuntimeFirewallPreownedTerminalContinuation rollback_continuation;
    try {
        rollback_continuation =
            RuntimeFirewallPreownedTerminalContinuation{
                [this, transaction](
                    RuntimeFirewallLifecycleTerminal rollback_terminal,
                    std::unique_ptr<RuntimeMutationAdmission::Lease> exact)
                    noexcept {
                    complete_preowned_runtime_firewall_config_rollback(
                        transaction,
                        std::move(rollback_terminal),
                        std::move(exact));
                }};
    } catch (...) {
        evidence.terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        evidence.terminal.previous_generation_certainly_retained = false;
        finish_preowned_runtime_firewall_config_apply(
            transaction,
            std::move(evidence.terminal),
            std::move(lease));
        return;
    }
    if (!start_preowned_runtime_firewall_config_phase(
            transaction,
            RuntimeFirewallLifecycleKind::config_rollback,
            lease,
            rollback_continuation)) {
        evidence.terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        evidence.terminal.previous_generation_certainly_retained = false;
        try {
            evidence.terminal.detail =
                "exact configuration rollback owner was not admitted";
        } catch (...) {
        }
        finish_preowned_runtime_firewall_config_apply(
            transaction,
            std::move(evidence.terminal),
            std::move(lease));
    }
}

void Daemon::complete_preowned_runtime_firewall_config_rollback(
    const std::shared_ptr<DaemonConfigGenerationTransaction>& transaction,
    RuntimeFirewallLifecycleTerminal terminal,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    if (!transaction) return;
    ConfigRollbackEvidence evidence;
    evidence.expected_identity = transaction->rollback_identity;
    evidence.exact_lease_owned = lease && static_cast<bool>(*lease) &&
        lease->token() == transaction->mutation_lease_token &&
        runtime_mutation_admission_.owns(*lease);
    evidence.published_generation_current =
        runtime_generation_.load(std::memory_order_acquire) ==
        transaction->base_runtime_generation;
    evidence.terminal = std::move(terminal);
    const bool verified_rollback =
        plan_config_rollback_terminal(evidence) ==
        ConfigRollbackAction::accept_verified_rollback;
    if (!verified_rollback) {
        evidence.terminal.outcome =
            RuntimeFirewallLifecycleOutcome::not_verified;
        evidence.terminal.previous_generation_certainly_retained = false;
        try {
            const auto rollback_detail = evidence.terminal.detail;
            evidence.terminal.detail =
                "configuration rollback was not verified";
            if (!rollback_detail.empty()) {
                evidence.terminal.detail += ": ";
                evidence.terminal.detail += rollback_detail;
            }
        } catch (...) {
        }
    } else {
        try {
            evidence.terminal.detail =
                transaction->candidate_failure_detail;
        } catch (...) {
        }
        if (!transaction->rollback_tail_scheduled) {
            transaction->rollback_tail_scheduled = true;
            try {
                cancel_meta_udp443_activation_cleanup();
                const auto cleanup_epoch =
                    meta_udp443_cleanup_epoch_.load(
                        std::memory_order_acquire);
                if (transaction
                        ->rollback_meta_activation_plan.has_value()) {
                    if (transaction->rollback_meta_fastnat_healthy &&
                        transaction->rollback_meta_filter_healthy) {
                        meta_udp443_incidents_.reset(
                            "meta-udp443-activation");
                        schedule_meta_udp443_activation_cleanup_retry(
                            std::move(
                                *transaction
                                     ->rollback_meta_activation_plan),
                            transaction->base_runtime_generation,
                            cleanup_epoch,
                            /*attempt=*/0U);
                    } else {
                        report_meta_udp443_degraded(
                            !transaction->rollback_meta_fastnat_healthy
                                ? "FastNAT was re-enabled during "
                                  "configuration rollback"
                                : "the exact owned first FORWARD hook "
                                  "could not be reverified after "
                                  "configuration rollback");
                        schedule_meta_udp443_activation_cleanup_retry(
                            std::move(
                                *transaction
                                     ->rollback_meta_activation_plan),
                            transaction->base_runtime_generation,
                            cleanup_epoch,
                            /*attempt=*/1U);
                        if (transaction
                                ->rollback_meta_fastnat_healthy) {
                            transaction
                                ->post_terminal_refresh_required = true;
                            transaction
                                ->post_terminal_full_refresh = true;
                        }
                    }
                } else if (
                    transaction->rollback_meta_filter_healthy) {
                    meta_udp443_incidents_.reset(
                        "meta-udp443-activation");
                } else {
                    report_meta_udp443_degraded(
                        "configuration rollback could not verify absence "
                        "of owned UDP/443 artifacts");
                    transaction->post_terminal_refresh_required = true;
                    transaction->post_terminal_full_refresh = true;
                }
            } catch (...) {
                transaction->post_terminal_refresh_required = true;
                transaction->post_terminal_full_refresh = true;
            }

            if (transaction->rollback_cleanup_scope_prepared) {
                try {
                    if (transaction->previous_runtime_active &&
                        runtime_generation_.load(
                            std::memory_order_acquire) ==
                            transaction->base_runtime_generation &&
                        !transaction
                             ->rollback_native_source_cleanup_cidrs
                             .empty()) {
                        const auto cleanup =
                            conntrack_manager_
                                .delete_ipv4_source_cidrs(
                                    transaction
                                        ->rollback_native_source_cleanup_cidrs,
                                    ConntrackSourceCleanupOptions{
                                        std::chrono::seconds{4},
                                        /*max_source_cidrs=*/32U});
                        if (cleanup.command_unavailable) {
                            Logger::instance().info(
                                "Native VPN direct-egress SNAT was "
                                "rolled back, but targeted conntrack "
                                "cleanup is unavailable; existing flows "
                                "will converge as they expire");
                        } else if (
                            cleanup.failed != 0U ||
                            cleanup.skipped != 0U) {
                            Logger::instance().info(
                                "Native VPN direct-egress rollback "
                                "cleanup left {} failed and {} skipped "
                                "source selector(s)",
                                cleanup.failed,
                                cleanup.skipped);
                        }
                    }
                } catch (...) {
                    try {
                        Logger::instance().info(
                            "Native VPN direct-egress rollback cleanup "
                            "was skipped; existing flows will converge "
                            "as they expire");
                    } catch (...) {
                    }
                }
                try {
                    const auto rollback_fwmark = fwmark_mask_value(
                        transaction->rollback.config.fwmark.value_or(
                            FwmarkConfig{}));
                    execute_committed_stale_flow_reconnect(
                        transaction->base_runtime_generation,
                        transaction->previous_runtime_active,
                        transaction->rollback_forwarded_scope_exact,
                        rollback_fwmark,
                        transaction->rollback_normal_retirement,
                        transaction->rollback_aggressive_retirement);
                } catch (...) {
                    transaction->post_terminal_refresh_required = true;
                    transaction->post_terminal_full_refresh = true;
                }
            } else {
                transaction->post_terminal_refresh_required = true;
                transaction->post_terminal_full_refresh = true;
            }
            try {
                reset_idle_stall_observer(
                    /*schedule_if_eligible=*/true);
            } catch (...) {
            }
        }
    }
    finish_preowned_runtime_firewall_config_apply(
        transaction,
        std::move(evidence.terminal),
        std::move(lease));
}

bool Daemon::publish_prepared_runtime_firewall_config_candidate(
    const std::shared_ptr<DaemonConfigGenerationTransaction>& transaction)
    noexcept {
    if (!transaction || transaction->candidate_published ||
        !transaction->candidate_core_publication_ready ||
        !transaction->candidate_resolver_generation ||
        runtime_generation_.load(std::memory_order_acquire) !=
            transaction->base_runtime_generation) {
        return false;
    }
    const bool bootstrap_from_stopped = transaction->publication_mode ==
        RuntimeConfigGenerationPublicationMode::
            staged_bootstrap_from_stopped;
    const auto candidate_fwmark = fwmark_mask_value(
        transaction->candidate.config.fwmark.value_or(FwmarkConfig{}));
    try {
        auto& publication =
            transaction->candidate_core_publication;
        auto cleanup = prepare_config_transition_cleanup_plan(
            transaction->previous_runtime_active,
            config_,
            firewall_state_.get_rules(),
            applied_list_content_state_,
            applied_native_vpn_direct_egress_snat_selectors_,
            resolved_internal_vpn_servers_,
            resolved_internal_vpn_service_targets_,
            transaction->candidate.config,
            publication);
        transaction->candidate_forwarded_scope_exact =
            cleanup.forwarded_scope_exact;
        transaction->candidate_native_source_cleanup_cidrs =
            std::move(cleanup.native_source_cleanup_cidrs);
        transaction->candidate_normal_retirement =
            std::move(cleanup.normal_retirement);
        transaction->candidate_aggressive_retirement =
            std::move(cleanup.aggressive_retirement);
    } catch (...) {
        // No irreversible post-COMMIT cleanup may be improvised. Failure to
        // prepare its exact bounded scope keeps ConfigStore on the base
        // generation and sends the already-mutated candidate to rollback.
        return false;
    }
    try {
        const auto publish_candidate =
            [this, &transaction, candidate_fwmark]() noexcept {
                using std::swap;
                auto& publication =
                    transaction->candidate_core_publication;
                swap(config_, transaction->candidate.config);
                outbound_marks_.swap(
                    transaction->candidate.outbound_marks);
                swap(active_keenetic_dns_,
                     transaction->candidate.keenetic_dns);
                firewall_state_.swap_outbound_marks(
                    transaction->candidate_firewall_outbound_marks);
                firewall_state_.set_fwmark_mask(candidate_fwmark);
                firewall_state_.swap_urltest_selections(
                    transaction->candidate_urltest_selections);
                publish_runtime_firewall_core_checkpoint(
                    publication,
                    RuntimeFirewallCoreMetaPublication::retain_candidate);
                publish_runtime_resolver_checkpoint(
                    transaction->candidate_resolver_generation,
                    transaction->candidate_resolver_sync,
                    /*retry_attempt=*/0U,
                    transaction->apply_started_ts,
                    RuntimeResolverGenerationPublication::
                        exchange_preimage);
                // This is the publication fence. ConfigStore readers are
                // blocked by its unique lock until the prepared active handle
                // is swapped immediately after this callback returns.
                runtime_generation_.store(
                    transaction->candidate_runtime_generation,
                    std::memory_order_release);
            };
        bool committed = false;
        switch (transaction->publication_mode) {
        case RuntimeConfigGenerationPublicationMode::staged_save:
        case RuntimeConfigGenerationPublicationMode::
                 staged_bootstrap_from_stopped:
            committed = config_store_.commit_prepared_active(
                transaction->active_commit,
                publish_candidate) ==
                PreparedActiveConfigCommitResult::committed;
            break;
        case RuntimeConfigGenerationPublicationMode::active_runtime_reload:
            committed =
                config_store_.commit_prepared_active_runtime_reload(
                    transaction->active_runtime_reload_commit,
                    publish_candidate) ==
                PreparedActiveRuntimeReloadCommitResult::committed;
            break;
        }
        if (!committed) {
            return false;
        }
        transaction->candidate_published = true;
        if (bootstrap_from_stopped) {
            try {
                runtime_state_store_.set_routing_runtime_active(true);
                transition_runtime_or_throw(
                    RuntimeState::running,
                    "stopped configuration bootstrap complete");
            } catch (...) {
                runtime_state_store_.set_routing_runtime_active(false);
                try {
                    transition_runtime_or_throw(
                        RuntimeState::broken,
                        "stopped configuration bootstrap publication failed");
                    publish_runtime_state();
                } catch (...) {
                }
                return false;
            }
        }
    } catch (...) {
        return false;
    }

    // Everything below is ancillary and may allocate or touch service
    // sockets. The kernel+resolver candidate is already verified and the
    // generation is published; an ancillary failure must not launch rollback.
    cancel_meta_udp443_activation_cleanup();
    const auto meta_cleanup_epoch =
        meta_udp443_cleanup_epoch_.load(std::memory_order_acquire);
    if (transaction->candidate_meta_activation_plan.has_value()) {
        if (transaction->candidate_meta_fastnat_healthy &&
            transaction->candidate_meta_filter_healthy) {
            meta_udp443_incidents_.reset("meta-udp443-activation");
            schedule_meta_udp443_activation_cleanup_retry(
                std::move(
                    *transaction->candidate_meta_activation_plan),
                transaction->candidate_runtime_generation,
                meta_cleanup_epoch,
                /*attempt=*/0U);
        } else {
            report_meta_udp443_degraded(
                !transaction->candidate_meta_fastnat_healthy
                    ? "FastNAT was re-enabled during configuration "
                      "publication"
                    : "the exact owned first FORWARD hook could not be "
                      "reverified after configuration publication");
            schedule_meta_udp443_activation_cleanup_retry(
                std::move(
                    *transaction->candidate_meta_activation_plan),
                transaction->candidate_runtime_generation,
                meta_cleanup_epoch,
                /*attempt=*/1U);
            if (transaction->candidate_meta_fastnat_healthy) {
                schedule_netfilter_runtime_refresh_noexcept(
                    NetfilterRefreshReason::full,
                    "could not repair configuration Meta UDP/443 "
                    "publication");
            }
        }
    } else if (transaction->candidate_meta_filter_healthy) {
        meta_udp443_incidents_.reset("meta-udp443-activation");
    } else {
        report_meta_udp443_degraded(
            "configuration publication could not verify absence of owned "
            "UDP/443 artifacts");
        schedule_netfilter_runtime_refresh_noexcept(
            NetfilterRefreshReason::full,
            "could not clean stale configuration Meta UDP/443 artifacts");
    }
    try {
        if (transaction->previous_runtime_active &&
            runtime_generation_.load(std::memory_order_acquire) ==
                transaction->candidate_runtime_generation &&
            !transaction->candidate_native_source_cleanup_cidrs.empty()) {
            const auto cleanup =
                conntrack_manager_.delete_ipv4_source_cidrs(
                    transaction
                        ->candidate_native_source_cleanup_cidrs,
                    ConntrackSourceCleanupOptions{
                        std::chrono::seconds{4},
                        /*max_source_cidrs=*/32U});
            if (cleanup.command_unavailable) {
                Logger::instance().info(
                    "Native VPN direct-egress SNAT changed, but targeted "
                    "post-configuration conntrack cleanup is unavailable; "
                    "existing flows will converge as they expire");
            } else if (
                cleanup.failed != 0U || cleanup.skipped != 0U) {
                Logger::instance().info(
                    "Native VPN direct-egress SNAT changed; targeted "
                    "post-configuration cleanup left {} failed and {} "
                    "skipped source selector(s)",
                    cleanup.failed,
                    cleanup.skipped);
            }
        }
    } catch (const std::exception& error) {
        try {
            Logger::instance().info(
                "Native VPN direct-egress post-configuration cleanup was "
                "skipped: {}; existing flows will converge as they expire",
                error.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            Logger::instance().info(
                "Native VPN direct-egress post-configuration cleanup was "
                "skipped by an unknown error; existing flows will converge "
                "as they expire");
        } catch (...) {
        }
    }
    execute_committed_stale_flow_reconnect(
        transaction->candidate_runtime_generation,
        transaction->previous_runtime_active,
        transaction->candidate_forwarded_scope_exact,
        candidate_fwmark,
        transaction->candidate_normal_retirement,
        transaction->candidate_aggressive_retirement);
    try {
        update_internal_vpn_verified_includes_lkg(
            transaction->candidate.internal_vpn_resolution);
        update_internal_vpn_service_verified_includes_lkg(
            transaction->candidate.internal_vpn_service_resolution);
    } catch (...) {
    }
    try {
        if (urltest_manager_) urltest_manager_->clear();
        register_urltest_outbounds();
    } catch (...) {
    }
    try {
        teardown_dns_probe();
        setup_dns_probe();
    } catch (...) {
    }
    try {
        schedule_keenetic_dns_refresh();
        schedule_lists_autoupdate();
        if (bootstrap_from_stopped) {
            schedule_owned_snat_health_check();
        }
        schedule_internal_vpn_catalog_refresh_if_needed(
            transaction->candidate.internal_vpn_resolution.state,
            transaction->candidate.internal_vpn_service_resolution.state);
    } catch (...) {
    }
    try {
        refresh_interface_traffic_config_targets(config_);
    } catch (...) {
    }
    try {
        refresh_resolver_config_hash_actual_async();
    } catch (...) {
    }
    try {
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
    } catch (...) {
    }
    try {
        request_remote_access_reconcile_from_control(
            "configuration generation publication");
    } catch (...) {
    }
    try {
        publish_runtime_state();
    } catch (...) {
    }
    return true;
}

void Daemon::finish_preowned_runtime_firewall_config_apply(
    const std::shared_ptr<DaemonConfigGenerationTransaction>& transaction,
    RuntimeFirewallLifecycleTerminal terminal,
    std::unique_ptr<RuntimeMutationAdmission::Lease> lease) noexcept {
    if (!transaction || !transaction->final_continuation) return;
    const bool bootstrap_from_stopped = transaction->publication_mode ==
        RuntimeConfigGenerationPublicationMode::
            staged_bootstrap_from_stopped;
    const auto runtime_terminal_action =
        plan_config_runtime_terminal(
            transaction->candidate_published, terminal);
    const auto bootstrap_terminal_action =
        plan_config_bootstrap_terminal(
            transaction->candidate_published, terminal);
    bool runtime_terminal_safe = bootstrap_from_stopped
        ? bootstrap_terminal_action ==
              ConfigBootstrapTerminalAction::keep_running
        : runtime_terminal_action ==
              ConfigRuntimeTerminalAction::keep_active;
    bool fail_closed = bootstrap_from_stopped
        ? bootstrap_terminal_action ==
              ConfigBootstrapTerminalAction::fail_closed
        : runtime_terminal_action ==
              ConfigRuntimeTerminalAction::fail_closed;
    if (bootstrap_from_stopped &&
        bootstrap_terminal_action ==
            ConfigBootstrapTerminalAction::restore_stopped) {
        try {
            runtime_state_store_.set_routing_runtime_active(false);
            if (runtime_state_machine_.state() != RuntimeState::stopped) {
                transition_runtime_or_throw(
                    RuntimeState::stopped,
                    "stopped configuration bootstrap retained its base");
            }
            publish_runtime_state();
        } catch (...) {
            fail_closed = true;
            runtime_terminal_safe = false;
            terminal.previous_generation_certainly_retained = false;
            try {
                terminal.detail =
                    "stopped configuration bootstrap could not restore "
                    "its stopped publication";
            } catch (...) {
            }
        }
    }
    if (fail_closed) {
        // An unknown candidate/rollback terminal is not a healthy base
        // generation. Fail closed before returning the mutation lease so no
        // later writer or health reader can trust the old running label.
        runtime_state_store_.set_routing_runtime_active(false);
        cancel_idle_stall_observer();
        cancel_meta_udp443_activation_cleanup();
        cancel_resolver_reload_retry();
        try {
            transition_runtime_or_throw(
                RuntimeState::broken,
                "configuration generation terminal is unknown");
            publish_runtime_state();
        } catch (const std::exception& error) {
            try {
                Logger::instance().error(
                    "Could not publish broken runtime after an unknown "
                    "configuration terminal: {}",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
        }
    }
    const auto terminal_route_epoch =
        terminal.observed_config_identity &&
                terminal.observed_config_identity->kind ==
                    ConfigTerminalOperationKind::candidate
            ? transaction->candidate_route_epoch
            : transaction->rollback_route_epoch;
    bool refresh_after_lease_return =
        runtime_terminal_safe &&
        transaction->post_terminal_refresh_required;
    bool full_refresh_after_lease_return =
        transaction->post_terminal_full_refresh;
    if (runtime_terminal_safe &&
        terminal_route_epoch != 0U &&
        routing_observation_epoch_.load(std::memory_order_acquire) !=
            terminal_route_epoch) {
        refresh_after_lease_return = true;
        full_refresh_after_lease_return = true;
    }
    if (runtime_terminal_safe &&
        transaction->meta_cleanup_invalidated &&
        !transaction->candidate_published &&
        !transaction->rollback_tail_scheduled) {
        // A clean pre-worker rejection still invalidated the old delayed
        // cleanup epoch. Recreate maintenance from a fresh published-state
        // snapshot instead of replaying the private candidate.
        refresh_after_lease_return = true;
        full_refresh_after_lease_return = true;
    }
    if (refresh_after_lease_return) {
        try {
            (void)runtime_firewall_retry_.retain_recovery(
                transaction->post_terminal_snat_recovery);
        } catch (...) {
            full_refresh_after_lease_return = true;
        }
    }
    auto continuation =
        std::move(transaction->final_continuation);
    continuation.invoke(
        std::move(terminal), std::move(lease));
    if (refresh_after_lease_return) {
        schedule_netfilter_runtime_refresh_noexcept(
            full_refresh_after_lease_return
                ? NetfilterRefreshReason::full
                : NetfilterRefreshReason::nat_only,
            full_refresh_after_lease_return
                ? "configuration transaction requires a fresh backend "
                  "snapshot"
                : "configuration transaction retained exact SNAT "
                  "recovery");
    }
}
#endif

void Daemon::dispatch_runtime_firewall_worker_attempt(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context,
    RuntimeFirewallOperationClaim queued_claim,
    OwnedSnatRecovery snat_recovery_input,
    PreparedNativeVpnCatalogPtr prepared_native_vpn_catalog,
    bool schedule_catalog_refresh) {
    if (!context || !runtime_firewall_owner_->is_active(context)) {
        runtime_firewall_owner_->terminate_before_worker(
            context,
            queued_claim,
            RuntimeFirewallOperationContext::SuccessorMode::
                defer_same_attempt,
            /*force_rerun=*/true);
        return;
    }
    auto& state = runtime_firewall_domain_state(context);
    const bool lifecycle_preapply =
        runtime_firewall_lifecycle_is_preapply(
            context->lifecycle_kind);
    const bool lifecycle_config_generation =
        runtime_firewall_lifecycle_is_config_generation(
            context->lifecycle_kind);
    const bool lifecycle_urltest_generation =
        runtime_firewall_lifecycle_is_urltest_generation(
            context->lifecycle_kind);
    const bool lifecycle_keenetic_dns_generation =
        runtime_firewall_lifecycle_is_keenetic_dns_generation(
            context->lifecycle_kind);
    const bool lifecycle_stop_cleanup =
        runtime_firewall_lifecycle_is_stop_cleanup(
            context->lifecycle_kind);
    const bool lifecycle_exact_tcp_reset_point =
        runtime_firewall_lifecycle_is_exact_tcp_reset_point(
            context->lifecycle_kind);
    const bool lifecycle_background_point_mutation =
        runtime_firewall_lifecycle_is_background_point_mutation(
            context->lifecycle_kind);
    const bool lifecycle_preowned =
        runtime_firewall_lifecycle_uses_preowned_continuation(
            context->lifecycle_kind);

    context->queued_claim = queued_claim;
    if (lifecycle_config_generation) {
        const auto transaction =
            state.config_generation_transaction;
        if (!transaction) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            state.preworker_failure_detail =
                "configuration generation transaction is unavailable";
            runtime_firewall_owner_->terminate_before_worker(
                context,
                queued_claim,
                RuntimeFirewallOperationContext::SuccessorMode::none,
                /*force_rerun=*/false);
            return;
        }
        ConfigTerminalOperationIdentity identity;
        identity.kind = runtime_firewall_lifecycle_is_config_candidate(
                context->lifecycle_kind)
            ? ConfigTerminalOperationKind::candidate
            : ConfigTerminalOperationKind::rollback;
        identity.operation_serial = queued_claim.serial;
        identity.base_runtime_generation = identity.kind ==
                ConfigTerminalOperationKind::candidate
            ? transaction->base_runtime_generation
            : transaction->candidate_runtime_generation;
        identity.target_runtime_generation = identity.kind ==
                ConfigTerminalOperationKind::candidate
            ? transaction->candidate_runtime_generation
            : transaction->candidate_runtime_generation + 1U;
        state.config_operation_identity = identity;
        if (identity.kind == ConfigTerminalOperationKind::candidate) {
            transaction->candidate_identity = identity;
        } else {
            transaction->rollback_identity = identity;
        }
    }
    if (lifecycle_urltest_generation &&
        !state.urltest_selection_transaction) {
        state.preworker_failure_kind =
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                preparation_failure;
        state.preworker_failure_detail =
            "URLTEST selection transaction is unavailable";
        runtime_firewall_owner_->terminate_before_worker(
            context,
            queued_claim,
            RuntimeFirewallOperationContext::SuccessorMode::none,
            /*force_rerun=*/false);
        return;
    }
    if (lifecycle_keenetic_dns_generation &&
        !state.keenetic_dns_refresh_transaction) {
        state.preworker_failure_kind =
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                preparation_failure;
        state.preworker_failure_detail =
            "Keenetic DNS refresh transaction is unavailable";
        runtime_firewall_owner_->terminate_before_worker(
            context,
            queued_claim,
            RuntimeFirewallOperationContext::SuccessorMode::none,
            /*force_rerun=*/false);
        return;
    }
    context->submitted_snat_recovery = std::move(snat_recovery_input);
    auto& snat_recovery = context->submitted_snat_recovery;
    context->prepared_native_vpn_catalog =
        prepared_native_vpn_catalog;
    context->schedule_catalog_refresh = schedule_catalog_refresh;
    context->successor_attempt = queued_claim.attempt;
    context->successor_runtime_generation =
        queued_claim.runtime_generation;
    context->successor_schedule_catalog_refresh =
        schedule_catalog_refresh;
    // Until the worker publishes and control proves success, every
    // pre-worker loss keeps the exact attempt. This also covers executor
    // rejection, whose queue envelope owns the sole terminalization.
    context->successor_mode =
        RuntimeFirewallOperationContext::SuccessorMode::
            defer_same_attempt;
    // Arm before any fallible preparation. Admission contention, input
    // allocation and executor rejection all publish a durable pre-worker
    // terminal and need the same independent drain fallback.
    if (!runtime_firewall_owner_->arm_completion_watchdog(context)) {
        runtime_firewall_owner_->terminate_before_worker(
            context,
            queued_claim,
            RuntimeFirewallOperationContext::SuccessorMode::
                defer_same_attempt,
            /*force_rerun=*/true);
        // No asynchronous fallback exists when watchdog registration fails.
        // We are still on the control loop and no worker has been queued, so
        // consume the exact coordinator terminal synchronously.
        drain_runtime_firewall_terminal(context, /*shutdown=*/false);
        return;
    }

    const auto terminalize_before_worker = [this, &context, queued_claim](
        RuntimeFirewallOperationContext::SuccessorMode successor_mode,
        bool force_rerun) {
        runtime_firewall_owner_->terminate_before_worker(
            context, queued_claim, successor_mode, force_rerun);
    };

    if (!runtime_firewall_lifecycle_generation_is_current(
            context->lifecycle_kind,
            queued_claim.runtime_generation)) {
        terminalize_before_worker(
            RuntimeFirewallOperationContext::SuccessorMode::none,
            /*force_rerun=*/false);
        return;
    }

    if (lifecycle_background_point_mutation) {
        context->successor_mode =
            RuntimeFirewallOperationContext::SuccessorMode::none;
        context->force_successor = false;
        state.suppress_coordinator_rerun = true;
        const auto transaction =
            state.background_point_mutation_transaction;
        if (!context->retained_mutation_lease || !transaction ||
            !transaction->valid() ||
            transaction->target.runtime_generation() !=
                queued_claim.runtime_generation) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            state.preworker_failure_detail =
                "background point mutation target is unavailable";
            terminalize_before_worker(
                RuntimeFirewallOperationContext::SuccessorMode::none,
                /*force_rerun=*/false);
            return;
        }

        try {
            auto worker_input =
                std::make_shared<RuntimeFirewallWorkerAttemptInput>();
            worker_input->operation_kind =
                RuntimeFirewallWorkerOperationKind::
                    background_point_mutation;
            worker_input->transaction.operation_serial = queued_claim.serial;
            worker_input->transaction.runtime_generation =
                queued_claim.runtime_generation;
            const auto target = transaction->target;
            worker_input->background_point_mutation_target = target;
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    transport_rejected;
            state.preworker_failure_detail =
                "background point mutation worker queue rejected the target";

            RuntimeFirewallOperationOwner::WorkerRunner runner{
                [this, target](
                    const RuntimeFirewallWorkerAttemptInput& input,
                    const RuntimeFirewallDelayedWorker::RunningClaim&
                        running_claim)
                    -> RuntimeFirewallWorkerAttemptResultPtr {
                    auto result =
                        std::make_shared<RuntimeFirewallWorkerAttemptResult>();
                    auto point = std::make_shared<
                        RuntimeBackgroundPointMutationResult>();
                    result->operation_kind =
                        RuntimeFirewallWorkerOperationKind::
                            background_point_mutation;
                    result->transaction.operation_serial =
                        input.transaction.operation_serial;
                    result->transaction.runtime_generation =
                        input.transaction.runtime_generation;
                    point->target = target;
                    result->background_point_mutation = point;

                    const auto& raw_claim = running_claim.raw_claim();
                    if (raw_claim.serial !=
                            input.transaction.operation_serial ||
                        raw_claim.runtime_generation !=
                            input.transaction.runtime_generation ||
                        !input.background_point_mutation_target.has_value() ||
                        *input.background_point_mutation_target != target) {
                        return result;
                    }
                    point->worker_started = true;
                    execute_runtime_background_point_mutation(target, *point);
                    return result;
                }};

            const bool enqueued =
                runtime_firewall_owner_->enqueue_worker_with_retained_lease(
                    context,
                    queued_claim,
                    std::move(worker_input),
                    std::move(runner));
            if (enqueued) {
                state.preworker_failure_kind =
                    DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                        none;
                state.preworker_failure_detail.clear();
            }
        } catch (const std::exception& error) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            try {
                state.preworker_failure_detail = error.what();
            } catch (...) {
            }
            if (context->worker_operation) {
                context->worker_operation.reset();
            } else {
                terminalize_before_worker(
                    RuntimeFirewallOperationContext::SuccessorMode::none,
                    /*force_rerun=*/false);
            }
        } catch (...) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            state.preworker_failure_detail =
                "background point mutation worker preparation failed";
            if (context->worker_operation) {
                context->worker_operation.reset();
            } else {
                terminalize_before_worker(
                    RuntimeFirewallOperationContext::SuccessorMode::none,
                    /*force_rerun=*/false);
            }
        }
        return;
    }

    if (lifecycle_exact_tcp_reset_point) {
        context->successor_mode =
            RuntimeFirewallOperationContext::SuccessorMode::none;
        context->force_successor = false;
        state.suppress_coordinator_rerun = true;
        if (!context->retained_mutation_lease ||
            !state.exact_tcp_reset_point_target.has_value() ||
            !state.exact_tcp_reset_point_target->valid() ||
            state.exact_tcp_reset_point_target->runtime_generation !=
                queued_claim.runtime_generation) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            state.preworker_failure_detail =
                "exact TCP reset point target is unavailable";
            terminalize_before_worker(
                RuntimeFirewallOperationContext::SuccessorMode::none,
                /*force_rerun=*/false);
            return;
        }

        try {
            auto worker_input =
                std::make_shared<RuntimeFirewallWorkerAttemptInput>();
            worker_input->operation_kind =
                RuntimeFirewallWorkerOperationKind::
                    exact_tcp_reset_point_mutation;
            worker_input->transaction.operation_serial = queued_claim.serial;
            worker_input->transaction.runtime_generation =
                queued_claim.runtime_generation;
            const auto target = *state.exact_tcp_reset_point_target;
            worker_input->exact_tcp_reset_point_target = target;
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    transport_rejected;
            state.preworker_failure_detail =
                "exact TCP reset point worker queue rejected the target";

            RuntimeFirewallOperationOwner::WorkerRunner runner{
                [this, target](
                    const RuntimeFirewallWorkerAttemptInput& input,
                    const RuntimeFirewallDelayedWorker::RunningClaim&
                        running_claim)
                    -> RuntimeFirewallWorkerAttemptResultPtr {
                    auto result =
                        std::make_shared<RuntimeFirewallWorkerAttemptResult>();
                    auto point = std::make_shared<
                        RuntimeExactTcpResetPointMutationResult>();
                    result->operation_kind =
                        RuntimeFirewallWorkerOperationKind::
                            exact_tcp_reset_point_mutation;
                    result->transaction.operation_serial =
                        input.transaction.operation_serial;
                    result->transaction.runtime_generation =
                        input.transaction.runtime_generation;
                    point->target = target;
                    result->exact_tcp_reset_point_mutation = point;

                    const auto& raw_claim = running_claim.raw_claim();
                    if (raw_claim.serial !=
                            input.transaction.operation_serial ||
                        raw_claim.runtime_generation !=
                            input.transaction.runtime_generation ||
                        !input.exact_tcp_reset_point_target.has_value() ||
                        *input.exact_tcp_reset_point_target != target) {
                        return result;
                    }

                    const auto compensate_install = [this, &point]() noexcept {
                        point->removal_attempted = true;
                        try {
                            point->removal_verified = firewall_ &&
                                firewall_->remove_exact_tcp_reset(
                                    point->target.rule);
                        } catch (...) {
                            point->removal_verified = false;
                        }
                    };

                    try {
                        KPBR_UNIQUE_LOCK(
                            affinity_mutation_lock,
                            udp_call_affinity_mutation_mutex_);
                        if (runtime_firewall_owner_->shutdown_requested() ||
                            !firewall_ ||
                            !running_.load(std::memory_order_acquire) ||
                            !routing_runtime_active() ||
                            runtime_generation_.load(
                                std::memory_order_acquire) !=
                                target.runtime_generation) {
                            return result;
                        }

                        if (target.kind ==
                            RuntimeExactTcpResetPointMutationKind::
                                remove_rule) {
                            point->mutation_boundary_entered = true;
                            point->removal_attempted = true;
                            try {
                                point->removal_verified = firewall_ &&
                                    firewall_->remove_exact_tcp_reset(
                                        target.rule);
                            } catch (...) {
                                point->removal_verified = false;
                            }
                            return result;
                        }

                        if (!idle_stall_observer_enabled_.load(
                                std::memory_order_acquire) ||
                            idle_stall_coverage_generation_.load(
                                std::memory_order_acquire) !=
                                target.coverage_generation ||
                            !target.exact_flow.has_value()) {
                            return result;
                        }
                        const auto observed =
                            conntrack_manager_.observe_exact_forwarded_flow(
                                *target.exact_flow, target.owned_mask);
                        if (observed.status !=
                                ConntrackExactFlowObservationStatus::Observed ||
                            !observed.flow.has_value() ||
                            !(*observed.flow == *target.exact_flow)) {
                            return result;
                        }
                        point->flow_revalidated = true;
                        point->mutation_boundary_entered = true;
                        try {
                            point->install_result =
                                firewall_->install_exact_tcp_reset(target.rule);
                        } catch (...) {
                            point->install_result =
                                FirewallExactTcpResetResult::failed;
                        }
                        if (point->install_result ==
                            FirewallExactTcpResetResult::installed) {
                            point->conntrack_delete_attempted = true;
                            try {
                                point->conntrack_delete_result =
                                    conntrack_manager_.
                                        delete_exact_forwarded_flow(
                                            *observed.flow,
                                            target.owned_mask);
                            } catch (...) {
                                point->conntrack_delete_result =
                                    ConntrackCleanupResult::Failed;
                            }
                        }
                        if (!point->fully_verified()) {
                            compensate_install();
                        }
                    } catch (...) {
                        if (point->mutation_boundary_entered &&
                            target.kind ==
                                RuntimeExactTcpResetPointMutationKind::
                                    install_then_delete_exact_flow) {
                            try {
                                KPBR_UNIQUE_LOCK(
                                    compensation_lock,
                                    udp_call_affinity_mutation_mutex_);
                                compensate_install();
                            } catch (...) {
                                point->removal_attempted = true;
                                point->removal_verified = false;
                            }
                        }
                    }
                    return result;
                }};

            const bool enqueued =
                runtime_firewall_owner_->enqueue_worker_with_retained_lease(
                    context,
                    queued_claim,
                    std::move(worker_input),
                    std::move(runner));
            if (enqueued) {
                state.preworker_failure_kind =
                    DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                        none;
                state.preworker_failure_detail.clear();
            }
        } catch (const std::exception& error) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            try {
                state.preworker_failure_detail = error.what();
            } catch (...) {
            }
            if (context->worker_operation) {
                context->worker_operation.reset();
            } else {
                terminalize_before_worker(
                    RuntimeFirewallOperationContext::SuccessorMode::none,
                    /*force_rerun=*/false);
            }
        } catch (...) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            state.preworker_failure_detail =
                "exact TCP reset point worker preparation failed";
            if (context->worker_operation) {
                context->worker_operation.reset();
            } else {
                terminalize_before_worker(
                    RuntimeFirewallOperationContext::SuccessorMode::none,
                    /*force_rerun=*/false);
            }
        }
        return;
    }

    if (lifecycle_stop_cleanup) {
        // STOP owns a deliberately small worker body. It must never enter the
        // normal apply/input-building path, resnapshot configuration, or
        // inherit an additive firewall successor.
        context->successor_mode =
            RuntimeFirewallOperationContext::SuccessorMode::none;
        context->force_successor = false;
        state.suppress_coordinator_rerun = true;
        if (!context->retained_mutation_lease ||
            !state.stop_cleanup_target.has_value() ||
            state.stop_cleanup_target->runtime_generation !=
                queued_claim.runtime_generation ||
            (state.stop_cleanup_target->cleanup_conntrack &&
             !state.stop_cleanup_target->conntrack_snapshot.valid())) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            state.preworker_failure_detail =
                "runtime STOP immutable cleanup authority is unavailable";
            terminalize_before_worker(
                RuntimeFirewallOperationContext::SuccessorMode::none,
                /*force_rerun=*/false);
            return;
        }

        // The exact owner is now accepted, so callback fencing cannot create
        // a clean-rejection cursor loss. Preserve the Meta plan explicitly;
        // the terminal branch restores it if no worker body starts.
        state.previous_meta_cleanup = pending_meta_udp443_cleanup_;
        cancel_idle_stall_observer();
        cancel_meta_udp443_activation_cleanup();
        state.preworker_side_effects_armed = true;

        try {
            auto worker_input =
                std::make_shared<RuntimeFirewallWorkerAttemptInput>();
            worker_input->operation_kind =
                RuntimeFirewallWorkerOperationKind::stop_cleanup;
            worker_input->transaction.operation_serial =
                queued_claim.serial;
            worker_input->transaction.runtime_generation =
                queued_claim.runtime_generation;
            const auto target = *state.stop_cleanup_target;
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    transport_rejected;
            state.preworker_failure_detail =
                "runtime STOP worker queue rejected the exact cleanup";

            RuntimeFirewallOperationOwner::WorkerRunner runner{
                [this, target](
                    const RuntimeFirewallWorkerAttemptInput& input,
                    const RuntimeFirewallDelayedWorker::RunningClaim&)
                    -> RuntimeFirewallWorkerAttemptResultPtr {
                    // Allocate both durable mailboxes before the first
                    // destructive command. After mutation begins, publishing
                    // the typed proof is move-only and cannot fail allocation.
                    auto result =
                        std::make_shared<RuntimeFirewallWorkerAttemptResult>();
                    auto stop_result =
                        std::make_shared<RuntimeStopCleanupResult>();
                    result->operation_kind =
                        RuntimeFirewallWorkerOperationKind::stop_cleanup;
                    result->transaction.operation_serial =
                        input.transaction.operation_serial;
                    result->transaction.runtime_generation =
                        input.transaction.runtime_generation;

                    RuntimeStopCleanupServices services;
                    services.cleanup_conntrack =
                        [this](const OwnedConntrackCleanupSnapshot& snapshot) {
                            if (!snapshot.valid()) return false;
                            KPBR_UNIQUE_LOCK(
                                affinity_mutation_lock,
                                udp_call_affinity_mutation_mutex_);
                            const auto summary =
                                conntrack_manager_.delete_marks_ordered(
                                    ordered_owned_conntrack_marks(snapshot),
                                    snapshot.owned_mask,
                                    ConntrackCleanupOptions{
                                        snapshot.ipv6_enabled,
                                        std::chrono::seconds{4}});
                            return !summary.command_unavailable &&
                                summary.failed == 0U &&
                                summary.skipped == 0U &&
                                summary.remaining_marks.empty();
                        };
                    services.clear_routing = [this]() {
                        const auto inventory =
                            routing_operation_owner_.clear();
                        return inventory &&
                            classify_runtime_routing_inventory(inventory) ==
                                RuntimeRoutingInventoryAuthority::
                                    authoritative &&
                            inventory->phase ==
                                RuntimeRoutingMutationPhase::cleared &&
                            inventory->outcome ==
                                RuntimeRoutingOperationOutcome::cleared &&
                            inventory->routes.empty() &&
                            inventory->rules.empty();
                    };
                    services.cleanup_firewall = [this]() {
                        KPBR_UNIQUE_LOCK(
                            affinity_mutation_lock,
                            udp_call_affinity_mutation_mutex_);
                        return firewall_->cleanup_and_inspect_owned()
                            .verified_absent();
                    };
                    services.deactivate_resolver = [this]() {
                        return run_system_resolver_hook("deactivate");
                    };
                    services.backoff = [](std::chrono::milliseconds delay) {
                        std::this_thread::sleep_for(delay);
                    };

                    execute_runtime_stop_cleanup_transaction_into(
                        *stop_result, target, services);
                    result->stop_cleanup = std::move(stop_result);
                    return result;
                }};

            const bool enqueued =
                runtime_firewall_owner_->enqueue_worker_with_retained_lease(
                    context,
                    queued_claim,
                    std::move(worker_input),
                    std::move(runner));
            if (enqueued) {
                state.preworker_failure_kind =
                    DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                        none;
                state.preworker_failure_detail.clear();
            }
            // Executor rejection is terminalized by the queue envelope which
            // already owns the exact claim and lease.
        } catch (const std::exception& error) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            try {
                state.preworker_failure_detail = error.what();
            } catch (...) {
            }
            if (context->worker_operation) {
                context->worker_operation.reset();
            } else {
                terminalize_before_worker(
                    RuntimeFirewallOperationContext::SuccessorMode::none,
                    /*force_rerun=*/false);
            }
        } catch (...) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            state.preworker_failure_detail =
                "runtime STOP worker preparation failed";
            if (context->worker_operation) {
                context->worker_operation.reset();
            } else {
                terminalize_before_worker(
                    RuntimeFirewallOperationContext::SuccessorMode::none,
                    /*force_rerun=*/false);
            }
        }
        return;
    }

    std::optional<RuntimeMutationAdmission::Lease> mutation_lease;
    if (!context->retained_mutation_lease) {
        try {
            mutation_lease = runtime_mutation_admission_.try_acquire(
                "runtime-firewall-worker");
        } catch (const std::exception& error) {
        state.preworker_failure_kind =
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                preparation_failure;
        try {
            state.preworker_failure_detail = error.what();
        } catch (...) {
            state.preworker_failure_detail =
                "runtime mutation admission failed";
        }
        const bool retry_required = lifecycle_preowned
            ? runtime_firewall_preapply_preworker_retry_available(
                  queued_claim.attempt)
            : runtime_firewall_preworker_retry_required(
                  snat_recovery.requested,
                  config_has_native_vpn_catalog_policy(config_),
                  urltest_after_firewall_gate_.waiting_for(
                      queued_claim.runtime_generation),
                  queued_claim.attempt,
                  RUNTIME_FIREWALL_RETRY_DELAYS.size());
        state.suppress_coordinator_rerun = !retry_required;
        terminalize_before_worker(
            retry_required
                ? RuntimeFirewallOperationContext::SuccessorMode::
                      reschedule_retry
                : RuntimeFirewallOperationContext::SuccessorMode::none,
            /*force_rerun=*/retry_required);
            return;
        } catch (...) {
        state.preworker_failure_kind =
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                preparation_failure;
        try {
            state.preworker_failure_detail =
                "runtime mutation admission failed with an unknown error";
        } catch (...) {
        }
        const bool retry_required = lifecycle_preowned
            ? runtime_firewall_preapply_preworker_retry_available(
                  queued_claim.attempt)
            : runtime_firewall_preworker_retry_required(
                  snat_recovery.requested,
                  config_has_native_vpn_catalog_policy(config_),
                  urltest_after_firewall_gate_.waiting_for(
                      queued_claim.runtime_generation),
                  queued_claim.attempt,
                  RUNTIME_FIREWALL_RETRY_DELAYS.size());
        state.suppress_coordinator_rerun = !retry_required;
        terminalize_before_worker(
            retry_required
                ? RuntimeFirewallOperationContext::SuccessorMode::
                      reschedule_retry
                : RuntimeFirewallOperationContext::SuccessorMode::none,
            /*force_rerun=*/retry_required);
            return;
        }
        if (!mutation_lease.has_value()) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    admission_contention;
            state.preworker_failure_detail =
                "runtime mutation admission is busy";
            terminalize_before_worker(
                RuntimeFirewallOperationContext::SuccessorMode::
                    defer_same_attempt,
                /*force_rerun=*/true);
            return;
        }
    }

    try {
        const bool lifecycle_start =
            runtime_firewall_lifecycle_uses_start_pipeline(
                context->lifecycle_kind);
        if (lifecycle_config_generation) {
            const auto& config_transaction =
                *state.config_generation_transaction;
            const bool candidate_phase =
                runtime_firewall_lifecycle_is_config_candidate(
                    context->lifecycle_kind);
            const auto& prepared = candidate_phase
                ? config_transaction.candidate
                : config_transaction.rollback;
            state.internal_vpn_resolution =
                prepared.internal_vpn_resolution;
            state.internal_vpn_service_resolution =
                prepared.internal_vpn_service_resolution;
            state.private_resolver_generation = candidate_phase
                ? config_transaction.candidate_resolver_generation
                : config_transaction.rollback_resolver_generation;
            if (!state.private_resolver_generation) {
                throw DaemonError(
                    "configuration resolver generation is unavailable");
            }
            state.lifecycle_trusted_dns_interfaces =
                state.private_resolver_generation
                    ->trusted_dns_interfaces;
            state.list_cache_snapshot = candidate_phase
                ? config_transaction.candidate_list_cache_snapshot
                : config_transaction.rollback_list_cache_snapshot;
            state.resolver_refresh_required = candidate_phase ||
                config_transaction.candidate_resolver_may_have_changed;
            state.lifecycle_resolver_verified =
                !state.resolver_refresh_required;
        } else if (lifecycle_urltest_generation) {
            // A selection change reuses the exact published config/catalog
            // generation. Only its private selection map differs.
            state.internal_vpn_resolution.effective_servers =
                resolved_internal_vpn_servers_;
            state.internal_vpn_service_resolution.effective_targets =
                resolved_internal_vpn_service_targets_;
            state.lifecycle_trusted_dns_interfaces =
                resolver_generation_snapshot_
                ? resolver_generation_snapshot_->trusted_dns_interfaces
                : build_dnsmasq_trusted_interfaces(
                      resolved_internal_vpn_servers_,
                      resolved_internal_vpn_service_targets_);
            state.resolver_refresh_required = false;
            state.lifecycle_resolver_verified = true;
            state.list_cache_snapshot =
                state.urltest_selection_transaction->list_cache_snapshot;
        } else if (lifecycle_keenetic_dns_generation) {
            const auto& transaction =
                *state.keenetic_dns_refresh_transaction;
            state.internal_vpn_resolution.effective_servers =
                resolved_internal_vpn_servers_;
            state.internal_vpn_service_resolution.effective_targets =
                resolved_internal_vpn_service_targets_;
            state.lifecycle_trusted_dns_interfaces =
                transaction.published_resolver_generation
                ? transaction.published_resolver_generation
                      ->trusted_dns_interfaces
                : build_dnsmasq_trusted_interfaces(
                      resolved_internal_vpn_servers_,
                      resolved_internal_vpn_service_targets_);
            state.list_cache_snapshot =
                transaction.list_cache_snapshot;
            state.private_resolver_generation =
                runtime_firewall_lifecycle_is_keenetic_dns_candidate(
                    context->lifecycle_kind)
                ? transaction.candidate_resolver_generation
                : transaction.rollback_resolver_generation;
            if (!state.private_resolver_generation) {
                throw DaemonError(
                    "private Keenetic DNS resolver generation is unavailable");
            }
            state.resolver_refresh_required = true;
            state.lifecycle_resolver_verified = false;
        } else if (lifecycle_preapply) {
            // Fence exactly the published generation. A cache refresh here
            // would silently turn pre-apply into candidate generation.
            state.internal_vpn_resolution.effective_servers =
                resolved_internal_vpn_servers_;
            state.internal_vpn_service_resolution.effective_targets =
                resolved_internal_vpn_service_targets_;
            state.lifecycle_trusted_dns_interfaces =
                resolver_generation_snapshot_
                ? resolver_generation_snapshot_->trusted_dns_interfaces
                : build_dnsmasq_trusted_interfaces(
                      resolved_internal_vpn_servers_,
                      resolved_internal_vpn_service_targets_);
            state.resolver_refresh_required = false;
            state.lifecycle_resolver_verified = true;
            state.list_cache_snapshot =
                resolver_generation_snapshot_ &&
                        resolver_generation_snapshot_->list_cache_snapshot
                ? resolver_generation_snapshot_->list_cache_snapshot
                : capture_relevant_list_cache_generation(config_);
        } else {
            state.internal_vpn_resolution =
                prepared_native_vpn_catalog
                ? prepared_native_vpn_catalog->interface_resolution
                : prepare_internal_vpn_server_resolution_from_cache();
            state.internal_vpn_service_resolution =
                prepared_native_vpn_catalog
                ? prepared_native_vpn_catalog->service_resolution
                : prepare_internal_vpn_service_resolution_from_cache();
            if (prepared_native_vpn_catalog) {
                context->schedule_catalog_refresh =
                    prepared_native_vpn_catalog->schedule_catalog_refresh;
                context->successor_schedule_catalog_refresh =
                    context->schedule_catalog_refresh;
            }
            if (context->schedule_catalog_refresh) {
                schedule_internal_vpn_catalog_refresh_if_needed(
                    state.internal_vpn_resolution.state,
                    state.internal_vpn_service_resolution.state);
            }

            state.lifecycle_trusted_dns_interfaces =
                build_dnsmasq_trusted_interfaces(
                    state.internal_vpn_resolution.effective_servers,
                    state.internal_vpn_service_resolution.effective_targets);
            const auto& next_resolver_access_policy =
                state.lifecycle_trusted_dns_interfaces;
            const auto current_resolver_access_policy =
                resolver_generation_snapshot_
                ? resolver_generation_snapshot_->trusted_dns_interfaces
                : build_dnsmasq_trusted_interfaces(
                      resolved_internal_vpn_servers_,
                      resolved_internal_vpn_service_targets_);
            state.resolver_refresh_required =
                runtime_firewall_lifecycle_is_foreground(
                    context->lifecycle_kind) ||
                current_resolver_access_policy !=
                    next_resolver_access_policy ||
                !resolver_generation_snapshot_ ||
                !resolver_generation_snapshot_->list_cache_snapshot;
        }
        if (lifecycle_start) {
            // START activates the already-pinned resolver/list generation.
            // Requiring activation is not authority to advance remote bodies.
            if (!state.list_cache_snapshot) {
                state.list_cache_snapshot =
                    resolver_generation_snapshot_ &&
                            resolver_generation_snapshot_
                                ->list_cache_snapshot
                        ? resolver_generation_snapshot_
                              ->list_cache_snapshot
                        : capture_relevant_list_cache_generation(config_);
            }
        } else if (!lifecycle_preowned) {
            state.list_cache_snapshot = state.resolver_refresh_required
                ? capture_relevant_list_cache_generation(config_)
                : resolver_generation_snapshot_->list_cache_snapshot;
        }

        RuntimeFirewallGenerationSnapshot generation_snapshot;
        generation_snapshot.operation_kind = lifecycle_preapply
            ? RuntimeFirewallWorkerOperationKind::config_preapply
            : (runtime_firewall_lifecycle_is_config_candidate(
                       context->lifecycle_kind)
                   ? RuntimeFirewallWorkerOperationKind::config_candidate
                   : (context->lifecycle_kind ==
                              RuntimeFirewallLifecycleKind::config_rollback
                          ? RuntimeFirewallWorkerOperationKind::
                                config_rollback
                          : (runtime_firewall_lifecycle_is_urltest_candidate(
                                 context->lifecycle_kind)
                                 ? RuntimeFirewallWorkerOperationKind::
                                       urltest_candidate
                                 : (context->lifecycle_kind ==
                                            RuntimeFirewallLifecycleKind::
                                                urltest_rollback
                                        ? RuntimeFirewallWorkerOperationKind::
                                              urltest_rollback
                                        : (runtime_firewall_lifecycle_is_keenetic_dns_candidate(
                                               context->lifecycle_kind)
                                               ? RuntimeFirewallWorkerOperationKind::
                                                     keenetic_dns_candidate
                                               : (context->lifecycle_kind ==
                                                          RuntimeFirewallLifecycleKind::
                                                              keenetic_dns_rollback
                                                      ? RuntimeFirewallWorkerOperationKind::
                                                            keenetic_dns_rollback
                                                      : RuntimeFirewallWorkerOperationKind::
                                                            reconcile_generation))))));
        auto& transaction = generation_snapshot.transaction;
        transaction.operation_serial = queued_claim.serial;
        transaction.runtime_generation = queued_claim.runtime_generation;
        const PreparedRuntimeInputs* config_generation_target = nullptr;
        const DaemonRuntimeFirewallOperationState::CorePublication*
            config_generation_previous_publication = nullptr;
        if (lifecycle_config_generation) {
            const bool candidate_phase =
                runtime_firewall_lifecycle_is_config_candidate(
                    context->lifecycle_kind);
            config_generation_target = candidate_phase
                ? &state.config_generation_transaction->candidate
                : &state.config_generation_transaction->rollback;
            if (!candidate_phase) {
                const auto& realized_candidate =
                    state.config_generation_transaction
                        ->candidate_core_publication;
                if (state.config_generation_transaction
                        ->candidate_core_publication_ready &&
                    realized_candidate.committed) {
                    config_generation_previous_publication =
                        &realized_candidate;
                } else if (!state.config_generation_transaction
                                ->candidate_firewall_preimage_is_base) {
                    throw DaemonError(
                        "configuration rollback has no exact candidate "
                        "firewall terminal class");
                }
            }
        } else if (lifecycle_urltest_generation &&
                   context->lifecycle_kind ==
                       RuntimeFirewallLifecycleKind::urltest_rollback &&
                   state.urltest_selection_transaction
                       ->candidate_core_publication_ready &&
                   state.urltest_selection_transaction
                       ->candidate_core_publication.committed) {
            config_generation_previous_publication =
                &state.urltest_selection_transaction
                     ->candidate_core_publication;
        } else if (lifecycle_keenetic_dns_generation &&
                   context->lifecycle_kind ==
                       RuntimeFirewallLifecycleKind::keenetic_dns_rollback &&
                   state.keenetic_dns_refresh_transaction
                       ->candidate_core_publication_ready &&
                   state.keenetic_dns_refresh_transaction
                       ->candidate_core_publication.committed) {
            config_generation_previous_publication =
                &state.keenetic_dns_refresh_transaction
                     ->candidate_core_publication;
        }
        transaction.config = config_generation_target
            ? config_generation_target->config
            : config_;
        transaction.outbound_marks = config_generation_target
            ? config_generation_target->outbound_marks
            : outbound_marks_;
        transaction.urltest_selections = lifecycle_config_generation
            ? (runtime_firewall_lifecycle_is_config_candidate(
                       context->lifecycle_kind)
                   ? state.config_generation_transaction
                         ->candidate_urltest_selections
                   : state.config_generation_transaction
                         ->rollback_urltest_selections)
            : (lifecycle_urltest_generation
                   ? (runtime_firewall_lifecycle_is_urltest_candidate(
                              context->lifecycle_kind)
                          ? state.urltest_selection_transaction
                                ->candidate_selections
                          : state.urltest_selection_transaction
                                ->rollback_selections)
                   : firewall_state_.get_urltest_selections());
        transaction.effective_internal_vpn_servers =
            state.internal_vpn_resolution.effective_servers;
        transaction.effective_internal_vpn_targets =
            internal_vpn_interface_runtime_targets(
                transaction.effective_internal_vpn_servers);
        transaction.effective_internal_vpn_targets.insert(
            transaction.effective_internal_vpn_targets.end(),
            state.internal_vpn_service_resolution.effective_targets.begin(),
            state.internal_vpn_service_resolution.effective_targets.end());
        transaction.candidate_native_vpn_direct_egress_snat_selectors =
            select_native_vpn_direct_egress_snat_selectors(
                transaction.effective_internal_vpn_targets);
        transaction.committed_meta_udp443_fwmark =
            config_generation_previous_publication
            ? config_generation_previous_publication
                  ->committed_meta_fwmark
            : committed_meta_udp443_fwmark_;
        transaction.committed_meta_udp443_owned_mask =
            config_generation_previous_publication
            ? config_generation_previous_publication
                  ->committed_meta_owned_mask
            : committed_meta_udp443_owned_mask_;
        transaction.list_max_file_size_bytes =
            max_file_size_bytes(transaction.config);
        transaction.list_cache_snapshot = state.list_cache_snapshot;
        transaction.requested_list_fingerprints =
            state.list_cache_snapshot
            ? state.list_cache_snapshot->fingerprints()
            : std::map<std::string, std::string>{};
        transaction.requested_mode =
            runtime_firewall_lifecycle_is_config_candidate(
                    context->lifecycle_kind)
            ? state.config_generation_transaction
                  ->candidate_firewall_policy.mode
            : (context->lifecycle_kind ==
                       RuntimeFirewallLifecycleKind::config_rollback
                   ? state.config_generation_transaction
                         ->rollback_firewall_policy.mode
            : (lifecycle_urltest_generation
                   ? runtime_refresh_firewall_mode()
                   : (runtime_firewall_lifecycle_is_foreground(
                          context->lifecycle_kind)
                          ? FirewallApplyMode::PreserveSets
                          : runtime_refresh_firewall_mode())));
        transaction.force_clear_dynamic_sets =
            runtime_firewall_lifecycle_is_config_candidate(
                    context->lifecycle_kind)
            ? state.config_generation_transaction
                  ->candidate_firewall_policy.force_clear_dynamic_sets
            : (context->lifecycle_kind ==
                       RuntimeFirewallLifecycleKind::config_rollback &&
                   state.config_generation_transaction
                       ->rollback_firewall_policy.force_clear_dynamic_sets);
        transaction.udp_call_affinity_ipset_available =
            opts_.udp_call_affinity_ipset_available;
        transaction.keenetic_dns_snapshot = config_generation_target
            ? config_generation_target->keenetic_dns.snapshot
            : (lifecycle_keenetic_dns_generation
                   ? (runtime_firewall_lifecycle_is_keenetic_dns_candidate(
                              context->lifecycle_kind)
                          ? state.keenetic_dns_refresh_transaction
                                ->candidate_view.snapshot
                          : state.keenetic_dns_refresh_transaction
                                ->rollback_view.snapshot)
                   : active_keenetic_dns_.snapshot);
        if (config_generation_previous_publication) {
            transaction.previous_rules =
                config_generation_previous_publication->rules;
            transaction.previous_list_usage =
                config_generation_previous_publication->list_usage;
            transaction.previous_list_content_state =
                config_generation_previous_publication
                    ->list_content_state;
            transaction.previous_list_fingerprints =
                config_generation_previous_publication
                    ->list_fingerprints;
            transaction
                .previous_native_vpn_direct_egress_snat_selectors =
                    config_generation_previous_publication
                        ->native_vpn_direct_egress_snat_selectors;
        } else {
            transaction.previous_rules =
                firewall_state_.get_rules();
            transaction.previous_list_usage = applied_list_usage_;
            transaction.previous_list_content_state =
                applied_list_content_state_;
            transaction.previous_list_fingerprints =
                applied_list_fingerprints_;
            transaction
                .previous_native_vpn_direct_egress_snat_selectors =
                    applied_native_vpn_direct_egress_snat_selectors_;
        }

        generation_snapshot.route.route_epoch =
            routing_observation_epoch_.load(std::memory_order_acquire);
        if (lifecycle_config_generation) {
            if (runtime_firewall_lifecycle_is_config_candidate(
                    context->lifecycle_kind)) {
                state.config_generation_transaction
                    ->candidate_route_epoch =
                        generation_snapshot.route.route_epoch;
            } else {
                state.config_generation_transaction
                    ->rollback_route_epoch =
                        generation_snapshot.route.route_epoch;
            }
        }
        generation_snapshot.route.reconcile_mode =
            runtime_firewall_lifecycle_is_foreground(
                context->lifecycle_kind)
            ? RouteReconcileMode::Strict
            : RouteReconcileMode::DeferredRepair;
        if (!lifecycle_preapply) {
            generation_snapshot.route.mutation_checkpoint =
                std::make_shared<RuntimeRouteMutationCheckpoint>();
            state.route_mutation_checkpoint =
                generation_snapshot.route.mutation_checkpoint;

            std::weak_ptr<RuntimeFirewallOperationContext> weak_context{
                context};
            context->pump_worker_checkpoint = [this, weak_context]() noexcept {
                const auto retained = weak_context.lock();
                if (!retained) return;
                pump_runtime_route_health_checkpoint(retained);
            };
            const auto route_mutation_checkpoint =
                generation_snapshot.route.mutation_checkpoint;
            context->cancel_worker_checkpoint =
                [route_mutation_checkpoint]() noexcept {
                    (void)route_mutation_checkpoint->cancel();
                };
        }

        const auto route_config =
            transaction.config.route.value_or(RouteConfig{});
        const bool has_explicit_inbound_scope =
            route_config.inbound_interfaces.has_value() &&
            !route_config.inbound_interfaces->empty();
        const bool has_native_vpn_bypass = std::any_of(
            transaction.effective_internal_vpn_servers.begin(),
            transaction.effective_internal_vpn_servers.end(),
            [](const InternalVpnServer& server) {
                return !server.process_clients;
            }) || std::any_of(
            transaction.effective_internal_vpn_targets.begin(),
            transaction.effective_internal_vpn_targets.end(),
            [](const InternalVpnRuntimeTarget& target) {
                return !target.process_clients;
            });
        transaction.forwarded_scope_allows_unmarked_cleanup =
            !has_explicit_inbound_scope && !has_native_vpn_bypass;

        generation_snapshot.cleanup.inspect_owned_snat =
            !lifecycle_config_generation &&
            (lifecycle_preapply || snat_recovery.requested);
        if (lifecycle_preapply) {
            generation_snapshot.cleanup
                .pre_mutation_owned_conntrack_cleanup_snapshot =
                snapshot_owned_conntrack_marks();
            if (snat_recovery.cleanup_snapshot.has_value()) {
                // Mandatory authority is evidence, not an optional hint. Pass
                // malformed or stale payloads through so the worker rejects
                // them fail-closed instead of laundering them into absence.
                generation_snapshot.cleanup
                    .mandatory_owned_conntrack_cleanup_snapshot =
                    snat_recovery.cleanup_snapshot;
            }
            generation_snapshot.cleanup.mode =
                RuntimeFirewallOwnedConntrackCleanupMode::
                    exact_pre_mutation_snapshot;
        } else if (generation_snapshot.cleanup.inspect_owned_snat) {
            generation_snapshot.cleanup
                .pre_mutation_owned_conntrack_cleanup_snapshot =
                snapshot_owned_conntrack_marks();
        }
        if (lifecycle_start) {
            generation_snapshot.cleanup.mode =
                RuntimeFirewallOwnedConntrackCleanupMode::
                    committed_candidate;
        } else if (!lifecycle_preowned) {
            generation_snapshot.cleanup.mode =
                RuntimeFirewallOwnedConntrackCleanupMode::none;
        }

        auto worker_input = make_runtime_firewall_worker_attempt_input(
            std::move(generation_snapshot));

        if (!lifecycle_start && !lifecycle_preowned) {
            state.previous_meta_cleanup = pending_meta_udp443_cleanup_;
            cancel_idle_stall_observer();
            cancel_meta_udp443_activation_cleanup();
            state.preworker_side_effects_armed = true;
        }
        auto worker_input_snapshot =
            std::make_shared<const RuntimeFirewallWorkerAttemptInput>(
                std::move(worker_input));
        std::unique_ptr<RuntimeMutationAdmission::Lease> lease_owner;
        if (mutation_lease.has_value()) {
            lease_owner =
                std::make_unique<RuntimeMutationAdmission::Lease>(
                    std::move(*mutation_lease));
        }
        state.preworker_failure_kind =
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                transport_rejected;
        state.preworker_failure_detail =
            "runtime firewall worker queue rejected the exact attempt";
        RuntimeFirewallOperationOwner::WorkerRunner worker_runner{
            [this](
                const RuntimeFirewallWorkerAttemptInput& input,
                const RuntimeFirewallDelayedWorker::RunningClaim&)
                -> RuntimeFirewallWorkerAttemptResultPtr {
                SystemRuntimeRouteHealthServices route_health_services{
                    netlink_};
                return
                    execute_runtime_firewall_worker_attempt_durable_with_route_preparation(
                    input,
                    route_health_services,
                    [this, &input](const RuntimeRouteHealthPlan& plan,
                                   RouteReconcileMode reconcile_mode) {
                        RuntimeRouteWorkerMutationResult result;
                        const auto exact_worker_input =
                            plan.operation_serial ==
                                input.route_health_request.operation_serial &&
                            plan.runtime_generation ==
                                input.route_health_request.runtime_generation &&
                            plan.route_epoch ==
                                input.route_health_request.route_epoch &&
                            plan.operation_serial ==
                                input.transaction.operation_serial &&
                            plan.runtime_generation ==
                                input.transaction.runtime_generation;
                        const auto current_generation =
                            runtime_generation_.load(
                                std::memory_order_acquire);
                        const auto current_route_epoch =
                            routing_observation_epoch_.load(
                                std::memory_order_acquire);
                        if (runtime_firewall_owner_->shutdown_requested()) {
                            result.ack = RuntimeRouteMutationAck::shutdown;
                            return result;
                        }
                        if (!exact_worker_input ||
                            current_generation != plan.runtime_generation ||
                            current_route_epoch != plan.route_epoch) {
                            result.ack = RuntimeRouteMutationAck::stale;
                            return result;
                        }

                        try {
                            const auto base_inventory =
                                routing_operation_owner_.snapshot();
                            if (classify_runtime_routing_inventory(
                                    base_inventory) ==
                                RuntimeRoutingInventoryAuthority::missing) {
                                result.ack = RuntimeRouteMutationAck::stale;
                                result.failure_detail =
                                    "runtime routing inventory is missing";
                                return result;
                            }

                            RuntimeRoutingOperationRequest routing_request;
                            routing_request.identity.operation_serial =
                                plan.operation_serial;
                            routing_request.identity.runtime_generation =
                                plan.runtime_generation;
                            // The worker attempt is the immutable routing
                            // intent for this generation.
                            routing_request.identity.intent_serial =
                                plan.operation_serial;
                            routing_request.identity.base_inventory_revision =
                                base_inventory->revision;
                            routing_request.identity.route_epoch =
                                plan.route_epoch;
                            routing_request.desired_routes =
                                plan.routing.routes;
                            routing_request.desired_rules =
                                plan.routing.rules;
                            routing_request.mode = reconcile_mode;

                            const auto& configured_outbounds =
                                input.route_health_request.config.outbounds;
                            if (configured_outbounds) {
                                const auto append_external_authority =
                                    [&](std::uint32_t table, int family) {
                                        const bool duplicate = std::any_of(
                                            routing_request
                                                .authorized_external_tables
                                                .begin(),
                                            routing_request
                                                .authorized_external_tables
                                                .end(),
                                            [&](const auto& authority) {
                                                return authority.table ==
                                                           table &&
                                                       authority.family ==
                                                           family;
                                            });
                                        if (!duplicate) {
                                            routing_request
                                                .authorized_external_tables
                                                .push_back({table, family});
                                        }
                                    };
                                for (const auto& outbound :
                                     *configured_outbounds) {
                                    if (outbound.type !=
                                            OutboundType::TABLE ||
                                        !outbound.table ||
                                        *outbound.table <= 0 ||
                                        static_cast<std::uint64_t>(
                                            *outbound.table) >
                                            std::numeric_limits<
                                                std::uint32_t>::max()) {
                                        continue;
                                    }
                                    const auto table =
                                        static_cast<std::uint32_t>(
                                            *outbound.table);
                                    for (const auto& rule :
                                         plan.routing.rules) {
                                        if (rule.table != table) continue;
                                        if (rule.family == 0) {
                                            append_external_authority(
                                                table, AF_INET);
                                            append_external_authority(
                                                table, AF_INET6);
                                        } else {
                                            append_external_authority(
                                                table, rule.family);
                                        }
                                    }
                                }
                            }

                            const auto previous_operation_serial =
                                base_inventory
                                    ->highest_consumed_operation_serial;
                            const auto base_revision =
                                base_inventory->revision;
                            const auto operation =
                                routing_operation_owner_.reconcile_exact(
                                    routing_request,
                                    [this,
                                     &input,
                                     &plan,
                                     previous_operation_serial,
                                     base_revision]() {
                                        RuntimeRoutingCurrentFence fence;
                                        const bool cancelled =
                                            runtime_firewall_owner_
                                                ->shutdown_requested() ||
                                            (input.route_mutation_checkpoint &&
                                             input.route_mutation_checkpoint
                                                     ->state() ==
                                                 RuntimeRouteMutationCheckpointState::
                                                     acked);
                                        // The current routing owner claim
                                        // prevents a successor from entering
                                        // concurrently. Shutdown or an already
                                        // terminal checkpoint is represented
                                        // as a typed replay fence: before a
                                        // write it stays zero-write; after a
                                        // write the executor rolls back.
                                        fence.last_operation_serial = cancelled
                                            ? plan.operation_serial
                                            : previous_operation_serial;
                                        fence.runtime_generation =
                                            runtime_generation_.load(
                                                std::memory_order_acquire);
                                        fence.intent_serial =
                                            plan.operation_serial;
                                        fence.inventory_revision =
                                            base_revision;
                                        fence.route_epoch =
                                            routing_observation_epoch_.load(
                                                std::memory_order_acquire);
                                        return fence;
                                    });

                            if (!operation.detail.empty()) {
                                result.failure_detail = operation.detail;
                            }
                            switch (operation.outcome) {
                                case RuntimeRoutingOperationOutcome::
                                    exact_candidate_committed:
                                    if (classify_runtime_routing_inventory(
                                            operation.inventory) !=
                                        RuntimeRoutingInventoryAuthority::
                                            authoritative) {
                                        result.ack =
                                            RuntimeRouteMutationAck::
                                                mutation_failed;
                                        break;
                                    }
                                    if (runtime_firewall_owner_
                                            ->shutdown_requested()) {
                                        result.ack =
                                            RuntimeRouteMutationAck::shutdown;
                                    } else if (
                                        runtime_generation_.load(
                                            std::memory_order_acquire) !=
                                            plan.runtime_generation ||
                                        routing_observation_epoch_.load(
                                            std::memory_order_acquire) !=
                                            plan.route_epoch) {
                                        result.ack =
                                            RuntimeRouteMutationAck::
                                                mutation_failed;
                                    } else {
                                        result.ack =
                                            RuntimeRouteMutationAck::applied;
                                    }
                                    break;
                                case RuntimeRoutingOperationOutcome::
                                    exact_candidate_rolled_back:
                                    if (runtime_firewall_owner_
                                            ->shutdown_requested()) {
                                        result.ack =
                                            RuntimeRouteMutationAck::shutdown;
                                    } else if (
                                        classify_runtime_routing_inventory(
                                            operation.inventory) !=
                                        RuntimeRoutingInventoryAuthority::
                                            authoritative) {
                                        result.ack =
                                            RuntimeRouteMutationAck::
                                                mutation_failed;
                                    } else {
                                        result.ack = operation
                                                .route_interface_unavailable
                                            ? RuntimeRouteMutationAck::
                                                  route_unavailable
                                            : RuntimeRouteMutationAck::stale;
                                    }
                                    break;
                                case RuntimeRoutingOperationOutcome::
                                    exact_precondition_failed:
                                    if (runtime_firewall_owner_
                                            ->shutdown_requested()) {
                                        result.ack =
                                            RuntimeRouteMutationAck::shutdown;
                                    } else {
                                        result.ack =
                                            classify_runtime_routing_inventory(
                                                operation.inventory) ==
                                                    RuntimeRoutingInventoryAuthority::
                                                        authoritative
                                            ? RuntimeRouteMutationAck::stale
                                            : RuntimeRouteMutationAck::
                                                  mutation_failed;
                                    }
                                    break;
                                case RuntimeRoutingOperationOutcome::
                                    exact_committed_cleanup_pending:
                                case RuntimeRoutingOperationOutcome::
                                    exact_partial_unknown:
                                    result.ack =
                                        RuntimeRouteMutationAck::
                                            mutation_failed;
                                    break;
                                case RuntimeRoutingOperationOutcome::
                                    exact_stale_before_mutation:
                                case RuntimeRoutingOperationOutcome::
                                    rejected_invalid_identity:
                                case RuntimeRoutingOperationOutcome::
                                    rejected_replay:
                                case RuntimeRoutingOperationOutcome::
                                    rejected_stale_inventory:
                                    result.ack =
                                        runtime_firewall_owner_
                                                ->shutdown_requested()
                                        ? RuntimeRouteMutationAck::shutdown
                                        : RuntimeRouteMutationAck::stale;
                                    break;
                                default:
                                    result.ack =
                                        RuntimeRouteMutationAck::
                                            mutation_failed;
                                    break;
                            }
                            if (result.ack !=
                                    RuntimeRouteMutationAck::applied &&
                                result.failure_detail.empty()) {
                                result.failure_detail =
                                    "exact runtime routing transaction "
                                    "did not commit";
                            }
                        } catch (const std::bad_alloc&) {
                            result.ack =
                                RuntimeRouteMutationAck::mutation_failed;
                            try {
                                result.failure_detail =
                                    "runtime route mutation could not "
                                    "allocate its terminal evidence";
                            } catch (...) {
                            }
                        } catch (const RouteInterfaceUnavailableError& error) {
                            result.ack =
                                RuntimeRouteMutationAck::route_unavailable;
                            try {
                                result.failure_detail = error.what();
                            } catch (...) {
                            }
                        } catch (const std::exception& error) {
                            result.ack =
                                RuntimeRouteMutationAck::mutation_failed;
                            try {
                                result.failure_detail = error.what();
                            } catch (...) {
                            }
                        } catch (...) {
                            result.ack =
                                classify_runtime_routing_inventory(
                                    routing_operation_owner_.snapshot()) ==
                                        RuntimeRoutingInventoryAuthority::
                                            authoritative
                                ? RuntimeRouteMutationAck::mutation_failed
                                : RuntimeRouteMutationAck::stale;
                            try {
                                result.failure_detail =
                                    "runtime route mutation failed with an "
                                    "unknown error";
                            } catch (...) {
                            }
                        }
                        return result;
                    },
                    [this, &input]() {
                        // Route observation, mutation and the control-only
                        // publication rendezvous have already completed.
                        // Hold this lock only for firewall/conntrack.
                        KPBR_UNIQUE_LOCK(
                            affinity_mutation_lock,
                            udp_call_affinity_mutation_mutex_);
                        return execute_runtime_firewall_worker_attempt(
                            input,
                            *firewall_,
                            conntrack_manager_,
                            netlink_);
                    });
            }};
        const bool enqueued = context->retained_mutation_lease
            ? runtime_firewall_owner_->enqueue_worker_with_retained_lease(
                  context,
                  queued_claim,
                  std::move(worker_input_snapshot),
                  std::move(worker_runner))
            : runtime_firewall_owner_->enqueue_worker(
                  context,
                  queued_claim,
                  std::move(worker_input_snapshot),
                  std::move(lease_owner),
                  std::move(worker_runner));
        if (enqueued) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    none;
            state.preworker_failure_detail.clear();
        }
        // On rejection the destroyed queue envelope publishes the exact
        // queued_abandoned terminal and returns the mutation lease. Do not
        // manufacture a second terminal here.
    } catch (const RouteInterfaceUnavailableError& error) {
        state.preworker_failure_kind =
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                route_unavailable;
        try {
            state.preworker_failure_detail = error.what();
        } catch (...) {
            state.preworker_failure_detail =
                "runtime route interface is unavailable";
        }
        const bool retry_required = lifecycle_preowned
            ? runtime_firewall_preapply_preworker_retry_available(
                  queued_claim.attempt)
            : snat_recovery.requested ||
                  urltest_after_firewall_gate_.waiting_for(
                      queued_claim.runtime_generation);
        state.suppress_coordinator_rerun = !retry_required;
        terminalize_before_worker(
            retry_required
                ? RuntimeFirewallOperationContext::SuccessorMode::
                      reschedule_retry
                : RuntimeFirewallOperationContext::SuccessorMode::none,
            /*force_rerun=*/retry_required);
    } catch (const std::exception& error) {
        const bool transport_rejected =
            state.preworker_failure_kind ==
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                transport_rejected;
        if (!transport_rejected) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
        }
        try {
            state.preworker_failure_detail = error.what();
        } catch (...) {
            state.preworker_failure_detail =
                "runtime firewall input preparation failed";
        }
        if (context->worker_operation) {
            context->worker_operation.reset();
        } else {
            const bool retry_required = transport_rejected ||
                (lifecycle_preowned
                     ? runtime_firewall_preapply_preworker_retry_available(
                           queued_claim.attempt)
                     : (!runtime_firewall_lifecycle_is_start(
                            context->lifecycle_kind) &&
                        runtime_firewall_preworker_retry_required(
                            snat_recovery.requested,
                            config_has_native_vpn_catalog_policy(config_),
                            urltest_after_firewall_gate_.waiting_for(
                                queued_claim.runtime_generation),
                            queued_claim.attempt,
                            RUNTIME_FIREWALL_RETRY_DELAYS.size())));
            if (!transport_rejected) {
                state.suppress_coordinator_rerun = !retry_required;
            }
            terminalize_before_worker(
                transport_rejected
                    ? RuntimeFirewallOperationContext::SuccessorMode::
                          defer_same_attempt
                    : (retry_required
                           ? RuntimeFirewallOperationContext::SuccessorMode::
                                 reschedule_retry
                           : RuntimeFirewallOperationContext::SuccessorMode::
                                 none),
                /*force_rerun=*/retry_required);
        }
    } catch (...) {
        const bool transport_rejected =
            state.preworker_failure_kind ==
            DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                transport_rejected;
        if (!transport_rejected) {
            state.preworker_failure_kind =
                DaemonRuntimeFirewallOperationState::PreworkerFailureKind::
                    preparation_failure;
            try {
                state.preworker_failure_detail =
                    "runtime firewall input preparation failed with an "
                    "unknown error";
            } catch (...) {
            }
        }
        if (context->worker_operation) {
            // If no queue envelope was made, Operation destruction performs
            // the only exact queued-claim terminalization. If an envelope was
            // already made, its shared state owns the same one-shot action.
            context->worker_operation.reset();
        } else {
            const bool retry_required = transport_rejected ||
                (lifecycle_preowned
                     ? runtime_firewall_preapply_preworker_retry_available(
                           queued_claim.attempt)
                     : (!runtime_firewall_lifecycle_is_start(
                            context->lifecycle_kind) &&
                        runtime_firewall_preworker_retry_required(
                            snat_recovery.requested,
                            config_has_native_vpn_catalog_policy(config_),
                            urltest_after_firewall_gate_.waiting_for(
                                queued_claim.runtime_generation),
                            queued_claim.attempt,
                            RUNTIME_FIREWALL_RETRY_DELAYS.size())));
            if (!transport_rejected) {
                state.suppress_coordinator_rerun = !retry_required;
            }
            terminalize_before_worker(
                transport_rejected
                    ? RuntimeFirewallOperationContext::SuccessorMode::
                          defer_same_attempt
                    : (retry_required
                           ? RuntimeFirewallOperationContext::SuccessorMode::
                                 reschedule_retry
                           : RuntimeFirewallOperationContext::SuccessorMode::
                                 none),
                /*force_rerun=*/retry_required);
        }
        try {
            Logger::instance().error(
                "Runtime firewall worker input could not be queued; the "
                "exact attempt will be deferred without consuming retry "
                "budget.");
        } catch (...) {
        }
    }
}

void Daemon::pump_runtime_route_health_checkpoint(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context)
    noexcept {
    if (!context || !runtime_firewall_owner_->is_active(context)) return;
    // The pump is a watchdog/shutdown seam and is declared noexcept. Avoid
    // the throwing domain-state accessor even though every production
    // context is created with this exact state type.
    if (!context->domain_state) return;
    auto& state = static_cast<DaemonRuntimeFirewallOperationState&>(
        *context->domain_state);
    const auto checkpoint = state.route_mutation_checkpoint;
    if (!checkpoint ||
        checkpoint->state() !=
            RuntimeRouteMutationCheckpointState::plan_ready) {
        return;
    }

    auto claim = checkpoint->try_claim_control();
    if (!claim.has_value()) return;
    const auto plan = claim->plan();
    if (!plan) {
        (void)claim->acknowledge(
            RuntimeRouteMutationAck::mutation_failed);
        return;
    }

    const bool shutting_down =
        runtime_firewall_owner_->shutdown_requested() ||
        !runtime_firewall_lifecycle_generation_is_current(
            context->lifecycle_kind,
            plan->runtime_generation);
    if (shutting_down) {
        (void)claim->acknowledge(RuntimeRouteMutationAck::shutdown);
        return;
    }

    const bool exact_context =
        context->queued_claim.serial == plan->operation_serial &&
        context->queued_claim.runtime_generation ==
            plan->runtime_generation &&
        plan->runtime_generation ==
            runtime_generation_.load(std::memory_order_acquire) &&
        plan->route_epoch ==
            routing_observation_epoch_.load(std::memory_order_acquire) &&
        context->worker_input &&
        context->worker_input->route_health_request.operation_serial ==
            plan->operation_serial &&
        context->worker_input->route_health_request.runtime_generation ==
            plan->runtime_generation &&
        context->worker_input->route_health_request.route_epoch ==
            plan->route_epoch;
    if (!exact_context) {
        (void)claim->acknowledge(RuntimeRouteMutationAck::stale);
        return;
    }

    // The route/rule mutation already completed in the worker and released
    // the combined owner. This control boundary only revalidates the exact
    // context, publishes its observation metadata and lets firewall proceed.
    try {
        log_ipv6_support_decision_once(plan->ipv6_decision);
    } catch (...) {
    }
    (void)claim->acknowledge(RuntimeRouteMutationAck::applied);
}

void Daemon::trigger_broad_urltest_probe_noexcept() noexcept {
    if (!urltest_manager_) return;
    try {
        Logger::instance().info(
            "Netfilter event: probing urltest endpoints after verified "
            "firewall publication...");
    } catch (...) {
    }
    if (!config_.outbounds.has_value()) return;
    for (const auto& outbound : *config_.outbounds) {
        if (outbound.type != OutboundType::URLTEST) continue;
        try {
            urltest_manager_->trigger_immediate_test(outbound.tag);
        } catch (const std::exception& error) {
            try {
                Logger::instance().info(
                    "Netfilter event: urltest '{}' probe could not be "
                    "started: {}",
                    outbound.tag,
                    error.what());
            } catch (...) {
            }
        } catch (...) {
        }
    }
}

bool Daemon::begin_runtime_firewall_lifecycle_resolver(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context)
    noexcept {
    const bool lifecycle_start = context &&
        runtime_firewall_lifecycle_activates_stopped_runtime(
            context->lifecycle_kind);
    const bool lifecycle_restart = context &&
        runtime_firewall_lifecycle_is_restart(context->lifecycle_kind);
    const bool lifecycle_config_generation = context &&
        runtime_firewall_lifecycle_is_config_generation(
            context->lifecycle_kind);
    const bool lifecycle_keenetic_dns_generation = context &&
        runtime_firewall_lifecycle_is_keenetic_dns_generation(
            context->lifecycle_kind);
    const bool lifecycle_cold_boot = context &&
        runtime_firewall_lifecycle_is_cold_boot(
            context->lifecycle_kind);
    if (!context || !runtime_firewall_owner_->is_active(context) ||
        (!lifecycle_start && !lifecycle_restart &&
         !lifecycle_config_generation &&
         !lifecycle_keenetic_dns_generation) ||
        !context->domain_state) {
        return false;
    }
    auto& state = static_cast<DaemonRuntimeFirewallOperationState&>(
        *context->domain_state);
    auto& attempt = state.lifecycle_resolver_attempt;
    const auto apply_transition = [&state](
        const RuntimeFirewallLifecycleResolverAttemptTransition& transition)
        noexcept {
        if (!transition.state_changed) return;
        state.lifecycle_resolver_verified = transition.verified;
        if (!transition.failure_detail.empty()) {
            try {
                state.lifecycle_failure_detail.assign(
                    transition.failure_detail.data(),
                    transition.failure_detail.size());
            } catch (...) {
            }
        }
    };
    if ((lifecycle_restart || lifecycle_config_generation ||
         lifecycle_keenetic_dns_generation) &&
        !state.resolver_refresh_required) {
        apply_transition(attempt.complete_not_required());
        return false;
    }
    if (attempt.phase() ==
        RuntimeFirewallLifecycleResolverAttemptPhase::in_flight) {
        const bool coordinator_in_flight =
            resolver_stream_coordinator_.in_flight();
        RuntimeFirewallLifecycleResolverAttemptTransition transition;
        if (coordinator_in_flight) {
            const auto active = resolver_stream_attempt_owner_.select(
                attempt.attempt_id(), resolver_generation_snapshot_);
            transition = attempt.poll(
                RuntimeFirewallLifecycleResolverActiveFacts{
                    true,
                    active.selection.correlated_attempt
                        ? attempt.attempt_id()
                        : std::string_view{},
                    active.selection.correlated_attempt
                        ? active.selection.generation
                        : nullptr},
                lifecycle_start
                    ? "resolver activation completion was not published"
                    : "resolver reload completion was not published");
        } else {
            transition = attempt.poll(
                RuntimeFirewallLifecycleResolverActiveFacts{},
                lifecycle_start
                    ? "resolver activation completion was not published"
                    : "resolver reload completion was not published");
        }
        apply_transition(transition);
        if (transition.action ==
            RuntimeFirewallLifecycleResolverAttemptAction::
                wait_for_completion) {
            return true;
        }
        return false;
    }
    if (attempt.phase() ==
        RuntimeFirewallLifecycleResolverAttemptPhase::completed) {
        return false;
    }

    const auto fail = [&attempt, &apply_transition](
        std::string_view detail) noexcept {
        const auto transition = attempt.phase() ==
                RuntimeFirewallLifecycleResolverAttemptPhase::not_started
            ? attempt.fail_before_start(detail)
            : attempt.coordinator_not_started(detail);
        apply_transition(transition);
    };

    // The active attempt id/generation are the IPC stream authority. Never
    // overwrite another coordinator claim before request() can reject us as
    // busy; the coordinator releases its lifetime before reporting idle.
    if (resolver_stream_coordinator_.in_flight()) {
        fail(lifecycle_start
                 ? "resolver activation coordinator is busy"
                 : "resolver reload coordinator is busy");
        return false;
    }

    try {
        if (!state.list_cache_snapshot) {
            fail(lifecycle_start
                     ? "runtime start resolver list generation is unavailable"
                     : "runtime restart resolver list generation is unavailable");
            return false;
        }
        if (lifecycle_cold_boot &&
            !state.private_resolver_generation) {
            apply_started_ts_.store(
                unix_timestamp_now_seconds(),
                std::memory_order_release);
            state.private_resolver_generation =
                std::make_shared<const ResolverGenerationSnapshot>(
                    make_resolver_generation_snapshot(
                        state.list_cache_snapshot,
                        state.lifecycle_trusted_dns_interfaces));
            state.publication_tail.mark_resolver_generation_published();
        } else if (!lifecycle_config_generation &&
            !lifecycle_keenetic_dns_generation &&
            !state.publication_tail.resolver_generation_published()) {
            apply_started_ts_.store(
                unix_timestamp_now_seconds(),
                std::memory_order_release);
            commit_resolver_generation_snapshot(
                make_resolver_generation_snapshot(
                    state.list_cache_snapshot,
                    state.lifecycle_trusted_dns_interfaces));
            state.publication_tail.mark_resolver_generation_published();
        }
        if ((lifecycle_cold_boot || lifecycle_config_generation ||
             lifecycle_keenetic_dns_generation) &&
            !state.private_resolver_generation) {
            fail("private lifecycle resolver generation is unavailable");
            return false;
        }
        if (!lifecycle_cold_boot && !lifecycle_config_generation &&
            !lifecycle_keenetic_dns_generation &&
            !resolver_generation_snapshot_) {
            fail("lifecycle resolver generation was not published");
            return false;
        }

        auto generation = std::make_shared<ResolverGenerationSnapshot>(
            *((lifecycle_cold_boot || lifecycle_config_generation ||
               lifecycle_keenetic_dns_generation)
                  ? state.private_resolver_generation
                  : resolver_generation_snapshot_));
        resolver_stream_attempt_owner_.assign_next_stream_epoch(
            *generation);
        const std::string attempt_id = generate_resolver_attempt_id();
        const auto args = build_system_resolver_hook_args(
            generation->config,
            lifecycle_start
                ? runtime_start_resolver_action()
                : std::string_view{"reload"},
            attempt_id);
        apply_transition(attempt.prearm(
            attempt_id,
            generation->stream_epoch,
            generation));
        if (attempt.phase() ==
            RuntimeFirewallLifecycleResolverAttemptPhase::completed) {
            return false;
        }
        if (args.empty()) {
            apply_transition(attempt.complete_without_stream());
            return false;
        }

        auto lifetime =
            resolver_stream_attempt_owner_.acquire_lifetime(
                attempt_id, generation);
        if (!lifecycle_cold_boot && !lifecycle_config_generation &&
            !lifecycle_keenetic_dns_generation) {
            resolver_generation_snapshot_ = generation;
        } else {
            state.private_resolver_generation = generation;
            if (state.config_generation_transaction) {
                if (runtime_firewall_lifecycle_is_config_candidate(
                        context->lifecycle_kind)) {
                    state.config_generation_transaction
                        ->candidate_resolver_generation = generation;
                } else {
                    state.config_generation_transaction
                        ->rollback_resolver_generation = generation;
                }
            }
            if (lifecycle_keenetic_dns_generation &&
                state.keenetic_dns_refresh_transaction) {
                if (runtime_firewall_lifecycle_is_keenetic_dns_candidate(
                        context->lifecycle_kind)) {
                    state.keenetic_dns_refresh_transaction
                        ->candidate_resolver_generation = generation;
                } else {
                    state.keenetic_dns_refresh_transaction
                        ->rollback_resolver_generation = generation;
                }
            }
        }
        resolver_stream_attempt_owner_.publish_active(
            lifetime, lifecycle_start);

        std::weak_ptr<RuntimeFirewallOperationContext> weak_context{
            context};
        ResolverStreamOperation operation;
        operation.runtime_generation =
            context->queued_claim.runtime_generation;
        operation.retry_attempt = context->queued_claim.attempt;
        operation.stream_epoch = generation->stream_epoch;
        operation.attempt_id = attempt_id;
        operation.timeout = std::chrono::seconds{15};
        operation.lifetime = std::move(lifetime);
        operation.invoke_hook = [this, args]() {
            KPBR_LOCK_GUARD(system_resolver_hook_mutex_);
            return hook_command_executor_(args);
        };
        operation.completion =
            [this, weak_context, generation](
                const ResolverStreamOperation& completed_operation,
                const ResolverStreamResult& result) noexcept {
                const auto retained = weak_context.lock();
                if (!retained ||
                    !runtime_firewall_owner_->is_active(retained) ||
                    !retained->domain_state) {
                    return;
                }
                auto& completed_state =
                    static_cast<DaemonRuntimeFirewallOperationState&>(
                        *retained->domain_state);
                RuntimeFirewallLifecycleResolverCompletionFacts facts;
                facts.completed_attempt_id =
                    completed_operation.attempt_id;
                facts.completed_stream_epoch =
                    completed_operation.stream_epoch;
                facts.completed_generation = generation;
                facts.lifecycle_generation_current =
                    runtime_firewall_lifecycle_generation_is_current(
                        retained->lifecycle_kind,
                        completed_operation.runtime_generation);
                facts.operation_completed = result.completed;
                facts.exit_code_zero = result.hook_exit_code == 0;
                facts.failure_detail = result.error;
                facts.default_failure_detail =
                    runtime_firewall_lifecycle_uses_start_pipeline(
                        retained->lifecycle_kind)
                    ? "resolver activation did not publish the expected "
                      "configuration stream"
                    : "resolver reload did not publish the expected "
                      "configuration stream";
                const auto active = resolver_stream_attempt_owner_.select(
                    completed_operation.attempt_id,
                    resolver_generation_snapshot_);
                facts.active_attempt_id =
                    active.selection.correlated_attempt
                    ? std::string_view{completed_operation.attempt_id}
                    : std::string_view{};
                facts.active_generation =
                    active.selection.correlated_attempt
                    ? active.selection.generation
                    : nullptr;
                const auto transition = completed_state
                    .lifecycle_resolver_attempt.complete(facts);
                if (!transition.state_changed) return;
                completed_state.lifecycle_resolver_verified =
                    transition.verified;
                if (!transition.failure_detail.empty()) {
                    try {
                        completed_state.lifecycle_failure_detail.assign(
                            transition.failure_detail.data(),
                            transition.failure_detail.size());
                    } catch (...) {
                    }
                }
                if (transition.request_terminal_drain) {
                    runtime_firewall_owner_->request_terminal_drain(
                        retained);
                }
            };

        const auto requested =
            resolver_stream_coordinator_.request(std::move(operation));
        if (requested ==
            ResolverStreamCoordinator::RequestResult::started) {
            if (lifecycle_config_generation &&
                runtime_firewall_lifecycle_is_config_candidate(
                    context->lifecycle_kind) &&
                state.config_generation_transaction) {
                state.config_generation_transaction
                    ->candidate_resolver_may_have_changed = true;
            }
            const auto transition = attempt.coordinator_started();
            apply_transition(transition);
            return transition.action ==
                RuntimeFirewallLifecycleResolverAttemptAction::
                    wait_for_completion;
        }
        if (requested ==
            ResolverStreamCoordinator::RequestResult::busy) {
            fail(lifecycle_start
                     ? "resolver activation coordinator is busy"
                     : "resolver reload coordinator is busy");
        } else {
            fail(lifecycle_start
                     ? "resolver activation worker rejected the operation"
                     : "resolver reload worker rejected the operation");
        }
    } catch (const std::exception& error) {
        fail(error.what());
    } catch (...) {
        fail(lifecycle_start
                 ? "resolver activation failed with an unknown error"
                 : "resolver reload failed with an unknown error");
    }
    return false;
}

bool Daemon::begin_runtime_firewall_start_rollback(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context)
    noexcept {
    if (!context || !runtime_firewall_owner_->is_active(context) ||
        !runtime_firewall_lifecycle_is_start(context->lifecycle_kind) ||
        !context->domain_state) {
        return false;
    }
    auto& state = static_cast<DaemonRuntimeFirewallOperationState&>(
        *context->domain_state);
    using Phase = DaemonRuntimeFirewallOperationState::
        LifecycleTailPhase;
    if (state.lifecycle_start_rollback_phase == Phase::completed) {
        return false;
    }
    if (state.lifecycle_start_rollback_phase == Phase::in_flight) {
        const auto result = state.lifecycle_start_rollback_result;
        if (!result ||
            !result->ready.load(std::memory_order_acquire)) {
            return true;
        }
        try {
            state.lifecycle_start_rollback_detail = result->detail;
        } catch (...) {
        }
        state.lifecycle_start_rollback_phase = Phase::completed;
        return false;
    }

    const auto reject_handoff = [&state](std::string_view detail) noexcept {
        state.lifecycle_start_rollback_result.reset();
        state.lifecycle_start_rollback_phase = Phase::not_started;
        if (state.lifecycle_start_rollback_handoff_rejections <
            kRuntimeFirewallStartRollbackHandoffRetryLimit) {
            ++state.lifecycle_start_rollback_handoff_rejections;
        }
        const bool retry =
            runtime_firewall_start_rollback_handoff_retry_available(
                state.lifecycle_start_rollback_handoff_rejections);
        try {
            state.lifecycle_start_rollback_detail.assign(
                detail.data(), detail.size());
            if (!retry) {
                if (!state.lifecycle_start_rollback_detail.empty()) {
                    state.lifecycle_start_rollback_detail += "; ";
                }
                state.lifecycle_start_rollback_detail +=
                    "rollback worker transport retry limit exhausted; "
                    "kernel cleanup was not verified";
            }
        } catch (...) {
        }
        if (!retry) {
            // The exact START terminal now proceeds through the ordinary
            // inactive+broken publication. Never report cleanup success when
            // the dedicated rollback executor did not accept the task.
            state.lifecycle_start_rollback_phase = Phase::completed;
        }
        return retry;
    };

    try {
        auto result =
            std::make_shared<RuntimeFirewallStartRollbackResult>();
        const auto deactivate_args = build_system_resolver_hook_args(
            config_, "deactivate");
        std::weak_ptr<RuntimeFirewallOperationContext> weak_context{
            context};
        state.lifecycle_start_rollback_result = result;
        state.lifecycle_start_rollback_phase = Phase::in_flight;

        const bool queued = runtime_firewall_owner_->enqueue_auxiliary(
            context,
            "runtime-start-rollback",
            [this, result, deactivate_args, weak_context]() mutable {
                const auto append_failure = [result](
                    const char* stage,
                    std::string_view detail) noexcept {
                    try {
                        if (!result->detail.empty()) {
                            result->detail += "; ";
                        }
                        result->detail += stage;
                        if (!detail.empty()) {
                            result->detail += ": ";
                            result->detail.append(
                                detail.data(), detail.size());
                        }
                    } catch (...) {
                    }
                };

                try {
                    const auto inventory =
                        routing_operation_owner_.clear();
                    result->routing_cleared =
                        classify_runtime_routing_inventory(inventory) ==
                            RuntimeRoutingInventoryAuthority::authoritative &&
                        inventory->routes.empty() &&
                        inventory->rules.empty() &&
                        inventory->phase ==
                            RuntimeRoutingMutationPhase::cleared &&
                        inventory->outcome ==
                            RuntimeRoutingOperationOutcome::cleared;
                    if (!result->routing_cleared) {
                        append_failure(
                            "routing cleanup",
                            "kernel removal was not authoritatively verified");
                    }
                } catch (const std::exception& error) {
                    append_failure("routing cleanup", error.what());
                } catch (...) {
                    append_failure(
                        "routing cleanup", "unknown error");
                }

                try {
                    KPBR_LOCK_GUARD(
                        udp_call_affinity_mutation_mutex_);
                    result->firewall_cleared =
                        firewall_->cleanup_and_inspect_owned()
                            .verified_absent();
                    if (!result->firewall_cleared) {
                        append_failure(
                            "firewall cleanup",
                            "kernel removal was not authoritatively verified");
                    }
                } catch (const std::exception& error) {
                    append_failure("firewall cleanup", error.what());
                } catch (...) {
                    append_failure(
                        "firewall cleanup", "unknown error");
                }

                try {
                    if (deactivate_args.empty()) {
                        result->resolver_deactivated = true;
                    } else {
                        KPBR_LOCK_GUARD(system_resolver_hook_mutex_);
                        result->resolver_deactivated =
                            hook_command_executor_(deactivate_args) == 0;
                        if (!result->resolver_deactivated) {
                            append_failure(
                                "resolver deactivate",
                                "hook returned a non-zero status");
                        }
                    }
                } catch (const std::exception& error) {
                    append_failure(
                        "resolver deactivate", error.what());
                } catch (...) {
                    append_failure(
                        "resolver deactivate", "unknown error");
                }

                result->ready.store(true, std::memory_order_release);
                (void)post_control_task(
                    [this, weak_context]() noexcept {
                        const auto retained = weak_context.lock();
                        if (retained) {
                            runtime_firewall_owner_
                                ->request_terminal_drain(retained);
                        }
                    },
                    "runtime-start-rollback-complete");
            });
        if (queued) return true;

        // Keep the exact terminal and lease parked. The bounded terminal
        // watchdog will retry the auxiliary handoff; finalizing without
        // clearing routes/firewall/resolver would falsely report a rollback.
        return reject_handoff(
            "runtime start rollback worker rejected the operation");
    } catch (const std::exception& error) {
        return reject_handoff(error.what());
    } catch (...) {
        return reject_handoff(
            "runtime start rollback could not be queued");
    }
}

void Daemon::drain_runtime_firewall_terminal(
    const std::shared_ptr<RuntimeFirewallOperationContext>& context,
    bool shutdown) {
    if (!context || !context->terminal_owner ||
        !runtime_firewall_owner_->is_active(context)) {
        return;
    }
    auto& state = runtime_firewall_domain_state(context);
    const bool lifecycle_preapply =
        runtime_firewall_lifecycle_is_preapply(
            context->lifecycle_kind);
    const bool lifecycle_config_generation =
        runtime_firewall_lifecycle_is_config_generation(
            context->lifecycle_kind);
    const bool lifecycle_urltest_generation =
        runtime_firewall_lifecycle_is_urltest_generation(
            context->lifecycle_kind);
    const bool lifecycle_keenetic_dns_generation =
        runtime_firewall_lifecycle_is_keenetic_dns_generation(
            context->lifecycle_kind);
    const bool lifecycle_preowned =
        runtime_firewall_lifecycle_uses_preowned_continuation(
            context->lifecycle_kind);
    const bool lifecycle_cold_boot =
        runtime_firewall_lifecycle_is_cold_boot(
            context->lifecycle_kind);
    const bool lifecycle_stop_cleanup =
        runtime_firewall_lifecycle_is_stop_cleanup(
            context->lifecycle_kind);
    const bool lifecycle_exact_tcp_reset_point =
        runtime_firewall_lifecycle_is_exact_tcp_reset_point(
            context->lifecycle_kind);
    const bool lifecycle_background_point_mutation =
        runtime_firewall_lifecycle_is_background_point_mutation(
            context->lifecycle_kind);

    auto drain = context->terminal_owner->try_begin_drain();
    if (!drain.has_value()) return;

    if (lifecycle_background_point_mutation) {
        const auto transaction =
            state.background_point_mutation_transaction;
        const auto return_retained_lease =
            [this, &context, &drain, &state]() noexcept {
                if (!context->retained_mutation_lease) {
                    auto returned = drain->take_retained_mutation_lease();
                    if (returned) {
                        context->retained_mutation_lease =
                            std::move(returned);
                    }
                }
                return context->retained_mutation_lease &&
                    static_cast<bool>(*context->retained_mutation_lease) &&
                    state.background_point_mutation_lease_token != 0U &&
                    context->retained_mutation_lease->token() ==
                        state.background_point_mutation_lease_token &&
                    runtime_mutation_admission_.owns(
                        *context->retained_mutation_lease);
        };
        const auto make_terminal = [](
            RuntimeFirewallLifecycleOutcome outcome,
            bool committed,
            bool ambiguous,
            std::string detail) {
            RuntimeFirewallLifecycleTerminal terminal;
            terminal.outcome = outcome;
            terminal.committed = committed;
            terminal.commit_ambiguous = ambiguous;
            terminal.transient = false;
            terminal.previous_generation_certainly_retained =
                !committed && !ambiguous;
            terminal.detail = std::move(detail);
            return terminal;
        };
        const auto finish_without_worker =
            [this,
             &context,
             &drain,
             &state,
             &return_retained_lease,
             &make_terminal,
             shutdown](bool worker_queue_abandoned) {
                const bool lease_returned = return_retained_lease();
                auto lifecycle_terminal = make_terminal(
                    lease_returned && shutdown
                        ? RuntimeFirewallLifecycleOutcome::shutdown
                        : RuntimeFirewallLifecycleOutcome::not_verified,
                    /*committed=*/false,
                    /*ambiguous=*/!lease_returned,
                    !lease_returned
                        ? "background point mutation did not return its "
                          "physical mutation lease"
                        : (state.preworker_failure_detail.empty()
                               ? (worker_queue_abandoned
                                      ? "background point mutation worker "
                                        "queue was abandoned"
                                      : "background point mutation ended "
                                        "before worker handoff")
                               : state.preworker_failure_detail));
                auto permit = runtime_firewall_owner_->
                    prepare_preowned_continuation_finalization(context);
                if (!permit.has_value()) return false;
                auto proof = worker_queue_abandoned
                    ? drain->finish_worker_terminal()
                    : drain->finish_coordinator_terminal();
                if (!proof.has_value()) return false;
                return runtime_firewall_owner_->
                    complete_preowned_continuation(
                        std::move(*permit),
                        std::move(*proof),
                        std::move(lifecycle_terminal));
        };

        if (drain->kind() ==
            RuntimeFirewallDelayedTerminalOwner::DrainKind::coordinator) {
            const auto* terminal = drain->coordinator_terminal();
            if (!terminal || !terminal->owned) return;
            (void)finish_without_worker(false);
            return;
        }

        const auto* terminal = drain->worker_terminal();
        if (!terminal) return;
        if (terminal->status ==
            RuntimeFirewallDelayedWorker::TerminalStatus::queued_abandoned) {
            if (!terminal->coordinator_completion.has_value() ||
                !terminal->coordinator_completion->owned) {
                return;
            }
            (void)finish_without_worker(true);
            return;
        }
        if (!terminal->running_claim.has_value() ||
            !terminal->mutation_lease) {
            return;
        }

        const RuntimeFirewallWorkerAttemptResult* worker_result =
            terminal->result.get();
        const auto point_result =
            worker_result && worker_result->background_point_mutation
            ? worker_result->background_point_mutation
            : std::shared_ptr<const RuntimeBackgroundPointMutationResult>{};
        const bool terminal_lease_identity_valid =
            terminal->mutation_lease.lease &&
            static_cast<bool>(*terminal->mutation_lease.lease) &&
            state.background_point_mutation_lease_token != 0U &&
            terminal->mutation_lease.lease->token() ==
                state.background_point_mutation_lease_token &&
            runtime_mutation_admission_.owns(
                *terminal->mutation_lease.lease);
        const bool typed_identity_valid =
            terminal->status ==
                RuntimeFirewallDelayedWorker::TerminalStatus::result &&
            transaction && context->worker_input && worker_result &&
            point_result &&
            terminal->running_claim->raw_claim().serial ==
                context->queued_claim.serial &&
            terminal->running_claim->raw_claim().runtime_generation ==
                context->queued_claim.runtime_generation &&
            terminal->running_claim->raw_claim().attempt ==
                context->queued_claim.attempt &&
            context->worker_input->operation_kind ==
                RuntimeFirewallWorkerOperationKind::
                    background_point_mutation &&
            worker_result->operation_kind ==
                RuntimeFirewallWorkerOperationKind::
                    background_point_mutation &&
            context->worker_input->transaction.operation_serial ==
                context->queued_claim.serial &&
            context->worker_input->transaction.runtime_generation ==
                context->queued_claim.runtime_generation &&
            worker_result->transaction.operation_serial ==
                context->queued_claim.serial &&
            worker_result->transaction.runtime_generation ==
                context->queued_claim.runtime_generation &&
            context->worker_input->
                background_point_mutation_target.has_value() &&
            *context->worker_input->background_point_mutation_target ==
                transaction->target &&
            point_result->target == transaction->target;
        const bool worker_control_verified =
            typed_identity_valid && terminal_lease_identity_valid &&
            point_result->control_publishable() &&
            !point_result->unsafe_publication_possible();

        if (!drain->begin_worker_control(runtime_firewall_retry_)) return;
        if (!drain->publish_worker_control([]() noexcept { return true; })) {
            return;
        }
        OwnedSnatRecovery no_point_recovery;
        if (!drain->complete_worker_control(
                runtime_firewall_retry_,
                worker_control_verified,
                std::move(no_point_recovery))) {
            return;
        }
        const auto* completion = drain->worker_control_completion();
        if (!completion || !completion->owned) return;
        const bool lease_returned = return_retained_lease();
        const bool identity_valid =
            typed_identity_valid && terminal_lease_identity_valid &&
            lease_returned;
        if (transaction) {
            transaction->result = point_result;
            transaction->typed_identity_valid = identity_valid;
        }
        const bool publishable =
            identity_valid && point_result->control_publishable() &&
            !point_result->unsafe_publication_possible();
        const bool ambiguous =
            !identity_valid ||
            (typed_identity_valid &&
             point_result->unsafe_publication_possible()) ||
            (typed_identity_valid &&
             point_result->mutation_boundary_entered &&
             !point_result->control_publishable());
        const bool committed =
            typed_identity_valid &&
            point_result->mutation_boundary_entered;

        context->worker_succeeded = publishable;
        context->worker_commit_ambiguous = ambiguous;
        auto lifecycle_terminal = make_terminal(
            !lease_returned
                ? RuntimeFirewallLifecycleOutcome::not_verified
                : (shutdown
                       ? RuntimeFirewallLifecycleOutcome::shutdown
                       : (publishable
                              ? RuntimeFirewallLifecycleOutcome::
                                    verified_success
                              : RuntimeFirewallLifecycleOutcome::
                                    not_verified)),
            committed,
            ambiguous,
            !lease_returned
                ? "background point mutation did not return its physical "
                  "mutation lease"
                : (!typed_identity_valid
                       ? "background point mutation worker returned no "
                         "matching typed proof"
                       : (point_result->unsafe_publication_possible()
                              ? "background point mutation publication "
                                "remains ambiguous"
                       : (!point_result->control_publishable()
                              ? "background point mutation result was not "
                                "control-publishable"
                              : std::string{}))));
        auto permit = runtime_firewall_owner_->
            prepare_preowned_continuation_finalization(context);
        if (!permit.has_value()) return;
        auto proof = drain->finish_worker_terminal();
        if (!proof.has_value()) return;
        (void)runtime_firewall_owner_->complete_preowned_continuation(
            std::move(*permit),
            std::move(*proof),
            std::move(lifecycle_terminal));
        return;
    }

    if (lifecycle_exact_tcp_reset_point) {
        const auto return_exact_retained_lease =
            [this, &context, &drain, &state]() noexcept {
                if (!context->retained_mutation_lease) {
                    auto returned = drain->take_retained_mutation_lease();
                    if (returned) {
                        context->retained_mutation_lease =
                            std::move(returned);
                    }
                }
                return context->retained_mutation_lease &&
                    static_cast<bool>(*context->retained_mutation_lease) &&
                    state.exact_tcp_reset_point_mutation_lease_token != 0U &&
                    context->retained_mutation_lease->token() ==
                        state.exact_tcp_reset_point_mutation_lease_token &&
                    runtime_mutation_admission_.owns(
                        *context->retained_mutation_lease);
        };
        const auto make_terminal = [](
            RuntimeFirewallLifecycleOutcome outcome,
            bool committed,
            bool ambiguous,
            std::string detail) {
            RuntimeFirewallLifecycleTerminal terminal;
            terminal.outcome = outcome;
            terminal.committed = committed;
            terminal.commit_ambiguous = ambiguous;
            terminal.transient = false;
            terminal.previous_generation_certainly_retained =
                !committed && !ambiguous;
            terminal.detail = std::move(detail);
            return terminal;
        };

        if (drain->kind() ==
            RuntimeFirewallDelayedTerminalOwner::DrainKind::coordinator) {
            const auto* terminal = drain->coordinator_terminal();
            if (!terminal || !terminal->owned) {
                return;
            }
            const bool exact_lease_returned =
                return_exact_retained_lease();
            auto lifecycle_terminal = make_terminal(
                !exact_lease_returned
                    ? RuntimeFirewallLifecycleOutcome::not_verified
                    : (shutdown
                           ? RuntimeFirewallLifecycleOutcome::shutdown
                           : RuntimeFirewallLifecycleOutcome::not_verified),
                /*committed=*/false,
                /*ambiguous=*/!exact_lease_returned,
                !exact_lease_returned
                    ? "exact TCP reset point did not return its physical "
                      "mutation lease"
                    : (state.preworker_failure_detail.empty()
                           ? "exact TCP reset point ended before worker "
                             "handoff"
                           : state.preworker_failure_detail));
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_coordinator_terminal();
            if (!proof.has_value()) return;
            (void)runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(lifecycle_terminal));
            return;
        }

        const auto* terminal = drain->worker_terminal();
        if (!terminal) return;
        if (terminal->status ==
            RuntimeFirewallDelayedWorker::TerminalStatus::queued_abandoned) {
            if (!terminal->coordinator_completion.has_value() ||
                !terminal->coordinator_completion->owned) {
                return;
            }
            const bool exact_lease_returned =
                return_exact_retained_lease();
            auto lifecycle_terminal = make_terminal(
                !exact_lease_returned
                    ? RuntimeFirewallLifecycleOutcome::not_verified
                    : (shutdown
                           ? RuntimeFirewallLifecycleOutcome::shutdown
                           : RuntimeFirewallLifecycleOutcome::not_verified),
                /*committed=*/false,
                /*ambiguous=*/!exact_lease_returned,
                !exact_lease_returned
                    ? "exact TCP reset point worker did not return its "
                      "physical mutation lease"
                    : (state.preworker_failure_detail.empty()
                           ? "exact TCP reset point worker queue was abandoned"
                           : state.preworker_failure_detail));
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_worker_terminal();
            if (!proof.has_value()) return;
            (void)runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(lifecycle_terminal));
            return;
        }
        if (!terminal->running_claim.has_value() ||
            !terminal->mutation_lease) {
            return;
        }

        const RuntimeFirewallWorkerAttemptResult* worker_result =
            terminal->result.get();
        const RuntimeExactTcpResetPointMutationResult* point_result =
            worker_result && worker_result->exact_tcp_reset_point_mutation
            ? worker_result->exact_tcp_reset_point_mutation.get()
            : nullptr;
        const bool terminal_lease_identity_valid =
            terminal->mutation_lease.lease &&
            static_cast<bool>(*terminal->mutation_lease.lease) &&
            state.exact_tcp_reset_point_mutation_lease_token != 0U &&
            terminal->mutation_lease.lease->token() ==
                state.exact_tcp_reset_point_mutation_lease_token &&
            runtime_mutation_admission_.owns(
                *terminal->mutation_lease.lease);
        const bool typed_identity_valid =
            terminal->status ==
                RuntimeFirewallDelayedWorker::TerminalStatus::result &&
            context->worker_input && worker_result && point_result &&
            terminal->running_claim->raw_claim().serial ==
                context->queued_claim.serial &&
            terminal->running_claim->raw_claim().runtime_generation ==
                context->queued_claim.runtime_generation &&
            terminal->running_claim->raw_claim().attempt ==
                context->queued_claim.attempt &&
            state.exact_tcp_reset_point_target.has_value() &&
            context->worker_input->operation_kind ==
                RuntimeFirewallWorkerOperationKind::
                    exact_tcp_reset_point_mutation &&
            worker_result->operation_kind ==
                RuntimeFirewallWorkerOperationKind::
                    exact_tcp_reset_point_mutation &&
            context->worker_input->transaction.operation_serial ==
                context->queued_claim.serial &&
            context->worker_input->transaction.runtime_generation ==
                context->queued_claim.runtime_generation &&
            worker_result->transaction.operation_serial ==
                context->queued_claim.serial &&
            worker_result->transaction.runtime_generation ==
                context->queued_claim.runtime_generation &&
            context->worker_input->exact_tcp_reset_point_target.has_value() &&
            *context->worker_input->exact_tcp_reset_point_target ==
                *state.exact_tcp_reset_point_target &&
            point_result->target == *state.exact_tcp_reset_point_target;
        const bool worker_control_verified =
            typed_identity_valid && terminal_lease_identity_valid &&
            point_result->fully_verified();

        if (!drain->begin_worker_control(runtime_firewall_retry_)) return;
        if (!drain->publish_worker_control([]() noexcept { return true; })) {
            return;
        }
        OwnedSnatRecovery no_point_recovery;
        if (!drain->complete_worker_control(
                runtime_firewall_retry_,
                worker_control_verified,
                std::move(no_point_recovery))) {
            return;
        }
        const auto* completion = drain->worker_control_completion();
        if (!completion || !completion->owned) {
            return;
        }
        const bool exact_lease_returned =
            return_exact_retained_lease();
        const bool identity_valid =
            typed_identity_valid && terminal_lease_identity_valid &&
            exact_lease_returned;
        const bool fully_verified =
            identity_valid && point_result->fully_verified();
        const bool ambiguous =
            !identity_valid ||
            (identity_valid && point_result->unsafe_publication_possible());
        const bool committed =
            typed_identity_valid && point_result->mutation_boundary_entered;

        std::string detail;
        if (!exact_lease_returned || !terminal_lease_identity_valid) {
            detail =
                "exact TCP reset point did not return its physical mutation "
                "lease";
        } else if (!typed_identity_valid) {
            detail =
                "exact TCP reset point worker returned no matching typed proof";
        } else if (point_result->unsafe_publication_possible()) {
            detail =
                "exact TCP reset publication could not be proven removed";
        } else if (!fully_verified) {
            detail = point_result->target.kind ==
                    RuntimeExactTcpResetPointMutationKind::remove_rule
                ? "exact TCP reset removal was not verified"
                : (point_result->flow_revalidated
                       ? "exact TCP reset flow retirement was not verified"
                       : "exact TCP reset target changed before mutation");
        }

        context->worker_succeeded = fully_verified;
        context->worker_commit_ambiguous = ambiguous;
        auto lifecycle_terminal = make_terminal(
            !exact_lease_returned
                ? RuntimeFirewallLifecycleOutcome::not_verified
                : (shutdown
                ? RuntimeFirewallLifecycleOutcome::shutdown
                : (fully_verified
                       ? RuntimeFirewallLifecycleOutcome::verified_success
                       : RuntimeFirewallLifecycleOutcome::not_verified)),
            committed,
            ambiguous,
            std::move(detail));
        auto permit = runtime_firewall_owner_->
            prepare_preowned_continuation_finalization(context);
        if (!permit.has_value()) return;
        auto proof = drain->finish_worker_terminal();
        if (!proof.has_value()) return;
        (void)runtime_firewall_owner_->complete_preowned_continuation(
            std::move(*permit),
            std::move(*proof),
            std::move(lifecycle_terminal));
        return;
    }

    if (lifecycle_stop_cleanup) {
        const auto return_retained_lease = [&context, &drain]() noexcept {
            if (context->retained_mutation_lease) return true;
            auto returned = drain->take_retained_mutation_lease();
            if (returned) {
                context->retained_mutation_lease = std::move(returned);
            }
            return static_cast<bool>(context->retained_mutation_lease);
        };
        const auto restore_after_clean_rejection =
            [this, &state]() noexcept {
                if (!state.stop_cleanup_target.has_value() ||
                    state.stop_cleanup_target->intent !=
                        RuntimeStopCleanupIntent::runtime_stop) {
                    return;
                }
                try {
                    resume_exact_tcp_reset_cleanups();
                } catch (...) {
                }
                try {
                    reset_idle_stall_observer(
                        /*schedule_if_eligible=*/true);
                } catch (...) {
                }
                try {
                    const auto current_generation =
                        runtime_generation_.load(std::memory_order_acquire);
                    if (state.previous_meta_cleanup.has_value() &&
                        state.previous_meta_cleanup->runtime_generation ==
                            current_generation) {
                        schedule_meta_udp443_activation_cleanup_retry(
                            state.previous_meta_cleanup->plan,
                            current_generation,
                            meta_udp443_cleanup_epoch_.load(
                                std::memory_order_acquire),
                            state.previous_meta_cleanup->attempt);
                    }
                } catch (...) {
                }
                state.preworker_side_effects_armed = false;
                schedule_netfilter_runtime_refresh_noexcept(
                    NetfilterRefreshReason::full,
                    "runtime STOP rejected before cleanup worker handoff");
            };
        const auto make_terminal =
            [&state](
                RuntimeFirewallLifecycleOutcome outcome,
                bool committed,
                bool ambiguous,
                std::string detail) {
                RuntimeFirewallLifecycleTerminal terminal;
                terminal.outcome = outcome;
                terminal.committed = committed;
                terminal.commit_ambiguous = ambiguous;
                terminal.transient = false;
                terminal.previous_generation_certainly_retained =
                    !committed && !ambiguous;
                terminal.detail = std::move(detail);
                return terminal;
            };

        if (drain->kind() ==
            RuntimeFirewallDelayedTerminalOwner::DrainKind::coordinator) {
            const auto* terminal = drain->coordinator_terminal();
            if (!terminal || !terminal->owned ||
                !return_retained_lease()) {
                return;
            }
            restore_after_clean_rejection();
            auto lifecycle_terminal = make_terminal(
                RuntimeFirewallLifecycleOutcome::not_verified,
                /*committed=*/false,
                /*ambiguous=*/false,
                state.preworker_failure_detail.empty()
                    ? "runtime STOP ended before worker handoff"
                    : state.preworker_failure_detail);
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_coordinator_terminal();
            if (!proof.has_value()) return;
            (void)runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(lifecycle_terminal));
            return;
        }

        const auto* terminal = drain->worker_terminal();
        if (!terminal) return;
        if (terminal->status ==
            RuntimeFirewallDelayedWorker::TerminalStatus::queued_abandoned) {
            if (!terminal->coordinator_completion.has_value() ||
                !terminal->coordinator_completion->owned ||
                !return_retained_lease()) {
                return;
            }
            restore_after_clean_rejection();
            auto lifecycle_terminal = make_terminal(
                RuntimeFirewallLifecycleOutcome::not_verified,
                /*committed=*/false,
                /*ambiguous=*/false,
                state.preworker_failure_detail.empty()
                    ? "runtime STOP worker queue was abandoned"
                    : state.preworker_failure_detail);
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_worker_terminal();
            if (!proof.has_value()) return;
            (void)runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(lifecycle_terminal));
            return;
        }
        if (!terminal->running_claim.has_value() ||
            !terminal->mutation_lease) {
            return;
        }

        const RuntimeFirewallWorkerAttemptResult* worker_result =
            terminal->result.get();
        const RuntimeStopCleanupResult* stop_result =
            worker_result && worker_result->stop_cleanup
            ? worker_result->stop_cleanup.get()
            : nullptr;
        const bool identity_valid =
            terminal->status ==
                RuntimeFirewallDelayedWorker::TerminalStatus::result &&
            context->worker_input && worker_result && stop_result &&
            state.stop_cleanup_target.has_value() &&
            context->worker_input->operation_kind ==
                RuntimeFirewallWorkerOperationKind::stop_cleanup &&
            worker_result->operation_kind ==
                RuntimeFirewallWorkerOperationKind::stop_cleanup &&
            context->worker_input->transaction.operation_serial ==
                context->queued_claim.serial &&
            context->worker_input->transaction.runtime_generation ==
                context->queued_claim.runtime_generation &&
            worker_result->transaction.operation_serial ==
                context->queued_claim.serial &&
            worker_result->transaction.runtime_generation ==
                context->queued_claim.runtime_generation &&
            stop_result->target.runtime_generation ==
                state.stop_cleanup_target->runtime_generation &&
            stop_result->target.intent ==
                state.stop_cleanup_target->intent &&
            stop_result->target.cleanup_conntrack ==
                state.stop_cleanup_target->cleanup_conntrack &&
            stop_result->target.deactivate_resolver ==
                state.stop_cleanup_target->deactivate_resolver &&
            stop_result->target.maximum_attempts ==
                state.stop_cleanup_target->maximum_attempts &&
            (!stop_result->target.cleanup_conntrack ||
             owned_conntrack_cleanup_snapshot_equal(
                 stop_result->target.conntrack_snapshot,
                 state.stop_cleanup_target->conntrack_snapshot));
        const bool kernel_verified =
            identity_valid && stop_result->kernel_cleanup_verified();
        const bool fully_verified =
            identity_valid && stop_result->fully_verified();

        std::string detail;
        if (!identity_valid) {
            detail =
                "runtime STOP worker returned no exact typed cleanup proof";
        } else if (stop_result->has_failures()) {
            detail = std::string{"runtime STOP "} +
                runtime_stop_cleanup_failure_name(
                    stop_result->last_failure_stage) +
                " stage was not verified";
        } else if (!fully_verified) {
            detail = kernel_verified
                ? "runtime STOP resolver deactivation was not verified"
                : "runtime STOP owned kernel cleanup was not verified";
        }

        if (!drain->begin_worker_control(runtime_firewall_retry_)) return;
        if (!drain->publish_worker_control(
                [this,
                 &state,
                 identity_valid,
                 kernel_verified,
                 fully_verified]() noexcept {
                    try {
                        if (!state.stop_cleanup_generation_advanced) {
                            runtime_generation_.fetch_add(
                                1U, std::memory_order_acq_rel);
                            state.stop_cleanup_generation_advanced = true;
                        }
                        runtime_state_store_.set_routing_runtime_active(false);
                        committed_meta_udp443_fwmark_.reset();
                        committed_meta_udp443_owned_mask_ = 0U;
                        cancel_owned_snat_health_check();
                        cancel_resolver_reload_retry();
                        cancel_internal_vpn_catalog_refresh_retry();
                        urltest_after_firewall_gate_.reset();
                        resolver_after_firewall_gate_.reset();
                        if (urltest_manager_) {
                            urltest_manager_->clear();
                        }
                        urltest_apply_incidents_.clear();
                        if (lists_runtime_mutation_retry_task_id_ >= 0) {
                            scheduler_->cancel(
                                lists_runtime_mutation_retry_task_id_);
                            lists_runtime_mutation_retry_task_id_ = -1;
                        }
                        lists_runtime_mutation_retry_force_reconcile_ = false;
                        if (keenetic_dns_refresh_task_id_ >= 0) {
                            scheduler_->cancel(keenetic_dns_refresh_task_id_);
                            keenetic_dns_refresh_task_id_ = -1;
                        }
                        if (keenetic_dns_refresh_admission_retry_task_id_ >=
                            0) {
                            scheduler_->cancel(
                                keenetic_dns_refresh_admission_retry_task_id_);
                            keenetic_dns_refresh_admission_retry_task_id_ =
                                -1;
                        }
                        if (kernel_verified) {
                            clear_exact_tcp_reset_cleanup_ownership();
                            cancel_owned_conntrack_cleanup_retry();
                            runtime_firewall_retry_
                                .clear_owned_snat_recovery();
                        }
                        state.preworker_side_effects_armed = false;
                        const auto target_state =
                            identity_valid && fully_verified
                            ? RuntimeState::stopped
                            : RuntimeState::broken;
                        if (runtime_state_machine_.state() != target_state) {
                            transition_runtime_or_throw(
                                target_state,
                                target_state == RuntimeState::stopped
                                    ? "runtime STOP cleanup verified"
                                    : "runtime STOP cleanup is incomplete");
                        }
                        publish_runtime_state();
                        return true;
                    } catch (const std::exception& error) {
                        try {
                            Logger::instance().error(
                                "Could not publish runtime STOP terminal: {}",
                                error.what());
                        } catch (...) {
                        }
                        return false;
                    } catch (...) {
                        return false;
                    }
                })) {
            return;
        }
        OwnedSnatRecovery no_stop_recovery;
        if (!drain->complete_worker_control(
                runtime_firewall_retry_,
                fully_verified,
                std::move(no_stop_recovery))) {
            return;
        }
        const auto* completion = drain->worker_control_completion();
        if (!completion || !completion->owned ||
            !return_retained_lease()) {
            return;
        }

        context->worker_succeeded = fully_verified;
        context->worker_commit_ambiguous = !identity_valid;
        auto lifecycle_terminal = make_terminal(
            fully_verified
                ? RuntimeFirewallLifecycleOutcome::verified_success
                : RuntimeFirewallLifecycleOutcome::not_verified,
            identity_valid && stop_result->mutation_boundary_entered,
            !identity_valid,
            std::move(detail));
        auto permit = runtime_firewall_owner_->
            prepare_preowned_continuation_finalization(context);
        if (!permit.has_value()) return;
        auto proof = drain->finish_worker_terminal();
        if (!proof.has_value()) return;
        const bool completed =
            runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(lifecycle_terminal));
        if (completed) {
            try {
                refresh_resolver_config_hash_actual_async();
            } catch (...) {
            }
        }
        return;
    }

    const auto retain_config_post_terminal_intent =
        [&context, &state, lifecycle_config_generation]() {
            if (!lifecycle_config_generation ||
                !state.config_generation_transaction) {
                return;
            }
            auto& transaction =
                *state.config_generation_transaction;
            try {
                transaction.post_terminal_snat_recovery =
                    merge_owned_snat_recovery(
                        transaction.post_terminal_snat_recovery,
                        context->completion.snat_recovery);
                const bool exact_snat_intent =
                    transaction.post_terminal_snat_recovery.requested ||
                    transaction.post_terminal_snat_recovery
                        .missing_observed ||
                    transaction.post_terminal_snat_recovery
                        .cleanup_snapshot.has_value();
                const bool full_refresh =
                    context->completion.rerun_requested ||
                    static_cast<bool>(
                        context->completion.next_prepared_catalog) ||
                    context->force_successor;
                transaction.post_terminal_refresh_required =
                    transaction.post_terminal_refresh_required ||
                    exact_snat_intent || full_refresh;
                transaction.post_terminal_full_refresh =
                    transaction.post_terminal_full_refresh ||
                    full_refresh;
            } catch (...) {
                // The coordinator still owns its exact SNAT latch. A fresh
                // full observation is the conservative continuation if the
                // duplicate transaction-side checkpoint could not allocate.
                transaction.post_terminal_refresh_required = true;
                transaction.post_terminal_full_refresh = true;
            }
        };

    const auto capture_completion =
        [this,
         &context,
         &retain_config_post_terminal_intent](
        const RuntimeFirewallOperationCompletion& source) {
        if (context->completion_captured) {
            if (context->worker_commit_ambiguous) return;

            // Netfilter/NAT events can arrive while this exact terminal is
            // parked on resolver activation or START rollback. Fold their
            // recovery payload into the already durable completion instead
            // of merely setting force_successor and losing SNAT inspection.
            (void)absorb_trailing_runtime_firewall_completion(
                context->completion,
                context->trailing_snat_recovery,
                context->trailing_prepared_native_vpn_catalog,
                context->force_successor);
            retain_config_post_terminal_intent();
            return;
        }
        auto captured = source;
        // Pre-worker terminal transfer deliberately leaves the recovery in
        // the coordinator. Snapshot it before closing the one-shot owner so
        // a rejected queue cannot drop an owned-SNAT repair request.
        if (!captured.snat_recovery.requested) {
            captured.snat_recovery =
                runtime_firewall_retry_.pending_owned_snat_recovery();
        }
        // Once COMMIT was entered without a proven result, neither an older
        // prepared candidate nor an event that arrived before the ambiguity
        // may replay it. The full netfilter resnapshot owner is armed below
        // and will create a fresh operation only after observing the backend.
        if (!context->worker_commit_ambiguous) {
            (void)absorb_trailing_runtime_firewall_completion(
                captured,
                context->trailing_snat_recovery,
                context->trailing_prepared_native_vpn_catalog,
                context->force_successor);
        }
        context->completion = std::move(captured);
        context->completion_captured = true;
        context->trailing_snat_recovery = {};
        context->trailing_prepared_native_vpn_catalog.reset();
        retain_config_post_terminal_intent();
    };

    const auto restore_preworker_control_state =
        [this, &state, shutdown]() {
            if (!state.preworker_side_effects_armed) return;
            if (!shutdown) {
                reset_idle_stall_observer(
                    /*schedule_if_eligible=*/true);
                const auto current_generation =
                    runtime_generation_.load(std::memory_order_acquire);
                if (state.previous_meta_cleanup.has_value() &&
                    state.previous_meta_cleanup->runtime_generation ==
                        current_generation) {
                    schedule_meta_udp443_activation_cleanup_retry(
                        state.previous_meta_cleanup->plan,
                        current_generation,
                        meta_udp443_cleanup_epoch_.load(
                            std::memory_order_acquire),
                        state.previous_meta_cleanup->attempt);
                }
            }
            state.preworker_side_effects_armed = false;
        };

    const auto settle_immediate_completion =
        [this, &state](
            RuntimeFirewallImmediateTerminalOutcome outcome) noexcept {
            const auto settlement =
                state.immediate_completion_intent.settle(outcome);
            if (settlement.status ==
                RuntimeFirewallImmediateCompletionIntent::SettleStatus::
                    retry) {
                return false;
            }
            if (settlement.broad_urltest_probe_claimed) {
                trigger_broad_urltest_probe_noexcept();
            }
            return true;
        };

    const auto absorb_retained_mutation_lease =
        [&context, &drain]() noexcept {
            // A retry after a fallible settlement may already have returned
            // the exact token to this context. Never ask the terminal owner
            // for it twice and never replace one physical authority.
            if (context->retained_mutation_lease) return true;
            auto returned = drain->take_retained_mutation_lease();
            if (returned) {
                context->retained_mutation_lease = std::move(returned);
            }
            return true;
        };

    const auto settle_lifecycle_completion =
        [&context, &state](
            RuntimeFirewallLifecycleOutcome outcome) noexcept {
            if (!context->lifecycle_completion) return;
            RuntimeFirewallLifecycleTerminal terminal;
            terminal.outcome = outcome;
            terminal.committed = state.core_publication.committed ||
                context->preapply_commit_observed;
            terminal.commit_ambiguous =
                context->worker_commit_ambiguous;
            terminal.transient = state.worker_failure_transient ||
                (runtime_firewall_lifecycle_is_foreground(
                     context->lifecycle_kind) &&
                 state.core_publication.committed &&
                 !state.lifecycle_resolver_verified);
            try {
                terminal.detail = state.lifecycle_failure_detail.empty()
                    ? state.worker_failure_detail
                    : state.lifecycle_failure_detail;
            } catch (...) {
                // Outcome and commit authority are sufficient for the caller;
                // diagnostic allocation must not strand the completion.
            }
            (void)context->lifecycle_completion.settle(
                std::move(terminal));
        };

    const auto finalize_start_broken =
        [this, &context, &state](std::string_view detail) noexcept {
            if (!runtime_firewall_lifecycle_is_start(
                    context->lifecycle_kind) ||
                state.publication_tail.start_finalized()) {
                return state.publication_tail.start_finalized();
            }
            if (!state.lifecycle_start_failure_detail_prepared) {
                try {
                    auto prepared = state.lifecycle_failure_detail.empty()
                        ? std::string{detail}
                        : state.lifecycle_failure_detail;
                    if (!state.lifecycle_start_rollback_detail.empty()) {
                        if (!prepared.empty()) {
                            prepared += "; ";
                        }
                        prepared += "rollback: ";
                        prepared += state.lifecycle_start_rollback_detail;
                    }
                    state.lifecycle_failure_detail.swap(prepared);
                    state.lifecycle_start_failure_detail_prepared = true;
                } catch (...) {
                }
            }
            // These are ancillary cleanup signals. None may turn a handled
            // START failure into std::terminate or prevent the mandatory
            // inactive+broken publication below from being retried.
            try {
                cancel_idle_stall_observer();
            } catch (...) {
            }
            try {
                cancel_meta_udp443_activation_cleanup();
            } catch (...) {
            }
            try {
                cancel_owned_snat_health_check();
            } catch (...) {
            }
            try {
                cancel_owned_conntrack_cleanup_retry();
            } catch (...) {
            }
            try {
                cancel_resolver_reload_retry();
            } catch (...) {
            }
            try {
                cancel_internal_vpn_catalog_refresh_retry();
            } catch (...) {
            }
            try {
                urltest_after_firewall_gate_.reset();
            } catch (...) {
            }
            try {
                resolver_after_firewall_gate_.reset();
            } catch (...) {
            }
            if (urltest_manager_) {
                try {
                    urltest_manager_->clear();
                } catch (...) {
                }
            }
            try {
                clear_exact_tcp_reset_cleanup_ownership();
            } catch (...) {
            }
            committed_meta_udp443_fwmark_.reset();
            committed_meta_udp443_owned_mask_ = 0U;
            try {
                refresh_resolver_config_hash_actual_async();
            } catch (...) {
            }

            bool inactive_published = false;
            try {
                runtime_state_store_.set_routing_runtime_active(false);
                inactive_published = true;
            } catch (const std::exception& error) {
                try {
                    Logger::instance().error(
                        "Failed to publish inactive runtime start state: {}",
                        error.what());
                } catch (...) {
                }
            } catch (...) {
            }

            bool broken_transitioned = false;
            try {
                transition_runtime_or_throw(
                    RuntimeState::broken, "runtime start failed");
                broken_transitioned =
                    runtime_state_machine_.state() == RuntimeState::broken;
            } catch (const std::exception& error) {
                try {
                    Logger::instance().error(
                        "Failed to enter broken runtime start state: {}",
                        error.what());
                } catch (...) {
                }
            } catch (...) {
            }

            bool snapshot_published = false;
            if (inactive_published && broken_transitioned) {
                try {
                    publish_runtime_state();
                    snapshot_published = true;
                } catch (const std::exception& error) {
                    try {
                        Logger::instance().error(
                            "Failed to publish broken runtime start state: {}",
                            error.what());
                    } catch (...) {
                    }
                } catch (...) {
                }
            }
            state.publication_tail.set_start_finalized(
                inactive_published && broken_transitioned &&
                snapshot_published);
            return state.publication_tail.start_finalized();
        };

    const auto finish_preworker_failure_policy =
        [this, &context, &state, shutdown, lifecycle_preowned]() {
            if (state.preworker_failure_policy_finished) return;
            if (lifecycle_preowned) {
                // Config pre-apply owns no URLTest, resolver or runtime-state
                // lifecycle. A transport/preparation failure must return its
                // exact request authority without publishing unrelated
                // incidents or moving the running runtime to broken.
                const auto kind = context->foreground_transport_exhausted
                    ? DaemonRuntimeFirewallOperationState::
                          PreworkerFailureKind::transport_rejected
                    : state.preworker_failure_kind;
                if (kind ==
                    DaemonRuntimeFirewallOperationState::
                        PreworkerFailureKind::transport_rejected) {
                    if (!runtime_firewall_owner_->
                            note_foreground_transport_rejection(context)) {
                        context->successor_mode =
                            RuntimeFirewallOperationContext::SuccessorMode::
                                none;
                        context->force_successor = false;
                        state.suppress_coordinator_rerun = true;
                        try {
                            state.lifecycle_failure_detail =
                                "configuration pre-apply worker transport "
                                "retry limit was exhausted";
                        } catch (...) {
                        }
                    }
                } else if (
                    kind != DaemonRuntimeFirewallOperationState::
                                PreworkerFailureKind::none &&
                    !runtime_firewall_preapply_preworker_retry_available(
                        context->queued_claim.attempt)) {
                    // The old-generation SNAT recovery remains eligible for a
                    // background refresh after the exact request lease is
                    // returned. It must never turn this HTTP/WAL operation
                    // into the coordinator's unbounded maintenance loop.
                    context->successor_mode =
                        RuntimeFirewallOperationContext::SuccessorMode::none;
                    context->force_successor = false;
                    state.suppress_coordinator_rerun = true;
                    try {
                        state.lifecycle_failure_detail =
                            "configuration pre-apply preparation retry limit "
                            "was exhausted";
                    } catch (...) {
                    }
                }
                state.preworker_failure_policy_finished = true;
                return;
            }
            if (shutdown) {
                state.preworker_failure_policy_finished = true;
                return;
            }

            const auto kind = context->foreground_transport_exhausted
                ? DaemonRuntimeFirewallOperationState::
                      PreworkerFailureKind::transport_rejected
                : state.preworker_failure_kind;
            if (kind == DaemonRuntimeFirewallOperationState::
                            PreworkerFailureKind::transport_rejected &&
                !runtime_firewall_owner_->
                    note_foreground_transport_rejection(context)) {
                const bool preserve_active_restart_recovery =
                    runtime_firewall_lifecycle_is_restart(
                        context->lifecycle_kind);
                context->successor_mode = preserve_active_restart_recovery
                    ? RuntimeFirewallOperationContext::SuccessorMode::
                          defer_same_attempt
                    : RuntimeFirewallOperationContext::SuccessorMode::none;
                context->force_successor =
                    preserve_active_restart_recovery;
                state.suppress_coordinator_rerun =
                    !preserve_active_restart_recovery;
                try {
                    state.lifecycle_failure_detail =
                        "runtime firewall worker transport retry limit "
                        "was exhausted";
                } catch (...) {
                }
            }
            if (runtime_firewall_lifecycle_is_start(
                    context->lifecycle_kind)) {
                try {
                    if (state.lifecycle_failure_detail.empty()) {
                        state.lifecycle_failure_detail =
                            context->foreground_transport_exhausted
                            ? "runtime start worker transport retry limit "
                              "was exhausted"
                            : (state.preworker_failure_detail.empty()
                                   ? "runtime start failed before worker "
                                     "handoff"
                                   : state.preworker_failure_detail);
                    }
                } catch (...) {
                }
                state.preworker_failure_policy_finished = true;
                return;
            }

            const auto generation = context->queued_claim.runtime_generation;
            const auto attempt = context->queued_claim.attempt;
            const bool urltest_pending =
                urltest_after_firewall_gate_.waiting_for(generation);
            if (kind == DaemonRuntimeFirewallOperationState::
                            PreworkerFailureKind::route_unavailable) {
                Logger::instance().verbose(
                    "Runtime route reconciliation is waiting for an "
                    "interface: {}",
                    state.preworker_failure_detail);
                if (urltest_pending &&
                    attempt >= RUNTIME_FIREWALL_RETRY_DELAYS.size()) {
                    for (const auto& tag :
                         urltest_after_firewall_gate_.pending_tags(
                             generation)) {
                        const auto incident =
                            urltest_apply_incidents_.record_failure(
                                tag, /*notify_immediately=*/true);
                        if (incident.notify) {
                            Logger::instance().error(
                                "Urltest '{}' firewall recovery is still "
                                "waiting for a route after {} bounded "
                                "retries: {}. The previous cursor remains "
                                "active.",
                                tag,
                                attempt,
                                state.preworker_failure_detail);
                        }
                    }
                }
            } else if (
                kind == DaemonRuntimeFirewallOperationState::
                            PreworkerFailureKind::preparation_failure) {
                if (urltest_pending ||
                    state.preworker_urltest_permanent_started) {
                    if (!state.preworker_urltest_permanent_started) {
                        auto failed_tags =
                            urltest_after_firewall_gate_.pending_tags(
                                generation);
                        state.preworker_failed_urltest_tags.assign(
                            failed_tags.begin(), failed_tags.end());
                        urltest_after_firewall_gate_.reset();
                        state.preworker_urltest_permanent_started = true;
                    }
                    try {
                        transition_runtime_or_throw(
                            RuntimeState::broken,
                            "urltest firewall recovery failed permanently");
                        publish_runtime_state();
                    } catch (...) {
                    }
                    for (const auto& tag :
                         state.preworker_failed_urltest_tags) {
                        const auto incident =
                            urltest_apply_incidents_.record_failure(
                                tag, /*notify_immediately=*/true);
                        if (incident.notify) {
                            Logger::instance().error(
                                "Urltest '{}' firewall recovery failed "
                                "permanently before worker handoff: {}. "
                                "Runtime state is broken while the last "
                                "verified kernel generation remains active.",
                                tag,
                                state.preworker_failure_detail);
                        }
                    }
                } else {
                    const bool retry =
                        context->successor_mode ==
                        RuntimeFirewallOperationContext::SuccessorMode::
                            reschedule_retry;
                    const auto incident =
                        runtime_firewall_incidents_.record_failure(
                            "runtime-firewall-reconciliation",
                            /*notify_immediately=*/true);
                    if (incident.notify) {
                        Logger::instance().error(
                            retry
                                ? "Runtime routing/firewall preparation "
                                  "failed: {}. A bounded retry will verify "
                                  "whether the failure clears."
                                : "Runtime routing/firewall preparation "
                                  "failed permanently: {}. The last "
                                  "committed runtime generation remains "
                                  "active.",
                            state.preworker_failure_detail);
                    }
                }
            } else if (
                kind == DaemonRuntimeFirewallOperationState::
                            PreworkerFailureKind::transport_rejected) {
                Logger::instance().info(
                    "Runtime firewall worker handoff was rejected; the exact "
                    "attempt remains deferred without consuming retry "
                    "budget.");
            } else if (
                kind == DaemonRuntimeFirewallOperationState::
                            PreworkerFailureKind::admission_contention) {
                Logger::instance().verbose(
                    "Runtime firewall worker is waiting behind another "
                    "runtime mutation.");
            }
            state.preworker_failure_policy_finished = true;
        };

    const auto finish_context =
        [this,
         &context,
         &state,
         &settle_lifecycle_completion,
         shutdown]() {
        if (!context->completion_captured) return;

        // Terminal shutdown never creates a successor. Retire the one-shot
        // owner before touching any potentially allocating recovery payload;
        // admission is already closed and the dedicated executor is being
        // drained by the lifecycle owner.
        if (shutdown) {
            runtime_firewall_owner_->cancel_completion_watchdog();
            runtime_firewall_owner_->reset_if_active(context);
            context->retained_mutation_lease.reset();
            settle_lifecycle_completion(
                RuntimeFirewallLifecycleOutcome::shutdown);
            return;
        }

        auto successor_mode = context->successor_mode;
        auto successor_attempt = context->successor_attempt;
        auto successor_generation =
            context->successor_runtime_generation != 0U
            ? context->successor_runtime_generation
            : context->queued_claim.runtime_generation;
        auto successor_recovery =
            std::move(context->completion.snat_recovery);
        auto successor_catalog =
            context->completion.next_prepared_catalog;
        if (!successor_catalog && !context->worker_succeeded &&
            !context->worker_commit_ambiguous) {
            successor_catalog = context->prepared_native_vpn_catalog;
        }
        bool schedule_catalog_refresh =
            context->successor_schedule_catalog_refresh;
        if (successor_catalog) {
            if (successor_generation != 0U &&
                successor_catalog->runtime_generation <
                    successor_generation) {
                // A catalog-less observation can already represent a newer
                // runtime generation. Never let an older prepared candidate
                // downgrade that retained intent; the successor must build a
                // fresh cache-only snapshot for the newer generation.
                successor_catalog.reset();
            } else {
                schedule_catalog_refresh =
                    successor_catalog->schedule_catalog_refresh;
            }
            if (successor_catalog &&
                successor_catalog->runtime_generation >
                    successor_generation) {
                successor_generation =
                    successor_catalog->runtime_generation;
                successor_attempt = 0U;
            }
        }

        // An ambiguous COMMIT has exactly one legal continuation: a fresh
        // backend resnapshot. Do not let a pre-existing trailing intent turn
        // it back into same-attempt replay in this finalizer.
        if (context->worker_commit_ambiguous) {
            successor_mode =
                RuntimeFirewallOperationContext::SuccessorMode::none;
            successor_catalog.reset();
            successor_recovery = {};
        }
        const bool completion_requests_rerun =
            runtime_firewall_terminal_requests_successor(
                context->worker_commit_ambiguous,
                context->completion.rerun_requested,
                context->force_successor,
                state.suppress_coordinator_rerun);
        if (successor_mode ==
                RuntimeFirewallOperationContext::SuccessorMode::none &&
            completion_requests_rerun) {
            successor_mode =
                RuntimeFirewallOperationContext::SuccessorMode::
                    defer_same_attempt;
        }

        const bool lifecycle_verified_success =
            context->worker_succeeded &&
            (!runtime_firewall_lifecycle_is_foreground(
                 context->lifecycle_kind) ||
             state.lifecycle_resolver_verified);
        // A source event which arrived during a successful foreground
        // lifecycle must survive after START changes state to running. Settle
        // and release the foreground request, then launch that trailing work
        // as an ordinary background successor.
        const bool detach_verified_foreground =
            runtime_firewall_lifecycle_is_foreground(
                context->lifecycle_kind) &&
            lifecycle_verified_success &&
            successor_mode !=
                RuntimeFirewallOperationContext::SuccessorMode::none;
        const bool detach_failed_restart_recovery =
            context->foreground_transport_exhausted &&
            runtime_firewall_lifecycle_is_restart(
                context->lifecycle_kind) &&
            successor_mode !=
                RuntimeFirewallOperationContext::SuccessorMode::none;
        const bool detach_foreground =
            detach_verified_foreground ||
            detach_failed_restart_recovery;
        const auto successor_lifecycle_kind =
            detach_foreground
            ? RuntimeFirewallLifecycleKind::background
            : context->lifecycle_kind;
        if (!runtime_firewall_lifecycle_generation_is_current(
                successor_lifecycle_kind,
                successor_generation) ||
            successor_mode ==
                RuntimeFirewallOperationContext::SuccessorMode::none) {
            runtime_firewall_owner_->cancel_completion_watchdog();
            runtime_firewall_owner_->reset_if_active(context);
            context->retained_mutation_lease.reset();
            if (lifecycle_verified_success &&
                runtime_firewall_lifecycle_is_start(
                    context->lifecycle_kind)) {
                resume_urltest_firewall_recovery(
                    context->queued_claim.runtime_generation);
            }
            settle_lifecycle_completion(
                lifecycle_verified_success
                    ? RuntimeFirewallLifecycleOutcome::verified_success
                    : RuntimeFirewallLifecycleOutcome::not_verified);
            return;
        }

        if (successor_generation == 0U) {
            successor_generation =
                runtime_generation_.load(std::memory_order_acquire);
        }
        if (!runtime_firewall_lifecycle_generation_is_current(
                successor_lifecycle_kind,
                successor_generation)) {
            runtime_firewall_owner_->cancel_completion_watchdog();
            runtime_firewall_owner_->reset_if_active(context);
            context->retained_mutation_lease.reset();
            settle_lifecycle_completion(
                RuntimeFirewallLifecycleOutcome::not_verified);
            return;
        }

        // Retain the exact successor before closing the one-shot terminal
        // context. Its SNAT snapshot/catalog then survive allocation or timer
        // registration failure while a fresh owner is being created.
        const bool retained =
            runtime_firewall_owner_->retain_pending_successor(
                context,
                successor_mode,
                successor_attempt,
                successor_generation,
                std::move(successor_recovery),
                std::move(successor_catalog),
                schedule_catalog_refresh,
                detach_foreground);
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->reset_if_active(context);
        if (!retained) {
            context->retained_mutation_lease.reset();
            settle_lifecycle_completion(
                lifecycle_verified_success
                    ? RuntimeFirewallLifecycleOutcome::verified_success
                    : RuntimeFirewallLifecycleOutcome::not_verified);
            Logger::instance().error(
                "Could not retain the exact runtime firewall successor; a "
                "fresh netfilter resnapshot was requested.");
            schedule_netfilter_runtime_refresh_noexcept(
                NetfilterRefreshReason::full,
                "runtime firewall successor ownership collision");
            return;
        }

        if (detach_foreground) {
            context->retained_mutation_lease.reset();
            settle_lifecycle_completion(
                lifecycle_verified_success
                    ? RuntimeFirewallLifecycleOutcome::verified_success
                    : RuntimeFirewallLifecycleOutcome::not_verified);
        }
        try {
            (void)runtime_firewall_owner_->launch_pending_successor();
        } catch (const std::exception& error) {
            try {
                Logger::instance().error(
                    "Could not arm the retained runtime firewall successor: "
                    "{}",
                    error.what());
            } catch (...) {
            }
        } catch (...) {
        }
    };

    const auto prepare_preapply_terminal =
        [&context, &state](RuntimeFirewallLifecycleOutcome outcome) {
            RuntimeFirewallLifecycleTerminal terminal;
            terminal.outcome = outcome;
            terminal.committed = state.core_publication.committed ||
                context->preapply_commit_observed;
            terminal.commit_ambiguous =
                context->worker_commit_ambiguous;
            terminal.transient = state.worker_failure_transient;
            if (!state.lifecycle_failure_detail.empty()) {
                terminal.detail = state.lifecycle_failure_detail;
            } else if (!state.worker_failure_detail.empty()) {
                terminal.detail = state.worker_failure_detail;
            } else {
                terminal.detail = state.preworker_failure_detail;
            }
            return terminal;
        };

    const auto prepare_config_generation_terminal =
        [&context, &state](
            RuntimeFirewallLifecycleOutcome outcome,
            bool previous_generation_certainly_retained) {
            RuntimeFirewallLifecycleTerminal terminal;
            terminal.outcome = outcome;
            terminal.committed = state.core_publication.committed ||
                context->preapply_commit_observed;
            terminal.commit_ambiguous =
                context->worker_commit_ambiguous;
            terminal.transient = state.worker_failure_transient;
            terminal.observed_config_identity =
                state.config_operation_identity;
            terminal.previous_generation_certainly_retained =
                !terminal.committed &&
                previous_generation_certainly_retained;
            if (!state.lifecycle_failure_detail.empty()) {
                terminal.detail = state.lifecycle_failure_detail;
            } else if (!state.worker_failure_detail.empty()) {
                terminal.detail = state.worker_failure_detail;
            } else {
                terminal.detail = state.preworker_failure_detail;
            }
            return terminal;
        };

    const auto prepare_urltest_generation_terminal =
        [&context, &state](
            RuntimeFirewallLifecycleOutcome outcome,
            bool previous_generation_certainly_retained) {
            RuntimeFirewallLifecycleTerminal terminal;
            terminal.outcome = outcome;
            terminal.committed = state.core_publication.committed;
            terminal.commit_ambiguous =
                context->worker_commit_ambiguous;
            terminal.transient = state.worker_failure_transient;
            terminal.previous_generation_certainly_retained =
                previous_generation_certainly_retained;
            if (!state.lifecycle_failure_detail.empty()) {
                terminal.detail = state.lifecycle_failure_detail;
            } else if (!state.worker_failure_detail.empty()) {
                terminal.detail = state.worker_failure_detail;
            } else {
                terminal.detail = state.preworker_failure_detail;
            }
            return terminal;
        };

    const auto prepare_cold_boot_terminal =
        [&context, &state](
            RuntimeFirewallLifecycleOutcome outcome,
            bool previous_generation_certainly_retained) {
            RuntimeFirewallLifecycleTerminal terminal;
            terminal.outcome = outcome;
            terminal.committed = state.core_publication.committed ||
                context->preapply_commit_observed;
            terminal.commit_ambiguous =
                context->worker_commit_ambiguous;
            terminal.transient = state.worker_failure_transient;
            terminal.previous_generation_certainly_retained =
                !terminal.committed &&
                previous_generation_certainly_retained;
            if (!state.lifecycle_failure_detail.empty()) {
                terminal.detail = state.lifecycle_failure_detail;
            } else if (!state.worker_failure_detail.empty()) {
                terminal.detail = state.worker_failure_detail;
            } else {
                terminal.detail = state.preworker_failure_detail;
            }
            return terminal;
        };

    const auto complete_finalized_preapply =
        [this, &context, &state, shutdown](
            RuntimeFirewallOperationOwner::
                PreownedContinuationFinalizationPermit&& permit,
            RuntimeFirewallOperationOwner::TerminalFinalizationProof&& proof,
            RuntimeFirewallLifecycleTerminal terminal,
            OwnedSnatRecovery successor_recovery) noexcept {
            auto successor_mode = context->successor_mode;
            const bool completion_requests_successor =
                runtime_firewall_terminal_requests_successor(
                    terminal.commit_ambiguous,
                    context->completion.rerun_requested,
                    context->force_successor,
                    state.suppress_coordinator_rerun);
            const bool successor_requested = !shutdown &&
                !terminal.commit_ambiguous &&
                (successor_mode !=
                     RuntimeFirewallOperationContext::SuccessorMode::none ||
                 completion_requests_successor);
            if (successor_requested) {
                if (successor_mode ==
                    RuntimeFirewallOperationContext::SuccessorMode::none) {
                    successor_mode =
                        RuntimeFirewallOperationContext::SuccessorMode::
                            defer_same_attempt;
                }
                const auto successor_generation =
                    context->successor_runtime_generation != 0U
                    ? context->successor_runtime_generation
                    : context->queued_claim.runtime_generation;
                if (runtime_firewall_lifecycle_generation_is_current(
                        context->lifecycle_kind,
                        successor_generation)) {
                    successor_recovery.requested = true;
                    const bool retained =
                        runtime_firewall_owner_->retain_pending_successor(
                            context,
                            successor_mode,
                            context->successor_attempt,
                            successor_generation,
                            std::move(successor_recovery),
                            {},
                            /*schedule_catalog_refresh=*/false,
                            /*detach_foreground=*/false);
                    if (retained) {
                        runtime_firewall_owner_->
                            cancel_completion_watchdog();
                        runtime_firewall_owner_->reset_if_active(context);
                        try {
                            (void)runtime_firewall_owner_->
                                launch_pending_successor();
                        } catch (const std::exception& error) {
                            try {
                                Logger::instance().error(
                                    "Could not arm retained config pre-apply "
                                    "successor: {}",
                                    error.what());
                            } catch (...) {
                            }
                        } catch (...) {
                        }
                        return true;
                    }
                    try {
                        terminal.detail =
                            "configuration pre-apply could not retain its "
                            "exact successor";
                    } catch (...) {
                    }
                } else {
                    try {
                        terminal.detail =
                            "configuration pre-apply generation became stale";
                    } catch (...) {
                    }
                }
                terminal.outcome =
                    RuntimeFirewallLifecycleOutcome::not_verified;
            }

            const bool refresh_after_return =
                terminal.commit_ambiguous || terminal.committed ||
                context->completion.snat_recovery.requested;
            const bool full_refresh = terminal.commit_ambiguous ||
                terminal.committed || context->completion.rerun_requested;
            const bool completed =
                runtime_firewall_owner_->complete_preowned_continuation(
                    std::move(permit),
                    std::move(proof),
                    std::move(terminal));
            if (!completed) {
                try {
                    Logger::instance().error(
                        "Finalized config pre-apply could not return its "
                        "reserved exact continuation");
                } catch (...) {
                }
            }
            if (completed && refresh_after_return) {
                schedule_netfilter_runtime_refresh_noexcept(
                    full_refresh
                        ? NetfilterRefreshReason::full
                        : NetfilterRefreshReason::nat_only,
                    full_refresh
                        ? "config pre-apply requires a fresh backend snapshot"
                        : "config pre-apply retained exact SNAT recovery");
            }
            return completed;
        };

    if (drain->kind() ==
        RuntimeFirewallDelayedTerminalOwner::DrainKind::coordinator) {
        const auto* terminal = drain->coordinator_terminal();
        if (!terminal || !terminal->owned) return;
        capture_completion(*terminal);
        restore_preworker_control_state();
        finish_preworker_failure_policy();
        if (!shutdown && runtime_firewall_lifecycle_is_start(
                context->lifecycle_kind) &&
            context->successor_mode ==
                RuntimeFirewallOperationContext::SuccessorMode::none) {
            if (begin_runtime_firewall_start_rollback(context)) {
                drain->park_until_wake();
                return;
            }
            if (!finalize_start_broken(
                    "runtime start ended before worker handoff")) {
                drain->park_until_wake();
                return;
            }
        }
        if (!absorb_retained_mutation_lease()) return;
        if (!settle_immediate_completion(
                shutdown
                    ? RuntimeFirewallImmediateTerminalOutcome::shutdown
                    : RuntimeFirewallImmediateTerminalOutcome::
                          not_verified)) {
            return;
        }
        if (lifecycle_cold_boot) {
            auto cold_boot_terminal = prepare_cold_boot_terminal(
                shutdown
                    ? RuntimeFirewallLifecycleOutcome::shutdown
                    : RuntimeFirewallLifecycleOutcome::not_verified,
                !shutdown);
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_coordinator_terminal();
            if (!proof.has_value()) return;
            if (!runtime_firewall_owner_->complete_preowned_continuation(
                    std::move(*permit),
                    std::move(*proof),
                    std::move(cold_boot_terminal))) {
                try {
                    Logger::instance().error(
                        "Cold-boot coordinator terminal violated its "
                        "prepared finalization proof");
                } catch (...) {
                }
            }
            return;
        }
        if (lifecycle_config_generation) {
            auto config_terminal = prepare_config_generation_terminal(
                shutdown
                    ? RuntimeFirewallLifecycleOutcome::shutdown
                    : RuntimeFirewallLifecycleOutcome::not_verified,
                !shutdown);
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_coordinator_terminal();
            if (!proof.has_value()) return;
            (void)runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(config_terminal));
            return;
        }
        if (lifecycle_urltest_generation) {
            auto urltest_terminal = prepare_urltest_generation_terminal(
                shutdown
                    ? RuntimeFirewallLifecycleOutcome::shutdown
                    : RuntimeFirewallLifecycleOutcome::not_verified,
                !shutdown);
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_coordinator_terminal();
            if (!proof.has_value()) return;
            (void)runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(urltest_terminal));
            return;
        }
        if (lifecycle_keenetic_dns_generation) {
            auto dns_terminal = prepare_urltest_generation_terminal(
                shutdown
                    ? RuntimeFirewallLifecycleOutcome::shutdown
                    : RuntimeFirewallLifecycleOutcome::not_verified,
                !shutdown);
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_coordinator_terminal();
            if (!proof.has_value()) return;
            (void)runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(dns_terminal));
            return;
        }
        std::optional<RuntimeFirewallLifecycleTerminal>
            preapply_terminal;
        std::optional<OwnedSnatRecovery>
            preapply_successor_recovery;
        if (lifecycle_preapply) {
            preapply_terminal = prepare_preapply_terminal(
                shutdown
                    ? RuntimeFirewallLifecycleOutcome::shutdown
                    : RuntimeFirewallLifecycleOutcome::not_verified);
            preapply_successor_recovery =
                context->completion.snat_recovery;
        }
        auto preapply_permit = lifecycle_preapply
            ? runtime_firewall_owner_->
                  prepare_preowned_continuation_finalization(context)
            : std::nullopt;
        if (lifecycle_preapply && !preapply_permit.has_value()) return;
        auto proof = drain->finish_coordinator_terminal();
        if (!proof.has_value()) return;
        if (lifecycle_preapply) {
            (void)complete_finalized_preapply(
                std::move(*preapply_permit),
                std::move(*proof),
                std::move(*preapply_terminal),
                std::move(*preapply_successor_recovery));
        } else {
            finish_context();
        }
        return;
    }

    const auto* terminal = drain->worker_terminal();
    if (!terminal) return;
    if (terminal->status ==
        RuntimeFirewallDelayedWorker::TerminalStatus::queued_abandoned) {
        if (!terminal->coordinator_completion.has_value() ||
            !terminal->coordinator_completion->owned) {
            return;
        }
        capture_completion(*terminal->coordinator_completion);
        restore_preworker_control_state();
        finish_preworker_failure_policy();
        if (!shutdown && runtime_firewall_lifecycle_is_start(
                context->lifecycle_kind) &&
            context->successor_mode ==
                RuntimeFirewallOperationContext::SuccessorMode::none) {
            if (begin_runtime_firewall_start_rollback(context)) {
                drain->park_until_wake();
                return;
            }
            if (!finalize_start_broken(
                    "runtime start worker queue was abandoned")) {
                drain->park_until_wake();
                return;
            }
        }
        if (!absorb_retained_mutation_lease()) return;
        if (!settle_immediate_completion(
                shutdown
                    ? RuntimeFirewallImmediateTerminalOutcome::shutdown
                    : RuntimeFirewallImmediateTerminalOutcome::
                          not_verified)) {
            return;
        }
        if (lifecycle_cold_boot) {
            auto cold_boot_terminal = prepare_cold_boot_terminal(
                shutdown
                    ? RuntimeFirewallLifecycleOutcome::shutdown
                    : RuntimeFirewallLifecycleOutcome::not_verified,
                !shutdown);
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_worker_terminal();
            if (!proof.has_value()) return;
            if (!runtime_firewall_owner_->complete_preowned_continuation(
                    std::move(*permit),
                    std::move(*proof),
                    std::move(cold_boot_terminal))) {
                try {
                    Logger::instance().error(
                        "Cold-boot abandoned-worker terminal violated its "
                        "prepared finalization proof");
                } catch (...) {
                }
            }
            return;
        }
        if (lifecycle_config_generation) {
            auto config_terminal = prepare_config_generation_terminal(
                shutdown
                    ? RuntimeFirewallLifecycleOutcome::shutdown
                    : RuntimeFirewallLifecycleOutcome::not_verified,
                !shutdown);
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_worker_terminal();
            if (!proof.has_value()) return;
            (void)runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(config_terminal));
            return;
        }
        if (lifecycle_urltest_generation) {
            auto urltest_terminal = prepare_urltest_generation_terminal(
                shutdown
                    ? RuntimeFirewallLifecycleOutcome::shutdown
                    : RuntimeFirewallLifecycleOutcome::not_verified,
                !shutdown);
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_worker_terminal();
            if (!proof.has_value()) return;
            (void)runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(urltest_terminal));
            return;
        }
        if (lifecycle_keenetic_dns_generation) {
            auto dns_terminal = prepare_urltest_generation_terminal(
                shutdown
                    ? RuntimeFirewallLifecycleOutcome::shutdown
                    : RuntimeFirewallLifecycleOutcome::not_verified,
                !shutdown);
            auto permit = runtime_firewall_owner_->
                prepare_preowned_continuation_finalization(context);
            if (!permit.has_value()) return;
            auto proof = drain->finish_worker_terminal();
            if (!proof.has_value()) return;
            (void)runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(dns_terminal));
            return;
        }
        std::optional<RuntimeFirewallLifecycleTerminal>
            preapply_terminal;
        std::optional<OwnedSnatRecovery>
            preapply_successor_recovery;
        if (lifecycle_preapply) {
            preapply_terminal = prepare_preapply_terminal(
                shutdown
                    ? RuntimeFirewallLifecycleOutcome::shutdown
                    : RuntimeFirewallLifecycleOutcome::not_verified);
            preapply_successor_recovery =
                context->completion.snat_recovery;
        }
        auto preapply_permit = lifecycle_preapply
            ? runtime_firewall_owner_->
                  prepare_preowned_continuation_finalization(context)
            : std::nullopt;
        if (lifecycle_preapply && !preapply_permit.has_value()) return;
        auto proof = drain->finish_worker_terminal();
        if (!proof.has_value()) return;
        if (lifecycle_preapply) {
            (void)complete_finalized_preapply(
                std::move(*preapply_permit),
                std::move(*proof),
                std::move(*preapply_terminal),
                std::move(*preapply_successor_recovery));
        } else {
            finish_context();
        }
        return;
    }

    if (!terminal->running_claim.has_value() ||
        !terminal->mutation_lease) {
        // A bare pre-worker lost_claim waits for the coordinator terminal;
        // try_begin_drain() normally filters it before reaching this branch.
        return;
    }

    // begin_worker() was crossed, so a later application/backend retry starts
    // with a fresh transport budget. Only consecutive pre-worker rejections
    // are bounded by the foreground handoff limit.
    context->foreground_transport_rejections = 0U;
    const RuntimeFirewallWorkerAttemptResult* worker_result =
        terminal->result.get();
    const bool retained_worker_lease =
        terminal->mutation_lease.return_policy ==
        RuntimeFirewallDelayedWorker::MutationLeaseReturnPolicy::
            return_to_operation_owner;
    if (lifecycle_preapply) {
        if (!state.core_publication.prepared) {
            DaemonRuntimeFirewallOperationState::CorePublication publication;
            OwnedSnatRecovery processed_recovery =
                context->submitted_snat_recovery;
            processed_recovery.requested = true;
            const bool result_valid =
                terminal->status ==
                    RuntimeFirewallDelayedWorker::TerminalStatus::result &&
                worker_result != nullptr && context->worker_input &&
                worker_result->operation_kind ==
                    RuntimeFirewallWorkerOperationKind::config_preapply &&
                context->worker_input->operation_kind ==
                    RuntimeFirewallWorkerOperationKind::config_preapply &&
                worker_result->transaction.operation_serial ==
                    context->queued_claim.serial &&
                worker_result->transaction.runtime_generation ==
                    context->queued_claim.runtime_generation &&
                context->worker_input->transaction.operation_serial ==
                    context->queued_claim.serial &&
                context->worker_input->transaction.runtime_generation ==
                    context->queued_claim.runtime_generation;
            const bool current_generation =
                runtime_firewall_lifecycle_generation_is_current(
                    context->lifecycle_kind,
                    context->queued_claim.runtime_generation);
            const bool commit_ambiguous = !result_valid ||
                (worker_result->transaction.commit_entered &&
                 !worker_result->transaction.committed());
            const bool committed = result_valid &&
                worker_result->transaction.committed();
            const bool verified = result_valid && current_generation &&
                !shutdown && worker_result->config_preapply_verified();

            OwnedSnatState inspected_after = OwnedSnatState::unknown;
            if (result_valid) {
                OwnedSnatState inspected_before = OwnedSnatState::unknown;
                if (worker_result->owned_snat_before.state.has_value() &&
                    !worker_result->owned_snat_before.failure.failed()) {
                    inspected_before =
                        *worker_result->owned_snat_before.state;
                }
                processed_recovery = observe_owned_snat_state(
                    std::move(processed_recovery),
                    inspected_before,
                    inspected_before == OwnedSnatState::missing
                        ? worker_result
                              ->pre_mutation_owned_conntrack_cleanup_snapshot
                        : std::nullopt);
                if (worker_result->owned_snat_after.state.has_value() &&
                    !worker_result->owned_snat_after.failure.failed()) {
                    inspected_after =
                        *worker_result->owned_snat_after.state;
                }
                processed_recovery = observe_owned_snat_state(
                    std::move(processed_recovery), inspected_after);

                const auto& cleanup =
                    worker_result->post_commit_owned_conntrack_cleanup;
                if (cleanup.attempted && cleanup.snapshot.has_value()) {
                    auto remaining = cleanup.summary.remaining_marks;
                    const bool cleanup_incomplete =
                        cleanup.failure.failed() ||
                        cleanup.summary.command_unavailable ||
                        cleanup.summary.failed != 0U ||
                        cleanup.summary.skipped != 0U;
                    if (cleanup_incomplete && remaining.empty()) {
                        remaining = ordered_owned_conntrack_marks(
                            *cleanup.snapshot);
                    }
                    if (remaining.empty() && !cleanup_incomplete) {
                        processed_recovery.cleanup_snapshot.reset();
                    } else if (!remaining.empty()) {
                        processed_recovery.cleanup_snapshot =
                            restrict_owned_conntrack_cleanup_snapshot(
                                *cleanup.snapshot, remaining);
                        processed_recovery.requested = true;
                    }
                }
            }

            std::string failure_detail;
            if (!verified) {
                if (!result_valid) {
                    failure_detail =
                        "configuration pre-apply returned no exact typed "
                        "worker result";
                } else if (worker_result->transaction.failure.has_value()) {
                    failure_detail =
                        worker_result->transaction.failure->message;
                } else if (
                    worker_result->owned_snat_before.failure.failed()) {
                    failure_detail =
                        worker_result->owned_snat_before.failure.message;
                } else if (
                    worker_result->owned_snat_after.failure.failed()) {
                    failure_detail =
                        worker_result->owned_snat_after.failure.message;
                } else if (!worker_result->exact_cleanup_authority_valid) {
                    failure_detail =
                        "configuration pre-apply exact cleanup authority "
                        "was not verified";
                } else if (committed) {
                    failure_detail =
                        "configuration pre-apply committed a repair but its "
                        "post-commit verification did not complete";
                } else if (commit_ambiguous) {
                    failure_detail =
                        "configuration pre-apply firewall COMMIT outcome is "
                        "ambiguous";
                } else if (worker_result
                               ->post_commit_owned_conntrack_cleanup
                               .attempted) {
                    failure_detail =
                        "configuration pre-apply exact conntrack cleanup "
                        "remains incomplete";
                } else if (!current_generation) {
                    failure_detail =
                        "configuration pre-apply generation became stale";
                } else {
                    failure_detail =
                        "configuration pre-apply did not reach a verified "
                        "terminal";
                }
            }

            const bool retry = !verified && !commit_ambiguous &&
                current_generation && !shutdown &&
                runtime_firewall_start_retry_available(
                    context->queued_claim.attempt);
            state.worker_failure_detail = std::move(failure_detail);
            publication.prepared = true;
            publication.committed = committed;
            state.core_publication = std::move(publication);
            state.processed_snat_recovery =
                std::move(processed_recovery);
            state.inspected_snat_after = inspected_after;
            state.worker_result_valid = result_valid;
            state.worker_failure_transient = retry;
            state.lifecycle_resolver_verified = true;
            context->worker_succeeded = verified;
            context->worker_commit_ambiguous = commit_ambiguous;
            context->preapply_commit_observed =
                context->preapply_commit_observed || committed;
            context->successor_mode = retry
                ? RuntimeFirewallOperationContext::SuccessorMode::
                      reschedule_retry
                : RuntimeFirewallOperationContext::SuccessorMode::none;
            state.suppress_coordinator_rerun = true;
        }

        if (!drain->begin_worker_control(runtime_firewall_retry_)) return;
        if (!drain->publish_worker_control([]() noexcept { return true; })) {
            return;
        }
        if (!state.processed_snat_recovery.has_value()) {
            state.processed_snat_recovery =
                context->submitted_snat_recovery;
        }
        if (!drain->complete_worker_control(
                runtime_firewall_retry_,
                !shutdown && context->worker_succeeded,
                *state.processed_snat_recovery)) {
            return;
        }
        const auto* completion = drain->worker_control_completion();
        if (!completion || !completion->owned) return;
        capture_completion(*completion);
        if (!retained_worker_lease ||
            !absorb_retained_mutation_lease()) {
            return;
        }
        if (!settle_immediate_completion(
                shutdown
                    ? RuntimeFirewallImmediateTerminalOutcome::shutdown
                    : (context->worker_succeeded
                           ? RuntimeFirewallImmediateTerminalOutcome::
                                 verified_success
                           : RuntimeFirewallImmediateTerminalOutcome::
                                 not_verified))) {
            return;
        }

        auto preapply_terminal = prepare_preapply_terminal(
            shutdown
                ? RuntimeFirewallLifecycleOutcome::shutdown
                : (context->worker_succeeded
                       ? RuntimeFirewallLifecycleOutcome::verified_success
                       : RuntimeFirewallLifecycleOutcome::not_verified));
        auto preapply_successor_recovery =
            context->completion.snat_recovery;
        auto preapply_permit = runtime_firewall_owner_->
            prepare_preowned_continuation_finalization(context);
        if (!preapply_permit.has_value()) return;
        auto proof = drain->finish_worker_terminal();
        if (!proof.has_value()) return;
        (void)complete_finalized_preapply(
            std::move(*preapply_permit),
            std::move(*proof),
            std::move(preapply_terminal),
            std::move(preapply_successor_recovery));
        return;
    }
    if (!state.core_publication.prepared) {
        DaemonRuntimeFirewallOperationState::CorePublication publication;
        std::optional<MetaUdp443ActivationPlan> candidate_meta_plan;
        OwnedSnatRecovery processed_recovery =
            context->submitted_snat_recovery;
        OwnedSnatState inspected_snat_after = OwnedSnatState::unknown;
        bool result_valid =
            terminal->status ==
                RuntimeFirewallDelayedWorker::TerminalStatus::result &&
            worker_result != nullptr &&
            context->worker_input &&
            worker_result->operation_kind ==
                context->worker_input->operation_kind &&
            worker_result->transaction.operation_serial ==
                context->queued_claim.serial &&
            worker_result->transaction.runtime_generation ==
                context->queued_claim.runtime_generation &&
            context->worker_input->transaction.operation_serial ==
                context->queued_claim.serial &&
            context->worker_input->transaction.runtime_generation ==
                context->queued_claim.runtime_generation;
        const bool current_generation =
            runtime_firewall_lifecycle_generation_is_current(
                context->lifecycle_kind,
                context->queued_claim.runtime_generation);

        bool commit_ambiguous =
            terminal->status !=
                RuntimeFirewallDelayedWorker::TerminalStatus::result ||
            worker_result == nullptr;
        bool transient_failure = !result_valid;
        std::string failure_detail;
        if (terminal->status ==
                RuntimeFirewallDelayedWorker::TerminalStatus::exception &&
            terminal->exception) {
            try {
                std::rethrow_exception(terminal->exception);
            } catch (const std::exception& error) {
                failure_detail = error.what();
            } catch (...) {
                failure_detail =
                    "runtime firewall worker threw a non-standard exception";
            }
        } else if (terminal->status ==
                   RuntimeFirewallDelayedWorker::TerminalStatus::
                       missing_result) {
            failure_detail =
                "runtime firewall worker returned no terminal result";
        } else if (terminal->status ==
                   RuntimeFirewallDelayedWorker::TerminalStatus::lost_claim) {
            failure_detail =
                "runtime firewall worker lost its exact operation claim";
        } else if (!result_valid) {
            failure_detail =
                "runtime firewall worker returned mismatched operation "
                "identity";
        }

        if (result_valid) {
            commit_ambiguous =
                worker_result->transaction.commit_entered &&
                !worker_result->transaction.committed();
            const auto& route_preparation =
                worker_result->route_preparation;
            if (route_preparation.required &&
                (!route_preparation.observation_succeeded ||
                 !route_preparation.worker_mutation_ack.has_value() ||
                 *route_preparation.worker_mutation_ack !=
                     RuntimeRouteMutationAck::applied ||
                 !route_preparation.checkpoint_published ||
                 !route_preparation.mutation_ack.has_value() ||
                 *route_preparation.mutation_ack !=
                     RuntimeRouteMutationAck::applied)) {
                // Route observation/mutation is a pre-COMMIT admission
                // boundary. It is never ambiguous and must not permit the
                // firewall transaction to run against an unacknowledged
                // desired route generation.
                commit_ambiguous = false;
                if (!route_preparation.observation_succeeded) {
                    transient_failure = true;
                    failure_detail =
                        route_preparation.observation_failure.detail;
                    if (failure_detail.empty()) {
                        failure_detail =
                            "runtime route observation did not complete";
                    }
                } else if (
                    !route_preparation.worker_mutation_ack.has_value()) {
                    transient_failure = true;
                    failure_detail =
                        "runtime route plan did not enter its combined "
                        "worker owner";
                } else if (
                    *route_preparation.worker_mutation_ack !=
                        RuntimeRouteMutationAck::applied) {
                    failure_detail =
                        route_preparation.worker_mutation_failure_detail;
                    switch (*route_preparation.worker_mutation_ack) {
                    case RuntimeRouteMutationAck::applied:
                        break;
                    case RuntimeRouteMutationAck::stale:
                        transient_failure = true;
                        if (failure_detail.empty()) {
                            failure_detail =
                                "runtime route observation became stale "
                                "before worker mutation";
                        }
                        break;
                    case RuntimeRouteMutationAck::route_unavailable:
                        transient_failure = false;
                        if (failure_detail.empty()) {
                            failure_detail =
                                "runtime route interface is unavailable";
                        }
                        break;
                    case RuntimeRouteMutationAck::mutation_failed:
                        transient_failure = false;
                        if (failure_detail.empty()) {
                            failure_detail =
                                "runtime route worker mutation failed";
                        }
                        break;
                    case RuntimeRouteMutationAck::shutdown:
                        transient_failure = false;
                        if (failure_detail.empty()) {
                            failure_detail =
                                "runtime route mutation stopped during "
                                "shutdown";
                        }
                        break;
                    }
                } else if (!route_preparation.checkpoint_published) {
                    transient_failure = true;
                    failure_detail =
                        "runtime route result could not enter its control "
                        "publication checkpoint";
                } else if (!route_preparation.mutation_ack.has_value()) {
                    transient_failure = true;
                    failure_detail =
                        "runtime route checkpoint returned no acknowledgement";
                } else {
                    switch (*route_preparation.mutation_ack) {
                    case RuntimeRouteMutationAck::applied:
                        break;
                    case RuntimeRouteMutationAck::stale:
                        transient_failure = true;
                        failure_detail =
                            "runtime route observation became stale before "
                            "publication";
                        break;
                    case RuntimeRouteMutationAck::route_unavailable:
                        transient_failure = false;
                        failure_detail =
                            "runtime route publication reported an "
                            "unexpected interface failure";
                        break;
                    case RuntimeRouteMutationAck::mutation_failed:
                        transient_failure = false;
                        failure_detail =
                            "runtime route publication failed";
                        break;
                    case RuntimeRouteMutationAck::shutdown:
                        transient_failure = false;
                        failure_detail =
                            "runtime route publication stopped during "
                            "shutdown";
                        break;
                    }
                }
            } else if (worker_result->transaction.failure.has_value()) {
                failure_detail =
                    worker_result->transaction.failure->message;
                transient_failure =
                    worker_result->transaction.failure->kind ==
                    RuntimeFirewallBackendFailureKind::transient_firewall;
            } else if (!worker_result->transaction_executed) {
                transient_failure = true;
                if (worker_result->owned_snat_before.failure.failed()) {
                    failure_detail =
                        worker_result->owned_snat_before.failure.message;
                } else {
                    failure_detail =
                        "runtime firewall backend transaction was not "
                        "admitted after its required observation";
                }
            }
        }

        const bool committed_candidate =
            result_valid && current_generation && !shutdown &&
            worker_result->transaction.committed();
        if (committed_candidate) {
            const auto& committed =
                *worker_result->transaction.committed_firewall;
            publication.rules = committed.rule_states;
            publication.list_content_state =
                committed.list_content_state;
            publication.list_usage = committed.list_usage;
            publication.list_fingerprints =
                context->worker_input->transaction
                    .requested_list_fingerprints;
            publication.internal_vpn_servers =
                state.internal_vpn_resolution.effective_servers;
            publication.internal_vpn_service_targets =
                state.internal_vpn_service_resolution.effective_targets;
            publication.native_vpn_direct_egress_snat_selectors =
                context->worker_input->transaction
                    .candidate_native_vpn_direct_egress_snat_selectors;
            candidate_meta_plan =
                worker_result->transaction.meta_activation_plan;
            if (candidate_meta_plan.has_value()) {
                publication.committed_meta_fwmark =
                    candidate_meta_plan->expected_fwmark;
                publication.committed_meta_owned_mask =
                    candidate_meta_plan->owned_mask;
            }
            publication.committed = true;
        }

        bool snat_healthy = true;
        if (processed_recovery.requested) {
            OwnedSnatState before = OwnedSnatState::unknown;
            if (result_valid &&
                worker_result->owned_snat_before.state.has_value() &&
                !worker_result->owned_snat_before.failure.failed()) {
                before = *worker_result->owned_snat_before.state;
            }
            std::optional<OwnedConntrackCleanupSnapshot> exact_snapshot;
            if (before == OwnedSnatState::missing && result_valid &&
                worker_result
                    ->pre_mutation_owned_conntrack_cleanup_snapshot
                    .has_value() &&
                worker_result
                    ->pre_mutation_owned_conntrack_cleanup_snapshot
                    ->valid() &&
                worker_result
                    ->pre_mutation_owned_conntrack_cleanup_snapshot
                    ->runtime_generation ==
                    context->queued_claim.runtime_generation) {
                exact_snapshot = worker_result
                    ->pre_mutation_owned_conntrack_cleanup_snapshot;
            }
            processed_recovery = observe_owned_snat_state(
                std::move(processed_recovery),
                before,
                std::move(exact_snapshot));

            if (result_valid &&
                worker_result->owned_snat_after.state.has_value() &&
                !worker_result->owned_snat_after.failure.failed()) {
                inspected_snat_after =
                    *worker_result->owned_snat_after.state;
            }
            processed_recovery = observe_owned_snat_state(
                std::move(processed_recovery),
                inspected_snat_after);
            snat_healthy =
                inspected_snat_after == OwnedSnatState::healthy;
            if (!snat_healthy) {
                transient_failure = true;
                if (failure_detail.empty()) {
                    failure_detail =
                        "tunnel SNAT scaffold was not healthy after the "
                        "runtime firewall transaction";
                }
            }
        }

        const bool worker_succeeded =
            publication.committed && snat_healthy;
        if (!worker_succeeded && failure_detail.empty()) {
            failure_detail = commit_ambiguous
                ? "runtime firewall COMMIT outcome is ambiguous"
                : "runtime firewall transaction did not commit";
        }

        const bool lifecycle_start =
            runtime_firewall_lifecycle_uses_start_pipeline(
                context->lifecycle_kind);
        bool route_preimage_certainly_retained = false;
        if (result_valid && worker_result) {
            const auto& route = worker_result->route_preparation;
            if (!route.required || !route.observation_succeeded) {
                route_preimage_certainly_retained = true;
            } else if (route.worker_mutation_ack.has_value()) {
                route_preimage_certainly_retained =
                    *route.worker_mutation_ack ==
                        RuntimeRouteMutationAck::stale ||
                    *route.worker_mutation_ack ==
                        RuntimeRouteMutationAck::route_unavailable;
            }
        }
        const bool retryable_failure = lifecycle_start
            ? transient_failure
            : (transient_failure ||
               processed_recovery.requested ||
               (context->worker_input &&
                config_has_native_vpn_catalog_policy(
                    context->worker_input->transaction.config)) ||
               urltest_after_firewall_gate_.waiting_for(
                   context->queued_claim.runtime_generation));
        const bool retry_budget_available =
            runtime_firewall_start_retry_available(
                context->queued_claim.attempt);
        const auto cold_budget_after_body =
            plan_runtime_cold_boot_candidate_budget(
                lifecycle_cold_boot && state.cold_boot_transaction
                    ? std::max(
                          state.cold_boot_transaction
                              ->completed_candidate_bodies,
                          context->queued_claim.attempt + 1U)
                    : 0U,
                kRuntimeFirewallStartBoundedRetryCount);
        const bool cold_retry_budget_available =
            cold_budget_after_body.dispatch !=
            RuntimeColdBootCandidateBudgetDispatch::exhausted;
        const bool cold_same_context_retry = lifecycle_cold_boot &&
            runtime_cold_boot_same_context_retry_allowed(
                transient_failure,
                publication.committed ||
                    context->preapply_commit_observed,
                commit_ambiguous,
                route_preimage_certainly_retained,
                cold_retry_budget_available);
        const bool bounded_retry_required =
            !lifecycle_config_generation &&
            !lifecycle_urltest_generation &&
            !lifecycle_keenetic_dns_generation &&
            !worker_succeeded &&
            !commit_ambiguous &&
            retryable_failure &&
            (lifecycle_cold_boot
                 ? cold_same_context_retry
                 : (!lifecycle_start || retry_budget_available));

        // The target GCC 8 old-string ABI does not promise nothrow move
        // assignment. Commit that sole fallible context field while the
        // checkpoint is still visibly unprepared. If it throws, the drain
        // guard re-arms and the complete local preparation is recomputed.
        state.worker_failure_detail = std::move(failure_detail);

        // Every context write below is covered by the static nothrow contract
        // above or is scalar. Publish prepared=true only inside this tail so a
        // retry can never observe a partially committed core checkpoint.
        publication.prepared = true;
        state.core_publication = std::move(publication);
        context->preapply_commit_observed =
            context->preapply_commit_observed ||
            state.core_publication.committed;
        if (lifecycle_cold_boot && state.cold_boot_transaction) {
            state.cold_boot_transaction->completed_candidate_bodies =
                std::max(
                    state.cold_boot_transaction->completed_candidate_bodies,
                    context->queued_claim.attempt + 1U);
        }
        state.candidate_meta_activation_plan =
            std::move(candidate_meta_plan);
        state.processed_snat_recovery =
            std::move(processed_recovery);
        state.inspected_snat_after = inspected_snat_after;
        context->worker_succeeded = worker_succeeded;
        state.worker_result_valid = result_valid;
        context->worker_commit_ambiguous = commit_ambiguous;
        state.worker_failure_transient = transient_failure;
        context->successor_mode = bounded_retry_required
            ? RuntimeFirewallOperationContext::SuccessorMode::
                  reschedule_retry
            : RuntimeFirewallOperationContext::SuccessorMode::none;
    }

    if (lifecycle_keenetic_dns_generation) {
        if (!drain->begin_worker_control(runtime_firewall_retry_)) return;
        // The DNS/firewall candidate remains private until the exact resolver
        // stream has published the matching generation.
        if (!drain->publish_worker_control(
                []() noexcept { return true; })) {
            return;
        }

        auto transaction = state.keenetic_dns_refresh_transaction;
        const bool candidate_phase =
            runtime_firewall_lifecycle_is_keenetic_dns_candidate(
                context->lifecycle_kind);
        const bool exact_generation =
            runtime_generation_.load(std::memory_order_acquire) ==
                context->queued_claim.runtime_generation;
        const bool exact_route_checkpoint =
            context->worker_input && worker_result &&
            context->worker_input->route_health_request.route_epoch != 0U &&
            routing_observation_epoch_.load(std::memory_order_acquire) ==
                context->worker_input->route_health_request.route_epoch &&
            worker_result->route_preparation.required &&
            worker_result->route_preparation.worker_mutation_ack ==
                std::optional<RuntimeRouteMutationAck>{
                    RuntimeRouteMutationAck::applied} &&
            worker_result->route_preparation.checkpoint_published &&
            worker_result->route_preparation.mutation_ack ==
                std::optional<RuntimeRouteMutationAck>{
                    RuntimeRouteMutationAck::applied};
        const bool route_firewall_commit_proven =
            transaction && !shutdown && exact_generation &&
            exact_route_checkpoint && context->worker_succeeded &&
            !context->worker_commit_ambiguous;
        if (transaction && candidate_phase) {
            transaction->candidate_route_firewall_commit_proven =
                route_firewall_commit_proven;
            transaction->candidate_exact_rollback_available =
                !shutdown && exact_generation &&
                exact_route_checkpoint &&
                !context->worker_commit_ambiguous;
        }

        if (!shutdown && context->worker_succeeded &&
            !state.publication_tail.resolver_tail_finished()) {
            const bool resolver_admitted = transaction &&
                transaction->terminal_orchestrator
                    .admit_resolver_stream_after_firewall(
                        route_firewall_commit_proven,
                        transaction->mutation_lease_token);
            if (resolver_admitted &&
                begin_runtime_firewall_lifecycle_resolver(context)) {
                drain->park_until_wake();
                return;
            }
            state.publication_tail.mark_resolver_tail_finished();
            const bool resolver_terminal_accepted =
                resolver_admitted &&
                transaction->terminal_orchestrator
                    .observe_resolver_stream_terminal(
                        state.lifecycle_resolver_verified,
                        transaction->mutation_lease_token);
            if (!resolver_terminal_accepted ||
                !state.lifecycle_resolver_verified) {
                context->worker_succeeded = false;
                state.worker_failure_transient = false;
                if (state.worker_failure_detail.empty()) {
                    state.worker_failure_detail =
                        !resolver_admitted
                        ? "Keenetic DNS route/firewall COMMIT proof was not "
                          "available before resolver publication"
                        : (state.lifecycle_failure_detail.empty()
                               ? "Keenetic DNS resolver stream was not "
                                 "verified"
                               : state.lifecycle_failure_detail);
                }
            }
        } else if (!context->worker_succeeded) {
            state.lifecycle_resolver_verified = false;
            state.publication_tail.mark_resolver_tail_finished();
        }
        const bool verified = !shutdown && exact_generation &&
            exact_route_checkpoint && context->worker_succeeded &&
            state.lifecycle_resolver_verified;

        bool route_preimage_certainly_retained = false;
        if (state.worker_result_valid && worker_result) {
            const auto& route = worker_result->route_preparation;
            if (!route.required || !route.observation_succeeded) {
                route_preimage_certainly_retained = true;
            } else if (route.worker_mutation_ack.has_value()) {
                route_preimage_certainly_retained =
                    *route.worker_mutation_ack ==
                        RuntimeRouteMutationAck::stale ||
                    *route.worker_mutation_ack ==
                        RuntimeRouteMutationAck::route_unavailable;
            }
        }
        const bool previous_generation_certainly_retained =
            state.worker_result_valid && worker_result &&
            worker_result->previous_generation_certainly_retained() &&
            route_preimage_certainly_retained;

        if (transaction && candidate_phase) {
            transaction->candidate_firewall_preimage_is_base =
                !state.core_publication.committed &&
                !context->worker_commit_ambiguous &&
                previous_generation_certainly_retained;
        }
        if (transaction && state.core_publication.committed) {
            auto& retained_publication = candidate_phase
                ? transaction->candidate_core_publication
                : transaction->rollback_core_publication;
            bool& retained_ready = candidate_phase
                ? transaction->candidate_core_publication_ready
                : transaction->rollback_core_publication_ready;
            if (!retained_ready) {
                retained_publication = std::move(state.core_publication);
                state.core_publication.prepared = true;
                state.core_publication.committed = true;
                auto& retained_meta_plan = candidate_phase
                    ? transaction->candidate_meta_activation_plan
                    : transaction->rollback_meta_activation_plan;
                retained_meta_plan =
                    std::move(state.candidate_meta_activation_plan);
                const bool filter_healthy = worker_result &&
                    worker_result->forward_udp_reject_after_commit.state ==
                        std::optional<OwnedForwardUdpRejectState>{
                            OwnedForwardUdpRejectState::healthy} &&
                    !worker_result->forward_udp_reject_after_commit
                         .failure.failed();
                const bool fastnat_healthy =
                    !retained_meta_plan.has_value() ||
                    (worker_result &&
                     worker_result->fastnat_after_commit
                             .disabled_or_unavailable ==
                         std::optional<bool>{true} &&
                     !worker_result->fastnat_after_commit.failure.failed());
                if (candidate_phase) {
                    transaction->candidate_meta_filter_healthy =
                        filter_healthy;
                    transaction->candidate_meta_fastnat_healthy =
                        fastnat_healthy;
                } else {
                    transaction->rollback_meta_filter_healthy =
                        filter_healthy;
                    transaction->rollback_meta_fastnat_healthy =
                        fastnat_healthy;
                }
                retained_ready = true;
            }
        }

        context->successor_mode =
            RuntimeFirewallOperationContext::SuccessorMode::none;
        state.suppress_coordinator_rerun = true;
        OwnedSnatRecovery no_dns_cleanup;
        if (!drain->complete_worker_control(
                runtime_firewall_retry_, verified, no_dns_cleanup)) {
            return;
        }
        const auto* completion = drain->worker_control_completion();
        if (!completion || !completion->owned) return;
        capture_completion(*completion);
        context->force_successor = false;
        if (!retained_worker_lease ||
            !absorb_retained_mutation_lease()) {
            return;
        }
        if (!settle_immediate_completion(
                shutdown
                    ? RuntimeFirewallImmediateTerminalOutcome::shutdown
                    : (verified
                           ? RuntimeFirewallImmediateTerminalOutcome::
                                 verified_success
                           : RuntimeFirewallImmediateTerminalOutcome::
                                 not_verified))) {
            return;
        }

        auto dns_terminal = prepare_urltest_generation_terminal(
            shutdown
                ? RuntimeFirewallLifecycleOutcome::shutdown
                : (verified
                       ? RuntimeFirewallLifecycleOutcome::verified_success
                       : RuntimeFirewallLifecycleOutcome::not_verified),
            previous_generation_certainly_retained);
        if (verified) {
            dns_terminal.committed = true;
            dns_terminal.commit_ambiguous = false;
        }
        auto permit = runtime_firewall_owner_->
            prepare_preowned_continuation_finalization(context);
        if (!permit.has_value()) return;
        auto proof = drain->finish_worker_terminal();
        if (!proof.has_value()) return;
        (void)runtime_firewall_owner_->complete_preowned_continuation(
            std::move(*permit),
            std::move(*proof),
            std::move(dns_terminal));
        return;
    }

    if (lifecycle_urltest_generation) {
        if (!drain->begin_worker_control(runtime_firewall_retry_)) return;
        // Route and firewall candidates stay private until the exact terminal
        // continuation publishes both selection cursors together.
        if (!drain->publish_worker_control(
                []() noexcept { return true; })) {
            return;
        }

        const bool exact_generation =
            runtime_generation_.load(std::memory_order_acquire) ==
                context->queued_claim.runtime_generation;
        const bool exact_route_checkpoint =
            context->worker_input && worker_result &&
            context->worker_input->route_health_request.route_epoch != 0U &&
            routing_observation_epoch_.load(std::memory_order_acquire) ==
                context->worker_input->route_health_request.route_epoch &&
            worker_result->route_preparation.required &&
            worker_result->route_preparation.worker_mutation_ack ==
                std::optional<RuntimeRouteMutationAck>{
                    RuntimeRouteMutationAck::applied} &&
            worker_result->route_preparation.checkpoint_published &&
            worker_result->route_preparation.mutation_ack ==
                std::optional<RuntimeRouteMutationAck>{
                    RuntimeRouteMutationAck::applied};
        const bool verified = !shutdown && exact_generation &&
            exact_route_checkpoint && context->worker_succeeded;

        bool route_preimage_certainly_retained = false;
        if (state.worker_result_valid && worker_result) {
            const auto& route = worker_result->route_preparation;
            if (!route.required || !route.observation_succeeded) {
                route_preimage_certainly_retained = true;
            } else if (route.worker_mutation_ack.has_value()) {
                route_preimage_certainly_retained =
                    *route.worker_mutation_ack ==
                        RuntimeRouteMutationAck::stale ||
                    *route.worker_mutation_ack ==
                        RuntimeRouteMutationAck::route_unavailable;
            }
        }
        const bool previous_generation_certainly_retained =
            state.worker_result_valid && worker_result &&
            worker_result->previous_generation_certainly_retained() &&
            route_preimage_certainly_retained;

        auto transaction = state.urltest_selection_transaction;
        if (transaction && state.core_publication.committed) {
            const bool candidate_phase =
                runtime_firewall_lifecycle_is_urltest_candidate(
                    context->lifecycle_kind);
            auto& retained_publication = candidate_phase
                ? transaction->candidate_core_publication
                : transaction->rollback_core_publication;
            bool& retained_ready = candidate_phase
                ? transaction->candidate_core_publication_ready
                : transaction->rollback_core_publication_ready;
            if (!retained_ready) {
                retained_publication = std::move(state.core_publication);
                // Preserve terminal evidence after moving the realized core.
                state.core_publication.prepared = true;
                state.core_publication.committed = true;
                auto& retained_meta_plan = candidate_phase
                    ? transaction->candidate_meta_activation_plan
                    : transaction->rollback_meta_activation_plan;
                retained_meta_plan =
                    std::move(state.candidate_meta_activation_plan);
                const bool filter_healthy = worker_result &&
                    worker_result->forward_udp_reject_after_commit.state ==
                        std::optional<OwnedForwardUdpRejectState>{
                            OwnedForwardUdpRejectState::healthy} &&
                    !worker_result->forward_udp_reject_after_commit
                         .failure.failed();
                const bool fastnat_healthy =
                    !retained_meta_plan.has_value() ||
                    (worker_result &&
                     worker_result->fastnat_after_commit
                             .disabled_or_unavailable ==
                         std::optional<bool>{true} &&
                     !worker_result->fastnat_after_commit.failure.failed());
                if (candidate_phase) {
                    transaction->candidate_meta_filter_healthy =
                        filter_healthy;
                    transaction->candidate_meta_fastnat_healthy =
                        fastnat_healthy;
                } else {
                    transaction->rollback_meta_filter_healthy =
                        filter_healthy;
                    transaction->rollback_meta_fastnat_healthy =
                        fastnat_healthy;
                }
                retained_ready = true;
            }
        }

        context->successor_mode =
            RuntimeFirewallOperationContext::SuccessorMode::none;
        state.suppress_coordinator_rerun = true;
        OwnedSnatRecovery no_urltest_cleanup;
        if (!drain->complete_worker_control(
                runtime_firewall_retry_, verified, no_urltest_cleanup)) {
            return;
        }
        const auto* completion = drain->worker_control_completion();
        if (!completion || !completion->owned) return;
        capture_completion(*completion);
        context->force_successor = false;
        if (!retained_worker_lease ||
            !absorb_retained_mutation_lease()) {
            return;
        }
        if (!settle_immediate_completion(
                shutdown
                    ? RuntimeFirewallImmediateTerminalOutcome::shutdown
                    : (verified
                           ? RuntimeFirewallImmediateTerminalOutcome::
                                 verified_success
                           : RuntimeFirewallImmediateTerminalOutcome::
                                 not_verified))) {
            return;
        }

        auto urltest_terminal = prepare_urltest_generation_terminal(
            shutdown
                ? RuntimeFirewallLifecycleOutcome::shutdown
                : (verified
                       ? RuntimeFirewallLifecycleOutcome::verified_success
                       : RuntimeFirewallLifecycleOutcome::not_verified),
            previous_generation_certainly_retained);
        auto permit = runtime_firewall_owner_->
            prepare_preowned_continuation_finalization(context);
        if (!permit.has_value()) return;
        auto proof = drain->finish_worker_terminal();
        if (!proof.has_value()) return;
        (void)runtime_firewall_owner_->complete_preowned_continuation(
            std::move(*permit),
            std::move(*proof),
            std::move(urltest_terminal));
        return;
    }

    if (lifecycle_config_generation) {
        if (!drain->begin_worker_control(runtime_firewall_retry_)) return;
        // Route and firewall have converged, but their candidate remains
        // private. The control publication callback is deliberately empty;
        // candidate core/config/resolver cursors are swapped only after the
        // exact resolver stream below succeeds.
        if (!drain->publish_worker_control(
                []() noexcept { return true; })) {
            return;
        }

        if (!shutdown && context->worker_succeeded &&
            !state.publication_tail.resolver_tail_finished()) {
            if (begin_runtime_firewall_lifecycle_resolver(context)) {
                drain->park_until_wake();
                return;
            }
            state.publication_tail.mark_resolver_tail_finished();
            if (!state.lifecycle_resolver_verified) {
                context->worker_succeeded = false;
                state.worker_failure_transient = false;
                if (state.worker_failure_detail.empty()) {
                    state.worker_failure_detail =
                        state.lifecycle_failure_detail.empty()
                        ? "configuration resolver stream was not verified"
                        : state.lifecycle_failure_detail;
                }
            }
        } else if (!context->worker_succeeded) {
            state.lifecycle_resolver_verified = false;
            state.publication_tail.mark_resolver_tail_finished();
        }

        const bool exact_generation =
            runtime_generation_.load(std::memory_order_acquire) ==
                context->queued_claim.runtime_generation;
        const bool exact_route_checkpoint =
            context->worker_input && worker_result &&
            context->worker_input->route_health_request.route_epoch != 0U &&
            routing_observation_epoch_.load(std::memory_order_acquire) ==
                context->worker_input->route_health_request.route_epoch &&
            worker_result->route_preparation.required &&
            worker_result->route_preparation.worker_mutation_ack ==
                std::optional<RuntimeRouteMutationAck>{
                    RuntimeRouteMutationAck::applied} &&
            worker_result->route_preparation.checkpoint_published &&
            worker_result->route_preparation.mutation_ack ==
                std::optional<RuntimeRouteMutationAck>{
                    RuntimeRouteMutationAck::applied};
        const bool verified = !shutdown && exact_generation &&
            exact_route_checkpoint &&
            context->worker_succeeded &&
            state.lifecycle_resolver_verified;
        if (!verified && context->worker_succeeded &&
            state.lifecycle_resolver_verified &&
            !exact_route_checkpoint &&
            state.worker_failure_detail.empty()) {
            try {
                state.worker_failure_detail =
                    "configuration route observation changed before "
                    "candidate publication";
            } catch (...) {
            }
        }
        context->successor_mode =
            RuntimeFirewallOperationContext::SuccessorMode::none;
        state.suppress_coordinator_rerun = true;

        if (runtime_firewall_lifecycle_is_config_candidate(
                context->lifecycle_kind) &&
            state.config_generation_transaction) {
            state.config_generation_transaction
                ->candidate_firewall_preimage_is_base =
                    !state.core_publication.committed &&
                    !context->worker_commit_ambiguous;
        }
        if (runtime_firewall_lifecycle_is_config_candidate(
                context->lifecycle_kind) &&
            state.config_generation_transaction &&
            state.core_publication.committed &&
            !state.config_generation_transaction
                 ->candidate_core_publication_ready) {
            auto& transaction =
                *state.config_generation_transaction;
            transaction.candidate_core_publication =
                std::move(state.core_publication);
            // Terminal evidence still has to report that the private
            // candidate entered COMMIT even though its realized core is now
            // retained by the transaction for publication or exact rollback.
            state.core_publication.prepared = true;
            state.core_publication.committed = true;
            transaction.candidate_meta_activation_plan =
                std::move(state.candidate_meta_activation_plan);
            transaction.candidate_meta_filter_healthy =
                    worker_result->forward_udp_reject_after_commit.state ==
                        std::optional<OwnedForwardUdpRejectState>{
                            OwnedForwardUdpRejectState::healthy} &&
                    !worker_result->forward_udp_reject_after_commit
                         .failure.failed();
            transaction.candidate_meta_fastnat_healthy =
                    !transaction.candidate_meta_activation_plan.has_value() ||
                    (worker_result->fastnat_after_commit
                             .disabled_or_unavailable ==
                         std::optional<bool>{true} &&
                     !worker_result->fastnat_after_commit.failure.failed());
            transaction.candidate_core_publication_ready = true;
        }

        if (verified && context->lifecycle_kind ==
                RuntimeFirewallLifecycleKind::config_rollback &&
            state.config_generation_transaction &&
            state.core_publication.committed) {
            auto& transaction =
                *state.config_generation_transaction;
            transaction.rollback_meta_activation_plan =
                std::move(state.candidate_meta_activation_plan);
            transaction.rollback_meta_filter_healthy =
                worker_result->forward_udp_reject_after_commit.state ==
                    std::optional<OwnedForwardUdpRejectState>{
                        OwnedForwardUdpRejectState::healthy} &&
                !worker_result->forward_udp_reject_after_commit
                     .failure.failed();
            transaction.rollback_meta_fastnat_healthy =
                !transaction.rollback_meta_activation_plan.has_value() ||
                (worker_result->fastnat_after_commit
                         .disabled_or_unavailable ==
                     std::optional<bool>{true} &&
                 !worker_result->fastnat_after_commit.failure.failed());
            try {
                if (!transaction.candidate_core_publication_ready ||
                    !transaction
                         .candidate_core_publication.committed) {
                    throw std::logic_error(
                        "realized configuration candidate is unavailable");
                }
                auto cleanup = prepare_config_transition_cleanup_plan(
                    transaction.previous_runtime_active,
                    transaction.candidate.config,
                    transaction.candidate_core_publication.rules,
                    transaction.candidate_core_publication
                        .list_content_state,
                    transaction.candidate_core_publication
                        .native_vpn_direct_egress_snat_selectors,
                    transaction.candidate_core_publication
                        .internal_vpn_servers,
                    transaction.candidate_core_publication
                        .internal_vpn_service_targets,
                    transaction.rollback.config,
                    state.core_publication);
                transaction.rollback_forwarded_scope_exact =
                    cleanup.forwarded_scope_exact;
                transaction.rollback_native_source_cleanup_cidrs =
                    std::move(cleanup.native_source_cleanup_cidrs);
                transaction.rollback_normal_retirement =
                    std::move(cleanup.normal_retirement);
                transaction.rollback_aggressive_retirement =
                    std::move(cleanup.aggressive_retirement);
                transaction.rollback_cleanup_scope_prepared = true;
            } catch (...) {
                transaction.rollback_cleanup_scope_prepared = false;
                transaction.post_terminal_refresh_required = true;
                transaction.post_terminal_full_refresh = true;
            }
        }

        OwnedSnatRecovery no_config_cleanup;
        if (!drain->complete_worker_control(
                runtime_firewall_retry_, verified, no_config_cleanup)) {
            return;
        }
        const auto* completion = drain->worker_control_completion();
        if (!completion || !completion->owned) return;
        capture_completion(*completion);
        context->force_successor = false;
        if (!retained_worker_lease ||
            !absorb_retained_mutation_lease()) {
            return;
        }
        if (!settle_immediate_completion(
                shutdown
                    ? RuntimeFirewallImmediateTerminalOutcome::shutdown
                    : (verified
                           ? RuntimeFirewallImmediateTerminalOutcome::
                                 verified_success
                           : RuntimeFirewallImmediateTerminalOutcome::
                                 not_verified))) {
            return;
        }

        const bool stopped_base_certainly_retained =
            context->lifecycle_kind ==
                RuntimeFirewallLifecycleKind::
                    config_bootstrap_from_stopped &&
            worker_result &&
            worker_result->previous_generation_certainly_retained();
        auto config_terminal = prepare_config_generation_terminal(
            shutdown
                ? RuntimeFirewallLifecycleOutcome::shutdown
                : (verified
                       ? RuntimeFirewallLifecycleOutcome::verified_success
                       : RuntimeFirewallLifecycleOutcome::not_verified),
            stopped_base_certainly_retained);
        if (verified) {
            config_terminal.committed = true;
            config_terminal.commit_ambiguous = false;
        }
        auto permit = runtime_firewall_owner_->
            prepare_preowned_continuation_finalization(context);
        if (!permit.has_value()) return;
        auto proof = drain->finish_worker_terminal();
        if (!proof.has_value()) return;
        (void)runtime_firewall_owner_->complete_preowned_continuation(
            std::move(*permit),
            std::move(*proof),
            std::move(config_terminal));
        return;
    }

    if (!drain->begin_worker_control(runtime_firewall_retry_)) return;

    const bool lifecycle_start =
        runtime_firewall_lifecycle_uses_start_pipeline(
            context->lifecycle_kind);
    const auto publish_core_candidate = [this, &state]() noexcept {
        if (state.publication_tail.core_published()) return true;
        auto& publication = state.core_publication;
        if (!publication.committed) return true;
        publish_runtime_firewall_core_checkpoint(
            publication,
            RuntimeFirewallCoreMetaPublication::exchange_preimage);
        state.publication_tail.mark_core_published();
        return true;
    };
    if (!drain->publish_worker_control([
            lifecycle_start,
            &publish_core_candidate]() noexcept {
            return lifecycle_start
                ? true
                : publish_core_candidate();
        })) {
        return;
    }

    if (!shutdown && state.publication_tail.core_published() &&
        !state.publication_tail.internal_vpn_lkg_published()) {
        update_internal_vpn_verified_includes_lkg(
            state.internal_vpn_resolution);
        update_internal_vpn_service_verified_includes_lkg(
            state.internal_vpn_service_resolution);
        state.publication_tail.mark_internal_vpn_lkg_published();
    }

    if (!shutdown && lifecycle_start &&
        !state.publication_tail.start_candidate_published()) {
        // START keeps its candidate private until resolver activate publishes
        // the exact expected stream. Meta/idle work is likewise deferred.
    } else if (!shutdown &&
               !state.publication_tail.meta_tail_finished()) {
        reset_idle_stall_observer(/*schedule_if_eligible=*/true);
        const auto current_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const auto candidate_cleanup_epoch =
            state.publication_tail.core_published()
            ? meta_udp443_cleanup_epoch_.load(
                  std::memory_order_acquire)
            : 0U;
        RuntimeFirewallMetaTailFacts facts;
        facts.core_published =
            state.publication_tail.core_published();
        facts.candidate_plan =
            state.candidate_meta_activation_plan.has_value()
            ? &*state.candidate_meta_activation_plan
            : nullptr;
        facts.filter_healthy =
            worker_result != nullptr &&
            worker_result->forward_udp_reject_after_commit.state ==
                std::optional<OwnedForwardUdpRejectState>{
                    OwnedForwardUdpRejectState::healthy} &&
            !worker_result->forward_udp_reject_after_commit.failure.failed();
        facts.fastnat_healthy =
            !state.candidate_meta_activation_plan.has_value() ||
            (worker_result != nullptr &&
             worker_result->fastnat_after_commit
                     .disabled_or_unavailable ==
                 std::optional<bool>{true} &&
             !worker_result->fastnat_after_commit.failure.failed());
        facts.worker_commit_ambiguous =
            context->worker_commit_ambiguous;
        facts.publication_epoch_changed =
            worker_result != nullptr &&
            meta_udp443_publication_may_have_changed(
                worker_result->meta_publication_epoch_before,
                worker_result->meta_publication_epoch_after);
        facts.previous_plan = state.previous_meta_cleanup.has_value()
            ? &state.previous_meta_cleanup->plan
            : nullptr;
        facts.previous_runtime_generation =
            state.previous_meta_cleanup.has_value()
            ? state.previous_meta_cleanup->runtime_generation
            : 0U;
        facts.current_runtime_generation = current_generation;
        facts.previous_attempt = state.previous_meta_cleanup.has_value()
            ? state.previous_meta_cleanup->attempt
            : 0U;

        const auto meta_tail =
            plan_runtime_firewall_meta_tail(facts);
        dispatch_runtime_firewall_meta_tail_effects(
            meta_tail,
            [this, current_generation, candidate_cleanup_epoch](
                RuntimeFirewallMetaTailEffect effect,
                const RuntimeFirewallMetaTailPlan& plan) {
                switch (effect) {
                    case RuntimeFirewallMetaTailEffect::reset_incident:
                        meta_udp443_incidents_.reset(
                            "meta-udp443-activation");
                        break;
                    case RuntimeFirewallMetaTailEffect::report_degraded:
                        report_meta_udp443_degraded(plan.incident_detail);
                        break;
                    case RuntimeFirewallMetaTailEffect::schedule_cleanup:
                        schedule_meta_udp443_activation_cleanup_retry(
                            *plan.cleanup_plan,
                            current_generation,
                            plan.cleanup_source ==
                                    RuntimeFirewallMetaCleanupSource::candidate
                                ? candidate_cleanup_epoch
                                : meta_udp443_cleanup_epoch_.load(
                                      std::memory_order_acquire),
                            plan.cleanup_attempt);
                        break;
                    case RuntimeFirewallMetaTailEffect::
                            schedule_full_refresh:
                        schedule_netfilter_runtime_refresh_noexcept(
                            NetfilterRefreshReason::full,
                            plan.refresh_detail.data());
                        break;
                }
            });
        state.publication_tail.mark_meta_tail_finished();
        state.preworker_side_effects_armed = false;
    }

    if (!shutdown && lifecycle_start &&
        !state.publication_tail.resolver_tail_finished()) {
        RuntimeFirewallStartResolverTailFacts resolver_facts;
        resolver_facts.cold_boot = lifecycle_cold_boot;
        resolver_facts.worker_succeeded = context->worker_succeeded;
        resolver_facts.worker_input_available =
            context->worker_input != nullptr;
        resolver_facts.worker_result_available = worker_result != nullptr;
        resolver_facts.route_preparation_required = worker_result &&
            worker_result->route_preparation.required;
        resolver_facts.worker_route_mutation_applied = worker_result &&
            worker_result->route_preparation.worker_mutation_ack ==
                std::optional<RuntimeRouteMutationAck>{
                    RuntimeRouteMutationAck::applied};
        resolver_facts.requested_route_epoch = context->worker_input
            ? context->worker_input->route_health_request.route_epoch
            : 0U;
        resolver_facts.current_route_epoch = lifecycle_cold_boot
            ? routing_observation_epoch_.load(
                  std::memory_order_acquire)
            : 0U;
        resolver_facts.operation_runtime_generation =
            context->queued_claim.runtime_generation;
        resolver_facts.current_runtime_generation = lifecycle_cold_boot
            ? runtime_generation_.load(std::memory_order_acquire)
            : 0U;
        resolver_facts.route_checkpoint_published = worker_result &&
            worker_result->route_preparation.checkpoint_published;
        resolver_facts.route_checkpoint_mutation_applied = worker_result &&
            worker_result->route_preparation.mutation_ack ==
                std::optional<RuntimeRouteMutationAck>{
                    RuntimeRouteMutationAck::applied};
        resolver_facts.core_committed =
            state.core_publication.committed;
        resolver_facts.commit_ambiguous =
            context->worker_commit_ambiguous;
        const auto resolver_tail =
            plan_runtime_firewall_start_resolver_tail(resolver_facts);
        if (lifecycle_cold_boot && state.cold_boot_transaction) {
            state.cold_boot_transaction->route_mutation_acknowledged =
                resolver_tail.route_mutation_acknowledged;
            state.cold_boot_transaction->exact_route_checkpoint_verified =
                resolver_tail.exact_route_checkpoint_verified;
        }
        if (!resolver_tail.begin_lifecycle_resolver) {
            if (resolver_tail.downgrade_nominal_worker_success) {
                context->worker_succeeded = false;
                state.worker_failure_transient = false;
                if (state.worker_failure_detail.empty()) {
                    state.worker_failure_detail =
                        "cold-boot route/firewall checkpoint was not exact "
                        "before resolver activation";
                }
            }
            state.lifecycle_resolver_verified = false;
            state.publication_tail.mark_resolver_tail_finished();
        } else {
            if (begin_runtime_firewall_lifecycle_resolver(context)) {
                drain->park_until_wake();
                return;
            }
            state.publication_tail.mark_resolver_tail_finished();
            if (state.lifecycle_resolver_verified) {
                if (!lifecycle_cold_boot &&
                    !publish_core_candidate()) {
                    return;
                }
                state.publication_tail.mark_start_candidate_published();
                // Re-enter once so the ordinary internal-VPN and Meta tails
                // observe only the now-verified published candidate.
                return;
            }
        }
    } else if (!shutdown && !lifecycle_start &&
               state.publication_tail.core_published() &&
               !state.publication_tail.resolver_tail_finished()) {
        const auto current_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const bool resolver_waits_for_firewall =
            resolver_after_firewall_gate_.waiting_for(
                current_generation);
        const bool foreground_lifecycle =
            runtime_firewall_lifecycle_is_foreground(
                context->lifecycle_kind);
        RuntimeFirewallNonStartResolverTailFacts resolver_facts;
        resolver_facts.foreground_lifecycle = foreground_lifecycle;
        resolver_facts.restart_lifecycle =
            runtime_firewall_lifecycle_is_restart(
                context->lifecycle_kind);
        resolver_facts.resolver_refresh_required =
            state.resolver_refresh_required;
        resolver_facts.resolver_waits_for_firewall =
            resolver_waits_for_firewall;
        resolver_facts.resolver_generation_published =
            state.publication_tail.resolver_generation_published();
        resolver_facts.resolver_stream_in_flight =
            state.resolver_refresh_required &&
            !resolver_waits_for_firewall &&
            !foreground_lifecycle &&
            resolver_stream_coordinator_.in_flight();
        const auto resolver_tail =
            plan_runtime_firewall_non_start_resolver_tail(
                resolver_facts);
        bool lifecycle_resolver_verified =
            resolver_tail.initially_verified;
        if (resolver_tail.publish_resolver_generation) {
            apply_started_ts_.store(
                unix_timestamp_now_seconds(),
                std::memory_order_release);
            commit_resolver_generation_snapshot(
                make_resolver_generation_snapshot(
                    state.list_cache_snapshot));
            state.publication_tail.mark_resolver_generation_published();
        }
        if (resolver_tail.cancel_existing_reload_retry) {
            cancel_resolver_reload_retry();
        }
        if (resolver_tail.action ==
            RuntimeFirewallResolverTailAction::
                foreground_lifecycle_stream) {
            if (begin_runtime_firewall_lifecycle_resolver(context)) {
                drain->park_until_wake();
                return;
            }
            lifecycle_resolver_verified =
                state.lifecycle_resolver_verified;
            if (lifecycle_resolver_verified) {
                if (acknowledge_verified_resolver_reload(
                        current_generation)) {
                    publish_runtime_state();
                }
                refresh_resolver_config_hash_actual_async();
            } else {
                schedule_resolver_reload_retry(
                    0, current_generation);
            }
        } else if (resolver_tail.action ==
                   RuntimeFirewallResolverTailAction::
                       background_existing_stream_retry) {
            schedule_resolver_reload_retry(
                0, current_generation);
        } else if (resolver_tail.action ==
                   RuntimeFirewallResolverTailAction::
                       background_direct_stream) {
            try {
                if (run_system_resolver_hook_stream_prepared(
                        "reload", /*rebuild_snapshot=*/false)) {
                    lifecycle_resolver_verified = true;
                    if (acknowledge_verified_resolver_reload(
                            current_generation)) {
                        publish_runtime_state();
                    }
                    refresh_resolver_config_hash_actual_async();
                } else {
                    schedule_resolver_reload_retry(
                        0, current_generation);
                }
            } catch (const std::exception& error) {
                lifecycle_resolver_verified = false;
                Logger::instance().info(
                    "Native VPN DNS access policy refresh was deferred: "
                    "{}",
                    error.what());
                schedule_resolver_reload_retry(
                    0, current_generation);
            } catch (...) {
                lifecycle_resolver_verified = false;
                schedule_resolver_reload_retry(
                    0, current_generation);
            }
        } else if (resolver_tail.action ==
                   RuntimeFirewallResolverTailAction::
                       foreground_gated_failure) {
            state.lifecycle_failure_detail =
                "resolver reload remains gated behind firewall recovery";
        }
        if (foreground_lifecycle) {
            state.lifecycle_resolver_verified =
                lifecycle_resolver_verified;
        }
        state.publication_tail.mark_resolver_tail_finished();
    }

    if (!shutdown && !lifecycle_cold_boot &&
        !state.publication_tail.conntrack_tail_finished()) {
        RuntimeFirewallConntrackTailFacts facts;
        if (state.worker_result_valid && worker_result != nullptr) {
            facts.native_source_cleanup_failed = worker_result
                ->native_direct_egress_source_cleanup.failure.failed();
            facts.native_source_cleanup_failure_detail = worker_result
                ->native_direct_egress_source_cleanup.failure.message;
        }
        facts.worker_succeeded = context->worker_succeeded;
        facts.processed_snat_recovery =
            state.processed_snat_recovery.has_value()
            ? &*state.processed_snat_recovery
            : nullptr;
        facts.inspected_snat_after = state.inspected_snat_after;
        facts.current_runtime_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const auto conntrack_tail =
            plan_runtime_firewall_conntrack_tail(facts);
        dispatch_runtime_firewall_conntrack_tail_effects(
            conntrack_tail,
            [this](
                RuntimeFirewallConntrackTailEffect effect,
                const RuntimeFirewallConntrackTailPlan& plan) {
                switch (effect) {
                    case RuntimeFirewallConntrackTailEffect::report_failure:
                        Logger::instance().info(
                            "Delayed native VPN source-flow cleanup was "
                            "incomplete: {}",
                            plan.native_source_cleanup_failure_detail);
                        break;
                    case RuntimeFirewallConntrackTailEffect::schedule_retry: {
                        const auto& snapshot =
                            *plan.cleanup_retry_snapshot;
                        schedule_owned_conntrack_cleanup_retry(
                            snapshot,
                            ordered_owned_conntrack_marks(snapshot));
                        break;
                    }
                }
            });
        state.publication_tail.mark_conntrack_tail_finished();
    }

    if (!shutdown &&
        !state.publication_tail.runtime_incident_tail_finished()) {
        const auto current_generation =
            runtime_generation_.load(std::memory_order_acquire);
        const bool route_epoch_current = !lifecycle_start ||
            (context->worker_input &&
             context->worker_input->route_health_request.route_epoch != 0U &&
             context->worker_input->route_health_request.route_epoch ==
                 routing_observation_epoch_.load(
                     std::memory_order_acquire));
        RuntimeFirewallTerminalTailFacts terminal_facts;
        terminal_facts.lifecycle_start = lifecycle_start;
        terminal_facts.lifecycle_cold_boot = lifecycle_cold_boot;
        terminal_facts.worker_succeeded = context->worker_succeeded;
        terminal_facts.worker_commit_ambiguous =
            context->worker_commit_ambiguous;
        terminal_facts.route_epoch_current = route_epoch_current;
        terminal_facts.ordinary_start_retry_available =
            runtime_firewall_start_retry_available(
                context->queued_claim.attempt);
        terminal_facts.successor_pending =
            context->successor_mode !=
                RuntimeFirewallOperationContext::SuccessorMode::none;
        terminal_facts.lifecycle_resolver_verified =
            state.lifecycle_resolver_verified;
        terminal_facts.start_candidate_published =
            state.publication_tail.start_candidate_published();
        terminal_facts.core_published =
            state.publication_tail.core_published();
        const auto terminal_tail =
            plan_runtime_firewall_terminal_tail(terminal_facts);

        if (terminal_tail.downgrade_stale_start_success) {
            // Interface events are serialized on this control loop, so this
            // remains the final exact fence before publishing running.
            context->worker_succeeded =
                terminal_tail.worker_succeeded_after_route_fence;
            if (terminal_tail.successor ==
                RuntimeFirewallTerminalTailSuccessor::reschedule_retry) {
                context->successor_mode =
                    RuntimeFirewallOperationContext::SuccessorMode::
                        reschedule_retry;
            } else if (terminal_tail.successor ==
                       RuntimeFirewallTerminalTailSuccessor::clear) {
                context->successor_mode =
                    RuntimeFirewallOperationContext::SuccessorMode::none;
            }
            context->force_successor = terminal_tail.force_successor;
            state.worker_failure_transient =
                terminal_tail.worker_failure_transient;
            state.worker_failure_detail.assign(
                terminal_tail.worker_failure_detail.data(),
                terminal_tail.worker_failure_detail.size());
        }
        if (lifecycle_start) {
            if (terminal_tail.dispatch ==
                RuntimeFirewallTerminalTailDispatch::start_verified) {
                bool publication_failed = false;
                if (!state.publication_tail.start_finalized()) {
                    if (lifecycle_cold_boot) {
                        bool exact_admission = false;
                        try {
                            const auto active =
                                runtime_mutation_admission_.active();
                            exact_admission = active.has_value() &&
                                active->token ==
                                    state.cold_boot_mutation_lease_token;
                        } catch (...) {
                        }

                        std::optional<
                            RuntimeColdBootPublicationCheckpoint>
                            prepared_publication;
                        try {
                            prepared_publication.emplace(
                                prepare_runtime_cold_boot_publication_checkpoint(
                                    RuntimeResolverPublicationTarget{
                                        resolver_generation_snapshot_,
                                        resolver_sync_,
                                        resolver_config_hash_actual_retry_attempt_,
                                        apply_started_ts_},
                                    state.private_resolver_generation,
                                    internal_vpn_lkg_store_,
                                    state.internal_vpn_resolution,
                                    state.internal_vpn_service_resolution));
                        } catch (...) {
                        }

                        bool publication_committed = false;
                        const bool publication_admitted =
                            prepared_publication.has_value() &&
                            publish_runtime_cold_boot_if_current(
                                [this,
                                 &context,
                                 &state,
                                 current_generation,
                                 route_epoch_current,
                                 exact_admission]() noexcept {
                                    return exact_admission &&
                                        route_epoch_current &&
                                        state.cold_boot_transaction &&
                                        state.cold_boot_transaction
                                            ->exact_route_checkpoint_verified &&
                                        state.private_resolver_generation &&
                                        state.core_publication.committed &&
                                        !context->worker_commit_ambiguous &&
                                        current_generation ==
                                            context->queued_claim
                                                .runtime_generation &&
                                        current_generation ==
                                            runtime_generation_.load(
                                                std::memory_order_acquire);
                                },
                                [this,
                                 &state,
                                 &prepared_publication,
                                 &publication_committed]() noexcept {
                                    publication_committed =
                                        publish_runtime_cold_boot_checkpoint(
                                            RuntimeColdBootPublicationTarget{
                                                RuntimeFirewallCorePublicationTarget{
                                                    firewall_state_,
                                                    applied_list_content_state_,
                                                    applied_list_usage_,
                                                    applied_list_fingerprints_,
                                                    resolved_internal_vpn_servers_,
                                                    resolved_internal_vpn_service_targets_,
                                                    applied_native_vpn_direct_egress_snat_selectors_,
                                                    committed_meta_udp443_fwmark_,
                                                    committed_meta_udp443_owned_mask_},
                                                state.core_publication,
                                                RuntimeResolverPublicationTarget{
                                                    resolver_generation_snapshot_,
                                                    resolver_sync_,
                                                    resolver_config_hash_actual_retry_attempt_,
                                                    apply_started_ts_},
                                                internal_vpn_lkg_store_,
                                                state.publication_tail},
                                            *prepared_publication,
                                            [this]() {
                                                runtime_state_store_
                                                    .set_routing_runtime_active(
                                                        true);
                                                if (runtime_state_machine_.state() !=
                                                    RuntimeState::running) {
                                                    transition_runtime_or_throw(
                                                        RuntimeState::running,
                                                        "cold-boot publication complete");
                                                }
                                            },
                                            [this]() {
                                                runtime_state_store_
                                                    .set_routing_runtime_active(
                                                        false);
                                                if (runtime_state_machine_.state() ==
                                                    RuntimeState::running) {
                                                    transition_runtime_or_throw(
                                                        RuntimeState::broken,
                                                        "cold-boot publication rollback");
                                                }
                                            },
                                            [this]() {
                                                publish_runtime_state();
                                            });
                                });
                        publication_failed =
                            !publication_admitted ||
                            !publication_committed;
                    } else {
                        try {
                            runtime_state_store_
                                .set_routing_runtime_active(true);
                            if (runtime_state_machine_.state() !=
                                RuntimeState::running) {
                                transition_runtime_or_throw(
                                    RuntimeState::running,
                                    "runtime start complete");
                            }
                            publish_runtime_state();
                            state.publication_tail
                                .set_start_finalized(true);
                        } catch (...) {
                            publication_failed = true;
                        }
                    }
                    if (publication_failed) {
                        try {
                            state.lifecycle_failure_detail =
                                "runtime start state publication failed";
                        } catch (...) {
                        }
                    }
                }

                if (publication_failed) {
                    context->worker_succeeded = false;
                    if (!lifecycle_cold_boot) {
                        if (begin_runtime_firewall_start_rollback(context)) {
                            drain->park_until_wake();
                            return;
                        }
                        if (!finalize_start_broken(
                                state.lifecycle_failure_detail)) {
                            drain->park_until_wake();
                            return;
                        }
                    }
                } else if (lifecycle_cold_boot) {
                    if (state.publication_tail.core_published() &&
                        !state.publication_tail
                             .internal_vpn_lkg_published()) {
                        try {
                            update_internal_vpn_verified_includes_lkg(
                                state.internal_vpn_resolution);
                            update_internal_vpn_service_verified_includes_lkg(
                                state.internal_vpn_service_resolution);
                            state.publication_tail
                                .mark_internal_vpn_lkg_published();
                        } catch (...) {
                        }
                    }
                    state.publication_tail
                        .mark_start_post_success_finished();
                } else if (!state.publication_tail
                                .start_post_success_finished()) {
                    // All remaining work is ancillary. A scheduler, notifier
                    // or logger failure must not replay the already-published
                    // START transition or strand its exact completion.
                    dispatch_runtime_firewall_start_ancillary_effects(
                        [this, &state, worker_result](
                            RuntimeFirewallStartAncillaryEffect effect) {
                            switch (effect) {
                                case RuntimeFirewallStartAncillaryEffect::
                                        reset_idle_observer:
                                    reset_idle_stall_observer(
                                        /*schedule_if_eligible=*/true);
                                    break;
                                case RuntimeFirewallStartAncillaryEffect::
                                        schedule_snat_health:
                                    schedule_owned_snat_health_check();
                                    break;
                                case RuntimeFirewallStartAncillaryEffect::
                                        schedule_internal_vpn_catalog:
                                    schedule_internal_vpn_catalog_refresh_if_needed(
                                        state.internal_vpn_resolution.state,
                                        state.internal_vpn_service_resolution
                                            .state);
                                    break;
                                case RuntimeFirewallStartAncillaryEffect::
                                        clear_runtime_firewall_incident:
                                    runtime_firewall_incidents_.clear();
                                    break;
                                case RuntimeFirewallStartAncillaryEffect::
                                        reconcile_remote_access:
#ifdef WITH_API
                                    request_remote_access_reconcile_from_control(
                                        "runtime start");
#endif
                                    break;
                                case RuntimeFirewallStartAncillaryEffect::
                                        schedule_keenetic_dns_refresh:
                                    schedule_keenetic_dns_refresh();
                                    break;
                                case RuntimeFirewallStartAncillaryEffect::
                                        refresh_resolver_hash:
                                    refresh_resolver_config_hash_actual_async();
                                    break;
                                case RuntimeFirewallStartAncillaryEffect::
                                        log_runtime_started:
                                    Logger::instance().info(
                                        "Routing runtime started.");
                                    break;
                                case RuntimeFirewallStartAncillaryEffect::
                                        reconcile_post_success_conntrack: {
                                    if (worker_result == nullptr) break;
                                    const auto& cleanup = worker_result
                                        ->post_commit_owned_conntrack_cleanup;
                                    RuntimeFirewallPostSuccessConntrackFacts
                                        facts;
                                    facts.attempted = cleanup.attempted;
                                    facts.snapshot = cleanup.snapshot.has_value()
                                        ? &*cleanup.snapshot
                                        : nullptr;
                                    facts.command_unavailable =
                                        cleanup.summary.command_unavailable;
                                    facts.cleanup_failed =
                                        cleanup.failure.failed();
                                    facts.remaining_marks =
                                        &cleanup.summary.remaining_marks;
                                    const auto cleanup_tail =
                                        plan_runtime_firewall_post_success_conntrack(
                                            facts);
                                    if (cleanup_tail
                                            .should_warn_command_unavailable()) {
                                        warn_conntrack_unavailable_once();
                                    }
                                    if (cleanup_tail.should_prepare_retry()) {
                                        auto remaining =
                                            cleanup_tail.retry_marks ==
                                                    RuntimeFirewallPostSuccessConntrackMarks::
                                                        reported_remaining
                                                ? *cleanup_tail
                                                       .reported_remaining_marks
                                                : ordered_owned_conntrack_marks(
                                                      *cleanup_tail
                                                           .retry_snapshot);
                                        if (!remaining.empty()) {
                                            schedule_owned_conntrack_cleanup_retry(
                                                *cleanup_tail.retry_snapshot,
                                                std::move(remaining));
                                        }
                                    }
                                    break;
                                }
                            }
                        });
                    state.publication_tail
                        .mark_start_post_success_finished();
                }
            } else if (terminal_tail.dispatch ==
                       RuntimeFirewallTerminalTailDispatch::start_pending) {
                try {
                    Logger::instance().info(
                        "Runtime start firewall attempt remains pending: {}",
                        state.worker_failure_detail);
                } catch (...) {
                }
            } else {
                if (!lifecycle_cold_boot) {
                    if (begin_runtime_firewall_start_rollback(context)) {
                        drain->park_until_wake();
                        return;
                    }
                    if (!finalize_start_broken(
                            state.lifecycle_failure_detail.empty()
                                ? std::string_view{
                                      state.worker_failure_detail}
                                : std::string_view{
                                      state.lifecycle_failure_detail})) {
                        drain->park_until_wake();
                        return;
                    }
                }
            }
        } else if (terminal_tail.dispatch ==
                   RuntimeFirewallTerminalTailDispatch::
                       background_success) {
            dispatch_runtime_firewall_background_success_effects(
                [this, current_generation](
                    RuntimeFirewallBackgroundSuccessEffect effect) {
                    switch (effect) {
                        case RuntimeFirewallBackgroundSuccessEffect::
                                release_urltest_recovery:
                            release_urltest_firewall_recovery(
                                current_generation);
                            break;
                        case RuntimeFirewallBackgroundSuccessEffect::
                                release_resolver_and_maybe_retry:
                            if (resolver_after_firewall_gate_.release(
                                    current_generation)) {
                                schedule_resolver_reload_retry(
                                    0, current_generation);
                            }
                            break;
                        case RuntimeFirewallBackgroundSuccessEffect::
                                clear_runtime_firewall_incident:
                            runtime_firewall_incidents_.clear();
                            break;
                        case RuntimeFirewallBackgroundSuccessEffect::
                                reconcile_remote_access:
#ifdef WITH_API
                            request_remote_access_reconcile_from_control(
                                "verified delayed firewall refresh");
#endif
                            break;
                        case RuntimeFirewallBackgroundSuccessEffect::
                                publish_runtime_state:
                            publish_runtime_state();
                            break;
                        case RuntimeFirewallBackgroundSuccessEffect::
                                log_refresh_complete:
                            Logger::instance().info(
                                "Delayed runtime firewall refresh complete.");
                            break;
                    }
                });
        } else {
            // Firewall remains on its verified LKG, but route preparation may
            // already have committed either an authoritative new generation
            // or a conservative recovery ledger. Publish that exact pairing
            // on every failed terminal; otherwise health/API can keep the
            // previous route snapshot merely because the new one is complete.
            dispatch_runtime_firewall_background_failure_effects(
                context->worker_commit_ambiguous,
                [this, &state](
                    RuntimeFirewallBackgroundFailureEffect effect) {
                    switch (effect) {
                        case RuntimeFirewallBackgroundFailureEffect::
                                publish_runtime_pairing_best_effort:
                            try {
                                publish_runtime_state();
                            } catch (const std::exception& error) {
                                try {
                                    Logger::instance().warn(
                                        "Could not publish runtime state after "
                                        "failed routing/firewall "
                                        "reconciliation: {}",
                                        error.what());
                                } catch (...) {
                                }
                            } catch (...) {
                            }
                            break;
                        case RuntimeFirewallBackgroundFailureEffect::
                                record_and_log_incident: {
                            const auto incident =
                                runtime_firewall_incidents_.record_failure(
                                    "runtime-firewall-reconciliation",
                                    /*notify_immediately=*/
                                        !state.worker_failure_transient);
                            if (state.worker_failure_transient) {
                                Logger::instance().info(
                                    "Delayed runtime firewall refresh remains "
                                    "pending: {}",
                                    state.worker_failure_detail);
                            } else if (incident.notify) {
                                Logger::instance().error(
                                    "Delayed runtime firewall refresh failed: "
                                    "{}. The last verified daemon snapshot "
                                    "remains active while a bounded retry "
                                    "resnapshots the backend.",
                                    state.worker_failure_detail);
                            }
                            break;
                        }
                        case RuntimeFirewallBackgroundFailureEffect::
                                schedule_ambiguous_refresh:
                            schedule_netfilter_runtime_refresh_noexcept(
                                NetfilterRefreshReason::full,
                                "ambiguous delayed runtime firewall COMMIT");
                            break;
                    }
                });
        }
        state.publication_tail.mark_runtime_incident_tail_finished();
    }

    if (!state.processed_snat_recovery.has_value()) {
        state.processed_snat_recovery =
            context->submitted_snat_recovery;
    }
    const bool lifecycle_verified =
        !lifecycle_start ||
        (state.publication_tail.start_finalized() &&
         state.lifecycle_resolver_verified &&
         routing_runtime_active());
    if (!drain->complete_worker_control(
            runtime_firewall_retry_,
            !shutdown && context->worker_succeeded &&
                lifecycle_verified,
            *state.processed_snat_recovery)) {
        return;
    }
    const auto* completion = drain->worker_control_completion();
    if (!completion || !completion->owned) return;
    capture_completion(*completion);
    if (retained_worker_lease) {
        if (!absorb_retained_mutation_lease()) return;
    } else if (!drain->release_worker_lease()) {
        return;
    }
    if (!settle_immediate_completion(
            shutdown
                ? RuntimeFirewallImmediateTerminalOutcome::shutdown
                : (context->worker_succeeded && lifecycle_verified
                       ? RuntimeFirewallImmediateTerminalOutcome::
                             verified_success
                       : RuntimeFirewallImmediateTerminalOutcome::
                             not_verified))) {
        return;
    }
    if (lifecycle_cold_boot) {
        const bool previous_generation_certainly_retained =
            worker_result != nullptr &&
            worker_result->previous_generation_certainly_retained();
        auto cold_boot_terminal = prepare_cold_boot_terminal(
            shutdown
                ? RuntimeFirewallLifecycleOutcome::shutdown
                : (context->worker_succeeded && lifecycle_verified
                       ? RuntimeFirewallLifecycleOutcome::verified_success
                       : RuntimeFirewallLifecycleOutcome::not_verified),
            previous_generation_certainly_retained);
        auto permit = runtime_firewall_owner_->
            prepare_preowned_continuation_finalization(context);
        if (!permit.has_value()) return;
        auto proof = drain->finish_worker_terminal();
        if (!proof.has_value()) return;
        if (!runtime_firewall_owner_->complete_preowned_continuation(
                std::move(*permit),
                std::move(*proof),
                std::move(cold_boot_terminal))) {
            try {
                Logger::instance().error(
                    "Cold-boot worker terminal violated its prepared "
                    "finalization proof");
            } catch (...) {
            }
        }
        return;
    }
    if (!drain->finish_worker_terminal()) return;
    finish_context();
}

void Daemon::handle_interface_event(const InterfaceMonitor::Event& event) {
    if (event.route_changed) {
        // The route-health worker consumes main-table reachability. A route
        // event invalidates that immutable plan and also retains one generic
        // successor. If the current worker already crossed its route ack,
        // the owner coalesces this refresh behind the terminal instead of
        // losing the event. It must not masquerade as link/topology churn or
        // trigger native-catalog work.
        routing_observation_epoch_.fetch_add(
            1U, std::memory_order_acq_rel);
        if (routing_runtime_active()) {
            (void)refresh_iproute_and_firewall_runtime(
                0U,
                {},
                /*schedule_catalog_refresh=*/false);
        }
        return;
    }
    auto& log = Logger::instance();
#ifdef WITH_API
    teardown_conntrack_events();
    if (status_stream_) {
        status_stream_->reconcile();
    }
    // Default-route publication and address churn are prerequisites of the
    // independent remote-access policy even when this interface is unrelated
    // to keen-pbr routing rules.
    request_remote_access_reconcile_from_control("interface event");
#endif
    if (!interface_event_requires_runtime_observation(event)) {
        return;
    }
    routing_observation_epoch_.fetch_add(1U, std::memory_order_acq_rel);
    if (!routing_runtime_active()) return;
    if (event.observation_gap) {
        recover_internal_vpn_catalog_after_observation_gap();
        return;
    }
    if (event.is_up &&
        (event.administrative_state_changed || event.topology_changed)) {
        // The kernel just made this link usable. Let only its deferred route
        // repairs bypass their remaining backoff before the event-driven
        // reconciliation below; unrelated/flapping links stay isolated.
        routing_operation_owner_.notify_interface_up(
            event.interface_name);
    }
    const bool reconcile_immediately =
        interface_event_affects_managed_runtime(
            config_,
            resolved_internal_vpn_servers_,
            resolved_internal_vpn_service_targets_,
            event.interface_name);
    const bool refresh_stable_catalog =
        config_has_stable_internal_vpn_server_policy(config_);
    const bool refresh_service_catalog =
        config_requires_internal_vpn_service_inventory(config_);
    if (!reconcile_immediately &&
        !refresh_stable_catalog &&
        !refresh_service_catalog) {
        return;
    }
    if (!reconcile_immediately) {
        // A new kernel name after NDMS renumbering is not yet present in the
        // persisted/effective rows. A topology event can be the only rename
        // notification Linux emits, so revoke the pre-rename catalog before
        // scheduling its asynchronous replacement. Address/state churn on an
        // unrelated WAN/LAN interface still leaves cache authority intact.
        if (event.topology_changed) {
            if (refresh_stable_catalog) {
                shared_ndms_catalog_cache().invalidate();
            }
            if (refresh_service_catalog) {
                shared_ndms_vpn_server_service_cache().invalidate();
            }
        }
        schedule_internal_vpn_catalog_refresh();
        return;
    }

    if (event.topology_changed) {
        log.info(
            "Interface {} topology changed, runtime observation triggered",
            event.interface_name);
    } else if (event.address_changed) {
        log.info("Interface {} address changed, iproute and firewall refresh triggered",
                 event.interface_name);
    } else {
        log.info("Interface {} state changed to {}, iproute and firewall refresh triggered",
                 event.interface_name,
                 event.is_up ? "UP" : "DOWN");
    }
    const auto configured_internal_servers = config_.route.has_value()
        ? config_.route->internal_vpn_servers.value_or(
              std::vector<InternalVpnServer>{})
        : std::vector<InternalVpnServer>{};
    const bool is_internal_vpn_event = std::any_of(
        resolved_internal_vpn_servers_.begin(),
        resolved_internal_vpn_servers_.end(),
        [&event](const InternalVpnServer& server) {
            return server.interface == event.interface_name;
        }) ||
        std::any_of(
            configured_internal_servers.begin(),
            configured_internal_servers.end(),
            [&event](const InternalVpnServer& server) {
                return server.interface == event.interface_name;
            });
    if (refresh_stable_catalog && is_internal_vpn_event) {
        // The cache may still be within its normal TTL, but an interface event
        // can mean NDMS renumbered or reused the old kernel name. Revoke its
        // authority before the immediate cache-only reconcile. The worker
        // below will restore authority only after a fresh RCI observation.
        shared_ndms_catalog_cache().invalidate();
    }
    if (refresh_service_catalog && event.topology_changed) {
        shared_ndms_vpn_server_service_cache().invalidate();
    }
    refresh_iproute_and_firewall_runtime();
    // A stable NDMS identity may keep the same id while KeeneticOS renumbers
    // its current kernel interface. Refresh on a bounded worker after the
    // immediate cache-only reconciliation; never block the control loop.
    if ((refresh_stable_catalog && is_internal_vpn_event) ||
        (refresh_service_catalog && event.topology_changed)) {
        schedule_internal_vpn_catalog_refresh();
    }
}

void Daemon::recover_internal_vpn_catalog_after_observation_gap() {
    if (!routing_runtime_active() ||
        !config_has_native_vpn_catalog_policy(config_)) {
        return;
    }
    recover_internal_vpn_after_observation_gap(
        // A netlink observation gap revokes the authority of the current
        // stable-id mapping. The include-only LKG is intentionally retained by
        // the runtime resolver.
        [this]() {
            if (config_has_stable_internal_vpn_server_policy(config_)) {
                shared_ndms_catalog_cache().invalidate();
            }
            if (config_requires_internal_vpn_service_inventory(config_)) {
                shared_ndms_vpn_server_service_cache().invalidate();
            }
        },
        // A previously scheduled retry may describe the pre-gap generation
        // and must not suppress this safety-critical reconciliation.
        [this]() { runtime_firewall_owner_->cancel_retry(); },
        // Reconcile from the invalidated cache immediately so an unverified
        // process_clients=false bypass cannot remain active. Suppress the
        // implicit catalog request here: the explicit final stage below gives
        // ENOBUFS and reconnect recovery one deterministic lifecycle order.
        [this]() {
            refresh_iproute_and_firewall_runtime(
                0,
                {},
                /*schedule_catalog_refresh=*/false);
        },
        // The single-flight gate coalesces this request with any refresh that
        // was already in flight and hands it to one immediate rerun.
        [this]() { schedule_internal_vpn_catalog_refresh(); });
}

void Daemon::handle_interface_monitor_events(uint32_t events) {
    constexpr uint32_t relevant_events = EPOLLIN | EPOLLERR | EPOLLHUP;
    if ((events & relevant_events) == 0) {
        return;
    }
    if (!interface_monitor_) {
        return;
    }

    if ((events & (EPOLLERR | EPOLLHUP)) != 0 && (events & EPOLLIN) == 0) {
        Logger::instance().error("Interface monitor fd reported epoll error/hangup");
        reconnect_interface_monitor();
        return;
    }

    try {
        interface_monitor_->handle_events();
    } catch (const std::exception& e) {
        Logger::instance().error("Interface monitor event handling failed: {}", e.what());
        reconnect_interface_monitor();
    }
}

void Daemon::register_interface_monitor_fd() {
    if (!interface_monitor_) {
        return;
    }

    const int fd = interface_monitor_->fd();
    add_fd(fd,
           EPOLLIN,
           [this](uint32_t events) { handle_interface_monitor_events(events); },
           true,
           "interface-monitor");
    interface_monitor_fd_ = fd;
}

void Daemon::unregister_interface_monitor_fd() {
    if (!interface_monitor_fd_) {
        return;
    }

    remove_fd(*interface_monitor_fd_, true, "interface-monitor");
    interface_monitor_fd_.reset();
}

void Daemon::schedule_interface_monitor_reconnect_retry() {
    if (!scheduler_ || interface_monitor_reconnect_task_id_ >= 0) {
        return;
    }

    interface_monitor_reconnect_task_id_ = scheduler_->schedule_oneshot(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            INTERFACE_MONITOR_RECONNECT_RETRY_DELAY),
        [this]() {
            interface_monitor_reconnect_task_id_ = -1;
            reconnect_interface_monitor();
        },
        "interface-monitor-reconnect");
}

void Daemon::reconnect_interface_monitor() {
    enqueue_control_task([this]() {
        if (!interface_monitor_) {
            return;
        }

        unregister_interface_monitor_fd();

        try {
            interface_monitor_->reconnect();
            register_interface_monitor_fd();
            Logger::instance().warn("Interface monitor reconnected after netlink error");
            // Events may have been lost while the socket was unavailable.
            // Treat every successful reconnect as an observation gap instead
            // of trusting a potentially stale NDMS-id to kernel-name mapping.
            recover_internal_vpn_catalog_after_observation_gap();
        } catch (const std::exception& e) {
            Logger::instance().error("Interface monitor reconnect failed: {}", e.what());
            schedule_interface_monitor_reconnect_retry();
        }
    }, false, "interface-monitor-reconnect");
}

void Daemon::add_fd(int fd,
                    uint32_t events,
                    FdCallback cb,
                    bool wait_for_completion,
                    const std::string& label) {
    enqueue_control_task([this, fd, events, cb = std::move(cb)]() mutable {
        KPBR_LOCK_GUARD(fd_entries_mutex_);
        // Build the complete callback registry candidate before exposing the
        // fd to epoll. After EPOLL_CTL_ADD succeeds, publication is one
        // no-throw swap, so allocation failure cannot leave an untracked live
        // registration or erase the stale callback prematurely.
        publish_fd_entry_after_successful_epoll_add(
            fd_entries_,
            FdEntry{fd, std::move(cb)},
            [this, fd, events]() {
                struct epoll_event ev{};
                ev.events = events;
                ev.data.fd = fd;
                if (epoll_ctl(
                        epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
                    throw DaemonError(
                        "epoll_ctl add fd failed: " +
                        std::string(strerror(errno)));
                }
            });
    }, wait_for_completion, label.empty() ? "add-fd" : label);
}

void Daemon::remove_fd(int fd,
                       bool wait_for_completion,
                       const std::string& label) {
    enqueue_control_task([this, fd]() {
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);

        KPBR_LOCK_GUARD(fd_entries_mutex_);
        fd_entries_.erase(
            std::remove_if(fd_entries_.begin(), fd_entries_.end(),
                           [fd](const FdEntry& e) { return e.fd == fd; }),
            fd_entries_.end());
    }, wait_for_completion, label.empty() ? "remove-fd" : label);
}

void Daemon::dispatch_event_fd(int fd, uint32_t events) {
    if (fd == signal_fd_) {
        handle_signal();
        return;
    }
    if (fd == control_fd_) {
        handle_control_commands();
        return;
    }

    FdCallback callback;
    {
        KPBR_LOCK_GUARD(fd_entries_mutex_);
        for (auto& entry : fd_entries_) {
            if (entry.fd == fd) {
                callback = entry.callback;
                break;
            }
        }
    }
    if (callback) {
        callback(events);
    }
}

void Daemon::run_event_loop() {
    constexpr int MAX_EVENTS = 16;
    struct epoll_event events[MAX_EVENTS];

    while (running_.load(std::memory_order_acquire)) {
        int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw DaemonError("epoll_wait failed: " + std::string(strerror(errno)));
        }

        bool signal_event_present = false;
        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == signal_fd_) {
                signal_event_present = true;
                // signalfd is drained in one pass. Give terminal signals
                // priority over every control, timer, API and netlink event
                // returned by this same unordered epoll batch.
                dispatch_event_fd(events[i].data.fd, events[i].events);
                break;
            }
        }
        if (!event_batch_allows_non_signal_dispatch(
                signal_event_present,
                running_.load(std::memory_order_acquire))) {
            continue;
        }

        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == signal_fd_) {
                continue;
            }
            dispatch_event_fd(events[i].data.fd, events[i].events);
            if (!running_.load(std::memory_order_acquire)) {
                break;
            }
        }
    }
}

void Daemon::run() {
    auto& log = Logger::instance();

    try {
#if defined(USE_KEENETIC_API) && defined(WITH_API)
        auto native_import_readiness =
            NdmsNativeImportJournalReadinessState::unavailable;
        auto native_delete_readiness =
            NdmsNativeDeleteWalReadiness::unsafe;
        auto native_mutation_admission =
            NdmsNativeMutationAdmissionState::unavailable;
        try {
            // Startup reconciliation uses the same established lock order as
            // every request. Publishing a cross-WAL clean hint from two
            // unlocked reads would let another cooperating process transition
            // between them and create a torn admission view.
            auto maintenance = std::make_unique<MaintenanceCoordinator>(
                "ndms-native-startup-reconciliation");
            auto runtime = runtime_mutation_admission_.try_acquire(
                "ndms-native-startup-reconciliation");
            if (!runtime.has_value()) {
                throw std::runtime_error(
                    "native startup runtime mutation admission is busy");
            }
            auto writer = admit_ndms_native_writer(
                ndms_native_observation_store_.state_directory(),
                std::move(maintenance),
                std::move(*runtime));
            if (writer.state != NdmsNativeWriterAdmissionState::admitted) {
                throw std::runtime_error(
                    "native startup writer admission failed");
            }
            // Before the inventory is judged: a process that died between
            // creating its WAL temporary and renaming it into place leaves a
            // name the inventory reads as unsafe, and without this sweep the
            // startup report below would say "unsafe" until the first write -
            // which the unsafe inventory itself refuses. The sweep is
            // noexcept, removes only this store's own dead-owner temporaries,
            // and an absent store is simply not its problem.
            ndms_native_import_wal_store_.sweep_orphaned_temporaries();
            ndms_native_delete_wal_store_.sweep_orphaned_temporaries();
            native_delete_readiness =
                ndms_native_delete_wal_store_.readiness();
            const auto native_import_inventory =
                ndms_native_import_wal_store_.try_inventory();
            native_import_readiness =
                summarize_ndms_native_import_readiness(
                    native_import_inventory);
            native_mutation_admission =
                summarize_ndms_native_mutation_admission(
                    native_import_inventory,
                    native_delete_readiness);

            // The removal crash window closes here and only here. A tunnel
            // deleted by an operator whose process then died leaves a durable
            // claim over a slot that is now free; the live caller learns of it
            // from removed_claim_survived, and nothing else would ever notice.
            // Skip unless this exact bounded snapshot proves a ready, empty
            // WAL. Busy, unsafe, I/O-failed and absent stores are unknown for
            // ownership retirement: `absent` is sufficient for a new writer
            // to publish exclusively, but it does not prove that no historical
            // claim still needs recovery. The recovery dispatcher retracts its
            // own claim, and a second remover racing it would turn that
            // retirement into a failure.
            const bool transaction_in_flight_or_unknown =
                !ndms_native_import_inventory_permits_ownership_reconciliation(
                    native_import_inventory);
            const auto reconciled =
                reconcile_ndms_native_ownership_claims(
                    ndms_native_ownership_store_,
                    transaction_in_flight_or_unknown,
                    ndms_native_interface_read_production_dependencies(),
                    native_delete_readiness);
            if (!reconciled.store_readable) {
                log.warn(
                    "Native import ownership claims could not be read; "
                    "stale claims cannot be retired this boot.");
            } else if (!reconciled.retired.empty() ||
                       !reconciled.unresolved.empty()) {
                // Counts only. An interface name is not a secret, but the
                // surrounding report has been deliberately redacted since the
                // journal observation above and there is no reason to widen it
                // here.
                log.info(
                    "Native import ownership reconciliation: examined={} "
                    "retired={} unresolved={}",
                    reconciled.claims_examined,
                    reconciled.retired.size(),
                    reconciled.unresolved.size());
            }
            writer.lease.verify_held();
            ndms_native_import_journal_readiness_.store(
                native_import_readiness, std::memory_order_release);
            ndms_native_mutation_admission_.store(
                native_mutation_admission, std::memory_order_release);
        } catch (...) {
            // Startup inventory is observational. Even an unexpected local
            // allocation/runtime failure must fail the report closed without
            // taking down the already-working routing daemon.
            native_import_readiness =
                NdmsNativeImportJournalReadinessState::unavailable;
            native_mutation_admission =
                NdmsNativeMutationAdmissionState::unavailable;
            ndms_native_import_journal_readiness_.store(
                native_import_readiness, std::memory_order_release);
            ndms_native_mutation_admission_.store(
                native_mutation_admission, std::memory_order_release);
        }
        // Deliberately log only the collapsed enum. Inventory entries can
        // contain transaction identifiers and filenames, neither of which
        // belongs in the API or routine daemon logs.
        log.info(
            "Native import WAL startup observation: state={} (report-only; "
            "every operation still reacquires maintenance, runtime and "
            "cooperative native-writer guards).",
            ndms_native_import_journal_readiness_state_name(
                native_import_readiness));
        log.info(
            "Native delete WAL startup observation: state={} (report-only; "
            "ownership reconciliation requires clean cross-kind state).",
            ndms_native_delete_wal_readiness_name(
                native_delete_readiness));
        log.info(
            "Native mutation pre-body admission: state={} (redacted hint; "
            "the coordinator still reacquires and rechecks authority).",
            ndms_native_mutation_admission_state_name(
                native_mutation_admission));
#endif

    // Startup happens before the event loop. It is the one lifecycle point
    // where a bounded shared-cache refresh may safely query loopback NDMS.
    // Prime Keenetic DNS explicitly before the first route/firewall mutation;
    // all runtime consumers below are cache-only and share this exact view.
    active_keenetic_dns_ = prepare_keenetic_dns_view(
        config_,
        /*allow_refresh=*/true,
        /*force_refresh=*/true);
    auto internal_vpn_resolution =
        resolve_internal_vpn_servers_for_runtime(
            config_,
            true,
            snapshot_internal_vpn_verified_includes_lkg());
    const auto internal_vpn_resolution_state =
        internal_vpn_resolution.state;
    auto internal_vpn_service_resolution =
        resolve_internal_vpn_services_for_runtime(
            config_,
            true,
            snapshot_internal_vpn_service_verified_includes_lkg());
    const auto internal_vpn_service_resolution_state =
        internal_vpn_service_resolution.state;
    log.info("Startup lists: checking local cache; only missing remote lists will be downloaded.");
    const auto relevant_lists = collect_relevant_list_names(config_);
    const auto dns_relevant_lists = collect_dns_relevant_list_names(config_);
    RemoteListRefreshControl refresh_control;
    refresh_control.cache_commit = make_guarded_cache_commit_callback();
    const RemoteListsRefreshResult refresh_result =
        list_service_.download_uncached(
            config_,
            outbound_marks_,
            &relevant_lists,
            &dns_relevant_lists,
            refresh_control);

    if (!refresh_result.cached_lists.empty()) {
        log.info("Startup lists: using cached list(s): {}", format_list_names(refresh_result.cached_lists));
    }
    if (!refresh_result.changed_lists.empty()) {
        log.info("Startup lists: downloaded missing list(s): {}", format_list_names(refresh_result.changed_lists));
    } else if (refresh_result.refreshed_lists.empty() && refresh_result.failed_lists.empty()) {
        log.info("Startup lists: all remote lists are available locally; no downloads needed.");
    }
    if (!refresh_result.unchanged_lists.empty()) {
        log.info("Startup lists: downloaded list(s) were unchanged: {}",
                 format_list_names(refresh_result.unchanged_lists));
    }
    if (!refresh_result.failed_lists.empty()) {
        log.warn("Startup lists: failed to download missing list(s): {}",
                 format_list_names(refresh_result.failed_lists));
    }

    // From this point through the initial firewall retries and resolver
    // stream, both consumers must observe the exact same remote-list bodies.
    auto startup_list_cache_snapshot =
        capture_relevant_list_cache_generation(config_);

    auto cold_boot = std::make_shared<DaemonColdBootTransaction>();
    cold_boot->runtime_generation =
        runtime_generation_.load(std::memory_order_acquire);
    cold_boot->list_cache_snapshot = startup_list_cache_snapshot;
    cold_boot->interface_resolution_state =
        internal_vpn_resolution_state;
    cold_boot->service_resolution_state =
        internal_vpn_service_resolution_state;
    cold_boot->prepared_native_vpn_catalog =
        std::make_shared<const PreparedNativeVpnCatalog>(
            PreparedNativeVpnCatalog{
                cold_boot->runtime_generation,
                std::move(internal_vpn_resolution),
                std::move(internal_vpn_service_resolution),
                /*schedule_catalog_refresh=*/false});

    // The store default is true for compatibility with ordinary constructed
    // snapshots. Cold boot must revoke that optimistic default before any
    // route/firewall candidate is handed to the asynchronous owner.
    runtime_state_store_.set_routing_runtime_active(false);
    normalize_urltest_selections();
    publish_runtime_state();

    // Start the internal control loop before handing off the owner. Posted
    // lifecycle completions are admitted, while API/user ingress remains
    // uninitialized until the typed cold-boot terminal opens services.
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        accept_posted_control_tasks_.store(
            true, std::memory_order_release);
    }
    running_.store(true, std::memory_order_release);
    event_loop_thread_id_.store(
        std::this_thread::get_id(), std::memory_order_relaxed);
    event_loop_active_.store(true, std::memory_order_release);
    // Arm the first owner admission through the event loop. A rejected timer
    // has not transferred authority, so retry its registration with the
    // existing bounded START delays. Exhaustion keeps the daemon alive and
    // opens diagnostics without touching the observed kernel generation.
    bool initial_cold_boot_handoff = false;
    for (std::size_t attempt = 0U;
         attempt < kRuntimeFirewallStartBoundedRetryCount &&
         !initial_cold_boot_handoff;
         ++attempt) {
        try {
            const int task_id = scheduler_->schedule_oneshot(
                kRuntimeFirewallStartRetryDelays[attempt],
                [this, cold_boot]() noexcept {
                    start_runtime_cold_boot_attempt(cold_boot);
                },
                "runtime-cold-boot-start");
            initial_cold_boot_handoff =
                runtime_cold_boot_scheduler_task_accepted(task_id);
        } catch (...) {
        }
    }
    if (!initial_cold_boot_handoff) {
        try {
            runtime_state_store_.set_routing_runtime_active(false);
            if (runtime_state_machine_.state() == RuntimeState::starting ||
                runtime_state_machine_.state() == RuntimeState::running) {
                transition_runtime_or_throw(
                    RuntimeState::broken,
                    "cold-boot event-loop handoff was rejected");
            }
            publish_runtime_state();
        } catch (...) {
        }
        open_runtime_cold_boot_services(
            cold_boot, /*runtime_ready=*/false);
    }
    log.info(
        "Daemon control loop is available; startup route/firewall/resolver "
        "publication is asynchronous.");
    } catch (...) {
        // Startup installs owned kernel state before dnsmasq proves that it
        // consumed the matching resolver generation. Any failure before the
        // event loop starts must therefore unwind every owned subsystem; the
        // normal shutdown tail below is never reached in this path.
        log.error("Daemon startup failed; rolling back partial runtime state.");
#ifdef WITH_API
        cancel_nfqws_boot_recovery();
        cancel_nfqws_retention_backfill();
        cancel_remote_access_recovery_watchdog();
        reset_remote_access_retry_bridge();
#endif
        runtime_mutation_admission_.shutdown();
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->cancel_retry();
        routing_test_admission_.shutdown();
        sighup_reload_coordinator_.stop();
        cancel_resolver_reload_retry();
        resolver_stream_coordinator_.request_stop();
        keenetic_dns_refresh_coordinator_.stop();
        cancel_idle_stall_observer();
        cancel_meta_udp443_activation_cleanup();
        cancel_owned_conntrack_cleanup_retry();
        list_refresh_tasks_.request_cancel_active();
        runtime_generation_.fetch_add(1, std::memory_order_acq_rel);
        if (urltest_manager_) {
            try {
                urltest_manager_->clear();
            } catch (const std::exception& cleanup_error) {
                log.error("Startup rollback: urltest cleanup failed: {}",
                          cleanup_error.what());
            }
        }
        scheduler_->cancel_all();
        // A queued SIGHUP preparation already owns its mutation lease. Drop
        // queued callbacks before waiting for that lease, while active workers
        // can still publish their ordinary completion through the control loop.
        // Keep the typed owner and its executor alive until the same exact
        // STOP transaction used by normal process shutdown has proved every
        // owned route/firewall/resolver artifact absent. Closing the owner
        // first would force this startup exception path back to unowned
        // direct kernel writes.
        runtime_firewall_owner_->prepare_for_process_cleanup();
        blocking_executor_.cancel_pending();
        quiesce_resolver_stream_recovery();
        quiesce_runtime_mutations();
        const bool startup_cleanup_verified =
            run_process_shutdown_cleanup();
        if (!startup_cleanup_verified) {
            log.error(
                "Startup rollback did not reach a verified typed cleanup "
                "terminal; runtime remains broken.");
        }
        runtime_firewall_owner_->request_shutdown();
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->cancel_retry();
        scheduler_->cancel_all();
        runtime_firewall_owner_->cancel_pending_work();
        runtime_firewall_owner_->pump_terminal_for_shutdown();
        runtime_firewall_owner_->shutdown_executor();
        runtime_firewall_owner_->pump_terminal_for_shutdown();
        runtime_firewall_owner_->cancel_completion_watchdog();
        runtime_firewall_owner_->cancel_retry();
        scheduler_->cancel_all();
        runtime_firewall_owner_->reset_active();
        {
            KPBR_LOCK_GUARD(control_tasks_mutex_);
            accept_posted_control_tasks_.store(
                false, std::memory_order_release);
        }
        if (control_fd_ >= 0) {
            handle_control_commands();
        }
#ifdef WITH_API
        if (status_stream_) {
            status_stream_->close_all();
        }
        if (dns_test_broadcaster_) {
            dns_test_broadcaster_->close_all();
        }
        if (api_server_) {
            api_server_->stop();
        }
        try {
            teardown_conntrack_events();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: conntrack cleanup failed: {}",
                      cleanup_error.what());
        }
        remove_remote_access_rules(
            RemoteAccessRemovalMode::expected_teardown);
#endif
        routing_test_executor_.cancel_pending_and_shutdown();
        blocking_executor_.cancel_pending_and_shutdown();
        try {
            unregister_interface_monitor_fd();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: interface monitor cleanup failed: {}",
                      cleanup_error.what());
        }
        try {
            teardown_dns_probe();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: DNS probe cleanup failed: {}",
                      cleanup_error.what());
        }
        runtime_state_store_.set_routing_runtime_active(false);
        resolver_sync_.runtime_stopped();
        try {
            transition_runtime_or_throw(
                RuntimeState::broken, "startup failed and was rolled back");
            publish_runtime_state();
        } catch (const std::exception& state_error) {
            log.error("Startup rollback: state publication failed: {}",
                      state_error.what());
        }
        try {
            remove_pid_file();
        } catch (const std::exception& cleanup_error) {
            log.error("Startup rollback: PID cleanup failed: {}",
                      cleanup_error.what());
        }
        throw;
    }

    log.info("Daemon event loop running. PID: {}", getpid());

    std::exception_ptr event_loop_failure;
    try {
        run_event_loop();
    } catch (...) {
        event_loop_failure = std::current_exception();
        running_.store(false, std::memory_order_release);
        try {
            log.error(
                "Daemon event loop failed; running the typed final cleanup "
                "before propagating the error.");
        } catch (...) {
        }
    }

#ifdef WITH_API
    // Fence retry callbacks while posted-control admission and Scheduler are
    // still alive. No API worker may retain a Daemon capture past this point.
    cancel_nfqws_boot_recovery();
    cancel_nfqws_retention_backfill();
    cancel_remote_access_recovery_watchdog();
    reset_remote_access_retry_bridge();
#endif
    // Stop the continuous forwarded-flow observer before closing admission to
    // the control loop or tearing down API/conntrack state.  An in-flight
    // observation is generation-fenced, but disabling it here also prevents a
    // late exact delete from racing normal shutdown.
    cancel_idle_stall_observer();
    cancel_meta_udp443_activation_cleanup();
    runtime_mutation_admission_.shutdown();
    routing_test_admission_.shutdown();
    sighup_reload_coordinator_.stop();
    cancel_resolver_reload_retry();
    resolver_stream_coordinator_.request_stop();
    keenetic_dns_refresh_coordinator_.stop();
    list_refresh_tasks_.request_cancel_active();
    // A queued SIGHUP preparation can already own the mutation lease. Discard
    // unclaimed blocking work, then drain every admitted/background owner
    // while its executor, watchdog scheduler and resolver IPC remain alive.
    runtime_firewall_owner_->prepare_for_process_cleanup();
    blocking_executor_.cancel_pending();
    // Admission is closed before quiescence, so new HTTP/SIGHUP writers are
    // rejected. Existing owners keep their token and may finish through the
    // control queue while this thread still owns the event-loop state.
    quiesce_resolver_stream_recovery();
    quiesce_runtime_mutations();
    const bool process_cleanup_verified =
        run_process_shutdown_cleanup();

    // Only the exact STOP terminal may close the owner/executor. Doing this
    // earlier can abandon a retained lease while routes/firewall remain.
    runtime_firewall_owner_->request_shutdown();
    runtime_firewall_owner_->cancel_completion_watchdog();
    runtime_firewall_owner_->cancel_retry();
    cancel_owned_conntrack_cleanup_retry();
    scheduler_->cancel_all();
    runtime_firewall_owner_->cancel_pending_work();
    runtime_firewall_owner_->pump_terminal_for_shutdown();
    runtime_firewall_owner_->shutdown_executor();
    runtime_firewall_owner_->pump_terminal_for_shutdown();
    runtime_firewall_owner_->cancel_completion_watchdog();
    runtime_firewall_owner_->cancel_retry();
    scheduler_->cancel_all();
    runtime_firewall_owner_->reset_active();
    {
        KPBR_LOCK_GUARD(control_tasks_mutex_);
        accept_posted_control_tasks_.store(
            false, std::memory_order_release);
    }
    handle_control_commands();
    event_loop_active_.store(false, std::memory_order_release);
    event_loop_thread_id_.store(std::thread::id{}, std::memory_order_relaxed);

    log.info("Shutting down...");
    transition_runtime_or_throw(RuntimeState::shutting_down, "daemon shutdown requested");
    publish_runtime_state();

#ifdef WITH_API
    if (status_stream_) {
        status_stream_->close_all();
    }
    if (dns_test_broadcaster_) {
        dns_test_broadcaster_->close_all();
    }
    if (api_server_) {
        api_server_->stop();
    }
    teardown_conntrack_events();
    remove_remote_access_rules(
        RemoteAccessRemovalMode::expected_teardown);
#endif

    // Stop accepting API work before retiring workers. Otherwise a handler can
    // enqueue against an executor that has already been shut down.
    resolver_hook_executor_.cancel_pending_and_shutdown();
    resolver_stream_executor_.cancel_pending_and_shutdown();
    resolver_io_executor_.cancel_pending_and_shutdown();
    routing_test_executor_.cancel_pending_and_shutdown();
    blocking_executor_.cancel_pending_and_shutdown();

    teardown_dns_probe();

    if (process_cleanup_verified) {
        runtime_state_store_.set_routing_runtime_active(false);
        transition_runtime_or_throw(
            RuntimeState::stopped, "daemon shutdown cleanup verified");
        publish_runtime_state();
    } else {
        log.error(
            "Daemon shutdown completed without verified owned route/firewall/"
            "resolver cleanup; stopped state was not published.");
    }
    remove_pid_file();
    if (event_loop_failure) {
        std::rethrow_exception(event_loop_failure);
    }
}

void Daemon::stop() {
    list_refresh_tasks_.request_cancel_active();
    runtime_mutation_admission_.shutdown();
    routing_test_admission_.shutdown();
    sighup_reload_coordinator_.stop();
    resolver_stream_coordinator_.request_stop();
    running_.store(false, std::memory_order_release);
    if (control_fd_ >= 0) {
        try {
            wake_control_loop();
        } catch (...) {
            // stop() is a best-effort wake path and must remain noexcept to
            // callers. Closing the fd during teardown already wakes epoll.
        }
    }
}

bool Daemon::running() const {
    return running_.load(std::memory_order_acquire);
}

void Daemon::write_pid_file() {
    const auto pid_file = config_.daemon.value_or(DaemonConfig{}).pid_file.value_or("");
    try {
        pid_file_.acquire(pid_file);
    } catch (const std::exception& error) {
        throw DaemonError(error.what());
    }
}

void Daemon::remove_pid_file() {
    pid_file_.remove();
}

} // namespace keen_pbr3
