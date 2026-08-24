#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../config/config.hpp"
#include "../lists/list_set_usage.hpp"
#include "../routing/firewall_state.hpp"
#include "../routing/netlink.hpp"
#include "../runtime/runtime_state_machine.hpp"
#include "../runtime/whatsapp_catalog_identity.hpp"

namespace keen_pbr3 {

inline bool reconnect_unmarked_flows_on_routing_change_enabled(
    const Config& config) noexcept {
    return config.daemon.value_or(DaemonConfig{})
        .reconnect_unmarked_flows_on_routing_change.value_or(true);
}

inline std::set<std::string>
reconnect_owned_flows_on_routing_change_list_names(
    const Config& config) {
    const auto daemon = config.daemon.value_or(DaemonConfig{});
    if (daemon.reconnect_owned_flows_on_routing_change_lists.has_value()) {
        return {
            daemon.reconnect_owned_flows_on_routing_change_lists->begin(),
            daemon.reconnect_owned_flows_on_routing_change_lists->end()};
    }

    // Backward-compatible automatic recommendation for catalogue installs
    // created before this setting existed. This is the immutable provenance
    // identity shared by the packaged Meta/WhatsApp IP companion. New
    // catalogue installs persist the resolved technical ID explicitly.
    std::set<std::string> recommended;
    for (const auto& [list_name, list] :
         config.lists.value_or(std::map<std::string, ListConfig>{})) {
        if (list.catalog_identity == kWhatsappIpCatalogIdentity) {
            recommended.insert(list_name);
        }
    }
    return recommended;
}

// Immutable provenance selector used by the independent preventive observer.
// Unlike UDP call affinity, this does not inherit the strong-reconnect
// enable/selection switches: an active packaged companion route is its own
// authority and copied or manually named lists cannot enable the actuator.
inline std::set<std::string>
packaged_whatsapp_ip_companion_list_names(const Config& config) {
    std::set<std::string> selected;
    for (const auto& [list_name, list] :
         config.lists.value_or(std::map<std::string, ListConfig>{})) {
        if (list.catalog_identity == kWhatsappIpCatalogIdentity) {
            selected.insert(list_name);
        }
    }
    return selected;
}

// Preventive rotation also needs the packaged call-affinity observer. Its
// source-wide high-port UDP view is a read-only safety guard: without it an
// ongoing P2P call could become invisible after the short companion-media
// hold and allow signalling TCP to be reset.
inline std::set<std::string>
preventive_whatsapp_media_guard_list_names(const Config& config) {
    return packaged_whatsapp_ip_companion_list_names(config);
}

inline bool preventive_whatsapp_media_guard_available(
    FirewallBackend backend,
    bool iptables_pair_set_available) noexcept {
    return backend == FirewallBackend::iptables &&
           iptables_pair_set_available;
}

inline bool idle_stall_observer_requested(const Config& config) {
    return !packaged_whatsapp_ip_companion_list_names(config).empty() ||
           (reconnect_unmarked_flows_on_routing_change_enabled(config) &&
            !reconnect_owned_flows_on_routing_change_list_names(config)
                 .empty());
}

namespace runtime_recovery_detail {

inline bool firewall_criteria_equal(
    const FirewallRuleCriteria& left,
    const FirewallRuleCriteria& right) noexcept {
    return left.dst_set_name == right.dst_set_name &&
           left.src_udp_peer_set_name == right.src_udp_peer_set_name &&
           left.dscp == right.dscp &&
           left.proto == right.proto &&
           left.persist_conntrack_mark == right.persist_conntrack_mark &&
           left.src_port == right.src_port &&
           left.dst_port == right.dst_port &&
           left.src_addr == right.src_addr &&
           left.dst_addr == right.dst_addr &&
           left.negate_src_port == right.negate_src_port &&
           left.negate_dst_port == right.negate_dst_port &&
           left.negate_src_addr == right.negate_src_addr &&
           left.negate_dst_addr == right.negate_dst_addr;
}

inline bool firewall_rule_states_equal(const RuleState& left,
                                       const RuleState& right) noexcept {
    // rule_index is deliberately excluded. Inserting an unrelated rule above
    // an existing one must not make every following rule look changed and
    // trigger a broad reconnect storm.
    return left.list_names == right.list_names &&
           left.set_names == right.set_names &&
           left.outbound_tag == right.outbound_tag &&
           left.action_type == right.action_type &&
           left.fwmark == right.fwmark &&
           firewall_criteria_equal(left.criteria, right.criteria);
}

// Destination-based conntrack cleanup cannot preserve selectors that are not
// expressible by `conntrack -D -d`.  Restrict it to broad, positive
// destination rules so source-, protocol-, port-, and DSCP-scoped traffic is
// never disconnected as collateral damage.
inline bool destination_only_conntrack_cleanup_eligible(
    const RuleState& rule) noexcept {
    if (rule.action_type == RuleActionType::Skip ||
        rule.action_type == RuleActionType::Pass) {
        return false;
    }

    const auto& criteria = rule.criteria;
    const bool has_positive_destination =
        !rule.list_names.empty() ||
        criteria.dst_set_name.has_value() ||
        !criteria.dst_addr.empty();
    // A list and dst_addr on the same rule are an intersection in the
    // firewall. `conntrack -D` cannot express that intersection without
    // expanding both sets, so treating the two selectors as a union would
    // disconnect unrelated flows.
    const bool has_mixed_destination_selectors =
        (!rule.list_names.empty() || criteria.dst_set_name.has_value()) &&
        !criteria.dst_addr.empty();
    return has_positive_destination &&
           !has_mixed_destination_selectors &&
           !criteria.src_udp_peer_set_name.has_value() &&
           !criteria.dscp.has_value() &&
           criteria.proto == L4Proto::Any &&
           criteria.src_port.empty() &&
           criteria.dst_port.empty() &&
           criteria.src_addr.empty() &&
           !criteria.negate_src_port &&
           !criteria.negate_dst_port &&
           !criteria.negate_src_addr &&
           !criteria.negate_dst_addr;
}

} // namespace runtime_recovery_detail

// Limit continuous reconnect observation to selected lists that are actually
// referenced by a committed, realized mark rule.  A configured list alone is
// not evidence that any live traffic can reach the corresponding outbound:
// it may be unused, disabled (Skip), pass-through, blackholed, or combined
// with selectors that destination-only conntrack cleanup cannot reproduce.
inline std::set<std::string>
active_destination_only_reconnect_list_names(
    const std::set<std::string>& selected_list_names,
    const std::vector<RuleState>& committed_rules) {
    std::set<std::string> active;
    if (selected_list_names.empty()) {
        return active;
    }

    for (const auto& rule : committed_rules) {
        if (rule.action_type != RuleActionType::Mark ||
            rule.fwmark == 0U ||
            !runtime_recovery_detail::
                destination_only_conntrack_cleanup_eligible(rule)) {
            continue;
        }

        for (const auto& list_name : rule.list_names) {
            if (selected_list_names.find(list_name) !=
                selected_list_names.end()) {
                active.insert(list_name);
            }
        }
    }
    return active;
}

struct ConntrackDestinationRetirementPlan {
    std::set<std::string> current_list_names;
    std::vector<std::string> current_destination_selectors;
};

struct ConntrackDestinationRetirementCoverage {
    std::vector<std::string> destination_selectors;
    // Dynamic DNS-derived members are not available through ListStreamer, and
    // bounded static tracking deliberately retains only its first selectors.
    // Callers expose this as quiet diagnostics; neither limitation justifies a
    // global conntrack flush.
    std::set<std::string> domain_backed_list_names;
    std::set<std::string> truncated_static_list_names;

    bool partial() const noexcept {
        return !domain_backed_list_names.empty() ||
               !truncated_static_list_names.empty();
    }
};

enum class RuntimeReconnectCommitState : std::uint8_t {
    committed,
    failed,
    rolled_back,
};

enum class StaleFlowReconnectExecution : std::uint8_t {
    completed,
    skipped_not_committed,
    skipped_inactive_runtime,
    skipped_invalid_generation,
    skipped_stale_generation,
    skipped_empty_plan,
    skipped_inexact_forwarded_scope,
    skipped_global_destination_scope,
    skipped_generation_changed,
    failed,
};

struct StaleFlowReconnectRequest {
    std::uint64_t expected_runtime_generation{0};
    ConntrackDestinationRetirementCoverage normal;
    ConntrackDestinationRetirementCoverage aggressive;
    // Destination selectors alone cannot preserve source-, protocol-, or
    // port-scoped inbound policies. Callers must opt in only after proving
    // that the live forwarded-flow scope is representable exactly.
    bool exact_forwarded_scope{false};

    bool empty() const noexcept {
        return normal.destination_selectors.empty() &&
               aggressive.destination_selectors.empty();
    }
};

namespace runtime_recovery_detail {

inline std::string_view trim_ascii_whitespace(
    std::string_view value) noexcept {
    constexpr std::string_view whitespace{" \t\r\n"};
    const auto first = value.find_first_not_of(whitespace);
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = value.find_last_not_of(whitespace);
    return value.substr(first, last - first + 1U);
}

inline bool is_global_destination_selector(
    std::string_view selector) noexcept {
    selector = trim_ascii_whitespace(selector);
    const auto slash = selector.rfind('/');
    if (slash == std::string_view::npos) {
        return false;
    }
    return trim_ascii_whitespace(selector.substr(slash + 1U)) == "0";
}

inline bool contains_global_destination_selector(
    const ConntrackDestinationRetirementCoverage& coverage) noexcept {
    return std::any_of(
        coverage.destination_selectors.begin(),
        coverage.destination_selectors.end(),
        [](const std::string& selector) {
            return is_global_destination_selector(selector);
        });
}

} // namespace runtime_recovery_detail

// Execute targeted stale-flow retirement only for the runtime generation that
// was successfully committed. Scope preparation may inspect live interfaces or
// conntrack state and therefore race with a newer apply; fence the generation
// both before and after preparation, before invoking the irreversible cleanup.
// The cleanup callback receives destination coverage only. There is no global
// flush mode, and /0 selectors are rejected explicitly.
template <typename IsRuntimeActive,
          typename CurrentGeneration,
          typename PrepareScope,
          typename Cleanup>
StaleFlowReconnectExecution run_stale_flow_reconnect_if_committed(
    RuntimeReconnectCommitState commit_state,
    const StaleFlowReconnectRequest& request,
    IsRuntimeActive&& is_runtime_active,
    CurrentGeneration&& current_generation,
    PrepareScope&& prepare_scope,
    Cleanup&& cleanup) noexcept {
    if (commit_state != RuntimeReconnectCommitState::committed) {
        return StaleFlowReconnectExecution::skipped_not_committed;
    }
    if (!request.exact_forwarded_scope) {
        return StaleFlowReconnectExecution::skipped_inexact_forwarded_scope;
    }
    if (request.empty()) {
        return StaleFlowReconnectExecution::skipped_empty_plan;
    }
    if (runtime_recovery_detail::contains_global_destination_selector(
            request.normal) ||
        runtime_recovery_detail::contains_global_destination_selector(
            request.aggressive)) {
        return StaleFlowReconnectExecution::
            skipped_global_destination_scope;
    }
    if (request.expected_runtime_generation == 0U) {
        return StaleFlowReconnectExecution::skipped_invalid_generation;
    }

    try {
        if (!is_runtime_active()) {
            return StaleFlowReconnectExecution::skipped_inactive_runtime;
        }
        if (current_generation() != request.expected_runtime_generation) {
            return StaleFlowReconnectExecution::skipped_stale_generation;
        }

        auto prepared_scope = prepare_scope();

        if (!is_runtime_active()) {
            return StaleFlowReconnectExecution::skipped_inactive_runtime;
        }
        if (current_generation() != request.expected_runtime_generation) {
            return StaleFlowReconnectExecution::skipped_generation_changed;
        }

        cleanup(prepared_scope, request);
        return StaleFlowReconnectExecution::completed;
    } catch (...) {
        return StaleFlowReconnectExecution::failed;
    }
}

inline std::set<std::string>
plan_conntrack_owned_destination_reconnect(
    const std::vector<RuleState>& previous_rules,
    const std::vector<RuleState>& current_rules,
    const std::set<std::string>& selected_list_names,
    const std::set<std::string>& changed_list_names = {},
    const std::set<std::string>& newly_enabled_list_names = {}) {
    using namespace runtime_recovery_detail;

    const auto relevant_rules = [](const std::vector<RuleState>& rules,
                                   const std::string& list_name) {
        std::vector<const RuleState*> result;
        for (const auto& rule : rules) {
            if (rule.action_type != RuleActionType::Mark ||
                std::find(
                    rule.list_names.begin(),
                    rule.list_names.end(),
                    list_name) == rule.list_names.end()) {
                continue;
            }
            result.push_back(&rule);
        }
        return result;
    };

    std::set<std::string> result;
    for (const auto& list_name : selected_list_names) {
        const auto previous = relevant_rules(previous_rules, list_name);
        const auto current = relevant_rules(current_rules, list_name);
        if (previous.empty() && current.empty()) continue;

        bool policy_changed = previous.size() != current.size();
        if (!policy_changed) {
            for (std::size_t index = 0; index < current.size(); ++index) {
                if (!firewall_rule_states_equal(
                        *previous[index], *current[index])) {
                    policy_changed = true;
                    break;
                }
            }
        }
        if (policy_changed ||
            changed_list_names.count(list_name) != 0U ||
            newly_enabled_list_names.count(list_name) != 0U) {
            result.insert(list_name);
        }
    }
    return result;
}

inline ConntrackDestinationRetirementPlan
destination_retirement_plan_for_lists(
    const std::set<std::string>& list_names) {
    ConntrackDestinationRetirementPlan plan;
    plan.current_list_names = list_names;
    return plan;
}

inline ConntrackDestinationRetirementCoverage
merge_conntrack_destination_retirement_coverage(
    ConntrackDestinationRetirementCoverage left,
    const ConntrackDestinationRetirementCoverage& right) {
    left.destination_selectors.insert(
        left.destination_selectors.end(),
        right.destination_selectors.begin(),
        right.destination_selectors.end());
    left.domain_backed_list_names.insert(
        right.domain_backed_list_names.begin(),
        right.domain_backed_list_names.end());
    left.truncated_static_list_names.insert(
        right.truncated_static_list_names.begin(),
        right.truncated_static_list_names.end());
    return left;
}

inline ConntrackDestinationRetirementPlan
plan_conntrack_destination_retirement(
    const std::vector<RuleState>& previous_rules,
    const std::vector<RuleState>& current_rules,
    const std::set<std::string>& changed_list_names = {}) {
    using namespace runtime_recovery_detail;
    ConntrackDestinationRetirementPlan plan;

    for (std::size_t index = 0; index < current_rules.size(); ++index) {
        const auto& current = current_rules[index];
        const bool existed_before = std::any_of(
            previous_rules.begin(),
            previous_rules.end(),
            [&current](const RuleState& previous) {
                return firewall_rule_states_equal(previous, current);
            });
        const bool referenced_list_changed = std::any_of(
            current.list_names.begin(), current.list_names.end(),
            [&changed_list_names](const std::string& list_name) {
                return changed_list_names.count(list_name) != 0U;
            });
        if (existed_before && !referenced_list_changed) {
            continue;
        }
        if (!destination_only_conntrack_cleanup_eligible(current)) {
            continue;
        }
        // A preceding pass rule can deliberately keep a subset of the same
        // destination direct. Destination-only conntrack deletion cannot
        // reproduce its source/protocol/port predicates, so fail closed rather
        // than interrupt an explicitly bypassed flow. Configurations without
        // an earlier pass (the common catalog/list path) still converge
        // immediately.
        const bool has_earlier_pass = std::any_of(
            current_rules.begin(),
            current_rules.begin() +
                static_cast<std::ptrdiff_t>(index),
            [](const RuleState& candidate) {
                return candidate.action_type == RuleActionType::Pass;
            });
        if (has_earlier_pass) {
            continue;
        }
        plan.current_list_names.insert(
            current.list_names.begin(), current.list_names.end());
        plan.current_destination_selectors.insert(
            plan.current_destination_selectors.end(),
            current.criteria.dst_addr.begin(),
            current.criteria.dst_addr.end());
    }

    return plan;
}

inline ConntrackDestinationRetirementCoverage
collect_conntrack_destination_retirement_coverage(
    const ConntrackDestinationRetirementPlan& plan,
    const AppliedListContentState& content_state) {
    ConntrackDestinationRetirementCoverage coverage;
    coverage.destination_selectors = plan.current_destination_selectors;
    for (const auto& list_name : plan.current_list_names) {
        const auto static_destinations =
            content_state.static_destinations.find(list_name);
        if (static_destinations != content_state.static_destinations.end()) {
            coverage.destination_selectors.insert(
                coverage.destination_selectors.end(),
                static_destinations->second.begin(),
                static_destinations->second.end());
        }
        if (content_state.domain_entry_lists.count(list_name) != 0U) {
            coverage.domain_backed_list_names.insert(list_name);
        }
        if (content_state.truncated_static_destination_lists.count(list_name) !=
            0U) {
            coverage.truncated_static_list_names.insert(list_name);
        }
    }
    return coverage;
}

// Snapshot of the policy which was actually committed to the kernel.  It is
// intentionally built from reconciler/controller state instead of comparing
// raw JSON, so cosmetic aliases and API/UI settings never disconnect users.
struct AppliedRoutingSignature {
    std::uint32_t owned_mask{0};
    std::vector<RuleState> firewall_rules;
};

inline constexpr std::array<std::chrono::milliseconds, 3>
    HOT_APPLY_FIREWALL_RETRY_DELAYS{
        std::chrono::milliseconds{100},
        std::chrono::milliseconds{200},
        std::chrono::milliseconds{400},
    };

template <typename Apply, typename Wait, typename OnRetry>
void retry_hot_apply_firewall(Apply&& apply,
                              Wait&& wait,
                              OnRetry&& on_retry) {
    for (std::size_t retry = 0;; ++retry) {
        try {
            apply();
            return;
        } catch (const TransientFirewallError& error) {
            if (retry >= HOT_APPLY_FIREWALL_RETRY_DELAYS.size()) {
                throw;
            }
            const auto delay = HOT_APPLY_FIREWALL_RETRY_DELAYS[retry];
            on_retry(retry + 1, delay, error);
            wait(delay);
        }
    }
}

// Replace a live runtime without first tearing down the generation which is
// currently forwarding traffic. Each stage must either reconcile in place or
// commit atomically. The caller remains responsible for publishing the new
// generation only after this function returns.
template <typename Reconcile,
          typename ApplyFirewall,
          typename Wait,
          typename OnRetry,
          typename ReloadResolver>
void apply_runtime_replacement(Reconcile&& reconcile,
                               ApplyFirewall&& apply_firewall,
                               Wait&& wait,
                               OnRetry&& on_retry,
                               ReloadResolver&& reload_resolver) {
    reconcile();
    retry_hot_apply_firewall(
        std::forward<ApplyFirewall>(apply_firewall),
        std::forward<Wait>(wait),
        std::forward<OnRetry>(on_retry));
    reload_resolver();
}

inline bool runtime_recovery_is_current(
    bool runtime_active,
    std::uint64_t expected_generation,
    std::uint64_t current_generation) noexcept {
    return runtime_active && expected_generation == current_generation;
}

inline bool deferred_runtime_mutation_intent_is_current(
    bool accepting_control_tasks,
    std::uint64_t expected_generation,
    std::uint64_t current_generation) noexcept {
    return accepting_control_tasks &&
           expected_generation == current_generation;
}

inline bool runtime_recovery_request_should_coalesce(
    std::size_t retry_attempt,
    bool retry_pending) noexcept {
    return retry_attempt == 0 && retry_pending;
}

struct RuntimeFirewallRetryPlan {
    bool schedule{false};
    bool maintenance{false};
    std::size_t next_attempt{0};
};

inline RuntimeFirewallRetryPlan plan_runtime_firewall_retry(
    std::size_t attempt,
    std::size_t bounded_retry_count,
    bool snat_recovery_requested,
    bool persistent_recovery_requested = false) noexcept {
    if (attempt < bounded_retry_count) {
        return RuntimeFirewallRetryPlan{
            /*schedule=*/true,
            /*maintenance=*/false,
            /*next_attempt=*/attempt + 1};
    }
    if (snat_recovery_requested || persistent_recovery_requested) {
        return RuntimeFirewallRetryPlan{
            /*schedule=*/true,
            /*maintenance=*/true,
            /*next_attempt=*/0};
    }
    return {};
}

struct OwnedConntrackCleanupSnapshot {
    std::uint64_t runtime_generation{0};
    std::uint32_t owned_mask{0};
    std::set<std::uint32_t> marks;
    std::set<std::uint32_t> priority_marks;
    bool ipv6_enabled{true};

    bool valid() const noexcept {
        return runtime_generation != 0 &&
               owned_mask != 0 &&
               !marks.empty();
    }
};

struct OwnedConntrackCleanupRetry {
    OwnedConntrackCleanupSnapshot snapshot;
    std::vector<std::uint32_t> ordered_marks;
    std::size_t no_progress_attempt{0};

    bool valid() const noexcept {
        return snapshot.valid() && !ordered_marks.empty();
    }
};

inline bool owned_conntrack_cleanup_retry_is_current(
    bool routing_runtime_active,
    const OwnedConntrackCleanupRetry& retry,
    std::uint64_t current_generation) noexcept {
    return routing_runtime_active &&
           retry.valid() &&
           retry.snapshot.runtime_generation == current_generation;
}

inline OwnedConntrackCleanupSnapshot merge_owned_conntrack_cleanup_snapshot(
    OwnedConntrackCleanupSnapshot left,
    OwnedConntrackCleanupSnapshot right) {
    if (!left.valid()) {
        return right;
    }
    if (!right.valid()) {
        return left;
    }
    // A newer runtime generation may reuse the same numerical mark for a
    // different outbound. Never carry an older generation's cleanup selector
    // into the current configuration.
    if (left.runtime_generation != right.runtime_generation ||
        left.owned_mask != right.owned_mask) {
        return left.runtime_generation > right.runtime_generation
            ? left
            : right;
    }
    left.marks.insert(right.marks.begin(), right.marks.end());
    left.priority_marks.insert(
        right.priority_marks.begin(), right.priority_marks.end());
    left.ipv6_enabled = left.ipv6_enabled || right.ipv6_enabled;
    return left;
}

struct OwnedSnatRecovery {
    bool requested{false};
    bool missing_observed{false};
    std::optional<OwnedConntrackCleanupSnapshot> cleanup_snapshot;
};

inline OwnedSnatRecovery observe_owned_snat_state(
    OwnedSnatRecovery recovery,
    OwnedSnatState state,
    std::optional<OwnedConntrackCleanupSnapshot> cleanup_snapshot =
        std::nullopt) {
    recovery.missing_observed =
        recovery.missing_observed ||
        state == OwnedSnatState::missing;
    if (state == OwnedSnatState::missing &&
        cleanup_snapshot.has_value() &&
        cleanup_snapshot->valid()) {
        if (recovery.cleanup_snapshot.has_value()) {
            recovery.cleanup_snapshot =
                merge_owned_conntrack_cleanup_snapshot(
                    std::move(*recovery.cleanup_snapshot),
                    std::move(*cleanup_snapshot));
        } else {
            recovery.cleanup_snapshot = std::move(cleanup_snapshot);
        }
    }
    return recovery;
}

inline OwnedSnatRecovery merge_owned_snat_recovery(
    OwnedSnatRecovery left,
    OwnedSnatRecovery right) {
    std::optional<OwnedConntrackCleanupSnapshot> cleanup_snapshot;
    if (left.cleanup_snapshot.has_value() &&
        right.cleanup_snapshot.has_value()) {
        cleanup_snapshot = merge_owned_conntrack_cleanup_snapshot(
            std::move(*left.cleanup_snapshot),
            std::move(*right.cleanup_snapshot));
    } else if (left.cleanup_snapshot.has_value()) {
        cleanup_snapshot = std::move(left.cleanup_snapshot);
    } else if (right.cleanup_snapshot.has_value()) {
        cleanup_snapshot = std::move(right.cleanup_snapshot);
    }
    return OwnedSnatRecovery{
        left.requested || right.requested,
        left.missing_observed || right.missing_observed,
        std::move(cleanup_snapshot),
    };
}

struct RuntimeFirewallRetryAdmission {
    bool coalesced{false};
    OwnedSnatRecovery snat_recovery;
};

enum class RuntimeFirewallOperationPhase : std::uint8_t {
    timer_pending,
    worker_queued,
    worker_running,
    control_pending,
};

// Small ownership token passed across the timer, worker and control-loop
// boundaries. Heavy immutable inputs/results stay in the corresponding
// closures; this claim only proves which logical operation owns the single
// retry slot and which hand-off phase may run next.
struct RuntimeFirewallOperationClaim {
    std::uint64_t serial{0};
    std::uint64_t runtime_generation{0};
    std::size_t attempt{0};
    RuntimeFirewallOperationPhase phase{
        RuntimeFirewallOperationPhase::timer_pending};

    explicit operator bool() const noexcept {
        return serial != 0U;
    }
};

// Control-loop-owned retry policy plus a mutex-protected cross-boundary claim
// for runtime routing/firewall reconciliation. The coordinator deliberately
// does not perform reconciliation itself: it only owns the single operation
// slot, its generation/attempt claim, and the latched owned-SNAT recovery
// request carried across coalesced attempts. The asynchronous API retains that
// slot through timer -> worker -> control; schedule()/defer_same_attempt()
// keep their original synchronous behavior.
class RuntimeFirewallRetryCoordinator {
public:
    RuntimeFirewallRetryAdmission begin_attempt(
        std::size_t retry_attempt,
        OwnedSnatRecovery snat_recovery) {
        pending_owned_snat_recovery_ = merge_owned_snat_recovery(
            std::move(pending_owned_snat_recovery_),
            std::move(snat_recovery));
        return RuntimeFirewallRetryAdmission{
            runtime_recovery_request_should_coalesce(
                retry_attempt, retry_pending()),
            pending_owned_snat_recovery_};
    }

    OwnedSnatRecovery retain_recovery(
        OwnedSnatRecovery snat_recovery) {
        pending_owned_snat_recovery_ = merge_owned_snat_recovery(
            std::move(pending_owned_snat_recovery_),
            std::move(snat_recovery));
        return pending_owned_snat_recovery_;
    }

    void complete_attempt(bool succeeded,
                          OwnedSnatRecovery snat_recovery) {
        const bool owned_recovery_completed =
            succeeded && snat_recovery.requested;
        (void)retain_recovery(std::move(snat_recovery));
        if (owned_recovery_completed) {
            pending_owned_snat_recovery_ = {};
        }
    }

    bool retry_pending() const noexcept {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        return active_schedule_serial_ != 0U;
    }

    bool owned_snat_recovery_pending() const noexcept {
        return pending_owned_snat_recovery_.requested;
    }

    bool route_unavailable_retry_required() const noexcept {
        return owned_snat_recovery_pending();
    }

    const OwnedSnatRecovery& pending_owned_snat_recovery() const noexcept {
        return pending_owned_snat_recovery_;
    }

    void clear_owned_snat_recovery() noexcept {
        pending_owned_snat_recovery_ = {};
    }

    template <typename Schedule, typename IsCurrent, typename RunAttempt>
    RuntimeFirewallRetryPlan schedule(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        std::size_t bounded_retry_count,
        OwnedSnatRecovery snat_recovery,
        Schedule&& schedule,
        IsCurrent&& is_current,
        RunAttempt&& run_attempt,
        bool persistent_recovery_requested = false) {
        return schedule_impl</*RetainOperationClaim=*/false>(
            attempt,
            runtime_generation,
            bounded_retry_count,
            std::move(snat_recovery),
            std::forward<Schedule>(schedule),
            std::forward<IsCurrent>(is_current),
            std::forward<RunAttempt>(run_attempt),
            persistent_recovery_requested);
    }

    // Asynchronous counterpart of schedule(). The timer callback receives a
    // worker_queued claim and the slot remains occupied until the caller walks
    // it through begin_worker(), begin_control() and complete_operation(), or
    // explicitly abandons it with cancel_operation().
    template <typename Schedule, typename IsCurrent, typename QueueOperation>
    RuntimeFirewallRetryPlan schedule_operation(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        std::size_t bounded_retry_count,
        OwnedSnatRecovery snat_recovery,
        Schedule&& schedule,
        IsCurrent&& is_current,
        QueueOperation&& queue_operation,
        bool persistent_recovery_requested = false) {
        return schedule_impl</*RetainOperationClaim=*/true>(
            attempt,
            runtime_generation,
            bounded_retry_count,
            std::move(snat_recovery),
            std::forward<Schedule>(schedule),
            std::forward<IsCurrent>(is_current),
            std::forward<QueueOperation>(queue_operation),
            persistent_recovery_requested);
    }

    // Admission contention is not a failed firewall attempt. Keep the exact
    // attempt number and retained recovery payload in the coordinator's one
    // timer slot, then retry only after the generation fence still matches.
    // This is deliberately separate from schedule(): it must not advance the
    // bounded retry budget or manufacture an incident merely because another
    // admitted runtime writer was active.
    template <typename Schedule, typename IsCurrent, typename RunAttempt>
    bool defer_same_attempt(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        OwnedSnatRecovery snat_recovery,
        Schedule&& schedule,
        IsCurrent&& is_current,
        RunAttempt&& run_attempt) {
        return defer_same_attempt_impl</*RetainOperationClaim=*/false>(
            attempt,
            runtime_generation,
            std::move(snat_recovery),
            std::forward<Schedule>(schedule),
            std::forward<IsCurrent>(is_current),
            std::forward<RunAttempt>(run_attempt));
    }

    // Admission-contention counterpart of schedule_operation(). It preserves
    // the exact attempt and recovery payload just like defer_same_attempt(),
    // but retains the operation claim after the timer fires.
    template <typename Schedule, typename IsCurrent, typename QueueOperation>
    bool defer_same_attempt_operation(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        OwnedSnatRecovery snat_recovery,
        Schedule&& schedule,
        IsCurrent&& is_current,
        QueueOperation&& queue_operation) {
        return defer_same_attempt_impl</*RetainOperationClaim=*/true>(
            attempt,
            runtime_generation,
            std::move(snat_recovery),
            std::forward<Schedule>(schedule),
            std::forward<IsCurrent>(is_current),
            std::forward<QueueOperation>(queue_operation));
    }

    std::optional<RuntimeFirewallOperationClaim> begin_worker(
        RuntimeFirewallOperationClaim claim) noexcept {
        return transition_operation(
            claim,
            RuntimeFirewallOperationPhase::worker_queued,
            RuntimeFirewallOperationPhase::worker_running);
    }

    std::optional<RuntimeFirewallOperationClaim> begin_control(
        RuntimeFirewallOperationClaim claim) noexcept {
        return transition_operation(
            claim,
            RuntimeFirewallOperationPhase::worker_running,
            RuntimeFirewallOperationPhase::control_pending);
    }

    bool operation_is_current(
        RuntimeFirewallOperationClaim claim) const noexcept {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        return operation_matches_locked(claim);
    }

    bool complete_operation(
        RuntimeFirewallOperationClaim claim) noexcept {
        if (claim.phase != RuntimeFirewallOperationPhase::control_pending) {
            return false;
        }
        return release_retry_slot_if_current(claim);
    }

    // Cancellation is terminal from any exact phase. Reusing an older phase
    // copy of a live claim is rejected, so a producer cannot accidentally
    // retire work already owned by the next boundary.
    bool cancel_operation(
        RuntimeFirewallOperationClaim claim) noexcept {
        return release_retry_slot_if_current(claim);
    }

    template <typename Cancel>
    void cancel(Cancel&& cancel) {
        int task_id = -1;
        {
            std::lock_guard<std::mutex> lock(operation_mutex_);
            if (active_schedule_serial_ == 0U) {
                return;
            }
            if (active_operation_phase_ ==
                RuntimeFirewallOperationPhase::timer_pending) {
                task_id = retry_task_id_;
            }
            // Invalidate first. Scheduler::cancel may erase the entry and then
            // throw while unregistering its fd; keeping a ghost task id would
            // make every periodic recovery owner believe a retry is armed
            // forever. Later phases have no live timer id, but are invalidated
            // by the same serial before their queued callbacks can publish.
            release_retry_slot_locked();
            (void)next_schedule_serial_locked();
        }
        if (task_id >= 0) {
            std::forward<Cancel>(cancel)(task_id);
        }
    }

private:
    enum class TimerTaskRegistration : std::uint8_t {
        consumed,
        installed,
        rejected,
    };

    template <bool RetainOperationClaim,
              typename Schedule,
              typename IsCurrent,
              typename RunAttempt>
    RuntimeFirewallRetryPlan schedule_impl(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        std::size_t bounded_retry_count,
        OwnedSnatRecovery snat_recovery,
        Schedule&& schedule,
        IsCurrent&& is_current,
        RunAttempt&& run_attempt,
        bool persistent_recovery_requested) {
        // The coordinator owns the recovery latch, so callers cannot
        // accidentally downgrade an exhausted owned-SNAT recovery to a
        // finished generic retry by passing an empty or stale payload.
        snat_recovery = retain_recovery(std::move(snat_recovery));
        if (retry_pending()) {
            return {};
        }

        const auto retry_plan = plan_runtime_firewall_retry(
            attempt,
            bounded_retry_count,
            snat_recovery.requested,
            persistent_recovery_requested);
        if (!retry_plan.schedule) {
            return retry_plan;
        }

        const auto operation_claim = reserve_retry_slot(
            runtime_generation, retry_plan.next_attempt);
        if (!operation_claim) {
            return {};
        }
        auto scheduled_recovery = std::move(snat_recovery);
        try {
            const int task_id = std::forward<Schedule>(schedule)(
                retry_plan,
                [this,
                 operation_claim,
                 snat_recovery = std::move(scheduled_recovery),
                 is_current = std::forward<IsCurrent>(is_current),
                 run_attempt = std::forward<RunAttempt>(run_attempt)]()
                    mutable {
                    if constexpr (RetainOperationClaim) {
                        auto queued_claim = transition_operation(
                            operation_claim,
                            RuntimeFirewallOperationPhase::timer_pending,
                            RuntimeFirewallOperationPhase::worker_queued);
                        if (!queued_claim.has_value()) {
                            return;
                        }
                        try {
                            if (!is_current(
                                    queued_claim->runtime_generation)) {
                                (void)cancel_operation(*queued_claim);
                                return;
                            }
                            run_attempt(
                                *queued_claim, std::move(snat_recovery));
                        } catch (...) {
                            (void)cancel_operation_identity_if_current(
                                *queued_claim);
                            throw;
                        }
                    } else {
                        // Compatibility path: release before either the stale
                        // fence or the synchronous callback, preserving the
                        // original reentrant-successor behavior.
                        if (!release_retry_slot_if_current(
                                operation_claim)) {
                            return;
                        }
                        if (!is_current(
                                operation_claim.runtime_generation)) {
                            return;
                        }
                        run_attempt(
                            operation_claim.attempt,
                            std::move(snat_recovery));
                    }
                });
            // Scheduler hooks may synchronously consume a ready timer. Do not
            // resurrect a completed slot, or attach its id after ownership has
            // already moved to a worker.
            (void)register_timer_task_if_current(
                operation_claim, task_id);
        } catch (...) {
            (void)cancel_operation_identity_if_current(operation_claim);
            throw;
        }
        return retry_plan;
    }

    template <bool RetainOperationClaim,
              typename Schedule,
              typename IsCurrent,
              typename RunAttempt>
    bool defer_same_attempt_impl(
        std::size_t attempt,
        std::uint64_t runtime_generation,
        OwnedSnatRecovery snat_recovery,
        Schedule&& schedule,
        IsCurrent&& is_current,
        RunAttempt&& run_attempt) {
        snat_recovery = retain_recovery(std::move(snat_recovery));
        if (retry_pending()) {
            return false;
        }

        const auto operation_claim = reserve_retry_slot(
            runtime_generation, attempt);
        if (!operation_claim) {
            return false;
        }
        auto scheduled_recovery = std::move(snat_recovery);
        bool accepted = true;
        try {
            const int task_id = std::forward<Schedule>(schedule)(
                [this,
                 operation_claim,
                 snat_recovery = std::move(scheduled_recovery),
                 is_current = std::forward<IsCurrent>(is_current),
                 run_attempt = std::forward<RunAttempt>(run_attempt)]()
                    mutable {
                    if constexpr (RetainOperationClaim) {
                        auto queued_claim = transition_operation(
                            operation_claim,
                            RuntimeFirewallOperationPhase::timer_pending,
                            RuntimeFirewallOperationPhase::worker_queued);
                        if (!queued_claim.has_value()) {
                            return;
                        }
                        try {
                            if (!is_current(
                                    queued_claim->runtime_generation)) {
                                (void)cancel_operation(*queued_claim);
                                return;
                            }
                            run_attempt(
                                *queued_claim, std::move(snat_recovery));
                        } catch (...) {
                            (void)cancel_operation_identity_if_current(
                                *queued_claim);
                            throw;
                        }
                    } else {
                        if (!release_retry_slot_if_current(
                                operation_claim)) {
                            return;
                        }
                        if (!is_current(
                                operation_claim.runtime_generation)) {
                            return;
                        }
                        run_attempt(
                            operation_claim.attempt,
                            std::move(snat_recovery));
                    }
                });
            const auto registration = register_timer_task_if_current(
                operation_claim, task_id);
            if (registration == TimerTaskRegistration::rejected) {
                accepted = false;
            }
        } catch (...) {
            (void)cancel_operation_identity_if_current(operation_claim);
            throw;
        }
        return accepted;
    }

    RuntimeFirewallOperationClaim reserve_retry_slot(
        std::uint64_t runtime_generation,
        std::size_t attempt) noexcept {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        if (active_schedule_serial_ != 0U) {
            return {};
        }
        active_schedule_serial_ = next_schedule_serial_locked();
        active_operation_generation_ = runtime_generation;
        active_operation_attempt_ = attempt;
        active_operation_phase_ =
            RuntimeFirewallOperationPhase::timer_pending;
        retry_task_id_ = -1;
        return RuntimeFirewallOperationClaim{
            active_schedule_serial_,
            runtime_generation,
            attempt,
            RuntimeFirewallOperationPhase::timer_pending};
    }

    std::optional<RuntimeFirewallOperationClaim> transition_operation(
        RuntimeFirewallOperationClaim claim,
        RuntimeFirewallOperationPhase expected,
        RuntimeFirewallOperationPhase next) noexcept {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        if (claim.phase != expected ||
            !operation_matches_locked(claim)) {
            return std::nullopt;
        }
        active_operation_phase_ = next;
        retry_task_id_ = -1;
        claim.phase = next;
        return claim;
    }

    TimerTaskRegistration register_timer_task_if_current(
        RuntimeFirewallOperationClaim claim,
        int task_id) noexcept {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        if (!operation_matches_locked(claim)) {
            return TimerTaskRegistration::consumed;
        }
        if (task_id < 0) {
            release_retry_slot_locked();
            return TimerTaskRegistration::rejected;
        }
        retry_task_id_ = task_id;
        return TimerTaskRegistration::installed;
    }

    std::uint64_t next_schedule_serial_locked() noexcept {
        ++schedule_serial_;
        if (schedule_serial_ == 0U) ++schedule_serial_;
        return schedule_serial_;
    }

    bool release_retry_slot_if_current(
        RuntimeFirewallOperationClaim claim) noexcept {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        if (!operation_matches_locked(claim)) return false;
        release_retry_slot_locked();
        return true;
    }

    bool operation_matches_locked(
        RuntimeFirewallOperationClaim claim) const noexcept {
        return claim &&
               active_schedule_serial_ == claim.serial &&
               active_operation_generation_ == claim.runtime_generation &&
               active_operation_attempt_ == claim.attempt &&
               active_operation_phase_ == claim.phase;
    }

    bool cancel_operation_identity_if_current(
        RuntimeFirewallOperationClaim claim) noexcept {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        if (!claim ||
            active_schedule_serial_ != claim.serial ||
            active_operation_generation_ != claim.runtime_generation ||
            active_operation_attempt_ != claim.attempt) {
            return false;
        }
        release_retry_slot_locked();
        return true;
    }

    void release_retry_slot_locked() noexcept {
        active_schedule_serial_ = 0U;
        retry_task_id_ = -1;
    }

    mutable std::mutex operation_mutex_;
    int retry_task_id_{-1};
    std::uint64_t schedule_serial_{0};
    std::uint64_t active_schedule_serial_{0};
    std::uint64_t active_operation_generation_{0};
    std::size_t active_operation_attempt_{0};
    RuntimeFirewallOperationPhase active_operation_phase_{
        RuntimeFirewallOperationPhase::timer_pending};
    OwnedSnatRecovery pending_owned_snat_recovery_;
};

// A transient URLTEST publication failure leaves the last committed cursor
// authoritative, but the complete routing/firewall generation must be
// reconciled before another selector is allowed to publish. Keep the exact
// affected selector set so one trailing health probe can be requested after
// verified recovery. A later runtime generation cannot release an older gate.
class UrltestAfterFirewallRecoveryGate {
public:
    void wait_for(std::uint64_t runtime_generation,
                  const std::string& urltest_tag) {
        if (!waiting_for(runtime_generation)) {
            std::set<std::string> replacement;
            replacement.insert(urltest_tag);
            tags_.swap(replacement);
            runtime_generation_ = runtime_generation;
            return;
        }
        tags_.insert(urltest_tag);
    }

    bool waiting_for(std::uint64_t runtime_generation) const noexcept {
        return runtime_generation_.has_value() &&
               *runtime_generation_ == runtime_generation;
    }

    std::set<std::string> pending_tags(
        std::uint64_t runtime_generation) const {
        if (!waiting_for(runtime_generation)) return {};
        return tags_;
    }

    std::set<std::string> release(
        std::uint64_t runtime_generation) noexcept {
        if (!waiting_for(runtime_generation)) {
            return {};
        }
        runtime_generation_.reset();
        return std::move(tags_);
    }

    void reset() noexcept {
        runtime_generation_.reset();
        tags_.clear();
    }

private:
    std::optional<std::uint64_t> runtime_generation_;
    std::set<std::string> tags_;
};

// The resolver helper may stream a pinned immutable last-known-good
// generation while the lifecycle state remains visibly broken, but only if
// routing is still genuinely active. Stopped and shutting-down runtimes stay
// fail-closed even if an old snapshot remains in memory.
inline bool resolver_lkg_stream_available(
    RuntimeState runtime_state,
    bool routing_runtime_active,
    bool committed_snapshot_available,
    bool exact_activation_stream_authorized = false) noexcept {
    if (!committed_snapshot_available) {
        return false;
    }
    if (!routing_runtime_active) {
        // A stopped runtime normally fails closed.  The sole exception is the
        // exact committed generation being synchronously streamed as part of
        // a lifecycle activation.  The daemon owns that pointer-scoped token;
        // an old helper token or an arbitrary manual request cannot set it.
        return exact_activation_stream_authorized &&
               (runtime_state == RuntimeState::starting ||
                runtime_state == RuntimeState::applying);
    }
    return runtime_state != RuntimeState::stopped &&
           runtime_state != RuntimeState::shutting_down;
}

// Resolver recovery may depend on a firewall rollback that outlives the
// bounded retry timer. Keep that dependency as an explicit generation latch:
// an empty retry slot is not proof that the firewall converged.
class ResolverAfterFirewallRecoveryGate {
public:
    void wait_for(std::uint64_t runtime_generation) noexcept {
        runtime_generation_ = runtime_generation;
    }

    bool waiting_for(std::uint64_t runtime_generation) const noexcept {
        return runtime_generation_ == runtime_generation;
    }

    bool release(std::uint64_t runtime_generation) noexcept {
        if (!waiting_for(runtime_generation)) {
            return false;
        }
        runtime_generation_.reset();
        return true;
    }

    void reset() noexcept {
        runtime_generation_.reset();
    }

private:
    std::optional<std::uint64_t> runtime_generation_;
};

// A firmware NAT rebuild may remove keen-pbr's postrouting scaffold while
// leaving already-classified conntrack entries alive. Evict only our marked
// flows, and only after observing that a genuinely missing scaffold was
// restored successfully. The observation is retained across bounded retries:
// a successful COMMIT followed by a transient inspection error must not lose
// the reason why affected connections need to be retired. An inspection error
// by itself is deliberately not enough to disrupt established connections.
inline bool should_cleanup_conntrack_after_snat_repair(
    OwnedSnatRecovery recovery,
    OwnedSnatState after) noexcept {
    return recovery.requested &&
           recovery.missing_observed &&
           after == OwnedSnatState::healthy;
}

// The netfilter hook is the fast path, but firmware scripts may rebuild NAT
// without invoking it. A slow periodic guard repairs only a verified missing
// or stale owned scaffold. It deliberately ignores an inspection error and
// coalesces with every already pending repair path.
inline bool should_run_periodic_snat_repair(
    bool routing_runtime_active,
    bool recovery_pending,
    bool netfilter_refresh_pending,
    OwnedSnatState state) noexcept {
    return routing_runtime_active &&
           !recovery_pending &&
           !netfilter_refresh_pending &&
           (state == OwnedSnatState::missing ||
            state == OwnedSnatState::stale);
}

inline bool should_run_periodic_urltest_firewall_recovery(
    bool routing_runtime_active,
    bool urltest_recovery_pending,
    bool runtime_retry_pending,
    bool netfilter_refresh_pending) noexcept {
    return routing_runtime_active &&
           urltest_recovery_pending &&
           !runtime_retry_pending &&
           !netfilter_refresh_pending;
}

inline bool should_run_periodic_netfilter_refresh(
    bool retry_timer_armed,
    bool refresh_reason_pending) noexcept {
    return !retry_timer_armed && refresh_reason_pending;
}

// PPE liveness reuses the existing full netfilter refresh owner. It may
// request one only from the idle/active health window; pending recovery or a
// previously coalesced netfilter reason remains the sole owner of convergence.
inline bool should_schedule_periodic_ppe_full_refresh(
    bool routing_runtime_active,
    bool recovery_pending,
    bool netfilter_refresh_pending,
    bool automatic_mode,
    bool desired_contract_drift,
    bool live_graph_semantic_drift) noexcept {
    return routing_runtime_active &&
        !recovery_pending &&
        !netfilter_refresh_pending &&
        automatic_mode &&
        (desired_contract_drift || live_graph_semantic_drift);
}

// Interface/default-route and central-firewall notifications may arrive in a
// burst while the remote-access reconciler is already backing off. Let the
// armed generation-fenced timer own the next attempt instead of allowing each
// observation to consume another retry immediately. With no timer, startup or
// a newly persisted desired state is still reconciled without delay.
inline bool should_coalesce_remote_access_runtime_refresh(
    bool retry_timer_armed,
    bool locally_unscheduled_retry,
    bool desired_generation_present,
    bool pending_or_degraded,
    bool recovery_owned) noexcept {
    return desired_generation_present && pending_or_degraded &&
           (retry_timer_armed || locally_unscheduled_retry || recovery_owned);
}

// The handler retains a hint if dispatch into the daemon bridge fails. That
// hint is deliberately opaque to the daemon, so the periodic control-loop
// owner also recognizes the handler's explicit recovery-ownership bit.  The
// attempt counter is diagnostic only: a permanent failure can follow one or
// more transient attempts and must not be turned into endless maintenance.
inline bool should_run_periodic_remote_access_recovery(
    bool retry_timer_armed,
    bool locally_unscheduled_retry,
    bool desired_generation_present,
    bool recovery_owned) noexcept {
    return !retry_timer_armed && desired_generation_present &&
           (locally_unscheduled_retry || recovery_owned);
}

// epoll does not promise an ordering for descriptors returned in one batch.
// If signalfd was ready, the event loop dispatches it first and admits the
// remaining descriptors only when that priority pass did not request terminal
// shutdown.
inline bool event_batch_allows_non_signal_dispatch(
    bool signal_event_present,
    bool daemon_running_after_signal_dispatch) noexcept {
    return !signal_event_present || daemon_running_after_signal_dispatch;
}

inline bool should_run_periodic_forward_udp_reject_repair(
    bool routing_runtime_active,
    bool recovery_pending,
    bool netfilter_refresh_pending,
    bool messages_first_active,
    bool fastnat_disabled,
    OwnedForwardUdpRejectState state) noexcept {
    return routing_runtime_active &&
           !recovery_pending &&
           !netfilter_refresh_pending &&
           (state == OwnedForwardUdpRejectState::missing ||
            state == OwnedForwardUdpRejectState::stale ||
            (messages_first_active && !fastnat_disabled));
}

// Exact conntrack retirement is irreversible. Both the committed runtime
// generation and the policy-cleanup epoch must still match at every async
// boundary; a rollback or disable changes at least one of them. The initial
// delay is deliberately non-zero because timerfd interprets {0,0} as disarm.
inline bool meta_udp443_cleanup_authority_matches(
    std::uint64_t expected_runtime_generation,
    std::uint64_t current_runtime_generation,
    std::uint64_t expected_cleanup_epoch,
    std::uint64_t current_cleanup_epoch) noexcept {
    return expected_runtime_generation == current_runtime_generation &&
           expected_cleanup_epoch == current_cleanup_epoch;
}

inline bool should_resume_pending_meta_udp443_cleanup(
    bool messages_first_active,
    bool fastnat_disabled,
    OwnedForwardUdpRejectState filter_state,
    int scheduled_task_id,
    bool pending_plan_available,
    bool worker_inflight = false) noexcept {
    return messages_first_active && fastnat_disabled &&
           filter_state == OwnedForwardUdpRejectState::healthy &&
           scheduled_task_id < 0 && pending_plan_available &&
           !worker_inflight;
}

inline bool should_restore_pending_meta_udp443_cleanup_after_apply_failure(
    bool pending_plan_available,
    std::uint64_t pending_runtime_generation,
    std::uint64_t current_runtime_generation,
    bool replacement_meta_policy_may_have_changed) noexcept {
    return !replacement_meta_policy_may_have_changed &&
           pending_plan_available &&
           pending_runtime_generation == current_runtime_generation;
}

inline bool meta_udp443_publication_may_have_changed(
    std::uint64_t epoch_before_apply,
    std::uint64_t epoch_after_failure) noexcept {
    return epoch_before_apply != epoch_after_failure;
}

inline bool should_report_ambiguous_meta_udp443_publication_failure(
    bool replacement_meta_policy_committed,
    std::uint64_t epoch_before_apply,
    std::uint64_t epoch_after_failure) noexcept {
    return !replacement_meta_policy_committed &&
           meta_udp443_publication_may_have_changed(
               epoch_before_apply, epoch_after_failure);
}

inline bool should_retain_candidate_meta_udp443_cleanup_after_apply_failure(
    bool replacement_meta_policy_committed,
    bool candidate_plan_available) noexcept {
    return replacement_meta_policy_committed && candidate_plan_available;
}

inline bool netfilter_refresh_callback_is_current(
    std::uint64_t callback_serial,
    std::uint64_t current_serial) noexcept {
    return callback_serial == current_serial;
}

inline bool should_trigger_broad_urltest_probe_after_netfilter_refresh(
    bool runtime_refreshed,
    bool full_refresh,
    bool targeted_recovery_pending_before_refresh) noexcept {
    return runtime_refreshed && full_refresh &&
           !targeted_recovery_pending_before_refresh;
}

struct NetfilterRefreshSchedule {
    std::chrono::steady_clock::time_point batch_started_at;
    std::chrono::steady_clock::time_point due_at;
    std::chrono::milliseconds delay{0};
};

// Full/mangle rebuilds arrive in longer NDMS bursts than NAT-only rebuilds.
// Each observation gets a source-appropriate quiet window, but no event may
// move the current batch past its hard deadline.
inline NetfilterRefreshSchedule plan_netfilter_refresh(
    std::chrono::steady_clock::time_point now,
    std::optional<std::chrono::steady_clock::time_point> batch_started_at,
    bool full_refresh_pending) noexcept {
    constexpr auto full_quiet = std::chrono::milliseconds{750};
    constexpr auto nat_quiet = std::chrono::milliseconds{250};
    constexpr auto max_batch = std::chrono::milliseconds{2000};
    const auto started_at = batch_started_at.value_or(now);
    const auto quiet = full_refresh_pending ? full_quiet : nat_quiet;
    const auto due_at = std::min(now + quiet, started_at + max_batch);
    auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(
        due_at - now);
    if (now + delay < due_at) {
        delay += std::chrono::milliseconds{1};
    }
    // timerfd treats an all-zero it_value as disarmed. Preserve the hard
    // deadline to millisecond scheduler precision while always returning an
    // armed one-shot interval.
    if (delay < std::chrono::milliseconds{1}) {
        delay = std::chrono::milliseconds{1};
    }
    return NetfilterRefreshSchedule{started_at, due_at, delay};
}

inline bool meta_udp443_failed_completion_matches_pending(
    std::uint64_t failed_schedule_serial,
    std::uint64_t pending_schedule_serial) noexcept {
    return failed_schedule_serial != 0U &&
           failed_schedule_serial == pending_schedule_serial;
}

inline std::uint64_t newest_meta_udp443_failed_completion_serial(
    std::uint64_t published_serial,
    std::uint64_t candidate_serial) noexcept {
    return std::max(published_serial, candidate_serial);
}

inline void publish_newest_meta_udp443_failed_completion_serial(
    std::atomic<std::uint64_t>& published,
    std::uint64_t candidate_serial) noexcept {
    auto observed = published.load(std::memory_order_acquire);
    while (observed < candidate_serial &&
           !published.compare_exchange_weak(
               observed,
               newest_meta_udp443_failed_completion_serial(
                   observed, candidate_serial),
               std::memory_order_acq_rel,
               std::memory_order_acquire)) {
    }
}

inline constexpr std::chrono::milliseconds
meta_udp443_initial_cleanup_delay() noexcept {
    return std::chrono::milliseconds{1};
}

template <typename InvalidateCatalog,
          typename CancelRetry,
          typename ReconcileRuntime,
          typename RequestCatalogRefresh>
void recover_internal_vpn_after_observation_gap(
    InvalidateCatalog&& invalidate_catalog,
    CancelRetry&& cancel_retry,
    ReconcileRuntime&& reconcile_runtime,
    RequestCatalogRefresh&& request_catalog_refresh) {
    invalidate_catalog();
    cancel_retry();
    reconcile_runtime();
    request_catalog_refresh();
}

enum class ResolverReloadRetryOutcome : std::uint8_t {
    stale_generation,
    recovered,
    retry,
    exhausted,
};

// A failed resolver hook gets a short convergence window first.  Once that
// bounded budget is exhausted the work must remain live, but at a quiet,
// capped cadence: dnsmasq/NDMS can stay busy for considerably longer than the
// initial 31 seconds during a cold boot.  Attempts at or beyond the bounded
// array are deliberately collapsed onto one maintenance slot, so callers
// cannot turn a large/stale attempt counter into an out-of-range access or a
// progressively faster retry.
struct ResolverReloadRetryPlan {
    std::size_t attempt{0};
    std::chrono::seconds delay{0};
    bool maintenance{false};
};

template <std::size_t N>
ResolverReloadRetryPlan plan_resolver_reload_retry(
    std::size_t attempt,
    const std::array<std::chrono::seconds, N>& bounded_delays,
    std::chrono::seconds maintenance_delay) noexcept {
    if (attempt < N) {
        return {attempt, bounded_delays[attempt], false};
    }
    return {N, maintenance_delay, true};
}

// A timer publication failure must not terminate resolver recovery. The
// independent periodic runtime-health owner may consume only the retained
// work for the exact current generation and only after firewall recovery has
// released the resolver ordering gate.
inline bool should_run_periodic_resolver_reload_recovery(
    bool routing_runtime_active,
    bool retry_timer_armed,
    bool retry_pending,
    bool firewall_generation_waiting,
    std::uint64_t pending_generation,
    std::uint64_t current_generation) noexcept {
    return routing_runtime_active && !retry_timer_armed && retry_pending &&
           !firewall_generation_waiting && pending_generation != 0U &&
           pending_generation == current_generation;
}

inline constexpr std::string_view kResolverReloadPendingRuntimeReason =
    "runtime restart committed; resolver reload pending";
inline constexpr std::string_view kResolverReloadExhaustedRuntimeReason =
    "resolver reload recovery exhausted";
inline constexpr std::string_view kResolverReloadRecoveredRuntimeReason =
    "resolver reload recovery complete";

enum class ResolverRuntimeRecoveryAction : std::uint8_t {
    preserve,
    refresh_running_reason,
    recover_resolver_broken,
    // The resolver recovered, but another owner broke the runtime and still
    // owns it. Drop this chain's own latch and leave the runtime alone.
    clear_resolver_latch_only,
};

// RuntimeState::broken is shared by several independent recovery owners.  A
// successful dnsmasq stream may clear only the exact latch installed by this
// resolver chain; URLTEST/firewall/apply failures remain authoritative.
//
// `resolver_latched` is this chain's OWN record that it exhausted, kept
// separately from the shared runtime reason. It has to be separate: the
// exhaustion path publishes kResolverReloadExhaustedRuntimeReason only when it
// finds the runtime still `running`, so whenever anything else broke the
// runtime first - which is the ordinary case during boot, where urltest and
// firewall reconciliation fail seconds earlier - the resolver's reason is
// never written, and a recovery keyed solely on that reason could never fire
// again. Recording the latch independently restores it without ever letting
// the resolver clear a `broken` that belongs to someone else.
inline ResolverRuntimeRecoveryAction plan_resolver_runtime_recovery(
    bool routing_runtime_active,
    RuntimeState state,
    std::string_view reason,
    bool resolver_latched = false) noexcept {
    if (!routing_runtime_active) {
        return ResolverRuntimeRecoveryAction::preserve;
    }
    if (state == RuntimeState::broken &&
        reason == kResolverReloadExhaustedRuntimeReason) {
        return ResolverRuntimeRecoveryAction::recover_resolver_broken;
    }
    if (state == RuntimeState::running &&
        reason == kResolverReloadPendingRuntimeReason) {
        return ResolverRuntimeRecoveryAction::refresh_running_reason;
    }
    // Another owner holds the runtime. The resolver may retire only its own
    // latch, and the runtime stays broken until that owner recovers.
    if (resolver_latched && state == RuntimeState::broken) {
        return ResolverRuntimeRecoveryAction::clear_resolver_latch_only;
    }
    return ResolverRuntimeRecoveryAction::preserve;
}

// Why a resolver reload retry was not scheduled. Every one of these paths used
// to return silently, which is how a chain that stops retrying forever leaves
// no trace: the operator sees a resolver stuck on its fallback and a log that
// says nothing after the last bounded attempt.
enum class ResolverReloadScheduleDecline : std::uint8_t {
    scheduled,
    no_scheduler,
    already_scheduled,
    routing_inactive,
    generation_superseded,
};

inline ResolverReloadScheduleDecline classify_resolver_reload_schedule(
    bool scheduler_available,
    bool retry_already_scheduled,
    bool routing_runtime_active,
    std::uint64_t expected_generation,
    std::uint64_t current_generation) noexcept {
    if (!scheduler_available) {
        return ResolverReloadScheduleDecline::no_scheduler;
    }
    if (retry_already_scheduled) {
        return ResolverReloadScheduleDecline::already_scheduled;
    }
    if (!routing_runtime_active) {
        return ResolverReloadScheduleDecline::routing_inactive;
    }
    if (expected_generation != current_generation) {
        return ResolverReloadScheduleDecline::generation_superseded;
    }
    return ResolverReloadScheduleDecline::scheduled;
}

// Only `already_scheduled` is routine: the chain is armed, this call is a
// duplicate. The rest each mean no retry will happen from this call, and the
// operator has no other way to learn it.
inline bool resolver_reload_schedule_decline_is_notable(
    ResolverReloadScheduleDecline decline) noexcept {
    return decline != ResolverReloadScheduleDecline::scheduled &&
           decline != ResolverReloadScheduleDecline::already_scheduled;
}

// How a runtime state transition should reach the log. Every ownership change
// passes through one daemon choke point, and before that point logged
// anything the 12.08 boot incident was undiagnosable: the runtime was broken
// by 09:55:38 with five candidate owners, and not one had written its name
// anywhere - runtime reasons appeared in no log line at all.
enum class RuntimeTransitionLogSeverity : std::uint8_t {
    // Entering broken names the owner; leaving it names the recoverer. Both
    // are the lines an operator greps for first, so they must stand out.
    warn,
    info,
};

inline RuntimeTransitionLogSeverity classify_runtime_transition_log(
    const RuntimeState previous, const RuntimeState next) noexcept {
    return next == RuntimeState::broken ||
                   previous == RuntimeState::broken
               ? RuntimeTransitionLogSeverity::warn
               : RuntimeTransitionLogSeverity::info;
}

inline const char* resolver_reload_schedule_decline_name(
    ResolverReloadScheduleDecline decline) noexcept {
    switch (decline) {
    case ResolverReloadScheduleDecline::scheduled:
        return "scheduled";
    case ResolverReloadScheduleDecline::no_scheduler:
        return "no scheduler";
    case ResolverReloadScheduleDecline::already_scheduled:
        return "a retry is already armed";
    case ResolverReloadScheduleDecline::routing_inactive:
        return "routing runtime is not active";
    case ResolverReloadScheduleDecline::generation_superseded:
        return "runtime generation was superseded";
    }
    return "unknown";
}

template <typename Reload>
ResolverReloadRetryOutcome evaluate_resolver_reload_retry(
    bool runtime_active,
    std::uint64_t expected_generation,
    std::uint64_t current_generation,
    std::size_t attempt,
    std::size_t max_attempts,
    Reload&& reload) {
    if (!runtime_recovery_is_current(
            runtime_active, expected_generation, current_generation)) {
        return ResolverReloadRetryOutcome::stale_generation;
    }
    if (reload()) {
        return ResolverReloadRetryOutcome::recovered;
    }
    return attempt + 1 < max_attempts
        ? ResolverReloadRetryOutcome::retry
        : ResolverReloadRetryOutcome::exhausted;
}

class CoalescedSingleFlightGate {
public:
    bool request() noexcept {
        auto state = state_.load(std::memory_order_acquire);
        for (;;) {
            if ((state & kInFlight) != 0) {
                if ((state & kPending) != 0) {
                    return false;
                }
                if (state_.compare_exchange_weak(
                        state,
                        static_cast<std::uint8_t>(state | kPending),
                        std::memory_order_acq_rel,
                        std::memory_order_acquire)) {
                    return false;
                }
                continue;
            }

            if (state_.compare_exchange_weak(
                    state,
                    kInFlight,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                return true;
            }
        }
    }

    bool complete() noexcept {
        auto state = state_.load(std::memory_order_acquire);
        for (;;) {
            const bool rerun_requested = (state & kPending) != 0;
            if (state_.compare_exchange_weak(
                    state,
                    0,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                return rerun_requested;
            }
        }
    }

private:
    static constexpr std::uint8_t kInFlight = 1U;
    static constexpr std::uint8_t kPending = 2U;
    std::atomic<std::uint8_t> state_{0};
};

// Single-flight admission for a periodic operation which also has a manual
// "run now" caller. Repeated periodic requests collapse into one trailing
// run. A manual request remains observable as in-flight until that trailing
// run actually completes; the API must not accept a second click merely
// because the first request has only reached the blocking queue.
class CoalescedManualSingleFlightGate {
public:
    struct Admission {
        bool launch{false};
        bool manual_accepted{false};
    };

    struct Completion {
        bool launch_trailing{false};
        bool manual_completed{false};
    };

    Admission request(bool manual) noexcept {
        auto state = state_.load(std::memory_order_acquire);
        for (;;) {
            if (manual && (state & kManual) != 0) {
                return {};
            }

            const bool launch = (state & kInFlight) == 0;
            auto desired = state;
            if (launch) {
                desired = static_cast<std::uint8_t>(desired | kInFlight);
            } else {
                desired = static_cast<std::uint8_t>(desired | kPending);
            }
            if (manual) {
                desired = static_cast<std::uint8_t>(desired | kManual);
            }

            if (state_.compare_exchange_weak(
                    state,
                    desired,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                return Admission{launch, manual};
            }
        }
    }

    Completion complete() noexcept {
        auto state = state_.load(std::memory_order_acquire);
        for (;;) {
            const bool manual = (state & kManual) != 0;
            const bool trailing = (state & kPending) != 0;
            const auto desired = trailing
                ? static_cast<std::uint8_t>(kInFlight |
                                            (manual ? kManual : 0U))
                : static_cast<std::uint8_t>(0U);
            if (state_.compare_exchange_weak(
                    state,
                    desired,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                return Completion{trailing, manual && !trailing};
            }
        }
    }

    bool abort() noexcept {
        return (state_.exchange(0, std::memory_order_acq_rel) & kManual) != 0;
    }

    bool manual_inflight() const noexcept {
        return (state_.load(std::memory_order_acquire) & kManual) != 0;
    }

private:
    static constexpr std::uint8_t kInFlight = 1U;
    static constexpr std::uint8_t kPending = 2U;
    static constexpr std::uint8_t kManual = 4U;
    std::atomic<std::uint8_t> state_{0};
};

// Grants at most one immediate trailing round for a failed asynchronous
// publication/handoff. The retry round itself cannot recursively mint another
// retry, while a later independent round starts with a fresh allowance.
class OneTrailingFailureRetry {
public:
    bool request(bool current_round_is_retry,
                 bool eligible) noexcept {
        if (current_round_is_retry || !eligible) {
            return false;
        }
        bool expected = false;
        return pending_.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
    }

    bool consume_for_round() noexcept {
        return pending_.exchange(false, std::memory_order_acq_rel);
    }

    void clear() noexcept {
        pending_.store(false, std::memory_order_release);
    }

private:
    std::atomic<bool> pending_{false};
};

class RuntimeIncidentLatch {
public:
    struct Decision {
        std::size_t consecutive_failures{0};
        bool notify{false};
    };

    explicit RuntimeIncidentLatch(std::size_t notification_threshold)
        : notification_threshold_(notification_threshold) {}

    Decision record_failure(const std::string& key,
                            bool notify_immediately = false) {
        auto& count = failure_counts_[key];
        ++count;
        const bool threshold_reached =
            notify_immediately || count >= notification_threshold_;
        return {
            count,
            threshold_reached && notified_.insert(key).second,
        };
    }

    void reset(const std::string& key) {
        failure_counts_.erase(key);
        notified_.erase(key);
    }

    void clear() {
        failure_counts_.clear();
        notified_.clear();
    }

private:
    std::size_t notification_threshold_;
    std::map<std::string, std::size_t> failure_counts_;
    std::set<std::string> notified_;
};

} // namespace keen_pbr3
