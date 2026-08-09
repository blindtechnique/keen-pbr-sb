#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
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

inline std::set<std::string>
experimental_whatsapp_tcp_reset_sources(const Config& config) {
    const auto daemon = config.daemon.value_or(DaemonConfig{});
    if (!daemon.experimental_whatsapp_tcp_reset_sources.has_value()) {
        return {};
    }
    return {
        daemon.experimental_whatsapp_tcp_reset_sources->begin(),
        daemon.experimental_whatsapp_tcp_reset_sources->end()};
}

// Immutable provenance selector used by the independent experimental
// preventive observer. Unlike UDP call affinity, this does not inherit the
// strong-reconnect enable/selection switches: the new per-device opt-in is
// its own authority and still cannot admit copied or manually named lists.
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
// hold and allow signalling TCP to be reset. This authority exists only when
// at least one device explicitly opted in.
inline std::set<std::string>
preventive_whatsapp_media_guard_list_names(const Config& config) {
    if (experimental_whatsapp_tcp_reset_sources(config).empty()) {
        return {};
    }
    return packaged_whatsapp_ip_companion_list_names(config);
}

inline bool preventive_whatsapp_media_guard_available(
    FirewallBackend backend,
    bool iptables_pair_set_available) noexcept {
    return backend == FirewallBackend::iptables &&
           iptables_pair_set_available;
}

inline bool idle_stall_observer_requested(const Config& config) {
    return !experimental_whatsapp_tcp_reset_sources(config).empty() ||
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
    bool snat_recovery_requested) noexcept {
    if (attempt < bounded_retry_count) {
        return RuntimeFirewallRetryPlan{
            /*schedule=*/true,
            /*maintenance=*/false,
            /*next_attempt=*/attempt + 1};
    }
    if (snat_recovery_requested) {
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

// Event-loop-owned retry state for runtime routing/firewall reconciliation.
// The coordinator deliberately does not perform reconciliation itself: it
// only owns the single timer slot, its generation/attempt payload, and the
// latched owned-SNAT recovery request carried across coalesced attempts.
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
        return retry_task_id_ >= 0;
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
        RunAttempt&& run_attempt) {
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
            snat_recovery.requested);
        if (!retry_plan.schedule) {
            return retry_plan;
        }

        scheduled_runtime_generation_ = runtime_generation;
        scheduled_retry_attempt_ = retry_plan.next_attempt;
        scheduled_snat_recovery_ = std::move(snat_recovery);
        try {
            retry_task_id_ = std::forward<Schedule>(schedule)(
                retry_plan,
                [this,
                 is_current = std::forward<IsCurrent>(is_current),
                 run_attempt = std::forward<RunAttempt>(run_attempt)]()
                    mutable {
                    const auto retry_attempt = scheduled_retry_attempt_;
                    const auto runtime_generation =
                        scheduled_runtime_generation_;
                    auto snat_recovery = scheduled_snat_recovery_;

                    // Release the single-flight slot before either the stale
                    // fence or the attempt callback. A reentrant failure may
                    // therefore install its successor immediately.
                    release_retry_slot();
                    if (!is_current(runtime_generation)) {
                        return;
                    }
                    run_attempt(
                        retry_attempt, std::move(snat_recovery));
                });
        } catch (...) {
            release_retry_slot();
            throw;
        }
        if (retry_task_id_ < 0) {
            release_retry_slot();
        }
        return retry_plan;
    }

    template <typename Cancel>
    void cancel(Cancel&& cancel) {
        if (!retry_pending()) {
            return;
        }
        const int task_id = retry_task_id_;
        std::forward<Cancel>(cancel)(task_id);
        release_retry_slot();
    }

private:
    void release_retry_slot() noexcept {
        retry_task_id_ = -1;
        scheduled_runtime_generation_ = 0;
        scheduled_retry_attempt_ = 0;
        scheduled_snat_recovery_ = {};
    }

    int retry_task_id_{-1};
    std::uint64_t scheduled_runtime_generation_{0};
    std::size_t scheduled_retry_attempt_{0};
    OwnedSnatRecovery scheduled_snat_recovery_;
    OwnedSnatRecovery pending_owned_snat_recovery_;
};

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
