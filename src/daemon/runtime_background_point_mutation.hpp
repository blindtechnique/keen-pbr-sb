#pragma once

#include "runtime_recovery_policy.hpp"

#include "../firewall/firewall.hpp"
#include "../runtime/idle_stall_detector.hpp"
#include "../runtime/meta_udp_443_activation_plan.hpp"
#include "../runtime/udp_call_affinity.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace keen_pbr3 {

// These comparisons deliberately live at the ownership boundary instead of
// changing observer/runtime value types merely to make them transportable.
// They compare every field which can grant a physical mutation or consume an
// observer reservation.
inline bool runtime_background_same_udp_call_affinity_decision(
    const UdpCallAffinityDecision& left,
    const UdpCallAffinityDecision& right) noexcept {
    return left.family == right.family && left.source == right.source &&
           left.destination == right.destination &&
           left.destination_port == right.destination_port &&
           left.list_name == right.list_name && left.fwmark == right.fwmark &&
           left.baseline_flows == right.baseline_flows &&
           left.refresh_only == right.refresh_only &&
           left.confirmation_token == right.confirmation_token;
}

inline bool runtime_background_same_idle_stall_delete_decision(
    const IdleStallDeleteDecision& left,
    const IdleStallDeleteDecision& right) noexcept {
    return left.flow == right.flow && left.reason == right.reason &&
           left.epoch == right.epoch && left.attempt_id == right.attempt_id;
}

inline bool runtime_background_same_meta_udp443_activation_plan(
    const MetaUdp443ActivationPlan& left,
    const MetaUdp443ActivationPlan& right) noexcept {
    return left.expected_fwmark == right.expected_fwmark &&
           left.owned_mask == right.owned_mask &&
           left.cleanup_owned_marks == right.cleanup_owned_marks &&
           left.destination_selectors == right.destination_selectors &&
           left.ipv6_enabled == right.ipv6_enabled &&
           left.allow_unmarked_cleanup == right.allow_unmarked_cleanup &&
           left.exact_flows == right.exact_flows;
}

inline bool runtime_background_same_owned_conntrack_cleanup_retry(
    const OwnedConntrackCleanupRetry& left,
    const OwnedConntrackCleanupRetry& right) noexcept {
    return owned_conntrack_cleanup_snapshot_equal(left.snapshot,
                                                   right.snapshot) &&
           left.ordered_marks == right.ordered_marks &&
           left.no_progress_attempt == right.no_progress_attempt;
}

inline bool runtime_background_same_conntrack_cleanup_summary(
    const ConntrackCleanupSummary& left,
    const ConntrackCleanupSummary& right) noexcept {
    return left.failed == right.failed && left.skipped == right.skipped &&
           left.command_unavailable == right.command_unavailable &&
           left.budget_exhausted == right.budget_exhausted &&
           left.remaining_marks == right.remaining_marks;
}

inline bool runtime_background_same_exact_flow_cleanup_summary(
    const ConntrackExactFlowCleanupSummary& left,
    const ConntrackExactFlowCleanupSummary& right) noexcept {
    return left.attempted == right.attempted &&
           left.failed == right.failed &&
           left.command_unavailable == right.command_unavailable &&
           left.budget_exhausted == right.budget_exhausted &&
           left.batch_limit_reached == right.batch_limit_reached &&
           left.generation_changed == right.generation_changed &&
           left.remaining_flows == right.remaining_flows;
}

inline bool runtime_background_exact_flow_identity_valid(
    const ConntrackExactForwardedFlow& flow) noexcept {
    const bool family_valid =
        flow.family == ConntrackFlowFamily::Ipv4 ||
        flow.family == ConntrackFlowFamily::Ipv6;
    const bool protocol_valid =
        flow.protocol == ConntrackFlowProtocol::Tcp ||
        flow.protocol == ConntrackFlowProtocol::Udp;
    return family_valid && protocol_valid && !flow.source.empty() &&
           !flow.destination.empty() && flow.source_port != 0U &&
           flow.destination_port != 0U;
}

inline bool runtime_background_same_exact_flow_selector(
    const ConntrackExactForwardedFlow& left,
    const ConntrackExactForwardedFlow& right) noexcept {
    return left.family == right.family &&
           left.protocol == right.protocol && left.source == right.source &&
           left.destination == right.destination &&
           left.source_port == right.source_port &&
           left.destination_port == right.destination_port &&
           left.mark == right.mark;
}

inline bool runtime_background_udp_decision_valid(
    const UdpCallAffinityDecision& decision,
    std::uint32_t owned_mask) noexcept {
    if ((decision.family != ConntrackFlowFamily::Ipv4 &&
         decision.family != ConntrackFlowFamily::Ipv6) ||
        decision.source.empty() || decision.destination.empty() ||
        decision.destination_port == 0U || decision.list_name.empty() ||
        decision.fwmark == 0U || owned_mask == 0U ||
        (decision.fwmark & ~owned_mask) != 0U ||
        decision.confirmation_token == 0U ||
        decision.baseline_flows.empty()) {
        return false;
    }

    for (std::size_t index = 0U;
         index < decision.baseline_flows.size();
         ++index) {
        const auto& flow = decision.baseline_flows[index];
        const auto live_owned_mark = flow.mark & owned_mask;
        if (!runtime_background_exact_flow_identity_valid(flow) ||
            flow.family != decision.family ||
            flow.protocol != ConntrackFlowProtocol::Udp ||
            flow.source != decision.source ||
            flow.destination != decision.destination ||
            flow.destination_port != decision.destination_port ||
            flow.tcp_state.has_value() ||
            (decision.refresh_only
                 ? (live_owned_mark != 0U &&
                    live_owned_mark != decision.fwmark)
                 : live_owned_mark != 0U)) {
            return false;
        }
        if (decision.refresh_only &&
            (!flow.assured || !flow.seen_reply ||
             flow.original.packets == 0U || flow.reply.packets == 0U)) {
            return false;
        }
        for (std::size_t previous = 0U; previous < index; ++previous) {
            if (runtime_background_same_exact_flow_selector(
                    flow, decision.baseline_flows[previous])) {
                return false;
            }
        }
    }
    return true;
}

struct RuntimeUdpCallAffinityPointMutationWork final {
    UdpCallAffinityDecision decision;
    std::string set_name;

    bool valid(std::uint32_t owned_mask) const noexcept {
        return !set_name.empty() &&
               runtime_background_udp_decision_valid(decision, owned_mask);
    }

    bool operator==(
        const RuntimeUdpCallAffinityPointMutationWork& other) const noexcept {
        return set_name == other.set_name &&
               runtime_background_same_udp_call_affinity_decision(
                   decision, other.decision);
    }
};

struct RuntimeUdpCallAffinityPointMutationTarget final {
    std::uint64_t runtime_generation{0U};
    std::uint64_t coverage_generation{0U};
    std::uint32_t owned_mask{0U};
    bool ipv6_enabled{false};
    UdpCallAffinityDetector::TimePoint decision_deadline{};
    std::vector<RuntimeUdpCallAffinityPointMutationWork> work;

    bool valid() const noexcept {
        if (runtime_generation == 0U || coverage_generation == 0U ||
            owned_mask == 0U ||
            decision_deadline == UdpCallAffinityDetector::TimePoint{} ||
            work.empty()) {
            return false;
        }
        for (std::size_t index = 0U; index < work.size(); ++index) {
            if (!work[index].valid(owned_mask) ||
                (!ipv6_enabled &&
                 work[index].decision.family ==
                     ConntrackFlowFamily::Ipv6)) {
                return false;
            }
            for (std::size_t previous = 0U; previous < index; ++previous) {
                const auto& left = work[index].decision;
                const auto& right = work[previous].decision;
                if (left.confirmation_token == right.confirmation_token ||
                    std::tie(left.family,
                             left.source,
                             left.destination_port,
                             left.destination) ==
                        std::tie(right.family,
                                 right.source,
                                 right.destination_port,
                                 right.destination)) {
                    return false;
                }
            }
        }
        return true;
    }

    bool operator==(
        const RuntimeUdpCallAffinityPointMutationTarget& other) const {
        return runtime_generation == other.runtime_generation &&
               coverage_generation == other.coverage_generation &&
               owned_mask == other.owned_mask &&
               ipv6_enabled == other.ipv6_enabled &&
               decision_deadline == other.decision_deadline &&
               work == other.work;
    }
};

inline bool runtime_background_idle_flow_matches_decision(
    const IdleStallDeleteDecision& decision,
    const ConntrackExactForwardedFlow& flow,
    std::uint32_t owned_mask) noexcept {
    if (!decision.epoch.valid() || decision.attempt_id == 0U ||
        owned_mask == 0U ||
        decision.reason ==
            IdleStallDecisionReason::
                idle_packaged_whatsapp_tcp_reset_rotation ||
        !runtime_background_exact_flow_identity_valid(flow)) {
        return false;
    }
    const bool family_matches =
        (decision.flow.family == IdleStallAddressFamily::ipv4 &&
         flow.family == ConntrackFlowFamily::Ipv4) ||
        (decision.flow.family == IdleStallAddressFamily::ipv6 &&
         flow.family == ConntrackFlowFamily::Ipv6);
    const bool protocol_matches =
        (decision.flow.protocol == IdleStallProtocol::tcp &&
         flow.protocol == ConntrackFlowProtocol::Tcp) ||
        (decision.flow.protocol == IdleStallProtocol::udp &&
         flow.protocol == ConntrackFlowProtocol::Udp);
    const bool mark_valid =
        flow.mark == 0U ||
        ((flow.mark & owned_mask) != 0U &&
         (flow.mark & ~owned_mask) == 0U);
    const bool readiness_valid =
        (flow.protocol == ConntrackFlowProtocol::Tcp &&
         flow.tcp_state ==
             std::optional<ConntrackTcpState>{
                 ConntrackTcpState::Established}) ||
        (flow.protocol == ConntrackFlowProtocol::Udp &&
         !flow.tcp_state.has_value() && flow.assured);
    const bool fastnat_reason_valid =
        decision.reason !=
            IdleStallDecisionReason::idle_fastnat_rotation ||
        (flow.protocol == ConntrackFlowProtocol::Tcp && flow.fastnat);
    return family_matches && protocol_matches && mark_valid &&
           readiness_valid && fastnat_reason_valid &&
           decision.flow.source == flow.source &&
           decision.flow.destination == flow.destination &&
           decision.flow.source_port == flow.source_port &&
           decision.flow.destination_port == flow.destination_port &&
           decision.flow.full_mark == flow.mark;
}

struct RuntimeIdleStallExactCleanupPointMutationWork final {
    IdleStallDeleteDecision decision;
    ConntrackExactForwardedFlow flow;

    bool valid(std::uint64_t runtime_generation,
               std::uint64_t coverage_generation,
               std::uint32_t owned_mask) const noexcept {
        return decision.epoch.runtime_generation == runtime_generation &&
               decision.epoch.coverage_generation == coverage_generation &&
               runtime_background_idle_flow_matches_decision(
                   decision, flow, owned_mask);
    }

    bool operator==(
        const RuntimeIdleStallExactCleanupPointMutationWork& other) const
        noexcept {
        return runtime_background_same_idle_stall_delete_decision(
                   decision, other.decision) &&
               flow == other.flow;
    }
};

struct RuntimeIdleStallExactCleanupPointMutationTarget final {
    std::uint64_t runtime_generation{0U};
    std::uint64_t coverage_generation{0U};
    std::uint32_t owned_mask{0U};
    std::vector<RuntimeIdleStallExactCleanupPointMutationWork> work;

    bool valid() const noexcept {
        if (runtime_generation == 0U || coverage_generation == 0U ||
            owned_mask == 0U || work.empty()) {
            return false;
        }
        for (std::size_t index = 0U; index < work.size(); ++index) {
            if (!work[index].valid(runtime_generation,
                                   coverage_generation,
                                   owned_mask)) {
                return false;
            }
            for (std::size_t previous = 0U; previous < index; ++previous) {
                if (work[index].decision.attempt_id ==
                        work[previous].decision.attempt_id ||
                    runtime_background_same_exact_flow_selector(
                        work[index].flow, work[previous].flow)) {
                    return false;
                }
            }
        }
        return true;
    }

    bool operator==(
        const RuntimeIdleStallExactCleanupPointMutationTarget& other) const {
        return runtime_generation == other.runtime_generation &&
               coverage_generation == other.coverage_generation &&
               owned_mask == other.owned_mask && work == other.work;
    }
};

inline bool runtime_background_meta_flow_authorized(
    const ConntrackExactForwardedFlow& flow,
    const MetaUdp443ActivationPlan& plan) noexcept {
    if (!runtime_background_exact_flow_identity_valid(flow) ||
        flow.protocol != ConntrackFlowProtocol::Udp ||
        flow.destination_port != 443U || flow.tcp_state.has_value() ||
        (!plan.ipv6_enabled &&
         flow.family == ConntrackFlowFamily::Ipv6)) {
        return false;
    }
    const auto owned_mark = flow.mark & plan.owned_mask;
    return (owned_mark == 0U && flow.mark == 0U &&
            plan.allow_unmarked_cleanup) ||
           (owned_mark != 0U &&
            plan.cleanup_owned_marks.count(owned_mark) != 0U);
}

inline bool runtime_background_meta_plan_valid(
    const MetaUdp443ActivationPlan& plan) noexcept {
    if (plan.expected_fwmark == 0U || plan.owned_mask == 0U ||
        (plan.expected_fwmark & ~plan.owned_mask) != 0U ||
        plan.cleanup_owned_marks.count(plan.expected_fwmark) == 0U ||
        plan.destination_selectors.empty()) {
        return false;
    }
    if (std::any_of(
            plan.cleanup_owned_marks.begin(),
            plan.cleanup_owned_marks.end(),
            [&plan](std::uint32_t mark) {
                return mark == 0U || (mark & ~plan.owned_mask) != 0U;
            })) {
        return false;
    }
    std::set<std::string> selectors;
    for (const auto& selector : plan.destination_selectors) {
        if (selector.empty() || !selectors.insert(selector).second) {
            return false;
        }
    }
    for (std::size_t index = 0U;
         index < plan.exact_flows.size();
         ++index) {
        if (!runtime_background_meta_flow_authorized(
                plan.exact_flows[index], plan)) {
            return false;
        }
        for (std::size_t previous = 0U; previous < index; ++previous) {
            if (runtime_background_same_exact_flow_selector(
                    plan.exact_flows[index], plan.exact_flows[previous])) {
                return false;
            }
        }
    }
    return true;
}

struct RuntimeMetaUdp443CleanupPointMutationTarget final {
    std::uint64_t runtime_generation{0U};
    std::uint64_t cleanup_epoch{0U};
    std::size_t attempt{0U};
    MetaUdp443ActivationPlan plan;

    bool valid() const noexcept {
        return runtime_generation != 0U && cleanup_epoch != 0U &&
               runtime_background_meta_plan_valid(plan);
    }

    bool operator==(
        const RuntimeMetaUdp443CleanupPointMutationTarget& other) const
        noexcept {
        return runtime_generation == other.runtime_generation &&
               cleanup_epoch == other.cleanup_epoch &&
               attempt == other.attempt &&
               runtime_background_same_meta_udp443_activation_plan(
                   plan, other.plan);
    }
};

inline bool runtime_background_owned_cleanup_retry_valid(
    const OwnedConntrackCleanupRetry& retry) noexcept {
    if (!retry.valid() || retry.snapshot.priority_marks.size() >
                              retry.snapshot.marks.size()) {
        return false;
    }
    if (!std::includes(retry.snapshot.marks.begin(),
                       retry.snapshot.marks.end(),
                       retry.snapshot.priority_marks.begin(),
                       retry.snapshot.priority_marks.end())) {
        return false;
    }
    std::set<std::uint32_t> ordered;
    for (const auto mark : retry.ordered_marks) {
        if (mark == 0U ||
            (mark & ~retry.snapshot.owned_mask) != 0U ||
            !ordered.insert(mark).second) {
            return false;
        }
    }
    return ordered == retry.snapshot.marks;
}

struct RuntimeOwnedConntrackCleanupPointMutationTarget final {
    OwnedConntrackCleanupRetry retry;

    bool valid() const noexcept {
        return runtime_background_owned_cleanup_retry_valid(retry);
    }

    bool operator==(
        const RuntimeOwnedConntrackCleanupPointMutationTarget& other) const
        noexcept {
        return runtime_background_same_owned_conntrack_cleanup_retry(
            retry, other.retry);
    }
};

enum class RuntimeBackgroundPointMutationKind : std::uint8_t {
    udp_call_affinity,
    idle_stall_exact_cleanup,
    meta_udp443_cleanup,
    owned_conntrack_cleanup,
};

using RuntimeBackgroundPointMutationTargetPayload = std::variant<
    std::monostate,
    RuntimeUdpCallAffinityPointMutationTarget,
    RuntimeIdleStallExactCleanupPointMutationTarget,
    RuntimeMetaUdp443CleanupPointMutationTarget,
    RuntimeOwnedConntrackCleanupPointMutationTarget>;

struct RuntimeBackgroundPointMutationTarget final {
    RuntimeBackgroundPointMutationKind kind{
        RuntimeBackgroundPointMutationKind::udp_call_affinity};
    std::uint64_t target_serial{0U};
    RuntimeBackgroundPointMutationTargetPayload payload;

    std::uint64_t runtime_generation() const noexcept {
        switch (kind) {
        case RuntimeBackgroundPointMutationKind::udp_call_affinity:
            if (const auto* value = std::get_if<
                    RuntimeUdpCallAffinityPointMutationTarget>(&payload)) {
                return value->runtime_generation;
            }
            break;
        case RuntimeBackgroundPointMutationKind::idle_stall_exact_cleanup:
            if (const auto* value = std::get_if<
                    RuntimeIdleStallExactCleanupPointMutationTarget>(
                    &payload)) {
                return value->runtime_generation;
            }
            break;
        case RuntimeBackgroundPointMutationKind::meta_udp443_cleanup:
            if (const auto* value = std::get_if<
                    RuntimeMetaUdp443CleanupPointMutationTarget>(&payload)) {
                return value->runtime_generation;
            }
            break;
        case RuntimeBackgroundPointMutationKind::owned_conntrack_cleanup:
            if (const auto* value = std::get_if<
                    RuntimeOwnedConntrackCleanupPointMutationTarget>(
                    &payload)) {
                return value->retry.snapshot.runtime_generation;
            }
            break;
        }
        return 0U;
    }

    bool payload_kind_matches() const noexcept {
        switch (kind) {
        case RuntimeBackgroundPointMutationKind::udp_call_affinity:
            return std::holds_alternative<
                RuntimeUdpCallAffinityPointMutationTarget>(payload);
        case RuntimeBackgroundPointMutationKind::idle_stall_exact_cleanup:
            return std::holds_alternative<
                RuntimeIdleStallExactCleanupPointMutationTarget>(payload);
        case RuntimeBackgroundPointMutationKind::meta_udp443_cleanup:
            return std::holds_alternative<
                RuntimeMetaUdp443CleanupPointMutationTarget>(payload);
        case RuntimeBackgroundPointMutationKind::owned_conntrack_cleanup:
            return std::holds_alternative<
                RuntimeOwnedConntrackCleanupPointMutationTarget>(payload);
        }
        return false;
    }

    bool valid() const noexcept {
        if (target_serial == 0U || !payload_kind_matches()) {
            return false;
        }
        switch (kind) {
        case RuntimeBackgroundPointMutationKind::udp_call_affinity:
            return std::get<RuntimeUdpCallAffinityPointMutationTarget>(
                       payload)
                .valid();
        case RuntimeBackgroundPointMutationKind::idle_stall_exact_cleanup:
            return std::get<
                       RuntimeIdleStallExactCleanupPointMutationTarget>(
                       payload)
                .valid();
        case RuntimeBackgroundPointMutationKind::meta_udp443_cleanup:
            return std::get<RuntimeMetaUdp443CleanupPointMutationTarget>(
                       payload)
                .valid();
        case RuntimeBackgroundPointMutationKind::owned_conntrack_cleanup:
            return std::get<
                       RuntimeOwnedConntrackCleanupPointMutationTarget>(
                       payload)
                .valid();
        }
        return false;
    }

    bool operator==(
        const RuntimeBackgroundPointMutationTarget& other) const {
        if (kind != other.kind || target_serial != other.target_serial ||
            !payload_kind_matches() || !other.payload_kind_matches()) {
            return false;
        }
        switch (kind) {
        case RuntimeBackgroundPointMutationKind::udp_call_affinity:
            return std::get<RuntimeUdpCallAffinityPointMutationTarget>(
                       payload) ==
                   std::get<RuntimeUdpCallAffinityPointMutationTarget>(
                       other.payload);
        case RuntimeBackgroundPointMutationKind::idle_stall_exact_cleanup:
            return std::get<
                       RuntimeIdleStallExactCleanupPointMutationTarget>(
                       payload) ==
                   std::get<
                       RuntimeIdleStallExactCleanupPointMutationTarget>(
                       other.payload);
        case RuntimeBackgroundPointMutationKind::meta_udp443_cleanup:
            return std::get<RuntimeMetaUdp443CleanupPointMutationTarget>(
                       payload) ==
                   std::get<RuntimeMetaUdp443CleanupPointMutationTarget>(
                       other.payload);
        case RuntimeBackgroundPointMutationKind::owned_conntrack_cleanup:
            return std::get<
                       RuntimeOwnedConntrackCleanupPointMutationTarget>(
                       payload) ==
                   std::get<
                       RuntimeOwnedConntrackCleanupPointMutationTarget>(
                       other.payload);
        }
        return false;
    }

    bool operator!=(
        const RuntimeBackgroundPointMutationTarget& other) const {
        return !(*this == other);
    }
};

struct RuntimeUdpCallAffinityPointMutationOutcome final {
    UdpCallAffinityDecision decision;
    std::vector<ConntrackExactForwardedFlow> revalidated_flows;
    bool publication_attempted{false};
    bool installed{false};
    bool publication_ambiguous{false};
    bool revalidation_failed{false};
    bool deadline_expired{false};
    std::size_t retired_flows{0U};
    std::size_t failed_flows{0U};

    bool valid_for(
        const RuntimeUdpCallAffinityPointMutationWork& target,
        std::uint32_t owned_mask) const noexcept {
        if (!runtime_background_same_udp_call_affinity_decision(
                decision, target.decision) ||
            !runtime_background_udp_decision_valid(decision, owned_mask) ||
            (installed && !publication_attempted) ||
            (publication_ambiguous &&
             (!publication_attempted || installed)) ||
            (revalidation_failed && deadline_expired) ||
            ((!installed || decision.refresh_only) &&
             (!revalidated_flows.empty() || retired_flows != 0U ||
              failed_flows != 0U)) ||
            retired_flows + failed_flows > revalidated_flows.size()) {
            return false;
        }
        for (std::size_t index = 0U;
             index < revalidated_flows.size();
             ++index) {
            const auto& flow = revalidated_flows[index];
            const auto owned_mark = flow.mark & owned_mask;
            if (!runtime_background_exact_flow_identity_valid(flow) ||
                flow.family != decision.family ||
                flow.protocol != ConntrackFlowProtocol::Udp ||
                flow.source != decision.source ||
                flow.destination != decision.destination ||
                flow.destination_port != decision.destination_port ||
                (owned_mark != 0U && owned_mark != decision.fwmark)) {
                return false;
            }
            for (std::size_t previous = 0U; previous < index; ++previous) {
                if (runtime_background_same_exact_flow_selector(
                        flow, revalidated_flows[previous])) {
                    return false;
                }
            }
        }
        return true;
    }

    bool operator==(
        const RuntimeUdpCallAffinityPointMutationOutcome& other) const
        noexcept {
        return runtime_background_same_udp_call_affinity_decision(
                   decision, other.decision) &&
               revalidated_flows == other.revalidated_flows &&
               publication_attempted == other.publication_attempted &&
               installed == other.installed &&
               publication_ambiguous == other.publication_ambiguous &&
               revalidation_failed == other.revalidation_failed &&
               deadline_expired == other.deadline_expired &&
               retired_flows == other.retired_flows &&
               failed_flows == other.failed_flows;
    }
};

struct RuntimeUdpCallAffinityPointMutationResult final {
    std::vector<RuntimeUdpCallAffinityPointMutationOutcome> outcomes;
    bool conntrack_unavailable{false};

    bool valid_for(
        const RuntimeUdpCallAffinityPointMutationTarget& target) const
        noexcept {
        if (outcomes.size() != target.work.size()) {
            return false;
        }
        for (std::size_t index = 0U; index < outcomes.size(); ++index) {
            if (!outcomes[index].valid_for(target.work[index],
                                           target.owned_mask)) {
                return false;
            }
        }
        return true;
    }

    bool operator==(
        const RuntimeUdpCallAffinityPointMutationResult& other) const
        noexcept {
        return outcomes == other.outcomes &&
               conntrack_unavailable == other.conntrack_unavailable;
    }
};

struct RuntimeIdleStallExactCleanupPointMutationOutcome final {
    IdleStallDeleteDecision decision;
    ConntrackExactForwardedFlow flow;
    bool attempted{false};
    ConntrackCleanupResult cleanup_result{ConntrackCleanupResult::Failed};

    bool valid_for(
        const RuntimeIdleStallExactCleanupPointMutationWork& target) const
        noexcept {
        return runtime_background_same_idle_stall_delete_decision(
                   decision, target.decision) &&
               flow == target.flow &&
               (attempted ||
                cleanup_result == ConntrackCleanupResult::Failed);
    }

    bool operator==(
        const RuntimeIdleStallExactCleanupPointMutationOutcome& other) const
        noexcept {
        return runtime_background_same_idle_stall_delete_decision(
                   decision, other.decision) &&
               flow == other.flow && attempted == other.attempted &&
               cleanup_result == other.cleanup_result;
    }
};

struct RuntimeIdleStallExactCleanupPointMutationResult final {
    std::vector<RuntimeIdleStallExactCleanupPointMutationOutcome> outcomes;
    bool command_unavailable{false};

    bool valid_for(
        const RuntimeIdleStallExactCleanupPointMutationTarget& target) const
        noexcept {
        if (outcomes.size() != target.work.size()) {
            return false;
        }
        bool saw_unavailable = false;
        for (std::size_t index = 0U; index < outcomes.size(); ++index) {
            if (!outcomes[index].valid_for(target.work[index])) {
                return false;
            }
            saw_unavailable =
                saw_unavailable ||
                (outcomes[index].attempted &&
                 outcomes[index].cleanup_result ==
                     ConntrackCleanupResult::CommandUnavailable);
        }
        return command_unavailable == saw_unavailable;
    }

    bool operator==(
        const RuntimeIdleStallExactCleanupPointMutationResult& other) const
        noexcept {
        return outcomes == other.outcomes &&
               command_unavailable == other.command_unavailable;
    }
};

struct RuntimeMetaUdp443CleanupPointMutationResult final {
    ConntrackExactFlowCleanupSummary cleanup;
    OwnedForwardUdpRejectState before{
        OwnedForwardUdpRejectState::unknown};
    OwnedForwardUdpRejectState after{
        OwnedForwardUdpRejectState::unknown};
    bool fastnat_before{false};
    bool fastnat_after{false};
    std::string worker_failure;

    bool valid_for(
        const RuntimeMetaUdp443CleanupPointMutationTarget& target) const
        noexcept {
        if (cleanup.failed > cleanup.attempted) {
            return false;
        }
        for (std::size_t index = 0U;
             index < cleanup.remaining_flows.size();
             ++index) {
            if (!runtime_background_meta_flow_authorized(
                    cleanup.remaining_flows[index], target.plan)) {
                return false;
            }
            for (std::size_t previous = 0U; previous < index; ++previous) {
                if (runtime_background_same_exact_flow_selector(
                        cleanup.remaining_flows[index],
                        cleanup.remaining_flows[previous])) {
                    return false;
                }
            }
        }
        return true;
    }

    bool operator==(
        const RuntimeMetaUdp443CleanupPointMutationResult& other) const
        noexcept {
        return runtime_background_same_exact_flow_cleanup_summary(
                   cleanup, other.cleanup) &&
               before == other.before && after == other.after &&
               fastnat_before == other.fastnat_before &&
               fastnat_after == other.fastnat_after &&
               worker_failure == other.worker_failure;
    }
};

inline bool runtime_background_cleanup_summary_valid_for(
    const ConntrackCleanupSummary& cleanup,
    const OwnedConntrackCleanupRetry& retry) noexcept {
    std::set<std::uint32_t> remaining;
    for (const auto mark : cleanup.remaining_marks) {
        if (retry.snapshot.marks.count(mark) == 0U ||
            !remaining.insert(mark).second) {
            return false;
        }
    }
    return cleanup.failed <= retry.ordered_marks.size() &&
           cleanup.skipped <= retry.ordered_marks.size() &&
           cleanup.failed + cleanup.skipped <=
               retry.ordered_marks.size();
}

struct RuntimeOwnedConntrackCleanupPointMutationResult final {
    ConntrackCleanupSummary cleanup;

    bool valid_for(
        const RuntimeOwnedConntrackCleanupPointMutationTarget& target) const
        noexcept {
        return runtime_background_cleanup_summary_valid_for(
            cleanup, target.retry);
    }

    bool operator==(
        const RuntimeOwnedConntrackCleanupPointMutationResult& other) const
        noexcept {
        return runtime_background_same_conntrack_cleanup_summary(
            cleanup, other.cleanup);
    }
};

using RuntimeBackgroundPointMutationResultPayload = std::variant<
    std::monostate,
    RuntimeUdpCallAffinityPointMutationResult,
    RuntimeIdleStallExactCleanupPointMutationResult,
    RuntimeMetaUdp443CleanupPointMutationResult,
    RuntimeOwnedConntrackCleanupPointMutationResult>;

struct RuntimeBackgroundPointMutationResult final {
    RuntimeBackgroundPointMutationTarget target;
    bool worker_started{false};
    bool mutation_boundary_entered{false};
    bool generation_revalidated{false};
    bool completed{false};
    RuntimeBackgroundPointMutationResultPayload payload;

    bool unsafe_publication_possible() const noexcept {
        if (target.kind !=
                RuntimeBackgroundPointMutationKind::udp_call_affinity ||
            !std::holds_alternative<
                RuntimeUdpCallAffinityPointMutationResult>(payload)) {
            return false;
        }
        const auto& udp =
            std::get<RuntimeUdpCallAffinityPointMutationResult>(payload);
        return std::any_of(
            udp.outcomes.begin(),
            udp.outcomes.end(),
            [](const auto& outcome) {
                return outcome.publication_ambiguous;
            });
    }

    bool result_kind_matches() const noexcept {
        switch (target.kind) {
        case RuntimeBackgroundPointMutationKind::udp_call_affinity:
            return std::holds_alternative<
                RuntimeUdpCallAffinityPointMutationResult>(payload);
        case RuntimeBackgroundPointMutationKind::idle_stall_exact_cleanup:
            return std::holds_alternative<
                RuntimeIdleStallExactCleanupPointMutationResult>(payload);
        case RuntimeBackgroundPointMutationKind::meta_udp443_cleanup:
            return std::holds_alternative<
                RuntimeMetaUdp443CleanupPointMutationResult>(payload);
        case RuntimeBackgroundPointMutationKind::owned_conntrack_cleanup:
            return std::holds_alternative<
                RuntimeOwnedConntrackCleanupPointMutationResult>(payload);
        }
        return false;
    }

    // A negative or partially successful worker outcome still has to reach
    // the control loop so detector reservations and exact retry authorities
    // can be published. Success is therefore deliberately not a condition;
    // exact immutable identity and one terminal typed result are.
    bool control_publishable() const noexcept {
        if (!target.valid() || !worker_started || !completed ||
            (mutation_boundary_entered && !generation_revalidated) ||
            !result_kind_matches()) {
            return false;
        }
        switch (target.kind) {
        case RuntimeBackgroundPointMutationKind::udp_call_affinity:
            return std::get<RuntimeUdpCallAffinityPointMutationResult>(
                       payload)
                .valid_for(std::get<
                           RuntimeUdpCallAffinityPointMutationTarget>(
                    target.payload));
        case RuntimeBackgroundPointMutationKind::idle_stall_exact_cleanup:
            return std::get<
                       RuntimeIdleStallExactCleanupPointMutationResult>(
                       payload)
                .valid_for(std::get<
                           RuntimeIdleStallExactCleanupPointMutationTarget>(
                    target.payload));
        case RuntimeBackgroundPointMutationKind::meta_udp443_cleanup:
            return std::get<RuntimeMetaUdp443CleanupPointMutationResult>(
                       payload)
                .valid_for(std::get<
                           RuntimeMetaUdp443CleanupPointMutationTarget>(
                    target.payload));
        case RuntimeBackgroundPointMutationKind::owned_conntrack_cleanup:
            return std::get<
                       RuntimeOwnedConntrackCleanupPointMutationResult>(
                       payload)
                .valid_for(std::get<
                           RuntimeOwnedConntrackCleanupPointMutationTarget>(
                    target.payload));
        }
        return false;
    }

    bool operator==(
        const RuntimeBackgroundPointMutationResult& other) const {
        if (target != other.target ||
            worker_started != other.worker_started ||
            mutation_boundary_entered != other.mutation_boundary_entered ||
            generation_revalidated != other.generation_revalidated ||
            completed != other.completed || !result_kind_matches() ||
            !other.result_kind_matches()) {
            return false;
        }
        switch (target.kind) {
        case RuntimeBackgroundPointMutationKind::udp_call_affinity:
            return std::get<RuntimeUdpCallAffinityPointMutationResult>(
                       payload) ==
                   std::get<RuntimeUdpCallAffinityPointMutationResult>(
                       other.payload);
        case RuntimeBackgroundPointMutationKind::idle_stall_exact_cleanup:
            return std::get<
                       RuntimeIdleStallExactCleanupPointMutationResult>(
                       payload) ==
                   std::get<
                       RuntimeIdleStallExactCleanupPointMutationResult>(
                       other.payload);
        case RuntimeBackgroundPointMutationKind::meta_udp443_cleanup:
            return std::get<RuntimeMetaUdp443CleanupPointMutationResult>(
                       payload) ==
                   std::get<RuntimeMetaUdp443CleanupPointMutationResult>(
                       other.payload);
        case RuntimeBackgroundPointMutationKind::owned_conntrack_cleanup:
            return std::get<
                       RuntimeOwnedConntrackCleanupPointMutationResult>(
                       payload) ==
                   std::get<
                       RuntimeOwnedConntrackCleanupPointMutationResult>(
                       other.payload);
        }
        return false;
    }

    bool operator!=(
        const RuntimeBackgroundPointMutationResult& other) const {
        return !(*this == other);
    }
};

// Control-side rendezvous. The target is fixed before admission; only the
// authenticated terminal writes result/typed_identity_valid, and the retained
// continuation consumes them while it still owns the same mutation lease.
struct RuntimeBackgroundPointMutationTransaction final {
    explicit RuntimeBackgroundPointMutationTransaction(
        RuntimeBackgroundPointMutationTarget immutable_target)
        : target(std::move(immutable_target)) {}

    const RuntimeBackgroundPointMutationTarget target;
    std::shared_ptr<const RuntimeBackgroundPointMutationResult> result;
    bool typed_identity_valid{false};

    bool valid() const noexcept {
        return target.valid();
    }
};

} // namespace keen_pbr3
