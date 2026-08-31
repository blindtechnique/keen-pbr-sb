#pragma once

#include "../runtime/meta_udp_443_activation_plan.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace keen_pbr3 {

// Immutable controller-side facts observed after one generic firewall worker
// terminal. Cleanup plans are borrowed only for this synchronous decision;
// this value neither owns recovery authority nor extends its lifetime.
struct RuntimeFirewallMetaTailFacts final {
    bool core_published{false};

    const MetaUdp443ActivationPlan* candidate_plan{nullptr};
    bool filter_healthy{false};
    bool fastnat_healthy{false};

    bool worker_commit_ambiguous{false};
    bool publication_epoch_changed{false};
    const MetaUdp443ActivationPlan* previous_plan{nullptr};
    std::uint64_t previous_runtime_generation{0U};
    std::uint64_t current_runtime_generation{0U};
    std::size_t previous_attempt{0U};
};

enum class RuntimeFirewallMetaCleanupSource : std::uint8_t {
    none,
    candidate,
    previous,
};

enum class RuntimeFirewallMetaIncidentAction : std::uint8_t {
    none,
    reset,
    degraded,
};

// Pure action plan for the already-eligible Meta publication tail. The caller
// retains the existing ordering: reset idle observation, snapshot generation
// and cleanup epoch, execute these effects, then mark tail progress complete.
// cleanup_plan is borrowed from RuntimeFirewallMetaTailFacts.
struct RuntimeFirewallMetaTailPlan final {
    RuntimeFirewallMetaCleanupSource cleanup_source{
        RuntimeFirewallMetaCleanupSource::none};
    const MetaUdp443ActivationPlan* cleanup_plan{nullptr};
    std::size_t cleanup_attempt{0U};

    RuntimeFirewallMetaIncidentAction incident_action{
        RuntimeFirewallMetaIncidentAction::none};
    std::string_view incident_detail;

    bool full_refresh{false};
    std::string_view refresh_detail;

    bool schedule_cleanup() const noexcept {
        return cleanup_source != RuntimeFirewallMetaCleanupSource::none &&
               cleanup_plan != nullptr;
    }

    bool report_degraded() const noexcept {
        return incident_action ==
            RuntimeFirewallMetaIncidentAction::degraded;
    }
};

RuntimeFirewallMetaTailPlan plan_runtime_firewall_meta_tail(
    const RuntimeFirewallMetaTailFacts& facts) noexcept;

} // namespace keen_pbr3
