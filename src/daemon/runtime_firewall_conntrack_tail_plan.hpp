#pragma once

#include "runtime_recovery_policy.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

// Immutable facts consumed by the controller-side conntrack tail after a
// firewall worker terminal. Pointers are borrowed for one synchronous plan
// call; the returned views remain valid only while these values remain alive.
struct RuntimeFirewallConntrackTailFacts final {
    bool native_source_cleanup_failed{false};
    std::string_view native_source_cleanup_failure_detail;
    bool worker_succeeded{false};
    const OwnedSnatRecovery* processed_snat_recovery{nullptr};
    OwnedSnatState inspected_snat_after{OwnedSnatState::unknown};
    std::uint64_t current_runtime_generation{0U};
};

// Pure decision result. The Daemon composition root retains the existing log
// and retry-scheduler callbacks; this plan neither performs effects nor owns a
// gate, retry budget or recovery state.
struct RuntimeFirewallConntrackTailPlan final {
    bool native_source_cleanup_failed{false};
    std::string_view native_source_cleanup_failure_detail;
    const OwnedConntrackCleanupSnapshot* cleanup_retry_snapshot{nullptr};

    bool report_native_source_cleanup_failure() const noexcept {
        return native_source_cleanup_failed;
    }

    bool schedule_owned_cleanup_retry() const noexcept {
        return cleanup_retry_snapshot != nullptr;
    }
};

RuntimeFirewallConntrackTailPlan plan_runtime_firewall_conntrack_tail(
    const RuntimeFirewallConntrackTailFacts& facts) noexcept;

// Facts from the worker's post-COMMIT owned-conntrack cleanup. The existing
// START tail intentionally ignores summary failed/skipped counters: only an
// explicit inspection failure with no remaining selectors falls back to all
// ordered owned marks. Every pointer is borrowed for one synchronous plan
// call.
struct RuntimeFirewallPostSuccessConntrackFacts final {
    bool attempted{false};
    const OwnedConntrackCleanupSnapshot* snapshot{nullptr};
    bool command_unavailable{false};
    bool cleanup_failed{false};
    const std::vector<std::uint32_t>* remaining_marks{nullptr};
};

enum class RuntimeFirewallPostSuccessConntrackMarks : std::uint8_t {
    none,
    reported_remaining,
    ordered_snapshot,
};

struct RuntimeFirewallPostSuccessConntrackPlan final {
    bool warn_command_unavailable{false};
    const OwnedConntrackCleanupSnapshot* retry_snapshot{nullptr};
    const std::vector<std::uint32_t>* reported_remaining_marks{nullptr};
    RuntimeFirewallPostSuccessConntrackMarks retry_marks{
        RuntimeFirewallPostSuccessConntrackMarks::none};

    bool should_warn_command_unavailable() const noexcept {
        return warn_command_unavailable;
    }

    bool should_prepare_retry() const noexcept {
        return retry_snapshot != nullptr &&
            retry_marks != RuntimeFirewallPostSuccessConntrackMarks::none;
    }
};

RuntimeFirewallPostSuccessConntrackPlan
plan_runtime_firewall_post_success_conntrack(
    const RuntimeFirewallPostSuccessConntrackFacts& facts) noexcept;

} // namespace keen_pbr3
