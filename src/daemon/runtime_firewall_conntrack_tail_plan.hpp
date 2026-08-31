#pragma once

#include "runtime_recovery_policy.hpp"

#include <cstdint>
#include <string_view>

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

} // namespace keen_pbr3
