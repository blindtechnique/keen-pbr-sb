#pragma once

#include <cstdint>
#include <string_view>

namespace keen_pbr3 {

// Controller-side terminal classification after the core/resolver/conntrack
// publication tails have finished. The plan is value-only: it neither owns
// retry authority nor performs runtime, scheduler, incident or logging
// effects.
enum class RuntimeFirewallTerminalTailDispatch : std::uint8_t {
    start_verified,
    start_pending,
    start_failed,
    background_success,
    background_failure,
};

// A stale final route observation is the only condition in this plan which
// rewrites an already selected successor. `preserve` means the caller must
// leave its existing successor fields untouched.
enum class RuntimeFirewallTerminalTailSuccessor : std::uint8_t {
    preserve,
    clear,
    reschedule_retry,
};

struct RuntimeFirewallTerminalTailFacts final {
    bool lifecycle_start{false};
    bool lifecycle_cold_boot{false};
    bool worker_succeeded{false};
    bool worker_commit_ambiguous{false};
    // The Daemon samples the live route epoch at the final control-loop fence
    // and passes the already classified result here. It must include the
    // existing non-zero epoch requirement.
    bool route_epoch_current{false};
    bool ordinary_start_retry_available{false};
    bool successor_pending{false};
    bool lifecycle_resolver_verified{false};
    bool start_candidate_published{false};
    bool core_published{false};
};

struct RuntimeFirewallTerminalTailPlan final {
    RuntimeFirewallTerminalTailDispatch dispatch{
        RuntimeFirewallTerminalTailDispatch::background_failure};
    RuntimeFirewallTerminalTailSuccessor successor{
        RuntimeFirewallTerminalTailSuccessor::preserve};
    bool downgrade_stale_start_success{false};
    bool force_successor{false};
    bool worker_failure_transient{false};
    bool worker_succeeded_after_route_fence{false};
    bool successor_pending_after_route_fence{false};
    bool verified_start{false};
    std::string_view worker_failure_detail;
};

RuntimeFirewallTerminalTailPlan plan_runtime_firewall_terminal_tail(
    const RuntimeFirewallTerminalTailFacts& facts) noexcept;

} // namespace keen_pbr3
