#pragma once

#include <exception>
#include <utility>

namespace keen_pbr3 {

enum class KeeneticDnsRefreshRecovery {
    none,
    firewall_only,
    firewall_then_resolver,
    resolver_only,
};

struct KeeneticDnsRefreshTransactionResult {
    bool committed{false};
    KeeneticDnsRefreshRecovery recovery{
        KeeneticDnsRefreshRecovery::none};
    std::exception_ptr primary_failure;
    std::exception_ptr recovery_failure;
};

// Execute the short, control-loop-owned half of a periodic Keenetic DNS
// refresh. The caller keeps the immutable list generation pinned for the
// complete call. Callbacks intentionally keep the policy independent of
// Daemon, netfilter and resolver IPC so every failure boundary is testable.
//
// A firewall call which throws is treated as an ambiguous kernel commit: its
// backend may have published one atomic family before a later family failed.
// Therefore rollback is required after every attempted firewall mutation, not
// only after a callback which returned normally. The resolver callback receives
// a bool reference and sets it immediately before attempting the external
// resolver stream. Pure snapshot preparation or in-memory commit failures
// therefore do not cause a needless dnsmasq reload. Resolver rollback is
// required only after that external boundary was crossed.
template <typename InstallCandidateFn,
          typename ApplyCandidateFirewallFn,
          typename ApplyCandidateResolverFn,
          typename RestorePreviousFn,
          typename ApplyRollbackFirewallFn,
          typename ApplyRollbackResolverFn>
KeeneticDnsRefreshTransactionResult run_keenetic_dns_refresh_transaction(
    bool firewall_needed,
    InstallCandidateFn&& install_candidate,
    ApplyCandidateFirewallFn&& apply_candidate_firewall,
    ApplyCandidateResolverFn&& apply_candidate_resolver,
    RestorePreviousFn&& restore_previous,
    ApplyRollbackFirewallFn&& apply_rollback_firewall,
    ApplyRollbackResolverFn&& apply_rollback_resolver) {
    static_assert(
        noexcept(restore_previous()),
        "Keenetic DNS transaction restore_previous must be noexcept");

    bool candidate_firewall_attempted = false;
    bool candidate_resolver_stream_attempted = false;

    try {
        std::forward<InstallCandidateFn>(install_candidate)();
        if (firewall_needed) {
            candidate_firewall_attempted = true;
            std::forward<ApplyCandidateFirewallFn>(
                apply_candidate_firewall)();
        }
        std::forward<ApplyCandidateResolverFn>(
            apply_candidate_resolver)(
                candidate_resolver_stream_attempted);
        return {true,
                KeeneticDnsRefreshRecovery::none,
                nullptr,
                nullptr};
    } catch (...) {
        const std::exception_ptr primary_failure =
            std::current_exception();

        // Restore every event-loop-owned value before touching external
        // state. Recovery callbacks must observe the previous DNS and
        // resolver generation, never a half-published candidate. This callback
        // is a compile-time noexcept contract because an uncertain in-memory
        // owner cannot be repaired safely by either external retry path.
        std::forward<RestorePreviousFn>(restore_previous)();

        if (candidate_firewall_attempted) {
            try {
                std::forward<ApplyRollbackFirewallFn>(
                    apply_rollback_firewall)();
            } catch (...) {
                return {
                    false,
                    candidate_resolver_stream_attempted
                        ? KeeneticDnsRefreshRecovery::firewall_then_resolver
                        : KeeneticDnsRefreshRecovery::firewall_only,
                    primary_failure,
                    std::current_exception(),
                };
            }
        }

        if (candidate_resolver_stream_attempted) {
            try {
                std::forward<ApplyRollbackResolverFn>(
                    apply_rollback_resolver)();
            } catch (...) {
                return {
                    false,
                    KeeneticDnsRefreshRecovery::resolver_only,
                    primary_failure,
                    std::current_exception(),
                };
            }
        }

        return {
            false,
            KeeneticDnsRefreshRecovery::none,
            primary_failure,
            nullptr,
        };
    }
}

// Recovery scheduling is deliberately separate from the transactional
// rollback. Scheduling may allocate or reject work during shutdown; callers
// must retain the original transaction exception while surfacing this second
// failure. A resolver-after-firewall gate is undone when no firewall retry
// owner could be installed, otherwise it could block future resolver repair
// indefinitely.
template <typename GateResolverFn,
          typename UngateResolverFn,
          typename ScheduleFirewallFn,
          typename ScheduleResolverFn>
std::exception_ptr dispatch_keenetic_dns_refresh_recovery(
    KeeneticDnsRefreshRecovery recovery,
    GateResolverFn&& gate_resolver,
    UngateResolverFn&& ungate_resolver,
    ScheduleFirewallFn&& schedule_firewall,
    ScheduleResolverFn&& schedule_resolver) noexcept {
    static_assert(
        noexcept(gate_resolver()),
        "Keenetic DNS recovery gate must be noexcept");
    static_assert(
        noexcept(ungate_resolver()),
        "Keenetic DNS recovery ungate must be noexcept");

    bool owns_gate = false;
    try {
        switch (recovery) {
        case KeeneticDnsRefreshRecovery::none:
            return nullptr;
        case KeeneticDnsRefreshRecovery::firewall_only:
            std::forward<ScheduleFirewallFn>(schedule_firewall)();
            return nullptr;
        case KeeneticDnsRefreshRecovery::firewall_then_resolver:
            owns_gate = std::forward<GateResolverFn>(gate_resolver)();
            std::forward<ScheduleFirewallFn>(schedule_firewall)();
            return nullptr;
        case KeeneticDnsRefreshRecovery::resolver_only:
            std::forward<ScheduleResolverFn>(schedule_resolver)();
            return nullptr;
        }
    } catch (...) {
        const std::exception_ptr failure = std::current_exception();
        if (owns_gate) {
            std::forward<UngateResolverFn>(ungate_resolver)();
        }
        return failure;
    }
    return nullptr;
}

} // namespace keen_pbr3
