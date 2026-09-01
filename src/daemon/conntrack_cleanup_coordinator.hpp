#pragma once

#include "../firewall/firewall.hpp"
#include "runtime_recovery_policy.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

// Control-loop callbacks only. The existing runtime firewall owner remains the
// sole physical mutation/admission path; this service owns just the durable
// pending retry and its timer.
struct ConntrackCleanupCoordinatorCallbacks final {
    std::function<int(
        std::chrono::milliseconds,
        std::function<void()>,
        std::string)> schedule_oneshot;
    std::function<void(int)> cancel_scheduled;
    std::function<void(OwnedConntrackCleanupRetry)> dispatch_retry;
    std::function<void()> retry_budget_exhausted;
};

class ConntrackCleanupCoordinator final {
public:
    ConntrackCleanupCoordinator() = default;
    explicit ConntrackCleanupCoordinator(
        ConntrackCleanupCoordinatorCallbacks callbacks)
        : callbacks_(std::move(callbacks)) {}

    ConntrackCleanupCoordinator(const ConntrackCleanupCoordinator&) = delete;
    ConntrackCleanupCoordinator& operator=(
        const ConntrackCleanupCoordinator&) = delete;

    void configure(ConntrackCleanupCoordinatorCallbacks callbacks) {
        callbacks_ = std::move(callbacks);
    }

    void schedule(
        const OwnedConntrackCleanupSnapshot& source_snapshot,
        std::vector<std::uint32_t> remaining_marks,
        std::size_t no_progress_attempt = 0U);

    void schedule_retry(const OwnedConntrackCleanupRetry& retry) {
        schedule(
            retry.snapshot,
            retry.ordered_marks,
            retry.no_progress_attempt);
    }

    void schedule_remaining(
        const OwnedConntrackCleanupRetry& retry,
        std::vector<std::uint32_t> remaining_marks);

    // Re-attempt timer publication after a previous scheduling exception. The
    // exact pending value remains durable until this succeeds or is cancelled.
    void arm();

    std::optional<OwnedConntrackCleanupSnapshot> pending_remainder(
        std::uint64_t runtime_generation) const;

    bool has_pending() const noexcept {
        return pending_.has_value();
    }

    bool timer_pending() const noexcept {
        return retry_task_id_ >= 0;
    }

    // Normal lifecycle cancellation preserves the previous throwing Scheduler
    // contract: state is cleared only after timer cancellation succeeds.
    void cancel();

    // Once an exact foreground owner has accepted the pending remainder, an
    // already-dequeued timer is harmless. Clear the durable value even if the
    // scheduler cannot unregister that callback.
    void clear_after_handoff() noexcept;

    // Returns true only for the first unavailable observation in this service
    // lifetime; the caller retains user-facing logging policy.
    bool note_command_unavailable() noexcept;

    const std::vector<FirewallSourceEgressSnatSelector>&
    committed_native_vpn_direct_egress_snat_selectors() const noexcept {
        return committed_native_vpn_direct_egress_snat_selectors_;
    }

    void commit_native_vpn_direct_egress_snat_selectors(
        const std::vector<FirewallSourceEgressSnatSelector>& selectors) {
        auto committed = selectors;
        committed_native_vpn_direct_egress_snat_selectors_.swap(committed);
    }

    void exchange_native_vpn_direct_egress_snat_selectors(
        std::vector<FirewallSourceEgressSnatSelector>& selectors) noexcept {
        committed_native_vpn_direct_egress_snat_selectors_.swap(selectors);
    }

private:
    void on_timer();

    ConntrackCleanupCoordinatorCallbacks callbacks_;
    int retry_task_id_{-1};
    std::optional<OwnedConntrackCleanupRetry> pending_;
    bool command_unavailable_reported_{false};
    // Exact source-scoped SNAT contract committed with the firewall core. A
    // change retires only flows from affected native-VPN source pools.
    std::vector<FirewallSourceEgressSnatSelector>
        committed_native_vpn_direct_egress_snat_selectors_;
};

} // namespace keen_pbr3
