#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>

#include "../firewall/firewall.hpp"

namespace keen_pbr3 {

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
