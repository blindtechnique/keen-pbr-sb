#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
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
