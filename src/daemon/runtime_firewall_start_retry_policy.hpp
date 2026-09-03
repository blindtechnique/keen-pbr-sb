#pragma once

#include <array>
#include <chrono>
#include <cstddef>

namespace keen_pbr3 {

// Bounded foreground START recovery schedule. Interactive START/config
// mutations must fail promptly instead of inheriting the much longer router
// boot window below.
inline constexpr std::array<std::chrono::milliseconds, 3>
    kRuntimeFirewallStartRetryDelays{
        std::chrono::milliseconds{100},
        std::chrono::milliseconds{200},
        std::chrono::milliseconds{400},
    };

constexpr std::size_t kRuntimeFirewallStartBoundedRetryCount =
    kRuntimeFirewallStartRetryDelays.size();

// KeeneticOS can still be rebuilding its netfilter state after S80 launches
// the daemon. Keep the first observations hot, then take fresh authoritative
// observations after the measured firmware-settle window. The final slot also
// bounds repeated scheduler/admission handoff rejection.
inline constexpr std::array<std::chrono::milliseconds, 5>
    kRuntimeColdBootRetryDelays{
        std::chrono::milliseconds{100},
        std::chrono::milliseconds{200},
        std::chrono::milliseconds{400},
        std::chrono::milliseconds{30000},
        std::chrono::milliseconds{60000},
    };

constexpr std::size_t kRuntimeColdBootBoundedRetryCount =
    kRuntimeColdBootRetryDelays.size();
static_assert(kRuntimeColdBootBoundedRetryCount > 0U);

// The process-start handoff has already consumed delay slot zero before the
// first candidate body. Same-owner retries therefore start at slot one and
// admit only the remaining candidate bodies.
constexpr std::size_t kRuntimeColdBootFollowupRetryCount =
    kRuntimeColdBootBoundedRetryCount - 1U;

constexpr bool runtime_cold_boot_followup_retry_available(
    std::size_t current_attempt) noexcept {
    return current_attempt < kRuntimeColdBootFollowupRetryCount;
}

constexpr std::chrono::milliseconds runtime_cold_boot_followup_retry_delay(
    std::size_t current_attempt) noexcept {
    const auto delay_index = current_attempt <
            kRuntimeColdBootFollowupRetryCount
        ? current_attempt + 1U
        : kRuntimeColdBootBoundedRetryCount - 1U;
    return kRuntimeColdBootRetryDelays[delay_index];
}

constexpr bool runtime_firewall_start_retry_available(
    std::size_t completed_attempt) noexcept {
    return completed_attempt <
           kRuntimeFirewallStartBoundedRetryCount;
}

constexpr bool runtime_cold_boot_retry_available(
    std::size_t completed_attempt) noexcept {
    return completed_attempt < kRuntimeColdBootBoundedRetryCount;
}

constexpr bool runtime_firewall_preapply_preworker_retry_available(
    std::size_t completed_attempt) noexcept {
    return runtime_firewall_start_retry_available(completed_attempt);
}

constexpr std::size_t
    kRuntimeFirewallStartRollbackHandoffRetryLimit = 4U;

constexpr bool runtime_firewall_start_rollback_handoff_retry_available(
    std::size_t recorded_rejections) noexcept {
    return recorded_rejections <
           kRuntimeFirewallStartRollbackHandoffRetryLimit;
}

} // namespace keen_pbr3
