#pragma once

#include <array>
#include <chrono>
#include <cstddef>

namespace keen_pbr3 {

// Shared bounded START recovery schedule. API START and cold boot consume
// these constants through their own orchestration policies; keeping the
// values in a lightweight header lets the cold-boot terminal seam remain
// independently buildable.
inline constexpr std::array<std::chrono::milliseconds, 3>
    kRuntimeFirewallStartRetryDelays{
        std::chrono::milliseconds{100},
        std::chrono::milliseconds{200},
        std::chrono::milliseconds{400},
    };

constexpr std::size_t kRuntimeFirewallStartBoundedRetryCount =
    kRuntimeFirewallStartRetryDelays.size();

constexpr bool runtime_firewall_start_retry_available(
    std::size_t completed_attempt) noexcept {
    return completed_attempt <
           kRuntimeFirewallStartBoundedRetryCount;
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
