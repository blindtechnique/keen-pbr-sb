#include "system_auth_capability.hpp"

#include <limits>

namespace keen_pbr3 {

const char* system_auth_capability_state_name(
    SystemAuthCapabilityState state) noexcept {
    switch (state) {
        case SystemAuthCapabilityState::usable:
            return "usable";
        case SystemAuthCapabilityState::endpoint_unproven:
            return "endpoint_unproven";
        case SystemAuthCapabilityState::loopback_not_accepted:
            return "loopback_not_accepted";
        case SystemAuthCapabilityState::challenge_absent:
            return "challenge_absent";
        case SystemAuthCapabilityState::firmware_policy_unknown:
            return "firmware_policy_unknown";
        case SystemAuthCapabilityState::lockout_budget_unsafe:
            return "lockout_budget_unsafe";
    }
    return "unknown";
}

std::uint32_t forwarded_failures_within(
    const SystemAuthLimiterBudget& limiter,
    std::chrono::seconds observation_window) {
    constexpr auto kSaturated = std::numeric_limits<std::uint32_t>::max();

    if (limiter.max_failures == 0U) return 0U;

    const auto cycle = limiter.window + limiter.lockout;
    if (cycle <= std::chrono::seconds::zero()) {
        // Nothing paces the caller, so the firmware's budget is spent as fast
        // as requests arrive.
        return kSaturated;
    }

    // One burst is always available immediately; each further complete cycle
    // inside the observation window buys the attacker another.
    const std::uint64_t cycles =
        1U + static_cast<std::uint64_t>(observation_window.count() /
                                        cycle.count());
    const std::uint64_t forwarded =
        static_cast<std::uint64_t>(limiter.max_failures) * cycles;
    if (forwarded >= kSaturated) return kSaturated;
    return static_cast<std::uint32_t>(forwarded);
}

SystemAuthCapability evaluate_system_auth_capability(
    const SystemAuthCapabilityInputs& inputs) {
    SystemAuthCapability capability;

    if (!inputs.endpoint_resolved) {
        capability.state = SystemAuthCapabilityState::endpoint_unproven;
        capability.detail =
            "no router-owned address was proven to serve the Keenetic "
            "authentication challenge";
        return capability;
    }

    if (inputs.endpoint_is_loopback) {
        capability.state = SystemAuthCapabilityState::loopback_not_accepted;
        capability.detail =
            "the firmware refuses /auth on loopback; a router-owned LAN "
            "address is required";
        return capability;
    }

    if (!inputs.challenge_observed) {
        capability.state = SystemAuthCapabilityState::challenge_absent;
        capability.detail =
            "the endpoint answered without a Keenetic realm and challenge";
        return capability;
    }

    if (!inputs.firmware_lockout) {
        capability.state = SystemAuthCapabilityState::firmware_policy_unknown;
        capability.detail =
            "the firmware lockout policy could not be read, so the local "
            "limiter cannot be proven to stay inside it";
        return capability;
    }

    capability.forwarded_failures_per_window = forwarded_failures_within(
        inputs.local_limiter, inputs.firmware_lockout->observation_window);

    // Strictly less than the threshold: reaching it IS the lock. Equality is a
    // failure, not a boundary we are allowed to sit on.
    if (capability.forwarded_failures_per_window >=
        inputs.firmware_lockout->threshold) {
        capability.state = SystemAuthCapabilityState::lockout_budget_unsafe;
        capability.detail =
            "the local limiter forwards " +
            std::to_string(capability.forwarded_failures_per_window) +
            " failures per firmware observation window, at or above the "
            "firmware threshold of " +
            std::to_string(inputs.firmware_lockout->threshold) +
            "; failed WebUI logins would lock the router administrator out of "
            "KeeneticOS";
        return capability;
    }

    capability.state = SystemAuthCapabilityState::usable;
    capability.may_replace_local_password = true;
    return capability;
}

} // namespace keen_pbr3
