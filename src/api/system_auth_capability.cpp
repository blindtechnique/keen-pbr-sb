#include "system_auth_capability.hpp"

#include <algorithm>
#include <cstdint>
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

    const auto capped = [&limiter](std::uint32_t forwarded) {
        if (!limiter.global_forward_cap) return forwarded;
        return std::min(forwarded, *limiter.global_forward_cap);
    };

    if (limiter.max_failures == 0U) return 0U;

    const std::int64_t observation = observation_window.count();
    const std::int64_t window = limiter.window.count();
    const std::int64_t lockout = limiter.lockout.count();

    // A limiter with no counting window resets before it can ever reach its
    // own threshold, and one with no lockout never makes the caller wait.
    // Either way nothing paces the forwarding.
    if (window <= 0 || lockout <= 0) return capped(kSaturated);

    // Replay of AuthLoginRateLimiter against an attacker who fires as fast as
    // allowed and resumes the instant each block lifts.
    std::int64_t now = 0;
    std::int64_t window_started = 0;
    std::int64_t blocked_until = -1;
    std::uint32_t failures = 0;
    std::uint64_t forwarded = 0;

    while (true) {
        if (blocked_until > now) now = blocked_until;
        if (now > observation) break;
        if (now - window_started >= window) {
            failures = 0;
            window_started = now;
            blocked_until = -1;
        }
        ++failures;
        ++forwarded;
        if (forwarded >= kSaturated) return capped(kSaturated);
        if (failures >= limiter.max_failures) {
            blocked_until = now + lockout;
        }
    }

    return capped(static_cast<std::uint32_t>(forwarded));
}

bool endpoint_is_loopback(const std::string& endpoint) {
    if (endpoint.empty()) return false;
    return endpoint.rfind("127.", 0) == 0 ||
           endpoint.rfind("[::1]", 0) == 0 ||
           endpoint.rfind("::1", 0) == 0;
}

SystemAuthCapabilityInputs build_system_auth_inputs(
    const SystemAuthEndpointState& endpoint_state,
    const std::optional<NdmsLockoutPolicy>& firmware_lockout,
    const SystemAuthLimiterBudget& limiter,
    const SystemAuthChallengeProbe& probe) {
    SystemAuthCapabilityInputs inputs;
    inputs.endpoint_resolved = !endpoint_state.endpoint.empty() &&
                               !endpoint_state.endpoint_unavailable;
    inputs.endpoint_is_loopback = endpoint_is_loopback(endpoint_state.endpoint);
    inputs.firmware_lockout = firmware_lockout;
    inputs.local_limiter = limiter;

    // Asked, never inferred. Skipped only when there is nothing to ask about
    // or when the answer cannot matter, so an unresolved or loopback endpoint
    // never costs a probe.
    inputs.challenge_observed =
        inputs.endpoint_resolved && !inputs.endpoint_is_loopback && probe &&
        probe(endpoint_state.endpoint);

    return inputs;
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
