#pragma once

#include "../keenetic/ndms_lockout_policy.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Whether keen-pbr may rely on the router's own authentication instead of the
// password stored in auth.json.
//
// The roadmap orders this check BEFORE legacy auth is removed, and the reason
// is asymmetric risk: keeping a local password one day too long is an
// inconvenience, while deleting it before the system verifier is proven leaves
// SSH as the owner's only way back into their own panel.
enum class SystemAuthCapabilityState {
    // Every check passed. Even here this authorises nothing on its own - it
    // only says the switch would be safe to make.
    usable,
    // No router-owned address was proven to serve the challenge.
    endpoint_unproven,
    // Only loopback was available. Measured on a live Keenetic: the firmware
    // answers /auth with 403 on 127.0.0.1 and 401 with a challenge on the LAN
    // address, so loopback can never verify anybody.
    loopback_not_accepted,
    // Something answers, but it issues no realm/challenge. A reachable
    // unrelated service on a stale port must not be mistaken for the verifier.
    challenge_absent,
    // The firmware's lockout policy could not be read, so we cannot prove our
    // own limiter stays inside it.
    firmware_policy_unknown,
    // Our limiter would forward enough failures to trip the firmware's lockout.
    // Since keen-pbr reaches the firmware from the router itself, every WebUI
    // login attempt spends the administrator's budget, and an attacker who can
    // reach our login form can lock the owner out of KeeneticOS - repeatedly,
    // because our lock lifts long before the firmware's does.
    lockout_budget_unsafe,
};

// The local limiter's shape, passed in rather than read from a global so the
// judgement can be tested against policies no router here happens to have.
struct SystemAuthLimiterBudget {
    std::uint32_t max_failures{0};
    std::chrono::seconds window{0};
    std::chrono::seconds lockout{0};
    // Router-wide ceiling on failures forwarded to the firmware, independent
    // of how many sources ask.
    //
    // Without it the per-source limiter bounds nothing that matters here: the
    // firmware sees one source - this router - so N attackers with one address
    // each multiply straight through. With it, the friendly per-source numbers
    // stop being a security parameter and go back to being a usability one.
    std::optional<std::uint32_t> global_forward_cap;
};

struct SystemAuthCapabilityInputs {
    // A router-owned numeric address was selected and probed.
    bool endpoint_resolved{false};
    // That address is loopback. Kept separate from "unresolved" because the
    // operator fix differs: one needs a LAN address, the other needs the web
    // service enabled at all.
    bool endpoint_is_loopback{false};
    // The realm and challenge headers were actually observed, not assumed.
    bool challenge_observed{false};
    std::optional<NdmsLockoutPolicy> firmware_lockout;
    SystemAuthLimiterBudget local_limiter;
};

struct SystemAuthCapability {
    SystemAuthCapabilityState state{
        SystemAuthCapabilityState::endpoint_unproven};
    std::string detail;
    // False for every state but `usable`. The local password stays until the
    // replacement is proven, never the other way round.
    bool may_replace_local_password{false};
    // How many failed logins our limiter lets through to the firmware inside
    // its observation window. Reported so an operator can see the margin, not
    // just the verdict.
    std::uint32_t forwarded_failures_per_window{0};
};

// Worst case number of failures the local limiter forwards to the firmware
// within `observation_window`, assuming an attacker who resumes the instant
// each local lockout expires.
//
// This replays AuthLoginRateLimiter's actual rules rather than approximating
// them with a closed form. The obvious formula - one burst per
// (window + lockout) - is wrong, because the lockout runs concurrently with
// the counting window, not after it: at lockout >= window the counter resets
// at the very moment the block lifts, so the attacker's cycle is the lockout
// alone. Getting that backwards understates the exposure, which is the one
// direction a safety check must never err in.
//
// Saturates instead of overflowing: a limiter that never blocks is unbounded,
// and reporting a wrapped small number there would turn the most dangerous
// configuration into the one that looks safest.
std::uint32_t forwarded_failures_within(
    const SystemAuthLimiterBudget& limiter,
    std::chrono::seconds observation_window);

// Pure. Reads nothing, writes nothing, and in particular never removes the
// local password - it only reports whether doing so would be safe.
SystemAuthCapability evaluate_system_auth_capability(
    const SystemAuthCapabilityInputs& inputs);

// The web server's auth state, reduced to what the verdict depends on.
struct SystemAuthEndpointState {
    // Where /auth lives, as the running configuration has it - whether that
    // came from discovery or from the stored file.
    std::string endpoint;
    bool endpoint_unavailable{false};
};

// Answers "does this endpoint serve the Keenetic challenge". Injected rather
// than called directly so the wiring below can be tested without a router.
using SystemAuthChallengeProbe = std::function<bool(const std::string&)>;

// Measured: the firmware answers /auth with 403 on loopback and 401 with a
// challenge on a router-owned LAN address. A loopback endpoint can therefore
// never verify anybody, however well-formed it looks.
bool endpoint_is_loopback(const std::string& endpoint);

// Builds the verdict's inputs from live state.
//
// This exists as its own function because the defect it replaces lived here
// and nowhere else: the judgement was right, the inputs handed to it were not.
// A seam around the judgement alone could not have caught it, and did not.
//
// In particular `challenge_observed` is obtained by asking `probe`, never by
// inferring from where the endpoint came from. A stored endpoint is one proved
// earlier and cached, not an unproven one - and on a healthy router nothing
// re-discovers it, so inference is permanently false there.
SystemAuthCapabilityInputs build_system_auth_inputs(
    const SystemAuthEndpointState& endpoint_state,
    const std::optional<NdmsLockoutPolicy>& firmware_lockout,
    const SystemAuthLimiterBudget& limiter,
    const SystemAuthChallengeProbe& probe);

const char* system_auth_capability_state_name(
    SystemAuthCapabilityState state) noexcept;

} // namespace keen_pbr3
