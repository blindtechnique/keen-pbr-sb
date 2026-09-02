#pragma once

#include <chrono>
#include <optional>
#include <string>

#include <nlohmann/json_fwd.hpp>

namespace keen_pbr3 {

// The firmware's own brute-force lockout, read from the very same
// /rci/show/rc/ip/http document endpoint discovery already fetches.
//
// This is not a curiosity. keen-pbr forwards WebUI logins to the firmware, so
// every failed attempt we pass on spends the router administrator's lockout
// budget rather than ours. Measured on a live Keenetic Ultra: threshold 5,
// duration 15, observation-window 3.
struct NdmsLockoutPolicy {
    // Failed attempts tolerated before the firmware locks the account.
    unsigned threshold{0};
    // How long the firmware keeps it locked. Minutes on the wire.
    std::chrono::seconds duration{0};
    // The span over which failures are counted. Minutes on the wire.
    std::chrono::seconds observation_window{0};
};

// Returns nullopt when the firmware reports no policy, when the values are
// unusable, or when any of the three is missing.
//
// Deliberately not a permissive default: not knowing the firmware's budget is
// a reason to refuse the switch, not a licence to assume there is room. A
// hardcoded "probably 5/15/3" would silently become wrong the moment an
// administrator tightens the policy.
std::optional<NdmsLockoutPolicy> parse_ndms_lockout_policy(
    const nlohmann::json& http_config);

// Reads the shared typed snapshot. The call may perform one bounded raw RCI
// refresh or be a cache hit shared with endpoint discovery; there is no timer
// or polling loop here.
//
// Returns nullopt for stale/unavailable/invalid policy, which callers must
// treat as "keep the conservative default and say so", never as "no policy,
// so no limit".
std::optional<NdmsLockoutPolicy> fetch_ndms_lockout_policy(
    std::string* error = nullptr);

} // namespace keen_pbr3
