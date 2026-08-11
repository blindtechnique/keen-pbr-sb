#include <doctest/doctest.h>

#include "api/system_auth_capability.hpp"
#include "keenetic/ndms_lockout_policy.hpp"

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

using namespace std::chrono_literals;

// Verbatim from /rci/show/rc/ip/http on a live Keenetic Ultra. The firmware
// spells the numbers as strings, and the port sits beside the policy in the
// same document endpoint discovery already reads.
nlohmann::json measured_http_config() {
    return nlohmann::json::parse(R"({
        "port": "777",
        "security-level": { "public": true, "ssl": true },
        "lockout-policy": {
            "threshold": "5",
            "duration": "15",
            "observation-window": "3"
        },
        "ssl": { "enable": true, "port": "5443" }
    })");
}

// What keen-pbr ships today: 5 failures per 60s window, 60s lockout.
SystemAuthLimiterBudget shipped_limiter() {
    SystemAuthLimiterBudget limiter;
    limiter.max_failures = 5;
    limiter.window = 60s;
    limiter.lockout = 60s;
    return limiter;
}

SystemAuthCapabilityInputs proven_endpoint() {
    SystemAuthCapabilityInputs inputs;
    inputs.endpoint_resolved = true;
    inputs.endpoint_is_loopback = false;
    inputs.challenge_observed = true;
    inputs.firmware_lockout = parse_ndms_lockout_policy(measured_http_config());
    inputs.local_limiter = shipped_limiter();
    return inputs;
}

} // namespace

TEST_CASE("the measured firmware policy parses") {
    const auto policy = parse_ndms_lockout_policy(measured_http_config());

    REQUIRE(policy.has_value());
    CHECK(policy->threshold == 5U);
    CHECK(policy->duration == 15min);
    CHECK(policy->observation_window == 3min);
}

TEST_CASE("an unreadable policy is nullopt, never a permissive default") {
    SUBCASE("no lockout-policy at all") {
        auto config = measured_http_config();
        config.erase("lockout-policy");
        CHECK_FALSE(parse_ndms_lockout_policy(config).has_value());
    }
    SUBCASE("a partial policy") {
        auto config = measured_http_config();
        config["lockout-policy"].erase("observation-window");
        // Two thirds of a policy is not a policy: the missing field is exactly
        // the one the margin is computed over.
        CHECK_FALSE(parse_ndms_lockout_policy(config).has_value());
    }
    SUBCASE("a non-numeric field") {
        auto config = measured_http_config();
        config["lockout-policy"]["threshold"] = "unlimited";
        CHECK_FALSE(parse_ndms_lockout_policy(config).has_value());
    }
    SUBCASE("a zero threshold") {
        auto config = measured_http_config();
        config["lockout-policy"]["threshold"] = "0";
        // "Never locks" is a policy we cannot reason about, not free headroom.
        CHECK_FALSE(parse_ndms_lockout_policy(config).has_value());
    }
    SUBCASE("a zero observation window") {
        auto config = measured_http_config();
        config["lockout-policy"]["observation-window"] = "0";
        CHECK_FALSE(parse_ndms_lockout_policy(config).has_value());
    }
    SUBCASE("not an object") {
        CHECK_FALSE(parse_ndms_lockout_policy(nlohmann::json::array()).has_value());
    }
}

TEST_CASE("numbers on the wire are accepted as well as strings") {
    auto config = measured_http_config();
    config["lockout-policy"]["threshold"] = 5;
    config["lockout-policy"]["duration"] = 15;
    config["lockout-policy"]["observation-window"] = 3;

    const auto policy = parse_ndms_lockout_policy(config);

    REQUIRE(policy.has_value());
    CHECK(policy->threshold == 5U);
}

TEST_CASE("forwarded failures count the bursts an attacker gets, not one") {
    SUBCASE("the shipped limiter over the measured window") {
        // 5 failures immediately, then the 60s lock lifts, 60s window resets,
        // and a second burst still lands inside the firmware's 3 minutes.
        CHECK(forwarded_failures_within(shipped_limiter(), 3min) == 10U);
    }
    SUBCASE("a limiter whose cycle outlasts the window allows one burst") {
        SystemAuthLimiterBudget limiter;
        limiter.max_failures = 2;
        limiter.window = 60s;
        limiter.lockout = 300s;
        CHECK(forwarded_failures_within(limiter, 3min) == 2U);
    }
    SUBCASE("a limiter that never blocks saturates instead of wrapping") {
        SystemAuthLimiterBudget limiter;
        limiter.max_failures = 5;
        limiter.window = 0s;
        limiter.lockout = 0s;
        // The most dangerous configuration must not be the one that reports
        // the smallest number.
        CHECK(forwarded_failures_within(limiter, 3min) ==
              std::numeric_limits<std::uint32_t>::max());
    }
    SUBCASE("a limiter that allows nothing forwards nothing") {
        SystemAuthLimiterBudget limiter;
        limiter.max_failures = 0;
        limiter.window = 60s;
        limiter.lockout = 60s;
        CHECK(forwarded_failures_within(limiter, 3min) == 0U);
    }
}

TEST_CASE("the shipped limiter is not safe against the measured firmware") {
    const auto capability = evaluate_system_auth_capability(proven_endpoint());

    // This is the finding, pinned so it cannot be lost: forwarding WebUI logins
    // to the firmware lets anyone who reaches our login form lock the router
    // administrator out of KeeneticOS for 15 minutes at a time.
    CHECK(capability.state ==
          SystemAuthCapabilityState::lockout_budget_unsafe);
    CHECK(capability.forwarded_failures_per_window == 10U);
    CHECK_FALSE(capability.may_replace_local_password);
    CHECK(capability.detail.find("10") != std::string::npos);
    CHECK(capability.detail.find("5") != std::string::npos);
}

TEST_CASE("a limiter tighter than the firmware budget is usable") {
    auto inputs = proven_endpoint();
    inputs.local_limiter.max_failures = 2;
    inputs.local_limiter.window = 60s;
    inputs.local_limiter.lockout = 300s;

    const auto capability = evaluate_system_auth_capability(inputs);

    CHECK(capability.state == SystemAuthCapabilityState::usable);
    CHECK(capability.may_replace_local_password);
    CHECK(capability.forwarded_failures_per_window == 2U);
}

TEST_CASE("equalling the firmware threshold is a failure, not a boundary") {
    auto inputs = proven_endpoint();
    // Exactly 5 forwarded failures against a threshold of 5. Reaching the
    // threshold IS the lock, so this must refuse.
    inputs.local_limiter.max_failures = 5;
    inputs.local_limiter.window = 60s;
    inputs.local_limiter.lockout = 300s;

    const auto capability = evaluate_system_auth_capability(inputs);

    CHECK(capability.forwarded_failures_per_window == 5U);
    CHECK(capability.state ==
          SystemAuthCapabilityState::lockout_budget_unsafe);
}

TEST_CASE("every precondition is required on its own") {
    const auto safe_limiter = [](SystemAuthCapabilityInputs& inputs) {
        inputs.local_limiter.max_failures = 2;
        inputs.local_limiter.window = 60s;
        inputs.local_limiter.lockout = 300s;
    };

    SUBCASE("no endpoint was proven") {
        auto inputs = proven_endpoint();
        safe_limiter(inputs);
        inputs.endpoint_resolved = false;
        CHECK(evaluate_system_auth_capability(inputs).state ==
              SystemAuthCapabilityState::endpoint_unproven);
    }
    SUBCASE("only loopback is available") {
        auto inputs = proven_endpoint();
        safe_limiter(inputs);
        inputs.endpoint_is_loopback = true;
        // Measured: the firmware answers 403 on 127.0.0.1 and 401 with a
        // challenge on the LAN address.
        CHECK(evaluate_system_auth_capability(inputs).state ==
              SystemAuthCapabilityState::loopback_not_accepted);
    }
    SUBCASE("something answers but issues no challenge") {
        auto inputs = proven_endpoint();
        safe_limiter(inputs);
        inputs.challenge_observed = false;
        CHECK(evaluate_system_auth_capability(inputs).state ==
              SystemAuthCapabilityState::challenge_absent);
    }
    SUBCASE("the firmware policy is unreadable") {
        auto inputs = proven_endpoint();
        safe_limiter(inputs);
        inputs.firmware_lockout.reset();
        CHECK(evaluate_system_auth_capability(inputs).state ==
              SystemAuthCapabilityState::firmware_policy_unknown);
    }
}

TEST_CASE("nothing but a clean pass may retire the local password") {
    const auto refusals = [] {
        std::vector<SystemAuthCapabilityInputs> cases;
        auto unresolved = proven_endpoint();
        unresolved.endpoint_resolved = false;
        cases.push_back(unresolved);
        auto loopback = proven_endpoint();
        loopback.endpoint_is_loopback = true;
        cases.push_back(loopback);
        auto silent = proven_endpoint();
        silent.challenge_observed = false;
        cases.push_back(silent);
        auto blind = proven_endpoint();
        blind.firmware_lockout.reset();
        cases.push_back(blind);
        cases.push_back(proven_endpoint());  // unsafe shipped limiter
        return cases;
    }();

    for (const auto& inputs : refusals) {
        const auto capability = evaluate_system_auth_capability(inputs);
        CHECK(capability.state != SystemAuthCapabilityState::usable);
        // Deleting the only local credential on anything short of a proven
        // replacement leaves SSH as the owner's sole way back in.
        CHECK_FALSE(capability.may_replace_local_password);
        // A refusal an operator cannot act on is barely better than silence.
        CHECK_FALSE(capability.detail.empty());
    }
}

TEST_CASE("state names are stable for reporting") {
    CHECK(std::string(system_auth_capability_state_name(
              SystemAuthCapabilityState::usable)) == "usable");
    CHECK(std::string(system_auth_capability_state_name(
              SystemAuthCapabilityState::loopback_not_accepted)) ==
          "loopback_not_accepted");
    CHECK(std::string(system_auth_capability_state_name(
              SystemAuthCapabilityState::lockout_budget_unsafe)) ==
          "lockout_budget_unsafe");
    CHECK(std::string(system_auth_capability_state_name(
              SystemAuthCapabilityState::firmware_policy_unknown)) ==
          "firmware_policy_unknown");
}

} // namespace keen_pbr3
