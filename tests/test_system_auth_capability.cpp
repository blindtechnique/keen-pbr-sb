#include <doctest/doctest.h>

#include "api/auth_runtime.hpp"
#include "api/system_auth_capability.hpp"
#include "health/routing_health_checker.hpp"
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

// What keen-pbr shipped before this slice: 5 failures per 60s window, 60s
// lockout, nothing bounding what reaches the firmware.
SystemAuthLimiterBudget legacy_limiter() {
    SystemAuthLimiterBudget limiter;
    limiter.max_failures = 5;
    limiter.window = 60s;
    limiter.lockout = 60s;
    return limiter;
}

// The per-source numbers chosen for a VPN helper on a home router: three
// attempts, then a hundred seconds. Usability, not a security parameter.
SystemAuthLimiterBudget current_limiter() {
    SystemAuthLimiterBudget limiter;
    limiter.max_failures = 3;
    limiter.window = 100s;
    limiter.lockout = 100s;
    return limiter;
}

SystemAuthCapabilityInputs proven_endpoint() {
    SystemAuthCapabilityInputs inputs;
    inputs.endpoint_resolved = true;
    inputs.endpoint_is_loopback = false;
    inputs.challenge_observed = true;
    inputs.firmware_lockout = parse_ndms_lockout_policy(measured_http_config());
    inputs.local_limiter = legacy_limiter();
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
    SUBCASE("the legacy limiter over the measured window") {
        // The lockout runs concurrently with the counting window, so at
        // lockout == window the counter resets the instant the block lifts:
        // bursts at t=0, 60, 120 and 180, not the two a
        // one-burst-per-(window+lockout) model would predict.
        CHECK(forwarded_failures_within(legacy_limiter(), 3min) == 20U);
    }
    SUBCASE("the chosen per-source numbers still overshoot on their own") {
        // Bursts at t=0 and t=100. Three attempts is the right call for a home
        // router; it just cannot be the thing that protects the firmware.
        CHECK(forwarded_failures_within(current_limiter(), 3min) == 6U);
    }
    SUBCASE("a global cap is what actually bounds the firmware's exposure") {
        auto limiter = current_limiter();
        limiter.global_forward_cap = 4U;
        CHECK(forwarded_failures_within(limiter, 3min) == 4U);
    }
    SUBCASE("a global cap never inflates a limiter that is already tighter") {
        auto limiter = current_limiter();
        limiter.global_forward_cap = 100U;
        CHECK(forwarded_failures_within(limiter, 3min) == 6U);
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

TEST_CASE("the legacy limiter is not safe against the measured firmware") {
    const auto capability = evaluate_system_auth_capability(proven_endpoint());

    // This is the finding, pinned so it cannot be lost: forwarding WebUI logins
    // to the firmware lets anyone who reaches our login form lock the router
    // administrator out of KeeneticOS for 15 minutes at a time.
    CHECK(capability.state ==
          SystemAuthCapabilityState::lockout_budget_unsafe);
    CHECK(capability.forwarded_failures_per_window == 20U);
    CHECK_FALSE(capability.may_replace_local_password);
    CHECK(capability.detail.find("20") != std::string::npos);
}

TEST_CASE("per-source numbers alone do not make the switch safe") {
    auto inputs = proven_endpoint();
    inputs.local_limiter = current_limiter();

    const auto capability = evaluate_system_auth_capability(inputs);

    // Three attempts per source is friendlier than five, and still overshoots.
    // Tightening the human-facing number was never going to be the fix.
    CHECK(capability.state ==
          SystemAuthCapabilityState::lockout_budget_unsafe);
    CHECK(capability.forwarded_failures_per_window == 6U);
}

TEST_CASE("the global forward cap is what makes the switch safe") {
    auto inputs = proven_endpoint();
    inputs.local_limiter = current_limiter();
    inputs.local_limiter.global_forward_cap =
        auth_forward_capacity_for(kNdmsDefaultLockoutThreshold);

    const auto capability = evaluate_system_auth_capability(inputs);

    // The human keeps three tries; the firmware never sees a fifth failure.
    CHECK(capability.state == SystemAuthCapabilityState::usable);
    CHECK(capability.may_replace_local_password);
    CHECK(capability.forwarded_failures_per_window == 4U);
}

TEST_CASE("the shipped capacity stops one short of the firmware threshold") {
    CHECK(auth_forward_capacity_for(kNdmsDefaultLockoutThreshold) == 4U);
    CHECK(auth_forward_capacity_for(1U) == 0U);
    // A zero threshold must not underflow into a budget of four billion.
    CHECK(auth_forward_capacity_for(0U) == 0U);
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

TEST_CASE("the forward budget stops before the firmware threshold") {
    const auto start = AuthForwardBudget::Clock::now();
    AuthForwardBudget budget(
        auth_forward_capacity_for(kNdmsDefaultLockoutThreshold),
        kNdmsDefaultLockoutObservation);

    for (int spent = 0; spent < 4; ++spent) {
        CHECK(budget.may_forward(start));
        budget.record_forwarded_failure(start);
    }

    // The fifth is the one the firmware would have counted as the lockout
    // trigger, so it never leaves this router.
    CHECK_FALSE(budget.may_forward(start));
    CHECK(budget.spent(start) == 4U);
}

TEST_CASE("the forward budget refills on a sliding window, not an epoch") {
    const auto start = AuthForwardBudget::Clock::now();
    AuthForwardBudget budget(2U, 100s);

    budget.record_forwarded_failure(start);
    budget.record_forwarded_failure(start + 60s);
    CHECK_FALSE(budget.may_forward(start + 60s));

    // At +100s the first failure ages out and exactly one slot returns. A
    // fixed-epoch counter would have handed back both and let a patient caller
    // straddle two epochs.
    CHECK(budget.may_forward(start + 100s));
    CHECK(budget.spent(start + 100s) == 1U);
    CHECK(budget.spent(start + 160s) == 0U);
}

TEST_CASE("a failure that raced past the guard is still counted") {
    const auto start = AuthForwardBudget::Clock::now();
    AuthForwardBudget budget(2U, 100s);

    budget.record_forwarded_failure(start);
    budget.record_forwarded_failure(start + 10s);
    // Two concurrent workers can both pass may_forward() before either
    // records. The budget must not forget the overspend.
    budget.record_forwarded_failure(start + 20s);

    CHECK_FALSE(budget.may_forward(start + 20s));
    // Bounded, and holding the newest timestamps: the refill is pushed later
    // than the first failure would have allowed, never earlier.
    CHECK(budget.spent(start + 20s) == 2U);
    CHECK_FALSE(budget.may_forward(start + 105s));
    CHECK(budget.may_forward(start + 115s));
}

TEST_CASE("a tightened policy does not hand back budget already spent") {
    const auto start = AuthForwardBudget::Clock::now();
    AuthForwardBudget budget(4U, 180s);

    for (int spent = 0; spent < 4; ++spent) {
        budget.record_forwarded_failure(start);
    }

    // The administrator lowers the firmware threshold from 5 to 3 while the
    // daemon is running. The four failures the firmware already counted do not
    // become unspent because we learned about the change afterwards.
    budget.reconfigure(auth_forward_capacity_for(3U), 180s);

    CHECK(budget.capacity() == 2U);
    CHECK(budget.spent(start) == 2U);
    CHECK_FALSE(budget.may_forward(start));
}

TEST_CASE("a loosened policy widens the budget without losing history") {
    const auto start = AuthForwardBudget::Clock::now();
    AuthForwardBudget budget(2U, 180s);

    budget.record_forwarded_failure(start);
    budget.record_forwarded_failure(start + 10s);
    CHECK_FALSE(budget.may_forward(start + 10s));

    budget.reconfigure(auth_forward_capacity_for(6U), 180s);

    CHECK(budget.capacity() == 5U);
    // Room opens up, but the two already spent are still on the books.
    CHECK(budget.may_forward(start + 10s));
    CHECK(budget.spent(start + 10s) == 2U);
}

TEST_CASE("a zero capacity budget forwards nothing and stays bounded") {
    const auto start = AuthForwardBudget::Clock::now();
    AuthForwardBudget budget(auth_forward_capacity_for(0U), 100s);

    CHECK_FALSE(budget.may_forward(start));
    for (int i = 0; i < 8; ++i) budget.record_forwarded_failure(start);
    CHECK(budget.spent(start) <= 1U);
    CHECK_FALSE(budget.may_forward(start));
}

TEST_CASE("the health report carries every state name the judge produces") {
    const SystemAuthCapabilityState states[] = {
        SystemAuthCapabilityState::usable,
        SystemAuthCapabilityState::endpoint_unproven,
        SystemAuthCapabilityState::loopback_not_accepted,
        SystemAuthCapabilityState::challenge_absent,
        SystemAuthCapabilityState::firmware_policy_unknown,
        SystemAuthCapabilityState::lockout_budget_unsafe,
    };

    for (const auto state : states) {
        RoutingHealthReport report;
        report.overall_ok = true;
        report.firewall_backend = FirewallBackend::iptables;
        report.system_auth_state = system_auth_capability_state_name(state);

        const auto json = routing_health_report_to_json(report);

        REQUIRE(json.contains("system_auth_state"));
        // A name the health layer silently rewrites is a name an operator
        // cannot act on, and the two vocabularies drifting apart is exactly
        // how "usable" would end up meaning something else.
        CHECK(json["system_auth_state"].get<std::string>() ==
              std::string(system_auth_capability_state_name(state)));
    }
}

TEST_CASE("an unmappable system-auth state never reports as usable") {
    RoutingHealthReport report;
    report.overall_ok = true;
    report.firewall_backend = FirewallBackend::iptables;
    report.system_auth_state = "invented_by_a_newer_build";

    const auto json = routing_health_report_to_json(report);

    // The one direction that must never happen: a state we cannot map becoming
    // the state that says it is safe to delete the only local password.
    CHECK(json["system_auth_state"].get<std::string>() == "endpoint_unproven");
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
