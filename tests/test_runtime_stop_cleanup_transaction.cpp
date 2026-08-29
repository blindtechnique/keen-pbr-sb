#include "daemon/runtime_stop_cleanup_transaction.hpp"

#include <doctest/doctest.h>

using namespace keen_pbr3;

namespace {

RuntimeStopCleanupTarget runtime_stop_target() {
    RuntimeStopCleanupTarget target;
    target.intent = RuntimeStopCleanupIntent::runtime_stop;
    target.runtime_generation = 17U;
    target.cleanup_conntrack = true;
    target.conntrack_snapshot.runtime_generation = 17U;
    target.conntrack_snapshot.owned_mask = 0x00ff0000U;
    target.conntrack_snapshot.marks = {0x00010000U};
    target.deactivate_resolver = true;
    return target;
}

} // namespace

TEST_CASE("process STOP accepts only its exact returned mutation lease") {
    RuntimeMutationAdmission expected_admission;
    RuntimeMutationAdmission foreign_admission;
    auto expected = expected_admission.try_acquire("expected-stop");
    auto foreign = foreign_admission.try_acquire("foreign-stop");
    REQUIRE(expected.has_value());
    REQUIRE(foreign.has_value());
    const auto expected_token = expected->token();
    auto expected_ptr =
        std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(*expected));
    auto foreign_ptr =
        std::make_unique<RuntimeMutationAdmission::Lease>(
            std::move(*foreign));

    CHECK(runtime_stop_cleanup_exact_lease_returned(
        expected_admission, expected_token, expected_ptr));
    CHECK_FALSE(runtime_stop_cleanup_exact_lease_returned(
        expected_admission, expected_token, foreign_ptr));
    CHECK_FALSE(runtime_stop_cleanup_exact_lease_returned(
        expected_admission, expected_token + 1U, expected_ptr));
    const std::unique_ptr<RuntimeMutationAdmission::Lease> missing;
    CHECK_FALSE(runtime_stop_cleanup_exact_lease_returned(
        expected_admission, expected_token, missing));
}

TEST_CASE("runtime STOP cleanup succeeds once and keeps one immutable target") {
    auto target = runtime_stop_target();
    std::size_t conntrack_calls = 0U;
    std::size_t route_calls = 0U;
    std::size_t firewall_calls = 0U;
    std::size_t resolver_calls = 0U;
    std::vector<std::chrono::milliseconds> delays;

    RuntimeStopCleanupServices services;
    services.cleanup_conntrack =
        [&](const OwnedConntrackCleanupSnapshot& snapshot) {
            ++conntrack_calls;
            CHECK(snapshot.runtime_generation == 17U);
            CHECK(snapshot.marks == std::set<std::uint32_t>{0x00010000U});
            return true;
        };
    services.clear_routing = [&] {
        ++route_calls;
        return true;
    };
    services.cleanup_firewall = [&] {
        ++firewall_calls;
        return true;
    };
    services.deactivate_resolver = [&] {
        ++resolver_calls;
        return true;
    };
    services.backoff =
        [&](std::chrono::milliseconds delay) {
            delays.push_back(delay);
        };

    const auto result =
        execute_runtime_stop_cleanup_transaction(
            std::move(target), services);
    CHECK(result.fully_verified());
    CHECK(result.kernel_cleanup_verified());
    CHECK(result.mutation_boundary_entered);
    CHECK(result.attempts == 1U);
    CHECK(conntrack_calls == 1U);
    CHECK(route_calls == 1U);
    CHECK(firewall_calls == 1U);
    CHECK(resolver_calls == 1U);
    CHECK(delays.empty());
}

TEST_CASE("runtime STOP retries only unverified monotonic cleanup stages") {
    auto target = runtime_stop_target();
    std::size_t conntrack_calls = 0U;
    std::size_t route_calls = 0U;
    std::size_t firewall_calls = 0U;
    std::size_t resolver_calls = 0U;
    std::vector<std::chrono::milliseconds> delays;

    RuntimeStopCleanupServices services;
    services.cleanup_conntrack =
        [&](const OwnedConntrackCleanupSnapshot&) {
            return ++conntrack_calls >= 2U;
        };
    services.clear_routing = [&] {
        ++route_calls;
        return true;
    };
    services.cleanup_firewall = [&] {
        return ++firewall_calls >= 2U;
    };
    services.deactivate_resolver = [&] {
        return ++resolver_calls >= 2U;
    };
    services.backoff =
        [&](std::chrono::milliseconds delay) {
            delays.push_back(delay);
        };

    const auto result =
        execute_runtime_stop_cleanup_transaction(
            std::move(target), services);
    CHECK(result.fully_verified());
    CHECK(result.attempts == 3U);
    CHECK(conntrack_calls == 2U);
    CHECK(route_calls == 1U);
    CHECK(firewall_calls == 2U);
    CHECK(resolver_calls == 2U);
    REQUIRE(delays.size() == 2U);
    CHECK(delays[0] == std::chrono::milliseconds{50});
    CHECK(delays[1] == std::chrono::milliseconds{150});
}

TEST_CASE("runtime STOP never deactivates resolver before kernel cleanup") {
    auto target = runtime_stop_target();
    std::size_t resolver_calls = 0U;
    RuntimeStopCleanupServices services;
    services.cleanup_conntrack =
        [](const OwnedConntrackCleanupSnapshot&) { return true; };
    services.clear_routing = [] { return false; };
    services.cleanup_firewall = [] { return true; };
    services.deactivate_resolver = [&] {
        ++resolver_calls;
        return true;
    };
    services.backoff = [](std::chrono::milliseconds) {};

    const auto result =
        execute_runtime_stop_cleanup_transaction(
            std::move(target), services);
    CHECK_FALSE(result.kernel_cleanup_verified());
    CHECK_FALSE(result.fully_verified());
    CHECK(result.attempts == 3U);
    CHECK(resolver_calls == 0U);
}

TEST_CASE("process shutdown skips conntrack but verifies resolver deactivation") {
    RuntimeStopCleanupTarget target;
    target.intent = RuntimeStopCleanupIntent::process_shutdown;
    target.runtime_generation = 41U;
    target.cleanup_conntrack = false;
    target.deactivate_resolver = true;
    std::size_t conntrack_calls = 0U;
    std::size_t resolver_calls = 0U;
    RuntimeStopCleanupServices services;
    services.cleanup_conntrack =
        [&](const OwnedConntrackCleanupSnapshot&) {
            ++conntrack_calls;
            return false;
        };
    services.clear_routing = [] { return true; };
    services.cleanup_firewall = [] { return true; };
    services.deactivate_resolver = [&] {
        ++resolver_calls;
        return true;
    };

    const auto result =
        execute_runtime_stop_cleanup_transaction(
            std::move(target), services);
    CHECK(result.fully_verified());
    CHECK(result.conntrack_cleanup_verified);
    CHECK(result.resolver_deactivation_verified);
    CHECK(result.attempts == 1U);
    CHECK(conntrack_calls == 0U);
    CHECK(resolver_calls == 1U);
}

TEST_CASE("shutdown cleanup owner readiness requires all three idle proofs") {
    CHECK_FALSE(runtime_shutdown_cleanup_owner_ready(false, false, false));
    CHECK_FALSE(runtime_shutdown_cleanup_owner_ready(true, true, false));
    CHECK_FALSE(runtime_shutdown_cleanup_owner_ready(true, false, true));
    CHECK_FALSE(runtime_shutdown_cleanup_owner_ready(true, true, true));
    CHECK(runtime_shutdown_cleanup_owner_ready(true, false, false));
}

TEST_CASE("STOP terminal retains running state after a clean preworker stop") {
    RuntimeStopCleanupTerminalFacts facts;
    facts.runtime_was_running = true;

    CHECK(runtime_stop_cleanup_terminal_publication(facts) ==
          RuntimeStopCleanupTerminalPublication::retain_running);
}

TEST_CASE("shutdown from stopped retains stopped after a clean preworker stop") {
    RuntimeStopCleanupTerminalFacts facts;
    facts.runtime_was_running = false;

    CHECK(runtime_stop_cleanup_terminal_publication(facts) ==
          RuntimeStopCleanupTerminalPublication::retain_stopped);
}

TEST_CASE("STOP terminal publishes stopped after fully verified cleanup") {
    RuntimeStopCleanupTerminalFacts facts;
    facts.runtime_was_running = true;
    facts.worker_started = true;
    facts.mutation_boundary_entered = true;
    facts.kernel_cleanup_verified = true;
    facts.resolver_deactivation_required = true;
    facts.resolver_deactivation_verified = true;

    CHECK(runtime_stop_cleanup_terminal_publication(facts) ==
          RuntimeStopCleanupTerminalPublication::publish_stopped);
}

TEST_CASE("resolver failure publishes inactive broken after kernel cleanup") {
    auto target = runtime_stop_target();
    RuntimeStopCleanupServices services;
    services.cleanup_conntrack =
        [](const OwnedConntrackCleanupSnapshot&) { return true; };
    services.clear_routing = [] { return true; };
    services.cleanup_firewall = [] { return true; };
    services.deactivate_resolver = [] { return false; };
    services.backoff = [](std::chrono::milliseconds) {};
    const auto result = execute_runtime_stop_cleanup_transaction(
        std::move(target), services);
    REQUIRE(result.kernel_cleanup_verified());
    CHECK_FALSE(result.fully_verified());

    RuntimeStopCleanupTerminalFacts facts;
    facts.runtime_was_running = true;
    facts.worker_started = true;
    facts.mutation_boundary_entered = result.mutation_boundary_entered;
    facts.kernel_cleanup_verified = result.kernel_cleanup_verified();
    facts.resolver_deactivation_required = result.target.deactivate_resolver;
    facts.resolver_deactivation_verified =
        result.resolver_deactivation_verified;
    CHECK(runtime_stop_cleanup_terminal_publication(facts) ==
          RuntimeStopCleanupTerminalPublication::publish_broken);
}

TEST_CASE("STOP terminal publishes broken after incomplete worker mutation") {
    RuntimeStopCleanupTerminalFacts facts;
    facts.runtime_was_running = true;
    facts.worker_started = true;
    facts.mutation_boundary_entered = true;
    facts.kernel_cleanup_verified = false;

    CHECK(runtime_stop_cleanup_terminal_publication(facts) ==
          RuntimeStopCleanupTerminalPublication::publish_broken);

    facts.worker_started = false;
    CHECK(runtime_stop_cleanup_terminal_publication(facts) ==
          RuntimeStopCleanupTerminalPublication::publish_broken);
}

TEST_CASE("runtime STOP clamps retry budget and records ambiguity as failure") {
    auto target = runtime_stop_target();
    target.maximum_attempts = 99U;
    std::size_t route_calls = 0U;
    RuntimeStopCleanupServices services;
    services.cleanup_conntrack =
        [](const OwnedConntrackCleanupSnapshot&) { return true; };
    services.clear_routing = [&] {
        ++route_calls;
        throw std::runtime_error("route inventory unknown");
        return false;
    };
    services.cleanup_firewall = [] { return true; };
    services.deactivate_resolver = [] { return true; };
    services.backoff = [](std::chrono::milliseconds) {};

    const auto result =
        execute_runtime_stop_cleanup_transaction(
            std::move(target), services);
    CHECK_FALSE(result.fully_verified());
    CHECK(result.attempts == 3U);
    CHECK(route_calls == 3U);
    CHECK(result.mutation_boundary_entered);
    CHECK(result.has_failures());
    CHECK(result.last_failure_stage ==
          RuntimeStopCleanupFailureStage::routing);
    CHECK((result.failure_stages & runtime_stop_cleanup_failure_bit(
              RuntimeStopCleanupFailureStage::routing)) != 0U);
}
