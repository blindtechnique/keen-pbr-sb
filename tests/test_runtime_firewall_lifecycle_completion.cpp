#include <doctest/doctest.h>

#include "daemon/runtime_firewall_lifecycle_completion.hpp"

#include <atomic>
#include <chrono>
#include <optional>
#include <string>
#include <thread>
#include <utility>

using namespace keen_pbr3;

namespace {

using LifecycleCompletion = RuntimeFirewallLifecycleCompletion;
using LifecycleOutcome = RuntimeFirewallLifecycleOutcome;
using LifecycleTerminal = RuntimeFirewallLifecycleTerminal;
using SettleStatus = LifecycleCompletion::Source::SettleStatus;

LifecycleTerminal verified_terminal(std::string detail) {
    return {
        LifecycleOutcome::verified_success,
        true,
        false,
        false,
        std::move(detail)};
}

LifecycleTerminal unverified_terminal(std::string detail) {
    return {
        LifecycleOutcome::not_verified,
        false,
        true,
        true,
        std::move(detail)};
}

} // namespace

TEST_CASE("runtime firewall lifecycle completion settles exactly once") {
    auto pair = LifecycleCompletion::create();
    auto competing_source = pair.source;
    std::atomic<unsigned int> settled{0U};

    std::thread first([source = pair.source, &settled]() mutable {
        if (source.settle(verified_terminal("verified winner")) ==
            SettleStatus::settled) {
            settled.fetch_add(1U, std::memory_order_relaxed);
        }
    });
    std::thread second(
        [source = std::move(competing_source), &settled]() mutable {
            if (source.settle(unverified_terminal("unverified winner")) ==
                SettleStatus::settled) {
                settled.fetch_add(1U, std::memory_order_relaxed);
            }
        });

    first.join();
    second.join();

    CHECK(settled.load(std::memory_order_relaxed) == 1U);
    const auto terminal = pair.wait.try_get();
    REQUIRE(terminal.has_value());
    if (terminal->detail == "verified winner") {
        CHECK(terminal->outcome == LifecycleOutcome::verified_success);
        CHECK(terminal->committed);
        CHECK_FALSE(terminal->commit_ambiguous);
        CHECK_FALSE(terminal->transient);
    } else {
        CHECK(terminal->detail == "unverified winner");
        CHECK(terminal->outcome == LifecycleOutcome::not_verified);
        CHECK_FALSE(terminal->committed);
        CHECK(terminal->commit_ambiguous);
        CHECK(terminal->transient);
    }

    CHECK(pair.source.settle(
              verified_terminal("late terminal")) ==
          SettleStatus::already_settled);
    LifecycleCompletion::Source empty_source;
    CHECK(empty_source.settle(
              unverified_terminal("no source")) ==
          SettleStatus::no_source);
}

TEST_CASE("runtime firewall lifecycle completion wakes every waiter") {
    using namespace std::chrono_literals;

    auto pair = LifecycleCompletion::create();
    auto first_wait = pair.wait;
    auto second_wait = pair.wait;
    std::optional<LifecycleTerminal> first_terminal;
    std::optional<LifecycleTerminal> second_terminal;

    std::thread first([&]() {
        first_terminal = first_wait.wait_for(2s);
    });
    std::thread second([&]() {
        second_terminal = second_wait.wait_for(2s);
    });

    CHECK(pair.source.settle(
              verified_terminal("both waiters")) ==
          SettleStatus::settled);
    first.join();
    second.join();

    REQUIRE(first_terminal.has_value());
    REQUIRE(second_terminal.has_value());
    CHECK(first_terminal->outcome ==
          LifecycleOutcome::verified_success);
    CHECK(second_terminal->outcome ==
          LifecycleOutcome::verified_success);
    CHECK(first_terminal->detail == "both waiters");
    CHECK(second_terminal->detail == "both waiters");
}

TEST_CASE(
    "last runtime firewall lifecycle source publishes conservative terminal") {
    using namespace std::chrono_literals;

    auto pair = LifecycleCompletion::create();
    auto last_source = pair.source;
    auto wait = pair.wait;

    pair.source = {};
    CHECK_FALSE(wait.ready());
    last_source = {};

    const auto terminal = wait.wait_for(2s);
    REQUIRE(terminal.has_value());
    CHECK(terminal->outcome == LifecycleOutcome::not_verified);
    CHECK_FALSE(terminal->committed);
    CHECK(terminal->commit_ambiguous);
    CHECK_FALSE(terminal->transient);
    CHECK(terminal->detail ==
          "runtime firewall lifecycle source abandoned");
}

TEST_CASE("runtime firewall lifecycle completion preserves shutdown") {
    auto pair = LifecycleCompletion::create();
    LifecycleTerminal shutdown{
        LifecycleOutcome::shutdown,
        false,
        false,
        false,
        "daemon shutdown"};

    CHECK(pair.source.settle(std::move(shutdown)) ==
          SettleStatus::settled);
    const auto terminal = pair.wait.wait();
    CHECK(terminal.outcome == LifecycleOutcome::shutdown);
    CHECK_FALSE(terminal.committed);
    CHECK_FALSE(terminal.commit_ambiguous);
    CHECK_FALSE(terminal.transient);
    CHECK(terminal.detail == "daemon shutdown");
}
