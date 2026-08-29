#include <doctest/doctest.h>

#include "daemon/api_runtime_lifecycle.hpp"

#include <array>
#include <stdexcept>
#include <vector>

using namespace keen_pbr3;

TEST_CASE("failed API setup retires every partially published resource") {
    bool server_live = false;
    bool context_live = false;
    bool conntrack_live = false;
    std::size_t rollback_calls = 0U;

    CHECK_THROWS_AS(
        run_api_setup_with_strong_rollback(
            [&]() {
                server_live = true;
                context_live = true;
                conntrack_live = true;
                throw std::runtime_error("setup failed after publication");
            },
            [&]() noexcept {
                ++rollback_calls;
                server_live = false;
                context_live = false;
                conntrack_live = false;
            }),
        std::runtime_error);

    CHECK(rollback_calls == 2U);
    CHECK_FALSE(server_live);
    CHECK_FALSE(context_live);
    CHECK_FALSE(conntrack_live);
}

TEST_CASE("successful API setup does not execute rollback") {
    bool setup_finished = false;
    std::size_t rollback_calls = 0U;

    run_api_setup_with_strong_rollback(
        [&]() { setup_finished = true; },
        [&]() noexcept { ++rollback_calls; });

    CHECK(setup_finished);
    CHECK(rollback_calls == 1U);
}

TEST_CASE("API retry retires the old conntrack registration before replacement") {
    bool registration_live = true;
    std::vector<int> order;

    const auto retry = [&]() {
        replace_api_conntrack_monitor_for_retry(
            [&]() {
                order.push_back(1);
                registration_live = false;
            },
            [&]() {
                order.push_back(registration_live ? -2 : 2);
                registration_live = true;
            });
    };

    retry();
    retry();

    CHECK(registration_live);
    CHECK(order == std::vector<int>{1, 2, 1, 2});
}

TEST_CASE("API retry leaves no old registration when replacement fails") {
    bool registration_live = true;

    CHECK_THROWS_AS(
        replace_api_conntrack_monitor_for_retry(
            [&]() { registration_live = false; },
            []() { throw std::runtime_error("replacement failed"); }),
        std::runtime_error);
    CHECK_FALSE(registration_live);
}

TEST_CASE("API teardown retires server before context and conntrack state") {
    bool server_live = true;
    bool context_live = true;
    bool conntrack_live = true;
    bool context_observed_stopped_server = false;
    bool conntrack_observed_retired_dependencies = false;
    std::array<int, 6> calls{};
    std::size_t call_count = 0U;

    const auto retire = [&]() {
        retire_api_runtime_in_dependency_order(
            [&]() noexcept {
                calls[call_count++] = 1;
                server_live = false;
            },
            [&]() noexcept {
                calls[call_count++] = 2;
                context_observed_stopped_server = !server_live;
                context_live = false;
            },
            [&]() {
                calls[call_count++] = 3;
                conntrack_observed_retired_dependencies =
                    !server_live && !context_live;
                conntrack_live = false;
            });
    };

    retire();
    retire();

    CHECK_FALSE(server_live);
    CHECK_FALSE(context_live);
    CHECK_FALSE(conntrack_live);
    CHECK(context_observed_stopped_server);
    CHECK(conntrack_observed_retired_dependencies);
    CHECK(calls == std::array<int, 6>{1, 2, 3, 1, 2, 3});
}

TEST_CASE("closed post-setup service gate retires the newly opened API") {
    bool server_live = true;
    bool context_live = true;
    bool conntrack_live = true;
    std::size_t retire_calls = 0U;

    const auto retain = retain_api_runtime_after_setup_if_gate_open(
        false,
        [&]() noexcept {
            ++retire_calls;
            server_live = false;
            context_live = false;
            conntrack_live = false;
        });

    CHECK_FALSE(retain);
    CHECK(retire_calls == 1U);
    CHECK_FALSE(server_live);
    CHECK_FALSE(context_live);
    CHECK_FALSE(conntrack_live);

    CHECK(retain_api_runtime_after_setup_if_gate_open(
        true, [&]() noexcept { ++retire_calls; }));
    CHECK(retire_calls == 1U);
}
