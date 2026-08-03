#include <doctest/doctest.h>

#include "daemon/config_reload_coordinator.hpp"

#include <atomic>
#include <thread>

using namespace keen_pbr3;

TEST_CASE("config reload coalesces a newer request and schedules one rerun") {
    ConfigReloadCoordinator coordinator;

    const auto first = coordinator.request();
    REQUIRE(first.status == ConfigReloadRequestStatus::started);
    REQUIRE(first.claim);

    const auto coalesced = coordinator.request();
    CHECK(coalesced.status == ConfigReloadRequestStatus::coalesced);
    CHECK_FALSE(coalesced.claim);

    CHECK(coordinator.claim_commit(first.claim) ==
          ConfigReloadCommitStatus::superseded);

    const auto completion = coordinator.complete(first.claim);
    CHECK(completion.owned);
    CHECK(completion.rerun_requested);

    const auto rerun = coordinator.request();
    REQUIRE(rerun.status == ConfigReloadRequestStatus::started);
    REQUIRE(rerun.claim);
    CHECK(rerun.claim.token != first.claim.token);
    CHECK(coordinator.claim_commit(rerun.claim) ==
          ConfigReloadCommitStatus::claimed);

    const auto rerun_completion = coordinator.complete(rerun.claim);
    CHECK(rerun_completion.owned);
    CHECK_FALSE(rerun_completion.rerun_requested);
}

TEST_CASE("config reload cancel wins an ambiguous control-post outcome") {
    ConfigReloadCoordinator coordinator;
    const auto request = coordinator.request();
    REQUIRE(request.status == ConfigReloadRequestStatus::started);

    REQUIRE(coordinator.cancel(request.claim));
    CHECK(coordinator.claim_commit(request.claim) ==
          ConfigReloadCommitStatus::lost);

    const auto completion = coordinator.complete(request.claim);
    CHECK(completion.owned);
    CHECK_FALSE(completion.rerun_requested);
    CHECK_FALSE(coordinator.complete(request.claim).owned);
}

TEST_CASE("config reload callback wins an ambiguous control-post outcome") {
    ConfigReloadCoordinator coordinator;
    const auto request = coordinator.request();
    REQUIRE(request.status == ConfigReloadRequestStatus::started);

    REQUIRE(coordinator.claim_commit(request.claim) ==
            ConfigReloadCommitStatus::claimed);
    CHECK_FALSE(coordinator.cancel(request.claim));

    const auto completion = coordinator.complete(request.claim);
    CHECK(completion.owned);
    CHECK_FALSE(completion.rerun_requested);
    CHECK_FALSE(coordinator.complete(request.claim).owned);
}

TEST_CASE("config reload cancel and callback race has exactly one owner") {
    for (int iteration = 0; iteration < 128; ++iteration) {
        ConfigReloadCoordinator coordinator;
        const auto request = coordinator.request();
        REQUIRE(request.status == ConfigReloadRequestStatus::started);

        std::atomic<bool> start{false};
        bool cancelled{false};
        ConfigReloadCommitStatus commit_status{
            ConfigReloadCommitStatus::lost};

        std::thread canceller([&]() {
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            cancelled = coordinator.cancel(request.claim);
        });
        std::thread callback([&]() {
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            commit_status = coordinator.claim_commit(request.claim);
        });

        start.store(true, std::memory_order_release);
        canceller.join();
        callback.join();

        const bool cancel_won =
            cancelled && commit_status == ConfigReloadCommitStatus::lost;
        const bool callback_won =
            !cancelled &&
            commit_status == ConfigReloadCommitStatus::claimed;
        CHECK(cancel_won != callback_won);

        CHECK(coordinator.complete(request.claim).owned);
        CHECK_FALSE(coordinator.complete(request.claim).owned);
    }
}

TEST_CASE("config reload stopped before commit cannot publish or rerun") {
    ConfigReloadCoordinator coordinator;
    const auto request = coordinator.request();
    REQUIRE(request.status == ConfigReloadRequestStatus::started);

    coordinator.request();
    coordinator.stop();

    CHECK(coordinator.claim_commit(request.claim) ==
          ConfigReloadCommitStatus::stopped);
    const auto completion = coordinator.complete(request.claim);
    CHECK(completion.owned);
    CHECK_FALSE(completion.rerun_requested);

    const auto after_stop = coordinator.request();
    CHECK(after_stop.status == ConfigReloadRequestStatus::stopped);
    CHECK_FALSE(after_stop.claim);
}

TEST_CASE("config reload rejects stale lost and empty tokens") {
    ConfigReloadCoordinator coordinator;
    const auto first = coordinator.request();
    REQUIRE(coordinator.claim_commit(first.claim) ==
            ConfigReloadCommitStatus::claimed);
    REQUIRE(coordinator.complete(first.claim).owned);

    const auto current = coordinator.request();
    REQUIRE(current.status == ConfigReloadRequestStatus::started);
    REQUIRE(current.claim.token != first.claim.token);

    CHECK(coordinator.claim_commit(first.claim) ==
          ConfigReloadCommitStatus::lost);
    CHECK_FALSE(coordinator.cancel(first.claim));
    CHECK_FALSE(coordinator.complete(first.claim).owned);

    const ConfigReloadClaim empty;
    CHECK(coordinator.claim_commit(empty) ==
          ConfigReloadCommitStatus::lost);
    CHECK_FALSE(coordinator.cancel(empty));
    CHECK_FALSE(coordinator.complete(empty).owned);

    REQUIRE(coordinator.claim_commit(current.claim) ==
            ConfigReloadCommitStatus::claimed);
    CHECK(coordinator.complete(current.claim).owned);
}

TEST_CASE("config reload completion releases ownership exactly once in every terminal phase") {
    SUBCASE("claimed") {
        ConfigReloadCoordinator coordinator;
        const auto request = coordinator.request();
        REQUIRE(coordinator.claim_commit(request.claim) ==
                ConfigReloadCommitStatus::claimed);
        CHECK(coordinator.complete(request.claim).owned);
        CHECK_FALSE(coordinator.complete(request.claim).owned);
    }

    SUBCASE("cancelled") {
        ConfigReloadCoordinator coordinator;
        const auto request = coordinator.request();
        REQUIRE(coordinator.cancel(request.claim));
        CHECK(coordinator.complete(request.claim).owned);
        CHECK_FALSE(coordinator.complete(request.claim).owned);
    }

    SUBCASE("superseded") {
        ConfigReloadCoordinator coordinator;
        const auto request = coordinator.request();
        coordinator.request();
        REQUIRE(coordinator.claim_commit(request.claim) ==
                ConfigReloadCommitStatus::superseded);
        CHECK(coordinator.complete(request.claim).owned);
        CHECK_FALSE(coordinator.complete(request.claim).owned);
    }

    SUBCASE("stopped") {
        ConfigReloadCoordinator coordinator;
        const auto request = coordinator.request();
        coordinator.stop();
        REQUIRE(coordinator.claim_commit(request.claim) ==
                ConfigReloadCommitStatus::stopped);
        CHECK(coordinator.complete(request.claim).owned);
        CHECK_FALSE(coordinator.complete(request.claim).owned);
    }
}
