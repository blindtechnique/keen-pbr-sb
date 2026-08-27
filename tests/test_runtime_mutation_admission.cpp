#include <doctest/doctest.h>

#include "daemon/config_reload_coordinator.hpp"
#include "runtime/runtime_mutation_admission.hpp"

#include <atomic>
#include <chrono>
#include <thread>
#include <utility>

using namespace keen_pbr3;

TEST_CASE("runtime mutation admission holds exactly one RAII lease") {
    RuntimeMutationAdmission admission;

    auto first = admission.try_acquire("config-apply");
    REQUIRE(first.has_value());
    CHECK(admission.owns(*first));
    CHECK_FALSE(admission.try_acquire("urltest-switch").has_value());

    const auto first_active = admission.active();
    REQUIRE(first_active.has_value());
    CHECK(first_active->token == first->token());
    CHECK(first_active->label == "config-apply");

    const auto first_token = first->token();
    RuntimeMutationAdmission::Lease moved{std::move(*first)};
    CHECK_FALSE(static_cast<bool>(*first));
    CHECK(admission.owns(moved));
    CHECK(moved.token() == first_token);

    moved.release();
    CHECK_FALSE(admission.owns(moved));

    auto second = admission.try_acquire("urltest-switch");
    REQUIRE(second.has_value());
    CHECK(second->token() != first_token);
    CHECK(admission.owns(*second));

    // A duplicate release from a retired lease must not clear the newer
    // owner's token.
    moved.release();
    CHECK(admission.owns(*second));
    const auto second_active = admission.active();
    REQUIRE(second_active.has_value());
    CHECK(second_active->token == second->token());
    CHECK(second_active->label == "urltest-switch");
}

TEST_CASE("runtime mutation admission releases ownership on destruction") {
    RuntimeMutationAdmission admission;

    {
        auto lease = admission.try_acquire("runtime-repair");
        REQUIRE(lease.has_value());
        CHECK(admission.owns(*lease));
    }

    CHECK_FALSE(admission.active().has_value());
    auto replacement = admission.try_acquire("runtime-repair");
    REQUIRE(replacement.has_value());
    CHECK(admission.owns(*replacement));
}

TEST_CASE("runtime mutation admission handoff gate closes only its scope") {
    RuntimeMutationAdmission admission;
    auto active = admission.try_acquire("config-apply");
    REQUIRE(active.has_value());

    auto handoff =
        admission.try_acquire_handoff_gate(*active);
    REQUIRE(handoff.has_value());
    REQUIRE(static_cast<bool>(*handoff));
    auto second =
        admission.try_acquire_handoff_gate(*active);
    REQUIRE(second.has_value());
    RuntimeMutationAdmission::HandoffGate moved{
        std::move(*second)};
    CHECK_FALSE(static_cast<bool>(*second));
    CHECK(admission.owns(*active));
    active->release();
    CHECK_FALSE(admission.active().has_value());
    CHECK_FALSE(
        admission.try_acquire("during-handoff").has_value());
    CHECK_FALSE(
        admission.wait_for_idle_for(std::chrono::milliseconds{0}));

    std::atomic<bool> waiter_finished{false};
    std::atomic<bool> waiter_ready{false};
    std::thread waiter([&] {
        waiter_ready.store(true, std::memory_order_release);
        waiter_finished.store(
            admission.wait_until_idle(),
            std::memory_order_release);
    });
    while (!waiter_ready.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    CHECK_FALSE(waiter_finished.load(std::memory_order_acquire));

    handoff->release();
    handoff->release();
    CHECK_FALSE(
        admission.wait_for_idle_for(std::chrono::milliseconds{0}));
    CHECK_FALSE(waiter_finished.load(std::memory_order_acquire));
    moved.release();
    waiter.join();
    CHECK(waiter_finished.load(std::memory_order_acquire));
    auto resumed = admission.try_acquire("after-handoff");
    REQUIRE(resumed.has_value());
    CHECK(admission.owns(*resumed));
}

TEST_CASE("runtime mutation handoff gate drains bounded shutdown") {
    RuntimeMutationAdmission admission;
    auto active = admission.try_acquire("config-apply");
    REQUIRE(active.has_value());
    auto handoff =
        admission.try_acquire_handoff_gate(*active);
    REQUIRE(handoff.has_value());

    active->release();
    admission.shutdown();
    CHECK_FALSE(
        admission.wait_for_idle_for(std::chrono::milliseconds{0}));
    CHECK_FALSE(admission.wait_until_idle());

    handoff->release();
    CHECK(
        admission.wait_for_idle_for(std::chrono::milliseconds{10}));
    CHECK_FALSE(admission.try_acquire("after-shutdown").has_value());
}

TEST_CASE("runtime mutation handoff gate may outlive admission") {
    std::optional<RuntimeMutationAdmission::HandoffGate> retained;
    {
        auto admission =
            std::make_unique<RuntimeMutationAdmission>();
        auto active = admission->try_acquire("config-apply");
        REQUIRE(active.has_value());
        retained =
            admission->try_acquire_handoff_gate(*active);
        REQUIRE(retained.has_value());
        active->release();
    }
    REQUIRE(static_cast<bool>(*retained));
    retained.reset();
}

TEST_CASE("runtime mutation admission shutdown is terminal") {
    RuntimeMutationAdmission admission;
    auto lease = admission.try_acquire("shutdown-race");
    REQUIRE(lease.has_value());

    admission.shutdown();

    // Closing admission rejects new work without invalidating an operation
    // which was already accepted and may still be committing kernel state.
    CHECK(admission.owns(*lease));
    CHECK(admission.active().has_value());
    CHECK_FALSE(admission.try_acquire("after-shutdown").has_value());
    CHECK_FALSE(admission.wait_for_idle_for(std::chrono::milliseconds{0}));

    // Releasing the last admitted operation wakes shutdown quiescence, but
    // terminal admission remains closed.
    lease->release();
    CHECK(admission.wait_for_idle_for(std::chrono::milliseconds{10}));
    CHECK_FALSE(admission.active().has_value());
    CHECK_FALSE(admission.try_acquire("after-release").has_value());
}

TEST_CASE("runtime mutation admission wakes deferred writer after release") {
    RuntimeMutationAdmission admission;
    auto blocker = admission.try_acquire("api-save");
    REQUIRE(blocker.has_value());

    std::atomic<bool> waiter_ready{false};
    std::atomic<bool> waiter_admitted{false};
    std::thread waiter([&] {
        waiter_ready.store(true, std::memory_order_release);
        waiter_admitted.store(
            admission.wait_until_idle(), std::memory_order_release);
    });

    while (!waiter_ready.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    blocker->release();
    waiter.join();

    CHECK(waiter_admitted.load(std::memory_order_acquire));
}

TEST_CASE("deferred SIGHUP coalescing retains one fresh reload") {
    RuntimeMutationAdmission admission;
    auto blocker = admission.try_acquire("api-restore");
    REQUIRE(blocker.has_value());

    ConfigReloadCoordinator reloads;
    const auto original = reloads.request();
    REQUIRE(original.status == ConfigReloadRequestStatus::started);
    const auto coalesced = reloads.request();
    CHECK(coalesced.status == ConfigReloadRequestStatus::coalesced);

    bool became_idle = false;
    std::thread waiter([&] { became_idle = admission.wait_until_idle(); });
    blocker->release();
    waiter.join();
    REQUIRE(became_idle);

    REQUIRE(reloads.cancel(original.claim));
    const auto completion = reloads.complete(original.claim);
    CHECK(completion.owned);
    CHECK(completion.rerun_requested);

    const auto fresh = reloads.request();
    CHECK(fresh.status == ConfigReloadRequestStatus::started);
}

TEST_CASE("runtime mutation admission rejects foreign and empty leases") {
    RuntimeMutationAdmission first;
    RuntimeMutationAdmission second;
    auto lease = first.try_acquire("first-owner");
    REQUIRE(lease.has_value());

    RuntimeMutationAdmission::Lease empty;
    CHECK_FALSE(first.owns(empty));
    CHECK_FALSE(second.owns(*lease));
    CHECK(first.owns(*lease));
    CHECK_FALSE(
        first.try_acquire_handoff_gate(empty).has_value());
    CHECK_FALSE(
        second.try_acquire_handoff_gate(*lease).has_value());
    auto gate = first.try_acquire_handoff_gate(*lease);
    REQUIRE(gate.has_value());
    gate->release();
}
