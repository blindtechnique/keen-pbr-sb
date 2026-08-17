#include <doctest/doctest.h>

#include "runtime/lifecycle_operation.hpp"

#include <stdexcept>

using namespace keen_pbr3;

TEST_CASE("lifecycle operation serializes mutations and preserves terminal state") {
    LifecycleOperationStore store;
    LifecycleOperationCoordinator coordinator(store);
    LifecycleOperationSnapshot operation;

    CHECK_FALSE(coordinator.begin(
        LifecycleOperationType::Restart,
        {{"stop", "Stop"}, {"start", "Start"}},
        operation));

    LifecycleOperationSnapshot rejected;
    CHECK(coordinator.begin(
              LifecycleOperationType::Start,
              {{"start", "Start"}},
              rejected) == operation.id);

    coordinator.start_stage(operation.id, "stop");
    coordinator.succeed_stage(operation.id, "stop");
    coordinator.start_stage(operation.id, "start");
    coordinator.fail_stage(operation.id, "start", "probe failed");
    coordinator.finish(operation.id, "probe failed");

    const auto snapshot = store.snapshot();
    REQUIRE(snapshot);
    CHECK(snapshot->result == LifecycleOperationResult::Failed);
    CHECK(snapshot->error == "probe failed");
    CHECK(snapshot->finished_at.has_value());
    CHECK(snapshot->stages[0].status == LifecycleOperationStatus::Succeeded);
    CHECK(snapshot->stages[1].status == LifecycleOperationStatus::Failed);
}

TEST_CASE("lifecycle store callback runs after snapshot publication") {
    LifecycleOperationStore store;
    LifecycleOperationCoordinator coordinator(store);
    bool observed = false;
    store.set_publish_callback([&] { observed = store.snapshot().has_value(); });

    LifecycleOperationSnapshot operation;
    CHECK_FALSE(coordinator.begin(
        LifecycleOperationType::Stop,
        {{"stop", "Stop"}},
        operation));
    CHECK(observed);
}

TEST_CASE("lifecycle publish failure does not strand active operation") {
    LifecycleOperationStore store;
    LifecycleOperationCoordinator coordinator(store);
    bool fail_once = true;
    store.set_publish_callback([&] {
        if (!fail_once) return;
        fail_once = false;
        throw std::runtime_error("injected publication failure");
    });

    LifecycleOperationSnapshot failed;
    CHECK_THROWS_AS(
        coordinator.begin(
            LifecycleOperationType::ApplyConfig,
            {{"validate", "Validate"}},
            failed),
        std::runtime_error);

    LifecycleOperationSnapshot recovered;
    CHECK_FALSE(coordinator.begin(
        LifecycleOperationType::ApplyConfig,
        {{"validate", "Validate"}},
        recovered));
    coordinator.finish(recovered.id);
}

TEST_CASE("lifecycle terminal publish failure releases active operation") {
    LifecycleOperationStore store;
    LifecycleOperationCoordinator coordinator(store);
    LifecycleOperationSnapshot operation;
    REQUIRE_FALSE(coordinator.begin(
        LifecycleOperationType::ApplyConfig,
        {{"validate", "Validate"}},
        operation));

    bool fail_once = true;
    store.set_publish_callback([&] {
        if (!fail_once) return;
        fail_once = false;
        throw std::runtime_error(
            "injected terminal publication failure");
    });
    CHECK_THROWS_AS(
        coordinator.finish(operation.id), std::runtime_error);

    LifecycleOperationSnapshot recovered;
    CHECK_FALSE(coordinator.begin(
        LifecycleOperationType::ApplyConfig,
        {{"validate", "Validate"}},
        recovered));
    coordinator.finish(recovered.id);
}
