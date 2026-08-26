#include <doctest/doctest.h>

#include "daemon/runtime_firewall_worker_operation.hpp"
#include "util/blocking_executor.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

using namespace keen_pbr3;

namespace {

struct TestWorkerInput {
    int value{0};
};

struct TestWorkerResult {
    int value{0};
};

using TestWorkerOperation =
    RuntimeFirewallWorkerOperation<TestWorkerInput, TestWorkerResult>;
using TestTerminal = TestWorkerOperation::TerminalEnvelope;
using TestTerminalStatus = TestWorkerOperation::TerminalStatus;
using TestTerminalMailboxPtr =
    TestWorkerOperation::TerminalMailboxPtr;
using TestMutationLeaseBinding =
    TestWorkerOperation::MutationLeaseBinding;
using TestMutationLeaseReturnPolicy =
    TestWorkerOperation::MutationLeaseReturnPolicy;

static_assert(
    !std::is_default_constructible_v<
        TestWorkerOperation::RunningClaim>);
static_assert(
    !std::is_constructible_v<
        TestWorkerOperation::RunningClaim,
        RuntimeFirewallOperationClaim>);
static_assert(!std::is_copy_constructible_v<TestMutationLeaseBinding>);
static_assert(
    std::is_nothrow_move_constructible_v<TestMutationLeaseBinding>);

RuntimeFirewallOperationClaim acquire_queued_claim(
    RuntimeFirewallRetryCoordinator& coordinator,
    std::uint64_t runtime_generation = 17U) {
    std::function<void()> timer_callback;
    std::optional<RuntimeFirewallOperationClaim> queued_claim;
    const auto plan = coordinator.schedule_operation(
        /*attempt=*/0,
        runtime_generation,
        /*bounded_retry_count=*/6,
        {},
        [&](const RuntimeFirewallRetryPlan&, auto callback) {
            timer_callback = std::move(callback);
            return 41;
        },
        [runtime_generation](std::uint64_t generation) {
            return generation == runtime_generation;
        },
        [&](RuntimeFirewallOperationClaim claim, OwnedSnatRecovery) {
            queued_claim = claim;
        });
    REQUIRE(plan.schedule);
    REQUIRE(static_cast<bool>(timer_callback));
    timer_callback();
    REQUIRE(queued_claim.has_value());
    REQUIRE(coordinator.operation_is_current(*queued_claim));
    return *queued_claim;
}

RuntimeFirewallOperationClaim acquire_typed_queued_claim(
    RuntimeFirewallRetryCoordinator& coordinator,
    std::uint64_t runtime_generation = 17U) {
    std::function<void()> timer_callback;
    std::optional<RuntimeFirewallOperationClaim> queued_claim;
    const PreparedNativeVpnCatalogPtr initial_catalog;
    const auto plan =
        coordinator
            .schedule_operation_with_prepared_catalog_and_terminal(
        /*attempt=*/0,
        runtime_generation,
        /*bounded_retry_count=*/6,
        {},
        initial_catalog,
        [&](const RuntimeFirewallRetryPlan&, auto callback) {
            timer_callback = std::move(callback);
            return 43;
        },
        [runtime_generation](std::uint64_t generation) {
            return generation == runtime_generation;
        },
        [&](RuntimeFirewallOperationClaim claim,
            OwnedSnatRecovery,
            PreparedNativeVpnCatalogPtr) {
            queued_claim = claim;
        },
        [](RuntimeFirewallOperationCompletion) noexcept {});
    REQUIRE(plan.schedule);
    REQUIRE(static_cast<bool>(timer_callback));
    timer_callback();
    REQUIRE(queued_claim.has_value());
    REQUIRE(coordinator.operation_is_current(*queued_claim));
    return *queued_claim;
}

TestWorkerOperation::MutationLeasePtr acquire_mutation_lease(
    RuntimeMutationAdmission& admission) {
    auto admitted = admission.try_acquire("runtime-firewall-worker-test");
    REQUIRE(admitted.has_value());
    return std::make_unique<RuntimeMutationAdmission::Lease>(
        std::move(*admitted));
}

TestWorkerOperation::OperationPtr make_operation(
    RuntimeFirewallRetryCoordinator& coordinator,
    RuntimeMutationAdmission& admission,
    RuntimeFirewallOperationClaim queued_claim,
    int value = 7,
    TestWorkerOperation::OnTerminalReady on_terminal_ready = {},
    TestTerminalMailboxPtr* retained_mailbox = nullptr) {
    auto mailbox = TestWorkerOperation::create_terminal_mailbox(
        std::move(on_terminal_ready));
    if (retained_mailbox != nullptr) {
        *retained_mailbox = mailbox;
    }
    auto operation = TestWorkerOperation::create(
        coordinator,
        queued_claim,
        std::make_shared<const TestWorkerInput>(
            TestWorkerInput{value}),
        acquire_mutation_lease(admission),
        mailbox);
    return operation;
}

bool same_claim(
    const RuntimeFirewallOperationClaim& left,
    const RuntimeFirewallOperationClaim& right) noexcept {
    return left.serial == right.serial &&
           left.runtime_generation == right.runtime_generation &&
           left.attempt == right.attempt &&
           left.phase == right.phase &&
           left.recovery_revision == right.recovery_revision;
}

void complete_running_terminal(
    RuntimeFirewallRetryCoordinator& coordinator,
    TestTerminal& terminal) {
    REQUIRE(terminal.running_claim.has_value());
    REQUIRE(terminal.mutation_lease.lease);
    CHECK(terminal.mutation_lease.return_policy ==
          TestMutationLeaseReturnPolicy::release_after_attempt);
    const auto control_claim = coordinator.begin_control(
        terminal.running_claim->raw_claim());
    REQUIRE(control_claim.has_value());
    CHECK(coordinator.complete_operation(*control_claim).owned);
    terminal.mutation_lease.lease.reset();
}

TestWorkerOperation::Worker successful_worker(
    int result_value,
    std::size_t* calls = nullptr) {
    return [result_value, calls](
               const TestWorkerInput&,
               const TestWorkerOperation::RunningClaim&) {
        if (calls != nullptr) ++*calls;
        return std::make_shared<const TestWorkerResult>(
            TestWorkerResult{result_value});
    };
}

} // namespace

TEST_CASE(
    "runtime firewall cancel pending publishes after releasing admission") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_typed_queued_claim(coordinator);
    std::size_t worker_calls = 0U;
    std::size_t wake_calls = 0U;
    bool admission_free_before_wake = false;
    auto operation = make_operation(
        coordinator,
        admission,
        queued_claim,
        /*value=*/7,
        [&]() {
            ++wake_calls;
            auto next = admission.try_acquire(
                "runtime-firewall-terminal-watchdog");
            admission_free_before_wake = next.has_value();
            throw std::runtime_error("control wake rejected");
        });

    PreparedNativeVpnCatalog prepared_catalog;
    prepared_catalog.runtime_generation = 17U;
    const auto prepared =
        std::make_shared<const PreparedNativeVpnCatalog>(
            std::move(prepared_catalog));
    const auto trailing =
        coordinator.begin_attempt_with_prepared_catalog(
            /*retry_attempt=*/0, {}, prepared);
    REQUIRE(trailing.coalesced);
    CHECK_FALSE(trailing.prepared_now);

    auto callback = operation->make_queued_closure(
        successful_worker(/*result_value=*/11, &worker_calls));

    BlockingExecutor executor(/*worker_count=*/0, /*max_queue_size=*/1);
    REQUIRE(executor.try_post(
        "runtime-firewall", std::move(callback)));
    callback = {};
    CHECK(coordinator.retry_pending());

    CHECK_NOTHROW(executor.cancel_pending());
    CHECK(worker_calls == 0U);
    CHECK(wake_calls == 1U);
    CHECK(admission_free_before_wake);
    CHECK_FALSE(coordinator.retry_pending());

    auto terminal = operation->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status ==
          TestTerminalStatus::queued_abandoned);
    CHECK_FALSE(terminal->running_claim.has_value());
    CHECK_FALSE(terminal->result);
    CHECK_FALSE(terminal->exception);
    CHECK_FALSE(terminal->mutation_lease);
    REQUIRE(terminal->coordinator_completion.has_value());
    CHECK(terminal->coordinator_completion->owned);
    CHECK(terminal->coordinator_completion->rerun_requested);
    CHECK(terminal->coordinator_completion
              ->next_prepared_catalog == prepared);
    CHECK_FALSE(operation->take_terminal().has_value());
}

TEST_CASE(
    "runtime firewall closure copies share one owner and one envelope") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::size_t wake_calls = 0U;
    TestTerminalMailboxPtr mailbox;
    auto operation = make_operation(
        coordinator,
        admission,
        queued_claim,
        /*value=*/7,
        [&]() { ++wake_calls; },
        &mailbox);

    std::function<void()> first = operation->make_queued_closure(
        successful_worker(/*result_value=*/13));
    CHECK_THROWS_AS(
        operation->make_queued_closure(
            successful_worker(/*result_value=*/17)),
        std::logic_error);

    std::function<void()> copy = first;
    std::function<void()> moved = std::move(copy);
    first = {};
    copy = {};
    CHECK(wake_calls == 0U);
    CHECK(coordinator.operation_is_current(queued_claim));

    moved = {};
    CHECK(wake_calls == 1U);
    CHECK_FALSE(coordinator.retry_pending());
    auto terminal = operation->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status ==
          TestTerminalStatus::queued_abandoned);
    CHECK_FALSE(operation->take_terminal().has_value());
    operation.reset();
    CHECK(wake_calls == 1U);
    CHECK_FALSE(mailbox->take_terminal().has_value());
}

TEST_CASE(
    "runtime firewall drop before queue arm preserves exact terminal") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim =
        acquire_typed_queued_claim(coordinator);
    std::size_t wake_calls = 0U;
    bool admission_free_before_wake = false;
    const auto mailbox =
        TestWorkerOperation::create_terminal_mailbox([&]() {
            ++wake_calls;
            auto next = admission.try_acquire(
                "unarmed-operation-watchdog");
            admission_free_before_wake = next.has_value();
            throw std::runtime_error("unarmed control wake rejected");
        });
    auto operation = TestWorkerOperation::create(
        coordinator,
        queued_claim,
        std::make_shared<const TestWorkerInput>(
            TestWorkerInput{17}),
        acquire_mutation_lease(admission),
        mailbox);

    PreparedNativeVpnCatalog prepared_catalog;
    prepared_catalog.runtime_generation = 17U;
    auto prepared =
        std::make_shared<const PreparedNativeVpnCatalog>(
            std::move(prepared_catalog));
    const std::weak_ptr<const PreparedNativeVpnCatalog> lifetime =
        prepared;
    const auto trailing =
        coordinator.begin_attempt_with_prepared_catalog(
            /*retry_attempt=*/0, {}, prepared);
    REQUIRE(trailing.coalesced);
    CHECK_FALSE(trailing.prepared_now);
    prepared.reset();
    CHECK_FALSE(lifetime.expired());

    CHECK_NOTHROW(operation.reset());
    CHECK(wake_calls == 1U);
    CHECK(admission_free_before_wake);
    CHECK_FALSE(coordinator.retry_pending());
    CHECK_FALSE(lifetime.expired());

    auto terminal = mailbox->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status ==
          TestTerminalStatus::queued_abandoned);
    CHECK_FALSE(terminal->running_claim.has_value());
    CHECK_FALSE(terminal->mutation_lease);
    REQUIRE(terminal->coordinator_completion.has_value());
    CHECK(terminal->coordinator_completion->owned);
    CHECK(terminal->coordinator_completion->rerun_requested);
    REQUIRE(terminal->coordinator_completion
                ->next_prepared_catalog);
    CHECK(terminal->coordinator_completion
              ->next_prepared_catalog->runtime_generation == 17U);
    CHECK_FALSE(mailbox->take_terminal().has_value());

    terminal.reset();
    CHECK(lifetime.expired());
}

TEST_CASE(
    "runtime firewall queue rejection and pre-handoff throw terminalize once") {
    SUBCASE("BlockingExecutor rejects the last callback") {
        RuntimeFirewallRetryCoordinator coordinator;
        RuntimeMutationAdmission admission;
        const auto queued_claim = acquire_queued_claim(coordinator);
        std::size_t wake_calls = 0U;
        bool admission_free_before_wake = false;
        auto operation = make_operation(
            coordinator,
            admission,
            queued_claim,
            /*value=*/7,
            [&]() {
                ++wake_calls;
                admission_free_before_wake = admission.try_acquire(
                    "ordinary-rejection-watchdog").has_value();
            });
        auto callback = operation->make_queued_closure(
            successful_worker(/*result_value=*/19));

        BlockingExecutor executor(
            /*worker_count=*/0, /*max_queue_size=*/0);
        CHECK_FALSE(executor.try_post(
            "runtime-firewall", std::move(callback)));
        callback = {};

        CHECK(wake_calls == 1U);
        CHECK(admission_free_before_wake);
        auto terminal = operation->take_terminal();
        REQUIRE(terminal.has_value());
        CHECK(terminal->status ==
              TestTerminalStatus::queued_abandoned);
        CHECK_FALSE(terminal->mutation_lease);
        CHECK(terminal->mutation_lease.return_policy ==
              TestMutationLeaseReturnPolicy::release_after_attempt);
    }

    SUBCASE("throw before ownership destroys the adapter argument") {
        RuntimeFirewallRetryCoordinator coordinator;
        RuntimeMutationAdmission admission;
        const auto queued_claim = acquire_queued_claim(coordinator);
        std::size_t wake_calls = 0U;
        auto operation = make_operation(
            coordinator,
            admission,
            queued_claim,
            /*value=*/7,
            [&]() { ++wake_calls; });
        auto callback = operation->make_queued_closure(
            successful_worker(/*result_value=*/23));

        const auto throwing_adapter =
            [](std::function<void()>) -> bool {
            throw std::runtime_error("queue rejected before handoff");
        };
        CHECK_THROWS_AS(
            throwing_adapter(std::move(callback)),
            std::runtime_error);
        callback = {};

        CHECK(wake_calls == 1U);
        REQUIRE(operation->take_terminal().has_value());
        CHECK_FALSE(coordinator.retry_pending());
    }
}

TEST_CASE(
    "runtime firewall retained queue rejection returns the exact lease") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::size_t wake_calls = 0U;
    bool admission_held_before_wake = false;
    bool pending_cleared_before_wake = false;
    TestTerminalMailboxPtr mailbox;
    mailbox = TestWorkerOperation::create_terminal_mailbox([&]() {
        ++wake_calls;
        admission_held_before_wake = !admission.try_acquire(
            "retained-rejection-watchdog").has_value();
        pending_cleared_before_wake =
            !mailbox->retained_mutation_lease_pending();
    });

    auto mutation_lease = acquire_mutation_lease(admission);
    const auto* const exact_lease = mutation_lease.get();
    auto operation = TestWorkerOperation::create(
        coordinator,
        queued_claim,
        std::make_shared<const TestWorkerInput>(TestWorkerInput{53}),
        TestMutationLeaseBinding::retained_lease(
            std::move(mutation_lease)),
        mailbox);
    CHECK(mailbox->retained_mutation_lease_pending());

    auto callback = operation->make_queued_closure(
        successful_worker(/*result_value=*/59));
    BlockingExecutor executor(/*worker_count=*/0, /*max_queue_size=*/0);
    CHECK_FALSE(executor.try_post(
        "runtime-firewall", std::move(callback)));
    callback = {};

    CHECK(wake_calls == 1U);
    CHECK(admission_held_before_wake);
    CHECK(pending_cleared_before_wake);
    auto terminal = operation->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status == TestTerminalStatus::queued_abandoned);
    CHECK_FALSE(terminal->running_claim.has_value());
    REQUIRE(terminal->coordinator_completion.has_value());
    REQUIRE(terminal->mutation_lease.lease);
    CHECK(terminal->mutation_lease.lease.get() == exact_lease);
    CHECK(terminal->mutation_lease.return_policy ==
          TestMutationLeaseReturnPolicy::return_to_operation_owner);
    CHECK_FALSE(mailbox->retained_mutation_lease_pending());
    CHECK_FALSE(admission.try_acquire("before-retained-return").has_value());

    terminal->mutation_lease.lease.reset();
    CHECK(admission.try_acquire("after-retained-return").has_value());
}

TEST_CASE(
    "runtime firewall retained prequeue failure returns the exact lease") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::size_t wake_calls = 0U;
    const auto mailbox = TestWorkerOperation::create_terminal_mailbox(
        [&]() { ++wake_calls; });
    auto mutation_lease = acquire_mutation_lease(admission);
    const auto* const exact_lease = mutation_lease.get();
    auto operation = TestWorkerOperation::create(
        coordinator,
        queued_claim,
        std::make_shared<const TestWorkerInput>(TestWorkerInput{61}),
        TestMutationLeaseBinding::retained_lease(
            std::move(mutation_lease)),
        mailbox);

    CHECK_THROWS_AS(
        operation->make_queued_closure({}),
        std::invalid_argument);
    CHECK(mailbox->retained_mutation_lease_pending());
    CHECK_NOTHROW(operation.reset());

    CHECK(wake_calls == 1U);
    CHECK_FALSE(mailbox->retained_mutation_lease_pending());
    auto terminal = mailbox->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status == TestTerminalStatus::queued_abandoned);
    REQUIRE(terminal->coordinator_completion.has_value());
    REQUIRE(terminal->mutation_lease.lease);
    CHECK(terminal->mutation_lease.lease.get() == exact_lease);
    CHECK(terminal->mutation_lease.return_policy ==
          TestMutationLeaseReturnPolicy::return_to_operation_owner);

    terminal->mutation_lease.lease.reset();
    CHECK(admission.try_acquire("after-prequeue-return").has_value());
}

TEST_CASE(
    "runtime firewall retained queue survives an adapter throw") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::size_t worker_calls = 0U;
    std::size_t wake_calls = 0U;
    auto operation = make_operation(
        coordinator,
        admission,
        queued_claim,
        /*value=*/7,
        [&]() { ++wake_calls; });
    auto callback = operation->make_queued_closure(
        successful_worker(/*result_value=*/29, &worker_calls));

    std::function<void()> retained;
    const auto handoff_then_throw =
        [&](std::function<void()> queued) -> bool {
        retained = std::move(queued);
        throw std::runtime_error("adapter threw after retaining work");
    };
    CHECK_THROWS_AS(
        handoff_then_throw(std::move(callback)),
        std::runtime_error);
    callback = {};
    CHECK(wake_calls == 0U);
    CHECK(coordinator.operation_is_current(queued_claim));

    retained();
    retained = {};
    CHECK(worker_calls == 1U);
    CHECK(wake_calls == 1U);

    auto terminal = operation->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status == TestTerminalStatus::result);
    complete_running_terminal(coordinator, *terminal);
}

TEST_CASE(
    "runtime firewall result is published before wake and transfers lease") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::size_t worker_calls = 0U;
    std::size_t wake_calls = 0U;
    std::optional<RuntimeFirewallOperationClaim> observed_running;
    std::optional<TestTerminal> observed_terminal;
    TestTerminalMailboxPtr mailbox;
    auto operation = make_operation(
        coordinator,
        admission,
        queued_claim,
        /*value=*/31,
        [&]() {
            ++wake_calls;
            observed_terminal = mailbox->take_terminal();
        },
        &mailbox);

    auto callback = operation->make_queued_closure(
        [&](const TestWorkerInput& input,
            const TestWorkerOperation::RunningClaim& running) {
            ++worker_calls;
            CHECK(input.value == 31);
            observed_running = running.raw_claim();
            return std::make_shared<const TestWorkerResult>(
                TestWorkerResult{37});
        });

    callback();
    callback = {};
    CHECK(worker_calls == 1U);
    CHECK(wake_calls == 1U);
    REQUIRE(observed_running.has_value());
    REQUIRE(observed_terminal.has_value());
    CHECK(observed_terminal->status ==
          TestTerminalStatus::result);
    REQUIRE(observed_terminal->running_claim.has_value());
    CHECK(same_claim(
        observed_terminal->running_claim->raw_claim(),
        *observed_running));
    REQUIRE(observed_terminal->result);
    CHECK(observed_terminal->result->value == 37);
    CHECK_FALSE(observed_terminal->exception);
    CHECK_FALSE(
        observed_terminal->coordinator_completion.has_value());
    REQUIRE(observed_terminal->mutation_lease);
    CHECK_FALSE(admission.try_acquire("early-control").has_value());
    CHECK_FALSE(operation->take_terminal().has_value());

    operation.reset();
    CHECK_FALSE(admission.try_acquire("lost-result-owner").has_value());
    complete_running_terminal(coordinator, *observed_terminal);
    CHECK(admission.try_acquire("after-control").has_value());
}

TEST_CASE(
    "runtime firewall worker exception becomes a durable running terminal") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::size_t wake_calls = 0U;
    auto operation = make_operation(
        coordinator,
        admission,
        queued_claim,
        /*value=*/7,
        [&]() {
            ++wake_calls;
            throw std::runtime_error("control post rejected");
        });
    auto callback = operation->make_queued_closure(
        [](const TestWorkerInput&,
           const TestWorkerOperation::RunningClaim&)
            -> TestWorkerOperation::ResultPtr {
            throw std::runtime_error("backend commit failed");
        });

    CHECK_NOTHROW(callback());
    callback = {};
    CHECK(wake_calls == 1U);
    auto terminal = operation->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status == TestTerminalStatus::exception);
    REQUIRE(terminal->running_claim.has_value());
    CHECK_FALSE(terminal->result);
    REQUIRE(terminal->exception);
    CHECK_THROWS_WITH_AS(
        std::rethrow_exception(terminal->exception),
        "backend commit failed",
        std::runtime_error);
    REQUIRE(terminal->mutation_lease);
    complete_running_terminal(coordinator, *terminal);
}

TEST_CASE(
    "runtime firewall null worker result becomes missing-result terminal") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::size_t wake_calls = 0U;
    auto operation = make_operation(
        coordinator,
        admission,
        queued_claim,
        /*value=*/7,
        [&]() { ++wake_calls; });
    auto callback = operation->make_queued_closure(
        [](const TestWorkerInput&,
           const TestWorkerOperation::RunningClaim&)
            -> TestWorkerOperation::ResultPtr {
            return {};
        });

    callback();
    callback = {};
    CHECK(wake_calls == 1U);
    auto terminal = operation->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status ==
          TestTerminalStatus::missing_result);
    REQUIRE(terminal->running_claim.has_value());
    CHECK_FALSE(terminal->result);
    CHECK_FALSE(terminal->exception);
    REQUIRE(terminal->mutation_lease);
    complete_running_terminal(coordinator, *terminal);
}

TEST_CASE(
    "runtime firewall invoked copies run and wake exactly once") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::size_t worker_calls = 0U;
    std::size_t wake_calls = 0U;
    auto operation = make_operation(
        coordinator,
        admission,
        queued_claim,
        /*value=*/7,
        [&]() { ++wake_calls; });
    auto callback = operation->make_queued_closure(
        successful_worker(/*result_value=*/41, &worker_calls));
    auto copy = callback;

    callback();
    copy();
    callback = {};
    copy = {};

    CHECK(worker_calls == 1U);
    CHECK(wake_calls == 1U);
    auto terminal = operation->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status == TestTerminalStatus::result);
    CHECK_FALSE(operation->take_terminal().has_value());
    complete_running_terminal(coordinator, *terminal);
}

TEST_CASE(
    "runtime firewall rejects a result after premature control transition") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::optional<RuntimeFirewallOperationClaim> control_claim;
    std::size_t wake_calls = 0U;
    auto operation = make_operation(
        coordinator,
        admission,
        queued_claim,
        /*value=*/7,
        [&]() { ++wake_calls; });
    auto callback = operation->make_queued_closure(
        [&](const TestWorkerInput&,
            const TestWorkerOperation::RunningClaim& running) {
            control_claim = coordinator.begin_control(
                running.raw_claim());
            REQUIRE(control_claim.has_value());
            return std::make_shared<const TestWorkerResult>(
                TestWorkerResult{43});
        });

    callback();
    callback = {};
    CHECK(wake_calls == 1U);
    auto terminal = operation->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status == TestTerminalStatus::lost_claim);
    REQUIRE(terminal->running_claim.has_value());
    CHECK_FALSE(terminal->result);
    CHECK_FALSE(terminal->exception);
    REQUIRE(terminal->mutation_lease);
    REQUIRE(control_claim.has_value());
    CHECK(coordinator.complete_operation(*control_claim).owned);
    terminal->mutation_lease.reset();
    CHECK(admission.try_acquire("after-stale-result").has_value());
}

TEST_CASE(
    "runtime firewall create rejects a claim which is no longer current") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    REQUIRE(coordinator.cancel_operation(queued_claim));
    auto lease = acquire_mutation_lease(admission);
    const auto mailbox =
        TestWorkerOperation::create_terminal_mailbox();

    CHECK_THROWS_AS(
        TestWorkerOperation::create(
            coordinator,
            queued_claim,
            std::make_shared<const TestWorkerInput>(
                TestWorkerInput{43}),
            std::move(lease),
            mailbox),
        std::invalid_argument);
    CHECK_FALSE(lease);
    CHECK(admission.try_acquire("after-create-reject").has_value());
}

TEST_CASE(
    "runtime firewall begin-worker loss releases lease and wakes once") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::size_t worker_calls = 0U;
    std::size_t wake_calls = 0U;
    bool admission_free_before_wake = false;
    auto operation = make_operation(
        coordinator,
        admission,
        queued_claim,
        /*value=*/7,
        [&]() {
            ++wake_calls;
            auto next = admission.try_acquire(
                "lost-claim-watchdog");
            admission_free_before_wake = next.has_value();
        });
    auto callback = operation->make_queued_closure(
        successful_worker(/*result_value=*/47, &worker_calls));
    auto copy = callback;

    REQUIRE(coordinator.cancel_operation(queued_claim));
    callback();
    copy();
    callback = {};
    copy = {};

    CHECK(worker_calls == 0U);
    CHECK(wake_calls == 1U);
    CHECK(admission_free_before_wake);
    auto terminal = operation->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status == TestTerminalStatus::lost_claim);
    CHECK_FALSE(terminal->running_claim.has_value());
    CHECK_FALSE(terminal->coordinator_completion.has_value());
    CHECK_FALSE(terminal->mutation_lease);
    CHECK_FALSE(operation->take_terminal().has_value());
}

TEST_CASE(
    "runtime firewall begin-worker loss returns a retained exact lease") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto queued_claim = acquire_queued_claim(coordinator);
    std::size_t worker_calls = 0U;
    std::size_t wake_calls = 0U;
    bool admission_held_before_wake = false;
    bool pending_cleared_before_wake = false;
    TestTerminalMailboxPtr mailbox;
    mailbox = TestWorkerOperation::create_terminal_mailbox([&]() {
        ++wake_calls;
        admission_held_before_wake = !admission.try_acquire(
            "retained-lost-claim-watchdog").has_value();
        pending_cleared_before_wake =
            !mailbox->retained_mutation_lease_pending();
    });
    auto mutation_lease = acquire_mutation_lease(admission);
    const auto* const exact_lease = mutation_lease.get();
    auto operation = TestWorkerOperation::create(
        coordinator,
        queued_claim,
        std::make_shared<const TestWorkerInput>(TestWorkerInput{67}),
        TestMutationLeaseBinding::retained_lease(
            std::move(mutation_lease)),
        mailbox);
    auto callback = operation->make_queued_closure(
        successful_worker(/*result_value=*/71, &worker_calls));

    REQUIRE(coordinator.cancel_operation(queued_claim));
    callback();
    callback = {};

    CHECK(worker_calls == 0U);
    CHECK(wake_calls == 1U);
    CHECK(admission_held_before_wake);
    CHECK(pending_cleared_before_wake);
    auto terminal = operation->take_terminal();
    REQUIRE(terminal.has_value());
    CHECK(terminal->status == TestTerminalStatus::lost_claim);
    CHECK_FALSE(terminal->running_claim.has_value());
    CHECK_FALSE(terminal->coordinator_completion.has_value());
    REQUIRE(terminal->mutation_lease.lease);
    CHECK(terminal->mutation_lease.lease.get() == exact_lease);
    CHECK(terminal->mutation_lease.return_policy ==
          TestMutationLeaseReturnPolicy::return_to_operation_owner);

    terminal->mutation_lease.lease.reset();
    CHECK(admission.try_acquire("after-retained-lost-claim").has_value());
}
