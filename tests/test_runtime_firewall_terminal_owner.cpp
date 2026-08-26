#include <doctest/doctest.h>

#include "daemon/runtime_firewall_terminal_owner.hpp"
#include "util/blocking_executor.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

using namespace keen_pbr3;

namespace {

struct TerminalOwnerInput {
    int value{0};
};

struct TerminalOwnerResult {
    int value{0};
};

using WorkerOperation = RuntimeFirewallWorkerOperation<
    TerminalOwnerInput, TerminalOwnerResult>;
using TerminalOwner = RuntimeFirewallTerminalOwner<
    TerminalOwnerInput, TerminalOwnerResult>;

static_assert(
    std::is_nothrow_invocable_v<
        TerminalOwner::CoordinatorTerminalSink&,
        RuntimeFirewallOperationCompletion>);

RuntimeFirewallOperationClaim acquire_queued_claim(
    RuntimeFirewallRetryCoordinator& coordinator,
    const TerminalOwner::CoordinatorTerminalSink& terminal_sink,
    std::uint64_t runtime_generation = 71U,
    PreparedNativeVpnCatalogPtr catalog = {},
    OwnedSnatRecovery snat_recovery = {},
    std::size_t attempt = 0U,
    OwnedSnatRecovery* delivered_recovery = nullptr,
    PreparedNativeVpnCatalogPtr* delivered_catalog = nullptr) {
    std::function<void()> timer_callback;
    std::optional<RuntimeFirewallOperationClaim> queued_claim;
    const auto plan = coordinator
        .schedule_operation_with_prepared_catalog_and_terminal(
            attempt,
            runtime_generation,
            /*bounded_retry_count=*/6U,
            std::move(snat_recovery),
            catalog,
            [&](const RuntimeFirewallRetryPlan&, auto callback) {
                timer_callback = std::move(callback);
                return 43;
            },
            [runtime_generation](std::uint64_t generation) {
                return generation == runtime_generation;
            },
            [&](RuntimeFirewallOperationClaim claim,
                OwnedSnatRecovery recovery,
                PreparedNativeVpnCatalogPtr prepared_catalog) {
                queued_claim = claim;
                if (delivered_recovery != nullptr) {
                    *delivered_recovery = std::move(recovery);
                }
                if (delivered_catalog != nullptr) {
                    *delivered_catalog = std::move(prepared_catalog);
                }
            },
            terminal_sink);
    REQUIRE(plan.schedule);
    REQUIRE(static_cast<bool>(timer_callback));
    timer_callback();
    REQUIRE(queued_claim.has_value());
    REQUIRE(coordinator.operation_is_current(*queued_claim));
    return *queued_claim;
}

RuntimeFirewallOperationClaim acquire_deferred_queued_claim(
    RuntimeFirewallRetryCoordinator& coordinator,
    const TerminalOwner::CoordinatorTerminalSink& terminal_sink,
    std::size_t attempt,
    std::uint64_t runtime_generation,
    PreparedNativeVpnCatalogPtr catalog,
    OwnedSnatRecovery snat_recovery,
    OwnedSnatRecovery* delivered_recovery = nullptr,
    PreparedNativeVpnCatalogPtr* delivered_catalog = nullptr) {
    std::function<void()> timer_callback;
    std::optional<RuntimeFirewallOperationClaim> queued_claim;
    const bool scheduled = coordinator
        .defer_same_attempt_operation_with_prepared_catalog_and_terminal(
            attempt,
            runtime_generation,
            std::move(snat_recovery),
            catalog,
            [&](auto callback) {
                timer_callback = std::move(callback);
                return 47;
            },
            [runtime_generation](std::uint64_t generation) {
                return generation == runtime_generation;
            },
            [&](RuntimeFirewallOperationClaim claim,
                OwnedSnatRecovery recovery,
                PreparedNativeVpnCatalogPtr prepared_catalog) {
                queued_claim = claim;
                if (delivered_recovery != nullptr) {
                    *delivered_recovery = std::move(recovery);
                }
                if (delivered_catalog != nullptr) {
                    *delivered_catalog = std::move(prepared_catalog);
                }
            },
            terminal_sink);
    REQUIRE(scheduled);
    REQUIRE(static_cast<bool>(timer_callback));
    timer_callback();
    REQUIRE(queued_claim.has_value());
    REQUIRE(coordinator.operation_is_current(*queued_claim));
    return *queued_claim;
}

WorkerOperation::MutationLeasePtr acquire_lease(
    RuntimeMutationAdmission& admission) {
    auto lease = admission.try_acquire("terminal-owner-test");
    REQUIRE(lease.has_value());
    return std::make_unique<RuntimeMutationAdmission::Lease>(
        std::move(*lease));
}

WorkerOperation::OperationPtr make_worker_operation(
    RuntimeFirewallRetryCoordinator& coordinator,
    RuntimeMutationAdmission& admission,
    RuntimeFirewallOperationClaim queued_claim,
    const TerminalOwner::OwnerPtr& owner) {
    return WorkerOperation::create(
        coordinator,
        queued_claim,
        std::make_shared<const TerminalOwnerInput>(
            TerminalOwnerInput{17}),
        acquire_lease(admission),
        owner->worker_terminal_mailbox());
}

struct RetainedWorkerOperation {
    WorkerOperation::OperationPtr operation;
    std::uint64_t lease_token{0U};
};

RetainedWorkerOperation make_retained_worker_operation(
    RuntimeFirewallRetryCoordinator& coordinator,
    RuntimeMutationAdmission& admission,
    RuntimeFirewallOperationClaim queued_claim,
    const TerminalOwner::OwnerPtr& owner) {
    auto lease = acquire_lease(admission);
    const auto lease_token = lease->token();
    return RetainedWorkerOperation{
        WorkerOperation::create(
            coordinator,
            queued_claim,
            std::make_shared<const TerminalOwnerInput>(
                TerminalOwnerInput{17}),
            WorkerOperation::MutationLeaseBinding::retained_lease(
                std::move(lease)),
            owner->worker_terminal_mailbox()),
        lease_token};
}

WorkerOperation::Worker successful_worker(int value) {
    return [value](const TerminalOwnerInput&,
                   const WorkerOperation::RunningClaim&) {
        return std::make_shared<const TerminalOwnerResult>(
            TerminalOwnerResult{value});
    };
}

} // namespace

TEST_CASE(
    "runtime firewall typed schedule executor rejection drains one exact terminal") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    std::size_t wake_calls = 0U;
    bool admission_free_before_wake = false;
    const auto owner = TerminalOwner::create([&]() {
        ++wake_calls;
        auto replacement = admission.try_acquire(
            "after-executor-rejection");
        admission_free_before_wake = replacement.has_value();
    });

    PreparedNativeVpnCatalog catalog;
    catalog.runtime_generation = 71U;
    const auto prepared =
        std::make_shared<const PreparedNativeVpnCatalog>(
            std::move(catalog));
    const OwnedSnatRecovery submitted_recovery{
        /*requested=*/true,
        /*missing_observed=*/true,
        OwnedConntrackCleanupSnapshot{
            /*runtime_generation=*/71U,
            /*owned_mask=*/0x00ffU,
            /*marks=*/{0x0101U, 0x0202U},
            /*priority_marks=*/{0x0202U},
            /*ipv6_enabled=*/false}};
    const auto check_exact_recovery = [](const OwnedSnatRecovery& recovery) {
        CHECK(recovery.requested);
        CHECK(recovery.missing_observed);
        REQUIRE(recovery.cleanup_snapshot.has_value());
        CHECK(recovery.cleanup_snapshot->runtime_generation == 71U);
        CHECK(recovery.cleanup_snapshot->owned_mask == 0x00ffU);
        CHECK(recovery.cleanup_snapshot->marks.count(0x0101U) == 1U);
        CHECK(recovery.cleanup_snapshot->marks.count(0x0202U) == 1U);
        CHECK(recovery.cleanup_snapshot->priority_marks.count(0x0202U) ==
              1U);
        CHECK_FALSE(recovery.cleanup_snapshot->ipv6_enabled);
    };
    OwnedSnatRecovery delivered_recovery;
    PreparedNativeVpnCatalogPtr delivered_catalog;
    const auto queued_claim = acquire_queued_claim(
        coordinator,
        owner->coordinator_terminal_sink(),
        /*runtime_generation=*/71U,
        prepared,
        submitted_recovery,
        /*attempt=*/0U,
        &delivered_recovery,
        &delivered_catalog);
    CHECK(queued_claim.attempt == 1U);
    CHECK(delivered_catalog == prepared);
    check_exact_recovery(delivered_recovery);

    // Model a newer exact observation retained after worker hand-off. Queue
    // rejection must return it through the single durable completion rather
    // than dropping it with the rejected executor envelope.
    const auto trailing = coordinator.begin_attempt_with_prepared_catalog(
        /*retry_attempt=*/0U, {}, prepared);
    REQUIRE(trailing.coalesced);
    CHECK_FALSE(trailing.prepared_now);

    auto operation = make_worker_operation(
        coordinator, admission, queued_claim, owner);
    std::size_t worker_calls = 0U;
    auto closure = operation->make_queued_closure(
        [&](const TerminalOwnerInput&,
            const WorkerOperation::RunningClaim&) {
            ++worker_calls;
            return std::make_shared<const TerminalOwnerResult>(
                TerminalOwnerResult{41});
        });

    BlockingExecutor executor(
        /*worker_count=*/0U, /*max_queue_size=*/0U);
    CHECK_FALSE(executor.try_post(
        "runtime-firewall-rejected", std::move(closure)));
    closure = {};

    CHECK(worker_calls == 0U);
    CHECK(wake_calls == 1U);
    CHECK(admission_free_before_wake);
    CHECK_FALSE(coordinator.retry_pending());

    auto drain = owner->try_begin_drain();
    REQUIRE(drain.has_value());
    CHECK(drain->kind() == TerminalOwner::DrainKind::worker);
    const auto* terminal = drain->worker_terminal();
    REQUIRE(terminal != nullptr);
    CHECK(terminal->status ==
          WorkerOperation::TerminalStatus::queued_abandoned);
    CHECK_FALSE(terminal->running_claim.has_value());
    CHECK_FALSE(terminal->mutation_lease);
    REQUIRE(terminal->coordinator_completion.has_value());
    CHECK(terminal->coordinator_completion->owned);
    CHECK(terminal->coordinator_completion->rerun_requested);
    // Pre-worker teardown transfers only exact catalogue/rerun authority.
    // Recovery remains latched in the coordinator so the successor takes a
    // fresh netfilter snapshot instead of replaying a captured cleanup plan.
    CHECK_FALSE(
        terminal->coordinator_completion->snat_recovery.requested);
    CHECK_FALSE(
        terminal->coordinator_completion->snat_recovery.missing_observed);
    CHECK_FALSE(
        terminal->coordinator_completion->snat_recovery.cleanup_snapshot
            .has_value());
    CHECK(coordinator.owned_snat_recovery_pending());
    check_exact_recovery(coordinator.pending_owned_snat_recovery());
    CHECK(terminal->coordinator_completion
              ->next_prepared_catalog == prepared);
    CHECK(drain->finish_worker_terminal());
    CHECK_FALSE(owner->try_begin_drain().has_value());
}

TEST_CASE(
    "runtime firewall typed defer shutdown preserves exact attempt and terminal") {
    using namespace std::chrono_literals;

    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    std::size_t wake_calls = 0U;
    bool admission_idle_before_wake = false;
    const auto owner = TerminalOwner::create([&]() {
        ++wake_calls;
        admission_idle_before_wake =
            admission.wait_for_idle_for(0ms);
    });

    PreparedNativeVpnCatalog catalog;
    catalog.runtime_generation = 73U;
    const auto prepared =
        std::make_shared<const PreparedNativeVpnCatalog>(
            std::move(catalog));
    const OwnedSnatRecovery submitted_recovery{
        /*requested=*/true,
        /*missing_observed=*/true,
        OwnedConntrackCleanupSnapshot{
            /*runtime_generation=*/73U,
            /*owned_mask=*/0x0f00U,
            /*marks=*/{0x0303U},
            /*priority_marks=*/{0x0303U},
            /*ipv6_enabled=*/true}};
    const auto check_exact_recovery = [](const OwnedSnatRecovery& recovery) {
        CHECK(recovery.requested);
        CHECK(recovery.missing_observed);
        REQUIRE(recovery.cleanup_snapshot.has_value());
        CHECK(recovery.cleanup_snapshot->runtime_generation == 73U);
        CHECK(recovery.cleanup_snapshot->owned_mask == 0x0f00U);
        CHECK(recovery.cleanup_snapshot->marks.count(0x0303U) == 1U);
        CHECK(recovery.cleanup_snapshot->priority_marks.count(0x0303U) ==
              1U);
        CHECK(recovery.cleanup_snapshot->ipv6_enabled);
    };
    OwnedSnatRecovery delivered_recovery;
    PreparedNativeVpnCatalogPtr delivered_catalog;
    const auto queued_claim = acquire_deferred_queued_claim(
        coordinator,
        owner->coordinator_terminal_sink(),
        /*attempt=*/3U,
        /*runtime_generation=*/73U,
        prepared,
        submitted_recovery,
        &delivered_recovery,
        &delivered_catalog);
    CHECK(queued_claim.attempt == 3U);
    CHECK(delivered_catalog == prepared);
    check_exact_recovery(delivered_recovery);

    // This is a fresh external observation while attempt 3 is queued. Fresh
    // observations enter at attempt 0; the deferred claim itself must retain
    // its original attempt 3 authority.
    const auto trailing = coordinator.begin_attempt_with_prepared_catalog(
        /*retry_attempt=*/0U, {}, prepared);
    REQUIRE(trailing.coalesced);
    CHECK_FALSE(trailing.prepared_now);

    auto operation = make_worker_operation(
        coordinator, admission, queued_claim, owner);
    std::size_t worker_calls = 0U;
    auto closure = operation->make_queued_closure(
        [&](const TerminalOwnerInput&,
            const WorkerOperation::RunningClaim&) {
            ++worker_calls;
            return std::make_shared<const TerminalOwnerResult>(
                TerminalOwnerResult{43});
        });
    BlockingExecutor executor(
        /*worker_count=*/0U, /*max_queue_size=*/1U);
    REQUIRE(executor.try_post(
        "runtime-firewall-deferred", std::move(closure)));
    closure = {};
    CHECK_FALSE(admission.wait_for_idle_for(0ms));

    admission.shutdown();
    CHECK_NOTHROW(executor.cancel_pending_and_shutdown());

    CHECK(worker_calls == 0U);
    CHECK(wake_calls == 1U);
    CHECK(admission_idle_before_wake);
    CHECK(admission.wait_for_idle_for(0ms));
    CHECK_FALSE(coordinator.retry_pending());

    auto drain = owner->try_begin_drain();
    REQUIRE(drain.has_value());
    CHECK(drain->kind() == TerminalOwner::DrainKind::worker);
    const auto* terminal = drain->worker_terminal();
    REQUIRE(terminal != nullptr);
    CHECK(terminal->status ==
          WorkerOperation::TerminalStatus::queued_abandoned);
    CHECK_FALSE(terminal->running_claim.has_value());
    CHECK_FALSE(terminal->mutation_lease);
    REQUIRE(terminal->coordinator_completion.has_value());
    CHECK(terminal->coordinator_completion->owned);
    CHECK(terminal->coordinator_completion->rerun_requested);
    CHECK_FALSE(
        terminal->coordinator_completion->snat_recovery.requested);
    CHECK_FALSE(
        terminal->coordinator_completion->snat_recovery.missing_observed);
    CHECK_FALSE(
        terminal->coordinator_completion->snat_recovery.cleanup_snapshot
            .has_value());
    CHECK(coordinator.owned_snat_recovery_pending());
    check_exact_recovery(coordinator.pending_owned_snat_recovery());
    CHECK(terminal->coordinator_completion
              ->next_prepared_catalog == prepared);
    CHECK(drain->finish_worker_terminal());
    CHECK_FALSE(owner->try_begin_drain().has_value());
}

TEST_CASE(
    "runtime firewall terminal owner retries one stable queued cancellation") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    std::size_t wake_calls = 0U;
    const auto owner = TerminalOwner::create([&]() { ++wake_calls; });
    const auto queued_claim = acquire_queued_claim(
        coordinator, owner->coordinator_terminal_sink());
    auto operation = make_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = operation->make_queued_closure(
        successful_worker(/*value=*/19));

    BlockingExecutor executor(/*worker_count=*/0U, /*max_queue_size=*/1U);
    REQUIRE(executor.try_post("terminal-owner", std::move(closure)));
    closure = {};
    REQUIRE(coordinator.retry_pending());
    executor.cancel_pending();

    CHECK(wake_calls == 1U);
    CHECK_FALSE(coordinator.retry_pending());
    CHECK(admission.try_acquire("after-queued-cancel").has_value());

    const WorkerOperation::TerminalEnvelope* stable_terminal = nullptr;
    const auto throwing_continuation = [&]() {
        auto drain = owner->try_begin_drain();
        REQUIRE(drain.has_value());
        CHECK(drain->kind() == TerminalOwner::DrainKind::worker);
        stable_terminal = drain->worker_terminal();
        REQUIRE(stable_terminal != nullptr);
        CHECK(stable_terminal->status ==
              WorkerOperation::TerminalStatus::queued_abandoned);
        REQUIRE(stable_terminal->coordinator_completion.has_value());
        CHECK(stable_terminal->coordinator_completion->owned);
        CHECK_FALSE(owner->try_begin_drain().has_value());
        throw std::runtime_error("control publication interrupted");
    };
    CHECK_THROWS_WITH_AS(
        throwing_continuation(),
        "control publication interrupted",
        std::runtime_error);

    // DrainGuard re-arms after the throw; the envelope was not moved again.
    CHECK(wake_calls == 2U);
    auto retry = owner->try_begin_drain();
    REQUIRE(retry.has_value());
    CHECK(retry->worker_terminal() == stable_terminal);
    CHECK(retry->finish_worker_terminal());
    CHECK_FALSE(owner->try_begin_drain().has_value());
}

TEST_CASE(
    "runtime firewall terminal drain park releases ownership without notifying") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    std::size_t wake_calls = 0U;
    const auto owner = TerminalOwner::create([&]() { ++wake_calls; });
    const auto queued_claim = acquire_queued_claim(
        coordinator, owner->coordinator_terminal_sink());
    auto operation = make_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = operation->make_queued_closure(
        successful_worker(/*value=*/23));

    // Abandoning the accepted envelope publishes one stable terminal and one
    // wake. Parking its drain must not immediately request another pass.
    closure = {};
    CHECK(wake_calls == 1U);

    auto first = owner->try_begin_drain();
    REQUIRE(first.has_value());
    REQUIRE(first->kind() == TerminalOwner::DrainKind::worker);
    const auto* stable_terminal = first->worker_terminal();
    REQUIRE(stable_terminal != nullptr);
    CHECK(stable_terminal->status ==
          WorkerOperation::TerminalStatus::queued_abandoned);
    CHECK_FALSE(owner->try_begin_drain().has_value());

    first->park_until_wake();
    CHECK_FALSE(static_cast<bool>(*first));
    CHECK(wake_calls == 1U);

    // The asynchronous tail's explicit drain request may now reacquire it;
    // no terminal was moved out and park itself emitted no notification.
    auto resumed = owner->try_begin_drain();
    REQUIRE(resumed.has_value());
    CHECK(resumed->worker_terminal() == stable_terminal);
    CHECK(wake_calls == 1U);
    CHECK(resumed->finish_worker_terminal());
    CHECK_FALSE(owner->try_begin_drain().has_value());
}

TEST_CASE(
    "runtime firewall terminal owner retains control claim across publication throw") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    std::size_t wake_calls = 0U;
    const auto owner = TerminalOwner::create([&]() { ++wake_calls; });
    const auto queued_claim = acquire_queued_claim(
        coordinator, owner->coordinator_terminal_sink());
    auto operation = make_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = operation->make_queued_closure(
        successful_worker(/*value=*/23));

    closure();
    closure = {};
    CHECK(wake_calls == 1U);

    const WorkerOperation::TerminalEnvelope* stable_terminal = nullptr;
    const RuntimeFirewallOperationClaim* stable_control_claim = nullptr;
    const RuntimeFirewallOperationCompletion* stable_completion = nullptr;
    std::size_t publication_calls = 0U;
    const auto throw_after_begin_control = [&]() {
        auto drain = owner->try_begin_drain();
        REQUIRE(drain.has_value());
        stable_terminal = drain->worker_terminal();
        REQUIRE(stable_terminal != nullptr);
        REQUIRE(stable_terminal->running_claim.has_value());
        REQUIRE(stable_terminal->mutation_lease);
        CHECK_FALSE(drain->release_worker_lease());
        CHECK_FALSE(drain->finish_worker_terminal());

        REQUIRE(drain->begin_worker_control(coordinator));
        CHECK(drain->begin_worker_control(coordinator));
        stable_control_claim = drain->worker_control_claim();
        REQUIRE(stable_control_claim != nullptr);
        CHECK(stable_control_claim->phase ==
              RuntimeFirewallOperationPhase::control_pending);
        throw std::runtime_error("publication before completion failed");
    };
    CHECK_THROWS_WITH_AS(
        throw_after_begin_control(),
        "publication before completion failed",
        std::runtime_error);

    CHECK(wake_calls == 2U);
    CHECK_FALSE(admission.try_acquire("lease-still-owned").has_value());
    const auto throw_after_publication = [&]() {
        auto drain = owner->try_begin_drain();
        REQUIRE(drain.has_value());
        CHECK(drain->worker_terminal() == stable_terminal);
        CHECK(drain->worker_control_claim() == stable_control_claim);
        REQUIRE(drain->worker_control_claim() != nullptr);
        REQUIRE(drain->publish_worker_control(
            [&]() noexcept {
                ++publication_calls;
                return true;
            }));
        CHECK(publication_calls == 1U);
        throw std::runtime_error("publication checkpoint retained");
    };
    CHECK_THROWS_WITH_AS(
        throw_after_publication(),
        "publication checkpoint retained",
        std::runtime_error);

    CHECK(wake_calls == 3U);
    CHECK_FALSE(admission.try_acquire("lease-still-owned").has_value());
    const auto throw_after_completion = [&]() {
        auto drain = owner->try_begin_drain();
        REQUIRE(drain.has_value());
        REQUIRE(drain->publish_worker_control(
            [&]() noexcept {
                ++publication_calls;
                return true;
            }));
        // The durable publication checkpoint suppresses a second callback.
        CHECK(publication_calls == 1U);
        REQUIRE(drain->complete_worker_control(
            coordinator,
            /*succeeded=*/true,
            {}));
        stable_completion = drain->worker_control_completion();
        REQUIRE(stable_completion != nullptr);
        CHECK(stable_completion->owned);
        throw std::runtime_error("publication after completion failed");
    };
    CHECK_THROWS_WITH_AS(
        throw_after_completion(),
        "publication after completion failed",
        std::runtime_error);

    CHECK(wake_calls == 4U);
    CHECK_FALSE(admission.try_acquire("lease-still-owned").has_value());
    auto retry = owner->try_begin_drain();
    REQUIRE(retry.has_value());
    CHECK(retry->worker_terminal() == stable_terminal);
    CHECK(retry->worker_control_claim() == stable_control_claim);
    CHECK(retry->worker_control_completion() == stable_completion);
    REQUIRE(retry->worker_control_claim() != nullptr);
    CHECK_FALSE(coordinator.operation_is_current(
        *retry->worker_control_claim()));
    CHECK_FALSE(retry->finish_worker_terminal());
    REQUIRE(retry->release_worker_lease());
    CHECK(admission.try_acquire("lease-released").has_value());
    CHECK(retry->finish_worker_terminal());
}

TEST_CASE(
    "runtime firewall terminal owner preserves coordinator payload when preworker loss wakes first") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    std::size_t wake_calls = 0U;
    const auto owner = TerminalOwner::create([&]() { ++wake_calls; });
    PreparedNativeVpnCatalog catalog;
    catalog.runtime_generation = 79U;
    const auto prepared =
        std::make_shared<const PreparedNativeVpnCatalog>(
            std::move(catalog));
    const auto queued_claim = acquire_queued_claim(
        coordinator,
        owner->coordinator_terminal_sink(),
        /*runtime_generation=*/79U,
        prepared);
    auto operation = make_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = operation->make_queued_closure(
        successful_worker(/*value=*/29));

    // Model the exact queue-adapter race: coordinator terminalization has
    // released the queued claim, but its noexcept sink has not run yet. The
    // accepted executor envelope observes the lost claim and wakes control
    // first.
    auto delayed_completion =
        coordinator.terminate_operation_for_resnapshot(
            queued_claim,
            /*force_rerun=*/true);
    REQUIRE(delayed_completion.owned);
    CHECK(delayed_completion.next_prepared_catalog == prepared);
    CHECK_NOTHROW(closure());
    closure = {};
    CHECK(wake_calls == 1U);

    // The loser alone is not allowed to close the owner or masquerade as a
    // terminal decision while the exact coordinator payload is in flight.
    CHECK_FALSE(owner->try_begin_drain().has_value());

    // The authoritative coordinator source arrives second and must not be
    // dropped merely because the subordinate mailbox source was seen first.
    owner->coordinator_terminal_sink()(
        std::move(delayed_completion));
    CHECK(wake_calls == 2U);
    auto coordinator_drain = owner->try_begin_drain();
    REQUIRE(coordinator_drain.has_value());
    CHECK(coordinator_drain->kind() ==
          TerminalOwner::DrainKind::coordinator);
    REQUIRE(coordinator_drain->coordinator_terminal() != nullptr);
    CHECK(coordinator_drain->coordinator_terminal()
              ->next_prepared_catalog == prepared);
    CHECK(coordinator_drain->finish_coordinator_terminal());
    CHECK(admission.try_acquire("after-stale-terminal").has_value());
}

TEST_CASE(
    "runtime firewall shutdown drains running terminal before admission becomes idle") {
    using namespace std::chrono_literals;

    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    std::size_t wake_calls = 0U;
    const auto owner = TerminalOwner::create([&]() { ++wake_calls; });
    const auto queued_claim = acquire_queued_claim(
        coordinator, owner->coordinator_terminal_sink());
    auto operation = make_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = operation->make_queued_closure(
        successful_worker(/*value=*/31));

    closure();
    closure = {};
    REQUIRE(wake_calls == 1U);
    REQUIRE(coordinator.retry_pending());

    admission.shutdown();
    CHECK_FALSE(admission.wait_for_idle_for(0ms));
    CHECK_FALSE(admission.try_acquire("shutdown-new-writer").has_value());

    // Shutdown pumps the same durable terminal protocol as the normal
    // watchdog. It does not destroy the admitted lease or coordinator claim.
    auto shutdown_drain = owner->try_begin_drain();
    REQUIRE(shutdown_drain.has_value());
    REQUIRE(shutdown_drain->worker_terminal() != nullptr);
    REQUIRE(shutdown_drain->worker_terminal()->mutation_lease);
    REQUIRE(shutdown_drain->begin_worker_control(coordinator));
    REQUIRE(shutdown_drain->publish_worker_control(
        []() noexcept { return true; }));
    REQUIRE(shutdown_drain->complete_worker_control(
        coordinator,
        /*succeeded=*/false,
        {}));
    REQUIRE(shutdown_drain->release_worker_lease());
    REQUIRE(shutdown_drain->finish_worker_terminal());

    CHECK_FALSE(coordinator.retry_pending());
    CHECK(admission.wait_for_idle_for(10ms));
    CHECK_FALSE(owner->try_begin_drain().has_value());
}

TEST_CASE(
    "runtime firewall coordinator winner safely dominates a later preworker loser") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    std::size_t wake_calls = 0U;
    const auto owner = TerminalOwner::create([&]() { ++wake_calls; });
    PreparedNativeVpnCatalog catalog;
    catalog.runtime_generation = 81U;
    const auto prepared =
        std::make_shared<const PreparedNativeVpnCatalog>(
            std::move(catalog));
    const auto queued_claim = acquire_queued_claim(
        coordinator,
        owner->coordinator_terminal_sink(),
        /*runtime_generation=*/81U,
        prepared);
    auto operation = make_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = operation->make_queued_closure(
        successful_worker(/*value=*/37));

    auto completion = coordinator.terminate_operation_for_resnapshot(
        queued_claim,
        /*force_rerun=*/true);
    REQUIRE(completion.owned);
    owner->coordinator_terminal_sink()(std::move(completion));
    REQUIRE(wake_calls == 1U);

    auto coordinator_drain = owner->try_begin_drain();
    REQUIRE(coordinator_drain.has_value());
    REQUIRE(coordinator_drain->coordinator_terminal() != nullptr);
    CHECK(coordinator_drain->coordinator_terminal()
              ->next_prepared_catalog == prepared);
    REQUIRE(coordinator_drain->finish_coordinator_terminal());

    // begin_worker() can no longer succeed. The late envelope releases its
    // lease before publication and cannot reopen the already authoritative
    // coordinator terminal decision.
    CHECK_NOTHROW(closure());
    closure = {};
    CHECK(wake_calls == 2U);
    CHECK_FALSE(owner->try_begin_drain().has_value());
    CHECK(admission.try_acquire("after-late-loser").has_value());
}

TEST_CASE(
    "runtime firewall coordinator sink retains scheduler rejection without a cycle") {
    RuntimeFirewallRetryCoordinator coordinator;
    std::size_t wake_calls = 0U;
    auto owner = TerminalOwner::create([&]() {
        ++wake_calls;
        throw std::runtime_error("wake rejected");
    });
    std::weak_ptr<TerminalOwner> owner_lifetime{owner};
    const auto mailbox = owner->worker_terminal_mailbox();
    const auto sink = owner->coordinator_terminal_sink();

    PreparedNativeVpnCatalog catalog;
    catalog.runtime_generation = 83U;
    const auto prepared =
        std::make_shared<const PreparedNativeVpnCatalog>(
            std::move(catalog));
    const auto plan = coordinator
        .schedule_operation_with_prepared_catalog_and_terminal(
            /*attempt=*/0U,
            /*runtime_generation=*/83U,
            /*bounded_retry_count=*/6U,
            {},
            prepared,
            [](const RuntimeFirewallRetryPlan&, auto) { return -1; },
            [](std::uint64_t) { return true; },
            [](RuntimeFirewallOperationClaim,
               OwnedSnatRecovery,
               PreparedNativeVpnCatalogPtr) {},
            sink);
    CHECK_FALSE(plan.schedule);
    CHECK(wake_calls == 1U);
    CHECK_FALSE(coordinator.retry_pending());

    const RuntimeFirewallOperationCompletion* stable_terminal = nullptr;
    const auto throwing_continuation = [&]() {
        auto drain = owner->try_begin_drain();
        REQUIRE(drain.has_value());
        CHECK(drain->kind() == TerminalOwner::DrainKind::coordinator);
        stable_terminal = drain->coordinator_terminal();
        REQUIRE(stable_terminal != nullptr);
        CHECK(stable_terminal->owned);
        CHECK(stable_terminal->rerun_requested);
        CHECK(stable_terminal->next_prepared_catalog == prepared);
        throw std::runtime_error("resnapshot continuation failed");
    };
    CHECK_THROWS_WITH_AS(
        throwing_continuation(),
        "resnapshot continuation failed",
        std::runtime_error);
    CHECK(wake_calls == 2U);

    auto retry = owner->try_begin_drain();
    REQUIRE(retry.has_value());
    CHECK(retry->coordinator_terminal() == stable_terminal);
    CHECK(retry->finish_coordinator_terminal());

    // The owner holds the mailbox, while its wake and terminal sink hold only
    // weak references back. Retaining both adapters cannot form a cycle.
    owner.reset();
    CHECK(owner_lifetime.expired());
    CHECK(mailbox != nullptr);
    CHECK_NOTHROW(sink(RuntimeFirewallOperationCompletion{}));
}

TEST_CASE(
    "runtime firewall terminal owner returns retained running lease after exact completion") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto owner = TerminalOwner::create();
    const auto queued_claim = acquire_queued_claim(
        coordinator, owner->coordinator_terminal_sink());
    auto retained = make_retained_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = retained.operation->make_queued_closure(
        successful_worker(/*value=*/41));

    closure();
    closure = {};
    auto drain = owner->try_begin_drain();
    REQUIRE(drain.has_value());
    REQUIRE(drain->kind() == TerminalOwner::DrainKind::worker);
    const auto* terminal = drain->worker_terminal();
    REQUIRE(terminal != nullptr);
    REQUIRE(terminal->running_claim.has_value());
    REQUIRE(terminal->mutation_lease.lease);
    CHECK(terminal->mutation_lease.return_policy ==
          WorkerOperation::MutationLeaseReturnPolicy::
              return_to_operation_owner);

    auto premature_return = drain->take_retained_mutation_lease();
    CHECK_FALSE(premature_return);
    CHECK_FALSE(drain->release_worker_lease());
    CHECK_FALSE(drain->finish_worker_terminal());

    REQUIRE(drain->begin_worker_control(coordinator));
    REQUIRE(drain->publish_worker_control(
        []() noexcept { return true; }));
    REQUIRE(drain->complete_worker_control(
        coordinator,
        /*succeeded=*/true,
        {}));
    CHECK_FALSE(drain->release_worker_lease());
    CHECK_FALSE(drain->finish_worker_terminal());

    auto returned = drain->take_retained_mutation_lease();
    REQUIRE(returned);
    CHECK(returned->token() == retained.lease_token);
    CHECK(admission.owns(*returned));
    auto duplicate_return = drain->take_retained_mutation_lease();
    CHECK_FALSE(duplicate_return);
    CHECK(drain->finish_worker_terminal());
    CHECK_FALSE(admission.try_acquire("retained-running-still-owned")
                    .has_value());
    returned.reset();
    CHECK(admission.try_acquire("retained-running-returned")
              .has_value());
}

TEST_CASE(
    "runtime firewall terminal owner returns retained queued abandoned lease") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto owner = TerminalOwner::create();
    const auto queued_claim = acquire_queued_claim(
        coordinator, owner->coordinator_terminal_sink());
    auto retained = make_retained_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = retained.operation->make_queued_closure(
        successful_worker(/*value=*/43));

    // Destroying the accepted-but-not-started executor envelope transfers the
    // exact coordinator completion and the outer owner's lease together.
    closure = {};
    auto drain = owner->try_begin_drain();
    REQUIRE(drain.has_value());
    REQUIRE(drain->kind() == TerminalOwner::DrainKind::worker);
    const auto* terminal = drain->worker_terminal();
    REQUIRE(terminal != nullptr);
    CHECK(terminal->status ==
          WorkerOperation::TerminalStatus::queued_abandoned);
    REQUIRE(terminal->coordinator_completion.has_value());
    REQUIRE(terminal->coordinator_completion->owned);
    REQUIRE(terminal->mutation_lease.lease);
    CHECK_FALSE(drain->finish_worker_terminal());

    auto returned = drain->take_retained_mutation_lease();
    REQUIRE(returned);
    CHECK(returned->token() == retained.lease_token);
    CHECK(admission.owns(*returned));
    CHECK(drain->finish_worker_terminal());
    CHECK_FALSE(admission.try_acquire("retained-queued-still-owned")
                    .has_value());
    returned.reset();
    CHECK(admission.try_acquire("retained-queued-returned")
              .has_value());
}

TEST_CASE(
    "runtime firewall terminal owner keeps retained lost first lease subordinate") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    std::size_t wake_calls = 0U;
    const auto owner = TerminalOwner::create([&]() { ++wake_calls; });
    const auto queued_claim = acquire_queued_claim(
        coordinator, owner->coordinator_terminal_sink());
    auto retained = make_retained_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = retained.operation->make_queued_closure(
        successful_worker(/*value=*/47));

    auto delayed_completion =
        coordinator.terminate_operation_for_resnapshot(
            queued_claim,
            /*force_rerun=*/true);
    REQUIRE(delayed_completion.owned);
    closure();
    closure = {};
    CHECK(wake_calls == 1U);

    // The lost_claim has the retained token but no terminal authority of its
    // own. Absorb it into stable storage and wait for the exact completion.
    CHECK_FALSE(owner->try_begin_drain().has_value());
    CHECK_FALSE(admission.try_acquire("retained-lost-first-pending")
                    .has_value());
    owner->coordinator_terminal_sink()(
        std::move(delayed_completion));
    CHECK(wake_calls == 2U);

    auto drain = owner->try_begin_drain();
    REQUIRE(drain.has_value());
    REQUIRE(drain->kind() == TerminalOwner::DrainKind::coordinator);
    REQUIRE(drain->coordinator_terminal() != nullptr);
    CHECK_FALSE(drain->finish_coordinator_terminal());
    auto returned = drain->take_retained_mutation_lease();
    REQUIRE(returned);
    CHECK(returned->token() == retained.lease_token);
    CHECK(admission.owns(*returned));
    CHECK(drain->finish_coordinator_terminal());
    CHECK_FALSE(owner->try_begin_drain().has_value());
    returned.reset();
    CHECK(admission.try_acquire("retained-lost-first-returned")
              .has_value());
}

TEST_CASE(
    "runtime firewall terminal owner waits for retained coordinator first late loss") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    std::size_t wake_calls = 0U;
    const auto owner = TerminalOwner::create([&]() { ++wake_calls; });
    const auto queued_claim = acquire_queued_claim(
        coordinator, owner->coordinator_terminal_sink());
    auto retained = make_retained_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = retained.operation->make_queued_closure(
        successful_worker(/*value=*/53));

    auto completion = coordinator.terminate_operation_for_resnapshot(
        queued_claim,
        /*force_rerun=*/true);
    REQUIRE(completion.owned);
    owner->coordinator_terminal_sink()(std::move(completion));
    CHECK(wake_calls == 1U);

    // Coordinator authority cannot close while the exact retained token is
    // still parked in the accepted worker envelope.
    CHECK(owner->worker_terminal_mailbox()
              ->retained_mutation_lease_pending());
    CHECK_FALSE(owner->try_begin_drain().has_value());
    CHECK_FALSE(admission.try_acquire("retained-coordinator-first-pending")
                    .has_value());

    closure();
    closure = {};
    CHECK(wake_calls == 2U);
    CHECK_FALSE(owner->worker_terminal_mailbox()
                    ->retained_mutation_lease_pending());
    auto drain = owner->try_begin_drain();
    REQUIRE(drain.has_value());
    REQUIRE(drain->kind() == TerminalOwner::DrainKind::coordinator);
    CHECK_FALSE(drain->finish_coordinator_terminal());
    auto returned = drain->take_retained_mutation_lease();
    REQUIRE(returned);
    CHECK(returned->token() == retained.lease_token);
    CHECK(admission.owns(*returned));
    CHECK(drain->finish_coordinator_terminal());
    CHECK_FALSE(owner->try_begin_drain().has_value());
    returned.reset();
    CHECK(admission.try_acquire("retained-coordinator-first-returned")
              .has_value());
}

TEST_CASE(
    "runtime firewall shutdown explicitly drains and releases returned retained lease") {
    using namespace std::chrono_literals;

    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeMutationAdmission admission;
    const auto owner = TerminalOwner::create();
    const auto queued_claim = acquire_queued_claim(
        coordinator, owner->coordinator_terminal_sink());
    auto retained = make_retained_worker_operation(
        coordinator, admission, queued_claim, owner);
    auto closure = retained.operation->make_queued_closure(
        successful_worker(/*value=*/59));
    BlockingExecutor executor(
        /*worker_count=*/0U, /*max_queue_size=*/1U);
    REQUIRE(executor.try_post(
        "retained-shutdown", std::move(closure)));
    closure = {};

    admission.shutdown();
    CHECK_FALSE(admission.wait_for_idle_for(0ms));
    CHECK_NOTHROW(executor.cancel_pending_and_shutdown());

    auto drain = owner->try_begin_drain();
    REQUIRE(drain.has_value());
    REQUIRE(drain->kind() == TerminalOwner::DrainKind::worker);
    REQUIRE(drain->worker_terminal() != nullptr);
    CHECK(drain->worker_terminal()->status ==
          WorkerOperation::TerminalStatus::queued_abandoned);
    CHECK_FALSE(drain->finish_worker_terminal());
    auto returned = drain->take_retained_mutation_lease();
    REQUIRE(returned);
    CHECK(returned->token() == retained.lease_token);
    CHECK(admission.owns(*returned));
    CHECK(drain->finish_worker_terminal());

    // Finishing the terminal does not silently release an outer owner's
    // lease. Shutdown destroys that returned token explicitly, then becomes
    // idle without admitting another writer.
    CHECK_FALSE(admission.wait_for_idle_for(0ms));
    returned.reset();
    CHECK(admission.wait_for_idle_for(10ms));
    CHECK_FALSE(admission.try_acquire("shutdown-remains-closed")
                    .has_value());
}
