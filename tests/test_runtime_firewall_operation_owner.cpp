#include <doctest/doctest.h>

#include "daemon/runtime_firewall_operation_owner.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

struct TestDomainState final : RuntimeFirewallOperationDomainState {};

struct OwnerHarness final {
    struct Timer final {
        int id{0};
        std::chrono::milliseconds delay{0};
        std::function<void()> callback;
        std::string label;
        bool cancelled{false};
    };

    RuntimeFirewallRetryCoordinator coordinator;
    std::vector<Timer> timers;
    int next_timer_id{10};
    bool reject_control_post{false};
    bool throw_control_post{false};
    bool throw_oneshot_schedule{false};
    bool reject_oneshot_schedule{false};
    bool run_oneshot_inline{false};
    bool throw_repeating_schedule{false};
    bool throw_domain_state_once{false};
    bool throw_dispatch_attempt{false};
    bool capture_retained_mutation_lease{false};
    bool promote_successor_during_drain{false};
    bool promotion_retained{false};
    bool promotion_eager_launch_result{true};
    bool drained_transport_exhausted{false};
    bool settle_transport_exhaustion{false};
    bool detach_restart_transport_recovery{false};
    bool detached_restart_recovery{false};
    bool detached_restart_launch_result{false};
    bool runtime_current{true};
    int control_posts{0};
    int oneshot_schedule_calls{0};
    int drain_calls{0};
    int dispatch_calls{0};
    OwnedSnatRecovery dispatched_recovery;
    PreparedNativeVpnCatalogPtr dispatched_catalog;
    RuntimeFirewallOperationClaim dispatched_claim;
    RuntimeFirewallLifecycleKind dispatched_lifecycle_kind{
        RuntimeFirewallLifecycleKind::background};
    bool dispatched_schedule_catalog_refresh{true};
    RuntimeFirewallOperationOwner::MutationLeasePtr
        returned_mutation_lease;
    std::optional<RuntimeFirewallOperationCompletion>
        drained_coordinator_completion;
    std::optional<RuntimeFirewallLifecycleTerminal>
        settled_transport_terminal;
    std::shared_ptr<RuntimeFirewallOperationOwner> owner;

    void create_owner() {
        RuntimeFirewallOperationOwner::Callbacks callbacks;
        callbacks.create_domain_state = [this] {
            if (throw_domain_state_once) {
                throw_domain_state_once = false;
                throw std::runtime_error{
                    "domain state allocation failed"};
            }
            return std::make_shared<TestDomainState>();
        };
        callbacks.post_control =
            [this](std::function<void()> callback, std::string) {
                ++control_posts;
                if (throw_control_post) {
                    throw std::runtime_error{"control post failed"};
                }
                if (reject_control_post) return false;
                callback();
                return true;
            };
        callbacks.schedule_oneshot =
            [this](std::chrono::milliseconds delay,
                   std::function<void()> callback,
                   std::string label) {
                ++oneshot_schedule_calls;
                if (run_oneshot_inline) callback();
                if (throw_oneshot_schedule) {
                    throw std::runtime_error{"oneshot schedule failed"};
                }
                if (reject_oneshot_schedule) return -1;
                const int id = next_timer_id++;
                timers.push_back(Timer{
                    id,
                    delay,
                    std::move(callback),
                    std::move(label),
                    false});
                return id;
            };
        callbacks.schedule_repeating =
            [this](std::chrono::milliseconds delay,
                   std::function<void()> callback,
                   std::string label) {
                if (throw_repeating_schedule) {
                    throw std::runtime_error{
                        "repeating watchdog schedule failed"};
                }
                const int id = next_timer_id++;
                timers.push_back(Timer{
                    id,
                    delay,
                    std::move(callback),
                    std::move(label),
                    false});
                return id;
            };
        callbacks.cancel_scheduled = [this](int id) {
            for (auto& timer : timers) {
                if (timer.id == id) timer.cancelled = true;
            }
        };
        callbacks.runtime_is_current = [this](
            std::uint64_t generation,
            RuntimeFirewallLifecycleKind) {
            return runtime_current && generation == 77U;
        };
        callbacks.urltest_waiting =
            [](std::uint64_t) { return false; };
        callbacks.dispatch_attempt =
            [this](RuntimeFirewallOperationOwner::ContextPtr context,
                   RuntimeFirewallOperationClaim claim,
                   OwnedSnatRecovery recovery,
                   PreparedNativeVpnCatalogPtr catalog,
                   bool schedule_catalog_refresh) {
                ++dispatch_calls;
                dispatched_lifecycle_kind = context->lifecycle_kind;
                dispatched_claim = claim;
                dispatched_recovery = std::move(recovery);
                dispatched_catalog = std::move(catalog);
                dispatched_schedule_catalog_refresh =
                    schedule_catalog_refresh;
                if (throw_dispatch_attempt) {
                    throw std::runtime_error{"dispatch attempt failed"};
                }
            };
        callbacks.drain_terminal =
            [this](RuntimeFirewallOperationOwner::ContextPtr context,
                   bool) {
                ++drain_calls;
                drained_transport_exhausted =
                    drained_transport_exhausted ||
                    context->foreground_transport_exhausted;
                auto drain = context->terminal_owner->try_begin_drain();
                if (!drain) return;
                bool detached_restart_this_drain = false;
                if (capture_retained_mutation_lease) {
                    auto returned =
                        drain->take_retained_mutation_lease();
                    if (returned) {
                        returned_mutation_lease = std::move(returned);
                    }
                }
                if (drain->kind() ==
                    RuntimeFirewallDelayedTerminalOwner::DrainKind::
                        coordinator) {
                    if (const auto* terminal =
                            drain->coordinator_terminal()) {
                        drained_coordinator_completion = *terminal;
                        if (detach_restart_transport_recovery &&
                            context->foreground_transport_exhausted) {
                            detached_restart_recovery =
                                owner->retain_pending_successor(
                                    context,
                                    RuntimeFirewallOperationContext::
                                        SuccessorMode::defer_same_attempt,
                                    context->successor_attempt,
                                    context->successor_runtime_generation,
                                    terminal->snat_recovery,
                                    terminal->next_prepared_catalog,
                                    context
                                        ->successor_schedule_catalog_refresh,
                                    /*detach_foreground=*/true);
                            detached_restart_this_drain =
                                detached_restart_recovery;
                        }
                    }
                    if (settle_transport_exhaustion &&
                        context->foreground_transport_exhausted) {
                        context->retained_mutation_lease.reset();
                        RuntimeFirewallLifecycleTerminal terminal;
                        terminal.outcome =
                            RuntimeFirewallLifecycleOutcome::not_verified;
                        terminal.commit_ambiguous = false;
                        terminal.transient = true;
                        terminal.detail =
                            "foreground transport retry limit exhausted";
                        settled_transport_terminal = terminal;
                        (void)context->lifecycle_completion.settle(
                            std::move(terminal));
                    }
                    (void)drain->finish_coordinator_terminal();
                } else if (capture_retained_mutation_lease) {
                    (void)drain->finish_worker_terminal();
                }
                if (promote_successor_during_drain) {
                    promotion_retained =
                        owner->retain_pending_successor(
                            context,
                            RuntimeFirewallOperationContext::SuccessorMode::
                                reschedule_retry,
                            /*attempt=*/0U,
                            /*runtime_generation=*/77U,
                            {},
                            {},
                            /*schedule_catalog_refresh=*/false);
                }
                owner->cancel_completion_watchdog();
                owner->reset_if_active(context);
                if (detached_restart_this_drain) {
                    context->retained_mutation_lease.reset();
                    RuntimeFirewallLifecycleTerminal terminal;
                    terminal.outcome =
                        RuntimeFirewallLifecycleOutcome::not_verified;
                    terminal.commit_ambiguous = false;
                    terminal.transient = true;
                    terminal.detail =
                        "restart transport retry limit exhausted";
                    settled_transport_terminal = terminal;
                    (void)context->lifecycle_completion.settle(
                        std::move(terminal));
                    detached_restart_launch_result =
                        owner->launch_pending_successor();
                }
                if (promotion_retained) {
                    try {
                        promotion_eager_launch_result =
                            owner->launch_pending_successor();
                    } catch (...) {
                        promotion_eager_launch_result = false;
                    }
                }
            };
        callbacks.active_mutation_label = [] {
            return std::string{"test-writer"};
        };
        owner = std::make_shared<RuntimeFirewallOperationOwner>(
            coordinator, std::move(callbacks));
    }

    Timer& timer_with_label(const std::string& label) {
        for (auto& timer : timers) {
            if (timer.label == label) return timer;
        }
        throw std::runtime_error("timer not found: " + label);
    }
};

std::unique_ptr<RuntimeMutationAdmission::Lease> acquire_test_lease(
    RuntimeMutationAdmission& admission,
    const std::string& label = "preowned-firewall") {
    auto lease = admission.try_acquire(label);
    if (!lease) return {};
    return std::make_unique<RuntimeMutationAdmission::Lease>(
        std::move(*lease));
}

TEST_CASE("runtime firewall operation owner coordinator hands off exact immediate attempt") {
    RuntimeFirewallRetryCoordinator coordinator;
    RuntimeFirewallOperationClaim queued_claim;
    OwnedSnatRecovery queued_recovery;
    PreparedNativeVpnCatalogPtr queued_catalog;
    RuntimeFirewallOperationCompletion retained_terminal;
    auto catalog = std::make_shared<PreparedNativeVpnCatalog>();
    catalog->runtime_generation = 77U;
    catalog->schedule_catalog_refresh = false;
    OwnedSnatRecovery recovery;
    recovery.requested = true;
    recovery.missing_observed = true;
    recovery.cleanup_snapshot = OwnedConntrackCleanupSnapshot{
        77U, 0x00ffU, {0x0101U}, {0x0101U}, false};

    const auto disposition = coordinator
        .start_immediate_operation_with_prepared_catalog_and_terminal(
            /*attempt=*/0U,
            /*runtime_generation=*/77U,
            recovery,
            catalog,
            [](std::uint64_t generation) {
                return generation == 77U;
            },
            [&](RuntimeFirewallOperationClaim claim,
                OwnedSnatRecovery exact_recovery,
                PreparedNativeVpnCatalogPtr exact_catalog) {
                queued_claim = claim;
                queued_recovery = std::move(exact_recovery);
                queued_catalog = std::move(exact_catalog);
            },
            [&](RuntimeFirewallOperationCompletion terminal) noexcept {
                retained_terminal = std::move(terminal);
            });

    CHECK(disposition ==
          RuntimeFirewallImmediateDisposition::handed_off);
    REQUIRE(queued_claim);
    CHECK(queued_claim.phase ==
          RuntimeFirewallOperationPhase::worker_queued);
    CHECK(queued_claim.attempt == 0U);
    CHECK(queued_claim.runtime_generation == 77U);
    CHECK(queued_recovery.requested);
    CHECK(queued_recovery.missing_observed);
    REQUIRE(queued_recovery.cleanup_snapshot.has_value());
    CHECK(queued_recovery.cleanup_snapshot->runtime_generation == 77U);
    CHECK(queued_catalog == catalog);
    CHECK(coordinator.operation_is_current(queued_claim));
    CHECK_FALSE(retained_terminal.owned);

    retained_terminal = coordinator.terminate_operation_for_resnapshot(
        queued_claim,
        /*force_rerun=*/true);
    CHECK(retained_terminal.owned);
    CHECK_FALSE(coordinator.retry_pending());
}

TEST_CASE("runtime firewall operation owner accepts one exact preowned lease") {
    OwnerHarness harness;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(admission);
    REQUIRE(lease);
    auto* const exact_lease = lease.get();
    const auto token = lease->token();
    const auto domain = std::make_shared<TestDomainState>();

    auto result = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/true,
        domain,
        admission,
        std::move(lease));

    CHECK(result.disposition ==
          RuntimeFirewallImmediateDisposition::handed_off);
    CHECK_FALSE(result.unaccepted_lease);
    const auto context = harness.owner->active_context();
    REQUIRE(context);
    REQUIRE(context->retained_mutation_lease);
    CHECK(context->retained_mutation_lease.get() == exact_lease);
    CHECK(context->retained_mutation_lease->token() == token);
    CHECK(admission.owns(*context->retained_mutation_lease));
    CHECK(harness.dispatch_calls == 1);

    harness.owner.reset();
    CHECK(harness.drain_calls == 0);
    CHECK_FALSE(context->retained_mutation_lease);
    CHECK_FALSE(context->worker_operation);
    CHECK_FALSE(context->terminal_owner);
    CHECK_FALSE(admission.active().has_value());
}

TEST_CASE("runtime firewall operation owner returns rejected preowned lease unchanged") {
    OwnerHarness harness;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    RuntimeMutationAdmission foreign_admission;
    auto lease = acquire_test_lease(admission);
    REQUIRE(lease);
    auto* const exact_lease = lease.get();
    const auto token = lease->token();

    auto foreign = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/true,
        std::make_shared<TestDomainState>(),
        foreign_admission,
        std::move(lease));

    CHECK(foreign.disposition ==
          RuntimeFirewallImmediateDisposition::rejected);
    REQUIRE(foreign.unaccepted_lease);
    CHECK(foreign.unaccepted_lease.get() == exact_lease);
    CHECK(foreign.unaccepted_lease->token() == token);
    CHECK(admission.owns(*foreign.unaccepted_lease));

    harness.owner->request_shutdown();
    auto shutdown = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/true,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(foreign.unaccepted_lease));

    CHECK(shutdown.disposition ==
          RuntimeFirewallImmediateDisposition::rejected);
    REQUIRE(shutdown.unaccepted_lease);
    CHECK(shutdown.unaccepted_lease.get() == exact_lease);
    CHECK(shutdown.unaccepted_lease->token() == token);
    shutdown.unaccepted_lease.reset();
    CHECK_FALSE(admission.active().has_value());
}

TEST_CASE("runtime firewall operation owner returns exact preowned lease while another context is active") {
    OwnerHarness harness;
    harness.create_owner();
    REQUIRE(harness.owner->start_immediate(
                /*attempt=*/0U,
                /*runtime_generation=*/77U,
                {},
                {},
                /*schedule_catalog_refresh=*/true,
                std::make_shared<TestDomainState>()) ==
            RuntimeFirewallImmediateDisposition::handed_off);
    const auto active = harness.owner->active_context();
    REQUIRE(active);

    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(admission, "active-context-preowned");
    REQUIRE(lease);
    auto* const exact_lease = lease.get();
    const auto token = lease->token();

    auto rejected = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/true,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease));

    CHECK(rejected.disposition ==
          RuntimeFirewallImmediateDisposition::rejected);
    REQUIRE(rejected.unaccepted_lease);
    CHECK(rejected.unaccepted_lease.get() == exact_lease);
    CHECK(rejected.unaccepted_lease->token() == token);
    CHECK(admission.owns(*rejected.unaccepted_lease));
    CHECK(harness.owner->active_context() == active);
    CHECK(harness.dispatch_calls == 1);

    rejected.unaccepted_lease.reset();
    CHECK_FALSE(admission.active().has_value());
    harness.owner->terminate_before_worker(
        active,
        harness.dispatched_claim,
        RuntimeFirewallOperationContext::SuccessorMode::none,
        /*force_rerun=*/false);
}

TEST_CASE("runtime firewall operation owner preserves one exact retained lease across scheduler failure") {
    OwnerHarness harness;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(admission, "pending-successor-preowned");
    REQUIRE(lease);
    auto* const exact_lease = lease.get();
    const auto token = lease->token();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/true,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease));
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    REQUIRE_FALSE(start.unaccepted_lease);
    auto completed = harness.owner->active_context();
    REQUIRE(completed);
    auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim,
            /*force_rerun=*/true);
    REQUIRE(completion.owned);
    REQUIRE(harness.owner->retain_pending_successor(
        completed,
        RuntimeFirewallOperationContext::SuccessorMode::defer_same_attempt,
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        std::move(completion.snat_recovery),
        std::move(completion.next_prepared_catalog),
        /*schedule_catalog_refresh=*/true));
    CHECK_FALSE(completed->retained_mutation_lease);
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(completed);

    const auto* pending = harness.owner->pending_successor_state();
    REQUIRE(pending != nullptr);
    REQUIRE(pending->retained_mutation_lease);
    CHECK(pending->retained_mutation_lease.get() == exact_lease);
    CHECK(pending->retained_mutation_lease->token() == token);
    CHECK(admission.owns(*pending->retained_mutation_lease));
    auto pending_watchdog = harness.timer_with_label(
        "runtime-firewall-terminal-watchdog").callback;

    SUBCASE("schedule_oneshot throws") {
        harness.throw_oneshot_schedule = true;
    }
    SUBCASE("schedule_oneshot rejects registration") {
        harness.reject_oneshot_schedule = true;
    }

    bool first_launch = true;
    CHECK_NOTHROW(first_launch =
                      harness.owner->launch_pending_successor());
    CHECK_FALSE(first_launch);
    CHECK_FALSE(harness.owner->active_context());
    pending = harness.owner->pending_successor_state();
    REQUIRE(pending != nullptr);
    REQUIRE(pending->retained_mutation_lease);
    CHECK(pending->retained_mutation_lease.get() == exact_lease);
    CHECK(pending->retained_mutation_lease->token() == token);
    CHECK(admission.owns(*pending->retained_mutation_lease));

    harness.throw_oneshot_schedule = false;
    harness.reject_oneshot_schedule = false;
    CHECK_NOTHROW(pending_watchdog());
    CHECK_FALSE(harness.owner->pending_successor());
    auto launched = harness.owner->active_context();
    REQUIRE(launched);
    REQUIRE(launched->retained_mutation_lease);
    CHECK(launched->retained_mutation_lease.get() == exact_lease);
    CHECK(launched->retained_mutation_lease->token() == token);
    CHECK(admission.owns(*launched->retained_mutation_lease));
    CHECK(harness.coordinator.retry_pending());
    CHECK(harness.timer_with_label(
              "runtime-firewall-terminal-watchdog").cancelled);
    // A late callback from the promoted timer is serial-fenced and cannot
    // disturb the successor which now owns the exact authority.
    CHECK_NOTHROW(pending_watchdog());
    CHECK(harness.owner->active_context() == launched);

    launched.reset();
    completed.reset();
    harness.owner.reset();
    CHECK_FALSE(admission.active().has_value());
}

TEST_CASE("runtime firewall operation owner preserves exact retry authority across scheduler failure") {
    OwnerHarness harness;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(admission, "retry-successor-preowned");
    REQUIRE(lease);
    auto* const exact_lease = lease.get();
    const auto token = lease->token();
    auto lifecycle = RuntimeFirewallLifecycleCompletion::create();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/true,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease),
        std::move(lifecycle.source),
        RuntimeFirewallLifecycleKind::restart_active);
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    auto completed = harness.owner->active_context();
    REQUIRE(completed);
    auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim,
            /*force_rerun=*/true);
    REQUIRE(completion.owned);
    REQUIRE(harness.owner->retain_pending_successor(
        completed,
        RuntimeFirewallOperationContext::SuccessorMode::reschedule_retry,
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        std::move(completion.snat_recovery),
        std::move(completion.next_prepared_catalog),
        /*schedule_catalog_refresh=*/true));
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(completed);
    auto pending_watchdog = harness.timer_with_label(
        "runtime-firewall-terminal-watchdog").callback;

    SUBCASE("schedule_oneshot throws") {
        harness.throw_oneshot_schedule = true;
        CHECK_THROWS(harness.owner->launch_pending_successor());
    }
    SUBCASE("schedule_oneshot rejects registration") {
        harness.reject_oneshot_schedule = true;
        CHECK_FALSE(harness.owner->launch_pending_successor());
    }

    CHECK_FALSE(harness.owner->active_context());
    const auto* pending = harness.owner->pending_successor_state();
    REQUIRE(pending != nullptr);
    REQUIRE(pending->retained_mutation_lease);
    CHECK(pending->retained_mutation_lease.get() == exact_lease);
    CHECK(pending->retained_mutation_lease->token() == token);
    CHECK(pending->lifecycle_completion);
    CHECK(pending->lifecycle_kind ==
          RuntimeFirewallLifecycleKind::restart_active);
    CHECK_FALSE(lifecycle.wait.ready());

    harness.throw_oneshot_schedule = false;
    harness.reject_oneshot_schedule = false;
    CHECK_NOTHROW(pending_watchdog());
    auto launched = harness.owner->active_context();
    REQUIRE(launched);
    REQUIRE(launched->retained_mutation_lease);
    CHECK(launched->retained_mutation_lease.get() == exact_lease);
    CHECK(launched->retained_mutation_lease->token() == token);
    CHECK(launched->lifecycle_completion);
    CHECK(launched->lifecycle_kind ==
          RuntimeFirewallLifecycleKind::restart_active);
    CHECK_FALSE(lifecycle.wait.ready());
    CHECK(harness.timer_with_label(
              "runtime-firewall-terminal-watchdog").cancelled);

    launched.reset();
    completed.reset();
    harness.owner.reset();
    CHECK(harness.drain_calls == 0);
    CHECK_FALSE(admission.active().has_value());
    const auto terminal = lifecycle.wait.try_get();
    REQUIRE(terminal.has_value());
    CHECK(terminal->outcome ==
          RuntimeFirewallLifecycleOutcome::not_verified);
}

TEST_CASE("runtime firewall START exhaustion releases admission before lifecycle terminal") {
    OwnerHarness harness;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(admission, "start-exhausted-preowned");
    REQUIRE(lease);
    auto lifecycle = RuntimeFirewallLifecycleCompletion::create();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/false,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease),
        std::move(lifecycle.source),
        RuntimeFirewallLifecycleKind::start_from_stopped);
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    auto completed = harness.owner->active_context();
    REQUIRE(completed);
    auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim,
            /*force_rerun=*/false);
    REQUIRE(completion.owned);
    REQUIRE(harness.owner->retain_pending_successor(
        completed,
        RuntimeFirewallOperationContext::SuccessorMode::reschedule_retry,
        /*attempt=*/3U,
        /*runtime_generation=*/77U,
        std::move(completion.snat_recovery),
        std::move(completion.next_prepared_catalog),
        /*schedule_catalog_refresh=*/false));
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(completed);

    REQUIRE(harness.owner->launch_pending_successor());
    CHECK_FALSE(harness.owner->pending_successor());
    CHECK_FALSE(harness.owner->active_context());
    CHECK_FALSE(admission.active().has_value());
    const auto terminal = lifecycle.wait.try_get();
    REQUIRE(terminal.has_value());
    CHECK(terminal->outcome ==
          RuntimeFirewallLifecycleOutcome::not_verified);
    CHECK(harness.timer_with_label(
              "runtime-firewall-terminal-watchdog").cancelled);
}

TEST_CASE("runtime firewall foreground transport rejection budget is bounded") {
    OwnerHarness harness;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(
        admission, "bounded-transport-preowned");
    REQUIRE(lease);
    auto lifecycle = RuntimeFirewallLifecycleCompletion::create();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/false,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease),
        std::move(lifecycle.source),
        RuntimeFirewallLifecycleKind::restart_active);
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    const auto context = harness.owner->active_context();
    REQUIRE(context);

    CHECK(harness.owner->note_foreground_transport_rejection(context));
    CHECK(harness.owner->note_foreground_transport_rejection(context));
    CHECK(harness.owner->note_foreground_transport_rejection(context));
    CHECK_FALSE(
        harness.owner->note_foreground_transport_rejection(context));
    CHECK(context->foreground_transport_rejections == 4U);
    CHECK(context->foreground_transport_exhausted);

    harness.owner.reset();
    CHECK_FALSE(admission.active().has_value());
    REQUIRE(lifecycle.wait.try_get().has_value());
}

TEST_CASE("runtime firewall background cancel cannot cancel a foreground lifecycle timer") {
    OwnerHarness harness;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(
        admission, "foreground-timer-preowned");
    REQUIRE(lease);
    auto lifecycle = RuntimeFirewallLifecycleCompletion::create();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/false,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease),
        std::move(lifecycle.source),
        RuntimeFirewallLifecycleKind::start_from_stopped);
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    auto completed = harness.owner->active_context();
    REQUIRE(completed);
    auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim,
            /*force_rerun=*/true);
    REQUIRE(completion.owned);
    REQUIRE(harness.owner->retain_pending_successor(
        completed,
        RuntimeFirewallOperationContext::SuccessorMode::defer_same_attempt,
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        std::move(completion.snat_recovery),
        std::move(completion.next_prepared_catalog),
        /*schedule_catalog_refresh=*/false));
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(completed);
    REQUIRE(harness.owner->launch_pending_successor());
    const auto foreground_timer_context =
        harness.owner->active_context();
    REQUIRE(foreground_timer_context);
    REQUIRE(harness.coordinator.retry_pending());
    auto& timer = harness.timer_with_label(
        "runtime-firewall-admission-retry");
    CHECK_FALSE(timer.cancelled);

    harness.owner->cancel_retry();

    CHECK(harness.owner->active_context() ==
          foreground_timer_context);
    CHECK(harness.coordinator.retry_pending());
    CHECK_FALSE(timer.cancelled);
    CHECK_FALSE(lifecycle.wait.ready());
    CHECK(admission.active().has_value());

    harness.owner.reset();
    CHECK_FALSE(admission.active().has_value());
    REQUIRE(lifecycle.wait.try_get().has_value());
}

TEST_CASE("runtime firewall operation owner keeps an accepted inline terminal authoritative") {
    OwnerHarness harness;
    harness.run_oneshot_inline = true;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(admission, "inline-terminal-preowned");
    REQUIRE(lease);

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/true,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease));
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    auto completed = harness.owner->active_context();
    REQUIRE(completed);
    auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim,
            /*force_rerun=*/true);
    REQUIRE(completion.owned);
    REQUIRE(harness.owner->retain_pending_successor(
        completed,
        RuntimeFirewallOperationContext::SuccessorMode::reschedule_retry,
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        std::move(completion.snat_recovery),
        std::move(completion.next_prepared_catalog),
        /*schedule_catalog_refresh=*/true));
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(completed);

    harness.throw_dispatch_attempt = true;
    CHECK_THROWS(harness.owner->launch_pending_successor());

    CHECK_FALSE(harness.owner->pending_successor());
    CHECK_FALSE(harness.owner->active_context());
    CHECK(harness.dispatch_calls == 2);
    CHECK(harness.drain_calls == 1);
    CHECK_FALSE(admission.active().has_value());
}

TEST_CASE("runtime firewall operation owner shutdown discards pending successor lease") {
    OwnerHarness harness;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(admission, "pending-shutdown-preowned");
    REQUIRE(lease);
    const auto token = lease->token();
    auto lifecycle = RuntimeFirewallLifecycleCompletion::create();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/true,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease),
        std::move(lifecycle.source),
        RuntimeFirewallLifecycleKind::start_from_stopped);
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    auto completed = harness.owner->active_context();
    REQUIRE(completed);
    auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim,
            /*force_rerun=*/true);
    REQUIRE(completion.owned);
    REQUIRE(harness.owner->retain_pending_successor(
        completed,
        RuntimeFirewallOperationContext::SuccessorMode::defer_same_attempt,
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        std::move(completion.snat_recovery),
        std::move(completion.next_prepared_catalog),
        /*schedule_catalog_refresh=*/true));
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(completed);
    const auto* pending = harness.owner->pending_successor_state();
    REQUIRE(pending != nullptr);
    REQUIRE(pending->retained_mutation_lease);
    CHECK(pending->retained_mutation_lease->token() == token);
    CHECK(admission.owns(*pending->retained_mutation_lease));
    CHECK_FALSE(harness.timer_with_label(
                    "runtime-firewall-terminal-watchdog").cancelled);

    harness.owner->request_shutdown();
    harness.owner->cancel_pending_work();

    CHECK_FALSE(harness.owner->pending_successor());
    CHECK_FALSE(admission.active().has_value());
    CHECK(harness.timer_with_label(
              "runtime-firewall-terminal-watchdog").cancelled);
    const auto terminal = lifecycle.wait.try_get();
    REQUIRE(terminal.has_value());
    CHECK(terminal->outcome ==
          RuntimeFirewallLifecycleOutcome::shutdown);
}

TEST_CASE("runtime firewall operation owner returns retained lease when its executor rejects the queue") {
    OwnerHarness harness;
    harness.capture_retained_mutation_lease = true;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(admission, "executor-reject-preowned");
    REQUIRE(lease);
    auto* const exact_lease = lease.get();
    const auto token = lease->token();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/true,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease));
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    const auto context = harness.owner->active_context();
    REQUIRE(context);
    REQUIRE(context->retained_mutation_lease);

    harness.owner->shutdown_executor();
    CHECK_FALSE(harness.owner->enqueue_worker_with_retained_lease(
        context,
        harness.dispatched_claim,
        std::make_shared<const RuntimeFirewallWorkerAttemptInput>(),
        [](const RuntimeFirewallWorkerAttemptInput&,
           const RuntimeFirewallDelayedWorker::RunningClaim&)
            -> RuntimeFirewallWorkerAttemptResultPtr {
            return std::make_shared<
                const RuntimeFirewallWorkerAttemptResult>();
        }));

    CHECK_FALSE(context->retained_mutation_lease);
    REQUIRE(harness.returned_mutation_lease);
    CHECK(harness.returned_mutation_lease.get() == exact_lease);
    CHECK(harness.returned_mutation_lease->token() == token);
    CHECK(admission.owns(*harness.returned_mutation_lease));
    CHECK_FALSE(harness.owner->active_context());

    harness.returned_mutation_lease.reset();
    CHECK_FALSE(admission.active().has_value());
}

TEST_CASE("runtime firewall operation owner immediate queue throw publishes one exact terminal") {
    RuntimeFirewallRetryCoordinator coordinator;
    auto catalog = std::make_shared<PreparedNativeVpnCatalog>();
    catalog->runtime_generation = 77U;
    std::size_t terminal_calls = 0U;
    RuntimeFirewallOperationCompletion retained_terminal;

    const auto disposition = coordinator
        .start_immediate_operation_with_prepared_catalog_and_terminal(
            0U,
            77U,
            OwnedSnatRecovery{/*requested=*/true,
                              /*missing_observed=*/false},
            catalog,
            [](std::uint64_t) { return true; },
            [](RuntimeFirewallOperationClaim,
               OwnedSnatRecovery,
               PreparedNativeVpnCatalogPtr) {
                throw std::runtime_error("queue adapter rejected");
            },
            [&](RuntimeFirewallOperationCompletion terminal) noexcept {
                ++terminal_calls;
                retained_terminal = std::move(terminal);
            });

    CHECK(disposition ==
          RuntimeFirewallImmediateDisposition::handed_off);
    CHECK(terminal_calls == 1U);
    CHECK(retained_terminal.owned);
    CHECK(retained_terminal.rerun_requested);
    CHECK(retained_terminal.next_prepared_catalog == catalog);
    CHECK_FALSE(coordinator.retry_pending());
    CHECK(coordinator.owned_snat_recovery_pending());
}

TEST_CASE("runtime firewall operation owner immediate handoff has no retry timer") {
    OwnerHarness harness;
    harness.create_owner();
    auto domain = std::make_shared<TestDomainState>();
    auto catalog = std::make_shared<PreparedNativeVpnCatalog>();
    catalog->runtime_generation = 77U;
    catalog->schedule_catalog_refresh = false;
    OwnedSnatRecovery recovery;
    recovery.requested = true;

    const auto disposition = harness.owner->start_immediate(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        recovery,
        catalog,
        /*schedule_catalog_refresh=*/false,
        domain);

    CHECK(disposition ==
          RuntimeFirewallImmediateDisposition::handed_off);
    CHECK(harness.dispatch_calls == 1);
    CHECK(harness.dispatched_claim.attempt == 0U);
    CHECK(harness.dispatched_claim.runtime_generation == 77U);
    CHECK(harness.dispatched_recovery.requested);
    CHECK(harness.dispatched_catalog == catalog);
    CHECK_FALSE(harness.dispatched_schedule_catalog_refresh);
    REQUIRE(harness.owner->active_context());
    CHECK(harness.owner->active_context()->domain_state == domain);
    CHECK(harness.drain_calls == 0);
    CHECK(harness.timers.size() == 1U);
    CHECK(harness.timers.front().label ==
          "runtime-firewall-terminal-watchdog");

    harness.owner->terminate_before_worker(
        harness.owner->active_context(),
        harness.dispatched_claim,
        RuntimeFirewallOperationContext::SuccessorMode::none,
        /*force_rerun=*/false);
    CHECK_FALSE(harness.owner->active_context());
}

TEST_CASE("runtime firewall operation owner immediate coalescing rejects domain inheritance") {
    OwnerHarness harness;
    harness.create_owner();
    auto first_domain = std::make_shared<TestDomainState>();
    auto second_domain = std::make_shared<TestDomainState>();
    REQUIRE(harness.owner->start_immediate(
                0U, 77U, {}, {}, true, first_domain) ==
            RuntimeFirewallImmediateDisposition::handed_off);
    const auto active = harness.owner->active_context();
    REQUIRE(active);

    OwnedSnatRecovery trailing;
    trailing.requested = true;
    const auto second = harness.owner->start_immediate(
        0U, 77U, trailing, {}, false, second_domain);
    CHECK(second == RuntimeFirewallImmediateDisposition::coalesced);
    CHECK(harness.owner->active_context().get() == active.get());
    CHECK(active->domain_state == first_domain);
    CHECK(active->domain_state != second_domain);
    CHECK(active->trailing_snat_recovery.requested);
    CHECK(active->force_successor);

    harness.owner->terminate_before_worker(
        active,
        harness.dispatched_claim,
        RuntimeFirewallOperationContext::SuccessorMode::none,
        /*force_rerun=*/false);
}

TEST_CASE("runtime firewall operation owner immediate watchdog drains rejected stale wake") {
    OwnerHarness harness;
    harness.runtime_current = false;
    harness.reject_control_post = true;
    harness.create_owner();
    auto domain = std::make_shared<TestDomainState>();

    const auto disposition = harness.owner->start_immediate(
        0U, 77U, {}, {}, true, domain);
    CHECK(disposition ==
          RuntimeFirewallImmediateDisposition::handed_off);
    CHECK(harness.dispatch_calls == 0);
    CHECK(harness.control_posts == 1);
    CHECK(harness.drain_calls == 0);
    REQUIRE(harness.owner->active_context());

    harness.reject_control_post = false;
    auto watchdog = harness.timer_with_label(
        "runtime-firewall-terminal-watchdog").callback;
    REQUIRE(watchdog);
    watchdog();
    CHECK(harness.drain_calls == 1);
    CHECK_FALSE(harness.owner->active_context());
    CHECK_FALSE(harness.coordinator.retry_pending());
}

TEST_CASE("runtime firewall operation owner immediate rejects before claim without watchdog") {
    OwnerHarness harness;
    harness.throw_repeating_schedule = true;
    harness.create_owner();
    auto domain = std::make_shared<TestDomainState>();

    const auto disposition = harness.owner->start_immediate(
        0U, 77U, {}, {}, true, domain);
    CHECK(disposition == RuntimeFirewallImmediateDisposition::rejected);
    CHECK(harness.dispatch_calls == 0);
    CHECK_FALSE(harness.coordinator.retry_pending());
    CHECK_FALSE(harness.owner->active_context());
}

TEST_CASE("runtime firewall operation owner immediate failure advances to attempt one after one second") {
    OwnerHarness harness;
    harness.create_owner();
    auto domain = std::make_shared<TestDomainState>();
    REQUIRE(harness.owner->start_immediate(
                0U, 77U, {}, {}, true, domain) ==
            RuntimeFirewallImmediateDisposition::handed_off);
    const auto failed = harness.owner->active_context();
    REQUIRE(failed);
    const auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim,
            /*force_rerun=*/true);
    REQUIRE(completion.owned);
    REQUIRE(harness.owner->retain_pending_successor(
        failed,
        RuntimeFirewallOperationContext::SuccessorMode::reschedule_retry,
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        completion.snat_recovery,
        completion.next_prepared_catalog,
        /*schedule_catalog_refresh=*/true));
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(failed);

    REQUIRE(harness.owner->launch_pending_successor());
    const auto retry = harness.owner->active_context();
    REQUIRE(retry);
    const auto& timer = harness.timer_with_label(
        "runtime-firewall-retry");
    CHECK(timer.delay == std::chrono::seconds{1});
    auto callback = timer.callback;
    REQUIRE(callback);
    callback();
    CHECK(harness.dispatch_calls == 2);
    CHECK(harness.dispatched_claim.attempt == 1U);
    CHECK(harness.dispatched_claim.runtime_generation == 77U);

    harness.owner->terminate_before_worker(
        retry,
        harness.dispatched_claim,
        RuntimeFirewallOperationContext::SuccessorMode::none,
        /*force_rerun=*/false);
}

TEST_CASE("runtime firewall START retry keeps exact lifecycle policy") {
    OwnerHarness harness;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(admission, "start-retry-preowned");
    REQUIRE(lease);
    auto lifecycle = RuntimeFirewallLifecycleCompletion::create();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/false,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease),
        std::move(lifecycle.source),
        RuntimeFirewallLifecycleKind::start_from_stopped);
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    CHECK_FALSE(harness.dispatched_schedule_catalog_refresh);

    const auto failed = harness.owner->active_context();
    REQUIRE(failed);
    auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim,
            /*force_rerun=*/true);
    REQUIRE(completion.owned);
    REQUIRE(harness.owner->retain_pending_successor(
        failed,
        RuntimeFirewallOperationContext::SuccessorMode::reschedule_retry,
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        std::move(completion.snat_recovery),
        std::move(completion.next_prepared_catalog),
        /*schedule_catalog_refresh=*/false));
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(failed);

    REQUIRE(harness.owner->launch_pending_successor());
    const auto retry = harness.owner->active_context();
    REQUIRE(retry);
    CHECK(retry->lifecycle_kind ==
          RuntimeFirewallLifecycleKind::start_from_stopped);
    CHECK_FALSE(retry->successor_schedule_catalog_refresh);
    const auto& timer = harness.timer_with_label(
        "runtime-firewall-retry");
    CHECK(timer.delay == std::chrono::milliseconds{100});
    auto callback = timer.callback;
    REQUIRE(callback);
    callback();
    CHECK(harness.dispatch_calls == 2);
    CHECK(harness.dispatched_claim.attempt == 1U);
    CHECK_FALSE(harness.dispatched_schedule_catalog_refresh);

    harness.owner->terminate_before_worker(
        retry,
        harness.dispatched_claim,
        RuntimeFirewallOperationContext::SuccessorMode::none,
        /*force_rerun=*/false);
}

TEST_CASE("runtime firewall owner runs auxiliary tail only for its active context") {
    OwnerHarness harness;
    harness.create_owner();
    const auto domain = std::make_shared<TestDomainState>();
    REQUIRE(harness.owner->start_immediate(
                /*attempt=*/0U,
                /*runtime_generation=*/77U,
                {},
                {},
                /*schedule_catalog_refresh=*/true,
                domain) ==
            RuntimeFirewallImmediateDisposition::handed_off);
    const auto context = harness.owner->active_context();
    REQUIRE(context);

    std::atomic<std::size_t> calls{0U};
    REQUIRE(harness.owner->enqueue_auxiliary(
        context,
        "test-lifecycle-tail",
        [&calls]() noexcept {
            calls.fetch_add(1U, std::memory_order_release);
        }));
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::seconds{1};
    while (calls.load(std::memory_order_acquire) == 0U &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    CHECK(calls.load(std::memory_order_acquire) == 1U);

    CHECK_FALSE(harness.owner->enqueue_auxiliary(
        std::make_shared<RuntimeFirewallOperationContext>(),
        "foreign-lifecycle-tail",
        [] {}));
    harness.owner->request_shutdown();
    CHECK_FALSE(harness.owner->enqueue_auxiliary(
        context,
        "shutdown-lifecycle-tail",
        [] {}));
}

TEST_CASE("runtime firewall operation owner exhausts SNAT preparation into periodic maintenance") {
    constexpr std::size_t bounded_retry_count = 6U;
    CHECK(runtime_firewall_preworker_retry_required(
        /*snat_recovery_requested=*/true,
        /*native_vpn_catalog_policy=*/false,
        /*urltest_recovery_waiting=*/false,
        /*attempt=*/0U,
        bounded_retry_count));
    CHECK(runtime_firewall_preworker_retry_required(
        /*snat_recovery_requested=*/true,
        /*native_vpn_catalog_policy=*/false,
        /*urltest_recovery_waiting=*/false,
        /*attempt=*/bounded_retry_count,
        bounded_retry_count));
    CHECK(runtime_firewall_preworker_retry_required(
        /*snat_recovery_requested=*/true,
        /*native_vpn_catalog_policy=*/true,
        /*urltest_recovery_waiting=*/true,
        /*attempt=*/bounded_retry_count,
        bounded_retry_count));
    CHECK_FALSE(runtime_firewall_preworker_retry_required(
        /*snat_recovery_requested=*/false,
        /*native_vpn_catalog_policy=*/true,
        /*urltest_recovery_waiting=*/false,
        /*attempt=*/bounded_retry_count,
        bounded_retry_count));
    CHECK(should_run_periodic_owned_snat_firewall_recovery(
        /*routing_runtime_active=*/true,
        /*owned_snat_recovery_pending=*/true,
        /*runtime_retry_pending=*/false,
        /*netfilter_refresh_pending=*/false));

    OwnerHarness harness;
    harness.create_owner();
    OwnedSnatRecovery recovery;
    recovery.requested = true;
    auto domain = std::make_shared<TestDomainState>();
    REQUIRE(harness.owner->start_immediate(
                bounded_retry_count,
                77U,
                std::move(recovery),
                {},
                true,
                domain) ==
            RuntimeFirewallImmediateDisposition::handed_off);
    const auto exhausted = harness.owner->active_context();
    REQUIRE(exhausted);
    auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim);
    REQUIRE(completion.owned);
    CHECK(completion.rerun_requested);
    CHECK_FALSE(runtime_firewall_terminal_requests_successor(
        /*commit_ambiguous=*/false,
        completion.rerun_requested,
        /*independent_trailing_intent=*/false,
        /*suppress_coordinator_rerun=*/true));
    CHECK(runtime_firewall_terminal_requests_successor(
        /*commit_ambiguous=*/false,
        completion.rerun_requested,
        /*independent_trailing_intent=*/true,
        /*suppress_coordinator_rerun=*/true));

    REQUIRE(harness.owner->retain_pending_successor(
        exhausted,
        RuntimeFirewallOperationContext::SuccessorMode::reschedule_retry,
        /*attempt=*/bounded_retry_count,
        /*runtime_generation=*/77U,
        std::move(completion.snat_recovery),
        std::move(completion.next_prepared_catalog),
        /*schedule_catalog_refresh=*/true));
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(exhausted);
    REQUIRE(harness.owner->launch_pending_successor());
    CHECK(harness.owner->active_context());
    CHECK(harness.coordinator.retry_pending());
    const auto& maintenance =
        harness.timer_with_label("runtime-firewall-retry");
    CHECK(maintenance.delay == std::chrono::seconds{60});
    CHECK(harness.coordinator.owned_snat_recovery_pending());
    CHECK_FALSE(should_run_periodic_owned_snat_firewall_recovery(
        /*routing_runtime_active=*/true,
        /*owned_snat_recovery_pending=*/true,
        /*runtime_retry_pending=*/true,
        /*netfilter_refresh_pending=*/false));
    harness.owner->cancel_retry();
}

TEST_CASE("runtime firewall operation owner retains netfilter source only after immediate rejection") {
    constexpr std::uint8_t full = 1U;
    constexpr std::uint8_t nat = 2U;

    CHECK(retain_netfilter_refresh_reasons_after_immediate_disposition(
              nat,
              full,
              RuntimeFirewallImmediateDisposition::rejected,
              /*routing_runtime_active=*/true,
              /*shutdown_requested=*/false) ==
          static_cast<std::uint8_t>(full | nat));
    CHECK(retain_netfilter_refresh_reasons_after_immediate_disposition(
              nat,
              full,
              RuntimeFirewallImmediateDisposition::coalesced,
              /*routing_runtime_active=*/true,
              /*shutdown_requested=*/false) == nat);
    CHECK(retain_netfilter_refresh_reasons_after_immediate_disposition(
              nat,
              full,
              RuntimeFirewallImmediateDisposition::handed_off,
              /*routing_runtime_active=*/true,
              /*shutdown_requested=*/false) == nat);
    CHECK(retain_netfilter_refresh_reasons_after_immediate_disposition(
              0U,
              full,
              RuntimeFirewallImmediateDisposition::rejected,
              /*routing_runtime_active=*/false,
              /*shutdown_requested=*/false) == 0U);
    CHECK(retain_netfilter_refresh_reasons_after_immediate_disposition(
              0U,
              full,
              RuntimeFirewallImmediateDisposition::rejected,
              /*routing_runtime_active=*/true,
              /*shutdown_requested=*/true) == 0U);
}

TEST_CASE("runtime firewall operation owner coalesces one active transport") {
    OwnerHarness harness;
    harness.create_owner();

    harness.owner->schedule(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {});
    const auto first = harness.owner->active_context();
    REQUIRE(first);
    CHECK(first->successor_attempt == 0U);
    CHECK(first->successor_runtime_generation == 77U);
    CHECK(harness.timers.size() == 1U);

    OwnedSnatRecovery trailing_recovery;
    trailing_recovery.requested = true;
    harness.owner->schedule(
        /*attempt=*/2U,
        /*runtime_generation=*/77U,
        std::move(trailing_recovery),
        {});
    CHECK(harness.owner->active_context().get() == first.get());
    CHECK(harness.timers.size() == 1U);
    CHECK(first->force_successor);
    CHECK(first->successor_attempt == 2U);
    CHECK(first->trailing_snat_recovery.requested);
    CHECK(first->successor_mode ==
          RuntimeFirewallOperationContext::SuccessorMode::
              defer_same_attempt);
}

TEST_CASE("runtime firewall operation owner schedules one startup-shaped recovery") {
    OwnerHarness current;
    current.create_owner();

    current.owner->schedule(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        /*snat_recovery=*/{},
        /*prepared_catalog=*/{});
    REQUIRE(current.timers.size() == 1U);
    const auto current_callback = current.timers.front().callback;
    CHECK(current.timers.front().label == "runtime-firewall-retry");
    CHECK(current.timers.front().delay == std::chrono::seconds{1});

    // A second startup observation joins the active transport instead of
    // creating a competing timer.
    current.owner->schedule(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        /*snat_recovery=*/{},
        /*prepared_catalog=*/{});
    CHECK(current.timers.size() == 1U);

    REQUIRE(current_callback);
    current_callback();
    CHECK(current.dispatch_calls == 1);
    CHECK(current.dispatched_claim.runtime_generation == 77U);
    CHECK(current.dispatched_claim.attempt == 1U);
    CHECK_FALSE(current.dispatched_recovery.requested);
    CHECK_FALSE(current.dispatched_catalog);

    OwnerHarness stale;
    stale.create_owner();
    stale.owner->schedule(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        /*snat_recovery=*/{},
        /*prepared_catalog=*/{});
    REQUIRE(stale.timers.size() == 1U);
    const auto stale_callback = stale.timers.front().callback;
    REQUIRE(stale_callback);
    stale.runtime_current = false;
    stale_callback();
    CHECK(stale.dispatch_calls == 0);
}

TEST_CASE("runtime firewall operation owner preserves deferred attempt") {
    OwnerHarness harness;
    harness.create_owner();

    harness.owner->defer(
        /*attempt=*/4U,
        /*runtime_generation=*/77U,
        {},
        /*schedule_catalog_refresh=*/false,
        {});

    const auto context = harness.owner->active_context();
    REQUIRE(context);
    CHECK(context->queued_claim.attempt == 4U);
    CHECK(context->successor_attempt == 4U);
    CHECK_FALSE(context->successor_schedule_catalog_refresh);
    const auto& timer = harness.timer_with_label(
        "runtime-firewall-admission-retry");
    CHECK(timer.delay == std::chrono::seconds{1});
}

TEST_CASE("runtime firewall operation owner watchdog recovers rejected control wake") {
    OwnerHarness harness;
    harness.reject_control_post = true;
    harness.create_owner();
    harness.owner->schedule(0U, 77U, {}, {});
    const auto context = harness.owner->active_context();
    REQUIRE(context);

    RuntimeFirewallOperationCompletion terminal;
    terminal.owned = true;
    context->terminal_owner->coordinator_terminal_sink()(
        std::move(terminal));
    CHECK(harness.control_posts == 1);
    CHECK_FALSE(context->drain_post_inflight.load());
    CHECK(harness.drain_calls == 0);

    harness.reject_control_post = false;
    harness.owner->arm_completion_watchdog(context);
    auto watchdog = harness.timer_with_label(
        "runtime-firewall-terminal-watchdog").callback;
    REQUIRE(watchdog);
    watchdog();
    CHECK(harness.drain_calls == 1);
    CHECK_FALSE(harness.owner->active_context());

    harness.owner->request_shutdown();
    harness.owner->request_shutdown();
    CHECK(harness.owner->shutdown_requested());
}

TEST_CASE("runtime firewall watchdog does not launch a promoted successor twice in one tick") {
    OwnerHarness harness;
    harness.reject_control_post = true;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(
        admission, "same-tick-successor-preowned");
    REQUIRE(lease);
    auto lifecycle = RuntimeFirewallLifecycleCompletion::create();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/false,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease),
        std::move(lifecycle.source),
        RuntimeFirewallLifecycleKind::start_from_stopped);
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    const auto completed = harness.owner->active_context();
    REQUIRE(completed);
    auto watchdog = harness.timer_with_label(
        "runtime-firewall-terminal-watchdog").callback;
    REQUIRE(watchdog);

    harness.promote_successor_during_drain = true;
    harness.throw_oneshot_schedule = true;
    harness.owner->terminate_before_worker(
        completed,
        harness.dispatched_claim,
        RuntimeFirewallOperationContext::SuccessorMode::reschedule_retry,
        /*force_rerun=*/true);
    CHECK(harness.drain_calls == 0);

    harness.reject_control_post = false;
    CHECK_NOTHROW(watchdog());
    CHECK(harness.promotion_retained);
    CHECK_FALSE(harness.promotion_eager_launch_result);
    CHECK(harness.owner->pending_successor());
    CHECK(harness.oneshot_schedule_calls == 1);

    harness.throw_oneshot_schedule = false;
    CHECK_NOTHROW(watchdog());
    CHECK(harness.oneshot_schedule_calls == 2);
    CHECK_FALSE(harness.owner->pending_successor());
    CHECK(harness.owner->active_context());

    harness.owner.reset();
    CHECK_FALSE(admission.active().has_value());
    const auto terminal = lifecycle.wait.try_get();
    REQUIRE(terminal.has_value());
}

TEST_CASE("runtime firewall operation owner watchdog survives throwing wake and registration") {
    OwnerHarness harness;
    harness.throw_control_post = true;
    harness.create_owner();
    harness.owner->schedule(0U, 77U, {}, {});
    const auto context = harness.owner->active_context();
    REQUIRE(context);

    RuntimeFirewallOperationCompletion terminal;
    terminal.owned = true;
    context->terminal_owner->coordinator_terminal_sink()(
        std::move(terminal));
    CHECK_FALSE(context->drain_post_inflight.load());
    CHECK(harness.drain_calls == 0);

    harness.throw_control_post = false;
    harness.throw_repeating_schedule = true;
    CHECK(harness.owner->arm_completion_watchdog(context));
    CHECK(harness.drain_calls == 1);
    CHECK_FALSE(harness.owner->active_context());
}

TEST_CASE("runtime firewall operation owner retains successor across domain allocation failure") {
    OwnerHarness harness;
    harness.create_owner();
    harness.owner->schedule(0U, 77U, {}, {});
    const auto completed = harness.owner->active_context();
    REQUIRE(completed);
    harness.coordinator.cancel([&](int id) {
        for (auto& timer : harness.timers) {
            if (timer.id == id) timer.cancelled = true;
        }
    });

    OwnedSnatRecovery old_recovery;
    old_recovery.missing_observed = true;
    REQUIRE(harness.owner->retain_pending_successor(
        completed,
        RuntimeFirewallOperationContext::SuccessorMode::reschedule_retry,
        /*attempt=*/1U,
        /*runtime_generation=*/76U,
        std::move(old_recovery),
        {},
        /*schedule_catalog_refresh=*/true));
    harness.owner->reset_if_active(completed);

    auto newer_catalog = std::make_shared<PreparedNativeVpnCatalog>();
    newer_catalog->runtime_generation = 77U;
    newer_catalog->schedule_catalog_refresh = false;
    OwnedSnatRecovery newer_recovery;
    newer_recovery.requested = true;
    harness.throw_domain_state_once = true;
    CHECK_THROWS(harness.owner->schedule(
        /*attempt=*/2U,
        /*runtime_generation=*/77U,
        std::move(newer_recovery),
        newer_catalog));
    CHECK(harness.owner->pending_successor());
    CHECK_FALSE(harness.owner->active_context());
    const auto* retained = harness.owner->pending_successor_state();
    REQUIRE(retained != nullptr);
    CHECK(retained->runtime_generation == 77U);
    CHECK(retained->attempt == 2U);
    CHECK(retained->snat_recovery.requested);
    CHECK(retained->snat_recovery.missing_observed);
    CHECK(retained->prepared_catalog == newer_catalog);
    CHECK_FALSE(retained->schedule_catalog_refresh);

    CHECK(harness.owner->launch_pending_successor());
    CHECK_FALSE(harness.owner->pending_successor());
    const auto launched = harness.owner->active_context();
    REQUIRE(launched);
    CHECK(launched->successor_runtime_generation == 77U);
    CHECK(launched->prepared_native_vpn_catalog == newer_catalog);

    auto callback = harness.timer_with_label(
        "runtime-firewall-admission-retry").callback;
    REQUIRE(callback);
    callback();
    CHECK(harness.dispatch_calls == 1);
    CHECK(harness.dispatched_recovery.requested);
    CHECK(harness.dispatched_recovery.missing_observed);
    CHECK(harness.dispatched_catalog == newer_catalog);
}

TEST_CASE("runtime firewall operation owner drops stale catalog for newer catalog-less successor") {
    OwnerHarness harness;
    harness.create_owner();
    harness.owner->schedule(0U, 77U, {}, {});
    const auto completed = harness.owner->active_context();
    REQUIRE(completed);
    harness.coordinator.cancel([&](int id) {
        for (auto& timer : harness.timers) {
            if (timer.id == id) timer.cancelled = true;
        }
    });

    auto stale_catalog = std::make_shared<PreparedNativeVpnCatalog>();
    stale_catalog->runtime_generation = 76U;
    REQUIRE(harness.owner->retain_pending_successor(
        completed,
        RuntimeFirewallOperationContext::SuccessorMode::reschedule_retry,
        /*attempt=*/1U,
        /*runtime_generation=*/76U,
        {},
        stale_catalog,
        /*schedule_catalog_refresh=*/false));
    harness.owner->reset_if_active(completed);

    harness.throw_domain_state_once = true;
    CHECK_THROWS(harness.owner->schedule(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        /*prepared_catalog=*/{}));
    const auto* retained = harness.owner->pending_successor_state();
    REQUIRE(retained != nullptr);
    CHECK(retained->runtime_generation == 77U);
    CHECK_FALSE(retained->prepared_catalog);

    CHECK(harness.owner->launch_pending_successor());
    CHECK_FALSE(harness.owner->pending_successor());
    const auto launched = harness.owner->active_context();
    REQUIRE(launched);
    CHECK(launched->successor_runtime_generation == 77U);
    CHECK_FALSE(launched->prepared_native_vpn_catalog);
}

TEST_CASE("runtime firewall operation owner watchdog pumps a worker checkpoint") {
    OwnerHarness harness;
    harness.create_owner();
    harness.owner->schedule(0U, 77U, {}, {});
    const auto context = harness.owner->active_context();
    REQUIRE(context);

    int checkpoint_pumps = 0;
    context->pump_worker_checkpoint = [&checkpoint_pumps]() {
        ++checkpoint_pumps;
    };
    REQUIRE(harness.owner->arm_completion_watchdog(context));
    auto watchdog = harness.timer_with_label(
        "runtime-firewall-terminal-watchdog").callback;
    REQUIRE(watchdog);

    watchdog();
    CHECK(checkpoint_pumps == 1);
    CHECK(harness.owner->active_context() == context);
}

TEST_CASE("runtime firewall operation owner cancels a worker checkpoint from control shutdown drain") {
    OwnerHarness harness;
    harness.create_owner();
    harness.owner->schedule(0U, 77U, {}, {});
    const auto context = harness.owner->active_context();
    REQUIRE(context);

    int checkpoint_cancels = 0;
    context->cancel_worker_checkpoint = [&checkpoint_cancels]() {
        ++checkpoint_cancels;
    };

    harness.owner->request_shutdown();
    harness.owner->request_shutdown();
    CHECK(harness.owner->shutdown_requested());
    CHECK(checkpoint_cancels == 0);

    harness.owner->pump_terminal_for_shutdown();
    CHECK(checkpoint_cancels == 1);
}

TEST_CASE("runtime firewall late intent survives an already captured completion") {
    RuntimeFirewallOperationCompletion completion;
    completion.owned = true;
    auto old_catalog = std::make_shared<PreparedNativeVpnCatalog>();
    old_catalog->runtime_generation = 76U;
    completion.next_prepared_catalog = old_catalog;
    OwnedSnatRecovery trailing;
    trailing.requested = true;
    trailing.missing_observed = true;
    trailing.cleanup_snapshot = OwnedConntrackCleanupSnapshot{
        77U, 0x00ffU, {0x0101U}, {0x0101U}, false};

    auto newest_catalog = std::make_shared<PreparedNativeVpnCatalog>();
    newest_catalog->runtime_generation = 77U;
    PreparedNativeVpnCatalogPtr trailing_catalog = newest_catalog;

    REQUIRE(absorb_trailing_runtime_firewall_completion(
        completion, trailing, trailing_catalog));
    CHECK(completion.rerun_requested);
    CHECK(completion.snat_recovery.requested);
    CHECK(completion.snat_recovery.missing_observed);
    REQUIRE(completion.snat_recovery.cleanup_snapshot.has_value());
    CHECK(completion.snat_recovery.cleanup_snapshot->runtime_generation ==
          77U);
    CHECK_FALSE(trailing.requested);
    CHECK_FALSE(trailing.missing_observed);
    CHECK_FALSE(trailing.cleanup_snapshot.has_value());
    REQUIRE(completion.next_prepared_catalog);
    CHECK(completion.next_prepared_catalog->runtime_generation == 77U);
    CHECK_FALSE(trailing_catalog);
    CHECK_FALSE(absorb_trailing_runtime_firewall_completion(
        completion, trailing, trailing_catalog));

    completion.rerun_requested = false;
    auto stale_catalog = std::make_shared<PreparedNativeVpnCatalog>();
    stale_catalog->runtime_generation = 75U;
    trailing_catalog = stale_catalog;
    REQUIRE(absorb_trailing_runtime_firewall_completion(
        completion, trailing, trailing_catalog));
    CHECK(completion.rerun_requested);
    REQUIRE(completion.next_prepared_catalog);
    CHECK(completion.next_prepared_catalog->runtime_generation == 77U);
    CHECK_FALSE(trailing_catalog);
}

TEST_CASE("runtime firewall START route fence uses the bounded retry policy") {
    CHECK(runtime_firewall_start_retry_available(0U));
    CHECK(runtime_firewall_start_retry_available(1U));
    CHECK(runtime_firewall_start_retry_available(2U));
    CHECK_FALSE(runtime_firewall_start_retry_available(3U));
    CHECK_FALSE(runtime_firewall_start_retry_available(99U));
}

TEST_CASE("runtime firewall START rollback handoff has a finite budget") {
    CHECK(runtime_firewall_start_rollback_handoff_retry_available(0U));
    CHECK(runtime_firewall_start_rollback_handoff_retry_available(1U));
    CHECK(runtime_firewall_start_rollback_handoff_retry_available(3U));
    CHECK_FALSE(
        runtime_firewall_start_rollback_handoff_retry_available(4U));
    CHECK_FALSE(
        runtime_firewall_start_rollback_handoff_retry_available(99U));
}

TEST_CASE("runtime firewall restart needs no resolver tail when no refresh is required") {
    CHECK(runtime_firewall_restart_resolver_initially_verified(
        RuntimeFirewallLifecycleKind::background,
        /*resolver_refresh_required=*/true,
        /*resolver_waits_for_firewall=*/true));
    CHECK(runtime_firewall_restart_resolver_initially_verified(
        RuntimeFirewallLifecycleKind::restart_active,
        /*resolver_refresh_required=*/false,
        /*resolver_waits_for_firewall=*/false));
    CHECK_FALSE(runtime_firewall_restart_resolver_initially_verified(
        RuntimeFirewallLifecycleKind::restart_active,
        /*resolver_refresh_required=*/false,
        /*resolver_waits_for_firewall=*/true));
    CHECK_FALSE(runtime_firewall_restart_resolver_initially_verified(
        RuntimeFirewallLifecycleKind::restart_active,
        /*resolver_refresh_required=*/true,
        /*resolver_waits_for_firewall=*/false));
    CHECK_FALSE(runtime_firewall_restart_resolver_initially_verified(
        RuntimeFirewallLifecycleKind::start_from_stopped,
        /*resolver_refresh_required=*/false,
        /*resolver_waits_for_firewall=*/false));
}

TEST_CASE("runtime firewall pending START transport exhaustion returns to a typed terminal") {
    OwnerHarness harness;
    harness.settle_transport_exhaustion = true;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(
        admission, "pending-transport-exhaustion");
    REQUIRE(lease);
    auto lifecycle = RuntimeFirewallLifecycleCompletion::create();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/false,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease),
        std::move(lifecycle.source),
        RuntimeFirewallLifecycleKind::start_from_stopped);
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    const auto completed = harness.owner->active_context();
    REQUIRE(completed);
    auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim,
            /*force_rerun=*/true);
    REQUIRE(completion.owned);
    REQUIRE(harness.owner->retain_pending_successor(
        completed,
        RuntimeFirewallOperationContext::SuccessorMode::
            defer_same_attempt,
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        OwnedSnatRecovery{
            /*requested=*/true,
            /*missing_observed=*/true},
        [] {
            auto catalog =
                std::make_shared<PreparedNativeVpnCatalog>();
            catalog->runtime_generation = 77U;
            catalog->schedule_catalog_refresh = false;
            return catalog;
        }(),
        /*schedule_catalog_refresh=*/false));
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(completed);

    for (std::size_t rejection = 0U; rejection < 3U;
         ++rejection) {
        harness.throw_domain_state_once = true;
        CHECK_THROWS(harness.owner->launch_pending_successor());
        CHECK(harness.owner->pending_successor());
        CHECK(admission.active().has_value());
        CHECK_FALSE(lifecycle.wait.try_get().has_value());
    }

    harness.throw_domain_state_once = true;
    CHECK(harness.owner->launch_pending_successor());
    CHECK_FALSE(harness.owner->pending_successor());
    CHECK(harness.drained_transport_exhausted);
    CHECK_FALSE(harness.owner->active_context());
    CHECK_FALSE(admission.active().has_value());
    REQUIRE(harness.drained_coordinator_completion.has_value());
    CHECK(harness.drained_coordinator_completion->rerun_requested);
    CHECK(harness.drained_coordinator_completion->snat_recovery.requested);
    CHECK(harness.drained_coordinator_completion->snat_recovery
              .missing_observed);
    REQUIRE(harness.drained_coordinator_completion
                ->next_prepared_catalog);
    CHECK(harness.drained_coordinator_completion
              ->next_prepared_catalog->runtime_generation == 77U);
    REQUIRE(harness.settled_transport_terminal.has_value());
    CHECK(harness.settled_transport_terminal->outcome ==
          RuntimeFirewallLifecycleOutcome::not_verified);
    CHECK_FALSE(harness.settled_transport_terminal->commit_ambiguous);
    CHECK(harness.settled_transport_terminal->transient);
    const auto lifecycle_terminal = lifecycle.wait.try_get();
    REQUIRE(lifecycle_terminal.has_value());
    CHECK(lifecycle_terminal->outcome ==
          RuntimeFirewallLifecycleOutcome::not_verified);
    CHECK(lifecycle_terminal->detail ==
          "foreground transport retry limit exhausted");
}

TEST_CASE("runtime firewall restart transport exhaustion detaches exact recovery to background") {
    OwnerHarness harness;
    harness.detach_restart_transport_recovery = true;
    harness.create_owner();
    RuntimeMutationAdmission admission;
    auto lease = acquire_test_lease(
        admission, "restart-transport-exhaustion");
    REQUIRE(lease);
    auto lifecycle = RuntimeFirewallLifecycleCompletion::create();

    auto start = harness.owner->start_immediate_preowned(
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        {},
        {},
        /*schedule_catalog_refresh=*/false,
        std::make_shared<TestDomainState>(),
        admission,
        std::move(lease),
        std::move(lifecycle.source),
        RuntimeFirewallLifecycleKind::restart_active);
    REQUIRE(start.disposition ==
            RuntimeFirewallImmediateDisposition::handed_off);
    const auto completed = harness.owner->active_context();
    REQUIRE(completed);
    auto completion =
        harness.coordinator.terminate_operation_for_resnapshot(
            harness.dispatched_claim,
            /*force_rerun=*/true);
    REQUIRE(completion.owned);

    OwnedSnatRecovery exact_recovery;
    exact_recovery.requested = true;
    exact_recovery.missing_observed = true;
    exact_recovery.cleanup_snapshot = OwnedConntrackCleanupSnapshot{
        77U, 0x00ffU, {0x0101U}, {0x0101U}, false};
    auto exact_catalog = std::make_shared<PreparedNativeVpnCatalog>();
    exact_catalog->runtime_generation = 77U;
    exact_catalog->schedule_catalog_refresh = false;
    REQUIRE(harness.owner->retain_pending_successor(
        completed,
        RuntimeFirewallOperationContext::SuccessorMode::
            defer_same_attempt,
        /*attempt=*/0U,
        /*runtime_generation=*/77U,
        std::move(exact_recovery),
        exact_catalog,
        /*schedule_catalog_refresh=*/false));
    harness.owner->cancel_completion_watchdog();
    harness.owner->reset_if_active(completed);

    for (std::size_t rejection = 0U; rejection < 3U;
         ++rejection) {
        harness.throw_domain_state_once = true;
        CHECK_THROWS(harness.owner->launch_pending_successor());
        CHECK(harness.owner->pending_successor());
        CHECK(admission.active().has_value());
        CHECK_FALSE(lifecycle.wait.try_get().has_value());
    }

    harness.throw_domain_state_once = true;
    CHECK(harness.owner->launch_pending_successor());
    CHECK(harness.detached_restart_recovery);
    CHECK(harness.detached_restart_launch_result);
    CHECK(harness.drain_calls == 1);
    CHECK(harness.oneshot_schedule_calls == 1);
    CHECK(harness.timer_with_label(
              "runtime-firewall-terminal-watchdog").cancelled);
    CHECK_FALSE(harness.owner->pending_successor());
    CHECK_FALSE(admission.active().has_value());
    const auto foreground_terminal = lifecycle.wait.try_get();
    REQUIRE(foreground_terminal.has_value());
    CHECK(foreground_terminal->outcome ==
          RuntimeFirewallLifecycleOutcome::not_verified);
    CHECK(foreground_terminal->detail ==
          "restart transport retry limit exhausted");

    auto& admission_retry = harness.timer_with_label(
        "runtime-firewall-admission-retry");
    REQUIRE(admission_retry.callback);
    admission_retry.callback();
    CHECK(harness.dispatch_calls == 2);
    CHECK(harness.dispatched_lifecycle_kind ==
          RuntimeFirewallLifecycleKind::background);
    CHECK(harness.dispatched_schedule_catalog_refresh == false);
    CHECK(harness.dispatched_recovery.requested);
    CHECK(harness.dispatched_recovery.missing_observed);
    REQUIRE(harness.dispatched_recovery.cleanup_snapshot.has_value());
    CHECK(harness.dispatched_recovery.cleanup_snapshot
              ->runtime_generation == 77U);
    REQUIRE(harness.dispatched_catalog);
    CHECK(harness.dispatched_catalog->runtime_generation == 77U);
    CHECK_FALSE(harness.dispatched_catalog->schedule_catalog_refresh);
}

} // namespace
