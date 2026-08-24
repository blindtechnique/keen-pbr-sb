#include <doctest/doctest.h>

#include "runtime/list_refresh_task.hpp"

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace keen_pbr3;

TEST_CASE("list refresh task retains mutation lifetime through terminal publication") {
    ListRefreshTaskCoordinator coordinator;
    auto exact_payload = std::make_shared<int>(73);
    std::weak_ptr<int> observed = exact_payload;
    bool terminal_publication_observed_lifetime = false;
    coordinator.set_publish_callback([&](const auto& snapshot) {
        if (list_refresh_task_status_is_terminal(snapshot.status)) {
            terminal_publication_observed_lifetime = !observed.expired();
        }
    });
    const auto started = coordinator.begin(1, exact_payload);
    REQUIRE(started.accepted);
    exact_payload.reset();

    REQUIRE_FALSE(observed.expired());
    REQUIRE(coordinator.mark_running(started.task.id, "meta"));
    REQUIRE(coordinator.mark_applying(started.task.id));
    REQUIRE(observed.lock());
    CHECK(*observed.lock() == 73);

    REQUIRE(coordinator.succeed(started.task.id, {}, true));
    CHECK(terminal_publication_observed_lifetime);
    CHECK(observed.expired());
}

TEST_CASE("read-only list refresh atomically upgrades to one forced reconcile") {
    ListRefreshTaskCoordinator coordinator;
    auto mutation_lifetime = std::make_shared<int>(118);
    std::weak_ptr<int> observed = mutation_lifetime;
    bool terminal_publication_observed_lifetime = false;
    coordinator.set_publish_callback([&](const auto& snapshot) {
        if (list_refresh_task_status_is_terminal(snapshot.status)) {
            terminal_publication_observed_lifetime = !observed.expired();
        }
    });

    const auto read_only = coordinator.begin(1);
    REQUIRE(read_only.accepted);
    REQUIRE_FALSE(read_only.coalesced);
    REQUIRE(coordinator.mark_running(read_only.task.id, "meta"));

    const auto upgraded = coordinator.begin(
        1, mutation_lifetime, /*upgrade_active=*/true);
    REQUIRE(upgraded.accepted);
    REQUIRE(upgraded.coalesced);
    CHECK(upgraded.task.id == read_only.task.id);
    REQUIRE(upgraded.cancellation.valid());
    CHECK(upgraded.cancellation.shared_flag() ==
          read_only.cancellation.shared_flag());
    CHECK(coordinator.force_reconcile_requested(read_only.task.id));
    mutation_lifetime.reset();
    CHECK_FALSE(observed.expired());

    // An upgraded reload must apply the live/current configuration even when
    // the worker reports HTTP 304 / no changed cache entry.
    CHECK(should_reconcile_committed_list_cache(
        /*reload_requested=*/false,
        /*force_reconcile=*/true,
        /*runtime_active=*/true,
        /*cache_changed=*/false));
    CHECK_FALSE(should_reconcile_committed_list_cache(
        /*reload_requested=*/false,
        /*force_reconcile=*/true,
        /*runtime_active=*/false,
        /*cache_changed=*/false));

    REQUIRE(coordinator.mark_applying(read_only.task.id));
    REQUIRE(coordinator.succeed(read_only.task.id, {}, true));
    CHECK(terminal_publication_observed_lifetime);
    CHECK(observed.expired());
}

TEST_CASE("deferred reload keeps force after the read-only task terminalizes") {
    ListRefreshTaskCoordinator coordinator;
    const auto read_only = coordinator.begin(1);
    REQUIRE(read_only.accepted);
    REQUIRE(coordinator.mark_running(read_only.task.id, "meta"));

    // Global admission was busy, so begin()/upgrade could not run. Preserve
    // the fact that a read-only task existed in the one deferred intent.
    bool deferred_force = merge_list_refresh_force_reconcile(
        /*retained=*/false,
        /*incoming=*/coordinator.active().has_value());
    REQUIRE(deferred_force);
    deferred_force = merge_list_refresh_force_reconcile(
        deferred_force,
        /*incoming later busy request=*/false);
    REQUIRE(deferred_force);

    REQUIRE(coordinator.succeed(read_only.task.id, {}, false));
    CHECK_FALSE(coordinator.active().has_value());

    auto mutation_lifetime = std::make_shared<int>(304);
    std::weak_ptr<int> observed = mutation_lifetime;
    const auto trailing = coordinator.begin(
        1,
        mutation_lifetime,
        /*upgrade_active=*/true,
        /*force_new=*/deferred_force);
    REQUIRE(trailing.accepted);
    CHECK_FALSE(trailing.coalesced);
    CHECK(coordinator.force_reconcile_requested(trailing.task.id));
    mutation_lifetime.reset();
    CHECK_FALSE(observed.expired());

    REQUIRE(coordinator.mark_running(trailing.task.id, "meta"));
    CHECK(should_reconcile_committed_list_cache(
        /*reload_requested=*/true,
        /*force_reconcile=*/
            coordinator.force_reconcile_requested(trailing.task.id),
        /*runtime_active=*/true,
        /*cache_changed=*/false));
    REQUIRE(coordinator.mark_applying(trailing.task.id));
    REQUIRE(coordinator.succeed(trailing.task.id, {}, true));
    CHECK(observed.expired());
}

TEST_CASE("list refresh shutdown terminalization releases mutation lifetime") {
    ListRefreshTaskCoordinator coordinator;
    auto exact_payload = std::make_shared<int>(91);
    std::weak_ptr<int> observed = exact_payload;
    const auto started = coordinator.begin(1, exact_payload);
    REQUIRE(started.accepted);
    exact_payload.reset();
    REQUIRE(coordinator.mark_running(started.task.id, "meta"));

    RemoteListsRefreshResult committed;
    committed.changed_lists = {"meta"};
    REQUIRE(finish_list_refresh_if_shutting_down(
        false, coordinator, started.task.id, committed));
    CHECK(observed.expired());
}

TEST_CASE("list refresh task tracks progress and structured success result") {
    std::int64_t now = 100;
    ListRefreshTaskCoordinator coordinator(4, [&] { return now; });
    std::vector<ListRefreshTaskSnapshot> publications;
    coordinator.set_publish_callback([&](const auto& snapshot) {
        publications.push_back(snapshot);
        // Re-entering a read API proves that publication is outside the state lock.
        CHECK(coordinator.find(snapshot.id).has_value());
    });

    const auto started = coordinator.begin(2);
    REQUIRE(started.accepted);
    CHECK(started.cancellation.valid());
    CHECK_FALSE(started.cancellation.cancellation_requested());
    REQUIRE(started.cancellation.shared_flag());
    CHECK_FALSE(started.cancellation.shared_flag()->load());
    CHECK(started.task.status == ListRefreshTaskStatus::Queued);
    CHECK(started.task.created_at == 100);
    CHECK(started.task.revision == 1);

    now = 101;
    REQUIRE(coordinator.mark_running(started.task.id, "meta"));
    now = 102;
    REQUIRE(coordinator.update_progress(started.task.id, 1, "telegram"));
    now = 103;
    REQUIRE(coordinator.update_progress(started.task.id, 2));
    now = 104;
    REQUIRE(coordinator.mark_applying(started.task.id));

    RemoteListsRefreshResult result;
    result.refreshed_lists = {"meta", "telegram"};
    result.changed_lists = {"meta"};
    now = 105;
    REQUIRE(coordinator.succeed(started.task.id, result, true));

    CHECK_FALSE(coordinator.active().has_value());
    const auto terminal = coordinator.find(started.task.id);
    REQUIRE(terminal);
    CHECK(terminal->status == ListRefreshTaskStatus::Succeeded);
    CHECK(terminal->started_at == 101);
    CHECK(terminal->finished_at == 105);
    CHECK(terminal->completed == 2);
    CHECK_FALSE(terminal->current.has_value());
    REQUIRE(terminal->terminal_result);
    CHECK(terminal->terminal_result->reloaded);
    CHECK(terminal->terminal_result->error.empty());
    CHECK(terminal->terminal_result->refresh_result.refreshed_lists ==
          std::vector<std::string>{"meta", "telegram"});
    CHECK(terminal->terminal_result->refresh_result.changed_lists ==
          std::vector<std::string>{"meta"});
    CHECK(publications.size() == 6);
}

TEST_CASE("list refresh task enforces one active task and valid transitions") {
    ListRefreshTaskCoordinator coordinator;
    const auto first = coordinator.begin(2);
    REQUIRE(first.accepted);

    const auto rejected = coordinator.begin(1);
    CHECK_FALSE(rejected.accepted);
    CHECK(rejected.task.id == first.task.id);
    CHECK_FALSE(rejected.cancellation.valid());

    CHECK_FALSE(coordinator.update_progress(first.task.id, 1));
    REQUIRE(coordinator.mark_running(first.task.id));
    REQUIRE(coordinator.update_progress(first.task.id, 1, "second"));
    CHECK_FALSE(coordinator.update_progress(first.task.id, 0));
    CHECK_FALSE(coordinator.update_progress(first.task.id, 3));
    CHECK_FALSE(coordinator.mark_running(first.task.id));
    CHECK_FALSE(coordinator.mark_applying("stale-task"));
    CHECK_FALSE(coordinator.succeed("stale-task", {}, false));
    REQUIRE(coordinator.fail(first.task.id, "download failed"));

    const auto terminal = coordinator.find(first.task.id);
    REQUIRE(terminal);
    CHECK(terminal->status == ListRefreshTaskStatus::Failed);
    REQUIRE(terminal->terminal_result);
    CHECK(terminal->terminal_result->error == "download failed");

    const auto next = coordinator.begin(0);
    CHECK(next.accepted);
    CHECK(next.task.id != first.task.id);
}

TEST_CASE("list refresh task exposes cooperative cancellation") {
    ListRefreshTaskCoordinator coordinator;
    const auto started = coordinator.begin(1);
    REQUIRE(started.accepted);
    REQUIRE(coordinator.mark_running(started.task.id, "slow-list"));

    REQUIRE(coordinator.request_cancel_active());
    CHECK(started.cancellation.cancellation_requested());
    const auto cancelling = coordinator.active();
    REQUIRE(cancelling);
    CHECK(cancelling->status == ListRefreshTaskStatus::Running);
    CHECK(cancelling->cancel_requested);

    // Requesting cancellation is idempotent; the worker owns terminalization.
    REQUIRE(coordinator.request_cancel(started.task.id));
    REQUIRE(coordinator.finish_cancelled(started.task.id, "shutdown"));

    const auto terminal = coordinator.find(started.task.id);
    REQUIRE(terminal);
    CHECK(terminal->status == ListRefreshTaskStatus::Cancelled);
    CHECK(terminal->cancel_requested);
    REQUIRE(terminal->terminal_result);
    CHECK(terminal->terminal_result->error == "shutdown");
    CHECK_FALSE(coordinator.request_cancel(started.task.id));
}

TEST_CASE("queued list refresh cancellation frees the single-flight slot immediately") {
    ListRefreshTaskCoordinator coordinator;
    auto exact_payload = std::make_shared<int>(44);
    std::weak_ptr<int> observed = exact_payload;
    bool terminal_publication_observed_lifetime = false;
    coordinator.set_publish_callback([&](const auto& snapshot) {
        if (list_refresh_task_status_is_terminal(snapshot.status)) {
            terminal_publication_observed_lifetime = !observed.expired();
        }
    });
    const auto started = coordinator.begin(1, exact_payload);
    REQUIRE(started.accepted);
    exact_payload.reset();

    REQUIRE(coordinator.request_cancel(started.task.id));
    CHECK(terminal_publication_observed_lifetime);
    CHECK(observed.expired());
    CHECK(started.cancellation.cancellation_requested());
    CHECK_FALSE(coordinator.active().has_value());
    CHECK_FALSE(coordinator.mark_running(started.task.id));

    const auto terminal = coordinator.find(started.task.id);
    REQUIRE(terminal);
    CHECK(terminal->status == ListRefreshTaskStatus::Cancelled);
    REQUIRE(terminal->terminal_result);
    CHECK(terminal->terminal_result->error ==
          "list refresh cancelled before execution");

    const auto next = coordinator.begin(1);
    CHECK(next.accepted);
}

TEST_CASE("running cancellation prevents apply and preserves committed lists") {
    ListRefreshTaskCoordinator coordinator;
    const auto started = coordinator.begin(1);
    REQUIRE(started.accepted);
    REQUIRE(coordinator.mark_running(started.task.id, "meta"));

    REQUIRE(coordinator.request_cancel(started.task.id));
    CHECK_FALSE(coordinator.mark_applying(started.task.id));

    RemoteListsRefreshResult partial;
    partial.changed_lists = {"meta"};
    REQUIRE(coordinator.finish_cancelled(
        started.task.id, "cancelled after commit", partial, false));

    const auto terminal = coordinator.find(started.task.id);
    REQUIRE(terminal);
    CHECK(terminal->status == ListRefreshTaskStatus::Cancelled);
    REQUIRE(terminal->terminal_result);
    CHECK_FALSE(terminal->terminal_result->reloaded);
    CHECK(terminal->terminal_result->refresh_result.changed_lists ==
          std::vector<std::string>{"meta"});
}

TEST_CASE("shutdown after cache commit cancels before runtime apply") {
    ListRefreshTaskCoordinator coordinator;
    const auto started = coordinator.begin(1);
    REQUIRE(started.accepted);
    REQUIRE(coordinator.mark_running(started.task.id, "meta"));

    RemoteListsRefreshResult committed;
    committed.refreshed_lists = {"meta"};
    committed.changed_lists = {"meta"};
    committed.relevant_changed_lists = {"meta"};
    committed.dns_relevant_changed_lists = {"meta"};

    REQUIRE(coordinator.request_cancel_active());
    REQUIRE(finish_list_refresh_if_shutting_down(
        false, coordinator, started.task.id, committed));

    CHECK_FALSE(coordinator.active().has_value());
    CHECK_FALSE(coordinator.mark_applying(started.task.id));
    const auto terminal = coordinator.find(started.task.id);
    REQUIRE(terminal);
    CHECK(terminal->status == ListRefreshTaskStatus::Cancelled);
    REQUIRE(terminal->terminal_result);
    CHECK(terminal->terminal_result->error == "daemon is shutting down");
    CHECK_FALSE(terminal->terminal_result->reloaded);
    CHECK(terminal->terminal_result->refresh_result.changed_lists ==
          std::vector<std::string>{"meta"});

    // The shutdown gate is a no-op while the control loop is still accepting
    // work, so normal completion remains owned by the caller.
    const auto next = coordinator.begin(0);
    REQUIRE(next.accepted);
    CHECK_FALSE(finish_list_refresh_if_shutting_down(
        true, coordinator, next.task.id, std::nullopt));
    CHECK(coordinator.active().has_value());
}

TEST_CASE("list refresh task refuses cancellation after apply begins") {
    ListRefreshTaskCoordinator coordinator;
    const auto started = coordinator.begin(0);
    REQUIRE(started.accepted);
    REQUIRE(coordinator.mark_running(started.task.id));
    REQUIRE(coordinator.mark_applying(started.task.id));

    CHECK_FALSE(coordinator.request_cancel(started.task.id));
    CHECK_FALSE(coordinator.request_cancel_active());
    CHECK_FALSE(coordinator.finish_cancelled(started.task.id, "too late"));
    CHECK_FALSE(started.cancellation.cancellation_requested());
    REQUIRE(coordinator.succeed(started.task.id, {}, true));
}

TEST_CASE("list refresh task retains bounded newest-first terminal history") {
    std::int64_t now = 10;
    ListRefreshTaskCoordinator coordinator(2, [&] { return now++; });
    std::vector<std::string> ids;

    for (int i = 0; i < 3; ++i) {
        const auto task = coordinator.begin(0);
        REQUIRE(task.accepted);
        ids.push_back(task.task.id);
        REQUIRE(coordinator.mark_running(task.task.id));
        REQUIRE(coordinator.succeed(task.task.id, {}, false));
    }

    const auto history = coordinator.terminal_history();
    REQUIRE(history.size() == 2);
    CHECK(history[0].id == ids[2]);
    CHECK(history[1].id == ids[1]);
    CHECK_FALSE(coordinator.find(ids[0]).has_value());
}

TEST_CASE("list refresh task observer failures do not strand single flight") {
    ListRefreshTaskCoordinator coordinator;
    coordinator.set_publish_callback([](const auto&) {
        throw std::runtime_error("injected observer failure");
    });

    const auto task = coordinator.begin(0);
    REQUIRE(task.accepted);
    REQUIRE(coordinator.mark_running(task.task.id));
    REQUIRE(coordinator.succeed(task.task.id, {}, false));

    const auto next = coordinator.begin(0);
    CHECK(next.accepted);
}

TEST_CASE("list refresh task status names cover wire values") {
    CHECK(std::string(list_refresh_task_status_name(ListRefreshTaskStatus::Queued)) ==
          "queued");
    CHECK(std::string(list_refresh_task_status_name(ListRefreshTaskStatus::Running)) ==
          "running");
    CHECK(std::string(list_refresh_task_status_name(ListRefreshTaskStatus::Applying)) ==
          "applying");
    CHECK(std::string(list_refresh_task_status_name(ListRefreshTaskStatus::Succeeded)) ==
          "succeeded");
    CHECK(std::string(list_refresh_task_status_name(ListRefreshTaskStatus::Failed)) ==
          "failed");
    CHECK(std::string(list_refresh_task_status_name(ListRefreshTaskStatus::Cancelled)) ==
          "cancelled");
}
