#include <doctest/doctest.h>

#include "runtime/list_refresh_task.hpp"

#include <stdexcept>
#include <string>
#include <vector>

using namespace keen_pbr3;

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
    const auto started = coordinator.begin(1);
    REQUIRE(started.accepted);

    REQUIRE(coordinator.request_cancel(started.task.id));
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
