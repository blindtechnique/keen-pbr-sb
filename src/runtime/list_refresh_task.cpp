#include "list_refresh_task.hpp"

#include <algorithm>
#include <ctime>
#include <utility>

namespace keen_pbr3 {

namespace {

std::int64_t system_time_seconds() {
    return static_cast<std::int64_t>(std::time(nullptr));
}

} // namespace

bool list_refresh_task_status_is_terminal(ListRefreshTaskStatus status) {
    switch (status) {
    case ListRefreshTaskStatus::Succeeded:
    case ListRefreshTaskStatus::Failed:
    case ListRefreshTaskStatus::Cancelled:
        return true;
    case ListRefreshTaskStatus::Queued:
    case ListRefreshTaskStatus::Running:
    case ListRefreshTaskStatus::Applying:
        return false;
    }
    return false;
}

const char* list_refresh_task_status_name(ListRefreshTaskStatus status) {
    switch (status) {
    case ListRefreshTaskStatus::Queued: return "queued";
    case ListRefreshTaskStatus::Running: return "running";
    case ListRefreshTaskStatus::Applying: return "applying";
    case ListRefreshTaskStatus::Succeeded: return "succeeded";
    case ListRefreshTaskStatus::Failed: return "failed";
    case ListRefreshTaskStatus::Cancelled: return "cancelled";
    }
    return "queued";
}

bool finish_list_refresh_if_shutting_down(
    bool accepting_control_tasks,
    ListRefreshTaskCoordinator& coordinator,
    const std::string& id,
    const std::optional<RemoteListsRefreshResult>& refresh_result) {
    if (accepting_control_tasks) return false;

    (void)coordinator.finish_cancelled(
        id,
        "daemon is shutting down",
        refresh_result.value_or(RemoteListsRefreshResult{}));
    return true;
}

ListRefreshCancellationToken::ListRefreshCancellationToken(
    std::shared_ptr<std::atomic<bool>> cancellation_flag)
    : cancellation_flag_(std::move(cancellation_flag)) {}

bool ListRefreshCancellationToken::valid() const noexcept {
    return static_cast<bool>(cancellation_flag_);
}

bool ListRefreshCancellationToken::cancellation_requested() const noexcept {
    return cancellation_flag_ &&
           cancellation_flag_->load(std::memory_order_acquire);
}

std::shared_ptr<const std::atomic<bool>>
ListRefreshCancellationToken::shared_flag() const noexcept {
    return cancellation_flag_;
}

ListRefreshTaskCoordinator::ListRefreshTaskCoordinator(
    std::size_t terminal_history_limit, Clock clock)
    : terminal_history_limit_(std::max<std::size_t>(1, terminal_history_limit)),
      clock_(clock ? std::move(clock) : Clock(system_time_seconds)) {}

std::int64_t ListRefreshTaskCoordinator::now() const {
    return clock_();
}

void ListRefreshTaskCoordinator::publish_noexcept(
    const PublishCallback& callback,
    const ListRefreshTaskSnapshot& snapshot) noexcept {
    if (!callback) return;
    try {
        callback(snapshot);
    } catch (...) {
        // Status observers are deliberately best-effort. A failed observer
        // must never strand the single-flight task in an active state.
    }
}

ListRefreshTaskBeginResult ListRefreshTaskCoordinator::begin(
    std::size_t total,
    std::optional<RuntimeMutationLeaseHandoff> mutation_lease,
    bool upgrade_active,
    bool force_new) {
    ListRefreshTaskBeginResult result;
    PublishCallback callback;
    {
        KPBR_LOCK_GUARD(mutex_);
        if (active_) {
            result.task = active_->snapshot;
            if (upgrade_active && mutation_lease &&
                mutation_lease->state() ==
                    RuntimeMutationLeaseHandoffState::Ready &&
                !active_->mutation_lease &&
                !active_->snapshot.cancel_requested &&
                (active_->snapshot.status == ListRefreshTaskStatus::Queued ||
                 active_->snapshot.status == ListRefreshTaskStatus::Running)) {
                // Upgrade the exact in-flight read-only task atomically. The
                // worker may already have committed cache data, so the lease
                // and force-reconcile bit must become visible together before
                // terminalization can observe either one.
                active_->mutation_lease = std::move(mutation_lease);
                active_->force_reconcile = true;
                result.accepted = true;
                result.coalesced = true;
                result.cancellation = ListRefreshCancellationToken(
                    active_->cancellation_flag);
            }
            return result;
        }

        if (mutation_lease &&
            mutation_lease->state() !=
                RuntimeMutationLeaseHandoffState::Ready) {
            return result;
        }

        const auto timestamp = now();
        auto cancellation_flag = std::make_shared<std::atomic<bool>>(false);
        ListRefreshTaskSnapshot snapshot;
        snapshot.id = "list-refresh-" + std::to_string(timestamp) + "-" +
                      std::to_string(++sequence_);
        snapshot.status = ListRefreshTaskStatus::Queued;
        snapshot.created_at = timestamp;
        snapshot.updated_at = timestamp;
        snapshot.total = total;
        snapshot.revision = 1;

        active_ = ActiveTask{
            snapshot,
            cancellation_flag,
            std::move(mutation_lease),
            force_new};
        callback = publish_callback_;
        result.accepted = true;
        result.task = std::move(snapshot);
        result.cancellation =
            ListRefreshCancellationToken(std::move(cancellation_flag));
    }
    publish_noexcept(callback, result.task);
    return result;
}

bool ListRefreshTaskCoordinator::mutate_active(
    const std::string& id,
    const std::function<bool(ListRefreshTaskSnapshot&)>& mutation) {
    ListRefreshTaskSnapshot published;
    PublishCallback callback;
    {
        KPBR_LOCK_GUARD(mutex_);
        if (!active_ || active_->snapshot.id != id ||
            !mutation(active_->snapshot)) {
            return false;
        }
        active_->snapshot.updated_at = now();
        ++active_->snapshot.revision;
        published = active_->snapshot;
        callback = publish_callback_;
    }
    publish_noexcept(callback, published);
    return true;
}

bool ListRefreshTaskCoordinator::mark_running(
    const std::string& id, std::optional<std::string> current) {
    return mutate_active(id, [&](ListRefreshTaskSnapshot& snapshot) {
        if (snapshot.status != ListRefreshTaskStatus::Queued) return false;
        snapshot.status = ListRefreshTaskStatus::Running;
        snapshot.started_at = now();
        snapshot.current = std::move(current);
        return true;
    });
}

bool ListRefreshTaskCoordinator::update_progress(
    const std::string& id,
    std::size_t completed,
    std::optional<std::string> current) {
    return mutate_active(id, [&](ListRefreshTaskSnapshot& snapshot) {
        if (snapshot.status != ListRefreshTaskStatus::Running ||
            completed < snapshot.completed || completed > snapshot.total) {
            return false;
        }
        snapshot.completed = completed;
        snapshot.current = std::move(current);
        return true;
    });
}

bool ListRefreshTaskCoordinator::mark_applying(const std::string& id) {
    return mutate_active(id, [](ListRefreshTaskSnapshot& snapshot) {
        if (snapshot.status != ListRefreshTaskStatus::Running ||
            snapshot.cancel_requested) {
            return false;
        }
        snapshot.status = ListRefreshTaskStatus::Applying;
        snapshot.current.reset();
        return true;
    });
}

ListRefreshMutationLeaseTakeResult
ListRefreshTaskCoordinator::take_mutation_lease(const std::string& id) {
    KPBR_LOCK_GUARD(mutex_);
    if (!active_ || active_->snapshot.id != id) {
        return {ListRefreshMutationLeaseTakeStatus::TaskNotActive, {}};
    }
    if (active_->snapshot.status == ListRefreshTaskStatus::Queued) {
        return {ListRefreshMutationLeaseTakeStatus::TaskNotReady, {}};
    }
    if (!active_->mutation_lease) {
        return {ListRefreshMutationLeaseTakeStatus::NoLease, {}};
    }

    auto taken = active_->mutation_lease->take();
    switch (taken.status) {
    case RuntimeMutationLeaseTakeStatus::Acquired:
        return {ListRefreshMutationLeaseTakeStatus::Acquired,
                std::move(taken.lease)};
    case RuntimeMutationLeaseTakeStatus::Empty:
        return {ListRefreshMutationLeaseTakeStatus::NoLease, {}};
    case RuntimeMutationLeaseTakeStatus::AlreadyTaken:
        return {ListRefreshMutationLeaseTakeStatus::AlreadyTaken, {}};
    case RuntimeMutationLeaseTakeStatus::Invalid:
        return {ListRefreshMutationLeaseTakeStatus::Invalid, {}};
    }
    return {ListRefreshMutationLeaseTakeStatus::Invalid, {}};
}

bool ListRefreshTaskCoordinator::request_cancel(const std::string& id) {
    ListRefreshTaskSnapshot published;
    PublishCallback callback;
    std::unique_ptr<RuntimeMutationAdmission::Lease> mutation_lease;
    {
        KPBR_LOCK_GUARD(mutex_);
        if (!active_ || active_->snapshot.id != id ||
            (active_->snapshot.status != ListRefreshTaskStatus::Queued &&
             active_->snapshot.status != ListRefreshTaskStatus::Running)) {
            return false;
        }
        active_->cancellation_flag->store(true, std::memory_order_release);
        if (active_->snapshot.cancel_requested) return true;
        active_->snapshot.cancel_requested = true;
        const auto timestamp = now();
        active_->snapshot.updated_at = timestamp;

        // A queued task has not acquired any external resources yet. Finish it
        // immediately so it cannot occupy the single-flight slot while the
        // executor is busy. A worker which eventually reaches this item will
        // simply fail mark_running() and return.
        if (active_->snapshot.status == ListRefreshTaskStatus::Queued) {
            active_->snapshot.status = ListRefreshTaskStatus::Cancelled;
            active_->snapshot.finished_at = timestamp;
            active_->snapshot.terminal_result = ListRefreshTaskTerminalResult{
                {}, false, "list refresh cancelled before execution"};
        }
        ++active_->snapshot.revision;
        published = active_->snapshot;
        callback = publish_callback_;

        if (published.status == ListRefreshTaskStatus::Cancelled) {
            terminal_history_.push_front(published);
            while (terminal_history_.size() > terminal_history_limit_) {
                terminal_history_.pop_back();
            }
            if (active_->mutation_lease) {
                auto taken = active_->mutation_lease->take();
                mutation_lease = std::move(taken.lease);
            }
            active_.reset();
        }
    }
    publish_noexcept(callback, published);
    (void)mutation_lease;
    return true;
}

bool ListRefreshTaskCoordinator::request_cancel_active() {
    std::optional<std::string> id;
    {
        KPBR_LOCK_GUARD(mutex_);
        if (active_) id = active_->snapshot.id;
    }
    return id && request_cancel(*id);
}

bool ListRefreshTaskCoordinator::finish(
    const std::string& id,
    ListRefreshTaskStatus status,
    ListRefreshTaskTerminalResult terminal_result) {
    if (!list_refresh_task_status_is_terminal(status)) return false;

    ListRefreshTaskSnapshot published;
    PublishCallback callback;
    std::unique_ptr<RuntimeMutationAdmission::Lease> mutation_lease;
    {
        KPBR_LOCK_GUARD(mutex_);
        if (!active_ || active_->snapshot.id != id) return false;

        auto& snapshot = active_->snapshot;
        if (list_refresh_task_status_is_terminal(snapshot.status)) return false;
        if (status == ListRefreshTaskStatus::Succeeded &&
            snapshot.status != ListRefreshTaskStatus::Running &&
            snapshot.status != ListRefreshTaskStatus::Applying) {
            return false;
        }
        if (status == ListRefreshTaskStatus::Cancelled &&
            snapshot.status != ListRefreshTaskStatus::Queued &&
            snapshot.status != ListRefreshTaskStatus::Running &&
            !(snapshot.status == ListRefreshTaskStatus::Applying &&
              snapshot.cancel_requested)) {
            return false;
        }

        const auto timestamp = now();
        snapshot.status = status;
        snapshot.current.reset();
        snapshot.updated_at = timestamp;
        snapshot.finished_at = timestamp;
        snapshot.terminal_result = std::move(terminal_result);
        if (status == ListRefreshTaskStatus::Cancelled) {
            snapshot.cancel_requested = true;
            active_->cancellation_flag->store(true, std::memory_order_release);
        }
        ++snapshot.revision;
        published = snapshot;
        callback = publish_callback_;

        terminal_history_.push_front(snapshot);
        while (terminal_history_.size() > terminal_history_limit_) {
            terminal_history_.pop_back();
        }
        if (active_->mutation_lease) {
            auto taken = active_->mutation_lease->take();
            mutation_lease = std::move(taken.lease);
        }
        active_.reset();
    }
    publish_noexcept(callback, published);
    (void)mutation_lease;
    return true;
}

bool ListRefreshTaskCoordinator::succeed(
    const std::string& id,
    RemoteListsRefreshResult refresh_result,
    bool reloaded) {
    return finish(id,
                  ListRefreshTaskStatus::Succeeded,
                  {std::move(refresh_result), reloaded, {}});
}

bool ListRefreshTaskCoordinator::fail(
    const std::string& id,
    std::string error,
    RemoteListsRefreshResult refresh_result,
    bool reloaded) {
    return finish(id,
                  ListRefreshTaskStatus::Failed,
                  {std::move(refresh_result), reloaded, std::move(error)});
}

bool ListRefreshTaskCoordinator::finish_cancelled(
    const std::string& id,
    std::string error,
    RemoteListsRefreshResult refresh_result,
    bool reloaded) {
    return finish(id,
                  ListRefreshTaskStatus::Cancelled,
                  {std::move(refresh_result), reloaded, std::move(error)});
}

std::optional<ListRefreshTaskSnapshot> ListRefreshTaskCoordinator::active() const {
    KPBR_LOCK_GUARD(mutex_);
    if (!active_) return std::nullopt;
    return active_->snapshot;
}

bool ListRefreshTaskCoordinator::force_reconcile_requested(
    const std::string& id) const {
    KPBR_LOCK_GUARD(mutex_);
    return active_ && active_->snapshot.id == id &&
           active_->force_reconcile;
}

std::optional<ListRefreshTaskSnapshot> ListRefreshTaskCoordinator::find(
    const std::string& id) const {
    KPBR_LOCK_GUARD(mutex_);
    if (active_ && active_->snapshot.id == id) return active_->snapshot;
    const auto it = std::find_if(
        terminal_history_.begin(),
        terminal_history_.end(),
        [&](const auto& snapshot) { return snapshot.id == id; });
    if (it == terminal_history_.end()) return std::nullopt;
    return *it;
}

std::vector<ListRefreshTaskSnapshot>
ListRefreshTaskCoordinator::terminal_history() const {
    KPBR_LOCK_GUARD(mutex_);
    return {terminal_history_.begin(), terminal_history_.end()};
}

void ListRefreshTaskCoordinator::set_publish_callback(PublishCallback callback) {
    KPBR_LOCK_GUARD(mutex_);
    publish_callback_ = std::move(callback);
}

} // namespace keen_pbr3
