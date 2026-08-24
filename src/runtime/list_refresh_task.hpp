#pragma once

#include "../daemon/list_service.hpp"
#include "../util/traced_mutex.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class ListRefreshTaskStatus : std::uint8_t {
    Queued,
    Running,
    Applying,
    Succeeded,
    Failed,
    Cancelled,
};

struct ListRefreshTaskTerminalResult {
    RemoteListsRefreshResult refresh_result;
    bool reloaded{false};
    std::string error;
};

struct ListRefreshTaskSnapshot {
    std::string id;
    ListRefreshTaskStatus status{ListRefreshTaskStatus::Queued};
    std::int64_t created_at{0};
    std::int64_t updated_at{0};
    std::optional<std::int64_t> started_at;
    std::optional<std::int64_t> finished_at;
    std::size_t total{0};
    std::size_t completed{0};
    std::optional<std::string> current;
    bool cancel_requested{false};
    std::optional<ListRefreshTaskTerminalResult> terminal_result;
    std::uint64_t revision{0};
};

class ListRefreshCancellationToken {
public:
    ListRefreshCancellationToken() = default;
    bool valid() const noexcept;
    bool cancellation_requested() const noexcept;
    std::shared_ptr<const std::atomic<bool>> shared_flag() const noexcept;

private:
    explicit ListRefreshCancellationToken(
        std::shared_ptr<std::atomic<bool>> cancellation_flag);

    std::shared_ptr<std::atomic<bool>> cancellation_flag_;

    friend class ListRefreshTaskCoordinator;
};

struct ListRefreshTaskBeginResult {
    bool accepted{false};
    bool coalesced{false};
    ListRefreshTaskSnapshot task;
    ListRefreshCancellationToken cancellation;
};

class ListRefreshTaskCoordinator {
public:
    using Clock = std::function<std::int64_t()>;
    using PublishCallback = std::function<void(const ListRefreshTaskSnapshot&)>;

    explicit ListRefreshTaskCoordinator(std::size_t terminal_history_limit = 8,
                                        Clock clock = {});

    // Retains the admitted operation lifetime until terminal publication (or
    // queued cancellation). The daemon uses this to keep its exact runtime
    // mutation lease across worker refresh, control-loop apply/rollback and
    // final task publication without a second ownership mechanism. A
    // `upgrade_active` can atomically attach a reload to an active read-only
    // task. `force_new` carries the same durable reconcile obligation when a
    // deferred retry starts only after that original task has terminalized.
    ListRefreshTaskBeginResult begin(
        std::size_t total,
        std::shared_ptr<void> operation_lifetime = {},
        bool upgrade_active = false,
        bool force_new = false);
    bool mark_running(const std::string& id,
                      std::optional<std::string> current = std::nullopt);
    bool update_progress(const std::string& id,
                         std::size_t completed,
                         std::optional<std::string> current = std::nullopt);
    bool mark_applying(const std::string& id);
    bool request_cancel(const std::string& id);
    bool request_cancel_active();

    bool succeed(const std::string& id,
                 RemoteListsRefreshResult refresh_result,
                 bool reloaded);
    bool fail(const std::string& id,
              std::string error,
              RemoteListsRefreshResult refresh_result = {},
              bool reloaded = false);
    bool finish_cancelled(const std::string& id,
                          std::string error = {},
                          RemoteListsRefreshResult refresh_result = {},
                          bool reloaded = false);

    std::optional<ListRefreshTaskSnapshot> active() const;
    bool force_reconcile_requested(const std::string& id) const;
    std::optional<ListRefreshTaskSnapshot> find(const std::string& id) const;
    std::vector<ListRefreshTaskSnapshot> terminal_history() const;
    void set_publish_callback(PublishCallback callback);

private:
    struct ActiveTask {
        ListRefreshTaskSnapshot snapshot;
        std::shared_ptr<std::atomic<bool>> cancellation_flag;
        std::shared_ptr<void> operation_lifetime;
        bool force_reconcile{false};
    };

    bool mutate_active(
        const std::string& id,
        const std::function<bool(ListRefreshTaskSnapshot&)>& mutation);
    bool finish(const std::string& id,
                ListRefreshTaskStatus status,
                ListRefreshTaskTerminalResult terminal_result);
    std::int64_t now() const;
    static void publish_noexcept(const PublishCallback& callback,
                                 const ListRefreshTaskSnapshot& snapshot) noexcept;

    const std::size_t terminal_history_limit_;
    Clock clock_;
    mutable TracedMutex mutex_;
    std::optional<ActiveTask> active_ GUARDED_BY(mutex_);
    std::deque<ListRefreshTaskSnapshot> terminal_history_ GUARDED_BY(mutex_);
    PublishCallback publish_callback_ GUARDED_BY(mutex_);
    std::uint64_t sequence_ GUARDED_BY(mutex_){0};
};

bool list_refresh_task_status_is_terminal(ListRefreshTaskStatus status);
const char* list_refresh_task_status_name(ListRefreshTaskStatus status);

inline bool should_reconcile_committed_list_cache(
    bool reload_requested,
    bool force_reconcile,
    bool runtime_active,
    bool cache_changed) noexcept {
    return runtime_active &&
           (force_reconcile || (reload_requested && cache_changed));
}

inline bool merge_list_refresh_force_reconcile(
    bool retained,
    bool incoming) noexcept {
    return retained || incoming;
}

// Returns true when shutdown owns terminalization and the caller must not
// mutate DNS/firewall/runtime state. A refresh may already have committed
// cache files; preserve that partial result for diagnostics and next startup.
bool finish_list_refresh_if_shutting_down(
    bool accepting_control_tasks,
    ListRefreshTaskCoordinator& coordinator,
    const std::string& id,
    const std::optional<RemoteListsRefreshResult>& refresh_result);

} // namespace keen_pbr3
