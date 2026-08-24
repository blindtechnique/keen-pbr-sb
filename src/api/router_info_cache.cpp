#include "router_info_cache.hpp"

#include <utility>

namespace keen_pbr3 {

namespace {

// Once a thread owns publication, every exit path must release cold waiters.
// In particular, nlohmann::json assignment/copy may allocate and throw.
class RefreshTerminalGuard {
public:
    RefreshTerminalGuard(std::unique_lock<std::mutex>& lock,
                         bool& refreshing,
                         std::condition_variable& refresh_finished)
        : lock_(lock)
        , refreshing_(refreshing)
        , refresh_finished_(refresh_finished) {}

    ~RefreshTerminalGuard() {
        refreshing_ = false;
        if (lock_.owns_lock()) {
            lock_.unlock();
        }
        refresh_finished_.notify_all();
    }

private:
    std::unique_lock<std::mutex>& lock_;
    bool& refreshing_;
    std::condition_variable& refresh_finished_;
};

} // namespace

RouterInfoCache::RouterInfoCache(FetchFn fetch,
                                 Clock::duration ttl,
                                 Clock::duration failure_retry,
                                 NowFn now)
    : fetch_(std::move(fetch))
    , ttl_(ttl)
    , failure_retry_(failure_retry)
    , now_(std::move(now)) {
    if (!now_) {
        now_ = [] { return Clock::now(); };
    }
}

nlohmann::json RouterInfoCache::response_locked() const {
    if (last_good_.has_value()) {
        return *last_good_;
    }
    if (last_failed_.has_value()) {
        return *last_failed_;
    }
    return nlohmann::json::object();
}

nlohmann::json RouterInfoCache::get() {
    for (;;) {
        Clock::time_point attempt_started;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            const auto now = now_();
            if (last_good_.has_value() && now < refresh_after_) {
                return *last_good_;
            }
            if (now < retry_after_) {
                return response_locked();
            }
            if (refreshing_) {
                if (last_good_.has_value()) {
                    // Stale-while-refresh: an overview request must not wait
                    // behind another request's RCI/network fan-out.
                    return *last_good_;
                }
                if (last_failed_.has_value()) {
                    // A failed cold result is also stale-while-refresh data.
                    // Only the process's first-ever fetch has no prior value.
                    return *last_failed_;
                }
                // There is nothing to return on the first-ever cold load.
                // Wait without the mutex and reuse the exact first result.
                refresh_finished_.wait(
                    lock, [this] { return !refreshing_; });
                continue;
            }
            refreshing_ = true;
            attempt_started = now;
        }

        FetchResult refreshed;
        try {
            // This is the only callback that may perform RCI/network I/O, and
            // it is deliberately outside the cache mutex.
            refreshed = fetch_();
        } catch (...) {
            refreshed.value = nlohmann::json::object();
            refreshed.success = false;
        }
        auto completed_at = attempt_started;
        try {
            completed_at = now_();
        } catch (...) {
            // The production clock is noexcept in practice. An injected clock
            // must still never strand refreshing_ or its cold waiters.
        }

        std::unique_lock<std::mutex> lock(mutex_);
        RefreshTerminalGuard terminal(
            lock, refreshing_, refresh_finished_);
        if (refreshed.success) {
            last_good_ = std::move(refreshed.value);
            last_failed_.reset();
            refresh_after_ = completed_at + ttl_;
            retry_after_ = Clock::time_point::min();
        } else {
            // Never replace an accepted snapshot with a partial failure.
            // A cold caller still receives the same bounded diagnostic value
            // that the old uncached implementation would have returned.
            last_failed_ = std::move(refreshed.value);
            retry_after_ = completed_at + failure_retry_;
        }
        return response_locked();
    }
}

} // namespace keen_pbr3
