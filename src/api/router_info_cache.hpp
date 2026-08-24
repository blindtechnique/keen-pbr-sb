#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>

namespace keen_pbr3 {

// Small cache for the router overview's RCI fan-out. The fetch callback is
// always called without mutex_ held: one request performs the refresh while
// concurrent readers keep receiving the last known-good snapshot.
class RouterInfoCache {
public:
    using Clock = std::chrono::steady_clock;

    struct FetchResult {
        nlohmann::json value;
        bool success{false};
    };

    using FetchFn = std::function<FetchResult()>;
    using NowFn = std::function<Clock::time_point()>;

    RouterInfoCache(FetchFn fetch,
                    Clock::duration ttl,
                    Clock::duration failure_retry,
                    NowFn now = {});

    nlohmann::json get();

private:
    nlohmann::json response_locked() const;

    FetchFn fetch_;
    Clock::duration ttl_;
    Clock::duration failure_retry_;
    NowFn now_;

    mutable std::mutex mutex_;
    std::condition_variable refresh_finished_;
    std::optional<nlohmann::json> last_good_;
    std::optional<nlohmann::json> last_failed_;
    Clock::time_point refresh_after_{Clock::time_point::min()};
    Clock::time_point retry_after_{Clock::time_point::min()};
    bool refreshing_{false};
};

} // namespace keen_pbr3
