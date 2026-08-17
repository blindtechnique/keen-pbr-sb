#pragma once

#ifdef WITH_API

#include "../util/traced_mutex.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace keen_pbr3 {

class SseBroadcaster {
public:
    struct Subscription {
        TracedMutex mutex;
        std::condition_variable_any cv;
        std::deque<std::string> messages GUARDED_BY(mutex);
        bool closed GUARDED_BY(mutex){false};
    };

    using SubscriptionPtr = std::shared_ptr<Subscription>;

    explicit SseBroadcaster(size_t max_queue_size = 128,
                            size_t max_subscriptions = 4);

    SubscriptionPtr subscribe();
    SubscriptionPtr subscribe(std::vector<std::string> initial_messages);
    void unsubscribe(const SubscriptionPtr& subscription);
    void publish(const std::string& message);
    // Revokes the current cohort while keeping admission open for clients
    // authenticated under the next session epoch.
    void revoke_active_subscriptions();
    void close_all();
    size_t active_subscriptions();

private:
    void close_subscriptions(bool close_admission, bool purge_messages);
    void compact_locked() REQUIRES(mutex_);

    size_t max_queue_size_;
    size_t max_subscriptions_;
    TracedMutex mutex_;
    std::vector<std::weak_ptr<Subscription>> subscriptions_ GUARDED_BY(mutex_);
    bool admission_closed_ GUARDED_BY(mutex_){false};
};

enum class SseSubscriptionWaitStatus {
    MESSAGE,
    HEARTBEAT,
    CLOSED,
    PEER_DISCONNECTED,
};

struct SseSubscriptionWaitResult {
    SseSubscriptionWaitStatus status{SseSubscriptionWaitStatus::HEARTBEAT};
    std::string message;
};

// Waits for queued SSE data without making the transport part of the
// broadcaster. The peer probe is deliberately invoked without holding the
// subscription mutex, then the queue and closed flag are checked again so a
// concurrent publish/close cannot be lost while the transport is inspected.
SseSubscriptionWaitResult wait_for_sse_subscription(
    const SseBroadcaster::SubscriptionPtr& subscription,
    std::chrono::milliseconds heartbeat_interval,
    std::chrono::milliseconds peer_probe_interval,
    const std::function<bool()>& peer_is_writable = {},
    const std::function<bool()>& authorization_is_current = {});

} // namespace keen_pbr3

#endif // WITH_API
