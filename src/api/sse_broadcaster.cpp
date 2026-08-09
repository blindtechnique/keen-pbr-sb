#ifdef WITH_API

#include "sse_broadcaster.hpp"

#include "../log/logger.hpp"

#include <algorithm>

namespace keen_pbr3 {

SseBroadcaster::SseBroadcaster(size_t max_queue_size,
                               size_t max_subscriptions)
    : max_queue_size_(max_queue_size)
    , max_subscriptions_(max_subscriptions) {}

SseBroadcaster::SubscriptionPtr SseBroadcaster::subscribe() {
    return subscribe({});
}

SseBroadcaster::SubscriptionPtr SseBroadcaster::subscribe(
    std::vector<std::string> initial_messages) {
    auto subscription = std::make_shared<Subscription>();
    {
        KPBR_UNIQUE_LOCK(sub_lock, subscription->mutex);
        subscription->messages.insert(
            subscription->messages.end(),
            std::make_move_iterator(initial_messages.begin()),
            std::make_move_iterator(initial_messages.end()));
    }
    KPBR_LOCK_GUARD(mutex_);
    if (admission_closed_) {
        Logger::instance().trace("sse_subscribe_rejected", "reason=closed");
        return nullptr;
    }
    compact_locked();
    if (subscriptions_.size() >= max_subscriptions_) {
        // Admission control is working as intended here.  The caller returns
        // HTTP 503/Retry-After to the rejected client, while an operator-facing
        // warning would incorrectly turn a busy/reloading browser into a
        // system incident in the notification bell.
        Logger::instance().info(
            "Rejecting SSE subscription: active={} limit={}",
            subscriptions_.size(),
            max_subscriptions_);
        return nullptr;
    }
    subscriptions_.push_back(subscription);
    Logger::instance().trace("sse_subscribe", "subscriptions={}", subscriptions_.size());
    return subscription;
}

void SseBroadcaster::unsubscribe(const SubscriptionPtr& subscription) {
    if (!subscription) {
        return;
    }

    {
        KPBR_UNIQUE_LOCK(sub_lock, subscription->mutex);
        subscription->closed = true;
    }
    subscription->cv.notify_all();

    KPBR_LOCK_GUARD(mutex_);
    compact_locked();
    Logger::instance().trace("sse_unsubscribe", "subscriptions={}", subscriptions_.size());
}

void SseBroadcaster::publish(const std::string& message) {
    KPBR_LOCK_GUARD(mutex_);
    Logger::instance().trace("sse_publish", "subscriptions={} bytes={}", subscriptions_.size(), message.size());

    auto out = subscriptions_.begin();
    for (auto it = subscriptions_.begin(); it != subscriptions_.end(); ++it) {
        auto subscription = it->lock();
        if (!subscription) {
            continue;
        }

        bool keep = true;
        {
            KPBR_UNIQUE_LOCK(sub_lock, subscription->mutex);
            if (subscription->closed) {
                keep = false;
            } else if (subscription->messages.size() >= max_queue_size_) {
                subscription->closed = true;
                keep = false;
            } else {
                subscription->messages.push_back(message);
            }
        }
        subscription->cv.notify_all();

        if (keep) {
            *out++ = *it;
        }
    }
    subscriptions_.erase(out, subscriptions_.end());
}

void SseBroadcaster::close_all() {
    std::vector<SubscriptionPtr> active;
    {
        KPBR_LOCK_GUARD(mutex_);
        admission_closed_ = true;
        for (auto& weak : subscriptions_) {
            if (auto subscription = weak.lock()) {
                active.push_back(std::move(subscription));
            }
        }
        subscriptions_.clear();
    }

    for (auto& subscription : active) {
        {
            KPBR_UNIQUE_LOCK(sub_lock, subscription->mutex);
            subscription->closed = true;
        }
        subscription->cv.notify_all();
    }
    Logger::instance().trace("sse_close_all", "closed={}", active.size());
}

size_t SseBroadcaster::active_subscriptions() {
    KPBR_LOCK_GUARD(mutex_);
    compact_locked();
    return subscriptions_.size();
}

void SseBroadcaster::compact_locked() {
    auto out = subscriptions_.begin();
    for (auto it = subscriptions_.begin(); it != subscriptions_.end(); ++it) {
        auto subscription = it->lock();
        if (!subscription) {
            continue;
        }

        KPBR_UNIQUE_LOCK(sub_lock, subscription->mutex);
        if (subscription->closed) {
            continue;
        }

        *out++ = *it;
    }
    subscriptions_.erase(out, subscriptions_.end());
}

SseSubscriptionWaitResult wait_for_sse_subscription(
    const SseBroadcaster::SubscriptionPtr& subscription,
    std::chrono::milliseconds heartbeat_interval,
    std::chrono::milliseconds peer_probe_interval,
    const std::function<bool()>& peer_is_writable) {
    using Clock = std::chrono::steady_clock;

    const auto started_at = Clock::now();
    const auto heartbeat_deadline =
        started_at +
        std::max(heartbeat_interval, std::chrono::milliseconds::zero());
    const auto probe_interval =
        std::max(peer_probe_interval, std::chrono::milliseconds::zero());
    auto next_probe_at =
        peer_is_writable
            ? started_at + probe_interval
            : heartbeat_deadline;

    const auto inspect_subscription = [&]() -> SseSubscriptionWaitResult {
        KPBR_UNIQUE_LOCK(lock, subscription->mutex);
        if (!subscription->messages.empty()) {
            auto message = std::move(subscription->messages.front());
            subscription->messages.pop_front();
            return {SseSubscriptionWaitStatus::MESSAGE, std::move(message)};
        }
        if (subscription->closed) {
            return {SseSubscriptionWaitStatus::CLOSED, {}};
        }
        return {SseSubscriptionWaitStatus::HEARTBEAT, {}};
    };

    while (true) {
        {
            KPBR_UNIQUE_LOCK(lock, subscription->mutex);
            if (!subscription->messages.empty()) {
                auto message = std::move(subscription->messages.front());
                subscription->messages.pop_front();
                return {SseSubscriptionWaitStatus::MESSAGE, std::move(message)};
            }
            if (subscription->closed) {
                return {SseSubscriptionWaitStatus::CLOSED, {}};
            }

            const auto now = Clock::now();
            if (now >= heartbeat_deadline) {
                return {SseSubscriptionWaitStatus::HEARTBEAT, {}};
            }

            const auto wake_at = std::min(heartbeat_deadline, next_probe_at);
            // The publisher and close path mutate the guarded state while
            // holding the same mutex, then notify this condition variable.
            // A plain wait keeps the unlock-and-block transition atomic and
            // lets the guarded checks below stay in the lock-aware scope.
            const auto wait_status =
                subscription->cv.wait_until(lock, wake_at);

            if (!subscription->messages.empty() || subscription->closed) {
                continue;
            }
            if (Clock::now() >= heartbeat_deadline) {
                return {SseSubscriptionWaitStatus::HEARTBEAT, {}};
            }
            if (wait_status == std::cv_status::no_timeout) {
                // Preserve predicate-wait semantics: an unrelated or
                // spurious notification must not run the peer probe early.
                continue;
            }
        }

        // Transport inspection may call into the socket implementation. It
        // must never run under Subscription::mutex because publish/close need
        // that mutex to wake this waiter.
        const bool peer_writable = !peer_is_writable || peer_is_writable();

        // A publish or close may have raced with the probe. Prefer that
        // authoritative subscription state over the transport result.
        auto current = inspect_subscription();
        if (current.status != SseSubscriptionWaitStatus::HEARTBEAT) {
            return current;
        }
        if (!peer_writable) {
            return {SseSubscriptionWaitStatus::PEER_DISCONNECTED, {}};
        }

        const auto now = Clock::now();
        if (now >= heartbeat_deadline) {
            return {SseSubscriptionWaitStatus::HEARTBEAT, {}};
        }
        // A zero probe interval is useful for deterministic one-shot tests,
        // but a successful probe must not turn into a busy loop.
        next_probe_at = probe_interval > std::chrono::milliseconds::zero()
                            ? now + probe_interval
                            : heartbeat_deadline;
    }
}

} // namespace keen_pbr3

#endif // WITH_API
