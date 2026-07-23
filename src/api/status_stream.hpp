#pragma once

#ifdef WITH_API

#include "generated/api_types.hpp"
#include "sse_broadcaster.hpp"

#include "../util/traced_mutex.hpp"

#include <functional>
#include <string>

namespace keen_pbr3 {

using StatusSnapshot = api::RuntimeInventoryResponse;

class StatusStream {
public:
    using SnapshotBuilder = std::function<StatusSnapshot()>;

    explicit StatusStream(SnapshotBuilder builder,
                          size_t max_queue_size = 128,
                          size_t max_subscriptions = 4);

    SseBroadcaster::SubscriptionPtr subscribe();
    void unsubscribe(const SseBroadcaster::SubscriptionPtr& subscription);
    void reconcile();
    void publish_connections(api::ConnectionEventState state);
    void close_all();

private:
    SnapshotBuilder builder_;
    SseBroadcaster broadcaster_;
    TracedMutex mutex_;
    std::string service_ GUARDED_BY(mutex_);
    std::string outbounds_ GUARDED_BY(mutex_);
    std::string interfaces_ GUARDED_BY(mutex_);
    api::ConnectionEventState connections_state_ GUARDED_BY(mutex_);
    std::string connections_ GUARDED_BY(mutex_);
    bool connections_initialized_ GUARDED_BY(mutex_){false};
    bool initialized_ GUARDED_BY(mutex_){false};
};

std::string make_named_sse_frame(const std::string& event,
                                 const std::string& payload);

} // namespace keen_pbr3

#endif
