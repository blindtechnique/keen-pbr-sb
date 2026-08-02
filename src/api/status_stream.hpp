#pragma once

#ifdef WITH_API

#include "generated/api_types.hpp"
#include "sse_broadcaster.hpp"

#include "../util/traced_mutex.hpp"

#include <functional>
#include <nlohmann/json.hpp>
#include <string>

namespace keen_pbr3 {

using StatusSnapshot = api::RuntimeInventoryResponse;

class StatusStream {
public:
    using SnapshotBuilder = std::function<StatusSnapshot()>;

    explicit StatusStream(SnapshotBuilder builder,
                          size_t max_queue_size = 32,
                          size_t max_subscriptions = 8);

    SseBroadcaster::SubscriptionPtr subscribe();
    void unsubscribe(const SseBroadcaster::SubscriptionPtr& subscription);
    void reconcile();
    void publish_interfaces(api::RuntimeInterfaceInventoryResponse state);
    // High-frequency interface counters are deliberately kept out of the
    // cached full inventory. The caller supplies a compact JSON object whose
    // schema is owned by the status stream rather than the REST OpenAPI model.
    void publish_interface_traffic(nlohmann::json state);
    void publish_connections(api::ConnectionEventState state);
    // Interactive DNS checks reuse the application-wide status stream.  A
    // separate EventSource per check used to leave short-lived subscriptions
    // behind until cpp-httplib observed the closed socket, exhausting the
    // small diagnostic broadcaster during reloads and quick rechecks.
    void publish_dns_probe(nlohmann::json state);
    // List downloads are long-lived background operations. Keep their latest
    // opaque task snapshot on the shared status stream so a reconnecting WebUI
    // can immediately resume progress rendering without another poller.
    void publish_list_refresh(nlohmann::json state);
    void close_all();
    bool has_subscribers();

private:
    SnapshotBuilder builder_;
    SseBroadcaster broadcaster_;
    TracedMutex mutex_;
    nlohmann::json service_ GUARDED_BY(mutex_);
    nlohmann::json outbounds_ GUARDED_BY(mutex_);
    nlohmann::json interfaces_ GUARDED_BY(mutex_);
    nlohmann::json connections_ GUARDED_BY(mutex_);
    bool connections_initialized_ GUARDED_BY(mutex_){false};
    nlohmann::json list_refresh_ GUARDED_BY(mutex_);
    bool list_refresh_initialized_ GUARDED_BY(mutex_){false};
    bool initialized_ GUARDED_BY(mutex_){false};
};

std::string make_named_sse_frame(const std::string& event,
                                 const std::string& payload);

} // namespace keen_pbr3

#endif
