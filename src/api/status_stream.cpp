#ifdef WITH_API

#include "status_stream.hpp"

#include <nlohmann/json.hpp>
#include <vector>

namespace keen_pbr3 {

namespace {

template<typename T>
std::string serialize(const T& value) {
    return nlohmann::json(value).dump();
}

std::string make_event_payload(const std::string& type,
                               const nlohmann::json& data) {
    return nlohmann::json{{"type", type}, {"data", data}}.dump();
}

} // namespace

std::string make_named_sse_frame(const std::string& event,
                                 const std::string& payload) {
    return "event: " + event + "\ndata: " + payload + "\n\n";
}

StatusStream::StatusStream(SnapshotBuilder builder, size_t max_queue_size)
    : builder_(std::move(builder))
    , broadcaster_(max_queue_size) {}

SseBroadcaster::SubscriptionPtr StatusStream::subscribe() {
    std::vector<std::string> changed_frames;
    SseBroadcaster::SubscriptionPtr subscription;

    {
        KPBR_LOCK_GUARD(mutex_);
        const auto snapshot = builder_();
        const auto service = serialize(snapshot.service);
        const auto outbounds = serialize(snapshot.outbounds);
        const auto interfaces = serialize(snapshot.interfaces);
        if (initialized_) {
            if (service != service_) {
                changed_frames.push_back(make_named_sse_frame(
                    "service", make_event_payload("service", snapshot.service)));
            }
            if (outbounds != outbounds_) {
                changed_frames.push_back(make_named_sse_frame(
                    "outbounds", make_event_payload("outbounds", snapshot.outbounds)));
            }
            if (interfaces != interfaces_) {
                changed_frames.push_back(make_named_sse_frame(
                    "interfaces", make_event_payload("interfaces", snapshot.interfaces)));
            }
        }
        service_ = service;
        outbounds_ = outbounds;
        interfaces_ = interfaces;
        initialized_ = true;

        const auto payload = make_event_payload(
            "snapshot",
            nlohmann::json{{"service", snapshot.service},
                           {"outbounds", snapshot.outbounds},
                           {"interfaces", snapshot.interfaces}});
        subscription = broadcaster_.subscribe(
            {make_named_sse_frame("snapshot", payload)});
    }

    // Never publish while holding StatusStream::mutex_: a slow subscriber
    // must not block snapshot reconciliation or create a lock-order cycle.
    for (const auto& frame : changed_frames) {
        broadcaster_.publish(frame);
    }
    return subscription;
}

void StatusStream::unsubscribe(
    const SseBroadcaster::SubscriptionPtr& subscription) {
    broadcaster_.unsubscribe(subscription);
}

void StatusStream::reconcile() {
    std::vector<std::string> frames;

    {
        KPBR_LOCK_GUARD(mutex_);
        const auto snapshot = builder_();
        const auto service = serialize(snapshot.service);
        const auto outbounds = serialize(snapshot.outbounds);
        const auto interfaces = serialize(snapshot.interfaces);
        if (!initialized_) {
            service_ = service;
            outbounds_ = outbounds;
            interfaces_ = interfaces;
            initialized_ = true;
            return;
        }

        if (service != service_) {
            service_ = service;
            frames.push_back(make_named_sse_frame(
                "service", make_event_payload("service", snapshot.service)));
        }
        if (outbounds != outbounds_) {
            outbounds_ = outbounds;
            frames.push_back(make_named_sse_frame(
                "outbounds", make_event_payload("outbounds", snapshot.outbounds)));
        }
        if (interfaces != interfaces_) {
            interfaces_ = interfaces;
            frames.push_back(make_named_sse_frame(
                "interfaces", make_event_payload("interfaces", snapshot.interfaces)));
        }
    }

    for (const auto& frame : frames) {
        broadcaster_.publish(frame);
    }
}

void StatusStream::close_all() {
    broadcaster_.close_all();
}

} // namespace keen_pbr3

#endif
