#ifdef WITH_API

#include "status_stream.hpp"

#include <nlohmann/json.hpp>
#include <vector>

namespace keen_pbr3 {

namespace {

std::string make_event_payload(const std::string& type,
                               const nlohmann::json& data) {
    return nlohmann::json{{"type", type}, {"data", data}}.dump();
}

nlohmann::json interface_inventory_without_traffic(
    const nlohmann::json& inventory) {
    auto topology = inventory;
    if (!topology.is_object()) {
        return topology;
    }
    auto interfaces = topology.find("interfaces");
    if (interfaces == topology.end() || !interfaces->is_array()) {
        return topology;
    }
    for (auto& entry : *interfaces) {
        if (entry.is_object()) {
            entry.erase("traffic");
        }
    }
    return topology;
}

} // namespace

std::string make_named_sse_frame(const std::string& event,
                                 const std::string& payload) {
    return "event: " + event + "\ndata: " + payload + "\n\n";
}

StatusStream::StatusStream(SnapshotBuilder builder,
                           size_t max_queue_size,
                           size_t max_subscriptions)
    : builder_(std::move(builder))
    , broadcaster_(max_queue_size, max_subscriptions) {}

SseBroadcaster::SubscriptionPtr StatusStream::subscribe() {
    std::vector<std::string> changed_frames;
    SseBroadcaster::SubscriptionPtr subscription;

    {
        KPBR_LOCK_GUARD(mutex_);
        const auto snapshot = builder_();
        const nlohmann::json service = snapshot.service;
        const nlohmann::json outbounds = snapshot.outbounds;
        const nlohmann::json interfaces = snapshot.interfaces;
        if (initialized_) {
            if (service != service_) {
                changed_frames.push_back(make_named_sse_frame(
                    "service", make_event_payload("service", service)));
            }
            if (outbounds != outbounds_) {
                changed_frames.push_back(make_named_sse_frame(
                    "outbounds", make_event_payload("outbounds", outbounds)));
            }
            if (interface_inventory_without_traffic(interfaces) !=
                interface_inventory_without_traffic(interfaces_)) {
                changed_frames.push_back(make_named_sse_frame(
                    "interfaces", make_event_payload("interfaces", interfaces)));
            }
        }
        service_ = service;
        outbounds_ = outbounds;
        interfaces_ = interfaces;
        initialized_ = true;

        const auto payload = make_event_payload(
            "snapshot",
            nlohmann::json{{"service", service},
                           {"outbounds", outbounds},
                           {"interfaces", interfaces}});
        std::vector<std::string> initial_frames{
            make_named_sse_frame("snapshot", payload)};
        if (connections_initialized_) {
            initial_frames.push_back(make_named_sse_frame(
                "connections",
                make_event_payload("connections", connections_)));
        }
        subscription = broadcaster_.subscribe(std::move(initial_frames));
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
        const nlohmann::json service = snapshot.service;
        const nlohmann::json outbounds = snapshot.outbounds;
        const nlohmann::json interfaces = snapshot.interfaces;
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
                "service", make_event_payload("service", service)));
        }
        if (outbounds != outbounds_) {
            outbounds_ = outbounds;
            frames.push_back(make_named_sse_frame(
                "outbounds", make_event_payload("outbounds", outbounds)));
        }
        const bool interface_topology_changed =
            interface_inventory_without_traffic(interfaces) !=
            interface_inventory_without_traffic(interfaces_);
        interfaces_ = interfaces;
        if (interface_topology_changed) {
            frames.push_back(make_named_sse_frame(
                "interfaces", make_event_payload("interfaces", interfaces)));
        }
    }

    for (const auto& frame : frames) {
        broadcaster_.publish(frame);
    }
}

void StatusStream::publish_interfaces(
    api::RuntimeInterfaceInventoryResponse state) {
    std::string frame;
    {
        KPBR_LOCK_GUARD(mutex_);
        if (!initialized_) {
            return;
        }
        nlohmann::json serialized = std::move(state);
        if (serialized == interfaces_) {
            return;
        }
        interfaces_ = std::move(serialized);
        frame = make_named_sse_frame(
            "interfaces", make_event_payload("interfaces", interfaces_));
    }
    broadcaster_.publish(frame);
}

void StatusStream::publish_interface_traffic(nlohmann::json state) {
    broadcaster_.publish(make_named_sse_frame(
        "interface_traffic",
        make_event_payload("interface_traffic", state)));
}

void StatusStream::publish_connections(api::ConnectionEventState state) {
    std::string frame;
    {
        KPBR_LOCK_GUARD(mutex_);
        const nlohmann::json serialized = state;
        if (connections_initialized_ && serialized == connections_) return;
        connections_ = std::move(serialized);
        connections_initialized_ = true;
        frame = make_named_sse_frame(
            "connections",
            make_event_payload("connections", connections_));
    }
    broadcaster_.publish(frame);
}

void StatusStream::publish_dns_probe(nlohmann::json state) {
    broadcaster_.publish(make_named_sse_frame(
        "dns_probe",
        make_event_payload("dns_probe", std::move(state))));
}

void StatusStream::close_all() {
    broadcaster_.close_all();
}

bool StatusStream::has_subscribers() {
    return broadcaster_.active_subscriptions() != 0;
}

} // namespace keen_pbr3

#endif
