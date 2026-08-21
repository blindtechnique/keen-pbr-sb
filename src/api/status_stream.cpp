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
        if (list_refresh_initialized_) {
            initial_frames.push_back(make_named_sse_frame(
                "list_refresh",
                make_event_payload("list_refresh", list_refresh_)));
        }
        if (component_transaction_initialized_) {
            initial_frames.push_back(make_named_sse_frame(
                "component_transaction",
                make_event_payload("component_transaction",
                                   component_transaction_)));
        }
        // Replayed for the same reason as the others, and it matters more
        // here: the install replaces the binary every transport runs on, so a
        // page opened or reloaded while it is happening has to be told that it
        // is happening rather than offer the operator a button to start a
        // second one.
        if (sing_box_install_initialized_) {
            initial_frames.push_back(make_named_sse_frame(
                "sing_box_install",
                make_event_payload("sing_box_install", sing_box_install_)));
        }
        // Keep cache mutation, delivery to the previous subscriber cohort and
        // newcomer registration in one order.  Registering first and excluding
        // just that pointer lets a concurrent second subscriber receive a
        // stale delta after its fresh snapshot.
        for (const auto& frame : changed_frames) {
            broadcaster_.publish(frame);
        }
        subscription = broadcaster_.subscribe(std::move(initial_frames));
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
        // Building the combined service/outbound/interface snapshot can touch
        // several runtime providers.  There is nothing to reconcile while no
        // browser is listening, so keep the cache cold and let the next
        // subscriber build one fresh authoritative snapshot on admission.
        if (broadcaster_.active_subscriptions() == 0U) {
            initialized_ = false;
            return;
        }
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
        for (const auto& frame : frames) {
            broadcaster_.publish(frame);
        }
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
        broadcaster_.publish(frame);
    }
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
        broadcaster_.publish(frame);
    }
}

void StatusStream::publish_dns_probe(nlohmann::json state) {
    broadcaster_.publish(make_named_sse_frame(
        "dns_probe",
        make_event_payload("dns_probe", std::move(state))));
}

void StatusStream::publish_list_refresh(nlohmann::json state) {
    std::string frame;
    {
        KPBR_LOCK_GUARD(mutex_);
        if (list_refresh_initialized_ && state == list_refresh_) return;
        list_refresh_ = std::move(state);
        list_refresh_initialized_ = true;
        frame = make_named_sse_frame(
            "list_refresh",
            make_event_payload("list_refresh", list_refresh_));
        broadcaster_.publish(frame);
    }
}

void StatusStream::publish_component_transaction(nlohmann::json state) {
    KPBR_LOCK_GUARD(mutex_);
    // Deliberately no equality skip. The others cache a state that happens to
    // repeat; this reports progress, and two identical phases in a row are two
    // events an operator is waiting for - suppressing the second would stall
    // the display at the very moment it is being watched.
    component_transaction_ = std::move(state);
    component_transaction_initialized_ = true;
    broadcaster_.publish(make_named_sse_frame(
        "component_transaction",
        make_event_payload("component_transaction",
                           component_transaction_)));
}

void StatusStream::publish_sing_box_install(nlohmann::json state) {
    KPBR_LOCK_GUARD(mutex_);
    // No equality skip, for the same reason as component_transaction: this
    // reports progress rather than caching a state that happens to repeat, and
    // suppressing a repeated phase would stall the display exactly while it is
    // being watched.
    sing_box_install_ = std::move(state);
    sing_box_install_initialized_ = true;
    broadcaster_.publish(make_named_sse_frame(
        "sing_box_install",
        make_event_payload("sing_box_install", sing_box_install_)));
}

void StatusStream::close_all() {
    broadcaster_.close_all();
}

void StatusStream::revoke_active_subscriptions() {
    broadcaster_.revoke_active_subscriptions();
}

bool StatusStream::has_subscribers() {
    return broadcaster_.active_subscriptions() != 0;
}

} // namespace keen_pbr3

#endif
