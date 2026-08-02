#ifdef WITH_API

#include <doctest/doctest.h>

#include "api/status_stream.hpp"
#include "daemon/daemon.hpp"

#include <chrono>
#include <future>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

StatusSnapshot make_snapshot(std::string version = "1",
                             size_t outbound_count = 0) {
    StatusSnapshot snapshot;
    snapshot.service.version = std::move(version);
    snapshot.service.build = "test";
    snapshot.service.status = api::HealthResponseStatus::RUNNING;
    snapshot.service.runtime_state = api::RuntimeState::RUNNING;
    snapshot.service.runtime_state_reason = "test";
    snapshot.service.os_type = "linux";
    snapshot.service.os_version = "test";
    snapshot.service.build_variant = "test";
    snapshot.service.resolver_live_status = api::ResolverLiveStatus::HEALTHY;
    snapshot.service.config_is_draft = false;
    snapshot.outbounds.outbounds.resize(outbound_count);
    for (size_t i = 0; i < outbound_count; ++i) {
        auto& outbound = snapshot.outbounds.outbounds[i];
        outbound.tag = "outbound" + std::to_string(i);
        outbound.type = api::OutboundType::INTERFACE;
        outbound.status = api::ResolverLiveStatus::HEALTHY;
    }
    return snapshot;
}

std::string pop(const SseBroadcaster::SubscriptionPtr& subscription) {
    KPBR_LOCK_GUARD(subscription->mutex);
    REQUIRE_FALSE(subscription->messages.empty());
    auto value = std::move(subscription->messages.front());
    subscription->messages.pop_front();
    return value;
}

size_t queued(const SseBroadcaster::SubscriptionPtr& subscription) {
    KPBR_LOCK_GUARD(subscription->mutex);
    return subscription->messages.size();
}

} // namespace

TEST_CASE("status stream queues one snapshot before changes") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });
    auto subscription = stream.subscribe();
    CHECK(stream.has_subscribers());

    const auto first = pop(subscription);
    CHECK(first.rfind("event: snapshot\n", 0) == 0);
    CHECK(queued(subscription) == 0);

    current.service.version = "2";
    stream.reconcile();
    CHECK(pop(subscription).rfind("event: service\n", 0) == 0);
}

TEST_CASE("status stream reports when no live subscribers remain") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });
    CHECK_FALSE(stream.has_subscribers());

    auto subscription = stream.subscribe();
    REQUIRE(subscription);
    CHECK(stream.has_subscribers());

    stream.unsubscribe(subscription);
    CHECK_FALSE(stream.has_subscribers());
}

TEST_CASE("status stream reconnect starts with a fresh current snapshot") {
    auto current = make_snapshot("1", 0);
    StatusStream stream([&] { return current; });
    auto first = stream.subscribe();
    REQUIRE(first);
    (void)pop(first);
    stream.unsubscribe(first);

    current = make_snapshot("2", 1);
    auto reconnected = stream.subscribe();
    REQUIRE(reconnected);
    const auto snapshot = pop(reconnected);
    CHECK(snapshot.rfind("event: snapshot\n", 0) == 0);
    CHECK(snapshot.find("\"version\":\"2\"") != std::string::npos);
    CHECK(snapshot.find("\"tag\":\"outbound0\"") != std::string::npos);
}

TEST_CASE("status stream subscribe sends changed state only to existing clients") {
    auto current = make_snapshot("1");
    StatusStream stream([&] { return current; });
    auto existing = stream.subscribe();
    REQUIRE(existing);
    (void)pop(existing);

    api::ConnectionEventState connections;
    connections.revision = 4;
    connections.changed_at = 100;
    connections.available = true;
    stream.publish_connections(connections);
    (void)pop(existing);

    const nlohmann::json list_refresh{
        {"task_id", "list-refresh-subscribe"},
        {"state", "running"},
    };
    stream.publish_list_refresh(list_refresh);
    (void)pop(existing);

    current = make_snapshot("2", 1);
    api::RuntimeInterfaceInventoryEntry interface;
    interface.name = "wg-subscribe";
    interface.status = api::RuntimeInterfaceInventoryStatusEnum::UP;
    interface.admin_up = true;
    current.interfaces.interfaces.push_back(std::move(interface));
    auto newcomer = stream.subscribe();
    REQUIRE(newcomer);

    const auto service_delta = pop(existing);
    CHECK(service_delta.rfind("event: service\n", 0) == 0);
    CHECK(service_delta.find("\"version\":\"2\"") !=
          std::string::npos);
    const auto outbounds_delta = pop(existing);
    CHECK(outbounds_delta.rfind("event: outbounds\n", 0) == 0);
    CHECK(outbounds_delta.find("\"tag\":\"outbound0\"") !=
          std::string::npos);
    const auto interfaces_delta = pop(existing);
    CHECK(interfaces_delta.rfind("event: interfaces\n", 0) == 0);
    CHECK(interfaces_delta.find("\"name\":\"wg-subscribe\"") !=
          std::string::npos);
    CHECK(queued(existing) == 0);

    const auto snapshot = pop(newcomer);
    CHECK(snapshot.rfind("event: snapshot\n", 0) == 0);
    CHECK(snapshot.find("\"version\":\"2\"") != std::string::npos);
    CHECK(snapshot.find("\"tag\":\"outbound0\"") !=
          std::string::npos);
    CHECK(snapshot.find("\"name\":\"wg-subscribe\"") !=
          std::string::npos);
    CHECK(pop(newcomer).rfind("event: connections\n", 0) == 0);
    CHECK(pop(newcomer).rfind("event: list_refresh\n", 0) == 0);
    CHECK(queued(newcomer) == 0);
}

TEST_CASE("status stream suppresses identical data and names changed datasets") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });
    auto subscription = stream.subscribe();
    (void)pop(subscription);

    stream.reconcile();
    CHECK(queued(subscription) == 0);

    current.service.version = "2";
    current.outbounds = make_snapshot("2", 1).outbounds;
    stream.reconcile();
    CHECK(pop(subscription).rfind("event: service\n", 0) == 0);
    CHECK(pop(subscription).rfind("event: outbounds\n", 0) == 0);
    CHECK(queued(subscription) == 0);
}

TEST_CASE("status stream publishes changed interface statistics only once") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });
    auto subscription = stream.subscribe();
    (void)pop(subscription);

    api::RuntimeInterfaceInventoryResponse interfaces;
    api::RuntimeInterfaceInventoryEntry entry;
    entry.name = "wg0";
    entry.status = api::RuntimeInterfaceInventoryStatusEnum::UP;
    interfaces.interfaces.push_back(entry);

    stream.publish_interfaces(interfaces);
    CHECK(pop(subscription).rfind("event: interfaces\n", 0) == 0);
    stream.publish_interfaces(std::move(interfaces));
    CHECK(queued(subscription) == 0);
}

TEST_CASE("status stream publishes compact interface traffic independently") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });
    auto subscription = stream.subscribe();
    (void)pop(subscription);

    stream.publish_interface_traffic(
        nlohmann::json{
            {"sampled_at_unix_ms", 1'234},
            {"interfaces",
             nlohmann::json::array({
                 {
                     {"name", "wg0"},
                     {"available", true},
                     {"reset", false},
                     {"rx_bytes", 100},
                     {"tx_bytes", 200},
                     {"rx_bits_per_second", 800},
                     {"tx_bits_per_second", 1'600},
                 },
             })},
        });

    const auto frame = pop(subscription);
    CHECK(frame.rfind("event: interface_traffic\n", 0) == 0);
    CHECK(frame.find("\"type\":\"interface_traffic\"") !=
          std::string::npos);
    CHECK(frame.find("\"sampled_at_unix_ms\":1234") !=
          std::string::npos);
    CHECK(frame.find("\"history\"") == std::string::npos);
}

TEST_CASE("interface traffic target delta reports removal exactly once") {
    const std::set<std::string> initial{"nwg2", "wg0"};
    const auto unchanged =
        plan_interface_traffic_targets(initial, initial);
    CHECK(unchanged.reported == initial);
    CHECK(unchanged.removed.empty());

    const std::set<std::string> reduced{"wg0"};
    const auto removed =
        plan_interface_traffic_targets(reduced, initial);
    CHECK(removed.reported == initial);
    CHECK(removed.removed == std::set<std::string>{"nwg2"});

    // The daemon stores the active set after publishing this delta. The next
    // cycle must therefore stop reporting the removed interface.
    const auto next =
        plan_interface_traffic_targets(reduced, reduced);
    CHECK(next.reported == reduced);
    CHECK(next.removed.empty());
}

TEST_CASE("active config contributes only concrete interface outbounds") {
    Config config;
    Outbound interface;
    interface.tag = "wg";
    interface.type = OutboundType::INTERFACE;
    interface.interface = "nwg2";

    Outbound missing_name;
    missing_name.tag = "missing";
    missing_name.type = OutboundType::INTERFACE;

    Outbound selector;
    selector.tag = "failover";
    selector.type = OutboundType::URLTEST;
    selector.interface = "must-not-be-sampled";

    config.outbounds =
        std::vector<Outbound>{interface, missing_name, selector};
    CHECK(
        interface_traffic_targets_from_config(config) ==
        std::vector<std::string>{"nwg2"});
}

TEST_CASE("status stream does not resend full inventory for traffic-only changes") {
    auto current = make_snapshot();
    api::RuntimeInterfaceInventoryEntry interface;
    interface.name = "wg0";
    interface.status = api::RuntimeInterfaceInventoryStatusEnum::UP;
    interface.admin_up = true;
    api::Traffic traffic;
    traffic.rx_bytes = 100;
    traffic.tx_bytes = 200;
    current.interfaces.interfaces.push_back(interface);
    current.interfaces.interfaces.front().traffic = traffic;

    StatusStream stream([&] { return current; });
    auto subscription = stream.subscribe();
    (void)pop(subscription);

    current.interfaces.interfaces.front().traffic->rx_bytes = 150;
    stream.reconcile();
    CHECK(queued(subscription) == 0);

    current.interfaces.interfaces.front().admin_up = false;
    stream.reconcile();
    CHECK(pop(subscription).rfind("event: interfaces\n", 0) == 0);
}

TEST_CASE("status stream closes slow and shutdown subscribers") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; }, 1);
    auto slow = stream.subscribe();
    current.service.version = "2";
    stream.reconcile();
    {
        KPBR_LOCK_GUARD(slow->mutex);
        CHECK(slow->closed);
    }

    auto active = stream.subscribe();
    stream.close_all();
    {
        KPBR_LOCK_GUARD(active->mutex);
        CHECK(active->closed);
    }
}

TEST_CASE("status stream shutdown permanently closes subscription admission") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });
    auto subscription = stream.subscribe();
    REQUIRE(subscription);

    stream.close_all();

    {
        KPBR_LOCK_GUARD(subscription->mutex);
        CHECK(subscription->closed);
    }
    CHECK_FALSE(stream.has_subscribers());
    CHECK_FALSE(stream.subscribe());
}

TEST_CASE("SSE wait drains queued messages without probing the peer") {
    auto subscription = std::make_shared<SseBroadcaster::Subscription>();
    {
        KPBR_LOCK_GUARD(subscription->mutex);
        subscription->messages.push_back("queued");
    }
    int probes = 0;

    const auto result = wait_for_sse_subscription(
        subscription,
        std::chrono::seconds(15),
        std::chrono::seconds(1),
        [&] {
            ++probes;
            return false;
        });

    CHECK(result.status == SseSubscriptionWaitStatus::MESSAGE);
    CHECK(result.message == "queued");
    CHECK(probes == 0);
}

TEST_CASE("SSE wait observes closed subscriptions without probing the peer") {
    auto subscription = std::make_shared<SseBroadcaster::Subscription>();
    {
        KPBR_LOCK_GUARD(subscription->mutex);
        subscription->closed = true;
    }
    int probes = 0;

    const auto result = wait_for_sse_subscription(
        subscription,
        std::chrono::seconds(15),
        std::chrono::seconds(1),
        [&] {
            ++probes;
            return true;
        });

    CHECK(result.status == SseSubscriptionWaitStatus::CLOSED);
    CHECK(probes == 0);
}

TEST_CASE("SSE wait rejects a dead peer and rechecks subscription state") {
    using namespace std::chrono_literals;

    auto subscription = std::make_shared<SseBroadcaster::Subscription>();
    std::promise<void> probe_started;
    auto probe_started_future = probe_started.get_future();
    std::promise<void> release_probe;
    auto release_probe_future = release_probe.get_future();

    auto waiter = std::async(std::launch::async, [&] {
        return wait_for_sse_subscription(
            subscription,
            2s,
            std::chrono::milliseconds::zero(),
            [&] {
                probe_started.set_value();
                release_probe_future.wait();
                return false;
            });
    });

    const bool probe_observed =
        probe_started_future.wait_for(3s) == std::future_status::ready;
    if (probe_observed) {
        // This acquisition also proves that the peer probe is not executed
        // while Subscription::mutex is held.
        KPBR_LOCK_GUARD(subscription->mutex);
        subscription->messages.push_back("published-during-probe");
    }
    subscription->cv.notify_all();
    release_probe.set_value();

    const auto waiter_ready = waiter.wait_for(5s);
    REQUIRE(probe_observed);
    REQUIRE(waiter_ready == std::future_status::ready);
    const auto result = waiter.get();
    CHECK(result.status == SseSubscriptionWaitStatus::MESSAGE);
    CHECK(result.message == "published-during-probe");

    auto dead = std::make_shared<SseBroadcaster::Subscription>();
    const auto disconnected = wait_for_sse_subscription(
        dead,
        std::chrono::seconds(15),
        std::chrono::milliseconds::zero(),
        [] { return false; });
    CHECK(disconnected.status ==
          SseSubscriptionWaitStatus::PEER_DISCONNECTED);
}

TEST_CASE("SSE wait emits an immediate zero heartbeat without probing") {
    auto subscription = std::make_shared<SseBroadcaster::Subscription>();
    const auto result = wait_for_sse_subscription(
        subscription,
        std::chrono::milliseconds::zero(),
        std::chrono::seconds(1));

    CHECK(result.status == SseSubscriptionWaitStatus::HEARTBEAT);
}

TEST_CASE("status stream reserves API capacity by limiting long-lived clients") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; }, 128, 2);

    auto first = stream.subscribe();
    auto second = stream.subscribe();
    REQUIRE(first);
    REQUIRE(second);
    CHECK_FALSE(stream.subscribe());

    stream.unsubscribe(first);
    CHECK(stream.subscribe());
}

TEST_CASE("status stream default supports a normal multi-tab session") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });
    std::vector<SseBroadcaster::SubscriptionPtr> subscriptions;

    for (int index = 0; index < 5; ++index) {
        auto subscription = stream.subscribe();
        REQUIRE(subscription);
        subscriptions.push_back(std::move(subscription));
    }
}

TEST_CASE("status stream replays and publishes conntrack revisions") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });

    api::ConnectionEventState initial;
    initial.revision = 0;
    initial.changed_at = 0;
    initial.available = true;
    stream.publish_connections(initial);

    auto subscription = stream.subscribe();
    CHECK(pop(subscription).rfind("event: snapshot\n", 0) == 0);
    CHECK(pop(subscription).rfind("event: connections\n", 0) == 0);

    auto changed = initial;
    changed.revision = 3;
    changed.changed_at = 100;
    stream.publish_connections(changed);
    const auto frame = pop(subscription);
    CHECK(frame.rfind("event: connections\n", 0) == 0);
    CHECK(frame.find("\"revision\":3") != std::string::npos);

    stream.publish_connections(changed);
    CHECK(queued(subscription) == 0);
}

TEST_CASE("status stream publishes transient DNS probes without snapshot state") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });
    auto subscription = stream.subscribe();
    REQUIRE(subscription);
    (void)pop(subscription);

    stream.publish_dns_probe(nlohmann::json{
        {"type", "DNS"},
        {"domain", "token.check.keen.pbr"},
        {"source_ip", "192.0.2.10"},
        {"ecs", nullptr},
    });

    const auto frame = pop(subscription);
    CHECK(frame.rfind("event: dns_probe\n", 0) == 0);
    CHECK(frame.find("\"type\":\"dns_probe\"") != std::string::npos);
    CHECK(frame.find("token.check.keen.pbr") != std::string::npos);

    stream.unsubscribe(subscription);
    auto reconnected = stream.subscribe();
    REQUIRE(reconnected);
    CHECK(pop(reconnected).rfind("event: snapshot\n", 0) == 0);
    CHECK(queued(reconnected) == 0);
}

TEST_CASE("status stream caches and replays the latest list refresh task") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });
    auto subscription = stream.subscribe();
    REQUIRE(subscription);
    (void)pop(subscription);

    const nlohmann::json queued_task{
        {"task_id", "list-refresh-7"},
        {"state", "queued"},
        {"completed", 0},
        {"total", 3},
    };
    stream.publish_list_refresh(queued_task);

    const auto frame = pop(subscription);
    CHECK(frame.rfind("event: list_refresh\n", 0) == 0);
    CHECK(frame.find("\"type\":\"list_refresh\"") != std::string::npos);
    CHECK(frame.find("\"task_id\":\"list-refresh-7\"") !=
          std::string::npos);

    stream.unsubscribe(subscription);
    auto reconnected = stream.subscribe();
    REQUIRE(reconnected);
    CHECK(pop(reconnected).rfind("event: snapshot\n", 0) == 0);
    const auto replay = pop(reconnected);
    CHECK(replay.rfind("event: list_refresh\n", 0) == 0);
    CHECK(replay.find("\"state\":\"queued\"") != std::string::npos);
    CHECK(queued(reconnected) == 0);
}

TEST_CASE("status stream suppresses identical list refresh snapshots") {
    auto current = make_snapshot();
    StatusStream stream([&] { return current; });
    auto subscription = stream.subscribe();
    REQUIRE(subscription);
    (void)pop(subscription);

    nlohmann::json task{
        {"task_id", "list-refresh-8"},
        {"state", "running"},
        {"completed", 1},
        {"total", 2},
    };
    stream.publish_list_refresh(task);
    CHECK(pop(subscription).rfind("event: list_refresh\n", 0) == 0);

    stream.publish_list_refresh(task);
    CHECK(queued(subscription) == 0);

    task["completed"] = 2;
    task["state"] = "succeeded";
    stream.publish_list_refresh(task);
    const auto changed = pop(subscription);
    CHECK(changed.find("\"completed\":2") != std::string::npos);
    CHECK(changed.find("\"state\":\"succeeded\"") !=
          std::string::npos);
}

#endif
