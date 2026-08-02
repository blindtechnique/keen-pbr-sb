#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "api/handler_status_events.hpp"
#include "api/handlers.hpp"
#include "api/server.hpp"
#include "api/status_stream.hpp"

#include <atomic>
#include <chrono>
#include <future>

namespace keen_pbr3 {

namespace {

ApiContext make_status_context(SseBroadcaster& broadcaster,
                               StatusStream& stream) {
    static const std::string config_path =
        "/tmp/keen-pbr-status-test.json";
    return ApiContext{
        config_path,
        broadcaster,
        [] { return Config{}; },
        [] { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> {
            return std::nullopt;
        },
        [] {},
        [](const Config&) {},
        [] { return ServiceHealthState{}; },
        [] { return RoutingHealthReport{}; },
        [] { return api::RuntimeOutboundsResponse{}; },
        [] { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) {
            return std::map<std::string, api::ListRefreshStateValue>{};
        },
        [](const std::string&) { return TestRoutingResult{}; },
        [] {},
        [] {},
        [](Config, std::string) { return ConfigApplyResult{}; },
        [] {},
        [] {},
        [] {},
        [](std::optional<std::string>) {
            return ListRefreshOperationResult{};
        },
        &stream,
    };
}

StatusSnapshot api_snapshot() {
    StatusSnapshot snapshot;
    snapshot.service.version = "test";
    snapshot.service.build = "test";
    snapshot.service.status = api::HealthResponseStatus::RUNNING;
    snapshot.service.runtime_state = api::RuntimeState::RUNNING;
    snapshot.service.runtime_state_reason = "test";
    snapshot.service.os_type = "linux";
    snapshot.service.os_version = "test";
    snapshot.service.build_variant = "test";
    snapshot.service.resolver_live_status = api::ResolverLiveStatus::HEALTHY;
    snapshot.service.config_is_draft = false;
    return snapshot;
}

} // namespace

TEST_CASE("status events endpoint returns SSE headers and snapshot first") {
    SseBroadcaster dns_broadcaster;
    StatusStream status_stream([] { return api_snapshot(); });
    auto context = make_status_context(dns_broadcaster, status_stream);
    ApiConfig config;
    config.listen = std::string("127.0.0.1:18193");
    ApiServer server(config);
    register_status_events_handler(server, context);
    server.start();

    int status = 0;
    std::string content_type;
    std::string body;
    httplib::Client client("127.0.0.1", 18193);
    (void)client.Get(
        "/api/status/events",
        [&status, &content_type](const httplib::Response& response) {
            status = response.status;
            content_type = response.get_header_value("Content-Type");
            return true;
        },
        [&body](const char* data, size_t length) {
            body.append(data, length);
            return false;
        });
    server.stop();

    CHECK(status == 200);
    CHECK(content_type.find("text/event-stream") != std::string::npos);
    CHECK(body.rfind("event: snapshot\ndata: ", 0) == 0);
}

TEST_CASE("status events endpoint rejects excess streams with retry guidance") {
    SseBroadcaster dns_broadcaster;
    StatusStream status_stream([] { return api_snapshot(); }, 32, 1);
    auto held_subscription = status_stream.subscribe();
    REQUIRE(held_subscription);

    auto context = make_status_context(dns_broadcaster, status_stream);
    ApiConfig config;
    config.listen = std::string("127.0.0.1:18194");
    ApiServer server(config);
    register_status_events_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", 18194);
    const auto response = client.Get("/api/status/events");
    server.stop();

    REQUIRE(response);
    CHECK(response->status == 503);
    CHECK(response->get_header_value("Retry-After") == "5");
    CHECK(response->get_header_value("Content-Type").find("application/json") !=
          std::string::npos);
    CHECK(response->body ==
          R"({"error":"too many active status streams"})");
}

TEST_CASE("status events endpoint wakes promptly when streams close") {
    using namespace std::chrono_literals;

    SseBroadcaster dns_broadcaster;
    StatusStream status_stream([] { return api_snapshot(); });
    auto context = make_status_context(dns_broadcaster, status_stream);
    ApiConfig config;
    config.listen = std::string("127.0.0.1:18195");
    ApiServer server(config);
    register_status_events_handler(server, context);
    server.start();

    std::promise<void> response_started;
    auto response_started_future = response_started.get_future();
    std::atomic_bool received_snapshot{false};
    auto request = std::async(std::launch::async, [&] {
        httplib::Client client("127.0.0.1", 18195);
        client.set_connection_timeout(1, 0);
        // Bound the worker even if a future shutdown regression prevents the
        // streaming handler from observing close_all().  Without a client
        // timeout the std::async future destructor could hang the test binary.
        client.set_read_timeout(3, 0);
        return client.Get(
            "/api/status/events",
            [&response_started](const httplib::Response&) {
                response_started.set_value();
                return true;
            },
            [&received_snapshot](const char*, size_t) {
                received_snapshot.store(true, std::memory_order_release);
                return true;
            });
    });

    const bool response_opened =
        response_started_future.wait_for(2s) == std::future_status::ready;
    const bool admitted = response_opened && status_stream.has_subscribers();
    if (response_opened) {
        status_stream.close_all();
    }
    const auto completion_before_stop = request.wait_for(2s);
    server.stop();
    auto completion = completion_before_stop;
    if (completion != std::future_status::ready) {
        completion = request.wait_for(4s);
    }

    CHECK(response_opened);
    CHECK(admitted);
    CHECK(received_snapshot.load(std::memory_order_acquire));
    CHECK(completion_before_stop == std::future_status::ready);
    REQUIRE(completion == std::future_status::ready);
    const auto result = request.get();
    REQUIRE(result);
    CHECK(result->status == 200);
}

} // namespace keen_pbr3

#endif
