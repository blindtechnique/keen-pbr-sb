#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api/handler_diagnostic_tasks.hpp"
#include "api/handler_runtime_inventory.hpp"
#include "api/sse_broadcaster.hpp"
#include "api/status_stream.hpp"

namespace keen_pbr3 {
namespace {

ApiContext make_diagnostic_tasks_context(SseBroadcaster& broadcaster) {
    ApiContext context{
        "/tmp/keen-pbr-diagnostic-tasks-test.json",
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
    };
    return context;
}

} // namespace

TEST_CASE("diagnostic task context has a safe empty fallback") {
    SseBroadcaster broadcaster;
    const auto context = make_diagnostic_tasks_context(broadcaster);
    const auto response = context.get_diagnostic_tasks();

    CHECK(response.capacity == 0);
    CHECK(response.tracked == 0);
    CHECK(response.tasks.empty());
}

TEST_CASE("diagnostic task endpoint returns one pull-only snapshot") {
    SseBroadcaster broadcaster;
    auto context = make_diagnostic_tasks_context(broadcaster);
    PeriodicTaskMetricsRegistry registry(
        {"resolver-hash-refresh", "owned-snat-health"});
    auto run = registry.begin("resolver-hash-refresh");
    REQUIRE(run.failure("dnsmasq did not converge"));

    int callback_calls = 0;
    context.get_diagnostic_tasks_fn = [&]() {
        ++callback_calls;
        return build_diagnostic_tasks_response(registry);
    };

    ApiConfig config;
    config.listen = std::string("127.0.0.1:18195");
    ApiServer server(config);
    register_diagnostic_tasks_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", 18195);
    const auto response = client.Get("/api/diagnostics/tasks");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    CHECK(callback_calls == 1);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body["capacity"] == 32);
    CHECK(body["tracked"] == 2);
    REQUIRE(body["tasks"].size() == 2);
    CHECK(body["tasks"][0]["label"] == "owned-snat-health");
    CHECK(body["tasks"][1]["label"] == "resolver-hash-refresh");
    CHECK(body["tasks"][1]["runs"] == 1);
    CHECK(body["tasks"][1]["failure"] == 1);
    CHECK(body["tasks"][1]["last_outcome"] == "failure");
    CHECK(body["tasks"][1]["last_error"] == "dnsmasq did not converge");
}

TEST_CASE("status stream never reads pull-only task metrics") {
    SseBroadcaster broadcaster;
    auto context = make_diagnostic_tasks_context(broadcaster);
    int callback_calls = 0;
    context.get_diagnostic_tasks_fn = [&]() {
        ++callback_calls;
        api::PeriodicTaskMetricsResponse response;
        response.capacity = 0;
        response.tracked = 0;
        return response;
    };

    StatusStream stream([&]() { return build_runtime_inventory(context); });
    stream.reconcile();
    stream.reconcile();

    CHECK(callback_calls == 0);
    const nlohmann::json inventory = build_runtime_inventory(context);
    CHECK_FALSE(inventory.contains("tasks"));
    CHECK_FALSE(inventory.contains("diagnostics"));
}

} // namespace keen_pbr3

#endif // WITH_API
