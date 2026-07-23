#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_runtime_inventory.hpp"
#include "../src/api/sse_broadcaster.hpp"

namespace keen_pbr3 {
namespace {

constexpr const char* kInventoryListen = "127.0.0.1:18194";
const std::string kInventoryConfigPath = "/tmp/keen-pbr-inventory-test.json";

ApiContext make_inventory_context(SseBroadcaster& broadcaster) {
    return ApiContext{
        kInventoryConfigPath,
        broadcaster,
        [] { return Config{}; },
        [] { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> {
            return std::nullopt;
        },
        [] {},
        [](const Config&) {},
        [] {
            ServiceHealthState state;
            state.status = api::HealthResponseStatus::RUNNING;
            state.runtime_state = "running";
            return state;
        },
        [] { return RoutingHealthReport{}; },
        [] {
            api::RuntimeOutboundsResponse response;
            api::RuntimeOutboundStateElement outbound;
            outbound.tag = "vpn";
            outbound.type = api::OutboundType::INTERFACE;
            outbound.status = api::ResolverLiveStatus::HEALTHY;
            response.outbounds.push_back(std::move(outbound));
            return response;
        },
        [] {
            api::RuntimeInterfaceInventoryResponse response;
            api::RuntimeInterfaceInventoryEntry interface;
            interface.name = "wg0";
            interface.status = api::RuntimeInterfaceInventoryStatusEnum::UP;
            response.interfaces.push_back(std::move(interface));
            return response;
        },
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
}

} // namespace

TEST_CASE("runtime inventory composes existing runtime providers") {
    SseBroadcaster broadcaster;
    auto context = make_inventory_context(broadcaster);
    const auto inventory = build_runtime_inventory(context);

    CHECK(inventory.service.status == api::HealthResponseStatus::RUNNING);
    REQUIRE(inventory.outbounds.outbounds.size() == 1);
    CHECK(inventory.outbounds.outbounds.front().tag == "vpn");
    REQUIRE(inventory.interfaces.interfaces.size() == 1);
    CHECK(inventory.interfaces.interfaces.front().name == "wg0");
}

TEST_CASE("runtime inventory endpoint returns the canonical snapshot") {
    SseBroadcaster broadcaster;
    auto context = make_inventory_context(broadcaster);
    ApiConfig config;
    config.listen = std::string(kInventoryListen);
    ApiServer server(config);
    register_runtime_inventory_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", 18194);
    const auto response = client.Get("/api/runtime/inventory");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body["service"]["status"] == "running");
    CHECK(body["outbounds"]["outbounds"][0]["tag"] == "vpn");
    CHECK(body["interfaces"]["interfaces"][0]["name"] == "wg0");
}

} // namespace keen_pbr3

#endif // WITH_API
