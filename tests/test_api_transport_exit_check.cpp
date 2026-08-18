#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/handler_transport_exit_check.hpp"
#include "../src/api/handlers.hpp"
#include "../src/api/server.hpp"
#include "../src/api/sse_broadcaster.hpp"

#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {

// The config the endpoint resolves an outbound tag against. One interface
// outbound with a device, and one blackhole - which carries no routing mark,
// and is therefore the shape that has no route for a probe to take.
Config exit_check_test_config() {
    Config config;
    Outbound tunnel;
    tunnel.tag = "wg";
    tunnel.type = OutboundType::INTERFACE;
    tunnel.interface = std::string("nwg1");
    Outbound hole;
    hole.tag = "block";
    hole.type = OutboundType::BLACKHOLE;
    config.outbounds = std::vector<Outbound>{tunnel, hole};
    return config;
}

ApiContext make_exit_check_test_context(SseBroadcaster& broadcaster) {
    ApiContext context{
        std::string("/nonexistent/config.json"),
        broadcaster,
        []() { return exit_check_test_config(); },
        []() { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> {
            return std::nullopt;
        },
        []() {},
        [](const Config&) {},
        []() { return ServiceHealthState{}; },
        []() { return RoutingHealthReport{}; },
        []() { return api::RuntimeOutboundsResponse{}; },
        []() { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) {
            return std::map<std::string, api::ListRefreshStateValue>{};
        },
        [](const std::string&) { return TestRoutingResult{}; },
        []() {},
        []() {},
        [](Config, std::string) { return ConfigApplyResult{}; },
        []() {},
        []() {},
        []() {},
        [](std::optional<std::string>) {
            return ListRefreshOperationResult{};
        },
    };
    return context;
}

struct ProbeCall {
    std::uint32_t fwmark{0};
    std::string device;
};

struct ExitCheckHarness {
    SseBroadcaster broadcaster;
    ApiContext context;
    ApiServer server;
    std::mutex mutex;
    std::vector<ProbeCall> calls;

    explicit ExitCheckHarness(const int api_port)
        : context(make_exit_check_test_context(broadcaster)),
          server([api_port]() {
              ApiConfig api_config;
              api_config.listen =
                  "127.0.0.1:" + std::to_string(api_port);
              return api_config;
          }()) {
        register_transport_exit_check_handler_for_test(
            server,
            context,
            [this](const std::string&,
                   std::uint32_t fwmark,
                   const std::string& device) {
                {
                    const std::lock_guard<std::mutex> guard(mutex);
                    calls.push_back({fwmark, device});
                }
                ExitProbeOutcome outcome;
                outcome.ok = true;
                outcome.attributed = !device.empty();
                // The pinned probe is given a different address from the
                // control, so a successful pair reads as "changed".
                outcome.address =
                    device.empty() ? "198.51.100.9" : "203.0.113.7";
                return outcome;
            });
        server.start();
    }
    ~ExitCheckHarness() { server.stop(); }

    std::vector<ProbeCall> recorded() {
        const std::lock_guard<std::mutex> guard(mutex);
        return calls;
    }
};

httplib::Result post_check(httplib::Client& client,
                           const nlohmann::json& body) {
    return client.Post(
        "/api/transports/exit-check", body.dump(), "application/json");
}

}  // namespace

TEST_CASE("exit check refuses a request that names both targets") {
    constexpr int api_port = 18291;
    ExitCheckHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    const auto response =
        post_check(client, {{"outbound", "wg"}, {"interface", "nwg1"}});

    REQUIRE(response);
    // Refused rather than resolved in either favour: a caller that does not
    // know which it meant must not have the choice made for it.
    CHECK(response->status == 400);
    CHECK(harness.recorded().empty());
}

TEST_CASE("exit check refuses a request that names neither target") {
    constexpr int api_port = 18292;
    ExitCheckHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    const auto response = post_check(client, nlohmann::json::object());

    REQUIRE(response);
    CHECK(response->status == 400);
    CHECK(harness.recorded().empty());
}

TEST_CASE("exit check refuses a target of the wrong type") {
    constexpr int api_port = 18293;
    ExitCheckHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    // A number is not a name. Accepting it would mean deciding what the
    // caller meant, which is the same mistake as accepting both.
    const auto response = post_check(client, {{"outbound", 7}});

    REQUIRE(response);
    CHECK(response->status == 400);
    CHECK(harness.recorded().empty());
}

TEST_CASE("exit check reports an outbound this config does not have") {
    constexpr int api_port = 18294;
    ExitCheckHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    const auto response = post_check(client, {{"outbound", "absent"}});

    REQUIRE(response);
    CHECK(response->status == 404);
    CHECK(harness.recorded().empty());
}

TEST_CASE("exit check refuses an outbound that carries no routing mark") {
    constexpr int api_port = 18295;
    ExitCheckHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    // No mark means no policy table selects it, so there is no route for a
    // probe to take. Probing anyway would measure the router's own
    // connection and report it under this outbound's name.
    const auto response = post_check(client, {{"outbound", "block"}});

    REQUIRE(response);
    CHECK(response->status == 409);
    CHECK(harness.recorded().empty());
}

TEST_CASE("exit check measures an outbound through its device and mark") {
    constexpr int api_port = 18296;
    ExitCheckHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    const auto response = post_check(client, {{"outbound", "wg"}});

    REQUIRE(response);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("verdict") == "working");
    CHECK(body.at("exit_address") == "changed");
    CHECK(body.at("through").at("address") == "203.0.113.7");

    const auto calls = harness.recorded();
    REQUIRE(calls.size() == 2U);
    CHECK(calls[0].device == "nwg1");
    CHECK(calls[0].fwmark != 0U);
    // The control is deliberately unmarked and unbound - it is the answer the
    // router gives without this transport.
    CHECK(calls[1].device.empty());
    CHECK(calls[1].fwmark == 0U);
}

TEST_CASE("exit check measures a native tunnel that has no outbound at all") {
    constexpr int api_port = 18297;
    ExitCheckHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    // The whole point of the interface form: a native firmware tunnel has no
    // keen-pbr outbound and no mark, and binding to its device is what makes
    // the answer attributable.
    const auto response = post_check(client, {{"interface", "nwg7"}});

    REQUIRE(response);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("verdict") == "working");
    CHECK(body.at("through").at("attributed") == true);

    const auto calls = harness.recorded();
    REQUIRE(calls.size() == 2U);
    CHECK(calls[0].device == "nwg7");
    CHECK(calls[0].fwmark == 0U);
    CHECK(calls[1].device.empty());
}

TEST_CASE("exit check refuses an interface name the kernel could not hold") {
    constexpr int api_port = 18298;
    ExitCheckHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    for (const auto& name :
         {std::string(""), std::string(20U, 'x'), std::string("a/b")}) {
        const auto response = post_check(client, {{"interface", name}});
        REQUIRE(response);
        CHECK(response->status == 400);
    }
    CHECK(harness.recorded().empty());
}

}  // namespace keen_pbr3

#endif  // WITH_API
