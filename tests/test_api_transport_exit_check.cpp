#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/handler_transport_exit_check.hpp"
#include "../src/api/handlers.hpp"
#include "../src/api/server.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/http/http_transport.hpp"

#include <atomic>
#include <chrono>
#include <future>
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

    explicit ExitCheckHarness(const int api_port,
                              ExitEchoFetcher fetcher = {})
        : context(make_exit_check_test_context(broadcaster)),
          server([api_port]() {
              ApiConfig api_config;
              api_config.listen =
                  "127.0.0.1:" + std::to_string(api_port);
              return api_config;
          }()) {
        if (!fetcher) {
            fetcher = [this](const std::string&,
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
            };
        }
        register_transport_exit_check_handler_for_test(
            server, context, std::move(fetcher));
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

class ExitEchoTransport final : public HttpTransport {
public:
    enum class Failure {
        none,
        bind,
        network,
    };

    HttpTransportRequest request;
    Failure failure{Failure::none};

    HttpTransportResponse perform(
        const HttpTransportRequest& value) override {
        request = value;
        if (failure == Failure::bind) {
            throw HttpTransportBindError(
                "SO_BINDTODEVICE(nwg1) failed: no such device");
        }
        if (failure == Failure::network) {
            throw HttpTransportError("connection timed out");
        }
        return {200, "8.8.8.8\n", {}, std::chrono::milliseconds(4)};
    }
};

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

TEST_CASE("exit echo filters every resolved destination class") {
    auto transport = std::make_shared<ExitEchoTransport>();

    const auto outcome = fetch_transport_exit_echo_for_test(
        transport, "https://api.ipify.org", 0x00010000U, "nwg1");

    REQUIRE(outcome.ok);
    REQUIRE(static_cast<bool>(transport->request.destination_filter));
    const auto& permitted = transport->request.destination_filter;
    CHECK_FALSE(permitted("127.0.0.1"));
    CHECK_FALSE(permitted("192.168.1.1"));
    CHECK_FALSE(permitted("169.254.169.254"));
    CHECK_FALSE(permitted("::1"));
    CHECK_FALSE(permitted("fe80::1"));
    CHECK_FALSE(permitted("fd00::1"));
    CHECK(permitted("8.8.8.8"));
    CHECK(permitted("2606:4700:4700::1111"));
}

TEST_CASE("exit echo reports an interface bind failure as unattributed") {
    auto transport = std::make_shared<ExitEchoTransport>();
    transport->failure = ExitEchoTransport::Failure::bind;

    const auto outcome = fetch_transport_exit_echo_for_test(
        transport, "https://api.ipify.org", 0x00010000U, "nwg1");

    CHECK_FALSE(outcome.ok);
    CHECK_FALSE(outcome.attributed);
    CHECK(exit_check_verdict(outcome) == ExitCheckVerdict::unattributed);
}

TEST_CASE("exit echo keeps post-bind network failures attributable") {
    auto transport = std::make_shared<ExitEchoTransport>();
    transport->failure = ExitEchoTransport::Failure::network;

    const auto outcome = fetch_transport_exit_echo_for_test(
        transport, "https://api.ipify.org", 0x00010000U, "nwg1");

    CHECK_FALSE(outcome.ok);
    CHECK(outcome.attributed);
    CHECK(exit_check_verdict(outcome) == ExitCheckVerdict::unreachable);
}

TEST_CASE("exit echo attributes a mark-only table outbound") {
    auto transport = std::make_shared<ExitEchoTransport>();

    SUBCASE("a successful marked request is working") {
        const auto outcome = fetch_transport_exit_echo_for_test(
            transport, "https://api.ipify.org", 0x00010000U, {});

        CHECK(outcome.ok);
        CHECK(outcome.attributed);
        CHECK(exit_check_verdict(outcome) == ExitCheckVerdict::working);
        CHECK(transport->request.bind_interface.empty());
        CHECK(transport->request.fwmark == 0x00010000U);
    }

    SUBCASE("a marked network failure stays attributable") {
        transport->failure = ExitEchoTransport::Failure::network;
        const auto outcome = fetch_transport_exit_echo_for_test(
            transport, "https://api.ipify.org", 0x00010000U, {});

        CHECK_FALSE(outcome.ok);
        CHECK(outcome.attributed);
        CHECK(exit_check_verdict(outcome) == ExitCheckVerdict::unreachable);
    }
}

TEST_CASE("exit check rejects a concurrent probe without invoking its fetcher") {
    using namespace std::chrono_literals;

    constexpr int api_port = 18299;
    std::promise<void> first_entered_promise;
    auto first_entered = first_entered_promise.get_future();
    std::promise<void> release_first_promise;
    auto release_first = release_first_promise.get_future().share();
    std::atomic<int> calls{0};

    ExitCheckHarness harness(
        api_port,
        [&](const std::string&, std::uint32_t,
            const std::string& device) {
            const int call = calls.fetch_add(1) + 1;
            if (call == 1) {
                first_entered_promise.set_value();
                release_first.wait();
            }
            ExitProbeOutcome outcome;
            outcome.ok = true;
            outcome.attributed = !device.empty();
            outcome.address =
                device.empty() ? "198.51.100.9" : "203.0.113.7";
            return outcome;
        });

    auto first_client =
        std::make_shared<httplib::Client>("127.0.0.1", api_port);
    first_client->set_read_timeout(5);
    auto first_request = std::async(std::launch::async, [first_client]() {
        return post_check(*first_client, {{"interface", "nwg1"}});
    });

    const bool first_was_admitted =
        first_entered.wait_for(3s) == std::future_status::ready;
    bool concurrent_was_rejected = false;
    int calls_before_release = calls.load();
    if (first_was_admitted) {
        httplib::Client second_client("127.0.0.1", api_port);
        second_client.set_read_timeout(3);
        const auto response =
            post_check(second_client, {{"interface", "nwg7"}});
        concurrent_was_rejected = response && response->status == 503;
        calls_before_release = calls.load();
    }

    release_first_promise.set_value();
    const auto completion = first_request.wait_for(5s);
    if (completion != std::future_status::ready) {
        first_client->stop();
    }

    CHECK(first_was_admitted);
    CHECK(concurrent_was_rejected);
    CHECK(calls_before_release == 1);
    REQUIRE(completion == std::future_status::ready);
    const auto first_response = first_request.get();
    REQUIRE(first_response);
    CHECK(first_response->status == 200);
    CHECK(calls.load() == 2);
}

}  // namespace keen_pbr3

#endif  // WITH_API
