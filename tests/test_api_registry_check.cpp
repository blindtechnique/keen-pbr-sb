#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/handler_registry_check.hpp"
#include "../src/api/handlers.hpp"
#include "../src/api/server.hpp"
#include "../src/api/sse_broadcaster.hpp"

#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {

Config registry_test_config(bool registry_enabled) {
    Config config;
    api::UiPreferences preferences;
    preferences.registry_lookup_enabled = registry_enabled;
    config.ui_preferences = preferences;
    Outbound tunnel;
    tunnel.tag = "wg";
    tunnel.type = OutboundType::INTERFACE;
    tunnel.interface = std::string("nwg1");
    config.outbounds = std::vector<Outbound>{tunnel};
    return config;
}

ApiContext make_registry_test_context(SseBroadcaster& broadcaster,
                                      bool registry_enabled) {
    return ApiContext{
        std::string("/nonexistent/config.json"),
        broadcaster,
        [registry_enabled]() { return registry_test_config(registry_enabled); },
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
}

// A trimmed copy of a real cheburcheck response, so the parsing under test is
// the parsing that will meet the service.
constexpr const char* kBlockedBody = R"({
  "id": "01a01bd4-67e4-778a-bf78-165533a587a2",
  "target": "rutracker.org",
  "target_type": "Домен",
  "blocked": true,
  "rkn_domain": "rutracker.org",
  "ips": ["104.21.32.39", "172.67.182.196"],
  "blocked_subnets": ["104.21.32.0/24"],
  "cdn_providers": {"cloudflare": [{"provider": "cloudflare"}]},
  "geo": {"asn": "AS13335", "organisation": "Cloudflare, Inc."},
  "reverse_lookup": []
})";

struct RegistryHarness {
    SseBroadcaster broadcaster;
    ApiContext context;
    ApiServer server;
    std::mutex mutex;
    std::vector<std::string> targets;
    bool fail{false};
    std::string body{kBlockedBody};

    RegistryHarness(const int api_port, const bool registry_enabled = true)
        : context(make_registry_test_context(broadcaster, registry_enabled)),
          server([api_port]() {
              ApiConfig api_config;
              api_config.listen = "127.0.0.1:" + std::to_string(api_port);
              return api_config;
          }()) {
        clear_registry_check_cache_for_testing();
        register_registry_check_handler_for_test(
            server, context, [this](const std::string& target) {
                {
                    const std::lock_guard<std::mutex> guard(mutex);
                    targets.push_back(target);
                }
                if (fail) throw std::runtime_error("connection refused");
                return body;
            });
        server.start();
    }
    ~RegistryHarness() {
        server.stop();
        clear_registry_check_cache_for_testing();
    }

    std::vector<std::string> asked() {
        const std::lock_guard<std::mutex> guard(mutex);
        return targets;
    }
};

httplib::Result post_check(httplib::Client& client,
                           const nlohmann::json& body) {
    return client.Post(
        "/api/routing/registry-check", body.dump(), "application/json");
}

}  // namespace

TEST_CASE("the daemon's own setting decides, not the request") {
    constexpr int api_port = 18321;
    RegistryHarness harness(api_port, /*registry_enabled=*/false);
    httplib::Client client("127.0.0.1", api_port);

    // The request asks as loudly as it can. It does not matter: consent lives
    // in the configuration, so a browser cannot authorise the lookup by
    // claiming it may.
    const auto response = post_check(
        client,
        {{"target", "rutracker.org"}, {"allow_external_lookup", true}});

    REQUIRE(response);
    CHECK(response->status == 200);
    const auto json = nlohmann::json::parse(response->body);
    CHECK_FALSE(json.at("checked").get<bool>());
    CHECK(json.at("reason") == "registry_lookup_disabled");
    CHECK(harness.asked().empty());
}

TEST_CASE("registry check reports the verdict and credits the service") {
    constexpr int api_port = 18322;
    RegistryHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    const auto response = post_check(client, {{"target", "RuTracker.ORG "}});

    REQUIRE(response);
    CHECK(response->status == 200);
    const auto json = nlohmann::json::parse(response->body);
    CHECK(json.at("checked").get<bool>());
    CHECK(json.at("blocked").get<bool>());
    CHECK(json.at("service") == "cheburcheck.ru");
    CHECK(json.at("rkn_domain") == "rutracker.org");
    CHECK(json.at("target") == "rutracker.org");
    CHECK(
        json.at("blocked_subnets").get<std::vector<std::string>>() ==
        std::vector<std::string>{"104.21.32.0/24"});
    CHECK(
        json.at("cdn_providers").get<std::vector<std::string>>() ==
        std::vector<std::string>{"cloudflare"});
    CHECK(json.at("organisation") == "Cloudflare, Inc.");
    CHECK_FALSE(json.at("cached").get<bool>());
    // Trimmed and lowercased before it is sent, so the cache key and the URL
    // do not depend on how it was typed.
    CHECK(harness.asked() == std::vector<std::string>{"rutracker.org"});
}

TEST_CASE("a second look at the same target does not ask again") {
    constexpr int api_port = 18323;
    RegistryHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    post_check(client, {{"target", "rutracker.org"}});
    const auto again = post_check(client, {{"target", "rutracker.org"}});

    REQUIRE(again);
    const auto json = nlohmann::json::parse(again->body);
    CHECK(json.at("cached").get<bool>());
    CHECK(json.at("blocked").get<bool>());
    CHECK(harness.asked().size() == 1);
}

TEST_CASE("a failed lookup is not a clean bill of health") {
    constexpr int api_port = 18324;
    RegistryHarness harness(api_port);
    harness.fail = true;
    httplib::Client client("127.0.0.1", api_port);

    const auto response = post_check(client, {{"target", "example.org"}});

    REQUIRE(response);
    CHECK(response->status == 200);
    const auto json = nlohmann::json::parse(response->body);
    CHECK_FALSE(json.at("checked").get<bool>());
    CHECK(json.at("reason") == "lookup_failed");
    // The field that would read as "not blocked" must be absent, not false.
    CHECK(json.find("blocked") == json.end());
}

TEST_CASE("an unreadable answer is reported as unreadable") {
    constexpr int api_port = 18325;
    RegistryHarness harness(api_port);
    harness.body = "<html>captive portal</html>";
    httplib::Client client("127.0.0.1", api_port);

    const auto response = post_check(client, {{"target", "example.org"}});

    REQUIRE(response);
    const auto json = nlohmann::json::parse(response->body);
    CHECK_FALSE(json.at("checked").get<bool>());
    CHECK(json.at("reason") == "unreadable_response");
    CHECK(json.find("blocked") == json.end());
}

TEST_CASE("a target that could not be a host is refused, not escaped") {
    constexpr int api_port = 18326;
    RegistryHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    for (const auto* target : {"example.org/../admin",
                               "example.org&target=other",
                               "example.org?x=1",
                               "exa mple.org",
                               ""}) {
        const auto response = post_check(client, {{"target", target}});
        REQUIRE(response);
        CHECK(response->status == 400);
    }
    CHECK(harness.asked().empty());
}

TEST_CASE("an address is a valid target, not only a domain") {
    constexpr int api_port = 18327;
    RegistryHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    CHECK(post_check(client, {{"target", "104.21.32.39"}})->status == 200);
    CHECK(post_check(client, {{"target", "2606:4700:3037::ac43:b6c4"}})
              ->status == 200);
    CHECK(harness.asked().size() == 2);
}

}  // namespace keen_pbr3

#endif  // WITH_API
