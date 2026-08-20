#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/handler_registry_check.hpp"
#include "../src/api/handlers.hpp"
#include "../src/api/server.hpp"
#include "../src/api/sse_broadcaster.hpp"

#include <filesystem>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {
namespace {

class RegistryTempDir {
public:
    RegistryTempDir() {
        char pattern[] = "/tmp/keen-pbr-registry-consent-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~RegistryTempDir() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

Config registry_test_config() {
    Config config;
    Outbound tunnel;
    tunnel.tag = "wg";
    tunnel.type = OutboundType::INTERFACE;
    tunnel.interface = std::string("nwg1");
    config.outbounds = std::vector<Outbound>{tunnel};
    return config;
}

ApiContext make_registry_test_context(SseBroadcaster& broadcaster) {
    return ApiContext{
        std::string("/nonexistent/config.json"),
        broadcaster,
        []() { return registry_test_config(); },
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
    RegistryConsentState consent_state{RegistryConsentState::enabled};
    bool fail{false};
    std::string body{kBlockedBody};

    RegistryHarness(const int api_port, const bool registry_enabled = true)
        : context(make_registry_test_context(broadcaster)),
          server([api_port]() {
              ApiConfig api_config;
              api_config.listen = "127.0.0.1:" + std::to_string(api_port);
              return api_config;
          }()),
          consent_state(registry_enabled ? RegistryConsentState::enabled
                                         : RegistryConsentState::disabled) {
        clear_registry_check_cache_for_testing();
        register_registry_check_handler_for_test(
            server, context, [this](const std::string& target) {
                {
                    const std::lock_guard<std::mutex> guard(mutex);
                    targets.push_back(target);
                }
                if (fail) throw std::runtime_error("connection refused");
                return body;
            },
            [this]() { return consent_state; },
            [this](bool enabled) {
                consent_state = enabled ? RegistryConsentState::enabled
                                        : RegistryConsentState::disabled;
                return true;
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

httplib::Result post_consent(httplib::Client& client, bool enabled) {
    return client.Post(
        "/api/routing/registry-consent",
        nlohmann::json{{"enabled", enabled}}.dump(),
        "application/json");
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

TEST_CASE("the dedicated consent endpoint changes the durable gate") {
    constexpr int api_port = 18328;
    RegistryHarness harness(api_port, /*registry_enabled=*/false);
    httplib::Client client("127.0.0.1", api_port);

    const auto initial = client.Get("/api/routing/registry-consent");
    REQUIRE(initial);
    CHECK(initial->status == 200);
    CHECK(initial->get_header_value("Cache-Control") == "no-store");

    const auto enabled = post_consent(client, true);
    REQUIRE(enabled);
    CHECK(enabled->status == 200);
    CHECK(enabled->get_header_value("Cache-Control") == "no-store");
    const auto enabled_json = nlohmann::json::parse(enabled->body);
    CHECK(enabled_json.at("enabled").get<bool>());
    CHECK(enabled_json.at("durable").get<bool>());
    CHECK(post_check(client, {{"target", "example.org"}})->status == 200);
    CHECK(harness.asked().size() == 1);

    const auto disabled = post_consent(client, false);
    REQUIRE(disabled);
    CHECK(disabled->status == 200);
    const auto denied = post_check(client, {{"target", "other.example"}});
    REQUIRE(denied);
    CHECK(nlohmann::json::parse(denied->body).at("reason") ==
          "registry_lookup_disabled");
    CHECK(harness.asked().size() == 1);

    const auto extra = client.Post(
        "/api/routing/registry-consent",
        nlohmann::json{{"enabled", true}, {"target", "example.org"}}.dump(),
        "application/json");
    REQUIRE(extra);
    CHECK(extra->status == 400);

    harness.consent_state = RegistryConsentState::absent;
    const auto absent = client.Get("/api/routing/registry-consent");
    REQUIRE(absent);
    CHECK(absent->status == 200);
    const auto absent_json = nlohmann::json::parse(absent->body);
    CHECK_FALSE(absent_json.at("enabled").get<bool>());
    CHECK(absent_json.at("durable").get<bool>());

    harness.consent_state = RegistryConsentState::unreadable;
    const auto unavailable = client.Get("/api/routing/registry-consent");
    REQUIRE(unavailable);
    CHECK(unavailable->status == 503);
    CHECK(unavailable->get_header_value("Cache-Control") == "no-store");
    const auto fail_closed = post_check(client, {{"target", "closed.example"}});
    REQUIRE(fail_closed);
    CHECK(fail_closed->status == 503);
    CHECK(harness.asked().size() == 1);
}

TEST_CASE("registry consent is a private fail-closed atomic sidecar") {
    RegistryTempDir directory;
    const auto path = directory.path / "registry-consent.json";

    CHECK(load_registry_consent_file_for_test(path.string()) ==
          RegistryConsentState::absent);
    CHECK(save_registry_consent_file_for_test(path.string(), true));
    CHECK(load_registry_consent_file_for_test(path.string()) ==
          RegistryConsentState::enabled);

    struct stat metadata {};
    REQUIRE(::stat(path.c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0600);
    CHECK(metadata.st_nlink == 1);
    CHECK(metadata.st_uid == ::geteuid());
    CHECK(metadata.st_gid == ::getegid());

    CHECK(save_registry_consent_file_for_test(path.string(), false));
    CHECK(load_registry_consent_file_for_test(path.string()) ==
          RegistryConsentState::disabled);

    REQUIRE(::chmod(path.c_str(), 0640) == 0);
    CHECK(load_registry_consent_file_for_test(path.string()) ==
          RegistryConsentState::unreadable);
    CHECK(save_registry_consent_file_for_test(path.string(), false));
    CHECK(load_registry_consent_file_for_test(path.string()) ==
          RegistryConsentState::disabled);

    const auto extra_link = directory.path / "consent-link.json";
    REQUIRE(::link(path.c_str(), extra_link.c_str()) == 0);
    CHECK(load_registry_consent_file_for_test(path.string()) ==
          RegistryConsentState::unreadable);
    REQUIRE(::unlink(extra_link.c_str()) == 0);

    {
        std::ofstream damaged(path);
        damaged << "{not-json}\n";
    }
    REQUIRE(::chmod(path.c_str(), 0600) == 0);
    CHECK(load_registry_consent_file_for_test(path.string()) ==
          RegistryConsentState::unreadable);
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

TEST_CASE("untrusted registry response collections and strings are bounded") {
    constexpr int api_port = 18329;
    RegistryHarness harness(api_port);
    nlohmann::json response = {
        {"blocked", true},
        {"blocked_subnets", nlohmann::json::array()},
        {"ips", nlohmann::json::array()},
        {"cdn_providers", nlohmann::json::object()},
        {"geo", {{"organisation", std::string(700, 'o')}}},
    };
    for (int index = 0; index < 50; ++index) {
        response["blocked_subnets"].push_back(
            "192.0.2." + std::to_string(index) + "/32");
        response["ips"].push_back("192.0.2." + std::to_string(index));
        response["cdn_providers"]["provider-" + std::to_string(index)] =
            nlohmann::json::array();
    }
    response["rkn_domain"] = std::string(700, 'd');
    harness.body = response.dump();
    httplib::Client client("127.0.0.1", api_port);

    const auto result = post_check(client, {{"target", "example.org"}});
    REQUIRE(result);
    const auto json = nlohmann::json::parse(result->body);
    CHECK(json.at("blocked_subnets").size() == 32);
    CHECK(json.at("ips").size() == 32);
    CHECK(json.at("cdn_providers").size() == 32);
    CHECK_FALSE(json.contains("rkn_domain"));
    CHECK_FALSE(json.contains("organisation"));
}

}  // namespace keen_pbr3

#endif  // WITH_API
