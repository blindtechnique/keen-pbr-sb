#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/handler_subscriptions.hpp"
#include "../src/api/maintenance_api.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/config/subscription_import_plan.hpp"
#include "../src/http/curl_runtime.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

namespace keen_pbr3 {
namespace {

class SubscriptionsTempDir {
public:
    SubscriptionsTempDir() {
        char pattern[] = "/tmp/keen-pbr-api-subscriptions-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }
    ~SubscriptionsTempDir() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }
    std::filesystem::path path;
};

class SubscriptionsTestMaintenanceLease final : public MaintenanceLease {
public:
    std::uint32_t base_generation() const noexcept override { return 1U; }
    std::uint32_t reserve(std::uint32_t expected) override {
        return expected + 1U;
    }
    void verify_held() override {}
};

ApiContext make_subscriptions_test_context(
    SseBroadcaster& broadcaster,
    const std::string& config_path) {
    ApiContext context{
        config_path,
        broadcaster,
        []() { return Config{}; },
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
    context.maintenance_lease_factory_fn =
        [](std::string) -> std::unique_ptr<MaintenanceLease> {
        return std::make_unique<SubscriptionsTestMaintenanceLease>();
    };
    return context;
}

// One fixture: a manager holding a vless transport whose link identity is
// published only as a fingerprint, exactly like production redaction.
const std::string kConfiguredLink = "vless://u@a.example:443#Existing";

struct FakeManager {
    httplib::Server server;
    std::thread thread;
    int port{0};
    std::vector<nlohmann::json> created;
    std::atomic<int> create_status{201};
    std::string create_error_body;

    explicit FakeManager(const std::filesystem::path& directory) {
        server.Get(
            "/v1/config/transports",
            [](const httplib::Request& request,
               httplib::Response& response) {
                if (request.get_header_value("Authorization") !=
                    "Bearer test-secret") {
                    response.status = 401;
                    return;
                }
                response.set_content(
                    nlohmann::json::array(
                        {{{"tag", "nl"},
                          {"type", "sing-box"},
                          {"interface", "vless1"},
                          {"link_fingerprint",
                           subscription_link_fingerprint(
                               kConfiguredLink)}}})
                        .dump(),
                    "application/json");
            });
        server.Post(
            "/v1/config/transports",
            [this](const httplib::Request& request,
                   httplib::Response& response) {
                if (request.get_header_value("Authorization") !=
                    "Bearer test-secret") {
                    response.status = 401;
                    return;
                }
                created.push_back(nlohmann::json::parse(request.body));
                response.status = create_status.load();
                if (response.status >= 300) {
                    response.set_content(create_error_body, "text/plain");
                } else {
                    response.set_content(
                        nlohmann::json{{"status", "created"}}.dump(),
                        "application/json");
                }
            });
        port = server.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        {
            std::ofstream config(directory / "transports.json");
            config << nlohmann::json{
                {"listen", "127.0.0.1:" + std::to_string(port)},
                {"api_key", "test-secret"},
            };
        }
        thread = std::thread([this]() { server.listen_after_bind(); });
        while (!server.is_running()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    ~FakeManager() {
        server.stop();
        thread.join();
    }
};

struct SubscriptionsHarness {
    SubscriptionsTempDir directory;
    std::unique_ptr<FakeManager> manager;
    SseBroadcaster broadcaster;
    ApiContext context;
    ApiServer server;
    std::size_t fetch_calls{0};
    std::string fetch_body;

    explicit SubscriptionsHarness(const int api_port,
                                  const bool with_manager = true)
        : context(make_subscriptions_test_context(
              broadcaster,
              (directory.path / "config.json").string())),
          server([api_port]() {
              ApiConfig api_config;
              api_config.listen =
                  "127.0.0.1:" + std::to_string(api_port);
              return api_config;
          }()) {
        if (with_manager) {
            manager = std::make_unique<FakeManager>(directory.path);
        }
        register_subscriptions_handler_for_test(
            server,
            context,
            [this](const std::string&) {
                ++fetch_calls;
                return fetch_body;
            });
        server.start();
    }
    ~SubscriptionsHarness() { server.stop(); }
};

std::string preview_and_get_id(httplib::Client& client,
                               const char* url =
                                   "https://provider.example/sub") {
    const auto response = client.Post(
        "/api/subscriptions/preview",
        nlohmann::json{{"url", url}}.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    return nlohmann::json::parse(response->body)
        .at("preview_id")
        .get<std::string>();
}

} // namespace

TEST_CASE("a refused URL never reaches the fetcher") {
    constexpr int api_port = 18281;
    SubscriptionsHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    struct Refusal {
        const char* url;
        const char* reason;
    };
    const Refusal refusals[] = {
        {"file:///etc/shadow", "scheme_not_allowed"},
        {"https://user:pass@provider.example/sub", "credentials_in_url"},
        {"http://127.0.0.1:79/rci/", "destination_not_permitted"},
        {"not a url", "malformed"},
    };
    for (const auto& refusal : refusals) {
        const auto response = client.Post(
            "/api/subscriptions/preview",
            nlohmann::json{{"url", refusal.url}}.dump(),
            "application/json");
        REQUIRE(response != nullptr);
        CHECK(response->status == 400);
        CHECK(nlohmann::json::parse(response->body)
                  .at("reason")
                  .get<std::string>() == refusal.reason);
    }
    CHECK(harness.fetch_calls == 0U);
}

TEST_CASE("preview plans against the manager's redacted state") {
    constexpr int api_port = 18282;
    SubscriptionsHarness harness(api_port);
    harness.fetch_body =
        kConfiguredLink + "\n" +
        "vless://22222222-2222-2222-2222-222222222222@b.example:443#Fresh\n"
        "vless://22222222-2222-2222-2222-222222222222@b.example:443#Fresh\n"
        "trojan://secret@c.example:8443#NL\n";
    httplib::Client client("127.0.0.1", api_port);

    const auto response = client.Post(
        "/api/subscriptions/preview",
        nlohmann::json{{"url", "https://provider.example/sub"}}.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    CHECK(harness.fetch_calls == 1U);

    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("document_kind") == "link_list");
    CHECK(body.at("expires_in_seconds").get<int>() == 600);
    const auto preview_id = body.at("preview_id").get<std::string>();
    CHECK(preview_id.size() == 64U);

    const auto& candidates = body.at("candidates");
    REQUIRE(candidates.size() == 4U);
    // Line 1 is the transport the manager already has - recognised through
    // its fingerprint, the only identity redaction leaves.
    CHECK(candidates[0].at("disposition") == "already_configured");
    CHECK(candidates[1].at("disposition") == "importable");
    CHECK(candidates[2].at("disposition") == "duplicate_in_document");
    CHECK(candidates[2].at("duplicate_of").get<int>() == 2);
    // "nl" is taken by the existing transport's tag.
    CHECK(candidates[3].at("disposition") == "tag_conflict");

    // The response carries no link and no credential, anywhere.
    CHECK(response->body.find("22222222-2222") == std::string::npos);
    CHECK(response->body.find("vless://") == std::string::npos);
    CHECK(response->body.find("secret") == std::string::npos);
}

TEST_CASE("preview refuses to plan without the manager") {
    // Without tags and fingerprints the plan cannot judge conflicts, and a
    // preview that silently skipped that judgement would read as "no
    // conflicts". The manager is consulted before the fetch.
    constexpr int api_port = 18283;
    SubscriptionsHarness harness(api_port, false);
    httplib::Client client("127.0.0.1", api_port);

    const auto response = client.Post(
        "/api/subscriptions/preview",
        nlohmann::json{{"url", "https://provider.example/sub"}}.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    CHECK(response->status == 503);
    CHECK(harness.fetch_calls == 0U);
}

TEST_CASE("apply creates the selected entry through the manager") {
    constexpr int api_port = 18284;
    SubscriptionsHarness harness(api_port);
    harness.fetch_body =
        "vless://22222222-2222-2222-2222-222222222222@b.example:443"
        "#Fresh%20NL\n";
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    const auto response = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections", nlohmann::json::array({{{"line", 1}}})},
        }
            .dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);

    const auto body = nlohmann::json::parse(response->body);
    REQUIRE(body.at("results").size() == 1U);
    const auto& result = body.at("results")[0];
    CHECK(result.at("outcome") == "created");
    CHECK(result.at("tag") == "fresh_nl");
    // vless1 belongs to the existing transport; the derived name is the next
    // free one, by the same rule the manual dialog uses.
    CHECK(result.at("interface") == "vless2");

    // What reached the manager is the full spec, link included: the create
    // pipeline is the manager's, not a parallel writer.
    REQUIRE(harness.manager->created.size() == 1U);
    const auto& spec = harness.manager->created.front();
    CHECK(spec.at("tag") == "fresh_nl");
    CHECK(spec.at("type") == "sing-box");
    CHECK(spec.at("interface") == "vless2");
    CHECK(spec.at("link").get<std::string>().find(
              "22222222-2222-2222-2222-222222222222") !=
          std::string::npos);
    CHECK(spec.at("auto_start") == false);
    CHECK(spec.at("display_name") == "Fresh NL");

    // A preview is a one-shot import: the consumed line cannot be created
    // twice, and saying so is a per-entry outcome, not a request failure.
    const auto again = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections", nlohmann::json::array({{{"line", 1}}})},
        }
            .dump(),
        "application/json");
    REQUIRE(again != nullptr);
    REQUIRE(again->status == 200);
    const auto second = nlohmann::json::parse(again->body);
    // Not a failure: nothing went wrong and there is nothing to fix. Its own
    // outcome, so the UI need not read an English error string to tell a
    // benign repeat from a real one.
    CHECK(second.at("results")[0].at("outcome") == "already_imported");
    CHECK(second.at("results")[0].at("error").is_null());
    CHECK(harness.manager->created.size() == 1U);
}

TEST_CASE("apply refuses what the preview did not offer") {
    constexpr int api_port = 18285;
    SubscriptionsHarness harness(api_port);
    harness.fetch_body =
        "vless://u@b.example:443#Fresh\n"
        "ssr://unsupported\n"
        "trojan://secret@c.example:8443#NL\n";
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    const auto expect_400 = [&client,
                             &preview_id](nlohmann::json selections) {
        const auto response = client.Post(
            "/api/subscriptions/apply",
            nlohmann::json{
                {"preview_id", preview_id},
                {"selections", std::move(selections)},
            }
                .dump(),
            "application/json");
        REQUIRE(response != nullptr);
        CHECK(response->status == 400);
    };

    // A line the preview never produced.
    expect_400(nlohmann::json::array({{{"line", 99}}}));
    // An unsupported scheme does not become importable because the caller
    // insists.
    expect_400(nlohmann::json::array({{{"line", 2}}}));
    // A conflicted tag without a resolution.
    expect_400(nlohmann::json::array({{{"line", 3}}}));
    // A malformed override tag.
    expect_400(nlohmann::json::array({{{"line", 1}, {"tag", "Bad-Tag"}}}));
    // The same line twice in one request is a caller bug, not two imports.
    expect_400(nlohmann::json::array({{{"line", 1}}, {{"line", 1}}}));

    // An unknown preview is gone, not invalid.
    const auto gone = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", std::string(64U, 'a')},
            {"selections", nlohmann::json::array({{{"line", 1}}})},
        }
            .dump(),
        "application/json");
    REQUIRE(gone != nullptr);
    CHECK(gone->status == 410);

    CHECK(harness.manager->created.empty());

    // The conflicted tag becomes importable exactly when the operator
    // resolves it by choosing another name.
    const auto resolved = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections",
             nlohmann::json::array({{{"line", 3}, {"tag", "nl_two"}}})},
        }
            .dump(),
        "application/json");
    REQUIRE(resolved != nullptr);
    REQUIRE(resolved->status == 200);
    const auto body = nlohmann::json::parse(resolved->body);
    CHECK(body.at("results")[0].at("outcome") == "created");
    CHECK(body.at("results")[0].at("tag") == "nl_two");
    REQUIRE(harness.manager->created.size() == 1U);
    CHECK(harness.manager->created.front().at("tag") == "nl_two");
}

TEST_CASE("a manager error that echoes the link is not repeated") {
    // The manager's share-link parser wraps url.Parse errors, and Go's url
    // errors quote the URL they failed on - credential included. An error
    // that names the secret it refused to store is worse than a blunt one.
    constexpr int api_port = 18286;
    SubscriptionsHarness harness(api_port);
    const std::string link =
        "vless://33333333-3333-3333-3333-333333333333@d.example:443#X";
    harness.fetch_body = link + "\n";
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    harness.manager->create_status = 400;
    harness.manager->create_error_body =
        "invalid connection link: parse \"" + link + "\": bad";

    const auto response = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections", nlohmann::json::array({{{"line", 1}}})},
        }
            .dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("results")[0].at("outcome") == "failed");
    const auto error =
        body.at("results")[0].at("error").get<std::string>();
    CHECK(error.find("33333333-3333") == std::string::npos);
    CHECK(error.find("HTTP 400") != std::string::npos);
    // A partial echo is the same leak: the credential lives between "://"
    // and "@", and an error quoting only that fragment has quoted the secret.
    harness.manager->create_error_body =
        "user \"33333333-3333-3333-3333-333333333333\" is not valid";
    const auto partial = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections", nlohmann::json::array({{{"line", 1}}})},
        }
            .dump(),
        "application/json");
    REQUIRE(partial != nullptr);
    CHECK(nlohmann::json::parse(partial->body)
              .at("results")[0]
              .at("error")
              .get<std::string>()
              .find("33333333-3333") == std::string::npos);

    // ...and an error that does not echo the link passes through, because
    // the manager's text is the useful one.
    harness.manager->create_error_body = "tag already exists";
    const auto second = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections", nlohmann::json::array({{{"line", 1}}})},
        }
            .dump(),
        "application/json");
    REQUIRE(second != nullptr);
    const auto second_body = nlohmann::json::parse(second->body);
    CHECK(second_body.at("results")[0]
              .at("error")
              .get<std::string>() == "tag already exists");
}

TEST_CASE("the production fetcher carries the destination policy") {
    // Everything above injects a fetcher; this pins the wiring itself. A
    // fetcher without the filter behaves identically on every allowed
    // destination and differs only where it must refuse - so the test asks
    // for a loopback URL with a hostname, which stage 1 cannot catch.
    CurlRuntime curl_runtime;
    const auto fetcher = make_subscription_fetcher();
    try {
        (void)fetcher("http://localhost:9/sub");
        FAIL("Expected the destination policy to refuse loopback");
    } catch (const ApiError& error) {
        CHECK(error.status() == 502);
        CHECK(std::string(error.what()).find("destination policy") !=
              std::string::npos);
    }
}

} // namespace keen_pbr3

#endif // WITH_API
