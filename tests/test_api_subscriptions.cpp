#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/handler_subscriptions.hpp"
#include "../src/api/maintenance_api.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/config/config_writer.hpp"
#include "../src/config/subscription_import_plan.hpp"
#include "../src/crypto/sha256.hpp"
#include "../src/http/curl_runtime.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
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
        [](Config, std::string) {
            return ConfigApplyResult{true, false, std::nullopt, {}};
        },
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
    context.restart_restore_service_fn =
        [](const std::string&) { return 0; };
    return context;
}

// One fixture: a manager holding a vless transport whose link identity is
// published only as a fingerprint, exactly like production redaction.
const std::string kConfiguredLink = "vless://u@a.example:443#Existing";

struct FakeManager {
    httplib::Server server;
    std::thread thread;
    int port{0};
    std::filesystem::path config_path;
    std::mutex mutex;
    std::string current_revision;
    std::vector<nlohmann::json> created;
    std::atomic<int> create_status{201};
    std::string create_error_body;
    std::atomic<int> batch_validate_calls{0};
    std::atomic<int> batch_create_calls{0};
    std::atomic<int> item_validate_calls{0};
    std::atomic<int> runtime_ready_calls{0};
    std::atomic<int> runtime_ready_after_calls{1};
    std::vector<std::string> last_runtime_ready_tags;
    std::string rejected_link;
    std::string late_existing_link;
    std::atomic<bool> expose_late_existing{false};
    std::atomic<bool> expose_late_identity{true};
    std::atomic<bool> expose_duplicate_late_identity{false};
    std::atomic<bool> rotated_api_key{false};

    explicit FakeManager(const std::filesystem::path& directory)
        : config_path(directory / "transports.json") {
        const auto authorized = [this](
                                    const httplib::Request& request,
                                    httplib::Response& response) {
            const auto expected = rotated_api_key.load(
                                      std::memory_order_acquire)
                                      ? "Bearer rotated-secret"
                                      : "Bearer test-secret";
            if (request.get_header_value("Authorization") != expected) {
                response.status = 401;
                return false;
            }
            return true;
        };
        server.Get(
            "/v1/config/transports",
            [this, authorized](const httplib::Request& request,
                   httplib::Response& response) {
                if (!authorized(request, response)) return;
                auto transports = nlohmann::json::array(
                    {{{"tag", "nl"},
                      {"type", "sing-box"},
                      {"interface", "vless1"},
                      {"link_fingerprint",
                       subscription_link_fingerprint(kConfiguredLink)}}});
                if (expose_late_existing.load(std::memory_order_acquire)) {
                    nlohmann::json late{
                        {"type", "sing-box"},
                        {"link_fingerprint",
                         subscription_link_fingerprint(late_existing_link)},
                    };
                    if (expose_late_identity.load(
                            std::memory_order_acquire)) {
                        late["tag"] = "winner";
                        late["interface"] = "vless9";
                    }
                    transports.push_back(std::move(late));
                    if (expose_duplicate_late_identity.load(
                            std::memory_order_acquire)) {
                        transports.push_back(
                            {{"tag", "other-winner"},
                             {"type", "sing-box"},
                             {"interface", "vless10"},
                             {"link_fingerprint",
                              subscription_link_fingerprint(
                                  late_existing_link)}});
                    }
                }
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    for (const auto& spec : created) {
                        auto redacted = spec;
                        if (redacted.contains("link") &&
                            redacted.at("link").is_string()) {
                            redacted["link_fingerprint"] =
                                subscription_link_fingerprint(
                                    redacted.at("link").get<std::string>());
                            redacted.erase("link");
                        }
                        transports.push_back(std::move(redacted));
                    }
                }
                response.set_content(transports.dump(), "application/json");
            });
        server.Get(
            "/healthz",
            [this](const httplib::Request&,
                   httplib::Response& response) {
                std::lock_guard<std::mutex> lock(mutex);
                response.set_content(
                    nlohmann::json{
                        {"status", "ok"},
                        {"config_revision", current_revision},
                    }.dump(),
                    "application/json");
            });
        server.Post(
            "/v1/transports/runtime-ready",
            [this, authorized](const httplib::Request& request,
                               httplib::Response& response) {
                if (!authorized(request, response)) return;
                const auto call = ++runtime_ready_calls;
                const auto body = nlohmann::json::parse(request.body);
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    last_runtime_ready_tags =
                        body.at("tags").get<std::vector<std::string>>();
                }
                response.set_content(
                    nlohmann::json{
                        {"ready",
                         call >= runtime_ready_after_calls.load()},
                    }.dump(),
                    "application/json");
            });
        server.Post(
            "/v1/config/transports/batch/validate-items",
            [this, authorized](const httplib::Request& request,
                               httplib::Response& response) {
                if (!authorized(request, response)) return;
                ++item_validate_calls;
                std::lock_guard<std::mutex> lock(mutex);
                if (request.get_header_value("If-Match") !=
                    "\"" + current_revision + "\"") {
                    response.status = 412;
                    return;
                }
                const auto body = nlohmann::json::parse(request.body);
                auto valid = nlohmann::json::array();
                for (const auto& spec : body.at("transports")) {
                    valid.push_back(
                        rejected_link.empty() ||
                        spec.value("link", std::string{}) != rejected_link);
                }
                response.set_content(
                    nlohmann::json{
                        {"status", "validated"},
                        {"config_revision", current_revision},
                        {"valid", std::move(valid)},
                    }.dump(),
                    "application/json");
            });
        server.Post(
            "/v1/config/transports/batch/validate",
            [this, authorized](const httplib::Request& request,
                   httplib::Response& response) {
                if (!authorized(request, response)) return;
                ++batch_validate_calls;
                const auto body = nlohmann::json::parse(request.body);
                if (!body.contains("transports") ||
                    !body.at("transports").is_array() ||
                    body.at("transports").empty()) {
                    response.status = 400;
                    return;
                }
                std::lock_guard<std::mutex> lock(mutex);
                if (request.get_header_value("If-Match") !=
                    "\"" + current_revision + "\"") {
                    response.status = 412;
                    return;
                }
                response.set_content(
                    nlohmann::json{
                        {"status", "valid"},
                        {"config_revision", current_revision},
                    }.dump(),
                    "application/json");
            });
        server.Post(
            "/v1/config/transports/batch",
            [this, authorized](const httplib::Request& request,
                               httplib::Response& response) {
                if (!authorized(request, response)) return;
                ++batch_create_calls;
                std::lock_guard<std::mutex> lock(mutex);
                if (request.get_header_value("If-Match") !=
                    "\"" + current_revision + "\"") {
                    response.status = 412;
                    return;
                }
                response.status = create_status.load();
                if (response.status >= 300) {
                    response.set_content(create_error_body, "text/plain");
                    return;
                }
                const auto body = nlohmann::json::parse(request.body);
                const auto& batch = body.at("transports");
                auto persisted = nlohmann::json::parse(read_config());
                auto& transports = persisted["transports"];
                for (const auto& spec : batch) {
                    created.push_back(spec);
                    transports.push_back(spec);
                }
                const auto exact = persisted.dump(2) + "\n";
                write_config(exact);
                current_revision = Sha256::hex(exact);
                response.set_content(
                    nlohmann::json{
                        {"status", "created"},
                        {"created", batch.size()},
                        {"config_revision", current_revision},
                    }.dump(),
                    "application/json");
            });
        port = server.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        const auto initial = nlohmann::json{
                {"listen", "127.0.0.1:" + std::to_string(port)},
                {"api_key", "test-secret"},
                {"transports", nlohmann::json::array()},
            }.dump(2) + "\n";
        write_config(initial);
        current_revision = Sha256::hex(initial);
        thread = std::thread([this]() { server.listen_after_bind(); });
        while (!server.is_running()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    ~FakeManager() {
        server.stop();
        thread.join();
    }

    void rotate_authority() {
        std::lock_guard<std::mutex> lock(mutex);
        auto config = nlohmann::json::parse(read_config());
        config["api_key"] = "rotated-secret";
        const auto exact = config.dump(2) + "\n";
        write_config(exact);
        current_revision = Sha256::hex(exact);
        rotated_api_key.store(true, std::memory_order_release);
    }

    void reload_from_disk() {
        std::lock_guard<std::mutex> lock(mutex);
        const auto exact = read_config();
        const auto config = nlohmann::json::parse(exact);
        created.clear();
        if (config.contains("transports") &&
            config.at("transports").is_array()) {
            for (const auto& spec : config.at("transports")) {
                created.push_back(spec);
            }
        }
        current_revision = Sha256::hex(exact);
    }

private:
    std::string read_config() const {
        std::ifstream input(config_path, std::ios::binary);
        return {
            std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>(),
        };
    }

    void write_config(const std::string& body) const {
        std::ofstream output(
            config_path, std::ios::binary | std::ios::trunc);
        output.write(body.data(), static_cast<std::streamsize>(body.size()));
    }
};

struct SubscriptionsHarness {
    SubscriptionsTempDir directory;
    std::unique_ptr<FakeManager> manager;
    SseBroadcaster broadcaster;
    ApiContext context;
    ApiServer server;
    std::size_t fetch_calls{0};
    std::size_t apply_calls{0};
    Config visible_config;
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
        {
            std::ofstream config(
                directory.path / "config.json",
                std::ios::binary | std::ios::trunc);
            config << "{}\n";
        }
        if (with_manager) {
            manager = std::make_unique<FakeManager>(directory.path);
        }
        context.get_visible_config_fn =
            [this]() { return visible_config; };
        context.config_is_draft_fn = []() { return false; };
        context.restart_restore_service_fn =
            [this](const std::string&) {
                if (manager) manager->reload_from_disk();
                return 0;
            };
        context.enqueue_apply_validated_config_fn =
            [this](Config candidate, std::string) {
                ++apply_calls;
                visible_config = std::move(candidate);
                return ConfigApplyResult{true, false, std::nullopt, {}};
            };
        context.transport_runtime_ready_wait_attempts = 4U;
        context.transport_runtime_ready_wait_interval_ms = 1U;
        ConfigSaveTestOptions options;
        options.recovery_state_root = directory.path / "recovery";
        register_subscriptions_handler_for_test(
            server,
            context,
            [this](const std::string&) {
                ++fetch_calls;
                return fetch_body;
            },
            [](const std::string& path, const std::string& body) {
                write_config_atomically(path, body);
            },
            options);
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

TEST_CASE("a subscription handed over as a file is planned without fetching") {
    // An operator importing a file already has the document in front of them.
    // Fetching anything at that point would be reaching for a destination
    // nobody named.
    constexpr int api_port = 18287;
    SubscriptionsHarness harness(api_port);
    harness.fetch_body = "this fetcher must not run";
    httplib::Client client("127.0.0.1", api_port);

    const std::string document =
        kConfiguredLink + "\n" +
        "vless://22222222-2222-2222-2222-222222222222@b.example:443#Fresh\n";
    const auto response = client.Post(
        "/api/subscriptions/preview",
        nlohmann::json{{"document", document}}.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    CHECK(harness.fetch_calls == 0U);

    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("document_kind") == "link_list");
    const auto& candidates = body.at("candidates");
    REQUIRE(candidates.size() == 2U);
    // The manager was still consulted: the first line is a transport it
    // already has, and a file import that skipped that judgement would be the
    // same false green a URL import is not allowed to be.
    CHECK(candidates[0].at("disposition") == "already_configured");
    CHECK(candidates[1].at("disposition") == "importable");

    // Same redaction as the fetched path: the document held credentials and
    // the response holds none of them.
    CHECK(response->body.find("22222222-2222") == std::string::npos);
    CHECK(response->body.find("vless://") == std::string::npos);
}

TEST_CASE("preview takes exactly one source and says which") {
    // A request carrying both is a caller that does not know which it meant.
    // Picking one for them imports from a source they did not choose.
    constexpr int api_port = 18288;
    SubscriptionsHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    const nlohmann::json bodies[] = {
        nlohmann::json{{"url", "https://provider.example/sub"},
                       {"document", "vless://x@a.example:443#One"}},
        nlohmann::json::object(),
        nlohmann::json{{"url", ""}, {"document", ""}},
    };
    for (const auto& request : bodies) {
        const auto response = client.Post("/api/subscriptions/preview",
                                          request.dump(),
                                          "application/json");
        REQUIRE(response != nullptr);
        CHECK(response->status == 400);
    }
    CHECK(harness.fetch_calls == 0U);
}

TEST_CASE("an oversized document is named rather than merely refused") {
    // The planner already bounds the body and reports `too_large`, which tells
    // the operator what was wrong with their file. A second bound in the
    // handler would answer 400 with nothing they could act on.
    constexpr int api_port = 18289;
    SubscriptionsHarness harness(api_port);
    httplib::Client client("127.0.0.1", api_port);

    const auto response = client.Post(
        "/api/subscriptions/preview",
        nlohmann::json{{"document", std::string(1024U * 1024U + 1U, 'a')}}
            .dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    CHECK(nlohmann::json::parse(response->body).at("document_kind") ==
          "too_large");
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

TEST_CASE("apply atomically creates a selected transport and linked route") {
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
    CHECK(result.at("error").is_null());
    // vless1 belongs to the existing transport; the derived name is the next
    // free one, by the same rule the manual dialog uses.
    CHECK(result.at("interface") == "vless2");

    // What reached the manager is one batch containing the full spec, while
    // the same composite commit applied the linked INTERFACE outbound.
    CHECK(harness.manager->batch_validate_calls.load() == 1);
    CHECK(harness.manager->batch_create_calls.load() == 1);
    CHECK(harness.manager->item_validate_calls.load() == 1);
    CHECK(harness.apply_calls == 1U);
    REQUIRE(harness.manager->created.size() == 1U);
    const auto& spec = harness.manager->created.front();
    CHECK(spec.at("tag") == "fresh_nl");
    CHECK(spec.at("type") == "sing-box");
    CHECK(spec.at("interface") == "vless2");
    CHECK(spec.at("link").get<std::string>().find(
              "22222222-2222-2222-2222-222222222222") !=
          std::string::npos);
    CHECK(spec.at("auto_start") == true);
    CHECK(spec.at("display_name") == "Fresh NL");
    REQUIRE(harness.visible_config.outbounds.has_value());
    const auto linked = std::find_if(
        harness.visible_config.outbounds->begin(),
        harness.visible_config.outbounds->end(),
        [](const Outbound& outbound) {
            return outbound.tag == "fresh_nl";
        });
    REQUIRE(linked != harness.visible_config.outbounds->end());
    CHECK(linked->type == OutboundType::INTERFACE);
    CHECK(linked->interface == std::optional<std::string>("vless2"));
    CHECK(linked->display_name == std::optional<std::string>("Fresh NL"));

    // A preview is a one-shot import: the consumed line cannot be created
    // twice, and saying so is a per-entry outcome, not a request failure.
    const auto again = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections",
             nlohmann::json::array(
                 {{{"line", 1}, {"tag", "retry_name"}}})},
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
    CHECK(second.at("results")[0].at("tag") == "fresh_nl");
    CHECK(second.at("results")[0].at("interface") == "vless2");
    CHECK(second.at("results")[0].at("error").is_null());
    CHECK(harness.manager->created.size() == 1U);
    CHECK(harness.manager->batch_create_calls.load() == 1);
    CHECK(harness.apply_calls == 1U);
}

TEST_CASE("one subscription batch creates every selected transport and route") {
    constexpr int api_port = 18292;
    SubscriptionsHarness harness(api_port);
    harness.manager->runtime_ready_after_calls.store(2);
    harness.fetch_body =
        "vless://22222222-2222-2222-2222-222222222222@b.example:443#One\n"
        "trojan://password@c.example:8443\n";
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    const auto response = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections",
             nlohmann::json::array({{{"line", 1}}, {{"line", 2}}})},
        }.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    CHECK(nlohmann::json::parse(response->body).at("results").size() == 2U);
    CHECK(harness.manager->batch_validate_calls.load() == 1);
    CHECK(harness.manager->batch_create_calls.load() == 1);
    CHECK(harness.manager->item_validate_calls.load() == 1);
    CHECK(harness.manager->runtime_ready_calls.load() == 2);
    CHECK(harness.manager->last_runtime_ready_tags ==
          std::vector<std::string>{"one", "sub_2"});
    CHECK(harness.manager->created.size() == 2U);
    CHECK(harness.apply_calls == 1U);
    REQUIRE(harness.visible_config.outbounds.has_value());
    CHECK(harness.visible_config.outbounds->size() == 2U);
    CHECK(harness.manager->created[1].at("display_name") ==
          "c.example:8443");
    CHECK(harness.visible_config.outbounds->at(1).display_name ==
          std::optional<std::string>("c.example:8443"));
}

TEST_CASE("one rejected item does not block valid subscription selections") {
    constexpr int api_port = 18294;
    SubscriptionsHarness harness(api_port);
    const std::string rejected = "vless://noauth#Broken";
    harness.fetch_body =
        rejected + "\n" +
        "trojan://password@c.example:8443#Working\n";
    harness.manager->rejected_link = rejected;
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    const auto response = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections",
             nlohmann::json::array({{{"line", 1}}, {{"line", 2}}})},
        }.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto results = nlohmann::json::parse(response->body).at("results");
    REQUIRE(results.size() == 2U);
    const auto failed = std::find_if(
        results.begin(), results.end(), [](const nlohmann::json& item) {
            return item.at("line") == 1;
        });
    const auto created = std::find_if(
        results.begin(), results.end(), [](const nlohmann::json& item) {
            return item.at("line") == 2;
        });
    REQUIRE(failed != results.end());
    REQUIRE(created != results.end());
    CHECK(failed->at("outcome") == "failed");
    CHECK(failed->at("tag").is_null());
    CHECK(failed->at("interface").is_null());
    CHECK(created->at("outcome") == "created");
    CHECK(harness.manager->item_validate_calls.load() == 1);
    CHECK(harness.manager->batch_validate_calls.load() == 1);
    CHECK(harness.manager->batch_create_calls.load() == 1);
    REQUIRE(harness.manager->created.size() == 1U);
    CHECK(harness.manager->created[0].at("tag") == "working");
    CHECK(harness.apply_calls == 1U);
    REQUIRE(harness.visible_config.outbounds.has_value());
    CHECK(harness.visible_config.outbounds->size() == 1U);
    CHECK(harness.visible_config.outbounds->at(0).tag == "working");
}

TEST_CASE("duplicate selected names fail one item without blocking the batch") {
    constexpr int api_port = 18296;
    SubscriptionsHarness harness(api_port);
    harness.fetch_body =
        "vless://22222222-2222-2222-2222-222222222222@b.example:443#One\n"
        "trojan://password@c.example:8443#Two\n";
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    const auto response = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections",
             nlohmann::json::array({
                 {{"line", 1}, {"tag", "same_name"}},
                 {{"line", 2}, {"tag", "same_name"}},
             })},
        }.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto results = nlohmann::json::parse(response->body).at("results");
    REQUIRE(results.size() == 2U);
    const auto failed = std::find_if(
        results.begin(), results.end(), [](const nlohmann::json& item) {
            return item.at("line") == 2;
        });
    REQUIRE(failed != results.end());
    CHECK(failed->at("outcome") == "failed");
    CHECK(failed->at("error") == "name is already in use");
    REQUIRE(harness.manager->created.size() == 1U);
    CHECK(harness.manager->created[0].at("tag") == "same_name");
    CHECK(harness.apply_calls == 1U);
}

TEST_CASE("new local runtime readiness has a bounded failure") {
    constexpr int api_port = 18295;
    SubscriptionsHarness harness(api_port);
    harness.context.transport_runtime_ready_wait_attempts = 2U;
    harness.context.transport_runtime_ready_wait_interval_ms = 1U;
    harness.manager->runtime_ready_after_calls.store(100);
    harness.fetch_body =
        "vless://22222222-2222-2222-2222-222222222222@b.example:443#New\n";
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    const auto response = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections", nlohmann::json::array({{{"line", 1}}})},
        }.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    CHECK(response->status == 503);
    CHECK(harness.manager->runtime_ready_calls.load() == 2);
    CHECK(harness.manager->created.empty());
    CHECK(harness.apply_calls == 0U);
    CHECK_FALSE(harness.visible_config.outbounds.has_value());
}

TEST_CASE("subscription auto-start batches are capped before mutation") {
    constexpr int api_port = 18297;
    SubscriptionsHarness harness(api_port);
    nlohmann::json nine = nlohmann::json::array();
    nlohmann::json eight = nlohmann::json::array();
    for (int line = 1; line <= 9; ++line) {
        harness.fetch_body +=
            "trojan://password@node" + std::to_string(line) +
            ".example:443#Node" + std::to_string(line) + "\n";
        nine.push_back({{"line", line}});
        if (line <= 8) eight.push_back({{"line", line}});
    }
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    const auto refused = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections", nine},
        }.dump(),
        "application/json");
    REQUIRE(refused != nullptr);
    CHECK(refused->status == 400);
    CHECK(harness.manager->item_validate_calls.load() == 0);
    CHECK(harness.manager->batch_create_calls.load() == 0);
    CHECK(harness.apply_calls == 0U);

    const auto accepted = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections", eight},
        }.dump(),
        "application/json");
    REQUIRE(accepted != nullptr);
    REQUIRE(accepted->status == 200);
    CHECK(nlohmann::json::parse(accepted->body).at("results").size() == 8U);
    CHECK(harness.manager->item_validate_calls.load() == 1);
    CHECK(harness.manager->batch_create_calls.load() == 1);
    CHECK(harness.manager->created.size() == 8U);
    CHECK(harness.apply_calls == 1U);
}

TEST_CASE("preview and apply include existing core route names") {
    constexpr int api_port = 18293;
    SubscriptionsHarness harness(api_port);
    Outbound core_owned;
    core_owned.type = OutboundType::INTERFACE;
    core_owned.tag = "fresh";
    core_owned.interface = "vless2";
    harness.visible_config.outbounds =
        std::vector<Outbound>{core_owned};
    harness.fetch_body =
        "vless://22222222-2222-2222-2222-222222222222@b.example:443#Fresh\n";
    httplib::Client client("127.0.0.1", api_port);

    const auto preview = client.Post(
        "/api/subscriptions/preview",
        nlohmann::json{{"url", "https://provider.example/sub"}}.dump(),
        "application/json");
    REQUIRE(preview != nullptr);
    REQUIRE(preview->status == 200);
    const auto preview_body = nlohmann::json::parse(preview->body);
    CHECK(preview_body.at("candidates")[0].at("disposition") ==
          "tag_conflict");

    const auto response = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_body.at("preview_id")},
            {"selections",
             nlohmann::json::array(
                 {{{"line", 1}, {"tag", "fresh_subscription"}}})},
        }.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    REQUIRE(harness.manager->created.size() == 1U);
    CHECK(harness.manager->created[0].at("interface") == "vless3");
}

TEST_CASE("apply rechecks link identity after acquiring the mutation lease") {
    constexpr int api_port = 18287;
    SubscriptionsHarness harness(api_port);
    const std::string link =
        "vless://44444444-4444-4444-4444-444444444444@late.example:443"
        "#Late";
    harness.fetch_body = link + "\n";
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    // Simulate another serialized writer finishing after preview but exactly
    // when this apply acquires the common lease. Reading manager state before
    // the lease makes this test POST a duplicate; reading under it observes
    // the winner and returns the benign tri-state outcome without a POST.
    harness.manager->late_existing_link = link;
    harness.context.maintenance_lease_factory_fn =
        [&harness](std::string) -> std::unique_ptr<MaintenanceLease> {
        harness.manager->expose_late_existing.store(
            true, std::memory_order_release);
        return std::make_unique<SubscriptionsTestMaintenanceLease>();
    };

    const auto response = client.Post(
        "/api/subscriptions/apply",
        nlohmann::json{
            {"preview_id", preview_id},
            {"selections",
             nlohmann::json::array(
                 {{{"line", 1}, {"tag", "requested_name"}}})},
        }
            .dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    REQUIRE(body.at("results").size() == 1U);
    CHECK(body.at("results")[0].at("outcome") == "already_imported");
    CHECK(body.at("results")[0].at("tag") == "winner");
    CHECK(body.at("results")[0].at("interface") == "vless9");
    CHECK(body.at("results")[0].at("error").is_null());
    CHECK(harness.manager->created.empty());
}

TEST_CASE("a late fingerprint without public identity returns null identity") {
    constexpr int api_port = 18290;
    SubscriptionsHarness harness(api_port);
    const std::string link =
        "vless://66666666-6666-6666-6666-666666666666@late.example:443"
        "#NoIdentity";
    harness.fetch_body = link + "\n";
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    harness.manager->late_existing_link = link;
    harness.manager->expose_late_identity.store(false,
                                                std::memory_order_release);
    harness.context.maintenance_lease_factory_fn =
        [&harness](std::string) -> std::unique_ptr<MaintenanceLease> {
        harness.manager->expose_late_existing.store(
            true, std::memory_order_release);
        return std::make_unique<SubscriptionsTestMaintenanceLease>();
    };

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
    const auto result =
        nlohmann::json::parse(response->body).at("results")[0];
    CHECK(result.at("outcome") == "already_imported");
    CHECK(result.at("tag").is_null());
    CHECK(result.at("interface").is_null());
    CHECK(result.at("error").is_null());
    CHECK(harness.manager->created.empty());
}

TEST_CASE("duplicate late fingerprints do not claim an arbitrary identity") {
    constexpr int api_port = 18291;
    SubscriptionsHarness harness(api_port);
    const std::string link =
        "vless://77777777-7777-7777-7777-777777777777@late.example:443"
        "#DuplicateIdentity";
    harness.fetch_body = link + "\n";
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    harness.manager->late_existing_link = link;
    harness.manager->expose_duplicate_late_identity.store(
        true, std::memory_order_release);
    harness.context.maintenance_lease_factory_fn =
        [&harness](std::string) -> std::unique_ptr<MaintenanceLease> {
        harness.manager->expose_late_existing.store(
            true, std::memory_order_release);
        return std::make_unique<SubscriptionsTestMaintenanceLease>();
    };

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
    const auto result =
        nlohmann::json::parse(response->body).at("results")[0];
    CHECK(result.at("outcome") == "already_imported");
    CHECK(result.at("tag").is_null());
    CHECK(result.at("interface").is_null());
    CHECK(result.at("error").is_null());
    CHECK(harness.manager->created.empty());
}

TEST_CASE("apply reads manager authority only after acquiring the mutation lease") {
    constexpr int api_port = 18289;
    SubscriptionsHarness harness(api_port);
    harness.fetch_body =
        "vless://55555555-5555-5555-5555-555555555555@new.example:443"
        "#Rotated\n";
    httplib::Client client("127.0.0.1", api_port);
    const auto preview_id = preview_and_get_id(client);

    harness.context.maintenance_lease_factory_fn =
        [&harness](std::string) -> std::unique_ptr<MaintenanceLease> {
        // Model a serialized Save winning immediately before this apply. The
        // new manager key becomes authoritative while the lease is acquired.
        // Reading transports.json before the lease sends the stale key and
        // fails; reading it under the lease observes one coherent generation.
        harness.manager->rotate_authority();
        return std::make_unique<SubscriptionsTestMaintenanceLease>();
    };

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
    CHECK(body.at("results")[0].at("outcome") == "created");
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

TEST_CASE("manager response text is never reflected through the API") {
    // Parser diagnostics can quote or transform the credential-bearing link.
    // A substring filter cannot cover percent-decoding or future parser
    // normalizations, so only the status class crosses this boundary.
    constexpr int api_port = 18286;
    SubscriptionsHarness harness(api_port);
    const std::string link =
        "trojan://p%40ss@d.example:443#X";
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
    CHECK(response->status == 400);
    CHECK(response->body.find("p%40ss") == std::string::npos);
    CHECK(response->body.find("p@ss") == std::string::npos);
    CHECK(response->body.find(harness.manager->create_error_body) ==
          std::string::npos);
    CHECK(harness.manager->created.empty());
    CHECK(harness.apply_calls == 0U);
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
