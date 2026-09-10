#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api_context_test_support.hpp"
#include "api/handler_lists_refresh.hpp"
#include "api/sse_broadcaster.hpp"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

class ListsRefreshApiFixture {
public:
    explicit ListsRefreshApiFixture(int port)
        : auth_file("KEEN_PBR_AUTH_FILE",
                    test_support::missing_auth_path(port))
        , context(test_support::make_minimal_api_context(
              broadcaster, "/tmp/keen-pbr-lists-refresh-test.json"))
        , server(make_config(port)) {
        register_lists_refresh_handler(server, context);
        server.start();
        client = std::make_unique<httplib::Client>("127.0.0.1", port);
    }

    ~ListsRefreshApiFixture() {
        server.stop();
    }

    static ApiConfig make_config(int port) {
        ApiConfig config;
        config.listen = "127.0.0.1:" + std::to_string(port);
        return config;
    }

    SseBroadcaster broadcaster;
    test_support::EnvironmentVariableGuard auth_file;
    ApiContext context;
    ApiServer server;
    std::unique_ptr<httplib::Client> client;
};

} // namespace

TEST_CASE("list refresh endpoint preserves the structured operation result") {
    std::vector<std::optional<std::string>> requests;
    ListsRefreshApiFixture fixture(test_support::isolated_api_port(4));
    fixture.context.refresh_lists_fn = [&](const api::ListRefreshRequest& request) {
        requests.push_back(request.name);
        return ListRefreshOperationResult{
            {"one", "two"},
            {"two"},
            {},
            true,
            "two lists refreshed",
        };
    };

    const auto response = fixture.client->Post(
        "/api/lists/refresh", R"({"name":"one"})", "application/json");

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    REQUIRE(requests.size() == 1);
    REQUIRE(requests.front().has_value());
    CHECK(*requests.front() == "one");

    const auto body = nlohmann::json::parse(response->body);
    CHECK(body["status"] == "ok");
    CHECK(body["message"] == "two lists refreshed");
    CHECK(body["refreshed_lists"] ==
          nlohmann::json::array({"one", "two"}));
    CHECK(body["changed_lists"] == nlohmann::json::array({"two"}));
    CHECK(body["failed_lists"] == nlohmann::json::array());
    CHECK(body["reloaded"] == true);
}

TEST_CASE("list refresh endpoint treats absent name as refresh all") {
    std::vector<std::optional<std::string>> requests;
    ListsRefreshApiFixture fixture(test_support::isolated_api_port(5));
    fixture.context.refresh_lists_fn = [&](const api::ListRefreshRequest& request) {
        requests.push_back(request.name);
        return ListRefreshOperationResult{};
    };

    const std::vector<std::string> bodies{"", "null", "{}"};
    for (const auto& body : bodies) {
        const auto response = fixture.client->Post(
            "/api/lists/refresh", body, "application/json");
        REQUIRE(response != nullptr);
        CHECK(response->status == 200);
    }

    REQUIRE(requests.size() == bodies.size());
    for (const auto& request : requests) {
        CHECK_FALSE(request.has_value());
    }
}

TEST_CASE("list refresh endpoint rejects malformed request bodies") {
    std::size_t calls = 0;
    ListsRefreshApiFixture fixture(test_support::isolated_api_port(6));
    fixture.context.refresh_lists_fn = [&](const api::ListRefreshRequest&) {
        ++calls;
        return ListRefreshOperationResult{};
    };

    const std::vector<std::string> bodies{
        "{",
        "[]",
        R"({"name":42})",
        R"({"name":"one","force_refresh":"yes"})",
        R"({"name":"one","accept_shrink":true})",
        R"({"name":"one","accept_shrink":{}})",
        R"({"accept_shrink":{"previous_sha256":"a","candidate_sha256":"b"}})",
    };
    for (const auto& body : bodies) {
        const auto response = fixture.client->Post(
            "/api/lists/refresh", body, "application/json");
        REQUIRE(response != nullptr);
        CHECK(response->status == 400);
    }
    CHECK(calls == 0);
}

TEST_CASE("list refresh endpoint carries force and exact one-list acceptance") {
    std::vector<api::ListRefreshRequest> requests;
    ListsRefreshApiFixture fixture(test_support::isolated_api_port(7));
    fixture.context.refresh_lists_fn = [&](const api::ListRefreshRequest& request) {
        requests.push_back(request);
        return ListRefreshOperationResult{};
    };
    const auto force = fixture.client->Post("/api/lists/refresh",
        R"({"name":"one","force_refresh":true})", "application/json");
    REQUIRE(force != nullptr);
    CHECK(force->status == 200);
    REQUIRE(requests.size() == 1);
    CHECK(requests.back().force_refresh.value_or(false));
    CHECK_FALSE(requests.back().accept_shrink.has_value());

    nlohmann::json body = {{"name", "one"}, {"accept_shrink", {
        {"previous_sha256", std::string(64, 'a')},
        {"candidate_sha256", std::string(64, 'b')}}}};
    const auto accept = fixture.client->Post("/api/lists/refresh", body.dump(), "application/json");
    REQUIRE(accept != nullptr);
    CHECK(accept->status == 200);
    REQUIRE(requests.size() == 2);
    CHECK(requests.back().force_refresh.value_or(false));
    REQUIRE(requests.back().accept_shrink.has_value());
    CHECK(requests.back().accept_shrink->previous_sha256 == std::string(64, 'a'));
    CHECK(requests.back().accept_shrink->candidate_sha256 == std::string(64, 'b'));

    body.erase("name");
    const auto all = fixture.client->Post("/api/lists/refresh", body.dump(), "application/json");
    REQUIRE(all != nullptr);
    CHECK(all->status == 400);
    body["name"] = "one";
    body["accept_shrink"]["candidate_sha256"] = std::string(64, 'G');
    const auto malformed = fixture.client->Post("/api/lists/refresh", body.dump(), "application/json");
    REQUIRE(malformed != nullptr);
    CHECK(malformed->status == 400);
    CHECK(requests.size() == 2);
}

TEST_CASE("list refresh endpoint propagates runtime apply failure instead of HTTP OK") {
    ListsRefreshApiFixture fixture(test_support::isolated_api_port(4));
    const ListRefreshOperationResult partial{
        {"one"}, {"one"}, {}, false, {}};
    for (const auto* stage : {"prepare", "owner_handoff", "terminal_wait", "terminal"}) {
        for (const auto* runtime_result : {"unchanged", "rolled_back", "unknown"}) {
            CAPTURE(stage);
            CAPTURE(runtime_result);
            fixture.context.refresh_lists_fn =
                [&, stage, runtime_result](const api::ListRefreshRequest&)
                    -> ListRefreshOperationResult {
                throw make_list_refresh_apply_error(
                    partial, stage, "retained exact terminal detail", runtime_result);
            };
            const auto response = fixture.client->Post(
                "/api/lists/refresh", R"({"name":"one"})", "application/json");
            REQUIRE(response != nullptr);
            CHECK(response->status == 503);
            const auto body = nlohmann::json::parse(response->body);
            CHECK(body["code"] == "list_refresh_apply_failed");
            CHECK(body["params"]["stage"] == stage);
            CHECK(body["params"]["runtime_result"] == runtime_result);
            CHECK(body["reloaded"] == false);
            CHECK(body["changed_lists"] == nlohmann::json::array({"one"}));
            CHECK(body["error"].get<std::string>().find(
                      "retained exact terminal detail") != std::string::npos);
            CHECK_FALSE(body.contains("status"));
        }
    }
}

TEST_CASE("list refresh endpoint allows successful cache-only updates") {
    ListsRefreshApiFixture fixture(test_support::isolated_api_port(5));
    for (const auto& result : {
             ListRefreshOperationResult{{"one"}, {}, {}, false,
                                        "Lists refreshed; no updates found"},
             ListRefreshOperationResult{{"one"}, {"one"}, {}, false,
                                        "Lists refreshed"},
             ListRefreshOperationResult{{"one"}, {"one"}, {}, false,
                 "Lists refreshed; runtime is stopped so changes will apply on next start"}}) {
        fixture.context.refresh_lists_fn =
            [&result](const api::ListRefreshRequest&) { return result; };
        const auto response = fixture.client->Post(
            "/api/lists/refresh", R"({"name":"one"})", "application/json");
        REQUIRE(response != nullptr);
        CHECK(response->status == 200);
        const auto body = nlohmann::json::parse(response->body);
        CHECK(body["status"] == "ok");
        CHECK(body["message"] == result.message);
        CHECK(body["reloaded"] == false);
        CHECK_FALSE(body.contains("code"));
    }
}

} // namespace keen_pbr3

#endif // WITH_API
