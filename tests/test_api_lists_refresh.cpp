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
    fixture.context.refresh_lists_fn = [&](std::optional<std::string> name) {
        requests.push_back(std::move(name));
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
    fixture.context.refresh_lists_fn = [&](std::optional<std::string> name) {
        requests.push_back(std::move(name));
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
    fixture.context.refresh_lists_fn = [&](std::optional<std::string>) {
        ++calls;
        return ListRefreshOperationResult{};
    };

    const std::vector<std::string> bodies{
        "{",
        "[]",
        R"({"name":42})",
    };
    for (const auto& body : bodies) {
        const auto response = fixture.client->Post(
            "/api/lists/refresh", body, "application/json");
        REQUIRE(response != nullptr);
        CHECK(response->status == 400);
    }
    CHECK(calls == 0);
}

} // namespace keen_pbr3

#endif // WITH_API
