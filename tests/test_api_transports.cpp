#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

#include "../src/api/handler_transports.hpp"
#include "../src/api/server.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/util/display_name.hpp"

namespace keen_pbr3 {

namespace {

ApiContext make_transports_test_context(SseBroadcaster& broadcaster,
                                        const std::string& config_path) {
    return ApiContext{
        config_path,
        broadcaster,
        []() { return Config{}; },
        []() { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> { return std::nullopt; },
        []() {},
        [](const Config&) {},
        []() { return ServiceHealthState{}; },
        []() { return RoutingHealthReport{}; },
        []() { return api::RuntimeOutboundsResponse{}; },
        []() { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) { return std::map<std::string, api::ListRefreshStateValue>{}; },
        [](const std::string&) { return TestRoutingResult{}; },
        []() {},
        []() {},
        [](Config, std::string) { return ConfigApplyResult{}; },
        []() {},
        []() {},
        []() {},
        [](std::optional<std::string>) { return ListRefreshOperationResult{}; },
    };
}

} // namespace

TEST_CASE("transports handler proxies authenticated companion response") {
    constexpr int api_port = 18221;
    const auto directory = std::filesystem::temp_directory_path() /
                           "keen-pbr-transport-handler-test";
    std::filesystem::create_directories(directory);
    const auto config_path = (directory / "config.json").string();

    httplib::Server companion;
    companion.Get("/v1/transports", [](const httplib::Request& request,
                                       httplib::Response& response) {
        if (request.get_header_value("Authorization") != "Bearer test-secret") {
            response.status = 401;
            return;
        }
        response.set_content(
            nlohmann::json::array({
                {{"tag", "reality"},
                 {"display_name", std::string(80, 'A')},
                 {"type", "sing-box-vless-reality"},
                 {"interface", "tun-reality"},
                 {"state", "up"},
                 {"updated_at", "2026-07-17T18:00:00Z"},
                 {"desired_up", true},
                 {"path",
                  {{"wire_transport", "tcp"},
                   {"framing", "raw"},
                   {"confidence", "derived"}}}},
            }).dump(),
            "application/json");
    });
    companion.Post("/v1/transports/reality/up", [](const httplib::Request& request,
                                                    httplib::Response& response) {
        if (request.get_header_value("Authorization") != "Bearer test-secret") {
            response.status = 401;
            return;
        }
        response.status = 202;
        response.set_content(
            nlohmann::json{{"status", "accepted"},
                           {"at", "2026-07-17T18:00:01Z"}}.dump(),
            "application/json");
    });
    companion.Get("/v1/config/transports", [](const httplib::Request& request,
                                              httplib::Response& response) {
        if (request.get_header_value("Authorization") != "Bearer test-secret") {
            response.status = 401;
            return;
        }
        response.set_content(
            nlohmann::json::array({
                {{"tag", "native_one"},
                 {"display_name", "Домашний туннель"},
                 {"type", "native"},
                 {"interface", "nwg1"}},
            }).dump(),
            "application/json");
    });
    companion.Post("/v1/config/transports", [](const httplib::Request& request,
                                                httplib::Response& response) {
        if (request.get_header_value("Authorization") != "Bearer test-secret") {
            response.status = 401;
            return;
        }
        const auto body = nlohmann::json::parse(request.body);
        if (body.value("tag", "") != "native_two") {
            response.status = 400;
            return;
        }
        response.status = 201;
        response.set_content(
            nlohmann::json{{"status", "created"}, {"tag", "native_two"}}.dump(),
            "application/json");
    });
    const int companion_port = companion.bind_to_any_port("127.0.0.1");
    REQUIRE(companion_port > 0);
    {
        std::ofstream config(directory / "transports.json");
        config << nlohmann::json{
            {"listen", "127.0.0.1:" + std::to_string(companion_port)},
            {"api_key", "test-secret"},
        };
    }
    std::thread companion_thread([&companion]() {
        companion.listen_after_bind();
    });
    while (!companion.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    SseBroadcaster broadcaster;
    ApiConfig api_config;
    api_config.listen = "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    auto context = make_transports_test_context(broadcaster, config_path);
    std::string traffic_target_source;
    std::vector<std::string> traffic_targets;
    context.replace_interface_traffic_targets_fn =
        [&](std::string source, std::vector<std::string> interfaces) {
            traffic_target_source = std::move(source);
            traffic_targets = std::move(interfaces);
        };
    register_transports_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto response = client.Get("/api/transports");
    const auto action_response = client.Post(
        "/api/transports",
        nlohmann::json{{"tag", "reality"}, {"action", "up"}}.dump(),
        "application/json");
    const auto invalid_action_response = client.Post(
        "/api/transports",
        nlohmann::json{{"tag", "../escape"}, {"action", "up"}}.dump(),
        "application/json");
    const auto config_response = client.Get("/api/transports/config");
    const auto create_response = client.Post(
        "/api/transports/config",
        nlohmann::json{
            {"operation", "create"},
            {"transport",
             {{"tag", "native_two"},
              {"type", "native"},
              {"interface", "nwg2"}}},
        }.dump(),
        "application/json");
    std::string overlong_display_name;
    for (std::size_t index = 0; index < 81; ++index) {
        overlong_display_name += "🚀";
    }
    const auto invalid_alias_response = client.Post(
        "/api/transports/config",
        nlohmann::json{
            {"operation", "create"},
            {"transport",
             {{"tag", "native_two"},
              {"display_name", overlong_display_name},
              {"type", "native"},
              {"interface", "nwg2"}}},
        }.dump(),
        "application/json");

    server.stop();
    companion.stop();
    companion_thread.join();
    std::filesystem::remove_all(directory);

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    REQUIRE(body.size() == 1);
    CHECK(body[0]["tag"] == "reality");
    CHECK(body[0]["interface"] == "tun-reality");
    CHECK(traffic_target_source == "managed-transports");
    CHECK(traffic_targets == std::vector<std::string>{"tun-reality"});
    REQUIRE(action_response != nullptr);
    CHECK(action_response->status == 200);
    const auto action_body = nlohmann::json::parse(action_response->body);
    CHECK(action_body["status"] == "accepted");
    REQUIRE(invalid_action_response != nullptr);
    CHECK(invalid_action_response->status == 400);
    REQUIRE(config_response != nullptr);
    CHECK(config_response->status == 200);
    CHECK(nlohmann::json::parse(config_response->body)[0]["tag"] == "native_one");
    CHECK(nlohmann::json::parse(config_response->body)[0]["display_name"] ==
          "Домашний туннель");
    REQUIRE(create_response != nullptr);
    CHECK(create_response->status == 200);
    CHECK(nlohmann::json::parse(create_response->body)["status"] == "created");
    REQUIRE(invalid_alias_response != nullptr);
    CHECK(invalid_alias_response->status == 400);
}

TEST_CASE("transport aliases use Unicode code points and reject controls") {
    std::string eighty_code_points;
    for (std::size_t index = 0; index < 80; ++index) {
        eighty_code_points += "🚀";
    }
    CHECK(display_name::is_valid(eighty_code_points));
    CHECK_FALSE(display_name::is_valid(eighty_code_points + "🚀"));
    CHECK_FALSE(display_name::is_valid("safe\u202etxt.exe"));
    CHECK_FALSE(display_name::is_valid(std::string{"bad\xFFname", 8}));
    CHECK(display_name::is_valid("", true));
    CHECK_FALSE(display_name::is_valid(""));
}

} // namespace keen_pbr3

#endif // WITH_API
