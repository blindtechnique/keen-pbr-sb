#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_logs.hpp"
#include "../src/api/server.hpp"
#include "../src/util/last_command_failure.hpp"

#include <atomic>
#include <filesystem>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {
namespace {

class LogApiTempDir {
public:
    LogApiTempDir() {
        char pattern[] = "/tmp/keen-pbr-api-logs-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~LogApiTempDir() {
        set_last_command_failure_path_for_testing(std::nullopt);
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

std::atomic<int> next_logs_api_port{18420};

} // namespace

TEST_CASE("logs endpoint includes the bounded last command failure") {
    LogApiTempDir directory;
    const auto failure_path =
        directory.path / "last-command-failure.log";
    set_last_command_failure_path_for_testing(failure_path.string());

    const std::vector<std::string> command{
        "/usr/sbin/iptables-restore", "-w", "10"};
    std::string invalid_response = "line 7 failed: ";
    invalid_response.push_back(static_cast<char>(0x8B));
    for (int index = 0; index < 20000; ++index) {
        invalid_response += "\xE2\x82\xAC";
    }
    REQUIRE(write_last_command_failure(
        {command,
         1,
         "*mangle\nCOMMIT\n",
         invalid_response,
         "nonzero_exit"}));

    ApiConfig config;
    const int port =
        next_logs_api_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_logs_handler(server);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto response = client.Get("/api/logs?lines=1");
    server.stop();

    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    REQUIRE(body.contains("last_command_failure"));
    REQUIRE(body.at("last_command_failure").is_string());
    const auto failure =
        body.at("last_command_failure").get<std::string>();
    CHECK(failure.find("iptables-restore") != std::string::npos);
    CHECK(failure.find("line 7 failed") != std::string::npos);
    CHECK(failure.find(static_cast<char>(0x8B)) == std::string::npos);
}

TEST_CASE("logs endpoint omits last command failure when no safe record exists") {
    LogApiTempDir directory;
    set_last_command_failure_path_for_testing(
        (directory.path / "missing.log").string());

    ApiConfig config;
    const int port =
        next_logs_api_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_logs_handler(server);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto response = client.Get("/api/logs?lines=1");
    server.stop();

    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    CHECK_FALSE(body.contains("last_command_failure"));
}

} // namespace keen_pbr3

#endif // WITH_API
