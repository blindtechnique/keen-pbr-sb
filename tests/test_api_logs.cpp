#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_logs.hpp"
#include "../src/api/server.hpp"
#include "../src/log/file_sink.hpp"
#include "../src/log/logger.hpp"
#include "../src/util/last_command_failure.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <thread>
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

class EnvironmentVariableGuard {
public:
    EnvironmentVariableGuard(const char* name, const std::string& value)
        : name_(name) {
        if (const char* previous = std::getenv(name)) {
            previous_ = previous;
        }
        REQUIRE(::setenv(name, value.c_str(), 1) == 0);
    }

    ~EnvironmentVariableGuard() {
        if (previous_.has_value()) {
            (void)::setenv(name_.c_str(), previous_->c_str(), 1);
        } else {
            (void)::unsetenv(name_.c_str());
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_;
};

class LogRuntimeGuard {
public:
    LogRuntimeGuard()
        : file_enabled_(file_logging_enabled())
        , level_(Logger::instance().level()) {}

    ~LogRuntimeGuard() {
        set_file_logging_enabled(file_enabled_);
        Logger::instance().set_level(level_);
    }

private:
    bool file_enabled_;
    LogLevel level_;
};

class LogSettingsTestHookGuard {
public:
    ~LogSettingsTestHookGuard() { set_log_settings_test_hook({}); }
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

TEST_CASE("logging settings are atomically persisted with private permissions") {
    LogApiTempDir directory;
    LogRuntimeGuard runtime;
    const auto settings_path = directory.path / "logging.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_LOG_SETTINGS_FILE", settings_path.string());

    ApiConfig config;
    const int port =
        next_logs_api_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_logs_handler(server);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto response = client.Post(
        "/api/logs/settings",
        R"({"file_enabled":false,"level":"debug"})",
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto result = nlohmann::json::parse(response->body);
    CHECK(result.at("ok").get<bool>());
    CHECK(result.at("durable").get<bool>());

    struct stat metadata {};
    REQUIRE(::stat(settings_path.c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0600);
    std::ifstream stored_file(settings_path);
    REQUIRE(stored_file.is_open());
    const auto stored = nlohmann::json::parse(stored_file);
    CHECK_FALSE(stored.at("file_enabled").get<bool>());
    CHECK(stored.at("level") == "debug");
}

TEST_CASE(
    "post-commit logging settings failure still updates visible runtime") {
    LogApiTempDir directory;
    LogRuntimeGuard runtime;
    const auto settings_path = directory.path / "logging.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_LOG_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard write_fault(
        "KEEN_PBR_TEST_LOG_SETTINGS_WRITE_FAULT", "directory_fsync");

    ApiConfig config;
    const int port =
        next_logs_api_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_logs_handler(server);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto response = client.Post(
        "/api/logs/settings",
        R"({"file_enabled":false,"level":"debug"})",
        "application/json");
    const auto visible = client.Get("/api/logs/settings");
    server.stop();

    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto result = nlohmann::json::parse(response->body);
    CHECK(result.at("ok").get<bool>());
    CHECK_FALSE(result.at("durable").get<bool>());
    CHECK(result.contains("warning"));

    REQUIRE(visible != nullptr);
    const auto visible_settings = nlohmann::json::parse(visible->body);
    CHECK_FALSE(visible_settings.at("file_enabled").get<bool>());
    CHECK(visible_settings.at("level") == "debug");
    CHECK_FALSE(file_logging_enabled());
    CHECK(Logger::instance().level() == LogLevel::debug);
}

TEST_CASE("concurrent partial logging updates cannot lose fields") {
    LogApiTempDir directory;
    LogRuntimeGuard runtime;
    LogSettingsTestHookGuard hook_guard;
    const auto settings_path = directory.path / "logging.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_LOG_SETTINGS_FILE", settings_path.string());

    ApiConfig config;
    const int port =
        next_logs_api_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_logs_handler(server);
    server.start();

    httplib::Client setup_client("127.0.0.1", port);
    const auto initial = setup_client.Post(
        "/api/logs/settings",
        R"({"file_enabled":true,"level":"info"})",
        "application/json");
    REQUIRE(initial != nullptr);
    REQUIRE(nlohmann::json::parse(initial->body).at("ok").get<bool>());

    std::mutex gate_mutex;
    std::condition_variable gate_condition;
    int requests_ready = 0;
    int reads_completed = 0;
    bool release_first = false;
    bool release_second = false;
    set_log_settings_test_hook([&](LogSettingsTestStage stage) {
        std::unique_lock<std::mutex> lock(gate_mutex);
        if (stage == LogSettingsTestStage::request_ready) {
            ++requests_ready;
            gate_condition.notify_all();
            return;
        }

        const int ordinal = ++reads_completed;
        gate_condition.notify_all();
        if (ordinal == 1) {
            gate_condition.wait(lock, [&] { return release_first; });
        } else if (ordinal == 2) {
            gate_condition.wait(lock, [&] { return release_second; });
        }
    });

    std::string first_body;
    std::string second_body;
    std::thread first([&] {
        httplib::Client client("127.0.0.1", port);
        if (const auto response = client.Post(
                "/api/logs/settings",
                R"({"file_enabled":false})",
                "application/json")) {
            first_body = response->body;
        }
    });

    {
        std::unique_lock<std::mutex> lock(gate_mutex);
        gate_condition.wait(lock, [&] { return reads_completed >= 1; });
    }

    std::thread second([&] {
        httplib::Client client("127.0.0.1", port);
        if (const auto response = client.Post(
                "/api/logs/settings",
                R"({"level":"debug"})",
                "application/json")) {
            second_body = response->body;
        }
    });

    {
        std::unique_lock<std::mutex> lock(gate_mutex);
        gate_condition.wait(lock, [&] { return requests_ready >= 2; });
        release_first = true;
    }
    gate_condition.notify_all();
    first.join();

    {
        const std::lock_guard<std::mutex> lock(gate_mutex);
        release_second = true;
    }
    gate_condition.notify_all();
    second.join();
    set_log_settings_test_hook({});

    const auto visible = setup_client.Get("/api/logs/settings");
    server.stop();

    REQUIRE_FALSE(first_body.empty());
    REQUIRE_FALSE(second_body.empty());
    CHECK(nlohmann::json::parse(first_body).at("ok").get<bool>());
    CHECK(nlohmann::json::parse(second_body).at("ok").get<bool>());
    REQUIRE(visible != nullptr);
    const auto settings = nlohmann::json::parse(visible->body);
    CHECK_FALSE(settings.at("file_enabled").get<bool>());
    CHECK(settings.at("level") == "debug");
    CHECK_FALSE(file_logging_enabled());
    CHECK(Logger::instance().level() == LogLevel::debug);
}

} // namespace keen_pbr3

#endif // WITH_API
