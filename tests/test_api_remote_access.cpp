#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_remote_access.hpp"
#include "../src/api/local_password_hash.hpp"
#include "../src/api/handler_dns_test.hpp"
#include "../src/api/handler_status_events.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/api/status_stream.hpp"
#include "../src/log/logger.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

class RemoteAccessTempDir {
public:
    RemoteAccessTempDir() {
        auto pattern =
            (std::filesystem::temp_directory_path() /
             "keen-pbr-remote-access-test-XXXXXX")
                .string();
        std::vector<char> buffer(pattern.begin(), pattern.end());
        buffer.push_back('\0');
        const char* created = ::mkdtemp(buffer.data());
        REQUIRE(created != nullptr);
        path = created;
    }

    ~RemoteAccessTempDir() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

class EnvironmentVariableGuard {
public:
    EnvironmentVariableGuard(const char* name, const std::string& value)
        : name_(name) {
        if (const char* previous = std::getenv(name)) previous_ = previous;
        REQUIRE(::setenv(name, value.c_str(), 1) == 0);
    }

    ~EnvironmentVariableGuard() {
        if (previous_) {
            (void)::setenv(name_.c_str(), previous_->c_str(), 1);
        } else {
            (void)::unsetenv(name_.c_str());
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_;
};

class RemoteAccessRunnerGuard {
public:
    RemoteAccessRunnerGuard() {
        reset_auth_settings_publication_hook_for_testing();
        reset_stream_admission_hook_for_testing();
        reset_auth_settings_admission_hook_for_testing();
        reset_auth_login_verified_hook_for_testing();
        reset_trusted_local_connection_evaluator_for_testing();
        reset_remote_access_reconciler_for_testing();
        reset_remote_access_command_runner_for_testing();
    }

    ~RemoteAccessRunnerGuard() {
        reset_auth_settings_publication_hook_for_testing();
        reset_stream_admission_hook_for_testing();
        reset_auth_settings_admission_hook_for_testing();
        reset_auth_login_verified_hook_for_testing();
        reset_trusted_local_connection_evaluator_for_testing();
        reset_remote_access_reconciler_for_testing();
        reset_remote_access_command_runner_for_testing();
    }
};

class RemoteAccessLogCapture {
public:
    RemoteAccessLogCapture()
        : previous_level_(Logger::instance().level()) {
        Logger::instance().set_level(LogLevel::info);
        Logger::instance().set_sink(
            [this](const std::string& line) { lines_.push_back(line); });
    }

    ~RemoteAccessLogCapture() {
        Logger::instance().clear_sink();
        Logger::instance().set_level(previous_level_);
    }

    const std::vector<std::string>& lines() const noexcept { return lines_; }

private:
    LogLevel previous_level_;
    std::vector<std::string> lines_;
};

using Rule = std::vector<std::string>;

class FakeIptables {
public:
    int run(const std::vector<std::string>& command) {
        if (command.empty() || command.front() != "iptables") return 2;
        std::size_t cursor = 1;
        if (cursor < command.size() && command[cursor] == "-w") {
            ++cursor;
            if (cursor < command.size() &&
                !command[cursor].empty() &&
                std::all_of(command[cursor].begin(), command[cursor].end(),
                            [](unsigned char ch) {
                                return ch >= '0' && ch <= '9';
                            })) {
                ++cursor;
            }
        }
        std::string table;
        if (cursor + 1 < command.size() && command[cursor] == "-t") {
            table = command[cursor + 1];
            cursor += 2;
        }
        if (cursor >= command.size()) return 2;
        const auto operation = command[cursor++];
        if (cursor >= command.size()) return 2;
        const auto chain = command[cursor++];

        if (operation == "-S") return chain_exists(table, chain) ? 0 : 1;
        if (operation == "-N") {
            if (chain_exists(table, chain)) return 1;
            chains_[table].insert(chain);
            return 0;
        }
        if (!chain_exists(table, chain)) return 2;

        auto& rules = rules_[table][chain];
        Rule rule(command.begin() + static_cast<std::ptrdiff_t>(cursor),
                  command.end());
        if (operation == "-I" && !rule.empty() && rule.front() == "1") {
            rule.erase(rule.begin());
        }
        const auto existing =
            std::find(rules.begin(), rules.end(), rule);
        if (operation == "-C") return existing == rules.end() ? 1 : 0;
        if (operation == "-A" || operation == "-I") {
            rules.push_back(std::move(rule));
            return 0;
        }
        if (operation == "-D") {
            if (existing == rules.end()) return 1;
            rules.erase(existing);
            return 0;
        }
        if (operation == "-F") {
            rules.clear();
            return 0;
        }
        if (operation == "-X") {
            if (!rules.empty()) return 1;
            chains_[table].erase(chain);
            rules_[table].erase(chain);
            return 0;
        }
        return 2;
    }

private:
    bool chain_exists(const std::string& table,
                      const std::string& chain) const {
        if ((table.empty() && chain == "INPUT") ||
            (table == "nat" && chain == "PREROUTING")) {
            return true;
        }
        const auto table_chains = chains_.find(table);
        return table_chains != chains_.end() &&
               table_chains->second.count(chain) != 0U;
    }

    std::map<std::string, std::set<std::string>> chains_;
    std::map<std::string, std::map<std::string, std::vector<Rule>>> rules_;
};

ApiContext make_remote_access_context(SseBroadcaster& broadcaster) {
    Config visible;
    ApiConfig api;
    api.listen = std::string("0.0.0.0:12121");
    visible.api = std::move(api);
    return ApiContext{
        "/tmp/keen-pbr-remote-access-api-test.json",
        broadcaster,
        [visible] { return visible; },
        [] { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> {
            return std::nullopt;
        },
        [] {},
        [](const Config&) {},
        [] { return ServiceHealthState{}; },
        [] { return RoutingHealthReport{}; },
        [] { return api::RuntimeOutboundsResponse{}; },
        [] { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) {
            return std::map<std::string, api::ListRefreshStateValue>{};
        },
        [](const std::string&) { return TestRoutingResult{}; },
        [] {},
        [] {},
        [](Config, std::string) { return ConfigApplyResult{}; },
        [] {},
        [] {},
        [] {},
        [](std::optional<std::string>) {
            return ListRefreshOperationResult{};
        },
    };
}

std::atomic<int> next_remote_access_port{18470};

std::string remote_access_session_cookie(
    const httplib::Response& response) {
    const auto header = response.get_header_value("Set-Cookie");
    const auto separator = header.find(';');
    return header.substr(0, separator);
}

void grant_step_up(httplib::Client& client,
                   const httplib::Headers& headers,
                   const std::string& username,
                   const std::string& password) {
    const auto response = client.Post(
        "/api/auth/step-up", headers,
        nlohmann::json{{"username", username}, {"password", password}}.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    CHECK(nlohmann::json::parse(response->body).at("granted").get<bool>());
}

} // namespace

TEST_CASE("remote access POST defers its firewall writer to the control retry") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE",
        (directory.path / "remote-access.json").string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    { std::ofstream auth(directory.path / "auth.json"); auth << R"({"enabled":true})"; }

    FakeIptables firewall;
    std::atomic<unsigned int> command_count{0};
    set_remote_access_command_runner_for_testing(
        [&firewall, &command_count](const std::vector<std::string>& command) {
            command_count.fetch_add(1U, std::memory_order_relaxed);
            return firewall.run(command);
        });

    SseBroadcaster broadcaster;
    auto context = make_remote_access_context(broadcaster);
    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_remote_access_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto enabled = client.Post(
        "/api/system/remote-access",
        R"({"enabled":true,"port":12121})",
        "application/json");
    REQUIRE(enabled != nullptr);
    const auto enabled_body = nlohmann::json::parse(enabled->body);
    CHECK(enabled_body.at("ok").get<bool>());
    CHECK(enabled_body.at("pending").get<bool>());
    CHECK(enabled_body.at("retry_scheduled").get<bool>());
    CHECK(enabled_body.at("retry_after_ms") == 0);
    CHECK(enabled_body.at("durable").get<bool>());
    CHECK(command_count.load(std::memory_order_relaxed) == 0U);

    const auto enabled_apply = retry_remote_access_reconcile(
        enabled_body.at("generation").get<std::uint64_t>(),
        "0.0.0.0:12121");
    CHECK(enabled_apply.apply.applied);
    CHECK(enabled_apply.status.state == RemoteAccessRuntimeState::applied);
    const auto commands_after_enable =
        command_count.load(std::memory_order_relaxed);
    CHECK(commands_after_enable > 0U);

    const auto disabled = client.Post(
        "/api/system/remote-access",
        R"({"enabled":false,"port":12121})",
        "application/json");
    server.stop();

    REQUIRE(disabled != nullptr);
    const auto disabled_body = nlohmann::json::parse(disabled->body);
    CHECK(disabled_body.at("ok").get<bool>());
    CHECK(disabled_body.at("pending").get<bool>());
    CHECK(disabled_body.at("durable").get<bool>());
    CHECK(command_count.load(std::memory_order_relaxed) ==
          commands_after_enable);
    const auto disabled_apply = retry_remote_access_reconcile(
        disabled_body.at("generation").get<std::uint64_t>(),
        "0.0.0.0:12121");
    CHECK(disabled_apply.apply.applied);
    CHECK(disabled_apply.status.state == RemoteAccessRuntimeState::closed);
    CHECK(remove_remote_access_rules());
}

TEST_CASE("remote access refuses a custom port instead of exposing direct 12121") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    {
        std::ofstream auth(directory.path / "auth.json");
        auth << R"({"enabled":true,"provider":"local"})";
    }

    std::atomic<unsigned int> command_count{0};
    set_remote_access_command_runner_for_testing(
        [&command_count](const std::vector<std::string>&) {
            command_count.fetch_add(1U, std::memory_order_relaxed);
            return 0;
        });

    SseBroadcaster broadcaster;
    auto context = make_remote_access_context(broadcaster);
    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_remote_access_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto response = client.Post(
        "/api/system/remote-access",
        R"({"enabled":true,"port":15443})",
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("error") == "custom_port_not_supported_safely");
    CHECK(body.at("supported_port") == 12121);
    CHECK(command_count.load(std::memory_order_relaxed) == 0U);
    CHECK_FALSE(std::filesystem::exists(settings_path));
}

TEST_CASE("Keenetic auth normalizes stale remote access and verifies cleanup without an incident") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":true,"port":12121})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"local"})";
    }

    FakeIptables firewall;
    set_remote_access_command_runner_for_testing(
        [&firewall](const std::vector<std::string>& command) {
            return firewall.run(command);
        });

    const auto opened =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE(opened.apply.applied);
    REQUIRE(opened.status.state == RemoteAccessRuntimeState::applied);
    // The supported fixed-port path keeps NAT absent. Seed a legacy owned NAT
    // chain as well so normalization proves cleanup in both tables.
    REQUIRE(firewall.run({"iptables", "-w", "1", "-t", "nat", "-N",
                          "KeenPbrRemote"}) == 0);
    REQUIRE(firewall.run({"iptables", "-w", "1", "-t", "nat", "-I",
                          "PREROUTING", "1", "-j", "KeenPbrRemote"}) == 0);
    CHECK(firewall.run(
              {"iptables", "-w", "1", "-S", "KeenPbrRemote"}) == 0);
    CHECK(firewall.run({"iptables", "-w", "1", "-t", "nat", "-S",
                        "KeenPbrRemote"}) == 0);

    // Model a stale/restored pair of durable files from an older build: WAN
    // access is still requested and its owned rules still exist, but router
    // credentials are now the authentication authority.
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"keenetic"})";
    }

    RemoteAccessLogCapture logs;
    auto result = refresh_remote_access_reconcile("0.0.0.0:12121");
    CHECK(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::closed);
    CHECK_FALSE(result.status.desired_enabled);
    CHECK(result.status.applied_generation ==
          result.status.desired_generation);
    CHECK_FALSE(result.status.incident_active);
    CHECK_FALSE(result.status.recovery_owned);
    CHECK_FALSE(result.incident_raised);
    CHECK(remote_access_runtime_is_verified_closed());
    CHECK(firewall.run(
              {"iptables", "-w", "1", "-S", "KeenPbrRemote"}) == 1);
    CHECK(firewall.run({"iptables", "-w", "1", "-t", "nat", "-S",
                        "KeenPbrRemote"}) == 1);

    const auto stored = nlohmann::json::parse(std::ifstream(settings_path));
    CHECK_FALSE(stored.at("enabled").get<bool>());
    CHECK(stored.at("port") == 12121);

    result = refresh_remote_access_reconcile("0.0.0.0:12121");
    CHECK(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::closed);
    CHECK_FALSE(result.incident_raised);
    CHECK_FALSE(result.incident_cleared);
    CHECK(std::none_of(
        logs.lines().begin(), logs.lines().end(),
        [](const std::string& line) {
            return line.find(
                       "Cannot reconcile remote-access firewall state") !=
                   std::string::npos;
        }));

    SseBroadcaster broadcaster;
    auto context = make_remote_access_context(broadcaster);
    ApiConfig config;
    const int api_port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(config);
    register_remote_access_handler(server, context);
    server.start();
    httplib::Client client("127.0.0.1", api_port);
    const auto status = client.Get("/api/system/remote-access");
    REQUIRE(status != nullptr);
    const auto status_body = nlohmann::json::parse(status->body);
    CHECK_FALSE(status_body.at("enabled").get<bool>());
    CHECK(status_body.at("auth_provider") == "keenetic");
    CHECK(status_body.at("blocked_reason") ==
          "keenetic_auth_plaintext_wan");
    CHECK(status_body.at("keenetic_auth_switch_allowed").get<bool>());
    CHECK_FALSE(status_body.at("custom_port_supported").get<bool>());
    CHECK(status_body.at("supported_port") == 12121);
    const auto enable = client.Post(
        "/api/system/remote-access",
        R"({"enabled":true,"port":12121})",
        "application/json");
    server.stop();
    REQUIRE(enable != nullptr);
    CHECK(nlohmann::json::parse(enable->body).at("error") ==
          "keenetic_auth_plaintext_wan");
}

TEST_CASE("Keenetic auth normalization keeps cleanup failures in bounded recovery") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":true,"port":12121})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"local"})";
    }

    FakeIptables firewall;
    bool cleanup_blocked = false;
    set_remote_access_command_runner_for_testing(
        [&firewall, &cleanup_blocked](
            const std::vector<std::string>& command) {
            return cleanup_blocked ? 4 : firewall.run(command);
        });

    const auto opened =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE(opened.apply.applied);
    REQUIRE(opened.status.state == RemoteAccessRuntimeState::applied);
    REQUIRE(firewall.run({"iptables", "-w", "1", "-t", "nat", "-N",
                          "KeenPbrRemote"}) == 0);
    REQUIRE(firewall.run({"iptables", "-w", "1", "-t", "nat", "-I",
                          "PREROUTING", "1", "-j", "KeenPbrRemote"}) == 0);
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"keenetic"})";
    }

    cleanup_blocked = true;
    RemoteAccessLogCapture logs;
    auto result = refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE_FALSE(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::pending);
    CHECK_FALSE(result.status.desired_enabled);
    CHECK(result.status.recovery_owned);
    CHECK(result.status.attempt == 1U);
    CHECK_FALSE(result.incident_raised);
    const auto generation = result.status.desired_generation;

    const auto stored = nlohmann::json::parse(std::ifstream(settings_path));
    CHECK_FALSE(stored.at("enabled").get<bool>());
    CHECK(stored.at("port") == 12121);

    for (unsigned int attempt = 2U; attempt <= 7U; ++attempt) {
        result = retry_remote_access_reconcile(
            generation, "0.0.0.0:12121");
    }
    CHECK_FALSE(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::degraded);
    CHECK(result.status.incident_active);
    CHECK(result.status.recovery_owned);
    CHECK(result.status.maintenance);
    CHECK(result.status.attempt == 7U);
    CHECK(result.incident_raised);
    CHECK(result.status.error.find(
              "owned firewall rules could not be removed and verified") !=
          std::string::npos);
    CHECK(result.status.error.find("plaintext WAN HTTP") ==
          std::string::npos);
    CHECK(std::count_if(
              logs.lines().begin(), logs.lines().end(),
              [](const std::string& line) {
                  return line.find(
                             "Cannot reconcile remote-access firewall state") !=
                         std::string::npos;
              }) == 1);

    result = retry_remote_access_reconcile(
        generation, "0.0.0.0:12121");
    CHECK_FALSE(result.incident_raised);
    CHECK(std::count_if(
              logs.lines().begin(), logs.lines().end(),
              [](const std::string& line) {
                  return line.find(
                             "Cannot reconcile remote-access firewall state") !=
                         std::string::npos;
              }) == 1);

    cleanup_blocked = false;
    result = retry_remote_access_reconcile(
        generation, "0.0.0.0:12121");
    CHECK(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::closed);
    CHECK(result.incident_cleared);
    CHECK(remote_access_runtime_is_verified_closed());
    CHECK(firewall.run(
              {"iptables", "-w", "1", "-S", "KeenPbrRemote"}) == 1);
    CHECK(firewall.run({"iptables", "-w", "1", "-t", "nat", "-S",
                        "KeenPbrRemote"}) == 1);
}

TEST_CASE("remote access reports pending and schedules an unapplied firewall state") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    { std::ofstream auth(directory.path / "auth.json"); auth << R"({"enabled":true})"; }
    std::atomic<unsigned int> command_count{0};
    set_remote_access_command_runner_for_testing(
        [&command_count](const std::vector<std::string>&) {
            command_count.fetch_add(1U, std::memory_order_relaxed);
            return 2;
        });

    SseBroadcaster broadcaster;
    auto context = make_remote_access_context(broadcaster);
    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_remote_access_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto response = client.Post(
        "/api/system/remote-access",
        R"({"enabled":true,"port":12121})",
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("ok").get<bool>());
    CHECK_FALSE(body.at("degraded").get<bool>());
    CHECK(body.at("pending").get<bool>());
    CHECK(body.at("retry_scheduled").get<bool>());
    CHECK(body.at("retry_after_ms") == 0);
    CHECK(body.contains("detail"));
    CHECK(command_count.load(std::memory_order_relaxed) == 0U);
    const auto attempted = retry_remote_access_reconcile(
        body.at("generation").get<std::uint64_t>(),
        "0.0.0.0:12121");
    CHECK_FALSE(attempted.apply.applied);
    CHECK(attempted.retry.delay == std::chrono::seconds{1});
    CHECK(command_count.load(std::memory_order_relaxed) > 0U);
    CHECK_FALSE(remove_remote_access_rules());

    std::ifstream stored_file(settings_path);
    REQUIRE(stored_file.is_open());
    const auto stored = nlohmann::json::parse(stored_file);
    CHECK(stored.at("enabled").get<bool>());
    CHECK(stored.at("port") == 12121);
}

TEST_CASE("remote access retries with timed hints and clears degraded state on success") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE",
        (directory.path / "remote-access.json").string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    { std::ofstream auth(directory.path / "auth.json"); auth << R"({"enabled":true})"; }
    { std::ofstream settings(directory.path / "remote-access.json"); settings << R"({"enabled":true,"port":12121})"; }

    RemoteAccessLogCapture logs;
    const auto error_count = [&logs]() {
        return std::count_if(
            logs.lines().begin(), logs.lines().end(),
            [](const std::string& line) {
                return line.rfind("[E] ", 0) == 0;
            });
    };

    FakeIptables firewall;
    bool blocked = true;
    set_remote_access_command_runner_for_testing(
        [&firewall, &blocked](const std::vector<std::string>& command) {
            return blocked ? 4 : firewall.run(command);
        });

    std::vector<RemoteAccessRetryHint> hints;
    set_remote_access_retry_scheduler(
        [&hints](const RemoteAccessRetryHint& hint) {
            hints.push_back(hint);
        });

    auto result = refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE_FALSE(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::pending);
    CHECK(result.status.attempt == 1);
    CHECK(result.status.recovery_owned);
    CHECK_FALSE(result.status.maintenance);
    REQUIRE(hints.size() == 1);
    CHECK(hints.back().delay == std::chrono::seconds{1});

    const auto generation = result.status.desired_generation;
    result = refresh_remote_access_reconcile("0.0.0.0:12121");
    CHECK(result.status.desired_generation == generation);
    CHECK(result.status.attempt == 2);
    CHECK(error_count() == 0);

    for (unsigned int attempt = 3; attempt <= 7; ++attempt) {
        result = retry_remote_access_reconcile(
            result.status.desired_generation, "0.0.0.0:12121");
        if (attempt < 7) CHECK(error_count() == 0);
    }
    CHECK(result.status.state == RemoteAccessRuntimeState::degraded);
    CHECK(result.status.incident_active);
    CHECK(result.status.attempt == 7);
    CHECK(result.status.recovery_owned);
    CHECK(result.status.maintenance);
    CHECK(result.incident_raised);
    CHECK(error_count() == 1);
    CHECK(result.retry.maintenance);
    CHECK(result.retry.delay == std::chrono::seconds{60});

    result = refresh_remote_access_reconcile("0.0.0.0:12121");
    CHECK(result.status.desired_generation == generation);
    CHECK(result.status.attempt == 8);
    CHECK(result.status.state == RemoteAccessRuntimeState::degraded);
    CHECK_FALSE(result.incident_raised);
    CHECK(error_count() == 1);

    blocked = false;
    result = retry_remote_access_reconcile(
        result.status.desired_generation, "0.0.0.0:12121");
    CHECK(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::applied);
    CHECK_FALSE(result.status.incident_active);
    CHECK(result.status.attempt == 0);
    CHECK_FALSE(result.status.recovery_owned);
    CHECK_FALSE(result.status.maintenance);
    CHECK(result.status.error.empty());
    CHECK(result.status.phase == RemoteAccessReconcilePhase::idle);
    CHECK(result.incident_cleared);
    CHECK(error_count() == 1);
}

TEST_CASE("remote access preserves the exact failed firewall phase") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE",
        (directory.path / "remote-access.json").string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    { std::ofstream auth(directory.path / "auth.json"); auth << R"({"enabled":true})"; }
    { std::ofstream settings(directory.path / "remote-access.json"); settings << R"({"enabled":true,"port":12121})"; }

    FakeIptables firewall;
    bool fail_filter_create = true;
    set_remote_access_command_runner_for_testing(
        [&firewall, &fail_filter_create](
            const std::vector<std::string>& command) {
            const auto create = std::find(
                command.begin(), command.end(), "-N");
            const bool nat = std::find(
                command.begin(), command.end(), "nat") != command.end();
            if (fail_filter_create && !nat && create != command.end() &&
                create + 1 != command.end() && *(create + 1) == "KeenPbrRemote") {
                fail_filter_create = false;
                return 4;
            }
            return firewall.run(command);
        });

    const auto result =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    CHECK_FALSE(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::pending);
    CHECK(result.status.phase ==
          RemoteAccessReconcilePhase::install_filter);
    CHECK(result.status.command_exit_code == 4);
    CHECK(result.status.error.find("phase=install_filter") !=
          std::string::npos);
}

TEST_CASE("remote access permanent failure retires transient recovery ownership") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE",
        (directory.path / "remote-access.json").string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    {
        std::ofstream auth(directory.path / "auth.json");
        auth << R"({"enabled":true})";
    }
    {
        std::ofstream settings(directory.path / "remote-access.json");
        settings << R"({"enabled":true,"port":12121})";
    }

    FakeIptables firewall;
    bool transient_block = true;
    set_remote_access_command_runner_for_testing(
        [&firewall, &transient_block](
            const std::vector<std::string>& command) {
            return transient_block ? 4 : firewall.run(command);
        });

    auto result = refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE_FALSE(result.apply.applied);
    REQUIRE(result.status.attempt == 1U);
    REQUIRE(result.status.recovery_owned);
    REQUIRE(result.retry.schedule);

    transient_block = false;
    {
        std::ofstream auth(directory.path / "auth.json");
        auth << R"({"enabled":false})";
    }
    result = retry_remote_access_reconcile(
        result.status.desired_generation, "0.0.0.0:12121");

    CHECK_FALSE(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::degraded);
    CHECK(result.status.attempt == 1U);
    CHECK_FALSE(result.status.recovery_owned);
    CHECK_FALSE(result.status.maintenance);
    CHECK_FALSE(result.retry.schedule);
    CHECK(result.incident_raised);
}

TEST_CASE("enabling authentication revives a closed remote desired state") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":true,"port":12121})";
    }
    {
        std::ofstream auth(auth_path);
        // Merely selecting the provider while authentication is disabled is
        // not an incompatible published credential path. Preserve the remote
        // desired state so enabling a safe provider can revive it below.
        auth << R"({"enabled":false,"provider":"keenetic"})";
    }

    FakeIptables firewall;
    std::atomic<unsigned int> command_count{0};
    set_remote_access_command_runner_for_testing(
        [&firewall, &command_count](const std::vector<std::string>& command) {
            command_count.fetch_add(1U, std::memory_order_relaxed);
            return firewall.run(command);
        });

    const auto auth_disabled =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE_FALSE(auth_disabled.apply.applied);
    REQUIRE(auth_disabled.status.state ==
            RemoteAccessRuntimeState::degraded);
    REQUIRE_FALSE(auth_disabled.status.recovery_owned);
    REQUIRE_FALSE(auth_disabled.retry.schedule);
    const auto commands_after_fail_closed =
        command_count.load(std::memory_order_relaxed);

    std::vector<RemoteAccessRetryHint> hints;
    set_remote_access_retry_scheduler(
        [&hints](const RemoteAccessRetryHint& hint) {
            hints.push_back(hint);
        });

    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto response = client.Post(
        "/api/auth/settings",
        R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})",
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("saved").get<bool>());
    CHECK(body.at("remote_access_pending").get<bool>());
    REQUIRE(hints.size() == 1U);
    CHECK(hints.front().delay == std::chrono::seconds{0});
    CHECK(hints.front().generation ==
          body.at("remote_access_generation").get<std::uint64_t>());
    // The auth HTTP worker only admitted work; it never became an iptables
    // writer itself.
    CHECK(command_count.load(std::memory_order_relaxed) ==
          commands_after_fail_closed);

    const auto recovered = retry_remote_access_reconcile(
        hints.front().generation, "0.0.0.0:12121");
    CHECK(recovered.apply.applied);
    CHECK(recovered.status.state == RemoteAccessRuntimeState::applied);
    CHECK_FALSE(recovered.status.recovery_owned);
    CHECK(command_count.load(std::memory_order_relaxed) >
          commands_after_fail_closed);
}

TEST_CASE("auth enable queues cleanup for an uninitialized remote runtime") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":false,"port":15443})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":false,"provider":"local"})";
    }

    const auto uninitialized = remote_access_runtime_status();
    REQUIRE(uninitialized.desired_generation == 0U);
    REQUIRE(uninitialized.state == RemoteAccessRuntimeState::closed);

    std::atomic<unsigned int> command_count{0};
    set_remote_access_command_runner_for_testing(
        [&command_count](const std::vector<std::string>&) {
            command_count.fetch_add(1U, std::memory_order_relaxed);
            return 1;
        });
    std::vector<RemoteAccessRetryHint> hints;
    set_remote_access_retry_scheduler(
        [&hints](const RemoteAccessRetryHint& hint) {
            hints.push_back(hint);
        });

    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", port);
    const auto response = client.Post(
        "/api/auth/settings",
        R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})",
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("remote_access_pending").get<bool>());
    REQUIRE(hints.size() == 1U);
    CHECK(hints.front().generation != 0U);
    CHECK(hints.front().delay == std::chrono::seconds{0});
    const auto pending = remote_access_runtime_status();
    CHECK(pending.desired_generation == hints.front().generation);
    CHECK_FALSE(pending.desired_enabled);
    CHECK(pending.state == RemoteAccessRuntimeState::pending);
    CHECK(command_count.load(std::memory_order_relaxed) == 0U);
}

TEST_CASE("auth settings need step-up and cannot switch to Keenetic while WAN is desired") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    set_trusted_local_connection_evaluator_for_testing(
        [](std::string_view, std::string_view, bool) { return true; });
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":true,"port":12121})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})";
    }

    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", port);
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", remote_access_session_cookie(*login)},
    };
    const auto request_body =
        R"({"enabled":true,"provider":"keenetic","username":"admin","password":"router-secret"})";

    const auto without_step_up = client.Post(
        "/api/auth/settings", headers, request_body, "application/json");
    REQUIRE(without_step_up != nullptr);
    CHECK(without_step_up->status == 403);
    CHECK(nlohmann::json::parse(without_step_up->body).at("error") ==
          "step_up_required");

    grant_step_up(client, headers, "admin", "secret");
    const auto before_blocked_switch =
        nlohmann::json::parse(std::ifstream(auth_path));
    REQUIRE(before_blocked_switch.at("provider") == "local");
    REQUIRE(before_blocked_switch.at("password_format") ==
            kLocalPasswordHashFormat);
    const auto migrated_password =
        before_blocked_switch.at("password").get<std::string>();
    REQUIRE(local_password_hash_encoded(migrated_password));
    REQUIRE(verify_local_password(migrated_password, "secret") ==
            LocalPasswordVerdict::matched);
    const auto blocked = client.Post(
        "/api/auth/settings", headers, request_body, "application/json");
    server.stop();

    REQUIRE(blocked != nullptr);
    CHECK(blocked->status == 409);
    CHECK(nlohmann::json::parse(blocked->body).at("error") ==
          "remote_access_incompatible_with_keenetic_auth");
    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    CHECK(stored.at("provider") == "local");
    CHECK(stored == before_blocked_switch);
    CHECK(stored.at("password") == migrated_password);
    CHECK(verify_local_password(
              stored.at("password").get<std::string>(), "secret") ==
          LocalPasswordVerdict::matched);
}

TEST_CASE("remote access shares the middleware auth file authority") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto production_auth_path = directory.path / "auth-production.json";
    const auto test_auth_path = directory.path / "auth-test-override.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard production_auth_file(
        "KEEN_PBR_AUTH_FILE", production_auth_path.string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    { std::ofstream settings(settings_path); settings << R"({"enabled":true,"port":12121})"; }
    { std::ofstream auth(production_auth_path); auth << R"({"enabled":true})"; }
    { std::ofstream auth(test_auth_path); auth << R"({"enabled":false})"; }

    FakeIptables firewall;
    set_remote_access_command_runner_for_testing(
        [&firewall](const std::vector<std::string>& command) {
            return firewall.run(command);
        });
    const auto production =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE(production.apply.applied);
    REQUIRE(production.status.state ==
            RemoteAccessRuntimeState::applied);

    // Test isolation remains stronger than the process-wide production path.
    // With both variables present, the dedicated remote fixture wins.
    {
        EnvironmentVariableGuard test_auth_file(
            "KEEN_PBR_TEST_REMOTE_AUTH_FILE", test_auth_path.string());
        reset_remote_access_reconciler_for_testing();
        const auto overridden =
            refresh_remote_access_reconcile("0.0.0.0:12121");
        CHECK_FALSE(overridden.apply.applied);
        CHECK(overridden.status.state ==
              RemoteAccessRuntimeState::degraded);
        CHECK_FALSE(overridden.status.recovery_owned);
    }
}

TEST_CASE("remote writer waits for auth disk and runtime publication") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":true,"port":12121})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})";
    }

    FakeIptables firewall;
    std::atomic<unsigned int> command_count{0};
    set_remote_access_command_runner_for_testing(
        [&firewall, &command_count](const std::vector<std::string>& command) {
            command_count.fetch_add(1U, std::memory_order_relaxed);
            return firewall.run(command);
        });

    // Model rules retained from the previous process, then its externally
    // published auth-disabled state and a fresh uninitialized coordinator.
    const auto seeded_rules =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE(seeded_rules.apply.applied);
    const auto commands_with_retained_rules =
        command_count.load(std::memory_order_relaxed);
    REQUIRE(commands_with_retained_rules > 0U);
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":false,"provider":"local"})";
    }
    reset_remote_access_reconciler_for_testing();

    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool disk_published = false;
    bool release_auth_publication = false;
    std::vector<std::string> events;
    set_auth_settings_publication_hook_for_testing(
        [&](AuthSettingsPublicationStage stage) {
            std::unique_lock<std::mutex> lock(barrier_mutex);
            if (stage == AuthSettingsPublicationStage::disk_published) {
                events.push_back("disk_published");
                disk_published = true;
                barrier_cv.notify_all();
                barrier_cv.wait(lock, [&]() {
                    return release_auth_publication;
                });
                return;
            }
            events.push_back("runtime_published");
            barrier_cv.notify_all();
        });
    set_remote_access_security_fence_hook_for_testing(
        [&](RemoteAccessSecurityFenceStage stage) {
            const std::lock_guard<std::mutex> lock(barrier_mutex);
            events.push_back(
                stage == RemoteAccessSecurityFenceStage::waiting
                    ? "writer_waiting"
                    : "writer_acquired");
            barrier_cv.notify_all();
        });

    std::vector<RemoteAccessRetryHint> hints;
    set_remote_access_retry_scheduler(
        [&hints](const RemoteAccessRetryHint& hint) {
            hints.push_back(hint);
        });

    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    server.start();

    int auth_status = 0;
    std::string auth_body;
    std::thread auth_thread([&]() {
        httplib::Client client("127.0.0.1", port);
        const auto response = client.Post(
            "/api/auth/settings",
            R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})",
            "application/json");
        if (response) {
            auth_status = response->status;
            auth_body = response->body;
        }
    });
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier_cv.wait(lock, [&]() { return disk_published; });
    }

    // The durable file is already enabled, while middleware deliberately
    // remains on its old disabled snapshot at this barrier. Even though the
    // old WAN rules still exist, the application-layer latch rejects rather
    // than admitting the request with that disabled snapshot.
    CHECK(nlohmann::json::parse(std::ifstream(auth_path))
              .at("enabled")
              .get<bool>());
    httplib::Client status_client("127.0.0.1", port);
    const auto old_runtime_status =
        status_client.Get("/api/auth/status");
    CHECK(old_runtime_status != nullptr);
    if (old_runtime_status) CHECK(old_runtime_status->status == 503);

    RemoteAccessReconcileResult racing_reconcile;
    std::thread reconcile_thread([&]() {
        racing_reconcile =
            refresh_remote_access_reconcile("0.0.0.0:12121");
    });
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier_cv.wait(lock, [&]() {
            return std::find(events.begin(), events.end(),
                             "writer_waiting") != events.end();
        });
        CHECK(std::find(events.begin(), events.end(),
                        "writer_acquired") == events.end());
        release_auth_publication = true;
    }
    CHECK(command_count.load(std::memory_order_relaxed) ==
          commands_with_retained_rules);
    barrier_cv.notify_all();

    auth_thread.join();
    reconcile_thread.join();
    server.stop();

    REQUIRE(auth_status == 200);
    const auto saved_auth = nlohmann::json::parse(auth_body);
    CHECK(saved_auth.at("saved").get<bool>());
    CHECK(saved_auth.at("remote_access_pending").get<bool>());
    CHECK(racing_reconcile.stale);
    CHECK(command_count.load(std::memory_order_relaxed) ==
          commands_with_retained_rules);

    const auto event_index = [&events](const std::string& event) {
        return std::distance(
            events.begin(),
            std::find(events.begin(), events.end(), event));
    };
    REQUIRE(std::find(events.begin(), events.end(),
                      "runtime_published") != events.end());
    REQUIRE(std::find(events.begin(), events.end(),
                      "writer_acquired") != events.end());
    CHECK(event_index("disk_published") < event_index("writer_waiting"));
    CHECK(event_index("writer_waiting") < event_index("runtime_published"));
    CHECK(event_index("runtime_published") < event_index("writer_acquired"));
    REQUIRE(hints.size() == 1U);
    CHECK(hints.front().generation ==
          saved_auth.at("remote_access_generation").get<std::uint64_t>());

    reset_auth_settings_publication_hook_for_testing();
    reset_remote_access_security_fence_hook_for_testing();
    const auto recovered = retry_remote_access_reconcile(
        hints.front().generation, "0.0.0.0:12121");
    CHECK(recovered.apply.applied);
    CHECK(recovered.status.state == RemoteAccessRuntimeState::applied);
    CHECK(command_count.load(std::memory_order_relaxed) >
          commands_with_retained_rules);
}

TEST_CASE("remote access releases single-flight ownership after runner exception") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE",
        (directory.path / "remote-access.json").string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    { std::ofstream auth(directory.path / "auth.json"); auth << R"({"enabled":true})"; }
    { std::ofstream settings(directory.path / "remote-access.json"); settings << R"({"enabled":true,"port":12121})"; }

    bool throw_once = true;
    FakeIptables firewall;
    set_remote_access_command_runner_for_testing(
        [&throw_once, &firewall](const std::vector<std::string>& command) {
            if (throw_once) {
                throw_once = false;
                throw std::runtime_error("injected runner failure");
            }
            return firewall.run(command);
        });

    auto result =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    CHECK_FALSE(result.apply.applied);
    CHECK(result.status.phase == RemoteAccessReconcilePhase::internal);
    CHECK(result.status.attempt == 1);
    CHECK(result.retry.schedule);

    result = retry_remote_access_reconcile(
        result.status.desired_generation, "0.0.0.0:12121");
    CHECK(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::applied);
}

TEST_CASE("remote access coalesces a concurrent refresh into one trailing pass") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE",
        (directory.path / "remote-access.json").string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    { std::ofstream auth(directory.path / "auth.json"); auth << R"({"enabled":true})"; }
    { std::ofstream settings(directory.path / "remote-access.json"); settings << R"({"enabled":true,"port":12121})"; }

    FakeIptables firewall;
    bool reentered = false;
    RemoteAccessReconcileResult nested;
    set_remote_access_command_runner_for_testing(
        [&firewall, &reentered, &nested](
            const std::vector<std::string>& command) {
            if (!reentered && std::find(command.begin(), command.end(), "-N") !=
                                  command.end()) {
                reentered = true;
                nested = refresh_remote_access_reconcile(
                    "0.0.0.0:12121");
            }
            return firewall.run(command);
        });

    std::vector<RemoteAccessRetryHint> hints;
    set_remote_access_retry_scheduler(
        [&hints](const RemoteAccessRetryHint& hint) {
            hints.push_back(hint);
        });

    auto result = refresh_remote_access_reconcile("0.0.0.0:12121");
    CHECK(nested.coalesced);
    CHECK(result.stale);
    CHECK(result.retry.schedule);
    CHECK(result.retry.delay == std::chrono::milliseconds{0});
    CHECK(result.status.desired_generation == 1);
    REQUIRE(hints.size() == 1);
    CHECK(hints.front().generation == 1);

    result = retry_remote_access_reconcile(1, "0.0.0.0:12121");
    CHECK(result.apply.applied);
    CHECK(result.status.applied_generation == 1);
}

TEST_CASE("remote access counts a failed attempt during a coalesced refresh") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE",
        (directory.path / "remote-access.json").string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    { std::ofstream auth(directory.path / "auth.json"); auth << R"({"enabled":true})"; }
    { std::ofstream settings(directory.path / "remote-access.json"); settings << R"({"enabled":true,"port":12121})"; }

    bool reentered = false;
    RemoteAccessReconcileResult nested;
    set_remote_access_command_runner_for_testing(
        [&reentered, &nested](const std::vector<std::string>&) {
            if (!reentered) {
                reentered = true;
                nested = refresh_remote_access_reconcile(
                    "0.0.0.0:12121");
            }
            return 4;
        });

    const auto result =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    CHECK(nested.coalesced);
    CHECK_FALSE(result.apply.applied);
    CHECK(result.status.desired_generation == 1);
    CHECK(result.status.attempt == 1);
    CHECK(result.status.state == RemoteAccessRuntimeState::pending);
    CHECK(result.retry.delay == std::chrono::seconds{1});
}

TEST_CASE("remote access retains an API retry hint until scheduler registration") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE",
        (directory.path / "remote-access.json").string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    { std::ofstream auth(directory.path / "auth.json"); auth << R"({"enabled":true})"; }
    { std::ofstream settings(directory.path / "remote-access.json"); settings << R"({"enabled":true,"port":12121})"; }

    set_remote_access_command_runner_for_testing(
        [](const std::vector<std::string>&) { return 4; });
    const auto result =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE(result.retry.schedule);

    std::vector<RemoteAccessRetryHint> delivered;
    set_remote_access_retry_scheduler(
        [&delivered](const RemoteAccessRetryHint& hint) {
            // Re-entry proves dispatch does not hold the registry mutex.
            (void)remote_access_runtime_status();
            delivered.push_back(hint);
        });
    REQUIRE(delivered.size() == 1);
    CHECK(delivered.front().generation ==
          result.status.desired_generation);
    CHECK(delivered.front().delay == std::chrono::seconds{1});
}

TEST_CASE("remote access teardown cleanup failure is quiet") {
    RemoteAccessRunnerGuard runner_guard;
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    set_remote_access_command_runner_for_testing(
        [](const std::vector<std::string>&) { return 4; });

    RemoteAccessLogCapture logs;
    CHECK_FALSE(remove_remote_access_rules(
        RemoteAccessRemovalMode::expected_teardown));
    CHECK(std::none_of(
        logs.lines().begin(), logs.lines().end(),
        [](const std::string& line) { return line.rfind("[E] ", 0) == 0; }));
    CHECK(std::any_of(
        logs.lines().begin(), logs.lines().end(),
        [](const std::string& line) {
            return line.find("expected teardown") != std::string::npos;
        }));
}

TEST_CASE("auth disable waits for verified startup remote cleanup") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    set_trusted_local_connection_evaluator_for_testing(
        [](std::string_view, std::string_view, bool) { return true; });
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":false,"port":15443})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})";
    }

    const auto before_reconcile = remote_access_runtime_status();
    REQUIRE(before_reconcile.desired_generation == 0U);

    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", remote_access_session_cookie(*login)},
    };
    grant_step_up(client, headers, "admin", "secret");
    const auto disable = client.Post(
        "/api/auth/settings",
        headers,
        R"({"enabled":false,"provider":"local"})",
        "application/json");
    server.stop();

    REQUIRE(disable != nullptr);
    CHECK(disable->status == 409);
    CHECK(nlohmann::json::parse(disable->body).at("error") ==
          "remote_access_enabled");
    CHECK(nlohmann::json::parse(std::ifstream(auth_path))
              .at("enabled")
              .get<bool>());
}

TEST_CASE("auth disable is staged so existing connections stay protected") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    set_trusted_local_connection_evaluator_for_testing(
        [](std::string_view, std::string_view, bool) { return true; });
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":false,"port":15443})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})";
    }

    FakeIptables firewall;
    set_remote_access_command_runner_for_testing(
        [&firewall](const std::vector<std::string>& command) {
            return firewall.run(command);
        });
    const auto closed =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE(closed.apply.applied);
    REQUIRE(remote_access_runtime_is_verified_closed());

    SseBroadcaster broadcaster;
    auto context = make_remote_access_context(broadcaster);
    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_remote_access_handler(server, context);
    server.start();

    httplib::Client keep_alive_client("127.0.0.1", port);
    const auto login = keep_alive_client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", remote_access_session_cookie(*login)},
    };
    grant_step_up(keep_alive_client, headers, "admin", "secret");
    const auto disable = keep_alive_client.Post(
        "/api/auth/settings",
        headers,
        R"({"enabled":false,"provider":"local"})",
        "application/json");
    REQUIRE(disable != nullptr);
    REQUIRE(disable->status == 200);
    const auto saved = nlohmann::json::parse(disable->body);
    CHECK(saved.at("saved").get<bool>());
    CHECK(saved.at("restart_required").get<bool>());
    CHECK(saved.at("runtime_auth_enabled").get<bool>());
    CHECK_FALSE(nlohmann::json::parse(std::ifstream(auth_path))
                    .at("enabled")
                    .get<bool>());

    // The same connection and its now-cleared session cannot inherit an
    // unauthenticated runtime. Registered long-lived streams are revoked by
    // the same session-epoch transition, covered by the next regression.
    const auto protected_request = keep_alive_client.Get(
        "/api/system/remote-access", headers);
    REQUIRE(protected_request != nullptr);
    CHECK(protected_request->status == 401);
    const auto runtime_auth =
        keep_alive_client.Get("/api/auth/status");
    server.stop();

    REQUIRE(runtime_auth != nullptr);
    const auto runtime = nlohmann::json::parse(runtime_auth->body);
    CHECK(runtime.at("enabled").get<bool>());
    CHECK_FALSE(runtime.at("authenticated").get<bool>());
}

TEST_CASE("credential rotation revokes admitted SSE cohorts") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    set_trusted_local_connection_evaluator_for_testing(
        [](std::string_view, std::string_view, bool) { return true; });
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":false,"port":15443})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"local","username":"admin","password":"old-secret"})";
    }

    SseBroadcaster dns_broadcaster;
    StatusStream status_stream([] { return StatusSnapshot{}; });
    auto context = make_remote_access_context(dns_broadcaster);
    context.status_stream = &status_stream;

    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_dns_test_handler(server, context);
    register_status_events_handler(server, context);

    auto admitted_dns = dns_broadcaster.subscribe();
    auto admitted_status = status_stream.subscribe();
    REQUIRE(admitted_dns != nullptr);
    REQUIRE(admitted_status != nullptr);
    REQUIRE(dns_broadcaster.active_subscriptions() == 1U);
    REQUIRE(status_stream.has_subscribers());
    dns_broadcaster.publish(
        R"({"type":"RESULT","sensitive":"old-session"})");

    server.start();
    httplib::Client client("127.0.0.1", port);
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"old-secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", remote_access_session_cookie(*login)},
    };
    grant_step_up(client, headers, "admin", "old-secret");
    const auto rotated = client.Post(
        "/api/auth/settings",
        headers,
        R"({"enabled":true,"provider":"local","username":"admin","password":"new-secret"})",
        "application/json");
    server.stop();

    REQUIRE(rotated != nullptr);
    REQUIRE(rotated->status == 200);
    CHECK(dns_broadcaster.active_subscriptions() == 0U);
    CHECK_FALSE(status_stream.has_subscribers());
    const auto revoked_dns = wait_for_sse_subscription(
        admitted_dns,
        std::chrono::milliseconds{0},
        std::chrono::milliseconds{0});
    const auto revoked_status = wait_for_sse_subscription(
        admitted_status,
        std::chrono::milliseconds{0},
        std::chrono::milliseconds{0});
    CHECK(revoked_dns.status == SseSubscriptionWaitStatus::CLOSED);
    CHECK(revoked_dns.message.empty());
    CHECK(revoked_status.status == SseSubscriptionWaitStatus::CLOSED);
    CHECK(revoked_status.message.empty());

    // Revocation closes only the previous session epoch. Freshly
    // authenticated clients can establish replacement streams.
    auto replacement_dns = dns_broadcaster.subscribe();
    auto replacement_status = status_stream.subscribe();
    CHECK(replacement_dns != nullptr);
    CHECK(replacement_status != nullptr);
    dns_broadcaster.unsubscribe(replacement_dns);
    status_stream.unsubscribe(replacement_status);
}

TEST_CASE(
    "credential rotation rejects a stream paused after middleware admission") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    set_trusted_local_connection_evaluator_for_testing(
        [](std::string_view, std::string_view, bool) { return true; });
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":false,"port":15443})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"local","username":"admin","password":"old-secret"})";
    }

    SseBroadcaster dns_broadcaster;
    auto context = make_remote_access_context(dns_broadcaster);
    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_dns_test_handler(server, context);

    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool middleware_admitted = false;
    bool release_stream = false;
    set_stream_admission_hook_for_testing([&]() {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        middleware_admitted = true;
        barrier_cv.notify_all();
        barrier_cv.wait(lock, [&]() { return release_stream; });
    });

    server.start();
    httplib::Client login_client("127.0.0.1", port);
    const auto login = login_client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"old-secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", remote_access_session_cookie(*login)},
    };
    grant_step_up(login_client, headers, "admin", "old-secret");

    int stream_status = 0;
    std::thread stream_thread([&]() {
        httplib::Client stream_client("127.0.0.1", port);
        const auto response = stream_client.Get(
            "/api/dns/test", headers);
        if (response) stream_status = response->status;
    });
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier_cv.wait(lock, [&]() { return middleware_admitted; });
    }

    httplib::Client rotate_client("127.0.0.1", port);
    const auto rotated = rotate_client.Post(
        "/api/auth/settings",
        headers,
        R"({"enabled":true,"provider":"local","username":"admin","password":"new-secret"})",
        "application/json");
    REQUIRE(rotated != nullptr);
    REQUIRE(rotated->status == 200);
    {
        const std::lock_guard<std::mutex> lock(barrier_mutex);
        release_stream = true;
    }
    barrier_cv.notify_all();
    stream_thread.join();
    server.stop();

    CHECK(stream_status == 401);
    CHECK(dns_broadcaster.active_subscriptions() == 0U);
}

TEST_CASE("queued credential rotation loses revoked session authority") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    set_trusted_local_connection_evaluator_for_testing(
        [](std::string_view, std::string_view, bool) { return true; });
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    { std::ofstream settings(settings_path); settings << R"({"enabled":false,"port":15443})"; }
    { std::ofstream auth(auth_path); auth << R"({"enabled":true,"provider":"local","username":"admin","password":"old-secret"})"; }

    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    server.start();
    httplib::Client login_client("127.0.0.1", port);
    const auto login = login_client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"old-secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", remote_access_session_cookie(*login)},
    };
    grant_step_up(login_client, headers, "admin", "old-secret");

    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool first_disk_published = false;
    bool first_admitted = false;
    bool second_admitted = false;
    bool release_first_admission = false;
    bool release_second_admission = false;
    int admission_sequence = 0;
    struct AuthSettingsHooksReset {
        ~AuthSettingsHooksReset() {
            reset_auth_settings_admission_hook_for_testing();
            reset_auth_settings_publication_hook_for_testing();
        }
    } auth_settings_hooks_reset;
    set_auth_settings_publication_hook_for_testing(
        [&](AuthSettingsPublicationStage stage) {
            if (stage != AuthSettingsPublicationStage::disk_published) return;
            const std::lock_guard<std::mutex> lock(barrier_mutex);
            first_disk_published = true;
            barrier_cv.notify_all();
        });
    set_auth_settings_admission_hook_for_testing([&]() {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        const int sequence = ++admission_sequence;
        if (sequence == 1) {
            first_admitted = true;
            barrier_cv.notify_all();
            barrier_cv.wait(
                lock, [&]() { return release_first_admission; });
        } else if (sequence == 2) {
            second_admitted = true;
            barrier_cv.notify_all();
            barrier_cv.wait(
                lock, [&]() { return release_second_admission; });
        }
    });

    int first_status = 0;
    int second_status = 0;
    std::thread first([&]() {
        httplib::Client client("127.0.0.1", port);
        const auto response = client.Post(
            "/api/auth/settings", headers,
            R"({"enabled":true,"provider":"local","username":"admin","password":"first-secret"})",
            "application/json");
        if (response) first_status = response->status;
    });
    bool first_reached_admission = false;
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        first_reached_admission = barrier_cv.wait_for(
            lock,
            std::chrono::seconds{5},
            [&]() { return first_admitted; });
    }
    if (!first_reached_admission) {
        {
            const std::lock_guard<std::mutex> lock(barrier_mutex);
            release_first_admission = true;
            release_second_admission = true;
        }
        barrier_cv.notify_all();
        first.join();
        server.stop();
        REQUIRE(first_reached_admission);
        return;
    }
    std::thread second([&]() {
        httplib::Client client("127.0.0.1", port);
        const auto response = client.Post(
            "/api/auth/settings", headers,
            R"({"enabled":true,"provider":"local","username":"admin","password":"second-secret"})",
            "application/json");
        if (response) second_status = response->status;
    });
    bool second_reached_admission = false;
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        second_reached_admission = barrier_cv.wait_for(
            lock,
            std::chrono::seconds{5},
            [&]() { return second_admitted; });
        release_first_admission = true;
    }
    barrier_cv.notify_all();

    bool first_reached_publication = false;
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        first_reached_publication = barrier_cv.wait_for(
            lock,
            std::chrono::seconds{5},
            [&]() { return first_disk_published; });
        release_second_admission = true;
    }
    barrier_cv.notify_all();
    first.join();
    second.join();
    server.stop();

    REQUIRE(second_reached_admission);
    REQUIRE(first_reached_publication);
    CHECK(first_status == 200);
    CHECK(second_status == 401);
    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    // The credential on disk is the first writer's and is not the password
    // itself: what is stored is a derived key, so the winner is identified by
    // what it verifies rather than by what it reads.
    const auto persisted = stored.at("password").get<std::string>();
    CHECK(persisted != "first-secret");
    CHECK(local_password_hash_encoded(persisted));
    CHECK(verify_local_password(persisted, "first-secret") ==
          LocalPasswordVerdict::matched);
    CHECK(verify_local_password(persisted, "second-secret") ==
          LocalPasswordVerdict::mismatched);
}

TEST_CASE("verified login cannot publish a session after auth rotation") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    set_trusted_local_connection_evaluator_for_testing(
        [](std::string_view, std::string_view, bool) { return true; });
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    { std::ofstream settings(settings_path); settings << R"({"enabled":false,"port":15443})"; }
    { std::ofstream auth(auth_path); auth << R"({"enabled":true,"provider":"local","username":"admin","password":"old-secret"})"; }

    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    server.start();
    httplib::Client admin_client("127.0.0.1", port);
    const auto admin_login = admin_client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"old-secret"})",
        "application/json");
    REQUIRE(admin_login != nullptr);
    REQUIRE(admin_login->status == 200);
    const httplib::Headers admin_headers{
        {"Cookie", remote_access_session_cookie(*admin_login)},
    };
    grant_step_up(admin_client, admin_headers, "admin", "old-secret");

    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool old_login_verified = false;
    bool release_old_login = false;
    set_auth_login_verified_hook_for_testing([&]() {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        old_login_verified = true;
        barrier_cv.notify_all();
        barrier_cv.wait(lock, [&]() { return release_old_login; });
    });
    struct AuthLoginHookReset {
        ~AuthLoginHookReset() {
            reset_auth_login_verified_hook_for_testing();
        }
    } auth_login_hook_reset;

    int stale_login_status = 0;
    std::string stale_set_cookie;
    std::thread stale_login([&]() {
        httplib::Client client("127.0.0.1", port);
        const auto response = client.Post(
            "/api/auth/login",
            R"({"username":"admin","password":"old-secret"})",
            "application/json");
        if (response) {
            stale_login_status = response->status;
            stale_set_cookie =
                response->get_header_value("Set-Cookie");
        }
    });
    bool old_login_reached_verification = false;
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        old_login_reached_verification = barrier_cv.wait_for(
            lock,
            std::chrono::seconds{5},
            [&]() { return old_login_verified; });
        if (!old_login_reached_verification) {
            // Never strand the request thread when the admission prerequisite
            // fails. The bounded REQUIRE below then reports the real failure
            // instead of hanging the entire monolithic suite.
            release_old_login = true;
        }
    }
    if (!old_login_reached_verification) {
        barrier_cv.notify_all();
        stale_login.join();
        server.stop();
        REQUIRE(old_login_reached_verification);
        return;
    }

    httplib::Client rotate_client("127.0.0.1", port);
    const auto rotated = rotate_client.Post(
        "/api/auth/settings", admin_headers,
        R"({"enabled":true,"provider":"local","username":"admin","password":"new-secret"})",
        "application/json");
    {
        const std::lock_guard<std::mutex> lock(barrier_mutex);
        release_old_login = true;
    }
    barrier_cv.notify_all();
    stale_login.join();
    server.stop();

    REQUIRE(rotated != nullptr);
    REQUIRE(rotated->status == 200);
    CHECK(stale_login_status == 409);
    CHECK(stale_set_cookie.empty());
}

TEST_CASE("logout purges queued authenticated SSE data") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    { std::ofstream settings(settings_path); settings << R"({"enabled":false,"port":15443})"; }
    { std::ofstream auth(auth_path); auth << R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})"; }

    SseBroadcaster broadcaster;
    auto context = make_remote_access_context(broadcaster);
    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_dns_test_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", remote_access_session_cookie(*login)},
    };
    auto admitted = broadcaster.subscribe();
    REQUIRE(admitted != nullptr);
    broadcaster.publish("sensitive queued result");

    const auto logout = client.Post(
        "/api/auth/logout", headers, "", "application/json");
    server.stop();
    REQUIRE(logout != nullptr);
    REQUIRE(logout->status == 200);
    const auto revoked = wait_for_sse_subscription(
        admitted,
        std::chrono::milliseconds{0},
        std::chrono::milliseconds{0});
    CHECK(revoked.status == SseSubscriptionWaitStatus::CLOSED);
    CHECK(revoked.message.empty());
}

TEST_CASE("logout closes and purges SSE before erasing its session") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    { std::ofstream settings(settings_path); settings << R"({"enabled":false,"port":15443})"; }
    { std::ofstream auth(auth_path); auth << R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})"; }

    SseBroadcaster broadcaster;
    auto context = make_remote_access_context(broadcaster);
    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool revoke_started = false;
    bool release_revoke = false;
    // Registered first, this exposes the point inside the common revoke epoch
    // immediately before the broadcaster callback closes and purges queues.
    server.on_auth_sessions_revoked([&]() {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        revoke_started = true;
        barrier_cv.notify_all();
        barrier_cv.wait(lock, [&]() { return release_revoke; });
    });
    register_dns_test_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", remote_access_session_cookie(*login)},
    };
    auto admitted = broadcaster.subscribe();
    REQUIRE(admitted != nullptr);
    broadcaster.publish("sensitive queued result");

    int logout_status = 0;
    std::thread logout_thread([&]() {
        httplib::Client logout_client("127.0.0.1", port);
        const auto response = logout_client.Post(
            "/api/auth/logout", headers, "", "application/json");
        if (response) logout_status = response->status;
    });
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier_cv.wait(lock, [&]() { return revoke_started; });
    }

    // The session is still authoritative while callbacks are retiring its
    // streams. The old clear/erase-first ordering returned false here and
    // left a window in which an independent waiter could drain its queue.
    httplib::Client status_client("127.0.0.1", port);
    const auto during_revoke = status_client.Get(
        "/api/auth/status", headers);
    {
        const std::lock_guard<std::mutex> lock(barrier_mutex);
        release_revoke = true;
    }
    barrier_cv.notify_all();
    logout_thread.join();
    server.stop();

    REQUIRE(during_revoke != nullptr);
    CHECK(nlohmann::json::parse(during_revoke->body)
              .at("authenticated")
              .get<bool>());
    CHECK(logout_status == 200);
    const auto revoked = wait_for_sse_subscription(
        admitted,
        std::chrono::milliseconds{0},
        std::chrono::milliseconds{0});
    CHECK(revoked.status == SseSubscriptionWaitStatus::CLOSED);
    CHECK(revoked.message.empty());
}

TEST_CASE("expired stream session cannot drain queued SSE data") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    { std::ofstream settings(settings_path); settings << R"({"enabled":false,"port":15443})"; }
    { std::ofstream auth(auth_path); auth << R"({"enabled":true,"provider":"local","username":"admin","password":"secret","session_ttl_seconds":1})"; }

    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", port);
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);

    httplib::Request admitted_request;
    admitted_request.remote_addr = "127.0.0.1";
    admitted_request.headers.emplace(
        "Cookie", remote_access_session_cookie(*login));
    auto authorization =
        server.make_stream_authorization_probe(admitted_request);
    SseBroadcaster broadcaster;
    auto admitted = broadcaster.subscribe(
        std::vector<std::string>{"sensitive queued result"});
    REQUIRE(admitted != nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds{1100});
    const auto expired = wait_for_sse_subscription(
        admitted,
        std::chrono::milliseconds{0},
        std::chrono::milliseconds{0},
        {},
        authorization);
    server.stop();

    CHECK(expired.status ==
          SseSubscriptionWaitStatus::PEER_DISCONNECTED);
    CHECK(expired.message.empty());
}

TEST_CASE("disabled auth fences retained rules until cleanup is verified") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":true,"port":12121})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true})";
    }

    FakeIptables firewall;
    set_remote_access_command_runner_for_testing(
        [&firewall](const std::vector<std::string>& command) {
            return firewall.run(command);
        });
    auto result =
        refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE(result.apply.applied);
    REQUIRE(result.status.state == RemoteAccessRuntimeState::applied);

    // Model an externally restored auth-disabled file while the prior WAN
    // rules still exist. Loopback remains a recovery path; a non-loopback API
    // request must not inherit disabled-auth admission.
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":false})";
    }
    CHECK(remote_access_runtime_blocks_unauthenticated_request(false));
    CHECK_FALSE(remote_access_runtime_blocks_unauthenticated_request(true));

    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":false,"port":15443})";
    }
    set_remote_access_command_runner_for_testing(
        [](const std::vector<std::string>&) { return 4; });
    result = refresh_remote_access_reconcile("0.0.0.0:12121");
    REQUIRE_FALSE(result.apply.applied);
    REQUIRE(result.status.state == RemoteAccessRuntimeState::pending);
    CHECK(remote_access_runtime_blocks_unauthenticated_request(false));

    set_remote_access_command_runner_for_testing(
        [&firewall](const std::vector<std::string>& command) {
            return firewall.run(command);
        });
    result = retry_remote_access_reconcile(
        result.status.desired_generation, "0.0.0.0:12121");
    REQUIRE(result.apply.applied);
    CHECK(result.status.state == RemoteAccessRuntimeState::closed);
    CHECK(remote_access_runtime_is_verified_closed());
    CHECK_FALSE(remote_access_runtime_blocks_unauthenticated_request(false));
}

TEST_CASE("remote enable is rejected after authentication was disabled") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":false,"port":15443})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":false,"provider":"local"})";
    }

    SseBroadcaster broadcaster;
    auto context = make_remote_access_context(broadcaster);
    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_remote_access_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", port);
    const auto response = client.Post(
        "/api/system/remote-access",
        R"({"enabled":true,"port":12121})",
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("error") == "login_disabled");
    CHECK_FALSE(nlohmann::json::parse(std::ifstream(settings_path))
                    .at("enabled")
                    .get<bool>());
}

TEST_CASE("concurrent remote enable wins before auth disable can publish") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    set_trusted_local_connection_evaluator_for_testing(
        [](std::string_view, std::string_view, bool) { return true; });
    const auto settings_path = directory.path / "remote-access.json";
    const auto auth_path = directory.path / "auth.json";
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", settings_path.string());
    EnvironmentVariableGuard remote_auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard server_auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    {
        std::ofstream settings(settings_path);
        settings << R"({"enabled":false,"port":15443})";
    }
    {
        std::ofstream auth(auth_path);
        auth << R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})";
    }

    SseBroadcaster broadcaster;
    auto context = make_remote_access_context(broadcaster);
    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_remote_access_handler(server, context);
    server.start();

    httplib::Client login_client("127.0.0.1", port);
    const auto login = login_client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", remote_access_session_cookie(*login)},
    };
    grant_step_up(login_client, headers, "admin", "secret");

    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool remote_admitted = false;
    bool release_remote = false;
    set_remote_access_desired_admission_hook_for_testing([&]() {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        remote_admitted = true;
        barrier_cv.notify_all();
        barrier_cv.wait(lock, [&]() { return release_remote; });
    });

    int remote_status = 0;
    int auth_status = 0;
    std::string remote_body;
    std::string auth_body;
    std::thread remote_thread([&]() {
        httplib::Client client("127.0.0.1", port);
        const auto response = client.Post(
            "/api/system/remote-access",
            headers,
            R"({"enabled":true,"port":12121})",
            "application/json");
        if (response) {
            remote_status = response->status;
            remote_body = response->body;
        }
    });
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier_cv.wait(lock, [&]() { return remote_admitted; });
    }

    std::atomic<bool> auth_started{false};
    std::thread auth_thread([&]() {
        auth_started.store(true, std::memory_order_release);
        httplib::Client client("127.0.0.1", port);
        const auto response = client.Post(
            "/api/auth/settings",
            headers,
            R"({"enabled":false,"provider":"local"})",
            "application/json");
        if (response) {
            auth_status = response->status;
            auth_body = response->body;
        }
    });
    while (!auth_started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    {
        const std::lock_guard<std::mutex> lock(barrier_mutex);
        release_remote = true;
    }
    barrier_cv.notify_all();
    remote_thread.join();
    auth_thread.join();
    server.stop();

    REQUIRE(remote_status == 200);
    CHECK(nlohmann::json::parse(remote_body).at("ok").get<bool>());
    REQUIRE(auth_status == 409);
    CHECK(nlohmann::json::parse(auth_body).at("error") ==
          "remote_access_enabled");
    CHECK(nlohmann::json::parse(std::ifstream(settings_path))
              .at("enabled")
              .get<bool>());
    CHECK(nlohmann::json::parse(std::ifstream(auth_path))
              .at("enabled")
              .get<bool>());
}

TEST_CASE("remote access desired POST cannot overtake a claimed bell transition") {
    RemoteAccessTempDir directory;
    RemoteAccessRunnerGuard runner_guard;
    EnvironmentVariableGuard settings_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE",
        (directory.path / "remote-access.json").string());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_TEST_REMOTE_AUTH_FILE",
        (directory.path / "auth.json").string());
    EnvironmentVariableGuard wan("KEEN_PBR_TEST_REMOTE_WAN", "wan-test");
    EnvironmentVariableGuard wait_mode(
        "KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout");
    {
        std::ofstream auth(directory.path / "auth.json");
        auth << R"({"enabled":false})";
    }
    {
        std::ofstream settings(directory.path / "remote-access.json");
        settings << R"({"enabled":true,"port":12121})";
    }

    FakeIptables firewall;
    set_remote_access_command_runner_for_testing(
        [&firewall](const std::vector<std::string>& command) {
            return firewall.run(command);
        });

    SseBroadcaster broadcaster;
    auto context = make_remote_access_context(broadcaster);
    ApiConfig config;
    const int port =
        next_remote_access_port.fetch_add(1, std::memory_order_relaxed);
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_remote_access_handler(server, context);
    server.start();

    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    bool notification_claimed = false;
    bool desired_admission_entered = false;
    bool release_notification = false;
    set_remote_access_incident_publish_hook_for_testing([&]() {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        notification_claimed = true;
        barrier_cv.notify_all();
        barrier_cv.wait(lock, [&]() { return release_notification; });
    });
    set_remote_access_desired_admission_hook_for_testing([&]() {
        const std::lock_guard<std::mutex> lock(barrier_mutex);
        desired_admission_entered = true;
        barrier_cv.notify_all();
    });

    RemoteAccessLogCapture logs;
    RemoteAccessReconcileResult failed;
    std::thread reconcile_thread([&]() {
        failed = refresh_remote_access_reconcile("0.0.0.0:12121");
    });
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier_cv.wait(lock, [&]() { return notification_claimed; });
    }

    std::string post_body;
    std::thread post_thread([&]() {
        httplib::Client client("127.0.0.1", port);
        const auto response = client.Post(
            "/api/system/remote-access",
            R"({"enabled":false,"port":15443})",
            "application/json");
        if (response) post_body = response->body;
    });
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier_cv.wait(lock, [&]() { return desired_admission_entered; });
    }

    // The POST reached desired-state admission but cannot publish generation
    // two until generation one's already-claimed bell is fully logged.
    const auto during_publication = remote_access_runtime_status();
    CHECK(during_publication.desired_generation == 1U);
    CHECK(during_publication.incident_active);
    {
        const std::lock_guard<std::mutex> lock(barrier_mutex);
        release_notification = true;
    }
    barrier_cv.notify_all();
    reconcile_thread.join();
    post_thread.join();
    server.stop();

    REQUIRE_FALSE(post_body.empty());
    const auto posted = nlohmann::json::parse(post_body);
    CHECK(posted.at("ok").get<bool>());
    CHECK(posted.at("pending").get<bool>());
    CHECK(posted.at("generation").get<std::uint64_t>() == 2U);
    CHECK(failed.incident_raised);
    const auto after_post = remote_access_runtime_status();
    CHECK(after_post.desired_generation == 2U);
    CHECK_FALSE(after_post.incident_active);
    CHECK(std::count_if(
              logs.lines().begin(), logs.lines().end(),
              [](const std::string& line) {
                  return line.rfind("[E] ", 0) == 0;
              }) == 1);
}

} // namespace keen_pbr3

#endif // WITH_API
