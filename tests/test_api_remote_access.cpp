#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_remote_access.hpp"
#include "../src/api/sse_broadcaster.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string>
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
    ~RemoteAccessRunnerGuard() {
        reset_remote_access_command_runner_for_testing();
    }
};

using Rule = std::vector<std::string>;

class FakeIptables {
public:
    int run(const std::vector<std::string>& command) {
        if (command.empty() || command.front() != "iptables") return 2;
        std::size_t cursor = 1;
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

} // namespace

TEST_CASE("remote access reports success only after verified firewall apply") {
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

    httplib::Client client("127.0.0.1", port);
    const auto enabled = client.Post(
        "/api/system/remote-access",
        R"({"enabled":true,"port":15443})",
        "application/json");
    REQUIRE(enabled != nullptr);
    const auto enabled_body = nlohmann::json::parse(enabled->body);
    CHECK(enabled_body.at("ok").get<bool>());
    CHECK(enabled_body.at("durable").get<bool>());

    const auto disabled = client.Post(
        "/api/system/remote-access",
        R"({"enabled":false,"port":15443})",
        "application/json");
    server.stop();

    REQUIRE(disabled != nullptr);
    const auto disabled_body = nlohmann::json::parse(disabled->body);
    CHECK(disabled_body.at("ok").get<bool>());
    CHECK(disabled_body.at("durable").get<bool>());
    CHECK(remove_remote_access_rules());
}

TEST_CASE("remote access never returns ok for an unapplied firewall state") {
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
    set_remote_access_command_runner_for_testing(
        [](const std::vector<std::string>&) { return 2; });

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
    CHECK_FALSE(body.contains("ok"));
    CHECK(body.at("degraded").get<bool>());
    CHECK(body.contains("detail"));
    CHECK_FALSE(remove_remote_access_rules());

    std::ifstream stored_file(settings_path);
    REQUIRE(stored_file.is_open());
    const auto stored = nlohmann::json::parse(stored_file);
    CHECK(stored.at("enabled").get<bool>());
    CHECK(stored.at("port") == 15443);
}

} // namespace keen_pbr3

#endif // WITH_API
