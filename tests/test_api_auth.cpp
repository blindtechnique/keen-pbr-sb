#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/auth_runtime.hpp"
#include "../src/api/handler_remote_access.hpp"
#include "../src/api/keenetic_auth.hpp"
#include "../src/api/server.hpp"
#include "../src/log/logger.hpp"

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <thread>
#include <unordered_set>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

class AuthTempDir {
public:
    AuthTempDir() {
        char pattern[] = "/tmp/keen-pbr-auth-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }

    ~AuthTempDir() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    std::filesystem::path path;
};

class FixedLocalAddressProvider final
    : public KeeneticAuthLocalAddressProvider {
public:
    FixedLocalAddressProvider(std::unordered_set<std::string> ipv4,
                              std::unordered_set<std::string> ipv6)
        : ipv4_(std::move(ipv4))
        , ipv6_(std::move(ipv6)) {}

    bool contains(KeeneticAuthAddressFamily family,
                  std::string_view canonical_address) const override {
        const auto& addresses =
            family == KeeneticAuthAddressFamily::ipv4 ? ipv4_ : ipv6_;
        return addresses.find(std::string{canonical_address}) != addresses.end();
    }

private:
    std::unordered_set<std::string> ipv4_;
    std::unordered_set<std::string> ipv6_;
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

class VerifiedClosedRemoteAccessGuard {
public:
    VerifiedClosedRemoteAccessGuard()
        : wait_mode_("KEEN_PBR_TEST_REMOTE_XTABLES_WAIT", "timeout") {
        reset_remote_access_reconciler_for_testing();
        reset_remote_access_command_runner_for_testing();
        // A missing owned chain is the exact verified-closed result needed by
        // these auth-only tests; no real firewall command is executed.
        set_remote_access_command_runner_for_testing(
            [](const std::vector<std::string>&) { return 1; });
        const auto result =
            refresh_remote_access_reconcile("0.0.0.0:12121");
        REQUIRE(result.apply.applied);
        REQUIRE(result.status.state == RemoteAccessRuntimeState::closed);
        REQUIRE(result.status.desired_generation != 0U);
        REQUIRE(result.status.applied_generation ==
                result.status.desired_generation);
    }

    ~VerifiedClosedRemoteAccessGuard() {
        reset_remote_access_reconciler_for_testing();
        reset_remote_access_command_runner_for_testing();
    }

private:
    EnvironmentVariableGuard wait_mode_;
};

class ThrowingPostCommitAuthLogger {
public:
    ThrowingPostCommitAuthLogger()
        : previous_level_(Logger::instance().level()) {
        Logger::instance().set_level(LogLevel::debug);
        Logger::instance().set_sink([](const std::string& line) {
            if (line.find("auth.json was published") !=
                std::string::npos) {
                throw std::runtime_error(
                    "synthetic post-commit auth logging failure");
            }
        });
    }

    ~ThrowingPostCommitAuthLogger() {
        Logger::instance().clear_sink();
        Logger::instance().set_level(previous_level_);
    }

private:
    LogLevel previous_level_;
};

class BoundHttpServer {
public:
    explicit BoundHttpServer(httplib::Server& server)
        : server_(server)
        , port_(server_.bind_to_any_port("127.0.0.1")) {
        REQUIRE(port_ > 0);
        thread_ = std::thread([this] { server_.listen_after_bind(); });
        while (!server_.is_running()) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(5));
        }
    }

    ~BoundHttpServer() {
        server_.stop();
        if (thread_.joinable()) thread_.join();
    }

    int port() const noexcept { return port_; }

private:
    httplib::Server& server_;
    int port_;
    std::thread thread_;
};

std::atomic<int> next_api_port{18320};

ApiConfig auth_api_config() {
    ApiConfig config;
    config.listen =
        "127.0.0.1:" +
        std::to_string(
            next_api_port.fetch_add(1, std::memory_order_relaxed));
    return config;
}

int configured_port(const ApiConfig& config) {
    REQUIRE(config.listen.has_value());
    const auto separator = config.listen->rfind(':');
    REQUIRE(separator != std::string::npos);
    return std::stoi(config.listen->substr(separator + 1));
}

void write_text(const std::filesystem::path& path,
                const std::string& body) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << body;
    REQUIRE(output);
}

nlohmann::json get_auth_status(httplib::Client& client) {
    const auto response = client.Get("/api/auth/status");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    CHECK(response->get_header_value("Cache-Control") == "no-store");
    CHECK(response->get_header_value("X-Content-Type-Options") == "nosniff");
    CHECK(response->get_header_value("X-Frame-Options") == "SAMEORIGIN");
    return nlohmann::json::parse(response->body);
}

std::string session_cookie(const httplib::Response& response) {
    const auto header = response.get_header_value("Set-Cookie");
    const auto separator = header.find(';');
    return header.substr(0, separator);
}

} // namespace

TEST_CASE("missing auth file keeps the bootstrap API open") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "missing-auth.json";
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.get("/api/auth-test/protected", [] { return R"({"ok":true})"; });
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto status = get_auth_status(client);
    const auto protected_response =
        client.Get("/api/auth-test/protected");

    CHECK_FALSE(status.at("enabled").get<bool>());
    CHECK(status.at("authenticated").get<bool>());
    CHECK_FALSE(status.contains("error"));
    CHECK_FALSE(status.contains("keenetic_endpoint"));
    REQUIRE(protected_response != nullptr);
    CHECK(protected_response->status == 200);
}

TEST_CASE("present invalid auth file fails closed as auth_misconfigured") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(auth_path, R"({"enabled":true,"password":)");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.get("/api/auth-test/protected", [] { return R"({"ok":true})"; });
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto status = get_auth_status(client);
    const auto protected_response =
        client.Get("/api/auth-test/protected");
    const auto login_response = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");

    CHECK(status.at("enabled").get<bool>());
    CHECK_FALSE(status.at("authenticated").get<bool>());
    CHECK(status.at("error") == "auth_misconfigured");
    CHECK_FALSE(status.contains("keenetic_endpoint"));
    REQUIRE(protected_response != nullptr);
    CHECK(protected_response->status == 401);
    REQUIRE(login_response != nullptr);
    CHECK(login_response->status == 503);
    CHECK(nlohmann::json::parse(login_response->body).at("error") ==
          "auth_misconfigured");
}

TEST_CASE("a non-regular auth path also fails closed") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    REQUIRE(std::filesystem::create_directory(auth_path));
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto status = get_auth_status(client);
    CHECK(status.at("enabled").get<bool>());
    CHECK_FALSE(status.at("authenticated").get<bool>());
    CHECK(status.at("error") == "auth_misconfigured");
}

TEST_CASE("auth settings are replaced atomically with private permissions") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"old","password":"old-secret"})");
    REQUIRE(::chmod(auth_path.c_str(), 0644) == 0);
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto login_response = client.Post(
        "/api/auth/login",
        R"({"username":"old","password":"old-secret"})",
        "application/json");
    REQUIRE(login_response != nullptr);
    REQUIRE(login_response->status == 200);
    const httplib::Headers headers{
        {"Cookie", session_cookie(*login_response)},
    };
    const auto settings_response = client.Post(
        "/api/auth/settings",
        headers,
        R"({"enabled":true,"provider":"local","username":"new","password":"new-secret"})",
        "application/json");

    REQUIRE(settings_response != nullptr);
    CHECK(settings_response->status == 200);
    CHECK(nlohmann::json::parse(settings_response->body).at("saved") ==
          true);

    struct stat metadata {};
    REQUIRE(::stat(auth_path.c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0600);
    const auto stored = nlohmann::json::parse(
        std::ifstream(auth_path));
    CHECK(stored.at("username") == "new");
    CHECK(stored.at("password") == "new-secret");

    // Changing authentication invalidates every session from the old mode.
    const auto old_session_status =
        client.Get("/api/auth/status", headers);
    REQUIRE(old_session_status != nullptr);
    CHECK_FALSE(
        nlohmann::json::parse(old_session_status->body)
            .at("authenticated")
            .get<bool>());
}

TEST_CASE("authentication cannot be disabled while remote access is desired") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    const auto remote_path = directory.path / "remote-access.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})");
    write_text(remote_path, R"({"enabled":true,"port":15443})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard remote_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", remote_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", session_cookie(*login)},
    };
    const auto disable = client.Post(
        "/api/auth/settings",
        headers,
        R"({"enabled":false,"provider":"local"})",
        "application/json");

    REQUIRE(disable != nullptr);
    CHECK(disable->status == 409);
    CHECK(nlohmann::json::parse(disable->body).at("error") ==
          "remote_access_enabled");
    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    CHECK(stored.at("enabled").get<bool>());

    // Rejection neither replaces auth nor clears the administrator's session.
    const auto status = client.Get("/api/auth/status", headers);
    REQUIRE(status != nullptr);
    CHECK(nlohmann::json::parse(status->body)
              .at("authenticated")
              .get<bool>());
}

TEST_CASE(
    "post-commit auth durability failure reloads the visible settings") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"old","password":"old-secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto login_response = client.Post(
        "/api/auth/login",
        R"({"username":"old","password":"old-secret"})",
        "application/json");
    REQUIRE(login_response != nullptr);
    REQUIRE(login_response->status == 200);
    const httplib::Headers headers{
        {"Cookie", session_cookie(*login_response)},
    };

    EnvironmentVariableGuard write_fault(
        "KEEN_PBR_TEST_AUTH_WRITE_FAULT", "directory_fsync");
    const auto settings_response = client.Post(
        "/api/auth/settings",
        headers,
        R"({"enabled":true,"provider":"local","username":"new","password":"new-secret"})",
        "application/json");

    REQUIRE(settings_response != nullptr);
    REQUIRE(settings_response->status == 200);
    const auto result = nlohmann::json::parse(settings_response->body);
    CHECK(result.at("saved").get<bool>());
    CHECK_FALSE(result.at("durable").get<bool>());
    CHECK(result.contains("warning"));

    std::ifstream stored_file(auth_path);
    REQUIRE(stored_file.is_open());
    const auto stored = nlohmann::json::parse(stored_file);
    CHECK(stored.at("username") == "new");
    CHECK(stored.at("password") == "new-secret");

    // The old session is invalidated and the newly visible credentials are
    // authoritative in memory immediately, not only after a process restart.
    const auto old_session_status =
        client.Get("/api/auth/status", headers);
    REQUIRE(old_session_status != nullptr);
    CHECK_FALSE(
        nlohmann::json::parse(old_session_status->body)
            .at("authenticated")
            .get<bool>());
    const auto new_login = client.Post(
        "/api/auth/login",
        R"({"username":"new","password":"new-secret"})",
        "application/json");
    REQUIRE(new_login != nullptr);
    CHECK(new_login->status == 200);
}

TEST_CASE(
    "post-commit logging exception leaves auth publication fail closed") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"old","password":"old-secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard write_fault(
        "KEEN_PBR_TEST_AUTH_WRITE_FAULT", "directory_fsync");

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"old","password":"old-secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{
        {"Cookie", session_cookie(*login)},
    };

    int settings_status = 0;
    {
        ThrowingPostCommitAuthLogger throwing_logger;
        const auto response = client.Post(
            "/api/auth/settings", headers,
            R"({"enabled":true,"provider":"local","username":"new","password":"new-secret"})",
            "application/json");
        REQUIRE(response != nullptr);
        settings_status = response->status;
    }
    CHECK(settings_status == 400);
    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    CHECK(stored.at("username") == "new");

    // The rename was visible but runtime publication did not finish. The
    // application layer must remain closed instead of reverting to the old
    // in-memory authentication snapshot.
    const auto status = client.Get("/api/auth/status");
    REQUIRE(status != nullptr);
    CHECK(status->status == 503);
}

TEST_CASE("pre-commit auth write failure preserves disk and memory") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "missing-auth.json";
    const auto remote_path = directory.path / "remote-access.json";
    write_text(remote_path, R"({"enabled":false,"port":12121})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard remote_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", remote_path.string());
    VerifiedClosedRemoteAccessGuard remote_access_closed;
    EnvironmentVariableGuard write_fault(
        "KEEN_PBR_TEST_AUTH_WRITE_FAULT", "write");

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto settings_response = client.Post(
        "/api/auth/settings",
        R"({"enabled":false,"provider":"local","username":"new","password":"new-secret"})",
        "application/json");

    REQUIRE(settings_response != nullptr);
    CHECK(settings_response->status == 500);
    CHECK(nlohmann::json::parse(settings_response->body).at("error") ==
          "cannot write auth.json");
    CHECK_FALSE(std::filesystem::exists(auth_path));

    const auto status = get_auth_status(client);
    CHECK_FALSE(status.at("enabled").get<bool>());
    CHECK(status.at("authenticated").get<bool>());
}

TEST_CASE("concurrent auth settings writes leave disk and memory consistent") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    const auto remote_path = directory.path / "remote-access.json";
    write_text(remote_path, R"({"enabled":false,"port":12121})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard remote_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", remote_path.string());
    VerifiedClosedRemoteAccessGuard remote_access_closed;

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    constexpr int writer_count = 12;
    const int port = configured_port(config);
    std::atomic<bool> failed{false};
    std::vector<std::thread> writers;
    writers.reserve(writer_count);
    for (int index = 0; index < writer_count; ++index) {
        writers.emplace_back([&, index] {
            httplib::Client client("127.0.0.1", port);
            const auto provider =
                index % 2 == 0 ? "local" : "keenetic";
            nlohmann::json settings{
                {"enabled", false},
                {"provider", provider},
            };
            if (provider == std::string{"keenetic"}) {
                settings["keenetic_endpoint"] =
                    "127.0.0.1:" + std::to_string(19000 + index);
            }
            const auto response = client.Post(
                "/api/auth/settings",
                settings.dump(),
                "application/json");
            if (!response || response->status != 200) {
                failed.store(true, std::memory_order_relaxed);
            }
        });
    }
    for (auto& writer : writers) writer.join();

    CHECK_FALSE(failed.load(std::memory_order_relaxed));
    std::ifstream stored_input(auth_path);
    REQUIRE(stored_input);
    const auto stored = nlohmann::json::parse(stored_input);

    httplib::Client client("127.0.0.1", port);
    const auto status = get_auth_status(client);
    CHECK(status.at("provider") == stored.at("provider"));
    CHECK_FALSE(status.at("enabled").get<bool>());

    struct stat metadata {};
    REQUIRE(::stat(auth_path.c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0600);
}

TEST_CASE("public auth status hides the configured Keenetic endpoint") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"keenetic","keenetic_endpoint":"127.0.0.1:8080"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto status = get_auth_status(client);
    CHECK(status.at("provider") == "keenetic");
    CHECK_FALSE(status.at("authenticated").get<bool>());
    CHECK_FALSE(status.contains("keenetic_endpoint"));
}

TEST_CASE("Keenetic endpoint parser accepts canonical local targets") {
    const FixedLocalAddressProvider local_addresses{
        {"127.0.0.1", "192.0.2.20"},
        {"::1"},
    };
    const auto ipv4_default =
        parse_keenetic_auth_endpoint("127.0.0.1", local_addresses);
    const auto ipv4_legacy =
        parse_keenetic_auth_endpoint("127.0.0.1:80", local_addresses);
    const auto ipv4_custom =
        parse_keenetic_auth_endpoint("127.0.0.1:65535", local_addresses);
    const auto ipv6_default =
        parse_keenetic_auth_endpoint("[::1]", local_addresses);
    const auto ipv6_custom =
        parse_keenetic_auth_endpoint("[::1]:8080", local_addresses);

    REQUIRE(ipv4_default);
    CHECK(ipv4_default->host == "127.0.0.1");
    CHECK(ipv4_default->port == 80);
    CHECK(ipv4_default->canonical == "127.0.0.1:80");
    REQUIRE(ipv4_legacy);
    CHECK(ipv4_legacy->canonical == "127.0.0.1:80");
    REQUIRE(ipv4_custom);
    CHECK(ipv4_custom->port == 65535);
    REQUIRE(ipv6_default);
    CHECK(ipv6_default->host == "::1");
    CHECK(ipv6_default->canonical == "[::1]:80");
    REQUIRE(ipv6_custom);
    CHECK(ipv6_custom->canonical == "[::1]:8080");

    const auto lan_endpoint =
        parse_keenetic_auth_endpoint("192.0.2.20:777", local_addresses);
    REQUIRE(lan_endpoint);
    CHECK(lan_endpoint->host == "192.0.2.20");
    CHECK(lan_endpoint->port == 777);
}

TEST_CASE("Keenetic endpoint parser rejects SSRF and parser bypass forms") {
    const FixedLocalAddressProvider local_addresses{
        {"127.0.0.1"},
        {"::1"},
    };
    const std::vector<std::string> rejected{
        "",
        "localhost:80",
        "127.0.0.2:80",
        "127.0.0.1.evil:80",
        "127.1:80",
        "2130706433:80",
        "0x7f000001:80",
        "http://127.0.0.1:80",
        "127.0.0.1:80/auth",
        "127.0.0.1:80?x=1",
        "127.0.0.1:80#fragment",
        "admin@127.0.0.1:80",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:-1",
        "127.0.0.1:+80",
        "127.0.0.1:80junk",
        "127.0.0.1:",
        "127.0.0.1:80\nHost:evil",
        "::1",
        "[::1",
        "[::1]extra",
        "[::1]:0",
        "[::1]:65536",
        "[0:0:0:0:0:0:0:1]:80",
        "[::ffff:127.0.0.1]:80",
    };

    for (const auto& endpoint : rejected) {
        CAPTURE(endpoint);
        std::string error;
        CHECK_FALSE(parse_keenetic_auth_endpoint(
            endpoint, local_addresses, &error));
        CHECK_FALSE(error.empty());
    }
}

TEST_CASE("auto Keenetic auth treats an invalid fallback as unavailable") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"keenetic","keenetic_endpoint":"192.0.2.10:80"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto status = get_auth_status(client);
    CHECK(status.at("enabled").get<bool>());
    CHECK_FALSE(status.at("authenticated").get<bool>());
    CHECK(status.at("error") == "auth_endpoint_unavailable");
}

TEST_CASE("manual Keenetic auth rejects an invalid local endpoint") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"keenetic","keenetic_endpoint_mode":"manual","keenetic_endpoint":"192.0.2.10:80"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto status = get_auth_status(client);
    CHECK(status.at("enabled").get<bool>());
    CHECK_FALSE(status.at("authenticated").get<bool>());
    CHECK(status.at("error") == "auth_misconfigured");
}

TEST_CASE("auth settings reject a non-loopback Keenetic endpoint") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "missing-auth.json";
    const auto remote_path = directory.path / "remote-access.json";
    write_text(remote_path, R"({"enabled":false,"port":12121})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard remote_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", remote_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    const auto response = client.Post(
        "/api/auth/settings",
        R"({"enabled":false,"provider":"keenetic","keenetic_endpoint":"http://127.0.0.1:80/auth"})",
        "application/json");

    REQUIRE(response != nullptr);
    CHECK(response->status == 400);
    CHECK(nlohmann::json::parse(response->body).at("error") ==
          "invalid Keenetic endpoint");
    CHECK_FALSE(std::filesystem::exists(auth_path));
}

TEST_CASE("Keenetic login serializes an adversarial username as JSON data") {
    httplib::Server router;
    const std::string username =
        R"(admin"},"injected":true,"login":"attacker)";
    std::optional<nlohmann::json> received;
    router.Get("/auth", [](const httplib::Request&,
                            httplib::Response& response) {
        response.status = 401;
        response.set_header("X-NDM-Realm", "Keenetic");
        response.set_header("X-NDM-Challenge", "challenge");
        response.set_header("Set-Cookie", "session=test; Path=/");
    });
    router.Post("/auth", [&received, &username](
                             const httplib::Request& request,
                             httplib::Response& response) {
        received = nlohmann::json::parse(request.body);
        response.status =
            received->is_object() &&
                    received->size() == 2U &&
                    received->value("login", std::string{}) == username &&
                    !received->contains("injected")
                ? 200
                : 401;
    });
    BoundHttpServer running(router);

    const auto result = verify_keenetic_credentials(
        "127.0.0.1:" + std::to_string(running.port()),
        username,
        "secret");

    CHECK(result.authenticated);
    CHECK(result.endpoint_verified);
    REQUIRE(received.has_value());
    CHECK(received->at("login") == username);
    CHECK(received->contains("password"));
    CHECK_FALSE(received->contains("injected"));
}

TEST_CASE("Keenetic login fails closed when router sends no challenge") {
    httplib::Server router;
    router.Get("/auth", [](const httplib::Request&,
                            httplib::Response& response) {
        response.status = 200;
        response.set_content(R"({"authenticated":true})", "application/json");
    });
    BoundHttpServer running(router);

    const auto result = verify_keenetic_credentials(
        "127.0.0.1:" + std::to_string(running.port()),
        "admin",
        "secret");

    CHECK(result.reachable);
    CHECK_FALSE(result.authenticated);
    CHECK_FALSE(result.endpoint_verified);
    CHECK(result.error == "router authentication is not enabled");
}

TEST_CASE("login failures are rate limited per remote address") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    for (std::size_t index = 0;
         index < kAuthLoginMaxFailures;
         ++index) {
        const auto response = client.Post(
            "/api/auth/login",
            R"({"username":"admin","password":"wrong"})",
            "application/json");
        REQUIRE(response != nullptr);
        CHECK(response->status == 401);
    }

    const auto blocked = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(blocked != nullptr);
    CHECK(blocked->status == 429);
    CHECK(blocked->get_header_value("Retry-After") == "60");
}

TEST_CASE("rate limiter is per-source bounded and garbage collects stale entries") {
    using Clock = AuthLoginRateLimiter::Clock;
    const auto start = Clock::time_point{std::chrono::seconds{100}};
    AuthLoginRateLimiter limiter({
        2,
        std::chrono::seconds{10},
        std::chrono::seconds{20},
        2,
    });

    limiter.record_failure("192.0.2.1", start);
    limiter.record_failure("192.0.2.1", start + std::chrono::seconds{1});
    CHECK_FALSE(limiter.allow(
        "192.0.2.1", start + std::chrono::seconds{2}));
    CHECK(limiter.allow(
        "192.0.2.2", start + std::chrono::seconds{2}));

    limiter.record_failure(
        "192.0.2.2", start + std::chrono::seconds{2});
    CHECK(limiter.tracked_source_count(
              start + std::chrono::seconds{2}) <= 2);
    limiter.record_failure(
        "192.0.2.3", start + std::chrono::seconds{3});
    CHECK(limiter.tracked_source_count(
              start + std::chrono::seconds{3}) <= 2);
    CHECK_FALSE(limiter.allow(
        "192.0.2.4", start + std::chrono::seconds{4}));
    CHECK(limiter.allow(
        "192.0.2.4", start + std::chrono::seconds{24}));

    CHECK(limiter.tracked_source_count(
              start + std::chrono::seconds{40}) == 0);
    CHECK(limiter.allow(
        "192.0.2.1", start + std::chrono::seconds{40}));
}

TEST_CASE("rate limiter normalizes IPv4-mapped peer addresses") {
    using Clock = AuthLoginRateLimiter::Clock;
    const auto start = Clock::time_point{std::chrono::seconds{100}};
    AuthLoginRateLimiter limiter({
        2,
        std::chrono::seconds{10},
        std::chrono::seconds{20},
        8,
    });

    limiter.record_failure("127.0.0.1", start);
    limiter.record_failure(
        "::ffff:127.0.0.1", start + std::chrono::seconds{1});
    CHECK_FALSE(limiter.allow(
        "127.0.0.1", start + std::chrono::seconds{2}));
}

TEST_CASE("session registry enforces its cap and garbage collects expiry") {
    using Clock = AuthSessionRegistry::Clock;
    const auto start = Clock::time_point{std::chrono::seconds{100}};
    AuthSessionRegistry sessions(2);

    CHECK(sessions.insert("one", std::chrono::seconds{10}, start));
    CHECK_FALSE(sessions.insert(
        "one", std::chrono::seconds{30}, start));
    CHECK(sessions.insert("two", std::chrono::seconds{20}, start));
    CHECK_FALSE(sessions.insert(
        "three", std::chrono::seconds{30}, start));
    CHECK(sessions.contains(
        "one", start + std::chrono::seconds{9}));
    CHECK_FALSE(sessions.contains(
        "one", start + std::chrono::seconds{10}));
    CHECK(sessions.insert(
        "three", std::chrono::seconds{30},
        start + std::chrono::seconds{10}));
    CHECK(sessions.size(start + std::chrono::seconds{10}) == 2);
    CHECK(sessions.size(start + std::chrono::seconds{40}) == 0);
}

TEST_CASE("web login refuses to exceed the global session cap") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    httplib::Client client("127.0.0.1", configured_port(config));
    std::unordered_set<std::string> cookies;
    for (std::size_t index = 0; index < kAuthSessionCapacity; ++index) {
        const auto response = client.Post(
            "/api/auth/login",
            R"({"username":"admin","password":"secret"})",
            "application/json");
        REQUIRE(response != nullptr);
        CAPTURE(index);
        REQUIRE(response->status == 200);
        const auto cookie =
            response->get_header_value("Set-Cookie");
        CHECK_FALSE(cookie.empty());
        CHECK(cookies.insert(cookie).second);
    }

    const auto overflow = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(overflow != nullptr);
    CHECK(overflow->status == 503);
    CHECK(nlohmann::json::parse(overflow->body).at("error") ==
          "session limit reached");
    CHECK(overflow->get_header_value("Set-Cookie").empty());
}

} // namespace keen_pbr3

#endif
