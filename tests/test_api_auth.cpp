#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/auth_runtime.hpp"
#include "../src/api/handler_remote_access.hpp"
#include "../src/api/keenetic_auth.hpp"
#include "../src/api/local_password_hash.hpp"
#include "../src/api/server.hpp"
#include "../src/log/logger.hpp"

#include <atomic>
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
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

class TrustedLocalConnectionEvaluatorGuard {
public:
    explicit TrustedLocalConnectionEvaluatorGuard(
        TrustedLocalConnectionEvaluatorForTesting evaluator) {
        set_trusted_local_connection_evaluator_for_testing(
            std::move(evaluator));
    }

    ~TrustedLocalConnectionEvaluatorGuard() {
        reset_trusted_local_connection_evaluator_for_testing();
    }
};

class CredentialHandlerAdmissionHookGuard {
public:
    explicit CredentialHandlerAdmissionHookGuard(
        CredentialHandlerAdmissionHook hook) {
        set_credential_handler_admission_hook_for_testing(std::move(hook));
    }

    ~CredentialHandlerAdmissionHookGuard() {
        reset_credential_handler_admission_hook_for_testing();
    }
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

void grant_local_step_up(httplib::Client& client,
                         const httplib::Headers& headers,
                         const std::string& username,
                         const std::string& password) {
    const auto response = client.Post(
        "/api/auth/step-up",
        headers,
        nlohmann::json{{"username", username}, {"password", password}}.dump(),
        "application/json");
    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    CHECK(nlohmann::json::parse(response->body).at("granted").get<bool>());
}

struct RawHttpResult {
    std::string response;
    bool peer_closed{false};
    std::chrono::milliseconds elapsed{};
};

RawHttpResult post_headers_without_body(
    const int port,
    const std::string_view path,
    const std::string_view cookie = {},
    const std::string_view extra_headers = {}) {
    const int socket_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(socket_fd >= 0);
    struct SocketCloser {
        int fd;
        ~SocketCloser() {
            if (fd >= 0) {
                (void)::shutdown(fd, SHUT_RDWR);
                (void)::close(fd);
            }
        }
    } closer{socket_fd};

    const timeval timeout{2, 0};
    REQUIRE(::setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                         &timeout, sizeof(timeout)) == 0);
    REQUIRE(::setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO,
                         &timeout, sizeof(timeout)) == 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    REQUIRE(::connect(socket_fd,
                      reinterpret_cast<const sockaddr*>(&address),
                      sizeof(address)) == 0);

    std::string request =
        "POST " + std::string{path} + " HTTP/1.1\r\n" +
        "Host: 127.0.0.1\r\n" +
        "Content-Type: application/json\r\n" +
        "Content-Length: 1048576\r\n" +
        "Connection: keep-alive\r\n";
    if (!cookie.empty()) {
        request += "Cookie: " + std::string{cookie} + "\r\n";
    }
    request += std::string{extra_headers};
    request += "\r\n";

    std::size_t sent = 0U;
    while (sent < request.size()) {
        const auto count = ::send(
            socket_fd, request.data() + sent, request.size() - sent, 0);
        REQUIRE(count > 0);
        sent += static_cast<std::size_t>(count);
    }

    const auto started = std::chrono::steady_clock::now();
    RawHttpResult result;
    std::array<char, 4096> buffer{};
    while (true) {
        const auto count = ::recv(
            socket_fd, buffer.data(), buffer.size(), 0);
        if (count > 0) {
            result.response.append(
                buffer.data(), static_cast<std::size_t>(count));
            continue;
        }
        result.peer_closed = count == 0;
        break;
    }
    result.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    return result;
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
    CHECK_FALSE(status.at("trusted_local_connection").get<bool>());
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
    CHECK_FALSE(status.at("trusted_local_connection").get<bool>());
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

TEST_CASE("a successful legacy login atomically migrates auth.json") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"legacy-secret","owner_note":"preserve-me"})");
    REQUIRE(::chmod(auth_path.c_str(), 0644) == 0);
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    {
        ApiServer server(config);
        server.start();
        httplib::Client client("127.0.0.1", configured_port(config));
        const auto login = client.Post(
            "/api/auth/login",
            R"({"username":"admin","password":"legacy-secret"})",
            "application/json");
        REQUIRE(login != nullptr);
        REQUIRE(login->status == 200);
        server.stop();
    }

    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    const auto persisted = stored.at("password").get<std::string>();
    CHECK(persisted != "legacy-secret");
    CHECK(stored.at("password_format") == kLocalPasswordHashFormat);
    CHECK(local_password_hash_encoded(persisted));
    CHECK(verify_local_password(persisted, "legacy-secret") ==
          LocalPasswordVerdict::matched);
    CHECK(stored.at("owner_note") == "preserve-me");
    struct stat metadata {};
    REQUIRE(::stat(auth_path.c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0600);

    // A crash/restart after the rename reads the new representation and still
    // admits the owner with the same password.
    ApiServer restarted(config);
    restarted.start();
    httplib::Client restarted_client(
        "127.0.0.1", configured_port(config));
    const auto after_restart = restarted_client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"legacy-secret"})",
        "application/json");
    REQUIRE(after_restart != nullptr);
    CHECK(after_restart->status == 200);
}

TEST_CASE("an untagged legacy password may look exactly like a hash") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    const std::string legacy = encode_local_password_hash(
        "not-the-owner-password",
        "0123456789abcdef0123456789abcdef",
        1000U);
    REQUIRE(local_password_hash_encoded(legacy));
    write_text(
        auth_path,
        nlohmann::json{
            {"enabled", true},
            {"provider", "local"},
            {"username", "admin"},
            {"password", legacy},
        }
                .dump());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    {
        ApiServer server(config);
        server.start();
        httplib::Client client("127.0.0.1", configured_port(config));
        const auto login = client.Post(
            "/api/auth/login",
            nlohmann::json{
                {"username", "admin"},
                {"password", legacy},
            }
                .dump(),
            "application/json");
        REQUIRE(login != nullptr);
        REQUIRE(login->status == 200);
        server.stop();
    }

    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    REQUIRE(stored.at("password_format") == kLocalPasswordHashFormat);
    const auto persisted = stored.at("password").get<std::string>();
    REQUIRE(local_password_hash_encoded(persisted));
    CHECK(verify_local_password(persisted, legacy) ==
          LocalPasswordVerdict::matched);

    // The atomic password+format publication remains usable after restart.
    ApiServer restarted(config);
    restarted.start();
    httplib::Client restarted_client(
        "127.0.0.1", configured_port(config));
    const auto after_restart = restarted_client.Post(
        "/api/auth/login",
        nlohmann::json{
            {"username", "admin"},
            {"password", legacy},
        }
            .dump(),
        "application/json");
    REQUIRE(after_restart != nullptr);
    CHECK(after_restart->status == 200);
}

TEST_CASE("an explicitly tagged damaged local password fails closed") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        nlohmann::json{
            {"enabled", true},
            {"provider", "local"},
            {"username", "admin"},
            {"password", kLocalPasswordHashFormat},
            {"password_format", kLocalPasswordHashFormat},
        }
                .dump());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    const auto status = get_auth_status(client);
    CHECK(status.at("error") == "auth_misconfigured");
    const auto login = client.Post(
        "/api/auth/login",
        nlohmann::json{
            {"username", "admin"},
            {"password", kLocalPasswordHashFormat},
        }
            .dump(),
        "application/json");
    REQUIRE(login != nullptr);
    CHECK(login->status == 503);
}

TEST_CASE("a pre-commit migration failure never locks out the legacy owner") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    const std::string legacy =
        R"({"enabled":true,"provider":"local","username":"admin","password":"legacy-secret"})";
    write_text(auth_path, legacy);
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard write_fault(
        "KEEN_PBR_TEST_AUTH_WRITE_FAULT", "write");

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto login = client.Post(
            "/api/auth/login",
            R"({"username":"admin","password":"legacy-secret"})",
            "application/json");
        REQUIRE(login != nullptr);
        CHECK(login->status == 200);
    }
    server.stop();

    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    CHECK(stored.at("password") == "legacy-secret");
    CHECK_FALSE(stored.contains("password_format"));
}

TEST_CASE("a post-rename migration sync failure keeps old and new boots usable") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"legacy-secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard write_fault(
        "KEEN_PBR_TEST_AUTH_WRITE_FAULT", "directory_fsync");

    const auto config = auth_api_config();
    {
        ApiServer server(config);
        server.start();
        httplib::Client client("127.0.0.1", configured_port(config));
        const auto login = client.Post(
            "/api/auth/login",
            R"({"username":"admin","password":"legacy-secret"})",
            "application/json");
        REQUIRE(login != nullptr);
        CHECK(login->status == 200);
        server.stop();
    }

    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    const auto persisted = stored.at("password").get<std::string>();
    CHECK(stored.at("password_format") == kLocalPasswordHashFormat);
    CHECK(local_password_hash_encoded(persisted));
    CHECK(verify_local_password(persisted, "legacy-secret") ==
          LocalPasswordVerdict::matched);

    ApiServer restarted(config);
    restarted.start();
    httplib::Client restarted_client(
        "127.0.0.1", configured_port(config));
    const auto after_restart = restarted_client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"legacy-secret"})",
        "application/json");
    REQUIRE(after_restart != nullptr);
    CHECK(after_restart->status == 200);
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
    TrustedLocalConnectionEvaluatorGuard trusted_local_transport(
        [](std::string_view, std::string_view, bool) { return true; });

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
    CHECK(login_response->get_header_value("Connection") == "close");
    const httplib::Headers headers{
        {"Cookie", session_cookie(*login_response)},
    };
    grant_local_step_up(client, headers, "old", "old-secret");
    const auto malformed = client.Post(
        "/api/auth/settings",
        headers,
        R"({"enabled":true,"provider":"local","password":"DO_NOT_ECHO",)",
        "application/json");
    REQUIRE(malformed != nullptr);
    CHECK(malformed->status == 400);
    CHECK(malformed->body.find("DO_NOT_ECHO") == std::string::npos);
    CHECK(nlohmann::json::parse(malformed->body).at("error") ==
          "invalid authentication settings request");
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
    // What is written is a derived key, never the password. The file is 0600,
    // but that is the only thing between it and anyone who reads it, and a
    // rescue snapshot copies this file as well.
    const auto persisted = stored.at("password").get<std::string>();
    CHECK(persisted != "new-secret");
    CHECK(persisted.find("new-secret") == std::string::npos);
    CHECK(stored.at("password_format") == kLocalPasswordHashFormat);
    CHECK(local_password_hash_encoded(persisted));
    CHECK(verify_local_password(persisted, "new-secret") ==
          LocalPasswordVerdict::matched);

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

    TrustedLocalConnectionEvaluatorGuard trusted_local_transport(
        [](std::string_view, std::string_view, bool) { return true; });

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
    grant_local_step_up(client, headers, "admin", "secret");
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

TEST_CASE("disabling local authentication removes the derived format tag") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    const auto remote_path = directory.path / "remote-access.json";
    const auto derived = encode_local_password_hash(
        "secret", "0123456789abcdef0123456789abcdef", 1000U);
    REQUIRE(local_password_hash_encoded(derived));
    write_text(
        auth_path,
        nlohmann::json{
            {"enabled", true},
            {"provider", "local"},
            {"username", "admin"},
            {"password", derived},
            {"password_format", kLocalPasswordHashFormat},
        }
            .dump());
    write_text(remote_path, R"({"enabled":false,"port":12121})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard remote_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", remote_path.string());
    VerifiedClosedRemoteAccessGuard remote_access_closed;
    TrustedLocalConnectionEvaluatorGuard trusted_local_transport(
        [](std::string_view, std::string_view, bool) { return true; });

    const auto config = auth_api_config();
    {
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
        grant_local_step_up(client, headers, "admin", "secret");

        const auto disable = client.Post(
            "/api/auth/settings",
            headers,
            R"({"enabled":false,"provider":"local"})",
            "application/json");
        REQUIRE(disable != nullptr);
        CHECK(disable->status == 200);
        server.stop();
    }

    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    CHECK_FALSE(stored.at("enabled").get<bool>());
    CHECK(stored.at("password") == "");
    CHECK_FALSE(stored.contains("password_format"));

    // Restart must load the deliberately disabled state instead of treating a
    // stale representation tag as a damaged derived credential.
    ApiServer restarted(config);
    restarted.start();
    httplib::Client restarted_client(
        "127.0.0.1", configured_port(config));
    const auto status = get_auth_status(restarted_client);
    CHECK_FALSE(status.at("enabled").get<bool>());
    CHECK_FALSE(status.contains("error"));
}

TEST_CASE(
    "Keenetic provider switch preserves local auth until capability is usable") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    const auto remote_path = directory.path / "remote-access.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"local-secret"})");
    write_text(remote_path, R"({"enabled":false,"port":12121})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard remote_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", remote_path.string());
    VerifiedClosedRemoteAccessGuard remote_access_closed;
    TrustedLocalConnectionEvaluatorGuard trusted_local_transport(
        [](std::string_view, std::string_view, bool) { return true; });

    std::atomic<unsigned int> forwarded_credentials{0};
    httplib::Server router;
    router.Get("/auth", [](const httplib::Request&,
                            httplib::Response& response) {
        response.status = 401;
        response.set_header("X-NDM-Realm", "Keenetic");
        response.set_header("X-NDM-Challenge", "challenge");
    });
    router.Post("/auth", [&forwarded_credentials](
                             const httplib::Request&,
                             httplib::Response& response) {
        forwarded_credentials.fetch_add(1, std::memory_order_relaxed);
        response.status = 200;
    });
    BoundHttpServer running_router(router);

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"local-secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers headers{{"Cookie", session_cookie(*login)}};
    grant_local_step_up(client, headers, "admin", "local-secret");

    const auto endpoint =
        "127.0.0.1:" + std::to_string(running_router.port());
    const auto response = client.Post(
        "/api/auth/settings",
        headers,
        nlohmann::json{
            {"enabled", true},
            {"provider", "keenetic"},
            {"keenetic_endpoint_mode", "manual"},
            {"keenetic_endpoint", endpoint},
            {"username", "admin"},
            {"password", "router-secret"},
        }
            .dump(),
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 503);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body.at("error") == "system_auth_capability_not_usable");
    CHECK(body.at("capability_state") == "loopback_not_accepted");
    CHECK(forwarded_credentials.load(std::memory_order_relaxed) == 0U);
    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    CHECK(stored.at("provider") == "local");
    const auto retained = stored.at("password").get<std::string>();
    CHECK(local_password_hash_encoded(retained));
    CHECK(verify_local_password(retained, "local-secret") ==
          LocalPasswordVerdict::matched);
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
    TrustedLocalConnectionEvaluatorGuard trusted_local_transport(
        [](std::string_view, std::string_view, bool) { return true; });

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
    grant_local_step_up(client, headers, "old", "old-secret");

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
    const auto persisted = stored.at("password").get<std::string>();
    CHECK(persisted != "new-secret");
    CHECK(stored.at("password_format") == kLocalPasswordHashFormat);
    CHECK(verify_local_password(persisted, "new-secret") ==
          LocalPasswordVerdict::matched);

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
    TrustedLocalConnectionEvaluatorGuard trusted_local_transport(
        [](std::string_view, std::string_view, bool) { return true; });

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
    grant_local_step_up(client, headers, "old", "old-secret");

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
    CHECK(status.at("no_auth_scope") == "loopback_only");
    CHECK_FALSE(status.at("network_api_blocked").get<bool>());
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

    // Both requests must cross pre-routing before either one publishes the
    // auth latch. A request which arrives after that point is intentionally
    // rejected with 503, so scheduler timing must not decide whether this
    // test exercises two admitted writers or the fail-closed publication
    // fence.
    constexpr int writer_count = 2;
    std::mutex admission_mutex;
    std::condition_variable admission_cv;
    int admitted_writers = 0;
    bool release_writers = false;
    set_auth_settings_admission_hook_for_testing([&]() {
        std::unique_lock lock(admission_mutex);
        ++admitted_writers;
        admission_cv.notify_all();
        admission_cv.wait(lock, [&]() { return release_writers; });
    });
    struct AdmissionHookReset {
        ~AdmissionHookReset() {
            reset_auth_settings_admission_hook_for_testing();
        }
    } admission_hook_reset;

    const int port = configured_port(config);
    std::atomic<bool> failed{false};
    std::vector<std::thread> writers;
    writers.reserve(writer_count);
    for (int index = 0; index < writer_count; ++index) {
        writers.emplace_back([&] {
            httplib::Client client("127.0.0.1", port);
            nlohmann::json settings{
                {"enabled", false},
                {"provider", "local"},
            };
            const auto response = client.Post(
                "/api/auth/settings",
                settings.dump(),
                "application/json");
            if (!response || response->status != 200) {
                failed.store(true, std::memory_order_relaxed);
            }
        });
    }
    bool both_admitted = false;
    {
        std::unique_lock lock(admission_mutex);
        both_admitted = admission_cv.wait_for(
            lock,
            std::chrono::seconds{5},
            [&]() { return admitted_writers == writer_count; });
        release_writers = true;
    }
    admission_cv.notify_all();
    for (auto& writer : writers) writer.join();

    REQUIRE(both_admitted);
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

TEST_CASE("queued auth settings cannot publish after an earlier request revokes its session") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    const auto remote_path = directory.path / "remote-access.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})");
    write_text(remote_path, R"({"enabled":false,"port":12121})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    EnvironmentVariableGuard remote_file(
        "KEEN_PBR_TEST_REMOTE_SETTINGS_FILE", remote_path.string());
    VerifiedClosedRemoteAccessGuard remote_access_closed;
    TrustedLocalConnectionEvaluatorGuard trusted_local_transport(
        [](std::string_view, std::string_view, bool) { return true; });

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    const int port = configured_port(config);
    httplib::Client client("127.0.0.1", port);
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const std::string cookie = session_cookie(*login);
    const httplib::Headers session{{"Cookie", cookie}};
    grant_local_step_up(client, session, "admin", "secret");

    std::mutex admission_mutex;
    std::condition_variable admission_cv;
    int admitted = 0;
    bool release_first = false;
    set_auth_settings_admission_hook_for_testing([&]() {
        std::unique_lock lock(admission_mutex);
        ++admitted;
        admission_cv.notify_all();
        if (admitted == 1) {
            admission_cv.wait(lock, [&]() { return release_first; });
        }
    });
    struct AdmissionHookReset {
        ~AdmissionHookReset() {
            reset_auth_settings_admission_hook_for_testing();
        }
    } admission_hook_reset;

    std::atomic<int> queued_status{0};
    std::thread queued([&]() {
        httplib::Client queued_client("127.0.0.1", port);
        const httplib::Headers queued_session{{"Cookie", cookie}};
        const auto response = queued_client.Post(
            "/api/auth/settings", queued_session,
            R"({"enabled":true,"provider":"local","username":"attacker","password":"replacement"})",
            "application/json");
        queued_status.store(
            response ? response->status : -1,
            std::memory_order_release);
    });

    bool first_admitted = false;
    {
        std::unique_lock lock(admission_mutex);
        first_admitted = admission_cv.wait_for(
            lock, std::chrono::seconds{5}, [&]() { return admitted == 1; });
    }
    int disabling_status = -1;
    if (first_admitted) {
        const auto disabling = client.Post(
            "/api/auth/settings", session,
            R"({"enabled":false,"provider":"local"})",
            "application/json");
        disabling_status = disabling ? disabling->status : -1;
    }
    {
        std::lock_guard lock(admission_mutex);
        release_first = true;
    }
    admission_cv.notify_all();
    queued.join();

    REQUIRE(first_admitted);
    REQUIRE(disabling_status == 200);
    CHECK(queued_status.load(std::memory_order_acquire) == 401);
    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    CHECK_FALSE(stored.at("enabled").get<bool>());
    CHECK(stored.at("provider") == "local");
    const bool attacker_published =
        stored.contains("username") && stored.at("username") == "attacker";
    CHECK_FALSE(attacker_published);
}

TEST_CASE("queued auth settings cannot publish after its step-up grant expires") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    VerifiedClosedRemoteAccessGuard remote_access_closed;
    TrustedLocalConnectionEvaluatorGuard trusted_local_transport(
        [](std::string_view, std::string_view, bool) { return true; });

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    const int port = configured_port(config);
    httplib::Client client("127.0.0.1", port);
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const std::string cookie = session_cookie(*login);
    const httplib::Headers session{{"Cookie", cookie}};
    grant_local_step_up(client, session, "admin", "secret");

    std::mutex admission_mutex;
    std::condition_variable admission_cv;
    bool admitted = false;
    bool release = false;
    set_auth_settings_admission_hook_for_testing([&]() {
        std::unique_lock lock(admission_mutex);
        admitted = true;
        admission_cv.notify_all();
        admission_cv.wait(lock, [&]() { return release; });
    });
    struct AdmissionHookReset {
        ~AdmissionHookReset() {
            reset_auth_settings_admission_hook_for_testing();
        }
    } admission_hook_reset;

    std::atomic<int> queued_status{0};
    std::thread queued([&]() {
        httplib::Client queued_client("127.0.0.1", port);
        const auto response = queued_client.Post(
            "/api/auth/settings", session,
            R"({"enabled":true,"provider":"local","username":"attacker","password":"replacement"})",
            "application/json");
        queued_status.store(
            response ? response->status : -1,
            std::memory_order_release);
    });

    bool request_admitted = false;
    {
        std::unique_lock lock(admission_mutex);
        request_admitted = admission_cv.wait_for(
            lock, std::chrono::seconds{5}, [&]() { return admitted; });
    }
    const auto separator = cookie.find('=');
    if (request_admitted && separator != std::string::npos) {
        server.revoke_step_up_grant_for_testing(cookie.substr(separator + 1));
    }
    {
        std::lock_guard lock(admission_mutex);
        release = true;
    }
    admission_cv.notify_all();
    queued.join();

    REQUIRE(request_admitted);
    REQUIRE(separator != std::string::npos);
    CHECK(queued_status.load(std::memory_order_acquire) == 403);
    const auto stored = nlohmann::json::parse(std::ifstream(auth_path));
    CHECK(stored.at("username") == "admin");
    CHECK_FALSE(stored.at("password") == "replacement");
}

TEST_CASE("login admission cannot cross a local to Keenetic publication") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"local-secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    std::atomic<unsigned int> forwarded_credentials{0U};
    httplib::Server router;
    router.Get("/auth", [](const httplib::Request&,
                            httplib::Response& response) {
        response.status = 401;
        response.set_header("X-NDM-Realm", "Keenetic");
        response.set_header("X-NDM-Challenge", "challenge");
    });
    router.Post("/auth", [&forwarded_credentials](
                             const httplib::Request&,
                             httplib::Response& response) {
        forwarded_credentials.fetch_add(1U, std::memory_order_relaxed);
        response.status = 200;
    });
    BoundHttpServer running_router(router);

    std::mutex hook_mutex;
    std::condition_variable hook_cv;
    bool admitted = false;
    bool release = false;
    CredentialHandlerAdmissionHookGuard admission_hook(
        [&](const std::string_view path) {
            if (path != "/api/auth/login") return;
            std::unique_lock lock(hook_mutex);
            admitted = true;
            hook_cv.notify_all();
            hook_cv.wait(lock, [&]() { return release; });
        });

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    std::atomic<int> login_status{-1};
    std::thread login_thread([&]() {
        httplib::Client client("127.0.0.1", configured_port(config));
        const auto response = client.Post(
            "/api/auth/login",
            R"({"username":"admin","password":"DO_NOT_FORWARD"})",
            "application/json");
        login_status.store(
            response ? response->status : -1,
            std::memory_order_release);
    });

    bool request_admitted = false;
    {
        std::unique_lock lock(hook_mutex);
        request_admitted = hook_cv.wait_for(
            lock, std::chrono::seconds{5}, [&]() { return admitted; });
    }
    if (request_admitted) {
        server.publish_auth_provider_for_testing(
            "keenetic",
            "127.0.0.1:" + std::to_string(running_router.port()));
    }
    {
        std::lock_guard lock(hook_mutex);
        release = true;
    }
    hook_cv.notify_all();
    login_thread.join();

    REQUIRE(request_admitted);
    CHECK(login_status.load(std::memory_order_acquire) == 403);
    CHECK(forwarded_credentials.load(std::memory_order_relaxed) == 0U);
}

TEST_CASE("step-up admission cannot cross a local to Keenetic publication") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"local-secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    std::atomic<unsigned int> forwarded_credentials{0U};
    httplib::Server router;
    router.Get("/auth", [](const httplib::Request&,
                            httplib::Response& response) {
        response.status = 401;
        response.set_header("X-NDM-Realm", "Keenetic");
        response.set_header("X-NDM-Challenge", "challenge");
    });
    router.Post("/auth", [&forwarded_credentials](
                             const httplib::Request&,
                             httplib::Response& response) {
        forwarded_credentials.fetch_add(1U, std::memory_order_relaxed);
        response.status = 200;
    });
    BoundHttpServer running_router(router);

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"local-secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const std::string cookie = session_cookie(*login);

    std::mutex hook_mutex;
    std::condition_variable hook_cv;
    bool admitted = false;
    bool release = false;
    CredentialHandlerAdmissionHookGuard admission_hook(
        [&](const std::string_view path) {
            if (path != "/api/auth/step-up") return;
            std::unique_lock lock(hook_mutex);
            admitted = true;
            hook_cv.notify_all();
            hook_cv.wait(lock, [&]() { return release; });
        });
    std::atomic<int> step_up_status{-1};
    std::thread step_up_thread([&]() {
        httplib::Client step_up_client(
            "127.0.0.1", configured_port(config));
        const httplib::Headers session{{"Cookie", cookie}};
        const auto response = step_up_client.Post(
            "/api/auth/step-up", session,
            R"({"username":"admin","password":"DO_NOT_FORWARD"})",
            "application/json");
        step_up_status.store(
            response ? response->status : -1,
            std::memory_order_release);
    });

    bool request_admitted = false;
    {
        std::unique_lock lock(hook_mutex);
        request_admitted = hook_cv.wait_for(
            lock, std::chrono::seconds{5}, [&]() { return admitted; });
    }
    if (request_admitted) {
        server.publish_auth_provider_for_testing(
            "keenetic",
            "127.0.0.1:" + std::to_string(running_router.port()));
    }
    {
        std::lock_guard lock(hook_mutex);
        release = true;
    }
    hook_cv.notify_all();
    step_up_thread.join();

    REQUIRE(request_admitted);
    CHECK(step_up_status.load(std::memory_order_acquire) == 403);
    CHECK(forwarded_credentials.load(std::memory_order_relaxed) == 0U);
}

TEST_CASE("Keenetic login rejects untrusted and forwarded transport before body parsing") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"keenetic","keenetic_endpoint_mode":"manual","keenetic_endpoint":"127.0.0.1:8080"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    std::atomic<unsigned int> evaluations{0U};
    TrustedLocalConnectionEvaluatorGuard local_transport(
        [&](std::string_view, std::string_view, const bool credential_fresh) {
            evaluations.fetch_add(1U, std::memory_order_relaxed);
            CHECK(credential_fresh);
            return false;
        });

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));

    const auto untrusted = client.Post(
        "/api/auth/login", "this is deliberately not JSON", "application/json");
    REQUIRE(untrusted != nullptr);
    CHECK(untrusted->status == 403);
    CHECK(untrusted->get_header_value("Cache-Control") == "no-store");
    CHECK(nlohmann::json::parse(untrusted->body).at("error") ==
          "protected_secret_transport_unavailable");
    CHECK(evaluations.load(std::memory_order_relaxed) == 1U);

    const httplib::Headers forwarded{{"X-Forwarded-For", "192.168.1.5"}};
    const auto spoofed = client.Post(
        "/api/auth/login", forwarded, "still not JSON", "application/json");
    REQUIRE(spoofed != nullptr);
    CHECK(spoofed->status == 403);
    // Forwarding headers are denied before the injectable socket evaluator.
    CHECK(evaluations.load(std::memory_order_relaxed) == 1U);

    const httplib::Headers plaintext_proxy{
        {"Origin", "http://vpn.router.keenetic.pro"},
        {"Sec-Fetch-Site", "same-origin"},
        {"X-Forwarded-Proto", "https"},
    };
    const auto plaintext = client.Post(
        "/api/auth/login", plaintext_proxy, "still not JSON", "application/json");
    REQUIRE(plaintext != nullptr);
    CHECK(plaintext->status == 403);
    // A claimed forwarding scheme cannot override the browser-visible HTTP
    // Origin, and the direct-local evaluator remains bypassed.
    CHECK(evaluations.load(std::memory_order_relaxed) == 1U);

}

TEST_CASE("Keenetic login rejects ambiguous HTTPS proxy headers") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"keenetic","keenetic_endpoint_mode":"manual","keenetic_endpoint":"127.0.0.1:8080"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    TrustedLocalConnectionEvaluatorGuard local_transport(
        [](std::string_view, std::string_view, bool) { return false; });

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    const httplib::Headers duplicate_origin{
        {"Origin", "https://one.router.keenetic.pro"},
        {"Origin", "https://two.router.keenetic.pro"},
    };
    const auto response = client.Post(
        "/api/auth/login", duplicate_origin, "must not be parsed",
        "application/json");

    REQUIRE(response != nullptr);
    CHECK(response->status == 403);
    CHECK(nlohmann::json::parse(response->body).at("error") ==
          "protected_secret_transport_unavailable");
}

TEST_CASE("Keenetic credential gates answer and close before a withheld body") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"keenetic","keenetic_endpoint_mode":"manual","keenetic_endpoint":"127.0.0.1:8080"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    TrustedLocalConnectionEvaluatorGuard local_transport(
        [](std::string_view, std::string_view, bool) { return false; });

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    const auto denied = post_headers_without_body(
        configured_port(config), "/api/auth/login");

    CHECK(denied.response.rfind("HTTP/1.1 403", 0U) == 0U);
    CHECK(denied.response.find("protected_secret_transport_unavailable") !=
          std::string::npos);
    CHECK(denied.response.find("Cache-Control: no-store") !=
          std::string::npos);
    CHECK(denied.response.find("Connection: close") != std::string::npos);
    CHECK(denied.peer_closed);
    CHECK(denied.elapsed < std::chrono::milliseconds{1000});
}

TEST_CASE("Keenetic login and step-up use trusted local HTTP transport") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    std::atomic<unsigned int> forwarded_credentials{0U};
    httplib::Server router;
    router.Get("/auth", [](const httplib::Request&,
                            httplib::Response& response) {
        response.status = 401;
        response.set_header("X-NDM-Realm", "Keenetic");
        response.set_header("X-NDM-Challenge", "challenge");
    });
    router.Post("/auth", [&forwarded_credentials](
                             const httplib::Request&,
                             httplib::Response& response) {
        forwarded_credentials.fetch_add(1U, std::memory_order_relaxed);
        response.status = 200;
    });
    BoundHttpServer running_router(router);
    write_text(
        auth_path,
        nlohmann::json{
            {"enabled", true},
            {"provider", "keenetic"},
            {"keenetic_endpoint_mode", "manual"},
            {"keenetic_endpoint",
             "127.0.0.1:" + std::to_string(running_router.port())},
        }.dump());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    std::atomic<unsigned int> evaluations{0U};
    TrustedLocalConnectionEvaluatorGuard local_transport(
        [&](std::string_view remote, std::string_view local,
            const bool credential_fresh) {
            CHECK_FALSE(remote.empty());
            CHECK_FALSE(local.empty());
            CHECK(credential_fresh);
            evaluations.fetch_add(1U, std::memory_order_relaxed);
            return true;
        });

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"router-secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers session{{"Cookie", session_cookie(*login)}};
    const auto step_up = client.Post(
        "/api/auth/step-up",
        session,
        R"({"username":"admin","password":"router-secret"})",
        "application/json");
    REQUIRE(step_up != nullptr);
    CHECK(step_up->status == 200);
    CHECK(nlohmann::json::parse(step_up->body).at("granted").get<bool>());
    CHECK(evaluations.load(std::memory_order_relaxed) == 2U);
    CHECK(forwarded_credentials.load(std::memory_order_relaxed) == 2U);
}

TEST_CASE("Keenetic login and step-up allow router-owned HTTPS proxy transport") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    std::atomic<unsigned int> forwarded_credentials{0U};
    httplib::Server router;
    router.Get("/auth", [](const httplib::Request&,
                            httplib::Response& response) {
        response.status = 401;
        response.set_header("X-NDM-Realm", "Keenetic");
        response.set_header("X-NDM-Challenge", "challenge");
    });
    router.Post("/auth", [&forwarded_credentials](
                             const httplib::Request&,
                             httplib::Response& response) {
        forwarded_credentials.fetch_add(1U, std::memory_order_relaxed);
        response.status = 200;
    });
    BoundHttpServer running_router(router);
    write_text(
        auth_path,
        nlohmann::json{
            {"enabled", true},
            {"provider", "keenetic"},
            {"keenetic_endpoint_mode", "manual"},
            {"keenetic_endpoint",
             "127.0.0.1:" + std::to_string(running_router.port())},
        }.dump());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    std::atomic<unsigned int> local_evaluations{0U};
    TrustedLocalConnectionEvaluatorGuard local_transport(
        [&](std::string_view, std::string_view, bool) {
            local_evaluations.fetch_add(1U, std::memory_order_relaxed);
            return false;
        });

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    const httplib::Headers https_proxy{
        {"Origin", "https://vpn.router.keenetic.pro"},
        {"Sec-Fetch-Site", "same-origin"},
        {"X-Forwarded-For", "198.51.100.25"},
        {"X-Forwarded-Proto", "https"},
    };
    const auto login = client.Post(
        "/api/auth/login",
        https_proxy,
        R"({"username":"admin","password":"router-secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    CHECK(login->get_header_value("Set-Cookie").find("; Secure") !=
          std::string::npos);

    auto step_up_headers = https_proxy;
    step_up_headers.emplace("Cookie", session_cookie(*login));
    const auto step_up = client.Post(
        "/api/auth/step-up",
        step_up_headers,
        R"({"username":"admin","password":"router-secret"})",
        "application/json");
    REQUIRE(step_up != nullptr);
    CHECK(step_up->status == 200);
    CHECK(nlohmann::json::parse(step_up->body).at("granted").get<bool>());
    // X-Forwarded-For prevents this request from entering the direct-LAN
    // evaluator; only the separate router-owned HTTPS proof may admit it.
    CHECK(local_evaluations.load(std::memory_order_relaxed) == 0U);
    CHECK(forwarded_credentials.load(std::memory_order_relaxed) == 2U);

    const auto settings = client.Post(
        "/api/auth/settings",
        step_up_headers,
        R"({"enabled":true,"provider":"keenetic"})",
        "application/json");
    REQUIRE(settings != nullptr);
    CHECK(settings->status == 403);

    const auto logout = client.Post(
        "/api/auth/logout", step_up_headers, "", "application/json");
    REQUIRE(logout != nullptr);
    CHECK(logout->status == 200);
    CHECK(logout->get_header_value("Set-Cookie").find("; Secure") !=
          std::string::npos);
}

TEST_CASE("Keenetic step-up rejects stale local proof before forwarding credentials") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    std::atomic<unsigned int> forwarded_credentials{0U};
    httplib::Server router;
    router.Get("/auth", [](const httplib::Request&,
                            httplib::Response& response) {
        response.status = 401;
        response.set_header("X-NDM-Realm", "Keenetic");
        response.set_header("X-NDM-Challenge", "challenge");
    });
    router.Post("/auth", [&forwarded_credentials](
                             const httplib::Request&,
                             httplib::Response& response) {
        forwarded_credentials.fetch_add(1U, std::memory_order_relaxed);
        response.status = 200;
    });
    BoundHttpServer running_router(router);
    write_text(
        auth_path,
        nlohmann::json{
            {"enabled", true},
            {"provider", "keenetic"},
            {"keenetic_endpoint_mode", "manual"},
            {"keenetic_endpoint",
             "127.0.0.1:" + std::to_string(running_router.port())},
        }.dump());
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());
    std::atomic<bool> transport_trusted{true};
    std::atomic<unsigned int> evaluations{0U};
    TrustedLocalConnectionEvaluatorGuard local_transport(
        [&](std::string_view, std::string_view,
            const bool credential_fresh) {
            CHECK(credential_fresh);
            evaluations.fetch_add(1U, std::memory_order_relaxed);
            return transport_trusted.load(std::memory_order_relaxed);
        });

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"router-secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    REQUIRE(forwarded_credentials.load(std::memory_order_relaxed) == 1U);
    const httplib::Headers session{{"Cookie", session_cookie(*login)}};

    transport_trusted.store(false, std::memory_order_relaxed);
    const auto denied = client.Post(
        "/api/auth/step-up",
        session,
        "not JSON and must not be parsed",
        "application/json");
    REQUIRE(denied != nullptr);
    CHECK(denied->status == 403);
    CHECK(nlohmann::json::parse(denied->body).at("error") ==
          "protected_secret_transport_unavailable");
    CHECK(evaluations.load(std::memory_order_relaxed) == 2U);
    CHECK(forwarded_credentials.load(std::memory_order_relaxed) == 1U);
}

TEST_CASE("nfqws action step-up runs after body read and before its handler") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    TrustedLocalConnectionEvaluatorGuard trusted_local_transport(
        [](std::string_view, std::string_view, bool) { return true; });

    const auto config = auth_api_config();
    ApiServer server(config);
    std::atomic<unsigned int> handled{0U};
    server.post(
        "/api/nfqws",
        [&](const std::string& body) {
            handled.fetch_add(1U, std::memory_order_relaxed);
            return nlohmann::json{{"body", body}}.dump();
        });
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers session{{"Cookie", session_cookie(*login)}};

    const auto upgrade = client.Post(
        "/api/nfqws", session, R"({"action":"upgrade"})",
        "application/json");
    REQUIRE(upgrade != nullptr);
    CHECK(upgrade->status == 403);
    CHECK(nlohmann::json::parse(upgrade->body).at("error") ==
          "step_up_required");
    CHECK(handled.load(std::memory_order_relaxed) == 0U);

    const std::vector<nlohmann::json> ordinary_payloads{
        {{"action", "service"}, {"command", "start"}},
        {{"action", "service"}, {"command", "stop"}},
        {{"action", "service"}, {"command", "restart"}},
        {{"action", "check_update"}},
    };
    for (const auto& payload : ordinary_payloads) {
        const auto ordinary = client.Post(
            "/api/nfqws", session, payload.dump(),
            "application/json");
        REQUIRE(ordinary != nullptr);
        CHECK(ordinary->status == 200);
    }
    CHECK(handled.load(std::memory_order_relaxed) == 4U);

    grant_local_step_up(client, session, "admin", "secret");
    const auto granted = client.Post(
        "/api/nfqws", session, R"({"action":"upgrade"})",
        "application/json");
    REQUIRE(granted != nullptr);
    CHECK(granted->status == 200);
    CHECK(handled.load(std::memory_order_relaxed) == 5U);
}

TEST_CASE("sing-box install requires step-up before its handler runs") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"admin","password":"secret"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    TrustedLocalConnectionEvaluatorGuard trusted_local_transport(
        [](std::string_view, std::string_view, bool) { return true; });

    const auto config = auth_api_config();
    ApiServer server(config);
    std::atomic<unsigned int> handled{0U};
    server.post(
        "/api/transports/sing-box/install",
        [&](const std::string&) {
            handled.fetch_add(1U, std::memory_order_relaxed);
            return nlohmann::json{{"installed", true}}.dump();
        });
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    const auto login = client.Post(
        "/api/auth/login",
        R"({"username":"admin","password":"secret"})",
        "application/json");
    REQUIRE(login != nullptr);
    REQUIRE(login->status == 200);
    const httplib::Headers session{{"Cookie", session_cookie(*login)}};

    const auto denied = client.Post(
        "/api/transports/sing-box/install", session,
        R"({"stop_running_transports":false})", "application/json");
    REQUIRE(denied != nullptr);
    CHECK(denied->status == 403);
    CHECK(nlohmann::json::parse(denied->body).at("error") ==
          "step_up_required");
    CHECK(handled.load(std::memory_order_relaxed) == 0U);

    grant_local_step_up(client, session, "admin", "secret");
    const auto granted = client.Post(
        "/api/transports/sing-box/install", session,
        R"({"stop_running_transports":false})", "application/json");
    REQUIRE(granted != nullptr);
    CHECK(granted->status == 200);
    CHECK(handled.load(std::memory_order_relaxed) == 1U);
}

TEST_CASE("rate limiter atomically caps parallel attempts from one source") {
    using Clock = AuthLoginRateLimiter::Clock;
    const auto start = Clock::now();
    AuthLoginRateLimiter limiter({
        3,
        std::chrono::seconds{100},
        std::chrono::seconds{100},
        8,
    });

    constexpr int workers = 16;
    std::atomic<int> ready{0};
    std::atomic<int> attempted{0};
    std::atomic<int> admitted{0};
    std::atomic<bool> begin{false};
    std::atomic<bool> release{false};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (int index = 0; index < workers; ++index) {
        threads.emplace_back([&]() {
            ready.fetch_add(1, std::memory_order_release);
            while (!begin.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            auto permit = limiter.reserve_attempt("192.0.2.10", start);
            if (permit) {
                admitted.fetch_add(1, std::memory_order_release);
            }
            attempted.fetch_add(1, std::memory_order_release);
            if (permit) {
                while (!release.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                permit->record_failure(start);
            }
        });
    }

    while (ready.load(std::memory_order_acquire) != workers) {
        std::this_thread::yield();
    }
    begin.store(true, std::memory_order_release);
    while (attempted.load(std::memory_order_acquire) != workers) {
        std::this_thread::yield();
    }
    // The old allow()/record_failure() split admitted all sixteen before any
    // worker could publish a failure. Reservations make the ceiling atomic.
    CHECK(admitted.load(std::memory_order_acquire) == 3);
    release.store(true, std::memory_order_release);
    for (auto& thread : threads) thread.join();

    CHECK_FALSE(limiter.reserve_attempt(
        "192.0.2.10", start + std::chrono::seconds{1}));
}

TEST_CASE("an abandoned login permit fails closed") {
    using Clock = AuthLoginRateLimiter::Clock;
    const auto start = Clock::now();
    AuthLoginRateLimiter limiter({
        1,
        std::chrono::seconds{100},
        std::chrono::seconds{100},
        8,
    });

    {
        auto permit = limiter.reserve_attempt("192.0.2.11", start);
        REQUIRE(permit.has_value());
        // Scope exit models parsing/verification throwing before a verdict.
    }
    CHECK_FALSE(limiter.reserve_attempt(
        "192.0.2.11", Clock::now()));
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

TEST_CASE("API requests never perform the router credential RCI read") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"keenetic",)"
        R"("keenetic_endpoint_mode":"manual",)"
        R"("keenetic_endpoint":"127.0.0.1:80"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    std::atomic<unsigned int> reads{0U};
    httplib::Server ndms;
    ndms.Get("/rci/show/rc/user",
             [&reads](const httplib::Request&, httplib::Response& response) {
                 reads.fetch_add(1U, std::memory_order_relaxed);
                 response.set_content(
                     R"({"admin":{"password":{"nt":{"hash":"aaaa"}},"tag":["http"]}})",
                     "application/json");
             });
    BoundHttpServer running_ndms(ndms);
    EnvironmentVariableGuard endpoint_override(
        "KEEN_PBR_TEST_NDMS_USER_ENDPOINT",
        "http://127.0.0.1:" + std::to_string(running_ndms.port()) +
            "/rci/show/rc/user");
    // The reviewed implementation used this override to make every request
    // due. Keeping it here makes the regression fail on that implementation;
    // the worker-based implementation intentionally ignores it.
    EnvironmentVariableGuard legacy_interval_override(
        "KEEN_PBR_TEST_NDMS_USER_INTERVAL_MS", "0");

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    httplib::Client client("127.0.0.1", configured_port(config));
    for (int request = 0; request < 8; ++request) {
        const auto response = client.Get("/api/auth/status");
        REQUIRE(response != nullptr);
        CHECK(response->status == 200);
    }
    server.stop();

    // One startup read establishes the baseline before sessions can be
    // published. The worker then waits 30 seconds; the eight requests cannot
    // wake it or perform RCI inline.
    CHECK(reads.load(std::memory_order_relaxed) == 1U);
}

TEST_CASE("concurrent router credential polls never queue another RCI read") {
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"keenetic",)"
        R"("keenetic_endpoint_mode":"manual",)"
        R"("keenetic_endpoint":"127.0.0.1:80"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    std::mutex read_mutex;
    std::condition_variable read_cv;
    bool entered = false;
    bool release = false;
    unsigned int reads = 0U;
    httplib::Server ndms;
    ndms.Get("/rci/show/rc/user",
             [&](const httplib::Request&, httplib::Response& response) {
                 std::unique_lock lock(read_mutex);
                 ++reads;
                 if (reads == 1U) {
                     response.set_content(
                         R"({"admin":{"password":{"nt":{"hash":"aaaa"}},"tag":["http"]}})",
                         "application/json");
                     return;
                 }
                 entered = true;
                 read_cv.notify_all();
                 read_cv.wait(lock, [&]() { return release; });
                 response.set_content(
                     R"({"admin":{"password":{"nt":{"hash":"aaaa"}},"tag":["http"]}})",
                     "application/json");
             });
    BoundHttpServer running_ndms(ndms);
    EnvironmentVariableGuard endpoint_override(
        "KEEN_PBR_TEST_NDMS_USER_ENDPOINT",
        "http://127.0.0.1:" + std::to_string(running_ndms.port()) +
            "/rci/show/rc/user");

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    std::string first_outcome;
    std::thread first([&]() {
        first_outcome = server.poll_router_credentials_for_testing();
    });

    bool first_entered = false;
    {
        std::unique_lock lock(read_mutex);
        first_entered = read_cv.wait_for(
            lock, std::chrono::seconds{5}, [&]() { return entered; });
    }
    std::string concurrent_outcome;
    if (first_entered) {
        concurrent_outcome = server.poll_router_credentials_for_testing();
    }
    {
        std::lock_guard lock(read_mutex);
        release = true;
    }
    read_cv.notify_all();
    first.join();
    server.stop();

    REQUIRE(first_entered);
    CHECK(concurrent_outcome == "concurrent");
    CHECK(first_outcome == "unchanged");
}

TEST_CASE("an external router credential change revokes the session cohort") {
    // The revocation machinery already existed; what this pins is the trigger.
    // An inert revocation is the one kind nobody notices, because nothing
    // fails - it just never fires.
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"keenetic",)"
        R"("keenetic_endpoint_mode":"manual",)"
        R"("keenetic_endpoint":"127.0.0.1:80"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    // Stands in for the firmware RCI, which lives on a fixed loopback port a
    // test cannot occupy.
    std::mutex document_mutex;
    std::string document =
        R"({"admin":{"password":{"nt":{"hash":"aaaa"}},"tag":["http"]}})";
    bool serve = true;
    httplib::Server ndms;
    ndms.Get("/rci/show/rc/user",
             [&](const httplib::Request&, httplib::Response& response) {
                 std::lock_guard<std::mutex> lock(document_mutex);
                 if (!serve) {
                     response.status = 503;
                     return;
                 }
                 response.set_content(document, "application/json");
             });
    const int ndms_port = ndms.bind_to_any_port("127.0.0.1");
    REQUIRE(ndms_port > 0);
    std::thread ndms_thread([&ndms]() { ndms.listen_after_bind(); });
    while (!ndms.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    EnvironmentVariableGuard endpoint_override(
        "KEEN_PBR_TEST_NDMS_USER_ENDPOINT",
        "http://127.0.0.1:" + std::to_string(ndms_port) +
            "/rci/show/rc/user");
    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    // Startup already established the baseline before the listener admitted a
    // session. A repeat is unchanged, not a second baseline.
    CHECK(server.poll_router_credentials_for_testing() == "unchanged");

    // The firmware becomes unreachable. That is not evidence of a change, and
    // it must not become the new baseline either.
    {
        std::lock_guard<std::mutex> lock(document_mutex);
        serve = false;
    }
    CHECK(server.poll_router_credentials_for_testing() == "unknown");

    // ...so a password changed while it was unreachable is still seen when it
    // comes back.
    {
        std::lock_guard<std::mutex> lock(document_mutex);
        serve = true;
        document =
            R"({"admin":{"password":{"nt":{"hash":"bbbb"}},"tag":["http"]}})";
    }
    CHECK(server.poll_router_credentials_for_testing() == "changed");
    // ...once. A change already acted on is not a change again.
    CHECK(server.poll_router_credentials_for_testing() == "unchanged");

    server.stop();
    ndms.stop();
    ndms_thread.join();
}

TEST_CASE("the local provider is not watched over RCI") {
    // A local password lives in auth.json, and changing it there already
    // advances the generation. Polling NDMS for it would be watching the
    // wrong file, and would spend an RCI read per request to do it.
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        R"({"enabled":true,"provider":"local","username":"a","password":"b"})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();
    CHECK(server.poll_router_credentials_for_testing() == "not_watched");
    server.stop();
}

TEST_CASE("concurrent local logins cannot multiply the key-stretch cost") {
    // The key stretch costs 475 ms of CPU by design. The login limiter that
    // was supposed to bound it is keyed per source, so 256 tracked sources
    // times three attempts is over three core-seconds per second on a
    // three-core router - a load generator, not a rate limit. Derivations are
    // serialised router-wide; a caller that arrives while one is running is
    // refused rather than queued, because queueing IS the exhaustion.
    AuthTempDir directory;
    const auto auth_path = directory.path / "auth.json";
    write_text(
        auth_path,
        std::string(R"({"enabled":true,"provider":"local",)") +
            R"("username":"admin","password":")" +
            encode_local_password_hash(
                "hunter2", std::string(32U, 0x61),
                kLocalPasswordHashMaximumIterations) +
            R"(","password_format":")" + kLocalPasswordHashFormat +
            R"("})");
    EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", auth_path.string());

    const auto config = auth_api_config();
    ApiServer server(config);
    server.start();

    std::atomic<int> accepted{0};
    std::atomic<int> busy{0};
    std::vector<std::thread> callers;
    for (int index = 0; index < 6; ++index) {
        callers.emplace_back([&config, &accepted, &busy]() {
            httplib::Client client("127.0.0.1", configured_port(config));
            client.set_read_timeout(10, 0);
            const auto login = client.Post(
                "/api/auth/login",
                R"({"username":"admin","password":"hunter2"})",
                "application/json");
            if (login == nullptr) return;
            if (login->status == 200) accepted.fetch_add(1);
            if (login->status == 503) busy.fetch_add(1);
        });
    }
    for (auto& caller : callers) caller.join();
    server.stop();

    // The derivation is deliberately slow here, so six simultaneous callers
    // cannot all have had the lock to themselves. At least one must have been
    // refused outright - under a blocking lock that number is always zero,
    // because nobody is ever refused, they only wait.
    CHECK(accepted.load() >= 1);
    CHECK(busy.load() >= 1);
}

} // namespace keen_pbr3

#endif
