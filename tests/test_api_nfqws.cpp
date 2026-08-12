#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api_context_test_support.hpp"
#include "api/handler_nfqws.hpp"
#include "api/sse_broadcaster.hpp"
#include "util/nfqws_validator.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

class NfqwsApiTemporaryFile {
public:
    NfqwsApiTemporaryFile() {
        path = "/tmp/keen-pbr-nfqws-api-" + std::to_string(::getpid()) +
               ".conf";
        std::ofstream output(path, std::ios::trunc);
        REQUIRE(output.good());
        output << "original-live-bytes\n";
    }

    ~NfqwsApiTemporaryFile() {
        std::error_code error;
        std::filesystem::remove(path, error);
    }

    std::string read() const {
        std::ifstream input(path);
        return {std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>()};
    }

    std::string path;
};

} // namespace

TEST_CASE("nfqws apply rejects an invalid candidate before every mutation") {
    const int port = test_support::isolated_api_port(7);
    test_support::EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", test_support::missing_auth_path(port));
    NfqwsApiTemporaryFile live;
    SseBroadcaster broadcaster;
    auto context = test_support::make_minimal_api_context(
        broadcaster, "/tmp/keen-pbr-nfqws-api-context.json");

    std::size_t validation_calls = 0;
    std::size_t provision_calls = 0;
    std::size_t write_calls = 0;
    std::size_t restart_calls = 0;
    NfqwsApplyStrategyTestHooks hooks;
    hooks.installed = [] { return true; };
    hooks.validate = [&](const std::string& name, const std::string& content) {
        ++validation_calls;
        CHECK(name == "candidate");
        CHECK(content.find("--filter-tcp=") != std::string::npos);
        return std::vector<ConfigValidationIssue>{
            {"NFQWS_ARGS/--filter-tcp", "port filter must not be empty"}};
    };
    hooks.provision = [&](const std::string&) {
        ++provision_calls;
        return NfqwsStrategyAssetSync{};
    };
    hooks.write_active = [&](const std::string& content) {
        ++write_calls;
        std::ofstream output(live.path, std::ios::trunc);
        output << content;
        return NfqwsFileWriteResult{};
    };
    hooks.restart = [&](int& status) {
        ++restart_calls;
        status = 0;
        return std::string("restarted\n");
    };

    ApiConfig config;
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_nfqws_handler_for_test(server, context, std::move(hooks));
    server.start();
    httplib::Client client("127.0.0.1", port);
    const auto request = nlohmann::json{
        {"action", "apply_strategy"},
        {"name", "candidate"},
        {"content", "NFQWS_ARGS=\"--filter-tcp= --lua-desync=fake\"\n"},
    };
    const auto response =
        client.Post("/api/nfqws", request.dump(), "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 400);
    const auto payload = nlohmann::json::parse(response->body);
    CHECK(payload.at("saved") == false);
    CHECK(payload.at("applied") == false);
    REQUIRE(payload.at("validation_errors").size() == 1U);
    CHECK(payload.at("validation_errors")[0].at("path") ==
          "NFQWS_ARGS/--filter-tcp");
    CHECK(validation_calls == 1U);
    CHECK(provision_calls == 0U);
    CHECK(write_calls == 0U);
    CHECK(restart_calls == 0U);
    CHECK(live.read() == "original-live-bytes\n");
}

TEST_CASE("nfqws apply rejects unsafe writable before provision write or restart") {
    // The previous case has already stopped its server, so reusing slot 7 is
    // safe and stays within the helper's supported 0..7 range.
    const int port = test_support::isolated_api_port(7);
    test_support::EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", test_support::missing_auth_path(port));
    NfqwsApiTemporaryFile live;
    SseBroadcaster broadcaster;
    auto context = test_support::make_minimal_api_context(
        broadcaster, "/tmp/keen-pbr-nfqws-api-writable-context.json");

    std::size_t validation_calls = 0;
    std::size_t provision_calls = 0;
    std::size_t write_calls = 0;
    std::size_t restart_calls = 0;
    NfqwsApplyStrategyTestHooks hooks;
    hooks.installed = [] { return true; };
    hooks.validate = [&](const std::string&, const std::string& content) {
        ++validation_calls;
        return validate_nfqws_candidate(content);
    };
    hooks.provision = [&](const std::string&) {
        ++provision_calls;
        return NfqwsStrategyAssetSync{};
    };
    hooks.write_active = [&](const std::string&) {
        ++write_calls;
        return NfqwsFileWriteResult{};
    };
    hooks.restart = [&](int& status) {
        ++restart_calls;
        status = 0;
        return std::string("restarted\n");
    };

    ApiConfig config;
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_nfqws_handler_for_test(server, context, std::move(hooks));
    server.start();
    httplib::Client client("127.0.0.1", port);
    for (const auto& base_args : {
             std::string("--writable=/tmp/attacker"),
             std::string("--writable=/var/run/keen-pbr-nfqws ") +
                 "--writable=/var/run/keen-pbr-nfqws",
         }) {
        const auto request = nlohmann::json{
            {"action", "apply_strategy"},
            {"name", "candidate"},
            {"content",
             "NFQWS_BASE_ARGS=\"" + base_args + "\"\n"
             "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n"},
        };
        const auto response =
            client.Post("/api/nfqws", request.dump(), "application/json");
        REQUIRE(response != nullptr);
        CHECK(response->status == 400);
    }
    server.stop();

    CHECK(validation_calls == 2U);
    CHECK(provision_calls == 0U);
    CHECK(write_calls == 0U);
    CHECK(restart_calls == 0U);
    CHECK(live.read() == "original-live-bytes\n");
}

TEST_CASE("successful nfqws apply requests the coalesced PPE firewall reconcile") {
    const int port = test_support::isolated_api_port(7);
    test_support::EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", test_support::missing_auth_path(port));
    SseBroadcaster broadcaster;
    auto context = test_support::make_minimal_api_context(
        broadcaster, "/tmp/keen-pbr-nfqws-api-ppe-context.json");

    std::size_t refresh_requests = 0;
    context.request_netfilter_runtime_refresh_fn = [&]() {
        ++refresh_requests;
        return true;
    };
    NfqwsApplyStrategyTestHooks hooks;
    hooks.installed = [] { return true; };
    hooks.validate = [](const std::string&, const std::string&) {
        return std::vector<ConfigValidationIssue>{};
    };
    hooks.provision = [](const std::string&) {
        return NfqwsStrategyAssetSync{};
    };
    hooks.write_active = [](const std::string&) {
        return NfqwsFileWriteResult{};
    };
    hooks.restart = [](int& status) {
        status = 0;
        return std::string("restarted\n");
    };

    ApiConfig config;
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_nfqws_handler_for_test(server, context, std::move(hooks));
    server.start();
    httplib::Client client("127.0.0.1", port);
    const auto response = client.Post(
        "/api/nfqws",
        nlohmann::json{
            {"action", "apply_strategy"},
            {"name", "candidate"},
            {"content",
             "NFQWS_ARGS=\"--filter-tcp=443 --lua-desync=fake\"\n"},
        }
            .dump(),
        "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    REQUIRE(response->status == 200);
    const auto payload = nlohmann::json::parse(response->body);
    CHECK(payload.at("ok") == true);
    CHECK(payload.at("firewall_reconcile_pending") == true);
    CHECK(refresh_requests == 1U);
}

TEST_CASE("nfqws upgrade is gated before every mutation without exact rollback") {
    const int port = test_support::isolated_api_port(7);
    test_support::EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", test_support::missing_auth_path(port));
    SseBroadcaster broadcaster;
    auto context = test_support::make_minimal_api_context(
        broadcaster, "/tmp/keen-pbr-nfqws-api-lease-context.json");

    std::vector<std::string> operations;
    context.maintenance_lease_factory_fn =
        [&operations](std::string operation)
            -> std::unique_ptr<MaintenanceLease> {
        operations.push_back(operation);
        throw MaintenanceLockError(
            MaintenanceLockErrorKind::busy,
            "another keen-pbr update or lifecycle operation is active",
            75);
    };

    ApiConfig config;
    config.listen = "127.0.0.1:" + std::to_string(port);
    ApiServer server(config);
    register_nfqws_handler_for_test(server, context, {});
    server.start();
    httplib::Client client("127.0.0.1", port);
    const auto status_response = client.Get("/api/nfqws");
    const auto response = client.Post(
        "/api/nfqws",
        nlohmann::json{{"action", "upgrade"}}.dump(),
        "application/json");
    server.stop();

    REQUIRE(status_response != nullptr);
    REQUIRE(status_response->status == 200);
    const auto status_payload =
        nlohmann::json::parse(status_response->body);
    CHECK_FALSE(status_payload.at("upgrade_capability")
                    .at("available")
                    .get<bool>());
    CHECK_FALSE(status_payload.at("restore_capability")
                    .at("exact_package_state")
                    .get<bool>());

    REQUIRE(response != nullptr);
    CHECK(response->status == 409);
    const auto payload = nlohmann::json::parse(response->body);
    CHECK(payload.at("error") == "nfqws_upgrade_unavailable");
    const auto& capability = payload.at("upgrade_capability");
    CHECK_FALSE(capability.at("available").get<bool>());
    CHECK_FALSE(capability.at("exact_previous_ipk").get<bool>());
    CHECK_FALSE(capability.at("verified_target_ipk").get<bool>());
    CHECK_FALSE(capability.at("exact_opkg_metadata_rollback").get<bool>());
    CHECK_FALSE(capability.at("boot_recovery").get<bool>());
    // Most important assertion: the capability gate is before even the lease.
    // Therefore backup, capture, journal and opkg are unreachable as well.
    CHECK(operations.empty());
}

} // namespace keen_pbr3

#endif // WITH_API
