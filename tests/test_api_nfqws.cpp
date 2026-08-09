#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api_context_test_support.hpp"
#include "api/handler_nfqws.hpp"
#include "api/sse_broadcaster.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
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

} // namespace keen_pbr3

#endif // WITH_API
