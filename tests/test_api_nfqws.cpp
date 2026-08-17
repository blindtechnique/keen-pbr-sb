#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api_context_test_support.hpp"
#include "api/handler_nfqws.hpp"
#include "api/sse_broadcaster.hpp"
#include "util/nfqws_validator.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>
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

TEST_CASE("nfqws guarded upgrade acquires the lease before every mutation") {
    const int port = test_support::isolated_api_port(7);
    test_support::EnvironmentVariableGuard auth_file(
        "KEEN_PBR_AUTH_FILE", test_support::missing_auth_path(port));
    SseBroadcaster broadcaster;
    auto context = test_support::make_minimal_api_context(
        broadcaster, "/tmp/keen-pbr-nfqws-api-lease-context.json");

    std::vector<std::string> operations;
    std::size_t refresh_requests = 0;
    context.request_netfilter_runtime_refresh_fn = [&]() {
        ++refresh_requests;
        return true;
    };
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
    const auto& capability = status_payload.at("upgrade_capability");
    CHECK(capability.at("available").get<bool>());
    CHECK(capability.at("mode") == "guarded_opkg");
    CHECK_FALSE(capability.at("exact_previous_ipk").get<bool>());
    CHECK_FALSE(capability.at("verified_target_ipk").get<bool>());
    CHECK_FALSE(capability.at("exact_opkg_metadata_rollback").get<bool>());
    CHECK_FALSE(capability.at("boot_recovery").get<bool>());
    CHECK_FALSE(capability.at("limitation").get<std::string>().empty());
    CHECK_FALSE(status_payload.at("restore_capability")
                    .at("exact_package_state")
                    .get<bool>());

    REQUIRE(response != nullptr);
    CHECK(response->status == 409);
    const auto payload = nlohmann::json::parse(response->body);
    CHECK(payload.at("error").get<std::string>().find("active") !=
          std::string::npos);
    // The held lease refuses before backup, journal, opkg and the mutation-side
    // netfilter guard. The named operation is retained for lock diagnostics.
    REQUIRE(operations.size() == 1U);
    CHECK(operations.front() == "nfqws-upgrade");
    CHECK(refresh_requests == 0U);
}

TEST_CASE("post-opkg footprint faults require captured-file recovery") {
    PackageFootprint before;
    before.files.push_back(PackageFileState{
        "/opt/usr/bin/nfqws2", true, false, std::string(64U, 'a')});
    before.present_count = 1U;

    SUBCASE("the observer throws after package mutation") {
        const auto assessment =
            assess_nfqws_post_upgrade_footprint_for_testing(
                before, []() -> PackageFootprint {
                    throw ApiError(
                        "cannot establish the post-opkg footprint", 409);
                });
        CHECK(assessment.recovery_required);
        CHECK(assessment.binary_outcome ==
              PackageBinaryOutcome::indeterminate);
        CHECK(assessment.error.find("post-opkg footprint") !=
              std::string::npos);
    }

    SUBCASE("the observer returns bounded but incomplete evidence") {
        const auto assessment =
            assess_nfqws_post_upgrade_footprint_for_testing(
                before, [] {
                    PackageFootprint incomplete;
                    incomplete.complete = false;
                    incomplete.errors.emplace_back(
                        "/opt/usr/bin/nfqws2");
                    return incomplete;
                });
        CHECK(assessment.recovery_required);
        CHECK(assessment.binary_outcome ==
              PackageBinaryOutcome::indeterminate);
        CHECK(assessment.error ==
              "post-upgrade package footprint is incomplete");
    }
}

TEST_CASE("nfqws opkg upgrade uses fixed argv and classifies timeout as unknown") {
    std::vector<std::vector<std::string>> commands;
    std::vector<SafeExecTimeouts> deadlines;
    std::size_t call = 0;
    const auto result = run_nfqws_bounded_opkg_for_testing(
        [&](const std::vector<std::string>& argv,
            SafeExecTimeouts timeout) {
            commands.push_back(argv);
            deadlines.push_back(timeout);
            ExecCaptureResult execution;
            if (call++ == 0U) {
                execution.exit_code = 0;
                execution.stdout_output = "feed updated\n";
                return execution;
            }
            execution.exit_code = -1;
            execution.stdout_output = "maintainer script started\n";
            execution.timed_out = true;
            return execution;
        });

    REQUIRE(commands.size() == 2U);
    CHECK(commands[0] ==
          std::vector<std::string>{"/opt/bin/opkg", "update"});
    CHECK(commands[1] == std::vector<std::string>{
                              "/opt/bin/opkg",
                              "upgrade",
                              "nfqws2-keenetic"});
    REQUIRE(deadlines.size() == 2U);
    CHECK(deadlines[0].timeout == std::chrono::minutes{10});
    CHECK(deadlines[0].kill_grace == std::chrono::seconds{5});
    CHECK(deadlines[1].timeout == std::chrono::minutes{10});
    CHECK(result.upgrade_started);
    CHECK(result.timed_out);
    CHECK_FALSE(result.termination_uncertain);
    CHECK(result.status != 0);
    CHECK(result.output.find("outcome is unknown") != std::string::npos);

    std::size_t recovery_calls = 0;
    const auto guarded = guard_nfqws_post_mutation_for_testing(
        [&] { return result.status != 0 || result.timed_out; },
        [&] {
            ++recovery_calls;
            return true;
        });
    CHECK(guarded.operation_completed);
    CHECK(guarded.component_broken);
    CHECK(guarded.recovery_attempted);
    CHECK(guarded.rolled_back);
    CHECK(recovery_calls == 1U);
}

TEST_CASE("uncertain opkg termination forbids observation and recovery") {
    std::size_t call = 0;
    const auto result = run_nfqws_bounded_opkg_for_testing(
        [&](const std::vector<std::string>&,
            SafeExecTimeouts) {
            ExecCaptureResult execution;
            if (call++ == 0U) {
                execution.exit_code = 0;
                return execution;
            }
            execution.exit_code = -1;
            execution.timed_out = true;
            execution.termination_uncertain = true;
            return execution;
        });

    REQUIRE(result.upgrade_started);
    CHECK(result.timed_out);
    CHECK(result.termination_uncertain);
    CHECK(result.status != 0);
    CHECK(result.output.find("could not be proven fully terminated") !=
          std::string::npos);

    std::size_t recovery_calls = 0;
    const auto guarded = guard_nfqws_post_mutation_for_testing(
        [&] { return true; },
        [&] {
            ++recovery_calls;
            return true;
        },
        /*recovery_allowed=*/false);
    CHECK(guarded.operation_completed);
    CHECK(guarded.component_broken);
    CHECK_FALSE(guarded.recovery_attempted);
    CHECK_FALSE(guarded.rolled_back);
    CHECK(recovery_calls == 0U);
}

TEST_CASE("nfqws journal remains degraded after file-only package recovery") {
    SUBCASE("a normal verified upgrade may clear its transaction") {
        CHECK(should_clear_nfqws_upgrade_journal_for_testing(
            /*component_broken=*/false,
            /*package_mutation_started=*/true,
            /*rolled_back=*/false,
            /*termination_uncertain=*/false));
    }

    SUBCASE("a quiesced feed update failure did not mutate the package") {
        CHECK(should_clear_nfqws_upgrade_journal_for_testing(
            /*component_broken=*/false,
            /*package_mutation_started=*/false,
            /*rolled_back=*/false,
            /*termination_uncertain=*/false));
    }

    SUBCASE("captured files do not roll back opkg metadata") {
        CHECK_FALSE(should_clear_nfqws_upgrade_journal_for_testing(
            /*component_broken=*/true,
            /*package_mutation_started=*/true,
            /*rolled_back=*/true,
            /*termination_uncertain=*/false));
    }

    SUBCASE("an uncertain live mutator can never authorize finalization") {
        CHECK_FALSE(should_clear_nfqws_upgrade_journal_for_testing(
            /*component_broken=*/true,
            /*package_mutation_started=*/true,
            /*rolled_back=*/false,
            /*termination_uncertain=*/true));
    }

    CHECK(nfqws_package_metadata_verified_for_testing(
        /*transaction_present=*/false));
    CHECK_FALSE(nfqws_package_metadata_verified_for_testing(
        /*transaction_present=*/true));
}

TEST_CASE("explicit captured-file restore never claims exact package state") {
    for (const bool files_restored : {false, true}) {
        CAPTURE(files_restored);
        const auto finalization =
            finalize_nfqws_captured_file_restore_for_testing(files_restored);
        CHECK_FALSE(finalization.ok);
        CHECK_FALSE(finalization.clear_journal);
        CHECK_FALSE(finalization.package_metadata_verified);
        CHECK(finalization.terminal_state ==
              (files_restored ? "metadata_unverified" : "incomplete"));
    }
}

TEST_CASE("nfqws optimistic status is invalidated by a none-to-none mutation") {
    CHECK(nfqws_optimistic_publish_survives_mutation_for_testing(
        /*mutation_between_reads=*/false));
    CHECK_FALSE(nfqws_optimistic_publish_survives_mutation_for_testing(
        /*mutation_between_reads=*/true));
}

TEST_CASE("every post-opkg exception enters the captured-file recovery funnel") {
    for (const auto& stage : {
             std::string("footprint observation"),
             std::string("config observation"),
             std::string("runtime observation"),
             std::string("outcome description"),
         }) {
        CAPTURE(stage);
        bool opkg_completed = false;
        std::size_t recovery_calls = 0;
        const auto guarded = guard_nfqws_post_mutation_for_testing(
            [&]() -> bool {
                opkg_completed = true;
                throw std::runtime_error("fault at " + stage);
            },
            [&] {
                ++recovery_calls;
                return true;
            });

        CHECK(opkg_completed);
        CHECK_FALSE(guarded.operation_completed);
        CHECK(guarded.component_broken);
        CHECK(guarded.recovery_attempted);
        CHECK(guarded.rolled_back);
        CHECK(guarded.operation_error.find(stage) != std::string::npos);
        CHECK(guarded.recovery_error.empty());
        CHECK(recovery_calls == 1U);
    }
}

TEST_CASE("uncertain post-opkg recovery retains a broken result") {
    const auto guarded = guard_nfqws_post_mutation_for_testing(
        []() -> bool {
            throw std::runtime_error("verification failed");
        },
        []() -> bool {
            throw std::runtime_error("restore verification failed");
        });

    CHECK(guarded.component_broken);
    CHECK(guarded.recovery_attempted);
    CHECK_FALSE(guarded.rolled_back);
    CHECK(guarded.operation_error == "verification failed");
    CHECK(guarded.recovery_error == "restore verification failed");
}

} // namespace keen_pbr3

#endif // WITH_API
