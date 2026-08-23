#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api_context_test_support.hpp"
#include "api/handler_nfqws.hpp"
#include "api/sse_broadcaster.hpp"
#include "crypto/sha256.hpp"
#include "update/component_ipk_store.hpp"
#include "util/nfqws_validator.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
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
    // The path verifies every target against the feed index; what it cannot
    // promise without the store is an exact copy of the installed version.
    CHECK(capability.at("verified_target_ipk").get<bool>());
    CHECK_FALSE(capability.at("exact_opkg_metadata_rollback").get<bool>());
    // The daemon acts on an interrupted journal at startup; what it decided
    // last time (if ever) rides along for the page.
    CHECK(capability.at("boot_recovery").get<bool>());
    CHECK(capability.contains("boot_recovery_last"));
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

namespace {

// A feed index and a fake opkg for the package sequence, so the seam tests
// drive the same verification path production does without a network or a
// package manager.
struct NfqwsPackageFixture {
    std::filesystem::path root;
    std::string served_bytes;
    std::string served_filename;
    std::vector<std::vector<std::string>> commands;
    std::vector<SafeExecTimeouts> deadlines;

    NfqwsPackageFixture() {
        std::string pattern = "/tmp/keen-pbr-nfqws-pkg-XXXXXX";
        REQUIRE(::mkdtemp(&pattern[0]) != nullptr);
        root = pattern;
    }
    ~NfqwsPackageFixture() {
        std::error_code error;
        std::filesystem::remove_all(root, error);
    }

    static std::string digest(const std::string& bytes) {
        Sha256 hasher;
        hasher.update(bytes);
        return hasher.hex_digest();
    }

    std::string store_root() const { return (root / "components").string(); }
    std::string feed_list() const { return (root / "feed-list").string(); }

    void serve(const std::string& version, const std::string& bytes) {
        served_bytes = bytes;
        served_filename = "nfqws2-keenetic_" + version + "_all_entware.ipk";
        std::ofstream feed(feed_list(), std::ios::trunc);
        feed << "Package: nfqws2-keenetic\nVersion: " << version
             << "\nArchitecture: all\nFilename: " << served_filename
             << "\nSize: " << bytes.size() << "\nSHA256sum: " << digest(bytes)
             << "\nDescription: test\n\n";
    }

    // Retain `version` as the store's current slot, the way a finished
    // earlier transaction would have left it.
    void retain_current(const std::string& version, const std::string& bytes) {
        ComponentIpkStore store(store_root(), "nfqws2-keenetic");
        FeedPackageEntry entry;
        entry.package = "nfqws2-keenetic";
        entry.version = version;
        entry.filename = "nfqws2-keenetic_" + version + "_all_entware.ipk";
        entry.size = bytes.size();
        entry.sha256 = digest(bytes);
        store.adopt(IpkSlot::current, bytes, entry);
    }

    // `install_outcome` shapes the opkg install result; every other command
    // behaves like a healthy opkg.
    std::vector<std::filesystem::path> working_directories;
    std::function<ExecCaptureResult(const std::vector<std::string>&,
                                    SafeExecTimeouts,
                                    const std::filesystem::path&)>
    executor(std::function<ExecCaptureResult()> install_outcome) {
        return [this, install_outcome](const std::vector<std::string>& argv,
                                       SafeExecTimeouts timeout,
                                       const std::filesystem::path& cwd) {
            commands.push_back(argv);
            deadlines.push_back(timeout);
            working_directories.push_back(cwd);
            feed_conf_present_at_command.push_back(
                std::filesystem::exists(root / "feed.conf"));
            ExecCaptureResult execution;
            REQUIRE(argv.size() >= 2U);
            if (argv[1] == "update") {
                execution.exit_code = 0;
                execution.stdout_output = "feed updated\n";
                return execution;
            }
            if (argv[1] == "download") {
                // opkg writes into its working directory, which the
                // transaction must have pointed at the store's staging.
                REQUIRE_FALSE(cwd.empty());
                std::ofstream file(cwd / served_filename,
                                   std::ios::binary | std::ios::trunc);
                file << served_bytes;
                execution.exit_code = 0;
                return execution;
            }
            if (argv[1] == "install" && argv.size() >= 3 &&
                argv[2] == "ca-certificates") {
                // The HTTPS prerequisites of a fresh install.
                CHECK(argv == std::vector<std::string>{
                                  "/opt/bin/opkg", "install",
                                  "ca-certificates", "wget-ssl"});
                execution.exit_code = deps_exit;
                execution.stdout_output = "Installing wget-ssl\n";
                return execution;
            }
            if (argv[1] == "remove") {
                // wget-nossl removal is best effort; a router without it
                // answers non-zero and that must not fail the install. The
                // component removal (the install's rollback) also lands
                // here when an action-level test drives it.
                REQUIRE(argv.size() == 3U);
                CHECK((argv[2] == "wget-nossl" ||
                       argv[2] == "nfqws2-keenetic"));
                execution.exit_code = argv[2] == "wget-nossl" ? 1 : 0;
                execution.stdout_output = "Removing " + argv[2] + "\n";
                return execution;
            }
            if (argv[1] == "install") return install_outcome();
            FAIL("unexpected package command " << argv[1]);
            return execution;
        };
    }

    int deps_exit{0};
    // Whether the feed definition existed at the moment of each command -
    // the https-first order is about WHEN the conf exists, not only that it
    // does at the end.
    std::vector<bool> feed_conf_present_at_command;

    std::string feed_conf() const { return (root / "feed.conf").string(); }
    std::string read_feed_conf() const {
        std::ifstream input(root / "feed.conf", std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());
    }
};

constexpr const char* kTestFeedConfContent =
    "src/gz nfqws2-keenetic https://nfqws.github.io/nfqws2-keenetic/all\n";

} // namespace

TEST_CASE("nfqws opkg upgrade uses fixed argv and classifies timeout as unknown") {
    NfqwsPackageFixture fixture;
    fixture.retain_current("1.2.4", "bytes of 1.2.4");
    fixture.serve("1.2.5", "bytes of 1.2.5");
    const auto result = run_nfqws_bounded_opkg_for_testing(
        fixture.executor([] {
            ExecCaptureResult execution;
            execution.exit_code = -1;
            execution.stdout_output = "maintainer script started\n";
            execution.timed_out = true;
            return execution;
        }),
        "1.2.4", fixture.store_root(), fixture.feed_list());

    REQUIRE(fixture.commands.size() == 3U);
    CHECK(fixture.commands[0] ==
          std::vector<std::string>{"/opt/bin/opkg", "update"});
    // opkg writes the download into its working directory, so the child is
    // moved into the store's staging directory with chdir - not with a
    // `sh -c 'cd ...'` wrapper, which on KeeneticOS reaches the NDM shell
    // wrapper and loses every positional parameter.
    CHECK(fixture.commands[1] == std::vector<std::string>{
                                     "/opt/bin/opkg", "download",
                                     "nfqws2-keenetic"});
    REQUIRE(fixture.working_directories.size() == 3U);
    CHECK(fixture.working_directories[0].empty());
    CHECK(fixture.working_directories[1] ==
          std::filesystem::path(fixture.store_root()) / "nfqws2-keenetic" /
              "staging");
    CHECK(fixture.working_directories[2].empty());
    // Installed from the verified file, not from whatever the feed serves
    // by the time opkg looks again.
    CHECK(fixture.commands[2] == std::vector<std::string>{
                                     "/opt/bin/opkg", "install",
                                     fixture.store_root() +
                                         "/nfqws2-keenetic/candidate.ipk"});
    REQUIRE(fixture.deadlines.size() == 3U);
    for (const auto& deadline : fixture.deadlines) {
        CHECK(deadline.timeout == std::chrono::minutes{10});
        CHECK(deadline.kill_grace == std::chrono::seconds{5});
    }
    CHECK(result.upgrade_started);
    CHECK(result.previous_exact);
    CHECK(result.target_version == "1.2.5");
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

TEST_CASE("nfqws opkg upgrade refuses a target the feed index does not vouch for") {
    NfqwsPackageFixture fixture;
    fixture.serve("1.2.5", "bytes of 1.2.5");
    // Same size as the feed promised, other content: the one tampering the
    // size check cannot catch, so this exercises the SHA-256 refusal.
    fixture.served_bytes = "bytes of 1.2.X";
    REQUIRE(fixture.served_bytes.size() == std::string("bytes of 1.2.5").size());
    bool install_ran = false;
    const auto result = run_nfqws_bounded_opkg_for_testing(
        fixture.executor([&] {
            install_ran = true;
            return ExecCaptureResult{};
        }),
        "1.2.4", fixture.store_root(), fixture.feed_list());

    CHECK_FALSE(install_ran);
    CHECK_FALSE(result.upgrade_started);
    CHECK(result.status != 0);
    CHECK(result.output.find("refused") != std::string::npos);
    CHECK(fixture.commands.size() == 2U);
    // No exact copy of 1.2.4 could be retained either: the feed serves
    // only 1.2.5.
    CHECK_FALSE(result.previous_exact);
}

TEST_CASE("nfqws opkg upgrade retains the installed ipk while the feed still serves it") {
    NfqwsPackageFixture fixture;
    fixture.serve("1.2.4", "bytes of 1.2.4");
    bool install_ran = false;
    const auto result = run_nfqws_bounded_opkg_for_testing(
        fixture.executor([&] {
            install_ran = true;
            return ExecCaptureResult{};
        }),
        "1.2.4", fixture.store_root(), fixture.feed_list());

    CHECK_FALSE(install_ran);
    CHECK_FALSE(result.upgrade_started);
    CHECK(result.up_to_date);
    CHECK(result.status == 0);
    CHECK(result.previous_exact);
    ComponentIpkStore store(fixture.store_root(), "nfqws2-keenetic");
    const auto current = store.inspect(IpkSlot::current);
    REQUIRE(current.state == IpkSlotState::usable);
    CHECK(current.retained->version == "1.2.4");
}

TEST_CASE("exact previous package reinstall is proven by opkg naming the version again") {
    NfqwsPackageFixture fixture;
    fixture.retain_current("1.2.4", "bytes of 1.2.4");
    std::string reported_version = "1.2.4";
    std::string output;
    const auto executor = fixture.executor([] {
        ExecCaptureResult execution;
        execution.exit_code = 0;
        execution.stdout_output = "Installing nfqws2-keenetic (1.2.4)\n";
        return execution;
    });

    SUBCASE("success") {
        CHECK(reinstall_exact_previous_nfqws_package_for_testing(
            executor, "1.2.4", [&] { return reported_version; },
            fixture.store_root(), output));
        REQUIRE(fixture.commands.size() == 1U);
        CHECK(fixture.commands[0] == std::vector<std::string>{
                                         "/opt/bin/opkg", "install",
                                         "--force-downgrade",
                                         "--force-reinstall",
                                         fixture.store_root() +
                                             "/nfqws2-keenetic/current.ipk"});
        CHECK(output.find("opkg metadata restored") != std::string::npos);
    }
    SUBCASE("opkg success but the database names another version") {
        reported_version = "1.2.5";
        CHECK_FALSE(reinstall_exact_previous_nfqws_package_for_testing(
            executor, "1.2.4", [&] { return reported_version; },
            fixture.store_root(), output));
        CHECK(output.find("not proven restored") != std::string::npos);
    }
    SUBCASE("the store holds a different version than expected") {
        CHECK_FALSE(reinstall_exact_previous_nfqws_package_for_testing(
            executor, "1.2.3", [&] { return reported_version; },
            fixture.store_root(), output));
        CHECK(fixture.commands.empty());
    }
    SUBCASE("the pre-upgrade version was unknown") {
        CHECK_FALSE(reinstall_exact_previous_nfqws_package_for_testing(
            executor, "", [&] { return reported_version; },
            fixture.store_root(), output));
        CHECK(fixture.commands.empty());
    }
}

TEST_CASE("a fresh install prepares https, writes the feed and installs the verified file") {
    NfqwsPackageFixture fixture;
    fixture.serve("1.2.4", "bytes of 1.2.4");
    bool package_installed = false;
    const auto result = run_nfqws_install_for_testing(
        fixture.executor([&] {
            package_installed = true;
            ExecCaptureResult execution;
            execution.exit_code = 0;
            execution.stdout_output = "Installing nfqws2-keenetic (1.2.4)\n";
            return execution;
        }),
        fixture.store_root(), fixture.feed_list(), fixture.feed_conf());

    CHECK(result.status == 0);
    CHECK(result.install_started);
    CHECK(package_installed);
    CHECK(result.target_version == "1.2.4");
    CHECK(result.feed_conf_written);
    // The feed definition is exactly what the shell installer writes.
    CHECK(fixture.read_feed_conf() == kTestFeedConfContent);
    // Sequence: entware update, https deps, wget-nossl removal (best
    // effort), the transaction's own update, the download in staging, the
    // install of the verified file.
    REQUIRE(fixture.commands.size() == 6U);
    CHECK(fixture.commands[0] ==
          std::vector<std::string>{"/opt/bin/opkg", "update"});
    CHECK(fixture.commands[1][2] == "ca-certificates");
    CHECK(fixture.commands[2][1] == "remove");
    CHECK(fixture.commands[3] ==
          std::vector<std::string>{"/opt/bin/opkg", "update"});
    CHECK(fixture.commands[4][1] == "download");
    CHECK(fixture.commands[5] == std::vector<std::string>{
                                     "/opt/bin/opkg", "install",
                                     fixture.store_root() +
                                         "/nfqws2-keenetic/candidate.ipk"});
    // The verified bytes are staged as the candidate; promotion to the
    // exact retained copy is the handler's step after verification.
    ComponentIpkStore store(fixture.store_root(), "nfqws2-keenetic");
    CHECK(store.inspect(IpkSlot::candidate).retained->version == "1.2.4");
}

TEST_CASE("an existing feed definition with custom content is left alone") {
    NfqwsPackageFixture fixture;
    fixture.serve("1.2.4", "bytes of 1.2.4");
    const std::string mirror =
        "src/gz nfqws2-keenetic https://mirror.example/nfqws\n";
    {
        std::ofstream conf(fixture.feed_conf(), std::ios::binary);
        conf << mirror;
    }
    const auto result = run_nfqws_install_for_testing(
        fixture.executor([] {
            ExecCaptureResult execution;
            execution.exit_code = 0;
            return execution;
        }),
        fixture.store_root(), fixture.feed_list(), fixture.feed_conf());

    CHECK(result.install_started);
    CHECK_FALSE(result.feed_conf_written);
    CHECK(fixture.read_feed_conf() == mirror);
    CHECK(result.output.find("custom content") != std::string::npos);
}

TEST_CASE("a canonical feed definition is rewritten through the https-first order") {
    // An interrupted earlier install leaves the canonical conf with the
    // plain wget still installed, and a present https feed makes the whole
    // `opkg update` fail. The order must therefore be: remove ours, update,
    // deps, write ours back, update.
    NfqwsPackageFixture fixture;
    fixture.serve("1.2.4", "bytes of 1.2.4");
    {
        std::ofstream conf(fixture.feed_conf(), std::ios::binary);
        conf << kTestFeedConfContent;
    }
    const auto result = run_nfqws_install_for_testing(
        fixture.executor([] {
            ExecCaptureResult execution;
            execution.exit_code = 0;
            return execution;
        }),
        fixture.store_root(), fixture.feed_list(), fixture.feed_conf());

    CHECK(result.install_started);
    CHECK(result.feed_conf_written);
    CHECK(fixture.read_feed_conf() == kTestFeedConfContent);
    // The order is the claim: our conf must be ABSENT while the stock
    // update, the https prerequisites and the wget-nossl removal run, and
    // present again from the second update on. A refactor that writes the
    // conf before the prerequisites would break exactly the interrupted-
    // install retry this order exists for.
    REQUIRE(fixture.feed_conf_present_at_command.size() == 6U);
    CHECK_FALSE(fixture.feed_conf_present_at_command[0]);
    CHECK_FALSE(fixture.feed_conf_present_at_command[1]);
    CHECK_FALSE(fixture.feed_conf_present_at_command[2]);
    CHECK(fixture.feed_conf_present_at_command[3]);
    CHECK(fixture.feed_conf_present_at_command[4]);
    CHECK(fixture.feed_conf_present_at_command[5]);
}

TEST_CASE("a prepared-hook refusal stops the install before opkg runs it") {
    NfqwsPackageFixture fixture;
    fixture.serve("1.2.4", "bytes of 1.2.4");
    bool package_installed = false;
    std::string hook_target;
    const auto result = run_nfqws_install_for_testing(
        fixture.executor([&] {
            package_installed = true;
            return ExecCaptureResult{};
        }),
        fixture.store_root(), fixture.feed_list(), fixture.feed_conf(),
        [&](const std::string& target) {
            hook_target = target;
            return false;
        });
    CHECK(hook_target == "1.2.4");
    CHECK_FALSE(result.install_started);
    CHECK_FALSE(package_installed);
    CHECK(result.status != 0);
    CHECK(result.output.find("journal could not record") != std::string::npos);
}

TEST_CASE("failed https prerequisites stop the install before the component is touched") {
    NfqwsPackageFixture fixture;
    fixture.serve("1.2.4", "bytes of 1.2.4");
    fixture.deps_exit = 2;
    bool package_installed = false;
    const auto result = run_nfqws_install_for_testing(
        fixture.executor([&] {
            package_installed = true;
            return ExecCaptureResult{};
        }),
        fixture.store_root(), fixture.feed_list(), fixture.feed_conf());

    CHECK(result.status != 0);
    CHECK_FALSE(result.install_started);
    CHECK_FALSE(package_installed);
    CHECK_FALSE(result.feed_conf_written);
    // Only entware update and the deps attempt ran.
    CHECK(fixture.commands.size() == 2U);
    CHECK(result.output.find("HTTPS prerequisites") != std::string::npos);
}

TEST_CASE("an install target the feed index does not vouch for is refused") {
    NfqwsPackageFixture fixture;
    fixture.serve("1.2.4", "bytes of 1.2.4");
    fixture.served_bytes = "bytes of 1.2.X";
    REQUIRE(fixture.served_bytes.size() ==
            std::string("bytes of 1.2.4").size());
    bool package_installed = false;
    const auto result = run_nfqws_install_for_testing(
        fixture.executor([&] {
            package_installed = true;
            return ExecCaptureResult{};
        }),
        fixture.store_root(), fixture.feed_list(), fixture.feed_conf());

    CHECK(result.status != 0);
    CHECK_FALSE(result.install_started);
    CHECK_FALSE(package_installed);
    CHECK(result.output.find("refused") != std::string::npos);
    ComponentIpkStore store(fixture.store_root(), "nfqws2-keenetic");
    CHECK(store.inspect(IpkSlot::candidate).state == IpkSlotState::absent);
}

TEST_CASE("uncertain opkg termination forbids observation and recovery") {
    NfqwsPackageFixture fixture;
    fixture.serve("1.2.5", "bytes of 1.2.5");
    const auto result = run_nfqws_bounded_opkg_for_testing(
        fixture.executor([] {
            ExecCaptureResult execution;
            execution.exit_code = -1;
            execution.timed_out = true;
            execution.termination_uncertain = true;
            return execution;
        }),
        "1.2.4", fixture.store_root(), fixture.feed_list());

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

    SUBCASE("an exact reinstall of the previous ipk does") {
        CHECK(should_clear_nfqws_upgrade_journal_for_testing(
            /*component_broken=*/true,
            /*package_mutation_started=*/true,
            /*rolled_back=*/true,
            /*termination_uncertain=*/false,
            /*exact_rollback_verified=*/true));
        // But only when the captured files and runtime came back too; the
        // reinstall alone proves the package database, not the component.
        CHECK_FALSE(should_clear_nfqws_upgrade_journal_for_testing(
            /*component_broken=*/true,
            /*package_mutation_started=*/true,
            /*rolled_back=*/false,
            /*termination_uncertain=*/false,
            /*exact_rollback_verified=*/true));
        // And never over an uncertain mutator.
        CHECK_FALSE(should_clear_nfqws_upgrade_journal_for_testing(
            /*component_broken=*/true,
            /*package_mutation_started=*/true,
            /*rolled_back=*/true,
            /*termination_uncertain=*/true,
            /*exact_rollback_verified=*/true));
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

namespace {

class BootRecoveryFakeLease final : public MaintenanceLease {
public:
    std::uint32_t base_generation() const noexcept override { return 1U; }
    std::uint32_t reserve(std::uint32_t expected) override {
        return expected + 1U;
    }
    void verify_held() override {}
};

// Every input and effect of the boot-recovery orchestration, scripted.
struct BootRecoveryFixture {
    ComponentTransactionStatus journal;
    // When set, the journal the orchestration re-reads under the lease -
    // pinning that decisions come from the leased read, not the free glance.
    std::optional<ComponentTransactionStatus> journal_under_lease;
    std::optional<NfqwsBootRecoveryLastAnswer> last_answer;
    bool execute_throws{false};
    bool lease_busy{false};
    bool lease_unsafe{false};
    int journal_reads{0};
    int lease_acquisitions{0};
    IpkSlotInspection current_ipk;
    ComponentCaptureState capture{ComponentCaptureState::usable};
    std::string version{"1.2.5"};
    std::string binary_sha{std::string(64, 'b')};
    NfqwsBootRecoveryStepResult step;
    int execute_calls{0};
    int clear_calls{0};
    int discard_calls{0};
    bool clear_ok{true};
    ComponentBootRecoveryPlan executed_plan;
    std::vector<NfqwsBootRecoveryResult> recorded;

    void abandoned_journal(ComponentTransactionPhase phase,
                           bool exact_previous = true) {
        journal.state = ComponentTransactionState::abandoned;
        ComponentTransactionRecord record;
        record.component = "nfqws2-keenetic";
        record.operation = "upgrade";
        record.phase = phase;
        record.binary_sha256 = std::string(64, 'a');
        record.previous_version = "1.2.4";
        record.target_version = "1.2.5";
        record.exact_previous_ipk = exact_previous;
        journal.record = record;
    }

    void exact_copy_retained() {
        current_ipk.state = IpkSlotState::usable;
        RetainedIpk retained;
        retained.version = "1.2.4";
        retained.sha256 = std::string(64, 'c');
        retained.size = 10;
        retained.filename = "x.ipk";
        current_ipk.retained = retained;
    }

    NfqwsBootRecoveryHooks hooks() {
        NfqwsBootRecoveryHooks wired;
        wired.read_journal = [this] {
            ++journal_reads;
            if (journal_reads > 1 && journal_under_lease) {
                return *journal_under_lease;
            }
            return journal;
        };
        wired.read_last_answer = [this] { return last_answer; };
        wired.acquire_lease =
            [this]() -> std::unique_ptr<MaintenanceLease> {
            ++lease_acquisitions;
            if (lease_busy) {
                throw MaintenanceLockError(MaintenanceLockErrorKind::busy,
                                           "held by S80");
            }
            if (lease_unsafe) {
                throw MaintenanceLockError(
                    MaintenanceLockErrorKind::unsafe_state,
                    "helper left an unrecognized record");
            }
            return std::make_unique<BootRecoveryFakeLease>();
        };
        wired.inspect_current_ipk = [this] { return current_ipk; };
        wired.capture_state = [this] { return capture; };
        wired.installed_version = [this] { return version; };
        wired.installed_binary_sha256 = [this] { return binary_sha; };
        wired.execute_restore = [this](const ComponentBootRecoveryPlan& plan,
                                       const ComponentTransactionRecord&,
                                       std::string& output) {
            ++execute_calls;
            executed_plan = plan;
            if (execute_throws) {
                throw std::runtime_error("service refused to stop");
            }
            output += "restore ran\n";
            return step;
        };
        wired.clear_journal = [this] {
            ++clear_calls;
            return clear_ok;
        };
        wired.discard_candidate = [this] { ++discard_calls; };
        wired.record_result = [this](const NfqwsBootRecoveryResult& result) {
            recorded.push_back(result);
        };
        return wired;
    }
};

} // namespace

TEST_CASE("boot recovery does nothing, and takes no lease, without a journal") {
    BootRecoveryFixture fixture;
    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::nothing_to_do);
    CHECK(fixture.lease_acquisitions == 0);
    CHECK(fixture.execute_calls == 0);
    CHECK(fixture.clear_calls == 0);
    // Nothing happened, so nothing is recorded for the page either.
    CHECK(fixture.recorded.empty());
}

TEST_CASE("a busy maintenance lease is a retry, not a result") {
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::mutating);
    fixture.lease_busy = true;
    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::lease_busy);
    CHECK(fixture.lease_acquisitions == 1);
    CHECK(fixture.execute_calls == 0);
    CHECK(fixture.recorded.empty());
}

TEST_CASE("interrupted before mutation: the journal is cleared and recorded") {
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::started);
    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::recovered);
    CHECK(result.plan == "clear_journal");
    CHECK(result.journal_cleared);
    CHECK(fixture.clear_calls == 1);
    CHECK(fixture.execute_calls == 0);
    REQUIRE(fixture.recorded.size() == 1U);
    CHECK(fixture.recorded.front().journal_cleared);
}

TEST_CASE("exact previous package: reinstall plan runs, candidate dropped, journal cleared") {
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::mutating);
    fixture.exact_copy_retained();
    // The install replaced the package before the crash.
    fixture.version = "1.2.5";
    fixture.step.rolled_back = true;
    fixture.step.package_metadata_restored = true;

    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::recovered);
    CHECK(result.plan == "reinstall_previous");
    CHECK(fixture.execute_calls == 1);
    CHECK(fixture.executed_plan.action ==
          ComponentBootRecoveryAction::reinstall_previous);
    CHECK(fixture.executed_plan.reinstall_version == "1.2.4");
    CHECK(fixture.discard_calls == 1);
    CHECK(fixture.clear_calls == 1);
    CHECK(result.journal_cleared);
    CHECK(result.output.find("restore ran") != std::string::npos);

}

TEST_CASE("a reinstall that only restored files is a failure, not a recovery") {
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::mutating);
    fixture.exact_copy_retained();
    fixture.version = "1.2.5";
    fixture.step.rolled_back = true;
    fixture.step.package_metadata_restored = false;

    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::failed);
    CHECK(fixture.clear_calls == 0);
    CHECK(fixture.discard_calls == 0);
    CHECK_FALSE(result.journal_cleared);
    REQUIRE(fixture.recorded.size() == 1U);
}

TEST_CASE("without an exact copy the files come back but the journal stays") {
    BootRecoveryFixture fixture;
    // The journal never promised an exact copy.
    fixture.abandoned_journal(ComponentTransactionPhase::verifying,
                              /*exact_previous=*/false);
    fixture.version = "1.2.5";
    fixture.step.rolled_back = true;

    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::journal_retained);
    CHECK(result.plan == "restore_files_inexact");
    CHECK(fixture.execute_calls == 1);
    // No exact reinstall happened, so no candidate is stale and the journal
    // must stay: package metadata is still unverified.
    CHECK(fixture.discard_calls == 0);
    CHECK(fixture.clear_calls == 0);
    CHECK_FALSE(result.journal_cleared);
}

TEST_CASE("a manual verdict runs nothing and keeps the journal") {
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::mutating,
                              /*exact_previous=*/false);
    fixture.version = "1.2.5";
    fixture.capture = ComponentCaptureState::absent;

    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::journal_retained);
    CHECK(result.plan == "manual");
    CHECK(fixture.execute_calls == 0);
    CHECK(fixture.clear_calls == 0);
    REQUIRE(fixture.recorded.size() == 1U);
    CHECK(fixture.recorded.front().plan == "manual");
}

TEST_CASE("a journal that survives its own clear is reported as a failure") {
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::verified);
    fixture.clear_ok = false;
    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::failed);
    CHECK_FALSE(result.journal_cleared);
    REQUIRE(fixture.recorded.size() == 1U);
}

TEST_CASE("one journal gets one answer: an already-answered journal is left alone") {
    // The journal from the interruption stayed on disk (journal_retained),
    // the operator repaired the package by hand, the daemon restarted.
    // Re-deriving a plan now would reinstall the old version over the
    // repair; the recorded answer's identity forbids it.
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::mutating);
    fixture.journal.record->started_at = 1787500000;
    fixture.exact_copy_retained();
    fixture.version = "1.2.6";
    NfqwsBootRecoveryLastAnswer answered;
    answered.journal_started_at = 1787500000;
    answered.journal_operation = "upgrade";
    answered.outcome = "journal_retained";
    fixture.last_answer = answered;

    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::nothing_to_do);
    CHECK(result.reason.find("already answered") != std::string::npos);
    CHECK(fixture.lease_acquisitions == 0);
    CHECK(fixture.execute_calls == 0);
    CHECK(fixture.clear_calls == 0);
    // The matching record keeps describing the run that acted.
    CHECK(fixture.recorded.empty());

    // A DIFFERENT journal (a new interruption) is acted on even though an
    // old answer exists.
    fixture.journal.record->started_at = 1787600000;
    fixture.step.rolled_back = true;
    fixture.step.package_metadata_restored = true;
    const auto fresh = run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(fresh.outcome == NfqwsBootRecoveryOutcome::recovered);
    CHECK(fresh.journal_started_at == 1787600000);
    CHECK(fixture.execute_calls == 1);
}

TEST_CASE("the decision comes from the journal re-read under the lease") {
    // Between the free glance and the lease, an operator's repair cleared
    // the journal. Acting on the stale glance would run a rollback against
    // a component nobody asked to touch.
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::mutating);
    fixture.exact_copy_retained();
    fixture.journal_under_lease = ComponentTransactionStatus{};

    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::nothing_to_do);
    CHECK(result.plan == "none");
    CHECK(fixture.execute_calls == 0);
    CHECK(fixture.clear_calls == 0);
    CHECK(fixture.journal_reads >= 2);
}

TEST_CASE("the restore_files plan needs no exact package and discards nothing") {
    // Package provably unchanged (version and digest match the record):
    // only the captured files come back, metadata was never in question.
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::mutating,
                              /*exact_previous=*/false);
    fixture.version = "1.2.4";
    fixture.binary_sha = std::string(64, 'a');
    fixture.step.rolled_back = true;
    fixture.step.package_metadata_restored = false;

    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::recovered);
    CHECK(result.plan == "restore_files");
    CHECK(fixture.execute_calls == 1);
    CHECK(fixture.discard_calls == 0);
    CHECK(fixture.clear_calls == 1);
    CHECK(result.journal_cleared);
}

TEST_CASE("a restore step that throws is a failure with the journal kept") {
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::mutating);
    fixture.exact_copy_retained();
    fixture.version = "1.2.5";
    fixture.execute_throws = true;

    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::failed);
    CHECK(result.output.find("service refused to stop") != std::string::npos);
    CHECK(fixture.clear_calls == 0);
    CHECK(fixture.discard_calls == 0);
    REQUIRE(fixture.recorded.size() == 1U);
}

TEST_CASE("a restored component whose journal cannot be cleared is a failure") {
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::mutating);
    fixture.exact_copy_retained();
    fixture.version = "1.2.5";
    fixture.step.rolled_back = true;
    fixture.step.package_metadata_restored = true;
    fixture.clear_ok = false;

    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::failed);
    CHECK(fixture.execute_calls == 1);
    CHECK(fixture.clear_calls == 1);
    CHECK_FALSE(result.journal_cleared);
}

TEST_CASE("a lease failure that is not busy is final and recorded") {
    BootRecoveryFixture fixture;
    fixture.abandoned_journal(ComponentTransactionPhase::mutating);
    fixture.lease_unsafe = true;
    const auto result =
        run_nfqws_boot_recovery_for_testing(fixture.hooks());
    CHECK(result.outcome == NfqwsBootRecoveryOutcome::failed);
    CHECK(result.output.find("unrecognized record") != std::string::npos);
    CHECK(fixture.execute_calls == 0);
    REQUIRE(fixture.recorded.size() == 1U);
}

TEST_CASE("every boot recovery outcome has a distinct stable name") {
    CHECK(std::string(nfqws_boot_recovery_outcome_name(
              NfqwsBootRecoveryOutcome::nothing_to_do)) == "nothing_to_do");
    CHECK(std::string(nfqws_boot_recovery_outcome_name(
              NfqwsBootRecoveryOutcome::lease_busy)) == "lease_busy");
    CHECK(std::string(nfqws_boot_recovery_outcome_name(
              NfqwsBootRecoveryOutcome::recovered)) == "recovered");
    CHECK(std::string(nfqws_boot_recovery_outcome_name(
              NfqwsBootRecoveryOutcome::journal_retained)) ==
          "journal_retained");
    CHECK(std::string(nfqws_boot_recovery_outcome_name(
              NfqwsBootRecoveryOutcome::failed)) == "failed");
}
} // namespace keen_pbr3

#endif // WITH_API
