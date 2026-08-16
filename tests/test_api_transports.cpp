#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>
#include <unistd.h>

#include "../src/api/handler_config.hpp"
#include "../src/api/handler_transports.hpp"
#include "../src/api/server.hpp"
#include "../src/api/sse_broadcaster.hpp"
#include "../src/backup/recovery_coordinator.hpp"
#include "../src/backup/restore_journal.hpp"
#include "../src/config/config_writer.hpp"
#include "../src/crypto/sha256.hpp"
#include "../src/util/display_name.hpp"

namespace keen_pbr3 {

namespace {

struct TransportMaintenanceTestState {
    std::size_t verify_calls = 0U;
    std::optional<std::size_t> fail_from_verify_call;
};

class TransportTestMaintenanceLease final
    : public MaintenanceLease {
public:
    TransportTestMaintenanceLease()
        : TransportTestMaintenanceLease(
              std::make_shared<TransportMaintenanceTestState>()) {}

    explicit TransportTestMaintenanceLease(
        std::shared_ptr<TransportMaintenanceTestState> state)
        : state_(std::move(state)) {}

    std::uint32_t base_generation()
        const noexcept override {
        return 1U;
    }

    std::uint32_t reserve(
        std::uint32_t expected_generation) override {
        return expected_generation + 1U;
    }

    void verify_held() override {
        ++state_->verify_calls;
        if (state_->fail_from_verify_call.has_value() &&
            state_->verify_calls >= *state_->fail_from_verify_call) {
            throw MaintenanceLockError(
                MaintenanceLockErrorKind::guardian_died,
                "injected delegated lifecycle owner death",
                1);
        }
    }

private:
    std::shared_ptr<TransportMaintenanceTestState> state_;
};

ApiContext make_transports_test_context(SseBroadcaster& broadcaster,
                                         const std::string& config_path,
                                         std::shared_ptr<TransportMaintenanceTestState>
                                             maintenance_state = {}) {
    if (!maintenance_state) {
        maintenance_state =
            std::make_shared<TransportMaintenanceTestState>();
    }
    ApiContext context{
        config_path,
        broadcaster,
        []() { return Config{}; },
        []() { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> { return std::nullopt; },
        []() {},
        [](const Config&) {},
        []() { return ServiceHealthState{}; },
        []() { return RoutingHealthReport{}; },
        []() { return api::RuntimeOutboundsResponse{}; },
        []() { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) { return std::map<std::string, api::ListRefreshStateValue>{}; },
        [](const std::string&) { return TestRoutingResult{}; },
        []() {},
        []() {},
        [](Config, std::string) { return ConfigApplyResult{}; },
        []() {},
        []() {},
        []() {},
        [](std::optional<std::string>) { return ListRefreshOperationResult{}; },
    };
    context.maintenance_lease_factory_fn =
        [maintenance_state](std::string)
            -> std::unique_ptr<MaintenanceLease> {
        return std::make_unique<
            TransportTestMaintenanceLease>(maintenance_state);
    };
    return context;
}

void write_transport_test_text(
    const std::filesystem::path& path,
    const std::string& content) {
    std::filesystem::create_directories(
        path.parent_path());
    std::ofstream output(
        path,
        std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output.write(
        content.data(),
        static_cast<std::streamsize>(content.size()));
    REQUIRE(output);
}

std::string read_transport_test_text(
    const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>(),
    };
}

std::string valid_transport_core_config(
    const std::string& listen) {
    return nlohmann::json{
        {"api",
         {
             {"enabled", true},
             {"listen", listen},
         }},
        {"outbounds",
         nlohmann::json::array({
             {
                 {"type", "table"},
                 {"tag", "wan"},
                 {"table", 254},
             },
         })},
        {"dns",
         {
             {"system_resolver",
              {
                  {"address", "127.0.0.1"},
              }},
             {"servers",
              nlohmann::json::array({
                  {
                      {"tag", "default_dns"},
                      {"address", "127.0.0.1"},
                  },
              })},
             {"fallback",
              nlohmann::json::array(
                  {"default_dns"})},
         }},
        {"route", {{"rules", nlohmann::json::array()}}},
    }
        .dump(2) +
        "\n";
}

std::string transport_mode_from_file(
    const std::filesystem::path& path) {
    return nlohmann::json::parse(
               read_transport_test_text(path))
        .value(
            "sing_box_process_mode",
            std::string("isolated"));
}

} // namespace

TEST_CASE("transports handler proxies authenticated companion response") {
    constexpr int api_port = 18221;
    const auto directory = std::filesystem::temp_directory_path() /
                           "keen-pbr-transport-handler-test";
    std::filesystem::create_directories(directory);
    const auto config_path = (directory / "config.json").string();

    httplib::Server companion;
    companion.Get("/v1/transports", [](const httplib::Request& request,
                                       httplib::Response& response) {
        if (request.get_header_value("Authorization") != "Bearer test-secret") {
            response.status = 401;
            return;
        }
        response.set_content(
            nlohmann::json::array({
                {{"tag", "reality"},
                 {"display_name", std::string(80, 'A')},
                 {"type", "sing-box-vless-reality"},
                 {"interface", "tun-reality"},
                 {"state", "up"},
                 {"updated_at", "2026-07-17T18:00:00Z"},
                 {"desired_up", true},
                 {"path",
                  {{"wire_transport", "tcp"},
                   {"framing", "raw"},
                   {"confidence", "derived"}}}},
            }).dump(),
            "application/json");
    });
    companion.Post("/v1/transports/reality/up", [](const httplib::Request& request,
                                                    httplib::Response& response) {
        if (request.get_header_value("Authorization") != "Bearer test-secret") {
            response.status = 401;
            return;
        }
        response.status = 202;
        response.set_content(
            nlohmann::json{{"status", "accepted"},
                           {"at", "2026-07-17T18:00:01Z"}}.dump(),
            "application/json");
    });
    companion.Get("/v1/config/transports", [](const httplib::Request& request,
                                              httplib::Response& response) {
        if (request.get_header_value("Authorization") != "Bearer test-secret") {
            response.status = 401;
            return;
        }
        response.set_content(
            nlohmann::json::array({
                {{"tag", "native_one"},
                  {"display_name", "Домашний туннель"},
                  {"type", "native"},
                  {"interface", "nwg1"},
                  {"link_fingerprint", std::string(64U, 'a')}},
            }).dump(),
            "application/json");
    });
    companion.Post("/v1/config/transports", [](const httplib::Request& request,
                                                httplib::Response& response) {
        if (request.get_header_value("Authorization") != "Bearer test-secret") {
            response.status = 401;
            return;
        }
        const auto body = nlohmann::json::parse(request.body);
        if (body.value("tag", "") != "native_two") {
            response.status = 400;
            return;
        }
        response.status = 201;
        response.set_content(
            nlohmann::json{{"status", "created"}, {"tag", "native_two"}}.dump(),
            "application/json");
    });
    const int companion_port = companion.bind_to_any_port("127.0.0.1");
    REQUIRE(companion_port > 0);
    {
        std::ofstream config(directory / "transports.json");
        config << nlohmann::json{
            {"listen", "127.0.0.1:" + std::to_string(companion_port)},
            {"api_key", "test-secret"},
        };
    }
    std::thread companion_thread([&companion]() {
        companion.listen_after_bind();
    });
    while (!companion.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    SseBroadcaster broadcaster;
    ApiConfig api_config;
    api_config.listen = "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    auto context = make_transports_test_context(broadcaster, config_path);
    std::string traffic_target_source;
    std::vector<std::string> traffic_targets;
    context.replace_interface_traffic_targets_fn =
        [&](std::string source, std::vector<std::string> interfaces) {
            traffic_target_source = std::move(source);
            traffic_targets = std::move(interfaces);
        };
    register_transports_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto response = client.Get("/api/transports");
    const auto action_response = client.Post(
        "/api/transports",
        nlohmann::json{{"tag", "reality"}, {"action", "up"}}.dump(),
        "application/json");
    const auto invalid_action_response = client.Post(
        "/api/transports",
        nlohmann::json{{"tag", "../escape"}, {"action", "up"}}.dump(),
        "application/json");
    const auto config_response = client.Get("/api/transports/config");
    const auto create_response = client.Post(
        "/api/transports/config",
        nlohmann::json{
            {"operation", "create"},
            {"transport",
             {{"tag", "native_two"},
              {"type", "native"},
              {"interface", "nwg2"}}},
        }.dump(),
        "application/json");
    std::string overlong_display_name;
    for (std::size_t index = 0; index < 81; ++index) {
        overlong_display_name += "🚀";
    }
    const auto invalid_alias_response = client.Post(
        "/api/transports/config",
        nlohmann::json{
            {"operation", "create"},
            {"transport",
             {{"tag", "native_two"},
              {"display_name", overlong_display_name},
              {"type", "native"},
              {"interface", "nwg2"}}},
        }.dump(),
        "application/json");

    server.stop();
    companion.stop();
    companion_thread.join();
    std::filesystem::remove_all(directory);

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    REQUIRE(body.size() == 1);
    CHECK(body[0]["tag"] == "reality");
    CHECK(body[0]["interface"] == "tun-reality");
    CHECK(traffic_target_source == "managed-transports");
    CHECK(traffic_targets == std::vector<std::string>{"tun-reality"});
    REQUIRE(action_response != nullptr);
    CHECK(action_response->status == 200);
    const auto action_body = nlohmann::json::parse(action_response->body);
    CHECK(action_body["status"] == "accepted");
    REQUIRE(invalid_action_response != nullptr);
    CHECK(invalid_action_response->status == 400);
    REQUIRE(config_response != nullptr);
    CHECK(config_response->status == 200);
    CHECK(nlohmann::json::parse(config_response->body)[0]["tag"] == "native_one");
    CHECK(nlohmann::json::parse(config_response->body)[0]["display_name"] ==
          "Домашний туннель");
    CHECK_FALSE(nlohmann::json::parse(config_response->body)[0].contains(
        "link_fingerprint"));
    REQUIRE(create_response != nullptr);
    CHECK(create_response->status == 200);
    CHECK(nlohmann::json::parse(create_response->body)["status"] == "created");
    REQUIRE(invalid_alias_response != nullptr);
    CHECK(invalid_alias_response->status == 400);
}

TEST_CASE(
    "sing-box process mode switch restarts the companion and verifies the active mode") {
    constexpr int api_port = 18224;
    const auto directory =
        std::filesystem::temp_directory_path() /
        ("keen-pbr-transport-mode-switch-" +
         std::to_string(::getpid()));
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    const auto config_path = directory / "config.json";
    const auto transports_path =
        directory / "transports.json";
    write_transport_test_text(config_path, "{}\n");

    httplib::Server companion;
    const int companion_port =
        companion.bind_to_any_port("127.0.0.1");
    REQUIRE(companion_port > 0);
    const auto initial_config =
        nlohmann::json{
            {"listen",
             "127.0.0.1:" +
                 std::to_string(companion_port)},
            {"api_key", "test-secret"},
            {"sing_box_process_mode", "isolated"},
            {"transports", nlohmann::json::array()},
        }
            .dump(2) +
        "\n";
    write_transport_test_text(
        transports_path, initial_config);

    std::mutex runtime_mutex;
    std::string running_mode = "isolated";
    bool runtime_ready = true;
    std::string locally_unready_mode;
    bool fail_next_restart = false;
    const auto require_auth =
        [](const httplib::Request& request,
           httplib::Response& response) {
            if (request.get_header_value(
                    "Authorization") !=
                "Bearer test-secret") {
                response.status = 401;
                return false;
            }
            return true;
        };
    companion.Get(
        "/healthz",
        [&](const httplib::Request&,
            httplib::Response& response) {
            const auto data =
                read_transport_test_text(
                    transports_path);
            response.set_content(
                nlohmann::json{
                    {"status", "ok"},
                    {"config_revision",
                     Sha256::hex(data)},
                }
                    .dump(),
                "application/json");
        });
    companion.Get(
        "/v1/config/settings",
        [&](const httplib::Request& request,
            httplib::Response& response) {
            if (!require_auth(request, response)) {
                return;
            }
            const auto configured =
                transport_mode_from_file(
                    transports_path);
            std::lock_guard<std::mutex> lock(
                runtime_mutex);
            response.set_content(
                nlohmann::json{
                    {"sing_box_process_mode",
                     configured},
                    {"running_sing_box_process_mode",
                     running_mode},
                    {"restart_required",
                     configured != running_mode},
                    {"runtime_ready",
                     runtime_ready},
                }
                    .dump(),
                "application/json");
        });
    companion.Put(
        "/v1/config/settings",
        [&](const httplib::Request& request,
            httplib::Response& response) {
            if (!require_auth(request, response)) {
                return;
            }
            const auto body =
                nlohmann::json::parse(request.body);
            const auto mode = body.value(
                "sing_box_process_mode",
                std::string{});
            if (mode != "isolated" &&
                mode != "shared") {
                response.status = 400;
                return;
            }
            auto config = nlohmann::json::parse(
                read_transport_test_text(
                    transports_path));
            config["sing_box_process_mode"] = mode;
            write_transport_test_text(
                transports_path,
                config.dump(2) + "\n");
            std::lock_guard<std::mutex> lock(
                runtime_mutex);
            response.set_content(
                nlohmann::json{
                    {"sing_box_process_mode", mode},
                    {"running_sing_box_process_mode",
                     running_mode},
                    {"restart_required",
                     mode != running_mode},
                    {"runtime_ready",
                     runtime_ready},
                }
                    .dump(),
                "application/json");
        });
    std::thread companion_thread([&companion]() {
        companion.listen_after_bind();
    });
    while (!companion.is_running()) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(10));
    }

    SseBroadcaster broadcaster;
    const auto maintenance_state =
        std::make_shared<TransportMaintenanceTestState>();
    auto context =
        make_transports_test_context(
            broadcaster,
            config_path.string(),
            maintenance_state);
    context.transport_runtime_ready_wait_attempts = 3U;
    context.transport_runtime_ready_wait_interval_ms = 1U;
    int restarts = 0;
    context.restart_restore_service_fn =
        [&](const std::string& script) {
            CHECK(
                script ==
                "/opt/etc/init.d/S79transport-manager");
            ++restarts;
            std::lock_guard<std::mutex> lock(
                runtime_mutex);
            if (fail_next_restart) {
                fail_next_restart = false;
                return 1;
            }
            running_mode =
                transport_mode_from_file(
                    transports_path);
            runtime_ready =
                running_mode != locally_unready_mode;
            return 0;
        };

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" +
        std::to_string(api_port);
    ApiServer server(api_config);
    register_transports_handler(
        server, context);
    server.start();

    httplib::Client client(
        "127.0.0.1", api_port);
    const auto before =
        client.Get("/api/transports/settings");
    const auto switched = client.Post(
        "/api/transports/settings",
        nlohmann::json{
            {"sing_box_process_mode", "shared"}}
            .dump(),
        "application/json");
    {
        std::lock_guard<std::mutex> lock(
            runtime_mutex);
        locally_unready_mode = "isolated";
    }
    const auto locally_unready = client.Post(
        "/api/transports/settings",
        nlohmann::json{
            {"sing_box_process_mode", "isolated"}}
            .dump(),
        "application/json");
    {
        std::lock_guard<std::mutex> lock(
            runtime_mutex);
        locally_unready_mode.clear();
        fail_next_restart = true;
    }
    const auto rolled_back = client.Post(
        "/api/transports/settings",
        nlohmann::json{
            {"sing_box_process_mode", "isolated"}}
            .dump(),
        "application/json");
    maintenance_state->fail_from_verify_call =
        maintenance_state->verify_calls + 1U;
    const auto lost_delegated_lease = client.Post(
        "/api/transports/settings",
        nlohmann::json{
            {"sing_box_process_mode", "isolated"}}
            .dump(),
        "application/json");
    const auto invalid = client.Post(
        "/api/transports/settings",
        nlohmann::json{
            {"sing_box_process_mode", "invalid"}}
            .dump(),
        "application/json");

    server.stop();
    companion.stop();
    companion_thread.join();

    REQUIRE(before != nullptr);
    CHECK(before->status == 200);
    CHECK(
        nlohmann::json::parse(before->body)
            .value(
                "running_sing_box_process_mode",
                "") == "isolated");
    REQUIRE(switched != nullptr);
    CHECK(switched->status == 200);
    const auto switched_body =
        nlohmann::json::parse(switched->body);
    CHECK(
        switched_body.value(
            "sing_box_process_mode", "") ==
        "shared");
    CHECK(
        switched_body.value(
            "running_sing_box_process_mode",
            "") == "shared");
    CHECK_FALSE(
        switched_body.value(
            "restart_required", true));
    CHECK(
        switched_body.value(
            "runtime_ready", false));
    REQUIRE(locally_unready != nullptr);
    CHECK(locally_unready->status == 500);
    REQUIRE(rolled_back != nullptr);
    CHECK(rolled_back->status == 500);
    REQUIRE(lost_delegated_lease != nullptr);
    CHECK(lost_delegated_lease->status == 500);
    CHECK(restarts == 6);
    CHECK(
        transport_mode_from_file(
            transports_path) == "isolated");
    {
        std::lock_guard<std::mutex> lock(
            runtime_mutex);
        CHECK(running_mode == "isolated");
    }
    REQUIRE(invalid != nullptr);
    CHECK(invalid->status == 400);

    std::filesystem::remove_all(directory);
}

TEST_CASE("transport aliases use Unicode code points and reject controls") {
    std::string eighty_code_points;
    for (std::size_t index = 0; index < 80; ++index) {
        eighty_code_points += "🚀";
    }
    CHECK(display_name::is_valid(eighty_code_points));
    CHECK_FALSE(display_name::is_valid(eighty_code_points + "🚀"));
    CHECK_FALSE(display_name::is_valid("safe\u202etxt.exe"));
    CHECK_FALSE(display_name::is_valid(std::string{"bad\xFFname", 8}));
    CHECK(display_name::is_valid("", true));
    CHECK_FALSE(display_name::is_valid(""));
}

TEST_CASE(
    "composite transport create rejects invalid preflight without side effects") {
    constexpr int api_port = 18222;
    const auto directory =
        std::filesystem::temp_directory_path() /
        ("keen-pbr-transport-composite-preflight-" +
         std::to_string(::getpid()));
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    const auto config_path =
        (directory / "config.json").string();
    {
        std::ofstream config(config_path);
        config << "{}\n";
    }

    bool draft = true;
    Config visible;
    Outbound existing;
    existing.type = OutboundType::INTERFACE;
    existing.tag = "existing";
    existing.interface = "tun-owned";
    visible.outbounds =
        std::vector<Outbound>{existing};

    int maintenance_acquisitions = 0;
    int save_begins = 0;
    int save_finishes = 0;
    int validations = 0;
    int applies = 0;

    SseBroadcaster broadcaster;
    auto context =
        make_transports_test_context(
            broadcaster, config_path);
    context.get_visible_config_fn =
        [&]() { return visible; };
    context.config_is_draft_fn =
        [&]() { return draft; };
    context.begin_save_operation_fn =
        [&]() { ++save_begins; };
    context.finish_config_operation_fn =
        [&]() { ++save_finishes; };
    context.validate_candidate_config_fn =
        [&](const Config&) { ++validations; };
    context.enqueue_apply_validated_config_fn =
        [&](Config, std::string) {
            ++applies;
            return ConfigApplyResult{};
        };
    context.maintenance_lease_factory_fn =
        [&](std::string)
            -> std::unique_ptr<MaintenanceLease> {
        ++maintenance_acquisitions;
        return std::make_unique<
            TransportTestMaintenanceLease>();
    };

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_transports_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const nlohmann::json base_request{
        {"operation", "create"},
        {"transport",
         {
             {"tag", "new_proxy"},
             {"type", "native"},
             {"interface", "tun-owned"},
         }},
        {"linked_outbound", {{"mode", "ensure"}}},
    };

    auto invalid_request = base_request;
    invalid_request["linked_outbound"]["unexpected"] =
        true;
    const auto invalid = client.Post(
        "/api/transports/config/apply",
        invalid_request.dump(),
        "application/json");
    const auto draft_conflict = client.Post(
        "/api/transports/config/apply",
        base_request.dump(),
        "application/json");

    draft = false;
    const auto ownership_conflict = client.Post(
        "/api/transports/config/apply",
        base_request.dump(),
        "application/json");

    server.stop();
    std::filesystem::remove_all(directory);

    REQUIRE(invalid != nullptr);
    CHECK(invalid->status == 400);
    REQUIRE(draft_conflict != nullptr);
    CHECK(draft_conflict->status == 409);
    REQUIRE(ownership_conflict != nullptr);
    CHECK(ownership_conflict->status == 409);
    CHECK(maintenance_acquisitions == 2);
    CHECK(save_begins == 2);
    CHECK(save_finishes == 2);
    CHECK(validations == 0);
    CHECK(applies == 0);
}

TEST_CASE(
    "composite transport HTTP apply commits authenticated CAS and both files") {
    constexpr int api_port = 18223;
    const auto directory =
        std::filesystem::temp_directory_path() /
        ("keen-pbr-transport-composite-success-" +
         std::to_string(::getpid()));
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    const auto config_path = directory / "config.json";
    const auto transports_path =
        directory / "transports.json";
    const auto recovery_root = directory / "recovery";
    const auto core_before =
        valid_transport_core_config(
            "127.0.0.1:12121");
    write_transport_test_text(
        config_path, core_before);

    std::mutex companion_mutex;
    std::string current_revision;
    std::string transport_after;
    int health_calls = 0;
    int validate_calls = 0;
    int create_calls = 0;
    bool validate_authenticated = false;
    bool create_authenticated = false;
    bool validate_if_match = false;
    bool create_if_match = false;
    bool validate_unavailable = false;
    bool create_precondition_conflict = false;

    httplib::Server companion;
    companion.Get(
        "/healthz",
        [&](const httplib::Request& request,
            httplib::Response& response) {
            std::lock_guard<std::mutex> lock(
                companion_mutex);
            ++health_calls;
            (void)request;
            response.set_content(
                nlohmann::json{
                    {"status", "ok"},
                    {"config_revision",
                     current_revision},
                }
                    .dump(),
                "application/json");
        });
    companion.Post(
        "/v1/config/transports/validate",
        [&](const httplib::Request& request,
            httplib::Response& response) {
            std::lock_guard<std::mutex> lock(
                companion_mutex);
            ++validate_calls;
            validate_authenticated =
                request.get_header_value(
                    "Authorization") ==
                "Bearer test-secret";
            validate_if_match =
                request.get_header_value("If-Match") ==
                "\"" + current_revision + "\"";
            if (validate_unavailable) {
                response.status = 503;
                response.set_content(
                    "temporarily unavailable",
                    "text/plain");
                return;
            }
            const auto body =
                nlohmann::json::parse(request.body);
            if (!validate_authenticated ||
                !validate_if_match ||
                body.value("tag", std::string{}) !=
                    (create_precondition_conflict
                         ? "proxy_three"
                         : "proxy_one")) {
                response.status = 400;
                response.set_content(
                    R"({"error":"invalid validate request"})",
                    "application/json");
                return;
            }
            response.set_content(
                nlohmann::json{
                    {"status", "valid"},
                    {"config_revision",
                     current_revision},
                }
                    .dump(),
                "application/json");
        });
    companion.Post(
        "/v1/config/transports",
        [&](const httplib::Request& request,
            httplib::Response& response) {
            std::lock_guard<std::mutex> lock(
                companion_mutex);
            ++create_calls;
            create_authenticated =
                request.get_header_value(
                    "Authorization") ==
                "Bearer test-secret";
            create_if_match =
                request.get_header_value("If-Match") ==
                "\"" + current_revision + "\"";
            const auto body =
                nlohmann::json::parse(request.body);
            if (!create_authenticated ||
                !create_if_match ||
                body.value("tag", std::string{}) !=
                    (create_precondition_conflict
                         ? "proxy_three"
                         : "proxy_one")) {
                response.status = 412;
                response.set_content(
                    R"({"error":"revision mismatch"})",
                    "application/json");
                return;
            }
            if (create_precondition_conflict) {
                response.status = 412;
                response.set_content(
                    "stale revision",
                    "text/plain");
                return;
            }
            const auto endpoint_config =
                nlohmann::json::parse(
                    read_transport_test_text(
                        transports_path));
            auto committed = endpoint_config;
            committed["specs"] =
                nlohmann::json::array({body});
            transport_after =
                committed.dump(2) + "\n";
            write_transport_test_text(
                transports_path,
                transport_after);
            current_revision =
                Sha256::hex(transport_after);
            response.status = 201;
            response.set_content(
                nlohmann::json{
                    {"status", "created"},
                    {"config_revision",
                     current_revision},
                }
                    .dump(),
                "application/json");
        });
    const int companion_port =
        companion.bind_to_any_port("127.0.0.1");
    REQUIRE(companion_port > 0);
    const std::string transport_before =
        nlohmann::json{
            {"listen",
             "127.0.0.1:" +
                 std::to_string(companion_port)},
            {"api_key", "test-secret"},
            {"specs", nlohmann::json::array()},
        }
            .dump(2) +
        "\n";
    write_transport_test_text(
        transports_path, transport_before);
    current_revision =
        Sha256::hex(transport_before);

    std::thread companion_thread([&]() {
        companion.listen_after_bind();
    });
    while (!companion.is_running()) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(10));
    }

    int validations = 0;
    int applies = 0;
    int save_begins = 0;
    int save_finishes = 0;
    bool applied_linked_outbound = false;
    SseBroadcaster broadcaster;
    auto context = make_transports_test_context(
        broadcaster, config_path.string());
    const auto visible = parse_config(core_before);
    context.get_visible_config_fn =
        [visible]() { return visible; };
    context.config_is_draft_fn =
        []() { return false; };
    context.begin_save_operation_fn =
        [&]() { ++save_begins; };
    context.finish_config_operation_fn =
        [&]() { ++save_finishes; };
    context.validate_candidate_config_fn =
        [&](const Config& candidate) {
            ++validations;
            const auto& outbounds =
                candidate.outbounds.value();
            applied_linked_outbound =
                applied_linked_outbound ||
                std::any_of(
                    outbounds.begin(),
                    outbounds.end(),
                    [](const Outbound& outbound) {
                        return outbound.tag ==
                                   "proxy_one" &&
                               outbound.interface ==
                                   std::optional<
                                       std::string>(
                                       "tun-proxy-one");
                    });
        };
    context.enqueue_apply_validated_config_fn =
        [&](Config candidate, std::string) {
            ++applies;
            CHECK(
                std::any_of(
                    candidate.outbounds->begin(),
                    candidate.outbounds->end(),
                    [](const Outbound& outbound) {
                        return outbound.tag ==
                               "proxy_one";
                    }));
            return ConfigApplyResult{
                true, false, std::nullopt, {}};
        };
    ConfigSaveTestOptions options;
    options.recovery_state_root = recovery_root;

    ApiConfig api_config;
    api_config.listen =
        "127.0.0.1:" + std::to_string(api_port);
    ApiServer server(api_config);
    register_transports_handler_for_test(
        server,
        context,
        [](const std::string& path,
           const std::string& body) {
            write_config_atomically(path, body);
        },
        options);
    server.start();

    httplib::Client client("127.0.0.1", api_port);
    const auto response = client.Post(
        "/api/transports/config/apply",
        nlohmann::json{
            {"operation", "create"},
            {"transport",
             {
                 {"tag", "proxy_one"},
                 {"display_name", "Primary proxy"},
                 {"type",
                  "sing-box-vless-reality"},
                 {"interface", "tun-proxy-one"},
             }},
            {"linked_outbound",
             {
                 {"mode", "ensure"},
                 {"display_name", "Primary proxy"},
             }},
        }
            .dump(),
        "application/json");
    {
        std::lock_guard<std::mutex> lock(
            companion_mutex);
        validate_unavailable = true;
    }
    const auto unavailable_response = client.Post(
        "/api/transports/config/apply",
        nlohmann::json{
            {"operation", "create"},
            {"transport",
             {
                 {"tag", "proxy_two"},
                 {"type",
                  "sing-box-vless-reality"},
                 {"interface", "tun-proxy-two"},
             }},
            {"linked_outbound",
             {
                 {"mode", "ensure"},
             }},
        }
            .dump(),
        "application/json");
    {
        std::lock_guard<std::mutex> lock(
            companion_mutex);
        validate_unavailable = false;
        create_precondition_conflict = true;
    }
    const auto conflict_response = client.Post(
        "/api/transports/config/apply",
        nlohmann::json{
            {"operation", "create"},
            {"transport",
             {
                 {"tag", "proxy_three"},
                 {"type",
                  "sing-box-vless-reality"},
                 {"interface", "tun-proxy-three"},
             }},
            {"linked_outbound",
             {
                 {"mode", "ensure"},
             }},
        }
            .dump(),
        "application/json");

    server.stop();
    companion.stop();
    companion_thread.join();

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    const auto body =
        nlohmann::json::parse(response->body);
    CHECK(body.value("status", "") == "applied");
    CHECK(body.value("saved", false));
    CHECK(body.value("applied", false));
    CHECK(
        body.value("transport_revision", "") ==
        current_revision);
    CHECK(validations == 2);
    CHECK(applies == 1);
    CHECK(save_begins == 3);
    CHECK(save_finishes == 3);
    CHECK(applied_linked_outbound);
    CHECK(health_calls >= 4);
    CHECK(validate_calls == 3);
    CHECK(create_calls == 2);
    CHECK(validate_authenticated);
    CHECK(create_authenticated);
    CHECK(validate_if_match);
    CHECK(create_if_match);
    REQUIRE(unavailable_response != nullptr);
    CHECK(unavailable_response->status == 503);
    REQUIRE(conflict_response != nullptr);
    CHECK(conflict_response->status == 409);
    CHECK(
        read_transport_test_text(transports_path) ==
        transport_after);
    const auto persisted_core =
        parse_config(
            read_transport_test_text(config_path));
    REQUIRE(persisted_core.outbounds.has_value());
    CHECK(
        std::any_of(
            persisted_core.outbounds->begin(),
            persisted_core.outbounds->end(),
            [](const Outbound& outbound) {
                return outbound.tag == "proxy_one";
            }));
    CHECK_FALSE(
        RestoreJournal(
            recovery_root / "config-save")
            .read_active()
            .has_value());

    std::filesystem::remove_all(directory);
}

TEST_CASE(
    "composite commit rejects manager and durable base divergence before WAL") {
    const auto directory =
        std::filesystem::temp_directory_path() /
        ("keen-pbr-transport-base-divergence-" +
         std::to_string(::getpid()));
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    const auto config_path = directory / "config.json";
    const auto transports_path =
        directory / "transports.json";
    const auto recovery_root = directory / "recovery";
    const std::string core_before = "{}\n";
    const std::string transport_before =
        "{\"revision\":\"durable-winner\"}\n";
    write_transport_test_text(
        config_path, core_before);
    write_transport_test_text(
        transports_path, transport_before);

    int mutations = 0;
    int writes = 0;
    SseBroadcaster broadcaster;
    auto context = make_transports_test_context(
        broadcaster, config_path.string());
    ConfigSaveTestOptions options;
    options.recovery_state_root = recovery_root;

    try {
        (void)commit_prepared_config_for_test(
            context,
            "transport-base-divergence-test",
            [&]() {
                PreparedConfigCommit prepared;
                prepared.config = Config{};
                prepared.serialized =
                    "{\"candidate\":true}\n";
                prepared.transport =
                    ConfigCommitTransportEffect{
                        transports_path.string(),
                        std::string(64U, '0'),
                        [&]() -> std::string {
                            ++mutations;
                            return {};
                        },
                        [](const std::string&) {},
                        [](const std::string&, MaintenanceLease&) {},
                    };
                return prepared;
            },
            [&](const std::string& path,
                const std::string& body) {
                ++writes;
                write_config_atomically(path, body);
            },
            options);
        FAIL("base divergence must be rejected");
    } catch (const ApiError& error) {
        CHECK(error.status() == 409);
    }

    CHECK(mutations == 0);
    CHECK(writes == 0);
    CHECK(
        read_transport_test_text(config_path) ==
        core_before);
    CHECK(
        read_transport_test_text(transports_path) ==
        transport_before);
    CHECK_FALSE(std::filesystem::exists(
        recovery_root / "config-save" / "active.json"));
    std::filesystem::remove_all(directory);
}

TEST_CASE(
    "transport CAS conflict preserves the concurrent winner and closes WAL") {
    const auto directory =
        std::filesystem::temp_directory_path() /
        ("keen-pbr-transport-cas-winner-" +
         std::to_string(::getpid()));
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    const auto config_path = directory / "config.json";
    const auto transports_path =
        directory / "transports.json";
    const auto recovery_root = directory / "recovery";
    const std::string core_before = "{}\n";
    const std::string transport_before =
        "{\"revision\":\"before\"}\n";
    const std::string concurrent_winner =
        "{\"revision\":\"concurrent-winner\"}\n";
    write_transport_test_text(
        config_path, core_before);
    write_transport_test_text(
        transports_path, transport_before);

    bool restore_called = false;
    int writes = 0;
    SseBroadcaster broadcaster;
    auto context = make_transports_test_context(
        broadcaster, config_path.string());
    ConfigSaveTestOptions options;
    options.recovery_state_root = recovery_root;

    try {
        (void)commit_prepared_config_for_test(
            context,
            "transport-cas-winner-test",
            [&]() {
                PreparedConfigCommit prepared;
                prepared.config = Config{};
                prepared.serialized =
                    "{\"candidate\":true}\n";
                prepared.transport =
                    ConfigCommitTransportEffect{
                        transports_path.string(),
                        Sha256::hex(transport_before),
                        [&]() -> std::string {
                            write_transport_test_text(
                                transports_path,
                                concurrent_winner);
                            throw
                                ConfigCommitNoMutationConflict(
                                    "concurrent winner",
                                    409);
                        },
                        [](const std::string&) {},
                        [&](const std::string&, MaintenanceLease&) {
                            restore_called = true;
                        },
                    };
                return prepared;
            },
            [&](const std::string& path,
                const std::string& body) {
                ++writes;
                write_config_atomically(path, body);
            },
            options);
        FAIL("CAS conflict must be returned");
    } catch (const ConfigCommitNoMutationConflict&
                 error) {
        CHECK(error.status() == 409);
    }

    CHECK(writes == 0);
    CHECK_FALSE(restore_called);
    CHECK(
        read_transport_test_text(config_path) ==
        core_before);
    CHECK(
        read_transport_test_text(transports_path) ==
        concurrent_winner);
    RestoreJournal journal(
        recovery_root / "config-save");
    CHECK_FALSE(journal.read_active().has_value());
    CHECK_FALSE(
        RestoreJournal(recovery_root)
            .unknown_present());
    std::filesystem::remove_all(directory);
}

TEST_CASE(
    "transport CAS WAL completion failure blocks startup recovery without restoring winner") {
    const auto directory =
        std::filesystem::temp_directory_path() /
        ("keen-pbr-transport-cas-unknown-" +
         std::to_string(::getpid()));
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    const auto config_path = directory / "config.json";
    const auto transports_path =
        directory / "transports.json";
    const auto recovery_root = directory / "recovery";
    const std::string core_before = "{}\n";
    const std::string transport_before =
        "{\"revision\":\"before\"}\n";
    const std::string concurrent_winner =
        "{\"revision\":\"concurrent-winner\"}\n";
    write_transport_test_text(
        config_path, core_before);
    write_transport_test_text(
        transports_path, transport_before);

    bool restore_called = false;
    SseBroadcaster broadcaster;
    auto context = make_transports_test_context(
        broadcaster, config_path.string());
    ConfigSaveTestOptions options;
    options.recovery_state_root = recovery_root;

    try {
        (void)commit_prepared_config_for_test(
            context,
            "transport-cas-unknown-test",
            [&]() {
                PreparedConfigCommit prepared;
                prepared.config = Config{};
                prepared.serialized =
                    "{\"candidate\":true}\n";
                prepared.transport =
                    ConfigCommitTransportEffect{
                        transports_path.string(),
                        Sha256::hex(transport_before),
                        [&]() -> std::string {
                            write_transport_test_text(
                                transports_path,
                                concurrent_winner);
                            write_transport_test_text(
                                recovery_root /
                                    "config-save" /
                                    "active.json",
                                "corrupt-active-marker");
                            throw
                                ConfigCommitNoMutationConflict(
                                    "concurrent winner",
                                    409);
                        },
                        [](const std::string&) {},
                        [&](const std::string&, MaintenanceLease&) {
                            restore_called = true;
                        },
                    };
                return prepared;
            },
            [](const std::string& path,
               const std::string& body) {
                write_config_atomically(path, body);
            },
            options);
        FAIL("unsafe WAL completion must fail closed");
    } catch (const ApiError& error) {
        CHECK(error.status() == 503);
        REQUIRE(error.body().has_value());
        CHECK(
            nlohmann::json::parse(*error.body())
                .value("recovery_required", false));
    }

    CHECK_FALSE(restore_called);
    CHECK(
        read_transport_test_text(config_path) ==
        core_before);
    CHECK(
        read_transport_test_text(transports_path) ==
        concurrent_winner);
    CHECK(
        RestoreJournal(recovery_root)
            .unknown_present());

    backup::RecoveryCoordinatorLayout layout;
    layout.state_root = recovery_root;
    layout.persistent.config = config_path;
    layout.persistent.transports = transports_path;
    backup::RecoveryCoordinator coordinator(layout);
    try {
        (void)coordinator.recover();
        FAIL("global UNKNOWN must block startup recovery");
    } catch (
        const backup::RecoveryCoordinatorError& error) {
        CHECK(
            error.kind() ==
            backup::RecoveryErrorKind::global_unknown);
    }
    CHECK(
        read_transport_test_text(transports_path) ==
        concurrent_winner);
    std::filesystem::remove_all(directory);
}

TEST_CASE(
    "composite transport checkpoints restore exact files before WAL completion") {
    const std::vector<ConfigSaveFaultStage> stages{
        ConfigSaveFaultStage::transport_mutated,
        ConfigSaveFaultStage::transports_ready,
    };
    std::size_t index = 0;
    for (const auto stage : stages) {
        const auto directory =
            std::filesystem::temp_directory_path() /
            ("keen-pbr-transport-checkpoint-" +
             std::to_string(::getpid()) + "-" +
             std::to_string(index++));
        std::filesystem::remove_all(directory);
        std::filesystem::create_directories(directory);
        const auto config_path =
            directory / "config.json";
        const auto transports_path =
            directory / "transports.json";
        const auto recovery_root =
            directory / "recovery";
        const std::string core_before =
            valid_transport_core_config(
                "127.0.0.1:12121");
        const std::string core_after =
            valid_transport_core_config(
                "127.0.0.1:12122");
        const std::string transport_before =
            "{\"revision\":\"before\"}\n";
        const std::string transport_after =
            "{\"revision\":\"after\"}\n";
        const auto before_revision =
            Sha256::hex(transport_before);
        const auto after_revision =
            Sha256::hex(transport_after);
        write_transport_test_text(
            config_path, core_before);
        write_transport_test_text(
            transports_path, transport_before);

        bool restore_called = false;
        bool verify_called = false;
        int applies = 0;
        SseBroadcaster broadcaster;
        auto context = make_transports_test_context(
            broadcaster, config_path.string());
        context.enqueue_apply_validated_config_fn =
            [&](Config, std::string) {
                ++applies;
                return ConfigApplyResult{
                    true, false, std::nullopt, {}};
            };
        ConfigSaveTestOptions options;
        options.recovery_state_root =
            recovery_root;
        options.fault_injector =
            [stage](ConfigSaveFaultStage current) {
                if (current == stage) {
                    throw std::runtime_error(
                        "injected composite checkpoint "
                        "failure");
                }
            };

        std::string failure_details;
        bool checkpoint_failed = false;
        try {
            (void)commit_prepared_config_for_test(
                context,
                "transport-checkpoint-test",
                [&]() {
                PreparedConfigCommit prepared;
                prepared.config = Config{};
                prepared.serialized = core_after;
                prepared.transport =
                    ConfigCommitTransportEffect{
                        transports_path.string(),
                        before_revision,
                        [&]() {
                            write_transport_test_text(
                                transports_path,
                                transport_after);
                            return after_revision;
                        },
                        [&](const std::string& revision) {
                            verify_called = true;
                            CHECK(
                                revision ==
                                after_revision);
                            CHECK(
                                read_transport_test_text(
                                    transports_path) ==
                                transport_after);
                        },
                        [&](const std::string& revision,
                            MaintenanceLease&) {
                            restore_called = true;
                            CHECK(
                                revision ==
                                before_revision);
                            CHECK(
                                read_transport_test_text(
                                    config_path) ==
                                core_before);
                            CHECK(
                                read_transport_test_text(
                                    transports_path) ==
                                transport_before);
                            RestoreJournal journal(
                                recovery_root /
                                "config-save");
                            CHECK(
                                journal.read_active()
                                    .has_value());
                        },
                    };
                return prepared;
                },
                [](const std::string& path,
                   const std::string& body) {
                    write_config_atomically(path, body);
                },
                options);
        } catch (const ApiError& error) {
            checkpoint_failed = true;
            failure_details = error.what();
            if (error.body().has_value()) {
                failure_details += ": " + *error.body();
            }
        } catch (const std::exception& error) {
            checkpoint_failed = true;
            failure_details = error.what();
        }

        INFO(failure_details);
        CHECK(checkpoint_failed);
        CHECK(restore_called);
        CHECK(
            verify_called ==
            (stage ==
             ConfigSaveFaultStage::transports_ready));
        CHECK(applies == 0);
        CHECK(
            read_transport_test_text(config_path) ==
            core_before);
        CHECK(
            read_transport_test_text(transports_path) ==
            transport_before);
        CHECK_FALSE(
            RestoreJournal(
                recovery_root / "config-save")
                .read_active()
                .has_value());
        std::filesystem::remove_all(directory);
    }
}

} // namespace keen_pbr3

#endif // WITH_API
