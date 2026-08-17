#ifdef WITH_API

#include "handler_transports.hpp"
#include "handler_config.hpp"
#include "maintenance_api.hpp"
#include "transport_manager_endpoint.hpp"

#include "../config/config_writer.hpp"
#include "../crypto/sha256.hpp"
#include "../util/display_name.hpp"
#include "../util/safe_exec.hpp"
#include "../update/sing_box_install_observation.hpp"
#include "../update/sing_box_install_policy.hpp"

#include <keen-pbr/version.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <httplib.h>
#include <initializer_list>
#include <iterator>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace keen_pbr3 {

namespace {

// The endpoint struct and its loader moved to transport_manager_endpoint.hpp
// when the subscription import became a second caller. The local name is kept
// so the forty existing call sites in this file stay unchanged.
TransportManagerEndpoint load_endpoint(
    const std::string& keen_pbr_config_path) {
    return load_transport_manager_endpoint(keen_pbr_config_path);
}

// Where install.sh records the binary it installed. Its presence is what
// distinguishes a sing-box this daemon put there from one the operator
// installed themselves.
constexpr const char* kSingBoxManagedMarkerPath =
    "/opt/etc/keen-pbr/sing-box-managed.path";

// The binary the transport manager is configured to run, which is the one an
// install would replace - not a hardcoded path that might not be the one in
// use.
std::string configured_sing_box_binary(const std::string& config_path) {
    const auto path =
        std::filesystem::path(config_path).parent_path() /
        "transports.json";
    std::ifstream input(path);
    if (!input.is_open()) return "/opt/bin/sing-box";
    const auto config = nlohmann::json::parse(input, nullptr, false);
    if (config.is_discarded() || !config.is_object()) {
        return "/opt/bin/sing-box";
    }
    return config.value("sing_box_binary", std::string("/opt/bin/sing-box"));
}

api::SingBoxInstallCapabilityOperation api_install_operation(
    const SingBoxInstallOperation operation) {
    switch (operation) {
    case SingBoxInstallOperation::install:
        return api::SingBoxInstallCapabilityOperation::INSTALL;
    case SingBoxInstallOperation::replace:
        return api::SingBoxInstallCapabilityOperation::REPLACE;
    case SingBoxInstallOperation::reinstall_same_version:
        return api::SingBoxInstallCapabilityOperation::
            REINSTALL_SAME_VERSION;
    case SingBoxInstallOperation::blocked:
        return api::SingBoxInstallCapabilityOperation::BLOCKED;
    }
    return api::SingBoxInstallCapabilityOperation::BLOCKED;
}

api::Blocker api_install_blocker(const SingBoxInstallBlocker blocker) {
    switch (blocker) {
    case SingBoxInstallBlocker::architecture_unsupported:
        return api::Blocker::ARCHITECTURE_UNSUPPORTED;
    case SingBoxInstallBlocker::entware_absent:
        return api::Blocker::ENTWARE_ABSENT;
    case SingBoxInstallBlocker::target_not_writable:
        return api::Blocker::TARGET_NOT_WRITABLE;
    case SingBoxInstallBlocker::foreign_binary_present:
        return api::Blocker::FOREIGN_BINARY_PRESENT;
    case SingBoxInstallBlocker::transports_running:
        return api::Blocker::TRANSPORTS_RUNNING;
    case SingBoxInstallBlocker::transport_state_unknown:
        return api::Blocker::TRANSPORT_STATE_UNKNOWN;
    }
    return api::Blocker::TRANSPORT_STATE_UNKNOWN;
}

bool valid_transport_tag(const std::string& tag) {
    if (tag.empty() || tag.size() > 24 || tag.front() < 'a' || tag.front() > 'z') {
        return false;
    }
    for (const char ch : tag) {
        const bool lowercase = ch >= 'a' && ch <= 'z';
        const bool digit = ch >= '0' && ch <= '9';
        if (!lowercase && !digit && ch != '_') {
            return false;
        }
    }
    return true;
}

bool string_in(const nlohmann::json& value,
               std::initializer_list<const char*> allowed) {
    if (!value.is_string()) return false;
    const auto text = value.get<std::string>();
    for (const auto* candidate : allowed) {
        if (text == candidate) return true;
    }
    return false;
}

bool valid_transport_path(const nlohmann::json& path) {
    if (!path.is_object() ||
        !path.contains("wire_transport") ||
        !string_in(path["wire_transport"], {"tcp", "udp", "tcp_udp", "unknown"}) ||
        !path.contains("framing") ||
        !string_in(path["framing"],
                   {"raw",
                    "websocket",
                    "http",
                    "http2",
                    "grpc",
                    "http_upgrade",
                    "quic",
                    "wireguard",
                    "unknown"}) ||
        !path.contains("confidence") ||
        !string_in(path["confidence"],
                   {"declared", "derived", "ambiguous", "unknown"})) {
        return false;
    }

    if (!path.contains("payload_networks")) return true;
    if (!path["payload_networks"].is_array()) return false;
    std::set<std::string> seen;
    for (const auto& network : path["payload_networks"]) {
        if (!string_in(network, {"tcp", "udp"}) ||
            !seen.insert(network.get<std::string>()).second) {
            return false;
        }
    }
    return true;
}

bool valid_transport_status(const nlohmann::json& status) {
    if (!status.is_object() ||
        !status.contains("tag") ||
        !status["tag"].is_string() ||
        !valid_transport_tag(status["tag"].get<std::string>()) ||
        !status.contains("type") ||
        !status["type"].is_string() ||
        status["type"].get_ref<const std::string&>().empty() ||
        !status.contains("interface") ||
        !status["interface"].is_string() ||
        status["interface"].get_ref<const std::string&>().empty() ||
        !status.contains("state") ||
        !string_in(status["state"], {"down", "starting", "up", "degraded"}) ||
        !status.contains("updated_at") ||
        !status["updated_at"].is_string() ||
        !status.contains("desired_up") ||
        !status["desired_up"].is_boolean()) {
        return false;
    }
    if (status.contains("display_name") &&
        (!status["display_name"].is_string() ||
         !display_name::is_valid(
             status["display_name"].get_ref<const std::string&>()))) {
        return false;
    }
    return !status.contains("path") || valid_transport_path(status["path"]);
}

bool valid_transport_spec_display_name(const nlohmann::json& spec,
                                       bool allow_empty) {
    if (!spec.is_object()) return false;
    if (!spec.contains("display_name")) return true;
    return spec["display_name"].is_string() &&
           display_name::is_valid(
               spec["display_name"].get_ref<const std::string&>(),
               allow_empty);
}

bool valid_revision(const std::string& revision) {
    return revision.size() == 64U &&
           std::all_of(
               revision.begin(),
               revision.end(),
               [](const char value) {
                   return (value >= '0' && value <= '9') ||
                          (value >= 'a' && value <= 'f');
               });
}

bool valid_sing_box_process_mode(const nlohmann::json& value) {
    return string_in(value, {"isolated", "shared"});
}

void validate_transport_runtime_settings(
    const nlohmann::json& settings) {
    if (!settings.is_object() ||
        !settings.contains("sing_box_process_mode") ||
        !valid_sing_box_process_mode(
            settings.at("sing_box_process_mode")) ||
        !settings.contains("running_sing_box_process_mode") ||
        !valid_sing_box_process_mode(
            settings.at("running_sing_box_process_mode")) ||
        !settings.contains("restart_required") ||
        !settings.at("restart_required").is_boolean() ||
        !settings.contains("runtime_ready") ||
        !settings.at("runtime_ready").is_boolean()) {
        throw ApiError(
            "transport manager returned invalid runtime settings",
            502);
    }
}

class TransportManagerClient final {
public:
    explicit TransportManagerClient(
        TransportManagerEndpoint endpoint)
        : endpoint_(std::move(endpoint)) {}

    std::string current_revision() const {
        httplib::Client client(endpoint_.host, endpoint_.port);
        client.set_connection_timeout(0, 300000);
        client.set_read_timeout(0, 300000);
        const auto response = client.Get("/healthz");
        if (!response) {
            throw ApiError(
                "transport manager is unavailable", 503);
        }
        const auto body = parse_json_response(
            *response, "health response");
        if (response->status < 200 ||
            response->status >= 300 ||
            !body.is_object() ||
            body.value("status", std::string{}) != "ok" ||
            !body.contains("config_revision") ||
            !body.at("config_revision").is_string()) {
            throw ApiError(
                "transport manager returned an invalid "
                "health response",
                502);
        }
        const auto revision =
            body.at("config_revision").get<std::string>();
        if (!valid_revision(revision)) {
            throw ApiError(
                "transport manager returned an invalid "
                "configuration revision",
                502);
        }
        return revision;
    }

    void validate_create(
        const nlohmann::json& transport,
        const std::string& expected_revision) const {
        const auto response = post(
            "/v1/config/transports/validate",
            transport,
            expected_revision);
        (void)parse_revision_response(
            response, expected_revision, "validate");
    }

    std::string create(
        const nlohmann::json& transport,
        const std::string& expected_revision) const {
        const auto response = post(
            "/v1/config/transports",
            transport,
            expected_revision);
        return parse_revision_response(
            response, expected_revision, "create");
    }

    void wait_for_revision(
        const std::string& expected_revision) const {
        if (!valid_revision(expected_revision)) {
            throw ApiError(
                "invalid expected transport revision", 500);
        }
        constexpr std::size_t kAttempts = 20U;
        for (std::size_t attempt = 0;
             attempt < kAttempts;
             ++attempt) {
            try {
                if (current_revision() ==
                    expected_revision) {
                    return;
                }
            } catch (const ApiError&) {
                if (attempt + 1U == kAttempts) throw;
            }
            if (attempt + 1U < kAttempts) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(250));
            }
        }
        throw ApiError(
            "transport manager did not load the expected "
            "configuration revision",
            503);
    }

    nlohmann::json settings() const {
        httplib::Client client(endpoint_.host, endpoint_.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(3, 0);
        const httplib::Headers headers{
            {"Authorization",
             "Bearer " + endpoint_.api_key},
        };
        const auto response =
            client.Get("/v1/config/settings", headers);
        if (!response) {
            throw ApiError(
                "transport manager is unavailable", 503);
        }
        if (response->status < 200 ||
            response->status >= 300) {
            throw ApiError(
                "transport manager returned HTTP " +
                    std::to_string(response->status),
                response->status == 503 ? 503 : 502,
                response->body);
        }
        auto body =
            parse_json_response(*response, "runtime settings");
        validate_transport_runtime_settings(body);
        return body;
    }

    nlohmann::json set_sing_box_process_mode(
        const std::string& mode) const {
        httplib::Client client(endpoint_.host, endpoint_.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(30, 0);
        const httplib::Headers headers{
            {"Authorization",
             "Bearer " + endpoint_.api_key},
        };
        const auto response = client.Put(
            "/v1/config/settings",
            headers,
            nlohmann::json{
                {"sing_box_process_mode", mode}}
                .dump(),
            "application/json");
        if (!response) {
            throw ApiError(
                "transport manager is unavailable", 503);
        }
        if (response->status < 200 ||
            response->status >= 300) {
            throw ApiError(
                "transport manager rejected sing-box process mode",
                response->status == 400
                    ? 400
                    : response->status == 503 ? 503 : 502,
                response->body);
        }
        auto body =
            parse_json_response(*response, "runtime settings");
        validate_transport_runtime_settings(body);
        return body;
    }

    nlohmann::json wait_for_runtime_mode(
        const std::string& expected_mode,
        std::size_t attempts,
        std::chrono::milliseconds interval) const {
        if ((expected_mode != "isolated" &&
             expected_mode != "shared") ||
            attempts == 0U) {
            throw ApiError(
                "invalid expected transport runtime mode",
                500);
        }
        for (std::size_t attempt = 0;
             attempt < attempts;
             ++attempt) {
            try {
                auto current = settings();
                if (current.at("sing_box_process_mode")
                            .get<std::string>() ==
                        expected_mode &&
                    current.at(
                               "running_sing_box_process_mode")
                            .get<std::string>() ==
                        expected_mode &&
                    !current.at("restart_required")
                         .get<bool>() &&
                    current.at("runtime_ready")
                        .get<bool>()) {
                    return current;
                }
            } catch (const ApiError&) {
                if (attempt + 1U == attempts) {
                    throw;
                }
            }
            if (attempt + 1U < attempts) {
                std::this_thread::sleep_for(interval);
            }
        }
        throw ApiError(
            "transport manager did not make the requested "
            "sing-box runtime locally ready",
            503);
    }

private:
    httplib::Result post(
        const std::string& path,
        const nlohmann::json& body,
        const std::string& expected_revision) const {
        httplib::Client client(endpoint_.host, endpoint_.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(30, 0);
        const httplib::Headers headers{
            {"Authorization",
             "Bearer " + endpoint_.api_key},
            {"If-Match",
             "\"" + expected_revision + "\""},
        };
        auto response = client.Post(
            path,
            headers,
            body.dump(),
            "application/json");
        if (!response) {
            throw ApiError(
                "transport manager is unavailable", 503);
        }
        return response;
    }

    static nlohmann::json parse_json_response(
        const httplib::Response& response,
        const char* description) {
        try {
            return nlohmann::json::parse(response.body);
        } catch (const nlohmann::json::exception&) {
            throw ApiError(
                std::string(
                    "transport manager returned malformed ") +
                    description,
                502);
        }
    }

    static std::string parse_revision_response(
        const httplib::Result& response,
        const std::string& expected_revision,
        const char* operation) {
        if (!response) {
            throw ApiError(
                "transport manager is unavailable", 503);
        }
        if (response->status == 412) {
            throw ConfigCommitNoMutationConflict(
                "Transport configuration changed while "
                "the operation was being prepared",
                409,
                response->body);
        }
        if (response->status < 200 ||
            response->status >= 300) {
            const int status =
                response->status == 400
                    ? 400
                    : response->status == 409
                          ? 409
                          : response->status == 503
                                ? 503
                          : 502;
            throw ApiError(
                std::string("transport manager could not ") +
                    operation +
                    " the transport",
                status,
                response->body);
        }
        const auto body = parse_json_response(
            *response, "configuration response");
        if (!body.is_object() ||
            !body.contains("config_revision") ||
            !body.at("config_revision").is_string()) {
            throw ApiError(
                "transport manager omitted the committed "
                "configuration revision",
                502);
        }
        const auto revision =
            body.at("config_revision").get<std::string>();
        if (!valid_revision(revision)) {
            throw ApiError(
                "transport manager returned an invalid "
                "configuration revision",
                502);
        }
        if (std::string(operation) == "validate" &&
            revision != expected_revision) {
            throw ApiError(
                "Transport configuration changed while "
                "the operation was being validated",
                409,
                body.dump());
        }
        return revision;
    }

    TransportManagerEndpoint endpoint_;
};

void restart_transport_manager_and_wait(
    ApiContext& ctx,
    const std::string& expected_revision,
    MaintenanceLease* maintenance = nullptr) {
    constexpr const char* kInitScript =
        "/opt/etc/init.d/S79transport-manager";
    int status = 0;
    if (ctx.restart_restore_service_fn) {
        status = ctx.restart_restore_service_fn(kInitScript);
    } else {
        ChildEnvironmentOverrides child_environment{
            {"KEEN_PBR_PERSISTENT_TRANSACTION", "1"},
        };
        if (maintenance != nullptr) {
            // Prove the scoped capability immediately before delegating it;
            // a token from a guardian that already died must never become a
            // child bypass of the lifecycle lock.
            maintenance->verify_held();
            const auto owner_pid = maintenance->borrow_owner_pid();
            const auto token = maintenance->borrow_token();
            if (owner_pid <= 1 || token.empty()) {
                throw std::runtime_error(
                    "maintenance lease cannot be delegated to transport manager");
            }
            child_environment.emplace_back(
                "KEEN_PBR_UPDATE_LOCK_PID",
                std::to_string(static_cast<long>(owner_pid)));
            child_environment.emplace_back(
                "KEEN_PBR_UPDATE_LOCK_TOKEN", token);
        }
        status = safe_exec_with_environment(
            {kInitScript, "restart"}, child_environment, true);
    }
    if (maintenance != nullptr) {
        // S79 temporarily becomes the authoritative lifecycle-lock owner.
        // A normal EXIT transfers the exact token back to this process. If
        // the child was killed before that hand-off, fail closed before any
        // caller can mutate rollback bytes under a lease it no longer owns.
        maintenance->verify_held();
    }
    if (status != 0) {
        throw std::runtime_error(
            "transport manager restart failed");
    }
    TransportManagerClient(
        load_endpoint(ctx.config_path))
        .wait_for_revision(expected_revision);
}

nlohmann::json restart_transport_manager_and_wait_for_runtime(
    ApiContext& ctx,
    const std::string& expected_revision,
    const std::string& expected_mode,
    MaintenanceLease* maintenance = nullptr) {
    restart_transport_manager_and_wait(
        ctx, expected_revision, maintenance);
    return TransportManagerClient(
               load_endpoint(ctx.config_path))
        .wait_for_runtime_mode(
            expected_mode,
            ctx.transport_runtime_ready_wait_attempts,
            std::chrono::milliseconds(
                ctx.transport_runtime_ready_wait_interval_ms));
}

} // namespace

using CompositeConfigCommit = std::function<std::string(
    ApiContext&,
    std::string,
    PrepareConfigCommit)>;

static void register_transports_handler_impl(
    ApiServer& server,
    ApiContext& ctx,
    CompositeConfigCommit commit_config) {
    // Read-only: measures the router and decides, changes nothing. The
    // measurement and the decision live in src/update, so both are testable
    // without each other and without a router; this handler only supplies the
    // one probe neither can take on its own - the running transport count,
    // which only the manager knows.
    server.get(
        "/api/transports/sing-box/capability",
        [&ctx]() -> std::string {
            const auto binary = configured_sing_box_binary(ctx.config_path);
            auto probes = production_sing_box_install_probes();
            const auto endpoint = load_endpoint(ctx.config_path);
            probes.count_running_transports =
                [&endpoint]() -> std::size_t {
                // Left unset on any failure below, so an unreachable manager
                // reaches the policy as "nobody could ask" and blocks, rather
                // than as a count of zero that would authorise the swap.
                httplib::Client client(endpoint.host, endpoint.port);
                client.set_connection_timeout(1, 0);
                client.set_read_timeout(3, 0);
                const httplib::Headers headers{
                    {"Authorization", "Bearer " + endpoint.api_key},
                };
                const auto response = client.Get("/v1/transports", headers);
                if (!response || response->status < 200 ||
                    response->status >= 300) {
                    throw ApiError("transport manager is unavailable", 503);
                }
                const auto body = nlohmann::json::parse(
                    response->body, nullptr, false);
                if (body.is_discarded() || !body.is_array()) {
                    throw ApiError(
                        "transport manager returned an invalid runtime "
                        "state",
                        502);
                }
                std::size_t running = 0U;
                for (const auto& status : body) {
                    if (!status.is_object()) continue;
                    const auto type =
                        status.value("type", std::string{});
                    if (type.rfind("sing-box", 0U) != 0U) continue;
                    // Anything that is not `down` has a process attached to
                    // the binary about to be replaced. `degraded` and
                    // `starting` count for exactly that reason.
                    if (status.value("state", std::string{}) != "down") {
                        ++running;
                    }
                }
                return running;
            };

            const auto observation = observe_sing_box_install(
                probes, binary, kSingBoxManagedMarkerPath);
            const auto policy = evaluate_sing_box_install(
                observation, KEEN_PBR3_SING_BOX_PINNED_VERSION);

            api::SingBoxInstallCapability capability;
            capability.available = policy.available;
            capability.operation = api_install_operation(policy.operation);
            capability.pinned_version =
                KEEN_PBR3_SING_BOX_PINNED_VERSION;
            if (!observation.installed_version.empty()) {
                capability.installed_version =
                    observation.installed_version;
            }
            if (!policy.asset_architecture.empty()) {
                capability.asset_architecture = policy.asset_architecture;
            }
            capability.blockers.reserve(policy.blockers.size());
            for (const auto blocker : policy.blockers) {
                capability.blockers.push_back(api_install_blocker(blocker));
            }
            capability.verified_archive_checksum =
                policy.verified_archive_checksum;
            capability.signed_release = policy.signed_release;
            capability.exact_rollback = policy.exact_rollback;
            return nlohmann::json(capability).dump();
        });

    server.get("/api/transports/environment", [&ctx]() -> std::string {
        const auto path = std::filesystem::path(ctx.config_path).parent_path() /
                          "transports.json";
        std::ifstream input(path);
        nlohmann::json config;
        if (input.is_open()) {
            try {
                input >> config;
            } catch (const nlohmann::json::exception&) {
                config = nlohmann::json::object();
            }
        }
        const auto binary = config.value("sing_box_binary", std::string("/opt/bin/sing-box"));
        std::error_code ec;
        const bool installed = std::filesystem::is_regular_file(binary, ec);
        return nlohmann::json{{"sing_box_installed", installed},
                              {"sing_box_binary", binary},
                              // One source: version.mk, threaded through the
                              // generated header. The literal that used to sit
                              // here said "tested" while the installer had been
                              // renamed to "pinned" - different promises about
                              // the same number. `tested_version` stays for the
                              // frontend that already reads it.
                              {"pinned_version",
                               KEEN_PBR3_SING_BOX_PINNED_VERSION},
                              {"tested_version",
                               KEEN_PBR3_SING_BOX_PINNED_VERSION},
                              // Prevent a newer preview bundle from reporting
                              // false success when an older companion silently
                              // drops fields such as display_name.
                              {"transport_api_version", 2}}
            .dump();
    });

    server.get("/api/transports/settings", [&ctx]() -> std::string {
        return TransportManagerClient(
                   load_endpoint(ctx.config_path))
            .settings()
            .dump();
    });

    server.post(
        "/api/transports/settings",
        [&ctx](const std::string& request_body) -> std::string {
            nlohmann::json request;
            try {
                request =
                    nlohmann::json::parse(request_body);
            } catch (const nlohmann::json::exception&) {
                throw ApiError(
                    "invalid transport settings JSON", 400);
            }
            if (!request.is_object() ||
                request.size() != 1U ||
                !request.contains(
                    "sing_box_process_mode") ||
                !valid_sing_box_process_mode(
                    request.at(
                        "sing_box_process_mode"))) {
                throw ApiError(
                    "sing_box_process_mode must be "
                    "'isolated' or 'shared'",
                    400);
            }
            const auto requested_mode =
                request.at("sing_box_process_mode")
                    .get<std::string>();

            try {
                auto maintenance =
                    ctx.acquire_maintenance_lease(
                        "transport-runtime-settings");
                (void)maintenance->reserve(
                    maintenance->base_generation());

                const auto transports_path =
                    std::filesystem::path(
                        ctx.config_path)
                        .parent_path() /
                    "transports.json";
                std::ifstream previous_input(
                    transports_path,
                    std::ios::binary);
                if (!previous_input) {
                    throw ApiError(
                        "transport manager config not found",
                        503);
                }
                const std::string previous_data{
                    std::istreambuf_iterator<char>(
                        previous_input),
                    std::istreambuf_iterator<char>()};
                if (!previous_input.eof() &&
                    previous_input.fail()) {
                    throw ApiError(
                        "could not read transport manager "
                        "config",
                        500);
                }

                const auto endpoint =
                    load_endpoint(ctx.config_path);
                TransportManagerClient client(endpoint);
                const auto before = client.settings();
                if (before.at(
                        "sing_box_process_mode")
                            .get<std::string>() ==
                        requested_mode &&
                    before.at(
                        "running_sing_box_process_mode")
                        .get<std::string>() ==
                        requested_mode &&
                    !before.at("restart_required")
                         .get<bool>() &&
                    before.at("runtime_ready")
                        .get<bool>()) {
                    maintenance->verify_held();
                    return before.dump();
                }

                const auto staged =
                    client.set_sing_box_process_mode(
                        requested_mode);
                const auto candidate_revision =
                    client.current_revision();
                const auto previous_mode =
                    before.at("sing_box_process_mode")
                        .get<std::string>();
                try {
                    nlohmann::json applied;
                    if (staged.at("restart_required")
                            .get<bool>() ||
                        !staged.at("runtime_ready")
                             .get<bool>()) {
                        applied =
                            restart_transport_manager_and_wait_for_runtime(
                                ctx,
                                candidate_revision,
                                requested_mode,
                                maintenance.get());
                    } else {
                        applied =
                            client.wait_for_runtime_mode(
                                requested_mode,
                                ctx.transport_runtime_ready_wait_attempts,
                                std::chrono::milliseconds(
                                    ctx.transport_runtime_ready_wait_interval_ms));
                    }
                    if (applied.at(
                            "sing_box_process_mode")
                                .get<std::string>() !=
                            requested_mode ||
                        applied.at(
                            "running_sing_box_process_mode")
                                .get<std::string>() !=
                            requested_mode ||
                        applied.at("restart_required")
                            .get<bool>() ||
                        !applied.at("runtime_ready")
                             .get<bool>()) {
                        throw std::runtime_error(
                            "transport manager did not "
                            "activate the requested "
                            "sing-box process mode");
                    }
                    maintenance->verify_held();
                    return applied.dump();
                } catch (const std::exception&
                             apply_error) {
                    try {
                        maintenance->verify_held();
                        write_file_atomically(
                            transports_path.string(),
                            previous_data);
                        (void)restart_transport_manager_and_wait_for_runtime(
                            ctx,
                            Sha256::hex(previous_data),
                            previous_mode,
                            maintenance.get());
                    } catch (const std::exception&
                                 rollback_error) {
                        throw ApiError(
                            "sing-box process mode switch "
                            "failed and rollback also "
                            "failed",
                            500,
                            nlohmann::json{
                                {"apply_error",
                                 apply_error.what()},
                                {"rollback_error",
                                 rollback_error.what()}}
                                .dump());
                    }
                    throw ApiError(
                        "sing-box process mode switch "
                        "failed; the previous mode was "
                        "restored",
                        500,
                        nlohmann::json{
                            {"error",
                             apply_error.what()}}
                            .dump());
                }
            } catch (const MaintenanceLockError& error) {
                throw_maintenance_api_error(error);
            }
        });

    server.get("/api/transports", [&ctx]() -> std::string {
        const auto endpoint = load_endpoint(ctx.config_path);
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(3, 0);
        const httplib::Headers headers{
            {"Authorization", "Bearer " + endpoint.api_key},
        };
        const auto response = client.Get("/v1/transports", headers);
        if (!response) {
            throw ApiError("transport manager is unavailable", 503);
        }
        if (response->status < 200 || response->status >= 300) {
            throw ApiError("transport manager returned HTTP " +
                               std::to_string(response->status),
                           502);
        }

        // Reject malformed companion responses before forwarding them to the UI.
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(response->body);
        } catch (const nlohmann::json::exception&) {
            throw ApiError("transport manager returned malformed JSON", 502);
        }
        if (!body.is_array()) {
            throw ApiError("transport manager returned an invalid response", 502);
        }
        for (const auto& status : body) {
            if (!valid_transport_status(status)) {
                throw ApiError(
                    "transport manager returned an invalid status item",
                    502);
            }
        }
        std::vector<std::string> traffic_interfaces;
        traffic_interfaces.reserve(body.size());
        for (const auto& status : body) {
            traffic_interfaces.push_back(
                status.at("interface").get<std::string>());
        }
        ctx.replace_interface_traffic_targets(
            "managed-transports", std::move(traffic_interfaces));
        return body.dump();
    });

    server.post("/api/transports", [&ctx](const std::string& request_body) -> std::string {
        nlohmann::json request;
        try {
            request = nlohmann::json::parse(request_body);
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid transport action JSON", 400);
        }

        if (!request.is_object() || !request.contains("tag") ||
            !request["tag"].is_string() || !request.contains("action") ||
            !request["action"].is_string()) {
            throw ApiError("transport action requires string tag and action", 400);
        }
        const auto tag = request["tag"].get<std::string>();
        const auto action = request["action"].get<std::string>();
        if (!valid_transport_tag(tag)) {
            throw ApiError("invalid transport tag", 400);
        }
        if (action != "up" && action != "down" && action != "restart") {
            throw ApiError("transport action must be up, down, or restart", 400);
        }

        const auto endpoint = load_endpoint(ctx.config_path);
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(15, 0);
        const httplib::Headers headers{
            {"Authorization", "Bearer " + endpoint.api_key},
        };
        const auto response = client.Post("/v1/transports/" + tag + "/" + action,
                                          headers,
                                          "",
                                          "application/json");
        if (!response) {
            throw ApiError("transport manager is unavailable", 503);
        }
        if (response->status < 200 || response->status >= 300) {
            throw ApiError("transport manager returned HTTP " +
                               std::to_string(response->status),
                           response->status == 404 ? 404 :
                           response->status == 400 ? 400 : 502,
                           response->body);
        }
        try {
            return nlohmann::json::parse(response->body).dump();
        } catch (const nlohmann::json::exception&) {
            throw ApiError("transport manager returned malformed JSON", 502);
        }
    });

    server.get("/api/transports/config", [&ctx]() -> std::string {
        const auto endpoint = load_endpoint(ctx.config_path);
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(3, 0);
        const httplib::Headers headers{
            {"Authorization", "Bearer " + endpoint.api_key},
        };
        const auto response = client.Get("/v1/config/transports", headers);
        if (!response) {
            throw ApiError("transport manager is unavailable", 503);
        }
        if (response->status < 200 || response->status >= 300) {
            throw ApiError("transport manager returned HTTP " +
                               std::to_string(response->status),
                           502);
        }
        try {
            auto body = nlohmann::json::parse(response->body);
            if (!body.is_array()) {
                throw ApiError("transport manager returned an invalid config response", 502);
            }
            for (auto& spec : body) {
                if (!valid_transport_spec_display_name(spec, false)) {
                    throw ApiError(
                        "transport manager returned an invalid transport alias",
                        502);
                }
                // The manager needs this identity internally so subscription
                // previews can recognise an existing secret link without
                // reading it. A SHA-256 of that link is still an offline
                // verifier for low-entropy proxy passwords and must not cross
                // the browser-facing API boundary.
                spec.erase("link_fingerprint");
            }
            return body.dump();
        } catch (const nlohmann::json::exception&) {
            throw ApiError("transport manager returned malformed JSON", 502);
        }
    });

    server.get("/api/transports/config/export", [&ctx]() -> std::string {
        const auto endpoint = load_endpoint(ctx.config_path);
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(5, 0);
        const httplib::Headers headers{
            {"Authorization", "Bearer " + endpoint.api_key},
        };
        const auto response = client.Get("/v1/config/transports/export", headers);
        if (!response) {
            throw ApiError("transport manager is unavailable", 503);
        }
        if (response->status < 200 || response->status >= 300) {
            throw ApiError("transport manager returned HTTP " +
                               std::to_string(response->status),
                           502);
        }
        try {
            const auto body = nlohmann::json::parse(response->body);
            if (!body.is_array()) {
                throw ApiError("transport manager returned an invalid export response", 502);
            }
            for (const auto& spec : body) {
                if (!valid_transport_spec_display_name(spec, false)) {
                    throw ApiError(
                        "transport manager returned an invalid transport alias",
                        502);
                }
            }
            return body.dump();
        } catch (const nlohmann::json::exception&) {
            throw ApiError("transport manager returned malformed JSON", 502);
        }
    });

    // Atomically create a managed transport and the interface outbound that
    // exposes it to keen-pbr. The browser never sends a complete core config:
    // the server derives the minimal outbound change from current persisted
    // state while the shared maintenance lease is held.
    server.post(
        "/api/transports/config/apply",
        [&ctx,
         commit_config = std::move(commit_config)](
            const std::string& request_body)
            -> std::string {
            nlohmann::json request;
            try {
                request =
                    nlohmann::json::parse(request_body);
            } catch (const nlohmann::json::exception&) {
                throw ApiError(
                    "invalid composite transport JSON", 400);
            }
            if (!request.is_object() ||
                request.value(
                    "operation", std::string{}) !=
                    "create" ||
                !request.contains("transport") ||
                !request.at("transport").is_object() ||
                !request.contains("linked_outbound") ||
                !request.at("linked_outbound").is_object()) {
                throw ApiError(
                    "composite transport create requires "
                    "transport and linked_outbound objects",
                    400);
            }
            for (auto iterator = request.begin();
                 iterator != request.end();
                 ++iterator) {
                if (iterator.key() != "operation" &&
                    iterator.key() != "transport" &&
                    iterator.key() != "linked_outbound") {
                    throw ApiError(
                        "unsupported composite transport "
                        "field: " +
                            iterator.key(),
                        400);
                }
            }

            const auto transport =
                request.at("transport");
            const auto linked =
                request.at("linked_outbound");
            for (auto iterator = linked.begin();
                 iterator != linked.end();
                 ++iterator) {
                if (iterator.key() != "mode" &&
                    iterator.key() != "display_name" &&
                    iterator.key() !=
                        "strict_enforcement") {
                    throw ApiError(
                        "unsupported linked outbound field: " +
                            iterator.key(),
                        400);
                }
            }
            if (linked.value(
                    "mode", std::string{}) != "ensure") {
                throw ApiError(
                    "the atomic endpoint currently supports "
                    "linked_outbound mode ensure only",
                    400);
            }
            if (!transport.contains("tag") ||
                !transport.at("tag").is_string() ||
                !valid_transport_tag(
                    transport.at("tag")
                        .get<std::string>()) ||
                !transport.contains("interface") ||
                !transport.at("interface").is_string() ||
                transport.at("interface")
                    .get_ref<const std::string&>()
                    .empty()) {
                throw ApiError(
                    "transport requires a valid tag and "
                    "interface",
                    400);
            }
            if (!valid_transport_spec_display_name(
                    transport, true)) {
                throw ApiError(
                    "transport display_name is invalid",
                    400);
            }
            if (linked.contains("display_name") &&
                (!linked.at("display_name").is_string() ||
                 !display_name::is_valid(
                     linked.at("display_name")
                         .get_ref<const std::string&>()))) {
                throw ApiError(
                    "linked outbound display_name is "
                    "invalid",
                    400);
            }
            if (linked.contains("strict_enforcement") &&
                !linked.at("strict_enforcement").is_null() &&
                !linked.at("strict_enforcement")
                     .is_boolean()) {
                throw ApiError(
                    "linked outbound strict_enforcement "
                    "must be boolean or null",
                    400);
            }

            return commit_config(
                ctx,
                "transport-linked-create",
                [&ctx,
                 transport,
                 linked]() -> PreparedConfigCommit {
                    if (ctx.config_is_draft()) {
                        throw ApiError(
                            "Save or discard the current "
                            "configuration draft before "
                            "creating a linked transport",
                            409);
                    }

                    auto candidate =
                        ctx.get_visible_config();
                    auto outbounds =
                        candidate.outbounds.value_or(
                            std::vector<Outbound>{});
                    const auto tag =
                        transport.at("tag")
                            .get<std::string>();
                    const auto interface_name =
                        transport.at("interface")
                            .get<std::string>();
                    for (const auto& outbound :
                         outbounds) {
                        if (outbound.tag == tag) {
                            throw ApiError(
                                "An outgoing route with tag '" +
                                    tag +
                                    "' already exists",
                                409);
                        }
                        if (outbound.type ==
                                OutboundType::INTERFACE &&
                            outbound.interface.has_value() &&
                            *outbound.interface ==
                                interface_name) {
                            throw ApiError(
                                "Interface '" +
                                    interface_name +
                                    "' is already owned by "
                                    "outgoing route '" +
                                    outbound.tag + "'",
                                409);
                        }
                    }

                    Outbound outbound;
                    outbound.type =
                        OutboundType::INTERFACE;
                    outbound.tag = tag;
                    outbound.interface = interface_name;
                    if (linked.contains("display_name")) {
                        outbound.display_name =
                            linked.at("display_name")
                                .get<std::string>();
                    } else if (
                        transport.contains(
                            "display_name") &&
                        transport.at("display_name")
                            .is_string() &&
                        !transport.at("display_name")
                             .get_ref<
                                 const std::string&>()
                             .empty()) {
                        outbound.display_name =
                            transport.at("display_name")
                                .get<std::string>();
                    }
                    if (linked.contains(
                            "strict_enforcement") &&
                        linked.at("strict_enforcement")
                            .is_boolean()) {
                        outbound.strict_enforcement =
                            linked.at(
                                "strict_enforcement")
                                .get<bool>();
                    }
                    outbounds.push_back(
                        std::move(outbound));
                    candidate.outbounds =
                        std::move(outbounds);

                    const auto endpoint =
                        load_endpoint(ctx.config_path);
                    TransportManagerClient client(endpoint);
                    const auto expected_revision =
                        client.current_revision();
                    client.validate_create(
                        transport, expected_revision);

                    PreparedConfigCommit prepared;
                    prepared.config =
                        std::move(candidate);
                    prepared.serialized =
                        serialize_config_for_persistence(
                            prepared.config);
                    prepared.success_status = "applied";
                    prepared.success_message =
                        "Transport and linked outgoing route "
                        "created";
                    prepared.transport =
                        ConfigCommitTransportEffect{
                            (std::filesystem::path(
                                 ctx.config_path)
                                 .parent_path() /
                             "transports.json")
                                .string(),
                            expected_revision,
                            [endpoint,
                             transport,
                             expected_revision]() {
                                return TransportManagerClient(
                                           endpoint)
                                    .create(
                                        transport,
                                        expected_revision);
                            },
                            [endpoint](
                                const std::string&
                                    revision) {
                                TransportManagerClient(
                                    endpoint)
                                    .wait_for_revision(
                                        revision);
                            },
                            [&ctx](
                                const std::string& revision,
                                MaintenanceLease& maintenance) {
                                restart_transport_manager_and_wait(
                                    ctx, revision, &maintenance);
                            },
                        };
                    return prepared;
                });
        });

    server.post("/api/transports/config", [&ctx](const std::string& request_body) -> std::string {
        nlohmann::json request;
        try {
            request = nlohmann::json::parse(request_body);
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid transport config operation JSON", 400);
        }
        if (!request.is_object() || !request.contains("operation") ||
            !request["operation"].is_string()) {
            throw ApiError("transport config operation is required", 400);
        }

        const auto operation = request["operation"].get<std::string>();
        std::string tag;
        if (operation == "update" || operation == "delete") {
            if (!request.contains("tag") || !request["tag"].is_string()) {
                throw ApiError("transport tag is required", 400);
            }
            tag = request["tag"].get<std::string>();
            if (!valid_transport_tag(tag)) {
                throw ApiError("invalid transport tag", 400);
            }
        }
        if ((operation == "create" || operation == "update") &&
            (!request.contains("transport") || !request["transport"].is_object())) {
            throw ApiError("transport object is required", 400);
        }
        if ((operation == "create" || operation == "update") &&
            !valid_transport_spec_display_name(request["transport"], true)) {
            throw ApiError(
                "transport display_name must be valid UTF-8, contain at most 80 "
                "Unicode code points, and contain no control characters",
                400);
        }
        if (operation != "create" && operation != "update" && operation != "delete") {
            throw ApiError("unsupported transport config operation", 400);
        }

        try {
            auto maintenance =
                ctx.acquire_maintenance_lease(
                    "transport-config-" + operation);
            (void)maintenance->reserve(
                maintenance->base_generation());

            const auto endpoint =
                load_endpoint(ctx.config_path);
            httplib::Client client(
                endpoint.host, endpoint.port);
            client.set_connection_timeout(1, 0);
            client.set_read_timeout(15, 0);
            const httplib::Headers headers{
                {"Authorization",
                 "Bearer " + endpoint.api_key},
            };
            const auto parse_response =
                [](const auto& response)
                    -> std::string {
                if (!response) {
                    throw ApiError(
                        "transport manager is unavailable",
                        503);
                }
                if (response->status < 200 ||
                    response->status >= 300) {
                    throw ApiError(
                        "transport manager returned HTTP " +
                            std::to_string(
                                response->status),
                        response->status == 400
                            ? 400
                            : response->status == 409
                                  ? 409
                                  : 502,
                        response->body);
                }
                try {
                    return nlohmann::json::parse(
                               response->body)
                        .dump();
                } catch (
                    const nlohmann::json::exception&) {
                    throw ApiError(
                        "transport manager returned "
                        "malformed JSON",
                        502);
                }
            };

            std::string result;
            if (operation == "create") {
                result = parse_response(client.Post(
                    "/v1/config/transports",
                    headers,
                    request["transport"].dump(),
                    "application/json"));
            } else if (operation == "update") {
                result = parse_response(client.Put(
                    "/v1/config/transports/" + tag,
                    headers,
                    request["transport"].dump(),
                    "application/json"));
            } else {
                result = parse_response(client.Delete(
                    "/v1/config/transports/" + tag,
                    headers));
            }
            maintenance->verify_held();
            return result;
        } catch (const MaintenanceLockError& error) {
            throw_maintenance_api_error(error);
        }
    });
}

void register_transports_handler(
    ApiServer& server,
    ApiContext& ctx) {
    register_transports_handler_impl(
        server,
        ctx,
        [](ApiContext& context,
           std::string operation,
           PrepareConfigCommit prepare) {
            return commit_prepared_config(
                context,
                std::move(operation),
                std::move(prepare));
        });
}

#ifdef KEEN_PBR3_TESTING
void register_transports_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options) {
    register_transports_handler_impl(
        server,
        ctx,
        [write_config_file =
             std::move(write_config_file),
         options = std::move(options)](
            ApiContext& context,
            std::string operation,
            PrepareConfigCommit prepare) {
            return commit_prepared_config_for_test(
                context,
                std::move(operation),
                std::move(prepare),
                write_config_file,
                options);
        });
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
