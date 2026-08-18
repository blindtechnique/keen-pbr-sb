#ifdef WITH_API

#include "handler_transports.hpp"
#include "handler_config.hpp"
#include "maintenance_api.hpp"
#include "status_stream.hpp"
#include "transport_manager_endpoint.hpp"

#include "../config/config_writer.hpp"
#include "../crypto/sha256.hpp"
#include "../util/display_name.hpp"
#include "../util/safe_exec.hpp"
#include "../update/sing_box_install_observation.hpp"
#include "../update/sing_box_install_policy.hpp"
#include "../update/sing_box_install_steps.hpp"
#include "../update/sing_box_transport_pause.hpp"
#include "../update/sing_box_installer.hpp"

#include <keen-pbr/version.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <httplib.h>
#include <initializer_list>
#include <iterator>
#include <mutex>
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

// The managed sing-box transports currently running, by tag. Throws rather
// than returning an empty list when the manager cannot answer, so an
// unreachable manager reaches the policy as "nobody could ask" instead of as
// "nothing is running".
//
// Tags rather than a count, because the two callers need the same set for
// different reasons - one asks how many would be disturbed, the other has to
// stop exactly these and start exactly these again - and deriving both from
// one read is what keeps them from disagreeing about which transports those
// are.
std::vector<std::string> running_sing_box_transport_tags(
    const TransportManagerEndpoint& endpoint) {
    httplib::Client client(endpoint.host, endpoint.port);
    client.set_connection_timeout(1, 0);
    client.set_read_timeout(3, 0);
    const httplib::Headers headers{
        {"Authorization", "Bearer " + endpoint.api_key},
    };
    const auto response = client.Get("/v1/transports", headers);
    if (!response || response->status < 200 || response->status >= 300) {
        throw ApiError("transport manager is unavailable", 503);
    }
    const auto body = nlohmann::json::parse(response->body, nullptr, false);
    if (body.is_discarded() || !body.is_array()) {
        throw ApiError(
            "transport manager returned an invalid runtime state", 502);
    }
    std::vector<std::string> running;
    for (const auto& status : body) {
        if (!status.is_object()) continue;
        const auto type = status.value("type", std::string{});
        if (type.rfind("sing-box", 0U) != 0U) continue;
        // Anything that is not `down` has a process attached to the binary
        // about to be replaced. `degraded` and `starting` count for exactly
        // that reason.
        if (status.value("state", std::string{}) == "down") continue;
        const auto tag = status.value("tag", std::string{});
        // A running transport whose tag the manager did not report cannot be
        // stopped by name, so it must not be counted as one this daemon could
        // put back. It still blocks - it is running on the binary.
        running.push_back(tag);
    }
    return running;
}

std::size_t count_running_sing_box_transports(
    const TransportManagerEndpoint& endpoint) {
    return running_sing_box_transport_tags(endpoint).size();
}

// Never throws: this is used on the path that puts an operator's tunnels back,
// and a throw there would abandon the remaining ones.
bool transport_action(const TransportManagerEndpoint& endpoint,
                      const std::string& tag,
                      const char* action) noexcept {
    try {
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(20, 0);
        const httplib::Headers headers{
            {"Authorization", "Bearer " + endpoint.api_key},
        };
        const auto response = client.Post(
            "/v1/transports/" + tag + "/" + action, headers, "",
            "application/json");
        return response && response->status >= 200 && response->status < 300;
    } catch (...) {
        return false;
    }
}

api::InstallOutcome api_install_outcome(
    const SingBoxInstallOutcome outcome) {
    switch (outcome) {
    case SingBoxInstallOutcome::installed:
        return api::InstallOutcome::INSTALLED;
    case SingBoxInstallOutcome::release_refused:
        return api::InstallOutcome::RELEASE_REFUSED;
    case SingBoxInstallOutcome::download_failed:
        return api::InstallOutcome::DOWNLOAD_FAILED;
    case SingBoxInstallOutcome::checksum_mismatch:
        return api::InstallOutcome::CHECKSUM_MISMATCH;
    case SingBoxInstallOutcome::archive_unusable:
        return api::InstallOutcome::ARCHIVE_UNUSABLE;
    case SingBoxInstallOutcome::staged_version_mismatch:
        return api::InstallOutcome::STAGED_VERSION_MISMATCH;
    case SingBoxInstallOutcome::install_failed:
        return api::InstallOutcome::INSTALL_FAILED;
    case SingBoxInstallOutcome::marker_not_written:
        return api::InstallOutcome::MARKER_NOT_WRITTEN;
    case SingBoxInstallOutcome::cancelled:
        return api::InstallOutcome::CANCELLED;
    }
    return api::InstallOutcome::INSTALL_FAILED;
}

api::ReleaseVerdict api_release_verdict(
    const SingBoxReleaseVerdict verdict) {
    switch (verdict) {
    case SingBoxReleaseVerdict::ready:
        return api::ReleaseVerdict::READY;
    case SingBoxReleaseVerdict::release_unreadable:
        return api::ReleaseVerdict::RELEASE_UNREADABLE;
    case SingBoxReleaseVerdict::archive_missing:
        return api::ReleaseVerdict::ARCHIVE_MISSING;
    case SingBoxReleaseVerdict::checksums_missing:
        return api::ReleaseVerdict::CHECKSUMS_MISSING;
    case SingBoxReleaseVerdict::checksum_unusable:
        return api::ReleaseVerdict::CHECKSUM_UNUSABLE;
    case SingBoxReleaseVerdict::checksum_mismatch:
        return api::ReleaseVerdict::CHECKSUM_MISMATCH;
    }
    return api::ReleaseVerdict::RELEASE_UNREADABLE;
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

// The install replaces the binary every sing-box transport runs on and takes a
// minute or more inside one request. Until this existed the operator watched a
// spinner: a slow download from GitHub and a hung one looked identical, and a
// second tab could not tell that anything was happening at all.
//
// The name a phase is broadcast under comes from the installer's own sequence
// (sing_box_install_phase_name), never from a list assembled here, so the
// display cannot describe a step the code no longer performs.
//
// Never throws. An install must not fail because nobody was listening to its
// progress - which is also why install_pinned_sing_box does not guard the
// observer call: the guard lives here, at the one place that can actually
// throw, instead of somewhere it could never fire.
void publish_sing_box_install_progress(
    const ApiContext& ctx,
    const std::string& phase,
    const bool active,
    const std::string& outcome,
    const std::uint64_t received = 0U,
    const std::uint64_t total = 0U) noexcept {
    if (ctx.status_stream == nullptr) return;
    try {
        nlohmann::json frame{
            {"phase", phase},
            {"active", active},
            {"pinned_version", KEEN_PBR3_SING_BOX_PINNED_VERSION},
            {"outcome", outcome}};
        // Only when there is something to say. A frame carrying zero bytes on
        // a phase that downloads nothing would invite a client to render a bar
        // stuck at nothing.
        if (received > 0U) frame["received_bytes"] = received;
        // And the total only when the server actually gave one. Zero is not a
        // size, it is the absence of one, and a client that divided by it
        // would show a percentage nobody measured.
        if (total > 0U) frame["total_bytes"] = total;
        ctx.status_stream->publish_sing_box_install(std::move(frame));
    } catch (...) {
    }
}

// The one install this daemon may be running, and whether stopping it is still
// free.
//
// Process-wide because the thing being protected is process-wide: there is one
// binary at one path, and the maintenance lease already means there is at most
// one install. This only has to answer "is there one, and may it still be
// stopped".
struct SingBoxInstallCancellation {
    std::mutex mutex;
    std::shared_ptr<std::atomic<bool>> token;
    // Cleared the moment the install reaches a phase that changes the router.
    // From then on a cancel is refused rather than queued: there is no version
    // of stopping a binary swap that leaves an operator better off than
    // letting it finish.
    bool reversible{false};
};

SingBoxInstallCancellation& sing_box_install_cancellation() {
    static SingBoxInstallCancellation state;
    return state;
}

// Guarantees every page watching is told the install ended, on every path out.
//
// Without it a throw between the first phase and the last - a lost maintenance
// lease, an unreachable manager - leaves every open page rendering progress
// for an install that stopped minutes ago, and offering no way back. The paths
// that throw here are failures, which is exactly when somebody is watching.
//
// Armed by construction, so it is constructed only once the install is going
// to be attempted: a refusal that never started one must not broadcast that
// one finished.
class SingBoxInstallProgressReporter {
public:
    explicit SingBoxInstallProgressReporter(const ApiContext& ctx)
        : ctx_(ctx) {}

    ~SingBoxInstallProgressReporter() {
        if (!finished_) {
            publish_sing_box_install_progress(ctx_, "finished", false,
                                              "aborted");
        }
    }

    SingBoxInstallProgressReporter(const SingBoxInstallProgressReporter&) =
        delete;
    SingBoxInstallProgressReporter& operator=(
        const SingBoxInstallProgressReporter&) = delete;

    void phase(const SingBoxInstallPhase phase) {
        {
            // The point of no return is the phase list itself, so a phase
            // added later cannot quietly become cancellable.
            auto& state = sing_box_install_cancellation();
            const std::lock_guard<std::mutex> lock(state.mutex);
            state.reversible = sing_box_install_phase_is_reversible(phase);
        }
        current_phase_ = sing_box_install_phase_name(phase);
        last_published_ = std::chrono::steady_clock::time_point{};
        publish_sing_box_install_progress(ctx_, current_phase_, true, {});
    }

    // Bytes for whichever phase is running. Rate-limited because curl calls
    // this many times a second and every call would be an SSE frame to every
    // open page: a progress display that floods the stream it travels on is
    // not an improvement on no progress display.
    void bytes(const std::uint64_t received,
               const std::uint64_t total) noexcept {
        const auto now = std::chrono::steady_clock::now();
        if (now - last_published_ < std::chrono::milliseconds(500)) return;
        last_published_ = now;
        publish_sing_box_install_progress(ctx_, current_phase_, true, {},
                                          received, total);
    }

    void finish(const std::string& outcome) {
        publish_sing_box_install_progress(ctx_, "finished", false, outcome);
        finished_ = true;
    }

private:
    const ApiContext& ctx_;
    std::string current_phase_;
    std::chrono::steady_clock::time_point last_published_{};
    bool finished_{false};
};

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
    // Installs the pinned release, and only when the capability that measured
    // this router says it may. The capability is re-taken here rather than
    // trusted from whatever the browser last read: between that read and this
    // request an operator may have started a tunnel, and the whole point of
    // the transports_running blocker is that the binary is not swapped from
    // under one.
    server.post(
        "/api/transports/sing-box/install",
        [&ctx](const std::string& request_body) -> std::string {
            // Absent body means no consent, which is the safe reading: an
            // install that stopped somebody's VPN because a field was missing
            // would be the worst possible default.
            bool stop_running = false;
            if (!request_body.empty()) {
                const auto parsed =
                    nlohmann::json::parse(request_body, nullptr, false);
                if (parsed.is_discarded() || !parsed.is_object()) {
                    throw ApiError(
                        "sing-box install body must be a JSON object", 400);
                }
                stop_running =
                    parsed.value("stop_running_transports", false);
            }

            const auto binary = configured_sing_box_binary(ctx.config_path);
            const auto endpoint = load_endpoint(ctx.config_path);
            auto probes = production_sing_box_install_probes();
            probes.count_running_transports =
                [&endpoint]() -> std::optional<std::size_t> {
                // A manager that cannot answer is reported as unknown, not as
                // an error out of the handler. Letting it escape would fail
                // the whole read with no detail and make the blocker it should
                // have produced unreachable - and this route exists to say
                // what this router can do, of which "the manager is down" is
                // an answer rather than a failure to answer.
                try {
                    return count_running_sing_box_transports(endpoint);
                } catch (const ApiError&) {
                    return std::nullopt;
                }
            };

            SingBoxInstallPaths paths;
            paths.binary_path = binary;
            paths.managed_marker_path = kSingBoxManagedMarkerPath;

            const auto refuse = [](const SingBoxInstallPolicy& policy) {
                nlohmann::json blockers = nlohmann::json::array();
                for (const auto blocker : policy.blockers) {
                    blockers.push_back(
                        sing_box_install_blocker_name(blocker));
                }
                throw ApiError(
                    "the sing-box install is not available on this router",
                    409,
                    nlohmann::json{
                        {"error",
                         "the sing-box install is not available on this "
                         "router"},
                        {"reason", "install_unavailable"},
                        {"blockers", blockers},
                    }
                        .dump());
            };

            const auto observation = observe_sing_box_install(
                probes, paths.binary_path, paths.managed_marker_path);
            auto policy = evaluate_sing_box_install(
                observation, KEEN_PBR3_SING_BOX_PINNED_VERSION);

            // Which blockers consent can answer is a decision, so it lives
            // with the other decisions in src/update rather than here.
            const bool pausing =
                stop_running &&
                sing_box_install_awaits_transport_consent(policy);
            if (!policy.available && !pausing) refuse(policy);

            try {
                auto maintenance =
                    ctx.acquire_maintenance_lease("sing-box-install");
                (void)maintenance->reserve(maintenance->base_generation());

                // Constructed after the lease, so nobody's tunnel goes down
                // for an install that then could not start. Its destructor
                // brings them back on every path out of this block, including
                // the ones that throw.
                std::optional<SingBoxTransportPause> pause;
                if (pausing) {
                    pause.emplace(
                        [&endpoint](const std::string& tag,
                                    const char* action) {
                            return transport_action(endpoint, tag, action);
                        },
                        running_sing_box_transport_tags(endpoint));
                    if (!pause->all_stopped()) {
                        // Something is still running on the binary about to be
                        // replaced. The pause destructor restarts whatever it
                        // did stop.
                        refuse(policy);
                    }
                    // Re-measured with the transports actually down, rather
                    // than assumed: the consent authorised stopping them, not
                    // skipping the check that they are stopped.
                    const auto after = observe_sing_box_install(
                        probes, paths.binary_path,
                        paths.managed_marker_path);
                    policy = evaluate_sing_box_install(
                        after, KEEN_PBR3_SING_BOX_PINNED_VERSION);
                    if (!policy.available) refuse(policy);
                }

                const std::string release_url =
                    std::string(
                        "https://api.github.com/repos/SagerNet/sing-box/"
                        "releases/tags/v") +
                    KEEN_PBR3_SING_BOX_PINNED_VERSION;

                // Armed here, after the capability allowed the install and the
                // lease was taken, so a refusal cannot announce the end of an
                // install that never began.
                SingBoxInstallProgressReporter progress(ctx);

                // Registered for the whole attempt and cleared on every path
                // out, so a cancel arriving after this install has finished
                // cannot abort the next one.
                auto cancellation = std::make_shared<std::atomic<bool>>(false);
                struct CancellationScope {
                    ~CancellationScope() {
                        auto& state = sing_box_install_cancellation();
                        const std::lock_guard<std::mutex> lock(state.mutex);
                        state.token.reset();
                        state.reversible = false;
                    }
                } cancellation_scope;
                {
                    auto& state = sing_box_install_cancellation();
                    const std::lock_guard<std::mutex> lock(state.mutex);
                    state.token = cancellation;
                    state.reversible = true;
                }

                // Anything a previous run left behind is removed first: the
                // run that failed to clean up is by definition the one that
                // could not run its own cleanup.
                discard_sing_box_staging(paths);
                auto report = install_pinned_sing_box(
                    production_sing_box_install_steps(
                        paths,
                        [&progress](const std::uint64_t received,
                                    const std::uint64_t total) {
                            progress.bytes(received, total);
                        },
                        cancellation),
                    release_url,
                    KEEN_PBR3_SING_BOX_PINNED_VERSION,
                    policy.asset_architecture,
                    [&progress](const SingBoxInstallPhase phase) {
                        progress.phase(phase);
                    });
                discard_sing_box_staging(paths);

                // A fetch aborted on purpose reports the same failure as one
                // that broke, and "the download failed" would send an operator
                // looking for a network problem they caused themselves.
                if (cancellation->load(std::memory_order_relaxed) &&
                    report.outcome ==
                        SingBoxInstallOutcome::download_failed) {
                    report.outcome = SingBoxInstallOutcome::cancelled;
                }

                // The lease is still held, so a lost one is reported as an
                // abort rather than as the outcome of an install whose result
                // this request is no longer entitled to publish.
                maintenance->verify_held();

                api::SingBoxInstallResult result;
                result.install_outcome =
                    api_install_outcome(report.outcome);
                result.pinned_version =
                    KEEN_PBR3_SING_BOX_PINNED_VERSION;
                if (report.outcome !=
                    SingBoxInstallOutcome::installed) {
                    result.release_verdict =
                        api_release_verdict(report.release_verdict);
                }
                if (!report.staged_version.empty()) {
                    result.staged_version = report.staged_version;
                }
                if (pause) {
                    // Started again here rather than left to the destructor,
                    // so the response can report which ones did not come back.
                    // A destructor cannot tell the operator anything.
                    const std::vector<std::string> stopped = pause->stopped();
                    pause->resume();
                    result.stopped_transports = stopped;
                    if (!pause->left_down().empty()) {
                        result.transports_left_down = pause->left_down();
                    }
                }

                // Released before anything says the install is over, and only
                // now. Every other tab derives "an install is running" from
                // the terminal frame, so announcing the end while the lease is
                // still held re-enables their button into a window where the
                // daemon answers 409 - to this install, to a config save, to
                // an nfqws upgrade. Saying it late is a moment of stale
                // "busy"; saying it early is a lie to every open page.
                maintenance.reset();
                progress.finish(
                    sing_box_install_outcome_name(report.outcome));
                if (report.outcome == SingBoxInstallOutcome::installed) {
                    Logger::instance().info(
                        "sing-box {} installed at {}",
                        KEEN_PBR3_SING_BOX_PINNED_VERSION,
                        paths.binary_path);
                } else {
                    Logger::instance().warn(
                        "sing-box install did not complete: {}",
                        sing_box_install_outcome_name(report.outcome));
                }
                return nlohmann::json(result).dump();
            } catch (const MaintenanceLockError& error) {
                throw_maintenance_api_error(error);
            }
        });

    // Stops an install that has not changed anything yet.
    //
    // Refused once the binary swap has begun, and that is the whole design: a
    // half-written binary is worse than an unwanted new one, and an operator
    // who asks to stop wants their router working, not broken sooner. The
    // refusal says which of the two reasons it is, because "nothing is
    // running" and "too late" are different facts about their router.
    server.post("/api/transports/sing-box/install/cancel",
                []() -> std::string {
        auto& state = sing_box_install_cancellation();
        const std::lock_guard<std::mutex> lock(state.mutex);
        if (!state.token) {
            throw ApiError(
                "no sing-box install is running",
                409,
                nlohmann::json{{"error", "no sing-box install is running"},
                               {"reason", "not_running"}}
                    .dump());
        }
        if (!state.reversible) {
            throw ApiError(
                "the sing-box install can no longer be stopped",
                409,
                nlohmann::json{
                    {"error", "the sing-box install can no longer be stopped"},
                    {"reason", "past_point_of_no_return"}}
                    .dump());
        }
        state.token->store(true, std::memory_order_relaxed);
        return nlohmann::json{{"cancelling", true}}.dump();
    });

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
                [&endpoint]() -> std::optional<std::size_t> {
                // Reported as unknown rather than thrown out of the handler.
                // This route exists to say what this router can do, and "the
                // transport manager is down" is one of the things it can say;
                // letting the exception escape failed the whole read with no
                // detail and made transport_state_unknown unreachable.
                try {
                    return count_running_sing_box_transports(endpoint);
                } catch (const ApiError&) {
                    return std::nullopt;
                }
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
            if (observation.running_transports.has_value()) {
                // Absent when nobody could ask, which is exactly the
                // transport_state_unknown blocker: a client must not read a
                // missing count as zero.
                capability.running_transports = static_cast<int64_t>(
                    *observation.running_transports);
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
