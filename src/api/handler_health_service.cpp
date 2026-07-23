#ifdef WITH_API

#include "handler_health_service.hpp"
#include "generated/api_types.hpp"
#include "update_version.hpp"
#include "handler_backup.hpp"
#include "../http/http_client.hpp"

#include <keen-pbr/version.hpp>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

#include <unistd.h>

namespace keen_pbr3 {

namespace {

constexpr const char* kUpdatePidFile = "/opt/var/run/keen-pbr-self-update.pid";
constexpr const char* kUpdateLogFile = "/opt/var/log/keen-pbr-self-update.log";
constexpr const char* kUpdateStateFile = "/opt/var/run/keen-pbr-self-update.json";
constexpr const char* kRescueHelper =
    "/opt/var/lib/keen-pbr/rescue/rescue-update.sh";
constexpr const char* kCurrentPackage =
    "/opt/var/lib/keen-pbr/rescue/current.ipk";
constexpr const char* kPreviousPackage =
    "/opt/var/lib/keen-pbr/rescue/previous.ipk";

std::string read_file_tail(const std::filesystem::path& path,
                           std::streamoff limit) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) return {};

    std::ifstream input(path, std::ios::binary);
    if (input && size > static_cast<std::uintmax_t>(limit)) {
        input.seekg(static_cast<std::streamoff>(size) - limit);
    }
    if (!input) return {};
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

std::optional<pid_t> read_update_pid() {
    std::ifstream input(kUpdatePidFile);
    long value = 0;
    if (!(input >> value) || value <= 1) return std::nullopt;
    return static_cast<pid_t>(value);
}

bool is_update_process(pid_t pid) {
    if (::kill(pid, 0) != 0 && errno != EPERM) return false;

    const auto cmdline = read_file_tail(
        std::filesystem::path("/proc") / std::to_string(pid) / "cmdline",
        16 * 1024);
    return cmdline.find("keen-pbr/self-update.sh") != std::string::npos ||
           cmdline.find("keen-pbr-self-update") != std::string::npos ||
           cmdline.find("rescue-update.sh") != std::string::npos;
}

bool update_is_running() {
    const auto pid = read_update_pid();
    if (pid && is_update_process(*pid)) return true;

    // A PID file is only a hint. Power loss, SIGKILL or PID reuse can leave it
    // behind, so remove it unless it points to this exact live helper.
    std::error_code ec;
    std::filesystem::remove(kUpdatePidFile, ec);
    return false;
}

nlohmann::json local_update_status() {
    nlohmann::json status = nlohmann::json::object();
    try {
        std::ifstream input(kUpdateStateFile, std::ios::binary);
        if (input) status = nlohmann::json::parse(input);
        if (!status.is_object()) status = nlohmann::json::object();
    } catch (const nlohmann::json::exception&) {
        status = nlohmann::json::object();
    }

    status["running"] = update_is_running();
    status["log"] = read_file_tail(kUpdateLogFile, 24 * 1024);
    std::error_code ec;
    status["package_rescue_ready"] =
        std::filesystem::is_regular_file(kRescueHelper, ec) &&
        std::filesystem::is_regular_file(kCurrentPackage, ec);
    ec.clear();
    status["package_rollback_available"] =
        std::filesystem::is_regular_file(kPreviousPackage, ec);
    return status;
}

std::mutex& update_start_mutex() {
    static std::mutex mutex;
    return mutex;
}

} // namespace

void register_health_service_handler(ApiServer& server, ApiContext& ctx) {
    // GET /api/health/service - daemon version/status + resolver/config summary
    server.get("/api/health/service", [&ctx]() -> std::string {
        return nlohmann::json(
                   build_health_response(ctx.get_service_health()))
            .dump();
    });

    server.get("/api/system/update", []() -> std::string {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(15));
        client.set_max_response_size(512U * 1024U);
        const auto release = nlohmann::json::parse(client.download(
            "https://api.github.com/repos/blindtechnique/keen-pbr-sb/releases/latest"));
        const auto latest = release.value("tag_name", std::string{});
        const std::string current = std::string("v") + KEEN_PBR3_VERSION_STRING +
                                    "-sb." + KEEN_PBR3_VERSION_RELEASE_STRING;
        auto release_notes = release.value("body", std::string{});
        constexpr std::size_t kReleaseNotesLimit = 64U * 1024U;
        if (release_notes.size() > kReleaseNotesLimit) {
            release_notes.resize(kReleaseNotesLimit);
            release_notes += "\n\n…";
        }
        const auto release_url = release.value("html_url", std::string{});
        const auto release_name = release.value("name", std::string{});
        const auto changelog_url = safe_github_tag(latest)
            ? std::string("https://github.com/blindtechnique/keen-pbr-sb/blob/") +
                  latest + "/CHANGELOG.md"
            : std::string{};
        auto response = local_update_status();
        response.update(nlohmann::json{{"current", current},
                                       {"latest", latest},
                                       {"available", is_newer_fork_version(latest, current)},
                                       {"current_ahead", is_newer_fork_version(current, latest)},
                                       {"release_name", release_name},
                                       {"release_notes", release_notes},
                                       {"release_url", release_url},
                                       {"changelog_url", changelog_url}});
        return response.dump();
    });

    // Local-only endpoint for cheap progress polling. Unlike the release check
    // it never contacts GitHub, so a running update does not generate a remote
    // request every three seconds.
    server.get("/api/system/update/status", []() -> std::string {
        return local_update_status().dump();
    });

    server.post("/api/system/update", [&ctx]() -> std::string {
        const std::lock_guard lock(update_start_mutex());
        const std::filesystem::path helper =
            "/opt/usr/lib/keen-pbr/self-update.sh";
        std::error_code ec;
        if (!std::filesystem::is_regular_file(helper, ec))
            throw ApiError("self-update helper is not installed", 409);
        if (update_is_running())
            throw ApiError("keen-pbr-sb update is already running", 409);
        create_full_rollback_backup(ctx);
        const int status = std::system(
            "/opt/usr/lib/keen-pbr/self-update.sh >/dev/null 2>&1 &");
        if (status != 0) throw ApiError("failed to start keen-pbr-sb update", 500);
        return R"({"ok":true,"started":true})";
    });

    server.post("/api/system/update/rollback", [&ctx]() -> std::string {
        const std::lock_guard lock(update_start_mutex());
        if (update_is_running())
            throw ApiError("keen-pbr-sb update or rollback is already running", 409);
        std::error_code ec;
        if (!std::filesystem::is_regular_file(kRescueHelper, ec) ||
            !std::filesystem::is_regular_file(kPreviousPackage, ec)) {
            throw ApiError(
                "previous IPK is not available; complete one managed update first",
                409);
        }

        create_full_rollback_backup(ctx);
        const int status = std::system(
            "(sleep 1; /opt/var/lib/keen-pbr/rescue/rescue-update.sh "
            "rollback-previous) >/dev/null 2>&1 &");
        if (status != 0)
            throw ApiError("failed to start keen-pbr-sb package rollback", 500);
        return R"({"ok":true,"started":true})";
    });
}

} // namespace keen_pbr3

#endif // WITH_API
