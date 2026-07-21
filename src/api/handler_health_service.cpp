#ifdef WITH_API

#include "handler_health_service.hpp"
#include "generated/api_types.hpp"
#include "update_version.hpp"
#include "handler_backup.hpp"
#include "../http/http_client.hpp"

#include <keen-pbr/version.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>

namespace keen_pbr3 {

void register_health_service_handler(ApiServer& server, ApiContext& ctx) {
    // GET /api/health/service - daemon version/status + resolver/config summary
    server.get("/api/health/service", [&ctx]() -> std::string {
        const auto service_health = ctx.get_service_health();
        api::HealthResponse resp;
        resp.version = KEEN_PBR3_VERSION_STRING;
        resp.build = KEEN_PBR3_VERSION_RELEASE_STRING;
        resp.status = service_health.status;
        resp.os_type = service_health.os_type;
        resp.os_version = service_health.os_version;
        resp.build_variant = service_health.build_variant;
        resp.resolver_config_hash = service_health.resolver_config_hash;
        resp.resolver_config_hash_actual = service_health.resolver_config_hash_actual;
        resp.resolver_config_hash_actual_ts = service_health.resolver_config_hash_actual_ts;
        resp.resolver_live_status = service_health.resolver_live_status;
        resp.resolver_config_probe_status = service_health.resolver_config_probe_status;
        resp.resolver_last_probe_ts = service_health.resolver_last_probe_ts;
        resp.apply_started_ts = service_health.apply_started_ts;
        resp.resolver_config_sync_state = service_health.resolver_config_sync_state;

        nlohmann::json response = resp;
        response["config_is_draft"] = service_health.config_is_draft;
        return response.dump();
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
        const std::filesystem::path running_file =
            "/opt/var/run/keen-pbr-self-update.pid";
        const std::filesystem::path log_file =
            "/opt/var/log/keen-pbr-self-update.log";
        std::string log;
        std::error_code ec;
        const auto size = std::filesystem::file_size(log_file, ec);
        if (!ec) {
            std::ifstream input(log_file, std::ios::binary);
            constexpr std::streamoff kLogLimit = 24 * 1024;
            if (input && size > static_cast<std::uintmax_t>(kLogLimit))
                input.seekg(static_cast<std::streamoff>(size) - kLogLimit);
            if (input) log.assign(std::istreambuf_iterator<char>(input),
                                  std::istreambuf_iterator<char>());
        }
        return nlohmann::json{{"current", current},
                              {"latest", latest},
                              {"available", is_newer_fork_version(latest, current)},
                              {"current_ahead", is_newer_fork_version(current, latest)},
                              {"release_name", release_name},
                              {"release_notes", release_notes},
                              {"release_url", release_url},
                              {"changelog_url", changelog_url},
                              {"running", std::filesystem::is_regular_file(running_file, ec)},
                              {"log", log}}
            .dump();
    });

    server.post("/api/system/update", [&ctx]() -> std::string {
        const std::filesystem::path helper =
            "/opt/usr/lib/keen-pbr/self-update.sh";
        const std::filesystem::path running_file =
            "/opt/var/run/keen-pbr-self-update.pid";
        std::error_code ec;
        if (!std::filesystem::is_regular_file(helper, ec))
            throw ApiError("self-update helper is not installed", 409);
        if (std::filesystem::is_regular_file(running_file, ec))
            throw ApiError("keen-pbr-sb update is already running", 409);
        create_full_rollback_backup(ctx);
        const int status = std::system(
            "/opt/usr/lib/keen-pbr/self-update.sh >/dev/null 2>&1 &");
        if (status != 0) throw ApiError("failed to start keen-pbr-sb update", 500);
        return R"({"ok":true,"started":true})";
    });
}

} // namespace keen_pbr3

#endif // WITH_API
