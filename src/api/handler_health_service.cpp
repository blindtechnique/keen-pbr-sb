#ifdef WITH_API

#include "handler_health_service.hpp"
#include "generated/api_types.hpp"
#include "update_version.hpp"
#include "handler_backup.hpp"
#include "../http/http_client.hpp"
#include "../update/rescue_integrity.hpp"

#include <keen-pbr/version.hpp>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

#include <unistd.h>

namespace keen_pbr3 {

namespace {

constexpr const char* kUpdatePidFile = "/opt/var/run/keen-pbr-self-update.pid";
constexpr const char* kUpdateLogFile = "/opt/var/log/keen-pbr-self-update.log";
constexpr const char* kUpdateStateFile = "/opt/var/run/keen-pbr-self-update.json";
constexpr const char* kUpdateLockPid =
    "/opt/var/run/keen-pbr-update.lock/pid";
constexpr const char* kUpdateLockOwner =
    "/opt/var/run/keen-pbr-update.lock/owner";
constexpr const char* kUpdateLockReady =
    "/opt/var/run/keen-pbr-update.lock/ready";
constexpr const char* kUpdateLockStart =
    "/opt/var/run/keen-pbr-update.lock/start";
constexpr const char* kRescueHelper =
    "/opt/var/lib/keen-pbr/rescue/rescue-update.sh";
constexpr const char* kCurrentPackage =
    "/opt/var/lib/keen-pbr/rescue/current.ipk";
constexpr const char* kPreviousPackage =
    "/opt/var/lib/keen-pbr/rescue/previous.ipk";
constexpr const char* kPreviousPackageConfig =
    "/opt/var/lib/keen-pbr/rescue/previous-config";
constexpr const char* kPendingUpdate =
    "/opt/var/lib/keen-pbr/rescue/pending";
constexpr const char* kUnknownUpdate =
    "/opt/var/lib/keen-pbr/rescue/UNKNOWN";
constexpr const char* kReleaseCacheFile =
    "/opt/var/cache/keen-pbr/software-release.json";
constexpr auto kReleaseCacheTtl = std::chrono::hours(1);

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

std::optional<pid_t> read_pid_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    long value = 0;
    if (!(input >> value) || value <= 1) return std::nullopt;
    return static_cast<pid_t>(value);
}

std::optional<std::string> process_start_time(pid_t pid) {
    std::ifstream input(std::filesystem::path("/proc") /
                        std::to_string(pid) / "stat");
    std::string stat;
    if (!std::getline(input, stat)) return std::nullopt;
    const auto comm_end = stat.rfind(") ");
    if (comm_end == std::string::npos) return std::nullopt;
    std::istringstream fields(stat.substr(comm_end + 2));
    std::string value;
    // The substring begins at field 3; starttime is field 22.
    for (int field = 3; field <= 22; ++field) {
        if (!(fields >> value)) return std::nullopt;
    }
    return value;
}

std::optional<std::string> read_single_line(
    const std::filesystem::path& path) {
    std::ifstream input(path);
    std::string value;
    if (!std::getline(input, value) || value.empty()) return std::nullopt;
    return value;
}

bool regular_nonempty_file(const std::filesystem::path& path) {
    return rescue_integrity::regular_nonempty_file(path);
}

bool executable_nonempty_file(const std::filesystem::path& path) {
    return regular_nonempty_file(path) &&
           ::access(path.c_str(), X_OK) == 0;
}

bool recovery_marker_present(const std::filesystem::path& path) {
    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    // An unreadable rescue directory must never be interpreted as healthy.
    return exists || static_cast<bool>(ec);
}

bool update_recovery_is_blocked() {
    return recovery_marker_present(kPendingUpdate) ||
           recovery_marker_present(kUnknownUpdate);
}

bool is_update_process(pid_t pid) {
    if (::kill(pid, 0) != 0 && errno != EPERM) return false;

    const auto cmdline = read_file_tail(
        std::filesystem::path("/proc") / std::to_string(pid) / "cmdline",
        16 * 1024);
    return cmdline.find("keen-pbr/self-update.sh") != std::string::npos ||
           cmdline.find("keen-pbr-self-update") != std::string::npos ||
           cmdline.find("rescue-update.sh") != std::string::npos ||
           cmdline.find("keen-pbr-sb-update.") != std::string::npos ||
           cmdline.find("/install.sh") != std::string::npos;
}

bool update_is_running() {
    const auto pid = read_pid_file(kUpdatePidFile);
    if (pid && is_update_process(*pid)) return true;

    // A PID file is only a hint. Power loss, SIGKILL or PID reuse can leave it
    // behind, so remove it unless it points to this exact live helper.
    std::error_code ec;
    std::filesystem::remove(kUpdatePidFile, ec);

    // The common mkdir lock also covers CLI installs and the small interval
    // before the self-update helper has written its compatibility PID file.
    // Trust a live owner only when the lock was fully published.
    if (regular_nonempty_file(kUpdateLockReady)) {
        std::optional<pid_t> lock_pid;
        std::optional<std::string> expected_start;
        if (regular_nonempty_file(kUpdateLockOwner)) {
            std::ifstream owner(kUpdateLockOwner);
            long pid_value = 0;
            std::string start;
            std::string token;
            std::string extra;
            if ((owner >> pid_value >> start >> token) &&
                !(owner >> extra) && pid_value > 1 && !token.empty()) {
                lock_pid = static_cast<pid_t>(pid_value);
                expected_start = std::move(start);
            }
        } else if (regular_nonempty_file(kUpdateLockPid) &&
                   regular_nonempty_file(kUpdateLockStart)) {
            lock_pid = read_pid_file(kUpdateLockPid);
            expected_start = read_single_line(kUpdateLockStart);
        }
        if (lock_pid && expected_start &&
            (::kill(*lock_pid, 0) == 0 || errno == EPERM)) {
            const auto actual_start = process_start_time(*lock_pid);
            if (actual_start && *actual_start == *expected_start) return true;
        }
    }
    return false;
}

bool wait_for_update_start() {
    constexpr auto kPollInterval = std::chrono::milliseconds(50);
    constexpr int kPollAttempts = 40;
    for (int attempt = 0; attempt < kPollAttempts; ++attempt) {
        if (update_is_running()) return true;
        std::this_thread::sleep_for(kPollInterval);
    }
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
    const bool recovery_blocked = update_recovery_is_blocked();
    status["package_recovery_pending"] =
        recovery_marker_present(kPendingUpdate);
    status["package_recovery_unknown"] =
        recovery_marker_present(kUnknownUpdate);
    status["package_rescue_ready"] =
        !recovery_blocked && executable_nonempty_file(kRescueHelper) &&
        rescue_integrity::verified_ipk_file(kCurrentPackage);
    status["package_rollback_available"] =
        !recovery_blocked && executable_nonempty_file(kRescueHelper) &&
        rescue_integrity::verified_ipk_file(kPreviousPackage) &&
        rescue_integrity::verified_snapshot(kPreviousPackageConfig);
    return status;
}

nlohmann::json read_release_cache() {
    try {
        std::ifstream input(kReleaseCacheFile, std::ios::binary);
        if (!input) return nlohmann::json::object();
        auto cache = nlohmann::json::parse(input);
        return cache.is_object() ? cache : nlohmann::json::object();
    } catch (const nlohmann::json::exception&) {
        return nlohmann::json::object();
    }
}

void write_release_cache(const nlohmann::json& release,
                         std::int64_t cached_at) {
    const std::filesystem::path path(kReleaseCacheFile);
    const auto temporary = path.string() + ".tmp";
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) return;

    {
        std::ofstream output(temporary,
                             std::ios::binary | std::ios::trunc);
        if (!output) return;
        output << nlohmann::json{{"cached_at", cached_at},
                                 {"release", release}}
                      .dump();
        if (!output) return;
    }

    std::filesystem::rename(temporary, path, ec);
    if (!ec) return;
    ec.clear();
    std::filesystem::remove(path, ec);
    ec.clear();
    std::filesystem::rename(temporary, path, ec);
}

std::int64_t unix_time_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool release_cache_is_fresh(const nlohmann::json& cache,
                            std::int64_t now) {
    if (!cache.contains("release") || !cache["release"].is_object())
        return false;
    const auto cached_at = cache.value("cached_at", std::int64_t{0});
    const auto ttl = std::chrono::duration_cast<std::chrono::seconds>(
                         kReleaseCacheTtl)
                         .count();
    return cached_at > 0 && now >= cached_at && now - cached_at < ttl;
}

nlohmann::json download_latest_release() {
    HttpClient client;
    client.set_timeout(std::chrono::seconds(15));
    client.set_user_agent("keen-pbr-sb/" KEEN_PBR3_VERSION_STRING);
    client.set_max_response_size(512U * 1024U);
    return nlohmann::json::parse(client.download(
        "https://api.github.com/repos/blindtechnique/keen-pbr-sb/releases/latest"));
}

std::string release_string(const nlohmann::json& release,
                           const char* field) {
    const auto value = release.find(field);
    return value != release.end() && value->is_string()
               ? value->get<std::string>()
               : std::string{};
}

nlohmann::json software_update_status(bool force_remote_check) {
    auto response = local_update_status();
    const std::string current = std::string("v") +
                                KEEN_PBR3_VERSION_STRING + "-sb." +
                                KEEN_PBR3_VERSION_RELEASE_STRING;
    const auto now = unix_time_now();
    const auto cache = read_release_cache();
    nlohmann::json release = nlohmann::json::object();
    bool cached = false;
    std::string check_error;

    if (!force_remote_check && release_cache_is_fresh(cache, now)) {
        release = cache["release"];
        cached = true;
    } else {
        try {
            release = download_latest_release();
            write_release_cache(release, now);
        } catch (const std::exception& error) {
            check_error = error.what();
            if (cache.contains("release") && cache["release"].is_object()) {
                release = cache["release"];
                cached = true;
            }
        }
    }

    const auto latest = release_string(release, "tag_name");
    auto release_notes = release_string(release, "body");
    constexpr std::size_t kReleaseNotesLimit = 64U * 1024U;
    if (release_notes.size() > kReleaseNotesLimit) {
        release_notes.resize(kReleaseNotesLimit);
        release_notes += "\n\n…";
    }
    const auto release_url = release_string(release, "html_url");
    const auto release_name = release_string(release, "name");
    const auto changelog_url =
        safe_github_tag(latest)
            ? std::string(
                  "https://github.com/blindtechnique/keen-pbr-sb/blob/") +
                  latest + "/CHANGELOG.md"
            : std::string{};

    response.update(
        nlohmann::json{{"current", current},
                       {"latest", latest},
                       {"available",
                        !latest.empty() &&
                            is_newer_fork_version(latest, current)},
                       {"current_ahead",
                        !latest.empty() &&
                            is_newer_fork_version(current, latest)},
                       {"release_name", release_name},
                       {"release_notes", release_notes},
                       {"release_url", release_url},
                       {"changelog_url", changelog_url},
                       {"cached", cached},
                       {"check_error", check_error}});
    return response;
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
        return software_update_status(false).dump();
    });

    server.post("/api/system/update/check", []() -> std::string {
        return software_update_status(true).dump();
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
        if (!executable_nonempty_file(helper))
            throw ApiError("self-update helper is not installed", 409);
        if (update_is_running())
            throw ApiError(
                "keen-pbr-sb update or rollback is already running", 409);
        if (update_recovery_is_blocked())
            throw ApiError(
                "package recovery is pending or has unknown state; run rescue recovery before starting another update",
                409);
        create_full_rollback_backup(ctx);
        const int status = std::system(
            "/opt/usr/lib/keen-pbr/self-update.sh >/dev/null 2>&1 &");
        if (status != 0 || !wait_for_update_start())
            throw ApiError("failed to start keen-pbr-sb update", 500);
        return R"({"ok":true,"started":true})";
    });

    server.post("/api/system/update/rollback", [&ctx]() -> std::string {
        const std::lock_guard lock(update_start_mutex());
        if (update_is_running())
            throw ApiError("keen-pbr-sb update or rollback is already running", 409);
        if (update_recovery_is_blocked())
            throw ApiError(
                "package recovery is pending or has unknown state; run rescue recovery before starting rollback",
                409);
        if (!executable_nonempty_file(kRescueHelper) ||
            !rescue_integrity::verified_ipk_file(kPreviousPackage) ||
            !rescue_integrity::verified_snapshot(
                kPreviousPackageConfig)) {
            throw ApiError(
                "previous IPK is not available; complete one managed update first",
                409);
        }
        if (std::system(
                "/opt/var/lib/keen-pbr/rescue/rescue-update.sh "
                "can-rollback-previous >/dev/null 2>&1") != 0) {
            throw ApiError(
                "previous IPK snapshot is incomplete or corrupted", 409);
        }

        create_full_rollback_backup(ctx);
        const int status = std::system(
            "/opt/var/lib/keen-pbr/rescue/rescue-update.sh "
            "rollback-previous >/dev/null 2>&1 &");
        if (status != 0 || !wait_for_update_start())
            throw ApiError("failed to start keen-pbr-sb package rollback", 500);
        return R"({"ok":true,"started":true})";
    });
}

} // namespace keen_pbr3

#endif // WITH_API
