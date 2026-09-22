#ifdef WITH_API

#include "handler_health_service.hpp"

#include "../config/config_writer.hpp"
#include "generated/api_types.hpp"
#include "update_version.hpp"
#include "handler_backup.hpp"
#include "../http/http_client.hpp"
#include "../log/logger.hpp"
#include "../update/rescue_integrity.hpp"
#include "../update/rollback_availability.hpp"

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
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <unistd.h>

namespace keen_pbr3 {

namespace {

constexpr const char* kUpdatePidFile = "/opt/var/run/keen-pbr-self-update.pid";
constexpr const char* kUpdateChannelPreference = "/opt/etc/keen-pbr/update-channel";
constexpr const char* kInstalledUpdateChannel = "/opt/usr/lib/keen-pbr/update-channel";
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

RescueStoreLayout rescue_store_layout() {
    RescueStoreLayout layout;
    layout.helper = kRescueHelper;
    layout.previous_package = kPreviousPackage;
    layout.previous_config = kPreviousPackageConfig;
    layout.pending_marker = kPendingUpdate;
    layout.unknown_marker = kUnknownUpdate;
    return layout;
}

// One reading of the store, shared by the status report and the refusal.
//
// Two readings would be two answers: a rollback that the panel showed as
// available can be refused with an unrelated reason, and the operator has no
// way to tell which of the two was wrong.
PackageRollbackState package_rollback_state() {
    return classify_package_rollback(
        observe_package_rollback(rescue_store_layout()));
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
    const auto rollback_state = package_rollback_state();
    status["package_rollback_available"] =
        package_rollback_is_available(rollback_state);
    // The reason, not just the verdict. Reported before a rollback is started
    // so an operator learns there is nothing to roll back to while it still
    // changes what they do, instead of at the moment they need it.
    status["package_rollback_state"] =
        package_rollback_state_name(rollback_state);
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
                         const std::string& channel,
                         std::int64_t cached_at) {
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.created_directory_mode = 0755;
    options.default_file_mode = 0644;
    options.file_mode = static_cast<mode_t>(0644);
    try {
        write_file_atomically(
            kReleaseCacheFile,
            nlohmann::json{{"cached_at", cached_at}, {"release", release},
                           {"channel", channel}}
                .dump(),
            options);
    } catch (const std::exception& error) {
        // Release metadata can always be fetched again. Preserve the previous
        // valid cache and keep update checks non-fatal.
        Logger::instance().warn(
            "Cannot persist software release cache atomically: {}",
            error.what());
    }
}

std::int64_t unix_time_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool release_cache_is_fresh(const nlohmann::json& cache,
                            const std::string& channel,
                            std::int64_t now) {
    if (!release_cache_matches_channel(cache, channel) ||
        !cache.contains("cached_at") || !cache["cached_at"].is_number_integer())
        return false;
    const auto cached_at = cache.value("cached_at", std::int64_t{0});
    const auto ttl = std::chrono::duration_cast<std::chrono::seconds>(
                         kReleaseCacheTtl)
                         .count();
    return cached_at > 0 && now >= cached_at && now - cached_at < ttl;
}

std::string installed_update_channel() {
    // Package-owned, not a conffile: an explicit CLI channel switch replaces
    // this marker together with the binary/helper. Missing is not "stable".
    return read_update_channel(kInstalledUpdateChannel).value_or("");
}

std::string selected_update_channel() {
    const auto installed = installed_update_channel();
    if (!valid_update_channel(installed))
        throw std::runtime_error("Installed update channel is missing or invalid");
    return read_update_channel(kUpdateChannelPreference).value_or(installed);
}

nlohmann::json download_latest_release(const std::string& channel) {
    if (channel != "alpha" && channel != "stable")
        throw std::runtime_error("Installed update channel is missing or invalid");
    HttpClient client;
    client.set_timeout(std::chrono::seconds(15));
    client.set_user_agent("keen-pbr-sb/" KEEN_PBR3_VERSION_STRING);
    client.set_max_response_size(channel == "alpha" ? 8U * 1024U * 1024U : 512U * 1024U);
    const auto endpoint = std::string(
        "https://api.github.com/repos/blindtechnique/keen-pbr-sb/releases") +
        (channel == "alpha" ? "?per_page=100" : "/latest");
    auto release = select_channel_release(
        nlohmann::json::parse(client.download(endpoint)), channel);
    if (published_fork_version(release).empty())
        throw std::runtime_error("No published package found in the installed update channel");
    return release;
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
    const std::string current = format_fork_version(
        KEEN_PBR3_VERSION_STRING, KEEN_PBR3_VERSION_RELEASE_STRING);
    const auto now = unix_time_now();
    std::string channel;
    std::string installed_channel;
    const auto cache = read_release_cache();
    nlohmann::json release = nlohmann::json::object();
    bool cached = false;
    std::string check_error;
    try {
        installed_channel = installed_update_channel();
        channel = selected_update_channel();
    } catch (const std::exception& error) {
        check_error = error.what();
    }

    if (!check_error.empty()) {
        // An invalid preference is not authority to switch channels.
    } else if (!force_remote_check && release_cache_is_fresh(cache, channel, now)) {
        release = cache["release"];
        cached = true;
    } else {
        try {
            release = download_latest_release(channel);
            write_release_cache(release, channel, now);
        } catch (const std::exception& error) {
            check_error = error.what();
            if (release_cache_matches_channel(cache, channel)) {
                release = cache["release"];
                cached = true;
            }
        }
    }

    const auto release_tag = release_string(release, "tag_name");
    const auto latest = published_fork_version(release);
    if (latest.empty() && check_error.empty()) {
        check_error = "Release metadata does not identify a single Keenetic package version";
    }
    auto release_notes = release_string(release, "body");
    constexpr std::size_t kReleaseNotesLimit = 64U * 1024U;
    if (release_notes.size() > kReleaseNotesLimit) {
        release_notes.resize(kReleaseNotesLimit);
        release_notes += "\n\n…";
    }
    const auto release_url = release_string(release, "html_url");
    const auto release_name = release_string(release, "name");
    const auto changelog_url =
        safe_github_tag(release_tag)
            ? std::string(
                  "https://github.com/blindtechnique/keen-pbr-sb/blob/") +
                  release_tag + "/CHANGELOG.md"
            : std::string{};

    response.update(
        nlohmann::json{{"current", current},
                       {"channel", channel},
                       {"installed_channel", installed_channel},
                       {"release_tag", release_tag},
                       {"source", "blindtechnique/keen-pbr-sb"},
                       {"channel_change", valid_update_channel(channel) &&
                           valid_update_channel(installed_channel) && channel != installed_channel},
                       {"installable", check_error.empty() &&
                           channel_release_installable(current, latest, installed_channel, channel)},
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

    server.post("/api/system/update/channel", [](const std::string& body) -> std::string {
        const std::lock_guard lock(update_start_mutex());
        const auto request = nlohmann::json::parse(body, nullptr, false);
        if (!request.is_object() || request.size() != 1 ||
            !request.contains("channel") || !request["channel"].is_string() ||
            !valid_update_channel(request["channel"].get<std::string>()))
            throw ApiError("Choose stable or alpha", 400);
        if (update_is_running() || update_recovery_is_blocked())
            throw ApiError("Update channel cannot change during an update or recovery", 409);
        const auto channel = request["channel"].get<std::string>();
        save_update_channel(kUpdateChannelPreference, channel);
        // No daemon config apply, remote request, service restart or install.
        return nlohmann::json{{"channel", channel}}.dump();
    });

    server.post("/api/system/update", [&ctx](const std::string& body) -> std::string {
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
        const auto request = nlohmann::json::parse(body, nullptr, false);
        if (!request.is_object() || request.size() != 3 ||
            !request.contains("channel") || !request["channel"].is_string() ||
            !request.contains("release_tag") || !request["release_tag"].is_string() ||
            !request.contains("version") || !request["version"].is_string())
            throw ApiError("Check the release and confirm its channel, tag and version", 400);
        const auto channel = selected_update_channel();
        const auto cache = read_release_cache();
        if (request["channel"] != channel ||
            !release_cache_is_fresh(cache, channel, unix_time_now()))
            throw ApiError("Update channel or release changed; check updates again", 409);
        const auto& release = cache["release"];
        const auto tag = release_string(release, "tag_name");
        const auto version = published_fork_version(release);
        const auto current = format_fork_version(
            KEEN_PBR3_VERSION_STRING, KEEN_PBR3_VERSION_RELEASE_STRING);
        if (!safe_github_tag(tag) || !safe_github_tag(version) ||
            request["release_tag"] != tag || request["version"] != version ||
            !channel_release_installable(current, version, installed_update_channel(), channel))
            throw ApiError("Release is no longer installable; downgrades are not supported by the panel", 409);
        create_full_rollback_backup(ctx);
        // Every token is from validated release metadata, not a caller URL.
        const std::string command = "/opt/usr/lib/keen-pbr/self-update.sh --channel " +
            channel + " --release-tag " + tag + " --expected-version " +
            version + " >/dev/null 2>&1 &";
        const int status = std::system(command.c_str());
        if (status != 0 || !wait_for_update_start())
            throw ApiError("failed to start keen-pbr-sb update", 500);
        return R"({"ok":true,"started":true})";
    });

    server.post("/api/system/update/rollback", [&ctx]() -> std::string {
        const std::lock_guard lock(update_start_mutex());
        if (update_is_running())
            throw ApiError("keen-pbr-sb update or rollback is already running", 409);
        // Same classification the status endpoint reports, so the refusal an
        // operator gets here always names the reason they were already shown.
        const auto rollback_state = package_rollback_state();
        if (!package_rollback_is_available(rollback_state))
            throw ApiError(package_rollback_state_message(rollback_state), 409);
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
