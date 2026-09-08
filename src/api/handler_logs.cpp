#ifdef WITH_API

#include "handler_logs.hpp"
#include "../log/subscription_notices.hpp"
#include <ctime>
#include "status_stream.hpp"

#include "../config/config_writer.hpp"
#include "../log/file_sink.hpp"
#include "../log/nfqws_log_maintenance.hpp"
#include "../log/logger.hpp"
#include "../log/notification_state.hpp"
#include "../util/last_command_failure.hpp"

#include <httplib.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr std::size_t kDefaultLines = 300;
constexpr std::size_t kMaxLines = 5000;
// Reading the tail is enough for diagnostics and keeps a rotated 1 MiB file
// from being pulled into memory in full.
constexpr std::size_t kMaxTailBytes = 512U * 1024U;

// Kept next to the config rather than inside it: the config is generated and
// validated against the API schema, while this is a local preference that must
// survive a config that fails to load.
constexpr const char* kSettingsPath = "/opt/etc/keen-pbr/logging.json";

std::mutex& settings_mutex() {
    static std::mutex mutex;
    return mutex;
}

#ifdef KEEN_PBR3_TESTING
std::mutex& test_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

LogSettingsTestHook& test_hook() {
    static LogSettingsTestHook hook;
    return hook;
}

void invoke_test_hook(LogSettingsTestStage stage) {
    LogSettingsTestHook hook;
    {
        const std::lock_guard<std::mutex> lock(test_hook_mutex());
        hook = test_hook();
    }
    if (hook) hook(stage);
}
#endif

std::string settings_path() {
#ifdef KEEN_PBR3_TESTING
    if (const char* configured =
            std::getenv("KEEN_PBR_TEST_LOG_SETTINGS_FILE")) {
        if (*configured != '\0') return configured;
    }
#endif
    return kSettingsPath;
}

std::string log_file_path() {
#ifdef KEEN_PBR3_TESTING
    if (const char* configured = std::getenv("KEEN_PBR_TEST_LOG_FILE")) {
        if (*configured != '\0') return configured;
    }
#endif
#ifdef KEEN_PBR_DEFAULT_LOG_FILE
    return KEEN_PBR_DEFAULT_LOG_FILE;
#else
    return "/opt/var/log/keen-pbr.log";
#endif
}

std::vector<std::string> read_tail(const std::string& path,
                                   std::size_t max_lines,
                                   bool& exists,
                                   std::uint64_t& size_bytes) {
    exists = false;
    size_bytes = 0;

    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        return {};
    }
    exists = true;

    file.seekg(0, std::ios::end);
    const auto file_size = static_cast<std::uint64_t>(file.tellg());
    size_bytes = file_size;

    const auto read_bytes =
        static_cast<std::streamoff>(std::min<std::uint64_t>(file_size, kMaxTailBytes));
    file.seekg(-read_bytes, std::ios::end);

    std::string chunk(static_cast<std::size_t>(read_bytes), '\0');
    file.read(chunk.data(), read_bytes);
    chunk.resize(static_cast<std::size_t>(file.gcount()));

    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start < chunk.size()) {
        const auto end = chunk.find('\n', start);
        if (end == std::string::npos) {
            lines.emplace_back(chunk.substr(start));
            break;
        }
        lines.emplace_back(chunk.substr(start, end - start));
        start = end + 1;
    }

    // The first line is usually cut in half by the byte-based seek.
    if (read_bytes > 0 && static_cast<std::uint64_t>(read_bytes) < file_size &&
        !lines.empty()) {
        lines.erase(lines.begin());
    }
    if (lines.size() > max_lines) {
        lines.erase(lines.begin(),
                    lines.begin() + static_cast<std::ptrdiff_t>(lines.size() - max_lines));
    }
    return lines;
}

nlohmann::json notification_state_json(const NotificationDismissalState& state) {
    return {{"revision", state.revision},
            {"log_ids", state.log_ids},
            {"update_ids", state.update_ids}};
}

struct NotificationTail {
    std::vector<std::string> lines;
    std::vector<std::string> line_ids;
};

NotificationTail read_notification_tail(const std::string& path) {
    // Obtain the identity from the open file, not a pathname stat: rotation
    // between stat/open must not attach an old line to a new file's identity.
    const auto close_file = [](FILE* handle) { (void)std::fclose(handle); };
    std::unique_ptr<FILE, decltype(close_file)> file(
        std::fopen(path.c_str(), "rb"), close_file);
    if (!file) {
        if (errno == ENOENT) return {};
        throw ApiError("Could not read notifications", 500);
    }
    struct stat metadata {};
    if (::fstat(::fileno(file.get()), &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
        throw ApiError("Could not read notifications", 500);
    }
    const auto size = static_cast<std::uint64_t>(metadata.st_size);
    const auto length = static_cast<std::size_t>(
        std::min<std::uint64_t>(size, kMaxTailBytes));
    const auto offset = size - length;
    if (::fseeko(file.get(), static_cast<off_t>(offset), SEEK_SET) != 0) {
        throw ApiError("Could not read notifications", 500);
    }
    std::string chunk(length, '\0');
    chunk.resize(std::fread(chunk.data(), 1, length, file.get()));
    if (std::ferror(file.get())) {
        throw ApiError("Could not read notifications", 500);
    }

    // Retain only the last 200 ranges. Even a log made of tiny lines keeps a
    // bounded number of allocations and hashes only the lines being returned.
    std::deque<std::pair<std::size_t, std::size_t>> ranges;
    std::size_t start = 0;
    if (offset != 0) {
        const auto first_end = chunk.find('\n');
        if (first_end == std::string::npos) return {};
        start = first_end + 1;
    }
    while (start < chunk.size()) {
        const auto newline = chunk.find('\n', start);
        const auto end = newline == std::string::npos ? chunk.size() : newline;
        ranges.emplace_back(start, end - start);
        if (ranges.size() > 200) ranges.pop_front();
        if (newline == std::string::npos) break;
        start = newline + 1;
    }
    NotificationTail result;
    result.lines.reserve(ranges.size());
    result.line_ids.reserve(ranges.size());
    for (const auto& range : ranges) {
        result.lines.emplace_back(chunk.substr(range.first, range.second));
        result.line_ids.push_back(notification_log_id(
            result.lines.back(),
            static_cast<std::uint64_t>(metadata.st_dev),
            static_cast<std::uint64_t>(metadata.st_ino),
            offset + range.first));
    }
    return result;
}

std::vector<std::string> notification_request_ids(
    const nlohmann::json& request, const char* key, std::size_t limit) {
    const auto value = request.find(key);
    if (value == request.end()) return {};
    if (!value->is_array() || value->size() > limit) {
        throw ApiError("Invalid notification dismissal IDs", 400);
    }
    std::vector<std::string> ids;
    ids.reserve(value->size());
    for (const auto& item : *value) {
        if (!item.is_string()) {
            throw ApiError("Invalid notification dismissal IDs", 400);
        }
        ids.push_back(item.get<std::string>());
    }
    return ids;
}

const char* level_name(LogLevel level) {
    switch (level) {
        case LogLevel::error: return "error";
        case LogLevel::warn: return "warn";
        case LogLevel::verbose: return "verbose";
        case LogLevel::debug: return "debug";
        case LogLevel::info:
        default: return "info";
    }
}

nlohmann::json read_settings() {
    nlohmann::json settings;
    settings["file_enabled"] = file_logging_enabled();
    settings["level"] = level_name(Logger::instance().level());
    settings["max_file_bytes"] = file_logging_max_bytes();
    settings["nfqws_max_file_bytes"] = nfqws_log_max_bytes();
    settings["size_limit_enabled"] = file_log_size_limit_enabled();
    settings["age_limit_enabled"] = file_log_age_limit_enabled();
    settings["max_age_days"] = file_log_max_age_days();
    settings["nfqws_size_limit_enabled"] = nfqws_log_size_limit_enabled();
    settings["nfqws_age_limit_enabled"] = nfqws_log_age_limit_enabled();
    settings["nfqws_max_age_days"] = nfqws_log_max_age_days();

    std::ifstream file(settings_path());
    if (!file.is_open()) {
        return settings;
    }
    try {
        const auto stored = nlohmann::json::parse(file);
        if (stored.contains("file_enabled") && stored["file_enabled"].is_boolean()) {
            settings["file_enabled"] = stored["file_enabled"].get<bool>();
        }
        if (stored.contains("level") && stored["level"].is_string()) {
            settings["level"] = stored["level"].get<std::string>();
        }
        for (const auto* key : {"max_file_bytes", "nfqws_max_file_bytes"}) {
            if (stored.contains(key) && stored[key].is_number_integer()) {
                const auto value = stored[key].get<std::uint64_t>();
                if (value >= kMinLogFileBytes && value <= kMaxLogFileBytes) {
                    settings[key] = value;
                }
            }
        }
        for (const auto* key : {"size_limit_enabled", "age_limit_enabled",
                               "nfqws_size_limit_enabled", "nfqws_age_limit_enabled"}) {
            if (stored.contains(key) && stored[key].is_boolean()) settings[key] = stored[key];
        }
        for (const auto* key : {"max_age_days", "nfqws_max_age_days"}) {
            if (stored.contains(key) && stored[key].is_number_integer() &&
                stored[key] >= 1U && stored[key] <= kMaximumLogAgeDays) settings[key] = stored[key];
        }
    } catch (const std::exception&) {
        // A corrupted preferences file must not take logging down with it.
    }
    return settings;
}

// False means that rename(2) made the new file visible but the directory fsync
// failed. Runtime must still adopt the visible settings so disk and memory do
// not disagree until the next process start.
bool write_settings(const nlohmann::json& settings) {
    bool committed = false;
    AtomicFileWriteOptions options;
    options.default_file_mode = 0600;
    options.file_mode = static_cast<mode_t>(0600);
    options.committed_result = &committed;
#ifdef KEEN_PBR3_TESTING
    if (const char* fault =
            std::getenv("KEEN_PBR_TEST_LOG_SETTINGS_WRITE_FAULT")) {
        if (std::string(fault) == "directory_fsync") {
            options.fault_injector = [](AtomicFileWriteStage stage) {
                if (stage == AtomicFileWriteStage::directory_fsync) {
                    throw std::runtime_error(
                        "injected logging settings directory sync failure");
                }
            };
        }
    }
#endif
    try {
        write_file_atomically(
            settings_path(), settings.dump(2) + "\n", options);
        return true;
    } catch (const AtomicFileWriteError& error) {
        if (!committed && !error.committed()) throw;
        Logger::instance().warn(
            "Logging settings were published but directory sync failed: {}",
            error.what());
        return false;
    }
}

} // namespace

void apply_stored_log_settings() {
    const std::lock_guard<std::mutex> lock(settings_mutex());
    const auto settings = read_settings();
    set_file_logging_enabled(settings.value("file_enabled", true));
    set_file_logging_max_bytes(settings.value("max_file_bytes", FileLogSink::kDefaultMaxBytes));
    set_nfqws_log_max_bytes(settings.value("nfqws_max_file_bytes", FileLogSink::kDefaultMaxBytes));
    set_file_log_retention(settings.value("size_limit_enabled", true),
        settings.value("age_limit_enabled", false), settings.value("max_age_days", kDefaultLogMaxAgeDays));
    set_nfqws_log_retention(settings.value("nfqws_size_limit_enabled", true),
        settings.value("nfqws_age_limit_enabled", false), settings.value("nfqws_max_age_days", kDefaultLogMaxAgeDays));
    try {
        Logger::instance().set_level(parse_log_level(settings.value("level", "info")));
    } catch (const std::exception&) {
        // Unknown level in the file: keep whatever the command line asked for.
    }
}

NotificationHandlers make_notification_handlers(
    StatusStream* status_stream, const std::string& config_path,
    std::function<nlohmann::json()> subscription_sources) {
    std::string load_error;
    const auto state_path =
        (std::filesystem::path(config_path).parent_path() / "notifications.json").string();
    auto notifications = std::make_shared<NotificationStateStore>(state_path, &load_error);
    if (!load_error.empty()) Logger::instance().warn("{}", load_error);
    if (status_stream) {
        status_stream->publish_notification_state(
            notification_state_json(notifications->snapshot()));
    }

    NotificationHandlers handlers;
    handlers.get = [notifications, subscription_sources]() {
        const auto tail = read_notification_tail(log_file_path());
        nlohmann::json response{
            {"lines", tail.lines},
            {"line_ids", tail.line_ids},
            {"state", notification_state_json(notifications->snapshot())}};
        response["subscription_notices"] = nlohmann::json::array();
        if (subscription_sources) {
            try {
                response["subscription_notices"] = subscription_notices(
                    subscription_sources(), static_cast<std::int64_t>(std::time(nullptr)));
            } catch (...) {
                response["subscription_notices_error"] = true;
            }
        }
        return response.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    };
    handlers.dismiss = [notifications, status_stream](const std::string& body) {
        const auto request = nlohmann::json::parse(body, nullptr, false);
        if (!request.is_object()) {
            throw ApiError("Invalid notification dismissal request", 400);
        }
        const auto log_ids = notification_request_ids(request, "log_ids", 200);
        const auto update_ids = notification_request_ids(
            request, "update_ids", kNotificationUpdateIdLimit);
        if (!valid_notification_dismissal(log_ids, update_ids)) {
            throw ApiError("Invalid notification dismissal IDs", 400);
        }
        std::string error;
        if (!notifications->dismiss(log_ids, update_ids, error)) {
            throw ApiError("Could not dismiss notifications", 500);
        }
        // A successful rename remains applied even if its directory sync was
        // not confirmed. The store adopts that visible state; do not retry it.
        if (!error.empty()) Logger::instance().warn("{}", error);
        const auto state = notification_state_json(notifications->snapshot());
        if (status_stream) status_stream->publish_notification_state(state);
        return state.dump();
    };
    return handlers;
}

void register_logs_handler(ApiServer& server,
                           StatusStream* status_stream,
                           const std::string& config_path,
                           std::function<nlohmann::json()> subscription_sources) {
    auto notifications = make_notification_handlers(status_stream, config_path, std::move(subscription_sources));
    server.get("/api/notifications", std::move(notifications.get));
    server.post("/api/notifications/dismiss", std::move(notifications.dismiss));

    // GET /api/logs?lines=N - tail of the daemon log file.
    //
    // The router runs keen-pbr from an init script where stderr is discarded,
    // so without this the only way to read a startup failure is over SSH.
    // get_stream is used only because it is the one registration form that
    // exposes the request, and the tail length comes in as a query parameter.
    server.get_stream("/api/logs", [](const httplib::Request& req,
                                      httplib::Response& res) {
        std::size_t lines = kDefaultLines;
        if (req.has_param("lines")) {
            try {
                lines = std::min<std::size_t>(
                    kMaxLines, std::max<std::size_t>(1, std::stoul(req.get_param_value("lines"))));
            } catch (const std::exception&) {
                lines = kDefaultLines;
            }
        }

        const auto path = log_file_path();
        bool exists = false;
        std::uint64_t size_bytes = 0;
        const auto tail = read_tail(path, lines, exists, size_bytes);

        nlohmann::json response;
        response["path"] = path;
        response["exists"] = exists;
        response["size_bytes"] = size_bytes;
        response["lines"] = tail;
        if (const auto failure = read_last_command_failure()) {
            response["last_command_failure"] = *failure;
        }
        // A legacy daemon log may contain arbitrary tool output. Replace an
        // invalid byte instead of turning the whole diagnostics endpoint into
        // HTTP 500; new command-failure snapshots are sanitized at write time.
        res.set_content(
            response.dump(
                -1,
                ' ',
                false,
                nlohmann::json::error_handler_t::replace),
            "application/json");
    });

    // GET /api/logs/settings - current logging preferences.
    server.get("/api/logs/settings",
               []() -> std::string {
                   const std::lock_guard<std::mutex> lock(settings_mutex());
                   return read_settings().dump();
               });

    // POST /api/logs/settings - turn the log file on or off, set verbosity.
    server.post("/api/logs/settings", [](const std::string& body) -> std::string {
        nlohmann::json response;
        try {
            const auto request = nlohmann::json::parse(body);
#ifdef KEEN_PBR3_TESTING
            invoke_test_hook(LogSettingsTestStage::request_ready);
#endif
            const std::lock_guard<std::mutex> lock(settings_mutex());
            auto settings = read_settings();
#ifdef KEEN_PBR3_TESTING
            invoke_test_hook(LogSettingsTestStage::after_read);
#endif

            if (request.contains("file_enabled") && request["file_enabled"].is_boolean()) {
                settings["file_enabled"] = request["file_enabled"].get<bool>();
            }
            if (request.contains("level") && request["level"].is_string()) {
                // Validate before storing so a typo cannot silence the log.
                const auto level = request["level"].get<std::string>();
                parse_log_level(level);
                settings["level"] = level;
            }
            for (const auto* key : {"max_file_bytes", "nfqws_max_file_bytes"}) {
                if (!request.contains(key)) continue;
                if (!request[key].is_number_integer() ||
                    request[key] < kMinLogFileBytes || request[key] > kMaxLogFileBytes) {
                    throw std::invalid_argument(std::string(key) +
                        " must be an integer from 65536 to 16777216 bytes");
                }
                settings[key] = request[key];
            }
            for (const auto* key : {"size_limit_enabled", "age_limit_enabled",
                                   "nfqws_size_limit_enabled", "nfqws_age_limit_enabled"}) {
                if (!request.contains(key)) continue;
                if (!request[key].is_boolean()) throw std::invalid_argument(std::string(key) + " must be a boolean");
                settings[key] = request[key];
            }
            for (const auto* key : {"max_age_days", "nfqws_max_age_days"}) {
                if (!request.contains(key)) continue;
                if (!request[key].is_number_integer() || request[key] < 1U || request[key] > kMaximumLogAgeDays) {
                    throw std::invalid_argument(std::string(key) + " must be an integer from 1 to 365 days");
                }
                settings[key] = request[key];
            }

            bool settings_durable = false;
            try {
                settings_durable = write_settings(settings);
            } catch (const std::exception& error) {
                Logger::instance().error(
                    "Cannot write logging.json atomically: {}",
                    error.what());
                response["error"] = "cannot write logging.json";
                return response.dump();
            }

            set_file_logging_enabled(settings.value("file_enabled", true));
            set_file_logging_max_bytes(settings.value("max_file_bytes", FileLogSink::kDefaultMaxBytes));
            set_nfqws_log_max_bytes(settings.value("nfqws_max_file_bytes", FileLogSink::kDefaultMaxBytes));
            set_file_log_retention(settings.value("size_limit_enabled", true),
                settings.value("age_limit_enabled", false), settings.value("max_age_days", kDefaultLogMaxAgeDays));
            set_nfqws_log_retention(settings.value("nfqws_size_limit_enabled", true),
                settings.value("nfqws_age_limit_enabled", false), settings.value("nfqws_max_age_days", kDefaultLogMaxAgeDays));
            Logger::instance().set_level(
                parse_log_level(settings.value("level", "info")));

            response["ok"] = true;
            response["durable"] = settings_durable;
            if (!settings_durable) {
                response["warning"] =
                    "logging settings are visible but directory durability "
                    "could not be confirmed";
            }
            response["settings"] = settings;
        } catch (const std::exception& e) {
            response["error"] = e.what();
        }
        return response.dump();
    });
}

#ifdef KEEN_PBR3_TESTING
void set_log_settings_test_hook(LogSettingsTestHook hook) {
    const std::lock_guard<std::mutex> lock(test_hook_mutex());
    test_hook() = std::move(hook);
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
