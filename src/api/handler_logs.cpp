#ifdef WITH_API

#include "handler_logs.hpp"

#include "../log/file_sink.hpp"
#include "../log/logger.hpp"

#include <httplib.h>

#include <algorithm>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/stat.h>
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

std::string log_file_path() {
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

    std::ifstream file(kSettingsPath);
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
    } catch (const std::exception&) {
        // A corrupted preferences file must not take logging down with it.
    }
    return settings;
}

bool write_settings(const nlohmann::json& settings) {
    std::ofstream file(kSettingsPath, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    file << settings.dump(2) << "\n";
    return file.good();
}

} // namespace

void apply_stored_log_settings() {
    const auto settings = read_settings();
    set_file_logging_enabled(settings.value("file_enabled", true));
    try {
        Logger::instance().set_level(parse_log_level(settings.value("level", "info")));
    } catch (const std::exception&) {
        // Unknown level in the file: keep whatever the command line asked for.
    }
}

void register_logs_handler(ApiServer& server, ApiContext& /*ctx*/) {
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
        res.set_content(response.dump(), "application/json");
    });

    // GET /api/logs/settings - current logging preferences.
    server.get("/api/logs/settings",
               []() -> std::string { return read_settings().dump(); });

    // POST /api/logs/settings - turn the log file on or off, set verbosity.
    server.post("/api/logs/settings", [](const std::string& body) -> std::string {
        nlohmann::json response;
        try {
            const auto request = nlohmann::json::parse(body);
            auto settings = read_settings();

            if (request.contains("file_enabled") && request["file_enabled"].is_boolean()) {
                settings["file_enabled"] = request["file_enabled"].get<bool>();
            }
            if (request.contains("level") && request["level"].is_string()) {
                // Validate before storing so a typo cannot silence the log.
                const auto level = request["level"].get<std::string>();
                parse_log_level(level);
                settings["level"] = level;
            }

            if (!write_settings(settings)) {
                response["error"] = "cannot write logging.json";
                return response.dump();
            }

            set_file_logging_enabled(settings.value("file_enabled", true));
            Logger::instance().set_level(
                parse_log_level(settings.value("level", "info")));

            response["ok"] = true;
            response["settings"] = settings;
        } catch (const std::exception& e) {
            response["error"] = e.what();
        }
        return response.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
