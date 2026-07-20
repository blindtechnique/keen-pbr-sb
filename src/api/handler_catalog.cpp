#ifdef WITH_API

#include "handler_catalog.hpp"

#include "../config/config.hpp"
#include "../http/http_client.hpp"
#include "../log/logger.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <sys/stat.h>

namespace keen_pbr3 {

namespace {

// The catalogue lives in one file in the awg-manager repository. Pointing at
// the branch rather than a pinned commit is deliberate: the whole purpose is
// to follow the author's additions and removals.
constexpr const char* kCatalogUrl =
    "https://raw.githubusercontent.com/hoaxisr/awg-manager/master/"
    "internal/presets/defaults.json";

constexpr const char* kCachePath = "/opt/var/cache/keen-pbr/catalog.json";
constexpr const char* kSettingsPath = "/opt/etc/keen-pbr/catalog-source.json";
// Shipped with the package so a fresh install without internet still offers
// something to choose from.
constexpr const char* kBundledPath = "/opt/usr/share/keen-pbr/catalog.json";

constexpr auto kMaxAge = std::chrono::hours(24 * 7);

std::mutex& catalog_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return {};
    }
    std::ostringstream out;
    out << file.rdbuf();
    return out.str();
}

bool write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    file << content;
    return file.good();
}

std::optional<std::chrono::system_clock::time_point> file_mtime(
    const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) {
        return std::nullopt;
    }
    return std::chrono::system_clock::from_time_t(st.st_mtime);
}

bool cache_is_fresh() {
    const auto mtime = file_mtime(kCachePath);
    if (!mtime) {
        return false;
    }
    return std::chrono::system_clock::now() - *mtime < kMaxAge;
}

// Only replaces the cache when the payload parses as the expected array, so a
// captive portal or an error page cannot wipe a working catalogue.
bool store_if_valid(const std::string& payload) {
    try {
        const auto parsed = nlohmann::json::parse(payload);
        if (!parsed.is_array() || parsed.empty()) {
            return false;
        }
    } catch (const std::exception&) {
        return false;
    }
    return write_file(kCachePath, payload);
}

// Resolves an outbound tag to its fwmark using the same allocation the rest of
// the daemon uses, so "download through vless-nl" means the same thing here as
// it does for an ordinary list.
uint32_t mark_for_detour(const Config& config, const std::string& tag) {
    if (tag.empty() || !config.outbounds) {
        return 0;
    }
    try {
        const auto marks = allocate_outbound_marks(
            config.fwmark.value_or(FwmarkConfig{}), *config.outbounds);
        const auto it = marks.find(tag);
        return it == marks.end() ? 0U : it->second;
    } catch (const std::exception&) {
        return 0;
    }
}

} // namespace

std::string catalog_detour() {
    try {
        const auto raw = read_file(kSettingsPath);
        if (raw.empty()) {
            return {};
        }
        return nlohmann::json::parse(raw).value("detour", std::string{});
    } catch (const std::exception&) {
        return {};
    }
}

bool refresh_catalog_if_stale(bool force, uint32_t fwmark) {
    std::lock_guard<std::mutex> lock(catalog_mutex());

    if (!force && cache_is_fresh()) {
        return false;
    }

    try {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(20));
        client.set_max_response_size(4U * 1024U * 1024U);

        const auto payload = client.download(kCatalogUrl, HttpRequestOptions{fwmark});
        if (!store_if_valid(payload)) {
            Logger::instance().warn(
                "List catalogue: downloaded file is not a valid catalogue, keeping the previous copy");
            return false;
        }
        Logger::instance().info("List catalogue updated from {}", kCatalogUrl);
        return true;
    } catch (const std::exception& e) {
        // The router's link to GitHub is unreliable; a failed refresh simply
        // leaves the previous copy in place.
        Logger::instance().warn("List catalogue refresh failed: {}", e.what());
        return false;
    }
}

void register_catalog_handler(ApiServer& server, ApiContext& ctx) {
    // GET /api/catalog - presets with their source and freshness.
    server.get("/api/catalog", []() -> std::string {
        std::lock_guard<std::mutex> lock(catalog_mutex());

        std::string source = "cache";
        auto payload = read_file(kCachePath);
        if (payload.empty()) {
            payload = read_file(kBundledPath);
            source = "bundled";
        }

        nlohmann::json response;
        response["source"] = source;

        if (const auto mtime = file_mtime(source == "cache" ? kCachePath : kBundledPath)) {
            response["updated_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                                         mtime->time_since_epoch()).count();
        }

        try {
            response["presets"] = nlohmann::json::parse(payload);
        } catch (const std::exception&) {
            response["presets"] = nlohmann::json::array();
            response["error"] = "catalogue is unavailable";
        }
        response["url"] = kCatalogUrl;
        response["detour"] = catalog_detour();
        return response.dump();
    });

    // POST /api/catalog/refresh - fetch now instead of waiting for the weekly
    // run. An optional detour is remembered, so the scheduled refresh keeps
    // using whatever route worked when the user pressed the button.
    server.post("/api/catalog/refresh", [&ctx](const std::string& body) -> std::string {
        nlohmann::json response;
        std::string detour = catalog_detour();

        try {
            if (!body.empty()) {
                const auto request = nlohmann::json::parse(body);
                if (request.contains("detour")) {
                    detour = request["detour"].is_string()
                                 ? request["detour"].get<std::string>()
                                 : std::string{};
                    nlohmann::json settings;
                    settings["detour"] = detour;
                    std::ofstream file(kSettingsPath, std::ios::out | std::ios::trunc);
                    if (file.is_open()) {
                        file << settings.dump(2) << "\n";
                    }
                }
            }
        } catch (const std::exception& e) {
            response["error"] = e.what();
            return response.dump();
        }

        const auto mark = mark_for_detour(ctx.get_visible_config(), detour);
        response["updated"] = refresh_catalog_if_stale(/*force=*/true, mark);
        response["detour"] = detour;
        return response.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
