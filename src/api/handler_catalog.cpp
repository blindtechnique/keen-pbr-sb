#ifdef WITH_API

#include "handler_catalog.hpp"

#include "../config/config.hpp"
#include "../http/http_client.hpp"
#include "../log/logger.hpp"
#include "../setup/catalog_setup_planner.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
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
// Unlike the cache/bundled transport source, this identity describes the
// logical authoritative catalogue and remains stable across refreshes.
constexpr const char* kCatalogIdentity =
    "github:hoaxisr/awg-manager:internal/presets/defaults.json";

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

nlohmann::json* find_preset(
    nlohmann::json& presets,
    const std::string& id) {
    if (!presets.is_array()) return nullptr;
    for (auto& preset : presets) {
        if (!preset.is_object()) continue;
        const auto candidate = preset.find("id");
        if (candidate != preset.end() &&
            candidate->is_string() &&
            candidate->get_ref<const std::string&>() == id) {
            return &preset;
        }
    }
    return nullptr;
}

const nlohmann::json* find_preset(
    const nlohmann::json& presets,
    const std::string& id) {
    if (!presets.is_array()) return nullptr;
    for (const auto& preset : presets) {
        if (!preset.is_object()) continue;
        const auto candidate = preset.find("id");
        if (candidate != preset.end() &&
            candidate->is_string() &&
            candidate->get_ref<const std::string&>() == id) {
            return &preset;
        }
    }
    return nullptr;
}

void append_missing_covered_presets(
    nlohmann::json& upstream_presets,
    const nlohmann::json& bundled_presets) {
    // The downloaded AWG Manager catalogue is allowed to evolve independently
    // from our relationship overlay. Keep every bundled child used by `covers`
    // available even when upstream renames or temporarily removes that preset;
    // otherwise one unrelated remote change would invalidate the whole graph.
    while (true) {
        std::set<std::string> missing_ids;
        for (const auto& preset : upstream_presets) {
            if (!preset.is_object()) continue;
            const auto covers = preset.find("covers");
            if (covers == preset.end() || !covers->is_array()) continue;
            for (const auto& child : *covers) {
                if (!child.is_string()) continue;
                const auto& child_id =
                    child.get_ref<const std::string&>();
                if (find_preset(upstream_presets, child_id) == nullptr) {
                    missing_ids.insert(child_id);
                }
            }
        }

        bool appended = false;
        for (const auto& child_id : missing_ids) {
            const auto* bundled_child =
                find_preset(bundled_presets, child_id);
            if (bundled_child == nullptr) continue;
            upstream_presets.push_back(*bundled_child);
            appended = true;
        }
        if (!appended) return;
    }
}

const nlohmann::json* dns_subnets(
    const nlohmann::json& preset) {
    const auto engines = preset.find("engines");
    if (engines == preset.end() || !engines->is_object()) {
        return nullptr;
    }
    const auto dns = engines->find("dns");
    if (dns == engines->end() || !dns->is_object()) {
        return nullptr;
    }
    const auto subnets = dns->find("subnets");
    return subnets == dns->end() ? nullptr : &*subnets;
}

void align_dns_subnets(
    nlohmann::json& target,
    const nlohmann::json& bundled) {
    if (const auto* subnets = dns_subnets(bundled)) {
        target["engines"]["dns"]["subnets"] = *subnets;
        return;
    }
    const auto engines = target.find("engines");
    if (engines == target.end() || !engines->is_object()) return;
    const auto dns = engines->find("dns");
    if (dns == engines->end() || !dns->is_object()) return;
    dns->erase("subnets");
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

// catalog_mutex() must be held by the caller.
nlohmann::json load_catalog_snapshot_locked() {
    std::string source = "cache";
    auto payload = read_file(kCachePath);
    if (payload.empty()) {
        payload = read_file(kBundledPath);
        source = "bundled";
    }

    nlohmann::json response;
    response["source"] = source;
    response["catalog_id"] = kCatalogIdentity;

    if (const auto mtime =
            file_mtime(source == "cache" ? kCachePath : kBundledPath)) {
        response["updated_at"] =
            std::chrono::duration_cast<std::chrono::seconds>(
                mtime->time_since_epoch())
                .count();
    }

    try {
        auto presets = nlohmann::json::parse(payload);
        auto bundled = nlohmann::json::array();
        try {
            const auto bundled_payload = read_file(kBundledPath);
            if (!bundled_payload.empty()) {
                bundled =
                    nlohmann::json::parse(bundled_payload);
            }
        } catch (const std::exception& error) {
            Logger::instance().warn(
                "List catalogue: bundled routing companion overlay is "
                "unavailable: {}",
                error.what());
        }
        response["presets"] =
            enrich_catalog_with_routing_companions(
                std::move(presets), bundled);
        add_catalog_identities(response);
    } catch (const std::exception&) {
        response["presets"] = nlohmann::json::array();
        response["error"] = "catalogue is unavailable";
    }
    response["url"] = kCatalogUrl;
    response["detour"] = catalog_detour();
    return response;
}

} // namespace

void add_catalog_identities(nlohmann::json& snapshot) {
    if (!snapshot.is_object()) return;
    const auto presets = snapshot.find("presets");
    if (presets == snapshot.end() || !presets->is_array()) return;
    for (auto& preset : *presets) {
        if (!preset.is_object()) continue;
        const auto id = preset.find("id");
        if (id == preset.end() || !id->is_string() ||
            id->get_ref<const std::string&>().empty()) {
            continue;
        }
        const auto& parent_id =
            id->get_ref<const std::string&>();
        preset["catalog_identity"] =
            setup::catalog_preset_identity(snapshot, parent_id);
        const auto companions =
            preset.find("routingCompanions");
        if (companions == preset.end() ||
            !companions->is_array()) {
            continue;
        }
        for (auto& companion : *companions) {
            if (!companion.is_object()) continue;
            const auto companion_id = companion.find("id");
            if (companion_id == companion.end() ||
                !companion_id->is_string() ||
                companion_id->get_ref<const std::string&>().empty()) {
                continue;
            }
            std::string identity_id =
                parent_id + "#routing-companion:" +
                companion_id->get_ref<const std::string&>();
            const auto explicit_identity =
                companion.find("catalogIdentityId");
            if (explicit_identity != companion.end() &&
                explicit_identity->is_string() &&
                !explicit_identity
                     ->get_ref<const std::string&>()
                     .empty()) {
                identity_id =
                    explicit_identity->get_ref<const std::string&>();
            }
            companion["catalog_identity"] =
                setup::catalog_preset_identity(
                    snapshot, identity_id);
        }
    }
}

nlohmann::json enrich_catalog_with_routing_companions(
    nlohmann::json upstream_presets,
    const nlohmann::json& bundled_presets) {
    if (!upstream_presets.is_array() ||
        !bundled_presets.is_array()) {
        return upstream_presets;
    }

    for (const auto& bundled_parent : bundled_presets) {
        if (!bundled_parent.is_object()) continue;
        const bool owns_companions =
            bundled_parent.contains("routingCompanions");
        const bool owns_covers =
            bundled_parent.contains("covers");
        const bool owns_warnings =
            bundled_parent.contains("warnings");
        const bool owns_hidden =
            bundled_parent.contains("hidden");
        if (!owns_companions && !owns_covers &&
            !owns_warnings && !owns_hidden) {
            continue;
        }
        const auto companions =
            bundled_parent.find("routingCompanions");
        const auto parent_id_value =
            bundled_parent.find("id");
        if (parent_id_value == bundled_parent.end() ||
            !parent_id_value->is_string() ||
            parent_id_value->get_ref<const std::string&>().empty()) {
            continue;
        }
        const auto& parent_id =
            parent_id_value->get_ref<const std::string&>();

        auto* upstream_parent =
            find_preset(upstream_presets, parent_id);
        if (upstream_parent == nullptr) {
            upstream_presets.push_back(bundled_parent);
            upstream_parent = &upstream_presets.back();
        } else {
            if (owns_companions) {
                (*upstream_parent)["routingCompanions"] =
                    *companions;
                // Once IP matching is delegated to a companion, the primary
                // must not retain stale upstream subnets and route them twice.
                align_dns_subnets(*upstream_parent, bundled_parent);
            }
            if (owns_covers) {
                (*upstream_parent)["covers"] =
                    bundled_parent.at("covers");
            }
            if (owns_warnings) {
                (*upstream_parent)["warnings"] =
                    bundled_parent.at("warnings");
                if (bundled_parent.contains("notice")) {
                    (*upstream_parent)["notice"] =
                        bundled_parent.at("notice");
                }
            }
            if (owns_hidden) {
                (*upstream_parent)["hidden"] =
                    bundled_parent.at("hidden");
            }
        }

        if (!owns_companions || !companions->is_array()) {
            continue;
        }
        for (const auto& companion : *companions) {
            if (!companion.is_object()) continue;
            const auto source_id_value =
                companion.find("sourcePresetId");
            if (source_id_value == companion.end() ||
                !source_id_value->is_string() ||
                source_id_value
                    ->get_ref<const std::string&>()
                    .empty()) {
                continue;
            }
            const auto& source_id =
                source_id_value->get_ref<const std::string&>();
            const auto* bundled_source =
                find_preset(bundled_presets, source_id);
            if (bundled_source == nullptr) continue;
            auto* upstream_source =
                find_preset(upstream_presets, source_id);
            if (upstream_source == nullptr) {
                upstream_presets.push_back(*bundled_source);
            } else {
                // The bundled subnet set is deliberately curated and is the
                // actual source of the inline companion. Keep it stable even
                // when the downloaded catalogue lags behind.
                align_dns_subnets(
                    *upstream_source, *bundled_source);
            }
        }
    }
    append_missing_covered_presets(
        upstream_presets, bundled_presets);
    return upstream_presets;
}

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

nlohmann::json load_catalog_snapshot() {
    std::lock_guard<std::mutex> lock(catalog_mutex());
    return load_catalog_snapshot_locked();
}

void register_catalog_handler(ApiServer& server, ApiContext& ctx) {
    // GET /api/catalog - presets with their source and freshness.
    server.get("/api/catalog", []() -> std::string {
        return load_catalog_snapshot().dump();
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
