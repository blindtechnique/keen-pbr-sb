#ifdef WITH_API

#include "handler_catalog.hpp"

#include "../config/config.hpp"
#include "../config/config_writer.hpp"
#include "../http/http_client.hpp"
#include "../log/logger.hpp"
#include "../setup/catalog_setup_planner.hpp"

#include <cctype>
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

// This string is hashed into the provenance of every installed list
// (see setup::catalog_preset_identity). Changing it would give every preset a
// new identity and orphan every list a user has already installed, so it stays
// exactly as first published even though the catalogue no longer comes from
// that repository. It is never shown to anyone.
constexpr const char* kCatalogIdentity =
    "github:hoaxisr/awg-manager:internal/presets/defaults.json";

// The catalogue is package data: it ships in the IPK and a release is how it
// changes. Nothing is fetched by default, so a blocked or hostile network
// cannot decide which lists the router offers.
constexpr const char* kBundledPath = "/opt/usr/share/keen-pbr/catalog.json";

// An operator who wants a different or mirrored catalogue writes its URL into
// catalog-source.json by hand. The API never sets it: the daemon must not be
// talked into fetching an arbitrary address by an HTTP request.
constexpr const char* kSettingsPath = "/opt/etc/keen-pbr/catalog-source.json";
// Only ever written when such a URL is configured. Installs that predate the
// package-owned catalogue may still have a file here; it is now ignored.
constexpr const char* kCachePath = "/opt/var/cache/keen-pbr/catalog.json";

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

// False means the replacement is visible but its directory fsync failed. It is
// still the authoritative file for this process and readers must not pretend
// that the previous generation remains active.
bool write_file(const std::string& path,
                const std::string& content,
                mode_t mode) {
    bool committed = false;
    AtomicFileWriteOptions options;
    options.create_parent_directories = true;
    options.created_directory_mode = 0755;
    options.default_file_mode = mode;
    options.file_mode = mode;
    options.committed_result = &committed;
    try {
        write_file_atomically(path, content, options);
        return true;
    } catch (const AtomicFileWriteError& error) {
        if (!committed && !error.committed()) throw;
        return false;
    }
}

std::optional<std::chrono::system_clock::time_point> file_mtime(
    const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) {
        return std::nullopt;
    }
    return std::chrono::system_clock::from_time_t(st.st_mtime);
}

nlohmann::json read_catalog_settings() {
    try {
        const auto raw = read_file(kSettingsPath);
        if (raw.empty()) return nlohmann::json::object();
        auto parsed = nlohmann::json::parse(raw);
        return parsed.is_object() ? parsed : nlohmann::json::object();
    } catch (const std::exception&) {
        return nlohmann::json::object();
    }
}

// A rejected URL is treated as no URL at all rather than as an error: the
// catalogue in the package is always a working answer, and refusing to serve
// one because a hand-edited settings file is wrong would be worse than
// ignoring the file. The rules match the ones the setup planner applies to
// every catalogue URL, so a source that passes here cannot smuggle in a
// preset the planner would then refuse.
std::string configured_catalog_url() {
    const auto settings = read_catalog_settings();
    const auto url = settings.value("url", std::string{});
    if (url.empty()) return {};

    for (const unsigned char character : url) {
        if (character <= 0x20U || character == 0x7fU || character == '\\') {
            return {};
        }
    }
    const auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos) return {};
    std::string scheme = url.substr(0, scheme_end);
    for (auto& character : scheme) {
        character = static_cast<char>(
            std::tolower(static_cast<unsigned char>(character)));
    }
    if (scheme != "https") return {};
    const auto authority_start = scheme_end + 3U;
    const auto authority_end = url.find_first_of("/?#", authority_start);
    if (authority_end == authority_start) return {};
    if (authority_start >= url.size()) return {};
    return url;
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

void merge_domain_supplements(
    nlohmann::json& target,
    const nlohmann::json& bundled) {
    const auto supplements = bundled.find("domainSupplements");
    if (supplements == bundled.end() || !supplements->is_array()) {
        target.erase("domainSupplements");
        return;
    }

    auto& engines = target["engines"];
    if (!engines.is_object()) engines = nlohmann::json::object();
    auto& dns = engines["dns"];
    if (!dns.is_object()) dns = nlohmann::json::object();

    nlohmann::json merged = nlohmann::json::array();
    std::set<std::string> seen;
    const auto domains = dns.find("domains");
    if (domains != dns.end() && domains->is_array()) {
        for (const auto& domain : *domains) {
            if (!domain.is_string()) continue;
            const auto& value = domain.get_ref<const std::string&>();
            if (!value.empty() && seen.insert(value).second) {
                merged.push_back(value);
            }
        }
    }
    for (const auto& domain : *supplements) {
        if (!domain.is_string()) continue;
        const auto& value = domain.get_ref<const std::string&>();
        if (!value.empty() && seen.insert(value).second) {
            merged.push_back(value);
        }
    }
    dns["domains"] = std::move(merged);

    // domainSupplements is package-owned merge metadata, not part of the
    // public catalogue contract consumed by the frontend and setup planner.
    target.erase("domainSupplements");
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
    const bool durable = write_file(kCachePath, payload, 0644);
    if (!durable) {
        Logger::instance().warn(
            "List catalogue cache is visible, but its durability could not "
            "be confirmed");
    }
    return true;
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
    // The package copy is authoritative. A cache is consulted only when the
    // operator pointed the daemon at a catalogue of their own; without that
    // the file left behind by older versions is not a source, and reading it
    // would silently reinstate the third-party catalogue it holds.
    const auto configured_url = configured_catalog_url();
    std::string source = "bundled";
    std::string payload;
    if (!configured_url.empty()) {
        payload = read_file(kCachePath);
        if (!payload.empty()) source = "cache";
    }
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
        // The overlay exists to give a foreign catalogue the routing
        // companions and subnets it does not carry. When the package copy is
        // itself the source there is nothing to overlay onto it.
        if (source == "cache") {
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
        }
        response["presets"] =
            enrich_catalog_with_routing_companions(
                std::move(presets), bundled);
        add_catalog_identities(response);
    } catch (const std::exception&) {
        response["presets"] = nlohmann::json::array();
        response["error"] = "catalogue is unavailable";
    }
    // Empty unless the operator configured a catalogue of their own. Clients
    // read it as "where this came from", and for a packaged catalogue the
    // honest answer is "nowhere on the network".
    response["url"] = configured_url;
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
        const bool owns_notice =
            bundled_parent.contains("notice");
        const bool owns_domain_supplements =
            bundled_parent.contains("domainSupplements");
        if (!owns_companions && !owns_covers &&
            !owns_warnings && !owns_hidden && !owns_notice &&
            !owns_domain_supplements) {
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
            }
            if (owns_hidden) {
                (*upstream_parent)["hidden"] =
                    bundled_parent.at("hidden");
            }
            if (owns_notice) {
                (*upstream_parent)["notice"] =
                    bundled_parent.at("notice");
            }
        }
        if (owns_domain_supplements) {
            merge_domain_supplements(
                *upstream_parent, bundled_parent);
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
    return read_catalog_settings().value("detour", std::string{});
}

bool refresh_catalog_if_stale(bool force, uint32_t fwmark) {
    std::lock_guard<std::mutex> lock(catalog_mutex());

    // No configured source means the catalogue is the one in the package, and
    // a package is updated by opkg rather than by this function. Returning
    // quietly keeps the daily scheduled run from logging a non-event.
    const auto url = configured_catalog_url();
    if (url.empty()) {
        return false;
    }

    if (!force && cache_is_fresh()) {
        return false;
    }

    try {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(20));
        client.set_max_response_size(4U * 1024U * 1024U);

        const auto payload = client.download(url, HttpRequestOptions{fwmark});
        if (!store_if_valid(payload)) {
            Logger::instance().warn(
                "List catalogue: downloaded file is not a valid catalogue, keeping the previous copy");
            return false;
        }
        Logger::instance().info("List catalogue updated from {}", url);
        return true;
    } catch (const std::exception& e) {
        // The router's link to the configured host is unreliable; a failed
        // refresh simply leaves the previous copy in place.
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

    // POST /api/catalog/refresh - remember the route lists are downloaded
    // through, and fetch the catalogue now when the operator configured one of
    // their own. With the packaged catalogue there is nothing to fetch, and
    // "packaged": true says so rather than leaving the client to read a bare
    // "updated": false as a failure.
    server.post("/api/catalog/refresh", [&ctx](const std::string& body) -> std::string {
        nlohmann::json response;
        std::string detour = catalog_detour();
        bool settings_durable = true;

        try {
            if (!body.empty()) {
                const auto request = nlohmann::json::parse(body);
                if (request.contains("detour")) {
                    detour = request["detour"].is_string()
                                 ? request["detour"].get<std::string>()
                                 : std::string{};
                    // Read-modify-write: a hand-configured catalogue URL
                    // lives in the same file, and remembering a detour must
                    // not delete it.
                    auto settings = read_catalog_settings();
                    settings["detour"] = detour;
                    settings_durable = write_file(
                        kSettingsPath,
                        settings.dump(2) + "\n",
                        0600);
                    if (!settings_durable) {
                        Logger::instance().warn(
                            "Catalog source settings are visible, but their "
                            "durability could not be confirmed");
                    }
                }
            }
        } catch (const std::exception& e) {
            Logger::instance().error(
                "Cannot write catalog-source.json atomically: {}",
                e.what());
            response["error"] = "cannot write catalog-source.json";
            return response.dump();
        }

        const auto mark = mark_for_detour(ctx.get_visible_config(), detour);
        response["updated"] = refresh_catalog_if_stale(/*force=*/true, mark);
        response["packaged"] = configured_catalog_url().empty();
        response["detour"] = detour;
        response["settings_durable"] = settings_durable;
        if (!settings_durable) {
            response["warning"] =
                "catalog source settings are visible but directory "
                "durability could not be confirmed";
        }
        return response.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
