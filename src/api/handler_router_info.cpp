#ifdef WITH_API

#include "handler_router_info.hpp"
#include "router_info_metadata.hpp"
#include "router_local_metrics.hpp"

#include "../http/http_client.hpp"
#include "../keenetic/ndms_version_projection.hpp"

#include <chrono>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace keen_pbr3 {
namespace {

std::optional<nlohmann::json> rci_get(const std::string& path) {
    try {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(2));
        client.set_max_response_size(2U * 1024U * 1024U);
        return nlohmann::json::parse(client.download(
            "http://127.0.0.1:79/rci" + path));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

nlohmann::json router_version_facts() {
    const auto snapshot = shared_ndms_router_version_facts_cache().get();
    auto out = nlohmann::json::object();
    if (!snapshot.facts) return out;
    const auto& version = *snapshot.facts;
    out["model"] = version.model;
    out["vendor"] = version.vendor;
    out["hw_id"] = version.hw_id;
    out["region"] = version.region;
    out["arch"] = version.arch;
    out["firmware_title"] = version.title;
    out["firmware_release"] = version.release;
    out["firmware_channel"] = version.sandbox;
    if (!version.firmware_date.empty()) {
        out["firmware_date"] = version.firmware_date;
    }
    return out;
}

bool known_name(const nlohmann::json& value, const char* key) {
    const auto found = value.find(key);
    return found != value.end() && found->is_string() &&
        !found->get_ref<const std::string&>().empty();
}

RouterInfoMetadata& router_metadata() {
    static RouterInfoMetadata metadata(rci_get, router_version_facts);
    return metadata;
}

nlohmann::json router_info() {
    auto out = router_metadata().get();
    // Backwards compatibility for older WebUI callers. The frequent endpoint
    // below reads only local sources and never waits for this RCI projection.
    out.update(local_router_metrics());
    out["available"] = known_name(out, "model") || known_name(out, "cpu_model");
    return out;
}

} // namespace

bool invalidate_router_info(const InterfaceMonitor::Event& event) {
    return router_metadata().invalidate(event);
}

void register_router_info_handler(ApiServer& server, ApiContext& /*ctx*/) {
    server.get("/api/system/router",
               []() -> std::string { return router_info().dump(); });
    server.get("/api/system/metrics",
               []() -> std::string { return local_router_metrics().dump(); });
}

} // namespace keen_pbr3

#endif // WITH_API
