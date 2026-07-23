#ifdef WITH_API

#include "handler_ndms_names.hpp"

#include "../http/http_client.hpp"
#include "../keenetic/ndms_interface_inventory.hpp"

#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

constexpr const char* kRciInterfaces =
    "http://127.0.0.1:79/rci/show/interface";
// The firmware's local web server is intentionally queried once for both the
// legacy name map and the typed tunnel inventory.
constexpr auto kCacheTtl = std::chrono::seconds(30);

std::mutex& cache_mutex() {
    static std::mutex mutex;
    return mutex;
}

NdmsInterfaceCatalog fetch_catalog() {
    try {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(3));
        client.set_max_response_size(2U * 1024U * 1024U);
        return parse_ndms_interface_catalog(
            nlohmann::json::parse(client.download(kRciInterfaces)));
    } catch (const std::exception&) {
        // OpenWrt, development hosts and older firmware legitimately have no
        // NDMS RCI endpoint. This is a capability result, not an API failure.
        return parse_ndms_interface_catalog(nlohmann::json{});
    }
}

NdmsInterfaceCatalog cached_catalog() {
    static NdmsInterfaceCatalog cached =
        parse_ndms_interface_catalog(nlohmann::json{});
    static std::chrono::steady_clock::time_point fetched_at{};
    static bool fetched_once = false;

    std::lock_guard<std::mutex> lock(cache_mutex());
    const auto now = std::chrono::steady_clock::now();
    if (!fetched_once || now - fetched_at > kCacheTtl) {
        cached = fetch_catalog();
        fetched_at = now;
        fetched_once = true;
    }
    return cached;
}

nlohmann::json typed_inventory(const NdmsInterfaceCatalog& catalog) {
    nlohmann::json interfaces = nlohmann::json::array();
    for (const auto& tunnel : catalog.tunnels) {
        nlohmann::json item{
            {"id", tunnel.id},
            {"kernel_name", tunnel.kernel_name},
            {"label", tunnel.label},
            {"firmware_type", tunnel.firmware_type},
            {"kind", ndms_tunnel_kind_name(tunnel.kind)},
            {"owner", "keenetic"},
            {"capabilities",
             {{"can_edit", false},
              {"can_delete", false},
              {"can_hide", false},
              {"backup_required", true}}},
        };
        if (tunnel.connected) item["connected"] = *tunnel.connected;
        if (tunnel.link) item["link"] = *tunnel.link;
        interfaces.push_back(std::move(item));
    }

    return nlohmann::json{
        {"available", catalog.firmware_available},
        {"read_only", true},
        {"mutation_mode", "disabled"},
        {"required_guards",
         nlohmann::json::array(
             {"typed_rci",
              "automatic_backup",
              "ownership_check",
              "optimistic_revision"})},
        {"interfaces", std::move(interfaces)},
    };
}

} // namespace

void register_ndms_names_handler(ApiServer& server, ApiContext& /*ctx*/) {
    server.get("/api/system/interface-names", []() -> std::string {
        const auto catalog = cached_catalog();
        return nlohmann::json{
            {"names", catalog.names},
            {"available", catalog.firmware_available},
        }.dump();
    });

    server.get("/api/system/ndms/interfaces", []() -> std::string {
        return typed_inventory(cached_catalog()).dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
