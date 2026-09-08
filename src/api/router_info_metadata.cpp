#include "router_info_metadata.hpp"

#include <chrono>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr auto kObservationTtl = std::chrono::seconds(60);
constexpr auto kObservationRetry = std::chrono::seconds(60);
constexpr auto kEventRefreshInterval = std::chrono::seconds(5);

bool string_field(const nlohmann::json& value, const char* field) {
    const auto found = value.find(field);
    return found != value.end() && found->is_string();
}

bool boolean_field(const nlohmann::json& value, const char* field) {
    const auto found = value.find(field);
    return found != value.end() && found->is_boolean();
}

bool authoritative_interface(const nlohmann::json& value) {
    return value.is_object() &&
        (string_field(value, "id") || string_field(value, "type") ||
         string_field(value, "description") || string_field(value, "state") ||
         string_field(value, "address") || boolean_field(value, "connected") ||
         value.contains("link"));
}

} // namespace

RouterInfoMetadata::RouterInfoMetadata(RciGetFn rci_get,
                                     VersionGetFn version_get,
                                     RouterInfoCache::NowFn now)
    : rci_get_(std::move(rci_get))
    , version_get_(std::move(version_get))
    , wan_([this] { return fetch_wan(); }, kObservationTtl,
           kObservationRetry, now, kEventRefreshInterval)
    , clients_([this] { return fetch_clients(); }, kObservationTtl,
               kObservationRetry, std::move(now), kEventRefreshInterval) {}

bool RouterInfoMetadata::invalidate(const InterfaceMonitor::Event& event) {
    const bool topology = event.topology_changed || event.administrative_state_changed;
    const bool wan = event.observation_gap || event.default_route_changed ||
        event.address_changed || topology;
    const bool clients = event.observation_gap || event.neighbor_changed || topology;
    if (wan) wan_.invalidate();
    if (clients) clients_.invalidate();
    return wan || clients;
}

RouterInfoCache::FetchResult RouterInfoMetadata::fetch_wan() {
    auto out = nlohmann::json::object();
    const auto internet = rci_get_("/show/internet/status");
    if (!internet || !internet->is_object()) return {std::move(out), false};
    const auto gateway = internet->find("gateway");
    const bool has_gateway = gateway != internet->end() && gateway->is_object();
    if (!boolean_field(*internet, "internet") && !has_gateway) {
        return {std::move(out), false};
    }
    if (boolean_field(*internet, "internet")) {
        out["internet"] = internet->at("internet");
    }
    // Follow the firmware-selected default interface; do not assume ISP/PPPoE
    // names. A known absence of an address replaces the previous WAN value.
    if (!has_gateway) return {std::move(out), true};
    const auto interface = gateway->value("interface", std::string{});
    if (interface.empty()) return {std::move(out), true};
    const auto observed = rci_get_("/show/interface/" + interface);
    if (!observed || !authoritative_interface(*observed)) {
        return {std::move(out), false};
    }
    const auto address = observed->value("address", std::string{});
    if (!address.empty()) out["wan_address"] = address;
    return {std::move(out), true};
}

RouterInfoCache::FetchResult RouterInfoMetadata::fetch_clients() {
    auto out = nlohmann::json::object();
    const auto hotspot = rci_get_("/show/ip/hotspot");
    if (!hotspot || !hotspot->is_object()) return {std::move(out), false};
    const auto hosts = hotspot->find("host");
    if (hosts == hotspot->end() || !hosts->is_array()) {
        return {std::move(out), false};
    }
    std::int64_t total = 0, active = 0;
    for (const auto& host : *hosts) {
        if (!host.is_object()) continue;
        ++total;
        if (host.value("active", false)) ++active;
    }
    out["clients_active"] = active;
    out["clients_total"] = total;
    return {std::move(out), true};
}

nlohmann::json RouterInfoMetadata::get() {
    // Version has its own shared process-wide cache, also consumed by system
    // information. Never invalidate or replace it because WAN/hotspot failed.
    auto out = version_get_();
    if (!out.is_object()) out = nlohmann::json::object();
    out.update(wan_.get());
    out.update(clients_.get());
    return out;
}

} // namespace keen_pbr3
