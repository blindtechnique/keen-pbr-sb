#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

namespace keen_pbr3 {

struct NdmsWebAddress {
    std::string interface_id;
    std::string address;
    bool preferred{false};
};

struct NdmsHttpServiceConfig {
    bool enabled{false};
    std::uint16_t port{80};
};

struct NdmsWebEndpoint {
    std::string host;
    std::uint16_t port{80};
    std::string canonical;
};

// Pure, bounded parsers for the two read-only RCI responses used by endpoint
// discovery. Only connected private management interfaces are returned.
std::vector<NdmsWebAddress> parse_ndms_web_addresses(
    const nlohmann::json& interfaces);

NdmsHttpServiceConfig parse_ndms_http_service_config(
    const nlohmann::json& http_config);

// Compatibility parser for older firmware without /show/rc/ip/http.
NdmsHttpServiceConfig parse_ndms_running_config_http_service(
    const nlohmann::json& running_config);

using NdmsWebEndpointProbe =
    std::function<bool(const NdmsWebEndpoint&)>;

// Builds candidates in deterministic order (Bridge0 first) and accepts only a
// target which actually exposes the Keenetic /auth challenge.
std::optional<NdmsWebEndpoint> select_ndms_web_endpoint(
    const std::vector<NdmsWebAddress>& addresses,
    const NdmsHttpServiceConfig& service,
    const NdmsWebEndpointProbe& probe);

// Performs one bounded read of each fixed loopback RCI URL. There is no timer
// or polling loop: callers decide when a refresh is necessary.
std::optional<NdmsWebEndpoint> discover_ndms_web_endpoint(
    const NdmsWebEndpointProbe& probe,
    std::string* error = nullptr);

} // namespace keen_pbr3
