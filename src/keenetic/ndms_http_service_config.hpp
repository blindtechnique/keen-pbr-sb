#pragma once

#include <cstdint>

#include <nlohmann/json_fwd.hpp>

namespace keen_pbr3 {

struct NdmsHttpServiceConfig {
    bool enabled{false};
    std::uint16_t port{80};
};

// Strict typed projection of the structured /show/rc/ip/http service fields.
// A missing or invalid port is not an authoritative service configuration.
NdmsHttpServiceConfig parse_ndms_http_service_config(
    const nlohmann::json& http_config);

} // namespace keen_pbr3
