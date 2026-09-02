#include "ndms_http_service_config.hpp"

#include <charconv>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {
namespace {

std::optional<std::uint16_t> parse_port(std::string_view value) {
    if (value.empty()) return std::nullopt;
    unsigned int parsed = 0;
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} ||
        result.ptr != value.data() + value.size() ||
        parsed == 0U ||
        parsed > std::numeric_limits<std::uint16_t>::max()) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(parsed);
}

} // namespace

NdmsHttpServiceConfig parse_ndms_http_service_config(
    const nlohmann::json& http_config) {
    if (!http_config.is_object() || http_config.empty()) {
        throw std::invalid_argument(
            "NDMS HTTP configuration response is invalid");
    }
    const auto port = http_config.find("port");
    if (port == http_config.end()) {
        throw std::invalid_argument(
            "NDMS HTTP configuration has no port");
    }
    std::optional<std::uint16_t> parsed;
    if (port->is_string()) {
        parsed = parse_port(port->get_ref<const std::string&>());
    } else if (port->is_number_unsigned()) {
        const auto value = port->get<std::uint64_t>();
        if (value > 0U &&
            value <= std::numeric_limits<std::uint16_t>::max()) {
            parsed = static_cast<std::uint16_t>(value);
        }
    } else if (port->is_number_integer()) {
        const auto value = port->get<std::int64_t>();
        if (value > 0 &&
            value <= std::numeric_limits<std::uint16_t>::max()) {
            parsed = static_cast<std::uint16_t>(value);
        }
    }
    if (!parsed) {
        throw std::invalid_argument(
            "NDMS HTTP configuration port is invalid");
    }
    return NdmsHttpServiceConfig{true, *parsed};
}

} // namespace keen_pbr3
