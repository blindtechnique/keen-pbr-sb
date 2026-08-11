#include "ndms_lockout_policy.hpp"

#include "../http/http_client.hpp"

#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

constexpr const char* kRciHttpConfig =
    "http://127.0.0.1:79/rci/show/rc/ip/http";

// The firmware spells these as strings ("5"), but older and newer builds have
// been seen using JSON numbers for neighbouring fields, so accept both rather
// than making the switch depend on a formatting detail.
std::optional<std::uint32_t> parse_count(const nlohmann::json& value) {
    if (value.is_string()) {
        const auto& text = value.get_ref<const std::string&>();
        if (text.empty()) return std::nullopt;
        std::uint64_t parsed = 0;
        for (const char ch : text) {
            if (ch < '0' || ch > '9') return std::nullopt;
            parsed = parsed * 10U + static_cast<std::uint64_t>(ch - '0');
            if (parsed > std::numeric_limits<std::uint32_t>::max()) {
                return std::nullopt;
            }
        }
        return static_cast<std::uint32_t>(parsed);
    }
    if (value.is_number_unsigned()) {
        const auto parsed = value.get<std::uint64_t>();
        if (parsed > std::numeric_limits<std::uint32_t>::max()) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(parsed);
    }
    if (value.is_number_integer()) {
        const auto parsed = value.get<std::int64_t>();
        if (parsed < 0 ||
            parsed > static_cast<std::int64_t>(
                         std::numeric_limits<std::uint32_t>::max())) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(parsed);
    }
    return std::nullopt;
}

std::optional<std::uint32_t> parse_field(const nlohmann::json& object,
                                         const char* key) {
    const auto found = object.find(key);
    if (found == object.end()) return std::nullopt;
    return parse_count(*found);
}

} // namespace

std::optional<NdmsLockoutPolicy> parse_ndms_lockout_policy(
    const nlohmann::json& http_config) {
    if (!http_config.is_object()) return std::nullopt;

    const auto policy = http_config.find("lockout-policy");
    if (policy == http_config.end() || !policy->is_object()) {
        return std::nullopt;
    }

    const auto threshold = parse_field(*policy, "threshold");
    const auto duration = parse_field(*policy, "duration");
    const auto observation = parse_field(*policy, "observation-window");
    if (!threshold || !duration || !observation) return std::nullopt;

    // A zero threshold means the firmware never locks. That is not "safe
    // because there is no lock" - it is a policy we cannot reason about, and
    // treating it as unlimited headroom is exactly the assumption this parser
    // exists to avoid.
    if (*threshold == 0U || *observation == 0U) return std::nullopt;

    NdmsLockoutPolicy parsed;
    parsed.threshold = *threshold;
    parsed.duration = std::chrono::minutes(*duration);
    parsed.observation_window = std::chrono::minutes(*observation);
    return parsed;
}

std::optional<NdmsLockoutPolicy> fetch_ndms_lockout_policy(
    std::string* error) {
    try {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(1));
        client.set_max_response_size(2U * 1024U * 1024U);
        const auto policy = parse_ndms_lockout_policy(
            nlohmann::json::parse(client.download(kRciHttpConfig)));
        if (!policy) {
            if (error) {
                *error = "NDMS reported no usable HTTP lockout policy";
            }
            return std::nullopt;
        }
        if (error) error->clear();
        return policy;
    } catch (const std::exception& exception) {
        if (error) {
            *error = std::string{"NDMS lockout policy read failed: "} +
                     exception.what();
        }
        return std::nullopt;
    }
}

} // namespace keen_pbr3
