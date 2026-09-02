#include "ndms_web_endpoint.hpp"
#include "ndms_http_config_projection.hpp"
#include "ndms_interface_resource.hpp"
#include "ndms_running_config_resource.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::size_t kMaximumAddresses = 128U;
constexpr std::size_t kMaximumRunningConfigLines = 16384U;
constexpr std::size_t kMaximumLineBytes = 4096U;
constexpr std::size_t kMaximumProbeCandidates = 4U;

std::string trim_ascii_whitespace(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1U);
}

std::string ascii_lower_trimmed(const std::string& value) {
    auto result = trim_ascii_whitespace(value);
    for (auto& character : result) {
        if (character >= 'A' && character <= 'Z') {
            character = static_cast<char>(character - 'A' + 'a');
        }
    }
    return result;
}

std::optional<bool> bool_value(const nlohmann::json& object,
                               const char* key) {
    const auto field = object.find(key);
    if (field == object.end()) return std::nullopt;
    if (field->is_boolean()) return field->get<bool>();
    if (!field->is_string()) return std::nullopt;
    const auto value =
        ascii_lower_trimmed(field->get_ref<const std::string&>());
    if (value == "yes" || value == "true" || value == "up" ||
        value == "connected" || value == "on") {
        return true;
    }
    if (value == "no" || value == "false" || value == "down" ||
        value == "disconnected" || value == "off") {
        return false;
    }
    return std::nullopt;
}

bool canonical_numeric_address(const std::string& value) {
    in_addr ipv4{};
    if (inet_pton(AF_INET, value.c_str(), &ipv4) == 1) {
        char canonical[INET_ADDRSTRLEN]{};
        return inet_ntop(
                   AF_INET, &ipv4, canonical, sizeof(canonical)) != nullptr &&
               value == canonical;
    }

    in6_addr ipv6{};
    if (inet_pton(AF_INET6, value.c_str(), &ipv6) != 1 ||
        IN6_IS_ADDR_LINKLOCAL(&ipv6)) {
        // A link-local address requires an interface scope identifier which
        // the current HTTP client deliberately does not accept.
        return false;
    }
    char canonical[INET6_ADDRSTRLEN]{};
    return inet_ntop(
               AF_INET6, &ipv6, canonical, sizeof(canonical)) != nullptr &&
           value == canonical;
}

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

std::string endpoint_text(const std::string& host,
                          const std::uint16_t port) {
    return host.find(':') == std::string::npos
               ? host + ":" + std::to_string(port)
               : "[" + host + "]:" + std::to_string(port);
}

void secure_wipe(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : &value[0];
    for (std::size_t offset = 0; offset < value.size(); ++offset) {
        bytes[offset] = 0;
    }
    value.clear();
}

void wipe_json_strings(nlohmann::json& value) noexcept {
    try {
        if (value.is_string()) {
            auto& text = value.get_ref<std::string&>();
            secure_wipe(text);
        } else if (value.is_array()) {
            for (auto& child : value) wipe_json_strings(child);
        } else if (value.is_object()) {
            for (auto& item : value.items()) {
                wipe_json_strings(item.value());
            }
        }
    } catch (...) {
    }
}

class JsonWipeGuard final {
public:
    explicit JsonWipeGuard(nlohmann::json& value) : value_(value) {}
    ~JsonWipeGuard() { wipe_json_strings(value_); }

private:
    nlohmann::json& value_;
};

} // namespace

std::vector<NdmsWebAddress> parse_ndms_web_addresses(
    const nlohmann::json& interfaces) {
    if (!interfaces.is_object()) {
        throw std::invalid_argument(
            "NDMS interface response is not an object");
    }

    std::vector<NdmsWebAddress> addresses;
    for (auto entry = interfaces.begin(); entry != interfaces.end(); ++entry) {
        if (!entry.value().is_object()) continue;
        const auto& object = entry.value();

        const auto security = object.find("security-level");
        const auto address = object.find("address");
        if (security == object.end() || !security->is_string() ||
            ascii_lower_trimmed(
                security->get_ref<const std::string&>()) != "private" ||
            address == object.end() || !address->is_string()) {
            continue;
        }
        const auto connected = bool_value(object, "connected");
        const auto global = bool_value(object, "global");
        const auto admin_only = bool_value(object, "admin-only");
        // These fields are security evidence, not optional display metadata.
        // Missing or malformed values must not be interpreted as safe.
        if (!connected.has_value() || !*connected ||
            !global.has_value() || *global ||
            !admin_only.has_value() || *admin_only) {
            continue;
        }

        const auto value =
            trim_ascii_whitespace(address->get_ref<const std::string&>());
        if (!canonical_numeric_address(value)) continue;

        auto id = entry.key();
        const auto explicit_id = object.find("id");
        if (explicit_id != object.end() && explicit_id->is_string()) {
            id = trim_ascii_whitespace(
                explicit_id->get_ref<const std::string&>());
        }
        if (id.empty() || id.size() > 128U) continue;

        addresses.push_back(
            NdmsWebAddress{id, value, id == "Bridge0"});
        if (addresses.size() > kMaximumAddresses) {
            throw std::invalid_argument(
                "NDMS interface response contains too many management addresses");
        }
    }

    std::sort(
        addresses.begin(),
        addresses.end(),
        [](const auto& left, const auto& right) {
            if (left.preferred != right.preferred) return left.preferred;
            if (left.interface_id != right.interface_id) {
                return left.interface_id < right.interface_id;
            }
            return left.address < right.address;
        });
    std::vector<NdmsWebAddress> unique_addresses;
    unique_addresses.reserve(addresses.size());
    std::unordered_set<std::string> seen;
    for (auto& address : addresses) {
        if (seen.insert(address.address).second) {
            unique_addresses.push_back(std::move(address));
        }
    }
    return unique_addresses;
}

NdmsHttpServiceConfig parse_ndms_running_config_http_service(
    const nlohmann::json& running_config) {
    if (!running_config.is_object()) {
        throw std::invalid_argument(
            "NDMS running-config response is not an object");
    }
    const auto messages = running_config.find("message");
    if (messages == running_config.end() || !messages->is_array() ||
        messages->size() > kMaximumRunningConfigLines) {
        throw std::invalid_argument(
            "NDMS running-config message is invalid");
    }

    NdmsHttpServiceConfig result;
    std::optional<std::uint16_t> configured_port;
    for (const auto& item : *messages) {
        if (!item.is_string()) {
            throw std::invalid_argument(
                "NDMS running-config line is not a string");
        }
        const auto& raw = item.get_ref<const std::string&>();
        if (raw.size() > kMaximumLineBytes) {
            throw std::invalid_argument(
                "NDMS running-config line is too large");
        }
        const auto line = trim_ascii_whitespace(raw);
        if (line == "service http") {
            result.enabled = true;
            continue;
        }
        constexpr std::string_view prefix{"ip http port "};
        if (line.size() <= prefix.size() ||
            line.compare(0, prefix.size(), prefix) != 0) {
            continue;
        }
        const auto parsed =
            parse_port(std::string_view{line}.substr(prefix.size()));
        if (!parsed || (configured_port && *configured_port != *parsed)) {
            throw std::invalid_argument(
                "NDMS HTTP port is invalid or ambiguous");
        }
        configured_port = parsed;
    }
    result.port = configured_port.value_or(80U);
    return result;
}

NdmsHttpServiceConfig cached_running_config_http_service() {
    const auto snapshot = shared_ndms_running_config_resource().get();
    if (!snapshot.document) {
        throw std::runtime_error(
            "NDMS running-config snapshot is unavailable");
    }
    const auto body = snapshot.document->body();
    auto document = nlohmann::json::parse(body.begin(), body.end());
    JsonWipeGuard wipe(document);
    return parse_ndms_running_config_http_service(document);
}

std::optional<NdmsWebEndpoint> select_ndms_web_endpoint(
    const std::vector<NdmsWebAddress>& addresses,
    const NdmsHttpServiceConfig& service,
    const NdmsWebEndpointProbe& probe) {
    if (!service.enabled || !probe) return std::nullopt;
    std::size_t attempted = 0U;
    for (const auto& address : addresses) {
        if (attempted++ >= kMaximumProbeCandidates) break;
        NdmsWebEndpoint endpoint{
            address.address,
            service.port,
            endpoint_text(address.address, service.port),
        };
        if (probe(endpoint)) return endpoint;
    }
    return std::nullopt;
}

std::optional<NdmsWebEndpoint> discover_ndms_web_endpoint(
    const NdmsWebEndpointProbe& probe,
    std::string* error) {
    try {
        const auto interface_snapshot =
            shared_ndms_interface_resource().get();
        if (!interface_snapshot.document) {
            throw std::runtime_error(
                "NDMS interface snapshot is unavailable");
        }
        const auto interface_body = interface_snapshot.document->body();
        auto interfaces = nlohmann::json::parse(
            interface_body.begin(), interface_body.end());
        JsonWipeGuard interface_wipe(interfaces);

        const auto addresses = parse_ndms_web_addresses(interfaces);
        if (addresses.empty()) {
            if (error) {
                *error =
                    "NDMS reported no connected private management address";
            }
            return std::nullopt;
        }

        const auto structured =
            shared_ndms_http_service_config_cache().get();
        if (structured.config) {
            if (!structured.config->enabled) {
                if (error) *error = "NDMS HTTP service is disabled";
                return std::nullopt;
            }
            auto endpoint = select_ndms_web_endpoint(
                addresses, *structured.config, probe);
            if (endpoint) {
                if (error) error->clear();
                return endpoint;
            }
            if (structured.status == NdmsCatalogCacheStatus::fresh) {
                if (error) {
                    *error =
                        "NDMS management addresses did not expose an auth challenge";
                }
                return std::nullopt;
            }
            // A stale structured LKG is useful only while its address:port
            // still proves the Keenetic challenge. If it does not, try the
            // already shared running-config compatibility projection.
        }

        // Older NDMS releases do not expose a usable structured subtree.
        // This is a second shared resource lookup, not another reader of the
        // structured HTTP-config URL.
        const auto service = cached_running_config_http_service();
        if (!service.enabled) {
            if (error) *error = "NDMS HTTP service is disabled";
            return std::nullopt;
        }
        auto endpoint =
            select_ndms_web_endpoint(addresses, service, probe);
        if (!endpoint && error) {
            *error =
                "NDMS management addresses did not expose an auth challenge";
        } else if (endpoint && error) {
            error->clear();
        }
        return endpoint;
    } catch (const std::exception& exception) {
        if (error) {
            *error =
                std::string{"NDMS endpoint discovery failed: "} +
                exception.what();
        }
        return std::nullopt;
    }
}

} // namespace keen_pbr3
