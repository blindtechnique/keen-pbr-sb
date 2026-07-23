#include "ndms_interface_inventory.hpp"

#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

std::string trim(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

std::string normalized(std::string value) {
    value.erase(
        std::remove_if(
            value.begin(),
            value.end(),
            [](unsigned char character) {
                return !std::isalnum(character);
            }),
        value.end());
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

std::optional<bool> boolean_field(const nlohmann::json& entry,
                                  const char* key,
                                  const char* truthy_word) {
    const auto found = entry.find(key);
    if (found == entry.end()) return std::nullopt;
    if (found->is_boolean()) return found->get<bool>();
    if (found->is_string()) {
        const auto value = normalized(found->get<std::string>());
        return value == normalized(truthy_word) ||
               value == "true" ||
               value == "yes" ||
               value == "up" ||
               value == "connected";
    }
    return std::nullopt;
}

std::optional<NdmsTunnelKind> classify(const std::string& id,
                                       const nlohmann::json& entry) {
    const auto firmware_type =
        normalized(entry.value("type", std::string{}));
    const auto subtype =
        normalized(entry.value("subtype", std::string{}));
    const auto protocol =
        normalized(entry.value("protocol", std::string{}));
    const auto proxy_type =
        normalized(entry.value("proxy-type", std::string{}));
    const auto combined =
        firmware_type + subtype + protocol + proxy_type;
    const auto normalized_id = normalized(id);
    const auto kernel_name =
        normalized(entry.value("interface-name", std::string{}));

    if (combined.find("amneziawireguard") != std::string::npos ||
        normalized_id.rfind("nwg", 0) == 0 ||
        kernel_name.rfind("nwg", 0) == 0) {
        return NdmsTunnelKind::amnezia_wireguard;
    }
    if (combined.find("wireguard") != std::string::npos) {
        return NdmsTunnelKind::wireguard;
    }
    if (combined.find("openvpn") != std::string::npos) {
        return NdmsTunnelKind::openvpn;
    }
    if (combined.find("ikev1") != std::string::npos ||
        combined.find("ikev2") != std::string::npos ||
        combined.find("ipsec") != std::string::npos) {
        return NdmsTunnelKind::ike;
    }
    if (combined.find("l2tp") != std::string::npos) {
        return NdmsTunnelKind::l2tp;
    }
    if (combined.find("sstp") != std::string::npos) {
        return NdmsTunnelKind::sstp;
    }
    if (combined.find("openconnect") != std::string::npos ||
        combined.find("anyconnect") != std::string::npos) {
        return NdmsTunnelKind::openconnect;
    }
    if (combined.find("socks5") != std::string::npos) {
        return NdmsTunnelKind::socks5_proxy;
    }
    if (combined.find("httpsproxy") != std::string::npos) {
        return NdmsTunnelKind::https_proxy;
    }
    if (combined.find("httpproxy") != std::string::npos) {
        return NdmsTunnelKind::http_proxy;
    }
    return std::nullopt;
}

} // namespace

NdmsInterfaceCatalog parse_ndms_interface_catalog(
    const nlohmann::json& interfaces) {
    NdmsInterfaceCatalog catalog;
    catalog.names = nlohmann::json::object();
    if (!interfaces.is_object()) return catalog;
    catalog.firmware_available = true;

    for (const auto& [id, entry] : interfaces.items()) {
        if (!entry.is_object()) continue;

        const auto kernel_name =
            trim(entry.value("interface-name", std::string{}));
        if (kernel_name.empty()) continue;

        const auto description =
            trim(entry.value("description", std::string{}));
        const auto firmware_type =
            trim(entry.value("type", std::string{}));
        const auto connected = boolean_field(entry, "connected", "yes");
        const auto link = boolean_field(entry, "link", "up");

        nlohmann::json name_entry{
            {"label", description.empty() ? id : description},
            {"id", id},
            {"type", firmware_type},
        };
        if (connected) name_entry["connected"] = *connected;
        if (link) name_entry["link"] = *link;
        catalog.names[kernel_name] = std::move(name_entry);

        const auto kind = classify(id, entry);
        if (!kind) continue;
        catalog.tunnels.push_back(NdmsTunnelInterface{
            id,
            kernel_name,
            description.empty() ? id : description,
            firmware_type,
            *kind,
            connected,
            link,
        });
    }

    std::sort(
        catalog.tunnels.begin(),
        catalog.tunnels.end(),
        [](const auto& left, const auto& right) {
            if (left.label != right.label) return left.label < right.label;
            return left.id < right.id;
        });
    return catalog;
}

const char* ndms_tunnel_kind_name(NdmsTunnelKind kind) noexcept {
    switch (kind) {
    case NdmsTunnelKind::amnezia_wireguard:
        return "amnezia_wireguard";
    case NdmsTunnelKind::wireguard:
        return "wireguard";
    case NdmsTunnelKind::openvpn:
        return "openvpn";
    case NdmsTunnelKind::ike:
        return "ike";
    case NdmsTunnelKind::l2tp:
        return "l2tp";
    case NdmsTunnelKind::sstp:
        return "sstp";
    case NdmsTunnelKind::openconnect:
        return "openconnect";
    case NdmsTunnelKind::http_proxy:
        return "http_proxy";
    case NdmsTunnelKind::https_proxy:
        return "https_proxy";
    case NdmsTunnelKind::socks5_proxy:
        return "socks5_proxy";
    }
    return "unknown";
}

} // namespace keen_pbr3
