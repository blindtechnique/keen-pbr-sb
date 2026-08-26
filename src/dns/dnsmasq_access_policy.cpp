#include "dnsmasq_access_policy.hpp"

#include <algorithm>
#include <set>
#include <string_view>
#include <utility>

namespace keen_pbr3 {
namespace {

void insert_exact_if_safe(
    std::set<std::string>& result,
    const std::string& selector) {
    if (selector.size() >= 2U &&
        selector.compare(0U, 2U, "br") == 0 &&
        result.find("br*") != result.end()) {
        return;
    }
    if (selector.find('*') == std::string::npos &&
        is_safe_dnsmasq_interface_selector(selector)) {
        result.insert(selector);
    }
}

} // namespace

bool is_safe_dnsmasq_interface_selector(
    const std::string& selector) noexcept {
    if (selector.empty() || selector.size() > 16U) {
        return false;
    }
    const bool wildcard = selector.back() == '*';
    const auto name_size =
        selector.size() - static_cast<std::size_t>(wildcard);
    if (name_size == 0U || name_size > 15U) {
        return false;
    }
    const std::string_view name(selector.data(), name_size);
    if (name == "." || name == "..") {
        return false;
    }
    return std::all_of(
        name.begin(), name.end(), [](const unsigned char character) {
            return (character >= 'a' && character <= 'z') ||
                   (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') ||
                   character == '_' || character == '-' ||
                   character == '.' || character == '@';
        });
}

std::vector<std::string> build_dnsmasq_trusted_interfaces(
    const std::vector<InternalVpnServer>& interface_servers,
    const std::vector<InternalVpnRuntimeTarget>& service_targets) {
    if (interface_servers.empty() && service_targets.empty()) {
        return {};
    }

    std::set<std::string> result;
    // Keenetic LAN segments are backed by BridgeN -> brN. Keeping this as a
    // wildcard admits every LAN segment without admitting a WAN device.
    result.insert("br*");

    for (const auto& server : interface_servers) {
        insert_exact_if_safe(result, server.interface);
    }
    for (const auto& target : service_targets) {
        if (target.match_kind == InternalVpnRuntimeMatchKind::interface &&
            target.interface.has_value()) {
            insert_exact_if_safe(result, *target.interface);
        }
        for (const auto& interface :
             target.verified_ingress_interfaces) {
            insert_exact_if_safe(result, interface);
        }
    }

    return {result.begin(), result.end()};
}

std::vector<std::string> select_dnsmasq_trusted_interfaces(
    std::optional<std::vector<std::string>> prepared_override,
    const std::vector<InternalVpnServer>& fallback_interface_servers,
    const std::vector<InternalVpnRuntimeTarget>& fallback_service_targets) {
    if (prepared_override.has_value()) {
        return std::move(*prepared_override);
    }
    return build_dnsmasq_trusted_interfaces(
        fallback_interface_servers, fallback_service_targets);
}

} // namespace keen_pbr3
