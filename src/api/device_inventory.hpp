#pragma once

#include <arpa/inet.h>
#include <algorithm>
#include <cctype>
#include <map>
#include <nlohmann/json.hpp>
#include <string>

namespace keen_pbr3 {

// Read-only suggestions, never DHCP reservations or persistent device identity.
// Project only documented host fields; do not expose the full RCI response.
inline nlohmann::json device_inventory(const nlohmann::json& hosts) {
    auto result = nlohmann::json{{"devices", nlohmann::json::array()},
                               {"truncated", false}};
    if (!hosts.is_array()) return result;
    std::map<std::string, nlohmann::json> by_address;
    const auto text = [](const nlohmann::json& host, const char* key) {
        const auto found = host.find(key);
        if (found == host.end() || !found->is_string()) return std::string{};
        const auto value = found->get<std::string>();
        if (value.size() > 320 || std::any_of(value.begin(), value.end(), [](unsigned char c) {
            return c < 32 || c == 127;
        })) return std::string{};
        return value;
    };
    std::size_t inspected = 0;
    for (const auto& host : hosts) {
        if (++inspected > 2048) { result["truncated"] = true; break; }
        if (!host.is_object()) continue;
        const auto ip = text(host, "ip");
        in_addr address{};
        if (inet_pton(AF_INET, ip.c_str(), &address) != 1) continue;
        const auto numeric = ntohl(address.s_addr);
        const auto first = numeric >> 24;
        if (first == 0 || first == 127 || first >= 224) continue;
        nlohmann::json entry{{"ipv4", ip}};
        const auto name = text(host, "name");
        const auto hostname = text(host, "hostname");
        if (!name.empty() || !hostname.empty()) entry["name"] = name.empty() ? hostname : name;
        auto mac = text(host, "mac");
        bool valid_mac = mac.size() == 17;
        for (std::size_t i = 0; valid_mac && i < mac.size(); ++i) {
            valid_mac = (i % 3 == 2) ? mac[i] == ':' : std::isxdigit(static_cast<unsigned char>(mac[i])) != 0;
        }
        if (valid_mac) {
            std::transform(mac.begin(), mac.end(), mac.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            entry["mac"] = mac;
        }
        const auto active = host.find("active");
        if (active != host.end() && active->is_boolean()) entry["active"] = *active;
        const auto existing = by_address.find(ip);
        if (existing != by_address.end()) {
            // A first observation can lack a MAC. Retain later identity evidence
            // so another host at this IPv4 cannot slip through as unambiguous.
            auto& previous = existing->second;
            if (entry.contains("mac")) {
                if (!previous.contains("mac")) previous["mac"] = entry["mac"];
                else if (entry["mac"] != previous["mac"]) previous["conflict"] = true;
            }
            continue;
        }
        if (by_address.size() >= 512) { result["truncated"] = true; continue; }
        by_address.emplace(ip, std::move(entry));
    }
    for (auto& [ip, entry] : by_address) {
        static_cast<void>(ip);
        result["devices"].push_back(std::move(entry));
    }
    return result;
}

} // namespace keen_pbr3
