#include "network_routes.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <utility>

namespace keen_pbr3 {

std::vector<std::string> parse_default_route_interfaces(std::string_view routes) {
    std::istringstream input{std::string(routes)};
    std::string line;
    std::getline(input, line);

    std::vector<std::pair<long, std::string>> candidates;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string iface, destination, gateway, flags, refcnt, use, metric;
        if (!(fields >> iface >> destination >> gateway >> flags >> refcnt >> use >> metric) ||
            destination != "00000000" || iface.empty() || iface == "lo") {
            continue;
        }
        try {
            if ((std::stoul(flags, nullptr, 16) & 0x1U) == 0) continue;
            candidates.emplace_back(std::stol(metric), iface);
        } catch (const std::exception&) {
            continue;
        }
    }

    std::stable_sort(candidates.begin(), candidates.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.first < rhs.first;
    });
    std::vector<std::string> result;
    for (const auto& candidate : candidates) {
        const auto& iface = candidate.second;
        if (std::find(result.begin(), result.end(), iface) == result.end()) result.push_back(iface);
    }
    return result;
}

std::vector<std::string> default_route_interfaces() {
    std::ifstream input("/proc/net/route");
    if (!input) return {};
    std::ostringstream content;
    content << input.rdbuf();
    return parse_default_route_interfaces(content.str());
}

std::string primary_default_route_interface() {
    const auto interfaces = default_route_interfaces();
    return interfaces.empty() ? std::string{} : interfaces.front();
}

} // namespace keen_pbr3
