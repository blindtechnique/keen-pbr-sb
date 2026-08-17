#pragma once

#include <map>
#include <sstream>
#include <string>

namespace keen_pbr3 {

// Merge NDMS `show ip dhcp bindings` output into an address -> display-name map.
//
// Extracted verbatim from the connections handler so the shape NDMS actually
// emits can be pinned by a test. The daemon has always parsed this output, but
// nothing described what it expects, and a firmware that renamed a key would
// have degraded silently into "no device names" with no failing test.
//
// NDMS entries deliberately overwrite anything already present for the same
// address: the DHCP hostname comes from the client, while `name` is what the
// user typed in the router's own UI, and that is what the panel should show.
inline void merge_dhcp_bindings(const std::string& output,
                                std::map<std::string, std::string>& names) {
    std::string ip, hostname, name;
    const auto flush = [&]() {
        const auto& preferred = name.empty() ? hostname : name;
        if (!ip.empty() && !preferred.empty()) names[ip] = preferred;
    };
    std::istringstream stream(output);
    for (std::string line; std::getline(stream, line);) {
        const auto first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        line.erase(0, first);
        const auto last = line.find_last_not_of(" \t\r\n");
        line.erase(last + 1);
        if (line == "lease:" || line == "binding:") {
            flush();
            ip.clear(); hostname.clear(); name.clear();
            continue;
        }
        const auto separator = line.find(':');
        if (separator == std::string::npos) continue;
        auto key = line.substr(0, separator);
        auto value = line.substr(separator + 1);
        const auto value_first = value.find_first_not_of(" \t");
        value = value_first == std::string::npos ? std::string{}
                                                 : value.substr(value_first);
        if (key == "ip" || key == "address") ip = value;
        else if (key == "hostname") hostname = value;
        else if (key == "name") name = value;
    }
    flush();
}

}  // namespace keen_pbr3
