#ifdef WITH_API

#include "handler_connections.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <deque>
#include <fstream>
#include <filesystem>
#include <iterator>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <arpa/inet.h>

namespace keen_pbr3 {
namespace {

using Clock = std::chrono::system_clock;
struct Connection {
    std::string protocol, state, source, destination, route;
    uint16_t source_port{0}, destination_port{0};
    uint32_t mark{0};
    std::int64_t first_seen{0}, last_seen{0};
    bool active{true};
};

std::mutex connections_mutex;
std::map<std::string, Connection> history;
constexpr size_t maximum_history_entries = 1500;
constexpr size_t maximum_dns_addresses = 3000;
constexpr size_t maximum_domains_per_address = 4;
constexpr const char* dns_query_log = "/tmp/dnsmasq-keen-pbr-queries.log";
std::map<std::string, std::deque<std::string>> domains_by_address;
std::streamoff dns_log_offset{0};

std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(Clock::now().time_since_epoch()).count();
}

std::string value_after(const std::string& token, const char* prefix) {
    const std::string p(prefix);
    return token.rfind(p, 0) == 0 ? token.substr(p.size()) : std::string{};
}

uint32_t number(const std::string& value) {
    try { return static_cast<uint32_t>(std::stoul(value, nullptr, 0)); }
    catch (...) { return 0; }
}

bool is_ip_address(const std::string& value) {
    in_addr ipv4{};
    in6_addr ipv6{};
    return inet_pton(AF_INET, value.c_str(), &ipv4) == 1 ||
           inet_pton(AF_INET6, value.c_str(), &ipv6) == 1;
}

void remember_domain(const std::string& address, const std::string& domain) {
    if (!is_ip_address(address) || domain.empty() || domain == "<Name>") return;
    auto& names = domains_by_address[address];
    names.erase(std::remove(names.begin(), names.end(), domain), names.end());
    names.push_front(domain);
    while (names.size() > maximum_domains_per_address) names.pop_back();
    while (domains_by_address.size() > maximum_dns_addresses)
        domains_by_address.erase(domains_by_address.begin());
}

void read_dns_query_log() {
    std::error_code ec;
    const auto size = std::filesystem::file_size(dns_query_log, ec);
    if (ec) return;
    if (size < static_cast<std::uintmax_t>(dns_log_offset)) dns_log_offset = 0;
    std::ifstream input(dns_query_log);
    if (!input) return;
    input.seekg(dns_log_offset);
    for (std::string line; std::getline(input, line);) {
        auto marker = line.find(" reply ");
        if (marker == std::string::npos) marker = line.find(" cached ");
        if (marker == std::string::npos) continue;
        std::istringstream fields(line.substr(marker + 7));
        std::string domain, separator, address;
        if (fields >> domain >> separator >> address && separator == "is")
            remember_domain(address, domain);
    }
    dns_log_offset = static_cast<std::streamoff>(size);

    // The log lives in tmpfs and is used only as a short DNS observation
    // stream. Keep it bounded; dnsmasq opens the file with append semantics.
    if (size > 2U * 1024U * 1024U) {
        std::ofstream truncate(dns_query_log, std::ios::trunc);
        dns_log_offset = 0;
    }
}

std::map<uint32_t, std::string> routes(const Config& config) {
    std::map<uint32_t, std::string> result;
    if (!config.outbounds) return result;
    const auto marks = allocate_outbound_marks(config.fwmark.value_or(FwmarkConfig{}), *config.outbounds);
    for (const auto& [tag, mark] : marks) result.emplace(mark, tag);
    return result;
}

std::map<std::string, std::string> device_names() {
    std::map<std::string, std::string> result;
    for (const char* path : {"/var/ndnproxymain.leases", "/opt/var/lib/misc/dnsmasq.leases", "/tmp/dhcp.leases"}) {
        std::ifstream leases(path);
        for (std::string line; std::getline(leases, line);) {
            std::istringstream stream(line);
            std::string expires, mac, ip, name;
            if (stream >> expires >> mac >> ip >> name && name != "*") result[ip] = name;
        }
    }

    // Keenetic keeps the user-visible client name in NDMS, separately from
    // the DHCP hostname. Querying NDMS also covers statically registered and
    // currently connected clients that are absent from dnsmasq lease files.
    if (FILE* pipe = popen("ndmc -c \"show ip dhcp bindings\" 2>/dev/null", "r")) {
        std::string ip, hostname, name;
        const auto flush = [&]() {
            const auto& preferred = name.empty() ? hostname : name;
            if (!ip.empty() && !preferred.empty()) result[ip] = preferred;
        };
        char buffer[1024];
        while (std::fgets(buffer, sizeof(buffer), pipe)) {
            std::string line(buffer);
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
            value = value_first == std::string::npos ? std::string{} : value.substr(value_first);
            if (key == "ip" || key == "address") ip = value;
            else if (key == "hostname") hostname = value;
            else if (key == "name") name = value;
        }
        flush();
        pclose(pipe);
    }
    return result;
}

void read_conntrack(const Config& config) {
    std::ifstream input("/proc/net/nf_conntrack");
    if (!input) input.open("/proc/net/ip_conntrack");
    const auto timestamp = now_seconds();
    for (auto& [_, connection] : history) connection.active = false;
    if (!input) return;
    const auto route_names = routes(config);
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream stream(line);
        std::vector<std::string> tokens;
        for (std::string token; stream >> token;) tokens.push_back(std::move(token));
        if (tokens.size() < 7) continue;
        Connection current;
        current.protocol = tokens[2];
        size_t cursor = 5;
        if (tokens[cursor].find('=') == std::string::npos) current.state = tokens[cursor++];
        else current.state = current.protocol == "udp" ? "ACTIVE" : "UNKNOWN";
        for (; cursor < tokens.size(); ++cursor) {
            const auto& token = tokens[cursor];
            if (current.source.empty()) current.source = value_after(token, "src=");
            else if (current.destination.empty()) current.destination = value_after(token, "dst=");
            else if (current.source_port == 0) current.source_port = static_cast<uint16_t>(number(value_after(token, "sport=")));
            else if (current.destination_port == 0) current.destination_port = static_cast<uint16_t>(number(value_after(token, "dport=")));
            if (const auto mark = value_after(token, "mark="); !mark.empty()) current.mark = number(mark);
        }
        if (current.source.empty() || current.destination.empty()) continue;
        current.route = "direct";
        const auto masked_mark = current.mark & fwmark_mask_value(config.fwmark.value_or(FwmarkConfig{}));
        if (const auto found = route_names.find(masked_mark); found != route_names.end()) current.route = found->second;
        const auto key = current.protocol + '|' + current.source + '|' + std::to_string(current.source_port) + '|' + current.destination + '|' + std::to_string(current.destination_port);
        auto& saved = history[key];
        if (saved.first_seen == 0) saved.first_seen = timestamp;
        current.first_seen = saved.first_seen;
        current.last_seen = timestamp;
        current.active = true;
        saved = std::move(current);
    }
    for (auto it = history.begin(); it != history.end();) {
        if (!it->second.active) it->second.state = "CLOSED";
        ++it;
    }
    while (history.size() > maximum_history_entries) {
        auto oldest = history.begin();
        for (auto it = std::next(history.begin()); it != history.end(); ++it) {
            if (it->second.last_seen < oldest->second.last_seen) oldest = it;
        }
        history.erase(oldest);
    }
}

} // namespace

void register_connections_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/connections", [&ctx]() -> std::string {
        std::lock_guard lock(connections_mutex);
        read_dns_query_log();
        read_conntrack(ctx.get_visible_config());
        const auto devices = device_names();
        nlohmann::json result = nlohmann::json::array();
        for (const auto& [id, c] : history) {
            const auto device = devices.find(c.source);
            const auto domains = domains_by_address.find(c.destination);
            result.push_back({{"id", id}, {"protocol", c.protocol}, {"state", c.state},
                {"source", c.source}, {"source_port", c.source_port},
                {"destination", c.destination}, {"destination_port", c.destination_port},
                {"route", c.route}, {"mark", c.mark}, {"active", c.active},
                {"device", device == devices.end() ? "" : device->second},
                {"destination_domains", domains == domains_by_address.end()
                    ? nlohmann::json::array()
                    : nlohmann::json(domains->second)},
                {"first_seen", c.first_seen}, {"last_seen", c.last_seen}});
        }
        return result.dump();
    });
}

} // namespace keen_pbr3
#endif
