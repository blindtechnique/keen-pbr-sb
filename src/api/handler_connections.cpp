#ifdef WITH_API

#include "handler_connections.hpp"

#include <chrono>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>

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
constexpr std::int64_t retention_seconds = 2 * 60 * 60;
constexpr size_t maximum_history_entries = 20000;

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
        if (timestamp - it->second.last_seen > retention_seconds) it = history.erase(it);
        else ++it;
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
        read_conntrack(ctx.get_visible_config());
        const auto devices = device_names();
        nlohmann::json result = nlohmann::json::array();
        for (const auto& [id, c] : history) {
            const auto device = devices.find(c.source);
            result.push_back({{"id", id}, {"protocol", c.protocol}, {"state", c.state},
                {"source", c.source}, {"source_port", c.source_port},
                {"destination", c.destination}, {"destination_port", c.destination_port},
                {"route", c.route}, {"mark", c.mark}, {"active", c.active},
                {"device", device == devices.end() ? "" : device->second},
                {"first_seen", c.first_seen}, {"last_seen", c.last_seen}});
        }
        return result.dump();
    });
}

} // namespace keen_pbr3
#endif
