#ifdef WITH_API

#include "handler_connections.hpp"
#include "connection_query.hpp"
#include "../util/base64.hpp"
#include "../util/safe_exec.hpp"

#include <algorithm>
#include <chrono>
#include <deque>
#include <fstream>
#include <filesystem>
#include <iterator>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <vector>
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
constexpr auto snapshot_ttl = std::chrono::seconds(2);
constexpr auto device_names_ttl = std::chrono::seconds(60);
std::map<std::string, std::deque<std::string>> domains_by_address;
std::streamoff dns_log_offset{0};
std::chrono::steady_clock::time_point snapshot_updated_at{};
std::chrono::steady_clock::time_point device_names_updated_at{};
std::map<std::string, std::string> cached_devices;

struct ConnectionQuerySnapshot {
    std::vector<std::string> ids;
    std::int64_t snapshot_at{0};
    std::chrono::steady_clock::time_point created_at;
};

std::map<std::string, ConnectionQuerySnapshot> query_snapshots;
std::uint64_t next_query_snapshot_id{0};
constexpr std::size_t maximum_query_snapshots = 8;
constexpr auto query_snapshot_ttl = std::chrono::seconds(60);

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

std::map<std::string, std::string> read_device_names() {
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
    const auto bindings = safe_exec_capture(
        {"ndmc", "-c", "show ip dhcp bindings"}, true, 512U * 1024U);
    if (bindings.exit_code == 0 && !bindings.truncated) {
        std::string ip, hostname, name;
        const auto flush = [&]() {
            const auto& preferred = name.empty() ? hostname : name;
            if (!ip.empty() && !preferred.empty()) result[ip] = preferred;
        };
        std::istringstream output(bindings.stdout_output);
        for (std::string line; std::getline(output, line);) {
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
    }
    return result;
}

const std::map<std::string, std::string>& device_names() {
    const auto now = std::chrono::steady_clock::now();
    if (device_names_updated_at.time_since_epoch().count() == 0 ||
        now - device_names_updated_at >= device_names_ttl) {
        cached_devices = read_device_names();
        device_names_updated_at = now;
    }
    return cached_devices;
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
        Connection current;
        std::string family, layer3, layer4, timeout, token;
        if (!(stream >> family >> layer3 >> current.protocol >> layer4 >> timeout >> token)) continue;
        if (token.find('=') == std::string::npos) {
            current.state = token;
            if (!(stream >> token)) continue;
        } else {
            current.state = current.protocol == "udp" ? "ACTIVE" : "UNKNOWN";
        }
        do {
            if (current.source.empty()) current.source = value_after(token, "src=");
            else if (current.destination.empty()) current.destination = value_after(token, "dst=");
            else if (current.source_port == 0) current.source_port = static_cast<uint16_t>(number(value_after(token, "sport=")));
            else if (current.destination_port == 0) current.destination_port = static_cast<uint16_t>(number(value_after(token, "dport=")));
            if (const auto mark = value_after(token, "mark="); !mark.empty()) current.mark = number(mark);
        } while (stream >> token);
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
    if (history.size() > maximum_history_entries) {
        std::vector<std::pair<std::int64_t, std::string>> by_age;
        by_age.reserve(history.size());
        for (const auto& [key, connection] : history) {
            by_age.emplace_back(connection.last_seen, key);
        }
        const auto remove_count = history.size() - maximum_history_entries;
        std::partial_sort(by_age.begin(), by_age.begin() + remove_count, by_age.end());
        for (size_t index = 0; index < remove_count; ++index) {
            history.erase(by_age[index].second);
        }
    }
}

void refresh_snapshot(const Config& config) {
    const auto now = std::chrono::steady_clock::now();
    if (snapshot_updated_at.time_since_epoch().count() != 0 &&
        now - snapshot_updated_at < snapshot_ttl) {
        return;
    }
    read_dns_query_log();
    read_conntrack(config);
    snapshot_updated_at = now;
}

api::ConnectionRecord connection_record(
    const std::string& id,
    const Connection& connection,
    const std::map<std::string, std::string>& devices) {
    api::ConnectionRecord record;
    record.id = id;
    record.protocol = connection.protocol;
    record.state = connection.state;
    record.source = connection.source;
    record.source_port = connection.source_port;
    record.destination = connection.destination;
    record.destination_port = connection.destination_port;
    record.route = connection.route;
    record.mark = connection.mark;
    record.active = connection.active;
    const auto device = devices.find(connection.source);
    record.device = device == devices.end() ? "" : device->second;
    const auto domains = domains_by_address.find(connection.destination);
    if (domains != domains_by_address.end()) {
        record.destination_domains.assign(
            domains->second.begin(),
            domains->second.end());
    }
    record.first_seen = connection.first_seen;
    record.last_seen = connection.last_seen;
    return record;
}

void validate_connection_query(const api::ConnectionQueryRequest& request) {
    const auto validate_length = [](const std::optional<std::string>& value,
                                    std::size_t maximum,
                                    const char* field) {
        if (value && value->size() > maximum) {
            throw ApiError(
                std::string(field) + " exceeds maximum length",
                400);
        }
    };
    validate_length(request.cursor, 256, "cursor");
    validate_length(request.search, 128, "search");
    validate_length(request.state, 32, "state");
    validate_length(request.route, 64, "route");
    validate_length(request.device, 128, "device");
    if (request.limit &&
        (*request.limit < 1 || *request.limit > 250)) {
        throw ApiError("limit must be between 1 and 250", 400);
    }
}

void purge_query_snapshots() {
    const auto now = std::chrono::steady_clock::now();
    for (auto iterator = query_snapshots.begin();
         iterator != query_snapshots.end();) {
        if (now - iterator->second.created_at >= query_snapshot_ttl) {
            iterator = query_snapshots.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

std::pair<std::string, std::size_t> decode_query_cursor(
    const std::string& cursor) {
    try {
        const auto decoded = base64_decode(cursor);
        const auto separator = decoded.find('|');
        if (separator == std::string::npos || separator == 0 ||
            separator + 1 >= decoded.size()) {
            throw std::invalid_argument("invalid cursor shape");
        }
        std::size_t parsed = 0;
        const auto offset = std::stoull(
            decoded.substr(separator + 1),
            &parsed,
            10);
        if (parsed != decoded.size() - separator - 1) {
            throw std::invalid_argument("invalid cursor offset");
        }
        return {decoded.substr(0, separator),
                static_cast<std::size_t>(offset)};
    } catch (const std::exception&) {
        throw ApiError("Invalid connection cursor", 400);
    }
}

std::string encode_query_cursor(const std::string& snapshot_id,
                                std::size_t offset) {
    return base64_encode(snapshot_id + "|" + std::to_string(offset));
}

api::ConnectionPage connection_page(
    const ConnectionQuerySnapshot& snapshot,
    const std::string& snapshot_id,
    std::size_t offset,
    std::size_t limit) {
    if (offset > snapshot.ids.size()) {
        throw ApiError("Invalid connection cursor offset", 400);
    }

    api::ConnectionPage page;
    page.total = static_cast<std::int64_t>(snapshot.ids.size());
    page.snapshot_at = snapshot.snapshot_at;
    const auto& devices = device_names();
    const auto end = std::min(snapshot.ids.size(), offset + limit);
    page.items.reserve(end - offset);
    for (std::size_t index = offset; index < end; ++index) {
        const auto connection = history.find(snapshot.ids[index]);
        if (connection == history.end()) continue;
        page.items.push_back(connection_record(
            connection->first,
            connection->second,
            devices));
    }
    if (end < snapshot.ids.size()) {
        page.next_cursor = encode_query_cursor(snapshot_id, end);
    }
    return page;
}

api::ConnectionPage query_connections(
    const ApiContext& ctx,
    const api::ConnectionQueryRequest& request) {
    validate_connection_query(request);
    std::lock_guard lock(connections_mutex);
    purge_query_snapshots();
    const auto limit =
        static_cast<std::size_t>(request.limit.value_or(100));

    if (request.cursor) {
        const auto [snapshot_id, offset] =
            decode_query_cursor(*request.cursor);
        const auto snapshot = query_snapshots.find(snapshot_id);
        if (snapshot == query_snapshots.end()) {
            throw ApiError(
                "Connection cursor expired; restart from the first page",
                409);
        }
        return connection_page(
            snapshot->second,
            snapshot_id,
            offset,
            limit);
    }

    refresh_snapshot(ctx.get_visible_config());
    const auto& devices = device_names();
    std::vector<api::ConnectionRecord> records;
    records.reserve(history.size());
    for (const auto& [id, connection] : history) {
        records.push_back(connection_record(id, connection, devices));
    }
    records = filter_and_sort_connections(std::move(records), request);

    ConnectionQuerySnapshot snapshot;
    snapshot.snapshot_at = now_seconds();
    snapshot.created_at = std::chrono::steady_clock::now();
    snapshot.ids.reserve(records.size());
    for (const auto& record : records) snapshot.ids.push_back(record.id);

    const std::string snapshot_id =
        std::to_string(snapshot.snapshot_at) + "-" +
        std::to_string(++next_query_snapshot_id);
    if (snapshot.ids.size() > limit) {
        while (query_snapshots.size() >= maximum_query_snapshots) {
            const auto oldest = std::min_element(
                query_snapshots.begin(),
                query_snapshots.end(),
                [](const auto& left, const auto& right) {
                    return left.second.created_at < right.second.created_at;
                });
            if (oldest == query_snapshots.end()) break;
            query_snapshots.erase(oldest);
        }
        query_snapshots.emplace(snapshot_id, snapshot);
    }
    return connection_page(snapshot, snapshot_id, 0, limit);
}

std::string serialize_connections(const ApiContext& ctx, bool active_only) {
    std::lock_guard lock(connections_mutex);
    refresh_snapshot(ctx.get_visible_config());
    const auto& devices = device_names();
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, c] : history) {
        if (active_only && !c.active) continue;
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
}

} // namespace

void register_connections_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/connections", [&ctx]() -> std::string {
        return serialize_connections(ctx, false);
    });
    server.get("/api/connections/active", [&ctx]() -> std::string {
        return serialize_connections(ctx, true);
    });
    server.post(
        "/api/connections/query",
        [&ctx](const std::string& body) -> std::string {
            try {
                const auto request =
                    nlohmann::json::parse(body)
                        .get<api::ConnectionQueryRequest>();
                return nlohmann::json(query_connections(ctx, request)).dump();
            } catch (const nlohmann::json::exception& error) {
                throw ApiError(
                    std::string("Invalid connection query: ") + error.what(),
                    400);
            }
        });
}

} // namespace keen_pbr3
#endif
