#ifdef WITH_API

#include "handler_connections.hpp"
#include "connection_query.hpp"
#include "dhcp_bindings.hpp"
#include "../dns/dns_query_log_maintenance.hpp"
#include "../util/base64.hpp"
#include "../util/ndmc.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <arpa/inet.h>

namespace keen_pbr3 {
namespace {

using Clock = std::chrono::system_clock;
using Connection = connection_detail::HistoryEntry;

std::mutex connections_mutex;
std::map<std::string, Connection> history;
constexpr size_t maximum_history_entries = 1500;
constexpr size_t reserved_closed_entries = 300;
constexpr size_t maximum_dns_addresses = 3000;
constexpr size_t maximum_domains_per_address = 4;
constexpr auto snapshot_ttl = std::chrono::seconds(2);
constexpr auto device_names_ttl = std::chrono::seconds(60);
std::map<std::string, std::deque<std::string>> domains_by_address;
std::streamoff dns_log_offset{0};
std::chrono::steady_clock::time_point snapshot_updated_at{};
std::chrono::steady_clock::time_point dns_log_updated_at{};
connection_detail::SnapshotObservation latest_observation;
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
    const auto maintenance = maintain_dns_query_log();
    // Never parse an accidentally unbounded tmpfs log. The old order read the
    // complete file first and only then truncated it, which could block an API
    // request after days without visiting the connections page.
    if (maintenance.state != DnsQueryLogMaintenanceState::within_limit) {
        if (maintenance.state == DnsQueryLogMaintenanceState::truncated) {
            dns_log_offset = 0;
        }
        // Even if truncation itself fails, do not turn an already oversized
        // tmpfs file into a long blocking API read.
        return;
    }
    const auto size = maintenance.observed_size;
    if (size < static_cast<std::uintmax_t>(dns_log_offset)) dns_log_offset = 0;
    std::ifstream input(dns_query_log_path);
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

}

using RoutingAddress = std::pair<int, std::array<unsigned char, 16>>;

std::optional<RoutingAddress> routing_address(const std::string& value) {
    if (value.empty() || value.find('\0') != std::string::npos) return std::nullopt;
    RoutingAddress address{AF_INET, {}};
    if (inet_pton(AF_INET, value.c_str(), address.second.data()) == 1) return address;
    address.first = AF_INET6;
    if (inet_pton(AF_INET6, value.c_str(), address.second.data()) == 1) return address;
    return std::nullopt;
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
    // ndmc must not inherit Entware's LD_LIBRARY_PATH; see src/util/ndmc.hpp.
    // A failure is reported there rather than swallowed here: an empty result
    // used to be indistinguishable from "this router has no bindings".
    const auto bindings = ndmc_capture("show ip dhcp bindings", 512U * 1024U);
    if (bindings.succeeded()) {
        merge_dhcp_bindings(bindings.capture.stdout_output, result);
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

bool is_active_conntrack_state(const Connection& connection) {
    if (connection.protocol != "tcp") return true;
    // Conntrack retains terminating TCP sessions until its timeout expires;
    // their presence in /proc alone does not mean the connection is active.
    return connection.state != "FIN_WAIT" && connection.state != "CLOSE_WAIT" &&
           connection.state != "LAST_ACK" && connection.state != "TIME_WAIT" &&
           connection.state != "CLOSE" && connection.state != "CLOSED" &&
           connection.state != "CLOSING";
}

bool trim_connection_history(connection_detail::History& entries) {
    if (entries.size() <= maximum_history_entries) return false;
    bool omitted_observed_row = false;
    std::vector<std::pair<std::int64_t, std::string>> active, closed;
    for (const auto& [key, connection] : entries) {
        (connection.active ? active : closed).emplace_back(connection.last_seen, key);
    }
    const auto active_limit = maximum_history_entries -
        std::min(reserved_closed_entries, closed.size());
    const auto remove_active = active.size() > active_limit
        ? active.size() - active_limit : 0;
    std::partial_sort(active.begin(), active.begin() + remove_active, active.end());
    for (size_t index = 0; index < remove_active; ++index) {
        omitted_observed_row |= entries.at(active[index].second).observed_in_snapshot;
        entries.erase(active[index].second);
    }
    const auto remove_closed = entries.size() > maximum_history_entries
        ? entries.size() - maximum_history_entries : 0;
    std::partial_sort(closed.begin(), closed.begin() + remove_closed, closed.end());
    for (size_t index = 0; index < remove_closed; ++index) {
        omitted_observed_row |= entries.at(closed[index].second).observed_in_snapshot;
        entries.erase(closed[index].second);
    }
    return omitted_observed_row;
}

void update_connection_history(connection_detail::History& entries,
                               std::istream& input,
                               const std::map<uint32_t, std::string>& route_names,
                               uint32_t mark_mask, std::int64_t timestamp,
                               connection_detail::SnapshotObservation* observation) {
    if (observation) *observation = {false, timestamp, false};
    // A failed read is not evidence that every observed connection closed.
    if (!input) return;
    // Keep the previous bounded snapshot separate until the stream tells us
    // which entries really disappeared. Otherwise early pruning would mistake
    // not-yet-read live sessions for history and evict genuinely closed ones.
    auto previous = std::move(entries);
    entries.clear();
    for (auto& [_, connection] : previous) {
        connection.active = false;
        connection.state = "CLOSED";
        connection.observed_in_snapshot = false;
    }
    bool snapshot_truncated = false;
    const auto trim_batch = [&entries, &snapshot_truncated] {
        // Stream even a large kernel table with at most 1564 current records,
        // plus the previous snapshot (at most 1500), never an unbounded map.
        if (entries.size() >= maximum_history_entries + 64) {
            snapshot_truncated |= trim_connection_history(entries);
        }
    };
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream stream(line);
        Connection current;
        std::string family, layer3, layer4, timeout, token;
        if (!(stream >> family)) continue;
        if (family == "ipv4" || family == "ipv6") {
            if (!(stream >> layer3 >> current.protocol >> layer4 >> timeout >> token)) continue;
        } else {
            // The legacy ip_conntrack fallback omits the layer-3 prefix.
            current.protocol = family;
            if (!(stream >> layer4 >> timeout >> token)) continue;
        }
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
        current.observed_in_snapshot = true;
        current.route = "direct";
        const auto masked_mark = current.mark & mark_mask;
        if (const auto found = route_names.find(masked_mark); found != route_names.end()) current.route = found->second;
        const auto key = current.protocol + '|' + current.source + '|' + std::to_string(current.source_port) + '|' + current.destination + '|' + std::to_string(current.destination_port);
        const auto old = previous.find(key);
        const auto duplicate = entries.find(key);
        const auto* saved = old != previous.end() ? &old->second :
            (duplicate != entries.end() ? &duplicate->second : nullptr);
        current.first_seen = saved && saved->first_seen != 0
            ? saved->first_seen : timestamp;
        current.active = is_active_conntrack_state(current);
        // Keep the last live observation stable while a terminating TCP entry
        // lingers in conntrack; do not make its age restart every snapshot.
        current.last_seen = current.active || !saved || saved->last_seen == 0
            ? timestamp : saved->last_seen;
        // Even an observed row omitted by the display cap must not return as
        // falsely closed when the remaining old rows are merged below.
        previous.erase(key);
        entries.insert_or_assign(key, std::move(current));
        trim_batch();
    }
    for (auto& [key, connection] : previous) {
        entries.emplace(key, std::move(connection));
        trim_batch();
    }
    snapshot_truncated |= trim_connection_history(entries);
    if (observation) {
        observation->available = input.eof() && !input.bad();
        observation->truncated = snapshot_truncated;
    }
}

void read_conntrack(const Config& config) {
    std::ifstream input("/proc/net/nf_conntrack");
    if (!input) input.open("/proc/net/ip_conntrack");
    update_connection_history(history, input, routes(config),
        fwmark_mask_value(config.fwmark.value_or(FwmarkConfig{})), now_seconds(),
        &latest_observation);
}

void refresh_conntrack_snapshot(const Config& config) {
    const auto now = std::chrono::steady_clock::now();
    if (snapshot_updated_at.time_since_epoch().count() != 0 &&
        now - snapshot_updated_at < snapshot_ttl) {
        return;
    }
    read_conntrack(config);
    snapshot_updated_at = now;
}

void refresh_snapshot(const Config& config) {
    const auto now = std::chrono::steady_clock::now();
    if (dns_log_updated_at.time_since_epoch().count() == 0 ||
        now - dns_log_updated_at >= snapshot_ttl) {
        read_dns_query_log();
        dns_log_updated_at = now;
    }
    refresh_conntrack_snapshot(config);
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

void connection_detail::update_history(
    History& entries, std::istream& input,
    const std::map<uint32_t, std::string>& route_names,
    uint32_t mark_mask, std::int64_t timestamp,
    SnapshotObservation* observation) {
    update_connection_history(entries, input, route_names, mark_mask, timestamp, observation);
}

RoutingConnectionsSnapshot connection_detail::select_routing_connections(
    const History& entries, const SnapshotObservation& observation,
    const std::vector<std::string>& destination_ips) {
    RoutingConnectionsSnapshot result;
    result.snapshot_available = observation.available;
    result.snapshot_at = observation.snapshot_at;
    if (!observation.available) return result;
    result.truncated = observation.truncated;

    std::vector<RoutingAddress> destinations;
    destinations.reserve(destination_ips.size());
    for (const auto& value : destination_ips) {
        if (const auto address = routing_address(value)) destinations.push_back(*address);
    }
    std::sort(destinations.begin(), destinations.end());
    destinations.erase(std::unique(destinations.begin(), destinations.end()), destinations.end());
    if (destinations.empty()) return result;

    constexpr std::size_t maximum_routing_rows = 64;
    for (const auto& [_, entry] : entries) {
        if (!entry.observed_in_snapshot) continue;
        const auto address = routing_address(entry.destination);
        if (!address || !std::binary_search(destinations.begin(), destinations.end(), *address)) continue;
        ++result.total;
        if (result.rows.size() < maximum_routing_rows) {
            auto row = entry;
            // History keeps last-active age stable for closing TCP states;
            // this projection reports when the kernel row was actually read.
            row.last_seen = observation.snapshot_at;
            result.rows.push_back(std::move(row));
        } else {
            result.truncated = true;
        }
    }
    return result;
}

RoutingConnectionsSnapshot get_routing_connections(
    const Config& config, const std::vector<std::string>& destination_ips) {
    // Connections-page enrichment can hold this mutex during an NDMS read.
    // Optional evidence must not delay an already completed DNS/FIB check.
    std::unique_lock lock(connections_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        RoutingConnectionsSnapshot unavailable;
        unavailable.snapshot_at = now_seconds();
        return unavailable;
    }
    refresh_conntrack_snapshot(config);
    return connection_detail::select_routing_connections(history, latest_observation, destination_ips);
}

void invalidate_connections_snapshot() {
    std::lock_guard lock(connections_mutex);
    snapshot_updated_at = {};
    dns_log_updated_at = {};
}

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
