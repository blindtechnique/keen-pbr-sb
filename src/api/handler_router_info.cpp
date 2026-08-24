#ifdef WITH_API

#include "handler_router_info.hpp"
#include "router_info_cache.hpp"

#include "../http/http_client.hpp"
#include "../log/logger.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <sys/statvfs.h>

namespace keen_pbr3 {

namespace {

constexpr const char* kRciBase = "http://127.0.0.1:79/rci";
// The overview refetches every 15 seconds. A 30-second accepted snapshot keeps
// that cadence useful without fanning out five RCI requests on every poll.
constexpr auto kCacheTtl = std::chrono::seconds(30);
// Five RCI calls per failed attempt at most twice a minute stays within the
// router-info ownership budget even when RCI is wholly absent (OpenWrt).
constexpr auto kFailureRetry = std::chrono::seconds(30);

std::optional<nlohmann::json> rci_get(const std::string& path) {
    try {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(2));
        client.set_max_response_size(2U * 1024U * 1024U);
        return nlohmann::json::parse(client.download(std::string(kRciBase) + path));
    } catch (const std::exception&) {
        // The firmware answers with an error object for unsupported paths and
        // is simply absent on OpenWrt builds. Neither is worth logging loudly.
        return std::nullopt;
    }
}

bool has_string_field(const nlohmann::json& value, const char* field) {
    const auto found = value.find(field);
    return found != value.end() && found->is_string();
}

bool has_number_field(const nlohmann::json& value, const char* field) {
    const auto found = value.find(field);
    return found != value.end() && found->is_number();
}

bool has_boolean_field(const nlohmann::json& value, const char* field) {
    const auto found = value.find(field);
    return found != value.end() && found->is_boolean();
}

bool authoritative_version(const std::optional<nlohmann::json>& value) {
    if (!value || !value->is_object()) {
        return false;
    }
    return has_string_field(*value, "model") ||
           has_string_field(*value, "vendor") ||
           has_string_field(*value, "release") ||
           has_string_field(*value, "title") ||
           has_string_field(*value, "arch") ||
           (value->contains("ndm") && value->at("ndm").is_object());
}

bool authoritative_system(const std::optional<nlohmann::json>& value) {
    if (!value || !value->is_object()) {
        return false;
    }
    return has_number_field(*value, "cpuload") ||
           has_number_field(*value, "conntotal") ||
           has_number_field(*value, "connfree");
}

bool authoritative_internet(const std::optional<nlohmann::json>& value) {
    if (!value || !value->is_object()) {
        return false;
    }
    return has_boolean_field(*value, "internet") ||
           (value->contains("gateway") &&
            value->at("gateway").is_object());
}

bool authoritative_hotspot(const std::optional<nlohmann::json>& value) {
    if (!value || !value->is_object()) {
        return false;
    }
    const auto hosts = value->find("host");
    return hosts != value->end() && hosts->is_array();
}

bool authoritative_interface(const nlohmann::json& value) {
    if (!value.is_object()) {
        return false;
    }
    return has_string_field(value, "id") ||
           has_string_field(value, "type") ||
           has_string_field(value, "description") ||
           has_string_field(value, "state") ||
           has_string_field(value, "address") ||
           has_boolean_field(value, "connected") ||
           value.contains("link");
}

std::string read_text_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return {};
    }
    std::ostringstream out;
    out << file.rdbuf();
    return out.str();
}

std::string trim(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return {};
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

// Reads "key: value" out of /proc-style files.
std::string proc_field(const std::string& content, const std::string& key) {
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        if (trim(line.substr(0, colon)) == key) {
            return trim(line.substr(colon + 1));
        }
    }
    return {};
}

std::optional<long> meminfo_kb(const std::string& content, const std::string& key) {
    const auto raw = proc_field(content, key);
    if (raw.empty()) {
        return std::nullopt;
    }
    try {
        return std::stol(raw);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::string cpu_model() {
    const auto cpuinfo = read_text_file("/proc/cpuinfo");
    for (const char* key : {"Hardware", "model name", "system type", "cpu model"}) {
        const auto value = proc_field(cpuinfo, key);
        if (!value.empty()) {
            return value;
        }
    }
    return {};
}

// Kernel thermal zones report milli-degrees; some report whole degrees.
std::optional<int> zone_temperature(const std::string& path) {
    const auto raw = trim(read_text_file(path));
    if (raw.empty()) {
        return std::nullopt;
    }
    try {
        const long value = std::stol(raw);
        if (value <= 0) {
            return std::nullopt;
        }
        return static_cast<int>(value > 1000 ? value / 1000 : value);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<int> cpu_temperature() {
    // thermal_zone0 is the SoC sensor on the aarch64 units; the rest of the
    // zones are ethernet and memory controllers and would only confuse.
    for (const char* path : {"/sys/class/thermal/thermal_zone0/temp",
                             "/sys/devices/virtual/thermal/thermal_zone0/temp",
                             "/sys/class/hwmon/hwmon0/temp1_input"}) {
        if (const auto value = zone_temperature(path)) {
            return value;
        }
    }
    return std::nullopt;
}

// The WAN address is taken from the interface the firmware itself considers
// the default gateway. Matching on names like "ISP" only works on one router.
struct WanAddressResult {
    std::optional<std::string> address;
    bool success{true};
};

WanAddressResult wan_address(const nlohmann::json& internet_status) {
    if (!internet_status.is_object()) {
        return {};
    }
    const auto gateway = internet_status.find("gateway");
    if (gateway == internet_status.end() || !gateway->is_object()) {
        return {};
    }
    const auto interface_id = gateway->value("interface", std::string{});
    if (interface_id.empty()) {
        return {};
    }

    const auto interface = rci_get("/show/interface/" + interface_id);
    if (!interface || !authoritative_interface(*interface)) {
        return {std::nullopt, false};
    }
    const auto address = interface->value("address", std::string{});
    if (address.empty()) {
        return {};
    }
    return {address, true};
}

struct ClientCounts {
    int active{0};
    int total{0};
};

ClientCounts count_clients(const nlohmann::json& hotspot) {
    ClientCounts counts;
    if (!hotspot.is_object()) {
        return counts;
    }
    const auto hosts = hotspot.find("host");
    if (hosts == hotspot.end() || !hosts->is_array()) {
        return counts;
    }
    for (const auto& host : *hosts) {
        if (!host.is_object()) {
            continue;
        }
        counts.total += 1;
        if (host.value("active", false)) {
            counts.active += 1;
        }
    }
    return counts;
}

RouterInfoCache::FetchResult build_router_info() {
    nlohmann::json out;

    const auto version_result = rci_get("/show/version");
    const auto system_result = rci_get("/show/system");
    const auto internet_result = rci_get("/show/internet/status");
    const auto hotspot_result = rci_get("/show/ip/hotspot");
    const auto version =
        version_result.value_or(nlohmann::json::object());
    const auto system =
        system_result.value_or(nlohmann::json::object());
    const auto internet =
        internet_result.value_or(nlohmann::json::object());
    const auto hotspot =
        hotspot_result.value_or(nlohmann::json::object());

    out["model"] = version.value("model", std::string{});
    out["vendor"] = version.value("vendor", std::string{});
    out["hw_id"] = version.value("hw_id", std::string{});
    out["region"] = version.value("region", std::string{});
    out["arch"] = version.value("arch", std::string{});
    out["firmware_title"] = version.value("title", std::string{});
    out["firmware_release"] = version.value("release", std::string{});
    out["firmware_channel"] = version.value("sandbox", std::string{});
    if (const auto ndm = version.find("ndm");
        ndm != version.end() && ndm->is_object()) {
        out["firmware_date"] = ndm->value("cdate", std::string{});
    }

    out["cpu_model"] = cpu_model();
    if (const auto load = system.find("cpuload");
        load != system.end() && load->is_number()) {
        out["cpu_load_percent"] = load->get<int>();
    }
    if (const auto temperature = cpu_temperature()) {
        out["cpu_temperature_c"] = *temperature;
    }

    // /proc/meminfo rather than the RCI "memory" string: the firmware reports
    // the raw total, while MemAvailable accounts for reclaimable cache and is
    // what actually matters to a user reading "how full is my router".
    const auto meminfo = read_text_file("/proc/meminfo");
    const auto mem_total = meminfo_kb(meminfo, "MemTotal");
    const auto mem_available = meminfo_kb(meminfo, "MemAvailable");
    if (mem_total && *mem_total > 0) {
        out["memory_total_mb"] = static_cast<int>(*mem_total / 1024);
        if (mem_available) {
            const long used = *mem_total - *mem_available;
            out["memory_used_mb"] = static_cast<int>(used / 1024);
            out["memory_used_percent"] = static_cast<int>(used * 100 / *mem_total);
        }
    }

    struct statvfs disk{};
    if (::statvfs("/opt", &disk) == 0 && disk.f_blocks > 0) {
        const auto block_size = static_cast<unsigned long long>(disk.f_frsize);
        const auto total = static_cast<unsigned long long>(disk.f_blocks) * block_size;
        const auto available = static_cast<unsigned long long>(disk.f_bavail) * block_size;
        const auto used = total - available;
        out["disk_total_mb"] = total / (1024ULL * 1024ULL);
        out["disk_used_mb"] = used / (1024ULL * 1024ULL);
        out["disk_used_percent"] = static_cast<int>(used * 100ULL / total);
    }

    const auto uptime_raw = trim(read_text_file("/proc/uptime"));
    if (!uptime_raw.empty()) {
        try {
            out["uptime_seconds"] = static_cast<long>(std::stod(uptime_raw));
        } catch (const std::exception&) {
        }
    }

    const auto loadavg_raw = trim(read_text_file("/proc/loadavg"));
    if (!loadavg_raw.empty()) {
        std::istringstream stream(loadavg_raw);
        std::vector<double> values;
        double value = 0;
        while (values.size() < 3 && stream >> value) {
            values.push_back(value);
        }
        if (values.size() == 3) {
            out["load_average"] = values;
        }
    }

    if (const auto online = internet.find("internet");
        online != internet.end() && online->is_boolean()) {
        out["internet"] = online->get<bool>();
    }
    const auto wan = wan_address(internet);
    if (wan.address.has_value()) {
        out["wan_address"] = *wan.address;
    }

    const auto clients = count_clients(hotspot);
    out["clients_active"] = clients.active;
    out["clients_total"] = clients.total;

    if (const auto total = system.find("conntotal");
        total != system.end() && total->is_number()) {
        out["conntrack_total"] = total->get<int>();
    }
    if (const auto free = system.find("connfree");
        free != system.end() && free->is_number()) {
        out["conntrack_free"] = free->get<int>();
    }

    out["available"] = !out["model"].get<std::string>().empty() ||
                       !out["cpu_model"].get<std::string>().empty();
    return {
        std::move(out),
        authoritative_version(version_result) &&
            authoritative_system(system_result) &&
            authoritative_internet(internet_result) &&
            authoritative_hotspot(hotspot_result) &&
            wan.success,
    };
}

nlohmann::json cached_router_info() {
    // A failed RCI refresh deliberately keeps one whole-generation LKG, so
    // local /proc metrics freeze with it instead of producing a mixed-age
    // response. Splitting local and RCI ownership is a separate later slice.
    static RouterInfoCache cache(
        [] { return build_router_info(); },
        kCacheTtl,
        kFailureRetry);
    return cache.get();
}

} // namespace

void register_router_info_handler(ApiServer& server, ApiContext& /*ctx*/) {
    // GET /api/system/router - hardware and firmware facts for the overview.
    server.get("/api/system/router",
               []() -> std::string { return cached_router_info().dump(); });
}

} // namespace keen_pbr3

#endif // WITH_API
