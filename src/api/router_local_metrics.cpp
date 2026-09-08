#include "router_local_metrics.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <fstream>
#include <limits>
#include <sstream>
#include <sys/statvfs.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}

std::optional<std::uint64_t> number(const std::string& text) {
    const auto token = trim(text);
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(token.data(), token.data() + token.size(), result);
    if (token.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != token.data() + token.size()) return std::nullopt;
    return result;
}

std::string read_local_text(const std::string& path) {
    std::ifstream input(path);
    if (!input) return {};
    // Only small proc/sysfs files are needed; never read the conntrack table.
    std::string value(64U * 1024U, '\0');
    input.read(value.data(), static_cast<std::streamsize>(value.size()));
    value.resize(static_cast<std::size_t>(input.gcount()));
    return value;
}

std::optional<RouterDiskSpace> read_disk_space() {
    struct statvfs disk{};
    if (::statvfs("/opt", &disk) != 0 || disk.f_blocks == 0) return std::nullopt;
    const auto block = static_cast<std::uint64_t>(disk.f_frsize ? disk.f_frsize : disk.f_bsize);
    const auto blocks = static_cast<std::uint64_t>(disk.f_blocks);
    if (block == 0 || blocks > std::numeric_limits<std::uint64_t>::max() / block) {
        return std::nullopt;
    }
    const auto available = std::min(blocks, static_cast<std::uint64_t>(disk.f_bavail));
    return RouterDiskSpace{blocks * block, available * block};
}

std::string field(const std::string& text, const std::string& key) {
    std::istringstream input(text);
    for (std::string line; std::getline(input, line);) {
        const auto colon = line.find(':');
        if (colon != std::string::npos && trim(line.substr(0, colon)) == key) {
            return trim(line.substr(colon + 1));
        }
    }
    return {};
}

std::optional<std::uint64_t> memory_kb(const std::string& text, const char* key) {
    std::istringstream input(field(text, key));
    std::string amount, unit;
    if (!(input >> amount >> unit) || unit != "kB") return std::nullopt;
    return number(amount);
}

int percentage(std::uint64_t used, std::uint64_t total) {
    return static_cast<int>(static_cast<long double>(used) * 100.0L / total);
}

std::optional<double> decimal(const std::string& text) {
    try {
        std::size_t end = 0;
        const auto value = std::stod(text, &end);
        if (end == text.size() && std::isfinite(value) && value >= 0) return value;
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

} // namespace

RouterLocalMetrics::RouterLocalMetrics(RouterLocalMetricSources sources,
                                       RouterInfoCache::NowFn now)
    : sources_(std::move(sources))
    , cache_([this] { return RouterInfoCache::FetchResult{sample(), true}; },
             std::chrono::seconds(1), std::chrono::seconds(1), std::move(now)) {
    if (!sources_.read_text) sources_.read_text = read_local_text;
    if (!sources_.disk_space) sources_.disk_space = read_disk_space;
}

std::optional<RouterLocalMetrics::CpuTicks> RouterLocalMetrics::parse_cpu(
    const std::string& text) {
    std::istringstream input(text.substr(0, text.find('\n')));
    std::string label;
    if (!(input >> label) || label != "cpu") return std::nullopt;
    std::array<std::uint64_t, 8> ticks{};
    std::size_t count = 0;
    for (std::string token; count < ticks.size() && input >> token; ++count) {
        const auto value = number(token);
        if (!value) return std::nullopt;
        ticks[count] = *value;
    }
    if (count < 4) return std::nullopt;
    CpuTicks result;
    // guest/guest_nice are already included in user/nice. I/O wait is idle,
    // not work done by the CPU. Ignore the additional guest columns.
    for (std::size_t index = 0; index < ticks.size(); ++index) {
        auto& target = index == 3 || index == 4 ? result.idle : result.busy;
        if (ticks[index] > std::numeric_limits<std::uint64_t>::max() - target) {
            return std::nullopt;
        }
        target += ticks[index];
    }
    return result;
}

nlohmann::json RouterLocalMetrics::sample() {
    auto out = nlohmann::json::object();
    const auto read = [this](const char* path) {
        try { return sources_.read_text(path); }
        catch (const std::exception&) { return std::string{}; }
    };
    const auto cpuinfo = read("/proc/cpuinfo");
    for (const char* key : {"Hardware", "model name", "system type", "cpu model"}) {
        const auto model = field(cpuinfo, key);
        if (!model.empty()) { out["cpu_model"] = model; break; }
    }

    const auto cpu = parse_cpu(read("/proc/stat"));
    if (cpu && previous_cpu_ && cpu->busy >= previous_cpu_->busy &&
        cpu->idle >= previous_cpu_->idle) {
        const auto busy = cpu->busy - previous_cpu_->busy;
        const auto idle = cpu->idle - previous_cpu_->idle;
        const long double elapsed = static_cast<long double>(busy) + idle;
        if (elapsed > 0) {
            out["cpu_load_percent"] = static_cast<int>(
                static_cast<long double>(busy) * 100.0L / elapsed);
        }
    }
    // An absent/reset counter starts a fresh sample pair, never a fake 0/100%.
    previous_cpu_ = cpu;

    for (const char* path : {"/sys/class/thermal/thermal_zone0/temp",
                             "/sys/devices/virtual/thermal/thermal_zone0/temp",
                             "/sys/class/hwmon/hwmon0/temp1_input"}) {
        if (const auto raw = number(read(path)); raw && *raw > 0) {
            const auto value = *raw >= 1000 ? *raw / 1000 : *raw;
            if (value <= static_cast<std::uint64_t>(std::numeric_limits<int>::max())) {
                out["cpu_temperature_c"] = value;
                break;
            }
        }
    }

    const auto meminfo = read("/proc/meminfo");
    if (const auto total = memory_kb(meminfo, "MemTotal"); total && *total > 0) {
        out["memory_total_mb"] = *total / 1024;
        if (const auto available = memory_kb(meminfo, "MemAvailable")) {
            const auto used = *total - std::min(*available, *total);
            out["memory_used_mb"] = used / 1024;
            out["memory_used_percent"] = percentage(used, *total);
        }
    }

    try {
        if (const auto disk = sources_.disk_space(); disk && disk->total_bytes > 0) {
            const auto used = disk->total_bytes -
                std::min(disk->available_bytes, disk->total_bytes);
            out["disk_total_mb"] = disk->total_bytes / (1024ULL * 1024ULL);
            out["disk_used_mb"] = used / (1024ULL * 1024ULL);
            out["disk_used_percent"] = percentage(used, disk->total_bytes);
        }
    } catch (const std::exception&) {
    }

    std::istringstream uptime(read("/proc/uptime"));
    std::string uptime_token;
    if (uptime >> uptime_token) {
        const auto seconds = decimal(uptime_token);
        if (seconds && static_cast<long double>(*seconds) <
                           static_cast<long double>(std::numeric_limits<std::int64_t>::max())) {
            out["uptime_seconds"] = static_cast<std::int64_t>(*seconds);
        }
    }
    std::istringstream loadavg(read("/proc/loadavg"));
    std::vector<double> loads;
    for (std::string token; loads.size() < 3 && loadavg >> token;) {
        const auto value = decimal(token);
        if (!value) break;
        loads.push_back(*value);
    }
    if (loads.size() == 3) out["load_average"] = loads;

    auto count = number(read("/proc/sys/net/netfilter/nf_conntrack_count"));
    auto maximum = number(read("/proc/sys/net/netfilter/nf_conntrack_max"));
    if (!count) count = number(read("/proc/sys/net/ipv4/netfilter/ip_conntrack_count"));
    if (!maximum) maximum = number(read("/proc/sys/net/ipv4/netfilter/ip_conntrack_max"));
    if (maximum && *maximum > 0) {
        out["conntrack_total"] = *maximum;
        if (count) out["conntrack_free"] = *maximum - std::min(*count, *maximum);
    }
    return out;
}

nlohmann::json RouterLocalMetrics::get() { return cache_.get(); }

nlohmann::json local_router_metrics() {
    static RouterLocalMetrics metrics;
    return metrics.get();
}

} // namespace keen_pbr3
