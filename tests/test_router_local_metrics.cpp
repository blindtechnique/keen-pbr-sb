#include <doctest/doctest.h>

#include "../src/api/router_local_metrics.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

class ManualClock {
public:
    RouterInfoCache::Clock::time_point now() const {
        return RouterInfoCache::Clock::time_point{elapsed_};
    }

    void advance(std::chrono::milliseconds duration) { elapsed_ += duration; }

private:
    std::chrono::milliseconds elapsed_{0};
};

struct LocalMetricsFixture {
    ManualClock clock;
    std::map<std::string, std::string> files;
    std::set<std::string> throwing_paths;
    std::map<std::string, int> reads;
    std::optional<RouterDiskSpace> disk;
    bool throw_disk{false};
    int disk_reads{0};
    RouterLocalMetrics metrics;

    LocalMetricsFixture()
        : metrics(sources(), [this] { return clock.now(); }) {}

    RouterLocalMetricSources sources() {
        return {
            [this](const std::string& path) {
                ++reads[path];
                if (throwing_paths.count(path)) {
                    throw std::runtime_error("injected local read failure");
                }
                const auto found = files.find(path);
                return found == files.end() ? std::string{} : found->second;
            },
            [this]() -> std::optional<RouterDiskSpace> {
                ++disk_reads;
                if (throw_disk) throw std::runtime_error("injected disk failure");
                return disk;
            },
        };
    }

    nlohmann::json next() {
        clock.advance(1s);
        return metrics.get();
    }
};

TEST_CASE("local router metrics CPU uses interval work, counts nice, and excludes guest duplication") {
    LocalMetricsFixture fixture;
    fixture.files["/proc/stat"] =
        "cpu 100 20 30 200 10 4 6 10 90 15\n"
        "cpu0 999 999 999 999 999 999 999 999\n";
    CHECK_FALSE(fixture.metrics.get().contains("cpu_load_percent"));

    // Work delta = 20 user + 10 nice + 10 system + 5 irq + 5 softirq + 5 steal.
    // Idle delta = 30 idle + 25 iowait. Guest columns are already in user/nice.
    fixture.files["/proc/stat"] =
        "cpu 120 30 40 230 35 9 11 15 5000 9000\n"
        "cpu0 1 1 1 1 1 1 1 1\n";
    CHECK(fixture.next().at("cpu_load_percent") == 50);
}

TEST_CASE("local router metrics reset, missing and unchanged CPU counters never invent load") {
    LocalMetricsFixture fixture;
    fixture.files["/proc/stat"] = "cpu 100 0 0 200\n";
    CHECK_FALSE(fixture.metrics.get().contains("cpu_load_percent"));
    CHECK_FALSE(fixture.next().contains("cpu_load_percent"));

    fixture.files["/proc/stat"] = "cpu 5 0 0 10\n";
    CHECK_FALSE(fixture.next().contains("cpu_load_percent"));
    fixture.files["/proc/stat"] = "cpu 10 0 0 15\n";
    CHECK(fixture.next().at("cpu_load_percent") == 50);

    fixture.files.erase("/proc/stat");
    CHECK_FALSE(fixture.next().contains("cpu_load_percent"));
    fixture.files["/proc/stat"] = "cpu 20 0 0 25\n";
    CHECK_FALSE(fixture.next().contains("cpu_load_percent"));
    fixture.files["/proc/stat"] = "cpu 20 0 0 125\n";
    // A real all-idle interval is different from unavailable data.
    CHECK(fixture.next().at("cpu_load_percent") == 0);
}

TEST_CASE("local router metrics coalesces reads until the exact one second boundary") {
    LocalMetricsFixture fixture;
    fixture.files["/proc/stat"] = "cpu 100 0 0 100\n";
    fixture.files["/proc/uptime"] = "10.75 900.0\n";
    const auto first = fixture.metrics.get();
    const auto initial_reads = fixture.reads;
    CHECK(first.at("uptime_seconds") == 10);

    fixture.files["/proc/stat"] = "cpu 150 0 0 150\n";
    fixture.files["/proc/uptime"] = "20.25 1000.0\n";
    CHECK(fixture.metrics.get() == first);
    fixture.clock.advance(999ms);
    CHECK(fixture.metrics.get() == first);
    CHECK(fixture.reads == initial_reads);
    CHECK(fixture.disk_reads == 1);

    fixture.clock.advance(1ms);
    const auto second = fixture.metrics.get();
    CHECK(second.at("uptime_seconds") == 20);
    CHECK(second.at("cpu_load_percent") == 50);
    CHECK(fixture.reads.at("/proc/stat") == 2);
    CHECK(fixture.disk_reads == 2);
    CHECK(fixture.metrics.get() == second);
    CHECK(fixture.disk_reads == 2);
}

TEST_CASE("local router metrics combines RAM, disk, uptime, thermal, load and conntrack readers") {
    LocalMetricsFixture fixture;
    fixture.files = {
        {"/proc/cpuinfo", "Hardware : Router SoC\nmodel name : secondary name\n"},
        {"/proc/stat", "cpu 10 0 0 90\n"},
        {"/proc/meminfo", "MemTotal: 524288 kB\nMemAvailable: 131072 kB\nMemFree: 8192 kB\n"},
        {"/proc/uptime", "86400.95 100000.0\n"},
        {"/proc/loadavg", "0.50 1.25 2.75 1/100 2345\n"},
        {"/sys/class/thermal/thermal_zone0/temp", "53555\n"},
        {"/proc/sys/net/netfilter/nf_conntrack_count", "3\n"},
        {"/proc/sys/net/netfilter/nf_conntrack_max", "10\n"},
    };
    fixture.disk = RouterDiskSpace{4ULL * 1024 * 1024 * 1024, 1ULL * 1024 * 1024 * 1024};
    const auto result = fixture.metrics.get();
    CHECK(result.at("cpu_model") == "Router SoC");
    CHECK(result.at("cpu_temperature_c") == 53);
    CHECK(result.at("memory_total_mb") == 512);
    CHECK(result.at("memory_used_mb") == 384);
    CHECK(result.at("memory_used_percent") == 75);
    CHECK(result.at("disk_total_mb") == 4096);
    CHECK(result.at("disk_used_mb") == 3072);
    CHECK(result.at("disk_used_percent") == 75);
    CHECK(result.at("uptime_seconds") == 86400);
    CHECK(result.at("load_average") == nlohmann::json::array({0.5, 1.25, 2.75}));
    CHECK(result.at("conntrack_total") == 10);
    CHECK(result.at("conntrack_free") == 7);
    CHECK_FALSE(result.contains("cpu_load_percent"));
    CHECK(fixture.reads.count("/proc/net/nf_conntrack") == 0);
    CHECK(fixture.reads.count("/proc/net/ip_conntrack") == 0);
}

TEST_CASE("local router metrics isolates read failures and omits failed fields on a fresh sample") {
    LocalMetricsFixture fixture;
    fixture.files = {
        {"/proc/meminfo", "MemTotal: 2048 kB\nMemAvailable: 1024 kB\n"},
        {"/proc/uptime", "40.5 100\n"},
        {"/proc/loadavg", "0.1 0.2 0.3 1/5 123\n"},
        {"/sys/class/thermal/thermal_zone0/temp", "47000\n"},
    };
    fixture.disk = RouterDiskSpace{2ULL * 1024 * 1024, 1024 * 1024};
    CHECK(fixture.metrics.get().at("memory_used_percent") == 50);

    fixture.throwing_paths = {"/proc/stat", "/proc/cpuinfo", "/proc/meminfo"};
    fixture.throw_disk = true;
    fixture.files["/proc/uptime"] = "41.5 101\n";
    const auto failed = fixture.next();
    CHECK_FALSE(failed.contains("cpu_model"));
    CHECK_FALSE(failed.contains("cpu_load_percent"));
    CHECK_FALSE(failed.contains("memory_total_mb"));
    CHECK_FALSE(failed.contains("memory_used_mb"));
    CHECK_FALSE(failed.contains("memory_used_percent"));
    CHECK_FALSE(failed.contains("disk_total_mb"));
    CHECK_FALSE(failed.contains("disk_used_mb"));
    CHECK_FALSE(failed.contains("disk_used_percent"));
    CHECK(failed.at("uptime_seconds") == 41);
    CHECK(failed.at("cpu_temperature_c") == 47);
    CHECK(failed.at("load_average") == nlohmann::json::array({0.1, 0.2, 0.3}));

    fixture.throwing_paths.clear();
    fixture.throw_disk = false;
    CHECK(fixture.next().at("memory_used_percent") == 50);
}

TEST_CASE("local router metrics unavailable or malformed inputs do not fabricate zero fields") {
    LocalMetricsFixture fixture;
    CHECK(fixture.metrics.get() == nlohmann::json::object());
    fixture.files = {
        {"/proc/stat", "cpu0 5 0 0 95\n"},
        {"/proc/meminfo", "MemTotal: 1048576 kB\nMemAvailable: -1 kB\n"},
        {"/proc/uptime", "nan 200\n"},
        {"/proc/loadavg", "1.0 invalid 2.0 1/10 123\n"},
        {"/sys/class/thermal/thermal_zone0/temp", "-1000\n"},
        {"/sys/devices/virtual/thermal/thermal_zone0/temp", "0\n"},
        {"/proc/sys/net/netfilter/nf_conntrack_count", "garbage\n"},
        {"/proc/sys/net/netfilter/nf_conntrack_max", "0\n"},
    };
    fixture.disk = RouterDiskSpace{0, 1024};
    const auto result = fixture.next();
    CHECK(result == nlohmann::json{{"memory_total_mb", 1024}});
}

TEST_CASE("local router metrics uses available CPU model and thermal fallback paths") {
    LocalMetricsFixture fixture;
    fixture.files = {
        {"/proc/cpuinfo", "system type : MediaTek MT7621\ncpu model : MIPS\n"},
        {"/sys/class/thermal/thermal_zone0/temp", "not available\n"},
        {"/sys/class/hwmon/hwmon0/temp1_input", "48000\n"},
    };
    const auto fallback = fixture.metrics.get();
    CHECK(fallback.at("cpu_model") == "MediaTek MT7621");
    CHECK(fallback.at("cpu_temperature_c") == 48);
    CHECK(fixture.reads.at("/sys/devices/virtual/thermal/thermal_zone0/temp") == 1);
    CHECK(fixture.reads.at("/sys/class/hwmon/hwmon0/temp1_input") == 1);

    fixture.files["/sys/class/thermal/thermal_zone0/temp"] = "55000\n";
    CHECK(fixture.next().at("cpu_temperature_c") == 55);
    CHECK(fixture.reads.at("/sys/class/hwmon/hwmon0/temp1_input") == 1);

    fixture.files["/sys/class/thermal/thermal_zone0/temp"] = "1000\n";
    CHECK(fixture.next().at("cpu_temperature_c") == 1);
    CHECK(fixture.reads.at("/sys/class/hwmon/hwmon0/temp1_input") == 1);
}

TEST_CASE("local router metrics RAM does not substitute MemFree and clamps available space") {
    LocalMetricsFixture fixture;
    fixture.files["/proc/meminfo"] = "MemTotal: 4096 kB\nMemFree: 2048 kB\n";
    const auto incomplete = fixture.metrics.get();
    CHECK(incomplete.at("memory_total_mb") == 4);
    CHECK_FALSE(incomplete.contains("memory_used_mb"));
    CHECK_FALSE(incomplete.contains("memory_used_percent"));

    fixture.files["/proc/meminfo"] = "MemTotal: 4096 kB\nMemAvailable: 8192 kB\n";
    fixture.disk = RouterDiskSpace{4ULL * 1024 * 1024, 8ULL * 1024 * 1024};
    const auto available = fixture.next();
    CHECK(available.at("memory_used_mb") == 0);
    CHECK(available.at("memory_used_percent") == 0);
    CHECK(available.at("disk_used_mb") == 0);
    CHECK(available.at("disk_used_percent") == 0);

    fixture.files["/proc/meminfo"] = "MemTotal: 4096 bytes\nMemAvailable: 0 kB\n";
    CHECK_FALSE(fixture.next().contains("memory_total_mb"));
}

TEST_CASE("local router metrics supports legacy conntrack counters without reading the flow table") {
    LocalMetricsFixture fixture;
    fixture.files = {
        {"/proc/sys/net/netfilter/nf_conntrack_count", "invalid\n"},
        {"/proc/sys/net/ipv4/netfilter/ip_conntrack_count", "25\n"},
        {"/proc/sys/net/ipv4/netfilter/ip_conntrack_max", "100\n"},
    };
    const auto legacy = fixture.metrics.get();
    CHECK(legacy.at("conntrack_total") == 100);
    CHECK(legacy.at("conntrack_free") == 75);

    fixture.files["/proc/sys/net/netfilter/nf_conntrack_count"] = "120\n";
    fixture.files["/proc/sys/net/netfilter/nf_conntrack_max"] = "110\n";
    const auto modern = fixture.next();
    CHECK(modern.at("conntrack_total") == 110);
    CHECK(modern.at("conntrack_free") == 0);
    CHECK(fixture.reads.at("/proc/sys/net/ipv4/netfilter/ip_conntrack_count") == 1);
    CHECK(fixture.reads.at("/proc/sys/net/ipv4/netfilter/ip_conntrack_max") == 1);

    fixture.files.erase("/proc/sys/net/netfilter/nf_conntrack_count");
    fixture.files.erase("/proc/sys/net/ipv4/netfilter/ip_conntrack_count");
    const auto no_count = fixture.next();
    CHECK(no_count.at("conntrack_total") == 110);
    CHECK_FALSE(no_count.contains("conntrack_free"));
    CHECK(fixture.reads.count("/proc/net/nf_conntrack") == 0);
    CHECK(fixture.reads.count("/proc/net/ip_conntrack") == 0);
}

TEST_CASE("local router metrics keeps CPU tick deltas exact above double integer precision") {
    LocalMetricsFixture fixture;
    constexpr std::uint64_t base = 9007199254741000ULL;
    fixture.files["/proc/stat"] =
        "cpu " + std::to_string(base) + " 0 0 " + std::to_string(base) + "\n";
    CHECK_FALSE(fixture.metrics.get().contains("cpu_load_percent"));
    fixture.files["/proc/stat"] =
        "cpu " + std::to_string(base + 30) + " 0 0 " + std::to_string(base + 70) + "\n";
    CHECK(fixture.next().at("cpu_load_percent") == 30);

    // Each field parses, but summing work would overflow uint64_t.
    fixture.files["/proc/stat"] = "cpu 18446744073709551615 1 0 100\n";
    CHECK_FALSE(fixture.next().contains("cpu_load_percent"));
    fixture.files["/proc/stat"] = "cpu 18446744073709551616 0 0 100\n";
    CHECK_FALSE(fixture.next().contains("cpu_load_percent"));
    fixture.files["/proc/stat"] = "cpu 50 0 0 50\n";
    CHECK_FALSE(fixture.next().contains("cpu_load_percent"));
    fixture.files["/proc/stat"] = "cpu 75 0 0 125\n";
    CHECK(fixture.next().at("cpu_load_percent") == 25);
}

} // namespace
} // namespace keen_pbr3
