#include "nfqws_log_maintenance.hpp"

#include "file_sink.hpp"
#include "../health/nfqws_scan_source.hpp"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <sstream>

namespace keen_pbr3 {
namespace {
std::atomic<std::size_t> maximum_bytes{FileLogSink::kDefaultMaxBytes};
std::atomic<bool> size_limit_enabled{true};
std::atomic<bool> age_limit_enabled{false};
std::atomic<unsigned> maximum_age_days{kDefaultLogMaxAgeDays};

bool managed_path(const std::string& path) {
    constexpr const char* prefix = "/opt/var/log/nfqws";
    return path.size() <= 128U && path.compare(0U, 18U, prefix) == 0 &&
           path.size() >= 22U && path.compare(path.size() - 4U, 4U, ".log") == 0 &&
           path.find('/', 13U) == std::string::npos &&
           path.find("..") == std::string::npos;
}
} // namespace

void set_nfqws_log_max_bytes(std::size_t value) {
    if (valid_log_file_max_bytes(value)) maximum_bytes.store(value, std::memory_order_relaxed);
}

std::size_t nfqws_log_max_bytes() {
    return maximum_bytes.load(std::memory_order_relaxed);
}

void set_nfqws_log_retention(bool size_enabled, bool age_enabled, unsigned days) {
    if (days < 1U || days > kMaximumLogAgeDays) return;
    size_limit_enabled.store(size_enabled, std::memory_order_relaxed);
    age_limit_enabled.store(age_enabled, std::memory_order_relaxed);
    maximum_age_days.store(days, std::memory_order_relaxed);
}
bool nfqws_log_size_limit_enabled() { return size_limit_enabled.load(std::memory_order_relaxed); }
bool nfqws_log_age_limit_enabled() { return age_limit_enabled.load(std::memory_order_relaxed); }
unsigned nfqws_log_max_age_days() { return maximum_age_days.load(std::memory_order_relaxed); }

std::vector<std::string> nfqws_managed_log_paths(const std::string& config) {
    std::vector<std::string> paths{"/opt/var/log/nfqws2.log"};
    auto add = [&](std::string path) {
        if (!path.empty() && path.front() == '@') path.erase(0U, 1U);
        if (managed_path(path) && std::find(paths.begin(), paths.end(), path) == paths.end()) {
            paths.push_back(std::move(path));
        }
    };
    std::istringstream input(config);
    std::string active_lines;
    std::string line;
    while (std::getline(input, line)) {
        const auto first = line.find_first_not_of(" \t\r");
        if (first == std::string::npos || line[first] == '#') continue;
        active_lines += line + '\n';
    }
    add(nfqws_flag_value(active_lines, "LOG_DEBUG_PATH"));
    add(nfqws_flag_value(active_lines, "--hostlist-auto-debug"));
    return paths;
}

void maintain_nfqws_logs() noexcept {
    const bool size_enabled = nfqws_log_size_limit_enabled();
    const bool age_enabled = nfqws_log_age_limit_enabled();
    if (!size_enabled && !age_enabled) return;
    try {
        // Configuration is small. A malformed/unbounded file must not cause
        // an equally unbounded allocation on the daemon maintenance path.
        std::ifstream input(kNfqwsConfigPath, std::ios::binary);
        std::string config;
        if (input) {
            constexpr std::size_t maximum_config_bytes = 256U * 1024U;
            config.resize(maximum_config_bytes + 1U);
            input.read(&config[0], static_cast<std::streamsize>(config.size()));
            config.resize(static_cast<std::size_t>(input.gcount()));
            if (config.size() > maximum_config_bytes) config.clear();
        }
        const auto limit = nfqws_log_max_bytes();
        const auto cutoff = std::time(nullptr) - static_cast<std::time_t>(nfqws_log_max_age_days()) * 86400;
        for (const auto& path : nfqws_managed_log_paths(config)) {
            if (size_enabled) (void)compact_log_tail(path, limit, limit / 2U);
            if (age_enabled) (void)prune_log_age(path, cutoff);
        }
    } catch (...) {
        // A best-effort diagnostic file must not interrupt routing work.
    }
}
} // namespace keen_pbr3
