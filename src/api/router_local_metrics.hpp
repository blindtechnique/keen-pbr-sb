#pragma once

#include "router_info_cache.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

struct RouterDiskSpace {
    std::uint64_t total_bytes{0};
    std::uint64_t available_bytes{0};
};

// Injectable local readers keep tests independent of host /proc and disks.
// Neither reader may use RCI, HTTP, shell commands or the runtime mutation path.
struct RouterLocalMetricSources {
    std::function<std::string(const std::string&)> read_text;
    std::function<std::optional<RouterDiskSpace>()> disk_space;
};

class RouterLocalMetrics {
public:
    explicit RouterLocalMetrics(RouterLocalMetricSources sources = {},
                                RouterInfoCache::NowFn now = {});
    nlohmann::json get();

private:
    struct CpuTicks {
        std::uint64_t busy{0};
        std::uint64_t idle{0};
    };
    nlohmann::json sample();
    static std::optional<CpuTicks> parse_cpu(const std::string& text);

    RouterLocalMetricSources sources_;
    // Only the existing cache's single fetch callback accesses this baseline.
    std::optional<CpuTicks> previous_cpu_;
    RouterInfoCache cache_;
};

nlohmann::json local_router_metrics();

} // namespace keen_pbr3
