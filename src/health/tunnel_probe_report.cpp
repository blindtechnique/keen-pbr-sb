#include "tunnel_probe_report.hpp"

#include <mutex>
#include <utility>

namespace keen_pbr3 {

namespace {

std::mutex& report_mutex() {
    static std::mutex mutex;
    return mutex;
}

TunnelProbeReport& report_storage() {
    static TunnelProbeReport report;
    return report;
}

}  // namespace

void publish_tunnel_probe_report(TunnelProbeReport report) {
    const std::lock_guard<std::mutex> lock(report_mutex());
    report_storage() = std::move(report);
}

TunnelProbeReport last_tunnel_probe_report() {
    const std::lock_guard<std::mutex> lock(report_mutex());
    return report_storage();
}

}  // namespace keen_pbr3
