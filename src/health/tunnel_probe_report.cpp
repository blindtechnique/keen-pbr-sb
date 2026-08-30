#include "tunnel_probe_report.hpp"

#include <functional>
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

namespace {

std::function<void()>& refresh_hook_storage() {
    static std::function<void()> hook;
    return hook;
}

}  // namespace

void set_tunnel_probe_refresh_hook(std::function<void()> hook) {
    const std::lock_guard<std::mutex> lock(report_mutex());
    refresh_hook_storage() = std::move(hook);
}

void request_tunnel_probe_refresh() {
    std::function<void()> hook;
    {
        const std::lock_guard<std::mutex> lock(report_mutex());
        hook = refresh_hook_storage();
    }
    // Copied out and called with the lock released: the hook hops onto the
    // control loop, and holding a lock across that is how deadlocks are made.
    if (hook) hook();
}

}  // namespace keen_pbr3
