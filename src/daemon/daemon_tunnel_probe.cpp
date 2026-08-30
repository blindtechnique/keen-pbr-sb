// The daemon's half of the "nfqws2 could not fix it, a tunnel can" automation.
//
// Deliberately its own translation unit. Everything here is two Daemon methods
// and the filesystem and network they need; keeping them out of
// daemon_runtime.cpp keeps this feature from colliding with every other change
// to that file, which is the busiest in the project.

#include "daemon.hpp"

#include "../health/differential_probe.hpp"
#include "../health/nfqws_scan_source.hpp"
#include "../http/http_transport.hpp"
#include "../log/logger.hpp"

#include <chrono>
#include <fstream>
#include <memory>
#include <utility>

namespace keen_pbr3 {

void Daemon::schedule_tunnel_probe() {
    // The interval belongs to the configuration, so the timer cannot simply be
    // armed with it: both the interval and the switch may change while the
    // daemon runs. Ticking once a minute and letting the pass decide whether
    // it is due costs one resolve per minute and lets either take effect
    // without a restart.
    constexpr auto kTick = std::chrono::minutes(1);

    scheduler_->schedule_repeating(
        kTick,
        [this]() {
            const auto resolved = resolve_tunnel_probe_setup(config_);
            if (!resolved.setup.has_value()) return;

            const auto now = std::chrono::steady_clock::now();
            const auto due = std::chrono::milliseconds(
                static_cast<std::int64_t>(resolved.setup->interval_ms));
            if (tunnel_probe_last_pass_.has_value() &&
                now - *tunnel_probe_last_pass_ < due) {
                return;
            }

            // A pass is minutes of real requests and the timer does not wait
            // for it. Without this a slow pass would be joined by the next.
            if (tunnel_probe_running_.exchange(true)) return;
            tunnel_probe_last_pass_ = now;

            const bool posted = blocking_executor_.try_post(
                "tunnel-probe",
                [this, config = config_]() { run_tunnel_probe_pass(config); });
            if (!posted) tunnel_probe_running_.store(false);
        },
        "tunnel-probe");
}

void Daemon::run_tunnel_probe_pass(const Config& config) noexcept {
    auto& log = Logger::instance();
    try {
        if (!tunnel_probe_task_) {
            TunnelProbeTask::Io io;
            io.read_file = [](const std::string& path) {
                return read_whole_file(path);
            };
            io.write_file = [](const std::string& path,
                               const std::string& contents) {
                std::ofstream out(path, std::ios::binary | std::ios::trunc);
                if (!out.is_open()) return false;
                out << contents;
                out.flush();
                return out.good();
            };
            io.run_probe = [](const DifferentialProbeRequest& request) {
                auto transport = default_http_transport();
                return run_differential_probe(*transport, request);
            };
            io.on_list_changed = [this](const TunnelProbeSetup&) {
                // A list file is read when the firewall is applied, so new
                // hosts do nothing until one happens. This runs on a worker
                // thread, so hop back to the control loop to ask for it.
                post_control_task(
                    [this]() {
                        schedule_netfilter_runtime_refresh(
                            NetfilterRefreshReason::full);
                    },
                    "tunnel-probe-list-refresh");
            };
            tunnel_probe_task_ =
                std::make_unique<TunnelProbeTask>(std::move(io));
        }

        const auto outcome = tunnel_probe_task_->run(config);
        // A pass that refused because the automation is off is the ordinary
        // case and says nothing worth a line; everything else does.
        if (outcome.refusal != TunnelProbeRefusal::disabled) {
            log.info("Tunnel probe: {}", TunnelProbeTask::describe(outcome));
        }
    } catch (const std::exception& error) {
        try {
            log.error("Tunnel probe pass failed: {}", error.what());
        } catch (...) {
        }
    } catch (...) {
    }
    tunnel_probe_running_.store(false);
}

}  // namespace keen_pbr3
