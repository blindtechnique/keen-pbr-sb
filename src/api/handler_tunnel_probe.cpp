#ifdef WITH_API

#include "handler_tunnel_probe.hpp"

#include "../health/tunnel_probe_report.hpp"

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

api::TunnelProbeStateResponse to_response(const TunnelProbeReport& report) {
    api::TunnelProbeStateResponse response;
    response.ever_ran = report.ever_ran;
    if (!report.refusal.empty()) response.refusal = report.refusal;
    if (!report.summary.empty()) response.summary = report.summary;
    response.probed = static_cast<int64_t>(report.probed);
    response.remaining = static_cast<int64_t>(report.remaining);
    // Sent even when empty: a panel showing "routed nothing" is saying
    // something, and an absent field would leave it unable to tell that from
    // "no pass has run".
    response.routed = report.routed;
    response.held_back = report.held_back;
    if (report.finished_at_unix_ms != 0) {
        response.finished_at_unix_ms =
            static_cast<int64_t>(report.finished_at_unix_ms);
    }
    return response;
}

}  // namespace

void register_tunnel_probe_handler(ApiServer& server) {
    server.get("/api/tunnel-probe", []() -> std::string {
        return nlohmann::json(to_response(last_tunnel_probe_report())).dump();
    });
}

}  // namespace keen_pbr3

#endif  // WITH_API
