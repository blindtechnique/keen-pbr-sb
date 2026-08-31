#ifdef WITH_API

#include "handler_tunnel_probe.hpp"

#include "../config/config.hpp"
#include "../health/nfqws_scan_source.hpp"
#include "../health/tunnel_probe_automation.hpp"
#include "../health/tunnel_probe_report.hpp"

#include <nlohmann/json.hpp>

#include <fstream>

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

bool write_whole_file(const std::string& path, const std::string& contents) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;
    out << contents;
    out.flush();
    return out.good();
}

// The two files, as they are now. `available` is false when the automation is
// not configured well enough to own any: empty lists then mean "nowhere to
// look", which is not the same as "nothing in them".
api::TunnelProbeHostsResponse read_hosts(const Config& config) {
    api::TunnelProbeHostsResponse response;

    const auto resolved = resolve_tunnel_probe_setup(config);
    if (!resolved.setup.has_value()) return response;
    const auto& setup = *resolved.setup;

    response.available = true;
    response.list_name = setup.list_name;
    response.list_file = setup.list_file;
    response.exclude_file = setup.exclude_file;
    response.routed = parse_host_list_file(read_whole_file(setup.list_file));
    response.excluded =
        parse_host_list_file(read_whole_file(setup.exclude_file));
    return response;
}

}  // namespace

void register_tunnel_probe_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/tunnel-probe", []() -> std::string {
        return nlohmann::json(to_response(last_tunnel_probe_report())).dump();
    });

    server.get("/api/tunnel-probe/hosts", [&ctx]() -> std::string {
        return nlohmann::json(read_hosts(ctx.get_visible_config())).dump();
    });

    server.post(
        "/api/tunnel-probe/hosts",
        [&ctx](const std::string& body) -> std::string {
            nlohmann::json request;
            try {
                request = nlohmann::json::parse(body);
            } catch (const std::exception&) {
                throw ApiError("Invalid request body", 400);
            }
            if (!request.is_object() || !request.contains("host") ||
                !request.at("host").is_string() ||
                !request.contains("action") ||
                !request.at("action").is_string()) {
                throw ApiError(
                    "Request must contain a host and an action", 400);
            }

            const auto host = request.at("host").get<std::string>();
            const auto action = request.at("action").get<std::string>();
            if (host.empty() || host.size() > 253U) {
                throw ApiError("Host must be between 1 and 253 characters",
                               400);
            }
            if (action != "remove" && action != "exclude" &&
                action != "restore") {
                throw ApiError(
                    "Action must be remove, exclude or restore", 400);
            }

            const auto config = ctx.get_visible_config();
            const auto resolved = resolve_tunnel_probe_setup(config);
            if (!resolved.setup.has_value()) {
                throw ApiError(
                    std::string("The tunnel probe automation owns no lists: ") +
                        describe_tunnel_probe_refusal(resolved.refusal),
                    400);
            }
            const auto& setup = *resolved.setup;

            if (action == "restore") {
                const auto excluded = read_whole_file(setup.exclude_file);
                if (!write_whole_file(setup.exclude_file,
                                      render_list_without(excluded, host))) {
                    throw ApiError("Could not write the never-list", 500);
                }
            } else {
                // Removal happens for both remaining actions; excluding is
                // removal plus a promise not to do it again.
                const auto routed = read_whole_file(setup.list_file);
                if (!write_whole_file(setup.list_file,
                                      render_list_without(routed, host))) {
                    throw ApiError("Could not write the list", 500);
                }
                if (action == "exclude") {
                    const auto excluded = read_whole_file(setup.exclude_file);
                    if (!write_whole_file(setup.exclude_file,
                                          render_list_with(excluded, host))) {
                        // The host is already out of the routed list, so the
                        // caller is not left worse off - but it will come back
                        // if it is found again, and they must know that.
                        throw ApiError(
                            "Removed from the list, but the never-list could "
                            "not be written",
                            500);
                    }
                }
            }

            // A list takes effect when it is read, and it is read when the
            // firewall is applied. Without this the host would keep using the
            // tunnel until something unrelated caused an apply.
            request_tunnel_probe_refresh();

            return nlohmann::json(read_hosts(config)).dump();
        });
}

}  // namespace keen_pbr3

#endif  // WITH_API
