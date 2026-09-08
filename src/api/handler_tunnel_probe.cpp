#ifdef WITH_API

#include "handler_tunnel_probe.hpp"
#include "tunnel_probe_review_view.hpp"

#include "../config/config.hpp"
#include "../config/config_writer.hpp"
#include "../health/nfqws_scan_source.hpp"
#include "../health/tunnel_probe_automation.hpp"
#include "../health/tunnel_probe_report.hpp"
#include "../log/logger.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <algorithm>
#include <chrono>
#include <mutex>

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
    try {
        write_file_atomically(path, contents);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// The two files, as they are now. `available` is false when the automation is
// not configured well enough to own any: empty lists then mean "nowhere to
// look", which is not the same as "nothing in them".
api::TunnelProbeHostsResponse read_hosts(const Config& config, bool is_draft) {
    api::TunnelProbeHostsResponse response;
    response.config_is_draft = is_draft;

    const auto resolved = resolve_tunnel_probe_setup(config);
    if (!resolved.setup.has_value()) return response;
    const auto& setup = *resolved.setup;

    // Only the small config is needed for ISP identity; no log/hostlist scan.
    std::ifstream source_file(kNfqwsConfigPath, std::ios::binary);
    std::string source_text(64U * 1024U, '\0');
    source_file.read(source_text.data(), static_cast<std::streamsize>(source_text.size()));
    source_text.resize(static_cast<std::size_t>(source_file.gcount()));
    const auto isp = nfqws_flag_value(source_text, "ISP_INTERFACE");
    const auto context = isp.empty() ? std::string{} :
        tunnel_probe_review_context(setup.outbound_tag, setup.interface, isp,
                                    setup.list_name, setup.list_file);

    const std::lock_guard<std::mutex> lock(tunnel_probe_list_io_mutex());

    response.available = true;
    response.list_name = setup.list_name;
    response.list_file = setup.list_file;
    response.exclude_file = setup.exclude_file;
    response.routed = parse_host_list_file(read_whole_file(setup.list_file));
    response.excluded =
        parse_host_list_file(read_whole_file(setup.exclude_file));
    std::string error;
    const auto reviews = load_tunnel_probe_review(setup.list_file, error);
    append_tunnel_probe_review_view(response, reviews, context, error.empty());
    return response;
}

Config active_probe_config(const ApiContext& ctx) {
    return ctx.get_tunnel_probe_active_config_fn
        ? ctx.get_tunnel_probe_active_config_fn() : ctx.get_visible_config();
}

}  // namespace

void register_tunnel_probe_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/tunnel-probe", []() -> std::string {
        return nlohmann::json(to_response(last_tunnel_probe_report())).dump();
    });

    server.get("/api/tunnel-probe/hosts", [&ctx]() -> std::string {
        return nlohmann::json(read_hosts(active_probe_config(ctx), ctx.config_is_draft())).dump();
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

            const auto config = active_probe_config(ctx);
            const auto resolved = resolve_tunnel_probe_setup(config);
            if (!resolved.setup.has_value()) {
                throw ApiError(
                    std::string("The tunnel probe automation owns no lists: ") +
                        describe_tunnel_probe_refusal(resolved.refusal),
                    400);
            }
            const auto& setup = *resolved.setup;

            // Serialize only the small local file edit, never a network probe
            // or firewall refresh. No runtime mutation admission is acquired.
            std::unique_lock<std::mutex> files_lock(tunnel_probe_list_io_mutex());
            const auto excluded_before_edit = parse_host_list_file(read_whole_file(setup.exclude_file));
            bool removed = false;
            std::string partial_error;
            std::vector<std::string> routed_before_edit;

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
                routed_before_edit = parse_host_list_file(routed);
                removed = std::find(routed_before_edit.begin(), routed_before_edit.end(), host) != routed_before_edit.end();
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
                        partial_error = "Removed from the list, but the never-list could not be written";
                    }
                }
            }

            if (removed) {
                std::string review_error;
                auto history = load_tunnel_probe_review(setup.list_file, review_error);
                const auto now_ms = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
                // It may have returned to the list since the last review pass.
                // Reconcile the real pre-edit membership before counting this
                // explicit removal, including two edits between worker ticks.
                sync_tunnel_probe_review(history, history.context, routed_before_edit,
                                         excluded_before_edit, now_ms);
                note_tunnel_probe_review_removal(history, host, now_ms);
                if (!save_tunnel_probe_review(setup.list_file, history, review_error)) {
                    // The requested removal already succeeded. Metadata failure
                    // must not turn it into another recovery workflow.
                    Logger::instance().warn("Tunnel probe review history could not be saved: {}", review_error);
                }
            }
            files_lock.unlock();

            // A list takes effect when it is read, and it is read when the
            // firewall is applied. Without this the host would keep using the
            // tunnel until something unrelated caused an apply.
            request_tunnel_probe_refresh();
            if (!partial_error.empty()) throw ApiError(partial_error, 500);

            return nlohmann::json(read_hosts(config, ctx.config_is_draft())).dump();
        });
}

}  // namespace keen_pbr3

#endif  // WITH_API
