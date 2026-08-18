#ifdef WITH_API

#include "handler_transport_exit_check.hpp"

#include "handlers.hpp"
#include "server.hpp"
#include "../config/config.hpp"
#include "../http/http_client.hpp"

#include <chrono>
#include <nlohmann/json.hpp>
#include <utility>

namespace keen_pbr3 {

namespace {

// One pinned echo service, not a configurable one. The operator is not
// choosing a destination here - the panel is - so there is nothing for a
// destination filter to protect, and a field the operator could point
// anywhere would turn a diagnostic into a request-forging surface.
constexpr const char* kEchoUrl = "https://api.ipify.org";

// An address is tens of bytes. The cap is what stops a hijacked or hostile
// response from being read at all, rather than being read and then rejected.
constexpr std::size_t kEchoResponseLimit = 256U;

constexpr std::chrono::seconds kEchoTimeout{10};

nlohmann::json probe_to_json(const ExitProbeOutcome& outcome) {
    return nlohmann::json{{"ok", outcome.ok},
                          {"attributed", outcome.attributed},
                          {"address", outcome.address},
                          {"latency_ms", outcome.latency_ms},
                          {"error", outcome.error}};
}

ExitProbeOutcome fetch_echo(const std::string& url,
                            std::uint32_t fwmark,
                            const std::string& device) {
    ExitProbeOutcome outcome;
    // Attribution is a property of the request we were able to build, not of
    // the answer: without a device to bind to there is nothing to attribute
    // the result to, and the same word is used this way by InterfaceProbe.
    outcome.attributed = !device.empty();

    HttpClient client;
    client.set_timeout(kEchoTimeout);
    client.set_max_response_size(kEchoResponseLimit);
    HttpRequestOptions options;
    options.fwmark = fwmark;
    options.bind_interface = device;

    const auto started = std::chrono::steady_clock::now();
    try {
        const std::string body = client.download(url, options);
        const auto address = parse_echoed_address(body);
        if (!address.has_value()) {
            // A captive portal answers 200 with a page. Reporting that as an
            // address would dress a hijacked request as a measurement.
            outcome.error = "the reply was not an address";
            return outcome;
        }
        outcome.ok = true;
        outcome.address = *address;
    } catch (const HttpError& error) {
        outcome.error = error.what();
        return outcome;
    }
    outcome.latency_ms = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started)
            .count());
    return outcome;
}

void register_impl(ApiServer& server, ApiContext& ctx, ExitEchoFetcher fetcher) {
    server.post(
        "/api/transports/exit-check",
        [&ctx, fetcher = std::move(fetcher)](
            const std::string& request_body) -> std::string {
            nlohmann::json request;
            try {
                request = nlohmann::json::parse(request_body);
            } catch (const nlohmann::json::exception&) {
                throw ApiError("request body is not JSON", 400);
            }
            if (!request.is_object() || !request.contains("outbound") ||
                !request["outbound"].is_string()) {
                throw ApiError("outbound is required", 400);
            }
            const auto tag = request["outbound"].get<std::string>();

            const Config config = ctx.get_visible_config_fn();
            const auto outbounds =
                config.outbounds.value_or(std::vector<Outbound>{});
            const auto found = std::find_if(
                outbounds.begin(), outbounds.end(),
                [&tag](const Outbound& ob) { return ob.tag == tag; });
            if (found == outbounds.end()) {
                throw ApiError("unknown outbound", 404);
            }

            const auto marks = allocate_outbound_marks(
                config.fwmark.value_or(FwmarkConfig{}), outbounds);
            const auto mark = marks.find(tag);
            if (mark == marks.end()) {
                // No mark means no policy table selects this outbound, so
                // there is no route for a probe to take. Saying so is more
                // use than probing the router's own connection and calling
                // the answer a tunnel.
                throw ApiError("this outbound carries no routing mark", 409);
            }

            const auto device = found->interface.value_or(std::string());
            const ExitProbeOutcome through =
                fetcher(kEchoUrl, mark->second, device);
            // The control runs unmarked and unbound: it is the answer the
            // router gives without this transport, and without it "changed"
            // would be a comparison against nothing.
            const ExitProbeOutcome direct = fetcher(kEchoUrl, 0U, std::string());

            const nlohmann::json response = {
                {"outbound", tag},
                {"verdict", exit_check_verdict_name(exit_check_verdict(through))},
                {"exit_address",
                 exit_address_change_name(exit_address_change(through, direct))},
                {"through", probe_to_json(through)},
                {"direct", probe_to_json(direct)}};
            return response.dump();
        });
}

}  // namespace

void register_transport_exit_check_handler(ApiServer& server, ApiContext& ctx) {
    register_impl(server, ctx, fetch_echo);
}

#ifdef KEEN_PBR3_TESTING
void register_transport_exit_check_handler_for_test(ApiServer& server,
                                                    ApiContext& ctx,
                                                    ExitEchoFetcher fetcher) {
    register_impl(server, ctx, std::move(fetcher));
}
#endif

}  // namespace keen_pbr3

#endif  // WITH_API
