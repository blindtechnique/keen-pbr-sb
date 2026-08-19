#ifdef WITH_API

#include "handler_transport_exit_check.hpp"

#include "handlers.hpp"
#include "server.hpp"
#include "../config/config.hpp"
#include "../config/subscription_fetch_policy.hpp"
#include "../http/http_client.hpp"

#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <utility>

namespace keen_pbr3 {

namespace {

// One pinned echo service, not a configurable one. Its resolved address and
// every redirect destination are still untrusted network input, so the
// transport applies the same actual-connection policy as subscription fetches.
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

ExitProbeOutcome fetch_echo_with_transport(
    const std::shared_ptr<HttpTransport>& transport,
    const std::string& url,
    std::uint32_t fwmark,
    const std::string& device) {
    ExitProbeOutcome outcome;
    // A routing mark attributes TABLE outbounds and a device bind attributes
    // interface outbounds, even when the far side never answers. A typed bind
    // failure below is the exception: the socket never became pinned to the
    // requested interface and must be reported as unattributed.
    outcome.attributed = fwmark != 0U || !device.empty();

    HttpClient client(transport);
    client.set_timeout(kEchoTimeout);
    client.set_max_response_size(kEchoResponseLimit);
    HttpRequestOptions options;
    options.fwmark = fwmark;
    options.destination_filter = [](const std::string& address) {
        return subscription_destination_permitted(address) ==
               SubscriptionDestinationVerdict::allowed;
    };
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
    } catch (const HttpBindError& error) {
        outcome.attributed = false;
        outcome.error = error.what();
        return outcome;
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

ExitProbeOutcome fetch_echo(const std::string& url,
                            std::uint32_t fwmark,
                            const std::string& device) {
    return fetch_echo_with_transport(
        default_http_transport(), url, fwmark, device);
}

void register_impl(ApiServer& server, ApiContext& ctx, ExitEchoFetcher fetcher) {
    auto probe_gate = std::make_shared<std::mutex>();
    server.post(
        "/api/transports/exit-check",
        [&ctx, fetcher = std::move(fetcher), probe_gate = std::move(probe_gate)](
            const std::string& request_body) -> std::string {
            nlohmann::json request;
            try {
                request = nlohmann::json::parse(request_body);
            } catch (const nlohmann::json::exception&) {
                throw ApiError("request body is not JSON", 400);
            }
            if (!request.is_object()) {
                throw ApiError("request body is not an object", 400);
            }
            const bool by_tag = request.contains("outbound") &&
                                request["outbound"].is_string();
            const bool by_device = request.contains("interface") &&
                                   request["interface"].is_string();
            // Exactly one, and a request naming both is refused rather than
            // resolved in someone's favour: a caller that does not know which
            // it meant must not have the choice made for it.
            if (by_tag == by_device) {
                throw ApiError(
                    "name exactly one of outbound or interface", 400);
            }

            std::string response_name;
            std::string device;
            std::uint32_t fwmark = 0U;

            if (by_device) {
                // A native firmware tunnel usually has no keen-pbr outbound
                // and therefore no routing mark. Binding the socket to its
                // device is what makes the measurement attributable.
                device = request["interface"].get<std::string>();
                if (device.empty() || device.size() >= 16U ||
                    device.find('/') != std::string::npos) {
                    throw ApiError("not an interface name", 400);
                }
                response_name = device;
            } else {
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
                    // there is no route for a probe to take.
                    throw ApiError(
                        "this outbound carries no routing mark", 409);
                }

                response_name = tag;
                fwmark = mark->second;
                device = found->interface.value_or(std::string());
            }

            std::unique_lock<std::mutex> gate_lock(
                *probe_gate, std::try_to_lock);
            if (!gate_lock.owns_lock()) {
                throw ApiError("another exit check is already running", 503);
            }

            const ExitProbeOutcome through =
                fetcher(kEchoUrl, fwmark, device);
            // The control runs unmarked and unbound: it is the answer the
            // router gives without this transport, and without it "changed"
            // would be a comparison against nothing.
            const ExitProbeOutcome direct = fetcher(kEchoUrl, 0U, std::string());

            const nlohmann::json response = {
                {"outbound", response_name},
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
ExitProbeOutcome fetch_transport_exit_echo_for_test(
    std::shared_ptr<HttpTransport> transport,
    const std::string& url,
    std::uint32_t fwmark,
    const std::string& device) {
    return fetch_echo_with_transport(
        std::move(transport), url, fwmark, device);
}

void register_transport_exit_check_handler_for_test(ApiServer& server,
                                                    ApiContext& ctx,
                                                    ExitEchoFetcher fetcher) {
    register_impl(server, ctx, std::move(fetcher));
}
#endif

}  // namespace keen_pbr3

#endif  // WITH_API
