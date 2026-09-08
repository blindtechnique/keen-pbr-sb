#ifdef WITH_API
#include "subscription_transport_update.hpp"
#include <httplib.h>
#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace keen_pbr3 {
namespace {
nlohmann::json read_state(httplib::Client& client, const httplib::Headers& headers) {
    const auto response = client.Get("/v1/config/transports/state", headers);
    if (!response || response->status != 200)
        throw std::runtime_error("manager_unavailable");
    const auto state = nlohmann::json::parse(response->body, nullptr, false);
    if (!state.is_object() || !state.contains("transports") ||
        !state["transports"].is_array() || !state.contains("revision") ||
        !state["revision"].is_string())
        throw std::runtime_error("manager_unavailable");
    return state;
}
bool valid_tag(const std::string& tag) {
    return !tag.empty() && tag.size() <= 128 &&
        std::all_of(tag.begin(), tag.end(), [](unsigned char ch) {
            return std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.';
        });
}
}

std::vector<SubscriptionTransportState> read_subscription_transports(
    const TransportManagerEndpoint& endpoint) {
    httplib::Client client(endpoint.host, endpoint.port);
    client.set_connection_timeout(1, 0);
    client.set_read_timeout(5, 0);
    const auto state = read_state(client, {{"Authorization", "Bearer " + endpoint.api_key}});
    std::vector<SubscriptionTransportState> result;
    for (const auto& spec : state.at("transports")) {
        if (!spec.is_object() || !valid_tag(spec.value("tag", std::string{})))
            throw std::runtime_error("manager_unavailable");
        const auto fingerprint = spec.value("type", std::string{}) == "sing-box"
            ? spec.value("link_fingerprint", std::string{}) : std::string{};
        result.push_back({spec.at("tag").get<std::string>(), fingerprint});
    }
    return result;
}

SubscriptionUpdateResult update_subscription_transports(
    const TransportManagerEndpoint& endpoint,
    const std::vector<SubscriptionTransportUpdate>& updates) {
    SubscriptionUpdateResult result;
    if (updates.empty()) return result;
    try {
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(15, 0);
        client.set_write_timeout(5, 0);
        httplib::Headers headers{{"Authorization", "Bearer " + endpoint.api_key}};
        auto state = read_state(client, headers);
        auto revision = state.at("revision").get<std::string>();
        for (const auto& update : updates) {
            const auto found = std::find_if(state["transports"].begin(), state["transports"].end(),
                [&](const auto& spec) { return spec.is_object() &&
                    spec.value("tag", std::string{}) == update.tag; });
            if (!valid_tag(update.tag) || found == state["transports"].end() ||
                found->value("type", std::string{}) != "sing-box") {
                result.error_code = "transport_changed";
                continue;
            }
            const auto fingerprint = found->value("link_fingerprint", std::string{});
            // A previous PUT may have succeeded before source metadata was saved.
            // A later refresh acknowledges that exact configuration, without a
            // second restart or a request to repeat the original import.
            if (!update.next_fingerprint.empty() && fingerprint == update.next_fingerprint) {
                result.applied_tags.push_back(update.tag);
                continue;
            }
            if (update.previous_fingerprint.empty() || fingerprint != update.previous_fingerprint) {
                result.error_code = "transport_changed";
                continue;
            }
            auto spec = *found;
            spec.erase("link_fingerprint");
            spec.erase("outbound_json");
            spec.erase("vless");
            spec["link"] = update.link;
            headers.erase("If-Match");
            headers.emplace("If-Match", "\"" + revision + "\"");
            const auto response = client.Put("/v1/config/transports/" + update.tag,
                headers, spec.dump(), "application/json");
            if (!response || response->status < 200 || response->status >= 300) {
                result.error_code = response && (response->status == 409 || response->status == 412)
                    ? "transport_changed" : "apply_failed";
                break;
            }
            result.applied_tags.push_back(update.tag);
            (*found)["link_fingerprint"] = update.next_fingerprint;
            const auto reply = nlohmann::json::parse(response->body, nullptr, false);
            if (!reply.is_object() || !reply.contains("config_revision") ||
                !reply["config_revision"].is_string()) {
                // Re-read on the next refresh; never guess a conditional revision.
                if (&update != &updates.back()) result.error_code = "manager_unavailable";
                break;
            }
            revision = reply["config_revision"].get<std::string>();
        }
    } catch (...) {
        result.error_code = "manager_unavailable";
    }
    return result;
}
}
#endif
