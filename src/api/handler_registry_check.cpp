#ifdef WITH_API

#include "handler_registry_check.hpp"

#include "../config/config.hpp"
#include "../http/http_client.hpp"
#include "../log/logger.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

// The public instance of cheburcheck. Its code is not vendored - only the
// verdict is shown, and the service is credited in the panel.
constexpr const char* kServiceUrl = "https://cheburcheck.ru/api/v1/check?target=";
constexpr const char* kServiceName = "cheburcheck.ru";

// The registry moves in days, not seconds, and the service publishes neither
// terms nor a rate limit. An hour of caching keeps a panel that is left open
// from turning one operator's curiosity into a stream of requests.
constexpr auto kCacheTtl = std::chrono::minutes(60);
constexpr std::size_t kCacheCap = 256;

// Long enough for a DoH round trip on a bad link, short enough that the panel
// does not look hung.
constexpr auto kTimeout = std::chrono::seconds(12);
constexpr std::size_t kMaxResponseBytes = 256U * 1024U;

struct CachedVerdict {
    nlohmann::json payload;
    std::chrono::steady_clock::time_point stored_at;
};

std::mutex& cache_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::map<std::string, CachedVerdict>& cache() {
    static std::map<std::string, CachedVerdict> entries;
    return entries;
}

std::string trim_lower(std::string value) {
    const auto not_space = [](unsigned char character) {
        return std::isspace(character) == 0;
    };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
                value.end());
    for (auto& character : value) {
        character = static_cast<char>(
            std::tolower(static_cast<unsigned char>(character)));
    }
    return value;
}

// Only what can appear in a hostname or an IP literal is sent. This is not
// cosmetic: the target is pasted by a person and lands in a URL, so anything
// that could carry a query separator or a control character is refused rather
// than escaped.
bool is_sendable_target(const std::string& target) {
    if (target.empty() || target.size() > 253U) return false;
    for (const unsigned char character : target) {
        const bool allowed =
            (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') ||
            character == '.' || character == '-' || character == ':';
        if (!allowed) return false;
    }
    return true;
}

// Only the fields the panel shows are carried through. A response is data from
// a service we do not control, so it is copied field by field rather than
// forwarded whole.
nlohmann::json summarise(const nlohmann::json& raw) {
    nlohmann::json summary;
    summary["checked"] = true;
    summary["service"] = kServiceName;
    summary["blocked"] = raw.value("blocked", false);

    const auto rkn = raw.find("rkn_domain");
    if (rkn != raw.end() && rkn->is_string()) {
        summary["rkn_domain"] = rkn->get<std::string>();
    }

    const auto subnets = raw.find("blocked_subnets");
    auto blocked_subnets = nlohmann::json::array();
    if (subnets != raw.end() && subnets->is_array()) {
        for (const auto& subnet : *subnets) {
            if (subnet.is_string()) blocked_subnets.push_back(subnet);
        }
    }
    summary["blocked_subnets"] = std::move(blocked_subnets);

    const auto ips = raw.find("ips");
    auto addresses = nlohmann::json::array();
    if (ips != raw.end() && ips->is_array()) {
        for (const auto& ip : *ips) {
            if (ip.is_string()) addresses.push_back(ip);
        }
    }
    summary["ips"] = std::move(addresses);

    // A blocked subnet on a shared CDN is the case where "the domain is not in
    // the registry" and "it still fails" are both true, so the provider names
    // are worth showing.
    const auto cdn = raw.find("cdn_providers");
    auto providers = nlohmann::json::array();
    if (cdn != raw.end() && cdn->is_object()) {
        for (const auto& item : cdn->items()) {
            providers.push_back(item.key());
        }
    }
    summary["cdn_providers"] = std::move(providers);

    const auto geo = raw.find("geo");
    if (geo != raw.end() && geo->is_object()) {
        const auto organisation = geo->find("organisation");
        if (organisation != geo->end() && organisation->is_string()) {
            summary["organisation"] = organisation->get<std::string>();
        }
    }
    return summary;
}

nlohmann::json not_checked(const std::string& reason) {
    nlohmann::json response;
    response["checked"] = false;
    response["service"] = kServiceName;
    response["reason"] = reason;
    return response;
}

RegistryFetcher& fetcher_slot() {
    static RegistryFetcher fetcher;
    return fetcher;
}

std::string fetch_default(const std::string& target, uint32_t fwmark) {
    HttpClient client;
    client.set_timeout(kTimeout);
    client.set_max_response_size(kMaxResponseBytes);
    return client.download(kServiceUrl + target, HttpRequestOptions{fwmark});
}

uint32_t mark_for_detour(const Config& config, const std::string& tag) {
    if (tag.empty() || !config.outbounds) return 0;
    try {
        const auto marks = allocate_outbound_marks(
            config.fwmark.value_or(FwmarkConfig{}), *config.outbounds);
        const auto found = marks.find(tag);
        return found == marks.end() ? 0U : found->second;
    } catch (const std::exception&) {
        return 0;
    }
}

void register_handler(ApiServer& server,
                      ApiContext& ctx,
                      bool use_injected_fetcher) {
    server.post(
        "/api/routing/registry-check",
        [&ctx, use_injected_fetcher](const std::string& body) -> std::string {
            nlohmann::json request;
            try {
                request = nlohmann::json::parse(body);
            } catch (const std::exception&) {
                nlohmann::json payload = {{"error", "Invalid request body"}};
                throw ApiError("Invalid request body", 400, payload.dump());
            }

            const auto target =
                trim_lower(request.value("target", std::string{}));
            if (!is_sendable_target(target)) {
                nlohmann::json payload = {
                    {"error", "target must be a domain name or IP address"}};
                throw ApiError("Invalid target", 400, payload.dump());
            }

            // The consent is the daemon's own setting, not something the
            // request may assert. A browser cannot authorise this by asking,
            // and the answer stays the same across a cleared browser, another
            // device, or a restore from backup.
            const auto config = ctx.get_visible_config();
            const bool enabled =
                config.ui_preferences.has_value() &&
                config.ui_preferences->registry_lookup_enabled.value_or(false);
            if (!enabled) {
                return not_checked("registry_lookup_disabled").dump();
            }

            {
                std::lock_guard<std::mutex> lock(cache_mutex());
                const auto found = cache().find(target);
                if (found != cache().end() &&
                    std::chrono::steady_clock::now() - found->second.stored_at <
                        kCacheTtl) {
                    auto cached = found->second.payload;
                    cached["cached"] = true;
                    return cached.dump();
                }
            }

            const auto detour = request.value("detour", std::string{});
            const auto mark =
                detour.empty() ? 0U : mark_for_detour(config, detour);

            std::string raw_body;
            try {
                raw_body = use_injected_fetcher && fetcher_slot()
                               ? fetcher_slot()(target)
                               : fetch_default(target, mark);
            } catch (const std::exception& error) {
                // A lookup that did not happen is reported as "not checked",
                // never as "not blocked": the panel must not turn a failed
                // request into a clean bill of health.
                Logger::instance().info(
                    "Registry check for '{}' did not complete: {}",
                    target,
                    error.what());
                auto response = not_checked("lookup_failed");
                response["error"] = error.what();
                return response.dump();
            }

            nlohmann::json parsed;
            try {
                parsed = nlohmann::json::parse(raw_body);
            } catch (const std::exception&) {
                return not_checked("unreadable_response").dump();
            }
            if (!parsed.is_object()) {
                return not_checked("unreadable_response").dump();
            }

            auto summary = summarise(parsed);
            summary["target"] = target;
            {
                std::lock_guard<std::mutex> lock(cache_mutex());
                if (cache().size() >= kCacheCap) cache().clear();
                cache()[target] =
                    CachedVerdict{summary, std::chrono::steady_clock::now()};
            }
            summary["cached"] = false;
            return summary.dump();
        });
}

} // namespace

void register_registry_check_handler(ApiServer& server, ApiContext& ctx) {
    register_handler(server, ctx, /*use_injected_fetcher=*/false);
}

void register_registry_check_handler_for_test(ApiServer& server,
                                              ApiContext& ctx,
                                              RegistryFetcher fetcher) {
    fetcher_slot() = std::move(fetcher);
    register_handler(server, ctx, /*use_injected_fetcher=*/true);
}

void clear_registry_check_cache_for_testing() {
    std::lock_guard<std::mutex> lock(cache_mutex());
    cache().clear();
}

} // namespace keen_pbr3

#endif
