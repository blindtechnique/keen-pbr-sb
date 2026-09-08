#ifdef WITH_API

#include "handler_list_preview.hpp"
#include "handlers.hpp"
#include "server.hpp"
#include "../http/http_client.hpp"
#include "../lists/list_source_decoder.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <set>

namespace keen_pbr3 {
namespace {
ListPreviewResult failed(const char* status) {
    ListPreviewResult result;
    result.status = status;
    result.complete = false;
    return result;
}

bool safe_tag(const std::string& tag) {
    return !tag.empty() && tag.size() <= 256U &&
           std::none_of(tag.begin(), tag.end(), [](unsigned char ch) {
               return ch < 0x20U || ch == 0x7fU;
           });
}

void validate_url(const std::string& value) {
    if (value.empty() || value.size() > 8192U ||
        std::any_of(value.begin(), value.end(), [](unsigned char ch) {
            return ch <= 0x20U || ch == 0x7fU || ch == '\\';
        })) throw ApiError("Field 'url' must be an HTTP or HTTPS URL", 400);
    CURLU* parsed = curl_url();
    if (parsed == nullptr) throw ApiError("URL validation is unavailable", 503);
    char* scheme = nullptr;
    char* host = nullptr;
    const bool valid = curl_url_set(parsed, CURLUPART_URL, value.c_str(), 0) == CURLUE_OK &&
                       curl_url_get(parsed, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
                       curl_url_get(parsed, CURLUPART_HOST, &host, 0) == CURLUE_OK &&
                       host != nullptr && host[0] != '\0' &&
                       (std::string(scheme) == "http" || std::string(scheme) == "https");
    curl_free(scheme);
    curl_free(host);
    curl_url_cleanup(parsed);
    if (!valid) throw ApiError("Field 'url' must be an HTTP or HTTPS URL", 400);
}

// HttpClient translates transport errors into HttpError. Preserve only the
// bounded error category here, never curl's diagnostic text (which may carry
// URL credentials), so size and route failures still have useful API states.
class PreviewTransport final : public HttpTransport {
public:
    explicit PreviewTransport(std::shared_ptr<HttpTransport> inner)
        : inner_(std::move(inner)), deadline_(std::chrono::steady_clock::now() + std::chrono::seconds{10}) {}
    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        reason = HttpTransportError::Reason::other;
        try {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline_ - std::chrono::steady_clock::now()).count();
            if (remaining <= 0)
                throw HttpTransportError("List preview deadline reached", HttpTransportError::Reason::timeout);
            auto bounded = request;
            bounded.timeout_ms = static_cast<long>(std::min<std::int64_t>(10000, remaining));
            bounded.max_header_size = 64U * 1024U;
            return inner_->perform(bounded);
        }
        catch (const HttpTransportError& error) { reason = error.reason(); throw; }
    }
    HttpTransportError::Reason reason{HttpTransportError::Reason::other};
private:
    std::shared_ptr<HttpTransport> inner_;
    std::chrono::steady_clock::time_point deadline_;
};

bool structured_response(const HttpTransportResponse& response) {
    const auto found = response.headers.find("content-type");
    if (found == response.headers.end()) return false;
    auto type = found->second.substr(0, found->second.find(';'));
    std::transform(type.begin(), type.end(), type.begin(), [](unsigned char ch) {
        return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch);
    });
    return type == "application/json" || type == "application/yaml" ||
           type == "application/x-yaml" || type == "text/yaml" || type == "text/html";
}

ListPreviewResult preview_source(const std::string& text, const std::string& format) {
    if (format == "text") return preview_list_text(text);
    const auto decoded = decode_list_source(text, format);
    ListPreviewResult result;
    result.complete = decoded.complete;
    result.lines = decoded.lines;
    result.valid_entries = decoded.valid_entries;
    result.unique_entries = static_cast<std::int64_t>(decoded.entries.size());
    result.duplicates = decoded.duplicates;
    result.invalid_entries = decoded.invalid_entries;
    result.ignored_lines = decoded.ignored_lines;
    result.ipv4 = decoded.ipv4;
    result.ipv6 = decoded.ipv6;
    result.domains = decoded.domains;
    result.limit_reason = decoded.limit_reason;
    result.errors_limited = decoded.errors_limited;
    if (decoded.limit_reason == "byte_limit" || decoded.limit_reason == "output_limit")
        result.status = "too_large";
    else if (!decoded.errors.empty() && decoded.errors.front().code == "invalid_encoding")
        result.status = "unsupported_format";
    result.entries_limited = decoded.entries.size() > kListPreviewSampleSize;
    for (const auto& entry : decoded.entries) {
        if (result.entries.size() >= kListPreviewSampleSize) break;
        result.entries.push_back({entry.line, entry.value, entry.type});
    }
    for (const auto& error : decoded.errors)
        result.errors.push_back({error.line, error.code, error.value});
    return result;
}

ListPreviewResult run_preview(const ListPreviewRequest& request, const Config& config,
                             const OutboundMarkMap& marks,
                             std::shared_ptr<HttpTransport> transport) {
    if (request.text) return preview_source(*request.text, request.format);
    auto chain = effective_list_refresh_detours(config, request.route);
    // Empty is direct only when the user's effective policy really is empty.
    // A configured but unavailable outbound must never become mark zero.
    std::vector<std::uint32_t> route_marks;
    if (chain.empty()) route_marks.push_back(0U);
    for (const auto& tag : chain) {
        const auto found = marks.find(tag);
        if (found != marks.end()) route_marks.push_back(found->second);
    }
    if (route_marks.empty()) return failed("route_unavailable");
    auto observed = std::make_shared<PreviewTransport>(transport ? std::move(transport) : default_http_transport());
    HttpClient client(observed);
    client.set_timeout(std::chrono::seconds{10});
    client.set_max_response_size(kListPreviewMaxBytes);
    bool only_route_failure = true;
    for (const auto mark : route_marks) {
        HttpRequestOptions options;
        options.fwmark = mark;
        // Authenticated, operator-selected list URLs intentionally retain LAN
        // support, matching ordinary lists. Transport restricts protocols for
        // initial requests and redirects to HTTP/HTTPS.
        try {
            const auto response = client.download_response(*request.url, options);
            if (response.body.size() > kListPreviewMaxBytes) return failed("too_large");
            if (response.status_code < 200 || response.status_code >= 300) {
                only_route_failure = false;
                continue;
            }
            if (request.format == "text" && structured_response(response)) return failed("unsupported_format");
            return preview_source(response.body, request.format);
        } catch (const HttpError&) {
            if (observed->reason == HttpTransportError::Reason::response_limit)
                return failed("too_large");
            if (observed->reason != HttpTransportError::Reason::mark)
                only_route_failure = false;
        } catch (const std::exception&) {
            only_route_failure = false;
        }
    }
    return failed(only_route_failure ? "route_unavailable" : "download_failed");
}
} // namespace

ListPreviewRequest parse_list_preview_request(const std::string& body) {
    nlohmann::json payload;
    try { payload = nlohmann::json::parse(body); }
    catch (const nlohmann::json::exception&) { throw ApiError("Invalid list preview request", 400); }
    if (!payload.is_object()) throw ApiError("Invalid list preview request", 400);
    for (auto iterator = payload.begin(); iterator != payload.end(); ++iterator) {
        if (iterator.key() != "url" && iterator.key() != "text" && iterator.key() != "format" &&
            iterator.key() != "refresh_detour_mode" && iterator.key() != "detour" &&
            iterator.key() != "fallback_detours") throw ApiError("Unknown list preview field", 400);
    }
    if (payload.contains("url") == payload.contains("text"))
        throw ApiError("List preview requires exactly one of 'url' or 'text'", 400);
    ListPreviewRequest request;
    if (payload.contains("format")) {
        if (!payload.at("format").is_string() ||
            !valid_list_source_format(payload.at("format").get_ref<const std::string&>()))
            throw ApiError("Unknown list source format", 400);
        request.format = payload.at("format").get<std::string>();
    }
    const auto field = payload.contains("url") ? "url" : "text";
    if (!payload.at(field).is_string()) throw ApiError("Preview source must be a string", 400);
    if (payload.contains("url")) {
        request.url = payload.at("url").get<std::string>();
        validate_url(*request.url);
        request.route.url = request.url;
    } else request.text = payload.at("text").get<std::string>();
    if (request.text && (payload.contains("refresh_detour_mode") || payload.contains("detour") || payload.contains("fallback_detours")))
        throw ApiError("Download routing only applies to URL previews", 400);
    if (payload.contains("refresh_detour_mode")) {
        if (!payload.at("refresh_detour_mode").is_string()) throw ApiError("Invalid refresh_detour_mode", 400);
        const auto mode = payload.at("refresh_detour_mode").get<std::string>();
        if (mode == "inherit") request.route.refresh_detour_mode = ListRefreshDetourMode::INHERIT;
        else if (mode == "override") request.route.refresh_detour_mode = ListRefreshDetourMode::OVERRIDE;
        else throw ApiError("Invalid refresh_detour_mode", 400);
    }
    std::set<std::string> tags;
    if (payload.contains("detour")) {
        if (!payload.at("detour").is_string()) throw ApiError("Invalid detour", 400);
        const auto tag = payload.at("detour").get<std::string>();
        if (!safe_tag(tag)) throw ApiError("Invalid detour", 400);
        request.route.detour = tag;
        tags.insert(tag);
    }
    if (payload.contains("fallback_detours")) {
        const auto& fallbacks = payload.at("fallback_detours");
        if (!fallbacks.is_array() || fallbacks.size() > 3U) throw ApiError("Invalid fallback_detours", 400);
        std::vector<std::string> values;
        for (const auto& fallback : fallbacks) {
            if (!fallback.is_string()) throw ApiError("Invalid fallback_detours", 400);
            const auto tag = fallback.get<std::string>();
            if (!safe_tag(tag) || !tags.insert(tag).second) throw ApiError("Invalid or repeated fallback detour", 400);
            values.push_back(tag);
        }
        request.route.fallback_detours = std::move(values);
    }
    const auto mode = effective_list_refresh_detour_mode(request.route);
    const bool local_chain = request.route.detour.has_value() ||
        !request.route.fallback_detours.value_or(std::vector<std::string>{}).empty();
    if ((mode == ListRefreshDetourMode::INHERIT && local_chain) ||
        (mode == ListRefreshDetourMode::OVERRIDE && !request.route.detour))
        throw ApiError("Download routing requires either inheritance or an explicit primary detour", 400);
    return request;
}

ListPreviewResult preview_list_request(const std::string& body, const Config& active_config,
                                      const OutboundMarkMap& active_marks,
                                      std::shared_ptr<HttpTransport> transport) {
    return run_preview(parse_list_preview_request(body), active_config, active_marks, std::move(transport));
}

std::string serialize_list_preview_result(const ListPreviewResult& result) {
    nlohmann::json response = {
        {"status", result.status}, {"complete", result.complete}, {"lines", result.lines},
        {"valid_entries", result.valid_entries}, {"unique_entries", result.unique_entries},
        {"duplicates", result.duplicates}, {"invalid_entries", result.invalid_entries},
        {"ignored_lines", result.ignored_lines}, {"ipv4", result.ipv4}, {"ipv6", result.ipv6},
        {"domains", result.domains}, {"entries", nlohmann::json::array()},
        {"errors", nlohmann::json::array()}, {"entries_limited", result.entries_limited},
        {"errors_limited", result.errors_limited}};
    for (const auto& entry : result.entries)
        response["entries"].push_back({{"line", entry.line}, {"value", entry.value}, {"type", entry.type}});
    for (const auto& error : result.errors)
        response["errors"].push_back({{"line", error.line}, {"code", error.code}, {"value", error.value}});
    if (!result.limit_reason.empty()) response["limit_reason"] = result.limit_reason;
    return response.dump();
}

std::string import_list_content_request(const std::string& body) {
    nlohmann::json payload;
    try { payload = nlohmann::json::parse(body); }
    catch (const nlohmann::json::exception&) { throw ApiError("Invalid list import request", 400); }
    if (!payload.is_object() || payload.size() != 2U ||
        !payload.contains("text") || !payload.at("text").is_string() ||
        !payload.contains("format") || !payload.at("format").is_string())
        throw ApiError("List import requires text and format strings", 400);
    const auto& format = payload.at("format").get_ref<const std::string&>();
    if (!valid_list_source_format(format)) throw ApiError("Unknown list source format", 400);
    const auto decoded = decode_list_source(payload.at("text").get_ref<const std::string&>(), format);
    nlohmann::json result = {{"complete", decoded.complete}, {"duplicates", decoded.duplicates},
        {"domains", nlohmann::json::array()}, {"ip_cidrs", nlohmann::json::array()},
        {"errors", nlohmann::json::array()}, {"errors_limited", decoded.errors_limited}};
    if (decoded.complete) {
        for (const auto& entry : decoded.entries)
            result[entry.type == "domain" ? "domains" : "ip_cidrs"].push_back(entry.value);
    }
    for (const auto& error : decoded.errors)
        result["errors"].push_back({{"line", error.line}, {"code", error.code}, {"value", error.value}});
    if (!decoded.limit_reason.empty()) result["limit_reason"] = decoded.limit_reason;
    return result.dump();
}

void register_list_preview_handler(ApiServer& server, ApiContext& ctx) {
    server.post("/api/lists/import", [](const std::string& body) {
        return import_list_content_request(body);
    });
    server.post("/api/lists/preview", [&ctx](const std::string& body) {
        const auto request = parse_list_preview_request(body);
        if (request.text) return serialize_list_preview_result(preview_source(*request.text, request.format));
        if (!ctx.get_active_config_fn) return serialize_list_preview_result(failed("route_unavailable"));
        Config active;
        OutboundMarkMap marks;
        try {
            active = ctx.get_active_config_fn();
            marks = allocate_outbound_marks(active.fwmark.value_or(FwmarkConfig{}),
                                            active.outbounds.value_or(std::vector<Outbound>{}));
        } catch (const std::exception&) {
            return serialize_list_preview_result(failed("route_unavailable"));
        }
        return serialize_list_preview_result(run_preview(request, active, marks, {}));
    });
}

} // namespace keen_pbr3
#endif
