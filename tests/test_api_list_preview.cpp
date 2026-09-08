#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/handler_list_preview.hpp"
#include "../src/api/server.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace keen_pbr3 {
namespace {
class PreviewMockTransport final : public HttpTransport {
public:
    std::vector<HttpTransportRequest> requests;
    std::function<HttpTransportResponse(const HttpTransportRequest&, std::size_t)> callback;
    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        requests.push_back(request);
        if (callback) return callback(request, requests.size());
        HttpTransportResponse response;
        response.status_code = 200;
        response.body = "192.0.2.1\nExample.org\n";
        return response;
    }
};

Config preview_config(const std::string& primary = {}, const std::vector<std::string>& fallbacks = {}) {
    Config config;
    if (!primary.empty()) {
        ListRefreshConfig refresh;
        refresh.detour = primary;
        refresh.fallback_detours = fallbacks;
        config.list_refresh = refresh;
    }
    return config;
}

void invalid_request(const std::string& body) {
    try {
        (void)parse_list_preview_request(body);
        FAIL("invalid preview request was accepted");
    } catch (const ApiError& error) {
        CHECK(error.status() == 400);
        CHECK(std::string(error.what()).find("secret-token") == std::string::npos);
    }
}
} // namespace

TEST_CASE("List preview API validates its source and existing route modes") {
    for (const char* body : {"not JSON", "[]", "{}", R"({"url":"https://example.org","text":""})",
             R"({"text":null})", R"({"url":42})", R"({"text":"","unknown":1})",
             R"({"text":"example.org","detour":"vpn"})",
             R"({"url":"https://example.org","refresh_detour_mode":"direct"})",
             R"({"url":"https://example.org","refresh_detour_mode":"explicit"})",
             R"({"url":"https://example.org","refresh_detour_mode":"override"})",
             R"({"url":"https://example.org","refresh_detour_mode":"inherit","detour":"vpn"})",
             R"({"url":"https://example.org","fallback_detours":["vpn"]})",
             R"({"url":"https://example.org","detour":"vpn","fallback_detours":["vpn"]})",
             R"({"url":"https://example.org","detour":"vpn","fallback_detours":["a","b","c","d"]})",
             R"({"url":"https://example.org","detour":""})"}) invalid_request(body);
    CHECK(parse_list_preview_request(R"({"text":""})").text == std::optional<std::string>{""});
    CHECK(parse_list_preview_request(R"({"url":"https://example.org","refresh_detour_mode":"inherit"})").url.has_value());
    CHECK(parse_list_preview_request(R"({"url":"https://example.org","refresh_detour_mode":"override","detour":"vpn","fallback_detours":["a","b","c"]})").route.fallback_detours->size() == 3);
}

TEST_CASE("List preview API allows operator LAN URLs but only HTTP protocols") {
    for (const char* url : {"file:///opt/secret-token", "ftp://secret-token@example.org/list", "https://", "https://example.org/a b", "https://example.org/\\secret-token"})
        invalid_request(nlohmann::json{{"url", url}}.dump());
    for (const char* url : {"http://192.168.1.1/list", "http://[::1]:8080/list", "https://localhost/list", "https://user:secret-token@example.org/list"}) {
        const auto parsed = parse_list_preview_request(nlohmann::json{{"url", url}}.dump());
        REQUIRE(parsed.url.has_value());
        CHECK(*parsed.url == url);
    }
}

TEST_CASE("List preview API inline text never performs HTTP or needs a route") {
    const auto transport = std::make_shared<PreviewMockTransport>();
    const auto result = preview_list_request(R"({"text":"example.org\nEXAMPLE.ORG.\n"})",
                                             preview_config("missing"), {}, transport);
    CHECK(result.status == "ok");
    CHECK(result.complete);
    CHECK(result.unique_entries == 1);
    CHECK(result.duplicates == 1);
    CHECK(transport->requests.empty());
    const auto empty = preview_list_request(R"({"text":""})", {}, {}, transport);
    CHECK(empty.complete);
    CHECK(empty.lines == 0);
    const auto large = preview_list_request(nlohmann::json{{"text", std::string(kListPreviewMaxBytes + 1U, 'x')}}.dump(), {}, {}, transport);
    CHECK(large.status == "too_large");
    CHECK(transport->requests.empty());
}

TEST_CASE("List preview API inherits active marks and bounds transport resources") {
    const auto transport = std::make_shared<PreviewMockTransport>();
    const auto result = preview_list_request(R"({"url":"http://192.168.1.1/list"})",
        preview_config("vpn"), {{"vpn", 1234U}}, transport);
    CHECK(result.status == "ok");
    REQUIRE(transport->requests.size() == 1);
    const auto& request = transport->requests.front();
    CHECK(request.url == "http://192.168.1.1/list");
    CHECK(request.fwmark == 1234U);
    CHECK(request.timeout_ms > 0);
    CHECK(request.timeout_ms <= 10000);
    CHECK(request.max_response_size == kListPreviewMaxBytes);
    CHECK(request.max_header_size == 64U * 1024U);
    CHECK(request.max_redirects == 5);
    CHECK_FALSE(static_cast<bool>(request.destination_filter));
    CHECK(request.bind_interface.empty());
    CHECK(request.headers.empty());
}

TEST_CASE("List preview API uses explicit override or genuinely empty direct policy") {
    const auto transport = std::make_shared<PreviewMockTransport>();
    CHECK(preview_list_request(R"({"url":"https://example.org","refresh_detour_mode":"override","detour":"chosen"})",
        preview_config("inherited"), {{"inherited", 100U}, {"chosen", 200U}}, transport).status == "ok");
    REQUIRE(transport->requests.size() == 1);
    CHECK(transport->requests[0].fwmark == 200U);
    transport->requests.clear();
    CHECK(preview_list_request(R"({"url":"https://example.org"})", {}, {}, transport).status == "ok");
    REQUIRE(transport->requests.size() == 1);
    CHECK(transport->requests[0].fwmark == 0U);
}

TEST_CASE("List preview API never silently falls back to direct for unavailable routes") {
    const auto transport = std::make_shared<PreviewMockTransport>();
    const auto missing = preview_list_request(R"({"url":"https://example.org","detour":"unsaved"})",
        {}, {{"other", 12U}}, transport);
    CHECK(missing.status == "route_unavailable");
    CHECK_FALSE(missing.complete);
    CHECK(transport->requests.empty());
    CHECK(preview_list_request(R"({"url":"https://example.org"})",
        preview_config("missing", {"available"}), {{"available", 15U}}, transport).status == "ok");
    REQUIRE(transport->requests.size() == 1);
    CHECK(transport->requests[0].fwmark == 15U);
}

TEST_CASE("List preview API retries configured routes under one shrinking deadline") {
    const auto transport = std::make_shared<PreviewMockTransport>();
    transport->callback = [](const HttpTransportRequest&, std::size_t attempt) {
        if (attempt == 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds{3});
            throw HttpTransportError("https://secret-token@example.org failed", HttpTransportError::Reason::connect);
        }
        HttpTransportResponse response;
        response.status_code = 200;
        response.body = "example.org";
        return response;
    };
    const auto result = preview_list_request(R"({"url":"https://secret-token@example.org"})",
        preview_config("a", {"b"}), {{"a", 10U}, {"b", 20U}}, transport);
    CHECK(result.status == "ok");
    REQUIRE(transport->requests.size() == 2);
    CHECK(transport->requests[0].fwmark == 10U);
    CHECK(transport->requests[1].fwmark == 20U);
    CHECK(transport->requests[1].timeout_ms < transport->requests[0].timeout_ms);
    CHECK(serialize_list_preview_result(result).find("secret-token") == std::string::npos);
}

TEST_CASE("List preview API reports bounded errors without transport diagnostics") {
    for (const auto reason : {HttpTransportError::Reason::other, HttpTransportError::Reason::timeout,
            HttpTransportError::Reason::tls, HttpTransportError::Reason::connect, HttpTransportError::Reason::resolve,
            HttpTransportError::Reason::response_limit, HttpTransportError::Reason::mark}) {
        const auto transport = std::make_shared<PreviewMockTransport>();
        transport->callback = [reason](const HttpTransportRequest&, std::size_t) -> HttpTransportResponse {
            throw HttpTransportError("secret-token and private diagnostic", reason);
        };
        const auto result = preview_list_request(R"({"url":"https://secret-token@example.org"})", {}, {}, transport);
        CHECK_FALSE(result.complete);
        CHECK(result.status == (reason == HttpTransportError::Reason::response_limit ? "too_large" :
                                reason == HttpTransportError::Reason::mark ? "route_unavailable" : "download_failed"));
        CHECK(serialize_list_preview_result(result).find("secret-token") == std::string::npos);
        CHECK(result.errors.empty());
    }
    const auto transport = std::make_shared<PreviewMockTransport>();
    transport->callback = [](const HttpTransportRequest&, std::size_t) -> HttpTransportResponse {
        throw std::runtime_error("secret-token");
    };
    CHECK(preview_list_request(R"({"url":"https://example.org"})", {}, {}, transport).status == "download_failed");
}

TEST_CASE("List preview API requires a successful final HTTP status") {
    for (const long status : {0L, 199L, 301L, 304L, 404L, 500L}) {
        const auto transport = std::make_shared<PreviewMockTransport>();
        transport->callback = [status](const HttpTransportRequest&, std::size_t) {
            HttpTransportResponse response;
            response.status_code = status;
            response.body = "example.org";
            return response;
        };
        CHECK(preview_list_request(R"({"url":"https://example.org"})", {}, {}, transport).status == "download_failed");
    }
}

TEST_CASE("List preview API rejects structured or oversized downloaded bodies") {
    for (const char* type : {"application/json", "application/yaml", "text/yaml", "text/html; charset=utf-8"}) {
        const auto transport = std::make_shared<PreviewMockTransport>();
        transport->callback = [type](const HttpTransportRequest&, std::size_t) {
            HttpTransportResponse response;
            response.status_code = 200;
            response.body = "example.org";
            response.headers["content-type"] = type;
            return response;
        };
        CHECK(preview_list_request(R"({"url":"https://example.org"})", {}, {}, transport).status == "unsupported_format");
    }
    const auto transport = std::make_shared<PreviewMockTransport>();
    transport->callback = [](const HttpTransportRequest&, std::size_t) {
        HttpTransportResponse response;
        response.status_code = 200;
        response.body = std::string(kListPreviewMaxBytes + 1U, 'x');
        return response;
    };
    CHECK(preview_list_request(R"({"url":"https://example.org"})", {}, {}, transport).status == "too_large");
}

TEST_CASE("List preview API serializes the finite response contract") {
    auto result = preview_list_text("192.0.2.1\nbad entry\n");
    auto body = nlohmann::json::parse(serialize_list_preview_result(result));
    CHECK(body.at("status") == "ok");
    CHECK(body.at("complete") == true);
    CHECK(body.at("lines") == 2);
    CHECK(body.at("unique_entries") == 1);
    CHECK(body.at("entries").at(0).at("type") == "ipv4");
    CHECK(body.at("errors").at(0).at("code") == "invalid_entry");
    CHECK(body.at("entries_limited") == false);
    CHECK(body.at("errors_limited") == false);
    CHECK_FALSE(body.contains("limit_reason"));
    result.complete = false;
    result.limit_reason = "line_limit";
    body = nlohmann::json::parse(serialize_list_preview_result(result));
    CHECK(body.at("limit_reason") == "line_limit");
    CHECK(body.at("complete") == false);
}

TEST_CASE("Structured list import returns all entries without the preview sample cap") {
    nlohmann::json values = nlohmann::json::array();
    for (int i = 0; i < 90; ++i) values.push_back("domain" + std::to_string(i) + ".example");
    values.push_back("DOMAIN0.example");
    values.push_back("192.0.2.55/24");
    values.push_back("192.0.2.0/24");
    const auto text = values.dump();
    const auto imported = nlohmann::json::parse(import_list_content_request(
        nlohmann::json{{"text", text}, {"format", "json-array"}}.dump()));
    CHECK(imported.at("complete") == true);
    CHECK(imported.at("domains").size() == 90U);
    CHECK(imported.at("ip_cidrs") == nlohmann::json::array({"192.0.2.0/24"}));
    CHECK(imported.at("duplicates") == 2);
    const auto preview = preview_list_request(
        nlohmann::json{{"text", text}, {"format", "json-array"}}.dump(), {}, {});
    CHECK(preview.complete);
    CHECK(preview.unique_entries == 91);
    CHECK(preview.entries.size() == 50U);
    CHECK(preview.entries_limited);
}

TEST_CASE("Structured list import never returns a partial applicable result") {
    const auto imported = nlohmann::json::parse(import_list_content_request(
        nlohmann::json{{"text", "payload:\n  - example.org\n  - 192.0.2.1/99\n"},
                       {"format", "yaml-payload"}}.dump()));
    CHECK(imported.at("complete") == false);
    CHECK(imported.at("domains").empty());
    CHECK(imported.at("ip_cidrs").empty());
    REQUIRE_FALSE(imported.at("errors").empty());
    CHECK(imported.at("errors").at(0).at("line") == 3);
    for (const auto& request : {R"({"text":"[]","format":"auto"})",
             R"({"text":"[]"})", R"({"text":[],"format":"json-array"})",
             R"({"text":"[]","format":"json-array","save":true})"}) {
        CHECK_THROWS_AS(import_list_content_request(request), ApiError);
    }
    invalid_request(R"({"text":"[]","format":"auto"})");
    invalid_request(R"({"text":"[]","format":1})");
}

TEST_CASE("Structured list format is persisted and validated by existing config parsing") {
    for (const auto& format : {"text", "json-array", "yaml-payload"}) {
        const nlohmann::json document = {{"lists", {{"remote", {
            {"url", "https://example.org/list"}, {"source_format", format}}}}}};
        const auto config = parse_config(document.dump());
        CHECK(config.lists->at("remote").source_format == std::optional<std::string>{format});
        CHECK(nlohmann::json(config).at("lists").at("remote").at("source_format") == format);
    }
    for (const auto& value : {nlohmann::json("auto"), nlohmann::json(42)}) {
        const nlohmann::json document = {{"lists", {{"remote", {
            {"url", "https://example.org/list"}, {"source_format", value}}}}}};
        try {
            (void)parse_config(document.dump());
            FAIL("invalid list format was accepted");
        } catch (const ConfigValidationError& error) {
            REQUIRE_FALSE(error.issues().empty());
            CHECK(error.issues().front().path == "lists.remote.source_format");
            CHECK(error.issues().front().code == (value.is_string() ?
                "config.list.source_format" : "config.value.string"));
        }
    }
    const auto preview = preview_list_request(nlohmann::json{
        {"format", "json-array"}, {"text", std::string(kListPreviewMaxBytes + 1U, 'x')}}.dump(), {}, {});
    CHECK_FALSE(preview.complete);
    CHECK(preview.status == "too_large");
    CHECK(preview.limit_reason == "byte_limit");
}

TEST_CASE("Explicit structured URL preview accepts JSON MIME while text stays unchanged") {
    auto transport = std::make_shared<PreviewMockTransport>();
    transport->callback = [](const HttpTransportRequest&, std::size_t) {
        HttpTransportResponse response;
        response.status_code = 200;
        response.headers["content-type"] = "application/json";
        response.body = R"(["Example.org","2001:db8::1/64"])";
        return response;
    };
    const auto result = preview_list_request(
        R"({"url":"https://example.org/list","format":"json-array"})", {}, {}, transport);
    CHECK(result.complete);
    CHECK(result.domains == 1);
    CHECK(result.ipv6 == 1);
    CHECK(preview_list_request(R"({"url":"https://example.org/list"})", {}, {}, transport).status == "unsupported_format");
}

} // namespace keen_pbr3
#endif
