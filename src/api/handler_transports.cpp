#ifdef WITH_API

#include "handler_transports.hpp"

#include <filesystem>
#include <fstream>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>

namespace keen_pbr3 {

namespace {

struct TransportManagerEndpoint {
    std::string host;
    int port;
    std::string api_key;
};

bool valid_transport_tag(const std::string& tag) {
    if (tag.empty() || tag.size() > 24 || tag.front() < 'a' || tag.front() > 'z') {
        return false;
    }
    for (const char ch : tag) {
        const bool lowercase = ch >= 'a' && ch <= 'z';
        const bool digit = ch >= '0' && ch <= '9';
        if (!lowercase && !digit && ch != '_') {
            return false;
        }
    }
    return true;
}

TransportManagerEndpoint load_endpoint(const std::string& keen_pbr_config_path) {
    const auto path = std::filesystem::path(keen_pbr_config_path).parent_path() /
                      "transports.json";
    std::ifstream input(path);
    if (!input.is_open()) {
        throw ApiError("transport manager config not found: " + path.string(), 503);
    }

    nlohmann::json config;
    input >> config;
    const auto listen = config.value("listen", std::string("127.0.0.1:12122"));
    const auto separator = listen.rfind(':');
    if (separator == std::string::npos) {
        throw ApiError("invalid transport manager listen address", 500);
    }

    const auto host = listen.substr(0, separator);
    if (host != "127.0.0.1" && host != "localhost") {
        throw ApiError("transport manager must listen on loopback", 500);
    }

    int port = 0;
    try {
        port = std::stoi(listen.substr(separator + 1));
    } catch (const std::exception&) {
        throw ApiError("invalid transport manager port", 500);
    }
    if (port <= 0 || port > 65535) {
        throw ApiError("transport manager port out of range", 500);
    }

    const auto api_key = config.value("api_key", std::string{});
    if (api_key.empty()) {
        throw ApiError("transport manager api_key is empty", 500);
    }
    return {host, port, api_key};
}

} // namespace

void register_transports_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/transports/environment", [&ctx]() -> std::string {
        const auto path = std::filesystem::path(ctx.config_path).parent_path() /
                          "transports.json";
        std::ifstream input(path);
        nlohmann::json config;
        if (input.is_open()) {
            try {
                input >> config;
            } catch (const nlohmann::json::exception&) {
                config = nlohmann::json::object();
            }
        }
        const auto binary = config.value("sing_box_binary", std::string("/opt/bin/sing-box"));
        std::error_code ec;
        const bool installed = std::filesystem::is_regular_file(binary, ec);
        return nlohmann::json{{"sing_box_installed", installed},
                              {"sing_box_binary", binary},
                              {"tested_version", "1.13.14"}}
            .dump();
    });

    server.get("/api/transports", [&ctx]() -> std::string {
        const auto endpoint = load_endpoint(ctx.config_path);
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(3, 0);
        const httplib::Headers headers{
            {"Authorization", "Bearer " + endpoint.api_key},
        };
        const auto response = client.Get("/v1/transports", headers);
        if (!response) {
            throw ApiError("transport manager is unavailable", 503);
        }
        if (response->status < 200 || response->status >= 300) {
            throw ApiError("transport manager returned HTTP " +
                               std::to_string(response->status),
                           502);
        }

        // Reject malformed companion responses before forwarding them to the UI.
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(response->body);
        } catch (const nlohmann::json::exception&) {
            throw ApiError("transport manager returned malformed JSON", 502);
        }
        if (!body.is_array()) {
            throw ApiError("transport manager returned an invalid response", 502);
        }
        return body.dump();
    });

    server.post("/api/transports", [&ctx](const std::string& request_body) -> std::string {
        nlohmann::json request;
        try {
            request = nlohmann::json::parse(request_body);
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid transport action JSON", 400);
        }

        if (!request.is_object() || !request.contains("tag") ||
            !request["tag"].is_string() || !request.contains("action") ||
            !request["action"].is_string()) {
            throw ApiError("transport action requires string tag and action", 400);
        }
        const auto tag = request["tag"].get<std::string>();
        const auto action = request["action"].get<std::string>();
        if (!valid_transport_tag(tag)) {
            throw ApiError("invalid transport tag", 400);
        }
        if (action != "up" && action != "down" && action != "restart") {
            throw ApiError("transport action must be up, down, or restart", 400);
        }

        const auto endpoint = load_endpoint(ctx.config_path);
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(15, 0);
        const httplib::Headers headers{
            {"Authorization", "Bearer " + endpoint.api_key},
        };
        const auto response = client.Post("/v1/transports/" + tag + "/" + action,
                                          headers,
                                          "",
                                          "application/json");
        if (!response) {
            throw ApiError("transport manager is unavailable", 503);
        }
        if (response->status < 200 || response->status >= 300) {
            throw ApiError("transport manager returned HTTP " +
                               std::to_string(response->status),
                           response->status == 404 ? 404 :
                           response->status == 400 ? 400 : 502,
                           response->body);
        }
        try {
            return nlohmann::json::parse(response->body).dump();
        } catch (const nlohmann::json::exception&) {
            throw ApiError("transport manager returned malformed JSON", 502);
        }
    });

    server.get("/api/transports/config", [&ctx]() -> std::string {
        const auto endpoint = load_endpoint(ctx.config_path);
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(3, 0);
        const httplib::Headers headers{
            {"Authorization", "Bearer " + endpoint.api_key},
        };
        const auto response = client.Get("/v1/config/transports", headers);
        if (!response) {
            throw ApiError("transport manager is unavailable", 503);
        }
        if (response->status < 200 || response->status >= 300) {
            throw ApiError("transport manager returned HTTP " +
                               std::to_string(response->status),
                           502);
        }
        try {
            const auto body = nlohmann::json::parse(response->body);
            if (!body.is_array()) {
                throw ApiError("transport manager returned an invalid config response", 502);
            }
            return body.dump();
        } catch (const nlohmann::json::exception&) {
            throw ApiError("transport manager returned malformed JSON", 502);
        }
    });

    server.get("/api/transports/config/export", [&ctx]() -> std::string {
        const auto endpoint = load_endpoint(ctx.config_path);
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(5, 0);
        const httplib::Headers headers{
            {"Authorization", "Bearer " + endpoint.api_key},
        };
        const auto response = client.Get("/v1/config/transports/export", headers);
        if (!response) {
            throw ApiError("transport manager is unavailable", 503);
        }
        if (response->status < 200 || response->status >= 300) {
            throw ApiError("transport manager returned HTTP " +
                               std::to_string(response->status),
                           502);
        }
        try {
            const auto body = nlohmann::json::parse(response->body);
            if (!body.is_array()) {
                throw ApiError("transport manager returned an invalid export response", 502);
            }
            return body.dump();
        } catch (const nlohmann::json::exception&) {
            throw ApiError("transport manager returned malformed JSON", 502);
        }
    });

    server.post("/api/transports/config", [&ctx](const std::string& request_body) -> std::string {
        nlohmann::json request;
        try {
            request = nlohmann::json::parse(request_body);
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid transport config operation JSON", 400);
        }
        if (!request.is_object() || !request.contains("operation") ||
            !request["operation"].is_string()) {
            throw ApiError("transport config operation is required", 400);
        }

        const auto operation = request["operation"].get<std::string>();
        std::string tag;
        if (operation == "update" || operation == "delete") {
            if (!request.contains("tag") || !request["tag"].is_string()) {
                throw ApiError("transport tag is required", 400);
            }
            tag = request["tag"].get<std::string>();
            if (!valid_transport_tag(tag)) {
                throw ApiError("invalid transport tag", 400);
            }
        }
        if ((operation == "create" || operation == "update") &&
            (!request.contains("transport") || !request["transport"].is_object())) {
            throw ApiError("transport object is required", 400);
        }
        if (operation != "create" && operation != "update" && operation != "delete") {
            throw ApiError("unsupported transport config operation", 400);
        }

        const auto endpoint = load_endpoint(ctx.config_path);
        httplib::Client client(endpoint.host, endpoint.port);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(15, 0);
        const httplib::Headers headers{
            {"Authorization", "Bearer " + endpoint.api_key},
        };
        const auto parse_response = [](const auto& response) -> std::string {
            if (!response) {
                throw ApiError("transport manager is unavailable", 503);
            }
            if (response->status < 200 || response->status >= 300) {
                throw ApiError("transport manager returned HTTP " +
                                   std::to_string(response->status),
                               response->status == 400 ? 400 : 502,
                               response->body);
            }
            try {
                return nlohmann::json::parse(response->body).dump();
            } catch (const nlohmann::json::exception&) {
                throw ApiError("transport manager returned malformed JSON", 502);
            }
        };
        if (operation == "create") {
            return parse_response(client.Post("/v1/config/transports",
                                              headers,
                                              request["transport"].dump(),
                                              "application/json"));
        }
        if (operation == "update") {
            return parse_response(client.Put("/v1/config/transports/" + tag,
                                             headers,
                                             request["transport"].dump(),
                                             "application/json"));
        }
        return parse_response(client.Delete("/v1/config/transports/" + tag, headers));
    });
}

} // namespace keen_pbr3

#endif // WITH_API
