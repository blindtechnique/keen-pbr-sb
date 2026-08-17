#ifdef WITH_API

#include "transport_manager_endpoint.hpp"

#include "server.hpp"

#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

TransportManagerEndpoint load_transport_manager_endpoint(
    const std::string& keen_pbr_config_path) {
    const auto path =
        std::filesystem::path(keen_pbr_config_path).parent_path() /
        "transports.json";
    std::ifstream input(path);
    if (!input.is_open()) {
        throw ApiError(
            "transport manager config not found: " + path.string(), 503);
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

} // namespace keen_pbr3

#endif // WITH_API
