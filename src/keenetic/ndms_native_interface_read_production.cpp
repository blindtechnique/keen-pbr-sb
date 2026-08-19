#include "ndms_native_interface_read_production.hpp"

#include "../http/http_client.hpp"

#include <chrono>

namespace keen_pbr3 {

namespace {

constexpr const char* kRciBase = "http://127.0.0.1:79/rci/";

} // namespace

NdmsNativeInterfaceReadDependencies
ndms_native_interface_read_production_dependencies() {
    NdmsNativeInterfaceReadDependencies dependencies;
    dependencies.read_document =
        [](const std::string& path) -> std::optional<nlohmann::json> {
        try {
            HttpClient client;
            client.set_timeout(std::chrono::seconds(4));
            client.set_max_response_size(2U * 1024U * 1024U);
            HttpRequestOptions options;
            options.destination_filter = [](const std::string& address) {
                return ndms_native_interface_read_loopback_destination_permitted(
                    address);
            };
            options.max_redirects = 0;
            const auto body =
                client.download(std::string(kRciBase) + path, options);
            if (body.empty()) {
                return nlohmann::json();
            }
            return nlohmann::json::parse(body);
        } catch (const std::exception&) {
            return std::nullopt;
        }
    };
    return dependencies;
}

} // namespace keen_pbr3
