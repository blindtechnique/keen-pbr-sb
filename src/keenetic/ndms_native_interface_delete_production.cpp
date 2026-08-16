#include "ndms_native_interface_delete_production.hpp"

#include "../http/http_client.hpp"
#include "../util/ndmc.hpp"

#include <chrono>

namespace keen_pbr3 {

namespace {

constexpr const char* kRciBase = "http://127.0.0.1:79/rci/";
constexpr std::size_t kNdmcCaptureBytes = 8192U;

} // namespace

NdmsNativeInterfaceDeleteDependencies
ndms_native_interface_delete_production_dependencies() {
    NdmsNativeInterfaceDeleteDependencies dependencies;
    dependencies.read_document =
        [](const std::string& path) -> std::optional<nlohmann::json> {
        try {
            HttpClient client;
            client.set_timeout(std::chrono::seconds(4));
            client.set_max_response_size(2U * 1024U * 1024U);
            const auto body = client.download(std::string(kRciBase) + path);
            if (body.empty()) {
                // The measured shape of an absent interface: a zero-byte
                // body, not an error and not JSON. Reported as a readable
                // "nothing here" rather than as a failed read.
                return nlohmann::json();
            }
            return nlohmann::json::parse(body);
        } catch (const std::exception&) {
            return std::nullopt;
        }
    };
    dependencies.run_command = [](const std::string& command) {
        // succeeded() also rejects a truncated capture, which is right here:
        // a banner we could not read whole is a result we cannot claim to
        // have understood.
        return ndmc_capture(command, kNdmcCaptureBytes).succeeded();
    };
    return dependencies;
}

} // namespace keen_pbr3
