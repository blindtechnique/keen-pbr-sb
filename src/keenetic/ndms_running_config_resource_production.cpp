#include "ndms_running_config_resource.hpp"

#include "../http/http_client.hpp"

#include <chrono>

namespace keen_pbr3 {
namespace {

constexpr const char* kRciRunningConfig =
    "http://127.0.0.1:79/rci/show/running-config";

} // namespace

NdmsRunningConfigResource& shared_ndms_running_config_resource() {
    static NdmsRunningConfigResource resource([] {
        HttpClient client;
        // This owner is also the legacy auth endpoint fallback. Preserve that
        // path's previous one-second interactive bound; daemon consumers keep
        // LKG and retry rather than extending login serialization to 3s.
        client.set_timeout(std::chrono::seconds(1));
        client.set_max_response_size(2U * 1024U * 1024U);
        return client.download(kRciRunningConfig);
    });
    return resource;
}

} // namespace keen_pbr3
