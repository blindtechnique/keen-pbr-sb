#include "ndms_http_config_resource.hpp"

#include "../http/http_client.hpp"

#include <chrono>

namespace keen_pbr3 {
namespace {

constexpr const char* kRciHttpConfig =
    "http://127.0.0.1:79/rci/show/rc/ip/http";

} // namespace

NdmsHttpConfigResource& shared_ndms_http_config_resource() {
    static NdmsHttpConfigResource resource([] {
        HttpClient client;
        // Both existing consumers used a one-second interactive bound.
        client.set_timeout(std::chrono::seconds(1));
        client.set_max_response_size(2U * 1024U * 1024U);
        return client.download(kRciHttpConfig);
    });
    return resource;
}

} // namespace keen_pbr3
