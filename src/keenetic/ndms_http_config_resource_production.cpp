#include "ndms_http_config_resource.hpp"

#include "../http/http_client.hpp"

#include <chrono>
#ifdef KEEN_PBR3_TESTING
#include <cstdlib>
#endif

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
#ifdef KEEN_PBR3_TESTING
        if (const auto* endpoint =
                std::getenv("KEEN_PBR_TEST_NDMS_HTTP_CONFIG_ENDPOINT")) {
            if (*endpoint) return client.download(endpoint);
        }
#endif
        return client.download(kRciHttpConfig);
    });
    return resource;
}

} // namespace keen_pbr3
