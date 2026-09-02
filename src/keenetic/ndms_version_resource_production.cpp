#include "ndms_version_resource.hpp"

#include "../http/http_client.hpp"

#include <chrono>

namespace keen_pbr3 {

NdmsVersionResource& shared_ndms_version_resource() {
    static NdmsVersionResource resource([] {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(2));
        client.set_max_response_size(2U * 1024U * 1024U);
        return client.download(
            "http://127.0.0.1:79/rci/show/version");
    });
    return resource;
}

} // namespace keen_pbr3
