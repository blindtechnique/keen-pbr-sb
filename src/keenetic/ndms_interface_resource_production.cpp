#include "ndms_interface_resource.hpp"

#include "../http/http_client.hpp"

#include <chrono>
#ifdef KEEN_PBR3_TESTING
#include <cstdlib>
#endif

namespace keen_pbr3 {
namespace {

constexpr const char* kRciInterfaces =
    "http://127.0.0.1:79/rci/show/interface";

} // namespace

NdmsInterfaceResource& shared_ndms_interface_resource() {
    static NdmsInterfaceResource resource([] {
        HttpClient client;
        // Endpoint discovery is part of login. Preserve its one-second bound;
        // daemon inventory consumers retain LKG and retry on transient misses.
        client.set_timeout(std::chrono::seconds(1));
        client.set_max_response_size(2U * 1024U * 1024U);
#ifdef KEEN_PBR3_TESTING
        // Exercise real discovery/parsing with a loopback firmware fixture.
        // Production always uses the fixed router RCI URL.
        if (const auto* endpoint =
                std::getenv("KEEN_PBR_TEST_NDMS_INTERFACE_ENDPOINT")) {
            if (*endpoint) return client.download(endpoint);
        }
#endif
        return client.download(kRciInterfaces);
    });
    return resource;
}

} // namespace keen_pbr3
