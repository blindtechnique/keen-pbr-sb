#include "ndms_interface_resource.hpp"

#include "../http/http_client.hpp"

#include <chrono>

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
        return client.download(kRciInterfaces);
    });
    return resource;
}

} // namespace keen_pbr3
