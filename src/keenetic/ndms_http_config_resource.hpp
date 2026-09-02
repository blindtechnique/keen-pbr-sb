#pragma once

#include "ndms_rci_json_resource.hpp"

#include <chrono>
#include <utility>

namespace keen_pbr3 {

using NdmsSensitiveHttpConfigDocument = NdmsSensitiveJsonDocument;
using NdmsHttpConfigFailure = NdmsRciJsonFailure;
using NdmsHttpConfigSnapshot = NdmsRciJsonSnapshot;

// Sole process-local owner of passive GET /rci/show/rc/ip/http reads. Endpoint
// discovery and the firmware lockout-policy projection consume the same exact
// immutable document generation instead of issuing independent RCI requests.
class NdmsHttpConfigResource final : public NdmsRciJsonResource {
public:
    using Clock = NdmsRciJsonResource::Clock;
    using FetchFn = NdmsRciJsonResource::FetchFn;
    using NowFn = NdmsRciJsonResource::NowFn;

    explicit NdmsHttpConfigResource(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(5),
        NowFn now_fn = {})
        : NdmsRciJsonResource(
              std::move(fetch_fn),
              NdmsRciJsonShape::object,
              cache_ttl,
              failure_retry,
              std::move(now_fn)) {}
};

NdmsHttpConfigResource& shared_ndms_http_config_resource();

} // namespace keen_pbr3
