#pragma once

#include "ndms_rci_json_resource.hpp"

#include <chrono>
#include <utility>

namespace keen_pbr3 {

using NdmsSensitiveInterfaceDocument = NdmsSensitiveJsonDocument;
using NdmsInterfaceFailure = NdmsRciJsonFailure;
using NdmsInterfaceSnapshot = NdmsRciJsonSnapshot;

// Sole shared owner for passive GET /rci/show/interface consumers. Native VPN
// mutation evidence deliberately remains an exact, operation-local read.
class NdmsInterfaceResource final : public NdmsRciJsonResource {
public:
    using Clock = NdmsRciJsonResource::Clock;
    using FetchFn = NdmsRciJsonResource::FetchFn;
    using NowFn = NdmsRciJsonResource::NowFn;

    explicit NdmsInterfaceResource(
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

NdmsInterfaceResource& shared_ndms_interface_resource();

} // namespace keen_pbr3
