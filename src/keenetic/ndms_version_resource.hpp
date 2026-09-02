#pragma once

#include "ndms_rci_json_resource.hpp"

#include <chrono>
#include <utility>

namespace keen_pbr3 {

using NdmsVersionSnapshot = NdmsRciJsonSnapshot;

class NdmsVersionResource final : public NdmsRciJsonResource {
public:
    using Clock = NdmsRciJsonResource::Clock;
    using FetchFn = NdmsRciJsonResource::FetchFn;
    using NowFn = NdmsRciJsonResource::NowFn;

    explicit NdmsVersionResource(
        FetchFn fetch_fn,
        Clock::duration cache_ttl = std::chrono::seconds(30),
        Clock::duration failure_retry = std::chrono::seconds(30),
        NowFn now_fn = {})
        : NdmsRciJsonResource(
              std::move(fetch_fn), NdmsRciJsonShape::version_document,
              cache_ttl, failure_retry, std::move(now_fn)) {}
};

NdmsVersionResource& shared_ndms_version_resource();

} // namespace keen_pbr3
