#include "ndms_version_projection.hpp"

namespace keen_pbr3 {

NdmsRouterVersionFactsCache& shared_ndms_router_version_facts_cache() {
    static NdmsRouterVersionFactsCache cache(shared_ndms_version_resource());
    return cache;
}

NdmsFirmwareVersionCache& shared_ndms_firmware_version_cache() {
    static NdmsFirmwareVersionCache cache(shared_ndms_version_resource());
    return cache;
}

} // namespace keen_pbr3
