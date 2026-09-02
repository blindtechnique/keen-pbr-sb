#include "ndms_http_config_projection.hpp"

namespace keen_pbr3 {

NdmsHttpServiceConfigCache& shared_ndms_http_service_config_cache() {
    static NdmsHttpServiceConfigCache cache(
        shared_ndms_http_config_resource());
    return cache;
}

NdmsLockoutPolicyCache& shared_ndms_lockout_policy_cache() {
    static NdmsLockoutPolicyCache cache(
        shared_ndms_http_config_resource());
    return cache;
}

} // namespace keen_pbr3
