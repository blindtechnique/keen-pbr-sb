#include "ndms_vpn_server_service_cache.hpp"

namespace keen_pbr3 {

NdmsVpnServerServiceCache& shared_ndms_vpn_server_service_cache() {
    static NdmsVpnServerServiceCache cache(
        shared_ndms_running_config_resource());
    return cache;
}

} // namespace keen_pbr3
