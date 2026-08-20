#pragma once

#ifdef WITH_API

#include "../keenetic/ndms_catalog_cache.hpp"
#include "../keenetic/ndms_vpn_server_service_cache.hpp"
#include "handlers.hpp"
#include "server.hpp"

#include <functional>
#include <string>
#include <vector>

namespace keen_pbr3 {

using NdmsNativeImportReadinessProvider =
    std::function<NdmsNativeImportJournalReadinessState()>;
using NdmsNativeInventoryProjectionProvider =
    std::function<NdmsNativeInventoryProjection(
        const std::vector<NdmsTunnelInterface>&,
        bool)>;

// Human names for interfaces, taken from the router's own configuration.
//
// keen-pbr works in kernel interface names - nwg2, ppp0, eth3 - because that
// is what routing needs. The person who set the router up named the same
// things differently in NDMS: "sddvpn.mooo.com AWG2", "Провайдер", "Гостевая
// сеть". Showing our names where theirs exist is the single largest source of
// confusion in the interface, and the firmware already knows the mapping.
void register_ndms_names_handler(ApiServer& server, ApiContext& ctx);

#ifdef KEEN_PBR3_TESTING
void register_ndms_names_handler_for_tests(ApiServer& server,
                                           NdmsCatalogCache& cache,
                                           std::vector<std::string>
                                               runtime_interface_names = {},
                                           NdmsNativeImportReadinessProvider
                                               native_import_readiness_provider = {},
                                           NdmsNativeInventoryProjectionProvider
                                               native_inventory_projection_provider = {});
void register_ndms_vpn_server_services_handler_for_tests(
    ApiServer& server,
    NdmsVpnServerServiceCache& cache);
#endif

} // namespace keen_pbr3

#endif
