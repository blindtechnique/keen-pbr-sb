#include "ndms_catalog_cache.hpp"

namespace keen_pbr3 {

NdmsCatalogCache& shared_ndms_catalog_cache() {
    static NdmsCatalogCache cache(shared_ndms_interface_resource());
    return cache;
}

} // namespace keen_pbr3
