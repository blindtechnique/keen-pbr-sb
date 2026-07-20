#pragma once

#ifdef WITH_API

#include "handlers.hpp"

namespace keen_pbr3 {

// POST /api/system/geo — where the proxy servers of managed transports are.
void register_geo_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
