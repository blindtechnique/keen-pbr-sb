#pragma once

#ifdef WITH_API
#include "handlers.hpp"
namespace keen_pbr3 {
void register_connections_handler(ApiServer& server, ApiContext& ctx);
}
#endif
