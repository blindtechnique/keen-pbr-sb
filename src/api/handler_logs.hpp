#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

namespace keen_pbr3 {
void register_logs_handler(ApiServer& server, ApiContext& ctx);
}

#endif
