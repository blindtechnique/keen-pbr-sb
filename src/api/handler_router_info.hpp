#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"
#include "../routing/interface_monitor.hpp"

namespace keen_pbr3 {
void register_router_info_handler(ApiServer& server, ApiContext& ctx);
bool invalidate_router_info(const InterfaceMonitor::Event& event);
}

#endif
