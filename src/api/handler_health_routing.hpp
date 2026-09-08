#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

namespace keen_pbr3 {

// A failed observation is an API error; a completed but degraded report is
// still a successful response. Keep the existing serialized body in both cases.
std::string make_routing_health_response(const RoutingHealthReport& report);

void register_health_routing_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
