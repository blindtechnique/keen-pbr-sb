#pragma once
#ifdef WITH_API
#include "handlers.hpp"

namespace keen_pbr3 {
api::ListHintsResponse query_list_hints(const ApiContext& ctx);
ApiServer::BodyRouteHandler make_list_hints_handler(ApiContext& ctx);
void register_list_hints_handler(ApiServer& server, ApiContext& ctx);
} // namespace keen_pbr3
#endif
