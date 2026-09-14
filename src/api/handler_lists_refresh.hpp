#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

namespace keen_pbr3 {

api::ListRefreshRequest parse_list_refresh_request(const std::string& body);

// The list cache may already be durable even when its runtime generation was
// not applied. Preserve that partial result without turning it into HTTP OK.
ApiError make_list_refresh_apply_error(
    const ListRefreshOperationResult& partial,
    const char* stage,
    const std::string& detail,
    const char* runtime_result = "unknown");

void register_lists_refresh_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
