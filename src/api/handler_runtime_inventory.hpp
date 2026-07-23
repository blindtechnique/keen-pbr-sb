#pragma once

#ifdef WITH_API

#include "generated/api_types.hpp"
#include "handlers.hpp"
#include "server.hpp"

namespace keen_pbr3 {

api::RuntimeInventoryResponse build_runtime_inventory(const ApiContext& ctx);
void register_runtime_inventory_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
