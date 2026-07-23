#ifdef WITH_API

#include "handler_runtime_inventory.hpp"

#include "handler_health_service.hpp"

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

api::RuntimeInventoryResponse build_runtime_inventory(const ApiContext& ctx) {
    api::RuntimeInventoryResponse inventory;
    inventory.service = build_health_response(ctx.get_service_health());
    inventory.outbounds = ctx.get_runtime_outbounds();
    inventory.interfaces = ctx.get_runtime_interfaces();
    return inventory;
}

void register_runtime_inventory_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/runtime/inventory", [&ctx]() -> std::string {
        return nlohmann::json(build_runtime_inventory(ctx)).dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
