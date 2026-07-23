#ifdef WITH_API

#include "handler_reload.hpp"
#include "generated/api_types.hpp"

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {
std::string success_response(const std::string& message) {
    api::ReloadResponse resp;
    resp.status = api::ConfigUpdateResponseStatus::OK;
    resp.message = message;
    return nlohmann::json(resp).dump();
}

std::string run_lifecycle(ApiContext& ctx,
                          LifecycleOperationType type,
                          std::vector<LifecycleOperationStage> stages,
                          const std::string& stage_id,
                          const std::function<void()>& action,
                          const std::string& message) {
    if (!ctx.lifecycle_operations) {
        action();
        return success_response(message);
    }

    LifecycleOperationSnapshot operation;
    if (const auto active = ctx.lifecycle_operations->begin(
            type, std::move(stages), operation)) {
        throw ApiError("A lifecycle operation is already active", 409,
                       nlohmann::json{{"error", "A lifecycle operation is already active"},
                                      {"active_operation_id", *active}}.dump());
    }

    try {
        ctx.lifecycle_operations->start_stage(operation.id, stage_id);
        action();
        ctx.lifecycle_operations->succeed_stage(operation.id, stage_id);
        ctx.lifecycle_operations->finish(operation.id);
        return success_response(message);
    } catch (const std::exception& error) {
        ctx.lifecycle_operations->fail_stage(operation.id, stage_id, error.what());
        ctx.lifecycle_operations->finish(operation.id, error.what());
        throw;
    } catch (...) {
        constexpr const char* error = "Unknown lifecycle operation failure";
        ctx.lifecycle_operations->fail_stage(operation.id, stage_id, error);
        ctx.lifecycle_operations->finish(operation.id, error);
        throw;
    }
}

} // namespace

void register_reload_handler(ApiServer& server, ApiContext& ctx) {
    server.post("/api/service/start", [&ctx]() -> std::string {
        return run_lifecycle(
            ctx, LifecycleOperationType::Start,
            {{"start_routing", "Start routing and firewall"}},
            "start_routing", [&ctx] { ctx.start_runtime(); },
            "Routing runtime started");
    });

    server.post("/api/service/stop", [&ctx]() -> std::string {
        return run_lifecycle(
            ctx, LifecycleOperationType::Stop,
            {{"stop_routing", "Stop routing and firewall"}},
            "stop_routing", [&ctx] { ctx.stop_runtime(); },
            "Routing runtime stopped");
    });

    server.post("/api/service/restart", [&ctx]() -> std::string {
        return run_lifecycle(
            ctx, LifecycleOperationType::Restart,
            {{"restart_routing", "Restart routing and firewall"}},
            "restart_routing", [&ctx] { ctx.restart_runtime(); },
            "Routing runtime restarted");
    });
}

} // namespace keen_pbr3

#endif // WITH_API
