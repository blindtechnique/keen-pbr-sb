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

RuntimeMutationAdmission::Lease take_lifecycle_lease(
    ApiRuntimeMutationGuard& mutation) {
    if (!mutation.uses_production_admission() ||
        !mutation.arm_handoff_gate()) {
        throw ApiError(
            "Runtime lifecycle owner is unavailable", 503);
    }
    return mutation.take_lease();
}

std::string run_lifecycle(ApiContext& ctx,
                          LifecycleOperationType type,
                          std::vector<LifecycleOperationStage> stages,
                          const std::string& stage_id,
                          const std::function<void(ApiRuntimeMutationGuard&)>&
                              action,
                          const std::string& message,
                          const std::string& mutation_label,
                          bool require_runtime_running,
                          bool require_runtime_stopped) {
    // Admission precedes the UI projection. A busy runtime therefore cannot
    // publish a short-lived failed lifecycle operation over the operation
    // which already owns kernel/DNS state.
    ApiRuntimeMutationGuard mutation(
        ctx,
        mutation_label,
        require_runtime_running,
        require_runtime_stopped);

    if (!ctx.lifecycle_operations) {
        action(mutation);
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
        action(mutation);
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
            "start_routing",
            [&ctx](ApiRuntimeMutationGuard& mutation) {
                if (ctx.can_start_runtime_with_lease()) {
                    ctx.start_runtime_with_lease(
                        take_lifecycle_lease(mutation));
                    return;
                }
                ctx.start_runtime();
            },
            "Routing runtime started", "start-runtime", false, true);
    });

    server.post("/api/service/stop", [&ctx]() -> std::string {
        return run_lifecycle(
            ctx, LifecycleOperationType::Stop,
            {{"stop_routing", "Stop routing and firewall"}},
            "stop_routing",
            [&ctx](ApiRuntimeMutationGuard& mutation) {
                if (ctx.can_stop_runtime_with_lease()) {
                    ctx.stop_runtime_with_lease(
                        take_lifecycle_lease(mutation));
                    return;
                }
                ctx.stop_runtime();
            },
            "Routing runtime stopped", "stop-runtime", true, false);
    });

    server.post("/api/service/restart", [&ctx]() -> std::string {
        return run_lifecycle(
            ctx, LifecycleOperationType::Restart,
            {{"restart_routing", "Restart routing and firewall"}},
            "restart_routing",
            [&ctx](ApiRuntimeMutationGuard& mutation) {
                if (ctx.can_restart_runtime_with_lease()) {
                    ctx.restart_runtime_with_lease(
                        take_lifecycle_lease(mutation));
                    return;
                }
                ctx.restart_runtime();
            },
            "Routing runtime restarted", "restart-runtime", true, false);
    });
}

} // namespace keen_pbr3

#endif // WITH_API
