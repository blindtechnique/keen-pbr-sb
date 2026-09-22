#ifdef WITH_API
#include "handler_list_hints.hpp"
#include "../lists/list_hints.hpp"

#include <memory>
#include <mutex>

namespace keen_pbr3 {

api::ListHintsResponse query_list_hints(const ApiContext& ctx) {
    const auto visible = ctx.get_visible_config_state();
    auto result = ctx.get_list_hints_fn
        ? ctx.get_list_hints_fn(visible.config) : build_list_hints(visible.config);
    result.revision = visible.revision;
    result.is_draft = visible.is_draft;
    return result;
}

ApiServer::BodyRouteHandler make_list_hints_handler(ApiContext& ctx) {
    // Bound this optional report to one worker. This mutex is unrelated to
    // apply/admission/lifecycle and never prevents saving or routing.
    const auto worker = std::make_shared<std::mutex>();
    return [&ctx, worker](const std::string&) {
        const std::unique_lock<std::mutex> lock(*worker, std::try_to_lock);
        if (!lock.owns_lock()) throw ApiError("List hints are already being computed", 503);
        return nlohmann::json(query_list_hints(ctx)).dump();
    };
}

void register_list_hints_handler(ApiServer& server, ApiContext& ctx) {
    server.post("/api/lists/hints", make_list_hints_handler(ctx));
}

} // namespace keen_pbr3
#endif
