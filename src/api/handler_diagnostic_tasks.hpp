#pragma once

#ifdef WITH_API

#include "generated/api_types.hpp"
#include "handlers.hpp"
#include "server.hpp"

#include "../runtime/periodic_task_metrics.hpp"

namespace keen_pbr3 {

api::PeriodicTaskMetricsResponse build_diagnostic_tasks_response(
    const PeriodicTaskMetricsRegistry& registry);
void register_diagnostic_tasks_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
