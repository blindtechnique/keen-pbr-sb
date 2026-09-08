#pragma once

#ifdef WITH_API

#include "generated/api_types.hpp"
#include "handlers.hpp"
#include "server.hpp"

#include "../runtime/periodic_task_metrics.hpp"
#include "../daemon/scheduler.hpp"

namespace keen_pbr3 {

api::PeriodicTaskMetricsResponse build_diagnostic_tasks_response(
    const PeriodicTaskMetricsRegistry& registry,
    const std::vector<ScheduledTaskSnapshot>& schedules = {},
    std::int64_t captured_at_unix_ms = 0);
void register_diagnostic_tasks_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
