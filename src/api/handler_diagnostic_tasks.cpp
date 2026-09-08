#ifdef WITH_API

#include "handler_diagnostic_tasks.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

std::int64_t api_integer(std::uint64_t value) noexcept {
    constexpr auto maximum =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    return static_cast<std::int64_t>(std::min(value, maximum));
}

api::LastOutcome api_outcome(PeriodicTaskOutcome outcome) noexcept {
    switch (outcome) {
    case PeriodicTaskOutcome::Success:
        return api::LastOutcome::SUCCESS;
    case PeriodicTaskOutcome::Noop:
        return api::LastOutcome::NOOP;
    case PeriodicTaskOutcome::Failure:
        return api::LastOutcome::FAILURE;
    case PeriodicTaskOutcome::Skipped:
        return api::LastOutcome::SKIPPED;
    case PeriodicTaskOutcome::Abandoned:
        return api::LastOutcome::ABANDONED;
    }
    return api::LastOutcome::ABANDONED;
}

api::PeriodicTaskMetricsEntry api_entry(
    const PeriodicTaskMetricsSnapshot& snapshot,
    const std::vector<ScheduledTaskSnapshot>& schedules,
    std::int64_t captured_at_unix_ms) {
    api::PeriodicTaskMetricsEntry entry;
    entry.label = snapshot.label;
    entry.runs = api_integer(snapshot.runs);
    entry.success = api_integer(snapshot.success);
    entry.noop = api_integer(snapshot.noop);
    entry.failure = api_integer(snapshot.failure);
    entry.consecutive_failures = api_integer(snapshot.consecutive_failures);
    entry.skipped = api_integer(snapshot.skipped);
    entry.abandoned = api_integer(snapshot.abandoned);
    entry.in_flight = api_integer(snapshot.in_flight);
    entry.total_duration_ms = api_integer(snapshot.total_duration_ms);
    entry.max_duration_ms = api_integer(snapshot.max_duration_ms);
    if (snapshot.last_duration_ms.has_value()) {
        entry.last_duration_ms = api_integer(*snapshot.last_duration_ms);
    }
    entry.last_started_at_unix_ms = snapshot.last_started_at_unix_ms;
    entry.last_finished_at_unix_ms = snapshot.last_finished_at_unix_ms;
    entry.last_event_at_unix_ms = snapshot.last_event_at_unix_ms;
    if (snapshot.last_outcome.has_value()) {
        entry.last_outcome = api_outcome(*snapshot.last_outcome);
    }
    if (!snapshot.last_error.empty()) {
        entry.last_error = snapshot.last_error;
    }
    entry.scheduling_state = "unknown";
    const auto scheduled = std::find_if(schedules.begin(), schedules.end(),
        [&snapshot](const ScheduledTaskSnapshot& candidate) {
            return candidate.label == snapshot.label;
        });
    if (scheduled != schedules.end()) {
        if (scheduled->state == ScheduledTaskState::NotScheduled) {
            entry.scheduling_state = "not_scheduled";
        } else if (scheduled->state == ScheduledTaskState::Scheduled &&
                   scheduled->remaining_ms.has_value()) {
            entry.scheduling_state = "scheduled";
            const auto captured = std::max<std::int64_t>(0, captured_at_unix_ms);
            const auto remaining = api_integer(*scheduled->remaining_ms);
            constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
            entry.next_run_at_unix_ms = remaining > maximum - captured
                ? maximum : captured + remaining;
        }
    }
    return entry;
}

} // namespace

api::PeriodicTaskMetricsResponse build_diagnostic_tasks_response(
    const PeriodicTaskMetricsRegistry& registry,
    const std::vector<ScheduledTaskSnapshot>& schedules,
    std::int64_t captured_at_unix_ms) {
    api::PeriodicTaskMetricsResponse response;
    response.capacity = api_integer(registry.capacity());
    response.tracked = api_integer(registry.size());
    const auto snapshot = registry.snapshot();
    response.tasks.reserve(snapshot.size());
    for (const auto& task : snapshot) {
        response.tasks.push_back(api_entry(task, schedules, captured_at_unix_ms));
    }
    return response;
}

void register_diagnostic_tasks_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/diagnostics/tasks", [&ctx]() -> std::string {
        return nlohmann::json(ctx.get_diagnostic_tasks()).dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
