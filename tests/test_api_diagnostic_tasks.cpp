#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cstdint>
#include <limits>

#include "api/handler_diagnostic_tasks.hpp"
#include "api/handler_runtime_inventory.hpp"
#include "api/sse_broadcaster.hpp"
#include "api/status_stream.hpp"

namespace keen_pbr3 {
namespace {

ApiContext make_diagnostic_tasks_context(SseBroadcaster& broadcaster) {
    ApiContext context{
        "/tmp/keen-pbr-diagnostic-tasks-test.json",
        broadcaster,
        [] { return Config{}; },
        [] { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> {
            return std::nullopt;
        },
        [] {},
        [](const Config&) {},
        [] { return ServiceHealthState{}; },
        [] { return RoutingHealthReport{}; },
        [] { return api::RuntimeOutboundsResponse{}; },
        [] { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) {
            return std::map<std::string, api::ListRefreshStateValue>{};
        },
        [](const std::string&) { return TestRoutingResult{}; },
        [] {},
        [] {},
        [](Config, std::string) { return ConfigApplyResult{}; },
        [] {},
        [] {},
        [] {},
        [](const api::ListRefreshRequest&) {
            return ListRefreshOperationResult{};
        },
    };
    return context;
}

bool has_no_next_run(const nlohmann::json& task) {
    const auto value = task.find("next_run_at_unix_ms");
    return value == task.end() || value->is_null();
}

} // namespace

TEST_CASE("diagnostic task context has a safe empty fallback") {
    SseBroadcaster broadcaster;
    const auto context = make_diagnostic_tasks_context(broadcaster);
    const auto response = context.get_diagnostic_tasks();

    CHECK(response.capacity == 0);
    CHECK(response.tracked == 0);
    CHECK(response.tasks.empty());
}

#ifndef KEEN_PBR_TASK_DIAGNOSTICS_FOCUSED
TEST_CASE("diagnostic task endpoint returns one pull-only snapshot") {
    SseBroadcaster broadcaster;
    auto context = make_diagnostic_tasks_context(broadcaster);
    PeriodicTaskMetricsRegistry registry(
        {"resolver-hash-refresh", "owned-snat-health"});
    auto run = registry.begin("resolver-hash-refresh");
    REQUIRE(run.failure("dnsmasq did not converge"));

    int callback_calls = 0;
    const std::vector<ScheduledTaskSnapshot> schedules{
        {"resolver-hash-refresh", ScheduledTaskState::Scheduled, 250U}};
    context.get_diagnostic_tasks_fn = [&]() {
        ++callback_calls;
        return build_diagnostic_tasks_response(registry, schedules, 1000);
    };

    ApiConfig config;
    config.listen = std::string("127.0.0.1:18195");
    ApiServer server(config);
    register_diagnostic_tasks_handler(server, context);
    server.start();

    httplib::Client client("127.0.0.1", 18195);
    const auto response = client.Get("/api/diagnostics/tasks");
    const auto repeated_response = client.Get("/api/diagnostics/tasks");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    REQUIRE(repeated_response != nullptr);
    CHECK(repeated_response->status == 200);
    CHECK(callback_calls == 2);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(nlohmann::json::parse(repeated_response->body) == body);
    CHECK(body["capacity"] == 32);
    CHECK(body["tracked"] == 2);
    REQUIRE(body["tasks"].size() == 2);
    CHECK(body["tasks"][0]["label"] == "owned-snat-health");
    CHECK(body["tasks"][1]["label"] == "resolver-hash-refresh");
    CHECK(body["tasks"][1]["runs"] == 1);
    CHECK(body["tasks"][1]["failure"] == 1);
    CHECK(body["tasks"][1]["last_outcome"] == "failure");
    CHECK(body["tasks"][1]["last_error"] == "dnsmasq did not converge");
    CHECK(body["tasks"][1]["consecutive_failures"] == 1);
    CHECK(body["tasks"][1]["scheduling_state"] == "scheduled");
    CHECK(body["tasks"][1]["next_run_at_unix_ms"] == 1250);
    CHECK(body["tasks"][0]["consecutive_failures"] == 0);
    CHECK(body["tasks"][0]["scheduling_state"] == "unknown");
    CHECK(has_no_next_run(body["tasks"][0]));
    const auto after_reads = registry.snapshot();
    REQUIRE(after_reads.size() == 2U);
    CHECK(after_reads[0].runs == 0U);
    CHECK(after_reads[1].runs == 1U);
    CHECK(after_reads[1].failure == 1U);
    CHECK(after_reads[1].consecutive_failures == 1U);

    const auto decoded = body.get<api::PeriodicTaskMetricsResponse>();
    REQUIRE(decoded.tasks.size() == 2U);
    CHECK(decoded.tasks[1].consecutive_failures == 1);
    CHECK(decoded.tasks[1].next_run_at_unix_ms == 1250);
    auto legacy_body = body;
    for (auto& task : legacy_body["tasks"]) {
        task.erase("consecutive_failures");
        task.erase("scheduling_state");
        task.erase("next_run_at_unix_ms");
    }
    const auto legacy = legacy_body.get<api::PeriodicTaskMetricsResponse>();
    REQUIRE(legacy.tasks.size() == 2U);
    CHECK(legacy.tasks[1].runs == 1);
    CHECK(legacy.tasks[1].failure == 1);
    CHECK_FALSE(legacy.tasks[1].consecutive_failures.has_value());
    CHECK_FALSE(legacy.tasks[1].scheduling_state.has_value());
    CHECK_FALSE(legacy.tasks[1].next_run_at_unix_ms.has_value());
}
#endif

TEST_CASE("diagnostic task repeated context reads preserve metrics and schedule") {
    SseBroadcaster broadcaster;
    auto context = make_diagnostic_tasks_context(broadcaster);
    PeriodicTaskMetricsRegistry registry({"resolver-hash-refresh"});
    auto failed = registry.begin("resolver-hash-refresh");
    REQUIRE(failed.failure("resolver unavailable"));
    auto active = registry.begin("resolver-hash-refresh");
    const std::vector<ScheduledTaskSnapshot> schedules{
        {"resolver-hash-refresh", ScheduledTaskState::Scheduled, 750U}};
    const auto before = registry.snapshot();
    int callback_calls = 0;
    context.get_diagnostic_tasks_fn = [&]() {
        ++callback_calls;
        return build_diagnostic_tasks_response(registry, schedules, 1000);
    };

    const nlohmann::json first = context.get_diagnostic_tasks();
    const nlohmann::json second = context.get_diagnostic_tasks();
    CHECK(first == second);
    CHECK(callback_calls == 2);
    REQUIRE(first["tasks"].size() == 1U);
    CHECK(first["tasks"][0]["runs"] == 2);
    CHECK(first["tasks"][0]["failure"] == 1);
    CHECK(first["tasks"][0]["in_flight"] == 1);
    CHECK(first["tasks"][0]["consecutive_failures"] == 1);
    CHECK(first["tasks"][0]["scheduling_state"] == "scheduled");
    CHECK(first["tasks"][0]["next_run_at_unix_ms"] == 1750);
    const auto decoded = first.get<api::PeriodicTaskMetricsResponse>();
    REQUIRE(decoded.tasks.size() == 1U);
    CHECK(decoded.tasks[0].next_run_at_unix_ms == 1750);
    const auto after = registry.snapshot();
    REQUIRE(after.size() == 1U);
    CHECK(after[0].runs == before[0].runs);
    CHECK(after[0].failure == before[0].failure);
    CHECK(after[0].in_flight == before[0].in_flight);
    CHECK(after[0].consecutive_failures == before[0].consecutive_failures);
    CHECK(after[0].last_started_at_unix_ms == before[0].last_started_at_unix_ms);
    CHECK(after[0].last_finished_at_unix_ms == before[0].last_finished_at_unix_ms);
    CHECK(schedules[0].state == ScheduledTaskState::Scheduled);
    CHECK(schedules[0].remaining_ms == 750U);
    CHECK(active.active());
    REQUIRE(active.noop());
}

TEST_CASE("diagnostic task schedules match exact metric labels only") {
    PeriodicTaskMetricsRegistry registry({"resolver-hash-refresh"});
    struct Case {
        const char* description;
        std::vector<ScheduledTaskSnapshot> schedules;
        const char* state;
        std::optional<std::int64_t> next_run;
    };
    const std::vector<Case> cases{
        {"not observed", {}, "unknown", std::nullopt},
        {"scheduled", {{"resolver-hash-refresh", ScheduledTaskState::Scheduled,
                         700U}}, "scheduled", 1700},
        {"already due", {{"resolver-hash-refresh", ScheduledTaskState::Scheduled,
                          0U}}, "scheduled", 1000},
        {"not scheduled", {{"resolver-hash-refresh",
                            ScheduledTaskState::NotScheduled, std::nullopt}},
         "not_scheduled", std::nullopt},
        {"unknown", {{"resolver-hash-refresh", ScheduledTaskState::Unknown,
                      std::nullopt}}, "unknown", std::nullopt},
        {"missing remaining time", {{"resolver-hash-refresh",
                                     ScheduledTaskState::Scheduled, std::nullopt}},
         "unknown", std::nullopt},
        {"unknown with stray time", {{"resolver-hash-refresh",
                                      ScheduledTaskState::Unknown, 700U}},
         "unknown", std::nullopt},
        {"not scheduled with stray time", {{"resolver-hash-refresh",
                                            ScheduledTaskState::NotScheduled, 700U}},
         "not_scheduled", std::nullopt},
        {"invalid state", {{"resolver-hash-refresh",
                            static_cast<ScheduledTaskState>(99), 700U}},
         "unknown", std::nullopt},
        {"timer alias is not a metric label", {{"resolver-config-hash-actual",
                                               ScheduledTaskState::Scheduled, 700U}},
         "unknown", std::nullopt},
        {"prefix is not exact", {{"resolver-hash-refresh-extra",
                                  ScheduledTaskState::Scheduled, 700U}},
         "unknown", std::nullopt},
        {"unrelated does not hide exact", {
             {"owned-snat-health", ScheduledTaskState::Scheduled, 1U},
             {"resolver-hash-refresh", ScheduledTaskState::Scheduled, 700U}},
         "scheduled", 1700},
    };
    for (const auto& fixture : cases) {
        CAPTURE(fixture.description);
        const nlohmann::json body = build_diagnostic_tasks_response(
            registry, fixture.schedules, 1000);
        REQUIRE(body["tasks"].size() == 1U);
        const auto& task = body["tasks"][0];
        CHECK(task["label"] == "resolver-hash-refresh");
        CHECK(task["scheduling_state"] == fixture.state);
        if (fixture.next_run) {
            CHECK(task["next_run_at_unix_ms"] == *fixture.next_run);
        } else {
            CHECK(has_no_next_run(task));
        }
        CHECK(task["runs"] == 0);
        CHECK(task["in_flight"] == 0);
        CHECK(task["consecutive_failures"] == 0);
    }
}

TEST_CASE("diagnostic next-run timestamps clamp rather than wrap") {
    PeriodicTaskMetricsRegistry registry({"interface-probe"});
    constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
    struct Case {
        std::int64_t captured;
        std::uint64_t remaining;
        std::int64_t expected;
    };
    const std::vector<Case> cases{
        {1000, 0U, 1000},
        {0, 0U, 0},
        {-1000, 7U, 7},
        {std::numeric_limits<std::int64_t>::min(), 7U, 7},
        {maximum - 5, 10U, maximum},
        {maximum, 1U, maximum},
        {0, std::numeric_limits<std::uint64_t>::max(), maximum},
        {1000, std::numeric_limits<std::uint64_t>::max(), maximum},
    };
    for (const auto& fixture : cases) {
        CAPTURE(fixture.captured);
        CAPTURE(fixture.remaining);
        const nlohmann::json body = build_diagnostic_tasks_response(
            registry, {{"interface-probe", ScheduledTaskState::Scheduled,
                        fixture.remaining}}, fixture.captured);
        CHECK(body["tasks"][0]["scheduling_state"] == "scheduled");
        CHECK(body["tasks"][0]["next_run_at_unix_ms"] == fixture.expected);
    }
}

TEST_CASE("diagnostic consecutive failures reflect terminal evidence only") {
    PeriodicTaskMetricsRegistry registry({"keenetic-dns-refresh"});
    const auto consecutive_failures = [&]() {
        const nlohmann::json body = build_diagnostic_tasks_response(registry);
        REQUIRE(body["tasks"].size() == 1U);
        CHECK(body["tasks"][0]["scheduling_state"] == "unknown");
        CHECK(has_no_next_run(body["tasks"][0]));
        return body["tasks"][0]["consecutive_failures"].get<std::int64_t>();
    };
    CHECK(consecutive_failures() == 0);
    auto failed = registry.begin("keenetic-dns-refresh");
    REQUIRE(failed.failure("first failure"));
    auto failed_again = registry.begin("keenetic-dns-refresh");
    REQUIRE(failed_again.failure("second failure"));
    CHECK(consecutive_failures() == 2);
    CHECK(consecutive_failures() == 2);
    registry.record_skipped("keenetic-dns-refresh", "busy");
    CHECK(consecutive_failures() == 2);
    auto skipped = registry.begin("keenetic-dns-refresh");
    REQUIRE(skipped.skipped("not admitted"));
    CHECK(consecutive_failures() == 2);
    auto abandoned = registry.begin("keenetic-dns-refresh");
    REQUIRE(abandoned.abandon("stale generation"));
    CHECK(consecutive_failures() == 2);
    auto success = registry.begin("keenetic-dns-refresh");
    CHECK(consecutive_failures() == 2);
    REQUIRE(success.success());
    CHECK(consecutive_failures() == 0);
    auto after_recovery = registry.begin("keenetic-dns-refresh");
    REQUIRE(after_recovery.failure("new failure"));
    CHECK(consecutive_failures() == 1);
    auto noop = registry.begin("keenetic-dns-refresh");
    REQUIRE(noop.noop());
    CHECK(consecutive_failures() == 0);
}

TEST_CASE("status stream never reads pull-only task metrics") {
    SseBroadcaster broadcaster;
    auto context = make_diagnostic_tasks_context(broadcaster);
    int callback_calls = 0;
    context.get_diagnostic_tasks_fn = [&]() {
        ++callback_calls;
        api::PeriodicTaskMetricsResponse response;
        response.capacity = 0;
        response.tracked = 0;
        return response;
    };

    StatusStream stream([&]() { return build_runtime_inventory(context); });
    stream.reconcile();
    stream.reconcile();

    CHECK(callback_calls == 0);
    const nlohmann::json inventory = build_runtime_inventory(context);
    CHECK_FALSE(inventory.contains("tasks"));
    CHECK_FALSE(inventory.contains("diagnostics"));
}

} // namespace keen_pbr3

#endif // WITH_API
