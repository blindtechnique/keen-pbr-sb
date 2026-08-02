#include <doctest/doctest.h>

#include "../src/daemon/resolver_health.hpp"
#include "../src/daemon/resolver_sync_state_machine.hpp"

#include <algorithm>
#include <array>

using namespace keen_pbr3;

namespace {

ResolverConfigHashProbeResult make_probe_result(ResolverConfigHashProbeStatus status,
                                                std::optional<std::int64_t> ts = std::nullopt,
                                                std::string hash = "",
                                                std::optional<std::string> raw_txt = std::nullopt) {
    ResolverConfigHashProbeResult result;
    result.status = status;
    result.parsed_value.ts = ts;
    result.parsed_value.hash = std::move(hash);
    result.raw_txt = std::move(raw_txt);
    return result;
}

} // namespace

TEST_CASE("resolver health: matching live TXT yields healthy converged state") {
    const auto probe = make_probe_result(
        ResolverConfigHashProbeStatus::SUCCESS,
        1744060805,
        "0123456789abcdef0123456789abcdef",
        "1744060805|0123456789abcdef0123456789abcdef");
    const auto state = build_resolver_actual_state(true, true, probe, 1744060806);
    CHECK(state.live_status == api::ResolverLiveStatus::HEALTHY);
    CHECK(state.last_probe_ts == std::optional<std::int64_t>{1744060806});
    CHECK(state.actual_hash == "0123456789abcdef0123456789abcdef");
    CHECK(state.actual_ts == std::optional<std::int64_t>{1744060805});
    CHECK(classify_resolver_config_sync_state(state.actual_ts, 1744060800, 1744060806, true) ==
          std::optional<api::ResolverConfigSyncState>{api::ResolverConfigSyncState::CONVERGED});
}

TEST_CASE("resolver reload is skipped only for a confirmed identical config") {
    constexpr std::string_view hash = "0123456789abcdef0123456789abcdef";
    CHECK_FALSE(resolver_reload_required(
        hash, hash, api::ResolverLiveStatus::HEALTHY));
    CHECK(resolver_reload_required(
        hash, "fedcba9876543210fedcba9876543210",
        api::ResolverLiveStatus::HEALTHY));
    CHECK(resolver_reload_required(
        hash, hash, api::ResolverLiveStatus::DEGRADED));
    CHECK(resolver_reload_required(
        "", hash, api::ResolverLiveStatus::HEALTHY));
}

TEST_CASE("resolver health: older live TXT during apply stays healthy and converging") {
    const auto probe = make_probe_result(
        ResolverConfigHashProbeStatus::SUCCESS,
        1744060800,
        "0123456789abcdef0123456789abcdef");
    const auto state = build_resolver_actual_state(true, true, probe, 1744060806);
    CHECK(state.live_status == api::ResolverLiveStatus::HEALTHY);
    CHECK(state.actual_hash == "0123456789abcdef0123456789abcdef");
    CHECK(state.actual_ts == std::optional<std::int64_t>{1744060800});
    CHECK(classify_resolver_config_sync_state(state.actual_ts, 1744060805, 1744060806, false) ==
          std::optional<api::ResolverConfigSyncState>{api::ResolverConfigSyncState::CONVERGING});
}

TEST_CASE("resolver health: query failure clears actual state and reports unavailable") {
    const auto probe = make_probe_result(ResolverConfigHashProbeStatus::QUERY_FAILED);
    const auto state = build_resolver_actual_state(true, true, probe, 1744060806);
    CHECK(state.live_status == api::ResolverLiveStatus::UNAVAILABLE);
    CHECK(state.last_probe_ts == std::optional<std::int64_t>{1744060806});
    CHECK(state.actual_hash.empty());
    CHECK_FALSE(state.actual_ts.has_value());
}

TEST_CASE("resolver health: missing or invalid TXT reports degraded") {
    const auto missing_state = build_resolver_actual_state(
        true,
        true,
        make_probe_result(ResolverConfigHashProbeStatus::NO_USABLE_TXT),
        1744060806);
    CHECK(missing_state.live_status == api::ResolverLiveStatus::DEGRADED);
    CHECK(missing_state.actual_hash.empty());
    CHECK_FALSE(missing_state.actual_ts.has_value());

    const auto invalid_state = build_resolver_actual_state(
        true,
        true,
        make_probe_result(ResolverConfigHashProbeStatus::INVALID_TXT, std::nullopt, "not-a-md5"),
        1744060807);
    CHECK(invalid_state.live_status == api::ResolverLiveStatus::DEGRADED);
    CHECK(invalid_state.actual_hash.empty());
    CHECK_FALSE(invalid_state.actual_ts.has_value());
}

TEST_CASE("resolver health: stopped runtime or missing resolver config reports unknown") {
    const auto probe = make_probe_result(
        ResolverConfigHashProbeStatus::SUCCESS,
        1744060805,
        "0123456789abcdef0123456789abcdef");
    CHECK(build_resolver_actual_state(false, true, probe, 1744060806).live_status ==
          api::ResolverLiveStatus::UNKNOWN);
    CHECK(build_resolver_actual_state(true, false, probe, 1744060806).live_status ==
          api::ResolverLiveStatus::UNKNOWN);
    CHECK(build_resolver_actual_state(true, true, std::nullopt, std::nullopt).live_status ==
          api::ResolverLiveStatus::UNKNOWN);
}

TEST_CASE("resolver sync state machine: fresh apply converges after matching TXT") {
    ResolverSyncStateMachine machine;
    machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    auto snapshot = machine.snapshot(101);
    CHECK(snapshot.sync_state ==
          std::optional<api::ResolverConfigSyncState>{api::ResolverConfigSyncState::CONVERGING});
    CHECK(snapshot.live_status == api::ResolverLiveStatus::HEALTHY);

    machine.probe_succeeded("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 101, 102);
    snapshot = machine.snapshot(102);
    CHECK(snapshot.sync_state ==
          std::optional<api::ResolverConfigSyncState>{api::ResolverConfigSyncState::CONVERGED});
    CHECK(snapshot.probe_status == api::ResolverConfigProbeStatus::SUCCESS);
    CHECK(snapshot.live_status == api::ResolverLiveStatus::HEALTHY);
}

TEST_CASE("resolver sync state machine: matching older TXT after non-DNS apply is converged") {
    ResolverSyncStateMachine machine;
    machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    machine.probe_succeeded("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 99, 101);

    const auto snapshot = machine.snapshot(101);
    CHECK(snapshot.sync_state ==
          std::optional<api::ResolverConfigSyncState>{api::ResolverConfigSyncState::CONVERGED});
    CHECK(snapshot.live_status == api::ResolverLiveStatus::HEALTHY);
}

TEST_CASE("resolver sync state machine: hash mismatch after window is stale") {
    ResolverSyncStateMachine machine;
    machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    machine.probe_succeeded("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 101, 102);

    const auto snapshot = machine.snapshot(120);
    CHECK(snapshot.sync_state ==
          std::optional<api::ResolverConfigSyncState>{api::ResolverConfigSyncState::STALE});
    CHECK(snapshot.live_status == api::ResolverLiveStatus::HEALTHY);
}

TEST_CASE("resolver sync state machine: missing or invalid TXT becomes stale not unavailable") {
    ResolverSyncStateMachine missing_machine;
    missing_machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    missing_machine.probe_failed(ResolverConfigHashProbeStatus::NO_USABLE_TXT, 120);
    auto snapshot = missing_machine.snapshot(120);
    CHECK(snapshot.sync_state ==
          std::optional<api::ResolverConfigSyncState>{api::ResolverConfigSyncState::STALE});
    CHECK(snapshot.probe_status == api::ResolverConfigProbeStatus::MISSING_TXT);
    CHECK(snapshot.live_status == api::ResolverLiveStatus::DEGRADED);

    ResolverSyncStateMachine invalid_machine;
    invalid_machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    invalid_machine.probe_failed(ResolverConfigHashProbeStatus::INVALID_TXT, 120);
    snapshot = invalid_machine.snapshot(120);
    CHECK(snapshot.sync_state ==
          std::optional<api::ResolverConfigSyncState>{api::ResolverConfigSyncState::STALE});
    CHECK(snapshot.probe_status == api::ResolverConfigProbeStatus::INVALID_TXT);
    CHECK(snapshot.live_status == api::ResolverLiveStatus::DEGRADED);
}

TEST_CASE("resolver sync state machine: missing TXT during apply stays converging") {
    ResolverSyncStateMachine machine;
    machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    machine.probe_failed(ResolverConfigHashProbeStatus::NO_USABLE_TXT, 101);

    const auto snapshot = machine.snapshot(105);
    CHECK(snapshot.sync_state ==
          std::optional<api::ResolverConfigSyncState>{api::ResolverConfigSyncState::CONVERGING});
    CHECK(snapshot.probe_status == api::ResolverConfigProbeStatus::MISSING_TXT);
    CHECK(snapshot.live_status == api::ResolverLiveStatus::HEALTHY);
}

TEST_CASE("resolver sync state machine: query failure is probe error without stale claim") {
    ResolverSyncStateMachine machine;
    machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    machine.probe_failed(ResolverConfigHashProbeStatus::QUERY_FAILED, 101);

    auto snapshot = machine.snapshot(105);
    CHECK(snapshot.sync_state ==
          std::optional<api::ResolverConfigSyncState>{api::ResolverConfigSyncState::CONVERGING});
    CHECK(snapshot.probe_status == api::ResolverConfigProbeStatus::QUERY_FAILED);

    snapshot = machine.snapshot(120);
    CHECK_FALSE(snapshot.sync_state.has_value());
    CHECK(snapshot.probe_status == api::ResolverConfigProbeStatus::QUERY_FAILED);
    CHECK(snapshot.live_status == api::ResolverLiveStatus::UNAVAILABLE);
}

TEST_CASE("resolver sync state machine: stopped or not configured is unknown") {
    ResolverSyncStateMachine stopped_machine;
    stopped_machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    stopped_machine.runtime_stopped();
    auto snapshot = stopped_machine.snapshot(120);
    CHECK_FALSE(snapshot.sync_state.has_value());
    CHECK(snapshot.probe_status == api::ResolverConfigProbeStatus::NOT_CONFIGURED);
    CHECK(snapshot.live_status == api::ResolverLiveStatus::UNKNOWN);

    ResolverSyncStateMachine missing_config_machine;
    missing_config_machine.expected_hash_updated("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    missing_config_machine.resolver_not_configured();
    snapshot = missing_config_machine.snapshot(120);
    CHECK_FALSE(snapshot.sync_state.has_value());
    CHECK(snapshot.probe_status == api::ResolverConfigProbeStatus::NOT_CONFIGURED);
    CHECK(snapshot.live_status == api::ResolverLiveStatus::UNKNOWN);
}

TEST_CASE("resolver convergence retry uses bounded exponential backoff") {
    CHECK(resolver_convergence_retry_delay(0) == std::chrono::seconds{1});
    CHECK(resolver_convergence_retry_delay(1) == std::chrono::seconds{2});
    CHECK(resolver_convergence_retry_delay(2) == std::chrono::seconds{4});
    CHECK(resolver_convergence_retry_delay(3) == std::chrono::seconds{8});
    CHECK(resolver_convergence_retry_delay(4) == std::chrono::seconds{16});
    CHECK(resolver_convergence_retry_delay(5) == std::chrono::seconds{32});
    CHECK(resolver_convergence_retry_delay(6) == std::chrono::seconds{60});
    CHECK(resolver_convergence_retry_delay(40) == std::chrono::seconds{60});
}

TEST_CASE("resolver probe commit keeps successful hash mismatch on bounded backoff") {
    ResolverSyncStateMachine machine;
    machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    auto previous = machine.snapshot(200);
    std::uint32_t attempt = 0;
    const std::array<std::chrono::seconds, 8> expected_delays{
        std::chrono::seconds{1},
        std::chrono::seconds{2},
        std::chrono::seconds{4},
        std::chrono::seconds{8},
        std::chrono::seconds{16},
        std::chrono::seconds{32},
        std::chrono::seconds{60},
        std::chrono::seconds{60},
    };

    for (std::size_t index = 0; index < expected_delays.size(); ++index) {
        machine.probe_succeeded(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 99, 201 + index);
        const auto current = machine.snapshot(201 + index);
        const auto plan =
            plan_resolver_probe_commit(previous, current, attempt);

        CHECK(current.sync_state ==
              std::optional<api::ResolverConfigSyncState>{
                  api::ResolverConfigSyncState::STALE});
        CHECK(plan.schedule_convergence_retry);
        CHECK(plan.convergence_retry_delay == expected_delays[index]);
        CHECK(plan.next_retry_attempt ==
              static_cast<std::uint32_t>(std::min<std::size_t>(index + 1, 6)));
        CHECK(plan.publish_runtime_state == (index == 0));
        CHECK(plan.report_stale_txt_observation == (index == 0));

        attempt = plan.next_retry_attempt;
        previous = current;
    }
}

TEST_CASE("resolver probe commit resets backoff only after convergence") {
    ResolverSyncStateMachine machine;
    machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    machine.probe_succeeded(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 99, 101);
    const auto mismatch = machine.snapshot(101);

    machine.probe_succeeded(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 99, 102);
    const auto converged = machine.snapshot(102);
    const auto convergence_plan =
        plan_resolver_probe_commit(mismatch, converged, 6);

    CHECK_FALSE(convergence_plan.schedule_convergence_retry);
    CHECK(convergence_plan.next_retry_attempt == 0);
    CHECK(convergence_plan.publish_runtime_state);

    machine.probe_succeeded(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 99, 103);
    const auto repeated = machine.snapshot(103);
    const auto repeated_plan =
        plan_resolver_probe_commit(converged, repeated, 0);

    CHECK_FALSE(repeated_plan.schedule_convergence_retry);
    CHECK(repeated_plan.next_retry_attempt == 0);
    CHECK_FALSE(repeated_plan.publish_runtime_state);
    CHECK_FALSE(repeated_plan.report_stale_txt_observation);
}

TEST_CASE("resolver probe commit preserves backoff across unresolved probe failures") {
    ResolverSyncStateMachine machine;
    machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    machine.probe_succeeded(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 99, 200);
    auto previous = machine.snapshot(200);

    machine.probe_failed(ResolverConfigHashProbeStatus::QUERY_FAILED, 201);
    auto unresolved = machine.snapshot(201);
    auto plan = plan_resolver_probe_commit(previous, unresolved, 3);

    CHECK(unresolved.live_status == api::ResolverLiveStatus::UNAVAILABLE);
    CHECK_FALSE(plan.schedule_convergence_retry);
    CHECK(plan.next_retry_attempt == 3);

    machine.probe_succeeded(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 99, 262);
    auto mismatch = machine.snapshot(262);
    plan = plan_resolver_probe_commit(unresolved, mismatch,
                                      plan.next_retry_attempt);

    CHECK(plan.schedule_convergence_retry);
    CHECK(plan.convergence_retry_delay == std::chrono::seconds{8});
    CHECK(plan.next_retry_attempt == 4);

    previous = mismatch;
    machine.probe_failed(ResolverConfigHashProbeStatus::INVALID_TXT, 263);
    unresolved = machine.snapshot(263);
    plan = plan_resolver_probe_commit(previous, unresolved, 4);

    CHECK(unresolved.sync_state ==
          std::optional<api::ResolverConfigSyncState>{
              api::ResolverConfigSyncState::STALE});
    CHECK_FALSE(plan.schedule_convergence_retry);
    CHECK(plan.next_retry_attempt == 4);

    machine.probe_succeeded(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 99, 324);
    mismatch = machine.snapshot(324);
    plan = plan_resolver_probe_commit(unresolved, mismatch,
                                      plan.next_retry_attempt);

    CHECK(plan.schedule_convergence_retry);
    CHECK(plan.convergence_retry_delay == std::chrono::seconds{16});
    CHECK(plan.next_retry_attempt == 5);
}

TEST_CASE("resolver semantic state ignores only probe timestamp") {
    ResolverSyncSnapshot baseline;
    baseline.expected_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    baseline.actual_hash = baseline.expected_hash;
    baseline.actual_ts = 100;
    baseline.last_probe_ts = 101;
    baseline.apply_started_ts = 99;
    baseline.sync_state = api::ResolverConfigSyncState::CONVERGED;
    baseline.probe_status = api::ResolverConfigProbeStatus::SUCCESS;
    baseline.live_status = api::ResolverLiveStatus::HEALTHY;

    auto fresh_probe = baseline;
    fresh_probe.last_probe_ts = 160;
    CHECK(resolver_sync_semantically_equal(baseline, fresh_probe));

    fresh_probe.actual_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    CHECK_FALSE(resolver_sync_semantically_equal(baseline, fresh_probe));
}

TEST_CASE("resolver sync checkpoint restores exact lifecycle state") {
    ResolverSyncStateMachine machine;
    machine.apply_started(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    machine.probe_succeeded(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 98, 101);
    machine.probe_failed(ResolverConfigHashProbeStatus::QUERY_FAILED, 102);
    const ResolverSyncCheckpoint checkpoint = machine.checkpoint();

    machine.apply_started(200, "cccccccccccccccccccccccccccccccc");
    machine.probe_failed(ResolverConfigHashProbeStatus::INVALID_TXT, 201);
    machine.runtime_stopped();
    machine.restore(checkpoint);

    const ResolverSyncCheckpoint restored = machine.checkpoint();
    CHECK(restored.expected_hash == checkpoint.expected_hash);
    CHECK(restored.actual_hash == checkpoint.actual_hash);
    CHECK(restored.actual_ts == checkpoint.actual_ts);
    CHECK(restored.last_probe_ts == checkpoint.last_probe_ts);
    CHECK(restored.apply_started_ts == checkpoint.apply_started_ts);
    CHECK(restored.probe_status == checkpoint.probe_status);
    CHECK(restored.consecutive_probe_failures ==
          checkpoint.consecutive_probe_failures);
    CHECK(restored.runtime_active == checkpoint.runtime_active);
    CHECK(restored.resolver_configured == checkpoint.resolver_configured);

    const auto snapshot = machine.snapshot(120);
    CHECK(snapshot.expected_hash == checkpoint.expected_hash);
    CHECK(snapshot.actual_hash == checkpoint.actual_hash);
    CHECK(snapshot.apply_started_ts == checkpoint.apply_started_ts);
    CHECK(machine.consecutive_probe_failures() ==
          checkpoint.consecutive_probe_failures);
}
