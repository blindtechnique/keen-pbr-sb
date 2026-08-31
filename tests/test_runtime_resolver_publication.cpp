#include <doctest/doctest.h>

#include "../src/daemon/runtime_resolver_publication.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace keen_pbr3 {
namespace {

std::shared_ptr<const ResolverGenerationSnapshot> generation_named(
    std::uint64_t generation,
    std::string expected_hash) {
    auto snapshot = std::make_shared<ResolverGenerationSnapshot>();
    snapshot->generation = generation;
    snapshot->expected_hash = std::move(expected_hash);
    return snapshot;
}

ResolverSyncCheckpoint sync_named(
    std::string expected_hash,
    int failures) {
    ResolverSyncCheckpoint checkpoint;
    checkpoint.expected_hash = std::move(expected_hash);
    checkpoint.actual_hash = "actual-" + checkpoint.expected_hash;
    checkpoint.actual_ts = 41;
    checkpoint.last_probe_ts = 42;
    checkpoint.apply_started_ts = 43;
    checkpoint.probe_status = api::ResolverConfigProbeStatus::SUCCESS;
    checkpoint.consecutive_probe_failures = failures;
    checkpoint.runtime_active = failures == 0;
    checkpoint.resolver_configured = true;
    return checkpoint;
}

void check_sync(
    const ResolverSyncStateMachine& sync,
    const std::string& expected_hash,
    int failures) {
    const auto checkpoint = sync.checkpoint();
    CHECK(checkpoint.expected_hash == expected_hash);
    CHECK(checkpoint.actual_hash == "actual-" + expected_hash);
    CHECK(checkpoint.actual_ts == 41);
    CHECK(checkpoint.last_probe_ts == 42);
    CHECK(checkpoint.apply_started_ts == 43);
    CHECK(
        checkpoint.probe_status ==
        api::ResolverConfigProbeStatus::SUCCESS);
    CHECK(checkpoint.consecutive_probe_failures == failures);
    CHECK(checkpoint.runtime_active == (failures == 0));
    CHECK(checkpoint.resolver_configured);
}

static_assert(noexcept(publish_runtime_resolver_checkpoint(
    std::declval<RuntimeResolverPublicationTarget>(),
    std::declval<RuntimeResolverPublicationSource>(),
    RuntimeResolverGenerationPublication::retain_source)));

} // namespace

TEST_CASE("DNS publication retains its prepared resolver generation source") {
    auto active_generation = generation_named(1U, "base-generation");
    auto candidate_generation = generation_named(2U, "candidate-generation");
    const auto candidate_identity = candidate_generation;
    ResolverSyncStateMachine active_sync;
    active_sync.restore(sync_named("base-sync", 0));
    auto candidate_sync = sync_named("candidate-sync", 3);
    std::uint32_t retry_attempt = 7U;
    std::atomic<std::int64_t> apply_started_ts{17};

    publish_runtime_resolver_checkpoint(
        RuntimeResolverPublicationTarget{
            active_generation,
            active_sync,
            retry_attempt,
            apply_started_ts},
        RuntimeResolverPublicationSource{
            candidate_generation,
            candidate_sync,
            0U,
            73},
        RuntimeResolverGenerationPublication::retain_source);

    CHECK(active_generation == candidate_identity);
    CHECK(candidate_generation == candidate_identity);
    check_sync(active_sync, "candidate-sync", 3);
    CHECK(retry_attempt == 0U);
    CHECK(apply_started_ts.load(std::memory_order_acquire) == 73);
}

TEST_CASE("config publication returns the old resolver generation preimage") {
    auto active_generation = generation_named(11U, "base-generation");
    const auto base_identity = active_generation;
    auto candidate_generation = generation_named(12U, "candidate-generation");
    const auto candidate_identity = candidate_generation;
    ResolverSyncStateMachine active_sync;
    active_sync.restore(sync_named("base-sync", 0));
    auto candidate_sync = sync_named("candidate-sync", 2);
    std::uint32_t retry_attempt = 9U;
    std::atomic<std::int64_t> apply_started_ts{19};

    publish_runtime_resolver_checkpoint(
        RuntimeResolverPublicationTarget{
            active_generation,
            active_sync,
            retry_attempt,
            apply_started_ts},
        RuntimeResolverPublicationSource{
            candidate_generation,
            candidate_sync,
            4U,
            83},
        RuntimeResolverGenerationPublication::exchange_preimage);

    CHECK(active_generation == candidate_identity);
    CHECK(candidate_generation == base_identity);
    check_sync(active_sync, "candidate-sync", 2);
    CHECK(retry_attempt == 4U);
    CHECK(apply_started_ts.load(std::memory_order_acquire) == 83);
}

TEST_CASE("resolver publication accepts an empty committed generation") {
    auto active_generation = generation_named(21U, "base-generation");
    std::shared_ptr<const ResolverGenerationSnapshot> empty_generation;
    ResolverSyncStateMachine active_sync;
    active_sync.restore(sync_named("base-sync", 0));
    auto stopped_sync = sync_named("stopped-sync", 1);
    std::uint32_t retry_attempt = 5U;
    std::atomic<std::int64_t> apply_started_ts{29};

    publish_runtime_resolver_checkpoint(
        RuntimeResolverPublicationTarget{
            active_generation,
            active_sync,
            retry_attempt,
            apply_started_ts},
        RuntimeResolverPublicationSource{
            empty_generation,
            stopped_sync,
            6U,
            0},
        RuntimeResolverGenerationPublication::retain_source);

    CHECK_FALSE(active_generation);
    CHECK_FALSE(empty_generation);
    check_sync(active_sync, "stopped-sync", 1);
    CHECK(retry_attempt == 6U);
    CHECK(apply_started_ts.load(std::memory_order_acquire) == 0);
}

} // namespace keen_pbr3
