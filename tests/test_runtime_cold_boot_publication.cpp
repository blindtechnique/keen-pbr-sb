#include <doctest/doctest.h>

#include "../src/daemon/runtime_cold_boot_publication.hpp"

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

struct OrderedStep final {
    std::vector<std::string>& order;
    std::string name;
    bool fail{false};

    void operator()() const {
        order.push_back(name);
        if (fail) throw std::runtime_error(name);
    }
};

std::shared_ptr<const ResolverGenerationSnapshot> generation_named(
    std::uint64_t generation,
    std::string hash) {
    auto result = std::make_shared<ResolverGenerationSnapshot>();
    result->generation = generation;
    result->expected_hash = std::move(hash);
    return result;
}

ResolverSyncCheckpoint sync_named(std::string hash, int failures) {
    ResolverSyncCheckpoint result;
    result.expected_hash = std::move(hash);
    result.actual_hash = "actual-" + result.expected_hash;
    result.actual_ts = 31;
    result.last_probe_ts = 32;
    result.apply_started_ts = 33;
    result.probe_status = api::ResolverConfigProbeStatus::SUCCESS;
    result.consecutive_probe_failures = failures;
    result.runtime_active = true;
    result.resolver_configured = true;
    return result;
}

InternalVpnServer server_named(std::string interface_name) {
    InternalVpnServer result;
    result.interface = std::move(interface_name);
    result.ndms_id = result.interface + "-id";
    result.process_clients = true;
    return result;
}

InternalVpnRuntimeResolution resolution_named(std::string interface_name) {
    InternalVpnRuntimeResolution result;
    result.state = InternalVpnRuntimeResolutionState::verified;
    result.verified_includes_for_lkg.push_back(
        server_named(std::move(interface_name)));
    return result;
}

struct ActiveCore final {
    FirewallState firewall_state;
    AppliedListContentState list_content_state;
    std::map<std::string, ListSetUsage> list_usage;
    std::map<std::string, std::string> list_fingerprints;
    InternalVpnResolutionCache internal_vpn_resolution_cache;
    ConntrackCleanupCoordinator conntrack_cleanup_coordinator;
    std::optional<std::uint32_t> meta_fwmark;
    std::uint32_t meta_owned_mask{0U};

    RuntimeFirewallCorePublicationTarget target() noexcept {
        return {
            firewall_state,
            list_content_state,
            list_usage,
            list_fingerprints,
            internal_vpn_resolution_cache,
            conntrack_cleanup_coordinator,
            meta_fwmark,
            meta_owned_mask};
    }
};

struct ResolverFixture final {
    std::shared_ptr<const ResolverGenerationSnapshot> generation{
        generation_named(1U, "base")};
    ResolverSyncStateMachine sync;
    std::uint32_t retry_attempt{7U};
    std::atomic<std::int64_t> apply_started_ts{73};

    ResolverFixture() { sync.restore(sync_named("base", 4)); }

    RuntimeResolverPublicationTarget target() noexcept {
        return {generation, sync, retry_attempt, apply_started_ts};
    }
};

} // namespace

TEST_CASE("cold-boot publication runner preserves commit order") {
    std::vector<std::string> order;

    const bool committed = detail::run_runtime_cold_boot_publication_steps(
        OrderedStep{order, "core"},
        OrderedStep{order, "restore-core"},
        OrderedStep{order, "lkg"},
        OrderedStep{order, "restore-lkg"},
        OrderedStep{order, "resolver"},
        OrderedStep{order, "restore-resolver"},
        OrderedStep{order, "activate"},
        OrderedStep{order, "rollback-runtime"},
        OrderedStep{order, "state"});

    CHECK(committed);
    CHECK(order == std::vector<std::string>{
        "core", "lkg", "resolver", "activate", "state"});
}

TEST_CASE("cold-boot publication runner restores exact completed prefix") {
    struct FailureCase final {
        std::string failed_step;
        std::vector<std::string> expected;
    };
    const std::vector<FailureCase> cases{
        {"core", {"core", "rollback-runtime", "state"}},
        {"lkg", {"core", "lkg", "rollback-runtime", "restore-core", "state"}},
        {"resolver", {"core", "lkg", "resolver", "rollback-runtime", "restore-lkg", "restore-core", "state"}},
        {"activate", {"core", "lkg", "resolver", "activate", "rollback-runtime", "restore-resolver", "restore-lkg", "restore-core", "state"}},
        {"state", {"core", "lkg", "resolver", "activate", "state", "rollback-runtime", "restore-resolver", "restore-lkg", "restore-core", "state"}},
    };

    for (const auto& failure : cases) {
        CAPTURE(failure.failed_step);
        std::vector<std::string> order;
        bool first_state = true;
        const auto step = [&order, &failure](const char* name) {
            return [&order, &failure, name]() {
                order.emplace_back(name);
                if (failure.failed_step == name) {
                    throw std::runtime_error(name);
                }
            };
        };
        const auto state = [&]() {
            order.emplace_back("state");
            if (failure.failed_step == "state" && first_state) {
                first_state = false;
                throw std::runtime_error("state");
            }
        };

        const bool committed =
            detail::run_runtime_cold_boot_publication_steps(
                step("core"),
                step("restore-core"),
                step("lkg"),
                step("restore-lkg"),
                step("resolver"),
                step("restore-resolver"),
                step("activate"),
                step("rollback-runtime"),
                state);

        CHECK_FALSE(committed);
        CHECK(order == failure.expected);
    }
}

TEST_CASE("cold-boot checkpoint publishes and restores core LKG and resolver") {
    ActiveCore core;
    core.meta_fwmark = 0x10000U;
    core.meta_owned_mask = 0xff0000U;
    RuntimeFirewallCorePublication candidate_core;
    candidate_core.prepared = true;
    candidate_core.committed = true;
    candidate_core.committed_meta_fwmark = 0x40000U;
    candidate_core.committed_meta_owned_mask = 0x0f0000U;

    ResolverFixture resolver;
    core.internal_vpn_resolution_cache.update_verified_servers(
        resolution_named("base-vpn"));
    InternalVpnServiceRuntimeResolution empty_services;
    empty_services.state = InternalVpnRuntimeResolutionState::verified;
    auto prepared = prepare_runtime_cold_boot_publication_checkpoint(
        resolver.target(),
        generation_named(2U, "candidate"),
        core.internal_vpn_resolution_cache,
        resolution_named("candidate-vpn"),
        empty_services);
    RuntimeFirewallPublicationTailProgress progress;
    bool runtime_active = false;
    int state_publications = 0;

    const bool committed = publish_runtime_cold_boot_checkpoint(
        RuntimeColdBootPublicationTarget{
            core.target(),
            candidate_core,
            resolver.target(),
            progress},
        prepared,
        [&]() { runtime_active = true; },
        [&]() { runtime_active = false; },
        [&]() { ++state_publications; });

    REQUIRE(committed);
    CHECK(runtime_active);
    CHECK(state_publications == 1);
    CHECK(progress.core_published());
    CHECK(progress.internal_vpn_lkg_published());
    CHECK(progress.start_finalized());
    CHECK(core.meta_fwmark == 0x40000U);
    CHECK(candidate_core.committed_meta_fwmark == 0x10000U);
    REQUIRE(
        core.internal_vpn_resolution_cache
                .snapshot_verified_servers()
                .size() == 1U);
    CHECK(
        core.internal_vpn_resolution_cache
                .snapshot_verified_servers()
                .front()
                .interface == "candidate-vpn");
    REQUIRE(resolver.generation);
    CHECK(resolver.generation->generation == 2U);
    CHECK(resolver.retry_attempt == 0U);
    const auto published_sync = resolver.sync.checkpoint();
    CHECK(published_sync.expected_hash == "candidate");
    CHECK(published_sync.apply_started_ts == 73);
    CHECK(published_sync.consecutive_probe_failures == 0);
}

TEST_CASE("cold-boot checkpoint rolls all published tuples back on state failure") {
    ActiveCore core;
    core.meta_fwmark = 0x10000U;
    core.meta_owned_mask = 0xff0000U;
    RuntimeFirewallCorePublication candidate_core;
    candidate_core.prepared = true;
    candidate_core.committed = true;
    candidate_core.committed_meta_fwmark = 0x40000U;
    candidate_core.committed_meta_owned_mask = 0x0f0000U;

    ResolverFixture resolver;
    const auto base_generation = resolver.generation;
    const auto base_sync = resolver.sync.checkpoint();
    core.internal_vpn_resolution_cache.update_verified_servers(
        resolution_named("base-vpn"));
    InternalVpnServiceRuntimeResolution empty_services;
    empty_services.state = InternalVpnRuntimeResolutionState::verified;
    auto prepared = prepare_runtime_cold_boot_publication_checkpoint(
        resolver.target(),
        generation_named(2U, "candidate"),
        core.internal_vpn_resolution_cache,
        resolution_named("candidate-vpn"),
        empty_services);
    RuntimeFirewallPublicationTailProgress progress;
    bool runtime_active = false;
    int state_publications = 0;

    const bool committed = publish_runtime_cold_boot_checkpoint(
        RuntimeColdBootPublicationTarget{
            core.target(),
            candidate_core,
            resolver.target(),
            progress},
        prepared,
        [&]() { runtime_active = true; },
        [&]() { runtime_active = false; },
        [&]() {
            ++state_publications;
            if (state_publications == 1) {
                throw std::runtime_error("state publication failed");
            }
        });

    CHECK_FALSE(committed);
    CHECK_FALSE(runtime_active);
    CHECK(state_publications == 2);
    CHECK_FALSE(progress.core_published());
    CHECK_FALSE(progress.internal_vpn_lkg_published());
    CHECK_FALSE(progress.start_finalized());
    CHECK(core.meta_fwmark == 0x10000U);
    CHECK(candidate_core.committed_meta_fwmark == 0x40000U);
    REQUIRE(
        core.internal_vpn_resolution_cache
                .snapshot_verified_servers()
                .size() == 1U);
    CHECK(
        core.internal_vpn_resolution_cache
                .snapshot_verified_servers()
                .front()
                .interface == "base-vpn");
    CHECK(resolver.generation == base_generation);
    CHECK(resolver.retry_attempt == 7U);
    CHECK(resolver.apply_started_ts.load(std::memory_order_acquire) == 73);
    const auto restored_sync = resolver.sync.checkpoint();
    CHECK(restored_sync.expected_hash == base_sync.expected_hash);
    CHECK(restored_sync.actual_hash == base_sync.actual_hash);
    CHECK(
        restored_sync.consecutive_probe_failures ==
        base_sync.consecutive_probe_failures);
}

} // namespace keen_pbr3
