#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_generation_input.hpp"

#include <memory>
#include <set>
#include <string>
#include <utility>

using namespace keen_pbr3;

TEST_CASE(
    "runtime firewall generation builder derives route identity from the transaction") {
    RuntimeFirewallGenerationSnapshot snapshot;
    snapshot.operation_kind =
        RuntimeFirewallWorkerOperationKind::config_preapply;
    snapshot.transaction.operation_serial = 41U;
    snapshot.transaction.runtime_generation = 73U;
    snapshot.transaction.config.daemon = DaemonConfig{};
    snapshot.transaction.config.daemon->max_file_size_bytes = 123456;
    snapshot.transaction.outbound_marks = {
        {"candidate-outbound", 0x00030000U}};
    snapshot.transaction.urltest_selections = {
        {"candidate-selector", "candidate-child"}};
    snapshot.transaction.requested_list_fingerprints = {
        {"candidate-list", "candidate-fingerprint"}};
    snapshot.transaction.previous_list_fingerprints = {
        {"published-list", "published-fingerprint"}};

    snapshot.route.route_epoch = 97U;
    snapshot.route.reconcile_mode = RouteReconcileMode::Strict;
    auto checkpoint_owner = std::make_shared<int>(1);
    std::shared_ptr<RuntimeRouteMutationCheckpoint> checkpoint(
        checkpoint_owner, nullptr);
    snapshot.route.mutation_checkpoint = checkpoint;

    snapshot.cleanup.inspect_owned_snat = true;
    snapshot.cleanup.mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    snapshot.cleanup.pre_mutation_owned_conntrack_cleanup_snapshot =
        OwnedConntrackCleanupSnapshot{
            73U,
            0x00FF0000U,
            {0x00030000U, 0x00070000U},
            {0x00030000U},
            true};
    snapshot.cleanup.mandatory_owned_conntrack_cleanup_snapshot =
        OwnedConntrackCleanupSnapshot{
            73U,
            0x00FF0000U,
            {0x00070000U},
            {},
            false};

    const auto input = make_runtime_firewall_worker_attempt_input(
        std::move(snapshot));

    CHECK(input.operation_kind ==
          RuntimeFirewallWorkerOperationKind::config_preapply);
    CHECK(input.transaction.operation_serial == 41U);
    CHECK(input.transaction.runtime_generation == 73U);
    REQUIRE(input.transaction.config.daemon.has_value());
    CHECK(input.transaction.config.daemon->max_file_size_bytes == 123456);
    CHECK(input.transaction.outbound_marks.at("candidate-outbound") ==
          0x00030000U);
    CHECK(input.transaction.requested_list_fingerprints.at(
              "candidate-list") == "candidate-fingerprint");
    CHECK(input.transaction.previous_list_fingerprints.at(
              "published-list") == "published-fingerprint");

    CHECK(input.route_health_request.operation_serial == 41U);
    CHECK(input.route_health_request.runtime_generation == 73U);
    CHECK(input.route_health_request.route_epoch == 97U);
    REQUIRE(input.route_health_request.config.daemon.has_value());
    CHECK(input.route_health_request.config.daemon->max_file_size_bytes ==
          123456);
    CHECK(input.route_health_request.outbound_marks.at(
              "candidate-outbound") == 0x00030000U);
    CHECK(input.route_health_request.urltest_selections.at(
              "candidate-selector") == "candidate-child");
    CHECK(input.route_reconcile_mode == RouteReconcileMode::Strict);
    CHECK_FALSE(checkpoint.owner_before(input.route_mutation_checkpoint));
    CHECK_FALSE(input.route_mutation_checkpoint.owner_before(checkpoint));

    CHECK(input.inspect_owned_snat);
    CHECK(input.owned_conntrack_cleanup_mode ==
          RuntimeFirewallOwnedConntrackCleanupMode::
              exact_pre_mutation_snapshot);
    REQUIRE(input.pre_mutation_owned_conntrack_cleanup_snapshot.has_value());
    CHECK((input.pre_mutation_owned_conntrack_cleanup_snapshot->marks ==
           std::set<std::uint32_t>{0x00030000U, 0x00070000U}));
    REQUIRE(input.mandatory_owned_conntrack_cleanup_snapshot.has_value());
    CHECK((input.mandatory_owned_conntrack_cleanup_snapshot->marks ==
           std::set<std::uint32_t>{0x00070000U}));
}

TEST_CASE(
    "runtime firewall generation builder never invents route or cleanup authority") {
    RuntimeFirewallGenerationSnapshot snapshot;
    snapshot.transaction.operation_serial = 5U;
    snapshot.transaction.runtime_generation = 9U;
    snapshot.transaction.outbound_marks = {{"only", 0x00010000U}};

    const auto input = make_runtime_firewall_worker_attempt_input(
        std::move(snapshot));

    CHECK(input.route_health_request.operation_serial == 5U);
    CHECK(input.route_health_request.runtime_generation == 9U);
    CHECK(input.route_health_request.route_epoch == 0U);
    CHECK(input.route_health_request.outbound_marks.at("only") ==
          0x00010000U);
    CHECK(input.route_reconcile_mode == RouteReconcileMode::DeferredRepair);
    CHECK_FALSE(input.route_mutation_checkpoint);
    CHECK_FALSE(input.inspect_owned_snat);
    CHECK_FALSE(
        input.pre_mutation_owned_conntrack_cleanup_snapshot.has_value());
    CHECK_FALSE(
        input.mandatory_owned_conntrack_cleanup_snapshot.has_value());
    CHECK(input.owned_conntrack_cleanup_mode ==
          RuntimeFirewallOwnedConntrackCleanupMode::none);
}

TEST_CASE(
    "candidate and rollback generation snapshots keep inverse preimages isolated") {
    RuntimeFirewallGenerationSnapshot candidate;
    candidate.transaction.operation_serial = 101U;
    candidate.transaction.runtime_generation = 12U;
    candidate.transaction.config.daemon = DaemonConfig{};
    candidate.transaction.config.daemon->max_file_size_bytes = 1200;
    candidate.transaction.outbound_marks = {
        {"candidate-outbound", 0x00090000U}};
    candidate.transaction.urltest_selections = {
        {"candidate-group", "candidate-child"}};
    candidate.transaction.requested_list_fingerprints = {
        {"policy", "candidate-body"}};
    candidate.transaction.previous_list_fingerprints = {
        {"policy", "published-body"}};
    candidate.transaction
        .candidate_native_vpn_direct_egress_snat_selectors = {
            FirewallSourceEgressSnatSelector{
                "candidate-egress", "10.90.0.0/24"}};
    candidate.transaction
        .previous_native_vpn_direct_egress_snat_selectors = {
            FirewallSourceEgressSnatSelector{
                "published-egress", "10.30.0.0/24"}};
    candidate.route.route_epoch = 201U;
    auto candidate_checkpoint_owner = std::make_shared<int>(1);
    std::shared_ptr<RuntimeRouteMutationCheckpoint> candidate_checkpoint(
        candidate_checkpoint_owner, nullptr);
    candidate.route.mutation_checkpoint = candidate_checkpoint;
    candidate.cleanup.inspect_owned_snat = true;
    candidate.cleanup.mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    candidate.cleanup.pre_mutation_owned_conntrack_cleanup_snapshot =
        OwnedConntrackCleanupSnapshot{
            11U,
            0x00FF0000U,
            {0x00030000U},
            {},
            true};

    RuntimeFirewallGenerationSnapshot rollback;
    rollback.transaction.operation_serial = 102U;
    rollback.transaction.runtime_generation = 13U;
    rollback.transaction.config.daemon = DaemonConfig{};
    rollback.transaction.config.daemon->max_file_size_bytes = 300;
    rollback.transaction.outbound_marks = {
        {"published-outbound", 0x00030000U}};
    rollback.transaction.urltest_selections = {
        {"published-group", "published-child"}};
    rollback.transaction.requested_list_fingerprints = {
        {"policy", "published-body"}};
    rollback.transaction.previous_list_fingerprints = {
        {"policy", "candidate-body"}};
    rollback.transaction
        .candidate_native_vpn_direct_egress_snat_selectors = {
            FirewallSourceEgressSnatSelector{
                "published-egress", "10.30.0.0/24"}};
    rollback.transaction
        .previous_native_vpn_direct_egress_snat_selectors = {
            FirewallSourceEgressSnatSelector{
                "candidate-egress", "10.90.0.0/24"}};
    rollback.route.route_epoch = 202U;
    auto rollback_checkpoint_owner = std::make_shared<int>(2);
    std::shared_ptr<RuntimeRouteMutationCheckpoint> rollback_checkpoint(
        rollback_checkpoint_owner, nullptr);
    rollback.route.mutation_checkpoint = rollback_checkpoint;
    rollback.cleanup.inspect_owned_snat = true;
    rollback.cleanup.mode =
        RuntimeFirewallOwnedConntrackCleanupMode::
            exact_pre_mutation_snapshot;
    rollback.cleanup.pre_mutation_owned_conntrack_cleanup_snapshot =
        OwnedConntrackCleanupSnapshot{
            12U,
            0x00FF0000U,
            {0x00090000U},
            {},
            false};

    const auto candidate_input =
        make_runtime_firewall_worker_attempt_input(std::move(candidate));
    const auto rollback_input =
        make_runtime_firewall_worker_attempt_input(std::move(rollback));

    REQUIRE(candidate_input.route_health_request.config.daemon.has_value());
    CHECK(candidate_input.route_health_request.config.daemon
              ->max_file_size_bytes == 1200);
    CHECK(candidate_input.route_health_request.outbound_marks.at(
              "candidate-outbound") == 0x00090000U);
    CHECK(candidate_input.route_health_request.urltest_selections.at(
              "candidate-group") == "candidate-child");
    CHECK(candidate_input.route_health_request.operation_serial ==
          candidate_input.transaction.operation_serial);
    CHECK(candidate_input.route_health_request.runtime_generation ==
          candidate_input.transaction.runtime_generation);
    CHECK(candidate_input.transaction.requested_list_fingerprints.at(
              "policy") == "candidate-body");
    CHECK(candidate_input.transaction.previous_list_fingerprints.at(
              "policy") == "published-body");
    REQUIRE(candidate_input.transaction
                .candidate_native_vpn_direct_egress_snat_selectors.size() ==
            1U);
    CHECK(candidate_input.transaction
              .candidate_native_vpn_direct_egress_snat_selectors.front()
              .interface == "candidate-egress");
    REQUIRE(candidate_input.transaction
                .previous_native_vpn_direct_egress_snat_selectors.size() ==
            1U);
    CHECK(candidate_input.transaction
              .previous_native_vpn_direct_egress_snat_selectors.front()
              .interface == "published-egress");

    REQUIRE(rollback_input.route_health_request.config.daemon.has_value());
    CHECK(rollback_input.route_health_request.config.daemon
              ->max_file_size_bytes == 300);
    CHECK(rollback_input.route_health_request.outbound_marks.at(
              "published-outbound") == 0x00030000U);
    CHECK(rollback_input.route_health_request.urltest_selections.at(
              "published-group") == "published-child");
    CHECK(rollback_input.route_health_request.operation_serial ==
          rollback_input.transaction.operation_serial);
    CHECK(rollback_input.route_health_request.runtime_generation ==
          rollback_input.transaction.runtime_generation);
    CHECK(rollback_input.transaction.requested_list_fingerprints.at(
              "policy") == "published-body");
    CHECK(rollback_input.transaction.previous_list_fingerprints.at(
              "policy") == "candidate-body");
    REQUIRE(rollback_input.transaction
                .candidate_native_vpn_direct_egress_snat_selectors.size() ==
            1U);
    CHECK(rollback_input.transaction
              .candidate_native_vpn_direct_egress_snat_selectors.front()
              .interface == "published-egress");
    REQUIRE(rollback_input.transaction
                .previous_native_vpn_direct_egress_snat_selectors.size() ==
            1U);
    CHECK(rollback_input.transaction
              .previous_native_vpn_direct_egress_snat_selectors.front()
              .interface == "candidate-egress");

    CHECK_FALSE(candidate_checkpoint.owner_before(
        candidate_input.route_mutation_checkpoint));
    CHECK_FALSE(candidate_input.route_mutation_checkpoint.owner_before(
        candidate_checkpoint));
    const bool distinct_checkpoint_owners =
        candidate_checkpoint.owner_before(
            rollback_input.route_mutation_checkpoint) ||
        rollback_input.route_mutation_checkpoint.owner_before(
            candidate_checkpoint);
    CHECK(distinct_checkpoint_owners);
    REQUIRE(candidate_input
                .pre_mutation_owned_conntrack_cleanup_snapshot.has_value());
    REQUIRE(rollback_input
                .pre_mutation_owned_conntrack_cleanup_snapshot.has_value());
    CHECK(candidate_input
              .pre_mutation_owned_conntrack_cleanup_snapshot->marks.count(
                  0x00030000U) == 1U);
    CHECK(candidate_input
              .pre_mutation_owned_conntrack_cleanup_snapshot->marks.count(
                  0x00090000U) == 0U);
    CHECK(rollback_input
              .pre_mutation_owned_conntrack_cleanup_snapshot->marks.count(
                  0x00090000U) == 1U);
    CHECK(rollback_input
              .pre_mutation_owned_conntrack_cleanup_snapshot->marks.count(
                  0x00030000U) == 0U);
}
