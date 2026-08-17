#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_reconcile_barrier.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>

namespace keen_pbr3 {
namespace {

NdmsCatalogSnapshot authoritative_baseline(
    const std::uint64_t generation = 7U,
    const std::uint64_t epoch = 11U) {
    NdmsCatalogSnapshot snapshot;
    snapshot.status = NdmsCatalogCacheStatus::fresh;
    snapshot.observation_generation = generation;
    snapshot.observation_epoch = epoch;
    snapshot.invalidation_epoch = epoch;
    return snapshot;
}

NdmsNativeReconcileCatalogEvidence catalog_evidence(
    const NdmsNativeReconcileTicket& ticket,
    const std::uint64_t observation_generation = 8U,
    const std::uint64_t observation_epoch = 12U) {
    return NdmsNativeReconcileCatalogEvidence{
        ticket.serial,
        ticket.expected_runtime_generation,
        true,
        NdmsCatalogCacheStatus::fresh,
        observation_generation,
        observation_epoch,
        observation_epoch,
        true,
    };
}

NdmsNativeReconcileFirewallEvidence firewall_evidence(
    const NdmsNativeReconcileTicket& ticket,
    const std::uint64_t observation_generation = 8U,
    const std::uint64_t observation_epoch = 12U) {
    return NdmsNativeReconcileFirewallEvidence{
        ticket.serial,
        ticket.expected_runtime_generation,
        true,
        observation_generation,
        observation_epoch,
        true,
    };
}

bool has_blocker(
    const NdmsNativeReconcileBarrierSnapshot& snapshot,
    const NdmsNativeReconcileBarrierBlocker blocker) {
    return std::find(
               snapshot.blockers.begin(),
               snapshot.blockers.end(),
               blocker) != snapshot.blockers.end();
}

} // namespace

TEST_CASE("native reconcile barrier is dormant and permanently preview-only") {
    NdmsNativeReconcileBarrier barrier;
    const auto snapshot = barrier.snapshot();

    CHECK(snapshot.state == NdmsNativeReconcileBarrierState::dormant);
    CHECK_FALSE(snapshot.apply_available);
    CHECK_FALSE(snapshot.ticket.has_value());
    CHECK(has_blocker(
        snapshot,
        NdmsNativeReconcileBarrierBlocker::mutation_release_disabled));
    CHECK(has_blocker(
        snapshot,
        NdmsNativeReconcileBarrierBlocker::allocator_range_unfenced));
}

TEST_CASE("native reconcile barrier arms only from an authoritative baseline") {
    NdmsNativeReconcileBarrier barrier;
    auto invalid = authoritative_baseline();

    invalid.status = NdmsCatalogCacheStatus::stale;
    CHECK_FALSE(barrier.arm(17U, invalid).has_value());
    invalid = authoritative_baseline();
    invalid.observation_epoch = invalid.invalidation_epoch - 1U;
    CHECK_FALSE(barrier.arm(17U, invalid).has_value());
    invalid = authoritative_baseline();
    invalid.observation_generation = 0U;
    CHECK_FALSE(barrier.arm(17U, invalid).has_value());
    CHECK_FALSE(barrier.arm(0U, authoritative_baseline()).has_value());

    const auto armed = barrier.arm(17U, authoritative_baseline());
    REQUIRE(armed.has_value());
    CHECK(armed->valid());
    CHECK(armed->baseline_observation_generation == 7U);
    CHECK(armed->required_invalidation_epoch == 12U);
    const auto snapshot = barrier.snapshot();
    CHECK(snapshot.state ==
          NdmsNativeReconcileBarrierState::awaiting_catalog);
    CHECK_FALSE(snapshot.apply_available);
}

TEST_CASE("native reconcile barrier requires a new current-epoch catalog") {
    NdmsNativeReconcileBarrier barrier;
    const auto ticket = barrier.arm(17U, authoritative_baseline());
    REQUIRE(ticket.has_value());

    auto stale = catalog_evidence(*ticket);
    stale.status = NdmsCatalogCacheStatus::stale;
    CHECK(barrier.observe_catalog(stale) ==
          NdmsNativeReconcileBarrierTransition::no_change);
    CHECK(has_blocker(
        barrier.snapshot(),
        NdmsNativeReconcileBarrierBlocker::catalog_not_fresh));

    auto old_generation = catalog_evidence(*ticket);
    old_generation.observation_generation =
        ticket->baseline_observation_generation;
    CHECK(barrier.observe_catalog(old_generation) ==
          NdmsNativeReconcileBarrierTransition::no_change);

    auto old_epoch = catalog_evidence(*ticket);
    old_epoch.observation_epoch =
        ticket->required_invalidation_epoch - 1U;
    old_epoch.invalidation_epoch =
        ticket->required_invalidation_epoch;
    CHECK(barrier.observe_catalog(old_epoch) ==
          NdmsNativeReconcileBarrierTransition::no_change);

    auto target_pending = catalog_evidence(*ticket);
    target_pending.exact_target_verified = false;
    CHECK(barrier.observe_catalog(target_pending) ==
          NdmsNativeReconcileBarrierTransition::no_change);
    CHECK(has_blocker(
        barrier.snapshot(),
        NdmsNativeReconcileBarrierBlocker::
            target_post_state_unverified));

    // More than one invalidation is allowed, but the accepted observation
    // must belong to the exact current epoch.
    const auto current = catalog_evidence(*ticket, 9U, 13U);
    CHECK(barrier.observe_catalog(current) ==
          NdmsNativeReconcileBarrierTransition::catalog_accepted);
    const auto snapshot = barrier.snapshot();
    CHECK(snapshot.state ==
          NdmsNativeReconcileBarrierState::awaiting_firewall);
    CHECK(snapshot.accepted_observation_generation == 9U);
    CHECK(snapshot.accepted_observation_epoch == 13U);

    const auto late_older = catalog_evidence(*ticket, 8U, 12U);
    CHECK(barrier.observe_catalog(late_older) ==
          NdmsNativeReconcileBarrierTransition::no_change);
    CHECK(barrier.snapshot().accepted_observation_generation == 9U);
}

TEST_CASE("native reconcile barrier binds firewall commit to the catalog pair") {
    NdmsNativeReconcileBarrier barrier;
    const auto ticket = barrier.arm(17U, authoritative_baseline());
    REQUIRE(ticket.has_value());
    REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket)) ==
            NdmsNativeReconcileBarrierTransition::catalog_accepted);

    auto not_committed = firewall_evidence(*ticket);
    not_committed.committed = false;
    CHECK(barrier.observe_firewall(not_committed) ==
          NdmsNativeReconcileBarrierTransition::no_change);

    auto wrong_generation = firewall_evidence(*ticket);
    ++wrong_generation.observation_generation;
    CHECK(barrier.observe_firewall(wrong_generation) ==
          NdmsNativeReconcileBarrierTransition::no_change);

    auto wrong_epoch = firewall_evidence(*ticket);
    ++wrong_epoch.observation_epoch;
    CHECK(barrier.observe_firewall(wrong_epoch) ==
          NdmsNativeReconcileBarrierTransition::no_change);

    CHECK(barrier.observe_firewall(firewall_evidence(*ticket)) ==
          NdmsNativeReconcileBarrierTransition::converged);
    const auto snapshot = barrier.snapshot();
    CHECK(snapshot.state == NdmsNativeReconcileBarrierState::converged);
    CHECK_FALSE(snapshot.apply_available);
    CHECK(barrier.observe_firewall(firewall_evidence(*ticket)) ==
          NdmsNativeReconcileBarrierTransition::no_change);
}

TEST_CASE("native reconcile barrier never accepts an older catalog after its pair is cleared") {
    SUBCASE("a stale cache observation cannot reopen an older generation") {
        NdmsNativeReconcileBarrier barrier;
        const auto ticket = barrier.arm(17U, authoritative_baseline());
        REQUIRE(ticket.has_value());
        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 9U, 13U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);

        auto stale = catalog_evidence(*ticket, 9U, 13U);
        stale.status = NdmsCatalogCacheStatus::stale;
        CHECK(barrier.observe_catalog(stale) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.snapshot().state ==
              NdmsNativeReconcileBarrierState::awaiting_catalog);
        CHECK(barrier.snapshot().accepted_observation_generation == 0U);

        CHECK(barrier.observe_catalog(catalog_evidence(*ticket, 8U, 12U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 8U, 12U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.snapshot().state ==
              NdmsNativeReconcileBarrierState::awaiting_catalog);

        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 10U, 14U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 10U, 14U)) ==
              NdmsNativeReconcileBarrierTransition::converged);
    }

    SUBCASE("an unverified newer target cannot reopen an older generation") {
        NdmsNativeReconcileBarrier barrier;
        const auto ticket = barrier.arm(17U, authoritative_baseline());
        REQUIRE(ticket.has_value());
        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 9U, 13U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);

        auto unverified = catalog_evidence(*ticket, 10U, 14U);
        unverified.exact_target_verified = false;
        CHECK(barrier.observe_catalog(unverified) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.snapshot().state ==
              NdmsNativeReconcileBarrierState::awaiting_catalog);

        CHECK(barrier.observe_catalog(catalog_evidence(*ticket, 8U, 12U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 8U, 12U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 10U, 14U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 10U, 14U)) ==
              NdmsNativeReconcileBarrierTransition::converged);
    }

    SUBCASE("a stale newer cache version revokes the older accepted pair") {
        NdmsNativeReconcileBarrier barrier;
        const auto ticket = barrier.arm(17U, authoritative_baseline());
        REQUIRE(ticket.has_value());
        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 9U, 13U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);

        auto stale_newer = catalog_evidence(*ticket, 10U, 14U);
        stale_newer.status = NdmsCatalogCacheStatus::stale;
        stale_newer.invalidation_epoch = 15U;
        CHECK(barrier.observe_catalog(stale_newer) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        CHECK(barrier.observe_catalog(catalog_evidence(*ticket, 9U, 13U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 9U, 13U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.snapshot().state ==
              NdmsNativeReconcileBarrierState::awaiting_catalog);

        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 11U, 15U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 11U, 15U)) ==
              NdmsNativeReconcileBarrierTransition::converged);
    }

    SUBCASE("a newer invalidation revokes an unverified same-pair recheck") {
        NdmsNativeReconcileBarrier barrier;
        const auto ticket = barrier.arm(17U, authoritative_baseline());
        REQUIRE(ticket.has_value());

        auto unverified = catalog_evidence(*ticket, 9U, 13U);
        unverified.exact_target_verified = false;
        CHECK(barrier.observe_catalog(unverified) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        auto stale_invalidated = catalog_evidence(*ticket, 9U, 13U);
        stale_invalidated.status = NdmsCatalogCacheStatus::stale;
        stale_invalidated.invalidation_epoch = 14U;
        CHECK(barrier.observe_catalog(stale_invalidated) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        CHECK(barrier.observe_catalog(catalog_evidence(*ticket, 9U, 13U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 9U, 13U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 10U, 14U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 10U, 14U)) ==
              NdmsNativeReconcileBarrierTransition::converged);
    }

    SUBCASE("an invalidation also blocks a later unverified old-pair replay") {
        NdmsNativeReconcileBarrier barrier;
        const auto ticket = barrier.arm(17U, authoritative_baseline());
        REQUIRE(ticket.has_value());
        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 9U, 13U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);

        auto stale_invalidated = catalog_evidence(*ticket, 9U, 13U);
        stale_invalidated.status = NdmsCatalogCacheStatus::stale;
        stale_invalidated.invalidation_epoch = 14U;
        CHECK(barrier.observe_catalog(stale_invalidated) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        auto replayed_unverified = catalog_evidence(*ticket, 9U, 13U);
        replayed_unverified.exact_target_verified = false;
        CHECK(barrier.observe_catalog(replayed_unverified) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.observe_catalog(catalog_evidence(*ticket, 9U, 13U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 9U, 13U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 10U, 14U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);
    }

    SUBCASE("a status-only stale result permanently revokes its retained pair") {
        NdmsNativeReconcileBarrier barrier;
        const auto ticket = barrier.arm(17U, authoritative_baseline());
        REQUIRE(ticket.has_value());
        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 9U, 13U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);

        auto stale_same_pair = catalog_evidence(*ticket, 9U, 13U);
        stale_same_pair.status = NdmsCatalogCacheStatus::stale;
        CHECK(barrier.observe_catalog(stale_same_pair) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        auto replayed_unverified = catalog_evidence(*ticket, 9U, 13U);
        replayed_unverified.exact_target_verified = false;
        CHECK(barrier.observe_catalog(replayed_unverified) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.observe_catalog(catalog_evidence(*ticket, 9U, 13U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 9U, 13U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 10U, 13U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);
    }

    SUBCASE("status-only stale also revokes an initially unverified pair") {
        NdmsNativeReconcileBarrier barrier;
        const auto ticket = barrier.arm(17U, authoritative_baseline());
        REQUIRE(ticket.has_value());

        auto unverified = catalog_evidence(*ticket, 9U, 13U);
        unverified.exact_target_verified = false;
        CHECK(barrier.observe_catalog(unverified) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        auto stale_same_pair = catalog_evidence(*ticket, 9U, 13U);
        stale_same_pair.status = NdmsCatalogCacheStatus::stale;
        CHECK(barrier.observe_catalog(stale_same_pair) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.observe_catalog(catalog_evidence(*ticket, 9U, 13U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);
        CHECK(barrier.observe_firewall(firewall_evidence(*ticket, 9U, 13U)) ==
              NdmsNativeReconcileBarrierTransition::no_change);

        REQUIRE(barrier.observe_catalog(catalog_evidence(*ticket, 10U, 13U)) ==
                NdmsNativeReconcileBarrierTransition::catalog_accepted);
    }
}

TEST_CASE("native reconcile barrier rejects a changed runtime generation") {
    NdmsNativeReconcileBarrier barrier;
    const auto ticket = barrier.arm(17U, authoritative_baseline());
    REQUIRE(ticket.has_value());

    auto catalog = catalog_evidence(*ticket);
    catalog.runtime_generation = 18U;
    CHECK(barrier.observe_catalog(catalog) ==
          NdmsNativeReconcileBarrierTransition::stale);
    const auto snapshot = barrier.snapshot();
    CHECK(snapshot.state == NdmsNativeReconcileBarrierState::stale);
    CHECK(has_blocker(
        snapshot,
        NdmsNativeReconcileBarrierBlocker::runtime_generation_changed));
    CHECK_FALSE(snapshot.apply_available);
}

TEST_CASE("native reconcile barrier ignores every old-ticket completion") {
    NdmsNativeReconcileBarrier barrier;
    const auto first = barrier.arm(17U, authoritative_baseline());
    REQUIRE(first.has_value());
    const auto second = barrier.arm(17U, authoritative_baseline(9U, 13U));
    REQUIRE(second.has_value());
    REQUIRE(second->serial != first->serial);

    CHECK(barrier.observe_catalog(catalog_evidence(*first)) ==
          NdmsNativeReconcileBarrierTransition::no_change);
    CHECK(barrier.observe_firewall(firewall_evidence(*first)) ==
          NdmsNativeReconcileBarrierTransition::no_change);
    CHECK(barrier.fail(first->serial) ==
          NdmsNativeReconcileBarrierTransition::no_change);
    CHECK(barrier.supersede(first->serial) ==
          NdmsNativeReconcileBarrierTransition::no_change);
    CHECK(barrier.snapshot().ticket->serial == second->serial);

    const auto second_catalog = catalog_evidence(*second, 10U, 14U);
    CHECK(barrier.observe_catalog(second_catalog) ==
          NdmsNativeReconcileBarrierTransition::catalog_accepted);
}

TEST_CASE("native reconcile barrier exact terminal transitions do not cross tickets") {
    NdmsNativeReconcileBarrier barrier;
    const auto failed = barrier.arm(17U, authoritative_baseline());
    REQUIRE(failed.has_value());
    CHECK(barrier.fail(failed->serial) ==
          NdmsNativeReconcileBarrierTransition::failed);
    CHECK(barrier.snapshot().state ==
          NdmsNativeReconcileBarrierState::failed);

    const auto superseded = barrier.arm(
        18U, authoritative_baseline(9U, 13U));
    REQUIRE(superseded.has_value());
    CHECK(barrier.supersede(superseded->serial) ==
          NdmsNativeReconcileBarrierTransition::stale);
    CHECK(has_blocker(
        barrier.snapshot(),
        NdmsNativeReconcileBarrierBlocker::ticket_superseded));
}

TEST_CASE("native reconcile ticket serial reserves zero across wrap") {
    CHECK(next_ndms_native_reconcile_ticket_serial(0U) == 1U);
    CHECK(next_ndms_native_reconcile_ticket_serial(
              std::numeric_limits<std::uint64_t>::max()) == 1U);
}

} // namespace keen_pbr3
