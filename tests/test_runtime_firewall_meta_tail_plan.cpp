#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_meta_tail_plan.hpp"

#include <type_traits>
#include <utility>

namespace keen_pbr3 {

static_assert(noexcept(plan_runtime_firewall_meta_tail(
    std::declval<const RuntimeFirewallMetaTailFacts&>())));

namespace {

RuntimeFirewallMetaTailFacts committed_candidate_facts(
    const MetaUdp443ActivationPlan* candidate_plan,
    bool fastnat_healthy,
    bool filter_healthy) {
    RuntimeFirewallMetaTailFacts facts;
    facts.core_published = true;
    facts.candidate_plan = candidate_plan;
    facts.fastnat_healthy = fastnat_healthy;
    facts.filter_healthy = filter_healthy;
    return facts;
}

} // namespace

TEST_CASE("healthy Meta candidate resets the incident and schedules attempt zero") {
    MetaUdp443ActivationPlan candidate;
    const auto plan = plan_runtime_firewall_meta_tail(
        committed_candidate_facts(
            &candidate,
            /*fastnat_healthy=*/true,
            /*filter_healthy=*/true));

    CHECK(plan.cleanup_source ==
          RuntimeFirewallMetaCleanupSource::candidate);
    CHECK(plan.cleanup_plan == &candidate);
    CHECK(plan.cleanup_attempt == 0U);
    CHECK(plan.incident_action ==
          RuntimeFirewallMetaIncidentAction::reset);
    CHECK(plan.incident_detail.empty());
    CHECK_FALSE(plan.full_refresh);
}

TEST_CASE("unhealthy FastNAT schedules attempt one without a full refresh") {
    MetaUdp443ActivationPlan candidate;
    for (const bool filter_healthy : {false, true}) {
        const auto plan = plan_runtime_firewall_meta_tail(
            committed_candidate_facts(
                &candidate,
                /*fastnat_healthy=*/false,
                filter_healthy));

        CHECK(plan.cleanup_plan == &candidate);
        CHECK(plan.cleanup_attempt == 1U);
        CHECK(plan.report_degraded());
        CHECK(plan.incident_detail ==
              "FastNAT was re-enabled during delayed firewall publication");
        CHECK_FALSE(plan.full_refresh);
        CHECK(plan.refresh_detail.empty());
    }
}

TEST_CASE("unhealthy forward hook schedules attempt one and a full refresh") {
    MetaUdp443ActivationPlan candidate;
    const auto plan = plan_runtime_firewall_meta_tail(
        committed_candidate_facts(
            &candidate,
            /*fastnat_healthy=*/true,
            /*filter_healthy=*/false));

    CHECK(plan.cleanup_plan == &candidate);
    CHECK(plan.cleanup_attempt == 1U);
    CHECK(plan.report_degraded());
    CHECK(plan.incident_detail ==
          "the exact owned first FORWARD hook could not be reverified after "
          "delayed publication");
    CHECK(plan.full_refresh);
    CHECK(plan.refresh_detail ==
          "could not repair delayed Meta UDP/443 publication");
}

TEST_CASE("balanced mode with a healthy filter only resets the incident") {
    const auto plan = plan_runtime_firewall_meta_tail(
        committed_candidate_facts(
            nullptr,
            /*fastnat_healthy=*/false,
            /*filter_healthy=*/true));

    CHECK_FALSE(plan.schedule_cleanup());
    CHECK(plan.incident_action ==
          RuntimeFirewallMetaIncidentAction::reset);
    CHECK_FALSE(plan.full_refresh);
}

TEST_CASE("balanced mode with an unhealthy filter reports and refreshes") {
    const auto plan = plan_runtime_firewall_meta_tail(
        committed_candidate_facts(
            nullptr,
            /*fastnat_healthy=*/false,
            /*filter_healthy=*/false));

    CHECK_FALSE(plan.schedule_cleanup());
    CHECK(plan.report_degraded());
    CHECK(plan.incident_detail ==
          "balanced mode could not verify absence of owned UDP/443 artifacts "
          "after delayed publication");
    CHECK(plan.full_refresh);
    CHECK(plan.refresh_detail ==
          "could not clean stale balanced-mode Meta UDP/443 artifacts");
}

TEST_CASE("failed unchanged publication restores the exact previous authority") {
    MetaUdp443ActivationPlan previous;
    RuntimeFirewallMetaTailFacts facts;
    facts.previous_plan = &previous;
    facts.previous_runtime_generation = 41U;
    facts.current_runtime_generation = 41U;
    facts.previous_attempt = 3U;

    const auto plan = plan_runtime_firewall_meta_tail(facts);

    CHECK(plan.cleanup_source ==
          RuntimeFirewallMetaCleanupSource::previous);
    CHECK(plan.cleanup_plan == &previous);
    CHECK(plan.cleanup_attempt == 3U);
    CHECK(plan.incident_action ==
          RuntimeFirewallMetaIncidentAction::none);
    CHECK_FALSE(plan.full_refresh);
}

TEST_CASE("ambiguous publication discards previous authority and refreshes") {
    MetaUdp443ActivationPlan previous;
    RuntimeFirewallMetaTailFacts facts;
    facts.previous_plan = &previous;
    facts.previous_runtime_generation = 41U;
    facts.current_runtime_generation = 41U;

    for (const bool worker_commit_ambiguous : {false, true}) {
        facts.worker_commit_ambiguous = worker_commit_ambiguous;
        facts.publication_epoch_changed = !worker_commit_ambiguous;
        const auto plan = plan_runtime_firewall_meta_tail(facts);

        CHECK_FALSE(plan.schedule_cleanup());
        CHECK(plan.report_degraded());
        CHECK(plan.incident_detail ==
              "delayed firewall COMMIT outcome is ambiguous; exact Meta "
              "cleanup authority was discarded");
        CHECK(plan.full_refresh);
        CHECK(plan.refresh_detail ==
              "could not resnapshot Meta UDP/443 after an ambiguous delayed "
              "COMMIT");
    }
}

TEST_CASE("failed unchanged publication without current authority is quiet") {
    RuntimeFirewallMetaTailFacts facts;
    facts.previous_runtime_generation = 9U;
    facts.current_runtime_generation = 10U;

    const auto without_plan = plan_runtime_firewall_meta_tail(facts);
    CHECK_FALSE(without_plan.schedule_cleanup());
    CHECK(without_plan.incident_action ==
          RuntimeFirewallMetaIncidentAction::none);
    CHECK_FALSE(without_plan.full_refresh);

    MetaUdp443ActivationPlan stale_previous;
    facts.previous_plan = &stale_previous;
    const auto stale_generation = plan_runtime_firewall_meta_tail(facts);
    CHECK_FALSE(stale_generation.schedule_cleanup());
    CHECK(stale_generation.incident_action ==
          RuntimeFirewallMetaIncidentAction::none);
    CHECK_FALSE(stale_generation.full_refresh);
}

TEST_CASE("committed core ignores failure-only previous publication facts") {
    MetaUdp443ActivationPlan previous;
    RuntimeFirewallMetaTailFacts facts;
    facts.core_published = true;
    facts.filter_healthy = true;
    facts.worker_commit_ambiguous = true;
    facts.publication_epoch_changed = true;
    facts.previous_plan = &previous;
    facts.previous_runtime_generation = 7U;
    facts.current_runtime_generation = 7U;

    const auto plan = plan_runtime_firewall_meta_tail(facts);

    CHECK_FALSE(plan.schedule_cleanup());
    CHECK(plan.incident_action ==
          RuntimeFirewallMetaIncidentAction::reset);
    CHECK_FALSE(plan.full_refresh);
}

} // namespace keen_pbr3
