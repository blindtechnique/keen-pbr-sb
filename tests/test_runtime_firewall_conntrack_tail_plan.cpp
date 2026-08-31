#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_conntrack_tail_plan.hpp"

#include <string>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {

static_assert(noexcept(plan_runtime_firewall_conntrack_tail(
    std::declval<const RuntimeFirewallConntrackTailFacts&>())));

namespace {

OwnedSnatRecovery make_repaired_snat_recovery(
    std::uint64_t runtime_generation) {
    OwnedConntrackCleanupSnapshot snapshot;
    snapshot.runtime_generation = runtime_generation;
    snapshot.owned_mask = 0x000f0000U;
    snapshot.marks = {0x00010000U, 0x00020000U};
    snapshot.priority_marks = {0x00020000U};
    snapshot.ipv6_enabled = false;

    OwnedSnatRecovery recovery;
    recovery.requested = true;
    recovery.missing_observed = true;
    recovery.cleanup_snapshot = std::move(snapshot);
    return recovery;
}

} // namespace

TEST_CASE("conntrack tail is empty without a valid worker result or repair") {
    const RuntimeFirewallConntrackTailFacts facts;

    const auto plan = plan_runtime_firewall_conntrack_tail(facts);

    CHECK_FALSE(plan.report_native_source_cleanup_failure());
    CHECK_FALSE(plan.schedule_owned_cleanup_retry());
}

TEST_CASE("conntrack tail reports only a valid worker cleanup failure") {
    RuntimeFirewallConntrackTailFacts facts;
    facts.native_source_cleanup_failure_detail = "source cleanup failed";

    CHECK_FALSE(
        plan_runtime_firewall_conntrack_tail(facts)
            .report_native_source_cleanup_failure());

    facts.native_source_cleanup_failed = true;
    const auto plan = plan_runtime_firewall_conntrack_tail(facts);
    CHECK(plan.report_native_source_cleanup_failure());
    CHECK(plan.native_source_cleanup_failure_detail ==
          "source cleanup failed");
    CHECK_FALSE(plan.schedule_owned_cleanup_retry());
}

TEST_CASE("conntrack tail retains a cleanup failure with empty detail") {
    RuntimeFirewallConntrackTailFacts facts;
    facts.native_source_cleanup_failed = true;

    const auto plan = plan_runtime_firewall_conntrack_tail(facts);

    CHECK(plan.report_native_source_cleanup_failure());
    CHECK(plan.native_source_cleanup_failure_detail.empty());
}

TEST_CASE("conntrack tail schedules the exact current repaired SNAT snapshot") {
    auto recovery = make_repaired_snat_recovery(42U);
    RuntimeFirewallConntrackTailFacts facts;
    facts.worker_succeeded = true;
    facts.processed_snat_recovery = &recovery;
    facts.inspected_snat_after = OwnedSnatState::healthy;
    facts.current_runtime_generation = 42U;

    const auto plan = plan_runtime_firewall_conntrack_tail(facts);

    REQUIRE(plan.schedule_owned_cleanup_retry());
    CHECK(plan.cleanup_retry_snapshot == &*recovery.cleanup_snapshot);
    CHECK(plan.cleanup_retry_snapshot->marks ==
          recovery.cleanup_snapshot->marks);
    CHECK(plan.cleanup_retry_snapshot->priority_marks ==
          recovery.cleanup_snapshot->priority_marks);
}

TEST_CASE("conntrack tail suppresses cleanup without every existing proof") {
    auto recovery = make_repaired_snat_recovery(7U);
    RuntimeFirewallConntrackTailFacts facts;
    facts.worker_succeeded = true;
    facts.processed_snat_recovery = &recovery;
    facts.inspected_snat_after = OwnedSnatState::healthy;
    facts.current_runtime_generation = 7U;

    facts.worker_succeeded = false;
    CHECK_FALSE(plan_runtime_firewall_conntrack_tail(facts)
                    .schedule_owned_cleanup_retry());
    facts.worker_succeeded = true;

    recovery.requested = false;
    CHECK_FALSE(plan_runtime_firewall_conntrack_tail(facts)
                    .schedule_owned_cleanup_retry());
    recovery.requested = true;

    recovery.missing_observed = false;
    CHECK_FALSE(plan_runtime_firewall_conntrack_tail(facts)
                    .schedule_owned_cleanup_retry());
    recovery.missing_observed = true;

    facts.inspected_snat_after = OwnedSnatState::unknown;
    CHECK_FALSE(plan_runtime_firewall_conntrack_tail(facts)
                    .schedule_owned_cleanup_retry());
    facts.inspected_snat_after = OwnedSnatState::healthy;

    facts.current_runtime_generation = 8U;
    CHECK_FALSE(plan_runtime_firewall_conntrack_tail(facts)
                    .schedule_owned_cleanup_retry());
    facts.current_runtime_generation = 7U;

    recovery.cleanup_snapshot.reset();
    CHECK_FALSE(plan_runtime_firewall_conntrack_tail(facts)
                    .schedule_owned_cleanup_retry());
}

TEST_CASE("conntrack tail can report and schedule in the same terminal") {
    auto recovery = make_repaired_snat_recovery(11U);

    RuntimeFirewallConntrackTailFacts facts;
    facts.native_source_cleanup_failed = true;
    facts.native_source_cleanup_failure_detail =
        "cleanup status unknown";
    facts.worker_succeeded = true;
    facts.processed_snat_recovery = &recovery;
    facts.inspected_snat_after = OwnedSnatState::healthy;
    facts.current_runtime_generation = 11U;

    const auto plan = plan_runtime_firewall_conntrack_tail(facts);
    CHECK(plan.report_native_source_cleanup_failure());
    CHECK(plan.schedule_owned_cleanup_retry());
}

} // namespace keen_pbr3
