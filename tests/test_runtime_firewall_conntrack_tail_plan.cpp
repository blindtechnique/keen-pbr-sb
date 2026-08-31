#include <doctest/doctest.h>

#include "../src/daemon/runtime_firewall_conntrack_tail_plan.hpp"

#include <string>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {

static_assert(noexcept(plan_runtime_firewall_conntrack_tail(
    std::declval<const RuntimeFirewallConntrackTailFacts&>())));
static_assert(noexcept(plan_runtime_firewall_post_success_conntrack(
    std::declval<
        const RuntimeFirewallPostSuccessConntrackFacts&>())));

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

TEST_CASE("post-success cleanup is empty without an attempted exact snapshot") {
    RuntimeFirewallPostSuccessConntrackFacts facts;
    std::vector<std::uint32_t> remaining{0x00010000U};
    facts.remaining_marks = &remaining;

    auto plan = plan_runtime_firewall_post_success_conntrack(facts);
    CHECK_FALSE(plan.should_warn_command_unavailable());
    CHECK_FALSE(plan.should_prepare_retry());

    OwnedConntrackCleanupSnapshot snapshot;
    facts.snapshot = &snapshot;
    plan = plan_runtime_firewall_post_success_conntrack(facts);
    CHECK_FALSE(plan.should_prepare_retry());

    facts.attempted = true;
    facts.snapshot = nullptr;
    plan = plan_runtime_firewall_post_success_conntrack(facts);
    CHECK_FALSE(plan.should_prepare_retry());
}

TEST_CASE("post-success command-unavailable warns and suppresses retry") {
    OwnedConntrackCleanupSnapshot snapshot;
    std::vector<std::uint32_t> remaining{0x00010000U};
    RuntimeFirewallPostSuccessConntrackFacts facts;
    facts.attempted = true;
    facts.snapshot = &snapshot;
    facts.command_unavailable = true;
    facts.cleanup_failed = true;
    facts.remaining_marks = &remaining;

    const auto plan =
        plan_runtime_firewall_post_success_conntrack(facts);
    CHECK(plan.should_warn_command_unavailable());
    CHECK_FALSE(plan.should_prepare_retry());
    CHECK(plan.retry_marks ==
          RuntimeFirewallPostSuccessConntrackMarks::none);
}

TEST_CASE("post-success cleanup reuses exact reported remaining marks") {
    OwnedConntrackCleanupSnapshot snapshot;
    std::vector<std::uint32_t> remaining{
        0x00020000U, 0x00010000U};
    RuntimeFirewallPostSuccessConntrackFacts facts;
    facts.attempted = true;
    facts.snapshot = &snapshot;
    facts.remaining_marks = &remaining;

    const auto plan =
        plan_runtime_firewall_post_success_conntrack(facts);
    REQUIRE(plan.should_prepare_retry());
    CHECK(plan.retry_snapshot == &snapshot);
    CHECK(plan.reported_remaining_marks == &remaining);
    CHECK(plan.retry_marks ==
          RuntimeFirewallPostSuccessConntrackMarks::reported_remaining);
}

TEST_CASE("post-success cleanup failure falls back to ordered snapshot marks") {
    OwnedConntrackCleanupSnapshot snapshot;
    const std::vector<std::uint32_t> remaining;
    RuntimeFirewallPostSuccessConntrackFacts facts;
    facts.attempted = true;
    facts.snapshot = &snapshot;
    facts.cleanup_failed = true;
    facts.remaining_marks = &remaining;

    const auto plan =
        plan_runtime_firewall_post_success_conntrack(facts);
    REQUIRE(plan.should_prepare_retry());
    CHECK(plan.retry_snapshot == &snapshot);
    CHECK(plan.reported_remaining_marks == nullptr);
    CHECK(plan.retry_marks ==
          RuntimeFirewallPostSuccessConntrackMarks::ordered_snapshot);
}

TEST_CASE("post-success successful cleanup with no remaining marks is done") {
    OwnedConntrackCleanupSnapshot snapshot;
    const std::vector<std::uint32_t> remaining;
    RuntimeFirewallPostSuccessConntrackFacts facts;
    facts.attempted = true;
    facts.snapshot = &snapshot;
    facts.remaining_marks = &remaining;

    const auto plan =
        plan_runtime_firewall_post_success_conntrack(facts);
    CHECK_FALSE(plan.should_warn_command_unavailable());
    CHECK_FALSE(plan.should_prepare_retry());
}

} // namespace keen_pbr3
