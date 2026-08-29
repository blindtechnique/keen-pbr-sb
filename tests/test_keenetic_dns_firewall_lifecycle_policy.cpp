#include <doctest/doctest.h>

#include "daemon/keenetic_dns_firewall_lifecycle_policy.hpp"
#include "daemon/runtime_firewall_operation_owner.hpp"
#include "daemon/runtime_firewall_worker_attempt.hpp"

#include <cstdint>
#include <utility>

using namespace keen_pbr3;

namespace {

RuntimeFirewallLifecycleTerminal verified_terminal() {
    RuntimeFirewallLifecycleTerminal terminal;
    terminal.outcome =
        RuntimeFirewallLifecycleOutcome::verified_success;
    terminal.committed = true;
    terminal.commit_ambiguous = false;
    return terminal;
}

KeeneticDnsCandidateTerminalEvidence committed_candidate_evidence() {
    KeeneticDnsCandidateTerminalEvidence evidence;
    evidence.outcome =
        RuntimeFirewallLifecycleOutcome::verified_success;
    evidence.committed = true;
    evidence.commit_ambiguous = false;
    evidence.exact_lease_owned = true;
    evidence.runtime_generation_current = true;
    evidence.candidate_core_available = true;
    evidence.exact_rollback_available = true;
    return evidence;
}

struct PublishedDnsGeneration {
    int dns{0};
    int firewall{0};
    int resolver{0};
};

} // namespace

TEST_CASE("Keenetic DNS lifecycle kinds retain preowned resolver ownership") {
    for (const auto lifecycle : {
             RuntimeFirewallLifecycleKind::keenetic_dns_candidate,
             RuntimeFirewallLifecycleKind::keenetic_dns_rollback}) {
        CHECK(runtime_firewall_lifecycle_is_keenetic_dns_generation(
            lifecycle));
        CHECK(runtime_firewall_lifecycle_uses_preowned_continuation(
            lifecycle));
        CHECK(runtime_firewall_lifecycle_requires_resolver(lifecycle));
        CHECK(runtime_firewall_lifecycle_uses_hot_retry(lifecycle));
    }
    CHECK(runtime_firewall_lifecycle_is_keenetic_dns_candidate(
        RuntimeFirewallLifecycleKind::keenetic_dns_candidate));
    CHECK_FALSE(runtime_firewall_lifecycle_is_keenetic_dns_candidate(
        RuntimeFirewallLifecycleKind::keenetic_dns_rollback));
    CHECK(runtime_firewall_worker_operation_is_keenetic_dns_generation(
        RuntimeFirewallWorkerOperationKind::keenetic_dns_candidate));
    CHECK(runtime_firewall_worker_operation_is_keenetic_dns_generation(
        RuntimeFirewallWorkerOperationKind::keenetic_dns_rollback));
}

TEST_CASE("Keenetic DNS production seam orders firewall resolver and publish") {
    constexpr std::uint64_t token = 41U;
    KeeneticDnsFirewallTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin(token));

    CHECK_FALSE(orchestrator.admit_resolver_stream_after_firewall(
        /*route_firewall_commit_proven=*/false, token));
    CHECK_FALSE(orchestrator.resolver_stream_verified(token));
    REQUIRE(orchestrator.admit_resolver_stream_after_firewall(
        /*route_firewall_commit_proven=*/true, token));
    REQUIRE(orchestrator.observe_resolver_stream_terminal(
        /*verified=*/true, token));
    REQUIRE(orchestrator.resolver_stream_verified(token));

    PublishedDnsGeneration published{1, 2, 3};
    PublishedDnsGeneration candidate{11, 12, 13};
    int publication_calls = 0;
    const bool publication_succeeded =
        publish_keenetic_dns_generation_if_current(
            []() noexcept { return true; },
            [&]() noexcept {
                ++publication_calls;
                using std::swap;
                swap(published.dns, candidate.dns);
                swap(published.firewall, candidate.firewall);
                swap(published.resolver, candidate.resolver);
            });
    REQUIRE(publication_succeeded);
    CHECK(publication_calls == 1);
    CHECK(published.dns == 11);
    CHECK(published.firewall == 12);
    CHECK(published.resolver == 13);

    auto evidence = committed_candidate_evidence();
    evidence.candidate_publication_succeeded = publication_succeeded;
    CHECK(orchestrator.complete_candidate(evidence, token) ==
          KeeneticDnsCandidateTerminalAction::publish_candidate);
    CHECK(orchestrator.phase() ==
          KeeneticDnsFirewallTerminalPhase::finished);
}

TEST_CASE("Keenetic DNS pre-COMMIT failure restores cleanly without resolver") {
    constexpr std::uint64_t token = 42U;
    KeeneticDnsFirewallTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin(token));

    KeeneticDnsCandidateTerminalEvidence evidence;
    evidence.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
    evidence.committed = false;
    evidence.commit_ambiguous = false;
    evidence.previous_generation_certainly_retained = true;
    evidence.exact_lease_owned = true;
    evidence.runtime_generation_current = true;
    evidence.candidate_firewall_preimage_is_base = true;
    CHECK(orchestrator.complete_candidate(evidence, token) ==
          KeeneticDnsCandidateTerminalAction::finish_clean_precommit);
    CHECK(orchestrator.phase() ==
          KeeneticDnsFirewallTerminalPhase::finished);
}

TEST_CASE("Keenetic DNS resolver failure rolls back with the same token") {
    constexpr std::uint64_t token = 43U;
    KeeneticDnsFirewallTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin(token));
    REQUIRE(orchestrator.admit_resolver_stream_after_firewall(true, token));
    REQUIRE(orchestrator.observe_resolver_stream_terminal(false, token));

    auto candidate = committed_candidate_evidence();
    candidate.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
    candidate.candidate_publication_succeeded = false;
    REQUIRE(orchestrator.complete_candidate(candidate, token) ==
            KeeneticDnsCandidateTerminalAction::start_exact_rollback);
    REQUIRE(orchestrator.phase() ==
            KeeneticDnsFirewallTerminalPhase::rollback);

    CHECK_FALSE(orchestrator.admit_resolver_stream_after_firewall(
        true, token + 1U));
    REQUIRE(orchestrator.admit_resolver_stream_after_firewall(true, token));
    REQUIRE(orchestrator.observe_resolver_stream_terminal(true, token));
    const auto rollback = verified_terminal();
    CHECK(orchestrator.complete_rollback(
              rollback,
              /*exact_lease_owned=*/true,
              /*runtime_generation_current=*/true,
              /*rollback_publication_succeeded=*/true,
              token) ==
          KeeneticDnsRollbackTerminalAction::finish_verified_rollback);
    CHECK(orchestrator.phase() ==
          KeeneticDnsFirewallTerminalPhase::finished);
}

TEST_CASE("Keenetic DNS exact route mutation rolls back after firewall pre-COMMIT failure") {
    constexpr std::uint64_t token = 47U;
    KeeneticDnsFirewallTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin(token));

    KeeneticDnsCandidateTerminalEvidence candidate;
    candidate.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
    candidate.committed = false;
    candidate.commit_ambiguous = false;
    candidate.previous_generation_certainly_retained = false;
    candidate.exact_lease_owned = true;
    candidate.runtime_generation_current = true;
    candidate.candidate_firewall_preimage_is_base = false;
    candidate.candidate_core_available = false;
    candidate.exact_rollback_available = true;
    REQUIRE(orchestrator.complete_candidate(candidate, token) ==
            KeeneticDnsCandidateTerminalAction::start_exact_rollback);
    REQUIRE(orchestrator.phase() ==
            KeeneticDnsFirewallTerminalPhase::rollback);

    CHECK_FALSE(orchestrator.admit_resolver_stream_after_firewall(
        /*route_firewall_commit_proven=*/true, token + 1U));
    CHECK(orchestrator.admit_resolver_stream_after_firewall(
        /*route_firewall_commit_proven=*/true, token));
}

TEST_CASE("Keenetic DNS ambiguous COMMIT never rolls back or replays") {
    RuntimeMutationAdmission admission;
    auto lease = admission.try_acquire("keenetic-dns-recovery-order");
    REQUIRE(lease.has_value());
    const std::uint64_t token = lease->token();
    KeeneticDnsFirewallTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin(token));

    auto evidence = committed_candidate_evidence();
    evidence.outcome = RuntimeFirewallLifecycleOutcome::not_verified;
    evidence.commit_ambiguous = true;
    CHECK(orchestrator.complete_candidate(evidence, token) ==
          KeeneticDnsCandidateTerminalAction::request_fresh_recovery);
    CHECK(orchestrator.phase() ==
          KeeneticDnsFirewallTerminalPhase::finished);

    // A duplicate terminal cannot re-enter candidate or rollback.
    CHECK(orchestrator.complete_candidate(evidence, token) ==
          KeeneticDnsCandidateTerminalAction::request_fresh_recovery);
    CHECK_FALSE(orchestrator.fresh_recovery_dispatch_allowed(
        /*recovery_required=*/true,
        admission.active().has_value()));
    lease.reset();
    REQUIRE_FALSE(admission.active().has_value());
    CHECK(orchestrator.fresh_recovery_dispatch_allowed(
        /*recovery_required=*/true,
        admission.active().has_value()));
}

TEST_CASE("Keenetic DNS publication CAS mismatch is fail closed and atomic") {
    PublishedDnsGeneration published{1, 2, 3};
    PublishedDnsGeneration candidate{11, 12, 13};
    int publication_calls = 0;
    const bool published_candidate =
        publish_keenetic_dns_generation_if_current(
            []() noexcept { return false; },
            [&]() noexcept {
                ++publication_calls;
                using std::swap;
                swap(published.dns, candidate.dns);
                swap(published.firewall, candidate.firewall);
                swap(published.resolver, candidate.resolver);
            });
    CHECK_FALSE(published_candidate);
    CHECK(publication_calls == 0);
    CHECK(published.dns == 1);
    CHECK(published.firewall == 2);
    CHECK(published.resolver == 3);

    constexpr std::uint64_t token = 45U;
    KeeneticDnsFirewallTerminalOrchestrator orchestrator;
    REQUIRE(orchestrator.begin(token));
    REQUIRE(orchestrator.admit_resolver_stream_after_firewall(true, token));
    REQUIRE(orchestrator.observe_resolver_stream_terminal(true, token));
    auto evidence = committed_candidate_evidence();
    evidence.candidate_publication_succeeded = published_candidate;
    CHECK(orchestrator.complete_candidate(evidence, token) ==
          KeeneticDnsCandidateTerminalAction::request_fresh_recovery);
    CHECK(orchestrator.phase() ==
          KeeneticDnsFirewallTerminalPhase::finished);
}

TEST_CASE("Keenetic DNS generation or physical token mismatch cannot publish") {
    constexpr std::uint64_t token = 46U;
    KeeneticDnsFirewallTerminalOrchestrator generation_mismatch;
    REQUIRE(generation_mismatch.begin(token));
    REQUIRE(generation_mismatch.admit_resolver_stream_after_firewall(
        true, token));
    REQUIRE(generation_mismatch.observe_resolver_stream_terminal(
        true, token));
    auto stale = committed_candidate_evidence();
    stale.runtime_generation_current = false;
    CHECK(generation_mismatch.complete_candidate(stale, token) ==
          KeeneticDnsCandidateTerminalAction::request_fresh_recovery);

    KeeneticDnsFirewallTerminalOrchestrator token_mismatch;
    REQUIRE(token_mismatch.begin(token));
    REQUIRE(token_mismatch.admit_resolver_stream_after_firewall(
        true, token));
    REQUIRE(token_mismatch.observe_resolver_stream_terminal(true, token));
    auto current = committed_candidate_evidence();
    current.candidate_publication_succeeded = true;
    CHECK(token_mismatch.complete_candidate(current, token + 1U) ==
          KeeneticDnsCandidateTerminalAction::request_fresh_recovery);
    CHECK(token_mismatch.phase() ==
          KeeneticDnsFirewallTerminalPhase::finished);
}
