#include "../src/firewall/firewall_contract.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

bool has(const std::vector<ConformanceViolation>& violations,
         const std::string& invariant) {
    return std::any_of(violations.begin(), violations.end(),
                       [&invariant](const ConformanceViolation& violation) {
                           return violation.invariant == invariant;
                       });
}

// A run in which everything went the way it should.
ConformanceObservation clean_run(
    const FirewallBackend backend = FirewallBackend::iptables) {
    ConformanceObservation observation;
    observation.requested_backend = backend;
    observation.reported_backend = backend;
    observation.referenced_sets = {"kpbr4_list_a", "kpbr6_list_a"};
    observation.existing_sets = {"kpbr4_list_a", "kpbr6_list_a", "kpbr4_other"};
    observation.apply_succeeded = true;
    observation.repeat_apply_succeeded = true;
    observation.foreign_objects_before = {"FORWARD_FOREIGN", "ndm_chain"};
    observation.foreign_objects_after_cleanup = {"FORWARD_FOREIGN", "ndm_chain"};
    return observation;
}

}  // namespace

TEST_CASE("contract: iptables publishes per table and needs generations for it") {
    const auto capabilities = capabilities_of(FirewallBackend::iptables);

    // Each table goes through its own `iptables-restore --noflush`, with the
    // builtin hook kept outside the transaction.
    CHECK(capabilities.publication == PublicationAtomicity::per_table);
    // The generations exist because the kernel gives this backend no
    // whole-ruleset swap - they are a consequence of the line above, not a
    // separate feature.
    CHECK(capabilities.generation_swap == CapabilityAnswer::yes);
    CHECK(capabilities.raw_prerouting == CapabilityAnswer::yes);
    CHECK(capabilities.owned_snat == CapabilityAnswer::yes);
}

TEST_CASE("contract: nftables gets its atomicity from the kernel and needs neither") {
    const auto capabilities = capabilities_of(FirewallBackend::nftables);

    // One `nft -j -f -` batch covers the table.
    CHECK(capabilities.publication == PublicationAtomicity::whole_ruleset);
    CHECK(capabilities.generation_swap == CapabilityAnswer::no);
    // create_firewall() refuses --use-raw-prerouting for this backend outright.
    CHECK(capabilities.raw_prerouting == CapabilityAnswer::no);
    CHECK(capabilities.owned_snat == CapabilityAnswer::yes);
}

TEST_CASE("contract: what nobody established is not reported as working") {
    // The shared harness installs foreign firewall state and drives convergence
    // against iptables only; --exercise-iptables-convergence refuses any other
    // backend. nftables may well converge - it has not been shown to, and this
    // names the gap instead of filling it with the comfortable answer.
    CHECK(capabilities_of(FirewallBackend::iptables).foreign_state_convergence ==
          CapabilityAnswer::yes);
    CHECK(capabilities_of(FirewallBackend::nftables).foreign_state_convergence ==
          CapabilityAnswer::not_established);
}

TEST_CASE("contract: a clean run of either backend raises nothing") {
    for (const auto backend :
         {FirewallBackend::iptables, FirewallBackend::nftables}) {
        const auto capabilities = capabilities_of(backend);
        CHECK(check_firewall_conformance(capabilities, clean_run(backend)).empty());
    }
}

TEST_CASE("contract: a backend that answers for a different one is caught first") {
    auto observation = clean_run(FirewallBackend::iptables);
    observation.reported_backend = FirewallBackend::nftables;

    const auto violations = check_firewall_conformance(
        capabilities_of(FirewallBackend::iptables), observation);

    CHECK(has(violations, "backend_identity"));
}

TEST_CASE("contract: a rule naming a set that does not exist is a fault") {
    // The shape that makes a ruleset look published and quietly match nothing.
    auto observation = clean_run();
    observation.referenced_sets.push_back("kpbr4_missing");

    const auto violations =
        check_firewall_conformance(capabilities_of(FirewallBackend::iptables),
                                   observation);

    CHECK(has(violations, "referenced_sets_exist"));
    CHECK(violations.front().detail.find("kpbr4_missing") != std::string::npos);
}

TEST_CASE("contract: publishing must work a second time") {
    // A backend that only publishes onto a clean slate cannot recover in place,
    // which is the whole of recovery on a router nobody can reach.
    auto observation = clean_run();
    observation.repeat_apply_succeeded = false;

    CHECK(has(check_firewall_conformance(
                  capabilities_of(FirewallBackend::iptables), observation),
              "apply_is_repeatable"));
}

TEST_CASE("contract: cleanup takes ours and leaves theirs") {
    auto leaves_ours = clean_run();
    leaves_ours.owned_objects_after_cleanup = {"kpbr4s", "kpbr4_mark"};
    CHECK(has(check_firewall_conformance(
                  capabilities_of(FirewallBackend::iptables), leaves_ours),
              "cleanup_removes_owned"));

    auto takes_theirs = clean_run();
    takes_theirs.foreign_objects_after_cleanup = {"FORWARD_FOREIGN"};
    const auto violations = check_firewall_conformance(
        capabilities_of(FirewallBackend::iptables), takes_theirs);
    CHECK(has(violations, "cleanup_preserves_foreign"));
    CHECK(violations.front().detail.find("ndm_chain") != std::string::npos);
}

TEST_CASE("contract: a failed apply is reported once, not as its consequences") {
    // Everything after publication describes a published ruleset. Judging it
    // anyway would turn one failure into five, and bury the one that matters.
    auto observation = clean_run();
    observation.apply_succeeded = false;
    observation.referenced_sets.push_back("kpbr4_missing");
    observation.repeat_apply_succeeded = false;
    observation.owned_objects_after_cleanup = {"kpbr4s"};

    const auto violations =
        check_firewall_conformance(capabilities_of(FirewallBackend::iptables),
                                   observation);

    REQUIRE(violations.size() == 1U);
    CHECK(violations.front().invariant == "apply");
}

TEST_CASE("contract: raw prerouting cannot be claimed by a backend without it") {
    auto observation = clean_run(FirewallBackend::nftables);
    observation.raw_prerouting_reported = true;

    CHECK(has(check_firewall_conformance(
                  capabilities_of(FirewallBackend::nftables), observation),
              "raw_prerouting_honesty"));
}

TEST_CASE("contract: a raw prerouting request must be honoured or refused, not dropped") {
    // create_firewall() throws for nftables rather than accepting and marking
    // in mangle instead. This invariant is what keeps that true: a request that
    // reaches a published ruleset without being used is a silent downgrade.
    auto observation = clean_run(FirewallBackend::iptables);
    observation.raw_prerouting_requested = true;
    observation.raw_prerouting_reported = false;

    CHECK(has(check_firewall_conformance(
                  capabilities_of(FirewallBackend::iptables), observation),
              "raw_prerouting_honesty"));

    observation.raw_prerouting_reported = true;
    CHECK(check_firewall_conformance(capabilities_of(FirewallBackend::iptables),
                                     observation)
              .empty());
}

TEST_CASE("contract: every value has a name to show") {
    CHECK(std::string{capability_answer_name(CapabilityAnswer::yes)} == "yes");
    CHECK(std::string{capability_answer_name(CapabilityAnswer::no)} == "no");
    CHECK(std::string{capability_answer_name(CapabilityAnswer::not_established)} ==
          "not_established");
    CHECK(std::string{publication_atomicity_name(
              PublicationAtomicity::whole_ruleset)} == "whole_ruleset");
    CHECK(std::string{publication_atomicity_name(
              PublicationAtomicity::per_table)} == "per_table");
}

}  // namespace keen_pbr3
