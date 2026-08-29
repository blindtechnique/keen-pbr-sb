#include "firewall_contract.hpp"

#include <algorithm>
#include <set>

namespace keen_pbr3 {

namespace {

std::vector<std::string> missing_from(const std::vector<std::string>& wanted,
                                      const std::vector<std::string>& present) {
    const std::set<std::string> have(present.begin(), present.end());
    std::vector<std::string> missing;
    for (const auto& entry : wanted) {
        if (have.count(entry) == 0U) missing.push_back(entry);
    }
    std::sort(missing.begin(), missing.end());
    missing.erase(std::unique(missing.begin(), missing.end()), missing.end());
    return missing;
}

std::string join(const std::vector<std::string>& values) {
    std::string joined;
    for (const auto& value : values) {
        if (!joined.empty()) joined += ", ";
        joined += value;
    }
    return joined;
}

}  // namespace

FirewallCapabilities capabilities_of(const FirewallBackend backend) noexcept {
    FirewallCapabilities capabilities;
    capabilities.backend = backend;
    switch (backend) {
        case FirewallBackend::iptables:
            // Each table is published by its own `iptables-restore --noflush`.
            capabilities.publication = PublicationAtomicity::per_table;
            // A/B generations exist here precisely because the kernel offers no
            // whole-ruleset swap to this backend.
            capabilities.generation_swap = CapabilityAnswer::yes;
            capabilities.owned_snat = CapabilityAnswer::yes;
            capabilities.raw_prerouting = CapabilityAnswer::yes;
            // The shared harness installs foreign state and drives convergence
            // against this backend only.
            capabilities.foreign_state_convergence = CapabilityAnswer::yes;
            break;
        case FirewallBackend::nftables:
            // One `nft -j -f -` batch covers the table.
            capabilities.publication = PublicationAtomicity::whole_ruleset;
            // Not needed: the transaction is the swap.
            capabilities.generation_swap = CapabilityAnswer::no;
            capabilities.owned_snat = CapabilityAnswer::yes;
            // create_firewall() refuses the request outright rather than
            // accepting and ignoring it.
            capabilities.raw_prerouting = CapabilityAnswer::no;
            // No harness coverage drives this backend over foreign state. It
            // may well converge; nobody has shown it.
            capabilities.foreign_state_convergence =
                CapabilityAnswer::not_established;
            break;
    }
    return capabilities;
}

FirewallCapabilities capabilities_of(const Firewall& firewall) noexcept {
    return capabilities_of(firewall.backend());
}

const char* capability_answer_name(const CapabilityAnswer answer) noexcept {
    switch (answer) {
        case CapabilityAnswer::yes:
            return "yes";
        case CapabilityAnswer::no:
            return "no";
        case CapabilityAnswer::not_established:
            break;
    }
    return "not_established";
}

const char* publication_atomicity_name(
    const PublicationAtomicity publication) noexcept {
    switch (publication) {
        case PublicationAtomicity::whole_ruleset:
            return "whole_ruleset";
        case PublicationAtomicity::per_table:
            break;
    }
    return "per_table";
}

std::vector<ConformanceViolation> check_firewall_conformance(
    const FirewallCapabilities& capabilities,
    const ConformanceObservation& observation) {
    std::vector<ConformanceViolation> violations;

    if (observation.reported_backend != observation.requested_backend) {
        violations.push_back(
            {"backend_identity",
             "the firewall reports a different backend than the one that was "
             "asked for, so every other answer describes something else"});
    }

    if (!observation.apply_succeeded) {
        violations.push_back({"apply", "publishing the ruleset failed"});
        // Everything below describes a published ruleset. Judging it now would
        // report the consequences of this one failure as separate faults.
        return violations;
    }

    const auto missing_sets =
        missing_from(observation.referenced_sets, observation.existing_sets);
    if (!missing_sets.empty()) {
        violations.push_back(
            {"referenced_sets_exist",
             "rules were published naming sets that do not exist: " +
                 join(missing_sets)});
    }

    if (!observation.repeat_apply_succeeded) {
        violations.push_back(
            {"apply_is_repeatable",
             "applying the same configuration a second time failed, so this "
             "backend can only publish onto a clean slate and cannot recover "
             "in place"});
    }

    if (!observation.owned_objects_after_cleanup.empty()) {
        violations.push_back(
            {"cleanup_removes_owned",
             "cleanup left objects of ours behind: " +
                 join(observation.owned_objects_after_cleanup)});
    }

    const auto lost_foreign = missing_from(observation.foreign_objects_before,
                                           observation.foreign_objects_after_cleanup);
    if (!lost_foreign.empty()) {
        violations.push_back(
            {"cleanup_preserves_foreign",
             "cleanup removed state belonging to somebody else: " +
                 join(lost_foreign)});
    }

    // Raw prerouting is the one capability a caller can ask for, so it is the
    // one that can be silently dropped. Both directions are faults: reporting
    // it while the backend does not have it, and accepting the request while
    // quietly marking in mangle instead.
    if (observation.raw_prerouting_reported &&
        capabilities.raw_prerouting != CapabilityAnswer::yes) {
        violations.push_back(
            {"raw_prerouting_honesty",
             "the backend reports marking in RAW PREROUTING, which it does not "
             "support"});
    }
    if (observation.raw_prerouting_requested &&
        !observation.raw_prerouting_reported) {
        violations.push_back(
            {"raw_prerouting_honesty",
             "RAW PREROUTING was requested and the backend did not report using "
             "it - a request that is dropped rather than refused"});
    }

    return violations;
}

}  // namespace keen_pbr3
