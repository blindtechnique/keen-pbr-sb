#pragma once

// What each firewall backend actually guarantees, and what both owe regardless.
//
// The two backends are not interchangeable and were never meant to be. iptables
// publishes one table at a time through `iptables-restore --noflush`, keeping
// the builtin hook outside the transaction so a failed COMMIT leaves the
// previously working chain in place; it needs A/B generations to imitate a swap
// the kernel will not give it, and it is the only backend that can move work to
// RAW PREROUTING. nftables gets a whole-table transaction from the kernel, so it
// carries neither generations nor a raw-prerouting path.
//
// Written down here because the difference is otherwise only discoverable by
// reading six thousand lines of one backend and three thousand of the other,
// and because a caller that assumes the wrong one is not wrong until the day a
// COMMIT fails halfway.
//
// This is a description, not a wish. Every field is answerable by reading the
// implementations, and the test that pins each one down says where. A property
// nobody has established is reported as such rather than guessed - the same
// rule the health probes follow, for the same reason.
//
// Deliberately not a shared RuleSet IR. Backend-specific atomicity and recovery
// stay where they are; this only names the contract they already keep.

#include "firewall.hpp"

#include <string>
#include <vector>

namespace keen_pbr3 {

enum class CapabilityAnswer {
    yes,
    no,
    // Neither the implementations nor the integration harness settle it. Say so
    // instead of picking the comfortable answer.
    not_established,
};

enum class PublicationAtomicity {
    // One kernel transaction covers the whole owned ruleset: it lands entirely
    // or not at all.
    whole_ruleset,
    // Each table is published by its own restore. A failure part-way leaves the
    // tables already published in place and the rest untouched - recoverable,
    // but not a single boundary.
    per_table,
};

struct FirewallCapabilities {
    FirewallBackend backend{FirewallBackend::iptables};
    PublicationAtomicity publication{PublicationAtomicity::per_table};
    // A/B chain generations, used to imitate a swap the backend cannot get from
    // the kernel. Present because it is needed, not because it is better.
    CapabilityAnswer generation_swap{CapabilityAnswer::no};
    // Owned SNAT that the backend can inspect and reconcile.
    CapabilityAnswer owned_snat{CapabilityAnswer::no};
    // Marking in RAW PREROUTING instead of mangle.
    CapabilityAnswer raw_prerouting{CapabilityAnswer::no};
    // Converges over foreign firewall state left by somebody else. This is the
    // one field where the honest answer differs from the hopeful one: only the
    // iptables path is exercised for it, so nftables is `not_established`.
    CapabilityAnswer foreign_state_convergence{CapabilityAnswer::not_established};
};

FirewallCapabilities capabilities_of(FirewallBackend backend) noexcept;

// Reads the backend off the instance rather than being told, so a caller cannot
// describe one backend while holding another.
FirewallCapabilities capabilities_of(const Firewall& firewall) noexcept;

const char* capability_answer_name(CapabilityAnswer answer) noexcept;
const char* publication_atomicity_name(PublicationAtomicity publication) noexcept;

// What the shared integration harness saw. Filled in by the harness, which is
// the only place with a live kernel; the judging below is pure so it can be
// tested without one.
struct ConformanceObservation {
    FirewallBackend requested_backend{FirewallBackend::iptables};
    FirewallBackend reported_backend{FirewallBackend::iptables};
    bool raw_prerouting_requested{false};
    bool raw_prerouting_reported{false};
    // Sets named by the published rules, and the sets that actually exist.
    std::vector<std::string> referenced_sets;
    std::vector<std::string> existing_sets;
    bool apply_succeeded{false};
    // The same configuration applied a second time. Publishing is expected to
    // be repeatable; a backend that only works from a clean slate cannot
    // recover.
    bool repeat_apply_succeeded{false};
    // Objects belonging to us, and objects belonging to somebody else, as seen
    // after cleanup(). Foreign state that was there before must still be there.
    std::vector<std::string> owned_objects_after_cleanup;
    std::vector<std::string> foreign_objects_before;
    std::vector<std::string> foreign_objects_after_cleanup;
};

struct ConformanceViolation {
    // Short, stable identifier so a harness failure names the invariant rather
    // than a line number.
    std::string invariant;
    std::string detail;
};

// The intersection both backends owe, whichever one the harness was pointed at.
//
// These are not the interesting differences - those are in FirewallCapabilities
// above. These are the promises that must survive the difference, and the ones
// a caller is entitled to make without asking which backend is underneath.
std::vector<ConformanceViolation> check_firewall_conformance(
    const FirewallCapabilities& capabilities,
    const ConformanceObservation& observation);

}  // namespace keen_pbr3
