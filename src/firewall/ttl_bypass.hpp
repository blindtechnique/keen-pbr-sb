#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

// The mangle chain KeeneticOS puts its TTL rewrite into when `ip ttl-fix` is
// enabled. The firmware owns it: it creates it, fills it and may rewrite it at
// any time. We only ever insert one rule of our own and remove copies of that
// same rule - never -F, never -X, never a rule that is not ours.
inline constexpr const char* kTtlChain = "_NDM_POSTROUTING_TTL";

// The mark nfqws2 sets on a packet it has already handled, and matches with
// `! --mark` to decide what to enqueue. Measured on a live router:
//   -A nfqws_pre -i eth3 -m mark --mark 0x40000000/0x40000000 -j RETURN
// nfqws2 already applies exactly this bypass inside its own chains; this is
// the same thing one hop later, where the firmware's TTL rewrite would
// otherwise clobber a desync that depends on the TTL it just changed.
//
// The value is deliberately NOT in keen-pbr's configurable mark space and is
// never set by us - we only match it. Nothing here touches 0x20000000.
inline constexpr std::uint32_t kNfqwsProcessedMark = 0x40000000u;
inline constexpr std::uint32_t kNfqwsProcessedMask = 0x40000000u;

// Identifies the one rule we own inside a chain we do not. Without a tag there
// is no way to tell our rule from an identical one somebody else added, and
// "delete the rule that looks like mine" would then be a way to damage another
// tool's configuration.
inline constexpr const char* kTtlBypassTag = "keen-pbr-sb:ttl-bypass";

enum class TtlBypassState {
    // The firmware chain does not exist, so there is nothing to bypass.
    //
    // Note this does NOT mean `ip ttl-fix` is off: on a measured router the
    // chain exists and is empty with ttl-fix disabled, because NDM creates the
    // scaffold regardless. Absence and emptiness are different facts, and only
    // absence is reported here.
    chain_absent,
    // We could not find out. A held xtables lock, a timeout or a missing
    // binary all land here rather than being mistaken for "no chain": those
    // say nothing about the chain, and answering an unanswered question with
    // "nothing to do" is how a feature disables itself in silence.
    unknown,
    // A kernel match we need is not registered. Doing nothing and reporting it
    // is the entire point - the alternative is a second writer shelling out
    // rules whose effect nobody verified.
    unsupported,
    // Our rule is present exactly once and first. Nothing to do.
    active,
    // Our rule exists but has drifted: not first, or duplicated. Repairable,
    // and worth surfacing, because something is rewriting the chain under us.
    conflict,
    // Our rule is absent and can be installed.
    missing,
};

struct TtlBypassPlan {
    TtlBypassState state{TtlBypassState::chain_absent};
    // argv per command, in order. Empty when there is nothing to do.
    std::vector<std::vector<std::string>> commands;
    // Human-readable reason, for health detail. Empty when uninteresting.
    std::string detail;
};

// Inputs a caller has to supply, kept explicit so the decision itself stays
// pure and testable without a router.
// What the caller learned by inspecting the chain. Deliberately three-valued:
// an inspection that failed is not evidence of absence.
enum class TtlChainObservation {
    present,
    absent,
    // Inspection failed for a reason that says nothing about the chain.
    indeterminate,
};

struct TtlBypassInputs {
    TtlChainObservation observation{TtlChainObservation::absent};
    // Rendered rules of that chain, one `-A <chain> ...` line each, in order.
    // The `-N` declaration line, if present, is ignored.
    std::vector<std::string> chain_rules;
    // Kernel-registered matches, from /proc/net/ip_tables_matches rather than
    // from `iptables-restore --test`: userspace can accept an extension the
    // kernel does not have and only fail at COMMIT.
    bool mark_match_available{false};
    bool comment_match_available{false};
};

// The exact rule we own, as it appears in `iptables -S` output.
std::string ttl_bypass_rule_spec();

// argv (after the iptables binary) that deletes our rule. Teardown needs this:
// we insert into a chain we do not own, so leaving the rule behind on stop or
// uninstall would abandon a modification to firmware state with nobody left to
// remove it - and, with nfqws2 still running, one that keeps suppressing the
// firmware's TTL rewrite for the rest of the router's uptime.
std::vector<std::string> ttl_bypass_delete_argv();

// Decides what to do. Never returns a command that creates, flushes or deletes
// the chain, and never one that touches a rule without our tag.
TtlBypassPlan plan_ttl_bypass(const TtlBypassInputs& inputs);

const char* ttl_bypass_state_name(TtlBypassState state) noexcept;

} // namespace keen_pbr3
