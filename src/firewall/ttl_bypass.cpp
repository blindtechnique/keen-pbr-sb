#include "ttl_bypass.hpp"

#include <iomanip>
#include <sstream>

namespace keen_pbr3 {

namespace {

std::string hex_mark(std::uint32_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

std::string mark_argument() {
    return hex_mark(kNfqwsProcessedMark) + "/" + hex_mark(kNfqwsProcessedMask);
}

// The match arguments, shared by the insert and the delete so the two can
// never drift into deleting something other than what we inserted.
std::vector<std::string> rule_body() {
    return {
        "-m", "mark", "--mark", mark_argument(),
        "-m", "comment", "--comment", kTtlBypassTag,
        "-j", "RETURN",
    };
}

std::vector<std::string> with_prefix(std::vector<std::string> prefix,
                                     const std::vector<std::string>& tail) {
    prefix.insert(prefix.end(), tail.begin(), tail.end());
    return prefix;
}

bool is_rule_of_chain(const std::string& line) {
    const std::string prefix = std::string("-A ") + kTtlChain + " ";
    return line.compare(0, prefix.size(), prefix) == 0;
}

// Matched by tag rather than by whole-line equality. iptables renders a
// comment quoted on some versions and bare on others, and a line that differs
// only in quoting is still unmistakably ours.
bool carries_our_tag(const std::string& line) {
    return line.find(kTtlBypassTag) != std::string::npos;
}

} // namespace

std::string ttl_bypass_rule_spec() {
    std::ostringstream out;
    out << "-A " << kTtlChain;
    for (const auto& token : rule_body()) {
        out << ' ' << token;
    }
    return out.str();
}

std::vector<std::string> ttl_bypass_delete_argv() {
    return with_prefix({"-t", "mangle", "-D", kTtlChain}, rule_body());
}

const char* ttl_bypass_state_name(TtlBypassState state) noexcept {
    switch (state) {
        case TtlBypassState::chain_absent: return "chain_absent";
        case TtlBypassState::unknown:      return "unknown";
        case TtlBypassState::unsupported:  return "unsupported";
        case TtlBypassState::active:       return "active";
        case TtlBypassState::conflict:     return "conflict";
        case TtlBypassState::missing:      return "missing";
        case TtlBypassState::disabled:     return "disabled";
    }
    return "unknown";
}

namespace {

// Copies of our own rule in the chain, ignoring the -N declaration and any
// line belonging elsewhere. Only tagged rules count: an untagged RETURN that
// happens to look identical belongs to whoever wrote it, not to us.
std::size_t count_our_rules(const std::vector<std::string>& chain_rules) {
    std::size_t found = 0;
    for (const auto& line : chain_rules) {
        if (is_rule_of_chain(line) && carries_our_tag(line)) ++found;
    }
    return found;
}

} // namespace

TtlBypassPlan plan_ttl_bypass(const TtlBypassInputs& inputs) {
    TtlBypassPlan plan;

    if (inputs.observation == TtlChainObservation::indeterminate) {
        // We asked and did not get an answer. Reporting "nothing to do" here
        // would let a held xtables lock silently disable the feature while
        // affirmatively claiming everything is fine.
        plan.state = TtlBypassState::unknown;
        plan.detail = "could not inspect the firmware TTL chain";
        return plan;
    }

    if (!inputs.enabled) {
        // Reported before the chain and capability checks, because the
        // operator's instruction is the fact they will look for after flipping
        // the switch. "chain_absent" while they are waiting to see the bypass
        // turn off answers a question nobody asked.
        plan.state = TtlBypassState::disabled;
        plan.detail = "disabled by configuration";
        // Off means gone, not "stop installing". A rule left behind would keep
        // working while the interface says it is off, which is the worst of
        // both: an effect with no visible cause.
        for (std::size_t i = 0; i < count_our_rules(inputs.chain_rules); ++i) {
            plan.commands.push_back(with_prefix(
                {"-t", "mangle", "-D", kTtlChain}, rule_body()));
        }
        return plan;
    }

    if (inputs.observation == TtlChainObservation::absent) {
        // Creating the chain ourselves would put us in the business of owning
        // a firmware chain, which is exactly what must not happen.
        plan.state = TtlBypassState::chain_absent;
        return plan;
    }

    if (!inputs.mark_match_available || !inputs.comment_match_available) {
        plan.state = TtlBypassState::unsupported;
        plan.detail = !inputs.mark_match_available
            ? "kernel match 'mark' is not registered"
            : "kernel match 'comment' is not registered";
        // No commands. Reporting the gap is the deliverable here: emitting the
        // rule anyway would either fail at commit or, worse, install a rule
        // whose match nobody verified.
        return plan;
    }

    // Position among this chain's rules, ignoring the -N declaration and any
    // line belonging to another chain.
    std::vector<std::size_t> ours;
    std::size_t position = 0;
    for (const auto& line : inputs.chain_rules) {
        if (!is_rule_of_chain(line)) {
            continue;
        }
        if (carries_our_tag(line)) {
            ours.push_back(position);
        }
        ++position;
    }

    const std::vector<std::string> insert_argv = with_prefix(
        {"-t", "mangle", "-I", kTtlChain, "1"}, rule_body());
    const std::vector<std::string> delete_argv = with_prefix(
        {"-t", "mangle", "-D", kTtlChain}, rule_body());

    if (ours.empty()) {
        plan.state = TtlBypassState::missing;
        plan.commands.push_back(insert_argv);
        return plan;
    }

    if (ours.size() == 1 && ours.front() == 0) {
        plan.state = TtlBypassState::active;
        return plan;
    }

    // Drifted: either something was inserted above us, or an earlier run left
    // duplicates. Both are repairable by removing every copy of OUR rule and
    // putting exactly one back at the top. Nothing without our tag is touched,
    // so a firmware rule that arrived above us is removed from in front of us
    // by re-inserting, never by deleting it.
    plan.state = TtlBypassState::conflict;
    plan.detail = ours.size() > 1
        ? "duplicate keen-pbr TTL bypass rules"
        : "keen-pbr TTL bypass rule is no longer first in the chain";
    for (std::size_t i = 0; i < ours.size(); ++i) {
        plan.commands.push_back(delete_argv);
    }
    plan.commands.push_back(insert_argv);
    return plan;
}

} // namespace keen_pbr3
