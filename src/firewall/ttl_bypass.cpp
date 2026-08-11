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

const char* ttl_bypass_state_name(TtlBypassState state) noexcept {
    switch (state) {
        case TtlBypassState::chain_absent: return "chain_absent";
        case TtlBypassState::unsupported:  return "unsupported";
        case TtlBypassState::active:       return "active";
        case TtlBypassState::conflict:     return "conflict";
        case TtlBypassState::missing:      return "missing";
    }
    return "unknown";
}

TtlBypassPlan plan_ttl_bypass(const TtlBypassInputs& inputs) {
    TtlBypassPlan plan;

    if (!inputs.chain_exists) {
        // The firmware only creates this chain when `ip ttl-fix` is in play.
        // Creating it ourselves would put us in the business of owning a
        // firmware chain, which is exactly what must not happen.
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
