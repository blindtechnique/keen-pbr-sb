#include <doctest/doctest.h>

#include "firewall/ttl_bypass.hpp"
#include "firewall/iptables.hpp"

#include <algorithm>
#include <deque>
#include <functional>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

using ControlResult = testing::IptablesControlResultForTest;

class ScopedIptablesControlRunner {
public:
    explicit ScopedIptablesControlRunner(
        testing::IptablesControlRunnerForTest runner) {
        testing::set_iptables_control_runner_for_test(std::move(runner));
    }

    ~ScopedIptablesControlRunner() {
        testing::reset_iptables_control_runner_for_test();
    }

    ScopedIptablesControlRunner(const ScopedIptablesControlRunner&) = delete;
    ScopedIptablesControlRunner& operator=(
        const ScopedIptablesControlRunner&) = delete;
};

ControlResult control_success(std::string output = {}) {
    return ControlResult{std::move(output), 0, false, false};
}

ControlResult control_transient() {
    return ControlResult{"xtables lock is busy", 4, false, false};
}

std::string ttl_chain_with_owned_rule() {
    return std::string("-N ") + kTtlChain + "\n" +
           ttl_bypass_rule_spec() + "\n";
}

std::string empty_ttl_chain() {
    return std::string("-N ") + kTtlChain + "\n";
}

TtlBypassInputs supported(std::vector<std::string> rules) {
    TtlBypassInputs inputs;
    inputs.observation = TtlChainObservation::present;
    inputs.chain_rules = std::move(rules);
    inputs.mark_match_available = true;
    inputs.comment_match_available = true;
    inputs.nfqws_processed_mark_observed = true;
    inputs.nfqws_processed_mark_compatible = true;
    inputs.routing_mark_disjoint = true;
    return inputs;
}

// The rule as iptables 1.4.21 renders it, comment quoted.
std::string our_rule() {
    return std::string("-A ") + kTtlChain +
        " -m mark --mark 0x40000000/0x40000000"
        " -m comment --comment \"" + kTtlBypassTag + "\" -j RETURN";
}

std::string firmware_ttl_rule() {
    return std::string("-A ") + kTtlChain + " -o eth3 -j TTL --ttl-set 64";
}

bool joined_contains(const std::vector<std::string>& argv,
                     const std::string& needle) {
    std::string joined;
    for (const auto& token : argv) {
        joined += token;
        joined += ' ';
    }
    return joined.find(needle) != std::string::npos;
}

bool any_command_contains(const TtlBypassPlan& plan, const std::string& needle) {
    return std::any_of(
        plan.commands.begin(), plan.commands.end(),
        [&needle](const std::vector<std::string>& argv) {
            return joined_contains(argv, needle);
        });
}

} // namespace

TEST_CASE("an absent firmware chain means there is nothing to bypass") {
    TtlBypassInputs inputs;
    inputs.observation = TtlChainObservation::absent;
    inputs.mark_match_available = true;
    inputs.comment_match_available = true;

    const auto plan = plan_ttl_bypass(inputs);

    // Creating the chain ourselves would make us the owner of a firmware
    // chain. Note absence is NOT the same as `ip ttl-fix` being off: on a
    // measured router the chain exists and is empty with ttl-fix disabled.
    CHECK(plan.state == TtlBypassState::chain_absent);
    CHECK(plan.commands.empty());
}

TEST_CASE("an inspection that failed is not evidence of absence") {
    TtlBypassInputs inputs;
    inputs.observation = TtlChainObservation::indeterminate;
    inputs.mark_match_available = true;
    inputs.comment_match_available = true;

    const auto plan = plan_ttl_bypass(inputs);

    // A held xtables lock, a timeout or a missing binary say nothing about the
    // chain. Answering that with "nothing to do" is how a feature disables
    // itself in silence while affirmatively reporting that all is well.
    CHECK(plan.state == TtlBypassState::unknown);
    CHECK(plan.commands.empty());
    CHECK_FALSE(plan.detail.empty());
}

TEST_CASE("teardown deletes exactly the rule we insert") {
    // The delete spec and the insert body must stay identical, or teardown
    // silently leaves our rule behind in a chain nobody else will clean.
    const auto insert = plan_ttl_bypass(supported({})).commands.front();
    const auto remove = ttl_bypass_delete_argv();

    REQUIRE(insert.size() >= 5);
    REQUIRE(remove.size() >= 4);
    // Everything after the chain/position prefix must match token for token.
    const std::vector<std::string> insert_body(insert.begin() + 5,
                                               insert.end());
    const std::vector<std::string> remove_body(remove.begin() + 4,
                                               remove.end());
    CHECK(insert_body == remove_body);
    CHECK(remove[2] == "-D");
    CHECK(remove[3] == std::string(kTtlChain));
    CHECK(joined_contains(remove, kTtlBypassTag));
}

TEST_CASE("a missing kernel match reports instead of writing") {
    auto inputs = supported({});
    inputs.mark_match_available = false;

    const auto plan = plan_ttl_bypass(inputs);

    // The whole requirement: capability drift becomes health, not a second
    // writer emitting a rule whose match nobody verified.
    CHECK(plan.state == TtlBypassState::unsupported);
    CHECK(plan.commands.empty());
    CHECK(plan.detail.find("mark") != std::string::npos);
}

TEST_CASE("a missing comment match also reports instead of writing") {
    auto inputs = supported({});
    inputs.comment_match_available = false;

    const auto plan = plan_ttl_bypass(inputs);

    // Without a tag there is no way to tell our rule from an identical one
    // somebody else added, so an untagged rule is not an acceptable fallback.
    CHECK(plan.state == TtlBypassState::unsupported);
    CHECK(plan.commands.empty());
    CHECK(plan.detail.find("comment") != std::string::npos);
}

TEST_CASE("an absent or changed nfqws processed mark keeps the bypass inert") {
    auto inputs = supported({our_rule()});
    inputs.nfqws_processed_mark_compatible = false;

    const auto plan = plan_ttl_bypass(inputs);

    CHECK(plan.state == TtlBypassState::conflict);
    CHECK(plan.detail.find("nfqws processed mark") != std::string::npos);
    REQUIRE(plan.commands.size() == 1);
    CHECK(plan.commands.front() == ttl_bypass_delete_argv());
}

TEST_CASE("an unreadable nfqws mark is unknown and never deletes a safe rule") {
    auto inputs = supported({our_rule()});
    inputs.nfqws_processed_mark_observed = false;
    inputs.nfqws_processed_mark_compatible = false;

    const auto plan = plan_ttl_bypass(inputs);

    CHECK(plan.state == TtlBypassState::unknown);
    CHECK(plan.commands.empty());
}

TEST_CASE("a keen-pbr mark overlap removes the owned bypass") {
    auto inputs = supported({our_rule()});
    inputs.routing_mark_disjoint = false;

    const auto plan = plan_ttl_bypass(inputs);

    CHECK(plan.state == TtlBypassState::conflict);
    CHECK(plan.detail.find("overlaps") != std::string::npos);
    REQUIRE(plan.commands.size() == 1);
    CHECK(plan.commands.front() == ttl_bypass_delete_argv());
}

TEST_CASE("an empty chain gets the rule inserted first") {
    const auto plan = plan_ttl_bypass(supported({}));

    CHECK(plan.state == TtlBypassState::missing);
    REQUIRE(plan.commands.size() == 1);
    CHECK(joined_contains(plan.commands.front(), "-I"));
    CHECK(joined_contains(plan.commands.front(),
                          std::string(kTtlChain) + " 1"));
    CHECK(joined_contains(plan.commands.front(), "0x40000000/0x40000000"));
    CHECK(joined_contains(plan.commands.front(), kTtlBypassTag));
    CHECK(joined_contains(plan.commands.front(), "RETURN"));
}

TEST_CASE("a chain with firmware rules gets ours in front of them") {
    const auto plan = plan_ttl_bypass(supported({firmware_ttl_rule()}));

    // Position one matters: a TTL rewrite that runs first has already
    // destroyed the thing the bypass exists to protect.
    CHECK(plan.state == TtlBypassState::missing);
    REQUIRE(plan.commands.size() == 1);
    CHECK(joined_contains(plan.commands.front(),
                          std::string(kTtlChain) + " 1"));
}

TEST_CASE("our rule already first is left completely alone") {
    const auto plan =
        plan_ttl_bypass(supported({our_rule(), firmware_ttl_rule()}));

    CHECK(plan.state == TtlBypassState::active);
    CHECK(plan.commands.empty());
}

TEST_CASE("a rule that drifted below a firmware rule is put back on top") {
    const auto plan =
        plan_ttl_bypass(supported({firmware_ttl_rule(), our_rule()}));

    CHECK(plan.state == TtlBypassState::conflict);
    // Exactly one delete of ours plus one insert. The firmware rule that got
    // in front is never deleted - we move ourselves, we do not remove them.
    REQUIRE(plan.commands.size() == 2);
    CHECK(joined_contains(plan.commands[0], "-D"));
    CHECK(joined_contains(plan.commands[1], "-I"));
    CHECK_FALSE(any_command_contains(plan, "--ttl-set"));
}

TEST_CASE("duplicates are collapsed to exactly one") {
    const auto plan = plan_ttl_bypass(
        supported({our_rule(), firmware_ttl_rule(), our_rule()}));

    CHECK(plan.state == TtlBypassState::conflict);
    // One delete per copy, then a single insert.
    REQUIRE(plan.commands.size() == 3);
    CHECK(joined_contains(plan.commands[0], "-D"));
    CHECK(joined_contains(plan.commands[1], "-D"));
    CHECK(joined_contains(plan.commands[2], "-I"));
}

TEST_CASE("an untagged lookalike is never touched") {
    // Same match, same verdict, no tag: somebody else's rule. Deleting it
    // would be damaging another tool's configuration, so ours is simply
    // inserted above it.
    const std::string lookalike = std::string("-A ") + kTtlChain +
        " -m mark --mark 0x40000000/0x40000000 -j RETURN";

    const auto plan = plan_ttl_bypass(supported({lookalike}));

    CHECK(plan.state == TtlBypassState::missing);
    REQUIRE(plan.commands.size() == 1);
    CHECK(joined_contains(plan.commands.front(), "-I"));
    CHECK_FALSE(any_command_contains(plan, "-D"));
}

TEST_CASE("rules of other chains are ignored when counting position") {
    // `iptables -S` output handed to us unfiltered must not make our rule look
    // like it is in the wrong place.
    const auto plan = plan_ttl_bypass(supported({
        "-N " + std::string(kTtlChain),
        "-A POSTROUTING -j " + std::string(kTtlChain),
        "-A nfqws_post -o eth3 -j NFQUEUE --queue-num 300",
        our_rule(),
    }));

    CHECK(plan.state == TtlBypassState::active);
    CHECK(plan.commands.empty());
}

TEST_CASE("no plan ever creates, flushes or deletes the firmware chain") {
    const std::vector<TtlBypassInputs> cases{
        supported({}),
        supported({firmware_ttl_rule()}),
        supported({firmware_ttl_rule(), our_rule()}),
        supported({our_rule(), our_rule()}),
    };

    for (const auto& inputs : cases) {
        const auto plan = plan_ttl_bypass(inputs);
        CHECK_FALSE(any_command_contains(plan, "-N"));
        CHECK_FALSE(any_command_contains(plan, "-F"));
        CHECK_FALSE(any_command_contains(plan, "-X"));
        // Every command must name the mangle table and our chain, so no plan
        // can ever reach a different table or a chain we did not intend.
        for (const auto& argv : plan.commands) {
            CHECK(joined_contains(argv, "-t mangle"));
            CHECK(joined_contains(argv, kTtlChain));
        }
    }
}

TEST_CASE("the planner never touches the neighbouring mark bit") {
    // 0x20000000 is explicitly out of bounds for this work.
    for (const auto& inputs :
         {supported({}), supported({firmware_ttl_rule(), our_rule()})}) {
        const auto plan = plan_ttl_bypass(inputs);
        CHECK_FALSE(any_command_contains(plan, "0x20000000"));
    }
    CHECK(ttl_bypass_rule_spec().find("0x20000000") == std::string::npos);
}

TEST_CASE("state names are stable for health output") {
    CHECK(std::string(ttl_bypass_state_name(TtlBypassState::chain_absent)) ==
          "chain_absent");
    CHECK(std::string(ttl_bypass_state_name(TtlBypassState::unsupported)) ==
          "unsupported");
    CHECK(std::string(ttl_bypass_state_name(TtlBypassState::active)) == "active");
    CHECK(std::string(ttl_bypass_state_name(TtlBypassState::conflict)) ==
          "conflict");
    CHECK(std::string(ttl_bypass_state_name(TtlBypassState::missing)) ==
          "missing");
}

TEST_CASE("the bypass is on unless the operator turns it off") {
    TtlBypassInputs inputs;

    // Every nfqws2 strategy this project ships uses a TTL-dependent desync, so
    // an opt-in switch would leave the fix off for everyone who never learns
    // it exists. Defaulting off would be a decision disguised as a default.
    CHECK(inputs.enabled);
}

TEST_CASE("turning it off removes the rule rather than stopping installs") {
    TtlBypassInputs inputs;
    inputs.enabled = false;
    inputs.observation = TtlChainObservation::present;
    inputs.mark_match_available = true;
    inputs.comment_match_available = true;
    inputs.chain_rules = {
        "-A _NDM_POSTROUTING_TTL -m mark --mark 0x40000000/0x40000000 "
        "-m comment --comment \"keen-pbr-sb:ttl-bypass\" -j RETURN",
    };

    const auto plan = plan_ttl_bypass(inputs);

    CHECK(plan.state == TtlBypassState::disabled);
    // A rule left behind keeps working while the interface says it is off:
    // an effect with no visible cause, which is worse than either state.
    REQUIRE(plan.commands.size() == 1);
    CHECK(plan.commands.front() == ttl_bypass_delete_argv());
}

TEST_CASE("turning it off when nothing is installed does nothing") {
    TtlBypassInputs inputs;
    inputs.enabled = false;
    inputs.observation = TtlChainObservation::present;
    inputs.mark_match_available = true;
    inputs.comment_match_available = true;

    const auto plan = plan_ttl_bypass(inputs);

    CHECK(plan.state == TtlBypassState::disabled);
    CHECK(plan.commands.empty());
}

TEST_CASE("turning it off removes every copy, not just the first") {
    const std::string ours =
        "-A _NDM_POSTROUTING_TTL -m mark --mark 0x40000000/0x40000000 "
        "-m comment --comment \"keen-pbr-sb:ttl-bypass\" -j RETURN";

    TtlBypassInputs inputs;
    inputs.enabled = false;
    inputs.observation = TtlChainObservation::present;
    inputs.mark_match_available = true;
    inputs.comment_match_available = true;
    inputs.chain_rules = {ours, ours};

    const auto plan = plan_ttl_bypass(inputs);

    CHECK(plan.state == TtlBypassState::disabled);
    CHECK(plan.commands.size() == 2);
}

TEST_CASE("turning it off never touches a rule that is not ours") {
    TtlBypassInputs inputs;
    inputs.enabled = false;
    inputs.observation = TtlChainObservation::present;
    inputs.mark_match_available = true;
    inputs.comment_match_available = true;
    // Same shape, no tag. It belongs to whoever wrote it.
    inputs.chain_rules = {
        "-A _NDM_POSTROUTING_TTL -m mark --mark 0x40000000/0x40000000 "
        "-j RETURN",
    };

    const auto plan = plan_ttl_bypass(inputs);

    CHECK(plan.state == TtlBypassState::disabled);
    CHECK(plan.commands.empty());
}

TEST_CASE("being told not to is reported apart from being unable to") {
    TtlBypassInputs off;
    off.enabled = false;
    off.observation = TtlChainObservation::present;
    off.mark_match_available = true;
    off.comment_match_available = true;

    TtlBypassInputs incapable;
    incapable.observation = TtlChainObservation::present;
    incapable.mark_match_available = true;
    incapable.comment_match_available = false;

    // An operator who flipped the switch and an operator whose kernel lacks a
    // match need different next actions, so the report must not merge them.
    CHECK(plan_ttl_bypass(off).state == TtlBypassState::disabled);
    CHECK(plan_ttl_bypass(incapable).state == TtlBypassState::unsupported);
    CHECK(std::string(ttl_bypass_state_name(TtlBypassState::disabled)) ==
          "disabled");
}

TEST_CASE("an unanswerable chain outranks the switch") {
    TtlBypassInputs inputs;
    inputs.enabled = false;
    inputs.observation = TtlChainObservation::indeterminate;

    // We cannot remove what we cannot see. Claiming "disabled" here would
    // assert the rule is gone while it may still be installed.
    CHECK(plan_ttl_bypass(inputs).state == TtlBypassState::unknown);
    CHECK(plan_ttl_bypass(inputs).commands.empty());
}


TEST_CASE("the firewall default keeps the bypass on") {
    // A router that never touches the setting must get the fix. Every shipped
    // nfqws2 strategy depends on the TTL surviving, so the default is the one
    // that matters most.
    IptablesFirewall firewall;
    CHECK(firewall.ttl_bypass_enabled());
}

TEST_CASE("the configuration flag reaches the firewall") {
    IptablesFirewall firewall;

    firewall.set_ttl_bypass_enabled(false);
    CHECK_FALSE(firewall.ttl_bypass_enabled());
    firewall.set_ttl_bypass_enabled(true);
    CHECK(firewall.ttl_bypass_enabled());
}

TEST_CASE("TTL teardown verifies exact absence after deleting its rule") {
    std::deque<ControlResult> results{
        control_success(ttl_chain_with_owned_rule()),
        control_success(),
        control_success(empty_ttl_chain()),
    };
    std::vector<std::vector<std::string>> commands;
    ScopedIptablesControlRunner runner{
        [&](const std::vector<std::string>& command) {
            commands.push_back(command);
            REQUIRE_FALSE(results.empty());
            const auto result = results.front();
            results.pop_front();
            return result;
        }};

    IptablesFirewall firewall;
    firewall.remove_ttl_bypass_for_test();

    CHECK(results.empty());
    REQUIRE(commands.size() == 3);
    CHECK(commands.front() == std::vector<std::string>{
        "iptables", "-t", "mangle", "-S", kTtlChain});
    std::vector<std::string> expected_delete{"iptables"};
    const auto delete_argv = ttl_bypass_delete_argv();
    expected_delete.insert(
        expected_delete.end(), delete_argv.begin(), delete_argv.end());
    CHECK(commands[1] == expected_delete);
    CHECK(commands[2] == commands.front());
    CHECK(firewall.ttl_bypass_state() == TtlBypassState::missing);
    CHECK(firewall.ttl_bypass_detail().empty());
}

TEST_CASE("TTL teardown retries a transient delete before claiming absence") {
    std::deque<ControlResult> results{
        control_success(ttl_chain_with_owned_rule()),
        control_transient(),
        control_success(ttl_chain_with_owned_rule()),
        control_success(),
        control_success(empty_ttl_chain()),
    };
    ScopedIptablesControlRunner runner{
        [&](const std::vector<std::string>&) {
            REQUIRE_FALSE(results.empty());
            const auto result = results.front();
            results.pop_front();
            return result;
        }};

    IptablesFirewall firewall;
    firewall.remove_ttl_bypass_for_test();

    CHECK(results.empty());
    CHECK(firewall.ttl_bypass_state() == TtlBypassState::missing);
}

TEST_CASE("TTL teardown retains degraded state when inspection never converges") {
    std::size_t calls = 0;
    ScopedIptablesControlRunner runner{
        [&](const std::vector<std::string>&) {
            ++calls;
            return control_transient();
        }};

    IptablesFirewall firewall;
    firewall.remove_ttl_bypass_for_test();

    CHECK(calls == 5);
    CHECK(firewall.ttl_bypass_state() == TtlBypassState::unknown);
    CHECK_FALSE(firewall.ttl_bypass_detail().empty());
}

} // namespace keen_pbr3
