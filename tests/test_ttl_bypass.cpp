#include <doctest/doctest.h>

#include "firewall/ttl_bypass.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

TtlBypassInputs supported(std::vector<std::string> rules) {
    TtlBypassInputs inputs;
    inputs.chain_exists = true;
    inputs.chain_rules = std::move(rules);
    inputs.mark_match_available = true;
    inputs.comment_match_available = true;
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
    inputs.chain_exists = false;
    inputs.mark_match_available = true;
    inputs.comment_match_available = true;

    const auto plan = plan_ttl_bypass(inputs);

    // The firmware creates this chain only when `ip ttl-fix` is in play.
    // Creating it ourselves would make us the owner of a firmware chain.
    CHECK(plan.state == TtlBypassState::chain_absent);
    CHECK(plan.commands.empty());
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

} // namespace keen_pbr3
