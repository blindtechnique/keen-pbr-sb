#include "../src/firewall/rule_counter_evidence.hpp"

#include <doctest/doctest.h>

#include <limits>
#include <stdexcept>

namespace keen_pbr3 {
namespace {

RuleState counter_state(std::size_t index, std::string set_name = "kpbr4_sample",
                        RuleActionType action = RuleActionType::Mark,
                        std::uint32_t mark = 0x40000) {
    RuleState state{};
    state.rule_index = index;
    if (!set_name.empty()) {
        state.set_names = {set_name};
        state.list_names = {"sample"};
    }
    state.action_type = action;
    state.fwmark = mark;
    state.outbound_tag = "vpn";
    return state;
}

std::string counter_save(const std::string& table, const std::string& chain,
                         const std::string& rules) {
    return "*" + table + "\n:" + chain + " - [0:0]\n" + rules + "COMMIT\n";
}

std::string counter_mark(const std::string& chain, const std::string& set,
                         std::string counts = "[7:700]", std::string extra = "") {
    return counts + " -A " + chain + " -m set --match-set " + set +
        " dst" + extra + " -j MARK --set-xmark 0x40000/0xffff0000\n";
}

nlohmann::json nft_counter_rule(int family, const std::string& set,
                               std::uint64_t packets = 7, std::uint64_t bytes = 700,
                               std::uint32_t mark = 0x40000,
                               std::uint32_t mask = 0xffff0000) {
    auto expr = nlohmann::json::array();
    if (!set.empty()) {
        expr.push_back({{"match", {{"op", "=="},
            {"left", {{"payload", {{"protocol", family == AF_INET6 ? "ip6" : "ip"}, {"field", "daddr"}}}}},
            {"right", "@" + set}}}});
    } else {
        expr.push_back({{"match", {{"op", "=="},
            {"left", {{"meta", {{"key", "l4proto"}}}}}, {"right", "tcp"}}}});
        expr.push_back({{"match", {{"op", "=="},
            {"left", {{"payload", {{"protocol", "tcp"}, {"field", "dport"}}}}}, {"right", 443}}}});
    }
    expr.push_back({{"counter", {{"packets", packets}, {"bytes", bytes}}}});
    expr.push_back({{"mangle", {{"key", {{"meta", {{"key", "mark"}}}}},
        {"value", {{"|", nlohmann::json::array({
            {{"&", nlohmann::json::array({{{"meta", {{"key", "mark"}}}}, ~mask | mark})}}, mark})}}}}}});
    expr.push_back({{"accept", nullptr}});
    return {{"rule", {{"family", "inet"}, {"table", "KeenPbrTable"},
        {"chain", "prerouting"}, {"handle", 77}, {"expr", expr}}}};
}

std::string nft_counter_dump(const std::vector<nlohmann::json>& rules) {
    nlohmann::json entries = nlohmann::json::array({
        {{"chain", {{"family", "inet"}, {"table", "KeenPbrTable"},
            {"name", "prerouting"}, {"hook", "prerouting"}}}}});
    for (const auto& row : rules) entries.push_back(row);
    return nlohmann::json{{"nftables", entries}}.dump();
}

} // namespace

TEST_CASE("firewall counters read RAW IPv4 and mangle IPv6 once per request") {
    auto state = counter_state(4);
    state.set_names.push_back("kpbr6_sample");
    state.fwmark_ipv6 = 0x50000;
    int reads4 = 0, reads6 = 0;
    const auto result = collect_firewall_counter_evidence(FirewallBackend::iptables,
        RawPreroutingMode{true, false}, {state}, {{4, AF_INET}, {4, AF_INET6}, {4, AF_INET}},
        0xffff0000, std::nullopt, [&](const std::vector<std::string>& args) {
            if (args[0] == "iptables-save") {
                CHECK(args == std::vector<std::string>{"iptables-save", "-c", "-t", "raw"});
                ++reads4;
                return CommandResult{counter_save("raw", "KeenPbrRaw",
                    counter_mark("KeenPbrRaw", "kpbr4_sample", "[18446744073709551615:18446744073709551614]")), 0, false};
            }
            CHECK(args == std::vector<std::string>{"ip6tables-save", "-c", "-t", "mangle"});
            ++reads6;
            return CommandResult{counter_save("mangle", "KeenPbrTable",
                "[0:0] -A KeenPbrTable -m set --match-set kpbr6_sample dst -j MARK --set-xmark 0x50000/0xffff0000\n"), 0, false};
        });
    REQUIRE(result.size() == 3);
    CHECK(reads4 == 1);
    CHECK(reads6 == 1);
    for (const auto& evidence : result) {
        CHECK(evidence.status == FirewallCounterStatus::Observed);
        CHECK(evidence.snapshot_at > 0);
        REQUIRE(evidence.rules.size() == 1);
        CHECK(evidence.rules[0].position == 1);
    }
    CHECK(result[0].rules[0].packets == std::numeric_limits<std::uint64_t>::max());
    CHECK(result[0].rules[0].bytes == std::numeric_limits<std::uint64_t>::max() - 1);
    CHECK(result[0].rules[0].table == "raw");
    CHECK(result[1].rules[0].packets == 0);
    CHECK(result[1].rules[0].family == AF_INET6);
    CHECK(result[1].rules[0].fwmark == 0x50000);
    CHECK(result[0].snapshot_at == result[2].snapshot_at);
}

TEST_CASE("firewall counters use only active generation and not MARK helper tails") {
    const auto mark = counter_state(1);
    const auto drop = counter_state(2, "kpbr4_blocked", RuleActionType::Drop);
    const auto pass = counter_state(3, "kpbr4_direct", RuleActionType::Pass);
    const std::string output =
        "*mangle\n:KeenPbrTable - [0:0]\n:KeenPbrTable_A - [0:0]\n:KeenPbrTable_B - [0:0]\n"
        "[1:1] -A KeenPbrTable -j KeenPbrTable_B\n" +
        counter_mark("KeenPbrTable_A", "kpbr4s_sample", "[9999:99999]") +
        counter_mark("KeenPbrTable_B", "kpbr4S_sample", "[10:1000]") +
        "[10:1000] -A KeenPbrTable_B -m set --match-set kpbr4S_sample dst -j CONNMARK --save-mark --nfmask 0xffff0000 --ctmask 0xffff0000\n"
        "[10:1000] -A KeenPbrTable_B -m set --match-set kpbr4S_sample dst -j RETURN\n"
        "[2:200] -A KeenPbrTable_B -m set --match-set kpbr4_blocked dst -j DROP\n"
        "[3:300] -A KeenPbrTable_B -m set --match-set kpbr4_direct dst -j RETURN\nCOMMIT\n";
    const auto result = collect_firewall_counter_evidence(FirewallBackend::iptables, {},
        {mark, drop, pass}, {{1, AF_INET}, {2, AF_INET}, {3, AF_INET}}, 0xffff0000, std::nullopt,
        [&](const auto&) { return CommandResult{output, 0, false}; });
    REQUIRE(result.size() == 3);
    for (const auto& evidence : result) {
        CHECK(evidence.status == FirewallCounterStatus::Observed);
        CHECK(evidence.total == 1);
        REQUIRE(evidence.rules.size() == 1);
        CHECK(evidence.rules[0].chain == "KeenPbrTable_B");
    }
    CHECK(result[0].rules[0].packets == 10);
    CHECK(result[0].rules[0].action == "mark");
    CHECK(result[1].rules[0].position == 4);
    CHECK(result[1].rules[0].action == "drop");
    CHECK_FALSE(result[1].rules[0].fwmark.has_value());
    CHECK(result[2].rules[0].action == "pass");
}

TEST_CASE("firewall counters do not attribute another selector or duplicate config owner") {
    auto tcp = counter_state(1);
    tcp.criteria.proto = L4Proto::Tcp;
    auto udp = counter_state(2);
    udp.criteria.proto = L4Proto::Udp;
    const auto output = counter_save("mangle", "KeenPbrTable",
        counter_mark("KeenPbrTable", "kpbr4_sample", "[11:110]", " -p tcp -i br0") +
        counter_mark("KeenPbrTable", "kpbr4_sample", "[22:220]", " -p udp"));
    auto states = std::vector<RuleState>{tcp, udp};
    bool duplicated = false;
    SUBCASE("different protocol selectors remain distinct") {}
    SUBCASE("indistinguishable config rules are ambiguous") {
        auto duplicate = tcp;
        duplicate.rule_index = 3;
        states.push_back(duplicate);
        duplicated = true;
    }
    const auto result = collect_firewall_counter_evidence(FirewallBackend::iptables, {},
        states, {{1, AF_INET}, {2, AF_INET}}, 0xffff0000, std::nullopt,
        [&](const auto&) { return CommandResult{output, 0, false}; });
    CHECK(result[0].status == (duplicated ? FirewallCounterStatus::Ambiguous : FirewallCounterStatus::Observed));
    if (duplicated) CHECK(result[0].rules.empty());
    else {
        REQUIRE(result[0].rules.size() == 1);
        CHECK(result[0].rules[0].packets == 11);
    }
    CHECK(result[1].status == FirewallCounterStatus::Observed);
    REQUIRE(result[1].rules.size() == 1);
    CHECK(result[1].rules[0].packets == 22);
}

TEST_CASE("firewall counters never turn absent malformed or failed reads into zero") {
    CommandResult output{counter_save("mangle", "KeenPbrTable",
        counter_mark("KeenPbrTable", "kpbr4_sample")), 0, false};
    bool throwing = false, ambiguous = false;
    SUBCASE("nonzero exit") { output.exit_code = 1; }
    SUBCASE("truncated capture") { output.truncated = true; }
    SUBCASE("missing COMMIT") { output.stdout_output.erase(output.stdout_output.find("COMMIT")); }
    SUBCASE("oversized capture") { output.stdout_output.assign(256U * 1024U + 1U, 'x'); }
    SUBCASE("reader exception") { throwing = true; }
    SUBCASE("counter prefix absent") {
        output.stdout_output = counter_save("mangle", "KeenPbrTable",
            counter_mark("KeenPbrTable", "kpbr4_sample", ""));
        ambiguous = true;
    }
    SUBCASE("counter uint64 overflow") {
        output.stdout_output = counter_save("mangle", "KeenPbrTable",
            counter_mark("KeenPbrTable", "kpbr4_sample", "[18446744073709551616:7]"));
        ambiguous = true;
    }
    SUBCASE("unknown match is not silently removed") {
        output.stdout_output = counter_save("mangle", "KeenPbrTable",
            counter_mark("KeenPbrTable", "kpbr4_sample", "[0:0]", " -m conntrack --ctstate NEW"));
        ambiguous = true;
    }
    SUBCASE("uint32 mark and mask overflow do not inherit verifier truncation") {
        output.stdout_output = counter_save("mangle", "KeenPbrTable",
            "[7:700] -A KeenPbrTable -m set --match-set kpbr4_sample dst -j MARK --set-xmark 0x100040000/0x1ffff0000\n");
        ambiguous = true;
    }
    SUBCASE("mark trailing garbage is not an exact token") {
        output.stdout_output = counter_save("mangle", "KeenPbrTable",
            "[7:700] -A KeenPbrTable -m set --match-set kpbr4_sample dst -j MARK --set-xmark 0x40000junk/0xffff0000\n");
        ambiguous = true;
    }
    const auto result = collect_firewall_counter_evidence(FirewallBackend::iptables, {},
        {counter_state(1)}, {{1, AF_INET}, {1, AF_INET}}, 0xffff0000, std::nullopt,
        [&](const auto&) -> CommandResult {
            if (throwing) throw std::runtime_error("injected");
            return output;
        });
    for (const auto& evidence : result) {
        CHECK(evidence.status == (ambiguous ? FirewallCounterStatus::Ambiguous : FirewallCounterStatus::Unavailable));
        CHECK(evidence.rules.empty());
        CHECK(evidence.total == 0);
    }
}

TEST_CASE("firewall counters bound result rows and input expansion before commands") {
    auto state = counter_state(1);
    std::string lines;
    for (int i = 0; i < 40; ++i) {
        lines += counter_mark("KeenPbrTable", "kpbr4_sample", "[1:10]", " -i br" + std::to_string(i));
    }
    bool too_large = false;
    SUBCASE("32 response rows retain a truthful total") {}
    SUBCASE("large Cartesian expected expansion stays diagnostic-only unavailable") {
        state.criteria.src_addr.assign(4097, "192.168.1.0/24");
        too_large = true;
    }
    int reads = 0;
    const auto result = collect_firewall_counter_evidence(FirewallBackend::iptables, {},
        {state}, {{1, AF_INET}}, 0xffff0000, std::nullopt, [&](const auto&) {
            ++reads;
            return CommandResult{counter_save("mangle", "KeenPbrTable", lines), 0, false};
        });
    if (too_large) {
        CHECK(reads == 0);
        CHECK(result[0].status == FirewallCounterStatus::Unavailable);
        CHECK(result[0].rules.empty());
    } else {
        CHECK(reads == 1);
        CHECK(result[0].status == FirewallCounterStatus::Observed);
        CHECK(result[0].total == 40);
        CHECK(result[0].truncated);
        CHECK(result[0].rules.size() == 32);
    }
}

TEST_CASE("firewall counters share one nft snapshot and recognize generated masked assignments") {
    auto state = counter_state(4);
    state.set_names.push_back("kpbr6_sample");
    state.fwmark_ipv6 = 0x50000;
    auto first = nft_counter_rule(AF_INET, "kpbr4_sample", 0, 0);
    // The generated conntrack-save action does not contribute another counter.
    first["rule"]["expr"].insert(first["rule"]["expr"].end() - 1,
        nlohmann::json{{"mangle", {{"key", {{"ct", {{"key", "mark"}}}}}, {"value", 0x40000}}}});
    const auto output = nft_counter_dump({
        first, nft_counter_rule(AF_INET6, "kpbr6_sample", 55, 5500, 0x50000)});
    int reads = 0;
    const auto result = collect_firewall_counter_evidence(FirewallBackend::nftables, {},
        {state}, {{4, AF_INET6}, {4, AF_INET}, {4, AF_INET6}}, 0xffff0000, std::nullopt,
        [&](const auto& args) {
            CHECK(args == std::vector<std::string>{"nft", "-j", "list", "chain", "inet", "KeenPbrTable", "prerouting"});
            ++reads;
            return CommandResult{output, 0, false};
        });
    CHECK(reads == 1);
    for (const auto& evidence : result) {
        CHECK(evidence.status == FirewallCounterStatus::Observed);
        REQUIRE(evidence.rules.size() == 1);
        CHECK(evidence.rules[0].fwmask == 0xffff0000);
        CHECK(evidence.rules[0].action == "mark");
    }
    CHECK(result[0].rules[0].family == AF_INET6);
    CHECK(result[0].rules[0].fwmark == 0x50000);
    CHECK(result[0].rules[0].packets == 55);
    CHECK(result[1].rules[0].packets == 0);
}

TEST_CASE("firewall counters mark incomplete nft identities ambiguous without guessing masks") {
    auto row = nft_counter_rule(AF_INET, "kpbr4_sample");
    auto state = counter_state(1);
    SUBCASE("additional unknown match") {
        row["rule"]["expr"].insert(row["rule"]["expr"].begin(),
            nlohmann::json{{"match", {{"op", "=="}, {"left", {{"ct", {{"key", "state"}}}}}, {"right", "new"}}}});
    }
    SUBCASE("incompatible assignment mask") {
        row = nft_counter_rule(AF_INET, "kpbr4_sample", 7, 700, 0x40000, 0xff000000);
    }
    SUBCASE("counter absent") { row["rule"]["expr"].erase(1); }
    SUBCASE("counter malformed") { row["rule"]["expr"][1]["counter"]["packets"] = -1; }
    SUBCASE("counter appears after terminal verdict") {
        auto count = row["rule"]["expr"][1];
        row["rule"]["expr"].erase(1);
        row["rule"]["expr"].push_back(count);
    }
    SUBCASE("unsupported address set items are not discarded from identity") {
        state.criteria.src_addr = {"192.0.2.1"};
        row["rule"]["expr"].insert(row["rule"]["expr"].begin(),
            nlohmann::json{{"match", {{"op", "=="},
                {"left", {{"payload", {{"protocol", "ip"}, {"field", "saddr"}}}}},
                {"right", {{"set", nlohmann::json::array({"192.0.2.1", {{"unsupported", true}}})}}}}}});
    }
    SUBCASE("repeated address selectors are not overwritten in identity") {
        state.criteria.src_addr = {"192.0.2.1"};
        row["rule"]["expr"].insert(row["rule"]["expr"].begin(),
            nlohmann::json{{"match", {{"op", "=="},
                {"left", {{"payload", {{"protocol", "ip"}, {"field", "saddr"}}}}},
                {"right", "192.0.2.1"}}}});
        row["rule"]["expr"].insert(row["rule"]["expr"].begin(),
            nlohmann::json{{"match", {{"op", "=="},
                {"left", {{"payload", {{"protocol", "ip"}, {"field", "saddr"}}}}},
                {"right", "192.0.2.0/24"}}}});
    }
    const auto result = collect_firewall_counter_evidence(FirewallBackend::nftables, {},
        {state}, {{1, AF_INET}}, 0xffff0000, std::nullopt,
        [&](const auto&) { return CommandResult{nft_counter_dump({row}), 0, false}; });
    CHECK(result[0].status == FirewallCounterStatus::Ambiguous);
    CHECK(result[0].rules.empty());
}

TEST_CASE("firewall counters do not label combined-family nft totals as IPv4 or IPv6") {
    auto state = counter_state(1, "");
    state.criteria.proto = L4Proto::Tcp;
    state.criteria.dst_port = "443";
    const auto result = collect_firewall_counter_evidence(FirewallBackend::nftables, {},
        {state}, {{1, AF_INET}, {1, AF_INET6}}, 0xffff0000, std::nullopt,
        [&](const auto&) {
            return CommandResult{nft_counter_dump({nft_counter_rule(AF_UNSPEC, "")}), 0, false};
        });
    CHECK(result[0].status == FirewallCounterStatus::Ambiguous);
    CHECK(result[1].status == FirewallCounterStatus::Ambiguous);
}

TEST_CASE("firewall counters skip inapplicable queries and honor an expired caller budget") {
    const auto active = counter_state(1);
    const auto skip = counter_state(2, "kpbr4_other", RuleActionType::Skip);
    int reads = 0;
    const auto result = collect_firewall_counter_evidence(FirewallBackend::iptables, {},
        {active, skip}, {{1, AF_INET}, {2, AF_INET}, {3, AF_INET}, {1, AF_UNSPEC}},
        0xffff0000, std::chrono::steady_clock::now() - std::chrono::seconds(1),
        [&](const auto&) { ++reads; return CommandResult{}; });
    CHECK(reads == 0);
    CHECK(result[0].status == FirewallCounterStatus::Unavailable);
    CHECK(result[1].status == FirewallCounterStatus::NotApplicable);
    CHECK(result[2].status == FirewallCounterStatus::Unavailable);
    CHECK(result[3].status == FirewallCounterStatus::NotApplicable);
}

} // namespace keen_pbr3
