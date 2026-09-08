#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/routing_firewall_evidence_view.hpp"

#include <limits>
#include <stdexcept>

namespace keen_pbr3 {
namespace {

TestRoutingEntry counter_entry(const std::string& ip, std::optional<std::size_t> index) {
    TestRoutingEntry entry;
    entry.ip = ip;
    entry.actual_rule_index = index;
    entry.expected_rule_index = 99;
    entry.expected_outbound = "expected-vpn";
    entry.actual_outbound = index ? "actual-vpn" : "(default)";
    entry.list_match = ListMatchInfo{"expected-list", "example.com"};
    entry.evaluation = index ? RoutingMatchEvaluation::Matched : RoutingMatchEvaluation::NotMatched;
    entry.fib.verdict = RoutingFibVerdict::Resolved;
    entry.fib.fwmark = 0x80040001U;
    entry.fib.table = 152;
    entry.fib.interface = "nwg1";
    entry.ok = true;
    return entry;
}

RuleState counter_state(std::size_t index, RuleActionType action = RuleActionType::Mark) {
    RuleState state{};
    state.rule_index = index;
    state.list_names = {"actual-list", "other-list"};
    state.set_names = {"kpbr4s_actual-list", "kpbr4d_other-list"};
    state.action_type = action;
    state.fwmark = 0x40000U;
    return state;
}

FirewallClassifierEvidence counter_observation(const FirewallClassifierQuery& query) {
    FirewallClassifierEvidence result;
    result.status = FirewallCounterStatus::Observed;
    result.snapshot_at = 100;
    result.total = 1;
    FirewallClassifierCounter row;
    row.family = query.family;
    row.table = "raw";
    row.chain = "KeenPbrRaw_A";
    row.position = query.rule_index + 1;
    row.action = "mark";
    row.set_name = "kpbr4d_other-list";
    row.fwmark = 0x40000U;
    row.fwmask = 0xffff0000U;
    row.packets = query.rule_index;
    row.bytes = 1234;
    result.rules.push_back(row);
    return result;
}

} // namespace

TEST_CASE("routing firewall evidence uses realized rule indices and deduplicates per family") {
    std::vector<TestRoutingEntry> entries{
        counter_entry("203.0.113.8", 7), counter_entry("203.0.113.9", 7),
        counter_entry("2001:DB8::8", 7), counter_entry("203.0.113.10", 2)};
    // Neither field index is a position in this pruned/reordered vector.
    const std::vector<RuleState> states{counter_state(2), counter_state(7)};
    int reads = 0;
    attach_routing_firewall_evidence(entries, states, [&](const auto& queries) {
        ++reads;
        REQUIRE(queries.size() == 3);
        CHECK(queries.at(0).rule_index == 7);
        CHECK(queries.at(0).family == AF_INET);
        CHECK(queries.at(1).rule_index == 7);
        CHECK(queries.at(1).family == AF_INET6);
        CHECK(queries.at(2).rule_index == 2);
        std::vector<FirewallClassifierEvidence> evidence;
        for (const auto& query : queries) evidence.push_back(counter_observation(query));
        return evidence;
    });
    CHECK(reads == 1);
    for (const auto& entry : entries) {
        REQUIRE(entry.firewall_counters.has_value());
        CHECK(entry.firewall_counters->status == FirewallCounterStatus::Observed);
        REQUIRE(entry.firewall_counters->rules.size() == 1);
        CHECK(entry.firewall_counters->rules.front().packets == *entry.actual_rule_index);
        // Do not filter live classifiers by the expected/config list match.
        CHECK(entry.firewall_counters->rules.front().set_name == "kpbr4d_other-list");
        CHECK(entry.list_match->list_name == "expected-list");
        CHECK(entry.fib.fwmark == 0x80040001U);
    }
    CHECK(entries.at(2).firewall_counters->rules.front().family == AF_INET6);
}

TEST_CASE("routing firewall evidence skips no-classifier and uncertain packet paths") {
    std::vector<TestRoutingEntry> entries{
        counter_entry("203.0.113.8", std::nullopt),
        counter_entry("example.com", 7), counter_entry("2001:db8:::8", 7),
        counter_entry("203.0.113.8/32", 7),
        counter_entry(std::string("203.0.113.8\0ignored", 19), 7)};
    auto unknown = counter_entry("203.0.113.9", 7);
    unknown.evaluation = RoutingMatchEvaluation::InsufficientContext;
    entries.push_back(unknown);
    unknown.evaluation = RoutingMatchEvaluation::Matched;
    unknown.actual_outbound = "(unknown)";
    entries.push_back(unknown);
    int reads = 0;
    attach_routing_firewall_evidence(entries, {counter_state(7)}, [&](const auto&) {
        ++reads;
        return std::vector<FirewallClassifierEvidence>{};
    });
    CHECK(reads == 0);
    for (const auto& entry : entries) {
        REQUIRE(entry.firewall_counters.has_value());
        CHECK(entry.firewall_counters->status == FirewallCounterStatus::NotApplicable);
        CHECK(entry.firewall_counters->rules.empty());
    }
}

TEST_CASE("routing firewall evidence missing captured rule is unavailable not another vector position") {
    std::vector<TestRoutingEntry> entries{counter_entry("203.0.113.8", 0)};
    int reads = 0;
    attach_routing_firewall_evidence(entries, {counter_state(7)}, [&](const auto&) {
        ++reads;
        return std::vector<FirewallClassifierEvidence>{};
    });
    CHECK(reads == 0);
    REQUIRE(entries.front().firewall_counters.has_value());
    CHECK(entries.front().firewall_counters->status == FirewallCounterStatus::Unavailable);
}

TEST_CASE("routing firewall evidence includes DROP and PASS even without applicable FIB") {
    std::vector<TestRoutingEntry> entries{
        counter_entry("203.0.113.8", 7), counter_entry("203.0.113.9", 2)};
    entries.at(0).fib.verdict = RoutingFibVerdict::NotApplicable;
    entries.at(0).fib.fwmark.reset();
    entries.at(1).fib.fwmark.reset();
    int reads = 0;
    attach_routing_firewall_evidence(entries,
        {counter_state(7, RuleActionType::Drop), counter_state(2, RuleActionType::Pass)},
        [&](const auto& queries) {
            ++reads;
            REQUIRE(queries.size() == 2);
            auto drop = counter_observation(queries.at(0));
            drop.rules.front().action = "drop";
            drop.rules.front().fwmark.reset();
            drop.rules.front().fwmask.reset();
            auto pass = counter_observation(queries.at(1));
            pass.rules.front().action = "pass";
            pass.rules.front().fwmark.reset();
            pass.rules.front().fwmask.reset();
            return std::vector<FirewallClassifierEvidence>{drop, pass};
        });
    CHECK(reads == 1);
    const auto drop = to_api_routing_firewall_evidence(*entries.at(0).firewall_counters);
    const auto pass = to_api_routing_firewall_evidence(*entries.at(1).firewall_counters);
    REQUIRE(drop.rules.size() == 1);
    REQUIRE(pass.rules.size() == 1);
    CHECK(drop.rules.front().action == api::RoutingTestFirewallCounterAction::DROP);
    CHECK(pass.rules.front().action == api::RoutingTestFirewallCounterAction::PASS);
    CHECK_FALSE(drop.rules.front().fwmark.has_value());
    CHECK_FALSE(drop.rules.front().fwmask.has_value());
    CHECK_FALSE(pass.rules.front().fwmark.has_value());
}

TEST_CASE("routing firewall evidence read errors preserve the completed base result") {
    bool throwing = false;
    SUBCASE("reader throws") { throwing = true; }
    SUBCASE("reader returns a misaligned partial vector") {}
    std::vector<TestRoutingEntry> entries{
        counter_entry("203.0.113.8", 7), counter_entry("203.0.113.9", 7)};
    int reads = 0;
    attach_routing_firewall_evidence(entries, {counter_state(7)}, [&](const auto& queries) {
        ++reads;
        CHECK(queries.size() == 1);
        if (throwing) throw std::runtime_error("injected counter read failure");
        return std::vector<FirewallClassifierEvidence>{};
    });
    CHECK(reads == 1);
    for (const auto& entry : entries) {
        CHECK(entry.firewall_counters->status == FirewallCounterStatus::Unavailable);
        CHECK(entry.firewall_counters->rules.empty());
        CHECK(entry.ok);
        CHECK(entry.actual_outbound == "actual-vpn");
        CHECK(entry.actual_rule_index == 7);
        CHECK(entry.fib.table == 152);
        CHECK(entry.fib.interface == "nwg1");
        CHECK(entry.list_match->list_name == "expected-list");
    }
}

TEST_CASE("routing firewall evidence DTO preserves ambiguity truncation and uint64 counters") {
    FirewallClassifierEvidence evidence = counter_observation({7, AF_INET6});
    evidence.status = FirewallCounterStatus::Ambiguous;
    evidence.total = 40;
    evidence.truncated = true;
    auto& row = evidence.rules.front();
    row.fwmark = 0xffffffffU;
    row.fwmask = 0;
    row.packets = std::numeric_limits<std::uint64_t>::max();
    row.bytes = 9007199254740993ULL;
    const auto dto = to_api_routing_firewall_evidence(evidence);
    CHECK(dto.status == api::RoutingTestFirewallCountersStatus::AMBIGUOUS);
    CHECK(dto.scope == api::RoutingTestFirewallCountersScope::PREROUTING);
    CHECK(dto.total == 40);
    CHECK(dto.truncated);
    CHECK(dto.snapshot_at == 100);
    REQUIRE(dto.rules.size() == 1);
    CHECK(dto.rules.front().family == api::Family::IPV6);
    CHECK(dto.rules.front().table == "raw");
    CHECK(dto.rules.front().chain == "KeenPbrRaw_A");
    CHECK(dto.rules.front().position == 8);
    CHECK(dto.rules.front().fwmark == 4294967295LL);
    CHECK(dto.rules.front().fwmask == 0);
    CHECK(dto.rules.front().packets == "18446744073709551615");
    CHECK(dto.rules.front().bytes == "9007199254740993");
    const auto wire = nlohmann::json(dto);
    CHECK(wire.at("status") == "ambiguous");
    CHECK(wire.at("scope") == "prerouting");
    CHECK(nlohmann::json(wire.get<api::FirewallCounters>()) == wire);
    for (const auto status : {FirewallCounterStatus::Observed, FirewallCounterStatus::Unavailable,
                             FirewallCounterStatus::NotApplicable}) {
        evidence.status = status;
        evidence.rules.clear();
        const auto other = nlohmann::json(to_api_routing_firewall_evidence(evidence));
        CHECK(nlohmann::json(other.get<api::FirewallCounters>()) == other);
    }
}

} // namespace keen_pbr3

#endif // WITH_API
