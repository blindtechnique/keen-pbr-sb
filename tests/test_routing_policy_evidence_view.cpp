#ifdef WITH_API

#include <doctest/doctest.h>

#include "../src/api/routing_policy_evidence_view.hpp"

#include <stdexcept>

namespace keen_pbr3 {
namespace {

TestRoutingEntry policy_entry(const std::string& ip,
    std::optional<std::uint32_t> mark = 0x40000U) {
    TestRoutingEntry entry;
    entry.ip = ip;
    entry.expected_outbound = mark ? "vpn" : "(default)";
    entry.actual_outbound = entry.expected_outbound;
    entry.ok = true;
    entry.evaluation = mark ? RoutingMatchEvaluation::Matched : RoutingMatchEvaluation::NotMatched;
    entry.fib.verdict = RoutingFibVerdict::Resolved;
    entry.fib.fwmark = mark;
    return entry;
}

DumpedRule policy_rule(int family, std::uint32_t mark, std::uint32_t mask,
                       std::uint32_t priority = 100) {
    DumpedRule rule;
    rule.family = family;
    rule.fwmark = mark;
    rule.fwmask = mask;
    rule.priority = priority;
    rule.table = 152;
    return rule;
}

} // namespace

TEST_CASE("routing policy view reads each family once and aligns repeated destinations") {
    int v4_reads = 0, v6_reads = 0;
    const auto result = collect_routing_policy_evidence({
        policy_entry("203.0.113.8"), policy_entry("2001:DB8::8"),
        policy_entry("203.0.113.9"), policy_entry("2001:db8:0:0::9")},
        [&](int family) {
            if (family == AF_INET) ++v4_reads;
            else if (family == AF_INET6) ++v6_reads;
            return PolicyRuleSnapshot{true, family == AF_INET ? 100 : 200,
                {policy_rule(family, 0x40000U, 0xffff0000U)}};
        });
    REQUIRE(result.size() == 4);
    CHECK(v4_reads == 1);
    CHECK(v6_reads == 1);
    for (std::size_t index = 0; index < result.size(); ++index) {
        CHECK(result[index].status == RoutingPolicyEvidenceStatus::Observed);
        CHECK(result[index].evidence.snapshot_at == (index % 2 == 0 ? 100 : 200));
        REQUIRE(result[index].evidence.rules.size() == 1);
        CHECK(result[index].evidence.rules.front().family == (index % 2 == 0 ? AF_INET : AF_INET6));
    }
}

TEST_CASE("routing policy view skips unknown packet context invalid IPs and dropped paths") {
    std::vector<TestRoutingEntry> entries;
    auto unknown = policy_entry("203.0.113.8");
    unknown.actual_outbound = "(unknown)";
    entries.push_back(unknown);
    auto insufficient = policy_entry("203.0.113.9");
    insufficient.evaluation = RoutingMatchEvaluation::InsufficientContext;
    entries.push_back(insufficient);
    auto drop = policy_entry("2001:db8::8");
    drop.fib.verdict = RoutingFibVerdict::NotApplicable;
    entries.push_back(drop);
    entries.push_back(policy_entry("example.com"));
    entries.push_back(policy_entry("203.0.113.8/32"));
    entries.push_back(policy_entry("2001:db8:::8"));
    entries.push_back(policy_entry(std::string("203.0.113.8\0ignored", 19)));
    int reads = 0;
    const auto result = collect_routing_policy_evidence(entries, [&](int) {
        ++reads;
        return PolicyRuleSnapshot{true, 100, {}};
    });
    CHECK(reads == 0);
    REQUIRE(result.size() == entries.size());
    for (const auto& view : result) {
        CHECK(view.status == RoutingPolicyEvidenceStatus::NotApplicable);
        CHECK(view.evidence.rules.empty());
        const auto wire = nlohmann::json(to_api_routing_policy_evidence(view));
        CHECK(wire.at("status") == "not_applicable");
        CHECK(nlohmann::json(wire.get<api::PolicyRules>()) == wire);
    }
}

TEST_CASE("routing policy view queries conclusive direct routing with zero mark") {
    auto direct = policy_entry("203.0.113.8", std::nullopt);
    // A failed FIB read does not erase the conclusive unmarked packet context.
    direct.fib.verdict = RoutingFibVerdict::Unavailable;
    const auto result = collect_routing_policy_evidence({direct}, [](int family) {
        return PolicyRuleSnapshot{true, 100, {
            policy_rule(family, 0, 0xffffffffU, 10),
            policy_rule(family, 0x40000U, 0xffff0000U, 20),
            policy_rule(family, 0, 0, 30)}};
    });
    REQUIRE(result.size() == 1);
    CHECK(result.front().status == RoutingPolicyEvidenceStatus::Observed);
    REQUIRE(result.front().evidence.rules.size() == 2);
    CHECK(result.front().evidence.rules.at(0).priority == 10);
    CHECK(result.front().evidence.rules.at(1).priority == 30);
}

TEST_CASE("routing policy view preserves foreign bits of the realized packet mark") {
    const auto result = collect_routing_policy_evidence(
        {policy_entry("203.0.113.8", 0x80040001U)}, [](int family) {
            return PolicyRuleSnapshot{true, 100, {
                policy_rule(family, 0x80000000U, 0x80000000U, 10),
                policy_rule(family, 0, 0x80000000U, 20),
                policy_rule(family, 1, 1, 30)}};
        });
    REQUIRE(result.size() == 1);
    REQUIRE(result.front().evidence.rules.size() == 2);
    CHECK(result.front().evidence.rules.at(0).priority == 10);
    CHECK(result.front().evidence.rules.at(1).priority == 30);
}

TEST_CASE("routing policy view isolates failed reads without retrying each address") {
    bool throwing = false;
    SUBCASE("adapter returns an unavailable snapshot") {}
    SUBCASE("adapter unexpectedly throws") { throwing = true; }
    int v4_reads = 0, v6_reads = 0;
    const auto result = collect_routing_policy_evidence({
        policy_entry("203.0.113.8"), policy_entry("203.0.113.9"),
        policy_entry("2001:db8::8")}, [&](int family) -> PolicyRuleSnapshot {
            if (family == AF_INET) {
                ++v4_reads;
                if (throwing) throw std::runtime_error("injected netlink read failure");
                return {false, 100, {}};
            }
            ++v6_reads;
            return {true, 200, {}};
        });
    REQUIRE(result.size() == 3);
    CHECK(v4_reads == 1);
    CHECK(v6_reads == 1);
    CHECK(result.at(0).status == RoutingPolicyEvidenceStatus::Unavailable);
    CHECK(result.at(1).status == RoutingPolicyEvidenceStatus::Unavailable);
    CHECK(result.at(0).evidence.snapshot_at == (throwing ? 0 : 100));
    CHECK(result.at(1).evidence.snapshot_at == result.at(0).evidence.snapshot_at);
    CHECK(result.at(0).evidence.rules.empty());
    CHECK(result.at(1).evidence.rules.empty());
    CHECK(result.at(2).status == RoutingPolicyEvidenceStatus::Observed);
    CHECK(result.at(2).evidence.snapshot_at == 200);
    CHECK(result.at(2).evidence.rules.empty());
    const auto wire = nlohmann::json(to_api_routing_policy_evidence(result.front()));
    CHECK(wire.at("status") == "unavailable");
    CHECK(nlohmann::json(wire.get<api::PolicyRules>()) == wire);
}

TEST_CASE("routing policy view wire format preserves limits uncertainty and uint32 values") {
    const auto result = collect_routing_policy_evidence(
        {policy_entry("2001:db8::8", 0xffffffffU)}, [](int family) {
            PolicyRuleSnapshot snapshot{true, 123, {}};
            for (unsigned index = 0; index < 34; ++index) {
                auto rule = policy_rule(family, 0xffffffffU, 0xffffffffU, 100 + index);
                rule.table = 0xffffffffU;
                rule.exact_identity_representable = index != 0;
                snapshot.rules.push_back(rule);
            }
            return snapshot;
        });
    REQUIRE(result.size() == 1);
    const auto wire = nlohmann::json(to_api_routing_policy_evidence(result.front()));
    CHECK(wire.at("status") == "observed");
    CHECK(wire.at("snapshot_at") == 123);
    CHECK(wire.at("total") == 34);
    CHECK(wire.at("truncated") == true);
    REQUIRE(wire.at("rules").size() == 32);
    const auto& first = wire.at("rules").at(0);
    CHECK(first.at("family") == "ipv6");
    CHECK(first.at("priority") == 100);
    CHECK(first.at("table").get<std::int64_t>() == 4294967295LL);
    CHECK(first.at("fwmark").get<std::int64_t>() == 4294967295LL);
    CHECK(first.at("fwmask").get<std::int64_t>() == 4294967295LL);
    CHECK(first.at("details_complete") == false);
    CHECK(wire.at("rules").at(1).at("details_complete") == true);
    CHECK(nlohmann::json(wire.get<api::PolicyRules>()) == wire);
}

} // namespace keen_pbr3

#endif // WITH_API
