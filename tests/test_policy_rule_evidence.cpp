#include "../src/routing/policy_rule_evidence.hpp"

#include <doctest/doctest.h>

#include <netinet/in.h>
#include <stdexcept>

namespace keen_pbr3 {
namespace {

DumpedRule rule(std::uint32_t priority, std::uint32_t mark,
                std::uint32_t mask, std::uint32_t table,
                int family = AF_INET, bool exact = true) {
    return {priority, mark, mask, table, family, exact};
}

} // namespace

TEST_CASE("policy rule evidence compares the complete mark mask and family") {
    PolicyRuleSnapshot snapshot{true, 1234, {
        rule(400, 0, 0, 254),
        rule(200, 0x00020000, 0x00ff0000, 152),
        rule(100, 0x80020000, 0x80ff0000, 153),
        rule(300, 0x00020000, 0x80ff0000, 154),
        rule(500, 0x00020000, 0x00ff0000, 155, AF_INET6),
        rule(600, 0x80020001, 0xffffffff, 156)}};

    const auto evidence = select_policy_rule_evidence(
        snapshot, AF_INET, 0x80020000);
    REQUIRE(evidence.rules.size() == 3);
    CHECK(evidence.rules[0].table == 153);
    CHECK(evidence.rules[1].table == 152);
    CHECK(evidence.rules[2].table == 254);
    CHECK(evidence.available);
    CHECK(evidence.snapshot_at == 1234);
    CHECK(evidence.total == 3);
    CHECK_FALSE(evidence.truncated);
    CHECK(snapshot.rules[0].priority == 400);

    const auto ipv6 = select_policy_rule_evidence(snapshot, AF_INET6, 0x20000);
    REQUIRE(ipv6.rules.size() == 1);
    CHECK(ipv6.rules[0].table == 155);
    const auto unmarked = select_policy_rule_evidence(snapshot, AF_INET, 0);
    REQUIRE(unmarked.rules.size() == 1);
    CHECK(unmarked.rules[0].table == 254);
}

TEST_CASE("policy rule evidence retains inexact rows even when marks disagree") {
    const PolicyRuleSnapshot snapshot{true, 9, {
        rule(100, 0x10000, 0xffff0000, 150, AF_INET, false),
        rule(200, 0x10000, 0xffff0000, 151),
        rule(300, 0, 0, 0, AF_INET, false),
        rule(50, 0, 0, 152, AF_INET6, false)}};
    const auto evidence = select_policy_rule_evidence(snapshot, AF_INET, 0x20000);
    REQUIRE(evidence.rules.size() == 2);
    CHECK(evidence.rules[0].table == 150);
    CHECK_FALSE(evidence.rules[0].exact_identity_representable);
    CHECK(evidence.rules[1].table == 0);
    CHECK_FALSE(evidence.rules[1].exact_identity_representable);
}

TEST_CASE("policy rule evidence caps after stable priority sorting") {
    PolicyRuleSnapshot snapshot{true, 10, {}};
    for (std::uint32_t index = 0; index < 40; ++index) {
        snapshot.rules.push_back(rule(40 - index, 0, 0, index));
    }
    snapshot.rules.push_back(rule(1, 0, 0, 999));
    const auto evidence = select_policy_rule_evidence(snapshot, AF_INET, 0);
    CHECK(evidence.total == 41);
    CHECK(evidence.truncated);
    REQUIRE(evidence.rules.size() == 32);
    CHECK(evidence.rules[0].table == 39);
    CHECK(evidence.rules[1].table == 999);
    CHECK(evidence.rules.back().priority == 31);
    CHECK(snapshot.rules.size() == 41);
}

TEST_CASE("policy rule evidence distinguishes an empty snapshot from unavailable") {
    PolicyRuleSnapshot snapshot{true, 15, {}};
    auto evidence = select_policy_rule_evidence(snapshot, AF_INET, 0x20000);
    CHECK(evidence.available);
    CHECK(evidence.rules.empty());
    CHECK(evidence.total == 0);
    CHECK_FALSE(evidence.truncated);

    snapshot.available = false;
    snapshot.rules.push_back(rule(100, 0, 0, 150));
    evidence = select_policy_rule_evidence(snapshot, AF_INET, 0x20000);
    CHECK_FALSE(evidence.available);
    CHECK(evidence.snapshot_at == 15);
    CHECK(evidence.rules.empty());
    CHECK(evidence.total == 0);
    CHECK_FALSE(evidence.truncated);
}

TEST_CASE("policy rule snapshot captures injected inventory without kernel access") {
    const auto snapshot = policy_rule_evidence_detail::capture_policy_rule_snapshot(
        AF_INET6, 123, [](int family) {
            return std::vector<DumpedRule>{rule(100, 0, 0, 254, family)};
        });
    CHECK(snapshot.available);
    CHECK(snapshot.snapshot_at == 123);
    REQUIRE(snapshot.rules.size() == 1);
    CHECK(snapshot.rules[0].family == AF_INET6);
}

TEST_CASE("policy rule snapshot does not expose partial inventory after read errors") {
    using Reader = policy_rule_evidence_detail::PolicyRuleDump;
    Reader reader = [](int) -> std::vector<DumpedRule> {
        const std::vector<DumpedRule> partial{rule(100, 0, 0, 254)};
        throw NetlinkError("interrupted raw dump");
    };
    SUBCASE("netlink failure") {}
    SUBCASE("other reader failure") {
        reader = [](int) -> std::vector<DumpedRule> {
            throw std::runtime_error("reader failure");
        };
    }
    const auto snapshot = policy_rule_evidence_detail::capture_policy_rule_snapshot(
        AF_INET, 456, reader);
    CHECK_FALSE(snapshot.available);
    CHECK(snapshot.snapshot_at == 456);
    CHECK(snapshot.rules.empty());
}

} // namespace keen_pbr3
