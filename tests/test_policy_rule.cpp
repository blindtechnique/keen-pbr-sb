#include <doctest/doctest.h>

#include "../src/routing/policy_rule.hpp"

#include <algorithm>
#include <iterator>
#include <netinet/in.h>
#include <stdexcept>
#include <vector>

namespace keen_pbr3 {
namespace {

class FakeRuleNetlink : public RuleNetlinkOperations {
public:
    RuleAddResult add_rule_for_family(const RuleSpec& spec, int family) override {
        added.push_back(family);
        if (family == failing_family) {
            throw std::runtime_error("injected failure");
        }
        if (family == existing_family || has_live(spec, family)) {
            add_live(spec, family);
            return RuleAddResult::AlreadyPresent;
        }
        add_live(spec, family);
        return RuleAddResult::Created;
    }

    void delete_rule_for_family(const RuleSpec& spec, int family) override {
        deleted.push_back(family);
        erase_live(spec, family);
    }

    std::vector<DumpedRule> dump_policy_rules(int family = 0) override {
        if (family == 0) {
            return live;
        }
        std::vector<DumpedRule> result;
        std::copy_if(
            live.begin(),
            live.end(),
            std::back_inserter(result),
            [family](const DumpedRule& rule) {
                return rule.family == family;
            });
        return result;
    }

    void add_live(const RuleSpec& spec, int family) {
        if (has_live(spec, family)) {
            return;
        }
        live.push_back({
            spec.priority,
            spec.fwmark,
            spec.fwmask,
            spec.table,
            family,
        });
    }

    void erase_live(const RuleSpec& spec, int family) {
        live.erase(
            std::remove_if(
                live.begin(),
                live.end(),
                [&](const DumpedRule& rule) {
                    return matches(rule, spec, family);
                }),
            live.end());
    }

    int failing_family{0};
    int existing_family{0};
    std::vector<int> added;
    std::vector<int> deleted;
    std::vector<DumpedRule> live;

private:
    static bool matches(const DumpedRule& live_rule,
                        const RuleSpec& spec,
                        int family) {
        return live_rule.priority == spec.priority &&
               live_rule.fwmark == spec.fwmark &&
               live_rule.fwmask == spec.fwmask &&
               live_rule.table == spec.table &&
               live_rule.family == family;
    }

    bool has_live(const RuleSpec& spec, int family) const {
        return std::any_of(
            live.begin(),
            live.end(),
            [&](const DumpedRule& rule) {
                return matches(rule, spec, family);
            });
    }
};

RuleSpec dual_stack_rule() {
    RuleSpec rule;
    rule.fwmark = 10;
    rule.table = 110;
    rule.priority = 10010;
    return rule;
}

} // namespace

TEST_CASE("PolicyRuleManager rolls back IPv4 when IPv6 add fails") {
    FakeRuleNetlink netlink;
    netlink.failing_family = AF_INET6;
    PolicyRuleManager rules(netlink);

    CHECK_THROWS(rules.add(dual_stack_rule()));
    CHECK(rules.size() == 0);
    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front() == AF_INET);
}

TEST_CASE("PolicyRuleManager does not delete a pre-existing rule during rollback") {
    FakeRuleNetlink netlink;
    netlink.existing_family = AF_INET;
    netlink.failing_family = AF_INET6;
    PolicyRuleManager rules(netlink);

    CHECK_THROWS(rules.add(dual_stack_rule()));
    CHECK(netlink.deleted.empty());
}

TEST_CASE("PolicyRuleManager clears only concrete rules it created") {
    FakeRuleNetlink netlink;
    netlink.existing_family = AF_INET6;
    PolicyRuleManager rules(netlink);
    rules.add(dual_stack_rule());
    rules.clear();

    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front() == AF_INET);
}

TEST_CASE("PolicyRuleManager reconciliation leaves an identical plan untouched") {
    FakeRuleNetlink netlink;
    PolicyRuleManager rules(netlink);
    const auto rule = dual_stack_rule();
    rules.add(rule);
    netlink.added.clear();
    netlink.deleted.clear();

    rules.reconcile({rule});

    CHECK(netlink.added.empty());
    CHECK(netlink.deleted.empty());
}

TEST_CASE("PolicyRuleManager adopts desired state without claiming ownership") {
    FakeRuleNetlink netlink;
    PolicyRuleManager rules(netlink);

    rules.adopt_desired({dual_stack_rule()});
    rules.clear();

    CHECK(netlink.deleted.empty());
}

TEST_CASE("PolicyRuleManager restores a vanished IPv4 rule without claiming live IPv6") {
    FakeRuleNetlink netlink;
    const auto rule = dual_stack_rule();
    netlink.add_live(rule, AF_INET6);
    PolicyRuleManager rules(netlink);
    rules.adopt_desired({rule});

    rules.reconcile({rule});

    REQUIRE(netlink.added.size() == 1);
    CHECK(netlink.added.front() == AF_INET);

    rules.clear();
    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front() == AF_INET);
}

TEST_CASE("PolicyRuleManager restores a vanished IPv6 rule without touching live IPv4") {
    FakeRuleNetlink netlink;
    const auto rule = dual_stack_rule();
    netlink.add_live(rule, AF_INET);
    PolicyRuleManager rules(netlink);
    rules.adopt_desired({rule});

    rules.reconcile({rule});

    REQUIRE(netlink.added.size() == 1);
    CHECK(netlink.added.front() == AF_INET6);

    rules.clear();
    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front() == AF_INET6);
}

TEST_CASE("PolicyRuleManager leaves complete foreign live state unowned") {
    FakeRuleNetlink netlink;
    const auto rule = dual_stack_rule();
    netlink.add_live(rule, AF_INET);
    netlink.add_live(rule, AF_INET6);
    PolicyRuleManager rules(netlink);
    rules.adopt_desired({rule});

    rules.reconcile({rule});
    rules.clear();

    CHECK(netlink.added.empty());
    CHECK(netlink.deleted.empty());
}

TEST_CASE("PolicyRuleManager keeps owned IPv4 while expanding to dual stack") {
    FakeRuleNetlink netlink;
    RuleSpec ipv4 = dual_stack_rule();
    ipv4.family = AF_INET;
    const RuleSpec dual_stack = dual_stack_rule();
    PolicyRuleManager rules(netlink);

    rules.add(ipv4);
    REQUIRE(netlink.live.size() == 1);

    rules.reconcile({dual_stack});

    CHECK(std::any_of(
        netlink.live.begin(),
        netlink.live.end(),
        [&](const DumpedRule& rule) {
            return rule.family == AF_INET &&
                   rule.fwmark == dual_stack.fwmark;
        }));
    CHECK(std::any_of(
        netlink.live.begin(),
        netlink.live.end(),
        [&](const DumpedRule& rule) {
            return rule.family == AF_INET6 &&
                   rule.fwmark == dual_stack.fwmark;
        }));
    CHECK(netlink.deleted.empty());

    rules.clear();
    CHECK(netlink.live.empty());
}

TEST_CASE("PolicyRuleManager removes only IPv6 while narrowing to IPv4") {
    FakeRuleNetlink netlink;
    const RuleSpec dual_stack = dual_stack_rule();
    RuleSpec ipv4 = dual_stack;
    ipv4.family = AF_INET;
    PolicyRuleManager rules(netlink);

    rules.add(dual_stack);
    REQUIRE(netlink.live.size() == 2);

    rules.reconcile({ipv4});

    REQUIRE(netlink.live.size() == 1);
    CHECK(netlink.live.front().family == AF_INET);
    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front() == AF_INET6);

    rules.clear();
    CHECK(netlink.live.empty());
}

} // namespace keen_pbr3
